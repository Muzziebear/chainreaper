"""Prompt injectors (spec §7 "Injected scope context — authorized assets only").

The scope injector is a **hard guardrail**: every agent prompt is prefixed with
the exact in-scope assets so the model never analyzes, references, or proposes
work against out-of-scope code. Built deterministically from the Discovery
``Target`` — not model-authored.
"""

from __future__ import annotations

from ..models import Target


# Caps so a large-scope program (e.g. beefy: 300+ assets / 240+ contracts) keeps the
# rendered scope block well under the OS per-arg limit (Linux MAX_ARG_STRLEN = 128KB)
# AND stays a usable prompt. The HARD guardrail is enforced deterministically
# downstream (scope_allowlist, dossier scoping, S3 out-of-scope drop) — the prompt is
# guidance, so summarising the overflow here is safe.
_MAX_ASSETS = 30
_MAX_ALLOW = 120
_MAX_OUT = 20


def scope_injector(target: Target | None, repo_ref: str | None = None) -> str:
    """Render the authorized-scope block for an agent system prompt (compact for
    large-scope programs; the deterministic layers enforce the full allowlist)."""
    if target is None:
        return (
            "## SCOPE (hard guardrail)\n"
            "No Discovery target available. Treat ONLY the indexed repository as in scope.\n"
        )

    in_scope = [a for a in target.assets_in_scope if a.in_scope]
    out_scope = [a for a in target.assets_in_scope if not a.in_scope]

    lines = [
        "## SCOPE (hard guardrail — do not cross)",
        f"Program: {target.name} ({target.program_id}).",
        f"Chains: {', '.join(target.chains) or 'n/a'}. "
        f"Languages: {', '.join(target.languages) or 'n/a'}.",
    ]

    # Program impacts ONCE (deduped across assets) — NOT repeated per asset (repeating
    # the full impacts list on every one of 300+ assets is what blew past the OS arg
    # limit on large programs).
    impacts: list[str] = []
    for a in target.assets_in_scope:
        for imp in a.impacts_in_scope:
            if imp not in impacts:
                impacts.append(imp)
    if impacts:
        shown = impacts[:12]
        more = f" (+{len(impacts) - len(shown)} more)" if len(impacts) > len(shown) else ""
        lines.append("Highest-paying in-scope impacts: " + "; ".join(shown) + more
                     + " — rank findings/tasks against these.")

    # Readable source roots the agent reads from (local_path / github_repo) matter most;
    # deployed addresses are provenance (summarised when many).
    lines.append("")
    lines.append("IN-SCOPE assets — analyze ONLY these:")
    src_assets = [a for a in in_scope if a.kind in ("local_path", "github_repo")]
    addr_assets = [a for a in in_scope if a.kind == "contract_address"]
    other_assets = [a for a in in_scope
                    if a.kind not in ("local_path", "github_repo", "contract_address")]

    for a in src_assets[:_MAX_ASSETS]:
        loc = a.ref
        if a.kind == "local_path" and a.source_repo:
            rev = f"@{a.revision[:10]}" if a.revision else ""
            loc = f"{a.ref}  (clone of {a.source_repo}{rev})"
        lines.append(f"  - {a.kind}: {loc}")
    if len(src_assets) > _MAX_ASSETS:
        lines.append(f"  - (+{len(src_assets) - _MAX_ASSETS} more in-scope source units under "
                     "the verified-source root above)")
    if addr_assets:
        nets = sorted({a.network for a in addr_assets if a.network})
        lines.append(f"  - {len(addr_assets)} in-scope deployed contract address(es)"
                     + (f" on {', '.join(nets)}" if nets else "")
                     + " — see the CONTRACT ALLOWLIST below (the source of truth).")
    for a in other_assets[:5]:
        lines.append(f"  - {a.kind}: {a.ref}")
    if repo_ref:
        lines.append(f"  (indexed repository: {repo_ref})")

    # The in-scope contract allowlist (spec §S0): the cloned repo is a SUPERSET, so the
    # only contracts in scope are these names — S2+ must NOT analyze any other contract.
    allow = getattr(target, "scope_allowlist", None) or []
    if allow:
        resolved = [c for c in allow if getattr(c, "resolved", False) and c.file]
        unresolved = [c for c in allow if not (getattr(c, "resolved", False) and c.file)]
        lines.append("")
        lines.append(
            f"IN-SCOPE CONTRACT ALLOWLIST ({len(allow)} contracts) — the cloned repo is a "
            "SUPERSET of the protocol; ONLY these contract names are in scope. Treat every "
            "other contract in the index as OUT-OF-SCOPE reference code. The harness enforces "
            "this allowlist deterministically; the list below is truncated for prompt size:")
        for c in resolved[:_MAX_ALLOW]:
            net = f" [{c.network}]" if c.network else ""
            lines.append(f"  - {c.name}{net} → {c.file}")
        if len(resolved) > _MAX_ALLOW:
            lines.append(f"  - (+{len(resolved) - _MAX_ALLOW} more resolved in-scope contracts — "
                         "query the index by name; all are in scope)")
        if unresolved:
            names = ", ".join(c.name for c in unresolved[:20])
            tail = f" (+{len(unresolved) - 20} more)" if len(unresolved) > 20 else ""
            lines.append(
                "  (allowlisted but no source file resolved — still in scope; locate by name "
                f"if the index has it: {names}{tail})")

    if out_scope:
        lines.append("")
        lines.append("OUT-OF-SCOPE — never analyze, cite, or propose work here:")
        for a in out_scope[:_MAX_OUT]:
            lines.append(f"  - {a.kind}: {a.ref}")
        if len(out_scope) > _MAX_OUT:
            lines.append(f"  - (+{len(out_scope) - _MAX_OUT} more out-of-scope assets)")

    lines.append(
        "\nDo NOT reference files, contracts, or addresses outside the in-scope assets. "
        "If the index surfaces out-of-scope code, ignore it."
    )
    return "\n".join(lines)
