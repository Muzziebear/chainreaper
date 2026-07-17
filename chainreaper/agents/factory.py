"""Agent factory (spec §7, §9).

Composes each agent's system prompt from four parts:
  1. the injected **SCOPE** guardrail (``orchestrator.injectors``),
  2. a backend-specific **TOOLS** block (how to invoke this provider's tool
     surface — supplied by the active ``Backend.tools_doc``),
  3. the backend-agnostic **methodology** prompt (``agents/prompts/<name>.md``),
  4. a **REQUIRED OUTPUT** block rendered from the agent's ``Emitter``s — the
     schema-validated save-scripts it must call (the prompt layer of the
     output obligation; the session + hooks enforce it).

Methodology lives in ``agents/prompts/`` (markdown) — owned by the agent layer,
not the Skills library (which now holds only knowledge/catalog data). Simple
string composition; no Jinja2 dependency for the S2 slice.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..models import HunterDossier, HunterTask, PrefilterDecision, ReconProfile, Target
from ..orchestrator.injectors import scope_injector
from ..tools.incident_catalog import incident_catalog
from .spec import Emitter

_PROMPTS = Path(__file__).resolve().parent / "prompts"

# Human descriptions for the REQUIRED OUTPUT block (presentation only).
_EMITTER_DESC = {
    "recon-create-profile": "your Recon profile (architecture_md, contract_types, "
                            "trust_boundaries, privileged_roles, ranked high_impact_areas, "
                            "threat_model)",
    "recon-create-task": "your HunterTask queue",
    "recon-create-invariant": "your invariant list",
    "hunt-create-finding": "each proven Finding (with its runnable impact PoC)",
    "hunt-finish": "your REQUIRED outcome record (finding | empty | blocked, with the "
                   "tally + what you tried) — you cannot stop until this is saved",
    "critic-create-verdict": "your REQUIRED adversarial Verdict on the finding under "
                             "review (TRUE_POSITIVE | FALSE_POSITIVE | NEEDS_LIVE_PROOF, "
                             "with your refutation attempt + CVSS) — you cannot stop "
                             "until this is saved",
}


def _prompt_body(name: str) -> str:
    """Return a prompt markdown body (tolerating optional YAML frontmatter)."""
    text = (_PROMPTS / f"{name}.md").read_text()
    if text.startswith("---"):
        end = text.find("\n---", 3)
        if end != -1:
            text = text[end + 4:]
    return text.strip()


def required_scripts_block(emitters: list[Emitter]) -> str:
    """Render the REQUIRED OUTPUT section from an agent's emitters."""
    lines = [
        "## REQUIRED OUTPUT — you MUST call these save-scripts before you finish",
        "You are read-only and you finish ONLY by persisting your output through "
        "these schema-validated scripts. A Stop hook blocks you from ending until "
        "each is satisfied, and your tools are restricted to read/search, the code "
        "index, and these scripts. The OUTPUT MECHANICS section of your task gives "
        "the exact file paths and command lines.",
    ]
    for e in emitters:
        what = _EMITTER_DESC.get(e.command, e.command)
        count = f"≥{e.min_calls} records" if e.multiple else f"exactly {e.min_calls}"
        lines.append(f"- `chainreaper {e.command}` — save {what} ({count}).")
    return "\n".join(lines)


def incident_block() -> str:
    """The protocol-class incident catalog, rendered for the prompt. The single
    Recon agent classifies the target's contract types *itself*, so we render ALL
    documented classes with their ``applies_to`` and instruct the agent to encode
    the ones matching the types it classifies. Each is a generic high-severity
    property the agent must turn into a regression invariant bound to THIS
    codebase's real hooks (``tools/incident_catalog.py``)."""
    classes = incident_catalog(None)
    if not classes:
        return ""
    lines = [
        "## PROTOCOL-CLASS INCIDENT CATALOG (regression class — apply the ones "
        "matching the contract types YOU classify)",
        "These are the documented high-severity incident classes. The `applies_to` "
        "field says which protocol types each covers. For EACH class whose "
        "`applies_to` matches a contract type you classified, you MUST emit a "
        "regression invariant (`origin = prior_finding`) asserting the property "
        "below, bound to THIS codebase's real hooks (find them with code-index), "
        "preserving the property's semantics, and framed for the initialized "
        "analyzer (the named slither detectors). Use the suggested id_hint prefix.",
    ]
    for c in classes:
        lines.append(
            f"- **{c['title']}** (id_hint `{c.get('id_hint', '?')}`, category "
            f"`{c.get('category', '?')}`, SC-class `{c.get('sc_class', '?')}`)\n"
            f"  - applies_to: {', '.join(c.get('applies_to', []))}\n"
            f"  - property: {(c.get('property') or '').strip()}\n"
            f"  - bind to: {c.get('bind_to', '')}\n"
            f"  - slither detectors: {', '.join(c.get('slither', [])) or '(structural)'}"
        )
    return "\n".join(lines)


# Full attack-class taxonomy (SC Top-10 2026 + blockchain extras = the VulnClass
# enum), grouped so the agent covers the classes a property/invariant pass
# systematically MISSES (liveness/DoS, ordering/MEV, economic amplification,
# adversarial external inputs, upgrade mechanics) — not just the accounting/auth/
# reentrancy surface its invariants already imply. Each line: vuln_class · SC/CWE ·
# what it looks like + when it applies.
_ATTACK_CLASS_GROUPS: list[tuple[str, str, list[str]]] = [
    ("Accounting & valuation", "property-shaped — your invariants usually imply these; still emit tasks", [
        "`logic_error` (SC02 Business Logic, CWE-840/682) — accounting errors, conservation breaks.",
        "`price_oracle_manipulation` (SC03, CWE-1339) — stale / out-of-band / spoofed / spot-manipulable price.",
        "`arithmetic_error` (SC07, CWE-682) — rounding-direction bias, divide-before-multiply, precision loss.",
        "`integer_overflow` (SC09, CWE-190) — overflow / underflow in unchecked or cast arithmetic.",
        "`first_depositor_inflation` (CWE-682) — ERC-4626 share/AUM inflation, donation skew.",
    ]),
    ("Authorization & signatures", "usually covered — confirm each applicable one has a task", [
        "`access_control` (SC01 Access Control, CWE-284/863) — missing/incorrect role gating, unprotected/again-callable init.",
        "`signature_replay` (CWE-294/347) — replay across chains / contracts / missing-or-reused nonce.",
        "`signature_malleability` (CWE-347) — ecrecover s-malleability, encode-packed hash collision.",
    ]),
    ("Reentrancy", "usually covered", [
        "`reentrancy` (SC08, CWE-841) — classic / cross-function / cross-contract.",
        "`readonly_reentrancy` (CWE-841) — a view (price/AUM/getter) read mid-callback returns inconsistent state.",
    ]),
    ("Liveness / Denial-of-Service — OFTEN MISSED", "maps to PERMANENT FREEZING + PROTOCOL INSOLVENCY (in-scope!)", [
        "`denial_of_service` (CWE-400/703; not in SC-Top-10 2026 but → PERMANENT FREEZING / "
        "INSOLVENCY) — can an attacker make execute/withdraw/order or a "
        "LIQUIDATION permanently revert? (revert-on-receive or blacklist/pausable collateral, poisoned "
        "callback, stuck request). Blocking liquidation → insolvency; wedging withdrawal → frozen funds.",
        "`unbounded_loop_dos` (CWE-834) — iteration over a user-growable set (markets, orders, holders).",
        "`gas_griefing` (CWE-400/691) — callback gas-limit abuse, return-bomb, execution-fee griefing.",
    ]),
    ("Transaction ordering / MEV — OFTEN MISSED", "maps to DIRECT THEFT", [
        "`mev_frontrunning` (CWE-362 race / CWE-841 workflow) — sandwich a deposit/withdraw/swap around an "
        "oracle update; keeper/sequencer front-running, censoring, or selectively executing requests; ADL / "
        "liquidation target selection gaming. Two-step keeper-executed flows that pick the oracle block are "
        "the prime surface — make at least one ordering/MEV task for that flow.",
    ]),
    ("Economic amplification — OFTEN MISSED", "turns a 'needs capital' lead into a real exploit", [
        "`flash_loan_attack` (SC04) — for EVERY manipulation hypothesis (AUM, share price, liquidity, price "
        "impact, oracle spot), ask whether a flash loan reaches the threshold with ~zero attacker capital, "
        "and emit a task to prove it that way.",
    ]),
    ("Adversarial external inputs — OFTEN MISSED", "arbitrary tokens / calls / params", [
        "`input_validation` (SC05, CWE-20) — unchecked params, config injection, missing bounds/freshness.",
        "`unchecked_external_calls` (SC06, CWE-252) — arbitrary-call proxies, ignored return values, return-bomb.",
        "weird-token handling (→ `logic_error`/`denial_of_service`, CWE-20) — market collateral is arbitrary "
        "ERC-20s: fee-on-transfer & rebasing break amount accounting; blacklist/pausable (e.g. USDC) DoS "
        "withdrawals/liquidations; ERC-777/hook tokens add reentrancy. Emit tasks for the token types in scope.",
    ]),
    ("Upgrade / proxy mechanics — OFTEN MISSED", "SC10 Proxy & Upgradeability; any upgradeable / delegatecall surface", [
        "`proxy_upgradeability` (SC10, CWE-1099/1023) — umbrella: unsafe upgrade authority, storage-layout "
        "drift, uninitialized implementation, unprotected upgrade path.",
        "`storage_collision` (SC10, CWE-1099) — storage-layout drift across upgrades / between proxy and impl.",
        "`selector_clash` (SC10, CWE-1023) — selector collisions in delegatecall / multicall / router plugin space.",
        "re-init / uninitialized implementation (→ `access_control`) — guards on the NEW impl, not just the proxy.",
    ]),
    ("Randomness", "if any value-bearing selection uses on-chain entropy", [
        "`bad_randomness` (SC10, CWE-330) — block.timestamp/number/hash used for a payout/selection.",
    ]),
]


def attack_class_block() -> str:
    """The full SC-Top-10 + extras attack-class CHECKLIST for the task queue. The
    invariant suite covers the *property-shaped* classes; this checklist exists so
    the agent also covers the classes a property pass misses — liveness/DoS,
    ordering/MEV, flash-loan amplification, weird-token inputs, upgrade mechanics —
    which are exactly where the highest-impact (freezing/insolvency/theft) bugs hide."""
    lines = [
        "## ATTACK-CLASS COVERAGE CHECKLIST (your task queue MUST walk ALL of this)",
        "Your invariant suite already implies the *property-shaped* classes (accounting, "
        "auth, reentrancy). That is necessary but NOT sufficient: a property-driven pass "
        "systematically UNDER-covers the classes below marked *OFTEN MISSED*. Go group by "
        "group; for EACH class that plausibly applies to the contract types you classified, "
        "emit at least one HunterTask (exploratory, `inv_id` unset, with a concrete "
        "`scope_hint` + falsifiable `hypothesis`). Liveness/DoS, ordering/MEV, and "
        "weird-token handling apply to essentially every DeFi protocol that custodies funds "
        "and executes user/keeper transactions — do not skip them. Only omit a class if it "
        "genuinely cannot apply here.",
    ]
    for title, note, items in _ATTACK_CLASS_GROUPS:
        lines.append(f"\n**{title}** — _{note}_")
        for it in items:
            lines.append(f"- {it}")
    return "\n".join(lines)


def cross_contract_block() -> str:
    """The protocol-interaction-graph + cross-contract attack mandate (T2.1). The
    biggest structural blind spot is single-contract scoping: modern DeFi exploits
    chain oracle→AMM→liquidation across several contracts, often flash-loan-amplified.
    Recon must MAP the graph and emit cross-contract tasks for it (arXiv 2511.00408)."""
    return (
        "## PROTOCOL INTERACTION GRAPH + CROSS-CONTRACT ATTACKS (T2.1 — do not skip)\n"
        "Single-contract thinking misses the highest-impact bugs. As part of your "
        "PROFILE, build a `protocol_graph`:\n"
        "- **nodes** = every in-scope contract PLUS each external integration you "
        "find — price **oracles** (Chainlink/TWAP/spot), **AMMs**/pools the protocol "
        "reads or swaps against, **bridges**/messaging, **lending** markets, and the "
        "**tokens** used as collateral. Mark `external: true` for 3rd-party ones.\n"
        "- **edges** = the interactions an exploit can CHAIN: a price `read`, an "
        "`amm_swap`, a `bridge_msg`, a `liquidation` trigger, a `flashloan_source`, a "
        "collateral/price dependency. Direction matters (who calls/reads whom).\n\n"
        "Then, in your task queue, emit **cross-contract tasks** (set `contracts` to "
        "all nodes in scope and `attack_path` to the ordered hops) for the economic "
        "chains the graph reveals. Canonical patterns to check whenever the graph "
        "supports them:\n"
        "- **oracle → AMM → liquidation**: manipulate a pool the oracle reads (spot "
        "or short-TWAP), move the reported price, then trigger mispriced "
        "liquidations / mint / borrow.\n"
        "- **flash-loan-amplified**: prepend a `flashloan_source` hop to ANY "
        "manipulation that needs capital — prove it with ~zero attacker funds.\n"
        "- **cross-module accounting**: a state change in contract A that contract B "
        "trusts without re-validation (shared vault/registry/accounting).\n"
        "- **bridge/multichain replay**: a message/proof valid on one path replayed "
        "on another.\n"
        "Emit at least one cross-contract task per economic chain the graph supports; "
        "a hunter will reproduce the full hop sequence in a multi-contract PoC.\n\n"
        "### EXTERNAL-DEPENDENCY TRUST ASSUMPTIONS (Tier-4 P3 — do not skip)\n"
        "For EACH `external: true` node, record on the node what the in-scope protocol "
        "IMPLICITLY TRUSTS about it in `trust_assumptions` — the latent failure modes a "
        "code-reading pass never states, e.g. \"assumes Curve `get_virtual_price` is "
        "manipulation-resistant\", \"assumes the Chainlink feed is fresh & never returns "
        "0/min\", \"assumes Aave never pauses\", \"trusts the LZ endpoint to deliver "
        "authentic messages\", \"assumes the reward token is a plain ERC-20 (no "
        "fee-on-transfer / reentrancy hook)\". Then, for each assumption that, if FALSE, "
        "would harm the protocol, emit a **dep-misbehavior task**: set `dep_target` to "
        "that dependency and `dep_assumptions` to the assumption(s) under attack (also "
        "list the dep in `contracts`). The campaign will mock the dependency on the fork "
        "to MISBEHAVE (return stale / extreme / reverting / reentrant values) and check "
        "the protocol's invariants still hold — a break proves the trust is unsafe "
        "(mispriced accounting, frozen withdrawals/liquidations on a dep pause, "
        "cross-contract reentrancy through a trusted callback)."
    )


def governance_block() -> str:
    """The governance / malicious-admin / upgrade-time mandate (Tier-4 P4). Two blind
    spots a property/invariant pass and an honest-actor model both miss: (a) what a
    COMPROMISED privileged role can do BEYOND its documented intent, and (b) what breaks
    at UPGRADE time (storage-layout drift, init front-run). Recon must enumerate both."""
    return (
        "## GOVERNANCE / MALICIOUS-ADMIN / UPGRADE-TIME (Tier-4 P4 — do not skip)\n"
        "Your invariants assume the privileged roles behave as documented and the code "
        "never changes. The highest-impact governance findings live in the opposite "
        "assumptions. Emit tasks for BOTH:\n\n"
        "**(a) Compromised / malicious privileged role.** For each `privileged_role` you "
        "identified, assume the key is COMPROMISED (or the holder is adversarial) and ask "
        "what it can do BEYOND its intent — then emit a task that sets **`malicious_role`** "
        "to that role. Concretely look for: a **timelock/governance BYPASS** (a privileged "
        "path that skips the delay/quorum the docs promise); a **parameter pushed to "
        "insolvency** (set a fee/LTV/oracle-staleness/cap to a value that bricks accounting "
        "or frees funds — within the role's *allowed* range, no bug needed); **draining via "
        "a 'legitimate' admin path** (sweep/rescue/migrate/upgrade-to-malicious-impl/"
        "set-fee-recipient that moves user funds); and **missing/loose bounds** on admin "
        "setters. The finding is 'a single compromised role causes catastrophic loss with "
        "no further bug' — that is in-scope (DIRECT THEFT / FREEZING / INSOLVENCY).\n\n"
        "**(b) Real-upgrade simulation.** For every upgradeable / proxied / delegatecall "
        "contract, emit a task with **`upgrade_sim: true`** that checks: **storage-layout "
        "drift** across implementation versions (a variable inserted/reordered/removed/"
        "retyped at an existing slot → the new code reads/writes the WRONG slot; the "
        "`index/storagediff` helper computes the exact collisions across two impls), an "
        "**init / re-init front-run** (the new implementation's initializer callable by "
        "anyone on a fresh deploy / after an upgrade → attacker seizes ownership), and an "
        "**unprotected upgrade authority** (who can call `upgradeTo`, and is the NEW impl "
        "guarded, not just the proxy). Storage collisions + a hijackable initializer are "
        "SC10 and are invisible to a single-version read."
    )


def incentive_block() -> str:
    """The game-theory / incentive / long-horizon mandate (Tier-4 P5). Two blind spots a
    single-actor, single-block property pass misses: (a) exploits that need MULTIPLE roles
    to COLLUDE, and (b) bugs that only emerge after TIME passes (funding/interest drift,
    epoch/checkpoint boundaries). Recon must emit tasks for both."""
    return (
        "## GAME-THEORY / INCENTIVE / LONG-HORIZON (Tier-4 P5 — do not skip)\n"
        "Your invariants assume one attacker acting in one block. The subtlest economic "
        "bugs break both assumptions. Emit tasks for BOTH:\n\n"
        "**(a) Multi-actor / collusion (incentive misalignment).** Where TWO roles can "
        "COLLUDE to extract value that neither could alone — a **keeper/sequencer** that "
        "orders or executes + an **LP/counterparty** it favours; a **briber** + a bribed "
        "**governance voter**; a **liquidator** + the **position owner**. Ask: is any "
        "actor's individually-rational, 'honest' action (ordering, executing, providing/"
        "pulling liquidity, voting) systematically enriching a coalition at the protocol's "
        "or other users' expense? Emit a task with **`multi_actor: true`** — the campaign "
        "adds the colluding actors + a coalition-PnL objective the fuzzer maximises.\n\n"
        "**(b) Long-horizon / epoch-aware.** Where the bug needs TIME to pass — "
        "interest/funding **drift**, reward-rate **decay**, **epoch/checkpoint** rollovers, "
        "**vesting** cliffs, TWAP windows, streaming. Ask: does accounting stay correct "
        "across many epochs; is any per-epoch/per-checkpoint boundary (first, last, "
        "rollover, skipped) mishandled; can a position be held to accrue an unfair edge? "
        "Emit a task with **`long_horizon: true`** — the campaign adds a `vm.warp`/`roll` "
        "time-advance step + a longer call sequence so deep-time state is actually reached. "
        "(Both flags can be set on one task when an exploit is a long-horizon collusion.)"
    )


def _compose(target: Target | None, repo_ref: str | None, tools_doc: str,
             prompt: str, emitters: list[Emitter], *extra: str) -> str:
    parts = [scope_injector(target, repo_ref), "## TOOLS\n" + tools_doc.strip(),
             _prompt_body(prompt)]
    parts.extend(p for p in extra if p)
    parts.append(required_scripts_block(emitters))
    return "\n\n".join(parts)


# Each invariant tool's sweet spot, so the recon agent routes invariants to the
# checker that actually suits the property's shape (T1.2) — not everything to one.
_TOOL_GUIDANCE = {
    "slither": "static detectors — pattern/structural properties (reentrancy shape, "
               "missing-modifier, arbitrary-send); fast, no harness.",
    "foundry": "a hand-written Foundry invariant/unit test — when the property needs "
               "a precise, scripted setup.",
    "medusa": "STATEFUL fuzzing (preferred for accounting/solvency/share-price/PnL) — "
              "long random call sequences against a handler; the deep invariant engine.",
    "echidna": "property/assertion fuzzing — boolean `echidna_*` properties over "
               "randomized sequences; pairs with medusa (Chimera writes one handler "
               "for both).",
    "halmos": "SYMBOLIC execution — PROVE an arithmetic/access property holds for ALL "
              "inputs (no counterexample) rather than just fuzzing it; use for "
              "conservation/rounding/access properties you want proven.",
    "wake": "Python-based detectors/testing framework — structural checks.",
    "properties": "crytic property suite (ERC compliance etc.).",
    "certora": "formal verification (CVL specs).",
}


def sast_block(initialized_tools: list[str], sast: dict | None) -> str:
    """ROUTING MENU + SLITHER FINDINGS block: invariants may only target a tool that
    is actually runnable on this host (T1.2 — static analyzers that ran at index time
    UNION the installed stateful-fuzz/symbolic tools), routed to the checker that
    suits each property, and grounded in slither's real output."""
    from ..models import InvariantTool
    from typing import get_args

    tools = initialized_tools or ["slither"]
    unavailable = [t for t in get_args(InvariantTool) if t not in tools]
    lines = [
        "## INVARIANT TOOL ROUTING MENU (assign invariant.tool ONLY from these)",
        "Runnable on this host: " + ", ".join(tools) + ".",
        "Route EACH invariant to the tool that fits the property's shape — do not "
        "send everything to one tool. Sweet spots:",
    ]
    for t in tools:
        g = _TOOL_GUIDANCE.get(t)
        if g:
            lines.append(f"- **{t}** — {g}")
    if unavailable:
        lines.append(
            "NOT installed on this host (an invariant assigned to one cannot be run, "
            "so do NOT use it): " + ", ".join(unavailable) + ".")
    if sast and (sast.get("checks") or sast.get("top")):
        lines.append("\n## SLITHER FINDINGS (the index's real detector output — ground invariants here)")
        checks = sast.get("checks") or []
        if checks:
            inv = "; ".join(f"{c['check_id']}/{c['impact']}×{c['n']}" for c in checks[:24])
            lines.append("Detectors present (check_id/impact×count): " + inv)
        top = sast.get("top") or []
        if top:
            lines.append("Top in-scope High/Medium findings:")
            for t in top[:24]:
                lines.append(f"  [{t['impact']}] {t['check_id']} {t['file']}:{t['line']} — "
                             f"{(t.get('description') or '').strip()}")
        lines.append("Pull more with `chainreaper code-index sast '{\"impact\":\"High\"}'` or "
                     "`'{\"contract\":\"MarketUtils\"}'`.")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Hunter (S4/S7) prompt composition                                            #
# --------------------------------------------------------------------------- #
def _fn_label(row: dict) -> str:
    """Compact ``Contract.name(sig) @ file:line`` label for an index row."""
    c = row.get("contract") or ""
    n = row.get("name") or ""
    sig = row.get("signature") or n
    head = f"{c}.{sig}" if c else sig
    loc = ""
    f = row.get("file")
    if f:
        ln = row.get("line") or row.get("line_start")
        loc = f"  @ {f}:{ln}" if ln else f"  @ {f}"
    return f"{head}{loc}"


def hunter_profile_block(profile: ReconProfile) -> str:
    """The shared Recon context every hunter receives (Glasswing: prevents drift).
    A compact digest of the profile — full architecture narrative + the top
    HotZones + privileged roles — NOT the whole object."""
    lines = ["## RECON PROFILE (shared context — the map you hunt against)"]
    if profile.contract_types:
        lines.append("Contract types: " + ", ".join(profile.contract_types))
    if profile.architecture_md:
        arch = profile.architecture_md.strip()
        lines.append("\n" + (arch[:1600] + " …" if len(arch) > 1600 else arch))
    if profile.high_impact_areas:
        lines.append("\nTop HotZones:")
        for hz in sorted(profile.high_impact_areas, key=lambda h: h.rank)[:6]:
            fns = ", ".join(hz.functions[:4])
            lines.append(f"  {hz.rank}. {hz.title} — {', '.join(hz.contracts[:4])}"
                         + (f" [{fns}]" if fns else ""))
    if profile.privileged_roles:
        roles = ", ".join(r.name for r in profile.privileged_roles[:8])
        lines.append("\nPrivileged roles: " + roles)
    # Protocol interaction graph slice (T2.1) — the cross-contract map a multi-hop
    # exploit travels (oracle reads, AMM swaps, bridges, flash-loan sources).
    pg = getattr(profile, "protocol_graph", None)
    if pg and (pg.nodes or pg.edges):
        ext = [n for n in pg.nodes if n.external]
        if ext:
            lines.append("\nExternal integrations: "
                         + ", ".join(f"{n.name}({n.kind})" for n in ext[:8]))
            # Tier-4 P3 — the implicit trust assumptions a dep-misbehavior attack targets.
            assumed = [n for n in ext if getattr(n, "trust_assumptions", None)]
            if assumed:
                lines.append("Trust assumptions (a dep-misbehavior task attacks each):")
                for n in assumed[:6]:
                    for a in n.trust_assumptions[:3]:
                        lines.append(f"  - {n.name}: {a}")
        if pg.edges:
            lines.append("Interaction edges (attack hops):")
            for e in pg.edges[:10]:
                lines.append(f"  {e.src} -[{e.kind}]-> {e.dst}"
                             + (f"  ({e.detail})" if e.detail else ""))
    return "\n".join(lines)


def hunter_task_block(task: HunterTask, dossier: HunterDossier | None,
                      decision: PrefilterDecision | None, repo_root: str | None) -> str:
    """The single task + its precomputed attack surface. ``reachable_entrypoints``
    is foregrounded: it is the bridge from "the bug is here" → "exploitable from
    THIS public entrypoint" → the PoC scaffold (spec §S4)."""
    seed = (decision.seed if decision else ("invariant-campaign" if task.inv_id else "hypothesis"))
    lines = [
        "## YOUR TASK (one task · one vuln-class · prove it with a runnable PoC)",
        f"task_id: {task.task_id}",
        f"title: {task.title}",
        f"vuln_class: {task.vuln_class.value if hasattr(task.vuln_class, 'value') else task.vuln_class}",
        f"priority: P{task.priority}   discovery-seed: {seed}"
        + (f"   inv_id: {task.inv_id}" if task.inv_id else ""),
        f"scope_hint: {task.scope_hint}",
        f"hypothesis: {task.hypothesis}",
    ]
    # Cross-contract / economic-chain task (T2.1): foreground the multi-hop scope so
    # the hunter builds a MULTI-CONTRACT PoC that reproduces the whole chain, not a
    # single-region check.
    if len(task.contracts) > 1 or task.attack_path:
        lines.append("\n### CROSS-CONTRACT attack (reproduce the FULL chain in one PoC):")
        if task.contracts:
            lines.append("  contracts in scope: " + ", ".join(task.contracts))
        if task.attack_path:
            lines.append("  attack path (ordered hops): " + " → ".join(task.attack_path))
        lines.append("  Your PoC must drive these contracts/integrations in sequence "
                     "(fork the real deployments where possible; add a flash-loan hop "
                     "if the manipulation needs capital) and assert $-impact at the end "
                     "of the chain.")
    # Tier-4 P3 — dep-misbehavior subtype: the bug is in the TRUST, not the in-scope
    # code's own logic. Foreground the dependency to mock + the assumptions under attack.
    if getattr(task, "dep_target", ""):
        lines.append("\n### DEP-MISBEHAVIOR task (attack the TRUST, not the code):")
        lines.append(f"  external dependency under test: {task.dep_target}")
        if task.dep_assumptions:
            lines.append("  trust assumptions to break: "
                         + "; ".join(task.dep_assumptions[:6]))
        lines.append("  Do NOT hunt the in-scope code's own logic here. Fork the real "
                     "deployment, bind `depAddr` to this dependency, and use the "
                     "`handle_dep*` primitives to make it MISBEHAVE (vm.mockCall a "
                     "stale/extreme value, vm.mockCallRevert a pause, or point it at a "
                     "reentering mock). Then show a protocol invariant breaks — mispriced "
                     "accounting, a permanently frozen withdrawal/liquidation, or "
                     "cross-contract reentrancy — i.e. the trust assumption is unsafe.")
    # Tier-4 P4 — compromised privileged role: assume the role is adversarial.
    if getattr(task, "malicious_role", ""):
        lines.append("\n### MALICIOUS-ADMIN task (assume this role is COMPROMISED):")
        lines.append(f"  compromised role: {task.malicious_role}")
        lines.append("  Assume the key is in attacker hands and ask what it does BEYOND "
                     "its documented intent: a timelock/governance BYPASS, a parameter "
                     "set (within the role's allowed range) that pushes the protocol to "
                     "insolvency or frees funds, or draining via a 'legitimate' admin path "
                     "(sweep/rescue/migrate/set-fee-recipient/upgrade-to-malicious-impl). "
                     "`vm.prank` the role in your PoC and demonstrate catastrophic "
                     "loss/freezing with NO further bug — a single compromised role is "
                     "enough. If a real timelock/multisig gates it, show the bypass or "
                     "say the control holds.")
    # Tier-4 P4 — real-upgrade simulation: storage drift + init front-run.
    if getattr(task, "upgrade_sim", False):
        lines.append("\n### UPGRADE-SIMULATION task (what breaks at upgrade time):")
        lines.append("  Check three SC10 failure modes: (1) STORAGE-LAYOUT DRIFT across "
                     "implementation versions — a var inserted/reordered/removed/retyped "
                     "at an existing slot makes the new code read/write the WRONG slot "
                     "(the `index/storagediff` helper computes the exact collisions; turn "
                     "one into a PoC where post-upgrade reads return corrupted state); "
                     "(2) INIT / RE-INIT FRONT-RUN — is the new implementation's "
                     "initializer callable by anyone (fresh deploy / after upgrade) so an "
                     "attacker seizes ownership? (3) UNPROTECTED UPGRADE AUTHORITY — who "
                     "can call `upgradeTo`, and is the NEW impl guarded (not just the "
                     "proxy)? Prove the corruption/seizure on a fork.")
    # Tier-4 P5 — multi-actor collusion + long-horizon modifiers.
    if getattr(task, "multi_actor", False):
        lines.append("\n### MULTI-ACTOR / COLLUSION task (optimize the COALITION):")
        lines.append("  This needs TWO+ roles to COLLUDE (keeper/sequencer + LP, briber + "
                     "voter, liquidator + owner). Your handler has `keeper`/`lp` actor "
                     "slots + `optimize_coalitionPnL()` — wire it to the colluding actors' "
                     "COMBINED value delta (model bribes as transfers between them) and "
                     "show one actor's individually-rational 'honest' action enriches the "
                     "coalition at the protocol's/other users' expense. A single-attacker "
                     "PoC does not satisfy this task.")
    if getattr(task, "long_horizon", False):
        lines.append("\n### LONG-HORIZON / EPOCH-AWARE task (let TIME pass):")
        lines.append("  The bug needs time to accrue (interest/funding drift, reward "
                     "decay, epoch/checkpoint/vesting boundaries). Use the "
                     "`handle_advanceTime` step (real `vm.warp`/`roll`) and the longer "
                     "medusa call sequence to reach deep-time state, then show drift "
                     "breaking accounting/solvency or a boundary (epoch rollover, "
                     "first/last checkpoint) the code mishandles. In your fork PoC, "
                     "`vm.warp`/`vm.roll` across the relevant horizon and assert the "
                     "$-impact at the end.")
    if repo_root:
        lines.append(f"in-scope repo root (read source with absolute paths): {repo_root}")
    if not dossier:
        lines.append("\n(No precomputed dossier — derive the attack surface from the index.)")
        return "\n".join(lines)

    re_rows = dossier.reachable_entrypoints or []
    lines.append("\n### Reachable public entrypoints — your PoC ATTACK SURFACE "
                 "(start the exploit from one of these):")
    if re_rows:
        for r in re_rows[:10]:
            lines.append("  - " + _fn_label(r))
    else:
        lines.append("  (none precomputed — the dossier found no external→target path; "
                     "confirm reachability yourself before claiming a finding, or this "
                     "lead is likely UNREACHABLE.)")
    if dossier.target_functions:
        lines.append("\n### Target functions (where the bug lives):")
        for r in dossier.target_functions[:10]:
            lines.append("  - " + _fn_label(r))
    if dossier.external_call_sinks:
        lines.append("\n### External-call sinks in scope (where damage lands):")
        for r in dossier.external_call_sinks[:8]:
            kind = r.get("kind") or r.get("type") or "call"
            lines.append(f"  - [{kind}] " + _fn_label(r))
    if dossier.accounting_state_vars:
        lines.append("\n### Accounting state (what to read for $-impact assertions):")
        for r in dossier.accounting_state_vars[:8]:
            c = r.get("contract") or ""
            v = r.get("name") or r.get("var") or ""
            lines.append(f"  - {c}.{v}" + (f" : {r['type']}" if r.get("type") else ""))
    if dossier.invariants:
        lines.append("\n### Binding invariants (a counterexample SEEDS the PoC — it is "
                     "NOT the finding; you still must demonstrate $-impact from an entrypoint):")
        for inv in dossier.invariants[:6]:
            iid = inv.inv_id if hasattr(inv, "inv_id") else inv.get("inv_id")
            stmt = inv.statement if hasattr(inv, "statement") else inv.get("statement", "")
            tool = inv.tool if hasattr(inv, "tool") else inv.get("tool", "")
            lines.append(f"  - {iid} [{tool}]: {stmt}")
    if dossier.controls:
        lines.append("\n### Existing controls (already-defended — don't chase these; "
                     "show why they DON'T stop you):")
        for c in dossier.controls[:8]:
            lines.append(f"  - {c}")
    if dossier.slither_findings:
        lines.append("\n### In-scope slither findings (static evidence to confirm/refute):")
        for f in dossier.slither_findings[:6]:
            lines.append(f"  - [{f.get('impact')}] {f.get('check_id')} "
                         f"{f.get('file')}:{f.get('line')}")
    if dossier.reach_note:
        lines.append(f"\nReachability note: {dossier.reach_note}")
    return "\n".join(lines)


def build_hunter_system(
    target: Target | None,
    repo_ref: str | None,
    tools_doc: str,
    emitters: list[Emitter],
    *,
    profile_block: str,
    task_block: str,
    fork_block: str = "",
) -> str:
    """System prompt for one Hunter agent (spec §7): SCOPE + sandbox TOOLS + the
    Hunter methodology + the shared Recon profile + this task's attack surface +
    the live FORK STATUS (which alias/block to fork, or local-only) + the REQUIRED
    OUTPUT obligation."""
    return _compose(target, repo_ref, tools_doc, "hunter", emitters,
                    profile_block, task_block, fork_block)


def critic_finding_block(finding: dict, vote_index: int = 1, votes_total: int = 1) -> str:
    """The Finding-under-review block for a Critic (S5/T3.1). Lays out everything the
    hunter claimed — the PoC + its run log most of all — so the critic can re-run it
    and adversarially refute. ``vote_index``/``votes_total`` make each of the N
    critics an independent skeptic."""
    poc = finding.get("poc") or {}
    locs = finding.get("locations") or []
    lines = [
        f"## FINDING UNDER REVIEW (you are critic {vote_index} of {votes_total} — "
        "vote INDEPENDENTLY)",
        f"finding_id: {finding.get('finding_id')}",
        f"task_id: {finding.get('task_id')}",
        f"title: {finding.get('title')}",
        f"vuln_class: {finding.get('vuln_class')}   sc_top10: {finding.get('sc_top10')}",
        f"severity_claim: {finding.get('severity_claim')}   "
        f"hunter_confidence: {finding.get('confidence')}   "
        f"live_validated: {finding.get('live_validated')}",
        f"trigger_class(claimed): {finding.get('trigger_class')}   "
        f"trigger_justification: {finding.get('trigger_justification') or '—'}",
        f"source_ref: {finding.get('source_ref')}   sink_ref: {finding.get('sink_ref')}",
        f"\ndescription: {finding.get('description')}",
        f"\nimpact: {finding.get('impact')}",
        f"\nexploit_scenario: {finding.get('exploit_scenario')}",
    ]
    pre = finding.get("preconditions") or []
    if pre:
        lines.append("preconditions: " + "; ".join(str(p) for p in pre))
    if locs:
        lines.append("\nlocations:")
        for loc in locs[:8]:
            ln = f"{loc.get('line_start')}" + (f"-{loc.get('line_end')}" if loc.get("line_end") else "")
            lines.append(f"  - {loc.get('file')}:{ln} {loc.get('contract') or ''}"
                         f".{loc.get('symbol') or ''}")
    lines.append("\n### THE POC (re-run it — this is the load-bearing evidence):")
    lines.append(f"framework: {poc.get('framework')}   succeeded(claimed): {poc.get('succeeded')}")
    lines.append(f"run_cmd: {poc.get('run_cmd')}")
    lines.append(f"expected_observation: {poc.get('expected_observation')}")
    for path, content in (poc.get("files") or {}).items():
        body = content if len(content) < 4000 else content[:4000] + "\n… (truncated)"
        lines.append(f"\n--- {path} ---\n{body}")
    if poc.get("run_log"):
        log = poc["run_log"]
        lines.append("\n--- run_log (claimed) ---\n" + (log[-2000:] if len(log) > 2000 else log))
    return "\n".join(lines)


def build_critic_system(
    target: Target | None,
    repo_ref: str | None,
    tools_doc: str,
    emitters: list[Emitter],
    *,
    profile_block: str,
    finding_block: str,
) -> str:
    """System prompt for one Critic agent (spec §7, §S5; T3.1): SCOPE + sandbox TOOLS
    (it re-runs the PoC) + the Critic methodology (REFUTE) + the shared Recon profile
    + the Finding under review + the REQUIRED verdict emitter."""
    return _compose(target, repo_ref, tools_doc, "critic", emitters,
                    profile_block, finding_block)


def build_spec_researcher_system(
    target: Target | None,
    repo_ref: str | None,
    tools_doc: str,
    emitters: list[Emitter],
) -> str:
    """System prompt for the Spec-Research agent (Tier-4 P2, ``mode="research"``):
    SCOPE + the (web-enabled) research TOOLS + the spec-research methodology + the
    REQUIRED invariant emitter. It fetches the target's documented promises (docs /
    whitepaper / audit reports / READMEs) and emits INTENT invariants
    (``Invariant`` with ``origin="spec"``) — the code-vs-intent gap a code-derived
    invariant pass cannot see. Its OUTPUT is bound to the in-scope code downstream;
    it never marks an external source in-scope."""
    return _compose(target, repo_ref, tools_doc, "spec_researcher", emitters)


def recon_profile_digest_block(profile_doc: dict | None, *, header: str) -> str:
    """Compact mechanism digest from a persisted ``ReconProfileInput`` dict —
    architecture, contract classes, ranked HotZones, privileged roles. Shared by the
    Threat-Research agent (Tier-4 P6) and the Recon SYNTHESIS session
    (``recon.synthesis_mode``) so both aim at the SPECIFIC protocol. Free-form dict in
    (it may carry extra keys), so read defensively."""
    if not profile_doc:
        return ""
    lines = [header]
    types = profile_doc.get("contract_types") or []
    if types:
        lines.append("Contract types: " + ", ".join(str(t) for t in types))
    arch = (profile_doc.get("architecture_md") or "").strip()
    if arch:
        lines.append("\n" + (arch[:1800] + " …" if len(arch) > 1800 else arch))
    hotzones = profile_doc.get("high_impact_areas") or []
    if hotzones:
        lines.append("\nTop HotZones (ranked):")
        for hz in sorted(hotzones, key=lambda h: h.get("rank", 99))[:8]:
            contracts = ", ".join((hz.get("contracts") or [])[:4])
            fns = ", ".join((hz.get("functions") or [])[:4])
            lines.append(f"  {hz.get('rank', '?')}. {hz.get('title', '')} — {contracts}"
                         + (f" [{fns}]" if fns else ""))
    roles = profile_doc.get("privileged_roles") or []
    if roles:
        names = ", ".join(str(r.get("name", r)) if isinstance(r, dict) else str(r)
                          for r in roles[:8])
        lines.append("\nPrivileged roles: " + names)
    return "\n".join(lines)


def recon_invariants_block(invariants: list[dict] | None, *, header: str) -> str:
    """Compact rendering of the code-derived + intent (SPEC-) invariant suite for the
    agents that must reason against it: the Threat-Research agent (so it does NOT
    re-derive an already-covered property — the Pendle ORAC-01 duplicate) and the Recon
    SYNTHESIS session (so each high/critical invariant gets a breaking task and the
    queue is linked to the suite). One line per invariant: id · severity · statement."""
    if not invariants:
        return ""
    lines = [header]
    for inv in invariants:
        inv_id = inv.get("inv_id", "?")
        sev = inv.get("severity", "")
        sev = sev.value if hasattr(sev, "value") else str(sev)
        stmt = (inv.get("statement") or "").strip().replace("\n", " ")
        if len(stmt) > 140:
            stmt = stmt[:140] + "…"
        origin = inv.get("origin", "")
        tag = " [intent]" if str(inv.get("inv_id", "")).upper().startswith("SPEC-") or origin == "spec" else ""
        lines.append(f"  - {inv_id} ({sev}){tag}: {stmt}")
    return "\n".join(lines)


def threat_research_profile_block(profile_doc: dict | None,
                                  invariants: list[dict] | None = None) -> str:
    """Mechanism digest + the EXISTING invariant suite for the Threat-Research agent
    (Tier-4 P6). The profile gives it the protocol's SPECIFIC shape; the invariant list
    tells it what recon ALREADY covers, so its novel hypotheses target the COMPLEMENT
    rather than restating a property the suite already owns (the failure we saw on
    Pendle, where P6 re-derived the ORAC-01 oracle-staleness lead)."""
    parts = [recon_profile_digest_block(
        profile_doc,
        header="## RECON PROFILE (the SPECIFIC mechanism — aim your novel hypotheses here)")]
    inv_block = recon_invariants_block(
        invariants,
        header="## ALREADY COVERED BY RECON (invariant suite — do NOT restate these; "
               "find the orthogonal COMPLEMENT)")
    if inv_block:
        parts.append(inv_block)
    return "\n\n".join(p for p in parts if p)


def threat_dossier_block(candidates: list[dict] | None) -> str:
    """Render the Threat-Research candidate leads for the Recon SYNTHESIS session. These
    are INTELLIGENCE, not scheduled tasks: synthesis carries each distinct one forward
    into the unified queue (origin="threat_research"), folding only true duplicates."""
    if not candidates:
        return ""
    lines = ["## THREAT-RESEARCH DOSSIER (candidate novel leads — carry each distinct one "
             "forward as origin=\"threat_research\"; fold only true duplicates)"]
    for c in candidates:
        tid = c.get("task_id", "?")
        vc = c.get("vuln_class", "")
        vc = vc.value if hasattr(vc, "value") else str(vc)
        title = (c.get("title") or "").strip().replace("\n", " ")
        hyp = (c.get("hypothesis") or "").strip().replace("\n", " ")
        scope = (c.get("scope_hint") or "").strip().replace("\n", " ")
        if len(hyp) > 200:
            hyp = hyp[:200] + "…"
        lines.append(f"  - [{tid}] ({vc}) {title}")
        if scope:
            lines.append(f"      scope: {scope}")
        if hyp:
            lines.append(f"      hypothesis: {hyp}")
    return "\n".join(lines)


def spec_profile_block(spec_invariants: list[dict] | None) -> str:
    """The 'spec profile' fed INTO the code-recon EXPLORE session
    (``recon.synthesis_mode``): the documented promises the Spec-Research agent (P2)
    extracted, so recon explores the code WITH the protocol's stated intent in hand and
    can flag a promise the code may not keep (the spec-vs-code gap). Built from the
    persisted intent invariants (origin="spec" / SPEC- ids)."""
    return recon_invariants_block(
        spec_invariants,
        header="## SPEC PROFILE — DOCUMENTED PROMISES (P2 intent invariants; reconcile "
               "each against the code as you explore — a promise with no enforcing code "
               "path is a prime lead)")


def build_threat_researcher_system(
    target: Target | None,
    repo_ref: str | None,
    tools_doc: str,
    emitters: list[Emitter],
    *,
    profile_block: str = "",
) -> str:
    """System prompt for the Threat-Research agent (Tier-4 P6, ``mode="research"``):
    SCOPE + the (web-enabled) research TOOLS + the threat-research methodology + the
    recon profile (the SPECIFIC mechanism, so its hypotheses are protocol-aimed) + the
    REQUIRED HunterTask emitter. It researches RECENT attack techniques (latest hacks /
    audit findings / papers) and the target's own mechanism and proposes
    protocol-specific, OFF-CHECKLIST hypotheses (deliberately NOT SC-Top-10-shaped) as
    exploratory ``HunterTask``s (``origin="threat_research"``). Its OUTPUT is bound to
    the in-scope code downstream; it never marks an external source in-scope."""
    return _compose(target, repo_ref, tools_doc, "threat_researcher", emitters,
                    profile_block)


def _catalog_seeds_block() -> str:
    """The invariant-catalog seeds block (wire matching ones first), or '' if none."""
    from ..tools.invariant_catalog import invariant_catalog

    seeds = invariant_catalog(None)
    if not seeds:
        return ""
    slim = [
        {k: s.get(k) for k in ("id", "library", "categories", "seeds_invariants", "tool")}
        for s in seeds
    ]
    return "## CATALOG SEEDS (wire matching ones first)\n" + json.dumps(slim, indent=1)


# Phase-specific context (recon.synthesis_mode): EXPLORE needs the invariant/profile
# grounding (slither + incident catalog + seeds); SYNTHESIS needs the task-shaping
# taxonomy (attack classes + cross-contract/dep + governance + incentive).
def _recon_explore_blocks(initialized_tools: list[str] | None, sast: dict | None) -> list[str]:
    return [sast_block(initialized_tools, sast), incident_block(), _catalog_seeds_block()]


def _recon_synthesis_blocks() -> list[str]:
    return [incident_block(), attack_class_block(), cross_contract_block(),
            governance_block(), incentive_block()]


def build_recon_system(
    target: Target | None,
    repo_ref: str | None,
    tools_doc: str,
    emitters: list[Emitter],
    initialized_tools: list[str] | None = None,
    sast: dict | None = None,
) -> str:
    """System prompt for the LEGACY single-session Recon agent (explore → profile →
    invariants → ranked tasks). Carries the invariant context injections
    (initialized tools + slither findings + the full incident catalog + catalog
    seeds) so the one agent formalizes invariants and then ranks tasks against
    them — it classifies the contract types itself, so the incident block is
    rendered unfiltered with ``applies_to`` for the agent to match. Used when
    ``recon.synthesis_mode`` is off; otherwise the two builders below split it."""
    extra = [*_recon_explore_blocks(initialized_tools, sast),
             attack_class_block(), cross_contract_block(), governance_block(),
             incentive_block()]
    return _compose(target, repo_ref, tools_doc, "recon", emitters, *extra)


_RECON_EXPLORE_DIRECTIVE = (
    "## PHASE — EXPLORE & FORMALIZE (Deliverables 1 & 2 ONLY; do NOT emit tasks)\n"
    "Recon runs in TWO sessions. THIS session produces ONLY (1) the Recon profile and "
    "(2) the invariant suite. Do NOT author the HunterTask queue here — a second, "
    "fully-informed SYNTHESIS session creates the single ranked queue with your profile, "
    "your invariants, AND a threat-research dossier all in hand. Spend this session being "
    "exhaustive on architecture, hotzones, accounting hooks, trust assumptions, the "
    "protocol graph, and a thorough invariant suite. Follow Deliverables 1 and 2 of the "
    "methodology below; IGNORE Deliverable 3 (tasks) entirely this session."
)
_RECON_SYNTHESIS_DIRECTIVE = (
    "## PHASE — TASK SYNTHESIS (author the ONE unified HunterTask queue)\n"
    "You have ALREADY explored the codebase and formalized the invariant suite (both are "
    "provided below as RECON PROFILE and INVARIANT SUITE), and a threat-research pass has "
    "proposed off-checklist candidate leads (THREAT-RESEARCH DOSSIER below). Your SOLE job "
    "now is to emit the single, comprehensive, de-duplicated, unified-ranked HunterTask "
    "queue, drawing on ALL of these sources at once. Follow the Deliverable-3 task taxonomy "
    "below. RULES:\n"
    " - CARRY FORWARD every distinct threat-research candidate as a task with "
    "origin=\"threat_research\", preserving its hypothesis + cited precedent. Fold ONLY true "
    "duplicates (same vuln-class AND same code region). When a candidate overlaps an "
    "invariant-driven task, KEEP the novel framing and link it — never silently drop novelty.\n"
    " - For each high/critical invariant above, emit a breaking task with its inv_id set.\n"
    " - Cover the full attack-class taxonomy + cross-contract/dep/governance/incentive tasks.\n"
    " - Set a real, discriminating priority 1..4 (do not mark everything P1). Use "
    "code-index / Read to re-anchor any scope_hint you are unsure of — you may read code to "
    "VERIFY, but you are SYNTHESIZING from the material below, not re-exploring."
)


def build_recon_explore_system(
    target: Target | None,
    repo_ref: str | None,
    tools_doc: str,
    emitters: list[Emitter],
    initialized_tools: list[str] | None = None,
    sast: dict | None = None,
    *,
    spec_profile: str = "",
) -> str:
    """Phase-1 prompt for the split Recon (``recon.synthesis_mode``): explore + profile +
    invariants, NO tasks. Fed the spec profile (P2 documented promises) so it reconciles
    code against stated intent. Emitters are profile+invariant only, so the Stop hook does
    not require tasks."""
    extra = [_RECON_EXPLORE_DIRECTIVE, spec_profile,
             *_recon_explore_blocks(initialized_tools, sast)]
    return _compose(target, repo_ref, tools_doc, "recon", emitters, *extra)


def build_recon_synthesis_system(
    target: Target | None,
    repo_ref: str | None,
    tools_doc: str,
    emitters: list[Emitter],
    *,
    profile_block: str = "",
    invariants_block: str = "",
    threat_dossier: str = "",
) -> str:
    """Phase-2 prompt for the split Recon (``recon.synthesis_mode``): the SOLE author of
    the unified HunterTask queue, fed the recon profile digest + the full invariant suite +
    the threat-research dossier. Emitter is the task emitter only. Reuses the recon
    methodology body (for the Deliverable-3 task taxonomy) plus the task-shaping blocks."""
    extra = [_RECON_SYNTHESIS_DIRECTIVE, profile_block, invariants_block, threat_dossier,
             *_recon_synthesis_blocks()]
    return _compose(target, repo_ref, tools_doc, "recon", emitters, *extra)
