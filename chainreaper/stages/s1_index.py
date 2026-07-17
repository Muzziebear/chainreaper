"""S1 · Index (spec §6, IMPL-NOTES §3-§5).

Compile + statically analyze each in-scope repo with Slither and persist the
structural model to the per-run SQLite index. Agents (S2+) query it via the
`code_index` tool. For the slice, Solidity-only via Slither (tree-sitter
enrichment deferred).
"""

from __future__ import annotations

from pathlib import Path

from ..index.build import build_index


def run(ctx) -> dict:
    target = ctx.target
    if target is None:
        raise RuntimeError("S1: no Target in state (S0 must run first)")

    # Candidate indexable assets (the cloned source). S0 may hand S1 *several* clones
    # (an Immunefi org expands to many repos); URL-form github_repo assets are provenance.
    candidates = []
    for asset in target.assets_in_scope:
        if not asset.in_scope or asset.kind not in ("local_path", "github_repo"):
            continue
        target_dir = Path(asset.ref)
        if asset.kind == "github_repo" and not target_dir.exists():
            continue  # provenance URL — the clone is a separate local_path asset
        if not target_dir.exists():
            raise FileNotFoundError(f"S1: in-scope asset path not found: {target_dir}")
        candidates.append(target_dir)

    if not candidates:
        raise RuntimeError("S1: no in-scope local/github repos to index")

    db_path = ctx.index_dir / "index.db"
    timeout = int(ctx.config.get("runtime", {}).get("default_timeout_s", 1800))
    repos, failures = [], []
    for target_dir in candidates:
        try:
            # reset the shared index on the first SUCCESSFULLY-indexed unit, then
            # accumulate the rest (a Target can have many in-scope units — per-address
            # verified-source units, or several cloned repos).
            repos.append(build_index(target_dir.name, target_dir, db_path,
                                     timeout=timeout, reset=not repos))
        except Exception as exc:  # a superset clone may include repos that don't compile
            # standalone (truffle/hardhat needing npm install, mismatched solc, etc.).
            # Index whatever compiles; only fail the stage if NOTHING did.
            failures.append({"repo": target_dir.name, "error": f"{type(exc).__name__}: {str(exc)[:300]}"})

    if not repos:
        detail = "; ".join(f"{f['repo']}: {f['error']}" for f in failures)
        raise RuntimeError(
            f"S1: no in-scope repo could be indexed ({len(failures)} failed). "
            f"Each needs a buildable toolchain (npm install / matching solc). {detail}")

    return {"stage": "s1", "status": "ok" if not failures else "partial",
            "repos": repos, "failures": failures,
            "index_db": str(ctx.index_dir / "index.db")}
