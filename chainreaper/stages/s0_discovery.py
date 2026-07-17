"""S0 · Discovery (spec §S0) — turn an operator intent into a concrete ``Target`` +
a materialized, in-scope ``workspace/`` that S1 can index.

Three entry modes, branched on the resolved ``--target`` reference:

  * **Immunefi** (slug or program URL) — fetch + merge the program's three tabs
    (``information``/``scope``/``resources``), clone the in-scope source repos, map the
    in-scope contract NAMES → source files (the allowlist), and assemble a ``Target``
    whose ``local_path`` clone assets S1 indexes while the allowlist keeps S2+ inside the
    in-scope subset of the superset repo.
  * **repo URL** — clone a bare git repo; the whole repo is in scope (no Immunefi scope).
  * **local path** — the offline/dev fallback (hand-built ``Target`` from a repo already
    on disk, e.g. ``gmx-source/``); no Immunefi fetch, no clone.

Deterministic + host-only network egress (spec §17); never executes target code. The
``discover`` board+ranking path lives in ``cli.discover`` (it selects a slug, then this
stage runs in Immunefi mode under ``scan``).
"""

from __future__ import annotations

import os
from pathlib import Path

from ..models import ScopeAsset, Target
from ..runtime.logging import get_logger
from ..targets import immunefi_client as imc
from ..targets import source_resolver as sr

log = get_logger()

# Known-target metadata so a hand-built (local-path) Target still carries useful
# Discovery fields (used by Recon/ranking later). Keyed by resolved path basename.
_KNOWN: dict[str, dict] = {
    "gmx-synthetics": {
        "program_id": "gmx",
        "name": "GMX V2 (Synthetics)",
        "url": "https://immunefi.com/bug-bounty/gmx/",
        "max_bounty_usd": 5_000_000.0,
        "chains": ["arbitrum", "avalanche"],
        "languages": ["solidity"],
        "impacts": [
            "Direct theft of user funds",
            "Permanent freezing of funds",
            "Protocol insolvency",
        ],
    },
    "gmx-contracts": {
        "program_id": "gmx",
        "name": "GMX V1",
        "url": "https://immunefi.com/bug-bounty/gmx/",
        "max_bounty_usd": 5_000_000.0,
        "chains": ["arbitrum", "avalanche"],
        "languages": ["solidity"],
        "impacts": ["Direct theft of user funds", "Permanent freezing of funds"],
    },
}


# --------------------------------------------------------------------------- #
# Config helpers                                                                #
# --------------------------------------------------------------------------- #
def _discovery_cfg(ctx) -> dict:
    return dict(ctx.config.get("discovery", {}) or {})


def _cache_dir(ctx) -> str:
    return _discovery_cfg(ctx).get("cache_dir", "runs/_targets")


def _explorer_key(ctx) -> str | None:
    """Etherscan V2 key — env first (never persisted to a tracked file), then config.
    One free key covers every chain."""
    keys = _discovery_cfg(ctx).get("explorer_api_keys", {}) or {}
    return (os.environ.get("ETHERSCAN_API_KEY")
            or keys.get("etherscan") or keys.get("ethereum"))


# --------------------------------------------------------------------------- #
# Mode: local path (offline/dev fallback — the original stub)                   #
# --------------------------------------------------------------------------- #
def _run_local(path: Path) -> Target:
    meta = _KNOWN.get(path.name, {})
    return Target(
        program_id=meta.get("program_id", path.name),
        name=meta.get("name", path.name),
        url=meta.get("url", ""),
        max_bounty_usd=meta.get("max_bounty_usd"),
        assets_in_scope=[
            ScopeAsset(
                kind="local_path",
                ref=str(path),
                in_scope=True,
                impacts_in_scope=meta.get("impacts", []),
                name=path.name,
            )
        ],
        chains=meta.get("chains", []),
        languages=meta.get("languages", ["solidity"]),
        program_type="smart_contract",
    )


# --------------------------------------------------------------------------- #
# Mode: bare repo URL (whole repo in scope)                                     #
# --------------------------------------------------------------------------- #
def _run_repo(ctx, url: str) -> Target:
    opts = ctx.target_opts or {}
    clones = sr.clone_sources([url], ctx.workspace, commit=opts.get("commit"))
    ok = [c for c in clones if c.ok]
    if not ok:
        detail = "; ".join(c.detail for c in clones)
        raise RuntimeError(f"S0: failed to clone repo {url}: {detail}")
    assets = sr.clones_to_assets(ok)
    return Target(
        program_id=ok[0].name,
        name=ok[0].name,
        url=url,
        assets_in_scope=assets,
        languages=["solidity"],
        program_type="smart_contract",
    )


# --------------------------------------------------------------------------- #
# Mode: Immunefi (slug or program URL)                                          #
# --------------------------------------------------------------------------- #
def _source_policy(ctx, has_addresses: bool, api_key: str | None) -> str:
    """Decide what the in-scope source of truth is (spec §S0 / source_policy):

      * ``explorer`` — the verified DEPLOYED source at the in-scope addresses IS the
        in-scope code (exact, self-contained, no superset, no npm/truffle build). Repo is
        context + fallback. Default for address-scoped programs when a key is available.
      * ``repo`` — the cloned source repo is the in-scope code (pre-launch / repo-scoped
        programs, or no explorer key).
    """
    policy = str((ctx.target_opts or {}).get("source_policy")
                 or _discovery_cfg(ctx).get("source_policy") or "auto").lower()
    if policy == "explorer":
        return "explorer"
    if policy == "repo":
        return "repo"
    return "explorer" if (has_addresses and api_key) else "repo"  # auto


def _run_immunefi(ctx, slug: str) -> Target:
    opts = ctx.target_opts or {}
    refresh = bool(opts.get("refresh"))
    # CLI --allow-kyc/--no-allow-kyc wins when set; otherwise the config default
    # (discovery.filters.allow_kyc, now true) decides — KYC only gates payout, not research.
    allow_kyc = opts.get("allow_kyc")
    if allow_kyc is None:
        allow_kyc = bool(ctx.config.get("discovery", {}).get("filters", {}).get("allow_kyc", True))

    program = imc.fetch_program(slug, refresh=refresh, cache_dir=_cache_dir(ctx))
    if program.kyc_required and not allow_kyc:
        raise RuntimeError(
            f"S0: program {slug!r} requires KYC — excluded by config "
            "discovery.filters.allow_kyc=false (or --no-allow-kyc).")

    target = imc.program_to_target(program)
    contract_assets = [a for a in target.assets_in_scope if a.kind == "contract_address"]
    has_addrs = any(a.address and a.network for a in contract_assets)
    api_key = _explorer_key(ctx)
    policy = _source_policy(ctx, has_addrs, api_key)

    # Clone the repos in BOTH modes: in repo-mode they're the in-scope source; in
    # explorer-mode they're context + the fallback for any unverified address. Immunefi
    # often lists a GitHub ORG URL → expand it to the org's Solidity repos first.
    good: list[sr.CloneResult] = []
    if program.repos:
        repos = sr.expand_repo_refs(program.repos)
        good = [c for c in sr.clone_sources(repos, ctx.workspace, commit=opts.get("commit")) if c.ok]

    if policy == "explorer":
        if not api_key:
            raise RuntimeError("S0: source_policy=explorer needs an Etherscan key "
                               "(set ETHERSCAN_API_KEY or discovery.explorer_api_keys).")
        pause = float(_discovery_cfg(ctx).get("explorer_rate_delay_s", 0.25))
        units, unresolved = sr.materialize_verified_sources(
            contract_assets, ctx.workspace, api_key, pause=pause)
        if not units:
            raise RuntimeError(
                f"S0: no verified deployed source resolved for {slug!r} "
                f"({len(unresolved)} addresses unverified). Set source_policy=repo to use the repo.")
        # The verified units are the indexed in-scope set; the repo clones stay in the
        # workspace as context (NOT added as indexable assets → S1 indexes only in-scope).
        target.assets_in_scope.extend(sr.verified_units_to_assets(units, program.impacts_in_scope))
        target.scope_allowlist = sr.verified_allowlist(contract_assets, units, good)
    else:
        if not good:
            raise RuntimeError(f"S0: no in-scope repo cloned for {slug!r} and no verified-source key.")
        target.assets_in_scope.extend(sr.clones_to_assets(good, program.impacts_in_scope))
        target.scope_allowlist = sr.map_scope_to_source(contract_assets, good)

    return target


# --------------------------------------------------------------------------- #
# Fork-RPC discovery (spec §S0 — surfaced for operator confirmation before S1)   #
# --------------------------------------------------------------------------- #
def _in_scope_chains(target: Target) -> list[str]:
    """Chains the in-scope assets actually live on (allowlist networks first, then the
    program's declared chains). These are the chains an S4 fork PoC must reach."""
    chains: list[str] = []
    for c in target.scope_allowlist:
        if c.network and c.network not in chains:
            chains.append(c.network)
    for a in target.assets_in_scope:
        if a.kind == "contract_address" and a.network and a.network not in chains:
            chains.append(a.network)
    for c in target.chains:
        cl = str(c).strip().lower()
        if cl and cl not in chains:
            chains.append(cl)
    return chains


def _discover_forks(ctx, target: Target) -> None:
    """Resolve + probe a fork RPC per in-scope chain and attach a redacted preview to the
    Target (so the operator can confirm RPC coverage before indexing). Skippable +
    bounded; never raises (a discovery convenience, not a hard gate)."""
    fork_cfg = (ctx.config.get("hunt", {}) or {}).get("fork", {}) or {}
    disc_cfg = _discovery_cfg(ctx)
    if not disc_cfg.get("fork_discovery", True):
        return
    chains = _in_scope_chains(target)
    if not chains:
        return
    try:
        from ..targets import rpc_resolver as rr
        rpcs = rr.resolve_fork_rpcs(
            chains, env=os.environ, config_rpcs=fork_cfg.get("rpc_urls") or {},
            probe_public=bool(disc_cfg.get("fork_probe_public", True)),
            timeout=float(fork_cfg.get("probe_timeout_s", 6)))
        target.fork_preview = [r.to_dict() for r in rpcs]
        log.info("[s0] fork-RPC discovery (in-scope chains):")
        for line in rr.summarize(rpcs).splitlines():
            log.info("%s", line)
        need = [r.chain for r in rpcs if r.status == rr.NEEDS_KEY]
        latest = [r.chain for r in rpcs if r.status in (rr.PUBLIC_LATEST, rr.READY_LATEST)]
        if need:
            log.info("[s0] ACTION: set <CHAIN>_RPC_URL (archive) for: %s "
                     "— e.g. `chainreaper secret set %s_RPC_URL <url>` (waits until provided).",
                     ", ".join(need), need[0].upper())
        if latest:
            log.info("[s0] NOTE: %s reachable but NON-archive — fine for latest-block PoCs; "
                     "historical/sustained fork PoCs need an archive key.", ", ".join(latest))
    except Exception as exc:  # discovery must never break Discovery
        log.info("[s0] fork-RPC discovery skipped: %s: %s", type(exc).__name__, exc)


# --------------------------------------------------------------------------- #
# Entry                                                                         #
# --------------------------------------------------------------------------- #
def run(ctx) -> dict:
    if not ctx.target_ref:
        raise ValueError("S0: no --target provided")
    ref = imc.resolve_ref(ctx.target_ref)

    if ref.kind == "local_path":
        target = _run_local(Path(ref.value))
    elif ref.kind in ("slug", "immunefi_url"):
        if not ref.slug:
            raise ValueError(f"S0: could not parse an Immunefi slug from {ctx.target_ref!r}")
        target = _run_immunefi(ctx, ref.slug)
    elif ref.kind == "repo_url":
        target = _run_repo(ctx, ref.value)
    else:
        raise ValueError(f"S0: unsupported target reference kind: {ref.kind}")

    _discover_forks(ctx, target)
    return target.model_dump(mode="json")
