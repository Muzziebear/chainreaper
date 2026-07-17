"""Fork-RPC discovery (spec §S0 / §S4 fork preflight, brought forward to Discovery).

S4's live ``createSelectFork`` PoCs pull real on-chain state, so each in-scope chain
needs a reachable RPC — ideally an **archive** node (a fork lazily reads state at its base
block; on a fast chain a non-archive node prunes that block within seconds, so a sustained
fork 403s mid-test). Rather than discover this only at hunt time, S0 resolves it up front so
the operator can confirm the RPC plan *before* indexing.

Per in-scope chain, resolve a candidate URL in priority order — ``<CHAIN>_RPC_URL`` env /
keystore → ``hunt.fork.rpc_urls`` config → a built-in list of known PUBLIC endpoints we
probe ourselves — then classify it (reachable? chainId match? archive-capable?). Where no
archive endpoint is available, the chain is flagged ``needs_key`` so the operator can supply
one (Alchemy/Infura free tier) and the harness waits.

The probe is the same injectable seam as ``runtime.fork`` (``default_prober``), so resolution
+ classification are unit-tested offline with ZERO network. URLs are REDACTED to host on
serialization (a provider key in the URL never lands in a checkpoint).
"""

from __future__ import annotations

import urllib.parse
from dataclasses import dataclass
from typing import Callable, Mapping

from ..runtime.fork import KNOWN_CHAIN_IDS, ProbeResult, default_prober

# Known public RPC endpoints per chain (probed in order; first reachable+matching wins).
# Public nodes are typically NON-archive (latest-only) — the probe tells archive from full.
KNOWN_PUBLIC_RPCS: dict[str, list[str]] = {
    "ethereum": ["https://ethereum-rpc.publicnode.com", "https://eth.llamarpc.com",
                 "https://rpc.ankr.com/eth", "https://cloudflare-eth.com"],
    "arbitrum": ["https://arbitrum-one.publicnode.com", "https://arb1.arbitrum.io/rpc",
                 "https://1rpc.io/arb"],
    "polygon": ["https://polygon-bor-rpc.publicnode.com", "https://polygon-rpc.com",
                "https://1rpc.io/matic"],
    "avalanche": ["https://avalanche-c-chain-rpc.publicnode.com",
                  "https://api.avax.network/ext/bc/C/rpc"],
    "base": ["https://base-rpc.publicnode.com", "https://mainnet.base.org"],
    "optimism": ["https://optimism-rpc.publicnode.com", "https://mainnet.optimism.io"],
    "bsc": ["https://bsc-rpc.publicnode.com", "https://binance.llamarpc.com"],
}

# status values (most → least usable for a fork PoC)
READY_ARCHIVE = "configured_archive"     # operator/config URL, serves deep historical state
READY_LATEST = "configured_latest"       # operator/config URL, latest-only (no archive)
PUBLIC_ARCHIVE = "public_archive"        # a known public endpoint that IS archive (rare)
PUBLIC_LATEST = "public_latest"          # a known public endpoint, latest-only
NEEDS_KEY = "needs_key"                   # nothing reachable → operator must supply an RPC
UNREACHABLE = "unreachable"              # a configured URL that didn't answer
CHAIN_MISMATCH = "chain_mismatch"        # answered, but wrong chainId


def _host(url: str | None) -> str:
    if not url:
        return ""
    try:
        return urllib.parse.urlparse(url).hostname or ""
    except ValueError:
        return "?"


@dataclass
class ChainRpc:
    chain: str
    status: str
    source: str                      # env | config | public | none
    url: str | None = None           # full URL (in-memory for the run; redacted on serialize)
    chain_id: int | None = None
    chain_id_expected: int | None = None
    archive: bool | None = None
    detail: str = ""

    @property
    def fork_ready(self) -> bool:
        """Reachable enough to fork at all (latest at minimum)."""
        return self.status in (READY_ARCHIVE, READY_LATEST, PUBLIC_ARCHIVE, PUBLIC_LATEST)

    @property
    def archive_ready(self) -> bool:
        """Can sustain a historical / long-running fork PoC."""
        return self.archive is True and self.fork_ready

    def to_dict(self) -> dict:
        # redact the URL to host — it may carry a provider key.
        return {"chain": self.chain, "status": self.status, "source": self.source,
                "host": _host(self.url), "chain_id": self.chain_id,
                "chain_id_expected": self.chain_id_expected, "archive": self.archive,
                "fork_ready": self.fork_ready, "archive_ready": self.archive_ready,
                "detail": self.detail}


def _classify(source: str, probe: ProbeResult, expected: int | None) -> tuple[str, str]:
    if not probe.reachable:
        return (UNREACHABLE if source in ("env", "config") else NEEDS_KEY,
                probe.detail or "endpoint not reachable")
    if expected is not None and probe.chain_id is not None and probe.chain_id != expected:
        return CHAIN_MISMATCH, f"endpoint chainId {probe.chain_id} != expected {expected}"
    if source in ("env", "config"):
        return (READY_ARCHIVE if probe.archive else READY_LATEST,
                "archive node" if probe.archive else "reachable, latest-only (non-archive)")
    return (PUBLIC_ARCHIVE if probe.archive else PUBLIC_LATEST,
            "public archive node" if probe.archive else "public node, latest-only (non-archive)")


def resolve_chain_rpc(
    chain: str,
    *,
    env: Mapping,
    config_rpcs: Mapping,
    probe_public: bool = True,
    timeout: float = 6.0,
    prober: Callable[[str, float], ProbeResult] = default_prober,
) -> ChainRpc:
    """Resolve + probe the best RPC for one chain. env > config > known public list."""
    chain = chain.lower()
    expected = KNOWN_CHAIN_IDS.get(chain)

    url = env.get(f"{chain.upper()}_RPC_URL")
    source = "env" if url else ""
    if not url:
        cfg = config_rpcs.get(chain) or config_rpcs.get(chain.lower())
        if cfg:
            url, source = str(cfg), "config"

    if url:
        probe = prober(url, timeout)
        status, detail = _classify(source, probe, expected)
        return ChainRpc(chain=chain, status=status, source=source, url=url,
                        chain_id=probe.chain_id, chain_id_expected=expected,
                        archive=probe.archive, detail=detail)

    if probe_public:
        best: ChainRpc | None = None
        for cand in KNOWN_PUBLIC_RPCS.get(chain, []):
            probe = prober(cand, timeout)
            status, detail = _classify("public", probe, expected)
            rpc = ChainRpc(chain=chain, status=status, source="public", url=cand,
                           chain_id=probe.chain_id, chain_id_expected=expected,
                           archive=probe.archive, detail=detail)
            if rpc.archive_ready:        # archive public node — take it immediately
                return rpc
            if rpc.fork_ready and best is None:
                best = rpc               # remember a latest-only fallback, keep looking for archive
        if best is not None:
            return best

    return ChainRpc(chain=chain, status=NEEDS_KEY, source="none",
                    chain_id_expected=expected,
                    detail=f"no reachable RPC; set {chain.upper()}_RPC_URL "
                           "(archive node for historical fork PoCs)")


def resolve_fork_rpcs(
    chains: list[str],
    *,
    env: Mapping,
    config_rpcs: Mapping | None = None,
    probe_public: bool = True,
    timeout: float = 6.0,
    prober: Callable[[str, float], ProbeResult] = default_prober,
) -> list[ChainRpc]:
    """Resolve every in-scope chain (deduped, order-preserving)."""
    config_rpcs = config_rpcs or {}
    seen: set[str] = set()
    out: list[ChainRpc] = []
    for c in chains:
        cl = str(c).strip().lower()
        if not cl or cl in seen:
            continue
        seen.add(cl)
        out.append(resolve_chain_rpc(cl, env=env, config_rpcs=config_rpcs,
                                     probe_public=probe_public, timeout=timeout, prober=prober))
    return out


def summarize(rpcs: list[ChainRpc]) -> str:
    """One-line-per-chain operator summary (hosts only, never keys)."""
    if not rpcs:
        return "no in-scope chains to fork"
    lines = []
    for r in rpcs:
        tag = {
            READY_ARCHIVE: "✓ archive", READY_LATEST: "✓ latest-only (needs archive key for historical PoCs)",
            PUBLIC_ARCHIVE: "✓ public archive", PUBLIC_LATEST: "~ public latest-only (needs archive key for historical PoCs)",
            NEEDS_KEY: "✗ needs RPC key", UNREACHABLE: "✗ configured URL unreachable",
            CHAIN_MISMATCH: "✗ wrong chainId",
        }.get(r.status, r.status)
        where = f" [{_host(r.url)}]" if r.url else ""
        lines.append(f"  {r.chain:10s} {tag}{where}")
    return "\n".join(lines)
