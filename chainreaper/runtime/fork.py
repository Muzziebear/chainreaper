"""Fork preflight (spec §S4 step 5, §10, §17) — resolve + validate + pin a fork RPC
per chain before the Hunters spawn, optionally fronting it with one shared ``anvil``
fork (cache- and rate-limit-friendly), and **degrade cleanly** to local-only when no
endpoint is configured/reachable.

Forking is the one irreducibly-external dependency: ``vm.createSelectFork`` /
``anvil --fork-url`` pull real on-chain state over the network, so a real RPC
endpoint + egress are required (a *latest*-block fork needs only a full node; an old
pinned block needs an archive node). Everything *around* that is deterministic and
lives here:

  * **resolve** each chain's URL from ``hunt.fork.rpc_urls`` or ``<CHAIN>_RPC_URL``;
  * **validate** it (reachable + ``eth_chainId`` matches) — fail fast, never hang;
  * **pin a block** (explicit, or the probed latest) for reproducible PoCs;
  * **shared anvil** (host backend): one ``anvil --fork-url … --fork-block-number …``
    per chain so every hunter hits a local node (Foundry's RPC cache is reused, the
    upstream isn't hammered) — hunters point at ``http://127.0.0.1:<port>``;
  * **export** ``<CHAIN>_RPC_URL`` (what foundry.toml's ``[rpc_endpoints]`` reads) and
    a checkpointable ``ForkPlan``.

The network probe + the anvil launch are injectable seams (``prober`` /
``anvil_launcher``), so the resolution/planning/degrade logic is unit-tested offline
with ZERO network and ZERO token spend. This never sends transactions to live
protocol state — fork simulation only (spec §17).
"""

from __future__ import annotations

import json
import os
import subprocess
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Mapping

from .exec import augmented_env
from .logging import get_logger

log = get_logger()

# chain name → canonical chainId (for the validate step). Override via hunt.fork.chain_ids.
KNOWN_CHAIN_IDS: dict[str, int] = {
    "ethereum": 1, "mainnet": 1,
    "arbitrum": 42161, "arbitrum_one": 42161, "arbitrum-one": 42161,
    "avalanche": 43114, "avax": 43114,
    "base": 8453, "optimism": 10, "op": 10,
    "polygon": 137, "bsc": 56, "bnb": 56,
    "gnosis": 100, "sepolia": 11155111,
    "sonic": 146,
}


# --------------------------------------------------------------------------- #
# Probe seam (network)                                                          #
# --------------------------------------------------------------------------- #
@dataclass
class ProbeResult:
    reachable: bool
    chain_id: int | None = None
    block_number: int | None = None
    archive: bool | None = None   # serves deep historical state (needed for a stable fork)
    detail: str = ""


def _rpc_call(url: str, method: str, params: list, timeout: float):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    # many public RPCs reject a blank User-Agent with HTTP 403 — always send one.
    req = urllib.request.Request(url, data=body, headers={
        "Content-Type": "application/json", "User-Agent": "chainreaper/0.1"})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (operator-supplied RPC)
        data = json.loads(r.read())
    if isinstance(data, dict) and data.get("error"):
        raise RuntimeError(str(data["error"]))
    return data["result"]


def default_prober(url: str, timeout: float) -> ProbeResult:
    """Real JSON-RPC probe (stdlib only): chainId + latest block + an archive check.
    Never raises — an unreachable/erroring endpoint comes back ``reachable=False``.

    The archive check matters because forking lazily reads state AT the fork's base
    block; on a fast chain a non-archive node prunes that block within seconds, so
    the fork 403s mid-test. We probe deep historical state (``eth_getBalance`` ~100k
    blocks back) to tell a true archive node from a latest-only full node."""
    try:
        cid = int(_rpc_call(url, "eth_chainId", [], timeout), 16)
        bn = int(_rpc_call(url, "eth_blockNumber", [], timeout), 16)
        archive: bool | None = None
        if bn > 100_000:
            try:
                _rpc_call(url, "eth_getBalance",
                          ["0x0000000000000000000000000000000000000001", hex(bn - 100_000)], timeout)
                archive = True
            except Exception:
                archive = False  # full/non-archive node (or restricted historical access)
        return ProbeResult(reachable=True, chain_id=cid, block_number=bn, archive=archive)
    except Exception as exc:  # connection / timeout / bad JSON / RPC error
        return ProbeResult(reachable=False, detail=f"{type(exc).__name__}: {str(exc)[:160]}")


# --------------------------------------------------------------------------- #
# Anvil seam (process)                                                          #
# --------------------------------------------------------------------------- #
@dataclass
class AnvilHandle:
    serve_url: str
    pid: int
    _proc: subprocess.Popen | None = None
    _logf: object = None        # open file object for anvil's output (closed on kill)
    _log_path: str | None = None  # path to scrub on teardown
    _secret: str | None = None  # the upstream URL to redact from the log

    def kill(self) -> None:
        if self._proc and self._proc.poll() is None:
            try:
                self._proc.terminate()
                try:
                    self._proc.wait(8)
                except subprocess.TimeoutExpired:
                    self._proc.kill()
            except OSError:
                pass
        if self._logf is not None:
            try:
                self._logf.close()
            except OSError:
                pass
        _scrub_log(self._log_path, self._secret)


def _scrub_log(log_path: str | None, secret: str | None) -> None:
    """Defense-in-depth: redact the upstream URL (which carries the API key) from
    anvil's log, in case any output slipped past ``--silent``."""
    if not log_path or not secret:
        return
    try:
        p = Path(log_path)
        if not p.exists():
            return
        text = p.read_text(errors="replace")
        if secret in text:
            host = urllib.parse.urlparse(secret).hostname or "upstream"
            p.write_text(text.replace(secret, f"<redacted-rpc:{host}>"))
    except OSError:
        pass


# Resilient defaults for forking a public/rate-limited node: longer per-request
# timeout + retries so anvil's startup block fetch doesn't fail on a slow upstream.
_ANVIL_DEFAULT_ARGS = ["--timeout", "20000", "--retries", "8"]


def default_anvil_launcher(chain: str, url: str, block: int | None, port: int,
                           *, ready_timeout: float = 90.0,
                           extra_args: list[str] | None = None,
                           log_path: str | None = None) -> AnvilHandle | None:
    """Launch a shared ``anvil`` fork on ``port`` and wait until it answers. Returns
    None if ``anvil`` is unavailable or never comes up (caller serves upstream
    directly). Foundry's per-chain RPC cache makes the fork cheap to re-warm.

    ``ready_timeout`` is generous by default (90s) because anvil fetches the fork
    block from the upstream *before* it opens the port — a slow/rate-limited public
    node can take a while. anvil's stdout+stderr go to ``log_path`` (if given) so a
    launch failure is diagnosable instead of silent."""
    import shutil
    env = augmented_env()
    anvil = shutil.which("anvil", path=env.get("PATH"))
    if not anvil:
        log.info("[fork] anvil not on PATH — serving upstream directly for %s", chain)
        return None
    # --silent suppresses anvil's startup banner, which otherwise prints the
    # --fork-url (and thus any API key) into the captured log. Errors still surface.
    cmd = [anvil, "--fork-url", url, "--port", str(port), "--host", "127.0.0.1", "--silent"]
    if block is not None:
        cmd += ["--fork-block-number", str(block)]
    cmd += list(extra_args) if extra_args is not None else _ANVIL_DEFAULT_ARGS
    logf = None
    try:
        if log_path:
            logf = open(log_path, "wb")  # noqa: SIM115 (handle lives on AnvilHandle)
        proc = subprocess.Popen(cmd, env=env,
                                stdout=(logf or subprocess.DEVNULL),
                                stderr=(subprocess.STDOUT if logf else subprocess.DEVNULL))
    except OSError as exc:
        log.info("[fork] anvil failed to start for %s: %s", chain, exc)
        if logf:
            logf.close()
        return None
    serve = f"http://127.0.0.1:{port}"
    deadline = time.monotonic() + ready_timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:  # anvil died (bad URL / archive needed / rate-limited)
            log.info("[fork] anvil for %s exited during startup (rc=%s); see %s",
                     chain, proc.returncode, log_path or "(no log)")
            if logf:
                logf.close()
            _scrub_log(log_path, url)
            return None
        if default_prober(serve, 2.0).reachable:
            return AnvilHandle(serve_url=serve, pid=proc.pid, _proc=proc, _logf=logf,
                               _log_path=log_path, _secret=url)
        time.sleep(0.5)
    log.info("[fork] anvil for %s not ready after %ss — serving upstream directly (see %s)",
             chain, ready_timeout, log_path or "(no log)")
    proc.terminate()
    if logf:
        logf.close()
    _scrub_log(log_path, url)
    return None


# --------------------------------------------------------------------------- #
# Plan                                                                          #
# --------------------------------------------------------------------------- #
ForkStatus = str  # ready | local_only | unconfigured | unreachable | chain_mismatch


@dataclass
class ChainFork:
    chain: str
    status: ForkStatus
    serve_url: str | None = None          # what hunters use (local anvil OR upstream)
    upstream_url: str | None = None       # the resolved upstream (redacted in to_dict)
    chain_id: int | None = None           # probed
    chain_id_expected: int | None = None
    block: int | None = None              # pinned fork block
    archive: bool | None = None           # upstream serves deep historical state
    fronted_by_anvil: bool = False
    anvil_pid: int | None = None
    detail: str = ""

    @property
    def ready(self) -> bool:
        return self.status == "ready" and bool(self.serve_url)

    def to_dict(self) -> dict:
        # never persist the upstream URL (may carry a provider key) — redact to host.
        host = ""
        if self.upstream_url:
            try:
                host = urllib.parse.urlparse(self.upstream_url).hostname or ""
            except Exception:
                host = "?"
        return {
            "chain": self.chain, "status": self.status,
            "serve_url": self.serve_url if self.fronted_by_anvil else ("upstream" if self.ready else None),
            "upstream_host": host, "chain_id": self.chain_id,
            "chain_id_expected": self.chain_id_expected, "block": self.block,
            "archive": self.archive,
            "fronted_by_anvil": self.fronted_by_anvil, "detail": self.detail,
        }


@dataclass
class ForkPlan:
    backend: str
    chains: list[ChainFork] = field(default_factory=list)
    _handles: list[AnvilHandle] = field(default_factory=list)
    # canonical env vars we overwrote in apply_env → their prior values, so teardown
    # can restore them. Without this, S4 poisons ``<CHAIN>_RPC_URL`` with the local
    # shared-anvil URL; after teardown that dead URL leaks into S5's fork resolution
    # (``ethereum=unreachable``). ``None`` means the var was unset before we touched it.
    _env_saved: dict[str, str | None] = field(default_factory=dict)
    _env_target: dict | None = None

    def ready_chains(self) -> list[ChainFork]:
        return [c for c in self.chains if c.ready]

    @property
    def any_ready(self) -> bool:
        return bool(self.ready_chains())

    def env_exports(self) -> dict[str, str]:
        """``<CHAIN>_RPC_URL`` → the URL hunters' foundry.toml should resolve to (the
        shared anvil if fronted, else the upstream)."""
        out: dict[str, str] = {}
        for c in self.ready_chains():
            out[f"{c.chain.upper()}_RPC_URL"] = c.serve_url  # type: ignore[assignment]
        return out

    def apply_env(self, env: dict | None = None) -> list[str]:
        target = env if env is not None else os.environ
        self._env_target = target
        for k, v in self.env_exports().items():
            if k not in self._env_saved:          # remember the FIRST (pre-fork) value only
                self._env_saved[k] = target.get(k)
            target[k] = v
        return list(self.env_exports())

    def restore_env(self) -> None:
        """Undo apply_env: put each overwritten ``<CHAIN>_RPC_URL`` back to its prior
        value (or unset it if it had none). Prevents this run's local anvil URL from
        leaking into a later stage's (e.g. S5's) fork resolution."""
        target = self._env_target
        if target is None:
            return
        for k, prior in self._env_saved.items():
            if prior is None:
                target.pop(k, None)
            else:
                target[k] = prior
        self._env_saved.clear()
        self._env_target = None

    def hunter_note(self) -> str:
        """The FORK block injected into each Hunter prompt — which alias is live (+
        pinned block) or that none is, so it forks correctly or goes local-only."""
        ready = self.ready_chains()
        if not ready:
            why = "; ".join(f"{c.chain}: {c.status}" for c in self.chains) or "no chains configured"
            return (
                "## FORK STATUS — NO mainnet fork available (" + why + ")\n"
                "You CANNOT run a mainnet-fork test. Build the strongest LOCAL PoC you "
                "can — instantiate the real target source and drive a real public "
                "entrypoint to demonstrate impact — and state in your outcome that live "
                "fork-validation is pending an RPC. Do NOT invent a fork."
            )
        lines = ["## FORK STATUS — mainnet fork is LIVE"]
        for c in ready:
            front = "shared anvil (local, cached)" if c.fronted_by_anvil else "upstream RPC"
            where = (f"pinned at block {c.block}" if c.block is not None
                     else "at the node's latest block")
            tail = ("Pin this block number in your PoC for reproducibility."
                    if c.block is not None else
                    "Do NOT pass a block number to createSelectFork — this node serves "
                    "LATEST state only; pinning a past block needs an archive RPC and "
                    "will 403.")
            lines.append(
                f"- alias `{c.chain}` (chainId {c.chain_id}) {where}, served via {front}. "
                f"Use `vm.createSelectFork(\"{c.chain}\")`, call a real deployed "
                f"entrypoint/token, and assert $-impact. {tail}"
            )
        if any(c.archive is False for c in ready):
            lines.append(
                "\n⚠️ The upstream is a NON-ARCHIVE node. On a fast chain its fork base "
                "block ages out within seconds, so a fork that reads state more than a "
                "few seconds after setUp may 403 mid-test. If createSelectFork state "
                "reads fail, switch to a LOCAL PoC immediately (instantiate the real "
                "source + a mock token, drive the real public entrypoint) rather than "
                "burning turns retrying — a stable fork needs an archive RPC.")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {"backend": self.backend, "any_ready": self.any_ready,
                "chains": [c.to_dict() for c in self.chains]}

    def summary(self) -> str:
        parts = []
        for c in self.chains:
            tag = (f"ready@{c.block}" + ("/anvil" if c.fronted_by_anvil else "/upstream")
                   if c.ready else c.status)
            parts.append(f"{c.chain}={tag}")
        return ", ".join(parts) or "no chains"

    def teardown(self) -> None:
        for h in self._handles:
            h.kill()
        self._handles.clear()
        self.restore_env()   # un-poison <CHAIN>_RPC_URL for later stages (e.g. S5)


# --------------------------------------------------------------------------- #
# Preflight                                                                     #
# --------------------------------------------------------------------------- #
def _resolve_url(chain: str, rpc_urls: Mapping, env: Mapping) -> str | None:
    url = rpc_urls.get(chain) or rpc_urls.get(chain.lower())
    if url:
        return str(url)
    envv = env.get(f"{chain.upper()}_RPC_URL")
    return str(envv) if envv else None


def plan_forks(
    fork_cfg: Mapping,
    target_chains: list[str] | None = None,
    *,
    exec_backend: str = "host",
    env: Mapping | None = None,
    log_dir: str | None = None,
    prober: Callable[[str, float], ProbeResult] = default_prober,
    anvil_launcher: Callable[..., AnvilHandle | None] = default_anvil_launcher,
) -> ForkPlan:
    """Resolve + validate + pin + (optionally) front a fork per chain. Pure control
    flow; the network + anvil are behind the injected ``prober``/``anvil_launcher``
    so this is unit-tested offline. Returns a :class:`ForkPlan` (call ``apply_env``
    before hunting and ``teardown`` after)."""
    env = env if env is not None else os.environ
    fork_cfg = fork_cfg or {}
    rpc_urls = fork_cfg.get("rpc_urls") or {}
    block_cfg = fork_cfg.get("block") or {}
    chain_ids = {**KNOWN_CHAIN_IDS, **(fork_cfg.get("chain_ids") or {})}
    shared = bool(fork_cfg.get("shared_anvil", True))
    timeout = float(fork_cfg.get("probe_timeout_s", 8))
    port_base = int(fork_cfg.get("anvil_port_base", 8545))
    anvil_ready = float(fork_cfg.get("anvil_ready_timeout_s", 90))
    anvil_args = fork_cfg.get("anvil_args")  # None → launcher's resilient defaults

    # chains worth forking: anything explicitly given a URL, plus the target's chains.
    chains: list[str] = []
    for c in list(rpc_urls.keys()) + list(target_chains or []):
        cl = str(c).strip().lower()
        if cl and cl not in chains:
            chains.append(cl)

    plan = ForkPlan(backend=exec_backend)
    next_port = port_base
    for chain in chains:
        expected = chain_ids.get(chain)
        url = _resolve_url(chain, rpc_urls, env)
        if not url:
            plan.chains.append(ChainFork(
                chain=chain, status="unconfigured",
                chain_id_expected=expected,
                detail="no URL in hunt.fork.rpc_urls or ${%s_RPC_URL}" % chain.upper()))
            continue
        probe = prober(url, timeout)
        if not probe.reachable:
            plan.chains.append(ChainFork(
                chain=chain, status="unreachable", upstream_url=url,
                chain_id_expected=expected, detail=probe.detail or "endpoint not reachable"))
            continue
        if expected is not None and probe.chain_id is not None and probe.chain_id != expected:
            plan.chains.append(ChainFork(
                chain=chain, status="chain_mismatch", upstream_url=url,
                chain_id=probe.chain_id, chain_id_expected=expected,
                detail=f"endpoint chainId {probe.chain_id} != expected {expected}"))
            continue

        # Block selection. An explicit int PINS the fork (reproducible) — but fetching
        # state at a PAST block is an *archive* request, which free/full nodes reject
        # (403 "archive requires a token"). So the default ("latest"/unset) is to NOT
        # pin: anvil/forge fork the node's current head, always served from live state.
        raw_blk = block_cfg.get(chain, block_cfg.get(chain.lower()))
        if isinstance(raw_blk, int):
            block = raw_blk
        elif raw_blk in (None, "", "latest"):
            block = None  # fork latest (no --fork-block-number) — no archive needed
        else:
            try:
                block = int(raw_blk)
            except (TypeError, ValueError):
                block = None

        serve_url, fronted, pid, note = url, False, None, ""
        if shared and exec_backend == "host":
            log_path = (str(Path(log_dir) / f"anvil-{chain}-{next_port}.log")
                        if log_dir else None)
            handle = anvil_launcher(chain, url, block, next_port,
                                    ready_timeout=anvil_ready, extra_args=anvil_args,
                                    log_path=log_path)
            if handle is not None:
                serve_url, fronted, pid = handle.serve_url, True, handle.pid
                plan._handles.append(handle)
                next_port += 1
            else:
                note = " (anvil unavailable → hunters use the upstream RPC directly)"
        elif shared and exec_backend != "host":
            note = f" (shared anvil not wired for exec_backend={exec_backend}; serving upstream)"

        plan.chains.append(ChainFork(
            chain=chain, status="ready", serve_url=serve_url, upstream_url=url,
            chain_id=probe.chain_id, chain_id_expected=expected, block=block,
            archive=probe.archive, fronted_by_anvil=fronted, anvil_pid=pid,
            detail=("forked at upstream latest" if block is None
                    else f"forked at pinned block {block}")
            + ("" if probe.archive is not False else " · non-archive upstream") + note))
    return plan
