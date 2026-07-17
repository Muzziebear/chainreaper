"""Ground-truth replay engine (T3.2).

``ground_truth_replay`` forks a case's pre-hack block and runs its reference PoC to
confirm the known exploit reproduces — the HARD positive control the harness
lacked. This is the foundation of calibration: it verifies the fork+PoC setup is
sound before we ask whether the harness *rediscovers* the hack (that path reuses
the normal S0→S4 pipeline against the victim — see ``calibrate.manifest``).

Costs COMPUTE, not tokens (no model calls). The forge run, the network fetch, and
the fork prober/anvil are all behind injected seams so the whole flow unit-tests
offline (the vendored synthetic case runs a real local ``forge test`` with no RPC).
"""

from __future__ import annotations

import shutil
import subprocess
import urllib.request
from pathlib import Path
from typing import Callable

from pydantic import BaseModel, Field

from ..runtime.exec import Sandbox, augmented_env
from ..runtime.fork import ForkPlan, default_anvil_launcher, default_prober, plan_forks
from ..runtime.logging import get_logger
from .cases import CASES_ROOT, ReplayCase
from .defihacklabs import build_case_project, default_cloner, ensure_clone, free_archive_for

log = get_logger()

# (workspace, --match-test, env) -> (returncode, combined_log). Injected in tests.
ForgeRunner = Callable[[Path, str, dict], "tuple[int, str]"]
# (url) -> source text. Injected in tests (no egress).
Fetcher = Callable[[str], str]


class ReplayResult(BaseModel):
    case_id: str
    ran: bool = False                 # the reference PoC actually executed
    reproduced: bool | None = None    # PoC passed (True) / failed (False) / couldn't run (None)
    fork: dict = Field(default_factory=dict)   # ForkPlan.to_dict() (redacted)
    detail: str = ""
    log_tail: str = ""

    @property
    def status(self) -> str:
        if self.reproduced is True:
            return "REPRODUCED"
        if self.reproduced is False:
            return "NOT-REPRODUCED"
        return "SKIPPED"


class CalibrationReport(BaseModel):
    results: list[ReplayResult] = Field(default_factory=list)

    @property
    def reproduced(self) -> int:
        return sum(1 for r in self.results if r.reproduced is True)

    @property
    def failed(self) -> int:
        return sum(1 for r in self.results if r.reproduced is False)

    @property
    def skipped(self) -> int:
        return sum(1 for r in self.results if r.reproduced is None)

    def scorecard(self) -> str:
        lines = [f"calibration · {len(self.results)} case(s): "
                 f"{self.reproduced} reproduced, {self.failed} not-reproduced, "
                 f"{self.skipped} skipped"]
        for r in self.results:
            lines.append(f"  [{r.status:14}] {r.case_id} — {r.detail}")
        return "\n".join(lines)


# --------------------------------------------------------------------------- #
# default seams                                                               #
# --------------------------------------------------------------------------- #
def default_forge_runner(ws: Path, match_test: str, env: dict) -> tuple[int, str]:
    forge = shutil.which("forge", path=env.get("PATH", ""))
    if not forge:
        return 127, "forge not on PATH"
    try:
        p = subprocess.run([forge, "test", "--match-test", match_test, "-vvv"],
                           cwd=str(ws), capture_output=True, text=True, timeout=900, env=env)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, "forge test timed out"


def default_fetcher(url: str) -> str:
    with urllib.request.urlopen(url, timeout=30) as resp:  # noqa: S310 (operator command)
        return resp.read().decode("utf-8", "replace")


# --------------------------------------------------------------------------- #
# replay                                                                      #
# --------------------------------------------------------------------------- #
def _stage_poc(case: ReplayCase, ws: Path, *, vendored_root: Path,
               fetcher: Fetcher) -> str | None:
    """Place the reference PoC into the sandbox. Returns an error detail or None."""
    if case.poc_source == "vendored":
        src = case.vendored_dir(vendored_root)
        if not src.is_dir():
            return f"vendored PoC dir not found: {src}"
        for sub in ("src", "test"):
            d = src / sub
            if d.is_dir():
                for f in d.glob("*.sol"):
                    shutil.copy2(f, ws / sub / f.name)
        return None
    if case.poc_source == "url":
        try:
            text = fetcher(case.poc_ref)
        except Exception as exc:  # network/operator path
            return f"could not fetch PoC ({exc})"
        name = case.poc_ref.rsplit("/", 1)[-1] or "Replay_exp.sol"
        (ws / "test" / name).write_text(text)
        return ("fetched PoC, but url cases also need the DeFiHackLabs helper bundle "
                "(basetest.sol/interface.sol) — provide it before a real replay")
    return "no reference PoC for this case (rediscovery-only)"


def _replay_defihacklabs(case: ReplayCase, *, work_dir: str | Path,
                         rpc_urls: dict | None, forge_runner: ForgeRunner,
                         cloner: Callable = default_cloner) -> ReplayResult:
    """Real DeFiHackLabs replay: clone the repo (cached), build a minimal project for
    the case (its _exp.sol + shared helpers + forge-std), point the chain alias at our
    archive ``<CHAIN>_RPC_URL``, and run the PoC's test against the pre-hack block.
    Needs an archive RPC for the case's chain; SKIPS cleanly without one."""
    env = augmented_env()
    chain = case.chain
    rpc = (rpc_urls or {}).get(chain) or (rpc_urls or {}).get(chain.lower()) \
        or env.get(f"{chain.upper()}_RPC_URL")
    used_free = False
    if not rpc:
        rpc = free_archive_for(chain)            # operator opted into free public archives
        used_free = bool(rpc)
    if not rpc:
        return ReplayResult(
            case_id=case.id, ran=False, reproduced=None,
            detail=f"needs an archive {chain.upper()}_RPC_URL (no known free archive for "
                   f'"{chain}"; DeFiHackLabs PoC forks it at the pre-hack block)')
    env[f"{chain.upper()}_RPC_URL"] = rpc
    cache = Path(work_dir).parent / "_defihacklabs"
    try:
        repo = ensure_clone(cache, cloner=cloner)
        ws = build_case_project(repo, case.poc_ref, chain, Path(work_dir) / "dhl")
    except Exception as exc:
        return ReplayResult(case_id=case.id, ran=False, reproduced=None,
                            detail=f"could not prepare DeFiHackLabs case ({exc})")
    # Free archive nodes are flaky on the cold fork fetch — retry once (forge's fork
    # cache is warm on the second try). A dedicated archive key rarely needs it.
    rc, out = forge_runner(Path(ws), case.poc_test, env)
    if rc != 0:
        rc, out = forge_runner(Path(ws), case.poc_test, env)
    reproduced = rc == 0
    tail = "\n".join(out.strip().splitlines()[-12:])
    src = "free public archive" if used_free else "archive RPC"
    return ReplayResult(
        case_id=case.id, ran=True, reproduced=reproduced,
        fork={"chain": chain, "block": case.block, "via": "defihacklabs",
              "archive": True, "free_public": used_free},
        detail=(f"reference PoC passed — exploit reproduced on the {src} fork" if reproduced
                else f"reference PoC failed (forge rc={rc})"),
        log_tail=tail)


def ground_truth_replay(
    case: ReplayCase,
    *,
    work_dir: str | Path,
    rpc_urls: dict | None = None,
    vendored_root: Path = CASES_ROOT,
    forge_runner: ForgeRunner = default_forge_runner,
    fetcher: Fetcher = default_fetcher,
    prober: Callable = default_prober,
    anvil_launcher: Callable = default_anvil_launcher,
) -> ReplayResult:
    """Fork the case's pre-hack block and run its reference PoC. ``reproduced`` is
    True iff the PoC passes (the known exploit fires). Local (vendored, needs_fork
    False) cases run with no RPC; fork cases need an archive ``<CHAIN>_RPC_URL``."""
    if case.poc_source == "none":
        return ReplayResult(case_id=case.id, ran=False, reproduced=None,
                            detail="rediscovery-only case (no reference PoC)")

    if case.poc_source == "defihacklabs":
        return _replay_defihacklabs(case, work_dir=work_dir, rpc_urls=rpc_urls,
                                    forge_runner=forge_runner)

    sandbox = Sandbox(work_dir)
    ws = sandbox.prepare(f"replay-{case.id}")
    err = _stage_poc(case, ws, vendored_root=vendored_root, fetcher=fetcher)
    if err and case.poc_source == "vendored":
        return ReplayResult(case_id=case.id, ran=False, reproduced=None, detail=err)

    fork_dict: dict = {}
    fork_plan: ForkPlan | None = None
    env = augmented_env()
    if case.needs_fork:
        fork_cfg = {
            "rpc_urls": rpc_urls or {},
            "block": {case.chain: case.block} if case.block is not None else {},
            "shared_anvil": True,
        }
        fork_plan = plan_forks(fork_cfg, [case.chain], env=env,
                               log_dir=str(Path(ws) / "logs"),
                               prober=prober, anvil_launcher=anvil_launcher)
        fork_dict = fork_plan.to_dict()
        if not fork_plan.any_ready:
            fork_plan.teardown()
            return ReplayResult(
                case_id=case.id, ran=False, reproduced=None, fork=fork_dict,
                detail=f"needs an archive {case.chain.upper()}_RPC_URL "
                       f"@ block {case.block} — fork not ready ({fork_plan.summary()})")
        fork_plan.apply_env(env)

    if err:  # url-case caveat (helpers) surfaced as skip, after the fork check
        if fork_plan:
            fork_plan.teardown()
        return ReplayResult(case_id=case.id, ran=False, reproduced=None,
                            fork=fork_dict, detail=err)

    try:
        rc, out = forge_runner(Path(ws), case.poc_test, env)
    finally:
        if fork_plan:
            fork_plan.teardown()
    reproduced = rc == 0
    tail = "\n".join(out.strip().splitlines()[-12:])
    return ReplayResult(
        case_id=case.id, ran=True, reproduced=reproduced, fork=fork_dict,
        detail=("reference PoC passed — exploit reproduced" if reproduced
                else f"reference PoC failed (forge rc={rc})"),
        log_tail=tail)


def run_calibration(cases: list[ReplayCase], *, work_dir: str | Path,
                    rpc_urls: dict | None = None, **kw) -> CalibrationReport:
    """Ground-truth replay over a set of cases → a scorecard."""
    results: list[ReplayResult] = []
    for case in cases:
        log.info("[calibrate] replay %s (%s)", case.id, case.name)
        r = ground_truth_replay(case, work_dir=Path(work_dir) / case.id,
                                rpc_urls=rpc_urls, **kw)
        log.info("[calibrate]   → %s · %s", r.status, r.detail)
        results.append(r)
    return CalibrationReport(results=results)
