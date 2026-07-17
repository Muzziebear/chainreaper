"""Calibration-rediscovery suite (task 0 — MEASURE THE CEILING).

The ground-truth replay ([[replay.py]]) proves a historical hack still fires on a
fork. The *rediscovery* suite answers the harder, load-bearing question raised
across the 8-target session (memory ``chainreaper-inverse-hunt``): the harness has
never produced an **attacker-triggerable, in-scope, no-external-condition** finding
— is that a real capability ceiling or were the audited targets simply clean?

To measure it we run the FULL billed pipeline (S1 index → S2 recon → S3 prefilter →
S4 hunt → S5 validate) against the *victim* of a hack whose root cause WAS exactly
that class (a permissionless donation/inflation, a reentrancy drain, an accounting
drain — no oracle, no admin), with the fork pinned to the pre-hack block, and score
whether a finding classed ``attacker_reachable`` (per the adversary model) lands on
the known root-cause contract+function.

  * rediscovered  → the plateau is base-rate: the targets were clean, the harness
                    can find this class when it exists → invest LESS in tasks 1/2.
  * NOT           → a real recall gap → tasks 1 (reachability) / 2 (stateful fuzz)
                    are justified.

Costs TOKENS (billed S2→S5) — gated behind ``calibrate --rediscovery``. The victim
source materialization + the pipeline driver + the store reader are injected seams,
so the orchestration unit-tests offline with stubs (``tests/smoke_calibrate``).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Callable

from pydantic import BaseModel, Field

from ..runtime.logging import get_logger
from .cases import ReplayCase
from .manifest import rediscovery_overlay, score_findings, score_rediscovery

log = get_logger()

# Cost bounds for a billed rediscovery run (the measurement needs only the top-ranked
# tasks on the small victim surface). Overridable via a custom pipeline_runner.
REDISCOVERY_CAPS = {
    "hunt": {"max_tasks": 8, "concurrency": 2},
    "validate": {"max_findings": 8, "concurrency": 2},
}

# (case, run_dir, overlay) -> run_id string. Drives the billed pipeline. Injected in tests.
PipelineRunner = Callable[[ReplayCase, Path, dict], str]
# (run_dir, run_id) -> list[finding dict]. Reads S4/S5 findings back. Injected in tests.
StoreReader = Callable[[Path, str], list]


class RediscoveryResult(BaseModel):
    case_id: str
    ran: bool = False
    rediscovered: bool = False
    match_level: str = "none"        # strong | partial | none
    n_findings: int = 0
    n_attacker_reachable: int = 0
    root_cause: str = ""
    detail: str = ""
    score: dict = Field(default_factory=dict)
    vuln_class_score: dict = Field(default_factory=dict)

    @property
    def status(self) -> str:
        if not self.ran:
            return "SKIPPED"
        if self.rediscovered:
            return "REDISCOVERED"
        if self.match_level == "partial":
            return "PARTIAL"
        return "MISSED"


class RediscoveryReport(BaseModel):
    results: list[RediscoveryResult] = Field(default_factory=list)

    @property
    def ran(self) -> int:
        return sum(1 for r in self.results if r.ran)

    @property
    def rediscovered(self) -> int:
        return sum(1 for r in self.results if r.rediscovered)

    @property
    def partial(self) -> int:
        return sum(1 for r in self.results if r.ran and not r.rediscovered
                   and r.match_level == "partial")

    def rate(self) -> float:
        return (self.rediscovered / self.ran) if self.ran else 0.0

    def scorecard(self) -> str:
        lines = [
            "rediscovery · attacker-triggerable/in-scope historical hacks",
            f"  ran={self.ran}  rediscovered={self.rediscovered}  "
            f"partial={self.partial}  rate={self.rate()*100:.0f}% "
            f"(of ran; {len(self.results)} case(s) total)",
            f"  {'status':13} {'case':26} {'reach':>5} {'find':>5}  root-cause",
        ]
        for r in self.results:
            lines.append(
                f"  {r.status:13} {r.case_id:26} {r.n_attacker_reachable:5} "
                f"{r.n_findings:5}  {r.root_cause}"
                + (f"  — {r.detail}" if r.detail else ""))
        return "\n".join(lines)


# --------------------------------------------------------------------------- #
# default seams (real, billed)                                                #
# --------------------------------------------------------------------------- #
def build_rediscovery_target(
    case: ReplayCase, run_dir: Path, *, api_key: str | None,
    materializer: Callable = None, pause: float = 0.25,
) -> tuple[object | None, str]:
    """Materialize the victim's verified DEPLOYED source and write the S0 checkpoint
    so ``run_pipeline(resume=True)`` starts from a ready Target (mirrors the btc24h
    fixture). Returns ``(Target|None, detail)``."""
    from ..models import Target
    from ..targets.source_resolver import (
        materialize_verified_sources,
        verified_allowlist,
        verified_units_to_assets,
    )
    mat = materializer or materialize_verified_sources

    chain = case.redisc_chain
    addrs = case.redisc_addresses
    if not addrs:
        return None, "no rediscovery addresses (set rediscovery_addresses or victims)"
    contracts = [{"name": case.root_cause_contract or case.name, "address": a, "network": chain}
                 for a in addrs]
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "checkpoints").mkdir(exist_ok=True)
    (run_dir / "workspace").mkdir(exist_ok=True)

    units, unresolved = mat(contracts, run_dir / "workspace", api_key, pause=pause)
    if not units:
        return None, f"no verified source materialized ({unresolved})"

    impacts = ["Direct theft of user funds", "Theft of unclaimed yield/funds",
               "Protocol insolvency"]
    assets = verified_units_to_assets(units, impacts)
    allowlist = verified_allowlist(contracts, units)
    target = Target(
        program_id=f"rediscover-{case.id}",
        name=f"{case.name} (calibration rediscovery)",
        url=case.reference_url or "",
        assets_in_scope=assets,
        scope_allowlist=allowlist,
        chains=[chain],
        languages=["solidity"],
        program_type="smart_contract",
    )
    (run_dir / "checkpoints" / "s0.json").write_text(
        json.dumps(target.model_dump(mode="json"), indent=1))
    return target, f"materialized {len(units)} unit(s), {len(assets)} asset(s)"


def default_pipeline_runner(case: ReplayCase, run_dir: Path, overlay: dict) -> str:
    """Run the billed S1→S5 pipeline against the pre-built S0 checkpoint and return
    the run id. Uses ``resume=True`` so the S0 Target we wrote is reused and S1..S5
    execute (index the victim source, recon, hunt on the pinned fork, validate)."""
    from ..config import load_config
    from ..orchestrator.sequencer import RunContext, run_pipeline

    cfg = load_config(None, overrides=overlay)
    run_id = run_dir.name
    ctx = RunContext(run_id=run_id, run_dir=run_dir, config=cfg,
                     target_ref=target_ref_for(case))
    run_pipeline(ctx, stop_after="s5", resume=True, log=log.info)
    return run_id


def target_ref_for(case: ReplayCase) -> str:
    return f"rediscover-{case.id}"


def default_store_reader(run_dir: Path, run_id: str) -> list:
    """Read the run's findings back from the artifact db."""
    from ..recon.store import ReconStore
    db = run_dir / "chainreaper.db"
    if not db.exists():
        return []
    return ReconStore(db).get_findings(run_id)


# --------------------------------------------------------------------------- #
# run one / run suite                                                         #
# --------------------------------------------------------------------------- #
def run_rediscovery(
    case: ReplayCase, *, work_dir: str | Path, rpc_urls: dict | None = None,
    api_key: str | None = None,
    pipeline_runner: PipelineRunner = default_pipeline_runner,
    store_reader: StoreReader = default_store_reader,
    materializer: Callable = None,
) -> RediscoveryResult:
    """Materialize the victim, run the billed pipeline on the pinned fork, and score
    whether the harness rediscovered the attacker-triggerable root cause."""
    if not case.rediscovery:
        return RediscoveryResult(case_id=case.id, ran=False,
                                 detail="not a rediscovery case")
    if not case.root_cause_contract:
        return RediscoveryResult(case_id=case.id, ran=False,
                                 detail="no root_cause_contract oracle")

    run_dir = Path(work_dir) / f"rediscover-{case.id}"
    api_key = api_key or os.environ.get("ETHERSCAN_API_KEY")
    target, detail = build_rediscovery_target(case, run_dir, api_key=api_key,
                                              materializer=materializer)
    if target is None:
        return RediscoveryResult(case_id=case.id, ran=False,
                                 root_cause=_rc(case), detail=detail)

    overlay = rediscovery_overlay(case, rpc_urls=rpc_urls)
    # Bound the billed run: the rediscovery measurement only needs the top-ranked tasks
    # on the (small) victim surface — cap S4 tasks + S5 findings so the suite is
    # affordable across several cases. (The case overlay's fork settings still win.)
    overlay.setdefault("hunt", {}).update(
        {k: v for k, v in REDISCOVERY_CAPS["hunt"].items()
         if k not in overlay.get("hunt", {})})
    overlay.setdefault("validate", {}).update(REDISCOVERY_CAPS["validate"])
    try:
        run_id = pipeline_runner(case, run_dir, overlay)
    except Exception as exc:  # a billed run can die; record + move on
        return RediscoveryResult(case_id=case.id, ran=False, root_cause=_rc(case),
                                 detail=f"pipeline error: {exc}")

    findings = store_reader(run_dir, run_id) or []
    score = score_rediscovery(case, findings)
    vc_score = score_findings(case, findings)
    return RediscoveryResult(
        case_id=case.id, ran=True,
        rediscovered=bool(score["rediscovered"]),
        match_level=str(score["match_level"]),
        n_findings=int(score["n_findings"]),
        n_attacker_reachable=int(score["n_attacker_reachable"]),
        root_cause=_rc(case),
        detail=("strong: attacker_reachable finding on the root cause"
                if score["rediscovered"] else
                ("partial: attacker_reachable finding in the right contract"
                 if score["match_level"] == "partial" else
                 f"no attacker_reachable finding on {_rc(case)}")),
        score=score, vuln_class_score=vc_score)


def run_rediscovery_suite(
    cases: list[ReplayCase], *, work_dir: str | Path, rpc_urls: dict | None = None,
    api_key: str | None = None, **kw,
) -> RediscoveryReport:
    """Run the rediscovery measurement over every ``rediscovery: true`` case."""
    subset = [c for c in cases if c.rediscovery]
    results: list[RediscoveryResult] = []
    for case in subset:
        log.info("[rediscovery] %s (%s)", case.id, case.name)
        r = run_rediscovery(case, work_dir=work_dir, rpc_urls=rpc_urls,
                            api_key=api_key, **kw)
        log.info("[rediscovery]   → %s · %s", r.status, r.detail)
        results.append(r)
    return RediscoveryReport(results=results)


def _rc(case: ReplayCase) -> str:
    fns = "/".join(case.root_cause_functions) or "*"
    return f"{case.root_cause_contract}.{fns}"
