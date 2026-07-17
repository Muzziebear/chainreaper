"""Threat-Research (Tier-4 P6) self-test — OFFLINE / ZERO token + ZERO web spend.

Asserts the load-bearing pieces of P6 without a live agent or the network:

  1. the **web-research agent mode** reused from P2 — a Threat-Research
     ``AgentSpec(mode="research")`` exposes WebFetch/WebSearch and its OWN emit
     script (``recon-create-task``); the Bash guard PERMITS the web tools ONLY for
     research mode (recon/hunt/critic stay web-denied), Edit/Task stay denied, Write
     stays scratch-gated;
  2. the **Threat-Research system prompt** composes (SCOPE + research methodology +
     the recon profile mechanism block + the HunterTask emitter);
  3. ``run_threat_research`` drives a (stubbed) research backend AFTER the main recon:
     it reads the persisted recon profile, runs in ``research`` mode, and its
     OFF-CHECKLIST HunterTasks (``origin="threat_research"``) land in the SAME per-run
     ``hunter_tasks`` table where ``get_tasks`` merges them with the recon queue;
  4. those off-checklist tasks **flow to the S4 queue** through the deterministic
     prefilter — including one whose dossier resolves NO in-scope targets (the
     never-drop / never-fold protection: a novel hypothesis is precisely the lead a
     checklist-driven dossier wouldn't pin to a function).

Run against the verified ``runs/test-merged`` fixture so the index is real.

Usage:  python tests/smoke_threatresearch.py [runs/<run_id>]
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

from chainreaper.agents.factory import (
    build_threat_researcher_system,
    threat_research_profile_block,
)
from chainreaper.agents.hooks import decide_guard
from chainreaper.agents.session import _disallowed_for
from chainreaper.agents.spec import AgentSpec, threat_research_emitters
from chainreaper.models import HunterTask, ReconProfileInput
from chainreaper.recon.dossier import build_dossiers
from chainreaper.recon.prefilter import prefilter
from chainreaper.recon.store import ReconStore
from chainreaper.stages.s2_recon import run_threat_research

RUN = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("runs/test-merged")
INDEX_DB = str(RUN / "index" / "index.db")

# A stub recon profile (what the MAIN recon would have persisted) so the threat-research
# agent receives the protocol's specific mechanism to aim at.
STUB_PROFILE = {
    "architecture_md": "A perp DEX: wallet → router → order handler → market store + "
                       "oracle. Custom funding-rate accrual + a bespoke keeper auction "
                       "for liquidations. Yield-bearing collateral rebases each epoch.",
    "contract_types": ["perp-dex", "oracle", "vault"],
    "trust_boundaries": [],
    "privileged_roles": [{"name": "keeper", "description": "runs liquidations"},
                         {"name": "owner", "description": "sets parameters"}],
    "high_impact_areas": [
        {"rank": 1, "title": "Funding-rate accrual", "contracts": ["MarketUtils"],
         "functions": ["getFundingFees"]},
    ],
    "threat_model": {},
}

# Stubbed off-checklist tasks (what the agent WOULD emit). The first anchors to a real
# in-scope symbol (resolves a dossier); the second is a deliberately novel hypothesis
# whose scope_hint resolves NOTHING — it must still survive the prefilter (never-drop).
STUB_THREAT_TASKS = [
    {"task_id": "task-threat-01", "title":
     "Epoch-boundary funding/rebase desync drains rounding dust at scale",
     "vuln_class": "logic_error", "scope_hint": "MockOracleProvider.getOraclePrice",
     "hypothesis": "per a 2026 perp-dex incident: if the rebase epoch crosses a funding "
                   "checkpoint within one tx, the bespoke accrual reads a pre-rebase index "
                   "and an attacker harvests the desync repeatedly.",
     "priority": 2, "origin": "threat_research"},
    {"task_id": "task-threat-02", "title":
     "Keeper-auction transient-storage (EIP-1153) reuse across liquidations",
     "vuln_class": "logic_error",
     "scope_hint": "BespokeKeeperAuction.settleViaTransientSlot",  # resolves nothing
     "hypothesis": "off-checklist: if the keeper auction caches a price in transient "
                   "storage and a second liquidation reuses the slot in the same tx, the "
                   "second settles at a stale transient price.",
     "priority": 3, "origin": "threat_research"},
    {"task_id": "task-threat-03", "title":
     "Cross-epoch collateral rebase double-counts in withdrawal accounting",
     "vuln_class": "logic_error", "scope_hint": "IVaultV1.withdrawFees",
     "hypothesis": "per a recent LST audit finding: rebasing collateral counted both as "
                   "shares and as raw balance during a withdraw straddling an epoch.",
     "priority": 2, "origin": "threat_research"},
]


class _StubResearchBackend:
    """Stands in for the web-enabled claude_cli research agent: instead of fetching
    write-ups + calling the save-script, it writes the stubbed off-checklist tasks
    straight to the store — exactly what the real ``recon-create-task`` emitter would do."""

    name = "stub-research"
    tools_doc = "## (stub) research TOOLS: WebFetch, WebSearch, Read, Grep, code-index"

    def __init__(self) -> None:
        self.last_spec: AgentSpec | None = None

    def selftest(self) -> str:
        return "stub ok"

    def run_agent(self, spec, *, index_db, artifact_db, run_id,
                  scratch_dir=None, cwd=None) -> dict:
        self.last_spec = spec
        store = ReconStore(artifact_db)
        store.create_schema()
        try:
            for t in STUB_THREAT_TASKS:
                store.add_task(run_id=run_id, agent=spec.name, session="stub", task=t)
        finally:
            store.close()
        return {"agent": spec.name, "session": "stub"}


def _guard_decision(tool: str, mode: str) -> str:
    env = {"CHAINREAPER_MODE": mode,
           "CHAINREAPER_ALLOWED_BASH": "code-index,recon-create-task",
           "CHAINREAPER_SCRATCH": "/tmp/scratch"}
    _, out = decide_guard({"tool_name": tool, "tool_input": {}}, env)
    return json.loads(out)["hookSpecificOutput"]["permissionDecision"]


def main() -> int:
    print(f"smoke_threatresearch: Threat-Research (T4 P6) · fixture={RUN}")
    assert Path(INDEX_DB).exists(), f"missing S1 index: {INDEX_DB}"

    # 1. web-research agent MODE — spec/session/hooks wiring for the threat researcher
    em = threat_research_emitters(3)
    assert len(em) == 1 and em[0].command == "recon-create-task", \
        f"threat emitter is not the task emitter: {[e.command for e in em]}"
    assert em[0].min_calls == 3, f"min_tasks not honoured: {em[0].min_calls}"
    spec = AgentSpec(name="threat_researcher", role="recon", mode="research",
                     system_prompt="x", emitters=em, user_message="y")
    allowed = spec.allowed_tools()
    assert "WebFetch" in allowed and "WebSearch" in allowed, f"research mode lacks web: {allowed}"
    assert any("recon-create-task" in t for t in allowed), "research mode missing task emit script"
    rdis = _disallowed_for("research")
    assert "WebFetch" not in rdis and "WebSearch" not in rdis, f"research disallows web: {rdis}"
    assert "Edit" in rdis and "Task" in rdis, "research must still disallow Edit/Task"
    for tool in ("WebFetch", "WebSearch"):
        assert _guard_decision(tool, "research") == "allow", f"research guard denied {tool}"
        assert _guard_decision(tool, "recon") == "deny", f"recon guard allowed {tool}"
        assert _guard_decision(tool, "hunt") == "deny", f"hunt guard allowed {tool}"
    assert _guard_decision("Edit", "research") == "deny", "research allowed Edit"
    assert _guard_decision("Task", "research") == "deny", "research allowed Task"
    print("  [OK ] research mode (P6 reuses P2 wiring): web ALLOWED for research only; "
          "task-emit scoped; Edit/Task denied")

    # 2. system prompt composes (incl. the profile mechanism block)
    pblock = threat_research_profile_block(STUB_PROFILE)
    assert "RECON PROFILE" in pblock and "Funding-rate" in pblock, f"profile block thin: {pblock[:120]}"
    sysp = build_threat_researcher_system(None, "test/repo", "## TOOLS\n(web)", em,
                                          profile_block=pblock)
    for needle in ("Threat-Research", "OFF-CHECKLIST", "threat_research",
                   "recon-create-task", "SCOPE", "RECON PROFILE"):
        assert needle in sysp, f"threat_researcher prompt missing {needle!r}"
    print(f"  [OK ] build_threat_researcher_system composes incl. profile block ({len(sysp)} chars)")

    # 3. run_threat_research drives the (stub) backend AFTER recon → off-checklist tasks persist
    with tempfile.TemporaryDirectory() as d:
        artifact_db = str(Path(d) / "chainreaper.db")
        store = ReconStore(artifact_db)
        store.create_schema()
        # seed the main-recon profile so the agent receives the mechanism context
        store.add_profile(run_id="smoke", agent="recon", session="seed", profile=STUB_PROFILE)
        store.close()

        backend = _StubResearchBackend()
        n = run_threat_research(backend, target=None, repo_ref="test/repo",
                                db_path=INDEX_DB, artifact_db=artifact_db,
                                run_id="smoke", min_tasks=3)
        assert n == 3, f"expected 3 off-checklist tasks, got {n}"
        assert backend.last_spec is not None and backend.last_spec.mode == "research", \
            "threat-research did not run in research mode"
        # the agent received the persisted recon profile as its mechanism block
        assert "Funding-rate" in backend.last_spec.system_prompt, \
            "threat-research prompt missing the recon profile mechanism"

        store = ReconStore(artifact_db)
        try:
            persisted = store.get_tasks("smoke")
        finally:
            store.close()
        threat = [t for t in persisted if t.get("origin") == "threat_research"]
        assert len(threat) == 3, f"off-checklist tasks not merged into queue: {len(threat)}"
    print("  [OK ] run_threat_research (research mode, post-recon) persists 3 off-checklist "
          "tasks (origin=threat_research) using the recon profile")

    # 4. off-checklist tasks FLOW to the S4 queue through the prefilter — including the
    #    one whose dossier resolves NO in-scope targets (never-drop / never-fold).
    tasks = [HunterTask.model_validate(t) for t in STUB_THREAT_TASKS]
    pin = ReconProfileInput.model_validate(STUB_PROFILE)
    dossiers = build_dossiers(INDEX_DB, tasks, pin, [])
    no_target = [t.task_id for t in tasks
                 if not dossiers[t.task_id].target_functions]
    assert "task-threat-02" in no_target, \
        f"expected the bogus-scope task to resolve no targets (got {no_target})"
    task_dicts = [{**t.model_dump(mode="json"),
                   "context": dossiers[t.task_id].model_dump(mode="json")} for t in tasks]
    result = prefilter(task_dicts)
    scheduled_ids = {t.task_id for t in result.scheduled}
    assert {"task-threat-01", "task-threat-02", "task-threat-03"} <= scheduled_ids, \
        f"off-checklist tasks did not reach S4: scheduled={scheduled_ids}"
    # the no-target novel hypothesis was NOT dropped
    d02 = result.decisions_by_id["task-threat-02"]
    assert d02.decision == "scheduled", \
        f"no-target threat task was dropped/deferred: {d02.decision} ({d02.reasons})"
    print(f"  [OK ] off-checklist tasks flow to S4 ({len(scheduled_ids)} scheduled, incl. "
          "the no-target novel hypothesis — never-drop protection holds)")

    print("smoke_threatresearch: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
