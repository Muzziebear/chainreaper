"""Spec-Research (Tier-4 P2) self-test — OFFLINE / ZERO token + ZERO web spend.

Asserts the four load-bearing pieces of P2 without a live agent or the network:

  1. the cross-cutting **web-research agent mode** — an ``AgentSpec(mode="research")``
     exposes WebFetch/WebSearch; ``session`` keeps them (not disallowed); the Bash
     guard PERMITS them ONLY for research mode (recon/hunt/critic stay web-denied),
     while Edit/Task stay denied and Write stays scratch-gated;
  2. the **Spec-Research system prompt** composes (SCOPE + research methodology +
     the invariant emitter);
  3. ``run_spec_research`` drives a (stubbed) research backend and its INTENT
     invariants (``origin="spec"``) land in the per-run ``invariants`` table where
     ``get_invariants`` merges them with the code-derived suite;
  4. those intent invariants **bind** to real ``file:symbol`` hooks (S1 index) and
     **flow to the S4 task queue** via the invariant-coverage backstop.

Run against the verified ``runs/test-merged`` fixture so the index + hooks are real.

Usage:  python tests/smoke_specresearch.py [runs/<run_id>]
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

from chainreaper.agents.factory import build_spec_researcher_system
from chainreaper.agents.hooks import decide_guard
from chainreaper.agents.session import _disallowed_for
from chainreaper.agents.spec import AgentSpec, spec_research_emitters
from chainreaper.models import Invariant, InvariantSuite
from chainreaper.recon.invariants import bind_hooks
from chainreaper.recon.store import ReconStore
from chainreaper.stages.s2_recon import _backstop_invariant_tasks, run_spec_research

RUN = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("runs/test-merged")
INDEX_DB = str(RUN / "index" / "index.db")

# Stubbed documented-promise invariants (what the agent WOULD emit), with hooks that
# resolve in the test-merged index so the bind step is real.
STUB_SPEC_INVARIANTS = [
    {"inv_id": "SPEC-01", "category": "oracle", "statement":
     'per docs: the protocol only acts on a price fresher than the heartbeat',
     "hooks": ["MockOracleProvider.getOraclePrice"], "severity": "high",
     "origin": "spec", "tool": "medusa"},
    {"inv_id": "SPEC-02", "category": "fee", "statement":
     'per docs: the withdrawal fee never exceeds the documented cap',
     "hooks": ["IVaultV1.withdrawFees"], "severity": "critical",
     "origin": "spec", "tool": "halmos"},
    {"inv_id": "SPEC-03", "category": "execution", "statement":
     'per docs: a solvent user can always deposit/withdraw (liveness)',
     "hooks": ["IWNT.deposit"], "severity": "high", "origin": "spec", "tool": "medusa"},
]


class _StubResearchBackend:
    """Stands in for the web-enabled claude_cli research agent: instead of fetching
    docs + calling the save-script, it writes the stubbed intent invariants straight
    to the store — exactly what the real ``recon-create-invariant`` emitter would do."""

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
            for inv in STUB_SPEC_INVARIANTS:
                store.add_invariant(run_id=run_id, agent=spec.name,
                                    session="stub", inv=inv)
        finally:
            store.close()
        return {"agent": spec.name, "session": "stub"}


def _guard_decision(tool: str, mode: str) -> str:
    env = {"CHAINREAPER_MODE": mode, "CHAINREAPER_ALLOWED_BASH": "code-index,recon-create-invariant",
           "CHAINREAPER_SCRATCH": "/tmp/scratch"}
    _, out = decide_guard({"tool_name": tool, "tool_input": {}}, env)
    return json.loads(out)["hookSpecificOutput"]["permissionDecision"]


def main() -> int:
    print(f"smoke_specresearch: Spec-Research (T4 P2) · fixture={RUN}")
    assert Path(INDEX_DB).exists(), f"missing S1 index: {INDEX_DB}"

    # 1. web-research agent MODE — spec/session/hooks wiring
    em = spec_research_emitters(3)
    spec = AgentSpec(name="spec_researcher", role="recon", mode="research",
                     system_prompt="x", emitters=em, user_message="y")
    allowed = spec.allowed_tools()
    assert "WebFetch" in allowed and "WebSearch" in allowed, f"research mode lacks web: {allowed}"
    assert any("recon-create-invariant" in t for t in allowed), "research mode missing emit script"
    # session: research keeps web; recon/hunt remove it
    rdis = _disallowed_for("research")
    assert "WebFetch" not in rdis and "WebSearch" not in rdis, f"research disallows web: {rdis}"
    assert "Edit" in rdis and "Task" in rdis, "research must still disallow Edit/Task"
    assert "WebFetch" in _disallowed_for("recon") and "WebFetch" in _disallowed_for("hunt"), \
        "recon/hunt must disallow web"
    # guard: web PERMITTED for research, DENIED for recon + hunt + critic(recon-mode)
    for tool in ("WebFetch", "WebSearch"):
        assert _guard_decision(tool, "research") == "allow", f"research guard denied {tool}"
        assert _guard_decision(tool, "recon") == "deny", f"recon guard allowed {tool}"
        assert _guard_decision(tool, "hunt") == "deny", f"hunt guard allowed {tool}"
    # research still denies Edit/Task and scratch-gates Write
    assert _guard_decision("Edit", "research") == "deny", "research allowed Edit"
    assert _guard_decision("Task", "research") == "deny", "research allowed Task"
    env_w = {"CHAINREAPER_MODE": "research", "CHAINREAPER_SCRATCH": "/tmp/scratch"}
    _, off = decide_guard({"tool_name": "Write", "tool_input": {"file_path": "/etc/x"}}, env_w)
    assert json.loads(off)["hookSpecificOutput"]["permissionDecision"] == "deny", "off-scratch Write allowed"
    _, on = decide_guard({"tool_name": "Write", "tool_input": {"file_path": "/tmp/scratch/a.json"}}, env_w)
    assert json.loads(on)["hookSpecificOutput"]["permissionDecision"] == "allow", "scratch Write denied"
    print("  [OK ] research mode: web ALLOWED for research only (recon/hunt/critic web-denied); "
          "Edit/Task denied; Write scratch-gated")

    # 2. system prompt composes
    sysp = build_spec_researcher_system(None, "test/repo", "## TOOLS\n(web)", em)
    for needle in ("Spec-Research", "origin", "INTENT", "recon-create-invariant", "SCOPE"):
        assert needle in sysp, f"spec_researcher prompt missing {needle!r}"
    print(f"  [OK ] build_spec_researcher_system composes ({len(sysp)} chars)")

    # 3. run_spec_research drives the (stub) research backend → intent invariants persist
    with tempfile.TemporaryDirectory() as d:
        artifact_db = str(Path(d) / "chainreaper.db")
        ReconStore(artifact_db).create_schema()
        backend = _StubResearchBackend()
        n = run_spec_research(backend, target=None, repo_ref="test/repo",
                              db_path=INDEX_DB, artifact_db=artifact_db,
                              run_id="smoke", min_invariants=3)
        assert n == 3, f"expected 3 intent invariants, got {n}"
        assert backend.last_spec is not None and backend.last_spec.mode == "research", \
            "spec-research did not run in research mode"
        store = ReconStore(artifact_db)
        try:
            persisted = store.get_invariants("smoke")
        finally:
            store.close()
        spec_invs = [i for i in persisted if i.get("origin") == "spec"]
        assert len(spec_invs) == 3, f"intent invariants not merged into the suite: {len(spec_invs)}"
    print("  [OK ] run_spec_research (research mode) persists 3 intent invariants (origin=spec)")

    # 4. intent invariants BIND to real hooks + FLOW to the S4 task queue
    invs = [Invariant.model_validate(d) for d in STUB_SPEC_INVARIANTS]
    coverage = bind_hooks(INDEX_DB, invs)
    bound = [i.inv_id for i in invs if coverage[i.inv_id]["bound"] > 0]
    assert len(bound) == 3, f"intent invariants did not bind: {bound}"
    assert all(i.status == "scaffolded" for i in invs), "bound intent invariants not scaffolded"
    suite = InvariantSuite(target="smoke", invariants=invs, coverage_map=coverage)
    tasks = _backstop_invariant_tasks(suite, [])
    spec_tasks = [t for t in tasks if t.inv_id and t.inv_id.startswith("SPEC-")]
    assert len(spec_tasks) == 3, f"intent invariants did not reach the S4 queue: {[t.task_id for t in tasks]}"
    assert all(t.task_id.startswith("task-inv-spec-") for t in spec_tasks), \
        f"unexpected task ids: {[t.task_id for t in spec_tasks]}"
    print(f"  [OK ] intent invariants bind ({len(bound)}/3) + flow to S4 "
          f"({len(spec_tasks)} tasks: {', '.join(t.task_id for t in spec_tasks)})")

    print("smoke_specresearch: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
