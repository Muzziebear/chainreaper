"""S2 synthesis-mode self-test (recon.synthesis_mode) — OFFLINE, ZERO token/web spend.

Drives the WHOLE S2 ``run()`` against the verified ``runs/test-merged`` fixture with a
stub backend, asserting the 4-phase flow and the context hand-offs the re-architecture
is for:

  spec-research → SPEC profile  ──┐
                                  ├─→ EXPLORE (profile+invariants, NO tasks)
                                  │      • receives the SPEC PROFILE (code-vs-intent)
                                  └─→ THREAT-RESEARCH (candidate leads)
                                         • receives the INVARIANT SUITE (find the COMPLEMENT)
                                  └─→ SYNTHESIS (the SOLE author of the unified queue)
                                         • receives profile + invariants + threat dossier
                                         • carries the novel orphan lead forward
                                         • folds a duplicate candidate (sole author: the
                                           un-carried candidate must NOT survive)

The stub emits phase-appropriate output keyed on each spec's emitters/mode and records
each phase's system prompt so we can assert what each phase was actually fed.

Usage:  python tests/smoke_synthesis.py [runs/<run_id>]
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

from chainreaper.config import load_config
from chainreaper.orchestrator.sequencer import RunContext
from chainreaper.recon.store import ReconStore
from chainreaper.stages import s2_recon

RUN = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("runs/test-merged")

# what each phase would emit -------------------------------------------------- #
SPEC_INVARIANTS = [
    {"inv_id": "SPEC-01", "category": "oracle", "severity": "high", "origin": "spec",
     "tool": "medusa", "hooks": ["MockOracleProvider.getOraclePrice"],
     "statement": "per docs: the protocol only acts on a price fresher than the heartbeat"},
    {"inv_id": "SPEC-02", "category": "fee", "severity": "critical", "origin": "spec",
     "tool": "halmos", "hooks": ["IVaultV1.withdrawFees"],
     "statement": "per docs: the withdrawal fee never exceeds the documented cap"},
]
PROFILE = {
    "architecture_md": "Perp DEX: wallet → router → order handler → market store + oracle. "
                       "Bespoke funding accrual; rebasing collateral each epoch.",
    "contract_types": ["perp-dex", "oracle", "vault"],
    "trust_boundaries": [],
    "privileged_roles": [{"name": "keeper", "description": "runs liquidations"}],
    "high_impact_areas": [{"rank": 1, "title": "Funding-rate accrual",
                           "contracts": ["MarketUtils"], "functions": ["getFundingFees"]}],
    "threat_model": {},
}
CODE_INVARIANTS = [
    {"inv_id": "PRICE-01", "category": "share_price", "severity": "high",
     "origin": "codebase_synth", "tool": "medusa",
     "hooks": ["MockOracleProvider.getOraclePrice"],
     "statement": "share price is stable across a read-only reentrant oracle call"},
    {"inv_id": "EXEC-01", "category": "execution", "severity": "critical",
     "origin": "codebase_synth", "tool": "slither", "hooks": ["IVaultV1.withdrawFees"],
     "statement": "no cross-contract reentrancy mutates accounting mid-execution"},
]
NOVEL = "task-threat-novel"   # orphan lead synthesis must carry forward
DUP = "task-threat-dup"       # overlaps PRICE-01; synthesis folds it (must NOT survive)
THREAT_CANDIDATES = [
    {"task_id": NOVEL, "title": "Keeper-auction transient-storage reuse across liquidations",
     "vuln_class": "logic_error", "scope_hint": "BespokeKeeperAuction.settleViaTransientSlot",
     "hypothesis": "off-checklist EIP-1153 slot reuse settles a 2nd liquidation at a stale price.",
     "priority": 2, "origin": "threat_research"},
    {"task_id": DUP, "title": "Oracle staleness on getOraclePrice (overlaps PRICE-01)",
     "vuln_class": "price_oracle_manipulation", "scope_hint": "MockOracleProvider.getOraclePrice",
     "hypothesis": "stale oracle price — already covered by invariant PRICE-01.",
     "priority": 3, "origin": "threat_research"},
]
# what the SYNTHESIS agent emits: invariant-driven tasks + the carried NOVEL lead.
# It deliberately does NOT re-emit DUP (folded) — proving sole authorship + dedup.
SYNTH_TASKS = [
    {"task_id": "task-inv-price-01", "title": "Break PRICE-01 share-price stability",
     "vuln_class": "price_oracle_manipulation", "scope_hint": "MockOracleProvider.getOraclePrice",
     "hypothesis": "violate PRICE-01", "priority": 1, "origin": "recon", "inv_id": "PRICE-01"},
    {"task_id": "task-inv-exec-01", "title": "Break EXEC-01 reentrancy",
     "vuln_class": "reentrancy", "scope_hint": "IVaultV1.withdrawFees",
     "hypothesis": "violate EXEC-01", "priority": 1, "origin": "recon", "inv_id": "EXEC-01"},
    {"task_id": NOVEL, "title": "Keeper-auction transient-storage reuse across liquidations",
     "vuln_class": "logic_error", "scope_hint": "BespokeKeeperAuction.settleViaTransientSlot",
     "hypothesis": "carried forward from threat research (EIP-1153 transient reuse).",
     "priority": 2, "origin": "threat_research"},
]


class _StubBackend:
    """Phase-aware stub: emits the right rows per spec and records each phase's prompt."""

    name = "stub"
    tools_doc = "## (stub) TOOLS: Read, Grep, code-index, WebFetch, WebSearch"

    def __init__(self) -> None:
        self.prompts: dict[str, str] = {}

    def selftest(self) -> str:
        return "stub ok"

    def _phase(self, spec) -> str:
        cmds = {e.command for e in spec.emitters}
        if spec.mode == "research" and "recon-create-invariant" in cmds:
            return "spec"
        if spec.mode == "research" and "recon-create-task" in cmds:
            return "threat"
        if "recon-create-profile" in cmds:
            return "explore"
        if cmds == {"recon-create-task"}:
            return "synthesis"
        return "unknown"

    def run_agent(self, spec, *, index_db, artifact_db, run_id, scratch_dir=None, cwd=None):
        phase = self._phase(spec)
        self.prompts[phase] = spec.system_prompt
        store = ReconStore(artifact_db)
        store.create_schema()
        try:
            if phase == "spec":
                for inv in SPEC_INVARIANTS:
                    store.add_invariant(run_id=run_id, agent=spec.name, session="stub", inv=inv)
            elif phase == "explore":
                store.add_profile(run_id=run_id, agent="recon", session="stub", profile=PROFILE)
                for inv in CODE_INVARIANTS:
                    store.add_invariant(run_id=run_id, agent=spec.name, session="stub", inv=inv)
            elif phase == "threat":
                for t in THREAT_CANDIDATES:
                    store.add_task(run_id=run_id, agent=spec.name, session="stub", task=t)
            elif phase == "synthesis":
                for t in SYNTH_TASKS:
                    store.add_task(run_id=run_id, agent=spec.name, session="stub", task=t)
        finally:
            store.close()
        return {"agent": spec.name, "session": "stub", "phase": phase}


def main() -> int:
    print(f"smoke_synthesis: S2 synthesis-mode flow · fixture={RUN}")
    assert (RUN / "checkpoints" / "s1.json").exists(), f"missing S1 checkpoint under {RUN}"

    cfg = load_config()
    assert cfg.get("recon", {}).get("synthesis_mode") is True, "synthesis_mode must default on"

    # Run against a TEMP copy of the run dir so the fixture's chainreaper.db is never
    # mutated (S2 clears+rewrites it). The S1 index + S0 repo are referenced by absolute
    # path from the checkpoints, so they stay read-only in place.
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d) / RUN.name
        (tmp / "checkpoints").mkdir(parents=True)
        for ck in ("s0.json", "s1.json"):
            shutil.copy(RUN / "checkpoints" / ck, tmp / "checkpoints" / ck)

        ctx = RunContext(run_id=RUN.name, run_dir=tmp, config=cfg)
        ctx.state["s0"] = json.loads((tmp / "checkpoints" / "s0.json").read_text())
        ctx.state["s1"] = json.loads((tmp / "checkpoints" / "s1.json").read_text())

        backend = _StubBackend()
        orig = s2_recon.build_backend
        s2_recon.build_backend = lambda *a, **k: backend  # type: ignore[assignment]
        try:
            result = s2_recon.run(ctx)
        finally:
            s2_recon.build_backend = orig  # type: ignore[assignment]

    assert result["status"] == "ok", f"S2 not ok: {result.get('status')}"
    assert {"spec", "explore", "threat", "synthesis"} <= set(backend.prompts), \
        f"not all 4 phases ran: {sorted(backend.prompts)}"
    print("  [OK ] all 4 phases ran: spec → explore → threat → synthesis")

    # 1. EXPLORE was fed the SPEC PROFILE (documented promises → code-vs-intent)
    ex = backend.prompts["explore"]
    assert "SPEC PROFILE" in ex and "withdrawal fee never exceeds" in ex, \
        "explore prompt missing the spec profile / documented promise"
    assert "do NOT emit any" in ex.lower() or "IGNORE Deliverable 3" in ex, \
        "explore prompt missing the no-tasks directive"
    print("  [OK ] EXPLORE received the SPEC PROFILE (code-vs-intent) + no-tasks directive")

    # 2. THREAT-RESEARCH was fed the INVARIANT SUITE (so it targets the complement)
    th = backend.prompts["threat"]
    assert "ALREADY COVERED" in th and "PRICE-01" in th, \
        "threat prompt missing the invariant suite ('already covered')"
    print("  [OK ] THREAT-RESEARCH received the invariant suite (PRICE-01) — targets the complement")

    # 3. SYNTHESIS was fed profile + invariants + the threat dossier (all sources)
    sy = backend.prompts["synthesis"]
    assert "THREAT-RESEARCH DOSSIER" in sy and NOVEL in sy, "synthesis missing the threat dossier"
    assert "INVARIANT SUITE" in sy and "PRICE-01" in sy, "synthesis missing the invariant suite"
    assert "RECON PROFILE" in sy and "Funding-rate accrual" in sy, "synthesis missing the profile"
    print("  [OK ] SYNTHESIS received ALL sources (profile + invariants + threat dossier)")

    # 4. Final queue: synthesis is the SOLE author — novel lead carried forward,
    #    the folded duplicate candidate does NOT survive, invariants are linked.
    tasks = result["hunter_tasks"]
    by_id = {t["task_id"]: t for t in tasks}
    assert NOVEL in by_id, f"novel orphan threat lead was lost: {sorted(by_id)}"
    assert by_id[NOVEL]["origin"] == "threat_research", "carried lead lost its threat_research origin"
    assert DUP not in by_id, \
        f"folded duplicate candidate survived → synthesis is NOT the sole author: {sorted(by_id)}"
    inv_linked = [t for t in tasks if t.get("inv_id")]
    assert inv_linked, "no invariant-linked tasks in the unified queue"
    # the spec + code invariants both merged into the persisted suite
    inv_ids = {i["inv_id"] for i in result["recon_profile"]["invariant_suite"]["invariants"]}
    assert {"SPEC-01", "SPEC-02", "PRICE-01", "EXEC-01"} <= inv_ids, \
        f"spec + code invariants did not merge into the suite: {sorted(inv_ids)}"
    print(f"  [OK ] SOLE-AUTHOR queue: novel lead carried (origin=threat_research), duplicate "
          f"folded (absent), {len(inv_linked)} invariant-linked, suite merges spec+code "
          f"({len(inv_ids)} invariants)")

    print("\nsmoke_synthesis: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
