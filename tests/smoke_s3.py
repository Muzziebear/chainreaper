"""S3 self-test (offline, ZERO token spend).

Loads an existing S2 checkpoint (``runs/<run_id>/checkpoints/s2.json``), runs the
deterministic prefilter + DB persistence, and asserts the spec §S3 contract:
  * every input task gets exactly one PrefilterDecision;
  * the scheduled queue is ordered by score desc and ranked 1..N;
  * no scheduled task was drop-eligible (no targets / all out-of-scope);
  * per-class caps and the global cap are respected;
  * invariant-driven tasks are present in the schedule;
  * decisions persist to chainreaper.db.hunter_tasks.schedule and round-trip
    through PrefilterDecision.

Usage:  python tests/smoke_s3.py [runs/<run_id>/checkpoints/s2.json]
Defaults to runs/test-s1/checkpoints/s2.json (the verified offline fixture).
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

from chainreaper.models import PrefilterDecision
from chainreaper.recon.prefilter import DEFAULT_CONFIG, prefilter
from chainreaper.recon.store import ReconStore


def _default_s2() -> Path:
    p = Path("runs/test-s1/checkpoints/s2.json")
    if p.exists():
        return p
    cands = sorted(Path("runs").glob("*/checkpoints/s2.json"))
    if not cands:
        raise SystemExit("no s2.json checkpoint found under runs/*/checkpoints/")
    return cands[-1]


def _out_of_scope(path: str | None) -> bool:
    p = (path or "").lower()
    return any(f in p for f in ("node_modules/", "/mock/", "mock/", "/test/"))


def _drop_eligible(dossier: dict) -> bool:
    tfs = dossier.get("target_functions", [])
    if not tfs:
        return True
    return all(_out_of_scope(t.get("file")) for t in tfs)


def main() -> int:
    s2_path = Path(sys.argv[1]) if len(sys.argv) > 1 else _default_s2()
    print(f"== s2 checkpoint: {s2_path} ==")
    s2 = json.loads(s2_path.read_text())
    tasks = s2["hunter_tasks"]
    assert tasks, "empty hunter_tasks"

    cfg = DEFAULT_CONFIG
    result = prefilter(tasks, config=cfg)
    decisions = result.decisions
    by_id = result.decisions_by_id

    # 1. every input task gets exactly one decision
    assert len(decisions) == len(tasks), f"{len(decisions)} decisions for {len(tasks)} tasks"
    assert len(by_id) == len(tasks), "duplicate decision task_ids"
    in_ids = {t["task_id"] for t in tasks}
    assert set(by_id) == in_ids, "decision task_ids != input task_ids (a task was lost)"
    kinds = {"scheduled": 0, "deferred": 0, "dropped": 0}
    for d in decisions:
        kinds[d.decision] += 1
    print(f"## decisions: {kinds} (total {len(decisions)})")

    # 2. scheduled queue ordered by score desc + ranked 1..N
    sched = result.scheduled
    assert len(sched) == kinds["scheduled"], "scheduled list/decision count mismatch"
    sched_decisions = [by_id[t.task_id] for t in sched]
    scores = [d.score for d in sched_decisions]
    assert scores == sorted(scores, reverse=True), "scheduled queue not ordered by score desc"
    ranks = [d.rank for d in sched_decisions]
    assert ranks == list(range(1, len(sched) + 1)), f"ranks not 1..N: {ranks}"
    print(f"## scheduled queue ({len(sched)}), score-ordered, ranks 1..{len(sched)}")
    for d in sched_decisions[:8]:
        t = next(t for t in sched if t.task_id == d.task_id)
        print(f"    #{d.rank:<2} {d.score:6.2f} [{d.seed:>18}] {t.vuln_class:<26} {t.title[:48]}")

    # 3. no scheduled task was drop-eligible; dropped ones really are
    ctx_by_id = {t["task_id"]: (t.get("context") or {}) for t in tasks}
    for t in sched:
        assert not _drop_eligible(ctx_by_id[t.task_id]), f"scheduled task {t.task_id} was drop-eligible"
    for d in decisions:
        if d.decision == "dropped":
            assert _drop_eligible(ctx_by_id[d.task_id]), f"dropped {d.task_id} not actually drop-eligible"
    print(f"## drop integrity ok ({kinds['dropped']} dropped, all genuinely un-huntable)")

    # 4. DEFAULT is UNCAPPED → every non-dropped task is scheduled. S2 synthesis owns
    #    dedup now, so S3 no longer defers twins: with no cap there are ZERO deferrals.
    deferred = [d for d in decisions if d.decision == "deferred"]
    assert not deferred, \
        f"uncapped default should defer nothing (dedup is S2's job): {[d.task_id for d in deferred]}"
    print(f"## uncapped default · scheduled {len(sched)} · 0 deferrals (dedup is S2's job) · by_class {result.by_class}")

    # 4b. an explicit cap is still honored (the configurable budget knob)
    capped = prefilter(tasks, config={**DEFAULT_CONFIG, "max_hunt_tasks": 3, "per_class_cap": 1})
    assert len(capped.scheduled) <= 3, f"explicit global cap exceeded: {len(capped.scheduled)}"
    for vc, n in capped.by_class.items():
        assert n <= 1, f"explicit per-class cap exceeded for {vc}: {n}"
    assert any(d.decision == "deferred" and any("cap" in r for r in d.reasons)
               for d in capped.decisions), "explicit cap produced no cap-deferral"
    print(f"## explicit cap (max 3, per-class 1) honored · scheduled {len(capped.scheduled)} · by_class {capped.by_class}")

    # 5. invariant-driven tasks present in the schedule (seed-tagged, same queue)
    inv_sched = [t for t in sched if t.inv_id]
    assert inv_sched, "no invariant-driven task scheduled"
    assert all(by_id[t.task_id].seed == "invariant-campaign" for t in inv_sched), \
        "invariant task not tagged invariant-campaign"
    assert all(by_id[t.task_id].seed == "hypothesis" for t in sched if not t.inv_id), \
        "non-invariant task not tagged hypothesis"
    print(f"## invariant-driven scheduled: {len(inv_sched)} (seed=invariant-campaign)")

    # 6. persist to chainreaper.db.hunter_tasks.schedule and round-trip
    run_id = "smoke-s3"
    with tempfile.TemporaryDirectory() as tmp:
        db = str(Path(tmp) / "chainreaper.db")
        store = ReconStore(db)
        store.create_schema()
        # seed the task rows so UPDATE ... schedule has something to write to
        for t in tasks:
            core = {k: v for k, v in t.items() if k != "context"}
            store.add_task(run_id=run_id, agent="stage", session="smoke", task=core)
        for d in decisions:
            store.set_task_schedule(run_id=run_id, task_id=d.task_id, schedule=d.model_dump(mode="json"))
        round_tripped = store.get_schedules(run_id)
        store.close()
    assert set(round_tripped) == in_ids, "persisted schedules != all tasks"
    for tid, raw in round_tripped.items():
        rt = PrefilterDecision.model_validate(raw)
        assert rt == by_id[tid], f"round-trip mismatch for {tid}"
    print(f"## persistence ok · {len(round_tripped)} schedules round-trip through PrefilterDecision")

    print("\nPASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
