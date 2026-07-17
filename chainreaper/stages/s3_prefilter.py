"""S3 · Prefilter (spec §S3) — the deterministic, thin policy gate between Recon
and the expensive S4 Hunt agents. **NO model/LLM calls, no network.**

Reads the S2 HunterTask queue + per-task dossiers from ``ctx.state["s2"]``, runs the
pure ``recon.prefilter`` (drop · order-by-agent-priority · conservative dedup · cap ·
tag — it does NOT re-score, since S2's agent already ranked with full context),
persists each ``PrefilterDecision`` to ``chainreaper.db.hunter_tasks.schedule`` (S3 →
S4 hand-off, mirroring the S2 ``context`` column), and checkpoints the scheduled
queue. Deferred/dropped tasks are recorded *with reasons* (never silently lost — S6
Gapfill can resurrect deferred).
"""

from __future__ import annotations

from pathlib import Path

from ..recon.prefilter import prefilter
from ..recon.store import ReconStore
from ..runtime.logging import get_logger

log = get_logger()


def run(ctx) -> dict:
    s2 = ctx.state.get("s2")
    if not s2 or s2.get("status") != "ok":
        raise RuntimeError("S3: S2 recon output not available in state (run S2 first)")
    tasks = s2.get("hunter_tasks") or []
    if not tasks:
        raise RuntimeError("S3: no HunterTasks in S2 output")

    cfg = ctx.config.get("prefilter", {}) or {}
    log.info("[s3] prefiltering %d hunter tasks (deterministic; no model calls)…", len(tasks))

    result = prefilter(tasks, config=cfg)

    # persist every decision to the per-run artifact DB (S3 → S4 hand-off).
    artifact_db = s2.get("artifact_db") or str(ctx.run_dir / "chainreaper.db")
    run_id = ctx.run_id
    persisted = 0
    if Path(artifact_db).exists():
        store = ReconStore(artifact_db)
        try:
            store.create_schema()  # idempotent + adds the `schedule` column if missing
            for d in result.decisions:
                store.set_task_schedule(run_id=run_id, task_id=d.task_id,
                                        schedule=d.model_dump(mode="json"))
                persisted += 1
        finally:
            store.close()
    else:
        log.info("[s3] artifact db %s missing — skipping schedule persistence", artifact_db)

    counts = {
        "scheduled": sum(1 for d in result.decisions if d.decision == "scheduled"),
        "deferred": sum(1 for d in result.decisions if d.decision == "deferred"),
        "dropped": sum(1 for d in result.decisions if d.decision == "dropped"),
        "by_class": result.by_class,
    }
    inv_scheduled = sum(1 for t in result.scheduled if t.inv_id)
    log.info("[s3] done · scheduled=%d (invariant=%d) deferred=%d dropped=%d · persisted=%d · db=%s",
             counts["scheduled"], inv_scheduled, counts["deferred"], counts["dropped"],
             persisted, artifact_db)

    return {
        "stage": "s3", "status": "ok",
        "artifact_db": artifact_db,
        "scheduled_tasks": [t.model_dump(mode="json") for t in result.scheduled],
        "decisions": [d.model_dump(mode="json") for d in result.decisions],
        "counts": counts,
    }
