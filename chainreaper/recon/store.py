"""Per-run artifact store — ``runs/{run_id}/chainreaper.db`` (the stage-output DB).

Separate from the S1 ``index/store.py`` (the structural index). This is where the
model-calling stages persist their *outputs*: the agents call schema-validated
``chainreaper recon-create-*`` subcommands that write here, and the stage reads
back to assemble its checkpoint. Owning the DDL + a small write/read API keeps the
"agent → script → database" contract in one place.

Tables (S2 slice):
  * ``recon_profile``  — one document per (run, agent, session): the validated
    ``ReconProfileInput`` (architecture + threat model + boundaries/roles/zones).
  * ``hunter_tasks``   — one row per ``HunterTask`` (queried individually by S3/S4).
  * ``invariants``     — one row per ``Invariant`` (hooks/coverage filled in by the
    deterministic ``bind_hooks`` pass after the agent emits).
  * ``agent_actions``  — audit log of every successful save-script call; the Stop
    hook counts these to enforce that an agent produced its required output.

Rows are scoped by ``(run_id, agent, session)`` so a re-run / hook-forced
continuation does not double-count, while readers default to the whole run.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS recon_profile (
  id                INTEGER PRIMARY KEY,
  run_id            TEXT NOT NULL,
  agent             TEXT,
  session           TEXT,
  architecture_md   TEXT,
  contract_types    TEXT,   -- json
  trust_boundaries  TEXT,   -- json
  privileged_roles  TEXT,   -- json
  high_impact_areas TEXT,   -- json
  threat_model      TEXT,   -- json
  doc               TEXT NOT NULL,  -- the full validated ReconProfileInput
  created_at        TEXT
);
CREATE TABLE IF NOT EXISTS hunter_tasks (
  id          INTEGER PRIMARY KEY,
  run_id      TEXT NOT NULL,
  agent       TEXT,
  session     TEXT,
  task_id     TEXT,
  title       TEXT,
  vuln_class  TEXT,
  priority    INTEGER,
  inv_id      TEXT,
  origin      TEXT,
  status      TEXT,
  doc         TEXT NOT NULL,  -- the full validated HunterTask
  context     TEXT,           -- the deterministic HunterDossier (S2 → S4 hand-off)
  schedule    TEXT,           -- the deterministic PrefilterDecision (S3 → S4 hand-off)
  created_at  TEXT
);
CREATE TABLE IF NOT EXISTS invariants (
  id          INTEGER PRIMARY KEY,
  run_id      TEXT NOT NULL,
  agent       TEXT,
  session     TEXT,
  inv_id      TEXT,
  category    TEXT,
  severity    TEXT,
  tool        TEXT,
  origin      TEXT,
  status      TEXT,
  hooks       TEXT,   -- json (canonicalized by bind_hooks)
  coverage    TEXT,   -- json (inv coverage report)
  doc         TEXT NOT NULL,  -- the full validated Invariant
  created_at  TEXT
);
CREATE TABLE IF NOT EXISTS agent_actions (
  id          INTEGER PRIMARY KEY,
  run_id      TEXT NOT NULL,
  agent       TEXT,
  session     TEXT,
  command     TEXT NOT NULL,
  detail      TEXT,
  created_at  TEXT
);
CREATE TABLE IF NOT EXISTS findings (
  id            INTEGER PRIMARY KEY,
  run_id        TEXT NOT NULL,
  agent         TEXT,
  session       TEXT,
  finding_id    TEXT,
  task_id       TEXT,
  title         TEXT,
  vuln_class    TEXT,
  severity      TEXT,
  confidence    REAL,
  live_validated INTEGER,
  trigger_class TEXT,           -- adversary-model class; only 'attacker_reachable' is payable
  doc           TEXT NOT NULL,  -- the full validated Finding
  created_at    TEXT
);
CREATE TABLE IF NOT EXISTS hunt_outcomes (
  id          INTEGER PRIMARY KEY,
  run_id      TEXT NOT NULL,
  agent       TEXT,
  session     TEXT,
  task_id     TEXT,
  outcome     TEXT,
  n_findings  INTEGER,
  poc_built   INTEGER,
  doc         TEXT NOT NULL,  -- the full validated HuntOutcome
  created_at  TEXT
);
CREATE TABLE IF NOT EXISTS verdicts (
  id            INTEGER PRIMARY KEY,
  run_id        TEXT NOT NULL,
  agent         TEXT,
  session       TEXT,
  finding_id    TEXT,
  verdict       TEXT,
  verdict_confidence INTEGER,
  adjusted_severity TEXT,
  doc           TEXT NOT NULL,  -- the full validated Verdict
  created_at    TEXT
);
CREATE INDEX IF NOT EXISTS ix_verdict_run ON verdicts(run_id, agent, session);
CREATE INDEX IF NOT EXISTS ix_profile_run ON recon_profile(run_id);
CREATE INDEX IF NOT EXISTS ix_task_run    ON hunter_tasks(run_id);
CREATE INDEX IF NOT EXISTS ix_inv_run     ON invariants(run_id);
CREATE INDEX IF NOT EXISTS ix_inv_invid   ON invariants(run_id, inv_id);
CREATE INDEX IF NOT EXISTS ix_action_run  ON agent_actions(run_id, agent, session, command);
CREATE INDEX IF NOT EXISTS ix_finding_run ON findings(run_id, agent, session);
CREATE INDEX IF NOT EXISTS ix_outcome_run ON hunt_outcomes(run_id, agent, session);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ReconStore:
    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row

    # -- lifecycle ---------------------------------------------------------- #
    def create_schema(self) -> None:
        self.conn.executescript(SCHEMA)
        # defensive migration for a pre-existing db created before `context` landed
        cols = {r[1] for r in self.conn.execute("PRAGMA table_info(hunter_tasks)")}
        if "context" not in cols:
            self.conn.execute("ALTER TABLE hunter_tasks ADD COLUMN context TEXT")
        if "schedule" not in cols:
            self.conn.execute("ALTER TABLE hunter_tasks ADD COLUMN schedule TEXT")
        self.conn.commit()

    def close(self) -> None:
        self.conn.commit()
        self.conn.close()

    def __enter__(self) -> "ReconStore":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- writers (used by the create-* CLI subcommands) --------------------- #
    def add_profile(self, *, run_id: str, agent: str, session: str, profile: dict) -> int:
        cur = self.conn.execute(
            "INSERT INTO recon_profile(run_id,agent,session,architecture_md,"
            "contract_types,trust_boundaries,privileged_roles,high_impact_areas,"
            "threat_model,doc,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (run_id, agent, session, profile.get("architecture_md", ""),
             json.dumps(profile.get("contract_types", [])),
             json.dumps(profile.get("trust_boundaries", [])),
             json.dumps(profile.get("privileged_roles", [])),
             json.dumps(profile.get("high_impact_areas", [])),
             json.dumps(profile.get("threat_model", {})),
             json.dumps(profile), _now()),
        )
        self.conn.commit()
        return cur.lastrowid

    def add_task(self, *, run_id: str, agent: str, session: str, task: dict) -> int:
        cur = self.conn.execute(
            "INSERT INTO hunter_tasks(run_id,agent,session,task_id,title,vuln_class,"
            "priority,inv_id,origin,status,doc,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (run_id, agent, session, task.get("task_id"), task.get("title"),
             task.get("vuln_class"), task.get("priority"), task.get("inv_id"),
             task.get("origin"), task.get("status"), json.dumps(task), _now()),
        )
        self.conn.commit()
        return cur.lastrowid

    def add_invariant(self, *, run_id: str, agent: str, session: str, inv: dict) -> int:
        cur = self.conn.execute(
            "INSERT INTO invariants(run_id,agent,session,inv_id,category,severity,"
            "tool,origin,status,hooks,coverage,doc,created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (run_id, agent, session, inv.get("inv_id"), inv.get("category"),
             inv.get("severity"), inv.get("tool"), inv.get("origin"),
             inv.get("status"), json.dumps(inv.get("hooks", [])), None,
             json.dumps(inv), _now()),
        )
        self.conn.commit()
        return cur.lastrowid

    def add_finding(self, *, run_id: str, agent: str, session: str, finding: dict) -> int:
        cur = self.conn.execute(
            "INSERT INTO findings(run_id,agent,session,finding_id,task_id,title,"
            "vuln_class,severity,confidence,live_validated,trigger_class,doc,created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (run_id, agent, session, finding.get("finding_id"), finding.get("task_id"),
             finding.get("title"), finding.get("vuln_class"),
             finding.get("severity_claim"), finding.get("confidence"),
             1 if finding.get("live_validated") else 0,
             finding.get("trigger_class"), json.dumps(finding), _now()),
        )
        self.conn.commit()
        return cur.lastrowid

    def add_outcome(self, *, run_id: str, agent: str, session: str, outcome: dict) -> int:
        cur = self.conn.execute(
            "INSERT INTO hunt_outcomes(run_id,agent,session,task_id,outcome,"
            "n_findings,poc_built,doc,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (run_id, agent, session, outcome.get("task_id"), outcome.get("outcome"),
             outcome.get("n_findings"), 1 if outcome.get("poc_built") else 0,
             json.dumps(outcome), _now()),
        )
        self.conn.commit()
        return cur.lastrowid

    def add_verdict(self, *, run_id: str, agent: str, session: str, verdict: dict) -> int:
        cur = self.conn.execute(
            "INSERT INTO verdicts(run_id,agent,session,finding_id,verdict,"
            "verdict_confidence,adjusted_severity,doc,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (run_id, agent, session, verdict.get("finding_id"), verdict.get("verdict"),
             verdict.get("verdict_confidence"), verdict.get("adjusted_severity"),
             json.dumps(verdict), _now()),
        )
        self.conn.commit()
        return cur.lastrowid

    def set_task_context(self, *, run_id: str, task_id: str, context: dict) -> None:
        """Attach the deterministic HunterDossier to a task row (S2 → S4 hand-off)."""
        self.conn.execute(
            "UPDATE hunter_tasks SET context=? WHERE run_id=? AND task_id=?",
            (json.dumps(context), run_id, task_id))
        self.conn.commit()

    def set_task_schedule(self, *, run_id: str, task_id: str, schedule: dict) -> None:
        """Attach the deterministic PrefilterDecision to a task row (S3 → S4 hand-off)."""
        self.conn.execute(
            "UPDATE hunter_tasks SET schedule=? WHERE run_id=? AND task_id=?",
            (json.dumps(schedule), run_id, task_id))
        self.conn.commit()

    def record_action(self, *, run_id: str, agent: str, session: str,
                      command: str, detail: str = "") -> None:
        self.conn.execute(
            "INSERT INTO agent_actions(run_id,agent,session,command,detail,created_at) "
            "VALUES(?,?,?,?,?,?)",
            (run_id, agent, session, command, detail, _now()),
        )
        self.conn.commit()

    # -- counting (used by the Stop hook to enforce required output) -------- #
    _COUNTABLE = {"recon_profile", "hunter_tasks", "invariants", "findings",
                  "hunt_outcomes", "verdicts"}

    def count_action(self, *, run_id: str, agent: str, session: str, command: str) -> int:
        return self.conn.execute(
            "SELECT COUNT(*) FROM agent_actions WHERE run_id=? AND agent=? AND "
            "session=? AND command=?", (run_id, agent, session, command),
        ).fetchone()[0]

    def count_records(self, *, run_id: str, agent: str, session: str, table: str) -> int:
        """Count output ROWS an agent persisted to ``table`` this session — the
        Stop hook's measure (so batching N records in one call still counts N)."""
        if table not in self._COUNTABLE:
            raise ValueError(f"not a countable output table: {table!r}")
        return self.conn.execute(
            f"SELECT COUNT(*) FROM {table} WHERE run_id=? AND agent=? AND session=?",
            (run_id, agent, session),
        ).fetchone()[0]

    def clear_run(self, run_id: str) -> None:
        """Drop all artifacts for a run — the stage recomputes S2 from scratch
        whenever it actually runs (resume is handled at the checkpoint layer)."""
        for tbl in ("recon_profile", "hunter_tasks", "invariants", "agent_actions"):
            self.conn.execute(f"DELETE FROM {tbl} WHERE run_id=?", (run_id,))
        self.conn.commit()

    def clear_tasks(self, run_id: str) -> None:
        """Drop only the HunterTask rows for a run, leaving the profile + invariants
        intact. Used by the split Recon (``recon.synthesis_mode``): the threat-research
        candidate leads are snapshotted, cleared here, then the synthesis session
        re-authors the SINGLE unified queue (carrying forward the leads it keeps), so
        the final queue has exactly one author and no candidate/duplicate rows linger."""
        self.conn.execute("DELETE FROM hunter_tasks WHERE run_id=?", (run_id,))
        self.conn.commit()

    def clear_hunt(self, run_id: str) -> None:
        """Drop the S4 Hunt artifacts for a run (findings + outcomes + their audit
        actions) so a re-run of S4 doesn't double-count. Leaves the S2/S3 recon
        rows (which S4 reads) intact."""
        for tbl in ("findings", "hunt_outcomes"):
            self.conn.execute(f"DELETE FROM {tbl} WHERE run_id=?", (run_id,))
        self.conn.execute(
            "DELETE FROM agent_actions WHERE run_id=? AND command IN "
            "('hunt-create-finding','hunt-finish','__stop_block__')", (run_id,))
        self.conn.commit()

    def clear_validate(self, run_id: str) -> None:
        """Drop the S5 Validate artifacts (verdicts + audit actions) so a re-run
        doesn't double-count. Leaves the S4 findings intact."""
        self.conn.execute("DELETE FROM verdicts WHERE run_id=?", (run_id,))
        self.conn.execute(
            "DELETE FROM agent_actions WHERE run_id=? AND command IN "
            "('critic-create-verdict','__stop_block__')", (run_id,))
        self.conn.commit()

    # -- readers (used by the stage) --------------------------------------- #
    def get_profile(self, run_id: str, agent: str = "recon") -> dict | None:
        row = self.conn.execute(
            "SELECT doc FROM recon_profile WHERE run_id=? AND agent=? "
            "ORDER BY id DESC LIMIT 1", (run_id, agent),
        ).fetchone()
        return json.loads(row["doc"]) if row else None

    def get_tasks(self, run_id: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT doc FROM hunter_tasks WHERE run_id=? ORDER BY id", (run_id,),
        ).fetchall()
        return [json.loads(r["doc"]) for r in rows]

    def get_schedules(self, run_id: str) -> dict[str, dict]:
        """task_id → its persisted PrefilterDecision dict (S3 output). Skips rows
        with no schedule yet (S3 not run)."""
        rows = self.conn.execute(
            "SELECT task_id, schedule FROM hunter_tasks WHERE run_id=? AND schedule IS NOT NULL",
            (run_id,),
        ).fetchall()
        return {r["task_id"]: json.loads(r["schedule"]) for r in rows}

    def get_contexts(self, run_id: str) -> dict[str, dict]:
        """task_id → its persisted HunterDossier dict (S2 output). Skips rows with
        no context yet. The authoritative S2 → S4 hand-off (the S3 checkpoint
        strips the dossier from its scheduled_tasks to stay small)."""
        rows = self.conn.execute(
            "SELECT task_id, context FROM hunter_tasks WHERE run_id=? AND context IS NOT NULL",
            (run_id,),
        ).fetchall()
        return {r["task_id"]: json.loads(r["context"]) for r in rows}

    def get_findings(self, run_id: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT doc FROM findings WHERE run_id=? ORDER BY id", (run_id,),
        ).fetchall()
        return [json.loads(r["doc"]) for r in rows]

    def get_outcomes(self, run_id: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT doc FROM hunt_outcomes WHERE run_id=? ORDER BY id", (run_id,),
        ).fetchall()
        return [json.loads(r["doc"]) for r in rows]

    def get_verdicts(self, run_id: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT doc FROM verdicts WHERE run_id=? ORDER BY id", (run_id,),
        ).fetchall()
        return [json.loads(r["doc"]) for r in rows]

    def get_invariants(self, run_id: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT doc FROM invariants WHERE run_id=? ORDER BY id", (run_id,),
        ).fetchall()
        return [json.loads(r["doc"]) for r in rows]

    def update_invariant(self, *, run_id: str, inv_id: str, hooks: list[str],
                         coverage: dict, status: str, doc: dict) -> None:
        """Persist the bind_hooks result back onto an invariant row."""
        self.conn.execute(
            "UPDATE invariants SET hooks=?, coverage=?, status=?, doc=? "
            "WHERE run_id=? AND inv_id=?",
            (json.dumps(hooks), json.dumps(coverage), status, json.dumps(doc),
             run_id, inv_id),
        )
        self.conn.commit()

    def counts(self, run_id: str) -> dict[str, int]:
        out: dict[str, int] = {}
        for tbl in ("recon_profile", "hunter_tasks", "invariants", "agent_actions"):
            out[tbl] = self.conn.execute(
                f"SELECT COUNT(*) FROM {tbl} WHERE run_id=?", (run_id,)
            ).fetchone()[0]
        return out
