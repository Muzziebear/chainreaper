"""The schema-validated save-scripts' core (spec §8 structured emitters).

``create_record`` is the one function behind every ``chainreaper recon-create-*``
subcommand: it coerces + validates agent-supplied JSON against the emitter's
Pydantic schema and inserts it into the per-run ``chainreaper.db``, logging an
``agent_actions`` row. Kept separate from the CLI so it unit-tests directly
(``tests/smoke_emitters.py``) without spawning a process.

Accepts either a single JSON object or a JSON array of records (an agent may
batch). A schema miss raises ``EmitError`` carrying the expected JSON schema, so
the CLI can print it and the agent can self-correct and re-run.
"""

from __future__ import annotations

import json
from typing import Any

from pydantic import ValidationError

from ..models import coerce_to_model
from ..recon.store import ReconStore
from .spec import EMITTERS


class EmitError(Exception):
    """A validation/usage failure; ``schema`` is the expected JSON schema (if any)."""

    def __init__(self, message: str, schema: dict | None = None):
        super().__init__(message)
        self.schema = schema


def _strip_fences(raw: str) -> str:
    s = raw.strip()
    if s.startswith("```"):
        s = s.split("\n", 1)[1] if "\n" in s else s
        if s.rstrip().endswith("```"):
            s = s.rstrip()[:-3]
    if not s.lstrip().startswith(("{", "[")):
        i, j = s.find("{"), s.rfind("}")
        if 0 <= i < j:
            s = s[i:j + 1]
    return s.strip()


def _insert(store: ReconStore, table: str, *, run_id: str, agent: str,
            session: str, obj: dict) -> None:
    if table == "recon_profile":
        store.add_profile(run_id=run_id, agent=agent, session=session, profile=obj)
    elif table == "hunter_tasks":
        store.add_task(run_id=run_id, agent=agent, session=session, task=obj)
    elif table == "invariants":
        store.add_invariant(run_id=run_id, agent=agent, session=session, inv=obj)
    elif table == "findings":
        store.add_finding(run_id=run_id, agent=agent, session=session, finding=obj)
    elif table == "hunt_outcomes":
        store.add_outcome(run_id=run_id, agent=agent, session=session, outcome=obj)
    elif table == "verdicts":
        store.add_verdict(run_id=run_id, agent=agent, session=session, verdict=obj)
    else:  # pragma: no cover - registry guarantees one of the above
        raise EmitError(f"no insert path for table {table!r}")


def create_record(command: str, raw_json: str, *, db: str, run_id: str = "",
                  agent: str = "", session: str = "") -> dict[str, Any]:
    """Validate ``raw_json`` against ``command``'s schema and persist it. Returns
    a small summary dict; raises ``EmitError`` on bad input."""
    emitter = EMITTERS.get(command)
    if emitter is None:
        raise EmitError(f"unknown emitter {command!r}; valid: {', '.join(EMITTERS)}")

    try:
        data = json.loads(_strip_fences(raw_json))
    except json.JSONDecodeError as exc:
        raise EmitError(f"not valid JSON: {exc}")

    records = data if isinstance(data, list) else [data]
    if not records:
        # An empty array is a legitimate "nothing to emit" for a list-accepting,
        # optional emitter (e.g. a Hunter with an `empty` outcome calling
        # hunt-create-finding []): treat it as a clean no-op, not an error.
        if emitter.multiple and emitter.min_calls == 0:
            return {"ok": True, "command": command, "count": 0, "table": emitter.table}
        raise EmitError(f"{command}: no records provided")
    if not emitter.multiple and len(records) != 1:
        raise EmitError(f"{command} expects exactly one JSON object, got {len(records)}")

    schema = emitter.schema.model_json_schema()
    validated: list[dict] = []
    for i, rec in enumerate(records):
        if not isinstance(rec, dict):
            raise EmitError(f"{command}: record {i} is not a JSON object", schema=schema)
        try:
            obj = emitter.schema.model_validate(coerce_to_model(emitter.schema, rec))
        except ValidationError as exc:
            raise EmitError(f"record {i} failed {emitter.schema.__name__} validation:\n{exc}",
                            schema=schema)
        # Stamp the canonical OWASP SC Top-10 (2026) code on a Finding when the
        # hunter left it blank, so every finding carries the right code (T1.4).
        if emitter.table == "findings" and not getattr(obj, "sc_top10", None):
            from ..models import sc_top10_for
            code = sc_top10_for(getattr(obj, "vuln_class", None))
            if code:
                obj.sc_top10 = code
        validated.append(obj.model_dump(mode="json"))

    store = ReconStore(db)
    try:
        store.create_schema()
        for obj in validated:
            _insert(store, emitter.table, run_id=run_id, agent=agent,
                    session=session, obj=obj)
        store.record_action(run_id=run_id, agent=agent, session=session,
                            command=command, detail=f"{len(validated)} record(s)")
    finally:
        store.close()

    return {"ok": True, "command": command, "count": len(validated), "table": emitter.table}
