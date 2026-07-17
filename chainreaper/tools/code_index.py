"""`code_index` query API (IMPL-NOTES §4, spec §8).

Read-side over the SQLite index built by S1. Every `query(kind, args)` returns a
list of JSON-serializable dicts. In S2+ this is exposed as an agent tool; for S1
it is unit-/self-tested directly.

A function is addressed by `{signature}` or `{contract, name}`.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path


class CodeIndex:
    def __init__(self, db_path: str | Path):
        self.conn = sqlite3.connect(str(db_path))
        self.conn.row_factory = sqlite3.Row

    def close(self) -> None:
        self.conn.close()

    # -- helpers ------------------------------------------------------------ #
    def _rows(self, sql: str, params: tuple = ()) -> list[dict]:
        return [dict(r) for r in self.conn.execute(sql, params).fetchall()]

    def _resolve_funcs(self, args: dict) -> list[dict]:
        """Resolve target functions to [{func_id, signature}]. A target addressed
        by {contract,name} resolves to every overload of that name in the contract."""
        if args.get("signature"):
            return self._rows("SELECT func_id, signature FROM functions WHERE signature=?",
                              (args["signature"],))
        if args.get("contract") and args.get("name"):
            return self._rows(
                "SELECT f.func_id, f.signature FROM functions f "
                "JOIN contracts c ON f.contract_id=c.contract_id "
                "WHERE c.name=? AND f.name=?", (args["contract"], args["name"]))
        if args.get("name"):
            return self._rows("SELECT func_id, signature FROM functions WHERE name=?",
                             (args["name"],))
        return []

    def _resolve_func_ids(self, args: dict) -> list[int]:
        return [r["func_id"] for r in self._resolve_funcs(args)]

    _FUNC_SELECT = (
        "SELECT f.func_id, c.name AS contract, f.name, f.signature, f.visibility, "
        "f.mutability, f.is_entrypoint, f.modifiers, fl.path AS file, "
        "f.line_start, f.line_end "
        "FROM functions f JOIN contracts c ON f.contract_id=c.contract_id "
        "LEFT JOIN files fl ON f.file_id=fl.file_id"
    )

    def _func_rows(self, where: str, params: tuple) -> list[dict]:
        rows = self._rows(f"{self._FUNC_SELECT} WHERE {where}", params)
        for r in rows:
            r["modifiers"] = json.loads(r["modifiers"]) if r.get("modifiers") else []
        return rows

    # -- public API --------------------------------------------------------- #
    def query(self, kind: str, args: dict | None = None) -> list[dict]:
        args = args or {}
        fn = getattr(self, f"_q_{kind}", None)
        if fn is None:
            raise ValueError(f"unknown code_index query kind: {kind!r}")
        return fn(args)

    def _q_contract(self, args: dict) -> list[dict]:
        name = args.get("name") or args.get("contract")
        if not name:
            raise ValueError('contract query needs {"name": "..."} (or "contract")')
        return self._rows(
            "SELECT c.contract_id, c.name, c.kind, fl.path AS file, c.line "
            "FROM contracts c LEFT JOIN files fl ON c.file_id=fl.file_id WHERE c.name=?",
            (name,))

    def _q_sast(self, args: dict) -> list[dict]:
        """Slither (SAST) findings recorded at index time — the detector output the
        Invariant Synthesizer grounds invariants in. Filter by impact
        (High/Medium/Low/Informational), check (slither check_id), contract (name
        substring), or file. Excludes node_modules/ unless include_deps=true."""
        where, params = ["1=1"], []
        if args.get("impact"):
            where.append("impact=?")
            params.append(str(args["impact"]).capitalize())
        if args.get("check"):
            where.append("check_id=?")
            params.append(args["check"])
        if args.get("file"):
            where.append("file=?")
            params.append(args["file"])
        if args.get("contract"):
            where.append("(file LIKE ? OR description LIKE ?)")
            params += [f"%{args['contract']}%", f"%{args['contract']}.%"]
        if not args.get("include_deps"):
            where.append("file NOT LIKE 'node_modules/%'")
        return self._rows(
            "SELECT tool, check_id, impact, confidence, file, line, "
            "substr(description,1,220) AS description FROM sast_findings "
            f"WHERE {' AND '.join(where)} ORDER BY CASE impact WHEN 'High' THEN 0 "
            "WHEN 'Medium' THEN 1 WHEN 'Low' THEN 2 ELSE 3 END, file LIMIT 200",
            tuple(params))

    def _q_function(self, args: dict) -> list[dict]:
        if args.get("signature"):
            return self._func_rows("f.signature=?", (args["signature"],))
        if args.get("contract") and args.get("name"):
            return self._func_rows("c.name=? AND f.name=?", (args["contract"], args["name"]))
        if args.get("name"):  # bare name (may match overloads across contracts)
            return self._func_rows("f.name=?", (args["name"],))
        raise ValueError('function query needs {signature} | {contract,name} | {name}')

    def _q_function_at(self, args: dict) -> list[dict]:
        """The function(s) spanning a file:line — robust resolution of a scope ref
        regardless of how it's named. File matched by exact path or basename."""
        f, line = args.get("file"), args.get("line")
        if not f or line is None:
            raise ValueError('function_at needs {file, line}')
        line = int(line)
        return self._func_rows(
            "(fl.path=? OR fl.path LIKE ?) AND f.line_start<=? AND f.line_end>=? "
            "ORDER BY (f.line_end - f.line_start)",  # smallest enclosing function first
            (f, f"%/{f.rsplit('/', 1)[-1]}", line, line))

    def _q_entrypoints(self, args: dict) -> list[dict]:
        if args.get("contract"):
            return self._func_rows("f.is_entrypoint=1 AND c.name=?", (args["contract"],))
        return self._func_rows("f.is_entrypoint=1", ())

    def _q_callers(self, args: dict) -> list[dict]:
        # Match callers both by resolved callee_func_id AND by callee signature.
        # The signature match is essential because external calls made through an
        # interface type resolve their callee to the *interface* declaration, not
        # the concrete implementation (e.g. ExchangeRouter -> IWithdrawalHandler).
        targets = self._resolve_funcs(args)
        ids = [t["func_id"] for t in targets]
        sigs = sorted({t["signature"] for t in targets if t.get("signature")})
        if not ids and not sigs:
            return []
        clauses, params = [], []
        if ids:
            clauses.append(f"e.callee_func_id IN ({','.join('?' * len(ids))})")
            params += ids
        if sigs:
            clauses.append(f"e.callee_sig IN ({','.join('?' * len(sigs))})")
            params += sigs
        rows = self._rows(
            f"SELECT DISTINCT f.func_id, c.name AS contract, f.name, f.signature, "
            f"f.visibility, f.mutability, f.is_entrypoint, f.modifiers, fl.path AS file, "
            f"f.line_start, f.line_end "
            f"FROM functions f JOIN contracts c ON f.contract_id=c.contract_id "
            f"LEFT JOIN files fl ON f.file_id=fl.file_id "
            f"JOIN call_edges e ON e.caller_func_id=f.func_id "
            f"WHERE {' OR '.join(clauses)}", tuple(params))
        for r in rows:
            r["modifiers"] = json.loads(r["modifiers"]) if r.get("modifiers") else []
        return rows

    def _q_callees(self, args: dict) -> list[dict]:
        ids = self._resolve_func_ids(args)
        if not ids:
            return []
        placeholders = ",".join("?" * len(ids))
        edges = self._rows(
            f"SELECT callee_func_id, callee_sig, call_type, line FROM call_edges "
            f"WHERE caller_func_id IN ({placeholders})", tuple(ids))
        out = []
        for e in edges:
            if e["callee_func_id"] is not None:
                fr = self._func_rows("f.func_id=?", (e["callee_func_id"],))
                if fr:
                    row = fr[0]
                    row.update({"external": False, "call_type": e["call_type"], "line": e["line"]})
                    out.append(row)
                    continue
            out.append({"signature": e["callee_sig"], "external": True,
                        "call_type": e["call_type"], "line": e["line"]})
        return out

    def _q_writers(self, args: dict) -> list[dict]:
        return self._var_access(args, "write")

    def _q_readers(self, args: dict) -> list[dict]:
        return self._var_access(args, "read")

    def _var_access(self, args: dict, access: str) -> list[dict]:
        return self._rows(
            f"{self._FUNC_SELECT} "
            "JOIN var_access va ON va.func_id=f.func_id "
            "JOIN state_vars sv ON va.var_id=sv.var_id "
            "JOIN contracts vc ON sv.contract_id=vc.contract_id "
            "WHERE vc.name=? AND sv.name=? AND va.access=?",
            (args["contract"], args["var"], access))

    def _q_external_calls_in(self, args: dict) -> list[dict]:
        ids = self._resolve_func_ids(args)
        if not ids:
            return []
        placeholders = ",".join("?" * len(ids))
        return self._rows(
            f"SELECT func_id, kind, detail, line FROM sinks "
            f"WHERE func_id IN ({placeholders}) "
            f"AND kind IN ('external_call','low_level_call','delegatecall')", tuple(ids))

    def _q_sinks(self, args: dict) -> list[dict]:
        where, params = [], []
        if args.get("kind"):
            where.append("s.kind=?")
            params.append(args["kind"])
        if args.get("contract"):
            where.append("c.name=?")
            params.append(args["contract"])
        clause = (" WHERE " + " AND ".join(where)) if where else ""
        return self._rows(
            "SELECT s.sink_id, c.name AS contract, f.signature AS func_signature, "
            "s.kind, s.detail, s.line FROM sinks s "
            "JOIN functions f ON s.func_id=f.func_id "
            "JOIN contracts c ON f.contract_id=c.contract_id" + clause, tuple(params))

    def _q_inheritance(self, args: dict) -> list[dict]:
        return self._rows(
            "SELECT i.base_name, i.base_contract_id FROM inheritance i "
            "JOIN contracts c ON i.contract_id=c.contract_id WHERE c.name=?",
            (args["contract"],))

    def _q_storage_layout(self, args: dict) -> list[dict]:
        return self._rows(
            "SELECT sv.name, sv.type, sv.visibility, sv.is_constant, sv.is_immutable, "
            "sv.slot, sv.line FROM state_vars sv "
            "JOIN contracts c ON sv.contract_id=c.contract_id WHERE c.name=?",
            (args["contract"],))

    def _q_proxy_info(self, args: dict) -> list[dict]:
        clause = " WHERE c.name=?" if args.get("contract") else ""
        params = (args["contract"],) if args.get("contract") else ()
        return self._rows(
            "SELECT c.name AS contract, p.pattern, p.impl_slot, p.init_guard "
            "FROM proxy_info p JOIN contracts c ON p.contract_id=c.contract_id" + clause,
            params)

    def _q_path(self, args: dict) -> list[dict]:
        # S10 (Trace) BFS over call_edges. S1 only stores edges; stub for now.
        return []


def query(db_path: str | Path, kind: str, args: dict | None = None) -> list[dict]:
    """Convenience one-shot: open, query, close."""
    idx = CodeIndex(db_path)
    try:
        return idx.query(kind, args)
    finally:
        idx.close()


def initialized_sast_tools(db_path: str | Path) -> list[str]:
    """The analyzers that actually ran at index time (distinct sast_findings.tool).
    These are the ONLY tools an invariant may be assigned to until a later stage
    initializes more (e.g. foundry/medusa in S4)."""
    conn = sqlite3.connect(str(db_path))
    try:
        rows = conn.execute(
            "SELECT DISTINCT tool FROM sast_findings WHERE tool IS NOT NULL AND tool!=''"
        ).fetchall()
        return sorted(r[0] for r in rows)
    except sqlite3.OperationalError:
        return []
    finally:
        conn.close()


def sast_overview(db_path: str | Path, max_checks: int = 40, max_top: int = 30) -> dict:
    """Summarize the index's SAST output for the Invariant Synthesizer prompt: the
    detector inventory (check_id × impact × count, in-scope only) and the top
    High/Medium findings on in-scope `contracts/` (excluding mocks/tests/deps)."""
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        checks = [dict(r) for r in conn.execute(
            "SELECT check_id, impact, COUNT(*) AS n FROM sast_findings "
            "WHERE file NOT LIKE 'node_modules/%' "
            "GROUP BY check_id, impact ORDER BY n DESC LIMIT ?", (max_checks,))]
        top = [dict(r) for r in conn.execute(
            "SELECT check_id, impact, file, line, substr(description,1,140) AS description "
            "FROM sast_findings WHERE impact IN ('High','Medium') "
            "AND file LIKE 'contracts/%' AND file NOT LIKE '%/mock/%' "
            "AND file NOT LIKE 'contracts/mock/%' AND file NOT LIKE '%/test/%' "
            "ORDER BY CASE impact WHEN 'High' THEN 0 ELSE 1 END, file LIMIT ?", (max_top,))]
        return {"checks": checks, "top": top}
    except sqlite3.OperationalError:
        return {"checks": [], "top": []}
    finally:
        conn.close()
