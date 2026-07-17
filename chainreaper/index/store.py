"""SQLite index store (IMPL-NOTES §3).

One DB per run at ``runs/{run_id}/index/index.db``. Owns the schema (DDL) and the
write API; reads/queries live in ``tools/code_index.py``. Backs both the
``IndexedRepo`` model and every ``code_index.query`` kind.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS repos (
  repo_id    INTEGER PRIMARY KEY,
  repo_ref   TEXT NOT NULL,
  language   TEXT NOT NULL,
  root_path  TEXT NOT NULL,
  commit_sha TEXT,
  indexed_at TEXT
);
CREATE TABLE IF NOT EXISTS files (
  file_id  INTEGER PRIMARY KEY,
  repo_id  INTEGER NOT NULL REFERENCES repos(repo_id),
  path     TEXT NOT NULL,
  language TEXT, loc INTEGER, sha256 TEXT
);
CREATE TABLE IF NOT EXISTS contracts (
  contract_id INTEGER PRIMARY KEY,
  repo_id     INTEGER NOT NULL REFERENCES repos(repo_id),
  file_id     INTEGER REFERENCES files(file_id),
  name        TEXT NOT NULL,
  kind        TEXT NOT NULL,
  line        INTEGER
);
CREATE TABLE IF NOT EXISTS inheritance (
  contract_id      INTEGER NOT NULL REFERENCES contracts(contract_id),
  base_name        TEXT NOT NULL,
  base_contract_id INTEGER REFERENCES contracts(contract_id)
);
CREATE TABLE IF NOT EXISTS functions (
  func_id        INTEGER PRIMARY KEY,
  contract_id    INTEGER NOT NULL REFERENCES contracts(contract_id),
  file_id        INTEGER REFERENCES files(file_id),
  name           TEXT NOT NULL,
  signature      TEXT NOT NULL,
  visibility     TEXT,
  mutability     TEXT,
  is_constructor INTEGER DEFAULT 0,
  is_entrypoint  INTEGER DEFAULT 0,
  modifiers      TEXT,
  line_start     INTEGER, line_end INTEGER
);
CREATE TABLE IF NOT EXISTS state_vars (
  var_id       INTEGER PRIMARY KEY,
  contract_id  INTEGER NOT NULL REFERENCES contracts(contract_id),
  name         TEXT NOT NULL,
  type         TEXT,
  visibility   TEXT,
  is_constant  INTEGER DEFAULT 0,
  is_immutable INTEGER DEFAULT 0,
  slot         INTEGER,
  line         INTEGER
);
CREATE TABLE IF NOT EXISTS var_access (
  func_id INTEGER NOT NULL REFERENCES functions(func_id),
  var_id  INTEGER NOT NULL REFERENCES state_vars(var_id),
  access  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS call_edges (
  edge_id        INTEGER PRIMARY KEY,
  caller_func_id INTEGER NOT NULL REFERENCES functions(func_id),
  callee_func_id INTEGER REFERENCES functions(func_id),
  callee_sig     TEXT NOT NULL,
  call_type      TEXT NOT NULL,
  line           INTEGER
);
CREATE TABLE IF NOT EXISTS sinks (
  sink_id INTEGER PRIMARY KEY,
  func_id INTEGER NOT NULL REFERENCES functions(func_id),
  kind    TEXT NOT NULL,
  detail  TEXT, line INTEGER
);
CREATE TABLE IF NOT EXISTS proxy_info (
  contract_id INTEGER REFERENCES contracts(contract_id),
  pattern TEXT, impl_slot TEXT, init_guard INTEGER
);
CREATE TABLE IF NOT EXISTS sast_findings (
  id INTEGER PRIMARY KEY, repo_id INTEGER REFERENCES repos(repo_id),
  tool TEXT, check_id TEXT, impact TEXT, confidence TEXT,
  file TEXT, line INTEGER, description TEXT, raw TEXT
);

CREATE INDEX IF NOT EXISTS ix_func_contract ON functions(contract_id);
CREATE INDEX IF NOT EXISTS ix_func_sig      ON functions(signature);
CREATE INDEX IF NOT EXISTS ix_func_entry    ON functions(is_entrypoint);
CREATE INDEX IF NOT EXISTS ix_edge_caller   ON call_edges(caller_func_id);
CREATE INDEX IF NOT EXISTS ix_edge_callee   ON call_edges(callee_func_id);
CREATE INDEX IF NOT EXISTS ix_edge_calleesig ON call_edges(callee_sig);
CREATE INDEX IF NOT EXISTS ix_va_var        ON var_access(var_id);
CREATE INDEX IF NOT EXISTS ix_va_func       ON var_access(func_id);
CREATE INDEX IF NOT EXISTS ix_sink_func     ON sinks(func_id);
CREATE INDEX IF NOT EXISTS ix_contract_name ON contracts(name);
"""


class Store:
    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")

    # -- lifecycle ---------------------------------------------------------- #
    def create_schema(self) -> None:
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def reset(self) -> None:
        """Drop all rows (idempotent re-index of a run)."""
        self.create_schema()
        for tbl in ("var_access", "call_edges", "sinks", "functions", "state_vars",
                    "inheritance", "proxy_info", "contracts", "files",
                    "sast_findings", "repos"):
            self.conn.execute(f"DELETE FROM {tbl}")
        self.conn.commit()

    def commit(self) -> None:
        self.conn.commit()

    def close(self) -> None:
        self.conn.commit()
        self.conn.close()

    # -- writers ------------------------------------------------------------ #
    def add_repo(self, repo_ref: str, language: str, root_path: str,
                 commit_sha: str | None = None, indexed_at: str | None = None) -> int:
        cur = self.conn.execute(
            "INSERT INTO repos(repo_ref,language,root_path,commit_sha,indexed_at) "
            "VALUES(?,?,?,?,?)",
            (repo_ref, language, root_path, commit_sha, indexed_at),
        )
        return cur.lastrowid

    def add_file(self, repo_id: int, path: str, language: str | None = None,
                 loc: int | None = None, sha256: str | None = None) -> int:
        cur = self.conn.execute(
            "INSERT INTO files(repo_id,path,language,loc,sha256) VALUES(?,?,?,?,?)",
            (repo_id, path, language, loc, sha256),
        )
        return cur.lastrowid

    def add_contract(self, repo_id: int, name: str, kind: str,
                     file_id: int | None = None, line: int | None = None) -> int:
        cur = self.conn.execute(
            "INSERT INTO contracts(repo_id,file_id,name,kind,line) VALUES(?,?,?,?,?)",
            (repo_id, file_id, name, kind, line),
        )
        return cur.lastrowid

    def add_inheritance(self, contract_id: int, base_name: str,
                        base_contract_id: int | None = None) -> None:
        self.conn.execute(
            "INSERT INTO inheritance(contract_id,base_name,base_contract_id) VALUES(?,?,?)",
            (contract_id, base_name, base_contract_id),
        )

    def add_function(self, contract_id: int, name: str, signature: str,
                     visibility: str | None, mutability: str | None,
                     is_constructor: bool, is_entrypoint: bool,
                     modifiers: list[str] | None, file_id: int | None,
                     line_start: int | None, line_end: int | None) -> int:
        cur = self.conn.execute(
            "INSERT INTO functions(contract_id,file_id,name,signature,visibility,"
            "mutability,is_constructor,is_entrypoint,modifiers,line_start,line_end) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (contract_id, file_id, name, signature, visibility, mutability,
             int(is_constructor), int(is_entrypoint),
             json.dumps(modifiers or []), line_start, line_end),
        )
        return cur.lastrowid

    def add_state_var(self, contract_id: int, name: str, type_: str | None,
                      visibility: str | None, is_constant: bool, is_immutable: bool,
                      slot: int | None, line: int | None) -> int:
        cur = self.conn.execute(
            "INSERT INTO state_vars(contract_id,name,type,visibility,is_constant,"
            "is_immutable,slot,line) VALUES(?,?,?,?,?,?,?,?)",
            (contract_id, name, type_, visibility, int(is_constant),
             int(is_immutable), slot, line),
        )
        return cur.lastrowid

    def add_var_access(self, func_id: int, var_id: int, access: str) -> None:
        self.conn.execute(
            "INSERT INTO var_access(func_id,var_id,access) VALUES(?,?,?)",
            (func_id, var_id, access),
        )

    def add_call_edge(self, caller_func_id: int, callee_sig: str, call_type: str,
                      callee_func_id: int | None = None, line: int | None = None) -> None:
        self.conn.execute(
            "INSERT INTO call_edges(caller_func_id,callee_func_id,callee_sig,call_type,line) "
            "VALUES(?,?,?,?,?)",
            (caller_func_id, callee_func_id, callee_sig, call_type, line),
        )

    def add_sink(self, func_id: int, kind: str, detail: str | None = None,
                 line: int | None = None) -> None:
        self.conn.execute(
            "INSERT INTO sinks(func_id,kind,detail,line) VALUES(?,?,?,?)",
            (func_id, kind, detail, line),
        )

    def add_proxy_info(self, contract_id: int, pattern: str | None,
                       impl_slot: str | None, init_guard: bool | None) -> None:
        self.conn.execute(
            "INSERT INTO proxy_info(contract_id,pattern,impl_slot,init_guard) VALUES(?,?,?,?)",
            (contract_id, pattern, impl_slot,
             None if init_guard is None else int(init_guard)),
        )

    def add_sast_finding(self, repo_id: int, tool: str, check_id: str | None,
                         impact: str | None, confidence: str | None, file: str | None,
                         line: int | None, description: str | None, raw: dict | None) -> None:
        self.conn.execute(
            "INSERT INTO sast_findings(repo_id,tool,check_id,impact,confidence,file,"
            "line,description,raw) VALUES(?,?,?,?,?,?,?,?,?)",
            (repo_id, tool, check_id, impact, confidence, file, line, description,
             json.dumps(raw) if raw is not None else None),
        )

    # -- summary ------------------------------------------------------------ #
    def counts(self) -> dict[str, int]:
        out = {}
        for tbl in ("repos", "files", "contracts", "functions", "state_vars",
                    "var_access", "call_edges", "sinks", "sast_findings"):
            out[tbl] = self.conn.execute(f"SELECT COUNT(*) FROM {tbl}").fetchone()[0]
        out["entrypoints"] = self.conn.execute(
            "SELECT COUNT(*) FROM functions WHERE is_entrypoint=1").fetchone()[0]
        return out
