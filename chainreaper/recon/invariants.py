"""Invariant hook-binding + recall grading (S2 Invariant Synthesizer support).

Two deterministic post-processing steps over the LLM-emitted ``InvariantList``:

* ``bind_hooks`` — resolve each invariant's ``hooks`` strings against the S1
  SQLite index to a real ``path:line symbol``. An invariant with no bound hook
  is worthless (the harness can't reference it), so binding is also the
  precision gate: ``coverage_map[inv_id]`` records bound/total + per-hook detail,
  and unbindable invariants can be dropped.

* ``grade_recall`` — the benchmark oracle. Grades the suite against
  ``tools_poc/invariants.md`` §10 (the 2025-hack regression class): does Recon
  surface invariants matching PRICE-01/PRICE-02 (share-price reentrancy
  stability + short-side coupling) and EXEC-01 (cross-contract reentrancy)?
"""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path
from typing import Any

# --------------------------------------------------------------------------- #
# Hook binding                                                                 #
# --------------------------------------------------------------------------- #
_FILELINE = re.compile(r"^(?P<path>[\w./-]+\.(?:sol|vy|rs|move))(?::(?P<line>\d+))?$")


def _row(conn: sqlite3.Connection, sql: str, params: tuple) -> dict | None:
    cur = conn.execute(sql, params)
    r = cur.fetchone()
    return dict(r) if r else None


_SYMBOL = re.compile(r"\b([A-Z][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*)")
_EMBEDDED_FILELINE = re.compile(r"([\w./-]+\.(?:sol|vy|rs|move)):(\d+)")
_BARE_NAME = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\b")


def _fn_row(conn, contract, name):
    sql = ("SELECT f.name, fl.path AS file, f.line_start, c.name AS contract "
           "FROM functions f JOIN contracts c ON f.contract_id=c.contract_id "
           "LEFT JOIN files fl ON f.file_id=fl.file_id WHERE f.name=? ")
    params: tuple = (name,)
    if contract:
        sql += "AND c.name=? "
        params = (name, contract)
    return _row(conn, sql + "ORDER BY f.line_start LIMIT 1", params)


def _var_row(conn, contract, name):
    sql = ("SELECT sv.name, sv.line, fl.path AS file, c.name AS contract "
           "FROM state_vars sv JOIN contracts c ON sv.contract_id=c.contract_id "
           "LEFT JOIN files fl ON c.file_id=fl.file_id WHERE sv.name=? ")
    params: tuple = (name,)
    if contract:
        sql += "AND c.name=? "
        params = (name, contract)
    return _row(conn, sql + "LIMIT 1", params)


def _resolve_hook(conn: sqlite3.Connection, hook: str) -> dict:
    """Resolve one hook string to a real file:symbol from the S1 index.

    Hooks are emitted in varied shapes — bare ``Contract.symbol``, a full
    ``contracts/x.sol:157``, or a rich ``Contract.symbol — contracts/x.sol:157
    [note]``. We extract the first ``Contract.symbol`` token and/or an embedded
    ``file:line`` and resolve by (in order) function → state var → embedded
    file:line (verified indexed) → contract. Returns ``{hook, resolved, file,
    line, symbol, kind}``."""
    h = hook.strip()
    miss = {"hook": hook, "resolved": False, "file": None, "line": None,
            "symbol": None, "kind": None}
    if not h:
        return miss

    sym = _SYMBOL.search(h)
    fl = _EMBEDDED_FILELINE.search(h)

    # 1. Contract.symbol → function, then state var
    if sym:
        contract, name = sym.group(1), sym.group(2)
        fr = _fn_row(conn, contract, name)
        if fr:
            return {"hook": hook, "resolved": True, "file": fr["file"],
                    "line": fr["line_start"], "symbol": f"{fr['contract']}.{fr['name']}",
                    "kind": "function"}
        sv = _var_row(conn, contract, name)
        if sv:
            return {"hook": hook, "resolved": True, "file": sv["file"], "line": sv["line"],
                    "symbol": f"{sv['contract']}.{sv['name']}", "kind": "state_var"}

    # 2. embedded file:line (verify the file is indexed)
    if fl:
        path, line = fl.group(1), int(fl.group(2))
        frow = _row(conn, "SELECT path FROM files WHERE path=? OR path LIKE ?",
                    (path, f"%/{path.split('/')[-1]}"))
        if frow:
            return {"hook": hook, "resolved": True, "file": frow["path"], "line": line,
                    "symbol": (f"{sym.group(1)}.{sym.group(2)}" if sym else None),
                    "kind": "file"}

    # 3. contract named by the symbol's left side, or a bare contract token
    candidates = []
    if sym:
        candidates.append(sym.group(1))
    bare = _BARE_NAME.search(h)
    if bare:
        candidates.append(bare.group(1))
    for cand in candidates:
        cr = _row(conn, "SELECT c.name, c.line, fl.path AS file FROM contracts c "
                  "LEFT JOIN files fl ON c.file_id=fl.file_id WHERE c.name=? LIMIT 1", (cand,))
        if cr:
            return {"hook": hook, "resolved": True, "file": cr["file"], "line": cr["line"],
                    "symbol": cr["name"], "kind": "contract"}

    # 4. function/var by a bare name (no contract qualifier)
    if bare:
        fr = _fn_row(conn, None, bare.group(1))
        if fr:
            return {"hook": hook, "resolved": True, "file": fr["file"],
                    "line": fr["line_start"], "symbol": f"{fr['contract']}.{fr['name']}",
                    "kind": "function"}
    return miss


def bind_hooks(db_path: str | Path, invariants: list[Any]) -> dict:
    """Resolve every invariant's hooks against the S1 index.

    Mutates each invariant in place: bound hooks are rewritten to canonical
    ``path:line symbol`` form; the invariant's ``status`` is bumped to
    ``scaffolded`` if at least one hook bound. Returns the ``coverage_map``
    (``inv_id -> {bound, total, hooks:[...]}``).
    """
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    coverage: dict[str, dict] = {}
    try:
        for inv in invariants:
            resolved = [_resolve_hook(conn, hk) for hk in (inv.hooks or [])]
            bound = [r for r in resolved if r["resolved"]]
            # rewrite hooks to canonical bound form where possible
            new_hooks = []
            for r in resolved:
                if r["resolved"] and r["file"]:
                    loc = f"{r['file']}:{r['line']}" if r.get("line") else r["file"]
                    new_hooks.append(f"{loc} {r['symbol']}".strip() if r.get("symbol") else loc)
                else:
                    new_hooks.append(r["hook"])
            inv.hooks = new_hooks
            if bound and inv.status == "proposed":
                inv.status = "scaffolded"
            coverage[inv.inv_id] = {
                "bound": len(bound), "total": len(resolved), "hooks": resolved,
            }
    finally:
        conn.close()
    return coverage


# --------------------------------------------------------------------------- #
# Recall grading — the 2025-hack regression suite (invariants.md §10)          #
# --------------------------------------------------------------------------- #
def _inv_text(inv: Any) -> str:
    return f"{inv.inv_id} {inv.statement} {' '.join(inv.hooks or [])}".lower()


def _has(text: str, *needles: str) -> bool:
    return any(n in text for n in needles)


def grade_recall(invariants: list[Any]) -> dict:
    """Grade the emitted suite against invariants.md §10 (PRICE-01/02 + EXEC-01).

    Each target is matched by category + keyword evidence. Returns
    ``{targets: {ID: {matched, inv_id, evidence}}, passed: bool, score: "n/3"}``.
    """
    def cat(inv: Any) -> str:
        c = inv.category
        return c.value if hasattr(c, "value") else str(c)

    targets = {
        # PRICE-01: AUM / market-token-price reentrancy stability
        "PRICE-01": {
            "desc": "share-price/AUM reentrancy stability",
            "match": lambda inv: cat(inv) in {"share_price", "oracle"}
            and _has(_inv_text(inv), "reentr")
            and _has(_inv_text(inv), "aum", "market token", "markettokenprice",
                     "share price", "share-price", "pool value", "poolvalue", "price")
            and _has(_inv_text(inv), "stab", "identical", "consistent", "mid-tx",
                     "re-read", "reread", "within", "same tx", "same transaction",
                     "manipulat", "invariant"),
        },
        # PRICE-02: short size ↔ short average price coupling. In GMX V2 the
        # analogous class is the open-interest ↔ open-interest-in-tokens (and
        # average-price) coupling — accept either the V1 (short) or V2 (OI) form.
        "PRICE-02": {
            "desc": "short/open-interest size ↔ average-price coupling stability",
            "match": lambda inv: cat(inv) in {"share_price", "position_pnl"}
            and _has(_inv_text(inv), "short", "open interest", "openinterest",
                     "open-interest", "average price", "averageprice", "average-price")
            and _has(_inv_text(inv), "couplin", "consistent", "inconsistent", "lag",
                     "stay", "in sync", "together", "size", "divergent", "diverge",
                     "atomic", "simultaneous", "lockstep", "synchron", "both", "equal"),
        },
        # EXEC-01: cross-contract reentrancy in execution/callback
        "EXEC-01": {
            "desc": "cross-contract reentrancy in execution",
            "match": lambda inv: cat(inv) == "execution"
            and _has(_inv_text(inv), "reentr")
            and _has(_inv_text(inv), "callback", "cross-contract", "cross contract",
                     "unwrap", "mid-execution", "mid execution", "execut", "transfer"),
        },
    }

    results: dict[str, dict] = {}
    for tid, spec in targets.items():
        hit = next((inv for inv in invariants if spec["match"](inv)), None)
        results[tid] = {
            "desc": spec["desc"],
            "matched": hit is not None,
            "inv_id": hit.inv_id if hit else None,
        }
    n = sum(1 for r in results.values() if r["matched"])
    return {"targets": results, "passed": n == len(targets), "score": f"{n}/{len(targets)}"}
