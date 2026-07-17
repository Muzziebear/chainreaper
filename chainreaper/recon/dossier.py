"""Per-task hunter dossier builder (S2 → S4 hand-off support).

Deterministically assembles a ``HunterDossier`` for each ``HunterTask`` from the
S1 index + the ReconProfile: the matched HotZone, the resolved target functions,
the **reachable public entrypoints** (attack surface, via a bounded callers-BFS),
the external-call sinks + accounting state in scope, the invariants binding the
region, the existing controls (so a hunter doesn't chase already-defended paths),
and the slither findings on the in-scope files. No model calls — this is the same
"read the index" determinism as ``bind_hooks``.
"""

from __future__ import annotations

import re
from collections import deque
from typing import Any

from ..models import HunterDossier, HunterTask, Invariant, ReconProfileInput
from ..tools.code_index import CodeIndex

_CM = re.compile(r"\b([A-Z][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*)")  # Contract.method
_FILELINE = re.compile(r"([\w./-]+\.(?:sol|vy|rs|move)):(\d+)")
_FILE = re.compile(r"([\w./-]+\.(?:sol|vy|rs|move))")
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _match_hotzone(task: HunterTask, hotzones: list) -> Any:
    tl = task.title.strip().lower()
    for hz in hotzones:
        if hz.title.strip().lower() == tl:
            return hz
    for hz in hotzones:
        h = hz.title.strip().lower()
        if h and (h in tl or tl in h):
            return hz
    best, best_n = None, 0
    sh = task.scope_hint.lower()
    for hz in hotzones:
        n = sum(1 for c in hz.contracts if c and c.lower() in sh)
        if n > best_n:
            best, best_n = hz, n
    return best if best_n else None


def _resolve_targets(ci: CodeIndex, text: str) -> list[dict]:
    """Resolve a task's scope text to concrete functions, robust to how the agent
    wrote it: by **file:line** (always present, naming-independent), by
    ``Contract.method``, and by **bare names** in parens scoped to the files the
    scope references (so we don't pull every `initialize`/`constructor` repo-wide)."""
    out, seen = [], set()

    def _add(rows: list[dict], only_files: set | None = None) -> None:
        for r in rows:
            sig = r.get("signature")
            if not sig or sig in seen:
                continue
            if only_files is not None and r.get("file") not in only_files:
                continue
            seen.add(sig)
            out.append({
                "contract": r.get("contract"), "name": r.get("name"), "signature": sig,
                "file": r.get("file"), "line_start": r.get("line_start"),
                "line_end": r.get("line_end"), "visibility": r.get("visibility"),
                "modifiers": r.get("modifiers"), "is_entrypoint": bool(r.get("is_entrypoint")),
            })

    files = set(_FILE.findall(text))
    basenames = {f.rsplit("/", 1)[-1] for f in files}

    # 1. file:line — the precise, naming-independent signal
    for f, ln in _FILELINE.findall(text):
        try:
            _add(ci.query("function_at", {"file": f, "line": int(ln)}))
        except Exception:
            pass
    # 2. Contract.method (e.g. canonicalized invariant hooks)
    for contract, method in _CM.findall(text):
        try:
            _add(ci.query("function", {"contract": contract, "name": method}))
        except Exception:
            pass
    # 3. bare function names in parens, scoped to the referenced files
    bare = set()
    for grp in re.findall(r"\(([^)]*)\)", text):
        bare |= {t for t in _IDENT.findall(grp) if len(t) >= 4}
    for nm in bare:
        try:
            rows = ci.query("function", {"name": nm})
        except Exception:
            rows = []
        scoped = {r.get("file") for r in rows
                  if r.get("file") and (r["file"] in files
                                        or r["file"].rsplit("/", 1)[-1] in basenames)}
        if scoped:
            _add(rows, only_files=scoped)
    return out[:24]


def _reachable_entrypoints(ci: CodeIndex, targets: list[tuple[str, str]],
                           max_depth: int = 4, max_visited: int = 140,
                           max_eps: int = 10) -> list[dict]:
    """Bounded callers-BFS upward from each target to the public entrypoints that
    can reach it — the attack surface for a PoC."""
    eps: dict[str, dict] = {}
    visited: set[tuple[str, str]] = set()
    frontier: deque = deque((c, n, [f"{c}.{n}"]) for c, n in targets)
    depth = 0
    while frontier and depth < max_depth and len(visited) < max_visited and len(eps) < max_eps:
        nxt: deque = deque()
        while frontier and len(visited) < max_visited:
            c, n, path = frontier.popleft()
            if (c, n) in visited:
                continue
            visited.add((c, n))
            try:
                callers = ci.query("callers", {"contract": c, "name": n})
            except Exception:
                callers = []
            for r in callers:
                rc, rn = r.get("contract"), r.get("name")
                if not rc or not rn:
                    continue
                rpath = [f"{rc}.{rn}", *path]
                if r.get("is_entrypoint"):
                    key = f"{rc}.{rn}"
                    eps.setdefault(key, {
                        "contract": rc, "name": rn, "signature": r.get("signature"),
                        "file": r.get("file"), "line_start": r.get("line_start"),
                        "modifiers": r.get("modifiers"), "path": " → ".join(rpath),
                    })
                elif (rc, rn) not in visited:
                    nxt.append((rc, rn, rpath))
        frontier = nxt
        depth += 1
    return list(eps.values())[:max_eps]


def _sinks(ci: CodeIndex, target_fns: list[dict], contracts: list[str]) -> list[dict]:
    sigs = {t["signature"] for t in target_fns if t.get("signature")}
    out, seen = [], set()
    for c in contracts:
        try:
            rows = ci.query("sinks", {"contract": c})
        except Exception:
            rows = []
        for r in rows:
            if sigs and r.get("func_signature") not in sigs:
                continue
            key = (r.get("func_signature"), r.get("kind"), r.get("line"))
            if key in seen:
                continue
            seen.add(key)
            out.append(r)
    return out[:30]


def _state_vars(ci: CodeIndex, contracts: list[str]) -> list[dict]:
    out = []
    for c in contracts:
        try:
            out += [{**r, "contract": c} for r in ci.query("storage_layout", {"contract": c})]
        except Exception:
            pass
    return out[:40]


def _slither(ci: CodeIndex, contracts: list[str]) -> list[dict]:
    out, seen = [], set()
    for c in contracts:
        try:
            rows = ci.query("sast", {"contract": c})
        except Exception:
            rows = []
        for r in rows:
            key = (r.get("check_id"), r.get("file"), r.get("line"))
            if key in seen:
                continue
            seen.add(key)
            out.append(r)
    # High/Medium first
    out.sort(key=lambda r: {"High": 0, "Medium": 1, "Low": 2}.get(r.get("impact"), 3))
    return out[:30]


def _controls(profile: ReconProfileInput, contracts: list[str]) -> list[str]:
    tcl = {c.lower() for c in contracts if c}
    out: list[str] = []
    for b in profile.trust_boundaries:
        blob = " ".join([b.name, b.description, b.crossing, *b.actors]).lower()
        if any(tc in blob for tc in tcl):
            out += b.controls
    for e in profile.threat_model.entries:
        blob = f"{e.asset} {e.threat}".lower()
        if e.existing_control and any(tc in blob for tc in tcl):
            out.append(e.existing_control)
    seen, res = set(), []
    for c in out:
        if c and c not in seen:
            seen.add(c)
            res.append(c)
    return res[:12]


def _relevant_invariants(task: HunterTask, invariants: list[Invariant],
                         inv_by_id: dict, target_keys: set[str]) -> list[Invariant]:
    rel: list[Invariant] = []
    if task.inv_id and task.inv_id in inv_by_id:
        rel.append(inv_by_id[task.inv_id])
    keys = {k.lower() for k in target_keys}
    for inv in invariants:
        if inv in rel:
            continue
        hooks = " ".join(inv.hooks).lower()
        if any(k in hooks for k in keys):
            rel.append(inv)
    return rel[:8]


def build_dossiers(index_db: str, tasks: list[HunterTask], profile: ReconProfileInput,
                   invariants: list[Invariant]) -> dict[str, HunterDossier]:
    ci = CodeIndex(index_db)
    inv_by_id = {inv.inv_id: inv for inv in invariants}
    hotzones = profile.high_impact_areas
    out: dict[str, HunterDossier] = {}
    try:
        for task in tasks:
            hz = _match_hotzone(task, hotzones)
            text = task.scope_hint
            if hz:
                text += " " + " ".join(hz.functions) + " " + " ".join(hz.contracts)
            if task.inv_id and task.inv_id in inv_by_id:
                text += " " + " ".join(inv_by_id[task.inv_id].hooks)
            # Cross-contract / economic-chain tasks (T2.1) span several contracts +
            # an attack path — fold both into the resolution text so the dossier
            # picks up every hop's surface, not just the single scope_hint region.
            cross = bool(len(task.contracts) > 1 or task.attack_path)
            if task.contracts:
                text += " " + " ".join(task.contracts)
            if task.attack_path:
                text += " " + " ".join(task.attack_path)
            target_fns = _resolve_targets(ci, text)

            contracts: list[str] = []
            for c in task.contracts:                       # the agent's explicit scope first
                if c and c not in contracts:
                    contracts.append(c)
            for t in target_fns:
                if t["contract"] and t["contract"] not in contracts:
                    contracts.append(t["contract"])
            for c in (hz.contracts if hz else []):
                if c and c not in contracts:
                    contracts.append(c)
            contracts = contracts[:16 if cross else 8]     # widen for multi-hop scope

            target_keys = set(contracts) | {f"{t['contract']}.{t['name']}" for t in target_fns}
            rel_invs = _relevant_invariants(task, invariants, inv_by_id, target_keys)

            # reachable entrypoints: targets that are themselves entrypoints + BFS up
            self_eps = [{"contract": t["contract"], "name": t["name"],
                         "signature": t["signature"], "file": t["file"],
                         "line_start": t["line_start"], "modifiers": t.get("modifiers"),
                         "path": f"{t['contract']}.{t['name']} (entrypoint)"}
                        for t in target_fns if t["is_entrypoint"]]
            bfs_targets = [(t["contract"], t["name"]) for t in target_fns if not t["is_entrypoint"]]
            reach = self_eps + _reachable_entrypoints(ci, bfs_targets)
            seen_ep, reach_u = set(), []
            for e in reach:
                k = f"{e['contract']}.{e['name']}"
                if k not in seen_ep:
                    seen_ep.add(k)
                    reach_u.append(e)
            note = ("" if reach_u else
                    "no resolved entrypoint path (S1 call-graph edges ~65% resolved — "
                    "trace from the routers manually)")

            out[task.task_id] = HunterDossier(
                task_id=task.task_id, vuln_class=task.vuln_class, hotzone=hz,
                target_functions=target_fns, reachable_entrypoints=reach_u[:10],
                external_call_sinks=_sinks(ci, target_fns, contracts),
                accounting_state_vars=_state_vars(ci, contracts),
                invariants=rel_invs, controls=_controls(profile, contracts),
                slither_findings=_slither(ci, contracts), reach_note=note,
            )
    finally:
        ci.close()
    return out
