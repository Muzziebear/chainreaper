"""S3 Prefilter — the deterministic VALIDITY + BUDGET gate between Recon and the
expensive S4 Hunt agents (spec §S3). NO model calls.

The S2 Recon SYNTHESIS session ([[chainreaper-s2-synthesis-mode]]) is the SOLE author
of the queue: it already RANKS (assigns each task a ``priority`` 1..4 with the profile,
the invariant suite, and the threat-research dossier all in context) and DEDUPES (folds
true duplicates, carries distinct leads forward). So S3 does NOT re-rank or re-dedupe —
that would be false precision over the agent's judgment. S3 is now purely the
deterministic gate the LLM should not own: it consumes the post-hoc dossier facts
(reachability + target resolution against the S1 index) and the operator's budget policy.

  1. **Drop** invalid / out-of-scope tasks — a dossier that resolved no
     ``target_functions``, or whose every target sits under ``node_modules/`` /
     ``mock/`` / ``test/``. Exact, factual, free; catches a hallucinated/out-of-scope
     ``scope_hint`` before an Opus hunter is spent on it. (Protected task subtypes —
     dep-misbehavior / governance / multi-actor / long-horizon / threat-research — are
     valid by construction and never dropped for resolving no in-scope target.)
  2. **Order** by the agent's ``priority`` (primary) with ONE hard-fact tiebreak —
     a reachable public entrypoint — then ``task_id`` for stability. This is not a
     re-score: a P2 never outranks a P1. Its only load-bearing role is choosing which
     tasks make the cut when a budget cap binds (best-first top-K).
  3. **Cap** to budget — per-``vuln_class`` cap, a floor of ≥1 per high-severity
     class present, a reserved invariant-task quota, then global top-K. Pure operator
     policy (default: no cap → every valid task schedules).
  4. **Tag** the discovery seed (``invariant-campaign`` when ``inv_id`` is set, else
     ``hypothesis``) — a HINT for S4's first tool, NOT a terminal lane (spec §S4).

Every task ends with exactly one ``PrefilterDecision``; deferred/dropped are recorded
*with reasons* so a later gapfill pass can resurrect them. The ``--stop-after s3``
boundary is the operator's cheap review gate on the final scheduled queue before the
expensive hunt. (Semantic "is this the same bug?" merging of PROVEN findings remains
the LLM S9 Dedupe stage's job, downstream — distinct from S2's task-level dedup.)
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import HunterTask, PrefilterDecision, VulnClass

# --------------------------------------------------------------------------- #
# Static tables (categorical facts — NOT tuned weights)                       #
# --------------------------------------------------------------------------- #
# Out-of-scope path fragments (spec §S3): a target under any of these is not huntable.
_OUT_OF_SCOPE_PATHS = ("node_modules/", "/mock/", "mock/", "/test/")

# The fund-loss / high-impact vuln classes that get the never-starve cap floor.
# A categorical judgment about what these classes *are*, not a numeric weighting.
_HIGH_SEVERITY_CLASSES = frozenset({
    VulnClass.PRICE_ORACLE.value, VulnClass.FLASH_LOAN.value, VulnClass.REENTRANCY.value,
    VulnClass.READONLY_REENTRANCY.value, VulnClass.ACCESS_CONTROL.value,
    VulnClass.BRIDGE_REPLAY.value, VulnClass.FIRST_DEPOSITOR.value, VulnClass.LOGIC_ERROR.value,
})

# Caps default to None = "all" (no cap): schedule every valid, non-duplicate task.
# A cap is a deliberate budget knob, not a default — comprehensive recon coverage
# should survive prefiltering unless the operator explicitly limits it.
DEFAULT_CONFIG: dict = {
    "max_hunt_tasks": None,          # global cap on scheduled tasks; None = all
    "per_class_cap": None,           # cap per vuln_class; None = all
    "invariant_quota": None,         # invariant-driven slots reserved under a cap; None = n/a
}


def _as_limit(value) -> float:
    """A cap value → a numeric limit; None / 'all' / '' / unparseable → unlimited (inf)."""
    if value is None:
        return float("inf")
    if isinstance(value, str) and value.strip().lower() in ("", "all", "none", "null"):
        return float("inf")
    try:
        return int(value)
    except (TypeError, ValueError):
        return float("inf")


# --------------------------------------------------------------------------- #
# Small helpers                                                               #
# --------------------------------------------------------------------------- #
def _vuln_value(v) -> str:
    return v.value if hasattr(v, "value") else str(v)


def _is_out_of_scope(path: str | None) -> bool:
    p = (path or "").lower()
    return any(frag in p for frag in _OUT_OF_SCOPE_PATHS)


def _in_scope_targets(dossier: dict) -> list[dict]:
    """Target functions that are NOT under an out-of-scope path."""
    return [t for t in dossier.get("target_functions", [])
            if not _is_out_of_scope(t.get("file"))]


# --------------------------------------------------------------------------- #
# Ordering — the agent's priority, with ONE deterministic hard-fact tiebreak    #
# --------------------------------------------------------------------------- #
def _rank_signals(task: HunterTask, dossier: dict) -> tuple[tuple, float, list[str], float]:
    """Return ``(sort_key, display_score, reasons, cost_estimate)``.

    ``sort_key`` (ascending = better) orders the queue by the agent's ``priority``
    (primary), with ONE hard-fact tiebreak — a reachable public entrypoint. This is
    NOT a re-score (the S2 synthesis session owns ranking); it only decides which
    tasks make the cut when a budget cap binds. ``task_id`` (added by the caller)
    breaks full ties for stability. ``display_score`` is a transparent number
    monotonic with ``sort_key`` so the schedule reads as score-descending.
    """
    pr = max(1, min(4, int(task.priority)))
    reach = bool(dossier.get("reachable_entrypoints"))

    sort_key = (pr, 0 if reach else 1)
    score = round((5 - pr) + (0.10 if reach else 0.0), 3)
    reasons = [f"priority:P{pr}", "reachable" if reach else "no-entrypoint-path"]

    n_targets = len(_in_scope_targets(dossier))
    cost = round(2.0 + 0.5 * n_targets + (1.5 if not reach else 0.0), 2)
    return sort_key, score, reasons, cost


# --------------------------------------------------------------------------- #
# Result container                                                            #
# --------------------------------------------------------------------------- #
@dataclass
class PrefilterResult:
    scheduled: list[HunterTask] = field(default_factory=list)        # ordered best-first
    decisions: list[PrefilterDecision] = field(default_factory=list)  # one per input task
    by_class: dict[str, int] = field(default_factory=dict)           # scheduled counts per vuln_class

    @property
    def decisions_by_id(self) -> dict[str, PrefilterDecision]:
        return {d.task_id: d for d in self.decisions}


# --------------------------------------------------------------------------- #
# Public entrypoint                                                           #
# --------------------------------------------------------------------------- #
def _seed_tag(task: HunterTask) -> str:
    return "invariant-campaign" if task.inv_id else "hypothesis"


def _coerce_task(td: dict) -> tuple[HunterTask, dict]:
    """Split a checkpoint task dict into (HunterTask, dossier). HunterTask forbids
    extra keys, so the ``context`` dossier is stripped before validation."""
    dossier = td.get("context") or {}
    core = {k: v for k, v in td.items() if k != "context"}
    return HunterTask.model_validate(core), dossier


def prefilter(tasks: list[dict], config: dict | None = None) -> PrefilterResult:
    """Drop, order, cap and tag the S2 HunterTask queue. Pure/deterministic, NO model
    calls — ranking is the agent's ``priority`` (S2 synthesis), not a re-score here, and
    dedup is the synthesis session's job (S3 no longer folds twins).

    ``tasks`` are the S2 checkpoint task dicts (each carrying its ``context``
    dossier). Returns a :class:`PrefilterResult` with the ordered scheduled queue and
    exactly one :class:`PrefilterDecision` per input task.
    """
    cfg = {**DEFAULT_CONFIG, **(config or {})}
    max_hunt = _as_limit(cfg.get("max_hunt_tasks"))      # inf = no global cap (all)
    per_class_cap = _as_limit(cfg.get("per_class_cap"))  # inf = no per-class cap (all)
    inv_quota = cfg.get("invariant_quota")
    inv_quota = 0 if inv_quota is None else int(inv_quota)

    decisions: dict[str, PrefilterDecision] = {}
    scored: list[dict] = []   # survivors: {task, dossier, vc, sortkey, score, reasons, cost, seed}

    # ---- 1. DROP invalid / out-of-scope -------------------------------------
    for td in tasks:
        task, dossier = _coerce_task(td)
        seed = _seed_tag(task)
        all_targets = dossier.get("target_functions", [])
        in_scope = _in_scope_targets(dossier)
        # Tier-4 P3/P4/P5/P6 — a dep-misbehavior (mocks an EXTERNAL dep), malicious-admin
        # (compromised role), upgrade-sim (storage drift / init front-run), multi-actor
        # (collusion coalition), long-horizon (time-drift) or threat-research (off-checklist
        # novel-technique) task is valid by construction; it must not be dropped just because
        # the in-scope readers didn't resolve to targets — a novel hypothesis is precisely the
        # lead a checklist-driven dossier wouldn't pin to a function.
        dep_task = bool(getattr(task, "dep_target", "") or getattr(task, "malicious_role", "")
                        or getattr(task, "upgrade_sim", False)
                        or getattr(task, "multi_actor", False)
                        or getattr(task, "long_horizon", False)
                        or getattr(task, "origin", "") == "threat_research")
        if not all_targets and not dep_task:
            decisions[task.task_id] = PrefilterDecision(
                task_id=task.task_id, score=0.0, rank=0, decision="dropped", seed=seed,
                reasons=["no resolved target functions (nothing huntable)"], cost_estimate=None)
            continue
        if not in_scope and not dep_task:
            decisions[task.task_id] = PrefilterDecision(
                task_id=task.task_id, score=0.0, rank=0, decision="dropped", seed=seed,
                reasons=["all targets under out-of-scope path (node_modules/mock/test)"],
                cost_estimate=None)
            continue
        sortkey, score, reasons, cost = _rank_signals(task, dossier)
        scored.append({"task": task, "dossier": dossier, "vc": _vuln_value(task.vuln_class),
                       "sortkey": sortkey, "score": score, "reasons": reasons,
                       "cost": cost, "seed": seed})

    # Order by the agent's priority (+ the reachability tiebreak); task_id breaks full
    # ties. Dedup is NOT done here — the S2 synthesis session is the sole author and
    # already folds true duplicates, so every dropped-survivor flows on to the cap.
    scored.sort(key=lambda s: (s["sortkey"], s["task"].task_id))
    kept = scored

    # ---- 2. CAP: per-class cap → floor → invariant quota → global top-K -----
    # 3a. per-vuln_class cap (overflow deferred). kept is already best-first.
    per_class_seen: dict[str, int] = {}
    capped: list[dict] = []
    for s in kept:
        vc = s["vc"]
        per_class_seen[vc] = per_class_seen.get(vc, 0) + 1
        if per_class_seen[vc] > per_class_cap:
            task = s["task"]
            decisions[task.task_id] = PrefilterDecision(
                task_id=task.task_id, score=s["score"], rank=0, decision="deferred",
                seed=s["seed"], reasons=s["reasons"] + [f"per-class cap ({per_class_cap}) for {vc}"],
                cost_estimate=s["cost"])
        else:
            capped.append(s)

    # 3b. build the scheduled set within the global budget, honouring guarantees:
    #     (i) floor ≥1 per high-severity class present, (ii) reserved invariant quota.
    # Only relevant when the global cap actually BINDS — with no cap (or a cap ≥ the
    # number of survivors) everything schedules in rank order and no reservation is needed.
    must: list[str] = []   # task_ids that must be scheduled if budget allows
    if max_hunt < len(capped):
        floor_classes = {s["vc"] for s in capped if s["vc"] in _HIGH_SEVERITY_CLASSES}
        for vc in sorted(floor_classes):
            top = next((s for s in capped if s["vc"] == vc), None)  # capped is best-first
            if top:
                must.append(top["task"].task_id)
        inv_taken = 0
        for s in capped:
            if inv_taken >= inv_quota:
                break
            if s["task"].inv_id and s["task"].task_id not in must:
                must.append(s["task"].task_id)
                inv_taken += 1

    scheduled_ids: list[str] = []
    must_set = set(must)
    # reserve the guaranteed slots first (still capped at the global budget)…
    for s in capped:
        if s["task"].task_id in must_set and len(scheduled_ids) < max_hunt:
            scheduled_ids.append(s["task"].task_id)
    # …then fill the remaining budget best-first.
    for s in capped:
        if len(scheduled_ids) >= max_hunt:
            break
        if s["task"].task_id not in scheduled_ids:
            scheduled_ids.append(s["task"].task_id)

    scheduled_set = set(scheduled_ids)

    # final scheduled order = best-first (capped already is), assign ranks.
    scheduled_sorted = [s for s in capped if s["task"].task_id in scheduled_set]
    scheduled_tasks: list[HunterTask] = []
    by_class: dict[str, int] = {}
    for rank, s in enumerate(scheduled_sorted, start=1):
        task = s["task"]
        why = list(s["reasons"])
        if task.task_id in must_set:
            why.append("invariant quota" if task.inv_id else f"high-severity floor ({s['vc']})")
        decisions[task.task_id] = PrefilterDecision(
            task_id=task.task_id, score=s["score"], rank=rank, decision="scheduled",
            seed=s["seed"], reasons=why, cost_estimate=s["cost"])
        scheduled_tasks.append(task)
        by_class[s["vc"]] = by_class.get(s["vc"], 0) + 1

    # overflow (capped but not scheduled) → deferred (global cap reached).
    for s in capped:
        if s["task"].task_id not in scheduled_set:
            task = s["task"]
            decisions[task.task_id] = PrefilterDecision(
                task_id=task.task_id, score=s["score"], rank=0, decision="deferred",
                seed=s["seed"], reasons=s["reasons"] + [f"global cap ({max_hunt}) reached"],
                cost_estimate=s["cost"])

    # one decision per input task, in input order (never silently lose a task).
    ordered = [decisions[td["task_id"]] for td in tasks if td.get("task_id") in decisions]
    return PrefilterResult(scheduled=scheduled_tasks, decisions=ordered, by_class=by_class)
