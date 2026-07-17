"""S4 · Hunt (round 1) — spec §S4, §7 (Hunter), §10 (sandbox).

Consumes the S3-scheduled ``HunterTask`` queue (ordered by the S2 agent's priority),
re-attaches each task's deterministic ``HunterDossier`` (the precomputed attack
surface — resolved targets, reachable public entrypoints, sinks, accounting state,
binding invariants, controls, slither findings) and the shared ``ReconProfile``, and
spawns up to *N* concurrent **Hunter** agents. Each hunter gets ONE task and a
writable Foundry **sandbox**; it writes + compiles + runs a PoC from a real public
entrypoint that demonstrates impact, then emits ``Finding``(s) via the
``hunt-create-finding`` save-script and a REQUIRED ``hunt-finish`` outcome record
(the Stop-hook obligation + per-task tally).

The seed tag (``invariant-campaign``/``hypothesis``) is a HINT for which tool the
hunter fires first — NOT a terminal lane: every lead still converges on the
fork-PoC + impact step (see [[chainreaper-s3-s4-design]] / spec §S4).

Deterministic plumbing (read scheduled tasks + dossiers, build the Hunter spec +
prompt, persist/tally findings, checkpoint) is unit-tested offline against
``runs/test-merged`` with ZERO token spend; only the Hunter sessions cost.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ..agents.factory import build_hunter_system, hunter_profile_block, hunter_task_block
from ..agents.spec import AgentSpec, HUNT_BASH_TOOLS, hunt_emitters
from ..backends import build_backend
from ..models import HunterDossier, HunterTask, PrefilterDecision, ReconProfile
from ..recon.store import ReconStore
from ..runtime.campaign import _STRESS_CLASSES, build_campaign
from ..runtime.exec import Sandbox
from ..runtime.fork import plan_forks
from ..runtime.logging import get_logger

log = get_logger()


# --------------------------------------------------------------------------- #
# Deterministic composition (unit-tested offline)                             #
# --------------------------------------------------------------------------- #
def build_hunter_spec(task: HunterTask, dossier: HunterDossier | None,
                      decision: PrefilterDecision | None, profile: ReconProfile,
                      *, target, repo_ref: str | None, repo_root: str | None,
                      sandbox_tools_doc: str, fork_note: str = "") -> AgentSpec:
    """Compose the scoped, output-obligated Hunter ``AgentSpec`` for one task — the
    shared Recon profile + this task's precomputed attack surface (its
    ``reachable_entrypoints`` are the PoC attack surface) + the sandbox TOOLS + the
    live FORK STATUS + the REQUIRED finding/outcome emitters. Pure: no backend,
    no tokens."""
    emitters = hunt_emitters()
    system = build_hunter_system(
        target, repo_ref, sandbox_tools_doc, emitters,
        profile_block=hunter_profile_block(profile),
        task_block=hunter_task_block(task, dossier, decision, repo_root),
        fork_block=fork_note,
    )
    seed = decision.seed if decision else ("invariant-campaign" if task.inv_id else "hypothesis")
    first = ("Begin by firing the campaign for your invariant, then turn the "
             "counterexample into a fork PoC." if seed == "invariant-campaign"
             else "Begin from the reachable entrypoints and form an exploit hypothesis.")
    return AgentSpec(
        name=f"hunter-{task.task_id}",
        role="hunt",
        system_prompt=system,
        emitters=emitters,
        mode="hunt",
        bash_tools=list(HUNT_BASH_TOOLS),
        user_message=(
            f"Hunt task {task.task_id} ({task.vuln_class.value if hasattr(task.vuln_class, 'value') else task.vuln_class}). "
            f"{first} Build, compile and run a PoC in your sandbox that starts from a "
            "real public entrypoint in YOUR TASK and demonstrates impact — not just a "
            "property violation. Emit a Finding for each proven vulnerability via "
            "`chainreaper hunt-create-finding`, then ALWAYS record your result with "
            "`chainreaper hunt-finish` (finding | empty | blocked). An honest `empty` "
            "is correct if nothing reproduces — never fabricate a finding."),
    )


# Hosts we treat as keyless free public archives (safe to embed in a checkpointed
# medusa config). The local anvil (127.0.0.1) is always keyless.
_KEYLESS_HOSTS = ("drpc.org", "publicnode.com", "blastapi.io", "llamarpc.com",
                  "1rpc.io", "ankr.com", "meowrpc.com", "nodies.app", "base.org",
                  "arbitrum.io", "gateway.tenderly.co", "blockpi.network")


def _campaign_fork(fork_plan) -> dict | None:
    """The keyless fork endpoint to embed in the medusa campaign config (fork-mode
    fuzzing), or None. Prefers the local anvil (fronted → keyless + cached); else a
    free public archive; never a keyed upstream (it would leak into the checkpoint)."""
    import urllib.parse
    for cf in fork_plan.ready_chains():
        url = cf.serve_url or ""
        if url.startswith("http://127.0.0.1") or url.startswith("http://localhost"):
            return {"rpc_url": url, "block": cf.block}          # local anvil — keyless
        try:
            host = urllib.parse.urlparse(url).hostname or ""
        except ValueError:
            host = ""
        if host and any(host == h or host.endswith("." + h) for h in _KEYLESS_HOSTS):
            return {"rpc_url": url, "block": cf.block}          # free public archive
    return None


# Hints that a task is MARKET-CONDITION sensitive even when its vuln_class isn't one of
# the canonical stress classes (e.g. a logic/accounting bug that only bites under a
# warped oracle or skewed pool). We force the Tier-4 P1 adverse-market layer when either
# the class is stress-sensitive or the attack path / hypothesis names a market surface.
_STRESS_HINTS = ("oracle", "price", "amm", "pool", "reserve", "peg", "depeg",
                 "collateral", "funding", "utilization", "liquidat", "twap", "slippage")


def _task_stress(task) -> bool:
    """Whether to turn on the adverse-market stress layer for this hunt task."""
    vc = getattr(task, "vuln_class", None)
    vc = vc.value if hasattr(vc, "value") else (vc if isinstance(vc, str) else "")
    if vc in _STRESS_CLASSES:
        return True
    hay = " ".join([
        getattr(task, "hypothesis", "") or "", getattr(task, "title", "") or "",
        getattr(task, "scope_hint", "") or "", " ".join(getattr(task, "attack_path", None) or []),
    ]).lower()
    return any(h in hay for h in _STRESS_HINTS)


# --------------------------------------------------------------------------- #
# Hand-off readers                                                            #
# --------------------------------------------------------------------------- #
def _load_handoff(ctx, run_id: str, artifact_db: str) -> tuple[dict, dict]:
    """Return ``(dossiers, schedules)`` keyed by task_id. The S3 checkpoint strips
    the dossier from its scheduled_tasks (to stay small), so the authoritative
    source is ``chainreaper.db.hunter_tasks.context``/``.schedule`` — with a fallback
    to the S2 checkpoint's task dicts (which carry ``context``) if the DB is gone."""
    dossiers: dict[str, dict] = {}
    schedules: dict[str, dict] = {}
    if Path(artifact_db).exists():
        store = ReconStore(artifact_db)
        try:
            store.create_schema()
            dossiers = store.get_contexts(run_id)
            schedules = store.get_schedules(run_id)
        finally:
            store.close()
    if not dossiers:  # fallback: the S2 checkpoint carries each task's context
        for td in (ctx.state.get("s2", {}) or {}).get("hunter_tasks", []) or []:
            if td.get("context"):
                dossiers[td["task_id"]] = td["context"]
    if not schedules:
        for d in (ctx.state.get("s3", {}) or {}).get("decisions", []) or []:
            schedules[d["task_id"]] = d
    return dossiers, schedules


# --------------------------------------------------------------------------- #
# Stage entry                                                                  #
# --------------------------------------------------------------------------- #
def run(ctx) -> dict:
    s2 = ctx.state.get("s2")
    s3 = ctx.state.get("s3")
    if not s2 or s2.get("status") != "ok":
        raise RuntimeError("S4: S2 recon output not available in state (run S2 first)")
    if not s3 or s3.get("status") != "ok":
        raise RuntimeError("S4: S3 prefilter output not available in state (run S3 first)")
    scheduled_raw = s3.get("scheduled_tasks") or []
    if not scheduled_raw:
        log.info("[s4] no scheduled tasks from S3 — nothing to hunt")
        return {"stage": "s4", "status": "ok", "artifact_db": s3.get("artifact_db"),
                "findings": [], "outcomes": [], "counts": {"scheduled": 0, "attempted": 0,
                "findings": 0, "with_finding": 0, "empty": 0, "blocked": 0}}

    target = ctx.target
    s1 = ctx.state.get("s1") or {}
    index_db = s1.get("index_db") or str(ctx.index_dir / "index.db")
    repos = s1.get("repos", [])
    repo_ref = repos[0]["repo_ref"] if repos else (target.name if target else None)
    repo_root = None
    if target is not None:
        repo_root = next((a.ref for a in target.assets_in_scope
                          if a.in_scope and a.kind in ("local_path", "github_repo")), None)

    artifact_db = s3.get("artifact_db") or s2.get("artifact_db") or str(ctx.run_dir / "chainreaper.db")
    run_id = ctx.run_id

    cfg = ctx.config.get("hunt", {}) or {}
    concurrency = max(1, int(cfg.get("concurrency", 1)))
    per_task_timeout = int(cfg.get("per_task_timeout_s", 2400))
    max_tasks = cfg.get("max_tasks")  # None = all scheduled
    fork_cfg = cfg.get("fork", {}) or {}
    exec_backend = (ctx.config.get("runtime", {}) or {}).get("exec_backend", "host")

    dossiers, schedules = _load_handoff(ctx, run_id, artifact_db)

    # order tasks by their S3 rank (the schedule's `rank`, 1 = top)
    def _rank(td: dict) -> int:
        d = schedules.get(td["task_id"]) or {}
        return d.get("rank") or 9999
    scheduled_all = sorted(scheduled_raw, key=_rank)

    # Resume mode: keep prior hunt results and run only the tasks that don't yet
    # have an outcome (so "run the remaining scheduled tasks" doesn't re-hunt the
    # ones already done). Off by default → a fresh S4 that clears + reruns.
    # Run-level ``--resume`` (chainreaper resume) OR an explicit ``hunt.resume`` config
    # override. Either keeps prior outcomes and re-hunts only tasks without one — and,
    # critically, suppresses the clear_hunt wipe below. (Previously only the config key
    # was read, so ``chainreaper resume`` after a deleted s4 checkpoint WIPED outcomes.)
    resume = bool(getattr(ctx, "resume", False)) or bool(cfg.get("resume", False))
    done_ids: set[str] = set()
    if resume and Path(artifact_db).exists():
        store = ReconStore(artifact_db)
        try:
            done_ids = {o.get("task_id") for o in store.get_outcomes(run_id)}
        finally:
            store.close()

    scheduled = [t for t in scheduled_all if t["task_id"] not in done_ids]
    if done_ids:
        log.info("[s4] resume · skipping %d already-hunted task(s); %d remaining of %d scheduled",
                 len(done_ids), len(scheduled), len(scheduled_all))
    if isinstance(max_tasks, int) and max_tasks >= 0:
        if max_tasks < len(scheduled):
            log.info("[s4] capping to top %d of %d %s tasks (hunt.max_tasks)",
                     max_tasks, len(scheduled), "remaining" if resume else "scheduled")
        scheduled = scheduled[:max_tasks]

    profile = ReconProfile.model_validate(s2["recon_profile"])
    sandbox = Sandbox(ctx.run_dir, backend=exec_backend, rpc=fork_cfg.get("rpc", {}))

    # Fork preflight: resolve + validate + pin (+ optional shared anvil) per chain,
    # export <CHAIN>_RPC_URL for foundry.toml, and degrade cleanly to local-only.
    target_chains = list(target.chains) if target else []
    fork_plan = plan_forks(fork_cfg, target_chains, exec_backend=exec_backend,
                           log_dir=str(ctx.run_dir / "logs"))
    exported = fork_plan.apply_env()
    fork_note = fork_plan.hunter_note()
    # Keyless fork endpoint to embed in the medusa campaign config (fork-mode fuzzing
    # against the REAL deployed contracts). Prefer the local anvil (fronted = keyless +
    # cached); else a free public archive; NEVER a keyed upstream (would leak in the
    # checkpointed config). None → campaigns stay local-only.
    campaign_fork = _campaign_fork(fork_plan)
    log.info("[s4] fork preflight · %s%s%s", fork_plan.summary(),
             f" · exported {exported}" if exported else " · local-only (no fork RPC)",
             " · medusa fork-mode ON" if campaign_fork else "")

    log.info("[s4] %s · %d task(s) · concurrency=%d · timeout=%ss",
             sandbox.describe(), len(scheduled), concurrency, per_task_timeout)

    # fresh hunt artifacts for this run (idempotent re-run) — but NOT in resume mode,
    # where prior findings/outcomes are kept and only the remaining tasks are hunted.
    if Path(artifact_db).exists() and not resume:
        store = ReconStore(artifact_db)
        try:
            store.create_schema()
            store.clear_hunt(run_id)
        finally:
            store.close()

    backend = build_backend(ctx.config, repo_root=repo_root, db_path=index_db)
    if hasattr(backend, "session_timeout"):
        backend.session_timeout = per_task_timeout  # hunt budget > recon default
    log.info("[s4] provider=%s", backend.name)

    def _hunt_one(td: dict) -> dict:
        task = HunterTask.model_validate({k: v for k, v in td.items() if k != "context"})
        dz = dossiers.get(task.task_id)
        dossier = HunterDossier.model_validate(dz) if dz else None
        dec = schedules.get(task.task_id)
        decision = PrefilterDecision.model_validate(dec) if dec else None
        # Chimera-style layered campaign scaffold, keyed to THIS task's bound
        # invariants + reachable surface (T1.3): one handler the hunter runs through
        # forge → medusa → halmos, feeding counterexamples into the fork-PoC funnel.
        # Tier-4 P1: force the adverse-market stress layer for oracle/price/market tasks
        # so the fuzzer warps the WORLD (oracle/pool/peg/funding) alongside the calls.
        campaign_files = build_campaign(task, dossier, fork=campaign_fork,
                                        stress=_task_stress(task), repo_root=repo_root)
        try:
            ws = sandbox.prepare(task.task_id, repo_root=repo_root,
                                 campaign_files=campaign_files)
        except NotImplementedError as exc:
            log.info("[s4] %s: sandbox unavailable — %s", task.task_id, exc)
            return {"task_id": task.task_id, "status": "blocked", "error": str(exc)}
        spec = build_hunter_spec(
            task, dossier, decision, profile, target=target, repo_ref=repo_ref,
            repo_root=repo_root, sandbox_tools_doc=sandbox.tools_doc(), fork_note=fork_note)
        log.info("[s4] ▶ hunting %s (P%d, seed=%s) in %s",
                 task.task_id, task.priority,
                 decision.seed if decision else "?", ws)
        try:
            summary = backend.run_agent(
                spec, index_db=index_db, artifact_db=artifact_db, run_id=run_id,
                scratch_dir=str(ws), cwd=str(ws))
            return {"task_id": task.task_id, "status": "ok", "session": summary.get("session")}
        except Exception as exc:  # a hunter crash must not sink the whole stage
            log.info("[s4] ✗ hunter %s failed: %s", task.task_id, exc)
            return {"task_id": task.task_id, "status": "error", "error": str(exc)[:300]}

    try:
        if concurrency == 1:
            per_task = [_hunt_one(td) for td in scheduled]
        else:
            with ThreadPoolExecutor(max_workers=concurrency) as ex:
                per_task = list(ex.map(_hunt_one, scheduled))
    finally:
        fork_plan.teardown()  # stop any shared anvil forks we launched

    # read back what the hunters persisted + reconcile per-task outcomes
    findings: list[dict] = []
    outcomes: list[dict] = []
    if Path(artifact_db).exists():
        store = ReconStore(artifact_db)
        try:
            findings = store.get_findings(run_id)
            outcomes = store.get_outcomes(run_id)
        finally:
            store.close()

    # Cumulative tally over ALL scheduled tasks (so a resume that ran only the
    # remaining tasks still produces a complete s4.json reflecting every outcome,
    # prior + new). A scheduled task with no outcome and no this-run error is
    # "pending" (not yet hunted — e.g. beyond max_tasks); it isn't counted attempted.
    outcome_by_task = {o.get("task_id"): o for o in outcomes}
    run_status_by_task = {r["task_id"]: r for r in per_task}
    tally = {"with_finding": 0, "empty": 0, "blocked": 0}
    per_task_tally: list[dict] = []
    attempted = 0
    for td in scheduled_all:
        tid = td["task_id"]
        o = outcome_by_task.get(tid)
        r = run_status_by_task.get(tid)
        if o is None and r is None:
            per_task_tally.append({"task_id": tid, "run_status": "pending", "outcome": None,
                                   "n_findings": 0, "poc_built": False, "error": None})
            continue
        attempted += 1
        if o is not None:
            kind = "with_finding" if o.get("outcome") == "finding" else (
                "blocked" if o.get("outcome") == "blocked" else "empty")
        else:
            kind = "blocked"  # ran this invocation but errored before hunt-finish
        tally[kind] += 1
        per_task_tally.append({
            "task_id": tid, "run_status": (r or {}).get("status", "done"),
            "outcome": (o or {}).get("outcome"),
            "n_findings": (o or {}).get("n_findings", 0),
            "poc_built": (o or {}).get("poc_built", False),
            "error": (r or {}).get("error"),
        })

    # payable set = attacker-reachable findings (adversary model); the rest are
    # external-condition / privileged-role / latent hardening notes.
    payable = sum(1 for f in findings if (f or {}).get("trigger_class") == "attacker_reachable")
    counts = {
        "scheduled": len(scheduled_all),
        "attempted": attempted,            # cumulative tasks hunted (prior + this run)
        "this_run": len(per_task),         # tasks hunted in THIS invocation
        "findings": len(findings),
        "attacker_reachable": payable,     # the payable subset
        "with_finding": tally["with_finding"],
        "empty": tally["empty"],
        "blocked": tally["blocked"],
    }
    log.info("[s4] done · this_run=%d attempted(cumulative)=%d findings=%d "
             "(attacker_reachable=%d · with_finding=%d empty=%d blocked=%d) · db=%s",
             counts["this_run"], counts["attempted"], counts["findings"], payable,
             counts["with_finding"], counts["empty"], counts["blocked"], artifact_db)

    return {
        "stage": "s4", "status": "ok",
        "artifact_db": artifact_db,
        "findings": findings,
        "outcomes": outcomes,
        "per_task": per_task_tally,
        "fork_plan": fork_plan.to_dict(),
        "counts": counts,
    }
