"""S2 · Recon (spec §6, §7; IMPL-NOTES §6) — the first model-calling stage.

ONE scoped, read-only agent session does the whole of Recon in order:
explore → **profile** (architecture, boundaries, roles, ranked HotZones, threat
model) → **invariant suite** (codebase-specific, hook-bound, tool-grounded) → ONE
**holistically-ranked HunterTask queue** (emitted last, so each task is informed by
the invariants and the slither findings the agent has already produced). Ranking is
the agent's own judgment with full context — which is why S3 no longer re-scores.

The stage then runs the deterministic post-pass (identical regardless of what the
agent emitted): ``bind_hooks`` + ``grade_recall`` on the invariants, an
invariant-coverage **backstop** (any high/critical invariant the agent did not turn
into a task gets one, so coverage is never silently lost), per-task
``HunterDossier`` assembly, and the checkpoint. Host-only, read-only.
"""

from __future__ import annotations

import os
import textwrap
from pathlib import Path

from ..agents.factory import (
    build_recon_explore_system,
    build_recon_synthesis_system,
    build_recon_system,
    build_spec_researcher_system,
    build_threat_researcher_system,
    recon_invariants_block,
    recon_profile_digest_block,
    spec_profile_block,
    threat_dossier_block,
    threat_research_profile_block,
)
from ..agents.spec import (
    AgentSpec,
    recon_emitters,
    recon_explore_emitters,
    recon_synthesis_emitters,
    spec_research_emitters,
    threat_research_emitters,
)
from ..backends import build_backend
from ..models import (
    HunterTask,
    Invariant,
    InvariantSuite,
    ReconProfile,
    ReconProfileInput,
    TaskStatus,
    VulnClass,
)
from ..recon.dossier import build_dossiers
from ..recon.invariants import bind_hooks, grade_recall
from ..recon.store import ReconStore
from ..runtime.exec import available_invariant_tools
from ..runtime.logging import get_logger
from ..tools.code_index import initialized_sast_tools, sast_overview

log = get_logger()

# category → (vuln_class, skills) for invariant-driven HunterTasks
_CATEGORY_VULN = {
    "share_price": (VulnClass.PRICE_ORACLE, ["sc03_oracle_manipulation", "sc08_reentrancy"]),
    "oracle": (VulnClass.PRICE_ORACLE, ["sc03_oracle_manipulation"]),
    "execution": (VulnClass.REENTRANCY, ["sc08_reentrancy"]),
    "solvency": (VulnClass.LOGIC_ERROR, ["sc02_business_logic"]),
    "position_pnl": (VulnClass.LOGIC_ERROR, ["sc07_arithmetic_rounding"]),
    "liquidation": (VulnClass.LOGIC_ERROR, ["sc02_business_logic"]),
    "fee": (VulnClass.LOGIC_ERROR, ["sc07_arithmetic_rounding"]),
    "access": (VulnClass.ACCESS_CONTROL, ["sc01_access_control"]),
    "cross_module": (VulnClass.LOGIC_ERROR, ["sc02_business_logic"]),
}


def _cat(inv) -> str:
    c = inv.category
    return c.value if hasattr(c, "value") else str(c)


def _sev(inv) -> str:
    s = inv.severity
    return s.value if hasattr(s, "value") else str(s)


def _invariant_tasks(suite: InvariantSuite) -> list[HunterTask]:
    """A HunterTask for each high/critical invariant — a hunter that breaks one has
    a finding with a built-in PoC."""
    tasks: list[HunterTask] = []
    for inv in suite.invariants:
        if _sev(inv) not in ("critical", "high"):
            continue
        vuln, skills = _CATEGORY_VULN.get(_cat(inv), (VulnClass.LOGIC_ERROR, []))
        tasks.append(HunterTask(
            task_id=f"task-inv-{inv.inv_id.lower()}",
            title=f"Break invariant {inv.inv_id}: "
                  + textwrap.shorten(inv.statement, width=88, placeholder="…"),
            vuln_class=vuln,
            scope_hint="; ".join(inv.hooks[:6]) or inv.inv_id,
            hypothesis=f"Find a call sequence that violates: {inv.statement}",
            suggested_skills=skills + [f"invariants/{_cat(inv)}", f"tooling/{inv.tool}"],
            priority=1 if _sev(inv) == "critical" else 2,
            origin="recon",
            status=TaskStatus.PENDING,
            inv_id=inv.inv_id,
        ))
    return tasks


def _backstop_invariant_tasks(suite: InvariantSuite,
                              existing: list[HunterTask]) -> list[HunterTask]:
    """Invariant-coverage backstop: a HunterTask for every high/critical invariant
    NOT already covered by an agent task (covered = a task carries its ``inv_id`` or
    shares the generated title). Guarantees no high/critical invariant silently
    loses its campaign while the agent still owns the ranking."""
    covered_ids = {t.inv_id for t in existing if t.inv_id}
    seen_titles = {t.title.lower() for t in existing}
    out: list[HunterTask] = []
    for t in _invariant_tasks(suite):
        if t.inv_id in covered_ids or t.title.lower() in seen_titles:
            continue
        out.append(t)
    return out


def run_spec_research(backend, *, target, repo_ref, db_path: str, artifact_db: str,
                      run_id: str, min_invariants: int = 3) -> int:
    """Tier-4 P2 — run the web-enabled Spec-Research agent BEFORE the main recon.

    It fetches the target's documented promises (docs / whitepaper / audits) and
    emits INTENT invariants (``origin="spec"``, ``SPEC-`` ids) straight into the
    per-run ``invariants`` table, where ``get_invariants`` merges them with the
    code-derived suite the main recon agent produces next — so they bind + flow to
    S4 like any invariant. Additive (not load-bearing): a thin/failed session must
    not sink Recon, so the caller wraps this in try/except. Returns the number of
    intent invariants persisted."""
    em = spec_research_emitters(min_invariants)
    spec = AgentSpec(
        name="spec_researcher", role="recon", mode="research",
        system_prompt=build_spec_researcher_system(target, repo_ref, backend.tools_doc, em),
        emitters=em,
        user_message=(
            "Research this target's DOCUMENTED PROMISES (in-repo docs/READMEs/NatSpec, "
            "the whitepaper/official docs, published audit reports, the bounty scope) "
            "and emit them as INTENT invariants (origin=\"spec\", SPEC- ids) bound to the "
            "real in-scope code. Capture the hard guarantees a user/integrator would be "
            "harmed by if violated — fee caps, withdrawal liveness, rounding direction, "
            "solvency/backing, access/authority bounds, oracle/peg promises. Quality over "
            "quantity; bind every one to in-scope hooks."),
    )
    backend.run_agent(spec, index_db=db_path, artifact_db=artifact_db, run_id=run_id)
    store = ReconStore(artifact_db)
    try:
        return sum(1 for d in store.get_invariants(run_id)
                   if (d.get("origin") == "spec") or str(d.get("inv_id", "")).upper().startswith("SPEC-"))
    finally:
        store.close()


def run_threat_research(backend, *, target, repo_ref, db_path: str, artifact_db: str,
                        run_id: str, min_tasks: int = 3, invariants: list | None = None) -> int:
    """Tier-4 P6 — run the web-enabled Threat-Research agent AFTER the main recon.

    It researches RECENT attack techniques (latest hacks / audit-contest findings /
    research papers) and the target's OWN bespoke mechanism, then proposes
    protocol-specific, OFF-CHECKLIST hypotheses (deliberately not SC-Top-10-shaped) as
    exploratory ``HunterTask``s (``origin="threat_research"``) — straight into the same
    per-run ``hunter_tasks`` table the recon agent wrote to, so ``get_tasks`` merges
    them with the recon queue and the deterministic finalize builds each one's dossier
    and schedules it to S4 like any other lead. The main recon's profile (already
    persisted) is fed in as the SPECIFIC mechanism to aim at. Additive (not
    load-bearing): a thin/failed session must not sink Recon, so the caller wraps this
    in try/except. Returns the number of off-checklist tasks persisted."""
    store = ReconStore(artifact_db)
    try:
        profile_doc = store.get_profile(run_id, agent="recon")
        # Feed the EXISTING invariant suite in too, so the threat agent targets the
        # orthogonal complement instead of re-deriving an already-covered property.
        inv_docs = invariants if invariants is not None else store.get_invariants(run_id)
    finally:
        store.close()
    em = threat_research_emitters(min_tasks)
    spec = AgentSpec(
        name="threat_researcher", role="recon", mode="research",
        system_prompt=build_threat_researcher_system(
            target, repo_ref, backend.tools_doc, em,
            profile_block=threat_research_profile_block(profile_doc, inv_docs)),
        emitters=em,
        user_message=(
            "Research the FRONTIER of attack technique (recent hacks/post-mortems, "
            "audit-contest findings for similar protocols, new disclosure classes) AND "
            "this protocol's OWN bespoke mechanism (read the in-scope code + the recon "
            "profile), then emit a small number of sharp, OFF-CHECKLIST HunterTasks "
            "(origin=\"threat_research\") at the intersection: a newly-understood "
            "technique applied to a specific in-scope mechanism. Do NOT restate the "
            "known-pattern checklist — the main recon already has those. Anchor every "
            "task's scope_hint to real in-scope code; cite the technique/precedent in "
            "the hypothesis; prioritise honestly (P1..P4 by plausibility × impact)."),
    )
    backend.run_agent(spec, index_db=db_path, artifact_db=artifact_db, run_id=run_id)
    store = ReconStore(artifact_db)
    try:
        return sum(1 for d in store.get_tasks(run_id)
                   if d.get("origin") == "threat_research")
    finally:
        store.close()


def _augment_dynamic_reachability(ctx, target, dossiers, store, run_id: str) -> None:
    """Task 1B glue: resolve the fork URL + deployed-address map from the Target, trace
    the deployed entrypoints, and persist any dossier whose reachability the fork trace
    upgrades. Best-effort — a missing fork / cast / address map is a clean no-op."""
    from ..recon.dynamic_reach import (
        augment_reachability_dynamic,
        default_tracer,
        entrypoint_probes_from_dossiers,
    )
    from ..runtime.fork import _resolve_url

    # deployed contract-name → address (contract_address assets)
    deployed = {a.name: a.address for a in target.assets_in_scope
                if a.address and a.name}
    if not deployed:
        log.info("[s2] dynamic reachability: no deployed addresses in scope — skipped")
        return
    fork_cfg = (ctx.config.get("hunt", {}) or {}).get("fork", {}) or {}
    chains = getattr(target, "chains", None) or []
    chain = chains[0] if chains else (next(iter(target.assets_in_scope), None)
                                      and target.assets_in_scope[0].network) or "ethereum"
    rpc_url = _resolve_url(str(chain), fork_cfg.get("rpc_urls") or {}, os.environ)
    if not rpc_url:
        log.info("[s2] dynamic reachability: no fork RPC for %s — skipped", chain)
        return
    probes = entrypoint_probes_from_dossiers(dossiers, deployed)
    newly = augment_reachability_dynamic(dossiers, probes, rpc_url=rpc_url,
                                         tracer=default_tracer)
    if newly:
        for tid, d in dossiers.items():
            store.set_task_context(run_id=run_id, task_id=tid,
                                   context=d.model_dump(mode="json"))


def run(ctx) -> dict:
    target = ctx.target
    if target is None:
        raise RuntimeError("S2: no Target in state (S0 must run first)")
    s1 = ctx.state.get("s1")
    # S1 returns "partial" when SOME in-scope units indexed and others failed to build
    # (a superset clone routinely carries units that don't compile standalone). That is
    # a usable index — S4/S5 read it leniently, so S2 must too. Only a missing/empty S1
    # result (nothing indexed → S1 would have raised) is fatal here.
    if not s1 or s1.get("status") not in ("ok", "partial"):
        raise RuntimeError("S2: S1 index not available in state (run S1 first)")

    db_path = s1.get("index_db") or str(ctx.index_dir / "index.db")
    if not Path(db_path).exists():
        raise FileNotFoundError(f"S2: index db not found: {db_path}")
    repos = s1.get("repos", [])
    repo_ref = repos[0]["repo_ref"] if repos else target.name
    # The recon agent's file-read root. Only assets that exist ON DISK qualify — this
    # skips the github_repo URL provenance assets (explorer mode keeps them as metadata;
    # the indexable source is the local_path verified units). With MULTIPLE in-scope units
    # (per-address verified-source units, or several cloned repos), use their common parent
    # so the agent can read across all of them (e.g. workspace/_verified for explorer mode).
    import os
    candidates = [str(Path(a.ref).resolve()) for a in target.assets_in_scope
                  if a.in_scope and a.kind in ("local_path", "github_repo") and Path(a.ref).exists()]
    if not candidates:
        raise FileNotFoundError(
            "S2: no in-scope repo root found on disk "
            f"(in-scope refs: {[a.ref for a in target.assets_in_scope if a.in_scope][:4]})")
    repo_root = candidates[0] if len(candidates) == 1 else os.path.commonpath(candidates)

    run_id = ctx.run_id
    agents_cfg = ctx.config.get("agents", {})
    min_tasks = int(agents_cfg.get("min_tasks", 8))
    min_invariants = int(agents_cfg.get("min_invariants", 12))

    # per-run artifact DB — the agent's save-scripts write here; we read it back.
    artifact_db = str(ctx.run_dir / "chainreaper.db")
    store = ReconStore(artifact_db)
    store.create_schema()
    store.clear_run(run_id)
    store.close()

    backend = build_backend(ctx.config, repo_root=repo_root, db_path=db_path)
    log.info("[s2] provider=%s · %s", backend.name, backend.selftest())

    # Tier-4 P2 — Spec-Research agent FIRST (web-enabled): documented-promise → intent
    # invariants (origin="spec"). Additive; a failure must not sink Recon. Gated by
    # config (default on); the API backend has no live web, so it contributes only what
    # the prompt + in-repo docs yield.
    spec_cfg = agents_cfg.get("spec_research", True)
    if spec_cfg:
        min_spec = int(agents_cfg.get("min_spec_invariants", 3))
        try:
            log.info("[s2] spec-research agent (documented promises → intent invariants)…")
            n_spec = run_spec_research(
                backend, target=target, repo_ref=repo_ref, db_path=db_path,
                artifact_db=artifact_db, run_id=run_id, min_invariants=min_spec)
            log.info("[s2] spec-research: %d intent invariant(s) (origin=spec)", n_spec)
        except Exception as exc:  # additive — never sink Recon on a spec-research failure
            log.info("[s2] spec-research skipped (non-fatal): %s", str(exc)[:200])

    # Invariant→tool routing (T1.2). The static analyzers that ran at index time
    # (slither for GMX) are joined with the stateful-fuzz / symbolic tools actually
    # INSTALLED on this host (medusa/echidna/halmos/foundry/wake), so recon may route
    # each invariant to the checker best suited to it AND guaranteed runnable in S4 —
    # not just the one analyzer that happened to run at index. Ground them in
    # slither's real findings (index reads, fed into the prompt).
    index_tools = initialized_sast_tools(db_path) or ["slither"]
    runnable_tools = available_invariant_tools()
    invariant_tools = sorted(set(index_tools) | set(runnable_tools))
    sast = sast_overview(db_path)
    log.info("[s2] index analyzers=%s · installed invariant tools=%s · routing menu=%s · "
             "slither findings: %d detectors, %d top in-scope",
             index_tools, runnable_tools, invariant_tools,
             len(sast.get("checks", [])), len(sast.get("top", [])))

    # 1. Recon. Two modes (config recon.synthesis_mode, default on):
    #   synthesis_mode — split into EXPLORE (profile+invariants, NO tasks) → threat-research
    #     (candidate leads, fed the invariants so it targets the COMPLEMENT) → a SYNTHESIS
    #     session that is the SOLE author of the unified, all-informed HunterTask queue.
    #     This is the "create the final combined task set ONCE, informed from all sources"
    #     design: research produces intelligence; recon synthesis produces the task plan.
    #   legacy — one session emits profile+invariants+tasks, then threat-research appends.
    synthesis_mode = bool(ctx.config.get("recon", {}).get("synthesis_mode", True))
    threat_cfg = agents_cfg.get("threat_research", True)
    min_threat = int(agents_cfg.get("min_threat_tasks", 3))

    if synthesis_mode:
        # Phase A — EXPLORE & FORMALIZE (profile + invariants, NO tasks). Fed the spec
        # profile (P2 documented promises persisted above) so it reconciles code vs intent.
        store = ReconStore(artifact_db)
        try:
            spec_invs = [d for d in store.get_invariants(run_id)
                         if d.get("origin") == "spec"
                         or str(d.get("inv_id", "")).upper().startswith("SPEC-")]
        finally:
            store.close()
        em_x = recon_explore_emitters(min_invariants)
        spec_x = AgentSpec(
            name="recon", role="recon",
            system_prompt=build_recon_explore_system(
                target, repo_ref, backend.tools_doc, em_x,
                initialized_tools=invariant_tools, sast=sast,
                spec_profile=spec_profile_block(spec_invs)),
            emitters=em_x,
            user_message=(
                "Explore the in-scope repository and produce — IN THIS ORDER — (1) your "
                "Recon profile and (2) your codebase-specific invariant suite bound to real "
                "hooks and checkable by an initialized tool. Do NOT emit any HunterTasks "
                "this session — a later synthesis pass authors the queue. Start from "
                "entrypoints and the highest-value modules; follow the call graph to "
                "accounting state and external calls; read the slither findings from the "
                "index; reconcile the code against the SPEC PROFILE's documented promises."),
        )
        log.info("[s2] recon EXPLORE agent (profile + invariants; tasks deferred to synthesis)…")
        backend.run_agent(spec_x, index_db=db_path, artifact_db=artifact_db, run_id=run_id)

        # Phase B — Threat-Research (candidate off-checklist leads). Now fed the recon
        # profile AND the invariant suite, so it targets the orthogonal complement rather
        # than re-deriving an already-covered property. Additive; failure is non-fatal.
        if threat_cfg:
            try:
                log.info("[s2] threat-research agent (novel techniques → candidate leads)…")
                n_threat = run_threat_research(
                    backend, target=target, repo_ref=repo_ref, db_path=db_path,
                    artifact_db=artifact_db, run_id=run_id, min_tasks=min_threat)
                log.info("[s2] threat-research: %d candidate lead(s)", n_threat)
            except Exception as exc:  # additive — never sink Recon on a threat-research failure
                log.info("[s2] threat-research skipped (non-fatal): %s", str(exc)[:200])

        # Snapshot the candidate leads, then CLEAR the task table so the synthesis session
        # is the SINGLE author of the final queue (it carries the kept leads forward).
        store = ReconStore(artifact_db)
        try:
            profile_doc = store.get_profile(run_id, agent="recon")
            inv_docs = store.get_invariants(run_id)
            candidates = store.get_tasks(run_id)  # only threat leads exist yet (explore emitted none)
            store.clear_tasks(run_id)
        finally:
            store.close()
        log.info("[s2] synthesis inputs: profile=%s invariants=%d threat-candidates=%d",
                 bool(profile_doc), len(inv_docs), len(candidates))

        # Phase C — SYNTHESIS: the SOLE author of the unified HunterTask queue, fed the
        # profile digest + the full invariant suite + the threat-research dossier.
        em_s = recon_synthesis_emitters(min_tasks)
        spec_s = AgentSpec(
            name="recon", role="recon",
            system_prompt=build_recon_synthesis_system(
                target, repo_ref, backend.tools_doc, em_s,
                profile_block=recon_profile_digest_block(
                    profile_doc, header="## RECON PROFILE (the mechanism you explored)"),
                invariants_block=recon_invariants_block(
                    inv_docs, header="## INVARIANT SUITE (emit a breaking task for each "
                    "high/critical one; link tasks via inv_id)"),
                threat_dossier=threat_dossier_block(candidates)),
            emitters=em_s,
            user_message=(
                "Author the SINGLE, comprehensive, de-duplicated, unified-ranked HunterTask "
                "queue now — informed by your RECON PROFILE, your INVARIANT SUITE, and the "
                "THREAT-RESEARCH DOSSIER above. For each high/critical invariant emit a "
                "breaking task (inv_id set); carry every distinct threat-research candidate "
                "forward (origin=\"threat_research\", preserving its hypothesis/precedent); "
                "cover the full attack-class + cross-contract/dep/governance/incentive "
                "taxonomy; fold only true duplicates; make priority 1..4 discriminating."),
        )
        log.info("[s2] recon SYNTHESIS agent (one unified queue informed from all sources)…")
        backend.run_agent(spec_s, index_db=db_path, artifact_db=artifact_db, run_id=run_id)

        # Degradation: if synthesis produced nothing, restore the threat candidates so the
        # run still has a queue (+ the invariant backstop below) rather than dying.
        store = ReconStore(artifact_db)
        try:
            if not store.get_tasks(run_id) and candidates:
                for c in candidates:
                    store.add_task(run_id=run_id, agent="threat_researcher",
                                   session="restored", task=c)
                log.info("[s2] synthesis produced no tasks; restored %d threat candidate(s)",
                         len(candidates))
        finally:
            store.close()
    else:
        # Legacy single Recon session — profile + invariants + ranked task queue at once.
        em = recon_emitters(min_tasks, min_invariants)
        spec = AgentSpec(
            name="recon", role="recon",
            system_prompt=build_recon_system(
                target, repo_ref, backend.tools_doc, em,
                initialized_tools=invariant_tools, sast=sast),
            emitters=em,
            user_message=(
                "Explore the in-scope repository, then produce — IN THIS ORDER — (1) your "
                "Recon profile, (2) your codebase-specific invariant suite bound to real "
                "hooks and checkable by an initialized tool, and (3) ONE prioritized "
                "HunterTask queue informed by both. Start from entrypoints and the "
                "highest-value modules; follow the call graph to accounting state and "
                "external calls; read the slither findings from the index. Emit the "
                "profile first, then the invariants, then the tasks: for each "
                "high/critical invariant include a task (with its inv_id set) to break it, "
                "plus exploratory tasks (inv_id unset) for high-impact surface no invariant "
                "covers. Make priority 1..4 a real, discriminating judgment using "
                "everything you now know — don't mark everything P1."),
        )
        log.info("[s2] recon agent (explore → profile → invariants → ranked tasks)…")
        backend.run_agent(spec, index_db=db_path, artifact_db=artifact_db, run_id=run_id)

        # Tier-4 P6 — Threat-Research AFTER recon (legacy): off-checklist tasks appended to
        # the queue. Reads the recon profile + invariants as the mechanism to aim at.
        if threat_cfg:
            try:
                log.info("[s2] threat-research agent (novel techniques → off-checklist tasks)…")
                n_threat = run_threat_research(
                    backend, target=target, repo_ref=repo_ref, db_path=db_path,
                    artifact_db=artifact_db, run_id=run_id, min_tasks=min_threat)
                log.info("[s2] threat-research: %d off-checklist task(s) (origin=threat_research)",
                         n_threat)
            except Exception as exc:  # additive — never sink Recon on a threat-research failure
                log.info("[s2] threat-research skipped (non-fatal): %s", str(exc)[:200])

    store = ReconStore(artifact_db)
    try:
        profile_doc = store.get_profile(run_id, agent="recon")
        if not profile_doc:
            raise RuntimeError("S2: recon agent produced no profile (chainreaper.db empty)")
        pin = ReconProfileInput.model_validate(profile_doc)
        tasks = [HunterTask.model_validate(d) for d in store.get_tasks(run_id)]
        invariants = [Invariant.model_validate(d) for d in store.get_invariants(run_id)]
    finally:
        store.close()
    if not tasks:
        raise RuntimeError("S2: recon agent produced no HunterTasks")
    if not invariants:
        raise RuntimeError("S2: recon agent produced no invariants")

    # 2. Deterministic finalize.
    store = ReconStore(artifact_db)
    try:
        # Enforce: an invariant may only target a tool that is actually runnable on
        # this host (T1.2). A tool outside the routing menu (e.g. certora when it is
        # not installed) is snapped to slither — the always-runnable static checker.
        fallback = index_tools[0] if index_tools else "slither"
        coerced = [inv.inv_id for inv in invariants if inv.tool not in invariant_tools]
        if coerced:
            for inv in invariants:
                if inv.tool not in invariant_tools:
                    inv.tool = fallback
            log.info("[s2] coerced %d invariant(s) to runnable tool %s (not in %s): %s",
                     len(coerced), fallback, invariant_tools, ", ".join(coerced))

        log.info("[s2] binding invariant hooks to S1 index…")
        coverage = bind_hooks(db_path, invariants)
        recall = grade_recall(invariants)
        for inv in invariants:
            store.update_invariant(
                run_id=run_id, inv_id=inv.inv_id, hooks=inv.hooks,
                coverage=coverage.get(inv.inv_id, {}), status=inv.status,
                doc=inv.model_dump(mode="json"))

        suite = InvariantSuite(
            target=target.program_id,
            invariants=invariants,
            handler_files={},  # scaffolding lands in S4
            runner_config={"note": "harness scaffolding deferred to S4 (Hunt)",
                           "tools": sorted({inv.tool for inv in invariants})},
            coverage_map=coverage,
        )

        # invariant-coverage backstop (persist + merge with the agent's queue)
        new_inv_tasks = _backstop_invariant_tasks(suite, tasks)
        for t in new_inv_tasks:
            store.add_task(run_id=run_id, agent="stage", session="invariant-derived",
                           task=t.model_dump(mode="json"))
        tasks = list(tasks) + new_inv_tasks
        if new_inv_tasks:
            log.info("[s2] backstop added %d invariant task(s) the agent didn't cover: %s",
                     len(new_inv_tasks), ", ".join(t.inv_id for t in new_inv_tasks))

        # Per-task hunter dossier (deterministic S2→S4 hand-off).
        log.info("[s2] building %d hunter dossiers (scope + reachability + linkage)…", len(tasks))
        dossiers = build_dossiers(db_path, tasks, pin, invariants)
        for t in tasks:
            d = dossiers.get(t.task_id)
            if d is not None:
                store.set_task_context(run_id=run_id, task_id=t.task_id,
                                       context=d.model_dump(mode="json"))
        reached = sum(1 for d in dossiers.values() if d.reachable_entrypoints)
        log.info("[s2] dossiers: %d/%d with reachable entrypoints", reached, len(dossiers))

        # Task 1B — DYNAMIC on-fork reachability fallback (gated, default off). For the
        # tasks still dark after 1A static edge resolution, trace deployed entrypoints on
        # the fork and record which in-scope functions actually execute. Costs fork calls.
        if bool(ctx.config.get("recon", {}).get("dynamic_reachability", False)) \
                and reached < len(dossiers):
            _augment_dynamic_reachability(ctx, target, dossiers, store, run_id)
            reached = sum(1 for d in dossiers.values() if d.reachable_entrypoints)
            log.info("[s2] dossiers after dynamic reachability: %d/%d reachable",
                     reached, len(dossiers))

        db_counts = store.counts(run_id)
    finally:
        store.close()

    profile = ReconProfile(
        target=target,
        architecture_md=pin.architecture_md,
        contract_types=pin.contract_types,
        trust_boundaries=pin.trust_boundaries,
        privileged_roles=pin.privileged_roles,
        high_impact_areas=pin.high_impact_areas,
        threat_model=pin.threat_model,
        protocol_graph=pin.protocol_graph,
        invariant_suite=suite,
    )

    bound_invs = sum(1 for c in coverage.values() if c["bound"] > 0)
    inv_driven = sum(1 for t in tasks if t.inv_id)
    log.info("[s2] done · hotzones=%d invariants=%d (bound=%d) tasks=%d "
             "(invariant-driven=%d) recall=%s (passed=%s) · db=%s",
             len(pin.high_impact_areas), len(suite.invariants), bound_invs,
             len(tasks), inv_driven, recall["score"], recall["passed"], artifact_db)

    return {
        "stage": "s2", "status": "ok",
        "artifact_db": artifact_db,
        "recon_profile": profile.model_dump(mode="json"),
        "hunter_tasks": [
            {**t.model_dump(mode="json"),
             "context": (dossiers[t.task_id].model_dump(mode="json")
                         if dossiers.get(t.task_id) else None)}
            for t in tasks
        ],
        "recall_grade": recall,
        "counts": {
            "hotzones": len(pin.high_impact_areas),
            "trust_boundaries": len(profile.trust_boundaries),
            "privileged_roles": len(profile.privileged_roles),
            "threat_entries": len(pin.threat_model.entries),
            "invariants": len(suite.invariants),
            "invariants_bound": bound_invs,
            "tasks": len(tasks),
            "invariant_driven_tasks": inv_driven,
        },
        "db_counts": db_counts,
    }
