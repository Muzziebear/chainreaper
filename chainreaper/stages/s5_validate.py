"""S5 · Validate (round 1) — spec §S5, §5 (Verdict), §7 (Critic); T3.1.

Adversarial validation of the S4 findings. For EACH Finding the stage spawns **N
independent Critic agents** (more for high-severity findings — the N-vote panel),
each given a writable sandbox to **re-run the PoC** and prompted to **refute** the
claim, then it **aggregates** their Verdicts into the finding's final disposition.
This addresses the self-validating-single-hunter blind spot (memory
``chainreaper-testing-roadmap`` #5): two hunters were observed to disagree on a
marginal lead, so a finding is only confirmed when independent skeptics concur.

Deterministic plumbing (read findings, build the critic spec/prompt, aggregate the
votes, checkpoint) is unit-tested offline with ZERO token spend; only the Critic
sessions cost.
"""

from __future__ import annotations

from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ..agents.factory import build_critic_system, critic_finding_block, hunter_profile_block
from ..agents.spec import AgentSpec, HUNT_BASH_TOOLS, critic_emitters
from ..backends import build_backend
from ..models import ReconProfile, Severity
from ..recon.store import ReconStore
from ..runtime.exec import Sandbox
from ..runtime.fork import plan_forks
from ..runtime.logging import get_logger

log = get_logger()

_HIGH_SEV = {Severity.CRITICAL.value, Severity.HIGH.value}


# --------------------------------------------------------------------------- #
# Deterministic composition (unit-tested offline)                             #
# --------------------------------------------------------------------------- #
def build_critic_spec(finding: dict, profile: ReconProfile, *, target, repo_ref: str | None,
                      repo_root: str | None, sandbox_tools_doc: str,
                      vote_index: int, votes_total: int) -> AgentSpec:
    """Compose the scoped, output-obligated Critic ``AgentSpec`` for one (finding,
    vote) — the shared Recon profile + the finding under review (with its PoC to
    re-run) + the sandbox TOOLS + the REQUIRED verdict emitter. Pure: no backend."""
    emitters = critic_emitters()
    system = build_critic_system(
        target, repo_ref, sandbox_tools_doc, emitters,
        profile_block=hunter_profile_block(profile),
        finding_block=critic_finding_block(finding, vote_index, votes_total))
    return AgentSpec(
        name=f"critic-{finding.get('finding_id')}-{vote_index}",
        role="critic",
        system_prompt=system,
        emitters=emitters,
        mode="hunt",                       # re-runs the PoC in a sandbox
        bash_tools=list(HUNT_BASH_TOOLS),
        user_message=(
            f"Adversarially validate finding {finding.get('finding_id')} "
            f"({finding.get('title')}). You are critic {vote_index} of {votes_total}. "
            "Recreate + RE-RUN its PoC in your sandbox, attack its assumptions against "
            "the real in-scope source, weigh existing controls, then record your "
            "verdict with `chainreaper critic-create-verdict` — TRUE_POSITIVE only if "
            "you independently reproduced real, reachable impact; FALSE_POSITIVE (with "
            "a concrete refutation) if you disproved it; NEEDS_LIVE_PROOF if it is "
            "plausible but the PoC does not demonstrate production impact. Do not "
            "rubber-stamp the hunter's claim."),
    )


def votes_for(finding: dict, votes_default: int, votes_high_sev: int) -> int:
    """N critics for a finding — more for high-severity (the adversarial panel)."""
    sev = str(finding.get("severity_claim") or "").lower()
    return max(1, votes_high_sev if sev in _HIGH_SEV else votes_default)


def aggregate_verdicts(finding: dict, verdicts: list[dict]) -> dict:
    """Fold N critic Verdicts into the finding's final disposition (T3.1). A finding
    is **confirmed only on a majority** of TRUE_POSITIVE; a majority FALSE_POSITIVE
    refutes it; anything mixed/uncertain is NEEDS_LIVE_PROOF (the conservative,
    precision-favouring rule — a marginal lead must not pass as confirmed)."""
    n = len(verdicts)
    counts = Counter(v.get("verdict") for v in verdicts)
    tp, fp = counts.get("TRUE_POSITIVE", 0), counts.get("FALSE_POSITIVE", 0)
    needs = counts.get("NEEDS_LIVE_PROOF", 0)
    if n == 0:
        final = "NEEDS_LIVE_PROOF"
    elif fp * 2 > n:
        final = "FALSE_POSITIVE"
    elif tp * 2 > n:
        final = "TRUE_POSITIVE"
    else:
        final = "NEEDS_LIVE_PROOF"
    winners = [v for v in verdicts if v.get("verdict") == final]
    conf = round(sum(v.get("verdict_confidence", 5) for v in winners) / max(1, len(winners)))
    # adjusted severity = the modal severity among the winning critics, else the claim
    sev_votes = Counter(v.get("adjusted_severity") for v in winners if v.get("adjusted_severity"))
    adj_sev = sev_votes.most_common(1)[0][0] if sev_votes else finding.get("severity_claim")
    refutation = next((v.get("refutation") for v in verdicts
                       if v.get("verdict") == "FALSE_POSITIVE" and v.get("refutation")), None)
    return {
        "finding_id": finding.get("finding_id"),
        "title": finding.get("title"),
        "final_verdict": final,
        "n_critics": n,
        "votes": {"TRUE_POSITIVE": tp, "FALSE_POSITIVE": fp, "NEEDS_LIVE_PROOF": needs},
        "verdict_confidence": conf,
        "adjusted_severity": adj_sev,
        "refutation": refutation,
    }


def _stage_poc_files(ws: Path, finding: dict) -> None:
    """Pre-write the hunter's PoC files into the critic's sandbox so it can re-run
    immediately (the critic still re-runs + judges; this just removes friction)."""
    poc = finding.get("poc") or {}
    for rel, content in (poc.get("files") or {}).items():
        try:
            dst = ws / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            if not dst.exists():
                dst.write_text(content)
        except OSError:
            pass


# --------------------------------------------------------------------------- #
# Stage entry                                                                  #
# --------------------------------------------------------------------------- #
def run(ctx) -> dict:
    s2 = ctx.state.get("s2")
    s4 = ctx.state.get("s4")
    if not s2 or s2.get("status") != "ok":
        raise RuntimeError("S5: S2 recon output not available in state (run S2 first)")
    if not s4 or s4.get("status") != "ok":
        raise RuntimeError("S5: S4 hunt output not available in state (run S4 first)")

    target = ctx.target
    run_id = ctx.run_id
    s1 = ctx.state.get("s1") or {}
    index_db = s1.get("index_db") or str(ctx.index_dir / "index.db")
    repos = s1.get("repos", [])
    repo_ref = repos[0]["repo_ref"] if repos else (target.name if target else None)
    repo_root = None
    if target is not None:
        repo_root = next((a.ref for a in target.assets_in_scope
                          if a.in_scope and a.kind in ("local_path", "github_repo")), None)
    artifact_db = s4.get("artifact_db") or str(ctx.run_dir / "chainreaper.db")

    cfg = ctx.config.get("validate", {}) or {}
    concurrency = max(1, int(cfg.get("concurrency", 1)))
    per_task_timeout = int(cfg.get("per_task_timeout_s", 1800))
    votes_default = int(cfg.get("votes_default", 1))
    votes_high_sev = int(cfg.get("votes_high_sev", 1))
    max_findings = cfg.get("max_findings")
    fork_cfg = cfg.get("fork", {}) or {}
    exec_backend = (ctx.config.get("runtime", {}) or {}).get("exec_backend", "host")

    # findings to validate (authoritative: the DB, falling back to the s4 checkpoint)
    findings: list[dict] = []
    if Path(artifact_db).exists():
        store = ReconStore(artifact_db)
        try:
            store.create_schema()
            findings = store.get_findings(run_id)
        finally:
            store.close()
    if not findings:
        findings = s4.get("findings") or []
    if not findings:
        log.info("[s5] no findings from S4 — nothing to validate")
        return {"stage": "s5", "status": "ok", "artifact_db": artifact_db,
                "verdicts": [], "aggregates": [],
                "counts": {"findings": 0, "critics": 0, "true_positive": 0,
                           "false_positive": 0, "needs_live_proof": 0}}

    if isinstance(max_findings, int) and max_findings >= 0:
        findings = findings[:max_findings]

    profile = ReconProfile.model_validate(s2["recon_profile"])
    sandbox = Sandbox(ctx.run_dir, backend=exec_backend, rpc=fork_cfg.get("rpc", {}))

    target_chains = list(target.chains) if target else []
    fork_plan = plan_forks(fork_cfg, target_chains, exec_backend=exec_backend,
                           log_dir=str(ctx.run_dir / "logs"))
    fork_plan.apply_env()
    log.info("[s5] fork preflight · %s", fork_plan.summary())

    # fresh validate artifacts (idempotent re-run)
    if Path(artifact_db).exists():
        store = ReconStore(artifact_db)
        try:
            store.create_schema()
            store.clear_validate(run_id)
        finally:
            store.close()

    backend = build_backend(ctx.config, repo_root=repo_root, db_path=index_db)
    if hasattr(backend, "session_timeout"):
        backend.session_timeout = per_task_timeout
    log.info("[s5] provider=%s · %d finding(s) · concurrency=%d", backend.name,
             len(findings), concurrency)

    # one (finding, vote) job per critic
    jobs: list[tuple[dict, int, int]] = []
    for f in findings:
        n = votes_for(f, votes_default, votes_high_sev)
        for i in range(1, n + 1):
            jobs.append((f, i, n))
    log.info("[s5] %d critic session(s) across %d finding(s)", len(jobs), len(findings))

    def _critique(job: tuple[dict, int, int]) -> dict:
        finding, idx, total = job
        fid = finding.get("finding_id")
        try:
            ws = sandbox.prepare(f"critic-{fid}-{idx}", repo_root=repo_root)
        except NotImplementedError as exc:
            log.info("[s5] %s/%d: sandbox unavailable — %s", fid, idx, exc)
            return {"finding_id": fid, "vote": idx, "status": "blocked", "error": str(exc)}
        _stage_poc_files(ws, finding)
        spec = build_critic_spec(finding, profile, target=target, repo_ref=repo_ref,
                                 repo_root=repo_root, sandbox_tools_doc=sandbox.tools_doc(),
                                 vote_index=idx, votes_total=total)
        log.info("[s5] ▶ critic %s vote %d/%d in %s", fid, idx, total, ws)
        try:
            backend.run_agent(spec, index_db=index_db, artifact_db=artifact_db,
                              run_id=run_id, scratch_dir=str(ws), cwd=str(ws))
            return {"finding_id": fid, "vote": idx, "status": "ok"}
        except Exception as exc:  # a critic crash must not sink the stage
            log.info("[s5] ✗ critic %s/%d failed: %s", fid, idx, exc)
            return {"finding_id": fid, "vote": idx, "status": "error", "error": str(exc)[:300]}

    try:
        if concurrency == 1:
            per_critic = [_critique(j) for j in jobs]
        else:
            with ThreadPoolExecutor(max_workers=concurrency) as ex:
                per_critic = list(ex.map(_critique, jobs))
    finally:
        fork_plan.teardown()

    # read back verdicts + aggregate per finding
    verdicts: list[dict] = []
    if Path(artifact_db).exists():
        store = ReconStore(artifact_db)
        try:
            verdicts = store.get_verdicts(run_id)
        finally:
            store.close()
    by_finding: dict[str, list[dict]] = {}
    for v in verdicts:
        by_finding.setdefault(v.get("finding_id"), []).append(v)

    aggregates = [aggregate_verdicts(f, by_finding.get(f.get("finding_id"), []))
                  for f in findings]
    tally = Counter(a["final_verdict"] for a in aggregates)
    counts = {
        "findings": len(findings),
        "critics": len(verdicts),
        "true_positive": tally.get("TRUE_POSITIVE", 0),
        "false_positive": tally.get("FALSE_POSITIVE", 0),
        "needs_live_proof": tally.get("NEEDS_LIVE_PROOF", 0),
    }
    log.info("[s5] done · findings=%d critics=%d → TP=%d FP=%d NEEDS=%d · db=%s",
             counts["findings"], counts["critics"], counts["true_positive"],
             counts["false_positive"], counts["needs_live_proof"], artifact_db)

    return {
        "stage": "s5", "status": "ok",
        "artifact_db": artifact_db,
        "verdicts": verdicts,
        "aggregates": aggregates,
        "per_critic": per_critic,
        "fork_plan": fork_plan.to_dict(),
        "counts": counts,
    }
