"""S4 Hunt self-test (offline, ZERO token spend).

Exercises the deterministic S4 plumbing against the verified ``runs/test-merged``
fixture (16 scheduled tasks w/ dossiers + schedule) — no Hunter session is spawned,
so no model tokens are spent. Asserts the spec §S4 contract:

  * the Hunt contracts validate + coerce (Finding/PoC/CodeLocation/HuntOutcome);
  * the stage's hand-off reader recovers every scheduled task's HunterDossier +
    PrefilterDecision from chainreaper.db (the S3 checkpoint strips the dossier);
  * the Hunter spec/prompt composes with the dossier's reachable_entrypoints as the
    PoC attack surface (the bridge "bug is here" → "exploitable from this entrypoint"),
    carries the sandbox TOOLS + the REQUIRED finding/outcome obligation, and runs in
    hunt mode with the sandbox toolchain allow-listed;
  * the Foundry sandbox scaffolds (foundry.toml + remappings + forge-std wired in);
  * `hunt-create-finding` + `hunt-finish` validate, persist, and round-trip through
    Finding / HuntOutcome, and the Stop hook enforces the outcome obligation.

Usage:  python tests/smoke_s4.py [runs/<run_id>]
Defaults to runs/test-merged (the verified offline fixture).
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

from chainreaper.agents.emitters import EmitError, create_record
from chainreaper.agents.hooks import decide_guard, decide_stop
from chainreaper.agents.spec import HUNT_BASH_TOOLS
from chainreaper.models import (
    CodeLocation,
    Finding,
    HunterDossier,
    HunterTask,
    HuntOutcome,
    PoC,
    PrefilterDecision,
    ReconProfile,
    Target,
)
from chainreaper.recon.store import ReconStore
from chainreaper.runtime.exec import Sandbox
from chainreaper.runtime.fork import AnvilHandle, ProbeResult, plan_forks
from chainreaper.stages.s4_hunt import _load_handoff, build_hunter_spec


def _ok(label: str) -> None:
    print(f"  ok: {label}")


class _Ctx:
    """Minimal RunContext stand-in for the deterministic readers."""

    def __init__(self, run_dir: Path, state: dict):
        self.run_dir = run_dir
        self.state = state
        self.config = {}
        self.run_id = run_dir.name

    @property
    def index_dir(self) -> Path:
        return self.run_dir / "index"

    @property
    def target(self):
        s0 = self.state.get("s0")
        return Target.model_validate(s0) if s0 else None


def _decision(out: str) -> str | None:
    return json.loads(out).get("hookSpecificOutput", {}).get("permissionDecision") if out else None


# --------------------------------------------------------------------------- #
# 1. Hunt contracts validate + coerce                                          #
# --------------------------------------------------------------------------- #
def test_contracts() -> None:
    print("== hunt contracts ==")
    poc = PoC(framework="foundry_fork",
              files={"test/Exploit.t.sol": "// pragma solidity ^0.8.0;"},
              run_cmd="forge test --match-test testExploit -vvv",
              expected_observation="vault drained: balanceOf(attacker) > 0",
              succeeded=True)
    loc = CodeLocation(file="contracts/X.sol", contract="X", symbol="withdraw",
                       line_start=10, line_end=20, fix_before="a", fix_after="b")
    f = Finding(finding_id="F-1", task_id="T-01", title="Reentrant withdraw drains pool",
                vuln_class="reentrancy", sc_top10="SC05", severity_claim="high",
                locations=[loc], source_ref="X.withdraw", sink_ref="X.call",
                description="d", impact="up to pool TVL", exploit_scenario="e",
                preconditions=["attacker holds 1 share"], poc=poc,
                live_validated=False, confidence="high", immunefi_impact="Theft of funds")
    assert f.confidence == 0.85, f.confidence            # qualitative token coerced
    assert f.poc.succeeded is True and f.poc.files
    # round-trip through JSON (the save-script path)
    f2 = Finding.model_validate(json.loads(f.model_dump_json()))
    assert f2 == f
    _ok("Finding/PoC/CodeLocation validate + confidence coerced + round-trip")

    o = HuntOutcome(task_id="T-01", outcome="empty", n_findings="0",
                    summary="explored 3 entrypoints, no reachable impact",
                    tools_run=["forge", "slither"], poc_built=False)
    assert o.outcome == "empty" and o.n_findings == 0
    # extra keys forbidden (emit-schema discipline)
    try:
        HuntOutcome.model_validate({"task_id": "x", "outcome": "empty", "summary": "s", "bogus": 1})
        raise AssertionError("extra key should be forbidden")
    except Exception:
        pass
    _ok("HuntOutcome validates + forbids extra keys")


# --------------------------------------------------------------------------- #
# 2. Hand-off reader + 3. prompt composition                                   #
# --------------------------------------------------------------------------- #
def test_handoff_and_prompt(run_dir: Path) -> dict:
    print(f"== hand-off + prompt composition ({run_dir}) ==")
    ckpt = run_dir / "checkpoints"
    state = {st: json.loads((ckpt / f"{st}.json").read_text())
             for st in ("s0", "s1", "s2", "s3") if (ckpt / f"{st}.json").exists()}
    ctx = _Ctx(run_dir, state)
    artifact_db = state["s3"].get("artifact_db") or str(run_dir / "chainreaper.db")

    scheduled = state["s3"]["scheduled_tasks"]
    assert scheduled, "no scheduled tasks in s3 checkpoint"
    # the S3 checkpoint strips the dossier from scheduled_tasks…
    assert not (scheduled[0].get("context")), "s3 scheduled_tasks should NOT carry the dossier"

    dossiers, schedules = _load_handoff(ctx, ctx.run_id, artifact_db)
    sched_ids = {t["task_id"] for t in scheduled}
    # …and the reader recovers every scheduled task's dossier + schedule from the DB
    missing_doss = [tid for tid in sched_ids if tid not in dossiers]
    assert not missing_doss, f"dossier hand-off lost tasks: {missing_doss}"
    assert sched_ids <= set(schedules), "schedule hand-off lost tasks"
    reach = sum(1 for tid in sched_ids if dossiers[tid].get("reachable_entrypoints"))
    _ok(f"hand-off recovered {len(dossiers)} dossiers + {len(schedules)} schedules "
        f"({reach}/{len(sched_ids)} scheduled tasks have reachable entrypoints)")

    profile = ReconProfile.model_validate(state["s2"]["recon_profile"])
    target = ctx.target
    repo_root = next((a.ref for a in target.assets_in_scope
                      if a.in_scope and a.kind in ("local_path", "github_repo")), None) if target else None
    sandbox = Sandbox(run_dir, backend="host")
    tools_doc = sandbox.tools_doc()

    # rank-1 task: compose its Hunter spec and assert the attack surface is foregrounded
    top = min(scheduled, key=lambda t: (schedules.get(t["task_id"], {}).get("rank") or 9999))
    task = HunterTask.model_validate({k: v for k, v in top.items() if k != "context"})
    dossier = HunterDossier.model_validate(dossiers[task.task_id])
    decision = PrefilterDecision.model_validate(schedules[task.task_id])
    spec = build_hunter_spec(task, dossier, decision, profile, target=target,
                             repo_ref=state["s1"]["repos"][0]["repo_ref"],
                             repo_root=repo_root, sandbox_tools_doc=tools_doc)
    sysp = spec.system_prompt

    assert spec.mode == "hunt" and spec.bash_tools == list(HUNT_BASH_TOOLS)
    assert spec.required_spec() == "hunt-create-finding:0,hunt-finish:1", spec.required_spec()
    assert "hunt-finish" in [e.command for e in spec.emitters]
    # the dossier's reachable entrypoints are the PoC attack surface → must be in-prompt
    eps = dossier.reachable_entrypoints
    assert eps, f"fixture task {task.task_id} has no reachable entrypoints to assert on"
    ep0 = eps[0]
    ep_name = ep0.get("name") or (ep0.get("signature") or "")[:24]
    assert ep_name and ep_name in sysp, f"entrypoint {ep_name!r} not surfaced in the hunter prompt"
    assert "ATTACK SURFACE" in sysp and "REQUIRED OUTPUT" in sysp
    assert "RECON PROFILE" in sysp and "Foundry sandbox" in sysp
    # the impact-PoC discipline (seed is a hint, not a terminal lane)
    assert "demonstrates impact" in sysp.lower() or "demonstrate impact" in sysp.lower()
    assert task.task_id in sysp
    _ok(f"hunter prompt for {task.task_id} foregrounds entrypoint {ep_name!r} "
        f"+ sandbox TOOLS + REQUIRED finding/outcome obligation")

    # the OUTPUT MECHANICS (added by session) inject the Finding/HuntOutcome schemas
    from chainreaper.agents.session import output_mechanics
    mech = output_mechanics(spec, "/tmp/ws")
    assert "hunt-create-finding" in mech and "hunt-finish" in mech
    assert "Finding" in mech and "HuntOutcome" in mech
    _ok("OUTPUT MECHANICS inject both save-scripts + their JSON schemas")
    return {"artifact_db": artifact_db}


# --------------------------------------------------------------------------- #
# 4. Sandbox scaffold                                                          #
# --------------------------------------------------------------------------- #
def test_sandbox(run_dir: Path) -> None:
    print("== sandbox scaffold ==")
    repo_root = "gmx-source/gmx-synthetics" if Path("gmx-source/gmx-synthetics").exists() else None
    with tempfile.TemporaryDirectory() as d:
        sb = Sandbox(Path(d), backend="host")
        ws = sb.prepare("T-01", repo_root=repo_root)
        assert (ws / "foundry.toml").exists()
        assert "forge-std/=" in (ws / "remappings.txt").read_text()
        assert (ws / "lib" / "forge-std" / "src" / "Test.sol").exists(), "forge-std not wired"
        for sub in ("src", "test", "script", "lib"):
            assert (ws / sub).is_dir()
        avail = sb.available_tools()
        _ok("foundry project scaffolded + forge-std wired · tools "
            + ", ".join(t for t, ok in avail.items() if ok))


# --------------------------------------------------------------------------- #
# 5. Emitters persist + round-trip + Stop obligation                           #
# --------------------------------------------------------------------------- #
def test_emitters_and_stop() -> None:
    print("== hunt emitters + stop obligation ==")
    with tempfile.TemporaryDirectory() as d:
        db = str(Path(d) / "chainreaper.db")
        ReconStore(db).create_schema()
        run_id, agent, session = "r", "hunter-T-01", "sess1"

        finding = {
            "finding_id": "F-1", "task_id": "T-01",
            "title": "Reentrant share-price re-read", "vuln_class": "readonly_reentrancy",
            "sc_top10": "SC05", "severity_claim": "critical",
            "description": "d", "impact": "TVL", "exploit_scenario": "e",
            "poc": {"framework": "foundry_fork", "files": {"test/E.t.sol": "x"},
                    "run_cmd": "forge test", "expected_observation": "drained",
                    "succeeded": True},
            "confidence": 0.8, "live_validated": False,
        }
        res = create_record("hunt-create-finding", json.dumps([finding]),
                            db=db, run_id=run_id, agent=agent, session=session)
        assert res["count"] == 1 and res["table"] == "findings", res
        _ok("hunt-create-finding validated + persisted (with nested PoC)")

        # schema miss carries the schema for self-correction
        try:
            create_record("hunt-create-finding", json.dumps([{"title": "no ids"}]),
                          db=db, run_id=run_id)
            raise AssertionError("expected EmitError for schema miss")
        except EmitError as exc:
            assert exc.schema is not None
        _ok("malformed Finding rejected with schema")

        # empty [] is a clean no-op for the optional finding emitter (empty hunt)
        res0 = create_record("hunt-create-finding", "[]", db=db, run_id=run_id,
                             agent="hunter-empty", session="se")
        assert res0["count"] == 0, res0
        _ok("empty hunt-create-finding [] is a clean no-op (not an error)")

        store = ReconStore(db)
        try:
            # Stop hook: required hunt-finish not yet recorded → block
            env = {"CHAINREAPER_RUN_ID": run_id, "CHAINREAPER_AGENT": agent,
                   "CHAINREAPER_SESSION": session,
                   "CHAINREAPER_REQUIRED": "hunt-create-finding:0,hunt-finish:1",
                   "CHAINREAPER_MAX_STOP_BLOCKS": "5"}
            code, out = decide_stop(env, store)
            assert code == 0 and json.loads(out).get("decision") == "block", (code, out)
            _ok("Stop blocks until hunt-finish recorded (finding alone is not enough)")
        finally:
            store.close()

        outcome = {"task_id": "T-01", "outcome": "finding", "n_findings": 1,
                   "poc_built": True, "tools_run": ["forge"], "summary": "drained on fork"}
        res = create_record("hunt-finish", json.dumps(outcome),
                            db=db, run_id=run_id, agent=agent, session=session)
        assert res["count"] == 1 and res["table"] == "hunt_outcomes", res

        store = ReconStore(db)
        try:
            env = {"CHAINREAPER_RUN_ID": run_id, "CHAINREAPER_AGENT": agent,
                   "CHAINREAPER_SESSION": session,
                   "CHAINREAPER_REQUIRED": "hunt-create-finding:0,hunt-finish:1",
                   "CHAINREAPER_MAX_STOP_BLOCKS": "5"}
            assert decide_stop(env, store) == (0, ""), "should allow once outcome recorded"
            _ok("Stop allows once hunt-finish recorded")

            # round-trip both through their models
            fs = store.get_findings(run_id)
            os_ = store.get_outcomes(run_id)
            assert len(fs) == 1 and len(os_) == 1
            assert Finding.model_validate(fs[0]).poc.succeeded is True
            assert HuntOutcome.model_validate(os_[0]).outcome == "finding"
            _ok("findings + outcomes round-trip through Finding / HuntOutcome")

            # an empty hunt (no findings) can still finish via hunt-finish alone
            create_record("hunt-finish", json.dumps(
                {"task_id": "T-02", "outcome": "empty", "summary": "nothing reachable"}),
                db=db, run_id=run_id, agent="hunter-T-02", session="sess2")
            env2 = {"CHAINREAPER_RUN_ID": run_id, "CHAINREAPER_AGENT": "hunter-T-02",
                    "CHAINREAPER_SESSION": "sess2",
                    "CHAINREAPER_REQUIRED": "hunt-create-finding:0,hunt-finish:1",
                    "CHAINREAPER_MAX_STOP_BLOCKS": "5"}
            assert decide_stop(env2, store) == (0, ""), "empty hunt must finish cleanly"
            _ok("empty hunt (0 findings) finishes cleanly via hunt-finish")

            # clear_hunt drops hunt artifacts, leaves recon rows
            store.clear_hunt(run_id)
            assert store.get_findings(run_id) == [] and store.get_outcomes(run_id) == []
            _ok("clear_hunt resets S4 artifacts for a re-run")
        finally:
            store.close()

    # guard hunt-mode allows the toolchain, denies egress/destructive (spot-check)
    genv = {"CHAINREAPER_MODE": "hunt", "CHAINREAPER_SCRATCH": "/tmp/ws",
            "CHAINREAPER_ALLOWED_BASH": "code-index,hunt-create-finding,hunt-finish",
            "CHAINREAPER_ALLOWED_TOOLS": ",".join(HUNT_BASH_TOOLS)}

    def g(tool, **inp):
        return _decision(decide_guard({"tool_name": tool, "tool_input": inp}, genv)[1])
    assert g("Write", file_path="/tmp/ws/test/E.t.sol") == "allow"
    assert g("Bash", command="forge test --match-test testExploit -vvv") == "allow"
    assert g("Bash", command="chainreaper hunt-finish --in /tmp/ws/o.json") == "allow"
    assert g("Bash", command="rm -rf /") == "deny"
    assert g("Bash", command="curl http://x") == "deny"
    _ok("guard hunt-mode allows toolchain + save-scripts, denies egress/destructive")


# --------------------------------------------------------------------------- #
# 6. Fork preflight (offline — injected prober/launcher, ZERO network)         #
# --------------------------------------------------------------------------- #
def test_fork_preflight() -> None:
    print("== fork preflight ==")
    URL = "https://arb-mainnet.g.alchemy.com/v2/SECRETKEY"

    def prober_ok(url, timeout):
        return ProbeResult(reachable=True, chain_id=42161, block_number=250, archive=True)

    def prober_full(url, timeout):  # reachable but NON-archive (latest-only)
        return ProbeResult(reachable=True, chain_id=42161, block_number=250, archive=False)

    def no_anvil(chain, url, block, port, **kw):
        return None

    def fake_anvil(chain, url, block, port, **kw):
        return AnvilHandle(serve_url=f"http://127.0.0.1:{port}", pid=4242)

    # (a) ready, served upstream (no shared anvil); default = fork LATEST (unpinned,
    # so a free/full node never needs archive state)
    plan = plan_forks({"rpc_urls": {"arbitrum": URL}, "shared_anvil": False},
                      ["arbitrum"], exec_backend="host", env={},
                      prober=prober_ok, anvil_launcher=no_anvil)
    cf = plan.chains[0]
    assert cf.ready and cf.block is None and not cf.fronted_by_anvil, cf
    assert plan.env_exports() == {"ARBITRUM_RPC_URL": URL}
    note = plan.hunter_note()
    assert "FORK STATUS" in note and "LIVE" in note and "arbitrum" in note
    assert "latest" in note.lower() and "archive" in note.lower()  # warns not to pin
    # to_dict must NOT leak the provider key, only the host
    assert "SECRETKEY" not in json.dumps(plan.to_dict())
    assert plan.chains[0].to_dict()["upstream_host"] == "arb-mainnet.g.alchemy.com"
    _ok("ready+upstream: validates, forks latest (no archive), exports env, redacts key")

    # (b) explicit block pin honored (for when an archive RPC is configured)
    plan_b = plan_forks({"rpc_urls": {"arbitrum": URL}, "block": {"arbitrum": 100},
                         "shared_anvil": False}, [], exec_backend="host", env={},
                        prober=prober_ok, anvil_launcher=no_anvil)
    assert plan_b.chains[0].block == 100 and "100" in plan_b.hunter_note()
    _ok("explicit fork block pin honored (archive-RPC case)")

    # (c) shared anvil fronts the fork; teardown is clean
    plan_c = plan_forks({"rpc_urls": {"arbitrum": URL}, "shared_anvil": True},
                        [], exec_backend="host", env={},
                        prober=prober_ok, anvil_launcher=fake_anvil)
    cf = plan_c.chains[0]
    assert cf.ready and cf.fronted_by_anvil and cf.serve_url == "http://127.0.0.1:8545"
    assert plan_c.env_exports()["ARBITRUM_RPC_URL"] == "http://127.0.0.1:8545"
    fenv: dict = {}
    plan_c.apply_env(fenv)
    assert fenv["ARBITRUM_RPC_URL"] == "http://127.0.0.1:8545"
    plan_c.teardown()  # no exception (handle has no live proc)
    _ok("shared anvil fronts fork + apply_env + teardown")

    # (d) unreachable + chain mismatch + unconfigured → clean degrade, never raises
    def prober_dead(url, timeout):
        return ProbeResult(reachable=False, detail="ConnectionRefused")

    def prober_wrongchain(url, timeout):
        return ProbeResult(reachable=True, chain_id=1, block_number=9)

    p_dead = plan_forks({"rpc_urls": {"arbitrum": URL}}, [], exec_backend="host",
                        env={}, prober=prober_dead, anvil_launcher=no_anvil)
    assert p_dead.chains[0].status == "unreachable" and not p_dead.any_ready
    p_wrong = plan_forks({"rpc_urls": {"arbitrum": URL}}, [], exec_backend="host",
                         env={}, prober=prober_wrongchain, anvil_launcher=no_anvil)
    assert p_wrong.chains[0].status == "chain_mismatch"
    p_unconf = plan_forks({}, ["arbitrum"], exec_backend="host", env={},
                          prober=prober_ok, anvil_launcher=no_anvil)
    assert p_unconf.chains[0].status == "unconfigured" and not p_unconf.any_ready
    assert "NO mainnet fork" in p_unconf.hunter_note()
    _ok("unreachable / chain_mismatch / unconfigured all degrade to local-only")

    # (d2) a non-archive upstream still forks (latest) but the note warns the hunter
    p_full = plan_forks({"rpc_urls": {"arbitrum": URL}, "shared_anvil": False},
                        [], exec_backend="host", env={},
                        prober=prober_full, anvil_launcher=no_anvil)
    assert p_full.chains[0].ready and p_full.chains[0].archive is False
    assert "NON-ARCHIVE" in p_full.hunter_note()
    assert p_full.chains[0].to_dict()["archive"] is False
    _ok("non-archive upstream detected → hunter warned to fall back to local fast")

    # (e) env-var fallback (no rpc_urls, URL only in the environment)
    p_env = plan_forks({}, ["arbitrum"], exec_backend="host",
                       env={"ARBITRUM_RPC_URL": URL}, prober=prober_ok,
                       anvil_launcher=no_anvil)
    assert p_env.chains[0].ready
    _ok("resolves RPC URL from <CHAIN>_RPC_URL env fallback")

    # (f) the live note threads into the composed hunter prompt
    from chainreaper.models import HunterTask, ReconProfile, Target
    task = HunterTask(task_id="T-X", title="t", vuln_class="reentrancy",
                      scope_hint="X.f", hypothesis="h")
    spec = build_hunter_spec(task, None, None, ReconProfile(target=Target(program_id="p", name="n")),
                             target=None, repo_ref="r", repo_root="/repo",
                             sandbox_tools_doc="TOOLS", fork_note=plan.hunter_note())
    assert "FORK STATUS" in spec.system_prompt and "createSelectFork" in spec.system_prompt
    _ok("fork note injected into the hunter system prompt")


def main() -> int:
    run_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("runs/test-merged")
    if not run_dir.exists():
        raise SystemExit(f"fixture run dir not found: {run_dir}")
    test_contracts()
    test_handoff_and_prompt(run_dir)
    test_sandbox(run_dir)
    test_emitters_and_stop()
    test_fork_preflight()
    print("\nsmoke_s4: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
