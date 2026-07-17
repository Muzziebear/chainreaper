"""Chimera campaign-scaffold self-test (T1.3, offline / ZERO token spend).

Asserts the deterministic layered-campaign generator (``runtime.campaign``) +
its wiring into the sandbox (``runtime.exec.Sandbox.prepare``):

  * a campaign is generated from a task's bound invariants → handler (actors +
    one ghost var per invariant + a ``handle_*`` wrapper per reachable entrypoint),
    properties (each invariant as ``invariant_<ID>`` that BOTH returns bool and
    asserts — so medusa property-mode AND echidna/medusa assertion-mode catch it),
    a halmos symbolic spec (``check_<ID>``), and valid medusa.json / echidna.yaml;
  * ``Sandbox.prepare`` writes the scaffold under the workspace (test/campaign/ +
    root configs) without clobbering hunter edits on a re-prepare;
  * the hunt-mode Bash guard permits the campaign toolchain (medusa/echidna/halmos);
  * (best-effort, only if forge is installed) the generated handler COMPILES.

Run against the verified ``runs/test-merged`` fixture so the invariants are real.

Usage:  python tests/smoke_campaign.py [runs/<run_id>]
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from chainreaper.agents.hooks import decide_guard
from chainreaper.agents.spec import HUNT_BASH_TOOLS
from chainreaper.models import HunterDossier, HunterTask
from chainreaper.recon.store import ReconStore
from chainreaper.runtime.campaign import build_campaign
from chainreaper.runtime.exec import Sandbox, augmented_env

RUN = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("runs/test-merged")


def _pick_task_with_invariants() -> tuple[HunterTask, HunterDossier]:
    store = ReconStore(str(RUN / "chainreaper.db"))
    store.create_schema()
    try:
        run_id = RUN.name
        ctxs = store.get_contexts(run_id)
        tasks = store.get_tasks(run_id)
    finally:
        store.close()
    assert tasks, f"no tasks in {RUN}/chainreaper.db"
    best = None
    for td in tasks:
        dz = ctxs.get(td["task_id"])
        if not dz:
            continue
        d = HunterDossier.model_validate(dz)
        if d.invariants:
            t = HunterTask.model_validate({k: v for k, v in td.items() if k != "context"})
            if best is None or len(d.invariants) > len(best[1].invariants):
                best = (t, d)
    assert best is not None, "no task with bound invariants in fixture"
    return best


def main() -> int:
    print(f"smoke_campaign: Chimera layered-campaign scaffold (T1.3) · fixture={RUN}")
    task, dossier = _pick_task_with_invariants()
    inv_ids = [i.inv_id for i in dossier.invariants]
    print(f"  task {task.task_id}: {len(inv_ids)} bound invariants, "
          f"{len(dossier.reachable_entrypoints)} reachable entrypoints")

    files = build_campaign(task, dossier)
    expected = {"test/campaign/Properties.sol", "test/campaign/Handler.sol",
                "test/campaign/Symbolic.t.sol", "medusa.json", "echidna.yaml", "CAMPAIGN.md"}
    assert set(files) == expected, f"unexpected file set: {set(files)}"
    print(f"  [OK ] generated {len(files)} files: {sorted(files)}")

    props, handler, sym = (files["test/campaign/Properties.sol"],
                           files["test/campaign/Handler.sol"],
                           files["test/campaign/Symbolic.t.sol"])
    # every invariant becomes a property + a symbolic check, keyed by its id
    for iid in inv_ids:
        frag = iid.replace("-", "_")
        assert f"invariant_{frag}" in props, f"missing property for {iid}"
        assert f"check_{frag}" in sym, f"missing symbolic check for {iid}"
    assert "returns (bool)" in props and "assert(ok)" in props, "property not dual-mode (bool+assert)"
    print(f"  [OK ] properties + symbolic checks for all {len(inv_ids)} invariants (dual-mode)")

    # handler carries actors + ghost vars + a wrapper per reachable entrypoint
    assert "attacker" in handler and "_actor(" in handler, "handler missing actors"
    assert handler.count("ghost_") >= 1, "handler missing ghost vars"
    assert "handle_" in handler and "is Properties" in handler, "handler missing wrappers/inherit"
    print("  [OK ] handler has actors + ghost vars + target-function wrappers")

    # configs valid + targeted at the Handler
    mj = json.loads(files["medusa.json"])
    assert mj["fuzzing"]["targetContracts"] == ["Handler"], "medusa not targeting Handler"
    prefixes = mj["fuzzing"]["testing"]["propertyTesting"]["testPrefixes"]
    assert "invariant_" in prefixes, "medusa not testing invariant_ prefix"
    assert mj["compilation"]["platformConfig"]["target"] == "test/campaign/Handler.sol"
    assert "testMode: assertion" in files["echidna.yaml"], "echidna not in assertion mode"
    print("  [OK ] medusa.json + echidna.yaml valid and target the Handler")

    # T2.2 — optimization objective + LLM-guided fuzz focus
    assert mj["fuzzing"]["testing"]["optimizationTesting"]["enabled"] is True, "optimization not enabled"
    assert "optimize_attackerPnL" in handler and "ghost_attackerPnL" in handler, "no PnL objective"
    focus = mj["fuzzing"]["testing"]["targetFunctionSignatures"]
    assert focus and all(s.startswith("Handler.handle_") for s in focus), f"no LLM fuzz focus: {focus}"
    assert "FUZZ SEEDING" in files["CAMPAIGN.md"] and "optimize_attackerPnL" in files["CAMPAIGN.md"]
    print(f"  [OK ] T2.2: optimization objective + LLM-guided fuzz focus ({len(focus)} fns)")

    # FORK-AWARE + MULTI-CONTRACT economic campaign (the "accurately test economic
    # threats" build): a cross-contract/economic task + a keyless fork URL → medusa
    # fork mode ON + flash-loan/AMM/harvest primitives + protocol-solvency objective.
    from chainreaper.models import HunterTask, VulnClass
    econ_task = HunterTask(
        task_id="T-ECON-1", title="flash-loan oracle/AMM economic chain",
        vuln_class=VulnClass.FLASH_LOAN, scope_hint="Vault.harvest",
        hypothesis="flash-loan amplified price move drains the vault",
        contracts=["Vault", "Strategy", "AMMPool", "FlashLoanSource"],
        attack_path=["FlashLoan:borrow", "AMM:swap-move-price", "Strategy:harvest", "FlashLoan:repay"])
    efiles = build_campaign(econ_task, dossier,
                            fork={"rpc_url": "http://127.0.0.1:8545", "block": 65560668})
    emj = json.loads(efiles["medusa.json"])
    efc = emj["fuzzing"]["chainConfig"]["forkConfig"]
    assert efc["forkModeEnabled"] is True and efc["rpcUrl"] == "http://127.0.0.1:8545" \
        and efc["rpcBlock"] == 65560668, efc
    eh = efiles["test/campaign/Handler.sol"]
    assert all(p in eh for p in ("handle_flashLoan", "handle_ammSwapMovePrice",
                                 "handle_triggerHarvest")), "economic primitives missing"
    assert "optimize_protocolLoss" in eh and "ghost_protocolSolvency" in eh, "no solvency objective"
    assert eh.count("real deployed address") >= 4, "missing real-address slots"
    assert "ECONOMIC / MULTI-CONTRACT" in efiles["CAMPAIGN.md"] \
        and "FORK MODE" in efiles["CAMPAIGN.md"], "runbook missing econ/fork mandate"
    # a non-fork build leaves fork mode OFF (no key embedded by default)
    assert json.loads(build_campaign(econ_task, dossier)["medusa.json"]
                      )["fuzzing"]["chainConfig"]["forkConfig"]["forkModeEnabled"] is False
    print("  [OK ] fork-aware medusa + multi-contract economic handler (flash-loan/AMM/"
          "harvest + solvency objective)")

    # Tier-4 P1 ADVERSE-MARKET stress layer: an oracle/price task auto-enables the
    # market-condition primitives + ghost market vars; the handler still compiles and
    # the runbook carries the stress mandate. A non-market task leaves it OFF.
    oracle_task = HunterTask(
        task_id="T-ORACLE-1", title="oracle price manipulation under stress",
        vuln_class=VulnClass.PRICE_ORACLE, scope_hint="LendingPool.liquidate",
        hypothesis="warped oracle price makes a solvent position liquidatable")
    sfiles = build_campaign(oracle_task, dossier,
                            fork={"rpc_url": "http://127.0.0.1:8545", "block": 0})
    sh = sfiles["test/campaign/Handler.sol"]
    stress_prims = ("handle_stressWarpOraclePrice", "handle_stressForceOracleStale",
                    "handle_stressSkewPoolReserves", "handle_stressDepegCollateral",
                    "handle_stressSpikeFunding")
    assert all(p in sh for p in stress_prims), "stress primitives missing from oracle task"
    stress_ghosts = ("ghost_oraclePriceBps", "ghost_oracleStale", "ghost_collateralPegBps",
                     "ghost_fundingRateBps", "ghost_poolSkewBps")
    assert all(g in sh for g in stress_ghosts), "ghost market vars missing"
    assert "ADVERSE-MARKET STRESS" in sfiles["CAMPAIGN.md"], "runbook missing stress mandate"
    # auto-derivation: a non-market task (access control) gets NO stress layer...
    ac_task = HunterTask(task_id="T-AC-1", title="missing onlyOwner",
                         vuln_class=VulnClass.ACCESS_CONTROL, scope_hint="X.setOwner",
                         hypothesis="anyone can call setOwner")
    assert "handle_stressWarpOraclePrice" not in \
        build_campaign(ac_task, dossier)["test/campaign/Handler.sol"], "stress leaked into AC task"
    # ...but an explicit stress=True forces it on even for that task.
    assert "handle_stressWarpOraclePrice" in \
        build_campaign(ac_task, dossier, stress=True)["test/campaign/Handler.sol"], \
        "explicit stress=True ignored"
    # ...and stress=False forces it OFF even for an oracle task.
    assert "handle_stressWarpOraclePrice" not in \
        build_campaign(oracle_task, dossier, stress=False)["test/campaign/Handler.sol"], \
        "explicit stress=False ignored"
    print("  [OK ] T4-P1: adverse-market stress layer (5 market primitives + ghost vars + "
          "auto/forced toggle)")

    # Tier-4 P3  DEP-MISBEHAVIOR layer: a task carrying a `dep_target` gets mock-dep
    # primitives that make the trusted EXTERNAL dependency misbehave on the fork, with
    # the protocol's invariants re-checked. A task with no dep_target gets none.
    dep_task = HunterTask(
        task_id="T-DEP-1", title="oracle dependency misbehavior",
        vuln_class=VulnClass.PRICE_ORACLE, scope_hint="LendingPool.liquidate",
        hypothesis="a stale/extreme/paused oracle breaks protocol solvency",
        contracts=["ChainlinkOracle"], dep_target="Chainlink ETH/USD feed",
        dep_assumptions=["assumes the feed is fresh & never returns 0/min",
                         "assumes the feed never reverts"])
    dfiles = build_campaign(dep_task, dossier,
                            fork={"rpc_url": "http://127.0.0.1:8545", "block": 0})
    dh = dfiles["test/campaign/Handler.sol"]
    dep_prims = ("handle_depReturnStale", "handle_depReturnExtreme", "handle_depRevert",
                 "handle_depReentrant", "handle_depClearMock")
    assert all(p in dh for p in dep_prims), "dep-misbehavior primitives missing"
    dep_ghosts = ("ghost_depStale", "ghost_depReturnBps", "ghost_depReverting",
                  "ghost_depReentered")
    assert all(g in dh for g in dep_ghosts), "dep ghost vars missing"
    assert "address internal depAddr" in dh, "dep address slot missing"
    assert "Chainlink ETH/USD feed" in dh, "dep_target not surfaced in handler"
    assert "EXTERNAL-DEPENDENCY MISBEHAVIOR" in dfiles["CAMPAIGN.md"], "runbook missing dep mandate"
    # a task with no dep_target gets NO dep layer
    assert "handle_depReturnStale" not in \
        build_campaign(oracle_task, dossier)["test/campaign/Handler.sol"], "dep layer leaked"
    print("  [OK ] T4-P3: dep-misbehavior layer (5 mock-dep primitives + ghost vars + dep addr "
          "slot, gated on dep_target)")

    # Tier-4 P5  MULTI-ACTOR + LONG-HORIZON: a multi_actor task gets colluding-actor
    # slots + an optimize_coalitionPnL objective; a long_horizon task gets a real
    # vm.warp/roll time-advance handler + a LONGER medusa callSequenceLength.
    p5_task = HunterTask(
        task_id="T-P5-1", title="keeper-LP collusion over epochs",
        vuln_class=VulnClass.MEV_FRONTRUN, scope_hint="Keeper.execute",
        hypothesis="a colluding keeper+LP extract value across funding epochs",
        multi_actor=True, long_horizon=True)
    p5files = build_campaign(p5_task, dossier)
    p5h = p5files["test/campaign/Handler.sol"]
    assert "optimize_coalitionPnL" in p5h and "ghost_coalitionPnL" in p5h, "no coalition objective"
    assert "keeper" in p5h and "lp" in p5h, "colluding actors missing"
    assert "handle_advanceTime" in p5h and "_P5Vm" in p5h and ".warp(" in p5h and ".roll(" in p5h, \
        "long-horizon time-advance handler missing"
    p5mj = json.loads(p5files["medusa.json"])
    assert p5mj["fuzzing"]["callSequenceLength"] == 300, "long-horizon callSequenceLength not raised"
    assert p5mj["fuzzing"]["blockTimestampDelayMax"] == 31536000, "long-horizon ts-delay not widened"
    # medusa rejects a partial config, so the FULL default must still be present (acceptance)
    assert p5mj["fuzzing"]["testing"]["optimizationTesting"]["enabled"] is True \
        and p5mj["compilation"]["platformConfig"]["target"] == "test/campaign/Handler.sol", \
        "long-horizon medusa.json lost required default keys"
    assert "MULTI-ACTOR / COLLUSION" in p5files["CAMPAIGN.md"] \
        and "LONG-HORIZON / EPOCH-AWARE" in p5files["CAMPAIGN.md"], "runbook missing P5 mandates"
    # a shallow (non-economic, non-attacker-class, non-P5) task keeps the DEFAULT
    # sequence length of 100 — TASK 2 only deepens cross-contract / attacker-primitive
    # tasks to 300, so a single-contract access_control task must stay at 100.
    ac_mj = json.loads(build_campaign(ac_task, dossier)["medusa.json"])
    assert ac_mj["fuzzing"]["callSequenceLength"] == 100, "shallow-task callSequenceLength changed"
    assert "optimize_coalitionPnL" not in handler and "handle_advanceTime" not in handler, "P5 leaked"
    print("  [OK ] T4-P5: multi-actor coalition objective + long-horizon vm.warp/roll handler + "
          "callSequenceLength 300 (medusa full-config preserved)")

    # Sandbox.prepare writes the scaffold + is non-clobbering on re-prepare
    with tempfile.TemporaryDirectory() as d:
        sb = Sandbox(d)
        ws = sb.prepare(task.task_id, repo_root=str(RUN), campaign_files=files)
        for rel in expected:
            assert (ws / rel).exists(), f"prepare did not write {rel}"
        marker = "// hunter wired this\n"
        (ws / "test/campaign/Handler.sol").write_text(marker)
        sb.prepare(task.task_id, repo_root=str(RUN), campaign_files=files)  # re-prepare
        assert (ws / "test/campaign/Handler.sol").read_text() == marker, \
            "re-prepare clobbered a hunter edit"
        print("  [OK ] Sandbox.prepare writes scaffold + does not clobber hunter edits")

    # guard permits the campaign toolchain
    env = {"CHAINREAPER_MODE": "hunt",
           "CHAINREAPER_ALLOWED_TOOLS": ",".join(HUNT_BASH_TOOLS),
           "CHAINREAPER_ALLOWED_BASH": "code-index,hunt-create-finding,hunt-finish",
           "CHAINREAPER_SCRATCH": "/tmp"}
    for cmd in ("medusa fuzz", "echidna test/campaign/Handler.sol --config echidna.yaml",
                "halmos --function check_"):
        _, out = decide_guard({"tool_name": "Bash", "tool_input": {"command": cmd}}, env)
        dec = json.loads(out)["hookSpecificOutput"]["permissionDecision"]
        assert dec == "allow", f"guard denied campaign cmd: {cmd}"
    print("  [OK ] hunt guard permits medusa/echidna/halmos")

    # best-effort: the generated handler compiles (only if forge present)
    forge = shutil.which("forge", path=augmented_env().get("PATH", ""))
    if forge:
        # Compile both the base handler AND the stress handler (the Tier-4 P1 market
        # primitives must be valid Solidity, not just present as strings).
        for label, cfiles in (("base", files), ("stress", sfiles),
                              ("dep-misbehavior", dfiles), ("multi-actor+long-horizon", p5files)):
            with tempfile.TemporaryDirectory() as d:
                ws = Sandbox(d).prepare(task.task_id, repo_root=str(RUN), campaign_files=cfiles)
                try:
                    p = subprocess.run([forge, "build"], cwd=str(ws), capture_output=True,
                                       text=True, timeout=180, env=augmented_env())
                    ok = p.returncode == 0
                    print(f"  [{'OK ' if ok else 'WARN'}] forge build of {label} handler "
                          f"({'compiles' if ok else 'failed — see below'})")
                    if not ok:
                        print("    " + "\n    ".join((p.stdout + p.stderr).strip().splitlines()[-6:]))
                except subprocess.TimeoutExpired:
                    print(f"  [WARN] forge build of {label} handler timed out (non-fatal)")
    else:
        print("  [SKIP] forge not on PATH — skipping compile check")

    print("smoke_campaign: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
