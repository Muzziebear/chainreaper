"""Cross-contract / economic-chain hunter-mode self-test (T2.1, offline / ZERO tokens).

Asserts the cross-contract path the harness was structurally blind to:
  * the protocol-interaction-graph models validate + ride on ReconProfile(Input);
  * a cross-contract HunterTask (multiple `contracts` + an `attack_path`) is
    recognised and rendered as a MULTI-CONTRACT attack in the hunter task block,
    and the protocol graph is rendered in the hunter profile block;
  * the recon system prompt carries the PROTOCOL INTERACTION GRAPH mandate;
  * the prefilter NEVER folds a cross-contract task into a single-region twin
    (it is distinct by construction), even when they share a vuln_class.

Usage:  python tests/smoke_crosscontract.py
"""

from __future__ import annotations

import sys

from chainreaper.agents.factory import (
    build_recon_system,
    cross_contract_block,
    hunter_profile_block,
    hunter_task_block,
    incentive_block,
)
from chainreaper.agents.spec import recon_emitters
from chainreaper.models import (
    HunterTask,
    ProtocolEdge,
    ProtocolGraph,
    ProtocolNode,
    ReconProfile,
    ReconProfileInput,
    VulnClass,
)
from chainreaper.recon.prefilter import prefilter


def _single(task_id: str, contract: str) -> dict:
    """A single-region task whose dossier resolves one contract function."""
    return {
        "task_id": task_id, "title": f"reentrancy in {contract}",
        "vuln_class": "reentrancy", "scope_hint": f"{contract}.deposit",
        "hypothesis": "x", "priority": 2,
        "context": {"task_id": task_id, "vuln_class": "reentrancy",
                    "target_functions": [{"contract": contract, "name": "deposit",
                                          "signature": "deposit()", "file": "src/A.sol",
                                          "line": 10, "is_entrypoint": True}]},
    }


def main() -> int:
    print("smoke_crosscontract: cross-contract / economic-chain hunter mode (T2.1)")

    # 1. graph models validate + ride on the profile
    graph = ProtocolGraph(
        nodes=[ProtocolNode(name="Vault", kind="vault"),
               ProtocolNode(name="ChainlinkOracle", kind="oracle", external=True),
               ProtocolNode(name="UniV3Pool", kind="amm", external=True)],
        edges=[ProtocolEdge(src="Vault", dst="ChainlinkOracle", kind="oracle_read",
                            detail="prices collateral"),
               ProtocolEdge(src="ChainlinkOracle", dst="UniV3Pool", kind="price_dep",
                            detail="TWAP source")])
    pin = ReconProfileInput(architecture_md="x" * 160, protocol_graph=graph)
    assert pin.protocol_graph.edges, "graph not carried on ReconProfileInput"
    profile = ReconProfile(protocol_graph=graph, architecture_md="x" * 160)
    print("  [OK ] protocol-graph models validate + ride on ReconProfile(Input)")

    # 2. recon system prompt carries the cross-contract mandate
    sysprompt = build_recon_system(None, "demo", "TOOLS", recon_emitters(8, 12),
                                   initialized_tools=["slither"], sast={"checks": [], "top": []})
    assert "PROTOCOL INTERACTION GRAPH" in sysprompt and "cross-contract" in sysprompt.lower()
    assert "oracle → AMM → liquidation" in cross_contract_block()
    print("  [OK ] recon system prompt carries the PROTOCOL INTERACTION GRAPH mandate")

    # 3. hunter blocks render the graph + the cross-contract attack
    xtask = HunterTask(
        task_id="T-XC-1", title="oracle→amm→liquidation", vuln_class=VulnClass.PRICE_ORACLE,
        scope_hint="Vault.liquidate", hypothesis="manipulate TWAP then liquidate",
        contracts=["Vault", "UniV3Pool", "ChainlinkOracle"],
        attack_path=["FlashLoan:borrow", "UniV3Pool:swap", "ChainlinkOracle:read", "Vault:liquidate"])
    pblock = hunter_profile_block(profile)
    assert "Interaction edges" in pblock and "oracle_read" in pblock, pblock
    tblock = hunter_task_block(xtask, None, None, repo_root="/repo")
    assert "CROSS-CONTRACT attack" in tblock, tblock
    assert "FlashLoan:borrow → UniV3Pool:swap" in tblock, tblock
    assert "Vault, UniV3Pool, ChainlinkOracle" in tblock, tblock
    print("  [OK ] hunter renders the graph + the full cross-contract attack path")

    # 4. prefilter never folds a cross-contract task into a single-region twin
    a = _single("T-A", "Vault")
    b = _single("T-B", "Vault")  # near-identical twin of A → would normally dedupe
    xc = {
        "task_id": "T-XC", "title": "oracle→amm→liquidation",
        "vuln_class": "reentrancy",  # SAME class as A/B on purpose
        "scope_hint": "Vault.liquidate", "hypothesis": "chain",
        "contracts": ["Vault", "UniV3Pool", "ChainlinkOracle"],
        "attack_path": ["UniV3Pool:swap", "Vault:liquidate"],
        "context": {"task_id": "T-XC", "vuln_class": "reentrancy",
                    "target_functions": [{"contract": "Vault", "name": "deposit",
                                          "signature": "deposit()", "file": "src/A.sol",
                                          "line": 10, "is_entrypoint": True}]},
    }
    res = prefilter([a, b, xc], config={"max_hunt_tasks": None, "per_class_cap": None})
    by_id = res.decisions_by_id
    assert by_id["T-XC"].decision == "scheduled", by_id["T-XC"]
    assert "duplicate" not in " ".join(by_id["T-XC"].reasons).lower(), by_id["T-XC"].reasons
    # the plain twin B *is* eligible to be folded (proves dedup still works generally)
    folded = by_id["T-B"].decision == "deferred" and any("duplicate" in r for r in by_id["T-B"].reasons)
    print(f"  [OK ] cross-contract task survives dedup (plain twin folded={folded})")

    # 5. Tier-4 P3 — external-integration trust assumptions + dep-misbehavior tasks
    dep_graph = ProtocolGraph(
        nodes=[ProtocolNode(name="Vault", kind="vault"),
               ProtocolNode(name="ChainlinkOracle", kind="oracle", external=True,
                            trust_assumptions=["assumes the feed is fresh & never returns 0",
                                               "assumes price is within sane bounds"])])
    assert dep_graph.nodes[1].trust_assumptions, "trust_assumptions not on ProtocolNode"
    dep_profile = ReconProfile(protocol_graph=dep_graph, architecture_md="x" * 160)
    dpblock = hunter_profile_block(dep_profile)
    assert "Trust assumptions" in dpblock and "ChainlinkOracle: assumes the feed is fresh" in dpblock, dpblock
    assert "EXTERNAL-DEPENDENCY TRUST ASSUMPTIONS" in cross_contract_block(), "recon mandate missing P3"
    # hunter renders the dep-misbehavior task
    dep_task = HunterTask(
        task_id="T-DEP-1", title="oracle dep misbehavior", vuln_class=VulnClass.PRICE_ORACLE,
        scope_hint="Vault.liquidate", hypothesis="stale/extreme oracle breaks solvency",
        contracts=["ChainlinkOracle"], dep_target="Chainlink ETH/USD feed",
        dep_assumptions=["assumes the feed is fresh & never returns 0"])
    dtblock = hunter_task_block(dep_task, None, None, repo_root="/repo")
    assert "DEP-MISBEHAVIOR task" in dtblock and "Chainlink ETH/USD feed" in dtblock, dtblock
    print("  [OK ] P3: trust_assumptions render + recon mandate + hunter dep-misbehavior block")

    # prefilter NEVER drops a dep-misbehavior task (valid by construction) even with no
    # resolved in-scope target functions, and never folds it as a duplicate.
    dep_td = {
        "task_id": "T-DEP", "title": "oracle dep misbehavior", "vuln_class": "price_oracle_manipulation",
        "scope_hint": "Vault.liquidate", "hypothesis": "stale oracle",
        "contracts": ["ChainlinkOracle"], "dep_target": "Chainlink ETH/USD feed",
        "dep_assumptions": ["assumes fresh"],
        "context": {"task_id": "T-DEP", "vuln_class": "price_oracle_manipulation",
                    "target_functions": []},  # external dep → no in-scope targets resolved
    }
    dres = prefilter([dep_td], config={"max_hunt_tasks": None, "per_class_cap": None})
    ddec = dres.decisions_by_id["T-DEP"]
    assert ddec.decision == "scheduled", f"dep-misbehavior task not scheduled: {ddec}"
    print("  [OK ] P3: prefilter keeps a dep-misbehavior task with no resolved targets (not dropped/folded)")

    # 6. Tier-4 P5 — game-theory: recon mandate + hunter render + prefilter keeps the tasks
    assert "GAME-THEORY / INCENTIVE / LONG-HORIZON" in incentive_block(), "P5 recon mandate missing"
    assert "GAME-THEORY / INCENTIVE / LONG-HORIZON" in sysprompt, "recon prompt missing P5 mandate"
    p5_task = HunterTask(
        task_id="T-P5", title="keeper-LP collusion across epochs", vuln_class=VulnClass.MEV_FRONTRUN,
        scope_hint="Keeper.execute", hypothesis="colluding keeper+LP extract value over time",
        multi_actor=True, long_horizon=True)
    p5block = hunter_task_block(p5_task, None, None, repo_root="/repo")
    assert "MULTI-ACTOR / COLLUSION task" in p5block and "LONG-HORIZON / EPOCH-AWARE task" in p5block, p5block
    p5_td = {"task_id": "T-P5", "title": "collusion", "vuln_class": "mev_frontrunning",
             "scope_hint": "Keeper.execute", "hypothesis": "x",
             "multi_actor": True, "long_horizon": True,
             "context": {"task_id": "T-P5", "vuln_class": "mev_frontrunning", "target_functions": []}}
    p5res = prefilter([p5_td], config={"max_hunt_tasks": None, "per_class_cap": None})
    assert p5res.decisions_by_id["T-P5"].decision == "scheduled", p5res.decisions_by_id["T-P5"]
    print("  [OK ] P5: incentive mandate + hunter multi-actor/long-horizon render + prefilter keeps the task")

    print("smoke_crosscontract: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
