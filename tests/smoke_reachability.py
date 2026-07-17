"""Static call-graph edge-resolution self-test (task 1A, offline / ZERO tokens).

Reproduces the Aave-v4 pathology: a Hub function is only reachable through a
Spoke/Router that calls it via an INTERFACE (``IHub(x).liquidate()``) — an edge
slither leaves pointing at the interface stub (no body), so the reachability BFS
can't climb Spoke→Hub and the task is (wrongly) marked unreachable.

Asserts that after ``load_export`` wires the resolved dispatch edges:
  * a caller through the interface resolves to the CONCRETE Hub function
    (``callers(Hub.liquidate)`` now includes the Router/Spoke), and
  * the reachability BFS reaches the Hub's internal function from a public
    entrypoint via the multi-hop Router→Spoke→Hub path — coverage that was 0
    without edge resolution.

Usage:  python tests/smoke_reachability.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from chainreaper.index.build import load_export
from chainreaper.index.store import Store
from chainreaper.recon.dossier import _reachable_entrypoints
from chainreaper.tools.code_index import CodeIndex


def _fn(name, sig, calls=None, visibility="public", mutability="nonpayable"):
    return {"name": name, "signature": sig, "visibility": visibility,
            "mutability": mutability, "modifiers": [], "line_start": 1, "line_end": 2,
            "calls": calls or [], "reads": [], "writes": [], "sinks": []}


# A modular Hub/Spoke deployment. The Router (public entrypoint) calls the Spoke via
# the ISpoke interface; the Spoke calls the Hub's internal accounting via IHub — both
# typed through interfaces, exactly what slither leaves unresolved.
EXPORT = {
    "contracts": [
        {"name": "IHub", "kind": "interface", "file": "IHub.sol", "inheritance": [],
         "state_vars": [], "functions": [_fn("settle", "settle(address)",
                                              visibility="external")]},
        {"name": "ISpoke", "kind": "interface", "file": "ISpoke.sol", "inheritance": [],
         "state_vars": [], "functions": [_fn("act", "act(uint256)", visibility="external")]},
        {"name": "Hub", "kind": "contract", "file": "Hub.sol", "inheritance": ["IHub"],
         "state_vars": [{"name": "debt", "type": "uint256", "visibility": "public"}],
         "functions": [
             _fn("settle", "settle(address)", visibility="external"),
             # the real accounting sink, internal, reached only via settle()
             _fn("_applyLoss", "_applyLoss(address)", visibility="internal"),
         ]},
        {"name": "Spoke", "kind": "contract", "file": "Spoke.sol", "inheritance": ["ISpoke"],
         "state_vars": [],
         "functions": [_fn("act", "act(uint256)", visibility="external",
                            calls=[{"callee_contract": "IHub", "callee_sig": "settle(address)",
                                    "call_type": "external", "line": 3}])]},
        {"name": "Router", "kind": "contract", "file": "Router.sol", "inheritance": [],
         "state_vars": [],
         "functions": [_fn("route", "route(uint256)", visibility="external",
                            calls=[{"callee_contract": "ISpoke", "callee_sig": "act(uint256)",
                                    "call_type": "external", "line": 4}])]},
    ],
    "detectors": [],
}

# Make Hub.settle actually call its internal sink so the BFS has an internal target.
EXPORT["contracts"][2]["functions"][0]["calls"] = [
    {"callee_contract": "Hub", "callee_sig": "_applyLoss(address)",
     "call_type": "internal", "line": 5}]


def main() -> int:
    print("smoke_reachability: static call-graph edge resolution (task 1A)")
    with tempfile.TemporaryDirectory() as d:
        db = Path(d) / "index.db"
        store = Store(db)
        load_export(store, EXPORT, repo_ref="fixture", target_dir=Path(d))
        store.commit()
        ci = CodeIndex(db)

        # 1. the interface-typed call now resolves to the CONCRETE Hub.settle
        callers_settle = ci.query("callers", {"contract": "Hub", "name": "settle"})
        caller_keys = {f"{r['contract']}.{r['name']}" for r in callers_settle}
        assert "Spoke.act" in caller_keys, f"Spoke.act should reach Hub.settle, got {caller_keys}"
        print(f"  [OK ] interface call Spoke→IHub resolves to Hub.settle "
              f"(callers={sorted(caller_keys)})")

        # 2. Spoke.act is reachable from Router via the ISpoke interface
        callers_act = ci.query("callers", {"contract": "Spoke", "name": "act"})
        assert any(r["name"] == "route" for r in callers_act), \
            f"Router.route should reach Spoke.act, got {callers_act}"
        print("  [OK ] interface call Router→ISpoke resolves to Spoke.act")

        # 3. the reachability BFS climbs Hub._applyLoss → ... → Router.route (multi-hop)
        reach = _reachable_entrypoints(ci, [("Hub", "_applyLoss")])
        eps = {f"{e['contract']}.{e['name']}" for e in reach}
        assert eps, "no reachable entrypoint for Hub._applyLoss (edge resolution failed)"
        # Router.route (the true external entrypoint) must be among them
        assert "Router.route" in eps or "Hub.settle" in eps, \
            f"expected multi-hop entrypoint to Hub._applyLoss, got {eps}"
        path = next((e["path"] for e in reach if e["contract"] == "Router"), None)
        print(f"  [OK ] reachability BFS: Hub._applyLoss reachable from {sorted(eps)}")
        if path:
            print(f"         resolved path: {path}")
        ci.close()

    # 4. TASK 1B — dynamic on-fork fallback upgrades a still-dark dossier from a trace
    from chainreaper.recon.dynamic_reach import (
        augment_reachability_dynamic,
        entrypoint_probes_from_dossiers,
    )

    class _Dossier:  # minimal dossier duck-type
        def __init__(self, targets, reach):
            self.target_functions = targets
            self.reachable_entrypoints = reach
            self.reach_note = "no resolved entrypoint path"

    dark = _Dossier(
        targets=[{"contract": "Vault", "name": "_settle", "signature": "_settle()"}],
        reach=[])  # static gave nothing
    dossiers = {"T-1": dark}
    deployed = {"Router": "0xRouter", "Vault": "0xVault"}
    # the dossier also carries the deployed Router entrypoint as a known target so a
    # probe is generated for it
    dark.target_functions.append({"contract": "Router", "name": "exec",
                                  "signature": "exec(uint256)"})
    probes = entrypoint_probes_from_dossiers(dossiers, deployed)
    assert any(p["contract"] == "Router" for p in probes), probes

    # stub tracer: calling Router.exec on the fork executes Router.exec → Vault._settle
    def stub_tracer(rpc, frm, to, sig):
        if to == "0xRouter":
            return [("Router", "exec"), ("Vault", "_settle")]
        return []

    newly = augment_reachability_dynamic(dossiers, probes, rpc_url="http://fork",
                                         tracer=stub_tracer)
    assert newly == 1, f"expected the dark dossier to resolve, got {newly}"
    assert dark.reachable_entrypoints, "dossier still dark after fork trace"
    assert dark.reachable_entrypoints[0]["contract"] == "Router"
    assert "fork-traced" in dark.reachable_entrypoints[0]["path"]
    # no-op safety: no rpc / no probes → 0, never raises
    assert augment_reachability_dynamic({"x": _Dossier([], [])}, [],
                                        rpc_url=None, tracer=stub_tracer) == 0
    print("  [OK ] dynamic (fork-trace) fallback resolves a still-dark task "
          f"({dark.reachable_entrypoints[0]['path']})")

    print("smoke_reachability: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
