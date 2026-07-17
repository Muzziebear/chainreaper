"""S1 self-test (IMPL-NOTES §4): run the documented queries against a built index.

Usage:  python tests/smoke_s1.py runs/<run_id>/index/index.db
Defaults to the most recent run if no path is given.
"""

from __future__ import annotations

import sys
from pathlib import Path

from chainreaper.tools.code_index import CodeIndex


def _latest_db() -> Path:
    runs = sorted(Path("runs").glob("*/index/index.db"))
    if not runs:
        raise SystemExit("no index.db found under runs/*/index/")
    # This self-test asserts GMX-specific structure (MultichainGmRouter / create*), so
    # prefer the canonical GMX fixture; only fall back to glob if it's absent (don't let
    # an unrelated run dir — beefy/woofi/etc. — shadow it).
    for pref in ("test-merged", "gmx-opus", "gmx-opus2"):
        cand = Path("runs") / pref / "index" / "index.db"
        if cand.exists():
            return cand
    return runs[-1]


def main() -> int:
    db = Path(sys.argv[1]) if len(sys.argv) > 1 else _latest_db()
    print(f"== index: {db} ==")
    idx = CodeIndex(db)

    def show(title, rows, fields=("contract", "name", "signature")):
        print(f"\n## {title}  ({len(rows)} rows)")
        for r in rows[:12]:
            print("   ", {k: r.get(k) for k in fields if k in r})

    # 1) entrypoints of the multichain GM router → createDeposit/Withdrawal/Shift
    ep = idx.query("entrypoints", {"contract": "MultichainGmRouter"})
    show("entrypoints {contract: MultichainGmRouter}", ep)
    names = {r["name"] for r in ep}
    assert {"createDeposit", "createWithdrawal", "createShift"} <= names, \
        f"expected create* entrypoints, got {sorted(names)}"

    # 2) callers of WithdrawalHandler.createWithdrawal → the routers (incl. via interface)
    callers = idx.query("callers", {"contract": "WithdrawalHandler", "name": "createWithdrawal"})
    show("callers {WithdrawalHandler.createWithdrawal}", callers)
    caller_contracts = {r["contract"] for r in callers}
    assert "ExchangeRouter" in caller_contracts, \
        f"expected ExchangeRouter among callers, got {sorted(caller_contracts)}"

    # 3) writers of DataStore.uintValues (sanity that var_access populated)
    writers = idx.query("writers", {"contract": "DataStore", "var": "uintValues"})
    show("writers {DataStore.uintValues}", writers)
    assert writers, "expected at least one writer of DataStore.uintValues"

    # 4) global entrypoint count + a couple of structural queries
    all_ep = idx.query("entrypoints", {})
    print(f"\n## total entrypoints across repo: {len(all_ep)}")
    inh = idx.query("inheritance", {"contract": "MultichainGmRouter"})
    show("inheritance {MultichainGmRouter}", inh, fields=("base_name", "base_contract_id"))
    sinks = idx.query("external_calls_in", {"contract": "WithdrawalHandler", "name": "createWithdrawal"})
    show("external_calls_in {WithdrawalHandler.createWithdrawal}", sinks,
         fields=("kind", "detail", "line"))

    idx.close()
    print("\nSMOKE OK — S1 self-test assertions passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
