"""Stateful cross-contract attacker-primitive self-test (TASK 2, compute not tokens).

Two halves:

  1. GENERATION — ``build_campaign`` for a cross-contract task now emits the first-class
     ATTACKER primitives (``handle_donate`` / reentrant ``fallback`` / ``handle_composeAB``)
     and a DEEPER medusa config (longer ``callSequenceLength`` + bigger ``testLimit``),
     and routes multi_actor/economic/attacker-class tasks to that composed handler.

  2. POSITIVE CONTROL — a genuine 2-contract, multi-step, ATTACKER-REACHABLE bug
     (``tests/fixtures/StatefulAttack.sol``: donation-then-borrow with unescrowed
     collateral, no oracle/admin) is FOUND by a fuzzer composing the attacker
     primitives across SharePool + Lender — the exact class the harness kept missing.
     Echidna falsifies the attacker-no-profit property in ~2s.

Usage:  python tests/smoke_stateful_attack.py
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from chainreaper.runtime.campaign import build_campaign
from chainreaper.runtime.exec import augmented_env

ENV = augmented_env()
FIXTURE = Path(__file__).parent / "fixtures" / "StatefulAttack.sol"


class _Task:
    """Minimal HunterTask-like duck type for a cross-contract donation task."""
    def __init__(self, **kw):
        self.task_id = kw.get("task_id", "T-X")
        self.vuln_class = kw.get("vuln_class", "first_depositor_inflation")
        self.scope_hint = kw.get("scope_hint", "")
        self.contracts = kw.get("contracts", ["SharePool", "Lender"])
        self.attack_path = kw.get("attack_path", ["SharePool.deposit", "Lender.borrow"])
        self.multi_actor = kw.get("multi_actor", False)
        self.long_horizon = False
        self.dep_target = ""
        self.dep_assumptions = []


def check_generation() -> bool:
    ok = True
    # cross-contract task → attacker primitives present + deeper campaign
    files = build_campaign(_Task(), None)
    handler = files["test/campaign/Handler.sol"]
    import json
    medusa = json.loads(files["medusa.json"])
    runbook = files["CAMPAIGN.md"]

    for needle in ("handle_donate", "handle_armReentrancy", "handle_composeAB",
                   "fallback() external", "ATTACKER PRIMITIVES"):
        if needle not in handler:
            print(f"  [FAIL] generated handler missing attacker primitive: {needle}")
            ok = False
    seq = medusa["fuzzing"]["callSequenceLength"]
    if seq < 300:
        print(f"  [FAIL] cross-contract task should deepen callSequenceLength, got {seq}")
        ok = False
    if "ATTACKER PRIMITIVES" not in runbook or "attacker_reachable" not in runbook:
        print("  [FAIL] runbook missing attacker-primitive / adversary-model guidance")
        ok = False
    if ok:
        print(f"  [OK ] cross-contract task → attacker primitives + deep campaign "
              f"(callSequenceLength={seq})")

    # a plain single-contract non-economic task should NOT get the attacker block
    plain = _Task(vuln_class="access_control", contracts=["Solo"], attack_path=[])
    ph = build_campaign(plain, None)["test/campaign/Handler.sol"]
    if "ATTACKER PRIMITIVES" in ph:
        print("  [FAIL] plain access_control task wrongly got the attacker block")
        ok = False
    else:
        print("  [OK ] plain single-contract task stays lean (no attacker block)")

    # a multi_actor task also routes to the composed/attacker campaign
    ma = build_campaign(_Task(vuln_class="access_control", multi_actor=True,
                              contracts=["Solo"], attack_path=[]), None)
    if "handle_composeAB" not in ma["test/campaign/Handler.sol"]:
        print("  [FAIL] multi_actor task not routed to the composed attacker campaign")
        ok = False
    else:
        print("  [OK ] multi_actor task routed to the composed attacker campaign")
    return ok


def check_positive_control() -> bool:
    echidna = shutil.which("echidna", path=ENV.get("PATH", ""))
    if not echidna:
        print("  [SKIP] echidna not on PATH — cannot run the 2-contract exploit control")
        return True  # not a failure of the code, just no fuzzer
    with tempfile.TemporaryDirectory() as d:
        shutil.copy2(FIXTURE, Path(d) / "StatefulAttack.sol")
        try:
            p = subprocess.run(
                [echidna, "StatefulAttack.sol", "--contract", "StatefulAttackHandler",
                 "--test-limit", "40000"],
                cwd=d, capture_output=True, text=True, timeout=180, env=ENV)
            out = (p.stdout or "") + (p.stderr or "")
        except subprocess.TimeoutExpired as exc:
            out = (exc.stdout or "") if isinstance(exc.stdout, str) else \
                (exc.stdout or b"").decode("utf-8", "replace")
    falsified = "falsified" in out.lower() or "no_profit: failed" in out.lower()
    composed = "handle_composeAB" in out or "handle_donate" in out
    print(f"  [{'OK ' if falsified else 'FAIL'}] fuzzer finds the 2-contract "
          f"donation-then-borrow bug (attacker_reachable)"
          + (" via the composed attacker primitive" if composed else ""))
    if not falsified:
        print("    (no falsification — last lines:)\n    "
              + "\n    ".join(out.strip().splitlines()[-6:]))
    return falsified


def main() -> int:
    print("smoke_stateful_attack: cross-contract attacker primitives (TASK 2)")
    gen = check_generation()
    pos = check_positive_control()
    if gen and pos:
        print("smoke_stateful_attack: PASS")
        return 0
    print("smoke_stateful_attack: FAIL")
    return 1


if __name__ == "__main__":
    sys.exit(main())
