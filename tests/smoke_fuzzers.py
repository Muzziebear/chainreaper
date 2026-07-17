"""Fuzzing-layer self-test (T1.1 — install the fuzzing layer).

Proves the three stateful/economic fuzzers the harness routes invariants to
(Medusa, Echidna, ItyFuzz) are installed AND actually catch a *deliberately
failing* invariant — the positive control the roadmap (memory
``chainreaper-testing-roadmap``) calls for. Each is exercised with the kind of
property it natively detects:

  * **Echidna** — a ``echidna_*`` boolean property that a fuzzed call sequence
    falsifies (property mode);
  * **Medusa**   — a ``property_*`` boolean property that fails (property mode);
  * **ItyFuzz**  — an *arbitrary external call* (attacker controls target +
    calldata): ItyFuzz's objective model is economic/native detectors, not
    arbitrary booleans, so its positive control is one of those detectors.

Resolution goes through ``runtime.exec.augmented_env`` (the SAME PATH logic the
harness uses), so a pass here means S2/S4 can find the binaries too. No tokens —
fuzzing campaigns cost compute, not model calls. Each campaign is capped to a few
seconds; all three find their bug essentially immediately.

Usage:  python tests/smoke_fuzzers.py
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from chainreaper.runtime.exec import augmented_env

ENV = augmented_env()
PATH = ENV.get("PATH", "")


def _which(tool: str) -> str | None:
    return shutil.which(tool, path=PATH)


def _run(cmd: list[str], cwd: str, timeout: int) -> str:
    """Run a fuzzer; return combined stdout+stderr. A timeout is fine (we cap the
    campaign and grep the streamed output for the violation it already printed)."""
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                           timeout=timeout, env=ENV)
        return (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired as exc:
        return (exc.stdout or "") + (exc.stderr or "") if isinstance(exc.stdout, str) \
            else ((exc.stdout or b"").decode("utf-8", "replace")
                  + (exc.stderr or b"").decode("utf-8", "replace"))


_BROKEN_SOL = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// A deliberately breakable invariant: counter must stay < 5, but inc() lets a
// fuzzed call sequence push it to 5 — the positive control for property fuzzers.
contract Broken {
    uint256 public counter;
    function inc() public { counter += 1; }
    function echidna_counter_below_5() public view returns (bool) { return counter < 5; }
    function property_counter_below_5() public view returns (bool) { return counter < 5; }
}
"""

_ARB_SOL = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Arbitrary external call — attacker controls target + calldata. This is one of
// ItyFuzz's native objective detectors (its model is economic/native, not
// arbitrary booleans), so it is the positive control for ItyFuzz.
contract Arb {
    function exec(address target, bytes calldata data) public {
        (bool ok, ) = target.call(data);
        require(ok);
    }
}
"""


def check_echidna() -> bool:
    if not _which("echidna"):
        print("  [MISS] echidna not on PATH (T1.1 install incomplete)")
        return False
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "Broken.sol").write_text(_BROKEN_SOL)
        out = _run(["echidna", "Broken.sol", "--contract", "Broken",
                    "--test-limit", "20000"], cwd=d, timeout=90)
    ok = "falsified" in out.lower() or "echidna_counter_below_5: failed" in out.lower()
    print(f"  [{'OK ' if ok else 'FAIL'}] echidna falsifies a broken property")
    if not ok:
        print("    (no 'falsified' in output — last lines:)\n    "
              + "\n    ".join(out.strip().splitlines()[-6:]))
    return ok


def check_medusa() -> bool:
    if not _which("medusa"):
        print("  [MISS] medusa not on PATH (T1.1 install incomplete)")
        return False
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "Broken.sol").write_text(_BROKEN_SOL)
        init = _run(["medusa", "init"], cwd=d, timeout=60)
        cfg = Path(d) / "medusa.json"
        if not cfg.exists():
            print(f"  [FAIL] medusa init produced no config\n    {init.strip()[-300:]}")
            return False
        import json
        c = json.loads(cfg.read_text())
        c["fuzzing"]["testLimit"] = 20000
        c["fuzzing"]["targetContracts"] = ["Broken"]
        c["compilation"]["target"] = "Broken.sol"
        cfg.write_text(json.dumps(c, indent=2))
        out = _run(["medusa", "fuzz"], cwd=d, timeout=120)
    ok = "test(s) failed" in out.lower() and "[failed]" in out.lower()
    print(f"  [{'OK ' if ok else 'FAIL'}] medusa fails a broken property")
    if not ok:
        print("    (no '[FAILED]' in output — last lines:)\n    "
              + "\n    ".join(out.strip().splitlines()[-6:]))
    return ok


def check_ityfuzz() -> bool:
    if not _which("ityfuzz"):
        print("  [MISS] ityfuzz not on PATH (T1.1 install incomplete)")
        return False
    solc = _which("solc")
    if not solc:
        print("  [MISS] solc not on PATH — cannot build the ItyFuzz target")
        return False
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "Arb.sol").write_text(_ARB_SOL)
        build = _run([solc, "Arb.sol", "--bin", "--abi", "--overwrite", "-o", "build"],
                     cwd=d, timeout=60)
        if not (Path(d) / "build" / "Arb.bin").exists():
            print(f"  [FAIL] solc did not build Arb.sol\n    {build.strip()[-300:]}")
            return False
        work = Path(d) / "work"
        out = _run(["ityfuzz", "evm", "-t", "./build/*", "-d", "all",
                    "--work-dir", str(work)], cwd=d, timeout=30)
        vuln_dir = work / "vulnerabilities"
        artifact = vuln_dir.is_dir() and any(vuln_dir.iterdir())
    ok = "found vulnerabilities" in out.lower() or "arbitrary call" in out.lower() or artifact
    print(f"  [{'OK ' if ok else 'FAIL'}] ityfuzz detects an arbitrary-call bug")
    if not ok:
        print("    (no vulnerability reported — last lines:)\n    "
              + "\n    ".join(out.strip().splitlines()[-6:]))
    return ok


def main() -> int:
    print("smoke_fuzzers: stateful/economic fuzzing layer (T1.1)")
    results = {
        "echidna": check_echidna(),
        "medusa": check_medusa(),
        "ityfuzz": check_ityfuzz(),
    }
    if all(results.values()):
        print("smoke_fuzzers: PASS — all three fuzzers installed and catch a broken invariant")
        return 0
    missing = [k for k, v in results.items() if not v]
    print(f"smoke_fuzzers: FAIL — {missing}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
