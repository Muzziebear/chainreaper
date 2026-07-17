"""Smoke: Fix A — campaign scaffold auto-inherits the repo's own test fixture.

Detects an abstract test base whose setUp() deploys the system, and generates a
Handler that inherits it (super.setUp() + override) instead of a blank stub — while
staying backward-compatible (no repo_root / no fixture → unchanged blank stub)."""

import tempfile
from pathlib import Path

from chainreaper.runtime.campaign import build_campaign, detect_test_fixture

FIXTURE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {Test} from "forge-std/Test.sol";
contract MockToken {}
contract Widget {}
abstract contract FooBaseTest is Test {
  Widget public widget;
  MockToken public tok;
  function setUp() public virtual {
    tok = new MockToken();
    widget = new Widget();
  }
  function _seedActor(uint256 x) internal {}
  function _swapHelper(bool z) internal {}
}
"""


class _Task:
    task_id = "T-X"
    vuln_class = "logic_error"
    attack_path = []
    contracts = ["Widget", "MockToken"]  # names that would clash if emitted as slots


class _Dossier:
    invariants = [{"id": "INV-1", "statement": "solvent", "hooks": ["swap"], "tool": "medusa"}]
    reachable_entrypoints = [{"name": "swap"}, {"name": "addLiquidity"}]
    target_functions = []


def _fails(msg):
    print("smoke_campaign_fixture: FAIL —", msg)
    raise SystemExit(1)


def main():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "test").mkdir()
        (root / "test" / "FooBase.t.sol").write_text(FIXTURE)
        # a vendored lib copy must be ignored (not chosen as the fixture)
        (root / "lib").mkdir()
        (root / "lib" / "junk.t.sol").write_text(FIXTURE.replace("FooBaseTest", "LibBase"))

        # 1. detection
        fx = detect_test_fixture(str(root), in_scope=["Widget"])
        assert fx, "fixture not detected"
        assert fx["name"] == "FooBaseTest", f"wrong fixture: {fx['name']}"
        assert fx["import_path"] == "../FooBase.t.sol", f"bad import path: {fx['import_path']}"
        assert "Widget widget" in fx["members"], fx["members"]
        assert "_swapHelper" in fx["helpers"], fx["helpers"]
        print("  [OK ] detects abstract fixture + import path + members/helpers (skips lib/)")

        # 2. wired handler
        h = build_campaign(_Task(), _Dossier(), repo_root=str(root))["test/campaign/Handler.sol"]
        assert "import {FooBaseTest} from \"../FooBase.t.sol\";" in h, "missing fixture import"
        assert "contract Handler is FooBaseTest, Properties {" in h, "missing inheritance"
        assert "super.setUp();" in h, "missing super.setUp()"
        assert "function setUp() public virtual override {" in h, "missing override on setUp"
        # the clash-prone econ slots must NOT be emitted when a fixture is inherited
        assert "address internal Widget;" not in h, "clashing econ slot emitted"
        print("  [OK ] Handler inherits fixture, super.setUp() + override, no type-name clash")

        # 3. backward compat — no repo_root → unchanged blank stub
        h0 = build_campaign(_Task(), _Dossier())["test/campaign/Handler.sol"]
        assert "contract Handler is Properties {" in h0, "backward-compat inheritance changed"
        assert "super.setUp" not in h0, "backward-compat setUp changed"
        assert "FooBaseTest" not in h0, "leaked fixture without repo_root"
        print("  [OK ] no repo_root → unchanged blank-stub scaffold (backward compatible)")

        # 4. no test/ dir → no fixture
        with tempfile.TemporaryDirectory() as d2:
            assert detect_test_fixture(d2) is None, "false-positive on empty repo"
        print("  [OK ] repo with no test fixture → None (safe no-op)")

    print("smoke_campaign_fixture: PASS")


if __name__ == "__main__":
    main()
