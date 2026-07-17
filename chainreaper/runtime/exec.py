"""Tool-invocation seam + per-task sandbox (IMPL-NOTES §2 / spec §10).

S1/S2 run analyzers on the host (read-only static analysis, no untrusted code) via
``run_tool``. **S4 Hunt** is where exploit PoCs run, so the sandbox lives here:

  * ``run_tool(cmd, …, backend=…)`` — the host/docker seam every concrete tool call
    goes through (so S4 can swap the backend without touching callers).
  * ``Sandbox`` — one writable workspace per Hunter task, scaffolded as a Foundry
    project (foundry.toml + remappings + ``forge-std`` wired in) into which the
    hunter writes + compiles + runs its PoC. ``exec_backend: host`` runs the
    toolchain directly off an augmented PATH (``~/.foundry/bin`` etc., like the S1
    index build); ``docker`` is the spec §10 ``chainreaper-sandbox`` image — the seam
    is in place and config-driven, the implementation lands when the image is built.

Keeping the workspace + toolchain knowledge here means the Hunter agent (which runs
the toolchain itself via Bash inside its ``claude -p`` session) and any deterministic
tool call the stage makes both go through one place.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

# Tool dirs added to PATH so the sandbox toolchain resolves under a non-login shell
# (mirrors ``index/build.py``: forge/cast/anvil live in ~/.foundry/bin, slither in
# the py-utils venv, etc.).
_TOOL_PATH_DIRS = [
    "/usr/local/py-utils/bin",
    str(Path.home() / ".cargo" / "bin"),
    str(Path.home() / ".foundry" / "bin"),
    str(Path.home() / ".bifrost" / "bin"),
    str(Path.home() / ".fuzzers" / "bin"),  # medusa/echidna/ityfuzz release binaries (T1.1)
]

# The sandbox toolchain a Hunter may invoke (basenames). Availability is resolved
# per-host by ``Sandbox.available_tools``; the agent guard allow-lists these.
DEFAULT_TOOLCHAIN = [
    "forge", "cast", "anvil", "chisel", "solc",
    "slither", "medusa", "echidna", "ityfuzz", "halmos",
]

# Each ``models.InvariantTool`` value → the host binary that actually CHECKS an
# invariant assigned to it (T1.2). The recon agent may only assign an invariant to
# a tool whose binary is installed; ``available_invariant_tools`` resolves this
# against the augmented PATH so S2's routing matches what S4 can really run.
# ``properties`` (crytic property tests) is driven by echidna, so it shares that
# binary. ``ityfuzz`` is intentionally absent: it is a hunt-time bytecode/economic
# fuzzer (T1.3/T2.2), not an invariant-property checker the recon assigns.
_INVARIANT_TOOL_BIN = {
    "foundry": "forge",
    "medusa": "medusa",
    "echidna": "echidna",
    "halmos": "halmos",
    "certora": "certoraRun",
    "wake": "wake",
    "slither": "slither",
    "properties": "echidna",
}


def available_invariant_tools(base: dict | None = None) -> list[str]:
    """The subset of ``models.InvariantTool`` values whose checker binary is
    installed on this host (resolved through the augmented PATH). This is the menu
    the S2 recon agent may assign ``invariant.tool`` from — so an invariant is only
    ever routed to a tool S4 can actually run (T1.2)."""
    env_path = augmented_env(base).get("PATH", "")
    out: list[str] = []
    for tool, binary in _INVARIANT_TOOL_BIN.items():
        if shutil.which(binary, path=env_path):
            out.append(tool)
    return out


def augmented_env(base: dict | None = None) -> dict[str, str]:
    """A copy of the environment with the toolchain dirs (and the active node)
    prepended to PATH, so ``forge``/``slither``/… resolve in a subprocess."""
    env = dict(base if base is not None else os.environ)
    extra = [d for d in _TOOL_PATH_DIRS if Path(d).is_dir()]
    node = shutil.which("node")
    if node:
        extra.append(str(Path(node).parent))
    if extra:
        env["PATH"] = os.pathsep.join(extra + [env.get("PATH", "")])
    return env


def run_tool(
    cmd: list[str],
    *,
    cwd: str | Path | None = None,
    timeout: int = 1800,
    backend: str = "host",
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess:
    """Run one tool command through the configured execution backend."""
    if backend == "host":
        return subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env if env is not None else augmented_env(),
        )
    if backend == "docker":  # spec §10 — chainreaper-sandbox image (pending)
        raise NotImplementedError(
            "exec_backend 'docker' (chainreaper-sandbox image) is not built yet; "
            "set runtime.exec_backend: host for now."
        )
    raise NotImplementedError(f"unknown exec_backend {backend!r} (use 'host' or 'docker')")


# --------------------------------------------------------------------------- #
# Foundry project scaffold                                                     #
# --------------------------------------------------------------------------- #
def _foundry_toml(rpc: dict) -> str:
    # A lean profile: optimizer on, viaIR off (fast — a fork PoC imports interfaces +
    # forge-std, not the whole protocol source). RPC endpoints read from the env so a
    # URL never lands in the workspace; the stage exports them before the hunt.
    lines = [
        "[profile.default]",
        'src = "src"',
        'test = "test"',
        'script = "script"',
        'out = "out"',
        'libs = ["lib"]',
        "optimizer = true",
        "optimizer_runs = 200",
        "via_ir = false",
        'evm_version = "cancun"',
        "",
        "[rpc_endpoints]",
    ]
    endpoints = rpc.get("endpoints") or {
        "arbitrum": "${ARBITRUM_RPC_URL}",
        "mainnet": "${MAINNET_RPC_URL}",
        "avalanche": "${AVALANCHE_RPC_URL}",
    }
    for name, url in endpoints.items():
        lines.append(f'{name} = "{url}"')
    return "\n".join(lines) + "\n"


# A minimal, self-contained forge-std shim written into the workspace only when no
# real forge-std is found on the host — enough for an interface-based fork PoC to
# compile + run (cheatcodes + assertions + console2) without network access.
_FORGE_STD_SHIM = r"""// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

interface Vm {
    function createSelectFork(string calldata urlOrAlias) external returns (uint256);
    function createSelectFork(string calldata urlOrAlias, uint256 block) external returns (uint256);
    function createFork(string calldata urlOrAlias) external returns (uint256);
    function selectFork(uint256 forkId) external;
    function rollFork(uint256 block) external;
    function prank(address) external;
    function startPrank(address) external;
    function stopPrank() external;
    function deal(address to, uint256 give) external;
    function deal(address token, address to, uint256 give) external;
    function warp(uint256) external;
    function roll(uint256) external;
    function label(address, string calldata) external;
    function expectRevert() external;
    function expectRevert(bytes calldata) external;
    function envOr(string calldata name, string calldata defaultValue) external view returns (string memory);
    function addr(uint256 privateKey) external pure returns (address);
    function sign(uint256 privateKey, bytes32 digest) external pure returns (uint8, bytes32, bytes32);
}

library console2 {
    address constant CONSOLE = 0x000000000000000000636F6e736F6c652e6c6f67;
    function _send(bytes memory payload) private view {
        address c = CONSOLE;
        assembly { pop(staticcall(gas(), c, add(payload, 32), mload(payload), 0, 0)) }
    }
    function log(string memory p0) internal view { _send(abi.encodeWithSignature("log(string)", p0)); }
    function log(string memory p0, uint256 p1) internal view { _send(abi.encodeWithSignature("log(string,uint256)", p0, p1)); }
    function log(string memory p0, address p1) internal view { _send(abi.encodeWithSignature("log(string,address)", p0, p1)); }
    function log(string memory p0, bool p1) internal view { _send(abi.encodeWithSignature("log(string,bool)", p0, p1)); }
    function log(uint256 p0) internal view { _send(abi.encodeWithSignature("log(uint256)", p0)); }
    function log(address p0) internal view { _send(abi.encodeWithSignature("log(address)", p0)); }
}

abstract contract Test {
    Vm internal constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);
    bool public IS_TEST = true;
    bool private _failed;

    function failed() public view returns (bool) { return _failed; }
    function fail() internal { _failed = true; }

    function assertTrue(bool c) internal { if (!c) { emit log("assertion failed"); fail(); } }
    function assertTrue(bool c, string memory err) internal { if (!c) { emit log_named_string("error", err); fail(); } }
    function assertEq(uint256 a, uint256 b) internal { if (a != b) { emit log("assertEq(uint) failed"); fail(); } }
    function assertEq(address a, address b) internal { if (a != b) { emit log("assertEq(address) failed"); fail(); } }
    function assertGt(uint256 a, uint256 b) internal { if (!(a > b)) { emit log("assertGt failed"); fail(); } }
    function assertGe(uint256 a, uint256 b) internal { if (!(a >= b)) { emit log("assertGe failed"); fail(); } }
    function assertLt(uint256 a, uint256 b) internal { if (!(a < b)) { emit log("assertLt failed"); fail(); } }

    event log(string);
    event log_named_string(string key, string val);
    event log_named_uint(string key, uint256 val);
    event log_named_address(string key, address val);
}
"""


@dataclass
class Sandbox:
    """A per-task Foundry sandbox. ``run_dir`` is the run root; each task gets its
    own writable workspace under ``run_dir/sandbox/<task_id>``."""

    run_dir: Path
    backend: str = "host"
    rpc: dict = field(default_factory=dict)
    toolchain: list[str] = field(default_factory=lambda: list(DEFAULT_TOOLCHAIN))

    def __post_init__(self) -> None:
        # Absolute: the hunter's sandbox dir becomes its CHAINREAPER_SCRATCH + cwd, and
        # the guard hook (running with cwd=sandbox) resolves the scratch path to decide
        # Write/Edit scope — a relative path would mis-resolve and deny legit writes.
        self.run_dir = Path(self.run_dir).resolve()

    # -- layout ------------------------------------------------------------- #
    def workspace(self, task_id: str) -> Path:
        return self.run_dir / "sandbox" / _safe(task_id)

    def env(self) -> dict[str, str]:
        """Augmented environment for any deterministic tool call the stage makes."""
        return augmented_env()

    # -- provisioning ------------------------------------------------------- #
    def prepare(self, task_id: str, *, repo_root: str | Path | None = None,
                forge_std_src: str | Path | None = None,
                campaign_files: dict[str, str] | None = None) -> Path:
        """Create + scaffold this task's Foundry workspace. Idempotent.

        ``campaign_files`` (workspace-relative path → content), when given, writes the
        Chimera-style layered-fuzzing scaffold (handler + properties + symbolic spec +
        medusa/echidna configs + runbook) generated by ``runtime.campaign`` from the
        task's bound invariants, so the Hunter starts the campaign from a real,
        invariant-keyed handler (T1.3). Existing files are NOT clobbered (idempotent /
        the hunter may have already edited them)."""
        if self.backend != "host":
            raise NotImplementedError(
                f"Sandbox.prepare for exec_backend {self.backend!r} is not built yet "
                "(spec §10 chainreaper-sandbox image); use host.")
        ws = self.workspace(task_id)
        for sub in ("src", "test", "script", "lib"):
            (ws / sub).mkdir(parents=True, exist_ok=True)
        (ws / "foundry.toml").write_text(_foundry_toml(self.rpc))
        (ws / "remappings.txt").write_text(
            "forge-std/=lib/forge-std/src/\n")
        self._wire_forge_std(ws, repo_root=repo_root, forge_std_src=forge_std_src)
        if campaign_files:
            for rel, content in campaign_files.items():
                dst = ws / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                if not dst.exists():  # don't overwrite hunter edits on a re-prepare
                    dst.write_text(content)
        return ws

    def _wire_forge_std(self, ws: Path, *, repo_root, forge_std_src) -> None:
        dst = ws / "lib" / "forge-std"
        if (dst / "src" / "Test.sol").exists() or (dst.is_symlink() and dst.exists()):
            return
        src = _find_forge_std(forge_std_src, repo_root)
        if src is not None:
            if dst.exists() or dst.is_symlink():
                if dst.is_symlink():
                    dst.unlink()
                else:
                    shutil.rmtree(dst)
            try:
                dst.symlink_to(src, target_is_directory=True)
                return
            except OSError:
                pass  # fall through to the vendored shim
        # No real forge-std available — vendor the minimal shim.
        (dst / "src").mkdir(parents=True, exist_ok=True)
        (dst / "src" / "Test.sol").write_text(_FORGE_STD_SHIM)

    # -- introspection ------------------------------------------------------ #
    def available_tools(self) -> dict[str, bool]:
        env_path = self.env().get("PATH", "")
        return {t: bool(shutil.which(t, path=env_path)) for t in self.toolchain}

    def tools_doc(self) -> str:
        """The TOOLS block injected into the Hunter system prompt (what it may run
        in its sandbox + how to persist findings)."""
        avail = self.available_tools()
        present = [t for t, ok in avail.items() if ok]
        missing = [t for t, ok in avail.items() if not ok]
        lines = [
            "You run inside a writable **Foundry sandbox** (your scratch dir IS the "
            "project root: it has foundry.toml, remappings.txt, src/, test/, "
            "script/, forge-std wired in under lib/, and a pre-generated "
            "**`campaign/`** Chimera handler + `CAMPAIGN.md` keyed to your bound "
            "invariants). You build, run, and iterate a PoC there. Tools (via Bash):",
            "- **forge** — `forge build`, `forge test --match-test <name> -vvv`. Your "
            "PRIMARY PoC vehicle. Prefer a **mainnet-fork** test "
            "(`vm.createSelectFork(\"arbitrum\")`) that calls a real public "
            "entrypoint and asserts $-impact.",
            "- **cast** / **anvil** — chain queries / a local fork node.",
            "- **medusa** / **echidna** — STATEFUL/property fuzzers. Wire "
            "`test/campaign/Handler.sol` to the real system, then `medusa fuzz` (deep "
            "stateful, config `medusa.json`) and `echidna test/campaign/Handler.sol "
            "--contract Handler --config echidna.yaml` (cross-check). A failing "
            "`invariant_*` prints the shrunk call sequence = your PoC seed.",
            "- **halmos** — SYMBOLIC proof over `campaign/Symbolic.t.sol` "
            "(`halmos --function check_`): proves a property or yields an all-paths "
            "counterexample.",
            "- **slither** — static detectors, to confirm/refute a structural lead. "
            "Run the LAYERS IN ORDER (forge smoke → medusa → echidna → halmos), then "
            "turn any counterexample into the fork PoC (see CAMPAIGN.md).",
            "- **Read / Grep / Glob** — read the in-scope target source directly "
            "(absolute paths under the repo root given in your TASK).",
            "- **Write / Edit** — ONLY inside your sandbox dir (PoC files + emit JSON).",
            "- **Bash, restricted** — the toolchain above + chainreaper save-scripts + "
            "benign shell utilities. No network (curl/wget/git/npm), no rm/sudo, no "
            "command substitution.",
            f"Toolchain available on this host: {', '.join(present) or 'none'}"
            + (f" (missing: {', '.join(missing)})." if missing else "."),
            "You persist results ONLY via `chainreaper hunt-create-finding` (one or "
            "more Findings, each with a runnable PoC) and the REQUIRED "
            "`chainreaper hunt-finish` (your outcome record) — see REQUIRED OUTPUT / "
            "OUTPUT MECHANICS.",
        ]
        return "\n".join(lines)

    def describe(self) -> str:
        avail = self.available_tools()
        return (f"sandbox backend={self.backend} · tools "
                + ", ".join(f"{t}{'' if ok else '✗'}" for t, ok in avail.items()))


# --------------------------------------------------------------------------- #
# helpers                                                                      #
# --------------------------------------------------------------------------- #
def _safe(task_id: str) -> str:
    return "".join(c if (c.isalnum() or c in "-_.") else "_" for c in task_id) or "task"


def _find_forge_std(explicit, repo_root) -> Path | None:
    """Locate a real forge-std source dir (so PoCs get the full library), or None."""
    cands: list[Path] = []
    if explicit:
        cands.append(Path(explicit))
    if repo_root:
        rr = Path(repo_root)
        cands += [rr / "lib" / "forge-std", rr.parent / "lib" / "forge-std"]
    for c in cands:
        if (c / "src" / "Test.sol").exists():
            return c.resolve()
    return None
