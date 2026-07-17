"""DeFiHackLabs case runner (T3.2).

DeFiHackLabs PoCs depend on the repo's shared helpers (``interface.sol`` /
``basetest.sol`` / ``tokenhelper.sol``) + ``forge-std`` and fork via a named alias
(``vm.createSelectFork("polygon", <block>)``) resolved from ``foundry.toml``. So a
real replay clones the repo once (cached), then builds a MINIMAL Foundry project
holding just the case's ``_exp.sol`` (in its ``YYYY-MM/`` subdir so ``../basetest``
imports resolve) + the shared helpers + a forge-std symlink, with the chain alias
pointed at our archive ``<CHAIN>_RPC_URL`` — so ``forge`` compiles only that case
(not the whole 1000-PoC repo) and forks the pre-hack block directly. ``reproduced``
= the PoC's ``testExploit`` passes (the attacker profits), i.e. the known exploit
fires against the deployed contracts at that block.

The git clone is behind an injected ``cloner`` so the control flow unit-tests
offline; the actual clone + fork run cost compute (an archive RPC), not tokens.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Callable

DHL_REPO = "https://github.com/SunWeb3Sec/DeFiHackLabs"
FORGE_STD_REPO = "https://github.com/foundry-rs/forge-std"
# The core shared helpers every PoC may import. (StableMath.sol is deliberately
# excluded — it pulls @balancer-labs deps not in the minimal bundle and few cases
# use it; a case that needs an extra helper can name it in poc_extra_helpers.)
_HELPERS = ("interface.sol", "basetest.sol", "tokenhelper.sol")

# Free public ARCHIVE endpoints per chain, used as a fallback when no
# ``<CHAIN>_RPC_URL`` is configured (operator opted into free public archives).
# Verified 2026-06-24: drpc.org serves year-old historical state on eth + polygon.
# Free nodes are FLAKY on the cold fork fetch (rate-limit / 5xx) — the replay retries
# once, which warms forge's fork cache. A dedicated archive key is still more reliable.
KNOWN_FREE_ARCHIVES: dict[str, list[str]] = {
    "mainnet": ["https://eth.drpc.org", "https://eth-mainnet.public.blastapi.io"],
    "ethereum": ["https://eth.drpc.org", "https://eth-mainnet.public.blastapi.io"],
    "polygon": ["https://polygon.drpc.org", "https://polygon-mainnet.public.blastapi.io"],
    "bsc": ["https://bsc.drpc.org", "https://bsc-mainnet.public.blastapi.io"],
    "arbitrum": ["https://arbitrum.drpc.org", "https://arbitrum-one.publicnode.com"],
    "optimism": ["https://optimism.drpc.org"],
    "base": ["https://base.drpc.org"],
    "avalanche": ["https://avalanche.drpc.org"],
    "fantom": ["https://fantom.drpc.org"],
}


def free_archive_for(chain: str) -> str | None:
    """First known free public archive endpoint for a chain (fallback when no
    ``<CHAIN>_RPC_URL`` is set). None if we don't know one."""
    cands = KNOWN_FREE_ARCHIVES.get((chain or "").lower())
    return cands[0] if cands else None


# (repo_url, dest_dir) -> None. Default clones shallow; injected in tests.
Cloner = Callable[[str, Path], None]


def default_cloner(repo: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "clone", "--depth", "1", repo, str(dest)],
                   check=True, capture_output=True, text=True, timeout=600)


def ensure_clone(cache_dir: str | Path, *, cloner: Cloner = default_cloner) -> Path:
    """Clone (or reuse) DeFiHackLabs + its forge-std submodule into ``cache_dir``."""
    repo = Path(cache_dir) / "DeFiHackLabs"
    if not (repo / "src" / "test" / "interface.sol").exists():
        if repo.exists():
            shutil.rmtree(repo)
        cloner(DHL_REPO, repo)
    fstd = repo / "lib" / "forge-std"
    if not (fstd / "src" / "Test.sol").exists():
        if fstd.exists():
            shutil.rmtree(fstd)
        cloner(FORGE_STD_REPO, fstd)
    return repo


def _foundry_toml(chain_alias: str) -> str:
    # The chain alias the PoC forks (e.g. "polygon") → our archive <CHAIN>_RPC_URL
    # (env-templated so the key never lands in the file). evm/fs match DeFiHackLabs.
    return (
        "[profile.default]\n"
        'src = "src"\ntest = "test"\nout = "out"\nlibs = ["lib"]\n'
        'evm_version = "shanghai"\noptimizer = true\noptimizer_runs = 200\n'
        'fs_permissions = [{ access = "read", path = "./"}]\n'
        "[rpc_endpoints]\n"
        f'{chain_alias} = "${{{chain_alias.upper()}_RPC_URL}}"\n'
    )


def build_case_project(repo: Path, poc_ref: str, chain_alias: str, work_dir: str | Path) -> Path:
    """Assemble the minimal Foundry project for one DeFiHackLabs case → workspace
    path. ``poc_ref`` is the repo-relative PoC path (e.g.
    ``src/test/2024-12/BTC24H_exp.sol``); its ``YYYY-MM/`` subdir is preserved under
    ``test/`` so the PoC's ``../interface.sol`` imports resolve next to the helpers."""
    ws = Path(work_dir).resolve()
    (ws / "test").mkdir(parents=True, exist_ok=True)
    (ws / "src").mkdir(parents=True, exist_ok=True)
    (ws / "lib").mkdir(parents=True, exist_ok=True)
    # forge-std symlink (avoid copying the whole lib)
    dst_fstd = ws / "lib" / "forge-std"
    if not dst_fstd.exists():
        try:
            dst_fstd.symlink_to((repo / "lib" / "forge-std").resolve(), target_is_directory=True)
        except OSError:
            shutil.copytree(repo / "lib" / "forge-std", dst_fstd)
    # shared helpers (those that exist) at test/ root
    for h in _HELPERS:
        src = repo / "src" / "test" / h
        if src.exists():
            shutil.copy2(src, ws / "test" / h)
    # the case PoC, preserving its sub-path under src/test/
    src_poc = repo / poc_ref
    if not src_poc.exists():
        raise FileNotFoundError(f"DeFiHackLabs PoC not found in clone: {poc_ref}")
    rel = poc_ref.split("src/test/", 1)[-1]            # e.g. "2024-12/BTC24H_exp.sol"
    dst_poc = ws / "test" / rel
    dst_poc.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src_poc, dst_poc)
    (ws / "foundry.toml").write_text(_foundry_toml(chain_alias))
    (ws / "remappings.txt").write_text("forge-std/=lib/forge-std/src/\n")
    return ws
