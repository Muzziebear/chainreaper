"""Keystore self-test (offline, ZERO network/tokens).

Asserts the .chainreaper/ secret store contract:
  * dotenv parsing (export prefix, quotes, comments, '#'/'=' in values);
  * load precedence — a real exported env var is NEVER overwritten; project file
    shadows the global file; missing files are a silent no-op;
  * set_secret round-trips, updates in place, creates a 0600 file + a self-protecting
    .chainreaper/.gitignore;
  * mask() never reveals the secret.

Usage:  python tests/smoke_secrets.py
"""

from __future__ import annotations

import stat
import sys
import tempfile
from pathlib import Path

from chainreaper import keystore as ks


def _check(name: str, cond: bool, detail: str = "") -> None:
    mark = "OK  " if cond else "FAIL"
    print(f"  [{mark}] {name}{(' — ' + detail) if detail else ''}")
    if not cond:
        raise AssertionError(name)


def test_parse() -> None:
    txt = ("# a comment\n"
           "export ETHERSCAN_API_KEY=abc123\n"
           'ARBITRUM_RPC_URL="https://x/y?key=ZZ#frag"\n'
           "\n"
           "EMPTYLINE_IGNORED\n"
           "QUOTED='single'\n")
    d = ks.parse_env_text(txt)
    _check("export prefix stripped", d.get("ETHERSCAN_API_KEY") == "abc123")
    _check("value keeps '#'/'=' after first '='", d.get("ARBITRUM_RPC_URL") == "https://x/y?key=ZZ#frag")
    _check("single quotes stripped", d.get("QUOTED") == "single")
    _check("non KEY=VALUE line ignored", "EMPTYLINE_IGNORED" not in d)


def test_load_precedence() -> None:
    with tempfile.TemporaryDirectory() as proj, tempfile.TemporaryDirectory() as home:
        (Path(proj) / ks.CHAINREAPER_DIRNAME).mkdir()
        (Path(proj) / ks.CHAINREAPER_DIRNAME / "env").write_text(
            "ETHERSCAN_API_KEY=from_project\nONLY_PROJECT=p\n")
        # monkeypatch the global dir to a temp home
        orig_global = ks.global_dir
        ks.global_dir = lambda: Path(home) / ks.CHAINREAPER_DIRNAME  # type: ignore[assignment]
        (Path(home) / ks.CHAINREAPER_DIRNAME).mkdir()
        (Path(home) / ks.CHAINREAPER_DIRNAME / "env").write_text(
            "ETHERSCAN_API_KEY=from_global\nONLY_GLOBAL=g\n")
        try:
            env = {"ETHERSCAN_API_KEY": "from_real_export"}  # already set → must win
            loaded = ks.load_env_files(environ=env, base=proj)
            _check("real export NOT overwritten", env["ETHERSCAN_API_KEY"] == "from_real_export")
            _check("exported key not reported loaded", "ETHERSCAN_API_KEY" not in loaded)
            _check("project-only key loaded", env.get("ONLY_PROJECT") == "p")
            _check("global fallback fills gaps", env.get("ONLY_GLOBAL") == "g")

            env2: dict = {}
            ks.load_env_files(environ=env2, base=proj)
            _check("project shadows global for shared key",
                   env2.get("ETHERSCAN_API_KEY") == "from_project")
        finally:
            ks.global_dir = orig_global  # type: ignore[assignment]

    # missing dir → silent no-op
    with tempfile.TemporaryDirectory() as empty:
        env3: dict = {}
        _check("missing files = no-op", ks.load_env_files(environ=env3, base=empty) == [])


def test_set_and_protect() -> None:
    with tempfile.TemporaryDirectory() as proj:
        p = ks.set_secret("ETHERSCAN_API_KEY", "KEY_ONE", base=proj)
        _check("env file created", p.is_file())
        mode = stat.S_IMODE(p.stat().st_mode)
        _check("env file is chmod 600", mode == 0o600, oct(mode))
        _check("self-protecting .gitignore written",
               (p.parent / ".gitignore").read_text().strip() == "*")
        # update in place (no duplicate line)
        ks.set_secret("ETHERSCAN_API_KEY", "KEY_TWO", base=proj)
        ks.set_secret("ARBITRUM_RPC_URL", "https://rpc", base=proj)
        d = ks.parse_env_text(p.read_text())
        _check("update in place (last value wins, single entry)", d["ETHERSCAN_API_KEY"] == "KEY_TWO")
        _check("no duplicate key lines",
               p.read_text().count("ETHERSCAN_API_KEY=") == 1, p.read_text())
        _check("second key appended", d.get("ARBITRUM_RPC_URL") == "https://rpc")

        env: dict = {}
        ks.load_env_files(environ=env, base=proj)
        _check("persisted keys load into env", env.get("ETHERSCAN_API_KEY") == "KEY_TWO")


def test_mask() -> None:
    _check("mask keeps only last 4", ks.mask("SUPERSECRETKEY1234") == "•" * 14 + "1234")
    _check("mask unset", ks.mask(None) == "(unset)")
    _check("mask never reveals full value", "SUPERSECRET" not in ks.mask("SUPERSECRET9999"))


def main() -> int:
    print("keystore smoke test (offline)\n")
    print("parse:")
    test_parse()
    print("load precedence:")
    test_load_precedence()
    print("set + protect:")
    test_set_and_protect()
    print("mask:")
    test_mask()
    print("\nsmoke_secrets: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
