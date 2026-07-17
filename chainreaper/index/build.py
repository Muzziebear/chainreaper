"""S1 Index driver — compile-aware Slither export → SQLite (IMPL-NOTES §3, §5).

Flow:
  1. Locate Slither's interpreter from its CLI shebang (its pipx venv).
  2. Run `slither_export.py` *with that interpreter* over the (already-compiled)
     target, producing a JSON structural model.
  3. Load the JSON into the SQLite `Store` (this runs in chainreaper's own venv).

Returns a summary dict (counts + paths) suitable as the S1 checkpoint payload.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

from ..runtime.exec import run_tool
from .store import Store

_EXPORT_SCRIPT = Path(__file__).parent / "slither_export.py"

# Standard tooling locations from tools_poc/README.md §2. Chainreaper makes the
# analysis toolchain reachable itself rather than depending on the parent shell
# having sourced ~/.bashrc — so `forge`/`solc`/`node` are present when Slither's
# crytic-compile shells out to compile the target.
_TOOL_PATH_DIRS = [
    "/usr/local/py-utils/bin",
    str(Path.home() / ".cargo" / "bin"),
    str(Path.home() / ".foundry" / "bin"),
    str(Path.home() / ".bifrost" / "bin"),
    str(Path.home() / ".fuzzers" / "bin"),  # medusa/echidna/ityfuzz release binaries (T1.1)
]


def _augmented_env() -> dict[str, str]:
    env = dict(os.environ)
    extra = [d for d in _TOOL_PATH_DIRS if Path(d).is_dir()]
    node = shutil.which("node")          # keep the active (nvm) node on PATH
    if node:
        extra.append(str(Path(node).parent))
    if extra:
        env["PATH"] = os.pathsep.join(extra + [env.get("PATH", "")])
    return env


def slither_interpreter() -> str:
    """Path to the python that backs the `slither` CLI (its pipx venv)."""
    slither = shutil.which("slither")
    if not slither:
        raise FileNotFoundError(
            "slither not found on PATH. Ensure tools_poc setup ran and PATH includes "
            "/usr/local/py-utils/bin (see tools_poc/README.md §2)."
        )
    first = Path(slither).read_text(errors="replace").splitlines()[0]
    if first.startswith("#!"):
        return first[2:].strip()
    # Fallback: sibling python in the same venv bin dir
    cand = Path(slither).parent / "python"
    if cand.exists():
        return str(cand)
    raise RuntimeError(f"could not determine slither interpreter from {slither}")


def run_slither_export(target_dir: Path, out_json: Path, *, timeout: int = 1800,
                       framework: str = "hardhat", solc_version: str | None = None,
                       remappings: list[str] | None = None,
                       foundry_profile: str | None = None) -> None:
    interp = slither_interpreter()
    out_json = out_json.resolve()        # subprocess runs with cwd=target_dir
    out_json.parent.mkdir(parents=True, exist_ok=True)
    env = _augmented_env()
    # Foundry monorepo: contracts live under a named profile's `src` (e.g. silo-core/
    # contracts via FOUNDRY_PROFILE=core), so the default `forge build` has nothing to
    # compile and crytic-compile errors "build-info is not a directory". forge + crytic
    # both honour FOUNDRY_PROFILE from the env, so pin it for the build.
    if foundry_profile:
        env["FOUNDRY_PROFILE"] = foundry_profile
    # Pin the exact solc for a verified-source unit (its Etherscan compiler version).
    # solc-select reads SOLC_VERSION; install it first (idempotent, no-op if present).
    if solc_version:
        run_tool(["solc-select", "install", solc_version], cwd=target_dir,
                 timeout=timeout, env=env)
        env["SOLC_VERSION"] = solc_version
    # Extra args after the framework = the standard-json import remappings (so the
    # solc-standard-json branch can resolve remapped imports like euler-vault-kit/…).
    cmd = [interp, str(_EXPORT_SCRIPT), ".", str(out_json), framework, *(remappings or [])]
    proc = run_tool(cmd, cwd=target_dir, timeout=timeout, env=env)
    if proc.returncode != 0 or not out_json.exists():
        raise RuntimeError(
            f"slither_export failed (rc={proc.returncode}).\n"
            f"--- stdout ---\n{proc.stdout[-3000:]}\n--- stderr ---\n{proc.stderr[-3000:]}"
        )


# Proxy / upgradeability detection (IMPL-NOTES §5: best-effort, deterministic,
# from the already-extracted Slither model — no extra subprocess, no egress).
# Covers both genuine delegatecall proxies and the Initializable pattern, which
# is GMX V2's actual upgrade/init surface (AC-04: "no re-init / no unprotected
# upgrade"). `slither-check-upgradeability` is a per-proxy-pair tool, better
# reserved for a targeted S4 check than repo-wide inventory.
_INIT_MOD_HINTS = ("initializ", "reinitializer", "oninitializing")
_UPGRADE_BASE_HINTS = ("initializable", "upgradeable", "uups", "erc1967",
                       "transparentupgradeableproxy", "beaconproxy", "proxy")

# Max concrete implementers to wire for a signature-only dispatch resolution (task
# 1A). Interface/base-typed hits are always wired; this only bounds the fallback so a
# ubiquitous signature (transfer/balanceOf/approve) doesn't connect the whole graph.
_MAX_SIG_DISPATCH = 6


def _is_init_func(f: dict) -> bool:
    name = (f.get("name") or "").lower()
    if name == "initialize" or (name.startswith("__") and "_init" in name):
        return True
    return any(any(h in (m or "").lower() for h in _INIT_MOD_HINTS)
               for m in (f.get("modifiers") or []))


def _detect_proxy_info(contract: dict) -> dict | None:
    """Return {pattern, impl_slot, init_guard} for a proxy/initializable contract,
    or None when the contract has no upgrade/init surface (so we only store
    meaningful rows). init_guard: True = guarded, False = unprotected init
    (the AC-04 vulnerability), None = no init function."""
    funcs = contract.get("functions", []) or []
    bases = [b.lower() for b in (contract.get("inheritance", []) or [])]

    has_delegate = any(s.get("kind") == "delegatecall"
                       for f in funcs for s in (f.get("sinks") or []))
    init_funcs = [f for f in funcs if _is_init_func(f)]
    inherits_upgradeable = any(h in b for b in bases for h in _UPGRADE_BASE_HINTS)

    def _has_init_mod(f: dict) -> bool:
        return any(any(h in (m or "").lower() for h in _INIT_MOD_HINTS)
                   for m in (f.get("modifiers") or []))

    if init_funcs:
        init_guard = any(_has_init_mod(f) for f in init_funcs)
    else:
        init_guard = None

    def _base_pattern() -> str | None:
        if any("uups" in b for b in bases):
            return "uups"
        if any("transparentupgradeableproxy" in b or "erc1967" in b for b in bases):
            return "transparent"
        if any("beacon" in b for b in bases):
            return "beacon"
        return None

    if has_delegate:
        pattern = _base_pattern() or "proxy"
    elif init_funcs or inherits_upgradeable:
        pattern = _base_pattern() or "initializable"
    else:
        return None

    return {"pattern": pattern, "impl_slot": None, "init_guard": init_guard}


def _loc(target_dir: Path, rel: str | None) -> int | None:
    if not rel:
        return None
    p = target_dir / rel
    try:
        return sum(1 for _ in p.open("r", errors="replace"))
    except OSError:
        return None


def load_export(store: Store, export: dict, *, repo_ref: str, target_dir: Path,
                language: str = "solidity", indexed_at: str | None = None,
                reset: bool = True) -> dict:
    """Populate the store from a slither_export JSON. Two passes so call edges,
    var access and inheritance can resolve to ids.

    ``reset`` wipes the store first (single-repo default). When a Target has MULTIPLE
    in-scope units (e.g. per-address verified-source units, or several cloned repos), S1
    resets ONCE before the first unit and accumulates the rest into the same index."""
    if reset:
        store.reset()
    repo_id = store.add_repo(repo_ref, language, str(target_dir), indexed_at=indexed_at)

    file_id: dict[str, int] = {}
    contract_id: dict[str, int] = {}
    var_id: dict[tuple[str, str], int] = {}      # (contract, var) -> id
    var_id_any: dict[str, int] = {}              # var name -> id (last-wins fallback)
    func_id_by_sig: dict[str, int] = {}          # global signature -> id
    func_id_by_cs: dict[tuple[str, str], int] = {}  # (contract, signature) -> id
    pending_calls: list[tuple[int, list[dict]]] = []   # (func_id, calls)
    pending_rw: list[tuple[int, str, list[str], list[str]]] = []  # (func_id, contract, reads, writes)
    pending_inherit: list[tuple[int, list[str]]] = []

    def get_file(rel: str | None) -> int | None:
        if not rel:
            return None
        if rel not in file_id:
            file_id[rel] = store.add_file(repo_id, rel, language=language, loc=_loc(target_dir, rel))
        return file_id[rel]

    contracts = export.get("contracts", [])
    # ---- pass 1: contracts, files, state vars, functions, sinks ---------- #
    for c in contracts:
        if c.get("error") and not c.get("functions"):
            pass  # still register the contract row below
        fid = get_file(c.get("file"))
        cid = store.add_contract(repo_id, c["name"], c.get("kind", "contract"),
                                 file_id=fid, line=c.get("line"))
        contract_id[c["name"]] = cid
        pending_inherit.append((cid, c.get("inheritance", [])))

        proxy = _detect_proxy_info(c)
        if proxy:
            store.add_proxy_info(cid, proxy["pattern"], proxy["impl_slot"], proxy["init_guard"])

        for v in c.get("state_vars", []):
            vid = store.add_state_var(cid, v["name"], v.get("type"), v.get("visibility"),
                                      v.get("is_constant", False), v.get("is_immutable", False),
                                      v.get("slot"), v.get("line"))
            var_id[(c["name"], v["name"])] = vid
            var_id_any[v["name"]] = vid

        for f in c.get("functions", []):
            vis = (f.get("visibility") or "").lower()
            is_ctor = bool(f.get("is_constructor"))
            is_entry = vis in ("public", "external") and not is_ctor
            ffid = get_file(f.get("file")) or fid
            func_id = store.add_function(
                cid, f.get("name", "?"), f.get("signature", "<unknown>"),
                vis or None, f.get("mutability"), is_ctor, is_entry,
                f.get("modifiers", []), ffid, f.get("line_start"), f.get("line_end"),
            )
            sig = f.get("signature", "")
            if sig:
                func_id_by_sig.setdefault(sig, func_id)
                func_id_by_cs[(c["name"], sig)] = func_id
            for s in f.get("sinks", []):
                store.add_sink(func_id, s["kind"], s.get("detail"), s.get("line"))
            pending_calls.append((func_id, f.get("calls", [])))
            pending_rw.append((func_id, c["name"], f.get("reads", []), f.get("writes", [])))

    # ---- pass 2: inheritance, var access, call edges --------------------- #
    for cid, bases in pending_inherit:
        for base in bases:
            store.add_inheritance(cid, base, contract_id.get(base))

    for func_id, cname, reads, writes in pending_rw:
        for vname in reads:
            vid = var_id.get((cname, vname)) or var_id_any.get(vname)
            if vid is not None:
                store.add_var_access(func_id, vid, "read")
        for vname in writes:
            vid = var_id.get((cname, vname)) or var_id_any.get(vname)
            if vid is not None:
                store.add_var_access(func_id, vid, "write")

    # Dispatch-resolution maps (task 1A): resolve interface-typed / proxy / library
    # external calls to their CONCRETE implementations so the reachability BFS can
    # traverse Spoke→IHub(x).fn()→Hub.fn edges that slither leaves pointing at the
    # interface (no body) — the ~35% of edges that were unresolved on modular/proxy
    # targets like Aave v4. Additive: we ADD resolved edges, never drop the direct one.
    kind_by_name = {c["name"]: (c.get("kind") or "contract") for c in contracts}
    implementers: dict[str, list[str]] = {}          # base/interface -> [concrete impls]
    for c in contracts:
        for b in c.get("inheritance", []) or []:
            implementers.setdefault(b, []).append(c["name"])
    concrete_by_sig: dict[str, list[tuple[str, int]]] = {}  # sig -> [(contract, fid)]
    for (cn, sig), fid in func_id_by_cs.items():
        if kind_by_name.get(cn) not in ("interface",):
            concrete_by_sig.setdefault(sig, []).append((cn, fid))

    def _dispatch_targets(cc: str | None, callee_sig: str, direct_fid: int | None) -> set[int]:
        """Concrete function ids a call may dispatch to beyond the direct callee:
        interface/base implementers (precise) + a bounded signature fallback when the
        direct callee is an interface stub or unresolved."""
        targets: set[int] = set()
        # 1. typed via an interface/abstract base -> every implementer's impl of the sig
        if cc and cc in implementers:
            for impl in implementers[cc]:
                fid = func_id_by_cs.get((impl, callee_sig))
                if fid is not None:
                    targets.add(fid)
        # 2. direct callee is an interface stub (no body) or unresolved -> concrete impls
        direct_is_iface = bool(cc) and kind_by_name.get(cc) == "interface"
        if (direct_fid is None or direct_is_iface) and callee_sig in concrete_by_sig:
            cands = concrete_by_sig[callee_sig]
            # keep precise interface hits; otherwise only resolve a small fan-out so a
            # ubiquitous signature (transfer/balanceOf) doesn't wire the whole graph.
            if targets or len(cands) <= _MAX_SIG_DISPATCH:
                targets.update(fid for _cn, fid in cands)
        targets.discard(direct_fid)  # don't duplicate the direct edge
        return targets

    resolved_added = 0
    for func_id, calls in pending_calls:
        for call in calls:
            callee_sig = call.get("callee_sig", "<unknown>")
            cc = call.get("callee_contract")
            callee_fid = None
            if cc and (cc, callee_sig) in func_id_by_cs:
                callee_fid = func_id_by_cs[(cc, callee_sig)]
            elif callee_sig in func_id_by_sig:
                callee_fid = func_id_by_sig[callee_sig]
            store.add_call_edge(func_id, callee_sig, call.get("call_type", "internal"),
                                callee_func_id=callee_fid, line=call.get("line"))
            # add resolved dispatch edges to concrete implementers (task 1A)
            for tfid in _dispatch_targets(cc, callee_sig, callee_fid):
                store.add_call_edge(func_id, callee_sig, "dispatch",
                                    callee_func_id=tfid, line=call.get("line"))
                resolved_added += 1
    if resolved_added:
        from ..runtime.logging import get_logger
        get_logger().info("[s1] call-graph: +%d resolved dispatch edge(s) "
                          "(interface/proxy/library)", resolved_added)

    # ---- detectors -> sast_findings -------------------------------------- #
    for d in export.get("detectors", []):
        if not isinstance(d, dict):
            continue
        elem = (d.get("elements") or [{}])[0]
        sm = elem.get("source_mapping", {}) if isinstance(elem, dict) else {}
        lines = sm.get("lines") or []
        store.add_sast_finding(
            repo_id, tool="slither", check_id=d.get("check"),
            impact=d.get("impact"), confidence=d.get("confidence"),
            file=(sm.get("filename_relative") or sm.get("filename_short")),
            line=lines[0] if lines else None,
            description=(d.get("description") or "")[:2000], raw=d,
        )

    store.commit()
    return store.counts()


def _foundry_has_buildable_src(target_dir: Path) -> bool:
    """True when foundry.toml yields a real compilable src — either the default profile's
    ``src`` dir exists (default ``src`` or a configured one like Fluid's ``contracts``),
    or it is a profile-split monorepo. Used to prefer Foundry over a coexisting Hardhat
    config for Foundry-primary repos (Fluid ships both foundry.toml + hardhat.config.ts)."""
    toml_path = target_dir / "foundry.toml"
    if not toml_path.exists():
        return False
    if (target_dir / "src").is_dir() or bool(foundry_profiles(target_dir)):
        return True
    try:
        import tomllib
        data = tomllib.loads(toml_path.read_text())
        src = ((data.get("profile") or {}).get("default") or {}).get("src")
        return bool(src) and (target_dir / src).is_dir()
    except Exception:
        return False


def detect_framework(target_dir: Path) -> str:
    """Pick the crytic-compile framework for a repo from its build files. Foundry
    and Hardhat are detected explicitly; ``-`` lets crytic-compile auto-detect.
    (Keeps GMX — a Hardhat repo — on ``hardhat`` while supporting Foundry targets.)
    A repo that ships BOTH foundry.toml and a hardhat.config (Fluid) is treated as
    Foundry when foundry.toml defines a buildable src — crytic's Hardhat platform
    needs Node 22 and is the wrong builder for a Foundry-primary repo."""
    has_hardhat = (target_dir / "hardhat.config.js").exists() or (target_dir / "hardhat.config.ts").exists()
    if (target_dir / "foundry.toml").exists() and _foundry_has_buildable_src(target_dir):
        return "foundry"
    if has_hardhat:
        return "hardhat"
    if (target_dir / "foundry.toml").exists():
        return "foundry"
    return "-"  # auto-detect


def foundry_profiles(target_dir: Path) -> dict[str, str]:
    """For a Foundry monorepo, the buildable production profiles → their ``src`` dir.

    Many modern repos (Silo, and other multi-package Foundry workspaces) put each package
    under a named profile (``[profile.core] src='silo-core/contracts'``) and leave the
    ``default`` profile without a ``src``, so a plain ``forge build`` compiles nothing.
    Returns ``{profile_name: src_rel}`` deduped by src dir, skipping test/echidna/invariant/
    coverage profiles. Empty dict = not a profile-split monorepo (index normally)."""
    toml_path = target_dir / "foundry.toml"
    if not toml_path.exists():
        return {}
    try:
        import tomllib
        data = tomllib.loads(toml_path.read_text())
    except Exception:
        return {}
    _SKIP = ("test", "echidna", "invariant", "fmt", "ci", "coverage", "docs", "fuzz")
    by_src: dict[str, str] = {}
    for name, cfg in (data.get("profile") or {}).items():
        if name == "default" or any(s in name.lower() for s in _SKIP):
            continue
        if not isinstance(cfg, dict):
            continue
        src = cfg.get("src")
        if src and (target_dir / src).is_dir() and src not in by_src.values():
            by_src[name] = src
    return by_src


def _is_foundry_monorepo(target_dir: Path) -> bool:
    """True when the default Foundry layout has no compilable src (so a plain build
    yields no build-info) but named profiles do — the case `foundry_profiles` handles."""
    default_src = (target_dir / "src").is_dir()
    return not default_src and bool(foundry_profiles(target_dir))


def compile_plan(target_dir: Path) -> tuple[str, str | None, list[str]]:
    """Return ``(framework, solc_version, remappings)`` for indexing ``target_dir``.

    A materialized verified-source unit drops a ``.chainreaper-compile.json`` sentinel
    saying "compile me as solc-standard-json with this exact solc + these import
    remappings" (Etherscan source has no build config but a known compiler + remappings)
    — that takes precedence; otherwise fall back to build-file detection with no version
    pin / no remappings."""
    sentinel = target_dir / ".chainreaper-compile.json"
    if sentinel.exists():
        try:
            plan = json.loads(sentinel.read_text())
            return (plan.get("framework") or "-", plan.get("solc_version"),
                    plan.get("remappings") or [])
        except (OSError, json.JSONDecodeError):
            pass
    return detect_framework(target_dir), None, []


def _export_and_load(target_dir: Path, db_path: Path, repo_ref: str, out_json: Path,
                     *, framework: str, solc_version: str | None, remappings: list[str],
                     foundry_profile: str | None, indexed_at: str | None, reset: bool,
                     timeout: int) -> dict:
    """One slither-export → load into the index. Returns this unit's count delta."""
    run_slither_export(target_dir, out_json, timeout=timeout,
                       framework=framework, solc_version=solc_version,
                       remappings=remappings, foundry_profile=foundry_profile)
    export = json.loads(out_json.read_text())
    store = Store(db_path)
    store.create_schema()
    try:
        before = store.counts() if not reset else {}
        total = load_export(store, export, repo_ref=repo_ref, target_dir=target_dir,
                            indexed_at=indexed_at, reset=reset)
        counts = (total if reset
                  else {k: total.get(k, 0) - before.get(k, 0) for k in total})
    finally:
        store.close()
    return {"export_json": str(out_json), "repo_ref": repo_ref, "counts": counts}


def build_index(repo_ref: str, target_dir: str | Path, db_path: str | Path,
                *, timeout: int = 1800, indexed_at: str | None = None,
                reset: bool = True) -> dict:
    """Compile + Slither-export + load one unit into the index. ``reset=False`` accumulates
    into an existing index (multi-unit Targets) instead of wiping it (single-repo default).

    A Foundry *monorepo* (profile-split packages, no default ``src``) is expanded into one
    sub-unit per buildable production profile (``repo:core``, ``repo:vaults``, …), each built
    with its ``FOUNDRY_PROFILE`` and merged into the shared index — so all in-scope packages
    get indexed instead of the whole repo failing on an empty default build."""
    target_dir = Path(target_dir).resolve()
    db_path = Path(db_path)
    framework, solc_version, remappings = compile_plan(target_dir)

    if framework == "foundry" and _is_foundry_monorepo(target_dir):
        profiles = foundry_profiles(target_dir)
        sub_results, failures, did_reset = [], [], False
        for prof in profiles:
            sub_ref = f"{repo_ref}:{prof}"
            out_json = db_path.parent / f"slither_export_{sub_ref.replace(':', '_')}.json"
            try:
                r = _export_and_load(
                    target_dir, db_path, sub_ref, out_json, framework="foundry",
                    solc_version=solc_version, remappings=remappings, foundry_profile=prof,
                    indexed_at=indexed_at, reset=reset and not did_reset, timeout=timeout)
                did_reset = did_reset or reset
                sub_results.append(r)
            except Exception as exc:
                failures.append({"profile": prof, "error": f"{type(exc).__name__}: {str(exc)[:200]}"})
        if not sub_results:
            detail = "; ".join(f"{f['profile']}: {f['error']}" for f in failures)
            raise RuntimeError(f"foundry monorepo {repo_ref}: no profile compiled ({detail})")
        merged: dict[str, int] = {}
        for r in sub_results:
            for k, v in r["counts"].items():
                merged[k] = merged.get(k, 0) + v
        return {"db_path": str(db_path), "repo_ref": repo_ref, "counts": merged,
                "profiles": [r["repo_ref"] for r in sub_results], "failures": failures,
                "export_json": sub_results[0]["export_json"]}

    out_json = db_path.parent / f"slither_export_{repo_ref}.json"
    r = _export_and_load(target_dir, db_path, repo_ref, out_json, framework=framework,
                         solc_version=solc_version, remappings=remappings,
                         foundry_profile=None, indexed_at=indexed_at, reset=reset,
                         timeout=timeout)
    return {"db_path": str(db_path), **r}
