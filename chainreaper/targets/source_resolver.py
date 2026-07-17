"""Source resolution (spec §S0 B) — clone the in-scope source repos into the run
workspace and bridge in-scope contract NAMES → source files.

The Immunefi ``scope/`` page names in-scope contracts by NAME; the ``resources/`` page
points at the GitHub repos, which are a **superset** of the in-scope set. So S0:

  1. **clones** each in-scope repo at the pinned commit/tag, or HEAD when nothing is
     pinned — recording the resolved sha for reproducibility (``--commit`` overrides);
  2. **maps** each in-scope contract name to the ``.sol`` file that defines it (by
     scanning for ``contract|library|interface|abstract contract <Name>``), producing
     the in-scope **allowlist** the scope injector enforces; unresolved names are flagged;
  3. optionally falls back to **verified explorer source** for an address with no repo
     match (closed-source / off-repo deployments).

The git + network calls are injectable seams (``runner`` / ``fetcher``) so the mapping
logic is unit-tested fully offline against a temp clone (ZERO network, ZERO tokens).
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

from ..models import InScopeContract, ScopeAsset

USER_AGENT = "chainreaper/0.1"

# matches a top-level Solidity type definition: contract/library/interface/abstract contract.
_CONTRACT_DEF_RE = re.compile(
    r"\b(?:abstract\s+contract|contract|library|interface)\s+([A-Za-z_]\w*)")

# Etherscan migrated to a single **V2 multichain** API (one key works across all chains;
# the old per-chain V1 hosts — api.arbiscan.io etc. — are deprecated). Chain → chainId.
_ETHERSCAN_V2 = "https://api.etherscan.io/v2/api"
_CHAIN_IDS = {
    "ethereum": 1, "mainnet": 1, "arbitrum": 42161, "polygon": 137,
    "avalanche": 43114, "base": 8453, "optimism": 10, "bsc": 56,
    "fantom": 250, "gnosis": 100, "linea": 59144, "scroll": 534352, "blast": 81457,
    "sonic": 146,
}


# --------------------------------------------------------------------------- #
# Clone                                                                         #
# --------------------------------------------------------------------------- #
@dataclass
class CloneResult:
    repo_url: str
    name: str
    local_path: str
    sha: str | None = None
    pinned: bool = False          # checked out an explicit commit/tag (vs HEAD)
    ok: bool = True
    detail: str = ""


def _git(args: list[str], cwd: str | Path | None = None, timeout: int = 600) -> tuple[int, str]:
    """Default git runner (injectable). Returns (returncode, combined-output)."""
    proc = subprocess.run(  # noqa: S603
        ["git", *args], cwd=str(cwd) if cwd else None,
        capture_output=True, text=True, timeout=timeout)
    return proc.returncode, (proc.stdout + proc.stderr).strip()


def _repo_name(url: str) -> str:
    tail = url.rstrip("/").split("/")[-1]
    return tail[:-4] if tail.endswith(".git") else tail


def _github_path_segments(url: str) -> list[str]:
    """Path segments of a github.com URL (``owner`` → org/user, ``owner/repo`` → repo)."""
    low = url.lower()
    if "github.com" not in low:
        return []
    after = url.split("github.com", 1)[1].lstrip("/:")
    after = after[:-4] if after.endswith(".git") else after
    return [s for s in after.strip("/").split("/") if s]


def expand_repo_refs(
    repos: Iterable[dict | str],
    *,
    fetcher: Callable[[str], str] = lambda u: _http_get(u),
) -> list[dict]:
    """Expand any GitHub **org/user** URL (``github.com/<owner>`` with no repo) into its
    individual source repos via the public API, since Immunefi often lists just the org.

    Keeps only non-fork, non-archived repos whose language is Solidity (or unknown) so we
    clone the contract repos, not forked token-lists / docs / frontends. Concrete
    ``owner/repo`` URLs pass through unchanged. Deduped by clone URL."""
    out: list[dict] = []
    seen: set[str] = set()

    def _add(url: str, title: str = "") -> None:
        u = url.rstrip("/")
        if u and u not in seen:
            seen.add(u)
            out.append({"url": u, "title": title})

    for r in repos:
        url = (r["url"] if isinstance(r, dict) else str(r)).strip()
        title = r.get("title", "") if isinstance(r, dict) else ""
        segs = _github_path_segments(url)
        if len(segs) != 1:  # concrete repo (or non-github) → keep as-is
            _add(url, title)
            continue
        owner = segs[0]
        try:
            listing = json.loads(fetcher(
                f"https://api.github.com/users/{owner}/repos?per_page=100&type=public"))
        except Exception:
            _add(url, title)  # API failed — fall back to the org URL (clone will flag it)
            continue
        if not isinstance(listing, list):
            _add(url, title)
            continue
        picked = 0
        for repo in listing:
            if not isinstance(repo, dict) or repo.get("fork") or repo.get("archived"):
                continue
            lang = repo.get("language")
            if lang not in (None, "Solidity"):
                continue
            _add(repo.get("html_url") or repo.get("clone_url") or "", repo.get("name") or "")
            picked += 1
        if picked == 0:  # nothing matched — keep the org URL so the miss is visible
            _add(url, title)
    return out


def clone_sources(
    repos: Iterable[dict | str],
    workspace: str | Path,
    *,
    commit: str | None = None,
    runner: Callable[..., tuple[int, str]] = _git,
    timeout: int = 600,
) -> list[CloneResult]:
    """Clone each in-scope source repo into ``workspace/<name>`` and resolve its sha.

    When ``commit`` is given it is checked out in every repo (operator pin); otherwise
    the default-branch HEAD is cloned and its sha recorded. Idempotent: an existing
    non-empty clone dir is reused (sha re-resolved), so ``--resume`` doesn't re-clone."""
    ws = Path(workspace)
    ws.mkdir(parents=True, exist_ok=True)
    results: list[CloneResult] = []
    for r in repos:
        url = r["url"] if isinstance(r, dict) else str(r)
        name = _repo_name(url)
        dest = ws / name
        res = CloneResult(repo_url=url, name=name, local_path=str(dest))
        if dest.exists() and any(dest.iterdir()):
            res.detail = "reused existing clone"
        else:
            # full clone (not --depth 1) so an explicit --commit can be checked out.
            args = (["clone", url, str(dest)] if commit
                    else ["clone", "--depth", "1", url, str(dest)])
            rc, out = runner(args, timeout=timeout)
            if rc != 0:
                res.ok = False
                res.detail = f"git clone failed: {out[-200:]}"
                results.append(res)
                continue
        if commit:
            rc, out = runner(["-C", str(dest), "checkout", commit], timeout=timeout)
            res.pinned = rc == 0
            if rc != 0:
                res.detail = f"checkout {commit} failed: {out[-160:]}"
        rc, sha = runner(["-C", str(dest), "rev-parse", "HEAD"], timeout=timeout)
        res.sha = sha.strip() if rc == 0 and sha.strip() else None
        results.append(res)
    return results


def clones_to_assets(clones: list[CloneResult], impacts: list[str] | None = None) -> list[ScopeAsset]:
    """Represent each successful clone as an indexable ``local_path`` ScopeAsset (S1
    indexes ``local_path``/``github_repo`` by path). Repo provenance (URL + resolved
    sha) rides along on ``source_repo`` / ``revision`` so the github URL itself is never
    handed to S1 as a path."""
    out: list[ScopeAsset] = []
    for c in clones:
        if not c.ok:
            continue
        out.append(ScopeAsset(
            kind="local_path", ref=c.local_path, in_scope=True,
            impacts_in_scope=impacts or [], name=c.name,
            source_repo=c.repo_url, revision=c.sha))
    return out


# --------------------------------------------------------------------------- #
# Name → source mapping (the in-scope allowlist)                                #
# --------------------------------------------------------------------------- #
def _index_contracts(roots: list[tuple[str, Path]]) -> dict[str, tuple[str, str]]:
    """Scan ``.sol`` files under each (repo_url, root) and map contract NAME →
    (repo_url, repo-relative file). First definition wins; vendored / generated /
    test paths are deprioritized so an in-scope name resolves to the real source,
    not a mock or a flattened blob.

    Files are walked in **sorted** order so the result is reproducible: ``rglob``
    iteration order is filesystem-dependent, and a superset clone can define the same
    contract name in two non-vendored files (e.g. ``contracts/X.sol`` AND its
    ``flattened/X.sol`` mirror) — without a stable order the resolved file would differ
    run-to-run/machine-to-machine."""
    primary: dict[str, tuple[str, str]] = {}
    secondary: dict[str, tuple[str, str]] = {}
    # non-canonical source: vendored deps, mocks/tests, and generated `flattened/` mirrors.
    _NONCANONICAL = ("node_modules/", "/mock", "mock/", "/test", "test/", "/lib/",
                     ".t.sol", "flattened/", "/flattened/")
    for repo_url, root in roots:
        if not root.exists():
            continue
        for sol in sorted(root.rglob("*.sol"), key=lambda p: p.as_posix()):
            rel = sol.relative_to(root).as_posix()
            low = rel.lower()
            is_vendor = any(seg in low for seg in _NONCANONICAL)
            try:
                text = sol.read_text(errors="replace")
            except OSError:
                continue
            for m in _CONTRACT_DEF_RE.finditer(text):
                cname = m.group(1)
                bucket = secondary if is_vendor else primary
                bucket.setdefault(cname, (repo_url, rel))
    merged = dict(secondary)
    merged.update(primary)  # primary (non-vendored) overrides
    return merged


def map_scope_to_source(
    in_scope: list[ScopeAsset] | list[dict],
    clones: list[CloneResult],
) -> list[InScopeContract]:
    """Build the in-scope contract allowlist by matching each scope asset's contract
    NAME to a Solidity definition in the clones. Unresolved names are returned with
    ``resolved=False`` + ``file=None`` (flagged, never dropped — spec §S0 B)."""
    roots = [(c.repo_url, Path(c.local_path)) for c in clones if c.ok]
    index = _index_contracts(roots)
    out: list[InScopeContract] = []
    seen: set[str] = set()
    for a in in_scope:
        name = (a.get("name") if isinstance(a, dict) else a.name) or ""
        if not name or name in seen:
            continue
        seen.add(name)
        addr = a.get("address") if isinstance(a, dict) else a.address
        net = a.get("network") if isinstance(a, dict) else a.network
        hit = index.get(name)
        out.append(InScopeContract(
            name=name, address=addr, network=net,
            file=hit[1] if hit else None,
            source_repo=hit[0] if hit else None,
            resolved=hit is not None))
    return out


# --------------------------------------------------------------------------- #
# Explorer verified-source fallback (optional)                                  #
# --------------------------------------------------------------------------- #
def _http_get(url: str, timeout: float = 30.0) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
        return r.read().decode("utf-8", "replace")


def fetch_verified_source(
    address: str,
    network: str,
    api_key: str | None,
    *,
    fetcher: Callable[[str], str] = _http_get,
) -> dict | None:
    """Etherscan **V2** ``getsourcecode`` fallback for an in-scope address whose source
    isn't in the cloned repos (newer/private deploy, or a closed-source target). This
    returns the EXACT verified DEPLOYED source — ground truth for what's actually in
    scope — including the proxy→implementation link for diamonds/proxies.

    Returns ``{contract_name, source, compiler, proxy, implementation, abi}`` or ``None``
    (unsupported chain / no key / unverified). One free Etherscan key covers all chains."""
    chain_id = _CHAIN_IDS.get((network or "").lower())
    if not chain_id or not api_key:
        return None
    url = (f"{_ETHERSCAN_V2}?chainid={chain_id}&module=contract&action=getsourcecode"
           f"&address={address}&apikey={api_key}")
    try:
        data = json.loads(fetcher(url))
    except Exception:
        return None
    if str(data.get("status")) != "1":
        return None
    result = data.get("result") or [{}]
    row = result[0] if isinstance(result, list) and result else {}
    if not isinstance(row, dict) or not row.get("SourceCode"):
        return None
    return {"contract_name": row.get("ContractName") or "",
            "source": row.get("SourceCode") or "",
            "compiler": row.get("CompilerVersion") or "",
            "proxy": row.get("Proxy") in ("1", 1),
            "implementation": row.get("Implementation") or "",
            "abi": row.get("ABI") or ""}


# --------------------------------------------------------------------------- #
# Verified-source materialization (explorer = source of truth)                  #
# --------------------------------------------------------------------------- #
# When scope is address-based, the verified DEPLOYED source IS the in-scope artifact
# (the repo is a superset / may be a different version). We fetch it per address, follow
# proxies to the implementation, dedupe identical source across addresses, and write a
# self-contained per-contract source unit S1 can index with no npm/truffle bootstrap.
_ZERO_ADDR = "0x0000000000000000000000000000000000000000"
# sentinel a materialized verified-source unit drops so S1 knows HOW to compile it
# (a bare dir of .sol with no build config → use solc-standard-json + this exact solc).
COMPILE_SENTINEL = ".chainreaper-compile.json"
_SOLC_VER_RE = re.compile(r"(\d+\.\d+\.\d+)")


def _solc_version(compiler: str) -> str | None:
    """``v0.8.23+commit.f704f362`` → ``0.8.23`` (the version the deployed bytecode used)."""
    m = _SOLC_VER_RE.search(compiler or "")
    return m.group(1) if m else None


def _safe_relpath(path: str) -> str:
    """Sanitize an Etherscan standard-json source path to a safe repo-relative file."""
    p = (path or "").replace("\\", "/").lstrip("/")
    parts = [seg for seg in p.split("/") if seg not in ("", "..", ".")]
    return "/".join(parts) or "Contract.sol"


def _sources_from_standard_json(obj: dict) -> dict[str, str]:
    sources = obj.get("sources") if isinstance(obj.get("sources"), dict) else None
    if sources is None and obj and all(
            isinstance(v, dict) and "content" in v for v in obj.values()):
        sources = obj  # the object IS the {path: {content}} map
    out: dict[str, str] = {}
    if isinstance(sources, dict):
        for path, entry in sources.items():
            content = (entry.get("content") if isinstance(entry, dict)
                       else entry if isinstance(entry, str) else "")
            if content:
                out[_safe_relpath(path)] = content
    return out


def _remappings_from_source(source_code: str) -> list[str]:
    """Extract ``settings.remappings`` from an Etherscan standard-json ``SourceCode``.
    Modern multi-repo verified source (Euler/OZ/etc.) imports via remapped prefixes
    (``euler-vault-kit/…``); without these the materialized files won't compile
    (``Source "…" not found``). Returns [] for a flat/sources-only export."""
    s = (source_code or "").strip()
    if not s:
        return []
    if s.startswith("{{") and s.endswith("}}"):
        s = s[1:-1]
    if not s.startswith("{"):
        return []
    try:
        obj = json.loads(s)
    except json.JSONDecodeError:
        return []
    settings = obj.get("settings") if isinstance(obj, dict) else None
    remaps = settings.get("remappings") if isinstance(settings, dict) else None
    return [str(r) for r in remaps] if isinstance(remaps, list) else []


def _parse_etherscan_source(source_code: str, contract_name: str) -> dict[str, str]:
    """Normalize Etherscan's ``SourceCode`` into ``{repo-relative path: content}``.

    Three shapes: a ``{{…}}`` double-wrapped standard-json (multi-file, preserves the
    real paths — preferred), a single ``{…}`` standard-json / sources map, or a plain
    flattened single file."""
    s = (source_code or "").strip()
    if not s:
        return {}
    if s.startswith("{{") and s.endswith("}}"):
        try:
            obj = json.loads(s[1:-1])
        except json.JSONDecodeError:
            obj = None
        if isinstance(obj, dict):
            files = _sources_from_standard_json(obj)
            if files:
                return files
    if s.startswith("{"):
        try:
            obj = json.loads(s)
        except json.JSONDecodeError:
            obj = None
        if isinstance(obj, dict):
            files = _sources_from_standard_json(obj)
            if files:
                return files
    return {f"{contract_name or 'Contract'}.sol": source_code}


@dataclass
class VerifiedUnit:
    """A self-contained verified-source unit (one logical contract's full source closure)
    materialized to disk and ready to index."""

    name: str
    dir: str
    chain: str
    addresses: list[str]                 # every in-scope address that maps to this source
    compiler: str = ""
    proxy: bool = False
    implementation: str | None = None
    files: list[str] = field(default_factory=list)
    primary_file: str | None = None      # the file defining ``name`` (None ⇒ not located)


def _def_file(files: dict[str, str], name: str) -> str | None:
    pat = re.compile(rf"\b(?:abstract\s+contract|contract|library|interface)\s+{re.escape(name)}\b")
    for rel, content in files.items():
        if pat.search(content):
            return rel
    return None


def materialize_verified_sources(
    contracts: list[ScopeAsset] | list[dict],
    workspace: str | Path,
    api_key: str | None,
    *,
    fetcher: Callable[[str], str] = _http_get,
    follow_proxies: bool = True,
    pause: float = 0.0,
) -> tuple[list[VerifiedUnit], list[dict]]:
    """Fetch + write the verified DEPLOYED source for each in-scope address.

    For a proxy, follows ``Implementation`` and analyzes the logic contract. Dedupes by
    source-content hash (one unit per distinct source; all its addresses recorded), so a
    contract deployed on several chains / behind several proxies is materialized once.
    Returns ``(units, unresolved)`` where ``unresolved`` records addresses with no verified
    source (flagged, never dropped). Writes under ``<workspace>/_verified/<chain>/``."""
    base = Path(workspace) / "_verified"
    units: list[VerifiedUnit] = []
    by_hash: dict[str, VerifiedUnit] = {}
    unresolved: list[dict] = []

    for a in contracts:
        name = (a.get("name") if isinstance(a, dict) else a.name) or ""
        addr = (a.get("address") if isinstance(a, dict) else a.address) or ""
        net = (a.get("network") if isinstance(a, dict) else a.network) or ""
        if not addr or not net:
            unresolved.append({"name": name, "address": addr, "network": net, "why": "no address/network"})
            continue
        row = fetch_verified_source(addr, net, api_key, fetcher=fetcher)
        if pause:
            time.sleep(pause)
        if not row:
            unresolved.append({"name": name, "address": addr, "network": net, "why": "unverified or fetch failed"})
            continue

        analyzed, impl = row, (row.get("implementation") or "")
        if follow_proxies and row.get("proxy") and impl and impl.lower() != _ZERO_ADDR:
            impl_row = fetch_verified_source(impl, net, api_key, fetcher=fetcher)
            if pause:
                time.sleep(pause)
            if impl_row and impl_row.get("source"):
                analyzed = impl_row  # the logic behind the proxy is the in-scope code

        cname = analyzed.get("contract_name") or name or "Contract"
        files = _parse_etherscan_source(analyzed.get("source", ""), cname)
        if not files:
            unresolved.append({"name": name, "address": addr, "network": net, "why": "empty verified source"})
            continue

        chash = hashlib.sha256(
            "".join(f"{k}\n{v}" for k, v in sorted(files.items())).encode("utf-8", "replace")).hexdigest()
        if chash in by_hash:
            u = by_hash[chash]
            if addr not in u.addresses:
                u.addresses.append(addr)
            continue

        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", f"{cname}_{addr[:10]}")
        udir = base / net / safe
        for rel, content in files.items():
            fp = udir / rel
            fp.parent.mkdir(parents=True, exist_ok=True)
            fp.write_text(content)
        # Preserve the standard-json import remappings (euler-vault-kit/=…, @openzeppelin/=…)
        # so the materialized multi-repo source actually COMPILES — without them S1 fails
        # with "Source … not found" on every remapped import (the common Euler/OZ case).
        remaps = _remappings_from_source(analyzed.get("source", ""))
        if remaps:
            (udir / "remappings.txt").write_text("\n".join(remaps) + "\n")
        # self-describing compile plan: bare verified source → solc-standard-json + the
        # EXACT solc the deployed bytecode used (no npm/truffle, no version guessing).
        (udir / COMPILE_SENTINEL).write_text(json.dumps({
            "framework": "solc-standard-json",
            "solc_version": _solc_version(analyzed.get("compiler", "")),
            "remappings": remaps,
            "source": "etherscan", "contract": cname, "address": addr, "chain": net}))
        unit = VerifiedUnit(
            name=cname, dir=str(udir), chain=net, addresses=[addr],
            compiler=analyzed.get("compiler", ""), proxy=bool(row.get("proxy")),
            implementation=(impl or None), files=list(files),
            primary_file=_def_file(files, cname))
        by_hash[chash] = unit
        units.append(unit)
    return units, unresolved


def verified_units_to_assets(units: list[VerifiedUnit], impacts: list[str] | None = None) -> list[ScopeAsset]:
    """Each verified unit → an indexable in-scope ``local_path`` ScopeAsset (provenance =
    ``etherscan:<chain>`` + the deployed address)."""
    out: list[ScopeAsset] = []
    for u in units:
        addr = u.addresses[0] if u.addresses else None
        out.append(ScopeAsset(
            kind="local_path", ref=u.dir, in_scope=True, impacts_in_scope=impacts or [],
            name=u.name, address=addr, network=u.chain,
            source_repo=f"etherscan:{u.chain}", revision=addr))
    return out


def verified_allowlist(
    contracts: list[ScopeAsset] | list[dict],
    units: list[VerifiedUnit],
    clones: list[CloneResult] | None = None,
) -> list[InScopeContract]:
    """Build the allowlist with explorer source as truth: resolve each in-scope contract
    to its verified unit (matched by deployed ADDRESS, so a scope display-name vs on-chain
    ContractName mismatch still resolves), falling back to the cloned repo for any address
    with no verified source, and flagging the rest."""
    addr_map: dict[str, VerifiedUnit] = {}
    for u in units:
        for ad in u.addresses:
            addr_map[ad.lower()] = u
    repo_allow = {c.name: c for c in map_scope_to_source(contracts, clones or [])}

    out: list[InScopeContract] = []
    seen: set[str] = set()
    for a in contracts:
        name = (a.get("name") if isinstance(a, dict) else a.name) or ""
        if not name or name in seen:
            continue
        seen.add(name)
        addr = (a.get("address") if isinstance(a, dict) else a.address) or ""
        net = (a.get("network") if isinstance(a, dict) else a.network) or ""
        u = addr_map.get(addr.lower())
        if u:
            out.append(InScopeContract(
                name=name, address=addr, network=net, file=u.primary_file,
                source_repo=u.dir, resolved=bool(u.primary_file)))
        elif name in repo_allow and repo_allow[name].resolved:
            out.append(repo_allow[name])
        else:
            out.append(InScopeContract(name=name, address=addr, network=net, resolved=False))
    return out
