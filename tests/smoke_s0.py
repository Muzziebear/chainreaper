"""S0 Discovery self-test (offline, ZERO network, ZERO token spend).

Exercises the full deterministic S0 surface against cached fixtures + a synthetic
clone — no Immunefi fetch, no git clone, no model calls:

  * ``resolve_ref`` classifies slug / Immunefi URL / repo URL / local path;
  * ``parse_program_object`` → ``ImmunefiProgram`` on the real ``gainsnetwork`` fixture
    (the merged program object lifted from the Next.js RSC flight stream);
  * ``program_to_target`` builds the metadata ``Target`` (contract-address + web + repo
    assets, impacts, PoC flag) and it round-trips through ``model_dump``/``model_validate``;
  * ``map_scope_to_source`` resolves in-scope contract NAMES → files in a temp clone and
    flags unresolved names (the allowlist);
  * ``scope_injector`` renders the in-scope contract allowlist (the superset guardrail);
  * ``parse_board`` + ranking order the discovery board.

Usage:  python tests/smoke_s0.py
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

from chainreaper.models import ScopeAsset, Target
from chainreaper.orchestrator.injectors import scope_injector
from chainreaper.runtime.fork import ProbeResult
from chainreaper.targets import immunefi_client as imc
from chainreaper.targets import rpc_resolver as rr
from chainreaper.targets import source_resolver as sr

_FIX = Path(__file__).parent / "fixtures"


def _check(name: str, cond: bool, detail: str = "") -> None:
    mark = "OK  " if cond else "FAIL"
    print(f"  [{mark}] {name}{(' — ' + detail) if detail else ''}")
    if not cond:
        raise AssertionError(name)


# --------------------------------------------------------------------------- #
def test_resolve_ref() -> None:
    _check("resolve slug", imc.resolve_ref("gainsnetwork").kind == "slug")
    r = imc.resolve_ref("https://immunefi.com/bug-bounty/gainsnetwork/scope/")
    _check("resolve immunefi url → slug", r.kind == "immunefi_url" and r.slug == "gainsnetwork")
    _check("resolve repo url", imc.resolve_ref("https://github.com/GainsNetwork/GNS-ethereum").kind == "repo_url")
    _check("resolve local path", imc.resolve_ref(str(Path(__file__))).kind == "local_path")


def test_parse_program() -> Target:
    obj = json.loads((_FIX / "immunefi_gainsnetwork.json").read_text())
    p = imc.parse_program_object(obj)
    _check("slug", p.slug == "gainsnetwork")
    _check("max bounty", p.max_bounty_usd == 200000.0, str(p.max_bounty_usd))
    _check("poc required", p.poc_required is True)
    _check("kyc not required", p.kyc_required is False)
    _check("languages = solidity", p.languages == ["solidity"], str(p.languages))
    _check("chains incl arbitrum+polygon",
           {"arbitrum", "polygon"} <= set(p.chains), str(p.chains))
    _check("in-scope contracts found", len(p.contracts) >= 20, str(len(p.contracts)))
    _check("contract carries name+address+network",
           all(c.name for c in p.contracts) and any(c.address and c.network for c in p.contracts))
    _check("source repos found (superset)",
           any("github.com/GainsNetwork" in r["url"] for r in p.repos), str([r["url"] for r in p.repos]))
    _check("impacts captured (critical first)",
           bool(p.impacts_in_scope) and "theft" in p.impacts_in_scope[0].lower())

    t = imc.program_to_target(p)
    kinds = {a.kind for a in t.assets_in_scope}
    _check("target has contract_address + github_repo assets",
           {"contract_address", "github_repo"} <= kinds, str(kinds))
    _check("target program_id = slug", t.program_id == "gainsnetwork")

    # round-trip preserves the new fields (and the local-path stub still validates).
    rt = Target.model_validate(t.model_dump(mode="json"))
    _check("Target round-trips", rt.program_id == "gainsnetwork" and rt.poc_required is True)
    return t


def test_map_scope_to_source() -> tuple[Target, list]:
    """Build a synthetic clone with two real-named contracts (one in a mock dir) +
    one missing, then assert the name→file allowlist resolves correctly."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td) / "GNS-ethereum"
        (root / "contracts" / "tokens").mkdir(parents=True)
        (root / "contracts" / "mock").mkdir(parents=True)
        (root / "contracts" / "tokens" / "GToken.sol").write_text(
            "pragma solidity ^0.8.0;\ncontract GToken is ERC20 {}\n")
        (root / "contracts" / "GTokenOpenPnlFeed.sol").write_text(
            "abstract contract GTokenOpenPnlFeed {}\n")
        # a same-named mock that must NOT win over the real source:
        (root / "contracts" / "mock" / "GToken.sol").write_text("contract GToken {}\n")

        clones = [sr.CloneResult(repo_url="https://github.com/GainsNetwork/GNS-ethereum",
                                 name="GNS-ethereum", local_path=str(root), sha="deadbeef", ok=True)]
        assets = [
            ScopeAsset(kind="contract_address", ref="0x1", name="GToken",
                       address="0x1", network="arbitrum"),
            ScopeAsset(kind="contract_address", ref="0x2", name="GTokenOpenPnlFeed",
                       address="0x2", network="arbitrum"),
            ScopeAsset(kind="contract_address", ref="0x3", name="NotInRepo",
                       address="0x3", network="arbitrum"),
        ]
        allow = sr.map_scope_to_source(assets, clones)
        by = {c.name: c for c in allow}
        _check("allowlist covers every scope name", len(allow) == 3, str(len(allow)))
        _check("GToken resolves to real source (not mock)",
               by["GToken"].resolved and "mock" not in (by["GToken"].file or ""), by["GToken"].file)
        _check("abstract contract resolves",
               by["GTokenOpenPnlFeed"].resolved and by["GTokenOpenPnlFeed"].file.endswith("GTokenOpenPnlFeed.sol"))
        _check("missing name flagged unresolved",
               by["NotInRepo"].resolved is False and by["NotInRepo"].file is None)
        _check("clones_to_assets → indexable local_path",
               sr.clones_to_assets(clones)[0].kind == "local_path")

        target = Target(program_id="gainsnetwork", name="Gains", scope_allowlist=allow,
                        assets_in_scope=assets)
        return target, allow


def test_expand_repo_refs() -> None:
    """Org URL → its Solidity repos (forks/docs dropped); concrete repos pass through."""
    org_listing = json.dumps([
        {"name": "gTrade-v6.1", "html_url": "https://github.com/GainsNetwork/gTrade-v6.1",
         "language": "Solidity", "fork": False, "archived": False},
        {"name": "GNS-tokens", "html_url": "https://github.com/GainsNetwork/GNS-tokens",
         "language": "Solidity", "fork": False, "archived": False},
        {"name": "default-token-list", "html_url": "https://github.com/GainsNetwork/default-token-list",
         "language": "JavaScript", "fork": True, "archived": False},
    ])
    expanded = sr.expand_repo_refs(
        [{"url": "https://github.com/GainsNetwork"},
         {"url": "https://github.com/GainsNetwork/GNS-ethereum"}],
        fetcher=lambda u: org_listing)
    urls = {e["url"] for e in expanded}
    _check("org expands to its Solidity repos",
           "https://github.com/GainsNetwork/gTrade-v6.1" in urls
           and "https://github.com/GainsNetwork/GNS-tokens" in urls)
    _check("forks/non-solidity dropped",
           "https://github.com/GainsNetwork/default-token-list" not in urls)
    _check("concrete repo passes through",
           "https://github.com/GainsNetwork/GNS-ethereum" in urls)
    _check("no bare org URL left", "https://github.com/GainsNetwork" not in urls)


def test_verified_source_materialization() -> None:
    """Explorer = source of truth: parse flattened + standard-json, follow a proxy to its
    implementation, dedupe identical source across addresses, flag the unverified."""
    # canned Etherscan V2 getsourcecode responses keyed by address.
    std_json = "{" + json.dumps({
        "language": "Solidity",
        "sources": {
            "contracts/Foo.sol": {"content": "pragma solidity 0.8.20;\ncontract Foo {}"},
            "lib/ERC20.sol": {"content": "contract ERC20 {}"},
        }}) + "}"
    responses = {
        "0xaaa": {"ContractName": "GToken", "CompilerVersion": "v0.8.14",
                  "SourceCode": "pragma solidity 0.8.14;\ncontract GToken {}", "Proxy": "0", "Implementation": ""},
        "0xbbb": {"ContractName": "Foo", "CompilerVersion": "v0.8.20",
                  "SourceCode": std_json, "Proxy": "0", "Implementation": ""},
        "0xccc": {"ContractName": "ERC1967Proxy", "CompilerVersion": "v0.8.20",
                  "SourceCode": "contract ERC1967Proxy {}", "Proxy": "1", "Implementation": "0xddd"},
        "0xddd": {"ContractName": "LogicV1", "CompilerVersion": "v0.8.20",
                  "SourceCode": "contract LogicV1 {}", "Proxy": "0", "Implementation": ""},
        "0xeee": {"ContractName": "GToken", "CompilerVersion": "v0.8.14",
                  "SourceCode": "pragma solidity 0.8.14;\ncontract GToken {}", "Proxy": "0", "Implementation": ""},
    }

    def fake_fetch(url: str) -> str:
        addr = (url.split("address=")[1].split("&")[0]).lower()
        row = responses.get(addr)
        if row is None:
            return json.dumps({"status": "0", "message": "NOTOK", "result": "not verified"})
        return json.dumps({"status": "1", "message": "OK", "result": [row]})

    assets = [
        ScopeAsset(kind="contract_address", ref="0xaaa", name="GToken", address="0xaaa", network="arbitrum"),
        ScopeAsset(kind="contract_address", ref="0xbbb", name="Foo", address="0xbbb", network="arbitrum"),
        ScopeAsset(kind="contract_address", ref="0xccc", name="ProxyContract", address="0xccc", network="arbitrum"),
        ScopeAsset(kind="contract_address", ref="0xeee", name="GTokenPolygon", address="0xeee", network="polygon"),
        ScopeAsset(kind="contract_address", ref="0xfff", name="Unverified", address="0xfff", network="arbitrum"),
    ]
    with tempfile.TemporaryDirectory() as td:
        units, unresolved = sr.materialize_verified_sources(
            assets, td, "FAKEKEY", fetcher=fake_fetch, pause=0.0)
        by_name = {u.name: u for u in units}
        _check("standard-json multi-file materialized", "Foo" in by_name
               and any(f.endswith("Foo.sol") for f in by_name["Foo"].files))
        _check("flattened single-file materialized", "GToken" in by_name)
        _check("proxy followed to implementation",
               "LogicV1" in by_name and by_name["LogicV1"].proxy
               and by_name["LogicV1"].implementation == "0xddd")
        _check("identical source deduped across chains (1 GToken unit, 2 addrs)",
               len(by_name["GToken"].addresses) == 2, str(by_name["GToken"].addresses))
        _check("unverified address flagged",
               any(u["address"] == "0xfff" for u in unresolved))
        _check("files written to disk", all((Path(u.dir)).exists() for u in units))
        _check("primary_file located", by_name["Foo"].primary_file
               and by_name["Foo"].primary_file.endswith("Foo.sol"))

        allow = sr.verified_allowlist(assets, units)
        by = {c.name: c for c in allow}
        _check("verified allowlist resolves by ADDRESS (scope name ≠ ContractName)",
               by["ProxyContract"].resolved and by["ProxyContract"].source_repo)
        _check("verified units → indexable local_path assets",
               sr.verified_units_to_assets(units)[0].kind == "local_path")


def test_parse_etherscan_source() -> None:
    flat = sr._parse_etherscan_source("contract X {}", "X")
    _check("flattened → single file", flat == {"X.sol": "contract X {}"})
    dj = "{" + json.dumps({"sources": {"a/B.sol": {"content": "contract B {}"}}}) + "}"
    parsed = sr._parse_etherscan_source(dj, "B")
    _check("double-brace standard-json → real paths", parsed == {"a/B.sol": "contract B {}"})
    _check("path traversal sanitized",
           sr._safe_relpath("../../etc/passwd") == "etc/passwd")


def test_fork_rpc_discovery() -> None:
    """Per-chain RPC resolution: env > config > public; archive vs latest-only; needs_key;
    URL redacted to host. Fully offline via an injected prober."""
    # a prober that answers by host substring (no network)
    def fake_prober(url: str, timeout: float) -> ProbeResult:
        if "alchemy" in url:                       # operator archive node
            return ProbeResult(reachable=True, chain_id=137, block_number=9, archive=True)
        if "publicnode" in url or "polygon-rpc" in url:   # public, non-archive
            return ProbeResult(reachable=True, chain_id=137, block_number=9, archive=False)
        if "arbitrum" in url or "arb1" in url or "1rpc.io/arb" in url:
            return ProbeResult(reachable=True, chain_id=42161, block_number=9, archive=False)
        return ProbeResult(reachable=False, detail="unreachable")

    # 1) env-provided archive URL wins → configured_archive, host redacted
    env = {"POLYGON_RPC_URL": "https://polygon-mainnet.g.alchemy.com/v2/SECRETKEY"}
    r = rr.resolve_chain_rpc("polygon", env=env, config_rpcs={}, prober=fake_prober)
    _check("env archive URL → configured_archive", r.status == rr.READY_ARCHIVE and r.archive_ready)
    d = r.to_dict()
    _check("URL redacted to host (no key)", "SECRETKEY" not in str(d) and d["host"].endswith("alchemy.com"))

    # 2) nothing configured → probe public list → latest-only (non-archive) → fork_ready, not archive
    r2 = rr.resolve_chain_rpc("polygon", env={}, config_rpcs={}, prober=fake_prober)
    _check("public non-archive → public_latest", r2.status == rr.PUBLIC_LATEST)
    _check("public latest forkable but not archive_ready", r2.fork_ready and not r2.archive_ready)

    # 3) a chain with no public list + nothing configured → needs_key
    r3 = rr.resolve_chain_rpc("zksync", env={}, config_rpcs={}, prober=fake_prober)
    _check("no RPC anywhere → needs_key", r3.status == rr.NEEDS_KEY and not r3.fork_ready)

    # 4) config URL used when env absent
    r4 = rr.resolve_chain_rpc("polygon", env={},
                              config_rpcs={"polygon": "https://polygon-mainnet.g.alchemy.com/v2/K"},
                              prober=fake_prober)
    _check("config URL → source=config, archive", r4.source == "config" and r4.archive_ready)

    # 5) full multi-chain resolve over Gains' chains, deduped
    rpcs = rr.resolve_fork_rpcs(["polygon", "arbitrum", "polygon"], env={}, prober=fake_prober)
    _check("resolve_fork_rpcs dedupes chains", [x.chain for x in rpcs] == ["polygon", "arbitrum"])
    _check("summarize renders hosts only",
           "needs RPC key" in rr.summarize([r3]) and "SECRETKEY" not in rr.summarize(rpcs))


def test_scope_injector(target: Target) -> None:
    block = scope_injector(target, repo_ref="GNS-ethereum")
    _check("injector renders allowlist header", "IN-SCOPE CONTRACT ALLOWLIST" in block)
    _check("injector lists resolved contract→file", "GToken" in block and ".sol" in block)
    _check("injector flags unresolved name", "NotInRepo" in block)
    _check("injector states superset guardrail", "SUPERSET" in block)


def test_board_ranking() -> None:
    html = (_FIX / "immunefi_board.html").read_text()
    cards = imc.parse_board(html)
    _check("board fixture parses ≥5 programs", len(cards) >= 5, str(len(cards)))
    with tempfile.TemporaryDirectory() as td:
        # arbitrum + open KYC, ranked (refresh=True so the injected fetcher is used).
        ranked = imc.list_programs(
            {"allow_kyc": True, "chains": ["arbitrum"]}, refresh=True, cache_dir=td,
            fetcher=lambda url: html)  # type: ignore[arg-type]
        _check("list_programs returns ranked arbitrum set", bool(ranked))
        _check("scores are descending", all(ranked[i].score >= ranked[i + 1].score
                                            for i in range(len(ranked) - 1)))
        default = imc.list_programs({}, refresh=True, cache_dir=td,
                                    fetcher=lambda url: html)  # type: ignore[arg-type]
        _check("kyc filter excludes layerzero by default",
               "layerzero" not in {c.slug for c in default})
        _check("score_breakdown is transparent",
               ranked[0].score_breakdown and "max_bounty" in ranked[0].score_breakdown)


def main() -> int:
    print("S0 Discovery smoke test (offline)\n")
    print("resolve_ref:")
    test_resolve_ref()
    print("parse program → Target:")
    test_parse_program()
    print("expand repo refs (org → repos):")
    test_expand_repo_refs()
    print("explorer verified-source (source of truth):")
    test_parse_etherscan_source()
    test_verified_source_materialization()
    print("map scope → source (allowlist):")
    target, _ = test_map_scope_to_source()
    print("fork-RPC discovery:")
    test_fork_rpc_discovery()
    print("scope injector:")
    test_scope_injector(target)
    print("discovery board + ranking:")
    test_board_ranking()
    print("\nsmoke_s0: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
