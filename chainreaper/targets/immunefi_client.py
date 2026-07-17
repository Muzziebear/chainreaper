"""Immunefi program client (spec §S0 A + C, §12 ``discovery``).

Immunefi is a **Next.js app-router** site: a program page no longer ships a
``<script id="__NEXT_DATA__">`` blob — the structured data is streamed as **RSC
flight chunks** via ``self.__next_f.push([1, "<chunk>"])``. We concatenate those
chunks and pull the program object (a balanced JSON object carrying ``slug`` +
``maxBounty`` + ``assets``) out of the stream. This is far more reliable than
scraping rendered HTML, and the SAME full object appears on all three program
tabs (``information`` / ``scope`` / ``resources``), so we fetch + merge them.

Hard-won realities baked in here (verified live on ``gainsnetwork``):
  * a **blank User-Agent → HTTP 403**, so every request sends one;
  * scope assets are ``{description=NAME, url=explorer-link, type}`` — the deployed
    address + network are parsed out of the explorer URL (NOT a repo/commit);
  * the source repos live in ``programCodebases`` (a *superset* of the in-scope set);
  * a program often pins no commit → the resolver clones HEAD and records the sha.

The network fetch is a single injectable seam (``fetcher``) so parsing + ranking are
unit-tested fully offline against a cached fixture (ZERO network, ZERO tokens).
"""

from __future__ import annotations

import json
import math
import re
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from ..models import ScopeAsset, Target

BASE_URL = "https://immunefi.com"
USER_AGENT = "chainreaper/0.1"
_PROGRAM_PAGES = ("information", "scope", "resources")

# block-explorer host → canonical chain name (mirrors runtime.fork.KNOWN_CHAIN_IDS).
_EXPLORER_NETWORKS: dict[str, str] = {
    "etherscan.io": "ethereum",
    "polygonscan.com": "polygon",
    "arbiscan.io": "arbitrum",
    "snowtrace.io": "avalanche",
    "snowscan.xyz": "avalanche",
    "basescan.org": "base",
    "optimistic.etherscan.io": "optimism",
    "bscscan.com": "bsc",
    "ftmscan.com": "fantom",
    "sonicscan.org": "sonic",
    "gnosisscan.io": "gnosis",
    "lineascan.build": "linea",
    "scrollscan.com": "scroll",
    "blastscan.io": "blast",
    "celoscan.io": "celo",
    "moonscan.io": "moonbeam",
}

# Immunefi ecosystem tag → canonical chain name (board/program ``tags.ecosystem``).
_ECOSYSTEM_ALIASES: dict[str, str] = {
    "eth": "ethereum", "ethereum": "ethereum",
    "arbitrum": "arbitrum", "arbitrum one": "arbitrum",
    "polygon": "polygon", "avalanche": "avalanche", "avax": "avalanche",
    "base": "base", "optimism": "optimism", "op": "optimism",
    "bsc": "bsc", "bnb": "bsc", "fantom": "fantom", "gnosis": "gnosis",
}

_ADDRESS_RE = re.compile(r"0x[a-fA-F0-9]{40}")
_FLIGHT_RE = re.compile(r"self\.__next_f\.push\(\[1,\s*(\".*?\")\]\)", re.S)
_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")


# --------------------------------------------------------------------------- #
# Ref resolution                                                               #
# --------------------------------------------------------------------------- #
@dataclass
class Ref:
    """A resolved ``--target`` argument."""

    kind: str           # slug | immunefi_url | repo_url | local_path
    value: str          # normalized: slug, full url, repo url, or absolute path
    slug: str | None = None


def resolve_ref(ref: str | None) -> Ref:
    """Classify a ``--target`` / ``discover`` argument into one of four kinds.

    Order matters: an existing local path wins (offline dev mode), then an Immunefi
    URL (slug parsed out), then a git/repo URL, then a bare Immunefi slug."""
    if not ref:
        raise ValueError("S0: no target reference provided")
    raw = ref.strip()

    p = Path(raw).expanduser()
    if p.exists():
        return Ref("local_path", str(p.resolve()))

    low = raw.lower()
    if "immunefi.com" in low:
        m = re.search(r"immunefi\.com/bug-bounty/([a-z0-9][a-z0-9_-]*)", low)
        slug = m.group(1) if m else None
        return Ref("immunefi_url", raw, slug=slug)

    if low.endswith(".git") or low.startswith(("http://", "https://", "git@")) or "github.com" in low:
        return Ref("repo_url", raw)

    if _SLUG_RE.match(low):
        return Ref("slug", low, slug=low)

    # an unresolvable non-existent path — surface clearly rather than guessing a slug.
    raise FileNotFoundError(
        f"S0: target {ref!r} is not a local path, Immunefi slug/URL, or repo URL")


# --------------------------------------------------------------------------- #
# Fetch + flight extraction                                                    #
# --------------------------------------------------------------------------- #
def _http_get(url: str, timeout: float = 30.0) -> str:
    """Fetch a URL with a real User-Agent (blank UA → Immunefi 403)."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (fixed immunefi host)
        return r.read().decode("utf-8", "replace")


def _flight_stream(html: str) -> str:
    """Concatenate the RSC flight chunks (``self.__next_f.push([1,"…"])``)."""
    chunks: list[str] = []
    for m in _FLIGHT_RE.finditer(html):
        try:
            chunks.append(json.loads(m.group(1)))
        except (json.JSONDecodeError, ValueError):
            continue
    return "".join(chunks)


def _enclosing_object(s: str, idx: int) -> dict | None:
    """Return the smallest balanced JSON object enclosing ``idx`` that parses.

    String-aware brace matcher: walks back to successive ``{`` candidates and tries
    to balance forward (respecting quoted strings + escapes), returning the first one
    that JSON-parses and contains ``idx``. The smallest such object around a unique
    key (e.g. ``"maxBounty"``) is exactly the program/board record."""
    pos = idx
    while True:
        b = s.rfind("{", 0, pos)
        if b < 0:
            return None
        depth = 0
        instr = False
        esc = False
        end = None
        for j in range(b, len(s)):
            c = s[j]
            if instr:
                if esc:
                    esc = False
                elif c == "\\":
                    esc = True
                elif c == '"':
                    instr = False
            elif c == '"':
                instr = True
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    end = j
                    break
        if end is not None and b <= idx <= end:
            try:
                return json.loads(s[b : end + 1])
            except json.JSONDecodeError:
                pass
        pos = b


def _objects_with(flight: str, anchor: str, *required: str) -> list[dict]:
    """All distinct objects in the flight that enclose an ``anchor`` key and carry
    every ``required`` key. Used to lift program/board records out of the stream."""
    out: list[dict] = []
    seen: set[str] = set()
    needle = f'"{anchor}"'
    for m in re.finditer(re.escape(needle), flight):
        obj = _enclosing_object(flight, m.start())
        if not obj or not all(k in obj for k in required):
            continue
        key = str(obj.get("slug") or obj.get("id") or len(out))
        if key in seen:
            continue
        seen.add(key)
        out.append(obj)
    return out


def extract_program_object(html_or_flight: str, slug: str | None = None) -> dict | None:
    """Pull the single Immunefi program object out of a page (HTML or flight).

    Anchors on ``maxBounty`` (unique per program page) and requires ``slug`` + ``assets``
    so we get the full bounty record, not a nested fragment."""
    flight = (_flight_stream(html_or_flight)
              if "self.__next_f" in html_or_flight else html_or_flight)
    cands = _objects_with(flight, "maxBounty", "slug", "assets")
    if not cands:
        cands = _objects_with(flight, "assets", "slug")
    if slug:
        for o in cands:
            if o.get("slug") == slug:
                return o
    return cands[0] if cands else None


# --------------------------------------------------------------------------- #
# Normalized program model                                                     #
# --------------------------------------------------------------------------- #
@dataclass
class ContractScope:
    name: str
    address: str | None
    network: str | None
    explorer_url: str
    type: str = "smart_contract"


@dataclass
class ImmunefiProgram:
    slug: str
    name: str
    url: str = ""
    max_bounty_usd: float | None = None
    total_paid_usd: float | None = None
    kyc_required: bool = False
    poc_required: bool = False
    languages: list[str] = field(default_factory=list)
    chains: list[str] = field(default_factory=list)
    program_type: str = "smart_contract"
    impacts_in_scope: list[str] = field(default_factory=list)
    contracts: list[ContractScope] = field(default_factory=list)   # in-scope contract addresses
    websites: list[dict] = field(default_factory=list)             # in-scope web assets (not code)
    repos: list[dict] = field(default_factory=list)                # source repos (superset)
    raw: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = {k: v for k, v in self.__dict__.items() if k != "raw"}
        d["contracts"] = [c.__dict__ for c in self.contracts]
        return d


def _network_from_url(url: str) -> str | None:
    low = (url or "").lower()
    for host, net in _EXPLORER_NETWORKS.items():
        if host in low:
            return net
    return None


def _address_from_url(url: str) -> str | None:
    m = _ADDRESS_RE.search(url or "")
    return m.group(0) if m else None


def _is_explorer(url: str) -> bool:
    return any(host in (url or "").lower() for host in _EXPLORER_NETWORKS)


def _github_repo_root(url: str) -> str | None:
    """Normalize any github.com URL (repo / tree / blob / sub-path) to its cloneable
    ``https://github.com/<owner>/<repo>`` root. Returns None for non-github URLs and for
    org-only URLs (no repo) — those are left to ``expand_repo_refs``."""
    if not url or "github.com" not in url.lower():
        return None
    after = url.split("github.com", 1)[1].lstrip("/:")
    parts = [p for p in after.split("/") if p]
    if len(parts) < 2:
        return None
    owner, repo = parts[0], parts[1]
    repo = repo[:-4] if repo.endswith(".git") else repo
    return f"https://github.com/{owner}/{repo}"


def _map_program_type(program_types: list[str]) -> str:
    pts = {str(t).strip().lower() for t in program_types}
    has_sc = any("smart contract" in t or t == "smart_contract" for t in pts)
    has_web = any("website" in t or "application" in t for t in pts)
    if has_sc and has_web:
        return "mixed"
    if has_sc:
        return "smart_contract"
    if has_web:
        return "web"
    return "smart_contract"


_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 4, "": 5}


def _impacts(obj: dict) -> list[str]:
    rows = obj.get("programImpacts") or obj.get("impacts") or []
    out: list[tuple[int, str]] = []
    seen: set[str] = set()
    for r in rows:
        if not isinstance(r, dict):
            continue
        text = (r.get("description") or r.get("title") or "").strip()
        if not text or text.lower() in seen:
            continue
        seen.add(text.lower())
        out.append((_SEV_ORDER.get(str(r.get("severity") or "").lower(), 5), text))
    out.sort(key=lambda t: t[0])
    return [t[1] for t in out[:16]]


def _norm_chains(tags: dict) -> list[str]:
    eco = tags.get("ecosystem") or []
    out: list[str] = []
    for c in eco:
        n = _ECOSYSTEM_ALIASES.get(str(c).strip().lower(), str(c).strip().lower())
        if n and n not in out:
            out.append(n)
    return out


def parse_program_object(obj: dict) -> ImmunefiProgram:
    """Pure parse of an Immunefi program object → :class:`ImmunefiProgram`.

    Unit-tested directly against the cached fixture (no network)."""
    tags = obj.get("tags") or {}
    languages = [str(x).strip().lower() for x in (tags.get("language") or [])]
    slug = obj.get("slug") or ""

    contracts: list[ContractScope] = []
    websites: list[dict] = []
    for a in obj.get("assets") or []:
        if not isinstance(a, dict):
            continue
        url = a.get("url") or ""
        name = (a.get("description") or a.get("title") or "").strip()
        atype = (a.get("type") or "").strip()
        if atype == "smart_contract" or _is_explorer(url):
            contracts.append(ContractScope(
                name=name, address=_address_from_url(url),
                network=_network_from_url(url), explorer_url=url, type=atype or "smart_contract"))
        else:
            websites.append({"name": name, "url": url, "type": atype})

    repos: list[dict] = []
    seen_repo: set[str] = set()
    for cb in obj.get("programCodebases") or []:
        if isinstance(cb, dict) and cb.get("url"):
            u = str(cb["url"]).strip()
            if u not in seen_repo:
                seen_repo.add(u)
                repos.append({"url": u, "title": cb.get("title") or ""})
    gh = obj.get("githubUrl")
    if gh and str(gh).strip() and str(gh).strip() not in seen_repo:
        repos.append({"url": str(gh).strip(), "title": "githubUrl"})
    # Some programs (e.g. MUX) list their in-scope SOURCE as `smart_contract` assets whose
    # url is a GitHub link (no deployed address) rather than via programCodebases — so the
    # repo set would be empty and S0 has nothing to clone. Harvest repo roots from any
    # github-URL asset so repo-mode can clone them (the assets still carry the sub-path for
    # the scope allowlist). Normalize tree/blob/sub-path URLs to the cloneable owner/repo.
    for c in contracts:
        root = _github_repo_root(c.explorer_url)
        if root and root not in seen_repo:
            seen_repo.add(root)
            repos.append({"url": root, "title": "scope-asset"})

    max_bounty = obj.get("maxBounty")
    return ImmunefiProgram(
        slug=slug,
        name=obj.get("project") or slug,
        url=f"{BASE_URL}/bug-bounty/{slug}/" if slug else "",
        max_bounty_usd=float(max_bounty) if isinstance(max_bounty, (int, float)) else None,
        total_paid_usd=None,
        kyc_required=bool(obj.get("kyc")),
        poc_required=str(obj.get("proofOfConceptType") or "").lower() == "required",
        languages=languages,
        chains=_norm_chains(tags),
        program_type=_map_program_type(tags.get("programType") or []),
        impacts_in_scope=_impacts(obj),
        contracts=contracts,
        websites=websites,
        repos=repos,
        raw=obj,
    )


def program_to_target(program: ImmunefiProgram) -> Target:
    """Build the metadata :class:`Target` from a parsed program — WITHOUT clones
    (the source resolver appends ``local_path`` clone assets + the allowlist in S0).

    Carries the in-scope contract-address assets + in-scope web assets + the source
    repos so the Target is complete and inspectable even before any clone (and the
    offline smoke test asserts on exactly this)."""
    impacts = program.impacts_in_scope
    assets: list[ScopeAsset] = []
    for c in program.contracts:
        assets.append(ScopeAsset(
            kind="contract_address", ref=c.address or c.explorer_url, in_scope=True,
            impacts_in_scope=impacts, name=c.name, address=c.address,
            network=c.network, explorer_url=c.explorer_url))
    for w in program.websites:
        assets.append(ScopeAsset(kind="website", ref=w.get("url") or "", in_scope=True,
                                 name=w.get("name")))
    for r in program.repos:
        assets.append(ScopeAsset(kind="github_repo", ref=r["url"], in_scope=True,
                                 name=r.get("title") or "", source_repo=r["url"]))
    return Target(
        program_id=program.slug,
        name=program.name,
        url=program.url,
        max_bounty_usd=program.max_bounty_usd,
        total_paid_usd=program.total_paid_usd,
        poc_required=program.poc_required,
        assets_in_scope=assets,
        chains=program.chains,
        languages=program.languages or ["solidity"],
        kyc_required=program.kyc_required,
        program_type=program.program_type,  # type: ignore[arg-type]
    )


# --------------------------------------------------------------------------- #
# Fetch + snapshot cache                                                        #
# --------------------------------------------------------------------------- #
def _slug_cache_dir(cache_dir: str | Path, slug: str) -> Path:
    return Path(cache_dir) / slug


def fetch_program(
    slug: str,
    *,
    refresh: bool = False,
    cache_dir: str | Path = "runs/_targets",
    fetcher: Callable[[str], str] = _http_get,
) -> ImmunefiProgram:
    """Fetch + merge a program's three tabs and return a parsed :class:`ImmunefiProgram`.

    The full object is identical across tabs, so we take the first that yields one and
    merge any extra keys from the others (defensive against future data splits). Caches
    the parsed object under ``<cache_dir>/<slug>/program.json``; ``refresh`` re-pulls."""
    cdir = _slug_cache_dir(cache_dir, slug)
    snap = cdir / "program.json"
    if snap.exists() and not refresh:
        return parse_program_object(json.loads(snap.read_text()))

    cdir.mkdir(parents=True, exist_ok=True)
    merged: dict = {}
    errors: list[str] = []
    for page in _PROGRAM_PAGES:
        url = f"{BASE_URL}/bug-bounty/{slug}/{page}/"
        try:
            html = fetcher(url)
        except Exception as exc:  # network/HTTP — tolerate per-page, need only one
            errors.append(f"{page}: {type(exc).__name__}: {str(exc)[:120]}")
            continue
        obj = extract_program_object(html, slug=slug)
        if not obj:
            errors.append(f"{page}: no program object in flight stream")
            continue
        (cdir / f"raw_{page}.json").write_text(json.dumps(obj))
        for k, v in obj.items():
            if k not in merged or (not merged.get(k) and v):
                merged[k] = v
    if not merged:
        raise RuntimeError(f"Immunefi: could not load program {slug!r} ({'; '.join(errors) or 'no data'})")
    merged.setdefault("slug", slug)
    snap.write_text(json.dumps(merged))
    return parse_program_object(merged)


# --------------------------------------------------------------------------- #
# Discovery board + ranking                                                     #
# --------------------------------------------------------------------------- #
@dataclass
class ProgramCard:
    """A normalized board entry for filtering + ranking (discover mode)."""

    slug: str
    name: str
    url: str
    max_bounty_usd: float | None
    kyc_required: bool
    poc_required: bool
    languages: list[str]
    chains: list[str]
    product_types: list[str]
    program_types: list[str]
    open_source: bool | None = None     # known only after a program fetch (board lacks assets)
    score: float = 0.0
    score_breakdown: dict[str, float] = field(default_factory=dict)


def _card_from_obj(obj: dict) -> ProgramCard:
    tags = obj.get("tags") or {}
    slug = obj.get("slug") or ""
    mb = obj.get("maxBounty")
    return ProgramCard(
        slug=slug,
        name=obj.get("project") or slug,
        url=f"{BASE_URL}/bug-bounty/{slug}/",
        max_bounty_usd=float(mb) if isinstance(mb, (int, float)) else None,
        kyc_required=bool(obj.get("kyc")),
        poc_required=str(obj.get("proofOfConceptType") or "").lower() == "required",
        languages=[str(x).strip().lower() for x in (tags.get("language") or [])],
        chains=_norm_chains(tags),
        product_types=[str(x).strip().lower() for x in (tags.get("productType") or [])],
        program_types=[str(x).strip().lower() for x in (tags.get("programType") or [])],
    )


DEFAULT_RANKING_WEIGHTS = {
    "max_bounty": 0.30, "total_paid": 0.20, "open_source": 0.20,
    "sc_focus": 0.15, "scope_clarity": 0.10, "kyc_penalty": 0.05,
    "crowd_saturation": 0.0,
}


def score_card(card: ProgramCard, weights: dict | None = None,
               *, board_max_bounty: float = 15_000_000.0) -> ProgramCard:
    """Transparent, configurable ranking (spec §S0 C). Each component is normalized to
    [0,1] and the weighted sum is recorded in ``score_breakdown`` so a ranking is always
    explainable. ``max_bounty`` is log-scaled so a single mega-bounty doesn't dominate."""
    w = {**DEFAULT_RANKING_WEIGHTS, **(weights or {})}
    mb = card.max_bounty_usd or 0.0
    ref = max(board_max_bounty, mb, 1.0)
    norm_bounty = math.log10(1 + mb) / math.log10(1 + ref) if mb > 0 else 0.0
    sc_focus = 1.0 if any("smart contract" in t for t in card.program_types) else 0.0
    # open-source is unknown from the board → neutral 0.5; precise once a program is fetched.
    open_source = 0.5 if card.open_source is None else (1.0 if card.open_source else 0.0)
    scope_clarity = 1.0 if (card.max_bounty_usd and card.chains and card.languages) else 0.4
    kyc_pen = 1.0 if card.kyc_required else 0.0

    comp = {
        "max_bounty": w["max_bounty"] * norm_bounty,
        "total_paid": 0.0,  # board has no total-paid; kept for parity with the formula
        "open_source": w["open_source"] * open_source,
        "sc_focus": w["sc_focus"] * sc_focus,
        "scope_clarity": w["scope_clarity"] * scope_clarity,
        "kyc_penalty": -w["kyc_penalty"] * kyc_pen,
        "crowd_saturation": 0.0,
    }
    card.score = round(sum(comp.values()), 4)
    card.score_breakdown = {k: round(v, 4) for k, v in comp.items()}
    return card


def _card_matches(card: ProgramCard, filters: dict) -> bool:
    f = filters or {}
    if f.get("open_source_only") and card.open_source is False:
        return False  # board can't prove open-source; only excludes KNOWN-closed
    if not f.get("allow_kyc", False) and card.kyc_required:
        return False
    min_b = f.get("min_max_bounty_usd")
    if min_b and (card.max_bounty_usd or 0) < float(min_b):
        return False
    want_chains = {str(c).lower() for c in (f.get("chains") or [])}
    if want_chains and not (want_chains & set(card.chains)):
        return False
    want_langs = {str(x).lower() for x in (f.get("languages") or [])}
    if want_langs and not (want_langs & set(card.languages)):
        return False
    return True


def parse_board(html_or_flight: str) -> list[ProgramCard]:
    """Lift every program card out of the explore-board flight stream."""
    flight = (_flight_stream(html_or_flight)
              if "self.__next_f" in html_or_flight else html_or_flight)
    cards = [_card_from_obj(o) for o in _objects_with(flight, "maxBounty", "slug", "project")]
    return [c for c in cards if c.slug]


def list_programs(
    filters: dict | None = None,
    *,
    refresh: bool = False,
    weights: dict | None = None,
    cache_dir: str | Path = "runs/_targets",
    fetcher: Callable[[str], str] = _http_get,
) -> list[ProgramCard]:
    """Pull + filter + rank the Immunefi board (discover mode). Caches the raw board
    flight under ``<cache_dir>/_board.flight``; ``refresh`` re-pulls."""
    cache = Path(cache_dir) / "_board.flight"
    if cache.exists() and not refresh:
        flight = cache.read_text()
    else:
        flight = _flight_stream(fetcher(f"{BASE_URL}/bug-bounty/"))
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(flight)
    cards = parse_board(flight)
    board_max = max([c.max_bounty_usd or 0 for c in cards] or [1.0])
    kept = [c for c in cards if _card_matches(c, filters or {})]
    for c in kept:
        score_card(c, weights, board_max_bounty=board_max)
    kept.sort(key=lambda c: c.score, reverse=True)
    return kept
