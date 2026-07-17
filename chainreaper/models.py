"""Core data model — the inter-stage Pydantic contracts (spec §5).

This module is the foundation: the same classes that define stage hand-offs are
(later) the LLM structured-output schemas (IMPL-NOTES §6). For the M1-spine + S1
slice we only need the **Discovery** and **Index** contracts plus the shared
enums and coercion helpers; the Recon/Hunt/Validate contracts are added when
their stages land.

Coercion helpers (`coerce_confidence`, `coerce_enum`, `coerce_int`) are ported
from the Visa pattern so a malformed LLM token degrades gracefully into a valid
value instead of raising — they're not used in deterministic S1 but live here so
S2+ emitters can reuse them.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

SCHEMA_VERSION = "0.1"


# --------------------------------------------------------------------------- #
# Enums                                                                        #
# --------------------------------------------------------------------------- #
class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class TaskStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    DONE = "done"
    DROPPED = "dropped"


class TriggerClass(str, Enum):
    """HOW a finding's impact is reached — the adversary-model classification the Hunter
    must self-assign. Only ``attacker_reachable`` is a payable, live-exploitable bug; the
    rest are honest downgrades (real defect, but the trigger is not attacker-controlled or
    not currently reachable). This moves the S5 liveness gate UPSTREAM into the emit.

      * ``attacker_reachable`` — impact reached using ONLY attacker-controlled inputs
        (own txns/capital, flash loans, permissionless entrypoints, tx ordering). PAYABLE.
      * ``external_condition`` — needs an assumed-honest dependency to misbehave (oracle
        returns a bad price, an external protocol reverts/pauses). Usually out of scope.
      * ``privileged_role`` — needs an admin/owner/trusted-role action on the attack path
        (a prank/setX of a gated role). Out of scope on most programs.
      * ``latent`` — a real defect with NO currently-reachable trigger (e.g. behind a
        disabled flag, an un-wired contract, or a future upgrade). Hardening note, not live.
    """

    ATTACKER_REACHABLE = "attacker_reachable"
    EXTERNAL_CONDITION = "external_condition"
    PRIVILEGED_ROLE = "privileged_role"
    LATENT = "latent"


class InvariantCategory(str, Enum):
    SOLVENCY = "solvency"
    SHARE_PRICE = "share_price"
    POSITION_PNL = "position_pnl"
    LIQUIDATION = "liquidation"
    ORACLE = "oracle"
    FEE = "fee"
    EXECUTION = "execution"
    ACCESS = "access"
    CROSS_MODULE = "cross_module"


class VulnClass(str, Enum):
    """OWASP Smart Contract Top-10 (2026) + blockchain extras (spec §5 / §9).

    Enum *values* are stable identifiers (used by prefilter / recon routing /
    incident catalog), so the 2026 re-ranking is reflected in the SC codes (see
    ``VULN_SC_TOP10``), NOT by renaming values. The 2026 list reordered the field
    (Business Logic → SC02, Flash Loan → SC04, Reentrancy → SC08) and dropped DoS
    and Bad-Randomness from the top 10 (kept here as real extras), adding Arithmetic
    Errors (SC07) and Proxy & Upgradeability (SC10)."""

    # --- OWASP SC Top-10 (2026) -------------------------------------------- #
    ACCESS_CONTROL = "access_control"             # SC01 Access Control
    LOGIC_ERROR = "logic_error"                   # SC02 Business Logic
    PRICE_ORACLE = "price_oracle_manipulation"    # SC03 Price Oracle Manipulation
    FLASH_LOAN = "flash_loan_attack"              # SC04 Flash Loan-Facilitated Attacks
    INPUT_VALIDATION = "input_validation"         # SC05 Lack of Input Validation
    UNCHECKED_CALLS = "unchecked_external_calls"  # SC06 Unchecked External Calls
    ARITHMETIC_ERROR = "arithmetic_error"         # SC07 Arithmetic Errors (rounding/precision)
    REENTRANCY = "reentrancy"                     # SC08 Reentrancy Attacks
    INTEGER_OVERFLOW = "integer_overflow"         # SC09 Integer Overflow & Underflow
    PROXY_UPGRADE = "proxy_upgradeability"        # SC10 Proxy & Upgradeability
    # --- blockchain extras (real classes; not in the 2026 top-10) ---------- #
    DOS = "denial_of_service"                       # liveness/DoS → freezing/insolvency
    BAD_RANDOMNESS = "bad_randomness"
    READONLY_REENTRANCY = "readonly_reentrancy"     # subtype of SC08
    FIRST_DEPOSITOR = "first_depositor_inflation"   # ERC-4626
    SIGNATURE_REPLAY = "signature_replay"
    SIGNATURE_MALLEABILITY = "signature_malleability"
    MEV_FRONTRUN = "mev_frontrunning"
    BRIDGE_REPLAY = "bridge_replay"
    UNBOUNDED_LOOP = "unbounded_loop_dos"
    GAS_GRIEFING = "gas_griefing"
    STORAGE_COLLISION = "storage_collision"         # subtype of SC10
    SELECTOR_CLASH = "selector_clash"               # subtype of SC10
    OTHER = "other"


# Canonical OWASP SC Top-10 (2026) code for each VulnClass value — the single
# source of truth a Finding's ``sc_top10`` should carry. Extras map to the nearest
# top-10 bucket (e.g. read-only reentrancy → SC08; storage-collision → SC10) so a
# finding always carries a top-10 code; ``None`` only for the catch-all ``other``.
VULN_SC_TOP10: dict[str, str | None] = {
    "access_control": "SC01",
    "logic_error": "SC02",
    "price_oracle_manipulation": "SC03",
    "flash_loan_attack": "SC04",
    "input_validation": "SC05",
    "unchecked_external_calls": "SC06",
    "arithmetic_error": "SC07",
    "reentrancy": "SC08",
    "integer_overflow": "SC09",
    "proxy_upgradeability": "SC10",
    # extras → nearest top-10 bucket
    "denial_of_service": "SC02",          # liveness break is a business-logic failure
    "bad_randomness": "SC02",
    "readonly_reentrancy": "SC08",
    "first_depositor_inflation": "SC07",  # share/AUM inflation = an arithmetic error
    "signature_replay": "SC01",           # auth bypass
    "signature_malleability": "SC01",
    "mev_frontrunning": "SC02",
    "bridge_replay": "SC01",
    "unbounded_loop_dos": "SC02",
    "gas_griefing": "SC02",
    "storage_collision": "SC10",
    "selector_clash": "SC10",
    "other": None,
}


def sc_top10_for(vuln_class: Any) -> str | None:
    """The OWASP SC Top-10 (2026) code for a ``VulnClass`` (member, value, or token)."""
    v = vuln_class.value if isinstance(vuln_class, VulnClass) else str(vuln_class)
    if v in VULN_SC_TOP10:
        return VULN_SC_TOP10[v]
    m = coerce_enum(v, VulnClass, default=None)
    return VULN_SC_TOP10.get(m.value) if m is not None else None


# --------------------------------------------------------------------------- #
# Coercion helpers (Visa pattern) — graceful degradation of LLM tokens        #
# --------------------------------------------------------------------------- #
def coerce_confidence(value: Any, default: float = 0.5) -> float:
    """Coerce an arbitrary token into a [0,1] confidence float.

    Accepts floats, ints, "0.7", "70%", or qualitative words (high/medium/low).
    """
    if isinstance(value, bool):  # bool is an int subclass; reject early
        return 1.0 if value else 0.0
    if isinstance(value, (int, float)):
        v = float(value)
        return min(1.0, max(0.0, v / 100.0 if v > 1.0 else v))
    if isinstance(value, str):
        s = value.strip().lower().rstrip("%")
        words = {"certain": 1.0, "high": 0.85, "likely": 0.7, "medium": 0.5,
                 "moderate": 0.5, "low": 0.25, "unlikely": 0.15, "none": 0.0}
        if s in words:
            return words[s]
        try:
            v = float(s)
            return min(1.0, max(0.0, v / 100.0 if v > 1.0 else v))
        except ValueError:
            return default
    return default


def coerce_enum(value: Any, enum_cls: type[Enum], default: Enum | None = None) -> Enum | None:
    """Best-effort map a token onto an Enum member (by value or name, case/sep-insensitive)."""
    if isinstance(value, enum_cls):
        return value
    if value is None:
        return default
    norm = str(value).strip().lower().replace("-", "_").replace(" ", "_")
    for member in enum_cls:
        mv = str(member.value).lower()
        if norm == mv or norm == member.name.lower():
            return member
    # substring fallback (e.g. "reentrancy bug" -> REENTRANCY)
    for member in enum_cls:
        if norm in str(member.value).lower() or str(member.value).lower() in norm:
            return member
    return default


def coerce_to_model(cls: type, data: Any) -> Any:
    """Recursively coerce a raw dict toward a Pydantic model's field types before
    validation — the deterministic-formatting layer for LLM-emitted JSON.

    Enum/Literal fields are snapped to the nearest valid member (so a near-miss
    token like ``"reentrancy bug"`` becomes ``reentrancy`` instead of failing
    validation and forcing the agent to re-emit). Nested models/lists/Optionals
    recurse. Unknown fields and types pass through untouched (validation still
    catches genuinely malformed data)."""
    import types as _t
    from typing import Literal, Union, get_args, get_origin

    def _coerce(annotation: Any, value: Any) -> Any:
        origin = get_origin(annotation)
        if origin is Union or origin is getattr(_t, "UnionType", ()):  # Optional[X]/X|None
            args = [a for a in get_args(annotation) if a is not type(None)]
            if value is None or not args:
                return value
            return _coerce(args[0], value)
        if origin in (list, list.__class__) or origin is list:
            inner = (get_args(annotation) or (str,))[0]
            return [_coerce(inner, v) for v in value] if isinstance(value, list) else value
        if origin is Literal:
            allowed = get_args(annotation)
            return value if value in allowed else allowed[0]
        if isinstance(annotation, type) and issubclass(annotation, Enum):
            m = coerce_enum(value, annotation, default=None)
            if m is not None:
                return m.value
            fallback = getattr(annotation, "OTHER", None)
            return (fallback.value if fallback is not None else next(iter(annotation)).value)
        if isinstance(annotation, type) and issubclass(annotation, BaseModel):
            return coerce_to_model(annotation, value)
        return value

    if not isinstance(data, dict):
        return data
    out = dict(data)
    for name, field in cls.model_fields.items():
        if name in out:
            try:
                out[name] = _coerce(field.annotation, out[name])
            except Exception:
                pass  # leave as-is; validation reports the real problem
    return out


def coerce_int(value: Any, default: int = 0, lo: int | None = None, hi: int | None = None) -> int:
    """Coerce to int, clamping to [lo, hi] when bounds are given."""
    try:
        if isinstance(value, str):
            value = value.strip().split()[0].rstrip("%")
        out = int(float(value))
    except (ValueError, TypeError, IndexError):
        out = default
    if lo is not None:
        out = max(lo, out)
    if hi is not None:
        out = min(hi, out)
    return out


# --------------------------------------------------------------------------- #
# Discovery contracts (spec §5)                                                #
# --------------------------------------------------------------------------- #
class ScopeAsset(BaseModel):
    schema_version: str = SCHEMA_VERSION
    kind: Literal["github_repo", "contract_address", "npm", "docs", "website", "local_path"]
    ref: str                                  # url / address / path
    in_scope: bool = True
    impacts_in_scope: list[str] = Field(default_factory=list)
    # --- S0 full-discovery enrichment (all optional → backward-compatible with the
    # local-path stub and the older 5-field ScopeAsset). The Immunefi scope/ page lists
    # in-scope contracts by NAME + NETWORK + deployed ADDRESS (explorer links), and the
    # resources/ page holds the source repos; these fields carry that provenance so S0
    # can bridge "in-scope address" → "source file" (see ``Target.scope_allowlist``). ---
    name: str | None = None                   # contract / repo name (e.g. "GToken")
    address: str | None = None                # deployed address (contract_address assets)
    network: str | None = None                # chain the address/clone belongs to
    explorer_url: str | None = None           # block-explorer link for an address asset
    revision: str | None = None               # pinned commit/tag OR resolved HEAD sha (repos/clones)
    source_repo: str | None = None            # repo URL a cloned local_path came from


class InScopeContract(BaseModel):
    """One row of the S0 **in-scope contract allowlist** (spec §S0 B).

    Bridges an Immunefi scope asset (contract ``name`` + deployed ``address`` +
    ``network``) to the ``file`` it lives in inside the cloned *superset* repo, matched
    by Solidity contract NAME. Because the clone holds ALL of a protocol's contracts but
    only the scope/ names are in-scope, the scope injector renders this allowlist so S2+
    never wanders into out-of-scope contracts. Deterministic S0 output — never LLM-written."""

    name: str
    address: str | None = None
    network: str | None = None
    file: str | None = None                   # repo-relative source path (None ⇒ unresolved)
    source_repo: str | None = None            # which cloned repo the file was found in
    resolved: bool = False                    # a matching contract definition was located


class Target(BaseModel):
    schema_version: str = SCHEMA_VERSION
    program_id: str                           # immunefi slug (or local id)
    name: str
    url: str = ""
    max_bounty_usd: float | None = None
    total_paid_usd: float | None = None
    poc_required: bool = False                # Immunefi "proofOfConceptType == required"
    assets_in_scope: list[ScopeAsset] = Field(default_factory=list)
    scope_allowlist: list[InScopeContract] = Field(default_factory=list)  # in-scope contract names→files
    chains: list[str] = Field(default_factory=list)
    languages: list[str] = Field(default_factory=list)
    kyc_required: bool = False
    program_type: Literal["smart_contract", "web", "blockchain_dlt", "mixed"] = "smart_contract"
    score: float = 0.0
    score_breakdown: dict[str, float] = Field(default_factory=dict)
    fork_preview: list[dict] = Field(default_factory=list)  # S0 fork-RPC discovery (redacted hosts)


# --------------------------------------------------------------------------- #
# Index contracts (spec §5)                                                    #
# --------------------------------------------------------------------------- #
class IndexedFile(BaseModel):
    path: str                                 # repo-relative
    language: str | None = None
    loc: int | None = None
    sha256: str | None = None


class ContractNode(BaseModel):
    name: str
    kind: Literal["contract", "interface", "library", "abstract"] = "contract"
    file: str | None = None
    line: int | None = None
    inherits: list[str] = Field(default_factory=list)


class CallEdge(BaseModel):
    caller_sig: str
    callee_sig: str
    call_type: Literal["internal", "external", "low_level", "delegatecall",
                       "library", "event", "solidity"] = "internal"
    external: bool = False
    line: int | None = None


class StateVar(BaseModel):
    contract: str
    name: str
    type: str | None = None
    visibility: str | None = None
    is_constant: bool = False
    is_immutable: bool = False
    slot: int | None = None                   # nullable in S1
    line: int | None = None


class Entrypoint(BaseModel):
    contract: str
    name: str
    signature: str
    visibility: str                           # public | external
    mutability: str | None = None
    modifiers: list[str] = Field(default_factory=list)
    file: str | None = None
    line_start: int | None = None
    line_end: int | None = None


class Sink(BaseModel):
    contract: str | None = None
    func_signature: str
    kind: Literal["low_level_call", "delegatecall", "transfer", "send", "ecrecover",
                  "selfdestruct", "external_call", "unchecked_math", "oracle_read"]
    detail: str | None = None
    line: int | None = None


class ProxyInfo(BaseModel):
    contract: str | None = None
    pattern: str | None = None                # transparent | uups | beacon | minimal | none
    impl_slot: str | None = None
    init_guard: bool | None = None


class IndexedRepo(BaseModel):
    schema_version: str = SCHEMA_VERSION
    repo_ref: str
    language: str
    files: list[IndexedFile] = Field(default_factory=list)
    contracts: list[ContractNode] = Field(default_factory=list)
    call_graph: list[CallEdge] = Field(default_factory=list)
    state_vars: list[StateVar] = Field(default_factory=list)
    entrypoints: list[Entrypoint] = Field(default_factory=list)
    external_calls: list[Sink] = Field(default_factory=list)
    proxy_info: ProxyInfo | None = None
    sast_raw: dict = Field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Recon contracts (spec §5 "Recon", §6 "S2 Recon")                            #
# --------------------------------------------------------------------------- #
# Design note (IMPL-NOTES §6, build directive): the *leaf* models below are the
# LLM structured-output schemas — every one sets ``extra="forbid"`` so the
# Anthropic SDK's ``transform_schema`` emits ``additionalProperties:false``
# (required for structured outputs). They are deliberately flat: no recursion,
# no min/max/length constraints, no free-form ``dict`` fields. The large
# container models (``ReconProfile``, ``InvariantSuite``) are NOT emitted in a
# single ``messages.parse`` call — they are assembled in Python from the
# decomposed emit-schemas (``ArchitectureReport`` / ``ThreatModel`` /
# ``HunterTaskList`` / ``InvariantList``), so they may carry ``dict`` fields the
# structured-output path forbids.

InvariantTool = Literal[
    "foundry", "medusa", "echidna", "halmos", "certora", "wake", "slither", "properties"
]


class TrustBoundary(BaseModel):
    """A line across which trust changes (wallet→contract, chain→bridge, …)."""

    model_config = ConfigDict(extra="forbid")

    name: str
    description: str
    actors: list[str] = Field(default_factory=list)       # parties on each side
    crossing: str = ""                                    # what crosses (funds/messages/signatures)
    controls: list[str] = Field(default_factory=list)     # mechanisms enforcing the boundary


class Role(BaseModel):
    """A privileged role / authority in the system."""

    model_config = ConfigDict(extra="forbid")

    name: str
    description: str
    capabilities: list[str] = Field(default_factory=list)  # what it can do
    granted_in: list[str] = Field(default_factory=list)    # contracts/modifiers enforcing it


class HotZone(BaseModel):
    """A ranked high-impact code region (spec: high_impact_areas)."""

    model_config = ConfigDict(extra="forbid")

    rank: int                                              # 1 = highest
    title: str
    contracts: list[str] = Field(default_factory=list)
    functions: list[str] = Field(default_factory=list)     # signatures or file:symbol
    rationale: str = ""                                    # why high-impact ($-terms where possible)
    vuln_classes: list[VulnClass] = Field(default_factory=list)


class ThreatEntry(BaseModel):
    """One asset→threat→control row of the STRIDE-ish threat model."""

    model_config = ConfigDict(extra="forbid")

    asset: str
    threat: str
    stride: str = ""                                       # S/T/R/I/D/E (or SCSVS category)
    existing_control: str = ""
    gap: str = ""                                          # residual risk worth hunting


class ThreatModel(BaseModel):
    """STRIDE-style asset→threat→existing-control mapping (emit-schema)."""

    model_config = ConfigDict(extra="forbid")

    summary: str = ""
    entries: list[ThreatEntry] = Field(default_factory=list)


class ProtocolNode(BaseModel):
    """A node in the protocol interaction graph (T2.1): an in-scope contract OR an
    external integration (oracle / AMM / bridge / lending market / token). The graph
    is what makes multi-hop, cross-contract attacks visible to the hunter."""

    model_config = ConfigDict(extra="forbid")

    name: str                                              # contract name or integration label
    kind: str = "contract"                                 # contract|oracle|amm|bridge|lending|token|external
    external: bool = False                                 # outside the in-scope code (3rd-party integration)
    detail: str = ""                                       # role / address / which protocol
    # Tier-4 P3 — what the in-scope protocol IMPLICITLY TRUSTS about this (external)
    # integration, e.g. "assumes Curve get_virtual_price is manipulation-resistant",
    # "assumes Aave never pauses", "trusts the LZ endpoint to deliver authentic msgs".
    # Each is a latent failure mode: a dep-misbehavior HunterTask attacks it on-fork.
    trust_assumptions: list[str] = Field(default_factory=list)


class ProtocolEdge(BaseModel):
    """A directed interaction between two protocol nodes (T2.1) — the hop an exploit
    can travel: a price read, an AMM swap, a bridge message, a liquidation trigger,
    a flash-loan source."""

    model_config = ConfigDict(extra="forbid")

    src: str                                               # source node name
    dst: str                                               # destination node name
    kind: str = "call"                                     # call|read|oracle_read|amm_swap|bridge_msg|liquidation|flashloan_source|price_dep|collateral
    detail: str = ""                                       # what crosses / why it matters for an attack


class ProtocolGraph(BaseModel):
    """The protocol interaction graph — nodes + edges (T2.1). A Recon deliverable
    (emitted as part of the profile) that surfaces the cross-contract / economic
    chains single-contract tasks miss (oracle→AMM→liquidation, flash-loan-amplified)."""

    model_config = ConfigDict(extra="forbid")

    nodes: list[ProtocolNode] = Field(default_factory=list)
    edges: list[ProtocolEdge] = Field(default_factory=list)


class Invariant(BaseModel):
    """A codebase-specific, testable property (spec §5). Emit-schema element."""

    model_config = ConfigDict(extra="forbid")

    inv_id: str                                            # stable handle, e.g. "PRICE-01"
    category: InvariantCategory
    statement: str                                         # precise, testable property
    hooks: list[str] = Field(default_factory=list)         # exact file:symbol bindings (S1)
    tool: InvariantTool = "medusa"
    severity: Severity = Severity.MEDIUM
    origin: Literal["catalog", "codebase_synth", "prior_finding", "spec"] = "codebase_synth"
    harness_ref: str | None = None                         # path to generated handler/test stub
    status: Literal["proposed", "scaffolded", "passing", "violated"] = "proposed"


class InvariantSuite(BaseModel):
    """Container assembled in Python (NOT an emit-schema — carries dicts)."""

    target: str
    invariants: list[Invariant] = Field(default_factory=list)
    handler_files: dict[str, str] = Field(default_factory=dict)   # path -> content
    runner_config: dict = Field(default_factory=dict)             # medusa.json/echidna.yaml/...
    coverage_map: dict = Field(default_factory=dict)              # inv_id -> hook-binding report


class HunterTask(BaseModel):
    """One narrow task: one vuln-class × one code region (spec §5)."""

    model_config = ConfigDict(extra="forbid")

    task_id: str
    title: str
    vuln_class: VulnClass
    scope_hint: str                                        # exact files/functions/contracts
    hypothesis: str                                        # what to try to prove
    suggested_skills: list[str] = Field(default_factory=list)
    priority: int = 2                                      # 1..4 (P1 highest)
    origin: Literal["recon", "gapfill", "feedback", "threat_research"] = "recon"
    status: TaskStatus = TaskStatus.PENDING
    inv_id: str | None = None                              # set for invariant-driven tasks
    # --- Cross-contract / economic-chain scope (T2.1) — when set, this task is NOT
    # pinned to a single contract: it spans an attack that chains several contracts /
    # integrations (oracle→AMM→liquidation, flash-loan-amplified). ``contracts`` lists
    # every node in scope; ``attack_path`` is the ordered hop sequence the hunter must
    # reproduce in a multi-contract PoC. Empty ⇒ a classic single-region task. ---
    contracts: list[str] = Field(default_factory=list)     # all contracts/integrations in scope
    attack_path: list[str] = Field(default_factory=list)   # ordered hops, e.g. ["FlashLoan","AMM:swap","Oracle:read","Vault:liquidate"]
    # --- Tier-4 P3 external-integration trust (dep-misbehavior subtype) — when
    # ``dep_target`` is set, this task does NOT hunt the in-scope code's own logic: it
    # asks "does the protocol stay safe when this EXTERNAL dependency MISBEHAVES?". The
    # campaign mocks ``dep_target`` on the fork to return adversarial values (stale /
    # extreme / reverting / reentrant) and re-checks the protocol's invariants. Empty ⇒
    # not a dep-misbehavior task. ---
    dep_target: str = ""                                   # the external dependency to adversarially mock (e.g. "Chainlink ETH/USD feed", "Curve 3pool")
    dep_assumptions: list[str] = Field(default_factory=list)  # the trust assumptions under attack (from the node's trust_assumptions)
    # --- Tier-4 P4 governance / malicious-admin / upgrade-time --- #
    # ``malicious_role`` set ⇒ assume that privileged role is COMPROMISED and ask what
    # it can do BEYOND its documented intent (timelock bypass, a parameter pushed to
    # insolvency, draining funds via a "legitimate" admin path). ``upgrade_sim`` set ⇒
    # a real-UPGRADE simulation task (storage-layout drift/collision across impls,
    # init/re-init front-run on a fresh deploy, unprotected upgrade authority). Both
    # empty/false ⇒ not a governance task.
    malicious_role: str = ""                               # the privileged role assumed compromised (e.g. "owner", "GOVERNOR_ROLE", "TimelockController")
    upgrade_sim: bool = False                              # real-upgrade-simulation task (storage diff + init front-run)
    # --- Tier-4 P5 game-theory / incentive / long-horizon --- #
    # ``multi_actor`` set ⇒ a COALITION attack (collusion / bribery / keeper–LP
    # incentive misalignment) — the campaign optimizes the colluding actors' COMBINED
    # PnL, not a single attacker's. ``long_horizon`` set ⇒ a time-dependent task —
    # the campaign adds a vm.warp/roll time-advance step + a longer call sequence so
    # interest/funding drift and epoch/checkpoint boundaries are explored.
    multi_actor: bool = False                              # multi-actor / collusion coalition task
    long_horizon: bool = False                             # epoch-aware / long-horizon time-drift task


class HunterDossier(BaseModel):
    """The complete-but-scoped starting context for the hunter of one HunterTask
    (spec §S4 "the Recon profile is the shared context every hunter receives" —
    here narrowed to just this task's slice). Assembled deterministically in Python
    from the S1 index + the ReconProfile (NOT an emit-schema), so it may carry
    free-form dict rows from the index. Index-derived lists hold raw query rows."""

    task_id: str
    vuln_class: VulnClass | None = None
    hotzone: HotZone | None = None                         # the HotZone this task came from
    target_functions: list[dict] = Field(default_factory=list)   # resolved scope (contract.fn + file:line)
    reachable_entrypoints: list[dict] = Field(default_factory=list)  # public entry → target (attack surface)
    external_call_sinks: list[dict] = Field(default_factory=list)    # external/low-level/transfer sinks in scope
    accounting_state_vars: list[dict] = Field(default_factory=list)  # state of the in-scope contracts
    invariants: list[Invariant] = Field(default_factory=list)        # invariants binding this region
    controls: list[str] = Field(default_factory=list)                # existing defenses (don't chase these)
    slither_findings: list[dict] = Field(default_factory=list)       # SAST findings on the in-scope files
    reach_note: str = ""                                             # reachability caveats (e.g. unresolved edges)


class PrefilterDecision(BaseModel):
    """S3 Prefilter verdict for one HunterTask (spec §S3). Deterministic — produced
    by ``recon/prefilter.py`` with NO model calls. Every task gets one; deferred and
    dropped tasks are recorded *with reasons* (never silently lost — S6 Gapfill can
    resurrect deferred). NOT an emit-schema (no LLM ever writes it), so it permits the
    extra keys a future field might add.

    ``seed`` is a HINT for S4 (which tool to fire first), not a terminal lane: an
    invariant-driven lead and an exploratory hypothesis converge on the SAME fork-PoC
    + impact step (see spec §S4)."""

    task_id: str
    score: float
    rank: int                                              # 1 = top of the scheduled queue; 0 for non-scheduled
    decision: Literal["scheduled", "deferred", "dropped"]
    seed: Literal["invariant-campaign", "hypothesis"]
    reasons: list[str] = Field(default_factory=list)
    cost_estimate: float | None = None                     # relative hunt-effort proxy (turns)


# -- Decomposed emit-schemas (one structured `messages.parse` call each) ----- #
class ArchitectureReport(BaseModel):
    """First Recon parse call: architecture + boundaries + roles + hot zones."""

    model_config = ConfigDict(extra="forbid")

    architecture_md: str = Field(
        description="Narrative (≥150 words): components, data flow wallet→router→handler→"
                    "store/oracle/bridge, trust boundaries, upgrade authorities.")
    contract_types: list[str] = Field(
        default_factory=list,
        description="Protocol CLASSES (not contract names): e.g. vault, amm, lending, perp, "
                    "oracle, bridge, perp-dex, liquid-staking.")
    trust_boundaries: list[TrustBoundary] = Field(
        default_factory=list, description="Several boundaries; do not leave empty.")
    privileged_roles: list[Role] = Field(
        default_factory=list, description="Each privileged role; do not leave empty.")
    high_impact_areas: list[HotZone] = Field(
        default_factory=list, description="Ranked HotZones (rank 1 = highest); do not leave empty.")


class HunterTaskList(BaseModel):
    """Emit-schema for the decomposed Hunter task queue."""

    model_config = ConfigDict(extra="forbid")

    tasks: list[HunterTask] = Field(default_factory=list)


class InvariantList(BaseModel):
    """Emit-schema for the Invariant Synthesizer step."""

    model_config = ConfigDict(extra="forbid")

    invariants: list[Invariant] = Field(default_factory=list)


class ReconProfileInput(BaseModel):
    """The ``recon-create-profile`` record — everything the Recon agent produces
    except the task queue and the invariant suite, persisted in a single call.

    It is ``ArchitectureReport`` ∪ ``ThreatModel`` (reusing the leaf models): the
    agent writes it once via ``chainreaper recon-create-profile`` and the stage
    assembles it (with the bound InvariantSuite) into the container ``ReconProfile``
    below. Like the other emit-schemas it forbids extra keys so the API backend's
    ``messages.parse`` can drive it too."""

    model_config = ConfigDict(extra="forbid")

    architecture_md: str = Field(
        description="Narrative (≥150 words): components, data flow wallet→router→handler→"
                    "store/oracle/bridge, trust boundaries, upgrade authorities.")
    contract_types: list[str] = Field(
        default_factory=list,
        description="Protocol CLASSES (not contract names): e.g. vault, amm, lending, perp, "
                    "oracle, bridge, perp-dex, liquid-staking.")
    trust_boundaries: list[TrustBoundary] = Field(
        default_factory=list, description="Several boundaries; do not leave empty.")
    privileged_roles: list[Role] = Field(
        default_factory=list, description="Each privileged role; do not leave empty.")
    high_impact_areas: list[HotZone] = Field(
        default_factory=list, description="Ranked HotZones (rank 1 = highest); do not leave empty.")
    threat_model: ThreatModel = Field(
        default_factory=ThreatModel,
        description="STRIDE-ish asset→threat→existing_control→gap rows for the top assets.")
    protocol_graph: ProtocolGraph = Field(
        default_factory=ProtocolGraph,
        description="Protocol interaction graph (T2.1): nodes = in-scope contracts + "
                    "external integrations (oracles/AMMs/bridges/lending/tokens); edges = "
                    "the interactions an exploit can chain (price reads, swaps, bridge "
                    "messages, liquidations, flash-loan sources). Drives cross-contract tasks.")


class ReconProfile(BaseModel):
    """Container assembled in Python from the emit-schemas above (spec §5)."""

    schema_version: str = SCHEMA_VERSION
    target: Target | None = None
    architecture_md: str = ""
    contract_types: list[str] = Field(default_factory=list)
    trust_boundaries: list[TrustBoundary] = Field(default_factory=list)
    privileged_roles: list[Role] = Field(default_factory=list)
    high_impact_areas: list[HotZone] = Field(default_factory=list)
    threat_model: ThreatModel = Field(default_factory=ThreatModel)
    protocol_graph: ProtocolGraph = Field(default_factory=ProtocolGraph)
    invariant_suite: InvariantSuite | None = None


# --------------------------------------------------------------------------- #
# Hunt contracts (spec §5 "Hunt"; §6 "S4 Hunt") — the S4 Hunter's outputs.     #
# --------------------------------------------------------------------------- #
# These are LLM emit-schemas (the ``hunt-create-finding`` / ``hunt-finish``
# save-scripts validate against them), so every one sets ``extra="forbid"`` —
# like the Recon emit-schemas. ``PoC.files`` is a *typed* ``dict[str, str]``
# (path → content), which the structured-output path renders as a typed
# ``additionalProperties`` and so is allowed (unlike the free-form ``dict`` rows
# the deterministic ``HunterDossier`` carries, which is why that one is NOT an
# emit-schema). ``Finding`` nests ``PoC`` + ``list[CodeLocation]`` the same way
# ``ReconProfileInput`` nests the leaf models above.
class CodeLocation(BaseModel):
    """A precise code site for a Finding (``file:line`` range + optional fix)."""

    model_config = ConfigDict(extra="forbid")

    file: str                                              # repo-relative path
    contract: str | None = None
    symbol: str | None = None                              # function / state var
    line_start: int | None = None
    line_end: int | None = None
    snippet: str | None = None                             # the offending code
    fix_before: str | None = None                          # current (vulnerable) form
    fix_after: str | None = None                           # proposed remediation


class PoC(BaseModel):
    """A runnable proof-of-concept (spec §5). The Hunter writes it in its sandbox
    and records the files + how to run + what was observed; ``succeeded`` reflects
    a real compile+run in the sandbox (``None`` = not run)."""

    model_config = ConfigDict(extra="forbid")

    framework: Literal["foundry_fork", "foundry_local", "hardhat", "anchor", "custom"] = "foundry_fork"
    files: dict[str, str] = Field(default_factory=dict)    # path -> content
    run_cmd: str = ""                                      # e.g. forge test --match-test testExploit -vvv
    expected_observation: str = ""                         # invariant broken / balance drained / $-impact
    run_log: str | None = None                             # captured stdout tail (proof, not prose)
    succeeded: bool | None = None                          # the PoC compiled AND ran to its assertion


class Finding(BaseModel):
    """A vulnerability the Hunter proved from a real public entrypoint with impact
    (spec §5). Emitted via ``hunt-create-finding``; the S5 Critic later refutes any
    lead lacking a reachable-entrypoint impact ``poc``."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str
    task_id: str
    title: str
    vuln_class: VulnClass
    sc_top10: str = ""                                     # "SC02" etc.
    scwe: str | None = None
    cwe: str | None = None
    swc: str | None = None
    severity_claim: Severity = Severity.MEDIUM             # hunter's initial claim
    locations: list[CodeLocation] = Field(default_factory=list)
    source_ref: str | None = None                          # where attacker input enters
    sink_ref: str | None = None                            # where it does damage
    description: str
    impact: str                                            # business-facing, $-terms where possible
    exploit_scenario: str
    preconditions: list[str] = Field(default_factory=list)
    poc: PoC | None = None                                 # script + how-to-run + observed result
    live_validated: bool = False                           # ran against fork/testnet successfully
    # ADVERSARY-MODEL classification (self-assigned by the Hunter). Only
    # ``attacker_reachable`` is a payable live bug; the others are honest downgrades whose
    # PoC needs a non-attacker input (mock/prank) or an unreachable trigger. Defaults to
    # external_condition — the safe, non-payable assumption — so an unclassified finding is
    # NOT silently treated as live. See TriggerClass.
    trigger_class: TriggerClass = TriggerClass.EXTERNAL_CONDITION
    trigger_justification: str = ""                        # WHY this class: what the attacker (only) controls, or which input is mocked/privileged
    confidence: float = 0.5                                # [0,1], coerced
    immunefi_impact: str | None = None                     # maps to program's reward category

    @field_validator("confidence", mode="before")
    @classmethod
    def _coerce_conf(cls, v: Any) -> float:
        return coerce_confidence(v)

    @field_validator("trigger_class", mode="before")
    @classmethod
    def _coerce_trigger(cls, v: Any) -> Any:
        return coerce_enum(v, TriggerClass, default=TriggerClass.EXTERNAL_CONDITION)

    @property
    def attacker_reachable(self) -> bool:
        """True only if the impact is reached with attacker-controlled inputs alone —
        the payable, live-exploitable set."""
        return self.trigger_class == TriggerClass.ATTACKER_REACHABLE


class FindingList(BaseModel):
    """Emit-schema list wrapper for the API-backend batch path (mirrors
    ``HunterTaskList`` / ``InvariantList``)."""

    model_config = ConfigDict(extra="forbid")

    findings: list[Finding] = Field(default_factory=list)


class HuntOutcome(BaseModel):
    """The Hunter's REQUIRED per-task outcome record (spec §S4 Out: "per-task
    outcome tally — attempted/blocked/empty"). One per Hunter session; it is the
    Stop-hook obligation, so a hunter that finds nothing still finishes cleanly by
    declaring ``empty`` (rather than being forced to fabricate a Finding)."""

    model_config = ConfigDict(extra="forbid")

    task_id: str
    outcome: Literal["finding", "empty", "blocked"]
    n_findings: int = 0                                    # Findings emitted this session
    poc_built: bool = False                                # a PoC was compiled+run in the sandbox
    tools_run: list[str] = Field(default_factory=list)     # forge/medusa/halmos/… actually invoked
    summary: str                                           # what was tried; for empty/blocked, why

    @field_validator("n_findings", mode="before")
    @classmethod
    def _coerce_n(cls, v: Any) -> int:
        return coerce_int(v, default=0, lo=0)


# --------------------------------------------------------------------------- #
# Validate contracts (spec §5 "Validate"; §6 "S5 Validate") — the Critic.       #
# --------------------------------------------------------------------------- #
class Verdict(BaseModel):
    """One Critic's adversarial verdict on a Finding (spec §5). The Critic tries to
    REFUTE the finding (re-reads the source + re-runs the PoC); S5 aggregates N
    independent verdicts into the finding's final disposition (T3.1 / blind-spot #5
    — the self-validating single hunter). Emit-schema (``extra="forbid"``)."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str
    verdict: Literal["TRUE_POSITIVE", "FALSE_POSITIVE", "NEEDS_LIVE_PROOF"]
    verdict_confidence: int = 5                            # 0..10, coerced
    refutation: str | None = None                          # how the critic tried to disprove it
    adjusted_severity: Severity = Severity.MEDIUM
    cvss_vector: str = ""
    cvss_score: float = 0.0
    cvss_rating: str = ""
    controls_considered: list[str] = Field(default_factory=list)
    reasoning: str

    @field_validator("verdict_confidence", mode="before")
    @classmethod
    def _coerce_vc(cls, v: Any) -> int:
        return coerce_int(v, default=5, lo=0, hi=10)

    @field_validator("cvss_score", mode="before")
    @classmethod
    def _coerce_cvss(cls, v: Any) -> float:
        try:
            return max(0.0, min(10.0, float(v)))
        except (TypeError, ValueError):
            return 0.0

    @field_validator("adjusted_severity", mode="before")
    @classmethod
    def _coerce_sev(cls, v: Any) -> Any:
        m = coerce_enum(v, Severity, default=Severity.MEDIUM)
        return m if m is not None else Severity.MEDIUM


class VerdictList(BaseModel):
    """Emit-schema list wrapper for the API-backend batch path (mirrors FindingList)."""

    model_config = ConfigDict(extra="forbid")

    verdicts: list[Verdict] = Field(default_factory=list)
