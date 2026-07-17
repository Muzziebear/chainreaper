# Chainreaper — Implementation Specification

> An elite, industry-class vulnerability-discovery harness for blockchain bug-bounty programs.
>
> Status: Draft v1.0 · Date: 2026-06-17 · Owner: Muzziebear

---

## 0. Document map

1. [Vision & design philosophy](#1-vision--design-philosophy)
2. [Source material & what we borrow](#2-source-material--what-we-borrow)
3. [System architecture](#3-system-architecture)
4. [Technology decisions](#4-technology-decisions)
5. [Core data model (stage contracts)](#5-core-data-model-stage-contracts)
6. [The 12-stage pipeline](#6-the-12-stage-pipeline)
7. [Agent roster & prompting](#7-agent-roster--prompting)
8. [Tool layer](#8-tool-layer)
9. [Knowledge / skills library](#9-knowledge--skills-library)
10. [Sandbox & runtime](#10-sandbox--runtime)
11. [LLM provider abstraction](#11-llm-provider-abstraction)
12. [Configuration](#12-configuration)
13. [CLI & operator surface](#13-cli--operator-surface)
14. [Reporting & submission](#14-reporting--submission)
15. [Repository layout](#15-repository-layout)
16. [Implementation roadmap](#16-implementation-roadmap)
17. [Safety, scope & legal guardrails](#17-safety-scope--legal-guardrails)
18. [Open decisions](#18-open-decisions)

---

## 1. Vision & design philosophy

Build a **modular, resumable, multi-agent harness** that, given the Immunefi bug-bounty landscape, autonomously selects high-value targets, ingests their in-scope source, and runs an adversarial hunt → validate → trace → report loop tuned for **smart-contract and on-chain protocol vulnerabilities**.

Five design principles, drawn directly from the Cloudflare / Mythos / Project Glasswing findings and validated against the two reference harnesses:

1. **Narrow scope beats breadth.** Many tightly-scoped hunter agents ("find oracle manipulation in `LiquidationEngine.liquidate`") outperform one exhaustive agent. Decompose aggressively.
2. **Adversarial review beats self-checking.** A separate Critic agent, prompted to *disprove* a finding, removes far more noise than telling the hunter to "be careful."
3. **Separate "is it buggy?" from "is it reachable?"** Discovery and reachability/Trace are distinct reasoning tasks and distinct stages.
4. **Proof, not prose.** Every promotable finding must ship a runnable PoC (Foundry mainnet-fork test or local exploit) that compiles and runs in a sandbox. Speculative "possibly/potentially" findings are triaged out before they cost human attention.
5. **Deterministic spine, agentic muscle.** The pipeline order, checkpoints, and data contracts are deterministic and resumable (Visa pattern). Inside each stage, agents are free-roaming within a sandbox (Strix pattern).

The system is **whitebox-first** (open-source in-scope code is the primary substrate) with **optional live validation** against public testnets/mainnet-forks — never destructive on-chain actions against live protocols.

---

## 2. Source material & what we borrow

| Source | What we take |
|---|---|
| **Cloudflare / Mythos / Glasswing** (blog) | The canonical pipeline: Recon → Hunt → Validate → Gapfill → Dedupe → Trace → Feedback → Report. ~50 concurrent narrow hunters; adversarial Validate with no authority to create findings; Trace as a distinct reachability stage; structured schema output with self-correction. |
| **Strix** (`references/.../strix`) | Dynamic multi-agent coordinator with a tree of agents, inter-agent messaging, snapshot/restore. Markdown **skills** library injected via Jinja2 into system prompts. Tool-driven lifecycle (`finish_scan` / `agent_finish`). Docker sandbox + in-container sidecars. LiteLLM multi-provider routing. LLM-based dedupe. CVSS scoring + per-finding markdown/JSON/CSV artifacts. Resume via `agents.json` + SQLite session DB. |
| **Visa VVA harness** (`references/.../visa-...`) | Deterministic numbered stages (S1–S9) with **pickle checkpoints** and `--resume` / `--stop-after`. Strict **Pydantic data contracts** between stages with LLM-output coercion (`_coerce_confidence`, enum aliasing) so malformed model output never crashes the pipeline. Injectors (CVE feed, design controls, CMDB) threaded once into all stages. `prefilter` deterministic policy gate before expensive verify. Adversarial S6 verifier that must *prove the finding wrong*. Two-pass (trivial + semantic) dedupe. SARIF + redaction in reporting. Per-stage error log + `degraded` flag + run manifest. Per-language researcher hints. |
| **OWASP SCSTG / SCSVS / SC Top-10 (2026)** + Web3 workflow docx | The blockchain vulnerability taxonomy, the SCSVS 12-control completeness model, the contract-type risk catalog, the tiered fuzzing pipeline (Foundry→Medusa→Echidna→Certora), and the concrete toolchain (Slither, Aderyn, Mythril, Halmos, Foundry, Echidna, Medusa, Certora, Tenderly). These become **skills**, **detectors/tools**, and **gapfill checklists**. |

**Net design:** Visa's deterministic, checkpointed, contract-typed spine; Strix's agent coordinator, skills, and sandbox living *inside* the Hunt and Validate stages; the Glasswing stage sequence as the canonical flow; blockchain knowledge as the domain layer.

---

## 3. System architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│ CLI / Operator surface  (chainreaper discover | scan | resume | report)     │
└───────────────────────────────┬──────────────────────────────────────────┘
                                 │
┌────────────────────────────────▼─────────────────────────────────────────┐
│ ORCHESTRATOR  (deterministic spine)                                        │
│  - stage sequencer S0..S11, checkpointing, --resume / --stop-after         │
│  - run manifest, error log, degraded flag, token/cost ledger               │
│  - injectors loaded once: scope rules, known-CVE/known-bug feed, controls  │
└───┬───────────────┬───────────────┬───────────────┬───────────────────────┘
    │               │               │               │
┌───▼────┐   ┌──────▼──────┐  ┌─────▼──────┐  ┌──────▼───────┐
│Target  │   │Index store  │  │Agent       │  │Knowledge /   │
│registry│   │(graph + AST │  │Coordinator │  │Skills library│
│(Immunefi│  │ + symbol DB)│  │(tree, msg, │  │(SC Top-10,   │
│ snapshot│  │             │  │ snapshot)  │  │ SCSVS, tools)│
└────────┘   └─────────────┘  └─────┬──────┘  └──────────────┘
                                     │
                          ┌──────────▼──────────┐
                          │ SANDBOX FLEET        │
                          │ Docker per task:     │
                          │  Foundry/Anvil fork, │
                          │  Slither/Mythril/    │
                          │  Echidna/Medusa,     │
                          │  Solana/Move toolch. │
                          └──────────────────────┘
                                     │
                          ┌──────────▼──────────┐
                          │ Findings store       │
                          │ (Pydantic + JSONL +  │
                          │  SQLite, per-run dir) │
                          └──────────────────────┘
```

Three layers:

- **Orchestrator (deterministic):** owns stage order, checkpoints, the run directory, the cost budget, and the injected context. Pure Python; no model calls of its own except via stages.
- **Agent runtime (agentic):** the `AgentCoordinator` (Strix-style) manages the live tree of Recon/Hunter/Critic/Tracer/Gapfill agents, message passing, and snapshot/restore. Stages S2–S10 invoke it.
- **Execution substrate:** the sandbox fleet (one container per hunter task / verify task) and the index store + findings store.

A **run** is identified by `run_id` and lives in `runs/{run_id}/`. Every stage reads the prior stage's checkpoint and writes its own, so any stage can be re-run in isolation.

---

## 4. Technology decisions

| Concern | Decision | Rationale |
|---|---|---|
| Language | **Python ≥ 3.11** | Both references are Python; blockchain SAST tooling (Slither, Mythril) is Python-native. |
| Agent SDK | **`claude-agent-sdk`** as primary, with a thin internal `Backend` protocol mirroring Visa's `prompt()` / `agentic()` so SDK / CLI / OpenAI-compat are swappable. | Strix uses `openai-agents[litellm]`; Visa uses Anthropic SDK + CLI. We default to Anthropic (Mythos/Claude family, the model family this harness is tuned for) and keep the abstraction for portability. |
| Default model | **`claude-opus-4-8`** for Hunt/Critic/Trace (deep reasoning), **`claude-sonnet-4-6`** for Recon/Index-assist/Dedupe (cheaper, high volume), **`claude-haiku-4-5`** for mechanical coercion/labeling. Per-role model config like Visa. | Match reasoning effort to stage cost profile. When a Mythos-class security model is available, route Hunt/Trace to it via config. |
| Data contracts | **Pydantic v2** models with defensive coercion helpers | Visa pattern — malformed LLM JSON must never crash a 9-stage run. |
| Checkpointing | **JSON + pickle hybrid**: human-readable JSON for findings/manifests, pickle for rich intermediate objects; `--resume` + `--stop-after sN`. | Visa resumability; JSON for the artifacts an analyst inspects. |
| Sandbox | **Docker**, one image `chainreaper-sandbox` with Foundry, Slither, Mythril, Aderyn, Solhint, Echidna, Medusa, Halmos, node/npm, solc-select, Solana CLI + Anchor, Move/Sui CLI. Network-egress controlled. | Self-contained reproducible PoC environment; mirrors Strix's container + sidecar pattern. |
| Code index | **Tree-sitter** (Solidity/Vyper/Rust/Move grammars) for AST + symbols; **Slither's IR + call graph** for Solidity-grade call/data-flow graphs; stored in **SQLite + a graph table** queryable by agents. | "Call property graphs" requirement; Slither already produces inheritance/call graphs and an SSA IR. |
| Concurrency | `asyncio` with a semaphore cap (default 16 concurrent agents; configurable to ~50 per Glasswing). | Parallel narrow hunters. |
| Target intel | **Immunefi** via official API where available, else a polite, rate-limited scraper of `immunefi.com/bug-bounty/`, cached as a `targets snapshot`. | Discovery stage S0. |

---

## 5. Core data model (stage contracts)

All inter-stage data is Pydantic. Every model carries `schema_version`. LLM-produced fields go through coercion helpers (`coerce_confidence`, `coerce_enum`, `coerce_int`) ported from Visa so a bad token degrades gracefully instead of crashing.

```python
# ---- Discovery ----
class Target(BaseModel):
    program_id: str                 # immunefi slug
    name: str
    url: str
    max_bounty_usd: float | None
    total_paid_usd: float | None
    assets_in_scope: list[ScopeAsset]   # repos, contracts, addresses, docs
    chains: list[str]               # ethereum, arbitrum, solana, ...
    languages: list[str]            # solidity, vyper, rust, move
    kyc_required: bool
    program_type: Literal["smart_contract","web","blockchain_dlt","mixed"]
    score: float                    # discovery ranking score
    score_breakdown: dict[str, float]

class ScopeAsset(BaseModel):
    kind: Literal["github_repo","contract_address","npm","docs","website"]
    ref: str                        # url / address
    in_scope: bool
    impacts_in_scope: list[str]     # "Direct theft of funds", etc.

# ---- Index ----
class IndexedRepo(BaseModel):
    repo_ref: str
    language: str
    files: list[IndexedFile]
    contracts: list[ContractNode]   # name, kind, inherits, file:line
    call_graph: list[CallEdge]      # caller_sig -> callee_sig, external?
    state_vars: list[StateVar]
    entrypoints: list[Entrypoint]   # external/public fns, reachable from EOA
    external_calls: list[Sink]      # .call/.delegatecall/transfer/oracle reads
    proxy_info: ProxyInfo | None    # pattern, impl slot, init guard status
    sast_raw: dict                  # slither/mythril/aderyn json blobs

# ---- Recon ----
class ReconProfile(BaseModel):
    target: Target
    architecture_md: str            # narrative: components, trust boundaries
    trust_boundaries: list[TrustBoundary]
    privileged_roles: list[Role]
    high_impact_areas: list[HotZone]  # ranked file/contract/function regions
    invariant_suite: InvariantSuite # codebase-specific invariants + scaffolded harness (see S2)
    contract_types: list[str]       # token, lending, amm, oracle, bridge...
    threat_model: ThreatModel       # STRIDE-ish, asset->threat->control

class Invariant(BaseModel):
    inv_id: str                     # stable handle, e.g. "SOLV-01" (used by harness + findings)
    category: InvariantCategory     # solvency|share_price|position_pnl|liquidation|oracle|
                                    #   fee|execution|access|cross_module
    statement: str                  # precise, testable property
    hooks: list[str]                # exact functions/state vars it binds to ("file:symbol")
    tool: Literal["foundry","medusa","echidna","halmos","certora","wake","slither","properties"]
    severity: Severity
    origin: Literal["catalog","codebase_synth","prior_finding"]  # generic vs target-derived
    harness_ref: str | None         # path to the generated handler/test stub
    status: Literal["proposed","scaffolded","passing","violated"]

class InvariantSuite(BaseModel):
    target: str
    invariants: list[Invariant]     # catalog-seeded + codebase-synthesized, deduped
    handler_files: dict[str, str]   # generated actor/handler scaffolds: path -> content
    runner_config: dict             # medusa.json / echidna.yaml / foundry profile
    coverage_map: dict              # which contracts/functions the suite exercises

class HunterTask(BaseModel):
    task_id: str
    title: str                      # "Read-only reentrancy in Vault.totalAssets"
    vuln_class: VulnClass           # SC Top-10 enum (see §9)
    scope_hint: str                 # exact files/functions/contracts
    hypothesis: str                 # what to try to prove
    suggested_skills: list[str]
    priority: int                   # 1..4 (P1 highest)
    origin: Literal["recon","gapfill","feedback"]
    status: TaskStatus

# ---- Hunt ----
class Finding(BaseModel):
    finding_id: str
    task_id: str
    title: str
    vuln_class: VulnClass
    sc_top10: str                   # "SC03"
    scwe: str | None; cwe: str | None; swc: str | None
    severity_claim: Severity        # hunter's initial claim
    locations: list[CodeLocation]   # file:line ranges, fix_before/after
    source_ref: str | None          # where attacker input enters
    sink_ref: str | None            # where it does damage
    description: str
    impact: str                     # business-facing, $-terms where possible
    exploit_scenario: str
    preconditions: list[str]
    poc: PoC | None                 # script + how-to-run + observed result
    live_validated: bool            # ran against fork/testnet successfully
    confidence: float               # [0,1], coerced
    immunefi_impact: str | None     # maps to program's reward category

class PoC(BaseModel):
    framework: Literal["foundry_fork","foundry_local","hardhat","anchor","custom"]
    files: dict[str, str]           # path -> content
    run_cmd: str
    expected_observation: str       # invariant broken / balance drained
    run_log: str | None
    succeeded: bool | None

# ---- Validate ----
class Verdict(BaseModel):
    finding_id: str
    verdict: Literal["TRUE_POSITIVE","FALSE_POSITIVE","NEEDS_LIVE_PROOF"]
    verdict_confidence: int         # 0..10
    refutation: str | None          # how the critic tried to disprove it
    adjusted_severity: Severity
    cvss_vector: str; cvss_score: float; cvss_rating: str
    controls_considered: list[str]  # business reqs / mitigations weighed
    reasoning: str

# ---- Dedupe / Trace ----
class DupGroup(BaseModel):
    canonical_id: str
    member_ids: list[str]
    root_cause: str

class TraceResult(BaseModel):
    finding_id: str
    reachable: bool
    entry_path: list[str]           # external entry -> ... -> sink
    attacker_controlled: bool
    notes: str

class DroppedFinding(BaseModel):       # audit trail (Visa pattern)
    finding_id: str
    reason: Literal["FALSE_POSITIVE","DUPLICATE","UNREACHABLE","PREFILTERED",
                    "OUT_OF_SCOPE","LOW_CONFIDENCE","ERROR"]
    detail: str
    canonical_id: str | None

# ---- Final ----
class RunReport(BaseModel):
    run_id: str; target: Target
    recon: ReconProfile
    findings: list[Finding]            # confirmed, ranked
    verdicts: dict[str, Verdict]
    dup_groups: list[DupGroup]
    traces: dict[str, TraceResult]
    dropped: list[DroppedFinding]
    metrics: RunMetrics                # coverage, precision, tokens, cost, timing
    degraded: bool
```

Enums (`VulnClass`, `Severity`, `TaskStatus`, `InvariantCategory`) and coercion helpers live in `chainreaper/models.py`. `InvariantCategory` = solvency | share_price | position_pnl | liquidation | oracle | fee | execution | access | cross_module (the invariant taxonomy in §S2 / `tools_poc/invariants.md`). `VulnClass` enumerates the SC Top-10 (2026) plus blockchain extras (read-only reentrancy, first-depositor/ERC-4626 inflation, signature replay/malleability, MEV/front-running, bridge replay, randomness, DoS-unbounded-loop, gas-griefing, storage-collision, selector-clash).

---

## 6. The 12-stage pipeline

Stages map directly to the requirements list (numbered there 1–12). Each stage: **inputs → work → outputs → checkpoint**. Stages S5/S6 and S7/S8 are the "Hunt/Validate ×2" rounds. `--stop-after` and `--resume` operate at stage granularity.

### S0 · Discovery  *(req #1)* — **two entry modes: discover-and-select, or point-at-a-program**

S0 turns an operator intent into a concrete `Target` + a materialized, in-scope `workspace/` that S1 can index. It runs on the **host** (network egress allowed — the egress-restricted sandbox is only for S4+); it never executes untrusted code.

- **In (one of):**
  - `scan --target <ref>` — `<ref>` is an **Immunefi program slug** (`gainsnetwork`), an **Immunefi program URL**, a **git repo URL**, or a **local path**; or
  - `discover [--filters …] [--auto-top N]` — no specific target → pull + rank the Immunefi board and select.
  - Operator filters: chain, language, min max-bounty, KYC tolerance, open-source-only.

- **A. Source of truth — the Immunefi program (`targets/immunefi_client.py`).** For a chosen slug, fetch and merge its three pages — `…/<slug>/information/`, `…/<slug>/scope/`, `…/<slug>/resources/` — by parsing the embedded **`__NEXT_DATA__` JSON** in each page's HTML (Immunefi is a Next.js app; this structured data layer is far more reliable than scraping rendered text). Cache the raw JSON under `runs/_targets/<slug>/` (`--refresh` re-pulls; polite + rate-limited + sends a `User-Agent` — a blank UA gets HTTP 403). Extract:
  - **information/** → `max_bounty_usd`, `total_paid_usd`, KYC flag, **PoC-required** flag, languages, chains, `program_type`, the rewards/severity table, and the **in-scope impacts** (e.g. "Direct theft of user funds", "Permanent freezing", "Insolvency") — the impacts hunters rank against.
  - **scope/** → the authoritative **in-scope asset list**. *Reality (verified on `gainsnetwork`): scope assets are listed by **contract NAME + NETWORK + deployed ADDRESS** (with block-explorer links), NOT by repo/commit.* Capture each `{name, address, network, explorer_url, type}`.
  - **resources/** → the **source repositories** (GitHub org/repo URLs), docs, prior audits, and architecture notes (e.g. Gains' "diamond architecture — all facets in-scope"). *The repo holds ALL of the protocol's contracts; only the scope/ names are in-scope.*

- **B. Resolve source → workspace (`targets/source_resolver.py`).**
  - **Clone** each in-scope source repo into `runs/{run_id}/workspace/<repo>` at the **pinned commit/tag** when the program specifies one; *Immunefi often pins nothing* → clone the default-branch HEAD and **record the resolved commit SHA** for reproducibility (`--commit <sha>` overrides). Also fetch reference docs / prior audits into the workspace.
  - **Map in-scope assets → source by contract NAME.** The scope table names (`GToken`, `GTokenOpenPnlFeed`, `ERC20Bridge`, diamond facets …) match Solidity contract names in the clone — this is the bridge from "address in scope" → "source file to analyze". Record an **in-scope allowlist** of `{contract_name, address, network, file}`; flag any unresolved names.
  - **Explorer fallback (optional):** for an address-only asset with no repo match (or a non-open-source target), fetch verified source via the block-explorer API (Etherscan/Arbiscan `getsourcecode`, needs an API key) into the workspace. Open-source-only runs normally have repos and skip this.

- **C. Ranking (discover mode only).** Score the pulled board with a transparent, configurable function:
  `score = w1·norm(max_bounty) + w2·norm(total_paid) + w3·open_source_ratio + w4·smart_contract_focus + w5·scope_clarity − w6·kyc_penalty − w7·crowd_saturation`. Present the ranked table; operator picks, or `--auto-top N` auto-selects.

- **Out:** a `Target` carrying program metadata + `assets_in_scope` (contract-address assets `{name,address,network}` + source-repo assets with `revision` + the resolved `local_path` clone(s)) + the **in-scope contract allowlist**; a materialized `workspace/` (cloned source + docs); `score`/`score_breakdown` in discover mode. Checkpoint `s0.json`.

- **Guardrails (§17):** only `in_scope` assets are cloned/analyzed; because the clone is a **superset** of the in-scope set, the **scope injector now enforces the in-scope contract-name/address allowlist** (not just the repo) so S2+ never wanders into out-of-scope contracts. KYC programs are skipped unless `--allow-kyc`. Egress is host-only and polite.

- **Fallback / dev mode:** `--target <local-path>` keeps the current behavior (hand-built `Target` from a local repo already on disk, e.g. `gmx-source/`) for offline development — no Immunefi fetch, no clone.

- **AS-BUILT (2026-06, supersedes parts of the above — see memory `chainreaper-s0-built` / `chainreaper-gains-hunt`):**
  - **Immunefi is now an app-router site** — program data is in the streamed RSC flight (`self.__next_f.push`), NOT `__NEXT_DATA__`. Parse the flight; always send a `User-Agent` (blank → 403).
  - **Explorer = source of truth (`discovery.source_policy: auto|explorer|repo`).** For address-scoped programs the **verified DEPLOYED source** at the in-scope addresses IS the in-scope code (exact, self-contained → no superset, no npm/truffle build), fetched via the **Etherscan V2 multichain** API (`getsourcecode`, one key all chains; follow proxy→implementation; content-dedupe; materialize under `workspace/_verified/<chain>/<name>_<addr>/` with a `.chainreaper-compile.json` solc-standard-json sentinel S1 reads). The repo is cloned as **context + fallback** only. `auto` = explorer when scope has addresses AND a key is present, else `repo`. Allowlist resolves **by address** (handles scope-name ≠ on-chain ContractName). On Gains this took the allowlist 6/16→15/16 resolved.
  - **Fork-RPC discovery (`targets/rpc_resolver.py`).** S0 resolves+probes a fork RPC per in-scope chain (`<CHAIN>_RPC_URL` env/keystore → `hunt.fork.rpc_urls` → built-in public list) and records a **redacted** `Target.fork_preview` (host only) + an operator summary, so RPC coverage is confirmed at the `--stop-after s0` gate before indexing. `needs_key` chains tell the operator to supply an archive node.
  - **Secret store (`chainreaper/keystore.py`).** Keys (`ETHERSCAN_API_KEY`, `<CHAIN>_RPC_URL`, …) persist in **`.chainreaper/env`** (gitignored, chmod 600), auto-loaded into env at CLI startup; a real export always wins. `chainreaper secret set/list/path`. The config loader does NO `${VAR}` interpolation (avoids plaintext-in-YAML).

### S1 · Index  *(req #2)*
- **In:** `Target`, workspace.
- **Work:** per repo/language:
  - Detect language (`lang/hints.py`-style ext map + content sniff; Solidity/Vyper/Rust-Solana/Move).
  - Build **AST + symbol table** via Tree-sitter; **call/inheritance/data-flow graph** via Slither IR (Solidity), `cargo`/Anchor metadata (Solana), Move prover model (Move).
  - Run baseline SAST and cache raw JSON: **Slither** (all detectors + upgradeability/proxy), **Aderyn**, **Solhint**, **Mythril** (bounded symbolic), storing outputs as evidence (not yet findings).
  - Detect **entrypoints** (external/public functions reachable from an EOA), **sinks** (`.call`/`delegatecall`/`transfer`/oracle reads/`ecrecover`/unchecked math), **proxy pattern + init-guard status**, **state vars** + storage layout.
- **Out:** `IndexedRepo[]`, persisted to the **index store** (SQLite) so agents can query "callers of X", "who writes `totalSupply`", "external calls in `withdraw`".
- **Notes:** This is the "create call property graphs" requirement. We reuse Slither rather than reinventing graph extraction; we add a thin query API agents call via the `code_index` tool (§8).

### S2 · Recon  *(req #3)*  — **AS BUILT: a single read-only agent session, ordered explore → profile → invariants → ranked tasks**
- **In:** `Target`, `IndexedRepo[]`, docs, SAST raw.
- **Work:** **ONE** read-only **Recon agent** session explores the indexed code + docs and produces its three deliverables *in order* — the order matters because each later step is sharper for having done the earlier ones, and because emitting the task queue LAST lets the agent rank it holistically with the invariants + slither findings already in hand (this is why S3 no longer re-scores; see §S3). *(History: invariant synthesis was originally a separate "Invariant Synthesizer" sub-agent that ran after Recon; it was merged into this one session in 2026-06 so the same mind that formalizes the properties also ranks what to test. The merge was verified to hold the GMX 2025-hack recall benchmark 3/3.)* The session produces:
  - `architecture_md` — components, data flow (wallet→frontend→contracts→oracles/bridges), trust boundaries, privileged roles, upgrade authorities.
  - `high_impact_areas` — ranked HotZones (lending liquidation, AMM pricing, oracle integration, withdrawal/mint paths, proxy init, bridge message verification).
  - **`invariant_suite` — a codebase-specific `InvariantSuite` (not generic boilerplate).** This is a first-class Recon output, emitted before the task queue. The agent derives invariants tailored to *this* target by:
    1. **Classifying** the protocol against `contract_types` (vault/AMM/lending/perp/bridge/oracle…) to pull the relevant **catalog** of invariant *categories* (solvency, share-price, position/PnL, liquidation/ADL, oracle, fee/funding/rounding, execution/reentrancy, access/config, cross-module) — the same taxonomy as the skills library (§9).
    2. **Binding each category to real code hooks** discovered in S1 — the actual accounting state vars and getters (e.g. for a perp/vault: pool/reserve/fee balances, share-price/AUM getter, PnL & average-price math, liquidation predicate). Generic "totalAssets ≥ Σ deposits" becomes a concrete, bound assertion like `balanceOf(vault) ≥ poolAmounts[t] + feeReserves[t]` referencing exact `file:symbol`s.
    3. **Mining prior audits + known-incident feed** (injected context) to add regression invariants for this protocol's class (e.g. share-price reentrancy stability, share-price round-trip ≤ identity).
    4. **Assigning each invariant a tool** (Foundry/Medusa/Echidna stateful, Halmos/Certora proof, Wake scenario, Slither static) and **scaffolding the harness** — generating actor/handler stubs (bounded LP/Trader/Keeper/Liquidator-style actions + ghost variables) and a runner config (medusa.json / echidna.yaml / foundry profile) into `handler_files`.

     Each `Invariant` carries a stable `inv_id`, `hooks`, `severity`, and `origin` (`catalog` vs `codebase_synth`). The suite seeds from reusable property libraries (e.g. ERC4626/ERC20/fixed-point) where the contract types match, then layers the synthesized, target-specific ones on top. *(Worked example: `tools_poc/invariants.md` is exactly this artifact, hand-produced for GMX V1/V2.)*
  - `threat_model` — STRIDE-style asset→threat→existing-control mapping, seeded by SCSVS categories.
  - **Hunter task queue (emitted LAST, one holistically-ranked queue)** — decompose HotZones into narrow `HunterTask`s, one vuln-class × one code region each, with scope hints and a hypothesis (Glasswing "narrow scope"). **The agent ranks the whole queue itself** — `priority` P1–P4 is a discriminating judgment made with the architecture, the invariants, and the slither findings all in context (not a coarse pre-dossier guess). **Invariants become tasks in the SAME queue:** for each high/critical invariant the agent emits a `HunterTask` carrying that `inv_id` (a hunter that breaks an invariant has a finding with a built-in PoC); exploratory tasks leave `inv_id` unset. A deterministic **invariant-coverage backstop** in the stage appends a task for any high/critical invariant the agent didn't cover, so coverage is never silently lost while the agent still owns the ranking.
- **Out:** `ReconProfile` (incl. `invariant_suite`) + a single ranked `HunterTask[]`, each with a deterministic per-task `HunterDossier` (resolved target functions, reachable public entrypoints, sinks, accounting state, binding invariants, controls, in-scope slither findings) persisted to `chainreaper.db.hunter_tasks.context` + the s2 checkpoint. *(Harness scaffolding — `handler_files`/runner configs — is deferred to S4, where the sandbox exists.)*
- **Design:** the Recon profile is the shared context every hunter receives — prevents drift/wander (Glasswing lesson). The invariant suite is the bridge from "read the code" to "fuzz/prove the code": Recon proposes, Hunt (S4) scaffolds + runs the campaigns, Validate (S5) confirms violations, Gapfill (S6) measures invariant/coverage gaps and synthesizes more.

### S3 · Prefilter task queue  *(deterministic THIN policy gate — NO model calls)*
- **In:** `HunterTask[]` + their per-task `HunterDossier`s (S2 output; persisted in `chainreaper.db.hunter_tasks.context` + the s2 checkpoint).
- **Work (all deterministic):** S2's single agent already ranked the queue with full context, so S3 does **NOT** re-score — it only does what determinism is genuinely better at. *(History: S3 originally carried a hand-tuned weighted scorer combining ~8 dossier signals. It was retired in 2026-06: the weights were arbitrary/untuned false-precision over the agent's judgment, and once S2 became one holistically-ranking session the scorer was redundant.)*
  - **Drop invalid / out-of-scope** — a task whose dossier resolved no `target_functions`, or whose targets all sit under `node_modules/` / `mock/` / `test/`, points at nothing huntable → drop (record the reason). Exact, not heuristic (the dossier resolved scope against the index).
  - **Order by the agent's `priority`** (P1–P4, primary) with deterministic **hard-fact tiebreaks only** — reachable public entrypoint present, then bound-invariant severity, then `task_id` for stability. This is a lexicographic ordering on monotonic signals, NOT a tuned weighting: a P2 never outranks a P1.
  - **Dedupe — conservative twins only:** fold a task only when it shares the same `vuln_class` AND a *very high* fraction of its `dossier.target_functions` with a higher-ranked task (containment ≥ 0.9); **distinct `inv_id`s are never folded** (each invariant is its own oracle). Semantic "is this the same bug?" merging is left to the LLM **S9 Dedupe** stage (on proven findings, where a wrong merge is cheap). The asymmetry is intentional — a false merge here kills a hunt that never runs.
  - **Cap to budget** per `vuln_class`, with a floor of ≥1 per high-severity class present (never starve a class) and a reserved quota for invariant-driven tasks; then global top-K within budget (concurrent-hunters × turns under `claude_cli`; per-hunter $ vs `max_usd` under `anthropic`).
  - **Tag the discovery seed** per task (`invariant-campaign | hypothesis`) so S4 knows which tool to fire first — a hint, NOT a terminal lane (see S4).
- **Out:** scheduled `HunterTask[]` ordered by agent priority, each with a recorded `PrefilterDecision` (`score` [a transparent priority-derived ordering value, not a tuned metric], `rank`, `decision: scheduled|deferred|dropped`, `seed`, `reasons[]`, `cost_estimate`). Deferred/dropped are recorded *with reasons* (never silently lost — S6 Gapfill can resurrect deferred). Persisted to `chainreaper.db.hunter_tasks.schedule` + `s3.json`.

### S4 · Hunt (round 1)  *(req #4)*
- **In:** `ReconProfile` (shared context), scheduled tasks **each with its `HunterDossier`** (resolved target functions, reachable public entrypoints, external-call sinks, accounting state, binding invariants, existing controls, in-scope slither findings — the source→sink / attack-surface context, precomputed deterministically in S2), index store, sandbox fleet.
- **Work:** the coordinator spawns up to *N* concurrent **Hunter agents**. Each hunter:
  1. Receives the Recon profile + its single task **+ its dossier** in context.
  2. Reads target code via `code_index` + `read`. The dossier already gives the source→sink path and the **reachable public entrypoints**, so the hunter starts from the concrete attack surface rather than re-deriving it.
  - **Invariant-driven tasks are a discovery *seed*, not a separate terminal mode.** When the task carries an `inv_id`, the hunter first runs the assigned campaign (Foundry/Medusa/Echidna, or Halmos/Wake) — or, for a slither-grounded invariant, confirms the static finding is a true positive. A violation yields a **falsifying call sequence / confirmed lead with a concrete reproducer** — but that is the *start*, not the finding. **Every lead (invariant counterexample OR exploratory hypothesis) then converges on the SAME PoC step below.** A harness counterexample is *not* the same as exploitable on the deployed protocol (mock tokens / relaxed actors / no access-control or oracle gating), *not* a demonstrated $-impact, and the S5 Critic will refute any lead lacking a reachable-entrypoint impact PoC. The invariant campaign is an **accelerator** — you adapt the shrunk sequence into the fork test and add impact assertions — not a shortcut past the PoC. Optimization-mode runs (e.g. "maximize share price/AUM") target the manipulation class directly.
  3. Forms an exploit hypothesis (seeded by the campaign counterexample when present); **writes a PoC** in its sandbox from a real public entrypoint in the dossier (Foundry mainnet-fork test preferred; local unit test or Anchor/Move test otherwise) that **demonstrates impact**, not just the property violation.
  4. Compiles & runs the PoC; iterates on failure (Mythos "proof generation" loop).
  5. If a public testnet / fork RPC is available and the program permits, **validates live** on a fork (never destructive against live mainnet protocol state).
  6. Emits `Finding`(s) with `poc`, `live_validated`, `confidence`, location source/sink refs, and the matching Immunefi impact category.
- **Out:** `Finding[]` (round 1) + per-task outcome tally (attempted/blocked/empty).
- **Tools:** full sandbox (Foundry/Anvil, Slither/Mythril/Echidna/Medusa, shell), `code_index`, `web_search` (CVE/known-bug intel), `create_finding`, `think`, `notes`.

### S5 · Validate (round 1)  *(req #5)*
- **In:** round-1 `Finding[]`.
- **Work:**
  - **Prefilter (deterministic):** drop findings in test/mock/example paths (unless a real secret/keys class), hallucinated files, `confidence < min`, missing source/sink when required. Trivial dedupe within line tolerance. (Visa S5 pattern — cheap gate before expensive critics.)
  - **Critic agents (adversarial):** every finding *not already live-validated* gets an independent **Critic** prompted to **prove it wrong** — open the cited code, walk the call chain to an external entrypoint, hunt for upstream validation / access control / CEI guards / pause flags / business-rule mitigations, probe those defenses with edge cases. The Critic **cannot create new findings** (Glasswing rule). It weighs **business requirements and existing security controls** and either refutes (→ FALSE_POSITIVE) or **lowers the severity** accordingly.
  - Emits `Verdict` with CVSS 3.1 vector + verdict_confidence + controls_considered. Live-validated findings skip refutation but still get CVSS scoring.
- **Out:** `Verdict[]`; FALSE_POSITIVEs move to `DroppedFinding[]` with reasoning.

### S6 · Gapfill  *(req #6)*
- **In:** `ReconProfile` (incl. `invariant_suite`), coverage map (files/functions/HotZones/SCSVS categories the round-1 hunters touched **+ which invariants were actually scaffolded, run, and with what fuzzing coverage**), surviving findings.
- **Work:** a **Gapfill agent** computes coverage and counteracts model bias toward already-successful classes (Glasswing). It:
  - Cross-references against the **SCSVS 12-category** + **SC Top-10** completeness checklist and the contract-type risk catalog (from §9) — e.g., "no one tested signature replay on the permit path", "AMM rounding direction unexamined", "proxy storage layout not diffed".
  - **Audits invariant coverage:** which `InvariantCategory`s have no bound invariant, which scaffolded invariants were never run, and which ran with low corpus/coverage — then **synthesizes new invariants** (extending `invariant_suite`) and re-queues weakly-fuzzed ones for longer/optimization-mode campaigns.
  - Re-queues uncovered/under-covered regions as new `HunterTask`s with `origin="gapfill"`.
- **Out:** new `HunterTask[]`.

### S7 · Hunt (round 2)  *(req #7)*
- Same machinery as S4, consuming gapfill tasks. Hunters still get the Recon profile plus a short digest of round-1 confirmed findings (to chain/extend, not duplicate).
- **Out:** round-2 `Finding[]`.

### S8 · Validate (round 2)  *(req #8)*
- Same machinery as S5, over round-2 findings.
- **Out:** round-2 `Verdict[]`.

### S9 · Dedupe  *(req #9)*
- **In:** all TRUE_POSITIVE / NEEDS_LIVE_PROOF findings from both rounds.
- **Work (two-pass, Visa+Strix):**
  - **Trivial pass (deterministic):** same file + vuln_class within line tolerance → group.
  - **Semantic pass (LLM):** "would one engineering fix close both?" Collapse shared-root-cause findings (same helper, same missing global control, cause+effect on one flow, same insecure setting at many read points) into a **canonical** `Finding`, preserving member locations.
- **Out:** `DupGroup[]`; non-canonical members → `DroppedFinding(reason=DUPLICATE)`.

### S10 · Trace  *(req #10)*
- **In:** canonical findings, index store.
- **Work:** a dedicated **Tracer agent per finding** answers *only* "can attacker-controlled input reach this sink from an external entrypoint?" — the deliberately separated reachability question (Glasswing lesson #3). It walks the call/data-flow graph from external entrypoints to the sink, confirms attacker-controllability of the tainted input, and records the `entry_path`. Findings that are real bugs but **unreachable** are demoted/dropped (`UNREACHABLE`), converting "flaw exists" → "reachable vulnerability."
- **Out:** `TraceResult[]`; reachability annotations on findings.

### S11 · Feedback  *(req #11)*
- **In:** reachable traces, drop reasons, coverage, per-stage metrics.
- **Work:**
  - **Within-run:** reachable traces that reveal new attack surface (e.g., a reachable sink suggests an adjacent unchecked path) become new hunt tasks — bounded by budget, optionally looping back to S7 once (configurable `--feedback-rounds`).
  - **Cross-run learning:** persist what worked/failed — which task templates produced TPs, which produced noise, per-vuln-class precision — into a `runs/_learning/` store that biases future Recon task generation and Gapfill checklists. False-positive patterns feed a growing prefilter ruleset.
- **Out:** optional extra tasks; updated learning store; finalized finding set.

### S12 · Report  *(req #12)*
- **In:** everything.
- **Work:** build `RunReport`; render:
  - **Markdown** executive + per-finding reports (impact in $-terms, exploit scenario, PoC + run log, remediation, CVSS, SC Top-10/SCWE/SWC mapping, reachability path).
  - **JSON + CSV** finding index.
  - **SARIF 2.1.0** for tooling ingestion.
  - **Immunefi-ready submission drafts** per finding (mapped to the program's impact/severity categories, with reproducible PoC) — staged as drafts; **never auto-submitted** (see §17).
  - **Redaction** pass (strip any leaked keys/secrets from logs) + `degraded` flag if any stage errored.
- **Out:** `runs/{run_id}/report/`.

---

## 7. Agent roster & prompting

Agents are built by a factory (`build_agent(role, skills, task, sandbox, model)`) that renders a Jinja2 system prompt from a base template + injected skills (Strix pattern). Lifecycle is tool-driven (`finish_task`).

| Agent | Stage | Scope mode | Key tools | Mandate |
|---|---|---|---|---|
| **Recon** | S2 | read-only | code_index, read, web_search, think | ONE session: map architecture + rank HotZones, derive the codebase-specific `InvariantSuite` bound to real hooks, then emit one holistically-ranked narrow-task queue (see §S2). *(The former separate "Invariant Synthesizer" agent was merged into this one in 2026-06.)* |
| **Hunter** | S4/S7 | full sandbox | sandbox, code_index, foundry, sast, create_finding | One task, one vuln-class. Prove with a runnable PoC. Validate on fork if allowed. |
| **Critic** | S5/S8 | read + read-only sandbox | code_index, read, foundry(read), think, emit_verdict | Disprove the finding. Weigh controls/business rules. Cannot create findings. Score CVSS. |
| **Gapfill** | S6 | read-only | coverage_query, code_index, checklist(SCSVS/SC10) | Find untested surface; emit gapfill tasks. |
| **Tracer** | S10 | read-only | code_index (graph queries), read | Only answer reachability source→sink. |
| **Dedupe** | S9 | none (prompt) | — | Collapse shared root causes. |
| **Root/Orchestrator-agent** | spans | coordinator | create_agent, send_message, view_graph, finish | Spawns and supervises the tree; not the deterministic orchestrator (that's code). |

**Prompt structure** (per agent, Jinja2):
- Role + non-negotiable mandate (e.g., Critic: "Assume the finding is WRONG until proven from source").
- Injected **scope context** (authorized assets only) — hard guardrail.
- Injected **skills** (relevant SC Top-10 / SCSVS / tooling docs).
- The **Recon profile** (for hunters).
- The single task + output schema (forces structured `create_finding` / `emit_verdict` tool calls; coercion on the way in).
- Thoroughness mandate + "proof, not prose" rule.

**Coordinator** (`AgentCoordinator`, Strix-derived): tree of agents, per-agent status (running/waiting/done/crashed), inter-agent messaging, `snapshot()`/`restore()` to `runs/{run_id}/state/agents.json` for resume. Concurrency capped by semaphore.

---

## 8. Tool layer

Tools are `@tool`-decorated async functions exposed to agents; errors are normalized (never crash the agent loop).

**Code intelligence**
- `code_index.query(kind, args)` — callers/callees of a function, writers/readers of a state var, external calls in a function, entrypoints, inheritance chain, storage layout, proxy info. Backed by the SQLite index + Slither IR.
- `read`, `grep`, `glob` — workspace file access (read-only for Recon/Critic/Tracer).

**Blockchain SAST / analysis** (wrappers that shell into the sandbox and return parsed JSON)
- `slither(target, detectors?)`, `aderyn(target)`, `solhint(target)`, `mythril(target, timeout)`, `halmos(test)` — symbolic/formal.
- `storage_layout_diff(impl_a, impl_b)` — proxy collision detection.

**Dynamic / PoC**
- `foundry`: `forge build|test|fuzz`, `cast`, `anvil` (fork a chain at block). Primary PoC vehicle.
- `echidna(contract, config)`, `medusa(config)` — property/invariant fuzzing (tiered pipeline: smoke→deep→targeted).
- `anchor_test`, `move_test` — non-EVM PoC runners.
- `fork_rpc(chain, block)` — spin a mainnet/testnet fork for live validation (read + simulate; no real txs against live protocol).

**Recon / intel**
- `web_search` — CVE / SWC / Solodit / DeFiHackLabs / prior-audit intel (optional provider key).
- `fetch_docs` — pull NatSpec / whitepaper / audit PDFs already in workspace.

**Workflow / lifecycle**
- `create_finding`, `emit_verdict`, `emit_trace`, `create_task` — structured, schema-validated emitters.
- `invariant_catalog(contract_types)` — returns the relevant invariant categories + templates for the target's protocol class (backs the Invariant Synthesizer); `scaffold(invariant)` — generates the handler/actor + runner-config stub for an invariant and writes it to the workspace.
- `think`, `notes`, `todo` — agent scratch space (file-backed).
- `coverage_query` — what's been analyzed + invariant run/coverage status (for Gapfill).
- `create_agent`, `send_message_to_agent`, `finish_task` — coordination/lifecycle.

---

## 9. Knowledge / skills library

Markdown skills (Strix pattern) under `chainreaper/skills/`, injected by name into agent prompts. Frontmatter `{name, description, applies_to}`. Categories:

- **`vuln_classes/`** — one file per SC Top-10 (2026) class + extras, each with: detection heuristics, code smells, call-graph patterns, a PoC template, and false-positive traps:
  - `sc01_access_control.md`, `sc02_business_logic.md`, `sc03_oracle_manipulation.md`, `sc04_flash_loan.md`, `sc05_input_validation.md`, `sc06_unchecked_external_calls.md`, `sc07_arithmetic_rounding.md`, `sc08_reentrancy.md` (classic/cross-function/cross-contract/read-only), `sc09_overflow_underflow.md`, `sc10_proxy_upgradeability.md`, plus `signature_replay_malleability.md`, `erc4626_inflation_first_depositor.md`, `mev_frontrunning.md`, `bridge_replay.md`, `bad_randomness.md`, `dos_unbounded_loop.md`, `gas_griefing.md`, `storage_collision.md`, `selector_clash.md`.
- **`scsvs/`** — the SCSVS 12 control categories as completeness checklists (ARCH, CODE, GOV, AUTH, COMM, CRYPTO, ORACLE/arithmetic, BLOCK/DoS, BRIDGE/state, DEFI/gas, COMP, + threat-modeling). Used by Recon and Gapfill.
- **`contract_types/`** — risk catalogs per type (token, crowdfunding, governance, DeFi-lending/AMM/yield, oracle, escrow, lottery/randomness, identity, bridge, vault/liquid-staking, NFT, Uniswap-V4-hooks).
- **`invariants/`** — the invariant catalog the Synthesizer draws from: per `InvariantCategory` (solvency, share-price, position/PnL, liquidation/ADL, oracle, fee/funding/rounding, execution/reentrancy, access, cross-module), each with a property template, the code-hook patterns to bind to, the tool to assign, and a handler/actor scaffold template. `tools_poc/invariants.md` is the concrete GMX instantiation.
- **`tooling/`** — how-to skills for Foundry-fork PoCs, Slither/Aderyn/Mythril, Echidna/Medusa config, Halmos/Certora specs, Anvil forking, Anchor/Move testing.
- **`coordination/`** — root-agent orchestration, hunter playbook, critic adversarial playbook, tracer reachability playbook.
- **`platforms/`** — EVM, Solana (Anchor), Move (Sui/Aptos), Cosmos/CosmWasm specifics.

Skills double as the **Gapfill checklist source** — coverage is measured against the union of SCSVS categories × in-scope contract types.

---

## 10. Sandbox & runtime

- **Image `chainreaper-sandbox`** (Docker): Foundry (forge/cast/anvil/chisel), solc-select (multi-version), Slither, Mythril, Manticore, Aderyn, Solhint, Echidna, Medusa, Halmos, Node/npm/Hardhat, Solana CLI + Anchor, Sui/Aptos Move CLI, Python tooling.
- **One container per hunter/critic task** (isolation; parallel PoCs can't collide), created from a manifest mapping the read-only workspace in at `/workspace` and a writable `/scratch` for PoCs. Mirrors Strix's `session_manager.create_or_reuse`.
- **Network policy:** default **egress-restricted**; fork RPC endpoints allowlisted. No outbound transactions to live protocol contracts — fork simulation only. `web_search` goes through a controlled proxy.
- **Resource caps:** per-container CPU/mem/time limits; per-task `max_turns`; global token/$ budget enforced by the orchestrator (hard ceiling, like Visa's `max_budget_usd`).
- **Backends pluggable** (`docker` default; `local` for dev; future `k8s` for fleet scale).

> **AS-BUILT TOOLCHAIN (2026-06 — Tier 1 of §16a CLOSED the fuzzing gap; see memory `chainreaper-testing-roadmap`).** The harness runs **host-mode** (`runtime.exec_backend: host`), not the Docker image above. Host toolchain now: ✓ forge/anvil/cast/chisel, slither, halmos, wake, aderyn, solc-select, crytic-compile, **and ✓ medusa / echidna / ityfuzz** (installed to `~/.fuzzers/bin` by T1.1, on the augmented PATH; `chainreaper doctor` reports them). Still ✗ certora, kontrol, mythril, manticore. The stateful-fuzzing layer is **live**: S2 routes each invariant to the runnable tool that suits it (T1.2), and S4's per-task sandbox is pre-scaffolded with a Chimera-style layered campaign — handler + properties + halmos spec + medusa/echidna configs generated from the bound invariants (T1.3) — that the hunter runs forge→medusa→echidna→halmos and feeds into the fork-PoC funnel.

---

## 11. LLM provider abstraction

A `Backend` protocol (Visa-style) with two surfaces:
- `prompt(user, *, model, system, max_tokens, schema?) -> str|obj` — one-shot (Recon summaries, Dedupe, coercion).
- `agentic(task, *, model, tools, max_turns) -> AgentResult` — tool-use loop (Hunters, Critics, Tracers).

Implementations: `anthropic_sdk` (default), `anthropic_cli`, `openai_compat` (LiteLLM-routed). Per-role model selection in config (`models.recon`, `models.hunt`, `models.critic`, `models.trace`, `models.dedupe`). Features: prompt-cache the shared Recon-profile/system prompt across the many hunter calls (cost), reasoning-effort control per role, retry with exponential backoff, token/usage ledger per stage. When a **Mythos-class security model** is provisioned, point `models.hunt`/`models.trace` at it via config — no code change.

---

## 12. Configuration

YAML, layered (`defaults` < `config.yaml` < `config.local.yaml` < env `${VAR:-default}`), Visa-style. Key blocks:

```yaml
discovery:
  source: immunefi
  filters: {min_max_bounty_usd: 50000, open_source_only: true,
            chains: [ethereum, arbitrum, base], languages: [solidity, vyper],
            allow_kyc: false}
  ranking_weights: {max_bounty: 0.3, total_paid: 0.2, open_source: 0.2,
                    sc_focus: 0.15, scope_clarity: 0.1, kyc_penalty: 0.05}
models:
  recon: claude-sonnet-4-6
  hunt:  claude-opus-4-8
  critic: claude-opus-4-8
  trace: claude-opus-4-8
  dedupe: claude-sonnet-4-6
  coerce: claude-haiku-4-5
hunt:
  max_concurrent_agents: 16        # raise toward 50 for big targets
  max_turns_per_task: 60
  require_poc: true
  live_validation: fork_only       # off | fork_only | testnet
validate:
  prefilter: {min_confidence: 0.55, reject_test_paths: true, line_tolerance: 3}
  critic_runs: 1                    # bump to 3 for adversarial voting
pipeline:
  feedback_rounds: 1
  stop_after: null                  # or s4, s10, ...
budget:
  max_usd: 200
  max_tokens: null
sandbox: {backend: docker, image: chainreaper-sandbox, egress: restricted}
```

Per-target overlays (extra exclusions, custom RPC) layer on top, like Visa's step1 overlay.

---

## 13. CLI & operator surface

```
chainreaper discover [--auto-top N] [--refresh] [--open-source-only]
        [--chains ...] [--languages ...] [--min-bounty N] [--allow-kyc]
        → pull + rank the Immunefi board (table), write snapshot under runs/_targets/

chainreaper scan --target <immunefi-slug|immunefi-url|repo-url|local-path> [--config c.yaml]
        [--commit <sha>] [--allow-kyc] [--refresh]
        [--stop-after sN] [--resume] [--feedback-rounds N] [--max-usd N]
        → S0 resolves the target (Immunefi fetch + clone, OR local path), then S1..S12, checkpointed

chainreaper resume --run <run_id>            # reuse checkpoints, finish run
chainreaper report --run <run_id> [--format md|json|sarif|immunefi]
chainreaper doctor                           # verify toolchain/creds/backends
chainreaper estimate --target <...>          # scope + cost estimate, no spend
```

Two run modes (Strix): **interactive TUI** (live agent tree, findings as they land) and **headless** (CI/batch, exit code reflects confirmed-finding count). A run manifest (`run_manifest.json`: config hash, models, target, command line, exit code) is written for every run.

---

## 14. Reporting & submission

- **Per-finding markdown:** title, severity (post-Critic, post-Trace), CVSS vector+score, SC Top-10 / SCWE / SWC mapping, $-impact, exploit scenario, source→sink reachability path, **PoC files + run log**, remediation.
- **Executive summary:** target, scope, coverage %, precision %, findings by severity, exploit chains, dropped-finding audit (with reasons), cost/token metrics, `degraded` flag.
- **Machine formats:** `findings.json`, `findings.csv`, `report.sarif`.
- **Immunefi submission drafts:** one per confirmed finding, pre-mapped to the program's impact category and severity scale, PoC attached, ready for **human review and manual submission**.
- **Redaction** before anything leaves the run dir.

---

## 15. Repository layout

```
chainreaper/
  cli.py                      # discover|scan|resume|report|doctor|estimate
  orchestrator/
    sequencer.py              # S0..S12 ordering, checkpoints, resume, budget
    checkpoints.py
    manifest.py
    injectors.py              # scope rules, known-bug feed, controls
  stages/
    s0_discovery.py  s1_index.py  s2_recon.py  s3_prefilter_tasks.py
    s4_hunt.py       s5_validate.py  s6_gapfill.py  s7_hunt2.py
    s8_validate2.py  s9_dedupe.py    s10_trace.py   s11_feedback.py
    s12_report.py
  agents/
    coordinator.py            # tree, messaging, snapshot/restore
    factory.py                # build_agent + Jinja2 prompt render
    prompts/                  # base templates per role
  backends/
    base.py  anthropic_sdk.py  anthropic_cli.py  openai_compat.py
  tools/
    code_index.py  sast.py  foundry.py  fuzzing.py  recon.py  workflow.py
  index/
    treesitter.py  slither_ir.py  store.py        # SQLite + graph
  skills/                     # markdown knowledge (see §9)
  report/
    markdown.py  sarif.py  cvss.py  cwe_scwe.py  redact.py  immunefi.py
  runtime/
    sandbox.py  docker_backend.py  session_manager.py
  models.py                   # Pydantic contracts + coercion + enums
  config/
    defaults.yaml  profiles/{sdk,cli,full}.yaml
  targets/
    immunefi_client.py        # fetch+parse __NEXT_DATA__ (information/scope/resources) + snapshot cache + ranking
    source_resolver.py        # clone repos@commit, map in-scope names→source files, explorer-API fallback, allowlist
containers/
  Dockerfile.sandbox
runs/                         # per-run output (gitignored)
  {run_id}/{workspace,state,checkpoints,findings,report}/
  _learning/                  # cross-run feedback store
tests/
docs/
```

---

## 16. Implementation roadmap

**Milestone 1 — Spine & contracts (week 1–2)**
- `models.py` (all Pydantic contracts + coercion), orchestrator sequencer with checkpoint/resume, config loader, run manifest, CLI skeleton (`scan`/`resume`/`doctor`), `Backend` protocol + `anthropic_sdk`. Stub stages that pass typed objects through. *Exit:* an end-to-end no-op run checkpoints and resumes.

**Milestone 2 — Index + Recon (week 2–4)**  ✅ **DONE & VERIFIED (2026-06)**
- Sandbox image, `code_index` (Slither IR + SQLite store), S1 Index, S2 Recon agent producing real ReconProfile + tasks, S3 prefilter. *Exit met:* `chainreaper scan --target gmx-source/gmx-synthetics --stop-after s3` → architecture doc + 18 hook-bound invariants + one holistically-ranked HunterTask queue + scheduled S3 decisions, recall 3/3 on the GMX 2025-hack class. (Backends: `claude_cli` verified; `anthropic` SDK present. Tree-sitter deferred — Slither covers Solidity.)

**Milestone 3 — Hunt + Validate single round (week 4–6)**  ⬅ **NEXT (S4 Hunt is the immediate target)**
- Coordinator, Hunter agent with Foundry-fork PoC loop, `create_finding`; Critic agent + prefilter + CVSS; skills library v1 (SC Top-10). *Exit:* on a known-vuln repo (e.g., a DeFiHackLabs case), hunters find it, produce a passing PoC, critic confirms.

**Milestone 4 — Full pipeline (week 6–8)**
- Gapfill, round 2, Dedupe (2-pass), Trace, Feedback (within-run + learning store), Report (md/json/sarif/immunefi-draft). Concurrency scaling. *Exit:* full S0→S12 on a real (authorized) Immunefi target in fork-only mode.

**Milestone 5 — Discovery + hardening (week 8–10)**
- S0 Immunefi client + ranking board, budget enforcement, redaction, egress policy, TUI, doctor/estimate, cross-run learning, non-EVM platform skills. *Exit:* `chainreaper discover` → pick → `scan` → reviewable report + submission drafts.

**Milestone 6 — Evaluation & tuning (ongoing)**
- Benchmark precision/recall against DeFiHackLabs PoC corpus + past Immunefi disclosures; tune ranking weights, critic-vote counts, prefilter thresholds; expand skills.

### 16a. Technique-coverage roadmap (2026-06 — apply all current SC testing techniques)

*Motivation:* GMX + Gains live runs returned ~0 robust findings. Honest read: credible negatives on well-audited targets (zero `blocked`, recall 3/3, good precision) **but** real structural blind spots + the harness can't run its own designed fuzzing layer. SOTA (2025/26) has converged on **layered hybrid** pipelines (static → stateful-fuzz → symbolic → LLM). Detail + citations live in memory `chainreaper-testing-roadmap`; that memory is authoritative.

**Blind spots:** (1) multi-contract/economic chains [biggest]; (2) deep stateful/long-horizon; (3) economic-model vs code bugs; (4) unknown-unknowns; (5) self-validating single hunter.

**Tier 1 — make the existing design real (quick, low-risk): ✅ BUILT 2026-06-24.**
- **T1.1 ✅** Fuzzing layer installed to `~/.fuzzers/bin` (Medusa 1.5.1, Echidna 2.3.2, ItyFuzz nightly), added to `index/build._TOOL_PATH_DIRS` + `runtime/exec._TOOL_PATH_DIRS`/`augmented_env`; `chainreaper doctor` reports each; positive-control smoke `tests/smoke_fuzzers.py` (echidna/medusa falsify a broken property; ityfuzz flags an arbitrary-call bug).
- **T1.2 ✅** Invariant→tool routing real: `runtime/exec.available_invariant_tools()` resolves which `InvariantTool` values are installed; `s2_recon` unions them with the index SAST tools and passes the menu to `factory.sast_block` (now per-tool *sweet-spot* guidance: medusa=stateful, halmos=symbolic-proof, slither=static…); the coercion guard snaps any non-runnable tool to slither.
- **T1.3 ✅** Chimera campaign engine: `runtime/campaign.build_campaign(task, dossier)` deterministically generates a handler (actors + one ghost var per invariant + a `handle_*` wrapper per reachable entrypoint) + Properties (each invariant as `invariant_<ID>` that BOTH returns bool and asserts → medusa property-mode AND echidna/medusa assertion-mode) + a halmos `check_<ID>` spec + valid `medusa.json`/`echidna.yaml` + `CAMPAIGN.md` runbook; `Sandbox.prepare(..., campaign_files=)` writes it (non-clobbering); hunter prompt + `tools_doc` drive forge→medusa→echidna→halmos→fork-PoC. Verified: real GMX dossier → handler compiles, medusa registers all invariants, halmos loads checks (`tests/smoke_campaign.py`).
- **T1.4 ✅** `VulnClass` aligned to OWASP SC Top-10 **2026** (re-ranked: Business-Logic SC02, Flash-Loan SC04, Reentrancy SC08; added `arithmetic_error` SC07 + `proxy_upgradeability` SC10; DoS/randomness kept as extras). Stable enum *values*; new `VULN_SC_TOP10` map + `sc_top10_for()` (single source of truth); emitter auto-stamps a Finding's `sc_top10`; `attack_class_block` SC labels corrected.

**Tier 2 — real capability gaps: ✅ BUILT 2026-06-24.**
- **T2.1 ✅** Cross-contract / economic-chain hunter mode. New `models.ProtocolGraph` (`ProtocolNode`/`ProtocolEdge`) rides on `ReconProfile(Input).protocol_graph`; `HunterTask` gained `contracts` + `attack_path` (empty ⇒ classic single-region task). `factory.cross_contract_block` injects the graph + multi-hop attack mandate (oracle→AMM→liquidation, flash-loan-amplified, cross-module, bridge replay) into recon; `hunter_profile_block` renders the graph, `hunter_task_block` renders the full attack chain; `dossier` folds all `contracts`/`attack_path` hops into resolution (cap 16); `prefilter` never folds a cross-contract task into a single-region twin. recon.md + hunter.md updated. (`tests/smoke_crosscontract.py`.)
- **T2.1/T2.2 fork-aware upgrade ✅ (2026-06-24)** — economic/cross-contract threats are now *accurately* tested, not just offered: the medusa campaign runs in **FORK MODE** against the real deployed contracts (`forkConfig` → a KEYLESS url: the local anvil, default-fronted, or a free archive; `s4_hunt._campaign_fork` guarantees no key leaks into the checkpoint), and cross-contract/economic tasks get a **multi-contract handler** (real-address slots + flash-loan/AMM-price-move/harvest primitives + a protocol-solvency `optimize_protocolLoss` objective) with a CAMPAIGN.md mandate to RUN the fork campaign before concluding `empty`. Verified live (medusa fork-mode reads real Polygon state via anvil; generated economic handler runs end-to-end) + `tests/smoke_campaign.py`.
- **T2.2 ✅** Optimization + LLM-guided fuzzing, layered onto the T1.3 campaign engine. The generated handler now carries `optimize_attackerPnL()` (medusa `optimizationTesting` enabled → MAXIMIZE attacker profit) + `ghost_attackerPnL`; `medusa.json` `targetFunctionSignatures` FOCUSES the fuzzer on the recon-ranked entrypoints (LLM4Fuzz-style steering — verified focus sigs exactly match generated wrappers + property/optimization tests still register); `handle_*` wrappers are ordered by the attack path; `CAMPAIGN.md` carries a FUZZ SEEDING section. (`tests/smoke_campaign.py` extended; real medusa run confirms optimization test executes.)

**Tier 3 — assurance & measurement:**
- **T3.1 ✅ BUILT 2026-06-24** S5 Critic + N-vote adversarial validation. `models.Verdict`/`VerdictList` added (coerced confidence 0..10 / cvss / severity). New `stages/s5_validate.py`: for each S4 finding spawns **N independent Critic agents** (`validate.votes_high_sev`=3 for critical/high, `votes_default`=1 else), each in a sandbox to **re-run the PoC** and prompted to **REFUTE** (`agents/prompts/critic.md`, `factory.build_critic_system`/`critic_finding_block`), then `aggregate_verdicts` folds the panel (majority TP→TRUE_POSITIVE, majority FP→FALSE_POSITIVE, mixed→NEEDS_LIVE_PROOF — precision-favouring). New `critic-create-verdict` emitter + `verdicts` table + CLI subcommand; runs in hunt mode so the existing guard/Stop-hook enforce it; wired into the sequencer (S5 is now a real stage, not a passthrough) + `config.validate`. Verified offline against `runs/bench-vault` (the known TRUE POSITIVE V-01): critic spec composes with the PoC under review, aggregation + Stop-hook + guard all pass, `s5_validate.run` runs with `max_findings:0` at zero tokens (`tests/smoke_s5.py`). Billed N-critic run on bench-vault is gated (token cost).
- **T3.2 ✅ BUILT 2026-06-24** Historical-hack replay calibration (`chainreaper/calibrate/` + `chainreaper calibrate` CLI + `bench/replays/registry.yaml`). `ground_truth_replay` forks a case's pre-hack block (reusing `runtime/fork.plan_forks` block-pinning) and runs its reference PoC → REPRODUCED / NOT-REPRODUCED / SKIPPED (no-RPC = clean skip). `manifest.rediscovery_overlay`/`score_findings` wire the billed harness-rediscovery measurement (gated). Verified: the self-contained synthetic positive control (`minivault-inflation`, reuses bench/vuln-vault) **reproduces for real via local forge, no RPC**; AND a **real DeFiHackLabs hack reproduces through the harness** — `calibrate/defihacklabs.py` (new `defihacklabs` poc_source) clones the repo + builds a minimal per-case project (the `_exp.sol` + the 3 shared helpers + forge-std, so only that case compiles) and forks the pre-hack block via the case's own alias pointed at our archive `<CHAIN>_RPC_URL`. **`chainreaper calibrate --case btc24h-2024-12` → REPRODUCED** on a Polygon archive fork (attacker +4953 USDT +0.76 WBTC ≈ the documented $85.7K). Full scorecard: minivault ✓ + btc24h ✓ + hedgey SKIPPED (mainnet, no RPC). `tests/smoke_calibrate.py` (injected seams + a real local replay). **BOTH follow-ups now CLOSED (2026-06-24):** (1) free-public-archive fallback (`KNOWN_FREE_ARCHIVES` + forge retry) → the full registry is **3/3 REPRODUCED with no manual RPC** incl. the **$48M Hedgey mainnet** hack on a free archive; (2) **harness-rediscovery PROVEN POSITIVE** — a billed S2(Opus)→S4 run on the BTC24H Lock victim ranked access_control P1 and landed **6/6 live-validated critical findings**, headlined by `T-AC-01-unauthorized-claim` (the real exploit), `score_findings` → rediscovered=True (5/6 match the oracle). So on a real hack the harness both reproduces AND independently discovers the bug.

*Sequence:* T1.1 → T1.2/T1.3 → T3.2 (calibration) → T2 as data directs → T3.1 (critic) when a real positive exists.

> **STATUS 2026-06-24 — ALL TIERS BUILT & verified (zero-token smoke suite green: smoke_s0..s5, smoke_secrets, smoke_emitters, smoke_fuzzers, smoke_campaign, smoke_calibrate, smoke_crosscontract) + the calibration EXERCISED on real hacks.** DeFiHackLabs calibration is live: the full registry **reproduces 3/3** with no manual RPC (incl. the $48M Hedgey mainnet hack on a free public archive), and a billed S2(Opus)→S4 rediscovery run on the BTC24H Lock victim **independently found the bug** — 6/6 live-validated critical findings, `score_findings` rediscovered=True. So the harness both *implements* every current SC-testing technique AND is empirically validated to reproduce + rediscover a real historical hack. Still open (broader empiricism, not blockers): a wider rediscovery-rate sample across more cases, and a billed S5 N-critic pass on a landed finding. Memories: `chainreaper-tier1-built`, `chainreaper-tier2-built`, `chainreaper-calibration-built`, `chainreaper-s5-critic-built`.

---

### 16b. Tier 4 — beyond pattern-shaped coverage (market / intent / trust / incentives / novelty)

*Motivation:* Tiers 1–3 + 5 live runs (GMX/Gains/Beefy/woofi/twyne — all credible zeros) built **rigorous** coverage of the *known, pattern-shaped* surface (reentrancy/oracle/flash-loan/accounting/cross-contract, fork-mode fuzzed + N-vote critic). But the harness reasons about **code + call sequences**; the highest-value *manual* findings come from reasoning about **markets, intent, external trust, incentives, and novelty**. Methodology review named the blind spots: (a) adverse-market state, (b) spec-vs-code, (c) external-integration trust, (d) governance / malicious-admin / upgrade-time, (e) game-theory/incentives, (f) long-horizon, (g) unknown-unknowns. Tier 4 closes these. Build each phase deterministic-scaffold + offline-smoke FIRST; billed agent/fuzz stages gated. Phases P2 & P6 introduce a NEW **web-research agent mode** (the recon/hunt/critic agents are web-denied).

**Cross-cutting prerequisite — `mode="research"` web-enabled agent.** ✅ **BUILT 2026-06-24 (with P2).** P2 + P6 need WebFetch/WebSearch. Add `mode="research"` to `AgentSpec`: `session.py` allows WebFetch/WebSearch (+ Read/Grep + the emit save-scripts), `hooks.decide_guard` permits them for that mode, output still via schema-validated emitters. Runs as a `claude_cli` agent (or wraps the built-in `deep-research` skill). Scope rule: a research agent READS external sources but its OUTPUT (invariants/hypotheses) is bound to the in-scope code downstream — it never marks external code in-scope.
  - *As built:* `agents/spec.RESEARCH_TOOLS` (Read/Grep/Glob + WebFetch/WebSearch + code-index) and `AgentSpec.__post_init__` give a `mode="research"` spec the web read-tools; `session._disallowed_for("research")` = `RESEARCH_DISALLOWED_TOOLS` (removes Edit/Notebook/Task but KEEPS web); `hooks.decide_guard` uses `RESEARCH_DENY_TOOLS` (Edit/MultiEdit/Notebook/Task) so WebFetch/WebSearch are PERMITTED for research mode and stay DENIED for recon/hunt/critic, while Write stays scratch-gated and Bash stays the chainreaper-only recon policy. Verified in `tests/smoke_specresearch.py`.

**P1 — Stress-fork (adverse-market simulation).** [blind spot a; HIGHEST leverage; no new agent] ✅ **BUILT & verified live 2026-06-24.** Fuzz the WORLD, not just calls. `runtime/campaign` gains a *market-condition* layer: handler primitives that **warp oracle prices, force oracle staleness, drain/skew AMM-pool reserves, depeg collateral, spike funding/utilization**, driven by the fuzzer alongside protocol calls — with the existing invariants + attacker-PnL/protocol-solvency objectives evaluated UNDER stress. Medusa fork-mode (already wired, T2 upgrade) runs it against deployed state; recon already maps the manipulable surfaces in `protocol_graph`. Wiring: `campaign.py` (market handler + ghost market vars + a `stress` flag on `build_campaign`), `s4_hunt` (pass stress for oracle/market tasks), hunter prompt. Verify: generate→compile→a real medusa stress run that moves a forked pool's price and re-checks solvency.
  - *As built:* `runtime/campaign._stress_block()` emits five `handle_stress*` primitives — `handle_stressWarpOraclePrice` (push the read price 0.01x–3x), `handle_stressForceOracleStale`, `handle_stressSkewPoolReserves` (drain/skew the real AMM pool), `handle_stressDepegCollateral`, `handle_stressSpikeFunding` — plus ghost market vars (`ghost_oraclePriceBps`/`ghost_oracleStale`/`ghost_collateralPegBps`/`ghost_fundingRateBps`/`ghost_poolSkewBps`). `build_campaign(..., stress: bool | None)`: `None` auto-enables for market-sensitive classes (`_STRESS_CLASSES` = the economic classes + `denial_of_service`/`arithmetic_error`); `True`/`False` force it. The medusa optimize_attackerPnL/optimize_protocolLoss objectives + every invariant are evaluated AFTER each stress move; CAMPAIGN.md gains an **ADVERSE-MARKET STRESS** mandate ("don't conclude empty for a market task until you've run the campaign with a stress wrapper wired to the forked world"). `s4_hunt._task_stress(task)` forces stress for oracle/price/market tasks (class ∈ `_STRESS_CLASSES` **or** the hypothesis/attack-path names a market surface — `_STRESS_HINTS`) and passes it to `build_campaign`. hunter.md describes the layer. **Live proof:** medusa fork-mode (block 21000000 mainnet, free archive) ran the generated stress handler 23,162 calls and falsified `invariant_priceUnmoved`; a deterministic forge fork test showed `handle_stressSkewPoolReserves` (a 2M-USDC swap) moved the **real** USDC/WETH pool price **+922 bps** (2637→2881 USDC/WETH). Both base + stress handlers compile; `tests/smoke_campaign.py` extended (5 primitives + ghost vars + auto/forced toggle + stress handler compiles). ruff + full smoke suite green.

**P2 — Spec/intent invariants (Spec-Research agent).** [blind spot b] ✅ **BUILT & verified offline 2026-06-24.** Code-derived invariants can't catch *code-consistent-but-wrong-vs-intent*. New `spec_researcher` agent (mode=research): fetches the target's docs/whitepaper/audit reports/READMEs, extracts the DOCUMENTED PROMISES ("fees never exceed X", "withdrawals always possible", "rounding favors the protocol"), and emits **intent invariants** (`Invariant`, `origin="spec"`). S2 binds them to real hooks (`bind_hooks`) → S4 tests them like any invariant. Wiring: agent role + `agents/prompts/spec_researcher.md` + reuse the invariant emitter with `origin="spec"`, web-enabled session, S2 calls it before the main recon. Verify offline with a stubbed research output → intent invariants bind + flow to S4.
  - *As built:* `models.Invariant.origin` gained `"spec"`. `agents/prompts/spec_researcher.md` (extract documented promises → bound, testable intent invariants with `SPEC-` ids) + `factory.build_spec_researcher_system`. `spec.spec_research_emitters(min)` reuses the `recon-create-invariant` emitter (small min, since spec-research is additive) so intent invariants write to the SAME `invariants` table the recon agent uses → `store.get_invariants` merges them and the deterministic finalize (`bind_hooks` + the `_backstop_invariant_tasks` coverage backstop) binds + folds them into the S4 queue automatically. `s2_recon.run_spec_research(...)` runs the agent BEFORE the main recon (after `clear_run`, so its rows survive), gated by `config.agents.spec_research` (default on) + `min_spec_invariants` (default 3), wrapped try/except so a thin/failed research session never sinks Recon. `tests/smoke_specresearch.py` (stubbed research backend, zero web/tokens): research-mode permissions + prompt composition + intent invariants persist (origin=spec) + bind to real hooks + reach the S4 task queue (`task-inv-spec-*`).

**P3 — External-integration trust assumptions.** [blind spot c] ✅ **BUILT & verified offline 2026-06-24.** Recon already lists external deps as `protocol_graph` external nodes; add their **trust assumptions** ("assumes Curve `get_virtual_price` is manipulation-resistant", "assumes Aave never pauses", "trusts the LZ endpoint") and a cross-contract HunterTask subtype **`dep-misbehavior`**: the campaign MOCKS the external dep on the fork to return adversarial values (stale / extreme / reverting / reentrant) and checks the protocol's invariants hold. Wiring: `models` (task subtype/field), `factory` (dep-assumption block + render), `campaign` (mock-dep primitives), recon prompt (enumerate dep assumptions).
  - *As built:* `models.ProtocolNode.trust_assumptions: list[str]` (latent failure modes per external node) + `HunterTask.dep_target` / `dep_assumptions` (set ⇒ dep-misbehavior subtype). `runtime/campaign._dep_block(dep_target, dep_assumptions)` emits a `depAddr` slot + ghost vars (`ghost_depStale`/`ghost_depReturnBps`/`ghost_depReverting`/`ghost_depReentered`) + five `handle_dep*` primitives (`Stale`/`Extreme`/`Revert`/`Reentrant`/`ClearMock`) that `vm.mockCall`/`vm.mockCallRevert` the trusted dependency to misbehave on the fork while EVERY invariant in Properties is re-checked; `build_campaign` auto-enables it when `task.dep_target` is set, and CAMPAIGN.md gains an EXTERNAL-DEPENDENCY MISBEHAVIOR mandate. `factory`: `cross_contract_block` gains an EXTERNAL-DEPENDENCY TRUST ASSUMPTIONS section (recon enumerates per-node assumptions → emits dep-misbehavior tasks), `hunter_profile_block` renders the trust assumptions, `hunter_task_block` renders a DEP-MISBEHAVIOR section. `recon.md` Deliverable-1 (fill `trust_assumptions`) + Deliverable-3 (emit dep-misbehavior tasks). `prefilter`: a dep-misbehavior task is never DROPPED for lack of resolved in-scope targets (valid by construction) and never folded as a duplicate (distinct by the dependency it attacks). Verified: `smoke_campaign.py` (dep-misbehavior task → 5 mock-dep primitives + ghost vars + dep addr slot + dep_target surfaced + runbook mandate, gated on `dep_target`, **handler compiles**) + `smoke_crosscontract.py` (trust_assumptions render + recon mandate + hunter dep block + prefilter keeps a dep task with no resolved targets).

**P4 — Governance / malicious-admin / upgrade-time.** [blind spot d] ✅ **BUILT & verified offline 2026-06-24.** Task types that (a) assume a **compromised/malicious privileged role** (what it can do *beyond intent* — timelock bypass, param injection to insolvency, draining via a "legit" admin path) and (b) **simulate a real upgrade** (storage-layout diff across impls, init front-run on a fresh deploy). Wiring: `models` (task flags), `factory` (malicious-admin + upgrade blocks), recon (privileged-role deep-dive), an `index/` storage-layout-diff helper.
  - *As built:* `models.HunterTask.malicious_role: str` (set ⇒ assume that role is compromised) + `upgrade_sim: bool` (set ⇒ real-upgrade-simulation task). `index/storagediff.py` — pure, deterministic storage-layout-diff: `normalize_layout` (drops constants/immutables, slot-ordered, declaration-order fallback when slots are unresolved), `storage_layout_collisions(old,new)` → upgrade-UNSAFE deltas (`reassigned` insert/reorder/replace at a used slot · `retyped` width/packing change · `removed` shifts later slots; append-only growth is SAFE), `diff_contract_storage(old_vars,new_vars)`. `factory.governance_block()` (the malicious-admin + upgrade-sim recon mandate) wired into `build_recon_system`; `hunter_task_block` renders a MALICIOUS-ADMIN section (compromised role → `vm.prank` the role, prove catastrophic loss with no further bug) and an UPGRADE-SIMULATION section (storage drift via `index/storagediff` + init/re-init front-run + unprotected upgrade authority). `recon.md` Deliverable-3 emits both. `prefilter` never drops/folds a malicious-admin or upgrade-sim task (valid + distinct by construction). Verified: `tests/smoke_governance.py` — storage-diff detects a deliberate reorder collision (+ retype/remove flagged, append-only SAFE, constant dropped, no-slot decl-order fallback) and the malicious-admin/upgrade-sim tasks render + survive the prefilter.

**P5 — Game-theoretic / incentive / long-horizon.** [blind spots e, f] ✅ **BUILT & verified (offline + live medusa) 2026-06-24.** Multi-actor optimization (collusion / bribery / keeper–LP incentive misalignment — N adversarial actors, not one) + **epoch-aware, `vm.warp`/`roll` time-warped long-horizon** campaigns (interest/funding drift over thousands of blocks, checkpoint boundaries). Wiring: `campaign` (multi-actor handler + time-advance sequences + larger `callSequenceLength`), recon (incentive/role-game tasks).
  - *As built:* `models.HunterTask.multi_actor: bool` (collusion coalition) + `long_horizon: bool` (time-drift). `runtime/campaign._multiactor_block()` adds colluding-actor slots (`keeper`, `lp`) + `int256 ghost_coalitionPnL` + `optimize_coalitionPnL()` (medusa MAXIMISES the coalition's combined PnL); `_longhorizon_block()` adds a file-level `_P5Vm` hevm-cheatcode interface + a REAL `handle_advanceTime` step (`vm.warp`+`vm.roll`, 1h–~30d/jump, no forge-std needed) so the fuzzer reaches deep-time state, and `_medusa_json(long_horizon=True)` raises `callSequenceLength` 100→300 + `blockTimestampDelayMax` 1wk→1yr. `build_campaign` auto-derives both flags off the task; CAMPAIGN.md gains MULTI-ACTOR/COLLUSION + LONG-HORIZON mandates. `factory.incentive_block()` (the P5 recon mandate) wired into `build_recon_system`; `hunter_task_block` renders a MULTI-ACTOR and a LONG-HORIZON section. `recon.md` Deliverable-3 emits both. `prefilter` never drops/folds a multi-actor or long-horizon task. **Verified:** `smoke_campaign.py` (coalition objective + colluding actors + real `vm.warp/roll` handler + `callSequenceLength==300` + full medusa default preserved; **all four handlers — base/stress/dep/P5 — `forge build` compile**) + `smoke_crosscontract.py` (recon mandate + hunter render + prefilter keeps the tasks); a **live medusa run** on the P5 long-horizon config accepted the 300-length config, registered `Optimization Test: optimize_coalitionPnL` + ran the `handle_advanceTime` cheatcode handler over 52k+ calls (15/15 tests, no "Invalid configuration").

**P6 — Novel-technique / unknown-unknowns (Threat-Research agent).** [blind spot g] ✅ **BUILT & verified offline 2026-06-24.** A checklist-driven recon is blind to novel techniques. New `threat_researcher` agent (mode=research): researches RECENT attack techniques (latest hacks, audit findings, research papers — pairs with the `deep-research` skill) + the SPECIFIC protocol's mechanism, and proposes **protocol-specific, off-checklist hypotheses** (NOT SC-Top-10-shaped) → exploratory `HunterTask`s (`origin="threat_research"`). Wiring: agent role + `agents/prompts/threat_researcher.md` + web-enabled mode + emit HunterTasks; S2 runs it after the main recon to add non-pattern leads.
  - *As built:* `models.HunterTask.origin` gained `"threat_research"`. `agents/prompts/threat_researcher.md` (research the FRONTIER of attack technique × this protocol's BESPOKE mechanism → emit off-checklist HunterTasks at the intersection, anchored to in-scope `scope_hint`, with a cited technique/precedent; do NOT restate the known-pattern checklist) + `factory.build_threat_researcher_system` (+ `factory.threat_research_profile_block`, a compact mechanism digest built from the persisted `ReconProfileInput` so the agent aims its hypotheses at THIS protocol). `spec.threat_research_emitters(min)` reuses the `recon-create-task` emitter (small min, additive) so off-checklist tasks write to the SAME `hunter_tasks` table the recon agent uses → `store.get_tasks` merges them and the deterministic finalize (`build_dossiers` + the prefilter) builds each one's dossier + schedules it to S4 automatically. `s2_recon.run_threat_research(...)` runs the agent AFTER the main recon (reads the just-persisted recon profile as the mechanism block; writes into the same per-run table so the existing `get_tasks` read picks them up), gated by `config.agents.threat_research` (default on) + `min_threat_tasks` (default 3), wrapped try/except so a thin/failed research session never sinks Recon. `recon/prefilter.py` never DROPS a threat-research task for unresolved targets and never FOLDS it as a duplicate (a novel hypothesis is precisely the lead a checklist dossier wouldn't pin to a function — valid + distinct by construction). `tests/smoke_threatresearch.py` (stubbed research backend, zero web/tokens): research-mode permissions (reuses P2 wiring) + prompt composition incl. the profile mechanism block + off-checklist tasks persist (origin=threat_research) using the recon profile + flow to the S4 queue through the prefilter, including one whose dossier resolves NO in-scope targets (never-drop protection holds).

*Sequence:* P1 → P2 → P3 → P4 → P5 → P6 (P1 first = highest leverage + no new agent; the web-research mode lands with P2 and is reused by P6). **All six phases BUILT 2026-06-24.** Each phase verified offline-first (deterministic scaffold + smoke); the billed research/fuzz runs are gated. Detail + per-phase build prompts in memory `chainreaper-tier4-roadmap`.

---

## 17. Safety, scope & legal guardrails

- **Scope is law.** The scope injector restricts every stage to assets explicitly marked in-scope by the bounty program; out-of-scope assets are never cloned, analyzed, or targeted.
- **No destructive on-chain actions.** Live validation is **fork/testnet simulation only**. The harness never sends exploiting transactions to live mainnet protocol contracts or third parties.
- **No auto-submission.** Reports and Immunefi drafts are produced for **human review**; submission is a manual operator step.
- **Respect program rules** (KYC, disclosure windows, prohibited techniques, rate limits) — encoded per-target and enforced.
- **Authorized use only.** This is a defensive/bug-bounty research tool; runs require an in-scope, authorized target. Egress is restricted by default; scraping Immunefi is rate-limited and polite (prefer the official API).
- **Secret hygiene.** Redaction strips keys/secrets from all logs and reports before they leave the run directory.

---

## 18. Open decisions

1. **Immunefi access** — official API vs. scrape? (Affects S0 reliability/legality. Recommend API if obtainable.)
2. **Mythos-class model availability** — if/when a security-specialized model is provisioned, which roles route to it (Hunt + Trace recommended)?
3. **Non-EVM priority** — ship EVM-only in v1 and add Solana/Move later, or include from the start? (Recommend EVM-first.)
4. **Critic voting depth** — default single critic vs. 3-vote adversarial panel for high-severity findings (cost vs. precision).
5. **Feedback loop bound** — how many within-run feedback rounds before diminishing returns (default 1; make configurable).
6. **Live testnet validation** — enable beyond fork-only for programs that explicitly permit it?

---

*Built on the Glasswing pipeline (Recon→Hunt→Validate→Gapfill→Dedupe→Trace→Feedback→Report), Strix's agent/skills/sandbox patterns, Visa's deterministic checkpointed stage contracts, and the OWASP SC Top-10 (2026) / SCSVS / SCSTG blockchain knowledge base.*
