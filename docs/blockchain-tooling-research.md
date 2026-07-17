# Blockchain Security Testing & Indexing — Tooling Research

> Grounded in the two codebases in `gmx-source/`. Scope: indexing / code intelligence, static analysis, invariant & fuzz testing, symbolic/formal verification, and the relevant Trail of Bits (ToB) ecosystem — with a concrete recommendation per target.
>
> Date: 2026-06-18 · Companion to `IMPLEMENTATION-SPEC.md`.

---

## 1. The two targets dictate two different toolchains

| | **gmx-contracts (V1)** | **gmx-synthetics (V2)** |
|---|---|---|
| Solidity | **0.6.12** (+ `^0.6.0`) — pre-0.8, **no built-in overflow checks** (SafeMath era) | **^0.8.x** (mostly `^0.8.0`, some 0.8.20/0.8.22) — checked arithmetic |
| Build | **Hardhat only** (JS/waffle) | **Hardhat + Foundry** (`foundry.toml`, `forge-std` submodule present) |
| Tests | 59 JS/TS Hardhat tests | 136 JS/TS Hardhat tests; **only 1 `.t.sol`** (Foundry barely used) |
| Fuzzing/invariants | **None** | **None wired** (Foundry present but unused for invariants) |
| Formal | None | **Certora engagement exists** (`audits/certora/`) |
| Oracle model | Keeper-pushed **fast-price feed** | Keeper/oracle-signed prices, multi-module pricing |
| Crown-jewel contracts | `core/` **Vault** (perps + GLP accounting, holds funds), `oracle/` price feeds, `amm/` | `order/`, `position/`, `market/`, `pricing/`, `swap/`, `oracle/`, `glv/`, `adl/`, `reader/` |
| Audits on file | ABDK, Quantstamp, Guardian | ABDK, **Certora**, Dedaub, Guardian (12+), Sherlock |

**Implications:**
- **V1's 0.6.12 is the main constraint.** Modern Foundry/Halmos/Medusa target newer solc, but all still compile 0.6.x via `solc-select` / `crytic-compile`. The cleaner path for V1 dynamic testing is **bytecode-level + fork-based** (ityfuzz, Echidna fork mode) since V1 is deployed and live — you can fuzz real on-chain state rather than reconstructing a 0.6.12 harness from scratch.
- **V2 is the easy case:** it already ships Foundry + forge-std and has a Certora history, so invariant testing and formal verification slot in directly. Its ~40-module surface makes **indexing/code-intelligence** the highest-value first investment.
- Both are **fork-friendly** (V2 already has `fork:arbitrum` / `fork:avalanche` Hardhat scripts and Tenderly config) → fork-based economic/oracle-manipulation simulation is realistic for both.

---

## 2. Indexing & code intelligence

The harness's Index stage needs: AST + symbols, call graph, inheritance graph, data-flow (taint source→sink), storage layout, entrypoint enumeration, and a queryable store. Recommended stack:

| Tool | Role | Why / notes | GMX fit |
|---|---|---|---|
| **Slither** (ToB) | **Primary indexing backbone** | Produces **SlithIR** (SSA IR), call graph, inheritance graph, data-dependency/taint, function summaries, storage layout (`slither-read-storage`), and **printers** (`call-graph`, `inheritance-graph`, `function-summary`, `cfg`). Python API → easy to extract into our own graph DB. Supports 0.5–0.8. | Works on **both** V1 (0.6.12) and V2. The single most important tool. |
| **Wake** (Ackee) | Secondary intelligence + LSP | Python framework: static analysis **+ detectors + LSP + control-flow/call graphs + integrated fuzzing**. "Slither + Foundry-style fuzzing in one." Has a VS Code language server (good for symbol resolution). *Wake Arena* (2025) is their graph-driven AI audit tool with 87 private detectors. | Strong on V2; modern-Solidity oriented. |
| **Surya** | Lightweight graph/visualization | Fast call graphs, inheritance, function-level mermaid/graphviz, `surya describe`. Cheap to run, good for the Recon architecture doc. | Both. |
| **Aderyn** (Cyfrin) | Fast AST static pass | Rust, AST-based, markdown output, CI-friendly, custom detectors (Nyth). Complements Slither, much faster on big trees. | Both (esp. V2's large surface). |
| **Semgrep + smart-contract rules** | Pattern indexing / variant analysis | Pattern matching across the tree; underpins "find similar bug elsewhere." | Both. |
| **ToB `trailmark` skill** | Code-graph + diagrams + mutation triage | From the ToB Claude Code skills repo — code graph analysis, Mermaid diagrams, protocol verification. Pairs with our agentic Recon. | Both. |
| `solidity-code-metrics` | Complexity metrics | Already in V1 deps; cheap HotZone ranking signal. | V1 ships it. |

**Recommendation:** Build the index store on **Slither IR + call/inheritance graph** as the canonical source, enrich with **Wake** (symbols/LSP + detectors) and **Surya** (visual call graphs for the Recon profile). This satisfies the "create call property graphs" requirement without reinventing graph extraction.

---

## 3. Static analysis / detectors (the cheap first pass)

Run all of these in the Index stage and cache raw JSON as *evidence* (not yet findings):

- **Slither** — 90+ detectors incl. reentrancy, uninitialized storage, **upgradeability/proxy** checks, arbitrary-send, unchecked-transfer. Custom detectors via API for GMX-specific patterns (e.g., oracle-staleness, fee rounding direction).
- **Wake detectors** — overlapping but complementary set; reentrancy, ownable, unchecked-return.
- **Aderyn** — fast structural issues; good signal-to-noise for triage.
- **Mythril** (ConsenSys) — bounded symbolic bug-finding, emits SWC IDs + example txs. Useful but slow; time-box it.
- **Semgrep** — variant analysis / org-specific anti-patterns.

> No single tool exceeds ~8–20% of real bugs (per the OWASP/IEEE data in the knowledge base) — the value is in **layering** + feeding outputs to the agentic hunters as leads, not treating them as the answer.

---

## 4. Invariant & fuzz testing (the core of finding real economic bugs)

This is where GMX-class bugs (insolvency, PnL accounting, oracle/AMM manipulation, ADL, fee rounding) actually surface. Current (2026) landscape and recommended layering:

| Tool | Type | Strengths | Weaknesses | Use for |
|---|---|---|---|---|
| **Foundry invariant** (`forge`) | In-process, coverage-guided | Fast, native to V2, great DX, handlers/actors model | No coverage report for invariants; weaker on deep multi-tx bugs alone | **Stage 1 smoke** — quick invariants every commit |
| **Medusa** (ToB) | Geth-based, parallel, coverage-guided | **Surpassed Echidna for most cases**; parallel workers; caught precision-loss bugs needing 100s of txs that others missed; smart mutation | Sequence shrinking still maturing | **Stage 2 deep stateful** — primary deep fuzzer |
| **Echidna** (ToB) | Haskell, property + assertion | Best **shrinking** + coverage reporting; mature; **fork mode** auto-discovers token holders | Single-process (slower than Medusa) | **Stage 3 targeted** — minimize/triage, fork-mode property tests |
| **ityfuzz** (fuzzland) | **Bytecode-level hybrid** | **On-chain fork mode**: pulls ABI/bytecode/state from RPC at any block; ~2.5× faster than Echidna; +44% bugs vs Echidna on Daedaluzz; great for **exploit reproduction on live state** | Less readable harnesses (bytecode) | **V1 + any live target** — fork-based exploit PoC without rebuilding a 0.6.12 harness |
| **Recon / chimera** | Abstraction + cloud | Write invariants once, run on Foundry/Echidna/Medusa; cloud scaling | Extra dependency | Scale/CI orchestration of the above |

**Recommended tiered pipeline (matches the knowledge-base workflow):**
1. **Smoke** — `forge test` invariants, every commit.
2. **Deep stateful** — **Medusa**, parallel workers, nightly/pre-hunt.
3. **Targeted** — **Echidna** for shrinking + fork-mode property tests on specific HotZones.
4. **Live repro** — **ityfuzz** fork mode for reproducing/confirming exploitability against real chain state.

**Per-target:**
- **V2:** Foundry invariants + Medusa are the natural fit (Foundry already present). Define invariants on `market`/`position`/`pricing`/`reader` (e.g., "pool solvency: claimable ≤ backing", "no free PnL", "fee rounds against user").
- **V1:** ityfuzz fork mode is the pragmatic primary (avoids reconstructing a 0.6.12 invariant harness); Echidna/Medusa also support 0.6.x via `solc-select` if you want source-level harnesses on the Vault.

---

## 5. Symbolic execution & formal verification

For the highest-value invariants where fuzzing can't give a *proof*:

| Tool | Approach | Notes | GMX fit |
|---|---|---|---|
| **Halmos** (a16z) | Symbolic testing, **reuses Foundry tests** | Bounded (set `--loop` depth); no separate spec language; lowest barrier to entry — reuses `forge` tests as symbolic properties | **V2** — easiest win on top of existing Foundry tests |
| **Kontrol** (Runtime Verification) | KEVM + Foundry | Most rigorous OSS option; **unbounded loop invariants**; Foundry cheatcode integration | V2 — for the hardest accounting invariants |
| **Certora Prover** (CVL) | Commercial, spec language | Most mature for deep protocol invariants; **GMX V2 already has a Certora engagement** → extend existing CVL specs rather than start cold | **V2** — reuse/extend `audits/certora` |
| **hevm** | Symbolic, consumes Foundry tests | Alternative/complement to Halmos | V2 |
| **Mythril / Manticore** (ToB) | Symbolic bug-finding | Manticore less actively maintained in 2025; Mythril useful but slow | Both, time-boxed |

**Recommendation:** Start with **Halmos** on V2 (cheap, reuses Foundry tests), escalate the few critical accounting invariants to **Kontrol** or the **existing Certora** specs. Treat formal as the apex of the pyramid, applied to a handful of must-hold invariants — not broadly.

---

## 6. Trail of Bits ecosystem — what to adopt directly

ToB authors most of the field-standard OSS here, and (notably) ships **Claude Code skills** we can fold straight into the harness's skills layer:

**Tools:** Slither, Echidna, Medusa, Manticore, **Diffusc** (differential fuzzing of *upgradeable* contracts — relevant since GMX upgrades), `crytic-compile` (the build-system abstraction all their tools share), `slither-read-storage`, `properties` (ToB's library of ready-made ERC20/ERC4626 property tests).

**ToB Claude Code skills** (`github.com/trailofbits/skills`) — directly reusable as harness skills:
- **`trailmark`** — code-graph analysis, Mermaid diagrams, **mutation-testing triage**, protocol verification.
- **`entry-point-analyzer`** — identify state-changing entry points (feeds our Trace/reachability + Recon entrypoint enumeration).
- **`audit-context-building`** — granular architectural understanding (our Recon stage).
- **`variant-analysis`** — find similar vulns across a codebase (our Gapfill/Feedback).
- **`differential-review`** — change analysis with git context.
- **`mutation-testing`**, **`property-based-testing`**, **`spec-to-code-compliance`**, **`building-secure-contracts`**.

**Recommendation:** Vendor the relevant ToB skills into our `chainreaper/skills/` library and standardize all tool invocation through **`crytic-compile`** so Slither/Echidna/Medusa share one build config across both Hardhat (V1/V2) and Foundry (V2).

---

## 7. Live / economic simulation & monitoring

- **Foundry fork tests + Anvil** — flash-loan / oracle-manipulation / multi-block MEV scenarios against forked state. V2 already has fork scripts; add Foundry fork tests.
- **ityfuzz fork mode** — automated exploit search against live state (see §4).
- **Tenderly** — V2 already configured (`tenderly.yaml`, `hardhat.config.tenderly.ts`); use for tx simulation/debugging and (optionally) monitoring.
- **Diffusc** (ToB) — differential testing across upgrades, valuable for GMX's upgrade cadence.

---

## 8. Recommended toolchain summary

```
INDEX / INTELLIGENCE   Slither (IR + graphs, backbone) + Wake (LSP/detectors) + Surya (viz) + Aderyn
                       + Semgrep (variant) ; all via crytic-compile
STATIC (cheap pass)    Slither detectors + Aderyn + Wake + Mythril(time-boxed) + Semgrep
INVARIANT/FUZZ         Foundry (smoke) → Medusa (deep, parallel) → Echidna (targeted/shrink)
                       → ityfuzz (live fork repro)
SYMBOLIC/FORMAL        Halmos (reuse Foundry tests) → Kontrol / Certora (critical invariants)
LIVE SIM               Foundry fork + Anvil, ityfuzz fork, Tenderly ; Diffusc for upgrades
SKILLS (agentic)       ToB skills: trailmark, entry-point-analyzer, audit-context-building,
                       variant-analysis, mutation-testing, property-based-testing
```

**First moves, per target:**
- **V2 (do first — highest ROI):** wire Slither + Wake indexing → author Foundry invariants on `market`/`position`/`pricing` → run Medusa → extend the existing **Certora** specs / add **Halmos** on existing Foundry tests.
- **V1:** Slither indexing (works on 0.6.12) → **ityfuzz fork mode** against the live Vault for economic invariants → Echidna source harness on `core/Vault` if deeper coverage is needed.

**Sandbox image** (`chainreaper-sandbox`) must therefore bundle: `solc-select` (0.6.12 + 0.8.x), Foundry, `crytic-compile`, Slither, Wake, Aderyn, Surya, Semgrep, Echidna, Medusa, ityfuzz, Halmos, Mythril, Node/Hardhat, and Tenderly CLI.

---

## 9. Additional tools worth adopting (GMX-specific)

Researching GMX's actual exploit history reshapes priorities. The **July 2025 $42M GMX V1 hack** was a **cross-contract reentrancy** in `PositionManager.executeDecreaseOrder`: the attacker reentered while `globalShortAveragePrices` lagged the updated short size, mispricing unrealized PnL → **inflating AUM → GLP price from $1.45 to $27**. Lessons that change the toolset:

- Single-contract reentrancy guards and static detectors **miss cross-contract reentrancy** — the bug was actually reproduced via **scenario-based testing**, and the broken safety property is an **economic invariant** ("GLP price reflects true AUM", "short size and average price stay consistent"). So the highest-value tools for GMX are **stateful invariant fuzzers in optimization mode** + **scenario/attack reproduction harnesses**, not more linters.
- The bug was introduced in 2022 while fixing a *different* bug → **mutation testing** (does the test suite catch regressions?) and **differential testing across versions** would have raised flags.

### A. Pre-built property / invariant libraries — top priority for GMX
- **`crytic/properties`** (ToB) — **168 ready-made properties**: ERC20 (25), ERC721 (19), **ERC4626 vault (37)**, and **ABDKMath64x64 fixed-point (106)**. **GMX V1 uses ABDK fixed-point math** (note `audits/ABDK_Gambit_Solidity.pdf` on file) and GLP is a vault-like share token → these properties apply almost directly. Run via Echidna/Medusa. This is the fastest path to meaningful invariants on both targets.
- **Echidna/Medusa optimization mode** — instead of "does this break," ask "**maximize GLP price / AUM**" — exactly the lens that surfaces the 2025 manipulation class.

### B. Mutation testing — validate the suite/invariants actually catch bugs
GMX ships large test suites (59 V1 + 136 V2 files) and our harness must not trust "no findings" from weak tests.
- **`slither-mutate`** (ToB) — mutation testing integrated with the Slither/crytic toolchain.
- **Certora Gambit** — generates mutants **and tests Certora CVL specs** (not just unit tests) → directly useful for the existing GMX V2 Certora specs.
- **vertigo-rs** (RareSkills) — the one that **auto-runs** the Foundry suite against mutants and reports a mutation score.

### C. Proxy / upgrade & deployment integrity
- **`slither-check-upgradeability`** (ToB) — storage-layout collisions, init-guard, constant↔variable corruption (V2 has `migration/` and upgradeable patterns).
- **`forge inspect <C> storage-layout`** / `cast storage` — storage-layout diffing across upgrades.
- **Diffyscan / decompilers (`heimdall-rs`, Dedaub)** — verify deployed bytecode == source (V1 is live on Arbitrum/Avalanche); decompile deployed contracts for fork-based analysis even where source drifts.

### D. Spec instrumentation & extra static passes
- **Scribble** (ConsenSys) — inline `/// #if_succeeds` spec annotations compiled into runtime assertions that fuzzers check; bridges human spec → automated property.
- **solc `SMTChecker`** — built into the compiler (free bounded model checking); enable on V2 (0.8.x) for cheap assertion/overflow proofs.
- **Pyrometer** (Nascent) — static + symbolic **range analysis**; strong on arithmetic/bounds, relevant to GMX accounting.
- **Slitherin** (Pessimistic) — extra Slither detector pack; **4naly3er** (Picodes) — fast Code4rena-style gas/QA triage report.

### E. Fuzzing at scale
- **Recon (`getrecon`) + chimera** — write invariants **once**, run across Foundry/Echidna/Medusa, and scale in the cloud — good fit for the harness's parallel Hunt stage.
- **Diligence Fuzzing (Harvey)** — cloud fuzzing that consumes Scribble specs.

### F. Runtime / post-deployment monitoring (adjacent, if scope extends past discovery)
- **Forta**, **OpenZeppelin Monitor** (migrate off Defender before its July 2026 sunset), **Tenderly alerts/Web3 Actions** — turn confirmed invariants into live attack-detection rules. Out of scope for pure discovery, but the natural next step given GMX runs live.

### Net additions to the recommended stack
On top of §8: add **`crytic/properties`** (esp. ABDK + ERC4626) and **optimization-mode fuzzing** as first-class invariant sources; **slither-mutate / Gambit / vertigo-rs** to gate test-suite quality; **slither-check-upgradeability + storage-layout diffing** for V2 upgrades; **Scribble + SMTChecker + Pyrometer** as additional static/spec layers; **Wake scenario testing** (already in the stack) confirmed as the cross-contract-reentrancy reproduction tool of choice for this exact codebase.

## Sources

- [Trail of Bits — Blockchain services](https://trailofbits.com/services/software-assurance/blockchain/)
- [Trail of Bits — Claude Code security skills repo](https://github.com/trailofbits/skills)
- [Unleashing Medusa: fast & scalable fuzzing — ToB blog](https://blog.trailofbits.com/2025/02/14/unleashing-medusa-fast-and-scalable-smart-contract-fuzzing/)
- [Differential fuzzing of upgradeable contracts (Diffusc) — ToB blog](https://blog.trailofbits.com/2023/07/07/differential-fuzz-testing-upgradeable-smart-contracts-with-diffusc/)
- [Solidity fuzzing comparison: Foundry vs Echidna vs Medusa](https://github.com/devdacian/solidity-fuzzing-comparison)
- [The Smart Contract Fuzzer Showdown (2026 Benchmark)](https://dev.to/ohmygod/the-smart-contract-fuzzer-showdown-foundry-vs-echidna-vs-medusa-vs-trident-2026-benchmark-4ofm)
- [Wake — Ackee Blockchain (GitHub)](https://github.com/Ackee-Blockchain/wake) · [getwake.io](https://getwake.io/)
- [Slither — static analysis framework (paper)](https://arxiv.org/pdf/1908.09878)
- [Halmos — a16z symbolic testing (GitHub)](https://github.com/a16z/halmos) · [a16z write-up](https://a16zcrypto.com/posts/article/symbolic-testing-with-halmos-leveraging-existing-tests-for-formal-verification/)
- [Kontrol / formally verifying loops — Runtime Verification](https://runtimeverification.com/blog/formally-verifying-loops-part-1)
- [ityfuzz — hybrid bytecode fuzzer (GitHub)](https://github.com/fuzzland/ityfuzz)
- [Cyfrin — best smart contract auditing & security tools](https://www.cyfrin.io/blog/industry-leading-smart-contract-auditing-and-security-tools)
- [awesome-web3-formal-verification](https://github.com/johnsonstephan/awesome-web3-formal-verification)
- [crytic/properties — pre-built security properties (ToB)](https://github.com/crytic/properties) · [ToB blog: reusable properties](https://blog.trailofbits.com/2023/02/27/reusable-properties-ethereum-contracts-echidna/)
- [Slither upgradeability checks (wiki)](https://github.com/crytic/slither/wiki/Upgradeability-Checks)
- [GMX hack analysis & attack scenarios with Wake — Ackee](https://ackee.xyz/blog/gmx-hack-analysis-attack-scenarios-with-wake/)
- [GMX $42M exploit root-cause — Verichains](https://blog.verichains.io/p/gmx-42m-exploit-root-cause-analysis) · [Halborn](https://www.halborn.com/blog/post/explained-the-gmx-hack-july-2025) · [Sherlock](https://sherlock.xyz/post/gmx-exchange-hack-explained)
- [Certora Gambit — mutation generator](https://medium.com/certora/gambit-23ef5cab02f5) · [vertigo-rs (RareSkills)](https://github.com/JoranHonig/vertigo)
- [Mutation testing for Solidity — the audit quality metric](https://dev.to/ohmygod/mutation-testing-for-solidity-the-audit-quality-metric-your-protocol-is-ignoring-4bnc)
