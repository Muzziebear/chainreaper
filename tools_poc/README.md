# tools_poc — Blockchain Security Tooling PoC (GMX)

Proof-of-concept install + validation of the security/indexing/fuzzing/formal toolchain from
`docs/blockchain-tooling-research.md`, exercised against the real code in `gmx-source/`:

- **gmx-contracts** (GMX V1) — Solidity **0.6.12**, Hardhat. Crown jewel: `core/Vault.sol`.
- **gmx-synthetics** (GMX V2) — Solidity **^0.8.x**, Hardhat + Foundry. ~40 modules.

Environment: Debian 13, 24 cores, Python 3.12, Node via nvm (16/20/22), Rust 1.96, Foundry 1.7.1.

> **TL;DR status:** 20+ tools installed and confirmed working. Static (Slither, Aderyn, Semgrep,
> Surya, Wake), fuzzing (Echidna, Medusa), symbolic/formal (Halmos, Mythril), mutation (Gambit,
> vertigo, slither-mutate), spec (Scribble), decompile (Heimdall), and the crytic/properties
> invariant library are all functional. Deferred: ityfuzz, Pyrometer, Kontrol (notes in §6).

---

## 1. Status matrix

| Tool | Category | Version | Install | Status | Exercised on |
|---|---|---|---|---|---|
| **Slither** | static / index | 0.11.5 | pipx `slither-analyzer` | ✅ works | V1: 156 contracts, **2857 findings** (52H/166M/747L); V2: 430 contracts ✅ |
| ↳ slither-mutate | mutation | (bundled) | " | ✅ present | — |
| ↳ slither-check-upgradeability | proxy safety | (bundled) | " | ✅ present | — |
| ↳ slither-read-storage | storage layout | (bundled) | " | ✅ present (needs `--rpc` for values) | — |
| ↳ slither call-graph printer | index | (bundled) | " | ✅ works | V1: **102 call-graph .dot** files |
| **Slitherin** | extra detectors | latest | pipx inject → slither | ✅ **29 extra** detectors | V1 |
| **Aderyn** | static | 0.1.9 | `cargo install aderyn` | ✅ works¹ | V1: **11H/18L**, V2: **12H/18L** |
| **Semgrep** | pattern / variant | 1.167.0 | pipx | ✅ works | V1: **1196**, V2: **608** findings (`p/smart-contracts`) |
| **Surya** | index / viz | 0.4.13 | `npm -g surya` | ✅ works | V1: describe + inheritance + mdreport |
| **Wake** | static + fuzz + LSP | 4.22.1 | pipx `eth-wake` | ✅ works | V1: 155 files, unsafe-erc20-call, reentrancy |
| **Echidna** | fuzzer | 2.3.2 | gh release binary | ✅ works (falsified a property) | smoke harness |
| **Medusa** | fuzzer | 1.5.1 | gh release binary | ✅ works (ran campaign) | smoke harness |
| **Halmos** | symbolic | 0.3.3 | pipx | ✅ works (proved a test) | smoke harness |
| **Mythril** | symbolic | 0.24.8 | pipx (+`setuptools<81`) | ✅ works on **bytecode**² | V1 PriceFeed (found overflow) |
| **Foundry** (forge/cast/anvil) | build/test/fuzz | 1.7.1 | foundryup | ✅ works | V1/V2 build, smoke |
| **crytic/properties** | invariant lib | git | clone | ✅ cloned (ERC20/4626/721/Math) | ready to wire |
| **Gambit** (Certora) | mutation | 1.0.6 | gh release binary | ✅ works (5 mutants on a file)³ | — |
| **vertigo** (eth-vertigo/-rs) | mutation | 1.3.0 | pipx (git) | ✅ works (needs project+tests) | — |
| **Scribble** | spec instrumentation | 0.7.10 | `npm -g eth-scribble` | ✅ works | — |
| **Heimdall** | decompiler | 0.9.2 | bifrost | ✅ works | — |
| **4naly3er** | static report | latest | git clone | ⏳ cloned (needs `yarn`) | — |
| **solc-select** | solc mgr | 1.2.0 | pipx | ✅ 0.6.12 + 0.8.20 | both |
| **crytic-compile** | build abstraction | 0.4.1 | pipx | ✅ works (needed by echidna/medusa) | both |
| **ityfuzz** | hybrid fuzzer | — | cargo (git) | ❌ build fail (alloy-primitives) | deferred §6 |
| **Pyrometer** | range analysis | — | — | ⏸ not attempted | §6 |
| **Kontrol** | formal (KEVM) | — | — | ⏸ not attempted (heavy) | §6 |

¹ Aderyn prints a full report then panics on a cosmetic post-print version-parse bug — the report file is complete and valid.
² Mythril's source mode auto-downloads solc from `solc-bin.ethereum.org`, which is **not resolvable** in this sandbox. Workaround: analyze compiled **runtime bytecode** (`-f file --bin-runtime`) or set `SOLC_BINARY` to a solc-select binary.
³ Gambit generates mutants fine on self-contained files; multi-file GMX contracts need a `gambit.json` config declaring `sourceroot` + `solc_remappings` (bare `--filename` can't resolve relative imports).

---

## 2. Quick start (env setup)

```bash
# PATH (persisted in ~/.bashrc): pipx tools live in /usr/local/py-utils/bin
export PATH="/usr/local/py-utils/bin:$HOME/.cargo/bin:$HOME/.foundry/bin:$HOME/.bifrost/bin:$PATH"
# node version manager
export NVM_DIR=/usr/local/share/nvm; source "$NVM_DIR/nvm.sh"
# local tool binaries (echidna, medusa, gambit)
export PATH="/workspaces/Blockchain-Testing/tools_poc/bin:$PATH"
```

**Critical per-project gotchas discovered (these block compilation if missed):**

| Project | solc | Node | Gotcha |
|---|---|---|---|
| **V1** gmx-contracts | 0.6.12 | **16** (`nvm use 16`) | `hardhat.config.js` requires `./env.json` → `cp env.example.json env.json` |
| **V2** gmx-synthetics | 0.8.x | **22** (default; Hardhat 2.26 needs ≥22.13 — the `.nvmrc` saying 20 is stale) | `npm install` **must** use `--legacy-peer-deps --ignore-scripts` (else `@parcel/watcher` gyp build fails and npm **rolls back the whole `node_modules`**) |

---

## 3. Per-tool usage against gmx-source

All result files are under `tools_poc/results/<tool>/`.

### Slither (primary static + index backbone)
```bash
# V1 (compile via Hardhat under node16 first)
cd gmx-source/gmx-contracts && cp -n env.example.json env.json
nvm use 16; npx hardhat compile
slither . --json out.json            # 156 contracts, 101 detectors, 2857 results
# Re-run without recompiling:
slither . --ignore-compile
# Indexing: per-contract call graphs (102 .dot files) + storage + summaries
slither . --ignore-compile --print call-graph        # → *.call-graph.dot
slither . --ignore-compile --print inheritance-graph
slither . --ignore-compile --print human-summary      # capture stderr: 2>&1
# V2: force hardhat framework or use foundry (see §2 gotchas); after compiling:
slither . --compile-force-framework hardhat --ignore-compile
```
Reentrancy variants, unchecked-transfer, missing-zero-address all fired on V1 — exactly the class
behind the 2025 GMX hack (though cross-contract reentrancy needs the fuzzers/Wake to confirm).

### Aderyn (fast Rust static pass)
```bash
cd gmx-source/gmx-contracts
aderyn . -x node_modules,test/ -o report.md   # exclude node_modules (incompatible-version fixtures break it)
```

### Semgrep (pattern / variant analysis — no compile needed)
```bash
semgrep --config p/smart-contracts gmx-source/gmx-contracts/contracts --json -o out.json
```

### Surya (architecture / call-graph for the Recon stage — no compile)
```bash
surya describe contracts/core/Vault.sol
surya inheritance contracts/core/*.sol > inherit.dot
surya mdreport report.md contracts/core/*.sol
```

### Wake (static + own compiler + LSP; reproduces attack scenarios)
```bash
cd gmx-source/gmx-contracts && nvm use 16
wake detect all          # downloads its own solc 0.6.12, compiles 155 files, prints annotated findings
# Wake is also the tool Ackee used to REPRODUCE the GMX hack via `wake test` python scenarios.
```

### Echidna + Medusa (property / invariant fuzzing) — needs `crytic-compile` on PATH
```bash
solc-select use 0.8.20
echidna src/Smoke.sol --contract Smoke --test-mode property --test-limit 50000
medusa fuzz --config medusa.json     # parallel, coverage-guided
```
Wire `crytic/properties` (ERC20/ERC4626/ABDKMath) against GMX tokens/GLP for real invariants.

### Halmos (symbolic, reuses Foundry tests)
```bash
halmos --root <foundry_project> --function check_<name>
```

### Mythril (symbolic) — use bytecode in this sandbox (solc-bin host blocked)
```bash
# from a compiled hardhat artifact:
python3 -c "import json;print(json.load(open('artifacts/.../X.json'))['deployedBytecode'])" > x.bin
myth analyze -f x.bin --bin-runtime --execution-timeout 120
```

### Mutation testing (validate the test suite / invariants)
```bash
gambit mutate --filename contracts/core/Vault.sol          # generate mutants
vertigo run --hardhat-parallel 8                            # run suite vs mutants (needs working test cmd)
slither-mutate <codebase> --test-cmd "<test command>"
```

### Decompile / spec
```bash
heimdall decompile <bytecode_or_address>
scribble --instrument <annotated.sol>     # compile specs into runtime assertions for fuzzing
```

---

## 4. Recommended layered workflow for GMX

1. **Index/Recon:** Slither (IR + 102 call-graph dots) + Surya (architecture) + Wake (LSP/detectors).
2. **Cheap static sweep:** Slither (+Slitherin) + Aderyn + Semgrep → leads, not verdicts.
3. **Invariant/fuzz (where the money bugs are):** Foundry smoke → Medusa deep → Echidna targeted,
   seeded with **crytic/properties** (ERC4626/ABDKMath for GLP/Vault) + optimization-mode ("maximize GLP price").
4. **Symbolic/formal:** Halmos on Foundry tests → escalate critical accounting invariants to Kontrol/Certora.
5. **Mutation:** Gambit/vertigo/slither-mutate to prove the suite actually catches regressions.

---

## 5. Reproduce

`tools_poc/setup/install.sh` reinstalls the whole stack. Per-run outputs are in `tools_poc/results/`.
Smoke harness for fuzzers/symbolic is in `tools_poc/smoke/`.

---

## 6. Deferred / known issues

- **ityfuzz** — `cargo install` fails compiling `alloy-primitives` (toolchain mismatch). Recommend the
  prebuilt `ityfuzzup` installer or a pinned nightly. High value for V1 (live-fork exploit repro) — worth revisiting.
- **Pyrometer** — not attempted (Rust build); optional range-analysis layer.
- **Kontrol** — not attempted; heavy (KEVM via `kup`, multi-GB). Use Halmos first; reserve Kontrol for the hardest invariants.
- **4naly3er** — cloned; needs `yarn install` in `tools_poc/4naly3er` to run.
- **Mythril source mode** — blocked by `solc-bin.ethereum.org` DNS; use bytecode mode or `SOLC_BINARY`.
- **V2 Hardhat via `npx`** — fails `HHE22`; use the local binary `./node_modules/.bin/hardhat` or Foundry.
- **V2 Slither** — analyzes all 430 contracts and emits findings (reentrancy×17, divide-before-multiply, arbitrary-send, weak-prng, tx.origin, unprotected-upgradeable, arbitrary-from-in-transferFrom). A few mock/relay functions log non-fatal `Impossible to generate IR` skips, and `--json` can fail to serialize on that; the human-readable text output (`results/slither/v2-full.txt`) is complete regardless.
