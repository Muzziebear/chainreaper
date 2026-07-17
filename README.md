<div align="center">

<img src="chainreaper/banner.png" alt="Chainreaper — Break the Blockchain">

<h3>An adversarial, multi-agent harness that discovers <em>and proves</em> smart-contract vulnerabilities.</h3>

<p>
  <a href="#license"><img src="https://img.shields.io/badge/license-MIT-yellow.svg" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/python-3.11%2B-blue.svg" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/PoCs-Foundry%20fork-black.svg" alt="Foundry">
  <img src="https://img.shields.io/badge/contracts-Pydantic%20v2-e92063.svg" alt="Pydantic v2">
  <img src="https://img.shields.io/badge/status-research-orange.svg" alt="Status: research">
</p>

</div>

Chainreaper automates the workflow a smart-contract auditor follows on a bug-bounty target: it pulls and indexes the source, reasons about the protocol's invariants and threat surface, generates candidate findings, then **proves or refutes each one with an executable proof-of-concept against a mainnet fork**. Its defining design goal is _false-positive resistance_ — an adversarial critic stage re-runs every proposed exploit and tries to break it before it is ever reported.

> [!WARNING]
> **Authorized use only.** Chainreaper is a defensive security-research tool for targets you are
> explicitly permitted to test — public bug-bounty programs, audit contests, or your own contracts.
> Do not point it at systems you have no authorization to assess.

## Table of contents

- [Why Chainreaper](#why-chainreaper)
- [Features](#features)
- [How it works](#how-it-works)
- [Installation](#installation)
- [Quickstart](#quickstart)
- [Configuration](#configuration)
- [Project layout](#project-layout)
- [Development](#development)
- [License](#license)

## Features

- **Evidence-based findings** — every candidate is validated by a runnable Foundry PoC on a mainnet fork; unproven claims are dropped.
- **Adversarial validation** — N independent critic agents re-run each PoC and attempt to refute it; verdicts aggregate to true-positive / false-positive / needs-proof.
- **Deterministic orchestration** — a plain sequencer drives the stages; only the reasoning stages call an LLM, and each emits a validated Pydantic contract consumed by the next.
- **Calibration suite** — replay known exploits to measure detection sensitivity before a live hunt.
- **Deep analysis toolchain** — stateful fuzzing (Echidna / Medusa), static analysis (Slither), cross-contract economic modeling, and stress-fork / adverse-market simulation.
- **Threat-surface coverage** — governance & upgrade-safety checks, external-integration trust modeling, and a threat-researcher mode for off-checklist techniques.
- **Pluggable LLM backend** — the official `anthropic` SDK (structured outputs + agentic tool-runner) or a local Claude CLI backend.

## How it works

A deterministic orchestrator sequences six stages. Each consumes the previous stage's validated data contract, so the pipeline is inspectable and resumable at any boundary.

```
  S0            S1           S2            S3             S4           S5
Discovery  →  Index   →   Recon    →   Prefilter  →    Hunt    →   Validate
  scope      codemap    hunt queue    gate/rank      fork PoCs    critic verdicts
```

| Stage  | Name      | Responsibility                                                                                                   |
| :----: | --------- | ---------------------------------------------------------------------------------------------------------------- |
| **S0** | Discovery | Resolve a target from a bug-bounty program or local repo; enumerate in-scope contracts.                          |
| **S1** | Index     | Build a structured codemap (Slither, optional Tree-sitter): functions, call graph, upgrade surface.              |
| **S2** | Recon     | Multi-agent synthesis — derive the protocol spec, explore, model the threat surface, author a ranked hunt queue. |
| **S3** | Prefilter | Deterministic validity + budget gate over the queue (drop / order / cap / tag).                                  |
| **S4** | Hunt      | A _hunter_ agent drives a Foundry sandbox, writing and running PoCs against a mainnet fork.                      |
| **S5** | Validate  | Independent _critic_ agents re-run each PoC and try to refute it; verdicts aggregate to TP / FP / needs-proof.   |

### S2 · Recon — from source to a ranked hunt queue

Recon is a multi-agent synthesis that turns the indexed codebase into a de-duplicated, ranked queue of concrete hypotheses to test. Every reasoning agent works from a **read-only tool surface** — it can query the code index, read files, and grep, but it cannot write or execute anything.

|  #  | Phase                                 | What it does                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Output                                                                                                                                                                 |
| :-: | ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
|  1  | **Spec research** _(web-enabled)_     | Reads the protocol's documented promises (docs, comments, whitepapers) — what the protocol _claims_ should always hold, independent of the implementation.                                                                                                                                                                                                                                                                                                         | **Intent invariants** (`origin=spec`)                                                                                                                                  |
|  2  | **Explore & formalize**               | The recon agent walks entrypoints → call graph → accounting state → external calls and reconciles the code against the documented promises. Emits **no tasks** in this phase.                                                                                                                                                                                                                                                                                      | A **protocol profile** (mechanism, actors, value flows) + a **codebase-specific invariant suite**, each invariant bound to a real function hook and a runnable checker |
|  3  | **Threat research** _(off-checklist)_ | A separate agent hunts novel/creative attack ideas, fed the profile and invariant suite so it targets the _orthogonal complement_ rather than re-deriving covered properties.                                                                                                                                                                                                                                                                                      | **Candidate leads**, each with a hypothesis and precedent                                                                                                              |
|  4  | **Synthesis**                         | A final agent is the **sole author** of the queue. Fed the profile digest, full invariant suite, and threat dossier, it emits one breaking task per high/critical invariant, carries every distinct threat lead forward, covers the full attack-class taxonomy (cross-contract, dependency, governance, incentive), folds true duplicates, and assigns discriminating priorities. An invariant-derived backstop guarantees a queue even if a phase yields nothing. | The unified, ranked `HunterTask` queue                                                                                                                                 |

An **invariant→tool routing** step joins the static analyzers that ran at index time with the stateful-fuzz / symbolic tools installed on the host, so each invariant is routed to the checker best suited to it _and_ guaranteed runnable downstream in S4.

### S3 · Prefilter

A purely deterministic gate over the queue — no LLM. It validates each task and drops the unreachable, with optional caps on tasks hunted.

### S4 · Hunt — prove or refute each hypothesis

Each scheduled task is hunted independently. The hunter is the only agent with a **read-write, executable sandbox** (a wired Foundry project), and it works the task down a funnel from cheap static checks to a full exploit reproduction on a fork of the live chain.

|  #  | Phase                 | What it does                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| :-: | --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
|  1  | **Fork preflight**    | Per target chain, resolve → validate → pin an archive RPC at a block, spin up a shared local `anvil` fork (verifying chain-id and contract codesize to avoid the stale-fork trap), and export `<CHAIN>_RPC_URL` for the sandbox. Degrades cleanly to local-only if no RPC.                                                                                                                                                                                                                                                                             |
|  2  | **Campaign scaffold** | A Chimera-style layered fuzzing harness is generated for _this_ task, keyed to its bound invariants and reachable surface. Depending on the task it composes an **attacker-primitive** layer (cross-contract stateful chains — `deposit→borrow`, `mint→donate→redeem`), an **adverse-market stress** layer (warps oracle price, pool reserves, peg, funding/utilization), a **dependency** layer (external integrations go stale / extreme / revert / reentrant), and **multi-actor** (coalition-PnL) + **long-horizon** (`vm.warp`/`vm.roll`) layers. |
|  3  | **Hunt loop**         | The hunter runs the task through the funnel: hand-written **Foundry** invariant/unit tests → stateful fuzzing with **Echidna** and **Medusa** (assertion, property, fork, and optimization modes) → symbolic checks with **Halmos**. Any counterexample feeds the **fork-PoC funnel**, where the hunter writes a Foundry test that reproduces the impact against the _real deployed contracts_ on the fork.                                                                                                                                            |
|  4  | **Outcome**           | A task yields a `Finding` + a runnable `PoC`, or an honest _empty_. The hunter classifies reachability (see [AGENTS.md](AGENTS.md#methodology-the-adversary-model)) rather than inflating severity.                                                                                                                                                                                                                                                                                                                                                    |

### S5 · Validate

Independent **critic** agent re-runs each PoC in a fresh sandbox and actively tries to _refute_ it — default to disproven if uncertain. Verdicts aggregate to **true-positive / false-positive / needs-proof**, and only findings that survive are reported. Most powerful when configured with a different LLM than the Hunt stage.

### Tooling

| Category                       | Tools                                                                                                                                            |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Static analysis / indexing** | [Slither](https://github.com/crytic/slither), optional [Tree-sitter](https://tree-sitter.github.io) (AST/symbols), a queryable SQLite code index |
| **Compilation & execution**    | [Foundry](https://getfoundry.sh) (`forge`, `cast`, `anvil`, `chisel`), `solc` via `solc-select`                                                  |
| **Stateful fuzzing**           | [Echidna](https://github.com/crytic/echidna), [Medusa](https://github.com/crytic/medusa) (assertion / property / fork / optimization modes)      |
| **Symbolic execution**         | [Halmos](https://github.com/a16z/halmos)                                                                                                         |
| **Forking**                    | archive-node RPCs pinned per chain, fronted by a shared local `anvil`                                                                            |
| **LLM backend**                | official [`anthropic`](https://pypi.org/project/anthropic/) SDK (structured outputs + agentic tool-runner), or a local Claude CLI backend        |

## Installation

**Prerequisites:** Python 3.11+, [Foundry](https://getfoundry.sh), and the external analysis toolchain (Slither, Echidna, Medusa) installed via the bundled setup script.

```bash
# clone
git clone https://github.com/Muzziebear/chainreaper.git
cd chainreaper

# install the package
python -m venv .venv && source .venv/bin/activate
pip install -e ".[agents,index,dev]"

# install the external analysis toolchain (Foundry, Slither, Echidna, Medusa, ...)
bash tools_poc/setup/install.sh

# verify the environment
chainreaper doctor
```

## Quickstart

```bash
# 1. configure credentials (see Configuration below)
mkdir -p .chainreaper && cp .env.example .chainreaper/env    # then fill in your keys

# 2. calibrate against known exploits to confirm detection sensitivity
chainreaper calibrate

# 3. hunt a target
chainreaper scan --help
```

The pipeline is resumable — `chainreaper resume <run-id>` continues from the last completed stage.

## Configuration

Secrets are loaded at startup from `.chainreaper/env` (git-ignored). Copy `.env.example` and fill in:

| Variable            | Purpose                                                                                              |
| ------------------- | ---------------------------------------------------------------------------------------------------- |
| `ANTHROPIC_API_KEY` | LLM backend for the reasoning stages (S2+).                                                          |
| `ETHERSCAN_API_KEY` | Verified-source resolution.                                                                          |
| `<CHAIN>_RPC_URL`   | Archive RPC endpoint per chain, used for mainnet-fork PoCs. Only the chains you target are required. |

## Project layout

```
chainreaper/     the Python package — orchestrator, stages, agents, backends, tooling
tests/           smoke tests for each stage, plus fixtures
bench/           self-contained replay cases used by the calibration suite
tools_poc/       setup script and invariant notes for the external analysis toolchain
docs/            implementation spec and design notes
```

## Development

```bash
pip install -e ".[dev]"
python tests/smoke_s0.py       # each stage ships a runnable smoke test
ruff check chainreaper/        # lint
```

The full design rationale lives in [`docs/IMPLEMENTATION-SPEC.md`](docs/IMPLEMENTATION-SPEC.md) and [`docs/IMPL-NOTES.md`](docs/IMPL-NOTES.md).

## References

- https://blog.cloudflare.com/build-your-own-vulnerability-harness/
- https://github.com/visa/visa-vulnerability-agentic-harness

## License

Released under the [MIT License](LICENSE).
