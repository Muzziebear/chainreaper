# AGENTS.md

Operating guide for AI coding agents (and humans) working on **Chainreaper**. Read this before
running or modifying the pipeline. For the product overview see [`README.md`](README.md); for the
full design rationale see [`docs/IMPLEMENTATION-SPEC.md`](docs/IMPLEMENTATION-SPEC.md).

## Golden rules

1. **Authorized targets only.** Chainreaper is a defensive research tool. Only run it against
   public bug-bounty programs, audit contests, or contracts you own. Never commit findings or run
   artifacts for a live target into this repo.
2. **Never commit secrets or run output.** Credentials live in `.chainreaper/env` and run artifacts
   in `runs/` — both are git-ignored. Keep API keys, RPC URLs, and target-specific findings out of
   source, tests, docs, and commit messages. Use `.env.example` for key *names* only.
3. **Contracts are law.** Every stage exchanges a validated Pydantic model (see
   `chainreaper/models.py`). When you change a stage's output, update the contract and every
   downstream consumer, not just the producer.
4. **Determinism vs. reasoning.** The orchestrator is deterministic; only S2/S4/S5 call an LLM.
   Keep non-LLM logic (gating, indexing, sequencing) free of model calls so runs are reproducible.

## Repository map

```
chainreaper/
├── cli.py             Typer entrypoint — commands: scan, discover, resume, doctor, calibrate
├── config.py          layered YAML config loader
├── config/defaults.yaml
├── keystore.py        loads .chainreaper/env into the environment at startup
├── models.py          Pydantic stage contracts (Target, Finding, PoC, HuntOutcome, TriggerClass, ...)
├── stages/            s0_discovery · s1_index · s2_recon · s3_prefilter · s4_hunt · s5_validate
├── orchestrator/      sequencer (run loop) · checkpoints · manifest · injectors (scope)
├── agents/            factory · session · spec · emitters · hooks · prompts/*.md
├── backends/          anthropic_sdk · claude_cli (both behind base.py)
├── recon/             dossier · invariants · prefilter · dynamic_reach · store
├── runtime/           exec (forge/PoC) · fork · campaign (fuzz) · logging
├── index/             build (Slither) · slither_export
├── calibrate/         replay known exploits (defihacklabs) · rediscovery scoring
├── targets/           immunefi_client · source_resolver · rpc_resolver
├── tools/             agent_tools · code_index · incident_catalog · invariant_catalog
└── skills/            invariant/incident YAML knowledge packs
tests/                 smoke_*.py — one runnable smoke test per stage/subsystem
bench/                 self-contained replay cases for calibration
tools_poc/             setup script + invariant notes for the external toolchain
```

## Running the pipeline

```bash
pip install -e ".[agents,index,dev]"    # package + LLM + index extras + dev tools
bash tools_poc/setup/install.sh          # Foundry, Slither, Echidna, Medusa, ...
chainreaper doctor                        # verify environment & toolchain
chainreaper calibrate                     # replay known exploits to confirm sensitivity
chainreaper scan --help                   # hunt a target
chainreaper resume <run-id>               # continue from the last completed stage
```

Credentials are read from `.chainreaper/env` at startup (`keystore.load_env_files`); a real
exported env var always wins over the file. Required keys: `ANTHROPIC_API_KEY`,
`ETHERSCAN_API_KEY`, and per-chain `<CHAIN>_RPC_URL` archive endpoints (fork PoCs need an **archive**
node).

## The pipeline (S0 → S5)

| Stage | Module | Contract-in → Contract-out |
|-------|--------|-----------------------------|
| S0 Discovery | `stages/s0_discovery.py` | program/repo ref → `Target` (in-scope contracts) |
| S1 Index | `stages/s1_index.py` | `Target` → `IndexedRepo` (Slither codemap) |
| S2 Recon | `stages/s2_recon.py` | `IndexedRepo` → ranked hunt queue (multi-agent synthesis) |
| S3 Prefilter | `stages/s3_prefilter.py` | queue → gated/ordered/capped queue (deterministic) |
| S4 Hunt | `stages/s4_hunt.py` | queue → `Finding` + `PoC` (Foundry fork sandbox) |
| S5 Validate | `stages/s5_validate.py` | `Finding`/`PoC` → `HuntOutcome` (critic verdicts: TP/FP/needs-proof) |

The sequencer (`orchestrator/sequencer.py`) owns the `RunContext` and checkpointing; a run resumes
from its last checkpoint. Scope is enforced by `orchestrator/injectors.py`.

## Agents & backends

- **Backends** implement `backends/base.py`. `anthropic_sdk` uses the official SDK
  (`messages.parse` for structured Pydantic output + beta `tool_runner` for the agentic loop).
  `claude_cli` drives a local Claude CLI subscription (prompts + DB save-scripts + hooks — *not*
  MCP/Skills). Pick via config/env.
- **Structured output**: agents emit validated Pydantic objects through `agents/emitters.py`; the
  model retries on schema mismatch at the tool-call layer. Prefer adding an emitter over parsing
  free text.
- **Prompts** live in `agents/prompts/*.md` (`recon`, `hunter`, `critic`, `spec_researcher`,
  `threat_researcher`). Edit the markdown, not inlined strings.
- **Mode guards**: agent behavior is gated by `mode == "hunt"` vs `mode == "research"`. Respect the
  guard when adding capabilities so recon-time agents can't perform hunt-time actions.

## Testing

Smoke tests are **runnable scripts**, not `pytest`-collected (some chain return values / take
positional args). Run the one for the subsystem you touched:

```bash
python tests/smoke_s0.py        # ... smoke_s1 .. smoke_s5, plus:
python tests/smoke_synthesis.py # S2 4-phase synthesis
python tests/smoke_campaign.py  # fuzz campaign engine
python tests/smoke_emitters.py  # structured-output contracts
python tests/smoke_calibrate.py # exploit-replay harness
ruff check chainreaper/         # lint (line-length 110, target py311)
```

When you add a stage or agent capability, add a matching `smoke_<name>.py` that exercises it end to
end and prints a pass/fail summary via its `main()`.

## Build & ops gotchas (learned the hard way)

These are real failure modes baked into the tooling — preserve the guards, don't "simplify" them
away:

- **Stale-anvil port squat.** A previous run's shared anvil can squat `:8545`, so the next run
  silently forks the *wrong* chain and produces false-empty results. Pre-flight: kill stray anvil,
  then verify the fork's chain-id and a known contract's codesize before hunting.
- **viaIR retry.** Some targets fail to compile with a "Stack too deep" error; the build path
  (`runtime/exec.py`, `index/slither_export.py`) retries with `--via-ir`. Keep that fallback.
- **Env poisoning.** Stage subprocesses can leak env mutations across runs; env is snapshotted and
  restored. Don't mutate `os.environ` globally in a stage — scope it and restore.
- **Resume must not wipe.** `RunContext` resume reuses prior checkpoints; a round-start that wipes
  state will destroy an in-progress run. Test resume after touching the sequencer.
- **Transient 5xx.** LLM/API calls wrap an attempt-loop with backoff for 429/529. Keep retries on
  new network call sites.
- **Foundry monorepos** need the right `FOUNDRY_PROFILE`; **Hardhat targets** need an `npm install`
  before indexing. `index/build.py` routes by repo type — extend it there, not ad hoc.
- **Archive RPC required.** Fork PoCs and fuzz campaigns need an archive node at the pinned block; a
  full (non-archive) node will fail on historical state.

## Methodology: the adversary model

Findings are classified by **how they can actually be triggered** (`TriggerClass` in `models.py`):

- `attacker_reachable` — an unprivileged attacker can trigger it directly (the only class that is
  usually payable on its own).
- `external_condition` — needs an external precondition the attacker can't force (e.g. a price move,
  a dependency going stale).
- `privileged_role` — requires a trusted/admin role; usually out of scope unless the model is
  malicious-admin.
- `latent` — real defect but not currently reachable.

Discipline that keeps false-positive rate low (mirror it in hunter/critic prompts):

- **Prove impact, then rate severity.** A PoC must reproduce the impact on a fork before a finding
  is reported; the critic independently re-runs and tries to refute it.
- **Model real parameters and the frontend**, not just the contract. Real deployment config
  (LLTV, caps, oracle age, UI-enforced minimums) frequently downgrades a "critical" to Low/QA.
- **Classify honestly.** If a PoC only works by pranking a privileged account or mocking
  attacker-uncontrolled input, it is *not* `attacker_reachable` — label it, don't inflate it.
- **Read the protocol's own docs** before calling documented behavior a bug — by-design abuse
  protections and known-issue disclosures are not findings.

## Conventions

- Python 3.11+, `ruff` (line length 110). Keep module docstrings (most files have one).
- Data flows through Pydantic models — add/extend contracts in `models.py`, never pass raw dicts
  between stages.
- Knowledge (invariants, incident catalog) is data in `skills/` and `tools/*_catalog.py`, not code —
  extend the YAML/catalog, not hardcoded logic.
- Commit identity: use a GitHub `noreply` email so personal addresses stay out of history.
