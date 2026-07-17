# Chainreaper — Implementation Notes (Addendum to IMPLEMENTATION-SPEC.md)

> Scope: the **build contracts** a fresh session needs to implement **Milestone 1 (spine) + S1 (Index)** without guessing. The spec (`IMPLEMENTATION-SPEC.md`) is the design; this file pins the concrete decisions the spec leaves open for that first vertical slice. Anything not needed until S2+ is flagged but not fully specified here.
>
> Status: v1 · 2026-06-19 · covers gaps identified in the spec review (deps/bootstrap, host-vs-Docker, SQLite schema + `code_index` API, tool→model mapping, model IDs/Backend).

---

## 0. What to build first (the slice)

```
Minimal spine (slim M1) ──► S1 Index ──► (later) S2 Recon ──► S4 Hunt
```

1. **Spine:** `models.py` (Discovery + Index contracts only, + enums + coercion), a tiny `orchestrator/sequencer.py` (stage list, JSON checkpoint, `--resume`/`--stop-after`), `backends/base.py` (protocol stub — not called in S1), `cli.py` (`scan`/`resume`/`doctor`). Stub S0: hand-build the GMX `Target` from a local path.
2. **S1 Index:** `index/store.py` (SQLite, schema below) + `index/slither_export.py` (runs under slither's interpreter) + `index/build.py` (S1 driver) + the `code_index.query` API.

**Exit criterion (matches spec M2 partial):** `chainreaper scan --target gmx-source/gmx-synthetics --stop-after s1` produces a populated SQLite index, and `code_index.query("entrypoints", {})` returns the multichain router externals.

---

## 1. Environment & dependency bootstrap

The environment has **no Python deps preinstalled** (verified: system Python 3.12 has no `pydantic`/`tree_sitter`/`click`/`yaml`). Bootstrap with a venv:

```bash
cd /workspaces/Blockchain-Testing
python3 -m venv .venv
source .venv/bin/activate
pip install -e .            # core: pydantic, pyyaml, typer
# S2+ later:  pip install -e '.[agents]'
# optional:   pip install -e '.[index]'   # tree-sitter enrichment
```

**Relationship to the analysis toolchain (important):** Chainreaper's venv holds *orchestration* deps only. The analysis tools (Slither, Foundry, …) stay where `tools_poc` put them — **pipx venvs on PATH** (`/usr/local/py-utils/bin`, etc.; see `tools_poc/README.md §2`). Chainreaper **shells out** to them (spec §8: "wrappers that shell into the sandbox"). Do **not** `pip install slither-analyzer` into chainreaper's venv — its pinned web3/crytic deps will fight pydantic v2. The one exception is the structural export script (§5), which is run *with slither's own interpreter*, not chainreaper's.

`chainreaper doctor` should verify PATH has: `slither`, `forge`, `python3` (≥3.11), and that `tools_poc/setup` ran. Per-project build gotchas (Node 22 + `--legacy-peer-deps --ignore-scripts` + viaIR for V2; Node 16 + `env.json` for V1) are in `tools_poc/README.md` — Index must compile the target the same way before invoking Slither.

---

## 2. Host vs Docker — decision for S1/S2

**Run S1 and S2 on the host; defer Docker to S4 (Hunt).** Rationale: S1/S2 only *read* code and run static analyzers (Slither/Surya/Aderyn) — no untrusted code executes, so the per-task Docker isolation in spec §10 buys little, and the host toolchain is already validated by `tools_poc`. Docker-per-task matters once hunters **run exploit PoCs and fork nodes** (S4), where it should be introduced.

Keep the seam cheap to add later: put all tool invocation behind one thin function so S4 can swap the backend without touching S1/S2.

```python
# chainreaper/runtime/exec.py
import subprocess
def run_tool(cmd: list[str], *, cwd=None, timeout=1800, backend="host") -> subprocess.CompletedProcess:
    if backend == "host":
        return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    raise NotImplementedError("docker backend lands in S4")  # spec §10
```

This satisfies spec §10's "backends pluggable (docker default; local for dev)" without building the image now.

---

## 3. S1 — SQLite index schema

`index/store.py` owns this. One DB per run at `runs/{run_id}/index/index.db`. The schema backs both the `IndexedRepo` model (§5) and every `code_index.query` kind (§4). DDL:

```sql
CREATE TABLE repos (
  repo_id    INTEGER PRIMARY KEY,
  repo_ref   TEXT NOT NULL,          -- e.g. "gmx-synthetics"
  language   TEXT NOT NULL,          -- "solidity"
  root_path  TEXT NOT NULL,
  commit_sha TEXT,
  indexed_at TEXT
);
CREATE TABLE files (
  file_id  INTEGER PRIMARY KEY,
  repo_id  INTEGER NOT NULL REFERENCES repos(repo_id),
  path     TEXT NOT NULL,            -- repo-relative
  language TEXT, loc INTEGER, sha256 TEXT
);
CREATE TABLE contracts (
  contract_id INTEGER PRIMARY KEY,
  repo_id     INTEGER NOT NULL REFERENCES repos(repo_id),
  file_id     INTEGER NOT NULL REFERENCES files(file_id),
  name        TEXT NOT NULL,
  kind        TEXT NOT NULL,         -- contract|interface|library|abstract
  line        INTEGER
);
CREATE TABLE inheritance (             -- one row per base
  contract_id      INTEGER NOT NULL REFERENCES contracts(contract_id),
  base_name        TEXT NOT NULL,
  base_contract_id INTEGER REFERENCES contracts(contract_id)  -- null if external
);
CREATE TABLE functions (
  func_id      INTEGER PRIMARY KEY,
  contract_id  INTEGER NOT NULL REFERENCES contracts(contract_id),
  file_id      INTEGER NOT NULL REFERENCES files(file_id),
  name         TEXT NOT NULL,
  signature    TEXT NOT NULL,        -- solidity_signature, e.g. "createWithdrawal(...)"
  visibility   TEXT,                 -- external|public|internal|private
  mutability   TEXT,                 -- payable|nonpayable|view|pure
  is_constructor INTEGER DEFAULT 0,
  is_entrypoint  INTEGER DEFAULT 0,  -- visibility in (public,external) AND not constructor
  modifiers    TEXT,                 -- JSON array of modifier names
  line_start   INTEGER, line_end INTEGER
);
CREATE TABLE state_vars (
  var_id      INTEGER PRIMARY KEY,
  contract_id INTEGER NOT NULL REFERENCES contracts(contract_id),
  name        TEXT NOT NULL,
  type        TEXT,
  visibility  TEXT,
  is_constant INTEGER DEFAULT 0,
  is_immutable INTEGER DEFAULT 0,
  slot        INTEGER,               -- nullable for S1 (needs slither-read-storage)
  line        INTEGER
);
CREATE TABLE var_access (              -- powers writers/readers queries
  func_id INTEGER NOT NULL REFERENCES functions(func_id),
  var_id  INTEGER NOT NULL REFERENCES state_vars(var_id),
  access  TEXT NOT NULL               -- read|write
);
CREATE TABLE call_edges (
  edge_id       INTEGER PRIMARY KEY,
  caller_func_id INTEGER NOT NULL REFERENCES functions(func_id),
  callee_func_id INTEGER REFERENCES functions(func_id),  -- null if target external/unknown
  callee_sig    TEXT NOT NULL,        -- always present
  call_type     TEXT NOT NULL,        -- internal|external|low_level|delegatecall|library|event|solidity
  line          INTEGER
);
CREATE TABLE sinks (
  sink_id INTEGER PRIMARY KEY,
  func_id INTEGER NOT NULL REFERENCES functions(func_id),
  kind    TEXT NOT NULL,              -- low_level_call|delegatecall|transfer|send|ecrecover|selfdestruct|external_call|unchecked_math|oracle_read
  detail  TEXT, line INTEGER
);
CREATE TABLE proxy_info (             -- optional / nullable in S1
  contract_id INTEGER REFERENCES contracts(contract_id),
  pattern TEXT, impl_slot TEXT, init_guard INTEGER
);
CREATE TABLE sast_findings (          -- raw evidence, NOT findings (spec S1)
  id INTEGER PRIMARY KEY, repo_id INTEGER REFERENCES repos(repo_id),
  tool TEXT, check_id TEXT, impact TEXT, confidence TEXT,
  file TEXT, line INTEGER, description TEXT, raw TEXT  -- raw = JSON blob
);

CREATE INDEX ix_func_contract ON functions(contract_id);
CREATE INDEX ix_func_sig      ON functions(signature);
CREATE INDEX ix_func_entry    ON functions(is_entrypoint);
CREATE INDEX ix_edge_caller   ON call_edges(caller_func_id);
CREATE INDEX ix_edge_callee   ON call_edges(callee_func_id);
CREATE INDEX ix_edge_calleesig ON call_edges(callee_sig);
CREATE INDEX ix_va_var        ON var_access(var_id);
CREATE INDEX ix_va_func       ON var_access(func_id);
CREATE INDEX ix_sink_func     ON sinks(func_id);
CREATE INDEX ix_contract_name ON contracts(name);
```

---

## 4. S1 — `code_index.query(kind, args)` API

Spec §8 lists the query *intents*; here are the concrete `kind`s, args, and return shapes. Implement in `tools/code_index.py` as SQL over §3. Every return is a list of JSON-serializable dicts (the agent tool wraps them; for S1, unit-test them directly). A function is addressed by `{contract?, name}` or `{signature}`.

| `kind` | `args` | returns (list of) |
|---|---|---|
| `contract` | `{name}` | `{contract_id, name, kind, file, line}` |
| `function` | `{signature}` or `{contract,name}` | `{func_id, contract, name, signature, visibility, mutability, file, line_start, line_end}` |
| `entrypoints` | `{contract?}` | functions with `is_entrypoint=1` (filter by contract if given) |
| `callers` | `{signature}` or `{contract,name}` | functions whose `call_edges.callee_func_id` = target |
| `callees` | `{signature}` or `{contract,name}` | callee functions (resolve `callee_func_id`; include unresolved `callee_sig` with `external:true`) |
| `writers` | `{contract,var}` | functions with `var_access.access='write'` on that var |
| `readers` | `{contract,var}` | functions with `var_access.access='read'` |
| `external_calls_in` | `{signature}` or `{contract,name}` | `sinks` rows where `kind` ∈ external/low_level/delegatecall for that func |
| `sinks` | `{contract?, kind?}` | `sinks` rows, optionally filtered |
| `inheritance` | `{contract}` | base chain `[{base_name, base_contract_id}]` |
| `storage_layout` | `{contract}` | `state_vars` rows (slot may be null in S1) |
| `proxy_info` | `{contract?}` | `proxy_info` rows |
| `path` | `{from_signature, to_signature, max_depth?}` | **S10 (Trace)** — BFS over `call_edges`; S1 only needs to *store* the edges. Stub returning `[]` is fine for the slice. |

Self-test on GMX V2: `entrypoints {contract:"MultichainGmRouter"}` → `createDeposit/createWithdrawal/createShift`; `callers {contract:"WithdrawalHandler", name:"createWithdrawal"}` → the routers; `writers {contract:"DataStore", var:"uintValues"}` (sanity that var_access populated).

---

## 5. S1 — tool output → `IndexedRepo` mapping

**Primary source = Slither** (covers every IndexedRepo field for Solidity). Tree-sitter is *optional enrichment* (precise token spans + non-Solidity later) — skip it for the first increment.

### Getting Slither's structural model out

Don't parse `--print` dot/text. Run a small export script **with Slither's own interpreter** (so `import slither` works without touching chainreaper's venv):

```bash
# discover slither's interpreter from the CLI shebang (pipx venv)
SLITHER_PY="$(sed -n '1s/^#!//p' "$(command -v slither)")"
"$SLITHER_PY" chainreaper/index/slither_export.py <target_dir> <out.json>
```

`slither_export.py` imports `from slither import Slither`, builds `Slither(target_dir)` (after the project is compiled per `tools_poc` gotchas), and dumps JSON. Chainreaper (its own venv) reads `out.json` and loads it into the §3 tables. Field map (Slither python API → schema):

| Slither object → attribute | → table.column |
|---|---|
| `contract.name`; `contract.contract_kind` / `is_interface` / `is_library` | `contracts.name`, `contracts.kind` |
| `contract.source_mapping` (file, lines) | `contracts.file_id`, `contracts.line` |
| `contract.inheritance` (list of `Contract`) | `inheritance.base_name` (+ resolve `base_contract_id`) |
| `function.solidity_signature` / `function.full_name` | `functions.signature` |
| `function.visibility` | `functions.visibility`; `is_entrypoint = visibility in {public,external} and not function.is_constructor` |
| `function.view` / `pure` / `payable` | `functions.mutability` |
| `function.is_constructor` | `functions.is_constructor` |
| `[m.name for m in function.modifiers]` | `functions.modifiers` (JSON) |
| `function.source_mapping` | `functions.line_start/line_end`, `functions.file_id` |
| `function.state_variables_written` / `_read` | `var_access` rows (access=write/read) |
| `function.internal_calls` | `call_edges` (call_type=internal, resolve callee_func_id) |
| `function.high_level_calls` (external) | `call_edges` (external) + `sinks` (external_call) |
| `function.low_level_calls` | `call_edges` (low_level) + `sinks` (low_level_call / delegatecall) |
| `function.solidity_calls` | `sinks` (ecrecover/selfdestruct/…) by name |
| `contract.state_variables` (name, type, visibility, is_constant, is_immutable) | `state_vars.*` (`slot` left null in S1) |
| Slither detector JSON (`slither --json -`) | `sast_findings.*` (one row per result; `raw` = the result object) |

`proxy_info` is best-effort in S1 (delegatecall-in-fallback heuristic, or run `slither-check-upgradeability` later) — nullable is acceptable.

**Tree-sitter (deferred):** if/when added, grammar is `tree-sitter-solidity` (PyPI, in the `[index]` extra); modern binding is `Language(tree_sitter_solidity.language())` on `tree-sitter>=0.22`. Use it for exact source spans and for Vyper/Rust/Move parsing in later targets — not needed while the target is Solidity and Slither compiles it.

---

## 6. LLM backend & model IDs (S2+, pinned now)

S1 does **not** call the model. This section is for S2+ but is pinned here so the next session is turnkey. **Grounded against the `claude-api` skill (authoritative) — not memory.**

### Model IDs (use these exact alias strings; never append date suffixes)

| Role (spec §12 `models.*`) | Model | ID |
|---|---|---|
| `hunt`, `critic`, `trace` | Claude Opus 4.8 | `claude-opus-4-8` |
| `recon`, `dedupe` | Claude Sonnet 4.6 | `claude-sonnet-4-6` |
| `coerce` | Claude Haiku 4.5 | `claude-haiku-4-5` |

Correction to the spec review: the spec's `claude-haiku-4-5` is **correct** (it's the preferred alias; the dated form `claude-haiku-4-5-20251001` also exists but aliases are preferred). The only addition: **Claude Fable 5 (`claude-fable-5`)** now exists — Anthropic's most capable model, 1M context, $10/$50 per MTok (above Opus tier). Optionally route `hunt`/`trace` to it for the hardest reasoning when budget allows; otherwise keep Opus 4.8 (it's the default and far cheaper at $5/$25).

### Backend — bind to the `anthropic` SDK (documented), not `claude-agent-sdk`

The spec names "claude-agent-sdk as primary," but the `anthropic` SDK already covers both Backend surfaces with documented APIs, and is what the `claude-api` skill authoritatively documents. Use it; revisit `claude-agent-sdk` only if you specifically want its higher-level agent runtime (then ground it against its repo in the skill's `live-sources.md`).

- **`Backend.prompt(...)` → `client.messages.parse(...)`** for structured stages (Recon profile, Dedupe, coercion, and the `create_finding`/`emit_verdict` emitters). This is the key fit: `output_format=<PydanticModel>` returns `response.parsed_output` as a *validated instance of our §5 contracts* — no hand-parsing, validation at the SDK layer. Plain text → `client.messages.create(...)`.
- **`Backend.agentic(...)` → `client.beta.messages.tool_runner(...)`** with `@beta_tool`-decorated functions (the hunter's sandbox tools), or a manual loop (`while stop_reason != "end_turn"`) when you need approval gates / custom logging.

Request conventions (all grounded):
- Default `thinking={"type": "adaptive"}` + `output_config={"effort": "high"}` (effort: `low|medium|high|xhigh|max`; `xhigh` for the hardest hunt/trace). Do **not** send `temperature`/`top_p`/`budget_tokens` — they 400 on Opus 4.8.
- **Stream when `max_tokens` is large** (>~16K): use `client.messages.stream(...)` + `.get_final_message()`; for Opus streaming default `max_tokens≈64000`.
- **Prompt-cache the shared Recon profile + system prompt** across the many hunter calls (spec §11): `cache_control={"type":"ephemeral"}` on the last stable system block; min cacheable prefix is **4096 tokens on Opus** (2048 on Sonnet). Keep the per-hunter task text *after* the cached prefix.
- Per-role model + effort live in `config/defaults.yaml` `models.*` (spec §12) — already structured for this.

### Structured-emitter pattern (the heart of S2+)

```python
# pseudocode — the create_finding emitter
from chainreaper.models import Finding
resp = client.messages.parse(
    model=cfg.models.hunt, max_tokens=8000,
    thinking={"type": "adaptive"}, output_config={"effort": "high"},
    system=[{"type": "text", "text": recon_profile_md, "cache_control": {"type": "ephemeral"}}],
    messages=[{"role": "user", "content": hunter_task_prompt}],
    output_format=Finding,           # ← validated against §5 contract
)
finding: Finding = resp.parsed_output   # already coerced/validated
```

This is why `models.py` (the §5 contracts) is the foundation: the same Pydantic classes that define stage hand-offs are the LLM output schemas. Build them first.
