"""Build a scoped, output-obligated ``claude -p`` invocation for an ``AgentSpec``.

This is where the three restriction layers are wired for the subscription backend:

  * **tool-permission config** — ``--disallowed-tools`` removes Edit/Task/web from
    the model's context entirely; ``--permission-mode bypassPermissions`` lets the
    permitted ops run without a headless permission prompt (the guard hook below is
    the real allow/deny authority — a hook ``permissionDecision:"allow"`` is not
    reliably honored under ``-p``, but a hook DENY is, even under bypass).
  * **hooks** — ``--settings.hooks`` points PreToolUse at ``chainreaper hook-guard``
    (denies off-scratch Write, non-``chainreaper`` Bash, Edit/Task/web) and Stop at
    ``chainreaper hook-stop`` (passed explicitly so they fire under ``-p``; we never
    use ``--bare``/``--safe-mode`` which would skip them).
  * **prompt** — the composed system prompt plus a concrete OUTPUT MECHANICS block
    (this session's scratch dir + the exact save-script command lines).

Pure construction: returns an ``Invocation`` (argv + env + settings) the backend
runs. No subprocess here, so it unit-tests without a live ``claude``.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path

from .spec import AgentSpec

# Removed from the model's context entirely (the guard hook is the hard backstop).
# Recon is read-only, so Edit is removed too; the Hunter needs Edit to iterate on
# its PoC (the guard gates Write/Edit to the sandbox workspace), so it keeps Edit.
DISALLOWED_TOOLS = ["Edit", "NotebookEdit", "Task", "WebFetch", "WebSearch"]
HUNT_DISALLOWED_TOOLS = ["NotebookEdit", "Task", "WebFetch", "WebSearch"]
# A *research* agent (Tier-4 P2/P6) keeps WebFetch/WebSearch — that is the whole point.
# Edit/Task/Notebook stay removed; it is read-only over the code (Write is scratch-gated
# by the guard, for the emit JSON only).
RESEARCH_DISALLOWED_TOOLS = ["Edit", "NotebookEdit", "Task"]


def _disallowed_for(mode: str) -> list[str]:
    if mode == "hunt":
        return list(HUNT_DISALLOWED_TOOLS)
    if mode == "research":
        return list(RESEARCH_DISALLOWED_TOOLS)
    return list(DISALLOWED_TOOLS)


# Secrets the agent process must NOT inherit — it never needs them (S0/S1 do the
# keyed fetches; by hunt time <CHAIN>_RPC_URL is the keyless local anvil / free node),
# and inheriting them risks a leak into logs (e.g. an `env` dump). Keystore-loaded
# keys + any conventional secret-bearing var are stripped from the agent env.
_SECRET_EXACT = {"ETHERSCAN_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY",
                 "ALCHEMY_API_KEY", "INFURA_API_KEY", "MNEMONIC", "PRIVATE_KEY",
                 "DEPLOYER_PRIVATE_KEY"}
_SECRET_SUFFIX = ("_API_KEY", "_SECRET", "_TOKEN", "_PRIVATE_KEY", "_PASSWORD",
                  "_MNEMONIC", "_APIKEY")


def _is_secret_key(name: str) -> bool:
    up = name.upper()
    if up in _SECRET_EXACT:
        return True
    # keep RPC endpoints (needed for forking; keyless by hunt time) even if a value
    # embeds a path token — they are matched by name, and RPC keys don't end in a
    # secret suffix.
    return any(up.endswith(sfx) for sfx in _SECRET_SUFFIX)


def _strip_secrets(env: dict) -> dict:
    """Drop secret-bearing env vars from a copy so the agent subprocess can't read or
    leak them (defense-in-depth alongside removing `env`/`printenv` from the guard)."""
    return {k: v for k, v in env.items() if not _is_secret_key(k)}


@dataclass
class Invocation:
    argv: list[str]
    env: dict[str, str]
    settings: dict
    scratch_dir: str
    session_id: str


def output_mechanics(spec: AgentSpec, scratch_dir: str) -> str:
    """The concrete 'how to save your output' block appended to the user message."""
    lines = [
        "## OUTPUT MECHANICS — how to save (REQUIRED, enforced)",
        f"Your scratch directory is: {scratch_dir}",
        "You persist output ONLY by writing JSON to a file under that scratch dir "
        "with the Write tool, then running the matching save-script (it validates "
        "against the schema and writes the database). You cannot write anywhere "
        "else, and you cannot finish until every required script below has succeeded.",
        "",
    ]
    for e in spec.emitters:
        fname = f"{scratch_dir}/{e.command}.json"
        schema = json.dumps(e.schema.model_json_schema(), separators=(",", ":"))
        shape = (f"a JSON ARRAY of ≥{e.min_calls} objects" if e.multiple
                 else "ONE JSON object")
        lines.append(
            f"- `{e.command}` — write {shape} to {fname}, then run:\n"
            f"    chainreaper {e.command} --in {fname}\n"
            f"  Each object MUST use the EXACT field names in this JSON Schema "
            f"(`{e.schema.__name__}`), resolving any $ref against $defs:\n  {schema}"
        )
    lines.append(
        "\nUse the EXACT schema field names above — do not invent fields. If a "
        "save-script prints a VALIDATION ERROR, read it, fix the JSON, and run it "
        "again. Query the index with `chainreaper code-index <kind> '<json>'`."
    )
    return "\n".join(lines)


def build_invocation(
    spec: AgentSpec,
    *,
    claude_bin: str,
    chainreaper_bin: str,
    model: str,
    index_db: str,
    artifact_db: str,
    run_id: str,
    session_id: str,
    scratch_dir: str,
    max_stop_blocks: int = 3,
    base_env: dict | None = None,
) -> Invocation:
    # The PreToolUse guard hook is the authoritative allow/deny decider. We run in
    # bypassPermissions so the *permitted* ops never stall on a headless permission
    # prompt; the guard's DENY is still honored under bypass (verified) and is what
    # enforces scope — off-scratch Write, non-`chainreaper` Bash, Edit/Task/web are
    # all refused. (A PreToolUse `permissionDecision:"allow"` is NOT reliably honored
    # in headless `-p`, so we do not depend on it.)
    settings = {
        "hooks": {
            "PreToolUse": [
                {"matcher": "*",
                 "hooks": [{"type": "command", "command": f"{chainreaper_bin} hook-guard"}]}
            ],
            "Stop": [
                {"hooks": [{"type": "command", "command": f"{chainreaper_bin} hook-stop"}]}
            ],
        },
    }

    user = spec.user_message + "\n\n" + output_mechanics(spec, scratch_dir)

    argv = [
        claude_bin, "-p", user,
        "--model", model,
        # stream-json (requires --verbose under -p) so the backend can log each
        # tool call / text event live instead of only after the session ends.
        "--output-format", "stream-json", "--verbose",
        "--permission-mode", "bypassPermissions",
        "--append-system-prompt", spec.system_prompt,
        "--disallowed-tools", *_disallowed_for(spec.mode),
        "--settings", json.dumps(settings),
    ]

    env = _strip_secrets(dict(base_env if base_env is not None else os.environ))
    # ensure `chainreaper` + `python` (and thus the save-scripts/hooks) resolve
    env["PATH"] = str(Path(sys.executable).resolve().parent) + os.pathsep + env.get("PATH", "")
    # DB paths MUST be absolute: the agent's cwd is the in-scope repo, so a relative
    # path would resolve under the repo (wrong db / "unable to open database file").
    env.update({
        "CHAINREAPER_INDEX_DB": str(Path(index_db).resolve()),
        "CHAINREAPER_ARTIFACT_DB": str(Path(artifact_db).resolve()),
        "CHAINREAPER_RUN_ID": run_id,
        "CHAINREAPER_AGENT": spec.name,
        "CHAINREAPER_SESSION": session_id,
        "CHAINREAPER_REQUIRED": spec.required_spec(),
        "CHAINREAPER_ALLOWED_BASH": ",".join(spec.allowed_bash()),
        "CHAINREAPER_SCRATCH": scratch_dir,
        "CHAINREAPER_MAX_STOP_BLOCKS": str(max_stop_blocks),
        # Hunt-mode scope: the guard relaxes Bash to this sandbox toolchain (+ a
        # benign-utility set) and gates Write/Edit to the scratch (= the sandbox
        # workspace). Empty/"recon" → strict read-only recon scope.
        "CHAINREAPER_MODE": spec.mode,
        "CHAINREAPER_ALLOWED_TOOLS": ",".join(spec.bash_tools),
    })

    return Invocation(argv=argv, env=env, settings=settings,
                      scratch_dir=scratch_dir, session_id=session_id)
