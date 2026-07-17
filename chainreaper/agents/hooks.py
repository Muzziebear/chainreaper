"""Claude Code hook decision logic (spec §7 scope guardrail; §8 finish_task).

Two hooks enforce, at the harness level, what the prompt only *asks* for — the
third restriction layer on top of the prompt and the tool-permission config:

* ``decide_guard`` — **PreToolUse**. Hard-denies anything off the agent's list:
  Edit/Task/web tools outright, ``Write`` unless it targets the session scratch
  dir, and ``Bash`` unless it is a single allowed ``chainreaper`` helper command.
  Defense-in-depth over ``--allowed-tools`` / ``--disallowed-tools``.

* ``decide_stop`` — **Stop**. Counts the ``agent_actions`` the save-scripts logged
  for this session against ``CHAINREAPER_REQUIRED`` (``cmd:min,...``). While a
  requirement is unmet it returns ``{"decision":"block"}`` so the agent cannot
  finish without producing its output. A ``max_stop_blocks`` cap converts a stuck
  agent into a clean stage failure instead of an infinite loop.

Functions are pure ``(input) -> (exit_code, stdout_json)`` so they unit-test
without a live ``claude`` session; the ``chainreaper hook-*`` CLI wrappers do the
stdin/stdout/exit plumbing.
"""

from __future__ import annotations

import json
import os
import shlex
from pathlib import Path
from typing import Mapping

from ..recon.store import ReconStore

# Tools a read-only recon agent may never use (removed from context too, but the
# guard is the hard backstop).
DENY_TOOLS = {"Edit", "MultiEdit", "NotebookEdit", "Task", "WebFetch", "WebSearch"}
# A Hunter writes + iterates a PoC in its sandbox workspace, so Edit/MultiEdit are
# permitted (gated to the workspace below); network/Task are still denied.
HUNT_DENY_TOOLS = {"NotebookEdit", "Task", "WebFetch", "WebSearch"}
# A *research* agent (Tier-4 P2 spec-research / P6 threat-research) is the ONLY mode
# the guard lets reach the web — WebFetch/WebSearch are NOT denied here (they are for
# recon/hunt/critic). It still cannot Edit/Task, and Write is scratch-gated below.
RESEARCH_DENY_TOOLS = {"Edit", "MultiEdit", "NotebookEdit", "Task"}

# Operators that would let a Bash call chain/redirect/substitute another command —
# any of these → deny. (Braces/parens/quotes are allowed: code-index JSON args and
# function signatures legitimately contain `{}`, `()`, `"`, `:`.)
_DANGEROUS = (";", "|", "&", "<", ">", "\n", "`", "$(")

# Hunt-mode Bash policy. The sandbox toolchain (forge/cast/anvil/medusa/…) comes
# from CHAINREAPER_ALLOWED_TOOLS; on top of that a Hunter may use these benign
# shell utilities to drive a PoC, and may NEVER use these destructive/egress ones.
_HUNT_BENIGN = frozenset({
    "cat", "ls", "head", "tail", "echo", "printf", "mkdir", "cp", "mv", "cd",
    "pwd", "test", "true", "false", "jq", "sed", "awk", "grep", "find", "wc",
    "sort", "uniq", "cut", "tr", "tee", "touch", "diff", "basename", "dirname",
    "which", "date", "xxd",
    # NOTE: `env`/`printenv` are deliberately NOT here — a hunter dumping the process
    # environment would leak inherited secrets into the logs (the agent env is also
    # secret-stripped in session.py as defense-in-depth).
})
_HUNT_HARD_DENY = frozenset({
    "rm", "rmdir", "sudo", "su", "curl", "wget", "ssh", "scp", "sftp", "nc",
    "ncat", "telnet", "dd", "mkfs", "shutdown", "reboot", "kill", "killall",
    "pkill", "chmod", "chown", "mount", "umount", "git", "pip", "pip3", "npm",
    "yarn", "pnpm", "cargo", "apt", "apt-get", "brew", "docker", "python",
    "python3", "bash", "sh", "zsh", "eval", "exec", "node", "npx",
})
# Shell tokens that separate one command from the next (each starts a new command
# head that must be independently allowed). Redirections (>, >>, 2>&1, …) are NOT
# separators — their operand is a filename, not a command.
_SEPARATORS = frozenset({";", "&&", "||", "|", "&"})

Decision = tuple[int, str]  # (exit_code, stdout)


# --------------------------------------------------------------------------- #
# helpers                                                                      #
# --------------------------------------------------------------------------- #
def _deny(reason: str) -> Decision:
    return 0, json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    })


def _allow_tool(reason: str = "permitted") -> Decision:
    # Explicit allow — bypasses the permission prompt. Required in headless `-p`:
    # "no decision" would fall through to a prompt that can't be answered (hang).
    return 0, json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
            "permissionDecisionReason": reason,
        }
    })


def _proceed() -> Decision:
    # exit 0, no JSON → "no decision" (Stop hook: let the agent stop normally).
    return 0, ""


def _within(path: str, root: str) -> bool:
    if not path or not root:
        return False
    try:
        p = Path(path).resolve()
        r = Path(root).resolve()
        return p == r or r in p.parents
    except OSError:
        return False


def chainreaper_subcommand(cmd: str) -> str | None:
    """Return the ``chainreaper`` subcommand a Bash command runs, or None if the
    command is not a single clean ``chainreaper …`` invocation (no chaining,
    redirection, or command substitution)."""
    if not cmd or any(tok in cmd for tok in _DANGEROUS):
        return None
    try:
        toks = shlex.split(cmd)
    except ValueError:
        return None
    if not toks:
        return None
    if toks[0].rsplit("/", 1)[-1] != "chainreaper":
        return None
    return toks[1] if len(toks) > 1 else None


def _basename(tok: str) -> str:
    return tok.rsplit("/", 1)[-1]


def command_segments(cmd: str) -> list[list[str]] | None:
    """Split a Bash command into per-command token lists (one per ``;``/``&&``/
    ``||``/``|``/``&`` separator), or None if it can't be parsed safely.

    Command substitution (`` ` `` / ``$(``) is rejected outright (arbitrary
    execution / egress). Redirections are left as ordinary tokens within a segment
    (their operand is a filename, not a command). Used by the hunt-mode guard to
    require every command *head* to be independently allow-listed."""
    if not cmd or "`" in cmd or "$(" in cmd or "\n" in cmd:
        return None
    try:
        toks = shlex.split(cmd)
    except ValueError:
        return None
    segments: list[list[str]] = []
    cur: list[str] = []
    for t in toks:
        if t in _SEPARATORS:
            segments.append(cur)
            cur = []
        else:
            cur.append(t)
    segments.append(cur)
    return [s for s in segments if s]


def _segment_head(tokens: list[str]) -> str | None:
    """The command head of a segment: the first token that is neither a leading
    ``VAR=value`` env assignment nor a redirection operand."""
    skip_next = False
    for t in tokens:
        if skip_next:
            skip_next = False
            continue
        if t in (">", ">>", "<", "2>", "&>", "2>&1", "1>", "1>&2"):
            skip_next = t not in ("2>&1", "1>&2")  # those are self-contained
            continue
        if "=" in t and t.split("=", 1)[0].isidentifier() and not t.startswith("/"):
            continue  # leading env assignment (FOO=bar cmd …)
        return t
    return None


def _parse_required(spec: str) -> list[tuple[str, int]]:
    out: list[tuple[str, int]] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        cmd, _, n = part.partition(":")
        try:
            out.append((cmd.strip(), int(n)))
        except ValueError:
            out.append((cmd.strip(), 1))
    return out


# --------------------------------------------------------------------------- #
# PreToolUse                                                                   #
# --------------------------------------------------------------------------- #
def decide_guard(data: Mapping, env: Mapping = os.environ) -> Decision:
    tool = data.get("tool_name", "")
    tool_input = data.get("tool_input") or {}
    mode = env.get("CHAINREAPER_MODE", "recon")
    hunt = mode == "hunt"
    research = mode == "research"

    deny_tools = (HUNT_DENY_TOOLS if hunt
                  else RESEARCH_DENY_TOOLS if research
                  else DENY_TOOLS)
    if tool in deny_tools:
        return _deny(f"{tool} is not permitted for this agent.")

    if tool in ("Write", "Edit", "MultiEdit"):
        # Writes/edits are gated to the agent's scratch dir — for the Hunter that
        # IS its sandbox workspace (where the PoC + emit JSON live).
        path = tool_input.get("file_path", "")
        scratch = env.get("CHAINREAPER_SCRATCH", "")
        if _within(path, scratch):
            return _allow_tool(f"{tool} to scratch dir")
        return _deny(
            f"{tool} is restricted to the scratch dir ({scratch or 'unset'}); "
            f"refused {tool} to {path or '?'}. Write your PoC + emit JSON under "
            "the scratch dir, then call the chainreaper save-script."
        )

    if tool == "Bash":
        cmd = tool_input.get("command", "")
        if hunt:
            return _guard_hunt_bash(cmd, env)
        allowed = {s.strip() for s in env.get("CHAINREAPER_ALLOWED_BASH", "").split(",") if s.strip()}
        sub = chainreaper_subcommand(cmd)
        if sub is None:
            return _deny(
                "Bash is restricted to a single `chainreaper <subcommand>` helper "
                f"(no pipes/redirects/chaining); refused: {cmd[:160]!r}"
            )
        if sub not in allowed:
            return _deny(
                f"`chainreaper {sub}` is not allowed for this agent. "
                f"Allowed: {sorted(allowed)}."
            )
        return _allow_tool(f"chainreaper {sub}")

    # Read / Grep / Glob and other read/utility tools: explicitly allow so the
    # headless session never stalls on a permission prompt. (Denied tools are
    # already refused above and removed from context via --disallowed-tools.)
    return _allow_tool(f"{tool} (read/utility)")


def _guard_hunt_bash(cmd: str, env: Mapping) -> Decision:
    """Hunt-mode Bash policy: the sandbox toolchain + chainreaper save-scripts + a
    benign-utility set, with destructive/egress binaries hard-denied. Every command
    head in the (possibly chained) line must be independently allowed."""
    allowed_bash = {s.strip() for s in env.get("CHAINREAPER_ALLOWED_BASH", "").split(",") if s.strip()}
    allowed_tools = {s.strip() for s in env.get("CHAINREAPER_ALLOWED_TOOLS", "").split(",") if s.strip()}
    segments = command_segments(cmd)
    if segments is None:
        return _deny(
            "Bash command could not be parsed safely (command substitution / "
            f"backticks are not allowed): {cmd[:160]!r}"
        )
    for tokens in segments:
        head = _segment_head(tokens)
        if head is None:
            return _deny(f"empty/redirect-only command segment in: {cmd[:160]!r}")
        base = _basename(head)
        if base in _HUNT_HARD_DENY:
            return _deny(f"`{base}` is not permitted in the hunt sandbox (destructive/egress).")
        if base == "chainreaper":
            sub = tokens[1] if len(tokens) > 1 else None
            if sub not in allowed_bash:
                return _deny(f"`chainreaper {sub}` is not allowed for this hunter. "
                             f"Allowed: {sorted(allowed_bash)}.")
            continue
        if base in allowed_tools or base in _HUNT_BENIGN:
            continue
        return _deny(
            f"`{base}` is not in the sandbox toolchain. Allowed: "
            f"{sorted(allowed_tools) + sorted(_HUNT_BENIGN)} (+ chainreaper save-scripts)."
        )
    return _allow_tool("hunt sandbox command")


# --------------------------------------------------------------------------- #
# Stop                                                                         #
# --------------------------------------------------------------------------- #
def decide_stop(env: Mapping, store: ReconStore) -> Decision:
    run = env.get("CHAINREAPER_RUN_ID", "")
    agent = env.get("CHAINREAPER_AGENT", "")
    session = env.get("CHAINREAPER_SESSION", "")
    required = _parse_required(env.get("CHAINREAPER_REQUIRED", ""))
    max_blocks = int(env.get("CHAINREAPER_MAX_STOP_BLOCKS", "3") or "3")

    from .spec import EMITTERS  # local import avoids any import-order surprises

    missing: list[tuple[str, int, int]] = []
    for cmd, need in required:
        emitter = EMITTERS.get(cmd)
        if emitter is None:
            continue
        have = store.count_records(
            run_id=run, agent=agent, session=session, table=emitter.table)
        if have < need:
            missing.append((cmd, have, need))

    if not missing:
        return _proceed()  # all required output produced → allow stop

    blocks = store.count_action(
        run_id=run, agent=agent, session=session, command="__stop_block__")
    if blocks >= max_blocks:
        # Stop forcing — let the stage fail loudly rather than loop forever.
        return 0, json.dumps({
            "systemMessage": f"chainreaper: stop allowed after {blocks} blocks; "
                             f"still missing {missing}",
        })

    store.record_action(run_id=run, agent=agent, session=session,
                        command="__stop_block__", detail=json.dumps(missing))
    reason = (
        "You have NOT finished. Before stopping you must still call: "
        + "; ".join(f"`chainreaper {c}` ({h}/{n} done)" for c, h, n in missing)
        + ". Write each record as JSON under $CHAINREAPER_SCRATCH, then invoke the "
        "save-script with --in. Do it now, then stop."
    )
    return 0, json.dumps({"decision": "block", "reason": reason})


def decide_stop_env(env: Mapping = os.environ) -> Decision:
    """``decide_stop`` opening the artifact DB from the environment (CLI path).
    Fails open (allow stop) if the DB is unavailable, so a misconfig can't hang
    the session."""
    db = env.get("CHAINREAPER_ARTIFACT_DB", "")
    if not db or not Path(db).exists():
        return _proceed()
    store = ReconStore(db)
    try:
        return decide_stop(env, store)
    finally:
        store.close()
