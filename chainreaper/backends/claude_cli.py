"""Claude Code CLI backend (spec §11; subscription-powered).

Drives the user's **Claude Code subscription** via the headless ``claude -p`` CLI
instead of the developer API — no ``ANTHROPIC_API_KEY``.

Design (prompts + save-scripts + hooks, not MCP, not Skills):
  ``run_agent(spec)`` launches **one bounded agentic session** per agent. The
  agent explores the in-scope source (native Read/Grep/Glob) and the S1 index
  (``chainreaper code-index`` over Bash), then persists its output by calling the
  schema-validated ``chainreaper recon-create-*`` save-scripts, which write the
  per-run ``chainreaper.db``. Scope and the output obligation are enforced three
  ways (``agents.session`` wires them): the prompt, the tool-permission config
  (``--allowed-tools``/``--disallowed-tools`` + ``--settings.permissions``), and
  Claude Code hooks (PreToolUse ``hook-guard`` + Stop ``hook-stop``).

``prompt``/``agentic`` remain as thin text helpers (e.g. ``selftest``); structured
output for this backend is the save-scripts, not ``messages.parse``.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
import uuid
from pathlib import Path
from typing import Any

from ..agents.session import build_invocation
from ..agents.spec import AgentSpec
from ..runtime.exec import augmented_env
from ..runtime.logging import get_logger

# The TOOLS block injected into agent system prompts for this backend (spec §7).
CLI_TOOLS_DOC = (
    "You are running inside Claude Code, read-only. The repository root is your "
    "working directory. Tools for exploration:\n"
    "- **Read / Grep / Glob** — read and search the in-scope source directly.\n"
    "- **Bash, restricted to the `chainreaper` helper:**\n"
    "  - `chainreaper code-index <kind> '<args_json>'` — the S1 structural index "
    "(Slither IR). kinds: contract, function, entrypoints, callers, callees, writers, "
    "readers, external_calls_in, sinks, inheritance, storage_layout, proxy_info, "
    "**sast** (slither detector findings recorded at index time — filter by "
    "'{\"impact\":\"High\"}', '{\"check\":\"reentrancy-eth\"}', or '{\"contract\":\"X\"}'). "
    "A function is addressed by '{\"signature\":\"...\"}' or "
    "'{\"contract\":\"...\",\"name\":\"...\"}'; a state var by "
    "'{\"contract\":\"...\",\"var\":\"...\"}'. Prints JSON. Prefer it over raw grep for "
    "call-graph, accounting, and slither-finding questions.\n"
    "    Example: chainreaper code-index sast '{\"impact\":\"High\"}'\n"
    "You persist results ONLY via the `chainreaper recon-create-*` save-scripts — see "
    "the REQUIRED OUTPUT and OUTPUT MECHANICS sections. Bash is limited to these "
    "`chainreaper` commands (no pipes/redirects/other programs)."
)


# Signatures of a TRANSIENT, retryable Anthropic API failure (as surfaced by the Claude
# Code CLI in its stream/stderr). Deliberately specific so a genuine agent/guard error is
# NOT mistaken for transient and retried pointlessly.
_TRANSIENT_API_MARKERS = (
    "529",              # Overloaded
    "overloaded",
    "rate_limit",       # 429
    "rate limit",
    "503",
    "service unavailable",
    "internal server error",
    "500 internal",
    "502 bad gateway",
    "api error: 5",     # generic 5xx as reported by the CLI
    "upstream connect error",
)


def _is_transient_api_error(text: str) -> bool:
    if not text:
        return False
    low = text.lower()
    return any(m in low for m in _TRANSIENT_API_MARKERS)


def _user_text(messages: list[dict]) -> str:
    parts = []
    for m in messages:
        c = m.get("content", "")
        parts.append(c if isinstance(c, str) else json.dumps(c))
    return "\n\n".join(parts)


class ClaudeCLIBackend:
    name = "claude_cli"
    tools_doc = CLI_TOOLS_DOC

    def __init__(self, config: Any, *, repo_root: Any = None, db_path: Any = None):
        self._claude = shutil.which("claude")
        if not self._claude:
            raise RuntimeError(
                "`claude` CLI not found on PATH — the claude_cli backend needs Claude "
                "Code installed and logged in (subscription). Run `chainreaper doctor`."
            )
        self._chainreaper = self._resolve_chainreaper()
        self._models = dict(config.get("models", {}))
        self.repo_root = str(Path(repo_root).resolve()) if repo_root else os.getcwd()
        self.db_path = str(db_path) if db_path else None
        recon = config.get("recon", {})
        agents = config.get("agents", {})
        # one session does explore + emit, so the budget is the old explore+emit sum.
        self.session_timeout = int(
            recon.get("session_timeout_s", recon.get("explore_timeout_s", 1200)))
        self.max_stop_blocks = int(agents.get("max_stop_blocks", 3))
        # Retry a session that dies on a TRANSIENT Anthropic API error (529 Overloaded /
        # 5xx / rate-limit). Default 2 retries with exponential backoff from 20s.
        self.transient_retries = int(agents.get("transient_retries", 2))
        self.transient_backoff_s = float(agents.get("transient_backoff_s", 20))

    # -- internals ---------------------------------------------------------- #
    @staticmethod
    def _resolve_chainreaper() -> str:
        """Absolute path to the ``chainreaper`` console script (hooks/save-scripts
        invoke it). Prefer the one next to the running interpreter (venv)."""
        cand = Path(sys.executable).resolve().parent / "chainreaper"
        if cand.exists():
            return str(cand)
        return shutil.which("chainreaper") or "chainreaper"

    def _model(self, role: str) -> str:
        return self._models.get(role, {}).get("id", "claude-opus-4-8")

    def _env(self) -> dict:
        env = dict(os.environ)
        env["PATH"] = str(Path(sys.executable).resolve().parent) + os.pathsep + env.get("PATH", "")
        if self.db_path:
            env["CHAINREAPER_INDEX_DB"] = self.db_path
        return env

    def _run_text(self, *, role: str, system: str, user: str, allowed: list[str],
                  disallowed: list[str], timeout: int) -> str:
        cmd = [self._claude, "-p", user, "--model", self._model(role),
               "--output-format", "json"]
        if system:
            cmd += ["--append-system-prompt", system]
        if allowed:
            cmd += ["--allowed-tools", *allowed]
        if disallowed:
            cmd += ["--disallowed-tools", *disallowed]
        try:
            proc = subprocess.run(cmd, cwd=self.repo_root, env=self._env(),
                                  capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"claude -p timed out after {timeout}s") from exc
        if proc.returncode != 0:
            raise RuntimeError(f"claude -p failed (exit {proc.returncode}): "
                               f"{(proc.stderr or proc.stdout)[:600]}")
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"claude -p produced non-JSON output: {proc.stdout[:300]}") from exc
        if data.get("is_error"):
            raise RuntimeError(f"claude session error: {str(data.get('result'))[:600]}")
        return data.get("result", "") or ""

    # -- live event logging ------------------------------------------------- #
    @staticmethod
    def _log_event(log, agent: str, raw_line: str, final: dict) -> None:
        """Turn one stream-json event into a concise live log line + capture the
        final result for error detection."""
        raw_line = raw_line.strip()
        if not raw_line:
            return
        try:
            ev = json.loads(raw_line)
        except json.JSONDecodeError:
            return
        etype = ev.get("type")
        msg = ev.get("message", {}) or {}
        if etype == "assistant":
            for b in (msg.get("content") or []):
                if b.get("type") == "tool_use":
                    inp = b.get("input", {}) or {}
                    arg = (inp.get("command") or inp.get("file_path") or inp.get("pattern")
                           or inp.get("path") or json.dumps(inp))
                    log.info("[%s] → %s: %s", agent, b.get("name"), str(arg)[:140])
                elif b.get("type") == "text" and b.get("text", "").strip():
                    log.info("[%s] 💬 %s", agent, b["text"].strip()[:200])
        elif etype == "user":
            for b in (msg.get("content") or []):
                if b.get("type") == "tool_result":
                    c = b.get("content")
                    txt = c if isinstance(c, str) else json.dumps(c)
                    tag = "ERR" if b.get("is_error") else "ok"
                    log.info("[%s]   ↳ %s: %s", agent, tag, str(txt).replace("\n", " ")[:110])
        elif etype == "result":
            final["is_error"] = bool(ev.get("is_error"))
            final["result"] = ev.get("result", "")
            final["num_turns"] = ev.get("num_turns")

    # -- Backend surface ---------------------------------------------------- #
    def run_agent(self, spec: AgentSpec, *, index_db: str, artifact_db: str,
                  run_id: str, scratch_dir: str | None = None,
                  cwd: str | None = None) -> dict:
        """Run ONE scoped, output-obligated ``claude -p`` agent session, streaming
        its events live to the run logger and a raw per-agent jsonl. The agent's
        output lands in ``chainreaper.db`` via its save-scripts; this returns a small
        session summary (the real result is read back from the store by the stage).

        ``scratch_dir`` / ``cwd`` override the defaults for a Hunter: its scratch IS
        its sandbox workspace (so Write/Edit + the PoC project share one writable
        root), and it runs *in* that workspace so ``forge`` finds foundry.toml."""
        import time as _time
        log = get_logger()
        run_dir = Path(artifact_db).resolve().parent
        work_dir = str(Path(cwd).resolve()) if cwd else self.repo_root
        logdir = run_dir / "logs"
        logdir.mkdir(parents=True, exist_ok=True)

        # A Hunter runs the sandbox toolchain (forge/slither/…) via Bash, so its env
        # needs the toolchain dirs on PATH (the read-only recon agents do not).
        base_env = augmented_env(os.environ) if spec.mode == "hunt" else os.environ

        # Transient Anthropic API errors (529 Overloaded, 5xx, rate limit) surface as an
        # `is_error` result / non-zero exit that kills the whole session mid-flight —
        # previously the task was lost with no outcome. Retry the session with backoff on
        # a transient signature only; genuine agent/guard errors still raise immediately.
        last_exc: Exception | None = None
        for attempt in range(self.transient_retries + 1):
            sid = uuid.uuid4().hex[:12]
            scratch = (Path(scratch_dir) if scratch_dir
                       else run_dir / "agent_scratch" / f"{spec.name}-{sid}")
            scratch.mkdir(parents=True, exist_ok=True)
            raw_log = logdir / f"agent-{spec.name}-{sid}.jsonl"
            # Re-resolve the claude binary per session: the Claude Code CLI auto-updates
            # itself, which briefly removes/relinks its binary — a path cached once at
            # backend construction goes stale and every later hunter dies with
            # FileNotFoundError. Resolve fresh here, and retry-with-reresolve on launch.
            self._claude = shutil.which("claude") or self._claude

            def _build():
                return build_invocation(
                    spec, claude_bin=self._claude, chainreaper_bin=self._chainreaper,
                    model=self._model(spec.role), index_db=str(index_db),
                    artifact_db=str(artifact_db), run_id=run_id, session_id=sid,
                    scratch_dir=str(scratch), max_stop_blocks=self.max_stop_blocks,
                    base_env=base_env,
                )

            inv = _build()
            retry_tag = f" (retry {attempt}/{self.transient_retries})" if attempt else ""
            log.info("[%s] session %s start (model=%s, timeout=%ss, mode=%s)%s · cwd=%s · raw → %s",
                     spec.name, sid, self._model(spec.role), self.session_timeout,
                     spec.mode, retry_tag, work_dir, raw_log)

            def _launch():
                return subprocess.Popen(inv.argv, cwd=work_dir, env=inv.env,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        text=True, bufsize=1)
            try:
                proc = _launch()
            except FileNotFoundError:
                # claude binary transiently gone (mid auto-update) — wait, re-resolve, retry.
                _time.sleep(8)
                self._claude = shutil.which("claude") or self._claude
                inv = _build()
                log.info("[%s] claude binary was missing (auto-update?); re-resolved to %s, retrying",
                         spec.name, self._claude)
                proc = _launch()
            final: dict = {"is_error": False, "result": "", "num_turns": None}
            errbuf: list[str] = []
            transient: list[bool] = [False]

            def _read_stdout() -> None:
                with open(raw_log, "w", encoding="utf-8") as f:
                    for line in proc.stdout:  # type: ignore[union-attr]
                        f.write(line)
                        f.flush()
                        if _is_transient_api_error(line):
                            transient[0] = True
                        self._log_event(log, spec.name, line, final)

            def _read_stderr() -> None:
                for line in proc.stderr:  # type: ignore[union-attr]
                    errbuf.append(line)
                    if _is_transient_api_error(line):
                        transient[0] = True

            t_out = threading.Thread(target=_read_stdout, daemon=True)
            t_err = threading.Thread(target=_read_stderr, daemon=True)
            t_out.start()
            t_err.start()
            try:
                proc.wait(timeout=self.session_timeout)
            except subprocess.TimeoutExpired as exc:
                proc.terminate()
                try:
                    proc.wait(10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                t_out.join(5)
                t_err.join(5)
                raise RuntimeError(
                    f"claude -p agent '{spec.name}' timed out after {self.session_timeout}s "
                    "(explore + emit). Raise recon.session_timeout_s if the repo is large."
                ) from exc
            t_out.join(5)
            t_err.join(5)

            failed = proc.returncode != 0 or final["is_error"]
            if not failed:
                log.info("[%s] session %s complete (turns=%s)", spec.name, sid,
                         final.get("num_turns"))
                return {"agent": spec.name, "session": sid, "scratch": str(scratch),
                        "result_tail": str(final.get("result", ""))[-400:]}

            detail = (str(final["result"])[:600] if final["is_error"]
                      else f"exit {proc.returncode}: {(''.join(errbuf))[:800]}")
            last_exc = RuntimeError(f"claude -p agent '{spec.name}' failed ({detail})")
            # Only a TRANSIENT API failure is worth re-running; a real agent/guard error
            # would just fail identically, so surface it immediately.
            if not (transient[0] and _is_transient_api_error(detail)) or attempt >= self.transient_retries:
                raise last_exc
            backoff = self.transient_backoff_s * (2 ** attempt)
            log.info("[%s] transient API error (session %s); retrying in %ss (%d/%d)",
                     spec.name, sid, backoff, attempt + 1, self.transient_retries)
            _time.sleep(backoff)
        raise last_exc  # unreachable, but keeps the type checker happy

    def prompt(self, *, role: str, system: str | list[Any], messages: list[dict],
               output_format: type | None = None, max_tokens: int = 8000,
               effort: str | None = None) -> Any:
        if output_format is not None:
            raise NotImplementedError(
                "claude_cli persists structured output via the recon-create-* "
                "save-scripts (run_agent), not messages.parse."
            )
        system = system if isinstance(system, str) else _user_text(system)
        return self._run_text(role=role, system=system, user=_user_text(messages),
                              allowed=["Read", "Grep", "Glob", "Bash(chainreaper:*)"],
                              disallowed=["Task"], timeout=self.session_timeout)

    def agentic(self, *, role: str, system: str | list[Any], messages: list[dict],
                tools: list[Any] | None = None, max_tokens: int = 16000,
                effort: str | None = None, max_iterations: int | None = None) -> Any:
        system = system if isinstance(system, str) else _user_text(system)
        return self._run_text(role=role, system=system, user=_user_text(messages),
                              allowed=["Read", "Grep", "Glob", "Bash(chainreaper:*)"],
                              disallowed=["Task"], timeout=self.session_timeout)

    # -- self-test ---------------------------------------------------------- #
    def selftest(self) -> str:
        out = self._run_text(role="recon", system="", user="Reply with exactly: PONG",
                            allowed=[], disallowed=["Task"], timeout=120)
        return f"selftest claude_cli model={self._model('recon')} reply={out.strip()[:16]!r}"
