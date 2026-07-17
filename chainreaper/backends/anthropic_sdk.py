"""Anthropic SDK backend (spec §11, IMPL-NOTES §6).

Concrete ``Backend`` implementation bound to the official ``anthropic`` SDK —
the surface the `claude-api` skill authoritatively documents. Two surfaces:

  * ``prompt(...)``  → ``client.messages.parse(output_format=Model)`` for the
    structured emitters (returns a validated §5 contract via ``parsed_output``);
    ``client.messages.create(...)`` for plain text.
  * ``agentic(...)`` → ``client.beta.messages.tool_runner(...)`` driving the
    read-only sandbox tools (``@beta_tool`` functions) to completion.

Request conventions (all grounded against the `claude-api` skill, NOT memory):
  * Per-role model + reasoning effort come from ``config.models.*`` (defaults.yaml).
  * **Adaptive thinking + effort** are sent for Sonnet 4.6 / Opus 4.x only.
    Claude Haiku 4.5 **400s** on ``output_config.effort`` and adaptive thinking,
    so the backend sends neither to ``claude-haiku-*``.
  * Never send ``temperature``/``top_p``/``budget_tokens`` (400 on Opus 4.8 /
    Sonnet 4.6 / Fable 5).
  * The shared system+skills prefix is prompt-cached (``cache_control`` ephemeral
    on the last system text block) so the many per-task calls reuse it.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import anthropic

# The TOOLS block injected into agent system prompts for this backend (spec §7).
# Describes the @beta_tool surface; structured output is automatic via parse().
API_TOOLS_DOC = (
    "You have these read-only tools (call them via the tool interface):\n"
    "- `code_index_query(kind, args_json)` — the S1 structural index (Slither IR). "
    "kinds: contract, function, entrypoints, callers, callees, writers, readers, "
    "external_calls_in, sinks, inheritance, storage_layout, proxy_info. A function is "
    'addressed by {"signature":"..."} or {"contract":"...","name":"..."}; a state var by '
    '{"contract":"...","var":"..."}.\n'
    "- `read_file(path, start_line, end_line)`, `grep(pattern, path_glob)`, "
    "`invariant_catalog_lookup(contract_types, categories)`.\n"
    "When asked for a structured result, simply provide the data — structured output is "
    "produced and validated automatically; do not hand-format JSON."
)


def _supports_effort_thinking(model_id: str) -> bool:
    """Haiku 4.5 rejects effort + adaptive thinking (400). Everything we route
    (Sonnet 4.6 / Opus 4.x / Fable 5) accepts both."""
    return not model_id.startswith("claude-haiku")


def _as_system_blocks(system: str | list[Any]) -> list[dict]:
    """Normalize a system prompt to cacheable text blocks.

    A plain string becomes a single ephemeral-cached block. A list is assumed to
    already be block dicts; we attach ``cache_control`` to the last text block so
    the stable system+skills prefix is cached across the many per-task calls
    (min cacheable prefix is 2048 tokens on Sonnet — keep volatile per-task text
    in the user message, after this prefix).
    """
    if isinstance(system, str):
        return [{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}]
    blocks = list(system)
    for blk in reversed(blocks):
        if isinstance(blk, dict) and blk.get("type") == "text":
            blk.setdefault("cache_control", {"type": "ephemeral"})
            break
    return blocks


def _text(message: Any) -> str:
    """Concatenate the text blocks of a Message / final tool-runner message."""
    parts = []
    for block in getattr(message, "content", []) or []:
        if getattr(block, "type", None) == "text":
            parts.append(block.text)
    return "\n".join(parts).strip()


def _first_list(dumped: dict) -> list:
    """Extract the single list field from a list-wrapper model dump
    (HunterTaskList.tasks / InvariantList.invariants)."""
    for v in dumped.values():
        if isinstance(v, list):
            return v
    return []


class AnthropicBackend:
    """Implements the ``Backend`` protocol (``backends/base.py``)."""

    name = "anthropic"
    tools_doc = API_TOOLS_DOC

    def __init__(self, config: Any, *, repo_root: Any = None, db_path: Any = None):
        # ``Anthropic()`` resolves ANTHROPIC_API_KEY from the environment.
        if not os.environ.get("ANTHROPIC_API_KEY"):
            raise RuntimeError(
                "ANTHROPIC_API_KEY is not set — required for S2+ (the first model-calling "
                "stage). Export it and re-run (run `chainreaper doctor` to verify)."
            )
        self.client = anthropic.Anthropic()
        self._models: dict = dict(config.get("models", {}))
        # repo_root/db_path power run_agent's read-only tool surface.
        self.repo_root = str(Path(repo_root).resolve()) if repo_root else os.getcwd()
        self.db_path = str(db_path) if db_path else None

    # -- per-role request shaping ------------------------------------------ #
    def _model_for(self, role: str) -> str:
        spec = self._models.get(role)
        if not spec or not spec.get("id"):
            raise KeyError(f"no model configured for role {role!r} (config.models.{role}.id)")
        return spec["id"]

    def _effort_for(self, role: str) -> str:
        return self._models.get(role, {}).get("effort", "high")

    def _base_kwargs(self, role: str, max_tokens: int, effort: str | None) -> dict:
        model = self._model_for(role)
        kw: dict[str, Any] = {"model": model, "max_tokens": max_tokens}
        if _supports_effort_thinking(model):
            kw["thinking"] = {"type": "adaptive"}
            kw["output_config"] = {"effort": effort or self._effort_for(role)}
        return kw

    # -- Backend surface ---------------------------------------------------- #
    def prompt(
        self,
        *,
        role: str,
        system: str | list[Any],
        messages: list[dict],
        output_format: type | None = None,
        max_tokens: int = 8000,
        effort: str | None = None,
    ) -> Any:
        kw = self._base_kwargs(role, max_tokens, effort)
        sys_blocks = _as_system_blocks(system)
        if output_format is not None:
            resp = self.client.messages.parse(
                system=sys_blocks, messages=messages, output_format=output_format, **kw
            )
            return resp.parsed_output
        resp = self.client.messages.create(system=sys_blocks, messages=messages, **kw)
        return _text(resp)

    def agentic(
        self,
        *,
        role: str,
        system: str | list[Any],
        messages: list[dict],
        tools: list[Any],
        max_tokens: int = 16000,
        effort: str | None = None,
        max_iterations: int | None = None,
    ) -> Any:
        kw = self._base_kwargs(role, max_tokens, effort)
        if max_iterations is not None:
            kw["max_iterations"] = max_iterations
        sys_blocks = _as_system_blocks(system)
        runner = self.client.beta.messages.tool_runner(
            system=sys_blocks, messages=messages, tools=tools, **kw
        )
        final = runner.until_done()
        return _text(final)

    def run_agent(self, spec: Any, *, index_db: str, artifact_db: str,
                  run_id: str, scratch_dir: str | None = None,
                  cwd: str | None = None) -> dict:
        """API-backend equivalent of the claude_cli session: explore with the
        read-only tools, then ``messages.parse`` each emitter's schema and write
        the validated records straight into ``chainreaper.db`` via the store. Same
        "agent output → database" contract, enforced by the stage's row check
        (no Claude Code hooks on this path)."""
        if getattr(spec, "mode", "recon") == "hunt":
            raise NotImplementedError(
                "The Hunter (sandbox tool-loop) is not implemented for the anthropic "
                "backend yet — run S4 with backend.provider=claude_cli.")
        from ..agents.emitters import _insert
        from ..recon.store import ReconStore
        from ..tools.agent_tools import build_readonly_tools

        tools = build_readonly_tools(index_db, self.repo_root)
        notes = self.agentic(
            role=spec.role, system=spec.system_prompt, tools=tools, max_tokens=16000,
            messages=[{"role": "user", "content":
                       spec.user_message + "\n\nExplore now, then end with a complete "
                       "written brief covering everything your deliverables need."}],
        )
        store = ReconStore(artifact_db)
        store.create_schema()
        session = "api"
        try:
            for e in spec.emitters:
                if e.multiple and e.list_schema is not None:
                    wrapper = self.prompt(
                        role=spec.role, system=spec.system_prompt,
                        output_format=e.list_schema, max_tokens=12000,
                        messages=[{"role": "user", "content":
                                   f"From your brief, emit the {e.list_schema.__name__} "
                                   f"(≥{e.min_calls} records).\n\nBRIEF:\n" + notes}])
                    records = _first_list(wrapper.model_dump(mode="json"))
                else:
                    obj = self.prompt(
                        role=spec.role, system=spec.system_prompt,
                        output_format=e.schema, max_tokens=8000,
                        messages=[{"role": "user", "content":
                                   f"From your brief, emit the {e.schema.__name__}."
                                   f"\n\nBRIEF:\n" + notes}])
                    records = [obj.model_dump(mode="json")]
                for rec in records:
                    _insert(store, e.table, run_id=run_id, agent=spec.name,
                            session=session, obj=rec)
                store.record_action(run_id=run_id, agent=spec.name, session=session,
                                    command=e.command, detail=f"{len(records)} record(s)")
        finally:
            store.close()
        return {"agent": spec.name, "session": session, "via": "messages.parse"}

    # -- self-test ---------------------------------------------------------- #
    def selftest(self) -> str:
        """One trivial ``messages.parse`` round-trip to verify creds + structured
        output before the stage spends real tokens (IMPL-NOTES §6)."""
        from pydantic import BaseModel, ConfigDict

        class _Ping(BaseModel):
            model_config = ConfigDict(extra="forbid")
            ok: bool

        out = self.prompt(
            role="coerce",
            system="Reply only via the structured tool.",
            messages=[{"role": "user", "content": "Return ok=true."}],
            output_format=_Ping,
            max_tokens=64,
        )
        return f"selftest ok={getattr(out, 'ok', None)}"
