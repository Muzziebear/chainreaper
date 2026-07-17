"""LLM provider abstraction (spec §11, IMPL-NOTES §6).

This is the protocol every concrete backend implements. It is **not called in
S1** (the Index stage is deterministic and shells out to static analyzers); the
stub lives here so the spine is complete and S2+ can bind the `anthropic` SDK
implementation (`backends/anthropic_sdk.py`) without reshaping the interface.

Two surfaces (IMPL-NOTES §6):
  * ``prompt(...)``  → structured/text completion. With ``output_format`` set to
    a Pydantic model, the SDK returns a validated instance (our §5 contracts) —
    this is the ``create_finding`` / ``emit_verdict`` emitter path.
  * ``agentic(...)`` → tool-using loop (the hunter's sandbox tools).
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class Backend(Protocol):
    name: str

    def prompt(
        self,
        *,
        role: str,
        system: str | list[Any],
        messages: list[dict],
        output_format: type | None = None,
        max_tokens: int = 8000,
        effort: str = "high",
    ) -> Any:
        """Single completion. Returns a validated model instance when
        ``output_format`` is given, else the assistant text."""
        ...

    def agentic(
        self,
        *,
        role: str,
        system: str | list[Any],
        messages: list[dict],
        tools: list[Any],
        max_tokens: int = 16000,
        effort: str = "high",
    ) -> Any:
        """Tool-using loop until the model stops. Returns the final message /
        accumulated tool results."""
        ...

    def run_agent(
        self,
        spec: Any,
        *,
        index_db: str,
        artifact_db: str,
        run_id: str,
        scratch_dir: str | None = None,
        cwd: str | None = None,
    ) -> dict:
        """Run one scoped, output-obligated agent (``agents.spec.AgentSpec``) to
        completion. The agent's output is persisted to the per-run
        ``chainreaper.db`` — by the ``recon-create-*`` save-scripts for the
        ``claude_cli`` backend, or written to the store via ``messages.parse`` for
        the API backend. Returns a small session summary; the stage reads the
        actual records back from the store."""
        ...
