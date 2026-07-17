"""LLM backends (spec §11). Two implementations, selected by ``backend.provider``:

* ``anthropic``   — the developer API SDK (``messages.parse`` structured output);
                    needs ``ANTHROPIC_API_KEY``.
* ``claude_cli``  — the Claude Code subscription via headless ``claude -p`` (no
                    API key); structured output via the ``chainreaper emit`` helper.

Both implement ``backends.base.Backend`` and expose ``tools_doc`` (the TOOLS block
the agent factory injects into system prompts).
"""

from __future__ import annotations

from typing import Any


def build_backend(config: Any, *, repo_root: Any = None, db_path: Any = None):
    """Construct the configured backend. ``repo_root``/``db_path`` give the
    subscription backend the agent's working dir + index path (ignored by the API
    backend, whose tools carry the index path directly)."""
    provider = str(config.get("backend", {}).get("provider", "anthropic"))
    if provider == "anthropic":
        from .anthropic_sdk import AnthropicBackend
        return AnthropicBackend(config, repo_root=repo_root, db_path=db_path)
    if provider in ("claude_cli", "anthropic_cli"):
        from .claude_cli import ClaudeCLIBackend
        return ClaudeCLIBackend(config, repo_root=repo_root, db_path=db_path)
    raise NotImplementedError(
        f"backend provider {provider!r} not implemented (use 'anthropic' or 'claude_cli')"
    )
