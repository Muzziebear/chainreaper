"""Read-only agent tools for S2 Recon (spec §7-§8, IMPL-NOTES §6).

The Recon agent (and the Invariant Synthesizer) explore the target through this
tool surface only — **read-only** (no writes, no sandbox, no shell beyond a
constrained `grep`). Each tool is an ``@beta_tool``-decorated function whose
schema the Anthropic SDK derives from the signature + docstring, passed to
``client.beta.messages.tool_runner(...)``.

``build_readonly_tools(db_path, repo_root)`` closes the tools over the per-run
SQLite index (the big reuse — wraps ``code_index.query``) and the in-scope repo
root (``read``/``grep``), plus the crytic/properties ``invariant_catalog``.
``web_search`` is deferred (spec §8 "optional provider key").

Every tool returns a **string** (the tool-result content). Outputs are bounded
so a wandering agent can't blow the context window.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from anthropic import beta_tool

from .code_index import CodeIndex
from .invariant_catalog import invariant_catalog as _invariant_catalog

_MAX_ROWS = 40          # cap rows returned from a code_index query
_MAX_CHARS = 8000       # cap any single tool-result payload
_MAX_READ_LINES = 400   # cap a single read_file span


def _clip(text: str) -> str:
    if len(text) <= _MAX_CHARS:
        return text
    return text[:_MAX_CHARS] + f"\n… [truncated, {len(text) - _MAX_CHARS} more chars]"


def _csv(value: str) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


def build_readonly_tools(db_path: str | Path, repo_root: str | Path) -> list:
    """Return the list of ``@beta_tool`` functions bound to this run's index + repo."""
    db_path = str(db_path)
    repo_root = Path(repo_root).resolve()

    @beta_tool
    def code_index_query(kind: str, args_json: str = "{}") -> str:
        """Query the structural code index (Slither-derived SQLite) built by S1.

        This is the primary way to navigate the target: callers/callees of a
        function, writers/readers of a state var, entrypoints, sinks, inheritance,
        storage layout, proxy info.

        Args:
            kind: One of: contract, function, entrypoints, callers, callees,
                writers, readers, external_calls_in, sinks, inheritance,
                storage_layout, proxy_info.
            args_json: JSON object of arguments for the query. A function is
                addressed by {"signature": "..."} or {"contract": "...", "name": "..."};
                a state var by {"contract": "...", "var": "..."}. Examples:
                {"contract": "MarketUtils"}, {"contract": "DataStore", "var": "uintValues"},
                {"kind": "delegatecall"}. Pass {} for unfiltered (e.g. all entrypoints).
        """
        try:
            args = json.loads(args_json) if args_json.strip() else {}
        except json.JSONDecodeError as exc:
            return f"error: args_json is not valid JSON: {exc}"
        if not isinstance(args, dict):
            return "error: args_json must be a JSON object"
        idx = CodeIndex(db_path)
        try:
            rows = idx.query(kind, args)
        except ValueError as exc:
            return f"error: {exc}"
        except Exception as exc:  # never crash the agent loop (spec §8)
            return f"error: query failed: {exc}"
        finally:
            idx.close()
        total = len(rows)
        payload = {"kind": kind, "count": total, "rows": rows[:_MAX_ROWS]}
        if total > _MAX_ROWS:
            payload["note"] = f"showing first {_MAX_ROWS} of {total} rows"
        return _clip(json.dumps(payload, default=str))

    @beta_tool
    def read_file(path: str, start_line: int = 1, end_line: int = 200) -> str:
        """Read a span of an in-scope source file (repo-relative path).

        Args:
            path: Repo-relative path, e.g. "contracts/market/MarketUtils.sol".
            start_line: 1-based first line to return.
            end_line: 1-based last line (inclusive). Capped to 400 lines per call.
        """
        target = (repo_root / path).resolve()
        # hard guardrail: stay inside the in-scope repo
        if not str(target).startswith(str(repo_root)):
            return "error: path escapes the in-scope repository root"
        if not target.is_file():
            return f"error: not a file: {path}"
        start = max(1, int(start_line))
        end = max(start, int(end_line))
        end = min(end, start + _MAX_READ_LINES - 1)
        try:
            lines = target.read_text(errors="replace").splitlines()
        except OSError as exc:
            return f"error: {exc}"
        span = lines[start - 1 : end]
        numbered = "\n".join(f"{start + i}\t{ln}" for i, ln in enumerate(span))
        return _clip(f"{path} (lines {start}-{start + len(span) - 1} of {len(lines)})\n{numbered}")

    @beta_tool
    def grep(pattern: str, path_glob: str = "") -> str:
        """Search in-scope source for a regex pattern (returns file:line: match).

        Args:
            pattern: A regular expression to search for, e.g. "nonReentrant".
            path_glob: Optional glob to restrict the search, e.g. "*.sol" or
                "contracts/market/*". Empty searches all files under the repo.
        """
        rg = shutil.which("rg")
        try:
            if rg:
                cmd = [rg, "--line-number", "--no-heading", "--max-count", "60", pattern]
                if path_glob:
                    cmd += ["--glob", path_glob]
                cmd += ["."]
            else:  # portable fallback
                cmd = ["grep", "-rIn", "--include", path_glob or "*", pattern, "."]
            proc = subprocess.run(
                cmd, cwd=str(repo_root), capture_output=True, text=True, timeout=60
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return f"error: grep failed: {exc}"
        out = proc.stdout.strip()
        if not out:
            return f"no matches for /{pattern}/" + (f" in {path_glob}" if path_glob else "")
        hits = out.splitlines()
        body = "\n".join(hits[:60])
        if len(hits) > 60:
            body += f"\n… [{len(hits) - 60} more matches]"
        return _clip(body)

    @beta_tool
    def invariant_catalog_lookup(contract_types: str = "", categories: str = "") -> str:
        """Look up reusable crytic/properties invariant seed libraries for the
        target's protocol class — wire these BEFORE synthesizing custom invariants.

        Args:
            contract_types: Comma-separated contract types, e.g. "vault,perp,oracle".
            categories: Comma-separated InvariantCategory names, e.g.
                "share_price,solvency,fee". Empty args return the full catalog.
        """
        seeds = _invariant_catalog(_csv(contract_types) or None, _csv(categories) or None)
        # trim each seed to the fields the synthesizer needs
        slim = [
            {
                "id": s.get("id"),
                "library": s.get("library"),
                "properties": s.get("properties", []),
                "contract_types": s.get("contract_types", []),
                "categories": s.get("categories", []),
                "seeds_invariants": s.get("seeds_invariants", []),
                "tool": s.get("tool"),
            }
            for s in seeds
        ]
        return _clip(json.dumps({"count": len(slim), "seeds": slim}, default=str))

    return [code_index_query, read_file, grep, invariant_catalog_lookup]
