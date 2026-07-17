"""Local secret store — keys live OUTSIDE the source, loaded into the environment.

Every secret the harness needs (``ETHERSCAN_API_KEY``, ``<CHAIN>_RPC_URL``,
``ANTHROPIC_API_KEY``, …) is consumed as an **environment variable** by the code that
uses it (S0 explorer source, S4 fork RPC, the anthropic backend). To survive a *fresh*
run without committing secrets or re-exporting them each shell, they are persisted in a
dotenv-style file under ``.chainreaper/`` (a gitignored directory) and loaded into
``os.environ`` once at CLI startup.

Precedence (a real export always wins):  exported env var  >  ``./.chainreaper/env``
(project-local)  >  ``~/.chainreaper/env`` (global fallback). A key already present in the
environment is never overwritten by a file.

The directory is self-protecting: creating it also writes ``.chainreaper/.gitignore``
(``*``) so secrets can never be committed even if the repo's root ``.gitignore`` misses
it, and the env file is written ``chmod 600``. Values are never logged — only masked.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

CHAINREAPER_DIRNAME = ".chainreaper"
ENV_FILENAME = "env"


# --------------------------------------------------------------------------- #
# Locations                                                                    #
# --------------------------------------------------------------------------- #
def project_dir(base: str | Path | None = None) -> Path:
    """``./.chainreaper`` (override the parent with ``$CHAINREAPER_HOME`` or ``base``)."""
    if base is not None:
        return Path(base) / CHAINREAPER_DIRNAME
    override = os.environ.get("CHAINREAPER_HOME")
    if override:
        return Path(override)
    return Path.cwd() / CHAINREAPER_DIRNAME


def global_dir() -> Path:
    return Path.home() / CHAINREAPER_DIRNAME


def env_file(base: str | Path | None = None) -> Path:
    return project_dir(base) / ENV_FILENAME


def env_search_paths(base: str | Path | None = None) -> list[Path]:
    """Files loaded, highest precedence first (project overrides global)."""
    paths = [env_file(base)]
    g = global_dir() / ENV_FILENAME
    if g not in paths:
        paths.append(g)
    return paths


# --------------------------------------------------------------------------- #
# Parse / load                                                                 #
# --------------------------------------------------------------------------- #
def parse_env_text(text: str) -> dict[str, str]:
    """Parse a dotenv-style file: ``KEY=VALUE`` per line, ``#`` comments, blank lines,
    an optional ``export`` prefix, and optional matching single/double quotes. A value
    is taken verbatim after the first ``=`` (so a key may contain ``#``/``=``)."""
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        if "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip()
        if not key:
            continue
        val = val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
            val = val[1:-1]
        out[key] = val
    return out


def load_env_files(*, environ: dict | None = None, base: str | Path | None = None) -> list[str]:
    """Load ``.chainreaper/env`` files into ``environ`` (default ``os.environ``).

    Never overwrites a key already set (a real export wins). Higher-precedence files are
    applied first so a project value shadows the global one. Missing/unreadable files are
    skipped silently. Returns the key names newly set (for an optional startup log)."""
    target = environ if environ is not None else os.environ
    loaded: list[str] = []
    for path in env_search_paths(base):
        try:
            if not path.is_file():
                continue
            data = parse_env_text(path.read_text())
        except OSError:
            continue
        for key, val in data.items():
            if key not in target and key not in loaded:
                target[key] = val
                loaded.append(key)
    return loaded


# --------------------------------------------------------------------------- #
# Write                                                                        #
# --------------------------------------------------------------------------- #
def _ensure_dir(d: Path) -> None:
    d.mkdir(parents=True, exist_ok=True)
    # self-protecting: ignore the whole dir regardless of the repo's root .gitignore.
    gi = d / ".gitignore"
    if not gi.exists():
        gi.write_text("*\n")


def set_secret(key: str, value: str, *, base: str | Path | None = None) -> Path:
    """Persist ``KEY=value`` to ``./.chainreaper/env`` (created ``chmod 600``), updating the
    line in place if the key already exists. Returns the env-file path."""
    key = key.strip()
    if not key:
        raise ValueError("secret key must be non-empty")
    path = env_file(base)
    _ensure_dir(path.parent)

    lines = path.read_text().splitlines() if path.exists() else []
    new_line = f"{key}={value}"
    replaced = False
    for i, raw in enumerate(lines):
        stripped = raw.strip()
        body = stripped[len("export "):].lstrip() if stripped.startswith("export ") else stripped
        if body.split("=", 1)[0].strip() == key:
            lines[i] = new_line
            replaced = True
            break
    if not replaced:
        lines.append(new_line)
    path.write_text("\n".join(lines) + "\n")
    try:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0600
    except OSError:
        pass
    return path


def list_secret_names(*, base: str | Path | None = None) -> dict[str, list[str]]:
    """``{path: [key names]}`` for each existing env file (names only, never values)."""
    out: dict[str, list[str]] = {}
    for path in env_search_paths(base):
        if path.is_file():
            try:
                out[str(path)] = list(parse_env_text(path.read_text()))
            except OSError:
                continue
    return out


def mask(value: str | None) -> str:
    """Mask a secret for display: keep the last 4 chars, redact the rest."""
    if not value:
        return "(unset)"
    if len(value) <= 4:
        return "•" * len(value)
    return "•" * (len(value) - 4) + value[-4:]
