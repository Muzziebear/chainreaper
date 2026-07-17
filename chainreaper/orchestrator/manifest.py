"""Run manifest (spec §13): config hash, models, target, command line, exit code.

Written for every run so a run dir is self-describing and reproducible.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any


def config_hash(config: dict) -> str:
    blob = json.dumps(config, sort_keys=True, default=str).encode()
    return hashlib.sha256(blob).hexdigest()[:16]


def write_manifest(
    run_dir: str | Path,
    *,
    run_id: str,
    config: dict,
    target: dict | None,
    argv: list[str] | None = None,
    exit_code: int | None = None,
    extra: dict[str, Any] | None = None,
) -> Path:
    run_dir = Path(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "run_id": run_id,
        "config_hash": config_hash(config),
        "models": config.get("models", {}),
        "target": {"program_id": target.get("program_id"), "name": target.get("name")} if target else None,
        "command_line": argv if argv is not None else sys.argv,
        "exit_code": exit_code,
    }
    if extra:
        manifest.update(extra)
    path = run_dir / "run_manifest.json"
    path.write_text(json.dumps(manifest, indent=2, default=str))
    return path
