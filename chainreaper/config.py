"""Layered YAML config loader (spec §12).

Resolution order (later overrides earlier): packaged ``config/defaults.yaml`` →
optional user ``--config`` file → CLI overrides. Returns a plain dict wrapped in
a tiny attribute-access shim so callers can write ``cfg.models["hunt"]`` etc.
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import yaml

_DEFAULTS_PATH = Path(__file__).parent / "config" / "defaults.yaml"


def _deep_merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


class Config(dict):
    """dict with attribute access for top-level keys."""

    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError as exc:  # pragma: no cover - defensive
            raise AttributeError(name) from exc


def load_config(user_config: str | Path | None = None, overrides: dict | None = None) -> Config:
    data: dict = {}
    if _DEFAULTS_PATH.exists():
        data = yaml.safe_load(_DEFAULTS_PATH.read_text()) or {}
    if user_config:
        p = Path(user_config)
        if not p.exists():
            raise FileNotFoundError(f"config file not found: {p}")
        data = _deep_merge(data, yaml.safe_load(p.read_text()) or {})
    if overrides:
        data = _deep_merge(data, overrides)
    return Config(data)
