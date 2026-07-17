"""`incident_catalog` — protocol-class known-incident lookup (spec §9).

Backs the S2 Invariant Synthesizer's regression class: given the target's
classified ``contract_types``, return the known high-severity incident classes for
those types from ``skills/incidents/incident_classes.yaml``. This is what makes
invariant synthesis CLASSIFICATION-driven rather than hardcoded per target — a
lending protocol gets the lending classes, a bridge gets the bridge classes, with
no prompt changes. Pure data lookup, no model call.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

_CATALOG_PATH = (Path(__file__).resolve().parent.parent
                 / "skills" / "incidents" / "incident_classes.yaml")


@lru_cache(maxsize=1)
def _load() -> list[dict]:
    if not _CATALOG_PATH.exists():
        return []
    data = yaml.safe_load(_CATALOG_PATH.read_text()) or {}
    return data.get("classes", [])


def incident_catalog(contract_types: list[str] | None = None) -> list[dict]:
    """Incident classes whose ``applies_to`` intersects the classified contract
    types. Empty/None contract_types returns the full catalog. Case-insensitive."""
    classes = _load()
    if not contract_types:
        return list(classes)
    want = {t.lower() for t in contract_types}
    return [c for c in classes
            if want & {a.lower() for a in c.get("applies_to", [])}]
