"""`invariant_catalog` tool (spec §8) — crytic/properties seed lookup.

Backs the S2 Invariant Synthesizer: given the target's `contract_types` (and/or
`InvariantCategory`s), return the ready-made property libraries to wire before
synthesizing custom invariants (invariants.md §0 "Reuse"). Pure data lookup over
`skills/invariants/property_seeds.yaml` — no model call. In S2 this is wrapped as
an agent tool; here it is importable and unit-testable directly.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

_CATALOG_PATH = Path(__file__).resolve().parent.parent / "skills" / "invariants" / "property_seeds.yaml"


@lru_cache(maxsize=1)
def _load() -> list[dict]:
    if not _CATALOG_PATH.exists():
        return []
    data = yaml.safe_load(_CATALOG_PATH.read_text()) or {}
    return data.get("seeds", [])


def property_seeds() -> list[dict]:
    """All registered seed property libraries."""
    return list(_load())


def invariant_catalog(contract_types: list[str] | None = None,
                      categories: list[str] | None = None) -> list[dict]:
    """Return seeds whose `contract_types` or `categories` intersect the args.

    With no filters, returns the full catalog. Matching is case-insensitive on
    the seed's declared `contract_types` / `categories`.
    """
    seeds = _load()
    if not contract_types and not categories:
        return list(seeds)

    want_types = {t.lower() for t in (contract_types or [])}
    want_cats = {c.lower() for c in (categories or [])}
    out = []
    for s in seeds:
        s_types = {t.lower() for t in s.get("contract_types", [])}
        s_cats = {c.lower() for c in s.get("categories", [])}
        if (want_types & s_types) or (want_cats & s_cats):
            out.append(s)
    return out
