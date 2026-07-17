"""Storage-layout diff for upgrade-safety (Tier-4 P4, spec §16b).

A proxy upgrade keeps the proxy's storage but swaps the implementation's *code*. If
the new implementation's storage LAYOUT is not a strict append-only extension of the
old one — a variable inserted, reordered, removed, or retyped at an already-used slot
— then every read/write in the new code lands on the WRONG slot: balances alias admin
flags, a `bool` overlays a `uint256`, accounting silently corrupts. This is SC10
(Proxy & Upgradeability), and it is invisible to a single-version code read because it
only exists in the DELTA between two implementations.

This module is a pure, deterministic helper (no tool runs): give it two contracts'
ordered storage layouts (from the S1 index ``state_vars`` rows, or any source) and it
returns the collisions that make the upgrade unsafe. Unit-tested offline; a P4
upgrade-simulation HunterTask cites its output as the seed for a fork PoC.

Layout model: each occupant is ``{slot, name, type}``. ``normalize_layout`` builds it
from raw state-var dicts/rows, dropping ``constant``/``immutable`` vars (they live in
code, not storage) and assigning declaration-order slots when explicit slots are absent
(slither without compilation does not resolve slots).
"""

from __future__ import annotations

from typing import Any


def _is_storage_var(v: Any) -> bool:
    """A declared state var occupies a storage slot unless it is constant/immutable."""
    def g(key: str) -> Any:
        return v.get(key) if isinstance(v, dict) else getattr(v, key, None)
    return not (bool(g("is_constant")) or bool(g("is_immutable")))


def normalize_layout(state_vars: list[Any]) -> list[dict]:
    """Normalize raw state-var dicts/rows → an ordered ``[{slot, name, type}]`` layout.

    Storage-occupying vars only (constants/immutables dropped), in declaration order.
    Uses an explicit ``slot`` when every storage var has one; otherwise falls back to
    the declaration ordinal (the order the analyzer returned them) so the diff still
    catches reorders/insertions/retypes even when slots were not resolved at index time.
    """
    storage = [v for v in (state_vars or []) if _is_storage_var(v)]

    def g(v: Any, key: str) -> Any:
        return v.get(key) if isinstance(v, dict) else getattr(v, key, None)

    have_slots = bool(storage) and all(g(v, "slot") is not None for v in storage)
    out: list[dict] = []
    for i, v in enumerate(storage):
        slot = int(g(v, "slot")) if have_slots else i
        out.append({"slot": slot, "name": g(v, "name") or "?",
                    "type": (str(g(v, "type")) if g(v, "type") is not None else "")})
    out.sort(key=lambda e: e["slot"])
    return out


def storage_layout_collisions(old: list[dict], new: list[dict]) -> list[dict]:
    """Compare two normalized layouts; return the upgrade-UNSAFE differences.

    Each collision is ``{slot, kind, old, new, detail}`` where ``kind`` is one of:
      * ``reassigned`` — a different variable now occupies a slot the old layout used
        (insert/reorder/replace) — the new code reads/writes the wrong field;
      * ``retyped`` — same variable name, different type at the same slot — width/packing
        change reinterprets the stored bytes;
      * ``removed`` — a slot the old layout used is gone in the new layout, shifting
        everything after it (only flagged when not already caught as ``reassigned``).
    Append-only growth (new slots beyond the old high-water mark) is SAFE → not reported.
    """
    by_slot_old = {e["slot"]: e for e in old}
    by_slot_new = {e["slot"]: e for e in new}
    collisions: list[dict] = []
    for slot in sorted(by_slot_old):
        o = by_slot_old[slot]
        n = by_slot_new.get(slot)
        if n is None:
            collisions.append({
                "slot": slot, "kind": "removed", "old": o, "new": None,
                "detail": f"slot {slot} ({o['name']}) removed — shifts all later slots"})
        elif n["name"] != o["name"]:
            collisions.append({
                "slot": slot, "kind": "reassigned", "old": o, "new": n,
                "detail": f"slot {slot}: '{o['name']}' ({o['type']}) → '{n['name']}' "
                          f"({n['type']}) — new code reads/writes the wrong field"})
        elif n["type"] != o["type"]:
            collisions.append({
                "slot": slot, "kind": "retyped", "old": o, "new": n,
                "detail": f"slot {slot} '{o['name']}': type {o['type']} → {n['type']} "
                          "— stored bytes reinterpreted"})
    return collisions


def diff_contract_storage(old_vars: list[Any], new_vars: list[Any]) -> dict:
    """Convenience: normalize two raw state-var lists and diff them. Returns
    ``{collisions, safe, old_layout, new_layout}``; ``safe`` is True iff the upgrade is
    a strict append-only extension (no collisions)."""
    old_layout = normalize_layout(old_vars)
    new_layout = normalize_layout(new_vars)
    collisions = storage_layout_collisions(old_layout, new_layout)
    return {"collisions": collisions, "safe": not collisions,
            "old_layout": old_layout, "new_layout": new_layout}
