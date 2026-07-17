"""Governance / malicious-admin / upgrade-time self-test (Tier-4 P4, offline / ZERO tokens).

Asserts the two P4 blind-spot closers:
  1. the ``index/storagediff`` storage-layout-diff helper detects upgrade-UNSAFE
     deltas (reorder / retype / remove) across two implementations, and passes a
     strict append-only extension as SAFE — including the constant/immutable drop and
     the declaration-order fallback when explicit slots are absent;
  2. the malicious-admin (``malicious_role``) + upgrade-sim (``upgrade_sim``) HunterTask
     subtypes are recognised — the recon system prompt carries the GOVERNANCE mandate,
     the hunter task block renders each subtype, and the prefilter never drops/folds them.

Usage:  python tests/smoke_governance.py
"""

from __future__ import annotations

import sys

from chainreaper.agents.factory import build_recon_system, governance_block, hunter_task_block
from chainreaper.agents.spec import recon_emitters
from chainreaper.index.storagediff import (
    diff_contract_storage,
    normalize_layout,
    storage_layout_collisions,
)
from chainreaper.models import HunterTask, VulnClass
from chainreaper.recon.prefilter import prefilter


def main() -> int:
    print("smoke_governance: governance / malicious-admin / upgrade-time (Tier-4 P4)")

    # 1a. storage-diff: a deliberate reorder collision (+ constant dropped)
    old_vars = [
        {"name": "owner", "type": "address", "slot": 0},
        {"name": "totalSupply", "type": "uint256", "slot": 1},
        {"name": "paused", "type": "bool", "slot": 2},
        {"name": "VERSION", "type": "uint256", "is_constant": True},  # not in storage
    ]
    new_vars = [  # paused & totalSupply swapped at slots 1/2 → both collide
        {"name": "owner", "type": "address", "slot": 0},
        {"name": "paused", "type": "bool", "slot": 1},
        {"name": "totalSupply", "type": "uint256", "slot": 2},
        {"name": "VERSION", "type": "uint256", "is_constant": True},
    ]
    res = diff_contract_storage(old_vars, new_vars)
    assert not res["safe"], "reorder upgrade wrongly judged safe"
    assert len(res["old_layout"]) == 3, "constant not dropped from layout"
    cols = {c["slot"]: c["kind"] for c in res["collisions"]}
    assert cols.get(1) == "reassigned" and cols.get(2) == "reassigned", cols
    print(f"  [OK ] storage-diff detects the deliberate reorder collision (slots {sorted(cols)})")

    # 1b. a type change at the same slot → retyped
    retype = storage_layout_collisions(
        normalize_layout([{"name": "bal", "type": "uint256", "slot": 0}]),
        normalize_layout([{"name": "bal", "type": "uint128", "slot": 0}]))
    assert len(retype) == 1 and retype[0]["kind"] == "retyped", retype
    # 1c. a removed slot shifts everything after it
    removed = storage_layout_collisions(
        normalize_layout([{"name": "a", "type": "uint256", "slot": 0},
                          {"name": "b", "type": "uint256", "slot": 1}]),
        normalize_layout([{"name": "a", "type": "uint256", "slot": 0}]))
    assert len(removed) == 1 and removed[0]["kind"] == "removed", removed
    # 1d. append-only extension is SAFE
    safe = diff_contract_storage(
        [{"name": "a", "type": "uint256", "slot": 0}],
        [{"name": "a", "type": "uint256", "slot": 0}, {"name": "b", "type": "address", "slot": 1}])
    assert safe["safe"] and not safe["collisions"], "append-only extension wrongly flagged"
    # 1e. declaration-order fallback when no explicit slots → reorder still caught
    noslot = storage_layout_collisions(
        normalize_layout([{"name": "a", "type": "uint256"}, {"name": "b", "type": "uint256"}]),
        normalize_layout([{"name": "b", "type": "uint256"}, {"name": "a", "type": "uint256"}]))
    assert len(noslot) == 2, f"decl-order reorder not caught: {noslot}"
    print("  [OK ] storage-diff: retype + remove flagged, append-only SAFE, no-slot decl-order works")

    # 2. recon system prompt carries the governance mandate
    sysprompt = build_recon_system(None, "demo", "TOOLS", recon_emitters(8, 12),
                                   initialized_tools=["slither"], sast={"checks": [], "top": []})
    assert "GOVERNANCE / MALICIOUS-ADMIN / UPGRADE-TIME" in sysprompt, "recon missing P4 mandate"
    assert "malicious_role" in governance_block() and "upgrade_sim" in governance_block()
    print("  [OK ] recon system prompt carries the GOVERNANCE / MALICIOUS-ADMIN / UPGRADE mandate")

    # 3. hunter renders the malicious-admin + upgrade-sim subtypes
    mtask = HunterTask(
        task_id="T-GOV-1", title="compromised owner drains via rescue",
        vuln_class=VulnClass.ACCESS_CONTROL, scope_hint="Vault.rescueTokens",
        hypothesis="a compromised owner sweeps user funds via the rescue path",
        malicious_role="owner")
    mblock = hunter_task_block(mtask, None, None, repo_root="/repo")
    assert "MALICIOUS-ADMIN task" in mblock and "compromised role: owner" in mblock, mblock
    utask = HunterTask(
        task_id="T-GOV-2", title="storage drift across VaultV2 upgrade",
        vuln_class=VulnClass.PROXY_UPGRADE, scope_hint="Vault (proxy)",
        hypothesis="V2 reorders storage → post-upgrade reads corrupt", upgrade_sim=True)
    ublock = hunter_task_block(utask, None, None, repo_root="/repo")
    assert "UPGRADE-SIMULATION task" in ublock and "STORAGE-LAYOUT DRIFT" in ublock, ublock
    print("  [OK ] hunter renders the malicious-admin + upgrade-simulation task subtypes")

    # 4. prefilter keeps governance tasks even with no resolved targets (not dropped/folded)
    def _gov_td(task_id: str, **extra) -> dict:
        return {"task_id": task_id, "title": "gov", "vuln_class": "access_control",
                "scope_hint": "Vault", "hypothesis": "x", **extra,
                "context": {"task_id": task_id, "vuln_class": "access_control",
                            "target_functions": []}}
    res = prefilter([_gov_td("T-MAL", malicious_role="owner"),
                     _gov_td("T-UPG", upgrade_sim=True)],
                    config={"max_hunt_tasks": None, "per_class_cap": None})
    by_id = res.decisions_by_id
    assert by_id["T-MAL"].decision == "scheduled", by_id["T-MAL"]
    assert by_id["T-UPG"].decision == "scheduled", by_id["T-UPG"]
    print("  [OK ] prefilter keeps malicious-admin + upgrade-sim tasks (no resolved targets)")

    print("smoke_governance: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
