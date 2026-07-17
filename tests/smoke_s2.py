"""S2 self-test: validate a Recon checkpoint (run after `scan --stop-after s2`).

Usage:  python tests/smoke_s2.py runs/<run_id>/checkpoints/s2.json
Defaults to the most recent run's s2 checkpoint.

Checks the exit criterion: a ReconProfile with architecture_md, ranked HotZones,
a HunterTask[] queue, and an InvariantSuite whose invariants bind to real
file:symbol hooks from the S1 index — plus the recall check (PRICE-01/PRICE-02 +
EXEC-01, the 2025-hack class) graded against tools_poc/invariants.md §10.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def _latest() -> Path:
    # This self-test grades GMX recall (PRICE-01/PRICE-02/EXEC-01), so prefer the
    # canonical GMX fixture; only glob-fall-back if it's absent (so an unrelated run
    # dir — beefy/woofi/etc. — can't shadow it).
    for pref in ("test-merged", "gmx-opus2", "gmx-opus"):
        cand = Path("runs") / pref / "checkpoints" / "s2.json"
        if cand.exists():
            return cand
    cands = sorted(Path("runs").glob("*/checkpoints/s2.json"))
    if not cands:
        raise SystemExit("no s2.json checkpoint found under runs/*/checkpoints/")
    return cands[-1]


def main() -> int:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else _latest()
    print(f"== s2 checkpoint: {path} ==")
    ck = json.loads(path.read_text())
    assert ck.get("status") == "ok", f"stage status not ok: {ck.get('status')}"

    profile = ck["recon_profile"]
    suite = profile["invariant_suite"]
    tasks = ck["hunter_tasks"]
    recall = ck["recall_grade"]

    # 1. ReconProfile shape
    assert profile.get("architecture_md"), "empty architecture_md"
    hz = profile["high_impact_areas"]
    assert hz, "no HotZones"
    assert all("rank" in z for z in hz), "HotZones missing rank"
    print(f"## architecture_md: {len(profile['architecture_md'])} chars")
    print(f"## contract_types: {profile['contract_types']}")
    print(f"## HotZones ({len(hz)}):")
    for z in sorted(hz, key=lambda z: z["rank"])[:6]:
        print(f"    [{z['rank']}] {z['title']} :: {', '.join(z['contracts'][:3])}")

    # 2. HunterTask queue
    assert tasks, "empty HunterTask queue"
    inv_tasks = [t for t in tasks if t.get("inv_id")]
    print(f"## HunterTasks: {len(tasks)} ({len(inv_tasks)} invariant-driven)")
    for t in tasks[:6]:
        print(f"    P{t['priority']} {t['vuln_class']}: {t['title'][:70]}")

    # 3. InvariantSuite binds to real S1 file:symbol hooks
    invs = suite["invariants"]
    cov = suite["coverage_map"]
    assert invs, "no invariants"
    bound_invs = [i for i in invs if cov.get(i["inv_id"], {}).get("bound", 0) > 0]
    assert bound_invs, "no invariant bound to a real S1 hook"
    # at least one hook resolved to an actual indexed file
    any_file = any(
        h.get("resolved") and h.get("file")
        for c in cov.values() for h in c.get("hooks", [])
    )
    assert any_file, "no hook resolved to an indexed file:line"
    print(f"## Invariants: {len(invs)} ({len(bound_invs)} bound to real hooks)")
    for i in invs[:8]:
        c = cov.get(i["inv_id"], {})
        print(f"    {i['inv_id']} [{i['category']}/{i['severity']}] "
              f"bound {c.get('bound', 0)}/{c.get('total', 0)} :: {i['hooks'][:2]}")

    # 4. Recall check — the 2025-hack regression class (invariants.md §10)
    print(f"## RECALL {recall['score']} (passed={recall['passed']}):")
    for tid, r in recall["targets"].items():
        mark = "HIT " if r["matched"] else "MISS"
        print(f"    [{mark}] {tid} {r['desc']} -> {r['inv_id']}")
    assert recall["passed"], (
        f"recall FAILED ({recall['score']}): the suite must surface PRICE-01/PRICE-02 "
        "+ EXEC-01 (the 2025-hack class)"
    )

    # 5. Artifact DB — the agents persisted their output to chainreaper.db via the
    #    save-scripts; assert it exists and agrees with the checkpoint.
    import sqlite3
    adb = ck.get("artifact_db")
    assert adb and Path(adb).exists(), f"artifact db (chainreaper.db) missing: {adb}"
    run_id = path.parent.parent.name
    conn = sqlite3.connect(adb)
    n = lambda t: conn.execute(  # noqa: E731
        f"SELECT COUNT(*) FROM {t} WHERE run_id=?", (run_id,)).fetchone()[0]
    db_profile, db_tasks, db_invs, db_actions = (
        n("recon_profile"), n("hunter_tasks"), n("invariants"), n("agent_actions"))
    conn.close()
    print(f"## chainreaper.db: profile={db_profile} tasks={db_tasks} "
          f"invariants={db_invs} agent_actions={db_actions}")
    assert db_profile >= 1, "no recon_profile row in chainreaper.db"
    assert db_invs == len(invs), f"db invariants {db_invs} != checkpoint {len(invs)}"
    assert db_tasks == len(tasks), f"db tasks {db_tasks} != checkpoint {len(tasks)}"
    assert db_actions >= 2, "expected agent_actions audit rows for the save-scripts"

    print("\nsmoke_s2: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
