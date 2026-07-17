"""Historical-hack replay calibration self-test (T3.2, offline / ZERO tokens).

Exercises the calibration plumbing with injected seams (a fake forge runner + a
fake fetcher) so it runs with no compute/network/tokens, then — best-effort, only
if forge is installed — runs the REAL vendored ground-truth replay (the MiniVault
inflation hack reproduces locally, no RPC).

Asserts:
  * the shipped registry loads + validates (incl. the self-contained synthetic
    positive control + a real DeFiHackLabs case);
  * ground_truth_replay reproduces a vendored case when its PoC passes, and reports
    NOT-REPRODUCED when it fails (injected forge runner);
  * a fork case with no <CHAIN>_RPC_URL SKIPS cleanly (reproduced=None), never
    crashes — graceful degradation;
  * the rediscovery overlay pins the fork block + carries the case oracle, and
    score_findings flags a hit when a finding matches the case's vuln-class.

Usage:  python tests/smoke_calibrate.py
"""

from __future__ import annotations

import shutil
import sys
import tempfile

from chainreaper.calibrate import (
    ground_truth_replay,
    load_registry,
    run_calibration,
    run_rediscovery,
    run_rediscovery_suite,
)
from chainreaper.calibrate.cases import ReplayCase
from chainreaper.calibrate.manifest import (
    rediscovery_overlay,
    score_findings,
    score_rediscovery,
)
from chainreaper.runtime.exec import augmented_env


def main() -> int:
    print("smoke_calibrate: historical-hack replay calibration (T3.2)")

    # 1. registry loads + validates
    cases = load_registry()
    ids = {c.id for c in cases}
    assert "minivault-inflation" in ids, "synthetic positive control missing from registry"
    vendored = [c for c in cases if c.poc_source == "vendored"]
    assert vendored, "no vendored case"
    assert any(c.poc_source == "defihacklabs" for c in cases), "no real DeFiHackLabs case"
    print(f"  [OK ] registry: {len(cases)} cases ({sorted(ids)})")

    case = next(c for c in cases if c.id == "minivault-inflation")

    # 2. reproduced=True when the (injected) forge run passes
    with tempfile.TemporaryDirectory() as d:
        r = ground_truth_replay(case, work_dir=d,
                                forge_runner=lambda ws, t, env: (0, "Suite result: ok. 1 passed"))
        assert r.ran and r.reproduced is True, r
    print("  [OK ] vendored case → REPRODUCED when PoC passes")

    # 3. reproduced=False when the forge run fails
    with tempfile.TemporaryDirectory() as d:
        r = ground_truth_replay(case, work_dir=d,
                                forge_runner=lambda ws, t, env: (1, "FAIL: assertion failed"))
        assert r.ran and r.reproduced is False, r
    print("  [OK ] vendored case → NOT-REPRODUCED when PoC fails")

    # 4. a fork case with no RPC skips cleanly (never crashes)
    fork_case = ReplayCase(id="x", name="x", chain="mainnet", block=123,
                           poc_source="url", poc_ref="http://example/x.sol", needs_fork=True)
    with tempfile.TemporaryDirectory() as d:
        r = ground_truth_replay(fork_case, work_dir=d, rpc_urls={},
                                fetcher=lambda u: "// fake",
                                forge_runner=lambda ws, t, env: (0, "should not run"))
        assert not r.ran and r.reproduced is None, r
        assert "RPC" in r.detail or "fork not ready" in r.detail, r.detail
    print("  [OK ] fork case with no RPC → SKIPPED cleanly")

    # 5. rediscovery overlay + scorer
    ov = rediscovery_overlay(case)
    assert ov["calibration"]["case_id"] == case.id
    assert ov["calibration"]["expected_vuln_classes"] == case.vuln_classes
    hit = score_findings(case, [{"finding_id": "F1", "vuln_class": case.vuln_classes[0]}])
    miss = score_findings(case, [{"finding_id": "F2", "vuln_class": "gas_griefing"}])
    assert hit["rediscovered"] and not miss["rediscovered"], (hit, miss)
    print("  [OK ] rediscovery overlay pins oracle + score_findings flags a hit")

    # 5b. TASK-0 rediscovery scorer: attacker_reachable + root-cause contract+function
    redisc = [c for c in cases if c.rediscovery]
    assert len(redisc) >= 4, f"expected the curated rediscovery cases, got {len(redisc)}"
    wl = next(c for c in redisc if c.id == "wiselending-2023-10")
    assert wl.root_cause_contract == "WiseLending" and wl.root_cause_functions
    # a correct rediscovery: attacker_reachable finding on the root cause contract+fn
    strong_f = [{"finding_id": "S1", "trigger_class": "attacker_reachable",
                 "vuln_class": "first_depositor_inflation",
                 "locations": [{"contract": "WiseLending", "symbol": "depositExactAmount"}]}]
    s = score_rediscovery(wl, strong_f)
    assert s["rediscovered"] and s["match_level"] == "strong", s
    # right area, imprecise function → partial (not a full rediscovery)
    part_f = [{"finding_id": "P1", "trigger_class": "attacker_reachable",
               "vuln_class": "reentrancy",
               "locations": [{"contract": "WiseLending", "symbol": "someOtherFn"}]}]
    sp = score_rediscovery(wl, part_f)
    assert not sp["rediscovered"] and sp["match_level"] == "partial", sp
    # external_condition finding on the root cause → NOT rediscovered (the whole point:
    # only attacker_reachable counts; mocked/privileged findings don't pay)
    ext_f = [{"finding_id": "E1", "trigger_class": "external_condition",
              "locations": [{"contract": "WiseLending", "symbol": "depositExactAmount"}]}]
    se = score_rediscovery(wl, ext_f)
    assert not se["rediscovered"] and se["match_level"] == "none", se
    # a missing trigger_class (pre-adversary-model finding) also does not count
    none_f = [{"finding_id": "N1", "vuln_class": "access_control",
               "locations": [{"contract": "WiseLending", "symbol": "depositExactAmount"}]}]
    assert not score_rediscovery(wl, none_f)["rediscovered"]
    print("  [OK ] score_rediscovery: attacker_reachable+root-cause=strong, "
          "imprecise=partial, external_condition/none=missed")

    # 5c. rediscovery RUNNER orchestration with injected seams (offline, no tokens)
    calls = {}
    def fake_materializer(contracts, ws, key, pause=0.0):
        calls["materialized"] = [c["address"] for c in contracts]
        class U:  # minimal VerifiedUnit-like
            name = "WiseLending"; dir = str(ws); compiler = "0.8.19"; addresses = []
        return [U()], []
    def fake_pipeline(case, run_dir, overlay):
        calls["overlay"] = overlay
        return run_dir.name
    def fake_store(run_dir, run_id):
        return strong_f  # the harness "found" it
    with tempfile.TemporaryDirectory() as d:
        # patch Target/verified helpers path by monkeypatching build via seams:
        # build_rediscovery_target uses the real materialize helpers, so stub those
        import chainreaper.calibrate.rediscovery as R
        orig_bt = R.build_rediscovery_target
        R.build_rediscovery_target = lambda case, run_dir, *, api_key, materializer=None, pause=0.0: (
            object(), "stub-materialized")
        try:
            res = run_rediscovery(wl, work_dir=d, api_key="k",
                                  pipeline_runner=fake_pipeline, store_reader=fake_store)
        finally:
            R.build_rediscovery_target = orig_bt
        assert res.ran and res.rediscovered and res.match_level == "strong", res
        assert res.n_attacker_reachable == 1, res
        assert "hunt" in calls["overlay"] and "fork" in calls["overlay"]["hunt"], calls
    print("  [OK ] rediscovery runner: materialize→pipeline→score wired (seams)")

    # 6. best-effort: REAL ground-truth replay of the vendored case (no RPC)
    if shutil.which("forge", path=augmented_env().get("PATH", "")):
        with tempfile.TemporaryDirectory() as d:
            report = run_calibration([case], work_dir=d)
            r = report.results[0]
            ok = r.reproduced is True
            print(f"  [{'OK ' if ok else 'WARN'}] real forge replay of {case.id}: {r.status}")
            if not ok:
                print("    " + (r.log_tail or r.detail))
                return 1
    else:
        print("  [SKIP] forge not on PATH — skipping real replay")

    print("smoke_calibrate: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
