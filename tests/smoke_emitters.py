"""Offline self-test for the S2 save-scripts + hooks (NO model tokens).

Exercises the three new pieces end-to-end against a temp chainreaper.db:
  1. ``agents.emitters.create_record`` — schema validation + insert + audit row,
     for profile/task/invariant, including batching, malformed JSON, and the
     single-object rule for the profile.
  2. ``agents.hooks.decide_guard`` — the PreToolUse scope guard.
  3. ``agents.hooks.decide_stop`` — the Stop output-obligation + loop guard.

Usage:  python tests/smoke_emitters.py
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from chainreaper.agents.emitters import EmitError, create_record
from chainreaper.agents.hooks import decide_guard, decide_stop
from chainreaper.recon.store import ReconStore


def _ok(label: str) -> None:
    print(f"  ok: {label}")


def _decision(out: str) -> str | None:
    """The PreToolUse permissionDecision ('allow'/'deny') in a guard result, if any."""
    if not out:
        return None
    return json.loads(out).get("hookSpecificOutput", {}).get("permissionDecision")


def test_emitters(db: str) -> None:
    print("== emitters ==")
    profile = {
        "architecture_md": "A vault routes deposits through a handler into a pool; "
                           "keepers execute with signed oracle prices.",
        "contract_types": ["vault", "perp-dex"],
        "trust_boundaries": [{"name": "wallet↔router", "description": "user funds in"}],
        "privileged_roles": [{"name": "keeper", "description": "executes orders"}],
        "high_impact_areas": [{"rank": 1, "title": "share-price accounting",
                               "contracts": ["MarketUtils"], "functions": ["MarketUtils.getMarketTokenPrice"]}],
        "threat_model": {"summary": "s", "entries": [
            {"asset": "pool value", "threat": "reentrant re-read", "gap": "no mid-tx guard"}]},
    }
    res = create_record("recon-create-profile", json.dumps(profile),
                        db=db, run_id="r", agent="recon", session="s1")
    assert res["count"] == 1 and res["table"] == "recon_profile", res
    _ok("profile inserted")

    tasks = [
        {"task_id": "t1", "title": "Break share price", "vuln_class": "reentrancy",
         "scope_hint": "MarketUtils.getMarketTokenPrice", "hypothesis": "reentrant re-read"},
        {"task_id": "t2", "title": "Oracle staleness", "vuln_class": "price_oracle_manipulation",
         "scope_hint": "Oracle.validatePrices", "hypothesis": "stale price accepted"},
    ]
    res = create_record("recon-create-task", json.dumps(tasks),
                        db=db, run_id="r", agent="recon", session="s1")
    assert res["count"] == 2, res
    _ok("2 tasks inserted (batched array)")

    invs = [{
        "inv_id": "PRICE-01", "category": "share_price",
        "statement": "market token price reads identically on any reentrant re-read",
        "hooks": ["MarketUtils.getMarketTokenPrice"], "severity": "critical",
        "tool": "medusa", "origin": "prior_finding",
    }]
    res = create_record("recon-create-invariant", json.dumps(invs),
                        db=db, run_id="r", agent="invariant_synth", session="s2")
    assert res["count"] == 1, res
    _ok("invariant inserted")

    # malformed JSON → EmitError
    try:
        create_record("recon-create-task", "{not json", db=db, run_id="r")
        raise AssertionError("expected EmitError for malformed JSON")
    except EmitError:
        _ok("malformed JSON rejected")

    # schema miss (task missing required fields) → EmitError carrying the schema
    try:
        create_record("recon-create-task", json.dumps([{"title": "no id"}]),
                      db=db, run_id="r")
        raise AssertionError("expected EmitError for schema miss")
    except EmitError as exc:
        assert exc.schema is not None, "schema-miss EmitError should carry the JSON schema"
        _ok("schema miss rejected (with schema)")

    # profile must be exactly one object
    try:
        create_record("recon-create-profile", json.dumps([profile, profile]),
                      db=db, run_id="r")
        raise AssertionError("expected EmitError for multi-profile")
    except EmitError:
        _ok("profile single-object rule enforced")

    store = ReconStore(db)
    try:
        assert store.count_records(run_id="r", agent="recon", session="s1",
                                   table="hunter_tasks") == 2
        assert store.count_records(run_id="r", agent="invariant_synth", session="s2",
                                   table="invariants") == 1
        # only SUCCESSFUL creates logged actions (3: profile, task-batch, invariant)
        c = store.counts("r")
        assert c["agent_actions"] == 3, c
        _ok(f"row counts + audit log correct ({c})")
    finally:
        store.close()


def test_guard() -> None:
    print("== guard (PreToolUse) ==")
    scratch = "/tmp/ch-scratch-xyz"
    env = {"CHAINREAPER_SCRATCH": scratch, "CHAINREAPER_ALLOWED_BASH": "code-index,recon-create-task"}

    def dec(tool, **inp):
        return _decision(decide_guard({"tool_name": tool, "tool_input": inp}, env)[1])

    # permitted ops must be EXPLICITLY allowed (else headless -p stalls on a prompt)
    assert dec("Read", file_path="x.sol") == "allow", "Read should be explicitly allowed"
    assert dec("Grep", pattern="x") == "allow", "Grep should be explicitly allowed"
    assert dec("Edit", file_path="x") == "deny", "Edit should be denied"
    assert dec("Task") == "deny", "Task should be denied"
    assert dec("WebFetch") == "deny", "WebFetch should be denied"
    _ok("Read/Grep explicit-allow; Edit/Task/WebFetch denied")

    assert dec("Write", file_path=f"{scratch}/profile.json") == "allow", "scratch write allowed"
    assert dec("Write", file_path="/tmp/evil.json") == "deny", "off-scratch write denied"
    _ok("Write explicit-allow scoped to scratch")

    assert dec("Bash", command="chainreaper code-index contract '{\"contract\":\"X\"}'") == "allow"
    assert dec("Bash", command="chainreaper code-index function '{\"signature\":\"foo(uint256)\"}'") == "allow"
    assert dec("Bash", command=f"chainreaper recon-create-task --in {scratch}/t.json") == "allow"
    _ok("allowed chainreaper bash (incl. JSON/sig args) explicit-allow")

    assert dec("Bash", command="rm -rf /") == "deny", "rm denied"
    assert dec("Bash", command="chainreaper code-index x; rm -rf /") == "deny", "chaining denied"
    assert dec("Bash", command="chainreaper doctor") == "deny", "non-allowed subcommand denied"
    _ok("rm / chaining / off-list subcommand denied")


def test_stop(db: str) -> None:
    print("== stop (output obligation + loop guard) ==")
    store = ReconStore(db)
    try:
        # fresh session s3 requiring 2 tasks, none yet → block
        env = {"CHAINREAPER_RUN_ID": "r2", "CHAINREAPER_AGENT": "recon",
               "CHAINREAPER_SESSION": "s3", "CHAINREAPER_REQUIRED": "recon-create-task:2",
               "CHAINREAPER_MAX_STOP_BLOCKS": "5"}
        code, out = decide_stop(env, store)
        assert code == 0 and json.loads(out).get("decision") == "block", (code, out)
        _ok("blocks when required tasks missing")

        # satisfy the requirement → allow
        for tid in ("a", "b"):
            store.add_task(run_id="r2", agent="recon", session="s3",
                           task={"task_id": tid, "title": tid, "vuln_class": "reentrancy",
                                 "scope_hint": "x", "hypothesis": "y"})
        assert decide_stop(env, store) == (0, ""), "should allow once satisfied"
        _ok("allows once requirement met")

        # loop guard: unmet requirement, max 2 blocks → 3rd call allows (systemMessage)
        env2 = {"CHAINREAPER_RUN_ID": "r3", "CHAINREAPER_AGENT": "invariant_synth",
                "CHAINREAPER_SESSION": "s4", "CHAINREAPER_REQUIRED": "recon-create-invariant:5",
                "CHAINREAPER_MAX_STOP_BLOCKS": "2"}
        d1 = json.loads(decide_stop(env2, store)[1])
        d2 = json.loads(decide_stop(env2, store)[1])
        c3, o3 = decide_stop(env2, store)
        assert d1.get("decision") == "block" and d2.get("decision") == "block"
        assert c3 == 0 and "decision" not in json.loads(o3), "3rd call should stop blocking"
        assert "systemMessage" in json.loads(o3)
        _ok("loop guard releases after max_stop_blocks")
    finally:
        store.close()


def main() -> int:
    with tempfile.TemporaryDirectory() as d:
        db = str(Path(d) / "chainreaper.db")
        ReconStore(db).create_schema()
        test_emitters(db)
        test_guard()
        test_stop(db)
    print("\nsmoke_emitters: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
