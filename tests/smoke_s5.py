"""S5 Validate (Critic) self-test (offline / ZERO token spend) — T3.1.

Exercises the deterministic S5 plumbing against the ``runs/bench-vault`` fixture
(the KNOWN TRUE POSITIVE: V-01 first-depositor inflation, critical, PoC succeeded) —
no Critic session is spawned, so no tokens are spent. Asserts:

  * the Verdict contract validates + coerces (verdict_confidence/cvss/severity);
  * the Critic spec/prompt composes with the finding-under-review block (PoC files +
    run_cmd inlined so the critic can re-run it), carries the sandbox TOOLS + the
    REQUIRED verdict obligation, and runs in hunt mode (sandbox to re-run PoCs);
  * `critic-create-verdict` validates, persists, and round-trips a Verdict through
    the store, and the Stop hook enforces the verdict obligation;
  * the hunt guard permits `critic-create-verdict`;
  * `votes_for` escalates high-severity findings to the N-vote panel, and
    `aggregate_verdicts` folds votes correctly (majority TP→TRUE_POSITIVE,
    majority FP→FALSE_POSITIVE, mixed→NEEDS_LIVE_PROOF);
  * `s5_validate.run` executes end-to-end with `validate.max_findings: 0` →
    JSON-serializable checkpoint, backend constructs, ZERO tokens.

Usage:  python tests/smoke_s5.py [runs/<run_id>]
Defaults to runs/bench-vault.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

from chainreaper.agents.emitters import create_record
from chainreaper.agents.hooks import decide_guard, decide_stop
from chainreaper.agents.spec import HUNT_BASH_TOOLS, critic_emitters
from chainreaper.models import ReconProfile, Verdict
from chainreaper.recon.store import ReconStore
from chainreaper.stages.s5_validate import (
    aggregate_verdicts,
    build_critic_spec,
    run as s5_run,
    votes_for,
)

RUN = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("runs/bench-vault")


class _Ctx:
    def __init__(self, run_dir: Path, state: dict, config: dict):
        self.run_id = run_dir.name
        self.run_dir = run_dir
        self.state = state
        self.config = config

    @property
    def index_dir(self) -> Path:
        return self.run_dir / "index"

    @property
    def target(self):
        from chainreaper.models import Target
        s0 = self.state.get("s0")
        return Target.model_validate(s0["target"]) if s0 and s0.get("target") else None


def _decision(out: str) -> str | None:
    return json.loads(out).get("hookSpecificOutput", {}).get("permissionDecision") if out else None


def _verdict(fid: str, v: str, conf: int = 8, sev: str = "critical", refut: str | None = None) -> dict:
    return {"finding_id": fid, "verdict": v, "verdict_confidence": conf,
            "adjusted_severity": sev, "reasoning": "r", "refutation": refut}


def main() -> int:
    print(f"smoke_s5: S5 Validate (Critic, T3.1) · fixture={RUN}")
    ckpt = RUN / "checkpoints"
    state = {st: json.loads((ckpt / f"{st}.json").read_text())
             for st in ("s0", "s1", "s2", "s3", "s4") if (ckpt / f"{st}.json").exists()}
    assert state.get("s4", {}).get("findings"), "fixture has no S4 findings to validate"
    finding = state["s4"]["findings"][0]
    fid = finding["finding_id"]
    print(f"  fixture finding: {fid} ({finding.get('severity_claim')}, "
          f"poc.succeeded={(finding.get('poc') or {}).get('succeeded')})")

    # 1. Verdict validates + coerces
    v = Verdict.model_validate({"finding_id": fid, "verdict": "TRUE_POSITIVE",
                               "verdict_confidence": "9", "adjusted_severity": "High",
                               "cvss_score": "8.5", "reasoning": "ok"})
    assert v.verdict_confidence == 9 and v.adjusted_severity.value == "high" and v.cvss_score == 8.5
    print("  [OK ] Verdict validates + coerces (confidence/severity/cvss)")

    # 2. critic spec/prompt composes with the finding under review
    profile = ReconProfile.model_validate(state["s2"]["recon_profile"])
    from chainreaper.runtime.exec import Sandbox
    spec = build_critic_spec(finding, profile, target=None, repo_ref="bench",
                             repo_root=str(RUN), sandbox_tools_doc=Sandbox(RUN).tools_doc(),
                             vote_index=2, votes_total=3)
    assert spec.mode == "hunt" and spec.role == "critic"
    assert "critic-create-verdict" in spec.required_spec()
    sp = spec.system_prompt
    assert "FINDING UNDER REVIEW" in sp and fid in sp and "critic 2 of 3" in sp
    assert "REFUTE" in sp and "run_cmd" in sp, "critic prompt missing refute mandate / PoC"
    print("  [OK ] critic spec composes (finding+PoC under review, refute mandate, hunt mode)")

    # 3. emitter round-trip + Stop-hook obligation + guard
    with tempfile.TemporaryDirectory() as d:
        db = str(Path(d) / "chainreaper.db")
        ReconStore(db).close()
        res = create_record("critic-create-verdict",
                            json.dumps(_verdict(fid, "TRUE_POSITIVE")),
                            db=db, run_id="r", agent="critic-x", session="s")
        assert res["ok"] and res["count"] == 1, res
        store = ReconStore(db)
        try:
            got = store.get_verdicts("r")
            assert len(got) == 1 and got[0]["finding_id"] == fid, got
            env = {"CHAINREAPER_RUN_ID": "r", "CHAINREAPER_AGENT": "critic-y",
                   "CHAINREAPER_SESSION": "s2", "CHAINREAPER_REQUIRED": "critic-create-verdict:1"}
            code, out = decide_stop(env, store)
            assert code == 0 and json.loads(out).get("decision") == "block", "Stop must block before verdict"
            create_record("critic-create-verdict", json.dumps(_verdict(fid, "FALSE_POSITIVE")),
                          db=db, run_id="r", agent="critic-y", session="s2")
            assert decide_stop(env, store) == (0, ""), "Stop must allow once verdict saved"
        finally:
            store.close()
    print("  [OK ] critic-create-verdict round-trips + Stop hook enforces the obligation")

    genv = {"CHAINREAPER_MODE": "hunt", "CHAINREAPER_ALLOWED_TOOLS": ",".join(HUNT_BASH_TOOLS),
            "CHAINREAPER_ALLOWED_BASH": ",".join(["code-index"] + [e.command for e in critic_emitters()]),
            "CHAINREAPER_SCRATCH": "/tmp"}
    _, out = decide_guard({"tool_name": "Bash",
                           "tool_input": {"command": "chainreaper critic-create-verdict --in v.json"}}, genv)
    assert _decision(out) == "allow", "guard must permit critic-create-verdict"
    print("  [OK ] hunt guard permits critic-create-verdict")

    # 4. votes_for + aggregation
    assert votes_for({"severity_claim": "critical"}, 1, 3) == 3
    assert votes_for({"severity_claim": "low"}, 1, 3) == 1
    tp3 = aggregate_verdicts(finding, [_verdict(fid, "TRUE_POSITIVE"), _verdict(fid, "TRUE_POSITIVE"),
                                       _verdict(fid, "FALSE_POSITIVE", refut="upstream guard")])
    assert tp3["final_verdict"] == "TRUE_POSITIVE", tp3
    fp3 = aggregate_verdicts(finding, [_verdict(fid, "FALSE_POSITIVE", refut="g"),
                                       _verdict(fid, "FALSE_POSITIVE", refut="h"),
                                       _verdict(fid, "TRUE_POSITIVE")])
    assert fp3["final_verdict"] == "FALSE_POSITIVE" and fp3["refutation"], fp3
    mixed = aggregate_verdicts(finding, [_verdict(fid, "TRUE_POSITIVE"),
                                         _verdict(fid, "FALSE_POSITIVE", refut="x"),
                                         _verdict(fid, "NEEDS_LIVE_PROOF")])
    assert mixed["final_verdict"] == "NEEDS_LIVE_PROOF", mixed
    none = aggregate_verdicts(finding, [])
    assert none["final_verdict"] == "NEEDS_LIVE_PROOF" and none["n_critics"] == 0
    print("  [OK ] votes_for escalates high-sev + aggregate_verdicts folds the N-vote panel")

    # 5. s5_validate.run end-to-end with max_findings=0 (no critics, zero tokens)
    cfg = json.loads(json.dumps({  # minimal config; backend constructs but is never called
        "validate": {"max_findings": 0, "concurrency": 1, "fork": {}},
        "runtime": {"exec_backend": "host"},
        "backend": {"provider": "claude_cli"},
        "models": {"critic": {"id": "claude-opus-4-8", "effort": "high"}},
    }))
    ctx = _Ctx(RUN, state, cfg)
    out = s5_run(ctx)
    assert out["status"] == "ok" and out["counts"]["critics"] == 0, out
    json.dumps(out)  # must be JSON-serializable
    print("  [OK ] s5_validate.run executes with max_findings=0 (0 critics, JSON-serializable)")

    print("smoke_s5: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
