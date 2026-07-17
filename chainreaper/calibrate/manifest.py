"""Harness-rediscovery wiring for calibration (T3.2).

The ground-truth replay proves the hack reproduces; the real measurement is
whether the harness *rediscovers* it. That reuses the normal pipeline — point
``chainreaper scan`` at the victim with the fork pinned to the pre-hack block —
so this module just produces the config overlay + scores the resulting findings
against the case's known vuln-class oracle. The billed S2/S4 stages are NOT run
here (gated, per the roadmap: build + smoke with stubs before any token spend).
"""

from __future__ import annotations

from .cases import ReplayCase


def rediscovery_overlay(case: ReplayCase, rpc_urls: dict | None = None) -> dict:
    """A ``chainreaper scan --config`` overlay that pins S4's fork to the case's
    pre-hack block on the victim's (rediscovery) chain, so a hunter sees the exact
    pre-exploit state. The chain is ``case.redisc_chain`` (which resolves to a
    ``<CHAIN>_RPC_URL`` env var, e.g. ``ethereum`` → ``ETHEREUM_RPC_URL``); if no URL
    is passed in, the plan reads it from the environment at run time."""
    import os
    chain = case.redisc_chain
    urls = dict(rpc_urls or {})
    if chain not in urls:
        env_url = os.environ.get(f"{chain.upper()}_RPC_URL")
        if env_url:
            urls[chain] = env_url
    fork: dict = {"rpc_urls": urls, "shared_anvil": True}
    if case.block is not None:
        fork["block"] = {chain: case.block}
    return {
        "hunt": {"fork": fork},
        # calibration provenance (read back by the scorer; harmless to the pipeline)
        "calibration": {
            "case_id": case.id, "chain": chain, "block": case.block,
            "victims": case.victims, "expected_vuln_classes": case.vuln_classes,
            "root_cause_contract": case.root_cause_contract,
            "root_cause_functions": case.root_cause_functions,
        },
    }


def _finding_blob(f: dict) -> str:
    """All the textual location evidence of a finding, lowercased — locations
    (contract/symbol/file), source_ref, sink_ref, title."""
    parts = [str(f.get("source_ref", "")), str(f.get("sink_ref", "")),
             str(f.get("title", "")), str(f.get("description", ""))]
    for loc in f.get("locations", []) or []:
        if isinstance(loc, dict):
            parts += [str(loc.get("contract", "")), str(loc.get("symbol", "")),
                      str(loc.get("file", ""))]
        else:
            parts.append(str(loc))
    return " ".join(parts).lower()


def _finding_symbols(f: dict) -> set[str]:
    """Function/symbol names a finding points at (locations[].symbol)."""
    out: set[str] = set()
    for loc in f.get("locations", []) or []:
        if isinstance(loc, dict) and loc.get("symbol"):
            # symbol may be "Contract.fn" or "fn(uint256)" — keep the bare name too
            sym = str(loc["symbol"])
            out.add(sym.lower())
            out.add(sym.split("(")[0].split(".")[-1].lower())
    return out


def score_rediscovery(case: ReplayCase, findings: list[dict]) -> dict:
    """Did the harness REDISCOVER this attacker-triggerable, in-scope hack?

    This is the task-0 measurement (stricter than :func:`score_findings`): a case is
    ``rediscovered`` only when a finding is (a) classed ``attacker_reachable`` — the
    payable, no-external-condition set per the adversary model — AND (b) lands on the
    known root-cause contract, ideally the exact function. Contract-only matches are
    reported as ``partial`` (right area, wrong/imprecise function). vuln-class overlap
    is carried as corroboration but is NOT required (the root cause is the oracle).
    """
    want_class = (case.expected_trigger_class or "attacker_reachable").lower()
    rc_contract = (case.root_cause_contract or "").lower()
    rc_fns = {fn.lower() for fn in case.root_cause_functions}
    expected_vc = {c.lower() for c in case.vuln_classes}

    strong: list[dict] = []   # attacker_reachable + contract + function
    partial: list[dict] = []  # attacker_reachable + contract, function imprecise
    reachable_any: list[dict] = []  # any attacker_reachable finding (context)
    for f in findings or []:
        tc = str(f.get("trigger_class", "")).lower()
        is_reachable = tc == want_class
        if is_reachable:
            reachable_any.append({"finding_id": f.get("finding_id"),
                                  "vuln_class": str(f.get("vuln_class", "")).lower()})
        if not is_reachable:
            continue
        blob = _finding_blob(f)
        syms = _finding_symbols(f)
        contract_hit = bool(rc_contract) and rc_contract in blob
        fn_hit = bool(rc_fns) and (bool(rc_fns & syms) or any(fn in blob for fn in rc_fns))
        rec = {"finding_id": f.get("finding_id"),
               "vuln_class": str(f.get("vuln_class", "")).lower(),
               "trigger_class": tc, "contract_hit": contract_hit, "fn_hit": fn_hit,
               "vuln_class_match": str(f.get("vuln_class", "")).lower() in expected_vc}
        if contract_hit and fn_hit:
            strong.append(rec)
        elif contract_hit or (fn_hit and not rc_contract):
            partial.append(rec)

    return {
        "case_id": case.id,
        "rediscovered": bool(strong),
        "partial": bool(partial) and not strong,
        "match_level": "strong" if strong else ("partial" if partial else "none"),
        "expected_trigger_class": want_class,
        "root_cause": f"{case.root_cause_contract}.{'/'.join(case.root_cause_functions)}",
        "n_findings": len(findings or []),
        "n_attacker_reachable": len(reachable_any),
        "strong_hits": strong,
        "partial_hits": partial,
    }


def score_findings(case: ReplayCase, findings: list[dict]) -> dict:
    """Did the harness rediscover the hack? A HIT = a finding whose ``vuln_class``
    matches one of the case's known classes (the oracle). Victim-address overlap is
    reported as corroborating evidence when the finding carries locations."""
    expected = {c.lower() for c in case.vuln_classes}
    victims = {v.lower() for v in case.victims}
    hits: list[dict] = []
    for f in findings or []:
        vc = str(f.get("vuln_class", "")).lower()
        if vc in expected:
            touches_victim = False
            if victims:
                blob = str(f.get("locations", "")) + str(f.get("sink_ref", "")) \
                    + str(f.get("source_ref", ""))
                touches_victim = any(v in blob.lower() for v in victims)
            hits.append({"finding_id": f.get("finding_id"), "vuln_class": vc,
                         "touches_victim": touches_victim})
    return {
        "case_id": case.id,
        "rediscovered": bool(hits),
        "expected_vuln_classes": sorted(expected),
        "n_findings": len(findings or []),
        "hits": hits,
    }
