"""Dynamic on-fork reachability fallback (task 1B).

Static edge resolution (task 1A, ``index/build._dispatch_targets``) recovers most
interface/proxy/library edges, but some entrypoints stay dark on heavily modular or
assembly-dispatched targets (Aave-v4-style Hub/Spoke, diamond proxies, router
byte-selector dispatch) where the concrete target isn't recoverable from source
alone. For a task still marked unreachable after 1A, this optional step establishes
GROUND-TRUTH reachability on the fork: it probes each deployed public entrypoint /
router / position-manager and records — via a transaction trace — which in-scope
functions actually execute, then feeds the resolved call sequence back into the
dossier so the hunter gets a concrete entrypoint→target path instead of "trace
manually".

Gated behind config ``recon.dynamic_reachability`` (default OFF — it costs fork
calls). The trace itself is an INJECTED seam (``Tracer``) so the orchestration
unit-tests offline; the default tracer is best-effort and degrades to a no-op when
no fork / no deployed-address map is available (never raises).
"""

from __future__ import annotations

from typing import Callable

from ..runtime.logging import get_logger

log = get_logger()

# (rpc_url, from_addr, to_addr, signature) -> list of (contract, function) that
# executed, in call order. Injected in tests; the default is best-effort.
Tracer = Callable[[str, str, str, str], "list[tuple[str, str]]"]

# One probe of a deployed entrypoint: the address to call + the human signature (the
# tracer derives calldata; a bare-selector call is enough — we only want the executed
# dispatch trace, even if arg-decoding reverts).
Probe = dict  # {"contract": str, "function": str, "address": str, "signature": str}


def augment_reachability_dynamic(
    dossiers: dict, probes: list[Probe], *, rpc_url: str | None,
    tracer: Tracer, from_addr: str = "0x000000000000000000000000000000000000dEaD",
    max_probes: int = 40,
) -> int:
    """For each dossier with NO static reachable entrypoint, consult the fork trace of
    the deployed entrypoints and, if any probe's execution touched one of the dossier's
    target functions, record that probe as a resolved entrypoint (with the traced
    call sequence as the path). Mutates ``dossiers`` in place; returns the number of
    dossiers newly given a reachable entrypoint. A no-op (returns 0) when there is no
    fork url or no probes — the caller stays on the static result."""
    if not rpc_url or not probes:
        return 0

    # trace each probe once (cache); map executed (contract, fn) -> [probes reaching it]
    reached_by_target: dict[tuple[str, str], list[dict]] = {}
    for pr in probes[:max_probes]:
        addr, sig = pr.get("address"), pr.get("signature", "")
        if not addr:
            continue
        try:
            trace = tracer(rpc_url, from_addr, addr, sig) or []
        except Exception as exc:  # best-effort — a failing probe never sinks the step
            log.info("[s2] dynamic-reach probe %s failed: %s", pr.get("function"), exc)
            continue
        seq = " → ".join(f"{c}.{f}" for c, f in trace)
        for (c, f) in trace:
            reached_by_target.setdefault((c, f), []).append(
                {"contract": pr.get("contract"), "name": pr.get("function"),
                 "address": addr, "path": seq or f"{pr.get('contract')}.{pr.get('function')}"})

    newly = 0
    for d in dossiers.values():
        if getattr(d, "reachable_entrypoints", None):
            continue  # already reachable statically
        targets = [(t.get("contract"), t.get("name"))
                   for t in (getattr(d, "target_functions", None) or [])]
        eps: list[dict] = []
        seen: set[str] = set()
        for key in targets:
            for ep in reached_by_target.get(key, []):
                k = f"{ep['contract']}.{ep['name']}"
                if k not in seen:
                    seen.add(k)
                    eps.append({"contract": ep["contract"], "name": ep["name"],
                                "signature": None, "file": None, "line_start": None,
                                "modifiers": [], "path": ep["path"] + "  [fork-traced]"})
        if eps:
            d.reachable_entrypoints = eps[:10]
            d.reach_note = ("resolved on-fork: deployed entrypoint(s) whose trace "
                            "reaches this target (dynamic reachability)")
            newly += 1
    if newly:
        log.info("[s2] dynamic reachability: resolved %d previously-dark task(s) "
                 "via fork trace", newly)
    return newly


def entrypoint_probes_from_dossiers(dossiers: dict, deployed: dict[str, str],
                                    max_out: int = 40) -> list[Probe]:
    """Build the probe set: every distinct entrypoint the dossiers already know about
    that has a DEPLOYED address in ``deployed`` (contract-name → address). The probe
    carries the human signature; the tracer derives calldata (a bare-selector call is
    enough to trace the dispatch path — it may revert on arg decoding, which the
    tracer still captures)."""
    probes: list[Probe] = []
    seen: set[str] = set()
    for d in dossiers.values():
        for ep in (getattr(d, "reachable_entrypoints", None) or []) + \
                  (getattr(d, "target_functions", None) or []):
            c, n, sig = ep.get("contract"), ep.get("name"), ep.get("signature")
            addr = deployed.get(c) if c else None
            key = f"{c}.{n}"
            if not addr or key in seen or not sig:
                continue
            seen.add(key)
            probes.append({"contract": c, "function": n, "address": addr,
                           "signature": sig})
            if len(probes) >= max_out:
                return probes
    return probes


def default_tracer(rpc_url: str, from_addr: str, to_addr: str,
                   signature: str) -> list[tuple[str, str]]:
    """Best-effort fork tracer: derive a bare-selector calldata from the human
    signature via ``cast sig`` and ``cast call … --trace``, then parse the executed
    frames. Returns [] on any failure (no cast, revert with no trace, etc.) so the
    caller degrades to the static result. Kept intentionally simple — the real signal
    is the injected tracer in a live wiring; this is the graceful default."""
    import json
    import shutil
    import subprocess

    from ..runtime.exec import augmented_env
    env = augmented_env()
    cast = shutil.which("cast", path=env.get("PATH", ""))
    if not cast:
        return []
    try:
        sel = subprocess.run([cast, "sig", signature], capture_output=True, text=True,
                             timeout=20, env=env)
        calldata = (sel.stdout or "").strip()
        if not calldata.startswith("0x"):
            return []
        # `cast call --trace` emits a call tree; use a JSON trace when available.
        p = subprocess.run(
            [cast, "call", to_addr, "--from", from_addr, "--data", calldata,
             "--rpc-url", rpc_url, "--trace", "--json"],
            capture_output=True, text=True, timeout=60, env=env)
    except Exception:
        return []
    out = (p.stdout or "").strip()
    if not out:
        return []
    try:
        data = json.loads(out)
    except Exception:
        return []
    # The exact JSON shape depends on the foundry version; extract (contract, fn) frames
    # defensively. Anything unrecognized → [] (degrade, don't guess).
    frames: list[tuple[str, str]] = []
    def _walk(node):
        if isinstance(node, dict):
            c = node.get("contract") or node.get("label")
            f = node.get("function") or node.get("method") or node.get("selector")
            if c and f:
                frames.append((str(c), str(f)))
            for v in node.values():
                _walk(v)
        elif isinstance(node, list):
            for v in node:
                _walk(v)
    _walk(data)
    return frames
