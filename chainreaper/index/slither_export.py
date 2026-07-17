#!/usr/bin/env python3
"""Slither structural export (IMPL-NOTES §5).

Run with **Slither's own interpreter** (its pipx venv), NOT chainreaper's venv:

    SLITHER_PY="$(sed -n '1s/^#!//p' "$(command -v slither)")"
    "$SLITHER_PY" chainreaper/index/slither_export.py <target_dir> <out.json> [crytic_args...]

It builds a `Slither` object over an already-compiled project and dumps a JSON
structural model that chainreaper (its own venv) loads into the SQLite index. We
walk the SlithIR operations rather than the high-level `internal_calls` /
`high_level_calls` convenience properties because the IR is stable across the
Slither API churn (0.10 → 0.11), giving precise call types, callee signatures,
and source lines for `call_edges` and `sinks`.

Output JSON shape is documented in `build.py` (the consumer).
"""

from __future__ import annotations

import json
import sys


def _sig(func) -> str:
    """Best-effort canonical signature for a function-like object."""
    for attr in ("solidity_signature", "full_name", "name"):
        try:
            val = getattr(func, attr, None)
            if val:
                return str(val)
        except Exception:
            continue
    return "<unknown>"


def _first_line(obj) -> int | None:
    try:
        lines = obj.source_mapping.lines
        return lines[0] if lines else None
    except Exception:
        return None


def _last_line(obj) -> int | None:
    try:
        lines = obj.source_mapping.lines
        return lines[-1] if lines else None
    except Exception:
        return None


def _filename(obj) -> str | None:
    try:
        fn = obj.source_mapping.filename
        # Filename namedtuple: prefer relative/short path
        return getattr(fn, "relative", None) or getattr(fn, "short", None) or getattr(fn, "absolute", None)
    except Exception:
        return None


def _contract_kind(c) -> str:
    try:
        if c.is_interface:
            return "interface"
        if c.is_library:
            return "library"
        if getattr(c, "is_abstract", False):
            return "abstract"
    except Exception:
        pass
    return "contract"


def _patch_type_resolution() -> None:
    """Make Slither's qualified-type resolution tolerant of duplicate contract names.

    Some protocols (Fluid) name a struct/enum holder ``Structs``/``Constants``/
    ``ErrorTypes`` in *every* module (12+ contracts called ``Structs``). solc compiles
    fine (scope-correct), but Slither's ``_find_from_type_name`` resolves a qualified
    type ``Structs.RateData`` only by ``canonical_name`` ("Structs.RateData") and the
    duplicate-name interference makes the lookup miss types that genuinely exist — it
    raises ``ParsingError`` and DROPS every function that uses one (373/489 contracts
    lost all functions on Fluid). This wraps the resolver to add a last-resort fallback:
    if the canonical lookup fails, match the type's SHORT name (the part after the dot)
    across all structures/enums. Only ever ADDS a resolution where the original raised —
    never overrides a correct one. For an index (navigation) resolving to a same-named
    struct is sufficient; near-duplicate definitions are structurally equivalent."""
    try:
        import slither.solc_parsing.solidity_types.type_parsing as tp
        from slither.core.expressions.literal import Literal
        from slither.core.solidity_types.array_type import ArrayType
        from slither.core.solidity_types.user_defined_type import UserDefinedType
    except Exception:
        return
    if getattr(tp, "_cr_shortname_patched", False):
        return
    _orig = tp._find_from_type_name

    def _patched(name, *args):
        try:
            return _orig(name, *args)
        except tp.ParsingError:
            # args = (functions, contracts, structs_da, all_structs, enums_da, all_enums)
            all_structs = args[3] if len(args) > 3 else []
            all_enums = args[5] if len(args) > 5 else []
            base = str(name)
            for pre in ("struct ", "enum ", "type(enum ", "contract ", "library "):
                if base.startswith(pre):
                    base = base[len(pre):]
            base = base.rstrip(")").split(" ")[0]
            depth = 0
            while base.endswith("[]"):
                base = base[:-2]
                depth += 1
            short = base.split(".")[-1].strip()
            if not short:
                raise
            cand = next((st for st in all_structs if getattr(st, "name", None) == short), None)
            if cand is None:
                cand = next((e for e in all_enums if getattr(e, "name", None) == short), None)
            if cand is None:
                raise
            t = UserDefinedType(cand)
            return ArrayType(t, Literal(depth, "uint256")) if depth else t

    tp._find_from_type_name = _patched
    tp._cr_shortname_patched = True


def _mutability(f) -> str | None:
    try:
        if f.payable:
            return "payable"
        if f.view:
            return "view"
        if f.pure:
            return "pure"
    except Exception:
        return None
    return "nonpayable"


def _export_function(f) -> dict:
    # Import IR operation types lazily (module path stable across versions).
    from slither.slithir.operations import (
        EventCall, HighLevelCall, InternalCall, LibraryCall, LowLevelCall,
        SolidityCall,
    )
    try:
        from slither.slithir.operations import Send, Transfer
    except Exception:  # pragma: no cover
        Send = Transfer = ()  # type: ignore

    calls: list[dict] = []
    sinks: list[dict] = []

    def add_call(callee_sig, call_type, line, callee_contract=None):
        calls.append({"callee_sig": callee_sig, "call_type": call_type,
                      "line": line, "callee_contract": callee_contract})

    def add_sink(kind, detail, line):
        sinks.append({"kind": kind, "detail": detail, "line": line})

    for node in getattr(f, "nodes", []) or []:
        line = _first_line(node)
        for ir in getattr(node, "irs", []) or []:
            try:
                if isinstance(ir, LibraryCall):
                    callee = getattr(ir, "function", None)
                    cc = getattr(getattr(callee, "contract", None), "name", None)
                    add_call(_sig(callee) if callee else "<library>", "library", line, cc)
                elif isinstance(ir, HighLevelCall):
                    callee = getattr(ir, "function", None)
                    cc = getattr(getattr(callee, "contract", None), "name", None)
                    add_call(_sig(callee) if callee else "<external>", "external", line, cc)
                    add_sink("external_call", _sig(callee) if callee else None, line)
                elif isinstance(ir, InternalCall):
                    callee = getattr(ir, "function", None)
                    cc = getattr(getattr(callee, "contract", None), "name", None)
                    add_call(_sig(callee) if callee else "<internal>", "internal", line, cc)
                elif isinstance(ir, LowLevelCall):
                    name = (getattr(ir, "function_name", None) or "").lower()
                    is_delegate = "delegatecall" in name
                    ct = "delegatecall" if is_delegate else "low_level"
                    add_call(name or "<low_level>", ct, line)
                    add_sink("delegatecall" if is_delegate else "low_level_call", name, line)
                elif Transfer and isinstance(ir, Transfer):
                    add_sink("transfer", "transfer", line)
                elif Send and isinstance(ir, Send):
                    add_sink("send", "send", line)
                elif isinstance(ir, SolidityCall):
                    sname = getattr(getattr(ir, "function", None), "name", "") or ""
                    add_call(sname or "<solidity>", "solidity", line)
                    low = sname.lower()
                    if "ecrecover" in low:
                        add_sink("ecrecover", sname, line)
                    elif "selfdestruct" in low or "suicide" in low:
                        add_sink("selfdestruct", sname, line)
                elif isinstance(ir, EventCall):
                    pass
            except Exception:
                continue

    return {
        "name": f.name,
        "signature": _sig(f),
        "visibility": getattr(f, "visibility", None),
        "mutability": _mutability(f),
        "is_constructor": bool(getattr(f, "is_constructor", False)),
        "modifiers": [getattr(m, "name", str(m)) for m in (getattr(f, "modifiers", []) or [])],
        "file": _filename(f),
        "line_start": _first_line(f),
        "line_end": _last_line(f),
        "reads": [getattr(v, "name", None) for v in (getattr(f, "state_variables_read", []) or [])
                  if getattr(v, "name", None)],
        "writes": [getattr(v, "name", None) for v in (getattr(f, "state_variables_written", []) or [])
                   if getattr(v, "name", None)],
        "calls": calls,
        "sinks": sinks,
    }


def _export_contract(c) -> dict:
    funcs = []
    try:
        declared = c.functions_declared
    except Exception:
        declared = [f for f in getattr(c, "functions", []) if getattr(f, "contract_declarer", None) is c]
    for f in declared:
        try:
            funcs.append(_export_function(f))
        except Exception as exc:  # keep going; one bad function shouldn't sink the export
            funcs.append({"name": getattr(f, "name", "?"), "signature": _sig(f),
                          "error": str(exc), "calls": [], "sinks": [],
                          "reads": [], "writes": [], "modifiers": []})

    state_vars = []
    for v in getattr(c, "state_variables_declared", getattr(c, "state_variables", [])) or []:
        state_vars.append({
            "name": v.name,
            "type": str(getattr(v, "type", None)) if getattr(v, "type", None) is not None else None,
            "visibility": getattr(v, "visibility", None),
            "is_constant": bool(getattr(v, "is_constant", False)),
            "is_immutable": bool(getattr(v, "is_immutable", False)),
            "line": _first_line(v),
        })

    return {
        "name": c.name,
        "kind": _contract_kind(c),
        "file": _filename(c),
        "line": _first_line(c),
        "inheritance": [b.name for b in (getattr(c, "inheritance", []) or [])],
        "functions": funcs,
        "state_vars": state_vars,
    }


def main(target_dir: str, out_path: str, crytic_args: list[str]) -> int:
    from slither import Slither

    _patch_type_resolution()

    framework = crytic_args[0] if crytic_args else ""
    if framework == "solc-standard-json":
        # A bare verified-source unit (Etherscan export): no build config, but a known
        # solc (pinned via SOLC_VERSION by the caller). Compile every .sol in the unit as
        # one solc-standard-json input — crytic-compile's solc platform can't take a
        # directory, and there's no truffle/hardhat to drive it.
        import glob

        from crytic_compile import CryticCompile
        from crytic_compile.platform.solc_standard_json import SolcStandardJson
        def _build_sj(via_ir: bool):
            sj = SolcStandardJson()
            for f in sorted(glob.glob("**/*.sol", recursive=True)):
                sj.add_source_file(f)
            # Extra args after the framework = import remappings (euler-vault-kit/=…,
            # @openzeppelin/=…) from the verified standard-json; without them remapped
            # imports fail to resolve ("Source … not found").
            for remap in crytic_args[1:]:
                if remap:
                    sj.add_remapping(remap)
            if via_ir:
                # Large functions (e.g. Gains/Ostium TradingCallbacks) were deployed
                # with the IR pipeline + optimizer and overflow the legacy codegen's
                # stack ("Stack too deep") without it. Faithful to the deployed solc
                # settings; only used as a retry so the fast (no-IR) path stays default.
                sj._json["settings"]["optimizer"] = {"enabled": True, "runs": 200}
                sj._json["settings"]["viaIR"] = True
            return sj

        try:
            sl = Slither(CryticCompile(_build_sj(via_ir=False)))
        except Exception as exc:
            msg = str(exc)
            if "Stack too deep" not in msg and "--via-ir" not in msg and "viaIR" not in msg:
                raise
            print("slither_export: stack-too-deep — retrying with viaIR + optimizer",
                  file=sys.stderr)
            sl = Slither(CryticCompile(_build_sj(via_ir=True)))
    else:
        kwargs = {}
        # Optional 1st extra arg = crytic-compile framework to force (e.g. "hardhat"),
        # so we reuse an existing build instead of letting auto-detect pick foundry.
        if framework and framework != "-":
            kwargs["compile_force_framework"] = framework
        sl = Slither(target_dir, **kwargs)

    contracts = []
    for c in sl.contracts:
        try:
            contracts.append(_export_contract(c))
        except Exception as exc:  # pragma: no cover
            contracts.append({"name": getattr(c, "name", "?"), "error": str(exc),
                              "functions": [], "state_vars": [], "inheritance": []})

    detectors = []
    try:
        import inspect as _inspect

        from slither.detectors import all_detectors
        from slither.detectors.abstract_detector import AbstractDetector

        for _name in dir(all_detectors):
            obj = getattr(all_detectors, _name)
            if _inspect.isclass(obj) and issubclass(obj, AbstractDetector) and obj is not AbstractDetector:
                try:
                    sl.register_detector(obj)
                except Exception:
                    continue
        results = sl.run_detectors()
        for group in results:
            if isinstance(group, list):
                detectors.extend(group)
            elif group:
                detectors.append(group)
    except Exception as exc:
        detectors = [{"_detector_error": str(exc)}]

    out = {
        "target_dir": target_dir,
        "contracts": contracts,
        "detectors": detectors,
    }
    with open(out_path, "w") as fh:
        json.dump(out, fh, default=str)
    print(f"slither_export: {len(contracts)} contracts, {len(detectors)} detector results -> {out_path}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("usage: slither_export.py <target_dir> <out.json> [crytic_args...]", file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1], sys.argv[2], sys.argv[3:]))
