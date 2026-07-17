"""Chimera-style layered fuzzing campaign scaffold (T1.3 / spec §16a, §10).

The SOTA DeFi-invariant pipeline is *layered hybrid*: write ONE handler (actors +
ghost vars + the invariants as properties) and run it through Foundry smoke →
**Medusa** stateful fuzzing → **Halmos** symbolic proof, then turn any
counterexample into a fork PoC that demonstrates $-impact. (Recon-Fuzz "Chimera":
one handler, many engines — github.com/Recon-Fuzz/create-chimera-app.)

This module DETERMINISTICALLY generates that handler skeleton from a task's bound
``Invariant``s (and its precomputed attack surface, when a ``HunterDossier`` is
present), so the Hunter starts the campaign from a real, invariant-keyed scaffold
instead of a blank page. The skeleton is intentionally a *stub the hunter wires to
the real contracts* — only the agent, reading the in-scope source, knows how to
deploy the system; we give it the actors, the ghost-variable slots, one
target-function wrapper per reachable entrypoint, and each invariant rendered as an
assertion property in all three engines' expected shapes + their configs.

The whole thing is pure string generation (no tool runs, no tokens) so it is
unit-tested offline; the fuzzers themselves only run inside the Hunter session.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any

# Assertion mode is the common denominator: a public ``invariant_*`` function that
# ``assert``s the property is caught by BOTH echidna (testMode: assertion) and medusa
# (assertionTesting) AND can be replayed in a Foundry test — Chimera's "write once,
# run everywhere". The hunter replaces ``assert(true)`` with the real check.


def _ident(s: str) -> str:
    """A safe Solidity identifier fragment from an arbitrary id/string."""
    out = re.sub(r"[^0-9A-Za-z_]", "_", s or "")
    if out and out[0].isdigit():
        out = "_" + out
    return out or "X"


def _inv_rows(invariants: list[Any]) -> list[dict]:
    """Normalize Invariant models OR raw dicts into ``{id, statement, hooks, tool,
    category}`` rows (the dossier may carry either)."""
    rows: list[dict] = []
    for inv in invariants or []:
        if hasattr(inv, "inv_id"):
            rows.append({"id": inv.inv_id, "statement": inv.statement,
                         "hooks": list(inv.hooks or []),
                         "tool": getattr(inv.tool, "value", inv.tool),
                         "category": getattr(inv.category, "value", inv.category)})
        elif isinstance(inv, dict):
            rows.append({"id": inv.get("inv_id") or inv.get("id") or "INV",
                         "statement": inv.get("statement", ""),
                         "hooks": list(inv.get("hooks") or []),
                         "tool": inv.get("tool", ""),
                         "category": inv.get("category", "")})
    return rows


def _fn_wrappers(task: Any, dossier: Any) -> list[str]:
    """One target-function wrapper name per reachable entrypoint / target function in
    the dossier — the surface the stateful fuzzer drives (the hunter fills the body).

    LLM-GUIDED ORDER (T2.2): the recon LLM's attack-path hops come FIRST (the fuzzer
    biases toward functions declared earlier), then the dossier's reachable
    entrypoints (recon-ranked), then other target functions — so the fuzzer's
    exploration is steered by recon's output, not blind."""
    names: list[str] = []
    seen: set[str] = set()

    def _push(raw: str) -> None:
        # an attack_path hop may be "Contract:fn" / "fn(...)" / "fn"
        frag = raw.split(":")[-1].split("(")[0].strip()
        n = _ident(frag) if frag else ""
        if n and n not in seen and n.lower() not in ("flashloan", "borrow", "swap", "read"):
            seen.add(n)
            names.append(n)

    for hop in (getattr(task, "attack_path", None) or []) if task is not None else []:
        _push(hop)
    src = []
    if dossier is not None:
        src = (getattr(dossier, "reachable_entrypoints", None) or []) + \
              (getattr(dossier, "target_functions", None) or [])
    for r in src:
        n = (r.get("name") or r.get("signature") or "") if isinstance(r, dict) else ""
        if n:
            _push(n)
        if len(names) >= 10:
            break
    return names[:10]


# --------------------------------------------------------------------------- #
# Fix A — reuse the repo's OWN test deployment fixture (auto-wire setUp)        #
# --------------------------------------------------------------------------- #
# Audit-contest repos almost always ship an abstract test base whose setUp()
# deploys the whole in-scope system (factory, pool, tokens, oracle, actors) plus
# helper methods. Detecting it and generating `contract Handler is <Fixture>`
# hands the hunter a fully-deployed, compiling starting point instead of a blank
# setUp() stub — the single biggest wiring tax that made hunters fall back to
# shallow bespoke tests. Deterministic, source-only (no compile); safe to no-op.
_ABSTRACT_RE = re.compile(r"\babstract\s+contract\s+(\w+)\b")
_SETUP_RE = re.compile(r"\bfunction\s+setUp\s*\(")
_NEW_RE = re.compile(r"\bnew\s+([A-Z]\w+)\s*[({]")
_MEMBER_RE = re.compile(r"^\s*([A-Z]\w+)\s+(?:public|internal|private)\s+(\w+)\s*;", re.M)
_HELPER_RE = re.compile(r"\bfunction\s+(_[A-Za-z]\w*)\s*\(")
_FIXTURE_NAME_HINT = re.compile(r"(base|fixture|setup|harness|scenario)", re.I)
_SKIP_PATH = ("/lib/", "/node_modules/", "/out/", "/cache/")


def detect_test_fixture(repo_root: Any, in_scope: list[str] | None = None) -> dict | None:
    """Find the repo's best abstract test fixture (setUp() that deploys the system).

    Returns ``{name, import_path, members, helpers}`` (import_path relative to
    ``test/campaign/`` where the generated Handler lives), or ``None`` when the repo
    ships no usable fixture (→ the scaffold keeps its blank-stub setUp, unchanged)."""
    from pathlib import Path as _P
    root = _P(repo_root) if repo_root else None
    if not root or not (root / "test").is_dir():
        return None
    scope = {s.split(":")[-1].split(".")[-1] for s in (in_scope or []) if s}
    best: dict | None = None
    best_score = 0
    for p in sorted((root / "test").glob("**/*.sol")):
        sp = str(p)
        if any(f in sp for f in _SKIP_PATH):
            continue
        try:
            text = p.read_text(errors="ignore")
        except Exception:
            continue
        if not _SETUP_RE.search(text):
            continue
        abstracts = _ABSTRACT_RE.findall(text)
        if not abstracts:
            continue
        news = _NEW_RE.findall(text)
        if not news:
            continue
        # prefer the abstract contract named like a fixture; else the last declared.
        name = next((a for a in abstracts if _FIXTURE_NAME_HINT.search(a)), abstracts[-1])
        in_scope_hits = len(scope & set(news)) if scope else 0
        score = len(news) + 3 * in_scope_hits + (2 if _FIXTURE_NAME_HINT.search(name) else 0)
        if score <= best_score:
            continue
        rel = p.relative_to(root).as_posix()               # e.g. test/Pool.base.t.sol
        import_path = os.path.relpath(rel, "test/campaign").replace(os.sep, "/")
        members = [f"{t} {n}" for t, n in _MEMBER_RE.findall(text)][:12]
        helpers = sorted(set(_HELPER_RE.findall(text)))[:16]
        best, best_score = (
            {"name": name, "import_path": import_path, "members": members, "helpers": helpers},
            score,
        )
    return best


# --------------------------------------------------------------------------- #
# File generators                                                             #
# --------------------------------------------------------------------------- #
def _properties_sol(invs: list[dict]) -> str:
    lines = [
        "// SPDX-License-Identifier: MIT",
        "pragma solidity >=0.8.0 <0.9.0;",
        "",
        "// Chimera Properties (T1.3) — each bound invariant as a public assertion",
        "// property. Assertion mode means echidna AND medusa both call these and flag",
        "// any that fail; they also replay in a Foundry test. Wire each body to the",
        "// real protocol state (read via the ghost vars / your deployed system), then",
        "// replace `assert(true)` with the actual check.",
        "abstract contract Properties {",
    ]
    targets = invs or [{"id": "PLACEHOLDER",
                        "statement": "the property you are hunting", "hooks": [], "tool": ""}]
    for inv in targets:
        iid = _ident(inv["id"])
        stmt = (inv["statement"] or "").replace("\n", " ").strip()
        hooks = ", ".join(inv["hooks"][:6]) or "(unbound)"
        lines += [
            "",
            f"    // {inv['id']} [{inv.get('tool','')}] — {stmt}",
            f"    // hooks: {hooks}",
            f"    function invariant_{iid}() public view returns (bool) {{",
            "        // TODO: set `ok` to the real check for the property above.",
            "        bool ok = true;",
            "        assert(ok); // caught by echidna/medusa ASSERTION mode",
            "        return ok;  // checked by medusa PROPERTY mode after each call",
            "    }",
        ]
    lines.append("}")
    return "\n".join(lines) + "\n"


def _stress_block() -> tuple[str, str]:
    """The Tier-4 P1 ADVERSE-MARKET layer: ghost *market-state* vars + ``handle_stress*``
    primitives that warp the WORLD the protocol reads — oracle price, oracle freshness,
    AMM-pool reserves, collateral peg, funding/utilization — so medusa (fork mode)
    composes them WITH the protocol's own calls and the existing invariants +
    optimize_attackerPnL/optimize_protocolLoss are evaluated UNDER stress.

    Returns ``(ghost_vars, primitives)`` to splice into the handler. The bodies are
    stubs the hunter wires to the FORKED oracle/pool (via ``vm.mockCall`` on the price
    feed, real swaps on the pool, ``vm.warp`` for staleness); the fuzzer drives them as
    first-class actions regardless."""
    ghosts = (
        "\n    // --- adverse-market ghost state (Tier-4 P1; fuzzer warps the WORLD) -- //\n"
        "    // Unstressed = 10000 bps (100%). The handle_stress* wrappers below move\n"
        "    // these; wire setUp()/the wrappers to the FORKED oracle+pool so the moves\n"
        "    // are REAL (a local mock can't depeg a real pool). Invariants are checked\n"
        "    // after every call, so a property that holds at peg but breaks under stress\n"
        "    // is surfaced as a shrunk sequence that INCLUDES the market move.\n"
        "    int256  internal ghost_oraclePriceBps     = 10000; // warped oracle price (bps of true)\n"
        "    bool    internal ghost_oracleStale;                // oracle forced stale?\n"
        "    int256  internal ghost_collateralPegBps   = 10000; // collateral peg (bps; <10000 = depeg)\n"
        "    uint256 internal ghost_fundingRateBps;             // spiked funding / utilization (bps)\n"
        "    int256  internal ghost_poolSkewBps;                // AMM reserve skew vs unstressed (bps)\n"
    )
    prims = (
        "\n    // --- adverse-market primitives (Tier-4 P1; wire to the FORKED world) ---- //\n"
        "    // medusa composes these alongside the protocol's handle_* calls; each move\n"
        "    // is bounded to a plausible-but-hostile range. RE-CHECK every invariant +\n"
        "    // optimize_protocolLoss after a move — the bug is usually 'holds at peg,\n"
        "    // insolvent under stress'.\n"
        "    function handle_stressWarpOraclePrice(uint256 priceBps, uint256 oracleSeed) public {\n"
        "        ghost_oraclePriceBps = int256(1 + (priceBps % 30000)); // 0.01x .. 3x of true\n"
        "        // TODO(fork): vm.mockCall the price feed the protocol READS (e.g.\n"
        "        //   Chainlink latestRoundData / a TWAP getter) to return this warped price.\n"
        "    }\n\n"
        "    function handle_stressForceOracleStale(uint256 ageSeed) public {\n"
        "        ghost_oracleStale = true;\n"
        "        // TODO(fork): vm.warp far past the feed's heartbeat AND/OR vm.mockCall the\n"
        "        //   feed's updatedAt to a stale timestamp — does the protocol still trade\n"
        "        //   on it / fail to revert? Stale price is a classic adverse-market sink.\n"
        "    }\n\n"
        "    function handle_stressSkewPoolReserves(uint256 amountIn, uint256 dirSeed) public {\n"
        "        ghost_poolSkewBps = int256((amountIn % 20000)) * (dirSeed % 2 == 0 ? int256(1) : -1);\n"
        "        // TODO(fork): swap on / drain the REAL AMM pool the protocol reads or routes\n"
        "        //   through to skew its reserves (spot-price / virtual-price manipulation,\n"
        "        //   read-only-reentrancy surface). Move it, then call the protocol.\n"
        "    }\n\n"
        "    function handle_stressDepegCollateral(uint256 pegBps) public {\n"
        "        ghost_collateralPegBps = int256(pegBps % 10001); // 0% .. 100% of peg\n"
        "        // TODO(fork): drop the collateral asset's price (mockCall its feed / move its\n"
        "        //   pool) — does liquidation stay solvent, or does bad debt accrue?\n"
        "    }\n\n"
        "    function handle_stressSpikeFunding(uint256 rateBps) public {\n"
        "        ghost_fundingRateBps = rateBps % 1000000; // up to 10000% APR-equivalent\n"
        "        // TODO(fork): drive utilization/funding to its cap (borrow out the pool /\n"
        "        //   vm.warp to accrue) — does interest/funding overflow, freeze withdrawals,\n"
        "        //   or push a position underwater while the protocol reads stale state?\n"
        "    }\n"
    )
    return ghosts, prims


def _dep_block(dep_target: str, dep_assumptions: list[str] | None = None) -> tuple[str, str, str]:
    """The Tier-4 P3 EXTERNAL-DEPENDENCY-MISBEHAVIOR layer. A dep-misbehavior task does
    NOT hunt the in-scope code's own logic — it asks "does the protocol stay safe when
    the EXTERNAL dependency it trusts MISBEHAVES?". On the fork, these ``handle_dep*``
    primitives ``vm.mockCall`` / ``vm.mockCallRevert`` the dependency so it returns
    ADVERSARIAL values (stale / extreme / reverting / reentrant) while the fuzzer keeps
    driving the protocol's own wrappers and EVERY invariant in Properties must still hold.

    Returns ``(addr_slot, ghost_vars, primitives)`` to splice into the handler. The mock
    selectors/return shapes are TODO-stubs the hunter wires to the real dependency ABI."""
    tgt = (dep_target or "the external dependency").replace("\n", " ").strip()
    assume = "; ".join((dep_assumptions or [])[:4])
    addr_slot = (
        "\n    // --- the EXTERNAL dependency under adversarial test (Tier-4 P3) ----- //\n"
        f"    // dep_target: {tgt}\n"
        + (f"    // trust assumptions under attack: {assume}\n" if assume else "")
        + "    address internal depAddr; // TODO(fork): real deployed address of the dependency\n"
    )
    ghosts = (
        "\n    // --- dep-misbehavior ghost state (Tier-4 P3) ---------------------- //\n"
        "    bool    internal ghost_depStale;       // dep forced to return stale data?\n"
        "    int256  internal ghost_depReturnBps = 10000; // dep return warped (bps of honest)\n"
        "    bool    internal ghost_depReverting;   // dep forced to revert (pause/DoS)?\n"
        "    bool    internal ghost_depReentered;   // dep reentered the protocol on callback?\n"
    )
    prims = (
        "\n    // --- dep-misbehavior primitives (Tier-4 P3; mock the FORKED dep) ---- //\n"
        "    // The fuzzer composes these with the protocol's own handle_* calls; after a\n"
        "    // mock is active EVERY invariant in Properties must STILL hold. The protocol\n"
        "    // trusts this dependency — prove the trust is (un)safe.\n"
        "    function handle_depReturnStale(uint256 ageSeed) public {\n"
        "        ghost_depStale = true;\n"
        "        // TODO(fork): vm.mockCall(depAddr, <getter selector>, abi.encode(... old\n"
        "        //   timestamp / last-good value ...)) so the dep looks fresh but is stale —\n"
        "        //   does the protocol act on stale data instead of reverting?\n"
        "    }\n\n"
        "    function handle_depReturnExtreme(uint256 valueSeed, uint256 dirSeed) public {\n"
        "        ghost_depReturnBps = dirSeed % 2 == 0 ? int256(1) : int256(1000000);\n"
        "        // TODO(fork): vm.mockCall(depAddr, <getter selector>, abi.encode(extreme))\n"
        "        //   — return ~0 or a huge value (uncapped oracle/virtual-price/exchange-rate).\n"
        "        //   Does accounting/liquidation stay solvent, or does it over/under-value?\n"
        "    }\n\n"
        "    function handle_depRevert() public {\n"
        "        ghost_depReverting = true;\n"
        "        // TODO(fork): vm.mockCallRevert(depAddr, <selector>, \"paused\") — the dep\n"
        "        //   pauses/reverts (Aave pause, feed down, bridge halt). Can the attacker\n"
        "        //   wedge withdrawals/liquidations (PERMANENT FREEZING) via this revert?\n"
        "    }\n\n"
        "    function handle_depReentrant(uint256 seed) public {\n"
        "        ghost_depReentered = true;\n"
        "        // TODO(fork): point depAddr at a malicious mock that REENTERS a protocol\n"
        "        //   entrypoint from inside the trusted call (callback/hook/ERC777). Does a\n"
        "        //   read mid-callback see inconsistent state? (cross-contract reentrancy.)\n"
        "    }\n\n"
        "    function handle_depClearMock() public {\n"
        "        ghost_depStale = false; ghost_depReverting = false; ghost_depReturnBps = 10000;\n"
        "        // TODO(fork): vm.clearMockedCalls() — restore honest behavior so the fuzzer\n"
        "        //   can explore enter-bad-state-then-recover sequences.\n"
        "    }\n"
    )
    return addr_slot, ghosts, prims


def _multiactor_block() -> tuple[str, str]:
    """The Tier-4 P5 MULTI-ACTOR / collusion layer. A single-attacker model misses
    exploits that need two roles to COLLUDE (a keeper that orders/executes + an LP that
    provides liquidity; a briber + a bribed governance voter). These extra actor slots +
    a COALITION-PnL objective let medusa maximise the colluding actors' COMBINED profit,
    so an incentive-misalignment exploit (one actor's 'honest' action enriches the other)
    is found. Returns ``(actor_slots, objective)``."""
    actors = (
        "\n    // --- colluding coalition actors (Tier-4 P5) ----------------------- //\n"
        "    address internal keeper = address(0xC0FFEE);  // colluding keeper / sequencer / operator\n"
        "    address internal lp     = address(0xD10DE);   // colluding LP / counterparty\n"
    )
    objective = (
        "\n    // --- MULTI-ACTOR coalition objective (Tier-4 P5) ------------------- //\n"
        "    // The attacker COLLUDES with keeper+lp (bribery / side-payments); medusa\n"
        "    // MAXIMIZES their COMBINED PnL, finding incentive-misalignment exploits a\n"
        "    // single-actor model misses (a keeper's 'honest' ordering enriches the LP, etc.).\n"
        "    int256 internal ghost_coalitionPnL;\n"
        "    function optimize_coalitionPnL() public view returns (int256) {\n"
        "        // TODO: wire to (attacker+keeper+lp combined value now - at setUp).\n"
        "        return ghost_coalitionPnL;\n"
        "    }\n"
    )
    return actors, objective


def _longhorizon_block() -> tuple[str, str, str]:
    """The Tier-4 P5 LONG-HORIZON / epoch-aware layer. Many incentive bugs only appear
    after time passes — interest/funding drift, reward-rate decay, epoch/checkpoint
    boundaries, vesting cliffs. This adds a real ``vm.warp``/``vm.roll`` time-advance
    primitive (via the hevm cheatcode address, no forge-std needed) the fuzzer composes
    with protocol calls, so long-horizon state is actually reached. Pair with the larger
    ``callSequenceLength`` in medusa.json. Returns ``(iface_decl, ghost_vars, primitives)``."""
    iface = ("\n// hevm cheatcode interface for the long-horizon time-advance step (Tier-4 P5).\n"
             "interface _P5Vm { function warp(uint256) external; function roll(uint256) external; }\n")
    ghosts = (
        "\n    // --- long-horizon time state (Tier-4 P5) -------------------------- //\n"
        "    address internal constant _P5_VM = address(uint160(uint256(keccak256(\"hevm cheat code\"))));\n"
        "    uint256 internal ghost_timeWarped; // cumulative seconds advanced\n"
    )
    prims = (
        "\n    // --- long-horizon time-advance (Tier-4 P5; real vm.warp/roll) ------ //\n"
        "    // medusa composes this with the protocol's calls; after a jump, interest/\n"
        "    // funding has accrued and epoch/checkpoint boundaries may have crossed, so\n"
        "    // every invariant + optimize_* is re-checked at the new point in time.\n"
        "    function handle_advanceTime(uint256 stepSeed) public {\n"
        "        uint256 step = 3600 + (stepSeed % uint256(2592000)); // 1h .. ~30d per step\n"
        "        _P5Vm(_P5_VM).warp(block.timestamp + step);\n"
        "        _P5Vm(_P5_VM).roll(block.number + 1 + step / 12); // ~12s blocks\n"
        "        ghost_timeWarped += step;\n"
        "    }\n"
    )
    return iface, ghosts, prims


def _attacker_block(wrappers: list[str]) -> tuple[str, str]:
    """The TASK-2 first-class ATTACKER-PRIMITIVE layer — the mechanisms behind the
    in-scope, attacker-triggerable class the harness kept missing (donation/first-
    depositor inflation, reentrancy drains, atomic multi-step chains). Unlike the
    stress/dep layers (which mock the WORLD for DISCOVERY only), every primitive here
    uses ONLY attacker-controlled inputs, so a winning sequence is directly
    ``attacker_reachable`` (payable per the adversary model). Returns ``(vars, prims)``.

    Emits:
      * ``handle_donate`` — a direct token transfer INTO a vault/pool (no mint), the
        share-price-inflation / first-depositor primitive (WiseLending, Sonne).
      * ``handle_reenter`` + a reentrant ``fallback`` — the Handler IS the malicious
        receiver; arm a re-entry target and the callback re-enters mid-state-update
        (Orion-style balance inflation, read-only reentrancy).
      * ``handle_composeAB`` — one atomic call that acts on contract A THEN contract B
        (deposit→borrow, mint→donate→redeem), so medusa explores genuine CROSS-CONTRACT
        stateful sequences, not one function in isolation.
    """
    # compose the first two distinct fuzzed entrypoints into an atomic A→B sequence.
    # Fall back to "example" (handle_example always exists when no wrapper resolved) so
    # the composed handler always references a real handle_* — never a dangling call.
    a = wrappers[0] if len(wrappers) > 0 else "example"
    b = wrappers[1] if len(wrappers) > 1 else (wrappers[0] if wrappers else "example")
    vars_ = (
        "\n    // --- attacker-primitive state (TASK 2; attacker-controlled ONLY) --- //\n"
        "    address internal donateTarget;   // TODO: the vault/pool whose share price a donation inflates\n"
        "    address internal donateToken;    // TODO: the underlying token to transfer in\n"
        "    address internal reenterTarget;  // TODO: contract to re-enter from the callback\n"
        "    bytes   internal reenterData;     // TODO: calldata for the re-entry\n"
        "    bool    internal reenterArmed;\n"
        "    uint256 internal reenterDepth;\n"
    )
    prims = (
        "\n    // --- ATTACKER PRIMITIVES (TASK 2) — attacker-reachable, no mock ----- //\n"
        "    // These use only what the attacker controls (own capital, own contract,\n"
        "    // permissionless entrypoints). A winning optimize_attackerPnL sequence built\n"
        "    // from THESE is a live, payable bug — no oracle/admin/dep mock in the path.\n\n"
        "    // DONATION / first-depositor inflation: transfer underlying straight into the\n"
        "    // vault (bypassing mint) to inflate the share price, then a victim mint rounds\n"
        "    // to zero shares / the attacker's 1 share is worth the whole pool.\n"
        "    function handle_donate(uint256 amount) public {\n"
        "        // TODO: IERC20(donateToken).transfer(donateTarget, _clamp(amount));\n"
        "        // update ghost_attackerPnL after redeeming the inflated share.\n"
        "    }\n\n"
        "    // REENTRANCY: the Handler is the malicious receiver. Arm a re-entry, then a\n"
        "    // protocol call that hands control back (token hook / ETH send / callback)\n"
        "    // re-enters before state settles.\n"
        "    function handle_armReentrancy(uint256 seed) public {\n"
        "        reenterArmed = true;\n"
        "        // TODO: set reenterTarget/reenterData to the entrypoint to re-enter.\n"
        "    }\n\n"
        "    function handle_reenter(uint256 amount) public {\n"
        "        // TODO: call the protocol path that invokes this contract back (which\n"
        "        // triggers the fallback below) while balances are mid-update.\n"
        "    }\n\n"
        "    // The re-entry itself: called when the protocol sends value / invokes a hook.\n"
        "    fallback() external payable {\n"
        "        if (reenterArmed && reenterDepth < 1 && reenterTarget != address(0)) {\n"
        "            reenterDepth++;\n"
        "            (bool ok, ) = reenterTarget.call(reenterData); ok;  // re-enter\n"
        "        }\n"
        "    }\n"
        "    receive() external payable {}\n\n"
        f"    // COMPOSED cross-contract sequence: act on A ({a}) THEN B ({b}) atomically,\n"
        "    // so medusa fuzzes a genuine 2-contract stateful chain (deposit→borrow,\n"
        "    // mint→donate→redeem), not one entrypoint in isolation.\n"
        "    function handle_composeAB(uint256 amountA, uint256 amountB, uint256 actorSeed) public {\n"
        "        address actor = _actor(actorSeed);\n"
        f"        handle_{a}(amountA, actorSeed);   // step 1 on contract A\n"
        f"        handle_{b}(amountB, actorSeed);   // step 2 on contract B (composed)\n"
        "        actor;\n"
        "    }\n"
    )
    return vars_, prims


def _handler_sol(invs: list[dict], wrappers: list[str], *, economic: bool = False,
                 contracts: list[str] | None = None, fork: bool = False,
                 stress: bool = False, dep_misbehavior: bool = False,
                 dep_target: str = "", dep_assumptions: list[str] | None = None,
                 multi_actor: bool = False, long_horizon: bool = False,
                 attacker: bool = False, fixture: dict | None = None) -> str:
    ghosts = []
    for inv in invs[:12]:
        iid = _ident(inv["id"])
        ghosts.append(f"    uint256 internal ghost_{iid};   // track state for {inv['id']}")
    if not ghosts:
        ghosts = ["    uint256 internal ghost_value;   // example accounting ghost"]
    wrap_fns = []
    for w in wrappers:
        wrap_fns.append(
            f"    function handle_{w}(uint256 amount, uint256 actorSeed) public {{\n"
            f"        address actor = _actor(actorSeed);\n"
            f"        // TODO: vm-prank `actor` and call the real {w}(...) on your system;\n"
            f"        // clamp `amount` to a sane range and update the ghost vars above.\n"
            f"    }}")
    if not wrap_fns:
        wrap_fns = [
            "    function handle_example(uint256 amount, uint256 actorSeed) public {\n"
            "        address actor = _actor(actorSeed);\n"
            "        // TODO: drive a real entrypoint of your in-scope system here.\n"
            "    }"]

    # Cross-contract / economic tasks get the extra machinery a multi-hop attack needs:
    # real deployed-address slots, flash-loan / AMM-price-move / harvest primitives that
    # the attack_path hops call, and a protocol-solvency objective (minimised) alongside
    # attacker PnL (maximised).
    econ_addrs, econ_prims, econ_obj = "", "", ""
    # With an inherited fixture the system is already deployed as named instances, so
    # skip the "address internal <Contract>" slots — they are redundant AND would clash
    # with the contract type names the fixture imports.
    if economic and not fixture:
        slots = []
        for c in (contracts or [])[:12]:
            slots.append(f"    address internal {_ident(c)[:40]}; // TODO: real deployed "
                         f"address of {c}")
        econ_addrs = ("\n    // --- in-scope contracts under attack (fill from your SCOPE; "
                      "fork mode = real deployed addresses) ---\n" + "\n".join(slots) + "\n"
                      if slots else "")
        econ_prims = (
            "\n    // --- economic-attack primitives (wire to the FORKED protocol) ----- //\n"
            "    // A multi-hop economic exploit chains these; the fuzzer composes them in\n"
            "    // random order/amounts while the optimizer maximises attacker PnL.\n"
            "    function handle_flashLoan(uint256 amount) public {\n"
            "        // TODO: borrow `amount` from a real flash-loan source on the fork,\n"
            "        // run the inner hops, repay. Models 'needs capital → ~zero capital'.\n"
            "    }\n\n"
            "    function handle_ammSwapMovePrice(uint256 amountIn, uint256 dirSeed) public {\n"
            "        // TODO: swap on the real AMM/pool the protocol reads or routes through\n"
            "        // to MOVE the price/reserves (oracle-manipulation / slippage surface).\n"
            "    }\n\n"
            "    function handle_triggerHarvest(uint256 actorSeed) public {\n"
            "        // TODO: trigger the strategy harvest/compound (the minOut/slippage\n"
            "        // swap is the sandwich surface); update ghost_protocolSolvency after.\n"
            "    }\n")
        econ_obj = (
            "\n    // --- protocol-solvency objective: medusa MINIMISES protocol value -- //\n"
            "    int256 internal ghost_protocolSolvency;\n"
            "    function optimize_protocolLoss() public view returns (int256) {\n"
            "        return -ghost_protocolSolvency; // maximise the protocol's LOSS\n"
            "    }\n")

    stress_vars, stress_prims = _stress_block() if stress else ("", "")
    dep_addr, dep_vars, dep_prims = (_dep_block(dep_target, dep_assumptions)
                                     if dep_misbehavior else ("", "", ""))
    ma_actors, ma_obj = _multiactor_block() if multi_actor else ("", "")
    lh_iface, lh_vars, lh_prims = _longhorizon_block() if long_horizon else ("", "", "")
    atk_vars, atk_prims = _attacker_block(wrappers) if attacker else ("", "")

    title = ("Chimera Handler (T1.3/T2.1) — MULTI-CONTRACT economic-attack target"
             if economic else "Chimera Handler (T1.3) — the stateful-fuzz target")
    if attacker:
        title += " · ATTACKER PRIMITIVES (T2: donation/reentrancy/compose)"
    if stress:
        title += " · ADVERSE-MARKET stress (T4 P1)"
    if dep_misbehavior:
        title += " · DEP-MISBEHAVIOR (T4 P3)"
    if multi_actor:
        title += " · MULTI-ACTOR coalition (T4 P5)"
    if long_horizon:
        title += " · LONG-HORIZON (T4 P5)"
    fork_note = ("// FORK MODE is ON (medusa.json): setUp() should `vm.createSelectFork` "
                 "and bind\n//   the real deployed addresses above — the fuzzer drives the "
                 "ACTUAL protocol.\n" if fork else "")
    # Fix A: when the repo ships a deployment fixture, inherit it so setUp() +
    # every deployed instance/helper come for free (no re-wiring the deploy).
    fix_import = ""
    fix_inherit = "Properties"
    fix_setup_body = ("        // TODO: deploy the in-scope contracts (or vm.createSelectFork)"
                      " + record state.\n")
    fix_note = ""
    if fixture and fixture.get("name"):
        fname = fixture["name"]
        fix_import = f'import {{{fname}}} from "{fixture.get("import_path", "")}";\n'
        fix_inherit = f"{fname}, Properties"
        mem = ", ".join(fixture.get("members") or []) or "(see the fixture source)"
        hlp = ", ".join(fixture.get("helpers") or []) or "(see the fixture source)"
        fix_setup_body = (
            "        // The repo's OWN fixture deploys the full in-scope system — reuse it.\n"
            "        super.setUp();\n"
            f"        // Ready to drive (inherited from {fname}):\n"
            f"        //   state:   {mem}\n"
            f"        //   helpers: {hlp}\n"
        )
        fix_note = (
            f"//\n// WIRED FIXTURE: this Handler inherits `{fname}` — setUp() already deploys\n"
            "//   the real in-scope system. Fill each handle_* wrapper by calling the inherited\n"
            "//   helpers/state above; do NOT re-deploy. Then run the campaign (CAMPAIGN.md).\n"
        )
    # overriding the fixture's virtual setUp() requires the override specifier.
    fix_setup_decl = ("    function setUp() public virtual override {\n" if fixture
                      else "    function setUp() public virtual {\n")
    return (
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity >=0.8.0 <0.9.0;\n\n"
        'import "./Properties.sol";\n'
        + fix_import
        + lh_iface + "\n"
        f"// {title}. Medusa/echidna call its public handle_* wrappers in random\n"
        "// sequences; the Properties asserts are checked after each call. Wire the\n"
        "// wrappers + setUp() to your deployed in-scope system (import it by absolute\n"
        "// path from your TASK's repo root), then run the layered campaign (CAMPAIGN.md).\n"
        + ("//\n" + fork_note if fork_note else "")
        + fix_note
        + f"contract Handler is {fix_inherit} {{\n"
        "    // --- actors -------------------------------------------------------- //\n"
        "    address internal alice   = address(0xA11CE);\n"
        "    address internal bob     = address(0xB0B);\n"
        "    address internal attacker = address(0xBAD);\n"
        "    address[3] internal actors = [alice, bob, attacker];\n"
        + econ_addrs + dep_addr + ma_actors + "\n"
        "    // --- ghost variables (one per bound invariant) --------------------- //\n"
        + "\n".join(ghosts) + "\n"
        + stress_vars + dep_vars + lh_vars + atk_vars + "\n"
        "    function _actor(uint256 seed) internal view returns (address) {\n"
        "        return actors[seed % actors.length];\n"
        "    }\n\n"
        "    // --- OPTIMIZATION objective (T2.2): maximize attacker PnL ----------- //\n"
        "    // medusa runs `optimize_*` to MAXIMIZE the return value, searching for the\n"
        "    // call sequence that most enriches the attacker. Wire ghost_attackerPnL in\n"
        "    // your handlers to (attacker value now - attacker value at setUp); a large\n"
        "    // positive maximum IS the economic exploit.\n"
        "    int256 internal ghost_attackerPnL;\n"
        "    function optimize_attackerPnL() public view returns (int256) {\n"
        "        return ghost_attackerPnL;\n"
        "    }\n"
        + econ_obj + ma_obj +
        "\n    // Wire this to deploy/fork your in-scope system + seed actor balances, and\n"
        "    // record the attacker's starting value so the handlers can update PnL.\n"
        + fix_setup_decl
        + fix_setup_body
        + "    }\n\n"
        "    // --- target-function wrappers (the fuzzed surface; LLM-ordered) ---- //\n"
        + "\n\n".join(wrap_fns) + "\n"
        + econ_prims + atk_prims + stress_prims + dep_prims + lh_prims +
        "}\n"
    )


def _symbolic_t_sol(invs: list[dict]) -> str:
    lines = [
        "// SPDX-License-Identifier: MIT",
        "pragma solidity >=0.8.0 <0.9.0;",
        "",
        'import "forge-std/Test.sol";',
        "",
        "// Halmos symbolic spec (T1.3) — PROVE each invariant holds for ALL inputs",
        "// (run: `halmos --function check_`). A halmos counterexample is a real,",
        "// all-paths violation; feed it into your fork PoC. A pass is a proof the",
        "// property holds (stronger than fuzzing). Wire each check to the real system.",
        "contract SymbolicSpec is Test {",
    ]
    targets = invs or [{"id": "PLACEHOLDER", "statement": "the property you are hunting"}]
    for inv in targets[:8]:
        iid = _ident(inv["id"])
        stmt = (inv["statement"] or "").replace("\n", " ").strip()
        lines += [
            "",
            f"    // {inv['id']} — {stmt}",
            f"    function check_{iid}(uint256 x, uint256 y) public {{",
            "        // TODO: set up symbolic state, exercise the function(s), then",
            "        //   assert the invariant. halmos explores all paths.",
            "        assert(true);",
            "    }",
        ]
    lines.append("}")
    return "\n".join(lines) + "\n"


def _medusa_json(focus: list[str] | None = None, fork: dict | None = None,
                 long_horizon: bool = False, deep: bool = False) -> str:
    # Medusa's config is a full, schema-validated document (a partial one is rejected
    # as "Invalid configuration"), so we emit the complete medusa 1.5.1 default and
    # patch only: target the Handler, test the invariant_*/property_* prefixes + asserts,
    # enable OPTIMIZATION (optimize_attackerPnL → maximize attacker profit, T2.2), focus
    # the fuzzer on the LLM-prioritised handle_* wrappers, a bounded testLimit, and a
    # campaign-local corpus. When `fork` is given (keyless URL — a local anvil or a free
    # public archive), enable medusa FORK MODE so the campaign fuzzes the REAL deployed
    # contracts (the only way to accurately test oracle/AMM/flash-loan/economic threats).
    focus_sigs = [f"Handler.handle_{w}(uint256,uint256)" for w in (focus or [])]
    fork_cfg = {"forkModeEnabled": False, "rpcUrl": "", "rpcBlock": 1, "poolSize": 20}
    if fork and fork.get("rpc_url"):
        fork_cfg = {"forkModeEnabled": True, "rpcUrl": fork["rpc_url"],
                    "rpcBlock": int(fork.get("block") or 0), "poolSize": 20}
    # Long-horizon (Tier-4 P5): a much longer call sequence so funding/interest drift +
    # epoch/checkpoint boundaries are reached within one sequence, and a wider per-call
    # timestamp jump so the time-advance handler can cross large gaps.
    # Cross-contract / economic (deep) tasks need a longer call sequence to reach a
    # multi-step stateful exploit (deposit→manipulate→borrow→withdraw across calls) and
    # a bigger budget to explore the composed handler space; long-horizon needs the
    # longest sequence + widest time jump.
    seq_len = 300 if (long_horizon or deep) else 100
    test_limit = 100000 if (deep or long_horizon) else 50000
    ts_delay_max = 31536000 if long_horizon else 604800  # 1 year vs 1 week per step
    cfg = {
        "fuzzing": {
            "workers": 10, "workerResetLimit": 50, "timeout": 0,
            "testLimit": test_limit, "shrinkLimit": 5000, "callSequenceLength": seq_len,
            "pruneFrequency": 5, "corpusDirectory": "medusa-corpus",
            "coverageEnabled": True, "coverageFormats": ["html", "lcov"],
            "coverageExclusions": [], "revertReporterEnabled": False,
            "targetContracts": ["Handler"], "predeployedContracts": {},
            "targetContractsBalances": [], "constructorArgs": {},
            "deployerAddress": "0x30000",
            "senderAddresses": ["0x10000", "0x20000", "0x30000"],
            "blockNumberDelayMax": 60480, "blockTimestampDelayMax": ts_delay_max,
            "transactionGasLimit": 12500000,
            "testing": {
                "stopOnFailedTest": False, "stopOnFailedContractMatching": False,
                "stopOnNoTests": True, "testAllContracts": False,
                "testViewMethods": True, "verbosity": 1,
                "assertionTesting": {
                    "enabled": True,
                    "panicCodeConfig": {"failOnAssertion": True},
                },
                "propertyTesting": {
                    "enabled": True, "testPrefixes": ["invariant_", "property_"],
                },
                "optimizationTesting": {"enabled": True, "testPrefixes": ["optimize_"]},
                "targetFunctionSignatures": focus_sigs, "excludeFunctionSignatures": [],
            },
            "chainConfig": {
                "codeSizeCheckDisabled": True,
                "cheatCodes": {"cheatCodesEnabled": True, "enableFFI": False},
                "skipAccountChecks": True,
                "forkConfig": fork_cfg,
            },
        },
        "compilation": {
            "platform": "crytic-compile",
            "platformConfig": {"target": "test/campaign/Handler.sol",
                               "solcVersion": "", "exportDirectory": "", "args": []},
        },
        "slither": {"useSlither": True, "cachePath": "slither_results.json", "args": []},
        "logging": {"level": "info", "logDirectory": "", "noColor": False},
    }
    return json.dumps(cfg, indent=2) + "\n"


def _echidna_yaml() -> str:
    # Assertion mode catches the public invariant_* asserts; verified vs echidna 2.3.2.
    return (
        "testMode: assertion\n"
        "testLimit: 50000\n"
        "corpusDir: echidna-corpus\n"
        "coverage: true\n"
    )


def _runbook_md(task_id: str, invs: list[dict], wrappers: list[str],
                attack_path: list[str], *, economic: bool = False,
                forked: bool = False, stress: bool = False,
                dep_misbehavior: bool = False, dep_target: str = "",
                dep_assumptions: list[str] | None = None,
                multi_actor: bool = False, long_horizon: bool = False,
                attacker: bool = False) -> str:
    inv_list = "\n".join(f"- {inv['id']} [{inv.get('tool','')}] — "
                         f"{(inv['statement'] or '').strip()}" for inv in invs) \
        or "- (no bound invariants — add your hunting property to campaign/Properties.sol)"
    fork_block = (
        "## FORK MODE — medusa fuzzes the REAL deployed contracts\n"
        "`medusa.json` has `forkConfig.forkModeEnabled=true` pointed at the live fork "
        "(keyless — the local anvil or a free archive). So the stateful campaign runs "
        "against ACTUAL on-chain state: bind the real deployed addresses in "
        "`Handler.setUp()` (your SCOPE lists them) and the fuzzer drives the genuine "
        "protocol. This is the ONLY way oracle/AMM/flash-loan/economic threats test "
        "accurately — a local mock cannot move a real pool's price.\n\n"
        if forked else "")
    econ_block = (
        "## ECONOMIC / MULTI-CONTRACT attack — RUN THE CAMPAIGN, don't hand-wave\n"
        "This task spans multiple contracts / an economic chain. The handler ships "
        "flash-loan / AMM-price-move / harvest primitives (`handle_flashLoan`, "
        "`handle_ammSwapMovePrice`, `handle_triggerHarvest`) plus a protocol-solvency "
        "objective (`optimize_protocolLoss`). Wire them to the forked protocol and let "
        "**medusa compose the hops** (flash-loan → move price → harvest/withdraw → "
        "repay) while the optimizer maximises attacker PnL / protocol loss. Do NOT "
        "conclude `empty` for an economic/cross-contract task until you have actually "
        "RUN the medusa fork campaign — a hand-PoC that doesn't move real pool state is "
        "not a sufficient test of this class.\n\n"
        if economic else "")
    stress_block = (
        "## ADVERSE-MARKET STRESS — fuzz the WORLD, not just the calls (Tier-4 P1)\n"
        "This is an oracle/price/market task, so the handler ships **market-condition "
        "primitives** the fuzzer drives ALONGSIDE the protocol's own calls: "
        "`handle_stressWarpOraclePrice` (push the price the protocol reads to 0.01x–3x), "
        "`handle_stressForceOracleStale` (heartbeat-stale feed), "
        "`handle_stressSkewPoolReserves` (drain/skew the real AMM pool), "
        "`handle_stressDepegCollateral` (drop the collateral peg), "
        "`handle_stressSpikeFunding` (max out funding/utilization). Wire each to the "
        "**forked** oracle + pool (`vm.mockCall` the price feed, real swaps on the pool, "
        "`vm.warp` for staleness) — a local mock can't move a real pool. medusa then "
        "explores sequences that **interleave a market move with a protocol call**, and "
        "every invariant + `optimize_protocolLoss` is re-checked AFTER the move. The bug "
        "you are hunting here is the one that **holds at peg but goes insolvent / "
        "liquidatable / drainable under stress** — do NOT conclude `empty` for a market "
        "task until you have RUN the campaign with at least one stress wrapper wired to "
        "the forked world and watched solvency under the warp.\n\n"
        if stress else "")
    dep_block = (
        "## EXTERNAL-DEPENDENCY MISBEHAVIOR — attack the TRUST, not the code (Tier-4 P3)\n"
        f"This task does NOT hunt the in-scope code's own logic — it tests whether the "
        f"protocol stays safe when **{dep_target or 'an external dependency it trusts'}** "
        "MISBEHAVES. The protocol implicitly assumes"
        + (": " + "; ".join(f'"{a}"' for a in (dep_assumptions or [])[:4]) if dep_assumptions
           else " this dependency is honest/available")
        + ". The handler ships **mock-dep primitives** (`handle_depReturnStale`, "
        "`handle_depReturnExtreme`, `handle_depRevert`, `handle_depReentrant`, "
        "`handle_depClearMock`). Bind `depAddr` to the dependency's real deployed address, "
        "then wire each primitive to `vm.mockCall` / `vm.mockCallRevert` the dependency's "
        "actual getter selector with an ADVERSARIAL return (stale timestamp, ~0 / huge "
        "value, a revert, or a reentering mock). medusa composes these with the protocol's "
        "own `handle_*` calls and **every invariant in Properties must STILL hold** — a "
        "break is a finding that the trust assumption is unsafe (mispriced accounting, "
        "frozen withdrawals/liquidations on a dep pause, or cross-contract reentrancy). Do "
        "NOT conclude `empty` until you have RUN the campaign with the dependency actually "
        "mocked to misbehave on the fork.\n\n"
        if dep_misbehavior else "")
    multiactor_block = (
        "## MULTI-ACTOR / COLLUSION — optimize the COALITION, not one attacker (Tier-4 P5)\n"
        "This is an incentive / role-game task: the bug needs TWO roles to COLLUDE (a "
        "keeper that orders/executes + an LP/counterparty; a briber + a bribed voter). "
        "The handler ships extra actor slots (`keeper`, `lp`) and a **coalition objective** "
        "`optimize_coalitionPnL()` — wire it to the colluding actors' COMBINED value delta "
        "so medusa maximises their joint profit (model bribes/side-payments as transfers "
        "between them). The finding is one actor's *individually-rational, 'honest'* action "
        "(ordering, executing, providing liquidity) systematically enriching the coalition "
        "at the protocol's/other users' expense — invisible to a single-attacker model.\n\n"
        if multi_actor else "")
    longhorizon_block = (
        "## LONG-HORIZON / EPOCH-AWARE — let TIME pass (Tier-4 P5)\n"
        "This bug only appears after time advances (interest/funding drift, reward-rate "
        "decay, epoch/checkpoint/vesting boundaries). The handler ships a real "
        "`handle_advanceTime` step (`vm.warp`+`vm.roll`, 1h–~30d per jump) and `medusa.json` "
        "uses a LONGER `callSequenceLength` (300) + a wider per-step timestamp jump, so the "
        "fuzzer reaches deep-time state. Let medusa interleave time jumps with protocol "
        "calls and re-check every invariant + `optimize_*` at the new time — hunt drift that "
        "breaks accounting/solvency or a boundary (epoch rollover, first/last checkpoint) "
        "the code mishandles. Do NOT conclude `empty` until you have fuzzed WITH the "
        "time-advance handler active.\n\n"
        if long_horizon else "")
    attacker_block = (
        "## ATTACKER PRIMITIVES — the in-scope, attacker-triggerable class (TASK 2)\n"
        "The handler ships first-class ATTACKER primitives that use ONLY attacker-"
        "controlled inputs, so a winning sequence is directly **attacker_reachable** "
        "(payable per the adversary model — no oracle/admin/dep mock in the path):\n"
        "- `handle_donate` — transfer underlying straight INTO a vault/pool (share-price "
        "/ first-depositor inflation: WiseLending, Sonne).\n"
        "- `handle_armReentrancy` + `handle_reenter` + the reentrant `fallback()` — the "
        "handler IS the malicious receiver; re-enter mid-state-update (Orion balance "
        "inflation, read-only reentrancy).\n"
        "- `handle_composeAB` — one atomic call across TWO contracts (deposit→borrow, "
        "mint→donate→redeem), so medusa fuzzes genuine cross-contract stateful chains.\n"
        "Wire these to the FORKED deployment, then let medusa MAXIMIZE `optimize_attackerPnL` "
        "over composed sequences. CRITICAL: the reported PoC must reach impact with these "
        "attacker-only primitives — if it needs the stress/dep world-mock, it is DISCOVERY "
        "only, not a payable finding (classify honestly, keep hunting for the attacker "
        "trigger).\n\n"
        if attacker else "")
    # FUZZ SEED (T2.2) — the recon LLM's output steering the fuzzer: prioritised
    # entrypoints (medusa targetFunctionSignatures focuses calls on these) + the
    # attack-path order + the optimization objective.
    focus = ", ".join(f"handle_{w}" for w in wrappers) or "(none resolved — fuzzing all)"
    path = " → ".join(attack_path) if attack_path else "(single-region task — no chain)"
    seed_block = (
        "## FUZZ SEEDING (LLM-guided, T2.2)\n"
        f"- **Prioritised wrappers** (medusa `targetFunctionSignatures` focuses the "
        f"fuzzer on these recon-ranked entrypoints; clear it in `medusa.json` to fuzz "
        f"everything): {focus}\n"
        f"- **Attack-path order** (wire + drive the wrappers in this sequence): {path}\n"
        "- **Optimization objective** — `optimize_attackerPnL()` is enabled: medusa "
        "MAXIMIZES it, hunting the most profitable sequence. Wire `ghost_attackerPnL` "
        "to the attacker's value delta; a large positive maximum is the economic "
        "exploit (the shrunk sequence is your PoC seed). Add an `optimize_*` for "
        "protocol-solvency loss too if useful.\n"
        "- Seed the corpus with a known-interesting sequence by adding it under the "
        "medusa corpus dir, or just bias `setUp()` toward the pre-exploit state.\n\n"
    )
    return (
        f"# Layered fuzzing campaign — task {task_id}\n\n"
        + fork_block + dep_block + multiactor_block + longhorizon_block
        + stress_block + econ_block + attacker_block + seed_block +
        "One Chimera handler, three engines (Recon-Fuzz pattern). Wire "
        "`campaign/Handler.sol::setUp` + the `handle_*` wrappers to the in-scope "
        "system (import it from your TASK's repo root), then run the layers IN ORDER "
        "and feed any counterexample into a fork PoC that proves $-impact:\n\n"
        "1. **Foundry smoke** — `forge build` then a quick `forge test` to confirm the "
        "handler deploys and one sequence runs.\n"
        "2. **Medusa (stateful)** — `medusa fuzz` (config `medusa.json`). The deep "
        "engine: long random call sequences against `Handler`, asserts checked after "
        "each. A failing `invariant_*` prints the shrunk call sequence → your PoC seed.\n"
        "3. **Echidna (property)** — `echidna test/campaign/Handler.sol --contract "
        "Handler --config echidna.yaml` — a second engine over the same handler "
        "(cross-checks medusa).\n"
        "4. **Halmos (symbolic)** — `halmos --function check_` over "
        "`test/campaign/Symbolic.t.sol` — PROVE the property (no counterexample) or "
        "get an all-paths violation.\n\n"
        "Then: turn the shrunk sequence / counterexample into a **fork PoC** "
        "(`vm.createSelectFork`) that starts from a real public entrypoint and asserts "
        "the $-impact — that PoC, not the property violation alone, is the Finding.\n\n"
        "## Bound invariants for this task\n" + inv_list + "\n"
    )


# --------------------------------------------------------------------------- #
# Entry point                                                                 #
# --------------------------------------------------------------------------- #
# Vuln classes whose accurate testing REQUIRES the economic / multi-contract machinery
# (flash-loan + AMM-price-move + harvest primitives, protocol-solvency objective).
_ECONOMIC_CLASSES = {
    "flash_loan_attack", "price_oracle_manipulation", "mev_frontrunning",
    "readonly_reentrancy", "first_depositor_inflation",
}

# Vuln classes that are MARKET-CONDITION sensitive — their accurate testing needs the
# adverse-market stress layer (Tier-4 P1): the bug only appears when the WORLD the
# protocol reads (oracle price/freshness, pool reserves, collateral peg, funding) is
# pushed to a hostile-but-plausible state. s4_hunt also forces stress for these.
_STRESS_CLASSES = _ECONOMIC_CLASSES | {"denial_of_service", "arithmetic_error"}

# Vuln classes whose exploit is driven by a first-class ATTACKER PRIMITIVE (TASK 2) —
# donation/first-depositor inflation, reentrancy, flash-loan-amplified chains. These
# get the attacker-primitive handler block (handle_donate/reenter/composeAB) whose
# winning sequence is directly attacker_reachable (no world-mock in the path).
_ATTACKER_CLASSES = {
    "reentrancy", "readonly_reentrancy", "first_depositor_inflation",
    "flash_loan_attack", "price_oracle_manipulation",
}


def build_campaign(task: Any, dossier: Any, *, fork: dict | None = None,
                   stress: bool | None = None, repo_root: Any = None) -> dict[str, str]:
    """Generate the Chimera campaign scaffold for one Hunter task as a
    ``{workspace-relative path: content}`` map. Deterministic; no tool runs.

    Pulls the bound invariants + the reachable/target functions from the task's
    ``HunterDossier`` (when present) so the handler is keyed to THIS task's real
    attack surface. ``fork`` (``{rpc_url, block}``, a KEYLESS URL) turns on medusa
    fork mode so the campaign fuzzes the real deployed contracts — essential for
    accurately testing oracle/AMM/flash-loan/economic threats. Cross-contract or
    economic tasks additionally get a multi-contract handler with flash-loan/AMM/
    harvest primitives + a protocol-solvency objective.

    ``stress`` turns on the Tier-4 P1 ADVERSE-MARKET layer (``handle_stress*`` market-
    condition primitives + ghost market vars so the fuzzer warps the oracle/pool/peg/
    funding the protocol reads WHILE the invariants + PnL/solvency objectives are
    evaluated under stress). ``None`` (default) auto-enables it for market-sensitive
    vuln classes; ``True``/``False`` force it (s4_hunt forces it for oracle/market
    tasks). Stress composes with fork mode — moving a REAL pool needs the fork.

    When the task carries a ``dep_target`` (Tier-4 P3 dep-misbehavior subtype), the
    handler additionally gets ``handle_dep*`` mock-dep primitives that make the trusted
    EXTERNAL dependency return adversarial values on the fork (stale/extreme/reverting/
    reentrant) while every invariant must still hold — testing the protocol's implicit
    trust assumptions about that integration.

    Tier-4 P5: a ``multi_actor`` task adds colluding-actor slots + an
    ``optimize_coalitionPnL`` objective (the optimizer maximises the coalition's combined
    profit); a ``long_horizon`` task adds a real ``vm.warp``/``vm.roll`` time-advance
    primitive + a longer medusa ``callSequenceLength`` so funding/interest drift and
    epoch/checkpoint boundaries are reached."""
    task_id = getattr(task, "task_id", None) or (task.get("task_id") if isinstance(task, dict) else "task")
    invs = _inv_rows(getattr(dossier, "invariants", None) if dossier is not None else None)
    wrappers = _fn_wrappers(task, dossier)
    attack_path = list(getattr(task, "attack_path", None) or [])
    contracts = list(getattr(task, "contracts", None) or [])
    vc = getattr(task, "vuln_class", None)
    vc = vc.value if hasattr(vc, "value") else (vc if isinstance(vc, str) else "")
    economic = bool(len(contracts) > 1 or attack_path or vc in _ECONOMIC_CLASSES)
    stressed = bool(stress) if stress is not None else (vc in _STRESS_CLASSES)
    forked = bool(fork and fork.get("rpc_url"))

    def _flag(name: str) -> Any:
        return getattr(task, name, None) if not isinstance(task, dict) else task.get(name)

    # Tier-4 P3 — dep-misbehavior subtype (task carries an external dep to mock).
    dep_target = (_flag("dep_target") or "")
    dep_assumptions = list(_flag("dep_assumptions") or [])
    dep_misbehavior = bool(dep_target)
    # Tier-4 P5 — multi-actor coalition + long-horizon flags.
    multi_actor = bool(_flag("multi_actor"))
    long_horizon = bool(_flag("long_horizon"))
    # TASK 2: cross-contract, colluding, or attacker-primitive-class tasks get the
    # first-class attacker handlers (donation/reentrancy/compose) + a deeper campaign.
    attacker = bool(economic or multi_actor or vc in _ATTACKER_CLASSES)
    deep = bool(economic or attacker)
    # Fix A: auto-detect the repo's own deployment fixture so the Handler inherits a
    # ready-deployed system instead of a blank setUp() stub (no-op if none found).
    fixture = detect_test_fixture(repo_root, in_scope=contracts) if repo_root else None
    # Solidity scaffold lives under test/ so `forge build`/`forge test` and
    # crytic-compile (medusa/echidna) all pick it up from the Foundry project.
    return {
        "test/campaign/Properties.sol": _properties_sol(invs),
        "test/campaign/Handler.sol": _handler_sol(invs, wrappers, economic=economic,
                                                  contracts=contracts, fork=forked,
                                                  stress=stressed, dep_misbehavior=dep_misbehavior,
                                                  dep_target=dep_target,
                                                  dep_assumptions=dep_assumptions,
                                                  multi_actor=multi_actor,
                                                  long_horizon=long_horizon,
                                                  attacker=attacker, fixture=fixture),
        "test/campaign/Symbolic.t.sol": _symbolic_t_sol(invs),
        "medusa.json": _medusa_json(wrappers, fork=fork, long_horizon=long_horizon,
                                    deep=deep),
        "echidna.yaml": _echidna_yaml(),
        "CAMPAIGN.md": _runbook_md(task_id, invs, wrappers, attack_path,
                                   economic=economic, forked=forked, stress=stressed,
                                   dep_misbehavior=dep_misbehavior, dep_target=dep_target,
                                   dep_assumptions=dep_assumptions, multi_actor=multi_actor,
                                   long_horizon=long_horizon, attacker=attacker),
    }
