"""Chainreaper CLI (spec §13). Slice surface: scan | resume | doctor.

`discover`/`report`/`estimate` land with their stages (S0 full / S12 / costing).
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

import typer

from .config import load_config
from .orchestrator.manifest import write_manifest
from .orchestrator.sequencer import RunContext, run_pipeline
from .runtime.logging import setup_logging

app = typer.Typer(add_completion=False, help="Chainreaper — vulnerability-discovery harness.")


@app.callback()
def _bootstrap() -> None:
    """Load persisted secrets from ``.chainreaper/env`` into the environment before any
    command runs (a real exported var always wins). Keys live outside the source tree."""
    from .keystore import load_env_files
    load_env_files()


def _new_run_id() -> str:
    return datetime.now(timezone.utc).strftime("run-%Y%m%d-%H%M%S")


def _runs_dir(cfg) -> Path:
    return Path(cfg.get("run", {}).get("runs_dir", "runs"))


@app.command()
def scan(
    target: str = typer.Option(..., "--target", "-t", help="program-id | repo-url | local path"),
    config: str | None = typer.Option(None, "--config", "-c", help="YAML config overlay"),
    stop_after: str | None = typer.Option(None, "--stop-after", help="stop after stage, e.g. s1"),
    resume: bool = typer.Option(False, "--resume", help="reuse checkpoints in the run dir"),
    run_id: str | None = typer.Option(None, "--run-id", help="explicit run id (default: timestamp)"),
    feedback_rounds: int = typer.Option(1, "--feedback-rounds"),
    max_usd: float | None = typer.Option(None, "--max-usd"),
    commit: str | None = typer.Option(None, "--commit",
        help="S0: pin the in-scope source clone(s) to this commit/tag (default: HEAD)"),
    allow_kyc: bool | None = typer.Option(None, "--allow-kyc/--no-allow-kyc",
        help="S0: proceed on a KYC-required program (default: from config "
             "discovery.filters.allow_kyc, now true). --no-allow-kyc to opt out."),
    refresh: bool = typer.Option(False, "--refresh",
        help="S0: re-pull the Immunefi program (ignore the cached snapshot)"),
    provider: str | None = typer.Option(None, "--provider",
        help="LLM backend override: anthropic (API key) | claude_cli (subscription)"),
) -> None:
    """Run S0..S12 (or up to --stop-after), checkpointed.

    --target is an Immunefi slug/URL (fetch+clone+map scope), a git repo URL, or a
    local path (offline dev mode).
    """
    overrides: dict = {"run": {"feedback_rounds": feedback_rounds, "max_usd": max_usd}}
    if provider:
        overrides["backend"] = {"provider": provider}
    cfg = load_config(config, overrides=overrides)
    rid = run_id or _new_run_id()
    run_dir = _runs_dir(cfg) / rid
    target_opts = {"commit": commit, "allow_kyc": allow_kyc, "refresh": refresh}
    ctx = RunContext(run_id=rid, run_dir=run_dir, config=cfg, target_ref=target,
                     target_opts=target_opts)
    logger = setup_logging(run_dir, rid)
    logger.info("chainreaper scan · run=%s · target=%s", rid, target)

    write_manifest(run_dir, run_id=rid, config=dict(cfg), target=None,
                   extra={"target_ref": target, "stop_after": stop_after})
    exit_code = 0
    try:
        run_pipeline(ctx, stop_after=stop_after, resume=resume, log=logger.info)
    except Exception as exc:  # surface failure, still write manifest
        exit_code = 1
        typer.secho(f"ERROR: {exc}", fg=typer.colors.RED, err=True)
    finally:
        target_payload = ctx.state.get("s0")
        write_manifest(run_dir, run_id=rid, config=dict(cfg), target=target_payload,
                       exit_code=exit_code, extra={"target_ref": target, "stop_after": stop_after})
    if exit_code:
        raise typer.Exit(exit_code)
    typer.secho(f"done · run dir: {run_dir}", fg=typer.colors.GREEN)


@app.command()
def discover(
    config: str | None = typer.Option(None, "--config", "-c", help="YAML config overlay"),
    auto_top: int | None = typer.Option(None, "--auto-top",
        help="auto-select the top-N program(s) and print the ready-to-run scan command"),
    refresh: bool = typer.Option(False, "--refresh", help="re-pull the board (ignore cache)"),
    open_source_only: bool | None = typer.Option(None, "--open-source-only",
        help="exclude programs known to be closed-source"),
    chains: list[str] = typer.Option(None, "--chains", help="filter by chain (repeatable)"),
    languages: list[str] = typer.Option(None, "--languages", help="filter by language (repeatable)"),
    min_bounty: float | None = typer.Option(None, "--min-bounty", help="minimum max-bounty USD"),
    allow_kyc: bool | None = typer.Option(None, "--allow-kyc", help="include KYC-required programs"),
    limit: int = typer.Option(40, "--limit", help="max rows to print"),
) -> None:
    """Pull + rank the Immunefi board (spec §S0 C). Deterministic, no token spend."""
    from .targets import immunefi_client as imc

    cfg = load_config(config)
    disc = dict(cfg.get("discovery", {}) or {})
    filters = dict(disc.get("filters", {}) or {})
    if open_source_only is not None:
        filters["open_source_only"] = open_source_only
    if chains:
        filters["chains"] = chains
    if languages:
        filters["languages"] = languages
    if min_bounty is not None:
        filters["min_max_bounty_usd"] = min_bounty
    if allow_kyc is not None:
        filters["allow_kyc"] = allow_kyc

    try:
        cards = imc.list_programs(filters, refresh=refresh,
                                  weights=disc.get("ranking_weights"),
                                  cache_dir=disc.get("cache_dir", "runs/_targets"))
    except Exception as exc:
        typer.secho(f"discover: failed to pull board: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1)

    if not cards:
        typer.secho("discover: no programs matched the filters", fg=typer.colors.YELLOW)
        raise typer.Exit(0)

    typer.secho(f"{'score':>6}  {'slug':24s} {'max-bounty':>13}  kyc poc  chains", bold=True)
    for c in cards[:limit]:
        kyc = "Y" if c.kyc_required else "·"
        poc = "Y" if c.poc_required else "·"
        typer.echo(f"{c.score:6.3f}  {c.slug:24s} {('$%0.0f' % (c.max_bounty_usd or 0)):>13}  "
                   f" {kyc}   {poc}  {', '.join(c.chains[:4])}")
    typer.echo(f"\n{len(cards)} programs (snapshot under {disc.get('cache_dir', 'runs/_targets')}/_board.flight)")

    if auto_top:
        picked = cards[:auto_top]
        typer.secho(f"\nauto-top {auto_top} → next:", fg=typer.colors.GREEN, bold=True)
        for c in picked:
            typer.echo(f"  chainreaper scan --target {c.slug}")


@app.command()
def resume(
    run: str = typer.Option(..., "--run", help="run id to resume"),
    config: str | None = typer.Option(None, "--config", "-c"),
    stop_after: str | None = typer.Option(None, "--stop-after"),
) -> None:
    """Reuse checkpoints and finish a run."""
    cfg = load_config(config)
    run_dir = _runs_dir(cfg) / run
    if not run_dir.exists():
        typer.secho(f"run dir not found: {run_dir}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2)
    ctx = RunContext(run_id=run, run_dir=run_dir, config=cfg, target_ref=None)
    logger = setup_logging(run_dir, run)
    logger.info("chainreaper resume · run=%s", run)
    run_pipeline(ctx, stop_after=stop_after, resume=True, log=logger.info)
    typer.secho(f"done · run dir: {run_dir}", fg=typer.colors.GREEN)


secret_app = typer.Typer(help="Manage API keys/secrets persisted under .chainreaper/ (gitignored).")
app.add_typer(secret_app, name="secret")


@secret_app.command("set")
def secret_set(
    key: str = typer.Argument(..., help="env var name, e.g. ETHERSCAN_API_KEY or ARBITRUM_RPC_URL"),
    value: str | None = typer.Argument(None, help="value (omit to persist the one already in your env)"),
) -> None:
    """Persist KEY=value to ./.chainreaper/env (chmod 600, gitignored) so it loads on every
    fresh run as an environment variable. With no value, saves the currently-exported one."""
    from .keystore import mask, set_secret
    val = value if value is not None else os.environ.get(key)
    if val is None:
        typer.secho(f"error: no value given and {key} is not set in the environment.\n"
                    f"  pass it:   chainreaper secret set {key} <value>\n"
                    f"  or export: export {key}=… && chainreaper secret set {key}",
                    fg=typer.colors.RED, err=True)
        raise typer.Exit(2)
    path = set_secret(key, val)
    typer.secho(f"saved {key}={mask(val)} → {path}", fg=typer.colors.GREEN)


@secret_app.command("list")
def secret_list() -> None:
    """List persisted secret NAMES (never values) and whether each is active in the env."""
    from .keystore import list_secret_names
    files = list_secret_names()
    if not files:
        typer.echo("no secrets persisted yet (use: chainreaper secret set <KEY> <value>)")
        return
    for path, names in files.items():
        typer.secho(path, bold=True)
        for n in names:
            active = " (active in env)" if os.environ.get(n) else ""
            typer.echo(f"  - {n}{active}")


@secret_app.command("path")
def secret_path() -> None:
    """Print the project secret-file path (./.chainreaper/env)."""
    from .keystore import env_file
    typer.echo(str(env_file()))


@app.command()
def doctor() -> None:
    """Verify toolchain + bootstrap (IMPL-NOTES §1)."""
    ok = True

    def check(name: str, passed: bool, detail: str = "") -> None:
        nonlocal ok
        ok = ok and passed
        mark = typer.style("OK ", fg=typer.colors.GREEN) if passed else typer.style("MISS", fg=typer.colors.RED)
        typer.echo(f"  [{mark}] {name}{(' — ' + detail) if detail else ''}")

    def warn(name: str, passed: bool, detail: str = "") -> None:
        """Non-fatal: needed by a later stage, not by S0/S1. Flagged, not failed."""
        mark = (typer.style("OK  ", fg=typer.colors.GREEN) if passed
                else typer.style("WARN", fg=typer.colors.YELLOW))
        typer.echo(f"  [{mark}] {name}{(' — ' + detail) if detail else ''}")

    import sys
    py_ok = sys.version_info >= (3, 11)
    check("python >= 3.11", py_ok, sys.version.split()[0])

    slither = shutil.which("slither")
    check("slither on PATH", bool(slither), slither or "not found; need /usr/local/py-utils/bin")
    if slither:
        try:
            first = Path(slither).read_text(errors="replace").splitlines()[0]
            interp = first[2:].strip() if first.startswith("#!") else "?"
            check("slither interpreter resolvable", interp != "?", interp)
        except OSError:
            check("slither interpreter resolvable", False)

    forge = shutil.which("forge")
    check("forge on PATH (S4)", bool(forge),
          forge or "missing; add $HOME/.foundry/bin to PATH (not needed for S1)")

    # Stateful/economic fuzzing layer (T1.1) — resolved through the SAME augmented
    # PATH the S2/S4 sandbox uses (so `doctor` agrees with the harness). Non-fatal:
    # needed only from S4 (and only for invariants routed to them); flagged if absent.
    from .runtime.exec import augmented_env
    fuzz_path = augmented_env().get("PATH", "")
    for tool, note in (("medusa", "stateful invariant fuzzer (Chimera campaign)"),
                       ("echidna", "property fuzzer"),
                       ("ityfuzz", "bytecode/economic fuzzer (fork detectors)")):
        loc = shutil.which(tool, path=fuzz_path)
        warn(f"{tool} on PATH (S4 fuzzing)", bool(loc),
             loc or f"missing — {note}; install to ~/.fuzzers/bin (see T1.1)")

    try:
        import pydantic  # noqa: F401
        import yaml  # noqa: F401
        check("core deps (pydantic, pyyaml, typer)", True)
    except ImportError as exc:
        check("core deps (pydantic, pyyaml, typer)", False, str(exc))

    tools_poc = Path("tools_poc/setup")
    check("tools_poc setup present", tools_poc.exists(), str(tools_poc))

    # S2+ (first model-calling stage) — non-fatal for S0/S1; one of the two
    # backends must be usable from S2 onward (provider chosen in config).
    import os
    try:
        import anthropic  # noqa: F401
        warn("anthropic SDK (S2+, provider=anthropic)", True, f"v{anthropic.__version__}")
    except ImportError:
        warn("anthropic SDK (S2+, provider=anthropic)", False, "run: pip install -e '.[agents]'")
    warn("ANTHROPIC_API_KEY set (provider=anthropic)", bool(os.environ.get("ANTHROPIC_API_KEY")),
         "required only when backend.provider=anthropic")

    # Secrets loaded from .chainreaper/env (the callback ran before this command).
    from .keystore import env_file, mask
    ef = env_file()
    warn("ETHERSCAN_API_KEY set (S0 verified-source = source of truth)",
         bool(os.environ.get("ETHERSCAN_API_KEY")),
         (mask(os.environ.get("ETHERSCAN_API_KEY")) if os.environ.get("ETHERSCAN_API_KEY")
          else f"persist it: chainreaper secret set ETHERSCAN_API_KEY <key>  (→ {ef})"))
    warn("ARBITRUM_RPC_URL set (S4 fork PoCs)", bool(os.environ.get("ARBITRUM_RPC_URL")),
         "archive RPC for createSelectFork; optional until S4")
    claude = shutil.which("claude")
    warn("claude CLI (provider=claude_cli)", bool(claude),
         (claude or "not found") + " — subscription-backed backend; no API key needed")

    if not ok:
        raise typer.Exit(1)
    typer.secho("doctor: all required checks passed", fg=typer.colors.GREEN)


@app.command()
def calibrate(
    case: str | None = typer.Option(None, "--case", help="run only this case id"),
    registry: str | None = typer.Option(None, "--registry", help="path to a cases registry YAML"),
    work_dir: str = typer.Option("runs/_calibrate", "--work-dir", help="sandbox/work dir"),
    rediscovery: bool = typer.Option(False, "--rediscovery",
        help="MEASURE THE CEILING: run the BILLED S1→S5 pipeline against each "
             "attacker-triggerable/in-scope hack's victim (fork pinned pre-hack) and "
             "score whether the harness rediscovers the root cause. Costs TOKENS."),
) -> None:
    """Historical-hack replay calibration (T3.2).

    Default mode (compute, not tokens) — fork each case's pre-hack block and run its
    reference PoC to confirm the known exploit REPRODUCES (the hard positive control).
    Fork cases need an archive ``<CHAIN>_RPC_URL`` (resolved from env /
    .chainreaper/env); local synthetic cases run with no RPC.

    ``--rediscovery`` mode (BILLED) — the task-0 capability measurement: run the full
    pipeline on each ``rediscovery: true`` case's victim and print a rediscovery-rate
    table (attacker_reachable finding landing on the known root cause = rediscovered).
    """
    from .calibrate import load_registry
    cases = load_registry(registry)
    if case:
        cases = [c for c in cases if c.id == case]
        if not cases:
            typer.secho(f"no case with id {case!r} in the registry", fg=typer.colors.RED, err=True)
            raise typer.Exit(1)

    if rediscovery:
        from .calibrate import run_rediscovery_suite
        subset = [c for c in cases if c.rediscovery]
        if not subset:
            typer.secho("no rediscovery-enabled cases in the registry "
                        "(set `rediscovery: true` + root_cause on a case)",
                        fg=typer.colors.YELLOW)
            raise typer.Exit(0)
        typer.secho(f"rediscovery: BILLED pipeline over {len(subset)} case(s) — "
                    "S1 index → S2 recon → S3 → S4 hunt → S5 validate", bold=True)
        report = run_rediscovery_suite(subset, work_dir=work_dir)
        typer.echo(report.scorecard())
        return

    # RPC URLs come from the environment (<CHAIN>_RPC_URL), loaded by the callback.
    from .calibrate import run_calibration
    report = run_calibration(cases, work_dir=work_dir)
    typer.echo(report.scorecard())
    # Non-zero exit if any case that ACTUALLY RAN failed to reproduce (a skip — no
    # RPC / no PoC — is not a failure of the harness).
    if report.failed:
        raise typer.Exit(1)


# --------------------------------------------------------------------------- #
# Helper subcommands — the tool + save-script surface the claude_cli agent calls #
# via Bash: `code-index` (read), `recon-create-*` (emit), `hook-*` (enforce).    #
# --------------------------------------------------------------------------- #
@app.command("code-index")
def code_index_cmd(
    kind: str = typer.Argument(..., help="contract|function|entrypoints|callers|callees|"
                               "writers|readers|external_calls_in|sinks|inheritance|"
                               "storage_layout|proxy_info|sast"),
    args: str = typer.Argument("{}", help='JSON args, e.g. \'{"contract":"MarketUtils"}\''),
    db: str | None = typer.Option(None, "--db", envvar="CHAINREAPER_INDEX_DB",
                                  help="path to the S1 index.db (or CHAINREAPER_INDEX_DB)"),
) -> None:
    """Query the S1 structural code index (read-only). Prints JSON rows."""
    import json
    from .tools.code_index import query as ci_query
    if not db:
        typer.secho("error: no index db (pass --db or set CHAINREAPER_INDEX_DB)", err=True)
        raise typer.Exit(2)
    try:
        parsed = json.loads(args) if args.strip() else {}
    except json.JSONDecodeError as exc:
        typer.secho(f"error: args is not valid JSON: {exc}", err=True)
        raise typer.Exit(2)
    try:
        rows = ci_query(db, kind, parsed)
    except Exception as exc:  # clean error (no traceback) so the agent can self-correct
        typer.secho(f"error: code-index {kind} {parsed}: {type(exc).__name__}: {exc}", err=True)
        raise typer.Exit(2)
    typer.echo(json.dumps({"kind": kind, "count": len(rows), "rows": rows[:60]}, default=str))


# the schema-validated save-scripts (spec §8) every claude_cli agent MUST call to
# persist its output to the per-run chainreaper.db — one per emit-schema. Logic in
# agents/emitters.py (unit-testable); DB + run/agent/session come from the session
# environment the backend sets.
def _emit_env() -> tuple[str, str, str, str]:
    db = os.environ.get("CHAINREAPER_ARTIFACT_DB", "")
    if not db:
        typer.secho("error: no artifact db (CHAINREAPER_ARTIFACT_DB unset)", err=True)
        raise typer.Exit(2)
    return (db, os.environ.get("CHAINREAPER_RUN_ID", ""),
            os.environ.get("CHAINREAPER_AGENT", ""),
            os.environ.get("CHAINREAPER_SESSION", ""))


def _run_emitter(command: str, infile: str | None) -> None:
    from .agents.emitters import EmitError, create_record
    db, run_id, agent, session = _emit_env()
    try:
        raw = Path(infile).read_text() if infile else sys.stdin.read()
    except OSError as exc:
        typer.secho(f"error: cannot read input: {exc}", err=True)
        raise typer.Exit(2)
    try:
        res = create_record(command, raw, db=db, run_id=run_id, agent=agent, session=session)
    except EmitError as exc:
        typer.secho(f"VALIDATION ERROR ({command}): {exc}", err=True)
        if exc.schema:
            typer.secho("\nEXPECTED JSON SCHEMA:\n" + json.dumps(exc.schema, indent=1), err=True)
        raise typer.Exit(1)
    typer.secho(f"OK: {command} saved {res['count']} record(s) → {res['table']}",
                fg=typer.colors.GREEN)


@app.command("recon-create-profile")
def recon_create_profile(
    infile: str | None = typer.Option(None, "--in", help="JSON file (else stdin)"),
) -> None:
    """Validate + persist the Recon profile (ReconProfileInput) to chainreaper.db."""
    _run_emitter("recon-create-profile", infile)


@app.command("recon-create-task")
def recon_create_task(
    infile: str | None = typer.Option(None, "--in", help="JSON object or array (else stdin)"),
) -> None:
    """Validate + persist one or more HunterTasks to chainreaper.db."""
    _run_emitter("recon-create-task", infile)


@app.command("recon-create-invariant")
def recon_create_invariant(
    infile: str | None = typer.Option(None, "--in", help="JSON object or array (else stdin)"),
) -> None:
    """Validate + persist one or more Invariants to chainreaper.db."""
    _run_emitter("recon-create-invariant", infile)


@app.command("hunt-create-finding")
def hunt_create_finding(
    infile: str | None = typer.Option(None, "--in", help="JSON object or array (else stdin)"),
) -> None:
    """Validate + persist one or more Findings (each with its PoC) to chainreaper.db."""
    _run_emitter("hunt-create-finding", infile)


@app.command("hunt-finish")
def hunt_finish(
    infile: str | None = typer.Option(None, "--in", help="JSON object (else stdin)"),
) -> None:
    """Validate + persist the Hunter's required HuntOutcome to chainreaper.db."""
    _run_emitter("hunt-finish", infile)


@app.command("critic-create-verdict")
def critic_create_verdict(
    infile: str | None = typer.Option(None, "--in", help="JSON object (else stdin)"),
) -> None:
    """Validate + persist the Critic's required adversarial Verdict to chainreaper.db."""
    _run_emitter("critic-create-verdict", infile)


# Claude Code hooks the agent session runs (PreToolUse / Stop): the harness-level
# enforcement layer — deny off-list tools, and block stop until the required
# save-scripts have produced their rows. Logic in agents/hooks.py.
@app.command("hook-guard")
def hook_guard() -> None:
    """PreToolUse hook: deny tools/commands outside the agent's allowed set."""
    from .agents.hooks import decide_guard
    raw = sys.stdin.read()
    try:
        data = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        data = {}
    code, out = decide_guard(data, os.environ)
    if out:
        typer.echo(out)
    raise typer.Exit(code)


@app.command("hook-stop")
def hook_stop() -> None:
    """Stop hook: block finishing until the required output rows exist."""
    from .agents.hooks import decide_stop_env
    try:
        sys.stdin.read()
    except Exception:
        pass
    code, out = decide_stop_env(os.environ)
    if out:
        typer.echo(out)
    raise typer.Exit(code)


if __name__ == "__main__":
    app()
