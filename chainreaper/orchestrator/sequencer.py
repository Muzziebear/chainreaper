"""Stage sequencer (spec §6, §15).

Owns S0..S12 ordering, JSON checkpointing, ``--resume`` and ``--stop-after`` at
stage granularity, and (later) budget enforcement. For the current slice only
S0 (stubbed) and S1 (Index) do real work; S2..S12 are pass-through stubs that
satisfy the "typed objects flow through, run checkpoints and resumes" M1 exit.

Each stage is a callable ``run(ctx) -> dict`` returning a JSON-serializable
checkpoint payload. The payload is persisted and reloaded on resume.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from ..config import Config
from ..models import Target
from .checkpoints import CheckpointStore


# --------------------------------------------------------------------------- #
# Run context                                                                  #
# --------------------------------------------------------------------------- #
@dataclass
class RunContext:
    run_id: str
    run_dir: Path
    config: Config
    target_ref: str | None = None             # raw --target arg (path/slug/url)
    target_opts: dict[str, Any] = field(default_factory=dict)  # S0 knobs: commit/allow_kyc/refresh
    store: CheckpointStore = field(init=False)
    state: dict[str, Any] = field(default_factory=dict)   # stage_id -> payload
    resume: bool = False   # run-level --resume; stages read this (e.g. S4 keeps prior outcomes)

    def __post_init__(self) -> None:
        self.run_dir = Path(self.run_dir)
        self.store = CheckpointStore(self.run_dir)

    @property
    def workspace(self) -> Path:
        return self.run_dir / "workspace"

    @property
    def index_dir(self) -> Path:
        return self.run_dir / "index"

    @property
    def target(self) -> Target | None:
        """Reconstruct the Discovery Target from the S0 checkpoint payload."""
        payload = self.state.get("s0")
        return Target.model_validate(payload) if payload else None


# --------------------------------------------------------------------------- #
# Stage registry                                                               #
# --------------------------------------------------------------------------- #
@dataclass
class Stage:
    id: str
    label: str
    fn: Callable[[RunContext], dict]


def _passthrough(stage_id: str, label: str) -> Stage:
    """A stub stage: records that it ran, passes typed state through unchanged."""
    def _run(ctx: RunContext) -> dict:
        return {"stage": stage_id, "status": "stub", "note": f"{label} not implemented yet"}
    return Stage(stage_id, label, _run)


def build_stages() -> list[Stage]:
    """Ordered S0..S12. Real stages imported lazily so the CLI stays importable
    even if an optional analysis dependency is missing."""
    from ..stages.s0_discovery import run as s0_run
    from ..stages.s1_index import run as s1_run
    from ..stages.s2_recon import run as s2_run
    from ..stages.s3_prefilter import run as s3_run
    from ..stages.s4_hunt import run as s4_run
    from ..stages.s5_validate import run as s5_run

    return [
        Stage("s0", "Discovery", s0_run),
        Stage("s1", "Index", s1_run),
        Stage("s2", "Recon", s2_run),
        Stage("s3", "Prefilter", s3_run),
        Stage("s4", "Hunt (round 1)", s4_run),
        Stage("s5", "Validate (round 1)", s5_run),
        _passthrough("s6", "Gapfill"),
        _passthrough("s7", "Hunt (round 2)"),
        _passthrough("s8", "Validate (round 2)"),
        _passthrough("s9", "Dedupe"),
        _passthrough("s10", "Trace"),
        _passthrough("s11", "Feedback"),
        _passthrough("s12", "Report"),
    ]


# --------------------------------------------------------------------------- #
# Sequencer                                                                    #
# --------------------------------------------------------------------------- #
def _normalize_stage_id(value: str | None) -> str | None:
    if value is None:
        return None
    v = value.strip().lower()
    return v if v.startswith("s") else f"s{v}"


def run_pipeline(
    ctx: RunContext,
    *,
    stop_after: str | None = None,
    resume: bool = False,
    log: Callable[[str], None] = print,
) -> dict[str, Any]:
    """Execute stages in order, checkpointing each. Returns the final state map."""
    ctx.resume = resume   # expose run-level resume to stages (S4 uses it to keep prior outcomes)
    stages = build_stages()
    stop_after = _normalize_stage_id(stop_after)
    valid_ids = {s.id for s in stages}
    if stop_after and stop_after not in valid_ids:
        raise ValueError(f"unknown --stop-after stage: {stop_after} (valid: {sorted(valid_ids)})")

    for stage in stages:
        if resume and ctx.store.exists(stage.id):
            ctx.state[stage.id] = ctx.store.load(stage.id)
            log(f"  [skip] {stage.id} {stage.label} (checkpoint reused)")
        else:
            log(f"  [run ] {stage.id} {stage.label}")
            payload = stage.fn(ctx)
            ctx.state[stage.id] = payload
            ctx.store.save(stage.id, payload)
        if stop_after and stage.id == stop_after:
            log(f"  [stop] stopped after {stage.id} ({stage.label})")
            break

    return ctx.state
