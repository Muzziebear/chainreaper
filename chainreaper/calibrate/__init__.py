"""Historical-hack replay calibration (T3.2 / spec §16a).

The harness's only positive control was the synthetic bench-vault. This subsystem
adds the HARD one: fork a known hack's pre-hack block and (a) reproduce it from a
reference PoC (ground truth), then (b) measure whether the harness *rediscovers*
it. Its results convert "are we missing techniques?" from opinion into data and
say whether Tier 2 is needed and for which classes.
"""

from __future__ import annotations

from .cases import ReplayCase, load_registry
from .manifest import rediscovery_overlay, score_findings, score_rediscovery
from .rediscovery import (
    RediscoveryReport,
    RediscoveryResult,
    run_rediscovery,
    run_rediscovery_suite,
)
from .replay import (
    CalibrationReport,
    ReplayResult,
    ground_truth_replay,
    run_calibration,
)

__all__ = [
    "ReplayCase",
    "load_registry",
    "ReplayResult",
    "CalibrationReport",
    "ground_truth_replay",
    "run_calibration",
    "rediscovery_overlay",
    "score_findings",
    "score_rediscovery",
    "RediscoveryResult",
    "RediscoveryReport",
    "run_rediscovery",
    "run_rediscovery_suite",
]
