"""Run logging (spec §15 observability).

A single ``chainreaper`` logger that writes to **stdout and** a per-run file,
flushing on every record — so progress is visible live even when the process is
launched headless with stdout redirected to a file (block-buffered ``print`` was
the reason S2 looked "stuck" with no output). Stage code and the agent-session
streamer both log through this.

Layout:
    runs/{run_id}/logs/pipeline.log        # the whole run, human-readable
    runs/{run_id}/logs/agent-<name>-<sid>.jsonl  # raw per-agent event stream
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

_LOGGER_NAME = "chainreaper"


def setup_logging(run_dir: str | Path, run_id: str, level: int = logging.INFO) -> logging.Logger:
    """Configure (idempotently) the run logger: flushing stdout + file handlers."""
    logs = Path(run_dir) / "logs"
    logs.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger(_LOGGER_NAME)
    logger.setLevel(level)
    logger.propagate = False
    # reconfigure cleanly each run
    for h in list(logger.handlers):
        logger.removeHandler(h)
        h.close()

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S")
    # StreamHandler/FileHandler both flush() after every emit() — the live behavior.
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    fh = logging.FileHandler(logs / "pipeline.log", encoding="utf-8")
    fh.setFormatter(fmt)
    logger.addHandler(sh)
    logger.addHandler(fh)

    logger.info("logging → %s", logs / "pipeline.log")
    return logger


def get_logger() -> logging.Logger:
    """The run logger. Falls back to a bare stdout handler if setup was skipped
    (e.g. a stage invoked outside the CLI) so messages are never silently dropped."""
    logger = logging.getLogger(_LOGGER_NAME)
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        logger.propagate = False
        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S"))
        logger.addHandler(sh)
    return logger
