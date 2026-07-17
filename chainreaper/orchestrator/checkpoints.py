"""Per-stage JSON checkpoints + run state (spec §6, §15).

Layout under a run dir:

    runs/{run_id}/
      checkpoints/{stage_id}.json     # the stage's output payload
      state.json                      # ordered list of completed stage ids

Checkpoints make ``--resume`` and ``--stop-after`` work at stage granularity:
a completed stage's payload is reloaded instead of recomputed.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class CheckpointStore:
    def __init__(self, run_dir: str | Path):
        self.run_dir = Path(run_dir)
        self.ckpt_dir = self.run_dir / "checkpoints"
        self.state_path = self.run_dir / "state.json"
        self.ckpt_dir.mkdir(parents=True, exist_ok=True)

    def _path(self, stage_id: str) -> Path:
        return self.ckpt_dir / f"{stage_id}.json"

    def exists(self, stage_id: str) -> bool:
        return self._path(stage_id).exists()

    def save(self, stage_id: str, payload: Any) -> None:
        self._path(stage_id).write_text(json.dumps(payload, indent=2, default=str))
        completed = self.completed()
        if stage_id not in completed:
            completed.append(stage_id)
            self.state_path.write_text(json.dumps({"completed": completed}, indent=2))

    def load(self, stage_id: str) -> Any:
        return json.loads(self._path(stage_id).read_text())

    def completed(self) -> list[str]:
        if self.state_path.exists():
            return json.loads(self.state_path.read_text()).get("completed", [])
        return []
