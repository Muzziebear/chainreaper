"""Calibration case registry (T3.2). A ``ReplayCase`` is one known historical hack
the harness should reproduce + rediscover; the registry is a curated YAML
(``bench/replays/registry.yaml``) of DeFiHackLabs cases + the self-contained
synthetic positive control."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

# Default registry shipped with the repo.
DEFAULT_REGISTRY = Path(__file__).resolve().parents[2] / "bench" / "replays" / "registry.yaml"
CASES_ROOT = DEFAULT_REGISTRY.parent / "cases"


class ReplayCase(BaseModel):
    """One known exploit to calibrate against (spec §16a / memory
    chainreaper-testing-roadmap T3.2)."""

    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    chain: str = "mainnet"            # fork alias (mainnet/bsc/arbitrum/…) or "local"
    block: int | None = None          # pre-hack fork block (None ⇒ read from the PoC)
    victims: list[str] = Field(default_factory=list)   # in-scope victim addresses
    attacker: str | None = None
    loss_usd: float | None = None
    vuln_classes: list[str] = Field(default_factory=list)  # VulnClass values to rediscover
    poc_source: Literal["vendored", "url", "defihacklabs", "none"] = "none"
    poc_ref: str = ""                 # vendored dir | raw URL | DeFiHackLabs repo path
    poc_test: str = "testExploit"     # forge --match-test name in the reference PoC
    needs_fork: bool = True           # vendored synthetic cases run local (False)
    reference_url: str | None = None
    notes: str = ""

    # --- rediscovery (the billed S2→S5 measurement; `calibrate --rediscovery`) --- #
    # A case is included in the rediscovery suite only when ``rediscovery`` is True AND
    # a rediscovery target can be resolved (verified source + a fork block). The root
    # cause is the exact contract+function(s) an attacker abuses — the harness has
    # "rediscovered" the hack iff it emits a finding classed ``attacker_reachable``
    # (payable, per the adversary model) that lands on that contract+function.
    rediscovery: bool = False
    rediscovery_chain: str = ""        # source/fork chain for the victim (defaults to ``chain``)
    root_cause_contract: str = ""      # contract holding the abused entrypoint
    root_cause_functions: list[str] = Field(default_factory=list)  # abused function name(s)
    # The trigger class a CORRECT rediscovery must carry (the whole point of task 0:
    # these cases are attacker-triggerable/in-scope, so a live find is attacker_reachable).
    expected_trigger_class: str = "attacker_reachable"
    # Materialization inputs for the rediscovery run (the on-chain victim source).
    rediscovery_addresses: list[str] = Field(default_factory=list)  # verified-source addrs to pull
    rediscovery_chain_id: int | None = None

    def vendored_dir(self, root: Path = CASES_ROOT) -> Path:
        return root / self.poc_ref

    @property
    def redisc_chain(self) -> str:
        return self.rediscovery_chain or self.chain

    @property
    def redisc_addresses(self) -> list[str]:
        """Verified-source addresses to materialize (falls back to the victim list)."""
        return self.rediscovery_addresses or self.victims


def load_registry(path: str | Path | None = None) -> list[ReplayCase]:
    """Load + validate the calibration registry (defaults to the shipped one)."""
    p = Path(path) if path else DEFAULT_REGISTRY
    data = yaml.safe_load(p.read_text()) or {}
    rows = data.get("cases", data) if isinstance(data, dict) else data
    return [ReplayCase.model_validate(r) for r in (rows or [])]
