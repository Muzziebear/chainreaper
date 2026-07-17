"""Agent contract — the single source of truth for what an agent is allowed to do
and what it MUST produce (spec §7, §8 "schema-validated emitters / finish_task").

An ``AgentSpec`` ties together the four things the rest of the system reads:
  * the composed system prompt (built by ``agents.factory``),
  * the **read tools** the agent may use,
  * the **emitters** — the schema-validated ``chainreaper`` save-scripts the agent
    must call to persist output to ``chainreaper.db`` (with a per-agent minimum),
  * the user message that kicks off the session.

It is consumed by three places, which is why it lives on its own:
  * ``agents.session`` — derives ``--allowed-tools`` / ``--settings`` / env,
  * the ``chainreaper recon-create-*`` CLI — looks up an emitter's schema + table,
  * ``agents.hooks`` (the Stop hook) — reads ``required_spec()`` to enforce output.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace

from ..models import (
    Finding,
    FindingList,
    HunterTask,
    HunterTaskList,
    HuntOutcome,
    Invariant,
    InvariantList,
    ReconProfileInput,
    Verdict,
    VerdictList,
)

# Read tools every recon-class agent shares: native read/search + the S1 index
# helper. NO Write/Edit/Task/web — those are denied (session + hooks).
READ_TOOLS = ["Read", "Grep", "Glob", "Bash(chainreaper code-index:*)"]

# A *research* agent (Tier-4 P2 spec-research, P6 threat-research) is the ONLY mode
# that may reach the web: it READS external sources (docs / whitepaper / audits) but
# its OUTPUT is still schema-bound to the in-scope code downstream. recon/hunt/critic
# stay web-denied (session + hooks). It keeps the read/index tools too.
RESEARCH_TOOLS = ["Read", "Grep", "Glob", "WebFetch", "WebSearch",
                  "Bash(chainreaper code-index:*)"]

# The Hunter additionally writes + iterates a PoC in its sandbox workspace (the
# guard gates Write/Edit to that workspace) and runs the sandbox toolchain.
HUNT_TOOLS = ["Read", "Grep", "Glob", "Write", "Edit", "Bash(chainreaper code-index:*)"]

# Default sandbox toolchain a Hunter's Bash may invoke (basenames; the guard
# allows these + a small benign-utility set, denies everything else). The actual
# availability is resolved by ``runtime.exec.Sandbox``.
HUNT_BASH_TOOLS = [
    "forge", "cast", "anvil", "chisel", "solc",
    "slither", "medusa", "echidna", "ityfuzz", "halmos",
]


@dataclass(frozen=True)
class Emitter:
    """One schema-validated save-script the agent must call to persist output."""

    command: str               # chainreaper subcommand, e.g. "recon-create-profile"
    schema: type               # per-record Pydantic model the script validates against
    table: str                 # ReconStore table it writes to
    multiple: bool = False     # accepts a list / is called many times
    list_schema: type | None = None  # list wrapper for the API-backend batch path
    min_calls: int = 1         # successful calls the Stop hook requires


@dataclass
class AgentSpec:
    """A scoped, output-obligated agent run."""

    name: str                  # agent name, e.g. "recon"
    role: str                  # model role (config.models.<role>)
    system_prompt: str         # composed system prompt (factory)
    emitters: list[Emitter]
    user_message: str
    read_tools: list[str] = None  # type: ignore[assignment]
    mode: str = "recon"        # "recon" (read-only) | "hunt" (sandbox: Write/Edit + toolchain) | "research" (read-only + web)
    bash_tools: list[str] = field(default_factory=list)  # non-chainreaper binaries allowed in hunt mode

    def __post_init__(self) -> None:
        if self.read_tools is None:
            if self.mode == "hunt":
                self.read_tools = list(HUNT_TOOLS)
            elif self.mode == "research":
                self.read_tools = list(RESEARCH_TOOLS)
            else:
                self.read_tools = list(READ_TOOLS)

    # -- derived surfaces (consumed by session.py / hooks.py) -------------- #
    def allowed_tools(self) -> list[str]:
        """Read tools + this agent's OWN emit scripts (per-agent tool scoping)."""
        return list(self.read_tools) + [
            f"Bash(chainreaper {e.command}:*)" for e in self.emitters
        ]

    def allowed_bash(self) -> list[str]:
        """chainreaper subcommands the PreToolUse guard hook permits."""
        return ["code-index", *[e.command for e in self.emitters]]

    def required_spec(self) -> str:
        """``cmd:min,cmd:min`` — what the Stop hook enforces (env CHAINREAPER_REQUIRED)."""
        return ",".join(f"{e.command}:{e.min_calls}" for e in self.emitters)


# --------------------------------------------------------------------------- #
# Static emitter registry — the create-* CLI + the API backend look up here.   #
# --------------------------------------------------------------------------- #
RECON_EMITTERS = [
    Emitter("recon-create-profile", ReconProfileInput, "recon_profile",
            multiple=False, list_schema=None, min_calls=1),
    Emitter("recon-create-task", HunterTask, "hunter_tasks",
            multiple=True, list_schema=HunterTaskList, min_calls=8),
]
INVARIANT_EMITTERS = [
    Emitter("recon-create-invariant", Invariant, "invariants",
            multiple=True, list_schema=InvariantList, min_calls=12),
]
# Hunt (S4/S7). ``hunt-create-finding`` is OPTIONAL (min_calls=0): a hunter that
# proves nothing must not be forced to fabricate a Finding. ``hunt-finish`` is the
# REQUIRED Stop-hook obligation — every Hunter session must record a HuntOutcome
# (finding / empty / blocked), which is also the per-task outcome tally (spec §S4).
HUNT_EMITTERS = [
    Emitter("hunt-create-finding", Finding, "findings",
            multiple=True, list_schema=FindingList, min_calls=0),
    Emitter("hunt-finish", HuntOutcome, "hunt_outcomes",
            multiple=False, list_schema=None, min_calls=1),
]
# Validate (S5). One Verdict per Critic session (the Stop-hook obligation); S5
# spawns N adversarial critics per finding and aggregates their verdicts.
CRITIC_EMITTERS = [
    Emitter("critic-create-verdict", Verdict, "verdicts",
            multiple=False, list_schema=VerdictList, min_calls=1),
]
EMITTERS: dict[str, Emitter] = {
    e.command: e for e in (*RECON_EMITTERS, *INVARIANT_EMITTERS, *HUNT_EMITTERS,
                           *CRITIC_EMITTERS)
}


def recon_emitters(min_tasks: int = 8, min_invariants: int = 12) -> list[Emitter]:
    """All three emitters for the LEGACY single-session Recon agent, in workflow order
    (profile → invariants → tasks). The Stop hook enforces each minimum, so the one
    session must produce the profile, the invariant suite, AND the ranked queue. Used
    when ``recon.synthesis_mode`` is off; the synthesis path splits these in two below."""
    profile, task = RECON_EMITTERS
    (inv,) = INVARIANT_EMITTERS
    return [
        profile,
        replace(inv, min_calls=max(1, min_invariants)),
        replace(task, min_calls=max(1, min_tasks)),
    ]


def recon_explore_emitters(min_invariants: int = 12) -> list[Emitter]:
    """Phase-1 of the split Recon (``recon.synthesis_mode``): the EXPLORE+FORMALIZE
    session emits the profile + invariant suite ONLY — NO task emitter, so the Stop
    hook does not (and cannot) require tasks here. Task synthesis is a later, fully
    informed session (see :func:`recon_synthesis_emitters`)."""
    profile, _task = RECON_EMITTERS
    (inv,) = INVARIANT_EMITTERS
    return [profile, replace(inv, min_calls=max(1, min_invariants))]


def recon_synthesis_emitters(min_tasks: int = 8) -> list[Emitter]:
    """Phase-2 of the split Recon (``recon.synthesis_mode``): the SYNTHESIS session
    emits the single, unified HunterTask queue ONLY (the profile + invariants already
    exist). It is the SOLE author of the final queue, fed the recon profile, the
    invariant suite, AND the threat-research dossier — so tasks are informed by every
    source at once. The Stop hook requires only the task minimum here."""
    _profile, task = RECON_EMITTERS
    return [replace(task, min_calls=max(1, min_tasks))]


def spec_research_emitters(min_invariants: int = 3) -> list[Emitter]:
    """The Spec-Research agent's single emitter (Tier-4 P2): ``recon-create-invariant``
    — the SAME invariants table the recon agent writes to, so its intent invariants
    (``origin="spec"``) merge into the suite and flow to S4 like any other. The minimum
    is small (a target may document only a few hard promises); spec-research is additive,
    not load-bearing, so the stage tolerates a short session."""
    (inv,) = INVARIANT_EMITTERS
    return [replace(inv, min_calls=max(1, min_invariants))]


def threat_research_emitters(min_tasks: int = 3) -> list[Emitter]:
    """The Threat-Research agent's single emitter (Tier-4 P6): ``recon-create-task``
    — the SAME ``hunter_tasks`` table the recon agent writes to, so its off-checklist,
    protocol-specific HunterTasks (``origin="threat_research"``) merge with the recon
    queue and flow to S4 like any other lead. The minimum is small (genuinely novel
    leads are scarce); threat-research is additive, not load-bearing, so the stage
    tolerates a short session."""
    _, task = RECON_EMITTERS
    return [replace(task, min_calls=max(1, min_tasks))]


def hunt_emitters() -> list[Emitter]:
    """The two Hunter emitters: optional ``hunt-create-finding`` (0+) then the
    required ``hunt-finish`` outcome record. The Stop hook lets a hunter finish
    only once it has recorded its outcome (the per-task tally)."""
    return list(HUNT_EMITTERS)


def critic_emitters() -> list[Emitter]:
    """The single Critic emitter: the REQUIRED ``critic-create-verdict``. The Stop
    hook lets a critic finish only once it has recorded its adversarial verdict."""
    return list(CRITIC_EMITTERS)
