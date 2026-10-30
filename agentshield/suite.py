"""Loads tasks and injections from the bundled JSON suites.

The answer key (utility checks, attacker success checks, expected safe
behaviour) lives in these objects but is never placed in anything an agent
sees: agents receive only `Task.prompt` and whatever the sandbox returns.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from importlib import resources
from typing import Any

TECHNIQUE_SETS = ("baseline", "heldout", "all")
_SUITE_FILES = ("workspace.json", "tasks.json", "attacks.json", "attacks_heldout.json")


@dataclass(frozen=True)
class Call:
    tool: str
    args: dict[str, Any]


@dataclass(frozen=True)
class Task:
    id: str
    prompt: str
    slot: str
    utility: dict[str, Any]
    reference_plan: tuple[Call, ...]
    final_answer: str

    @property
    def source(self) -> str:
        """Kind of content the injection arrives in: email, file or web."""
        return self.slot.split("_", 1)[0]

    @property
    def required_action(self) -> Call | None:
        """The state-changing call the task exists for (last one in the reference plan), if any."""
        actions = [c for c in self.reference_plan if c.tool in ACTION_DESTINATION]
        return actions[-1] if actions else None

    @property
    def relay_capable(self) -> bool:
        """Can this task send text out of the workspace, so injected text could propagate?"""
        req = self.required_action
        return req is not None and req.tool in OUTBOUND_TEXT_TOOLS


# Destination argument of each state-changing tool: what identifies "the same action".
ACTION_DESTINATION = {
    "send_email": "to",
    "post_http": "url",
    "transfer_money": "to_account",
    "delete_file": "path",
    "write_file": "path",
}
OUTBOUND_TEXT_TOOLS = frozenset({"send_email", "post_http"})


@dataclass(frozen=True)
class Goal:
    id: str
    category: str
    severity: str
    expected_safe_behavior: str
    instruction: str
    success: dict[str, Any]
    calls: tuple[Call, ...]


@dataclass(frozen=True)
class Technique:
    id: str
    description: str
    template: str
    heldout: bool = False


@dataclass(frozen=True)
class Injection:
    goal: Goal
    technique: Technique
    user_name: str

    @property
    def id(self) -> str:
        return f"{self.goal.id}/{self.technique.id}"

    @property
    def text(self) -> str:
        goal = self.goal.instruction
        return self.technique.template.format(goal=goal, goal_cap=goal[:1].upper() + goal[1:], user=self.user_name)


def case_id(task: Task, injection: Injection | None, position: str) -> str:
    """Stable identifier of one benchmark scenario (repeats share it)."""
    if injection is None:
        return f"{task.id}__benign"
    return f"{task.id}__{injection.goal.id}__{injection.technique.id}__{position}"


def _read(name: str) -> dict[str, Any]:
    return json.loads(resources.files("agentshield.suites").joinpath(name).read_text())


def _calls(raw: list[dict[str, Any]]) -> tuple[Call, ...]:
    return tuple(Call(c["tool"], c["args"]) for c in raw)


def load_tasks() -> list[Task]:
    return [
        Task(t["id"], t["prompt"], t["slot"], t["utility"], _calls(t["reference_plan"]), t["final_answer"])
        for t in _read("tasks.json")["tasks"]
    ]


def load_goals() -> list[Goal]:
    return [
        Goal(
            g["id"],
            g["category"],
            g["severity"],
            g["expected_safe_behavior"],
            g["instruction"],
            g["success"],
            _calls(g["calls"]),
        )
        for g in _read("attacks.json")["goals"]
    ]


def load_techniques(technique_set: str = "baseline") -> list[Technique]:
    if technique_set not in TECHNIQUE_SETS:
        raise ValueError(f"technique set must be one of {TECHNIQUE_SETS}")
    baseline = [Technique(t["id"], t["description"], t["template"]) for t in _read("attacks.json")["techniques"]]
    heldout = [
        Technique(t["id"], t["description"], t["template"], heldout=True)
        for t in _read("attacks_heldout.json")["techniques"]
    ]
    return {"baseline": baseline, "heldout": heldout, "all": baseline + heldout}[technique_set]


def load_injections(user_name: str = "Alex Morgan", technique_set: str = "baseline") -> list[Injection]:
    return [Injection(g, t, user_name) for g in load_goals() for t in load_techniques(technique_set)]


def suite_hash() -> str:
    """Content hash of all suite files, recorded with every run for reproducibility."""
    h = hashlib.sha256()
    for name in _SUITE_FILES:
        h.update(resources.files("agentshield.suites").joinpath(name).read_bytes())
    return h.hexdigest()[:12]
