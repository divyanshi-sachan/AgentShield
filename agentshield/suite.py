"""Loads tasks and injections from the bundled JSON suites."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from importlib import resources
from typing import Any


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


@dataclass(frozen=True)
class Goal:
    id: str
    category: str
    instruction: str
    success: dict[str, Any]
    calls: tuple[Call, ...]


@dataclass(frozen=True)
class Technique:
    id: str
    description: str
    template: str


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
        return self.technique.template.format(goal=self.goal.instruction, user=self.user_name)


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
        Goal(g["id"], g["category"], g["instruction"], g["success"], _calls(g["calls"]))
        for g in _read("attacks.json")["goals"]
    ]


def load_techniques() -> list[Technique]:
    return [Technique(t["id"], t["description"], t["template"]) for t in _read("attacks.json")["techniques"]]


def load_injections(user_name: str = "Alex Morgan") -> list[Injection]:
    return [Injection(g, t, user_name) for g in load_goals() for t in load_techniques()]


def suite_hash() -> str:
    """Content hash of all suite files, recorded with every run for reproducibility."""
    h = hashlib.sha256()
    for name in ("workspace.json", "tasks.json", "attacks.json"):
        h.update(resources.files("agentshield.suites").joinpath(name).read_bytes())
    return h.hexdigest()[:12]
