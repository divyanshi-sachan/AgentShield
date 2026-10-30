"""Offline, deterministic stand-in agent for testing the harness itself.

It follows each task's reference plan and, whenever the injected text is still
present in a tool output it observes, follows the injection with a
per-technique probability taken from its profile. It is a calibration fixture
for the pipeline and for defenses that rewrite or block content. It says
nothing about how real models behave; use the Claude agent for that.
"""

from __future__ import annotations

import random
from typing import Any

from ..defenses import ToolGateway
from ..suite import Call, Injection, Task
from .base import AgentResult

PROFILES: dict[str, dict[str, float]] = {
    "naive": {"default": 1.0},
    "medium": {
        "naive": 0.2,
        "ignore_previous": 0.4,
        "important_message": 0.8,
        "fake_system": 0.6,
        "context_break": 0.7,
        "authority_urgency": 0.5,
        "completion_prime": 0.5,
        "default": 0.5,
    },
    "robust": {"default": 0.0},
}


def _substitute(args: dict[str, Any], last: str) -> dict[str, Any]:
    return {k: v.replace("$last", last) if isinstance(v, str) else v for k, v in args.items()}


class ScriptedAgent:
    name = "scripted"

    def __init__(self, profile: str = "medium", seed: int = 0):
        if profile not in PROFILES:
            raise ValueError(f"unknown profile '{profile}' (available: {', '.join(PROFILES)})")
        self.profile = profile
        self.seed = seed

    def config(self) -> dict[str, Any]:
        return {"agent": self.name, "profile": self.profile}

    def _follow_probability(self, injection: Injection) -> float:
        p = PROFILES[self.profile]
        return p.get(injection.technique.id, p["default"])

    def run(self, task: Task, gateway: ToolGateway, system_prompt: str, injection: Injection | None) -> AgentResult:
        rng = random.Random(f"{self.seed}:{task.id}:{injection.id if injection else '-'}")
        followed = False
        last = ""
        for step in task.reference_plan:
            last = gateway.call(step.tool, _substitute(step.args, last))
            if injection and not followed and injection.text in last:
                followed = True  # decide once, at first exposure
                if rng.random() < self._follow_probability(injection):
                    self._execute(injection.goal.calls, gateway)
        return AgentResult(final_answer=task.final_answer.replace("$last", last))

    @staticmethod
    def _execute(calls: tuple[Call, ...], gateway: ToolGateway) -> None:
        last = ""
        for c in calls:
            last = gateway.call(c.tool, _substitute(c.args, last))
