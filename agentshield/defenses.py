"""Defense interface and the tool gateway every agent must call through.

A defense can rewrite the system prompt, rewrite untrusted tool output before
the model sees it, and veto tool calls before they execute. Because all agents
reach the environment only through `ToolGateway`, any defense works with any
agent backend unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .env import TOOLS, Environment, ToolError


class Defense:
    name = "base"

    def system_prompt(self, prompt: str) -> str:
        return prompt

    def tool_output(self, tool: str, output: str, trace: list["ToolEvent"]) -> str:
        return output

    def check_call(self, tool: str, args: dict[str, Any], trace: list["ToolEvent"]) -> str | None:
        """Return a reason string to block the call, or None to allow it."""
        return None


class NoDefense(Defense):
    name = "none"


DEFENSES: dict[str, type[Defense]] = {NoDefense.name: NoDefense}


def get_defense(name: str) -> Defense:
    if name not in DEFENSES:
        raise ValueError(f"unknown defense '{name}' (available: {', '.join(DEFENSES)})")
    return DEFENSES[name]()


@dataclass
class ToolEvent:
    tool: str
    args: dict[str, Any]
    output: str
    blocked: str | None = None
    error: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {"tool": self.tool, "args": self.args, "output": self.output, "blocked": self.blocked, "error": self.error}


@dataclass
class ToolGateway:
    env: Environment
    defense: Defense
    max_calls: int = 30
    trace: list[ToolEvent] = field(default_factory=list)

    def call(self, tool: str, args: dict[str, Any]) -> str:
        if len(self.trace) >= self.max_calls:
            return self._record(tool, args, "ERROR: tool call budget exhausted", error=True)
        reason = self.defense.check_call(tool, args, self.trace)
        if reason:
            return self._record(tool, args, f"ERROR: blocked by security policy: {reason}", blocked=reason)
        try:
            output = self.env.execute(tool, args)
        except ToolError as e:
            return self._record(tool, args, f"ERROR: {e}", error=True)
        if tool in TOOLS and TOOLS[tool].untrusted_output:
            output = self.defense.tool_output(tool, output, self.trace)
        return self._record(tool, args, output)

    def _record(self, tool: str, args: dict[str, Any], output: str, blocked: str | None = None, error: bool = False) -> str:
        self.trace.append(ToolEvent(tool, dict(args), output, blocked, error))
        return output
