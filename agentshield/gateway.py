"""The single choke point between any agent and the sandbox.

Every tool call is checked by the defense pipeline, executed (or not), and
recorded as an event with provenance and the defense decision.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from typing import Any

from .defenses import DefenseContext, ObservedText, Pipeline, ToolCall
from .env import SINK_TOOLS, Environment, ToolError


@dataclass
class ToolEvent:
    event_id: str
    tool: str
    args: dict[str, Any]
    output: str
    status: str  # "ok" | "blocked" | "error"
    source: str | None = None
    source_id: str | None = None
    trust: str | None = None
    blocked_by: str | None = None
    reason: str | None = None
    sink: bool = False
    t_ms: float = 0.0

    @property
    def blocked(self) -> bool:
        return self.status == "blocked"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ToolGateway:
    env: Environment
    defense: Pipeline
    user_prompt: str
    max_calls: int = 30
    trace: list[ToolEvent] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.ctx = DefenseContext(self.user_prompt, self.env.policy)

    def system_prompt(self, base: str) -> str:
        return self.defense.prepare_system_prompt(base, self.ctx)

    def final_answer(self, answer: str) -> str:
        return self.defense.inspect_output(answer, self.ctx)

    def call(self, tool: str, args: dict[str, Any]) -> str:
        start = time.perf_counter()
        sink = tool in SINK_TOOLS
        if len(self.trace) >= self.max_calls:
            return self._record(tool, args, "ERROR: tool call budget exhausted", "error", start, sink=sink)

        decision = self.defense.inspect_tool_call(ToolCall(tool, dict(args)), self.ctx)
        if not decision.allowed:
            msg = f"ERROR: blocked by security policy: {decision.reason}"
            return self._record(
                tool, args, msg, "blocked", start, sink=sink, blocked_by=decision.defense, reason=decision.reason
            )

        try:
            result = self.env.execute(tool, args)
        except ToolError as e:
            return self._record(tool, args, f"ERROR: {e}", "error", start, sink=sink, reason=str(e))

        prov = result.provenance
        sensitive = prov.source == "file" and self.env.is_sensitive_file(prov.source_id)
        self.ctx.observed.append(ObservedText(result.text, prov))
        self.defense.observe(result.text, prov, self.ctx, sensitive)
        text = self.defense.inspect_input(result.text, prov, self.ctx)
        return self._record(tool, args, text, "ok", start, sink=sink, prov=prov)

    def _record(self, tool, args, output, status, start, sink=False, prov=None, blocked_by=None, reason=None) -> str:
        self.trace.append(
            ToolEvent(
                event_id=f"evt-{len(self.trace) + 1:03d}",
                tool=tool,
                args=dict(args),
                output=output,
                status=status,
                source=prov.source if prov else None,
                source_id=prov.source_id if prov else None,
                trust=prov.trust if prov else None,
                blocked_by=blocked_by,
                reason=reason,
                sink=sink,
                t_ms=round((time.perf_counter() - start) * 1000, 3),
            )
        )
        return output
