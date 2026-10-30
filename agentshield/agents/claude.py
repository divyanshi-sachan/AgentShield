"""Claude tool-calling agent: a manual agent loop over the sandbox tools.

A manual loop (rather than the SDK tool runner) keeps every tool call flowing
through `ToolGateway`, so defenses and tracing apply uniformly.

Controlled across defense comparisons: model, effort, system prompt (only
defenses may change it, and the change is recorded), tool definitions, turn
limit, tool-call limit and token budget. Sampling temperature cannot be fixed
on current models, so run-to-run variance is handled with `--repeats`.

Server-side refusal fallbacks are deliberately not enabled: a fallback would
let a different model finish the episode and contaminate per-model results.
Refusals are recorded as their own outcome instead.
"""

from __future__ import annotations

from typing import Any

from ..env import TOOLS
from ..gateway import ToolGateway
from ..suite import Injection, Task
from .base import AgentResult

DEFAULT_MODEL = "claude-opus-5-5"


def _sdk_version() -> str | None:
    try:
        from importlib.metadata import version

        return version("anthropic")
    except Exception:
        return None


class ClaudeAgent:
    name = "claude"

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        effort: str = "medium",
        max_turns: int = 12,
        token_budget: int = 200_000,
        timeout: float = 120.0,
        max_retries: int = 3,
        client: Any = None,
    ):
        if client is None:
            import anthropic  # optional dependency: pip install agentshield[anthropic]

            # The SDK retries 408/409/429/5xx and connection errors with backoff.
            client = anthropic.Anthropic(timeout=timeout, max_retries=max_retries)
        self.client = client
        self.model = model
        self.effort = effort
        self.max_turns = max_turns
        self.token_budget = token_budget
        self.timeout = timeout
        self.max_retries = max_retries
        self.tools = [
            {"name": t.name, "description": t.description, "input_schema": t.input_schema(), "strict": True}
            for t in TOOLS.values()
        ]

    def config(self) -> dict[str, Any]:
        return {
            "agent": self.name,
            "model": self.model,
            "effort": self.effort,
            "max_turns": self.max_turns,
            "token_budget": self.token_budget,
            "timeout": self.timeout,
            "max_retries": self.max_retries,
            "anthropic_sdk_version": _sdk_version(),
        }

    def run(self, task: Task, gateway: ToolGateway, system_prompt: str, injection: Injection | None) -> AgentResult:
        # `injection` is ignored: the real agent must never see the answer key.
        messages: list[dict[str, Any]] = [{"role": "user", "content": task.prompt}]
        usage = {"input_tokens": 0, "output_tokens": 0}
        reported: str | None = None

        for _ in range(self.max_turns):
            response = self.client.messages.create(
                model=self.model,
                max_tokens=16000,
                system=system_prompt,
                tools=self.tools,
                output_config={"effort": self.effort},
                messages=messages,
            )
            usage["input_tokens"] += response.usage.input_tokens
            usage["output_tokens"] += response.usage.output_tokens
            text = "".join(b.text for b in response.content if b.type == "text")
            reported = getattr(response, "model", None) or reported

            if response.stop_reason == "refusal":
                return AgentResult(final_answer=text, refused=True, usage=usage, model_reported=reported)
            if response.stop_reason == "max_tokens":
                return AgentResult(final_answer=text, error="max_tokens", usage=usage, model_reported=reported)

            tool_uses = [b for b in response.content if b.type == "tool_use"]
            if not tool_uses:
                return AgentResult(final_answer=text, usage=usage, model_reported=reported)
            if usage["input_tokens"] + usage["output_tokens"] > self.token_budget:
                return AgentResult(final_answer=text, error="token_budget", usage=usage, model_reported=reported)

            messages.append({"role": "assistant", "content": response.content})
            results = []
            for block in tool_uses:
                output = gateway.call(block.name, dict(block.input))
                results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": output,
                        "is_error": output.startswith("ERROR:"),
                    }
                )
            messages.append({"role": "user", "content": results})

        return AgentResult(final_answer="", error="max_turns", usage=usage, model_reported=reported)
