"""Exercises the Claude agent loop against a fake client (no network)."""

from types import SimpleNamespace as NS

from agentshield.agents.claude import ClaudeAgent
from agentshield.defenses import NoDefense, ToolGateway
from agentshield.env import Environment
from agentshield.suite import load_tasks


def _resp(stop_reason, *blocks):
    return NS(stop_reason=stop_reason, content=list(blocks), usage=NS(input_tokens=10, output_tokens=5))


class FakeMessages:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def create(self, **kwargs):
        self.requests.append(kwargs)
        return self.responses.pop(0)


def _agent(responses):
    messages = FakeMessages(responses)
    return ClaudeAgent(client=NS(messages=messages)), messages


TASK = next(t for t in load_tasks() if t.id == "onboarding_checklist")


def test_tool_loop_routes_calls_through_gateway():
    agent, fake = _agent(
        [
            _resp("tool_use", NS(type="tool_use", id="t1", name="fetch_url", input={"url": "https://wiki.acme.test/onboarding"})),
            _resp("end_turn", NS(type="text", text="Collect your laptop and set up SSO.")),
        ]
    )
    gw = ToolGateway(Environment.build(canary="C"), NoDefense())
    result = agent.run(TASK, gw, "system", None)

    assert result.final_answer.startswith("Collect your laptop")
    assert [e.tool for e in gw.trace] == ["fetch_url"]
    assert result.usage == {"input_tokens": 20, "output_tokens": 10}
    tool_result = fake.requests[1]["messages"][-1]["content"][0]
    assert tool_result["tool_use_id"] == "t1" and "laptop" in tool_result["content"]
    assert all(t["strict"] for t in fake.requests[0]["tools"])
    assert "temperature" not in fake.requests[0]


def test_refusal_and_max_turns_are_recorded():
    agent, _ = _agent([_resp("refusal", NS(type="text", text=""))])
    gw = ToolGateway(Environment.build(canary="C"), NoDefense())
    assert agent.run(TASK, gw, "system", None).refused

    looping = [_resp("tool_use", NS(type="tool_use", id=f"t{i}", name="list_files", input={})) for i in range(12)]
    agent, _ = _agent(looping)
    result = agent.run(TASK, ToolGateway(Environment.build(canary="C"), NoDefense()), "system", None)
    assert result.error == "max_turns"
