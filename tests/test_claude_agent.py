"""The Claude agent loop against a fake client (no network)."""

from types import SimpleNamespace as NS

from agentshield.agents.claude import ClaudeAgent
from agentshield.defenses import get_defense
from agentshield.env import Environment
from agentshield.gateway import ToolGateway
from agentshield.suite import load_injections, load_tasks


def _resp(stop_reason, *blocks, tokens=(10, 5)):
    return NS(stop_reason=stop_reason, content=list(blocks), usage=NS(input_tokens=tokens[0], output_tokens=tokens[1]))


class FakeMessages:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def create(self, **kwargs):
        self.requests.append(kwargs)
        return self.responses.pop(0)


def _agent(responses, **kw):
    messages = FakeMessages(responses)
    return ClaudeAgent(client=NS(messages=messages), **kw), messages


def _gw(defense="none"):
    return ToolGateway(Environment.build(canary="C"), get_defense(defense), TASK.prompt)


TASK = next(t for t in load_tasks() if t.id == "onboarding_checklist")


def test_tool_loop_routes_calls_through_gateway():
    agent, fake = _agent(
        [
            _resp(
                "tool_use",
                NS(type="tool_use", id="t1", name="fetch_url", input={"url": "https://wiki.acme.test/onboarding"}),
            ),
            _resp("end_turn", NS(type="text", text="Collect your laptop and set up SSO.")),
        ]
    )
    gw = _gw()
    result = agent.run(TASK, gw, "system", None)

    assert result.final_answer.startswith("Collect your laptop")
    assert [e.tool for e in gw.trace] == ["fetch_url"]
    assert result.usage == {"input_tokens": 20, "output_tokens": 10}
    tool_result = fake.requests[1]["messages"][-1]["content"][0]
    assert tool_result["tool_use_id"] == "t1" and "laptop" in tool_result["content"]
    first = fake.requests[0]
    assert all(t["strict"] for t in first["tools"])
    assert "temperature" not in first and first["output_config"] == {"effort": "medium"}
    assert first["model"] == "claude-opus-5-5"


def test_agent_never_sees_answer_key():
    injection = load_injections()[0]
    agent, fake = _agent([_resp("end_turn", NS(type="text", text="done"))])
    agent.run(TASK, _gw(), "system", injection)
    sent = str(fake.requests[0]["messages"]) + fake.requests[0]["system"]
    assert injection.goal.instruction not in sent and "evil.test" not in sent


def test_blocked_call_is_returned_as_error_result():
    agent, fake = _agent(
        [
            _resp(
                "tool_use", NS(type="tool_use", id="t1", name="delete_file", input={"path": "important/contracts.md"})
            ),
            _resp("end_turn", NS(type="text", text="ok")),
        ]
    )
    agent.run(TASK, _gw("D4"), "system", None)
    result = fake.requests[1]["messages"][-1]["content"][0]
    assert result["is_error"] and "blocked by security policy" in result["content"]


def test_refusal_max_turns_and_token_budget():
    agent, _ = _agent([_resp("refusal", NS(type="text", text=""))])
    assert agent.run(TASK, _gw(), "system", None).refused

    looping = [_resp("tool_use", NS(type="tool_use", id=f"t{i}", name="list_files", input={})) for i in range(12)]
    agent, _ = _agent(looping)
    assert agent.run(TASK, _gw(), "system", None).error == "max_turns"

    heavy = [_resp("tool_use", NS(type="tool_use", id="t1", name="list_files", input={}), tokens=(900, 200))]
    agent, _ = _agent(heavy, token_budget=1000)
    assert agent.run(TASK, _gw(), "system", None).error == "token_budget"
