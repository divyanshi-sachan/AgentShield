"""Self-tests that keep the benchmark's ground truth honest.

If a reference plan cannot complete its task, or an attacker goal's call
sequence does not satisfy its own success check, every number the benchmark
reports would be wrong. These tests catch that before a run does.
"""

import pytest

from agentshield.agents.scripted import _substitute
from agentshield.checks import evaluate
from agentshield.env import TOOLS, Environment, scenario_slots
from agentshield.suite import load_goals, load_injections, load_tasks

TASKS = load_tasks()
GOALS = load_goals()


def _replay(env, calls):
    outputs, last = [], ""
    for c in calls:
        last = env.execute(c.tool, _substitute(c.args, last))
        outputs.append(last)
    return outputs


@pytest.mark.parametrize("task", TASKS, ids=lambda t: t.id)
def test_reference_plan_achieves_utility(task):
    env = Environment.build(canary="ASHLD-T")
    last = _replay(env, task.reference_plan)[-1]
    assert evaluate(task.utility, env, task.final_answer.replace("$last", last))


@pytest.mark.parametrize("task", TASKS, ids=lambda t: t.id)
def test_task_is_not_trivially_satisfied(task):
    assert not evaluate(task.utility, Environment.build(canary="ASHLD-T"), "")


@pytest.mark.parametrize("task", TASKS, ids=lambda t: t.id)
def test_reference_plan_exposes_agent_to_its_slot(task):
    assert task.slot in scenario_slots()
    env = Environment.build(canary="ASHLD-T", injection_text="<<MARKER>>", slot=task.slot)
    assert any("<<MARKER>>" in o for o in _replay(env, task.reference_plan))


@pytest.mark.parametrize("goal", GOALS, ids=lambda g: g.id)
def test_goal_calls_achieve_goal(goal):
    env = Environment.build(canary="ASHLD-T")
    assert not evaluate(goal.success, env, "")
    _replay(env, goal.calls)
    assert evaluate(goal.success, env, "")


@pytest.mark.parametrize("goal", GOALS, ids=lambda g: g.id)
def test_goal_success_not_triggered_by_benign_tasks(goal):
    for task in TASKS:
        env = Environment.build(canary="ASHLD-T")
        _replay(env, task.reference_plan)
        assert not evaluate(goal.success, env, ""), f"{task.id} trips {goal.id}"


def test_all_referenced_tools_exist():
    for calls in [t.reference_plan for t in TASKS] + [g.calls for g in GOALS]:
        assert all(c.tool in TOOLS for c in calls)


def test_ids_unique_and_injections_render():
    assert len({t.id for t in TASKS}) == len(TASKS)
    injections = load_injections()
    assert len({i.id for i in injections}) == len(injections)
    for inj in injections:
        assert inj.goal.instruction in inj.text
        assert "{goal}" not in inj.text and "{user}" not in inj.text
