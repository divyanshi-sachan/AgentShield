import json

from agentshield.agents import ScriptedAgent
from agentshield.defenses import Defense, NoDefense, ToolGateway
from agentshield.env import Environment
from agentshield.runner import plan_episodes, run_benchmark, wilson
from agentshield.suite import load_injections, load_tasks

TASKS = load_tasks()
INJECTIONS = load_injections()


def run(profile, tmp_path, defense=None, seed=0):
    agent = ScriptedAgent(profile=profile, seed=seed)
    return run_benchmark(agent, defense or NoDefense(), TASKS, INJECTIONS, seed=seed, out_dir=tmp_path)


def test_plan_size():
    assert len(plan_episodes(TASKS, INJECTIONS, repeats=2)) == 2 * len(TASKS) * (len(INJECTIONS) + 1)


def test_naive_agent_is_fully_compromised_and_robust_is_not(tmp_path):
    _, naive = run("naive", tmp_path)
    _, robust = run("robust", tmp_path)
    assert naive["attack_success_rate"]["rate"] == 1.0
    assert robust["attack_success_rate"]["rate"] == 0.0
    assert naive["benign_utility"]["rate"] == robust["benign_utility"]["rate"] == 1.0


def test_medium_profile_is_deterministic_and_partial(tmp_path):
    _, a = run("medium", tmp_path / "a")
    _, b = run("medium", tmp_path / "b")
    assert a["attack_success_rate"] == b["attack_success_rate"]
    assert 0.0 < a["attack_success_rate"]["rate"] < 1.0


def test_back_to_back_runs_get_separate_directories(tmp_path):
    first, _ = run("robust", tmp_path)
    second, _ = run("robust", tmp_path)
    assert first != second and (first / "summary.json").exists() and (second / "summary.json").exists()


def test_run_writes_artifacts(tmp_path):
    run_dir, summary = run("medium", tmp_path)
    lines = (run_dir / "episodes.jsonl").read_text().splitlines()
    assert len(lines) == summary["episodes"]
    first = json.loads(lines[0])
    assert first["injection_id"] is None and first["trace"]
    assert json.loads((run_dir / "summary.json").read_text())["config"]["suite_hash"]
    assert "Attack success rate" in (run_dir / "report.md").read_text()


class BlockAllSinks(Defense):
    name = "test-block-sinks"

    def check_call(self, tool, args, trace):
        return "sink" if tool in {"send_email", "post_http", "transfer_money", "delete_file"} else None


def test_defense_hook_changes_outcomes_and_counts_false_positives(tmp_path):
    _, m = run("naive", tmp_path, defense=BlockAllSinks())
    assert m["attack_success_rate"]["rate"] == 0.0
    assert m["benign_blocked_calls"] > 0  # it also blocks legitimate sends and payments
    assert m["benign_utility"]["rate"] < 1.0


def test_gateway_budget_and_errors():
    gw = ToolGateway(Environment.build(canary="C"), NoDefense(), max_calls=1)
    assert gw.call("read_file", {"path": "missing"}).startswith("ERROR:")
    assert "budget" in gw.call("list_files", {})


def test_wilson_bounds():
    lo, hi = wilson(5, 10)
    assert 0.2 < lo < 0.5 < hi < 0.8
    assert wilson(0, 0) == (0.0, 0.0)
