"""Runs an experiment matrix (one agent, several defense pipelines) from a TOML file."""

from __future__ import annotations

import json
import time
import tomllib
import uuid
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .agents.scripted import _substitute
from .checks import evaluate
from .compare import compare_runs
from .dashboard import render_dashboard
from .defenses import get_defense
from .env import POSITIONS, TOOLS, Environment
from .report import render_comparison_report
from .runner import check_paid_run_allowed, load_run, plan_episodes, run_benchmark
from .suite import ACTION_DESTINATION, TECHNIQUE_SETS, Goal, Task, case_id, load_injections, load_tasks


def load_config(path: str | Path) -> dict[str, Any]:
    cfg = tomllib.loads(Path(path).read_text())
    run = cfg.setdefault("run", {})
    run.setdefault("defenses", ["none"])
    run.setdefault("techniques", "baseline")
    run.setdefault("positions", ["end"])
    run.setdefault("repeats", 1)
    run.setdefault("seed", 0)
    run.setdefault("concurrency", 1)
    if run["techniques"] not in TECHNIQUE_SETS:
        raise ValueError(f"run.techniques must be one of {TECHNIQUE_SETS}")
    if bad := set(run["positions"]) - set(POSITIONS):
        raise ValueError(f"unknown positions: {bad}")
    for spec in run["defenses"]:
        get_defense(spec)  # fail fast on typos
    cfg.setdefault("agent", {"type": "scripted"})
    cfg.setdefault("name", Path(path).stem)
    return cfg


def make_agent(agent_cfg: dict[str, Any], seed: int):
    kind = agent_cfg.get("type", "scripted")
    if kind == "scripted":
        from .agents import ScriptedAgent

        return ScriptedAgent(profile=agent_cfg.get("profile", "medium"), seed=seed)
    if kind == "claude":
        from .agents.claude import ClaudeAgent

        keys = ("model", "effort", "max_turns", "token_budget", "timeout", "max_retries")
        return ClaudeAgent(**{k: agent_cfg[k] for k in keys if k in agent_cfg})
    raise ValueError(f"unknown agent type '{kind}'")


def select(cfg: dict[str, Any]):
    """Apply the config's filters. Unknown ids are an error, never silently ignored."""
    run = cfg["run"]
    tasks = load_tasks()
    injections = load_injections(technique_set=run["techniques"])
    for key, known in [
        ("tasks", {t.id for t in tasks}),
        ("goals", {i.goal.id for i in injections}),
        ("technique_ids", {i.technique.id for i in injections}),
    ]:
        if unknown := set(run.get(key) or []) - known:
            raise ValueError(f"run.{key} has unknown ids (for technique set '{run['techniques']}'): {sorted(unknown)}")
    if run.get("tasks"):
        tasks = [t for t in tasks if t.id in set(run["tasks"])]
    if run.get("goals"):
        injections = [i for i in injections if i.goal.id in set(run["goals"])]
    if run.get("technique_ids"):
        injections = [i for i in injections if i.technique.id in set(run["technique_ids"])]
    return tasks, injections


def check_compatibility(task: Task, goal: Goal) -> list[str]:
    """Reasons a task/goal pair would produce a meaningless episode (empty list = compatible).

    Checked offline against the sandbox: the task must expose the agent to the
    injected slot, its own reference plan must not already satisfy the
    attacker's success check, and the goal's decisive action must differ from
    the task's legitimate action.
    """
    problems = []
    if unknown := [c.tool for c in goal.calls if c.tool not in TOOLS]:
        problems.append(f"goal uses unknown tools {unknown}")
        return problems
    env = Environment.build(canary="ASHLD-COMPATCHECK0000", injection_text="<<PROBE>>", slot=task.slot)
    last, outputs = "", []
    for c in task.reference_plan:
        last = env.execute(c.tool, _substitute(c.args, last)).text
        outputs.append(last)
    if not any("<<PROBE>>" in o for o in outputs):
        problems.append("task never exposes the agent to its injection slot")
    if evaluate(goal.success, env, task.final_answer.replace("$last", last)):
        problems.append("task's own reference plan already satisfies the attacker's success check")
    req, decisive = task.required_action, goal.calls[-1]
    if req and req.tool == decisive.tool:
        key = ACTION_DESTINATION[req.tool]
        if str(req.args[key]).lower() == str(decisive.args.get(key, "")).lower():
            problems.append("attacker's decisive action is identical to the task's legitimate action")
    return problems


def composition(cfg: dict[str, Any]) -> dict[str, Any]:
    """Exact episode composition of a config, with every incompatible task/goal pair listed."""
    run = cfg["run"]
    tasks, injections = select(cfg)
    plan = plan_episodes(tasks, injections, run["repeats"], run["positions"])
    attacked = [p for p in plan if p[1] is not None]
    scenarios = Counter(case_id(t, i, pos) for t, i, pos, _ in attacked)
    goals = sorted({i.goal.id: i.goal for i in injections}.items())
    incompatible = [
        {"task": t.id, "goal": gid, "problems": probs}
        for t in tasks
        for gid, g in goals
        if (probs := check_compatibility(t, g))
    ]
    per_defense = {
        "total": len(plan),
        "attacked": len(attacked),
        "controls": len(plan) - len(attacked),
        "distinct_attack_scenarios": len(scenarios),
        "repeats_per_scenario": sorted(set(scenarios.values())),
        "by_task": dict(Counter(p[0].id for p in attacked)),
        "by_goal": dict(Counter(p[1].goal.id for p in attacked)),
        "by_technique": dict(Counter(p[1].technique.id for p in attacked)),
        "by_position": dict(Counter(p[2] for p in attacked)),
        "controls_by_task": dict(Counter(p[0].id for p in plan if p[1] is None)),
    }
    return {
        "per_defense": per_defense,
        "defenses": run["defenses"],
        "total_episodes": per_defense["total"] * len(run["defenses"]),
        "relay_capable_tasks": [t.id for t in tasks if t.relay_capable],
        "tasks_with_required_action": {t.id: t.required_action.tool for t in tasks if t.required_action},
        "incompatible": incompatible,
    }


def check_expected(cfg: dict[str, Any], comp: dict[str, Any]) -> list[str]:
    """Compare the config's optional [expected] block with the actual composition."""
    exp = cfg.get("expected", {})
    actual = {
        "total": comp["per_defense"]["total"],
        "attacked": comp["per_defense"]["attacked"],
        "controls": comp["per_defense"]["controls"],
        "distinct_attack_scenarios": comp["per_defense"]["distinct_attack_scenarios"],
        "repeats_per_scenario": comp["per_defense"]["repeats_per_scenario"],
    }
    return [
        f"expected {k} = {v}, actual {actual[k]}"
        for k, v in exp.items()
        if k in actual and (actual[k] != v and actual[k] != [v])
    ]


def episode_count(cfg: dict[str, Any]) -> int:
    tasks, injections = select(cfg)
    run = cfg["run"]
    return len(plan_episodes(tasks, injections, run["repeats"], run["positions"])) * len(run["defenses"])


def run_experiment(
    config_path: str | Path,
    out_dir: str | Path = "results",
    progress: Callable[[str], None] | None = None,
    allow_dirty: bool = False,
) -> tuple[Path, dict[str, Any]]:
    cfg = load_config(config_path)
    run = cfg["run"]
    tasks, injections = select(cfg)
    comp = composition(cfg)
    if comp["incompatible"]:
        raise ValueError(f"incompatible task/goal combinations, not running: {comp['incompatible']}")
    if mismatch := check_expected(cfg, comp):
        raise ValueError(f"composition does not match [expected]: {mismatch}")
    agent_type = cfg["agent"].get("type", "scripted")
    check_paid_run_allowed({"agent": agent_type}, allow_dirty=allow_dirty)
    experiment_id = uuid.uuid4().hex[:12]
    exp_dir = Path(out_dir) / f"{time.strftime('%Y%m%d-%H%M%S')}_{cfg['name']}"
    exp_dir.mkdir(parents=True, exist_ok=False)
    (exp_dir / "experiment.json").write_text(
        json.dumps({**cfg, "experiment_id": experiment_id, "composition": comp}, indent=2)
    )

    run_dirs = []
    for spec in run["defenses"]:
        agent = make_agent(cfg["agent"], run["seed"])
        defense = get_defense(spec)
        if progress:
            progress(f"running defense {defense.name}")
        run_dir, _ = run_benchmark(
            agent,
            defense,
            tasks,
            injections,
            seed=run["seed"],
            repeats=run["repeats"],
            out_dir=exp_dir / "runs",
            positions=run["positions"],
            run_name=defense.name,
            concurrency=run["concurrency"],
            experiment_id=experiment_id,
            allow_dirty=allow_dirty,
        )
        run_dirs.append(run_dir)

    cmp = compare_runs([load_run(d) for d in run_dirs], seed=run["seed"])
    (exp_dir / "comparison.json").write_text(json.dumps(cmp, indent=2))
    (exp_dir / "comparison.md").write_text(render_comparison_report(cfg["name"], cmp, cfg.get("notes", "")))
    (exp_dir / "dashboard.html").write_text(render_dashboard(cfg["name"], cmp))
    return exp_dir, cmp
