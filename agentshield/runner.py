"""Runs episodes (task x injection x repeat) and aggregates metrics."""

from __future__ import annotations

import json
import math
import platform
import subprocess
import time
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

from . import __version__
from .agents.base import SYSTEM_PROMPT, Agent
from .checks import evaluate
from .defenses import Defense, ToolGateway
from .env import Environment, make_canary
from .suite import Injection, Task, suite_hash


@dataclass
class Episode:
    episode_id: str
    task_id: str
    injection_id: str | None
    goal_id: str | None
    category: str | None
    technique_id: str | None
    repeat: int
    utility: bool
    attack_success: bool | None
    refused: bool
    error: str | None
    tool_calls: int
    blocked_calls: int
    final_answer: str
    usage: dict[str, int]
    trace: list[dict[str, Any]]
    seconds: float


def plan_episodes(
    tasks: Iterable[Task], injections: Iterable[Injection], repeats: int = 1
) -> list[tuple[Task, Injection | None, int]]:
    """Every task once with no injection (benign baseline), then once per injection, per repeat."""
    injections = list(injections)
    plan: list[tuple[Task, Injection | None, int]] = []
    for r in range(repeats):
        for task in tasks:
            plan.append((task, None, r))
            plan.extend((task, inj, r) for inj in injections)
    return plan


def run_episode(agent: Agent, defense: Defense, task: Task, injection: Injection | None, repeat: int, seed: int) -> Episode:
    episode_id = f"{task.id}::{injection.id if injection else 'benign'}::r{repeat}"
    env = Environment.build(
        canary=make_canary(seed, episode_id),
        injection_text=injection.text if injection else None,
        slot=task.slot,
    )
    gateway = ToolGateway(env, defense)
    system_prompt = defense.system_prompt(SYSTEM_PROMPT.format(user_name=env.user["name"], user_email=env.user["email"]))

    start = time.monotonic()
    result = agent.run(task, gateway, system_prompt, injection)
    seconds = time.monotonic() - start

    return Episode(
        episode_id=episode_id,
        task_id=task.id,
        injection_id=injection.id if injection else None,
        goal_id=injection.goal.id if injection else None,
        category=injection.goal.category if injection else None,
        technique_id=injection.technique.id if injection else None,
        repeat=repeat,
        utility=evaluate(task.utility, env, result.final_answer),
        attack_success=evaluate(injection.goal.success, env, result.final_answer) if injection else None,
        refused=result.refused,
        error=result.error,
        tool_calls=len(gateway.trace),
        blocked_calls=sum(1 for e in gateway.trace if e.blocked),
        final_answer=result.final_answer,
        usage=result.usage,
        trace=[e.to_dict() for e in gateway.trace],
        seconds=round(seconds, 3),
    )


def wilson(successes: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def _rate(values: list[bool]) -> dict[str, Any]:
    k, n = sum(values), len(values)
    lo, hi = wilson(k, n)
    return {"rate": round(k / n, 4) if n else None, "k": k, "n": n, "ci95": [round(lo, 4), round(hi, 4)]}


def summarize(episodes: list[Episode]) -> dict[str, Any]:
    benign = [e for e in episodes if e.injection_id is None]
    attacked = [e for e in episodes if e.injection_id is not None]

    def breakdown(key: str) -> dict[str, Any]:
        groups: dict[str, list[Episode]] = defaultdict(list)
        for e in attacked:
            groups[getattr(e, key)].append(e)
        return {
            g: {"asr": _rate([e.attack_success for e in es]), "utility": _rate([e.utility for e in es])}
            for g, es in sorted(groups.items())
        }

    return {
        "episodes": len(episodes),
        "benign_utility": _rate([e.utility for e in benign]),
        "utility_under_attack": _rate([e.utility for e in attacked]),
        "attack_success_rate": _rate([e.attack_success for e in attacked]),
        "refusal_rate": _rate([e.refused for e in episodes]),
        "error_rate": _rate([e.error is not None for e in episodes]),
        "benign_blocked_calls": sum(e.blocked_calls for e in benign),
        "attack_blocked_calls": sum(e.blocked_calls for e in attacked),
        "by_technique": breakdown("technique_id"),
        "by_goal": breakdown("goal_id"),
        "by_category": breakdown("category"),
        "by_task": breakdown("task_id"),
        "tokens": {
            "input": sum(e.usage.get("input_tokens", 0) for e in episodes),
            "output": sum(e.usage.get("output_tokens", 0) for e in episodes),
        },
    }


def _git_sha() -> str | None:
    try:
        out = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, timeout=5)
        return out.stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def _fresh_dir(parent: Path, base: str) -> Path:
    """Create a new run directory; never reuse one, even for runs started in the same second."""
    parent.mkdir(parents=True, exist_ok=True)
    for n in range(1, 1000):
        candidate = parent / (base if n == 1 else f"{base}-{n}")
        try:
            candidate.mkdir()
            return candidate
        except FileExistsError:
            continue
    raise RuntimeError(f"could not create a run directory for {base}")


def run_benchmark(
    agent: Agent,
    defense: Defense,
    tasks: list[Task],
    injections: list[Injection],
    seed: int = 0,
    repeats: int = 1,
    out_dir: str | Path = "results",
    progress: Callable[[int, int, Episode], None] | None = None,
) -> tuple[Path, dict[str, Any]]:
    config = {
        **agent.config(),
        "defense": defense.name,
        "seed": seed,
        "repeats": repeats,
        "tasks": [t.id for t in tasks],
        "injections": [i.id for i in injections],
        "suite_hash": suite_hash(),
        "agentshield_version": __version__,
        "git_sha": _git_sha(),
        "python": platform.python_version(),
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }
    variant = config.get("profile") or config.get("model") or ""
    base = f"{time.strftime('%Y%m%d-%H%M%S')}_{config['agent']}-{variant}_{defense.name}"
    run_dir = _fresh_dir(Path(out_dir), base)
    (run_dir / "config.json").write_text(json.dumps(config, indent=2))

    plan = plan_episodes(tasks, injections, repeats)
    episodes: list[Episode] = []
    with (run_dir / "episodes.jsonl").open("w") as f:
        for i, (task, injection, r) in enumerate(plan, 1):
            ep = run_episode(agent, defense, task, injection, r, seed)
            episodes.append(ep)
            f.write(json.dumps(asdict(ep)) + "\n")
            f.flush()
            if progress:
                progress(i, len(plan), ep)

    summary = summarize(episodes)
    (run_dir / "summary.json").write_text(json.dumps({"config": config, "metrics": summary}, indent=2))
    from .report import render_markdown

    (run_dir / "report.md").write_text(render_markdown(config, summary))
    return run_dir, summary
