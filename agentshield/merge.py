"""Merge runs by case_id and run_id for repeat analysis.

Rules:
- Every episode is keyed by (run_id, episode_id), so identical episode ids from
  different runs (e.g. repeat 0 of a baseline and repeat 0 of a repeat study)
  never collide.
- The same run cannot be merged twice; a duplicate key inside one run is an error.
- A reference run (e.g. the original baseline) is kept separate: it is compared
  against the repeated runs as a replication check and is never counted as an
  additional repeat.
- Run directories are only read, never written.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .runner import Episode, load_run_full, scenario_stats, summarize
from .stats import scenario_consistency


class MergeError(ValueError):
    pass


def _run_id(config: dict[str, Any], run_dir: Path) -> str:
    # Runs made before run ids existed are identified by their directory path.
    return config.get("run_id") or f"legacy:{run_dir.resolve()}"


def merge_runs(run_dirs: list[str | Path], reference: str | Path | None = None) -> dict[str, Any]:
    runs: list[dict[str, Any]] = []
    seen_runs: set[str] = set()
    seen_keys: set[tuple[str, str]] = set()
    primary: list[Episode] = []
    reference_eps: list[Episode] = []
    labels: dict[int, dict[str, str]] = {}

    entries = [(Path(d), "primary") for d in run_dirs]
    if reference is not None:
        entries.append((Path(reference), "reference"))
    for run_dir, role in entries:
        config, episodes, _ = load_run_full(run_dir)
        rid = _run_id(config, run_dir)
        if rid in seen_runs:
            raise MergeError(f"run {rid} ({run_dir}) was given more than once")
        seen_runs.add(rid)
        for e in episodes:
            key = (rid, e.episode_id)
            if key in seen_keys:
                raise MergeError(f"duplicate episode {e.episode_id} inside run {rid}")
            seen_keys.add(key)
            labels[id(e)] = {"run_id": rid, "role": role, "merged_id": f"{rid}/{e.episode_id}"}
            (reference_eps if role == "reference" else primary).append(e)
        runs.append(
            {
                "run_id": rid,
                "role": role,
                "dir": str(run_dir),
                "episodes": len(episodes),
                "model": config.get("model") or config.get("profile"),
                "defense": config.get("defense"),
                "suite_hash": config.get("suite_hash"),
                "system_prompt_sha256": config.get("system_prompt_sha256"),
                "tool_schema_sha256": config.get("tool_schema_sha256"),
            }
        )
    _check_comparable(runs)
    return {"runs": runs, "primary": primary, "reference": reference_eps, "labels": labels}


def _check_comparable(runs: list[dict[str, Any]]) -> None:
    """Merged runs must share the model, defense and suite; prompt/tool hashes too when recorded."""
    for key in ("model", "defense", "suite_hash", "system_prompt_sha256", "tool_schema_sha256"):
        values = {r[key] for r in runs if r[key] is not None}
        if len(values) > 1:
            raise MergeError(f"runs differ in {key}: {sorted(values)}; refusing to pool them")


def _by_case(episodes: list[Episode], fn) -> dict[str, list[float]]:
    out: dict[str, list[float]] = defaultdict(list)
    for e in episodes:
        if e.api_error or e.injection_id is None:
            continue
        v = fn(e)
        if v is not None:
            out[e.case_id].append(float(bool(v)))
    return out


_OUTCOMES = {
    "attack_success": lambda e: e.attack_success,
    "task_success": lambda e: e.utility,
    "any_propagation": lambda e: (
        (e.propagation in ("exact", "partial", "indicator")) if e.propagation is not None else None
    ),
    "exact_propagation": lambda e: e.injection_propagated,
    "legit_action_completed": lambda e: (e.legit_action == "completed") if e.legit_action is not None else None,
}


def repeat_analysis(merged: dict[str, Any]) -> dict[str, Any]:
    """Scenario-level statistics over the primary runs, plus a replication check against the reference."""
    primary: list[Episode] = merged["primary"]
    reference: list[Episode] = merged["reference"]
    attacked = [e for e in primary if e.injection_id is not None and not e.api_error]

    replication: dict[str, Any] = {}
    if reference:
        for name, fn in _OUTCOMES.items():
            p, r = _by_case(primary, fn), _by_case(reference, fn)
            shared = sorted(set(p) & set(r))
            if not shared:
                continue
            agree = [k for k in shared if (sum(p[k]) / len(p[k]) >= 0.5) == (r[k][0] >= 0.5)]
            replication[name] = {
                "shared_scenarios": len(shared),
                "reference_rate": round(sum(r[k][0] for k in shared) / len(shared), 4),
                "repeat_mean_rate": round(sum(sum(p[k]) / len(p[k]) for k in shared) / len(shared), 4),
                "agreement_with_repeat_majority": round(len(agree) / len(shared), 4),
                "disagreeing_scenarios": [k for k in shared if k not in agree],
            }

    per_scenario = {name: scenario_consistency(_by_case(primary, fn)) for name, fn in _OUTCOMES.items()}
    return {
        "runs": merged["runs"],
        "primary_episodes": len(primary),
        "reference_episodes": len(reference),
        "reference_policy": "The reference run is a replication check only; it is never pooled as an extra repeat.",
        "metrics": summarize(primary, model=next((r["model"] for r in merged["runs"]), None)),
        "scenario_stats": scenario_stats(attacked),
        "per_scenario_frequency": per_scenario,
        "replication_vs_reference": replication,
    }


def write_merge(merged: dict[str, Any], analysis: dict[str, Any], out_dir: str | Path) -> Path:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    with (out / "merged_episodes.jsonl").open("w") as f:
        for e in merged["primary"] + merged["reference"]:
            f.write(json.dumps({**merged["labels"][id(e)], **asdict(e)}) + "\n")
    (out / "repeat_analysis.json").write_text(json.dumps(analysis, indent=2))
    from .report import render_repeat_report

    (out / "repeat_analysis.md").write_text(render_repeat_report(analysis))
    return out
