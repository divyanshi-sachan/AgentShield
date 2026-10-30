"""Paired comparison of runs on identical scenarios (defense vs baseline)."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from .metrics import is_api_error
from .stats import mcnemar_exact, paired_bootstrap


def _scenario_means(episodes: list[dict[str, Any]], field: str, attacked: bool) -> dict[str, float]:
    sums: dict[str, list[float]] = defaultdict(list)
    for e in episodes:
        if is_api_error(e.get("error")):
            continue  # an API failure is neither a compromise nor a successful defense
        if (e["injection_id"] is not None) == attacked:
            sums[e["case_id"]].append(float(bool(e[field])))
    return {k: sum(v) / len(v) for k, v in sums.items()}


def compare_runs(
    runs: list[tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]], seed: int = 0
) -> dict[str, Any]:
    """Compare every run against the baseline run (defense 'none', else the first run)."""
    base_idx = next((i for i, (c, _, _) in enumerate(runs) if c["defense"] == "none"), 0)
    b_cfg, b_m, b_eps = runs[base_idx]
    b_asr = _scenario_means(b_eps, "attack_success", attacked=True)
    b_util = _scenario_means(b_eps, "utility", attacked=False)
    b_uua = _scenario_means(b_eps, "utility", attacked=True)

    rows = []
    for cfg, m, eps in runs:
        asr = _scenario_means(eps, "attack_success", attacked=True)
        util = _scenario_means(eps, "utility", attacked=False)
        uua = _scenario_means(eps, "utility", attacked=True)
        shared = sorted(set(asr) & set(b_asr))
        only_base = sum(1 for k in shared if b_asr[k] >= 0.5 and asr[k] < 0.5)
        only_treat = sum(1 for k in shared if asr[k] >= 0.5 and b_asr[k] < 0.5)
        d_asr = paired_bootstrap(b_asr, asr, seed=seed)
        d_util = paired_bootstrap(b_util, util, seed=seed)
        d_uua = paired_bootstrap(b_uua, uua, seed=seed)
        base_rate = b_m["attack_success_rate"]["rate"] or 0.0
        this_rate = m["attack_success_rate"]["rate"] or 0.0
        rows.append(
            {
                "defense": cfg["defense"],
                "is_baseline": cfg is b_cfg,
                "asr": m["attack_success_rate"],
                "normal_task_success": m["normal_task_success"],
                "utility_under_attack": m["utility_under_attack"],
                "false_block_rate": m["false_block_rate"],
                "violation_attempt_rate": m["violation_attempt_rate"],
                "defense_stop_rate": m["defense_stop_rate"],
                "asr_relative_reduction": round(1 - this_rate / base_rate, 4) if base_rate else None,
                "asr_delta": _fmt(d_asr),
                "ntsr_delta": _fmt(d_util),
                "utility_under_attack_delta": _fmt(d_uua),
                "mcnemar": {
                    "only_baseline_compromised": only_base,
                    "only_defense_compromised": only_treat,
                    "p_value": mcnemar_exact(only_base, only_treat),
                },
                "overhead": m["overhead"],
                "overhead_delta": {k: round(m["overhead"][k] - b_m["overhead"][k], 5) for k in m["overhead"]},
                "by_technique": {k: v["asr"]["rate"] for k, v in m["by_technique"].items()},
                "by_source": {k: v["asr"]["rate"] for k, v in m["by_source"].items()},
                "by_goal": {k: v["asr"]["rate"] for k, v in m["by_goal"].items()},
                "by_position": {k: v["asr"]["rate"] for k, v in m["by_position"].items()},
                "scenarios_compared": len(shared),
            }
        )
    return {
        "baseline": b_cfg["defense"],
        "agent": {k: b_cfg.get(k) for k in ("agent", "model", "profile", "effort")},
        "rows": rows,
    }


def _fmt(t: tuple[float, float, float]) -> dict[str, float]:
    return {"diff": round(t[0], 4), "ci95": [round(t[1], 4), round(t[2], 4)]}
