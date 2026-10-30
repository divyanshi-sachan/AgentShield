"""Small, dependency-free statistics used for reporting.

- Wilson score intervals for binary rates.
- Exact McNemar test for paired binary outcomes on identical scenarios.
- Paired bootstrap over scenarios for differences in rates. Repeats of one
  scenario are averaged first, so they never count as independent samples.
"""

from __future__ import annotations

import math
import random
from collections.abc import Mapping


def wilson(successes: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def mcnemar_exact(b: int, c: int) -> float:
    """Two-sided exact McNemar p-value.

    b = scenarios where only the baseline was compromised,
    c = scenarios where only the treatment was compromised.
    """
    n = b + c
    if n == 0:
        return 1.0
    tail = sum(math.comb(n, k) for k in range(min(b, c) + 1)) / 2**n
    return min(1.0, 2 * tail)


def cluster_bootstrap(
    clusters: Mapping[str, list[float]], n_boot: int = 2000, seed: int = 0
) -> tuple[float, float, float]:
    """Pooled rate with a 95% CI that resamples whole clusters (e.g. all episodes of one task).

    Scenarios that share a task, goal or phrasing are correlated; resampling at
    the cluster level keeps that correlation instead of pretending every
    episode is independent, which widens the interval honestly.
    """
    totals = [(sum(v), len(v)) for v in clusters.values() if v]
    if not totals:
        return (0.0, 0.0, 0.0)
    successes, sizes = zip(*totals, strict=True)
    point = sum(successes) / sum(sizes)
    if len(set(successes)) == 1 and len(set(sizes)) == 1 or sum(successes) in (0, sum(sizes)):
        return (point, point, point)  # every resample is identical
    rng = random.Random(seed)
    m = len(totals)
    boots = []
    for _ in range(n_boot):
        idx = rng.choices(range(m), k=m)
        boots.append(sum(successes[i] for i in idx) / sum(sizes[i] for i in idx))
    boots.sort()
    return (point, boots[int(0.025 * n_boot)], boots[int(0.975 * n_boot) - 1])


def scenario_consistency(scenarios: Mapping[str, list[float]]) -> dict:
    """How often each scenario succeeded across its repeats.

    Returns the distribution of per-scenario success counts ("k/r" -> number of
    scenarios), the share of scenarios with mixed outcomes (some repeats
    succeeded, some did not), and the mean of per-scenario rates (each scenario
    weighted equally regardless of its number of repeats).
    """
    groups = {k: v for k, v in scenarios.items() if v}
    if not groups:
        return {"scenarios": 0, "frequency": {}, "mixed_share": None, "mean_scenario_rate": None}
    freq: dict[str, int] = {}
    mixed = 0
    for v in groups.values():
        k, r = int(sum(v)), len(v)
        freq[f"{k}/{r}"] = freq.get(f"{k}/{r}", 0) + 1
        mixed += 0 < k < r
    repeats = sorted({len(v) for v in groups.values()})
    return {
        "scenarios": len(groups),
        "repeats_per_scenario": repeats,
        "frequency": dict(sorted(freq.items(), key=lambda kv: (int(kv[0].split("/")[1]), int(kv[0].split("/")[0])))),
        "mixed_share": round(mixed / len(groups), 4),
        "mean_scenario_rate": round(sum(sum(v) / len(v) for v in groups.values()) / len(groups), 4),
    }


def paired_bootstrap(
    baseline: Mapping[str, float],
    treatment: Mapping[str, float],
    n_boot: int = 2000,
    seed: int = 0,
) -> tuple[float, float, float]:
    """Mean difference (treatment - baseline) over shared scenarios, with a 95% percentile CI."""
    keys = sorted(set(baseline) & set(treatment))
    if not keys:
        return (0.0, 0.0, 0.0)
    diffs = [treatment[k] - baseline[k] for k in keys]
    point = sum(diffs) / len(diffs)
    rng = random.Random(seed)
    boots = sorted(sum(rng.choice(diffs) for _ in diffs) / len(diffs) for _ in range(n_boot))
    return (point, boots[int(0.025 * n_boot)], boots[int(0.975 * n_boot) - 1])
