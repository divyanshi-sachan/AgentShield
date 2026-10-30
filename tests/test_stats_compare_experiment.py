"""Statistics, paired comparison, experiment runner and dashboard."""

import json

import pytest

from agentshield.cli import main
from agentshield.experiment import episode_count, load_config, run_experiment
from agentshield.stats import mcnemar_exact, paired_bootstrap, wilson


def test_wilson():
    lo, hi = wilson(5, 10)
    assert 0.2 < lo < 0.5 < hi < 0.8
    assert wilson(0, 0) == (0.0, 0.0)
    assert wilson(10, 10)[1] == 1.0


def test_mcnemar_known_values():
    assert mcnemar_exact(0, 0) == 1.0
    assert mcnemar_exact(5, 5) == 1.0
    assert mcnemar_exact(10, 0) == pytest.approx(2 / 1024)
    assert mcnemar_exact(0, 10) == mcnemar_exact(10, 0)


def test_paired_bootstrap_groups_by_scenario_and_is_deterministic():
    base = {f"s{i}": 1.0 for i in range(20)}
    treat = {f"s{i}": (0.0 if i < 15 else 1.0) for i in range(20)}
    point, lo, hi = paired_bootstrap(base, treat, seed=1)
    assert point == pytest.approx(-0.75) and lo <= point <= hi
    assert paired_bootstrap(base, treat, seed=1) == (point, lo, hi)
    assert paired_bootstrap({}, {}) == (0.0, 0.0, 0.0)


@pytest.fixture
def config(tmp_path):
    p = tmp_path / "exp.toml"
    p.write_text(
        'name = "mini"\n[agent]\ntype = "scripted"\nprofile = "naive"\n'
        '[run]\ntasks = ["reply_to_vendor", "pay_supplier_invoice"]\n'
        'defenses = ["none", "D2", "D4"]\npositions = ["start", "end"]\n'
    )
    return p


def test_load_config_validates(tmp_path, config):
    assert episode_count(load_config(config)) == 3 * 2 * (35 * 2 + 1)
    bad = tmp_path / "bad.toml"
    bad.write_text('[run]\ndefenses = ["D7"]\n')
    with pytest.raises(ValueError):
        load_config(bad)


def test_experiment_end_to_end(tmp_path, config):
    exp_dir, cmp = run_experiment(config, tmp_path / "out")
    rows = {r["defense"]: r for r in cmp["rows"]}
    assert rows["none"]["is_baseline"] and rows["none"]["asr"]["rate"] == 1.0
    assert rows["D4"]["asr"]["rate"] == 0.0
    assert rows["D4"]["asr_relative_reduction"] == 1.0
    assert rows["D4"]["asr_delta"]["diff"] == -1.0
    assert rows["D4"]["mcnemar"]["p_value"] < 0.001
    assert rows["D2"]["ntsr_delta"]["diff"] == -0.5  # invoice payment blocked
    for f in ["comparison.json", "comparison.md", "dashboard.html", "experiment.json"]:
        assert (exp_dir / f).exists()
    html = (exp_dir / "dashboard.html").read_text()
    assert "plotly.js/2.35.2" in html and "Attack success rate by defense" in html
    md = (exp_dir / "comparison.md").read_text()
    assert "Security vs. usability" in md and "McNemar" in md
    assert json.loads((exp_dir / "comparison.json").read_text())["baseline"] == "none"


def test_cli_run_and_compare(tmp_path, capsys):
    out = tmp_path / "r"
    main(["run", "--profile", "naive", "--tasks", "news_digest", "--quiet", "--out", str(out)])
    main(["run", "--profile", "naive", "--tasks", "news_digest", "--defense", "D4", "--quiet", "--out", str(out)])
    runs = sorted(p for p in out.iterdir())
    main(["compare", *map(str, runs), "--out", str(tmp_path / "cmp")])
    assert (tmp_path / "cmp" / "dashboard.html").exists()
    main(["experiment", "experiments/e1_e4_defense_matrix.toml", "--dry-run"])
    assert "2268 episodes" in capsys.readouterr().err


def test_cluster_bootstrap_is_wider_than_naive_for_correlated_clusters():
    from agentshield.stats import cluster_bootstrap

    clusters = {"a": [1.0] * 50, "b": [0.0] * 50, "c": [1.0] * 50, "d": [0.0] * 50}
    point, lo, hi = cluster_bootstrap(clusters, seed=0)
    wl, wh = wilson(100, 200)
    assert point == 0.5 and (hi - lo) > (wh - wl)
    assert cluster_bootstrap({}) == (0.0, 0.0, 0.0)


def test_cost_estimate():
    from agentshield.pricing import estimate_cost

    c = estimate_cost("claude-haiku-5-5", 1_000_000, 1_000_000)
    assert c["usd"] == 0.6
    assert estimate_cost("unknown-model", 1, 1) is None
