"""Cross-agent propagation: two-agent hand-off, propagation defense, metrics."""

import json

import pytest

from agentshield.cli import main
from agentshield.crossagent import (
    _B_OBEY_BY_CATEGORY,
    DOC_AGENT_ADDRESS,
    render_cross_report,
    run_scenario,
    run_suite,
    summarize_cross,
)
from agentshield.suite import load_goals, load_techniques

GOALS = {g.id: g for g in load_goals()}
TECHS = {t.id: t for t in load_techniques("all")}
LEAK = GOALS["leak_secret_email"]


def test_suite_is_deterministic_and_has_enough_scenarios():
    a = [(r.scenario_id, r.downstream_attack_success, r.forward_category) for r in run_suite(seed=0)]
    b = [(r.scenario_id, r.downstream_attack_success, r.forward_category) for r in run_suite(seed=0)]
    assert a == b
    assert len([r for r in run_suite(seed=0) if not r.benign]) >= 20


def test_trace_spans_both_agents_with_one_correlation_id():
    # verbatim forward of an obvious-but-followed goal: pick a scenario that reached B
    results = [r for r in run_suite(seed=0) if r.downstream_attack_success]
    assert results, "expected some downstream successes in the unprotected workflow"
    r = results[0]
    agents = {e["agent"] for e in r.trace}
    assert agents == {"A", "B"}
    assert {e["correlation_id"] for e in r.trace} == {r.correlation_id}
    # A forwards to the document agent; B then acts in its own sandbox
    assert any(
        e["agent"] == "A" and e["tool"] == "send_email" and e["args"]["to"] == DOC_AGENT_ADDRESS for e in r.trace
    )
    assert any(e["agent"] == "B" for e in r.trace)


def test_defense_stops_downstream_without_sanitizing_content():
    s = summarize_cross(run_suite(seed=0))
    u, p = s["unprotected"], s["protected"]
    # Unprotected: instructions reach B and some attacks succeed downstream.
    assert u["downstream_attack_success_rate"]["k"] > 0
    assert u["provenance_preservation_rate"]["rate"] == 0.0
    # Protected: content may still be forwarded (propagation can be >0) ...
    assert p["propagation_rate"]["k"] > 0
    # ... but provenance is preserved, nothing reaches B as an instruction, nothing succeeds.
    assert p["provenance_preservation_rate"]["rate"] == 1.0
    assert p["instruction_reached_b_rate"]["k"] == 0
    assert p["downstream_attack_success_rate"]["k"] == 0


def test_no_false_positives_on_benign_documents():
    s = summarize_cross(run_suite(seed=0))
    assert s["unprotected"]["benign_task_success"]["rate"] == 1.0
    assert s["protected"]["benign_task_success"]["rate"] == 1.0
    assert s["protected"]["false_positive_rate"]["rate"] == 0.0


def test_verbatim_forward_reaches_b_and_leaks_canary_without_defense(monkeypatch):
    # Force A to forward verbatim and B to obey, to exercise the full exploit path.
    monkeypatch.setattr("agentshield.crossagent._choose_behaviour", lambda inj, rng: "verbatim")
    monkeypatch.setitem(_B_OBEY_BY_CATEGORY, "exact", 1.0)
    r = run_scenario(LEAK, TECHS["naive"], defense=False, seed=0, index=0)
    assert r.forward_category == "exact"
    assert r.instruction_reached_b and r.b_acted_on_instruction and r.downstream_attack_success
    # The canary actually left Agent B's sandbox to the attacker address.
    assert any(e["agent"] == "B" and e["tool"] == "send_email" for e in r.trace)


def test_same_scenario_blocked_with_defense(monkeypatch):
    monkeypatch.setattr("agentshield.crossagent._choose_behaviour", lambda inj, rng: "verbatim")
    monkeypatch.setitem(_B_OBEY_BY_CATEGORY, "exact", 1.0)
    r = run_scenario(LEAK, TECHS["naive"], defense=True, seed=0, index=0)
    # Content still forwarded (exact), but provenance preserved, so B never acts.
    assert r.forward_category == "exact" and r.provenance_preserved
    assert not r.instruction_reached_b and not r.downstream_attack_success


@pytest.mark.parametrize(
    "behaviour,expected",
    [("removed", "none"), ("verbatim", "exact"), ("partial", "partial"), ("paraphrased", "indicator")],
)
def test_forward_behaviours_map_to_categories(monkeypatch, behaviour, expected):
    monkeypatch.setattr("agentshield.crossagent._choose_behaviour", lambda inj, rng: behaviour)
    r = run_scenario(LEAK, TECHS["naive"], defense=False, seed=0, index=0)
    assert r.forward_category == expected
    # 'removed' carries no instruction, so it can never reach B.
    if expected == "none":
        assert not r.instruction_reached_b and not r.downstream_attack_success


def test_benign_scenario_has_no_attack_fields():
    r = run_scenario(None, None, defense=False, seed=0, index=0)
    assert r.benign and r.goal_id is None and r.forward_category == "no_outbound"
    assert not r.downstream_attack_success and r.b_task_success


def test_cli_writes_report(tmp_path, capsys):
    main(["crossagent", "--out", str(tmp_path / "ca"), "--benign", "3"])
    report = (tmp_path / "ca" / "report.md").read_text()
    assert "cross-agent prompt injection propagation" in report.lower()
    assert "Downstream attack success" in capsys.readouterr().out
    rows = [json.loads(x) for x in (tmp_path / "ca" / "scenarios.jsonl").read_text().splitlines()]
    assert len(rows) >= 20 and all("correlation_id" in r for r in rows)
    summary = json.loads((tmp_path / "ca" / "summary.json").read_text())
    assert render_cross_report(summary, 0)  # renders without error
