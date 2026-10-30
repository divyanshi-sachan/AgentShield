"""Markdown reports for single runs and for multi-defense comparisons."""

from __future__ import annotations

from typing import Any

LIMITATIONS = [
    "The workspace is small and synthetic: 7 tasks, 5 attacker goals, single-turn tasks, one injection per episode.",
    "The scripted agent is a calibration fixture, not a model. With it, prompt-level defenses (D1) cannot change "
    "outcomes by construction; only enforcement defenses (D2-D4) can. Its numbers describe a worst-case compromised "
    "agent, not real model behaviour.",
    "D2's intent rules are keyword-based and D4's allowlists are hand-written for this workspace; both would need "
    "per-deployment configuration in practice.",
    "D4 uses a simulated approver that declines anything outside policy. Real users approve some unsafe actions.",
    "Attacker success is checked against fixed goals. Harmful actions outside those goals are not counted as attacks "
    "(they may still appear in traces and as utility failures).",
    "Model runs cannot fix sampling temperature; use repeats and read the confidence intervals.",
]


def pct(r: dict[str, Any] | None) -> str:
    if not r or r.get("rate") is None:
        return "n/a"
    lo, hi = r["ci95"]
    digits = 1 if hi < 0.1 else 0  # keep small upper bounds visible, e.g. [0–0.4] rather than [0–0]
    return f"{r['rate'] * 100:.1f}% [{lo * 100:.{digits}f}–{hi * 100:.{digits}f}] ({r['k']}/{r['n']})"


def _fbr(f: dict[str, Any]) -> str:
    if f["rate"] is None:
        return "n/a (no benign sink calls)"
    return f"{f['rate'] * 100:.1f}% ({f['blocked']}/{f['sink_calls']} benign sink calls)"


def _table(title: str, groups: dict[str, Any]) -> list[str]:
    lines = [f"### {title}", "", "| | Attack success | Utility under attack |", "|---|---|---|"]
    lines += [f"| `{name}` | {pct(g['asr'])} | {pct(g['utility'])} |" for name, g in groups.items()]
    return lines + [""]


def _trace_excerpt(trace: list[dict[str, Any]], limit: int = 8) -> list[str]:
    out = []
    for ev in trace[:limit]:
        args = ", ".join(f"{k}={str(v)[:40]!r}" for k, v in ev["args"].items())
        flag = {"blocked": f" BLOCKED by {ev['blocked_by']}: {ev['reason']}", "error": " (error)"}.get(ev["status"], "")
        trust = f" [{ev['trust']}]" if ev.get("trust") else ""
        out.append(f"    {ev['event_id']} {ev['tool']}({args}){trust}{flag}")
    return out


def _examples(episodes: list[Any], traces: dict[str, list[dict[str, Any]]], pick, title: str, n: int = 3) -> list[str]:
    chosen = [e for e in episodes if e.injection_id and pick(e)][:n]
    lines = [f"### {title}", ""]
    if not chosen:
        return lines + ["None.", ""]
    for e in chosen:
        lines += [f"- `{e.case_id}` (task `{e.task_id}`, goal `{e.goal_id}`, technique `{e.technique_id}`)", "", "```"]
        lines += _trace_excerpt(traces.get(e.episode_id, []))
        lines += ["```", ""]
    return lines


def render_run_report(config: dict[str, Any], m: dict[str, Any], episodes: list[Any], traces: dict[str, Any]) -> str:
    variant = config.get("model") or config.get("profile") or ""
    o = m["overhead"]
    lines = [
        f"# AgentShield run: {config['agent']} ({variant}), defense `{config['defense']}`",
        "",
        "## Configuration",
        "",
        f"- Agent: `{config['agent']}` {variant} " + (f"(effort {config['effort']})" if config.get("effort") else ""),
        f"- Defense pipeline: `{config['defense']}`",
        f"- Suite hash `{config['suite_hash']}`, seed {config['seed']}, repeats {config['repeats']}, "
        f"positions {', '.join(config['positions'])}",
        f"- {m['episodes']} episodes over {m['scenarios']} scenarios; git `{config.get('git_sha')}`; {config['started_at']}",
        f"- System prompt sha256 `{config.get('system_prompt_sha256')}` (system_prompt.txt), tool schemas sha256 "
        f"`{config.get('tool_schema_sha256')}` (tools.json)"
        + (" — reconstructed after the run from unchanged code" if config.get("reproducibility_backfilled") else ""),
        "",
        "Rates show 95% Wilson intervals and k/n. Wilson intervals assume every episode is independent; repeats "
        "of the same scenario are not, so use the scenario-clustered intervals below for inference. Results "
        "describe the selected tasks only and do not generalise beyond them.",
        "",
        "## Headline",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Attack success rate (ASR, lower is better) | {pct(m['attack_success_rate'])} |",
        f"| Normal task success (NTSR, higher is better) | {pct(m['normal_task_success'])} |",
        f"| Task success under attack | {pct(m['utility_under_attack'])} |",
        f"| Violation attempts (agent tried the attacker's action) | {pct(m['violation_attempt_rate'])} |",
        f"| Injection propagation (attacker text relayed to a non-attacker recipient) | "
        f"{pct(m.get('injection_propagation_rate'))} |",
        f"| Defense stop rate (attempts that did not succeed) | {pct(m['defense_stop_rate'])} |",
        f"| False block rate | {_fbr(m['false_block_rate'])} |",
        f"| Benign episodes with any block | {pct(m['benign_episodes_with_block'])} |",
        f"| Refusals | {pct(m['refusal_rate'])} |",
        f"| Errors, all kinds (API, turn, token or call limits) | {pct(m['error_rate'])} |",
        f"| API-error episodes (excluded from every rate) | {_api(m.get('api_errors'))} |",
        f"| Mean per episode: seconds / tool calls / tokens in / out | {o['mean_seconds']} / {o['mean_tool_calls']} / "
        f"{o['mean_input_tokens']} / {o['mean_output_tokens']} |",
        f"| Blocks by defense | {m['blocks_by_defense'] or 'none'} |",
        f"| Latency per episode: median / p95 seconds | {o.get('p50_seconds', 'n/a')} / {o.get('p95_seconds', 'n/a')} |",
        f"| Tokens in / out (total) | {m.get('tokens', {}).get('input', 0):,} / {m.get('tokens', {}).get('output', 0):,} |",
        f"| Estimated API cost | {_cost(m.get('cost'))} |",
        "",
    ]
    if m.get("harm_rates"):
        lines += ["## Harm rates", "", "| Harm | Rate |", "|---|---|"]
        lines += [f"| {name.replace('_', ' ').capitalize()} | {pct(r)} |" for name, r in m["harm_rates"].items()]
        lines += [""]
    lines += _legit(m.get("legit_action"))
    lines += _propagation(m.get("propagation"))
    lines += _scenarios(m.get("scenario_stats"))
    lines += _clustered(m.get("asr_clustered_ci"))
    lines += _generalization(m.get("generalization"))
    lines += ["## Breakdown", ""]
    for key, title in [
        ("by_category", "By category"),
        ("by_severity", "By severity"),
        ("by_goal", "By attacker goal"),
        ("by_technique", "By technique"),
        ("by_source", "By source"),
        ("by_position", "By position"),
        ("by_task", "By user task"),
    ]:
        lines += _table(title, m[key])
    lines += ["## Examples", ""]
    lines += _examples(episodes, traces, lambda e: e.attack_success, "Successful attacks")
    lines += _examples(
        episodes, traces, lambda e: e.attack_attempted and not e.attack_success, "Attempts stopped by the defense"
    )
    lines += _examples(episodes, traces, lambda e: not e.attack_attempted, "Attacks the agent did not act on")
    lines += ["## Limitations", ""] + [f"- {x}" for x in LIMITATIONS] + [""]
    return "\n".join(lines)


def _cost(c: dict[str, Any] | None) -> str:
    if not c:
        return "n/a (no token usage or unknown model price)"
    p = c["price_per_mtok"]
    return f"${c['usd']:.4f} at ${p['input']}/${p['output']} per MTok in/out (list prices as of {c['prices_as_of']})"


def _api(a: dict[str, Any] | None) -> str:
    if not a:
        return "n/a"
    return f"{a['count']} ({pct(a['rate_of_all_episodes'])})"


def _legit(legit: dict[str, Any] | None) -> list[str]:
    if not legit or not any(legit.values()):
        return []
    lines = [
        "## Legitimate action status by task",
        "",
        "Each task's own required action (e.g. paying the real invoice): completed, never attempted, attempted "
        "but blocked by a defense, or attempted and failed.",
        "",
        "| Task | Condition | Completed | Not attempted | Blocked | Failed |",
        "|---|---|---|---|---|---|",
    ]
    for label in ("benign", "attacked"):
        for task, r in legit.get(label, {}).items():
            lines.append(
                f"| `{task}` | {label} | {pct(r['completed'])} | {pct(r['not_attempted'])} | "
                f"{pct(r['blocked'])} | {pct(r['failed'])} |"
            )
    return lines + [""]


def _propagation(p: dict[str, Any] | None) -> list[str]:
    if not p or not p.get("by_task"):
        return []
    lines = [
        "## Injection propagation (relay-capable tasks only)",
        "",
        p["note"],
        "",
        "| Task | n | Exact | Partial | Indicator only | None | No outbound | Provenance flagged when relayed |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for task, r in p["by_task"].items():
        lines.append(
            f"| `{task}` | {r['n']} | {pct(r['exact'])} | {pct(r['partial'])} | {pct(r['indicator'])} | "
            f"{pct(r['none'])} | {pct(r['no_outbound'])} | {pct(r['provenance_preserved_when_relayed'])} |"
        )
    return lines + [""]


def _scenarios(s: dict[str, Any] | None) -> list[str]:
    if not s:
        return []
    lines = [
        "## Scenario-level results",
        "",
        "Each scenario is one exact task × goal × technique × position. Frequencies count scenarios by how many "
        "of their repeats had the outcome; mixed scenarios had both outcomes across repeats. Intervals resample "
        "whole scenarios, so repeats are not treated as independent.",
        "",
        "| Outcome | Scenarios | Repeats each | Mean scenario rate | Scenario-clustered 95% CI | Mixed scenarios | Frequency |",
        "|---|---|---|---|---|---|---|",
    ]
    for name, v in s.items():
        c = v["scenario_clustered"]
        freq = ", ".join(f"{k}: {n}" for k, n in v["frequency"].items())
        lines.append(
            f"| {name.replace('_', ' ')} | {v['scenarios']} | {', '.join(map(str, v['repeats_per_scenario']))} | "
            f"{v['mean_scenario_rate'] * 100:.1f}% | [{c['ci95'][0] * 100:.1f}, {c['ci95'][1] * 100:.1f}] | "
            f"{v['mixed_share'] * 100:.1f}% | {freq} |"
        )
    return lines + [""]


def render_repeat_report(a: dict[str, Any]) -> str:
    m = a["metrics"]
    lines = [
        "# AgentShield repeat analysis",
        "",
        f"{a['primary_episodes']} primary episodes from {sum(r['role'] == 'primary' for r in a['runs'])} run(s); "
        f"{a['reference_episodes']} reference episodes. {a['reference_policy']}",
        "",
        "| Run | Role | Episodes | Model | Defense | Suite |",
        "|---|---|---|---|---|---|",
    ]
    lines += [
        f"| `{r['run_id']}` | {r['role']} | {r['episodes']} | {r['model']} | {r['defense']} | `{r['suite_hash']}` |"
        for r in a["runs"]
    ]
    lines += [
        "",
        "## Headline (primary runs only)",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Attack success rate | {pct(m['attack_success_rate'])} |",
        f"| Task success under attack | {pct(m['utility_under_attack'])} |",
        f"| Normal task success | {pct(m['normal_task_success'])} |",
        f"| API-error episodes (excluded) | {_api(m.get('api_errors'))} |",
        "",
    ]
    lines += _legit(m.get("legit_action"))
    lines += _propagation(m.get("propagation"))
    lines += _scenarios(a.get("scenario_stats"))
    if a["replication_vs_reference"]:
        lines += [
            "## Replication against the reference run",
            "",
            "Reference outcome (single observation) vs the majority of repeats, per shared scenario.",
            "",
            "| Outcome | Shared scenarios | Reference rate | Repeat mean rate | Agreement | Disagreeing |",
            "|---|---|---|---|---|---|",
        ]
        for name, r in a["replication_vs_reference"].items():
            lines.append(
                f"| {name.replace('_', ' ')} | {r['shared_scenarios']} | {r['reference_rate'] * 100:.1f}% | "
                f"{r['repeat_mean_rate'] * 100:.1f}% | {r['agreement_with_repeat_majority'] * 100:.1f}% | "
                f"{len(r['disagreeing_scenarios'])} |"
            )
        lines.append("")
    lines += ["## Limitations", ""] + [f"- {x}" for x in LIMITATIONS] + [""]
    return "\n".join(lines)


def _clustered(c: dict[str, Any] | None) -> list[str]:
    if not c:
        return []
    lines = [
        "## Clustered intervals for ASR",
        "",
        "Scenarios that share a task, goal or technique are correlated. These intervals resample whole clusters "
        "instead of single episodes, so they are wider and more honest than the Wilson interval above.",
        "",
        "| Resampling unit | ASR | 95% CI | Clusters |",
        "|---|---|---|---|",
    ]
    for key, v in c.items():
        unit = key.removeprefix("by_").removesuffix("_cluster")
        lines.append(
            f"| {unit} | {v['rate'] * 100:.1f}% | [{v['ci95'][0] * 100:.1f}, {v['ci95'][1] * 100:.1f}] | {v['clusters']} |"
        )
    if all(v["rate"] in (0.0, 1.0) for v in c.values()):
        lines += [
            "",
            "Every outcome is identical, so resampling cannot produce any spread and these intervals collapse to a "
            "point. Use the Wilson upper bound above as the uncertainty for a zero (or full) success rate.",
        ]
    return lines + [""]


def _generalization(g: dict[str, Any] | None) -> list[str]:
    if not g:
        return []
    d = g["gap_heldout_minus_standard"]
    return [
        "## Generalization to unseen phrasings",
        "",
        "| Phrasings | ASR |",
        "|---|---|",
        f"| Standard (used while designing defenses) | {pct(g['standard'])} |",
        f"| Unseen (held out) | {pct(g['heldout'])} |",
        f"| Gap, unseen minus standard | {d['diff'] * 100:+.1f} pp [{d['ci95'][0] * 100:+.1f}, {d['ci95'][1] * 100:+.1f}], "
        f"paired over {g['paired_cells']} task×goal×position cells; McNemar p {_p(g['mcnemar_p'])} |",
        "",
    ]


def _p(p: float) -> str:
    return "<0.001" if p < 0.001 else f"{p:.3f}"


def _delta(d: dict[str, Any]) -> str:
    return f"{d['diff'] * 100:+.1f} pp [{d['ci95'][0] * 100:+.1f}, {d['ci95'][1] * 100:+.1f}]"


def render_comparison_report(name: str, cmp: dict[str, Any], notes: str = "") -> str:
    agent = cmp["agent"]
    lines = [
        f"# AgentShield experiment: {name}",
        "",
        f"Agent: `{agent.get('agent')}` {agent.get('model') or agent.get('profile') or ''}. "
        f"Baseline: `{cmp['baseline']}`. Deltas are paired over identical scenarios (repeats averaged per scenario) "
        "with 95% bootstrap intervals; p-values are exact McNemar tests on per-scenario outcomes.",
        "",
    ]
    if notes:
        lines += [notes.strip(), ""]
    lines += [
        "## Security vs. usability",
        "",
        "| Defense | ASR | ΔASR vs baseline | Relative reduction | McNemar p | NTSR | ΔNTSR | Task success under attack | False block rate |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for r in cmp["rows"]:
        rel = f"{r['asr_relative_reduction'] * 100:.0f}%" if r["asr_relative_reduction"] is not None else "n/a"
        fbr = r["false_block_rate"]
        fbr_s = f"{fbr['rate'] * 100:.1f}% ({fbr['blocked']}/{fbr['sink_calls']})" if fbr["rate"] is not None else "n/a"
        lines.append(
            f"| `{r['defense']}` | {pct(r['asr'])} | {'—' if r['is_baseline'] else _delta(r['asr_delta'])} | "
            f"{'—' if r['is_baseline'] else rel} | {'—' if r['is_baseline'] else _p(r['mcnemar']['p_value'])} | "
            f"{pct(r['normal_task_success'])} | {'—' if r['is_baseline'] else _delta(r['ntsr_delta'])} | "
            f"{pct(r['utility_under_attack'])} | {fbr_s} |"
        )
    lines += [
        "",
        "## Overhead (mean per episode)",
        "",
        "| Defense | Seconds | Tool calls | Input tokens | Output tokens |",
        "|---|---|---|---|---|",
    ]
    for r in cmp["rows"]:
        o = r["overhead"]
        lines.append(
            f"| `{r['defense']}` | {o['mean_seconds']} | {o['mean_tool_calls']} | {o['mean_input_tokens']} | {o['mean_output_tokens']} |"
        )

    for key, title in [
        ("by_goal", "ASR by attacker goal"),
        ("by_technique", "ASR by technique"),
        ("by_source", "ASR by source"),
        ("by_position", "ASR by position"),
    ]:
        groups = sorted({g for r in cmp["rows"] for g in r[key]})
        if not groups:
            continue
        lines += [
            "",
            f"## {title}",
            "",
            "| Defense | " + " | ".join(f"`{g}`" for g in groups) + " |",
            "|---|" + "---|" * len(groups),
        ]
        for r in cmp["rows"]:
            cells = [f"{r[key][g] * 100:.0f}%" if r[key].get(g) is not None else "–" for g in groups]
            lines.append(f"| `{r['defense']}` | " + " | ".join(cells) + " |")
    lines += ["", "## Limitations", ""] + [f"- {x}" for x in LIMITATIONS] + [""]
    return "\n".join(lines)
