"""Markdown report rendering for a run summary."""

from __future__ import annotations

from typing import Any


def _pct(r: dict[str, Any]) -> str:
    if r["rate"] is None:
        return "n/a"
    lo, hi = r["ci95"]
    return f"{r['rate'] * 100:.1f}% [{lo * 100:.0f}–{hi * 100:.0f}] ({r['k']}/{r['n']})"


def _table(title: str, groups: dict[str, Any]) -> list[str]:
    lines = [f"### {title}", "", "| | Attack success | Utility under attack |", "|---|---|---|"]
    lines += [f"| `{name}` | {_pct(g['asr'])} | {_pct(g['utility'])} |" for name, g in groups.items()]
    return lines + [""]


def render_markdown(config: dict[str, Any], m: dict[str, Any]) -> str:
    agent = config.get("model") or config.get("profile") or ""
    lines = [
        f"# AgentShield run: {config['agent']} ({agent}), defense `{config['defense']}`",
        "",
        f"Suite `{config['suite_hash']}` · seed {config['seed']} · repeats {config['repeats']} · "
        f"git `{config.get('git_sha')}` · {config['started_at']}",
        "",
        "Rates show 95% Wilson confidence intervals.",
        "",
        "## Headline",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Attack success rate (lower is better) | {_pct(m['attack_success_rate'])} |",
        f"| Benign utility (higher is better) | {_pct(m['benign_utility'])} |",
        f"| Utility under attack | {_pct(m['utility_under_attack'])} |",
        f"| Refusals | {_pct(m['refusal_rate'])} |",
        f"| Errors (max turns / tokens) | {_pct(m['error_rate'])} |",
        f"| Calls blocked on benign runs (false positives) | {m['benign_blocked_calls']} |",
        f"| Calls blocked on attacked runs | {m['attack_blocked_calls']} |",
        f"| Tokens in / out | {m['tokens']['input']:,} / {m['tokens']['output']:,} |",
        "",
        "## Breakdown",
        "",
    ]
    lines += _table("By technique", m["by_technique"])
    lines += _table("By attacker goal", m["by_goal"])
    lines += _table("By category", m["by_category"])
    lines += _table("By user task", m["by_task"])
    return "\n".join(lines)
