"""Self-contained HTML dashboard for an experiment comparison (Plotly from a pinned CDN build)."""

from __future__ import annotations

import html
import json
from typing import Any

PLOTLY = "https://cdnjs.cloudflare.com/ajax/libs/plotly.js/2.35.2/plotly.min.js"


def _heat(cmp: dict[str, Any], key: str) -> dict[str, Any]:
    cols = sorted({g for r in cmp["rows"] for g in r[key]})
    return {
        "x": cols,
        "y": [r["defense"] for r in cmp["rows"]],
        "z": [[(r[key].get(c) or 0) * 100 for c in cols] for r in cmp["rows"]],
    }


def render_dashboard(name: str, cmp: dict[str, Any]) -> str:
    rows = cmp["rows"]
    data = {
        "defenses": [r["defense"] for r in rows],
        "asr": [r["asr"]["rate"] * 100 for r in rows],
        "asr_lo": [(r["asr"]["rate"] - r["asr"]["ci95"][0]) * 100 for r in rows],
        "asr_hi": [(r["asr"]["ci95"][1] - r["asr"]["rate"]) * 100 for r in rows],
        "ntsr": [(r["normal_task_success"]["rate"] or 0) * 100 for r in rows],
        "uua": [(r["utility_under_attack"]["rate"] or 0) * 100 for r in rows],
        "tool_calls": [r["overhead"]["mean_tool_calls"] for r in rows],
        "tokens": [r["overhead"]["mean_input_tokens"] + r["overhead"]["mean_output_tokens"] for r in rows],
        "technique": _heat(cmp, "by_technique"),
        "source": _heat(cmp, "by_source"),
        "goal": _heat(cmp, "by_goal"),
    }
    title = html.escape(name)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>AgentShield: {title}</title>
<script src="{PLOTLY}"></script>
<style>
 body {{ font-family: system-ui, sans-serif; margin: 0 auto; max-width: 1100px; padding: 16px; color: #1d1d1f; background: #fff; }}
 h1 {{ font-size: 1.4rem; }} p {{ color: #555; }}
 .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 480px), 1fr)); gap: 16px; }}
 .chart {{ min-height: 360px; border: 1px solid #e5e5e5; border-radius: 8px; }}
</style></head><body>
<h1>AgentShield experiment: {title}</h1>
<p>Agent: {html.escape(str(cmp["agent"].get("agent")))} {html.escape(str(cmp["agent"].get("model") or cmp["agent"].get("profile") or ""))}.
Baseline: {html.escape(cmp["baseline"])}. Error bars are 95% Wilson intervals.</p>
<div class="grid">
 <div id="asr" class="chart"></div><div id="tradeoff" class="chart"></div>
 <div id="technique" class="chart"></div><div id="source" class="chart"></div>
 <div id="goal" class="chart"></div><div id="overhead" class="chart"></div>
</div>
<script>
const D = {json.dumps(data)};
const L = (t, extra) => Object.assign({{title: {{text: t, font: {{size: 14}}}}, margin: {{l: 110, r: 20, t: 40, b: 60}}, template: 'plotly_white'}}, extra || {{}});
const cfg = {{responsive: true, displaylogo: false}};
Plotly.newPlot('asr', [{{type: 'bar', x: D.defenses, y: D.asr, marker: {{color: '#c0392b'}},
  error_y: {{type: 'data', symmetric: false, array: D.asr_hi, arrayminus: D.asr_lo}}}}],
  L('Attack success rate by defense (%)', {{yaxis: {{range: [0, 100]}}}}), cfg);
Plotly.newPlot('tradeoff', [{{type: 'scatter', mode: 'markers+text', x: D.asr, y: D.ntsr, text: D.defenses,
  textposition: 'top center', marker: {{size: 12, color: '#2c7fb8'}}, name: 'no attack'}},
  {{type: 'scatter', mode: 'markers', x: D.asr, y: D.uua, marker: {{size: 9, symbol: 'diamond', color: '#7f8c8d'}}, name: 'under attack'}}],
  L('Task success vs attack success (%)', {{xaxis: {{title: 'ASR (lower is better)', range: [-5, 105]}},
  yaxis: {{title: 'Task success (higher is better)', range: [-5, 105]}}}}), cfg);
const heat = (id, h, t) => Plotly.newPlot(id, [{{type: 'heatmap', x: h.x, y: h.y, z: h.z, zmin: 0, zmax: 100,
  colorscale: 'Reds', texttemplate: '%{{z:.0f}}', hovertemplate: '%{{y}} / %{{x}}: %{{z:.1f}}%<extra></extra>'}}],
  L(t, {{xaxis: {{tickangle: -30}}}}), cfg);
heat('technique', D.technique, 'ASR by technique and defense (%)');
heat('source', D.source, 'ASR by source and defense (%)');
heat('goal', D.goal, 'ASR by attacker goal and defense (%)');
Plotly.newPlot('overhead', [{{type: 'bar', x: D.defenses, y: D.tool_calls, name: 'tool calls'}},
  {{type: 'bar', x: D.defenses, y: D.tokens, name: 'tokens', yaxis: 'y2'}}],
  L('Mean overhead per episode', {{barmode: 'group', yaxis: {{title: 'tool calls'}},
  yaxis2: {{title: 'tokens', overlaying: 'y', side: 'right'}}}}), cfg);
</script></body></html>
"""
