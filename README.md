# AgentShield

**Ground-truth evaluation of indirect prompt injection against tool-calling LLM agents.**

AgentShield puts an agent in a sandboxed workspace (inbox, files, web pages, payment and email tools), plants attacker-written instructions inside the content it reads while doing ordinary user tasks, and records what the agent *does*. Success is decided from environment state — did a per-run canary secret reach an attacker address, was money moved, was a file deleted — never by keyword-matching the model's reply.

> Status: v0.1 scaffold. The harness, attack suites, offline calibration agent, Claude agent and reporting work and are tested. Defenses beyond the no-defense baseline are next (see Roadmap). No real-model results are reported yet.

## Why ground truth

Most prompt-injection benchmarks score a response by looking for phrases like "I can't help with that". That produces false positives (a refusal that still leaked data) and false negatives (compliance phrased politely). Here every attacker goal and every user task is a declarative check over the sandbox's final state, and both are verified by self-tests before any run:

- each task's reference plan really completes the task,
- each attacker goal's call sequence really satisfies its own success check,
- no benign task accidentally trips an attacker check,
- each task's reference plan really exposes the agent to the injected slot.

## What a run measures

| Metric | Meaning |
|---|---|
| Attack success rate (ASR) | Fraction of attacked episodes where the attacker goal was achieved |
| Benign utility | Fraction of tasks completed with no attack present |
| Utility under attack | Fraction of tasks still completed while under attack |
| Blocked calls on benign runs | Defense false positives |
| Refusals / errors | Model refusals, turn or token limits |

Every rate is reported with a 95% Wilson interval and broken down by technique, attacker goal, category and task. Each run writes `config.json` (agent, model, defense, seed, suite content hash, git SHA), `episodes.jsonl` (full tool-call trace per episode), `summary.json` and `report.md`.

## Suite (v0.1)

- **7 user tasks** across email, files and web: summarize, reply, pay an invoice, extract action items, forward a report, read a wiki page, digest a news page.
- **5 attacker goals**: leak a secret by email, leak it by HTTP, unauthorized transfer, delete a file, send a lure link to a colleague.
- **7 delivery techniques**: naive, ignore-previous, user impersonation ("important message"), fake system notice, fake end-of-content plus new user turn, authority and urgency, pre-written assistant agreement.

7 tasks × (35 injections + 1 benign) = 252 episodes per run. Everything targets the simulated sandbox only: `*.evil.test` addresses, fake accounts and a random canary token.

## Quick start

```bash
uv venv --python 3.13 && uv pip install -e ".[dev]"
python -m agentshield list
python -m agentshield run --agent scripted --profile medium   # offline, no API key
pytest
```

Against Claude (uses your Anthropic credentials; check the episode count first):

```bash
uv pip install -e ".[anthropic]"
python -m agentshield run --agent claude --dry-run
python -m agentshield run --agent claude --model claude-opus-5-5 --tasks news_digest,pay_supplier_invoice
```

Server-side refusal fallbacks are intentionally off so every episode is answered by the model under test; refusals are counted separately.

## Offline calibration agent

`--agent scripted` is a deterministic stand-in, not a model. It follows each task's reference plan and, when the injected text is still present in what it reads, obeys with a per-technique probability set by its profile. It exists to test the harness and any defense that rewrites or blocks content. The numbers below confirm the pipeline measures what it should; they are **not** findings about real agents.

| Profile | ASR | Benign utility |
|---|---|---|
| `naive` | 100.0% (245/245) | 100% (7/7) |
| `medium` | 51.0% (125/245) | 100% (7/7) |
| `robust` | 0.0% (0/245) | 100% (7/7) |

## Architecture

```
agentshield/
  env.py          sandboxed workspace + 10 tools, flagged untrusted-output / sink
  checks.py       declarative ground-truth checks (utility and attacker success)
  suite.py        loads tasks, goals, techniques; suite content hash
  suites/         workspace.json, tasks.json, attacks.json
  defenses.py     Defense interface + ToolGateway (every tool call passes through it)
  agents/         scripted (offline calibration), claude (manual tool-use loop)
  runner.py       episode planning, execution, metrics with Wilson CIs
  report.py       markdown report
  cli.py          `agentshield list | run`
tests/            55 tests: env, checks, suite integrity, runner, Claude loop (mocked)
```

A defense implements up to three hooks — rewrite the system prompt, rewrite untrusted tool output, veto a tool call — and works with every agent because agents can only reach the environment through `ToolGateway`.

## Roadmap

1. **Defenses**: spotlighting/datamarking of untrusted content; an injection classifier on tool outputs; a taint-tracking tool-call policy that blocks sink calls whose arguments derive from untrusted content; a dual-LLM (privileged/quarantined) split.
2. **Real-model baselines** with repeats, plus cost and latency per episode.
3. **Adaptive attacker**: an LLM that rewrites failed injections against a given defense, to test robustness beyond a fixed payload list.
4. **Detection output**: SARIF findings and detection rules derived from successful traces.
5. **Multi-step and multi-turn** attacks, and RAG-style retrieval as an injection vector.

## Related work

AgentDojo (Debenedetti et al., 2024) and InjecAgent (Zhan et al., 2024) evaluate indirect prompt injection in tool-using agents; garak and PyRIT are broader LLM red-teaming toolkits. AgentShield is deliberately small and focuses on ground-truth scoring, explicit false-positive accounting for defenses, and a defense interface that is independent of the agent backend.

## License

MIT
