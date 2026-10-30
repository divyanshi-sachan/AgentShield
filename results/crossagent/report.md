# AgentShield: cross-agent prompt injection propagation

Agent A (ForwardAgent) reads an attacker-controlled email and forwards the document to Agent B (DocumentAgent) through the sandbox. Both agents are deterministic fixtures (no model, no network); seed 0. The question: does an instruction A would not act on reach B and get acted on there?

Propagation = the forwarded document still carries the attacker instruction (verbatim, partial or paraphrased-with-attacker-token). Downstream attack success = Agent B acted on it and the attacker goal was achieved in B's sandbox (ground-truth state, e.g. the protected canary left B). The propagation defense keeps forwarded third-party content tagged untrusted, so B treats it as data.

| Metric | Unprotected | Protected |
|---|---|---|
| Propagation rate (instruction survives A's forward) | 58.0% (29/50) | 60.0% (30/50) |
| Instruction reaches B as a trusted instruction | 58.0% (29/50) | 0.0% (0/50) |
| Downstream attack success (B acts, goal achieved) | 44.0% (22/50) | 0.0% (0/50) |
| Provenance preserved when content was relayed | 0.0% (0/29) | 100.0% (30/30) |
| Benign document task success | 100.0% (5/5) | 100.0% (5/5) |
| False positive rate on benign forwards | 0.0% (0/5) | 0.0% (0/5) |

## Forward categories (attack scenarios)

| Category | Unprotected | Protected |
|---|---|---|
| exact | 14 | 14 |
| indicator | 4 | 10 |
| none | 21 | 20 |
| partial | 11 | 6 |

## Reading

- Propagation can be high while downstream success is driven by whether provenance survives the hand-off.
- The defense preserves provenance without sanitizing content: the document still reaches B, but tagged untrusted, so B does not treat the embedded instruction as a command.

## Limitations

- Both agents are deterministic fixtures, not models; rates describe the pipeline and the defense logic, not how a real model forwards or obeys. Plug the Claude agent into the same hand-off to measure that.
- 'paraphrased' is modelled by one reword template carrying the attacker's address; real paraphrase is broader.
- Downstream success is scored only against the fixed attacker goals.
