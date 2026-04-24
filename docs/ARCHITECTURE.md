# Architecture

## Design principles

aigrc is built on four quality engineering principles:

1. **Fail explicitly, never silently.** Every payload produces a PASS, FAIL, or ERROR outcome with evidence. No silent timeouts or swallowed exceptions.
2. **Reproducible given the same input.** Target responses are captured in reports. Temperature defaults to 0. Payloads and evaluation heuristics are versioned alongside the code.
3. **Human-readable and machine-readable in parallel.** Every run produces both JSON (CI gates, dashboards, SIEM) and Markdown (audit binders, board packs).
4. **CI-native by default.** The CLI returns a nonzero exit code when the pass rate falls below a threshold. No portal, no login, no vendor lock-in.

## Layered structure

```
  CLI layer                    typer commands, rich output
    |
  Check layer                  payload library + evaluation heuristics
    |
  Core layer                   Registry, Target, Reporter, models
    |
  Target layer                 HTTP client, mock, pluggable providers
```

Each layer depends only on the layer below. Checks never call HTTP directly. Targets never interpret payloads.

## Why this shape

The hard problem in AI governance is not building one clever test. It is building an extensible, auditable test runner that a serious practitioner can add to and that a regulator can trust. The layering lets us:

- Add a new check without touching the CLI
- Swap the target implementation (mock, OpenAI, Anthropic, local vLLM) without touching the check
- Extend reporters without touching either
- Mock every layer independently in unit tests

## Evaluation heuristics

Evaluation lives inside each check module, not in a generic evaluator, because each attack class has different success signals:

- **Canary leakage:** PASS if the canary token does not appear. Strong, low false positive.
- **Scope drift:** PASS if off-topic content does not appear.
- **Prompt leak signatures:** FAIL if two or more distinctive system-prompt substrings appear.
- **Compliance indicators:** FAIL on phrases that show the model is executing the injection.
- **Refusal indicators:** PASS on explicit refusal phrases.

These are heuristics, not a language model judge. That is deliberate: a deterministic heuristic is reproducible and auditable. The companion tool Qopilot provides the LLM-backed interpretation layer separately.

## Mock target

The mock exists so the tool can run in CI without consuming API credits, and so design partners can see the tool working during a discovery call without needing to connect their own system. The mock implements a reasonably-but-not-perfectly secured model. It refuses obvious overrides and fails on base64, unicode confusables, delimiter injection, and hypothetical framing. That distribution is intentional: it produces realistic partial-compliance results that demonstrate the tool rather than flatter the tool.

## Framework mappings as data

Every regulatory framework lives in a YAML file under `aigrc/mappings/`. A check carries pointers to framework control IDs in its metadata. At report time, the Reporter looks up the full control titles and includes them in the evidence.

This makes mappings easy to update (edit YAML, commit, tag release) and easy to audit (diff tells you exactly what changed and when). We commit to a quarterly review cadence plus ad-hoc review whenever a regulator publishes updated guidance.

## What we deliberately do not do

- **No opinionated scoring model.** aigrc reports pass rate and regulatory control status. It does not invent a proprietary "AI risk score" that nobody can audit. If a client needs a composite score, the RES (Resilience Engineering Scorecard) method is published separately.
- **No hosted service.** The tool is a CLI. Reports are files. The client keeps their data.
- **No telemetry.** The tool never phones home.
- **No generic LLM-judge evaluator.** Judgement is either a deterministic heuristic (in aigrc) or an explicit LLM call the user controls (in Qopilot).
