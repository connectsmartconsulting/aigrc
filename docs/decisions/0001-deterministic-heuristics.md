# ADR-0001: Deterministic heuristic evaluation instead of LLM-judge

**Status:** Accepted
**Date:** 2026-04-23

## Context

Two patterns dominate current AI assurance tooling. Red-team toolkits (Garak, PyRIT) use pattern matching and signature detection. Evaluation frameworks (Promptfoo, TruLens) use an LLM-as-judge pattern where one model grades another.

We had to choose one approach for aigrc v0.1.

## Decision

aigrc uses deterministic heuristic evaluation only. The LLM-judge pattern is available through the companion tool Qopilot, but never inside a check.

## Rationale

1. **Reproducibility.** A regulator or auditor who re-runs the same check against the same target with the same payloads must get the same result. LLM judges introduce stochasticity that undermines audit defensibility.
2. **Auditability.** The evaluation logic is inspectable Python. No prompt engineering hides inside the runtime. A reviewer can read every heuristic and understand exactly what produced a PASS or FAIL.
3. **Cost and latency.** Heuristics are free and instant. LLM judges double the cost of every check and make CI integration painful.
4. **Separation of concerns.** Judgement is a different activity from execution. We deliberately push judgement into Qopilot where the user controls the model, the prompt, and the cost.

## Consequences

- aigrc heuristics will occasionally produce false positives or false negatives. We accept this in exchange for reproducibility.
- We must document every heuristic and its known failure modes explicitly.
- Heuristic refinement becomes a first-class activity with every new check.
- Qopilot, not aigrc, is where nuance lives.

## Revisit

If regulatory guidance shifts toward accepting LLM-judge evidence (unlikely in the 2026 to 2028 window given SR&ED and IRAP audit conservatism), we may add an optional `--judge <model>` flag in v1.x.
