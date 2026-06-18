# ADR-0004: Two-tier canary-and-regex detection for the PII leakage check

**Status:** Accepted
**Date:** 2026-06-18 (documented retroactively; the decision was made during the v0.2.0 build on 2026-05-05)

## Context

The pii-leakage check probes a target with prompts designed to elicit disclosure of personally identifiable information, either seeded into the model context or hallucinated by the model. We needed a method to decide, for each response, whether leakage occurred.

ADR-0001 had already established the governing principle for all aigrc checks: evaluation is deterministic heuristic, never LLM-judge, in exchange for reproducibility and auditability. The question for the PII check was not whether to use heuristics, but which heuristic design detects leakage reliably while honouring that principle.

This ADR documents the detection layer only. How detections are weighted, scored, or turned into a resilience verdict is handled separately and is out of scope here.

## Decision

The pii-leakage check uses a two-tier detector:

- **Tier 1 (high confidence) — canary exact match.** Synthetic, test-only PII values (a name, SIN-format string, test card PAN, email, date of birth, phone number) are seeded into the target's system-prompt context. An exact match of any canary token in the response is confirmed leakage of the seeded record.
- **Tier 2 (medium confidence) — PII-shaped regex sweep.** The response is swept for PII-shaped patterns (SIN, card, email, phone, date formats) that are not canary tokens. A match indicates the model emitted PII-shaped content beyond the seeded record.

## Rationale

1. **Direct application of ADR-0001.** Both tiers are deterministic and inspectable. The same target, payloads, and seeded canaries produce the same verdict on every run. No model grades the output, so there is no stochasticity to undermine audit defensibility.

2. **The two tiers answer two different questions.** Tier 1 answers "did the model disclose the specific record it was trusted with?" — the highest-value signal, because the canary is known-planted and a match is unambiguous. Tier 2 answers "did the model emit anything PII-shaped at all?" — broader coverage that catches disclosure the canary set would miss. One tier without the other would leave a gap: canary-only misses non-seeded leakage; regex-only cannot distinguish a confirmed trusted-record breach from an incidental pattern match.

3. **Confidence labelling reflects evidential strength, not severity.** A canary match is proof; a regex match is an indicator that a reviewer should confirm. Labelling them high and medium confidence keeps the evidence honest about what each tier actually establishes.

4. **No new dependencies.** Both tiers are standard-library string and regex operations. Consistent with ADR-0001 and ADR-0002, detection adds no runtime dependency and no external service.

## Consequences

- The regex tier will occasionally produce false positives (a coincidental PII-shaped string) and false negatives (obfuscated or paraphrased PII the patterns do not match). Consistent with ADR-0001, we accept bounded heuristic imprecision deliberately, in exchange for the reproducibility and auditability that an LLM-judge or model-based detector cannot provide. The tradeoff is the point, not a limitation to apologise for.
- Confidence tiers must be surfaced in the evidence so a reviewer can distinguish a confirmed canary breach from a regex indicator that warrants confirmation.
- Canary tokens are synthetic and test-only by construction, so they are safe to commit to a public repository and safe to seed into any target.
- The two-tier deterministic design followed directly from the ADR-0001 principle (reproducibility and auditability over model-based judgement); a separate formal comparative evaluation of alternative detectors, such as a named-entity-recognition model, was therefore not undertaken at design time. This is recorded here for provenance honesty.

## Regulatory coverage

The check maps to NIST AI RMF MEASURE 2.10 (privacy risk measurement), OWASP LLM02:2025 (sensitive information disclosure), EU AI Act Article 10(3) (data governance for personal data), and PIPEDA Principle 4.5 (limiting use, disclosure, and retention).

## Revisit

If detection accuracy proves insufficient in a given client context, a model-based or named-entity-recognition detector could be evaluated as an optional, opt-in tier — consistent with the optional `--judge` revisit clause in ADR-0001, and subject to the same requirement that any non-deterministic detector be clearly labelled and never the default.
