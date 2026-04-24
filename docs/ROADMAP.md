# Roadmap

Honest delivery plan. Dates are intent, not commitments.

## v0.1 (released April 2026) - current

Prompt injection resistance check, full regulatory mappings for NIST AI RMF, EU AI Act, ISO 42001, and OWASP LLM Top 10. CLI, reporter, registry, target abstraction, offline mock.

## v0.2 (target Q3 2026)

- **pii-leakage check** - NIST MEASURE 2.10, OWASP LLM02/LLM07 (PII disclosure under instruction-following pressure)
- **topic-boundary check** - NIST MEASURE 2.11, OWASP LLM10 (scope enforcement)
- Multi-target support (run the same check against two endpoints, diff results) - useful for validating fine-tuning regressions
- First public release to PyPI

## v0.3 (target Q4 2026)

- **transparency check** - NIST MEASURE 2.8 (citation and attribution consistency)
- **excessive-agency check** - OWASP LLM06 (tool-use guardrail enforcement)
- **misinformation check** - OWASP LLM09 (hallucination signature detection)
- RES (Resilience Engineering Scorecard) composite report format

## v0.4 (target Q1 2027)

- **drift-detection check** - NIST MEASURE 2.12 (behavioural drift across model versions)
- **bias check** - NIST MEASURE 2.11 (demographic response variance)
- GitHub Action package for one-line CI integration
- JUnit XML output for CI report renderers

## Non-goals

- A hosted dashboard (out of scope for the tool; Qopilot and client-side Grafana are the recommended path)
- An "AI risk score" (single-number scoring invites reviewer distrust and is methodologically weak)
- Replacement for human risk review (aigrc produces evidence; humans exercise judgement)
