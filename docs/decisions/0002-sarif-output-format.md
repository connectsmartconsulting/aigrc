# ADR-0002: SARIF v2.1.0 as the third report format

**Status:** Accepted
**Date:** 2026-04-27

## Context

aigrc v0.1.0 shipped with two report formats: a JSON evidence file (machine-readable, schema-defined by our Pydantic models) and a Markdown audit binder (human-readable, aimed at risk committees and engagement deliverables).

Within a few days of the release it became clear there is a third audience we had not served: the security engineering function inside our prospective clients. These teams already operate on SARIF (Static Analysis Results Interchange Format), the OASIS standard consumed by GitHub Code Scanning, GitLab Security Dashboards, Azure DevOps, and most modern CI security tooling. They do not want a third dashboard. They want findings to appear in the dashboard they already use.

We had to decide whether to add SARIF as a first-class output format or whether to stick with the two original formats and let users transform JSON to SARIF themselves.

## Decision

aigrc v0.1.1 adds SARIF v2.1.0 as a first-class report format, opt-in via `--report-sarif <path>`. The Pydantic JSON output remains the canonical aigrc-native format. SARIF is a derived, lossy projection optimised for consumption by external security tooling.

## Rationale

1. **Distribution leverage.** A team that runs aigrc in their pipeline and uploads a SARIF artefact to GitHub Code Scanning gets findings in the Security tab automatically — same place their CodeQL and Dependabot results appear. That is a far stronger integration story for adoption than asking them to write a transformer.

2. **Regulatory traceability is preserved.** SARIF supports `properties` on rules and results. We embed the framework mappings (NIST AI RMF MEASURE 2.7, OWASP LLM01:2025, EU AI Act Article 15, ISO 42001 A.7.4) directly on each finding. Engineers reading findings in GitHub Security tab see the regulatory control that was violated, not just a technical attack class.

3. **Consistent with the separation-of-concerns principle from ADR-0001.** Deterministic heuristics produce findings; multiple reporters render the findings for different audiences. Adding a reporter is the cheap, correct extension point.

4. **No new dependencies.** SARIF is JSON. The implementation is approximately 80 lines of code with zero new runtime dependencies.

## Consequences

- aigrc now has three reporters to maintain: JSON, Markdown, SARIF. Each test suite must validate all three.
- The SARIF projection is lossy: it only emits FAIL findings as `results`, with PASS findings represented in the run-level summary properties. This matches SARIF convention (results are findings to act on), but means a SARIF consumer cannot reconstruct full evidence — they must consult the JSON or Markdown reports for that.
- We commit to following SARIF v2.1.0 spec changes if and when OASIS publishes minor updates.

## Implementation notes

- Schema URL pinned to the OASIS-hosted v2.1.0 schema.
- `level` set to `error` for all FAIL results. We consider any prompt injection bypass an error worth surfacing in CI; teams who disagree can downgrade via SARIF post-processing.
- Rule IDs are the `technique` strings (`direct_override`, `encoded_payload`, etc.). Stable across releases. Renaming a technique would be a breaking change requiring a major version bump.

## Revisit

If real-world use shows that consumers need a different result shape (for example, GitLab's Security Dashboard preferring a flatter property layout), we will revisit before v1.0. We will not change the JSON or Markdown formats to accommodate SARIF consumer preferences.
