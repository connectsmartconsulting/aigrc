# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.2] - 2026-04-27

### Fixed
- **Critical:** v0.1.1 published the SARIF test, README documentation, and version
  bump but did not actually include the implementation changes to `cli.py` and
  `aigrc/core/reporter.py`. As a result, v0.1.1 fails on `import` time with both
  an `AttributeError` (no `Reporter.write_sarif`) and a separate `SyntaxError`
  in the prompt-injection check metadata (a latent v0.1.0 corruption). v0.1.2
  ships the missing SARIF implementation and repairs the metadata string.
- Restore correct `description` field in `prompt-injection` check metadata.
- Untrack `__pycache__` artefacts that were inadvertently committed; add them
  to `.gitignore`.

### Notes
- Users on v0.1.0 or v0.1.1 should upgrade to v0.1.2.
- v0.1.0 and v0.1.1 GitHub Releases will be annotated with a deprecation notice
  pointing to v0.1.2.
  
## [0.1.2] - 2026-04-27

### Fixed
- Corrupted metadata `description` string in `prompt-injection` check. The bug
  was a silent latent issue from v0.1.0 that did not surface until v0.1.1 added
  a SARIF test which imports the check module. v0.1.0 and v0.1.1 are both
  affected and should not be used; v0.1.2 is the recommended baseline release.
  
## [0.1.1] - 2026-04-27

### Added
- SARIF v2.1.0 report output (`--report-sarif <path>`). aigrc findings now flow
  natively into GitHub Code Scanning, GitLab Security Dashboards, Azure DevOps,
  and any tooling that consumes the OASIS SARIF standard. Each rule carries the
  full regulatory mapping (NIST AI RMF, EU AI Act, ISO 42001, OWASP LLM Top 10)
  in its description and on every result, so security teams can trace findings
  back to the specific regulatory control without leaving their existing dashboard.
- Test coverage for SARIF output, validating schema compliance and framework
  metadata propagation.
- ADR-0002 documenting the decision to ship SARIF as the third report format.

## [0.1.0] - 2026-04-23

### Added
- Initial public release.
- `prompt-injection` check with 18-payload OWASP LLM01 taxonomy coverage (direct override, encoded payload, role confusion, hypothetical framing, emotional framing, prompt leakage, delimiter injection, unicode confusable, hierarchy flip, refusal suppression, language switch, task redirection, markdown injection, scope violation, data exfiltration).
- Regulatory mappings for NIST AI RMF (MEASURE 2.6, 2.7), EU AI Act Article 15, ISO/IEC 42001 A.7.4 / A.6.2.6, and OWASP LLM Top 10 2025 (LLM01, LLM07).
- Typer-based CLI with `version`, `list`, and `check` subcommands.
- JSON and Markdown reporters.
- OpenAI-compatible target (any endpoint exposing POST /v1/chat/completions) plus offline deterministic mock target for CI and demos.
- GitHub Actions workflow running pytest, ruff, and CLI smoke tests against Python 3.10, 3.11, and 3.12.
- Architecture and roadmap documentation.
