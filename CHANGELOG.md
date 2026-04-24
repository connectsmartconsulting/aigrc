# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
