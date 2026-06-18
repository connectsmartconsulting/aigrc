# aigrc — AI Governance Runtime Checks

## What this is
Open-source Python CLI for AI behaviour validation. Runs structured adversarial
payloads against an AI system and produces governance traces — replayable
evidence artifacts mapped to regulatory controls.

## Current state
- v0.1.5 released and tagged
- Two live checks: prompt-injection (18 payloads), pii-leakage (12 payloads)
- Four output formats: JSON, SARIF 2.1.0, Markdown, HTML
- 36 tests passing
- Offline mock target for CI (no API key required)

## Repo structure
aigrc/checks/          — one file per check (prompt_injection_basic.py, pii_leakage_basic.py)
aigrc/core/            — Target abstraction (target.py), Reporter (reporter.py), models (models.py), registry (registry.py)
aigrc/cli.py           — CLI dispatcher (typer)
docs/decisions/        — Architecture Decision Records (ADR-0001 to ADR-0004)
docs/ROADMAP.md        — Delivery roadmap
tests/                 — pytest suite (test_prompt_injection.py, test_pii_leakage.py, test_target.py, test_evidence_hash.py)

## Standards
- Each check: CHECK_ID, CHECK_VERSION, REGULATORY_MAPPINGS, run() function returning CheckResult
- Commits follow conventional commits: feat/fix/docs/test/chore(scope): message
- pytest must pass before every commit — no exceptions
- CHANGELOG.md updated with every release tag
- Add files by name — never git add . (keeps build artifacts out of commits)

## Environment
- Virtual environment: .venv (at repo root)
- Python: 3.10+
- Activate: source .venv/bin/activate
- Run tests: python -m pytest -q
- Install dev dependencies: pip install -e ".[dev]"

## Target schemes
- mock://moderate, mock://strict, mock://leaky — offline deterministic targets
- openai://model-name — resolves to OpenAI chat completions endpoint
- https://... — raw OpenAI-compatible endpoint passthrough
