# aigrc — AI Governance Runtime Checks

## What this is
Open-source Python CLI for AI behaviour validation. Part of Connect Smart 
Consulting's AI-GRC framework.

## Current state
- v0.1.2 released and tagged
- One live check: prompt-injection (18 payloads, JSON/SARIF/Markdown output)
- Next: pii-leakage check (v0.2.0, target: May 24)

## Repo structure
aigrc/checks/          — one file per check (prompt_injection_basic.py is the template)
aigrc/core/reporter.py — Reporter class: write_json, write_markdown, write_sarif
aigrc/targets/mock.py  — MockTarget, handles mock://moderate and mock://strict
aigrc/cli.py           — CLI dispatcher
tests/                 — pytest suite (must pass: all green before any commit)

## Standards
- Each check: CHECK_ID, CHECK_VERSION, REGULATORY_MAPPINGS, PAYLOADS list, run() function
- run() returns dict consumed by Reporter
- Commits follow conventional commits: feat/fix/docs/test/chore(scope): message
- pytest must pass before every commit — no exceptions
- CHANGELOG.md updated with every release tag
