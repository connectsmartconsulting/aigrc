# aigrc

**AI Governance Risk and Compliance Automation**

[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-0.1.0--alpha-orange.svg)]()
[![Status](https://img.shields.io/badge/status-early%20development-yellow.svg)]()

> **Status: v0.1.0-alpha** - Early-stage open-source R&D project. The control library, scoring engine, and CLI are working. Live AI system integration, adversarial testing, and CI/CD hooks are on the roadmap (v0.2 onwards). See [Roadmap](#development-roadmap) for what's built vs. what's coming.

An open-source Python framework for AI governance risk and compliance evaluation. The long-term goal: help organizations move beyond documented AI governance policies to validated, auditable, executable governance controls.

Built by [Connect Smart Consulting Inc.](https://connectsmartconsulting.com) - Ottawa, Ontario, Canada.

---

## The Problem We're Working On

Most organizations have AI governance policies documented in GRC tools or SharePoint. Few have a way to verify whether those controls actually perform when something goes wrong.

`aigrc` is our open-source attempt to close that gap - starting with structured control libraries and compliance scoring (v0.1), and progressively adding live system integration, adversarial validation, and CI/CD governance gates.

**This is active R&D.** Contributions, feedback, and issue reports are very welcome.

---

## What's in v0.1.0-alpha

The current release is the foundation layer. It does **not** yet scan live AI systems - it provides the control library, scoring engine, reporting, and CLI scaffolding that v0.2+ will build on.

### Working Today

- **Control library** with 14 governance controls across NIST AI RMF, ISO/IEC 42001, EU AI Act, and OWASP LLM Top 10
- **Scoring engine** that calculates compliance score (0-100%) and risk rating (CRITICAL/HIGH/MEDIUM/LOW/MINIMAL)
- **CLI** with `scan`, `list-controls`, and `version` commands
- **Reporting** in text, JSON, and Markdown formats
- **Tests** - 10 unit tests passing across the control library and scoring engine

### Not Yet Implemented (Coming in v0.2+)

- Live AI system integration (currently controls are checklist-based, not active validators)
- Adversarial testing harness
- CI/CD hooks (GitHub Actions, Jenkins)
- REST API
- Custom control authoring DSL
- Drift detection

See [Development Roadmap](#development-roadmap) below for the phased plan.

---

## Quick Start

### Installation

From source (PyPI release planned for v0.2):

```bash
git clone https://github.com/connectsmartconsulting/aigrc.git
cd aigrc
pip install -e .
```

### Run a Compliance Assessment

```bash
aigrc scan \
  --org "Your Org" \
  --system "Your AI System" \
  --frameworks nist owasp \
  --format markdown \
  --output governance_report.md
```

### Python API

```python
from aigrc import GovernanceScanner, ReportGenerator

scanner = GovernanceScanner(
    organization="Your Org",
    ai_system="Your AI System"
)

result = scanner.run(frameworks=["nist", "owasp"])

reporter = ReportGenerator(result)
reporter.to_markdown("governance_report.md")

print(f"Compliance Score: {result.compliance_score}%")
print(f"Risk Rating: {result.risk_rating}")
```

---

## Framework Coverage (v0.1.0-alpha)

| Framework | Controls in v0.1 | Full Coverage Target |
|-----------|------------------|----------------------|
| NIST AI RMF | 4 (GOVERN, MAP, MEASURE, MANAGE) | v0.3 |
| ISO/IEC 42001 | 3 (Context, Planning, Performance) | v0.3 |
| EU AI Act | 3 (High-Risk AI, Transparency, Data Governance) | v0.3 |
| OWASP LLM Top 10 | 4 (LLM01, LLM02, LLM06, LLM08) | v0.2 |

More controls added every sprint. See [docs/RD_ACTIVITY_LOG.md](docs/RD_ACTIVITY_LOG.md) for development history.

---

## Development Roadmap

| Version | Phase | Status | Target |
|---------|-------|--------|--------|
| v0.1.0-alpha | Foundation - Control library, scoring engine, CLI | **Released** | Q2 2026 |
| v0.2 | API + CI/CD - FastAPI REST, GitHub Actions, Docker, custom controls | Planning | Q3 2026 |
| v0.3 | Live Integration - AI system connectors, adversarial testing harness, drift detection, 30+ controls | Planning | Q4 2026 |
| v1.0 | Platform - Multi-tenant, certification report templates, audit packaging | Planning | Q1 2027 |

This is open R&D - timelines may shift as the project matures.

---

## Development

### Run Tests

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

### Contributing

Contributions are welcome and appreciated. Areas where help is especially valuable:

- Additional governance controls (frameworks, regulations, jurisdictions)
- Validators that move controls from checklist to executable
- CI/CD integration patterns
- Documentation and examples

To contribute:

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Add tests for new functionality
4. Submit a PR

Issues, questions, and feedback are also very welcome via GitHub Issues.

---

## About Connect Smart Consulting Inc.

`aigrc` is part of the broader Connect Smart Assurance Platform (CSAP) under active development by Connect Smart Consulting Inc., an Ottawa-based consultancy specializing in AI governance, cybersecurity validation, and quality engineering assurance.

We help organizations validate that their AI governance controls actually perform - not just that they exist on paper.

- Website: [connectsmartconsulting.com](https://connectsmartconsulting.com)
- Contact: safiuddin@connectsmartconsulting.com
- Founder: Safiuddin Mohammed Ahmed - 18 years in enterprise QA and DevSecOps (S&P Global, Thomson Reuters, Bell Canada, Broadcom, Flight Centre Travel Group)

---

## License

MIT License - see [LICENSE](LICENSE) for details.

Copyright (c) 2026 Connect Smart Consulting Inc.
