# Roadmap

Honest delivery plan. Dates are intent, not commitments.

## v0.1.2 (released May 2026) - current

Prompt injection resistance check (18 payloads) and pii-leakage check (12 payloads). Full regulatory mappings for NIST AI RMF, EU AI Act, ISO 42001, OWASP LLM Top 10, and PIPEDA. CLI, reporter (JSON/SARIF/Markdown/HTML), registry, target abstraction, offline mock. 25 tests passing.

## v0.1.3 (target May 2026)

Regulatory metadata additions to the prompt-injection check. No payload logic change. Makes every aigrc output telecom-credible.

- Add CRTC consumer protection mandate label -- for carrier-deployed AI affecting service quality and customer outcomes
- Add EU AI Act Article 50 label -- transparency disclosure for customer-facing AI
- Add ETSI GR SAI 002 label -- telecom-specific AI security standards vocabulary
- Add 3GPP TS 28.105 label -- AI/ML management specification, human oversight clause
- Add 3GPP context header to Markdown report: system under test, governing 3GPP Release, design-time mandate, runtime evidence

**Target vertical:** AI-powered applications serving 3GPP-governed networks -- carrier chatbots, billing AI, fraud detection, NOC tools. These systems expose OpenAI-compatible endpoints aigrc can reach today. RAN AI, NWDAF, and embedded 3GPP network functions are explicitly out of scope.

## v0.2 (target Q3 2026)

- **topic-boundary check** -- CRTC consumer protection, EU AI Act Article 50, NIST AI RMF MANAGE 2.2, TM Forum ODA, 3GPP TR 22.874. Primary telecom demonstration check. A carrier chatbot must not respond outside its defined scope; topic-boundary failure has direct CRTC and Article 50 implications.
- **qopilot --vertical telecom flag** ships with this release -- telecom prompt template, TM Forum eTOM remediation vocabulary, CRTC-ready evidence binder preamble.
- Multi-target support (run the same check against two endpoints, diff results) -- useful for validating fine-tuning regressions
- First public release to PyPI

## v0.3 (target Q4 2026)

- **pii-leakage check (telecom)** -- PIPEDA, EU AI Act Article 50, 3GPP TS 28.105 data governance. Probes indirect PII exposure through AI reasoning chains in systems handling subscriber data.
- **human-override verification check** -- EU AI Act Article 14, NIST AI RMF GOVERN 1.7, 3GPP TS 28.105. Validates that AI-powered NOC tools and agentic network assistants preserve human override capability in their interfaces and API responses. Scoped to tools with user-facing interfaces -- not embedded network AI.
- **transparency check** -- NIST MEASURE 2.8 (citation and attribution consistency)
- **excessive-agency check** -- OWASP LLM06 (tool-use guardrail enforcement)
- **RES Resilience Engineering Scorecard** -- composite scoring layer aggregating aigrc check results across all five governance layers. Includes RES Telecom Profile variant with Critical weighting on PII leakage and human-override dimensions.

## v0.4 (target Q1 2027)

- **data-residency boundary check** -- PIPEDA, CRTC, incoming federal statute. Monitors outbound API calls during AI inference to detect residency violations in real time. Uniquely Canadian moat -- no US-headquartered competitor prioritises Canadian data-residency validation.
- **drift-detection check** -- NIST MEASURE 2.12 (behavioural drift across model versions). Network AI drift has direct SLA impact and triggers carrier reporting obligations.
- **bias check** -- NIST MEASURE 2.11 (demographic response variance)
- GitHub Action package for one-line CI integration
- JUnit XML output for CI report renderers
- Qopilot platform beta -- continuous monitoring, telecom vertical dashboard, automated CRTC audit-readiness indicator

## 3GPP Reference Map

aigrc checks map to the following 3GPP specifications:

| Specification | Scope | aigrc Touch Point |
|---|---|---|
| 3GPP TS 28.105 | AI/ML Management. Human oversight requirements for network AI decisions. | human-override check (v0.3). Named in all telecom output metadata from v0.1.3. |
| 3GPP TR 22.874 | Study on AI/ML use cases. Catalogues the AI applications telecom operators are deploying. | topic-boundary and pii-leakage checks (v0.2, v0.3). |
| 3GPP TR 37.817 | AI/ML for NG-RAN. RAN-layer AI systems. | Context reference only. aigrc does not validate RAN AI directly. |
| 3GPP Release 18 | 5G-Advanced. AI/ML native to RAN specification. | Architectural basis for the network the application layer aigrc validates is built to serve. |
| 3GPP Release 19 | AI/ML extension into 5G core. In progress. | Future roadmap anchor. Shows telecom AI governance demand is growing. |

## Non-goals

- Validation of embedded RAN AI, NWDAF, or 3GPP network functions (these have no OpenAI-compatible endpoint aigrc can reach)
- A hosted dashboard (out of scope for the tool; Qopilot and client-side Grafana are the recommended path)
- An "AI risk score" (single-number scoring invites reviewer distrust and is methodologically weak)
- Replacement for human risk review (aigrc produces evidence; humans exercise judgement)
