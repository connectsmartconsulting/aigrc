"""Report writers: JSON (machine readable), Markdown (audit binder), SARIF (CI security tools)."""

from __future__ import annotations

import json
from pathlib import Path

from aigrc.core.models import CheckResult, Outcome


class Reporter:
    @staticmethod
    def write_json(result: CheckResult, path: Path) -> Path:
        path.write_text(json.dumps(result.model_dump(), indent=2))
        return path

    @staticmethod
    def write_sarif(result: CheckResult, path: Path) -> Path:
        """Write a SARIF v2.1.0 report.

        SARIF (Static Analysis Results Interchange Format) is the OASIS standard
        consumed by GitHub Code Scanning, GitLab security dashboards, Azure DevOps,
        and most modern CI security tooling. Producing SARIF means findings show
        up natively in those tools without custom parsing.

        Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
        """
        rules = []
        seen_techniques: set[str] = set()
        for p in result.payloads:
            if p.technique in seen_techniques:
                continue
            seen_techniques.add(p.technique)
            rules.append({
                "id": p.technique,
                "name": p.technique.replace("_", " ").title().replace(" ", ""),
                "shortDescription": {"text": f"AI prompt injection: {p.technique.replace('_', ' ')}"},
                "fullDescription": {
                    "text": (
                        f"Detects whether the target AI system resists "
                        f"{p.technique.replace('_', ' ')} attacks. Mapped to "
                        + ", ".join(f"{f.framework} {f.control_id}" for f in result.frameworks)
                        + "."
                    )
                },
                "defaultConfiguration": {"level": "warning"},
                "helpUri": "https://github.com/connectsmartconsulting/aigrc",
            })

        results = []
        for p in result.payloads:
            if p.outcome != Outcome.FAIL:
                continue
            results.append({
                "ruleId": p.technique,
                "level": "error",
                "message": {
                    "text": f"{p.label}: {p.evidence}"
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": result.target},
                        "region": {"startLine": 1, "startColumn": 1},
                    }
                }],
                "properties": {
                    "payloadId": p.payload_id,
                    "technique": p.technique,
                    "elapsedMs": p.elapsed_ms,
                    "frameworks": [
                        f"{f.framework} {f.control_id}" for f in result.frameworks
                    ],
                },
            })

        sarif = {
            "version": "2.1.0",
            "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "aigrc",
                        "version": result.check_version,
                        "informationUri": "https://github.com/connectsmartconsulting/aigrc",
                        "organization": "Connect Smart Consulting Inc.",
                        "shortDescription": {"text": "Executable AI governance checks mapped to NIST AI RMF, EU AI Act, ISO 42001, and OWASP LLM Top 10."},
                        "rules": rules,
                    }
                },
                "invocations": [{
                    "executionSuccessful": result.errored == 0,
                    "startTimeUtc": result.started_at,
                    "endTimeUtc": result.finished_at,
                }],
                "results": results,
                "properties": {
                    "checkId": result.check_id,
                    "passRate": result.pass_rate,
                    "summary": result.summary,
                    "totalPayloads": len(result.payloads),
                    "passed": result.passed,
                    "failed": result.failed,
                    "errored": result.errored,
                },
            }],
        }
        path.write_text(json.dumps(sarif, indent=2))
        return path

    @staticmethod
    def write_markdown(result: CheckResult, path: Path) -> Path:
        lines = []
        lines.append(f"# aigrc evidence report")
        lines.append("")
        lines.append(f"**Check:** `{result.check_id}` v{result.check_version}")
        lines.append(f"**Target:** `{result.target}`")
        if result.model_hint:
            lines.append(f"**Model:** `{result.model_hint}`")
        lines.append(f"**Started:** {result.started_at}")
        lines.append(f"**Finished:** {result.finished_at}")
        lines.append(f"**Offline mode:** {'yes' if result.offline else 'no'}")
        lines.append("")
        lines.append("## Regulatory mapping")
        lines.append("")
        lines.append("| Framework | Control | Title |")
        lines.append("|---|---|---|")
        for f in result.frameworks:
            lines.append(f"| {f.framework} | {f.control_id} | {f.title} |")
        lines.append("")
        lines.append("## Summary")
        lines.append("")
        lines.append(f"- Total payloads: {len(result.payloads)}")
        lines.append(f"- Passed: {result.passed}")
        lines.append(f"- Failed: {result.failed}")
        lines.append(f"- Errored: {result.errored}")
        lines.append(f"- Pass rate: {result.pass_rate:.1f}%")
        lines.append("")
        lines.append(f"**Overall:** {result.summary}")
        lines.append("")
        lines.append("## Findings")
        lines.append("")
        lines.append("| # | Payload | Technique | Outcome | Evidence |")
        lines.append("|---|---|---|---|---|")
        for i, p in enumerate(result.payloads, 1):
            ev = p.evidence.replace("|", "\\|")[:120]
            lines.append(f"| {i} | {p.label} | {p.technique} | **{p.outcome.value}** | {ev} |")
        lines.append("")
        lines.append("## Notes")
        lines.append("")
        lines.append(
            "This report was produced by aigrc. Each payload is mapped to a regulatory "
            "control in the metadata above. For translation into business-language "
            "narrative and remediation guidance, see the companion tool Qopilot "
            "(`qopilot interpret --report <this-report>.json`)."
        )
        path.write_text("\n".join(lines))
        return path
