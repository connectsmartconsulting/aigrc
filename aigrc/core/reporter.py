"""Report writers: JSON (machine readable) and Markdown (audit binder)."""

from __future__ import annotations

import json
from pathlib import Path

from aigrc.core.models import CheckResult


class Reporter:
    @staticmethod
    def write_json(result: CheckResult, path: Path) -> Path:
        path.write_text(json.dumps(result.model_dump(), indent=2))
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
