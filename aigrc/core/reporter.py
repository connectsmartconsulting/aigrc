"""Report writers: JSON (machine readable), Markdown (audit binder), SARIF (CI security tools), HTML (client delivery)."""

from __future__ import annotations

import json
from pathlib import Path

from aigrc.core.models import CheckResult, Outcome

try:
    from res.scorer import score_report as _res_score
    _RES_AVAILABLE = True
except ImportError:
    _RES_AVAILABLE = False


def _res_panel_html(result: CheckResult) -> str:
    """Generate RES scorecard HTML panel. Returns empty string if res not installed."""
    if not _RES_AVAILABLE:
        return ""
    try:
        res_data = _res_score(result.model_dump())
        overall = res_data["overall_score"]
        risk = res_data["risk_level"]
        verdict = res_data["verdict"]
        score_class = f"score-{risk}"

        layer_cells = ""
        for lk in ["L1", "L2", "L3", "L4", "L5"]:
            ld = res_data["layer_scores"][lk]
            if ld["score"] is None:
                layer_cells += (
                    f'<div class="res-layer">'
                    f'<div class="res-layer-score res-not-tested">&#8212;</div>'
                    f'<div class="res-layer-name">{ld["name"]}</div>'
                    f'<div class="res-layer-tag">{lk} &middot; not tested</div>'
                    f'</div>'
                )
            else:
                sc = ld["score"]
                if sc >= 90:
                    sc_class = "score-low"
                elif sc >= 70:
                    sc_class = "score-moderate"
                elif sc >= 50:
                    sc_class = "score-elevated"
                else:
                    sc_class = "score-high"
                layer_cells += (
                    f'<div class="res-layer">'
                    f'<div class="res-layer-score {sc_class}">{sc:.0f}</div>'
                    f'<div class="res-layer-name">{ld["name"]}</div>'
                    f'<div class="res-layer-tag">{lk} &middot; {ld["passes"]}/{ld["tested"]}</div>'
                    f'</div>'
                )

        return f"""
  <div class="res-panel">
    <div class="res-header">
      <div>
        <div class="res-title">Resilience Engineering Scorecard (RES v0.1.0)</div>
        <div class="res-subtitle">Willis 5-layer AI governance assessment</div>
      </div>
      <div class="res-score-block">
        <div class="res-score-num {score_class}">{overall:.1f}<span class="res-score-denom">/100</span></div>
        <div class="res-verdict {score_class}">{verdict}</div>
      </div>
    </div>
    <div class="res-layers">{layer_cells}</div>
  </div>"""
    except Exception:
        return ""


class Reporter:
    @staticmethod
    def write_json(result: CheckResult, path: Path) -> Path:
        path.write_text(json.dumps(result.model_dump(), indent=2))
        return path

    @staticmethod
    def write_sarif(result: CheckResult, path: Path) -> Path:
        """Write a SARIF v2.1.0 report."""
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
                "message": {"text": f"{p.label}: {p.evidence}"},
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
                    "frameworks": [f"{f.framework} {f.control_id}" for f in result.frameworks],
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
        lines.append("# aigrc evidence report")
        lines.append("")
        lines.append(f"**Check:** `{result.check_id}` v{result.check_version}")
        lines.append(f"**Target:** `{result.target}`")
        if result.model_hint:
            lines.append(f"**Model:** `{result.model_hint}`")
        lines.append(f"**Started:** {result.started_at}")
        lines.append(f"**Finished:** {result.finished_at}")
        lines.append(f"**Offline mode:** {'yes' if result.offline else 'no'}")
        lines.append("")
        has_3gpp = any("3GPP" in f.framework for f in result.frameworks)
        if has_3gpp:
            lines.append("")
            lines.append("## 3GPP context")
            lines.append("")
            lines.append(
                f"**System under test:** `{result.target}`  "
                f"**Design-time mandate:** 3GPP TS 28.105 (AI/ML Management)  "
                f"**Runtime evidence:** this report."
            )
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

    @staticmethod
    def write_html(result: CheckResult, path: Path) -> Path:
        """Write a self-contained HTML evidence report with RES scorecard panel."""
        pass_color = "#2dd4bf"
        fail_color = "#f87171"
        warn_color = "#fbbf24"

        summary_color = {
            "COMPLIANT": pass_color,
            "PARTIAL COMPLIANCE": warn_color,
            "NON-COMPLIANT": fail_color,
        }.get(result.summary, warn_color)

        framework_rows = ""
        for f in result.frameworks:
            framework_rows += f"<tr><td>{f.framework}</td><td>{f.control_id}</td><td>{f.title}</td></tr>\n"

        payload_rows = ""
        for i, p in enumerate(result.payloads, 1):
            outcome_val = p.outcome.value
            if outcome_val == "PASS":
                badge = '<span class="badge pass">PASS</span>'
            elif outcome_val == "FAIL":
                badge = '<span class="badge fail">FAIL</span>'
            else:
                badge = f'<span class="badge warn">{outcome_val}</span>'
            ev = p.evidence[:120].replace("<", "&lt;").replace(">", "&gt;")
            payload_rows += (
                f"<tr>"
                f"<td>{i}</td>"
                f"<td>{p.label}</td>"
                f"<td><code>{p.technique}</code></td>"
                f"<td>{badge}</td>"
                f"<td>{ev}</td>"
                f"</tr>\n"
            )

        offline_badge = "Yes" if result.offline else "No"
        model_row = f"<tr><td>Model</td><td><code>{result.model_hint}</code></td></tr>" if result.model_hint else ""

        res_panel = _res_panel_html(result)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>aigrc Evidence Report — {result.check_id}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         background: #0f172a; color: #e2e8f0; line-height: 1.6; }}
  .container {{ max-width: 960px; margin: 0 auto; padding: 2rem 1.5rem; }}
  header {{ border-bottom: 2px solid #1e3a5f; padding-bottom: 1.5rem; margin-bottom: 2rem; }}
  .logo {{ font-size: 0.75rem; letter-spacing: 0.15em; color: #64b5c8;
           text-transform: uppercase; margin-bottom: 0.5rem; }}
  h1 {{ font-size: 1.5rem; font-weight: 700; color: #f1f5f9; }}
  h1 code {{ background: #1e3a5f; padding: 0.1em 0.4em; border-radius: 4px;
             font-size: 1.3rem; color: {pass_color}; }}
  h2 {{ font-size: 1rem; font-weight: 600; color: #94a3b8; letter-spacing: 0.08em;
        text-transform: uppercase; margin: 2rem 0 0.75rem; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.875rem; }}
  th {{ text-align: left; padding: 0.5rem 0.75rem; background: #1e293b;
        color: #94a3b8; font-weight: 600; font-size: 0.75rem;
        text-transform: uppercase; letter-spacing: 0.05em; }}
  td {{ padding: 0.5rem 0.75rem; border-bottom: 1px solid #1e293b; vertical-align: top; }}
  tr:last-child td {{ border-bottom: none; }}
  code {{ background: #1e293b; padding: 0.1em 0.35em; border-radius: 3px;
          font-size: 0.8em; color: #7dd3fc; }}
  .summary-box {{ background: #1e293b; border-left: 4px solid {summary_color};
                  border-radius: 6px; padding: 1.25rem 1.5rem; margin: 1.5rem 0; }}
  .summary-status {{ font-size: 1.25rem; font-weight: 700; color: {summary_color}; }}
  .summary-rate {{ font-size: 0.875rem; color: #94a3b8; margin-top: 0.25rem; }}
  .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin: 1.5rem 0; }}
  .stat {{ background: #1e293b; border-radius: 6px; padding: 1rem; text-align: center; }}
  .stat-value {{ font-size: 1.5rem; font-weight: 700; }}
  .stat-label {{ font-size: 0.75rem; color: #94a3b8; text-transform: uppercase;
                 letter-spacing: 0.05em; margin-top: 0.25rem; }}
  .passed {{ color: {pass_color}; }}
  .failed {{ color: {fail_color}; }}
  .badge {{ display: inline-block; padding: 0.15em 0.5em; border-radius: 3px;
            font-size: 0.75rem; font-weight: 700; letter-spacing: 0.05em; }}
  .badge.pass {{ background: #064e3b; color: {pass_color}; }}
  .badge.fail {{ background: #450a0a; color: {fail_color}; }}
  .badge.warn {{ background: #451a03; color: {warn_color}; }}
  .res-panel {{ background: #0d1e3a; border: 1px solid #1e3a5f; border-radius: 8px;
                padding: 1.5rem; margin-bottom: 2rem; }}
  .res-header {{ display: flex; align-items: center; justify-content: space-between;
                 margin-bottom: 1rem; }}
  .res-title {{ font-size: 0.7rem; letter-spacing: 0.15em; color: #4a9eda;
                text-transform: uppercase; font-weight: 600; }}
  .res-subtitle {{ font-size: 0.8rem; color: #94a3b8; margin-top: 0.2rem; }}
  .res-score-block {{ text-align: right; }}
  .res-score-num {{ font-size: 2.5rem; font-weight: 700; line-height: 1; }}
  .res-score-denom {{ font-size: 1rem; color: #475569; }}
  .res-verdict {{ font-size: 0.75rem; font-weight: 600; letter-spacing: 0.08em;
                  text-transform: uppercase; margin-top: 0.2rem; }}
  .res-layers {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 0.75rem; }}
  .res-layer {{ background: #1e293b; border-radius: 6px; padding: 0.75rem; text-align: center; }}
  .res-layer-score {{ font-size: 1.25rem; font-weight: 700; }}
  .res-layer-name {{ font-size: 0.65rem; color: #94a3b8; text-transform: uppercase;
                     letter-spacing: 0.06em; margin-top: 0.2rem; }}
  .res-layer-tag {{ font-size: 0.6rem; color: #475569; margin-top: 0.1rem; }}
  .res-not-tested {{ color: #475569; }}
  .score-low {{ color: {pass_color}; }}
  .score-moderate {{ color: {warn_color}; }}
  .score-elevated {{ color: #fb923c; }}
  .score-high {{ color: {fail_color}; }}
  footer {{ margin-top: 3rem; padding-top: 1.5rem; border-top: 1px solid #1e293b;
            font-size: 0.75rem; color: #475569; }}
  footer a {{ color: #64b5c8; text-decoration: none; }}
</style>
</head>
<body>
<div class="container">
  <header>
    <div class="logo">Connect Smart Consulting Inc. — aigrc v{result.check_version}</div>
    <h1>Evidence Report: <code>{result.check_id}</code></h1>
  </header>
{res_panel}
  <h2>Run details</h2>
  <table>
    <tr><td>Target</td><td><code>{result.target}</code></td></tr>
    {model_row}
    <tr><td>Started</td><td>{result.started_at}</td></tr>
    <tr><td>Finished</td><td>{result.finished_at}</td></tr>
    <tr><td>Offline mode</td><td>{offline_badge}</td></tr>
  </table>

  <h2>Regulatory mapping</h2>
  <table>
    <thead><tr><th>Framework</th><th>Control</th><th>Title</th></tr></thead>
    <tbody>{framework_rows}</tbody>
  </table>

  <h2>Result</h2>
  <div class="summary-box">
    <div class="summary-status">{result.summary}</div>
    <div class="summary-rate">Pass rate: {result.pass_rate:.1f}%</div>
  </div>
  <div class="stats">
    <div class="stat"><div class="stat-value">{len(result.payloads)}</div>
      <div class="stat-label">Total</div></div>
    <div class="stat"><div class="stat-value passed">{result.passed}</div>
      <div class="stat-label">Passed</div></div>
    <div class="stat"><div class="stat-value failed">{result.failed}</div>
      <div class="stat-label">Failed</div></div>
    <div class="stat"><div class="stat-value">{result.errored}</div>
      <div class="stat-label">Errored</div></div>
  </div>

  <h2>Payload findings</h2>
  <table>
    <thead>
      <tr><th>#</th><th>Payload</th><th>Technique</th><th>Outcome</th><th>Evidence</th></tr>
    </thead>
    <tbody>{payload_rows}</tbody>
  </table>

  <footer>
    Generated by <a href="https://github.com/connectsmartconsulting/aigrc">aigrc</a>
    — <a href="https://connectsmartconsulting.com">Connect Smart Consulting Inc.</a>
    — RES scorecard powered by <a href="https://github.com/connectsmartconsulting/res">res</a>
    — For audit narrative see <a href="https://github.com/connectsmartconsulting/qopilot">Qopilot</a>.
  </footer>
</div>
</body>
</html>"""
        path.write_text(html, encoding="utf-8")
        return path
