"""aigrc CLI."""

from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from aigrc import __version__
from aigrc.checks import prompt_injection_basic  # noqa: F401 - registration
from aigrc.checks import pii_leakage_basic  # noqa: F401 - registration
from aigrc.core import Reporter, build_target, get_registry

app = typer.Typer(
    no_args_is_help=True,
    add_completion=False,
    help="aigrc: executable AI governance checks mapped to regulatory frameworks.",
)
console = Console()

# AGCP RG-3 and RG-6 technique to Willis layer mapping
_TECHNIQUE_TO_LAYER: dict[str, str] = {
    "direct_override":     "L2",
    "role_confusion":      "L2",
    "hypothetical":        "L2",
    "emotional_framing":   "L2",
    "language_switch":     "L2",
    "hierarchy_flip":      "L3",
    "refusal_suppression": "L3",
    "task_redirection":    "L3",
    "scope_violation":     "L3",
    "encoded_payload":     "L4",
    "delimiter_injection": "L4",
    "indirect_injection":  "L4",
    "unicode_confusable":  "L4",
    "markdown_injection":  "L4",
    "data_exfiltration":   "L4",
    "prompt_leak":         "L5",
    "pii_direct":          "L2",
    "pii_indirect":        "L2",
    "pii_context":         "L3",
    "pii_encoded":         "L4",
}


def _agcp_fields(result) -> dict:
    """Compute AGCP Phase 1 conformance fields from a CheckResult.

    Evidence hash recipe (documented for independent verification):
      1. Take the tagged payload list exactly as it appears in the output
         "payloads" field (each payload's model_dump(), including agcp_layer).
      2. Serialize with json.dumps(..., sort_keys=True, separators=(",", ":")).
      3. SHA-256 the UTF-8 encoding of that string; the hex digest is
         evidence_hash.
    A verifier can recompute the hash from the published "payloads" array alone.
    """
    # Tag each payload with its Willis/AGCP layer FIRST, so the hash covers
    # exactly the evidence that ships in the "payloads" field.
    tagged_payloads = [
        p.model_copy(update={"agcp_layer": _TECHNIQUE_TO_LAYER.get(p.technique, "L2")})
        for p in result.payloads
    ]

    payload_json = json.dumps(
        [p.model_dump() for p in tagged_payloads],
        sort_keys=True,
        separators=(",", ":"),
    )
    evidence_hash = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
    evidence_id = str(uuid.uuid4())

    layers_covered = sorted({
        _TECHNIQUE_TO_LAYER.get(p.technique, "L2") for p in result.payloads
    })

    return {
        "evidence_id": evidence_id,
        "evidence_hash": evidence_hash,
        "source_system": "aigrc",
        "evaluation_timestamp": result.started_at,
        "provenance_chain": [
            {"tool": "aigrc", "version": __version__, "evidence_hash": evidence_hash}
        ],
        "agcp_conformance_levels": layers_covered,
        "payloads": tagged_payloads,
    }


@app.command("version")
def _version():
    """Print aigrc version."""
    console.print(f"aigrc v{__version__}")


@app.command("list")
def list_checks():
    """List available checks with their regulatory mappings."""
    reg = get_registry()
    table = Table(title="aigrc checks")
    table.add_column("Check ID", style="cyan")
    table.add_column("Version")
    table.add_column("Frameworks")
    for cid in reg.list_checks():
        meta = reg.metadata(cid)
        fws = ", ".join(f"{f['framework']} {f['control_id']}" for f in meta.get("frameworks", []))
        table.add_row(cid, meta.get("version", ""), fws)
    console.print(table)


@app.command("check")
def run_check(
    name: str = typer.Argument(..., help="Check id, e.g. 'prompt-injection'"),
    target: str = typer.Option(..., "--target", help="Endpoint URL or mock://..."),
    model: str = typer.Option("gpt-4o-mini", "--model", help="Model hint for target"),
    offline: bool = typer.Option(False, "--offline", help="Run against mock target"),
    fail_below: float = typer.Option(0.0, "--fail-below", help="Exit nonzero if pass rate below this percent"),
    report_json: Path = typer.Option(None, "--report-json", help="JSON report path"),
    report_md: Path = typer.Option(None, "--report-md", help="Markdown report path"),
    report_sarif: Path = typer.Option(None, "--report-sarif", help="SARIF v2.1.0 report path (for GitHub Code Scanning, etc.)"),
    report_html: Path = typer.Option(None, "--report-html", help="Self-contained HTML report path"),
):
    """Run a check against a target."""
    reg = get_registry()
    try:
        check_fn = reg.get(name)
    except KeyError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(code=2)

    tgt = build_target(target, model=model, offline=offline)

    console.print(f"[bold]aigrc v{__version__}[/bold]  Check: [cyan]{name}[/cyan]")
    meta = reg.metadata(name)
    fws = "   ".join(f"{f['framework']}: {f['control_id']}" for f in meta.get("frameworks", [])[:3])
    console.print(f"[dim]{fws}[/dim]")
    console.print("")

    result = check_fn(tgt, offline=offline)

    # Enrich with AGCP Phase 1 conformance fields
    result = result.model_copy(update=_agcp_fields(result))

    for i, p in enumerate(result.payloads, 1):
        color = {"PASS": "green", "FAIL": "red", "ERROR": "yellow"}[p.outcome.value]
        console.print(
            f"[{color}][{i:2d}/{len(result.payloads)}][/{color}] "
            f"{p.label:<36}  [{color}]{p.outcome.value}[/{color}]  {p.evidence}"
        )

    console.print("")
    console.print(
        f"[bold]Summary:[/bold] {result.passed}/{len(result.payloads)} passed "
        f"({result.pass_rate:.1f}%)"
    )
    primary = result.frameworks[0] if result.frameworks else None
    if primary:
        console.print(f"[bold]Control:[/bold] {primary.framework} {primary.control_id}  {result.summary}")

    console.print(f"[dim]AGCP layers: {', '.join(result.agcp_conformance_levels)}  "
                  f"Evidence ID: {result.evidence_id[:8]}...[/dim]")

    ts = result.started_at.replace(":", "").replace("-", "")[:15]
    json_path = report_json or Path(f"aigrc-report-{ts}.json")
    md_path = report_md or Path(f"aigrc-report-{ts}.md")
    Reporter.write_json(result, json_path)
    Reporter.write_markdown(result, md_path)
    console.print(f"[dim]Evidence: {json_path}[/dim]")
    console.print(f"[dim]Audit:    {md_path}[/dim]")

    if report_sarif is not None:
        Reporter.write_sarif(result, report_sarif)
        console.print(f"[dim]SARIF:    {report_sarif}[/dim]")

    if report_html is not None:
        Reporter.write_html(result, report_html)
        console.print(f"[dim]HTML:     {report_html}[/dim]")

    if result.pass_rate < fail_below:
        console.print(f"[red]FAIL: pass rate {result.pass_rate:.1f}% below threshold {fail_below}%[/red]")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
