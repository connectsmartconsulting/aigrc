"""aigrc CLI."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from aigrc import __version__
from aigrc.checks import prompt_injection_basic  # noqa: F401 - registration
from aigrc.core import Reporter, build_target, get_registry
from aigrc.core.models import Outcome

app = typer.Typer(
    no_args_is_help=True,
    add_completion=False,
    help="aigrc: executable AI governance checks mapped to regulatory frameworks.",
)
console = Console()


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

    ts = result.started_at.replace(":", "").replace("-", "")[:15]
    json_path = report_json or Path(f"aigrc-report-{ts}.json")
    md_path = report_md or Path(f"aigrc-report-{ts}.md")
    Reporter.write_json(result, json_path)
    Reporter.write_markdown(result, md_path)
    console.print(f"[dim]Evidence: {json_path}[/dim]")
    console.print(f"[dim]Audit:    {md_path}[/dim]")

    if result.pass_rate < fail_below:
        console.print(f"[red]FAIL: pass rate {result.pass_rate:.1f}% below threshold {fail_below}%[/red]")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
