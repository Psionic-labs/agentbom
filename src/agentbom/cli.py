import sys
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from agentbom.models import SEVERITY_RANK, ScanResult, Severity
from agentbom.report import print_terminal, render_json
from agentbom.scan import scan

app = typer.Typer(add_completion=False, no_args_is_help=True)


class OutputFormat(StrEnum):
    terminal = "terminal"
    json = "json"


class FailOn(StrEnum):
    high = "high"
    medium = "medium"
    low = "low"


_THRESHOLDS: dict[FailOn, Severity] = {
    FailOn.high: "high",
    FailOn.medium: "medium",
    FailOn.low: "low",
}


@app.callback()
def main() -> None:
    """Inventory the agent context a repository loads and flag risky patterns in it."""


@app.command("scan")
def scan_command(
    path: Annotated[Path, typer.Argument(help="Repository root to scan.")] = Path(),
    output_format: Annotated[
        OutputFormat, typer.Option("--format", help="Output format.")
    ] = OutputFormat.terminal,
    fail_on: Annotated[
        FailOn,
        typer.Option("--fail-on", help="Exit 1 when a finding has this severity or higher."),
    ] = FailOn.high,
) -> None:
    """List the agent context in a repository and report findings."""
    if not path.is_dir():
        typer.echo(f"error: {path} is not a directory", err=True)
        raise typer.Exit(2)
    result = scan(path)
    if output_format is OutputFormat.json:
        sys.stdout.buffer.write(render_json(result).encode("utf-8"))
        sys.stdout.flush()
    else:
        print_terminal(result, Console(), Console(stderr=True))
    raise typer.Exit(exit_code(result, _THRESHOLDS[fail_on]))


def exit_code(result: ScanResult, fail_on: Severity) -> int:
    # A partial scan cannot be trusted, so a tool error outranks any finding.
    if result.errors:
        return 2
    threshold = SEVERITY_RANK[fail_on]
    return 1 if any(SEVERITY_RANK[f.severity] >= threshold for f in result.findings) else 0
