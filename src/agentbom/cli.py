import sys
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from agentbom.report import print_terminal, render_json
from agentbom.scan import scan

app = typer.Typer(add_completion=False, no_args_is_help=True)


class OutputFormat(StrEnum):
    terminal = "terminal"
    json = "json"


@app.callback()
def main() -> None:
    """Inventory the agent context a repository loads."""


@app.command("scan")
def scan_command(
    path: Annotated[Path, typer.Argument(help="Repository root to scan.")] = Path(),
    output_format: Annotated[
        OutputFormat, typer.Option("--format", help="Output format.")
    ] = OutputFormat.terminal,
) -> None:
    """List the MCP servers, skills, hooks and rules files in a repository."""
    if not path.is_dir():
        typer.echo(f"error: {path} is not a directory", err=True)
        raise typer.Exit(2)
    result = scan(path)
    if output_format is OutputFormat.json:
        sys.stdout.buffer.write(render_json(result).encode("utf-8"))
        sys.stdout.flush()
    else:
        print_terminal(result, Console(), Console(stderr=True))
    raise typer.Exit(2 if result.errors else 0)
