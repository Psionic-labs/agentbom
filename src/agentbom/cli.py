import os
import stat
import sys
import tempfile
from enum import StrEnum
from pathlib import Path
from typing import Annotated, NoReturn

import typer
from rich.console import Console

from agentbom.discover import read_source
from agentbom.lockfile import (
    LOCKFILE_NAME,
    LockError,
    Lockfile,
    build_lock,
    parse_lock,
    render_lock,
)
from agentbom.models import SEVERITY_RANK, ScanError, ScanResult, Severity
from agentbom.report import print_drift, print_errors, print_terminal, render_json
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

PathArgument = Annotated[Path, typer.Argument(help="Repository root to scan.")]
FormatOption = Annotated[OutputFormat, typer.Option("--format", help="Output format.")]
FailOnOption = Annotated[
    FailOn, typer.Option("--fail-on", help="Exit 1 when a finding has this severity or higher.")
]


@app.callback()
def main() -> None:
    """Inventory the agent context a repository loads and flag risky patterns in it."""


@app.command("scan")
def scan_command(
    path: PathArgument = Path(),
    output_format: FormatOption = OutputFormat.terminal,
    fail_on: FailOnOption = FailOn.high,
) -> None:
    """List the agent context in a repository and report findings."""
    _require_directory(path)
    result = scan(path)
    _report(result, output_format, drift=False)
    raise typer.Exit(exit_code(result, _THRESHOLDS[fail_on]))


@app.command("lock")
def lock_command(path: PathArgument = Path()) -> None:
    """Record the definition of every artifact in agentbom.lock."""
    _require_directory(path)
    result = scan(path)
    if result.errors:
        print_errors(result, Console(stderr=True))
        _fail(f"{LOCKFILE_NAME} not written, because a partial scan cannot be trusted")
    target = path / LOCKFILE_NAME
    mode = _lstat_mode(target)
    if mode is not None and not stat.S_ISREG(mode):
        _fail(f"{LOCKFILE_NAME} is not a regular file")
    try:
        lock = build_lock(result.artifacts, result.file_digests)
    except ValueError as error:
        _fail(f"{LOCKFILE_NAME} not written: {error}")
    _replace_file(target, render_lock(lock))
    count = len(result.artifacts)
    typer.echo(f"Locked {count} artifact{'' if count == 1 else 's'} in {LOCKFILE_NAME}.")


@app.command("check")
def check_command(
    path: PathArgument = Path(),
    output_format: FormatOption = OutputFormat.terminal,
    fail_on: FailOnOption = FailOn.high,
) -> None:
    """Report findings and any drift from agentbom.lock, which always fails the check."""
    _require_directory(path)
    result = scan(path, _read_lock(path))
    _report(result, output_format, drift=True)
    raise typer.Exit(exit_code(result, _THRESHOLDS[fail_on]))


def _require_directory(path: Path) -> None:
    if not path.is_dir():
        _fail(f"{path} is not a directory")


def _read_lock(root: Path) -> Lockfile:
    file = root / LOCKFILE_NAME
    if _lstat_mode(file) is None:
        _fail(f"no {LOCKFILE_NAME} in {root}; run `agentbom lock` first")
    text = read_source(file, LOCKFILE_NAME)
    if isinstance(text, ScanError):
        _fail(f"{text.path}: {text.message}")
    try:
        return parse_lock(text)
    except LockError as error:
        _fail(f"{LOCKFILE_NAME}: {error}")


def _report(result: ScanResult, output_format: OutputFormat, *, drift: bool) -> None:
    if output_format is OutputFormat.json:
        sys.stdout.buffer.write(render_json(result).encode("utf-8"))
        sys.stdout.flush()
        return
    out = Console()
    print_terminal(result, out, Console(stderr=True))
    if drift:
        print_drift(result, out)


def _replace_file(target: Path, text: str) -> None:
    # A new file replaces the old one, so a crash never leaves half a lockfile and the
    # write never goes through a link.
    temporary: Path | None = None
    try:
        handle, name = tempfile.mkstemp(dir=target.parent, prefix=f".{target.name}.")
        temporary = Path(name)
        with os.fdopen(handle, "wb") as file:
            file.write(text.encode("utf-8"))
        temporary.chmod(0o644)
        temporary.replace(target)
    except OSError as error:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        _fail(f"cannot write {target.name}: {error.strerror or type(error).__name__}")


def _lstat_mode(file: Path) -> int | None:
    try:
        return file.lstat().st_mode
    except FileNotFoundError:
        return None
    except OSError as error:
        _fail(f"cannot read {file.name}: {error.strerror or type(error).__name__}")


def _fail(message: str) -> NoReturn:
    typer.echo(f"error: {message}", err=True)
    raise typer.Exit(2)


def exit_code(result: ScanResult, fail_on: Severity) -> int:
    # A partial scan cannot be trusted, so a tool error outranks any finding.
    if result.errors:
        return 2
    threshold = SEVERITY_RANK[fail_on]
    return 1 if any(SEVERITY_RANK[f.severity] >= threshold for f in result.findings) else 0
