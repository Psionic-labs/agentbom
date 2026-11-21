import os
import stat
import sys
import tempfile
from datetime import date
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
from agentbom.policy import POLICY_FILENAME, Policy, PolicyError, apply_policy, parse_policy
from agentbom.report import print_errors, print_terminal, render_json, render_markdown
from agentbom.sarif import render_sarif
from agentbom.scan import scan

app = typer.Typer(add_completion=False, no_args_is_help=True)


class OutputFormat(StrEnum):
    terminal = "terminal"
    json = "json"
    sarif = "sarif"
    markdown = "markdown"


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
    FailOn | None,
    typer.Option(
        "--fail-on",
        help="Exit 1 when a finding has this severity or higher. "
        "Overrides fail_on in the policy file; the default is high.",
    ),
]
PolicyOption = Annotated[
    Path | None,
    typer.Option(
        "--policy",
        help=f"Policy file to apply. The default is PATH/{POLICY_FILENAME} when it exists.",
    ),
]


@app.callback()
def main() -> None:
    """Inventory the agent context a repository loads and flag risky patterns in it."""


@app.command("scan")
def scan_command(
    path: PathArgument = Path(),
    output_format: FormatOption = OutputFormat.terminal,
    fail_on: FailOnOption = None,
    policy_file: PolicyOption = None,
) -> None:
    """List the agent context in a repository and report findings."""
    _require_directory(path)
    _run("scan", path, None, output_format, fail_on, _load_policy(path, policy_file))


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
    fail_on: FailOnOption = None,
    policy_file: PolicyOption = None,
) -> None:
    """Report findings and any drift from agentbom.lock, which always fails the check."""
    _require_directory(path)
    policy = _load_policy(path, policy_file)
    _run("check", path, _read_lock(path), output_format, fail_on, policy)


def _run(
    command: str,
    path: Path,
    lock: Lockfile | None,
    output_format: OutputFormat,
    fail_on: FailOn | None,
    policy: Policy | None,
) -> NoReturn:
    result = scan(path, lock)
    if policy is not None:
        result = apply_policy(policy, result, date.today())
    _report(result, output_format, command=command, drift=lock is not None)
    if fail_on is not None:
        threshold = _THRESHOLDS[fail_on]
    else:
        threshold = "high" if policy is None else policy.fail_on
    raise typer.Exit(exit_code(result, threshold))


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


def _load_policy(root: Path, explicit: Path | None) -> Policy | None:
    file = root / POLICY_FILENAME if explicit is None else explicit
    if explicit is None and _lstat_mode(file) is None:
        return None
    text = read_source(file, file.name)
    if isinstance(text, ScanError):
        _fail(f"{text.path}: {text.message}")
    try:
        return parse_policy(text)
    except PolicyError as error:
        _fail(f"{file.name}: {error}")


def _report(result: ScanResult, output_format: OutputFormat, *, command: str, drift: bool) -> None:
    match output_format:
        case OutputFormat.terminal:
            print_terminal(result, Console(), Console(stderr=True), drift=drift)
            return
        case OutputFormat.json:
            text = render_json(result)
        case OutputFormat.sarif:
            text = render_sarif(result)
        case OutputFormat.markdown:
            text = render_markdown(result, command=command, drift=drift)
    sys.stdout.buffer.write(text.encode("utf-8"))
    sys.stdout.flush()


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
