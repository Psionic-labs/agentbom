import json
import re
import unicodedata
from typing import Any

from pydantic import JsonValue
from rich.console import Console
from rich.table import Table
from rich.text import Text

from agentbom.lockfile import LOCKFILE_NAME
from agentbom.models import (
    Artifact,
    Drift,
    FieldChange,
    Finding,
    Hook,
    McpServer,
    RemoteLaunch,
    ScanResult,
    Script,
    Settings,
    Severity,
    StdioLaunch,
)
from agentbom.policy import POLICY_FILENAME

SCHEMA_VERSION = 4
_SEVERITY_LABELS: dict[Severity, str] = {"high": "HIGH", "medium": "MED", "low": "LOW"}
_INVISIBLE_CATEGORIES = frozenset({"Cc", "Cf", "Co", "Cs", "Zl", "Zp"})
_BACKTICK_RUNS = re.compile("`+")


def render_json(result: ScanResult) -> str:
    document = {
        "schema_version": SCHEMA_VERSION,
        "artifacts": [_artifact_document(artifact) for artifact in result.artifacts],
        "drift": [item.model_dump(mode="json") for item in result.drift],
        "policy_notes": list(result.policy_notes),
        "suppressed": [item.model_dump(mode="json") for item in result.suppressed],
        "errors": [error.model_dump(mode="json") for error in result.errors],
        "findings": [finding.model_dump(mode="json") for finding in result.findings],
    }
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _artifact_document(artifact: Artifact) -> dict[str, Any]:
    # Secrets live in env and header values, so only their keys leave the scanner.
    match artifact:
        case McpServer(launch=StdioLaunch() as launch):
            document = artifact.model_dump(mode="json", exclude={"launch": {"env"}})
            document["launch"]["env_keys"] = sorted(launch.env)
        case McpServer(launch=RemoteLaunch() as launch):
            document = artifact.model_dump(mode="json", exclude={"launch": {"headers"}})
            document["launch"]["header_keys"] = sorted(launch.headers)
        case Settings(env=env):
            document = artifact.model_dump(mode="json", exclude={"env"})
            document["env_keys"] = sorted(env)
        case Hook():
            document = artifact.model_dump(mode="json")
        case _:
            document = artifact.model_dump(mode="json", exclude={"body"})
    document["id"] = artifact.id
    document["content_hash"] = artifact.content_hash
    return document


def summary_line(result: ScanResult) -> str:
    counts = dict.fromkeys(("mcp_server", "skill", "hook", "rules", "script", "settings"), 0)
    for artifact in result.artifacts:
        counts[artifact.kind] += 1
    return "Found: " + ", ".join(
        [
            _count(counts["mcp_server"], "MCP server"),
            _count(counts["skill"], "skill"),
            _count(counts["hook"], "hook"),
            _count(counts["rules"], "rules file"),
            _count(counts["script"], "script"),
            _count(counts["settings"], "settings file"),
        ]
    )


def print_terminal(result: ScanResult, out: Console, err: Console, *, drift: bool) -> None:
    out.print(Text(summary_line(result)), soft_wrap=True)
    if result.artifacts:
        table = Table()
        for header in ("Kind", "Name", "Path", "Agents", "Detail"):
            table.add_column(header, overflow="fold")
        for artifact in result.artifacts:
            table.add_row(
                *(
                    Text(_visible(cell))
                    for cell in (
                        artifact.kind,
                        artifact.name,
                        artifact.source.path,
                        ", ".join(artifact.agents),
                        _detail(artifact),
                    )
                )
            )
        out.print(table)
    for line in body_lines(result, drift=drift):
        out.print(Text(_visible(line)), soft_wrap=True)
    print_errors(result, err)


def body_lines(result: ScanResult, *, drift: bool) -> list[str]:
    """What the terminal and Markdown reports say after the inventory."""
    lines = [finding_line(finding) for finding in result.findings]
    lines.append(findings_total(result))
    if result.suppressed:
        count = len(result.suppressed)
        noun = "finding" if count == 1 else "findings"
        lines.append(f"{count} {noun} suppressed by {POLICY_FILENAME}.")
    lines.extend(f"policy: {note}" for note in result.policy_notes)
    if drift:
        lines.extend(drift_lines(result.drift))
    return lines


def render_markdown(result: ScanResult, *, command: str, drift: bool) -> str:
    """A heading and one code block, so nothing from the repository renders as Markdown."""
    lines = [summary_line(result), *body_lines(result, drift=drift)]
    lines += [f"error: {error.path}: {error.message}" for error in result.errors]
    text = "\n".join(_visible(line) for line in lines)
    longest = max((len(run) for run in _BACKTICK_RUNS.findall(text)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"### agentbom {command}: {_status(result)}\n\n{fence}text\n{text}\n{fence}\n"


def _status(result: ScanResult) -> str:
    if result.errors:
        return f"{len(result.errors)} error(s), so the result cannot be trusted"
    return findings_total(result).removesuffix(".")


def print_errors(result: ScanResult, err: Console) -> None:
    if result.errors:
        err.print(Text(f"{len(result.errors)} error(s):"))
        for error in result.errors:
            err.print(Text(_visible(f"{error.path}: {error.message}")))


def drift_lines(drift: tuple[Drift, ...]) -> list[str]:
    """The readable diff between the lockfile and the repository, ending in a total."""
    lines: list[str] = []
    for item in drift:
        lines.append(f"{item.change.upper():<8} {item.artifact_id}")
        for change in item.fields:
            lines.extend(_field_lines(change))
    if not drift:
        return [*lines, f"No drift from {LOCKFILE_NAME}."]
    noun = "difference" if len(drift) == 1 else "differences"
    return [*lines, f"{len(drift)} {noun} from {LOCKFILE_NAME}."]


def _field_lines(change: FieldChange) -> list[str]:
    if change.hidden:
        note = "only a digest is locked; review the file's diff"
        return [f"  {change.field}: {change.change} ({note})"]
    lines = [f"  {change.field}:"]
    if change.change != "added":
        lines.extend(_value_lines("-", change.before))
    if change.change != "removed":
        lines.extend(_value_lines("+", change.after))
    return lines


def _value_lines(mark: str, value: JsonValue) -> list[str]:
    # A string prints raw unless it reads as JSON, so "false" and false never look alike.
    if isinstance(value, str) and not _reads_as_json(value):
        text = value
    else:
        text = json.dumps(value, ensure_ascii=False)
    return [f"    {mark} {line}" for line in text.split("\n")]


def _reads_as_json(text: str) -> bool:
    try:
        json.loads(text)
    except (ValueError, RecursionError):
        return False
    return True


def finding_line(finding: Finding) -> str:
    where = finding.location.path
    if finding.location.line is not None:
        where = f"{where}:{finding.location.line}"
    return f"{_SEVERITY_LABELS[finding.severity]:<4}  {finding.rule_id}  {where}  {finding.message}"


def findings_total(result: ScanResult) -> str:
    if not result.findings:
        return "No findings."
    counts = dict.fromkeys(_SEVERITY_LABELS, 0)
    for finding in result.findings:
        counts[finding.severity] += 1
    noun = "finding" if len(result.findings) == 1 else "findings"
    return (
        f"{len(result.findings)} {noun} "
        f"({counts['high']} high, {counts['medium']} medium, {counts['low']} low)."
    )


def _detail(artifact: Artifact) -> str:
    match artifact:
        case McpServer(launch=StdioLaunch(command=command)):
            return command
        case McpServer(launch=RemoteLaunch(url=url)):
            return url
        case Hook(commands=commands, url=url, handler_type=handler_type):
            return next(iter(commands.values()), url or handler_type)
        case Script(language=language):
            return language
        case _:
            return ""


def _count(n: int, noun: str) -> str:
    return f"{n} {noun}" if n == 1 else f"{n} {noun}s"


def _visible(text: str) -> str:
    # Repo files are untrusted: escape control and format characters (ANSI
    # escapes, bidi overrides, zero-width text) instead of sending them to a terminal.
    return "".join(
        _escape(char) if unicodedata.category(char) in _INVISIBLE_CATEGORIES else char
        for char in text
    )


def _escape(char: str) -> str:
    code = ord(char)
    return f"\\u{code:04x}" if code <= 0xFFFF else f"\\U{code:08x}"
