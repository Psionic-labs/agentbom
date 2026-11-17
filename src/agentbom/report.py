import json
import unicodedata
from typing import Any

from rich.console import Console
from rich.table import Table
from rich.text import Text

from agentbom.models import Artifact, Hook, McpServer, RemoteLaunch, ScanResult, StdioLaunch

SCHEMA_VERSION = 1
_INVISIBLE_CATEGORIES = frozenset({"Cc", "Cf", "Co", "Cs", "Zl", "Zp"})


def render_json(result: ScanResult) -> str:
    document = {
        "schema_version": SCHEMA_VERSION,
        "artifacts": [_artifact_document(artifact) for artifact in result.artifacts],
        "errors": [error.model_dump(mode="json") for error in result.errors],
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
        case Hook():
            document = artifact.model_dump(mode="json")
        case _:
            document = artifact.model_dump(mode="json", exclude={"body"})
    document["id"] = artifact.id
    document["content_hash"] = artifact.content_hash
    return document


def summary_line(result: ScanResult) -> str:
    counts = dict.fromkeys(("mcp_server", "skill", "hook", "rules"), 0)
    for artifact in result.artifacts:
        counts[artifact.kind] += 1
    return "Found: " + ", ".join(
        [
            _count(counts["mcp_server"], "MCP server"),
            _count(counts["skill"], "skill"),
            _count(counts["hook"], "hook"),
            _count(counts["rules"], "rules file"),
        ]
    )


def print_terminal(result: ScanResult, out: Console, err: Console) -> None:
    out.print(Text(summary_line(result)))
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
    if result.errors:
        err.print(Text(f"{len(result.errors)} error(s):"))
        for error in result.errors:
            err.print(Text(_visible(f"{error.path}: {error.message}")))


def _detail(artifact: Artifact) -> str:
    match artifact:
        case McpServer(launch=StdioLaunch(command=command)):
            return command
        case McpServer(launch=RemoteLaunch(url=url)):
            return url
        case Hook(commands=commands, url=url, handler_type=handler_type):
            return next(iter(commands.values()), url or handler_type)
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
