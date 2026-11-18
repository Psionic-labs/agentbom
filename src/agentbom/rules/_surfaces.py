"""The text each artifact exposes to text rules, and the context that text runs in."""

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import Literal, assert_never

from agentbom.models import (
    Artifact,
    Hook,
    McpServer,
    RemoteLaunch,
    Rules,
    Script,
    Settings,
    Severity,
    Skill,
    StdioLaunch,
)

# executable: runs as a command or program. config: a value an agent passes to a
# server or process. skill_prose / rules_prose: instructions an agent reads.
Context = Literal["executable", "config", "skill_prose", "rules_prose"]

# A rule rates each context it applies to; a context missing from its table is skipped.
SeverityTable = Mapping[Context, Severity]


@dataclass(frozen=True)
class Surface:
    artifact: Artifact
    context: Context
    field: str
    text: str
    line: int | None


def surfaces(artifact: Artifact) -> Iterator[Surface]:
    match artifact:
        case McpServer():
            yield from _server_surfaces(artifact)
        case Hook():
            for shell, command in artifact.commands.items():
                yield Surface(artifact, "executable", f"commands.{shell}", command, None)
            if artifact.url is not None:
                yield Surface(artifact, "config", "url", artifact.url, None)
        case Script():
            yield Surface(artifact, "executable", "body", artifact.body, 1)
        case Skill():
            if artifact.description is not None:
                yield Surface(artifact, "skill_prose", "description", artifact.description, None)
            yield Surface(artifact, "skill_prose", "body", artifact.body, artifact.body_line)
        case Rules():
            yield Surface(artifact, "rules_prose", "body", artifact.body, artifact.body_line)
        case Settings():
            for key, value in artifact.env.items():
                yield Surface(artifact, "config", f"env.{key}", value, None)
        case _:
            assert_never(artifact)


def _server_surfaces(server: McpServer) -> Iterator[Surface]:
    launch = server.launch
    match launch:
        case StdioLaunch():
            command = " ".join((launch.command, *launch.args))
            yield Surface(server, "executable", "command", command, None)
            for key, value in launch.env.items():
                yield Surface(server, "config", f"env.{key}", value, None)
        case RemoteLaunch():
            yield Surface(server, "config", "url", launch.url, None)
            for key, value in launch.headers.items():
                yield Surface(server, "config", f"headers.{key}", value, None)
        case _:
            assert_never(launch)


def field_label(surface: Surface) -> str:
    """The surface's field, prefixed with its artifact's name when one file holds several."""
    match surface.artifact:
        case McpServer():
            return f'server "{surface.artifact.name}" {surface.field}'
        case Hook():
            return f"hook {surface.artifact.name} {surface.field}"
        case _:
            return surface.field


def line_of(surface: Surface, offset: int) -> int | None:
    """The file line of the character at `offset` in `surface.text`, when the surface has one."""
    if surface.line is None:
        return None
    return surface.line + surface.text.count("\n", 0, offset)
