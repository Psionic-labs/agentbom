from collections.abc import Callable, Iterator
from typing import assert_never

from agentbom.models import Agent, Artifact, ScanError
from agentbom.parsers.hooks import (
    parse_copilot_hooks_json,
    parse_cursor_hooks_json,
    parse_nested_hooks_json,
)
from agentbom.parsers.markdown import parse_rules_md, parse_skill_md
from agentbom.parsers.mcp import parse_mcp_json, parse_vscode_mcp_json
from agentbom.registry import Format

ParseFn = Callable[[str, str, tuple[Agent, ...]], Iterator[Artifact | ScanError]]


def parser_for(format: Format) -> ParseFn:
    match format:
        case "mcp_json":
            return parse_mcp_json
        case "vscode_mcp_json":
            return parse_vscode_mcp_json
        case "nested_hooks_json":
            return parse_nested_hooks_json
        case "cursor_hooks_json":
            return parse_cursor_hooks_json
        case "copilot_hooks_json":
            return parse_copilot_hooks_json
        case "skill_md":
            return parse_skill_md
        case "rules_md":
            return parse_rules_md
        case _:
            assert_never(format)


def parse(
    text: str, path: str, format: Format, agents: tuple[Agent, ...]
) -> tuple[list[Artifact], list[ScanError]]:
    artifacts: list[Artifact] = []
    errors: list[ScanError] = []
    for item in parser_for(format)(text, path, agents):
        if isinstance(item, ScanError):
            errors.append(item)
        else:
            artifacts.append(item)
    return artifacts, errors
