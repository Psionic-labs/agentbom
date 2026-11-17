import re
from collections.abc import Iterator
from pathlib import PurePosixPath

import yaml
from pydantic import JsonValue

from agentbom.models import Agent, Location, Rules, ScanError, Skill
from agentbom.parsers._shape import ShapeError, to_json_value

_DELIMITER = "---"
_FLAT_LINE = re.compile(r"([A-Za-z_][A-Za-z0-9_-]*)\s*:(.*)")
_FLAT_SCALARS: dict[str, JsonValue] = {"": None, "true": True, "false": False}


def parse_skill_md(text: str, path: str, agents: tuple[Agent, ...]) -> Iterator[Skill | ScanError]:
    try:
        frontmatter, body, body_line = _split_frontmatter(text)
    except ShapeError as error:
        yield ScanError(path=path, message=str(error))
        return
    declared_name = frontmatter.get("name")
    description = frontmatter.get("description")
    yield Skill(
        name=declared_name
        if isinstance(declared_name, str) and declared_name
        else PurePosixPath(path).parent.name,
        source=Location(path=path, line=1),
        agents=agents,
        description=description if isinstance(description, str) else None,
        frontmatter=frontmatter,
        body=body,
        body_line=body_line,
    )


def parse_rules_md(text: str, path: str, agents: tuple[Agent, ...]) -> Iterator[Rules | ScanError]:
    yield _rules(text, path, agents)


def _rules(text: str, path: str, agents: tuple[Agent, ...]) -> Rules | ScanError:
    try:
        frontmatter, body, body_line = _split_frontmatter(text)
    except ShapeError as error:
        return ScanError(path=path, message=str(error))
    return Rules(
        name=path,
        source=Location(path=path, line=1),
        agents=agents,
        frontmatter=frontmatter,
        body=body,
        body_line=body_line,
    )


def _split_frontmatter(text: str) -> tuple[dict[str, JsonValue], str, int]:
    """Return the frontmatter, the body, and the 1-based file line the body starts on."""
    lines = text.split("\n")
    if lines[0].rstrip(" \t") != _DELIMITER:
        return {}, text, 1
    closing = next((i for i in range(1, len(lines)) if lines[i].rstrip(" \t") == _DELIMITER), None)
    if closing is None:
        raise ShapeError("frontmatter has no closing --- line")
    header, body, body_line = lines[1:closing], "\n".join(lines[closing + 1 :]), closing + 2
    try:
        return _yaml_mapping(header), body, body_line
    except ShapeError:
        # Real skills and rules ship frontmatter that YAML rejects but agents load, such as
        # `globs: *.mdc` or an unquoted description with a second `: `, so read flat lines.
        flat = _flat_mapping(header)
        if flat is None:
            raise
        return flat, body, body_line


def _yaml_mapping(lines: list[str]) -> dict[str, JsonValue]:
    try:
        loaded = yaml.safe_load("".join(f"{line}\n" for line in lines))
    except yaml.MarkedYAMLError as error:
        mark = error.problem_mark
        where = f" at line {mark.line + 2}" if mark is not None else ""
        raise ShapeError(f"invalid YAML frontmatter: {error.problem}{where}") from error
    except yaml.YAMLError as error:
        raise ShapeError(f"invalid YAML frontmatter: {error}") from error
    except RecursionError as error:
        raise ShapeError("invalid YAML frontmatter: nesting too deep") from error
    if loaded is None:
        return {}
    frontmatter = to_json_value(loaded, "frontmatter")
    if not isinstance(frontmatter, dict):
        raise ShapeError("frontmatter must be a mapping")
    return frontmatter


def _flat_mapping(lines: list[str]) -> dict[str, JsonValue] | None:
    mapping: dict[str, JsonValue] = {}
    for line in lines:
        if not line.strip():
            continue
        match = _FLAT_LINE.fullmatch(line)
        if match is None:
            return None
        raw = match.group(2).strip()
        mapping[match.group(1)] = _FLAT_SCALARS.get(raw, raw)
    return mapping
