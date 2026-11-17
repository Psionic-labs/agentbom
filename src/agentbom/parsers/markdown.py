from collections.abc import Iterator
from pathlib import PurePosixPath

import yaml
from pydantic import JsonValue

from agentbom.models import Agent, Location, Rules, ScanError, Skill
from agentbom.parsers._shape import ShapeError, to_json_value

_DELIMITER = "---"


def parse_skill_md(text: str, path: str, agents: tuple[Agent, ...]) -> Iterator[Skill | ScanError]:
    try:
        frontmatter, body = _split_frontmatter(text)
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
    )


def parse_rules_md(text: str, path: str, agents: tuple[Agent, ...]) -> Iterator[Rules | ScanError]:
    try:
        frontmatter, body = _split_frontmatter(text)
    except ShapeError as error:
        yield ScanError(path=path, message=str(error))
        return
    yield Rules(
        name=path,
        source=Location(path=path, line=1),
        agents=agents,
        frontmatter=frontmatter,
        body=body,
    )


def _split_frontmatter(text: str) -> tuple[dict[str, JsonValue], str]:
    lines = text.split("\n")
    if lines[0].rstrip(" \t") != _DELIMITER:
        return {}, text
    closing = next((i for i in range(1, len(lines)) if lines[i].rstrip(" \t") == _DELIMITER), None)
    if closing is None:
        raise ShapeError("frontmatter has no closing --- line")
    try:
        loaded = yaml.safe_load("".join(f"{line}\n" for line in lines[1:closing]))
    except yaml.MarkedYAMLError as error:
        mark = error.problem_mark
        where = f" at line {mark.line + 2}" if mark is not None else ""
        raise ShapeError(f"invalid YAML frontmatter: {error.problem}{where}") from error
    except yaml.YAMLError as error:
        raise ShapeError(f"invalid YAML frontmatter: {error}") from error
    except RecursionError as error:
        raise ShapeError("invalid YAML frontmatter: nesting too deep") from error
    body = "\n".join(lines[closing + 1 :])
    if loaded is None:
        return {}, body
    frontmatter = to_json_value(loaded, "frontmatter")
    if not isinstance(frontmatter, dict):
        raise ShapeError("frontmatter must be a mapping")
    return frontmatter, body
