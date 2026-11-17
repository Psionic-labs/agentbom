import json
import math
import re
from datetime import date
from typing import Any

from pydantic import JsonValue

_SURROGATE = re.compile("[\ud800-\udfff]")
_MAX_DEPTH = 64
_MAX_NODES = 100_000


class ShapeError(Exception):
    pass


def load_json(text: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError as error:
        raise ShapeError(
            f"invalid JSON: {error.msg} (line {error.lineno}, column {error.colno})"
        ) from error
    except RecursionError as error:
        raise ShapeError("invalid JSON: nesting too deep") from error
    except ValueError as error:
        raise ShapeError(f"invalid JSON: {error}") from error


def as_text(value: object, where: str) -> str:
    if not isinstance(value, str):
        raise ShapeError(f"{where} must be a string")
    if _SURROGATE.search(value):
        raise ShapeError(f"{where} contains an unpaired surrogate escape")
    return value


def as_optional_text(value: object, where: str) -> str | None:
    return None if value is None else as_text(value, where)


def as_object(value: object, where: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ShapeError(f"{where} must be an object")
    for key in value:
        as_text(key, f"{where} key")
    return value


def as_list(value: object, where: str) -> list[object]:
    if not isinstance(value, list):
        raise ShapeError(f"{where} must be a list")
    return value


def as_text_list(value: object, where: str) -> tuple[str, ...]:
    return tuple(as_text(item, f"{where}[{i}]") for i, item in enumerate(as_list(value, where)))


def as_text_map(value: object, where: str) -> dict[str, str]:
    return {key: as_text(item, f"{where}.{key}") for key, item in as_object(value, where).items()}


def to_json_value(value: object, where: str) -> JsonValue:
    nodes = 0

    def convert(item: object, at: str, depth: int) -> JsonValue:
        nonlocal nodes
        nodes += 1
        if nodes > _MAX_NODES:
            raise ShapeError(f"{where} expands to more than {_MAX_NODES} values")
        if depth > _MAX_DEPTH:
            raise ShapeError(f"{where} nests deeper than {_MAX_DEPTH} levels")
        if item is None or isinstance(item, bool | int):
            return item
        if isinstance(item, float):
            if not math.isfinite(item):
                raise ShapeError(f"{at} is not a finite number")
            return item
        if isinstance(item, str):
            return as_text(item, at)
        if isinstance(item, date):
            return item.isoformat()
        if isinstance(item, list):
            return [convert(child, f"{at}[{i}]", depth + 1) for i, child in enumerate(item)]
        if isinstance(item, dict):
            result: dict[str, JsonValue] = {}
            for key, child in item.items():
                if not isinstance(key, str):
                    raise ShapeError(f"{at} has a non-string key {key!r}")
                result[as_text(key, f"{at} key")] = convert(child, f"{at}.{key}", depth + 1)
            return result
        raise ShapeError(f"{at} is a {type(item).__name__}, which has no JSON form")

    return convert(value, where, 0)
