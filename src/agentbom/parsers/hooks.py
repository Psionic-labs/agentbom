from collections.abc import Iterator, Mapping

from agentbom.models import Agent, Hook, HookShell, Location, ScanError
from agentbom.parsers._shape import (
    ShapeError,
    as_list,
    as_object,
    as_optional_text,
    as_text,
    load_json,
)
from agentbom.parsers.jsonc import strip_jsonc

_COMMAND_ONLY: Mapping[str, HookShell] = {"command": "default"}
_COPILOT_SHELLS: Mapping[str, HookShell] = {
    "command": "default",
    "bash": "bash",
    "powershell": "powershell",
}


def parse_nested_hooks_json(
    text: str, path: str, agents: tuple[Agent, ...]
) -> Iterator[Hook | ScanError]:
    try:
        document = document_object(text)
    except ShapeError as error:
        yield ScanError(path=path, message=str(error))
        return
    yield from nested_hooks(document, path, agents)


def nested_hooks(
    document: dict[str, object], path: str, agents: tuple[Agent, ...]
) -> Iterator[Hook | ScanError]:
    """Claude Code and Codex: event -> matcher groups -> handlers."""
    try:
        events = _events(document)
    except ShapeError as error:
        yield ScanError(path=path, message=str(error))
        return
    for event, groups_value in events.items():
        try:
            groups = as_list(groups_value, f"hooks.{event}")
        except ShapeError as error:
            yield ScanError(path=path, message=str(error))
            continue
        for g, group_value in enumerate(groups):
            where = f"hooks.{event}[{g}]"
            try:
                group = as_object(group_value, where)
                matcher = as_optional_text(group.get("matcher"), f"{where}.matcher")
                handlers = as_list(group.get("hooks"), f"{where}.hooks")
            except ShapeError as error:
                yield ScanError(path=path, message=str(error))
                continue
            for i, handler in enumerate(handlers):
                name = f"{event}[{g}].hooks[{i}]"
                try:
                    fields = as_object(handler, f"hooks.{name}")
                    hook = _hook(fields, name, event, matcher, path, agents, _COMMAND_ONLY)
                except ShapeError as error:
                    yield ScanError(path=path, message=str(error))
                    continue
                yield hook


def parse_cursor_hooks_json(
    text: str, path: str, agents: tuple[Agent, ...]
) -> Iterator[Hook | ScanError]:
    yield from _flat_hooks(text, path, agents, _COMMAND_ONLY)


def parse_copilot_hooks_json(
    text: str, path: str, agents: tuple[Agent, ...]
) -> Iterator[Hook | ScanError]:
    try:
        stripped = strip_jsonc(text)
    except ShapeError as error:
        yield ScanError(path=path, message=str(error))
        return
    if not stripped.strip():
        # A file that is entirely commented out is how repos disable their hooks.
        return
    yield from _flat_hooks(stripped, path, agents, _COPILOT_SHELLS)


def _flat_hooks(
    text: str, path: str, agents: tuple[Agent, ...], shells: Mapping[str, HookShell]
) -> Iterator[Hook | ScanError]:
    """Cursor and Copilot: event -> handlers, each handler carrying its own matcher."""
    try:
        events = _events(document_object(text))
    except ShapeError as error:
        yield ScanError(path=path, message=str(error))
        return
    for event, entries_value in events.items():
        try:
            entries = as_list(entries_value, f"hooks.{event}")
        except ShapeError as error:
            yield ScanError(path=path, message=str(error))
            continue
        for i, entry in enumerate(entries):
            name = f"{event}[{i}]"
            try:
                fields = as_object(entry, f"hooks.{name}")
                matcher = as_optional_text(fields.get("matcher"), f"hooks.{name}.matcher")
                hook = _hook(fields, name, event, matcher, path, agents, shells)
            except ShapeError as error:
                yield ScanError(path=path, message=str(error))
                continue
            yield hook


def document_object(text: str) -> dict[str, object]:
    return as_object(load_json(text), "top level")


def _events(document: dict[str, object]) -> dict[str, object]:
    return as_object(document.get("hooks", {}), "hooks")


def _hook(
    fields: dict[str, object],
    name: str,
    event: str,
    matcher: str | None,
    path: str,
    agents: tuple[Agent, ...],
    shells: Mapping[str, HookShell],
) -> Hook:
    where = f"hooks.{name}"
    return Hook(
        name=name,
        source=Location(path=path),
        agents=agents,
        event=event,
        matcher=matcher,
        handler_type=as_text(fields.get("type", "command"), f"{where}.type"),
        commands={
            shell: as_text(fields[key], f"{where}.{key}")
            for key, shell in shells.items()
            if key in fields
        },
        url=as_optional_text(fields.get("url"), f"{where}.url"),
    )
