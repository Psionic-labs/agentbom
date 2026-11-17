from collections.abc import Iterator

from agentbom.models import (
    Agent,
    Location,
    McpServer,
    RemoteLaunch,
    RemoteTransport,
    ScanError,
    StdioLaunch,
)
from agentbom.parsers._shape import (
    ShapeError,
    as_object,
    as_optional_text,
    as_text,
    as_text_list,
    as_text_map,
    load_json,
)
from agentbom.parsers.jsonc import strip_jsonc

_REMOTE_TRANSPORTS: dict[str | None, RemoteTransport] = {
    None: "http",
    "http": "http",
    "streamable-http": "http",
    "streamableHttp": "http",
    "sse": "sse",
    "ws": "ws",
}


def parse_mcp_json(
    text: str, path: str, agents: tuple[Agent, ...]
) -> Iterator[McpServer | ScanError]:
    yield from _parse_servers(text, path, agents, "mcpServers")


def parse_vscode_mcp_json(
    text: str, path: str, agents: tuple[Agent, ...]
) -> Iterator[McpServer | ScanError]:
    try:
        stripped = strip_jsonc(text)
    except ShapeError as error:
        yield ScanError(path=path, message=str(error))
        return
    yield from _parse_servers(stripped, path, agents, "servers")


def _parse_servers(
    text: str, path: str, agents: tuple[Agent, ...], key: str
) -> Iterator[McpServer | ScanError]:
    try:
        document = as_object(load_json(text), "top level")
        servers = as_object(document.get(key, {}), key)
    except ShapeError as error:
        yield ScanError(path=path, message=str(error))
        return
    for name, entry in servers.items():
        where = f"{key}.{name}"
        try:
            launch = _launch(entry, where)
        except ShapeError as error:
            yield ScanError(path=path, message=str(error))
            continue
        if launch is None:
            continue
        yield McpServer(name=name, source=Location(path=path), agents=agents, launch=launch)


def _launch(entry: object, where: str) -> StdioLaunch | RemoteLaunch | None:
    fields = as_object(entry, where)
    if fields.get("type") == "sdk":
        # Claude Code skips sdk entries in config files; only the SDK host can register them.
        return None
    if "command" in fields:
        return StdioLaunch(
            transport="stdio",
            command=as_text(fields["command"], f"{where}.command"),
            args=as_text_list(fields.get("args", []), f"{where}.args"),
            env=as_text_map(fields.get("env", {}), f"{where}.env"),
        )
    if "url" not in fields:
        raise ShapeError(f"{where} has neither a command nor a url")
    declared = as_optional_text(fields.get("type"), f"{where}.type")
    if declared == "stdio":
        raise ShapeError(f"{where} is a stdio server with no command")
    if declared not in _REMOTE_TRANSPORTS:
        raise ShapeError(f"{where}.type {declared!r} is not a supported transport")
    return RemoteLaunch(
        transport=_REMOTE_TRANSPORTS[declared],
        url=as_text(fields["url"], f"{where}.url"),
        headers=as_text_map(fields.get("headers", {}), f"{where}.headers"),
    )
