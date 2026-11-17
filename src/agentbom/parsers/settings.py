from collections.abc import Iterator

from agentbom.models import Agent, Hook, Location, ScanError, Settings
from agentbom.parsers._shape import (
    ShapeError,
    as_object,
    as_optional_text,
    as_text_list,
    as_text_map,
)
from agentbom.parsers.hooks import document_object, nested_hooks


def parse_claude_settings_json(
    text: str, path: str, agents: tuple[Agent, ...]
) -> Iterator[Hook | Settings | ScanError]:
    try:
        document = document_object(text)
    except ShapeError as error:
        yield ScanError(path=path, message=str(error))
        return
    yield from nested_hooks(document, path, agents)
    try:
        yield _settings(document, path, agents)
    except ShapeError as error:
        yield ScanError(path=path, message=str(error))


def _settings(document: dict[str, object], path: str, agents: tuple[Agent, ...]) -> Settings:
    permissions = as_object(document.get("permissions", {}), "permissions")
    enable_all = document.get("enableAllProjectMcpServers")
    if enable_all is not None and not isinstance(enable_all, bool):
        raise ShapeError("enableAllProjectMcpServers must be true or false")
    return Settings(
        name=path,
        source=Location(path=path),
        agents=agents,
        allow=as_text_list(permissions.get("allow", []), "permissions.allow"),
        deny=as_text_list(permissions.get("deny", []), "permissions.deny"),
        ask=as_text_list(permissions.get("ask", []), "permissions.ask"),
        default_mode=as_optional_text(permissions.get("defaultMode"), "permissions.defaultMode"),
        additional_directories=as_text_list(
            permissions.get("additionalDirectories", []), "permissions.additionalDirectories"
        ),
        enable_all_project_mcp_servers=enable_all,
        env=as_text_map(document.get("env", {}), "env"),
    )
