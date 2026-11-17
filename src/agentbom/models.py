import hashlib
import json
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue

Agent = Literal["claude_code", "cursor", "vscode", "copilot", "codex", "agents_md"]
HookShell = Literal["default", "bash", "powershell"]


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Location(_Frozen):
    path: str
    line: int | None = None


class StdioLaunch(_Frozen):
    transport: Literal["stdio"]
    command: str
    args: tuple[str, ...] = ()
    env: dict[str, str] = Field(default_factory=dict)


class RemoteLaunch(_Frozen):
    transport: Literal["http", "sse"]
    url: str
    headers: dict[str, str] = Field(default_factory=dict)


class _ArtifactBase(_Frozen):
    kind: str
    name: str
    source: Location
    agents: tuple[Agent, ...]

    @property
    def id(self) -> str:
        return f"{self.kind}:{self.source.path}:{self.name}"

    @property
    def content_hash(self) -> str:
        content = self.model_dump(mode="json", exclude={"source", "agents"})
        canonical = json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class McpServer(_ArtifactBase):
    kind: Literal["mcp_server"] = "mcp_server"
    launch: Annotated[StdioLaunch | RemoteLaunch, Field(discriminator="transport")]


class Hook(_ArtifactBase):
    kind: Literal["hook"] = "hook"
    event: str
    matcher: str | None
    handler_type: str
    commands: dict[HookShell, str]
    url: str | None = None


class Skill(_ArtifactBase):
    kind: Literal["skill"] = "skill"
    description: str | None
    frontmatter: dict[str, JsonValue]
    body: str


class Rules(_ArtifactBase):
    kind: Literal["rules"] = "rules"
    frontmatter: dict[str, JsonValue]
    body: str


Artifact = Annotated[McpServer | Hook | Skill | Rules, Field(discriminator="kind")]


class ScanError(_Frozen):
    path: str
    message: str


class ScanResult(_Frozen):
    artifacts: tuple[Artifact, ...]
    errors: tuple[ScanError, ...]
