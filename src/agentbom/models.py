import hashlib
import json
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue

ArtifactKind = Literal["mcp_server", "hook", "skill", "rules", "script", "settings"]
DriftKind = ArtifactKind | Literal["file"]
Agent = Literal["claude_code", "cursor", "vscode", "copilot", "codex", "agents_md"]
HookShell = Literal["default", "bash", "powershell"]
RemoteTransport = Literal["http", "sse", "ws"]
Severity = Literal["low", "medium", "high"]
Confidence = Literal["low", "medium", "high"]
RuleId = Literal[
    "ABOM-001",
    "ABOM-002",
    "ABOM-003",
    "ABOM-004",
    "ABOM-005",
    "ABOM-006",
    "ABOM-007",
    "ABOM-008",
    "ABOM-009",
    "ABOM-010",
]
SEVERITY_RANK: dict[Severity, int] = {"low": 0, "medium": 1, "high": 2}
ScriptLanguage = Literal[
    "shell", "powershell", "python", "javascript", "typescript", "ruby", "perl", "batch"
]


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
    transport: RemoteTransport
    url: str
    headers: dict[str, str] = Field(default_factory=dict)


class _ArtifactBase(_Frozen):
    kind: ArtifactKind
    name: str
    source: Location
    agents: tuple[Agent, ...]

    @property
    def id(self) -> str:
        return f"{self.kind}:{self.source.path}:{self.name}"

    @property
    def content_hash(self) -> str:
        content = self.model_dump(mode="json", exclude={"source", "agents", "body_line"})
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
    body_line: int


class Rules(_ArtifactBase):
    kind: Literal["rules"] = "rules"
    frontmatter: dict[str, JsonValue]
    body: str
    body_line: int


class Script(_ArtifactBase):
    kind: Literal["script"] = "script"
    language: ScriptLanguage
    body: str


class Settings(_ArtifactBase):
    kind: Literal["settings"] = "settings"
    allow: tuple[str, ...] = ()
    deny: tuple[str, ...] = ()
    ask: tuple[str, ...] = ()
    default_mode: str | None = None
    additional_directories: tuple[str, ...] = ()
    enable_all_project_mcp_servers: bool | None = None
    env: dict[str, str] = Field(default_factory=dict)


Artifact = Annotated[
    McpServer | Hook | Skill | Rules | Script | Settings, Field(discriminator="kind")
]


class ScanError(_Frozen):
    path: str
    message: str


class Finding(_Frozen):
    rule_id: RuleId
    severity: Severity
    confidence: Confidence
    message: str
    location: Location
    artifact_id: str
    fix: str | None = None


Change = Literal["added", "removed", "changed"]


class FieldChange(_Frozen):
    """One leaf of an artifact definition that differs from the lockfile.

    `before` is meaningful unless the field was added, `after` unless it was removed.
    A hidden field holds a digest, because the lockfile never stores its value.
    """

    field: str
    change: Change
    before: JsonValue = None
    after: JsonValue = None
    hidden: bool


class Drift(_Frozen):
    """An artifact, or a whole source file, that differs from the lockfile."""

    artifact_id: str
    change: Change
    kind: DriftKind
    name: str
    location: Location
    fields: tuple[FieldChange, ...]


class ScanResult(_Frozen):
    artifacts: tuple[Artifact, ...]
    errors: tuple[ScanError, ...]
    findings: tuple[Finding, ...]
    drift: tuple[Drift, ...] = ()
    file_digests: dict[str, str] = Field(default_factory=dict)
