"""ABOM-007: settings, servers and commands that grant an agent more than it needs."""

import re
import shlex
from collections.abc import Iterator, Sequence

from agentbom.models import (
    Artifact,
    Finding,
    Location,
    McpServer,
    RuleId,
    Settings,
    Severity,
    StdioLaunch,
)
from agentbom.rules._surfaces import SeverityTable, line_of, surfaces

_RULE: RuleId = "ABOM-007"

# Entries that allow every command, every MCP tool or every web domain.
_BROAD_ALLOW = frozenset(
    {
        "*",
        "Bash",
        "Bash(*)",
        "Bash(**)",
        "Bash(:*)",
        "Bash(*:*)",
        "Bash(* *)",
        "mcp__*",
        "WebFetch",
        "WebFetch(*)",
        "WebFetch(domain:*)",
    }
)
# Compared after lowercasing, turning backslashes into slashes and dropping trailing slashes,
# so "/" becomes "" and C:\ becomes "c:".
_BROAD_ROOTS = frozenset(
    {
        "",
        "~",
        "$home",
        "${home}",
        "%userprofile%",
        "$env:userprofile",
        "${env:userprofile}",
        "${userhome}",
        "/home",
        "/users",
        "/root",
    }
)
_DRIVE_ROOT = re.compile(r"[a-z]:(/users)?")
_FILESYSTEM_PACKAGE = re.compile(
    r"(?:^|/)(?:@modelcontextprotocol/server-filesystem|mcp-server-filesystem)(?:[@=].*)?",
    re.IGNORECASE,
)

_BYPASS_SEVERITY: SeverityTable = {"executable": "high"}
_BYPASS_FLAG = re.compile(
    r"(?<![\w-])(?:--dangerously-skip-permissions|--dangerously-bypass-approvals-and-sandbox"
    r"|--permission-mode[= ]+[\"']?bypassPermissions|--yolo|--allow-all-tools)(?![\w-])",
    re.IGNORECASE,
)
# A bypass flag counts only on a command line that runs an agent CLI, so a guard script
# that greps for the flag is not a finding.
_AGENT_CLI = re.compile(
    r"(?<![\w-])(?:claude|codex|gemini|copilot|cursor-agent|qwen)", re.IGNORECASE
)
_CONTINUATION = re.compile(r"[\\`]\n")
_COMMENT = re.compile(r"\s*(?:#|//|::|rem\s)", re.IGNORECASE)

_SETTINGS_FIX = "allow only the specific commands and tools the project needs"


def _is_broad_root(path: str) -> bool:
    stripped = path.strip().strip("\"'")
    if not stripped:
        return False
    normalized = stripped.replace("\\", "/").rstrip("/").lower()
    return normalized in _BROAD_ROOTS or _DRIVE_ROOT.fullmatch(normalized) is not None


def _finding(
    artifact: Artifact, severity: Severity, message: str, fix: str, line: int | None = None
) -> Finding:
    return Finding(
        rule_id=_RULE,
        severity=severity,
        confidence="high",
        message=message,
        location=Location(path=artifact.source.path, line=line),
        artifact_id=artifact.id,
        fix=fix,
    )


def _settings_findings(settings: Settings) -> Iterator[Finding]:
    if settings.default_mode == "bypassPermissions":
        yield _finding(
            settings,
            "high",
            "defaultMode is bypassPermissions",
            'set defaultMode to "default" or "acceptEdits"; Claude Code ignores '
            "bypassPermissions in project settings since v2.1.257, but older clients honor it",
        )
    for entry in settings.allow:
        if entry.strip() in _BROAD_ALLOW:
            yield _finding(
                settings, "medium", f"permissions.allow grants {entry.strip()}", _SETTINGS_FIX
            )
    if settings.enable_all_project_mcp_servers is True:
        yield _finding(
            settings,
            "medium",
            "enableAllProjectMcpServers auto-approves every server in .mcp.json",
            "remove enableAllProjectMcpServers and list approved servers in enabledMcpjsonServers",
        )
    for directory in settings.additional_directories:
        if _is_broad_root(directory):
            yield _finding(
                settings,
                "medium",
                f"permissions.additionalDirectories grants access to {directory.strip()}",
                "limit additionalDirectories to the directories the project needs",
            )


def _argv(launch: StdioLaunch) -> list[str]:
    command = launch.command.strip()
    try:
        words = shlex.split(command) if any(c.isspace() for c in command) else [command]
    except ValueError:
        words = command.split()
    return [*words, *launch.args]


def _filesystem_root(server: McpServer, launch: StdioLaunch) -> Finding | None:
    argv = _argv(launch)
    package = next(
        (i for i, word in enumerate(argv) if _FILESYSTEM_PACKAGE.search(word.replace("\\", "/"))),
        None,
    )
    if package is None:
        return None
    for root in argv[package + 1 :]:
        if not root.startswith("-") and _is_broad_root(root):
            return _finding(
                server,
                "medium",
                f'filesystem server "{server.name}" is rooted at {root.strip()}',
                'root the filesystem server at the project directory, such as "."',
            )
    return None


def _bypass_findings(artifact: Artifact) -> Iterator[Finding]:
    for surface in surfaces(artifact):
        severity = _BYPASS_SEVERITY.get(surface.context)
        if severity is None:
            continue
        # Same length, so offsets still point into surface.text.
        text = _CONTINUATION.sub("  ", surface.text)
        start = 0
        for line in text.split("\n"):
            flag = _BYPASS_FLAG.search(line)
            if flag and not _COMMENT.match(line) and _AGENT_CLI.search(line):
                offset = start + flag.start()
                yield _finding(
                    artifact,
                    severity,
                    f"{surface.field} runs an agent with permission checks disabled",
                    "drop the flag and allow only the tools the automation needs",
                    line=line_of(surface, offset),
                )
                break
            start += len(line) + 1


class OverBroadPermissions:
    rule_id: RuleId = _RULE

    def run(self, artifacts: Sequence[Artifact]) -> Iterator[Finding]:
        for artifact in artifacts:
            if isinstance(artifact, Settings):
                yield from _settings_findings(artifact)
            if isinstance(artifact, McpServer) and isinstance(artifact.launch, StdioLaunch):
                root = _filesystem_root(artifact, artifact.launch)
                if root is not None:
                    yield root
            yield from _bypass_findings(artifact)
