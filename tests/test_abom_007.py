import pytest

from agentbom.models import Finding, Location, McpServer, Script, Settings, StdioLaunch
from agentbom.rules.abom_007_permissions import OverBroadPermissions

HERE = Location(path=".claude/settings.json")


def _messages(*artifacts: Settings | McpServer | Script) -> list[str]:
    return [finding.message for finding in OverBroadPermissions().run(artifacts)]


def _filesystem(*args: str, command: str = "npx") -> McpServer:
    return McpServer(
        name="fs",
        source=Location(path=".mcp.json"),
        agents=("claude_code",),
        launch=StdioLaunch(transport="stdio", command=command, args=args),
    )


def _script(body: str) -> Script:
    return Script(
        name="s.sh",
        source=Location(path=".claude/hooks/s.sh", line=1),
        agents=(),
        language="shell",
        body=body,
    )


@pytest.mark.parametrize(
    "entry", ["*", "Bash", "Bash(*)", " Bash(:*) ", "mcp__*", "WebFetch", "WebFetch(domain:*)"]
)
def test_broad_allow_entries_are_flagged(entry: str) -> None:
    settings = Settings(name="s", source=HERE, agents=(), allow=(entry,))
    assert _messages(settings) == [f"permissions.allow grants {entry.strip()}"]


@pytest.mark.parametrize(
    "entry",
    [
        "Bash(npm run test:*)",
        "Bash(git *)",
        "mcp__github",
        "mcp__github__get_issue",
        "Read(**)",
        "Edit",
        "WebFetch(domain:github.com)",
    ],
)
def test_narrow_allow_entries_are_not_flagged(entry: str) -> None:
    assert _messages(Settings(name="s", source=HERE, agents=(), allow=(entry,))) == []


@pytest.mark.parametrize(
    "root",
    [
        "/",
        "~",
        "~/",
        "$HOME",
        "${HOME}",
        "%USERPROFILE%",
        "/home",
        "/Users/",
        "C:\\",
        "c:/",
        "C:\\Users",
    ],
)
def test_broad_roots_are_flagged_for_filesystem_servers_and_extra_directories(root: str) -> None:
    settings = Settings(name="s", source=HERE, agents=(), additional_directories=(root,))
    server = _filesystem("-y", "@modelcontextprotocol/server-filesystem@1.0.0", ".", root)
    assert _messages(settings, server) == [
        f"permissions.additionalDirectories grants access to {root.strip()}",
        f'filesystem server "fs" is rooted at {root}',
    ]


@pytest.mark.parametrize(
    "root", [".", "./src", "/home/dev/app", "~/code", "${workspaceFolder}", "D:\\repo"]
)
def test_project_roots_are_not_flagged(root: str) -> None:
    settings = Settings(name="s", source=HERE, agents=(), additional_directories=(root,))
    server = _filesystem("-y", "@modelcontextprotocol/server-filesystem", root)
    assert _messages(settings, server) == []


def test_filesystem_server_forms() -> None:
    assert _messages(_filesystem("/", command="mcp-server-filesystem")) == [
        'filesystem server "fs" is rooted at /'
    ]
    assert _messages(_filesystem(command="npx -y @modelcontextprotocol/server-filesystem ~")) == [
        'filesystem server "fs" is rooted at ~'
    ]
    assert _messages(_filesystem("-y", "@modelcontextprotocol/server-memory", "/")) == []


@pytest.mark.parametrize(
    "body",
    [
        "claude -p 'x' --dangerously-skip-permissions",
        "npx @anthropic-ai/claude-code --permission-mode bypassPermissions -p x",
        "claude --permission-mode=bypassPermissions",
        "gemini --yolo -p 'fix it'",
        "copilot -p 'x' --allow-all-tools",
        '"$CLAUDE_BIN" --dangerously-skip-permissions',
        "set -e\ncodex exec \\\n  --dangerously-bypass-approvals-and-sandbox",
    ],
)
def test_agent_runs_without_permission_checks_are_flagged(body: str) -> None:
    assert _messages(_script(body)) == ["body runs an agent with permission checks disabled"]


@pytest.mark.parametrize(
    "body",
    [
        "grep -q -- '--dangerously-skip-permissions' <<< \"$cmd\" && exit 2",
        "# never run claude with --dangerously-skip-permissions",
        "claude --permission-mode plan",
        "claude --allow-dangerously-skip-permissions -p x",
        "pytest --yolo-mode",
    ],
)
def test_mentions_and_safe_modes_are_not_flagged(body: str) -> None:
    assert _messages(_script(body)) == []


def test_bypass_finding_points_at_the_flag_line() -> None:
    (finding,) = OverBroadPermissions().run([_script("set -e\nclaude \\\n  --yolo\n")])
    assert finding == Finding(
        rule_id="ABOM-007",
        severity="high",
        confidence="high",
        message="body runs an agent with permission checks disabled",
        location=Location(path=".claude/hooks/s.sh", line=3),
        artifact_id="script:.claude/hooks/s.sh:s.sh",
        fix="drop the flag and allow only the tools the automation needs",
    )


def test_settings_findings_and_severities() -> None:
    settings = Settings(
        name="s",
        source=HERE,
        agents=(),
        default_mode="bypassPermissions",
        enable_all_project_mcp_servers=True,
    )
    findings = list(OverBroadPermissions().run([settings]))
    assert [(f.severity, f.message) for f in findings] == [
        ("high", "defaultMode is bypassPermissions"),
        ("medium", "enableAllProjectMcpServers auto-approves every server in .mcp.json"),
    ]
    assert _messages(settings.model_copy(update={"enable_all_project_mcp_servers": False})) == [
        "defaultMode is bypassPermissions"
    ]
