"""ABOM-008: hooks that run a shell command on their own, when a session starts or a
prompt is submitted, from files the repository controls."""

import re
from collections.abc import Iterator, Sequence

from agentbom.models import Artifact, Finding, Hook, HookShell, Location, RuleId, Script

# Event names are case-sensitive and differ per agent.
_AUTO_RUN_EVENTS: frozenset[str] = frozenset(
    {
        # Claude Code and Codex. Setup runs on `claude --init` and `--maintenance`.
        "SessionStart",
        "Setup",
        "UserPromptSubmit",
        # Cursor
        "sessionStart",
        "beforeSubmitPrompt",
        "workspaceOpen",
        # Copilot (sessionStart is shared with Cursor)
        "userPromptSubmitted",
    }
)

# Command names are case-sensitive except PowerShell's. Short names need an
# argument after them, so "GH Token" or `const nc = 1` is not a command. `nc -U`
# talks to a local Unix socket, and `conn.fetch(` is a method, not the network fetch.
_NETWORK_COMMAND = re.compile(
    r"(?<![\w.$-])(?:curl|wget|(?i:Invoke-WebRequest|iwr|irm|Invoke-RestMethod)|scp"
    r"|(?:ssh|gh)(?=[ \t]+[\w@.-])|(?:nc|ncat)(?=[ \t]+[\w@.-])(?![ \t]+-U\b)"
    r"|git[ \t]+(?:clone|fetch|pull)|npm[ \t]+(?:i|install|ci)|pnpm[ \t]+(?:i|install)"
    r"|yarn(?:[ \t]+install)?(?=[ \t]*(?:$|[;&|)\"'`]))|pip3?[ \t]+install"
    r"|uv[ \t]+(?:sync|pip[ \t]+install)|npx|bunx|uvx"
    r"|brew[ \t]+install|apt(?:-get)?[ \t]+install)(?![\w-])",
    re.MULTILINE,
)
_NETWORK_CALL = re.compile(
    r"(?:(?<![\w.$])|(?<=\bglobalThis\.)|(?<=\bwindow\.)|(?<=\bself\.))fetch\("
    r"|\bhttps?\.(?:request|get)\(|\brequests\.(?:get|post|put|patch|delete|head"
    r"|request|Session)\b|\burllib\b|\bhttpx\b|\baxios\b",
)
# The repository root, found the usual way, is a path and not a hidden command.
_REPO_ROOT = re.compile(
    r"\$\(\s*git rev-parse --show-toplevel\s*\)|`\s*git rev-parse --show-toplevel\s*`"
)
_LOCAL_URL = re.compile(r"^https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])(?:[:/]|$)", re.I)
_PRINT_COMMANDS = frozenset({"echo", "printf", "write-host", "write-output", "true", ":"})
_FIX = "make the hook opt-in, or keep it to a reviewed script with no network access"


def _substitutes(shell: HookShell, command: str) -> bool:
    command = _REPO_ROOT.sub("", command)
    # In PowerShell a backtick escapes the next character; only $( runs a command.
    return "$(" in command or (shell != "powershell" and "`" in command)


def _prints_only(shell: HookShell, command: str) -> bool:
    """Every command in the line prints a message and nothing runs or gets written."""
    if _substitutes(shell, command):
        return False
    segments = [""]
    quote: str | None = None
    escaped = False
    for char in command:
        if escaped:
            escaped = False
        elif char == "\\" and quote != "'":
            escaped = True
        elif quote is not None:
            if char == quote:
                quote = None
        elif char in "'\"":
            quote = char
        elif char in "<>":
            return False
        elif char in ";&|\n":
            segments.append("")
            continue
        segments[-1] += char
    words = [segment.split(maxsplit=1) for segment in segments]
    return all(not w or w[0].lower() in _PRINT_COMMANDS for w in words)


def _scripts_run(command: str, scripts: Sequence[Script]) -> list[Script]:
    text = command.replace("\\", "/")
    return [
        script
        for script in scripts
        if re.search(rf"(?:^|[\s\"'/=]){re.escape(script.source.path)}(?=$|[\s\"';|&)])", text)
    ]


def _networked(script: Script) -> bool:
    body = script.body
    return _NETWORK_COMMAND.search(body) is not None or _NETWORK_CALL.search(body) is not None


def _command_finding(hook: Hook, scripts: Sequence[Script]) -> Finding | None:
    if all(_prints_only(shell, command) for shell, command in hook.commands.items()):
        return None
    reasons: list[str] = []
    via = sorted(
        {
            s.source.path
            for c in hook.commands.values()
            for s in _scripts_run(c, scripts)
            if _networked(s)
        }
    )
    if via or any(_NETWORK_COMMAND.search(c) for c in hook.commands.values()):
        reasons.append("network access")
    if any(_substitutes(shell, c) for shell, c in hook.commands.items()):
        reasons.append("command substitution")
    message = f"{hook.name} hook runs a shell command automatically"
    if reasons:
        message += " with " + " and ".join(reasons)
    if via:
        message += f" (via {', '.join(via)})"
    return Finding(
        rule_id="ABOM-008",
        severity="high" if reasons else "medium",
        confidence="medium",
        message=message,
        location=Location(path=hook.source.path),
        artifact_id=hook.id,
        fix=_FIX,
    )


def _http_finding(hook: Hook) -> Finding | None:
    if hook.url is None or _LOCAL_URL.match(hook.url):
        return None
    return Finding(
        rule_id="ABOM-008",
        severity="medium",
        confidence="medium",
        message=f"{hook.name} hook calls an external URL automatically",
        location=Location(path=hook.source.path),
        artifact_id=hook.id,
        fix=_FIX,
    )


class AutoRunHooks:
    rule_id: RuleId = "ABOM-008"

    def run(self, artifacts: Sequence[Artifact]) -> Iterator[Finding]:
        scripts = [a for a in artifacts if isinstance(a, Script)]
        for artifact in artifacts:
            if not isinstance(artifact, Hook) or artifact.event not in _AUTO_RUN_EVENTS:
                continue
            match artifact.handler_type:
                case "command" if artifact.commands:
                    finding = _command_finding(artifact, scripts)
                case "http":
                    finding = _http_finding(artifact)
                case _:
                    finding = None
            if finding is not None:
                yield finding
