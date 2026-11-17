import re
from dataclasses import dataclass
from typing import Literal

from pathspec.patterns.gitignore.basic import GitIgnoreBasicPattern

from agentbom.models import Agent, ScriptLanguage

Format = Literal[
    "mcp_json",
    "vscode_mcp_json",
    "claude_settings_json",
    "nested_hooks_json",
    "cursor_hooks_json",
    "copilot_hooks_json",
    "skill_md",
    "rules_md",
    "cursor_mdc",
    "script",
]


@dataclass(frozen=True)
class SourcePattern:
    pattern: str
    format: Format
    agents: tuple[Agent, ...]


_CLAUDE_HOOK_AGENTS: tuple[Agent, ...] = ("claude_code", "cursor", "copilot")
_CLAUDE_SKILL_AGENTS: tuple[Agent, ...] = ("claude_code", "cursor", "vscode")
_AGENTS_SKILL_AGENTS: tuple[Agent, ...] = ("codex", "cursor")

SCRIPT_LANGUAGES: dict[str, ScriptLanguage] = {
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".ps1": "powershell",
    ".psm1": "powershell",
    ".py": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".rb": "ruby",
    ".pl": "perl",
    ".bat": "batch",
    ".cmd": "batch",
}

# Directories whose scripts an agent runs, with the agents of the config row that runs them.
_SCRIPT_DIRECTORIES: tuple[tuple[str, tuple[Agent, ...]], ...] = (
    (".claude/hooks/**/", _CLAUDE_HOOK_AGENTS),
    (".cursor/hooks/**/", ("cursor",)),
    (".codex/hooks/**/", ("codex",)),
    (".github/hooks/**/", ("copilot",)),
    ("**/.claude/skills/*/**/", _CLAUDE_SKILL_AGENTS),
    (".agents/skills/*/**/", _AGENTS_SKILL_AGENTS),
    (".cursor/skills/*/**/", ("cursor",)),
    (".github/skills/*/**/", ("copilot",)),
)


def _script_rows() -> tuple[SourcePattern, ...]:
    # gitwildmatch has no brace expansion, so each directory and extension is its own row.
    return tuple(
        SourcePattern(f"{directory}*{extension}", "script", agents)
        for directory, agents in _SCRIPT_DIRECTORIES
        for extension in SCRIPT_LANGUAGES
    )


REGISTRY: tuple[SourcePattern, ...] = (
    SourcePattern(".mcp.json", "mcp_json", ("claude_code", "vscode")),
    SourcePattern(".cursor/mcp.json", "mcp_json", ("cursor",)),
    SourcePattern(".vscode/mcp.json", "vscode_mcp_json", ("vscode",)),
    SourcePattern(".claude/settings.json", "claude_settings_json", _CLAUDE_HOOK_AGENTS),
    SourcePattern(".claude/settings.local.json", "claude_settings_json", _CLAUDE_HOOK_AGENTS),
    SourcePattern(".codex/hooks.json", "nested_hooks_json", ("codex",)),
    SourcePattern(".cursor/hooks.json", "cursor_hooks_json", ("cursor",)),
    SourcePattern(".github/hooks/*.json", "copilot_hooks_json", ("copilot",)),
    SourcePattern("**/.claude/skills/*/SKILL.md", "skill_md", _CLAUDE_SKILL_AGENTS),
    SourcePattern(".agents/skills/*/SKILL.md", "skill_md", _AGENTS_SKILL_AGENTS),
    SourcePattern(".cursor/skills/*/SKILL.md", "skill_md", ("cursor",)),
    SourcePattern(".github/skills/*/SKILL.md", "skill_md", ("copilot",)),
    SourcePattern("**/.claude/rules/**/*.md", "rules_md", ("claude_code", "vscode")),
    SourcePattern(".claude/commands/**/*.md", "rules_md", ("claude_code",)),
    SourcePattern(".claude/agents/**/*.md", "rules_md", ("claude_code",)),
    SourcePattern("**/AGENTS.md", "rules_md", ("agents_md",)),
    SourcePattern("**/CLAUDE.md", "rules_md", ("claude_code",)),
    SourcePattern("**/CLAUDE.local.md", "rules_md", ("claude_code",)),
    SourcePattern(".cursorrules", "rules_md", ("cursor",)),
    SourcePattern("**/.cursor/rules/**/*.mdc", "cursor_mdc", ("cursor",)),
    SourcePattern(".github/copilot-instructions.md", "rules_md", ("copilot",)),
    SourcePattern(".github/instructions/**/*.instructions.md", "rules_md", ("copilot",)),
    SourcePattern(".github/prompts/**/*.prompt.md", "rules_md", ("vscode",)),
    SourcePattern(".github/agents/**/*.md", "rules_md", ("copilot",)),
    *_script_rows(),
)


def _compile(pattern: str) -> re.Pattern[str]:
    anchored = pattern if pattern.startswith("**/") else f"/{pattern}"
    regex = GitIgnoreBasicPattern(anchored).regex
    if regex is None:
        raise ValueError(f"registry pattern {pattern!r} matches nothing")
    return regex


_COMPILED = tuple((row, _compile(row.pattern)) for row in REGISTRY)


def match_source(path: str) -> SourcePattern | None:
    # fullmatch, because a gitignore pattern also matches every path under a
    # directory of the same name, and only the file itself is a source.
    for row, regex in _COMPILED:
        if regex.fullmatch(path):
            return row
    return None
