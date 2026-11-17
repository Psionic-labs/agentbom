import re
from dataclasses import dataclass
from typing import Literal

from pathspec.patterns.gitignore.basic import GitIgnoreBasicPattern

from agentbom.models import Agent

Format = Literal[
    "mcp_json",
    "vscode_mcp_json",
    "nested_hooks_json",
    "cursor_hooks_json",
    "copilot_hooks_json",
    "skill_md",
    "rules_md",
    "cursor_mdc",
]


@dataclass(frozen=True)
class SourcePattern:
    pattern: str
    format: Format
    agents: tuple[Agent, ...]


REGISTRY: tuple[SourcePattern, ...] = (
    SourcePattern(".mcp.json", "mcp_json", ("claude_code", "vscode")),
    SourcePattern(".cursor/mcp.json", "mcp_json", ("cursor",)),
    SourcePattern(".vscode/mcp.json", "vscode_mcp_json", ("vscode",)),
    SourcePattern(
        ".claude/settings.json", "nested_hooks_json", ("claude_code", "cursor", "copilot")
    ),
    SourcePattern(
        ".claude/settings.local.json",
        "nested_hooks_json",
        ("claude_code", "cursor", "copilot"),
    ),
    SourcePattern(".codex/hooks.json", "nested_hooks_json", ("codex",)),
    SourcePattern(".cursor/hooks.json", "cursor_hooks_json", ("cursor",)),
    SourcePattern(".github/hooks/*.json", "copilot_hooks_json", ("copilot",)),
    SourcePattern("**/.claude/skills/*/SKILL.md", "skill_md", ("claude_code", "cursor", "vscode")),
    SourcePattern(".agents/skills/*/SKILL.md", "skill_md", ("codex", "cursor")),
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
