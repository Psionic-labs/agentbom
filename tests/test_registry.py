from typing import get_args

import pytest

from agentbom.models import Agent, ScriptLanguage
from agentbom.registry import REGISTRY, SCRIPT_LANGUAGES, match_source


@pytest.mark.parametrize(
    ("path", "expected_format", "expected_agents"),
    [
        (".mcp.json", "mcp_json", ("claude_code", "vscode")),
        (".cursor/mcp.json", "mcp_json", ("cursor",)),
        (".vscode/mcp.json", "vscode_mcp_json", ("vscode",)),
        (".claude/settings.local.json", "claude_settings_json", None),
        (".codex/hooks.json", "nested_hooks_json", ("codex",)),
        (".cursor/hooks.json", "cursor_hooks_json", ("cursor",)),
        (".github/hooks/guard.json", "copilot_hooks_json", ("copilot",)),
        ("apps/web/.claude/skills/deploy/SKILL.md", "skill_md", None),
        (".agents/skills/deploy/SKILL.md", "skill_md", ("codex", "cursor")),
        (".claude/rules/deep/nested/style.md", "rules_md", ("claude_code", "vscode")),
        ("packages/ui/AGENTS.md", "rules_md", ("agents_md",)),
        (".claude/CLAUDE.md", "rules_md", ("claude_code",)),
        ("lib/.cursor/rules/team/style.mdc", "rules_md", ("cursor",)),
        (".github/instructions/a/b.instructions.md", "rules_md", ("copilot",)),
        (".claude/hooks/guard.sh", "script", ("claude_code", "cursor", "copilot")),
        (".claude/hooks/lib/util.mjs", "script", ("claude_code", "cursor", "copilot")),
        (".cursor/hooks/start.ps1", "script", ("cursor",)),
        (".codex/hooks/check.py", "script", ("codex",)),
        (".github/hooks/block-secrets.js", "script", ("copilot",)),
        ("apps/web/.claude/skills/deploy/scripts/run.ts", "script", None),
        (".claude/skills/deploy/setup.cmd", "script", ("claude_code", "cursor", "vscode")),
        (".agents/skills/deploy/bin/x.rb", "script", ("codex", "cursor")),
        (".cursor/skills/deploy/x.pl", "script", ("cursor",)),
        (".github/skills/deploy/a/b/x.bash", "script", ("copilot",)),
        (".claude/skills/deploy/SKILL.md", "skill_md", None),
    ],
)
def test_known_sources_match(
    path: str, expected_format: str, expected_agents: tuple[str, ...] | None
) -> None:
    row = match_source(path)
    assert row is not None
    assert row.format == expected_format
    if expected_agents is not None:
        assert row.agents == expected_agents


@pytest.mark.parametrize(
    "path",
    [
        "sub/.mcp.json",
        "sub/.cursorrules",
        ".github/hooks/nested/guard.json",
        ".claude/skills/deploy/scripts/SKILL.md",
        ".claude/skills/SKILL.md",
        "AGENTS.md/notes.txt",
        ".cursor/rules/style.md",
        "README.md",
        "scripts/setup.sh",
        ".claude/skills/setup.sh",
        ".claude/hooks/notes.txt",
        "sub/.claude/hooks/guard.sh",
    ],
)
def test_other_paths_do_not_match(path: str) -> None:
    assert match_source(path) is None


def test_first_matching_row_wins() -> None:
    row = match_source(".claude/commands/AGENTS.md")
    assert row is not None
    assert row.pattern == ".claude/commands/**/*.md"


def test_registry_agents_are_known() -> None:
    known = set(get_args(Agent))
    for row in REGISTRY:
        assert row.agents
        assert set(row.agents) <= known


def test_every_script_extension_maps_to_a_language() -> None:
    for extension, language in SCRIPT_LANGUAGES.items():
        row = match_source(f".claude/hooks/a{extension}")
        assert row is not None
        assert row.format == "script", extension
        assert language in get_args(ScriptLanguage)
