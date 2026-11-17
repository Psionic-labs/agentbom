import os
import sys
from pathlib import Path

import pytest

from agentbom.discover import MAX_FILE_BYTES
from agentbom.models import McpServer, Skill
from agentbom.scan import scan
from tests.conftest import junction_or_skip, symlink_or_skip, write_tree

SKILL = "---\nname: {name}\ndescription: d\n---\nBody\n"
NESTED_HOOKS = {"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "x"}]}]}}
FLAT_HOOKS = {"version": 1, "hooks": {"stop": [{"command": "x"}]}}


def _inventory(root: Path) -> set[tuple[str, str, str, tuple[str, ...]]]:
    result = scan(root)
    assert result.errors == ()
    return {(a.kind, a.source.path, a.name, a.agents) for a in result.artifacts}


def test_every_registry_source_is_inventoried(tmp_path: Path) -> None:
    write_tree(
        tmp_path,
        {
            ".mcp.json": {"mcpServers": {"m1": {"command": "npx"}}},
            ".cursor/mcp.json": {"mcpServers": {"m2": {"type": "http", "url": "https://c"}}},
            ".vscode/mcp.json": '{"servers": {"m3": {"type": "sse", "url": "https://v"},},}',
            ".claude/settings.json": NESTED_HOOKS,
            ".claude/settings.local.json": NESTED_HOOKS,
            ".codex/hooks.json": NESTED_HOOKS,
            ".cursor/hooks.json": FLAT_HOOKS,
            ".github/hooks/guard.json": FLAT_HOOKS,
            "apps/web/.claude/skills/a/SKILL.md": SKILL.format(name="alpha"),
            ".agents/skills/b/SKILL.md": SKILL.format(name="beta"),
            ".cursor/skills/c/SKILL.md": SKILL.format(name="gamma"),
            ".github/skills/d/SKILL.md": SKILL.format(name="delta"),
            ".claude/rules/style.md": "r",
            ".claude/commands/ship.md": "c",
            ".claude/agents/reviewer.md": "a",
            "AGENTS.md": "a",
            "CLAUDE.md": "c",
            "CLAUDE.local.md": "c",
            ".cursorrules": "c",
            ".cursor/rules/ts.mdc": "---\nalwaysApply: true\n---\nc",
            ".github/copilot-instructions.md": "c",
            ".github/instructions/ts.instructions.md": "---\napplyTo: '**/*.ts'\n---\nc",
            ".github/prompts/fix.prompt.md": "p",
            ".github/agents/helper.md": "a",
            ".claude/hooks/guard.sh": "echo hi\n",
            ".claude/skills/a/scripts/run.py": "print(1)\n",
            "README.md": "not agent context",
            "docs/.mcp.json": {"mcpServers": {"nested": {"command": "x"}}},
        },
    )
    hook_agents = ("claude_code", "cursor", "copilot")
    assert _inventory(tmp_path) == {
        ("mcp_server", ".mcp.json", "m1", ("claude_code", "vscode")),
        ("mcp_server", ".cursor/mcp.json", "m2", ("cursor",)),
        ("mcp_server", ".vscode/mcp.json", "m3", ("vscode",)),
        ("hook", ".claude/settings.json", "Stop[0].hooks[0]", hook_agents),
        ("hook", ".claude/settings.local.json", "Stop[0].hooks[0]", hook_agents),
        ("settings", ".claude/settings.json", ".claude/settings.json", hook_agents),
        ("settings", ".claude/settings.local.json", ".claude/settings.local.json", hook_agents),
        ("script", ".claude/hooks/guard.sh", ".claude/hooks/guard.sh", hook_agents),
        (
            "script",
            ".claude/skills/a/scripts/run.py",
            ".claude/skills/a/scripts/run.py",
            ("claude_code", "cursor", "vscode"),
        ),
        ("hook", ".codex/hooks.json", "Stop[0].hooks[0]", ("codex",)),
        ("hook", ".cursor/hooks.json", "stop[0]", ("cursor",)),
        ("hook", ".github/hooks/guard.json", "stop[0]", ("copilot",)),
        (
            "skill",
            "apps/web/.claude/skills/a/SKILL.md",
            "alpha",
            ("claude_code", "cursor", "vscode"),
        ),
        ("skill", ".agents/skills/b/SKILL.md", "beta", ("codex", "cursor")),
        ("skill", ".cursor/skills/c/SKILL.md", "gamma", ("cursor",)),
        ("skill", ".github/skills/d/SKILL.md", "delta", ("copilot",)),
        ("rules", ".claude/rules/style.md", ".claude/rules/style.md", ("claude_code", "vscode")),
        ("rules", ".claude/commands/ship.md", ".claude/commands/ship.md", ("claude_code",)),
        ("rules", ".claude/agents/reviewer.md", ".claude/agents/reviewer.md", ("claude_code",)),
        ("rules", "AGENTS.md", "AGENTS.md", ("agents_md",)),
        ("rules", "CLAUDE.md", "CLAUDE.md", ("claude_code",)),
        ("rules", "CLAUDE.local.md", "CLAUDE.local.md", ("claude_code",)),
        ("rules", ".cursorrules", ".cursorrules", ("cursor",)),
        ("rules", ".cursor/rules/ts.mdc", ".cursor/rules/ts.mdc", ("cursor",)),
        (
            "rules",
            ".github/copilot-instructions.md",
            ".github/copilot-instructions.md",
            ("copilot",),
        ),
        (
            "rules",
            ".github/instructions/ts.instructions.md",
            ".github/instructions/ts.instructions.md",
            ("copilot",),
        ),
        ("rules", ".github/prompts/fix.prompt.md", ".github/prompts/fix.prompt.md", ("vscode",)),
        ("rules", ".github/agents/helper.md", ".github/agents/helper.md", ("copilot",)),
    }


def test_artifacts_are_sorted_with_unique_ids(tmp_path: Path) -> None:
    write_tree(
        tmp_path,
        {
            "b/AGENTS.md": "x",
            "AGENTS.md": "x",
            ".mcp.json": {"mcpServers": {"z": {"command": "z"}, "a": {"command": "a"}}},
            ".claude/commands/AGENTS.md": "first match wins",
        },
    )
    result = scan(tmp_path)
    keys = [(a.kind, a.source.path, a.name) for a in result.artifacts]
    assert keys == [
        ("mcp_server", ".mcp.json", "a"),
        ("mcp_server", ".mcp.json", "z"),
        ("rules", ".claude/commands/AGENTS.md", ".claude/commands/AGENTS.md"),
        ("rules", "AGENTS.md", "AGENTS.md"),
        ("rules", "b/AGENTS.md", "b/AGENTS.md"),
    ]
    ids = [a.id for a in result.artifacts]
    assert len(ids) == len(set(ids))
    assert result.artifacts[2].agents == ("claude_code",)


def test_malformed_file_is_an_error_and_other_files_still_inventory(tmp_path: Path) -> None:
    write_tree(
        tmp_path,
        {
            ".mcp.json": "{not json",
            ".cursor/mcp.json": {
                "mcpServers": {"bad": {"type": "carrier-pigeon", "url": "wss://x"}}
            },
            "AGENTS.md": "fine",
        },
    )
    result = scan(tmp_path)
    assert [a.source.path for a in result.artifacts] == ["AGENTS.md"]
    assert [e.path for e in result.errors] == [".cursor/mcp.json", ".mcp.json"]
    assert "'carrier-pigeon'" in result.errors[0].message
    assert result.errors[1].message.startswith("invalid JSON")


def test_gitignore_rules_apply_per_directory(tmp_path: Path) -> None:
    write_tree(
        tmp_path,
        {
            ".gitignore": "build/\nCLAUDE.local.md\n!/kept/CLAUDE.local.md\n!build/AGENTS.md\n",
            "CLAUDE.local.md": "ignored by root pattern",
            "kept/CLAUDE.local.md": "re-included by negation",
            "build/AGENTS.md": "inside an ignored directory, which git never re-includes",
            "build/.claude/skills/s/SKILL.md": b"\xff not even utf-8",
            "pkg/.gitignore": "AGENTS.md\n",
            "pkg/AGENTS.md": "ignored by nested .gitignore",
            "pkg/sub/AGENTS.md": "ignored by the parent directory's .gitignore",
            "pkg/keep/.gitignore": "!AGENTS.md\n",
            "pkg/keep/AGENTS.md": "re-included by the deeper .gitignore",
            "other/AGENTS.md": "a sibling .gitignore does not apply",
        },
    )
    assert {path for _, path, _, _ in _inventory(tmp_path)} == {
        "kept/CLAUDE.local.md",
        "pkg/keep/AGENTS.md",
        "other/AGENTS.md",
    }


def test_git_directory_is_not_scanned(tmp_path: Path) -> None:
    write_tree(tmp_path, {".git/AGENTS.md": "x", "AGENTS.md": "x"})
    assert {path for _, path, _, _ in _inventory(tmp_path)} == {"AGENTS.md"}


def test_symlinked_files_and_directories_are_not_read(tmp_path: Path) -> None:
    write_tree(
        tmp_path,
        {".agents/skills/s/SKILL.md": SKILL.format(name="s"), "docs/notes.md": "notes"},
    )
    symlink_or_skip(tmp_path / ".claude", ".agents", is_dir=True)
    symlink_or_skip(tmp_path / "CLAUDE.md", "docs/notes.md", is_dir=False)
    symlink_or_skip(tmp_path / "AGENTS.md", "missing.md", is_dir=False)
    assert _inventory(tmp_path) == {
        ("skill", ".agents/skills/s/SKILL.md", "s", ("codex", "cursor"))
    }


def test_junctioned_directories_are_not_read(tmp_path: Path) -> None:
    write_tree(tmp_path, {".agents/skills/s/SKILL.md": SKILL.format(name="s")})
    junction_or_skip(tmp_path / ".claude", tmp_path / ".agents")
    assert (tmp_path / ".claude" / "skills" / "s" / "SKILL.md").is_file()
    assert _inventory(tmp_path) == {
        ("skill", ".agents/skills/s/SKILL.md", "s", ("codex", "cursor"))
    }


def test_file_size_limit(tmp_path: Path) -> None:
    write_tree(
        tmp_path,
        {"CLAUDE.md": b"a" * MAX_FILE_BYTES, "AGENTS.md": b"a" * (MAX_FILE_BYTES + 1)},
    )
    result = scan(tmp_path)
    assert [a.source.path for a in result.artifacts] == ["CLAUDE.md"]
    assert [(e.path, e.message) for e in result.errors] == [
        ("AGENTS.md", "file is larger than the 2 MiB limit")
    ]


def test_non_utf8_file_is_an_error(tmp_path: Path) -> None:
    write_tree(tmp_path, {"AGENTS.md": b"caf\xe9\n"})
    result = scan(tmp_path)
    assert result.artifacts == ()
    assert [(e.path, e.message) for e in result.errors] == [
        ("AGENTS.md", "not valid UTF-8 (byte 3)")
    ]


def test_named_pipe_is_an_error_not_a_hang(tmp_path: Path) -> None:
    if sys.platform == "win32":
        pytest.skip("named pipes in the filesystem need POSIX")
    os.mkfifo(tmp_path / "AGENTS.md")
    result = scan(tmp_path)
    assert [(e.path, e.message) for e in result.errors] == [("AGENTS.md", "not a regular file")]


def test_bom_and_line_endings_do_not_change_content(tmp_path: Path) -> None:
    lf = "---\nname: s\ndescription: >\n  folded\n---\nline one\nline two\n"
    variants = {
        "lf": lf.encode("utf-8"),
        "crlf_bom": b"\xef\xbb\xbf" + lf.replace("\n", "\r\n").encode("utf-8"),
        "cr": lf.replace("\n", "\r").encode("utf-8"),
    }
    hashes = set()
    for label, data in variants.items():
        write_tree(tmp_path / label, {".claude/skills/s/SKILL.md": data})
        (skill,) = scan(tmp_path / label).artifacts
        assert isinstance(skill, Skill)
        assert skill.body == "line one\nline two\n"
        assert skill.description == "folded\n"
        hashes.add(skill.content_hash)
    assert len(hashes) == 1


def test_hidden_characters_are_preserved(tmp_path: Path) -> None:
    write_tree(tmp_path, {".mcp.json": '{"mcpServers": {"s": {"command": "a\\u200bb\u202e"}}}'})
    (server,) = scan(tmp_path).artifacts
    assert isinstance(server, McpServer)
    assert server.launch.model_dump()["command"] == "a\u200bb\u202e"


def test_root_must_be_a_directory(tmp_path: Path) -> None:
    write_tree(tmp_path, {"file.txt": "x"})
    with pytest.raises(NotADirectoryError):
        scan(tmp_path / "file.txt")
