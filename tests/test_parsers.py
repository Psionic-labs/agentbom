import json
from typing import get_args

import pytest

from agentbom.models import Hook, McpServer, RemoteLaunch, Rules, Skill, StdioLaunch
from agentbom.parsers import parse, parser_for
from agentbom.registry import Format


def test_every_format_has_a_parser() -> None:
    for format in get_args(Format):
        assert callable(parser_for(format))


def _servers(text: str, format: Format = "mcp_json") -> list[McpServer]:
    artifacts, errors = parse(text, ".mcp.json", format, ("claude_code",))
    assert errors == []
    assert all(isinstance(a, McpServer) for a in artifacts)
    return [a for a in artifacts if isinstance(a, McpServer)]


def _errors(text: str, format: Format, path: str = "f") -> list[str]:
    return [e.message for e in parse(text, path, format, ("cursor",))[1]]


def test_mcp_stdio_and_remote_servers() -> None:
    text = json.dumps(
        {
            "mcpServers": {
                "local": {"command": "npx", "args": ["-y", "pkg@1.0.0"], "env": {"K": "v"}},
                "remote": {
                    "type": "streamable-http",
                    "url": "https://x/mcp",
                    "headers": {"A": "b"},
                },
                "legacy": {"type": "sse", "url": "https://x/sse"},
                "untyped": {"url": "https://x/u", "disabled": True},
            }
        }
    )
    servers = {s.name: s.launch for s in _servers(text)}
    assert servers["local"] == StdioLaunch(
        transport="stdio", command="npx", args=("-y", "pkg@1.0.0"), env={"K": "v"}
    )
    assert servers["remote"] == RemoteLaunch(
        transport="http", url="https://x/mcp", headers={"A": "b"}
    )
    assert servers["legacy"] == RemoteLaunch(transport="sse", url="https://x/sse")
    assert servers["untyped"] == RemoteLaunch(transport="http", url="https://x/u")


def test_mcp_missing_servers_key_is_empty() -> None:
    assert _servers('{"other": 1}') == []


@pytest.mark.parametrize(
    ("entry", "needle"),
    [
        ({"type": "ws", "url": "wss://x"}, "'ws'"),
        ({"type": "stdio", "url": "https://x"}, "no command"),
        ({"args": ["x"]}, "neither a command nor a url"),
        ({"command": "npx", "args": "not-a-list"}, "args must be a list"),
        ({"command": "npx", "env": {"K": 1}}, "env.K must be a string"),
        ("just a string", "must be an object"),
    ],
)
def test_bad_mcp_entry_is_an_error_and_other_entries_still_parse(
    entry: object, needle: str
) -> None:
    text = json.dumps({"mcpServers": {"bad": entry, "good": {"command": "uvx"}}})
    artifacts, errors = parse(text, ".mcp.json", "mcp_json", ("claude_code",))
    assert [a.name for a in artifacts] == ["good"]
    assert len(errors) == 1
    assert errors[0].path == ".mcp.json"
    assert "mcpServers.bad" in errors[0].message
    assert needle in errors[0].message


def test_mcp_top_level_must_be_an_object() -> None:
    assert _errors("[1, 2]", "mcp_json") == ["top level must be an object"]


def test_mcp_invalid_json_reports_position() -> None:
    (message,) = _errors('{\n  "mcpServers": {,}\n}', "mcp_json")
    assert message.startswith("invalid JSON")
    assert "line 2" in message


def test_strict_json_rejects_comments() -> None:
    assert _errors('{"mcpServers": {} // note\n}', "mcp_json")


def test_vscode_mcp_accepts_jsonc() -> None:
    text = """{
      // Servers for this workspace
      "inputs": [],
      "servers": {
        /* the docs server */
        "docs": {
          "type": "http",
          "url": "https://example.com/a//b/*c*/", // keep the slashes
          "headers": {"Note": "say \\"hi\\" // not a comment",},
        },
        "local": {"type": "stdio", "command": "node", "args": ["a,]", "b"],},
      },
    }"""
    servers = {s.name: s.launch for s in _servers(text, "vscode_mcp_json")}
    assert servers["docs"] == RemoteLaunch(
        transport="http",
        url="https://example.com/a//b/*c*/",
        headers={"Note": 'say "hi" // not a comment'},
    )
    assert servers["local"] == StdioLaunch(transport="stdio", command="node", args=("a,]", "b"))


def test_vscode_mcp_unterminated_comment_is_an_error() -> None:
    assert _errors('{"servers": {} /* open', "vscode_mcp_json") == [
        "invalid JSON: unterminated block comment"
    ]


def test_unpaired_surrogate_is_an_error() -> None:
    errors = _errors('{"mcpServers": {"s": {"command": "\\ud800"}}}', "mcp_json")
    assert len(errors) == 1
    assert "surrogate" in errors[0]


def _hooks(text: str, format: Format) -> list[Hook]:
    artifacts, errors = parse(text, "hooks.json", format, ("codex",))
    assert errors == []
    return [a for a in artifacts if isinstance(a, Hook)]


def test_nested_hooks() -> None:
    text = json.dumps(
        {
            "permissions": {"allow": ["Bash(ls)"]},
            "hooks": {
                "PreToolUse": [
                    {"matcher": "Bash", "hooks": [{"type": "command", "command": "a.sh"}]},
                    {"hooks": [{"command": "b.sh"}, {"type": "http", "url": "https://h"}]},
                ],
                "SessionStart": [{"matcher": "startup", "hooks": [{"type": "prompt"}]}],
            },
        }
    )
    hooks = {h.name: h for h in _hooks(text, "nested_hooks_json")}
    assert set(hooks) == {
        "PreToolUse[0].hooks[0]",
        "PreToolUse[1].hooks[0]",
        "PreToolUse[1].hooks[1]",
        "SessionStart[0].hooks[0]",
    }
    first = hooks["PreToolUse[0].hooks[0]"]
    assert (first.event, first.matcher, first.handler_type) == ("PreToolUse", "Bash", "command")
    assert first.commands == {"default": "a.sh"}
    assert hooks["PreToolUse[1].hooks[0]"].matcher is None
    assert hooks["PreToolUse[1].hooks[0]"].handler_type == "command"
    http = hooks["PreToolUse[1].hooks[1]"]
    assert (http.handler_type, http.url, http.commands) == ("http", "https://h", {})
    assert hooks["SessionStart[0].hooks[0]"].matcher == "startup"


def test_settings_without_hooks_has_no_artifacts() -> None:
    assert _hooks('{"permissions": {"defaultMode": "plan"}}', "nested_hooks_json") == []


def test_malformed_nested_hook_group_is_an_error_and_others_parse() -> None:
    text = json.dumps(
        {
            "hooks": {
                "Stop": "not-a-list",
                "PreToolUse": [{"matcher": "Bash"}, {"hooks": [{"command": "ok.sh"}, 3]}],
            }
        }
    )
    artifacts, errors = parse(text, ".claude/settings.json", "nested_hooks_json", ("claude_code",))
    assert [a.name for a in artifacts] == ["PreToolUse[1].hooks[0]"]
    assert sorted(e.message for e in errors) == [
        "hooks.PreToolUse[0].hooks must be a list",
        "hooks.PreToolUse[1].hooks[1] must be an object",
        "hooks.Stop must be a list",
    ]


def test_cursor_hooks() -> None:
    text = json.dumps(
        {
            "version": 1,
            "hooks": {
                "beforeShellExecution": [
                    {"command": "./a.sh", "matcher": "git", "timeout": 5},
                    {"command": "./b.sh"},
                ]
            },
        }
    )
    hooks = _hooks(text, "cursor_hooks_json")
    assert [(h.name, h.matcher, h.handler_type, h.commands) for h in hooks] == [
        ("beforeShellExecution[0]", "git", "command", {"default": "./a.sh"}),
        ("beforeShellExecution[1]", None, "command", {"default": "./b.sh"}),
    ]


def test_copilot_hooks_keep_each_shell() -> None:
    text = json.dumps(
        {
            "version": 1,
            "hooks": {
                "preToolUse": [
                    {"type": "command", "bash": "./a.sh", "powershell": ".\\a.ps1", "cwd": "."}
                ]
            },
        }
    )
    (hook,) = _hooks(text, "copilot_hooks_json")
    assert hook.name == "preToolUse[0]"
    assert hook.commands == {"bash": "./a.sh", "powershell": ".\\a.ps1"}


def _markdown(text: str, path: str, format: Format) -> Skill | Rules:
    artifacts, errors = parse(text, path, format, ("claude_code",))
    assert errors == []
    (artifact,) = artifacts
    assert isinstance(artifact, Skill | Rules)
    return artifact


def test_skill_frontmatter_and_body() -> None:
    text = "---\nname: deploy\ndescription: Ship it\nallowed-tools: [Bash]\n---\n# Deploy\n"
    skill = _markdown(text, ".claude/skills/release/SKILL.md", "skill_md")
    assert isinstance(skill, Skill)
    assert skill.name == "deploy"
    assert skill.description == "Ship it"
    assert skill.frontmatter == {
        "name": "deploy",
        "description": "Ship it",
        "allowed-tools": ["Bash"],
    }
    assert skill.body == "# Deploy\n"
    assert skill.source.line == 1


@pytest.mark.parametrize(
    "text",
    ["# No frontmatter\n", "---\ndescription: d\n---\nbody", "---\nname: ''\n---\n", "---\n---\n"],
)
def test_skill_name_falls_back_to_directory(text: str) -> None:
    skill = _markdown(text, ".claude/skills/release/SKILL.md", "skill_md")
    assert skill.name == "release"


def test_skill_folded_description() -> None:
    text = "---\nname: s\ndescription: >\n  first line\n  second line\n---\n"
    skill = _markdown(text, ".agents/skills/s/SKILL.md", "skill_md")
    assert isinstance(skill, Skill)
    assert skill.description == "first line second line\n"


def test_frontmatter_dates_become_iso_strings() -> None:
    text = "---\ncreated: 2026-11-18\nstamp: 2026-11-18 10:30:00\n---\n"
    skill = _markdown(text, ".claude/skills/s/SKILL.md", "skill_md")
    assert skill.frontmatter == {"created": "2026-11-18", "stamp": "2026-11-18T10:30:00"}


@pytest.mark.parametrize(
    ("text", "needle"),
    [
        ("---\nname: [unclosed\n---\n", "invalid YAML frontmatter"),
        ("---\n- a\n- b\n---\n", "must be a mapping"),
        ("---\nname: x\n", "no closing --- line"),
        ("---\n1: one\n---\n", "non-string key"),
        ("---\nblob: !!binary aGVsbG8=\n---\n", "no JSON form"),
        ("---\nx: .nan\n---\n", "not a finite number"),
        ("---\na: &a [*a]\n---\n", "deeper than"),
        (
            "---\na: &a [x, x, x, x, x, x, x, x, x, x]\n"
            + "".join(
                f"{c}: &{c} [*{p}, *{p}, *{p}, *{p}, *{p}, *{p}, *{p}, *{p}, *{p}, *{p}]\n"
                for p, c in zip("abcdef", "bcdefg", strict=True)
            )
            + "---\n",
            "more than",
        ),
    ],
)
def test_bad_frontmatter_is_an_error_without_an_artifact(text: str, needle: str) -> None:
    artifacts, errors = parse(text, ".claude/skills/s/SKILL.md", "skill_md", ("claude_code",))
    assert artifacts == []
    assert len(errors) == 1
    assert needle in errors[0].message


def test_rules_name_is_path_and_frontmatter_is_optional() -> None:
    plain = _markdown("Use tabs.\n", "AGENTS.md", "rules_md")
    assert (plain.name, plain.frontmatter, plain.body) == ("AGENTS.md", {}, "Use tabs.\n")
    text = "---\nalwaysApply: true\nglobs: '*.ts'\n---\nRule body\n"
    rule = _markdown(text, ".cursor/rules/ts.mdc", "rules_md")
    assert rule.name == ".cursor/rules/ts.mdc"
    assert rule.frontmatter == {"alwaysApply": True, "globs": "*.ts"}
    assert rule.body == "Rule body\n"


def test_rules_starting_with_text_keep_later_rules_in_body() -> None:
    text = "# Title\n---\nnot: frontmatter\n---\n"
    rule = _markdown(text, "CLAUDE.md", "rules_md")
    assert rule.frontmatter == {}
    assert rule.body == text


def test_cursor_mdc_reads_unquoted_globs_like_cursor() -> None:
    text = "---\ndescription: Rules for .mdc files\nglobs: *.mdc\nalwaysApply: false\n---\n# Body\n"
    rule = _markdown(text, ".cursor/rules/mdc-files.mdc", "cursor_mdc")
    assert rule.frontmatter == {
        "description": "Rules for .mdc files",
        "globs": "*.mdc",
        "alwaysApply": False,
    }
    assert rule.body == "# Body\n"


def test_cursor_mdc_prefers_yaml_when_it_parses() -> None:
    text = "---\nglobs:\n  - '*.ts'\n  - '*.tsx'\nalwaysApply: true\n---\n"
    rule = _markdown(text, ".cursor/rules/ts.mdc", "cursor_mdc")
    assert rule.frontmatter == {"globs": ["*.ts", "*.tsx"], "alwaysApply": True}


def test_cursor_mdc_that_is_neither_yaml_nor_flat_is_an_error() -> None:
    text = "---\nglobs: *.ts\n  - nested\n---\n"
    artifacts, errors = parse(text, ".cursor/rules/x.mdc", "cursor_mdc", ("cursor",))
    assert artifacts == []
    assert len(errors) == 1
    assert errors[0].message.startswith("invalid YAML frontmatter")
    assert errors[0].message.endswith("at line 2")


def test_other_rules_files_need_valid_yaml_frontmatter() -> None:
    artifacts, errors = parse(
        "---\npaths: *.ts\n---\n", ".claude/rules/x.md", "rules_md", ("vscode",)
    )
    assert artifacts == []
    assert len(errors) == 1
