import hashlib
import json
import subprocess
import sys
from pathlib import Path

from typer.testing import CliRunner

from agentbom.cli import app
from tests.conftest import write_tree

runner = CliRunner()

SECRET = "ghp_s3cretTokenValue"
REPO: dict[str, str | dict[str, object]] = {
    ".mcp.json": {
        "mcpServers": {
            "gh": {"command": "npx", "args": ["-y", "gh-mcp@1.2.3"], "env": {"GH_TOKEN": SECRET}},
            "docs": {
                "type": "http",
                "url": "https://docs/mcp",
                "headers": {"Authorization": SECRET},
            },
        }
    },
    ".claude/skills/a/SKILL.md": "---\nname: a\n---\nskill body text\n",
    ".claude/skills/b/SKILL.md": "---\nname: b\n---\nskill body text\n",
    "AGENTS.md": "rules body text\n",
}


def test_json_output(tmp_path: Path) -> None:
    write_tree(tmp_path, REPO)
    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])
    assert result.exit_code == 0, result.output
    document = json.loads(result.stdout)
    assert document["schema_version"] == 1
    assert document["errors"] == []
    by_id = {a["id"]: a for a in document["artifacts"]}
    assert list(by_id) == [
        "mcp_server:.mcp.json:docs",
        "mcp_server:.mcp.json:gh",
        "rules:AGENTS.md:AGENTS.md",
        "skill:.claude/skills/a/SKILL.md:a",
        "skill:.claude/skills/b/SKILL.md:b",
    ]
    gh = by_id["mcp_server:.mcp.json:gh"]
    assert gh["launch"] == {
        "transport": "stdio",
        "command": "npx",
        "args": ["-y", "gh-mcp@1.2.3"],
        "env_keys": ["GH_TOKEN"],
    }
    canonical = (
        '{"kind":"mcp_server","launch":{"args":["-y","gh-mcp@1.2.3"],"command":"npx",'
        f'"env":{{"GH_TOKEN":"{SECRET}"}},"transport":"stdio"}},"name":"gh"}}'
    )
    assert gh["content_hash"] == hashlib.sha256(canonical.encode()).hexdigest()
    assert gh["source"] == {"path": ".mcp.json", "line": None}
    assert gh["agents"] == ["claude_code", "vscode"]
    assert by_id["mcp_server:.mcp.json:docs"]["launch"] == {
        "transport": "http",
        "url": "https://docs/mcp",
        "header_keys": ["Authorization"],
    }
    skill = by_id["skill:.claude/skills/a/SKILL.md:a"]
    assert skill["frontmatter"] == {"name": "a"}
    assert "body" not in skill
    assert "body" not in by_id["rules:AGENTS.md:AGENTS.md"]


def test_json_output_never_contains_secrets_bodies_or_absolute_paths(tmp_path: Path) -> None:
    write_tree(tmp_path, REPO)
    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])
    assert SECRET not in result.stdout
    assert "body text" not in result.stdout
    assert str(tmp_path) not in result.stdout
    assert tmp_path.as_posix() not in result.stdout


def test_json_output_is_byte_identical_across_runs(tmp_path: Path) -> None:
    write_tree(tmp_path, REPO)
    first = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])
    second = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])
    assert first.stdout_bytes == second.stdout_bytes
    assert first.stdout_bytes.endswith(b"}\n")


def test_terminal_output(tmp_path: Path) -> None:
    write_tree(tmp_path, REPO)
    result = runner.invoke(app, ["scan", str(tmp_path)], env={"COLUMNS": "200"})
    assert result.exit_code == 0
    lines = result.stdout.splitlines()
    assert lines[0] == "Found: 2 MCP servers, 2 skills, 0 hooks, 1 rules file"
    assert "https://docs/mcp" in result.stdout
    assert SECRET not in result.stdout
    assert str(tmp_path) not in result.stdout


def test_terminal_summary_singular_and_empty(tmp_path: Path) -> None:
    write_tree(tmp_path / "one", {".cursor/hooks.json": {"hooks": {"stop": [{"command": "x"}]}}})
    write_tree(tmp_path / "one", {".mcp.json": {"mcpServers": {"s": {"command": "x"}}}})
    write_tree(tmp_path / "one", {".claude/skills/s/SKILL.md": "x"})
    one = runner.invoke(app, ["scan", str(tmp_path / "one")])
    assert one.stdout.splitlines()[0] == "Found: 1 MCP server, 1 skill, 1 hook, 0 rules files"
    (tmp_path / "empty").mkdir()
    empty = runner.invoke(app, ["scan", str(tmp_path / "empty")])
    assert empty.exit_code == 0
    assert empty.stdout == "Found: 0 MCP servers, 0 skills, 0 hooks, 0 rules files\n"


def test_terminal_escapes_control_and_bidi_characters(tmp_path: Path) -> None:
    name = "evil\x1b[31m‮"
    write_tree(tmp_path, {".mcp.json": {"mcpServers": {name: {"command": "x\x07"}}}})
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 0
    assert "\x1b" not in result.stdout
    assert "‮" not in result.stdout
    assert "\x07" not in result.stdout
    assert "\\u001b" in result.stdout


def test_errors_exit_2_and_go_to_stderr_in_terminal_mode(tmp_path: Path) -> None:
    write_tree(tmp_path, {".mcp.json": "{broken", "AGENTS.md": "ok"})
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 2
    assert result.stdout.splitlines()[0] == "Found: 0 MCP servers, 0 skills, 0 hooks, 1 rules file"
    assert ".mcp.json: invalid JSON" in result.stderr
    assert "invalid JSON" not in result.stdout


def test_errors_exit_2_and_are_in_the_json_document(tmp_path: Path) -> None:
    write_tree(tmp_path, {".mcp.json": "{broken", "AGENTS.md": "ok"})
    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])
    assert result.exit_code == 2
    document = json.loads(result.stdout)
    assert [e["path"] for e in document["errors"]] == [".mcp.json"]
    assert [a["id"] for a in document["artifacts"]] == ["rules:AGENTS.md:AGENTS.md"]


def test_path_that_is_not_a_directory_exits_2(tmp_path: Path) -> None:
    write_tree(tmp_path, {"file.txt": "x"})
    for target in (tmp_path / "file.txt", tmp_path / "missing"):
        result = runner.invoke(app, ["scan", str(target)])
        assert result.exit_code == 2
        assert "is not a directory" in result.stderr


def test_default_path_is_the_current_directory(tmp_path: Path) -> None:
    write_tree(tmp_path, {"AGENTS.md": "x"})
    result = subprocess.run(
        [sys.executable, "-m", "agentbom", "scan", "--format", "json"],
        cwd=tmp_path,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    document = json.loads(result.stdout.decode("utf-8"))
    assert [a["id"] for a in document["artifacts"]] == ["rules:AGENTS.md:AGENTS.md"]
