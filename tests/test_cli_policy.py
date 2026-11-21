import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agentbom.cli import app
from tests.conftest import write_tree

runner = CliRunner()

REPO: dict[str, str | dict[str, object]] = {
    ".mcp.json": {"mcpServers": {"docs": {"command": "npx", "args": ["-y", "docs-mcp"]}}},
}
IGNORE_UNPINNED = (
    "version: 1\n"
    "ignore:\n"
    "  - rule: ABOM-005\n"
    "    path: .mcp.json\n"
    "    reason: docs server is vendored\n"
    "    expires: 2999-01-01\n"
)


def test_policy_file_in_the_repository_is_applied(tmp_path: Path) -> None:
    write_tree(tmp_path, {**REPO, "agentbom.policy.yml": IGNORE_UNPINNED})
    result = runner.invoke(app, ["scan", str(tmp_path), "--fail-on", "low"])
    assert result.exit_code == 0, result.output
    assert result.stdout.splitlines()[-2:] == [
        "No findings.",
        "1 finding suppressed by agentbom.policy.yml.",
    ]
    document = json.loads(runner.invoke(app, ["scan", str(tmp_path), "--format", "json"]).stdout)
    assert document["findings"] == []
    (suppressed,) = document["suppressed"]
    assert (suppressed["by"], suppressed["reason"]) == ("ignore", "docs server is vendored")
    assert suppressed["finding"]["rule_id"] == "ABOM-005"


@pytest.mark.parametrize(
    ("policy_fail_on", "cli_fail_on", "expected"),
    [(None, None, 0), ("medium", None, 1), ("medium", "high", 0), ("high", "medium", 1)],
)
def test_cli_fail_on_overrides_the_policy(
    tmp_path: Path, policy_fail_on: str | None, cli_fail_on: str | None, expected: int
) -> None:
    policy = "version: 1\n" + (f"fail_on: {policy_fail_on}\n" if policy_fail_on else "")
    write_tree(tmp_path, {**REPO, "agentbom.policy.yml": policy})
    args = ["scan", str(tmp_path)] + (["--fail-on", cli_fail_on] if cli_fail_on else [])
    assert runner.invoke(app, args).exit_code == expected


def test_explicit_policy_file_is_used_and_must_exist(tmp_path: Path) -> None:
    write_tree(tmp_path / "repo", REPO)
    write_tree(tmp_path, {"team.policy.yml": IGNORE_UNPINNED})
    repo = str(tmp_path / "repo")
    applied = runner.invoke(
        app, ["scan", repo, "--fail-on", "low", "--policy", str(tmp_path / "team.policy.yml")]
    )
    assert applied.exit_code == 0, applied.output
    missing = runner.invoke(app, ["scan", repo, "--policy", str(tmp_path / "none.yml")])
    assert missing.exit_code == 2
    assert "none.yml: cannot read" in missing.stderr


def test_invalid_policy_exits_2_for_scan_and_check(tmp_path: Path) -> None:
    policy = "version: 1\nignore:\n  - {rule: ABOM-005, path: .mcp.json, reason: r}\n"
    write_tree(tmp_path, {**REPO, "agentbom.policy.yml": policy})
    assert runner.invoke(app, ["lock", str(tmp_path)]).exit_code == 0
    for command in ("scan", "check"):
        result = runner.invoke(app, [command, str(tmp_path)])
        assert result.exit_code == 2
        assert "agentbom.policy.yml: ignore.0.expires: Field required" in result.stderr


def test_policy_cannot_hide_drift_from_check(tmp_path: Path) -> None:
    write_tree(tmp_path, {**REPO, "agentbom.policy.yml": IGNORE_UNPINNED})
    assert runner.invoke(app, ["lock", str(tmp_path)]).exit_code == 0
    servers = {"docs": {"command": "npx", "args": ["-y", "docs-mcp", "--root", "/"]}}
    write_tree(tmp_path, {".mcp.json": {"mcpServers": servers}})
    result = runner.invoke(app, ["check", str(tmp_path), "--fail-on", "high"])
    assert result.exit_code == 1
    assert "HIGH  ABOM-006  .mcp.json" in result.stdout
    assert "1 finding suppressed by agentbom.policy.yml." in result.stdout


def test_expired_ignore_is_reported_and_stops_applying(tmp_path: Path) -> None:
    policy = IGNORE_UNPINNED.replace("2999-01-01", "2000-01-01")
    write_tree(tmp_path, {**REPO, "agentbom.policy.yml": policy})
    result = runner.invoke(app, ["scan", str(tmp_path), "--fail-on", "medium"])
    assert result.exit_code == 1
    assert (
        'policy: ignore for ABOM-005 on ".mcp.json" expired on 2000-01-01; '
        "its findings are reported again"
    ) in result.stdout


@pytest.mark.parametrize("command", ["scan", "check"])
def test_sarif_and_markdown_formats_keep_the_exit_code(tmp_path: Path, command: str) -> None:
    write_tree(tmp_path, REPO)
    assert runner.invoke(app, ["lock", str(tmp_path)]).exit_code == 0
    sarif = runner.invoke(app, [command, str(tmp_path), "--format", "sarif", "--fail-on", "low"])
    assert sarif.exit_code == 1
    (run,) = json.loads(sarif.stdout)["runs"]
    assert [r["ruleId"] for r in run["results"]] == ["ABOM-005"]
    markdown = runner.invoke(app, [command, str(tmp_path), "--format", "markdown"])
    assert markdown.exit_code == 0
    assert markdown.stdout.startswith(
        f"### agentbom {command}: 1 finding (0 high, 1 medium, 0 low)\n"
    )
