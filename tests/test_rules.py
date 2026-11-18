from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import get_args

import pytest

import agentbom.rules
from agentbom.models import (
    Artifact,
    Finding,
    Hook,
    Location,
    McpServer,
    RemoteLaunch,
    RuleId,
    Rules,
    Script,
    Settings,
    Severity,
    Skill,
    StdioLaunch,
)
from agentbom.rules import RULES, run_rules
from agentbom.rules._surfaces import Surface, field_label, line_of, surfaces
from agentbom.scan import scan
from tests.conftest import write_tree

HERE = Location(path="x")


def _shape(artifact: Artifact) -> list[tuple[str, str, str, int | None]]:
    return [(s.context, s.field, s.text, s.line) for s in surfaces(artifact)]


def test_stdio_server_is_one_executable_surface_plus_env_config() -> None:
    server = McpServer(
        name="s",
        source=HERE,
        agents=(),
        launch=StdioLaunch(
            transport="stdio", command="npx", args=("-y", "pkg"), env={"A": "1", "B": "2"}
        ),
    )
    assert _shape(server) == [
        ("executable", "command", "npx -y pkg", None),
        ("config", "env.A", "1", None),
        ("config", "env.B", "2", None),
    ]


def test_remote_server_url_and_headers_are_config() -> None:
    server = McpServer(
        name="s",
        source=HERE,
        agents=(),
        launch=RemoteLaunch(transport="http", url="https://h", headers={"Authorization": "t"}),
    )
    assert _shape(server) == [
        ("config", "url", "https://h", None),
        ("config", "headers.Authorization", "t", None),
    ]


def test_hook_commands_are_executable_and_url_is_config() -> None:
    hook = Hook(
        name="h",
        source=HERE,
        agents=(),
        event="SessionStart",
        matcher=None,
        handler_type="command",
        commands={"bash": "a.sh", "powershell": "a.ps1"},
        url="https://h",
    )
    assert _shape(hook) == [
        ("executable", "commands.bash", "a.sh", None),
        ("executable", "commands.powershell", "a.ps1", None),
        ("config", "url", "https://h", None),
    ]


def test_script_skill_rules_and_settings_surfaces() -> None:
    script = Script(name="s.sh", source=HERE, agents=(), language="shell", body="echo")
    skill = Skill(
        name="k",
        source=HERE,
        agents=(),
        description="d",
        frontmatter={},
        body="b",
        body_line=4,
    )
    bare_skill = skill.model_copy(update={"description": None})
    rules = Rules(name="r", source=HERE, agents=(), frontmatter={}, body="r", body_line=1)
    settings = Settings(name="s", source=HERE, agents=(), allow=("Bash",), env={"K": "v"})
    assert _shape(script) == [("executable", "body", "echo", 1)]
    assert _shape(skill) == [
        ("skill_prose", "description", "d", None),
        ("skill_prose", "body", "b", 4),
    ]
    assert _shape(bare_skill) == [("skill_prose", "body", "b", 4)]
    assert _shape(rules) == [("rules_prose", "body", "r", 1)]
    assert _shape(settings) == [("config", "env.K", "v", None)]


def test_field_label_names_the_artifact_when_a_file_holds_several() -> None:
    server = McpServer(
        name="docs",
        source=HERE,
        agents=(),
        launch=StdioLaunch(transport="stdio", command="npx", env={"K": "v"}),
    )
    hook = Hook(
        name="SessionStart[0].hooks[1]",
        source=HERE,
        agents=(),
        event="SessionStart",
        matcher=None,
        handler_type="command",
        commands={"default": "x"},
    )
    rules = Rules(name="r", source=HERE, agents=(), frontmatter={}, body="b", body_line=1)
    assert [field_label(s) for s in surfaces(server)] == [
        'server "docs" command',
        'server "docs" env.K',
    ]
    assert [field_label(s) for s in surfaces(hook)] == [
        "hook SessionStart[0].hooks[1] commands.default"
    ]
    assert [field_label(s) for s in surfaces(rules)] == ["body"]


def test_line_of_counts_newlines_before_the_offset() -> None:
    rules = Rules(name="r", source=HERE, agents=(), frontmatter={}, body="", body_line=1)
    surface = Surface(rules, "rules_prose", "body", "one\ntwo\nthree", 5)
    assert line_of(surface, 0) == 5
    assert line_of(surface, 3) == 5
    assert line_of(surface, 4) == 6
    assert line_of(surface, surface.text.index("three")) == 7
    assert line_of(Surface(rules, "rules_prose", "description", "a\nb", None), 2) is None


def test_scan_reports_body_lines_from_the_file(tmp_path: Path) -> None:
    write_tree(tmp_path, {".claude/skills/s/SKILL.md": "---\nname: s\n---\nfirst\nsecond\n"})
    (skill,) = scan(tmp_path).artifacts
    body = next(s for s in surfaces(skill) if s.field == "body")
    assert line_of(body, body.text.index("second")) == 5


def test_rules_have_unique_known_ids() -> None:
    ids = [rule.rule_id for rule in RULES]
    assert len(ids) == len(set(ids)), "a rule is registered twice"
    assert set(ids) <= set(get_args(RuleId))


class _FakeRule:
    rule_id: RuleId = "ABOM-009"

    def __init__(self, findings: Sequence[tuple[Severity, RuleId, str, int | None, str]]) -> None:
        self._findings = findings

    def run(self, artifacts: Sequence[Artifact]) -> Iterable[Finding]:
        for severity, rule_id, path, line, message in self._findings:
            yield Finding(
                rule_id=rule_id,
                severity=severity,
                confidence="low",
                message=message,
                location=Location(path=path, line=line),
                artifact_id=f"rules:{path}:{path}",
            )


def test_findings_sort_by_severity_rule_path_line_and_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rule = _FakeRule(
        [
            ("low", "ABOM-001", "a", 1, "m"),
            ("medium", "ABOM-009", "b", 3, "m"),
            ("high", "ABOM-009", "a", None, "m"),
            ("medium", "ABOM-009", "b", 2, "z"),
            ("medium", "ABOM-009", "b", 2, "a"),
            ("medium", "ABOM-002", "z", 9, "m"),
            ("high", "ABOM-002", "b", 1, "m"),
        ]
    )
    monkeypatch.setattr(agentbom.rules, "RULES", (rule,))
    findings = run_rules(())
    assert [
        (f.severity, f.rule_id, f.location.path, f.location.line, f.message) for f in findings
    ] == [
        ("high", "ABOM-002", "b", 1, "m"),
        ("high", "ABOM-009", "a", None, "m"),
        ("medium", "ABOM-002", "z", 9, "m"),
        ("medium", "ABOM-009", "b", 2, "a"),
        ("medium", "ABOM-009", "b", 2, "z"),
        ("medium", "ABOM-009", "b", 3, "m"),
        ("low", "ABOM-001", "a", 1, "m"),
    ]


def test_scan_runs_the_rules_on_the_parsed_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[str] = []

    class Recorder:
        rule_id: RuleId = "ABOM-009"

        def run(self, artifacts: Sequence[Artifact]) -> Iterable[Finding]:
            seen.extend(a.id for a in artifacts)
            return ()

    monkeypatch.setattr(agentbom.rules, "RULES", (Recorder(),))
    write_tree(tmp_path, {"b/AGENTS.md": "x", "AGENTS.md": "x"})
    assert scan(tmp_path).findings == ()
    assert seen == ["rules:AGENTS.md:AGENTS.md", "rules:b/AGENTS.md:b/AGENTS.md"]
