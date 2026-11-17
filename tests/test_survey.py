import importlib.util
from collections.abc import Iterator, Sequence
from pathlib import Path
from types import ModuleType

import pytest

import agentbom.rules
from agentbom.models import Artifact, Finding, Location, RuleId
from agentbom.scan import scan
from tests.conftest import write_tree

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
FAKE_TOKEN = "ghp_" + "0123456789abcdefghijklmnopqrstuvwxyzAB"


@pytest.fixture
def survey(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    monkeypatch.syspath_prepend(str(SCRIPTS))
    spec = importlib.util.spec_from_file_location("survey", SCRIPTS / "survey.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _LineFinder:
    """Flags every line of every rules file that contains `needle`, with its line number."""

    def __init__(self, rule_id: RuleId, needle: str) -> None:
        self.rule_id = rule_id
        self._needle = needle

    def run(self, artifacts: Sequence[Artifact]) -> Iterator[Finding]:
        for artifact in artifacts:
            if artifact.kind not in ("rules", "script"):
                continue
            for offset, text in enumerate(artifact.body.split("\n")):
                if self._needle in text:
                    yield Finding(
                        rule_id=self.rule_id,
                        severity="medium",
                        confidence="low",
                        message=f"found {self._needle}",
                        location=Location(path=artifact.source.path, line=offset + 1),
                        artifact_id=artifact.id,
                    )


def _install(monkeypatch: pytest.MonkeyPatch, survey: ModuleType, *rules: _LineFinder) -> None:
    monkeypatch.setattr(agentbom.rules, "RULES", rules)
    monkeypatch.setattr(survey, "RULES", rules)


def _survey_rows(tmp_path: Path, survey: ModuleType) -> list[dict[str, object]]:
    result = scan(tmp_path)
    rows: list[dict[str, object]] = survey.rows(
        "o/r", "abc", tmp_path, result, survey.secret_rule()
    )
    return rows


def test_rows_carry_the_line_excerpt(
    tmp_path: Path, survey: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    long_line = "  run this now " + "x" * 300
    _install(
        monkeypatch, survey, _LineFinder("ABOM-009", "run this"), _LineFinder("ABOM-010", "ghp_")
    )
    write_tree(tmp_path, {"AGENTS.md": f"intro\r\n{long_line}\r\n"})
    (row,) = _survey_rows(tmp_path, survey)
    assert row == {
        "repo": "o/r",
        "sha": "abc",
        "rule_id": "ABOM-009",
        "severity": "medium",
        "confidence": "low",
        "path": "AGENTS.md",
        "line": 2,
        "message": "found run this",
        "excerpt": long_line.strip()[:200],
    }


def test_a_line_with_a_secret_is_redacted(
    tmp_path: Path, survey: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install(
        monkeypatch, survey, _LineFinder("ABOM-009", "run this"), _LineFinder("ABOM-010", "ghp_")
    )
    write_tree(tmp_path, {"AGENTS.md": f"run this with {FAKE_TOKEN}\n"})
    rows = _survey_rows(tmp_path, survey)
    assert {row["rule_id"]: row["excerpt"] for row in rows} == {
        "ABOM-009": "<redacted>",
        "ABOM-010": "<redacted>",
    }
    assert FAKE_TOKEN not in repr(rows)


def test_excerpts_are_left_out_without_abom_010(
    tmp_path: Path, survey: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install(monkeypatch, survey, _LineFinder("ABOM-009", "run this"))
    write_tree(tmp_path, {"AGENTS.md": f"run this with {FAKE_TOKEN}\n"})
    (row,) = _survey_rows(tmp_path, survey)
    assert row["excerpt"] is None


def test_findings_without_a_line_have_no_excerpt(tmp_path: Path, survey: ModuleType) -> None:
    write_tree(tmp_path, {".mcp.json": {"mcpServers": {"s": {"command": "npx", "args": ["p"]}}}})
    (row,) = _survey_rows(tmp_path, survey)
    assert (row["rule_id"], row["line"], row["excerpt"]) == ("ABOM-005", None, None)
