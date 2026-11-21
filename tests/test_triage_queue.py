from _survey_records import FindingRow, Scanned
from triage_queue import queue


def _row(rule: str, line: int) -> FindingRow:
    return FindingRow.model_validate(
        {
            "rule_id": rule,
            "severity": "high",
            "confidence": "high",
            "path": ".claude/settings.json",
            "line": line,
            "message": "m",
            "excerpt": None,
        }
    )


def _scanned(repo: str, *rows: FindingRow) -> Scanned:
    return Scanned.model_validate(
        {
            "repo": repo,
            "sha": "c" * 40,
            "seconds": 1.0,
            "artifacts": {},
            "scan_errors": 0,
            "findings": rows,
        }
    )


def test_notice_rules_are_all_queued_and_hygiene_rules_are_sampled() -> None:
    records = [
        _scanned("o/a", _row("ABOM-010", 3), *(_row("ABOM-005", n) for n in range(1, 11))),
        _scanned("o/b", _row("ABOM-009", 1), _row("ABOM-008", 2)),
    ]

    items = queue(records, per_rule=4, seed=1)

    by_rule = {rule: [i for i in items if i.rule_id == rule] for rule in {i.rule_id for i in items}}
    assert len(by_rule["ABOM-010"]) == len(by_rule["ABOM-009"]) == 1
    assert len(by_rule["ABOM-005"]) == 4
    assert by_rule["ABOM-005"][0].reason == "precision sample 4 of 10"
    assert len(by_rule["ABOM-008"]) == 1
    assert by_rule["ABOM-010"][0].url == (
        f"https://github.com/o/a/blob/{'c' * 40}/.claude/settings.json#L3"
    )
    assert queue(list(reversed(records)), per_rule=4, seed=1) == items
