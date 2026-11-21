from _survey_records import CheckoutFailed, FindingRow, Scanned
from survey_stats import FindingKey, Verdict, report


def _row(rule: str, severity: str, line: int) -> FindingRow:
    return FindingRow.model_validate(
        {
            "rule_id": rule,
            "severity": severity,
            "confidence": "high",
            "path": "AGENTS.md",
            "line": line,
            "message": "m",
            "excerpt": "secret-looking excerpt",
        }
    )


def _scanned(repo: str, artifacts: dict[str, int], *rows: FindingRow) -> Scanned:
    return Scanned.model_validate(
        {
            "repo": repo,
            "sha": "a" * 40,
            "seconds": 1.0,
            "artifacts": artifacts,
            "scan_errors": 0,
            "findings": rows,
        }
    )


def test_report_counts_repositories_findings_and_precision_without_names() -> None:
    records: dict[str, Scanned | CheckoutFailed] = {
        "o/a": _scanned(
            "o/a",
            {"rules": 2, "mcp_server": 1},
            _row("ABOM-009", "high", 1),
            _row("ABOM-009", "high", 2),
        ),
        "o/b": _scanned("o/b", {"rules": 1}),
        "o/c": CheckoutFailed(repo="o/c", sha="b" * 40, error="gone"),
        "o/old": _scanned("o/old", {"rules": 1}, _row("ABOM-010", "high", 1)),
    }
    verdicts: dict[FindingKey, Verdict] = {
        ("o/a", "ABOM-009", "AGENTS.md", 1): "true_positive",
        ("o/a", "ABOM-009", "AGENTS.md", 2): "false_positive",
    }

    text = report(["o/a", "o/b", "o/c", "o/d"], records, verdicts)

    assert "| Scanned | 2 |" in text
    assert "| Checkout failed | 1 |" in text
    assert "| Not yet scanned | 1 |" in text
    assert "| rules | 2 | 100.0% | 3 |" in text
    assert "| mcp_server | 1 | 50.0% | 1 |" in text
    assert "| ABOM-009 | 2 | 2 | 0 | 0 | 1 | 50.0% | 2 | 50.0% |" in text
    assert "ABOM-010" not in text
    assert "| A high finding | 1 | 50.0% |" in text
    for leak in ("o/a", "AGENTS.md", "secret-looking"):
        assert leak not in text
