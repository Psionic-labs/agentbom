"""Aggregate a survey's results into the Markdown tables of the scan report.

Usage: uv run python scripts/survey_stats.py REPOS.json RESULTS.jsonl [--triage TRIAGE.jsonl]

Prints counts only, never a repository name, a path or an excerpt, so the output can go
into a published report. TRIAGE.jsonl holds one hand verdict per finding:
{"repo", "rule_id", "path", "line", "verdict": "true_positive" | "false_positive"}.
"""

import argparse
import json
from collections import Counter
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Literal

from _survey_records import CheckoutFailed, FindingRow, Scanned, read_records
from pydantic import BaseModel, ConfigDict, TypeAdapter

from agentbom.models import ArtifactKind, RuleId

KINDS: tuple[ArtifactKind, ...] = ("mcp_server", "skill", "hook", "rules", "script", "settings")
Verdict = Literal["true_positive", "false_positive"]


class TriageEntry(BaseModel):
    model_config = ConfigDict(frozen=True, extra="ignore")

    repo: str
    rule_id: RuleId
    path: str
    line: int | None
    verdict: Verdict


FindingKey = tuple[str, str, str, int | None]


def _key(repo: str, row: FindingRow) -> FindingKey:
    return (repo, row.rule_id, row.path, row.line)


def _pct(part: int, whole: int) -> str:
    return f"{100 * part / whole:.1f}%" if whole else "n/a"


def _table(header: Sequence[str], rows: Iterable[Sequence[object]]) -> str:
    lines = ["| " + " | ".join(header) + " |", "|" + " --- |" * len(header)]
    lines += ["| " + " | ".join(str(cell) for cell in row) + " |" for row in rows]
    return "\n".join(lines)


def report(
    selected: Sequence[str],
    records: dict[str, Scanned | CheckoutFailed],
    verdicts: dict[FindingKey, Verdict],
) -> str:
    current = [records[repo] for repo in selected if repo in records]
    scanned = [r for r in current if isinstance(r, Scanned)]
    failed = [r for r in current if isinstance(r, CheckoutFailed)]
    total = len(scanned)
    sections = [
        "## Sample",
        _table(
            ("Measure", "Repositories"),
            [
                ("Selected", len(selected)),
                ("Scanned", total),
                ("Checkout failed", len(failed)),
                ("Not yet scanned", len(selected) - len(current)),
                ("Scanned with at least one scan error", sum(r.scan_errors > 0 for r in scanned)),
                ("No agent artifact found", sum(not r.artifacts for r in scanned)),
            ],
        ),
        "## Agent context found",
        _table(
            ("Kind", "Repositories with one", "Share of scanned", "Artifacts"),
            [
                (
                    kind,
                    sum(r.artifacts.get(kind, 0) > 0 for r in scanned),
                    _pct(sum(r.artifacts.get(kind, 0) > 0 for r in scanned), total),
                    sum(r.artifacts.get(kind, 0) for r in scanned),
                )
                for kind in KINDS
            ],
        ),
    ]
    findings = Counter(row.rule_id for r in scanned for row in r.findings)
    repos_hit = Counter(rule for r in scanned for rule in {row.rule_id for row in r.findings})
    severity = Counter((row.rule_id, row.severity) for r in scanned for row in r.findings)
    triaged = Counter(
        (row.rule_id, verdicts[_key(r.repo, row)])
        for r in scanned
        for row in r.findings
        if _key(r.repo, row) in verdicts
    )
    rule_rows = []
    for rule in sorted(findings):
        true, false = triaged[(rule, "true_positive")], triaged[(rule, "false_positive")]
        rule_rows.append(
            (
                rule,
                findings[rule],
                severity[(rule, "high")],
                severity[(rule, "medium")],
                severity[(rule, "low")],
                repos_hit[rule],
                _pct(repos_hit[rule], total),
                true + false,
                _pct(true, true + false),
            )
        )
    sections += [
        "## Findings by rule",
        _table(
            (
                "Rule",
                "Findings",
                "High",
                "Medium",
                "Low",
                "Repositories",
                "Share of scanned",
                "Triaged",
                "Precision",
            ),
            rule_rows,
        ),
    ]
    with_any = sum(bool(r.findings) for r in scanned)
    with_high = sum(any(row.severity == "high" for row in r.findings) for r in scanned)
    sections += [
        "## Repositories with findings",
        _table(
            ("Measure", "Repositories", "Share of scanned"),
            [
                ("Any finding", with_any, _pct(with_any, total)),
                ("A high finding", with_high, _pct(with_high, total)),
            ],
        ),
    ]
    return "\n\n".join(sections) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("repos", type=Path)
    parser.add_argument("results", type=Path)
    parser.add_argument("--triage", type=Path)
    args = parser.parse_args()
    selected = [str(e["repo"]) for e in json.loads(args.repos.read_text(encoding="utf-8"))]
    verdicts: dict[FindingKey, Verdict] = {}
    if args.triage:
        adapter = TypeAdapter(TriageEntry)
        for line in args.triage.read_text(encoding="utf-8").splitlines():
            if line.strip():
                entry = adapter.validate_json(line)
                verdicts[(entry.repo, entry.rule_id, entry.path, entry.line)] = entry.verdict
    print(report(selected, read_records(args.results), verdicts), end="")


if __name__ == "__main__":
    main()
