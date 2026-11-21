"""List the findings of a survey to review by hand, with a link to each at its pinned commit.

Usage: uv run python scripts/triage_queue.py RESULTS.jsonl OUT.jsonl [--sample N] [--seed N]

Every finding of a rule that can warrant a private notice is queued. Rules that flag
hygiene rather than a vulnerability are sampled, N per rule, to estimate their precision.
"""

import argparse
import random
from pathlib import Path

from _survey_records import FindingRow, Scanned, read_records
from pydantic import BaseModel, ConfigDict

from agentbom.models import RuleId

# Hidden text, remote code execution, credential reads, exfiltration, instruction
# overrides and embedded secrets can hurt a project's users, so a true one gets a notice.
NOTICE_RULES: frozenset[RuleId] = frozenset(
    {"ABOM-001", "ABOM-002", "ABOM-003", "ABOM-004", "ABOM-009", "ABOM-010"}
)


class QueueItem(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    repo: str
    sha: str
    rule_id: RuleId
    severity: str
    path: str
    line: int | None
    message: str
    excerpt: str | None
    url: str
    reason: str


def _item(record: Scanned, row: FindingRow, reason: str) -> QueueItem:
    anchor = f"#L{row.line}" if row.line else ""
    return QueueItem(
        repo=record.repo,
        sha=record.sha,
        rule_id=row.rule_id,
        severity=row.severity,
        path=row.path,
        line=row.line,
        message=row.message,
        excerpt=row.excerpt,
        url=f"https://github.com/{record.repo}/blob/{record.sha}/{row.path}{anchor}",
        reason=reason,
    )


def queue(records: list[Scanned], per_rule: int, seed: int) -> list[QueueItem]:
    pairs = sorted(
        ((record, row) for record in records for row in record.findings),
        key=lambda pair: (pair[0].repo, pair[1].rule_id, pair[1].path, pair[1].line or 0),
    )
    items = [
        _item(record, row, "notice rule") for record, row in pairs if row.rule_id in NOTICE_RULES
    ]
    rng = random.Random(seed)
    for rule in sorted({row.rule_id for _, row in pairs} - NOTICE_RULES):
        members = [pair for pair in pairs if pair[1].rule_id == rule]
        picked = rng.sample(members, min(per_rule, len(members)))
        reason = f"precision sample {len(picked)} of {len(members)}"
        items += [_item(record, row, reason) for record, row in picked]
    return items


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("results", type=Path)
    parser.add_argument("out", type=Path)
    parser.add_argument("--sample", type=int, default=30)
    parser.add_argument("--seed", type=int, default=20261222)
    args = parser.parse_args()
    records = [r for r in read_records(args.results).values() if isinstance(r, Scanned)]
    items = queue(records, args.sample, args.seed)
    args.out.write_text("".join(item.model_dump_json() + "\n" for item in items), encoding="utf-8")
    print(f"{len(items)} findings to review in {args.out}")


if __name__ == "__main__":
    main()
