from pathlib import Path
from typing import get_args

import pytest

from agentbom.lockfile import LOCKFILE_NAME, parse_lock
from agentbom.models import RuleId
from agentbom.scan import scan

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
KINDS = ("malicious", "benign")
MINIMUM_CASES = 3

CASES = sorted(
    case for case in FIXTURES.glob("*/*/*") if case.is_dir() and case.parent.name in KINDS
)


@pytest.mark.parametrize(
    "case", CASES, ids=[case.relative_to(FIXTURES).as_posix() for case in CASES]
)
def test_fixture_case(case: Path) -> None:
    rule_id, kind = case.parent.parent.name, case.parent.name
    lock_file = case / LOCKFILE_NAME
    lock = parse_lock(lock_file.read_text(encoding="utf-8")) if lock_file.is_file() else None
    assert (lock is not None) == (rule_id == "ABOM-006"), "only drift cases carry a lockfile"
    result = scan(case, lock)
    assert result.errors == ()
    flagged = [f.message for f in result.findings if f.rule_id == rule_id]
    if kind == "malicious":
        assert flagged, f"{rule_id} missed this case"
    else:
        assert flagged == [], f"{rule_id} flagged a benign case"


def test_fixture_layout_is_rule_kind_case() -> None:
    known = set(get_args(RuleId))
    unexpected = [
        path.relative_to(FIXTURES).as_posix()
        for path in FIXTURES.glob("*/*/*")
        if not path.is_dir()
        or path.parent.name not in KINDS
        or path.parent.parent.name not in known
    ]
    unexpected += [
        path.relative_to(FIXTURES).as_posix()
        for path in [*FIXTURES.glob("*"), *FIXTURES.glob("*/*")]
        if not path.is_dir()
    ]
    assert unexpected == []


def test_every_rule_has_enough_fixtures() -> None:
    gaps = [
        f"{rule_id} has {count} {kind} case(s)"
        for rule_id in get_args(RuleId)
        for kind in KINDS
        if (count := len([c for c in CASES if c.parts[-3:-1] == (rule_id, kind)])) < MINIMUM_CASES
    ]
    assert gaps == []
