from datetime import UTC, date, datetime, timedelta

import pytest
from select_repos import Candidate, Group, eligible, sample

COLLECTED = date(2026, 11, 22)


def _candidate(repo: str, *groups: Group, **changes: object) -> Candidate:
    fields: dict[str, object] = {
        "repo": repo,
        "groups": groups,
        "stars": 50,
        "size_kb": 2_000,
        "fork": False,
        "archived": False,
        "pushed_at": datetime(2026, 11, 1, tzinfo=UTC),
        "sha": "a" * 40,
    }
    return Candidate.model_validate(fields | changes)


def test_an_active_original_repository_is_eligible() -> None:
    assert eligible(_candidate("owner/repo", "mcp"), COLLECTED, excluded=set())


@pytest.mark.parametrize(
    "changes",
    [
        {"fork": True},
        {"archived": True},
        {"stars": 9},
        {"size_kb": 100_001},
        {"size_kb": 0},
        {"sha": None},
        {"pushed_at": None},
        {"pushed_at": datetime(2026, 11, 22, tzinfo=UTC) - timedelta(days=366)},
    ],
)
def test_ineligible_repositories(changes: dict[str, object]) -> None:
    assert not eligible(_candidate("owner/repo", "mcp", **changes), COLLECTED, excluded=set())


def test_excluded_repositories_and_our_own_organization_are_skipped() -> None:
    excluded = {"week2/repo"}
    assert not eligible(_candidate("Week2/Repo", "rules"), COLLECTED, excluded)
    assert not eligible(_candidate("psionic-labs/vigil", "rules"), COLLECTED, set())


def test_sample_is_reproducible_and_draws_each_repository_once() -> None:
    pool = [_candidate(f"o/both-{n}", "mcp", "rules") for n in range(6)]
    pool += [_candidate(f"o/rules-{n}", "rules") for n in range(6)]

    first, shortfall = sample(pool, per_group=4, seed=7)
    again, _ = sample(list(reversed(pool)), per_group=4, seed=7)

    assert first == again
    assert len({s.repo for s in first}) == len(first) == 8
    assert sum(s.group == "mcp" for s in first) == 4
    assert sum(s.group == "rules" for s in first) == 4
    assert all("mcp" in s.why for s in first if s.group == "mcp")
    assert shortfall == {"skills": 4, "hooks": 4}


def test_a_different_seed_draws_a_different_sample() -> None:
    pool = [_candidate(f"o/r-{n}", "skills") for n in range(30)]
    assert sample(pool, 5, seed=1)[0] != sample(pool, 5, seed=2)[0]
