"""Pick public repositories that use agent config files, for the week-5 mass scan.

Usage:
  uv run python scripts/select_repos.py collect OUT_DIR [--pages N]
  uv run python scripts/select_repos.py sample OUT_DIR [--seed N] [--per-group N]

`collect` runs GitHub code search through `gh` for each group's file patterns, then looks
up every repository found: stars, size, fork and archive status, last push, and the commit
its default branch points at. It writes OUT_DIR/candidates.json.

`sample` keeps eligible candidates and draws up to --per-group repositories from each group
with a seeded shuffle, so the same candidates and seed always give the same list. It writes
OUT_DIR/repos.json for scripts/survey.py and OUT_DIR/selection.json with the method.
"""

import argparse
import json
import random
import subprocess
import time
from collections.abc import Iterable, Sequence
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, TypeAdapter

ROOT = Path(__file__).resolve().parent.parent
WEEK2_REPOS = ROOT / "scripts" / "survey_repos.json"
OWN_ORG = "Psionic-labs"

Group = Literal["mcp", "skills", "hooks", "rules"]
QUERIES: dict[Group, tuple[str, ...]] = {
    "mcp": (
        "filename:.mcp.json",
        "filename:mcp.json path:.cursor",
        "filename:mcp.json path:.vscode",
    ),
    "skills": (
        "filename:SKILL.md path:.claude/skills",
        "filename:SKILL.md path:.agents/skills",
    ),
    "hooks": (
        "filename:settings.json path:.claude hooks",
        "filename:hooks.json path:.cursor",
        "filename:hooks.json path:.codex",
    ),
    "rules": (
        "filename:CLAUDE.md",
        "filename:AGENTS.md",
        "extension:mdc path:.cursor/rules",
        "filename:copilot-instructions.md path:.github",
    ),
}
# Code search returns at most 1,000 results per query, in best-match order. Slicing by file
# size spreads the results across many more repositories than the first pages of one query.
SIZE_SLICES = ("size:<300", "size:300..1500", "size:1500..6000", "size:>6000")
SEARCH_INTERVAL_SECONDS = 6.5
LOOKUP_BATCH = 50
MIN_STARS = 10
MAX_SIZE_KB = 100_000
MAX_DAYS_SINCE_PUSH = 365


class Candidate(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    repo: str
    groups: tuple[Group, ...]
    stars: int
    size_kb: int
    fork: bool
    archived: bool
    pushed_at: datetime | None
    sha: str | None


class Candidates(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    collected_on: date
    queries: dict[Group, tuple[str, ...]]
    size_slices: tuple[str, ...]
    pages: int
    search_hits: int
    incomplete_searches: int
    candidates: tuple[Candidate, ...]


class Selected(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    repo: str
    sha: str
    group: Group
    why: tuple[Group, ...]
    stars: int
    size_kb: int


def _gh(*args: str) -> str:
    """Run `gh`, waiting out rate limits for up to five minutes."""
    for _ in range(5):
        run = subprocess.run(["gh", *args], capture_output=True, encoding="utf-8", check=False)
        if run.returncode == 0:
            return run.stdout
        if "rate limit" not in run.stderr.lower():
            break
        time.sleep(60)
    raise SystemExit(f"gh {' '.join(args[:3])} failed: {run.stderr.strip()}")


def _search(query: str, page: int) -> tuple[list[str], bool]:
    fields = {"q": query, "per_page": "100", "page": str(page)}
    flags = [part for key, value in fields.items() for part in ("-f", f"{key}={value}")]
    reply = json.loads(_gh("api", "-X", "GET", "search/code", *flags))
    repos = [item["repository"]["full_name"] for item in reply["items"]]
    return repos, bool(reply["incomplete_results"])


class _Branch(BaseModel):
    target: dict[str, str] | None


class _RepoInfo(BaseModel):
    nameWithOwner: str
    stargazerCount: int
    diskUsage: int | None
    isFork: bool
    isArchived: bool
    pushedAt: datetime | None
    defaultBranchRef: _Branch | None


_LOOKUP = TypeAdapter(dict[str, _RepoInfo | None])
_LOOKUP_FIELDS = (
    "nameWithOwner stargazerCount diskUsage isFork isArchived pushedAt "
    "defaultBranchRef { target { oid } }"
)


def _lookup(repos: Sequence[str]) -> dict[str, _RepoInfo]:
    """Repository details by searched name; deleted or private repositories are left out."""
    fields = []
    for index, repo in enumerate(repos):
        owner, name = repo.split("/", 1)
        fields.append(
            f"r{index}: repository(owner: {json.dumps(owner)}, name: {json.dumps(name)}) "
            f"{{ {_LOOKUP_FIELDS} }}"
        )
    run = subprocess.run(
        ["gh", "api", "graphql", "-f", "query=query { " + " ".join(fields) + " }"],
        capture_output=True,
        encoding="utf-8",
        check=False,
    )
    # A missing repository makes gh exit non-zero, but the reply still carries the others.
    data = json.loads(run.stdout or "{}").get("data")
    if data is None:
        raise SystemExit(f"GraphQL lookup failed: {run.stderr.strip()}")
    found = _LOOKUP.validate_python(data)
    return {repos[int(alias[1:])]: info for alias, info in found.items() if info is not None}


def _candidate(info: _RepoInfo, groups: set[Group]) -> Candidate:
    target = info.defaultBranchRef.target if info.defaultBranchRef else None
    return Candidate(
        repo=info.nameWithOwner,
        groups=tuple(sorted(groups)),
        stars=info.stargazerCount,
        size_kb=info.diskUsage or 0,
        fork=info.isFork,
        archived=info.isArchived,
        pushed_at=info.pushedAt,
        sha=target.get("oid") if target else None,
    )


def collect(pages: int) -> Candidates:
    groups: dict[str, set[Group]] = {}
    hits = incomplete = 0
    for group, queries in QUERIES.items():
        for query in queries:
            for size in SIZE_SLICES:
                for page in range(1, pages + 1):
                    repos, partial = _search(f"{query} {size}", page)
                    print(f"{group}: {query} {size} page {page}: {len(repos)}", flush=True)
                    hits += len(repos)
                    incomplete += partial
                    for repo in repos:
                        groups.setdefault(repo, set()).add(group)
                    time.sleep(SEARCH_INTERVAL_SECONDS)
                    if len(repos) < 100:
                        break
    names = sorted(groups)
    found: dict[str, _RepoInfo] = {}
    for start in range(0, len(names), LOOKUP_BATCH):
        found |= _lookup(names[start : start + LOOKUP_BATCH])
    merged: dict[str, Candidate] = {}
    for name, info in found.items():
        prior = merged.get(info.nameWithOwner)
        both = groups[name] | set(prior.groups if prior else ())
        merged[info.nameWithOwner] = _candidate(info, both)
    return Candidates(
        collected_on=datetime.now(UTC).date(),
        queries=QUERIES,
        size_slices=SIZE_SLICES,
        pages=pages,
        search_hits=hits,
        incomplete_searches=incomplete,
        candidates=tuple(merged[repo] for repo in sorted(merged)),
    )


def eligible(candidate: Candidate, collected_on: date, excluded: set[str]) -> bool:
    return (
        candidate.sha is not None
        and not candidate.fork
        and not candidate.archived
        and candidate.stars >= MIN_STARS
        and 0 < candidate.size_kb <= MAX_SIZE_KB
        and candidate.pushed_at is not None
        and candidate.pushed_at.date() >= collected_on - timedelta(days=MAX_DAYS_SINCE_PUSH)
        and candidate.repo.lower() not in excluded
        and candidate.repo.split("/", 1)[0].lower() != OWN_ORG.lower()
    )


def sample(
    candidates: Iterable[Candidate], per_group: int, seed: int
) -> tuple[list[Selected], dict[Group, int]]:
    """Up to `per_group` repositories per group; a repository is drawn for at most one group."""
    rng = random.Random(seed)
    pool = sorted(candidates, key=lambda candidate: candidate.repo.lower())
    taken: set[str] = set()
    selected: list[Selected] = []
    shortfall: dict[Group, int] = {}
    for group in QUERIES:
        members = [c for c in pool if group in c.groups]
        rng.shuffle(members)
        fresh = [c for c in members if c.repo not in taken][:per_group]
        if len(fresh) < per_group:
            shortfall[group] = per_group - len(fresh)
        for c in fresh:
            taken.add(c.repo)
            assert c.sha is not None
            selected.append(
                Selected(
                    repo=c.repo,
                    sha=c.sha,
                    group=group,
                    why=c.groups,
                    stars=c.stars,
                    size_kb=c.size_kb,
                )
            )
    return sorted(selected, key=lambda s: s.repo.lower()), shortfall


def _excluded() -> set[str]:
    week2 = json.loads(WEEK2_REPOS.read_text(encoding="utf-8"))
    return {str(entry["repo"]).lower() for entry in week2}


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=1, sort_keys=True) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    collect_command = commands.add_parser("collect")
    collect_command.add_argument("out", type=Path)
    collect_command.add_argument("--pages", type=int, default=2)
    sample_command = commands.add_parser("sample")
    sample_command.add_argument("out", type=Path)
    sample_command.add_argument("--seed", type=int, default=20261222)
    sample_command.add_argument("--per-group", type=int, default=125)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    if args.command == "collect":
        result = collect(args.pages)
        (args.out / "candidates.json").write_text(
            result.model_dump_json(indent=1) + "\n", encoding="utf-8"
        )
        print(f"{len(result.candidates)} candidate repositories from {result.search_hits} hits")
        return
    found = TypeAdapter(Candidates).validate_json(
        (args.out / "candidates.json").read_text(encoding="utf-8")
    )
    excluded = _excluded()
    pool = [c for c in found.candidates if eligible(c, found.collected_on, excluded)]
    selected, shortfall = sample(pool, args.per_group, args.seed)
    _write_json(args.out / "repos.json", [s.model_dump(mode="json") for s in selected])
    _write_json(
        args.out / "selection.json",
        {
            "collected_on": found.collected_on.isoformat(),
            "queries": found.queries,
            "size_slices": found.size_slices,
            "pages": found.pages,
            "search_hits": found.search_hits,
            "incomplete_searches": found.incomplete_searches,
            "candidates": len(found.candidates),
            "eligible": len(pool),
            "eligible_by_group": {g: sum(g in c.groups for c in pool) for g in QUERIES},
            "criteria": {
                "min_stars": MIN_STARS,
                "max_size_kb": MAX_SIZE_KB,
                "max_days_since_push": MAX_DAYS_SINCE_PUSH,
                "forks": False,
                "archived": False,
                "excluded": f"the {len(excluded)} week-2 survey repositories and {OWN_ORG}",
            },
            "seed": args.seed,
            "per_group": args.per_group,
            "selected": len(selected),
            "selected_by_group": {g: sum(s.group == g for s in selected) for g in QUERIES},
            "shortfall": shortfall,
        },
    )
    print(f"{len(selected)} of {len(pool)} eligible repositories; shortfall {shortfall or 'none'}")


if __name__ == "__main__":
    main()
