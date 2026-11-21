"""Scan a pinned list of public repositories: the week-2 review and the week-5 mass scan.

Usage: uv run python scripts/survey.py REPOS.json [--out DIR] [--delete]

REPOS.json is a list of {"repo": "owner/name", "sha": "<commit>"}; other keys are ignored.
Each repository is checked out under DIR/owner__name/ (default .survey/) and scanned, never
run. DIR/results.jsonl gains one line per repository with its artifact counts, scan errors
and findings, each with an excerpt of the matched line for local review only. A rerun skips
repositories already scanned at the same commit, so a stopped survey resumes where it was.
"""

import argparse
import codecs
import json
import subprocess
import time
from collections import Counter
from pathlib import Path

from _checkout import checkout_path, ensure_checkout, remove_checkout
from _survey_records import CheckoutFailed, FindingRow, Scanned, append_record, read_records

from agentbom.models import Finding, Location, ScanResult, Script
from agentbom.rules import RULES, Rule
from agentbom.scan import scan

ROOT = Path(__file__).resolve().parent.parent
EXCERPT_CHARS = 200
REDACTED = "<redacted>"


def secret_rule() -> Rule | None:
    return next((rule for rule in RULES if rule.rule_id == "ABOM-010"), None)


def excerpt(checkout: Path, finding: Finding, secrets: Rule | None) -> str | None:
    """The finding's source line, or None when the finding has no line or secrets are unchecked."""
    if finding.location.line is None or secrets is None:
        return None
    try:
        data = (checkout / finding.location.path).read_bytes()
    except OSError:
        return None
    text = (
        data.removeprefix(codecs.BOM_UTF8)
        .decode("utf-8", errors="replace")
        .replace("\r\n", "\n")
        .replace("\r", "\n")
    )
    lines = text.split("\n")
    if finding.location.line > len(lines):
        return None
    line = lines[finding.location.line - 1].strip()[:EXCERPT_CHARS]
    # Scanned as a script so every ABOM-010 pattern applies; any hit hides the whole line.
    probe = Script(
        name="excerpt", source=Location(path="excerpt"), agents=(), language="shell", body=line
    )
    return REDACTED if any(secrets.run([probe])) else line


def _checkout_error(error: BaseException) -> str:
    if isinstance(error, subprocess.CalledProcessError):
        lines = (error.stderr or "").strip().splitlines()
        return lines[-1] if lines else f"git exited with {error.returncode}"
    if isinstance(error, subprocess.TimeoutExpired):
        return f"git timed out after {error.timeout:.0f} s"
    return str(error)


def rows(checkout: Path, result: ScanResult, secrets: Rule | None) -> tuple[FindingRow, ...]:
    return tuple(
        FindingRow(
            rule_id=finding.rule_id,
            severity=finding.severity,
            confidence=finding.confidence,
            path=finding.location.path,
            line=finding.location.line,
            message=finding.message,
            excerpt=excerpt(checkout, finding, secrets),
        )
        for finding in result.findings
    )


def survey_one(
    repo: str, sha: str, out: Path, *, delete: bool, secrets: Rule | None, url: str | None = None
) -> Scanned | CheckoutFailed:
    started = time.monotonic()
    try:
        checkout = ensure_checkout(repo, sha, out, url)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, SystemExit) as error:
        if delete and checkout_path(repo, out).exists():
            remove_checkout(checkout_path(repo, out))
        return CheckoutFailed(repo=repo, sha=sha, error=_checkout_error(error))
    result = scan(checkout)
    record = Scanned(
        repo=repo,
        sha=sha,
        seconds=round(time.monotonic() - started, 1),
        artifacts=dict(Counter(artifact.kind for artifact in result.artifacts)),
        scan_errors=len(result.errors),
        findings=rows(checkout, result, secrets),
    )
    if delete:
        remove_checkout(checkout)
    return record


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("repos", type=Path, help="JSON list of {repo, sha}")
    parser.add_argument("--out", type=Path, default=ROOT / ".survey", help="checkouts and results")
    parser.add_argument("--delete", action="store_true", help="delete each checkout once scanned")
    args = parser.parse_args()
    entries = [(e["repo"], e["sha"]) for e in json.loads(args.repos.read_text(encoding="utf-8"))]
    args.out.mkdir(parents=True, exist_ok=True)
    results = args.out / "results.jsonl"
    done = read_records(results)
    secrets = secret_rule()
    if secrets is None:
        print("ABOM-010 is not registered, so excerpts are left out.")
    for index, (repo, sha) in enumerate(entries, start=1):
        previous = done.get(repo)
        if isinstance(previous, Scanned) and previous.sha == sha:
            continue
        record = survey_one(repo, sha, args.out, delete=args.delete, secrets=secrets)
        append_record(results, record)
        done[repo] = record
        outcome = (
            f"{len(record.findings)} findings in {record.seconds} s"
            if isinstance(record, Scanned)
            else f"checkout failed: {record.error}"
        )
        print(f"[{index}/{len(entries)}] {repo}: {outcome}", flush=True)
    current = [done[repo] for repo, _ in entries if repo in done]
    scanned = [record for record in current if isinstance(record, Scanned)]
    failed = [record for record in current if isinstance(record, CheckoutFailed)]
    rules = Counter(row.rule_id for record in scanned for row in record.findings)
    print(f"\n{sum(rules.values())} findings in {len(scanned)} repositories")
    for rule_id, count in sorted(rules.items()):
        print(f"  {rule_id}: {count}")
    for record in scanned:
        if record.scan_errors:
            print(f"  {record.repo}: {record.scan_errors} scan errors")
    for record in failed:
        print(f"Checkout failed: {record.repo}: {record.error}")


if __name__ == "__main__":
    main()
