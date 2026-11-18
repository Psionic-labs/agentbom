"""Scan a list of public repositories for the week-2 hand review.

Usage: uv run python scripts/survey.py scripts/survey_repos.json

repos.json is a list of {"repo": "owner/name", "sha": "<commit>"}. Each repository is
checked out under .survey/owner__name/ and every finding is written to
.survey/results.jsonl with an excerpt of the matched line for local review only.
"""

import argparse
import codecs
import json
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any

from _checkout import ensure_checkout

from agentbom.models import Finding, Location, ScanResult, Script
from agentbom.rules import RULES, Rule
from agentbom.scan import scan

ROOT = Path(__file__).resolve().parent.parent
SURVEY = ROOT / ".survey"
EXCERPT_CHARS = 200
REDACTED = "<redacted>"


def secret_rule() -> Rule | None:
    return next((rule for rule in RULES if rule.rule_id == "ABOM-010"), None)


def excerpt(checkout: Path, finding: Finding, secrets: Rule | None) -> str | None:
    """The finding's source line, or None when the finding has no line or secrets are unchecked."""
    if finding.location.line is None or secrets is None:
        return None
    data = (checkout / finding.location.path).read_bytes()
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


def rows(
    repo: str, sha: str, checkout: Path, result: ScanResult, secrets: Rule | None
) -> list[dict[str, Any]]:
    return [
        {
            "repo": repo,
            "sha": sha,
            "rule_id": finding.rule_id,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "path": finding.location.path,
            "line": finding.location.line,
            "message": finding.message,
            "excerpt": excerpt(checkout, finding, secrets),
        }
        for finding in result.findings
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("repos", type=Path, help="JSON list of {repo, sha}")
    entries = json.loads(parser.parse_args().repos.read_text(encoding="utf-8"))
    secrets = secret_rule()
    if secrets is None:
        print("ABOM-010 is not registered, so excerpts are left out.")
    results: list[dict[str, Any]] = []
    scan_errors: dict[str, int] = {}
    failed: list[str] = []
    for entry in entries:
        repo, sha = entry["repo"], entry["sha"]
        try:
            checkout = ensure_checkout(repo, sha, SURVEY)
        except (subprocess.CalledProcessError, SystemExit) as error:
            print(f"{repo}: checkout failed: {error}")
            failed.append(repo)
            continue
        result = scan(checkout)
        scan_errors[repo] = len(result.errors)
        results.extend(rows(repo, sha, checkout, result, secrets))
    SURVEY.mkdir(exist_ok=True)
    with (SURVEY / "results.jsonl").open("w", encoding="utf-8", newline="\n") as out:
        for row in results:
            out.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    print(f"\n{len(results)} findings in {len(scan_errors)} repositories")
    for rule_id, count in sorted(Counter(row["rule_id"] for row in results).items()):
        print(f"  {rule_id}: {count}")
    print("Scan errors per repository:")
    for repo, count in sorted(scan_errors.items()):
        print(f"  {repo}: {count}")
    if failed:
        print(f"Checkout failed: {', '.join(failed)}")


if __name__ == "__main__":
    main()
