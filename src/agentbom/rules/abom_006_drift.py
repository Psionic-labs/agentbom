"""ABOM-006: an artifact whose definition differs from agentbom.lock.

Unlike the rules in RULES, drift needs the lockfile, so it reads the drift that
`diff_lock` computed instead of the artifacts.
"""

from collections.abc import Iterator, Sequence

from agentbom.lockfile import LOCKFILE_NAME
from agentbom.models import Drift, DriftKind, Finding, RuleId

RULE_ID: RuleId = "ABOM-006"
_FIX = f"Review the change, then run `agentbom lock` to record it in {LOCKFILE_NAME}."
_NOUNS: dict[DriftKind, str] = {
    "mcp_server": "MCP server",
    "hook": "hook",
    "skill": "skill",
    "rules": "rules file",
    "script": "script",
    "settings": "settings file",
    "file": "file",
}


def drift_findings(drift: Sequence[Drift]) -> Iterator[Finding]:
    # A changed file is its own finding only when no artifact in it drifted; the diff
    # still lists it, so a change the artifacts do not show stays visible.
    reported = {item.location.path for item in drift if item.kind != "file"}
    for item in drift:
        if item.kind == "file" and item.location.path in reported:
            continue
        yield Finding(
            rule_id=RULE_ID,
            severity="high",
            confidence="high",
            message=_message(item),
            location=item.location,
            artifact_id=item.artifact_id,
            fix=_FIX,
        )


def _message(item: Drift) -> str:
    subject = f'{_NOUNS[item.kind]} "{item.name}"'
    match item.change:
        case "added":
            return f"{subject} is not in {LOCKFILE_NAME}"
        case "removed":
            return f"{subject} is in {LOCKFILE_NAME} but no longer in the repository"
        case "changed":
            fields = ", ".join(change.field for change in item.fields)
            return f"{subject} differs from {LOCKFILE_NAME}" + (f": {fields}" if fields else "")
