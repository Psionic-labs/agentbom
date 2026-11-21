"""agentbom.policy.yml: the fail threshold, approved artifacts and expiring ignores."""

from collections.abc import Sequence
from datetime import date
from typing import Annotated, Literal

import yaml
from pathspec import GitIgnoreSpec
from pydantic import BaseModel, ConfigDict, StringConstraints, ValidationError

from agentbom.lockfile import LOCKFILE_NAME
from agentbom.models import Artifact, Finding, ScanResult, Severity, Suppression

POLICY_FILENAME = "agentbom.policy.yml"
POLICY_VERSION: Literal[1] = 1
_MAX_ERROR_LOCATION = 6

Text = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
ContentHash = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
# Drift cannot be ignored: review the change and run `agentbom lock` instead.
IgnorableRuleId = Literal[
    "ABOM-001",
    "ABOM-002",
    "ABOM-003",
    "ABOM-004",
    "ABOM-005",
    "ABOM-007",
    "ABOM-008",
    "ABOM-009",
    "ABOM-010",
]


class PolicyError(ValueError):
    pass


class _PolicyModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class AllowedServer(_PolicyModel):
    path: Text
    name: Text
    sha256: ContentHash


class AllowedSkill(_PolicyModel):
    path: Text
    sha256: ContentHash


class Allow(_PolicyModel):
    mcp_servers: tuple[AllowedServer, ...] = ()
    skills: tuple[AllowedSkill, ...] = ()


class Ignore(_PolicyModel):
    rule: IgnorableRuleId
    path: Text
    reason: Text
    expires: date


class Policy(_PolicyModel):
    version: Literal[1]
    fail_on: Severity = "high"
    allow: Allow = Allow()
    ignore: tuple[Ignore, ...] = ()


def parse_policy(text: str) -> Policy:
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as error:
        raise PolicyError(f"invalid YAML: {error}") from error
    except RecursionError as error:
        raise PolicyError("invalid YAML: nesting too deep") from error
    if not isinstance(document, dict):
        raise PolicyError("the top level must be a mapping")
    version = document.get("version")
    if type(version) is not int or version != POLICY_VERSION:
        raise PolicyError(f"unsupported version {version!r}; this agentbom reads version 1")
    ignores = document.get("ignore")
    for index, entry in enumerate(ignores if isinstance(ignores, list) else []):
        if isinstance(entry, dict) and entry.get("rule") == "ABOM-006":
            raise PolicyError(
                f"ignore.{index}.rule: drift (ABOM-006) cannot be ignored; review the change "
                f"and run `agentbom lock` to update {LOCKFILE_NAME}"
            )
    try:
        return Policy.model_validate(document)
    except ValidationError as error:
        first = error.errors()[0]
        location = [str(part) for part in first["loc"]]
        if len(location) > _MAX_ERROR_LOCATION:
            location = [*location[:_MAX_ERROR_LOCATION], "..."]
        where = ".".join(location) or "top level"
        raise PolicyError(f"{where}: {first['msg']}") from error


def apply_policy(policy: Policy, result: ScanResult, today: date) -> ScanResult:
    """Move approved and ignored findings to `suppressed`, and explain stale entries."""
    approved, notes = _approved(policy.allow, result.artifacts)
    active = [entry for entry in policy.ignore if today <= entry.expires]
    notes += [
        f'ignore for {entry.rule} on "{entry.path}" expired on {entry.expires}; '
        "its findings are reported again"
        for entry in policy.ignore
        if today > entry.expires
    ]
    patterns = [GitIgnoreSpec.from_lines([entry.path]) for entry in active]
    used: set[int] = set()
    kept: list[Finding] = []
    suppressed: list[Suppression] = []
    for finding in result.findings:
        if finding.rule_id == "ABOM-006":
            kept.append(finding)
        elif finding.artifact_id in approved:
            suppressed.append(
                Suppression(finding=finding, by="allow", reason=approved[finding.artifact_id])
            )
        elif (index := _matching_ignore(active, patterns, finding)) is not None:
            used.add(index)
            suppressed.append(
                Suppression(finding=finding, by="ignore", reason=active[index].reason)
            )
        else:
            kept.append(finding)
    notes += [
        f'ignore for {entry.rule} on "{entry.path}" matches no finding; remove it'
        for index, entry in enumerate(active)
        if index not in used
    ]
    return result.model_copy(
        update={
            "findings": tuple(kept),
            "suppressed": tuple(suppressed),
            "policy_notes": tuple(notes),
        }
    )


def _matching_ignore(
    active: Sequence[Ignore], patterns: Sequence[GitIgnoreSpec], finding: Finding
) -> int | None:
    return next(
        (
            index
            for index, entry in enumerate(active)
            if entry.rule == finding.rule_id and patterns[index].match_file(finding.location.path)
        ),
        None,
    )


def _approved(allow: Allow, artifacts: Sequence[Artifact]) -> tuple[dict[str, str], list[str]]:
    """Artifact ids whose content matches an allow entry, with the reason; notes for the rest."""
    by_key = {(a.kind, a.source.path, a.name): a for a in artifacts}
    skills = {a.source.path: a for a in artifacts if a.kind == "skill"}
    approved: dict[str, str] = {}
    notes: list[str] = []
    entries: list[tuple[str, Artifact | None, str]] = [
        (f'MCP server "{e.name}" in {e.path}', by_key.get(("mcp_server", e.path, e.name)), e.sha256)
        for e in allow.mcp_servers
    ]
    entries += [(f'skill "{e.path}"', skills.get(e.path), e.sha256) for e in allow.skills]
    for label, artifact, sha256 in entries:
        if artifact is None:
            notes.append(f"allowed {label} is not in the repository; remove it")
        elif artifact.content_hash != sha256:
            notes.append(
                f"allowed {label} changed since it was approved; its findings are reported "
                f"until the policy approves sha256 {artifact.content_hash}"
            )
        else:
            approved[artifact.id] = f"approved in {POLICY_FILENAME} at sha256 {sha256[:12]}"
    return approved, notes
