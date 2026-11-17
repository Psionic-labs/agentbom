from collections.abc import Iterable, Sequence
from typing import Protocol

from agentbom.models import SEVERITY_RANK, Artifact, Finding, RuleId
from agentbom.rules.abom_005_unpinned import UnpinnedServer


class Rule(Protocol):
    @property
    def rule_id(self) -> RuleId: ...

    def run(self, artifacts: Sequence[Artifact]) -> Iterable[Finding]: ...


RULES: tuple[Rule, ...] = (UnpinnedServer(),)


def run_rules(artifacts: Sequence[Artifact]) -> tuple[Finding, ...]:
    findings = [finding for rule in RULES for finding in rule.run(artifacts)]
    return tuple(sorted(findings, key=_finding_key))


def _finding_key(finding: Finding) -> tuple[int, str, str, int, str, str]:
    return (
        -SEVERITY_RANK[finding.severity],
        finding.rule_id,
        finding.location.path,
        finding.location.line or 0,
        finding.message,
        finding.artifact_id,
    )
