from collections.abc import Iterable, Sequence
from typing import Protocol

from agentbom.models import SEVERITY_RANK, Artifact, Finding, RuleId
from agentbom.rules.abom_001_hidden_unicode import HiddenUnicode
from agentbom.rules.abom_002_remote_exec import RemoteScriptExecution
from agentbom.rules.abom_003_credential_paths import CredentialPathAccess
from agentbom.rules.abom_004_outbound_transfer import OutboundDataTransfer
from agentbom.rules.abom_005_unpinned import UnpinnedServer
from agentbom.rules.abom_007_permissions import OverBroadPermissions
from agentbom.rules.abom_008_auto_run_hooks import AutoRunHooks
from agentbom.rules.abom_009_instruction_override import InstructionOverride
from agentbom.rules.abom_010_secrets import EmbeddedSecrets


class Rule(Protocol):
    @property
    def rule_id(self) -> RuleId: ...

    def run(self, artifacts: Sequence[Artifact]) -> Iterable[Finding]: ...


RULES: tuple[Rule, ...] = (
    HiddenUnicode(),
    RemoteScriptExecution(),
    CredentialPathAccess(),
    OutboundDataTransfer(),
    UnpinnedServer(),
    OverBroadPermissions(),
    AutoRunHooks(),
    InstructionOverride(),
    EmbeddedSecrets(),
)


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
