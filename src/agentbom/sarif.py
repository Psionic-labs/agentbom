"""SARIF 2.1.0 output, in the shape GitHub code scanning reads."""

import hashlib
import json
from importlib.metadata import version
from typing import Any
from urllib.parse import quote

from agentbom.models import Finding, RuleId, ScanResult, Severity

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/Psionic-labs/contextlock"

# Name, one-line description and default severity, from the detection rules spec.
RULE_INFO: dict[RuleId, tuple[str, str, Severity]] = {
    "ABOM-001": (
        "HiddenUnicode",
        "Hidden Unicode (tag, zero-width or bidirectional characters) in agent context",
        "high",
    ),
    "ABOM-002": (
        "RemoteScriptExecution",
        "Downloads and runs a script, such as curl piped to a shell",
        "high",
    ),
    "ABOM-003": (
        "CredentialPathAccess",
        "Reads SSH keys, cloud credentials, .env files, keychains or browser profiles",
        "high",
    ),
    "ABOM-004": (
        "OutboundDataTransfer",
        "Sends file contents or environment variables to an external URL",
        "high",
    ),
    "ABOM-005": (
        "UnpinnedServer",
        "MCP server launched from a package, image or git source without an exact version",
        "medium",
    ),
    "ABOM-006": (
        "Drift",
        "Agent context differs from agentbom.lock",
        "high",
    ),
    "ABOM-007": (
        "OverBroadPermissions",
        "Wildcard allowlists, permission-bypass modes or auto-approve-all settings",
        "medium",
    ),
    "ABOM-008": (
        "AutoRunHooks",
        "Hook that runs shell commands automatically from repository-controlled files",
        "medium",
    ),
    "ABOM-009": (
        "InstructionOverride",
        "Tells the agent to ignore earlier instructions or hide actions from the user",
        "medium",
    ),
    "ABOM-010": (
        "EmbeddedSecrets",
        "Hard-coded token or secret instead of an environment variable reference",
        "high",
    ),
}
_LEVELS: dict[Severity, str] = {"high": "error", "medium": "warning", "low": "note"}
# GitHub maps security-severity to its critical, high, medium and low alert labels.
_SECURITY_SEVERITY: dict[Severity, str] = {"high": "8.0", "medium": "5.0", "low": "2.0"}
_RULE_IDS: tuple[RuleId, ...] = tuple(sorted(RULE_INFO))


def render_sarif(result: ScanResult) -> str:
    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "agentbom",
                "version": version("contextlock"),
                "informationUri": INFORMATION_URI,
                "rules": [_rule(rule_id) for rule_id in _RULE_IDS],
            }
        },
        "invocations": [
            {
                "executionSuccessful": not result.errors,
                "toolExecutionNotifications": [
                    {
                        "level": "error",
                        "message": {"text": error.message},
                        "locations": [_location(error.path, None)],
                    }
                    for error in result.errors
                ],
            }
        ],
        "results": [_result(finding) for finding in result.findings],
    }
    document = {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def _rule(rule_id: RuleId) -> dict[str, Any]:
    name, description, severity = RULE_INFO[rule_id]
    return {
        "id": rule_id,
        "name": name,
        "shortDescription": {"text": description},
        "fullDescription": {"text": description},
        "defaultConfiguration": {"level": _LEVELS[severity]},
        "properties": {
            "security-severity": _SECURITY_SEVERITY[severity],
            "tags": ["security", "agent-supply-chain"],
        },
    }


def _result(finding: Finding) -> dict[str, Any]:
    text = finding.message if finding.fix is None else f"{finding.message}. {finding.fix}"
    identity = "\n".join(
        (finding.rule_id, finding.location.path, finding.artifact_id, finding.message)
    )
    return {
        "ruleId": finding.rule_id,
        "ruleIndex": _RULE_IDS.index(finding.rule_id),
        "level": _LEVELS[finding.severity],
        "message": {"text": text},
        "locations": [_location(finding.location.path, finding.location.line)],
        "partialFingerprints": {
            "agentbom/v1": hashlib.sha256(identity.encode("utf-8")).hexdigest()
        },
        "properties": {"confidence": finding.confidence, "artifactId": finding.artifact_id},
    }


def _location(path: str, line: int | None) -> dict[str, Any]:
    # GitHub needs a region, so a finding about a whole file points at its first line.
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": quote(path), "uriBaseId": "%SRCROOT%"},
            "region": {"startLine": line or 1},
        }
    }
