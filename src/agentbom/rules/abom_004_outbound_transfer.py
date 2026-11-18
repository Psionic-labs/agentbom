"""ABOM-004: commands or instructions that send environment variables, files or secrets
to an external URL, and webhook or capture URLs in commands and config."""

import re
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from typing import Literal

from agentbom.models import Artifact, Finding, Location, McpServer, RuleId
from agentbom.rules._prose import regions
from agentbom.rules._surfaces import (
    Context,
    SeverityTable,
    Surface,
    field_label,
    line_of,
    surfaces,
)

_SEVERITY: SeverityTable = {
    "executable": "high",
    "config": "high",
    "skill_prose": "high",
    "rules_prose": "high",
}
_COMMANDS: frozenset[Context] = frozenset({"executable", "skill_prose", "rules_prose"})
_PROSE: frozenset[Context] = frozenset({"skill_prose", "rules_prose"})
_FIX = "remove the outbound transfer or move it behind a reviewed, allowlisted integration"

_LOCAL_HOST = r"(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])(?![\w.-])"
_LOCAL = re.compile(_LOCAL_HOST, re.IGNORECASE)
_EXTERNAL_URL = re.compile(rf"\bhttps?://(?!{_LOCAL_HOST})[\w\[]", re.IGNORECASE)
_DATA_FLAG = r"\s(?:-d|--data(?:-binary|-urlencode|-ascii)?)(?:[ \t]+|=)"
_FORM_FLAG = r"\s(?:-F|--form)(?:[ \t]+|=)"
_SECRET_VAR = (
    r"\$\{?(?-i:[A-Z_][A-Z0-9_]*?(?:TOKEN|SECRET|KEY|PASSWORD|PASSWD|CREDENTIAL|AUTH)[A-Z0-9_]*)"
)
_WHOLE_ENV = r"\bprocess\.env\b(?!\s*\??\.|\s*\[)"
_HOST_START = r"(?:\b(?:https?|wss?)://|(?<![\w./@-]))"
_SEND_VERB = r"\b(?:send|post|upload|transmit|exfiltrate|forward|beacon)\b"
# Model tokens ("prompt tokens", "token usage") are not credentials.
_TOKEN = (
    r"(?<!prompt )(?<!input )(?<!output )(?<!completion )"
    r"tokens?\b(?!\s+(?:counts?|usage|limits?|budgets?|costs?|windows?)\b)"
)
_SECRET_OBJECT = (
    rf"(?:environment\s+variables|env\s+vars|(?<![\w.$-])\.env\b|secrets?|{_TOKEN}|credentials?"
    r"|api[\s_-]?keys?|ssh\s+keys?|the\s+(?:file|repository|repo|codebase)\s+contents)\b"
)
# "Send requests with your API key in the Authorization header" is how an API is
# called, not a transfer of the key.
_AUTH_CONTEXT = re.compile(r"\b(?:headers?|authorization|bearer|authenticat\w*)\b", re.I)


@dataclass(frozen=True)
class _Pattern:
    label: str
    regex: re.Pattern[str]


@dataclass(frozen=True)
class _Family:
    contexts: frozenset[Context]
    action: str
    instruction: str
    patterns: tuple[_Pattern, ...]
    # line: skip a command whose line targets only localhost. sentence: the
    # sentence must name an external URL and not be about authentication.
    target: Literal["line", "sentence", "any"]


def _patterns(*sources: str, label: str = "") -> tuple[_Pattern, ...]:
    return tuple(_Pattern(label, re.compile(s, re.IGNORECASE | re.MULTILINE)) for s in sources)


def _hosts(*pairs: tuple[str, str]) -> tuple[_Pattern, ...]:
    return tuple(p for label, host in pairs for p in _patterns(_HOST_START + host, label=label))


_ENV_TO_NETWORK = _Family(
    _COMMANDS,
    "sends environment variables to an external URL",
    "send environment variables to an external URL",
    _patterns(
        r"\b(?:env|printenv|set)\b[ \t]*\|[^\n]*\b(?:curl|wget|nc|ncat|netcat|socat)\b",
        rf"\bcurl\b[^\n]*?(?:{_DATA_FLAG}|{_FORM_FLAG}|\s(?:-T|--upload-file)(?:[ \t]+|=))"
        r"[^\n]*\$\([ \t]*(?:env|printenv)[ \t]*\)",
        # Single quotes stop the shell expanding the variable, so only double
        # quotes or a bare word carry its value.
        rf"\bcurl\b[^\n]*?(?:{_DATA_FLAG}|{_FORM_FLAG})(?:\"[^\"\n]*?|[^\s'\"]*?){_SECRET_VAR}",
        rf"\bfetch\([^)]*?\bbody\s*:[^,}}]*?{_WHOLE_ENV}",
        rf"\b(?:axios|got|request|superagent|needle)\.post\([^)]*?{_WHOLE_ENV}",
        r"\b(?:requests|httpx)\.(?:post|put|patch)\([^)]*?\bos\.environ\b(?!\s*\[|\s*\.get\b)",
        r"\bjson\s*=\s*dict\(\s*os\.environ\s*\)",
        r"\bInvoke-(?:RestMethod|WebRequest)\b[^\n]*-Method[ \t]+Post\b[^\n]*-Body\b[^\n]*\$env:",
        r"\b(?:Get-ChildItem|gci|ls|dir)[ \t]+env:[^\n]*\|[^\n]*"
        r"\bInvoke-(?:RestMethod|WebRequest)\b",
    ),
    "line",
)
_FILE_TO_NETWORK = _Family(
    _COMMANDS,
    "sends file contents to an external URL",
    "send file contents to an external URL",
    _patterns(
        # `@-` is stdin, which the env-to-network patterns cover when it is the environment.
        rf"\bcurl\b[^\n]*?{_DATA_FLAG}[\"']?@(?!-)",
        rf"\bcurl\b[^\n]*?{_FORM_FLAG}[\"']?[^\s=\"']*=[@<](?!-)",
        r"\bcurl\b[^\n]*?\s(?:-T|--upload-file)(?:[ \t]+|=)[\"']?(?!-[\s\"'])\S",
        r"\bwget\b[^\n]*--post-file\b",
        r"\b(?:nc|ncat|netcat)\b[ \t]+\S+[ \t]+\d+[ \t]*<[ \t]*\S+",
    ),
    "line",
)
_WEBHOOK_URL = _Family(
    frozenset({"executable", "config"}),
    "contains a webhook or capture URL",
    "",
    _hosts(
        ("Slack webhook", r"hooks\.slack\.com/services/"),
        ("Discord webhook", r"(?:[\w-]+\.)?discord(?:app)?\.com/api/webhooks/"),
        ("webhook.site", r"webhook\.site\b"),
        ("RequestBin", r"(?:[\w-]+\.)*requestbin\.[a-z]+\b"),
        ("Pipedream", r"(?:[\w-]+\.)+pipedream\.net\b"),
        ("ngrok tunnel", r"(?:[\w-]+\.)+ngrok(?:-free)?\.(?:io|app)\b"),
        ("Interactsh", r"(?:[\w-]+\.)+interact\.sh\b"),
        ("OAST", r"(?:[\w-]+\.)+oast\.(?:fun|me|online|pro|site|live)\b"),
        ("Burp Collaborator", r"(?:[\w-]+\.)+(?:burpcollaborator\.net|oastify\.com)\b"),
        ("Canarytokens", r"(?:[\w-]+\.)*canarytokens\.com\b"),
    ),
    "any",
)
_EXFIL_INSTRUCTION = _Family(
    _PROSE,
    "",
    "send secrets to an external URL",
    _patterns(rf"{_SEND_VERB}(?:\W+[\w-]+){{0,4}}?\W*{_SECRET_OBJECT}"),
    "sentence",
)
_FAMILIES = (_ENV_TO_NETWORK, _FILE_TO_NETWORK, _WEBHOOK_URL, _EXFIL_INSTRUCTION)


def _line(text: str, match: re.Match[str]) -> str:
    end = text.find("\n", match.end())
    return text[text.rfind("\n", 0, match.start()) + 1 : len(text) if end < 0 else end]


def _only_local(line: str) -> bool:
    return _LOCAL.search(line) is not None and _EXTERNAL_URL.search(line) is None


def _counts(family: _Family, region: str, hit: re.Match[str]) -> bool:
    match family.target:
        case "line":
            return not _only_local(_line(region, hit))
        case "sentence":
            return _EXTERNAL_URL.search(region) is not None and _AUTH_CONTEXT.search(region) is None
        case "any":
            return True


def _first_match(family: _Family, surface: Surface) -> tuple[int, int, str] | None:
    for region in regions(surface):
        hits = [
            (region.start + hit.start(), region.start + hit.end(), pattern.label)
            for pattern in family.patterns
            for hit in pattern.regex.finditer(region.text)
            if _counts(family, region.text, hit)
        ]
        if hits:
            return min(hits)
    return None


def _applies(family: _Family, surface: Surface) -> bool:
    if surface.context not in family.contexts:
        return False
    # Which remote MCP hosts are allowed is a policy decision, not this rule's.
    return not (isinstance(surface.artifact, McpServer) and surface.field == "url")


def _findings(surface: Surface) -> Iterator[Finding]:
    severity = _SEVERITY.get(surface.context)
    if severity is None:
        return
    reported: list[tuple[int, int]] = []
    for family in _FAMILIES:
        if not _applies(family, surface):
            continue
        found = _first_match(family, surface)
        if found is None:
            continue
        start, end, label = found
        if any(start < done_end and done_start < end for done_start, done_end in reported):
            continue
        reported.append((start, end))
        action = (
            f"tells the agent to {family.instruction}"
            if surface.context in _PROSE
            else family.action
        )
        yield Finding(
            rule_id="ABOM-004",
            severity=severity,
            confidence="medium",
            message=f"{field_label(surface)} {action}" + (f" ({label})" if label else ""),
            location=Location(path=surface.artifact.source.path, line=line_of(surface, start)),
            artifact_id=surface.artifact.id,
            fix=_FIX,
        )


class OutboundDataTransfer:
    rule_id: RuleId = "ABOM-004"

    def run(self, artifacts: Sequence[Artifact]) -> Iterator[Finding]:
        for artifact in artifacts:
            for surface in surfaces(artifact):
                yield from _findings(surface)
