"""ABOM-002: commands that download a script and run it, or run a base64-decoded one."""

import re
from collections.abc import Iterator, Sequence
from dataclasses import dataclass

from agentbom.models import Artifact, Finding, Location, RuleId
from agentbom.rules._prose import regions
from agentbom.rules._surfaces import SeverityTable, Surface, field_label, line_of, surfaces

_SEVERITY: SeverityTable = {"executable": "high", "skill_prose": "medium", "rules_prose": "medium"}

_DOWNLOADER = r"\b(?:curl|wget|fetch|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b"
_SUDO_ENV = r"(?:sudo[ \t]+(?:-\S+[ \t]+)*)?(?:env[ \t]+)?(?:\w+=\S*[ \t]+)*"
_SHELL = r"(?:ba|z|da|k|fi)?sh\b"
# An interpreter runs piped input only with no script argument, or with `-`;
# `python -m json.tool` or `node -e '...'` just reads it as data.
_INTERPRETER = r"(?:python[0-9.]*|node|perl|ruby)(?=[ \t]*(?:$|\n|[;&|)'\"`]|-(?:\s|$)))"
_POWERSHELL = r"(?:iex|Invoke-Expression|pwsh|powershell)\b"
_FETCHED = r"[ \t]*(?:curl|wget)\b"


@dataclass(frozen=True)
class _Family:
    label: str
    action: str
    instruction: str
    patterns: tuple[re.Pattern[str], ...]
    executable_only: bool = False


def _compile(*patterns: str) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(p, re.IGNORECASE | re.MULTILINE) for p in patterns)


_DOWNLOAD_AND_RUN = ("downloads and runs remote code", "download and run remote code")
_DECODE_AND_RUN = ("runs an obfuscated command", "run an obfuscated command")

_FAMILIES: tuple[_Family, ...] = (
    _Family(
        "pipe to shell",
        *_DOWNLOAD_AND_RUN,
        _compile(
            rf"{_DOWNLOADER}[^\n|;&]*\|[ \t]*{_SUDO_ENV}(?:{_SHELL}|{_INTERPRETER}|{_POWERSHELL})"
        ),
    ),
    _Family(
        "process substitution",
        *_DOWNLOAD_AND_RUN,
        _compile(
            rf"\b(?:(?:ba|z)?sh|source)[ \t]+<\({_FETCHED}",
            rf"(?:^|[\s;&|])\.[ \t]+<\({_FETCHED}",
        ),
    ),
    _Family(
        "eval of fetched content",
        *_DOWNLOAD_AND_RUN,
        _compile(
            rf"\beval[ \t]+[\"']?(?:\$\(|`){_FETCHED}",
            rf"\b(?:ba|z)?sh[ \t]+-c[ \t]+[\"']?(?:\$\(|`){_FETCHED}",
            rf"\bpython[0-9.]*[ \t]+-c[ \t]+[\"']?(?:\$\(|`){_FETCHED}",
        ),
    ),
    _Family(
        "PowerShell download and invoke",
        *_DOWNLOAD_AND_RUN,
        _compile(
            r"\b(?:iex|Invoke-Expression)\b[^\n]*\b(?:DownloadString|DownloadFile|Invoke-WebRequest"
            r"|iwr|irm|Invoke-RestMethod|Net\.WebClient)\b",
            r"\b(?:DownloadString|irm|iwr|Invoke-RestMethod|Invoke-WebRequest)\b[^\n]*\|[ \t]*"
            r"(?:iex|Invoke-Expression)\b",
        ),
    ),
    _Family(
        "encoded PowerShell command",
        *_DECODE_AND_RUN,
        _compile(
            r"\b(?:powershell|pwsh)(?:\.exe)?(?:[ \t]+\S+)*?[ \t]+-(?:e|ec|enc|encodedcommand)"
            r"[ \t]+[A-Za-z0-9+/=]{20,}"
        ),
    ),
    _Family(
        "base64-decoded command",
        *_DECODE_AND_RUN,
        _compile(
            r"\bbase64[ \t]+(?:-d|--decode)\b[^\n|]*\|[ \t]*(?:sudo[ \t]+)?(?:ba|z)?sh\b",
            r"\bexec\([ \t]*(?:base64\.)?b64decode\(",
            r"\beval\([ \t]*(?:atob|Buffer\.from)\(",
        ),
    ),
    _Family(
        "fetched script",
        *_DOWNLOAD_AND_RUN,
        _compile(
            r"\beval\(\s*await\s+\(?\s*await\s+fetch\(",
            r"\bnew\s+Function\([^)]*\bfetch\(",
            r"\bexec\(\s*(?:requests\.get|urllib\.request\.urlopen)\(",
        ),
        executable_only=True,
    ),
)


def _first_match(family: _Family, surface: Surface) -> tuple[int, int] | None:
    for region in regions(surface):
        found = [m for p in family.patterns if (m := p.search(region.text))]
        if found:
            first = min(found, key=lambda m: m.start())
            return region.start + first.start(), region.start + first.end()
    return None


def _findings(surface: Surface) -> Iterator[Finding]:
    severity = _SEVERITY.get(surface.context)
    if severity is None:
        return
    reported: list[tuple[int, int]] = []
    for family in _FAMILIES:
        if family.executable_only and surface.context != "executable":
            continue
        span = _first_match(family, surface)
        # One command often matches two families (`irm x | iex`); report it once.
        if span is None or any(span[0] < end and start < span[1] for start, end in reported):
            continue
        reported.append(span)
        action = (
            family.action
            if surface.context == "executable"
            else f"tells the agent to {family.instruction}"
        )
        yield Finding(
            rule_id="ABOM-002",
            severity=severity,
            confidence="medium",
            message=f"{field_label(surface)} {action} ({family.label})",
            location=Location(path=surface.artifact.source.path, line=line_of(surface, span[0])),
            artifact_id=surface.artifact.id,
            fix="download to a file, verify a pinned checksum or signature, then run it",
        )


class RemoteScriptExecution:
    rule_id: RuleId = "ABOM-002"

    def run(self, artifacts: Sequence[Artifact]) -> Iterator[Finding]:
        for artifact in artifacts:
            for surface in surfaces(artifact):
                yield from _findings(surface)
