"""ABOM-003: hooks, scripts or instructions that read SSH keys, credential files,
OS credential stores, browser profiles or .env files."""

import re
from collections.abc import Iterator, Sequence
from dataclasses import dataclass

from agentbom.models import Artifact, Finding, Location, RuleId
from agentbom.rules._prose import regions
from agentbom.rules._surfaces import SeverityTable, Surface, field_label, line_of, surfaces

_SEVERITY: SeverityTable = {"executable": "high", "skill_prose": "medium", "rules_prose": "medium"}

_HOME = (
    r"(?:~|\$HOME|\$\{HOME\}|%USERPROFILE%|%HOME%|\$env:USERPROFILE|\$env:HOME"
    r"|/root|/home/[\w.-]+|/Users/[\w.-]+|[A-Za-z]:[/\\]{1,2}Users[/\\]{1,2}[\w.-]+)"
)
_SEP = r"[/\\]{1,2}"
_DOTENV = r"(?<![\w.$-])\.env(?!\.(?:example|sample|template|dist)\b)(?:\.[\w-]+)?(?![\w-])"
# Copying a template into place, and ignore files, are setup rather than reads.
_DOTENV_SETUP = re.compile(r"\.env\.(?:example|sample|template|dist)\b|\wignore\b", re.IGNORECASE)
_VERBS = (
    "read|cat|open|print|show|display|copy|send|upload|include|paste|output|dump"
    "|exfiltrate|collect|grab|extract|load"
)
# "Open .env in your editor" and "load .env with direnv" are setup steps, not reads.
_DOTENV_VERBS = "|".join(v for v in _VERBS.split("|") if v not in ("open", "load"))
_PERMISSION_RULE = re.compile(
    r"\b(?:Read|Edit|MultiEdit|Write|Glob|Grep|Bash|WebFetch|NotebookEdit)\([^)\n]*$"
)
_EXCLUDE_OPTION = re.compile(r"(?:--exclude(?:-from)?|--ignore|\s-x)[= \t]+['\"]?[^\s'\"]*$")
# ssh authenticating with a key, or ssh-add and ssh-keygen managing one, uses the
# key without reading it out; `scp key host:` still counts.
_KEY_IN_USE = re.compile(
    r"(?:\b(?:ssh|scp|sftp)\b[^\n|;&]*\s-i[ \t]*['\"]?|\bssh-(?:add|keygen)\b[^\n|;&]*\s"
    r"|\bIdentityFile[ \t=]+['\"]?)\S*$"
)


@dataclass(frozen=True)
class _Path:
    label: str
    pattern: re.Pattern[str]


@dataclass(frozen=True)
class _Family:
    description: str
    executable: tuple[_Path, ...]
    prose: tuple[_Path, ...]
    # Prose must also say to read; None when the match is itself a command.
    verbs: re.Pattern[str] | None
    # A line or sentence matching this is not a read.
    unless: re.Pattern[str] | None = None


def _paths(label: str, *patterns: str) -> tuple[_Path, ...]:
    return tuple(_Path(label, re.compile(p, re.IGNORECASE | re.MULTILINE)) for p in patterns)


def _verbs(words: str) -> re.Pattern[str]:
    return re.compile(rf"\b(?:{words})\b", re.IGNORECASE)


_SSH = (
    *_paths("private key", rf"\.ssh{_SEP}id_[\w-]+(?![\w-]|\.pub)"),
    *_paths(
        "~/.ssh directory",
        rf"{_HOME}{_SEP}\.ssh{_SEP}\*(?!\.pub)",
        rf"\b(?:tar|zip|rsync|scp|cp[ \t]+-\w*[rRa]\w*)\b[^\n|;&]*{_HOME}{_SEP}\.ssh(?:{_SEP})?"
        r"(?=$|[\s'\"])",
    ),
)
_CLOUD = (
    *_paths("AWS credentials", rf"\.aws{_SEP}credentials\b"),
    *_paths(
        "gcloud credentials",
        rf"{_HOME}{_SEP}\.config{_SEP}gcloud{_SEP}(?:application_default_)?credentials\.json",
    ),
    *_paths("Azure CLI profile", rf"{_HOME}{_SEP}\.azure\b"),
    *_paths("kubeconfig", rf"{_HOME}{_SEP}\.kube{_SEP}config\b"),
    *_paths("Docker credentials", rf"{_HOME}{_SEP}\.docker{_SEP}config\.json"),
    *_paths(".netrc", rf"{_HOME}{_SEP}[._]netrc\b"),
    *_paths(".npmrc", rf"{_HOME}{_SEP}\.npmrc\b"),
    *_paths(".pypirc", rf"{_HOME}{_SEP}\.pypirc\b"),
    *_paths("git credentials", rf"{_HOME}{_SEP}\.git-credentials\b"),
    *_paths("GitHub CLI token", rf"{_HOME}{_SEP}\.config{_SEP}gh{_SEP}hosts\.yml"),
)
_KEYCHAIN = (
    *_paths(
        "macOS keychain",
        r"\bsecurity[ \t]+(?:find-generic-password|find-internet-password|dump-keychain)\b",
    ),
    *_paths("libsecret", r"\bsecret-tool[ \t]+lookup\b"),
    *_paths(
        "Windows Credential Manager",
        r"\bcmdkey(?:\.exe)?[ \t]+/list\b",
        r"\bGet-StoredCredential\b",
        r"\bCredRead\w*\b",
    ),
)
_BROWSER = (
    *_paths(
        "browser profile",
        rf"Library{_SEP}Application Support{_SEP}(?:Google{_SEP}Chrome|BraveSoftware"
        rf"|Microsoft Edge|Firefox)",
        rf"\.mozilla{_SEP}firefox\b",
        rf"\.config{_SEP}(?:google-chrome|chromium|BraveSoftware)\b",
        rf"AppData{_SEP}(?:Local|Roaming){_SEP}(?:Google{_SEP}Chrome|Microsoft{_SEP}Edge"
        rf"|Mozilla{_SEP}Firefox|BraveSoftware)",
    ),
    *_paths("Firefox password store", r"(?<![\w.-])(?:key4\.db|logins\.json)\b"),
)
_DOTENV_READS = _paths(
    ".env file",
    # The read command must sit where a command starts, so prose in a comment
    # ("read more about .env") is not a `more .env`.
    r"(?:^|[;&|(`\"'\[,])[ \t]*(?:(?:sudo|xargs|exec|command|then|do|else)[ \t]+)*"
    r"(?:cat|less|more|head|tail|type|bat|xxd|base64|strings|cp|scp|rsync|tar|zip"
    rf"|Get-Content|gc)(?=[ \t])[^\n|;&>]*?(?P<path>{_DOTENV})",
    rf"\bopen\([ \t]*['\"][^'\"\n]*(?P<path>{_DOTENV})['\"]"
    r"(?![ \t]*,[ \t]*(?:mode[ \t]*=[ \t]*)?['\"][wax])",
    rf"\breadFile(?:Sync)?\([ \t]*['\"][^'\"\n]*(?P<path>{_DOTENV})['\"]",
)

_ANY_VERB = _verbs(_VERBS)
_FAMILIES: tuple[_Family, ...] = (
    _Family("SSH keys", _SSH, _SSH, _ANY_VERB),
    _Family("credential files", _CLOUD, _CLOUD, _ANY_VERB),
    _Family("the OS credential store", _KEYCHAIN, _KEYCHAIN, None),
    _Family("browser data", _BROWSER, _BROWSER, _ANY_VERB),
    _Family(
        "environment secrets",
        _DOTENV_READS,
        _paths(".env file", _DOTENV),
        _verbs(_DOTENV_VERBS),
        _DOTENV_SETUP,
    ),
)


def _ignored(text: str, match: re.Match[str], scope: str, family: _Family) -> bool:
    path_start = match.start("path") if "path" in match.re.groupindex else match.start()
    before = text[text.rfind("\n", 0, path_start) + 1 : path_start]
    if any(p.search(before) for p in (_PERMISSION_RULE, _EXCLUDE_OPTION, _KEY_IN_USE)):
        return True
    return family.unless is not None and family.unless.search(scope) is not None


def _line(text: str, match: re.Match[str]) -> str:
    end = text.find("\n", match.end())
    return text[text.rfind("\n", 0, match.start()) + 1 : len(text) if end < 0 else end]


def _first_match(family: _Family, surface: Surface) -> tuple[int, str] | None:
    prose = surface.context != "executable"
    for region in regions(surface):
        if prose and family.verbs is not None and family.verbs.search(region.text) is None:
            continue
        hits = [
            (region.start + match.start(), path.label)
            for path in (family.prose if prose else family.executable)
            for match in path.pattern.finditer(region.text)
            if not _ignored(
                region.text, match, region.text if prose else _line(region.text, match), family
            )
        ]
        if hits:
            return min(hits)
    return None


def _findings(surface: Surface) -> Iterator[Finding]:
    severity = _SEVERITY.get(surface.context)
    if severity is None:
        return
    for family in _FAMILIES:
        found = _first_match(family, surface)
        if found is None:
            continue
        offset, label = found
        verb = "reads" if surface.context == "executable" else "tells the agent to read"
        yield Finding(
            rule_id="ABOM-003",
            severity=severity,
            confidence="medium",
            message=f"{field_label(surface)} {verb} {family.description} ({label})",
            location=Location(path=surface.artifact.source.path, line=line_of(surface, offset)),
            artifact_id=surface.artifact.id,
            fix="do not let agent hooks, scripts or instructions access credential files",
        )


class CredentialPathAccess:
    rule_id: RuleId = "ABOM-003"

    def run(self, artifacts: Sequence[Artifact]) -> Iterator[Finding]:
        for artifact in artifacts:
            for surface in surfaces(artifact):
                yield from _findings(surface)
