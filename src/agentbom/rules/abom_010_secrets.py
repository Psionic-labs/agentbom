"""ABOM-010: credentials written into agent files instead of referenced from the environment."""

import math
import re
from collections import Counter
from collections.abc import Iterator, Sequence
from dataclasses import dataclass

from agentbom.models import Artifact, Confidence, Finding, Location, RuleId, Severity
from agentbom.rules._surfaces import SeverityTable, Surface, line_of, surfaces

_KNOWN_SEVERITY: SeverityTable = {
    "executable": "high",
    "config": "high",
    "skill_prose": "high",
    "rules_prose": "high",
}
_GENERIC_SEVERITY: SeverityTable = {"executable": "high", "config": "high"}
_FIX = (
    "move the secret to an environment variable and reference it as ${NAME}; "
    "rotate the exposed value"
)

# Token formats are case-sensitive, so these patterns are too. Keys are message nouns.
_KNOWN: dict[str, tuple[re.Pattern[str], ...]] = {
    "a GitHub token": (
        re.compile(r"(?<![A-Za-z0-9_])gh[pousr]_[A-Za-z0-9]{36,}(?![A-Za-z0-9])"),
        re.compile(r"(?<![A-Za-z0-9_])github_pat_[A-Za-z0-9_]{60,}"),
    ),
    "an Anthropic API key": (re.compile(r"sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}"),),
    "an OpenAI API key": (
        re.compile(r"(?<![\w-])sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}"),
        re.compile(r"(?<![\w-])sk-[A-Za-z0-9]{48}(?![A-Za-z0-9])"),
    ),
    "an AWS access key": (re.compile(r"(?<![A-Za-z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Za-z0-9])"),),
    "a Google API key": (re.compile(r"(?<![\w-])AIza[0-9A-Za-z_-]{35}(?![\w-])"),),
    # Real Slack tokens put a numeric id after the prefix, which "xoxb-your-token" lacks.
    "a Slack token": (
        re.compile(r"(?<![\w-])xox[abposr]-\d+-[0-9A-Za-z-]{10,}"),
        re.compile(r"(?<![\w-])xapp-\d-[A-Za-z0-9-]{20,}"),
    ),
    "a Stripe live key": (re.compile(r"(?<![A-Za-z0-9_])(?:sk|rk)_live_[0-9A-Za-z]{24,}"),),
    "a GitLab token": (re.compile(r"(?<![\w-])glpat-[0-9A-Za-z_-]{20,}"),),
    "an npm token": (re.compile(r"(?<![A-Za-z0-9_])npm_[A-Za-z0-9]{36}(?![A-Za-z0-9])"),),
    "a Hugging Face token": (re.compile(r"(?<![A-Za-z0-9_])hf_[A-Za-z0-9]{34,}(?![A-Za-z0-9])"),),
    "a SendGrid API key": (re.compile(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"),),
    # The header alone is how docs talk about keys; a key also has a base64 body. The
    # separator may be a newline or a literal "\n" inside a quoted string.
    "a private key": (
        re.compile(
            r"-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED|PGP) )?PRIVATE KEY(?: BLOCK)?-----"
            r"(?:(?:\s|\\[rn])+[\w-]+:[^\n\\]*)*(?:\s|\\[rn])+[A-Za-z0-9+/]{32,}"
        ),
    ),
}

_SECRET_KEY = re.compile(
    r"TOKEN|SECRET|PASSWORD|PASSWD|API[_-]?KEY|ACCESS[_-]?KEY|PRIVATE[_-]?KEY|AUTH(?!OR(?!IZ))"
    r"|CREDENTIAL|BEARER",
    re.IGNORECASE,
)
# Keys that name where a secret lives or how it is used, not the secret itself.
_NOT_A_SECRET_KEY = re.compile(
    r"[_-](?:URL|URI|ENDPOINT|HOST|DOMAIN|PATH|FILE|DIR|ID|NAME|TYPE|MODE|ENABLED|HEADER"
    r"|ISSUER|AUDIENCE|REGION|SCOPES?|TTL|TIMEOUT|EXPIRY|LENGTH|METHOD|PROVIDER)$",
    re.IGNORECASE,
)
_AUTH_SCHEME = re.compile(r"^(?:Bearer|Basic|token)\s+", re.IGNORECASE)
_SECRET_VALUE = re.compile(r"[A-Za-z0-9+/=_.~-]{16,}")
_PLACEHOLDER = re.compile(
    r"your[-_ ]|xxx|changeme|example|placeholder|dummy|test|\*\*\*|redacted|replace[-_]?me"
    r"|fake|sample",
    re.IGNORECASE,
)
_CODE_REFERENCE = re.compile(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+")
_MIN_ENTROPY = 3.5

# Literal secrets in commands: a secret-named flag, an Authorization header, or an assignment
# to a secret-named variable or key.
_EXECUTABLE_SECRETS = (
    re.compile(
        r"(?<![\w-])(--(?:[a-z]+-)*(?:token|api-?key|api_key|secret|password))[= ]+[\"']?"
        r"([^\s\"'\\]+)",
        re.IGNORECASE,
    ),
    re.compile(r"\b(Authorization):\s*(?:Bearer|Basic|token)\s+([^\s\"'\\]+)", re.IGNORECASE),
    re.compile(
        r"(?<![\w$.-])([A-Za-z_][\w-]*)[\"']?\s*(?::=|[:=])\s*[\"']?([A-Za-z0-9+/=_.~-]{16,})"
    ),
)


def _entropy(value: str) -> float:
    counts = Counter(value)
    return -sum(n / len(value) * math.log2(n / len(value)) for n in counts.values())


def _is_wordy(value: str) -> bool:
    """Words, numbers and short version tags joined by separators, like "client-credentials-v2"."""
    return all(
        part.isalpha() or part.isdigit() or len(part) <= 3
        for part in re.split(r"[-_.]", value)
        if part
    )


def _looks_secret(value: str) -> bool:
    value = _AUTH_SCHEME.sub("", value.strip())
    return (
        _SECRET_VALUE.fullmatch(value) is not None
        and not value.startswith(("/", "./", "../", "~/"))
        and any(char.isdigit() for char in value)
        and any(char.isalpha() for char in value)
        and len(set(value)) > 1
        and _PLACEHOLDER.search(value) is None
        and _CODE_REFERENCE.fullmatch(value) is None
        and not _is_wordy(value)
        and _entropy(value) >= _MIN_ENTROPY
    )


def _is_secret_key(key: str) -> bool:
    return _SECRET_KEY.search(key) is not None and _NOT_A_SECRET_KEY.search(key) is None


def _is_real_token(provider: str, token: str) -> bool:
    if provider == "an AWS access key" and "EXAMPLE" in token:
        return False
    return _PLACEHOLDER.search(token) is None and len(set(token[-16:])) > 4


@dataclass(frozen=True)
class _Hit:
    start: int
    end: int
    severity: Severity
    confidence: Confidence
    message: str


def _known_hits(surface: Surface) -> Iterator[_Hit]:
    severity = _KNOWN_SEVERITY.get(surface.context)
    if severity is None:
        return
    for provider, patterns in _KNOWN.items():
        matches = [
            match
            for pattern in patterns
            for match in pattern.finditer(surface.text)
            if _is_real_token(provider, match.group())
        ]
        if matches:
            first = min(matches, key=lambda match: match.start())
            message = f"{surface.field} contains {provider}"
            yield _Hit(first.start(), first.end(), severity, "high", message)


def _generic_candidates(surface: Surface) -> Iterator[tuple[int, int, str]]:
    """(start, end, message) of each keyed literal that looks like a secret."""
    if surface.context == "config":
        _, _, key = surface.field.partition(".")
        if key and _is_secret_key(key) and _looks_secret(surface.text):
            yield 0, len(surface.text), f"{surface.field} looks like a hard-coded secret"
        return
    for pattern in _EXECUTABLE_SECRETS:
        for match in pattern.finditer(surface.text):
            key, value = match.group(1), match.group(2)
            if _is_secret_key(key) and _looks_secret(value):
                message = f"{surface.field} looks like a hard-coded secret ({key})"
                yield match.start(2), match.end(2), message


def _hits(surface: Surface) -> list[_Hit]:
    known = list(_known_hits(surface))
    severity = _GENERIC_SEVERITY.get(surface.context)
    if severity is None:
        return known
    generic = [
        _Hit(start, end, severity, "medium", message)
        for start, end, message in _generic_candidates(surface)
        if not any(start < hit.end and hit.start < end for hit in known)
    ]
    return known + sorted(generic, key=lambda hit: hit.start)[:1]


class EmbeddedSecrets:
    rule_id: RuleId = "ABOM-010"

    def run(self, artifacts: Sequence[Artifact]) -> Iterator[Finding]:
        for artifact in artifacts:
            for surface in surfaces(artifact):
                for hit in _hits(surface):
                    yield Finding(
                        rule_id=self.rule_id,
                        severity=hit.severity,
                        confidence=hit.confidence,
                        message=hit.message,
                        location=Location(
                            path=artifact.source.path, line=line_of(surface, hit.start)
                        ),
                        artifact_id=artifact.id,
                        fix=_FIX,
                    )
