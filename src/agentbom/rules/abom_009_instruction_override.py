"""ABOM-009: prose that tells the agent to drop earlier instructions or hide what it does."""

import re
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass

from agentbom.models import Artifact, Finding, Location, RuleId
from agentbom.rules._surfaces import SeverityTable, line_of, surfaces

_SEVERITY: SeverityTable = {"skill_prose": "medium", "rules_prose": "medium"}

# Up to three filler words between key terms, never crossing the end of a sentence.
_GAP = r"(?:[^\w.!?]+\w+){0,3}?[^\w.!?]+"
_AUDIENCE = r"(?:the\s+)?(?:user|human|developer|operator)s?\b(?!\Ws\b)"
_NEGATION_BEFORE = re.compile(r"(?:\b(?:never|not|no|cannot)|n\Wt)\s+(?:\w+\s+)?$", re.IGNORECASE)
# What may sit between the start of a clause and an imperative verb: list markers and
# emphasis, or a word that introduces an instruction.
_CLAUSE_START = re.compile(
    r"(?:^[\s#>*_+\-\d.)]*|[;:,(]\s*|\b(?:and|then|also|always|you|should|must|please|to|just|now)\s+)$",
    re.IGNORECASE | re.MULTILINE,
)

_SENTENCE_END = re.compile(
    r"(?<!\be\.g)(?<!\bi\.e)(?<!\betc)[.!?](?=\s|$)|\n\s*\n|\n(?=\s*(?:[-*+]|\d+[.)]|#{1,6})\s)"
)
_ILLUSTRATIVE = re.compile(
    r"\b(?:for example|for instance|e\.g\.|such as|attackers?|malicious|prompt injection|injected"
    r"|jailbreak attempts?|watch out|be wary|beware|detect|refuse)",
    re.IGNORECASE,
)
_FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
_QUOTED = re.compile(r"`[^`\n]*`|\"[^\"\n]*\"|\u201c[^\u201d\n]*\u201d")


def _not_negated(text: str, start: int) -> bool:
    return _NEGATION_BEFORE.search(text, max(0, start - 40), start) is None


def _at_clause_start(text: str, start: int) -> bool:
    line_start = text.rfind("\n", 0, start) + 1
    return _CLAUSE_START.search(text, line_start, start) is not None


def _always(text: str, start: int) -> bool:
    return True


@dataclass(frozen=True)
class _Pattern:
    regex: re.Pattern[str]
    # A context check on the text before the match.
    applies: Callable[[str, int], bool] = _always


def _pattern(regex: str, applies: Callable[[str, int], bool] = _always) -> _Pattern:
    return _Pattern(re.compile(regex, re.IGNORECASE), applies)


# Each family yields at most one finding per field, labelled "<field> tells the agent to <label>".
_FAMILIES: dict[str, tuple[_Pattern, ...]] = {
    "ignore earlier instructions": (
        _pattern(
            rf"\b(?:ignore|disregard|forget|override|bypass){_GAP}"
            rf"(?:previous|prior|earlier|above|preceding|original|system|developer){_GAP}"
            r"(?:instructions?|rules?|guidelines?|prompts?|directives?|messages?)\b",
            _not_negated,
        ),
    ),
    "take on an unrestricted persona": (
        _pattern(
            r"\byou are (?:now|no longer)(?:[^\w.!?]+\w+){0,4}?[^\w.!?]+"
            r"(?:(?-i:DAN)\b|jailbroken|unrestricted|without (?:any )?restrictions)"
        ),
        _pattern(r"\bdeveloper mode enabled\b"),
    ),
    "hide its actions from the user": (
        _pattern(
            r"\b(?:do not|don\Wt|never|without)\s+"
            r"(?:tell|telling|inform|informing|notify|notifying|mention|mentioning|alert|alerting)"
            rf"\s+(?:this\s+|it\s+|anything\s+)?(?:to\s+)?{_AUDIENCE}(?!\s+to\b)"
        ),
        _pattern(
            r"\b(?:do not|don\Wt|never|without)\s+(?:reveal|revealing|show|showing)\s+"
            rf"(?:this|it|anything|these|that)\s+(?:to\s+)?{_AUDIENCE}"
        ),
        _pattern(
            r"\b(?:hide|conceal)\s+(?:this|that|these|everything|anything"
            r"|(?:the|these|those|your|any|all)\s+(?:\w+\s+)?"
            r"(?:actions?|steps?|changes?|commands?|edits?|modifications?|activity|output))\b"
            rf"[^.\n]{{0,20}}?\bfrom\s+{_AUDIENCE}"
        ),
        _pattern(r"\b(?:hide|conceal)\s+your\s+(?:actions|activity|tracks)\b"),
        _pattern(
            r"\bkeep\s+(?:this|it|that|these|everything)\s+(?:a\s+)?secret\s+from\s+" + _AUDIENCE
        ),
        _pattern(
            r"\b(?:silently|secretly|covertly)\s+"
            r"(?:run|execute|send|upload|modify|delete|install)\b",
            _at_clause_start,
        ),
    ),
}


def _mask_quoted(text: str) -> str:
    """Blank out fenced blocks, inline code and double-quoted spans, keeping every offset."""
    lines = text.split("\n")
    fence: str | None = None
    for i, line in enumerate(lines):
        opening = _FENCE.match(line)
        if fence is not None:
            if opening and opening.group(1)[0] == fence[0] and len(opening.group(1)) >= len(fence):
                fence = None
            lines[i] = " " * len(line)
        elif opening:
            fence = opening.group(1)
            lines[i] = " " * len(line)
        else:
            lines[i] = _QUOTED.sub(lambda quoted: " " * len(quoted.group()), line)
    return "\n".join(lines)


def _sentence(text: str, start: int, end: int) -> str:
    before = 0
    for boundary in _SENTENCE_END.finditer(text, 0, start):
        before = boundary.end()
    after = _SENTENCE_END.search(text, end)
    return text[before : after.start() if after else len(text)]


def _first_match(text: str, masked: str, patterns: tuple[_Pattern, ...]) -> int | None:
    found: list[int] = []
    for pattern in patterns:
        for match in pattern.regex.finditer(masked):
            if pattern.applies(masked, match.start()) and not _ILLUSTRATIVE.search(
                _sentence(text, match.start(), match.end())
            ):
                found.append(match.start())
                break
    return min(found, default=None)


class InstructionOverride:
    rule_id: RuleId = "ABOM-009"

    def run(self, artifacts: Sequence[Artifact]) -> Iterator[Finding]:
        for artifact in artifacts:
            for surface in surfaces(artifact):
                severity = _SEVERITY.get(surface.context)
                if severity is None:
                    continue
                masked = _mask_quoted(surface.text)
                for label, patterns in _FAMILIES.items():
                    start = _first_match(surface.text, masked, patterns)
                    if start is None:
                        continue
                    yield Finding(
                        rule_id=self.rule_id,
                        severity=severity,
                        confidence="low",
                        message=f"{surface.field} tells the agent to {label}",
                        location=Location(path=artifact.source.path, line=line_of(surface, start)),
                        artifact_id=artifact.id,
                        fix="remove instructions that override earlier rules or hide actions "
                        "from the user",
                    )
