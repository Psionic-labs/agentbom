"""ABOM-001: invisible Unicode that can hide instructions from a human reviewer."""

import re
import unicodedata
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from typing import Literal

from pydantic import JsonValue

from agentbom.models import Artifact, Finding, Location, RuleId, Rules, Skill
from agentbom.rules._surfaces import Surface, line_of, surfaces

Category = Literal["tag", "zero-width", "bidirectional control"]

_CANDIDATES = re.compile(
    "[\u061c\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\U000e0000-\U000e007f]"
)
_ALWAYS_HIDDEN: dict[str, Category] = {
    **dict.fromkeys(("\u200b", "\u2060", "\u2061", "\u2062", "\u2063", "\u2064"), "zero-width"),
    **dict.fromkeys(("\u180e", "\ufeff"), "zero-width"),
    **dict.fromkeys(map(chr, range(0x202A, 0x202F)), "bidirectional control"),
    **dict.fromkeys(map(chr, range(0x2066, 0x206A)), "bidirectional control"),
}
_TAG_FIRST, _TAG_LAST = 0xE0000, 0xE007F
_FLAG_BASE = "\U0001f3f4"
# CLDR subdivision ids, the only tag specs RGI flags use: a region and 1 to 4 alphanumerics.
_SUBDIVISION = re.compile(
    "[\U000e0061-\U000e007a]{2}[\U000e0030-\U000e0039\U000e0061-\U000e007a]{1,4}"
)

_EMOJI_RANGES = (
    (0x00A9, 0x00A9),
    (0x00AE, 0x00AE),
    (0x203C, 0x203C),
    (0x2049, 0x2049),
    (0x2122, 0x2122),
    (0x2139, 0x2139),
    (0x2190, 0x21FF),
    (0x2300, 0x23FF),
    (0x24C2, 0x24C2),
    (0x25A0, 0x27BF),
    (0x2934, 0x2935),
    (0x2B00, 0x2BFF),
    (0x3030, 0x3030),
    (0x303D, 0x303D),
    (0x3297, 0x3297),
    (0x3299, 0x3299),
    (0xFE0F, 0xFE0F),
    (0x1F000, 0x1FFFD),
)
# Scripts whose orthography uses ZWJ/ZWNJ: Arabic (and Persian), the Indic scripts,
# Sinhala, Myanmar and Khmer.
_JOINING_SCRIPT_RANGES = (
    (0x0600, 0x06FF),
    (0x0750, 0x077F),
    (0x08A0, 0x08FF),
    (0x0900, 0x0DFF),
    (0x1000, 0x109F),
    (0x1780, 0x17FF),
    (0xFB50, 0xFDFF),
    (0xFE70, 0xFEFC),
)


def _in(ranges: tuple[tuple[int, int], ...], char: str) -> bool:
    code = ord(char)
    return any(low <= code <= high for low, high in ranges)


def _before(text: str, i: int) -> str:
    return text[i - 1] if i > 0 else ""


def _after(text: str, i: int) -> str:
    return text[i + 1] if i + 1 < len(text) else ""


def _joining_letter(char: str) -> bool:
    # Indic conjuncts put the joiner after a virama, a combining mark, not a letter.
    return (
        bool(char) and _in(_JOINING_SCRIPT_RANGES, char) and unicodedata.category(char)[0] in "LM"
    )


def _zwj_allowed(text: str, i: int) -> bool:
    before, after = _before(text, i), _after(text, i)
    emoji = bool(before and after) and _in(_EMOJI_RANGES, before) and _in(_EMOJI_RANGES, after)
    return emoji or _joining_letter(before)


def _zwnj_allowed(text: str, i: int) -> bool:
    return _joining_letter(_before(text, i))


def _mark_allowed(text: str, i: int) -> bool:
    start = text.rfind("\n", 0, i) + 1
    end = text.find("\n", i)
    line = text[start : end if end != -1 else len(text)]
    return any(
        unicodedata.bidirectional(char) in ("R", "AL") and unicodedata.category(char)[0] == "L"
        for char in line
    )


# Characters that are legitimate in some neighborhoods: category, and when they are allowed.
_CONDITIONAL: dict[str, tuple[Category, Callable[[str, int], bool]]] = {
    "\u200d": ("zero-width", _zwj_allowed),
    "\u200c": ("zero-width", _zwnj_allowed),
    "\u200e": ("bidirectional control", _mark_allowed),
    "\u200f": ("bidirectional control", _mark_allowed),
    "\u061c": ("bidirectional control", _mark_allowed),
}


def _is_tag(char: str) -> bool:
    return _TAG_FIRST <= ord(char) <= _TAG_LAST


def _is_flag_sequence(text: str, start: int, end: int) -> bool:
    """Whether tags text[start:end] are the spec and terminator of a subdivision flag."""
    return (
        _before(text, start) == _FLAG_BASE
        and text[end - 1] == chr(_TAG_LAST)
        and _SUBDIVISION.fullmatch(text, start, end - 1) is not None
    )


@dataclass
class _Tally:
    first: int
    count: int = 0
    decoded: int = 0
    code_points: set[int] = field(default_factory=set)

    def add(self, char: str) -> None:
        self.count += 1
        self.code_points.add(ord(char))
        if 0xE0020 <= ord(char) <= 0xE007E:
            self.decoded += 1


def _tally(text: str) -> dict[Category, _Tally]:
    tallies: dict[Category, _Tally] = {}

    def add(category: Category, offset: int) -> None:
        tallies.setdefault(category, _Tally(first=offset)).add(text[offset])

    resume = 0
    for match in _CANDIDATES.finditer(text):
        i = match.start()
        if i < resume:
            continue
        char = text[i]
        if _is_tag(char):
            end = i
            while end < len(text) and _is_tag(text[end]):
                end += 1
            resume = end
            if not _is_flag_sequence(text, i, end):
                for offset in range(i, end):
                    add("tag", offset)
        elif char in _ALWAYS_HIDDEN:
            add(_ALWAYS_HIDDEN[char], i)
        else:
            category, allowed = _CONDITIONAL[char]
            if not allowed(text, i):
                add(category, i)
    return tallies


def _message(category: Category, tally: _Tally, where: str) -> str:
    codes = sorted(tally.code_points)
    if tally.count == 1:
        message = f"hidden {category} character U+{codes[0]:04X} in {where}"
    else:
        message = f"{tally.count} hidden {category} characters in {where}"
        if category != "tag":
            message += " (" + ", ".join(f"U+{code:04X}" for code in codes) + ")"
    if category == "tag":
        noun = "character" if tally.decoded == 1 else "characters"
        message += f" (decodes to {tally.decoded} ASCII {noun})"
    return message


def _visible(label: str) -> str:
    return _CANDIDATES.sub("?", label)


def _frontmatter_strings(value: JsonValue, where: str) -> Iterator[tuple[str, str]]:
    if isinstance(value, str):
        yield where, value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _frontmatter_strings(item, f"{where}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _frontmatter_strings(item, f"{where}[{index}]")


def _texts(artifact: Artifact) -> Iterator[tuple[str, str, Surface | None]]:
    """Every (field, text, surface) to check; surface is None for text with no file line."""
    seen: set[str] = set()
    for surface in surfaces(artifact):
        seen.add(surface.text)
        yield surface.field, surface.text, surface
    yield "name", artifact.name, None
    seen.add(artifact.name)
    if isinstance(artifact, Skill | Rules):
        for where, text in _frontmatter_strings(artifact.frontmatter, "frontmatter"):
            # The skill name and description are already checked as their own fields.
            if text not in seen:
                yield where, text, None


class HiddenUnicode:
    rule_id: RuleId = "ABOM-001"

    def run(self, artifacts: Sequence[Artifact]) -> Iterator[Finding]:
        for artifact in artifacts:
            for where, text, surface in _texts(artifact):
                for category, tally in _tally(text).items():
                    line = line_of(surface, tally.first) if surface is not None else None
                    yield Finding(
                        rule_id=self.rule_id,
                        severity="high",
                        confidence="high",
                        message=_message(category, tally, _visible(where)),
                        location=Location(path=artifact.source.path, line=line),
                        artifact_id=artifact.id,
                        fix="remove the invisible characters; if intentional, document why",
                    )
