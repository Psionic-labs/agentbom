"""Sentences and negation, for rules that judge instructions written in prose."""

import re
from collections.abc import Iterator
from dataclasses import dataclass

from agentbom.rules._surfaces import Surface


@dataclass(frozen=True)
class Sentence:
    start: int
    text: str


_FENCE = re.compile(r"[ \t]*(?:```|~~~)")
# A Markdown list item, heading or quote starts a new block; any other line
# continues the paragraph above it, so a soft-wrapped sentence stays whole.
_BLOCK_START = re.compile(r"[ \t]*(?:[-*+][ \t]|\d+[.)][ \t]|#|>)")
_NUMBERED_ITEM = re.compile(r"[ \t]*\d+[.)][ \t]")
_HEADING = re.compile(r"[ \t]*#")
_TABLE_ROW = re.compile(r"[ \t]*\|")
_CELL_BORDER = re.compile(r"(?<!\\)\|")
_SENTENCE_END = re.compile(r"(?<=[.!?])(?<!\be\.g\.)(?<!\bi\.e\.)(?<!\betc\.)\s+")
_NEGATION = re.compile(
    r"\b(?:"
    r"(?:never|do\s+not|don['\u2019]t)(?!\s+(?:forget|hesitate|fail)\b)"
    r"|must\s+not|mustn['\u2019]t|should\s+not|shouldn['\u2019]t"
    r"|avoid(?:s|ing)?|refus(?:e|es|ing)|den(?:y|ies|ied)"
    r"|not\s+allowed|prohibited|forbidden"
    r"|without(?!\s+(?:asking|telling|notifying|informing|alerting|mentioning|showing"
    r"|confirming|prompting|letting)\b)"
    r")\b",
    re.IGNORECASE,
)


def sentences(text: str) -> Iterator[Sentence]:
    """Sentences of Markdown prose, each with its offset in `text`.

    Paragraphs split on `.`, `!` or `?` before whitespace; list items, headings,
    table cells and lines of a code block are sentences of their own.
    """
    for start, end in _blocks(text):
        block = text[start:end]
        cursor = 0
        marker = _NUMBERED_ITEM.match(block)
        for boundary in _SENTENCE_END.finditer(block, marker.end() if marker else 0):
            yield from _trimmed(text, start + cursor, start + boundary.start())
            cursor = boundary.end()
        yield from _trimmed(text, start + cursor, end)


def negated(sentence: str) -> bool:
    return _NEGATION.search(sentence) is not None


def regions(surface: Surface) -> Iterator[Sentence]:
    """The parts of a surface a rule searches: all of a command or value, or each
    prose sentence that does not negate what it says."""
    if surface.context in ("skill_prose", "rules_prose"):
        yield from (s for s in sentences(surface.text) if not negated(s.text))
    else:
        yield Sentence(0, surface.text)


def _blocks(text: str) -> Iterator[tuple[int, int]]:
    open_start: int | None = None
    open_end = 0
    in_fence = False
    offset = 0
    for line in text.splitlines(keepends=True):
        start, offset = offset, offset + len(line)
        end = start + len(line.rstrip("\r\n"))
        fence = _FENCE.match(line) is not None
        standalone = fence or in_fence or not line.strip() or _TABLE_ROW.match(line)
        if open_start is not None and (standalone or _BLOCK_START.match(line)):
            yield open_start, open_end
            open_start = None
        if fence:
            in_fence = not in_fence
        elif in_fence:
            yield start, end
        elif _TABLE_ROW.match(line):
            yield from _cells(line, start, end)
        elif line.strip():
            if open_start is None:
                open_start = start
            open_end = end
            if _HEADING.match(line):
                yield open_start, open_end
                open_start = None
    if open_start is not None:
        yield open_start, open_end


def _cells(line: str, start: int, end: int) -> Iterator[tuple[int, int]]:
    cursor = start
    for border in _CELL_BORDER.finditer(line, 0, end - start):
        yield cursor, start + border.start()
        cursor = start + border.end()
    yield cursor, end


def _trimmed(text: str, start: int, end: int) -> Iterator[Sentence]:
    chunk = text[start:end]
    stripped = chunk.strip()
    if stripped:
        yield Sentence(start + len(chunk) - len(chunk.lstrip()), stripped)
