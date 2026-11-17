import pytest

from agentbom.models import Finding, Location, Rules, Skill
from agentbom.rules.abom_001_hidden_unicode import HiddenUnicode

ZWJ, ZWNJ = "\u200d", "\u200c"
FLAG, CANCEL = "\U0001f3f4", "\U000e007f"


def _tags(text: str) -> str:
    return "".join(chr(0xE0000 + ord(char)) for char in text)


def _rules(body: str) -> Rules:
    return Rules(
        name="AGENTS.md",
        source=Location(path="AGENTS.md", line=1),
        agents=("agents_md",),
        frontmatter={},
        body=body,
        body_line=1,
    )


def _messages(body: str) -> list[str]:
    return [finding.message for finding in HiddenUnicode().run([_rules(body)])]


@pytest.mark.parametrize(
    "body",
    [
        "caf\u00e9 \u65e5\u672c\u8a9e \U0001f44d\U0001f3fd",
        "\U0001f468" + ZWJ + "\U0001f469" + ZWJ + "\U0001f467" + ZWJ + "\U0001f466",
        "\U0001f468\U0001f3fd" + ZWJ + "\U0001f4bb",
        "\u2764\ufe0f" + ZWJ + "\U0001f525",
        "\U0001f3f3\ufe0f" + ZWJ + "\u26a7\ufe0f",
        "\U0001f642" + ZWJ + "\u2194\ufe0f",
        FLAG + _tags("gbeng") + CANCEL,
        FLAG + _tags("gbsct") + CANCEL + FLAG + _tags("gbwls") + CANCEL,
        FLAG + _tags("usca") + CANCEL,
        "\u0645\u06cc" + ZWNJ + "\u062e\u0648\u0627\u0647\u0645",
        "\u0915\u094d" + ZWJ + "\u0937",
        "\u0d28\u0d4d" + ZWJ,
        "\u05e9\u05dc\u05d5\u05dd" + "\u200f" + " 2024",
        "\u0645\u0631\u062d\u0628\u0627" + "\u061c" + "!",
        "inter\u00adnationalization",
    ],
)
def test_legitimate_text_is_not_flagged(body: str) -> None:
    assert _messages(body) == []


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ("a\u200bb", "hidden zero-width character U+200B in body"),
        ("pass" + ZWJ + "word", "hidden zero-width character U+200D in body"),
        (ZWJ + "\U0001f525", "hidden zero-width character U+200D in body"),
        ("\U0001f525" + ZWJ, "hidden zero-width character U+200D in body"),
        ("\U0001f525" + ZWJ + "a", "hidden zero-width character U+200D in body"),
        ("Auf" + ZWNJ + "lage", "hidden zero-width character U+200C in body"),
        ("x\u2060y", "hidden zero-width character U+2060 in body"),
        ("x\ufeffy", "hidden zero-width character U+FEFF in body"),
        ("x\u180ey", "hidden zero-width character U+180E in body"),
        ("echo \u202egnp.exe", "hidden bidirectional control character U+202E in body"),
        (
            "if x \u2066admin\u2069",
            "2 hidden bidirectional control characters in body (U+2066, U+2069)",
        ),
        ("plain \u200e text", "hidden bidirectional control character U+200E in body"),
        (
            "\u05e9\u05dc\u05d5\u05dd\nplain \u200f text",
            "hidden bidirectional control character U+200F in body",
        ),
        (_tags("hi"), "2 hidden tag characters in body (decodes to 2 ASCII characters)"),
        (
            FLAG + _tags("run it now") + CANCEL,
            "11 hidden tag characters in body (decodes to 10 ASCII characters)",
        ),
        (FLAG + _tags("gbeng"), "5 hidden tag characters in body (decodes to 5 ASCII characters)"),
        (
            "x" + _tags("gbeng") + CANCEL,
            "6 hidden tag characters in body (decodes to 5 ASCII characters)",
        ),
        (CANCEL, "hidden tag character U+E007F in body (decodes to 0 ASCII characters)"),
    ],
)
def test_hidden_characters_are_flagged(body: str, message: str) -> None:
    assert _messages(body) == [message]


def test_one_finding_per_category_located_at_the_first_character() -> None:
    body = "line one\nok\na\u200bb\u200bc \u202e\n"
    findings = list(HiddenUnicode().run([_rules(body)]))
    assert [(f.message, f.location.line) for f in findings] == [
        ("2 hidden zero-width characters in body (U+200B)", 3),
        ("hidden bidirectional control character U+202E in body", 3),
    ]


def test_skill_name_description_and_frontmatter_are_checked_once() -> None:
    hidden = "\u200b"
    skill = Skill(
        name="fmt" + hidden,
        source=Location(path=".claude/skills/fmt/SKILL.md", line=1),
        agents=("claude_code",),
        description="Formats" + hidden,
        frontmatter={
            "name": "fmt" + hidden,
            "description": "Formats" + hidden,
            "metadata": {"tags": ["ok", "bad" + hidden]},
        },
        body="clean",
        body_line=5,
    )
    findings = list(HiddenUnicode().run([skill]))
    assert [f.message for f in findings] == [
        "hidden zero-width character U+200B in description",
        "hidden zero-width character U+200B in name",
        "hidden zero-width character U+200B in frontmatter.metadata.tags[1]",
    ]
    assert all(f.location == Location(path=".claude/skills/fmt/SKILL.md") for f in findings)


def test_finding_shape_and_no_decoded_payload() -> None:
    (finding,) = HiddenUnicode().run([_rules("ok " + _tags("secret-payload"))])
    assert finding == Finding(
        rule_id="ABOM-001",
        severity="high",
        confidence="high",
        message="14 hidden tag characters in body (decodes to 14 ASCII characters)",
        location=Location(path="AGENTS.md", line=1),
        artifact_id="rules:AGENTS.md:AGENTS.md",
        fix="remove the invisible characters; if intentional, document why",
    )
    assert "secret" not in finding.message
