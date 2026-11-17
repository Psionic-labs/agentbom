import json
from pathlib import Path
from typing import Any

import pytest

from agentbom.models import McpServer
from agentbom.scan import scan

REPO_ROOT = Path(__file__).resolve().parent.parent
GOLDENS = sorted((REPO_ROOT / "tests" / "samples").glob("*.json"))


def _load(golden: Path) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(golden.read_text(encoding="utf-8"))
    return data


@pytest.mark.parametrize("golden", GOLDENS, ids=[golden.stem for golden in GOLDENS])
def test_sample_repo_inventory_matches_golden(golden: Path) -> None:
    sample = _load(golden)
    checkout = REPO_ROOT / ".samples" / sample["repo"].replace("/", "__")
    if not (checkout / ".git").is_dir():
        pytest.fail(f"{checkout} is missing; run `uv run python scripts/fetch_samples.py`")
    head = (checkout / ".git" / "HEAD").read_text(encoding="utf-8").strip()
    assert head == sample["sha"], "run `uv run python scripts/fetch_samples.py`"

    result = scan(checkout)

    assert result.errors == ()
    expected = sample["artifacts"]
    assert {(a.kind, a.source.path, a.name) for a in result.artifacts} == {
        (a["kind"], a["path"], a["name"]) for a in expected
    }
    assert len(result.artifacts) == len(expected)
    assert {
        (a.source.path, a.name): a.launch.transport
        for a in result.artifacts
        if isinstance(a, McpServer)
    } == {(a["path"], a["name"]): a["transport"] for a in expected if a["kind"] == "mcp_server"}


def test_there_are_five_samples() -> None:
    assert len(GOLDENS) == 5
