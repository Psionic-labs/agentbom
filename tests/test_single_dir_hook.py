import json
import subprocess
import sys
from pathlib import Path

import pytest

HOOK = Path(__file__).resolve().parents[1] / ".claude" / "hooks" / "single_dir.py"


def run_hook(event: dict[str, object]) -> int:
    return subprocess.run(
        [sys.executable, str(HOOK)], input=json.dumps(event), text=True, capture_output=True
    ).returncode


@pytest.mark.parametrize(
    "event",
    [
        {"tool_name": "Bash", "tool_input": {"command": "git worktree add ../agentbom-week3"}},
        {
            "tool_name": "PowerShell",
            "tool_input": {"command": "git -C D:/Coding/agentbom worktree add x"},
        },
        {"tool_name": "Bash", "tool_input": {"command": "git clone . ../copy"}},
        {"tool_name": "Bash", "tool_input": {"command": "cd /d && git worktree add x"}},
        {"tool_name": "Bash", "tool_input": {"command": "echo $(git clone . y)"}},
        {"tool_name": "EnterWorktree", "tool_input": {}},
        {"tool_name": "Agent", "tool_input": {"prompt": "x", "isolation": "worktree"}},
    ],
)
def test_blocks_extra_directories(event: dict[str, object]) -> None:
    assert run_hook(event) == 2


@pytest.mark.parametrize(
    "event",
    [
        {"tool_name": "Bash", "tool_input": {"command": "git switch feat/week2-detectors"}},
        {"tool_name": "PowerShell", "tool_input": {"command": "git worktree list"}},
        {"tool_name": "Agent", "tool_input": {"prompt": "x"}},
        {
            "tool_name": "Bash",
            "tool_input": {"command": "git commit -F - <<'EOF'\nblocks `git worktree add`\nEOF"},
        },
        {"tool_name": "Bash", "tool_input": {"command": "grep -n 'git clone' README.md"}},
    ],
)
def test_allows_in_place_work(event: dict[str, object]) -> None:
    assert run_hook(event) == 0
