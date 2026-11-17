import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


def _ruff_check(source: str, filename: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "ruff", "check", "--stdin-filename", filename, "-"],
        input=source,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        check=False,
    )


@pytest.mark.parametrize(
    "source",
    [
        "import subprocess\n\nsubprocess.run(['x'], check=True)\n",
        "import socket\n\nsocket.create_connection(('example.com', 80))\n",
        "from urllib.request import urlopen\n\nurlopen('https://example.com')\n",
        "import os\n\nos.system('x')\n",
    ],
)
def test_scanner_package_rejects_process_and_network_calls(source: str) -> None:
    result = _ruff_check(source, "src/agentbom/probe.py")
    assert result.returncode == 1, result.stdout
    assert "TID251" in result.stdout


def test_scanner_package_accepts_plain_imports() -> None:
    result = _ruff_check("import json\n\njson.dumps(1)\n", "src/agentbom/probe.py")
    assert result.returncode == 0, result.stdout


def test_scripts_may_run_processes() -> None:
    source = "import subprocess\n\nsubprocess.run(['x'], check=True)\n"
    result = _ruff_check(source, "scripts/probe.py")
    assert result.returncode == 0, result.stdout
