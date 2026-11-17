import subprocess
import sys
from pathlib import Path

import pytest

from agentbom.models import Location, Script
from agentbom.rules.abom_001_hidden_unicode import HiddenUnicode

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


def test_python_sources_hold_no_hidden_characters() -> None:
    sources = sorted(
        path
        for directory in ("src", "tests", "scripts")
        for path in (REPO_ROOT / directory).rglob("*.py")
    )
    scripts = [
        Script(
            name=path.relative_to(REPO_ROOT).as_posix(),
            source=Location(path=path.relative_to(REPO_ROOT).as_posix()),
            agents=(),
            language="python",
            body=path.read_text(encoding="utf-8"),
        )
        for path in sources
    ]
    found = HiddenUnicode().run(scripts)
    findings = [f"{f.location.path}:{f.location.line} {f.message}" for f in found]
    assert findings == [], "write invisible characters as \\u escapes"
