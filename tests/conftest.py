import json
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path

import pytest


def write_tree(root: Path, files: Mapping[str, str | bytes | Mapping[str, object]]) -> None:
    for relative, content in files.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            target.write_bytes(content)
        elif isinstance(content, Mapping):
            target.write_bytes(json.dumps(content).encode("utf-8"))
        else:
            target.write_bytes(content.encode("utf-8"))


def symlink_or_skip(link: Path, target: str, *, is_dir: bool) -> None:
    try:
        link.symlink_to(target, target_is_directory=is_dir)
    except OSError as error:
        pytest.skip(f"this OS cannot create symlinks here: {error}")


def junction_or_skip(link: Path, target: Path) -> None:
    if sys.platform != "win32":
        pytest.skip("junctions are a Windows feature")
    subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(target)], check=True, capture_output=True
    )
