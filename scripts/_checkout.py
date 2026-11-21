"""Shallow checkouts of public GitHub repositories at a pinned commit."""

import os
import shutil
import stat
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

FETCH_TIMEOUT_SECONDS = 600
# No credential prompt for a repository that went private or was deleted, and no Git LFS
# downloads: the scan reads text files, never large binaries.
_GIT_ENV = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1"}


def _git(cwd: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-c", "core.longpaths=true", *args],
        cwd=cwd,
        check=check,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        env=_GIT_ENV,
        timeout=FETCH_TIMEOUT_SECONDS,
    )


def _is_pinned(target: Path, sha: str) -> bool:
    head = _git(target, "rev-parse", "HEAD", check=False)
    if head.returncode != 0 or head.stdout.strip() != sha:
        return False
    return _git(target, "status", "--porcelain").stdout == ""


def checkout_path(repo: str, checkouts: Path) -> Path:
    return checkouts / repo.replace("/", "__")


def ensure_checkout(repo: str, sha: str, checkouts: Path, url: str | None = None) -> Path:
    """Check out `owner/repo` at `sha` under `checkouts/owner__repo`, skipping one already there."""
    target = checkout_path(repo, checkouts)
    target.mkdir(parents=True, exist_ok=True)
    if (target / ".git").is_dir() and _is_pinned(target, sha):
        print(f"{repo}: already at {sha}")
        return target
    if not (target / ".git").is_dir():
        _git(target, "init", "--quiet")
        _git(target, "remote", "add", "origin", url or f"https://github.com/{repo}.git")
    print(f"{repo}: fetching {sha}")
    _git(target, "fetch", "--quiet", "--depth", "1", "origin", sha)
    _git(target, "checkout", "--quiet", "--force", "--detach", "FETCH_HEAD")
    _git(target, "clean", "--quiet", "--force", "-d")
    if not _is_pinned(target, sha):
        raise SystemExit(f"{repo}: checkout did not end at {sha}")
    return target


def _clear_read_only(function: Callable[..., object], path: str, _: object) -> None:
    # Git writes its object files read-only, and Windows refuses to delete those.
    Path(path).chmod(stat.S_IWRITE)
    function(path)


def remove_checkout(target: Path) -> None:
    if sys.version_info >= (3, 12):
        shutil.rmtree(target, onexc=_clear_read_only)
    else:
        shutil.rmtree(target, onerror=_clear_read_only)
