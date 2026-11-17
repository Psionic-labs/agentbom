"""Check out each sample repository in tests/samples at its pinned commit under .samples/."""

import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GOLDENS = ROOT / "tests" / "samples"
CHECKOUTS = ROOT / ".samples"


def _git(cwd: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-c", "core.longpaths=true", *args],
        cwd=cwd,
        check=check,
        capture_output=True,
        text=True,
    )


def _is_pinned(target: Path, sha: str) -> bool:
    head = _git(target, "rev-parse", "HEAD", check=False)
    if head.returncode != 0 or head.stdout.strip() != sha:
        return False
    return _git(target, "status", "--porcelain").stdout == ""


def ensure_checkout(repo: str, sha: str) -> Path:
    target = CHECKOUTS / repo.replace("/", "__")
    target.mkdir(parents=True, exist_ok=True)
    if (target / ".git").is_dir() and _is_pinned(target, sha):
        print(f"{repo}: already at {sha}")
        return target
    if not (target / ".git").is_dir():
        _git(target, "init", "--quiet")
        _git(target, "remote", "add", "origin", f"https://github.com/{repo}.git")
    print(f"{repo}: fetching {sha}")
    _git(target, "fetch", "--quiet", "--depth", "1", "origin", sha)
    _git(target, "checkout", "--quiet", "--force", "--detach", "FETCH_HEAD")
    _git(target, "clean", "--quiet", "--force", "-d")
    if not _is_pinned(target, sha):
        raise SystemExit(f"{repo}: checkout did not end at {sha}")
    return target


def main() -> None:
    for golden in sorted(GOLDENS.glob("*.json")):
        sample = json.loads(golden.read_text(encoding="utf-8"))
        ensure_checkout(sample["repo"], sample["sha"])


if __name__ == "__main__":
    main()
