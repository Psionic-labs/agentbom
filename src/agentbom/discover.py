import codecs
import os
import stat
from dataclasses import dataclass
from pathlib import Path, PurePath

from pathspec import GitIgnoreSpec

from agentbom.models import ScanError
from agentbom.registry import SourcePattern, match_source

MAX_FILE_BYTES = 2 * 1024 * 1024


@dataclass(frozen=True)
class SourceFile:
    path: str
    text: str
    pattern: SourcePattern


class _Ignores:
    """The .gitignore files seen so far, keyed by the directory they sit in."""

    def __init__(self) -> None:
        self._specs: dict[str, GitIgnoreSpec] = {}

    def add(self, directory: str, text: str) -> None:
        self._specs[directory] = GitIgnoreSpec.from_lines(text.split("\n"))

    def ignores(self, path: str, *, is_dir: bool) -> bool:
        # The deepest .gitignore with a matching pattern decides, as in git.
        parts = path.split("/")
        for depth in range(len(parts) - 1, -1, -1):
            spec = self._specs.get("/".join(parts[:depth]))
            if spec is None:
                continue
            relative = "/".join(parts[depth:]) + ("/" if is_dir else "")
            verdict = spec.check_file(relative).include
            if verdict is not None:
                return verdict
        return False


def discover(root: Path) -> tuple[list[SourceFile], list[ScanError]]:
    if not root.is_dir():
        raise NotADirectoryError(root)
    sources: list[SourceFile] = []
    errors: list[ScanError] = []
    ignores = _Ignores()

    def relative(path: str) -> str:
        return PurePath(os.path.relpath(path, root)).as_posix()

    def walk_error(error: OSError) -> None:
        where = relative(error.filename) if error.filename else "."
        errors.append(ScanError(path=where, message=_os_message(error)))

    for current, dirnames, filenames in os.walk(root, onerror=walk_error, followlinks=False):
        here = Path(current)
        directory = "" if here == root else relative(current)
        if ".gitignore" in filenames and not _is_link(here / ".gitignore"):
            gitignore = _read(here / ".gitignore", _join(directory, ".gitignore"))
            if isinstance(gitignore, ScanError):
                errors.append(gitignore)
            else:
                ignores.add(directory, gitignore)
        dirnames[:] = sorted(
            name
            for name in dirnames
            if name != ".git"
            and not _is_link(here / name)
            and not ignores.ignores(_join(directory, name), is_dir=True)
        )
        for name in sorted(filenames):
            path = _join(directory, name)
            pattern = match_source(path)
            if pattern is None or _is_link(here / name):
                continue
            if ignores.ignores(path, is_dir=False):
                continue
            text = _read(here / name, path)
            if isinstance(text, ScanError):
                errors.append(text)
            else:
                sources.append(SourceFile(path=path, text=text, pattern=pattern))
    return sources, errors


def _decode_text(data: bytes) -> str:
    text = data.removeprefix(codecs.BOM_UTF8).decode("utf-8")
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _read(file: Path, path: str) -> str | ScanError:
    try:
        if not stat.S_ISREG(file.lstat().st_mode):
            return ScanError(path=path, message="not a regular file")
        with file.open("rb") as handle:
            data = handle.read(MAX_FILE_BYTES + 1)
    except OSError as error:
        return ScanError(path=path, message=_os_message(error))
    if len(data) > MAX_FILE_BYTES:
        return ScanError(path=path, message="file is larger than the 2 MiB limit")
    try:
        return _decode_text(data)
    except UnicodeDecodeError as error:
        return ScanError(path=path, message=f"not valid UTF-8 (byte {error.start})")


def _os_message(error: OSError) -> str:
    # str(error) embeds the absolute filename, and output must stay repo-relative.
    return f"cannot read: {error.strerror or type(error).__name__}"


def _is_link(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return False
    # Windows junctions are not symlinks to Python 3.11, yet os.walk follows them.
    reparse_tag = getattr(info, "st_reparse_tag", 0)
    return stat.S_ISLNK(info.st_mode) or reparse_tag == stat.IO_REPARSE_TAG_MOUNT_POINT


def _join(directory: str, name: str) -> str:
    return f"{directory}/{name}" if directory else name
