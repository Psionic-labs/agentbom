"""Find the agent files in a repository: the files git tracks, or every file outside git.

In a git checkout (a `.git` at the root), the files come from `.git/index`, so a file is
scanned exactly when it is tracked, whatever `.gitignore` or `.git/info/exclude` say.
Outside git, every file under the root is scanned.

A symlink is followed through the tracked paths, never on disk, and the files it leads to
are scanned at their real path. A symlink that cannot be followed (it dangles, is
absolute, leaves the repository or enters a submodule) is a scan error when its own path
is an agent file. Otherwise it may be a directory hiding agent files, so its target is
locked: adding or retargeting it is drift.
"""

import bisect
import codecs
import os
import re
import stat
import sys
from dataclasses import dataclass, field
from pathlib import Path, PurePath

from agentbom.gitindex import (
    DIRECTORY,
    GITLINK,
    REGULAR,
    SYMLINK,
    GitIndexError,
    hash_size,
    object_type,
    parse_index,
)
from agentbom.models import ScanError
from agentbom.registry import SourcePattern, match_source

MAX_FILE_BYTES = 2 * 1024 * 1024
_MAX_LINK_HOPS = 40
_MAX_LINK_DEPTH = 8
_MAX_LINKED_FILES = 100_000
_ABSOLUTE = re.compile(r"^(/|[A-Za-z]:)")


@dataclass(frozen=True)
class SourceFile:
    path: str
    text: str
    pattern: SourcePattern


@dataclass(frozen=True)
class Discovery:
    sources: list[SourceFile]
    # Each symlink that leads an agent to a scanned file, with its target.
    links: dict[str, str]
    errors: list[ScanError]


class _Unresolved(Exception):
    pass


@dataclass
class _Tree:
    """The paths in a repository: regular files, symlinks and their targets, submodules."""

    files: set[str] = field(default_factory=set)
    links: dict[str, str] = field(default_factory=dict)
    submodules: set[str] = field(default_factory=set)
    _sorted: list[str] = field(default_factory=list)

    def freeze(self) -> None:
        self._sorted = sorted(self.files | self.links.keys() | self.submodules)

    def under(self, directory: str) -> list[str]:
        if not directory:
            return self._sorted
        prefix = directory + "/"
        start = bisect.bisect_left(self._sorted, prefix)
        end = start
        while end < len(self._sorted) and self._sorted[end].startswith(prefix):
            end += 1
        return self._sorted[start:end]

    def follow(self, path: str) -> str:
        """The path with every symlink in it replaced by its target, as the OS would."""
        resolved: list[str] = []
        pending = list(reversed(path.split("/")))
        hops = 0
        while pending:
            part = pending.pop()
            if part in ("", "."):
                continue
            if part == "..":
                if not resolved:
                    raise _Unresolved("points outside the repository")
                resolved.pop()
                continue
            resolved.append(part)
            current = "/".join(resolved)
            if current in self.submodules:
                raise _Unresolved("points into a submodule, which is not scanned")
            target = self.links.get(current)
            if target is None:
                continue
            hops += 1
            if hops > _MAX_LINK_HOPS:
                raise _Unresolved("goes through too many links")
            if _ABSOLUTE.match(target):
                raise _Unresolved("has an absolute target")
            resolved.pop()
            pending.extend(reversed(target.split("/")))
        return "/".join(resolved)

    def expand(self, link: str, virtual: str, depth: int, out: list[tuple[str, str]]) -> None:
        """Add (path an agent sees, real file) for every file reached through `link`."""
        if depth > _MAX_LINK_DEPTH:
            raise _Unresolved("nests links too deeply")
        real = self.follow(link)
        if real in self.files:
            out.append((virtual, real))
            return
        children = self.under(real)
        if not children:
            raise _Unresolved("points to nothing in the repository")
        if not real or link.startswith(real + "/"):
            raise _Unresolved("points to a directory that contains it")
        for child in children:
            seen = f"{virtual}/{child[len(real) + 1 :]}"
            if child in self.files:
                out.append((seen, child))
            elif child in self.links:
                self.expand(child, seen, depth + 1, out)
            if len(out) > _MAX_LINKED_FILES:
                raise _Unresolved(f"leads to more than {_MAX_LINKED_FILES} files")


def discover(root: Path) -> Discovery:
    if not root.is_dir():
        raise NotADirectoryError(root)
    errors: list[ScanError] = []
    tree = _git_tree(root, errors) if _lexists(root / ".git") else _walk_tree(root, errors)
    tree.freeze()
    patterns: dict[str, SourcePattern] = {}
    for path in sorted(tree.files):
        pattern = match_source(path)
        if pattern is not None:
            patterns[path] = pattern
    links: dict[str, str] = {}
    for link in sorted(tree.links):
        reached: list[tuple[str, str]] = []
        try:
            tree.expand(link, link, 0, reached)
        except _Unresolved as problem:
            if match_source(link) is not None:
                errors.append(ScanError(path=link, message=f"symlink {problem}"))
            else:
                links[link] = tree.links[link]
            continue
        for seen, real in sorted(reached):
            pattern = match_source(seen)
            if pattern is not None:
                links[link] = tree.links[link]
                patterns.setdefault(real, pattern)
    sources: list[SourceFile] = []
    on_disk = _DiskCheck(root)
    for path, pattern in sorted(patterns.items()):
        text = on_disk.read(path)
        if isinstance(text, ScanError):
            errors.append(text)
        else:
            sources.append(SourceFile(path=path, text=text, pattern=pattern))
    return Discovery(sources=sources, links=links, errors=errors)


def _git_tree(root: Path, errors: list[ScanError]) -> _Tree:
    tree = _Tree()
    try:
        git_dir = _git_dir(root)
        common = git_dir
        if (git_dir / "commondir").is_file():
            common = git_dir / (git_dir / "commondir").read_text(encoding="utf-8").strip()
        config = common / "config"
        size = hash_size(config.read_text(encoding="utf-8")) if config.is_file() else 20
        index = git_dir / "index"
        entries = parse_index(index.read_bytes(), size) if index.is_file() else {}
    except (OSError, UnicodeDecodeError, GitIndexError) as error:
        message = _os_message(error) if isinstance(error, OSError) else str(error)
        errors.append(ScanError(path=".git", message=message))
        return tree
    for path, mode in entries.items():
        kind = object_type(mode)
        if kind == REGULAR:
            tree.files.add(path)
        elif kind == SYMLINK:
            target = _link_target(root, path, errors)
            if target is not None:
                tree.links[path] = target
        elif kind == GITLINK:
            tree.submodules.add(path)
        elif kind == DIRECTORY:
            errors.append(ScanError(path=path, message="a sparse directory is not checked out"))
    return tree


def _git_dir(root: Path) -> Path:
    dot_git = root / ".git"
    mode = dot_git.lstat().st_mode
    if stat.S_ISDIR(mode):
        return dot_git
    if not stat.S_ISREG(mode):
        raise GitIndexError(".git is neither a directory nor a file")
    # A worktree or submodule checkout has a `.git` file naming its git directory.
    pointer = dot_git.read_text(encoding="utf-8").strip()
    if not pointer.startswith("gitdir:"):
        raise GitIndexError(".git is a file without a gitdir line")
    return root / pointer.removeprefix("gitdir:").strip()


def _link_target(root: Path, path: str, errors: list[ScanError]) -> str | None:
    # git stores a symlink's target as its content; with core.symlinks off the checkout
    # writes it as a plain file, and otherwise the OS returns it.
    file = root / path
    try:
        if stat.S_ISLNK(file.lstat().st_mode):
            return file.readlink().as_posix()
        return file.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError) as error:
        message = _os_message(error) if isinstance(error, OSError) else "target is not UTF-8"
        errors.append(ScanError(path=path, message=f"symlink {message}"))
        return None


def _walk_tree(root: Path, errors: list[ScanError]) -> _Tree:
    tree = _Tree()

    def relative(path: str) -> str:
        return PurePath(os.path.relpath(path, root)).as_posix()

    def walk_error(error: OSError) -> None:
        where = relative(error.filename) if error.filename else "."
        errors.append(ScanError(path=where, message=_os_message(error)))

    for current, dirnames, filenames in os.walk(root, onerror=walk_error, followlinks=False):
        here = Path(current)
        directory = "" if here == root else relative(current)
        directories: list[str] = []
        for name in dirnames:
            if name == ".git":
                continue
            if _is_link(here / name):
                _add_disk_link(tree, here / name, _join(directory, name), errors)
            else:
                directories.append(name)
        dirnames[:] = sorted(directories)
        for name in filenames:
            path = _join(directory, name)
            if _is_link(here / name):
                _add_disk_link(tree, here / name, path, errors)
            else:
                tree.files.add(path)
    return tree


def _add_disk_link(tree: _Tree, file: Path, path: str, errors: list[ScanError]) -> None:
    try:
        tree.links[path] = file.readlink().as_posix()
    except OSError as error:
        errors.append(ScanError(path=path, message=f"symlink {_os_message(error)}"))


class _DiskCheck:
    """Reads tracked files, refusing any whose path on disk goes through a link."""

    def __init__(self, root: Path) -> None:
        self._root = root
        self._linked: dict[str, bool] = {}

    def read(self, path: str) -> str | ScanError:
        parts = path.split("/")
        for depth in range(1, len(parts)):
            directory = "/".join(parts[:depth])
            if directory not in self._linked:
                self._linked[directory] = _is_link(self._root / directory)
            if self._linked[directory]:
                return ScanError(path=path, message=f"{directory} is a link on disk")
        return read_source(self._root / path, path)


def _decode_text(data: bytes) -> str:
    text = data.removeprefix(codecs.BOM_UTF8).decode("utf-8")
    return text.replace("\r\n", "\n").replace("\r", "\n")


def read_source(file: Path, path: str) -> str | ScanError:
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


def _lexists(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True


def _is_link(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return False
    if stat.S_ISLNK(info.st_mode):
        return True
    if sys.platform == "win32":
        # Windows junctions are not symlinks to Python 3.11, yet os.walk follows them.
        return info.st_reparse_tag == stat.IO_REPARSE_TAG_MOUNT_POINT
    return False


def _join(directory: str, name: str) -> str:
    return f"{directory}/{name}" if directory else name
