"""ABOM-005: an MCP server launched from a package, image or git source with no exact version."""

import re
import shlex
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import PureWindowsPath

from agentbom.models import Artifact, Finding, Location, McpServer, RuleId, StdioLaunch

_SEMVER = re.compile(
    r"v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?"
)
_COMMIT = re.compile(r"[0-9a-fA-F]{40}")
_NPM_GIT_PREFIXES = ("git+", "git://", "github:", "gitlab:", "bitbucket:", "gist:")
_GITHUB_SHORTHAND = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(#.*)?")
_PY_NAME = r"[A-Za-z0-9][A-Za-z0-9._-]*(?:\[[^\]]*\])?"
_PEP440_EXACT = re.compile(rf"{_PY_NAME}\s*===?\s*[A-Za-z0-9.!+_-]+")
_UV_AT_VERSION = re.compile(rf"{_PY_NAME}@v?\d+(?:\.\d+)+[A-Za-z0-9.+_-]*")
_PY_GIT_COMMIT = re.compile(r"@[0-9a-fA-F]{40}(#|$)")
_GIT_REF = re.compile(r"@[^/@]*$")
_USERINFO = re.compile(r"(?<=://)[^/@\s]*@")
_WINDOWS_DRIVE = re.compile(r"[A-Za-z]:[\\/]")
_PATH_START = re.compile(r"([A-Za-z]:)?[\\/]|\.{1,2}[\\/]|~[\\/]")
_EXECUTABLE_SUFFIXES = (".exe", ".cmd", ".bat", ".ps1")


def _is_local_path(spec: str) -> bool:
    return (
        spec.startswith((".", "/", "~", "file:"))
        or "\\" in spec
        or _WINDOWS_DRIVE.match(spec) is not None
    )


def _is_unresolved(spec: str) -> bool:
    # A variable expands at launch time, so the scanner cannot see the real version.
    return "$" in spec or "%" in spec or "{{" in spec


def _npm_fix(spec: str) -> str | None:
    if _is_local_path(spec):
        return None
    if spec.startswith(_NPM_GIT_PREFIXES) or _GITHUB_SHORTHAND.fullmatch(spec):
        source, _, ref = spec.partition("#")
        return None if _COMMIT.fullmatch(ref) else f"pin a commit, e.g. {source}#<commit-sha>"
    if "://" in spec:
        return None
    at = spec.rfind("@")
    name, version = (spec[:at], spec[at + 1 :]) if at > 0 else (spec, "")
    return None if _SEMVER.fullmatch(version) else f"pin an exact version, e.g. {name}@<x.y.z>"


def _python_fix(spec: str) -> str | None:
    if "git+" in spec:
        if _PY_GIT_COMMIT.search(spec):
            return None
        return f"pin a commit, e.g. {_GIT_REF.sub('', spec)}@<commit-sha>"
    if _is_local_path(spec) or "://" in spec or "/" in spec:
        return None
    if _PEP440_EXACT.fullmatch(spec) or _UV_AT_VERSION.fullmatch(spec):
        return None
    name = re.match(r"[A-Za-z0-9._-]*", spec)
    return f"pin an exact version, e.g. {name.group() if name else spec}==<x.y.z>"


def _image_fix(image: str) -> str | None:
    if "@sha256:" in image:
        return None
    last = image.rsplit("/", 1)[-1]
    repository, _, tag = last.partition(":")
    if tag and tag != "latest":
        return None
    base = image[: len(image) - len(last)] + repository
    return f"pin a version tag or digest, e.g. {base}@sha256:<digest>"


@dataclass(frozen=True)
class _Launcher:
    tool: str
    noun: str
    fix: Callable[[str], str | None]
    package_flags: frozenset[str] = frozenset()
    value_flags: frozenset[str] = frozenset()


_NPX = _Launcher(
    "npx",
    "package",
    _npm_fix,
    frozenset({"-p", "--package"}),
    frozenset(
        {"-c", "--call", "--registry", "--cache", "--userconfig", "-w", "--workspace", "--prefix"}
    ),
)
_UV_VALUE_FLAGS = frozenset(
    {
        "--with",
        "--with-editable",
        "--with-requirements",
        "-p",
        "--python",
        "--python-preference",
        "--index",
        "--default-index",
        "-i",
        "--index-url",
        "--extra-index-url",
        "-f",
        "--find-links",
        "--index-strategy",
        "--keyring-provider",
        "-c",
        "--constraints",
        "--overrides",
        "-b",
        "--build-constraints",
        "-C",
        "--config-setting",
        "--resolution",
        "--prerelease",
        "--exclude-newer",
        "--link-mode",
        "-P",
        "--upgrade-package",
        "--reinstall-package",
        "--refresh-package",
        "--no-build-package",
        "--no-binary-package",
        "--allow-insecure-host",
        "--env-file",
        "--directory",
        "--project",
        "--cache-dir",
        "--config-file",
        "--color",
    }
)
_CONTAINER_VALUE_FLAGS = frozenset(
    {
        "-a",
        "--attach",
        "--add-host",
        "--annotation",
        "--arch",
        "--authfile",
        "--blkio-weight",
        "--blkio-weight-device",
        "--cap-add",
        "--cap-drop",
        "--cgroup-parent",
        "--cgroupns",
        "--cidfile",
        "-c",
        "--cpu-shares",
        "--cpu-period",
        "--cpu-quota",
        "--cpu-rt-period",
        "--cpu-rt-runtime",
        "--cpus",
        "--cpuset-cpus",
        "--cpuset-mems",
        "--creds",
        "--detach-keys",
        "--device",
        "--device-cgroup-rule",
        "--device-read-bps",
        "--device-read-iops",
        "--device-write-bps",
        "--device-write-iops",
        "--dns",
        "--dns-option",
        "--dns-search",
        "--domainname",
        "-e",
        "--env",
        "--entrypoint",
        "--env-file",
        "--expose",
        "--gidmap",
        "--gpus",
        "--group-add",
        "--health-cmd",
        "--health-interval",
        "--health-retries",
        "--health-start-interval",
        "--health-start-period",
        "--health-timeout",
        "-h",
        "--hostname",
        "--ip",
        "--ip6",
        "--ipc",
        "--isolation",
        "--kernel-memory",
        "-l",
        "--label",
        "--label-file",
        "--link",
        "--link-local-ip",
        "--log-driver",
        "--log-opt",
        "--mac-address",
        "-m",
        "--memory",
        "--memory-reservation",
        "--memory-swap",
        "--memory-swappiness",
        "--mount",
        "--name",
        "--net",
        "--network",
        "--network-alias",
        "--oom-score-adj",
        "--os",
        "-p",
        "--publish",
        "--pid",
        "--pids-limit",
        "--platform",
        "--pod",
        "--pull",
        "--restart",
        "--runtime",
        "--secret",
        "--security-opt",
        "--shm-size",
        "--stop-signal",
        "--stop-timeout",
        "--storage-opt",
        "--sysctl",
        "--tmpfs",
        "--tz",
        "--uidmap",
        "--ulimit",
        "--umask",
        "--unsetenv",
        "-u",
        "--user",
        "--userns",
        "--uts",
        "--variant",
        "-v",
        "--volume",
        "--volume-driver",
        "--volumes-from",
        "-w",
        "--workdir",
    }
)
_UV = _Launcher("uvx", "package", _python_fix, frozenset({"--from"}), _UV_VALUE_FLAGS)
_DOCKER = _Launcher("docker", "image", _image_fix, value_flags=_CONTAINER_VALUE_FLAGS)
_PODMAN = _Launcher("podman", "image", _image_fix, value_flags=_CONTAINER_VALUE_FLAGS)

# Keyed by the leading argv words (program name lowercased, without .exe/.cmd).
_LAUNCHERS: dict[tuple[str, ...], _Launcher] = {
    ("npx",): _NPX,
    ("npm", "exec"): _Launcher(
        "npm exec", "package", _npm_fix, _NPX.package_flags, _NPX.value_flags
    ),
    ("npm", "x"): _Launcher("npm exec", "package", _npm_fix, _NPX.package_flags, _NPX.value_flags),
    ("bunx",): _Launcher(
        "bunx", "package", _npm_fix, frozenset({"-p", "--package"}), frozenset({"--cwd"})
    ),
    ("pnpm", "dlx"): _Launcher(
        "pnpm dlx",
        "package",
        _npm_fix,
        frozenset({"--package"}),
        frozenset({"--allow-build", "--registry", "--reporter", "-C", "--dir"}),
    ),
    ("yarn", "dlx"): _Launcher("yarn dlx", "package", _npm_fix, frozenset({"-p", "--package"})),
    ("uvx",): _UV,
    ("uv", "tool", "run"): _Launcher(
        "uv tool run", "package", _python_fix, _UV.package_flags, _UV.value_flags
    ),
    ("pipx", "run"): _Launcher(
        "pipx run",
        "package",
        _python_fix,
        frozenset({"--spec"}),
        frozenset({"--python", "--pip-args", "-i", "--index-url", "--backend"}),
    ),
    ("docker", "run"): _DOCKER,
    ("docker", "container", "run"): _DOCKER,
    ("podman", "run"): _PODMAN,
    ("podman", "container", "run"): _PODMAN,
}
_LONGEST_PREFIX = max(len(prefix) for prefix in _LAUNCHERS)
_PROGRAMS = frozenset({prefix[0] for prefix in _LAUNCHERS} | {"cmd"})


def _split_line(line: str) -> list[str]:
    try:
        return shlex.split(line, posix=True)
    except ValueError:
        return line.split()


def _command_words(command: str) -> list[str]:
    if not any(char.isspace() for char in command):
        return [command]
    # A path with spaces to a launcher is one word; anything else is a whole command line.
    if _PATH_START.match(command) and _program(command) in _PROGRAMS:
        return [command]
    return _split_line(command)


def _argv(launch: StdioLaunch) -> list[str]:
    argv = [*_command_words(launch.command.strip()), *launch.args]
    if len(argv) > 2 and _program(argv[0]) == "cmd" and argv[1].lower() in ("/c", "/k"):
        argv = argv[2:]
        if len(argv) == 1:
            argv = _split_line(argv[0])
    return argv


def _program(word: str) -> str:
    name = PureWindowsPath(word).name.lower()
    for suffix in _EXECUTABLE_SUFFIXES:
        name = name.removesuffix(suffix)
    return name


def _launcher(argv: list[str]) -> tuple[_Launcher, list[str]] | None:
    if not argv:
        return None
    words = [_program(argv[0]), *(word.lower() for word in argv[1:_LONGEST_PREFIX])]
    for length in range(_LONGEST_PREFIX, 0, -1):
        launcher = _LAUNCHERS.get(tuple(words[:length]))
        if launcher is not None:
            return launcher, argv[length:]
    return None


def _specs(launcher: _Launcher, args: list[str]) -> list[str]:
    """The package specs a launcher installs: its package flags, else its first positional."""
    explicit: list[str] = []
    positional: str | None = None
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            positional = args[i + 1] if i + 1 < len(args) else None
            break
        if not arg.startswith("-") or arg == "-":
            positional = arg
            break
        name, has_value, value = arg.partition("=")
        if name in launcher.package_flags:
            if has_value:
                explicit.append(value)
            elif i + 1 < len(args):
                explicit.append(args[i + 1])
                i += 1
        elif name in launcher.value_flags and not has_value:
            i += 1
        i += 1
    if explicit:
        return explicit
    return [] if positional is None else [positional]


def _finding(server: McpServer, launch: StdioLaunch) -> Finding | None:
    found = _launcher(_argv(launch))
    if found is None:
        return None
    launcher, args = found
    for spec in _specs(launcher, args):
        if not spec or _is_unresolved(spec):
            continue
        fix = launcher.fix(spec)
        if fix is None:
            continue
        shown = _USERINFO.sub("", spec)
        return Finding(
            rule_id="ABOM-005",
            severity="medium",
            confidence="high",
            message=(
                f'server "{server.name}" runs {launcher.tool} {launcher.noun} "{shown}" '
                "without an exact version"
            ),
            location=Location(path=server.source.path),
            artifact_id=server.id,
            fix=_USERINFO.sub("", fix),
        )
    return None


class UnpinnedServer:
    rule_id: RuleId = "ABOM-005"

    def run(self, artifacts: Sequence[Artifact]) -> Iterator[Finding]:
        for artifact in artifacts:
            if isinstance(artifact, McpServer) and isinstance(artifact.launch, StdioLaunch):
                finding = _finding(artifact, artifact.launch)
                if finding is not None:
                    yield finding
