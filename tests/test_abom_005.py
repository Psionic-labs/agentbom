import pytest

from agentbom.models import Finding, Location, McpServer, RemoteLaunch, StdioLaunch
from agentbom.rules.abom_005_unpinned import UnpinnedServer

SHA = "4f2c9d0a6b1e3f5a7c9e1b3d5f7a9c1e3b5d7f9a"


def _run(command: str, *args: str) -> list[Finding]:
    server = McpServer(
        name="srv",
        source=Location(path=".mcp.json"),
        agents=("claude_code",),
        launch=StdioLaunch(transport="stdio", command=command, args=args),
    )
    return list(UnpinnedServer().run([server]))


def _flagged_spec(command: str, *args: str) -> str | None:
    findings = _run(command, *args)
    if not findings:
        return None
    (finding,) = findings
    return finding.message.split('"')[3]


@pytest.mark.parametrize(
    ("argv", "spec"),
    [
        (("npx", "-y", "pkg"), "pkg"),
        (("npx", "pkg@latest"), "pkg@latest"),
        (("npx", "pkg@next"), "pkg@next"),
        (("npx", "pkg@^1.2.3"), "pkg@^1.2.3"),
        (("npx", "pkg@~1.2.3"), "pkg@~1.2.3"),
        (("npx", "pkg@>=1.2.3"), "pkg@>=1.2.3"),
        (("npx", "pkg@1"), "pkg@1"),
        (("npx", "pkg@1.2"), "pkg@1.2"),
        (("npx", "pkg@1.x"), "pkg@1.x"),
        (("npx", "pkg@*"), "pkg@*"),
        (("npx", "@scope/pkg"), "@scope/pkg"),
        (("npx", "@scope/pkg@latest"), "@scope/pkg@latest"),
        (("npx", "-y", "--prefer-offline", "-q", "pkg"), "pkg"),
        (("npx", "--registry", "https://r.example", "pkg"), "pkg"),
        (("npx", "-p", "pkg", "bin"), "pkg"),
        (("npx", "--package=pkg@1.2.3", "--package=other", "bin"), "other"),
        (("npx", "-y", "--", "pkg@1.2"), "pkg@1.2"),
        (("npx", "github:o/r"), "github:o/r"),
        (("npx", "o/r#main"), "o/r#main"),
        (("npx", "git+https://github.com/o/r.git#v1.0.0"), "git+https://github.com/o/r.git#v1.0.0"),
        (("bunx", "pkg"), "pkg"),
        (("pnpm", "dlx", "pkg"), "pkg"),
        (("yarn", "dlx", "-q", "pkg@latest"), "pkg@latest"),
        (("npm", "exec", "--yes", "--", "pkg"), "pkg"),
        (("npx.cmd", "-y", "pkg"), "pkg"),
        (("C:\\Program Files\\nodejs\\npx.cmd", "-y", "pkg"), "pkg"),
        (("/usr/local/bin/npx", "pkg"), "pkg"),
        (("npx -y pkg",), "pkg"),
        (("npx -y 'pkg@1.2'",), "pkg@1.2"),
        (("cmd", "/c", "npx", "-y", "pkg"), "pkg"),
        (("cmd.exe", "/C", "npx -y pkg"), "pkg"),
        (("uvx", "mcp-server-fetch"), "mcp-server-fetch"),
        (("uvx", "mcp-server-fetch>=1.0"), "mcp-server-fetch>=1.0"),
        (("uvx", "mcp-server-fetch~=1.0"), "mcp-server-fetch~=1.0"),
        (("uvx", "mcp-server-fetch==1.*"), "mcp-server-fetch==1.*"),
        (("uvx", "tool@latest"), "tool@latest"),
        (("uvx", "--python", "3.12", "tool"), "tool"),
        (("uvx", "--from", "tool>=1", "tool-cli"), "tool>=1"),
        (
            ("uvx", "--from", "git+https://github.com/o/r@main", "t"),
            "git+https://github.com/o/r@main",
        ),
        (("uv", "tool", "run", "tool"), "tool"),
        (("pipx", "run", "--spec", "tool", "t"), "tool"),
        (("pipx", "run", "tool"), "tool"),
        (("docker", "run", "-i", "--rm", "img"), "img"),
        (("docker", "run", "-i", "--rm", "img:latest"), "img:latest"),
        (("docker", "run", "--pull", "always", "-e", "K", "ghcr.io/o/img"), "ghcr.io/o/img"),
        (("docker", "run", "--name=x", "-v", "/a:/b", "img"), "img"),
        (("docker", "run", "localhost:5000/img"), "localhost:5000/img"),
        (("docker", "container", "run", "img"), "img"),
        (("podman", "run", "-it", "img"), "img"),
    ],
)
def test_unpinned_launches_are_flagged(argv: tuple[str, ...], spec: str) -> None:
    assert _flagged_spec(*argv) == spec


@pytest.mark.parametrize(
    "argv",
    [
        ("npx", "-y", "pkg@1.2.3"),
        ("npx", "pkg@v1.2.3"),
        ("npx", "pkg@1.2.3-beta.1+build.5"),
        ("npx", "@scope/pkg@0.0.1"),
        ("npx", "-p", "pkg@1.2.3", "unpinned-bin-name"),
        ("npx", f"github:o/r#{SHA}"),
        ("npx", f"o/r#{SHA}"),
        ("npx", "./server"),
        ("npx", "../server"),
        ("npx", "/opt/server"),
        ("npx", "file:../server"),
        ("npx", "C:\\servers\\x"),
        ("npx", "https://example.com/pkg-1.2.3.tgz"),
        ("npx", "-c", "eslint ."),
        ("npx", "pkg@${VERSION}"),
        ("npx",),
        ("pnpm", "exec", "pkg"),
        ("uvx", "mcp-server-fetch==2025.4.7"),
        ("uvx", "mcp-server-fetch===1.0"),
        ("uvx", "tool[extra]==1.2.3"),
        ("uvx", "tool@1.2.3"),
        ("uvx", "--from", "tool==1.2.3", "tool-cli"),
        ("uvx", "--from", f"git+https://github.com/o/r@{SHA}", "t"),
        ("uvx", "--from", ".", "t"),
        ("uv", "run", "server.py"),
        ("pipx", "run", "--spec", "tool==1.0", "t"),
        ("docker", "run", "-i", "img:1.2.0"),
        ("docker", "run", "-i", "img:v1"),
        ("docker", "run", "img@sha256:" + "a" * 64),
        ("docker", "run", "localhost:5000/img:2.0"),
        ("docker", "run", "$IMAGE"),
        ("docker", "ps"),
        ("node", "server.js"),
        ("python", "-m", "server"),
        ("bash", "-c", "npx -y pkg"),
        ("/opt/bin/server",),
    ],
)
def test_pinned_local_and_other_launches_are_not_flagged(argv: tuple[str, ...]) -> None:
    assert _run(*argv) == []


def test_finding_shape() -> None:
    (finding,) = _run("npx", "-y", "@scope/pkg@^1.0.0")
    assert finding == Finding(
        rule_id="ABOM-005",
        severity="medium",
        confidence="high",
        message='server "srv" runs npx package "@scope/pkg@^1.0.0" without an exact version',
        location=Location(path=".mcp.json"),
        artifact_id="mcp_server:.mcp.json:srv",
        fix="pin an exact version, e.g. @scope/pkg@<x.y.z>",
    )


@pytest.mark.parametrize(
    ("argv", "fix"),
    [
        (("uvx", "tool>=1"), "pin an exact version, e.g. tool==<x.y.z>"),
        (("npx", "github:o/r#main"), "pin a commit, e.g. github:o/r#<commit-sha>"),
        (
            ("uvx", "--from", "git+https://github.com/o/r.git@v1", "t"),
            "pin a commit, e.g. git+https://github.com/o/r.git@<commit-sha>",
        ),
        (
            ("docker", "run", "ghcr.io/o/img:latest"),
            "pin a version tag or digest, e.g. ghcr.io/o/img@sha256:<digest>",
        ),
    ],
)
def test_fix_names_the_package(argv: tuple[str, ...], fix: str) -> None:
    (finding,) = _run(*argv)
    assert finding.fix == fix


def test_docker_message_names_an_image() -> None:
    (finding,) = _run("docker", "run", "img")
    assert finding.message == 'server "srv" runs docker image "img" without an exact version'


def test_credentials_in_a_git_url_never_reach_the_message_or_fix() -> None:
    token = "glpat-s3cretValueForTests00"
    (finding,) = _run("uvx", "--from", f"git+https://oauth2:{token}@gitlab.com/o/r", "t")
    assert token not in finding.message
    assert finding.fix is not None
    assert token not in finding.fix
    assert "gitlab.com/o/r" in finding.message


def test_remote_servers_are_not_checked() -> None:
    server = McpServer(
        name="r",
        source=Location(path=".mcp.json"),
        agents=("claude_code",),
        launch=RemoteLaunch(transport="http", url="https://npx.example/latest"),
    )
    assert list(UnpinnedServer().run([server])) == []
