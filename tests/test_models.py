import hashlib

from agentbom.models import Location, McpServer, Rules, StdioLaunch


def _rules(path: str, body: str) -> Rules:
    return Rules(
        name=path,
        source=Location(path=path, line=1),
        agents=("agents_md",),
        frontmatter={},
        body=body,
    )


def test_id_is_kind_path_and_name() -> None:
    server = McpServer(
        name="docs",
        source=Location(path=".mcp.json"),
        agents=("claude_code",),
        launch=StdioLaunch(transport="stdio", command="npx"),
    )
    assert server.id == "mcp_server:.mcp.json:docs"


def test_content_hash_is_sha256_of_canonical_content_json() -> None:
    canonical = r'{"body":"Be nice.\n","frontmatter":{},"kind":"rules","name":"AGENTS.md"}'
    expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    assert _rules("AGENTS.md", "Be nice.\n").content_hash == expected


def test_content_hash_ignores_location_and_agents() -> None:
    a = _rules("AGENTS.md", "x")
    b = Rules(
        name="AGENTS.md",
        source=Location(path="AGENTS.md", line=7),
        agents=("cursor", "codex"),
        frontmatter={},
        body="x",
    )
    assert a.content_hash == b.content_hash


def test_content_hash_changes_with_content() -> None:
    assert _rules("AGENTS.md", "x").content_hash != _rules("AGENTS.md", "y").content_hash
