import pytest

from agentbom.models import Finding, Location, McpServer, RemoteLaunch, Rules, Script, StdioLaunch
from agentbom.rules.abom_010_secrets import EmbeddedSecrets

# Fake values assembled at runtime that match each provider's format.
ALNUM = "Q7mZ2vK9pL4xR8tN1wB6yH3jC5dF0gS2aE7uI9oP4kM1nV6b"
TOKENS = {
    "a GitHub token": "ghp_" + ALNUM[:36],
    "an Anthropic API key": "sk-ant-api03-" + (ALNUM * 2)[:90],
    "an OpenAI API key": "sk-" + ALNUM[:48],
    "an AWS access key": "ASIA" + "2E0A8F3B5C7D9E1F",
    "a Google API key": "AIza" + ALNUM[:35],
    "a Slack token": "xoxp-" + "1234567890-0987654321-" + ALNUM[:24],
    "a Stripe live key": "sk_" + "live_" + ALNUM[:24],
    "a GitLab token": "glpat-" + ALNUM[:20],
    "an npm token": "npm_" + ALNUM[:36],
    "a Hugging Face token": "hf_" + ALNUM[:34],
    "a SendGrid API key": "SG." + ALNUM[:22] + "." + ALNUM[:43],
    "a private key": "-----BEGIN RSA PRIVATE KEY-----\n"
    + ALNUM
    + "\n-----END RSA PRIVATE KEY-----",
}
SECRET = "Zx81Kq3LmP0vT7rW2sY9"


def _script(body: str) -> Script:
    return Script(
        name="s.sh", source=Location(path="s.sh", line=1), agents=(), language="shell", body=body
    )


def _server(env: dict[str, str]) -> McpServer:
    return McpServer(
        name="srv",
        source=Location(path=".mcp.json"),
        agents=(),
        launch=StdioLaunch(transport="stdio", command="./server", env=env),
    )


def _remote(headers: dict[str, str]) -> McpServer:
    return McpServer(
        name="srv",
        source=Location(path=".mcp.json"),
        agents=(),
        launch=RemoteLaunch(transport="http", url="https://mcp.company.io", headers=headers),
    )


def _rules(body: str) -> Rules:
    return Rules(
        name="AGENTS.md",
        source=Location(path="AGENTS.md", line=1),
        agents=(),
        frontmatter={},
        body=body,
        body_line=1,
    )


def _messages(*artifacts: Script | McpServer | Rules) -> list[str]:
    return [finding.message for finding in EmbeddedSecrets().run(artifacts)]


@pytest.mark.parametrize(("provider", "token"), TOKENS.items())
def test_known_tokens_are_flagged_in_every_context(provider: str, token: str) -> None:
    assert _messages(_rules(f"Use {token} here.")) == [f"body contains {provider}"]
    assert _messages(_script(f"run '{token}'")) == [f"body contains {provider}"]
    assert _messages(_server({"VALUE": token})) == [f"env.VALUE contains {provider}"]


@pytest.mark.parametrize(
    "text",
    [
        "AKIAIOSFODNN7EXAMPLE",
        "ghp_" + "x" * 36,
        "ghp_" + "your_token_goes_here_0123456789abcdef",
        "sk-proj-" + "X" * 48,
        "xoxb-your-bot-token-here",
        "AKIA" + "0" * 16,
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
    ],
)
def test_placeholders_are_not_flagged(text: str) -> None:
    assert _messages(_rules(text), _server({"GITHUB_TOKEN": text})) == []


@pytest.mark.parametrize("text", ["ghp_" + ALNUM[:20], "mask-" + ALNUM[:48], "xsk-" + ALNUM[:48]])
def test_near_misses_of_known_formats_are_not_flagged(text: str) -> None:
    assert _messages(_rules(text), _server({"VALUE": text})) == []


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("GITHUB_TOKEN", SECRET),
        ("DB_PASSWORD", "hT9#".replace("#", "x") + "kL2mN8pQ4rS6vW1y"),
        ("X-Api-Key", "3f2a9c1e-7b4d-4e8a-9c2f-1a6b3d5e7f90"),
        ("client_secret", "aB3dE5gH7jK9mN1pQ3sT"),
        ("Authorization", "Bearer " + SECRET),
        ("Authorization", "Basic dXNlcjpzM2NyZXRQYXNzd29yZDE="),
    ],
)
def test_keyed_literals_in_config_are_flagged(key: str, value: str) -> None:
    expected = [f"env.{key} looks like a hard-coded secret"]
    assert _messages(_server({key: value})) == expected
    assert _messages(_remote({key: value})) == [f"headers.{key} looks like a hard-coded secret"]


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("GITHUB_TOKEN", "${GITHUB_TOKEN}"),
        ("GITHUB_TOKEN", "$GITHUB_TOKEN"),
        ("GITHUB_TOKEN", "${input:github_token}"),
        ("GITHUB_TOKEN", "{{ secrets.GH_TOKEN_2 }}"),
        ("GITHUB_TOKEN", "%GITHUB_TOKEN%"),
        ("GITHUB_TOKEN", "<paste-token-2-here>"),
        ("Authorization", "Bearer ${env:API_TOKEN}"),
        ("API_KEY", "your-api-key-goes-here-123"),
        ("API_KEY", "test_9a8b7c6d5e4f3a2b1c"),
        ("API_KEY", "aaaaaaaaaaaaaaaaaaaa1"),
        ("API_KEY", "short9a8b7c"),
        ("API_KEY", "abcdefghijklmnopqrstuvwxyz"),
        ("API_KEY", "client-credentials-v2-flow"),
        ("API_KEY", "process.env.OPENAI_KEY_2"),
        ("API_KEY", "a1a1a1a1a1a1a1a1a1a1"),
        ("TOKEN_URL", "https://auth.company.io/oauth2/v1/token"),
        ("TOKEN_FILE", "/run/secrets/gh_token2"),
        ("AUTH_CLIENT_ID", "9a8b7c6d5e4f3a2b1c0d"),
        ("GIT_AUTHOR_EMAIL", "dev9a8b7c6d@company.io"),
        ("MODEL", SECRET),
    ],
)
def test_references_placeholders_and_non_secret_keys_are_not_flagged(key: str, value: str) -> None:
    assert _messages(_server({key: value}), _remote({key: value})) == []


@pytest.mark.parametrize(
    ("body", "key"),
    [
        (f"publish --api-key={SECRET}", "--api-key"),
        (f"publish --auth-token {SECRET}", "--auth-token"),
        (f'curl -H "Authorization: Bearer {SECRET}" https://x', "Authorization"),
        (f"export GH_TOKEN={SECRET}", "GH_TOKEN"),
        (f'const apiKey = "{SECRET}";', "apiKey"),
        (f'{{"client_secret": "{SECRET}"}}', "client_secret"),
    ],
)
def test_keyed_literals_in_commands_are_flagged(body: str, key: str) -> None:
    assert _messages(_script(body)) == [f"body looks like a hard-coded secret ({key})"]


@pytest.mark.parametrize(
    "body",
    [
        'publish --token "$NPM_TOKEN"',
        "publish --token-file ./token.txt",
        'curl -H "Authorization: Bearer ${API_TOKEN}"',
        "const apiKey = process.env.OPENAI_API_KEY_V2;",
        'const TOKEN_STORAGE_KEY = "app.auth.token.v1";',
        f"echo {SECRET}",
        f"MODEL={SECRET}",
    ],
)
def test_commands_without_literal_secrets_are_not_flagged(body: str) -> None:
    assert _messages(_script(body)) == []


def test_generic_values_are_not_checked_in_prose() -> None:
    assert _messages(_rules(f"Set GITHUB_TOKEN={SECRET} first.")) == []


def test_a_known_token_is_not_also_reported_as_generic() -> None:
    token = TOKENS["a GitHub token"]
    assert _messages(_server({"GITHUB_TOKEN": token})) == [
        "env.GITHUB_TOKEN contains a GitHub token"
    ]
    assert _messages(_script(f"export GH_TOKEN={token}")) == ["body contains a GitHub token"]


def test_private_key_in_a_quoted_string_with_escaped_newlines() -> None:
    body = 'KEY="-----BEGIN EC PRIVATE KEY-----\\n' + ALNUM + '\\n-----END EC PRIVATE KEY-----"'
    assert _messages(_script(body)) == ["body contains a private key"]


def test_one_finding_per_family_with_the_first_line() -> None:
    first, second = TOKENS["a GitHub token"], "ghs_" + ALNUM[2:40]
    body = (
        f"intro\nA={first}\nB={second}\nexport API_TOKEN={SECRET}\nexport AUTH_SECRET={SECRET}x\n"
    )
    findings = list(EmbeddedSecrets().run([_script(body)]))
    assert [(f.message, f.location.line, f.confidence) for f in findings] == [
        ("body contains a GitHub token", 2, "high"),
        ("body looks like a hard-coded secret (API_TOKEN)", 4, "medium"),
    ]


def test_finding_never_contains_the_value() -> None:
    findings = list(EmbeddedSecrets().run([_server({"GITHUB_TOKEN": TOKENS["a GitHub token"]})]))
    assert findings == [
        Finding(
            rule_id="ABOM-010",
            severity="high",
            confidence="high",
            message="env.GITHUB_TOKEN contains a GitHub token",
            location=Location(path=".mcp.json"),
            artifact_id="mcp_server:.mcp.json:srv",
            fix="move the secret to an environment variable and reference it as ${NAME}; "
            "rotate the exposed value",
        )
    ]
    for token in TOKENS.values():
        for finding in EmbeddedSecrets().run([_script(f"X={token}")]):
            assert token[:8] not in finding.message
            assert token[-8:] not in finding.message
