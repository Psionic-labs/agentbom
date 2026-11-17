# agentbom

agentbom lists the agent context a repository loads: MCP servers, skills,
hooks, the scripts they run, project settings and rules or instruction
files for Claude Code, Cursor, VS Code,
GitHub Copilot, Codex and `AGENTS.md`. It reads files and never runs them,
and it makes no network calls.

Today it has one command, `scan`, which prints an inventory and the
findings of its detection rules. A lockfile and CI checks are not built
yet.

## Install from source

Requires [uv](https://docs.astral.sh/uv/) and Python 3.11 or later.

```sh
git clone <this repository>
cd agentbom
uv sync
uv run agentbom scan path/to/repo
```

## Usage

```sh
agentbom scan [PATH] [--format terminal|json] [--fail-on high|medium|low]
```

`PATH` defaults to the current directory. The terminal format prints a
summary line, a table and one line per finding:

```text
MED   ABOM-005  .mcp.json  server "docs" runs npx package "docs-mcp" without an exact version
1 finding (0 high, 1 medium, 0 low).
```

The JSON format prints a document with `schema_version` (2), `artifacts`,
`errors` and `findings`. Each finding has a `rule_id`, `severity`,
`confidence`, `message`, `location`, `artifact_id` and `fix`. Messages
never quote a secret value.

Both formats leave out secrets: MCP server `env` and `headers` and the
settings `env` show their keys only. JSON output leaves out skill, rules
and script bodies and gives each artifact a `content_hash` instead.

The scan skips `.git`, files and directories matched by `.gitignore`, and
symlinks. Files larger than 2 MiB, files that are not UTF-8 and files that
do not parse are reported as errors.

Exit codes: `2` when `PATH` is not a directory or any file could not be
read or parsed, because a partial scan cannot be trusted; otherwise `1`
when a finding has the `--fail-on` severity (default `high`) or higher;
otherwise `0`.

## What it finds

The patterns live in `src/agentbom/registry.py`.

| Kind | Files |
| --- | --- |
| MCP servers | `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json` |
| Hooks | `.claude/settings.json`, `.claude/settings.local.json`, `.codex/hooks.json`, `.cursor/hooks.json`, `.github/hooks/*.json` |
| Settings | `.claude/settings.json`, `.claude/settings.local.json` (permissions, `enableAllProjectMcpServers`, `env`) |
| Scripts | Shell, PowerShell, Python, JavaScript, TypeScript, Ruby, Perl and batch files under `.claude/hooks/`, `.cursor/hooks/`, `.codex/hooks/`, `.github/hooks/` and inside any skill directory listed below |
| Skills | `.claude/skills/*/SKILL.md` (at any depth), `.agents/skills/*/SKILL.md`, `.cursor/skills/*/SKILL.md`, `.github/skills/*/SKILL.md` |
| Rules files | `AGENTS.md`, `CLAUDE.md`, `CLAUDE.local.md` (at any depth), `.claude/rules/**/*.md` (at any depth), `.claude/commands/**/*.md`, `.claude/agents/**/*.md`, `.cursorrules`, `.cursor/rules/**/*.mdc` (at any depth), `.github/copilot-instructions.md`, `.github/instructions/**/*.instructions.md`, `.github/prompts/**/*.prompt.md`, `.github/agents/**/*.md` |

## Rules

Each rule lives in `src/agentbom/rules/` and is proven by the malicious and
benign cases under `fixtures/<RULE-ID>/`.

| ID | Rule | Severity | Confidence |
| --- | --- | --- | --- |
| ABOM-005 | Unpinned server: an MCP server launched with `npx`, `bunx`, `npm exec`, `pnpm dlx`, `yarn dlx`, `uvx`, `uv tool run`, `pipx run`, `docker run` or `podman run` from a package without an exact version, a git source without a commit, or an image with no tag or `latest` | Medium | High |

## License

Apache-2.0
