# agentbom

agentbom lists the agent context a repository loads: MCP servers, skills,
hooks and rules or instruction files for Claude Code, Cursor, VS Code,
GitHub Copilot, Codex and `AGENTS.md`. It reads files and never runs them,
and it makes no network calls.

Today it has one command, `scan`, which prints an inventory. Detection
rules, a lockfile and CI checks are not built yet.

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
agentbom scan [PATH] [--format terminal|json]
```

`PATH` defaults to the current directory. The terminal format prints a
summary line and a table. The JSON format prints a document with
`schema_version`, `artifacts` and `errors`.

Both formats leave out secrets: MCP server `env` and `headers` show their
keys only. JSON output leaves out skill and rules bodies and gives each
artifact a `content_hash` instead.

The scan skips `.git`, files and directories matched by `.gitignore`, and
symlinks. Files larger than 2 MiB, files that are not UTF-8 and files that
do not parse are reported as errors.

Exit codes: `0` when the scan finished without errors, `2` when `PATH` is
not a directory or any file could not be read or parsed.

## What it finds

The patterns live in `src/agentbom/registry.py`.

| Kind | Files |
| --- | --- |
| MCP servers | `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json` |
| Hooks | `.claude/settings.json`, `.claude/settings.local.json`, `.codex/hooks.json`, `.cursor/hooks.json`, `.github/hooks/*.json` |
| Skills | `.claude/skills/*/SKILL.md` (at any depth), `.agents/skills/*/SKILL.md`, `.cursor/skills/*/SKILL.md`, `.github/skills/*/SKILL.md` |
| Rules files | `AGENTS.md`, `CLAUDE.md`, `CLAUDE.local.md` (at any depth), `.claude/rules/**/*.md` (at any depth), `.claude/commands/**/*.md`, `.claude/agents/**/*.md`, `.cursorrules`, `.cursor/rules/**/*.mdc` (at any depth), `.github/copilot-instructions.md`, `.github/instructions/**/*.instructions.md`, `.github/prompts/**/*.prompt.md`, `.github/agents/**/*.md` |

## License

Apache-2.0
