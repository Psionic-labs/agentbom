# Working on agentbom

- The scanner reads files and never runs them. Never add network or subprocess calls under `src/agentbom/`; ruff's `banned-api` check (TID251) rejects them. Scripts and tests may use them.
- Run `uv run ruff check`, `uv run ruff format`, `uv run mypy` and `uv run pytest` before finishing a task.
