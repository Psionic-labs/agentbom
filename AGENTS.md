# Working on agentbom

- The scanner reads files and never runs them. Never add network or subprocess calls under `src/agentbom/`; ruff's `banned-api` check (TID251) rejects them. Scripts and tests may use them.
- Keep parsing pure: parsers turn text into artifacts. Only `discover.py` and `cli.py` touch the filesystem.
- To support a new agent file, add a row to `src/agentbom/registry.py`, and a parser only when the file has a new format.
- Detection rules will live in `src/agentbom/rules/`, one file each. Every rule needs fixtures (3 malicious, 3 benign) and a test before merging.
- Run `uv run python scripts/fetch_samples.py` once to check out the sample repositories under `.samples/`; the sample tests fail without them.
- Run `uv run ruff check`, `uv run ruff format`, `uv run mypy` and `uv run pytest` before finishing a task.
- Do not edit fixtures or the expected inventories in `tests/samples/` to make a test pass; fix the code.
