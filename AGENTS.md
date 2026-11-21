# Working on agentbom

- The scanner reads files and never runs them. Never add network or subprocess calls under `src/agentbom/`; ruff's `banned-api` check (TID251) rejects them. Scripts and tests may use them.
- Keep parsing pure: parsers turn text into artifacts. Only `discover.py` and `cli.py` touch the filesystem.
- To support a new agent file, add a row to `src/agentbom/registry.py`, and a parser only when the file has a new format.
- Detection rules live in `src/agentbom/rules/`, one file each, registered in `RULES`. Rules see only artifacts, never files. Text rules iterate `surfaces()` from `rules/_surfaces.py` and map each context to a severity through one table per rule. Every rule needs fixtures (3 malicious, 3 benign) under `fixtures/<RULE-ID>/` before merging.
- ABOM-006 (drift) is the one rule outside `RULES`, because it needs the lockfile: `lockfile.diff_lock` computes drift and `rules/abom_006_drift.py` turns it into findings. Its fixtures come from `scripts/make_drift_fixtures.py`, which locks each case before editing it; add cases there, never write a lockfile by hand.
- This repository gates its own pull requests with `action/` and `.github/workflows/agentbom.yml`. Adding or editing an agent file, including anything under `fixtures/`, changes what `agentbom.lock` records: run `uv run agentbom lock` and commit the lockfile. `agentbom.policy.yml` ignores the fixture findings; never add an ignore to make a real finding pass.
- Run `uv run python scripts/fetch_samples.py` once to check out the sample repositories under `.samples/`; the sample tests fail without them.
- Run `uv run ruff check`, `uv run ruff format`, `uv run mypy` and `uv run pytest` before finishing a task.
- Do not edit fixtures or the expected inventories in `tests/samples/` to make a test pass; fix the code.
