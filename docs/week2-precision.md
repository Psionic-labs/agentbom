# Week 2: per-rule precision on 50 public repositories

Rerun with `uv run python scripts/survey.py scripts/survey_repos.json`. The list pins each
repository to a commit. All 50 scan with zero errors.

A finding counts as a true positive when the flagged text really does what the rule
describes. Severity is judged separately for ABOM-008, where it depends on network access.

| Rule | Findings | True positives | Precision | Notes |
| --- | --- | --- | --- | --- |
| ABOM-001 | 0 | 0 | n/a | No hidden Unicode in the sample |
| ABOM-002 | 4 | 2 | 50% | Both false positives are shell comments in one repo's safety hook |
| ABOM-003 | 5 | 4 | 80% | False positive is a trailing comment in a code block ("tests read ~/.npmrc") |
| ABOM-004 | 2 | 2 | 100% | Both are a Vercel deploy skill uploading a tarball, true to the spec but low value |
| ABOM-005 | 66 | 66 | 100% | No misses among the 9 unflagged launches |
| ABOM-007 | 6 | 6 | 100% | |
| ABOM-008 | 49 | 49 | 100% | Severity: 1 of 24 high findings is wrongly high, after the tuning below |
| ABOM-009 | 0 | 0 | n/a | No override phrases in the sample |
| ABOM-010 | 1 | 1 | 100% | A live-looking `ctx7sk-` key in `.mcp.json` headers |

## Tuning applied

ABOM-008 rated three hooks in parcadei/Continuous-Claude-v3 as high for network access
they do not have. Two causes are fixed, each with regression tests:

- `nc -U` talks to a local Unix socket and no longer counts as network access.
- A method named `fetch` (`conn.fetch(`) no longer counts. The global `fetch(`,
  `globalThis.fetch(` and `window.fetch(` still do.

One remains. A JavaScript keyword list containing the string `"yarn"` reads as a bare
`yarn` install command.

## Open questions

- **Comments in ABOM-002 and ABOM-003.** Three of the four false positives are comments.
  Skipping comments needs a shell quote tracker. A naive one is evadable, because a line
  starting with `#` can sit inside a multi-line string and still run code after the
  string closes.
- **ABOM-008 command substitution.** FastLED is high only because its hook uses `$(...)`
  for a local directory walk. The spec says substitution escalates. The survey suggests
  it should not escalate on its own.
- **Recall gaps found in the sample.** TheMostlyGreat/mythos runs hook scripts from
  `.safeword/hooks/`, which discovery does not read, so two networked hooks stay medium.
  KeepSoftwareSimple/compass-calendar pipes `curl` to `bash` in
  `.cursor/environment.json`, which the registry does not cover.
