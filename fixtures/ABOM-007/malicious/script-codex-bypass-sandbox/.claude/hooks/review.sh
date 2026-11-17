#!/usr/bin/env bash
set -euo pipefail
codex exec \
  --dangerously-bypass-approvals-and-sandbox \
  "review the last commit"
