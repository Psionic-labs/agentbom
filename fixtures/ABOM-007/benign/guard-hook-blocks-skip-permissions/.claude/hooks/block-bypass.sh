#!/usr/bin/env bash
# Refuse to start a nested claude run with --dangerously-skip-permissions.
cmd=$(jq -r ".tool_input.command")
if printf '%s' "$cmd" | grep -q -- '--dangerously-skip-permissions'; then
  echo "permission bypass is not allowed" >&2
  exit 2
fi
