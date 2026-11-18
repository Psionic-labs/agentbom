"""PreToolUse hook: all work happens in this one directory, never in extra worktrees or clones."""

import json
import re
import sys

BLOCKED_COMMAND = re.compile(
    r"(?:^|[;&|(]|\$\()\s*git\b[^\n;|&`]*?\b(worktree\s+add|clone)\b", re.MULTILINE
)
REASON = (
    "Blocked: work only in D:\\Coding\\agentbom. Do not create worktrees, clones or "
    "sibling folders; switch branches in place with `git switch` instead."
)


def is_blocked(event: dict) -> bool:
    tool = event.get("tool_name", "")
    tool_input = event.get("tool_input") or {}
    if tool == "EnterWorktree":
        return True
    if tool == "Agent" and tool_input.get("isolation") == "worktree":
        return True
    if tool in ("Bash", "PowerShell"):
        return bool(BLOCKED_COMMAND.search(tool_input.get("command", "")))
    return False


def main() -> int:
    if is_blocked(json.load(sys.stdin)):
        print(REASON, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
