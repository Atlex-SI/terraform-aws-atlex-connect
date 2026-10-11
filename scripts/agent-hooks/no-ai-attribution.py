#!/usr/bin/env python3
"""Claude Code PreToolUse hook (Bash): block commits and PRs that carry AI attribution.

Atlex rule C3 (docs/standards/core.md). Looks at `git commit`/`git tag` and `gh pr`/`gh api`/
`gh release` commands, including any message or body file they name (-F, --file, --body-file).
Exit 2 blocks the command and tells the agent why; exit 0 lets it through. Stdlib only.
"""

import json
import os
import re
import shlex
import sys

# Same pattern as the `pr-lint` job in .github/workflows/pr-lint.yml; keep the two in step.
ATTRIBUTION = re.compile(
    r"co-authored-by:.*(claude|anthropic|openai|codex|copilot|chatgpt)"
    r"|generated (with|by) \[?(claude|codex|chatgpt|copilot)"
    r"|noreply@anthropic\.com",
    re.IGNORECASE,
)
WATCHED = re.compile(r"\bgit\b.*\b(commit|tag)\b|\bgh\s+(pr|api|release)\b", re.DOTALL)
FILE_FLAGS = {"-F", "--file", "--body-file"}


def message_files(command: str) -> list[str]:
    try:
        tokens = shlex.split(command)
    except ValueError:
        return []
    files = []
    for i, token in enumerate(tokens):
        if token in FILE_FLAGS and i + 1 < len(tokens):
            files.append(tokens[i + 1])
        else:
            for flag in ("--file=", "--body-file="):
                if token.startswith(flag):
                    files.append(token[len(flag) :])
    return [f for f in files if f != "-"]


def main() -> int:
    payload = json.load(sys.stdin)
    command = (payload.get("tool_input") or {}).get("command") or ""
    if not WATCHED.search(command):
        return 0

    texts = [command]
    cwd = payload.get("cwd") or os.getcwd()
    for name in message_files(command):
        path = os.path.join(cwd, os.path.expanduser(name))
        try:
            with open(path, encoding="utf-8", errors="replace") as handle:
                texts.append(handle.read())
        except OSError:
            pass

    for text in texts:
        match = ATTRIBUTION.search(text)
        if match:
            print(
                f"Blocked by scripts/agent-hooks/no-ai-attribution.py: found AI attribution "
                f"({match.group(0)!r}). Atlex rule C3: no AI co-author trailers in commits and no "
                f"'Generated with' lines in PRs. Remove it and run the command again.",
                file=sys.stderr,
            )
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
