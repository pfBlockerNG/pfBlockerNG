#!/usr/bin/env python3
"""Claude Code Stop-hook guard: block a done-claim with no gate run after it.

PROBLEM
-------
An agent turn edits ``src/``/``tests/`` code, then claims "done"/"fixed"/
"implemented" in its final message without running any canonical gate
(pytest/phpunit/phpstan/phpcs/php -l/ruff/shellcheck/shellspec/mypy) after
the last edit. CLAUDE.md's THE GATE requires an evidenced gate run before a
step is declared done; this hook enforces that mechanically at the Stop
event instead of relying on the agent remembering.

CONTRACT (code.claude.com/docs/en/hooks, Stop event)
-----------------------------------------------------
stdin: a JSON object; documented fields include ``session_id``,
``transcript_path``, ``cwd``, ``hook_event_name`` (``Stop``/``SubagentStop``),
``permission_mode``, ``last_assistant_message``. ``stop_hook_active`` is not
in the documented schema but is honored here if present (loop-guard
forward/backward compat).

Allow the stop: exit 0, no output. Block: print
``{"decision": "block", "reason": "<text>"}`` as the sole stdout line, exit 0.

This script is registered nowhere yet (issue #925 rollout step 1) -- it is
shipped and tested, not wired into ``.claude/settings.json``.
"""

from __future__ import annotations

import json
import re
import sys
from typing import Any

_MARKER = "[stop-guard]"
_BLOCK_REASON = (
    f"{_MARKER} CLAUDE.md THE GATE: code was edited but no gate command ran "
    "after the last edit. Run the canonical gates for the touched languages "
    "and report expected-vs-actual output -- or state explicitly why no gate "
    "applies."
)

_TAIL_LINES = 50

_EDIT_TOOLS = ("Edit", "Write")
_EDIT_PATH_RE = re.compile(r"(^|/)(src|tests)/")
_CLAIM_RE = re.compile(r"\b(done|completed?|implemented|fixed|landed|finished|green)\b", re.IGNORECASE)
_GATE_KEYWORDS = (
    "pytest",
    "phpunit",
    "phpstan",
    "phpcs",
    "php -l",
    "ruff",
    "shellcheck",
    "shellspec",
    "mypy",
)


def _parse_lines(lines: list[str]) -> list[dict[str, Any]]:
    """Best-effort JSONL parse; unparseable/non-dict lines are skipped."""
    entries: list[dict[str, Any]] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(obj, dict):
            entries.append(obj)
    return entries


def _last_genuine_user_index(entries: list[dict[str, Any]]) -> int | None:
    """Index of the last entry that is a real user prompt (not a tool result)."""
    idx: int | None = None
    for i, e in enumerate(entries):
        if e.get("type") == "user" and "toolUseResult" not in e:
            idx = i
    return idx


def _content_items(entry: dict[str, Any]) -> list[dict[str, Any]]:
    message = entry.get("message")
    if not isinstance(message, dict):
        return []
    content = message.get("content")
    if not isinstance(content, list):
        return []
    return [c for c in content if isinstance(c, dict)]


def _last_edit_index(turn: list[dict[str, Any]]) -> int | None:
    """Index of the last entry in ``turn`` that edits a src/tests/ non-.md file."""
    last: int | None = None
    for i, e in enumerate(turn):
        if e.get("type") != "assistant":
            continue
        for item in _content_items(e):
            if item.get("type") != "tool_use" or item.get("name") not in _EDIT_TOOLS:
                continue
            tool_input = item.get("input")
            if not isinstance(tool_input, dict):
                continue
            file_path = tool_input.get("file_path")
            if not isinstance(file_path, str):
                continue
            if _EDIT_PATH_RE.search(file_path) and not file_path.endswith(".md"):
                last = i
    return last


def _gate_ran_after(turn: list[dict[str, Any]], after_index: int) -> bool:
    for i, e in enumerate(turn):
        if i <= after_index or e.get("type") != "assistant":
            continue
        for item in _content_items(e):
            if item.get("type") != "tool_use" or item.get("name") != "Bash":
                continue
            tool_input = item.get("input")
            if not isinstance(tool_input, dict):
                continue
            command = tool_input.get("command")
            if not isinstance(command, str):
                continue
            if any(kw in command for kw in _GATE_KEYWORDS):
                return True
    return False


def _last_assistant_text(turn: list[dict[str, Any]]) -> str:
    for e in reversed(turn):
        if e.get("type") != "assistant":
            continue
        for item in reversed(_content_items(e)):
            if item.get("type") == "text" and isinstance(item.get("text"), str):
                return item["text"]
    return ""


def decide(payload: dict[str, Any], tail_lines: list[str]) -> str | None:
    """Return a block reason, or None to allow the stop."""
    if payload.get("stop_hook_active"):
        return None
    if any(_MARKER in line for line in tail_lines):
        return None

    entries = _parse_lines(tail_lines)
    if not entries:
        return None

    last_user_idx = _last_genuine_user_index(entries)
    turn = entries[last_user_idx + 1 :] if last_user_idx is not None else entries
    if not turn:
        return None

    last_edit_idx = _last_edit_index(turn)
    if last_edit_idx is None:
        return None

    claim_text = payload.get("last_assistant_message")
    if not isinstance(claim_text, str) or not claim_text:
        claim_text = _last_assistant_text(turn)
    if not _CLAIM_RE.search(claim_text):
        return None

    if _gate_ran_after(turn, last_edit_idx):
        return None

    return _BLOCK_REASON


def main() -> int:
    try:
        payload = json.load(sys.stdin)
        if not isinstance(payload, dict):
            return 0
        transcript_path = payload.get("transcript_path")
        tail_lines: list[str] = []
        if isinstance(transcript_path, str) and transcript_path:
            with open(transcript_path, encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
            tail_lines = lines[-_TAIL_LINES:]
        reason = decide(payload, tail_lines)
        if reason:
            print(json.dumps({"decision": "block", "reason": reason}))
    except Exception:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
