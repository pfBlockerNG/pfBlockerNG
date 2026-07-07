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

# Byte-bounded tail read: a fixed small LINE window (the first cut used 50 lines)
# silently drops the triggering edit on any real turn longer than the window --
# each tool round-trip is >=2 JSONL lines -- flipping BLOCK to ALLOW. 5 MB from
# EOF comfortably covers a whole turn while keeping memory bounded; the turn
# boundary (last genuine user prompt) decides scope, not the window.
_TAIL_BYTES = 5_000_000

_EDIT_TOOLS = ("Edit", "Write")
_EDIT_PATH_RE = re.compile(r"(^|/)(src|tests)/")
_CLAIM_RE = re.compile(r"\b(done|completed?|implemented|fixed|landed|finished|green)\b", re.IGNORECASE)
# \b-anchored: a bare substring test credits `ruff` inside `truffle` as a gate run.
_GATE_RE = re.compile(
    r"\b(pytest|phpunit|phpstan|phpcs|php -l|ruff|shellcheck|shellspec|mypy)\b",
    re.IGNORECASE,
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
    # `i < after_index` (not <=): an Edit and its gate Bash call batched as two
    # tool_use blocks in the SAME assistant entry must credit the gate.
    for i, e in enumerate(turn):
        if i < after_index or e.get("type") != "assistant":
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
            if _GATE_RE.search(command):
                return True
    return False


def _last_assistant_text(turn: list[dict[str, Any]]) -> str:
    """Text of the LAST assistant entry only -- never an earlier entry's text.

    Walking further back would resurrect a stale mid-turn "done" from before
    later tool work and false-block a turn whose real final entry made no claim.
    """
    for e in reversed(turn):
        if e.get("type") != "assistant":
            continue
        for item in reversed(_content_items(e)):
            if item.get("type") == "text" and isinstance(item.get("text"), str):
                return item["text"]
        return ""
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
            with open(transcript_path, "rb") as f:
                f.seek(0, 2)
                size = f.tell()
                f.seek(max(0, size - _TAIL_BYTES))
                data = f.read().decode("utf-8", errors="replace")
            tail_lines = data.splitlines()
            if size > _TAIL_BYTES and tail_lines:
                tail_lines = tail_lines[1:]  # drop the partial first line of the byte cut
        reason = decide(payload, tail_lines)
        if reason:
            print(json.dumps({"decision": "block", "reason": reason}))
    except Exception:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
