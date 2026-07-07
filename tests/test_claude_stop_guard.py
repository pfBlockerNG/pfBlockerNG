"""Tests for scripts/claude-stop-guard.py.

Issue #925 step 1: a Claude Code Stop-hook that blocks a "done"-style claim
made after editing src/tests/ code with no canonical gate command run since
the last edit. Not wired into any settings file yet -- script + tests only.

The checker is a hyphen-named script under scripts/, loaded via importlib by
path (the house pattern for dash-named tools -- see
tests/test_version_probe.py loading scripts/check-pfsense-versions.py).

Fixture-builder helpers construct transcript-entry dicts matching the shape
probed live (top-level ``type`` in user/assistant; assistant ``message.content``
is a list of ``{"type": "tool_use", ...}`` / ``{"type": "text", ...}`` dicts).
Every JSONL "tail" the tests build is what ``decide()`` receives as raw lines,
exactly as ``main()`` would read them off the transcript file.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

_TOOL = Path(__file__).resolve().parent.parent / "scripts" / "claude-stop-guard.py"
_spec = importlib.util.spec_from_file_location("claude_stop_guard", _TOOL)
assert _spec is not None and _spec.loader is not None
csg = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = csg
_spec.loader.exec_module(csg)


# --------------------------------------------------------------------------- #
# Fixture builders -- one genuine transcript entry shape each.
# --------------------------------------------------------------------------- #


def _user(*, tool_result: bool = False) -> dict[str, Any]:
    """A ``type=='user'`` entry; ``tool_result`` toggles the disambiguating key."""
    entry: dict[str, Any] = {"type": "user", "message": {"role": "user", "content": "hi"}}
    if tool_result:
        entry["toolUseResult"] = {"stdout": "ok"}
    return entry


def _edit(file_path: object, tool: str = "Edit") -> dict[str, Any]:
    return {
        "type": "assistant",
        "message": {"content": [{"type": "tool_use", "name": tool, "input": {"file_path": file_path}}]},
    }


def _bash(command: object) -> dict[str, Any]:
    return {
        "type": "assistant",
        "message": {"content": [{"type": "tool_use", "name": "Bash", "input": {"command": command}}]},
    }


def _text(text: str) -> dict[str, Any]:
    return {"type": "assistant", "message": {"content": [{"type": "text", "text": text}]}}


def _lines(entries: list[dict[str, Any]]) -> list[str]:
    return [json.dumps(e) for e in entries]


# A minimal "edit + claim + no gate" turn -- reused as the row-1 baseline.
_ROW1_TURN = [_edit("src/foo.php"), _text("All done, tests updated.")]


def _row1_tail() -> list[str]:
    return _lines([_user(), *_ROW1_TURN])


# --------------------------------------------------------------------------- #
# Coverage matrix rows 1-13
# --------------------------------------------------------------------------- #


def test_row1_edit_claim_no_gate_blocks() -> None:
    reason = csg.decide({}, _row1_tail())
    assert reason is not None, "src edit + done claim + no gate must block"
    assert "[stop-guard]" in reason


def test_row2_gate_after_edit_allows() -> None:
    turn = [_edit("src/foo.php"), _bash("php -l src/foo.php && vendor/bin/phpunit"), _text("Done.")]
    reason = csg.decide({}, _lines([_user(), *turn]))
    assert reason is None, "a gate command run AFTER the edit must allow the stop"


def test_row3_gate_only_before_last_edit_blocks() -> None:
    turn = [_bash("python3 -m pytest"), _edit("src/foo.py"), _text("Implemented and done.")]
    reason = csg.decide({}, _lines([_user(), *turn]))
    assert reason is not None, "a gate run BEFORE the last edit does not satisfy THE GATE"


def test_row4_no_edits_allows() -> None:
    turn = [_text("This is done, just a chat reply, no code touched.")]
    reason = csg.decide({}, _lines([_user(), *turn]))
    assert reason is None, "a claim with no code edit in the turn must not block"


def test_row5_stop_hook_active_allows() -> None:
    reason = csg.decide({"stop_hook_active": True}, _row1_tail())
    assert reason is None, "stop_hook_active truthy is a loop guard -- always allow"


def test_row6_marker_already_present_allows() -> None:
    turn = [_text("Previous turn ended with [stop-guard] warning"), _edit("src/foo.php"), _text("Done.")]
    reason = csg.decide({}, _lines([_user(), *turn]))
    assert reason is None, "the marker already in the tail means we already blocked once -- do not re-block"


def test_row7_docs_only_edits_allow() -> None:
    turn = [
        _edit("docs/misc/architecture-notes.md"),
        _edit("src/usr/local/pkg/pfblockerng/README.md"),
        _text("Documentation updated, done."),
    ]
    reason = csg.decide({}, _lines([_user(), *turn]))
    assert reason is None, ".md edits under docs/ AND under src/ are both excluded by the .md suffix rule"


def test_row8_edit_without_claim_allows() -> None:
    turn = [_edit("src/foo.php"), _text("Still investigating the parser, next step is more tests.")]
    reason = csg.decide({}, _lines([_user(), *turn]))
    assert reason is None, "an edit with no completion claim must not block"


def test_row9_tests_path_edit_triggers_like_src() -> None:
    turn = [_edit("tests/test_foo.py"), _text("Fixed the flaky test, done.")]
    reason = csg.decide({}, _lines([_user(), *turn]))
    assert reason is not None, "tests/ is a sibling axis to src/ -- must trigger identically"


_GATE_KEYWORDS = ("pytest", "phpunit", "phpstan", "phpcs", "php -l", "ruff", "shellcheck", "shellspec", "mypy")


def test_row10_each_gate_keyword_recognized() -> None:
    for keyword in _GATE_KEYWORDS:
        turn = [_edit("src/foo.php"), _bash(f"run the gate: {keyword} --whatever"), _text("Done.")]
        reason = csg.decide({}, _lines([_user(), *turn]))
        assert reason is None, f"gate keyword {keyword!r} must be recognized as a satisfying gate command"


def test_row11_last_assistant_message_absent_falls_back_to_transcript() -> None:
    # No 'last_assistant_message' key in payload at all -- must fall back to the
    # last text block of the last assistant entry in the turn (row-1 shape).
    reason = csg.decide({}, _row1_tail())
    assert reason is not None
    assert "[stop-guard]" in reason


def test_row12_gate_in_prior_turn_does_not_count() -> None:
    prior_turn_gate = _bash("python3 -m pytest")
    older_user = _user()
    newer_user = _user()  # the LAST genuine user prompt -- starts the current turn
    current_turn = [_edit("src/foo.php"), _text("Implemented, done.")]
    tail = _lines([older_user, prior_turn_gate, newer_user, *current_turn])
    reason = csg.decide({}, tail)
    assert reason is not None, "a gate run in a PRIOR turn must not satisfy the current turn's THE GATE"


def test_row13_write_tool_counts_as_edit() -> None:
    turn = [_edit("src/new_file.php", tool="Write"), _text("Created the new module, done.")]
    reason = csg.decide({}, _lines([_user(), *turn]))
    assert reason is not None, "Write is a code edit exactly like Edit"


# --------------------------------------------------------------------------- #
# Review findings (PR #945) -- each pinned red->green against the pre-fix code.
# --------------------------------------------------------------------------- #


def test_long_turn_edit_early_in_turn_still_blocks() -> None:
    # decide()-level pin: the decision logic itself must have no turn-length
    # window. The main()-level 50-line-tail regression (which this test cannot
    # see -- it bypasses the file read) is pinned red->green by
    # test_main_long_turn_via_subprocess_blocks below.
    turn: list[dict[str, Any]] = [_edit("src/foo.php")]
    turn += [_text(f"investigating step {i}, still looking") for i in range(60)]
    turn += [_text("All done, fixed the bug.")]
    reason = csg.decide({}, _lines([_user(), *turn]))
    assert reason is not None, "an edit early in a long turn must still trigger the guard"


def test_main_long_turn_via_subprocess_blocks(tmp_path: Path) -> None:
    turn: list[dict[str, Any]] = [_edit("src/foo.php")]
    turn += [_text(f"noise {i}") for i in range(60)]
    turn += [_text("All done, fixed it.")]
    transcript = tmp_path / "long.jsonl"
    transcript.write_text("\n".join(_lines([_user(), *turn])) + "\n", encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(_TOOL)],
        input=json.dumps({"hook_event_name": "Stop", "transcript_path": str(transcript)}),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    assert proc.stdout, "main() must block a long turn whose edit precedes >50 lines of activity"
    assert json.loads(proc.stdout)["decision"] == "block"


def test_main_byte_cap_truncating_user_boundary_still_blocks(tmp_path: Path) -> None:
    # A transcript larger than the 5 MB tail cap loses the user-prompt boundary;
    # the remaining tail is then treated as the whole turn and must still block.
    filler = [_text("x" * 100_000) for _ in range(60)]  # ~6 MB before the edit
    turn = [_edit("src/foo.php"), _text("All done, fixed it.")]
    transcript = tmp_path / "huge.jsonl"
    transcript.write_text("\n".join(_lines([_user(), *filler, *turn])) + "\n", encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(_TOOL)],
        input=json.dumps({"hook_event_name": "Stop", "transcript_path": str(transcript)}),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    assert proc.stdout, "losing the user boundary to the byte cap must not disarm the guard"
    assert json.loads(proc.stdout)["decision"] == "block"


def test_gate_keyword_inside_larger_word_not_credited() -> None:
    # 'ruff' inside 'truffle' must not count as a gate run (word-boundary match).
    turn = [_edit("src/foo.php"), _bash("npm install truffle-hardhat"), _text("Done.")]
    reason = csg.decide({}, _lines([_user(), *turn]))
    assert reason is not None, "a gate keyword embedded in an unrelated word must not satisfy THE GATE"


def test_stale_done_before_final_tooluse_entry_does_not_block() -> None:
    # The claim fallback reads ONLY the last assistant entry; a stale mid-turn
    # "done" from before later tool work must not false-block.
    turn = [_edit("src/foo.php"), _text("Done with step one, more to do."), _bash("ls -la")]
    reason = csg.decide({}, _lines([_user(), *turn]))
    assert reason is None, "a turn whose final assistant entry makes no claim must not block"


_CLAIM_WORDS = ("done", "complete", "completed", "implemented", "fixed", "landed", "finished", "green")


def test_each_claim_keyword_recognized() -> None:
    for word in _CLAIM_WORDS:
        turn = [_edit("src/foo.php"), _text(f"The task is now {word}.")]
        reason = csg.decide({}, _lines([_user(), *turn]))
        assert reason is not None, f"claim keyword {word!r} must trigger the guard"


def test_payload_claim_text_preferred_over_transcript() -> None:
    # A present, non-claiming last_assistant_message wins over a claiming transcript text...
    reason = csg.decide({"last_assistant_message": "Still investigating the parser."}, _row1_tail())
    assert reason is None, "payload last_assistant_message must be preferred over the transcript fallback"
    # ...and a claiming one wins over a non-claiming transcript text.
    turn = [_edit("src/foo.php"), _text("Wrapping up now.")]
    reason = csg.decide({"last_assistant_message": "All done."}, _lines([_user(), *turn]))
    assert reason is not None, "a claiming payload last_assistant_message must trigger the guard"


def test_gate_keyword_case_insensitive() -> None:
    # _GATE_RE is deliberately case-insensitive (consistent with _CLAIM_RE).
    turn = [_edit("src/foo.php"), _bash("PYTEST -q tests/"), _text("Done.")]
    reason = csg.decide({}, _lines([_user(), *turn]))
    assert reason is None, "an upper-case gate command must still credit the gate"


def test_main_byte_cut_on_exact_line_boundary_keeps_first_line(tmp_path: Path, monkeypatch: Any, capsys: Any) -> None:
    # When the byte cut lands exactly after a newline, the first tail line is
    # COMPLETE and must be kept -- dropping it can discard the triggering edit
    # and silently flip BLOCK to ALLOW.
    import io

    lines = _lines([_user(), _edit("src/foo.php"), _text("All done, fixed it.")])
    transcript = tmp_path / "boundary.jsonl"
    transcript.write_text("\n".join(lines) + "\n", encoding="utf-8")
    size = transcript.stat().st_size
    cap = size - (len(lines[0].encode()) + 1)  # cut starts exactly at the edit line
    monkeypatch.setattr(csg, "_TAIL_BYTES", cap)
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps({"transcript_path": str(transcript)})))
    assert csg.main() == 0
    out = capsys.readouterr().out
    assert out, "a boundary-aligned byte cut must not drop the complete edit line (BLOCK expected)"
    assert json.loads(out)["decision"] == "block"


def test_same_entry_batched_edit_and_gate_allows() -> None:
    entry = {
        "type": "assistant",
        "message": {
            "content": [
                {"type": "tool_use", "name": "Edit", "input": {"file_path": "src/foo.php"}},
                {"type": "tool_use", "name": "Bash", "input": {"command": "pytest -q tests/"}},
            ]
        },
    }
    reason = csg.decide({}, _lines([_user(), entry, _text("Done.")]))
    assert reason is None, "an Edit and its gate Bash call batched in ONE assistant entry must credit the gate"


# --------------------------------------------------------------------------- #
# Hostile-input rows
# --------------------------------------------------------------------------- #


def test_hostile_empty_transcript_allows() -> None:
    assert csg.decide({}, []) is None


def test_hostile_transcript_path_absent_main_exits_zero() -> None:
    proc = subprocess.run(
        [sys.executable, str(_TOOL)],
        input=json.dumps({"hook_event_name": "Stop"}),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, f"missing transcript_path must fail open; stderr={proc.stderr!r}"
    assert proc.stdout == ""


def test_hostile_transcript_file_missing_main_exits_zero(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist.jsonl"
    proc = subprocess.run(
        [sys.executable, str(_TOOL)],
        input=json.dumps({"hook_event_name": "Stop", "transcript_path": str(missing)}),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, f"a missing transcript file must fail open; stderr={proc.stderr!r}"
    assert proc.stdout == ""


def test_hostile_garbage_jsonl_interleaved_still_blocks() -> None:
    tail = ["not json{", *_row1_tail(), "{also truncated"]
    reason = csg.decide({}, tail)
    assert reason is not None, "unparseable lines must be skipped individually, not abort the scan"
    assert "[stop-guard]" in reason


def test_hostile_all_binary_garbage_allows() -> None:
    tail = ["\x00\x01\x02 not json", "???not json either???"]
    assert csg.decide({}, tail) is None


def test_hostile_tool_use_missing_input_no_crash() -> None:
    bad_entries = [
        {"type": "assistant", "message": {"content": [{"type": "tool_use", "name": "Edit"}]}},  # no input
        {"type": "assistant", "message": {"content": [{"type": "tool_use", "name": "Edit", "input": {}}]}},  # no path
        {"type": "assistant", "message": {"content": ["not-a-dict-item"]}},  # non-dict content item
        _text("Done."),
    ]
    reason = csg.decide({}, _lines([_user(), *bad_entries]))
    assert reason is None, "malformed tool_use entries must be skipped, not crash, and yield no trigger"


def test_hostile_claim_boundary_undone_vs_done_period() -> None:
    turn_undone = [_edit("src/foo.php"), _text("This leaves the migration undone for now.")]
    assert csg.decide({}, _lines([_user(), *turn_undone])) is None, "'undone' must NOT match the claim regex"

    turn_done_period = [_edit("src/foo.php"), _text("DONE.")]
    reason = csg.decide({}, _lines([_user(), *turn_done_period]))
    assert reason is not None, "'DONE.' must match the claim regex (word boundary before the period)"


def test_hostile_oversized_line_no_crash() -> None:
    # The huge line sits BEFORE the real trigger turn so it cannot become the
    # "final assistant text" fallback -- this row is about not crashing/hanging
    # on a huge line, not about which text wins the claim check.
    huge_line = json.dumps(_text("x" * (1024 * 1024)))
    tail = [huge_line, *_row1_tail()]
    reason = csg.decide({}, tail)  # must not raise
    assert reason is not None, "an oversized-but-valid line must not break scanning of the real trigger"


def test_hostile_stdin_not_json_main_exits_zero_empty_stdout() -> None:
    proc = subprocess.run(
        [sys.executable, str(_TOOL)],
        input="not valid json at all {{{",
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, f"non-JSON stdin must fail open; stderr={proc.stderr!r}"
    assert proc.stdout == ""


def test_hostile_block_path_via_subprocess(tmp_path: Path) -> None:
    transcript = tmp_path / "transcript.jsonl"
    transcript.write_text("\n".join(_row1_tail()) + "\n", encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(_TOOL)],
        input=json.dumps({"hook_event_name": "Stop", "transcript_path": str(transcript)}),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    out = json.loads(proc.stdout)
    assert out["decision"] == "block"
    assert "[stop-guard]" in out["reason"]
