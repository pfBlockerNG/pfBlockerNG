"""Unit coverage for the per-step timing helper (issue #605).

Pins the contract the parsers rely on: every timed step emits exactly one
``PFB_TIMING <label> <seconds>.2fs`` line to stdout, and — only when the session log is
open (``PFB_DIAG_DIR`` set + :func:`open_log` called) — the same line lands in
``$PFB_DIAG_DIR/timing.log``. Also pins that the decorator is transparent (return value +
exceptions pass through), that a step which raises still emits its line, and the
open-once/close-once session-log lifecycle (fresh file per session).
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

import pytest

from tests.timing import close_log, open_log, timed, timed_step

# PFB_TIMING <label> <float>s — the one parseable shape the diagnostics consumer greps.
_LINE = re.compile(r"^PFB_TIMING (?P<label>\S+) (?P<secs>\d+\.\d{2})s$")


@pytest.fixture(autouse=True)
def _isolate_timing_log() -> Iterator[None]:
    """Close the module-global session log around each test so an open handle from one
    file-sink test never leaks into the next (the handle is process-global state)."""
    close_log()
    yield
    close_log()


def test_timed_emits_one_parseable_line(capsys: pytest.CaptureFixture[str]) -> None:
    with timed("mystep"):
        pass
    lines = capsys.readouterr().out.strip().splitlines()
    assert len(lines) == 1, f"expected exactly one PFB_TIMING line, got: {lines}"
    m = _LINE.match(lines[0])
    assert m is not None, f"line not in 'PFB_TIMING <label> <secs>s' shape: {lines[0]!r}"
    assert m.group("label") == "mystep"
    float(m.group("secs"))  # the 2-decimal seconds field parses as a number


def test_timed_step_decorator_is_transparent(capsys: pytest.CaptureFixture[str]) -> None:
    @timed_step()
    def add(a: int, b: int) -> int:
        return a + b

    # return value passes through
    assert add(2, 3) == 5
    # and it emits a line labelled by the function's qualname
    out = capsys.readouterr().out.strip()
    m = _LINE.match(out)
    assert m is not None and "add" in m.group("label"), f"unexpected timing line: {out!r}"


def test_timed_step_callable_label_names_from_args(capsys: pytest.CaptureFixture[str]) -> None:
    # A callable label receives the wrapped function's args and builds the label from them.
    @timed_step(lambda _vm, scope="update", **_k: f"reload:{scope}")
    def reload(_vm: str, scope: str = "update") -> None:
        return None

    reload("vm", "updateip")
    m = _LINE.match(capsys.readouterr().out.strip())
    assert m is not None and m.group("label") == "reload:updateip"


def test_timed_step_label_callable_error_falls_back_to_qualname(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # A buggy label callable must never break the wrapped call — fall back to the qualname.
    @timed_step(lambda *_a, **_k: str(1 / 0))  # raises ZeroDivisionError (return-types as str)
    def work() -> int:
        return 42

    assert work() == 42  # the call still succeeds
    m = _LINE.match(capsys.readouterr().out.strip())
    assert m is not None and "work" in m.group("label")


def test_timed_step_explicit_label_overrides_qualname(capsys: pytest.CaptureFixture[str]) -> None:
    @timed_step("custom-label")
    def noop() -> None:
        return None

    noop()
    m = _LINE.match(capsys.readouterr().out.strip())
    assert m is not None and m.group("label") == "custom-label"


def test_timed_emits_even_when_block_raises(capsys: pytest.CaptureFixture[str]) -> None:
    # A step that fails must still report how long it ran before failing.
    with pytest.raises(ValueError), timed("boom"):
        raise ValueError("kaboom")
    m = _LINE.match(capsys.readouterr().out.strip())
    assert m is not None and m.group("label") == "boom"


def test_timed_min_seconds_suppresses_fast_blocks(capsys: pytest.CaptureFixture[str]) -> None:
    # A block faster than the threshold emits nothing (the poll-flood guard) ...
    with timed("fastpoll", min_seconds=10.0):
        pass
    assert capsys.readouterr().out == "", "a sub-threshold block must not emit a timing line"
    # ... while min_seconds=0 (the default behaviour) always emits.
    with timed("always", min_seconds=0.0):
        pass
    assert _LINE.match(capsys.readouterr().out.strip()) is not None


def test_timed_writes_to_open_log_when_env_set(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Given PFB_DIAG_DIR set + the session log opened (as the _pfb_timing_log fixture does)
    monkeypatch.setenv("PFB_DIAG_DIR", str(tmp_path))
    open_log()
    # When two steps run
    with timed("step-a"):
        pass
    with timed("step-b"):
        pass
    # Then both lines land in $PFB_DIAG_DIR/timing.log (flushed per line, same shape as stdout)
    log = tmp_path / "timing.log"
    assert log.exists(), "timing.log was not created under PFB_DIAG_DIR"
    file_lines = log.read_text(encoding="utf-8").strip().splitlines()
    assert len(file_lines) == 2
    matches = [_LINE.match(ln) for ln in file_lines]
    assert all(matches), f"file lines not parseable: {file_lines}"
    labels = {m.group("label") for m in matches if m}
    assert labels == {"step-a", "step-b"}


def test_open_log_creates_missing_diag_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The smoke harness's PFB_DIAG_DIR may not exist yet when the session log opens, so
    # open_log() must create it ONCE — otherwise the lines never reach timing.log.
    diag = tmp_path / "does" / "not" / "exist" / "smoke-diag"
    assert not diag.exists()
    monkeypatch.setenv("PFB_DIAG_DIR", str(diag))
    open_log()
    with timed("step"):
        pass
    log = diag / "timing.log"
    assert log.exists(), "open_log() must create the missing PFB_DIAG_DIR and the log"
    assert _LINE.match(log.read_text(encoding="utf-8").strip()) is not None


def test_open_log_starts_a_fresh_file_each_session(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # open_log() opens in 'w' mode, so a new session does NOT accumulate the prior run's lines.
    monkeypatch.setenv("PFB_DIAG_DIR", str(tmp_path))
    open_log()
    with timed("first-session"):
        pass
    close_log()
    open_log()  # second "session"
    with timed("second-session"):
        pass
    file_lines = (tmp_path / "timing.log").read_text(encoding="utf-8").strip().splitlines()
    assert len(file_lines) == 1, f"second session must truncate, not append: {file_lines}"
    assert "second-session" in file_lines[0]


def test_no_log_when_env_unset(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # Given PFB_DIAG_DIR is NOT set, open_log() is a no-op and nothing is written (terminal-only)
    monkeypatch.delenv("PFB_DIAG_DIR", raising=False)
    open_log()
    with timed("nofile"):
        pass
    assert not (tmp_path / "timing.log").exists()
