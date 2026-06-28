"""Per-step timing for the test suites (issue #605) — stdlib only, no plugin.

pytest's ``--durations`` reports per-test setup/call/teardown phases (Layer A), but it
cannot see *inside* a test body. This module is Layer B: a tiny ``time.perf_counter``
timer that emits one greppable line per timed STEP — each ``reload`` / ``ssh`` / feed
download — so the cost of a slow live-VM test (e.g. "where do the 80s go") is visible
rather than guessed.

Each step emits a single consistent, parseable line::

    PFB_TIMING <label> <seconds>.2fs

to the terminal (live, via ``print``) AND, when the timing log is open, to
``$PFB_DIAG_DIR/timing.log`` so the lines ride the uploaded diagnostics for offline
parsing. The log is opened ONCE per session by :func:`open_log` and closed by
:func:`close_log` (the ``_pfb_timing_log`` session fixture in ``tests/conftest.py``
drives both) — ``_emit`` only writes to the already-open handle, never sets up per call.
``PFB_DIAG_DIR`` is set by the smoke launcher (``scripts/run-smoke.sh``); the unit suite
leaves it unset, so the log stays closed there and timing is terminal-only. Timing is
best-effort: a write error is swallowed, never failing a test.
"""

from __future__ import annotations

import contextlib
import functools
import os
import time
from collections.abc import Callable, Iterator
from typing import IO, ParamSpec, TypeVar

_PREFIX = "PFB_TIMING"
_DIAG_DIR_ENV = "PFB_DIAG_DIR"
_LOG_NAME = "timing.log"

_P = ParamSpec("_P")
_R = TypeVar("_R")

# The per-session timing log handle, opened once by open_log() and closed by close_log().
# None means "no file sink" (terminal-only) — the unit suite, where PFB_DIAG_DIR is unset.
_log_file: IO[str] | None = None


def open_log() -> None:
    """Open the per-step timing log once for the session (idempotent).

    No-op when ``PFB_DIAG_DIR`` is unset (the unit suite) — timing is terminal-only then.
    Opens in ``w`` mode so each session starts a fresh log (no cross-run accumulation).
    The directory is created here, ONCE — ``_emit`` never sets up per call.
    """
    global _log_file
    if _log_file is not None:
        return
    diag_dir = os.environ.get(_DIAG_DIR_ENV)
    if not diag_dir:
        return
    try:
        os.makedirs(diag_dir, exist_ok=True)
        _log_file = open(os.path.join(diag_dir, _LOG_NAME), "w", encoding="utf-8")
    except OSError:
        _log_file = None  # best-effort — fall back to terminal-only


def close_log() -> str | None:
    """Close the session timing log and return its path (for a teardown summary), or None."""
    global _log_file
    if _log_file is None:
        return None
    path = _log_file.name
    try:
        _log_file.close()
    except OSError:
        pass
    _log_file = None
    return path


def _emit(label: str, seconds: float) -> None:
    """Emit one ``PFB_TIMING`` line to the terminal and (if open) the session log."""
    line = f"{_PREFIX} {label} {seconds:.2f}s"
    print(line, flush=True)
    if _log_file is not None:
        try:
            _log_file.write(line + "\n")
            _log_file.flush()  # flush per line so the log survives an unclean teardown
        except (OSError, ValueError):
            pass  # best-effort — a log-write failure must never fail a test


@contextlib.contextmanager
def timed(label: str, min_seconds: float = 0.0) -> Iterator[None]:
    """Time the wrapped block and emit one ``PFB_TIMING <label> <seconds>`` line.

    The line is emitted even when the block raises, so a step that errors still reports
    how long it ran before failing.

    ``min_seconds`` suppresses the emit for blocks faster than the threshold — use it on
    a chokepoint that fires in a tight poll loop (e.g. ``SmokeVM.ssh``) so only the
    genuinely heavy calls surface and the fast polls don't flood the log. The default
    (0.0) always emits.
    """
    start = time.perf_counter()
    try:
        yield
    finally:
        elapsed = time.perf_counter() - start
        if elapsed >= min_seconds:
            _emit(label, elapsed)


def timed_step(
    label: str | Callable[..., str] | None = None,
) -> Callable[[Callable[_P, _R]], Callable[_P, _R]]:
    """Decorator: time a function call under ``label`` (defaults to its qualname).

    ``label`` may be a plain string, or a callable taking the SAME arguments as the
    wrapped function and returning the label — so a step can name itself from its args
    (e.g. ``lambda vm, scope="update", **k: f"reload:{scope}"``). A label callable that
    raises is swallowed and falls back to the qualname: timing must never break the call.

    Transparent — preserves the wrapped function's signature, return value, and raised
    exceptions; it only adds the timing emit around the call.
    """

    def decorate(fn: Callable[_P, _R]) -> Callable[_P, _R]:
        @functools.wraps(fn)
        def wrapper(*args: _P.args, **kwargs: _P.kwargs) -> _R:
            if callable(label):
                try:
                    name = label(*args, **kwargs)
                except Exception:
                    name = fn.__qualname__
            else:
                name = label or fn.__qualname__
            with timed(name):
                return fn(*args, **kwargs)

        return wrapper

    return decorate
