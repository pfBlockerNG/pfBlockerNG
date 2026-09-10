"""Failure-path coverage for the issue #3054 regression harness."""

from __future__ import annotations

import contextlib
import importlib
import os
import signal
import subprocess
import threading
from pathlib import Path
from typing import Any

import pytest

regression: Any = importlib.import_module("tests.test_channel_install_teardown_regression")


def test_regression_wrapper_cleans_captured_group_when_inner_test_raises(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A subprocess captured before an inner failure is still killed and reaped."""
    spawned: list[subprocess.Popen[str]] = []

    def fail_after_spawn() -> None:
        proc = regression.channel_install.subprocess.Popen(
            ["sleep", "30"],
            stdout=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        spawned.append(proc)
        raise RuntimeError("forced inner failure")

    monkeypatch.setattr(
        regression.channel_install,
        "test_output_reader_does_not_outlive_the_run",
        fail_after_spawn,
    )
    try:
        with pytest.raises(RuntimeError, match="forced inner failure"):
            regression.test_output_reader_teardown_kills_surviving_pkg_descendant(monkeypatch, tmp_path)
        assert len(spawned) == 1, f"fixture broken: expected one captured process, got {len(spawned)}"
        survivors = regression._live_group_pids(spawned[0].pid)
        assert not survivors, f"regression wrapper leaked a process after inner failure: {survivors}"
    finally:
        for proc in spawned:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(proc.pid, signal.SIGKILL)
            proc.wait(timeout=5)


def test_install_process_cleanup_fails_boundedly_when_an_escaped_writer_blocks_reader() -> None:
    """An unowned pipe writer yields a bounded teardown error, never a blocking close."""
    read_fd, write_fd = os.pipe()
    proc = subprocess.Popen(["sleep", "30"], start_new_session=True)
    stream = os.fdopen(read_fd, encoding="utf-8")
    proc.stdout = stream
    escaped = subprocess.Popen(["sleep", "30"], stdout=write_fd, start_new_session=True)
    os.close(write_fd)

    reader_started = threading.Event()

    def read_output() -> None:
        reader_started.set()
        list(stream)

    reader = threading.Thread(target=read_output, daemon=True)
    reader.start()
    assert reader_started.wait(timeout=5), "fixture broken: Python output reader did not start"

    finished = threading.Event()
    errors: list[Exception] = []

    def finish() -> None:
        try:
            regression.channel_install._finish_install_process(proc, proc.pid, reader, completion_timeout=0.0)
        except RuntimeError as exc:
            errors.append(exc)
        finally:
            finished.set()

    cleanup = threading.Thread(target=finish, daemon=True)
    cleanup.start()
    try:
        assert finished.wait(timeout=12), "cleanup blocked while closing a stream with a live reader"
        assert len(errors) == 1, f"expected one bounded reader error, got {errors!r}"
        assert "Python output reader outlived installer cleanup" in str(errors[0])
    finally:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(escaped.pid, signal.SIGKILL)
        escaped.wait(timeout=5)
        cleanup.join(timeout=5)
        with contextlib.suppress(ProcessLookupError):
            os.killpg(proc.pid, signal.SIGKILL)
        proc.wait(timeout=5)
        reader.join(timeout=5)
        if not stream.closed:
            stream.close()
