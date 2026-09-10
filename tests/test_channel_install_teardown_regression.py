"""Regression coverage for channel-installer subprocess teardown (issue #3054)."""

from __future__ import annotations

import contextlib
import os
import shlex
import signal
import subprocess
import time
from pathlib import Path
from typing import Any

import pytest

from tests import test_channel_install as channel_install


def _live_group_pids(pgid: int) -> list[int]:
    result = subprocess.run(
        ["ps", "-eo", "pid=,pgid=,stat="],
        capture_output=True,
        text=True,
        check=True,
    )
    return [
        int(fields[0])
        for line in result.stdout.splitlines()
        if len(fields := line.split()) == 3 and int(fields[1]) == pgid and not fields[2].startswith("Z")
    ]


def test_output_reader_teardown_kills_surviving_pkg_descendant(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A real blocked pkg descendant cannot outlive the install test's temporary root."""
    started = tmp_path / "descendant-started"
    release = tmp_path / "descendant-release"
    original_stub = channel_install._PKG_STUB
    original_popen = subprocess.Popen
    capture: list[subprocess.Popen[str]] = []

    stream_start = '        /bin/echo "pfb-stream-marker-2644"\n'
    stream_start_with_marker = f"        printf 'started\\n' > {shlex.quote(str(started))}\n" + stream_start
    post_unblock = f"""    if [ -f {shlex.quote(str(started))} ]; then
        while [ ! -f {shlex.quote(str(release))} ]; do
            sleep 0.1
        done
    fi
"""
    monkeypatch.setattr(
        channel_install,
        "_PKG_STUB",
        original_stub.replace(stream_start, stream_start_with_marker, 1).replace(
            '    _repo=""\n', post_unblock + '    _repo=""\n', 1
        ),
    )

    def capture_popen(*args: Any, **kwargs: Any) -> subprocess.Popen[str]:
        proc = original_popen(*args, **kwargs)
        if kwargs.get("start_new_session") is True:
            capture.append(proc)
        return proc

    monkeypatch.setattr(channel_install.subprocess, "Popen", capture_popen)

    pgid = -1
    try:
        channel_install.test_output_reader_does_not_outlive_the_run()
        assert started.exists(), "fixture broken: the real pkg descendant never reached its blocking call"
        assert len(capture) == 1, f"expected one isolated installer process, captured {len(capture)}"
        pgid = capture[0].pid
        survivors = _live_group_pids(pgid)
        assert not survivors, f"installer process-group members outlived test teardown: {survivors}"
    finally:
        for captured_proc in capture:
            captured_pgid = captured_proc.pid
            with contextlib.suppress(ProcessLookupError):
                os.killpg(captured_pgid, signal.SIGKILL)
            deadline = time.monotonic() + 5.0
            while _live_group_pids(captured_pgid) and time.monotonic() < deadline:
                time.sleep(0.05)
            captured_proc.wait(timeout=5)
