"""A per-test alarm (standard library only): a test that hangs fails with a message instead of stalling the run.

conftest.py imports the fixture so every test in this directory has it; `-p hang_guard` loads it anywhere else.
PFB_TEST_TIMEOUT (seconds, default 60) sets the limit. The alarm covers the test and its function-scoped fixtures, not
module-scoped ones (the Docker image build takes minutes). POSIX only: it needs SIGALRM.
"""

from __future__ import annotations

import os
import signal
from collections.abc import Iterator
from types import FrameType

import pytest


@pytest.fixture(autouse=True)
def hang_guard() -> Iterator[None]:
    seconds = float(os.environ.get("PFB_TEST_TIMEOUT", "60"))

    def on_alarm(_signum: int, _frame: FrameType | None) -> None:
        raise TimeoutError(f"test exceeded {seconds:g} s: hung?")

    previous = signal.signal(signal.SIGALRM, on_alarm)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
