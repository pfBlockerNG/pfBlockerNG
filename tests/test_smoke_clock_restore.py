"""The guest clock a smoke module stepped is restored and verified, or the module fails naming the skew (#3996)."""

from __future__ import annotations

import subprocess
from types import SimpleNamespace
from typing import Any

import pytest

from tests.smoke import helpers as h


class Clock:
    """A guest whose clock follows host time plus an offset that ``date -f %s`` may or may not apply."""

    def __init__(self, *, applies: list[bool]) -> None:
        self.now = 1_000_000
        self.applies = applies
        self.sets: list[int] = []

    def ssh(self, *argv: str, **_kw: Any) -> subprocess.CompletedProcess[str]:
        if argv == ("date", "+%s"):
            return subprocess.CompletedProcess(argv, 0, f"{self.now}\n", "")
        if argv[:3] == ("date", "-f", "%s"):
            self.sets.append(int(argv[3]))
            if self.applies.pop(0):
                self.now = int(argv[3])
            return subprocess.CompletedProcess(argv, 0, "", "")
        raise AssertionError(argv)


def _vm(clock: Clock) -> Any:
    return SimpleNamespace(ssh=clock.ssh)


def test_a_restored_clock_is_verified() -> None:
    clock = Clock(applies=[True])
    clock.now = 5_000_000  # stepped away
    h.restore_guest_clock(_vm(clock), guest_before=1_000_000, elapsed=lambda: 90)
    assert clock.now == 1_000_090 and len(clock.sets) == 1


def test_a_clock_that_did_not_take_is_set_again_once() -> None:
    clock = Clock(applies=[False, True])
    clock.now = 5_000_000
    h.restore_guest_clock(_vm(clock), guest_before=1_000_000, elapsed=lambda: 90)
    assert len(clock.sets) == 2 and clock.now == 1_000_090


def test_a_clock_that_never_takes_fails_naming_the_skew() -> None:
    clock = Clock(applies=[False, False])
    clock.now = 5_000_000
    with pytest.raises(AssertionError, match=r"skew of \+3999\d{3}s"):
        h.restore_guest_clock(_vm(clock), guest_before=1_000_000, elapsed=lambda: 90)


def test_wait_until_names_what_it_awaited_on_expiry() -> None:
    with pytest.raises(RuntimeError, match="Core never republished the export"):
        h.wait_until(lambda: False, timeout=0.05, interval=0.01, what="Core never republished the export")
