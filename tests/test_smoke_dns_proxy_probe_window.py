"""Off-appliance tests of the on-box probe window in the pfB-DNS decider-restart test (issue #3566).

The live test asks the proxy for a listed name every 0.2 s while an update pass restarts the decider, then insists on
UPGRADE_PROBE_MIN_ROWS answers so that "every probe got the VIP" means something. The probe window used to be the
duration of the update pass, which is a property of the runner, not of the test: CI runs whose pass took 0.5-0.6 s
logged 4 rows and failed the count, runs whose pass took 0.75-0.85 s logged 5-6 and passed. These cases pin that
`_Probe.stop()` guarantees a minimum sample size, not coverage of the restart window; cleanup via `abort()` never waits.
"""

from __future__ import annotations

import pytest

from tests.smoke import helpers as h
from tests.smoke import test_smoke_dns_proxy as dns

PERIOD = 0.2  # the probe's pause between two questions (an answer takes a few ms on top)
ANSWER = f"NOERROR:{h.DEFAULT_DNSBL_VIP4}"


class _Clock:
    """Controlled time for `helpers`: `sleep` advances `monotonic`, everything else is the real module."""

    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds

    def __getattr__(self, name: str) -> object:
        import time

        return getattr(time, name)


class _Guest:
    """The probe's log as the loop writes it on a guest: one row per PERIOD of the clock, from its first question."""

    def __init__(self, clock: _Clock) -> None:
        self.clock = clock
        self.began = clock.now
        self.killed: float | None = None

    def log(self) -> str:
        end = self.clock.now if self.killed is None else self.killed
        count = int((end - self.began) / PERIOD + 1e-9) + 1
        return "".join(f"{1_794_000_000 + int(self.began + i * PERIOD)} {ANSWER}\n" for i in range(count))


@pytest.fixture
def guest(monkeypatch: pytest.MonkeyPatch) -> tuple[_Clock, _Guest, dns._Probe]:
    clock = _Clock()
    guest = _Guest(clock)
    monkeypatch.setattr(h, "time", clock)
    monkeypatch.setattr(dns, "_cat", lambda _vm, _path: guest.log())

    def sh(_vm: object, script: str, **_kw: object) -> object:
        if "pkill" in script and guest.killed is None:
            guest.killed = clock.now
        return type("Done", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    monkeypatch.setattr(dns, "_sh", sh)
    probe = dns._Probe(object(), "listed.example")  # type: ignore[arg-type]
    return clock, guest, probe


def test_the_loop_runs_on_until_it_has_the_rows_asked_for(guest: tuple[_Clock, _Guest, dns._Probe]) -> None:
    """An update pass of 0.55 s (a fast runner) leaves 3 rows; the stop waits for the 5 the assertion needs."""
    clock, _guest, probe = guest
    clock.now += 0.55  # the update pass
    rows = probe.stop()
    assert len(rows) >= dns.UPGRADE_PROBE_MIN_ROWS, rows
    dns._assert_probe_answered(rows, "the decider's restart")


def test_a_window_that_already_holds_the_rows_is_not_extended(guest: tuple[_Clock, _Guest, dns._Probe]) -> None:
    """A slow runner (a pass of 2 s) has the rows already: the stop does not wait for more."""
    clock, _guest, probe = guest
    clock.now += 2.0
    before = clock.now
    rows = probe.stop()
    assert len(rows) >= dns.UPGRADE_PROBE_MIN_ROWS
    assert clock.now - before < 1.0, "the stop waited although the loop had enough rows"


def test_the_cleanup_stop_kills_at_once(guest: tuple[_Clock, _Guest, dns._Probe]) -> None:
    """The `finally` of a failed test stops the probe without waiting; a second stop returns the first read."""
    clock, _guest, probe = guest
    rows = probe.abort()
    assert clock.now == 0.0, "the cleanup stop waited on the clock"
    assert len(rows) == 1
    clock.now += 5.0
    assert probe.abort() == rows


def test_a_loop_that_never_reaches_the_rows_fails_loudly_and_is_still_killed(
    guest: tuple[_Clock, _Guest, dns._Probe],
) -> None:
    """A loop that cannot log (the guest hung) is a failure of the wait, not a silent short read; the loop is killed."""
    clock, guest_, probe = guest
    guest_.log = lambda: ""  # type: ignore[method-assign]
    with pytest.raises(RuntimeError, match="stuck/environment"):
        probe.stop()
    assert guest_.killed is not None, "the probe loop was left running after the wait gave up"
    assert 29.0 <= clock.now <= 31.0, f"expected the 30 s watchdog, got {clock.now} s"
