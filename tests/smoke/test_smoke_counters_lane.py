"""Core's day-change counters lane clears the widget counters with no crontab entry (#3996).

At the first minute boundary of a new local day Core re-reads the settings, logs its decision and runs the
counters program with the verbs due. The guest clock is stepped to 50 s before a minute boundary on the
target day, so the observed boundary is the lane's own schedule; the oracle is what
``pfBlockerNG_clearsqlite()`` writes: ``lastclear.lastipclear`` / ``lastdnsblclear`` (seeded with
an old stamp so "cleared" differs from "never had any"). The clock is restored in a ``finally``.
"""

from __future__ import annotations

import os
import shlex
import time
from collections.abc import Iterator

import pytest

from . import helpers as h
from .conftest import SmokeVM
from .test_smoke_core_api import await_core_up

_PFB_INC = "/usr/local/pkg/pfblockerng/pfblockerng.inc"
_IP_CFG = "installedpackages/pfblockerngglobal/widget-clearip"
_DNSBL_CFG = "installedpackages/pfblockerngglobal/widget-cleardnsbl"
_OLD = "2000-01-01 00:00:00"
_CORE_LOG = "/var/log/pfblockerng/core.log"
_DAY_CHANGE = "the day changed:"
_CAP = 180.0  # hung-run cap for one minute boundary plus Core's run; never an expected wait
_SQLITE = f"require_once('{_PFB_INC}');pfb_global();$db = pfb_open_sqlite(6, 'smoke counters lane');"


@pytest.fixture(scope="module")
def counters_vm(smoke_vm: SmokeVM) -> Iterator[SmokeVM]:
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    await_core_up(smoke_vm)
    try:
        yield smoke_vm
    finally:
        h.collect_host_diagnostics(smoke_vm)


def _stamps(vm: SmokeVM) -> tuple[str, str]:
    raw = h._php_read_scalar(
        vm, _SQLITE, "$db->querySingle(\"SELECT lastipclear || '|' || lastdnsblclear FROM lastclear WHERE row = 0\")"
    )
    ip, _, dnsbl = raw.partition("|")
    return ip, dnsbl


def _seed_stamps(vm: SmokeVM) -> None:
    result = h.php_eval(
        vm,
        _SQLITE + "$db->exec(\"INSERT INTO lastclear (row, lastipclear, lastdnsblclear) SELECT 0, '', '' "
        'WHERE NOT EXISTS (SELECT 1 FROM lastclear WHERE row = 0)");'
        + f"$db->exec(\"UPDATE lastclear SET lastipclear = '{_OLD}', lastdnsblclear = '{_OLD}' WHERE row = 0\");"
        "echo 'OK';",
    )
    assert result.returncode == 0 and "OK" in result.stdout, f"seeding the clear stamps failed: {result}"
    assert _stamps(vm) == (_OLD, _OLD), f"the clear stamps were not seeded: {_stamps(vm)}"


def _guest(vm: SmokeVM, *argv: str) -> str:
    result = vm.ssh(*argv)
    assert result.returncode == 0, f"{argv}: {result}"
    return result.stdout.strip()


_stepped_to: list[int] = []  # midnights earlier cases stepped to: Core fires only on a date after the last it saw


def _day_start(vm: SmokeVM, sunday: bool) -> int:
    """Epoch of a future local midnight on a Sunday (``%u`` 7) or a weekday (1-6), later than any earlier case's."""
    for ahead in range(1, 30):
        weekday = int(_guest(vm, "date", f"-v+{ahead}d", "+%u"))
        midnight = int(_guest(vm, "date", f"-v+{ahead}d", "-v0H", "-v0M", "-v0S", "+%s"))
        if (weekday == 7) == sunday and midnight > max(_stepped_to, default=0):
            _stepped_to.append(midnight)
            return midnight
    raise AssertionError("no matching day within 30 days")


def _lines_ending(vm: SmokeVM, text: str) -> int:
    """How many lines of Core's log end with ``text`` (letters, spaces and colons only)."""
    result = vm.ssh(f"/usr/bin/grep -c -e {shlex.quote(text + '$')} {_CORE_LOG} || true")
    return int(result.stdout.strip() or 0)


@pytest.fixture
def stepped_clock(counters_vm: SmokeVM) -> Iterator[SmokeVM]:
    """Hand out the VM; restore the guest clock (and NTP if it ran) whatever the test did."""
    vm = counters_vm
    guest_before = int(_guest(vm, "date", "+%s"))
    host_before = time.monotonic()
    ntp = vm.ssh("pgrep", "-x", "ntpd").returncode == 0
    if ntp:
        assert vm.ssh("pkill", "-x", "ntpd").returncode == 0, "could not stop ntpd for the clock step"
    try:
        yield vm
    finally:
        try:
            h.restore_guest_clock(vm, guest_before=guest_before, elapsed=lambda: time.monotonic() - host_before)
        finally:
            if ntp:
                h.php_eval(vm, "require_once('system.inc');system_ntp_configure();echo 'OK';")


@pytest.mark.smoke
@pytest.mark.timeout(600)
@pytest.mark.parametrize(
    ("ip_cadence", "dnsbl_cadence", "sunday", "ip_cleared", "dnsbl_cleared"),
    [
        pytest.param("daily", "weekly", False, True, False, id="weekday-daily-weekly"),
        pytest.param("daily", "weekly", True, True, True, id="sunday-daily-weekly"),
        pytest.param("never", "never", False, False, False, id="weekday-never-never"),
    ],
)
def test_core_clears_the_counters_at_a_day_change(
    stepped_clock: SmokeVM,
    ip_cadence: str,
    dnsbl_cadence: str,
    sunday: bool,
    ip_cleared: bool,
    dnsbl_cleared: bool,
) -> None:
    vm = stepped_clock
    h.assert_no_pfb_cron_entry(vm, "counters lane")
    h.config_set(vm, _IP_CFG, ip_cadence)
    h.config_set(vm, _DNSBL_CFG, dnsbl_cadence)
    _seed_stamps(vm)

    verbs = " ".join(v for v, on in (("clearip", ip_cleared), ("cleardnsbl", dnsbl_cleared)) if on)
    decision = f"{_DAY_CHANGE} " + (f"the counters lane clears {verbs}" if verbs else "no counter is due to clear")
    decided = h.count_log_marker(vm, _CORE_LOG, _DAY_CHANGE)
    decided_so = _lines_ending(vm, decision)
    midnight = _day_start(vm, sunday)
    _guest(vm, "date", "-f", "%s", str(midnight + 50))
    # Core logs its counters decision at the day change, so this poll ends on the decision, not on a margin.
    h.wait_until(
        lambda: h.count_log_marker(vm, _CORE_LOG, _DAY_CHANGE) > decided,
        timeout=_CAP,
        interval=1.0,
        what="Core logging its counters decision at the day change",
    )
    assert int(_guest(vm, "date", "+%s")) >= midnight + 60, "Core decided before the day-change boundary"

    expected = (ip_cleared, dnsbl_cleared)

    def cleared() -> tuple[bool, bool]:
        ip, dnsbl = _stamps(vm)
        return ip != _OLD, dnsbl != _OLD

    if any(expected):
        h.wait_until(
            lambda: cleared() == expected,
            timeout=_CAP,
            interval=2.0,
            what="Core clearing the counters at the day-change boundary",
        )
    assert _lines_ending(vm, decision) > decided_so, f"Core's day-change decision was not {decision!r}"
    # Core decided this day change: what it did not start clearing stayed uncleared.
    assert cleared() == expected, f"cleared (ip, dnsbl) was {cleared()}, wanted {expected}"
    h.assert_no_pfb_cron_entry(vm, "counters lane done")
