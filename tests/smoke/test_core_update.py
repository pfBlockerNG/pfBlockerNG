"""issue #3941: Core runs every Update, on a real pfSense box, after the package install.

* ``StartUpdate`` starts a manual Update: Core runs the Outpost's Update program, ``GetUpdate`` shows its log (the
  cursor is the opaque string ``next``) and ends ``running: false`` with the result ``success``;
* a second ``StartUpdate`` while one runs is ``conflict`` (409), and the one running is the first;
* a manual Update (what Run Now starts) leaves the schedule's ``lastRun`` alone: only a scheduled or retry Update
  records an outcome (what the #2308 ledger tests held for the PHP tick);
* the tick no longer writes the PHP scheduler's state file: Core owns the schedule, and ``GetSchedule`` shows the feed
  group the box has.

The module deploys the branch package once; the Core socket is awaited (bounded) before anything is asked of it.
tests/smoke/test_smoke_tick.py and test_smoke_apply_on_change.py hold the Updates the tick asks Core for.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Iterator
from typing import Any

import pytest

from . import helpers as h
from .conftest import SmokeVM
from .test_smoke_core_api import await_core_up

pytestmark = pytest.mark.smoke

PHP = "/usr/local/bin/php"
PFB_PHP = "/usr/local/www/pfblockerng/pfblockerng.php"
# The PHP scheduler's state file and its lock (schedule_state_dir defaults to /usr/local/etc): retired at the install.
RETIRED_STATE = ("/usr/local/etc/pfb_schedule_state.json", "/usr/local/etc/pfb_schedule_state.json.lock")
LEDGER = "/var/db/pfblockerng/pfb_due_ledger.json"
# Outer bound on an Update Core runs: salvage only, never an assertion about duration.
UPDATE_WATCHDOG = 600.0


@pytest.fixture(scope="module")
def core_vm(smoke_vm: SmokeVM) -> Iterator[SmokeVM]:
    """The branch package deployed once, one feed group configured, and Core answering."""
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    feed_url = h.write_local_feed(smoke_vm, "smoke_core_update_ip.txt", "192.0.2.30/32\n192.0.2.31/32\n")
    h.inject(smoke_vm, h.IpCase(aliasname="smokecoreupd", feed_url=feed_url, header="smokecoreupd", family="v4"))
    await_core_up(smoke_vm)
    try:
        yield smoke_vm
    finally:
        h.collect_host_diagnostics(smoke_vm)


def await_idle(vm: SmokeVM) -> None:
    """Block until Core runs no Update, so a test starts from a quiet Core. The watchdog only salvages a stuck run."""
    deadline = time.monotonic() + UPDATE_WATCHDOG
    while h.core_update_view(vm)["running"]:
        if time.monotonic() > deadline:
            pytest.fail(f"STUCK: an Update still runs after {UPDATE_WATCHDOG:.0f}s: {h.core_update_view(vm)}")
        time.sleep(1)


def schedule_feeds(vm: SmokeVM) -> dict[str, Any] | None:
    """``GetSchedule``'s ``feeds`` entry (``None``: nothing is or will be due)."""
    reply = h.core_call(vm, "GetSchedule")
    assert reply["status"] == 200, f"GetSchedule did not answer 200: {reply}"
    feeds: dict[str, Any] | None = reply["body"]["feeds"]
    return feeds


def test_start_update_runs_a_manual_update_and_it_ends_with_its_log(core_vm: SmokeVM) -> None:
    """Given an idle Core, When StartUpdate asks for a manual Update, Then it ends `success` and GetUpdate has its log.

    Red when: StartUpdate is not served (no --update-cmd), the Update never ends, its result is not `success`, or its
    log (the program's stdout, `update.log`) lacks the pass's start and end lines.
    """
    vm = core_vm
    await_idle(vm)
    before = h.core_update_view(vm)["update"]

    reply = h.core_call(vm, "StartUpdate", {"trigger": "manual", "scope": "both", "force": "none"})
    assert reply["status"] == 200 and not reply["body"], f"StartUpdate was not admitted: {reply}"

    view = h.await_core_update_end(vm, before=before, watchdog=UPDATE_WATCHDOG)
    update = view["update"]
    assert view["running"] is False, f"GetUpdate must say the Update is over: {view}"
    assert (update["trigger"], update["scope"], update["force"]) == ("manual", "both", "none"), f"the request: {update}"
    assert update["result"] == "success", f"the manual Update did not succeed: {update}"
    assert update["finishedAt"] >= update["startedAt"] > 0, f"the Update's times: {update}"
    assert isinstance(view["next"], str), f"the cursor is a string (it exceeds 2^53): {view['next']!r}"

    log = h.core_update_log(vm)
    for line in ("UPDATE PROCESS START", "UPDATE PROCESS ENDED"):
        assert line in log, f"the Update's log has no {line!r} line:\n{log[-2000:]}"


def test_a_second_start_update_while_one_runs_gets_conflict(core_vm: SmokeVM) -> None:
    """Given an idle Core, When two StartUpdate calls follow at once, Then the second is `conflict` and the first runs.

    Both calls run in one on-box process: a started Update spawns the Update program, which cannot end before the
    second call returns, so the second call finds the gate taken.

    Red when: the second Update is admitted (two passes would write the same files) or the conflict is another code.
    """
    vm = core_vm
    await_idle(vm)
    before = h.core_update_view(vm)["update"]

    first, second = h.core_calls(
        vm,
        [
            ("StartUpdate", {"trigger": "manual", "scope": "both", "force": "none"}),
            ("StartUpdate", {"trigger": "manual", "scope": "ip", "force": "none"}),
        ],
    )
    assert first["status"] == 200, f"the first StartUpdate must be admitted: {first}"
    assert second["status"] == 409, f"a second Update while one runs must be refused with 409: {second}"
    assert second["body"]["error"]["code"] == "conflict", f"the second refusal's code: {second}"

    view = h.await_core_update_end(vm, before=before, watchdog=UPDATE_WATCHDOG)
    update = view["update"]
    assert (update["scope"], update["result"]) == ("both", "success"), (
        f"the Update that ran is the first one (scope both), and it succeeded: {update}"
    )


def test_a_manual_update_leaves_the_schedules_last_run_alone(core_vm: SmokeVM) -> None:
    """Given a scheduled feed group, When a manual Update (Run Now) runs, Then the feeds `lastRun` is unchanged.

    Only a scheduled or retry Update reports feed outcomes, which Core records as the feed's last run; a manual
    pass (even a Force Download) reports none. A pass that claimed the schedule's run would move `lastRun`.

    Red when: the manual Update's result makes Core record a run the schedule never made.
    """
    vm = core_vm
    await_idle(vm)
    with h.scheduled_updates_on(vm):
        feeds = schedule_feeds(vm)
        assert feeds is not None, (
            "precondition: Core's schedule must hold the feed group (a `null` entry proves nothing)"
        )
        before = h.core_update_view(vm)["update"]

        for force in ("none", "download"):
            reply = h.core_call(vm, "StartUpdate", {"trigger": "manual", "scope": "ip", "force": force})
            assert reply["status"] == 200, f"StartUpdate (force={force}) was not admitted: {reply}"
            view = h.await_core_update_end(vm, before=before, watchdog=UPDATE_WATCHDOG)
            before = view["update"]
            after = schedule_feeds(vm)
            assert after is not None and after["lastRun"] == feeds["lastRun"], (
                f"a manual Update (force={force}) moved the schedule's lastRun: before={feeds} after={after}"
            )


def test_the_tick_does_not_write_the_php_schedule_state(core_vm: SmokeVM) -> None:
    """Given a scheduled feed group that Core's schedule shows, When a tick runs, Then no PHP schedule state is written.

    The PHP scheduler kept `pfb_schedule_state.json` (and a lock) beside its derived cache in the due ledger; Core
    keeps the schedule state now. The files are removed first, so a tick that wrote them again is the only way
    they can be there.

    Red when: the tick writes the state file, its lock, or the ledger's schedule rows (`_meta`, `extra:*`) again.
    """
    vm = core_vm
    await_idle(vm)
    with h.scheduled_updates_on(vm):
        assert schedule_feeds(vm) is not None, "precondition: Core's schedule must hold the feed group"
        for path in RETIRED_STATE:
            assert vm.ssh("rm", "-f", path).returncode == 0, f"could not remove {path}"
        h.wait_no_active_pfb_task(vm)

        tick = vm.ssh(PHP, PFB_PHP, "tick", timeout=180)
        assert tick.returncode == 0, f"the tick failed: rc={tick.returncode} {tick.stdout}{tick.stderr}"
        # An Update the tick asked for ends before the files are read: it is the one that ran the passes it names.
        await_idle(vm)

    for path in RETIRED_STATE:
        assert vm.ssh("test", "-e", path).returncode != 0, f"the tick wrote the retired PHP schedule state {path}"
    ledger = vm.ssh("cat", LEDGER, timeout=30)
    retired = sorted(
        key
        for key in (json.loads(ledger.stdout) if ledger.returncode == 0 and ledger.stdout.strip() else {})
        if key == "_meta" or key.startswith("extra:")
    )
    assert retired == [], f"the tick wrote the PHP scheduler's derived cache into the ledger again: {retired}"
