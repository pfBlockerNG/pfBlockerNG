"""Tier-B flow: the Update page runs the one Update through Core and follows it (issue #3941, cutover step C3).

Marker ``ui_e2e`` -- run on demand with ``pytest tests/smoke -m ui_e2e --override-ini="addopts="``.

Run Now is a multi-step flow (POST, then polls of ``?ajax=update``), so Tier A cannot see it. The oracle is Core's
Update as the page's own poll endpoint reports it, never the POST response alone. The Update is HELD by a pre-update
hook that waits for a release marker, so "the Update is running" is a state the test controls, not a race against a
run on a box with no feeds that ends in seconds.
"""

from __future__ import annotations

import json
import uuid
from typing import TYPE_CHECKING, Any

import pytest

from .. import helpers
from .test_functional import SAVE_TIMEOUT, UPDATE_PAGE

if TYPE_CHECKING:
    from collections.abc import Iterator

    from .webui import WebUI

pytestmark = pytest.mark.ui_e2e

# The line a finished pass logs last (pfblockerng_apply.inc); it reaches the page through Core's update.log.
END_LINE = "UPDATE PROCESS ENDED"
# Generous salvage caps, never assertions: an expiry is a stuck run (stuck/environment), not a verdict.
HELD_SALVAGE_S = 90.0
FINISH_SALVAGE_S = 300.0


def _poll(webui: WebUI, after: str | None = None) -> dict[str, Any]:
    """One ``?ajax=update`` poll, as the page's poller sends it: the previous ``next`` as ``after``."""
    query = "?ajax=update" + (f"&after={after}" if after is not None else "")
    resp = webui.get(UPDATE_PAGE + query)
    assert resp.status_code == 200, f"ajax=update returned HTTP {resp.status_code}: {resp.text[:200]!r}"
    payload = json.loads(resp.text)
    assert "error" not in payload, f"Core did not answer the poll: {payload!r}"
    return payload


def _wait_no_update_running(webui: WebUI) -> None:
    """Block until Core reports no Update running (a sibling test's Run Now may still be ending)."""
    helpers.wait_until(lambda: not _poll(webui)["running"], timeout=FINISH_SALVAGE_S, interval=1.0)


@pytest.fixture
def held_update(smoke_vm: helpers.SmokeVM, webui: WebUI) -> Iterator[tuple[str, str]]:
    """A pre-update hook that marks it was entered, then holds the Update until the release marker appears.

    Yields ``(entered_marker, release_marker)``. The hook's own wait is bounded (150 x 1 s) so a test that dies
    before releasing cannot leave an Update running for ever; the teardown releases, waits the Update out and
    removes the hook, so a leftover cannot hold another test's Update.
    """
    token = f"c3{uuid.uuid4().hex[:8]}"
    entered = helpers.hook_marker_path(token, "entered")
    release = helpers.hook_marker_path(token, "release")
    script = f"hook_pre_{token}_hold.sh"
    body = (
        f"#!/bin/sh\n/usr/bin/touch {entered}\nn=0\n"
        f"while [ ! -f {release} ] && [ $n -lt 150 ]; do /bin/sleep 1; n=$((n+1)); done\n"
    )
    hook = {
        "script": script,
        "_body": body,
        "when": "pre",
        "enabled": "on",
        "description": f"smoke {token} hold the Update",
        "timeout": "200",
    }
    _wait_no_update_running(webui)  # a prior test's Update would run the hook before this test asked for it
    smoke_vm.ssh("/bin/rm", "-f", entered, release)
    helpers.set_update_hooks(smoke_vm, [hook])
    try:
        yield entered, release
    finally:
        smoke_vm.ssh("/usr/bin/touch", release)
        _wait_no_update_running(webui)
        helpers.clear_update_hooks(smoke_vm)
        smoke_vm.ssh("/bin/rm", "-f", entered, release, f"{helpers.HOOK_SCRIPT_DIR}/{script}")


def _run_now(webui: WebUI, scope: str = "dnsbl", force: str = "none") -> str:
    """Submit Run Now for ``scope`` and ``force``; the page's answer."""
    resp = webui.post(
        UPDATE_PAGE,
        overrides={"pfb_scope": scope, "pfb_force_mode": force},
        submit=("run", "Run Now"),
        timeout=SAVE_TIMEOUT,
    )
    return resp.text


def test_run_now_is_followed_to_its_end_and_a_second_run_is_refused(
    smoke_vm: helpers.SmokeVM, webui: WebUI, held_update: tuple[str, str]
) -> None:
    """Run Now starts Core's Update; the poll shows it running, then its end line; a second Run Now is refused.

    Scenario:
      Given no Update is running and a pre-update hook holds the next one,
      When Run Now is submitted for scope dnsbl, force none,
      Then the page says it started that Update,
      And once the hook is entered the first poll shows running:true for a manual dnsbl Update with force none;

      When a plain page load and a second Run Now arrive while it runs,
      Then the page load says an update is running and wires the poller, and the second Run Now is told
        "An Update is running." (Core's conflict) -- and the first Update is still the one running;

      When the hold is released and the poll follows its cursor until Core reports done and the log is drained,
      Then the log (read in cursor order, each ``next`` sent back as ``after``) holds the update's end line, the
        Update's result is success and no Update runs.

    Fail-before: the page dispatched a detached ``pfb_trigger`` and tailed a run log by byte offset, so the poll
    endpoint answered no ``update`` object and a second Run Now was skipped by a process-table scan.
    """
    entered, release = held_update
    assert not _poll(webui)["running"], "precondition: no Update is running before Run Now"

    answered = _run_now(webui)
    assert "Running: scope=dnsbl force=none" in answered, (
        "Run Now did not say it started the Update: the status line the POST answered was missing"
    )
    helpers.wait_until(lambda: helpers.hook_marker_exists(smoke_vm, entered), timeout=HELD_SALVAGE_S, interval=1.0)

    first = _poll(webui)
    assert first["running"] is True, f"the held Update must be running: {first!r}"
    assert first["done"] is False
    assert (first["update"]["trigger"], first["update"]["scope"], first["update"]["force"]) == (
        "manual",
        "dnsbl",
        "none",
    ), f"Core's Update is not the one Run Now asked for: {first['update']!r}"
    started_at = first["update"]["startedAt"]

    page = webui.get(UPDATE_PAGE).text
    assert "An update is running." in page, "a plain load while an Update runs must say so in the status line"
    assert "ajax=update" in page, "a plain load while an Update runs must wire the poller (auto-tail)"

    refused = _run_now(webui)
    assert "An Update is running." in refused, "a second Run Now while one runs must be told an Update is running"
    still = _poll(webui)
    assert still["running"] is True and still["update"]["startedAt"] == started_at, (
        f"the refused Run Now must leave the first Update running, not start another: {still!r}"
    )

    smoke_vm.ssh("/usr/bin/touch", release)
    log = ""
    after: str | None = None
    last: dict[str, Any] = {}

    def drained() -> bool:
        nonlocal log, after, last
        last = _poll(webui, after)
        log += last["log"]
        after = last["next"]
        return last["done"] and last["log"] == ""

    helpers.wait_until(drained, timeout=FINISH_SALVAGE_S, interval=1.0)
    assert END_LINE in log, (
        f"the Update's end line never reached the poll\n"
        f"  expected to contain: {END_LINE!r}\n"
        f"  actual tail: {log[-600:]!r}"
    )
    assert last["running"] is False
    assert last["update"]["result"] == "success", f"the Update did not succeed: {last['update']!r}"
    assert last["update"]["startedAt"] == started_at, "the followed Update must be the one that was started"


def test_a_cursor_of_a_finished_update_still_reads_and_a_new_run_starts_a_fresh_log(
    smoke_vm: helpers.SmokeVM, webui: WebUI, held_update: tuple[str, str]
) -> None:
    """The poller notices a new Update: its first poll with the old cursor reads the NEW Update's log from its start.

    Scenario:
      Given a finished Update and the cursor a poller was left with (its ``next``),
      When Run Now starts another Update and the poller polls with that old cursor,
      Then the reply is the new Update's log from its start (a different ``startedAt`` is how the page's
        poller knows to clear its log), not the old log's remainder.
    """
    entered, release = held_update
    smoke_vm.ssh("/usr/bin/touch", release)  # the first Update runs straight through
    _run_now(webui)
    helpers.wait_until(
        lambda: _poll(webui)["update"] is not None and not _poll(webui)["running"],
        timeout=FINISH_SALVAGE_S,
        interval=1.0,
    )
    finished = _poll(webui)
    old_cursor = finished["next"]
    old_started = finished["update"]["startedAt"]
    assert finished["update"]["finishedAt"] is not None, f"precondition: the first Update must have ended: {finished!r}"

    smoke_vm.ssh("/bin/rm", "-f", entered, release)  # the second Update is held again
    assert "Running: scope=dnsbl force=none" in _run_now(webui), "the second Run Now must start an Update"
    helpers.wait_until(lambda: helpers.hook_marker_exists(smoke_vm, entered), timeout=HELD_SALVAGE_S, interval=1.0)

    fresh = _poll(webui, old_cursor)
    assert fresh["running"] is True, f"the second Update must be running: {fresh!r}"
    assert fresh["update"]["startedAt"] >= old_started
    assert fresh["log"] == _poll(webui)["log"][: len(fresh["log"])], (
        "a stale cursor must read from the start of the new log"
    )
