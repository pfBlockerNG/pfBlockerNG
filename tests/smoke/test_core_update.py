"""issue #3941: Core runs every Update, on a real pfSense box, after the package install.

* ``StartUpdate`` starts a manual Update: Core runs the Outpost's Update program, ``GetUpdate`` shows its log (the
  cursor is the opaque string ``next``) and ends ``running: false`` with the result ``success``;
* a second ``StartUpdate`` while one runs is ``conflict`` (409), and the one running is the first;
* a manual Update (what Run Now starts) leaves the schedule's ``lastRun`` alone: only a scheduled or retry Update
  records an outcome (what the #2308 ledger tests held for the PHP tick);
* the tick no longer writes the PHP scheduler's state file: Core owns the schedule, and ``GetSchedule`` shows the feed
  group the box has.
* a manual Update runs Core's FeedPhase for every feed type (DNSBL, IPv4, IPv6, custom groups and synthetic DNSBL-IP
  rows); a retry Update checks the regular feeds through the same planning path, not the scheduler's `scheduled`
  trigger, which the harness's retained `.pfb_cron_disable` defers;
* a 304 leaves the original, parsed and action files unrewritten; a failed transfer leaves the last-good ones and the
  `.fail` marker, and a retry after the source recovers publishes the new feed.

The module deploys the branch package once; the Core socket is awaited (bounded) before anything is asked of it.
tests/smoke/test_smoke_tick.py and test_smoke_apply_on_change.py hold the Updates the tick asks Core for.
"""

from __future__ import annotations

import json
import os
import re
import time
from collections.abc import Iterator
from typing import Any, NamedTuple

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


DB = "/var/db/pfblockerng"


def _run_update(vm: SmokeVM, trigger: str = "manual", scope: str = "both") -> tuple[dict[str, Any], str]:
    """One Update of ``trigger``, awaited: its final ``update`` record and its whole log."""
    await_idle(vm)
    before = h.core_update_view(vm)["update"]
    params = {"trigger": trigger, "scope": scope, "force": "none"} if trigger == "manual" else {"trigger": trigger}
    started = h.core_call(vm, "StartUpdate", params)
    assert started["status"] == 200, f"StartUpdate {params} was not admitted: {started}"
    view = h.await_core_update_end(vm, before=before, watchdog=UPDATE_WATCHDOG)
    update: dict[str, Any] = view["update"]
    return update, h.core_update_log(vm)


def _run_manual_update(vm: SmokeVM, scope: str = "both") -> str:
    update, log = _run_update(vm, "manual", scope)
    assert update["result"] == "success", f"Update failed: {update}"
    return log


def _snapshot(vm: SmokeVM, paths: list[str]) -> dict[str, tuple[bytes, str]]:
    """Each file's bytes, inode, high-resolution modification/change times and size."""
    out = {}
    for path in paths:
        raw = vm.ssh("cat", path)
        assert raw.returncode == 0, f"cannot read Core artifact {path}: {raw.stderr}"
        stat = vm.ssh("stat", "-f", "%i %.9Fm %.9Fc %z", path)
        assert stat.returncode == 0, f"cannot stat Core artifact {path}: {stat.stderr}"
        out[path] = (raw.stdout.encode(), stat.stdout.strip())
    return out


def _assert_feed_disposition(log: str, feed_id: str, disposition: str) -> None:
    # The ID is matched whole: `ipv4:x_v4` must not be satisfied by the line of `custom:ipv4:x_v4`.
    pattern = rf"(?<![A-Za-z0-9_:-]){re.escape(feed_id)}(?![A-Za-z0-9_:-])[^\n]*\b{disposition}\b"
    assert re.search(pattern, log), f"Core Update log has no {feed_id} {disposition} result:\n{log[-4000:]}"


def _add_ip_custom_lists(vm: SmokeVM, custom: dict[str, tuple[str, str]]) -> None:
    """Give the IP group of each ``{root: (aliasname, text)}`` a custom list, which makes its ``custom:ipv*:`` feed."""
    snippet = "".join(
        f"$l = config_get_path({h._php_str(root)}, array());\n"
        f"foreach ($l as $i => $g) {{ if (($g['aliasname'] ?? '') === {h._php_str(alias)}) "
        f"{{ $l[$i]['custom'] = base64_encode({h._php_str(text)}); }} }}\n"
        f"config_set_path({h._php_str(root)}, $l);\n"
        for root, (alias, text) in custom.items()
    )
    result = h.php_eval(vm, snippet + "write_config('pfBlockerNG smoke: custom IP lists');\necho 'OK';")
    assert result.returncode == 0 and "OK" in result.stdout, f"custom IP lists not written: {result.stdout}"


def _configure_every_feed_type(vm: SmokeVM, mock_feeds: Any, tag: str) -> tuple[dict[str, str], tuple[str, ...]]:
    """One DNSBL, one IPv4 and one IPv6 group, each with a custom list, and the DNSBL-IP rows they feed.

    Returns ``({feed ID: its mock feed name}, the IDs with no feed of their own: custom groups and synthetic rows)``.
    """
    kinds = ("dnsbl", "v4", "v6")
    mock = {k: f"core_update_{tag}_{k}" for k in kinds}
    alias = {k: f"cu{tag}{k}" for k in kinds}
    bodies = {
        "dnsbl": "ads.example.com\n203.0.113.9\n2001:db8::9\n",  # the IP literals are what feeds DNSBLIP
        "v4": "198.51.100.44\n",
        "v6": "2001:db8::44\n",
    }
    urls = {k: mock_feeds.register(mock[k], bodies[k]) for k in kinds}
    dnsbl = h.DnsblCase(
        aliasname=alias["dnsbl"],
        header=alias["dnsbl"],
        feed_url=urls["dnsbl"],
        dnsbl_ip_action="Deny_Both",
        custom_domains=["custom.example.com"],
    )
    ip4 = h.IpCase(aliasname=alias["v4"], header=alias["v4"], feed_url=urls["v4"], family="v4")
    ip6 = h.IpCase(aliasname=alias["v6"], header=alias["v6"], feed_url=urls["v6"], family="v6")
    h.inject_dnsbl_lists(vm, [(dnsbl, "Deny")])
    h.inject_ip_lists(vm, [ip4, ip6])
    _add_ip_custom_lists(
        vm,
        {
            h.CFG_IP_V4_LISTS: (alias["v4"], "198.51.100.77\r\n"),
            h.CFG_IP_V6_LISTS: (alias["v6"], "2001:db8::77\r\n"),
        },
    )
    provider, title = f"cu{tag}cat", f"Core{tag}"
    category_source = f"{DB}/{provider}/{provider}_test_cat"
    seeded = h.php_eval(
        vm,
        f"mkdir({h._php_str(f'{DB}/{provider}')}, 0755, TRUE);"
        f'file_put_contents({h._php_str(category_source)}, "blacklist.example.com\\n");'
        "config_set_path('installedpackages/pfblockerngblacklist', array("
        f"'blacklist_enable'=>'on','blacklist_selected'=>{h._php_str(provider)},"
        f"'item'=>array(array('xml'=>{h._php_str(provider)},'title'=>{h._php_str(title)},"
        f"'feed'=>{h._php_str(urls['dnsbl'])},'selected'=>'test-cat','size'=>'0'))));"
        "write_config('pfBlockerNG smoke: Core category parsing'); echo 'OK';",
    )
    assert seeded.returncode == 0 and "OK" in seeded.stdout, f"category setup failed: {seeded.stdout} {seeded.stderr}"
    h.tell_core_the_settings_changed(vm)
    regular = {
        f"dnsbl:{alias['dnsbl']}": mock["dnsbl"],
        f"ipv4:{alias['v4']}_v4": mock["v4"],
        f"ipv6:{alias['v6']}_v6": mock["v6"],
    }
    own_less = (
        f"custom:dnsbl:{alias['dnsbl']}",
        f"custom:ipv4:{alias['v4']}",
        f"custom:ipv6:{alias['v6']}",
        "synthetic:ipv4:DNSBLIP_v4",
        "synthetic:ipv6:DNSBLIP_v6",
        f"blacklist:{provider}:test-cat",
    )
    return regular, own_less


@pytest.mark.timeout(3 * UPDATE_WATCHDOG + 300)
def test_manual_update_logs_core_dispositions_for_every_feed_type(core_vm: SmokeVM, mock_feeds: Any) -> None:
    """A Core manual Update logs each FeedPhase ID and its disposition for every feed type.

    Red against the PHP-owned path: it cannot report per-ID Core FeedPhase outcomes.
    """
    vm = core_vm
    regular, own_less = _configure_every_feed_type(vm, mock_feeds, "manual")

    log = _run_manual_update(vm)

    for feed_id in (*regular, *own_less):
        _assert_feed_disposition(log, feed_id, "changed")
    for feed_id, mock in regular.items():
        seen = mock_feeds.statuses(mock)
        assert 200 in seen, f"{feed_id}: the local server was never fetched: {seen}"

    ip_outputs = {
        "cumanualv4_v4": b"198.51.100.44\n",
        "cumanualv6_v6": b"2001:db8::44\n",
        "cumanualv4_custom_v4": b"198.51.100.77\n",
        "cumanualv6_custom_v6": b"2001:db8::77\n",
        "DNSBLIP_v4": b"203.0.113.9\n",
        "DNSBLIP_v6": b"2001:db8::9\n",
    }
    for stem, expected in ip_outputs.items():
        paths = [f"{DB}/original/{stem}.parsed.ip", f"{DB}/deny/{stem}.txt"]
        for path, (actual, _) in _snapshot(vm, paths).items():
            assert actual == expected, f"{path}: parsed/consumed bytes {actual!r}, expected {expected!r}"
    for stem, domain in (
        ("cumanualdnsbl", "ads.example.com"),
        ("cumanualdnsbl_custom", "custom.example.com"),
        ("Coremanual_test_cat", "blacklist.example.com"),
    ):
        paths = [f"{DB}/dnsblorig/{stem}.parsed.ndjson", f"{DB}/dnsbl/{stem}.txt"]
        for path, (actual, _) in _snapshot(vm, paths).items():
            payloads = [json.loads(line)[1] for line in actual.splitlines()]
            assert domain in payloads, f"{path}: expected parsed domain {domain!r}, got {payloads!r}"


@pytest.mark.timeout(3 * UPDATE_WATCHDOG + 300)
def test_retry_update_runs_core_feed_phase_for_every_regular_feed_type(core_vm: SmokeVM, mock_feeds: Any) -> None:
    """A retry Update fetches changed sources through Core and logs each regular feed ID; it is not a scheduled run.

    A `.fail` marker is what asks for a feed's retry; each source then serves a new body, so every disposition is
    `changed` and every one needs a fresh 200 from the local server.
    """
    vm = core_vm
    regular, _ = _configure_every_feed_type(vm, mock_feeds, "sched")
    _run_manual_update(vm)
    seen = {mock: len(mock_feeds.statuses(mock)) for mock in regular.values()}
    new_bodies = {"dnsbl": "ads2.example.com\n", "ipv4": "198.51.100.88\n", "ipv6": "2001:db8::88\n"}
    for feed_id, mock in regular.items():
        kind, stem = feed_id.split(":")
        mock_feeds.set_content(mock, new_bodies[kind])
        folder = "dnsbl" if kind == "dnsbl" else "deny"
        assert vm.ssh("touch", f"{DB}/{folder}/{stem}.fail").returncode == 0, f"cannot mark {feed_id} for retry"

    with h.scheduled_updates_on(vm):
        update, log = _run_update(vm, "retry")

    assert update["trigger"] == "retry", f"Core ran {update}"
    for feed_id, mock in regular.items():
        _assert_feed_disposition(log, feed_id, "changed")
        assert 200 in mock_feeds.statuses(mock)[seen[mock] :], f"{feed_id}: retry never fetched the source"


class _OneFeed(NamedTuple):
    mock: str
    feed_id: str
    scope: str
    files: list[str]  # the original baseline, its parsed output and (IP) the action file
    parsed: str
    fail_marker: str


def _arrange_one_feed(vm: SmokeVM, mock_feeds: Any, kind: str, tag: str) -> _OneFeed:
    """One enabled feed of ``kind`` (``ipv4`` or ``dnsbl``) served by the local server; Core told of it."""
    mock, header = f"core_update_{tag}", f"coreupd{tag}"
    if kind == "dnsbl":
        url = mock_feeds.register(mock, "ads.example.org\n")
        h.inject_dnsbl_lists(vm, [(h.DnsblCase(aliasname=header, header=header, feed_url=url), "Deny")])
        parsed = [f"{DB}/dnsblorig/{header}.parsed.{ext}" for ext in ("ndjson", "v4.ip", "v6.ip")]
        files = [f"{DB}/dnsblorig/{header}.orig", *parsed, f"{DB}/dnsbl/{header}.txt"]
        feed = _OneFeed(mock, f"dnsbl:{header}", "dnsbl", files, parsed[0], f"{DB}/dnsbl/{header}.fail")
    else:
        url = mock_feeds.register(mock, "198.51.100.45\n")
        h.inject_ip_lists(vm, [h.IpCase(aliasname=header, header=header, feed_url=url, family="v4")])
        stem = f"{header}_v4"
        parsed_ip = f"{DB}/original/{stem}.parsed.ip"
        files = [f"{DB}/original/{stem}.orig", parsed_ip, f"{DB}/deny/{stem}.txt"]
        feed = _OneFeed(mock, f"ipv4:{stem}", "ip", files, parsed_ip, f"{DB}/deny/{stem}.fail")
    return feed


@pytest.mark.timeout(3 * UPDATE_WATCHDOG + 300)
@pytest.mark.parametrize("kind", ["ipv4", "dnsbl"])
def test_core_http_304_keeps_original_parsed_and_action_files_unrewritten(
    core_vm: SmokeVM, mock_feeds: Any, kind: str
) -> None:
    """A matching HTTP validator is answered 304 by the local server and Core leaves every output file untouched."""
    vm = core_vm
    feed = _arrange_one_feed(vm, mock_feeds, kind, f"304{kind}")
    mock_feeds.enable_etag(feed.mock, '"core-update-v1"')
    h.tell_core_the_settings_changed(vm)
    log1 = _run_manual_update(vm, feed.scope)
    first = mock_feeds.statuses(feed.mock)
    before = _snapshot(vm, feed.files)

    log2 = _run_manual_update(vm, feed.scope)
    after = _snapshot(vm, feed.files)

    second = mock_feeds.statuses(feed.mock)[len(first) :]
    assert 200 in first, f"the first Update never fetched the source: {first}"
    assert second and set(second) == {304}, f"the second Update must only see 304 answers: {second}"
    assert before == after, f"304 rewrote an original, parsed or action file: before={before!r} after={after!r}"
    _assert_feed_disposition(log1, feed.feed_id, "changed")
    _assert_feed_disposition(log2, feed.feed_id, "unchanged")


@pytest.mark.timeout(3 * UPDATE_WATCHDOG + 300)
@pytest.mark.parametrize("kind", ["ipv4", "dnsbl"])
def test_core_failed_transfer_keeps_last_good_files_and_retry_state_until_recovery(
    core_vm: SmokeVM, mock_feeds: Any, kind: str
) -> None:
    """A 503 leaves the last-good files and the `.fail` marker, and no successful check is recorded for the feed.

    The source then recovers with a new body: the next retry Update fetches it and publishes the new parsed file.
    """
    vm = core_vm
    feed = _arrange_one_feed(vm, mock_feeds, kind, f"fail{kind}")
    h.tell_core_the_settings_changed(vm)
    _run_manual_update(vm, feed.scope)
    before = _snapshot(vm, feed.files)
    seen = len(mock_feeds.statuses(feed.mock))
    absent = vm.ssh("test", "!", "-f", feed.fail_marker)
    assert absent.returncode == 0, f"precondition: successful baseline left {feed.fail_marker}"
    mock_feeds.set_status(feed.mock, 503)

    with h.scheduled_updates_on(vm):
        _, log = _run_update(vm, "manual", feed.scope)
        failed = mock_feeds.statuses(feed.mock)[seen:]
        after = _snapshot(vm, feed.files)
        marker = vm.ssh("test", "-f", feed.fail_marker)
        schedule = h.core_call(vm, "GetSchedule")
        ledger_result = vm.ssh("cat", "/usr/local/etc/pfb_core/schedule_state.json")
        assert ledger_result.returncode == 0, f"cannot read Core outcome ledger: {ledger_result.stderr}"
        ledger = json.loads(ledger_result.stdout)

        mock_feeds.set_status(feed.mock, None)
        mock_feeds.set_content(feed.mock, "ads2.example.org\n" if kind == "dnsbl" else "198.51.100.99\n")
        _, recovered_log = _run_update(vm, "retry")
        recovered = _snapshot(vm, feed.files)

    assert failed and set(failed) == {503}, f"the Update must see only the failing source: {failed}"
    assert before == after, f"a failed transfer changed the last-good files: before={before!r} after={after!r}"
    assert marker.returncode == 0, "a failed transfer cleared the feed's .fail retry marker"
    assert schedule["status"] == 200, f"GetSchedule did not answer: {schedule}"
    assert feed.feed_id not in schedule["body"]["lastSuccessfulCheck"], "a failed transfer was recorded as a check"
    assert "last_successful_check" not in ledger["items"].get(feed.feed_id, {}), f"failure closed ledger: {ledger}"
    _assert_feed_disposition(log, feed.feed_id, "failed")
    assert mock_feeds.statuses(feed.mock)[-1] == 200, "the retry after recovery never fetched the source"
    _assert_feed_disposition(recovered_log, feed.feed_id, "changed")
    assert recovered[feed.parsed] != before[feed.parsed], "the recovered source's parsed file was not published"
