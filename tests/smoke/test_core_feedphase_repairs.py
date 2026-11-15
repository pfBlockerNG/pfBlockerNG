"""#3977: native acceptance for publication recovery and list-script sequencing repairs."""

from __future__ import annotations

import contextlib
import json
import os
import shlex
import subprocess
import uuid
from collections.abc import Generator
from typing import Any

import pytest

from . import helpers as h
from .conftest import SmokeVM
from .test_core_update import (
    DB,
    _assert_feed_disposition,
    _prepare_mock_feeds,
    _run_update,
    _snapshot,
    await_idle,
)
from .test_core_update import core_vm as core_vm

pytestmark = pytest.mark.smoke

MANIFEST = "/var/unbound/pfb_py_sources.json"
LIST_SCRIPT_DIR = "/usr/local/pkg/pfblockerng/list_scripts"


@contextlib.contextmanager
def _restored_case(
    vm: SmokeVM,
) -> Generator[tuple[str, list[str], list[tuple[str, str]]], None, None]:
    """Restore the exact starting config and remove only this case's unique guest paths."""
    token = uuid.uuid4().hex[:12]
    snapshot = f"/tmp/pfb3977-{token}-config.xml"
    saved = vm.ssh("/bin/cp", "-p", "/conf/config.xml", snapshot)
    assert saved.returncode == 0, f"cannot snapshot config: {saved}"
    owned: list[str] = []
    status_aliases: list[tuple[str, str]] = []
    failures: list[BaseException] = []
    try:
        yield token, owned, status_aliases
    except BaseException as failure:
        failures.append(failure)
    finally:
        if owned:
            try:
                removed = vm.ssh("/bin/rm", "-rf", *owned)
                if removed.returncode != 0:
                    failures.append(RuntimeError(f"could not remove owned paths {owned!r}: {removed}"))
            except BaseException as failure:
                failures.append(failure)
        if status_aliases:
            try:
                closes = "".join(
                    f"pfb_sync_status_close_removed_alias({h._php_str(gtype)},{h._php_str(alias)},$pfb['dbdir']);"
                    for gtype, alias in dict.fromkeys(status_aliases)
                )
                closed = h.php_eval(
                    vm,
                    f"require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');pfb_global();{closes}echo 'OK';",
                )
                if closed.returncode != 0 or "OK" not in closed.stdout:
                    failures.append(RuntimeError(f"could not close owned sync status: {closed}"))
            except BaseException as failure:
                failures.append(failure)
        try:
            h.restore_pfb_config_baseline(vm, snapshot_path=snapshot)
        except BaseException as failure:
            failures.append(failure)
        try:
            h.tell_core_the_settings_changed(vm)
        except BaseException as failure:
            failures.append(failure)
        try:
            removed = vm.ssh("/bin/rm", "-f", snapshot)
            if removed.returncode != 0:
                failures.append(RuntimeError(f"could not remove config snapshot {snapshot}: {removed}"))
        except BaseException as failure:
            failures.append(failure)
        if len(failures) == 1:
            raise failures[0]
        if failures:
            raise BaseExceptionGroup("native repair fixture failures", failures)


def _write_guest(vm: SmokeVM, path: str, body: str, *, executable: bool = False) -> None:
    written = subprocess.run(
        vm.ssh_argv("/usr/bin/tee", path), input=body, text=True, capture_output=True, timeout=30, check=False
    )
    assert written.returncode == 0, f"cannot write {path}: {written.stderr}"
    if executable:
        changed = vm.ssh("/bin/chmod", "0755", path)
        assert changed.returncode == 0, f"cannot make {path} executable: {changed}"


def _install_list_script(vm: SmokeVM, owned: list[str], name: str, body: str) -> str:
    assert name == os.path.basename(name) and name not in ("", ".", "..")
    path = f"{LIST_SCRIPT_DIR}/{name}"
    assert vm.ssh("test", "-d", LIST_SCRIPT_DIR).returncode == 0, f"missing list-script dir {LIST_SCRIPT_DIR}"
    assert vm.ssh("test", "!", "-e", path).returncode == 0, f"refusing to replace existing script {path}"
    owned.append(path)
    _write_guest(vm, path, body, executable=True)
    return name


def _set_group_scripts(
    vm: SmokeVM,
    scripts: dict[str, tuple[str, str]],
    orders: dict[str, str] | None = None,
) -> None:
    rows = ",".join(
        f"{h._php_str(alias)}=>array({h._php_str(pre)},{h._php_str(post)})" for alias, (pre, post) in scripts.items()
    )
    order_rows = ",".join(f"{h._php_str(alias)}=>{h._php_str(order)}" for alias, order in (orders or {}).items())
    result = h.php_eval(
        vm,
        "$wanted=array(" + rows + ");"
        "$orders=array(" + order_rows + ");"
        f"$groups=config_get_path({h._php_str(h.CFG_DNSBL_LISTS)},array());"
        "foreach($groups as &$group){$name=(string)($group['aliasname']??'');"
        "if(isset($wanted[$name])){$group['script_pre']=$wanted[$name][0];"
        "$group['script_post']=$wanted[$name][1];}"
        "if(isset($orders[$name])){$group['order']=$orders[$name];}}unset($group);"
        f"config_set_path({h._php_str(h.CFG_DNSBL_LISTS)},$groups);"
        "write_config('pfBlockerNG smoke: native list scripts');echo 'OK';",
    )
    assert result.returncode == 0 and "OK" in result.stdout, f"script config failed: {result}"
    h.tell_core_the_settings_changed(vm)


def _dnsbl_payloads(vm: SmokeVM, header: str) -> list[str]:
    raw = _snapshot(vm, [f"{DB}/dnsbl/{header}.txt"])[f"{DB}/dnsbl/{header}.txt"][0]
    return [json.loads(line)[1] for line in raw.splitlines()]


def _manifest_row(vm: SmokeVM, header: str) -> dict[str, Any]:
    result = vm.ssh("cat", MANIFEST)
    assert result.returncode == 0, f"cannot read {MANIFEST}: {result.stderr}"
    rows = [row for row in json.loads(result.stdout)["feeds"] if row["feed"] == header]
    assert len(rows) == 1, f"active manifest must contain exactly one {header} row: {rows!r}"
    raw = rows[0].get("raw")
    assert isinstance(raw, str) and raw and not raw.startswith("/"), f"invalid raw member: {rows[0]!r}"
    member = vm.ssh("cat", f"/var/unbound/{raw}")
    assert member.returncode == 0, f"active manifest member is missing: {rows[0]!r}: {member.stderr}"
    rows[0]["_member"] = member.stdout
    return rows[0]


def _open_dnsbl_ledger(vm: SmokeVM) -> list[dict[str, Any]]:
    text = h._php_read_scalar(
        vm,
        "require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');pfb_global();",
        "json_encode(pfb_sync_status_list_open($pfb['dbdir'],'dnsbl'))",
    )
    return json.loads(text)


def _last_successful_checks(schedule: dict[str, Any]) -> dict[str, Any]:
    body = schedule.get("body")
    assert isinstance(body, dict), f"GetSchedule body must hold lastSuccessfulCheck: {schedule!r}"
    assert "lastSuccessfulCheck" in body, f"GetSchedule body is missing lastSuccessfulCheck: {body!r}"
    checks = body["lastSuccessfulCheck"]
    if type(checks) is list:
        assert checks == [], f"GetSchedule lastSuccessfulCheck must be a map, got {checks!r}"
        return {}
    assert isinstance(checks, dict), f"GetSchedule lastSuccessfulCheck must be a map, got {checks!r}"
    return checks


def _assert_first_dns_state(vm: SmokeVM, blocked: str, passed: str) -> None:
    h.flush_unbound_name(vm, blocked)
    h.flush_unbound_name(vm, passed)
    blocked_answer = h.dns_probe(vm, blocked)
    passed_answer = h.dns_probe(vm, passed)
    assert h.is_vip(blocked_answer), f"{blocked} is not blocked on its first answer: {blocked_answer}"
    assert not h.is_vip(passed_answer), f"{passed} is unexpectedly blocked on its first answer: {passed_answer}"


@pytest.mark.timeout(1800)
def test_dnsbl_publication_obstruction_retains_lkg_then_same_source_retry_publishes(
    core_vm: SmokeVM, mock_feeds: Any
) -> None:
    """A real ``feed.bk`` obstruction retains live LKG, then an unchanged retry consumes ready artifacts."""
    vm = core_vm
    with _restored_case(vm) as (token, owned, status_aliases):
        await_idle(vm)
        _prepare_mock_feeds(vm, dnsbl=True)
        old = h.unique_domain(f"repair-old-{token}")
        new = h.unique_domain(f"repair-new-{token}")
        name = f"repair-publication-{token}.txt"
        header = f"repairpub{token}"
        alias = f"repairgrp{token}"
        url = mock_feeds.register(name, old + "\n")
        mock_feeds.enable_etag(name, '"repair-v1"')
        status_aliases.append(("dnsbl", alias))
        h.inject_dnsbl_lists(vm, [(h.DnsblCase(aliasname=alias, header=header, feed_url=url), "Deny")])
        h.tell_core_the_settings_changed(vm)

        baseline, baseline_log = _run_update(vm, "manual", "dnsbl")
        assert baseline["result"] == "success", baseline
        _assert_feed_disposition(baseline_log, f"dnsbl:{header}", "changed")
        h.wait_unbound_ready(vm)
        h._require_pfb_dns_serving(vm)
        assert _dnsbl_payloads(vm, header) == [old]
        baseline_row = _manifest_row(vm, header)
        assert old in baseline_row["_member"] and new not in baseline_row["_member"]
        _assert_first_dns_state(vm, old, new)

        mock_feeds.set_content(name, new + "\n", etag='"repair-v2"')
        pending_update = f"{DB}/dnsbl/{header}.update"
        assert vm.ssh("test", "!", "-e", pending_update).returncode == 0, pending_update
        owned.append(pending_update)
        h.force_dnsbl_refetch(vm, header)
        assert vm.ssh("test", "-f", pending_update).returncode == 0, (
            f"failed to establish owned publication-retry marker {pending_update}"
        )
        obstruction = f"{DB}/dnsbl/{header}.bk"
        assert vm.ssh("test", "!", "-e", obstruction).returncode == 0, obstruction
        made = vm.ssh("/bin/mkdir", obstruction)
        assert made.returncode == 0, f"cannot create owned publication obstruction: {made}"
        owned.append(obstruction)
        before_failure_http = len(mock_feeds.statuses(name))

        failed, failed_log = _run_update(vm, "manual", "dnsbl")
        assert failed["result"] == "success", f"the pass must finish while the feed remains failed: {failed}"
        assert mock_feeds.statuses(name)[before_failure_http:] == [200], mock_feeds.statuses(name)
        assert "FeedPhase" in failed_log and "publication failed" in failed_log, failed_log[-4000:]
        for marker in (f"{DB}/dnsbl/{header}.fail", f"{DB}/dnsbl/{header}.update"):
            assert vm.ssh("test", "-f", marker).returncode == 0, f"publication failure did not retain {marker}"
        ledger = _open_dnsbl_ledger(vm)
        assert any(row["item"] == f"DNSBL_{alias}" and row["stage"] == "download" for row in ledger), ledger
        assert _dnsbl_payloads(vm, header) == [old]
        retained = _manifest_row(vm, header)
        assert old in retained["_member"] and new not in retained["_member"], retained
        _assert_first_dns_state(vm, old, new)

        removed = vm.ssh("/bin/rmdir", obstruction)
        assert removed.returncode == 0, f"cannot remove owned obstruction: {removed}"
        owned.remove(obstruction)
        before_retry_http = len(mock_feeds.statuses(name))
        swap_before = h.count_log_marker(vm, h.PFB_LOG, h.SWAP_LOG_MARKER)

        with h.due_feed_group(vm, "dnsbl", alias):
            recovered, recovered_log = _run_update(vm, "retry")
        assert recovered["result"] == "success", recovered
        _assert_feed_disposition(recovered_log, f"dnsbl:{header}", "unchanged")
        retry_http = mock_feeds.statuses(name)[before_retry_http:]
        assert 200 not in retry_http and set(retry_http).issubset({304}), (
            f"publication-only retry forced a body refetch: {retry_http}"
        )
        h.wait_zero_downtime_swap(vm, since=swap_before)
        assert _dnsbl_payloads(vm, header) == [new]
        published = _manifest_row(vm, header)
        assert new in published["_member"] and old not in published["_member"], published
        _assert_first_dns_state(vm, new, old)
        for marker in (f"{DB}/dnsbl/{header}.fail", f"{DB}/dnsbl/{header}.update"):
            assert vm.ssh("test", "!", "-e", marker).returncode == 0, f"recovery retained {marker}"
        assert _open_dnsbl_ledger(vm) == [], "recovery did not close the DNSBL failure ledger"


@pytest.mark.timeout(1200)
@pytest.mark.parametrize(
    ("layout", "expected_trace"),
    (
        ("same-group", "pre1\npost1\npre2\npost2\n"),
        ("across-groups", "pre1\npost1\npre2\npost2\n"),
        ("script-free-successor", "post1\n"),
        ("pre-only-observer", "post1\npre2\n"),
    ),
    ids=("same-group", "across-groups", "script-free-successor", "pre-only-observer"),
)
def test_native_two_feed_scripts_preserve_per_feed_side_effect_order(
    core_vm: SmokeVM, layout: str, expected_trace: str
) -> None:
    """Feed 2 must parse bytes produced after feed 1's real post/publication boundary."""
    vm = core_vm
    with _restored_case(vm) as (token, owned, status_aliases):
        await_idle(vm)
        _prepare_mock_feeds(vm, dnsbl=True)
        current = h.unique_domain(f"repair-current-{token}")
        previous = h.unique_domain(f"repair-previous-{token}")
        h1, h2 = f"repairone{token}", f"repairtwo{token}"
        a1, a2 = f"repairfirst{token}", f"repairsecond{token}"
        source1 = h.write_local_feed(vm, f"{h1}.source", current + "\n")
        owned.append(source1)
        source2 = h.write_local_feed(vm, f"{h2}.source", previous + "\n")
        owned.append(source2)
        trace = f"{DB}/repair-script-{token}.trace"
        owned.append(trace)
        _write_guest(vm, trace, "")

        qtrace, qsource2 = shlex.quote(trace), shlex.quote(source2)
        qaction1 = shlex.quote(f"{DB}/dnsbl/{h1}.txt")
        pre_name = f"dnsbl_pre_repair_{token}.sh"
        post_name = f"dnsbl_post_repair_{token}.sh"
        _install_list_script(
            vm,
            owned,
            pre_name,
            '#!/bin/sh\nset -eu\n[ "$#" -eq 2 ] && [ -f "$1" ] && [ "$2" = dnsbl ] || exit 91\n'
            + (
                "n=2\n"
                if layout == "pre-only-observer"
                else f"if /usr/bin/grep -q '^pre1$' {qtrace}; then n=2; else n=1; fi\n"
            )
            + f"printf 'pre%s\\n' \"$n\" >> {qtrace}\n"
            + (
                f"/usr/bin/grep -q {shlex.quote(current)} {qaction1}\nprintf '%s\\n' {shlex.quote(current)} > \"$1\"\n"
                if layout == "pre-only-observer"
                else ""
            ),
        )
        _install_list_script(
            vm,
            owned,
            post_name,
            '#!/bin/sh\nset -eu\n[ "$#" -eq 2 ] && [ -f "$1" ] && [ "$2" = dnsbl ] || exit 93\n'
            f'case "$1" in *{h1}*) n=1;; *{h2}*) n=2;; *) exit 94;; esac\n'
            f"printf 'post%s\\n' \"$n\" >> {qtrace}\n"
            f"[ \"$n\" -ne 1 ] || printf '%s\\n' {shlex.quote(current)} > {qsource2}\n",
        )
        pre1_name = f"dnsbl_pre_repair_{token}_first.sh"
        pre2_name = f"dnsbl_pre_repair_{token}_second.sh"
        if layout == "across-groups":
            for label, group_pre in ((1, pre1_name), (2, pre2_name)):
                _install_list_script(
                    vm,
                    owned,
                    group_pre,
                    '#!/bin/sh\nset -eu\n[ "$#" -eq 2 ] && [ -f "$1" ] && [ "$2" = dnsbl ] || exit 95\n'
                    f"printf 'pre{label}\\n' >> {qtrace}\n",
                )

        if layout == "same-group":
            first = h.DnsblCase(aliasname=a1, header=h1, feed_url=source1, extra_rows=[(h2, source2)])
            status_aliases.append(("dnsbl", a1))
            h.inject_dnsbl_lists(vm, [(first, "Deny")])
            scripts = {a1: (pre_name, post_name)}
        else:
            first = h.DnsblCase(aliasname=a1, header=h1, feed_url=source1)
            second = h.DnsblCase(aliasname=a2, header=h2, feed_url=source2)
            status_aliases.extend((("dnsbl", a1), ("dnsbl", a2)))
            h.inject_dnsbl_lists(vm, [(first, "Deny"), (second, "Deny")])
            if layout == "across-groups":
                scripts = {a1: (pre1_name, post_name), a2: (pre2_name, post_name)}
            elif layout == "script-free-successor":
                scripts = {a1: ("", post_name), a2: ("", "")}
            else:
                scripts = {a1: ("", post_name), a2: (pre_name, "")}
        orders = None if layout == "same-group" else {a1: "primary", a2: "default"}
        _set_group_scripts(vm, scripts, orders)

        update, log = _run_update(vm, "manual", "dnsbl")
        assert update["result"] == "success", update
        assert vm.ssh("cat", trace).stdout == expected_trace
        assert _dnsbl_payloads(vm, h2) == [current], (
            f"feed 2 did not observe feed 1's completed side effect; previous={previous!r}"
        )
        _assert_feed_disposition(log, f"dnsbl:{h1}", "changed")
        _assert_feed_disposition(log, f"dnsbl:{h2}", "changed")


@pytest.mark.timeout(1800)
def test_post_only_unchanged_reparse_runs_once_without_refetch_and_failure_stays_pending(
    core_vm: SmokeVM, mock_feeds: Any
) -> None:
    """Post-only local reparse and no-op hooks run once; a later post failure cannot report success."""
    vm = core_vm
    with _restored_case(vm) as (token, owned, status_aliases):
        await_idle(vm)
        _prepare_mock_feeds(vm, dnsbl=True)
        domain = h.unique_domain(f"repair-post-{token}")
        name = f"repair-post-{token}.txt"
        header, alias = f"repairpost{token}", f"repairpostgrp{token}"
        url = mock_feeds.register(name, domain + "\n")
        mock_feeds.enable_etag(name, '"repair-post-v1"')
        trace = f"{DB}/repair-post-{token}.trace"
        hook_trace = f"{DB}/repair-hooks-{token}.trace"
        owned.extend((trace, hook_trace))
        _write_guest(vm, trace, "")
        _write_guest(vm, hook_trace, "")

        post_name = f"dnsbl_post_repair_{token}.sh"
        post_path = f"{LIST_SCRIPT_DIR}/{post_name}"
        _install_list_script(
            vm,
            owned,
            post_name,
            '#!/bin/sh\nset -eu\n[ "$#" -eq 2 ] && [ -f "$1" ] && [ "$2" = dnsbl ] || exit 91\n'
            f"printf 'post\\n' >> {shlex.quote(trace)}\n",
        )
        pre_hook = f"hook_pre_repair_{token}.sh"
        post_hook = f"hook_post_repair_{token}.sh"
        owned.extend((f"{h.HOOK_SCRIPT_DIR}/{pre_hook}", f"{h.HOOK_SCRIPT_DIR}/{post_hook}"))
        h.set_update_hooks(
            vm,
            [
                {
                    "script": pre_hook,
                    "_body": f"#!/bin/sh\nprintf 'pre\\n' >> {shlex.quote(hook_trace)}\n",
                    "when": "pre",
                    "enabled": "on",
                    "timeout": "60",
                },
                {
                    "script": post_hook,
                    "_body": "#!/bin/sh\n"
                    + 'printf \'post|%s|%s|%s|%s\\n\' "$PFB_IP_CHANGED" "$PFB_DNSBL_CHANGED" '
                    + f'"$PFB_CHANGED_IP_ALIASES" "$PFB_CHANGED_DNSBL_GROUPS" >> {shlex.quote(hook_trace)}\n',
                    "when": "post",
                    "enabled": "on",
                    "timeout": "60",
                },
            ],
        )
        status_aliases.append(("dnsbl", alias))
        h.inject_dnsbl_lists(vm, [(h.DnsblCase(aliasname=alias, header=header, feed_url=url), "Deny")])
        _set_group_scripts(vm, {alias: ("", post_name)})

        baseline, _ = _run_update(vm, "manual", "dnsbl")
        assert baseline["result"] == "success", baseline
        assert vm.ssh("cat", trace).stdout == "post\n", "baseline did not execute the selected valid post script"
        _write_guest(vm, trace, "")
        _write_guest(vm, hook_trace, "")
        before_http = list(mock_feeds.statuses(name))
        original_before = _snapshot(vm, [f"{DB}/dnsblorig/{header}.orig"])

        unchanged, unchanged_log = _run_update(vm, "manual", "dnsbl")
        after_http = list(mock_feeds.statuses(name))
        post_trace = vm.ssh("cat", trace).stdout
        hooks_after = vm.ssh("cat", hook_trace).stdout
        original_after = _snapshot(vm, [f"{DB}/dnsblorig/{header}.orig"])
        payload_after = _dnsbl_payloads(vm, header)
        observed = (
            f"http={after_http!r} post={post_trace!r} hooks={hooks_after!r} "
            f"orig={original_after!r} payload={payload_after!r}"
        )
        assert unchanged["result"] == "success", f"{unchanged}; {observed}"
        assert after_http == before_http, f"local post-only reparse made a network request; {observed}"
        assert post_trace == "post\n", f"post-only script did not run exactly once; {observed}"
        _assert_feed_disposition(unchanged_log, f"dnsbl:{header}", "reparsed")
        assert hooks_after == "pre\npost|0|0||\n", (
            f"no-op global hooks must run once with zero flags and empty changed lists; {observed}"
        )
        assert original_after == original_before
        assert payload_after == [domain]
        assert _open_dnsbl_ledger(vm) == []

        _write_guest(
            vm,
            post_path,
            '#!/bin/sh\nset -eu\n[ "$#" -eq 2 ] && [ -f "$1" ] && [ "$2" = dnsbl ] || exit 91\n'
            f"printf 'post-fail\\n' >> {shlex.quote(trace)}\nexit 7\n",
            executable=True,
        )
        _write_guest(vm, trace, "")
        schedule_before = h.core_call(vm, "GetSchedule")
        assert schedule_before["status"] == 200, schedule_before
        successful_before = _last_successful_checks(schedule_before).get(f"dnsbl:{header}")
        with h.due_feed_group(vm, "dnsbl", alias):
            failed, _ = _run_update(vm, "retry")
        assert failed["result"] == "success", failed
        assert vm.ssh("cat", trace).stdout == "post-fail\n", "failing post script did not run exactly once"
        ledger = _open_dnsbl_ledger(vm)
        assert any(row["item"] == f"DNSBL_{alias}" and row["stage"] == "script" for row in ledger), ledger
        schedule_after = h.core_call(vm, "GetSchedule")
        assert schedule_after["status"] == 200, schedule_after
        assert _last_successful_checks(schedule_after).get(f"dnsbl:{header}") == successful_before, (
            f"post failure was reported as successful: before={schedule_before} after={schedule_after}"
        )
