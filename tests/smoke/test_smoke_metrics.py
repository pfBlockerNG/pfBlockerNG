"""Metrics export (#3522, #3757) — live-VM smoke of the textfile publisher.

Cases parse the real installed PHP writer's public textfile with the existing
Prometheus parser. The receiving-endpoint matrix pins exact labels and sums
without introducing a dependency on the upstream node_exporter service.

Tests:
    test_metrics_toggle_installs_cron_and_publishes   — cron line + a parseable, complete file
    test_metrics_pass_status_after_update_pass        — a real update pass records start/end
    test_metrics_pass_status_ignores_a_settings_save_pass — a settings-save pass leaves the pass times alone
    test_metrics_master_disable_removes_cron_and_file — master switch off tears the export down
    test_metrics_toggle_off_removes_cron_and_file     — option off tears the export down
    test_metrics_verb_publishes_nothing_while_disabled — the verb leaves no file while the option is off
    test_metrics_verb_ignores_a_stale_sentinel_while_the_option_is_off — a leftover sentinel cannot outvote a disable
    test_metrics_dir_missing_logs_once                — a missing textfile dir logs once, exits 0
    test_dns_dimensions_and_group_lifecycle           — real DNS counter labels and independent owner transitions

DESELECTED from the default ``python -m pytest`` (smoke-only). Run via::

    scripts/local-smoke.sh --marker smoke --filter metrics
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import secrets
from collections.abc import Iterator
from typing import TYPE_CHECKING
from urllib.parse import parse_qs

import pytest

from . import helpers as h
from .conftest import SmokeVM
from .test_smoke_dns_gateway import (
    BYPASSED_ALIAS_IP,
    CLIENT_LAN_IP,
    LAN_DESCRIPTION,
    LAN_V6_ADDR,
    LOG_TRANSPORT,
    PFSENSE_LAN_IP,
    TRANSPORTS,
    _ask,
    _ask_from_alias,
    _client_v6,
    _dig,
    _publish_listener_owner_table,
    _wait_dnsbl_row,
)
from .test_smoke_dns_gateway import gateway_on as gateway_on
from .test_smoke_dns_gateway import go_toolchain as go_toolchain
from .test_smoke_dns_gateway import gui as gui
from .test_smoke_dns_gateway import gw as gw
from .test_smoke_dns_gateway import probe_binary as probe_binary
from .test_smoke_dns_proxy import PROXY_RC, _apply, _capture, _client_alias, _dnsbl_rows, _php_ok, _set_proxy_toggle
from .ui.webui import CSRF_FIELD, scrape_form_fields

if TYPE_CHECKING:
    from prometheus_client.metrics_core import Metric

    from .conftest import _StubDnsServer
    from .test_smoke_dns_gateway import Gateway
    from .test_smoke_dns_proxy import State
    from .ui.webui import WebUI

_PFB_EXTRA = "/usr/local/pkg/pfblockerng/pfblockerng_extra.inc"
_TEXTFILE_DIR = "/var/tmp/node_exporter"
_PROM = f"{_TEXTFILE_DIR}/pfblockerng.prom"
_CRONTAB = "/etc/crontab"
_CRON_NEEDLE = "pfblockerng.php metrics"
_CRON_COMMAND = "/usr/bin/timeout -s TERM -k 5 50 /usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php metrics"
_SENTINEL = "/usr/local/etc/pfb_metrics_enabled"
_ERROR_LOG = f"{h.PFB_LOGDIR}/error.log"
_ERROR_MARKER = "Metrics export:"
_SOURCES = {
    "pfctl",
    "pf_rules",
    "dnsbl_db",
    "resolver_db",
    "schedule_state",
    "sync_status",
    "py_sync_status",
    "pass_status",
}

_FEED_ALIAS = "smokemetrics"
_FEED_ADDRESSES = ("192.0.2.30", "192.0.2.31")


@pytest.fixture(scope="module", autouse=True)
def deployed_vm(smoke_vm: SmokeVM) -> Iterator[SmokeVM]:
    """Deploy the branch .pkg once, with one IPv4 feed so a pfB table exists to export."""
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    feed_url = h.write_local_feed(smoke_vm, "smoke_metrics_ip.txt", "".join(f"{ip}/32\n" for ip in _FEED_ADDRESSES))
    spec = h.IpCase(aliasname=_FEED_ALIAS, feed_url=feed_url, header=_FEED_ALIAS, action="Deny_Both")
    h.inject_ip_lists(smoke_vm, [spec])
    h.reload(smoke_vm, "updateip", wait_unbound=False)
    h.apply_filter_sync(smoke_vm)
    try:
        yield smoke_vm
    finally:
        h.collect_host_diagnostics(smoke_vm)


@pytest.fixture(autouse=True)
def _textfile_dir(deployed_vm: SmokeVM) -> Iterator[None]:
    """Use the textfile directory, preserving a pre-existing node_exporter installation."""
    existed = deployed_vm.ssh("/bin/test", "-d", _TEXTFILE_DIR).returncode == 0
    made = deployed_vm.ssh("/usr/bin/install", "-d", "-m", "0755", _TEXTFILE_DIR)
    assert made.returncode == 0, f"could not create {_TEXTFILE_DIR}: {made.stderr!r}"
    try:
        yield
    finally:
        try:
            _set_export(deployed_vm, False)
            h.reload(deployed_vm, "update", wait_unbound=False)
        finally:
            if not existed:
                removed = deployed_vm.ssh("/bin/rmdir", _TEXTFILE_DIR)
                if removed.returncode != 0:
                    absent = deployed_vm.ssh(
                        f"test -x /var/tmp && test ! -e {_TEXTFILE_DIR} && test ! -L {_TEXTFILE_DIR}"
                    )
                    assert (
                        removed.returncode == 1
                        and removed.stderr == f"rmdir: {_TEXTFILE_DIR}: No such file or directory\n"
                        and absent.returncode == 0
                    ), f"owned textfile directory cleanup failed: {removed!r}; absence probe: {absent!r}"


def _set_export(vm: SmokeVM, on: bool) -> None:
    """Set the Metrics export option the way a system-context caller does (the page save is package-gated)."""
    toggle = "PfbToggle::On" if on else "PfbToggle::Off"
    result = h.php_eval(
        vm,
        f"require_once('{_PFB_EXTRA}');"
        f"PfbConfig::writeSystem('gen/pfb_metrics_export', {toggle});"
        "write_config('pfBlockerNG smoke: metrics export toggle');"
        "echo 'OK';",
    )
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_set_export({on}) failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}")


def _sync(vm: SmokeVM) -> None:
    """Run a sync pass, which reconciles the metrics cron entry (wait for no resolver: pf-level asserts only)."""
    h.reload(vm, "update", wait_unbound=False)


def _run_verb(vm: SmokeVM) -> None:
    """Run the metrics verb exactly as the cron entry does, minus the timeout wrapper."""
    result = vm.ssh(h.PHP_BIN, h.PFB_CLI, "metrics")
    assert result.returncode == 0, f"metrics verb failed: rc={result.returncode} {result.stdout!r} {result.stderr!r}"


def _cron_lines(vm: SmokeVM) -> list[str]:
    """Every /etc/crontab line carrying the metrics verb."""
    result = vm.ssh("/usr/bin/grep", "-F", _CRON_NEEDLE, _CRONTAB)
    assert result.returncode in (0, 1), f"grep {_CRONTAB} failed: rc={result.returncode} {result.stderr!r}"
    return result.stdout.splitlines()


def _exists(vm: SmokeVM, path: str) -> bool:
    return vm.ssh("/bin/test", "-e", path).returncode == 0


def _fetch_families(vm: SmokeVM) -> dict[str, Metric]:
    """Fetch the published file and parse it with the Prometheus client; a parse error fails the test."""
    # Deferred: the parser is a smoke-group dependency, and importing this module must not need it.
    from prometheus_client.parser import text_string_to_metric_families

    fetched = vm.ssh("/bin/cat", _PROM)
    assert fetched.returncode == 0, f"cannot read {_PROM}: {fetched.stderr!r}"
    return {family.name: family for family in text_string_to_metric_families(fetched.stdout)}


def _guest_epoch(vm: SmokeVM) -> int:
    result = vm.ssh("/bin/date", "+%s")
    assert result.returncode == 0, f"date failed: {result.stderr!r}"
    return int(result.stdout.strip())


def _pass_times(vm: SmokeVM) -> tuple[float, float]:
    """Published (last_start, last_end) of the update pass."""
    families = _fetch_families(vm)
    start = families["pfblockerng_update_last_start_timestamp_seconds"].samples[0].value
    end = families["pfblockerng_update_last_end_timestamp_seconds"].samples[0].value
    return start, end


@pytest.mark.smoke
@pytest.mark.timeout(300)
def test_metrics_toggle_installs_cron_and_publishes(deployed_vm: SmokeVM) -> None:
    """Enabling the option installs one bounded every-minute cron line and the verb publishes a valid file.

    Scenario:
        Given the option is on and a sync pass has run,
        Then /etc/crontab carries exactly one metrics line: minute '*', run as root, hard-bounded by timeout -k 5 50;
        When the verb runs,
        Then pfblockerng.prom exists with mode 0644, parses cleanly, carries pfblockerng_info (non-empty
            version), pfblockerng_metrics_source_up 1 for all eight sources (a source absent because its
            feature is off is up), and pfblockerng_ip_table_entries for the feed's pfB table with the
            count pfctl reports; and no temp file is left behind.
    """
    vm = deployed_vm
    _set_export(vm, True)
    _sync(vm)

    lines = _cron_lines(vm)
    assert len(lines) == 1, f"expected exactly one metrics cron line, found {lines!r}"
    minute, hour, mday, month, wday, who, command = lines[0].split(None, 6)
    assert (minute, hour, mday, month, wday) == ("*",) * 5, f"metrics cron must run every minute: {lines[0]!r}"
    assert who == "root", f"metrics cron must run as root: {lines[0]!r}"
    assert command.startswith(_CRON_COMMAND), f"metrics cron must be hard-bounded by timeout -k 5 50: {lines[0]!r}"

    _run_verb(vm)

    mode = vm.ssh("/usr/bin/stat", "-f", "%Lp", _PROM)
    assert mode.stdout.strip() == "644", f"{_PROM} mode must be 0644, got {mode.stdout!r} {mode.stderr!r}"

    families = _fetch_families(vm)
    info = families["pfblockerng_info"].samples
    assert len(info) == 1 and info[0].labels["version"], f"pfblockerng_info must carry a version: {info!r}"

    up = {s.labels["source"]: s.value for s in families["pfblockerng_metrics_source_up"].samples}
    assert up == dict.fromkeys(_SOURCES, 1.0), f"all eight sources must report up (an absent feature is up): {up!r}"

    # Expected tables come from pfctl itself, so the check does not skip when the VM has none.
    listed = vm.ssh(h.PFCTL, "-sT")
    assert listed.returncode == 0, f"pfctl -sT failed: {listed.stderr!r}"
    pfb_tables = {line.strip() for line in listed.stdout.splitlines() if line.strip().startswith("pfB_")}
    feed_table = f"pfB_{_FEED_ALIAS}_v4"
    assert feed_table in pfb_tables, f"precondition: pfctl -sT must list {feed_table}: {sorted(pfb_tables)}"
    entries = {s.labels["table"]: s.value for s in families["pfblockerng_ip_table_entries"].samples}
    assert set(entries) <= pfb_tables, f"exported tables missing from pfctl -sT: {sorted(set(entries) - pfb_tables)}"
    members = len(h.pfctl_table_members(vm, feed_table))
    assert members > 0, f"precondition: {feed_table} must hold the feed's addresses, or 0 == 0 proves nothing"
    assert entries.get(feed_table) == members, f"{feed_table} entry count must equal pfctl's membership: {entries!r}"

    # The publisher's temp file lives only for the rename; the minute cron can overlap this read.
    def no_temp_file() -> bool:
        names = vm.ssh("/bin/ls", "-A", _TEXTFILE_DIR).stdout.split()
        return not [name for name in names if name.startswith(".pfbmetrics_")]

    assert h.wait_until(no_temp_file, timeout=10.0, interval=1.0), "a .pfbmetrics_ temp file was left behind"


@pytest.mark.smoke
@pytest.mark.timeout(420)
def test_metrics_pass_status_after_update_pass(deployed_vm: SmokeVM) -> None:
    """A real update pass records its start and end, and the export reports both.

    Scenario:
        Given the option is on,
        When an update pass runs and the verb publishes afterwards,
        Then pfblockerng_update_last_end_timestamp_seconds >= pfblockerng_update_last_start_timestamp_seconds,
            and the start is no earlier than the guest clock read before the pass (a stale file cannot pass).
    """
    vm = deployed_vm
    _set_export(vm, True)
    before = _guest_epoch(vm)
    _sync(vm)
    _run_verb(vm)

    start, end = _pass_times(vm)
    assert start >= before, f"last_start {start} predates the pass (guest clock before it: {before})"
    assert end >= start > 0, f"a finished pass must have last_end >= last_start > 0: start={start} end={end}"


@pytest.mark.smoke
@pytest.mark.timeout(600)
def test_metrics_pass_status_ignores_a_settings_save_pass(deployed_vm: SmokeVM) -> None:
    """A settings-save pass is not an Update pass, so the recorded pass times do not move.

    Scenario:
        Given an update pass has recorded its start and end and the guest clock has moved past them,
        When a settings-save pass runs (``sync_package_pfblockerng('noupdates')`` sets ``$pfb['save']``),
        Then the published last_start and last_end are still exactly the update pass's.
    """
    vm = deployed_vm
    _set_export(vm, True)
    _sync(vm)
    _run_verb(vm)
    recorded = _pass_times(vm)
    assert recorded[1] >= recorded[0] > 0, f"precondition: the update pass must have recorded its times: {recorded}"
    assert h.wait_until(lambda: _guest_epoch(vm) > recorded[1], timeout=15.0, interval=1.0), (
        "precondition: the guest clock must move past the recorded pass, or a recording save pass could not show"
    )

    saved = h.php_eval(
        vm,
        "require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');"
        "global $pfb; pfb_global();"
        "sync_package_pfblockerng('noupdates');"
        "echo 'OK';",
        timeout=300,
    )
    assert "OK" in saved.stdout, f"settings-save pass failed: rc={saved.returncode} {saved.stdout!r} {saved.stderr!r}"
    _run_verb(vm)

    assert _pass_times(vm) == recorded, "a settings-save pass must leave last_start and last_end untouched"


@pytest.mark.smoke
@pytest.mark.timeout(420)
def test_metrics_master_disable_removes_cron_and_file(deployed_vm: SmokeVM) -> None:
    """Turning pfBlockerNG's master switch off removes the metrics cron line and the published file.

    Scenario:
        Given the option is on, the cron line is installed and the file is published,
        When the master switch is turned off and a sync pass runs,
        Then no metrics cron line and no pfblockerng.prom remain.
    """
    vm = deployed_vm
    _set_export(vm, True)
    _sync(vm)
    _run_verb(vm)
    assert len(_cron_lines(vm)) == 1, "precondition: the metrics cron line must be installed"
    assert _exists(vm, _PROM), "precondition: the file must be published"
    try:
        h.set_package_enabled(vm, False)
        _sync(vm)
        assert _cron_lines(vm) == [], "the metrics cron line must be removed while pfBlockerNG is disabled"
        assert not _exists(vm, _PROM), "pfblockerng.prom must be removed while pfBlockerNG is disabled"
    finally:
        h.set_package_enabled(vm, True)


@pytest.mark.smoke
@pytest.mark.timeout(420)
def test_metrics_toggle_off_removes_cron_and_file(deployed_vm: SmokeVM) -> None:
    """Turning the option off removes the metrics cron line and the published file.

    Scenario:
        Given the option is on, the cron line is installed and the file is published,
        When the option is turned off and a sync pass runs,
        Then no metrics cron line and no pfblockerng.prom remain.
    """
    vm = deployed_vm
    _set_export(vm, True)
    _sync(vm)
    _run_verb(vm)
    assert len(_cron_lines(vm)) == 1, "precondition: the metrics cron line must be installed"
    assert _exists(vm, _PROM), "precondition: the file must be published"

    _set_export(vm, False)
    _sync(vm)
    assert _cron_lines(vm) == [], "the metrics cron line must be removed when the option is off"
    assert not _exists(vm, _PROM), "pfblockerng.prom must be removed when the option is off"


@pytest.mark.smoke
@pytest.mark.timeout(300)
def test_metrics_verb_publishes_nothing_while_disabled(deployed_vm: SmokeVM) -> None:
    """The verb never publishes while the option is off, so a run that outlives a disable leaves no file.

    Scenario:
        Given the option is off (no cron line, no enabled sentinel) and the textfile directory exists,
        When the verb runs,
        Then it exits 0 and neither pfblockerng.prom nor a temp file is created.
    """
    vm = deployed_vm
    assert _cron_lines(vm) == [], "precondition: the option must be off"
    assert not _exists(vm, _SENTINEL), "precondition: the enabled sentinel must be absent"

    _run_verb(vm)

    assert not _exists(vm, _PROM), "the verb must not publish while the option is off"
    names = vm.ssh("/bin/ls", "-A", _TEXTFILE_DIR).stdout.split()
    assert names == [], f"the verb must leave nothing in the textfile directory while disabled: {names!r}"


@pytest.mark.smoke
@pytest.mark.timeout(300)
def test_metrics_verb_ignores_a_stale_sentinel_while_the_option_is_off(deployed_vm: SmokeVM) -> None:
    """A sentinel left behind by a sync that returned before reconciling does not authorize a publish.

    Scenario:
        Given the option is off in the configuration but the enabled sentinel is still there,
        When the verb runs,
        Then it exits 0, publishes nothing, and removes the stale sentinel.
    """
    vm = deployed_vm
    assert _cron_lines(vm) == [], "precondition: the option must be off"
    touched = vm.ssh("/usr/bin/touch", _SENTINEL)
    assert touched.returncode == 0, f"could not create {_SENTINEL}: {touched.stderr!r}"

    _run_verb(vm)

    assert not _exists(vm, _PROM), "a stale sentinel must not outvote the stored disable"
    assert not _exists(vm, _SENTINEL), "the stale sentinel must be removed"
    names = vm.ssh("/bin/ls", "-A", _TEXTFILE_DIR).stdout.split()
    assert names == [], f"the verb must leave nothing in the textfile directory: {names!r}"


@pytest.mark.smoke
@pytest.mark.timeout(300)
def test_metrics_dir_missing_logs_once(deployed_vm: SmokeVM) -> None:
    """A missing textfile directory is logged once per outage and never fatal.

    No sync pass runs, so no cron line is installed and no minute run can add a log line of its own to the
    count: the option is turned on in the configuration and the enabled sentinel is created directly.

    Scenario:
        Given a successful publish has run (re-arming the log) and the directory is then removed,
        When the verb runs twice,
        Then both runs exit 0, the directory is not recreated, and the pfBlockerNG error log
            gains exactly one 'Metrics export:' line.
    """
    vm = deployed_vm
    assert _cron_lines(vm) == [], "precondition: no cron line, so no cron run touches the log"
    _set_export(vm, True)
    touched = vm.ssh("/usr/bin/touch", _SENTINEL)
    assert touched.returncode == 0, f"could not create {_SENTINEL}: {touched.stderr!r}"
    _run_verb(vm)
    assert _exists(vm, _PROM), "precondition: a publish into the existing directory must succeed"

    removed = vm.ssh("/bin/rm", "-rf", _TEXTFILE_DIR)
    assert removed.returncode == 0, f"could not remove {_TEXTFILE_DIR}: {removed.stderr!r}"
    before = h.count_log_marker(vm, _ERROR_LOG, _ERROR_MARKER)
    _run_verb(vm)
    _run_verb(vm)
    after = h.count_log_marker(vm, _ERROR_LOG, _ERROR_MARKER)

    assert after - before == 1, f"two runs must log exactly one '{_ERROR_MARKER}' line: {before} -> {after}"
    assert not _exists(vm, _TEXTFILE_DIR), "the verb must never create the textfile directory"


_BLOCKED = "pfblockerng_dnsbl_blocked_queries_total"
_RESOLVER = "pfblockerng_dnsbl_resolver_queries_total"
_ENTRIES = "pfblockerng_dnsbl_group_entries"
_PKG = "/usr/local/pkg/pfblockerng/pfblockerng.inc"


def _export(vm: SmokeVM) -> dict[str, Metric]:
    _run_verb(vm)
    families = _fetch_families(vm)
    seen: set[tuple[str, tuple[tuple[str, str], ...]]] = set()
    for family in families.values():
        for sample in family.samples:
            if sample.name in (_BLOCKED, _RESOLVER):
                key = sample.name, tuple(sorted(sample.labels.items()))
                assert key not in seen, f"duplicate DNS metric label set: {sample}"
                seen.add(key)
                allowed = (
                    {"group", "origin", "qtype", "transport"} if sample.name == _BLOCKED else {"qtype", "transport"}
                )
                allowed |= {"listener_ip", "listener_interface", "client_ip"}
                for dimension in ("listener_ip", "client_ip"):
                    if dimension in sample.labels:
                        assert str(ipaddress.ip_address(sample.labels[dimension])) == sample.labels[dimension], sample
                assert "listener_interface" not in sample.labels or "listener_ip" in sample.labels, sample
                assert sample.labels.keys() <= allowed, f"unexpected DNS labels: {sample}"
                assert sample.labels.get("transport", "UDP") in {"UDP", "TCP", "DoT", "DoH", "DoQ"}, sample
                if "origin" in sample.labels:
                    assert sample.labels["origin"] in {"custom", "builtin"}, sample
    return families


def _samples(families: dict[str, Metric], name: str) -> list[tuple[dict[str, str], float]]:
    return [(s.labels, s.value) for family in families.values() for s in family.samples if s.name == name]


def _show_dns_prom(vm: SmokeVM, stage: str) -> None:
    fetched = vm.ssh("/bin/cat", _PROM)
    assert fetched.returncode == 0, f"cannot record {_PROM}: {fetched.stderr!r}"
    rows = [line for line in fetched.stdout.splitlines() if line.startswith((_BLOCKED, _RESOLVER))]
    print(f"DNS_PROMETHEUS {stage}\n" + "\n".join(rows), flush=True)


def _blocks(families: dict[str, Metric], group: str) -> dict[tuple[str, str], float]:
    counts: dict[tuple[str, str], float] = {}
    for labels, value in _samples(families, _BLOCKED):
        if labels.get("group") == group and value != 0:
            key = (labels.get("qtype", ""), labels.get("transport", ""))
            counts[key] = counts.get(key, 0) + value
    return counts


def _origin_blocks(families: dict[str, Metric], origin: str) -> float:
    return sum(
        value
        for labels, value in _samples(families, _BLOCKED)
        if labels.get("group") == "DNSBL_Regex" and labels.get("origin") == origin
    )


def _wait_blocks(vm: SmokeVM, expected: dict[str, dict[tuple[str, str], float]]) -> dict[str, Metric]:
    last: dict[str, Metric] = {}

    def committed() -> bool:
        nonlocal last
        last = _export(vm)
        return all(_blocks(last, group) == counts for group, counts in expected.items())

    try:
        h.wait_until(committed, timeout=60.0, interval=0.5)
    except RuntimeError as exc:
        actual = {group: _blocks(last, group) for group in expected}
        raise AssertionError(f"DNS metric commit: expected {expected}, got {actual}") from exc
    return last


def _accounting_apply_state(vm: SmokeVM) -> dict[str, object]:
    output = _php_ok(
        vm,
        f"require_once('{_PKG}'); pfb_global();"
        "$state = array('retry' => @file_get_contents($pfb['dnsbl_file'] . '.reload'),"
        "'pending' => pfb_pending_changes(), 'converged' => pfb_dnsbl_converged(),"
        "'vip_conf' => is_file($pfb['dnsbl_conf']), 'vip_service' => is_service_running('pfb_dnsbl'),"
        "'generation' => pfb_unbound_py_marker_generation($pfb['dnsbldir'] . '/pfb_py_reload'),"
        "'applied' => pfb_unbound_py_marker_generation($pfb['dnsbldir'] . '/pfb_py_reload.applied'),"
        "'fingerprint' => pfb_dnsbl_reload_fingerprint($pfb));"
        "echo '<<<ACCOUNTING>>>' . json_encode($state) . '<<<END>>>';",
        "read accounting apply state",
    )
    match = re.search(r"<<<ACCOUNTING>>>(.*?)<<<END>>>", output, re.DOTALL)
    assert match, f"missing accounting apply state: {output!r}"
    return json.loads(match.group(1))


def _epochs(vm: SmokeVM) -> dict[tuple[str, str], str]:
    output = _php_ok(
        vm,
        "$db = new SQLite3('/var/unbound/pfb_py_dnsbl.sqlite', SQLITE3_OPEN_READONLY);"
        "$rows = $db->query('SELECT owner, origin, epoch FROM dnsbl_group_epochs');"
        "$epochs = array(); while ($row = $rows->fetchArray(SQLITE3_ASSOC)) { $epochs[] = $row; }"
        "$owners = array(); foreach (array('dns_metric_totals', 'dns_metric_blocks') as $table) {"
        "$rows = $db->query('SELECT DISTINCT owner, origin FROM ' . $table);"
        "while ($row = $rows->fetchArray(SQLITE3_ASSOC)) { $owners[] = $row; } } $db->close();"
        "echo '<<<EPOCHS>>>' . json_encode(array('epochs' => $epochs, 'owners' => $owners)) . '<<<END>>>';",
        "read group incarnations",
    )
    match = re.search(r"<<<EPOCHS>>>(.*?)<<<END>>>", output, re.DOTALL)
    assert match, f"missing epoch snapshot: {output!r}"
    state = json.loads(match.group(1))
    epochs = {(row["owner"], row["origin"]): row["epoch"] for row in state["epochs"]}
    assert all((row["owner"], row["origin"]) in epochs for row in state["owners"]), f"orphan ownership: {state}"
    return epochs


def _group_action(vm: SmokeVM, alias: str, action: str) -> None:
    _php_ok(
        vm,
        f"$lists = config_get_path({h._php_str(h.CFG_DNSBL_LISTS)}, array());"
        f"foreach ($lists as &$list) {{ if ($list['aliasname'] === {h._php_str(alias)}) {{"
        f"$list['action'] = {h._php_str(action)}; }} }} unset($list);"
        f"config_set_path({h._php_str(h.CFG_DNSBL_LISTS)}, $lists);"
        "write_config('pfBlockerNG smoke: metric group enabled state');",
        "set group action",
    )
    _apply(vm)


@pytest.mark.smoke
@pytest.mark.timeout(1800)
def test_dns_dimensions_and_group_lifecycle(gw: Gateway, gateway_on: State, stub_dns: _StubDnsServer) -> None:
    """Real traffic survives disable/restart; deletion and explicit clear remove its counters.

    Given two configured groups and five original client transports,
    When A is disabled, re-enabled, deleted and recreated,
    Then only deletion changes its incarnation and resets its counts, never B's.
    With pfB-DNS off, DNSBL is off with it (#3770): a listed name asked of Unbound reaches the upstream.
    """
    vm = gw.vm
    token = secrets.token_hex(4)
    aliases = [f"smmetric{token}{suffix}" for suffix in ("a", "b")]
    groups = [f"DNSBL_{alias}" for alias in aliases]
    # Five requests, not a type/transport Cartesian product. DoQ reuses the existing A-only probe.
    cases = [
        (0, "udp", "TXT", "UDP"),
        (0, "tcp", "AAAA", "TCP"),
        (0, "dot", "HTTPS", "DoT"),
        (1, "doh-post", "TXT", "DoH"),
        (1, "doq", "A", "DoQ"),
    ]
    names = [h.unique_domain(f"metric-{transport}") for _, transport, _, _ in cases]
    recreated = h.unique_domain("metric-recreated")
    native = h.unique_domain("metric-native")
    held = h.unique_domain("metric-held")
    released = h.unique_domain("metric-released")
    feeds = [[names[i] for i, case in enumerate(cases) if case[0] == group] for group in (0, 1)]
    feeds[0].extend([recreated, native, held])
    feeds[1].append(released)
    specs = [
        h.DnsblCase(
            aliasname=alias,
            header=alias,
            mode=h.DnsblMode.VIP,
            feed_url=h.write_local_feed(vm, f"{alias}.txt", "".join(f"{name}\n" for name in feed)),
        )
        for alias, feed in zip(aliases, feeds, strict=True)
    ]
    state_path = f"/var/tmp/{aliases[0]}-metrics-state.json"
    paths = ", ".join(
        h._php_str(path) for path in (h.CFG_DNSBL_LISTS, h.CFG_DNSBL_SETTINGS, f"{h.CFG_GLOBAL}/pfb_metrics_export")
    )
    _php_ok(
        vm,
        f"$state = array('config' => array(), 'directory' => is_dir('/var/tmp/node_exporter'));"
        f"foreach (array({paths}) as $path) {{ $value = config_get_path($path, NULL);"
        "$state['config'][$path] = array('present' => $value !== NULL, 'value' => $value); }"
        "$file = '/var/tmp/node_exporter/pfblockerng.prom';"
        "$state['prom'] = is_file($file) ? base64_encode(file_get_contents($file)) : NULL;"
        "$state['mode'] = is_file($file) ? (fileperms($file) & 0777) : 0644;"
        f"file_put_contents({h._php_str(state_path)}, json_encode($state));",
        "save metric test state",
    )
    made = vm.ssh("/usr/bin/install", "-d", "-m", "0755", "/var/tmp/node_exporter")
    assert made.returncode == 0, f"textfile directory: {made.stderr!r}"
    try:
        h.inject_dnsbl_lists(vm, [(spec, "Deny") for spec in specs])
        _set_export(vm, True)
        _apply(vm)
        initial = _export(vm)
        entries = {labels["group"]: value for labels, value in _samples(initial, _ENTRIES)}
        assert {group: entries.get(group) for group in groups} == dict(zip(groups, map(len, feeds), strict=True)), (
            entries
        )
        assert all(not _blocks(initial, group) for group in groups), initial
        epochs = _epochs(vm)
        assert all(re.fullmatch(r"[0-9a-f]{32}", epochs[group, "custom"]) for group in groups), epochs

        wanted: dict[str, dict[tuple[str, str], float]] = {group: {} for group in groups}
        resolver_before = {tuple(sorted(labels.items())): value for labels, value in _samples(initial, _RESOLVER)}
        for name, (index, transport, qtype, label) in zip(names, cases, strict=True):
            if transport == "doq":
                answer, raw = _ask(gw.client, transport, name)
                assert h.is_vip(answer), f"DoQ must really block {name}: {answer}\n{raw}"
            else:
                reply = _dig(gw.client, transport, qtype, name)
                assert reply.rcode == "NOERROR", f"{transport}/{qtype}: {reply.raw}"
            assert not stub_dns.received(name), f"blocked query reached upstream: {stub_dns.received(name)}"
            wanted[groups[index]][qtype, label] = 1
        counted = _wait_blocks(vm, wanted)
        _show_dns_prom(vm, "after-five-transports")
        resolver_after = {tuple(sorted(labels.items())): value for labels, value in _samples(counted, _RESOLVER)}
        for _, _, qtype, transport in cases:
            key = tuple(
                sorted(
                    {
                        "qtype": qtype,
                        "transport": transport,
                        "listener_ip": PFSENSE_LAN_IP,
                        "listener_interface": LAN_DESCRIPTION,
                    }.items()
                )
            )
            assert resolver_after.get(key, 0) >= resolver_before.get(key, 0) + 1, (key, resolver_before, resolver_after)

        _group_action(vm, aliases[0], "Disabled")
        disabled = _export(vm)
        _show_dns_prom(vm, "disabled-owner-retained")
        assert not any(labels.get("group") == groups[0] for labels, _ in _samples(disabled, _ENTRIES)), disabled
        assert _epochs(vm)[groups[0], "custom"] == epochs[groups[0], "custom"], "disable replaced A's incarnation"
        assert {group: _blocks(disabled, group) for group in groups} == wanted, disabled
        _group_action(vm, aliases[0], "unbound")
        enabled = _export(vm)
        assert any(labels.get("group") == groups[0] for labels, _ in _samples(enabled, _ENTRIES)), enabled
        assert _epochs(vm)[groups[0], "custom"] == epochs[groups[0], "custom"], "re-enable replaced A's incarnation"
        assert {group: _blocks(enabled, group) for group in groups} == wanted, enabled

        prior_apply = _accounting_apply_state(vm)
        assert prior_apply["vip_conf"] and prior_apply["vip_service"], prior_apply
        null_b = h.DnsblCase(aliasname=aliases[1], header=aliases[1], mode=h.DnsblMode.NULL, feed_url=specs[1].feed_url)
        _php_ok(
            vm,
            "$db = new SQLite3('/var/unbound/pfb_py_dnsbl.sqlite'); $db->enableExceptions(TRUE);"
            '$db->exec("CREATE TRIGGER metric_accounting_refusal BEFORE DELETE ON dnsbl_group_epochs '
            "BEGIN SELECT RAISE(ABORT,'metrics smoke accounting refusal'); END\"); $db->close();",
            "refuse actual accounting deletion",
        )
        try:
            h.inject_dnsbl_lists(vm, [(null_b, "Deny")])
            failed = vm.ssh(
                h.PHP_BIN, h.PFB_CLI, "pfb_trigger", "scope=dnsbl", "force=false", "trigger=cron", timeout=180.0
            )
            assert failed.returncode == 1, f"accounting failure must fail the apply: {failed.stdout}\n{failed.stderr}"
            failed_apply = _accounting_apply_state(vm)
            assert failed_apply["retry"] == "accounting" and failed_apply["pending"], failed_apply
            assert failed_apply["vip_conf"] and failed_apply["vip_service"], failed_apply
            assert (failed_apply["generation"], failed_apply["applied"]) == (
                prior_apply["generation"],
                prior_apply["applied"],
            ), failed_apply
            assert _epochs(vm) == epochs, "failed reconciliation changed authority"
            answer, raw = _ask(gw.client, "udp", held)
            assert h.is_vip(answer), f"the old generation must still serve its VIP: {answer}\n{raw}"
            wanted[groups[0]]["A", "UDP"] = 1
            _wait_blocks(vm, wanted)
            _show_dns_prom(vm, "accounting-failure-old-generation-held")
        finally:
            _php_ok(
                vm,
                "$db = new SQLite3('/var/unbound/pfb_py_dnsbl.sqlite'); $db->enableExceptions(TRUE);"
                "$db->exec('DROP TRIGGER IF EXISTS metric_accounting_refusal'); $db->close();",
                "restore writable accounting",
            )
        recovered = vm.ssh(
            h.PHP_BIN, h.PFB_CLI, "pfb_trigger", "scope=dnsbl", "force=false", "trigger=cron", timeout=180.0
        )
        assert recovered.returncode == 0, f"accounting retry failed: {recovered.stdout}\n{recovered.stderr}"
        recovered_apply = _accounting_apply_state(vm)
        assert recovered_apply["fingerprint"] == failed_apply["fingerprint"], (failed_apply, recovered_apply)
        assert recovered_apply["retry"] is False and not recovered_apply["pending"], recovered_apply
        assert recovered_apply["converged"], recovered_apply
        assert not recovered_apply["vip_conf"] and not recovered_apply["vip_service"], recovered_apply
        deleted = _export(vm)
        _show_dns_prom(vm, "accounting-recovered-identical-generation")
        assert (groups[0], "custom") not in _epochs(vm), "deleted A still has an incarnation"
        assert not any(labels.get("group") == groups[0] for labels, _ in _samples(deleted, _BLOCKED)), deleted
        assert not any(labels.get("group") == groups[0] for labels, _ in _samples(deleted, _ENTRIES)), deleted
        assert _blocks(deleted, groups[1]) == wanted[groups[1]], deleted
        answer, raw = _ask(gw.client, "udp", released)
        assert set(answer.records) == {"0.0.0.0"}, f"the new generation must apply NULL blocking: {answer}\n{raw}"
        wanted[groups[1]]["A", "UDP"] = 1
        _wait_blocks(vm, {groups[0]: {}, groups[1]: wanted[groups[1]]})
        h.inject_dnsbl_lists(vm, [(spec, "Deny") for spec in specs])
        _apply(vm)
        new_epochs = _epochs(vm)
        assert new_epochs[groups[0], "custom"] != epochs[groups[0], "custom"], "recreated A reused deleted incarnation"
        assert new_epochs[groups[1], "custom"] == epochs[groups[1], "custom"], "recreating A changed B"
        wanted[groups[0]] = {}
        _wait_blocks(vm, wanted)
        answer, raw = _ask(gw.client, "udp", recreated)
        assert h.is_vip(answer), f"recreated A did not block: {answer}\n{raw}"
        wanted[groups[0]]["A", "UDP"] = 1
        _wait_blocks(vm, wanted)
        before_restart = _export(vm)
        resolver_counts = {
            tuple(sorted(labels.items())): value for labels, value in _samples(before_restart, _RESOLVER)
        }

        restarted = vm.ssh(PROXY_RC, "restart", timeout=180.0)
        assert restarted.returncode == 0, f"ordinary service restart: {restarted.stdout}\n{restarted.stderr}"
        h.wait_until(lambda: _capture(vm).service == "running", timeout=180.0, interval=0.5)
        after_restart = _export(vm)
        _show_dns_prom(vm, "ordinary-restart-retained")
        assert {group: _blocks(after_restart, group) for group in groups} == wanted, after_restart
        assert _epochs(vm) == new_epochs, "ordinary restart changed group incarnations"
        restarted_counts = {
            tuple(sorted(labels.items())): value for labels, value in _samples(after_restart, _RESOLVER)
        }
        assert all(restarted_counts.get(key, 0) >= value for key, value in resolver_counts.items()), (
            resolver_counts,
            restarted_counts,
        )
        _php_ok(vm, f"require_once('{_PKG}'); pfb_global(); pfBlockerNG_clearsqlite('cleardnsbl');", "clear counters")
        cleared = _wait_blocks(vm, {group: {} for group in groups})
        _show_dns_prom(vm, "explicit-clear")
        doq_labels = {
            "qtype": "A",
            "transport": "DoQ",
            "listener_ip": PFSENSE_LAN_IP,
            "listener_interface": LAN_DESCRIPTION,
        }
        assert any(labels == doq_labels and value > 0 for labels, value in _samples(after_restart, _RESOLVER))
        assert sum(value for labels, value in _samples(cleared, _RESOLVER) if labels == doq_labels) == 0, _samples(
            cleared, _RESOLVER
        )
        assert _epochs(vm) == new_epochs, "explicit clear replaced group incarnations"

        # The proxy counts a private-use type under its own receiving-socket labels.
        numeric_key = {
            "qtype": "TYPE65280",
            "transport": "UDP",
            "listener_ip": PFSENSE_LAN_IP,
            "listener_interface": LAN_DESCRIPTION,
        }
        before_value = sum(value for labels, value in _samples(_export(vm), _RESOLVER) if labels == numeric_key)
        numeric = h.unique_domain("metric-numeric")
        reply = _dig(gw.client, "udp", "TYPE65280", numeric)
        assert reply.rcode == "NOERROR", f"TYPE65280 query through the proxy: {reply.raw}"
        assert stub_dns.received(numeric), f"unlisted numeric query did not reach upstream: {reply.raw}"

        def numeric_committed() -> bool:
            return (
                sum(value for labels, value in _samples(_export(vm), _RESOLVER) if labels == numeric_key)
                == before_value + 1
            )

        assert h.wait_until(numeric_committed, timeout=60.0, interval=0.5), (
            before_value,
            _samples(_export(vm), _RESOLVER),
        )

        _set_proxy_toggle(vm, False)
        _apply(vm)
        reply = _dig(gw.client, "udp", "TXT", native)
        assert reply.rcode == "NOERROR", f"native TXT query: {reply.raw}"
        assert stub_dns.received(native), f"pfB-DNS off: the listed {native} must reach the upstream: {reply.raw}"

        # One collision phase: feed regex and global regex share the display group, never ownership.
        collision_alias = f"smmetric{token}regex"
        collision_owner = f"DNSBL_{collision_alias}"
        suffix = h.unique_domain("metric-regex")
        custom_name = f"feed1.{suffix}"
        builtin_name = f"builtin1.{suffix}"
        collision = h.DnsblCase(
            aliasname=collision_alias,
            header=collision_alias,
            mode=h.DnsblMode.VIP,
            feed_url=h.write_local_feed(vm, f"{collision_alias}.txt", rf"/^feed[0-9]+\.{re.escape(suffix)}$/" + "\n"),
            user_regex=[rf"^builtin[0-9]+\.{re.escape(suffix)}$"],
        )
        h.inject_dnsbl_lists(vm, [(spec, "Deny") for spec in [collision, *specs]])
        _php_ok(
            vm,
            f"config_set_path({h._php_str(h.CFG_DNSBL_SETTINGS + '/global_log_mode')}, 'override');"
            f"config_set_path({h._php_str(h.CFG_DNSBL_SETTINGS + '/global_log')}, 'enabled');"
            "write_config('pfBlockerNG smoke: explicit collision block mechanism');",
            "set collision block mechanism",
        )
        _apply(vm)
        collision_epochs = _epochs(vm)
        original_custom = collision_epochs[collision_owner, "custom"]
        original_builtin = collision_epochs["DNSBL_Regex", "builtin"]
        baseline = _export(vm)
        custom_before = _origin_blocks(baseline, "custom")
        builtin_before = _origin_blocks(baseline, "builtin")
        for name in (custom_name, builtin_name):
            answer, raw = _ask(gw.client, "udp", name)
            assert h.is_vip(answer), f"collision regex did not block {name}: {answer}\n{raw}"
            assert not stub_dns.received(name), f"collision block reached upstream: {name}"

        def collision_committed() -> bool:
            current = _export(vm)
            return (_origin_blocks(current, "custom"), _origin_blocks(current, "builtin")) == (
                custom_before + 1,
                builtin_before + 1,
            )

        assert h.wait_until(collision_committed, timeout=60.0, interval=0.5)
        h.inject_dnsbl_lists(vm, [(spec, "Deny") for spec in specs])
        _php_ok(
            vm,
            f"config_set_path({h._php_str(h.CFG_DNSBL_SETTINGS + '/pfb_regex')}, '');"
            "write_config('pfBlockerNG smoke: disable builtin regex after custom deletion');",
            "disable builtin regex",
        )
        _apply(vm)
        removed = _export(vm)
        _show_dns_prom(vm, "custom-regex-deleted-builtin-retained")
        assert _origin_blocks(removed, "custom") == custom_before, removed
        assert _origin_blocks(removed, "builtin") == builtin_before + 1, removed
        assert (collision_owner, "custom") not in _epochs(vm)
        assert _epochs(vm)["DNSBL_Regex", "builtin"] == original_builtin
        h.inject_dnsbl_lists(vm, [(spec, "Deny") for spec in [collision, *specs]])
        _apply(vm)
        assert _epochs(vm)[collision_owner, "custom"] != original_custom
        assert _epochs(vm)["DNSBL_Regex", "builtin"] == original_builtin
        assert _origin_blocks(_export(vm), "custom") == custom_before
        fresh_name = f"feed2.{suffix}"
        answer, raw = _ask(gw.client, "udp", fresh_name)
        assert h.is_vip(answer), f"fresh custom regex did not block: {answer}\n{raw}"
        assert not stub_dns.received(fresh_name)
        assert h.wait_until(collision_committed, timeout=60.0, interval=0.5)
    finally:
        try:
            try:
                _set_export(vm, False)
            finally:
                _php_ok(
                    vm,
                    f"$state = json_decode(file_get_contents({h._php_str(state_path)}), TRUE);"
                    "foreach ($state['config'] as $path => $entry) {"
                    "if ($entry['present']) { config_set_path($path, $entry['value']); } "
                    "else { config_del_path($path); } }"
                    "write_config('pfBlockerNG smoke: restore metric test configuration');",
                    "restore metric test configuration",
                )
                _apply(vm)
        finally:
            _php_ok(
                vm,
                f"$state = json_decode(file_get_contents({h._php_str(state_path)}), TRUE);"
                "$file = '/var/tmp/node_exporter/pfblockerng.prom';"
                "if ($state['prom'] !== NULL) { file_put_contents($file, base64_decode($state['prom']));"
                "chmod($file, $state['mode']); } else { @unlink($file); }"
                "if (!$state['directory']) { rmdir('/var/tmp/node_exporter'); }"
                f"unlink({h._php_str(state_path)});",
                "restore metric textfile state",
            )


def _save_client_privacy(vm: SmokeVM, gui: WebUI, on: bool, *, refused: bool = False) -> None:
    """Record the real Save boundary and preserve unrelated controls on success or refusal."""
    general = "/pfblockerng/pfblockerng_general.php"

    def snapshot(stage: str) -> dict[str, object]:
        output = _php_ok(
            vm,
            f"require_once('{_PKG}'); pfb_global();"
            f"$gen = config_get_path({h._php_str(h.CFG_GLOBAL)}, array());"
            "$effectiveGen = array(); $foreignGen = $gen;"
            "foreach (pfb_cfg_registry() as $key => $entry) {"
            "if (!str_starts_with($key, 'gen/')) { continue; }"
            "$bare = substr($key, 4); $value = PfbConfig::read($key);"
            "$effectiveGen[$bare] = $value instanceof PfbStoredEnum ? $value->toStored() : $value;"
            "unset($foreignGen[$bare]); }"
            "unset($effectiveGen['pfb_metrics_client_ip']);"
            "$state = array('gen' => $gen, 'effectiveGen' => $effectiveGen, 'foreignGen' => $foreignGen,"
            f"'dnsbl' => config_get_path({h._php_str(h.CFG_DNSBL_SETTINGS)}, array()),"
            "'registry' => array('enable_cb' => PfbConfig::read('gen/enable_cb')->value,"
            "'pfb_dnsbl' => PfbConfig::read('dnsbl/pfb_dnsbl')->value,"
            "'active' => pfb_dnsbl_active()));"
            "echo '<<<CONTROLS>>>' . json_encode($state) . '<<<END>>>';",
            "capture privacy Save controls",
        )
        match = re.search(r"<<<CONTROLS>>>(.*?)<<<END>>>", output, re.DOTALL)
        assert match, output
        state = json.loads(match.group(1))
        script = vm.ssh("/bin/cat", PROXY_RC)
        assert script.returncode == 0, script.stderr
        print(f"PRIVACY_SAVE {stage} config={json.dumps(state, sort_keys=True)}\n{script.stdout}", flush=True)
        return state

    def controls() -> dict[str, str]:
        page = gui.get(general)
        assert page.status_code == 200, page.text
        return {
            key: value
            for key, value in scrape_form_fields(page.text).items()
            if key not in (CSRF_FIELD, "save", "pfb_metrics_client_ip")
        }

    before = snapshot("before")
    before_controls = controls()
    posted = {"pfb_metrics_client_ip": "on" if on else ""}
    submitted_controls = dict(before_controls)
    if refused:
        posted["log_syslog"] = "" if before_controls.get("log_syslog", "") == "on" else "on"
        submitted_controls["log_syslog"] = posted["log_syslog"]
    response = gui.post(general, posted)
    submitted = None
    for reply in [*response.history, response]:
        if reply.request.method == "POST":
            body = reply.request.body
            if isinstance(body, bytes):
                body = body.decode("utf-8")
            assert isinstance(body, str), f"General Save did not submit an encoded form: {type(body)!r}"
            submitted = parse_qs(body, keep_blank_values=True)
            submitted.pop(CSRF_FIELD, None)
            print(f"PRIVACY_SAVE submitted={json.dumps(submitted, sort_keys=True)}", flush=True)
    assert submitted is not None, "real General Save did not expose a captured POST request"
    after = snapshot("after")
    after_controls = controls()
    assert response.status_code == 200, response.text
    if refused:
        assert "privacy3757 refused Save" in response.text, response.text
        assert "still enabled" in response.text, response.text
        assert "No General settings were saved." in response.text, response.text
        assert after["gen"] == before["gen"], (before, after)
    else:
        assert h.config_get(vm, f"{h.CFG_GLOBAL}/pfb_metrics_client_ip") == ("on" if on else ""), response.text
    assert {key: values for key, values in submitted.items() if key not in ("save", "pfb_metrics_client_ip")} == {
        key: [value] for key, value in submitted_controls.items()
    }, (submitted_controls, submitted)
    assert after["effectiveGen"] == before["effectiveGen"], (before, after)
    assert after["foreignGen"] == before["foreignGen"], (before, after)
    assert after["dnsbl"] == before["dnsbl"], (before, after)
    assert after_controls == before_controls, (before_controls, after_controls, before, after)
    assert after["registry"] == before["registry"], (before, after)


def _snapshot_endpoint_metric_config(vm: SmokeVM, state_path: str) -> None:
    paths = ", ".join(h._php_str(path) for path in (h.CFG_DNSBL_LISTS, h.CFG_DNSBL_SETTINGS, h.CFG_GLOBAL))
    _php_ok(
        vm,
        "$state = array();"
        f"foreach (array({paths}) as $path) {{ $value = config_get_path($path, NULL);"
        "$state[$path] = array('present' => $value !== NULL, 'value' => $value); }"
        f"file_put_contents({h._php_str(state_path)}, json_encode($state));",
        "save endpoint metric configuration",
    )


def _restore_endpoint_metric_config(vm: SmokeVM, state_path: str) -> None:
    _php_ok(
        vm,
        f"$state = json_decode(file_get_contents({h._php_str(state_path)}), TRUE);"
        "foreach ($state as $path => $entry) {"
        "if ($entry['present']) { config_set_path($path, $entry['value']); } "
        "else { config_del_path($path); } }"
        "write_config('pfBlockerNG smoke: restore endpoint metric configuration');"
        f"unlink({h._php_str(state_path)});",
        "restore endpoint metric configuration",
    )


@pytest.mark.smoke
@pytest.mark.timeout(1800)
def test_dns_client_privacy_save_purges_labels_and_fences_old_worker_retry(
    gw: Gateway, gateway_on: State, gui: WebUI
) -> None:
    """Actual two-client traffic, Save-time purge, enabled restart and failed-batch retry."""
    vm = gw.vm
    # gateway_on can validly inherit DNSBL disabled; inject_dnsbl_lists enables both core and DNSBL below.
    client_path = f"{h.CFG_GLOBAL}/pfb_metrics_client_ip"
    prior_client = h.config_get_state(vm, client_path)
    alias = f"smprivacy{secrets.token_hex(4)}"
    group = f"DNSBL_{alias}"
    state_path = f"/var/tmp/{alias}-metrics-state.json"
    _snapshot_endpoint_metric_config(vm, state_path)
    names = [h.unique_domain("privacy") for _ in range(8)]
    spec = h.DnsblCase(
        aliasname=alias,
        header=alias,
        mode=h.DnsblMode.VIP,
        feed_url=h.write_local_feed(vm, f"{alias}.txt", "".join(f"{name}\n" for name in names)),
    )

    def counted(total: int, clients: dict[str, float]) -> None:
        current = _wait_blocks(vm, {group: {("A", "UDP"): total}})
        rows = [(labels, value) for labels, value in _samples(current, _BLOCKED) if labels.get("group") == group]
        assert rows, "privacy assertions require actual counted requests"
        assert sum(value for _, value in rows) == total, rows
        assert [value for labels, value in rows if labels == {"group": group}] == [0], rows
        attributed = [(labels, value) for labels, value in rows if labels != {"group": group}]
        assert all(labels.get("listener_ip") == PFSENSE_LAN_IP for labels, _ in attributed), rows
        assert all(labels.get("listener_interface") == LAN_DESCRIPTION for labels, _ in attributed), rows
        actual: dict[str, float] = {}
        for labels, value in rows:
            if "client_ip" in labels:
                actual[labels["client_ip"]] = actual.get(labels["client_ip"], 0) + value
        assert actual == clients, rows
        if not clients:
            assert all("client_ip" not in labels for labels, _ in rows), rows

    def ask(index: int, second: bool = False) -> None:
        answer, raw = _ask_from_alias(gw, "udp", names[index]) if second else _ask(gw.client, "udp", names[index])
        assert h.is_vip(answer), raw

    def writer_state() -> dict[str, int]:
        queries = {
            "policy": "SELECT client_ip FROM dns_metric_settings WHERE row=0",
            "trigger": "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name='privacy3757'",
            "aggregate": f"SELECT SUM(count) FROM dns_metric_totals WHERE groupname='{group}'",
            "detail": f"SELECT SUM(count) FROM dns_metric_blocks WHERE groupname='{group}'",
            "legacy": f"SELECT SUM(counter) FROM dnsbl WHERE groupname='{group}'",
        }
        output = _php_ok(
            vm,
            "$db = new SQLite3('/var/unbound/pfb_py_dnsbl.sqlite'); $db->enableExceptions(TRUE);"
            "$db->exec('BEGIN'); $state = array();"
            + "".join(
                f"$state[{h._php_str(key)}] = $db->querySingle({h._php_str(query)});" for key, query in queries.items()
            )
            + "$db->exec('COMMIT'); $db->close();"
            "echo '<<<WRITER>>>' . json_encode($state) . '<<<END>>>';",
            "capture held metric writer state",
        )
        match = re.search(r"<<<WRITER>>>(.*?)<<<END>>>", output, re.DOTALL)
        assert match, output
        return json.loads(match.group(1))

    def privacy_state(stage: str) -> dict:
        output = _php_ok(
            vm,
            f"require_once('{_PKG}'); pfb_global();"
            "$files = array_merge(pfb_dnsbl_loaded_input_paths($pfb),"
            "array($pfb['unbound_py_conf'],"
            "$pfb['dns_proxy_gateway_applied'], $pfb['dnsbldir'].'/pfb_py_reload',"
            "$pfb['dnsbldir'].'/pfb_py_reload.applied'));"
            "$fence = function() use ($files) { $out = array(); foreach ($files as $file) {"
            "clearstatcache(TRUE, $file); if (!is_file($file)) { $out[$file] = NULL; continue; }"
            "$hash = hash_file('sha256',$file); $stat = stat($file);"
            "$out[$file] = array('sha256'=>$hash, 'ino'=>$stat['ino'], 'size'=>$stat['size'],"
            "'mtime'=>$stat['mtime'], 'ctime'=>$stat['ctime']); } return $out; };"
            "$before = $fence();"
            "$state = array('ready'=>pfb_dns_proxy_ready(),"
            "'gateway_pid'=>trim((string)@file_get_contents($pfb['dns_proxy_ready'])),"
            "'ini'=>parse_ini_file($pfb['unbound_py_conf'], FALSE, INI_SCANNER_RAW),"
            "'reload'=>@file_get_contents($pfb['dnsbldir'].'/pfb_py_reload'),"
            "'applied'=>@file_get_contents($pfb['dnsbldir'].'/pfb_py_reload.applied'),"
            "'generation'=>pfb_unbound_py_marker_generation($pfb['dnsbldir'].'/pfb_py_reload'),"
            "'applied_generation'=>pfb_unbound_py_marker_generation($pfb['dnsbldir'].'/pfb_py_reload.applied'),"
            "'gateway_applied'=>trim((string)@file_get_contents($pfb['dns_proxy_gateway_applied'])),"
            "'source_fingerprint'=>pfb_dnsbl_reload_fingerprint($pfb), 'db'=>array());"
            "foreach (array('resolver'=>array($pfb['dnsbl_resolver'],'dns_metric_queries'),"
            "'dnsbl'=>array($pfb['dnsbl_info'],'dns_metric_blocks')) as $kind=>$spec) {"
            "$db = new SQLite3($spec[0], SQLITE3_OPEN_READONLY); $db->enableExceptions(TRUE);"
            "$db->exec('BEGIN'); $rows = array();"
            "$result = $db->query('SELECT client_ip,SUM(count) AS count FROM '.$spec[1].' GROUP BY client_ip');"
            "while ($row = $result->fetchArray(SQLITE3_ASSOC)) { $rows[] = $row; }"
            "$state['db'][$kind] = array('policy'=>$db->querySingle("
            "'SELECT client_ip,epoch FROM dns_metric_settings WHERE row=0', TRUE), 'clients'=>$rows);"
            "if ($kind === 'dnsbl') { $state['db'][$kind]['group_clients'] = array();"
            '$result = $db->query("SELECT client_ip,SUM(count) AS count FROM dns_metric_blocks '
            f"WHERE groupname='{group}' GROUP BY client_ip\");"
            "while ($row = $result->fetchArray(SQLITE3_ASSOC)) { $state['db'][$kind]['group_clients'][] = $row; } }"
            "$db->exec('COMMIT'); $db->close(); }"
            "$state['fences'] = $before; $state['stable'] = $before === $fence();"
            "echo '<<<PRIVACY>>>' . json_encode($state) . '<<<END>>>';",
            "read privacy activation fences",
        )
        match = re.search(r"<<<PRIVACY>>>(.*?)<<<END>>>", output, re.DOTALL)
        assert match, output
        state = json.loads(match.group(1))
        print(f"PRIVACY_STATE {stage}={json.dumps(state, sort_keys=True)}", flush=True)
        assert state["stable"], state
        assert state["ready"] and state["gateway_pid"].isdigit(), state
        assert state["gateway_applied"], state
        # These are observed file generations, not the in-process Snapshot.gen.
        for raw_key, parsed_key in (("reload", "generation"), ("applied", "applied_generation")):
            raw_marker = state[raw_key]
            assert isinstance(raw_marker, str) and re.fullmatch(r"(?:0|[1-9][0-9]*)\n?", raw_marker), state
            assert int(raw_marker) == state[parsed_key], state
        assert state["generation"] == state["applied_generation"], state
        return state

    def raw_clients(state: dict, enabled: bool, total: int, clients: dict[str, int]) -> None:
        for database in state["db"].values():
            assert database["policy"]["client_ip"] == int(enabled), state
            assert re.fullmatch(r"[0-9a-f]{32}", database["policy"]["epoch"]), state
            assert all(row["client_ip"] != BYPASSED_ALIAS_IP for row in database["clients"]), state
            if not enabled:
                assert all(row["client_ip"] == "" for row in database["clients"]), state
        actual = {row["client_ip"]: row["count"] for row in state["db"]["dnsbl"]["group_clients"]}
        assert actual == {"": total - sum(clients.values()), **clients}, state

    try:
        h.inject_dnsbl_lists(vm, [(spec, "Deny")])
        _set_export(vm, True)
        _save_client_privacy(vm, gui, False)
        h.config_restore_state(vm, client_path, (False, ""))
        assert h.config_get_state(vm, client_path) == (False, ""), "default-OFF proof needs an absent setting"
        _apply(vm)
        print(f"PRIVACY_APPLY default-off={_capture(vm)!r}", flush=True)
        with _client_alias(gw.client, BYPASSED_ALIAS_IP):
            ask(0)
            ask(1, True)
            counted(2, {})
            _save_client_privacy(vm, gui, True)
            _apply(vm)
            print(f"PRIVACY_APPLY enabled={_capture(vm)!r}", flush=True)
            ask(2)
            ask(3, True)
            counted(4, {CLIENT_LAN_IP: 1, BYPASSED_ALIAS_IP: 1})
            restarted = vm.ssh(PROXY_RC, "restart", timeout=180.0)
            assert restarted.returncode == 0, restarted.stdout + restarted.stderr
            h.wait_until(lambda: _capture(vm).service == "running", timeout=180.0, interval=0.5)
            counted(4, {CLIENT_LAN_IP: 1, BYPASSED_ALIAS_IP: 1})
            _php_ok(
                vm,
                "$db = new SQLite3('/var/unbound/pfb_py_dnsbl.sqlite'); $db->enableExceptions(TRUE);"
                '$db->exec("CREATE TRIGGER privacy3757_save BEFORE DELETE ON dns_metric_blocks '
                "BEGIN SELECT RAISE(ABORT,'privacy3757 refused Save'); END\"); $db->close();",
                "refuse the required privacy transaction",
            )
            try:
                _save_client_privacy(vm, gui, False, refused=True)
                counted(4, {CLIENT_LAN_IP: 1, BYPASSED_ALIAS_IP: 1})
            finally:
                _php_ok(
                    vm,
                    "$db = new SQLite3('/var/unbound/pfb_py_dnsbl.sqlite');"
                    "$db->exec('DROP TRIGGER IF EXISTS privacy3757_save'); $db->close();",
                    "release the refused privacy transaction",
                )
            expected_writer = {"policy": 1, "trigger": 0, "aggregate": 4, "detail": 4, "legacy": 4}
            assert writer_state() == expected_writer
            error_path = f"{h.PFB_LOGDIR}/py_error.log"
            before_error = h.read_log_file(vm, error_path)
            # Fail a real client-bearing batch; OFF can still coalesce to blank client_ip.
            _php_ok(
                vm,
                "$db = new SQLite3('/var/unbound/pfb_py_dnsbl.sqlite'); $db->enableExceptions(TRUE);"
                '$db->exec("CREATE TRIGGER privacy3757 BEFORE INSERT ON dns_metric_blocks '
                "WHEN NEW.client_ip != '' BEGIN SELECT RAISE(ABORT,'privacy3757 retry'); END\"); $db->close();",
                "hold client-bearing metric retry",
            )
            ask(4, True)
            expected_writer["trigger"] = 1

            def failed_writer_held() -> bool:
                assert writer_state() == expected_writer, "held writer changed policy, trigger or committed counts"
                errors = h.read_log_file(vm, error_path)
                assert errors.startswith(before_error), "module error log rotated during failed-writer proof"
                fresh_error = re.search(
                    r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d,\d+\|ERROR\|",
                    errors[len(before_error) :],
                    re.MULTILINE,
                )
                rows = _dnsbl_rows(vm, names[4])
                if not fresh_error or not rows:
                    return False
                assert len(rows) == 1, rows
                assert rows[0][3] == BYPASSED_ALIAS_IP and rows[0][11:14] == ["UDP", PFSENSE_LAN_IP, LAN_DESCRIPTION], (
                    rows
                )
                return True

            h.wait_until(failed_writer_held, timeout=60.0, interval=0.5)
            counted(4, {CLIENT_LAN_IP: 1, BYPASSED_ALIAS_IP: 1})
            _save_client_privacy(vm, gui, False)
            off_saved = privacy_state("off-saved")
            assert off_saved["ini"]["metrics_client_ip"] == "off", off_saved
            # Save may already have committed the blank retry while restarting the service.
            saved_total = sum(row["count"] for row in off_saved["db"]["dnsbl"]["group_clients"])
            assert saved_total in (4, 5), off_saved
            raw_clients(off_saved, False, saved_total, {})
            unpublished = vm.ssh("/bin/sh", "-c", f"test ! -e {_PROM} && test ! -L {_PROM}")
            assert unpublished.returncode in (0, 1), unpublished.stderr
            if unpublished.returncode != 0:
                assert all(
                    "client_ip" not in sample.labels
                    for family in _fetch_families(vm).values()
                    for sample in family.samples
                ), "OFF Save left a published client label"
            _php_ok(
                vm,
                "$db = new SQLite3('/var/unbound/pfb_py_dnsbl.sqlite');"
                "$db->exec('DROP TRIGGER privacy3757'); $db->close();",
                "release old metric retry",
            )
            counted(5, {})
            raw_clients(privacy_state("old-alias-retried"), False, 5, {})
            ask(5)
            counted(6, {})
            before_on = privacy_state("off-six-before-on")
            raw_clients(before_on, False, 6, {})
            assert before_on["ini"]["metrics_client_ip"] == "off", before_on
            assert _capture(vm).service == "running", before_on
            assert {kind: db["policy"] for kind, db in before_on["db"].items()} == {
                kind: db["policy"] for kind, db in off_saved["db"].items()
            }, (off_saved, before_on)
            _save_client_privacy(vm, gui, True)
            activated = privacy_state("on-saved")
            assert _capture(vm).service == "running", activated
            assert activated["gateway_pid"] != before_on["gateway_pid"], (before_on, activated)
            assert activated["ini"]["metrics_client_ip"] == "on", activated
            assert activated["gateway_applied"] == before_on["gateway_applied"], (before_on, activated)
            assert activated["source_fingerprint"] == before_on["source_fingerprint"], (before_on, activated)
            raw_clients(activated, True, 6, {})
            for kind, database in activated["db"].items():
                assert database["policy"]["epoch"] != before_on["db"][kind]["policy"]["epoch"], activated
                assert database["policy"]["epoch"] != off_saved["db"][kind]["policy"]["epoch"], activated
            # The gateway is the one process that decides: its new pid above is the fresh module init.
            ask(6)
            counted(7, {CLIENT_LAN_IP: 1})
            after_seven = privacy_state("on-seven")
            raw_clients(after_seven, True, 7, {CLIENT_LAN_IP: 1})
            assert after_seven["fences"] == activated["fences"], (activated, after_seven)
            assert after_seven["gateway_pid"] == activated["gateway_pid"], (activated, after_seven)
            assert {kind: db["policy"] for kind, db in after_seven["db"].items()} == {
                kind: db["policy"] for kind, db in activated["db"].items()
            }, (activated, after_seven)
            _apply(vm)
            ask(7)
            counted(8, {CLIENT_LAN_IP: 2})
            after_eight = privacy_state("applied-eight")
            raw_clients(after_eight, True, 8, {CLIENT_LAN_IP: 2})
            assert {kind: db["policy"] for kind, db in after_eight["db"].items()} == {
                kind: db["policy"] for kind, db in activated["db"].items()
            }, (activated, after_eight)
            assert BYPASSED_ALIAS_IP not in vm.ssh("/bin/cat", _PROM).stdout, "purged old client reappeared"
    finally:
        try:
            _php_ok(
                vm,
                "$db = new SQLite3('/var/unbound/pfb_py_dnsbl.sqlite');"
                "$db->exec('DROP TRIGGER IF EXISTS privacy3757'); $db->close();",
                "remove privacy retry fixture",
            )
        finally:
            try:
                _save_client_privacy(vm, gui, prior_client[1] == "on")
            finally:
                try:
                    _restore_endpoint_metric_config(vm, state_path)
                finally:
                    _apply(vm)


@pytest.mark.smoke
@pytest.mark.timeout(1800)
def test_dns_receiving_endpoint_matrix_reaches_public_metrics(gw: Gateway, gateway_on: State, gui: WebUI) -> None:
    """Native-valid physical owners cover 12 requests; isolated trusted Unicode metadata covers two.

    The isolated control-table phase tests encoding, not pfSense interface UI admission.
    """
    vm = gw.vm
    client_path = f"{h.CFG_GLOBAL}/pfb_metrics_client_ip"
    prior_client = h.config_get_state(vm, client_path)
    alias = f"smendpoint{secrets.token_hex(4)}"
    group = f"DNSBL_{alias}"
    state_path = f"/var/tmp/{alias}-metrics-state.json"
    _snapshot_endpoint_metric_config(vm, state_path)
    names = {
        (address, transport): h.unique_domain("endpoint-metric")
        for address in (PFSENSE_LAN_IP, LAN_V6_ADDR)
        for transport in TRANSPORTS
    }
    unicode_owner = 'LAN, "旧" \\ & OWNER'
    isolated_names = {address: h.unique_domain("endpoint-unicode") for address in (PFSENSE_LAN_IP, LAN_V6_ADDR)}
    spec = h.DnsblCase(
        aliasname=alias,
        header=alias,
        mode=h.DnsblMode.VIP,
        feed_url=h.write_local_feed(
            vm, f"{alias}.txt", "".join(f"{name}\n" for name in (*names.values(), *isolated_names.values()))
        ),
    )
    try:
        h.inject_dnsbl_lists(vm, [(spec, "Deny")])
        _set_export(vm, True)
        _save_client_privacy(vm, gui, False)
        _apply(vm)
        print(f"ENDPOINT_MATRIX_APPLY {_capture(vm)!r}", flush=True)
        wanted: dict[tuple[str, str], float] = {}
        exact: dict[tuple[str, str, str], float] = {}
        with _client_v6(gw.client):
            for (address, transport), name in names.items():
                answer, raw = _ask(gw.client, transport, name, server=address)
                assert h.is_vip(answer), raw
                label = LOG_TRANSPORT[transport]
                wanted["A", label] = wanted.get(("A", label), 0) + 1
                key = (address, label, LAN_DESCRIPTION)
                exact[key] = exact.get(key, 0) + 1
            try:
                _publish_listener_owner_table(vm, dict.fromkeys(isolated_names, unicode_owner))
                for address, name in isolated_names.items():
                    answer, raw = _ask(gw.client, "udp", name, server=address)
                    assert h.is_vip(answer), raw
                    wanted["A", "UDP"] += 1
                    exact[address, "UDP", unicode_owner] = 1
            finally:
                _publish_listener_owner_table(vm, None)
        families = _wait_blocks(vm, {group: wanted})
        rows = [(labels, value) for labels, value in _samples(families, _BLOCKED) if labels.get("group") == group]
        assert all("client_ip" not in labels for labels, _ in rows), rows
        assert sum(value for _, value in rows) == 14, rows
        assert [value for labels, value in rows if labels == {"group": group}] == [0], rows
        attributed = [(labels, value) for labels, value in rows if labels != {"group": group}]
        expected_rows = [
            (
                {
                    "group": group,
                    "origin": "custom",
                    "qtype": "A",
                    "transport": transport,
                    "listener_ip": address,
                    "listener_interface": interface,
                },
                value,
            )
            for (address, transport, interface), value in exact.items()
        ]
        assert sorted((tuple(sorted(labels.items())), value) for labels, value in attributed) == sorted(
            (tuple(sorted(labels.items())), value) for labels, value in expected_rows
        ), rows
        public_labelsets = [tuple(sorted(labels.items())) for labels, _ in rows]
        assert len(public_labelsets) == len(set(public_labelsets)), rows
        for address, name in isolated_names.items():
            assert any(
                labels
                == {
                    "group": group,
                    "origin": "custom",
                    "qtype": "A",
                    "transport": "UDP",
                    "listener_ip": address,
                    "listener_interface": unicode_owner,
                }
                and value == 1
                for labels, value in rows
            ), rows
            _wait_dnsbl_row(vm, name)
            [row] = _dnsbl_rows(vm, name)
            assert len(row) == 14 and row[11:14] == ["UDP", address, unicode_owner], row
    finally:
        try:
            _save_client_privacy(vm, gui, prior_client[1] == "on")
        finally:
            try:
                _restore_endpoint_metric_config(vm, state_path)
            finally:
                _apply(vm)
