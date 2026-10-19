"""Metrics export (#3522) — live-VM smoke of the node_exporter textfile publisher.

The smoke image installs packages offline, so ``pfSense-pkg-node_exporter`` is absent and
cannot be installed here. The tests therefore:

* enable the option through the config gateway (the General page refuses ``on`` without the
  package; that refusal is POSTed and checked by the ui-render test
  ``test_general_metrics_export_save_is_refused_without_node_exporter``),
* create ``/var/tmp/node_exporter`` themselves as the stand-in for node_exporter's textfile
  directory, and remove it again,
* validate the published file runner-side with the Prometheus Python client's text parser
  (it replaces the ``node_textfile_scrape_error`` check node_exporter would give).

Tests:
    test_metrics_toggle_installs_cron_and_publishes   — cron line + a parseable, complete file
    test_metrics_pass_status_after_update_pass        — a real update pass records start/end
    test_metrics_pass_status_ignores_a_settings_save_pass — a settings-save pass leaves the pass times alone
    test_metrics_master_disable_removes_cron_and_file — master switch off tears the export down
    test_metrics_toggle_off_removes_cron_and_file     — option off tears the export down
    test_metrics_verb_publishes_nothing_while_disabled — the verb leaves no file while the option is off
    test_metrics_verb_ignores_a_stale_sentinel_while_the_option_is_off — a leftover sentinel cannot outvote a disable
    test_metrics_dir_missing_logs_once                — a missing textfile dir logs once, exits 0

DESELECTED from the default ``python -m pytest`` (smoke-only). Run via::

    scripts/local-smoke.sh --marker smoke --filter metrics
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from typing import TYPE_CHECKING

import pytest

from . import helpers as h
from .conftest import SmokeVM

if TYPE_CHECKING:
    from prometheus_client.metrics_core import Metric

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


@pytest.fixture(scope="module")
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
    """Stand in for node_exporter's textfile directory; leave the export off and the directory gone."""
    made = deployed_vm.ssh("/usr/bin/install", "-d", "-m", "0755", _TEXTFILE_DIR)
    assert made.returncode == 0, f"could not create {_TEXTFILE_DIR}: {made.stderr!r}"
    try:
        yield
    finally:
        try:
            _set_export(deployed_vm, False)
            h.reload(deployed_vm, "update", wait_unbound=False)
        finally:
            deployed_vm.ssh("/bin/rm", "-rf", _TEXTFILE_DIR)


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
