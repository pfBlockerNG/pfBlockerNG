"""The package installs no pfBlockerNG crontab entry and retires the ones an older package left (#3996).

Core runs every schedule, so root's crontab, /etc/crontab and config.xml ``cron/item`` must hold no entry
naming ``pfblockerng.php`` or ``pfb_core_`` after a fresh install, an upgrade from a package that had
entries, a sync pass with the metrics export on, and (in ``ui/test_no_cron_entry_widget.py``) a widget save.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest

from . import helpers as h
from .conftest import SmokeVM
from .test_core_scheduled_maintenance import _force_install

_PHP_CLI = "/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php"
# The exact commands the previous package installed (minute, hour, weekday): the tick, the metrics export
# and the two counter clearings. The retirement needles end in a space, so these must be historical verbatim.
LEGACY_JOBS = (
    (f"{_PHP_CLI} cron-tick >> /var/log/pfblockerng/pfblockerng.log 2>&1", "*/15", "*", "*"),
    (f"/usr/bin/timeout -s TERM -k 5 50 {_PHP_CLI} metrics >> /dev/null 2>&1", "*", "*", "*"),
    (f"{_PHP_CLI} clearip >/dev/null 2>&1", "0", "0", "*"),
    (f"{_PHP_CLI} cleardnsbl >/dev/null 2>&1", "0", "0", "7"),
)


@pytest.fixture(scope="module")
def installed_vm(smoke_vm: SmokeVM) -> Iterator[SmokeVM]:
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    try:
        yield smoke_vm
    finally:
        h.collect_host_diagnostics(smoke_vm)


def _seed_legacy_jobs(vm: SmokeVM) -> None:
    calls = "".join(
        f"install_cron_job({h._php_str(cmd)}, TRUE, {h._php_str(minute)}, {h._php_str(hour)}, '*', '*', "
        f"{h._php_str(wday)}, 'root');"
        for cmd, minute, hour, wday in LEGACY_JOBS
    )
    result = h.php_eval(vm, f"require_once('services.inc');{calls}echo 'OK';")
    assert result.returncode == 0 and "OK" in result.stdout, f"seeding the legacy cron jobs failed: {result}"


@pytest.mark.smoke
@pytest.mark.timeout(600)
def test_fresh_install_enabled_apply_and_metrics_sync_leave_no_cron_entry(installed_vm: SmokeVM) -> None:
    vm = installed_vm
    h.assert_no_pfb_cron_entry(vm, "fresh install")
    h.set_package_enabled(vm, True)
    h.reload(vm, "update", wait_unbound=False)
    h.assert_no_pfb_cron_entry(vm, "enabled apply")
    h.php_eval(
        vm,
        "require_once('/usr/local/pkg/pfblockerng/pfblockerng_extra.inc');"
        "PfbConfig::writeSystem('gen/pfb_metrics_export', PfbToggle::On);"
        "write_config('pfBlockerNG smoke: metrics export on');echo 'OK';",
    )
    h.reload(vm, "update", wait_unbound=False)
    h.assert_no_pfb_cron_entry(vm, "sync pass with the metrics export on")


@pytest.mark.smoke
@pytest.mark.timeout(900)
def test_upgrade_retires_the_entries_the_previous_package_installed(installed_vm: SmokeVM, prev_pkg: Path) -> None:
    vm = installed_vm
    _force_install(vm, prev_pkg)
    _seed_legacy_jobs(vm)
    seeded = h.pfb_cron_entries(vm)
    assert len(seeded) >= len(LEGACY_JOBS), f"precondition: the legacy jobs were not seeded: {seeded}"

    _force_install(vm, Path(os.environ["SMOKE_PKG"]))

    h.assert_no_pfb_cron_entry(vm, "upgrade from a package with entries")
    h.reload(vm, "update", wait_unbound=False)
    h.assert_no_pfb_cron_entry(vm, "sync pass after the upgrade")
