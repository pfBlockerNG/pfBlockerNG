"""Tier-A ``ui_render`` coverage for the Reports/Alerts day-bucket + hourly-chart
fix over real ISO-8601 ``dnsbl.log`` content (ADR-60 Phase 5).

``pfblockerng_alerts.php?view=dnsbl_stat`` is already GET-swept generically by
``test_render_smoke.py``'s ``alerts_dnsbl_stat`` table entry, but that sweep
never seeds any log content, so the day-bucket/hourly-chart code this phase
touches (the ``cut``/``awk`` pipelines gated behind ``file_exists($alert_log)``)
never actually runs there. This module seeds real ISO-format rows and asserts
the ACTUAL corrected grouping, not merely "the page didn't crash": before this
phase's fix, every row bucketed to its own distinct second and the hourly chart
showed an empty hour field -- both regressions this test would catch.

The DNSBL sinkhole block page (``www/index.php``) is a *different* consumer
this phase also fixes, but it is NOT reachable from this harness: it is served
by the DNSBL VIP sinkhole lighttpd on a separate port, never the authenticated
webConfigurator session (see ``test_render_smoke.py``'s
``EXCLUDED_FROM_TIER_A`` "dnsbl_vip_sinkhole_pages" entry, verified pre-existing
and unrelated to this phase). Its correlation-grep fix is proven instead by
``tests/php/LogFormatConsumersTest.php``'s red/green shell-pipeline execution
tests; live confirmation against a real block is this ADR's own Phase 9
live-VM smoke item (and ADR-14's separate Tier-B VIP-sinkhole leg) -- not a gap
in this phase.
"""

from __future__ import annotations

import subprocess
from typing import TYPE_CHECKING

import pytest

from .render_oracle import PhpErrorLogGuard, evaluate_render

if TYPE_CHECKING:
    from collections.abc import Iterator

    from ..conftest import SmokeVM
    from .webui import WebUI

pytestmark = pytest.mark.ui_render

DNSBL_LOG = "/var/log/pfblockerng/dnsbl.log"
CHART_STATS_CSV = "/usr/local/www/pfblockerng/chart_stats.csv"
ALERTS_DNSBL_STAT_PAGE = "/pfblockerng/pfblockerng_alerts.php?view=dnsbl_stat"

# Fixed, clearly-synthetic dates (never the wall clock, never helpers.unique_domain()
# -- this is pure log-content grouping, no DNS resolution happens) so this fixture's
# own rows are unambiguous in diagnostics and can't collide with any real entry.
DAY_1 = "2030-01-15"
DAY_2 = "2030-01-16"

_FIXTURE_LINES = (
    f"DNSBL-python,{DAY_1} 09:00:05,rv60p5-a.com,203.0.113.21,Python,DNSBL,RV60P5Group,Match,RV60P5Feed,+,A\n"
    f"DNSBL-python,{DAY_1} 09:30:10,rv60p5-b.com,203.0.113.22,Python,DNSBL,RV60P5Group,Match,RV60P5Feed,+,A\n"
    f"DNSBL-python,{DAY_1} 14:15:20,rv60p5-c.com,203.0.113.23,Python,DNSBL,RV60P5Group,Match,RV60P5Feed,+,A\n"
    f"DNSBL-python,{DAY_2} 08:05:00,rv60p5-d.com,203.0.113.24,Python,DNSBL,RV60P5Group,Match,RV60P5Feed,+,A\n"
)


@pytest.fixture
def _seeded_dnsbl_log(smoke_vm: SmokeVM) -> Iterator[None]:
    """Append the 4 fixture rows to ``dnsbl.log``; restore the pre-test size after.

    Self-encapsulated (CLAUDE.md): this module carries no ``ui_e2e``/``ui_browser``
    marker, so the shared ``_ui_pfb_isolation`` config-restore fixture does not run
    for it -- teardown here truncates the log back to its exact pre-test byte size
    and FAILS LOUDLY if that didn't take, instead of leaking synthetic rows to a
    sibling test.
    """
    vm = smoke_vm
    log_dir = DNSBL_LOG.rsplit("/", 1)[0]
    ensure = vm.ssh(f"mkdir -p {log_dir} && touch {DNSBL_LOG}", timeout=15)
    assert ensure.returncode == 0, f"failed to ensure {DNSBL_LOG} exists: {ensure.stderr!r}"

    size_before = vm.ssh("stat", "-f", "%z", DNSBL_LOG, timeout=15)
    assert size_before.returncode == 0, f"failed to stat {DNSBL_LOG}: stderr={size_before.stderr!r}"
    original_size = size_before.stdout.strip()

    append = subprocess.run(
        vm.ssh_argv("tee", "-a", DNSBL_LOG),
        input=_FIXTURE_LINES,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert append.returncode == 0, f"failed to append fixture rows to {DNSBL_LOG}: stderr={append.stderr!r}"

    yield

    restore = vm.ssh(f"truncate -s {original_size} {DNSBL_LOG}", timeout=15)
    assert restore.returncode == 0, f"failed to restore {DNSBL_LOG} size: stderr={restore.stderr!r}"
    size_after = vm.ssh("stat", "-f", "%z", DNSBL_LOG, timeout=15)
    assert size_after.returncode == 0 and size_after.stdout.strip() == original_size, (
        f"{DNSBL_LOG} restore did not take (before={original_size!r}, after={size_after.stdout.strip()!r}) "
        "-- synthetic rows leaked to sibling tests"
    )


def test_alerts_dnsbl_stat_renders_iso_day_bucket_and_hourly_chart(
    smoke_vm: SmokeVM, webui: WebUI, _seeded_dnsbl_log: None
) -> None:
    """Real ISO-8601 dnsbl.log content buckets by day and charts by hour correctly.

    Scenario:
      Given 3 DAY_1 rows (2 in hour 09, 1 in hour 14) and 1 DAY_2 row.
      When  GET the DNSBL Block Stats view.
      Then  the Tier-A render oracle passes (200, no PHP diagnostic, page marker)
            AND both day buckets render (not one bucket per distinct second)
            AND the hourly chart shows a real hour, never an empty "()" field.
    """
    guard = PhpErrorLogGuard(smoke_vm)
    guard.snapshot()

    resp = webui.get(ALERTS_DNSBL_STAT_PAGE)
    result = evaluate_render(ALERTS_DNSBL_STAT_PAGE, resp.status_code, resp.text, ("DNSBL Block Stats",))
    assert result.ok, f"Tier-A render oracle failed for the DNSBL stats page: {result.detail}"

    body = resp.text
    assert DAY_1 in body, f"day bucket {DAY_1!r} not rendered -- day-bucket grouping is broken"
    assert DAY_2 in body, f"day bucket {DAY_2!r} not rendered -- day-bucket grouping is broken"
    # The pre-fix bug ('cut -d \' \' -f1-2' on a 2-space-token ISO line) makes every
    # full "date time" string its own bucket -- assert that regression stayed dead.
    assert f"{DAY_1} 09:00:05" not in body, (
        "a full per-second timestamp rendered as its own row key -- the day-bucket field-selection regression is back"
    )

    chart = smoke_vm.ssh("cat", CHART_STATS_CSV, timeout=15)
    assert chart.returncode == 0, f"failed to read {CHART_STATS_CSV}: stderr={chart.stderr!r}"
    assert f"{DAY_1} (09)," in chart.stdout, (
        f"hourly chart label missing the correct hour for {DAY_1} 09:00 -- got: {chart.stdout!r}"
    )
    assert "()," not in chart.stdout, f"hourly chart shows an EMPTY hour field -- got: {chart.stdout!r}"

    guard.assert_no_growth()
