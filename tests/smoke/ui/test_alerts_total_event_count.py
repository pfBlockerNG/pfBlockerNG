"""Tier-A ``ui_render`` coverage for the Alerts stats page's "Total event(s)"
count (issue #1261: ``$alert_log_total_count`` moves from ``exec("grep -c ^
... 2>&1")`` to ``pfb_count_lines()``).

``pfblockerng_alerts.php?view=dnsbl_stat`` renders ``Total event(s): [ N ]``
from ``$alert_stats['count'][$alert_view]`` (pfblockerng_alerts.php:4860),
fed by the exec()-replaced line at :1829/1831. This module seeds ``dnsbl.log``
with an EXACT, controlled line count (never appended to an unknown baseline,
unlike ``test_alerts_stat_render.py``'s fixture) and asserts the rendered
``[ N ]`` matches it precisely -- not merely that the page renders 200
(CLAUDE.md test mandate #4).
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
ALERTS_DNSBL_STAT_PAGE = "/pfblockerng/pfblockerng_alerts.php?view=dnsbl_stat"

# Fixed, clearly-synthetic date (never the wall clock) so these rows are
# unambiguous in diagnostics and can't collide with any real entry.
_DAY = "2030-02-20"
_ROW = f"DNSBL-python,{_DAY} 10:00:00,ic1261-a.com,203.0.113.30,Python,DNSBL,IC1261Group,Match,IC1261Feed,+,A\n"


@pytest.fixture
def _dnsbl_log_backup(smoke_vm: SmokeVM) -> Iterator[SmokeVM]:
    """Move ``dnsbl.log`` aside so a test can write an EXACT byte content, then restore it.

    Self-encapsulated (CLAUDE.md): no ``ui_e2e``/``ui_browser`` marker, so the shared
    isolation fixture does not run for this module -- teardown restores the exact
    pre-test file (or its absence) and FAILS LOUDLY if that didn't take.
    """
    vm = smoke_vm
    had_file = vm.ssh("test", "-f", DNSBL_LOG, timeout=15).returncode == 0
    backup = f"{DNSBL_LOG}.bak-1261"
    if had_file:
        mv = vm.ssh("mv", DNSBL_LOG, backup, timeout=15)
        assert mv.returncode == 0, f"failed to back up {DNSBL_LOG}: {mv.stderr!r}"

    yield vm

    vm.ssh("rm", "-f", DNSBL_LOG, timeout=15)
    if had_file:
        restore = vm.ssh("mv", backup, DNSBL_LOG, timeout=15)
        assert restore.returncode == 0, f"failed to restore {DNSBL_LOG}: {restore.stderr!r}"
    still_backed_up = vm.ssh("test", "-f", backup, timeout=15).returncode == 0
    assert not still_backed_up, f"{DNSBL_LOG} restore did not take -- backup {backup} still present"


def _write_log(vm: SmokeVM, content: str) -> None:
    log_dir = DNSBL_LOG.rsplit("/", 1)[0]
    ensure = vm.ssh(f"mkdir -p {log_dir}", timeout=15)
    assert ensure.returncode == 0, f"failed to ensure {log_dir}: {ensure.stderr!r}"
    write = subprocess.run(
        vm.ssh_argv("tee", DNSBL_LOG),
        input=content,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert write.returncode == 0, f"failed to write {DNSBL_LOG}: stderr={write.stderr!r}"


def test_alerts_total_event_count_matches_exact_seeded_line_count(webui: WebUI, _dnsbl_log_backup: SmokeVM) -> None:
    """The displayed "Total event(s): [ N ]" is the EXACT line count, including a dangling final line.

    Scenario: three newline-terminated rows.
      Given dnsbl.log holds exactly 3 complete rows,
      When  GET the DNSBL Block Stats view,
      Then  the render oracle passes AND "[ 3 ]" is the rendered total.

    Scenario: a dangling (unterminated) final row -- the #1257/#1261 line the
    old `wc -l`-shaped bugs and the new pfb_count_lines() must agree on.
      Given a 4th row appended WITHOUT a trailing newline,
      When  GET the same view again,
      Then  "[ 4 ]" renders -- the dangling row IS counted (grep -c ^ semantics).
    """
    vm = _dnsbl_log_backup
    guard = PhpErrorLogGuard(vm)
    guard.snapshot()

    # Scenario: three newline-terminated rows.
    _write_log(vm, _ROW * 3)
    resp = webui.get(ALERTS_DNSBL_STAT_PAGE)
    result = evaluate_render(ALERTS_DNSBL_STAT_PAGE, resp.status_code, resp.text, ("DNSBL Block Stats",))
    assert result.ok, f"Tier-A render oracle failed for the DNSBL stats page: {result.detail}"
    assert "[ 3 ]" in resp.text, (
        f'expected "Total event(s): [ 3 ]" for 3 seeded rows, not found in body (status={resp.status_code})'
    )

    # Scenario: + one dangling (unterminated) final row -> must still be counted.
    _write_log(vm, _ROW * 3 + _ROW.rstrip("\n"))
    resp = webui.get(ALERTS_DNSBL_STAT_PAGE)
    result = evaluate_render(ALERTS_DNSBL_STAT_PAGE, resp.status_code, resp.text, ("DNSBL Block Stats",))
    assert result.ok, f"Tier-A render oracle failed for the DNSBL stats page: {result.detail}"
    assert "[ 4 ]" in resp.text, (
        'expected "Total event(s): [ 4 ]" (3 terminated + 1 dangling row) -- '
        f"a dangling final line must still be counted, not found in body (status={resp.status_code})"
    )

    guard.assert_no_growth()


def test_alerts_total_event_count_is_zero_when_log_absent(webui: WebUI, _dnsbl_log_backup: SmokeVM) -> None:
    """A missing dnsbl.log renders "Total event(s): [ 0 ]", never a PHP warning or a wrong number.

    Given dnsbl.log does not exist (the fixture removed it),
    When  GET the DNSBL Block Stats view,
    Then  the render oracle passes (no PHP diagnostic in the body, no new
          php_error.log line) AND the total renders "[ 0 ]".
    """
    vm = _dnsbl_log_backup
    exists = vm.ssh("test", "-f", DNSBL_LOG, timeout=15).returncode == 0
    assert not exists, f"test setup bug: {DNSBL_LOG} unexpectedly exists before the missing-file scenario"

    guard = PhpErrorLogGuard(vm)
    guard.snapshot()

    resp = webui.get(ALERTS_DNSBL_STAT_PAGE)
    result = evaluate_render(ALERTS_DNSBL_STAT_PAGE, resp.status_code, resp.text, ("DNSBL Block Stats",))
    assert result.ok, f"Tier-A render oracle failed for the DNSBL stats page: {result.detail}"
    assert "[ 0 ]" in resp.text, (
        f'expected "Total event(s): [ 0 ]" for a missing log, not found in body (status={resp.status_code})'
    )

    guard.assert_no_growth()
