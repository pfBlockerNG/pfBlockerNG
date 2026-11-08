"""Rendered comma-domain actions and malformed CSV totals stay intact."""

from __future__ import annotations

import csv
import html
import io
import re
import subprocess
from collections.abc import Iterator
from contextlib import contextmanager
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .render_oracle import evaluate_render
from .test_alerts_render_verify import _backup_seeded_files, _restore_seeded_files
from .test_browser_stats import _open

if TYPE_CHECKING:
    from playwright.sync_api import Page

    from .webui import WebUI


@contextmanager
def _stats_log(vm: helpers.SmokeVM, log: str, preference: str, contents: str) -> Iterator[None]:
    path = f"/var/log/pfblockerng/{log}"
    key = f"installedpackages/pfblockerngglobal/{preference}"
    prior = helpers.config_get_state(vm, key)
    backups = _backup_seeded_files(vm, (path, "/usr/local/www/pfblockerng/chart_stats.csv"))
    try:
        helpers.config_set(vm, key, "")
        seeded = subprocess.run(
            vm.ssh_argv("tee", path), input=contents, text=True, capture_output=True, timeout=30, check=False
        )
        assert seeded.returncode == 0, seeded.stderr
        yield
    finally:
        try:
            helpers.config_restore_state(vm, key, prior)
        finally:
            errors = _restore_seeded_files(vm, backups)
            assert not errors, errors


def _csv(row: list[str]) -> str:
    stream = io.StringIO()
    csv.writer(stream, lineterminator="\n").writerow(row)
    return stream.getvalue()


@pytest.mark.ui_browser
def test_dns_stats_comma_domain_cells_and_actions(browser_page: Page, webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    domain = "a,b.test"
    row = ["DNSBL", "2030-01-15 09:00:00", domain, "192.0.2.1", "Python", "TLD", "Group", domain, "Feed", "+", "A"]
    with _stats_log(smoke_vm, "dnsbl.log", "pfbdnsblstat", _csv(row)):
        _open(browser_page, webui, "/pfblockerng/pfblockerng_alerts.php?view=dnsbl_stat")
        for category in ("dnsbldomain", "dnsblevald"):
            cells = browser_page.locator(f"#Alert_Stats_{category} tbody tr").first.locator("td")
            assert cells.last.inner_text() == domain
            assert cells.nth(2).inner_text() == "TLD"
            assert cells.first.locator("button").get_attribute("value") == domain
            assert cells.first.locator("a").get_attribute("href") == (
                "/pfblockerng/pfblockerng_threats.php?domain=a%2Cb.test"
            )


@pytest.mark.ui_browser
def test_reply_stats_comma_domain_source_filter_round_trip(
    browser_page: Page, webui: WebUI, smoke_vm: helpers.SmokeVM
) -> None:
    domain = "a,b.test"
    source = "192.0.2.1"
    row = ["DNS-reply", "2030-01-15 09:00:00", "cache", "A", "A", "300", domain, source, "192.0.2.53", "US"]
    with _stats_log(smoke_vm, "dns_reply.log", "pfbdnsblreplystat", _csv(row)):
        _open(browser_page, webui, "/pfblockerng/pfblockerng_alerts.php?view=dnsbl_reply_stat")
        button = browser_page.locator("#Alert_Stats_replysrcipd tbody button").first
        assert button.get_attribute("value") == f"{domain},{source}"
        with browser_page.expect_navigation(wait_until="domcontentloaded"):
            button.click()
        assert browser_page.locator('[name="filterlogentries_replydomain"]').input_value() == domain
        assert browser_page.locator('[name="filterlogentries_replysrcip"]').input_value() == source


@pytest.mark.ui_render
@pytest.mark.parametrize("lines", [1, 2])
def test_dns_stats_unterminated_csv_total(webui: WebUI, smoke_vm: helpers.SmokeVM, lines: int) -> None:
    contents = 'DNS-reply,2030-01-15 09:00:00,"unterminated' + "\n" * lines
    with _stats_log(smoke_vm, "dns_reply.log", "pfbdnsblreplystat", contents):
        path = "/pfblockerng/pfblockerng_alerts.php?view=dnsbl_reply_stat"
        response = webui.get(path)
        result = evaluate_render(path, response.status_code, response.text, ("DNS Reply Stats",))
        assert result.ok, result.detail
        total = re.search(r"Total event\(s\):\s*\[\s*(\d+)\s*\]", html.unescape(response.text))
        assert total is not None, "Stats total heading missing"
        assert int(total.group(1)) == lines, f"Expected {lines} physical lines, got {total.group(1)}"
