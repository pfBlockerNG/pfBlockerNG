"""One shared Stats time range (#3773): the picker, the window and the fallback on real appliance data.

Rows are stamped with the appliance clock (the window is computed there). Logs and settings are backed
up and restored; nothing is stubbed.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlsplit

import pytest

from .. import helpers
from .conftest import wait_for_document_ready
from .test_dns_stats_review import _stats_log

if TYPE_CHECKING:
    from playwright.sync_api import Expect, Page

    from .webui import WebUI

ALERTS = "/pfblockerng/pfblockerng_alerts.php"
SAVED_RANGE = "installedpackages/pfblockerngglobal/pfbchartcnt"
LEGACY_STAMP = "Feb 15 09:00:00"  # pre-ISO log format: never inside a window, always inside "All time"
VIEWS = (
    # view, log, hidden-stat preference, Top table panel, timeline panel
    ("dnsbl_reply_stat", "dns_reply.log", "pfbdnsblreplystat", "replydomain", "replychart"),
    ("ip_block_stat", "ip_block.log", "pfbblockstat", "ipfeed", "ipchart"),
)


def _expect() -> Expect:
    return pytest.importorskip("playwright.sync_api").expect


def _vm_stamps(vm: helpers.SmokeVM) -> tuple[str, str]:
    """``now - 2 h`` and ``now - 30 h`` rendered by the appliance's own PHP clock."""
    both = helpers._php_read_scalar(
        vm, "", "date('Y-m-d H:i:s', time() - 2 * 3600) . ',' . date('Y-m-d H:i:s', time() - 30 * 3600)"
    )
    recent, older = both.split(",")
    return recent, older


def _row(view: str, stamp: str, token: str) -> str:
    """One log line whose Top-table value (reply domain / IP feed) is ``token``."""
    if view == "dnsbl_reply_stat":
        return f"DNS-reply,{stamp},cache,A,A,300,{token},192.0.2.1,192.0.2.53,US\n"
    return (
        f"{stamp},100,em0,WAN,block,4,6,TCP,192.0.2.1,198.51.100.1,54321,80,in,US,pfB_Range_v4,"
        f"192.0.2.1,{token},Unknown,Unknown,64500,asn.range.com,Range ASN,+\n"
    )


@contextmanager
def _saved_default(vm: helpers.SmokeVM, value: str) -> Iterator[None]:
    prior = helpers.config_get_state(vm, SAVED_RANGE)
    try:
        helpers.config_set(vm, SAVED_RANGE, value)
        yield
    finally:
        helpers.config_restore_state(vm, SAVED_RANGE, prior)


def _stats_tempfiles(vm: helpers.SmokeVM) -> list[str]:
    result = vm.ssh("find", "/tmp", "/var/tmp", "-maxdepth", "1", "-name", "pfb-stats-*")
    return sorted(result.stdout.split())


def _settle(page: Page, view: str) -> None:
    wait_for_document_ready(page)
    if view == "dnsbl_reply_stat":  # DNS panels arrive over fetch; IP panels are server-rendered
        _expect()(page.locator("#Alert_Stats_Loading")).to_have_attribute("aria-busy", "false", timeout=60_000)
        _expect()(page.locator("#Alert_Stats_Retry")).not_to_be_visible()
    assert page.locator("#usernamefld").count() == 0


def _open(page: Page, webui: WebUI, view: str, query: str = "") -> None:
    page.goto(webui.url(f"{ALERTS}?view={view}{query}"), wait_until="domcontentloaded", timeout=90_000)
    _settle(page, view)


def _reveal(page: Page, stat: str) -> None:
    body = page.locator(f"#Alert_Stats_{stat}_panel-body")
    page.locator(f"#Alert_Stats_{stat}").scroll_into_view_if_needed()
    if not body.is_visible():
        page.locator(f"#Alert_Stats_A_{stat}").click()
    _expect()(body).to_be_visible()


def _top(page: Page, panel: str) -> dict[str, int]:
    """The Top table as ``{value: count}``."""
    _reveal(page, panel)
    _expect()(page.locator(f"#Alert_Stats_{panel} tbody")).to_be_attached()
    rows = page.locator(f"#Alert_Stats_{panel} tbody tr").evaluate_all(
        "rows => rows.map(r => [r.cells[r.cells.length - 1].innerText.trim(), r.cells[1].innerText.trim()])"
    )
    return {value: int(count) for value, count in rows}


def _pick(page: Page, *, value: str | None = None, label: str | None = None) -> dict[str, list[str]]:
    """Choose an option in the shared picker; returns the query of the page it navigates to."""
    with page.expect_navigation(wait_until="domcontentloaded") as navigation:
        page.locator("#Alert_Stats_Range").select_option(value=value, label=label)
    response = navigation.value
    assert response is not None
    assert response.request.method == "GET", "the picker must navigate, not submit the Stats POST form"
    return parse_qs(urlsplit(page.url).query)


def _shown_window(page: Page) -> tuple[datetime, datetime]:
    """The from/to the page says it is showing: two ``<time>`` elements in ``#Alert_Stats_Window``."""
    times = page.locator("#Alert_Stats_Window time")
    _expect()(times).to_have_count(2)
    start, end = (datetime.fromisoformat(stamp) for stamp in times.evaluate_all("t => t.map(e => e.dateTime)"))
    text = page.locator("#Alert_Stats_Window").inner_text()
    for stamp in (start, end):
        assert stamp.strftime("%Y-%m-%d %H:%M") in text, f"{stamp} not visible in {text!r}"
    return start, end


def _assert_window(
    page: Page,
    table: str,
    chart: str,
    *,
    value: str,
    total: int,
    top: dict[str, int],
    title: str,
    now: datetime,
    first: datetime,
) -> None:
    expect = _expect()
    expect(page.locator("#Alert_Stats_Range")).to_have_value(value)
    expect(page.locator("#Alert_Stats_Total")).to_have_text(str(total))
    # The shown window ends at the request time; it starts N hours earlier, or at the first dated record for All time.
    start, end = _shown_window(page)
    assert now <= end <= now + timedelta(minutes=15), (end, now)
    assert start == (first if value == "max" else end - timedelta(hours=int(value))), (start, end)
    assert _top(page, table) == top
    _reveal(page, chart)
    expect(page.locator("#chart")).to_be_attached()
    expect(page.locator(f"#Alert_Stats_{chart} .panel-title")).to_contain_text(title)
    assert page.locator("#chart .dropdown-toggle").count() == 0, "the per-timeline Date Range dropdown is gone"


@pytest.mark.ui_browser
@pytest.mark.parametrize(("view", "log", "preference", "table", "chart"), VIEWS)
def test_stats_time_range_is_one_shared_window_for_every_panel(
    browser_page: Page,
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    view: str,
    log: str,
    preference: str,
    table: str,
    chart: str,
) -> None:
    page = browser_page
    recent_stamp, older_stamp = _vm_stamps(smoke_vm)
    recent, older, legacy = (helpers.unique_domain(label) for label in ("rangerecent", "rangeolder", "rangelegacy"))
    contents = (
        _row(view, LEGACY_STAMP, legacy) + 3 * _row(view, older_stamp, older) + 2 * _row(view, recent_stamp, recent)
    )
    leftovers = _stats_tempfiles(smoke_vm)
    # Lower bound for the request time, and the first dated record "All time" starts at.
    shown = {
        "now": datetime.fromisoformat(recent_stamp) + timedelta(hours=2),
        "first": datetime.fromisoformat(older_stamp),
    }
    with _stats_log(smoke_vm, log, preference, contents), _saved_default(smoke_vm, "24"):
        _open(page, webui, view)

        # One labelled native control in its own pane of the page-level Statistics panel (owner, 2026-11-09),
        # outside any nested form, never a POST.
        select = page.locator("#Alert_Stats_Range")
        _expect()(page.get_by_label("Time range", exact=True)).to_have_attribute("id", "Alert_Stats_Range")
        assert select.get_attribute("name") == "range"
        assert select.evaluate("el => el.closest('form').id") == "iform_stats"
        assert page.locator("#iform_stats form").count() == 0
        top = page.locator("#iform_stats > .panel:has(#Alert_Stats_Total)").first
        _expect()(top.locator(".panel-body #Alert_Stats_Range")).to_have_count(1)
        _expect()(top.locator(".panel-heading #Alert_Stats_Range")).to_have_count(0)
        title = {"dnsbl_reply_stat": "DNS Reply Statistics", "ip_block_stat": "IP Block Statistics"}[view]
        assert top.locator(".panel-title").inner_text().split("Total event", 1)[0].strip() == title
        assert {"24", "48", "168", "max"} <= set(select.locator("option").evaluate_all("o => o.map(e => e.value)"))
        _expect()(select.locator('option[value="max"]')).to_have_text("All time")

        # Saved default 24: only the 2 h rows; the legacy row and the 30 h rows are outside the window.
        _assert_window(page, table, chart, value="24", total=2, top={recent: 2}, title="(Last 24 hours)", **shown)

        query = _pick(page, value="48")
        assert query["range"] == ["48"]
        assert query["view"] == [view]
        _settle(page, view)
        _assert_window(
            page, table, chart, value="48", total=5, top={recent: 2, older: 3}, title="(Last 48 hours)", **shown
        )

        query = _pick(page, label="All time")
        assert query["range"] == ["max"]
        assert query["view"] == [view]
        _settle(page, view)
        _assert_window(
            page,
            table,
            chart,
            value="max",
            total=6,
            top={recent: 2, older: 3, legacy: 1},
            title="(All time)",
            **shown,
        )

        # An unknown range is not an error and not an injection path: it falls back to the saved default.
        _open(page, webui, view, "&range=evil")
        _assert_window(page, table, chart, value="24", total=2, top={recent: 2}, title="(Last 24 hours)", **shown)

        # Picking a range never rewrites the saved default.
        assert helpers.config_get_state(smoke_vm, SAVED_RANGE) == (True, "24")
    assert _stats_tempfiles(smoke_vm) == leftovers, "windowed Stats left a temp file behind"


@pytest.mark.ui_render
def test_stats_data_endpoint_validates_the_same_range(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    recent_stamp, older_stamp = _vm_stamps(smoke_vm)
    contents = (
        _row("dnsbl_reply_stat", LEGACY_STAMP, helpers.unique_domain("rangelegacy"))
        + 3 * _row("dnsbl_reply_stat", older_stamp, helpers.unique_domain("rangeolder"))
        + 2 * _row("dnsbl_reply_stat", recent_stamp, helpers.unique_domain("rangerecent"))
    )

    def bucket(stamp: str, count: int) -> dict[str, object]:
        return {"edate": f"{stamp[:10]} ({stamp[11:13]})", "ecount": count}

    def data(query: str) -> dict[str, object]:
        response = webui.get(f"{ALERTS}?view=dnsbl_reply_stat&stats_data=1{query}")
        assert response.status_code == 200
        assert "application/json" in response.headers.get("content-type", "")
        return {key: value for key, value in response.json().items() if key in ("total", "timeline")}

    recent_only = {"total": 2, "timeline": [bucket(recent_stamp, 2)]}
    both = {"total": 5, "timeline": [bucket(older_stamp, 3), bucket(recent_stamp, 2)]}
    everything = {"total": 6, "timeline": both["timeline"]}  # the legacy row has no ISO hour to chart
    with _stats_log(smoke_vm, "dns_reply.log", "pfbdnsblreplystat", contents), _saved_default(smoke_vm, "24"):
        assert data("") == recent_only
        assert data("&range=24") == recent_only
        assert data("&range=48") == both
        assert data("&range=max") == everything
        for invalid in ("evil", "1%3Bid", "-1", ""):
            assert data(f"&range={invalid}") == recent_only, invalid
