"""Shared Stats loading, private data, deferred panels and native filter behavior.

Success responses always come from the appliance. Routes only hold or abort the
real transport; no test supplies replacement Stats HTML or JSON.
"""

from __future__ import annotations

import csv
import io
import re
from datetime import datetime, timedelta
from typing import TYPE_CHECKING
from urllib.parse import parse_qs

import pytest

from .. import helpers
from .test_dns_stats_review import _stats_log

if TYPE_CHECKING:
    from playwright.sync_api import Expect, Page, Route

    from .webui import WebUI

ALERTS = "/pfblockerng/pfblockerng_alerts.php"
DATA_ROUTE = "**/pfblockerng_alerts.php?*stats_data=1*"
VIEWS = (
    ("dnsbl_stat", "dnsbl.log", "pfbdnsblstat", "dnsbl"),
    ("dnsbl_reply_stat", "dns_reply.log", "pfbdnsblreplystat", "reply"),
)


def _vm_hours(vm: helpers.SmokeVM, count: int) -> list[str]:
    """``count`` hourly stamps from the appliance clock, oldest first: ``now - 30 min - i h``.

    A ``count``-hour window then holds exactly these rows, with 30 min of slack at both edges.
    """
    if not count:
        return []
    stamp = "date('Y-m-d H:i:s', time() - 1800 - $i * 3600)"
    expr = f"implode('|', array_map(fn (int $i): string => {stamp}, range(0, {count - 1})))"
    return helpers._php_read_scalar(vm, "", expr).split("|")[::-1]


def _rows(prefix: str, domain: str, stamps: list[str] | None = None) -> str:
    stream = io.StringIO()
    writer = csv.writer(stream, lineterminator="\n")
    # Future-dated by default: inside every range, whatever the appliance clock says.
    for stamp in stamps or [
        (datetime(2031, 2, 15, 9) + timedelta(hours=index)).strftime("%Y-%m-%d %H:%M:%S") for index in range(3)
    ]:
        if prefix == "dnsbl":
            writer.writerow(["DNSBL", stamp, domain, "192.0.2.1", "Python", "TLD", "Group", domain, "Feed", "+", "A"])
        else:
            writer.writerow(["DNS-reply", stamp, "cache", "A", "A", "300", domain, "192.0.2.1", "192.0.2.53", "US"])
    return stream.getvalue()


def _expect() -> Expect:
    return pytest.importorskip("playwright.sync_api").expect


def _ready(page: Page) -> None:
    _expect()(page.locator("#Alert_Stats_Loading")).to_have_attribute("aria-busy", "false", timeout=60_000)
    _expect()(page.locator("#Alert_Stats_Retry")).not_to_be_visible()
    assert page.locator("#usernamefld").count() == 0


def _reveal(page: Page, stat: str) -> None:
    body = page.locator(f"#Alert_Stats_{stat}_panel-body")
    page.locator(f"#Alert_Stats_{stat}").scroll_into_view_if_needed()
    if not body.is_visible():
        page.locator(f"#Alert_Stats_A_{stat}").click()
    _expect()(body).to_be_visible()


@pytest.mark.ui_browser
@pytest.mark.parametrize(("view", "log", "preference", "prefix"), VIEWS)
def test_stats_progressive_shell_real_payload_and_lazy_panels(
    browser_page: Page,
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    view: str,
    log: str,
    preference: str,
    prefix: str,
) -> None:
    """An eager scan, early table construction or repeated fetch breaks this test."""
    page = browser_page
    held: list[Route] = []
    requests: list[str] = []
    domain = "a,b." + helpers.unique_domain()

    def hold(route: Route) -> None:
        requests.append(route.request.url)
        held.append(route)
        page.evaluate("() => { document.documentElement.dataset.statsRequestHeld = 'true'; }")

    page.route(DATA_ROUTE, hold)
    with _stats_log(smoke_vm, log, preference, _rows(prefix, domain)):
        page.set_viewport_size({"width": 1024, "height": 320})
        try:
            page.goto(webui.url(f"{ALERTS}?view={view}&range=24"), wait_until="domcontentloaded", timeout=90_000)
            # Baseline RED must be this missing loading contract, not a route timeout.
            _expect()(page.locator("#Alert_Stats_Loading")).to_have_attribute("aria-busy", "true")
            _expect()(page.locator("#Alert_Stats_Status")).to_have_attribute("role", "status")
            _expect()(page.locator('#iform_stats input[name="__csrf_magic"]')).to_have_value(re.compile(r".+"))
            assert page.locator("#iform_stats tbody, #iform_stats svg").count() == 0
            _expect()(page.locator("html")).to_have_attribute("data-stats-request-held", "true")
            assert len(held) == 1, "Initial shell did not initiate exactly one data request"
            assert held[0].request.method == "GET"
            assert parse_qs(held[0].request.url.split("?", 1)[1])["view"] == [view]
            with page.expect_response(lambda response: "stats_data=1" in response.url) as received:
                held.pop().continue_()
            response = received.value
            assert response.status == 200
            assert "application/json" in response.headers.get("content-type", "")
            assert "no-store" in response.headers.get("cache-control", "")
            payload = response.json()
            assert payload["total"] == 3
            assert payload["timeline"] == [
                {"edate": "2031-02-15 (09)", "ecount": 1},
                {"edate": "2031-02-15 (10)", "ecount": 1},
                {"edate": "2031-02-15 (11)", "ecount": 1},
            ]
            assert all(
                "<script" not in panel["html"].lower() and "<form" not in panel["html"].lower()
                for panel in payload["panels"]
            )
            _ready(page)
            # Last panel is causally offscreen in the deliberately short viewport.
            last = f"{prefix}date"
            assert page.locator(f"#Alert_Stats_{last} tbody").count() == 0
            _reveal(page, last)
            _expect()(page.locator(f"#Alert_Stats_{last} tbody")).to_contain_text("2031-02-15")
            _reveal(page, f"{prefix}domain")
            row = page.locator(f"#Alert_Stats_{prefix}domain tbody tr").first
            assert row.locator("td").last.inner_text() == domain
            assert row.locator("td").nth(1).inner_text().strip() == "3"
            assert row.locator("button").get_attribute("value") == domain
            if prefix == "dnsbl":
                assert row.locator("a").get_attribute("href") == (
                    "/pfblockerng/pfblockerng_threats.php?domain=" + domain.replace(",", "%2C")
                )
                assert row.locator("td").nth(2).inner_text() == "TLD"
            page.locator(f"#Alert_Stats_A_{prefix}domain").click()
            page.locator(f"#Alert_Stats_A_{prefix}domain").click()
            _reveal(page, f"{prefix}chart")
            assert len(requests) == 1, "Expanding panels fetched the log again"
            # The shared range reloads every panel: exactly one more data request, carrying the new range.
            with page.expect_navigation(wait_until="domcontentloaded"):
                page.locator("#Alert_Stats_Range").select_option("168")
            _expect()(page.locator("html")).to_have_attribute("data-stats-request-held", "true")
            assert len(held) == 1 and len(requests) == 2, "A range change must fetch the log exactly once"
            assert parse_qs(requests[1].split("?", 1)[1])["range"] == ["168"]
            held.pop().continue_()
            _ready(page)
            assert page.locator("#iform_stats form").count() == 0
            # Lazy action buttons must submit through the native outer CSRF form.
            if prefix == "reply":
                _reveal(page, "replysrcipd")
                button = page.locator("#Alert_Stats_replysrcipd tbody button").first
                assert button.get_attribute("value") == f"{domain},192.0.2.1"
            else:
                _reveal(page, "dnsbldomain")
                button = page.locator("#Alert_Stats_dnsbldomain tbody button").first
            with page.expect_request(lambda request: request.method == "POST") as posted:
                with page.expect_navigation(wait_until="domcontentloaded"):
                    button.click()
            fields = parse_qs(posted.value.post_data or "")
            assert fields["__csrf_magic"][0]
            assert fields[f"filterlogentries_submit_{'replysrcipd' if prefix == 'reply' else 'dnsbldomain'}"] == [
                f"{domain},192.0.2.1" if prefix == "reply" else domain
            ]
            field = page.locator(f'[name="filterlogentries_{prefix}domain"]')
            _expect()(field).to_have_value(domain)
            if prefix == "reply":
                _expect()(page.locator('[name="filterlogentries_replysrcip"]')).to_have_value("192.0.2.1")
            _expect()(field).to_have_css("background-color", "rgb(25, 118, 210)")
            field.fill("")
            _expect()(field).not_to_have_css("background-color", "rgb(25, 118, 210)")
            field.fill(domain)
            _expect()(field).to_have_css("background-color", "rgb(25, 118, 210)")
            assert field.get_attribute("autocomplete") == "off"
        finally:
            for route in held:
                route.abort()
            page.unroute(DATA_ROUTE, hold)


@pytest.mark.ui_browser
@pytest.mark.parametrize(("view", "log", "preference", "prefix"), VIEWS)
def test_stats_progressive_transport_error_retry_is_real(
    browser_page: Page,
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    view: str,
    log: str,
    preference: str,
    prefix: str,
) -> None:
    page = browser_page
    attempts: list[str] = []

    def abort_first(route: Route) -> None:
        attempts.append(route.request.method)
        if len(attempts) == 1:
            route.abort("failed")
        else:
            route.continue_()

    page.route(DATA_ROUTE, abort_first)
    with _stats_log(smoke_vm, log, preference, _rows(prefix, helpers.unique_domain())):
        try:
            page.goto(webui.url(f"{ALERTS}?view={view}"), wait_until="domcontentloaded", timeout=90_000)
            retry = page.locator("#Alert_Stats_Retry")
            _expect()(retry).to_be_visible()
            _expect()(retry).to_have_attribute("type", "button")
            assert page.locator("#Alert_Stats_Status").inner_text().strip()
            with page.expect_response(lambda response: "stats_data=1" in response.url) as received:
                retry.click()
            assert received.value.json()["total"] == 3
            _ready(page)
            assert attempts == ["GET", "GET"]
        finally:
            page.unroute(DATA_ROUTE, abort_first)


@pytest.mark.ui_browser
@pytest.mark.parametrize(("view", "log", "preference", "prefix"), VIEWS)
@pytest.mark.parametrize("width", [320, 768, 1024, 1440])
def test_stats_progressive_timeline_geometry_and_shared_ranges(
    browser_page: Page,
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    view: str,
    log: str,
    preference: str,
    prefix: str,
    width: int,
) -> None:
    page = browser_page
    requests: list[str] = []
    page.on("request", lambda request: requests.append(request.url) if "stats_data=1" in request.url else None)
    stamps = _vm_hours(smoke_vm, 30)
    with _stats_log(smoke_vm, log, preference, _rows(prefix, helpers.unique_domain(), stamps)):
        page.set_viewport_size({"width": width, "height": 768})
        # Start on a range the loop changes, so every pick is a real change and reloads the page.
        page.goto(webui.url(f"{ALERTS}?view={view}&range=8064"), wait_until="domcontentloaded", timeout=90_000)
        _ready(page)
        for count, bars in ((24, 24), (168, 30), (8064, 30), (24, 24)):
            with page.expect_navigation(wait_until="domcontentloaded"):
                page.locator("#Alert_Stats_Range").select_option(str(count))
            _ready(page)
            _reveal(page, prefix + "chart")
            _expect()(page.locator("#Alert_Stats_Range")).to_have_value(str(count))
            _expect()(page.locator("#chart .nv-bar")).to_have_count(bars)
            geometry = page.locator("#chart svg").evaluate("""svg => ({
                width: svg.getBoundingClientRect().width,
                bad: [...svg.querySelectorAll('rect')].some(r =>
                    !Number.isFinite(Number(r.getAttribute('width'))) || Number(r.getAttribute('width')) < 0)
            })""")
            assert geometry["width"] > 0 and not geometry["bad"], geometry
            oldest = stamps[-bars]
            page.locator("#chart .nv-bar").first.hover(force=True)
            _expect()(
                page.locator(".nvtooltip").filter(has_text=f"{oldest[:10]} ({oldest[11:13]})").last
            ).to_be_visible()
        assert len(requests) == 5, "Each load must fetch the log exactly once"


@pytest.mark.ui_render
@pytest.mark.parametrize(("view", "log", "preference", "prefix"), VIEWS)
def test_stats_progressive_empty_data_is_not_a_transport_error(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    view: str,
    log: str,
    preference: str,
    prefix: str,
) -> None:
    with _stats_log(smoke_vm, log, preference, ""):
        response = webui.get(f"{ALERTS}?view={view}&stats_data=1")
        assert "application/json" in response.headers.get("content-type", ""), "Stats data returned HTML"
        assert response.json()["total"] == 0
        assert response.json()["timeline"] == []


@pytest.mark.ui_browser
@pytest.mark.parametrize("view", ["ip_block_stat", "ip_permit_stat", "ip_match_stat", "../dns_reply.log", "invalid"])
def test_stats_progressive_data_rejects_non_dns_views(browser_page: Page, webui: WebUI, view: str) -> None:
    response = browser_page.context.request.get(webui.url(f"{ALERTS}?view={view}&stats_data=1"))
    assert response.status == 400
    assert "application/json" in response.headers.get("content-type", "")


@pytest.mark.ui_browser
def test_stats_progressive_data_rejects_mutating_method(browser_page: Page, webui: WebUI) -> None:
    response = browser_page.context.request.put(webui.url(f"{ALERTS}?view=dnsbl_stat&stats_data=1"))
    assert response.status == 405
    assert response.headers.get("allow") == "GET"


@pytest.mark.ui_browser
def test_stats_progressive_unauthenticated_data_never_exposes_panels(browser_page: Page, webui: WebUI) -> None:
    browser = browser_page.context.browser
    assert browser is not None
    anonymous = browser.new_context(ignore_https_errors=True)
    try:
        response = anonymous.request.get(webui.url(f"{ALERTS}?view=dnsbl_stat&stats_data=1"))
        assert "panels" not in response.text()
        assert "usernamefld" in response.text() or "SESSION_TIMEOUT" in response.text() or response.status in (401, 403)
    finally:
        anonymous.close()


@pytest.mark.ui_render
def test_stats_progressive_hidden_reply_panels_do_not_compute_a_total(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    preference = "installedpackages/pfblockerngglobal/pfbdnsblreplystat"
    hidden = (
        "replydate,replychart,replytype,replyorec,replyrec,replyttl,replydomain,"
        "replytld,replytld2,replytld3,replysrcipd,replysrcip,replydstip,replygeoip"
    )
    with _stats_log(smoke_vm, "dns_reply.log", "pfbdnsblreplystat", _rows("reply", helpers.unique_domain())):
        helpers.config_set(smoke_vm, preference, "replydomain")
        partial = webui.get(f"{ALERTS}?view=dnsbl_reply_stat&stats_data=1")
        assert "application/json" in partial.headers.get("content-type", "")
        assert partial.json()["total"] == 3
        assert "replydomain" not in [panel["id"] for panel in partial.json()["panels"]]
        helpers.config_set(smoke_vm, preference, hidden)
        response = webui.get(f"{ALERTS}?view=dnsbl_reply_stat&stats_data=1")
        assert "application/json" in response.headers.get("content-type", "")
        assert response.json() == {"total": None, "timeline": [], "panels": []}


@pytest.mark.ui_browser
@pytest.mark.parametrize(
    ("view", "log", "preference", "action"),
    [
        ("ip_block_stat", "ip_block.log", "pfbblockstat", "block"),
        ("ip_permit_stat", "ip_permit.log", "pfbpermitstat", "pass"),
        ("ip_match_stat", "ip_match.log", "pfbmatchstat", "match"),
    ],
)
def test_stats_progressive_ip_shared_renderer_preserves_native_chart(
    browser_page: Page,
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    view: str,
    log: str,
    preference: str,
    action: str,
) -> None:
    line = (
        f"2031-02-15 09:00:00,100,em0,WAN,{action},4,6,TCP,"
        "192.0.2.1,198.51.100.1,54321,80,in,US,pfB_Stats_v4,"
        "192.0.2.1,StatsFeed,Unknown,Unknown,64500,asn.stats.com,Stats ASN,+\n"
    )
    page = browser_page
    data_requests: list[str] = []
    page.on("request", lambda request: data_requests.append(request.url) if "stats_data=1" in request.url else None)
    with _stats_log(smoke_vm, log, preference, line):
        page.goto(webui.url(f"{ALERTS}?view={view}"), wait_until="domcontentloaded", timeout=90_000)
        _reveal(page, "ipgeoip")
        _expect()(page.locator("#Alert_Stats_ipgeoip tbody")).to_contain_text("US")
        _expect()(page.locator("#pieChart_ipgeoip svg")).to_have_attribute("viewBox", re.compile(r".+"))
        _reveal(page, "ipchart")
        _expect()(page.locator("#chart .nv-bar")).to_have_count(24)
        nonzero = page.locator("#chart .nv-bar").evaluate_all(
            "bars => bars.filter(bar => bar.__data__.ecount > 0).map(bar => "
            "({edate: bar.__data__.edate, ecount: bar.__data__.ecount}))"
        )
        assert nonzero == [{"edate": "2031-02-15 (09)", "ecount": 1}]
        assert not data_requests, "IP aggregation was moved to an unrequested data route"
        assert page.locator('#iform_stats input[name="__csrf_magic"]').input_value()


@pytest.mark.ui_browser
def test_stats_progressive_expired_session_never_injects_login_html(
    browser_page: Page,
    webui: WebUI,
) -> None:
    page = browser_page
    # route.fetch() stores the anonymous reply's fresh session cookie in the shared browser context, which
    # would log out every later browser test; keep the authenticated cookies and put them back afterwards.
    cookies = page.context.cookies()

    def expired(route: Route) -> None:
        # Strip authentication only from the real data GET, not the shell.
        headers = dict(route.request.headers)
        headers["cookie"] = ""
        response = route.fetch(headers=headers)
        assert "usernamefld" in response.text() or "SESSION_TIMEOUT" in response.text() or response.status in (401, 403)
        route.fulfill(response=response)

    page.route(DATA_ROUTE, expired)
    try:
        page.goto(webui.url(f"{ALERTS}?view=dnsbl_reply_stat"), wait_until="domcontentloaded", timeout=90_000)
        _expect()(page.locator("#Alert_Stats_Retry")).to_be_visible()
        _expect()(page.locator("#Alert_Stats_Status")).to_contain_text(re.compile(r"session|sign.in|log.in", re.I))
        assert page.locator("#iform_stats #usernamefld, #iform_stats .login").count() == 0
    finally:
        page.unroute(DATA_ROUTE, expired)
        page.context.clear_cookies()
        page.context.add_cookies(
            [{"name": c["name"], "value": c["value"], "domain": c["domain"], "path": c["path"]} for c in cookies]
        )
