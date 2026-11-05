"""Live DDR page checks: automatic semantic results, read-only polling and preserved form state."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import time
import xml.etree.ElementTree as ET
from html import unescape
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, quote, urlsplit

import pytest

from .. import helpers
from ..test_smoke_dns_gateway import (
    DDR_DNS_NAME,
    DDR_TARGET,
    _ensure_ddr,
    _expected_svcb,
    _parse_reply,
    _set_lists,
    _svcb_records,
)
from ..test_smoke_dns_gateway import (
    gateway_on as gateway_on,
)
from ..test_smoke_dns_gateway import (
    go_toolchain as go_toolchain,
)
from ..test_smoke_dns_gateway import (
    gw as gw,
)
from ..test_smoke_dns_gateway import (
    probe_binary as probe_binary,
)
from .test_browser_feeds import JS_TIMEOUT_MS, _open
from .test_sync_status_panels import panel
from .webui import CSRF_FIELD, extract_csrf_token, looks_like_login_page

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from pathlib import Path

    from playwright.sync_api import Page, Route

    from ..test_smoke_dns_gateway import Gateway
    from ..test_smoke_dns_proxy import State
    from .webui import WebUI

DNS_PAGE = "/pfblockerng/pfblockerng_dns.php"
PANEL_ID = "pfb-dns-status-ddr"

LISTENER_QUERY = "ajax=ddr&listener="
PENDING_ROWS = (
    "() => [...document.querySelectorAll('#pfb-dns-status-ddr tr[data-address]')]"
    ".some(row => row.dataset.state === 'pending')"
)
SWEEP_RUNNING = "() => document.getElementById('pfb-dns-status-ddr_panel-body').hasAttribute('aria-busy')"


@pytest.fixture(autouse=True)
def _ui_pfb_isolation(request: pytest.FixtureRequest) -> Iterator[None]:
    """Preserve the module gateway, not the UI session's pre-gateway baseline."""
    if not request.node.get_closest_marker("ui_browser") or "gw" not in request.fixturenames:
        yield
        return
    gw = request.getfixturevalue("gw")
    snapshot = "/root/pfb_ddr_ui_baseline.xml"
    result = gw.vm.ssh("/bin/cp", "/conf/config.xml", snapshot)
    assert result.returncode == 0, result.stderr
    before = helpers.pfb_config_digest(gw.vm)
    try:
        yield
    finally:
        try:
            if helpers.pfb_config_digest(gw.vm) != before:
                helpers.restore_pfb_config_baseline(gw.vm, snapshot_path=snapshot)
        finally:
            gw.vm.ssh("/bin/rm", "-f", snapshot)


@pytest.mark.ui_render
def test_dns_ddr_initial_page_keeps_pending_rows_and_shared_name(gw: Gateway, gateway_on: State, webui: WebUI) -> None:
    """The initial response exposes every bound listener before any DNS result is available."""
    _ensure_ddr(gw, on=True)
    response = webui.get(DNS_PAGE)
    assert response.status_code == 200, response.text
    section = panel(response.text, PANEL_ID)
    assert section is not None, response.text
    table_match = re.search(r"<table\b.*?</table>", section, re.DOTALL)
    assert table_match, section
    table = ET.fromstring(table_match.group())
    assert [cell.text for cell in table.findall("./thead/tr/th")] == ["Interface", "Address", "State"]
    assert _shared_name(response.text).rstrip(".").lower() == DDR_DNS_NAME.rstrip(".").lower()
    assert sum(DDR_DNS_NAME.lower() in text.lower() for text in table.itertext()) == 0
    listeners = helpers.php_eval(
        gw.vm,
        "require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');"
        "echo json_encode(['bound'=>pfb_dns_proxy_listener_list()['listening']['udp+tcp']]);",
    )
    assert listeners.returncode == 0, listeners.stderr
    match = re.search(r'\{"bound":.*\}', listeners.stdout)
    assert match, listeners.stdout
    bound = json.loads(match.group())["bound"]
    rows = table.findall("./tbody/tr")
    assert bound and {row.attrib["data-address"] for row in rows} == set(bound), listeners.stdout
    assert len(rows) == len(bound), section
    for row in rows:
        assert row.attrib["data-state"] == "pending", ET.tostring(row, encoding="unicode")
        cells = row.findall("td")
        assert len(cells) == 3, ET.tostring(row, encoding="unicode")
        icon = cells[2].find(".//i")
        assert icon is not None and {"fa-spinner", "fa-spin", "text-muted"} <= set(icon.attrib["class"].split())
        spoken = cells[2].find(".//span[@class='sr-only']")
        assert spoken is not None and spoken.text, ET.tostring(row, encoding="unicode")


@pytest.mark.ui_browser
def test_dns_ddr_initial_checks_are_async_and_keep_rows_on_failure(
    gw: Gateway, gateway_on: State, browser_page: Page, webui: WebUI
) -> None:
    """A stalled first query cannot block the form, later rows, or retained background results."""
    _ensure_ddr(gw, on=True)
    page = browser_page
    page.clock.install()
    held: list[Route] = []
    requested: list[str] = []
    phase = "hold"

    def selected_listener(route: Route) -> None:
        query = parse_qs(urlsplit(route.request.url).query)
        assert set(query) == {"ajax", "listener"}, query
        requested.append(query["listener"][0])
        if phase == "hold" and not held:
            held.append(route)
        elif phase == "fail":
            route.abort()
        else:
            route.continue_()

    page.route("**/pfblockerng_dns.php?ajax=ddr&listener=*", selected_listener)
    with page.expect_request(lambda request: "ajax=ddr&listener=" in request.url):
        page.goto(webui.url(DNS_PAGE), wait_until="domcontentloaded", timeout=JS_TIMEOUT_MS * 3)
    assert page.locator("#usernamefld").count() == 0
    rows = page.locator(f"#{PANEL_ID} tr[data-address]")
    addresses = rows.evaluate_all("rows => rows.map(row => row.dataset.address)")
    assert len(addresses) > 1 and len(held) == 1, addresses
    assert rows.evaluate_all("rows => rows.every(row => row.dataset.state === 'pending')")
    assert rows.locator("td:nth-child(3) .fa-spinner.fa-spin.text-muted").count() == len(addresses)
    page.evaluate(
        """() => {
            window.ddrInitialTable = document.querySelector('#pfb-dns-status-ddr table');
            window.ddrInitialRows = [...window.ddrInitialTable.querySelectorAll('tbody tr')];
        }"""
    )
    page.locator("#pfb_dns_name").fill("unsaved-ddr-name.com")
    assert page.locator('button[type="submit"][name="save"]').is_enabled()
    phase = "pass"
    held[0].abort()
    page.wait_for_function(
        """() => window.ddrInitialRows.slice(1).every(row => row.dataset.state !== 'pending')""",
        timeout=JS_TIMEOUT_MS,
    )
    assert requested == addresses, requested
    assert rows.first.get_attribute("data-state") == "pending"
    note = page.locator("#pfb-dns-ddr-refresh-status")
    note.wait_for(state="visible", timeout=JS_TIMEOUT_MS)
    page.clock.run_for(30000)
    page.wait_for_function(
        "() => window.ddrInitialRows.every(row => row.dataset.state !== 'pending')",
        timeout=JS_TIMEOUT_MS,
    )
    note.wait_for(state="hidden", timeout=JS_TIMEOUT_MS)
    assert requested == addresses + addresses, requested
    results = rows.evaluate_all("rows => rows.map(row => [row.dataset.state, row.cells[2].innerHTML])")
    assert any(state == "matched" for state, _ in results), results
    phase = "fail"
    page.clock.run_for(30000)
    note.wait_for(state="visible", timeout=JS_TIMEOUT_MS)
    assert rows.evaluate_all("rows => rows.map(row => [row.dataset.state, row.cells[2].innerHTML])") == results
    assert page.evaluate(
        """() => window.ddrInitialTable === document.querySelector('#pfb-dns-status-ddr table') &&
            window.ddrInitialRows.every((row, index) =>
                row === document.querySelectorAll('#pfb-dns-status-ddr tbody tr')[index])"""
    )
    assert page.locator("#pfb_dns_name").input_value() == "unsaved-ddr-name.com"


@pytest.mark.ui_browser
@pytest.mark.parametrize("failure", ["http", "login", "redirect", "json", "shape", "missing", "duplicate", "timeout"])
def test_dns_ddr_failed_refresh_keeps_rows_and_last_results_then_recovers(
    gw: Gateway, gateway_on: State, browser_page: Page, webui: WebUI, failure: str
) -> None:
    """A failed refresh keeps every row, its element and its last results; the next complete sweep clears the note."""
    _ensure_ddr(gw, on=True)
    page = browser_page
    page.clock.install()
    requests = _track_listener_requests(page)
    _open(page, webui, DNS_PAGE)
    _wait_settled(page)
    section = page.locator(f"#{PANEL_ID}")
    states = _states(page)
    addresses = list(states)
    assert "matched" in states.values(), states
    successes = section.locator(".text-success").count()
    _remember_rows(page)
    endpoint = "**/pfblockerng_dns.php?ajax=ddr&listener=*"
    panel_html = f'<div id="{PANEL_ID}"><div id="{PANEL_ID}_panel-body"></div></div>'
    replies = {
        "http": (503, "text/plain", "Service unavailable"),
        "login": (200, "text/html", '<form id="unexpected-login"></form>'),
        "json": (200, "application/json", "{"),
        "shape": (200, "application/json", '{"html":7}'),
        "missing": (200, "application/json", json.dumps({"html": "<p>No DDR panel</p>"})),
        "duplicate": (200, "application/json", json.dumps({"html": panel_html + panel_html})),
    }
    held: list[Route] = []

    def fail_refresh(route: Route) -> None:
        if failure == "timeout":
            held.append(route)
        elif failure == "redirect":
            route.fulfill(status=302, headers={"Location": DNS_PAGE + "?ajax=ddr&redirected=1"})
        else:
            status, content_type, body = replies[failure]
            route.fulfill(status=status, content_type=content_type, body=body)

    page.route(endpoint, fail_refresh)
    before = len(requests)
    page.clock.run_for(30000)
    if failure == "timeout":
        # Held rows time out after their own 15 s request budget; then the next rows are queried.
        seen = 0
        while seen < len(addresses):
            _wait_until(page, lambda: len(held) > seen, f"rows after {seen} to be queried")
            seen = len(held)
            page.clock.run_for(15000)
    _wait_sweep_done(page)
    assert len(requests) - before == len(addresses), requests[before:]
    assert len(held) == (len(addresses) if failure == "timeout" else 0), held
    unavailable = section.get_by_role("status")
    unavailable.wait_for(state="visible", timeout=JS_TIMEOUT_MS)
    assert section.locator(".text-success").count() == successes, "A failed refresh changed the last results"
    assert _states(page) == states, "A failed refresh changed the last results"
    assert _rows_kept(page), "A failed refresh replaced the DDR table or its rows"
    page.unroute(endpoint)
    before = len(requests)
    page.clock.run_for(30000)
    _wait_sweep_done(page)
    assert len(requests) - before == len(addresses), requests[before:]
    unavailable.wait_for(state="hidden", timeout=JS_TIMEOUT_MS)
    restored = _states(page)
    assert restored == states, f"Expected restored DNS results {states}, got {restored}"
    assert _rows_kept(page), "Recovery replaced the DDR table or its rows"
    count = len(requests)
    page.evaluate("window.dispatchEvent(new PageTransitionEvent('pagehide'))")
    page.clock.run_for(60000)
    assert len(requests) == count, "Polling continued after the page was hidden"


@pytest.mark.ui_render
@pytest.mark.parametrize("method", ["GET", "POST"])
def test_dns_ddr_read_only_dispatch(method: str, webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    form_page = webui.get(DNS_PAGE)
    before = _config_digest(smoke_vm)
    url = DNS_PAGE + "?ajax=ddr"
    if method == "GET":
        response = webui.get(url)
        assert response.status_code == 200, response.text
        assert panel(response.json()["html"], PANEL_ID) is not None, response.text
    else:
        token = extract_csrf_token(form_page.text)
        response = webui.session.post(webui.url(url), data={CSRF_FIELD: token}, verify=webui._verify, timeout=30)  # noqa: SLF001
        assert response.status_code == 405, response.text
        assert response.headers.get("Allow") == "GET", response.headers
    assert "no-store" in response.headers.get("Cache-Control", ""), response.headers
    assert _config_digest(smoke_vm) == before, "DDR dispatch changed config.xml"


@pytest.mark.ui_render
def test_dns_ddr_array_selector_is_rejected(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    before = _config_digest(smoke_vm)
    response = webui.get(DNS_PAGE + "?ajax=ddr&listener[]=127.0.0.1%3A53")
    assert response.status_code == 400, response.text
    assert "no-store" in response.headers.get("Cache-Control", ""), response.headers
    assert _config_digest(smoke_vm) == before, "Rejected DDR selector changed config.xml"


@pytest.mark.ui_render
def test_dns_ddr_ajax_requires_the_web_session(webui: WebUI) -> None:
    response = webui.get_unauthenticated(DNS_PAGE + "?ajax=ddr")
    assert looks_like_login_page(response.text), response.text
    assert "application/json" not in response.headers.get("Content-Type", ""), response.headers
    assert "data-address=" not in response.text, response.text


def _config_digest(vm: helpers.SmokeVM) -> str:
    result = vm.ssh("/bin/cat", "/conf/config.xml")
    assert result.returncode == 0, result.stderr
    return hashlib.sha256(result.stdout.encode()).hexdigest()


def _status_rows(html: str) -> dict[str, ET.Element]:
    """Rows of the DDR table: one per listener, each State cell an accessible icon with a valid data-state."""
    section = panel(html, PANEL_ID)
    assert section is not None, "pfB-DNS has no DDR Advertisements section"
    assert "refresh_ddr" not in section and "Refresh DDR advertisements" not in section, section
    assert "<pre" not in section and "STDOUT" not in section and "STDERR" not in section, section
    table = re.search(r"<table\b.*?</table>", section, re.DOTALL)
    assert table, section
    root = ET.fromstring(table.group())
    assert [cell.text for cell in root.findall("./thead/tr/th")] == ["Interface", "Address", "State"]
    rows = root.findall("./tbody/tr")
    result = {row.attrib["data-address"]: row for row in rows}
    assert len(result) == len(rows), f"duplicate addresses: {section}"
    for row in rows:
        cells = row.findall("td")
        assert len(cells) == 3, ET.tostring(row, encoding="unicode")
        icon = cells[2].find(".//i")
        spoken = cells[2].find(".//span[@class='sr-only']")
        assert icon is not None and spoken is not None and spoken.text, ET.tostring(row, encoding="unicode")
        if row.attrib["data-state"] == "pending":
            assert {"fa-spinner", "fa-spin", "text-muted"} <= set(icon.attrib.get("class", "").split()), ET.tostring(
                row, encoding="unicode"
            )
        else:
            assert icon.attrib.get("title"), ET.tostring(row, encoding="unicode")
        assert ("text-success" in " ".join(node.attrib.get("class", "") for node in cells[2].iter())) == (
            row.attrib["data-state"] == "matched"
        ), ET.tostring(row, encoding="unicode")
    return result


def _shared_name(html: str) -> str:
    """The applied DNS Name, shown once in the pfB-DNS Status overview."""
    match = re.search(r'<tr id="pfb-dns-status-name"><th>DNS Name</th><td>([^<]*)</td></tr>', html)
    assert match, html
    return unescape(match.group(1)).strip()


def _page_html(webui: WebUI) -> str:
    response = webui.get(DNS_PAGE)
    assert response.status_code == 200, response.text
    return response.text


def _listener_html(webui: WebUI, address: str) -> str:
    """One selected listener's check, fetched as the page fetches it: uncached and timestamped."""
    response = webui.get(f"{DNS_PAGE}?{LISTENER_QUERY}{quote(address, safe='')}")
    assert response.status_code == 200, response.text
    assert "no-store" in response.headers.get("Cache-Control", ""), response.headers
    html = response.json()["html"]
    assert re.search(r"Checked: \d{4}-\d{2}-\d{2}", html), html
    return html


def _checked_rows(webui: WebUI) -> dict[str, ET.Element]:
    """Every bound listener's result, one selected request each, as the page's own sweep fetches them."""
    rows: dict[str, ET.Element] = {}
    for address in _status_rows(_page_html(webui)):
        checked = _status_rows(_listener_html(webui, address))
        assert set(checked) == {address}, checked
        rows.update(checked)
    return rows


def _wait_until(page: Page, done: Callable[[], bool], what: str) -> None:
    """Poll from Python, so the page's fake clock never stalls the wait."""
    deadline = time.monotonic() + 3 * JS_TIMEOUT_MS / 1000
    while not done():
        assert time.monotonic() < deadline, f"timed out waiting for {what}"
        page.wait_for_timeout(50)


def _wait_settled(page: Page) -> None:
    _wait_until(page, lambda: not page.evaluate(PENDING_ROWS), "every DDR row to get a result")


def _wait_sweep_done(page: Page) -> None:
    _wait_until(page, lambda: not page.evaluate(SWEEP_RUNNING), "the DDR sweep to finish")


def _states(page: Page) -> dict[str, str]:
    return {address: row.attrib["data-state"] for address, row in _status_rows(page.content()).items()}


def _remember_rows(page: Page) -> None:
    page.evaluate("""() => {
        window.ddrTable = document.querySelector('#pfb-dns-status-ddr table');
        window.ddrRows = [...document.querySelectorAll('#pfb-dns-status-ddr tbody tr')];
    }""")


def _rows_kept(page: Page) -> bool:
    """True while the table and every row element are the ones remembered by _remember_rows."""
    return page.evaluate("""() => {
        const rows = [...document.querySelectorAll('#pfb-dns-status-ddr tbody tr')];
        return document.querySelector('#pfb-dns-status-ddr table') === window.ddrTable &&
            rows.length === window.ddrRows.length && rows.every((row, index) => row === window.ddrRows[index]);
    }""")


def _track_listener_requests(page: Page) -> list[str]:
    requests: list[str] = []
    page.on("request", lambda request: requests.append(request.url) if LISTENER_QUERY in request.url else None)
    return requests


def _run_poll(page: Page, requests: list[str], rows: int) -> None:
    """Fire the 30 second poll under the fake clock; the sweep must query each row once and then finish."""
    before = len(requests)
    page.clock.run_for(30000)
    _wait_sweep_done(page)
    assert len(requests) - before == rows, requests[before:]


@pytest.mark.ui_render
def test_dns_ddr_listener_checks_agree_with_directed_svcb_without_writing_config(
    gw: Gateway, gateway_on: State, webui: WebUI
) -> None:
    """Each selected listener check agrees with an independent directed SVCB observation; the page carries no result."""
    _ensure_ddr(gw, on=True)
    before = _config_digest(gw.vm)
    rows = _status_rows(_page_html(webui))
    assert rows and all(row.attrib["data-state"] == "pending" for row in rows.values()), rows
    listeners = helpers.php_eval(
        gw.vm,
        "require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');echo json_encode(["
        "'listening'=>pfb_dns_proxy_listener_list()['listening'],'names'=>pfb_dns_proxy_name_answers()]);",
    )
    assert listeners.returncode == 0, listeners.stderr
    match = re.search(r'\{"listening":.*\}', listeners.stdout)
    assert match, listeners.stdout
    observed = json.loads(match.group())
    bound = observed["listening"]["udp+tcp"]
    assert bound and set(rows) == set(bound), f"bound: {bound}; page: {rows}"
    loopback = gw.vm.ssh("/sbin/ifconfig", "lo0")
    assert loopback.returncode == 0, loopback.stderr
    loopback6 = {
        str(ipaddress.ip_address(address.split("%", 1)[0]))
        for address in re.findall(r"\binet6\s+(\S+)", loopback.stdout)
    }
    for listener in rows:
        html = _listener_html(webui, listener)
        checked = _status_rows(html)
        assert set(checked) == {listener}, html
        row = checked[listener]
        host, _, port = listener.rpartition(":")
        host = str(ipaddress.ip_address(host.strip("[]")))
        source = ("::1" if host in loopback6 else None) if ":" in host else "127.0.0.1"
        arguments = [
            "/usr/bin/timeout",
            "-s",
            "TERM",
            "-k1",
            "3",
            "/usr/bin/drill",
            "-b1232",
            *(["-6"] if ":" in host else []),
            *(["-I", source] if source is not None else []),
            "-p",
            port,
            "_dns.resolver.arpa.",
            f"@{host}",
            "SVCB",
        ]
        result = gw.vm.ssh(*arguments)
        print(f"DDR reference {listener}, source={source!r}: {arguments!r}\n{result.stdout}{result.stderr}")
        assert result.returncode == 0, f"{listener}: {result.stdout}\n{result.stderr}"
        reply = _parse_reply(result.stdout)
        assert reply.rcode in {"NOERROR", "REFUSED"}, result.stdout
        cells = row.findall("td")
        assert "".join(cells[1].itertext()) == listener, ET.tostring(row, encoding="unicode")
        state = row.attrib["data-state"]
        if reply.rcode == "REFUSED":
            assert state == "error", ET.tostring(row, encoding="unicode")
        else:
            wanted = []
            for record in _expected_svcb(DDR_TARGET, doh_443=False, address=host):
                alpn = record.params["alpn"]
                service_port = record.params.get("port", "443" if alpn == "h2" else "853")
                endpoint = f"[{host}]:{service_port}" if ":" in host else f"{host}:{service_port}"
                kind = {"h2": "doh", "dot": "dot", "doq": "doq"}[alpn]
                if endpoint in observed["listening"].get(kind, {}):
                    wanted.append(record)
            assert _svcb_records(reply) == wanted, reply.raw
            expected_state = "matched" if host in observed["names"] or host in {"127.0.0.1", "::1"} else "unverified"
            if not wanted:
                expected_state = "no_transport"
            assert state == expected_state, ET.tostring(row, encoding="unicode")
    reloaded = _status_rows(_page_html(webui))
    assert set(reloaded) == set(rows)
    unbound = webui.get(f"{DNS_PAGE}?{LISTENER_QUERY}{quote('203.0.113.99:9', safe='')}")
    assert unbound.status_code == 200, unbound.text
    assert "no-store" in unbound.headers.get("Cache-Control", ""), unbound.headers
    assert "203.0.113.99:9" not in unbound.json()["html"], unbound.text
    assert _config_digest(gw.vm) == before, "read-only DDR checks changed config.xml"


@pytest.mark.ui_render
def test_dns_ddr_disabled_is_not_a_successful_match(gw: Gateway, gateway_on: State, webui: WebUI) -> None:
    _ensure_ddr(gw, on=True)
    assert any(row.attrib["data-state"] == "matched" for row in _checked_rows(webui).values())
    try:
        _ensure_ddr(gw, on=False)
        rows = _checked_rows(webui)
        assert rows and all(row.attrib["data-state"] == "off" for row in rows.values()), rows
    finally:
        _ensure_ddr(gw, on=True)


@pytest.mark.ui_render
def test_dns_ddr_stale_dns_name_is_a_mismatch(gw: Gateway, gateway_on: State, webui: WebUI) -> None:
    """A valid advertisement for the old name must not bless the current configured name."""
    _ensure_ddr(gw, on=True)
    baseline = _checked_rows(webui)
    verified = {address for address, row in baseline.items() if row.attrib["data-state"] == "matched"}
    assert verified, baseline
    replacement = helpers.unique_domain("ddr-stale")
    try:
        _set_lists(gw.vm, {"pfb_dns_name": replacement})
        before = _config_digest(gw.vm)
        rows = _checked_rows(webui)
        assert set(rows) == set(baseline), rows
        assert all(rows[address].attrib["data-state"] == "mismatch" for address in verified), rows
        assert all(row.attrib["data-state"] != "matched" for row in rows.values()), rows
        assert _config_digest(gw.vm) == before, "DDR mismatch check changed config.xml"
    finally:
        _set_lists(gw.vm, {"pfb_dns_name": DDR_DNS_NAME})


@pytest.mark.ui_browser
def test_dns_ddr_checks_automatically_after_saving(
    gw: Gateway, gateway_on: State, browser_page: Page, webui: WebUI
) -> None:
    _ensure_ddr(gw, on=True)
    page = browser_page
    _open(page, webui, DNS_PAGE)
    _wait_settled(page)
    assert any(state == "matched" for state in _states(page).values()), _states(page)
    with page.expect_navigation(wait_until="domcontentloaded"):
        page.locator('button[type="submit"][name="save"]').click()
    assert page.locator(".input-errors").count() == 0, page.locator("body").inner_text()
    _wait_settled(page)
    assert any(state == "matched" for state in _states(page).values()), _states(page)


@pytest.mark.ui_browser
@pytest.mark.parametrize("width", [320, 768, 1024, 1440])
def test_dns_ddr_timer_preserves_unsaved_form_and_collapse(
    gw: Gateway, gateway_on: State, browser_page: Page, webui: WebUI, width: int, screenshot_dir: Path
) -> None:
    """An automatic refresh changes only State cells, including while collapsed, at every supported width."""
    _ensure_ddr(gw, on=True)
    page = browser_page
    page.set_viewport_size({"width": width, "height": 900})
    page.clock.install()
    requests = _track_listener_requests(page)
    _open(page, webui, DNS_PAGE)
    section = page.locator(f"#{PANEL_ID}")
    body = section.locator(f"#{PANEL_ID}_panel-body")
    assert section.locator("pre, #pfb-dns-ddr-refresh").count() == 0
    assert section.locator("tr[data-address]").count() > 0
    _wait_settled(page)
    states = _states(page)
    assert "matched" in states.values(), states
    for icon in section.locator("td i").all():
        assert icon.get_attribute("title"), icon.evaluate("el => el.outerHTML")
        assert icon.locator("..").locator(".sr-only").inner_text()
    before = _config_digest(gw.vm)
    page.locator("#pfb_dns_name").fill("unsaved-ddr-name.com")
    page.evaluate("window.ddrBody = document.getElementById('pfb-dns-status-ddr_panel-body')")
    body.evaluate("el => el.insertAdjacentHTML('beforeend', '<span id=\"ddr-before-refresh\"></span>')")
    _remember_rows(page)
    toggle = section.get_by_role("link", name="Toggle DDR Advertisements", exact=True)
    toggle.click()
    body.wait_for(state="hidden", timeout=JS_TIMEOUT_MS)
    _run_poll(page, requests, len(states))
    assert page.locator("#ddr-before-refresh").count() == 1, "A refresh replaced the panel body"
    assert page.evaluate("window.ddrBody === document.getElementById('pfb-dns-status-ddr_panel-body')")
    assert _rows_kept(page), "A refresh replaced the DDR table or its rows"
    refreshed_states = _states(page)
    assert refreshed_states == states, (
        f"Automatic refresh changed unchanged DNS results: {states} -> {refreshed_states}"
    )
    assert page.locator("#pfb_dns_name").input_value() == "unsaved-ddr-name.com"
    assert not body.is_visible(), "refresh expanded the collapsed panel"
    toggle.click()
    body.wait_for(state="visible", timeout=JS_TIMEOUT_MS)
    dimensions = section.evaluate(
        """el => {
            const page = document.documentElement.scrollWidth;
            const display = el.style.display;
            el.style.display = 'none';
            const withoutPanel = document.documentElement.scrollWidth;
            el.style.display = display;
            return {right: el.getBoundingClientRect().right, width: innerWidth, page, withoutPanel,
                tables: [...el.querySelectorAll('.table-responsive')].map(n => getComputedStyle(n).overflowX)};
        }"""
    )
    assert dimensions["right"] <= dimensions["width"], dimensions
    assert dimensions["page"] == dimensions["withoutPanel"], f"DDR must not widen the rest of the page: {dimensions}"
    assert dimensions["tables"] and all(value in ("auto", "scroll") for value in dimensions["tables"]), dimensions
    assert _config_digest(gw.vm) == before, "browser refresh changed config.xml"
    section.screenshot(path=str(screenshot_dir / f"pfb-dns-ddr-{width}.png"))
