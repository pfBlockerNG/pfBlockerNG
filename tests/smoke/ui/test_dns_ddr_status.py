"""Live DDR page checks: automatic semantic results, read-only polling and preserved form state."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import xml.etree.ElementTree as ET
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlsplit

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
    from collections.abc import Iterator
    from pathlib import Path

    from playwright.sync_api import Page, Route

    from ..test_smoke_dns_gateway import Gateway
    from ..test_smoke_dns_proxy import State
    from .webui import WebUI

DNS_PAGE = "/pfblockerng/pfblockerng_dns.php"
PANEL_ID = "pfb-dns-status-ddr"


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
    names = re.findall(r'<([a-z]+)\b[^>]*\bid="pfb-dns-ddr-name"[^>]*>.*?</\1>', section, re.DOTALL)
    assert len(names) == 1, section
    name_match = re.search(r'<[a-z]+\b[^>]*\bid="pfb-dns-ddr-name"[^>]*>.*?</[a-z]+>', section, re.DOTALL)
    assert name_match is not None and name_match.start() < table_match.start(), section
    name = ET.fromstring(name_match.group())
    assert "".join(name.itertext()).rstrip(".").lower() == DDR_DNS_NAME.rstrip(".").lower()
    assert sum(DDR_DNS_NAME.lower() in text.lower() for text in table.itertext()) == 0
    listeners = helpers.php_eval(
        gw.vm,
        "require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');"
        "echo json_encode(pfb_dns_proxy_listener_list()['listening']['udp+tcp']);",
    )
    assert listeners.returncode == 0, listeners.stderr
    bound = json.loads(listeners.stdout)
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
def test_dns_ddr_failed_refresh_clears_stale_results_and_recovers(
    gw: Gateway, gateway_on: State, browser_page: Page, webui: WebUI, failure: str
) -> None:
    _ensure_ddr(gw, on=True)
    page = browser_page
    page.clock.install()
    _open(page, webui, DNS_PAGE)
    section = page.locator(f"#{PANEL_ID}")
    states = {address: row.attrib["data-state"] for address, row in _status_rows(page.content()).items()}
    assert "matched" in states.values(), states
    endpoint = "**/pfblockerng_dns.php?ajax=ddr"
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
    requests: list[str] = []
    page.on("request", lambda request: requests.append(request.url) if request.url.endswith("?ajax=ddr") else None)

    def fail_refresh(route: Route) -> None:
        if failure == "timeout":
            held.append(route)
        elif failure == "redirect":
            route.fulfill(status=302, headers={"Location": DNS_PAGE + "?ajax=ddr&redirected=1"})
        else:
            status, content_type, body = replies[failure]
            route.fulfill(status=status, content_type=content_type, body=body)

    page.route(endpoint, fail_refresh)
    if failure == "timeout":
        with page.expect_request(lambda request: request.url.endswith("?ajax=ddr")):
            page.clock.run_for(30000)
        assert len(requests) == 1, requests
        page.clock.run_for(15000)
    else:
        with page.expect_response(lambda response: response.url.endswith("?ajax=ddr")):
            page.clock.run_for(30000)
    unavailable = section.get_by_role("status")
    unavailable.wait_for(state="visible", timeout=JS_TIMEOUT_MS)
    assert section.locator(".text-success").count() == 0, "Failed refresh retained stale green results"
    if failure == "timeout":
        assert len(held) == 1 and len(requests) == 1, requests
    page.unroute(endpoint)
    with page.expect_response(lambda response: "ajax=ddr" in response.url):
        page.clock.run_for(30000)
    unavailable.wait_for(state="detached", timeout=JS_TIMEOUT_MS)
    restored = {address: row.attrib["data-state"] for address, row in _status_rows(page.content()).items()}
    assert restored == states, f"Expected restored DNS results {states}, got {restored}"
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
    section = panel(html, PANEL_ID)
    assert section is not None, "pfB-DNS has no DDR Advertisements section"
    assert "refresh_ddr" not in section and "Refresh DDR advertisements" not in section, section
    assert "<pre" not in section and "STDOUT" not in section and "STDERR" not in section, section
    assert re.search(r"Checked: \d{4}-\d{2}-\d{2}", section), section
    table = re.search(r"<table\b.*?</table>", section, re.DOTALL)
    assert table, section
    root = ET.fromstring(table.group())
    assert [cell.text for cell in root.findall("./thead/tr/th")] == ["Interface", "Address", "DNS Name", "State"]
    rows = root.findall("./tbody/tr")
    result = {row.attrib["data-address"]: row for row in rows}
    assert len(result) == len(rows), f"duplicate addresses: {section}"
    for row in rows:
        state = row.findall("td")[3]
        icon = state.find(".//i")
        spoken = state.find(".//span[@class='sr-only']")
        assert icon is not None and icon.attrib.get("title"), ET.tostring(row, encoding="unicode")
        assert spoken is not None and spoken.text, ET.tostring(row, encoding="unicode")
        assert ("text-success" in " ".join(node.attrib.get("class", "") for node in state.iter())) == (
            row.attrib["data-state"] == "matched"
        ), ET.tostring(row, encoding="unicode")
    return result


@pytest.mark.ui_render
def test_dns_ddr_page_load_checks_each_actual_listener_without_writing_config(
    gw: Gateway, gateway_on: State, webui: WebUI
) -> None:
    """Load/reload and AJAX agree with independent directed SVCB observations, without a refresh control."""
    _ensure_ddr(gw, on=True)
    before = _config_digest(gw.vm)
    initial = webui.get(DNS_PAGE)
    assert initial.status_code == 200, initial.text
    rows = _status_rows(initial.text)
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
    for listener, row in rows.items():
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
        assert "".join(cells[2].itertext()).rstrip(".").lower() == DDR_TARGET.rstrip(".").lower()
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
    reloaded = webui.get(DNS_PAGE)
    assert reloaded.status_code == 200, reloaded.text
    assert set(_status_rows(reloaded.text)) == set(rows)
    refreshed = webui.get(DNS_PAGE + "?ajax=ddr&host=203.0.113.99&port=9")
    assert refreshed.status_code == 200, refreshed.text
    assert "no-store" in refreshed.headers.get("Cache-Control", ""), refreshed.headers
    assert set(_status_rows(refreshed.json()["html"])) == set(rows)
    assert _config_digest(gw.vm) == before, "read-only DDR checks changed config.xml"


@pytest.mark.ui_render
def test_dns_ddr_disabled_is_not_a_successful_match(gw: Gateway, gateway_on: State, webui: WebUI) -> None:
    _ensure_ddr(gw, on=True)
    assert any(row.attrib["data-state"] == "matched" for row in _status_rows(webui.get(DNS_PAGE).text).values())
    try:
        _ensure_ddr(gw, on=False)
        rows = _status_rows(webui.get(DNS_PAGE).text)
        assert rows and all(row.attrib["data-state"] == "off" for row in rows.values()), rows
    finally:
        _ensure_ddr(gw, on=True)


@pytest.mark.ui_render
def test_dns_ddr_stale_dns_name_is_a_mismatch(gw: Gateway, gateway_on: State, webui: WebUI) -> None:
    """A valid advertisement for the old name must not bless the current configured name."""
    _ensure_ddr(gw, on=True)
    baseline = _status_rows(webui.get(DNS_PAGE).text)
    verified = {address for address, row in baseline.items() if row.attrib["data-state"] == "matched"}
    assert verified, baseline
    replacement = helpers.unique_domain("ddr-stale")
    try:
        _set_lists(gw.vm, {"pfb_dns_name": replacement})
        before = _config_digest(gw.vm)
        rows = _status_rows(webui.get(DNS_PAGE).text)
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
    assert any(row.attrib["data-state"] == "matched" for row in _status_rows(page.content()).values())
    with page.expect_navigation(wait_until="domcontentloaded"):
        page.locator('button[type="submit"][name="save"]').click()
    assert page.locator(".input-errors").count() == 0, page.locator("body").inner_text()
    assert any(row.attrib["data-state"] == "matched" for row in _status_rows(page.content()).values())


@pytest.mark.ui_browser
@pytest.mark.parametrize("width", [320, 768, 1024, 1440])
def test_dns_ddr_timer_preserves_unsaved_form_and_collapse(
    gw: Gateway, gateway_on: State, browser_page: Page, webui: WebUI, width: int, screenshot_dir: Path
) -> None:
    """An automatic real request changes only panel children, including while collapsed, at every supported width."""
    _ensure_ddr(gw, on=True)
    page = browser_page
    page.set_viewport_size({"width": width, "height": 900})
    page.clock.install()
    _open(page, webui, DNS_PAGE)
    section = page.locator(f"#{PANEL_ID}")
    body = section.locator(f"#{PANEL_ID}_panel-body")
    assert section.locator("pre, #pfb-dns-ddr-refresh").count() == 0
    assert section.locator("tr[data-address]").count() > 0
    states = {address: row.attrib["data-state"] for address, row in _status_rows(page.content()).items()}
    assert "matched" in states.values(), states
    for icon in section.locator("td i").all():
        assert icon.get_attribute("title"), icon.evaluate("el => el.outerHTML")
        assert icon.locator("..").locator(".sr-only").inner_text()
    before = _config_digest(gw.vm)
    page.locator("#pfb_dns_name").fill("unsaved-ddr-name.com")
    page.evaluate("window.ddrBody = document.getElementById('pfb-dns-status-ddr_panel-body')")
    body.evaluate("el => el.insertAdjacentHTML('beforeend', '<span id=\"ddr-before-refresh\"></span>')")
    toggle = section.get_by_role("link", name="Toggle DDR Advertisements", exact=True)
    toggle.click()
    body.wait_for(state="hidden", timeout=JS_TIMEOUT_MS)
    with page.expect_response(lambda response: "ajax=ddr" in response.url, timeout=30000) as refreshed:
        page.clock.run_for(30000)
    assert refreshed.value.status == 200, refreshed.value.text()
    page.locator("#ddr-before-refresh").wait_for(state="detached", timeout=JS_TIMEOUT_MS)
    refreshed_states = {address: row.attrib["data-state"] for address, row in _status_rows(page.content()).items()}
    assert refreshed_states == states, (
        f"Automatic refresh changed unchanged DNS results: {states} -> {refreshed_states}"
    )
    assert page.locator("#pfb_dns_name").input_value() == "unsaved-ddr-name.com"
    assert page.evaluate("window.ddrBody === document.getElementById('pfb-dns-status-ddr_panel-body')")
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
