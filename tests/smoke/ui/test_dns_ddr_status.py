"""Applied DNS status: one complete snapshot per refresh, with read-only accessible rendering."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import xml.etree.ElementTree as ET
from html import unescape
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest

from .. import helpers
from ..test_smoke_dns_gateway import DDR_DNS_NAME, _ensure_ddr, _parse_reply, _set_lists, _svcb_records
from ..test_smoke_dns_gateway import gateway_on as gateway_on
from ..test_smoke_dns_gateway import go_toolchain as go_toolchain
from ..test_smoke_dns_gateway import gw as gw
from ..test_smoke_dns_gateway import probe_binary as probe_binary
from .test_browser_feeds import JS_TIMEOUT_MS, _open
from .test_render_smoke import _resolver_address_keys_restored
from .test_sync_status_panels import panel
from .webui import CSRF_FIELD, extract_csrf_token, looks_like_login_page

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from playwright.sync_api import Page, Route

    from ..test_smoke_dns_gateway import Gateway
    from ..test_smoke_dns_proxy import State
    from .webui import WebUI

DNS_PAGE = "/pfblockerng/pfblockerng_dns_general.php"
PANEL_ID = "pfb-dns-status-ddr"
STATUS_QUERY = "ajax=ddr"
ENDPOINT = "**/pfblockerng_dns_general.php?ajax=ddr"


@pytest.fixture(autouse=True)
def _ui_pfb_isolation(request: pytest.FixtureRequest) -> Iterator[None]:
    """Preserve the module gateway, not the UI session's pre-gateway baseline."""
    if not request.node.get_closest_marker("ui_browser") or "gw" not in request.fixturenames:
        yield
        return
    gateway = request.getfixturevalue("gw")
    snapshot = "/root/pfb_ddr_ui_baseline.xml"
    result = gateway.vm.ssh("/bin/cp", "/conf/config.xml", snapshot)
    assert result.returncode == 0, result.stderr
    before = helpers.pfb_config_digest(gateway.vm)
    try:
        yield
    finally:
        try:
            if helpers.pfb_config_digest(gateway.vm) != before:
                helpers.restore_pfb_config_baseline(gateway.vm, snapshot_path=snapshot)
        finally:
            gateway.vm.ssh("/bin/rm", "-f", snapshot)


def _config_digest(vm: helpers.SmokeVM) -> str:
    result = vm.ssh("/bin/cat", "/conf/config.xml")
    assert result.returncode == 0, result.stderr
    return hashlib.sha256(result.stdout.encode()).hexdigest()


def _status_rows(html: str) -> dict[str, ET.Element]:
    section = panel(html, PANEL_ID)
    assert section is not None, html
    assert "<pre" not in section and "STDOUT" not in section and "STDERR" not in section, section
    table = re.search(r"<table\b.*?</table>", section, re.DOTALL)
    assert table, section
    root = ET.fromstring(table.group())
    assert [cell.text for cell in root.findall("./thead/tr/th")] == ["Interface", "Address", "State"]
    rows = root.findall("./tbody/tr")
    result = {row.attrib["data-address"]: row for row in rows}
    assert len(result) == len(rows), f"Duplicate addresses: {section}"
    for row in rows:
        cells = row.findall("td")
        assert len(cells) == 3, ET.tostring(row, encoding="unicode")
        assert row.attrib["data-state"] in {"matched", "no_transport", "off"}, ET.tostring(row, encoding="unicode")
        icon = cells[2].find(".//i")
        spoken = cells[2].find(".//span[@class='sr-only']")
        assert icon is not None and icon.attrib.get("title"), ET.tostring(row, encoding="unicode")
        assert spoken is not None and spoken.text, ET.tostring(row, encoding="unicode")
        assert ("text-success" in icon.attrib["class"]) == (row.attrib["data-state"] == "matched"), icon.attrib
    return result


def _shared_name(html: str) -> str:
    match = re.search(r'<tr id="pfb-dns-status-name"><th>DNS Name</th><td>([^<]*)</td></tr>', html)
    assert match, html
    return unescape(match.group(1)).strip()


def _snapshot_html(webui: WebUI) -> str:
    response = webui.get(DNS_PAGE + "?" + STATUS_QUERY)
    assert response.status_code == 200, response.text
    assert "no-store" in response.headers.get("Cache-Control", ""), response.headers
    html = response.json()["html"]
    assert html.startswith('<div id="pfb-dns-status">'), html
    assert re.search(r"Snapshot: \d{4}-\d{2}-\d{2}", html), html
    return html


def _states(page: Page) -> dict[str, str]:
    return {address: row.attrib["data-state"] for address, row in _status_rows(page.content()).items()}


def _track_requests(page: Page) -> list[str]:
    requests: list[str] = []
    page.on(
        "request",
        lambda request: (
            requests.append(request.url) if STATUS_QUERY in request.url and request.redirected_from is None else None
        ),
    )
    return requests


def _poll(page: Page, requests: list[str]) -> None:
    before = len(requests)
    with page.expect_response(lambda response: STATUS_QUERY in response.url):
        page.clock.run_for(30000)
    page.wait_for_function("() => !document.getElementById('pfb-dns-status').hasAttribute('aria-busy')")
    assert len(requests) - before == 1, requests[before:]
    assert parse_qs(urlsplit(requests[-1]).query) == {"ajax": ["ddr"]}, requests[-1]


@pytest.mark.ui_render
def test_dns_ddr_initial_page_renders_applied_snapshot(gw: Gateway, gateway_on: State, webui: WebUI) -> None:
    """Tier A: the initial response already contains applied rows, not deferred per-address queries."""
    _ensure_ddr(gw, on=True)
    response = webui.get(DNS_PAGE)
    assert response.status_code == 200, response.text
    rows = _status_rows(response.text)
    assert rows and any(row.attrib["data-state"] == "matched" for row in rows.values()), rows
    assert _shared_name(response.text).lower() == DDR_DNS_NAME.rstrip(".").lower()
    assert 'data-state="pending"' not in response.text, response.text
    observed = helpers.php_eval(
        gw.vm,
        "require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');echo json_encode(pfb_dns_proxy_applied_status());",
    )
    assert observed.returncode == 0, observed.stderr
    match = re.search(r'\{"version":.*\}', observed.stdout)
    assert match, observed.stdout
    applied = json.loads(match.group())
    bound = {
        item["address"] for item in applied["listeners"] if item["kind"] == "udp+tcp" and item["state"] == "listening"
    }
    assert set(rows) == bound, f"page={set(rows)}, applied={bound}"
    for address, row in rows.items():
        host = address.rsplit(":", 1)[0].strip("[]")
        advertisement = applied["advertisements"][host]
        expected = "off" if not applied["ddr"] else ("matched" if advertisement["records"] else "no_transport")
        assert row.attrib["data-state"] == expected, ET.tostring(row, encoding="unicode")
    assert set(_status_rows(_snapshot_html(webui))) == bound


@pytest.mark.ui_render
def test_dns_ddr_unavailable_control_snapshot_is_not_an_absent_name(
    gw: Gateway, gateway_on: State, webui: WebUI
) -> None:
    """An unreadable control socket affects status, not the running DNS service or saved name."""
    _ensure_ddr(gw, on=True)
    baseline = _shared_name(_snapshot_html(webui))
    control = "/var/run/pfb_dns/ctl.sock"
    held = control + ".status-test"
    configured = helpers.php_eval(
        gw.vm,
        "require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');"
        "echo json_encode(['socket'=>$pfb['dns_proxy_ctl']]);",
    )
    match = re.search(r'\{"socket":".*?"\}', configured.stdout)
    assert configured.returncode == 0 and match, configured.stdout + configured.stderr
    assert json.loads(match.group())["socket"] == control, configured.stdout
    absent = gw.vm.ssh("/bin/test", "!", "-e", held)
    assert absent.returncode == 0, f"Refusing to replace an existing socket backup: {held}"
    moved = gw.vm.ssh("/bin/mv", control, held)
    assert moved.returncode == 0, moved.stderr
    try:
        for url in (DNS_PAGE, DNS_PAGE + "?" + STATUS_QUERY):
            response = webui.get(url)
            assert response.status_code == 200, response.text
            html = response.json()["html"] if STATUS_QUERY in url else response.text
            assert _shared_name(html) == "Unavailable", html
            section = panel(html, PANEL_ID)
            assert section is not None and "Applied pfB-DNS status unavailable." in section, section
            assert 'data-state="matched"' not in section and 'data-state="pending"' not in section, section
    finally:
        restored = gw.vm.ssh("/bin/mv", held, control)
        assert restored.returncode == 0, restored.stderr
    assert _shared_name(_snapshot_html(webui)) == baseline


@pytest.mark.ui_render
@pytest.mark.parametrize("method", ["GET", "POST"])
def test_dns_ddr_read_only_dispatch(method: str, webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    form_page = webui.get(DNS_PAGE)
    before = _config_digest(smoke_vm)
    url = DNS_PAGE + "?" + STATUS_QUERY
    if method == "GET":
        response = webui.get(url)
        assert response.status_code == 200, response.text
        assert 'id="pfb-dns-status-overview"' in response.json()["html"], response.text
    else:
        token = extract_csrf_token(form_page.text)
        response = webui.session.post(webui.url(url), data={CSRF_FIELD: token}, verify=webui._verify, timeout=30)  # noqa: SLF001
        assert response.status_code == 405, response.text
        assert response.headers.get("Allow") == "GET", response.headers
    assert "no-store" in response.headers.get("Cache-Control", ""), response.headers
    assert _config_digest(smoke_vm) == before, "Status dispatch changed config.xml"


@pytest.mark.ui_render
@pytest.mark.parametrize(
    "selector",
    [
        "listener[]=127.0.0.1%3A53",
        "listener=127.0.0.1%3A53",
        *[
            urlencode({"listener": target})
            for target in (
                "127.0.0.1:53; touch /tmp/ddr",
                "dns.example.com:53",
                "127.0.0.1:0",
                "127.0.0.1:65536",
                "127.0.0.1:053",
                "127.0.0.1:",
                "::1:53",
                "[fe80::1%em0]:53",
                "[2001:0db8::1]:53",
                "[::ffff:192.0.2.1]:53",
                "",
                "192.0.2.99:53",
                "192.0.2.50:53",
                "192.0.2.1:853",
                "192.0.2.1:53",
            )
        ],
    ],
)
def test_dns_ddr_no_longer_accepts_per_address_queries(selector: str, webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    before = _config_digest(smoke_vm)
    response = webui.get(DNS_PAGE + "?" + STATUS_QUERY + "&" + selector)
    assert response.status_code == 400, response.text
    assert _config_digest(smoke_vm) == before, "Rejected selector changed config.xml"


@pytest.mark.ui_render
def test_dns_ddr_ajax_requires_the_web_session(webui: WebUI) -> None:
    response = webui.get_unauthenticated(DNS_PAGE + "?" + STATUS_QUERY)
    assert looks_like_login_page(response.text), response.text
    assert "application/json" not in response.headers.get("Content-Type", ""), response.headers
    assert "data-address=" not in response.text, response.text


@pytest.mark.ui_render
def test_dns_ddr_unapplied_saved_name_does_not_replace_applied_name(
    gw: Gateway, gateway_on: State, webui: WebUI
) -> None:
    _ensure_ddr(gw, on=True)
    baseline = _snapshot_html(webui)
    before = {address: row.attrib["data-state"] for address, row in _status_rows(baseline).items()}
    replacement = helpers.unique_domain("ddr-unapplied")
    try:
        _set_lists(gw.vm, {"pfb_dns_name": replacement})
        digest = _config_digest(gw.vm)
        html = _snapshot_html(webui)
        assert _shared_name(html) == _shared_name(baseline), html
        assert {address: row.attrib["data-state"] for address, row in _status_rows(html).items()} == before
        assert _config_digest(gw.vm) == digest, "Status read applied saved intent"
    finally:
        _set_lists(gw.vm, {"pfb_dns_name": DDR_DNS_NAME})


@pytest.mark.ui_render
def test_dns_ddr_disabled_is_not_an_advertisement(gw: Gateway, gateway_on: State, webui: WebUI) -> None:
    _ensure_ddr(gw, on=True)
    assert any(row.attrib["data-state"] == "matched" for row in _status_rows(_snapshot_html(webui)).values())
    try:
        _ensure_ddr(gw, on=False)
        rows = _status_rows(_snapshot_html(webui))
        assert rows and all(row.attrib["data-state"] == "off" for row in rows.values()), rows
    finally:
        _ensure_ddr(gw, on=True)


@pytest.mark.ui_browser
@pytest.mark.parametrize("failure", ["http", "login", "redirect", "json", "shape", "missing", "duplicate", "timeout"])
def test_dns_ddr_failed_refresh_retains_snapshot_then_recovers(
    gw: Gateway, gateway_on: State, browser_page: Page, webui: WebUI, failure: str
) -> None:
    """Tier B: a failed whole refresh retains all overview/listener/DDR values; one later snapshot recovers."""
    _ensure_ddr(gw, on=True)
    page = browser_page
    page.clock.install()
    requests = _track_requests(page)
    _open(page, webui, DNS_PAGE)
    assert not requests, requests
    hops: list[str] = []
    page.on(
        "request",
        lambda request: (
            hops.append(request.url) if STATUS_QUERY in request.url and request.redirected_from is not None else None
        ),
    )
    before = _states(page)
    page.evaluate("window.originalOverview = document.getElementById('pfb-dns-status-overview')")
    duplicate = '<div id="pfb-dns-status"></div>' * 2
    replies = {
        "http": (503, "text/plain", "Unavailable"),
        "login": (200, "text/html", '<form id="unexpected-login"></form>'),
        "json": (200, "application/json", "{"),
        "shape": (200, "application/json", '{"html":7}'),
        "missing": (200, "application/json", json.dumps({"html": "<p>No overview</p>"})),
        "duplicate": (200, "application/json", json.dumps({"html": duplicate})),
    }
    held: list[Route] = []

    def fail(route: Route) -> None:
        if failure == "timeout":
            held.append(route)
        elif failure == "redirect":
            route.fulfill(status=302, headers={"Location": DNS_PAGE + "?ajax=ddr&redirected=1"})
        else:
            status, content_type, body = replies[failure]
            route.fulfill(status=status, content_type=content_type, body=body)

    page.route(ENDPOINT, fail)
    page.clock.run_for(30000)
    if failure == "timeout":
        page.wait_for_function("() => document.getElementById('pfb-dns-status').hasAttribute('aria-busy')")
        page.clock.run_for(15000)
    note = page.locator("#pfb-dns-ddr-refresh-status")
    note.wait_for(state="visible", timeout=JS_TIMEOUT_MS)
    assert len(requests) == 1, requests
    expected_hops = [webui.url(DNS_PAGE + "?ajax=ddr&redirected=1")] if failure == "redirect" else []
    assert hops == expected_hops, hops
    assert len(held) == (1 if failure == "timeout" else 0), held
    assert _states(page) == before, "Failure changed the previous applied snapshot"
    assert page.evaluate("window.originalOverview === document.getElementById('pfb-dns-status-overview')")
    page.unroute(ENDPOINT)
    _poll(page, requests)
    note.wait_for(state="hidden", timeout=JS_TIMEOUT_MS)
    assert _states(page) == before
    count = len(requests)
    page.evaluate("window.dispatchEvent(new PageTransitionEvent('pagehide'))")
    page.clock.run_for(60000)
    assert len(requests) == count, "Polling continued after pagehide"


@pytest.mark.ui_browser
@pytest.mark.parametrize("width", [320, 768, 1024, 1440])
def test_dns_ddr_refresh_replaces_complete_status_preserving_form_and_collapse(
    gw: Gateway, gateway_on: State, browser_page: Page, webui: WebUI, width: int, screenshot_dir: Path
) -> None:
    """One response updates the DNS Name and inventory, not just old State cells; form/collapse/focus survive."""
    _ensure_ddr(gw, on=True)
    page = browser_page
    page.set_viewport_size({"width": width, "height": 900})
    page.clock.install()
    requests = _track_requests(page)
    _open(page, webui, DNS_PAGE)
    assert not requests, requests
    before = _config_digest(gw.vm)
    page.locator("#pfb_dns_name").fill("unsaved-ddr-name.com")
    section = page.locator(f"#{PANEL_ID}")
    body = section.locator(f"#{PANEL_ID}_panel-body")
    toggle = section.get_by_role("link", name="Toggle DDR Advertisements", exact=True)
    toggle.click()
    body.wait_for(state="hidden", timeout=JS_TIMEOUT_MS)
    toggle.focus()
    replacement = _snapshot_html(webui).replace(DDR_DNS_NAME.rstrip("."), "changed.example.com")
    replacement = replacement.replace('data-address="127.0.0.1:53"', 'data-address="127.0.0.9:53"')
    replacement = replacement.replace("<td>127.0.0.1:53</td>", "<td>127.0.0.9:53</td>")
    assert _shared_name(replacement) == "changed.example.com", replacement
    assert 'data-address="127.0.0.9:53"' in replacement, replacement
    page.route(
        ENDPOINT, lambda route: route.fulfill(content_type="application/json", body=json.dumps({"html": replacement}))
    )
    _poll(page, requests)
    assert _shared_name(page.content()) == "changed.example.com", page.content()
    assert "127.0.0.9:53" in _states(page), _states(page)
    assert "127.0.0.1:53" not in _states(page), _states(page)
    assert page.locator("#pfb_dns_name").input_value() == "unsaved-ddr-name.com"
    assert not body.is_visible(), "Refresh expanded a collapsed panel"
    assert toggle.evaluate("el => el === document.activeElement"), "Refresh lost keyboard focus"
    toggle.click()
    body.wait_for(state="visible", timeout=JS_TIMEOUT_MS)
    assert section.locator('tr[data-address="127.0.0.9:53"] td').nth(1).inner_text() == "127.0.0.9:53", (
        section.inner_html()
    )
    dimensions = section.evaluate("""el => ({right: el.getBoundingClientRect().right, width: innerWidth,
        tables: [...el.querySelectorAll('.table-responsive')].map(n => getComputedStyle(n).overflowX)})""")
    assert dimensions["right"] <= dimensions["width"], dimensions
    assert dimensions["tables"] and all(value in ("auto", "scroll") for value in dimensions["tables"]), dimensions
    assert _config_digest(gw.vm) == before, "Browser refresh changed config.xml"
    section.screenshot(path=str(screenshot_dir / f"pfb-dns-ddr-{width}.png"))


@pytest.mark.ui_browser
def test_dns_ddr_snapshot_is_available_after_saving(
    gw: Gateway, gateway_on: State, browser_page: Page, webui: WebUI
) -> None:
    _ensure_ddr(gw, on=True)
    page = browser_page
    with _resolver_address_keys_restored(gw.vm):
        _open(page, webui, DNS_PAGE)
        assert "matched" in _states(page).values(), _states(page)
        with page.expect_navigation(wait_until="domcontentloaded"):
            page.locator('button[type="submit"][name="save"]').click()
        assert page.locator(".input-errors").count() == 0, page.locator("body").inner_text()
        assert "matched" in _states(page).values(), _states(page)


@pytest.mark.ui_render
def test_dns_ddr_applied_snapshot_agrees_with_explicit_directed_dns(
    gw: Gateway, gateway_on: State, webui: WebUI
) -> None:
    """Keep the independent DNS diagnostic: automatic rendering must describe the records actually served."""
    _ensure_ddr(gw, on=True)
    before = _config_digest(gw.vm)
    rows = _status_rows(_snapshot_html(webui))
    observed = helpers.php_eval(
        gw.vm,
        "require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');echo json_encode(pfb_dns_proxy_applied_status());",
    )
    assert observed.returncode == 0, observed.stderr
    match = re.search(r'\{"version":.*\}', observed.stdout)
    assert match, observed.stdout
    applied = json.loads(match.group())
    loopback = gw.vm.ssh("/sbin/ifconfig", "lo0")
    assert loopback.returncode == 0, loopback.stderr
    loopback6 = {
        str(ipaddress.ip_address(address.split("%", 1)[0]))
        for address in re.findall(r"\binet6\s+(\S+)", loopback.stdout)
    }
    checked = 0
    for listener in rows:
        host, _, port = listener.rpartition(":")
        host = str(ipaddress.ip_address(host.strip("[]")))
        if ipaddress.ip_address(host).is_unspecified:
            continue
        source = ("::1" if host in loopback6 else None) if ":" in host else "127.0.0.1"
        result = gw.vm.ssh(
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
        )
        assert result.returncode == 0, f"{listener}: {result.stdout}\n{result.stderr}"
        reply = _parse_reply(result.stdout)
        assert reply.rcode in {"NOERROR", "REFUSED"}, reply.raw
        if reply.rcode == "REFUSED":
            continue  # Applied-state status is not an endpoint/ACL health check.
        actual = []
        for record in _svcb_records(reply):
            alpn = record.params["alpn"]
            actual.append(
                {
                    "priority": record.priority,
                    "target": record.target.rstrip("."),
                    "alpn": alpn,
                    "port": int(record.params.get("port", "443" if alpn == "h2" else "853")),
                    "hint": record.params.get("ipv4hint", record.params.get("ipv6hint")),
                    "path": record.params.get("dohpath", ""),
                }
            )
        expected = applied["advertisements"][host]
        assert actual == sorted(expected["records"], key=lambda record: record["priority"]), reply.raw
        additional = sorted(
            str(ipaddress.ip_address(record.rdata)) for record in reply.additional if record.rtype in {"A", "AAAA"}
        )
        assert additional == sorted(expected["additional"]), reply.raw
        checked += 1
    assert checked > 0, f"No directed DNS response could be checked: {rows}"
    assert _config_digest(gw.vm) == before, "Explicit read-only DNS diagnostic changed config.xml"
