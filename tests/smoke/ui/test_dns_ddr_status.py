"""Live DDR page checks: automatic semantic results, read-only polling and preserved form state."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import xml.etree.ElementTree as ET
from typing import TYPE_CHECKING

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
from .test_dns_ddr_refresh_client import (
    test_periodic_ddr_refresh_replaces_only_results_and_recovers as _check_refresh,
)
from .test_sync_status_panels import panel
from .webui import CSRF_FIELD, extract_csrf_token, looks_like_login_page

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from playwright.sync_api import Page

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


@pytest.mark.ui_browser
@pytest.mark.parametrize("failure", ["timeout", "http", "redirect", "json", "missing", "duplicate"])
def test_dns_ddr_refresh_failure_recovery(failure: str) -> None:
    _check_refresh(failure)


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
        response = webui.session.post(webui.url(url), data={CSRF_FIELD: token}, timeout=30)
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
                overflow: [...document.querySelectorAll('body *')].filter(n =>
                    n.getClientRects().length && n.getBoundingClientRect().right > innerWidth &&
                    !n.closest('.table-responsive')).slice(0, 12).map(n =>
                    ({tag: n.tagName, id: n.id, classes: n.className, right: n.getBoundingClientRect().right})),
                tables: [...el.querySelectorAll('.table-responsive')].map(n => getComputedStyle(n).overflowX)};
        }"""
    )
    assert dimensions["right"] <= dimensions["width"], dimensions
    assert dimensions["page"] <= dimensions["width"], dimensions
    assert dimensions["tables"] and all(value in ("auto", "scroll") for value in dimensions["tables"]), dimensions
    assert _config_digest(gw.vm) == before, "browser refresh changed config.xml"
    section.screenshot(path=str(screenshot_dir / f"pfb-dns-ddr-{width}.png"))
