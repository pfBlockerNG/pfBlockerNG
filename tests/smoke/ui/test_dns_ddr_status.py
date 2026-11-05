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
    test_ddr_ajax_dispatch_exits_before_seeding_and_releases_session as _check_dispatch,
)
from .test_dns_ddr_refresh_client import (
    test_periodic_ddr_refresh_replaces_only_results_and_recovers as _check_refresh,
)
from .test_sync_status_panels import panel
from .webui import looks_like_login_page

if TYPE_CHECKING:
    from pathlib import Path

    from playwright.sync_api import Page

    from ..test_smoke_dns_gateway import Gateway
    from ..test_smoke_dns_proxy import State
    from .webui import WebUI

DNS_PAGE = "/pfblockerng/pfblockerng_dns.php"
PANEL_ID = "pfb-dns-status-ddr"


@pytest.mark.ui_browser
@pytest.mark.parametrize("failure", ["timeout", "http", "redirect", "json", "missing", "duplicate"])
def test_dns_ddr_refresh_failure_recovery(failure: str) -> None:
    _check_refresh(failure)


@pytest.mark.ui_render
@pytest.mark.parametrize("method", ["GET", "POST"])
def test_dns_ddr_read_only_dispatch(method: str) -> None:
    _check_dispatch(method)


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
        "require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');echo json_encode(pfb_dns_proxy_listener_list());",
    )
    assert listeners.returncode == 0, listeners.stderr
    match = re.search(r'\{"listening":.*\}', listeners.stdout)
    assert match, listeners.stdout
    bound = json.loads(match.group())["listening"]["udp+tcp"]
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
            assert _svcb_records(reply) == _expected_svcb(DDR_TARGET, doh_443=False, address=host), reply.raw
            assert state in ({"matched", "unverified"} if host in {"127.0.0.1", "::1"} else {"matched"}), ET.tostring(
                row, encoding="unicode"
            )
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
        page.get_by_role("button", name="Save", exact=True).click()
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
    assert page.locator("#pfb_dns_name").input_value() == "unsaved-ddr-name.com"
    assert page.evaluate("window.ddrBody === document.getElementById('pfb-dns-status-ddr_panel-body')")
    assert not body.is_visible(), "refresh expanded the collapsed panel"
    toggle.click()
    body.wait_for(state="visible", timeout=JS_TIMEOUT_MS)
    dimensions = section.evaluate(
        "el => ({right: el.getBoundingClientRect().right, width: innerWidth, "
        "page: document.documentElement.scrollWidth, tables: [...el.querySelectorAll('.table-responsive')]"
        ".map(n => getComputedStyle(n).overflowX)})"
    )
    assert dimensions["right"] <= dimensions["width"], dimensions
    assert dimensions["page"] <= dimensions["width"], dimensions
    assert dimensions["tables"] and all(value in ("auto", "scroll") for value in dimensions["tables"]), dimensions
    assert _config_digest(gw.vm) == before, "browser refresh changed config.xml"
    section.screenshot(path=str(screenshot_dir / f"pfb-dns-ddr-{width}.png"))
