"""Live DDR status observations: reachable render, read-only refresh and browser layout."""

from __future__ import annotations

import hashlib
import ipaddress
import re
import xml.etree.ElementTree as ET
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from ..test_smoke_dns_gateway import (
    DDR_TARGET,
    _ensure_ddr,
    _expected_svcb,
    _parse_reply,
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

if TYPE_CHECKING:
    from playwright.sync_api import Page

    from ..test_smoke_dns_gateway import Gateway
    from ..test_smoke_dns_proxy import State
    from .webui import WebUI

DNS_PAGE = "/pfblockerng/pfblockerng_dns.php"
PANEL_ID = "pfb-dns-status-ddr"


def _records(output: str) -> list[str]:
    """Compare decoded answer records, not changing DNS IDs and query timestamps."""
    section = output.partition(";; ANSWER SECTION:")[2].partition(";; AUTHORITY SECTION:")[0]
    return sorted(" ".join(line.split()) for line in section.splitlines() if line and not line.startswith(";"))


def _config_digest(vm: helpers.SmokeVM) -> str:
    result = vm.ssh("/bin/cat", "/conf/config.xml")
    assert result.returncode == 0, result.stderr
    return hashlib.sha256(result.stdout.encode()).hexdigest()


@pytest.mark.ui_render
def test_dns_ddr_status_refresh_reports_each_actual_listener_without_writing_config(
    gw: Gateway, gateway_on: State, webui: WebUI
) -> None:
    """Each returned observation equals a real local-source drill query at that bound port."""
    _ensure_ddr(gw, on=True)
    before = _config_digest(gw.vm)
    initial = webui.get(DNS_PAGE)
    assert initial.status_code == 200, initial.text
    section = panel(initial.text, PANEL_ID)
    assert section is not None, "pfB-DNS has no DDR Advertisements section"
    assert "Not yet queried" in section and "pfb-dns-ddr-stdout" not in section, section
    assert "Refresh DDR advertisements" in section, section

    listeners = helpers.php_eval(
        gw.vm,
        "require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');echo json_encode(pfb_dns_proxy_listener_list());",
    )
    assert listeners.returncode == 0, listeners.stderr
    import json

    match = re.search(r'\{"listening":.*\}', listeners.stdout)
    assert match, listeners.stdout
    bound = json.loads(match.group())["listening"]["udp+tcp"]
    assert bound, listeners.stdout
    expected = {}
    loopback = gw.vm.ssh("/sbin/ifconfig", "lo0")
    assert loopback.returncode == 0, loopback.stderr
    loopback6 = {
        str(ipaddress.ip_address(address.split("%", 1)[0]))
        for address in re.findall(r"\binet6\s+(\S+)", loopback.stdout)
    }
    expected_rcodes = {}
    for listener in bound:
        host, _, port = listener.rpartition(":")
        host = str(ipaddress.ip_address(host.strip("[]")))
        assert 1 <= int(port) <= 65535, listener
        ipv6 = ":" in host
        source = ("::1" if host in loopback6 else None) if ipv6 else "127.0.0.1"
        arguments = [
            "/usr/bin/timeout",
            "-s",
            "TERM",
            "-k1",
            "3",
            "/usr/bin/drill",
            "-b1232",
            *(["-6"] if ipv6 else []),
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
        assert re.search(r"^;;\s*_dns\.resolver\.arpa\.\s+IN\s+SVCB\s*$", result.stdout, re.MULTILINE), result.stdout
        expected[listener] = _records(result.stdout)
        expected_rcodes[listener] = reply.rcode
        if host in {"127.0.0.1", "::1"}:
            assert reply.rcode == "NOERROR" and _svcb_records(reply) == _expected_svcb(
                DDR_TARGET, doh_443=False, address=host
            ), result.stdout

    refreshed = webui.get(DNS_PAGE + "?refresh_ddr=1&host=203.0.113.99&port=9")
    assert refreshed.status_code == 200, refreshed.text
    section = panel(refreshed.text, PANEL_ID)
    assert section is not None, "refresh lost the DDR section"
    assert re.search(r"Queried: \d{4}-\d{2}-\d{2}", section), section
    table = re.search(r"<table\b.*?</table>", section, re.DOTALL)
    assert table, section
    observations = {}
    for row in ET.fromstring(table.group()).findall("./tbody/tr"):
        cells = row.findall("td")
        address = cells[2].text or ""
        stdout = cells[3].find(".//pre[@class='pfb-dns-ddr-stdout']")
        assert stdout is not None, f"{address}: query output absent: {ET.tostring(row, encoding='unicode')}"
        observations[address] = _records(stdout.text or "")
        assert re.search(r"^;;\s*_dns\.resolver\.arpa\.\s+IN\s+SVCB\s*$", stdout.text or "", re.MULTILINE), stdout.text
        print(f"DDR observed {address}:\n{stdout.text}")
        assert _parse_reply(stdout.text or "").rcode == expected_rcodes[address], stdout.text
        state = cells[3].find("strong")
        expected_state = (
            "Query error"
            if expected_rcodes[address] == "REFUSED"
            else ("Advertised" if expected[address] else "NOERROR, no advertisements")
        )
        assert state is not None and state.text == expected_state, ET.tostring(row, encoding="unicode")
    assert observations == expected, f"bound targets {expected!r}; UI observations {observations!r}"
    assert _config_digest(gw.vm) == before, "read-only DDR refresh changed config.xml"
    assert "203.0.113.99" not in observations, observations
    assert "does not prove" in section and "protocol default" in section, section


@pytest.mark.ui_browser
def test_dns_ddr_status_section_collapses_refreshes_and_scrolls_on_a_phone(
    gw: Gateway, gateway_on: State, browser_page: Page, webui: WebUI
) -> None:
    """The real control refreshes the page and a complete decoded answer stays inside its panel."""
    _ensure_ddr(gw, on=True)
    page = browser_page
    page.set_viewport_size({"width": 390, "height": 844})
    _open(page, webui, DNS_PAGE)
    section = page.locator(f"#{PANEL_ID}")
    assert section.count() == 1, "pfB-DNS has no DDR Advertisements section"
    body = section.locator(f"#{PANEL_ID}_panel-body")
    toggle = section.get_by_role("link", name="Toggle DDR Advertisements", exact=True)
    toggle.click()
    body.wait_for(state="hidden", timeout=JS_TIMEOUT_MS)
    toggle.click()
    body.wait_for(state="visible", timeout=JS_TIMEOUT_MS)
    assert "Not yet queried" in body.inner_text(), body.inner_text()
    before = _config_digest(gw.vm)
    with page.expect_navigation(wait_until="domcontentloaded"):
        section.get_by_role("link", name="Refresh DDR advertisements", exact=True).click()
    section = page.locator(f"#{PANEL_ID}")
    assert "Queried:" in section.inner_text(), section.inner_text()
    raw = section.locator("pre.pfb-dns-ddr-stdout")
    assert raw.count() > 0 and "rcode: NOERROR" in raw.first.inner_text(), section.inner_text()
    assert _config_digest(gw.vm) == before, "browser refresh changed config.xml"
    dimensions = section.evaluate(
        "el => ({right: el.getBoundingClientRect().right, width: innerWidth, "
        "page: document.documentElement.scrollWidth, tables: [...el.querySelectorAll('.table-responsive')]"
        ".map(n => getComputedStyle(n).overflowX), raw: [...el.querySelectorAll('pre')]"
        ".map(n => ({overflow: getComputedStyle(n).overflowX, whiteSpace: getComputedStyle(n).whiteSpace}))})"
    )
    assert dimensions["right"] <= dimensions["width"], dimensions
    assert dimensions["page"] <= dimensions["width"], dimensions
    assert dimensions["tables"] and all(value in ("auto", "scroll") for value in dimensions["tables"]), dimensions
    assert dimensions["raw"] and all(
        value["overflow"] in ("auto", "scroll") and value["whiteSpace"] == "pre" for value in dimensions["raw"]
    ), dimensions
