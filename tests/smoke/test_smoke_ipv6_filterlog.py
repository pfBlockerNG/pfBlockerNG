"""Live-VM smoke (issue #3395): a real pf-logged IPv6 block reaches ip_block.log and Alerts.

civm opens a TCP connection to a public IPv6 victim listed in a logged, floating
Deny_Outbound v6 list. pf blocks the SYN as it enters LAN and logs it, the filterlog
daemon (``pfb_daemon_filterlog``) turns that line into an ip_block.log row, and
``pfblockerng_alerts.php`` renders the row attributed to the list. This is the IPv6 twin
of ``test_syslog_export``'s IPv4 real-filterlog path; the IPv6 Alerts tests in
``tests/smoke/ui/test_alerts.py`` only seed synthetic rows.

The victim is public and never answered. pfSense has an IPv6 default route through SLIRP,
so a temporary blackhole host route keeps a SYN that a regression let through off the
Internet.

DESELECTED from the default ``python -m pytest`` (smoke-only). Run via::

    python -m pytest tests/smoke/test_smoke_ipv6_filterlog.py -m smoke --override-ini="addopts="

Needs the booted ``smoke_vm`` + ``client_vm`` (civm) fixtures and the branch ``.pkg``
(``SMOKE_PKG``); without these the cases skip cleanly. The Alerts case also needs the
webConfigurator login (``SMOKE_ADMIN_PASSWORD``, optional ``SMOKE_ADMIN_USER``) and skips
without it; CI sets it, and the smoke job's skip allowlist fails an unlisted skip.
"""

from __future__ import annotations

import csv
import ipaddress
import os
import re

import pytest

from . import helpers as h
from .conftest import SmokeVM
from .test_syslog_export import _enable_ip_floating_logged_rule, _filterlog_pid
from .ui.credgate import ADMIN_PASSWORD_ENV
from .ui.webui import WebUI, looks_like_login_page, row_containing

pytestmark = pytest.mark.smoke

# Public (never ULA or the fec0::/64 WAN on-link net, which pfb_collect_localip counts as
# local) and never answered.
VICTIM = "2606:4700:7777::1111"
VICTIM_PORT = 80
FILTER_LOG = "/var/log/filter.log"
# Salvage cap only: the poll returns as soon as the row lands.
ROW_WAIT_SECS = 60.0
ALERTS_PAGE = "/pfblockerng/pfblockerng_alerts.php"
# convert_ip_log() puts the attributed external host, raw, in this href; the SRC/DST cells
# bracket IPv6 and add a zero-width space after every colon, so only the href is matchable.
THREAT_HOST_HREF = re.compile(r'/pfblockerng/pfblockerng_threats\.php\?host=([^"&]+)')


@pytest.fixture(scope="module")
def v6_deny_list(smoke_vm: SmokeVM) -> h.IpCase:
    """Deploy, then list VICTIM in a logged, floating Deny_Outbound v6 list on LAN; full reload."""
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    feed = h.write_local_feed(smoke_vm, "pfb_v6filterlog.txt", f"{VICTIM}/128\n")
    case = h.IpCase(
        aliasname="pfb_v6filterlog", feed_url=feed, action="Deny_Outbound", family="v6", header="pfb_v6filterlog"
    )
    h.inject(smoke_vm, case)
    _enable_ip_floating_logged_rule(smoke_vm)
    h.reload(smoke_vm, "update")
    members = h.pfctl_table_members(smoke_vm, case.alias)
    if not h.ip_in(VICTIM, [m.split("/", 1)[0] for m in members]):
        raise RuntimeError(f"precondition: expected {VICTIM} in {case.alias}, got {members}")
    return case


@pytest.fixture(autouse=True)
def _empty_ip_block_log(v6_deny_list: h.IpCase, smoke_vm: SmokeVM) -> None:
    """Every test starts from an empty ip_block.log, so no victim row survives from a sibling."""
    smoke_vm.ssh(f": > {h.IP_BLOCK_LOG}", timeout=30)
    left = h.read_log_file(smoke_vm, h.IP_BLOCK_LOG)
    assert left == "", f"ip_block.log reset did not take: expected empty, got {left[-400:]!r}"


@pytest.fixture(scope="module")
def alerts_ui(smoke_vm: SmokeVM) -> WebUI:
    """A logged-in webConfigurator session; skips on a box without the admin password."""
    password = os.environ.get(ADMIN_PASSWORD_ENV)
    if not password:
        pytest.skip(f"{ADMIN_PASSWORD_ENV} not set: the Alerts page needs the webConfigurator login")
    ui = WebUI(smoke_vm.host, smoke_vm.web_port, os.environ.get("SMOKE_ADMIN_USER") or "admin", password)
    ui.login()
    return ui


def _victim_rows(vm: SmokeVM) -> list[list[str]]:
    """ip_block.log rows whose source or destination is VICTIM, compared by value."""
    rows = csv.reader(h.read_log_file(vm, h.IP_BLOCK_LOG).splitlines())
    return [row for row in rows if h.ip_in(VICTIM, row[8:10])]


def _set_victim_blackhole(vm: SmokeVM, *, present: bool) -> None:
    """Add or delete pfSense's blackhole host route for VICTIM."""
    args = ("add", "-host", VICTIM, "::1", "-blackhole") if present else ("delete", "-host", VICTIM)
    res = vm.ssh("/sbin/route", "-6", *args, timeout=30)
    if res.returncode != 0:
        raise RuntimeError(f"route -6 {' '.join(args)} failed: rc={res.returncode} {res.stdout!r} {res.stderr!r}")


def _connect_victim(client_vm: SmokeVM) -> None:
    """civm opens a TCP connection to VICTIM; it never completes (blocked, and blackholed past pf)."""
    url = f"http://[{VICTIM}]:{VICTIM_PORT}/"
    client_vm.ssh("curl", "-g", "-o", "/dev/null", "--connect-timeout", "2", "--max-time", "4", url, timeout=30)


def _wait_victim_rows(vm: SmokeVM, case: h.IpCase, src: str) -> list[list[str]]:
    """Completion barrier: the victim's ip_block.log rows, once the daemon has written one."""
    rows: list[list[str]] = []

    def logged() -> bool:
        nonlocal rows
        rows = _victim_rows(vm)
        return bool(rows)

    try:
        h.wait_until(logged, timeout=ROW_WAIT_SECS, interval=1.0)
    except RuntimeError:
        pf_lines = [ln for ln in h.read_log_file(vm, FILTER_LOG).splitlines() if VICTIM in ln]
        raise AssertionError(
            f"salvage cap expired / stuck or environment: expected an ip_block.log row for {VICTIM} "
            f"from {src}, got none.\n  filter.log lines for the victim (last 5): {pf_lines[-5:]}\n"
            f"  {case.alias}: {h.pfctl_table_members(vm, case.alias)}"
        ) from None
    return rows


def _block_victim(vm: SmokeVM, client_vm: SmokeVM, case: h.IpCase) -> tuple[str, list[str]]:
    """civm, route-pinned via pfSense's LAN IPv6, connects to VICTIM: returns (civm's source, the row).

    Asserts first that ip_block.log holds no VICTIM row. VICTIM stays blackholed on pfSense
    throughout, so a SYN a regression let through never leaves the lab.
    """
    lan6 = h.get_lan_ipv6(vm)
    _filterlog_pid(vm)
    _set_victim_blackhole(vm, present=True)
    try:
        src = h.pin_client_route6(client_vm, VICTIM, lan6)
        try:
            before = _victim_rows(vm)
            assert before == [], f"ip_block.log before the probe: expected no row for {VICTIM}, got {before}"
            _connect_victim(client_vm)
            return src, _wait_victim_rows(vm, case, src)[0]
        finally:
            h.unpin_client_route6(client_vm, VICTIM)
    finally:
        _set_victim_blackhole(vm, present=False)


def _row_fields(row: list[str]) -> dict[str, object]:
    """The ip_block.log fields the Alerts page attributes an IPv6 outbound block by."""

    def addr(text: str) -> object:
        try:
            return ipaddress.ip_address(text)
        except ValueError:
            return text

    col = row + [""] * (15 - len(row))
    return {
        "fields": len(row),
        "action": col[4],
        "ip_version": col[5],
        "src": addr(col[8]),
        "dst": addr(col[9]),
        "direction": col[12],
        "alias": col[14],
    }


def _alerts_html(ui: WebUI) -> str:
    """The logged-in Alerts page body."""
    resp = ui.get(ALERTS_PAGE)
    assert resp.status_code == 200 and not looks_like_login_page(resp.text), (
        f"GET {ALERTS_PAGE}: expected the logged-in page at HTTP 200, got HTTP {resp.status_code} "
        f"(login form: {looks_like_login_page(resp.text)})"
    )
    return resp.text


def _victim_threat_links(html: str) -> list[str]:
    """The page's threat-lookup hrefs whose host is VICTIM, compared by value."""
    return [m.group(0) for m in THREAT_HOST_HREF.finditer(html) if h.ip_in(VICTIM, [m.group(1)])]


def test_real_ipv6_block_reaches_ip_block_log(smoke_vm: SmokeVM, client_vm: SmokeVM, v6_deny_list: h.IpCase) -> None:
    """Issue #3395 row D1: pf's logged IPv6 block becomes an attributed ip_block.log row.

    Given a logged, floating Deny_Outbound v6 list holding VICTIM on LAN, the filterlog daemon
      running, and civm's route to VICTIM pinned via pfSense's LAN IPv6,
      And ip_block.log holding no row for VICTIM,
    When civm opens a TCP connection to VICTIM,
    Then a 23-field IPv6 ``block`` row lands with direction ``out``, VICTIM as the
      destination (the external host), civm's pinned IPv6 as the source, and the list's alias.
    """
    src, row = _block_victim(smoke_vm, client_vm, v6_deny_list)
    want = {
        "fields": 23,
        "action": "block",
        "ip_version": "6",
        "src": ipaddress.ip_address(src),
        "dst": ipaddress.ip_address(VICTIM),
        "direction": "out",
        "alias": v6_deny_list.alias,
    }
    got = _row_fields(row)
    assert got == want, f"ip_block.log row for {VICTIM}: expected {want}, got {got}; row={row}"


def test_real_ipv6_block_renders_on_alerts_page(
    smoke_vm: SmokeVM, client_vm: SmokeVM, v6_deny_list: h.IpCase, alerts_ui: WebUI
) -> None:
    """Issue #3395 row D2: the Alerts page shows the real IPv6 block, attributed to the list.

    Given D1's list and route pin, and an Alerts page with no threat-lookup link for VICTIM,
    When civm's blocked connection to VICTIM lands in ip_block.log,
    Then the Alerts page shows VICTIM as a row's threat-lookup host, and that row names the
      list's alias.
    """
    before = _victim_threat_links(_alerts_html(alerts_ui))
    assert before == [], f"Alerts before the probe: expected no threat link for {VICTIM}, got {before}"
    _block_victim(smoke_vm, client_vm, v6_deny_list)
    html = _alerts_html(alerts_ui)
    links = _victim_threat_links(html)
    assert links, (
        f"Alerts after the probe: expected a threat link for {VICTIM}, got hosts {THREAT_HOST_HREF.findall(html)}"
    )
    row = row_containing(html, links[0])
    assert v6_deny_list.alias in row, f"Alerts row for {VICTIM}: expected alias {v6_deny_list.alias!r}, got {row!r}"
