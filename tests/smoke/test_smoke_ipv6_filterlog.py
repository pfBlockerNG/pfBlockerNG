"""Live-VM smoke (issue #3395): a real pf-logged IPv6 block reaches ip_block.log in the Alerts shape.

civm opens a TCP connection to a public IPv6 victim listed in a logged, floating
Deny_Outbound v6 list. pf blocks the SYN as it enters LAN and logs it, and the filterlog
daemon (``pfb_daemon_filterlog``) turns that line into an ip_block.log row matching
``ui/test_alerts.py``'s ``_ipv6_alert_seed_fields`` layout: the synthetic row
``test_ipv6_alert_external_host_attribution`` proves the Alerts page renders. This is the
IPv6 twin of ``test_syslog_export``'s IPv4 real-filterlog path.

The victim is public and never answered. pfSense has an IPv6 default route through SLIRP,
so a temporary blackhole host route keeps a SYN that a regression let through off the
Internet.

DESELECTED from the default ``python -m pytest`` (smoke-only). Run via::

    python -m pytest tests/smoke/test_smoke_ipv6_filterlog.py -m smoke --override-ini="addopts="

Needs the booted ``smoke_vm`` + ``client_vm`` (civm) fixtures and the branch ``.pkg``
(``SMOKE_PKG``); without these the cases skip cleanly.
"""

from __future__ import annotations

import csv
import ipaddress
import os

import pytest

from . import helpers as h
from .conftest import SmokeVM
from .test_syslog_export import _enable_ip_floating_logged_rule, _filterlog_pid
from .ui.test_alerts import _ipv6_alert_seed_fields

pytestmark = pytest.mark.smoke

# Public (never ULA or the fec0::/64 WAN on-link net, which pfb_collect_localip counts as
# local) and never answered.
VICTIM = "2606:4700:7777::1111"
VICTIM_PORT = 80
FILTER_LOG = "/var/log/filter.log"
# Salvage cap only: the poll returns as soon as the row lands. It stays under run-smoke.sh's
# 30 s per-test timeout so the salvage diagnostic prints instead of a bare pytest-timeout.
ROW_WAIT_SECS = 15.0


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
    h.apply_filter_sync(smoke_vm)
    members = h.pfctl_table_members(smoke_vm, case.alias)
    if not h.ip_in(VICTIM, [m.split("/", 1)[0] for m in members]):
        raise RuntimeError(f"precondition: expected {VICTIM} in {case.alias}, got {members}")
    return case


@pytest.fixture(autouse=True)
def _empty_ip_block_log(v6_deny_list: h.IpCase, smoke_vm: SmokeVM) -> None:
    """Every test starts from an empty ip_block.log, so no victim row survives from a sibling."""
    res = smoke_vm.ssh(f": > {h.IP_BLOCK_LOG}", timeout=30)
    assert res.returncode == 0, f"ip_block.log reset: expected rc 0, got rc={res.returncode} {res.stderr!r}"
    left = h.read_log_file(smoke_vm, h.IP_BLOCK_LOG)
    assert left == "", f"ip_block.log reset did not take: expected empty, got {left[-400:]!r}"


def _victim_rows(vm: SmokeVM) -> list[list[str]]:
    """ip_block.log rows naming VICTIM in any column (by value), so a misplaced column still shows."""
    rows = csv.reader(h.read_log_file(vm, h.IP_BLOCK_LOG).splitlines())
    return [row for row in rows if h.ip_in(VICTIM, row)]


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


def _alerts_shape(row: list[str], seed: dict[str, str]) -> dict[str, object]:
    """Map the real row with the field order used by the Alerts test's synthetic seed."""

    def addr(text: str | None) -> object:
        try:
            return ipaddress.ip_address(text or "")
        except ValueError:
            return text

    named = dict(zip(seed, row))
    return {
        "fields": len(row),
        "action": named.get("action"),
        "ipv": named.get("ipv"),
        "src_ip": addr(named.get("src_ip")),
        "dst_ip": addr(named.get("dst_ip")),
        "dir": named.get("dir"),
        "alias": named.get("alias"),
    }


def test_real_ipv6_block_reaches_ip_block_log(smoke_vm: SmokeVM, client_vm: SmokeVM, v6_deny_list: h.IpCase) -> None:
    """Issue #3395 rows D1+D2: pf's logged IPv6 block becomes an ip_block.log row in the Alerts shape.

    Given a logged, floating Deny_Outbound v6 list holding VICTIM on LAN, the filterlog daemon
      running, and civm's route to VICTIM pinned via pfSense's LAN IPv6,
      And ip_block.log holding no row for VICTIM,
    When civm opens a TCP connection to VICTIM,
    Then a ``block`` row lands in the layout the Alerts IPv6 attribution test seeds:
      all 23 fields, family 6, direction ``out``, VICTIM in the ``dst_ip`` column the page
      reads an outbound external host from, civm's pinned IPv6 in ``src_ip`` (the local
      host), and the list's alias.
    """
    vm = smoke_vm
    lan6 = h.get_lan_ipv6(vm)
    _filterlog_pid(vm)
    _set_victim_blackhole(vm, present=True)
    try:
        src = h.pin_client_route6(client_vm, VICTIM, lan6)
        try:
            before = _victim_rows(vm)
            assert before == [], f"ip_block.log before the probe: expected no row for {VICTIM}, got {before}"
            _connect_victim(client_vm)
            row = _wait_victim_rows(vm, v6_deny_list, src)[0]
        finally:
            h.unpin_client_route6(client_vm, VICTIM)
    finally:
        _set_victim_blackhole(vm, present=False)

    seed = _ipv6_alert_seed_fields("", src, VICTIM, "out", VICTIM)
    want = {
        "fields": len(seed),
        "action": seed["action"],
        "ipv": seed["ipv"],
        "src_ip": ipaddress.ip_address(seed["src_ip"]),
        "dst_ip": ipaddress.ip_address(seed["dst_ip"]),
        "dir": seed["dir"],
        "alias": v6_deny_list.alias,
    }
    got = _alerts_shape(row, seed)
    assert got == want, f"ip_block.log row for {VICTIM}: expected {want}, got {got}; row={row}"
