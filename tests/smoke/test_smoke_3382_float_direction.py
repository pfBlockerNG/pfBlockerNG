"""Live-VM smoke (issue #3382): floating auto-rules are direction ``in``, and the opt-in
firewall-traffic twin covers the firewall's own outbound connections.

Real two-VM pfSense CE setup (civm = the LAN client behind the firewall). The victim is
the runner's WAN-subnet host alias (``192.168.89.2``): it answers HTTP for the mock feed
server, so "blocked" is a real reachable -> unreachable transition, not an inert address.

  1. Deny Outbound blocks the client's egress when the Outbound interface is the client-facing
     LAN, with floating ON (the regression: the rule was pinned to ``out`` and never saw
     traffic ENTERING LAN) and OFF (the control: an interface rule was always ``in``). With
     WAN as the Outbound interface and floating ON it must NOT block (the documented
     behaviour change: the old ``out`` rule on WAN did).
  2. A Deny Inbound alias on WAN that holds the firewall's WAN (post-NAT) address must not
     touch the client's egress: only a floating rule left at direction ``any`` would.
  3. 'Apply outbound rules to firewall traffic': with WAN as the Inbound interface, the
     firewall's own ``fetch`` to a Deny Outbound address is blocked by the ``out`` twin
     (source ``(self)``); with the toggle OFF pfBlockerNG leaves it alone.

DESELECTED from the default ``python -m pytest`` (smoke-only). Run via::

    python -m pytest tests/smoke/test_smoke_3382_float_direction.py -m smoke --override-ini="addopts="

Needs the booted ``smoke_vm`` + ``client_vm`` (civm) fixtures and the branch ``.pkg``
(``SMOKE_PKG``); without these the cases skip cleanly.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterator
from itertools import pairwise

import pytest

from . import helpers as h
from .conftest import GUEST_TO_HOST_ALIAS, PFSENSE_LAN_IP, SmokeVM, _MockFeedServer, _StubDnsServer

pytestmark = pytest.mark.smoke

CFG_IP_SETTINGS = "installedpackages/pfblockerngipsettings/config/0"

# The runner's WAN-subnet host alias: reachable from civm (LAN -> NAT -> WAN) and from
# pfSense itself, and it hosts the mock feed server the probes fetch.
VICTIM = GUEST_TO_HOST_ALIAS
# RFC 5737 TEST-NET-3: keeps a rule's alias non-empty while the victim is NOT yet in it.
DUMMY = "203.0.113.77"
PROBE_NAME = "pfb3382_probe.txt"


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _set_ipcfg(vm: SmokeVM, kv: dict[str, str], *, timeout: float = 60.0) -> None:
    """Merge key=value pairs into the pfBlockerNG IP settings section + write_config."""
    sets = "".join(f"$ip[{h._php_str(k)}] = {h._php_str(v)};\n" for k, v in kv.items())
    snippet = (
        f"$ip = config_get_path({h._php_str(CFG_IP_SETTINGS)}, array());\n{sets}"
        f"config_set_path({h._php_str(CFG_IP_SETTINGS)}, $ip);\n"
        "write_config('pfBlockerNG smoke: #3382 ipcfg');\necho 'OK';"
    )
    r = h.php_eval(vm, snippet, timeout=timeout)
    if r.returncode != 0 or "OK" not in r.stdout:
        raise RuntimeError(f"_set_ipcfg failed: rc={r.returncode} {r.stderr!r} {r.stdout!r}")


def _wire(
    vm: SmokeVM,
    header: str,
    action: str,
    victims: tuple[str, ...],
    *,
    inbound: str,
    outbound: str,
    float_on: bool,
    fw_self: bool,
) -> h.IpCase:
    """Wire ONE IP list (alias ``pfB_<header>_v4``) + the full rule-shaping settings, then update.

    Every setting the scenario depends on is written explicitly, so no case inherits a
    sibling's interface/float/toggle state. The package's own filter reload is detached, so
    every rule-changing update here is followed by a blocking ``apply_filter_sync``.
    """
    feed = h.write_local_feed(vm, f"{header}.txt", "".join(f"{ip}/32\n" for ip in victims))
    case = h.IpCase(aliasname=header, feed_url=feed, action=action, family="v4", header=header)
    h.inject(vm, case)
    _set_ipcfg(
        vm,
        {
            "inbound_interface": inbound,
            "outbound_interface": outbound,
            "enable_float": "on" if float_on else "",
            "fw_self_outbound": "on" if fw_self else "",
            "enable_log": "on",
        },
    )
    h.reload(vm, "update")
    h.apply_filter_sync(vm)
    return case


def _add_victim(vm: SmokeVM, case: h.IpCase, victims: tuple[str, ...]) -> None:
    """Change the alias CONTENT only (the rule already exists), then update."""
    h.write_local_feed(vm, f"{case.header}.txt", "".join(f"{ip}/32\n" for ip in victims))
    h.force_ip_refetch(vm, f"{case.header}_v4")
    h.reload(vm, "update")


def _rule_packets(vm: SmokeVM, alias: str, direction: str, *, timeout: float = 30.0) -> int:
    """Packets matched by the pf rule for ``alias`` in ``direction``; -1 if no such rule is loaded.

    ``pfctl -sr -vv`` prints each rule, then ``[ Evaluations: N Packets: M ... ]``. Reading M
    before/after a probe proves THAT rule saw the traffic, not merely that it exists.
    """
    lines = vm.ssh("/bin/sh", "-c", "pfctl -sr -vv 2>/dev/null", timeout=timeout).stdout.splitlines()
    rule = re.compile(rf"^@\d+ \w+(?: \w+)? {direction}\b")
    # -vv prints a table as <name:count>; anchor the name so a prefix-sharing alias cannot match.
    table = re.compile(rf"<{re.escape(alias)}[:>]")
    counters = [
        int(m.group(1))
        for line, nxt in pairwise(lines)
        if rule.match(line) and table.search(line) and (m := re.search(r"Packets: (\d+)", nxt))
    ]
    return sum(counters) if counters else -1


def _civm_fetch_ok(cl: SmokeVM, url: str, *, timeout: float = 30.0) -> bool:
    """True iff civm fetched ``url`` THROUGH pfSense (host route pinned to the LAN gateway)."""
    host = url.split("/")[2].split(":")[0]
    r = cl.ssh(
        "/bin/sh",
        "-c",
        f"dev=$(ip -4 -o addr show | awk '/192\\.168\\.1\\./{{print $2; exit}}'); "
        f'ip route replace {host}/32 via {PFSENSE_LAN_IP} dev "$dev" 2>/dev/null || true; '
        f"curl -sf -o /dev/null --connect-timeout 3 --max-time 5 {url}; echo rc=$?",
        timeout=timeout,
    )
    return "rc=0" in r.stdout


def _firewall_fetch_ok(vm: SmokeVM, url: str, *, timeout: float = 30.0) -> bool:
    """True iff the firewall ITSELF fetched ``url`` (a locally originated connection)."""
    r = vm.ssh("/bin/sh", "-c", f"fetch -q -T 5 -o /dev/null {url}; echo rc=$?", timeout=timeout)
    return "rc=0" in r.stdout


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def deployed_vm(smoke_vm: SmokeVM, client_vm: SmokeVM, stub_dns: _StubDnsServer) -> Iterator[SmokeVM]:
    """Deploy the branch .pkg once; every case wires its own rules (see :func:`_wire`)."""
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    h.use_system_dns_upstream(smoke_vm)
    yield smoke_vm


@pytest.fixture
def probe_url(mock_feeds: _MockFeedServer) -> str:
    """A URL on the victim host that answers 200 while nothing blocks it."""
    return mock_feeds.register(PROBE_NAME, "pfb3382\n")


# --------------------------------------------------------------------------- #
# 1. Client egress is blocked by a Deny Outbound rule on the CLIENT-facing interface only
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("outbound", "float_on", "blocked"),
    [("lan", True, True), ("lan", False, True), ("wan", True, False)],
    ids=["lan-floating-on", "lan-floating-off", "wan-floating-on"],
)
def test_deny_outbound_blocks_client_egress_only_on_the_client_facing_interface(
    deployed_vm: SmokeVM, client_vm: SmokeVM, probe_url: str, outbound: str, float_on: bool, blocked: bool
) -> None:
    """Scenario: Deny Outbound with LAN, or WAN, as the Outbound interface.

    Given the alias does not yet hold the victim, civm reaches it (before-state).
    When  the victim joins the alias and pfBlockerNG updates.
    Then  on LAN civm can no longer reach it and the rule's packet counter moved — the rule is
          direction ``in`` there, where client egress enters, with floating on AND off.
    And   on WAN with floating on civm still reaches it and the counter did not move: the
          rule is ``in`` on an interface the egress only LEAVES (the old ``out`` rule blocked it).
    """
    vm = deployed_vm
    header = f"pfb3382{outbound}{'fl' if float_on else 'if'}"
    case = _wire(
        vm,
        header,
        "Deny_Outbound",
        (DUMMY,),
        inbound=h.SMOKE_IP_IFACE,
        outbound=outbound,
        float_on=float_on,
        fw_self=False,
    )
    where = f"outbound={outbound} float_on={float_on}"

    assert _civm_fetch_ok(client_vm, probe_url), (
        f"before: civm must reach {probe_url} while {VICTIM} is not in {case.alias} ({where})"
    )
    counter_before = _rule_packets(vm, case.alias, "in")
    assert counter_before >= 0, f"no direction-in rule for {case.alias} is loaded ({where})"

    _add_victim(vm, case, (DUMMY, VICTIM))
    members = {m.split("/")[0] for m in h.pfctl_table_members(vm, case.alias)}
    assert VICTIM in members, f"{VICTIM} is not in {case.alias} after the update: {sorted(members)} ({where})"

    reached = _civm_fetch_ok(client_vm, probe_url)
    counter_after = _rule_packets(vm, case.alias, "in")
    if blocked:
        assert not reached, f"civm still reached {probe_url} with {VICTIM} in {case.alias} ({where})"
        assert counter_after > counter_before, (
            f"the direction-in rule for {case.alias} never matched the client's egress "
            f"(before={counter_before}, after={counter_after}, {where})"
        )
    else:
        assert reached, (
            f"civm could not reach {probe_url}: the WAN rule blocked egress that only LEAVES WAN, "
            f"as the old direction-out rule did ({where})"
        )
        assert counter_after == counter_before, (
            f"the direction-in rule on {outbound} matched the client's egress "
            f"(before={counter_before}, after={counter_after}, {where})"
        )


# --------------------------------------------------------------------------- #
# 2. A WAN Deny Inbound rule must not over-match the client's post-NAT egress
# --------------------------------------------------------------------------- #


def test_deny_inbound_on_wan_does_not_match_client_egress(
    deployed_vm: SmokeVM, client_vm: SmokeVM, probe_url: str
) -> None:
    """Scenario: floating Deny Inbound on WAN whose alias holds the firewall's WAN address.

    Given civm's egress leaves WAN with the WAN address as its post-NAT source.
    When  a floating Deny Inbound rule on WAN lists that address as a blocked SOURCE.
    Then  civm still reaches an unrelated address and the rule saw no packet — a floating
          rule left at direction ``any`` would match the outbound leg and cut the client off.
    """
    vm = deployed_vm
    wan_ip = h.get_live_ipv4(vm, "wan")
    assert wan_ip, "the firewall has no WAN IPv4 to use as the post-NAT source"
    case = _wire(
        vm, "pfb3382overmatch", "Deny_Inbound", (wan_ip,), inbound="wan", outbound="lan", float_on=True, fw_self=False
    )

    counter_before = _rule_packets(vm, case.alias, "in")
    assert counter_before >= 0, f"no direction-in rule for {case.alias} is loaded"
    members = {m.split("/")[0] for m in h.pfctl_table_members(vm, case.alias)}
    assert wan_ip in members, f"the WAN address {wan_ip} is not in {case.alias}: {sorted(members)}"

    assert _civm_fetch_ok(client_vm, probe_url), (
        f"civm could not reach {probe_url}: the WAN Deny Inbound rule over-matched its post-NAT egress"
    )
    counter_after = _rule_packets(vm, case.alias, "in")
    assert counter_after == counter_before, (
        f"the WAN Deny Inbound rule matched the client's outbound leg (before={counter_before}, after={counter_after})"
    )


# --------------------------------------------------------------------------- #
# 3. 'Apply outbound rules to firewall traffic' covers the firewall's own connections
# --------------------------------------------------------------------------- #


def test_fw_self_outbound_blocks_the_firewalls_own_connection(deployed_vm: SmokeVM, probe_url: str) -> None:
    """Scenario: Deny Outbound + the firewall-traffic toggle, WAN as the Inbound interface.

    Given the toggle is OFF, the firewall's own fetch of the victim succeeds and no ``out``
          rule exists (pfBlockerNG leaves locally originated traffic alone).
    When  the toggle is turned ON and pfBlockerNG updates.
    Then  the same fetch is blocked and the ``out`` twin's packet counter moved.
    """
    vm = deployed_vm
    case = _wire(
        vm, "pfb3382self", "Deny_Outbound", (VICTIM,), inbound="wan", outbound="lan", float_on=True, fw_self=False
    )

    assert _rule_packets(vm, case.alias, "out") == -1, "before: no out rule may exist with the toggle OFF"
    assert _firewall_fetch_ok(vm, probe_url), (
        f"before: the firewall must reach {probe_url} while the toggle is OFF (pfBlockerNG does not filter it)"
    )

    try:
        _set_ipcfg(vm, {"fw_self_outbound": "on"})
        h.reload(vm, "update")
        h.apply_filter_sync(vm)

        counter_before = _rule_packets(vm, case.alias, "out")
        assert counter_before >= 0, f"no out twin for {case.alias} is loaded with the toggle ON"
        assert not _firewall_fetch_ok(vm, probe_url), (
            f"the firewall still reached {probe_url} with the toggle ON and {VICTIM} in {case.alias}"
        )
        counter_after = _rule_packets(vm, case.alias, "out")
        assert counter_after > counter_before, (
            f"the out twin never matched the firewall's own connection (before={counter_before}, after={counter_after})"
        )
    finally:
        # The twin cuts the firewall off from the runner host (feeds, stub DNS): never leave it on.
        _set_ipcfg(vm, {"fw_self_outbound": ""})
        h.reload(vm, "update")
        h.apply_filter_sync(vm)
