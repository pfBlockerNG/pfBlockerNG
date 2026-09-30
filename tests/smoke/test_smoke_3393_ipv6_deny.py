"""Live-VM smoke (issue #3393): pfBlockerNG IPv6 deny rules drop real IPv6 packets.

Real two-VM pfSense CE setup (civm = the LAN client behind the firewall). The victim is
``fec0::9``, an unassigned address inside the WAN's on-link ``fec0::/64``: nothing answers, so
"blocked" is read from pf itself — the deny rule's packet counter moving and no state forming
for the probe's destination port — never from an application result.

  1. A v6 Deny Outbound alias (floating ON and OFF) and a v6 Deny Both alias (its outbound leg)
     drop civm's egress toward a listed victim; the same victim unlisted is forwarded, so the
     counter moving is the listing's doing. A rule rendered ``inet`` never sees an IPv6 packet.
  2. 'Apply outbound rules to firewall traffic' adds the ``out`` twin (source ``(self)``) for a v6
     Deny Outbound alias: the firewall's own connection is forwarded with the toggle OFF and
     dropped with it ON.

DESELECTED from the default ``python -m pytest`` (smoke-only). Run via::

    python -m pytest tests/smoke/test_smoke_3393_ipv6_deny.py -m smoke --override-ini="addopts="

Needs the booted ``smoke_vm`` + ``client_vm`` (civm) fixtures and the branch ``.pkg``
(``SMOKE_PKG``); without these the cases skip cleanly.
"""

from __future__ import annotations

import ipaddress
import itertools
import re
from collections.abc import Iterator

import pytest

from . import helpers as h
from .conftest import SmokeVM
from .test_smoke_3382_float_direction import _rule_packets, _set_ipcfg
from .test_smoke_3382_float_direction import deployed_vm as deployed_vm

pytestmark = pytest.mark.smoke

# Unassigned address inside pfSense WAN's on-link SLIRP fec0::/64, nothing answers: the IPv6
# analogue of 192.168.89.9.
VICTIM = "fec0::9"
# RFC 3849 documentation address: keeps the alias non-empty while the victim is not in it.
DUMMY = "2001:db8::77"
ALIAS_PREFIX = "pfB_pfb3393"
_VICTIM_ADDR = ipaddress.IPv6Address(VICTIM)
# A fresh destination port per probe: a state left by an earlier probe never matches the next.
_PORTS = itertools.count(18300)
# ``pfctl -ss`` prints IPv6 endpoints as ``addr[port]`` (NAT'd lines add a parenthesised second one).
_ENDPOINT = re.compile(r"([0-9A-Fa-f:]+)\[(\d+)\]")


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _wire6(
    vm: SmokeVM, header: str, action: str, victims: tuple[str, ...], *, float_on: bool, fw_self: bool
) -> h.IpCase:
    """Wire ONE v6 IP list (alias ``pfB_<header>_v6``) + the full rule-shaping settings, then update.

    Every setting the scenario depends on is written explicitly, so no case inherits a
    sibling's interface/float/toggle state.
    """
    feed = h.write_local_feed(vm, f"{header}.txt", "".join(f"{ip}/128\n" for ip in victims))
    case = h.IpCase(aliasname=header, feed_url=feed, action=action, family="v6", header=header)
    h.inject(vm, case)
    _set_ipcfg(
        vm,
        {
            "inbound_interface": "wan",
            "outbound_interface": "lan",
            "enable_float": "on" if float_on else "",
            "fw_self_outbound": "on" if fw_self else "",
            "enable_log": "on",
        },
    )
    h.reload(vm, "update")
    return case


def _add_victim6(vm: SmokeVM, case: h.IpCase, victims: tuple[str, ...]) -> None:
    """Change the alias CONTENT only (the rule already exists), then update."""
    h.write_local_feed(vm, f"{case.header}.txt", "".join(f"{ip}/128\n" for ip in victims))
    h.force_ip_refetch(vm, f"{case.header}_v6")
    h.reload(vm, "update")


def _endpoints(line: str) -> set[tuple[ipaddress.IPv6Address, int]]:
    """Every ``addr[port]`` IPv6 endpoint of a ``pfctl -ss`` line, as (address, port) VALUES.

    Only a real IPv6 address parses, so an IPv4 ``a.b.c.d:port`` endpoint or a stray hex word
    before a ``[`` never yields a match.
    """
    found = set()
    for text, port in _ENDPOINT.findall(line):
        try:
            found.add((ipaddress.IPv6Address(text), int(port)))
        except ValueError:
            continue
    return found


def _endpoint_ips(line: str) -> set[ipaddress.IPv6Address]:
    """The IPv6 addresses of the ``addr[port]`` endpoints of a ``pfctl -ss`` line."""
    return {ip for ip, _ in _endpoints(line)}


def _is_victim_state(line: str, port: int) -> bool:
    """True iff ``line`` has the victim as an endpoint on exactly ``port``."""
    return (_VICTIM_ADDR, port) in _endpoints(line)


def _victim_states(vm: SmokeVM, port: int) -> list[str]:
    """The live ``pfctl -ss`` state lines with the victim on destination ``port``."""
    res = vm.ssh(h.PFCTL, "-ss")
    if res.returncode != 0:
        raise RuntimeError(f"pfctl -ss failed: rc={res.returncode} stderr={res.stderr!r}")
    return [line for line in res.stdout.splitlines() if _is_victim_state(line, port)]


def _civm_connect(cl: SmokeVM, port: int) -> None:
    """Open one TCP connection from civm to the victim; the outcome is read from pf, not from curl."""
    cl.ssh("/bin/sh", "-c", f"curl -g -6 -s -o /dev/null --connect-timeout 3 --max-time 5 http://[{VICTIM}]:{port}/")


def _firewall_connect(vm: SmokeVM, port: int) -> None:
    """Open one TCP connection from the firewall ITSELF to the victim; the outcome is read from pf."""
    vm.ssh("/bin/sh", "-c", f"/usr/bin/nc -6 -z -w 3 {VICTIM} {port}")


def _members(vm: SmokeVM, alias: str) -> set[ipaddress.IPv6Address]:
    """The alias table's addresses, by value (``/128`` suffix dropped)."""
    return {ipaddress.IPv6Address(m.split("/")[0]) for m in h.pfctl_table_members(vm, alias)}


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


@pytest.fixture(autouse=True)
def _restore_v6_rules(deployed_vm: SmokeVM) -> Iterator[None]:
    """Remove every v6 list and the float/toggle settings a case wired; fail loudly if a rule stays."""
    yield
    vm = deployed_vm
    settings = h._php_str(h.CFG_IP_SETTINGS)
    snippet = (
        f"config_set_path({h._php_str(h.CFG_IP_V6_LISTS)}, array());\n"
        f"$ip = config_get_path({settings}, array());\n"
        "$ip['enable_float'] = '';\n"
        "$ip['fw_self_outbound'] = '';\n"
        f"config_set_path({settings}, $ip);\n"
        "write_config('pfBlockerNG smoke: #3393 restore');\n"
        "echo 'OK';"
    )
    r = h.php_eval(vm, snippet)
    if r.returncode != 0 or "OK" not in r.stdout:
        raise RuntimeError(f"restoring the v6 lists failed: rc={r.returncode} {r.stderr!r} {r.stdout!r}")
    h.reload(vm, "update")
    res = vm.ssh(h.PFCTL, "-sr")
    if res.returncode != 0:
        raise RuntimeError(f"pfctl -sr failed: rc={res.returncode} stderr={res.stderr!r}")
    left = [line for line in res.stdout.splitlines() if ALIAS_PREFIX in line]
    if left:
        raise RuntimeError(f"{ALIAS_PREFIX}* rules survived the restore:\n" + "\n".join(left))


# --------------------------------------------------------------------------- #
# 1. A v6 Deny Outbound / Deny Both rule drops the client's egress toward a listed victim
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("action", "float_on"),
    [("Deny_Outbound", True), ("Deny_Outbound", False), ("Deny_Both", True)],
    ids=["deny-outbound-floating-on", "deny-outbound-floating-off", "deny-both-floating-on"],
)
def test_v6_deny_rule_drops_client_egress(
    deployed_vm: SmokeVM, client_vm: SmokeVM, action: str, float_on: bool
) -> None:
    """Scenario: a v6 Deny Outbound (floating ON or OFF) or Deny Both alias, LAN as the Outbound interface.

    Given the alias holds only a decoy, civm's connect toward the victim is not matched by the
          rule and pfSense forwards it (a pf state forms from civm's pinned source).
    When  the victim joins the alias and pfBlockerNG updates.
    Then  civm's next connect is matched by the deny rule (its packet counter moved) and no pf
          state forms for it: the rule is ``inet6`` and saw the IPv6 packet.
    """
    vm = deployed_vm
    where = f"action={action} float_on={float_on}"
    header = f"pfb3393{'out' if action == 'Deny_Outbound' else 'both'}{'fl' if float_on else 'if'}"
    src = h.pin_client_route6(client_vm, VICTIM, h.get_lan_ipv6(vm))
    try:
        case = _wire6(vm, header, action, (DUMMY,), float_on=float_on, fw_self=False)
        before = _rule_packets(vm, case.alias, "in")
        assert before >= 0, f"no direction-in rule for {case.alias} is loaded ({where})"

        port = next(_PORTS)
        _civm_connect(client_vm, port)
        after = _rule_packets(vm, case.alias, "in")
        assert after == before, (
            f"before: the rule matched civm's connect to the UNLISTED {VICTIM} "
            f"(before={before}, after={after}, {where})"
        )
        states = _victim_states(vm, port)
        assert any(ipaddress.IPv6Address(src) in _endpoint_ips(s) for s in states), (
            f"before: no pf state for {VICTIM} port {port} from civm's source {src}; states seen: {states} ({where})"
        )

        _add_victim6(vm, case, (DUMMY, VICTIM))
        members = _members(vm, case.alias)
        assert _VICTIM_ADDR in members, f"{VICTIM} is not in {case.alias} after the update: {sorted(members)} ({where})"

        before = _rule_packets(vm, case.alias, "in")
        port = next(_PORTS)
        _civm_connect(client_vm, port)
        after = _rule_packets(vm, case.alias, "in")
        assert after > before, (
            f"the deny rule for {case.alias} never matched civm's connect to the LISTED {VICTIM} "
            f"(before={before}, after={after}, {where})"
        )
        states = _victim_states(vm, port)
        assert states == [], f"a pf state formed for the dropped connect to {VICTIM} port {port}: {states} ({where})"
    finally:
        h.unpin_client_route6(client_vm, VICTIM)


# --------------------------------------------------------------------------- #
# 2. 'Apply outbound rules to firewall traffic' adds a v6 twin for the firewall's own connections
# --------------------------------------------------------------------------- #


def test_fw_self_outbound_v6_twin_drops_firewall_egress(deployed_vm: SmokeVM) -> None:
    """Scenario: a v6 Deny Outbound alias holding the victim, WAN as the Inbound interface.

    Given the toggle is OFF, no ``out`` rule exists and the firewall's own connect to the victim
          is forwarded (an outbound pf state forms on the WAN).
    When  the toggle is turned ON and pfBlockerNG updates.
    Then  the ``out`` twin is loaded, its packet counter moves on the next connect and no pf
          state forms for it.
    """
    vm = deployed_vm
    wan_if = h.config_get(vm, "interfaces/wan/if")
    case = _wire6(vm, "pfb3393self", "Deny_Outbound", (VICTIM,), float_on=True, fw_self=False)
    members = _members(vm, case.alias)
    assert _VICTIM_ADDR in members, f"{VICTIM} is not in {case.alias}: {sorted(members)}"

    assert _rule_packets(vm, case.alias, "out") == -1, "before: no out rule may exist with the toggle OFF"
    port = next(_PORTS)
    _firewall_connect(vm, port)
    assert _rule_packets(vm, case.alias, "out") == -1, "before: an out rule appeared with the toggle OFF"
    states = _victim_states(vm, port)
    assert any(s.split()[0] == wan_if and " -> " in s for s in states), (
        f"before: no outbound pf state on {wan_if} for the firewall's connect to {VICTIM} port {port}; "
        f"states seen: {states}"
    )

    _set_ipcfg(vm, {"fw_self_outbound": "on"})
    h.reload(vm, "update")

    before = _rule_packets(vm, case.alias, "out")
    assert before >= 0, f"no out twin for {case.alias} is loaded with the toggle ON"
    port = next(_PORTS)
    _firewall_connect(vm, port)
    after = _rule_packets(vm, case.alias, "out")
    assert after > before, (
        f"the out twin for {case.alias} never matched the firewall's own connect (before={before}, after={after})"
    )
    states = _victim_states(vm, port)
    assert states == [], f"a pf state formed for the dropped connect to {VICTIM} port {port}: {states}"
