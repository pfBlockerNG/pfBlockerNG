"""Live-VM smoke: pfBlockerNG "Clear firewall states" (killstates) on an IPv6 block (#3394).

The IPv6 mirror of ``test_smoke_killstates.py`` (read its docstring first: the floating
LAN+WAN Deny_Outbound rule, the content-only Update that keeps killstates eligible, the
Permit_Inbound choice for #705). A civm connection creates a pf state to a public IPv6
victim; the victim is then added to a pfBlockerNG v6 deny list and an Update runs:

  C1. killstates OFF ⇒ the state SURVIVES; a fresh connection is dropped by the rule.
  C2. killstates ON  ⇒ the state is REMOVED; a fresh connection is dropped by the rule.
  C3. killstates ON + the second victim on a v6 'Permit_*' custom list ⇒ the permitted
      victim's state is SPARED while the listed victim's is REMOVED in the same pass.

IPv6-specific facts (probed live on CE 2.8.1 in #3394):

* The victims are PUBLIC (2606:4700:7777::/48). pfb_remove_states skips local subnets
  (the LAN ``fd00::/64``, the WAN's SLIRP ``fec0::/64``) and anything failing
  ``FILTER_FLAG_NO_PRIV_RANGE|FILTER_FLAG_NO_RES_RANGE``.
* pfSense has an IPv6 default route out WAN through QEMU SLIRP (NAT66), so each victim
  gets a pfSense BLACKHOLE host route for the test's duration: the probe never reaches
  the Internet (tcpdump on WAN saw nothing). pf still records the state on LAN ingress,
  before routing drops the packet: ``vtnet2 tcp <victim>[80] <- <civm>[port]``. With
  ``set state-policy if-bound`` it binds to the LAN NIC, one of the pfB rule's
  interfaces, so the kill walk evaluates it.
* civm's route to each victim is pinned via pfSense's LAN IPv6 (#3392 helpers); the pinned
  source is what the before-state asserts, matched by value, not by substring.
"""

from __future__ import annotations

import contextlib
import ipaddress
import os
from collections.abc import Iterator

import pytest

from . import helpers as h
from .conftest import SmokeVM, _StubDnsServer
from .test_smoke_killstates import _append_permit_customlist, _rule_block_packets, _set_ipcfg, _state_diag

pytestmark = pytest.mark.smoke

# PERMIT_VICTIM also sits on the v6 Permit custom list (module fixture), as an explicit
# '/128': a bare v6 entry gets '/32' appended (a known quirk, PfbRemoveStatesTest), which
# would suppress VICTIM too. DUMMY keeps the alias non-empty so the rule stays built.
VICTIM = "2606:4700:7777::1111"
PERMIT_VICTIM = "2606:4700:7777::2222"
DUMMY = "2606:4700:7777::77"
HEADER = "pfbkillstates6"  # IP feed header → on-disk file pfbkillstates6_v6.txt
PERMIT_ALIAS = "pfbkillpermit6"
ALIAS_TABLE = f"pfB_{HEADER}_v6"
FEED_FILE = "pfb_killstates_ip6.txt"
# h.inject() replaces the v6 lists node with the deny list (row 0); the permit list is appended.
PERMIT_ROW = 1


def _endpoints(line: str) -> set[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """The addresses of one ``pfctl -ss`` line (``addr[port]``, NAT'd ``(addr[port])``)."""
    addrs: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    for token in line.split():
        with contextlib.suppress(ValueError):
            addrs.add(ipaddress.ip_address(token.strip("()").split("[", 1)[0]))
    return addrs


def _states(vm: SmokeVM, ip: str, src: str | None = None) -> list[str]:
    """pf state lines with ``ip`` as an endpoint (and ``src`` too, when given), by value."""
    r = vm.ssh("/bin/sh", "-c", "pfctl -ss", timeout=30)
    if r.returncode != 0:
        raise RuntimeError(f"pfctl -ss failed: rc={r.returncode} {r.stderr!r}")
    want = {ipaddress.ip_address(a) for a in (ip, src) if a}
    return [line.strip() for line in r.stdout.splitlines() if want <= _endpoints(line)]


def _pf_blackhole(vm: SmokeVM, ip: str, *, add: bool) -> None:
    """Add (or delete) pfSense's blackhole host route for ``ip``."""
    cmd = f"route -6 add -host {ip} ::1 -blackhole" if add else f"route -6 delete -host {ip}"
    r = vm.ssh("/bin/sh", "-c", cmd, timeout=30)
    if r.returncode != 0:
        raise RuntimeError(f"`{cmd}` failed: rc={r.returncode} {r.stdout!r} {r.stderr!r}")


@contextlib.contextmanager
def _blackholed(vm: SmokeVM, cl: SmokeVM, *victims: str) -> Iterator[str]:
    """Blackhole each victim on pfSense, pin civm's route to it via the LAN; yield civm's source.

    Everything is undone on exit, in reverse order, even when the body or a later step fails.
    """
    lan6 = h.get_lan_ipv6(vm)
    with contextlib.ExitStack() as undo:
        src = ""
        for ip in victims:
            _pf_blackhole(vm, ip, add=True)
            undo.callback(_pf_blackhole, vm, ip, add=False)
            src = h.pin_client_route6(cl, ip, lan6)
            undo.callback(h.unpin_client_route6, cl, ip)
        yield src


def _civm_connect(cl: SmokeVM, ip: str) -> str:
    """civm attempts a TCP connection to ``ip`` (the caller pinned the route); return curl's exit."""
    r = cl.ssh(
        "/bin/sh",
        "-c",
        f"curl -g -s -o /dev/null --connect-timeout 3 --max-time 4 'http://[{ip}]/'; echo curl_rc=$?",
        timeout=20,
    )
    return r.stdout.strip()


def _establish_state(vm: SmokeVM, cl: SmokeVM, ip: str, src: str) -> list[str]:
    """civm connects to the (unblocked) ``ip``; return the pf state lines for exactly ``src`` → ``ip``.

    curl returns after its SYN retransmits time out, so a SYN that passed the LAN allow has
    already created the state.
    """
    curl = _civm_connect(cl, ip)
    states = _states(vm, ip, src)
    assert states, (
        f"expected a pf state {src} -> {ip} after civm connected ({curl}), got none; "
        f"states naming {ip}: {_states(vm, ip)!r}\n{_state_diag(vm, table=ALIAS_TABLE)}"
    )
    return states


def _assert_fresh_connection_blocked(vm: SmokeVM, cl: SmokeVM) -> None:
    """A brand-new connection to VICTIM bumps the floating reject rule's packet counter."""
    before = _rule_block_packets(vm, table=ALIAS_TABLE)
    curl = _civm_connect(cl, VICTIM)
    after = _rule_block_packets(vm, table=ALIAS_TABLE)
    assert 0 <= before < after, (
        f"expected a fresh connection to the blocked {VICTIM} ({curl}) to increment the reject "
        f"rule's packet counter, got before={before} after={after}\n{_state_diag(vm, table=ALIAS_TABLE)}"
    )


def _block(vm: SmokeVM, ips: tuple[str, ...] = (VICTIM,)) -> None:
    """Add ``ips`` to the existing rule's alias and run an Update (content-only ⇒ killstates eligible)."""
    h.write_local_feed(vm, FEED_FILE, "".join(f"{ip}/128\n" for ip in ips))
    h.force_ip_refetch(vm, f"{HEADER}_v6")
    h.reload(vm, "update")


def _unblock_baseline(vm: SmokeVM, *, kill_on: bool) -> None:
    """Per-test baseline: victims unblocked, killstates as wanted, no state left to either victim."""
    h.write_local_feed(vm, FEED_FILE, f"{DUMMY}/128\n")
    _set_ipcfg(vm, {"killstates": "on" if kill_on else ""})
    h.force_ip_refetch(vm, f"{HEADER}_v6")
    h.reload(vm, "update")
    for ip in (VICTIM, PERMIT_VICTIM):
        vm.ssh("/bin/sh", "-c", f"pfctl -k ::/0 -k {ip}", timeout=30)
        left = _states(vm, ip)
        if left:
            raise RuntimeError(f"baseline reset left states to {ip}: {left!r}")


@pytest.fixture(scope="module")
def ip6_block_vm(smoke_vm: SmokeVM, client_vm: SmokeVM, stub_dns: _StubDnsServer) -> Iterator[SmokeVM]:
    """Deploy; wire a floating LAN+WAN v6 Deny_Outbound (reject) rule plus a v6 Permit custom list.

    Given: the smoke VM is booted with the branch .pkg available; civm is up.
    When:  one v6 IP feed (header ``pfbkillstates6``) holding only DUMMY is injected as a
           floating Deny_Outbound rule on LAN+WAN, and a 'Permit_Inbound' v6 custom list
           holds PERMIT_VICTIM/128 (set up here so each test's Update stays content-only).
    Then:  the reject rule exists and neither victim is blocked.
    """
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")

    h.deploy(smoke_vm)
    h.use_system_dns_upstream(smoke_vm)

    feed = h.write_local_feed(smoke_vm, FEED_FILE, f"{DUMMY}/128\n")
    h.inject(
        smoke_vm,
        h.IpCase(aliasname=HEADER, feed_url=feed, action="Deny_Outbound", family="v6", header=HEADER),
    )
    _append_permit_customlist(smoke_vm, PERMIT_ALIAS, f"{PERMIT_VICTIM}/128", lists=h.CFG_IP_V6_LISTS)
    _set_ipcfg(smoke_vm, {"outbound_interface": "lan,wan", "enable_float": "on", "enable_log": "on"})
    h.reload(smoke_vm, "update")
    yield smoke_vm


def test_killstates_v6_off_preserves_state_bypassing_new_block(ip6_block_vm: SmokeVM, client_vm: SmokeVM) -> None:
    """C1 — killstates OFF: an IPv6 state created before the block SURVIVES the Update.

    Given: Clear-States OFF and a civm state to the still-unblocked VICTIM from its pinned source.
    When:  VICTIM is added to the v6 block alias and pfBlockerNG runs an Update.
    Then:  that state is still present, VICTIM is in the live alias, and a fresh connection
           is dropped by the rule — preservation of the old flow, not an inert block.
    """
    vm = ip6_block_vm
    _unblock_baseline(vm, kill_on=False)
    with _blackholed(vm, client_vm, VICTIM) as src:
        before = _establish_state(vm, client_vm, VICTIM, src)

        _block(vm)

        after = _states(vm, VICTIM, src)
        assert after, (
            f"killstates OFF must PRESERVE the state {src} -> {VICTIM}, but it was cleared.\n"
            f"  before: {before!r}\n  after: {after!r}\n{_state_diag(vm, table=ALIAS_TABLE)}"
        )
        table = vm.ssh("/bin/sh", "-c", f"pfctl -t {ALIAS_TABLE} -T show", timeout=30).stdout
        assert VICTIM in table.split(), f"expected {VICTIM} in the live block alias {ALIAS_TABLE}, got:\n{table}"
        _assert_fresh_connection_blocked(vm, client_vm)


def test_killstates_v6_on_clears_state_so_block_takes_effect(ip6_block_vm: SmokeVM, client_vm: SmokeVM) -> None:
    """C2 — killstates ON: pfBlockerNG removes the IPv6 state on Update, so the block takes effect.

    Given: Clear-States ON and a civm state to the still-unblocked VICTIM from its pinned source.
    When:  VICTIM is added to the v6 block alias and pfBlockerNG runs an Update.
    Then:  no state names VICTIM any more, and a fresh connection is dropped by the rule.
    """
    vm = ip6_block_vm
    _unblock_baseline(vm, kill_on=True)
    with _blackholed(vm, client_vm, VICTIM) as src:
        before = _establish_state(vm, client_vm, VICTIM, src)

        _block(vm)

        after = _states(vm, VICTIM)
        assert not after, (
            f"killstates ON must CLEAR every state to {VICTIM} on Update, but these survived.\n"
            f"  before: {before!r}\n  after: {after!r}\n{_state_diag(vm, table=ALIAS_TABLE)}"
        )
        _assert_fresh_connection_blocked(vm, client_vm)


def test_killstates_v6_on_spares_permit_customlist_state(ip6_block_vm: SmokeVM, client_vm: SmokeVM) -> None:
    """C3 — killstates ON: a v6 Permit-customlist IP's state survives the pass that kills VICTIM's.

    Given: Clear-States ON; the v6 'Permit_Inbound' custom list row holding PERMIT_VICTIM
           (asserted from config); civm states to BOTH still-unblocked victims.
    When:  BOTH victims are added to the v6 block alias and pfBlockerNG runs an Update.
    Then:  both are in the live alias (a real permit-vs-deny conflict), VICTIM's state is
           removed (the kill pass ran) and PERMIT_VICTIM's state survives.
    """
    vm = ip6_block_vm
    _unblock_baseline(vm, kill_on=True)

    row = f"{h.CFG_IP_V6_LISTS}/{PERMIT_ROW}"
    name, action, custom = (h.config_get(vm, f"{row}/{key}") for key in ("aliasname", "action", "custom"))
    assert (name, action) == (PERMIT_ALIAS, "Permit_Inbound") and custom != "", (
        f"expected the v6 Permit custom-list row '{PERMIT_ALIAS}' (action 'Permit_Inbound', non-empty "
        f"custom) at config row {PERMIT_ROW}, got name={name!r} action={action!r} custom={custom!r}"
    )

    with _blackholed(vm, client_vm, VICTIM, PERMIT_VICTIM) as src:
        before_victim = _establish_state(vm, client_vm, VICTIM, src)
        before_permit = _establish_state(vm, client_vm, PERMIT_VICTIM, src)

        _block(vm, (VICTIM, PERMIT_VICTIM))

        table = vm.ssh("/bin/sh", "-c", f"pfctl -t {ALIAS_TABLE} -T show", timeout=30).stdout
        assert {VICTIM, PERMIT_VICTIM} <= set(table.split()), (
            f"expected {VICTIM} and {PERMIT_VICTIM} in the live block alias {ALIAS_TABLE}, got:\n{table}"
        )
        after_victim = _states(vm, VICTIM)
        assert not after_victim, (
            f"killstates ON must CLEAR the non-permitted {VICTIM}'s state (proves the pass ran), but "
            f"it survived.\n  before: {before_victim!r}\n  after: {after_victim!r}\n"
            f"{_state_diag(vm, table=ALIAS_TABLE)}"
        )
        after_permit = _states(vm, PERMIT_VICTIM, src)
        assert after_permit, (
            f"killstates must SPARE the Permit-customlist {PERMIT_VICTIM}'s state, but it was killed.\n"
            f"  before: {before_permit!r}\n  after: {after_permit!r}\n{_state_diag(vm, table=ALIAS_TABLE)}"
        )
