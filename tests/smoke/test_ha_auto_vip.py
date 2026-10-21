"""Smoke leg: Auto VIP on an HA pair follows the primary's sinkhole address (issue #3540).

Node A (``ha_pair.primary``) sends in policy scope, node B (``ha_pair.secondary``) receives. Both run "Create VIPs
automatically". Each node owns its own VIP object (B's uniqid is never A's); only the ADDRESS follows the primary:

* S1 A's first candidate address (172.16.53.53) lies inside one of its own interface subnets, so its pass picks the
  second (192.168.53.53); B alone would pick 172.16.53.53. After A sends, B holds a marked VIP at A's address, keeps
  its own stored VIP id and answers a blocked name with that address.
* S2 B's first candidate is taken the same way and its own pass has already picked the second. After A (nothing in
  the way, so it picks 172.16.53.53) sends, B removes its marked VIP, creates none, leaves its interface alone and
  lists the conflict on the Sync page.

A node's picker (``pfb_pick_free_dnsbl_vip``) treats an address as taken when it lies inside an interface subnet that
is live on the node; an unmarked IP-alias VIP does not count. The conflict is therefore LAN readdressed into
172.16.53.0/24, which the HA pair does not use (WAN, the harness' management path and the SYNC link stay as they are).

DESELECTED from the default ``python -m pytest`` (``--ignore=tests/smoke``). Run locally::

    scripts/local-smoke.sh --ref <pushed-sha> --no-two-vm --filter test_ha_auto_vip
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import pytest

from . import helpers as h
from .ha_pair import HaPair, wait_carp_state
from .ha_policy import (
    DNSBL,
    Baseline,
    arrange_baseline,
    assert_applied_once,
    assert_receive,
    assert_sent,
    configure_sender,
    emit,
    findings,
    node_state,
    php_json,
    read_leaves,
    receive_state,
    reset_pair,
    set_leaves,
    settle,
    show,
    sync_once,
    wait_filter_idle,
)
from .test_ha_policy_authority import guest_webui
from .ui.test_sync_status_panels import render_sync_page

if TYPE_CHECKING:
    from .conftest import SmokeVM

pytestmark = pytest.mark.smoke

# pfb_dnsbl_vip_candidates(AF_INET), in the order a node tries them.
FIRST, SECOND, THIRD = h.AUTO_VIP_IP4, "192.168.53.53", "10.53.53.53"
CANDIDATES = (FIRST, SECOND, THIRD)
FINDING = "DNSBL auto-VIP: the synced IPv4 address is not free on this node"
GROUP = "pfbha3540"
# LAN's address while it is the conflict: inside 172.16.53.0/24, so FIRST is covered by an interface subnet.
LAN = "lan"
CONFLICT_LAN_ADDRESS, CONFLICT_LAN_PREFIX = "172.16.53.1", "24"


@pytest.fixture(scope="module")
def baseline(ha_pair: HaPair) -> Baseline:
    """Both nodes at one policy, with different local values and a distinct manual DNSBL VIP object on B."""
    wait_carp_state(ha_pair.primary, "MASTER", node="primary")
    wait_carp_state(ha_pair.secondary, "BACKUP", node="secondary")
    return arrange_baseline(ha_pair)


@dataclass(frozen=True)
class Lan:
    """A node's LAN address as it was stored, and live on ``nic``, before a test moved it."""

    vm: SmokeVM
    nic: str
    address: str
    prefix: str


@pytest.fixture
def moved_lans() -> list[Lan]:
    """The LAN addresses the running test moved, to be put back (live and stored) whatever its outcome."""
    return []


@pytest.fixture(autouse=True)
def _reset(ha_pair: HaPair, baseline: Baseline, moved_lans: list[Lan]) -> Iterator[None]:
    """Put both nodes back at the baseline after each test and fail loudly when that does not take.

    Every step runs even when an earlier one fails, and the failures are raised together: a LAN that did not come back
    must neither hide the baseline reset nor be hidden by it.
    """
    yield
    failures: list[str] = []
    for lan in reversed(moved_lans):
        try:
            move_lan(lan.vm, lan, to=lan.address, prefix=lan.prefix)
        except Exception as exc:
            failures.append(f"LAN restore: {exc}")
    try:
        # The config restore leaves live aliases behind; the next test reads them from ifconfig.
        for vm in (ha_pair.primary, ha_pair.secondary):
            drop_candidate_aliases(vm)
        reset_pair(ha_pair, baseline)
    except Exception as exc:
        failures.append(str(exc))
    if failures:
        raise AssertionError("; ".join(failures))


# --------------------------------------------------------------------------- #
# Building blocks
# --------------------------------------------------------------------------- #


def vips(vm: SmokeVM) -> list[dict[str, Any]]:
    """The node's stored virtual IPs, in stored order."""
    return list(read_leaves(vm, ["virtualip/vip"])["virtualip/vip"] or [])


def marked_vips(vm: SmokeVM) -> list[dict[str, Any]]:
    """The IPv4 VIPs the package created and owns on this node."""
    return [vip for vip in vips(vm) if vip.get("descr") == h.AUTO_VIP_DESCR_V4]


def stored_vip_id(vm: SmokeVM) -> Any:
    path = f"{DNSBL}/pfb_dnsvip4"
    return read_leaves(vm, [path])[path]


def drop_candidate_aliases(vm: SmokeVM) -> None:
    """Take the three candidate addresses off the VIP interface; an address that is not there is not an error."""
    vm.ssh(
        f"for a in {' '.join(CANDIDATES)}; do /sbin/ifconfig {h.SMOKE_VIP_IFACE} -alias $a >/dev/null 2>&1; done; true"
    )


def lan_now(vm: SmokeVM) -> Lan:
    """LAN as stored on ``vm``; it must be live exactly so, or the test would restore a state it never saw."""
    keys = {key: f"interfaces/{LAN}/{key}" for key in ("if", "ipaddr", "subnet")}
    stored = read_leaves(vm, list(keys.values()))
    nic, address, prefix = (str(stored[path]) for path in keys.values())
    assert address and address != "dhcp" and prefix, f"premise: LAN has no static IPv4 address stored: {stored!r}"
    live = inet_addresses(vm, nic)
    assert live == [address], f"premise: LAN's stored address: expected it to be the one live on {nic}, got {live!r}"
    return Lan(vm, nic, address, prefix)


def inet_addresses(vm: SmokeVM, nic: str) -> list[str]:
    """The IPv4 addresses ``ifconfig`` shows on ``nic``, in the order it lists them."""
    words = vm.ssh(f"/sbin/ifconfig {nic}").stdout.split()
    return [words[i + 1] for i, word in enumerate(words[:-1]) if word == "inet"]


def move_lan(vm: SmokeVM, lan: Lan, *, to: str, prefix: str) -> None:
    """Store ``to``/``prefix`` as LAN's address and make it the only IPv4 address live on its NIC.

    The picker reads the interface subnets that are live. Fails unless ifconfig shows exactly ``to`` afterwards.
    """
    set_leaves(
        vm,
        {f"interfaces/{LAN}/ipaddr": to, f"interfaces/{LAN}/subnet": prefix},
        "pfBlockerNG smoke: HA #3540 LAN address",
    )
    for address in inet_addresses(vm, lan.nic):
        if address != to:
            vm.ssh(f"/sbin/ifconfig {lan.nic} inet {address} -alias")
    if to not in inet_addresses(vm, lan.nic):
        vm.ssh(f"/sbin/ifconfig {lan.nic} inet {to}/{prefix} alias")
    live = inet_addresses(vm, lan.nic)
    assert live == [to], f"{lan.nic} on this node: expected the one IPv4 address {to!r}, got {live!r}"


def readdress_lan(vm: SmokeVM, moved: list[Lan]) -> None:
    """Put LAN's address inside 172.16.53.0/24 (the first candidate becomes an interface subnet conflict).

    The original is recorded BEFORE anything is touched, so a half-applied move is still undone.
    """
    original = lan_now(vm)
    moved.append(original)
    move_lan(vm, original, to=CONFLICT_LAN_ADDRESS, prefix=CONFLICT_LAN_PREFIX)


def own_pick(vm: SmokeVM) -> Any:
    """The address this node's own picker (``pfb_pick_free_dnsbl_vip``) chooses for IPv4 right now."""
    return php_json(vm, emit(f"pfb_pick_free_dnsbl_vip(AF_INET, '{h.SMOKE_VIP_IFACE}')"))


def install_group(pair: HaPair, domain: str, *, on: tuple[SmokeVM, ...]) -> None:
    """One DNSBL deny group answering with the VIP on each of ``on``, fed by a local file that exists on BOTH nodes.

    A node reads its own copy of the feed path, so a node that only receives the group still blocks the name.
    """
    feed = ""
    for vm in (pair.primary, pair.secondary):
        feed = h.write_local_feed(vm, f"{GROUP}.txt", f"{domain}\n")
    spec = h.DnsblCase(aliasname=GROUP, feed_url=feed, header=GROUP, mode=h.DnsblMode.VIP)
    for vm in on:
        h.inject_dnsbl_lists(vm, [(spec, "Deny")])


def quiesce(vm: SmokeVM) -> None:
    """No pass, tick or firewall reload of the package is left running on ``vm``."""
    settle(vm)
    wait_filter_idle(vm)


def check(problems: list[str], condition: bool, expected: str, actual: Any) -> None:
    """Record one wrong fact. The test asserts the list, so one live run reports every wrong fact, not the first."""
    if not condition:
        problems.append(f"expected {expected}; got {actual!r}")


def subnets(rows: list[dict[str, Any]]) -> list[str]:
    return [str(row.get("subnet")) for row in rows]


# --------------------------------------------------------------------------- #
# S1: the secondary follows the primary's address
# --------------------------------------------------------------------------- #


# A's update pass with a new DNSBL group, then B's receive-spawned apply pass, then two probes
@pytest.mark.timeout(2400)
def test_secondary_creates_its_vip_at_the_address_the_primary_chose(ha_pair: HaPair, moved_lans: list[Lan]) -> None:
    """A picks 192.168.53.53 because 172.16.53.53 lies in its LAN subnet; B, which would pick 172.16.53.53, follows.

    Given: both nodes on Auto VIP, a VIP-answering DNSBL group on A only, A's LAN inside 172.16.53.0/24
    When:  A's update pass provisions its VIP and sends its policy to B
    Then:  both hold a marked VIP at 192.168.53.53, B's stored VIP id names B's own object, and each node
           answers the blocked name with 192.168.53.53

    Red when: B creates its VIP at its own first free candidate (the address never leaves A), or B's stored id is
    A's, or B answers with a different address than A.
    """
    a, b = ha_pair.primary, ha_pair.secondary
    domain = h.unique_domain("havip")
    install_group(ha_pair, domain, on=(a,))
    for vm in (a, b):
        h.set_dnsvip_auto(vm, True)
    readdress_lan(a, moved_lans)
    configure_sender(ha_pair, "manual")
    assert marked_vips(a) == [], f"before the send: expected no marked VIP on A, got {marked_vips(a)!r}"
    assert marked_vips(b) == [], f"before the send: expected no marked VIP on B, got {marked_vips(b)!r}"
    picks = {"A": own_pick(a), "B": own_pick(b)}
    assert picks == {"A": SECOND, "B": FIRST}, (
        f"before the send: expected the nodes to pick on their own, got {picks!r}"
    )

    sync = sync_once(ha_pair, "manual")
    quiesce(a)
    wait_filter_idle(b)
    show("S1 A send record", sync.send)
    show("S1 B receive record", sync.receive)
    assert_sent(sync, "manual", node_state(a).digest)
    assert_receive(sync, "changed")
    assert_applied_once(sync)

    a_marked, b_marked = marked_vips(a), marked_vips(b)
    problems: list[str] = []
    check(
        problems,
        subnets(a_marked) == [SECOND],
        f"A's marked VIP at [{SECOND!r}] ({FIRST} is inside its LAN subnet)",
        subnets(a_marked),
    )
    check(
        problems,
        subnets(b_marked) == [SECOND],
        f"B's marked VIP at A's address [{SECOND!r}], not its own pick",
        subnets(b_marked),
    )
    b_own_id = f"_vip{b_marked[0].get('uniqid')}" if b_marked else "<no marked VIP on B>"
    check(problems, stored_vip_id(b) == b_own_id, "B's pfb_dnsvip4 naming B's own marked VIP", stored_vip_id(b))
    ids = {"A": stored_vip_id(a), "B": stored_vip_id(b)}
    check(problems, ids["A"] != ids["B"], "B's pfb_dnsvip4 differing from A's", ids)
    for name, vm in (("A", a), ("B", b)):
        h.wait_unbound_ready(vm)
        answer = h.dns_probe(vm, domain, "A")
        check(problems, h.resolves_to(answer, SECOND), f"{name} answering {domain} with the VIP {SECOND}", answer)
    assert not problems, "; ".join(problems)


# --------------------------------------------------------------------------- #
# S2: the secondary cannot use the primary's address
# --------------------------------------------------------------------------- #


@pytest.mark.timeout(3000)  # B's own pass, A's pass with the send, B's receive-spawned apply pass and a rendered page
def test_secondary_with_the_address_in_use_creates_no_vip_and_reports_it(
    ha_pair: HaPair, moved_lans: list[Lan]
) -> None:
    """A picks 172.16.53.53, which lies in B's LAN subnet: B drops the VIP it made at 192.168.53.53 and lists why.

    Given: both nodes on Auto VIP with the same DNSBL group, B's LAN inside 172.16.53.0/24; B's own pass has
           picked 192.168.53.53 while it is no receiver
    When:  A (free, so it picks 172.16.53.53) sends its policy to B
    Then:  B has no VIP at any candidate address and no marked VIP, its LAN and its other VIPs are untouched, and
           B's findings file and rendered Sync page carry the conflict

    Red when: B keeps the VIP it made for itself (it is not bound to the address A published), or creates one at
    another candidate, or touches its LAN or other VIPs, or does not say why it has no VIP.
    """
    a, b = ha_pair.primary, ha_pair.secondary
    domain = h.unique_domain("havip")
    install_group(ha_pair, domain, on=(a, b))
    for vm in (a, b):
        h.set_dnsvip_auto(vm, True)
    # The policies differ on every build, so the receive is a change even where the address is not synced.
    set_leaves(a, {f"{DNSBL}/top1m_inclusion": "pfbha-3540"}, "pfBlockerNG smoke: HA #3540 policy difference")
    readdress_lan(b, moved_lans)
    picks = {"A": own_pick(a), "B": own_pick(b)}
    assert picks == {"A": FIRST, "B": SECOND}, (
        f"before B's pass: expected the nodes to pick on their own, got {picks!r}"
    )

    h.reload(b, "update")
    quiesce(b)
    picked = subnets(marked_vips(b))
    assert picked == [SECOND], (
        f"before the send: expected B's own pass to pick [{SECOND!r}] ({FIRST} is in its LAN subnet), got {picked!r}"
    )
    assert h.vip_alias_live(b, SECOND), f"before the send: B's marked VIP {SECOND} is not live on {h.SMOKE_VIP_IFACE}"
    assert receive_state(b).get("accepted_digest") is None, f"before the send: B is a receiver: {receive_state(b)!r}"
    assert FINDING not in findings(b), f"before the send: expected no conflict finding on B, got {findings(b)!r}"
    others_before = [vip for vip in vips(b) if vip.get("descr") != h.AUTO_VIP_DESCR_V4]
    assert others_before, "before the send: expected B to hold its manual DNSBL VIP, got none"

    configure_sender(ha_pair, "manual")
    sync = sync_once(ha_pair, "manual")
    quiesce(a)
    wait_filter_idle(b)
    show("S2 A send record", sync.send)
    show("S2 B receive record", sync.receive)
    assert_sent(sync, "manual", node_state(a).digest)
    assert_receive(sync, "changed")
    assert_applied_once(sync)
    assert subnets(marked_vips(a)) == [FIRST], (
        f"expected A's marked VIP at [{FIRST!r}] (nothing in its way), got {subnets(marked_vips(a))!r}"
    )

    held = vips(b)
    lan = moved_lans[0]
    problems: list[str] = []
    check(problems, marked_vips(b) == [], "no marked VIP on B", marked_vips(b))
    check(
        problems,
        [v for v in held if v.get("subnet") in CANDIDATES] == [],
        f"no VIP on B at any of {CANDIDATES}",
        subnets(held),
    )
    live_candidates = [address for address in CANDIDATES if h.vip_alias_live(b, address)]
    check(problems, live_candidates == [], f"no candidate address live on {h.SMOKE_VIP_IFACE} on B", live_candidates)
    others_after = [vip for vip in held if vip.get("descr") != h.AUTO_VIP_DESCR_V4]
    check(problems, others_after == others_before, "B's other VIPs untouched", others_after)
    check(
        problems,
        inet_addresses(b, lan.nic) == [CONFLICT_LAN_ADDRESS],
        f"B's LAN still the one address {CONFLICT_LAN_ADDRESS} on {lan.nic}",
        inet_addresses(b, lan.nic),
    )
    check(problems, FINDING in findings(b), f"{FINDING!r} in B's findings", findings(b))
    with guest_webui(b) as ui_b:
        page = render_sync_page(b, ui_b)
    check(problems, FINDING in page, f"{FINDING!r} on B's rendered Sync page", "absent")
    assert not problems, "; ".join(problems)
