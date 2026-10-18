"""Smoke leg: per-field XMLRPC policy sync between two real pfSense guests (issue #3455).

Node A (``ha_pair.primary``) sends, node B (``ha_pair.secondary``) receives. Every row drives the platform's own
transport and reads the records the package writes, never a double:

* automatic: core's ``rc.filter_synchronize`` on A carries the package's policy paths to B (A's record: ``handed``),
* manual: an apply pass on A sends to the target row (A's record: ``sent``, acceptance unconfirmed),
* B's ``pfb_sync_receive.json`` says what B received (``last``) and, apart, what its apply did (``apply``); one
  changed receive spawns exactly one update pass (``UPDATE PROCESS START``), scheduled ticks stay off.

Rows: R1/R2 policy mirrors and local values stay, R3 one receive applies once and enforces, R4 deletes, empties,
renames and reorders, R5 + X6 idempotent repeat and a timed-out retry over a stalled transport, R7 + X8 credentials
and local keys never reach B, R8 an injected local field is ignored and listed, X1 Blacklist provider credentials
follow their xml, X7 empty values survive core's encoding (inside R4).

DESELECTED from the default ``python -m pytest`` (``--ignore=tests/smoke``). Run locally::

    scripts/local-smoke.sh --ref <pushed-sha> --no-two-vm --filter test_ha_policy_sync
"""

from __future__ import annotations

import base64
import json
import threading
from collections.abc import Iterable, Iterator
from dataclasses import asdict, dataclass
from typing import Any

import pytest

from . import helpers as h
from .ha_pair import HaPair, wait_carp_state
from .ha_policy import (
    B_VIP_UNIQID,
    BLACKLIST,
    BLACKLIST_XML,
    CONFIG,
    DNSBL,
    GEN,
    IP,
    LISTS_V4,
    LISTS_V6,
    NEW_ROW_DEFAULTS,
    TRANSPORTS,
    Baseline,
    NodeState,
    Sync,
    Transport,
    add_deny_group,
    apply_banners,
    arrange_baseline,
    assert_applied_once,
    assert_dnsbl_vip,
    assert_receive,
    assert_sent,
    blacklist_item,
    configure_sender,
    credential_values,
    diff_leaves,
    grep_leaks,
    identities,
    inject_leaf,
    local_by_identity,
    node_local_leaves,
    node_state,
    node_time,
    pf_table,
    policy_payload,
    read_leaves,
    read_sections,
    receive_state,
    reset_pair,
    row_key,
    send_payload,
    send_state,
    sentinel,
    set_leaves,
    settle,
    show,
    sync_once,
    token,
    unexpected_additions,
    wait_apply,
    wait_filter_idle,
    write_sections,
)

pytestmark = pytest.mark.smoke

V4, V6, BL = "pfblockernglistsv4", "pfblockernglistsv6", "pfblockerngblacklist"
ROW_ROOTS = (LISTS_V4, LISTS_V6, BLACKLIST)
ROW_SECTIONS = tuple(f"{root}/" for root in ROW_ROOTS)
SYSTEM_LOG = "/var/log/system.log"
# The pfSense XMLRPC client logs this once per failed attempt before it retries.
CLIENT_RETRY_MARKER = "Retrying XMLRPC Request due to error"


@pytest.fixture(scope="module")
def baseline(ha_pair: HaPair) -> Baseline:
    """Both nodes at one policy, with different local values and a distinct DNSBL VIP object on B."""
    wait_carp_state(ha_pair.primary, "MASTER", node="primary")
    wait_carp_state(ha_pair.secondary, "BACKUP", node="secondary")
    arranged = arrange_baseline(ha_pair)
    a, b = node_state(ha_pair.primary), node_state(ha_pair.secondary)
    assert a.digest == b.digest, f"baseline: A's policy digest {a.digest} != B's {b.digest}; nothing is left to sync"
    show("baseline", {"digest": a.digest, "gateway": arranged.gateway})
    return arranged


@pytest.fixture(autouse=True)
def _reset(ha_pair: HaPair, baseline: Baseline) -> Iterator[None]:
    """Put both nodes back at the baseline after each test and fail loudly when that does not take."""
    yield
    # A test that stalled B's webgui must not leave it stopped for the next one (a no-op when it ran).
    ha_pair.secondary.ssh("pkill -CONT nginx; true")
    reset_pair(ha_pair, baseline)


# --------------------------------------------------------------------------- #
# Building blocks
# --------------------------------------------------------------------------- #


def b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def row_prefix(vm: Any, section: str, identity: str) -> str:
    """``installedpackages/<section>/<config|item>/<n>`` of the row whose alias / xml is ``identity`` on ``vm``."""
    key = "item" if section == BL else "config"
    ids = identities(read_sections(vm, [section])[section])
    assert identity in ids, f"{identity!r} is not among {section}'s rows {ids}"
    return f"installedpackages/{section}/{key}/{ids.index(identity)}"


@dataclass(frozen=True)
class Run:
    """One policy send with both nodes' policy before and after it."""

    a_before: NodeState
    b_before: NodeState
    sync: Sync
    a_after: NodeState
    b_after: NodeState


def sync_policy(pair: HaPair, transport: Transport) -> Run:
    """Send A's pending policy change once and read both nodes before and after; print the records asserted on."""
    a_before, b_before = node_state(pair.primary), node_state(pair.secondary)
    assert a_before.digest != b_before.digest, (
        f"the edit on A did not move its policy digest ({a_before.digest}): there is nothing to send"
    )
    sync = sync_once(pair, transport)
    run = Run(a_before, b_before, sync, node_state(pair.primary), node_state(pair.secondary))
    show(f"{transport} A send record", sync.send)
    show(f"{transport} B receive record", sync.receive)
    show(f"{transport} B update passes", sync.passes)
    return run


def assert_mirrored(pair: HaPair, run: Run, transport: Transport) -> None:
    """The send, the receive and B's policy afterwards: what every changed policy sync must show."""
    assert_sent(run.sync, transport, run.a_before.digest)
    assert_receive(run.sync, "changed", run.a_before.digest)
    assert_applied_once(run.sync)
    assert run.a_after.digest == run.a_before.digest, (
        f"A's policy moved while it sent: {run.a_before.digest} -> {run.a_after.digest}"
    )
    assert run.b_after.digest == run.a_after.digest, (
        f"B's policy digest: expected A's {run.a_after.digest}, got {run.b_after.digest}"
    )
    moved = diff_leaves(run.a_after.projection, run.b_after.projection)
    assert not any(moved.values()), f"B's policy leaves differ from A's: {json.dumps(moved, default=str)[:1500]}"
    assert run.b_after.core == run.b_before.core, (
        f"B's interfaces/VIPs/gateways/webgui moved: expected {run.b_before.core}, got {run.b_after.core}"
    )
    assert_dnsbl_vip(pair.secondary, "secondary", B_VIP_UNIQID)


def assert_local_kept(before: NodeState, after: NodeState, *, new_rows: Iterable[str] = (), rows: bool = True) -> None:
    """B's local leaves did not move: none changed or removed, and any added leaf is a new row's editor default.

    ``rows=False`` leaves the list sections out: a test that reorders or renames rows checks them by identity.
    """

    def kept(state: NodeState) -> dict[str, Any]:
        # A section whose every group went is stored on B as an empty element: the section root is row territory too.
        return {p: v for p, v in state.local.items() if rows or not (p in ROW_ROOTS or p.startswith(ROW_SECTIONS))}

    moved = diff_leaves(kept(before), kept(after))
    assert not moved["changed"], f"B's local leaves changed: expected none, got {moved['changed']!r}"
    assert not moved["removed"], f"B lost local leaves: expected none, got {moved['removed']!r}"
    stray = unexpected_additions(moved["added"], new_rows)
    assert not stray, f"B gained local leaves that are not a new row's defaults: {stray!r}"


def b_own_scalars() -> dict[str, Any]:
    """B's seeded string local leaves by path (the hook row is a list and is covered by the local-leaf comparison)."""
    leaves = node_local_leaves("B", vip_uniqid=B_VIP_UNIQID)
    return {path: value for path, value in leaves.items() if isinstance(value, str)}


def assert_b_keeps_its_own_values(pair: HaPair) -> None:
    """Read back B's seeded local scalars (credentials, alert prefs, interfaces, VIP reference): still B's, not A's."""
    expected = b_own_scalars()
    actual = read_leaves(pair.secondary, expected)
    wrong = {p: (expected[p], actual[p]) for p in expected if actual[p] != expected[p]}
    assert not wrong, f"B's own local values changed (expected, actual): {wrong!r}"


# --------------------------------------------------------------------------- #
# R1 / R2
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("transport", TRANSPORTS)
@pytest.mark.timeout(900)  # two pfSsh round trips per edit, one synchronous send, B's apply pass, two node-state reads
def test_policy_change_reaches_b_and_b_keeps_its_local_values(
    ha_pair: HaPair, baseline: Baseline, transport: Transport
) -> None:
    """A policy edit on A (an IP deny group and a DNSBL whitelist) makes B's stored policy A's; B's own values stay."""
    a, b = ha_pair.primary, ha_pair.secondary
    alias = f"pfbha_r1{token()}"
    whitelist = b64(f"{alias}-white.com\n")
    configure_sender(ha_pair, transport)
    add_deny_group(ha_pair, baseline, alias, "198.51.100.31")
    set_leaves(a, {f"{DNSBL}/whitelist": whitelist}, "pfBlockerNG smoke: HA whitelist")

    run = sync_policy(ha_pair, transport)

    assert_mirrored(ha_pair, run, transport)
    row = row_prefix(b, V4, alias)
    assert_local_kept(run.b_before, run.b_after, new_rows=[row])
    assert_b_keeps_its_own_values(ha_pair)
    got = read_leaves(b, [f"{DNSBL}/whitelist", f"{row}/aliasname", f"{row}/action"])
    assert got == {f"{DNSBL}/whitelist": whitelist, f"{row}/aliasname": alias, f"{row}/action": "Deny_Inbound"}, (
        f"B's copy of the edited policy leaves: got {got!r}"
    )
    own = local_by_identity(read_sections(b, [V4])[V4])
    assert own[alias] == NEW_ROW_DEFAULTS, (
        f"B's new group {alias} gets B's editor defaults, not A's local values: expected {NEW_ROW_DEFAULTS!r}, "
        f"got {own[alias]!r}"
    )


# --------------------------------------------------------------------------- #
# R3
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("transport", TRANSPORTS)
@pytest.mark.timeout(900)  # a send, B's apply pass with its detached firewall reload, and bounded settle polls
def test_one_receive_applies_once_and_enforces(ha_pair: HaPair, baseline: Baseline, transport: Transport) -> None:
    """One receive on B runs one apply pass, with no window and no tick of ours, and B enforces afterwards."""
    b = ha_pair.secondary
    alias, address = f"pfbha_r3{token()}", "198.51.100.41"
    configure_sender(ha_pair, transport)
    add_deny_group(ha_pair, baseline, alias, address)
    before = pf_table(b, alias)
    assert before == [], f"before the sync B must not enforce {alias}: pfB_{alias}_v4 holds {before}"
    quiet = read_leaves(b, [f"{GEN}/pfb_quiet_hours"])[f"{GEN}/pfb_quiet_hours"]
    assert quiet in (None, ""), f"B has an apply window configured, so the apply may legitimately wait: {quiet!r}"
    inhibited = b.ssh(f"test -f {h.PFB_CRON_DISABLE_PATH}")
    assert inhibited.returncode == 0, "scheduled ticks are not inhibited on B: its apply pass could be a cron tick"

    run = sync_policy(ha_pair, transport)

    assert_mirrored(ha_pair, run, transport)
    apply = run.sync.receive["apply"]
    assert apply["reason"].startswith("update pass completed"), (
        f"B's apply record: expected a completed pass, got {apply!r}"
    )
    assert apply["opened"] >= run.sync.t0_b, (
        f"B's apply opened before the send: {apply!r} (send at B's {run.sync.t0_b})"
    )
    wait_filter_idle(b)  # the pass's firewall reload is detached; its process is the completion signal
    members = pf_table(b, alias)
    assert h.member_present(members, address), (
        f"after one receive B must enforce {alias}: expected {address} in pfB_{alias}_v4, got {members}"
    )


# --------------------------------------------------------------------------- #
# R4 (+ X7)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("transport", TRANSPORTS)
@pytest.mark.timeout(900)  # one send of a many-leaf edit, B's apply pass, section reads on both nodes
def test_deletes_empties_renames_and_reorders_mirror_on_b(
    ha_pair: HaPair, baseline: Baseline, transport: Transport
) -> None:
    """Deleted leaves, groups and sections go from B; '' stays ''; rows follow A's names and order; B's locals stay."""
    a, b = ha_pair.primary, ha_pair.secondary
    configure_sender(ha_pair, transport)
    sections = [V4, V6, BL]
    a0, b0 = read_sections(a, sections), read_sections(b, sections)
    v4 = a0[V4]
    groups = {row["aliasname"]: row for row in v4["config"]}
    v4["config"] = [
        groups["pfbha_k2"],
        {**groups["pfbha_k1"], "aliasname": "pfbha_k1r"},
    ]  # k1 renamed, d1 deleted, swapped
    items = {item["xml"]: item for item in a0[BL]["item"]}
    delta = {**blacklist_item("bl_delta"), "title": ""}  # a new provider with an empty nested policy leaf
    write_sections(
        a,
        {
            V4: v4,
            V6: None,
            BL: {"item": [items["bl_gamma"], items["bl_alpha"], delta]},
        },  # every v6 group deleted, beta deleted
        "pfBlockerNG smoke: HA rows edited",
    )
    scalars: dict[str, Any] = {
        f"{DNSBL}/top1m_inclusion": None,
        f"{DNSBL}/pfb_regex_list": "",
        f"{DNSBL}/whitelist": [],
    }
    set_leaves(a, scalars, "pfBlockerNG smoke: HA scalars deleted and emptied")
    expected = {f"{DNSBL}/top1m_inclusion": None, f"{DNSBL}/pfb_regex_list": "", f"{DNSBL}/whitelist": ""}
    assert read_leaves(a, expected) == expected, (
        f"A's own persisted shape: expected {expected!r}, got {read_leaves(a, expected)!r}"
    )

    run = sync_policy(ha_pair, transport)

    assert_mirrored(ha_pair, run, transport)
    assert_local_kept(run.b_before, run.b_after, rows=False)
    after = read_sections(b, sections)
    assert identities(after[V4]) == ["pfbha_k2", "pfbha_k1r"], f"B's IPv4 groups: got {identities(after[V4])}"
    assert identities(after[V6]) == [], f"B's IPv6 groups after A deleted them all: got {identities(after[V6])}"
    assert identities(after[BL]) == ["bl_gamma", "bl_alpha", "bl_delta"], f"B's providers: got {identities(after[BL])}"
    v4_local, v4_before = local_by_identity(after[V4]), local_by_identity(b0[V4])
    assert v4_local["pfbha_k2"] == v4_before["pfbha_k2"], (
        f"a surviving group keeps B's row-local leaves: expected {v4_before['pfbha_k2']!r}, "
        f"got {v4_local['pfbha_k2']!r}"
    )
    assert v4_local["pfbha_k1r"] == NEW_ROW_DEFAULTS, (
        f"a renamed group is a new identity with B's defaults: expected {NEW_ROW_DEFAULTS!r}, "
        f"got {v4_local['pfbha_k1r']!r}"
    )
    bl_local, bl_before = local_by_identity(after[BL]), local_by_identity(b0[BL])
    for xml in ("bl_gamma", "bl_alpha"):
        assert bl_local[xml] == bl_before[xml], (
            f"provider {xml} keeps B's own credentials: expected {bl_before[xml]!r}, got {bl_local[xml]!r}"
        )
    assert bl_local["bl_delta"] == {"username": "", "password": ""}, (
        f"a new provider starts blank: {bl_local['bl_delta']!r}"
    )
    assert read_leaves(b, expected) == expected, (
        f"B's persisted deleted/empty leaves: expected {expected!r}, got {read_leaves(b, expected)!r}"
    )
    delta_row = row_prefix(b, BL, "bl_delta")
    assert read_leaves(b, [f"{delta_row}/title", f"{delta_row}/selected"]) == {
        f"{delta_row}/title": "",
        f"{delta_row}/selected": "",
    }, "an empty nested provider leaf did not survive the transport as ''"
    leaked = grep_leaks(b, [sentinel("A", "script_pre"), sentinel("A", "script_post")], [CONFIG])
    assert leaked == [], f"A's row-local script sentinels reached B's config: {leaked}"


# --------------------------------------------------------------------------- #
# R5 (+ X6)
# --------------------------------------------------------------------------- #


@pytest.mark.timeout(1200)  # a first send, two repeats, a send stalled until the client retries, a final repeat
def test_repeat_and_timed_out_retry_are_idempotent(ha_pair: HaPair, baseline: Baseline) -> None:
    """The same policy again is 'unchanged' and applies nothing; a send the client had to retry lands exactly once."""
    a, b = ha_pair.primary, ha_pair.secondary
    configure_sender(ha_pair, "manual")
    add_deny_group(ha_pair, baseline, f"pfbha_r5a{token()}", "198.51.100.51")
    first = sync_policy(ha_pair, "manual")
    assert_mirrored(ha_pair, first, "manual")

    sha, banners = first.b_after.installedpackages_sha256, apply_banners(b)
    for transport in TRANSPORTS:
        configure_sender(ha_pair, transport)
        again = sync_once(ha_pair, transport)
        show(f"{transport} repeat", asdict(again))
        assert_sent(again, transport, first.a_after.digest)
        assert_receive(again, "unchanged", first.a_after.digest)
        assert again.passes == 0, f"{transport}: an unchanged receive ran {again.passes} update pass(es)"
        assert node_state(b).installedpackages_sha256 == sha, (
            f"{transport}: an unchanged receive rewrote B's pfBlockerNG sections"
        )
    assert apply_banners(b) == banners, f"B ran {apply_banners(b) - banners} update pass(es) for repeats of one policy"

    # X6: A's client gives up on a stalled B after 5 s and retries; B's webgui resumes after the retry was logged.
    configure_sender(ha_pair, "manual", timeout=5)
    add_deny_group(ha_pair, baseline, f"pfbha_r5b{token()}", "198.51.100.52")
    digest = node_state(a).digest
    last_before = (receive_state(b).get("last") or {}).copy()
    t0_b, banners = node_time(b), apply_banners(b)
    retries = h.count_log_marker(a, SYSTEM_LOG, CLIENT_RETRY_MARKER)
    outcome: dict[str, BaseException] = {}

    def send() -> None:
        try:
            h.reload(a, "update", wait_unbound=False, timeout=600)
        except BaseException as exc:  # noqa: BLE001 -- re-raised in the test thread after the join
            outcome["error"] = exc

    stalled = b.ssh("pkill -STOP nginx")
    assert stalled.returncode == 0, f"could not stall B's webgui: rc={stalled.returncode} {stalled.stderr!r}"
    sender = threading.Thread(target=send)
    resumed = None
    try:
        sender.start()
        # The only completion signal for "the client's attempt timed out" is its own log line: bounded, STUCK on expiry.
        h.wait_until(lambda: h.count_log_marker(a, SYSTEM_LOG, CLIENT_RETRY_MARKER) > retries, timeout=180, interval=2)
        during = (receive_state(b).get("last") or {}).copy()
    finally:
        resumed = b.ssh("pkill -CONT nginx")
        sender.join(timeout=600)
    assert resumed.returncode == 0, f"could not resume B's webgui: rc={resumed.returncode} {resumed.stderr!r}"
    assert not sender.is_alive(), "A's apply pass never returned after B's webgui resumed"
    assert "error" not in outcome, f"A's apply pass failed: {outcome.get('error')!r}"
    assert during == last_before, (
        f"B received while its webgui was stalled, so the first attempt did not time out: {during!r}"
    )

    wait_apply(b, since=t0_b)
    settle(b)
    retried = Sync(t0_b, send_state(a), receive_state(b), apply_banners(b) - banners)
    show("timed-out retry", asdict(retried))
    assert h.count_log_marker(a, SYSTEM_LOG, CLIENT_RETRY_MARKER) > retries, "A's client never logged a retry"
    assert_sent(retried, "manual", digest)
    assert_receive(retried, "changed", digest)
    assert_applied_once(retried)
    later = sync_once(ha_pair, "manual")
    show("receive after the retry", asdict(later))
    assert_receive(later, "unchanged", digest)
    assert later.passes == 0, f"a receive after the retry ran {later.passes} update pass(es)"


# --------------------------------------------------------------------------- #
# R7 (+ X8)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("transport", TRANSPORTS)
@pytest.mark.timeout(900)  # a send, B's apply pass, and recursive on-box greps of /conf and /var/log
def test_credentials_and_local_keys_never_reach_b(ha_pair: HaPair, baseline: Baseline, transport: Transport) -> None:
    """A's six credential kinds and every ``sync: local`` key the guests keep apart never reach B: B keeps its own.

    The keys are :data:`ha_policy.LOCAL_SEEDS` (ports, interfaces, log limits, toggles, scope and so on, each with a
    node-specific value); the few left out are :data:`ha_policy.UNSEEDED_LOCAL_KEYS`, printed in the run with their
    reason. A feed URL with an embedded key is policy and arrives.
    """
    a, b = ha_pair.primary, ha_pair.secondary
    alias = f"pfbha_r7{token()}"
    keyed = f"https://feeds.invalid/{alias}.txt?apikey={sentinel('KEY', alias)}"
    secrets_a = credential_values("A")
    configure_sender(ha_pair, transport)
    # The keyed row is disabled: B stores it as policy without ever fetching it.
    keyed_row = {"header": f"{alias}_key", "url": keyed, "state": "Disabled", "format": "auto"}
    add_deny_group(ha_pair, baseline, alias, "198.51.100.71", rows=[keyed_row])
    seen_on_a = grep_leaks(a, secrets_a, [CONFIG])
    assert seen_on_a == [CONFIG], f"control: A's own credentials must be in its config.xml, grep found {seen_on_a}"
    early = grep_leaks(b, secrets_a, ["/conf", "/var/log"])
    assert early == [], f"control: A's credentials are on B before any sync: {early}"

    run = sync_policy(ha_pair, transport)

    assert_mirrored(ha_pair, run, transport)
    row = row_prefix(b, V4, alias)
    leaked = grep_leaks(b, secrets_a, ["/conf", "/var/log", h.PFB_DBDIR])
    assert leaked == [], f"{transport}: A's credentials reached B in {leaked}"
    own = local_by_identity(read_sections(b, [BL])[BL])
    expected = {
        xml: {"username": sentinel("B", f"{xml}_user"), "password": sentinel("B", f"{xml}_pass")}
        for xml in BLACKLIST_XML
    }
    assert own == expected, f"B's provider credentials: expected {expected!r}, got {own!r}"
    assert_b_keeps_its_own_values(ha_pair)
    assert_local_kept(run.b_before, run.b_after, new_rows=[row])
    stored = read_leaves(b, [f"{row}/row/1/url"])[f"{row}/row/1/url"]
    assert stored == keyed, f"the embedded-key feed URL is policy and must be on B: expected {keyed!r}, got {stored!r}"
    assert h.guest_file_contains(b, CONFIG, keyed), "the embedded-key feed URL is not in B's config.xml"


# --------------------------------------------------------------------------- #
# R8
# --------------------------------------------------------------------------- #


@pytest.mark.timeout(900)  # one real XMLRPC call, B's apply pass, section reads
def test_injected_local_leaves_are_ignored_and_listed(ha_pair: HaPair, baseline: Baseline) -> None:
    """A request with B's HA credentials that adds local fields: B's values stay and its receive record lists them."""
    a, b = ha_pair.primary, ha_pair.secondary
    alias = f"pfbha_r8{token()}"
    add_deny_group(ha_pair, baseline, alias, "198.51.100.81")
    payload = policy_payload(a)
    digest = node_state(a).digest
    injected_iface, injected_password = sentinel("INJ", "inbound_interface"), sentinel("INJ", "item_password")
    iface_path = f"{IP}/inbound_interface"
    items = payload["installedpackages"][BL]["item"]
    password_path = f"installedpackages/{BL}/item/{row_key(items, 'xml', 'bl_alpha')}/password"
    inject_leaf(payload, iface_path, injected_iface)
    inject_leaf(payload, password_path, injected_password)
    b_before = node_state(b)
    t0_b, banners = node_time(b), apply_banners(b)

    result = send_payload(ha_pair, payload)

    assert result.get("ok") is True, f"B refused the request: {result}"
    receive = receive_state(b)
    last = receive.get("last") or {}
    show("injected request B receive record", receive)
    assert last.get("time", 0) >= t0_b, f"B's receive record is stale: {last!r}"
    assert last.get("outcome") == "changed", f"B's receive outcome: expected changed, got {last!r}"
    assert sorted(last.get("ignored", [])) == sorted([iface_path, password_path]), (
        f"B's ignored paths: expected {sorted([iface_path, password_path])}, got {last!r}"
    )
    assert last.get("ignored_count") == 2, f"B's ignored_count: expected 2, got {last!r}"
    assert last.get("accepted_digest") == digest, (
        f"B accepted the injected request, so its accepted digest must be A's {digest}, got {last!r}"
    )
    assert last.get("incoming_digest") != last.get("accepted_digest"), (
        f"the incoming digest covers the injected leaves, the accepted one must not: both are {last!r}"
    )
    receive = wait_apply(b, since=t0_b)
    settle(b)
    sync = Sync(t0_b, {}, receive, apply_banners(b) - banners)
    assert_applied_once(sync)
    after = node_state(b)
    assert_local_kept(b_before, after, new_rows=[row_prefix(b, V4, alias)])
    alpha = row_prefix(b, BL, "bl_alpha")
    got = read_leaves(b, [iface_path, f"{alpha}/password"])
    expected = {iface_path: "wan", f"{alpha}/password": sentinel("B", "bl_alpha_pass")}
    assert got == expected, f"B's own values after the injected request: expected {expected!r}, got {got!r}"
    leaked = grep_leaks(b, [injected_iface, injected_password], [CONFIG, "/var/log"])
    assert leaked == [], f"the injected local values reached B's storage: {leaked}"


# --------------------------------------------------------------------------- #
# X1
# --------------------------------------------------------------------------- #


@pytest.mark.timeout(1200)  # two sends (reorder + provider update, then delete + add) and B's apply pass for each
def test_blacklist_provider_credentials_follow_their_xml(ha_pair: HaPair, baseline: Baseline) -> None:
    """Provider usernames/passwords stay B's own, keyed by xml, through reorder, update, delete and add on A."""
    a, b = ha_pair.primary, ha_pair.secondary
    configure_sender(ha_pair, "manual")
    b_creds = local_by_identity(read_sections(b, [BL])[BL])
    a_creds = local_by_identity(read_sections(a, [BL])[BL])
    items = {item["xml"]: item for item in read_sections(a, [BL])[BL]["item"]}
    alpha = {**items["bl_alpha"], "feed": "https://feeds.invalid/bl_alpha-v2.tar.gz", "title": "PFBHA bl_alpha v2"}
    delta = blacklist_item("bl_delta")
    steps: list[tuple[str, list[dict[str, str]], list[str]]] = [
        ("reorder and update", [items["bl_gamma"], alpha, items["bl_beta"]], ["bl_gamma", "bl_alpha", "bl_beta"]),
        ("delete and add", [items["bl_gamma"], alpha, delta], ["bl_gamma", "bl_alpha", "bl_delta"]),
    ]
    for name, rows, order in steps:
        write_sections(a, {BL: {"item": rows}}, f"pfBlockerNG smoke: HA providers {name}")
        before = node_state(b)

        run = sync_policy(ha_pair, "manual")

        assert_mirrored(ha_pair, run, "manual")
        assert_local_kept(before, run.b_after, rows=False)
        section = read_sections(b, [BL])[BL]
        assert identities(section) == order, f"{name}: B's providers expected {order}, got {identities(section)}"
        got = local_by_identity(section)
        expected = {xml: b_creds.get(xml, {"username": "", "password": ""}) for xml in order}
        assert got == expected, f"{name}: B's provider credentials by xml: expected {expected!r}, got {got!r}"
        feeds = {row["xml"]: row["feed"] for row in section["item"]}
        assert feeds["bl_alpha"] == alpha["feed"], (
            f"{name}: B's provider update: expected {alpha['feed']!r}, got {feeds['bl_alpha']!r}"
        )
        mine = local_by_identity(read_sections(a, [BL])[BL])
        a_expected = {xml: a_creds.get(xml, {"username": "", "password": ""}) for xml in order}
        assert mine == a_expected, f"{name}: A's own provider credentials: expected {a_expected!r}, got {mine!r}"
        leaked = grep_leaks(b, credential_values("A"), [CONFIG, "/var/log"])
        assert leaked == [], f"{name}: A's credentials reached B in {leaked}"
        assert_b_keeps_its_own_values(ha_pair)
