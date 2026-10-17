"""Smoke leg: two real pfSense guests as an HA pair across package builds (issue #3455, spec rows 6 and 9).

Node A (``pair.primary``) sends, node B (``pair.secondary``) receives. The previous build is the package ``prev_pkg``
returns: the last devel commit before the per-field sync series, where the sender still keys off ``syncinterfaces``.
The branch build is ``SMOKE_PKG``. ``ha_versions.install_build`` swaps a node between them and every phase prints a
``PFB_HA_BUILD`` line (marker verdict, package name-version, code hash) for each node it touches. Scheduled ticks stay
off (``.pfb_cron_disable``); both nodes are back on the branch build at baseline config before and after every test.

  Scenario: both nodes upgrade from the previous build, the legacy checkbox checked or unchecked (row 6)
    Given both nodes run the previous build and A holds the legacy Sync page's stored values
    When  A syncs once, both nodes upgrade, and A syncs again from the same starting point on B
    Then  the upgrade only turned the checkbox into ``syncscope`` (``lists`` / ``all``), and the same sections reach
          B by the same legacy call with the same stored content

  Scenario: the branch build sends its policy scope to a receiver still on the previous build (row 9)
    Then  B's pfBlockerNG sections are byte-identical, the package made exactly one ``restore_config_section`` call,
          A shows the target as sent, acceptance unconfirmed, and pfSense HA still syncs B's other sections

  Scenario: a sender still on the previous build syncs to a receiver on the branch build (row 9)
    Then  B stores what the previous build's legacy merge stores, and records no receive and runs no apply
"""

from __future__ import annotations

import os
import secrets
from collections.abc import Iterator
from pathlib import Path

import pytest

from . import ha_policy as hp
from . import ha_versions as hv
from . import helpers as h
from .ha_pair import SECONDARY_SYNC_IP, HaPair

pytestmark = pytest.mark.smoke

# The Sync page's checkbox as the previous build stores it, and what an upgrade makes of it.
LEGACY_TOGGLE = {"checked": "on", "unchecked": ""}
SCOPE_AFTER_UPGRADE = {"checked": "lists", "unchecked": "all"}
WHITELIST = f"{hp.DNSBL}/whitelist"
WHITELIST_A = "cGZiaGEtdmVyc2lvbnMtd2hpdGUuY29tCg=="  # base64 "pfbha-versions-white.com\n"
TARGET = f"{SECONDARY_SYNC_IP}:443"


@pytest.fixture(scope="module")
def baseline(ha_pair: HaPair) -> Iterator[hp.Baseline]:
    """Both nodes on the branch build with the shared HA policy baseline; the branch build is restored at the end."""
    yield hp.arrange_baseline(ha_pair)
    hv.restore_branch(ha_pair)


@pytest.fixture(autouse=True)
def _pair_on_the_branch_build_at_baseline(ha_pair: HaPair, baseline: hp.Baseline, prev_pkg: Path) -> Iterator[None]:
    """Each test starts on the branch build at the baseline config, and the next one finds the same."""
    hv.put_back(ha_pair, baseline)
    yield
    hv.put_back(ha_pair, baseline)


@pytest.mark.parametrize("variant", ["checked", "unchecked"])
@pytest.mark.timeout(900)  # four package swaps, two update passes and two syslog windows exceed the 30 s default
def test_upgrade_from_previous_build_keeps_legacy_sync(ha_pair: HaPair, prev_pkg: Path, variant: str) -> None:
    """Upgrading both nodes turns the legacy checkbox into ``syncscope`` and changes nothing A sends or B stores."""
    a, b = ha_pair.primary, ha_pair.secondary
    branch = Path(os.environ["SMOKE_PKG"])
    toggle, scope = LEGACY_TOGGLE[variant], SCOPE_AFTER_UPGRADE[variant]
    password = ha_pair.sync_password

    # Given both nodes run the previous build, A holding the legacy Sync page's values and B a legacy receiver's.
    for node, vm in (("A", a), ("B", b)):
        hv.install_build(vm, prev_pkg, "previous", node=node, phase="before the upgrade")
    hp.set_leaves(
        a,
        {hp.SYNC: hv.legacy_sync_section("manual", toggle=toggle, password=password)},
        "pfBlockerNG smoke: legacy sender",
        secret_values=[password],
    )
    hp.set_leaves(
        b,
        {hp.SYNC: {"varsynconchanges": "disabled", "varsynctimeout": "150", "syncinterfaces": toggle}},
        "pfBlockerNG smoke: legacy receiver",
    )
    names = hv.sync_section_names(a, with_settings=toggle != "on")
    b_start = hv.pfb_sections(b)

    # When A syncs once on the previous build.
    with hv.LogWindow(a) as a_log, hv.LogWindow(b) as b_log:
        h.reload(a, "update", wait_unbound=False)
    a_legacy = hv.pfb_sections(a)
    payload = [name for name in names if a_legacy.get(name) is not None]
    differing = [name for name in payload if a_legacy[name] != b_start.get(name)]
    assert "pfblockernglistsv4" in differing, (
        f"non-vacuity: A's lists must differ from B's before the sync: {differing}"
    )
    if variant == "unchecked":
        assert {"pfblockerngipsettings", "pfblockerngdnsblsettings"} <= set(differing), (
            f"non-vacuity: the settings sections must differ so the unchecked box shows: {differing}"
        )
    calls = hv.package_xmlrpc(a_log.text)
    assert (calls.begun, calls.methods, len(calls.lines)) == (1, ["merge_installedpackages_section"], 2), (
        f"expected one merge_installedpackages_section call from the previous build, got {calls}"
    )
    assert hv.package_writes(b_log.text) == [payload], (
        f"B's merged sections: expected {[payload]!r}, got {hv.package_writes(b_log.text)!r}"
    )
    b_legacy = hv.pfb_sections(b)
    hv.assert_sections(
        {name: b_legacy.get(name) for name in payload},
        {name: a_legacy[name] for name in payload},
        "the legacy result on B: the synced sections are A's",
    )
    rest = {name: tree for name, tree in b_legacy.items() if name not in payload}
    hv.assert_sections(rest, {n: t for n, t in b_start.items() if n not in payload}, "B's sections outside the payload")
    hv.evidence(
        "legacy-sync",
        variant=variant,
        a_package_calls=calls.methods,
        b_pfb_writes=hv.package_writes(b_log.text),
        payload=payload,
        differing_before=differing,
    )

    # And both nodes upgrade to the branch build.
    for node, vm in (("A", a), ("B", b)):
        hv.install_build(vm, branch, "branch", node=node, phase="after the upgrade")
        # Read raw, with no package code run since the install: the install hook did the migration, not a later page.
        stored = (h.config_get_state(vm, hv.SYNCSCOPE), h.config_get_state(vm, hv.SYNCINTERFACES))
        assert stored == ((True, scope), (False, "")), (
            f"{node}: expected syncscope {scope!r} and no syncinterfaces straight after the install, got {stored}"
        )
    a_up, b_up = hv.pfb_sections(a), hv.pfb_sections(b)
    for node, before, after in (("A", a_legacy, a_up), ("B", b_legacy, b_up)):
        delta = hp.diff_leaves(hv.flatten_sections(before), hv.flatten_sections(after))
        assert delta == hv.migration_delta(toggle, scope), (
            f"{node}: the upgrade must only turn the checkbox into syncscope; moved: {delta}"
        )
        hv.evidence("upgrade-delta", variant=variant, node=node, moved=delta)

    # When A syncs again, with B back at the content it had before the first sync.
    hp.write_sections(b, {name: b_start.get(name) for name in payload}, "pfBlockerNG smoke: B before the sync")
    hv.assert_sections(
        {name: hv.pfb_sections(b).get(name) for name in payload},
        {name: b_start.get(name) for name in payload},
        "B must start the second sync where it started the first",
    )
    hp.clear_sync_state(a)
    banners = hp.apply_banners(b)
    with hv.LogWindow(a) as a_log, hv.LogWindow(b) as b_log:
        h.reload(a, "update", wait_unbound=False)

    # Then the same sections reach B by the same legacy call and B stores the same content.
    (attempt,) = hp.send_state(a).get("attempts") or [{}]
    assert (attempt.get("target"), attempt.get("outcome")) == (TARGET, "sent"), f"A's send attempt: got {attempt!r}"
    assert "digest" not in attempt, f"a legacy scope carries no policy digest, got {attempt!r}"
    calls = hv.package_xmlrpc(a_log.text)
    assert (calls.begun, calls.methods, len(calls.lines)) == (1, ["merge_installedpackages_section"], 2), (
        f"expected the same merge_installedpackages_section call after the upgrade, got {calls}"
    )
    assert hv.package_writes(b_log.text) == [payload], (
        f"B's merged sections after the upgrade: expected {[payload]!r}, got {hv.package_writes(b_log.text)!r}"
    )
    a_new, b_new = hv.pfb_sections(a), hv.pfb_sections(b)
    hv.assert_sections(
        {name: b_new.get(name) for name in payload},
        {name: a_new[name] for name in payload},
        "the result on B after the upgrade: the synced sections are A's",
    )
    hv.assert_sections(
        {name: b_new.get(name) for name in payload},
        {name: b_legacy.get(name) for name in payload},
        "the receive result must be preserved across the upgrade",
    )
    hv.assert_sections(
        {n: t for n, t in b_new.items() if n not in payload},
        {n: t for n, t in b_up.items() if n not in payload},
        "B's sections outside the payload",
    )
    # A legacy receive records nothing and applies nothing; asserted after a drain, never before.
    assert hp.in_flight(b) == [], f"B has an apply in flight after a legacy receive: {hp.in_flight(b)}"
    hp.settle(b)
    assert hp.receive_state(b) == {}, f"a legacy receive must leave no receive record, got {hp.receive_state(b)}"
    assert hp.apply_banners(b) == banners, "B ran an update pass for a legacy receive"
    hv.evidence(
        "after-upgrade-sync",
        variant=variant,
        a_send_record=hp.send_state(a),
        a_package_calls=calls.methods,
        b_pfb_writes=hv.package_writes(b_log.text),
        payload=payload,
        b_receive_record=hp.receive_state(b),
        b_update_passes=hp.apply_banners(b) - banners,
    )


@pytest.mark.parametrize("transport", hp.TRANSPORTS)
@pytest.mark.timeout(900)  # a package swap, a full update pass, a core HA sync and a web login exceed the 30 s default
def test_new_policy_sender_leaves_previous_receiver_untouched(
    ha_pair: HaPair, prev_pkg: Path, transport: hp.Transport
) -> None:
    """A policy send to a receiver on the previous build changes none of its pfBlockerNG storage."""
    a, b = ha_pair.primary, ha_pair.secondary
    sentinel = f"pfb_smoke_ha_{secrets.token_hex(4)}"
    alias = hv.sentinel_alias_php(sentinel, "192.0.2.80")

    # Given A (branch) sends its policy scope and B runs the previous build, with a policy A has and B lacks.
    hv.install_build(b, prev_pkg, "previous", node="B", phase="receiver on the previous build")
    hv.announce(a, "A", "sender on the branch build")
    hp.configure_sender(ha_pair, transport, scope="policy")
    hp.set_leaves(a, {WHITELIST: WHITELIST_A}, "pfBlockerNG smoke: policy edit on A")
    a_state = hp.node_state(a)
    b_policy = hp.read_leaves(b, list(a_state.projection))
    assert WHITELIST in a_state.projection and b_policy[WHITELIST] != a_state.projection[WHITELIST], (
        f"non-vacuity: A's whitelist must be in its projection and differ from B's: {b_policy.get(WHITELIST)!r}"
    )
    b_hashes, b_trees = hv.pfb_hashes(b), hv.pfb_sections(b)
    if transport == "automatic":
        hp.php_write(a, alias, "pfBlockerNG smoke: HA sentinel alias")

    # When A sends once.
    with hv.LogWindow(a) as a_log, hv.LogWindow(b) as b_log:
        hp.trigger_send(ha_pair, transport)
    hv.wait_sync_idle(a)
    hp.wait_filter_idle(b)

    # Then A's record and panel show the send, and the package made no call of its own beyond the one it should.
    digest = a_state.digest
    hp.assert_sent(hp.Sync(0, hp.send_state(a), {}, 0), transport, digest)
    calls = hv.package_xmlrpc(a_log.text)
    rows = hv.sender_panel_rows(a)
    assert len(rows) == 1 and rows[0][2] == digest, f"sender panel: expected one row carrying {digest!r}, got {rows!r}"
    if transport == "manual":
        assert (calls.begun, calls.methods, len(calls.lines)) == (1, ["restore_config_section"], 2), (
            f"the package must make exactly one restore_config_section call, got {calls}"
        )
        assert hv.package_writes(b_log.text) == [[]], (
            f"B must log one receive that merged no pfBlockerNG section, got {hv.package_writes(b_log.text)!r}"
        )
        assert (rows[0][0], rows[0][3]) == (TARGET, "sent, acceptance unconfirmed"), f"sender panel row: {rows[0]!r}"
        hp.core_ha_on(ha_pair)  # the baseline keeps pfSense HA sync off A; this second send rides it
        hp.php_write(a, alias, "pfBlockerNG smoke: HA sentinel alias")
        hp.trigger_send(ha_pair, "automatic")
        hv.wait_sync_idle(a)
        hp.wait_filter_idle(b)
    else:
        assert calls.lines == [], f"in automatic mode core sends; the package made calls of its own: {calls}"
        assert (rows[0][0], rows[0][3]) == ("pfSense HA sync", "handed to pfSense HA sync"), f"panel row: {rows[0]!r}"
        synced = [
            ln for ln in a_log.text.splitlines() if "rc.filter_synchronize" in ln and "restore_config_section" in ln
        ]
        assert synced, "pfSense's own HA sync never reported a restore_config_section success towards B"
    assert h.guest_file_contains(b, hp.CONFIG, sentinel), (
        "B's other sections did not follow pfSense HA: no sentinel alias"
    )
    assert hv.pfb_hashes(b) == b_hashes, "B's pfBlockerNG sections changed: not byte-identical"
    hv.assert_sections(hv.pfb_sections(b), b_trees, "B's pfBlockerNG sections")
    hv.evidence(
        "new-sender-previous-receiver",
        transport=transport,
        a_send_record=hp.send_state(a),
        a_package_calls=calls.methods,
        a_panel_row=rows[0],
        b_pfb_writes=hv.package_writes(b_log.text),
        b_pfb_sections_byte_identical=True,
        b_sentinel_alias_arrived=True,
    )


@pytest.mark.parametrize("transport", hp.TRANSPORTS)
@pytest.mark.timeout(900)  # a package swap, a full update pass or core HA sync, and the drains exceed the 30 s default
def test_previous_sender_keeps_legacy_semantics_on_new_receiver(
    ha_pair: HaPair, prev_pkg: Path, transport: hp.Transport
) -> None:
    """A previous-build sender's legacy sync lands on a branch-build receiver exactly as it does on a previous one."""
    a, b = ha_pair.primary, ha_pair.secondary
    password = ha_pair.sync_password

    # Given A runs the previous build with the unchecked legacy box, B the branch build.
    hv.install_build(a, prev_pkg, "previous", node="A", phase="sender on the previous build")
    hv.announce(b, "B", "receiver on the branch build")
    b_start = hv.pfb_sections(b)  # B as it was before A sent anything
    hp.set_leaves(
        a,
        {hp.SYNC: hv.legacy_sync_section(transport, toggle="", password=password)},
        "pfBlockerNG smoke: legacy sender",
        secret_values=[password],
    )
    a_sent = hv.pfb_sections(a)
    payload = [name for name in hv.sync_section_names(a, with_settings=True) if a_sent.get(name) is not None]
    differing = [name for name in payload if a_sent[name] != b_start.get(name)]
    assert {"pfblockernglistsv4", "pfblockerngipsettings"} <= set(differing), (
        f"non-vacuity: A's sections must differ from B's before the sync: {differing}"
    )
    if transport == "automatic":
        hp.core_ha_on(ha_pair)  # the baseline keeps pfSense HA sync off A; the automatic transport rides it
    banners = hp.apply_banners(b)

    # When A syncs once.
    with hv.LogWindow(a) as a_log, hv.LogWindow(b) as b_log:
        hp.trigger_send(ha_pair, transport)
    hv.wait_sync_idle(a)
    hp.wait_filter_idle(b)

    # Then B holds what the previous build's legacy merge stores, by the legacy call.
    calls = hv.package_xmlrpc(a_log.text)
    if transport == "manual":
        assert (calls.begun, calls.methods, len(calls.lines)) == (1, ["merge_installedpackages_section"], 2), (
            f"expected the previous build's one merge_installedpackages_section call, got {calls}"
        )
        assert hv.package_writes(b_log.text) == [payload], (
            f"B's merged sections: expected {[payload]!r}, got {hv.package_writes(b_log.text)!r}"
        )
        merged = {name: a_sent[name] for name in payload}
    else:
        assert calls.lines == [], f"in automatic mode core sends; the previous build made calls of its own: {calls}"
        merged = {name: hv.legacy_auto_merge(b_start.get(name), a_sent[name]) for name in payload}
    expected = {**b_start, **merged}
    hv.assert_sections(hv.pfb_sections(b), expected, f"B after a legacy {transport} sync")
    # Legacy receives record nothing and apply nothing; asserted after a drain, never before.
    assert hp.in_flight(b) == [], f"B has an apply in flight after a legacy receive: {hp.in_flight(b)}"
    hp.settle(b)
    assert hp.receive_state(b) == {}, f"a legacy receive must leave no receive record, got {hp.receive_state(b)}"
    assert hp.apply_banners(b) == banners, "B ran an update pass for a legacy receive"
    hv.evidence(
        "previous-sender-new-receiver",
        transport=transport,
        a_package_calls=calls.methods,
        b_pfb_writes=hv.package_writes(b_log.text),
        payload=payload,
        b_receive_record=hp.receive_state(b),
        b_update_passes=hp.apply_banners(b) - banners,
    )
