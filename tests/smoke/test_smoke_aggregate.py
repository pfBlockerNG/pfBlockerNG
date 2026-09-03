"""ADR-11 — live-VM smoke coverage for the opt-in per-type aggregate ("Uber") aliases.

pfBlockerNG can build, per SELECTED action type x family, a Native ``urltable`` alias
``pfB_<Type>_Aggregated_<family>`` (Type in {Deny,Permit,Match,Native}, family in
{v4,v6}) = the deduped/``iprange``d union of that type's effective dir. The multi-select
``pfb_agg_types`` (IP settings, opt-in, default ``""`` = none) gates it. The build
runs IN the update pass (``sync_package_pfblockerng`` -> ``pfb_build_aggregate_aliases``,
``inc:2144``, called ``inc:11116``): for each selected type it writes the member union,
runs ``pfblockerng.sh aggregate`` (cat | sort -u | iprange, rebuilt on a member's mtime),
registers the Native alias (NEVER ``pfb_firewall_rule`` -- no rule), and writes a never-empty
``.lst`` consumer file. A deselected / disabled type is torn down (alias/table/files removed).
Whether that rebuild counts as a CHANGE is decided on the aggregate's canonical content, not on
its mtime (issue #3156): only a changed aggregate is loaded INLINE (``pfctl -T replace``) and
merged into ``$pfb['changed_ip_aliases']`` -> the ADR-12 ``post`` hook's
``PFB_CHANGED_IP_ALIASES`` -- and the build/load completes BEFORE the ``post`` hook fires.

These tests drive the REAL production path: ``helpers.reload(vm, scope)`` runs the same
``pfblockerng.php <scope>`` CLI the GUI/cron use, which calls ``sync_package_pfblockerng``
and so builds the aggregates + fires the hooks. We observe the result via ``pfctl``
(table presence + members + rule references), the on-box ``.lst`` consumer file, and -- for
the post-hook freshness leg -- an env-dump + ``pfctl -T show`` ``post`` hook whose markers
we read straight back over SSH (the hook runs as root in host context, not chrooted).

WHAT THIS FILE AUTOMATES (ADR §7 manual-smoke checklist):

* **None selected = no-op** -- ``pfb_agg_types=""`` + an injected Deny member ⇒ the
  ``pfB_Deny_Aggregated_v4`` table is ABSENT and its ``.lst`` does not exist (the OFF
  branch / byte-identical baseline).
* **Deny aggregate on + Native = no rule** -- select ``["Deny"]`` ⇒ the table is built
  with the fed IP and ``pfctl_rule_has_alias`` is FALSE (Native ⇒ no firewall rule); the
  member table ``pfB_<x>_v4`` stays present (additive).
* **Cross-type, no leakage** -- a Permit member with ``["Permit"]`` selected ⇒ its IP is
  in ``pfB_Permit_Aggregated_v4`` and ABSENT from ``pfB_Deny_Aggregated_v4`` (which is
  not selected, so its table is never built). The per-type membership half is pinned
  off-box in ``tests/php/AggregateMemberListTest.php``; this is the live end-to-end half.
* **All-combinations additive** -- select ``["Deny"]`` then ``["Deny","Permit"]`` with a
  deny + a permit member ⇒ both aggregates present with the right contents, and the
  existing member tables stay present/unchanged (before-state asserted first).
* **Never-empty consumer file on an empty union** -- a selected type with NO members
  (``["Match"]`` + no Match member) ⇒ the ``.lst`` EXISTS and is non-empty (a ``#``
  placeholder) and NO pf table is loaded (absent/empty).
* **Teardown on deselect** -- select ``["Deny"]`` (table + ``.lst`` exist), then
  ``set_aggregate_types(vm, [])`` + reload ⇒ table gone, ``.lst`` removed (before/after).
* **Post-hook fires after the aggregate is ready** (the headline requirement) -- a
  ``post`` hook dumps the live aggregate table + its env; after a Deny member-feed change
  the hook sees the FRESH (new-IP) table, and ``PFB_CHANGED_IP_ALIASES`` contains
  ``pfB_Deny_Aggregated_v4``. The before-state (the pre-change table did NOT contain the
  new IP) proves the change CAUSED it -- not a stale read.
* **Deny incl DNSBLIP** -- a ``DnsblCase`` whose feed embeds an IP literal with
  ``dnsbl_ip_action="Deny_Both"`` collects that IP into ``pfB_DNSBLIP_v4`` (denydir), so
  with ``["Deny"]`` selected it folds into ``pfB_Deny_Aggregated_v4``.

WHAT STAYS MAINTAINER-MANUAL (ADR §7, the smoke image cannot exercise it):

* **HAProxy referenceability** (ADR §7 E) -- no HAProxy package on the smoke image, so the
  ``ipalias_pfB_Deny_Aggregated_v4.lst`` emission (``is_alias()`` + expansion) cannot be
  asserted here. Remains the ADR §7 manual checklist item.
* **Effective post-suppression CONTENT spot-check** (ADR §7 A -- a suppressed/whitelisted
  IP ABSENT, a Deny-action GeoIP continent IP PRESENT) and the **power-set byte-identity**
  sweep (ADR §7 B) stay maintainer-manual: they need the real ``suppress`` pass / a MaxMind
  GeoIP download / a full power-set walk that this targeted CI leg does not reproduce. The
  membership decision behind them is pinned off-box in ``AggregateMemberListTest.php``.

DESELECTED from the default ``python -m pytest`` (``--ignore=tests/smoke``). Run only by the
smoke workflow::

    python -m pytest tests/smoke -m smoke --override-ini="addopts="

These need the booted ``smoke_vm`` fixture, the branch ``.pkg`` (``SMOKE_PKG``), and the
smoke deps; without them they skip cleanly.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from . import helpers as h
from .conftest import SmokeVM, _StubDnsServer

pytestmark = pytest.mark.smoke


@pytest.fixture(scope="module")
def deployed_vm(smoke_vm: SmokeVM, stub_dns: _StubDnsServer) -> Iterator[SmokeVM]:  # noqa: ARG001
    """Deploy the branch .pkg once for the aggregate module (mirrors the hooks module).

    Egress stays OPEN across every reload: the update path builds DNSBL too
    (``pfb_create_dnsbl``) and a dark egress deadlocks the guest. ``ensure_dnsbl_vip`` +
    ``use_system_dns_upstream`` give DNSBL a sinkhole VIP + a reachable upstream so the
    DNSBLIP leg has real work. Hooks AND the aggregate selector are cleared up front AND
    on teardown so no stray hook/selection bleeds into another module's reloads. The
    session VM is torn down at end of run, so collect a full guest snapshot on teardown.
    """
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    h.snapshot_unbound_conf(smoke_vm)
    h.ensure_dnsbl_vip(smoke_vm)
    h.use_system_dns_upstream(smoke_vm)
    # Defensive: start from a known-clean hook list AND no aggregate selection so nothing
    # left over from an earlier module/run can fire or build during this module's reloads.
    h.clear_update_hooks(smoke_vm)
    h.set_aggregate_types(smoke_vm, [])
    try:
        yield smoke_vm
    finally:
        # Leave NO hooks and NO aggregate selection behind, then a final update so any
        # aggregate this module built is torn down before the next module's reloads. Then
        # collect diagnostics (best-effort, never masks a result).
        h.clear_update_hooks(smoke_vm)
        h.set_aggregate_types(smoke_vm, [])
        try:
            h.reload(smoke_vm, "update")
        except Exception as exc:  # noqa: BLE001 -- teardown cleanup, never mask the test result
            print(f"[smoke] aggregate teardown reload failed (non-fatal): {exc}")
        h.unblock_egress()
        h.collect_host_diagnostics(smoke_vm)


def _table_absent_or_empty(vm: SmokeVM, name: str) -> bool:
    """True iff pf table ``name`` is not loaded at all, or loaded but empty.

    An empty union is torn down to ``pfctl -T kill`` (table absent); we also accept a
    present-but-empty table so the assertion is robust to either realisation of "no
    members" — both satisfy the ADR contract "no empty table loaded with content".
    """
    if name not in h.pfctl_tables(vm):
        return True
    return h.pfctl_table_members(vm, name) == []


# --------------------------------------------------------------------------- #
# 1) None selected = no-op — the OFF branch / byte-identical baseline
# --------------------------------------------------------------------------- #


def test_aggregate_none_selected_is_noop(deployed_vm: SmokeVM) -> None:
    """``pfb_agg_types=""`` ⇒ NO aggregate alias/table/file is built (the OFF branch).

    With no type selected, ``pfb_build_aggregate_aliases`` registers/builds nothing —
    a Deny member is still injected and processed normally, but ``pfB_Deny_Aggregated_v4``
    must be ABSENT from ``pfctl -sTables`` and its ``.lst`` consumer file must not exist.
    Asserting on a freshly-injected Deny member (whose OWN member table DOES build) makes
    "absent" meaningful: the denydir is non-empty, yet the aggregate is still not created
    because nothing is selected.
    """
    agg = h.aggregate_table("Deny", "v4")
    consumer = h.aggregate_consumer_path("Deny", "v4")

    h.set_aggregate_types(deployed_vm, [])
    feed = h.write_local_feed(deployed_vm, "agg_noop_deny.txt", "198.51.100.10\n")
    spec = h.IpCase(aliasname="aggnoop", feed_url=feed, header="aggnoop", action="Deny_Both")
    h.inject(deployed_vm, spec)
    h.reload(deployed_vm, "update")
    h.apply_filter_sync(deployed_vm)

    # The member table DID build (the denydir has content) — so the aggregate's absence
    # is a real OFF-branch result, not just "nothing ran". The blocking filter apply above
    # makes the following one-shot table read authoritative.
    assert h.pfctl_table_members(deployed_vm, spec.alias), (
        f"member table {spec.alias} missing — injection did not build"
    )
    assert agg not in h.pfctl_tables(deployed_vm), f"aggregate {agg} built with NOTHING selected (OFF branch broken)"
    assert deployed_vm.ssh("test", "-f", consumer).returncode != 0, (
        f"aggregate consumer {consumer} exists with NOTHING selected (OFF branch broken)"
    )


# --------------------------------------------------------------------------- #
# 2) Deny aggregate on + Native = NO firewall rule
# --------------------------------------------------------------------------- #


def test_aggregate_deny_builds_table_native_no_rule(deployed_vm: SmokeVM) -> None:
    """Selecting ``["Deny"]`` builds ``pfB_Deny_Aggregated_v4`` (fed IP present), NO rule.

    Scenario: a Deny member feed + the Deny aggregate selected.
      Given a Deny ``IpCase`` whose feed lists ``198.51.100.11`` and the member table
        ``pfB_aggdeny_v4`` therefore builds,
      When ``pfb_agg_types`` selects ``["Deny"]`` and a full ``update`` runs,
      Then ``pfB_Deny_Aggregated_v4`` is loaded and CONTAINS the fed IP (the union of the
        denydir), and ``pfctl_rule_has_alias(pfB_Deny_Aggregated_v4)`` is FALSE — Native means
        NO firewall rule, the load-bearing ADR-11 contract. The member table stays present
        (the aggregate is ADDITIVE — it does not consume/replace the per-feed table).
    """
    fed_ip = "198.51.100.11"
    agg = h.aggregate_table("Deny", "v4")

    feed = h.write_local_feed(deployed_vm, "agg_deny_member.txt", f"{fed_ip}\n")
    spec = h.IpCase(aliasname="aggdeny", feed_url=feed, header="aggdeny", action="Deny_Both")
    h.inject(deployed_vm, spec)
    h.set_aggregate_types(deployed_vm, ["Deny"])
    h.reload(deployed_vm, "update")
    h.apply_filter_sync(deployed_vm)

    members = h.pfctl_table_members(deployed_vm, agg)
    assert h.member_present(members, fed_ip), f"fed Deny IP {fed_ip} not in aggregate {agg}: {members}"
    # Native ⇒ no firewall rule references the aggregate alias.
    assert not h.pfctl_rule_has_alias(deployed_vm, agg), (
        f"aggregate {agg} is referenced by a pf rule — Native must add NONE"
    )
    # Additive: the per-feed member table is untouched/present alongside the aggregate
    # One sync covers both member-table reads below.
    assert h.pfctl_table_members(deployed_vm, spec.alias), (
        f"member table {spec.alias} vanished — aggregate not additive"
    )
    assert h.member_present(h.pfctl_table_members(deployed_vm, spec.alias), fed_ip), (
        f"member table {spec.alias} lost {fed_ip} — aggregate perturbed the source table"
    )


# --------------------------------------------------------------------------- #
# 3) Cross-type — a Permit member does NOT leak into the Deny aggregate
# --------------------------------------------------------------------------- #


def test_aggregate_permit_does_not_leak_into_deny(deployed_vm: SmokeVM) -> None:
    """A Permit member with ``["Permit"]`` selected lands in the Permit aggregate ONLY.

    Scenario: a Permit-action member + only the Permit aggregate selected.
      Given a ``Permit_Both`` ``IpCase`` (its member file lands in permitdir) and
        ``pfb_agg_types=["Permit"]`` (Deny NOT selected),
      When a full ``update`` runs,
      Then the fed IP is in ``pfB_Permit_Aggregated_v4`` AND ``pfB_Deny_Aggregated_v4`` is
        absent/empty (never built — Deny is unselected) and certainly does not contain the
        Permit IP. This is the live end-to-end half of the no-cross-type-leakage contract
        (the membership half is unit-pinned in ``AggregateMemberListTest.php``).
    """
    fed_ip = "198.51.100.12"
    permit_agg = h.aggregate_table("Permit", "v4")
    deny_agg = h.aggregate_table("Deny", "v4")

    feed = h.write_local_feed(deployed_vm, "agg_permit_member.txt", f"{fed_ip}\n")
    spec = h.IpCase(aliasname="aggpermit", feed_url=feed, header="aggpermit", action="Permit_Both")
    h.inject(deployed_vm, spec)
    h.set_aggregate_types(deployed_vm, ["Permit"])
    h.reload(deployed_vm, "update")
    h.apply_filter_sync(deployed_vm)

    permit_members = h.pfctl_table_members(deployed_vm, permit_agg)
    assert h.member_present(permit_members, fed_ip), f"Permit IP {fed_ip} not in {permit_agg}: {permit_members}"
    # Deny aggregate is NOT selected ⇒ never built ⇒ absent/empty and free of the Permit IP.
    assert _table_absent_or_empty(deployed_vm, deny_agg), (
        f"{deny_agg} exists with content though Deny is NOT selected: {h.pfctl_tables(deployed_vm)}"
    )
    if deny_agg in h.pfctl_tables(deployed_vm):
        assert not h.member_present(h.pfctl_table_members(deployed_vm, deny_agg), fed_ip), (
            f"Permit IP {fed_ip} LEAKED into {deny_agg} — cross-type isolation broken"
        )


# --------------------------------------------------------------------------- #
# 4) Additive across a combination — {Deny} then {Deny,Permit}
# --------------------------------------------------------------------------- #


def test_aggregate_additive_across_combination(deployed_vm: SmokeVM) -> None:
    """Selecting ``["Deny"]`` then ``["Deny","Permit"]`` adds the Permit aggregate only.

    Scenario: a deny member + a permit member; grow the selection from one type to two.
      Given both an injected Deny member (``198.51.100.13``) and a Permit member
        (``198.51.100.14``),
      Given (BEFORE) ``pfb_agg_types=["Deny"]`` + update ⇒ ``pfB_Deny_Aggregated_v4``
        holds the deny IP while ``pfB_Permit_Aggregated_v4`` is absent (only Deny built),
      When the selection grows to ``["Deny","Permit"]`` and a full ``update`` runs,
      Then BOTH aggregates are present with the right contents, AND the existing member
        tables (``pfB_aggcombo_deny_v4`` / ``pfB_aggcombo_permit_v4``) stay present and
        still hold their IPs (unchanged) — proving adding the second aggregate is additive,
        not a rebuild that perturbs the per-feed tables. The before-state (Permit aggregate
        absent at ``["Deny"]``) proves the second select CAUSED the Permit aggregate.
    """
    deny_ip = "198.51.100.13"
    permit_ip = "198.51.100.14"
    deny_agg = h.aggregate_table("Deny", "v4")
    permit_agg = h.aggregate_table("Permit", "v4")

    deny_feed = h.write_local_feed(deployed_vm, "agg_combo_deny.txt", f"{deny_ip}\n")
    permit_feed = h.write_local_feed(deployed_vm, "agg_combo_permit.txt", f"{permit_ip}\n")
    deny_spec = h.IpCase(aliasname="aggcombodeny", feed_url=deny_feed, header="aggcombodeny", action="Deny_Both")
    permit_spec = h.IpCase(
        aliasname="aggcombopermit", feed_url=permit_feed, header="aggcombopermit", action="Permit_Both"
    )
    # BOTH lists in ONE config write — a second h.inject() to the same v4 root would REPLACE
    # the first (config_set_path(root, array($list))), leaving only the permit list and
    # silently voiding the "Deny+Permit together" premise.
    h.inject_ip_lists(deployed_vm, [deny_spec, permit_spec])

    # BEFORE: only Deny selected ⇒ Deny aggregate present, Permit aggregate absent.
    h.set_aggregate_types(deployed_vm, ["Deny"])
    h.reload(deployed_vm, "update")
    h.apply_filter_sync(deployed_vm)
    deny_members_before = h.pfctl_table_members(deployed_vm, deny_agg)
    assert h.member_present(deny_members_before, deny_ip), f"Deny IP {deny_ip} not in {deny_agg}: {deny_members_before}"
    assert _table_absent_or_empty(deployed_vm, permit_agg), (
        f"{permit_agg} present though only Deny selected: {h.pfctl_tables(deployed_vm)}"
    )

    # AFTER: grow to {Deny,Permit} ⇒ both aggregates present with their own contents.
    h.set_aggregate_types(deployed_vm, ["Deny", "Permit"])
    h.reload(deployed_vm, "update")
    h.apply_filter_sync(deployed_vm)
    assert h.member_present(h.pfctl_table_members(deployed_vm, deny_agg), deny_ip), (
        f"Deny IP {deny_ip} dropped from {deny_agg} after adding Permit"
    )
    assert h.member_present(h.pfctl_table_members(deployed_vm, permit_agg), permit_ip), (
        f"Permit IP {permit_ip} not in {permit_agg} after selecting it"
    )
    # The per-feed member tables are unchanged (additive): both still present + hold their IP.
    assert h.member_present(h.pfctl_table_members(deployed_vm, deny_spec.alias), deny_ip), (
        f"member table {deny_spec.alias} changed — aggregate combination perturbed it"
    )
    assert h.member_present(h.pfctl_table_members(deployed_vm, permit_spec.alias), permit_ip), (
        f"member table {permit_spec.alias} changed — aggregate combination perturbed it"
    )


# --------------------------------------------------------------------------- #
# 5) Never-empty consumer file on an EMPTY union
# --------------------------------------------------------------------------- #


def test_aggregate_empty_union_writes_never_empty_consumer(deployed_vm: SmokeVM) -> None:
    """A selected type with NO members still writes a non-empty ``.lst`` (placeholder).

    Scenario: select a type whose dir has zero members for the family.
      Given NO Match member is injected (matchdir empty for v4),
      When ``pfb_agg_types=["Match"]`` and a full ``update`` runs,
      Then the consumer file ``pfB_Match_Aggregated_v4.lst`` EXISTS and is non-empty (a
        ``#`` placeholder line, so a downstream ``-f`` consumer never trips empty-file
        validation — the ADR-11 never-empty contract), AND no pf table is loaded with
        content (the empty union is killed, not loaded as an empty table).
    """
    consumer = h.aggregate_consumer_path("Match", "v4")
    agg = h.aggregate_table("Match", "v4")

    h.set_aggregate_types(deployed_vm, ["Match"])
    h.reload(deployed_vm, "update")
    h.apply_filter_sync(deployed_vm)

    assert deployed_vm.ssh("test", "-f", consumer).returncode == 0, f"never-empty consumer {consumer} missing"
    body = deployed_vm.ssh("cat", consumer).stdout
    assert body.strip() != "", f"consumer {consumer} is empty — never-empty contract broken (body={body!r})"
    assert _table_absent_or_empty(deployed_vm, agg), (
        f"an empty-union aggregate {agg} was loaded with content: {h.pfctl_table_members(deployed_vm, agg)}"
    )


# --------------------------------------------------------------------------- #
# 6) Teardown on deselect — table + .lst removed
# --------------------------------------------------------------------------- #


def test_aggregate_teardown_on_deselect(deployed_vm: SmokeVM) -> None:
    """Deselecting a type removes its aggregate table + consumer file (no orphans).

    Scenario: build the Deny aggregate, then deselect everything.
      Given (BEFORE) ``pfb_agg_types=["Deny"]`` + a Deny member + update ⇒
        ``pfB_Deny_Aggregated_v4`` is loaded AND its ``.lst`` exists,
      When ``set_aggregate_types(vm, [])`` + a full ``update`` runs,
      Then the pf table is GONE from ``pfctl -sTables`` and the ``.lst`` is removed.
      The before-state (table + file present) proves the deselect CAUSED the teardown.
    """
    fed_ip = "198.51.100.15"
    agg = h.aggregate_table("Deny", "v4")
    consumer = h.aggregate_consumer_path("Deny", "v4")

    feed = h.write_local_feed(deployed_vm, "agg_teardown_deny.txt", f"{fed_ip}\n")
    spec = h.IpCase(aliasname="aggteardown", feed_url=feed, header="aggteardown", action="Deny_Both")
    h.inject(deployed_vm, spec)

    # BEFORE: Deny selected ⇒ table + consumer exist.
    h.set_aggregate_types(deployed_vm, ["Deny"])
    h.reload(deployed_vm, "update")
    h.apply_filter_sync(deployed_vm)
    assert h.member_present(h.pfctl_table_members(deployed_vm, agg), fed_ip), f"{agg} not built before teardown"
    assert deployed_vm.ssh("test", "-f", consumer).returncode == 0, f"consumer {consumer} missing before teardown"

    # AFTER: deselect everything ⇒ table gone + consumer removed.
    h.set_aggregate_types(deployed_vm, [])
    h.reload(deployed_vm, "update")
    h.apply_filter_sync(deployed_vm)
    assert agg not in h.pfctl_tables(deployed_vm), f"{agg} still loaded after deselect — teardown left an orphan table"
    assert deployed_vm.ssh("test", "-f", consumer).returncode != 0, (
        f"consumer {consumer} still present after deselect — teardown left an orphan file"
    )


# --------------------------------------------------------------------------- #
# 7) ★ Post-hook fires AFTER the aggregate is ready (the headline requirement) ★
# --------------------------------------------------------------------------- #


def test_aggregate_post_hook_sees_fresh_table_and_changed_alias(deployed_vm: SmokeVM) -> None:
    """A ``post`` hook sees the FRESH aggregate table + its name in PFB_CHANGED_IP_ALIASES.

    Scenario: a post hook records the live aggregate table; a Deny member-feed change.
      Given ``pfb_agg_types=["Deny"]`` + a Deny member feed, settled by one update so the
        aggregate ``pfB_Deny_Aggregated_v4`` is loaded, and a ``post`` hook whose command
        (a) dumps ``pfctl -t pfB_Deny_Aggregated_v4 -T show`` to a marker and (b) dumps the
        env to the env marker,
      Given (BEFORE) the settled aggregate does NOT yet contain the new IP,
      When the Deny feed is rewritten to ADD a new IP, its re-fetch is forced
        (``force_ip_refetch`` — even a full update reuse-caches an unchanged-on-disk feed),
        and a full ``update`` runs,
      Then (a) the table the hook recorded CONTAINS the NEW IP (the build/load ran BEFORE
        the post hook — the hook never saw the stale pre-update table), and (b) the hook's
        ``PFB_CHANGED_IP_ALIASES`` contains ``pfB_Deny_Aggregated_v4`` (the rebuilt
        aggregate merged into the changed-alias context). The before-state (new IP absent
        from the settled table) proves the feed change CAUSED the fresh read.
    """
    token = "aggposthook"
    agg = h.aggregate_table("Deny", "v4")
    settle_ip = "198.51.100.16"
    new_ip = "203.0.113.16"
    feed_name = "agg_posthook_deny.txt"
    table_marker = f"/tmp/pfb_aggtbl_{token}"
    env_marker = h.hook_marker_path(token, "post")

    feed = h.write_local_feed(deployed_vm, feed_name, f"{settle_ip}\n")
    spec = h.IpCase(aliasname="aggposthook", feed_url=feed, header="aggposthook", action="Deny_Both")
    on_disk_header = f"{spec.header}_{spec.family}"  # IP feed file is {header}{vtype} (inc:10126)
    h.inject(deployed_vm, spec)
    h.set_aggregate_types(deployed_vm, ["Deny"])

    # The post hook records the LIVE aggregate table, then the env. Under the ADR-12
    # security model a hook runs a VETTED script file (not a typed command), so install
    # the script via the transient ``_body`` key that set_update_hooks() writes into the
    # on-box hook-script dir before persisting the entry.
    post_hook = {
        "script": f"hook_post_{token}.sh",
        "_body": f"#!/bin/sh\n/sbin/pfctl -t {agg} -T show > {table_marker}\n/usr/bin/env > {env_marker}\n",
        "when": "post",
        "enabled": "on",
        "description": f"smoke {token} aggregate post",
        "timeout": "60",
    }
    h.set_update_hooks(deployed_vm, [post_hook])
    try:
        # Settle: one update builds + loads the aggregate from the original feed.
        h.clear_hook_markers(deployed_vm, token)
        deployed_vm.ssh("/bin/rm", "-f", table_marker)
        h.reload(deployed_vm, "update")
        h.apply_filter_sync(deployed_vm)

        # BEFORE: the settled aggregate does NOT yet contain the new IP.
        settled = h.pfctl_table_members(deployed_vm, agg)
        assert h.member_present(settled, settle_ip), f"settle IP {settle_ip} not in {agg} after settle: {settled}"
        assert not h.member_present(settled, new_ip), (
            f"new IP {new_ip} already in {agg} before the feed change — cannot prove freshness"
        )

        # CHANGE: rewrite the feed to ADD the new IP + force the re-fetch (bust the reuse cache),
        # then one update. The aggregate must be (re)built BEFORE the post hook fires.
        h.write_local_feed(deployed_vm, feed_name, f"{settle_ip}\n{new_ip}\n")
        h.force_ip_refetch(deployed_vm, on_disk_header)
        h.clear_hook_markers(deployed_vm, token)
        deployed_vm.ssh("/bin/rm", "-f", table_marker)
        h.reload(deployed_vm, "update")
        h.apply_filter_sync(deployed_vm)

        # (a) The table the hook recorded contains the NEW IP — proof the hook saw the FRESH,
        #     loaded aggregate (built before the post hook), never the stale pre-update content.
        assert h.hook_marker_exists(deployed_vm, table_marker), f"post hook did not record the aggregate table {agg}"
        seen = deployed_vm.ssh("cat", table_marker).stdout
        assert new_ip in seen, (
            f"post hook saw a STALE {agg}: new IP {new_ip} absent from the hook's recorded table "
            f"(the build/load did not complete before the post hook): {seen!r}"
        )
        # (b) The rebuilt aggregate's name is in the changed-alias context the hook received.
        env = h.read_hook_env(deployed_vm, env_marker)
        assert env is not None, "post hook did not run (no env marker)"
        changed = env.get("PFB_CHANGED_IP_ALIASES", "").split()
        assert agg in changed, f"rebuilt aggregate {agg} not in PFB_CHANGED_IP_ALIASES: {changed!r} (env={env})"
    finally:
        # Always clear the hook (and its marker) so a mid-test failure cannot leave the
        # table-dumping post hook configured for the rest of the module.
        h.clear_update_hooks(deployed_vm)
        deployed_vm.ssh("/bin/rm", "-f", table_marker)


# --------------------------------------------------------------------------- #
# 8) Deny aggregate folds in a DNSBLIP IP (the DNSBL-IP -> denydir contract)
# --------------------------------------------------------------------------- #


def test_aggregate_deny_includes_dnsblip(deployed_vm: SmokeVM) -> None:
    """An IP literal in a DNSBL feed (DNSBL-IP=Deny) folds into ``pfB_Deny_Aggregated_v4``.

    Scenario: the "DNSBL IP" firewall feature deposits feed-embedded IP literals into
    ``pfB_DNSBLIP_v4`` — and with ``dnsbl_ip_action="Deny_Both"`` that table lives in
    denydir, so the Deny aggregate's denydir glob folds it in for free (no special-casing).
      Given a ``DnsblCase`` whose feed embeds the IP literal ``198.51.100.17`` and
        ``dnsbl_ip_action="Deny_Both"`` (collect DNSBL-IP into the Deny dir),
      When ``pfb_agg_types=["Deny"]`` and a full ``update`` runs,
      Then ``198.51.100.17`` (via ``pfB_DNSBLIP_v4``) is present in
        ``pfB_Deny_Aggregated_v4``. A blocking filter apply precedes the authoritative
        ``pfctl_table_members`` reads on both tables.
    """
    dnsblip = "198.51.100.17"
    agg = h.aggregate_table("Deny", "v4")
    domain = h.unique_domain("aggdnsblip")

    # A DNSBL feed body that embeds an IP literal — the DNSBL-IP feature collects it into
    # pfB_DNSBLIP_v4 (denydir under a Deny action). A domain line keeps the feed valid DNSBL.
    feed = h.write_local_feed(deployed_vm, "agg_dnsblip_feed.txt", f"{domain}\n{dnsblip}\n")
    spec = h.DnsblCase(
        aliasname="aggdnsblip",
        feed_url=feed,
        header="aggdnsblip",
        mode=h.DnsblMode.NULL,
        dnsbl_ip_action="Deny_Both",
    )
    h.inject(deployed_vm, spec)
    h.set_aggregate_types(deployed_vm, ["Deny"])
    h.reload(deployed_vm, "update")

    h.apply_filter_sync(deployed_vm)
    # Sanity: the DNSBLIP member table itself collected the literal (the fold's source).
    dnsblip_members = h.pfctl_table_members(deployed_vm, "pfB_DNSBLIP_v4")
    assert h.member_present(dnsblip_members, dnsblip), (
        f"DNSBLIP {dnsblip} not collected into pfB_DNSBLIP_v4: {dnsblip_members}"
    )
    # The Deny aggregate folds the denydir (incl. DNSBLIP) in. Use CIDR COVERAGE, not exact
    # membership: the aggregate is iprange-collapsed, so the DNSBLIP IP can be folded into a
    # supernet (e.g. .16 + .17 -> .16/31) — present in the set, but not as its bare literal.
    agg_members = h.pfctl_table_members(deployed_vm, agg)
    assert h.member_covers(agg_members, dnsblip), f"DNSBLIP {dnsblip} did not fold into {agg}: {agg_members}"
