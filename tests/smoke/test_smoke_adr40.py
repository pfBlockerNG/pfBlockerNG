"""ADR-40 Phase 3 — live-VM smoke coverage: content-addressed alias reload gating.

pfBlockerNG now gates alias reloads on CONTENT, not feed-fetch.  After this
phase, the last-applied set mirror (``/var/db/aliastables/<alias>.txt``) is
compared against the newly computed canonical set; ``pfctl -T replace`` and
ADR-12 ``PFB_CHANGED_IP_ALIASES`` are driven ONLY by aliases whose membership
set actually changed.

These tests drive the REAL production path via ``helpers.reload(vm, 'update')``
and observe the content-gate through the ADR-12 post-hook env (same technique
as ``test_smoke_hooks.py``).

WHAT THIS FILE AUTOMATES (ADR-40 Phase 3 acceptance criteria):

* **Idempotence** — after a first update that loads a feed, a second update over
  the SAME feed content produces ``PFB_CHANGED_IP_ALIASES=''`` (empty) — the
  content-gate skips aliases whose set did not change.  This is the core
  Phase 3 correctness claim: ``PFB_CHANGED_IP_ALIASES`` empty does NOT mean
  "no reload was attempted"; it means "the canonical set was identical, so
  the alias was not reloaded".

* **Surgical reload on content change** — after settling, if the feed content
  changes (a new IP is added), the alias appears in ``PFB_CHANGED_IP_ALIASES``
  on the next update (the content-gate fires); the pf table gains the new IP.

These two together exercise both sides of ``pfb_alias_set_different()``:
  FALSE (idempotence, skip) and TRUE (content changed, reload).

WHAT STAYS MANUAL / OUT OF SCOPE HERE:

* Cross-list (dedup/reputation) scope widening (ADR-40 §2 hybrid scope) — the
  enable_dup / enable_drep config toggles require new harness helpers not yet
  in the smoke fixture set.  Covered by unit tests (AliasContentGateTest:
  testCrossListScopeWidensDuplicateList).

DESELECTED from the default ``python -m pytest`` (``--ignore=tests/smoke``).
Run via the smoke workflow or locally::

    python -m pytest tests/smoke -m smoke --override-ini="addopts="

Requires the booted ``smoke_vm`` fixture, the branch ``.pkg`` (``SMOKE_PKG``),
and the smoke deps; without them these tests skip cleanly.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from . import helpers as h
from .conftest import SmokeVM, _StubDnsServer

pytestmark = pytest.mark.smoke


@pytest.fixture(scope="module")
def adr40_vm(smoke_vm: SmokeVM, stub_dns: _StubDnsServer) -> Iterator[SmokeVM]:
    """Deploy the branch .pkg once for the ADR-40 content-gate module.

    Egress stays OPEN throughout (``pkg add`` + pfBlockerNG's feed-fetch paths
    need a reachable network).  Each test installs and clears its own post-hook;
    we do a defensive clear up front and on teardown so no stray hook bleeds
    into another module's reloads.  Diagnostics are collected on teardown for
    post-mortem when a test fails.
    """
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    h.snapshot_unbound_conf(smoke_vm)
    h.ensure_dnsbl_vip(smoke_vm)
    h.use_system_dns_upstream(smoke_vm)
    h.clear_update_hooks(smoke_vm)
    try:
        yield smoke_vm
    finally:
        h.clear_update_hooks(smoke_vm)
        h.unblock_egress()
        h.collect_host_diagnostics(smoke_vm)


# --------------------------------------------------------------------------- #
# 1) Idempotence — second update over unchanged feed content emits no aliases
# --------------------------------------------------------------------------- #


def test_adr40_content_gate_idempotence(adr40_vm: SmokeVM) -> None:
    """A second reload over an UNCHANGED feed produces PFB_CHANGED_IP_ALIASES=''.

    Scenario A (ADR-40 §2): content-addressed skip.

    Background: pfBlockerNG loads a local feed once (first update), writing the
    canonical set mirror to ``/var/db/aliastables/<alias>.txt``.  On the NEXT
    update, the feed is re-read and the new canonical set is compared against
    the mirror.  When the sets are IDENTICAL, ``pfb_alias_set_different()``
    returns FALSE, the alias is NOT added to ``$pfb_alias_lists``, and
    ``PFB_CHANGED_IP_ALIASES`` is EMPTY.

    **Given** a single IPv4 local feed with a stable IP (192.0.2.201, RFC 5737)
    and a post env-dump hook; the feed is settled by a first update.

    **And** (before-state): the pf table contains the settled IP — proving the
    first load ran and the table is populated, so an empty ``PFB_CHANGED_IP_ALIASES``
    on the second pass cannot be explained by "the table never loaded".

    **When** ``helpers.reload(vm, 'update')`` runs again over the SAME unchanged
    feed content.

    **Then** the post hook fires and ``PFB_CHANGED_IP_ALIASES`` does NOT contain
    the alias — the content-gate short-circuited the reload.

    **And** the pf table still holds the settled IP (confirming no phantom flush).

    Before Phase 3: ``$pfb_alias_lists`` was populated from the download loop
    (feed re-fetched → alias always added, regardless of content), so a
    no-content-change update still emitted the alias in ``PFB_CHANGED_IP_ALIASES``
    — a false positive triggering unnecessary pfctl operations and ADR-12 hooks.
    FAILS on pre-Phase-3 code; PASSES after the fix.
    """
    token = "p3idem"
    marker = h.hook_marker_path(token, "post")
    fed_ip = "192.0.2.201"
    feed_file = "smoke_adr40_idem.txt"

    # Set up: install the env-dump hook and configure a local feed with one IP.
    h.set_update_hooks(adr40_vm, [h.env_dump_hook(token, "post")])
    feed_url = h.write_local_feed(adr40_vm, feed_file, f"{fed_ip}\n")
    ip_spec = h.IpCase(
        aliasname="smokeadr40idem",
        feed_url=feed_url,
        header="smokeadr40idem",
    )
    h.inject(adr40_vm, ip_spec)

    # First update: settle the feed.  The alias WILL appear in
    # PFB_CHANGED_IP_ALIASES on this pass (mirror absent on first load →
    # pfb_alias_set_different() returns TRUE).  Assert it to prove the hook
    # fires and the first-load path works before testing the idempotence path.
    h.clear_hook_markers(adr40_vm, token)
    h.reload(adr40_vm, "update")
    env_first = h.read_hook_env(adr40_vm, marker)
    assert env_first is not None, "post hook did not fire on the settling update"
    assert ip_spec.alias in (env_first.get("PFB_CHANGED_IP_ALIASES") or ""), (
        "first update: alias should appear in PFB_CHANGED_IP_ALIASES "
        "(mirror absent → new set → content gate fires): "
        f"got {env_first.get('PFB_CHANGED_IP_ALIASES')!r}"
    )

    # Before-state: pf table is populated with the settled IP.
    members_before = h.pfctl_table_members(adr40_vm, ip_spec.alias)
    assert any(fed_ip in m for m in members_before), (
        f"before-state: pf table {ip_spec.alias} does not contain {fed_ip}: {members_before}"
    )

    # Second update: SAME feed content, no changes.
    # pfb_alias_set_different() must return FALSE → alias NOT added to $pfb_alias_lists.
    h.clear_hook_markers(adr40_vm, token)
    h.reload(adr40_vm, "update")
    env_second = h.read_hook_env(adr40_vm, marker)
    assert env_second is not None, "post hook did not fire on the idempotence update"

    changed = env_second.get("PFB_CHANGED_IP_ALIASES") or ""
    assert ip_spec.alias not in changed, (
        f"ADR-40 P3 idempotence FAILED: alias {ip_spec.alias!r} appeared in "
        f"PFB_CHANGED_IP_ALIASES on an update with no feed content change.\n"
        f"Expected PFB_CHANGED_IP_ALIASES to be empty or not contain the alias; "
        f"got {changed!r}\n"
        "Pre-Phase-3 symptom: the download loop added the alias regardless of content; "
        "Phase 3 fix: pfb_alias_set_different() gates the write loop, which is the "
        "sole populator of $pfb_alias_lists."
    )

    # Pf table must still hold the IP — no phantom flush from a skipped reload.
    members_after = h.pfctl_table_members(adr40_vm, ip_spec.alias)
    assert any(fed_ip in m for m in members_after), (
        f"after idempotent update: pf table {ip_spec.alias} lost {fed_ip} — "
        f"a flush ran even though no pfctl -T replace was needed: {members_after}"
    )

    h.clear_update_hooks(adr40_vm)


# --------------------------------------------------------------------------- #
# 2) Surgical reload on content change
# --------------------------------------------------------------------------- #


def test_adr40_content_gate_fires_on_change(adr40_vm: SmokeVM) -> None:
    """When feed content CHANGES, the alias appears in PFB_CHANGED_IP_ALIASES.

    Scenario B (ADR-40 §2): content-addressed reload triggers on genuine delta.

    **Given** a local feed is settled (one IP: 192.0.2.202); the post hook fires;
    the pf table holds only the OLD IP (before-state assertion).

    **When** the feed file is rewritten with a DIFFERENT IP (192.0.2.203) and
    ``force_ip_refetch`` invalidates the reuse cache, then ``reload('update')`` runs.

    **Then** the alias appears in ``PFB_CHANGED_IP_ALIASES`` (the content-gate
    returned TRUE), AND the pf table now contains ONLY the NEW IP (pfctl -T replace
    ran with the updated canonical set and the old IP is gone).

    This is the complementary ON-branch to ``test_adr40_content_gate_idempotence``
    — together they prove ``pfb_alias_set_different()`` is a real two-sided gate,
    not an always-false or always-true no-op.
    """
    token = "p3chng"
    marker = h.hook_marker_path(token, "post")
    old_ip = "192.0.2.202"
    new_ip = "192.0.2.203"
    feed_file = "smoke_adr40_chng.txt"

    h.set_update_hooks(adr40_vm, [h.env_dump_hook(token, "post")])
    feed_url = h.write_local_feed(adr40_vm, feed_file, f"{old_ip}\n")
    ip_spec = h.IpCase(
        aliasname="smokeadr40chng",
        feed_url=feed_url,
        header="smokeadr40chng",
    )
    h.inject(adr40_vm, ip_spec)

    # Settle with the OLD IP.
    h.clear_hook_markers(adr40_vm, token)
    h.reload(adr40_vm, "update")
    env_settle = h.read_hook_env(adr40_vm, marker)
    assert env_settle is not None, "post hook did not fire on the settling update"

    # Before-state: only old_ip in the table; new_ip absent.
    members_before = h.pfctl_table_members(adr40_vm, ip_spec.alias)
    assert any(old_ip in m for m in members_before), (
        f"before-state: pf table {ip_spec.alias} missing {old_ip}: {members_before}"
    )
    assert not any(new_ip in m for m in members_before), (
        f"before-state: pf table {ip_spec.alias} already contains {new_ip}: {members_before}"
    )

    # Change: rewrite feed with a DIFFERENT IP; invalidate the reuse cache so
    # pfBlockerNG re-reads the file (force_ip_refetch touches the .update marker).
    h.write_local_feed(adr40_vm, feed_file, f"{new_ip}\n")
    h.force_ip_refetch(adr40_vm, ip_spec.header)

    h.clear_hook_markers(adr40_vm, token)
    h.reload(adr40_vm, "update")
    env_changed = h.read_hook_env(adr40_vm, marker)
    assert env_changed is not None, "post hook did not fire after feed content change"

    changed = env_changed.get("PFB_CHANGED_IP_ALIASES") or ""
    assert ip_spec.alias in changed, (
        f"ADR-40 P3 content-change gate FAILED: alias {ip_spec.alias!r} absent from "
        f"PFB_CHANGED_IP_ALIASES after feed content changed from {old_ip!r} to {new_ip!r}.\n"
        f"Got PFB_CHANGED_IP_ALIASES={changed!r}\n"
        "pfb_alias_set_different() should have returned TRUE (sets differ)."
    )

    # After-state: pf table holds new_ip only; old_ip removed.
    members_after = h.pfctl_table_members(adr40_vm, ip_spec.alias)
    assert any(new_ip in m for m in members_after), (
        f"after content change: pf table {ip_spec.alias} missing new IP {new_ip}: {members_after}"
    )
    assert not any(old_ip in m for m in members_after), (
        f"after content change: pf table {ip_spec.alias} still contains old IP {old_ip}: {members_after}"
    )

    h.clear_update_hooks(adr40_vm)
