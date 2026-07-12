"""issue #1084 live-VM smoke: the batch IP `recompute` flow end-to-end.

pfBlockerNG's batch ``recompute`` verb (``pfblockerng.sh``, invoked from
``pfblockerng.inc`` ~19060-19135) replaces the old incremental duplicate()/dMax/pMax
pass: real feeds parse -> a pristine post-preprocessing snapshot per header
(``pfb_ip_recompute_write_snapshot``) -> a per-family memberlist -> ONE
``pfblockerng.sh recompute`` call that rewrites EVERY alias of that family from its
snapshot -> the rewritten deny files load into their pf tables. This module drives
that whole pipeline through the real CLI (``helpers.reload``) on a real pfSense VM
and observes the on-box deny/master files + live ``pfctl`` tables — the CI-runnable,
credential-free half (Part 1 of issue #1170). Part 2 (R3/R7/R8-outage below) adds the
Continent/GeoIP-adjacent rows that stay credential-free by riding the issue #1219
``seed_geoip_dataset`` local-CSV fixture (R3/R7) or by hiding any GeoIP database for the
pass (R8-outage) — never a real MaxMind account.

WHAT THIS FILE AUTOMATES:

* **R1 — cross-feed dedup ownership** — two overlapping v4 Deny feeds (a
  CIDR-containment overlap + an exact repeat, dedup ON): the higher-priority feed
  (config order) keeps the overlap in BOTH the on-box deny file and its pf table;
  the lower-priority feed keeps only its unique row.
* **R2 — v6 snapshot round-trip** — a v6 Deny feed's pristine post-preprocessing
  snapshot (``.snap``) is written on first ingest, and its content round-trips
  byte-identical into a SECOND pass's deny file/pf table when the feed is held
  static (recompute re-emits the same snapshot unchanged).
* **R4 — unchanged-sibling survives a family-wide rewrite** — one alias's feed
  genuinely changes (a real re-download, via ``force_ip_refetch``); an untouched
  sibling alias (never reprocessed this pass) still shows correct, unperturbed
  content after recompute rewrites the whole family from the memberlist.
* **R5 / R9 — closing-pass placeholder refill, both branches of
  ``pfb_ip_closing_pass_active()``** — dup=ON (R5, unconditional closing) and
  dup=OFF+pRep=ON (R9, closing fires only because recompute genuinely ran): an
  alias that collapses to ZERO rows (suppression for R5; a pMax /24 offender
  divert for R9 — GeoIP-free, unlike dMax/match modes) gets the deny placeholder,
  never a stale 0-byte file.
* **R6 — suppression realigns across a sibling's recompute (regression pin,
  the #1084-review resurrection bug)** — an IP suppressed on alias A stays
  suppressed even after an UNRELATED sibling B's genuine change drives a
  family-wide recompute that rewrites A too (recompute's snapshot is a
  PRE-suppression capture, so a stale suppression gate would resurrect it).
* **R3 — continent snapshot write, BOTH families** — a GeoIP Continent list
  (Deny_Both, seeded from the official MaxMind-DB test corpus, issue #1219/#1228)
  writes a fresh ``.snap`` + ``.aggcount`` for its v4 alias AND, independently, its
  v6 alias — pinned against the corpus's North-America asymmetry (US carries 3 v4
  rows vs. 1 v6 row) so a v4-only snapshot bug (the pre-fix state
  ``IpRecomputeRanWiringTest`` guards against) cannot pass vacuously.
* **R7 — v6 continent snapshot TRACKING across two regens** — the same v6
  ``.snap`` genuinely changes content across two passes when the underlying
  continent membership changes, proving the snapshot follows live regens rather
  than freezing at a one-time seed (issue #1084 review; ``c3fc39d3``).
* **R8-outage — a GeoIP-unavailable pass preserves the reputation match
  artifacts** — dMax with offenders present and no ``GeoLite2-Country.mmdb``
  reachable (the image bakes none; one a credentialed sibling downloaded into the
  shared VM is hidden for the pass and restored after):
  ``pfb_recompute_finish()`` takes the GeoIP-unavailable branch and leaves a
  pre-existing per-alias match file byte-identical, never swapping/removing it.
* **R8-restored — a clean pass with GeoIP UP clears the reputation match
  artifacts (issue #1228)** — with a real binary ``.mmdb`` seeded, a cc-list HIT
  (``ccwhite=match``) writes the consolidated ``matchdedup`` file and a SIBLING
  cc-list MISS (``ccblack=match``) writes a per-alias ``match<alias>.txt``; a
  SECOND pass whose cc-list matches neither offender reconciles BOTH away.

Reload-scope note: R1/R2/R5/R9 are single-pass (or repeat-input) cases and use
``reload(scope='updateip')`` — its ``force=true`` sets ``$pfb['reuse']='on'`` for the
WHOLE pass, so every configured Deny alias is genuinely reprocessed (never the
early "exists, skip" cache) without needing a marker touch (see
``test_smoke_suppression.py``'s identical rationale). R4/R6 need to distinguish "this
alias's OWN feed did not change" from "recompute ran anyway" — the exact axis
`force=true` collapses (every alias becomes `$feed_changed` every pass) — so they use
the ADR-40-proven two-pass shape instead: ``reload(scope='update')`` (respects the
per-alias reuse-skip) + ``force_ip_refetch()`` on ONLY the alias that must genuinely
re-ingest. R3/R7 use ``reload(scope='update')`` too (matches the
``test_smoke_714_asn_geoip.py`` c8 precedent for continent builds — the continent
loop's own md5-comparison change detector, not the feed-reuse cache, gates the
snapshot write). R8-outage uses ``reload(scope='updateip')`` (matches R9's dMax/pMax
sibling: `force=true` reliably fires `repcheck` without a marker touch).

DESELECTED from the default ``python -m pytest`` (``--ignore=tests/smoke``). Run via
the smoke workflow or locally::

    python -m pytest tests/smoke -m smoke --override-ini="addopts="

Requires the booted ``smoke_vm`` fixture and the branch ``.pkg`` (``SMOKE_PKG``);
without it the module fixture skips cleanly. Pure IP-side (no DNSBL, no DNS probe) —
mirrors the minimal ``test_smoke_suppression.py``/``test_smoke_714_asn_geoip.py``
deploy shape.
"""

from __future__ import annotations

import os
import subprocess
from collections.abc import Iterator

import pytest

from . import helpers as h
from .conftest import SmokeVM

pytestmark = pytest.mark.smoke

CFG_IP_SETTINGS = h.CFG_IP_SETTINGS
DENYDIR = f"{h.PFB_DBDIR}/deny"
SNAPDIR = f"{h.PFB_DBDIR}/snapshot"
MASTERFILE = f"{h.PFB_DBDIR}/masterfile"
# pfblockerng.inc:50 $pfb['origdir'] -- the recompute snapshot's '.aggcount' sidecar dir (R3).
ORIGDIR = f"{h.PFB_DBDIR}/original"
# pfblockerng.sh:92 pfbmatch -- the dMax per-alias 'match<alias>.txt' reputation artifact dir (R8-outage).
MATCHDIR = f"{h.PFB_DBDIR}/match"

# Pin ip_placeholder explicitly (PHP and pfblockerng.sh both default to this value) so
# R5/R9's collapse assertion compares against an exact string no matter what an earlier
# module left in the shared config.
PLACEHOLDER_IP = "127.1.7.7"


@pytest.fixture(scope="module")
def deployed_vm(smoke_vm: SmokeVM) -> Iterator[SmokeVM]:
    """Deploy the branch .pkg once for the issue #1084 recompute module.

    Pure IP-side: the batch recompute pipeline runs inside the IP-scope reload path
    only (no DNSBL, no DNS probe needed) -- mirrors the minimal
    ``test_smoke_suppression.py``/``test_smoke_714_asn_geoip.py`` shape.
    """
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    try:
        yield smoke_vm
    finally:
        # Leave no dedup/reputation/suppression/placeholder/continent knob set for the next module.
        h.set_ip_dedup(smoke_vm, False)
        h.set_ip_reputation(smoke_vm)
        h.set_ip_suppression(smoke_vm, enabled=False)
        _set_placeholder(smoke_vm, "")
        h.set_ip_continent(smoke_vm, "North America", action="Disabled")
        h.set_ip_continent(smoke_vm, "Europe", action="Disabled")
        h.collect_host_diagnostics(smoke_vm)


def _set_placeholder(vm: SmokeVM, value: str) -> None:
    """Set ``ip_placeholder`` at ``CFG_IP_SETTINGS`` -- a local one-off (not promoted to
    helpers.py; only R5/R9 in this module need a deterministic placeholder value)."""
    snippet = (
        f"$ip = config_get_path({h._php_str(CFG_IP_SETTINGS)}, array());\n"
        f"$ip['ip_placeholder'] = {h._php_str(value)};\n"
        f"config_set_path({h._php_str(CFG_IP_SETTINGS)}, $ip);\n"
        "write_config('pfBlockerNG smoke: ip_placeholder');\n"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_set_placeholder failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}")


def _lines(vm: SmokeVM, path: str) -> list[str]:
    """Non-blank lines of an on-box file (mirrors test_smoke_suppression.py's
    ``_member_lines`` -- generalised here to any deny/master/snapshot file)."""
    result = vm.ssh("cat", path)
    return [ln.strip() for ln in result.stdout.splitlines() if ln.strip()]


def _exists(vm: SmokeVM, path: str) -> bool:
    """Whether an on-box file exists (R8-restored's reconcile assertions -- a
    reconciled-away artifact must be genuinely GONE, not merely empty)."""
    return vm.ssh("/bin/test", "-f", path).returncode == 0


def _raw(vm: SmokeVM, path: str) -> str:
    """Raw on-box file content -- for byte-identity checks a line-set cannot make."""
    return vm.ssh("cat", path).stdout


# --------------------------------------------------------------------------- #
# R1 -- cross-feed dedup ownership (CIDR containment + exact repeat)
# --------------------------------------------------------------------------- #


def test_recompute_dedup_ownership_across_overlapping_feeds(deployed_vm: SmokeVM) -> None:
    """dedup ON: the higher-priority feed keeps a containment overlap AND an exact
    repeat; the lower-priority feed keeps only its unique row -- on-box AND pf table.

    Scenario: two v4 Deny feeds sharing real overlap, not disjoint IPs.
      Given feed A (config order 1st, so highest recompute priority) lists a /24
        network (``203.0.113.0/24``) and a bare host (``198.51.100.211``), and
        feed B (2nd) lists a host INSIDE A's /24 (``203.0.113.44``, a CIDR-containment
        overlap), an EXACT repeat of A's bare host (``198.51.100.211``), and its own
        unique host (``198.51.100.212``),
      When dedup is ON and a single ``updateip`` reload runs,
      Then A's deny file/table is UNCHANGED (both its original rows, priority owns
        ties) while B's deny file/table holds ONLY its unique row -- both overlap
        classes pruned from B, mirroring the shellspec unit suite's own adversarial
        shapes (never a disjoint-IP pair, which would pass vacuously).
    """
    h.set_ip_dedup(deployed_vm, True)
    h.set_ip_reputation(deployed_vm)
    h.set_ip_suppression(deployed_vm, enabled=False)

    feed_a = h.write_local_feed(deployed_vm, "r1_feed_a.txt", "203.0.113.0/24\n198.51.100.211\n")
    feed_b = h.write_local_feed(deployed_vm, "r1_feed_b.txt", "203.0.113.44\n198.51.100.211\n198.51.100.212\n")
    spec_a = h.IpCase(aliasname="r1a", feed_url=feed_a, header="r1a", action="Deny_Both")
    spec_b = h.IpCase(aliasname="r1b", feed_url=feed_b, header="r1b", action="Deny_Both")
    # Order matters: A first = highest recompute priority (config order == memberlist
    # priority, pfb_ip_recompute_family_headers()).
    h.inject_ip_lists(deployed_vm, [spec_a, spec_b])
    h.reload(deployed_vm, "updateip", wait_unbound=False)

    a_lines = _lines(deployed_vm, f"{DENYDIR}/r1a_v4.txt")
    b_lines = _lines(deployed_vm, f"{DENYDIR}/r1b_v4.txt")
    assert sorted(a_lines) == sorted(["203.0.113.0/24", "198.51.100.211"]), f"feed A perturbed: {a_lines}"
    assert b_lines == ["198.51.100.212"], f"feed B ownership wrong (overlap not pruned): {b_lines}"

    master = _lines(deployed_vm, MASTERFILE)
    assert "r1a_v4 203.0.113.0/24" in master, f"masterfile missing A's /24 row: {master}"
    assert "r1a_v4 198.51.100.211" in master, f"masterfile missing A's exact-repeat winner: {master}"
    assert "r1b_v4 198.51.100.212" in master, f"masterfile missing B's unique row: {master}"
    assert "r1b_v4 203.0.113.44" not in master, f"masterfile kept B's pruned containment row: {master}"
    assert "r1b_v4 198.51.100.211" not in master, f"masterfile kept B's pruned exact-repeat row: {master}"

    a_members = h.wait_pfctl_table(deployed_vm, spec_a.alias)
    b_members = h.wait_pfctl_table(deployed_vm, spec_b.alias)
    assert h.member_present(a_members, "198.51.100.211"), (
        f"pf table {spec_a.alias} missing exact-repeat winner: {a_members}"
    )
    assert h.member_covers(a_members, "203.0.113.44"), f"pf table {spec_a.alias} missing its /24 coverage: {a_members}"
    assert h.member_present(b_members, "198.51.100.212"), f"pf table {spec_b.alias} missing unique row: {b_members}"
    assert not h.member_present(b_members, "198.51.100.211"), (
        f"pf table {spec_b.alias} kept the exact-repeat row it should have lost: {b_members}"
    )
    assert not h.member_covers(b_members, "203.0.113.44"), (
        f"pf table {spec_b.alias} kept the containment-overlap row it should have lost: {b_members}"
    )


# --------------------------------------------------------------------------- #
# R2 -- v6 snapshot write + round-trip across a static pass
# --------------------------------------------------------------------------- #


def test_recompute_v6_snapshot_round_trips_across_static_pass(deployed_vm: SmokeVM) -> None:
    """A v6 Deny feed's pristine snapshot round-trips unchanged into a SECOND pass
    when the feed is held static.

    Scenario: one v6 Deny feed, two successive updateip passes with no edit between.
      Given a v6 Deny feed (a /64 network + a bare host inside a DIFFERENT /64),
      When the first ``updateip`` pass runs,
      Then the ``.snap`` file exists under the snapshot dir with exactly the fed
        rows, and the deny file/pf table match,
      When a SECOND ``updateip`` pass runs with the feed held static (updateip's
        force=true reprocesses every alias from its cached raw body regardless),
      Then the deny file is BYTE-IDENTICAL to the first pass and the pf table still
        holds both rows (recompute re-emits the same snapshot unchanged).
    """
    h.set_ip_dedup(deployed_vm, True)  # dup=on is required to invoke the v6 family at all.
    h.set_ip_reputation(deployed_vm)
    h.set_ip_suppression(deployed_vm, enabled=False)

    body = "2001:db8:5678::/64\n2001:db8:5678:1::42\n"
    feed = h.write_local_feed(deployed_vm, "r2_feed_v6.txt", body)
    spec = h.IpCase(aliasname="r2v6", feed_url=feed, header="r2v6", action="Deny_Both", family="v6")
    h.inject_ip_lists(deployed_vm, [spec])

    h.reload(deployed_vm, "updateip", wait_unbound=False)
    snap_lines = _lines(deployed_vm, f"{SNAPDIR}/r2v6_v6.snap")
    deny_lines_pass1 = _lines(deployed_vm, f"{DENYDIR}/r2v6_v6.txt")
    deny_raw_pass1 = _raw(deployed_vm, f"{DENYDIR}/r2v6_v6.txt")
    expected = sorted(["2001:db8:5678::/64", "2001:db8:5678:1::42"])
    assert sorted(snap_lines) == expected, f"snapshot content wrong after first ingest: {snap_lines}"
    assert sorted(deny_lines_pass1) == expected, f"deny file content wrong after first ingest: {deny_lines_pass1}"
    members_pass1 = h.wait_pfctl_table(deployed_vm, spec.alias)
    assert h.member_present(members_pass1, "2001:db8:5678:1::42"), f"pf table missing bare host: {members_pass1}"
    assert h.member_covers(members_pass1, "2001:db8:5678::1"), f"pf table missing /64 coverage: {members_pass1}"

    # Held static: no edit, no force_ip_refetch -- updateip's force=true alone
    # reprocesses this alias again from its cached raw body.
    h.reload(deployed_vm, "updateip", wait_unbound=False)
    deny_raw_pass2 = _raw(deployed_vm, f"{DENYDIR}/r2v6_v6.txt")
    assert deny_raw_pass2 == deny_raw_pass1, (
        f"deny file not byte-identical across a static pass: pass1={deny_raw_pass1!r} pass2={deny_raw_pass2!r}"
    )
    master = _lines(deployed_vm, MASTERFILE)
    assert "r2v6_v6 2001:db8:5678::/64" in master, f"masterfile missing v6 /64 row after round-trip: {master}"
    assert "r2v6_v6 2001:db8:5678:1::42" in master, f"masterfile missing v6 host row after round-trip: {master}"
    members_pass2 = h.wait_pfctl_table(deployed_vm, spec.alias)
    assert h.member_present(members_pass2, "2001:db8:5678:1::42"), (
        f"pf table lost bare host after round-trip: {members_pass2}"
    )
    assert h.member_covers(members_pass2, "2001:db8:5678::1"), (
        f"pf table lost /64 coverage after round-trip: {members_pass2}"
    )


# --------------------------------------------------------------------------- #
# R4 -- an unchanged sibling survives a family-wide recompute rewrite
# --------------------------------------------------------------------------- #


def test_recompute_rewrites_unchanged_sibling_across_passes(deployed_vm: SmokeVM) -> None:
    """A genuinely unprocessed sibling alias still shows correct content after
    recompute rewrites the WHOLE family (not just the alias that changed).

    Scenario: two v4 Deny feeds; only one is genuinely re-ingested on pass 2.
      Given (BEFORE) alias A (``198.51.100.31``) and alias B (``198.51.100.41``)
        both settle correctly on the first ``update`` pass,
      When A's feed is rewritten to ADD a row and force-refetched (a REAL
        re-download, via ``force_ip_refetch``), while B is left completely
        untouched (no edit, no refetch marker -- B is genuinely SKIPPED this pass
        by the reuse-cache, never re-added to the "feed changed" set) and a second
        ``update`` runs,
      Then A's deny file gains the new row AND B's deny file/pf table are STILL
        correct -- proving recompute reads B from its (unchanged) memberlist
        snapshot rather than silently dropping an alias nothing "touched" this pass.
    """
    h.set_ip_dedup(deployed_vm, True)
    h.set_ip_reputation(deployed_vm)
    h.set_ip_suppression(deployed_vm, enabled=False)

    feed_a = h.write_local_feed(deployed_vm, "r4_feed_a.txt", "198.51.100.31\n")
    feed_b = h.write_local_feed(deployed_vm, "r4_feed_b.txt", "198.51.100.41\n")
    spec_a = h.IpCase(aliasname="r4a", feed_url=feed_a, header="r4a", action="Deny_Both")
    spec_b = h.IpCase(aliasname="r4b", feed_url=feed_b, header="r4b", action="Deny_Both")
    h.inject_ip_lists(deployed_vm, [spec_a, spec_b])
    h.reload(deployed_vm, "update")

    # BEFORE: both settle correctly.
    a_before = _lines(deployed_vm, f"{DENYDIR}/r4a_v4.txt")
    b_before = _lines(deployed_vm, f"{DENYDIR}/r4b_v4.txt")
    assert a_before == ["198.51.100.31"], f"A did not settle before the change: {a_before}"
    assert b_before == ["198.51.100.41"], f"B did not settle before the change: {b_before}"

    # CHANGE: A gains a row via a REAL re-download; B is left completely alone.
    h.write_local_feed(deployed_vm, "r4_feed_a.txt", "198.51.100.31\n198.51.100.32\n")
    h.force_ip_refetch(deployed_vm, "r4a_v4")
    h.reload(deployed_vm, "update")

    a_after = _lines(deployed_vm, f"{DENYDIR}/r4a_v4.txt")
    b_after = _lines(deployed_vm, f"{DENYDIR}/r4b_v4.txt")
    assert sorted(a_after) == sorted(["198.51.100.31", "198.51.100.32"]), f"A's change was not applied: {a_after}"
    assert b_after == ["198.51.100.41"], f"B (never touched) was dropped/perturbed by the family rewrite: {b_after}"

    master = _lines(deployed_vm, MASTERFILE)
    assert "r4a_v4 198.51.100.32" in master, f"masterfile missing A's new row: {master}"
    assert "r4b_v4 198.51.100.41" in master, f"masterfile missing B's unchanged row after the family rewrite: {master}"

    b_members = h.wait_pfctl_table(deployed_vm, spec_b.alias)
    assert h.member_present(b_members, "198.51.100.41"), f"pf table {spec_b.alias} lost its member: {b_members}"


# --------------------------------------------------------------------------- #
# R5 -- closing-pass placeholder refill, dup=ON branch (suppression collapse)
# --------------------------------------------------------------------------- #


def test_recompute_closing_refills_placeholder_dup_on(deployed_vm: SmokeVM) -> None:
    """dup=ON: an alias that collapses to ZERO rows via suppression gets the deny
    placeholder, never a stale 0-byte file (``pfb_ip_closing_pass_active()``'s
    unconditional ``(TRUE, 'on')`` branch).

    Scenario: one v4 Deny feed whose sole IP is fully suppressed.
      Given a Deny feed with ONE public (non-reserved -- Suppression drops
        RFC 5737/3849 unconditionally when on, issue #760) IP, and that exact
        IP is the ONLY suppression-list entry,
      When dedup is ON and a single ``updateip`` reload runs,
      Then the alias's deny file equals the placeholder EXACTLY (not empty, not
        the raw IP -- a broken suppression pass would leave the raw IP; a broken
        closing pass would leave 0 bytes).

    No pf-table assertion: the alias loop reads the still-empty deny file and unlinks
    the aliastables mirror for a brand-new alias (pfblockerng.inc, empty $alias_ips +
    empty $pfctlck) BEFORE the closing pass writes the placeholder, so no table exists
    this pass.
    """
    h.set_ip_dedup(deployed_vm, True)
    h.set_ip_reputation(deployed_vm)
    ip = "172.104.90.10"
    h.set_ip_suppression(deployed_vm, enabled=True, v4=[f"{ip}/32"])
    _set_placeholder(deployed_vm, PLACEHOLDER_IP)

    feed = h.write_local_feed(deployed_vm, "r5_feed.txt", f"{ip}\n")
    spec = h.IpCase(aliasname="r5", feed_url=feed, header="r5", action="Deny_Both")
    h.inject_ip_lists(deployed_vm, [spec])
    h.reload(deployed_vm, "updateip", wait_unbound=False)

    deny_lines = _lines(deployed_vm, f"{DENYDIR}/r5_v4.txt")
    assert deny_lines == [PLACEHOLDER_IP], f"suppression-collapsed alias not placeholder-refilled: {deny_lines}"


# --------------------------------------------------------------------------- #
# R9 -- closing-pass placeholder refill, dup=OFF + pRep=ON branch (pMax collapse)
# --------------------------------------------------------------------------- #


def test_recompute_closing_refills_placeholder_dup_off_pmax(deployed_vm: SmokeVM) -> None:
    """dup=OFF + pRep=ON: an alias whose rows ALL migrate to a higher-priority
    sibling's collapsed /24 (pMax offender divert) gets the deny placeholder --
    the ``alias_arg='off'`` branch of ``pfb_ip_closing_pass_active()`` fires only
    because ``recompute_ran_v4`` is TRUE (dup is OFF, so it is NOT unconditional).

    pMax is GeoIP-free (unconditional block, ``pfblockerng.sh
    pfb_recompute_rep_actionmap``) -- unlike dMax/match mode, no MaxMind database
    is needed, so this row is in-scope for the credential-free CI leg.

    Scenario: two v4 Deny feeds sharing one /24, over the pMax threshold.
      Given anchor (config order 1st, highest priority) lists ONE host in
        ``192.0.2.0/24``, and collapse (2nd) lists TWO more hosts in the SAME /24
        (combined count 3 > pmax=2 -> the whole /24 is an offender),
      When dedup is OFF, pRep is ON with pmax=2, and a single ``updateip`` reload
        runs,
      Then anchor's deny file holds the collapsed ``192.0.2.0/24`` supernet (proving
        the offender mechanism genuinely fired) and collapse's deny file -- now
        holding NOTHING of its own -- equals the placeholder, not 0 bytes.
    """
    h.set_ip_dedup(deployed_vm, False)
    h.set_ip_reputation(deployed_vm, prep=True, pmax=2)
    h.set_ip_suppression(deployed_vm, enabled=False)
    _set_placeholder(deployed_vm, PLACEHOLDER_IP)

    feed_anchor = h.write_local_feed(deployed_vm, "r9_feed_anchor.txt", "192.0.2.21\n")
    feed_collapse = h.write_local_feed(deployed_vm, "r9_feed_collapse.txt", "192.0.2.22\n192.0.2.23\n")
    spec_anchor = h.IpCase(aliasname="r9hi", feed_url=feed_anchor, header="r9hi", action="Deny_Both")
    spec_collapse = h.IpCase(aliasname="r9lo", feed_url=feed_collapse, header="r9lo", action="Deny_Both")
    # Order matters: anchor first = highest recompute priority, so it absorbs the
    # collapsed /24; "collapse" (listed 2nd) is the one that ends up empty.
    h.inject_ip_lists(deployed_vm, [spec_anchor, spec_collapse])
    h.reload(deployed_vm, "updateip", wait_unbound=False)

    anchor_lines = _lines(deployed_vm, f"{DENYDIR}/r9hi_v4.txt")
    collapse_lines = _lines(deployed_vm, f"{DENYDIR}/r9lo_v4.txt")
    assert anchor_lines == ["192.0.2.0/24"], f"pMax offender did not collapse to the anchor's /24: {anchor_lines}"
    assert collapse_lines == [PLACEHOLDER_IP], f"pMax-collapsed alias not placeholder-refilled: {collapse_lines}"

    # No pf-table assertion for the collapsed alias: its mirror is unlinked while the
    # deny file is still empty, before the closing pass refills the placeholder (see
    # test_recompute_closing_refills_placeholder_dup_on).
    anchor_members = h.wait_pfctl_table(deployed_vm, spec_anchor.alias)
    assert h.member_covers(anchor_members, "192.0.2.21"), (
        f"pf table lost the anchor's own offending host: {anchor_members}"
    )
    assert h.member_covers(anchor_members, "192.0.2.22"), (
        f"pf table missing the absorbed sibling host: {anchor_members}"
    )


# --------------------------------------------------------------------------- #
# R6 -- suppression realigns across a SIBLING's recompute (regression pin)
# --------------------------------------------------------------------------- #


def test_recompute_suppression_realigns_across_sibling_change(deployed_vm: SmokeVM) -> None:
    """A suppressed IP stays suppressed even after an UNRELATED sibling's genuine
    change drives a family-wide recompute that rewrites the suppressed alias too.

    Regression pin for the #1084-review resurrection bug: ``pfb_recompute()``'s
    snapshot is a PRE-suppression capture (see ``pfb_ip_suppress_body_active()``'s
    docblock in pfblockerng.inc), so recompute alone would resurrect a suppressed IP
    on ANY pass that rewrites that alias -- ``pfb_ip_suppress_body_active()``'s
    ``$feed_changed || $recompute_ran`` clause is what re-applies suppression even
    when the SUPPRESSED alias's OWN feed did not change.

    Uses ``reload(scope='update')`` (not 'updateip'): 'updateip' force=true makes
    EVERY alias `$feed_changed` on EVERY pass (see the module docstring), which
    would make this scenario impossible to construct -- A's own feed must
    genuinely NOT be reprocessed this pass for the regression to be exercisable.

    Scenario: alias A (one suppressed IP + one surviving IP) + sibling alias B.
      Given (BEFORE, after settling) X (suppressed) is ABSENT from A's deny file
        while Z (not suppressed) is present,
      When B's feed is rewritten and force-refetched (a REAL re-download -- B's
        OWN change) while A is left completely untouched, and a second ``update``
        runs,
      Then X is STILL absent from A's deny file/pf table (re-suppression re-ran
        for A even though A's own feed did not change) and Z is still present, AND
        B's deny file reflects its new content (proving the sibling's change
        genuinely happened and drove this pass).
    """
    h.set_ip_dedup(deployed_vm, True)
    h.set_ip_reputation(deployed_vm)
    suppressed_ip = "172.104.91.20"
    survivor_ip = "172.104.91.21"
    h.set_ip_suppression(deployed_vm, enabled=True, v4=[f"{suppressed_ip}/32"])

    feed_a = h.write_local_feed(deployed_vm, "r6_feed_a.txt", f"{suppressed_ip}\n{survivor_ip}\n")
    feed_b = h.write_local_feed(deployed_vm, "r6_feed_b.txt", "172.104.92.30\n")
    spec_a = h.IpCase(aliasname="r6a", feed_url=feed_a, header="r6a", action="Deny_Both")
    spec_b = h.IpCase(aliasname="r6b", feed_url=feed_b, header="r6b", action="Deny_Both")
    h.inject_ip_lists(deployed_vm, [spec_a, spec_b])
    h.reload(deployed_vm, "update")

    # BEFORE: the suppressed IP is genuinely absent (not merely "never checked").
    a_before = _lines(deployed_vm, f"{DENYDIR}/r6a_v4.txt")
    assert suppressed_ip not in a_before, f"suppression did not remove {suppressed_ip} on settle: {a_before}"
    assert survivor_ip in a_before, f"unrelated survivor {survivor_ip} wrongly removed on settle: {a_before}"

    # CHANGE: ONLY B's feed genuinely changes (a real re-download); A is untouched.
    h.write_local_feed(deployed_vm, "r6_feed_b.txt", "172.104.92.31\n")
    h.force_ip_refetch(deployed_vm, "r6b_v4")
    h.reload(deployed_vm, "update")

    a_after = _lines(deployed_vm, f"{DENYDIR}/r6a_v4.txt")
    assert suppressed_ip not in a_after, (
        f"REGRESSION (#1084 resurrection bug): {suppressed_ip} resurfaced in A after an UNRELATED "
        f"sibling's recompute -- suppression did not re-run for a feed-unchanged alias: {a_after}"
    )
    assert survivor_ip in a_after, (
        f"unrelated survivor {survivor_ip} dropped by the sibling-triggered rewrite: {a_after}"
    )

    a_members = h.wait_pfctl_table(deployed_vm, spec_a.alias)
    assert not h.member_present(a_members, suppressed_ip), (
        f"pf table {spec_a.alias} still carries the suppressed IP: {a_members}"
    )
    assert h.member_present(a_members, survivor_ip), f"pf table {spec_a.alias} lost the survivor: {a_members}"

    b_after = _lines(deployed_vm, f"{DENYDIR}/r6b_v4.txt")
    assert b_after == ["172.104.92.31"], f"B's own change was not applied -- the sibling trigger is not real: {b_after}"


# --------------------------------------------------------------------------- #
# R3 -- continent snapshot write, BOTH families (official MaxMind-DB test corpus,
# issue #1219/#1228 fixture, credential-free)
# --------------------------------------------------------------------------- #

# tests/smoke/fixtures/README.md "GeoIP fixtures -- CSV + binary mmdb, one corpus":
# North America = US. v4 Blocks has 3 direct US rows; v6 Blocks has exactly 1 --
# the asymmetry this row is built to distinguish (a v4-only snapshot bug could not
# pass this).
NORTH_AMERICA_ISOS = "US"


def test_recompute_continent_snapshot_both_families(deployed_vm: SmokeVM) -> None:
    """A Deny_Both continent list writes a fresh recompute snapshot for its v4 alias
    AND, independently, its v6 alias -- the continent loop's ``$pfbadv`` gate around
    ``pfb_ip_recompute_write_snapshot()`` (pfblockerng.inc)
    carries no ``$vtype`` restriction, so BOTH families must snapshot, not just v4.

    Scenario: the North America continent (US) enabled for both families.
      Given the official MaxMind-DB test corpus is seeded and North America's
        countries4/6 are both set to "US",
      When a single real update pass builds the continent,
      Then BOTH the v4 and v6 continent ``.snap`` files exist with content matching
        their own built ``.txt`` (not mere existence), each with the correct
        ``.aggcount`` line-count sidecar -- and the v6 content/count genuinely differs
        from v4's (3 US v4 rows vs. 1 v6 row), proving the v6 write was read from the
        v6 source specifically, not a copy of v4's. Member SETS are pinned (sorted
        lines, not raw concatenation order) -- the continent build's own ISO-to-ISO
        join order is an internal implementation detail this row does not pin.
    """
    h.seed_geoip_dataset(deployed_vm)
    h.set_package_enabled(deployed_vm, True)
    h.set_ip_continent(
        deployed_vm, "North America", action="Deny_Both", countries4=NORTH_AMERICA_ISOS, countries6=NORTH_AMERICA_ISOS
    )
    h.reload(deployed_vm, "update", wait_unbound=False)

    # pfblockerng.inc:165 abbreviates this continent's alias base to 'pfB_NAmerica' (NOT the
    # page/config name) -- the alias name is what every on-box artifact below is keyed by.
    v4_alias = "pfB_NAmerica_v4"
    v6_alias = "pfB_NAmerica_v6"
    v4_lines = _lines(deployed_vm, f"{DENYDIR}/{v4_alias}.txt")
    v6_lines = _lines(deployed_vm, f"{DENYDIR}/{v6_alias}.txt")
    expected_v4 = sorted(["50.114.0.0/22", "214.78.0.0/19", "216.160.83.56/29"])
    expected_v6 = sorted(["2001:480::/43"])
    assert sorted(v4_lines) == expected_v4, f"North America v4 continent members wrong: {v4_lines}"
    assert sorted(v6_lines) == expected_v6, f"North America v6 continent members wrong: {v6_lines}"
    assert len(v4_lines) == 3 and len(v6_lines) == 1, (
        f"v4 must carry US's 3 rows vs v6's 1 -- got v4={v4_lines} v6={v6_lines}"
    )

    # The snapshot is the PRISTINE pre-processing capture; the deny file is the emitted
    # `LC_ALL=C sort -u` set. Same members, different line order -- so pin the member set,
    # not the bytes (the counts below pin the v4/v6 asymmetry).
    v4_snap = sorted(_lines(deployed_vm, f"{SNAPDIR}/{v4_alias}.snap"))
    v6_snap = sorted(_lines(deployed_vm, f"{SNAPDIR}/{v6_alias}.snap"))
    assert v4_snap == expected_v4, f"v4 continent snapshot members != its built .txt: {v4_snap}"
    assert v6_snap == expected_v6, (
        f"v6 continent snapshot members != its built .txt (v4-only snapshot-gate regression): {v6_snap}"
    )
    assert v6_snap != v4_snap, "v4/v6 snapshots must differ -- an identical pair cannot prove the v6 write happened"

    v4_aggcount = _raw(deployed_vm, f"{ORIGDIR}/{v4_alias}.aggcount")
    v6_aggcount = _raw(deployed_vm, f"{ORIGDIR}/{v6_alias}.aggcount")
    assert v4_aggcount == "3\n", f"v4 .aggcount sidecar wrong: {v4_aggcount!r}"
    assert v6_aggcount == "1\n", f"v6 .aggcount sidecar wrong: {v6_aggcount!r}"


# --------------------------------------------------------------------------- #
# R7 -- v6 continent snapshot TRACKS across two regens (not frozen at the seed)
# --------------------------------------------------------------------------- #


def test_recompute_continent_v6_snapshot_tracks_regens(deployed_vm: SmokeVM) -> None:
    """The v6 continent snapshot follows the LIVE regenerated content across two
    passes -- it must not freeze at whatever the first pass (or an upgrade seed)
    wrote (issue #1084 review, ``c3fc39d3``).

    Uses the Europe continent (GI/IM) so this test's continent config is
    independent of R3's North America config -- self-encapsulated, no order
    dependence.

    Scenario: Europe's countries6 swapped between two passes.
      Given (BEFORE) countries6="GI" and a real update pass builds the continent,
      Then the v6 snapshot holds ONLY GI's network,
      When countries6 is changed to "IM" (a genuinely different membership) and a
        SECOND real update pass runs,
      Then the v6 snapshot now holds ONLY IM's network -- DIFFERENT from pass 1's
        content, proving the snapshot tracks the regen rather than staying frozen.
    """
    h.seed_geoip_dataset(deployed_vm)
    h.set_package_enabled(deployed_vm, True)
    v6_alias = "pfB_Europe_v6"

    h.set_ip_continent(deployed_vm, "Europe", action="Deny_Both", countries4="", countries6="GI")
    h.reload(deployed_vm, "update", wait_unbound=False)
    snap_pass1 = _raw(deployed_vm, f"{SNAPDIR}/{v6_alias}.snap")
    assert snap_pass1 == "2a02:ffc0::/29\n", f"pass 1 v6 snapshot wrong (GI only): {snap_pass1!r}"

    h.set_ip_continent(deployed_vm, "Europe", action="Deny_Both", countries4="", countries6="IM")
    h.reload(deployed_vm, "update", wait_unbound=False)
    snap_pass2 = _raw(deployed_vm, f"{SNAPDIR}/{v6_alias}.snap")
    assert snap_pass2 == "2a02:ff40::/29\n", f"pass 2 v6 snapshot wrong (IM only): {snap_pass2!r}"
    assert snap_pass2 != snap_pass1, (
        f"v6 continent snapshot did not track the regenerated membership (frozen-snapshot "
        f"regression): pass1={snap_pass1!r} pass2={snap_pass2!r}"
    )


# --------------------------------------------------------------------------- #
# R8-outage -- GeoIP unavailable this pass: preserve the previous reputation
# match artifacts, never swap/remove them (issue #1228 tracks the restored leg)
# --------------------------------------------------------------------------- #

# pfblockerng.sh's window-awk match-file format (pfb_recompute_rep_subset): one
# "<pfx>.0/24" header line, then one "!<ip>" line per exempted/dup'd member. A
# realistic prior-pass artifact for the SAME offending /24 this test's feed creates.
_R8_MATCH_STAGE = "198.51.100.0/24\n!198.51.100.10\n"
# pfblockerng.sh's pfb_recompute_finish() log line (rec_geoip_ok==0 branch) --
# family-qualified so it cannot be confused with a sibling family's line.
GEOIP_OUTAGE_MARKER = "recompute [ v4 ]: GeoIP unavailable this pass -- keeping previous reputation match artifacts"


def _stage_match_file(vm: SmokeVM, rec_alias: str, contents: str, *, timeout: float = 30.0) -> str:
    """Write ``contents`` verbatim to ``MATCHDIR/match<rec_alias>.txt`` via ``tee`` (mirrors
    ``write_local_feed``'s mkdir-then-tee). ``rec_alias`` is the SNAPSHOT-derived name
    pfblockerng.sh reconciles on (``rec_alias="${rec_snap##*/}"; rec_alias="${rec_alias%%.*}"``,
    pfblockerng.sh:896) -- i.e. ``<header>_<family>``, NOT the pf table's ``pfB_*`` name.

    R8-outage's local one-off: a leading '!' line (the real match-file format) sent through
    ``php_eval``/``file_put_contents`` gets mangled -- pfSsh.php's REPL treats a '!'-led line
    as a raw shell-escape -- so this writes bytes over SSH stdin instead.
    """
    path = f"{MATCHDIR}/match{rec_alias}.txt"
    mk = subprocess.run(
        vm.ssh_argv("/bin/mkdir", "-p", MATCHDIR), capture_output=True, text=True, timeout=timeout, check=False
    )
    if mk.returncode != 0:
        raise RuntimeError(f"_stage_match_file: mkdir {MATCHDIR} failed: rc={mk.returncode} {mk.stderr!r}")
    result = subprocess.run(
        vm.ssh_argv("tee", path), input=contents, capture_output=True, text=True, timeout=timeout, check=False
    )
    if result.returncode != 0:
        raise RuntimeError(f"_stage_match_file({path}) failed: rc={result.returncode} {result.stderr!r}")
    return path


def test_recompute_geoip_outage_preserves_match_artifacts(deployed_vm: SmokeVM) -> None:
    """dMax repmode with an offender present and no ``GeoLite2-Country.mmdb`` reachable
    (the image bakes ``mmdblookup`` but never a database; a database a credentialed
    sibling module downloaded into the shared VM is hidden for this pass and restored
    after): ``pfb_recompute_finish()`` must take the GeoIP-unavailable branch and leave
    a PRE-EXISTING per-alias reputation match file untouched, never swap/remove it.

    STAGED PRECONDITION (documented, not a fake of the code path under test): this box
    can never produce a real ``match<alias>.txt`` through a GeoIP-UP pass (no
    ``.mmdb`` ever exists here -- the restored-GeoIP leg needs real MaxMind
    credentials to fetch a binary database a CSV fixture cannot substitute for;
    tracked as issue #1228). The file staged below stands in for "what a prior pass
    wrote while GeoIP was up" -- realistic content in the real on-disk format, not a
    fabricated code path: the property under test is that THIS pass, with GeoIP
    down, leaves it alone.

    Scenario: one v4 Deny alias with an offending /24 (dmax=2, 3 members present).
      Given (before) a pre-existing match file for that alias's own offending /24,
      When dRep/dMax is on, an offender is present, and a real Force-IP pass runs
        with no ``.mmdb`` on box,
      Then the match file is BYTE-IDENTICAL afterwards (the rec_geoip_ok==1 reconcile
        that would have swapped/removed it never ran) and the pfBlockerNG log gained
        the GeoIP-unavailable line.
    """
    # The outage is the box's natural state (the image bakes mmdblookup, never a database),
    # but a credentialed sibling module can have downloaded one into the session-shared VM --
    # hide it for this pass and put it back, so the branch under test is reached either way.
    mmdb_path = f"{h.GEOIP_SHARE_DIR}/GeoLite2-Country.mmdb"
    stash_path = f"{mmdb_path}.r8-stash"
    stashed = deployed_vm.ssh("/bin/test", "-f", mmdb_path).returncode == 0
    if stashed:
        moved = deployed_vm.ssh("/bin/mv", mmdb_path, stash_path)
        assert moved.returncode == 0, f"could not hide {mmdb_path}: {moved.stderr!r}"

    try:
        h.set_ip_dedup(deployed_vm, False)
        h.set_ip_reputation(deployed_vm, drep=True, dmax=2)
        h.set_ip_suppression(deployed_vm, enabled=False)

        feed = h.write_local_feed(deployed_vm, "r8_feed.txt", "198.51.100.10\n198.51.100.11\n198.51.100.12\n")
        spec = h.IpCase(aliasname="r8", feed_url=feed, header="r8", action="Deny_Both")
        h.inject_ip_lists(deployed_vm, [spec])

        # The reconcile keys on the memberlist's snapshot-derived name (<header>_<family>),
        # never the pf table's pfB_* name -- staging under the latter could never fail.
        rec_alias = f"{spec.header}_{spec.family}"
        match_path = _stage_match_file(deployed_vm, rec_alias, _R8_MATCH_STAGE)

        # BEFORE: the staged artifact round-tripped exactly, and the outage line hasn't fired yet.
        before_content = _raw(deployed_vm, match_path)
        assert before_content == _R8_MATCH_STAGE, f"staged match file did not round-trip: {before_content!r}"
        before_marker = h.count_log_marker(deployed_vm, h.PFB_LOG, GEOIP_OUTAGE_MARKER)

        h.reload(deployed_vm, "updateip", wait_unbound=False)

        after_content = _raw(deployed_vm, match_path)
        assert after_content == before_content, (
            f"GeoIP-outage pass perturbed the previous match artifact: "
            f"before={before_content!r} after={after_content!r}"
        )
        after_marker = h.count_log_marker(deployed_vm, h.PFB_LOG, GEOIP_OUTAGE_MARKER)
        assert after_marker > before_marker, (
            f"expected a new {GEOIP_OUTAGE_MARKER!r} line in {h.PFB_LOG} (before={before_marker}, after={after_marker})"
        )
    finally:
        if stashed:
            deployed_vm.ssh("/bin/mv", stash_path, mmdb_path)


# --------------------------------------------------------------------------- #
# R8-restored -- GeoIP available, cc-list stops matching: a clean pass clears
# the reputation match artifacts (issue #1228)
# --------------------------------------------------------------------------- #


def test_recompute_geoip_restored_clears_match_artifacts(deployed_vm: SmokeVM) -> None:
    """dMax with GeoIP UP: a clean pass (no cc-list match for any offender)
    reconciles away BOTH the consolidated ``matchdedup`` file and a per-alias
    ``match<alias>.txt`` -- ``pfb_recompute_finish()``'s ``rec_geoip_ok=1`` branch
    (issue #1228; the CSV-only fixture could never reach this leg).

    Two offending /24s classify to DIFFERENT actions in the SAME pass -- a cc-list
    HIT can only ever emit ``matchexempt`` (-> the consolidated ``matchdedup``
    file), never a per-alias file (pfblockerng.sh's classify ``case``); only a
    cc-list MISS with ``ccblack=match`` emits ``matchdup`` (-> the per-alias file).
    Both offenders are needed to pin BOTH artifacts' clearing in one pass.

    Scenario: GeoIP is available; the cc-list stops matching either offender.
      Given a v4 Deny feed with two offending /24s whose ``.1`` resolve in the
        seeded database (``67.43.156.0/24`` -> BT, ``111.235.160.0/24`` -> CN;
        dmax below each's member count), and dMax with ``ccwhite='match'``,
        ``ccblack='match'``, ``ccexclude='BT'`` (a HIT for the first, a MISS for
        the second),
      When a real update pass runs,
      Then (BEFORE-STATE, asserted) ``matchdedup_v4.txt`` EXISTS carrying the
        HIT offender's /24 (the ``matchexempt`` action) and the per-alias
        ``match<alias>.txt`` EXISTS carrying the MISS offender's /24 (the
        ``matchdup`` action), and the GeoIP-unavailable log line did NOT fire
        (this pass had GeoIP),
      When ``ccexclude`` is changed to a country neither offender is in
        (``GI``) and ``ccblack`` is turned off (so neither offender classifies
        into ANY action -- a genuinely clean pass) and a SECOND real pass runs,
      Then both ``matchdedup_v4.txt`` and the per-alias ``match<alias>.txt`` are
        GONE -- the clean pass reconciled them away, and the GeoIP-unavailable
        line STILL did not fire.
    """
    h.seed_geoip_dataset(deployed_vm)
    h.set_ip_dedup(deployed_vm, False)
    h.set_ip_suppression(deployed_vm, enabled=False)

    matchdedup_path = f"{MATCHDIR}/matchdedup_v4.txt"
    match_alias_path = f"{MATCHDIR}/matchd2_v4.txt"
    # issue #760/#1228 hostile input: a stale artifact from an earlier module run
    # would make the before-state assertion below meaningless -- start clean, loudly.
    for stale in (matchdedup_path, match_alias_path):
        rm = deployed_vm.ssh("/bin/rm", "-f", stale)
        assert rm.returncode == 0, f"could not clear stale artifact {stale}: rc={rm.returncode} {rm.stderr!r}"

    feed = h.write_local_feed(
        deployed_vm,
        "d2_feed.txt",
        "67.43.156.10\n67.43.156.11\n67.43.156.12\n111.235.160.10\n111.235.160.11\n111.235.160.12\n",
    )
    spec = h.IpCase(aliasname="d2", feed_url=feed, header="d2", action="Deny_Both")
    h.inject_ip_lists(deployed_vm, [spec])

    # PASS 1: ccexclude="BT" -- a HIT for 67.43.156 (-> matchexempt/matchdedup),
    # a MISS for 111.235.160 with ccblack='match' (-> matchdup/per-alias file).
    h.set_ip_reputation(deployed_vm, drep=True, dmax=2, ccwhite="match", ccblack="match", ccexclude="BT")
    before_marker = h.count_log_marker(deployed_vm, h.PFB_LOG, GEOIP_OUTAGE_MARKER)
    h.reload(deployed_vm, "updateip", wait_unbound=False)

    matchdedup_pass1 = _raw(deployed_vm, matchdedup_path)
    assert matchdedup_pass1 == "67.43.156.0/24\n!67.43.156.10\n!67.43.156.11\n!67.43.156.12\n", (
        f"matchdedup_v4.txt wrong after the HIT pass (expected the BT offender's /24 + members): {matchdedup_pass1!r}"
    )
    match_alias_pass1 = _raw(deployed_vm, match_alias_path)
    assert match_alias_pass1 == "111.235.160.0/24\n!111.235.160.10\n!111.235.160.11\n!111.235.160.12\n", (
        f"per-alias match file wrong after the MISS+ccblack=match pass (expected the CN offender's "
        f"/24 + members): {match_alias_pass1!r}"
    )
    marker_pass1 = h.count_log_marker(deployed_vm, h.PFB_LOG, GEOIP_OUTAGE_MARKER)
    assert marker_pass1 == before_marker, (
        f"GeoIP-unavailable line fired on a pass that HAD GeoIP: before={before_marker} after={marker_pass1}"
    )

    # PASS 2: ccexclude="GI" (a substring of neither BT nor CN) + ccblack='off' --
    # NEITHER offender classifies into any action, so the reconcile clears both.
    h.set_ip_reputation(deployed_vm, drep=True, dmax=2, ccwhite="match", ccblack="off", ccexclude="GI")
    h.reload(deployed_vm, "updateip", wait_unbound=False)

    assert not _exists(deployed_vm, matchdedup_path), (
        f"matchdedup_v4.txt survived a clean pass (no cc-list match) -- reconcile did not fire: "
        f"content={_raw(deployed_vm, matchdedup_path)!r}"
    )
    assert not _exists(deployed_vm, match_alias_path), (
        f"per-alias match file survived a clean pass (no cc-list match) -- reconcile did not fire: "
        f"content={_raw(deployed_vm, match_alias_path)!r}"
    )
    marker_pass2 = h.count_log_marker(deployed_vm, h.PFB_LOG, GEOIP_OUTAGE_MARKER)
    assert marker_pass2 == before_marker, (
        f"GeoIP-unavailable line fired on the restored/clean pass: before={before_marker} after={marker_pass2}"
    )
