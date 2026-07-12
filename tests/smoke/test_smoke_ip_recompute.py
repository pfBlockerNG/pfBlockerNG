"""issue #1084 live-VM smoke: the batch IP `recompute` flow end-to-end.

pfBlockerNG's batch ``recompute`` verb (``pfblockerng.sh``, invoked from
``pfblockerng.inc`` ~19060-19135) replaces the old incremental duplicate()/dMax/pMax
pass: real feeds parse -> a pristine post-preprocessing snapshot per header
(``pfb_ip_recompute_write_snapshot``) -> a per-family memberlist -> ONE
``pfblockerng.sh recompute`` call that rewrites EVERY alias of that family from its
snapshot -> the rewritten deny files load into their pf tables. This module drives
that whole pipeline through the real CLI (``helpers.reload``) on a real pfSense VM
and observes the on-box deny/master files + live ``pfctl`` tables — the CI-runnable,
credential-free half (Part 1 of issue #1170); Continent/GeoIP-dependent rows are
Part 2.

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

Reload-scope note: R1/R2/R5/R9 are single-pass (or repeat-input) cases and use
``reload(scope='updateip')`` — its ``force=true`` sets ``$pfb['reuse']='on'`` for the
WHOLE pass, so every configured Deny alias is genuinely reprocessed (never the
early "exists, skip" cache) without needing a marker touch (see
``test_smoke_suppression.py``'s identical rationale). R4/R6 need to distinguish "this
alias's OWN feed did not change" from "recompute ran anyway" — the exact axis
`force=true` collapses (every alias becomes `$feed_changed` every pass) — so they use
the ADR-40-proven two-pass shape instead: ``reload(scope='update')`` (respects the
per-alias reuse-skip) + ``force_ip_refetch()`` on ONLY the alias that must genuinely
re-ingest.

WHAT STAYS FOR STEP 2 (Continent/GeoIP-dependent, per the issue #1170 brief):

* R3/R7/R8 — anything requiring a real MaxMind GeoIP database (dMax/match-mode
  country classification, Continent-list interaction with recompute).

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
from collections.abc import Iterator

import pytest

from . import helpers as h
from .conftest import SmokeVM

pytestmark = pytest.mark.smoke

CFG_IP_SETTINGS = h.CFG_IP_SETTINGS
DENYDIR = f"{h.PFB_DBDIR}/deny"
SNAPDIR = f"{h.PFB_DBDIR}/snapshot"
MASTERFILE = f"{h.PFB_DBDIR}/masterfile"

# A fixed, known placeholder (default is PHP-side only — pfblockerng.sh reads the RAW
# config node via read_xml_tag.sh, with no fallback — see pfb['ip_ph']'s pfb_filter
# default vs. the shell's direct XML read) so R5/R9's collapse assertion compares
# against an EXACT string instead of an ambiguous default.
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
        # Leave no dedup/reputation/suppression knob set for the next module's reloads.
        h.set_ip_dedup(smoke_vm, False)
        h.set_ip_reputation(smoke_vm)
        h.set_ip_suppression(smoke_vm, enabled=False)
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
    assert set(a_lines) == {"203.0.113.0/24", "198.51.100.211"}, f"feed A perturbed: {a_lines}"
    assert set(b_lines) == {"198.51.100.212"}, f"feed B ownership wrong (overlap not pruned): {b_lines}"

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
    expected = {"2001:db8:5678::/64", "2001:db8:5678:1::42"}
    assert set(snap_lines) == expected, f"snapshot content wrong after first ingest: {snap_lines}"
    assert set(deny_lines_pass1) == expected, f"deny file content wrong after first ingest: {deny_lines_pass1}"
    members_pass1 = h.wait_pfctl_table(deployed_vm, spec.alias)
    assert h.member_present(members_pass1, "2001:db8:5678:1::42"), f"pf table missing bare host: {members_pass1}"
    assert h.member_covers(members_pass1, "2001:db8:5678::1"), f"pf table missing /64 coverage: {members_pass1}"

    # Held static: no edit, no force_ip_refetch -- updateip's force=true alone
    # reprocesses this alias again from its cached raw body.
    h.reload(deployed_vm, "updateip", wait_unbound=False)
    deny_lines_pass2 = _lines(deployed_vm, f"{DENYDIR}/r2v6_v6.txt")
    assert set(deny_lines_pass2) == set(deny_lines_pass1), (
        f"deny file changed across a static pass: pass1={deny_lines_pass1} pass2={deny_lines_pass2}"
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
    assert set(a_before) == {"198.51.100.31"}, f"A did not settle before the change: {a_before}"
    assert set(b_before) == {"198.51.100.41"}, f"B did not settle before the change: {b_before}"

    # CHANGE: A gains a row via a REAL re-download; B is left completely alone.
    h.write_local_feed(deployed_vm, "r4_feed_a.txt", "198.51.100.31\n198.51.100.32\n")
    h.force_ip_refetch(deployed_vm, "r4a_v4")
    h.reload(deployed_vm, "update")

    a_after = _lines(deployed_vm, f"{DENYDIR}/r4a_v4.txt")
    b_after = _lines(deployed_vm, f"{DENYDIR}/r4b_v4.txt")
    assert set(a_after) == {"198.51.100.31", "198.51.100.32"}, f"A's change was not applied: {a_after}"
    assert set(b_after) == {"198.51.100.41"}, (
        f"B (never touched) was dropped/perturbed by the family rewrite: {b_after}"
    )

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
        closing pass would leave 0 bytes) and the pf table carries the placeholder.
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
    members = h.wait_pfctl_table(deployed_vm, spec.alias)
    assert h.member_present(members, PLACEHOLDER_IP), f"pf table missing the placeholder: {members}"


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

    collapse_members = h.wait_pfctl_table(deployed_vm, spec_collapse.alias)
    assert h.member_present(collapse_members, PLACEHOLDER_IP), f"pf table missing the placeholder: {collapse_members}"
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
    snapshot is a PRE-suppression capture (issue #1084 review comment,
    pfblockerng.inc ~5065), so recompute alone would resurrect a suppressed IP on
    ANY pass that rewrites that alias -- ``pfb_ip_suppress_body_active()``'s
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
