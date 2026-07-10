"""ADR-62 — the closing §7 acceptance rows (live pfSense VM).

Retiring PHP's feed-level ABP classification (``$easylist``/header-sniff/
``$validate_header``) in favour of a single per-line capture predicate
(``pfb_dnsbl_is_abp_rule_line``, mirrored in Python's per-line routing) is proven
off-appliance by the byte-identity corpus (``tests/test_adr62_*``,
``tests/php/Adr62*Test.php``). This module supplies the AUTOMATED live-VM rows
ADR.md §7 requires for Accepted (CLAUDE.md "ADR acceptance" — automated tests, not
a manual sign-off): each of the seven acceptance rows maps to one test here, or to
an existing case elsewhere (noted in the row's docstring) that already covers it.

DESELECTED from the default ``python -m pytest`` (``--ignore=tests/smoke`` in
pyproject.toml). Run only by the smoke workflow::

    python -m pytest tests/smoke -m smoke --override-ini="addopts="

Row -> test map (ADR.md §7):
  1. Plain hosts feed            -> test_smoke_feeds.py::test_dnsbl_http_hosts_feed_loads (reused, unchanged by ADR-62)
  2. ABP feed, full shape set    -> test_adr62_abp_full_shape_set_no_marker (this module)
  3. Mixed plain feed, D2        -> test_adr62_mixed_plain_feed_all_block_delta_d2 (this module)
  4. Bracketed IPv6 vs [Adblock] -> test_adr62_bracketed_ipv6_dnsblip_vs_adblock_marker (this module)
  5. CSV feed type                -> test_adr62_csv_bambenek_feed_blocks (this module)
  6. IDN/punycode                -> test_adr62_idn_raw_unicode_blocks_under_punycode (this module)
  7. Reuse + TLD-enabled run      -> test_adr62_reused_feed_old_dialect_txt_resolves_same_verdict
                                     + test_adr62_tld_enabled_run_keeps_plain_row_classification (this module)

These need the booted ``smoke_vm`` fixture, the branch ``.pkg`` (``SMOKE_PKG``), and
the smoke deps; without them they skip cleanly.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from . import helpers as h
from .conftest import STUB_DNS_A, SmokeVM, _StubDnsServer

pytestmark = pytest.mark.smoke


@pytest.fixture(scope="module")
def deployed_vm(smoke_vm: SmokeVM, client_vm: SmokeVM, stub_dns: _StubDnsServer) -> Iterator[SmokeVM]:
    """Deploy the branch .pkg once for the ADR-62 closing rows (mirrors the ABP module).

    All feeds here are delivered via ``write_local_feed`` (no HTTP mock needed — Part
    C's HTTP-fetch contract is proven elsewhere); egress is managed per-case by
    ``CaseContext``. The DNSBL VIP is injected once (DNSBL force-disables itself
    without one) and System DNS points at the controlled stub.
    """
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    h.ensure_dnsbl_vip(smoke_vm)
    h.use_system_dns_upstream(smoke_vm)
    h.assert_link_health(client_vm, smoke_vm, control_name=h.unique_domain())
    try:
        yield smoke_vm
    finally:
        h.unblock_egress()
        # MODULE ISOLATION: several cases below enable non-default DNSBL settings
        # (dnsbl_ip_action, tld_enabled) via inject()'s config-merge, which reset()
        # does not clear (same isolation concern test_smoke_abp.py documents).
        try:
            h.clear_dnsbl_settings(smoke_vm)
        except Exception as cleanup_exc:  # noqa: BLE001
            print(f"[smoke] clear_dnsbl_settings failed on ADR-62 teardown (suppressed): {cleanup_exc!r}")
        h.collect_host_diagnostics(smoke_vm)


# --------------------------------------------------------------------------- #
# Row 2 — an ABP-headed feed's full shape set: || blocks, @@|| resolves (already
# proven by test_smoke_feeds.py::test_dnsbl_http_abp_feed_loads), PLUS the shapes
# that test does not cover: a feed /regex/ block, an element-hiding line producing
# NO spurious domain (D2/D3), and — the ADR-62-specific assertion — NO '.abp'
# marker file on-box (the marker mechanism is retired; every feed is tagged
# 'plain' now, per Decision 5).
# --------------------------------------------------------------------------- #


@pytest.mark.timeout(300)
def test_adr62_abp_full_shape_set_no_marker(deployed_vm: SmokeVM, client_vm: SmokeVM) -> None:
    """Row 2: an ABP-headed feed's ||/regex/element-hiding shapes, with NO '.abp' marker.

    Given (before the feed loads) both the anchor and the regex targets RESOLVE via
      the controlled stub, and the element-hiding line's domain-shaped prefix ALSO
      resolves.
    When a feed carrying the ``[Adblock Plus 2.0]`` header plus a ``||anchor^``
      block, a ``/^regex$/`` block, and a ``elem##.ad-banner`` element-hiding line
      loads (Force Update),
    Then the anchor and regex targets are VIP-blocked (per-line capture routes both
      to ``parse_abp``, unchanged from before this ADR — the header line itself is
      now an ordinary skippable ``[...]`` control line, ADR-62 Decision 1/2), the
      element-hiding target STILL RESOLVES (its domain-shaped prefix must never
      become a spurious block — D2/D3), and the feed's ``.abp`` marker file is
      ABSENT on-box (Decision 5: the marker mechanism is retired; a pre-fix reader
      would find this feed marked ``format_hint='abp'`` via a stray marker file).
    """
    anchor = h.unique_domain("adr62r2anchor")  # ||anchor^ -> must BLOCK
    regex_target = h.unique_domain("adr62r2rx")  # /^regex$/ -> must BLOCK
    elem = h.unique_domain("adr62r2elem")  # elem##.ad-banner -> must RESOLVE (no spurious block)
    regex_line = "/^" + regex_target.replace(".", "\\.") + "$/"
    body = h.abp_feed(f"||{anchor}^", regex_line, f"{elem}##.ad-banner")
    header = "adr62row2"
    feed_url = h.write_local_feed(deployed_vm, "smoke_adr62_row2.txt", body)
    spec = h.DnsblCase(aliasname="adr62row2", feed_url=feed_url, header=header, mode=h.DnsblMode.VIP)

    for name in (anchor, regex_target, elem):
        before = h.dns_probe_client(client_vm, name, "A")
        assert h.resolves_to(before, STUB_DNS_A), f"{name} should resolve via stub BEFORE listing, got {before}"
        assert not h.is_vip(before), f"{name} unexpectedly VIP-blocked before any feed: {before}"

    with h.CaseContext(deployed_vm, spec):
        h.unblock_egress()  # the "resolves" probes (elem) must reach the controlled stub
        for name in (anchor, regex_target, elem):
            h.flush_unbound_name(deployed_vm, name)

        ans_anchor = h.dns_probe_client_until(client_vm, anchor, h.is_vip)
        assert not h.resolves_to(ans_anchor, STUB_DNS_A), f"{anchor} still resolving after ||{anchor}^: {ans_anchor}"

        ans_regex = h.dns_probe_client_until(client_vm, regex_target, h.is_vip)
        assert not h.resolves_to(ans_regex, STUB_DNS_A), (
            f"{regex_target} still resolving after its feed /regex/ block: {ans_regex}"
        )

        ans_elem = h.dns_probe_client(client_vm, elem, "A")
        assert h.resolves_to(ans_elem, STUB_DNS_A), (
            f"element-hiding line {elem}##.ad-banner must NOT block {elem} (D2/D3 no-spurious-domain): {ans_elem}"
        )
        assert not h.is_vip(ans_elem), f"{elem} wrongly VIP-blocked by an element-hiding line: {ans_elem}"

        marker = f"{h.PFB_DBDIR}/dnsbl/{header}.abp"
        marker_check = deployed_vm.ssh("/bin/test", "-e", marker)
        assert marker_check.returncode != 0, (
            f"'.abp' marker file {marker} exists on-box — the marker mechanism is retired (ADR-62 Decision 5), "
            f"every feed is tagged 'plain' now: test -e rc={marker_check.returncode}"
        )


# --------------------------------------------------------------------------- #
# Row 3 — a mixed, HEADER-LESS plain feed (hosts + stray ||anchor^ + /regex/):
# ALL THREE block (delta D2 — a feed regex rule, host-mangled and dropped before
# this ADR, is now honoured wherever it occurs).
# --------------------------------------------------------------------------- #


@pytest.mark.timeout(300)
def test_adr62_mixed_plain_feed_all_block_delta_d2(deployed_vm: SmokeVM, client_vm: SmokeVM) -> None:
    """Row 3 (delta D2): a header-less mixed feed — hosts + ||anchor^ + /regex/ — all block.

    Given (before the feed loads) all three names RESOLVE via the controlled stub.
    When a feed with NO ABP header (``[Adblock``/``! Title:``) mixing a hosts-format
      line, a stray ``||anchor^`` anchor, and a ``/^regex$/`` block loads,
    Then all three are VIP-blocked: the hosts line via the unaffected plain
      pipeline, the anchor via the pre-existing ADR-21 per-line capture, and the
      regex line via ADR-62's broadened capture (delta D2 — pre-ADR-62 this line
      was host-mangled + parse-fail-logged, never a block; the D2 delta's own
      target: a feed regex rule now works wherever it occurs, not only inside a
      header-classified ABP feed).
    """
    hosts_dom = h.unique_domain("adr62r3host")
    anchor_dom = h.unique_domain("adr62r3anchor")
    regex_dom = h.unique_domain("adr62r3rx")
    regex_line = "/^" + regex_dom.replace(".", "\\.") + "$/"
    body = "\n".join([f"0.0.0.0 {hosts_dom}", f"||{anchor_dom}^", regex_line]) + "\n"
    feed_url = h.write_local_feed(deployed_vm, "smoke_adr62_row3.txt", body)
    spec = h.DnsblCase(aliasname="adr62row3", feed_url=feed_url, header="adr62row3", mode=h.DnsblMode.VIP)

    for name in (hosts_dom, anchor_dom, regex_dom):
        before = h.dns_probe_client(client_vm, name, "A")
        assert h.resolves_to(before, STUB_DNS_A), f"{name} should resolve via stub BEFORE listing, got {before}"
        assert not h.is_vip(before), f"{name} unexpectedly VIP-blocked before any feed: {before}"

    with h.CaseContext(deployed_vm, spec):
        h.unblock_egress()
        for name in (hosts_dom, anchor_dom, regex_dom):
            h.flush_unbound_name(deployed_vm, name)
            ans = h.dns_probe_client_until(client_vm, name, h.is_vip)
            assert not h.resolves_to(ans, STUB_DNS_A), f"{name} still resolving after the mixed feed loaded: {ans}"


# --------------------------------------------------------------------------- #
# Row 4 — a bracketed IPv6 literal collects into the DNSBLIP alias table; a
# genuine '[Adblock Plus 2.0]' marker (also bracket-wrapped) does NOT.
# --------------------------------------------------------------------------- #


@pytest.mark.timeout(300)
def test_adr62_bracketed_ipv6_dnsblip_vs_adblock_marker(deployed_vm: SmokeVM, client_vm: SmokeVM) -> None:
    """Row 4 (Semantics #3): a bracketed IPv6 literal collects; a real [Adblock...] marker does not.

    Scenario: a feed carries the ``[Adblock Plus 2.0]`` header line (a bracket-
    wrapped NON-IPv6 control line — must be SKIPPED, never mistaken for an
    address) followed by a bracketed IPv6 literal (``[2001:db8:aaaa:bbbb::]`` —
    RFC 3849 documentation range, issue #938's shape) and a plain domain (to keep
    the feed a valid DNSBL entry).

    Given the domain RESOLVES via the stub before the feed loads.
    When the feed loads with ``dnsbl_ip_action="Deny_Both"`` (the "DNSBL IP"
      firewall feature) and a Force Update runs,
    Then the domain is VIP-blocked (feed loaded), the UNWRAPPED IPv6 address
      is present in ``pfB_DNSBLIP_v6`` (``pfb_dnsbl_unbracket_ip6`` — unaffected
      by this ADR, still runs BEFORE the universal control-line skip), and NO
      DNSBLIP_v6 member contains the literal ``Adblock`` text (the header line
      was correctly skipped as a non-IPv6 bracketed control line, never
      misparsed as an address).
    """
    domain = h.unique_domain("adr62r4dom")
    ipv6_lit = "2001:db8:aaaa:bbbb::"  # RFC 3849 documentation range
    body = "\n".join([h.ABP_HEADER, f"[{ipv6_lit}]", domain]) + "\n"
    feed_url = h.write_local_feed(deployed_vm, "smoke_adr62_row4.txt", body)
    spec = h.DnsblCase(
        aliasname="adr62row4",
        feed_url=feed_url,
        header="adr62row4",
        mode=h.DnsblMode.VIP,
        dnsbl_ip_action="Deny_Both",
    )

    before = h.dns_probe_client(client_vm, domain, "A")
    assert h.resolves_to(before, STUB_DNS_A), f"{domain} should resolve via stub BEFORE listing, got {before}"

    with h.CaseContext(deployed_vm, spec):
        h.flush_unbound_name(deployed_vm, domain)
        ans = h.dns_probe_client_until(client_vm, domain, h.is_vip)
        assert not h.resolves_to(ans, STUB_DNS_A), f"{domain} still resolving after the feed loaded: {ans}"

        v6_members = h.wait_pfctl_table(deployed_vm, "pfB_DNSBLIP_v6")
        assert h.member_present(v6_members, ipv6_lit), (
            f"bracketed IPv6 literal {ipv6_lit} not collected into pfB_DNSBLIP_v6: {v6_members}"
        )
        assert not any("Adblock" in m for m in v6_members), (
            f"the '[Adblock Plus 2.0]' header line leaked into pfB_DNSBLIP_v6 as a member: {v6_members}"
        )


# --------------------------------------------------------------------------- #
# Row 5 — a representative CSV feed type (Bambenek Consulting 'bbc': 4-col CSV,
# domain detected via csvline[3] containing 'osint.bambenekconsulting.com'). The
# CSV switch (inc:16508-16609) is untouched by this ADR (§2 item 3, "Explicitly
# kept / out of scope" — CSV column extraction stays in PHP unchanged).
# --------------------------------------------------------------------------- #


@pytest.mark.timeout(300)
def test_adr62_csv_bambenek_feed_blocks(deployed_vm: SmokeVM, client_vm: SmokeVM) -> None:
    """Row 5: a Bambenek Consulting ('bbc') CSV-format DNSBL row extracts and blocks.

    Given the CSV row's domain (col 0) RESOLVES via the stub before the feed loads.
    When a single-line 4-column CSV body (``domain,comment,date,url``, with col 3
      containing ``osint.bambenekconsulting.com`` — the detection marker
      ``pfblockerng.inc:16574-16580``) loads,
    Then the domain is VIP-blocked — the CSV switch (untouched by this ADR)
      extracts col 0 and the extracted domain flows through the SAME plain
      pipeline (host-prefix/scheme/IDN/pfb_filter) as any other domain line.
    """
    domain = h.unique_domain("adr62r5csv")
    body = f"{domain},bambenek-comment,20260101,http://osint.bambenekconsulting.com/manual/index.php\n"
    feed_url = h.write_local_feed(deployed_vm, "smoke_adr62_row5.txt", body)
    spec = h.DnsblCase(aliasname="adr62row5", feed_url=feed_url, header="adr62row5", mode=h.DnsblMode.VIP)

    before = h.dns_probe_client(client_vm, domain, "A")
    assert h.resolves_to(before, STUB_DNS_A), f"{domain} should resolve via stub BEFORE listing, got {before}"

    with h.CaseContext(deployed_vm, spec):
        h.flush_unbound_name(deployed_vm, domain)
        ans = h.dns_probe_client_until(client_vm, domain, h.is_vip)
        assert not h.resolves_to(ans, STUB_DNS_A), (
            f"CSV-extracted domain {domain} still resolving after the bbc feed loaded: {ans}"
        )


# --------------------------------------------------------------------------- #
# Row 6 — a raw (non-punycode) IDN feed line blocks under its punycode form.
# PHP's idn_to_ascii() converts at parse time (pfblockerng.inc:16713); Python
# never converts (ADR §1.5) — the query MUST use the already-converted form.
# ``café-adr62row6.com`` -> ``xn--caf-adr62row6-dhb.com``, verified against the
# REAL idn_to_ascii() this session (`php -r 'echo idn_to_ascii(...)'`) — a fixed
# literal (like the existing IDN-confusable smoke cases in test_smoke_matrix.py),
# not helpers.unique_domain(), because the exact Unicode shape under test cannot
# be a random hex label.
# --------------------------------------------------------------------------- #


@pytest.mark.timeout(300)
def test_adr62_idn_raw_unicode_blocks_under_punycode(deployed_vm: SmokeVM, client_vm: SmokeVM) -> None:
    """Row 6: a raw Unicode IDN feed line blocks when queried under its punycode form.

    Given the punycode name RESOLVES via the stub before the feed loads.
    When a feed containing the RAW UTF-8 line ``café-adr62row6.com`` loads,
    Then a query for ``xn--caf-adr62row6-dhb.com`` (PHP's ``idn_to_ascii()``
      conversion, verified against the real function) is VIP-blocked — proving
      the plain pipeline's IDN conversion (unaffected by this ADR) still runs
      for a bare domain line reaching the plain path.
    """
    raw = "café-adr62row6.com"
    punycode = "xn--caf-adr62row6-dhb.com"
    body = f"{raw}\n"
    feed_url = h.write_local_feed(deployed_vm, "smoke_adr62_row6.txt", body)
    spec = h.DnsblCase(aliasname="adr62row6", feed_url=feed_url, header="adr62row6", mode=h.DnsblMode.VIP)

    before = h.dns_probe_client(client_vm, punycode, "A")
    assert h.resolves_to(before, STUB_DNS_A), f"{punycode} should resolve via stub BEFORE listing, got {before}"

    with h.CaseContext(deployed_vm, spec):
        h.flush_unbound_name(deployed_vm, punycode)
        ans = h.dns_probe_client_until(client_vm, punycode, h.is_vip)
        assert not h.resolves_to(ans, STUB_DNS_A), (
            f"punycode form {punycode} of raw IDN line {raw!r} still resolving after the feed loaded: {ans}"
        )


# --------------------------------------------------------------------------- #
# Row 7a — a feed REUSED (not re-downloaded) whose on-disk '.txt' predates this
# pass resolves the SAME verdict as its pre-placed content, and a stale '.abp'
# marker (an old install's leftover) is swept opportunistically (Decision 5).
#
# NOTE ON SCOPE: this row uses the 6-col plain dialect, unchanged by this ADR
# (Semantics #7's SAFE sub-case). A bare-domain line inside an OLD raw-ABP-
# verbatim '.txt' (written by a pre-ADR-62 $easylist feed) hits a genuine,
# separately-tracked defect on reuse (issue #1105, discovered while building this
# row) — pfb_unbound_python_sources() drops a comma-less line instead of writing
# it verbatim, so that specific sub-case is DELIBERATELY NOT asserted here (it
# would be a documented-red test, not a passing acceptance row); see ADR.md
# Semantics #7 and issue #1105 for the tracked gap.
# --------------------------------------------------------------------------- #


@pytest.mark.timeout(300)
def test_adr62_reused_feed_old_dialect_txt_resolves_same_verdict(deployed_vm: SmokeVM, client_vm: SmokeVM) -> None:
    """Row 7a (Semantics #7): a reused feed's pre-existing '.txt' resolves unchanged; stale marker swept.

    Given a configured, already-loaded DNSBL feed (a normal pass downloaded and
      blocked domain A), whose on-disk staging file (``{dnsdir}/{header}.txt``)
      is then OVERWRITTEN with an old-generation 6-col row for a different
      domain B plus a stale ``{header}.abp`` marker — simulating the on-disk
      state a pre-ADR-62 install leaves behind across a pkg upgrade — while the
      feed URL now serves a DIFFERENT (decoy) domain C.
    When a scheduled-style (NON-force) update pass runs with the config
      UNCHANGED — no alias was added or removed, so the change sweep does NOT
      run its ``rmdir_recursive({dnsdir})`` staging wipe, and the pass reaches
      the reuse fork (gated on ``$pfbreuse == ''``: files present, no
      ``.update``/``.fail`` marker, non-force trigger),
    Then the OVERWRITTEN old-dialect domain B is VIP-blocked (the ``.txt`` was
      used as-is, never re-downloaded or re-parsed), the DECOY domain C (which
      only a real re-download could load) still RESOLVES, and the stale
      ``.abp`` marker is GONE (Decision 5's opportunistic sweep on the reuse
      fork).
    """
    header = "adr62row7reuse"
    loaded_domain = h.unique_domain("adr62r7base")
    reused_domain = h.unique_domain("adr62r7old")
    decoy_domain = h.unique_domain("adr62r7decoy")

    feed_name = "smoke_adr62_row7_feed.txt"
    feed_url = h.write_local_feed(deployed_vm, feed_name, f"{loaded_domain}\n")
    spec = h.DnsblCase(aliasname="adr62row7reuse", feed_url=feed_url, header=header, mode=h.DnsblMode.VIP)

    dnsbl_dir = f"{h.PFB_DBDIR}/dnsbl"
    marker = f"{dnsbl_dir}/{header}.abp"

    for name in (loaded_domain, reused_domain, decoy_domain):
        before = h.dns_probe_client(client_vm, name, "A")
        assert h.resolves_to(before, STUB_DNS_A), f"{name} should resolve via stub BEFORE listing, got {before}"

    with h.CaseContext(deployed_vm, spec):
        h.unblock_egress()  # the decoy "still resolves" probe must reach the controlled stub

        # Baseline: the feed genuinely loaded via the normal download path.
        h.flush_unbound_name(deployed_vm, loaded_domain)
        ans_loaded = h.dns_probe_client_until(client_vm, loaded_domain, h.is_vip)
        assert not h.resolves_to(ans_loaded, STUB_DNS_A), (
            f"baseline feed domain {loaded_domain} still resolving after the initial load: {ans_loaded}"
        )

        # Simulate the pre-upgrade on-disk state: an old-generation '.txt' (6-col
        # dialect, different domain) + a stale '.abp' marker; the served feed now
        # carries a decoy so any re-download is detectable.
        h.write_local_feed(deployed_vm, f"dnsbl/{header}.txt", f",{reused_domain},,1,{header},{header}\n")
        h.write_local_feed(deployed_vm, f"dnsbl/{header}.abp", "")
        h.write_local_feed(deployed_vm, feed_name, f"{decoy_domain}\n")

        marker_before = deployed_vm.ssh("/bin/test", "-e", marker)
        assert marker_before.returncode == 0, f"test setup failed: stale marker {marker} not present before the pass"

        # Non-force pass, config unchanged: reaches the reuse ('exists') fork.
        # A Force-DNSBL reload cannot — it sets reuse_dnsbl='on' and reloads from
        # the '.orig' download cache, re-parsing the ORIGINAL content instead of
        # honouring the staged '.txt'.
        h.reload(deployed_vm, "update")

        h.flush_unbound_name(deployed_vm, reused_domain)
        ans_reused = h.dns_probe_client_until(client_vm, reused_domain, h.is_vip)
        assert not h.resolves_to(ans_reused, STUB_DNS_A), (
            f"old-dialect reused-'.txt' domain {reused_domain} still resolving after the non-force pass "
            f"(the reuse fork should have used the staged '.txt' as-is): {ans_reused}"
        )

        ans_decoy = h.dns_probe_client(client_vm, decoy_domain, "A")
        assert h.resolves_to(ans_decoy, STUB_DNS_A), (
            f"decoy domain {decoy_domain} (only reachable via a real re-download) is blocked — "
            f"the feed was re-downloaded instead of reusing the staged '.txt': {ans_decoy}"
        )
        assert not h.is_vip(ans_decoy), f"decoy domain {decoy_domain} wrongly VIP-blocked: {ans_decoy}"

        marker_after = deployed_vm.ssh("/bin/test", "-e", marker)
        assert marker_after.returncode != 0, (
            f"stale '.abp' marker {marker} still present after the reuse pass — Decision 5's opportunistic "
            f"sweep should have removed it: test -e rc={marker_after.returncode}"
        )


# --------------------------------------------------------------------------- #
# Row 7b — a TLD-enabled update run does not disturb ordinary plain-row
# classification, in the EXACT shape that triggered issue #1060 (a mixed feed —
# a comma-first plain row alongside a verbatim-captured line — with NO
# ABP-classified feed configured at all, so the old '$abp_feeds' marker glob was
# always empty). Deep TLD-classification correctness (whole-TLD blacklisting,
# the empty-feed-column skip itself) is the PHPUnit oracle's job
# (tests/php/Adr62TldAnalysisCorpusTest.php) — this row is a coarse live
# end-to-end regression guard that turning pfb_tld on does not break normal
# DNSBL blocking for the plain/anchor rows sharing that same update pass.
# --------------------------------------------------------------------------- #


@pytest.mark.timeout(300)
def test_adr62_tld_enabled_run_keeps_plain_row_classification(deployed_vm: SmokeVM, client_vm: SmokeVM) -> None:
    """Row 7b (issue #1060 regression guard): TLD mode + a mixed feed still blocks both rows.

    Given both names RESOLVE via the stub before the feed loads.
    When ``pfb_tld=on`` (no TLD blacklist configured) and a mixed, HEADER-LESS
      feed (a hosts line + a verbatim ``||anchor^`` line — no ABP-classified
      feed anywhere in this pass, matching issue #1060's exact trigger shape)
      loads,
    Then both the hosts-line domain and the anchor domain are VIP-blocked — the
      TLD-analysis pass's unconditional empty-feed-column skip (ADR-62 Phase 5,
      the surviving half of issue #1060) does not misclassify the comma-first
      plain row just because a verbatim-captured line coexists in the same feed.
    """
    hosts_dom = h.unique_domain("adr62r7bhost")
    anchor_dom = h.unique_domain("adr62r7banchor")
    body = "\n".join([f"0.0.0.0 {hosts_dom}", f"||{anchor_dom}^"]) + "\n"
    feed_url = h.write_local_feed(deployed_vm, "smoke_adr62_row7b.txt", body)
    spec = h.DnsblCase(
        aliasname="adr62row7btld",
        feed_url=feed_url,
        header="adr62row7btld",
        mode=h.DnsblMode.VIP,
        tld_enabled=True,
    )

    for name in (hosts_dom, anchor_dom):
        before = h.dns_probe_client(client_vm, name, "A")
        assert h.resolves_to(before, STUB_DNS_A), f"{name} should resolve via stub BEFORE listing, got {before}"

    with h.CaseContext(deployed_vm, spec):
        for name in (hosts_dom, anchor_dom):
            h.flush_unbound_name(deployed_vm, name)
            ans = h.dns_probe_client_until(client_vm, name, h.is_vip)
            assert not h.resolves_to(ans, STUB_DNS_A), (
                f"{name} still resolving with pfb_tld=on (TLD mode broke ordinary plain-row blocking): {ans}"
            )
