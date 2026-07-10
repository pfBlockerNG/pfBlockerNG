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
  7. Reuse + TLD-enabled run      -> test_adr62_reused_feed_current_generation_ndjson_resolves_without_redownload
                                     + test_adr62_tld_enabled_run_keeps_plain_row_classification (this module)

NDJSON interchange format (issue #1083): the per-feed staging '.txt'/'.raw' files are
schema-v1 NDJSON now (docs/misc/architecture-notes.md "DNSBL interchange format").
test_adr62_stale_generation_rebuild_hold_row_orig_present and its '.orig'-absent sibling
below pin the staging-generation guard's rebuild-from-'.orig' fallback (a pre-#1083 '.txt'
is never verbatim-reused, even on a Held row).

These need the booted ``smoke_vm`` fixture, the branch ``.pkg`` (``SMOKE_PKG``), and
the smoke deps; without them they skip cleanly.
"""

from __future__ import annotations

import os
import shlex
from collections.abc import Iterator

import pytest

from . import helpers as h
from .conftest import STUB_DNS_A, SmokeVM, _StubDnsServer

pytestmark = pytest.mark.smoke


def _feed_log_count(vm: SmokeVM, header: str, phrase: str, *, timeout: float = 30.0) -> int:
    """Count main-log lines for THIS feed (``[ <header> ]``) that also contain ``phrase``.

    Mirrors ``test_smoke_feeds.py``'s private helper of the same name/shape (kept local
    here rather than imported across test modules).
    """
    cmd = (
        f"/usr/bin/grep -F {shlex.quote(f'[ {header} ]')} {shlex.quote(h.PFB_LOG)} 2>/dev/null "
        f"| /usr/bin/grep -Fc {shlex.quote(phrase)}"
    )
    res = vm.ssh(cmd, timeout=timeout)
    try:
        return int(res.stdout.strip())
    except ValueError:
        return 0


def _set_dnsbl_row_state(vm: SmokeVM, header: str, state: str, *, timeout: float = 30.0) -> None:
    """Flip one DNSBL row's ``state`` field in-place, post-:func:`h.inject`.

    ``DnsblCase`` rows are always emitted 'Enabled' (helpers.py:2307/2484) — no per-row state
    override exists on the dataclass. This reaches into the already-written config for
    the one test that needs a 'Hold' row, rather than widening ``DnsblCase`` for it.
    """
    snippet = (
        f"$lists = config_get_path({h._php_str(h.CFG_DNSBL_LISTS)}, array());\n"  # noqa: SLF001
        "foreach ($lists as $li => $l) {\n"
        "    if (!isset($l['row'])) { continue; }\n"
        "    foreach ($l['row'] as $ri => $r) {\n"
        f"        if (($r['header'] ?? '') === {h._php_str(header)}) {{\n"  # noqa: SLF001
        f"            $lists[$li]['row'][$ri]['state'] = {h._php_str(state)};\n"  # noqa: SLF001
        "        }\n"
        "    }\n"
        "}\n"
        f"config_set_path({h._php_str(h.CFG_DNSBL_LISTS)}, $lists);\n"  # noqa: SLF001
        "write_config('pfBlockerNG smoke #1083: DNSBL row state override');\n"
        "echo 'OK';"
    )
    res = h.php_eval(vm, snippet, timeout=timeout)
    if res.returncode != 0 or "OK" not in res.stdout:
        raise RuntimeError(
            f"_set_dnsbl_row_state({header!r}, {state!r}) failed: rc={res.returncode} {res.stderr!r} {res.stdout!r}"
        )


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
    inline_dom = h.unique_domain("adr62r3inline")
    regex_line = "/^" + regex_dom.replace(".", "\\.") + "$/"
    # The ' ## ' inline-comment row guards the PR #1107 fail-open class: an
    # unanchored '##' capture diverted this line to parse_abp (None) and
    # silently LOST the block; the cosmetic-prefix guard keeps it plain-path.
    body = (
        "\n".join([f"0.0.0.0 {hosts_dom}", f"||{anchor_dom}^", regex_line, f"0.0.0.0 {inline_dom} ## inline comment"])
        + "\n"
    )
    feed_url = h.write_local_feed(deployed_vm, "smoke_adr62_row3.txt", body)
    spec = h.DnsblCase(aliasname="adr62row3", feed_url=feed_url, header="adr62row3", mode=h.DnsblMode.VIP)

    for name in (hosts_dom, anchor_dom, regex_dom, inline_dom):
        before = h.dns_probe_client(client_vm, name, "A")
        assert h.resolves_to(before, STUB_DNS_A), f"{name} should resolve via stub BEFORE listing, got {before}"
        assert not h.is_vip(before), f"{name} unexpectedly VIP-blocked before any feed: {before}"

    with h.CaseContext(deployed_vm, spec):
        h.unblock_egress()
        for name in (hosts_dom, anchor_dom, regex_dom, inline_dom):
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
    ipv4_anchor = "192.0.2.77"  # RFC 5737; delta D6: plain-feed ||<IP>^ now collects
    body = "\n".join([h.ABP_HEADER, f"[{ipv6_lit}]", f"||{ipv4_anchor}^", domain]) + "\n"
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

        # Delta D6 (ADR §2, PR #1107 review): a plain feed's ||<IPv4>^ anchor
        # collects into the DNSBLIP v4 alias (origin/devel silently dropped it).
        v4_members = h.wait_pfctl_table(deployed_vm, "pfB_DNSBLIP_v4")
        assert h.member_present(v4_members, ipv4_anchor), (
            f"plain-feed ABP IP anchor ||{ipv4_anchor}^ not collected into pfB_DNSBLIP_v4 (delta D6): {v4_members}"
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
# Row 7a — a feed REUSED (not re-downloaded) whose on-disk '.txt' is genuinely
# CURRENT-GENERATION NDJSON resolves the same verdict, with no redownload.
#
# SUPERSEDES a retired predecessor that staged an old-generation 6-col CSV row and
# asserted the reuse fork consumed it verbatim: issue #1083 added the staging-
# generation guard (pfb_dnsbl_staging_is_current_generation), so a pre-#1083
# '.txt' is NEVER verbatim-reused any more — it is rebuilt from '.orig' instead
# (see the two rows immediately below). This row keeps the ORIGINAL's staging
# technique (h.write_local_feed onto the live '.txt') but stages content that
# genuinely passes the generation guard, so the still-valid "reuse without
# redownload" happy path stays covered.
# --------------------------------------------------------------------------- #


@pytest.mark.timeout(300)
def test_adr62_reused_feed_current_generation_ndjson_resolves_without_redownload(
    deployed_vm: SmokeVM, client_vm: SmokeVM
) -> None:
    """Row 7a (Semantics #7): a current-generation NDJSON '.txt' reuses without redownload.

    Given a configured, already-loaded DNSBL group with TWO feed rows (a normal
      pass downloaded both: the main row blocked domain A, the sibling row
      blocked X1), whose main-row staging file (``{dnsdir}/{header}.txt``) is
      then OVERWRITTEN with a hand-written schema-v1 NDJSON domain row (the exact
      ``pfb_dnsbl_ndjson_emit_domain_row`` byte shape) for a DIFFERENT domain B —
      simulating a feed whose staging genuinely already is in the current NDJSON
      generation — while the SIBLING row's served feed changes content (X1 → X2)
      and the main row's served feed stays byte-identical.
    When a genuine cron pass runs with the config UNCHANGED — the changed sibling
      re-ingests (that is what makes the pass rebuild the DNSBL database at all),
      while the unchanged main row takes the VERBATIM-REUSE fork (current-
      generation staging passes the #1083 generation guard, so no rebuild is forced).
    Then B is VIP-blocked (the staged NDJSON line was consumed as-is, never
      re-downloaded or re-parsed), A now RESOLVES again (its row exists only in
      the '.orig' download cache — reuse never touches it), X2 is VIP-blocked
      (proof the pass genuinely ran), and no new 'Rebuild' log line appears for
      the header (the generation guard accepted the staging as current).
    """
    header = "adr62row7reuse"
    sib_header = "adr62row7sib"
    loaded_domain = h.unique_domain("adr62r7base")
    reused_domain = h.unique_domain("adr62r7cur")
    sib1_domain = h.unique_domain("adr62r7sib1")
    sib2_domain = h.unique_domain("adr62r7sib2")

    feed_name = "smoke_adr62_row7_feed.txt"
    sib_feed_name = "smoke_adr62_row7_sibling.txt"
    feed_url = h.write_local_feed(deployed_vm, feed_name, f"{loaded_domain}\n")
    sib_feed_url = h.write_local_feed(deployed_vm, sib_feed_name, f"{sib1_domain}\n")
    spec = h.DnsblCase(
        aliasname="adr62row7reuse",
        feed_url=feed_url,
        header=header,
        mode=h.DnsblMode.VIP,
        extra_rows=[(sib_header, sib_feed_url)],
    )

    for name in (loaded_domain, reused_domain, sib1_domain, sib2_domain):
        before = h.dns_probe_client(client_vm, name, "A")
        assert h.resolves_to(before, STUB_DNS_A), f"{name} should resolve via stub BEFORE listing, got {before}"

    with h.CaseContext(deployed_vm, spec):
        h.unblock_egress()  # later "resolves again" probes must reach the controlled stub

        # Baseline: both rows genuinely loaded via the normal download path.
        for name in (loaded_domain, sib1_domain):
            h.flush_unbound_name(deployed_vm, name)
            ans = h.dns_probe_client_until(client_vm, name, h.is_vip)
            assert not h.resolves_to(ans, STUB_DNS_A), (
                f"baseline feed domain {name} still resolving after the initial load: {ans}"
            )

        rebuild_before = _feed_log_count(deployed_vm, header, "Rebuild")

        # Overwrite the MAIN row's staging with a hand-written, CURRENT-generation
        # NDJSON domain row for a DIFFERENT domain — the exact byte shape
        # pfb_dnsbl_ndjson_emit_domain_row() produces for this header/alias/mode.
        # Its served feed stays byte-identical (no re-download trigger); the
        # SIBLING feed changes so the cron pass rebuilds the database at all.
        ndjson_line = (
            f'{{"kind":"domain","domain":"{reused_domain}","log":"1","feed":"{header}","group":"{spec.alias}"}}\n'
        )
        h.write_local_feed(deployed_vm, f"dnsbl/{header}.txt", ndjson_line)
        h.write_local_feed(deployed_vm, sib_feed_name, f"{sib2_domain}\n")

        # Genuine cron pass (non-force): the changed sibling re-ingests and
        # triggers the rebuild; the unchanged main row takes the reuse fork.
        # A Force-DNSBL reload cannot exercise that fork — it sets
        # reuse_dnsbl='on' and re-parses the '.orig' download cache instead of
        # honouring the staged '.txt'.
        pinned_hour = h.pin_cron_due(deployed_vm)
        h.reload(deployed_vm, "cron")
        hour_now = h.guest_hour(deployed_vm)
        assert hour_now == pinned_hour, (
            f"guest hour rolled over between pin_cron_due ({pinned_hour}) and cron ({hour_now}) — "
            f"the EveryDay feeds were never due, this run proves nothing; re-run"
        )

        h.flush_unbound_name(deployed_vm, reused_domain)
        ans_reused = h.dns_probe_client_until(client_vm, reused_domain, h.is_vip)
        assert not h.resolves_to(ans_reused, STUB_DNS_A), (
            f"current-generation staged domain {reused_domain} still resolving after the cron pass "
            f"(the reuse fork should have consumed the staged NDJSON '.txt' as-is): {ans_reused}"
        )

        h.flush_unbound_name(deployed_vm, sib2_domain)
        ans_sib2 = h.dns_probe_client_until(client_vm, sib2_domain, h.is_vip)
        assert not h.resolves_to(ans_sib2, STUB_DNS_A), (
            f"changed sibling domain {sib2_domain} not blocked — the cron pass never re-ingested the "
            f"sibling feed, so this run rebuilt nothing and proves nothing: {ans_sib2}"
        )

        h.flush_unbound_name(deployed_vm, loaded_domain)
        ans_loaded_after = h.dns_probe_client(client_vm, loaded_domain, "A")
        assert h.resolves_to(ans_loaded_after, STUB_DNS_A), (
            f"original main-row domain {loaded_domain} still blocked after the reuse pass — its row "
            f"exists only in the '.orig' cache, so reuse must never have re-parsed it: {ans_loaded_after}"
        )

        rebuild_after = _feed_log_count(deployed_vm, header, "Rebuild")
        assert rebuild_after == rebuild_before, (
            f"unexpected 'Rebuild' log line for {header} (before={rebuild_before}, after={rebuild_after}) — "
            f"current-generation NDJSON staging should have passed the #1083 generation guard"
        )


# --------------------------------------------------------------------------- #
# Stale-generation rebuild (issue #1083) — a pre-#1083 '.txt' left over across
# a pkg upgrade is NEVER verbatim-reused: pfb_dnsbl_staging_is_current_generation
# rejects it, and the sync loop rebuilds from '.orig' via the same machinery a
# Reload uses — refetching over the network only when '.orig' itself is absent.
# Both rows stage a HOLD row (state='Hold') to prove the rebuild reaches even a
# row pfblockerng_sync_cron()'s own change-detector pass skips outright, and both
# stage the exact #1083/#1105 old-dialect mix: a 6-col CSV line plus a bare-
# domain line (the shape a comma-less verbatim-ABP line took pre-#1083 — issue
# #1105) so a regression that drops the bare line on rebuild is caught here.
# --------------------------------------------------------------------------- #


@pytest.mark.timeout(300)
def test_adr62_stale_generation_rebuild_hold_row_orig_present(deployed_vm: SmokeVM, client_vm: SmokeVM) -> None:
    """#1083 stale-generation rebuild: a Hold row with a pre-#1083 '.txt' rebuilds from '.orig'.

    Given a Hold-state DNSBL row whose feed genuinely serves TWO domains (a
      6-col-CSV-shaped target and a bare-domain-shaped target — issue #1105's
      dropped-line shape), downloaded once so '.orig' holds both, alongside a
      sibling row that will be due this cron pass; the main row's staging
      '.txt' is then overwritten with old-dialect (pre-#1083) content for the
      SAME two domains, simulating a pkg-upgrade leftover on a never-
      redownloaded, held feed.
    When a genuine cron pass runs (the sibling's change makes the pass rebuild
      the DNSBL database at all; the Hold row's own state never triggers a
      redownload attempt for it — pfblockerng_sync_cron() bypasses it outright)
      and the staging-generation guard rejects the stale '.txt',
    Then a NEW 'Rebuild' log line appears for the header, '.orig' is BYTE-
      IDENTICAL before and after (the rebuild reparsed the existing download
      cache — it never refetched over the network), the rebuilt '.txt' is
      NDJSON (starts with '{'), and BOTH domains are blocked — including the
      bare-domain line, proving the #1105 dropped-line class cannot recur once
      a stale staging file is rebuilt from '.orig' instead of reused verbatim.
    """
    header = "adr62rebuilda"
    sib_header = "adr62rebuildasib"
    domain_csv = h.unique_domain("adr62rbacsv")
    domain_bare = h.unique_domain("adr62rbabare")
    sib1_domain = h.unique_domain("adr62rbasib1")
    sib2_domain = h.unique_domain("adr62rbasib2")

    feed_name = "smoke_adr62_rebuilda_feed.txt"
    sib_feed_name = "smoke_adr62_rebuilda_sibling.txt"
    feed_url = h.write_local_feed(deployed_vm, feed_name, f"{domain_csv}\n{domain_bare}\n")
    sib_feed_url = h.write_local_feed(deployed_vm, sib_feed_name, f"{sib1_domain}\n")
    spec = h.DnsblCase(
        aliasname="adr62rebuilda",
        feed_url=feed_url,
        header=header,
        mode=h.DnsblMode.VIP,
        extra_rows=[(sib_header, sib_feed_url)],
    )

    orig_path = f"{h.PFB_DBDIR}/dnsblorig/{header}.orig"
    txt_path = f"{h.PFB_DBDIR}/dnsbl/{header}.txt"

    for name in (domain_csv, domain_bare, sib1_domain, sib2_domain):
        before = h.dns_probe_client(client_vm, name, "A")
        assert h.resolves_to(before, STUB_DNS_A), f"{name} should resolve via stub BEFORE listing, got {before}"

    with h.CaseContext(deployed_vm, spec):
        h.unblock_egress()

        # Baseline: both rows genuinely loaded via the normal download path — this
        # is what populates '.orig' with both target domains.
        for name in (domain_csv, domain_bare, sib1_domain):
            h.flush_unbound_name(deployed_vm, name)
            ans = h.dns_probe_client_until(client_vm, name, h.is_vip)
            assert not h.resolves_to(ans, STUB_DNS_A), f"baseline domain {name} still resolving: {ans}"

        _set_dnsbl_row_state(deployed_vm, header, "Hold")

        orig_before = deployed_vm.ssh("cat", orig_path)
        assert orig_before.returncode == 0, (
            f"test setup failed: genuine '.orig' not present at {orig_path}: {orig_before.stderr!r}"
        )

        rebuild_before = _feed_log_count(deployed_vm, header, "Rebuild")

        # Simulate the pre-#1083 on-disk leftover: a 6-col CSV row plus a bare-
        # domain row (issue #1105's shape) for the SAME two domains '.orig' holds.
        h.write_local_feed(deployed_vm, f"dnsbl/{header}.txt", f",{domain_csv},,1,{header},{header}\n{domain_bare}\n")
        h.write_local_feed(deployed_vm, sib_feed_name, f"{sib2_domain}\n")

        pinned_hour = h.pin_cron_due(deployed_vm)
        h.reload(deployed_vm, "cron")
        hour_now = h.guest_hour(deployed_vm)
        assert hour_now == pinned_hour, (
            f"guest hour rolled over between pin_cron_due ({pinned_hour}) and cron ({hour_now}) — "
            f"the EveryDay feeds were never due, this run proves nothing; re-run"
        )

        rebuild_after = _feed_log_count(deployed_vm, header, "Rebuild")
        assert rebuild_after > rebuild_before, (
            f"expected a NEW 'Rebuild' log line for {header} (before={rebuild_before}, after={rebuild_after}) — "
            f"the staging-generation guard should have rejected the old-dialect '.txt'"
        )

        orig_after = deployed_vm.ssh("cat", orig_path)
        assert orig_after.returncode == 0 and orig_after.stdout == orig_before.stdout, (
            f"'.orig' changed across the rebuild pass — expected byte-identical reuse, no network "
            f"refetch: before={orig_before.stdout!r} after={orig_after.stdout!r}"
        )

        txt_content = deployed_vm.ssh("cat", txt_path)
        assert txt_content.returncode == 0 and txt_content.stdout.startswith("{"), (
            f"rebuilt staging {txt_path} does not start with NDJSON '{{': {txt_content.stdout[:80]!r}"
        )

        h.flush_unbound_name(deployed_vm, sib2_domain)
        ans_sib2 = h.dns_probe_client_until(client_vm, sib2_domain, h.is_vip)
        assert not h.resolves_to(ans_sib2, STUB_DNS_A), f"sibling {sib2_domain} not re-ingested: {ans_sib2}"

        for name in (domain_csv, domain_bare):
            h.flush_unbound_name(deployed_vm, name)
            ans = h.dns_probe_client_until(client_vm, name, h.is_vip)
            assert not h.resolves_to(ans, STUB_DNS_A), (
                f"{name} not blocked after the stale-generation rebuild (the #1105 dropped-line class "
                f"would show here): {ans}"
            )


@pytest.mark.timeout(300)
def test_adr62_stale_generation_rebuild_orig_absent_triggers_download(deployed_vm: SmokeVM, client_vm: SmokeVM) -> None:
    """#1083 stale-generation rebuild: with '.orig' absent, the rebuild fork downloads fresh.

    Given the SAME Hold-row + stale-'.txt' setup as the '.orig'-present sibling
      case, except '.orig' is removed before the pass (a download cache that
      never existed, or was purged, alongside a stale pre-#1083 '.txt').
    When the cron pass runs and the staging-generation guard rejects the stale
      '.txt' the same way,
    Then a NEW 'Rebuild' log line appears for the header, '.orig' — ABSENT
      beforehand — is genuinely refetched (present afterwards: the rebuild fork
      falls back to a real download when there is nothing in the cache to
      reuse), the rebuilt '.txt' is NDJSON, and both domains from the live feed
      are blocked.
    """
    header = "adr62rebuildb"
    sib_header = "adr62rebuildbsib"
    domain_csv = h.unique_domain("adr62rbbcsv")
    domain_bare = h.unique_domain("adr62rbbbare")
    sib1_domain = h.unique_domain("adr62rbbsib1")
    sib2_domain = h.unique_domain("adr62rbbsib2")

    feed_name = "smoke_adr62_rebuildb_feed.txt"
    sib_feed_name = "smoke_adr62_rebuildb_sibling.txt"
    feed_url = h.write_local_feed(deployed_vm, feed_name, f"{domain_csv}\n{domain_bare}\n")
    sib_feed_url = h.write_local_feed(deployed_vm, sib_feed_name, f"{sib1_domain}\n")
    spec = h.DnsblCase(
        aliasname="adr62rebuildb",
        feed_url=feed_url,
        header=header,
        mode=h.DnsblMode.VIP,
        extra_rows=[(sib_header, sib_feed_url)],
    )

    orig_path = f"{h.PFB_DBDIR}/dnsblorig/{header}.orig"
    txt_path = f"{h.PFB_DBDIR}/dnsbl/{header}.txt"

    for name in (domain_csv, domain_bare, sib1_domain, sib2_domain):
        before = h.dns_probe_client(client_vm, name, "A")
        assert h.resolves_to(before, STUB_DNS_A), f"{name} should resolve via stub BEFORE listing, got {before}"

    with h.CaseContext(deployed_vm, spec):
        h.unblock_egress()

        for name in (domain_csv, domain_bare, sib1_domain):
            h.flush_unbound_name(deployed_vm, name)
            ans = h.dns_probe_client_until(client_vm, name, h.is_vip)
            assert not h.resolves_to(ans, STUB_DNS_A), f"baseline domain {name} still resolving: {ans}"

        _set_dnsbl_row_state(deployed_vm, header, "Hold")

        deployed_vm.ssh("/bin/rm", "-f", orig_path)
        orig_gone = deployed_vm.ssh("/bin/test", "-e", orig_path)
        assert orig_gone.returncode != 0, f"test setup failed: '.orig' {orig_path} still present after rm"

        rebuild_before = _feed_log_count(deployed_vm, header, "Rebuild")

        h.write_local_feed(deployed_vm, f"dnsbl/{header}.txt", f",{domain_csv},,1,{header},{header}\n{domain_bare}\n")
        h.write_local_feed(deployed_vm, sib_feed_name, f"{sib2_domain}\n")

        pinned_hour = h.pin_cron_due(deployed_vm)
        h.reload(deployed_vm, "cron")
        hour_now = h.guest_hour(deployed_vm)
        assert hour_now == pinned_hour, (
            f"guest hour rolled over between pin_cron_due ({pinned_hour}) and cron ({hour_now}) — "
            f"the EveryDay feeds were never due, this run proves nothing; re-run"
        )

        rebuild_after = _feed_log_count(deployed_vm, header, "Rebuild")
        assert rebuild_after > rebuild_before, (
            f"expected a NEW 'Rebuild' log line for {header} (before={rebuild_before}, after={rebuild_after})"
        )

        orig_now = deployed_vm.ssh("/bin/test", "-e", orig_path)
        assert orig_now.returncode == 0, (
            f"'.orig' {orig_path} still absent after the rebuild pass — the no-cache fallback should have refetched it"
        )

        txt_content = deployed_vm.ssh("cat", txt_path)
        assert txt_content.returncode == 0 and txt_content.stdout.startswith("{"), (
            f"rebuilt staging {txt_path} does not start with NDJSON '{{': {txt_content.stdout[:80]!r}"
        )

        h.flush_unbound_name(deployed_vm, sib2_domain)
        ans_sib2 = h.dns_probe_client_until(client_vm, sib2_domain, h.is_vip)
        assert not h.resolves_to(ans_sib2, STUB_DNS_A), f"sibling {sib2_domain} not re-ingested: {ans_sib2}"

        for name in (domain_csv, domain_bare):
            h.flush_unbound_name(deployed_vm, name)
            ans = h.dns_probe_client_until(client_vm, name, h.is_vip)
            assert not h.resolves_to(ans, STUB_DNS_A), (
                f"{name} not blocked after the no-cache rebuild (fresh download + reparse): {ans}"
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
