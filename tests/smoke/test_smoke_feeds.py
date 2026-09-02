"""ADR-16 Part C — the live HTTP-feed load smoke (the Part-C kill-gate).

Every other smoke case (``test_smoke_matrix.py`` / ``test_smoke_abp.py``) feeds a
LOCAL file (``write_local_feed``) — chosen partly for HTTP-fetch reliability (ADR-16
Context 5). This module is the one place the suite drives the REAL HTTP feed-fetch
path: each case points a ``IpCase``/``DnsblCase`` at a ``mock_feeds.feed_url(<name>)``
URL (the stdlib ``_MockFeedServer`` serving ``tests/smoke/fixtures/``, reachable by
the guest at ``http://192.168.89.2:<port>/<name>`` over SLIRP — survives the egress
block), runs a real Force Update, and asserts the feed loaded on the box. This
exercises pfBlockerNG's ``curl`` contract (gzip / redirects / no-304) end-to-end —
the gap Part C closes.

DESELECTED from the default ``python -m pytest`` (``--ignore=tests/smoke`` in
pyproject.toml). Run only by the smoke workflow::

    python -m pytest tests/smoke -m smoke --override-ini="addopts="

KILL-GATE (ADR-16 §7). The Part-C premise — "a Force Update reliably FETCHES an HTTP
feed from the mock over SLIRP and LOADS it, in CI" — is falsifiable. The two proof
cases (``test_ip_http_feed_loads`` + ``test_dnsbl_http_feed_loads``) come FIRST; the
format expansion follows. The reliability bar is **>= 4/5 clean runs at a sane
per-leg budget**: if the live CI run cannot hit it, ``test_smoke_feeds.py`` is
DEMOTED to dispatch-only (dropped from the gated smoke set) — Part A still ships and
the local-file load coverage (the matrix) remains. The numbers + GO/DEMOTE decision
are recorded in ``legacy/ADRs/ADR_16_Feeds_Tabs_And_Feed_Smoke/RESULTS/05_Results.txt``;
this run is OPTIMISTIC-GO (all formats authored) pending the live evidence.

Fixture members / non-members are the Phase-4 RESULTS contract (RESULTS/04 §"THE 6
SAMPLE FEEDS"); the IP CIDR/range membership is asserted CIDR-aware (``_covered_by``)
because the listed forms are networks, not the probe host.

RESOLVE-PROOF NOTE (mirrors the matrix #51 lifecycle, NOT a host override): a DNSBL
name that must RESOLVE is asserted to resolve to the controlled stub sentinel
(``STUB_DNS_A``) with egress left OPEN in the probe body (``unblock_egress``) —
pfSense forwards a not-blocked name to the SLIRP stub (``use_system_dns_upstream``),
so the pass is a KNOWN, observable answer (never a loose "not blocked"). A control
Host-Override is deliberately AVOIDED here: Unbound serves a host override as
``local-data`` BEFORE the python module, so an override would SHADOW the matcher —
it cannot prove a name is unblocked by the matcher (the ABP ``@@`` allow-exception
especially), and on a BLOCKED member it would mask the block. The member block
returns its VIP shape locally regardless of egress, so leaving egress open is no
false-green.

These need the booted ``smoke_vm`` fixture, the branch ``.pkg`` (``SMOKE_PKG``), the
``mock_feeds`` server, and the smoke deps; without them they skip cleanly.
"""

from __future__ import annotations

import bz2
import gzip
import io
import ipaddress
import os
import re
import shlex
import subprocess
import tarfile
import zipfile
from collections.abc import Callable, Iterator

import pytest

from . import helpers as h
from .conftest import FIXTURES_DIR, STUB_DNS_A, SmokeVM, _MockFeedServer, _StubDnsServer

pytestmark = pytest.mark.smoke


@pytest.fixture(scope="module")
def deployed_vm(smoke_vm: SmokeVM, client_vm: SmokeVM, stub_dns: _StubDnsServer) -> Iterator[SmokeVM]:
    """Deploy the branch .pkg once for the HTTP-feed-load matrix (mirrors the ADR-04
    matrix / ABP modules).

    Egress is managed per-case by ``CaseContext`` (OPEN across inject + the Force
    Update so the mock HTTP fetch is reachable; BLOCKED for the probe). The DNSBL VIP
    is injected once (DNSBL force-disables itself without one), and System DNS is
    pointed at the controlled stub so a not-blocked name has a known answer. A full
    guest snapshot is collected on teardown for the workflow to upload.
    """
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    # The mock feed server is the SLIRP host alias 192.168.89.2 (RFC1918) — the default-ON
    # feed-host internal-address filter (SSRF guard, pfb_feed_internal_filter) would reject
    # every HTTP mock fetch as an internal-resolving host. Allowlist the SLIRP test network
    # so the filter stays ON yet the mock is reachable (the fix for the regression these
    # HTTP-feed tests hit after the filter landed default-on).
    h.set_feed_internal_allowlist(smoke_vm, "192.168.89.0/24")
    h.ensure_dnsbl_vip(smoke_vm)
    h.use_system_dns_upstream(smoke_vm)
    h.assert_link_health(client_vm, smoke_vm, control_name=h.unique_domain())
    try:
        yield smoke_vm
    finally:
        h.unblock_egress()
        h.collect_host_diagnostics(smoke_vm)


def _covered_by(members: list[str], ip: str) -> bool:
    """True iff ``ip`` is covered by any pf table member, CIDR-aware (by value).

    ``helpers.member_present`` only matches an exact host or a member whose network
    ADDRESS equals ``ip``; the IP fixtures list NETWORKS (``198.51.100.0/24``) and a
    range expands to covering CIDRs (``.10/31`` …), so a host INSIDE them needs a real
    ``ipaddress`` containment test. Compares by value (``::`` == ``::0``), so the
    member's textual form never matters.
    """
    target = ipaddress.ip_address(ip)
    for member in members:
        try:
            if target in ipaddress.ip_network(member, strict=False):
                return True
        except ValueError:
            continue
    return False


# --------------------------------------------------------------------------- #
# KILL-GATE — the two proof cases (one IP, one DNSBL) over real HTTP.
# These run FIRST (§7): they falsify the Part-C premise before the format matrix.
# --------------------------------------------------------------------------- #


def test_ip_http_feed_loads(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """KILL-GATE (IP): a plain-IP+CIDR feed served over HTTP loads into the pf table.

    Scenario: the Phase-4 ``ip_plain_cidr.txt`` fixture is fetched by a real Force
    Update over the mock (``feed_url`` = the HTTP URL, NOT a local file) and its
    entries land in ``pfB_<alias>_v4`` with a referencing rule.

    Given the feed is NOT yet configured, the alias table does not exist (the
    transition's before-state — proven via ``pfctl_tables``).
    When the case injects + Force-Updates over the HTTP feed,
    Then the listed plain host (``203.0.113.5``) and a host covered by the listed
    CIDR (``198.51.100.7`` in ``198.51.100.0/24``) are table members, a never-listed
    host (``203.0.113.250``) is NOT, and a loaded pf rule references the alias —
    proving the HTTP fetch reached the matcher (member + non-member + wiring).
    """
    member_host = "203.0.113.5"  # the plain listed host
    member_in_cidr = "198.51.100.7"  # inside the listed 198.51.100.0/24
    non_member = "203.0.113.250"  # in 203.0.113.x but NOT listed
    feed_url = mock_feeds.feed_url("ip_plain_cidr.txt")
    spec = h.IpCase(aliasname="smokefeedip4", feed_url=feed_url, header="smokefeedip4", family="v4")

    # BEFORE: the alias table does not exist until the feed is loaded.
    assert spec.alias not in h.pfctl_tables(deployed_vm), f"{spec.alias} present before the feed was ever loaded"

    with h.CaseContext(deployed_vm, spec):
        # CaseContext.__enter__ applies the blocking filter sync before this read.
        members = h.pfctl_table_members(deployed_vm, spec.alias)
        assert h.member_present(members, member_host), f"{member_host} not in {spec.alias}: {members}"
        assert _covered_by(members, member_in_cidr), f"{member_in_cidr} not covered by {spec.alias}: {members}"
        assert not _covered_by(members, non_member), f"{non_member} unexpectedly in {spec.alias}: {members}"
        assert h.pfctl_rule_has_alias(deployed_vm, spec.alias), f"no loaded pf rule references {spec.alias}"


def test_dnsbl_http_feed_loads(deployed_vm: SmokeVM, client_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """KILL-GATE (DNSBL): a plain-domain feed served over HTTP loads into the matcher.

    Scenario: the Phase-4 ``dnsbl_plain.txt`` fixture is fetched by a real Force
    Update over the mock and its single domain blocks on the box.

    Given the listed member is NOT yet on any feed, it RESOLVES via the controlled
    stub upstream (``STUB_DNS_A``) — a real, observable before-state.
    When the case injects + Force-Updates over the HTTP feed,
    Then the listed domain (``uuid-a344db4286a4.com``) returns the VIP block shape and
    no longer resolves, while a non-member (``uuid-06cf362c2890.com``) still RESOLVES
    via the stub — proving the HTTP fetch loaded the feed and ONLY the listed name
    blocks (member + non-member, both observed).
    """
    member = "uuid-a344db4286a4.com"  # listed -> must BLOCK
    non_member = "uuid-06cf362c2890.com"  # not listed -> must RESOLVE
    feed_url = mock_feeds.feed_url("dnsbl_plain.txt")
    spec = h.DnsblCase(aliasname="smokefeeddnsbl", feed_url=feed_url, header="smokefeeddnsbl", mode=h.DnsblMode.VIP)

    # BEFORE: the member is not on any feed yet -> it resolves via the stub sentinel.
    before = h.dns_probe_client(client_vm, member, "A")
    assert h.resolves_to(before, STUB_DNS_A), f"{member} should resolve via stub BEFORE listing, got {before}"
    assert not h.is_vip(before), f"{member} unexpectedly VIP-blocked before any feed: {before}"

    with h.CaseContext(deployed_vm, spec):
        # The "resolves" probes must reach the controlled stub: leave egress OPEN. The
        # member's VIP block returns locally regardless, so this is no false-green.
        h.unblock_egress()
        # The `before` probe pre-resolved `member` via the stub (TTL 60s). A feed/cron
        # allow->block swap is TTL-bounded BY DESIGN (ADR-10) and does NOT flush the
        # C-cache, so that cached real answer would serve past the swap. Clear the one
        # name (as test_smoke_matrix.py's unlock lifecycle does), then poll until the
        # async swap's VIP block lands.
        h.flush_unbound_name(deployed_vm, member)
        blocked = h.dns_probe_client_until(client_vm, member, h.is_vip)
        assert not h.resolves_to(blocked, STUB_DNS_A), f"{member} still resolving after the feed block: {blocked}"
        passed = h.dns_probe_client(client_vm, non_member, "A")
        assert h.resolves_to(passed, STUB_DNS_A), f"non-member {non_member} should resolve via stub, got {passed}"
        assert not h.is_vip(passed), f"non-member {non_member} wrongly VIP-blocked: {passed}"


# --------------------------------------------------------------------------- #
# Feed-host internal-address filter (SSRF guard) — BOTH branches over the live box.
# --------------------------------------------------------------------------- #


def test_feed_internal_filter_blocks_then_allowlist_exempts(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """The default-ON feed-host filter BLOCKS an internal-resolving feed; the allowlist EXEMPTS it.

    The mock feed server is the SLIRP host alias 192.168.89.2 (RFC1918) — exactly the
    internal-pivot the filter (``pfb_feed_internal_filter``, default ON) guards against.
    This pins BOTH branches end to end over the live box (the module fixture allowlists
    192.168.89.0/24 so the other HTTP-feed cases load at all; this test brackets it).

    Scenario:
      Given the filter ON and the allowlist EMPTY (so 192.168.89.2 is not exempt),
      When  the mock IP feed is Force-Updated,
      Then  the download is REFUSED (the refusal reason is logged) and the pf table
            is never built (the block branch).
      When  the SLIRP net 192.168.89.0/24 is then allowlisted and re-updated,
      Then  the SAME feed downloads and its pf table IS built (the exempt branch).
    """
    feed_url = mock_feeds.feed_url("ip_plain_cidr.txt")
    spec = h.IpCase(aliasname="smokefiltergate", feed_url=feed_url, header="smokefiltergate", family="v4")
    # The refusal fires at pfb_download()'s entry vetting during the IP download pass
    # (pfb_filter PFB_FILTER_URL routes through pfb_feed_host_allowed; observed live in
    # run 28706678122 — the error.log reject carries the 'pfb_download_failure' reference).
    # pfb_filter's reason-free "… Invalid URL (…) [ <url> ]" error.log line (logtype 6)
    # is untouched by #811 — but every entry-reject site now also calls
    # pfb_log_feed_host_reject() (#811), so a header-scoped, reason-bearing
    # "[ header ] <reason> — skipped" line lands in the MAIN log, making the cause
    # visible without digging through error.log. Assert THAT line: scope it by header
    # AND the exact guard reason, so a sibling feed's failure can never satisfy it.
    # NOTE: the download pipeline's on-box header carries the family suffix
    # ("smokefiltergate_v4"), so the marker anchors on that rendered form, not the bare
    # alias name (run 28706678122: the line logged as "[ smokefiltergate_v4 ] … — skipped").
    refused_marker = f"[ {spec.header}_v4 ] feed host resolves to a non-permitted address — skipped"
    main_log = h.PFB_LOG
    # The mock fetch must be reachable across both updates (the SSRF filter, not egress,
    # is what we are exercising).
    h.unblock_egress()
    try:
        h.inject(deployed_vm, spec)
        # BLOCK branch: empty allowlist => the internal mock host is not exempt.
        # An IpCase settles its pf table + rule only after the full Force Update
        # FOLLOWED BY the targeted updateip (see CaseContext) — mirror that here so
        # the "table not built" assertion reflects a fully settled reload, not a race.
        h.set_feed_internal_allowlist(deployed_vm, "")
        assert spec.alias not in h.pfctl_tables(deployed_vm), f"{spec.alias} present before any load"
        refused_before = h.count_log_marker(deployed_vm, main_log, refused_marker)
        h.reload(deployed_vm, "update")
        h.reload(deployed_vm, "updateip")
        h.apply_filter_sync(deployed_vm)
        assert spec.alias not in h.pfctl_tables(deployed_vm), (
            "filter ON + empty allowlist must BLOCK the internal mock feed (pf table not built)"
        )
        # A missing pf table alone is non-specific — a dead mock server would look identical.
        # Assert the actual refusal reason was logged, so this proves the SSRF guard fired,
        # not merely that nothing happened to load.
        refused_after = h.count_log_marker(deployed_vm, main_log, refused_marker)
        assert refused_after > refused_before, (
            f"Expected {refused_marker!r} in {main_log} after the filtered update "
            f"(before={refused_before}, after={refused_after}) — the pf table being empty does "
            "not by itself prove the SSRF guard refused the download"
        )

        # EXEMPT branch: allowlist the SLIRP net => the SAME feed now downloads + loads.
        h.set_feed_internal_allowlist(deployed_vm, "192.168.89.0/24")
        h.reload(deployed_vm, "update")
        h.reload(deployed_vm, "updateip")
        h.apply_filter_sync(deployed_vm)
        members = h.pfctl_table_members(deployed_vm, spec.alias)
        assert members, "allowlisting the SLIRP CIDR must EXEMPT the feed (pf table built)"
        assert h.member_present(members, "203.0.113.5"), f"listed host missing after exemption: {members}"
    finally:
        # Restore the module-default allowlist (siblings rely on it) and baseline the box.
        h.set_feed_internal_allowlist(deployed_vm, "192.168.89.0/24")
        h.reset(deployed_vm)


# --------------------------------------------------------------------------- #
# EXPAND — one case per remaining representative Phase-4 format (gate held):
#   IP    {range, IPv6}
#   DNSBL {hosts, ABP/EasyList}
# Same shape as the kill-gate, fixtures served over HTTP via mock_feeds.feed_url.
# --------------------------------------------------------------------------- #


def test_ip_http_range_feed_loads(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """IP range over HTTP: ``ip_range.txt`` (``198.51.100.10-198.51.100.20``) loads.

    The range expands to the covering CIDRs (``.10/31``, ``.12/30``, ``.16/30``,
    ``.20/32``). Before-state: the alias table does not exist. After a Force Update
    over the HTTP feed, a host INSIDE the range (``.15``) is covered, a host just past
    the top (``.21``) and one well outside (``.200``) are NOT, and a rule references
    the alias — proving the range expansion loaded via the HTTP fetch.
    """
    inside = "198.51.100.15"  # inside .10..20
    just_past = "198.51.100.21"  # one past the top (must NOT be covered)
    outside = "198.51.100.200"  # well outside
    feed_url = mock_feeds.feed_url("ip_range.txt")
    spec = h.IpCase(aliasname="smokefeedrange", feed_url=feed_url, header="smokefeedrange", family="v4")

    assert spec.alias not in h.pfctl_tables(deployed_vm), f"{spec.alias} present before the feed was ever loaded"

    with h.CaseContext(deployed_vm, spec):
        members = h.pfctl_table_members(deployed_vm, spec.alias)
        assert _covered_by(members, inside), f"{inside} not covered by the range in {spec.alias}: {members}"
        assert not _covered_by(members, just_past), (
            f"{just_past} (one past the range) unexpectedly in {spec.alias}: {members}"
        )
        assert not _covered_by(members, outside), f"{outside} unexpectedly in {spec.alias}: {members}"
        assert h.pfctl_rule_has_alias(deployed_vm, spec.alias), f"no loaded pf rule references {spec.alias}"


def test_ipv6_http_feed_loads(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """IPv6 over HTTP: ``ip_ipv6.txt`` (single + /48) loads into the v6 alias table.

    Before-state: the ``pfB_<alias>_v6`` table does not exist. After a Force Update
    over the HTTP feed, the single host (``2001:db8::1``) and a host covered by the
    listed /48 (``2001:db8:1::99`` in ``2001:db8:1::/48``) are members, a host
    outside both (``2001:db8:dead::1``) is NOT, and a rule references the alias.
    IPv6 membership is compared BY VALUE (``::`` == ``::0``) via ``_covered_by``.
    """
    member_host = "2001:db8::1"  # the single listed host
    member_in_prefix = "2001:db8:1::99"  # inside the listed 2001:db8:1::/48
    non_member = "2001:db8:dead::1"  # outside the /48 AND != the single host
    feed_url = mock_feeds.feed_url("ip_ipv6.txt")
    spec = h.IpCase(aliasname="smokefeedip6", feed_url=feed_url, header="smokefeedip6", family="v6")

    assert spec.alias not in h.pfctl_tables(deployed_vm), f"{spec.alias} present before the feed was ever loaded"

    with h.CaseContext(deployed_vm, spec):
        members = h.pfctl_table_members(deployed_vm, spec.alias)
        assert _covered_by(members, member_host), f"{member_host} not in {spec.alias}: {members}"
        assert _covered_by(members, member_in_prefix), f"{member_in_prefix} not covered by {spec.alias}: {members}"
        assert not _covered_by(members, non_member), f"{non_member} unexpectedly in {spec.alias}: {members}"
        assert h.pfctl_rule_has_alias(deployed_vm, spec.alias), f"no loaded pf rule references {spec.alias}"


# --------------------------------------------------------------------------- #
# issue #1004 — the generic IP-list per-line parse-error detail sink (Site B: the
# "other family" heuristic in the regex-fallback path). Mirrors the DNSBL strict-
# scheme parse-error-log proof (test_strict_skips_invalid_scheme_and_path_and_logs)
# but for pfb_parse_fail_log() (strict mode)/ip_parsed_error.log.
# --------------------------------------------------------------------------- #


def test_ip_generic_parse_failure_logs_line_and_number(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """issue #1004: a Site-B IP parse failure logs the bad line + its source line
    number; the once-per-feed main-log summary stays exactly one line (no spam).

    AUTHORED, NOT EXECUTED against a live VM (no VM in this session;
    sync_package_pfblockerng() is the CI-untestable monolith issue #993 names, so a
    live-VM smoke run is the only coverage path for its parse loop). Pins the
    expected on-box observable for the next live smoke run.

    ``bad_line`` ("999.999.999.999") is a genuine Site-B garbage line: digit/dot
    only (clears the heuristic's ``[a-zA-Z,;|"'?]`` exclusion), 4 dot-groups
    (IP-shaped) but out-of-range octets (fails ``validate_ipv4`` AND the ipv4
    regex's 0-255 octet classes), and not the opposite family (no ':'). A line
    WITH LETTERS (e.g. the issue's illustrative "not-an-ip-!!!") does NOT reach
    this heuristic at all -- the same exclusion class short-circuits whenever a
    letter is present, so it is silently dropped, uncounted, by EXISTING design
    (verified by reading the heuristic; not a #1004 change).

    Given the alias table does not exist yet, and the main-log summary + the
      ip_parsed_error.log header marker are captured before any update (before-
      state, transition proof),
    When a feed with one valid host + the one bad line loads via a Force Update,
    Then the valid host is a pf table member, EXACTLY ONE new ip_parsed_error.log
      row appears for this feed's header, that row's line + oline fields carry the
      bad text and its 1-based source line number (2 -- ``$ip_lineno`` increments
      once per fgets() line before either line is judged), and the main log gains
      EXACTLY ONE new "[!] Parse Errors [ header ]: 1" summary line -- proving the
      once-per-feed contract (no per-line spam) is unchanged by #1004.
    """
    header = "smokeip1004"
    # The IP loop names each on-disk feed/logged header {row.header}{vtype}, so the
    # ip_parsed_error.log row and the "[!] Parse Errors [ ... ]" summary both carry the
    # family-suffixed form -- NOT the bare IpCase.header (see helpers.py IpCase docstring).
    logged_header = f"{header}_v4"
    valid_host = "203.0.113.90"
    bad_line = "999.999.999.999"
    feed_url = mock_feeds.register("ip_parse_fail_bad.txt", f"{valid_host}\n{bad_line}\n")
    spec = h.IpCase(aliasname="smokeip1004", feed_url=feed_url, header=header, family="v4")

    # BEFORE: no table yet, no row for this (session-unique) header, no summary line.
    assert spec.alias not in h.pfctl_tables(deployed_vm), f"{spec.alias} present before the feed was ever loaded"
    header_marker = f",{logged_header},"
    header_before = h.count_log_marker(deployed_vm, h.IP_PARSE_ERR_LOG, header_marker)
    summary_marker = f"[!] Parse Errors [ {logged_header} ]: 1"
    summary_before = h.count_log_marker(deployed_vm, h.PFB_LOG, summary_marker)

    with h.CaseContext(deployed_vm, spec):
        members = h.pfctl_table_members(deployed_vm, spec.alias)
        assert h.member_present(members, valid_host), f"{valid_host} not in {spec.alias}: {members}"

        header_after = h.count_log_marker(deployed_vm, h.IP_PARSE_ERR_LOG, header_marker)
        assert header_after == header_before + 1, (
            f"expected exactly ONE new ip_parsed_error.log row for header {logged_header!r} "
            f"(before={header_before}, after={header_after})"
        )
        parse_err = h.read_log_file(deployed_vm, h.IP_PARSE_ERR_LOG)
        # Row shape: {ts},{logged_header},{line},{oline},{lineno} -- $oline's raw fgets()
        # newline is stripped by the writer, so line and oline both read as the bad line.
        assert f"{logged_header},{bad_line},{bad_line},2" in parse_err, (
            f"expected the bad line + its 1-based source line number (2) in the new "
            f"ip_parsed_error.log row, got:\n{parse_err[-2000:]}"
        )

        summary_after = h.count_log_marker(deployed_vm, h.PFB_LOG, summary_marker)
        assert summary_after == summary_before + 1, (
            f"expected exactly ONE new '{summary_marker}' summary line (before={summary_before}, "
            f"after={summary_after}) -- the once-per-feed summary must not spam per-line"
        )


def test_dnsbl_http_hosts_feed_loads(deployed_vm: SmokeVM, client_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """DNSBL hosts format over HTTP: ``dnsbl_hosts.txt`` (``0.0.0.0 <domain>``) blocks.

    The leading sink IP is stripped, leaving the domain to block. Before-state: the
    member RESOLVES via the stub upstream. After a Force Update over the HTTP feed,
    the listed domain (``uuid-947e69114606.com``) returns the VIP block shape and no
    longer resolves, while a non-member (``uuid-55ca85f92f34.com``) still RESOLVES via
    the stub.
    """
    member = "uuid-947e69114606.com"  # listed (hosts line) -> must BLOCK
    non_member = "uuid-55ca85f92f34.com"  # not listed -> must RESOLVE
    feed_url = mock_feeds.feed_url("dnsbl_hosts.txt")
    spec = h.DnsblCase(aliasname="smokefeedhosts", feed_url=feed_url, header="smokefeedhosts", mode=h.DnsblMode.VIP)

    before = h.dns_probe_client(client_vm, member, "A")
    assert h.resolves_to(before, STUB_DNS_A), f"{member} should resolve via stub BEFORE listing, got {before}"
    assert not h.is_vip(before), f"{member} unexpectedly VIP-blocked before any feed: {before}"

    with h.CaseContext(deployed_vm, spec):
        h.unblock_egress()  # the non-member "resolves" probe must reach the stub upstream
        # before-probe warmed the C-cache; a feed swap is TTL-bounded (see kill-gate) -> flush + poll.
        h.flush_unbound_name(deployed_vm, member)
        blocked = h.dns_probe_client_until(client_vm, member, h.is_vip)
        assert not h.resolves_to(blocked, STUB_DNS_A), f"{member} still resolving after the feed block: {blocked}"
        passed = h.dns_probe_client(client_vm, non_member, "A")
        assert h.resolves_to(passed, STUB_DNS_A), f"non-member {non_member} should resolve via stub, got {passed}"
        assert not h.is_vip(passed), f"non-member {non_member} wrongly VIP-blocked: {passed}"


def test_dnsbl_http_abp_feed_loads(deployed_vm: SmokeVM, client_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """DNSBL ABP/EasyList over HTTP: ``dnsbl_abp.txt``'s ``||``/``@@`` lines load.

    The body starts with ``[Adblock Plus 2.0]`` (an ordinary skippable bracket
    control line, ADR-62) and every ``||``/``@@`` line is captured per-line
    (``pfb_dnsbl_is_abp_rule_line()``) and routed to the Python ABP parser. The
    feed BLOCKs ``||uuid-22f166f56cca.com^`` and contains a ``||``/``@@`` pair on
    ``uuid-f26156c6df69.com`` — the feed-allow ``@@`` (band 2) BEATS the feed-block
    ``||`` (band 1), so that name RESOLVES.

    Before-state: the ``||``-only member RESOLVES via the stub upstream. After a Force
    Update over the HTTP feed:
      * ``uuid-22f166f56cca.com`` (``||`` only) -> VIP block;
      * ``uuid-f26156c6df69.com`` (``||`` then ``@@``) -> RESOLVES (allow exception);
      * ``uuid-8ed2df53e469.com`` (not in the feed) -> RESOLVES (non-member).
    The allow-exception is asserted to resolve via the stub WITHOUT a host override
    (no ``control_local_data``) — an override would be served as ``local-data`` ahead
    of the matcher and resolve the name regardless of ``@@``, a false-green. Resolving
    via the matcher's allow path is the load-bearing branch: it proves the ABP ``@@``
    parsed and BEAT the ``||`` block, not merely that a block loaded.
    """
    blocked_name = "uuid-22f166f56cca.com"  # || only -> must BLOCK
    allow_exception = "uuid-f26156c6df69.com"  # || then @@ -> must RESOLVE
    non_member = "uuid-8ed2df53e469.com"  # not in the feed -> must RESOLVE
    feed_url = mock_feeds.feed_url("dnsbl_abp.txt")
    spec = h.DnsblCase(aliasname="smokefeedabp", feed_url=feed_url, header="smokefeedabp", mode=h.DnsblMode.VIP)

    # BEFORE: the ||-only name is not yet on any feed -> it resolves via the stub.
    before = h.dns_probe_client(client_vm, blocked_name, "A")
    assert h.resolves_to(before, STUB_DNS_A), f"{blocked_name} should resolve via stub BEFORE listing, got {before}"
    assert not h.is_vip(before), f"{blocked_name} unexpectedly VIP-blocked before any feed: {before}"

    with h.CaseContext(deployed_vm, spec):
        # The two "resolves" probes (the @@ exception + the non-member) must reach the
        # controlled stub: leave egress OPEN. The || block returns the VIP locally, so
        # this is no false-green.
        h.unblock_egress()
        # before-probe warmed the C-cache; a feed swap is TTL-bounded (see kill-gate) -> flush + poll.
        h.flush_unbound_name(deployed_vm, blocked_name)
        ans_blocked = h.dns_probe_client_until(client_vm, blocked_name, h.is_vip)
        assert not h.resolves_to(ans_blocked, STUB_DNS_A), (
            f"{blocked_name} still resolving after the || block: {ans_blocked}"
        )
        ans_allow = h.dns_probe_client(client_vm, allow_exception, "A")
        assert h.resolves_to(ans_allow, STUB_DNS_A), (
            f"ABP @@ allow-exception {allow_exception} must RESOLVE via the stub (@@ beats ||), got {ans_allow}"
        )
        assert not h.is_vip(ans_allow), f"ABP @@ allow-exception {allow_exception} wrongly VIP-blocked: {ans_allow}"
        ans_non = h.dns_probe_client(client_vm, non_member, "A")
        assert h.resolves_to(ans_non, STUB_DNS_A), f"non-member {non_member} should resolve via stub, got {ans_non}"
        assert not h.is_vip(ans_non), f"non-member {non_member} wrongly VIP-blocked: {ans_non}"


# --------------------------------------------------------------------------- #
# ADR-21/ADR-62 — per-line ABP detection inside a HEADER-LESS feed.
# The kill-gate/expand case above feeds a body that carries the ``[Adblock
# Plus 2.0]`` header line; ADR-62 retired the header sniff, so that header line is
# now just an ordinary skipped bracket control line -- the SAME per-line capture
# (``pfb_dnsbl_is_abp_rule_line()``) drives BOTH cases identically. This case
# proves the same per-line capture holds with NO header line present at all:
# ``||``/``@@||`` anchors are routed line-by-line to the ABP parser (PHP download
# loop + manifest builder write the anchors verbatim; Python ``build()`` routes
# them to ``parse_abp`` -> ``abp_rules``) WHILE plain-domain lines in the SAME
# feed keep the plain pipeline.
# --------------------------------------------------------------------------- #


@pytest.mark.timeout(300)
def test_abp_perline_detection_in_plain_feed(
    deployed_vm: SmokeVM, client_vm: SmokeVM, mock_feeds: _MockFeedServer
) -> None:
    """ADR-21: ``||block^`` / ``@@||allow^`` in a HEADER-LESS feed resolve correctly.

    Scenario: a header-less DNSBL feed row (NOT whole-feed ABP — ``format_hint='plain'``)
    mixes ABP-anchored entries with a plain-domain block. Per-line detection (ADR-21 §2.1)
    must route the anchors to ``parse_abp`` while the plain line keeps the plain pipeline.

    Delivery note — the entries ride a normal FEED row, not the GUI Custom_List field. A
    Custom_List entry is tagged provenance='user' (band-5 SOVEREIGN user block) by the
    manifest, which would beat a feed ``@@`` allow and defeat the §4.2 override under test.
    Feed-level ABP semantics (where a feed ``@@`` allow band 2 beats a feed block band 1)
    are exactly what per-line detection must reproduce, so the feed row is the faithful
    mechanism. The body carries runtime ``unique_domain()`` uuids, so it is a LOCAL feed
    (``write_local_feed``), as the ABP matrix (test_smoke_abp.py) delivers its feeds.

    Background — the feed body (no ``[Adblock`` / ``! Title:`` header) contains:
      * ``||<block>^``                      -> block the domain (§4.1)
      * ``@@||<allow>^`` AND a plain ``<allow>`` line
                                            -> the same-feed plain block of ``<allow>``
                                               is OVERRIDDEN by its ``@@`` allow (§4.2)
      * ``<plain>``                         -> a plain-domain block, unaffected (§4.5)

    Given (before the feed is loaded) all three names RESOLVE via the controlled stub
      upstream (``STUB_DNS_A``) — the real, observable before-state of the transition.
    When the case injects the header-less feed + runs a Force Update (Unbound reloads),
    Then:
      * ``<block>`` returns the VIP block shape and no longer resolves
        (``||block^`` reached ``parse_abp`` from a NON-ABP feed — the ADR-21 win);
      * ``<allow>`` RESOLVES via the stub (its ``@@`` allow beat the SAME-FEED plain
        block — proving per-line ``@@||`` parsed and won, not merely that nothing
        blocked: a regression would leave it VIP-blocked by the plain entry);
      * ``<plain>`` returns the VIP block shape (the plain pipeline is untouched).

    The two "resolves" assertions reach the stub via the matcher's allow/non-block
    path (no host override — an override is served as ``local-data`` ahead of the
    matcher and would resolve the name regardless, a false-green; see this module's
    RESOLVE-PROOF NOTE). Resolving through the matcher is the load-bearing branch.
    """
    block_name = h.unique_domain("adr21blk")  # ||block^ -> must BLOCK
    allow_name = h.unique_domain("adr21allow")  # plain block + @@||allow^ -> must RESOLVE
    plain_name = h.unique_domain("adr21plain")  # plain block -> must BLOCK (unaffected)
    # A HEADER-LESS body: no [Adblock / ! Title: line, so the feed stays format_hint='plain'
    # and only per-line detection can catch the anchors. The plain ``allow_name`` line is
    # placed alongside its ``@@`` to prove @@ overrides a plain block in the SAME feed.
    body = "\n".join([f"||{block_name}^", f"@@||{allow_name}^", allow_name, plain_name]) + "\n"
    feed_url = h.write_local_feed(deployed_vm, "smoke_adr21_perline.txt", body)
    spec = h.DnsblCase(aliasname="smokeadr21", feed_url=feed_url, header="smokeadr21", mode=h.DnsblMode.VIP)

    # BEFORE: none of the three names is on any feed yet -> each resolves via the stub.
    for name in (block_name, allow_name, plain_name):
        before = h.dns_probe_client(client_vm, name, "A")
        assert h.resolves_to(before, STUB_DNS_A), f"{name} should resolve via stub BEFORE listing, got {before}"
        assert not h.is_vip(before), f"{name} unexpectedly VIP-blocked before any feed: {before}"

    with h.CaseContext(deployed_vm, spec):
        # The "resolves" probe (the @@ allow) must reach the controlled stub: leave egress
        # OPEN. A VIP block returns locally regardless of egress, so this is no false-green.
        h.unblock_egress()
        # The before-probes warmed the C-cache; a feed allow->block swap is TTL-bounded BY
        # DESIGN (ADR-10) and does not flush the cache -> flush each name, then poll the
        # blocked ones until the async swap's VIP lands.
        for name in (block_name, allow_name, plain_name):
            h.flush_unbound_name(deployed_vm, name)

        ans_block = h.dns_probe_client_until(client_vm, block_name, h.is_vip)
        assert not h.resolves_to(ans_block, STUB_DNS_A), f"{block_name} still resolving after ||block^: {ans_block}"

        ans_plain = h.dns_probe_client_until(client_vm, plain_name, h.is_vip)
        assert not h.resolves_to(ans_plain, STUB_DNS_A), f"{plain_name} still resolving after plain block: {ans_plain}"

        ans_allow = h.dns_probe_client(client_vm, allow_name, "A")
        assert h.resolves_to(ans_allow, STUB_DNS_A), (
            f"@@||{allow_name}^ must RESOLVE via the stub (its @@ allow beats the same-feed plain block): {ans_allow}"
        )
        assert not h.is_vip(ans_allow), f"{allow_name} wrongly VIP-blocked despite its @@ allow: {ans_allow}"


# --------------------------------------------------------------------------- #
# ADR-21 hardening — two review fixes, each ORIGINALLY pinned by a DISTINGUISHING
# live transition: (1) a leading UTF-8 BOM must not mask a ``[...]`` control
# line's classification; (2) per-line ABP capture is VERBATIM (a path anchor is
# skipped, never truncated into a domain-wide over-block).
# --------------------------------------------------------------------------- #


@pytest.mark.timeout(300)
def test_abp_bom_header_still_detected(deployed_vm: SmokeVM, client_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """ADR-21/ADR-62/#1108: a UTF-8 BOM must not mask a header line OR a mid-feed comment.

    Scenario: a feed whose first bytes are a UTF-8 BOM (``EF BB BF``) followed by the
    ``[Adblock Plus 2.0]`` header, a single feed regex ``/badword/``, and a THIRD,
    non-leading line that itself opens with its own BOM ahead of a ``!`` comment
    carrying a unique marker. ADR-62's per-line capture (``pfb_dnsbl_is_abp_rule_line()``)
    compiles the feed ``/regex/`` regardless of a header line's presence, so the VIP
    block on a ``badword``-bearing name is feed-loaded sanity; the strict regression
    oracle is the parse-error-log count for the mid-feed marker.
    ``pfb_dnsbl_strip_bom()`` runs on EVERY line, not just the first — a regression
    there leaves the mid-feed BOM in place, the ``!`` control-line skip misses it
    (it no longer starts with ``!``), and the line falls through to domain
    validation and gets logged via ``pfb_parse_fail_log()``. This complements
    ``test_dnsbl_bom_header_feed_parses_without_error`` below, which pins the
    LEADING-line case the same way.

    Given (before the feed loads) the regex-target name RESOLVES via the controlled stub
      upstream (``STUB_DNS_A``), and a baseline count of the mid-feed marker in the
      DNSBL parse-error log.
    When the BOM-led ABP feed loads (Force Update),
    Then the ``badword``-bearing name returns the VIP block shape and no longer
      resolves (feed-loaded sanity), AND the parse-error-log count for the mid-feed
      marker stays AT the baseline — a per-line BOM-strip regression would strictly
      increase it (the mid-feed comment logged as invalid data instead of skipped).
    """
    uid = h.unique_domain("adr21bom").split(".", 1)[0]  # the unique label only
    blocked = f"xbadwordx-{uid}.com"
    # A fixed ASCII marker (mirrors the sibling test below), reused both as the
    # mid-feed comment text and as the count_log_marker() needle.
    bom_marker = "Issue #1108: BOM-led mid-feed '!' comment line"
    body = h.abp_feed_bom("/badword/", h.ABP_BOM + "! " + bom_marker)
    feed_url = h.write_local_feed(deployed_vm, "smoke_adr21_bom.txt", body)
    spec = h.DnsblCase(aliasname="smokeadr21bom", feed_url=feed_url, header="smokeadr21bom", mode=h.DnsblMode.VIP)

    # BEFORE: the name is on no feed yet -> it resolves via the stub sentinel.
    before = h.dns_probe_client(client_vm, blocked, "A")
    assert h.resolves_to(before, STUB_DNS_A), f"{blocked} should resolve via stub BEFORE listing, got {before}"
    assert not h.is_vip(before), f"{blocked} unexpectedly VIP-blocked before any feed: {before}"

    parse_err_before = h.count_log_marker(deployed_vm, h.DNSBL_PARSE_ERR_LOG, bom_marker)

    with h.CaseContext(deployed_vm, spec):
        # The block returns the VIP locally; egress stays OPEN so the before/after stub
        # contrast is real (a would-be resolve still reaches the stub, no false-green).
        h.unblock_egress()
        h.flush_unbound_name(deployed_vm, blocked)
        ans = h.dns_probe_client_until(client_vm, blocked, h.is_vip)
        assert not h.resolves_to(ans, STUB_DNS_A), (
            f"{blocked} still resolving after a BOM-led ABP feed regex block "
            f"(a BOM-masked header would leave the feed 'plain' and drop the regex): {ans}"
        )

        # THEN (RED->GREEN carrier): no NEW parse-error log line for the mid-feed
        # BOM-led '!' comment -- a regressed per-line strip would leave it un-skipped,
        # falling through to domain validation and logged as invalid data.
        parse_err_after = h.count_log_marker(deployed_vm, h.DNSBL_PARSE_ERR_LOG, bom_marker)
        assert parse_err_after == parse_err_before, (
            f"expected NO new DNSBL parse-error log line for the mid-feed BOM-led '!' "
            f"comment (before={parse_err_before}, after={parse_err_after}) -- a "
            f"non-leading BOM must be stripped and the comment skipped, never logged "
            f"as invalid data:\n{h.read_log_file(deployed_vm, h.DNSBL_PARSE_ERR_LOG)[-2000:]}"
        )


@pytest.mark.timeout(300)
def test_abp_perline_path_anchor_not_overblocked(
    deployed_vm: SmokeVM, client_vm: SmokeVM, mock_feeds: _MockFeedServer
) -> None:
    """ADR-21: a path-anchored ``||domain/path^`` in a plain feed must NOT block the domain.

    Per-line ABP capture writes the anchor VERBATIM ahead of the plain pipeline's
    URL/path stripping. ``parse_abp`` then SKIPS a path anchor (``/`` in the host ->
    returns None), so the domain is not blocked. The pre-fix code stripped ``/path^``
    FIRST, truncating the line to ``||domain`` -> ``parse_abp`` would block ``domain`` (a
    spurious wildcard over-block). A sibling clean ``||<blk>^`` proves the feed actually
    loaded and per-line routing is live (else the path-resolves assertion is vacuous).

    Given (before the feed loads) BOTH names RESOLVE via the controlled stub upstream.
    When the header-less feed (``||<blk>^`` + ``||<path>/ads^``) loads (Force Update),
    Then ``<blk>`` is VIP-blocked (per-line ``||`` reached parse_abp), while ``<path>``
      STILL RESOLVES via the stub (its path anchor was skipped, not truncated into a
      block). The pre-fix truncation would VIP-block ``<path>`` too, failing this.
    """
    blk = h.unique_domain("adr21pblk")  # clean ||blk^ -> must BLOCK (feed-loaded proof)
    path_dom = h.unique_domain("adr21ppath")  # ||path/ads^ -> path anchor -> must RESOLVE
    body = "\n".join([f"||{blk}^", f"||{path_dom}/ads^"]) + "\n"
    feed_url = h.write_local_feed(deployed_vm, "smoke_adr21_path.txt", body)
    spec = h.DnsblCase(aliasname="smokeadr21pth", feed_url=feed_url, header="smokeadr21pth", mode=h.DnsblMode.VIP)

    # BEFORE: neither name is on any feed yet -> each resolves via the stub sentinel.
    for name in (blk, path_dom):
        before = h.dns_probe_client(client_vm, name, "A")
        assert h.resolves_to(before, STUB_DNS_A), f"{name} should resolve via stub BEFORE listing, got {before}"
        assert not h.is_vip(before), f"{name} unexpectedly VIP-blocked before any feed: {before}"

    with h.CaseContext(deployed_vm, spec):
        # The clean || block returns the VIP locally; egress stays OPEN so the path
        # anchor's continued resolution reaches the stub (a real non-block, no false-green).
        h.unblock_egress()
        for name in (blk, path_dom):
            h.flush_unbound_name(deployed_vm, name)

        ans_blk = h.dns_probe_client_until(client_vm, blk, h.is_vip)
        assert not h.resolves_to(ans_blk, STUB_DNS_A), f"{blk} still resolving after ||{blk}^: {ans_blk}"

        ans_path = h.dns_probe_client(client_vm, path_dom, "A")
        assert h.resolves_to(ans_path, STUB_DNS_A), (
            f"||{path_dom}/ads^ is a PATH anchor -> parse_abp must skip it, so {path_dom} must RESOLVE "
            f"(pre-fix truncation to ||{path_dom} would over-block it): {ans_path}"
        )
        assert not h.is_vip(ans_path), (
            f"{path_dom} wrongly VIP-blocked (path anchor truncated into a block): {ans_path}"
        )


# --------------------------------------------------------------------------- #
# Issue #946 — the UTF-8 BOM strip is hoisted to the TOP of the per-line parse loop,
# ahead of the '!' comment skip, the ADR-21 '||' anchor short-circuit, and CSV
# autodetection (all three previously ran against a still-BOM'd first line). The
# committed fixture below opens with a BOM directly ahead of a '!' comment line,
# followed by an anchor line and a hosts line -- neither of the latter two carries a
# BOM, so they are unaffected by the fix either way (see the test docstring).
# --------------------------------------------------------------------------- #


def test_dnsbl_bom_header_feed_parses_without_error(
    deployed_vm: SmokeVM, client_vm: SmokeVM, mock_feeds: _MockFeedServer
) -> None:
    """Issue #946: a BOM-led '!' first line no longer misclassifies the rest of the feed.

    ``dnsbl_bom_header.txt`` (header-less, non-ABP) opens with a UTF-8 BOM
    (``EF BB BF``) directly ahead of a '!' comment line, followed by an ADR-21 ``||``
    anchor line and a plain hosts (``0.0.0.0 <domain>``) line. ``pfb_dnsbl_strip_bom()``
    is now hoisted to the TOP of the per-line loop, so line 1's BOM is stripped BEFORE
    the '!' comment check runs. Pre-fix, that check ran against the still-BOM'd line,
    missed the '!' prefix, and the line fell through as data -- ultimately failing
    domain validation and getting logged via ``pfb_parse_fail_log()``, whose ``$oline``
    field is the untouched, BOM-bearing original line.

    The anchor line and the hosts line carry NO BOM, so both block identically
    whether or not this fix is present -- they prove the feed as a whole still loads,
    but the parse-error-log assertion below is the actual RED->GREEN carrier.

    Given (before the feed loads) both domains RESOLVE via the controlled stub
      upstream, and a baseline count of this fixture's exact BOM-led original line in
      the DNSBL parse-error log (a fresh, never-updated header).
    When the feed loads over HTTP (Force Update),
    Then both the anchor-line domain and the hosts-line domain return the VIP block
      shape, AND the parse-error-log count for the BOM-led line stays AT the baseline
      -- pre-fix it would strictly increase (the line would be logged as bad data
      instead of skipped as a comment).
    """
    anchor_member = "uuid-6c91761cef48.com"  # ADR-21 '||' anchor line -> must BLOCK
    hosts_member = "uuid-2329767ef078.com"  # hosts '0.0.0.0 domain' line -> must BLOCK
    feed_url = mock_feeds.feed_url("dnsbl_bom_header.txt")
    spec = h.DnsblCase(aliasname="smokefeedbom", feed_url=feed_url, header="smokefeedbom", mode=h.DnsblMode.VIP)
    # An ASCII substring of the fixture's BOM-led '!' line (skips the BOM bytes
    # themselves -- grep -F matches it anywhere in the CSV's $oline field, so the
    # leading BOM need not round-trip through the SSH/grep pipeline byte-for-byte).
    bom_line_marker = "Issue #946: BOM-led '!' comment first line"

    # BEFORE: neither domain is on any feed yet -> both resolve via the stub sentinel.
    for name in (anchor_member, hosts_member):
        before = h.dns_probe_client(client_vm, name, "A")
        assert h.resolves_to(before, STUB_DNS_A), f"{name} should resolve via stub BEFORE listing, got {before}"
        assert not h.is_vip(before), f"{name} unexpectedly VIP-blocked before any feed: {before}"

    parse_err_before = h.count_log_marker(deployed_vm, h.DNSBL_PARSE_ERR_LOG, bom_line_marker)

    with h.CaseContext(deployed_vm, spec):
        h.unblock_egress()
        for name in (anchor_member, hosts_member):
            h.flush_unbound_name(deployed_vm, name)

        ans_anchor = h.dns_probe_client_until(client_vm, anchor_member, h.is_vip)
        assert not h.resolves_to(ans_anchor, STUB_DNS_A), (
            f"{anchor_member} still resolving after the ADR-21 anchor line block: {ans_anchor}"
        )
        ans_hosts = h.dns_probe_client_until(client_vm, hosts_member, h.is_vip)
        assert not h.resolves_to(ans_hosts, STUB_DNS_A), (
            f"{hosts_member} still resolving after the hosts-line block: {ans_hosts}"
        )

        # THEN (RED->GREEN carrier): no NEW parse-error log line for the BOM-led '!'
        # first line -- pre-fix this count would be strictly greater (the still-BOM'd
        # line missed the '!' comment skip and was logged as an invalid domain).
        parse_err_after = h.count_log_marker(deployed_vm, h.DNSBL_PARSE_ERR_LOG, bom_line_marker)
        assert parse_err_after == parse_err_before, (
            f"expected NO new DNSBL parse-error log line for the BOM-led '!' first line "
            f"(before={parse_err_before}, after={parse_err_after}) -- a BOM-led comment "
            f"must be skipped, never logged as invalid data:\n"
            f"{h.read_log_file(deployed_vm, h.DNSBL_PARSE_ERR_LOG)[-2000:]}"
        )


# --------------------------------------------------------------------------- #
# ADR-22 — the "Lenient feed parsing" toggle (pfb_dnsbl_lenient) over the live box.
#
# The non-lite DNSBL download path strips a ``<scheme>://`` prefix from each feed
# line (pfblockerng.inc:11316-11329). Lenient (toggle ON — the migrated/legacy
# default) keeps today's permissive strip: ANY ``://`` is removed at its first
# occurrence and a URL path is stripped downstream, so a malformed-scheme line
# (digit-start) and a path line are still extracted + blocked. Strict (toggle OFF —
# the new-install default) validates the scheme against RFC 3986 and rejects a URL
# path: a rejected line is SKIPPED, recorded per-line in the DNSBL parse-error log
# (pfb_parse_fail_log -> $pfb['dnsbl_parse_err']), and counted into ONE per-feed WARNING
# in the main pfBlockerNG log (pfb_dnsbl_scheme_skip_warn).
#
# DELIVERY: the scheme lines ride a normal LOCAL feed row (write_local_feed), the
# same mechanism test_abp_perline_detection_in_plain_feed uses — the body carries
# runtime unique_domain() uuids so it must be a local file, and a feed row is exactly
# what flows through the non-lite download loop the toggle gates (the GUI Custom_List
# feeds the SAME loop via a synthetic row; the loop, not the entry point, is the
# behaviour under test). Tests A/B drive inject -> set toggle -> Force Update manually
# (NOT CaseContext, which injects+reloads atomically before the toggle could be set)
# and restore config + custom feed in finally.
# --------------------------------------------------------------------------- #


def _scheme_feed_path(vm: SmokeVM, name: str, lines: list[str]) -> str:
    """Write a header-less plain feed of raw scheme lines; return its on-box path."""
    body = "\n".join(lines) + "\n"
    return h.write_local_feed(vm, name, body)


@pytest.mark.timeout(300)
def test_strict_skips_invalid_scheme_and_path_and_logs(deployed_vm: SmokeVM, client_vm: SmokeVM) -> None:
    """ADR-22 strict (lenient OFF): invalid-scheme + path lines are skipped AND logged.

    Scenario: a DNSBL feed mixes two well-formed scheme lines (a valid RFC 3986 scheme,
    no path) with two malformed ones (a digit-start scheme; a valid scheme bearing a URL
    path). With ``pfb_dnsbl_lenient='off'`` the parser must BLOCK the two well-formed
    hosts and SKIP+LOG the two malformed lines — both in the DNSBL parse-error log
    (per-line) and as one per-feed WARNING in the main log (ADR §2.3).

    Given (before any feed loads) all four hosts RESOLVE via the controlled stub upstream
      (``STUB_DNS_A``) — the real, observable before-state (none is blocked yet).
    When  the feed is written, ``pfb_dnsbl_lenient`` is set OFF (strict), and a Force
      Update runs (Unbound reloads),
    Then:
      * ``http://<http>``      -> VIP/NULL block (valid scheme, no path);
      * ``evil://<evil>``      -> VIP/NULL block (valid custom RFC 3986 scheme, no path);
      * ``123://<badscheme>``  -> still RESOLVES (digit-start scheme rejected -> skipped);
      * ``http://<haspath>/path`` -> still RESOLVES (URL path rejected -> skipped);
    And the two skipped originals' labels appear in the DNSBL parse-error log, AND a
      per-feed "N line(s) skipped - strict parsing ..." WARNING for this feed is present
      in the main pfBlockerNG log (count strictly greater than the pre-update baseline,
      proving THIS update wrote it).
    """
    http_dom = h.unique_domain("adr22http")  # http://     -> valid scheme, no path -> BLOCK
    evil_dom = h.unique_domain("adr22evil")  # evil://     -> valid custom scheme   -> BLOCK
    bad_dom = h.unique_domain("adr22bad")  # 123://       -> digit-start invalid    -> SKIP+LOG
    path_dom = h.unique_domain("adr22path")  # http://.../path -> URL path present  -> SKIP+LOG
    header = "smokeadr22strict"
    feed_url = _scheme_feed_path(
        deployed_vm,
        "smoke_adr22_strict.txt",
        [f"http://{http_dom}", f"evil://{evil_dom}", f"123://{bad_dom}", f"http://{path_dom}/path"],
    )
    spec = h.DnsblCase(aliasname="smokeadr22s", feed_url=feed_url, header=header, mode=h.DnsblMode.VIP)

    def _blocked(ans: h.DnsAnswer) -> bool:
        return h.is_vip(ans) or h.is_null_ip(ans)

    try:
        # BEFORE: none of the four is on a feed yet -> each resolves via the stub.
        h.unblock_egress()
        for name in (http_dom, evil_dom, bad_dom, path_dom):
            before = h.dns_probe_client(client_vm, name, "A")
            assert h.resolves_to(before, STUB_DNS_A), f"{name} should resolve via stub BEFORE listing, got {before}"
            assert not _blocked(before), f"{name} unexpectedly blocked before any feed: {before}"

        # WHEN: load the feed STRICTLY (lenient OFF). Capture the per-feed-WARNING + the
        # parse-error-log baselines before the update so a strictly-greater count proves
        # THIS update emitted them.
        h.inject(deployed_vm, spec)
        h.set_dnsbl_lenient(deployed_vm, False)
        warn_marker = f"{header}: 2 line(s) skipped"
        warn_before = h.count_log_marker(deployed_vm, h.PFB_LOG, warn_marker)
        h.reload(deployed_vm, "update")

        # THEN (DNS shapes): the two valid-scheme hosts BLOCK; the two skipped lines
        # still RESOLVE. A feed load swaps via the ADR-10 async path -> flush + poll the
        # blocked names; the skipped names were never listed so they keep resolving.
        h.flush_unbound_name(deployed_vm, http_dom)
        h.flush_unbound_name(deployed_vm, evil_dom)
        ans_http = h.dns_probe_client_until(client_vm, http_dom, _blocked)
        assert not h.resolves_to(ans_http, STUB_DNS_A), (
            f"http://{http_dom} still resolving after strict load: {ans_http}"
        )
        ans_evil = h.dns_probe_client_until(client_vm, evil_dom, _blocked)
        assert not h.resolves_to(ans_evil, STUB_DNS_A), (
            f"evil://{evil_dom} still resolving after strict load: {ans_evil}"
        )
        ans_bad = h.dns_probe_client(client_vm, bad_dom, "A")
        assert h.resolves_to(ans_bad, STUB_DNS_A), (
            f"123://{bad_dom} must be SKIPPED under strict (digit-start scheme) -> still resolves, got {ans_bad}"
        )
        assert not _blocked(ans_bad), f"123://{bad_dom} wrongly blocked under strict (should be skipped): {ans_bad}"
        ans_path = h.dns_probe_client(client_vm, path_dom, "A")
        assert h.resolves_to(ans_path, STUB_DNS_A), (
            f"http://{path_dom}/path must be SKIPPED under strict (URL path) -> still resolves, got {ans_path}"
        )
        assert not _blocked(ans_path), (
            f"http://{path_dom}/path wrongly blocked under strict (should be skipped): {ans_path}"
        )

        # THEN (logging, ADR §2.3): both skipped originals appear in the parse-error log...
        parse_err = h.read_log_file(deployed_vm, h.DNSBL_PARSE_ERR_LOG)
        assert bad_dom in parse_err, f"{bad_dom} (123:// skip) not in DNSBL parse-error log:\n{parse_err[-2000:]}"
        assert path_dom in parse_err, f"{path_dom} (path skip) not in DNSBL parse-error log:\n{parse_err[-2000:]}"
        # ...and exactly the per-feed summary WARNING (2 lines skipped) appears in the main log.
        warn_after = h.count_log_marker(deployed_vm, h.PFB_LOG, warn_marker)
        assert warn_after > warn_before, (
            f"per-feed strict-skip WARNING ('{warn_marker}') not appended to {h.PFB_LOG} "
            f"(before={warn_before}, after={warn_after})"
        )
    finally:
        h.reset(deployed_vm)
        h.set_dnsbl_lenient(deployed_vm, True)
        deployed_vm.ssh("/bin/rm", "-f", feed_url)


@pytest.mark.timeout(300)
def test_lenient_blocks_invalid_scheme_and_path(deployed_vm: SmokeVM, client_vm: SmokeVM) -> None:
    """ADR-22 lenient (ON): invalid-scheme + path lines are BLOCKED, no WARNING (today's behaviour).

    The lenient counterpart of the strict test: with ``pfb_dnsbl_lenient='on'`` the SAME
    two malformed lines that strict skips are instead extracted and blocked (byte-identical
    to today's permissive strip), and NO per-feed strict-skip WARNING is emitted. Pairing
    this ON case with the OFF case above proves the toggle is a real branch, not an
    always-skip or always-block path.

    Given (before any feed loads) both hosts RESOLVE via the controlled stub upstream.
    When  the feed is written, ``pfb_dnsbl_lenient`` is set ON (lenient), and a Force
      Update runs,
    Then  ``123://<badscheme>`` and ``http://<haspath>/path`` BOTH return the block shape
      and no longer resolve (the digit-start scheme is stripped; the path is stripped
      downstream) — AND no per-feed strict-skip WARNING for this feed appears in the main
      log (lenient is silent, ADR §2.3).
    """
    bad_dom = h.unique_domain("adr22lbad")  # 123://     -> stripped -> BLOCK under lenient
    path_dom = h.unique_domain("adr22lpath")  # http://.../path -> path stripped -> BLOCK under lenient
    header = "smokeadr22lenient"
    feed_url = _scheme_feed_path(
        deployed_vm,
        "smoke_adr22_lenient.txt",
        [f"123://{bad_dom}", f"http://{path_dom}/path"],
    )
    spec = h.DnsblCase(aliasname="smokeadr22l", feed_url=feed_url, header=header, mode=h.DnsblMode.VIP)

    def _blocked(ans: h.DnsAnswer) -> bool:
        return h.is_vip(ans) or h.is_null_ip(ans)

    try:
        # BEFORE: neither host is on a feed yet -> each resolves via the stub.
        h.unblock_egress()
        for name in (bad_dom, path_dom):
            before = h.dns_probe_client(client_vm, name, "A")
            assert h.resolves_to(before, STUB_DNS_A), f"{name} should resolve via stub BEFORE listing, got {before}"
            assert not _blocked(before), f"{name} unexpectedly blocked before any feed: {before}"

        # WHEN: load the feed LENIENTLY (toggle ON).
        h.inject(deployed_vm, spec)
        h.set_dnsbl_lenient(deployed_vm, True)
        # Any per-feed strict-skip WARNING for THIS feed (1 or 2 lines) must NOT appear.
        warn_marker_any = f"{header}: "
        warn_before = h.count_log_marker(deployed_vm, h.PFB_LOG, "line(s) skipped - strict parsing")
        # Baseline the feed-specific count too: the log persists across cases, so assert it is
        # UNCHANGED by this reload rather than absolutely zero (transition, not absolute state).
        feed_warn_before = h.count_log_marker(deployed_vm, h.PFB_LOG, warn_marker_any + "1 line(s) skipped")
        feed_warn_before += h.count_log_marker(deployed_vm, h.PFB_LOG, warn_marker_any + "2 line(s) skipped")
        h.reload(deployed_vm, "update")

        # THEN (DNS shapes): both malformed lines are now BLOCKED (today's behaviour).
        for name in (bad_dom, path_dom):
            h.flush_unbound_name(deployed_vm, name)
        ans_bad = h.dns_probe_client_until(client_vm, bad_dom, _blocked)
        assert not h.resolves_to(ans_bad, STUB_DNS_A), (
            f"123://{bad_dom} must be BLOCKED under lenient (today's strip), still resolving: {ans_bad}"
        )
        ans_path = h.dns_probe_client_until(client_vm, path_dom, _blocked)
        assert not h.resolves_to(ans_path, STUB_DNS_A), (
            f"http://{path_dom}/path must be BLOCKED under lenient (path stripped downstream), got {ans_path}"
        )

        # THEN (logging): lenient is SILENT -> no new strict-skip WARNING line at all, and
        # none naming this feed.
        warn_after = h.count_log_marker(deployed_vm, h.PFB_LOG, "line(s) skipped - strict parsing")
        assert warn_after == warn_before, (
            f"lenient mode must emit NO strict-skip WARNING, but the count rose "
            f"(before={warn_before}, after={warn_after})"
        )
        feed_warn_after = h.count_log_marker(deployed_vm, h.PFB_LOG, warn_marker_any + "1 line(s) skipped")
        feed_warn_after += h.count_log_marker(deployed_vm, h.PFB_LOG, warn_marker_any + "2 line(s) skipped")
        assert feed_warn_after == feed_warn_before, (
            f"lenient mode wrongly emitted a per-feed strict-skip WARNING for {header} "
            f"(before={feed_warn_before}, after={feed_warn_after})"
        )
    finally:
        h.reset(deployed_vm)
        h.set_dnsbl_lenient(deployed_vm, True)
        deployed_vm.ssh("/bin/rm", "-f", feed_url)


@pytest.mark.timeout(300)
def test_migration_sets_lenient_on_for_existing_install(deployed_vm: SmokeVM) -> None:
    """ADR-22 §2.2 grandfather on the live box: an existing install lacking the key -> 'on'.

    Given the live DNSBL-settings section is populated (it always is on the deployed box —
      pfb_dnsbl etc. are set) and ``pfb_dnsbl_lenient`` is REMOVED (the upgrade-from-an-
      older-version state) — asserted absent as the before-state,
    When  ``pfb_registry_pass()`` runs against that section and the result is persisted
      (the install-hook body),
    Then  the live config now reads ``pfb_dnsbl_lenient == 'on'`` — a present value is
      never overwritten.

    Scoped to the DNSBL section only: driving the full ``pfblockerng_install.inc``
    require-flow would re-run every install side effect (VIP / python-mode / PFBL-03
    migrations, the pass over every other section) on the live box.
    """
    sentinel_open = "<<<LENIENT>>>"
    sentinel_close = "<<<END>>>"

    # BEFORE: populate the section (it is on the deployed box) then REMOVE the key, and
    # assert it is absent — the genuine "upgraded-from-older-version" before-state.
    remove = (
        f"$d = config_get_path({h._php_str(h.CFG_DNSBL_SETTINGS)}, array());\n"
        "$d['pfb_dnsbl'] = 'on';\n"  # ensure the section is populated (an existing install)
        "unset($d['pfb_dnsbl_lenient']);\n"
        f"config_set_path({h._php_str(h.CFG_DNSBL_SETTINGS)}, $d);\n"
        "write_config('pfBlockerNG smoke: ADR-22 grandfather before-state');\n"
        "echo 'OK';"
    )
    res = h.php_eval(deployed_vm, remove)
    assert "OK" in res.stdout, f"could not stage the grandfather before-state: {res.stdout!r} {res.stderr!r}"
    assert h.config_get(deployed_vm, h.CFG_DNSBL_SETTINGS + "/pfb_dnsbl_lenient") == "", (
        "pfb_dnsbl_lenient should be ABSENT (empty) before the registry pass runs"
    )

    try:
        # WHEN: run the SHIPPED registry pass (the install-hook body), scoped to just the
        # DNSBL section, against the live config and persist the (changed) result.
        migrate = (
            "require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');\n"
            f"$section = {h._php_str(h.CFG_DNSBL_SETTINGS)};\n"
            "$cfg = config_get_path($section, array());\n"
            "$result = pfb_registry_pass(array($section => $cfg));\n"
            "$out = array_key_exists($section, $result) ? $result[$section] : NULL;\n"
            "if ($out !== NULL) {\n"
            "  config_set_path($section, $out);\n"
            "  write_config('pfBlockerNG: registry pass (smoke)');\n"
            "}\n"
            f"echo {h._php_str(sentinel_open)} . ($out === NULL ? 'NULL' : 'SET') . {h._php_str(sentinel_close)};"
        )
        res = h.php_eval(deployed_vm, migrate)
        assert sentinel_open in res.stdout, f"registry pass eval produced no sentinel: {res.stdout!r} {res.stderr!r}"
        verdict = res.stdout[res.stdout.find(sentinel_open) + len(sentinel_open) : res.stdout.find(sentinel_close)]
        assert verdict == "SET", f"registry pass should SET the changed section (returned {verdict})"

        # THEN: the live config now carries pfb_dnsbl_lenient == 'on'.
        after = h.config_get(deployed_vm, h.CFG_DNSBL_SETTINGS + "/pfb_dnsbl_lenient")
        assert after == "on", f"registry pass must set pfb_dnsbl_lenient='on' for an existing install, got {after!r}"
    finally:
        # Restore the harness default (lenient ON) — same value the pass set, but make
        # the cleanup explicit + independent of the assertion above.
        h.set_dnsbl_lenient(deployed_vm, True)


# --------------------------------------------------------------------------- #
# ADR-31 — DNSWL allow-feeds (per-row Deny/Permit action) end-to-end journey.
#
# A DNSBL feed row with ``action='Permit'`` emits ``mode='permit'`` in the PHP
# manifest, which the Python module loads into whiteDB at band 2 (feed-allow).
# Band 2 overrides any same-feed-or-cross-feed block (band 1) but loses to:
#   band 6 — manual DNSBL whitelist (suppression textarea)
#   band 5 — sovereign user block (Custom_List / pfb_regex / lock)
#
# §2.2 contract cases proven here (all before-and-after, no false-greens):
#   §2.2.1  block-only feed (absent/Deny action): domain still blocks (baseline)
#   §2.2.2  Permit feed overrides a block feed on the shared domain
#   §2.2.3  band 5 (Custom_List) and band 6 (whitelist suppression) still win
#   §2.2.4  subdomain-covering (child of a listed parent resolves); non-listed unaffected
#   teardown: remove Permit → shared domain is blocked again (no whiteDB residue)
# --------------------------------------------------------------------------- #


@pytest.mark.timeout(600)
def test_dnswl_permit_feed_allow_overrides_block_feed(deployed_vm: SmokeVM, client_vm: SmokeVM) -> None:
    """ADR-31 §2.2 end-to-end: a Permit feed allow-overrides a block feed and teardown re-blocks.

    All test domains use :func:`helpers.unique_domain` (uuid-*.com) — never RFC 6761
    TLDs (.test/.example/.invalid) which Unbound's built-in local-zones shadow before
    pfBlockerNG runs, and never HSTS-preload names (HSTS default-ON forces NULL on a
    VIP block, masking whether a name actually resolved). Probed from the civm
    LAN client via :func:`helpers.dns_probe_client` (pfSense's LAN resolver); the
    first response after each reload is authoritative.

    Background — the feed layout used:
      * Block feed  (Deny action, aliasname=smokednyblk):  S, B, M (+ M in Custom_List -> band 5)
      * Permit feed (Permit action, aliasname=smokednypmt): S, P (parent); child.P is a subdomain

    where:
      S = shared domain   (block feed + permit feed  -> permit wins at band 2)
      B = block-only      (block feed only           -> blocked at band 1)
      M = manually-blocked(block feed + Custom_List  -> blocked at band 5, beats permit)
      P = permit parent   (permit feed only          -> resolves; child.P also resolves)
      X = non-listed      (not on any feed           -> always resolves)
      W = whitelisted     (permit feed + suppression -> suppression/band 6 still resolves)

    Scenario (BDD):
      Given (§2.2.1 — block-only baseline, before permit feed exists):
        * S, B, M, P, child.P all RESOLVE via the stub sentinel (no feed is live yet)
      When the BLOCK FEED alone is loaded (Deny action, no Permit feed),
      Then S, B, M are VIP-blocked; P, child.P, X RESOLVE (§2.2.1: block-only = standard
           block, absent action = Deny, §2.2.4 non-listed unaffected).
      When the PERMIT FEED is added alongside the block feed (Permit action),
      Then (§2.2.2) S RESOLVES (permit feed at band 2 beats block feed at band 1);
           (§2.2.2) B remains VIP-blocked (B is on the block feed, not the permit feed);
           (§2.2.3) M remains VIP-blocked (Custom_List = band-5 sovereign block beats band 2);
           (§2.2.4) P and child.P RESOLVE (permit feed covers P; Unbound's wildcard logic
                    extends the allow to child.P); X RESOLVES (not on any feed).
      When the PERMIT FEED is removed (Permit→Deny teardown):
      Then S is VIP-blocked again (no permit feed -> whiteDB entry gone -> band-1 block wins).
    """
    # --- Domain setup (unique_domain ensures no collision / RFC 6761 / HSTS issue) ---
    s_domain = h.unique_domain("adr31s")  # Shared: block + permit -> permit wins
    b_domain = h.unique_domain("adr31b")  # Block-only -> always blocked
    m_domain = h.unique_domain("adr31m")  # Manually-blocked via Custom_List (band 5)
    p_domain = h.unique_domain("adr31p")  # Permit parent -> resolves
    child_p = "child." + p_domain  # Subdomain of permit parent -> also resolves (§2.2.4)
    x_domain = h.unique_domain("adr31x")  # Non-listed -> always resolves

    # Block feed body: S, B, M (plain domain list; header-less = plain pipeline)
    block_body = "\n".join([s_domain, b_domain, m_domain]) + "\n"
    block_feed_url = h.write_local_feed(deployed_vm, "smoke_adr31_block.txt", block_body)

    # Permit feed body: S, P.  child.P is a subdomain — no explicit listing needed;
    # pfBlockerNG's DNSBL wildcard logic (python mode, whiteDB allow) covers it.
    permit_body = "\n".join([s_domain, p_domain]) + "\n"
    permit_feed_url = h.write_local_feed(deployed_vm, "smoke_adr31_permit.txt", permit_body)

    # Block spec: M is also in Custom_List so it gets a band-5 sovereign-user-block row
    # (provenance='user'), which beats the band-2 permit even if M were on the permit feed.
    block_spec = h.DnsblCase(
        aliasname="smokeadr31blk",
        feed_url=block_feed_url,
        header="smokeadr31blk",
        mode=h.DnsblMode.VIP,
        custom_domains=[m_domain],  # -> band-5 sovereign block for M
    )
    # Permit spec: VIP mode (same sinkhole shape); no custom_domains.
    permit_spec = h.DnsblCase(
        aliasname="smokeadr31pmt",
        feed_url=permit_feed_url,
        header="smokeadr31pmt",
        mode=h.DnsblMode.VIP,
    )

    try:
        h.unblock_egress()

        # ------------------------------------------------------------------ #
        # GIVEN — before-state: nothing is on any feed yet, all names RESOLVE.
        # ------------------------------------------------------------------ #
        for name in (s_domain, b_domain, m_domain, p_domain, child_p, x_domain):
            before = h.dns_probe_client(client_vm, name, "A")
            assert h.resolves_to(before, STUB_DNS_A), (
                f"{name} should resolve via stub BEFORE any feed is loaded, got {before}"
            )
            assert not h.is_vip(before), f"{name} unexpectedly VIP-blocked before any feed: {before}"

        # ------------------------------------------------------------------ #
        # §2.2.1 — BLOCK-ONLY FEED (Deny action, no Permit feed).
        # Expected: S, B, M blocked; P, child.P, X resolve.
        # Absent/Deny action = standard block feed (§2.2.1 + §2.2.5).
        # ------------------------------------------------------------------ #
        h.inject(deployed_vm, block_spec)
        h.reload(deployed_vm, "updatednsbl")

        # The before-probes warmed the C-cache; a feed swap is TTL-bounded (ADR-10)
        # -> flush each expected-blocked name then poll until the VIP block appears.
        for name in (s_domain, b_domain, m_domain):
            h.flush_unbound_name(deployed_vm, name)

        # §2.2.1: S is blocked by the block feed (no permit feed yet).
        ans_s_blk = h.dns_probe_client_until(client_vm, s_domain, h.is_vip)
        assert not h.resolves_to(ans_s_blk, STUB_DNS_A), (
            f"§2.2.1: {s_domain} should be VIP-blocked by the block feed (no permit feed yet): {ans_s_blk}"
        )

        # §2.2.1: B is blocked by the block feed (block-only, never on permit).
        ans_b_blk = h.dns_probe_client_until(client_vm, b_domain, h.is_vip)
        assert not h.resolves_to(ans_b_blk, STUB_DNS_A), (
            f"§2.2.1: {b_domain} should be VIP-blocked by the block feed: {ans_b_blk}"
        )

        # §2.2.1/§2.2.3: M is blocked via the block feed AND via band-5 Custom_List.
        ans_m_blk = h.dns_probe_client_until(client_vm, m_domain, h.is_vip)
        assert not h.resolves_to(ans_m_blk, STUB_DNS_A), (
            f"§2.2.3: {m_domain} should be VIP-blocked (Custom_List band-5 + block feed): {ans_m_blk}"
        )

        # §2.2.4: P and child.P RESOLVE (not on any block feed); X RESOLVES (not listed).
        for name in (p_domain, child_p, x_domain):
            ans = h.dns_probe_client(client_vm, name, "A")
            assert h.resolves_to(ans, STUB_DNS_A), (
                f"§2.2.4/non-listed: {name} should RESOLVE via stub (not on block feed): {ans}"
            )
            assert not h.is_vip(ans), f"{name} wrongly VIP-blocked with no matching feed: {ans}"

        # ------------------------------------------------------------------ #
        # §2.2.2 — ADD PERMIT FEED (block + permit coexist).
        # Expected: S RESOLVES (permit band 2 beats block band 1);
        #           B still BLOCKED (only on block feed);
        #           M still BLOCKED (band-5 Custom_List beats band-2 permit);
        #           P and child.P RESOLVE (on permit feed); X RESOLVES (not listed).
        # ------------------------------------------------------------------ #
        h.inject_dnsbl_lists(
            deployed_vm,
            [
                (block_spec, "Deny"),  # block feed: S, B, M (+ Custom_List band 5 for M)
                (permit_spec, "Permit"),  # permit feed: S, P -> band 2 allow
            ],
        )
        h.reload(deployed_vm, "updatednsbl")

        # S was cached as VIP-blocked (from the block-only phase above); a permit-feed
        # swap is TTL-bounded (ADR-10) -> flush S then poll until it RESOLVES.
        h.flush_unbound_name(deployed_vm, s_domain)
        # Also flush P/child.P so any stale not-on-feed answer clears for a clean check.
        h.flush_unbound_name(deployed_vm, p_domain)
        h.flush_unbound_name(deployed_vm, child_p)

        # §2.2.2: S RESOLVES — permit feed (band 2) overrides block feed (band 1).
        ans_s_pmt = h.dns_probe_client_until(client_vm, s_domain, lambda a: h.resolves_to(a, STUB_DNS_A))
        assert h.resolves_to(ans_s_pmt, STUB_DNS_A), (
            f"§2.2.2: {s_domain} must RESOLVE via stub (permit feed band 2 beats block band 1): {ans_s_pmt}"
        )
        assert not h.is_vip(ans_s_pmt), (
            f"§2.2.2: {s_domain} still VIP-blocked despite being on the permit feed: {ans_s_pmt}"
        )

        # §2.2.2: B remains VIP-blocked — only on the block feed, not the permit feed.
        ans_b_pmt = h.dns_probe_client(client_vm, b_domain, "A")
        assert h.is_vip(ans_b_pmt), (
            f"§2.2.2: {b_domain} must remain VIP-blocked (only on block feed, not on permit feed): {ans_b_pmt}"
        )
        assert not h.resolves_to(ans_b_pmt, STUB_DNS_A), (
            f"§2.2.2: {b_domain} wrongly resolving — block-only domain must stay blocked: {ans_b_pmt}"
        )

        # §2.2.3: M remains VIP-blocked — Custom_List (band 5) beats permit (band 2).
        ans_m_pmt = h.dns_probe_client(client_vm, m_domain, "A")
        assert h.is_vip(ans_m_pmt), (
            f"§2.2.3: {m_domain} must remain VIP-blocked (Custom_List band 5 > permit band 2): {ans_m_pmt}"
        )
        assert not h.resolves_to(ans_m_pmt, STUB_DNS_A), (
            f"§2.2.3: {m_domain} wrongly resolving — band-5 Custom_List must beat permit feed: {ans_m_pmt}"
        )

        # §2.2.4: P RESOLVES — on the permit feed; child.P RESOLVES — subdomain covering.
        ans_p = h.dns_probe_client(client_vm, p_domain, "A")
        assert h.resolves_to(ans_p, STUB_DNS_A), (
            f"§2.2.4: {p_domain} must RESOLVE via stub (permit feed allow): {ans_p}"
        )
        assert not h.is_vip(ans_p), f"§2.2.4: {p_domain} wrongly VIP-blocked despite permit feed: {ans_p}"

        ans_child = h.dns_probe_client(client_vm, child_p, "A")
        assert h.resolves_to(ans_child, STUB_DNS_A), (
            f"§2.2.4: {child_p} must RESOLVE via stub (subdomain of permit-listed parent): {ans_child}"
        )
        assert not h.is_vip(ans_child), (
            f"§2.2.4: {child_p} wrongly VIP-blocked (subdomain of permit-listed parent should resolve): {ans_child}"
        )

        # §2.2.4 (non-listed unaffected): X still RESOLVES — no feed entry for X.
        ans_x = h.dns_probe_client(client_vm, x_domain, "A")
        assert h.resolves_to(ans_x, STUB_DNS_A), (
            f"§2.2.4: non-listed {x_domain} must RESOLVE via stub (not on any feed): {ans_x}"
        )
        assert not h.is_vip(ans_x), f"§2.2.4: non-listed {x_domain} wrongly VIP-blocked: {ans_x}"

        # ------------------------------------------------------------------ #
        # TEARDOWN — remove Permit: reload as block-only again.
        # Expected: S is VIP-blocked again (no whiteDB residue from permit).
        # This is also the implicit §2.2.5 proof (absent action = Deny = standard block).
        # ------------------------------------------------------------------ #
        h.inject(deployed_vm, block_spec)  # block-only; no permit feed
        h.reload(deployed_vm, "updatednsbl")

        # S was cached as RESOLVED (from the permit phase above); the permit feed is
        # gone so S should now be VIP-blocked. ADR-10 allow->block is TTL-bounded ->
        # flush S then poll until the block lands.
        h.flush_unbound_name(deployed_vm, s_domain)
        ans_s_teardown = h.dns_probe_client_until(client_vm, s_domain, h.is_vip)
        assert h.is_vip(ans_s_teardown), (
            f"teardown: {s_domain} must be VIP-blocked again after removing the permit feed "
            f"(no whiteDB residue): {ans_s_teardown}"
        )
        assert not h.resolves_to(ans_s_teardown, STUB_DNS_A), (
            f"teardown: {s_domain} still resolving after removing the permit feed: {ans_s_teardown}"
        )

    finally:
        h.unblock_egress()
        h.reset(deployed_vm)
        # Clean up the local feed files we wrote directly to /var/db/pfblockerng/.
        deployed_vm.ssh("/bin/rm", "-f", block_feed_url, permit_feed_url)


# --------------------------------------------------------------------------- #
# Issue #538 — cron → pfb_update_check feed-change detector
#
# All other local-feed smoke cases drive feed reloads via the ``update``
# (Force Update) verb or the ``force_dnsbl_refetch`` shortcut (which manually
# touches ``{header}.update``), bypassing ``pfb_update_check`` entirely.
# These two tests exercise the REAL scheduled-cron path and pin BOTH branches
# of the detector:
#
#   CHANGED  — source mtime > .orig mtime → detector marks feed due → re-ingest
#   UNCHANGED — source mtime == .orig mtime → detector skips feed  → reuse/exists
#
# This gap caused the #533 misdiagnosis ("local edits never re-ingested").
# They ARE — but only on ``cron``, not on Force Update.
# --------------------------------------------------------------------------- #


def _feed_log_count(vm: SmokeVM, header: str, phrase: str, *, timeout: float = 30.0) -> int:
    """Count main-log lines for THIS feed (``[ <header> ]``) that also contain ``phrase``."""
    cmd = (
        f"/usr/bin/grep -F {shlex.quote(f'[ {header} ]')} {shlex.quote(h.PFB_LOG)} 2>/dev/null "
        f"| /usr/bin/grep -Fc {shlex.quote(phrase)}"
    )
    res = vm.ssh(cmd, timeout=timeout)
    try:
        return int(res.stdout.strip())
    except ValueError:
        return 0


def _bump_feed_mtime(
    vm: SmokeVM, feed_path: str, orig_path: str, *, advance: str | None = None, timeout: float = 30.0
) -> None:
    """Set ``feed_path``'s mtime relative to ``orig_path`` — entirely on the guest, timezone-free.

    ``touch -r`` copies ``orig``'s mtime onto the feed (→ equal). When ``advance`` is given (a
    FreeBSD ``touch -A [[hh]mm]SS`` offset, e.g. ``"0200"`` = +2 min), the feed mtime is then
    advanced by that amount (→ strictly later than ``.orig``). Relative ops only: an absolute
    ``touch -t`` built from the runner's local time would be re-interpreted in the GUEST's
    timezone, skewing the mtime when runner and guest timezones differ.
    """
    r = vm.ssh(f"/usr/bin/touch -r {shlex.quote(orig_path)} {shlex.quote(feed_path)}", timeout=timeout)
    if r.returncode != 0:
        raise RuntimeError(f"touch -r {orig_path} -> {feed_path} failed: rc={r.returncode} {r.stderr!r}")
    if advance is not None:
        a = vm.ssh(f"/usr/bin/touch -A {shlex.quote(advance)} {shlex.quote(feed_path)}", timeout=timeout)
        if a.returncode != 0:
            raise RuntimeError(f"touch -A {advance} {feed_path} failed: rc={a.returncode} {a.stderr!r}")


@pytest.mark.timeout(600)
def test_cron_detects_changed_local_feed(deployed_vm: SmokeVM, client_vm: SmokeVM) -> None:
    """Issue #538 guard: the scheduled cron path detects an in-place local-feed edit and re-ingests it.

    ADR-42 Phase 2: detection is now content-hash based (xxh128 sidecar), not mtime-based.
    The feed edit writes different bytes; the hash differs → re-ingest regardless of mtime.
    This pins the CHANGED branch of ``pfb_update_check`` (cron verb → hash change detected →
    ``{header}.update`` touched → feed re-downloaded). It is the production path the #533
    misdiagnosis missed, distinct from the Force/``force_dnsbl_refetch`` shortcut that all
    other local-feed smoke tests use.

    Scenario (BDD):
      Given the feed contains only ``dom_old`` (initial ingest via Force Update blocks it,
        and writes the .xxhash128 sidecar for the .orig);
        and ``dom_new`` is NOT on any feed (resolves via stub sentinel, not blocked);
      When the feed source is edited in-place to add ``dom_new`` (content changes, so the
        xxh128 hash differs from the sidecar baseline), pfb_reuse is OFF and
        pfb_dailystart matches the current guest hour (so the EveryDay feed is due),
        and the ``cron`` verb is run (NOT ``force_dnsbl_refetch``);
      Then ``dom_new`` becomes BLOCKED (detector re-ingested the edited feed),
        ``dom_old`` stays BLOCKED, and the main log gained a header-scoped
        "Downloading update" line for this feed during the cron run.
    """
    dom_old = h.unique_domain("cronchgold")
    dom_new = h.unique_domain("cronchgnew")
    header = "smokecronchg"
    feed_path: str | None = None

    try:
        h.unblock_egress()

        # GIVEN — write initial feed (dom_old only); ingest (a single updatednsbl creates the
        # .orig baseline + .xxhash128 sidecar + .txt and blocks dom_old).
        feed_path = h.write_local_feed(deployed_vm, "smoke_cronchg.txt", dom_old + "\n")
        spec = h.DnsblCase(aliasname="smokecronchg", feed_url=feed_path, header=header, mode=h.DnsblMode.VIP)
        h.inject(deployed_vm, spec)
        h.reload(deployed_vm, "updatednsbl")

        # BEFORE state: dom_old blocked, dom_new resolves via stub.
        h.flush_unbound_name(deployed_vm, dom_old)
        ans_old_before = h.dns_probe_client_until(client_vm, dom_old, h.is_vip)
        assert h.is_vip(ans_old_before), (
            f"BEFORE: {dom_old} must be VIP-blocked after initial ingest, got {ans_old_before}"
        )
        ans_new_before = h.dns_probe_client(client_vm, dom_new, "A")
        assert h.resolves_to(ans_new_before, STUB_DNS_A), (
            f"BEFORE: {dom_new} must resolve via stub (not yet listed), got {ans_new_before}"
        )
        assert not h.is_vip(ans_new_before), (
            f"BEFORE: {dom_new} must NOT be blocked before feed edit, got {ans_new_before}"
        )

        # WHEN — edit feed in-place (add dom_new).  Content changes → xxh128 hash differs
        # from the sidecar → cron will detect and re-ingest.  No mtime manipulation needed:
        # detection is hash-based, not mtime-based (ADR-42 Phase 2).
        h.write_local_feed(deployed_vm, "smoke_cronchg.txt", dom_old + "\n" + dom_new + "\n")

        # Pin pfb_reuse=off and dailystart=now (just before cron to dodge hour-rollover race).
        h.pin_cron_due(deployed_vm)

        # Capture baselines BEFORE the cron run: the per-feed header line (proves the detector
        # actually evaluated THIS feed) and the re-ingest marker.
        hdr_before = h.count_log_marker(deployed_vm, h.PFB_LOG, f"[ {header} ]")
        dl_before = _feed_log_count(deployed_vm, header, "Downloading update")

        # WHEN — run the genuine cron path (NOT force_dnsbl_refetch — that is the shortcut).
        h.reload(deployed_vm, "cron")

        # THEN (fast guard) — the cron actually evaluated this feed. If the EveryDay feed was not
        # due (e.g. the wall-clock hour rolled over between pin_cron_due and the cron), no
        # detector line appears; fail HERE with a clear reason instead of a 120s probe timeout.
        hdr_after = h.count_log_marker(deployed_vm, h.PFB_LOG, f"[ {header} ]")
        assert hdr_after > hdr_before, (
            f"cron did not evaluate [ {header} ] (before={hdr_before}, after={hdr_after}) — the "
            f"EveryDay feed was not due (hour rollover?), so this run proves nothing; re-run"
        )

        # THEN — dom_new becomes blocked (cron re-ingested the edited feed).
        h.flush_unbound_name(deployed_vm, dom_new)
        ans_new_after = h.dns_probe_client_until(client_vm, dom_new, h.is_vip, timeout=120.0)
        assert h.is_vip(ans_new_after), (
            f"AFTER cron: {dom_new} must be VIP-blocked (detector re-ingested edited feed), got {ans_new_after}"
        )
        # dom_old stays blocked (it was already listed).
        ans_old_after = h.dns_probe_client(client_vm, dom_old, "A")
        assert h.is_vip(ans_old_after), f"AFTER cron: {dom_old} must remain VIP-blocked, got {ans_old_after}"

        # Corroborate: detector fired — "Downloading update" count increased for this header.
        dl_after = _feed_log_count(deployed_vm, header, "Downloading update")
        assert dl_after > dl_before, (
            f"Expected a new '[ {header} ] ... Downloading update' line in {h.PFB_LOG} "
            f"after cron (before={dl_before}, after={dl_after}) — detector did not re-ingest"
        )

    finally:
        reset_exc = None
        try:
            h.reset(deployed_vm)
        except Exception as exc:  # noqa: BLE001
            reset_exc = exc
        if feed_path:
            deployed_vm.ssh("/bin/rm", "-f", feed_path)
        if reset_exc is not None:
            raise reset_exc


@pytest.mark.timeout(600)
def test_cron_skips_unchanged_local_feed(deployed_vm: SmokeVM, client_vm: SmokeVM) -> None:
    """Issue #538 guard: an unchanged local feed on a cron run is NOT re-parsed.

    ADR-42 Phase 2: detection is now content-hash based (xxh128 sidecar).  The source bytes
    are identical to the last-ingested .orig, so the hash matches the sidecar and the
    detector takes the "Update not required" path without re-ingesting.

    This pins the UNCHANGED branch of ``pfb_update_check``.  With nothing due, the cron
    takes the ``noupdates`` path, which SKIPS the sync feed-loop entirely — so the reuse is
    proven by the DETECTOR verdict ("Update not required"), NOT a sync-loop "exists" line.

    Scenario (BDD):
      Given the feed contains ``dom`` (initial ingest blocks it and writes the .xxhash128
        sidecar for the .orig);
      When no content change is made to the source, pfb_reuse is OFF and pfb_dailystart
        matches the current guest hour, and the ``cron`` verb runs;
      Then the detector logs a new "Update not required" verdict (hash matches sidecar),
        no "Downloading update" line appears for this header, and ``dom`` remains blocked.
    """
    dom = h.unique_domain("cronunchg")
    header = "smokecronunchg"
    feed_path: str | None = None

    try:
        h.unblock_egress()

        # GIVEN — write feed, ingest (a single updatednsbl creates the .orig + .xxhash128 sidecar).
        feed_path = h.write_local_feed(deployed_vm, "smoke_cronunchg.txt", dom + "\n")
        spec = h.DnsblCase(aliasname="smokecronunchg", feed_url=feed_path, header=header, mode=h.DnsblMode.VIP)
        h.inject(deployed_vm, spec)
        h.reload(deployed_vm, "updatednsbl")

        # BEFORE state: dom blocked.
        h.flush_unbound_name(deployed_vm, dom)
        ans_before = h.dns_probe_client_until(client_vm, dom, h.is_vip)
        assert h.is_vip(ans_before), f"BEFORE: {dom} must be VIP-blocked after initial ingest, got {ans_before}"

        # No content change — source bytes == .orig bytes → hash matches sidecar.
        # No mtime manipulation is needed: detection is hash-based (ADR-42 Phase 2).

        # Pin pfb_reuse=off and dailystart=now.
        pinned_hour = h.pin_cron_due(deployed_vm)

        # Capture baselines BEFORE cron. With an unchanged feed the cron takes the noupdates
        # path (sync feed-loop skipped), so the reliable positive signal is the DETECTOR verdict
        # "Update not required" — emitted by pfb_update_check, which runs BEFORE that dispatch.
        notreq_before = h.count_log_marker(deployed_vm, h.PFB_LOG, "Update not required")
        dl_before = _feed_log_count(deployed_vm, header, "Downloading update")

        # WHEN — cron.
        h.reload(deployed_vm, "cron")

        # THEN (fast guard) — the guest hour must still match the pinned hour. Unlike the
        # changed-feed sibling (test_cron_detects_changed_local_feed), this unchanged/noupdates
        # path logs no "[ header ]" marker to fast-guard on, so guard on the wall clock itself:
        # a rollover between pin_cron_due and this cron means the EveryDay feed was never due,
        # and the "no re-ingest" assertions below would prove nothing about the change detector.
        hour_after = h.guest_hour(deployed_vm)
        assert hour_after == pinned_hour, (
            f"guest hour rolled over between pin_cron_due ({pinned_hour}) and cron "
            f"({hour_after}) — the EveryDay feed was not due this run; this proves nothing "
            f"about the change detector, re-run"
        )

        # THEN — no new "Downloading update" (reuse held — feed not re-ingested).
        dl_after = _feed_log_count(deployed_vm, header, "Downloading update")
        assert dl_after == dl_before, (
            f"Expected NO new '[ {header} ] ... Downloading update' after unchanged cron "
            f"(before={dl_before}, after={dl_after}) — detector incorrectly re-ingested"
        )

        # THEN — the detector evaluated the due feed and saw no change (equal mtimes).
        notreq_after = h.count_log_marker(deployed_vm, h.PFB_LOG, "Update not required")
        assert notreq_after > notreq_before, (
            f"Expected a new 'Update not required' detector verdict after unchanged cron "
            f"(before={notreq_before}, after={notreq_after}) — reuse path not confirmed"
        )

        # THEN — dom remains blocked (feed was not cleared).
        ans_after = h.dns_probe_client(client_vm, dom, "A")
        assert h.is_vip(ans_after), f"AFTER unchanged cron: {dom} must remain VIP-blocked, got {ans_after}"

    finally:
        reset_exc = None
        try:
            h.reset(deployed_vm)
        except Exception as exc:  # noqa: BLE001
            reset_exc = exc
        if feed_path:
            deployed_vm.ssh("/bin/rm", "-f", feed_path)
        if reset_exc is not None:
            raise reset_exc


@pytest.mark.timeout(600)
def test_cron_skips_local_feed_with_bumped_mtime_but_same_content(deployed_vm: SmokeVM, client_vm: SmokeVM) -> None:
    """Local feed change detection: a bumped mtime with IDENTICAL content is NOT re-ingested.

    ADR-42 Phase 2: the old mtime-then-md5 two-step is replaced by a pure content-hash gate
    (xxh128 sidecar).  The source bytes are unchanged → the hash equals the sidecar → the
    detector takes "Update not required" regardless of mtime.

    The old "( mtime changed, content identical )" log marker no longer exists; the verdict
    is now the same "Update not required" path used by the no-change case.

    RED on pre-Phase-2 code: the old code compared mtimes first — if the mtime differed it
    would fall through to md5 confirmation and emit "mtime changed, content identical", which
    passed.  The same-second edge case (equal mtime, different content) was the blind spot.
    GREEN after Phase 2: the single hash path catches both cases consistently.

    Scenario (BDD):
      Given the feed contains ``dom`` (initial ingest blocks it and writes the .xxhash128
        sidecar; ``.orig`` bytes == source bytes);
      When the source mtime is bumped LATER than ``.orig`` WITHOUT changing content
        (``touch -r`` + ``touch -A``), pfb_reuse is OFF and pfb_dailystart matches the
        guest hour, and the ``cron`` verb runs;
      Then the detector logs a new "Update not required" verdict (hash matches sidecar),
        no "Downloading update" line appears for this header, and ``dom`` remains blocked.
    """
    dom = h.unique_domain("cronsame")
    header = "smokecronsame"
    feed_path: str | None = None

    try:
        h.unblock_egress()

        # GIVEN — write feed, ingest (updatednsbl creates the .orig + .xxhash128 sidecar).
        feed_path = h.write_local_feed(deployed_vm, "smoke_cronsame.txt", dom + "\n")
        spec = h.DnsblCase(aliasname="smokecronsame", feed_url=feed_path, header=header, mode=h.DnsblMode.VIP)
        h.inject(deployed_vm, spec)
        h.reload(deployed_vm, "updatednsbl")

        # BEFORE state: dom blocked.
        h.flush_unbound_name(deployed_vm, dom)
        ans_before = h.dns_probe_client_until(client_vm, dom, h.is_vip)
        assert h.is_vip(ans_before), f"BEFORE: {dom} must be VIP-blocked after initial ingest, got {ans_before}"

        # WHEN — bump source mtime LATER than .orig WITHOUT changing content (timezone-free:
        # copy orig's mtime onto source, then advance it by +120 s — no absolute touch -t).
        orig_path = f"{h.PFB_DBDIR}/dnsblorig/{header}.orig"
        _bump_feed_mtime(deployed_vm, feed_path, orig_path, advance="0200")

        # Pin pfb_reuse=off and dailystart=now (just before cron).
        pinned_hour = h.pin_cron_due(deployed_vm)
        notreq_before = h.count_log_marker(deployed_vm, h.PFB_LOG, "Update not required")
        dl_before = _feed_log_count(deployed_vm, header, "Downloading update")

        # WHEN — cron (the genuine detector path).
        h.reload(deployed_vm, "cron")

        # THEN (fast guard) — the guest hour must still match the pinned hour. This
        # unchanged-content path (like its `test_cron_skips_unchanged_local_feed` sibling) logs
        # no "[ header ]" marker to fast-guard on, so guard on the wall clock itself: a rollover
        # between pin_cron_due and this cron means the EveryDay feed was never due, and the
        # "Update not required" assertion below would prove nothing about the change detector.
        hour_after = h.guest_hour(deployed_vm)
        assert hour_after == pinned_hour, (
            f"guest hour rolled over between pin_cron_due ({pinned_hour}) and cron "
            f"({hour_after}) — the EveryDay feed was not due this run; this proves nothing "
            f"about the change detector, re-run"
        )

        # THEN — hash confirms no content change: "Update not required" appeared, no download.
        # (ADR-42 Phase 2: the old "mtime changed, content identical" marker no longer exists;
        # both mtime-equal and mtime-bumped-same-content cases share the same "Update not
        # required" path because the gate is purely hash-based.)
        notreq_after = h.count_log_marker(deployed_vm, h.PFB_LOG, "Update not required")
        assert notreq_after > notreq_before, (
            f"Expected a new 'Update not required' verdict after cron "
            f"(before={notreq_before}, after={notreq_after}) — hash gate did not confirm unchanged content"
        )
        dl_after = _feed_log_count(deployed_vm, header, "Downloading update")
        assert dl_after == dl_before, (
            f"Expected NO '[ {header} ] ... Downloading update' (content identical, hash unchanged) "
            f"(before={dl_before}, after={dl_after}) — feed was wrongly re-ingested"
        )

        # THEN — dom remains blocked (feed not cleared).
        ans_after = h.dns_probe_client(client_vm, dom, "A")
        assert h.is_vip(ans_after), f"AFTER cron: {dom} must remain VIP-blocked, got {ans_after}"

    finally:
        reset_exc = None
        try:
            h.reset(deployed_vm)
        except Exception as exc:  # noqa: BLE001
            reset_exc = exc
        if feed_path:
            deployed_vm.ssh("/bin/rm", "-f", feed_path)
        if reset_exc is not None:
            raise reset_exc


@pytest.mark.timeout(600)
def test_cron_detects_changed_local_feed_same_second(deployed_vm: SmokeVM, client_vm: SmokeVM) -> None:
    """ADR-42 Phase 2: a same-second content change (mtime indistinguishable) is detected.

    This is the blind spot that ADR-42 Phase 2 closes.  The old mtime gate compared
    whole-second timestamps: a content change written within the same second as the prior
    ingest produced EQUAL mtimes → the old code concluded "unchanged" and missed the
    re-ingest.  The new xxh128-sidecar gate compares bytes, so it catches the change even
    when mtime is forced to be identical.

    RED on pre-Phase-2 code: equal mtime → ``pfb_local_feed_changed`` returns FALSE →
    cron logs "Update not required" → ``dom_new`` is never blocked (assertion fails).
    GREEN after Phase 2: different bytes → different hash → "Update found" → re-ingest →
    ``dom_new`` becomes blocked.

    Scenario (BDD):
      Given the feed contains only ``dom_old`` (initial ingest blocks it and writes the
        .xxhash128 sidecar for the .orig);
        and ``dom_new`` is NOT blocked;
      When the source is rewritten with DIFFERENT content (add ``dom_new``) AND the source
        mtime is forced EQUAL to the ``.orig`` mtime (``touch -r`` — simulates same-second
        write), pfb_reuse is OFF and pfb_dailystart matches the guest hour, and the ``cron``
        verb is run;
      Then ``dom_new`` becomes BLOCKED (detector re-ingested despite equal mtime),
        ``dom_old`` stays BLOCKED, and a new "Downloading update" line appears for this header.
    """
    dom_old = h.unique_domain("cronsamesold")
    dom_new = h.unique_domain("cronsamesnew")
    header = "smokecronamess"
    feed_path: str | None = None

    try:
        h.unblock_egress()

        # GIVEN — write initial feed (dom_old only); ingest creates .orig + .xxhash128 sidecar.
        feed_path = h.write_local_feed(deployed_vm, "smoke_cronamess.txt", dom_old + "\n")
        spec = h.DnsblCase(aliasname="smokecronamess", feed_url=feed_path, header=header, mode=h.DnsblMode.VIP)
        h.inject(deployed_vm, spec)
        h.reload(deployed_vm, "updatednsbl")

        # BEFORE: dom_old blocked, dom_new resolves via stub.
        h.flush_unbound_name(deployed_vm, dom_old)
        ans_old_before = h.dns_probe_client_until(client_vm, dom_old, h.is_vip)
        assert h.is_vip(ans_old_before), (
            f"BEFORE: {dom_old} must be VIP-blocked after initial ingest, got {ans_old_before}"
        )
        ans_new_before = h.dns_probe_client(client_vm, dom_new, "A")
        assert not h.is_vip(ans_new_before), (
            f"BEFORE: {dom_new} must NOT be blocked before feed edit, got {ans_new_before}"
        )

        # WHEN — rewrite feed with NEW content (add dom_new) AND force source mtime to EQUAL
        # the .orig mtime (touch -r copies the .orig mtime onto the source file).
        # This simulates the same-second write: mtime is identical → old code would skip;
        # new code hashes the bytes and detects the change.
        orig_path = f"{h.PFB_DBDIR}/dnsblorig/{header}.orig"
        h.write_local_feed(deployed_vm, "smoke_cronamess.txt", dom_old + "\n" + dom_new + "\n")
        # Force source mtime = orig mtime — the defining condition for the blind spot.
        _bump_feed_mtime(deployed_vm, feed_path, orig_path)  # touch -r: source mtime := orig mtime

        # Pin pfb_reuse=off and dailystart=now.
        h.pin_cron_due(deployed_vm)

        hdr_before = h.count_log_marker(deployed_vm, h.PFB_LOG, f"[ {header} ]")
        dl_before = _feed_log_count(deployed_vm, header, "Downloading update")

        # WHEN — cron (genuine detector path).
        h.reload(deployed_vm, "cron")

        # Fast guard: cron actually evaluated this feed.
        hdr_after = h.count_log_marker(deployed_vm, h.PFB_LOG, f"[ {header} ]")
        assert hdr_after > hdr_before, (
            f"cron did not evaluate [ {header} ] (before={hdr_before}, after={hdr_after}) — "
            f"EveryDay feed not due (hour rollover?); re-run"
        )

        # THEN — dom_new becomes blocked (detector caught the same-second change).
        h.flush_unbound_name(deployed_vm, dom_new)
        ans_new_after = h.dns_probe_client_until(client_vm, dom_new, h.is_vip, timeout=120.0)
        assert h.is_vip(ans_new_after), (
            f"AFTER cron: {dom_new} must be VIP-blocked (same-second change detected by hash), "
            f"got {ans_new_after} — ADR-42 Phase 2 blind-spot guard"
        )
        ans_old_after = h.dns_probe_client(client_vm, dom_old, "A")
        assert h.is_vip(ans_old_after), f"AFTER cron: {dom_old} must remain VIP-blocked, got {ans_old_after}"

        # Corroborate: detector fired — "Downloading update" count increased.
        dl_after = _feed_log_count(deployed_vm, header, "Downloading update")
        assert dl_after > dl_before, (
            f"Expected a new '[ {header} ] ... Downloading update' line (same-second change detected) "
            f"(before={dl_before}, after={dl_after}) — hash gate did not trigger re-ingest"
        )

    finally:
        reset_exc = None
        try:
            h.reset(deployed_vm)
        except Exception as exc:  # noqa: BLE001
            reset_exc = exc
        if feed_path:
            deployed_vm.ssh("/bin/rm", "-f", feed_path)
        if reset_exc is not None:
            raise reset_exc


# --------------------------------------------------------------------------- #
# ADR-42 Phase 3 — conditional GET (ETag / If-None-Match → 304, and the
# Last-Modified / CURLOPT_TIMECONDITION fallback) over the live box.
#
# Five cases prove the reachable branches of pfb_update_check()'s remote-feed
# detector (the ETag path via pfb_conditional_get_decision(), plus the
# no-validator and Last-Modified-driven-304 paths that sit in front of it):
#
#   (a) unchanged feed + matching ETag → 304 → "304 not modified" → no re-ingest.
#   (b) changed feed + new ETag → 200 → body_hash != persisted → re-ingest.
#   (c) server emits NO validator at all (no ETag, no Last-Modified —
#       mock_feeds.disable_lastmod()) → the guest stores nothing, so every probe
#       is a plain GET and download + hash genuinely decides (same bytes →
#       "content unchanged" → no re-ingest). Distinct from (d): here there is no
#       stored validator to send in the first place.
#   (d) a stored Last-Modified validator exists but the server IGNORES the
#       conditional request and always answers 200 (identical bytes) →
#       body_hash == persisted → "content unchanged" → no re-ingest. Distinct
#       from (c): the guest DOES send a conditional header; the server just
#       doesn't honour it.
#   (e) a stored Last-Modified validator exists and the server DOES honour
#       If-Modified-Since (mock_feeds.enable_lastmod_304()) → 304 → "304 not
#       modified" → no re-ingest. Proves the CURLOPT_TIMECONDITION fallback
#       (no ETag) reaches an actual 304, not just the ETag/If-None-Match path
#       that (a) already covers.
#
# The mock server is extended with ETag support (enable_etag / set_content),
# a no-validator-at-all opt-out (disable_lastmod), and an IMS-aware 304
# responder (enable_lastmod_304). All cases use the cron verb — the real
# detector path.  These run live in Phase 5; they are correct by construction
# here.
# --------------------------------------------------------------------------- #


@pytest.mark.timeout(600)
def test_cron_304_skips_unchanged_remote_feed(
    deployed_vm: SmokeVM, client_vm: SmokeVM, mock_feeds: _MockFeedServer
) -> None:
    """ADR-42 Phase 3 (a): 304 from a conditional GET skips re-ingest of an unchanged remote feed.

    The primary Phase-3 win: the guest sends ``If-None-Match`` with the stored ETag; the
    server returns 304 (no body); the detector logs "304 not modified" and skips re-ingest.

    RED on pre-Phase-3 code: the old HEAD probe path logs "Remote timestamp: … Update not
    required" — the "304 not modified" marker is the Phase-3 proof that the new code path
    was taken; its absence would mean the old HEAD path is still running.

    Scenario (BDD):
      Given the remote DNSBL feed is loaded (Force Update writes .orig + .xxhash128 + .etag);
        ``dom`` is VIP-blocked;
      When feed content is UNCHANGED (same ETag on the server), pfb_reuse is OFF and
        pfb_dailystart matches now, and the ``cron`` verb is run;
      Then the detector logs "304 not modified", does NOT log "Downloading update",
        and ``dom`` remains blocked.
    """
    dom = h.unique_domain("p3304skip")
    header = "smokep3304skip"
    etag = '"p3-etag-v1"'
    feed_name = "p3_304_skip.txt"

    try:
        h.unblock_egress()

        # Register the feed WITH an ETag so the guest can store a validator.
        mock_feeds.register(feed_name, dom + "\n")
        mock_feeds.enable_etag(feed_name, etag)
        feed_url = mock_feeds.feed_url(feed_name)

        # GIVEN — inject + Force Update to establish the .orig baseline + ingest the body.
        spec = h.DnsblCase(aliasname="smokep3304skip", feed_url=feed_url, header=header, mode=h.DnsblMode.VIP)
        h.inject(deployed_vm, spec)
        h.reload(deployed_vm, "updatednsbl")

        # BEFORE: dom is VIP-blocked.
        h.flush_unbound_name(deployed_vm, dom)
        ans_before = h.dns_probe_client_until(client_vm, dom, h.is_vip)
        assert h.is_vip(ans_before), f"BEFORE: {dom} must be VIP-blocked after initial ingest, got {ans_before}"

        # The cron detector prefixes the verdict with the feed header, so the marker
        # below is scoped by header and verdict.
        h.pin_cron_due(deployed_vm)
        not_mod_marker = h.detector_status_marker(header, "( 304 not modified )")
        not_mod_before = h.count_log_marker(deployed_vm, h.PFB_LOG, not_mod_marker)
        dl_before = _feed_log_count(deployed_vm, header, "Downloading update")

        # WHEN — the conditional-GET 304 needs the validator PERSISTED first, then READ on a
        # later probe. The validator is written by the cron detector (pfb_update_check) on a
        # 200, NOT by the updatednsbl Force ingest above, and only once a {header}.orig baseline
        # exists — so the store-then-read can span a couple of cron passes. Run cron until
        # the marker appears (the #572 fix aligned the read base to {header}.orig), capped so
        # a genuine failure still surfaces.
        for _pass in range(4):
            # issue #2489: pin_cron_due() reserves a ONE-SHOT pending occurrence, which the
            # first pass consumes. Without re-arming, passes 2..4 return at "No Updates
            # required." before reaching pfb_update_check(), so the validator this loop
            # depends on is stored and never read. The production tick reserves each
            # scheduled occurrence the same way, one per pass.
            if _pass:
                h.pin_cron_due(deployed_vm)
            h.reload(deployed_vm, "cron")
            if h.count_log_marker(deployed_vm, h.PFB_LOG, not_mod_marker) > not_mod_before:
                break

        # THEN — "[ header ] ( 304 not modified )" appeared within the cap (Phase-3 code-path
        # proof, now also proving the SAME cron pass evaluated THIS feed's header).
        not_mod_after = h.count_log_marker(deployed_vm, h.PFB_LOG, not_mod_marker)
        assert not_mod_after > not_mod_before, (
            f"Expected {not_mod_marker!r} (Phase-3 conditional GET proof) within 4 cron "
            f"passes (before={not_mod_before}, after={not_mod_after}) — 304 path not taken"
        )

        # THEN — no re-ingest.
        dl_after = _feed_log_count(deployed_vm, header, "Downloading update")
        assert dl_after == dl_before, (
            f"Expected NO '[ {header} ] ... Downloading update' after 304 "
            f"(before={dl_before}, after={dl_after}) — detector incorrectly re-ingested"
        )

        # THEN — dom remains blocked.
        ans_after = h.dns_probe_client(client_vm, dom, "A")
        assert h.is_vip(ans_after), f"AFTER 304 cron: {dom} must remain VIP-blocked, got {ans_after}"

    finally:
        reset_exc = None
        try:
            h.reset(deployed_vm)
        except Exception as exc:  # noqa: BLE001
            reset_exc = exc
        if reset_exc is not None:
            raise reset_exc


@pytest.mark.timeout(600)
def test_cron_200_reingest_changed_remote_feed(
    deployed_vm: SmokeVM, client_vm: SmokeVM, mock_feeds: _MockFeedServer
) -> None:
    """ADR-42 Phase 3 (b): a changed remote feed (new ETag → 200) is re-ingested via hash compare.

    The server bumps the ETag when the body changes; the guest's stored ETag no longer
    matches → 200 with new body → body_hash != persisted_hash → re-ingest.

    RED on a broken impl that only checks status (304/200) without the hash compare:
    it would still re-ingest on 200, but the "content changed" marker proves the Phase-3
    hash-comparison path is taken (not the old "md5 changed" path).

    Scenario (BDD):
      Given the remote DNSBL feed is loaded (``dom_old`` blocked; .etag=etag_v1);
        ``dom_new`` is NOT blocked;
      When the feed body is updated + ETag bumped to etag_v2, pfb_reuse is OFF and
        pfb_dailystart matches now, and the ``cron`` verb runs;
      Then the detector logs "content changed" + "Downloading update",
        ``dom_new`` becomes VIP-blocked, and ``dom_old`` remains blocked.
    """
    dom_old = h.unique_domain("p3200old")
    dom_new = h.unique_domain("p3200new")
    header = "smokep3200chg"
    etag_v1 = '"p3-etag-v1"'
    etag_v2 = '"p3-etag-v2"'
    feed_name = "p3_200_changed.txt"

    try:
        h.unblock_egress()

        mock_feeds.register(feed_name, dom_old + "\n")
        mock_feeds.enable_etag(feed_name, etag_v1)
        feed_url = mock_feeds.feed_url(feed_name)

        spec = h.DnsblCase(aliasname="smokep3200chg", feed_url=feed_url, header=header, mode=h.DnsblMode.VIP)
        h.inject(deployed_vm, spec)
        h.reload(deployed_vm, "updatednsbl")

        # BEFORE: dom_old blocked, dom_new resolves.
        h.flush_unbound_name(deployed_vm, dom_old)
        ans_old_before = h.dns_probe_client_until(client_vm, dom_old, h.is_vip)
        assert h.is_vip(ans_old_before), f"BEFORE: {dom_old} must be VIP-blocked, got {ans_old_before}"
        ans_new_before = h.dns_probe_client(client_vm, dom_new, "A")
        assert not h.is_vip(ans_new_before), f"BEFORE: {dom_new} must NOT be blocked, got {ans_new_before}"

        # WHEN — update body + bump ETag on the server.
        mock_feeds.set_content(feed_name, dom_old + "\n" + dom_new + "\n", etag=etag_v2)

        h.pin_cron_due(deployed_vm)
        dl_before = _feed_log_count(deployed_vm, header, "Downloading update")
        # "[ header ] ( content changed )" is the Phase-3 hash-compare verdict itself (not
        # merely its re-ingest side effect), header-scoped by #811 — the docstring's RED
        # premise (a status-only impl that skips the hash compare) would still log
        # "Downloading update" without ever logging this, and a header-scoped count also
        # proves THIS feed (not a sibling) was the one evaluated.
        chg_marker = h.detector_status_marker(header, "( content changed )")
        chg_before = h.count_log_marker(deployed_vm, h.PFB_LOG, chg_marker)

        h.reload(deployed_vm, "cron")

        # THEN — "Downloading update" appeared (feed was re-ingested).
        dl_after = _feed_log_count(deployed_vm, header, "Downloading update")
        assert dl_after > dl_before, (
            f"Expected '[ {header} ] ... Downloading update' after changed-feed cron "
            f"(before={dl_before}, after={dl_after}) — detector did not detect the change"
        )

        # THEN — the hash-compare verdict itself fired: "[ header ] ( content changed )".
        chg_after = h.count_log_marker(deployed_vm, h.PFB_LOG, chg_marker)
        assert chg_after > chg_before, (
            f"Expected {chg_marker!r} verdict after the ETag bump + body change "
            f"(before={chg_before}, after={chg_after}) — hash-compare path not taken"
        )

        # THEN — dom_new becomes blocked.
        h.flush_unbound_name(deployed_vm, dom_new)
        ans_new_after = h.dns_probe_client_until(client_vm, dom_new, h.is_vip, timeout=120.0)
        assert h.is_vip(ans_new_after), (
            f"AFTER cron: {dom_new} must be VIP-blocked (changed feed re-ingested), got {ans_new_after}"
        )
        ans_old_after = h.dns_probe_client(client_vm, dom_old, "A")
        assert h.is_vip(ans_old_after), f"AFTER cron: {dom_old} must remain VIP-blocked, got {ans_old_after}"

    finally:
        reset_exc = None
        try:
            h.reset(deployed_vm)
        except Exception as exc:  # noqa: BLE001
            reset_exc = exc
        if reset_exc is not None:
            raise reset_exc


@pytest.mark.timeout(600)
def test_cron_no_validator_download_hash_decides(
    deployed_vm: SmokeVM, client_vm: SmokeVM, mock_feeds: _MockFeedServer
) -> None:
    """ADR-42 Phase 3 (c): server with NO validator at all → download + hash decides (same bytes → no re-ingest).

    The mock is opted OUT of its default Last-Modified header via ``disable_lastmod()``, so
    this feed genuinely emits no ETag AND no Last-Modified — the guest never stores a ``.etag``
    or ``.lastmod`` sidecar for it, and every probe is an unconditional GET. The detector
    downloads the full body and compares the xxh128 hash. Identical bytes → "content unchanged"
    → no re-ingest. This proves the last-resort path never stalls even with zero validators to
    fall back on — distinct from the sibling "spurious 200" case below, where a validator IS
    stored but the server ignores the conditional request it produces.

    RED on a broken impl that skips the download when no validator is stored: no
    "content unchanged" marker would ever appear for a no-validator server feed.

    Scenario (BDD):
      Given the remote DNSBL feed is loaded with NO validator at all (server emits neither
        ETag nor Last-Modified); ``dom`` is VIP-blocked;
      When feed content is UNCHANGED, pfb_reuse is OFF, pfb_dailystart matches now,
        and the ``cron`` verb runs;
      Then the detector downloads the full body, logs "content unchanged",
        does NOT log "Downloading update", and ``dom`` remains blocked.
    """
    dom = h.unique_domain("p3noetag")
    header = "smokep3noetag"
    feed_name = "p3_no_etag.txt"

    try:
        h.unblock_egress()

        # Register WITHOUT ETag, and opt out of the mock's default Last-Modified header too:
        # the server emits NO validator whatsoever (no conditional support), so the guest
        # never has anything to send back and the download+hash path is the only option.
        mock_feeds.register(feed_name, dom + "\n")
        mock_feeds.disable_lastmod(feed_name)
        feed_url = mock_feeds.feed_url(feed_name)

        spec = h.DnsblCase(aliasname="smokep3noetag", feed_url=feed_url, header=header, mode=h.DnsblMode.VIP)
        h.inject(deployed_vm, spec)
        h.reload(deployed_vm, "updatednsbl")

        # BEFORE: dom is blocked.
        h.flush_unbound_name(deployed_vm, dom)
        ans_before = h.dns_probe_client_until(client_vm, dom, h.is_vip)
        assert h.is_vip(ans_before), f"BEFORE: {dom} must be VIP-blocked after initial ingest, got {ans_before}"

        # Feed unchanged; no If-None-Match will be sent (no stored ETag). #811 header-scopes
        # the "( content unchanged )" verdict line, so the marker below proves BOTH the
        # verdict and that THIS feed's header was evaluated.
        h.pin_cron_due(deployed_vm)
        not_unch_marker = h.detector_status_marker(header, "( content unchanged )")
        not_unch_before = h.count_log_marker(deployed_vm, h.PFB_LOG, not_unch_marker)
        dl_before = _feed_log_count(deployed_vm, header, "Downloading update")

        h.reload(deployed_vm, "cron")

        # THEN — "[ header ] ( content unchanged )" appeared (full download + hash comparison
        # taken for THIS feed).
        not_unch_after = h.count_log_marker(deployed_vm, h.PFB_LOG, not_unch_marker)
        assert not_unch_after > not_unch_before, (
            f"Expected {not_unch_marker!r} log line after no-validator cron "
            f"(before={not_unch_before}, after={not_unch_after}) — download+hash path not taken"
        )

        # THEN — no re-ingest (identical bytes).
        dl_after = _feed_log_count(deployed_vm, header, "Downloading update")
        assert dl_after == dl_before, (
            f"Expected NO '[ {header} ] ... Downloading update' (same bytes) "
            f"(before={dl_before}, after={dl_after}) — wrongly re-ingested"
        )

        # THEN — dom remains blocked.
        ans_after = h.dns_probe_client(client_vm, dom, "A")
        assert h.is_vip(ans_after), f"AFTER no-validator cron: {dom} must remain VIP-blocked, got {ans_after}"

    finally:
        reset_exc = None
        try:
            h.reset(deployed_vm)
        except Exception as exc:  # noqa: BLE001
            reset_exc = exc
        if reset_exc is not None:
            raise reset_exc


@pytest.mark.timeout(600)
def test_cron_spurious_200_same_bytes_no_reingest(
    deployed_vm: SmokeVM, client_vm: SmokeVM, mock_feeds: _MockFeedServer
) -> None:
    """ADR-42 Phase 3 (d) — §2 contract #5: a spurious 200 with identical bytes is NOT re-ingested.

    Unlike case (c), this feed keeps the mock's DEFAULT Last-Modified header (no
    ``disable_lastmod()`` call), so the guest DOES store a ``.lastmod`` validator and DOES send
    a conditional request on the next probe — the server just ignores it and always answers
    200.  body_hash == persisted_hash → "content unchanged" → no re-ingest.  This proves
    contract #5: the hash compare, not the raw status code, is what decides.

    RED on a broken impl that treats every 200 as changed: it would log "Downloading update"
    and re-ingest on every cron run — the "content unchanged" marker proves the hash
    comparison is applied and wins over the raw status code.

    Scenario (BDD):
      Given the remote IP feed is loaded (``member_ip`` is in the pf table); server has no ETag;
      When feed bytes are UNCHANGED, pfb_reuse is OFF, pfb_dailystart matches now,
        and the ``cron`` verb runs (server returns plain 200 — no If-None-Match sent);
      Then the detector logs "content unchanged", does NOT log "Downloading update",
        and the pf table still contains ``member_ip``.
    """
    member_ip = "198.51.100.1"
    feed_name = "p3_spurious_200.txt"
    header = "smokep3spur200"

    try:
        h.unblock_egress()

        # Register WITHOUT ETag → server always returns 200 (no conditional support).
        mock_feeds.register(feed_name, member_ip + "\n")
        feed_url = mock_feeds.feed_url(feed_name)

        spec = h.IpCase(aliasname="smokep3spur200", feed_url=feed_url, header=header, family="v4")
        # pfBlockerNG logs IP-feed activity under the family-suffixed alias name
        # ([ <aliasname>_<family> ]), NOT the row header — so the per-feed log marker
        # is aliasname_family, not the bare header.
        feed_marker = f"{spec.aliasname}_{spec.family}"
        with h.CaseContext(deployed_vm, spec):
            members_before = h.pfctl_table_members(deployed_vm, spec.alias)
            assert h.member_present(members_before, member_ip), (
                f"BEFORE: {member_ip} must be in {spec.alias}: {members_before}"
            )

            # Pin cron due (inside CaseContext so config is active). #811 header-scopes the
            # "( content unchanged )" verdict, so the marker below proves both the verdict
            # and that THIS feed's marker (aliasname_family) was the one evaluated.
            h.pin_cron_due(deployed_vm)
            not_unch_marker = h.detector_status_marker(feed_marker, "( content unchanged )")
            not_unch_before = h.count_log_marker(deployed_vm, h.PFB_LOG, not_unch_marker)
            dl_before = _feed_log_count(deployed_vm, feed_marker, "Downloading update")

            # WHEN — cron; server returns 200 (no ETag → no If-None-Match → plain 200).
            h.reload(deployed_vm, "cron")
            h.apply_filter_sync(deployed_vm)

            # THEN — "[ feed_marker ] ( content unchanged )" appeared (spurious 200 detected
            # by hash, for THIS feed).
            not_unch_after = h.count_log_marker(deployed_vm, h.PFB_LOG, not_unch_marker)
            assert not_unch_after > not_unch_before, (
                f"Expected {not_unch_marker!r} after spurious-200 cron "
                f"(before={not_unch_before}, after={not_unch_after}) — hash compare not applied"
            )

            # THEN — no re-ingest.
            dl_after = _feed_log_count(deployed_vm, feed_marker, "Downloading update")
            assert dl_after == dl_before, (
                f"Expected NO '[ {feed_marker} ] ... Downloading update' (identical bytes) "
                f"(before={dl_before}, after={dl_after}) — spurious 200 triggered wrong re-ingest"
            )

            # THEN — pf table still contains member_ip.
            members_after = h.pfctl_table_members(deployed_vm, spec.alias)
            assert h.member_present(members_after, member_ip), (
                f"AFTER spurious-200 cron: {member_ip} must still be in {spec.alias}: {members_after}"
            )

    finally:
        reset_exc = None
        try:
            h.reset(deployed_vm)
        except Exception as exc:  # noqa: BLE001
            reset_exc = exc
        if reset_exc is not None:
            raise reset_exc


@pytest.mark.timeout(600)
def test_cron_lastmod_304_skips_unchanged_feed(
    deployed_vm: SmokeVM, client_vm: SmokeVM, mock_feeds: _MockFeedServer
) -> None:
    """ADR-42 Phase 3 (e): a Last-Modified-driven 304 (no ETag) skips re-ingest via CURLOPT_TIMECONDITION.

    Case (a) already proves the ETag/If-None-Match half of the conditional-GET contract.  This
    feed carries NO ETag, so once a ``.lastmod`` validator is stored, the detector's fallback
    branch (``CURLOPT_TIMECONDITION`` / ``CURLOPT_TIMEVALUE`` — pfblockerng.inc ~8818-8821) is
    what sends the conditional request; ``mock_feeds.enable_lastmod_304()`` makes the server
    actually honour ``If-Modified-Since`` and answer 304, distinct from case (d) where a
    Last-Modified validator exists but the server ignores it. Without this test, the
    CURLOPT_TIMECONDITION branch could regress to always-200 and nothing would notice — every
    other case either uses ETag or never reaches an actual 304.

    RED on a broken/regressed CURLOPT_TIMECONDITION wire-up (e.g. the fallback branch silently
    stops sending a conditional header, or the value sent isn't recognised by an IMS-aware
    server): the mock's ``enable_lastmod_304()`` responder would never see a satisfying
    If-Modified-Since, so it always answers 200 — no "304 not modified" marker would appear
    within the cron-pass cap.

    Scenario (BDD):
      Given the remote DNSBL feed is loaded with NO ETag (server does not emit one);
        ``dom`` is VIP-blocked;
      When feed content is UNCHANGED, the server honours If-Modified-Since with a real 304,
        pfb_reuse is OFF, pfb_dailystart matches now, and the ``cron`` verb runs;
      Then the detector logs "304 not modified", does NOT log "Downloading update",
        and ``dom`` remains blocked.
    """
    dom = h.unique_domain("p3lm304")
    header = "smokep3lm304"
    feed_name = "p3_lastmod_304.txt"

    try:
        h.unblock_egress()

        # Register WITHOUT ETag — only the mock's default Last-Modified header is emitted —
        # and opt this name into the RFC-conformant If-Modified-Since responder so the guest's
        # stored .lastmod validator actually earns a 304 (not just a header that's ignored, as
        # in case (d) above).
        mock_feeds.register(feed_name, dom + "\n")
        mock_feeds.enable_lastmod_304(feed_name)
        feed_url = mock_feeds.feed_url(feed_name)

        # GIVEN — inject + Force Update to establish the .orig baseline + ingest the body.
        spec = h.DnsblCase(aliasname="smokep3lm304", feed_url=feed_url, header=header, mode=h.DnsblMode.VIP)
        h.inject(deployed_vm, spec)
        h.reload(deployed_vm, "updatednsbl")

        # BEFORE: dom is VIP-blocked.
        h.flush_unbound_name(deployed_vm, dom)
        ans_before = h.dns_probe_client_until(client_vm, dom, h.is_vip)
        assert h.is_vip(ans_before), f"BEFORE: {dom} must be VIP-blocked after initial ingest, got {ans_before}"

        # Feed unchanged; the stored Last-Modified validator still matches. #811 header-scopes
        # the "( 304 not modified )" verdict line itself, so the marker below is scoped by
        # header AND verdict — no separate global count + "fast guard" needed.
        h.pin_cron_due(deployed_vm)
        not_mod_marker = h.detector_status_marker(header, "( 304 not modified )")
        not_mod_before = h.count_log_marker(deployed_vm, h.PFB_LOG, not_mod_marker)
        dl_before = _feed_log_count(deployed_vm, header, "Downloading update")

        # WHEN — same store-then-read span as case (a): the .lastmod validator is written by
        # the cron detector (pfb_update_check) on its first 200, not by the updatednsbl Force
        # ingest above. Run cron until the marker appears, capped so a genuine failure still
        # surfaces.
        for _pass in range(4):
            # issue #2489: pin_cron_due() reserves a ONE-SHOT pending occurrence, which the
            # first pass consumes. Without re-arming, passes 2..4 return at "No Updates
            # required." before reaching pfb_update_check(), so the validator this loop
            # depends on is stored and never read. The production tick reserves each
            # scheduled occurrence the same way, one per pass.
            if _pass:
                h.pin_cron_due(deployed_vm)
            h.reload(deployed_vm, "cron")
            if h.count_log_marker(deployed_vm, h.PFB_LOG, not_mod_marker) > not_mod_before:
                break

        # THEN — "[ header ] ( 304 not modified )" appeared within the cap
        # (CURLOPT_TIMECONDITION proof, now also proving THIS feed's header was evaluated).
        not_mod_after = h.count_log_marker(deployed_vm, h.PFB_LOG, not_mod_marker)
        assert not_mod_after > not_mod_before, (
            f"Expected {not_mod_marker!r} (Last-Modified/CURLOPT_TIMECONDITION 304 proof) "
            f"within 4 cron passes (before={not_mod_before}, after={not_mod_after}) — "
            f"the no-ETag conditional-GET fallback did not reach a 304"
        )

        # THEN — no re-ingest.
        dl_after = _feed_log_count(deployed_vm, header, "Downloading update")
        assert dl_after == dl_before, (
            f"Expected NO '[ {header} ] ... Downloading update' after 304 "
            f"(before={dl_before}, after={dl_after}) — detector incorrectly re-ingested"
        )

        # THEN — dom remains blocked.
        ans_after = h.dns_probe_client(client_vm, dom, "A")
        assert h.is_vip(ans_after), f"AFTER 304 cron: {dom} must remain VIP-blocked, got {ans_after}"

    finally:
        reset_exc = None
        try:
            h.reset(deployed_vm)
        except Exception as exc:  # noqa: BLE001
            reset_exc = exc
        if reset_exc is not None:
            raise reset_exc


# --------------------------------------------------------------------------- #
# ADR-44 — MIME normalisation: compressed feed decompression end-to-end.
#
# pfb_download() runs `/usr/bin/file -b --mime-type` on the downloaded bytes and
# routes them to the matching decompressor:
#   application/zip      → bsdtar -xOf
#   application/gzip     → gunzip -c
#   application/x-bzip2  → bzip2 -dkc
#
# ADR-44's pfb_mime_normalise() leaves these three MIME types unchanged (the
# gzip/bzip guard).  The gzip and bzip2 cases are REGRESSION GUARDS: if the
# guard were removed and normalise() rewrote application/gzip or
# application/x-bzip2 to application/zip, bsdtar would be called on an
# incompatible byte-stream and load zero entries — the member_present assertion
# below would fail, catching the regression.
#
# Archives are built in-memory (stdlib) and served via mock_feeds.register()
# (bytes pass through verbatim, Content-Type text/plain, no Content-Encoding —
# so pfBlockerNG's curl receives raw archive bytes and must detect them itself).
# --------------------------------------------------------------------------- #

_ADR44_BODY = "203.0.113.7\n198.51.100.23\n"
_ADR44_MEMBER = "203.0.113.7"

# ADR-45 structural-integrity smoke fixtures live in the committed corpus
# (fixtures/archive_*; see fixtures/README.md). The member below is the IP the
# recoverable octet-stream ZIP (archive_octet_recover.zip) extracts to — distinct
# from ADR-44's for isolation.
_ADR45_MEMBER = "203.0.113.11"


def _fixture_bytes(name: str) -> bytes:
    """Raw bytes of a committed fixture — the same file the mock serves via feed_url(name).

    Lets the ADR-45 octet-stream guards probe file(1) on EXACTLY the bytes the guest
    fetches, so the guard and the served feed can never drift apart.
    """
    return (FIXTURES_DIR / name).read_bytes()


def _box_mime_type(vm: SmokeVM, data: bytes, remote_tmp: str = "/tmp/adr45_mime_probe.bin", flag: str = "-b") -> str:
    """Upload ``data`` to ``remote_tmp`` on the guest via stdin, return ``file(1)`` MIME type.

    Used by the ADR-45 octet-stream guard tests to verify that the specific bytes
    actually trigger ``application/octet-stream`` on the box's ``file(1)`` before
    asserting the recovery / rejection behaviour.  Pass ``flag="-bZ"`` for the
    decompress-and-look verdict (the ADR-48 compressed-peek guard).  Cleans up
    the temp file afterwards.
    """
    # Binary upload: subprocess.run without text=True accepts bytes as input.
    subprocess.run(vm.ssh_argv("tee", remote_tmp), input=data, capture_output=True, timeout=30.0, check=False)
    result = vm.ssh("file", flag, "--mime-type", remote_tmp)
    vm.ssh("rm", "-f", remote_tmp)
    return result.stdout.strip()


def _box_cmd_rc(vm: SmokeVM, data: bytes, remote_tmp: str, cmd: str) -> int:
    """Upload ``data`` to ``remote_tmp`` via stdin, run the sh command ``cmd``, return its exit code.

    Same upload discipline as ``_box_mime_type`` -- probes the EXACT served bytes rather
    than a local guess. ``cmd`` is a full POSIX-sh command line referencing ``remote_tmp``.
    Cleans up the temp file afterwards.
    """
    subprocess.run(vm.ssh_argv("tee", remote_tmp), input=data, capture_output=True, timeout=30.0, check=False)
    try:
        result = vm.ssh(cmd)
    finally:
        vm.ssh("rm", "-f", remote_tmp)
    return result.returncode


@pytest.mark.timeout(120)  # full update + targeted reload + file-detect/decompress/re-validate > the 30s cap on slow CI
def test_zip_feed_imports(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """ADR-44: a zip-compressed IP feed downloads, decompresses, and loads (application/zip path).

    Scenario: the mock serves raw zip bytes (no Content-Encoding, Content-Type text/plain).
    pfb_download() must detect application/zip via ``/usr/bin/file -b --mime-type`` and
    route to ``bsdtar -xOf``, producing the plain IP list.

    Given the alias table does not exist (before-state: the feed is not yet configured).
    When the case injects + Force-Updates over the HTTP zip feed,
    Then 203.0.113.7 (a member of the inner plain-text list) is present in the pf table
      and a rule references the alias — proving the zip archive was fetched, file-detected,
      and correctly decompressed end-to-end.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("list.txt", _ADR44_BODY)
    zp = buf.getvalue()
    feed_url = mock_feeds.register("adr44_zip.zip", zp)
    spec = h.IpCase(aliasname="adr44zip", feed_url=feed_url, header="adr44zip", family="v4")

    # Given — the alias does not exist yet (assert BEFORE-state).
    assert spec.alias not in h.pfctl_tables(deployed_vm), f"{spec.alias} present before the zip feed was ever loaded"

    with h.CaseContext(deployed_vm, spec):
        # When — Force Update downloads + file-detects application/zip + bsdtar decompresses.
        members = h.pfctl_table_members(deployed_vm, spec.alias)
        # Then — the member IP loaded (fails if zip bytes were misrouted to the wrong decompressor).
        assert h.member_present(members, _ADR44_MEMBER), (
            f"expected {_ADR44_MEMBER!r} in {spec.alias} after zip decompression, got: {members}"
        )
        assert h.pfctl_rule_has_alias(deployed_vm, spec.alias), (
            f"no loaded pf rule references {spec.alias} after zip feed import"
        )


@pytest.mark.timeout(120)  # full update + targeted reload + file-detect/decompress/re-validate > the 30s cap on slow CI
def test_gzip_feed_imports(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """ADR-44 REGRESSION GUARD: a gzip-compressed IP feed downloads, decompresses, and loads.

    Scenario: the mock serves raw gzip bytes.  pfb_download() must detect application/gzip
    via ``/usr/bin/file -b --mime-type`` and route to ``gunzip -c``.

    REGRESSION: if pfb_mime_normalise() ever rewrites application/gzip → application/zip,
    bsdtar would be called on a gzip byte-stream and load zero entries — the member_present
    assertion below catches that regression.

    Given the alias table does not exist (before-state: the feed is not yet configured).
    When the case injects + Force-Updates over the HTTP gzip feed,
    Then 203.0.113.7 is present in the pf table and a rule references the alias —
      proving the gzip normalise() guard left application/gzip unchanged.
    """
    gz = gzip.compress(_ADR44_BODY.encode(), mtime=0)
    feed_url = mock_feeds.register("adr44_gz.gz", gz)
    spec = h.IpCase(aliasname="adr44gz", feed_url=feed_url, header="adr44gz", family="v4")

    # Given — the alias does not exist yet (assert BEFORE-state).
    assert spec.alias not in h.pfctl_tables(deployed_vm), f"{spec.alias} present before the gzip feed was ever loaded"

    with h.CaseContext(deployed_vm, spec):
        # When — Force Update downloads + file-detects application/gzip + gunzip decompresses.
        members = h.pfctl_table_members(deployed_vm, spec.alias)
        # Then — the member IP loaded (fails if gzip was mis-normalised to application/zip).
        assert h.member_present(members, _ADR44_MEMBER), (
            f"expected {_ADR44_MEMBER!r} in {spec.alias} after gzip decompression, "
            f"got: {members} — "
            f"(regression: pfb_mime_normalise() may have rewritten application/gzip → application/zip, "
            f"routing gzip bytes to bsdtar and loading zero entries)"
        )
        assert h.pfctl_rule_has_alias(deployed_vm, spec.alias), (
            f"no loaded pf rule references {spec.alias} after gzip feed import"
        )


@pytest.mark.timeout(120)  # full update + targeted reload + file-detect/decompress/re-validate > the 30s cap on slow CI
def test_bzip2_feed_imports(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """ADR-44 REGRESSION GUARD: a bzip2-compressed IP feed downloads, decompresses, and loads.

    Scenario: the mock serves raw bzip2 bytes.  pfb_download() must detect application/x-bzip2
    via ``/usr/bin/file -b --mime-type`` and route to ``bzip2 -dkc``.

    REGRESSION: if pfb_mime_normalise() ever rewrites application/x-bzip2 → application/zip,
    bsdtar would be called on a bzip2 byte-stream and load zero entries — the member_present
    assertion below catches that regression.

    Given the alias table does not exist (before-state: the feed is not yet configured).
    When the case injects + Force-Updates over the HTTP bzip2 feed,
    Then 203.0.113.7 is present in the pf table and a rule references the alias —
      proving the bzip2 normalise() guard left application/x-bzip2 unchanged.
    """
    bz = bz2.compress(_ADR44_BODY.encode())
    feed_url = mock_feeds.register("adr44_bz.bz2", bz)
    spec = h.IpCase(aliasname="adr44bz", feed_url=feed_url, header="adr44bz", family="v4")

    # Given — the alias does not exist yet (assert BEFORE-state).
    assert spec.alias not in h.pfctl_tables(deployed_vm), f"{spec.alias} present before the bzip2 feed was ever loaded"

    with h.CaseContext(deployed_vm, spec):
        # When — Force Update downloads + file-detects application/x-bzip2 + bzip2 decompresses.
        members = h.pfctl_table_members(deployed_vm, spec.alias)
        # Then — the member IP loaded (fails if bzip2 was mis-normalised to application/zip).
        assert h.member_present(members, _ADR44_MEMBER), (
            f"expected {_ADR44_MEMBER!r} in {spec.alias} after bzip2 decompression, "
            f"got: {members} — "
            f"(regression: pfb_mime_normalise() may have rewritten application/x-bzip2 → application/zip, "
            f"routing bzip2 bytes to bsdtar and loading zero entries)"
        )
        assert h.pfctl_rule_has_alias(deployed_vm, spec.alias), (
            f"no loaded pf rule references {spec.alias} after bzip2 feed import"
        )


# --------------------------------------------------------------------------- #
# ADR-45 structural-integrity smoke — corrupt-archive-rejected + octet-stream
# --------------------------------------------------------------------------- #
# Paired design (one corrupt + one healthy per format) so green proves the probe
# is a REAL branch, not an always-reject path:
#   corrupt zip   ←→ test_zip_feed_imports  (healthy valid pair)
#   corrupt gzip  ←→ test_gzip_feed_imports (healthy valid pair)
#   corrupt bzip2 ←→ test_bzip2_feed_imports (healthy valid pair)
# --------------------------------------------------------------------------- #


@pytest.mark.timeout(120)
def test_corrupt_zip_rejected(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """ADR-45: a corrupt ZIP feed is rejected by the structural probe.

    Scenario: the mock serves a ZIP whose first local-file-header signature
    (``PK\\x03\\x04``) is clobbered but whose central directory + EOCD are intact.
    file(1) still reports ``application/zip`` (it reads the EOCD), so the feed
    enters the ZIP branch; ``bsdtar -tf`` then fails to parse the broken local
    header and exits non-zero. pfb_validate_archive() catches that; pfb_download()
    result success flag is FALSE; the alias is never created.

    NB: a *tail-truncated* ZIP is NOT a reliable corruption — libarchive streams
    local headers without needing the EOCD, so ``tar -tf`` on the first half still
    lists+extracts the entry (verified on the FreeBSD smoke box). Corrupting the
    leading local-header signature is what makes the probe reject.

    Paired with ``test_zip_feed_imports`` (healthy ZIP imports) to prove the probe
    is a real branch, not an always-reject path: if the probe were always-reject,
    the healthy case would also fail; it does not.

    Given the alias does not exist (the feed has never been successfully loaded).
    When the case injects + Force-Updates over the corrupt ZIP bytes,
    Then the alias remains absent — the structural probe rejected the corrupt archive
      before extraction and pfb_download() result success flag was FALSE.
    """
    # FreeBSD-verified corpus fixture (fixtures/archive_corrupt.zip; see
    # fixtures/README.md "Archive corpus"): leading PK\x03\x04 signature clobbered,
    # EOCD intact — file(1) → application/zip (ZIP branch), bsdtar -tf then rejects.
    feed_url = mock_feeds.feed_url("archive_corrupt.zip")
    spec = h.IpCase(aliasname="adr45czp", feed_url=feed_url, header="adr45czp", family="v4")

    # Given — alias absent before any load attempt.
    assert spec.alias not in h.pfctl_tables(deployed_vm), (
        f"{spec.alias} present before corrupt-zip feed — unexpected before-state"
    )

    with h.CaseContext(deployed_vm, spec):
        # When — Force Update fetches corrupt ZIP; structural probe (bsdtar) fails.
        # Then — alias still absent; pfb_download result success flag was FALSE; table never created.
        tables_after = h.pfctl_tables(deployed_vm)
        assert spec.alias not in tables_after, (
            f"expected {spec.alias!r} absent after corrupt ZIP (structural probe must reject), "
            f"found it present — tables: {tables_after}"
        )


@pytest.mark.timeout(120)
def test_corrupt_gzip_rejected(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """ADR-45: a corrupt (truncated) gzip feed is rejected by the structural probe.

    Scenario: the corpus fixture is a valid gzip stream truncated past its header —
    the deflate payload and CRC/ISIZE trailer are gone, so ``gunzip -t`` exits
    non-zero. pfb_validate_archive() catches the failure; pfb_download() result success flag is
    FALSE; the alias is never created. (Unlike ZIP, a truncated gzip IS reliably
    corrupt to the codec — gzip is a single stream with no streamable directory.)

    Paired with ``test_gzip_feed_imports`` (healthy gzip imports) to prove the probe
    is a real branch.

    Given the alias does not exist (the feed has never been successfully loaded).
    When the case injects + Force-Updates over the truncated gzip bytes,
    Then the alias remains absent — the structural probe rejected the corrupt archive.
    """
    # FreeBSD-verified corpus fixture (fixtures/archive_corrupt.gz; see README):
    # file(1) → application/gzip (gzip branch), gunzip -t rejects the truncated stream.
    feed_url = mock_feeds.feed_url("archive_corrupt.gz")
    spec = h.IpCase(aliasname="adr45cgz", feed_url=feed_url, header="adr45cgz", family="v4")

    # Given — alias absent before any load attempt.
    assert spec.alias not in h.pfctl_tables(deployed_vm), (
        f"{spec.alias} present before corrupt-gzip feed — unexpected before-state"
    )

    with h.CaseContext(deployed_vm, spec):
        # When — Force Update fetches corrupt gzip; structural probe (bsdtar) fails.
        # Then — alias still absent.
        tables_after = h.pfctl_tables(deployed_vm)
        assert spec.alias not in tables_after, (
            f"expected {spec.alias!r} absent after corrupt gzip (structural probe must reject), "
            f"found it present — tables: {tables_after}"
        )


@pytest.mark.timeout(120)
def test_corrupt_bzip2_rejected(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """ADR-45: a corrupt (truncated) bzip2 feed is rejected by the structural probe.

    Scenario: the corpus fixture is a valid bzip2 stream truncated mid-block, so
    ``bzip2 -t`` exits non-zero. pfb_validate_archive() rejects it; pfb_download()
    result success flag is FALSE; the alias is never created.

    Paired with ``test_bzip2_feed_imports`` (healthy bzip2 imports) to prove the probe
    is a real branch.

    Given the alias does not exist (the feed has never been successfully loaded).
    When the case injects + Force-Updates over the truncated bzip2 bytes,
    Then the alias remains absent — the structural probe rejected the corrupt archive.
    """
    # FreeBSD-verified corpus fixture (fixtures/archive_corrupt.bz2; see README):
    # file(1) → application/x-bzip2 (bzip2 branch), bzip2 -t rejects the truncated stream.
    feed_url = mock_feeds.feed_url("archive_corrupt.bz2")
    spec = h.IpCase(aliasname="adr45cbz", feed_url=feed_url, header="adr45cbz", family="v4")

    # Given — alias absent before any load attempt.
    assert spec.alias not in h.pfctl_tables(deployed_vm), (
        f"{spec.alias} present before corrupt-bzip2 feed — unexpected before-state"
    )

    with h.CaseContext(deployed_vm, spec):
        # When — Force Update fetches corrupt bzip2; structural probe (bsdtar) fails.
        # Then — alias still absent.
        tables_after = h.pfctl_tables(deployed_vm)
        assert spec.alias not in tables_after, (
            f"expected {spec.alias!r} absent after corrupt bzip2 (structural probe must reject), "
            f"found it present — tables: {tables_after}"
        )


@pytest.mark.timeout(120)
def test_octet_stream_zip_recovered(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """ADR-45 / #581 fix: a valid ZIP that file(1) mislabels as octet-stream is recovered
    and imported via the Phase-3 structural-recovery path.

    Real-world analogue: the Cisco Umbrella / Popularity List ``top-1m.csv.zip`` (and
    similar self-extracting ZIPs with a short SFX stub) causes ``file(1)`` to report
    ``application/octet-stream`` rather than ``application/zip``.  Before ADR-45,
    pfb_filter() would reject it outright; after, pfb_octet_recover_type() probes
    the bytes with bsdtar and recovers the correct type.

    Fixture: a valid ZIP with a short text SFX-stub-like preamble prepended before the
    local file header (``PK\\x03\\x04``).  bsdtar uses backward EOCD scanning + SFX-offset
    correction and still extracts it; FreeBSD ``file(1)`` (libmagic) cannot classify the
    text-then-binary stream and reports ``application/octet-stream`` (verified on the
    CE 2.8 smoke box).  NB: a raw NUL/control-byte prefix is NOT usable here — FreeBSD
    libmagic misreads ``\\x00\\x01\\x02..`` as ``image/x-tga`` (a non-allow-listed type
    that the gate rejects outright, never reaching octet-stream recovery), whereas the
    same bytes read as octet-stream on macOS/Linux.  The text preamble avoids that.

    On-box guard: if the box's ``file(1)`` does NOT report ``application/octet-stream``
    for these bytes (e.g. it instead detects the embedded ZIP), the recovery path is not
    exercised — the feed still imports via the normal ``application/zip`` branch and the
    test logs the observed verdict rather than failing.

    Given the alias does not exist.
    When the case injects + Force-Updates over the junk-prefixed ZIP,
    Then 203.0.113.11 is present in the pf table — the archive was recovered and loaded.
    """
    # FreeBSD-verified corpus fixture (fixtures/archive_octet_recover.zip; see README):
    # a valid ZIP behind a text SFX-stub preamble → FreeBSD file(1) octet-stream (recovery
    # exercised), bsdtar still extracts the trailing ZIP.
    fixture = "archive_octet_recover.zip"
    feed_url = mock_feeds.feed_url(fixture)
    spec = h.IpCase(aliasname="adr45orec", feed_url=feed_url, header="adr45orec", family="v4")

    # On-box MIME guard: probe file(1) on EXACTLY the bytes the guest fetches.
    box_mime = _box_mime_type(deployed_vm, _fixture_bytes(fixture))
    recovery_exercised = box_mime == "application/octet-stream"
    if recovery_exercised:
        print(
            f"\n[adr45] on-box file(1) reports {box_mime!r} for junk-prefixed ZIP "
            f"— octet-stream recovery path WILL be exercised"
        )
    else:
        print(
            f"\n[adr45] on-box file(1) reports {box_mime!r} for junk-prefixed ZIP "
            f"(not octet-stream); recovery path not exercised — feed imports via normal zip branch"
        )

    # Given — alias absent before any load attempt.
    assert spec.alias not in h.pfctl_tables(deployed_vm), (
        f"{spec.alias} present before octet-stream-recovery feed — unexpected before-state"
    )

    with h.CaseContext(deployed_vm, spec):
        # When — Force Update fetches the junk-prefixed ZIP.
        members = h.pfctl_table_members(deployed_vm, spec.alias)
        # Then — member is present regardless of which branch handled it.
        # (When recovery_exercised: proves octet-stream was recovered to application/zip and imported.
        #  When not: proves the normal zip branch handled it — still a valid import assertion.)
        assert h.member_present(members, _ADR45_MEMBER), (
            f"expected {_ADR45_MEMBER!r} in {spec.alias} after junk-prefixed ZIP, got: {members} "
            f"(box file(1) reported {box_mime!r}; recovery_exercised={recovery_exercised})"
        )
        assert h.pfctl_rule_has_alias(deployed_vm, spec.alias), (
            f"no loaded pf rule references {spec.alias} after octet-stream ZIP recovery"
        )


@pytest.mark.timeout(120)
def test_junk_octet_stream_rejected(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """ADR-45 / ADR §7: a genuine junk blob that file(1) reports as octet-stream is rejected.

    This is the MUST-ACCOMPANY counterpart to ``test_octet_stream_zip_recovered`` —
    together they pin BOTH branches of the recovery gate (ADR §3 positive-ID-only rule):

    - Recovery case: octet-stream + valid archive  → IMPORTED (recovered to application/zip).
    - This case:     octet-stream + junk blob       → REJECTED (no structural probe passes).

    ADR §7 explicitly states: "a genuinely-unknown octet-stream (random binary / HTML page)
    is ever accepted" is a REJECT criterion.  pfb_octet_recover_type() returns NULL when
    no archive type passes bsdtar; pfb_filter() then calls unlink_if_exists + returns FALSE.

    Fixture: NUL + control bytes (\\x00\\x01\\x02\\x03, repeated) — reported as
    ``application/octet-stream`` by file(1) on FreeBSD (verified on the CE 2.8 smoke box),
    macOS, and Linux.  On-box guard: if the box's file(1) does NOT report octet-stream, the
    test is skipped (inconclusive — the reject branch for octet-stream is not triggered).

    Given the alias does not exist.
    When the case injects + Force-Updates over the junk blob,
    Then the alias remains absent — no structural probe passed; the blob was rejected.
    """
    # FreeBSD-verified corpus fixture (fixtures/archive_junk_octet.bin; see README):
    # pure NUL/ctrl bytes → file(1) octet-stream, no archive magic → every probe fails.
    fixture = "archive_junk_octet.bin"
    feed_url = mock_feeds.feed_url(fixture)
    spec = h.IpCase(aliasname="adr45junk", feed_url=feed_url, header="adr45junk", family="v4")

    # On-box MIME guard: the junk-rejected branch only applies when file(1) sees octet-stream.
    box_mime = _box_mime_type(deployed_vm, _fixture_bytes(fixture))
    if box_mime != "application/octet-stream":
        pytest.skip(
            f"junk blob produced {box_mime!r} on this box (not application/octet-stream); "
            f"the octet-stream reject branch is not exercised — test inconclusive"
        )

    # Given — alias absent before any load attempt.
    assert spec.alias not in h.pfctl_tables(deployed_vm), (
        f"{spec.alias} present before junk-blob feed — unexpected before-state"
    )

    with h.CaseContext(deployed_vm, spec):
        # When — Force Update fetches the junk blob; all structural probes fail.
        # Then — alias remains absent (ADR §7: junk octet-stream must never be accepted).
        tables_after = h.pfctl_tables(deployed_vm)
        assert spec.alias not in tables_after, (
            f"expected {spec.alias!r} absent after junk octet-stream blob "
            f"(ADR §7: recovery must not blanket-accept application/octet-stream), "
            f"found it present — tables: {tables_after}"
        )


# --------------------------------------------------------------------------- #
# ADR-48: canonical 'pfb_validate: REJECT' log line per wired download-
# validation stage. Phases 1-2 landed pfb_validate_log_line() /
# pfb_validate_log() and wired every LIVE reject site through it (see
# RESULTS/01_Results.txt, RESULTS/02_Results.txt for the exact rendered
# templates these tests grep). Before Phase 2, pfb_download() logged an
# ad-hoc, per-site message with no common shape and no "pfb_validate: REJECT"
# substring anywhere -- so every assertion below FAILS on pre-Phase-2 code
# (the marker cannot exist) and PASSES post-Phase-2. Delta-based (count
# BEFORE vs AFTER each case's own Force Update, computed INSIDE its
# CaseContext block) so a test never rides another test's leftover log lines
# -- self-encapsulated per the CLAUDE.md ordering-independence mandate.
# --------------------------------------------------------------------------- #


def _recent_validate_lines(vm: SmokeVM, limit: int = 5) -> str:
    """Return up to the last ``limit`` 'pfb_validate:' lines from the pfB log.

    Diagnostic-only, called ONLY from inside a failing branch below (never
    unconditionally in an ``assert`` message, which Python would evaluate even
    on the passing path) -- a bare count tells you a line was missing, not
    what WAS actually logged instead. Feeds the CLAUDE.md expected-vs-actual
    mandate: the failure message shows the REAL log excerpt, not just a number.
    """
    text = h.read_log_file(vm, h.PFB_LOG)
    lines = [ln for ln in text.splitlines() if "pfb_validate:" in ln]
    return "\n".join(lines[-limit:]) if lines else "(no 'pfb_validate:' line found in the log)"


# --------------------------------------------------------------------------- #
# issue #2658 — the ingest size ceilings, proved against the appliance itself.
#
# The shipped ceilings are deliberately generous (gigabytes), so tripping them
# with real bytes is not something a smoke VM can afford. What the appliance —
# and only the appliance — can answer is whether the two MECHANISMS the ceilings
# rest on actually work there: does FreeBSD's /bin/sh honour the ulimit prefix and
# surface the kill as a nonzero status, and does the appliance's libcurl enforce
# its maximum-file-size option. Each case pairs that live probe with proof that
# the deployed package is wired to the same mechanism.
# --------------------------------------------------------------------------- #

_PFB_INC = "/usr/local/pkg/pfblockerng/pfblockerng.inc"


def _shipped_define(name: str) -> str:
    """The verbatim ``define('<name>', <value>);`` line from the repo's own source.

    Asserting the box carries THIS line — rather than re-typing the number here —
    proves the deployed package is the one under test without duplicating the
    constant into the test. Numeric and single-quoted string values both match.
    """
    source = (FIXTURES_DIR.parent.parent.parent / "src/usr/local/pkg/pfblockerng/pfblockerng.inc").read_text()
    match = re.search(rf"^define\('{re.escape(name)}', (?:\d+|'[^']*')\);$", source, re.MULTILINE)
    assert match is not None, f"{name} is not defined in the repo source"
    return match.group(0)


@pytest.mark.timeout(120)
def test_extraction_ceiling_stops_an_oversized_write(deployed_vm: SmokeVM) -> None:
    """issue #2658: the extraction ceiling really stops a writing child on FreeBSD.

    Every archive extraction now runs behind ``ulimit -f`` so a small archive that
    expands to gigabytes is killed by the kernel instead of filling the staging
    filesystem. Whether that holds is a property of the appliance's shell and
    kernel, not of PHP: FreeBSD's /bin/sh must accept the prefix, the kernel must
    raise SIGXFSZ at the limit, and the shell must report the kill as the nonzero
    status the extraction gates already reject.

    Given a two-block ceiling and a child asked to write one MiB
    When the wrapped command runs on the appliance
    Then the child is killed at the ceiling — the status is nonzero and the file on
      disk is a couple of KiB, not the MiB that was requested — and the deployed
      package carries the shipped ceiling and runs its extractions under it.
    """
    target = "/tmp/pfb2658_extract_probe"
    deployed_vm.ssh("rm", "-f", target)
    probe = deployed_vm.ssh(
        f"{{ ulimit -f 2 || exit 1; /bin/dd if=/dev/zero of={target} bs=1024 count=1024; }} 2>/dev/null; "
        f"echo rc=$?; /usr/bin/stat -f %z {target}"
    )
    deployed_vm.ssh("rm", "-f", target)
    out = probe.stdout

    rc_line = next((ln for ln in out.splitlines() if ln.startswith("rc=")), "")
    size_line = out.strip().splitlines()[-1] if out.strip() else ""
    assert rc_line == "rc=153", (
        f"expected the SIGXFSZ exit status (128+25) the cap note keys on, got {rc_line!r} "
        f"— full probe output: {out!r} {probe.stderr!r}"
    )
    assert size_line.isdigit() and int(size_line) < 1024 * 1024, (
        f"the ceiling must truncate the write, not merely report on it — wrote {size_line!r} bytes"
    )

    ceiling = _shipped_define("PFB_EXTRACT_MAX_BLOCKS")
    shipped = deployed_vm.ssh("grep", "-F", "-c", ceiling, _PFB_INC)
    assert shipped.stdout.strip() == "1", (
        f"the deployed package does not carry {ceiling!r} — grep said {shipped.stdout!r}"
    )
    wiring = deployed_vm.ssh("grep", "-F", "-c", "exec(pfb_extract_cmd(", _PFB_INC)
    assert wiring.stdout.strip().isdigit() and int(wiring.stdout.strip()) > 0, (
        f"the deployed package runs no extraction under the ceiling — grep said {wiring.stdout!r}"
    )


def _probe_flags(line: str) -> set[str]:
    """The file flags in one probe line, minus the ones FreeBSD sets itself.

    `uarch` (UF_ARCHIVE) is maintained by the kernel on every newly written file,
    so its presence is not a restoration and must not read as one — the live run
    that taught us this reported `flags=[uarch]` on a correctly flagged extract.
    """
    raw = line.split("flags=[", 1)[1].split("]", 1)[0] if "flags=[" in line else ""
    return {flag for flag in raw.split(",") if flag} - {"uarch"}


@pytest.mark.timeout(120)
def test_extraction_refuses_archive_supplied_metadata(deployed_vm: SmokeVM) -> None:
    """issue #2659: the appliance's own bsdtar drops what the archive claims.

    Extraction runs as ROOT on the appliance, which is the only privilege level
    where the whole class is visible: an unprivileged run cannot chown, keeps no
    setuid bit and restores no file flags, so off-appliance suites can only pin
    the argv and probe the vectors their tar and uid can express. Here the box
    answers the question directly — its tar, its kernel, its root.

    Given an archive whose member claims a foreign owner, a setuid mode, an
      extended attribute and an immutable file flag (ACLs are out of the probe's
      reach: FreeBSD needs the filesystem mounted with ACLs enabled to author
      one, so --no-acls is pinned by the flag-set assertion rather than here)
    When the appliance extracts it twice as root, once with the shipped flag set
      and once without
    Then the unflagged extraction carries that metadata onto disk — the live
      before-state this ticket exists for — the flagged one carries none of it,
      and the deployed package carries the flag set on every disk-writing
      extraction and on none of the stdout ones.
    """
    flags = _shipped_define("PFB_TAR_EXTRACT_FLAGS")
    flag_argv = flags.split("'")[3]
    # NOT /tmp: pfSense mounts it as tmpfs, which cannot hold file flags at all
    # ("chflags: Operation not supported"), so a fixture built there could not
    # claim the vector this case exists to refuse. /root sits on the same
    # filesystem as the real staging parents under /var/db and /usr/local/share.
    work = "/root/pfb2659_metadata_probe"
    # `stat -f %Sp` renders the mode as ls does, so the setuid bit reads as `rws`
    # whichever sub-field specifier carries it; `%Sf` is the file flags; lsextattr
    # lists attribute NAMES, so an empty list means none survived.
    report = (
        'r() { printf "%s uid=%s mode=%s flags=[%s] xattr=[%s]\\n" "$1" '
        '"$(/usr/bin/stat -f %u "$2")" "$(/usr/bin/stat -f %Sp "$2")" '
        '"$(/usr/bin/stat -f %Sf "$2")" '
        '"$(/usr/sbin/lsextattr -q user "$2" 2>/dev/null | tr -d " \\t\\n")"; };'
    )
    probe = deployed_vm.ssh(
        f"W={work}; {report} "
        "/bin/chflags -R 0 $W 2>/dev/null; /bin/rm -rf $W; /bin/mkdir -p $W/build && "
        'printf "203.0.113.11\\n" > $W/build/member.dat && '
        "/usr/sbin/chown 12345:12345 $W/build/member.dat && "
        # chown AFTER chmod would need FreeBSD's "unless the caller is the
        # super-user" carve-out to keep the setuid bit; ordering it first needs
        # no carve-out at all.
        "/bin/chmod 4755 $W/build/member.dat || exit 90; "
        # Both are filesystem-dependent, so neither may abort the probe -- but a
        # vector the fixture never carried cannot prove its own refusal, so the
        # assertions below require the fixture line to show it, and any failure
        # to author one is captured as a labelled line rather than discarded.
        "/usr/sbin/setextattr user pfb2659 carried $W/build/member.dat 2>&1 | "
        "/usr/bin/sed 's/^/authoring setextattr: /'; "
        "/bin/chflags uchg $W/build/member.dat 2>&1 | /usr/bin/sed 's/^/authoring chflags: /'; "
        '/sbin/mount -p | /usr/bin/awk \'$2 == "/" {print "authoring rootfs: " $3}\'; '
        "r fixture $W/build/member.dat; "
        "/usr/bin/tar -cf $W/foreign.tar -C $W/build member.dat || exit 91; "
        "/bin/chflags 0 $W/build/member.dat 2>/dev/null; "
        "/bin/mkdir $W/control $W/shipped || exit 92; "
        "/usr/bin/tar -xf $W/foreign.tar -C $W/control; echo control_rc=$?; "
        f"/usr/bin/tar -xf $W/foreign.tar {flag_argv} -C $W/shipped; echo shipped_rc=$?; "
        "r control $W/control/member.dat; r shipped $W/shipped/member.dat; "
        "/usr/bin/tar --version; "
        # The flagged extraction's mode is the archive's masked by the extracting
        # process's umask, so record the umask that governs it on the appliance.
        'printf "umask sh=%s\\n" "$(umask)"; '
        "/usr/local/bin/php -r 'printf(\"umask php=%04o\\n\", umask());' 2>/dev/null; "
        "/usr/bin/grep -E '^[[:space:]]*:umask=' /etc/login.conf | /usr/bin/head -2; "
        "/usr/bin/grep -i umask /root/.cshrc 2>/dev/null; /usr/bin/true"
    )
    deployed_vm.ssh(f"/bin/chflags -R 0 {work} 2>/dev/null; /bin/rm -rf {work}")

    lines = dict(
        (ln.split(" ", 1)[0], ln.split(" ", 1)[1])
        for ln in probe.stdout.splitlines()
        if ln.startswith(("fixture ", "control ", "shipped "))
    )
    codes = [ln for ln in probe.stdout.splitlines() if "_rc=" in ln]
    assert set(lines) == {"fixture", "control", "shipped"}, (
        f"the probe did not report all three files — stdout {probe.stdout!r} stderr {probe.stderr!r}"
    )
    # The flagged run's exit status is also the appliance's answer on whether its
    # tar accepts the shipped flag set at all.
    assert codes == ["control_rc=0", "shipped_rc=0"], (
        f"both extractions must succeed on the appliance's tar, including with the shipped flag set; "
        f"got {codes!r} — stdout {probe.stdout!r} stderr {probe.stderr!r}"
    )

    fixture, control, shipped = lines["fixture"], lines["control"], lines["shipped"]
    assert "uid=12345" in control and "rws" in control, (
        f"the unflagged extraction must carry the archive's owner and setuid mode for this case to mean "
        f"anything — appliance reported control {control!r} from fixture {fixture!r}"
    )
    fixture_flags = _probe_flags(fixture)
    authoring = [ln for ln in probe.stdout.splitlines() if ln.startswith("authoring ")]
    assert "pfb2659" in fixture, (
        f"the fixture must carry an extended attribute for its refusal to mean anything — appliance "
        f"reported fixture {fixture!r}, authoring {authoring!r}"
    )
    assert "pfb2659" in control, (
        f"the appliance's tar did not restore the extended attribute the fixture carried, so this "
        f"vector proves nothing here — fixture {fixture!r}, control {control!r}"
    )
    assert "pfb2659" not in shipped, (
        f"the flagged extraction restored the extended attribute — fixture {fixture!r}, "
        f"control {control!r}, shipped {shipped!r}"
    )
    # The file-flag vector is the one the appliance's own filesystem may refuse to
    # author. Exercise it when the fixture carried it; when it did not, require the
    # captured authoring diagnostic that says why, so the gap is auditable instead
    # of a negative nothing could ever have failed.
    if fixture_flags:
        assert fixture_flags <= _probe_flags(control), (
            f"the appliance's tar did not restore the file flag the fixture carried, so this vector "
            f"proves nothing here — fixture {fixture!r}, control {control!r}"
        )
    else:
        assert any(ln.startswith("authoring chflags: ") or ln.startswith("authoring rootfs: ") for ln in authoring), (
            f"the fixture carried no file flag and the probe captured no reason — fixture {fixture!r}, "
            f"authoring {authoring!r}, stderr {probe.stderr!r}"
        )
    assert "uid=0" in shipped, f"the flagged extraction must own its output: {shipped!r}"
    assert "rws" not in shipped and "rwx" in shipped, (
        f"the flagged extraction must drop the setuid bit and keep an ordinary mode: {shipped!r}"
    )
    # --no-same-permissions hands the mode to the extracting process's umask, so a
    # umask with read bits set would make published feed members unreadable to
    # anything but root. That assumption is environmental, so the box states it.
    # Both readings are login-context: the ssh /bin/sh child and a php child of it.
    # pfb_download() runs from cron or php-fpm, which take their umask from rc
    # rather than from a login class, so this is a proxy for that context -- a
    # narrow one, since FreeBSD's default is 022 for both.
    umasks = dict(re.findall(r"^umask (sh|php)=(\S+)$", probe.stdout, re.MULTILINE))
    assert set(umasks) == {"sh", "php"}, (
        f"the probe did not report both umasks — captured {umasks!r}, stdout {probe.stdout!r}"
    )
    for source, value in sorted(umasks.items()):
        assert int(value, 8) & 0o055 == 0, (
            f"the extracting process's umask ({source}={value}) would strip read and execute bits from "
            f"published feed members, which the flag set now leaves to the umask — shipped {shipped!r}"
        )
    assert not (_probe_flags(shipped) & (fixture_flags | _probe_flags(control))), (
        f"the flagged extraction restored an archive-supplied file flag — fixture {fixture!r}, "
        f"control {control!r}, shipped {shipped!r}"
    )
    assert "xattr=[]" in shipped, (
        f"the flagged extraction restored an extended attribute — fixture {fixture!r}, "
        f"control {control!r}, shipped {shipped!r}"
    )

    deployed = deployed_vm.ssh("grep", "-F", "-c", flags, _PFB_INC)
    assert deployed.stdout.strip() == "1", (
        f"the deployed package does not carry {flags!r} — grep said {deployed.stdout!r}"
    )
    disk_writing = deployed_vm.ssh(f"/usr/bin/grep -c -e 'tar -x[a-z]*f.*PFB_TAR_EXTRACT_FLAGS' {_PFB_INC}")
    assert disk_writing.stdout.strip() == "5", (
        f"the deployed package must flag all five disk-writing extractions — grep said {disk_writing.stdout!r}"
    )
    stdout_sites = deployed_vm.ssh(f"/usr/bin/grep -c -e 'tar -xOf.*PFB_TAR_EXTRACT_FLAGS' {_PFB_INC}")
    assert stdout_sites.stdout.strip() == "0", (
        f"the deployed package must leave the stdout extractions unflagged — grep said {stdout_sites.stdout!r}"
    )


@pytest.mark.timeout(120)
def test_download_ceiling_refuses_an_oversized_body(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """issue #2658: the appliance's own ext/curl enforces the maximum-file-size option.

    The download ceiling is only worth setting if the libcurl the appliance ships
    acts on it; the option's documented behaviour differs by version, which is why
    the ticket asks for it to be probed on the box rather than assumed. This drives
    the appliance's ext/curl — the same extension pfb_download() uses — against the
    mock feed with the ceiling lowered to a handful of bytes, and asserts it refuses
    with error 63: the code the reject branch keys on and the code the shipped error
    table already names.

    The no-Content-Length (mid-transfer) shape is covered off-appliance by
    ``tests/php/DownloadSizeRefusalTest``, which drives the real pfb_download()
    against a streaming fixture server; the mock feed server here always declares a
    length, so this case pins the appliance-specific half.

    Given a real feed body served over HTTP and a ceiling far below it
    When the appliance's ext/curl fetches it with that ceiling
    Then it refuses with "maximum file size exceeded" (63) rather than writing the
      body out, and the deployed package sets that same option for every feed.
    """
    feed_url = mock_feeds.feed_url("ip_plain_cidr.txt")
    snippet = (
        f"$c = curl_init({feed_url!r});"
        " curl_setopt($c, CURLOPT_MAXFILESIZE_LARGE, 16);"
        " curl_setopt($c, CURLOPT_RETURNTRANSFER, TRUE);"
        " curl_exec($c);"
        ' echo "errno=" . curl_errno($c) . "\n";'
    )
    probe = deployed_vm.ssh("/usr/local/bin/php", "-r", snippet)

    assert "errno=63" in probe.stdout, (
        "the appliance's ext/curl did not refuse an over-large body with error 63 "
        f"— probe output: {probe.stdout!r} {probe.stderr!r}"
    )

    ceiling = _shipped_define("PFB_DOWNLOAD_MAX_BYTES")
    shipped = deployed_vm.ssh("grep", "-F", "-c", ceiling, _PFB_INC)
    assert shipped.stdout.strip() == "1", (
        f"the deployed package does not carry {ceiling!r} — grep said {shipped.stdout!r}"
    )
    wiring = deployed_vm.ssh("grep", "-F", "-c", "CURLOPT_MAXFILESIZE_LARGE => PFB_DOWNLOAD_MAX_BYTES", _PFB_INC)
    assert wiring.stdout.strip() == "1", (
        f"the deployed package does not set the download ceiling — grep said {wiring.stdout!r}"
    )


@pytest.mark.timeout(120)
def test_validate_log_structural_reject_line(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """ADR-48 P3: a structural-probe reject emits the canonical stage=structural line.

    Reuses the FreeBSD-verified ADR-45 corpus fixture (fixtures/archive_corrupt.gz;
    see fixtures/README.md "Archive corpus") -- a truncated gzip whose on-box
    file(1) verdict is the already-confirmed ``application/gzip``, so the
    rendered ``detected=`` value here is known without a fresh on-box probe.
    ``detected=`` is ``"{file_type} " . basename($file_download)``
    (RESULTS/02_Results.txt), and ``$file_download``'s basename is always
    ``{header}_v4.raw`` -- the package suffixes the on-box feed header with the
    address family (``_v4``/``_v6``), and pfb_download() builds
    ``$file_dwn = "{pfborig}/{header}"`` then appends ``.raw`` -- fully
    deterministic from the header + family we choose (proven live: the first
    fan-out logged ``feed=adr48stc_v4 ... adr48stc_v4.raw`` while this marker
    grepped the unsuffixed header and counted 0).

    Before ADR-48 Phase 2, this branch logged an ad-hoc "Corrupt or unreadable
    {type} archive"-style message via pfb_logger() directly, with no
    "pfb_validate: REJECT" substring anywhere -- this test would FAIL on that
    pre-Phase-2 code (no line ever matches the canonical marker) and PASSES
    once pfb_validate_log() wires the site.

    Given the alias is absent and no canonical structural-reject line for this
      feed's header exists yet (the delta baseline, captured before the Force
      Update -- not asserted as a global zero, per the no-false-pass-from-a-
      sibling-test rule).
    When the case Force-Updates over the truncated gzip (the structural probe
      -- gunzip -t -- rejects it, same as ADR-45's test_corrupt_gzip_rejected),
    Then the alias remains absent (ADR-45's existing pin) AND a NEW line
      matching "pfb_validate: REJECT feed=<hdr> stage=structural
      reason=probe_failed detected=application/gzip <hdr>.raw" appears in the
      pfB log.
    """
    header = "adr48stc"
    feed_url = mock_feeds.feed_url("archive_corrupt.gz")
    spec = h.IpCase(aliasname=header, feed_url=feed_url, header=header, family="v4")
    marker = (
        f"pfb_validate: REJECT feed={header}_v4 stage=structural reason=probe_failed "
        f"detected=application/gzip {header}_v4.raw"
    )

    # Given -- alias absent + delta baseline for this feed's canonical line.
    assert spec.alias not in h.pfctl_tables(deployed_vm), f"{spec.alias} present before the corrupt-gzip feed"
    before = h.count_log_marker(deployed_vm, h.PFB_LOG, marker)

    with h.CaseContext(deployed_vm, spec):
        # When -- Force Update; the structural probe (gunzip -t) rejects the truncated stream.
        tables_after = h.pfctl_tables(deployed_vm)
        assert spec.alias not in tables_after, (
            f"expected {spec.alias!r} absent after corrupt gzip (structural probe must reject), "
            f"found it present — tables: {tables_after}"
        )
        # Then -- a NEW canonical reject line was logged (proves the ADR-48 wiring
        # fired, not merely that the reject happened -- ADR-45 already pins the latter).
        after = h.count_log_marker(deployed_vm, h.PFB_LOG, marker)
        if not (after > before):
            raise AssertionError(
                f"expected a NEW line matching {marker!r} in {h.PFB_LOG} after the corrupt-gzip "
                f"Force Update; count before={before} after={after}\n"
                f"recent pfb_validate lines actually in the log:\n{_recent_validate_lines(deployed_vm)}"
            )


@pytest.mark.timeout(120)
def test_validate_log_mime_reject_line(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """ADR-48 P3: an outer MIME-gate reject emits the canonical stage=mime line.

    Reuses the FreeBSD-verified ADR-45 corpus fixture (fixtures/archive_junk_octet.bin;
    see fixtures/README.md) -- pure NUL/control bytes that file(1) reports as
    application/octet-stream, for which pfb_octet_recover_type() finds no
    archive type that passes -- the reject falls through to the OUTER MIME
    gate (stage=mime, reason=mime_not_allowed) with
    mime_raw=application/octet-stream, rc=0 (file(1) itself succeeds; it is
    the allow-list check that fails -- RESULTS/02_Results.txt's rendered
    template).

    Before ADR-48 Phase 2, this branch logged an ad-hoc "[PFB_FILTER - 17]
    Failed or invalid Mime Type: [...]" message with no "pfb_validate: REJECT"
    substring anywhere -- this test would FAIL on that pre-Phase-2 code.

    Given the alias is absent and no canonical mime-reject line for this feed's
      header exists yet (delta baseline).
    When the case Force-Updates over the junk octet-stream blob (same fixture
      as ADR-45's test_junk_octet_stream_rejected; skipped, not failed, if this
      box's file(1) does not report octet-stream for it -- the reject branch
      would then not be exercised, matching that sibling test's own guard),
    Then the alias remains absent AND a NEW line matching "pfb_validate: REJECT
      feed=<hdr> stage=mime reason=mime_not_allowed
      detected=application/octet-stream rc=0" appears in the pfB log.
    """
    header = "adr48mim"
    fixture = "archive_junk_octet.bin"
    feed_url = mock_feeds.feed_url(fixture)
    spec = h.IpCase(aliasname=header, feed_url=feed_url, header=header, family="v4")
    # feed= carries the on-box header, which the package suffixes with the
    # address family (_v4) -- see the structural test's docstring.
    marker = (
        f"pfb_validate: REJECT feed={header}_v4 stage=mime reason=mime_not_allowed "
        f"detected=application/octet-stream rc=0"
    )

    # On-box guard: the mime-gate reject only fires this way when file(1) sees octet-stream
    # for these exact bytes (mirrors test_junk_octet_stream_rejected's guard for the same fixture).
    box_mime = _box_mime_type(deployed_vm, _fixture_bytes(fixture))
    if box_mime != "application/octet-stream":
        pytest.skip(
            f"junk blob produced {box_mime!r} on this box (not application/octet-stream); "
            f"the mime-gate reject branch is not exercised — test inconclusive"
        )

    # Given -- alias absent + delta baseline for this feed's canonical line.
    assert spec.alias not in h.pfctl_tables(deployed_vm), f"{spec.alias} present before the junk-blob feed"
    before = h.count_log_marker(deployed_vm, h.PFB_LOG, marker)

    with h.CaseContext(deployed_vm, spec):
        # When -- Force Update; the outer MIME gate rejects (no archive type recovers).
        tables_after = h.pfctl_tables(deployed_vm)
        assert spec.alias not in tables_after, (
            f"expected {spec.alias!r} absent after junk octet-stream (mime gate must reject), "
            f"found it present — tables: {tables_after}"
        )
        # Then -- a NEW canonical reject line was logged.
        after = h.count_log_marker(deployed_vm, h.PFB_LOG, marker)
        if not (after > before):
            raise AssertionError(
                f"expected a NEW line matching {marker!r} in {h.PFB_LOG} after the junk-blob "
                f"Force Update; count before={before} after={after}\n"
                f"recent pfb_validate lines actually in the log:\n{_recent_validate_lines(deployed_vm)}"
            )


@pytest.mark.timeout(120)
def test_validate_log_inner_reject_line(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """ADR-48 P3: the gzip pre-extraction compressed peek emits the canonical stage=inner line.

    Forces the inner stage through the gz ``file -bZ`` COMPRESSED-PEEK sub-path
    (reason=compressed_mime_not_allowed). The zip POST-EXTRACTION sub-path is
    covered separately by ``test_validate_log_zip_inner_reject_line`` below --
    before issue #808's fix the re-run probed ``$input[1]`` = the ORIGINAL
    archive (the extracted file rode in the legacy-unused ``$input[0]``), so it
    always passed for a valid zip; the first fan-out proved that no-op live (a
    valid zip wrapping a PDF payload produced NO inner reject on either
    edition). The fix repoints the probe at the extracted payload.

    Built INLINE: a valid gzip stream is trivially portable (any gzip writer's
    output passes ``gunzip -t``), unlike the FreeBSD-libmagic-sensitive
    corrupt/octet-stream corpus this ADR reuses elsewhere. The gzip wraps the
    exact "%PDF-1.4\\n" byte string tests/php/PfbFilterRejectDetailTest.php
    already uses off-appliance: file(1) reliably reports application/pdf via
    the plain "%PDF-" text magic -- and ``file -bZ`` (decompress-and-look) on
    the gzip must yield the same inner verdict, which the on-box guard below
    re-confirms for the exact served bytes rather than assuming it.

    Route on-box: outer MIME gate sees application/gzip (allow-listed), the
    ADR-45 structural probe (``gunzip -t``) passes -- valid stream -- then the
    pre-extraction ``file -bZ`` peek sees application/pdf, which is NOT in the
    allow-list, and rejects with stage=inner.

    Before ADR-48 Phase 2, this branch logged an ad-hoc "Failed or invalid
    Mime Type Compressed: [...]" message with no "pfb_validate: REJECT"
    substring anywhere -- this test would FAIL on that pre-Phase-2 code.

    Given the alias is absent and no canonical inner-reject line for this
      feed's header exists yet (delta baseline).
    When the case Force-Updates over the gzip (structural probe passes, the
      compressed peek rejects the PDF inner content),
    Then the alias remains absent AND a NEW line matching "pfb_validate: REJECT
      feed=<hdr>_v4 stage=inner reason=compressed_mime_not_allowed
      detected=application/pdf rc=0" appears in the pfB log.
    """
    header = "adr48inr"
    entry_bytes = b"%PDF-1.4\n"
    gz_bytes = gzip.compress(entry_bytes)

    # On-box guard: the compressed peek only rejects this way when file -bZ sees
    # application/pdf inside the EXACT gzip bytes served (same probe-the-served-
    # bytes discipline as the ADR-45 octet-stream guards).
    box_inner_mime = _box_mime_type(deployed_vm, gz_bytes, flag="-bZ")
    if box_inner_mime != "application/pdf":
        pytest.skip(
            f"gzip-wrapped PDF payload produced {box_inner_mime!r} on this box's file -bZ "
            f"(not application/pdf); the compressed-peek reject branch is not exercised — test inconclusive"
        )

    feed_url = mock_feeds.register("adr48_inner.gz", gz_bytes)
    spec = h.IpCase(aliasname=header, feed_url=feed_url, header=header, family="v4")
    # feed= carries the on-box header, which the package suffixes with the
    # address family (_v4) -- see the structural test's docstring.
    marker = (
        f"pfb_validate: REJECT feed={header}_v4 stage=inner reason=compressed_mime_not_allowed "
        f"detected=application/pdf rc=0"
    )

    # Given -- alias absent + delta baseline for this feed's canonical line.
    assert spec.alias not in h.pfctl_tables(deployed_vm), f"{spec.alias} present before the inner-reject gzip feed"
    before = h.count_log_marker(deployed_vm, h.PFB_LOG, marker)

    with h.CaseContext(deployed_vm, spec):
        # When -- Force Update; the gzip is structurally valid but the peek rejects its inner type.
        tables_after = h.pfctl_tables(deployed_vm)
        assert spec.alias not in tables_after, (
            f"expected {spec.alias!r} absent after the inner-reject gzip (compressed peek "
            f"must reject), found it present — tables: {tables_after}"
        )
        # Then -- a NEW canonical reject line was logged.
        after = h.count_log_marker(deployed_vm, h.PFB_LOG, marker)
        if not (after > before):
            raise AssertionError(
                f"expected a NEW line matching {marker!r} in {h.PFB_LOG} after the inner-reject "
                f"gzip Force Update; count before={before} after={after}\n"
                f"recent pfb_validate lines actually in the log:\n{_recent_validate_lines(deployed_vm)}"
            )


@pytest.mark.timeout(120)
def test_validate_log_zip_inner_reject_line(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """Issue #808: the ZIP post-extraction re-check now probes the EXTRACTED payload, not the archive.

    Before the fix, the ZIP inner-content re-check called ``pfb_filter(array($file_org_esc,
    $file_download, ...), PFB_FILTER_FILE_MIME, ...)`` -- ``$input[1]`` was
    ``$file_download``, the ORIGINAL zip archive (already outer-MIME-allow-listed as
    application/zip), never the extracted file. So a zip wrapping a disallowed inner
    payload sailed through with NO inner reject -- a pure no-op observed LIVE by the
    ADR-48 fan-out (run 28700531268) on both CE 2.8 and Plus 26.03. The fix repoints the
    probe at ``$orig_download`` (the extracted file), so this canonical stage=inner line
    now fires for real.

    Built INLINE: a single-member zip wrapping the same "%PDF-1.4\\n" byte string the
    sibling gzip inner-reject test uses (also tests/php/PfbFilterRejectDetailTest.php's
    fixture) -- file(1) reliably reports application/pdf for it via the plain "%PDF-"
    text magic. The member name avoids ".xlsx" (would route to the xlsx-extraction
    branch instead) and the payload has no commas (the tar|sed|tr extraction pipeline
    must pass it through byte-intact for the re-probe to see the same PDF bytes).

    Given the alias is absent and no canonical inner-reject line for this feed's header
      exists yet (delta baseline).
    When the case Force-Updates over the zip (outer MIME gate + structural probe both
      pass -- valid application/zip -- extraction succeeds, then the post-extraction
      re-check probes the extracted PDF payload and rejects it),
    Then the alias remains absent AND a NEW line matching "pfb_validate: REJECT
      feed=<hdr>_v4 stage=inner reason=inner_mime_not_allowed detected=application/pdf
      rc=0" appears in the pfB log.
    """
    header = "issue808zin"
    entry_bytes = b"%PDF-1.4\n"

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("payload.pdf", entry_bytes)
    zip_bytes = buf.getvalue()

    # On-box guards (skip-if-inconclusive): the outer gate must route to the ZIP
    # branch at all, and the extracted-content probe must actually see application/pdf.
    box_outer_mime = _box_mime_type(deployed_vm, zip_bytes)
    if box_outer_mime != "application/zip":
        pytest.skip(
            f"zip bytes produced {box_outer_mime!r} on this box's file -b (not application/zip); "
            f"the outer gate would not route to the ZIP branch — test inconclusive"
        )
    box_inner_mime = _box_mime_type(deployed_vm, entry_bytes)
    if box_inner_mime != "application/pdf":
        pytest.skip(
            f"PDF payload produced {box_inner_mime!r} on this box's file -b (not application/pdf); "
            f"the extracted-content probe would not reject — test inconclusive"
        )

    feed_url = mock_feeds.register("issue808_zip_inner.zip", zip_bytes)
    spec = h.IpCase(aliasname=header, feed_url=feed_url, header=header, family="v4")
    # feed= carries the on-box header, which the package suffixes with the
    # address family (_v4) -- see the structural test's docstring.
    marker = (
        f"pfb_validate: REJECT feed={header}_v4 stage=inner reason=inner_mime_not_allowed detected=application/pdf rc=0"
    )

    # Given -- alias absent + delta baseline for this feed's canonical line.
    assert spec.alias not in h.pfctl_tables(deployed_vm), f"{spec.alias} present before the inner-reject zip feed"
    before = h.count_log_marker(deployed_vm, h.PFB_LOG, marker)

    with h.CaseContext(deployed_vm, spec):
        # When -- Force Update; the zip is structurally valid but the extracted-payload
        # re-check rejects its inner PDF content.
        tables_after = h.pfctl_tables(deployed_vm)
        assert spec.alias not in tables_after, (
            f"expected {spec.alias!r} absent after the inner-reject zip (post-extraction "
            f"re-check must reject), found it present — tables: {tables_after}"
        )
        # Then -- a NEW canonical reject line was logged.
        after = h.count_log_marker(deployed_vm, h.PFB_LOG, marker)
        if not (after > before):
            raise AssertionError(
                f"expected a NEW line matching {marker!r} in {h.PFB_LOG} after the inner-reject "
                f"zip Force Update; count before={before} after={after}\n"
                f"recent pfb_validate lines actually in the log:\n{_recent_validate_lines(deployed_vm)}"
            )


@pytest.mark.timeout(120)
def test_zip_extraction_failure_rejected_not_empty(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """Issue #819: a ZIP whose member DATA is corrupt is rejected as a decompression
    failure, not silently imported as an empty feed.

    Before the fix, the non-xlsx ZIP branch ran
    ``tar -xOf {file} | sed 's/,[[:space:]]/; /g' | tr ',' '\\n' > {file_org}`` without
    ``pipefail`` -- the ``sh -c`` exit status of a pipeline is its LAST command's, here
    ``tr``, which always succeeds even when ``tar`` fails mid-stream on a CRC error. So
    a tar extraction failure left ``$retval == 0``: the (empty) ``.orig`` file passed the
    inner-content MIME gate (an empty file probes as the allow-listed ``inode/x-empty``)
    and the feed imported as a silent, member-less "empty feed" with NO error logged.
    A non-zero extraction status prevents publication. The staged-publish path logs
    the precise ``zip publish failed`` marker before returning.

    Fixture: a valid single-member DEFLATE zip with one byte flipped a few bytes into
    the compressed data stream (past the 30-byte local file header + filename). The
    ADR-45 structural probe (``tar -tf``) reads only the central directory (at the
    archive's tail) and stays intact, so it still PASSES -- the corruption is invisible
    to the listing probe and only surfaces as a CRC failure when ``tar -xOf`` actually
    decompresses the member. That is the live red-before-fix vector this test pins.

    Given the alias is absent and a delta baseline of ZIP publish-failure lines in
      the pfB log (module-wide, on purpose -- only the delta across THIS case's own
      Force Update window is asserted).
    When the case Force-Updates over the corrupt-payload zip (outer MIME gate sees
      application/zip and the structural listing probe passes, but extraction itself
      fails on the corrupted member),
    Then the alias remains absent AND a NEW ZIP publish-failure line appears in the
      pfB log -- the extraction error surfaced as an error, not a silent empty import.
    """
    member = "payload.txt"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr(member, "x" * 4096)
    raw = bytearray(buf.getvalue())
    # Local file header is 30 bytes + len(member); flip a byte a few bytes into the
    # deflate stream so the CRC check fails on extraction while the central
    # directory (at the tail, read by `tar -tf`) stays intact.
    data_off = 30 + len(member) + 4
    raw[data_off] ^= 0xFF
    zip_bytes = bytes(raw)

    remote_tmp = "/tmp/issue819_zip_extract_fail.zip"

    # On-box guards (skip-if-inconclusive) -- probe the EXACT served bytes:
    box_mime = _box_mime_type(deployed_vm, zip_bytes)
    if box_mime != "application/zip":
        pytest.skip(
            f"corrupt-payload zip produced {box_mime!r} on this box's file -b (not application/zip); "
            f"the outer gate would not route to the ZIP branch — test inconclusive"
        )
    listing_rc = _box_cmd_rc(deployed_vm, zip_bytes, remote_tmp, f"/usr/bin/tar -tf {remote_tmp}")
    if listing_rc != 0:
        pytest.skip(
            f"tar -tf exited {listing_rc} on this box for the corrupt-payload zip (expected 0); "
            f"the ADR-45 structural probe would reject first — the extraction path is never reached"
        )
    extract_rc = _box_cmd_rc(deployed_vm, zip_bytes, remote_tmp, f"/usr/bin/tar -xOf {remote_tmp} > /dev/null")
    if extract_rc == 0:
        pytest.skip(
            "tar -xOf exited 0 on this box for the corrupt-payload zip (expected non-zero); "
            "the corruption did not take -- extraction would succeed and the reject branch is never exercised"
        )

    header = "issue819zex"
    feed_url = mock_feeds.register("issue819_zip_extract_fail.zip", zip_bytes)
    spec = h.IpCase(aliasname=header, feed_url=feed_url, header=header, family="v4")
    marker = f"[pfb_download] zip publish failed (tar exit {extract_rc})"

    # Given -- alias absent + delta baseline of ZIP publish-failure lines.
    assert spec.alias not in h.pfctl_tables(deployed_vm), f"{spec.alias} present before the corrupt-payload zip feed"
    before = h.count_log_marker(deployed_vm, h.PFB_LOG, marker)

    with h.CaseContext(deployed_vm, spec):
        # When -- Force Update; the outer gate + structural probe both pass, extraction fails.
        tables_after = h.pfctl_tables(deployed_vm)
        assert spec.alias not in tables_after, (
            f"expected {spec.alias!r} absent after the corrupt-payload zip (extraction must fail), "
            f"found it present — tables: {tables_after}"
        )
        # Then -- a NEW ZIP publish-failure line was logged (the error surfaced,
        # rather than the feed silently importing as empty).
        after = h.count_log_marker(deployed_vm, h.PFB_LOG, marker)
        if not (after > before):
            tail = h.read_log_file(deployed_vm, h.PFB_LOG).splitlines()[-20:]
            raise AssertionError(
                f"expected a NEW {marker!r} line in {h.PFB_LOG} after the corrupt-payload "
                f"zip Force Update; count before={before} after={after}\n"
                f"last 20 lines of {h.PFB_LOG}:\n" + "\n".join(tail)
            )


@pytest.mark.timeout(120)
def test_validate_log_healthy_feed_no_spurious_reject(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """ADR-48 P3: a healthy feed load emits ZERO new 'pfb_validate: REJECT' lines.

    The MUST-ACCOMPANY counterpart to the three reject-line tests above --
    together they prove the canonical marker is a REAL reject signal tied to
    an actual validation failure, not something pfb_download() logs on every
    run regardless of outcome (the ADR §7 / RESULTS/03 reject criterion: "no
    healthy feed logs a spurious REJECT"). Reuses the Phase-4 ip_plain_cidr.txt
    fixture (already the KILL-GATE healthy-load fixture for
    test_ip_http_feed_loads).

    Given the alias is absent and a delta baseline of every 'pfb_validate:
      REJECT' line already in the pfB log (module-wide, on purpose: whatever
      an earlier test in this module already wrote is irrelevant here -- only
      the delta across THIS case's own Force Update window is asserted, so
      this test never depends on run order).
    When the case Force-Updates over the healthy plain-IP+CIDR feed,
    Then the listed member loads (the feed genuinely succeeded, not merely
      "didn't crash") AND the REJECT-marker count is UNCHANGED -- no spurious
      REJECT line was logged for a feed that never failed validation.
    """
    header = "adr48hlt"
    feed_url = mock_feeds.feed_url("ip_plain_cidr.txt")
    spec = h.IpCase(aliasname=header, feed_url=feed_url, header=header, family="v4")
    member_host = "203.0.113.5"  # the plain listed host (fixtures/README.md)

    # Given -- alias absent + delta baseline of ANY reject marker.
    assert spec.alias not in h.pfctl_tables(deployed_vm), f"{spec.alias} present before the healthy feed was loaded"
    before = h.count_log_marker(deployed_vm, h.PFB_LOG, "pfb_validate: REJECT")

    with h.CaseContext(deployed_vm, spec):
        # When -- Force Update loads the healthy feed successfully.
        members = h.pfctl_table_members(deployed_vm, spec.alias)
        assert h.member_present(members, member_host), (
            f"expected {member_host!r} in {spec.alias} after the healthy feed load, got: {members}"
        )
        # Then -- no NEW canonical REJECT line was logged for this successful load.
        after = h.count_log_marker(deployed_vm, h.PFB_LOG, "pfb_validate: REJECT")
        if not (after == before):
            raise AssertionError(
                f"expected NO NEW 'pfb_validate: REJECT' line in {h.PFB_LOG} after a healthy feed "
                f"load; count before={before} after={after} (a healthy feed must never emit a "
                f"validation reject)\n"
                f"recent pfb_validate lines actually in the log:\n{_recent_validate_lines(deployed_vm)}"
            )


# --------------------------------------------------------------------------- #
# ADR-48 Phase 4 (issue #789): the Python-side per-entry reject tally surfaces
# as the SAME canonical marker at stage=entries. Unlike Phases 1-3 (rejects
# inside pfb_download()'s PHP-side MIME/structural gates), these entries are
# rejected by Python's ABP parser (parse_abp/normalise, ADR-06/07) once the
# feed content itself has already passed those PHP-side gates -- so the fixture
# here is a plain ABP body (built inline, no FreeBSD-sensitive archive/MIME
# concern), delivered via a DnsblCase reload (updatednsbl), not an IpCase.
# --------------------------------------------------------------------------- #


@pytest.mark.timeout(120)
def test_validate_log_entries_reject_line(
    deployed_vm: SmokeVM, client_vm: SmokeVM, mock_feeds: _MockFeedServer
) -> None:
    """ADR-48 P4: rejectable ABP entries tally + emit the canonical stage=entries line.

    The feed carries THREE lines: one healthy block (proves the feed genuinely
    loaded/parsed -- not merely "didn't crash") and one entry per RESOLVED
    reject bucket -- a no-dot host ('shape') and a 64-char label ('wire_cap',
    over the #753 63-char cap). Before this phase, pfb_unbound.py counted
    neither rejection anywhere, so no 'pfb_validate: REJECT ... stage=entries'
    line could ever appear -- this test FAILS on pre-Phase-4 code (the marker
    cannot exist) and PASSES once build()'s tally + pfb_emit_entry_reject_stats()
    wire it end-to-end.

    Given the healthy member resolves before listing (no stale block from a
      prior case) and no canonical entries-reject line for this feed's header
      exists yet for either bucket (the delta baseline).
    When the case Force-Updates (updatednsbl) over the ABP feed,
    Then the healthy member is VIP-blocked (feed loaded) AND a NEW
      'pfb_validate: REJECT feed=<hdr> stage=entries reason=shape detected=1'
      line appears AND a NEW '... reason=wire_cap detected=1' line appears.
    """
    header = "adr48ent"
    blocked_name = h.unique_domain("adr48ent")
    shape_reject_host = "adr48noshapehost"  # no "." -> normalise() 'shape' reject
    wire_cap_reject_host = "a" * 64 + ".example.com"  # 64-char label -> #753 'wire_cap' reject
    body = h.abp_feed(
        f"||{blocked_name}^",
        f"||{shape_reject_host}^",
        f"||{wire_cap_reject_host}^",
    )
    feed_url = mock_feeds.register("adr48_entries.txt", body)
    spec = h.DnsblCase(aliasname=header, feed_url=feed_url, header=header, mode=h.DnsblMode.VIP)
    shape_marker = f"pfb_validate: REJECT feed={header} stage=entries reason=shape detected=1"
    wire_cap_marker = f"pfb_validate: REJECT feed={header} stage=entries reason=wire_cap detected=1"

    # Given -- the healthy member resolves before listing + delta baseline for both markers.
    before_probe = h.dns_probe_client(client_vm, blocked_name, "A")
    assert h.resolves_to(before_probe, STUB_DNS_A), (
        f"{blocked_name} should resolve via stub BEFORE listing, got {before_probe}"
    )
    assert not h.is_vip(before_probe), f"{blocked_name} unexpectedly VIP-blocked before any feed: {before_probe}"
    before_shape = h.count_log_marker(deployed_vm, h.PFB_LOG, shape_marker)
    before_wire_cap = h.count_log_marker(deployed_vm, h.PFB_LOG, wire_cap_marker)

    with h.CaseContext(deployed_vm, spec):
        # When -- Force Update; egress stays OPEN only to warm/flush the cache entry
        # (the block itself resolves locally regardless).
        h.unblock_egress()
        h.flush_unbound_name(deployed_vm, blocked_name)
        ans = h.dns_probe_client_until(client_vm, blocked_name, h.is_vip)
        assert h.is_vip(ans), (
            f"expected {blocked_name!r} VIP-blocked after the entries-reject feed (feed must have "
            f"genuinely loaded/parsed), got {ans}"
        )

        # Then -- each rejectable entry tallied + emitted its OWN canonical line.
        after_shape = h.count_log_marker(deployed_vm, h.PFB_LOG, shape_marker)
        if not (after_shape > before_shape):
            raise AssertionError(
                f"expected a NEW line matching {shape_marker!r} in {h.PFB_LOG} after the "
                f"entries-reject Force Update; count before={before_shape} after={after_shape}\n"
                f"recent pfb_validate lines actually in the log:\n{_recent_validate_lines(deployed_vm)}"
            )
        after_wire_cap = h.count_log_marker(deployed_vm, h.PFB_LOG, wire_cap_marker)
        if not (after_wire_cap > before_wire_cap):
            raise AssertionError(
                f"expected a NEW line matching {wire_cap_marker!r} in {h.PFB_LOG} after the "
                f"entries-reject Force Update; count before={before_wire_cap} after={after_wire_cap}\n"
                f"recent pfb_validate lines actually in the log:\n{_recent_validate_lines(deployed_vm)}"
            )


@pytest.mark.timeout(120)
def test_validate_log_healthy_abp_feed_no_entries_reject(
    deployed_vm: SmokeVM, client_vm: SmokeVM, mock_feeds: _MockFeedServer
) -> None:
    """ADR-48 P4 / §7 reject-criterion pin: a healthy ABP feed emits ZERO new
    'stage=entries' lines, even with deliberate SKIP-class lines present.

    The MUST-ACCOMPANY counterpart to ``test_validate_log_entries_reject_line``
    above: reuses the deliberate-skip corpus (comment, cosmetic/element-hiding,
    a tracking-script path anchor, an IP-valued anchor, a ``$badfilter`` rule on
    an UNRELATED domain) that ``tests/test_adr06_build_module.py::
    TestSkipClassesTallyZero`` already pins as tallying nothing at the unit
    level -- this proves the same guarantee end-to-end on the live box: a feed
    built entirely of skips (plus one healthy block, proving the feed loaded)
    must never spam the operator with a spurious ``stage=entries`` line.

    Given the healthy member resolves before listing and no 'stage=entries'
      line for this feed's header exists yet (the delta baseline, module-wide
      generic-marker style per the Phase-3 healthy-feed guard).
    When the case Force-Updates over the skip-only + one-healthy-block feed,
    Then the healthy member is VIP-blocked (feed genuinely loaded) AND the
      'pfb_validate: REJECT ... feed=<hdr> stage=entries' marker count is
      UNCHANGED -- no skip class was miscounted as a reject.
    """
    header = "adr48ehl"
    blocked_name = h.unique_domain("adr48ehl")
    body = h.abp_feed(
        "! Title: a comment line",
        "example.com##.ad-banner",
        "||cdn.example.net/track.js",  # path anchor -> SKIP, not a reject
        "||203.0.113.7^",  # IP-valued anchor -> firewall path, not a reject
        "||gone.example.com^$badfilter",  # parses to a Rule, pruned in reconcile() -- unrelated domain
        f"||{blocked_name}^",
    )
    feed_url = mock_feeds.register("adr48_healthy_abp.txt", body)
    spec = h.DnsblCase(aliasname=header, feed_url=feed_url, header=header, mode=h.DnsblMode.VIP)
    entries_marker = f"pfb_validate: REJECT feed={header} stage=entries"

    # Given -- the healthy member resolves before listing + delta baseline.
    before_probe = h.dns_probe_client(client_vm, blocked_name, "A")
    assert h.resolves_to(before_probe, STUB_DNS_A), (
        f"{blocked_name} should resolve via stub BEFORE listing, got {before_probe}"
    )
    assert not h.is_vip(before_probe), f"{blocked_name} unexpectedly VIP-blocked before any feed: {before_probe}"
    before = h.count_log_marker(deployed_vm, h.PFB_LOG, entries_marker)

    with h.CaseContext(deployed_vm, spec):
        # When -- Force Update; the skip lines never reach a block dict, only the
        # clean anchor does.
        h.unblock_egress()
        h.flush_unbound_name(deployed_vm, blocked_name)
        ans = h.dns_probe_client_until(client_vm, blocked_name, h.is_vip)
        assert h.is_vip(ans), (
            f"expected {blocked_name!r} VIP-blocked after the healthy ABP feed (feed must have "
            f"genuinely loaded/parsed), got {ans}"
        )

        # Then -- no NEW stage=entries line for this feed (the skip classes tallied nothing).
        after = h.count_log_marker(deployed_vm, h.PFB_LOG, entries_marker)
        if not (after == before):
            raise AssertionError(
                f"expected NO NEW {entries_marker!r} line in {h.PFB_LOG} after a healthy ABP feed "
                f"load (a deliberate skip class must never tally as a reject); count "
                f"before={before} after={after}\n"
                f"recent pfb_validate lines actually in the log:\n{_recent_validate_lines(deployed_vm)}"
            )


# --------------------------------------------------------------------------- #
# ADR-49: opt-in plain-text sanity scan (pfb_feed_sanity, default OFF). Live-VM
# proof that the config-only gate wired in Phase 2 (pfblockerng.inc's pfb_download,
# right after the MIME accept) genuinely runs: OFF is a no-op on an HTML-error-page
# feed that would otherwise sail through the MIME allow-list; ON rejects it
# (stage=plaintext) via the same ADR-48 canonical line the mime/structural/inner
# stages already use; and a real blocklist feed still imports with the scan ON
# (a real branch, not an always-reject path).
# --------------------------------------------------------------------------- #

# Mirrors the gate's in_array() list in pfblockerng.inc pfb_download() -- keep in sync.
_SANITY_SCANNED_MIME_TYPES = ("text/plain", "text/html", "text/csv", "application/csv")


@pytest.mark.timeout(180)
def test_feed_sanity_flag_gates_html_error_page_reject(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """ADR-49: pfb_feed_sanity OFF (default) never rejects; ON rejects an HTML-error-page feed.

    Two DISTINCT, never-before-fetched headers over the SAME served fixture
    (``html_error_page.html``) -- not one header Force-Updated twice -- because
    pfb_download()'s own per-list "reuse" shortcut (pfblockerng.inc: once a header's
    ``{header}.orig``/``.txt`` already exists, a later pass can skip straight to
    reusing it without calling pfb_download() again) means re-running the SAME
    header a second time is not guaranteed to re-invoke the gate at all. A header
    pfBlockerNG has never fetched before has no such shortcut available -- the first
    fetch of ANY header always calls pfb_download() -- so using two fresh headers
    isolates the flag as the only variable that differs between the OFF and ON legs.

    Given the scan OFF (explicit + the registered default) and a fresh header with
      no pre-existing reject line,
    When Force-Updating the HTML-error-page feed under that header,
    Then NO 'stage=plaintext' reject line appears for it (the before-state proving
      an off install is unaffected).
    Given the scan then flipped ON and a SECOND fresh header over the SAME feed body,
    When Force-Updating it,
    Then a NEW 'pfb_validate: REJECT ... stage=plaintext reason=html_error_page ...'
      line appears for THAT header, and its alias table stays absent -- the flag
      (not the feed content, which is identical in both legs) caused the reject.
    """
    fixture = "html_error_page.html"
    feed_url = mock_feeds.feed_url(fixture)

    # On-box guard (ADR-49 §5 / the ADR-45 libmagic-divergence lesson): ASSERT, never
    # skip, so a libmagic surprise fails LOUDLY with the real verdict -- the plaintext
    # gate only ever sees this fixture at all if FreeBSD file(1) calls it an
    # allow-listed text type.
    box_mime = _box_mime_type(deployed_vm, _fixture_bytes(fixture))
    assert box_mime in _SANITY_SCANNED_MIME_TYPES, (
        f"expected {fixture} on-box file(1) verdict in {_SANITY_SCANNED_MIME_TYPES}, "
        f"got {box_mime!r} -- the plaintext gate would never see this fixture at all "
        f"(adjust the fixture bytes until it lands on a scanned text type)"
    )

    header_off = "adr49sanoff"
    header_on = "adr49sanon"
    # feed= carries the on-box header with its family suffix (see the ADR-48
    # structural-reject test's docstring); detected= is basename($file_download),
    # always "<header>_v4.raw".
    marker_off = f"pfb_validate: REJECT feed={header_off}_v4 stage=plaintext"
    marker_on = (
        f"pfb_validate: REJECT feed={header_on}_v4 stage=plaintext reason=html_error_page detected={header_on}_v4.raw"
    )

    try:
        # Given -- flag OFF (explicit; also the registered default) + a fresh header.
        h.set_feed_sanity(deployed_vm, False)
        before_off = h.count_log_marker(deployed_vm, h.PFB_LOG, marker_off)
        assert before_off == 0, f"{marker_off!r} must not pre-exist for a brand-new header, got {before_off}"

        spec_off = h.IpCase(aliasname=header_off, feed_url=feed_url, header=header_off, family="v4")
        with h.CaseContext(deployed_vm, spec_off):
            # Then -- the scan never ran: no reject line for this header (the before-state).
            after_off = h.count_log_marker(deployed_vm, h.PFB_LOG, marker_off)
            if not (after_off == before_off == 0):
                raise AssertionError(
                    f"flag OFF must be a no-op: expected NO {marker_off!r} line in {h.PFB_LOG} "
                    f"(before={before_off}), got after={after_off} -- the scan ran with "
                    f"pfb_feed_sanity off\n"
                    f"recent pfb_validate lines actually in the log:\n{_recent_validate_lines(deployed_vm)}"
                )

        # When -- flip the SAME feed body's flag ON, fetched under a FRESH header.
        h.set_feed_sanity(deployed_vm, True)
        before_on = h.count_log_marker(deployed_vm, h.PFB_LOG, marker_on)
        assert before_on == 0, f"{marker_on!r} must not pre-exist for a brand-new header, got {before_on}"

        spec_on = h.IpCase(aliasname=header_on, feed_url=feed_url, header=header_on, family="v4")
        with h.CaseContext(deployed_vm, spec_on):
            # Then -- a NEW canonical reject line appears; the flag CAUSED the reject
            # (the flag-off leg above is the before-state proving causation, not merely
            # "a line exists somewhere").
            after_on = h.count_log_marker(deployed_vm, h.PFB_LOG, marker_on)
            if not (after_on > before_on):
                raise AssertionError(
                    f"expected a NEW line matching {marker_on!r} in {h.PFB_LOG} after enabling "
                    f"pfb_feed_sanity and Force-Updating the error-page feed; count "
                    f"before={before_on} after={after_on}\n"
                    f"recent pfb_validate lines actually in the log:\n{_recent_validate_lines(deployed_vm)}"
                )
            tables_on = h.pfctl_tables(deployed_vm)
            assert spec_on.alias not in tables_on, (
                f"expected {spec_on.alias!r} absent after a rejected download (stage=plaintext "
                f"must reject before any table build), found it present — tables: {tables_on}"
            )
    finally:
        h.set_feed_sanity(deployed_vm, False)


@pytest.mark.timeout(120)
def test_feed_sanity_flag_on_still_imports_healthy_feed(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """ADR-49: pfb_feed_sanity ON still imports a genuinely healthy text feed.

    The MUST-ACCOMPANY counterpart to the reject-line test above -- proves the scan
    is a REAL branch (rejects the error page, not every text/plain|html|csv feed) by
    reusing the already-verified healthy ``ip_plain_cidr.txt`` fixture (the Part-C
    kill-gate fixture for ``test_ip_http_feed_loads``) with the scan explicitly ON.

    Given the scan ON and the alias absent (a fresh header, no pre-existing reject
      line),
    When Force-Updating the healthy plain-IP+CIDR feed,
    Then the listed member loads into the pf table (genuinely imported, not merely
      "didn't crash") AND no NEW 'stage=plaintext' reject line was logged for it.
    """
    header = "adr49sanhlt"
    feed_url = mock_feeds.feed_url("ip_plain_cidr.txt")
    spec = h.IpCase(aliasname=header, feed_url=feed_url, header=header, family="v4")
    member_host = "203.0.113.5"  # the plain listed host (fixtures/README.md)
    reject_marker = f"pfb_validate: REJECT feed={header}_v4 stage=plaintext"

    try:
        # Given -- scan ON, alias absent, no pre-existing reject line for this fresh header.
        h.set_feed_sanity(deployed_vm, True)
        tables_before = h.pfctl_tables(deployed_vm)
        assert spec.alias not in tables_before, (
            f"{spec.alias} present before the healthy feed was loaded; pfctl tables: {tables_before}"
        )
        before = h.count_log_marker(deployed_vm, h.PFB_LOG, reject_marker)

        with h.CaseContext(deployed_vm, spec):
            # When -- Force Update loads the healthy feed with the scan ON.
            members = h.pfctl_table_members(deployed_vm, spec.alias)
            assert h.member_present(members, member_host), (
                f"expected {member_host!r} in {spec.alias} after the healthy feed load with "
                f"pfb_feed_sanity ON, got: {members}"
            )
            # Then -- no NEW reject line: the scan is a real branch, not an always-reject path.
            after = h.count_log_marker(deployed_vm, h.PFB_LOG, reject_marker)
            if not (after == before):
                raise AssertionError(
                    f"expected NO NEW {reject_marker!r} line in {h.PFB_LOG} after a healthy feed "
                    f"load with pfb_feed_sanity ON; count before={before} after={after} (a healthy "
                    f"feed must never be misclassified as an error page)\n"
                    f"recent pfb_validate lines actually in the log:\n{_recent_validate_lines(deployed_vm)}"
                )
    finally:
        h.set_feed_sanity(deployed_vm, False)


# --------------------------------------------------------------------------- #
# ADR-46: archive member-name guard before disk-writing extraction. The
# GeoIP/top-1M/blacklist URLs are hardcoded in pfblockerng.php, so these cases
# drive pfb_download() DIRECTLY via h.php_eval pointed at the mock server (the
# test_smoke_714_asn_geoip.py pattern). One hostile case per guarded site --
# the ZIP GeoIP/top-1M branch, the gzip GeoIP branch, and the UT1/blacklist
# branch -- plus the benign pass-through regression pin.
# --------------------------------------------------------------------------- #

_ADR46_WORKDIR = f"{h.PFB_DBDIR}/adr46_guard"


def _adr46_download(vm: SmokeVM, feed_url: str, file_dwn: str, header: str, dl_type: str) -> str:
    """Run pfb_download(PfbDownloadRequest(..., type=<dl_type>)) on the box; return stdout.

    ``header`` is the request's extraction/log field: the ``tar -C`` target for the
    ZIP geoip/top1m branch, and the ``feed=`` token of the canonical reject line at
    every wired site.
    """
    snippet = (
        "require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');\n"
        "pfb_global();\n"
        "$ok = pfb_download(new PfbDownloadRequest("
        f"listUrl: {h._php_str(feed_url)}, "  # noqa: SLF001
        f"downloadPath: {h._php_str(file_dwn)}, flex: FALSE, "  # noqa: SLF001
        f"header: {h._php_str(header)}, format: '', logType: 1, versionType: '', "  # noqa: SLF001
        f"timeout: 60, type: {h._php_str(dl_type)}, username: '', password: '', "  # noqa: SLF001
        "sourceInterface: FALSE, extraHeaders: array()));"
        "$ok = $ok->success;\n"
        "echo $ok ? 'PFB_DL_TRUE' : 'PFB_DL_FALSE';"
    )
    res = h.php_eval(vm, snippet, timeout=120.0)
    return res.stdout


@pytest.mark.timeout(120)
def test_adr46_hostile_member_zip_rejected(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """ADR-46: an archive with a parent-dir-escaping member is rejected BEFORE disk extraction.

    Fixture: archive_traversal.zip (committed raw bytes -- stock zip/bsdtar refuse to
    create a '..' member; see fixtures/README.md). Two members steer the top-1M ZIP
    branch into the disk-writing `tar -xf -C` path; the second member is
    `../pfb_adr46_escape.txt`.

    Pre-ADR-46 behaviour is SILENT PARTIAL SUCCESS -- bsdtar's default refusal just
    skips the `..` member (extraction stderr is discarded) and the result success flag is
    TRUE -- so this test FAILS on pre-guard code (pfb_download reported success, no
    canonical line) and PASSES with the guard (explicit stage=member reject).

    Given a clean work dir and the delta baseline for the stage=member line,
    When  pfb_download() fetches the traversal ZIP as a top-1M extra,
    Then  its result success flag is FALSE, a canonical "stage=member reason=unsafe_member_name
      detected=../pfb_adr46_escape.txt" line is logged, the downloaded archive is
      unlinked, and NOTHING was extracted (no benign member, no escape file).
    """
    marker = "stage=member reason=unsafe_member_name detected=../pfb_adr46_escape.txt"
    workdir = f"{_ADR46_WORKDIR}_hostile"
    target = f"{workdir}/out"
    escape_file = f"{h.PFB_DBDIR}/pfb_adr46_escape.txt"
    try:
        # Given -- clean slate + delta baseline.
        deployed_vm.ssh(f"/bin/rm -rf {workdir} {escape_file} && /bin/mkdir -p {target}")
        before = h.count_log_marker(deployed_vm, h.PFB_LOG, marker)

        # When -- drive the top-1M ZIP branch directly at the traversal fixture.
        out = _adr46_download(
            deployed_vm, mock_feeds.feed_url("archive_traversal.zip"), f"{workdir}/dl.zip", target, "top1m"
        )

        # Then -- explicit reject, not silent partial success.
        assert "PFB_DL_FALSE" in out, (
            f"expected pfb_download success flag FALSE on a '..'-member archive "
            f"(pre-ADR-46 it silently reported success); got stdout: {out!r}"
        )
        after = h.count_log_marker(deployed_vm, h.PFB_LOG, marker)
        if not (after > before):
            raise AssertionError(
                f"expected a NEW line matching {marker!r} in {h.PFB_LOG} after the traversal-zip "
                f"download; count before={before} after={after}\n"
                f"recent pfb_validate lines actually in the log:\n{_recent_validate_lines(deployed_vm)}"
            )
        leftovers = deployed_vm.ssh(
            f"/bin/ls -A {target} 2>/dev/null; test -e {workdir}/dl.zip.raw && echo RAW-PRESENT; "
            f"test -e {escape_file} && echo ESCAPE-PRESENT"
        ).stdout.strip()
        assert leftovers == "", (
            f"expected no extraction artifacts after the member-guard reject (empty target dir, "
            f"archive unlinked, no escape file); found: {leftovers!r}"
        )
    finally:
        deployed_vm.ssh(f"/bin/rm -rf {workdir} {escape_file}")


@pytest.mark.timeout(120)
def test_adr46_legit_multifile_zip_still_imports(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """ADR-46: a legitimate multi-member archive still extracts -- the guard is a pass-through.

    The ADR §7 reject criterion: a legitimate archive that imports today must not fail
    after the guard. Built inline (a valid zip is portable; only hostile members need
    the committed-fixture treatment).

    Given a clean pre-created target dir (asserted empty) and the stage=member baseline,
    When  pfb_download() fetches a benign two-member ZIP as a top-1M extra,
    Then  its result success flag is TRUE, both members land in the target dir (--strip=1 applied),
      and NO stage=member line was added.
    """
    workdir = f"{_ADR46_WORKDIR}_legit"
    target = f"{workdir}/out"
    guard_marker = "stage=member reason=unsafe_member_name"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("d/adr46_a.csv", "192.0.2.21\n")  # inert RFC 5737 data
        z.writestr("d/adr46_b.csv", "192.0.2.22\n")
    feed_url = mock_feeds.register("adr46_legit.zip", buf.getvalue())
    try:
        # Given -- empty target (before-state: members absent).
        deployed_vm.ssh(f"/bin/rm -rf {workdir} && /bin/mkdir -p {target}")
        pre = deployed_vm.ssh(f"/bin/ls -A {target}").stdout.strip()
        assert pre == "", f"target dir must start empty, found: {pre!r}"
        before = h.count_log_marker(deployed_vm, h.PFB_LOG, guard_marker)

        # When -- same driver, benign archive.
        out = _adr46_download(deployed_vm, feed_url, f"{workdir}/dl.zip", target, "top1m")

        # Then -- import succeeds and the guard stayed silent.
        assert "PFB_DL_TRUE" in out, (
            f"expected pfb_download success flag TRUE for a benign multi-member zip "
            f"(the guard must be a pass-through); got stdout: {out!r}"
        )
        extracted = deployed_vm.ssh(f"/bin/ls -A {target}").stdout.split()
        assert sorted(extracted) == ["adr46_a.csv", "adr46_b.csv"], (
            f"expected both members extracted with --strip=1 into {target}; found: {extracted!r}"
        )
        after = h.count_log_marker(deployed_vm, h.PFB_LOG, guard_marker)
        assert after == before, (
            f"expected NO NEW {guard_marker!r} line for a benign archive; "
            f"count before={before} after={after}\n"
            f"recent pfb_validate lines actually in the log:\n{_recent_validate_lines(deployed_vm)}"
        )
    finally:
        deployed_vm.ssh(f"/bin/rm -rf {workdir}")


# --------------------------------------------------------------------------- #
# issue #2668 — the GeoIP extraction branches publish through staging, so an
# extraction that fails part-way leaves the tree already in service untouched.
#
# Only the appliance can answer whether the staged publish holds against ITS
# bsdtar and ITS filesystem: the refusal has to arrive from libarchive's own CRC
# check, and the publication is a FreeBSD rename inside the target directory.
# --------------------------------------------------------------------------- #

_PFB2668_WORKDIR = f"{h.PFB_DBDIR}/pfb2668_stage"


def _published_tree(vm: SmokeVM, target: str) -> str:
    """Every file under $target as `<md5>  <name>` lines, sorted — the byte-identity oracle."""
    return vm.ssh(
        f"cd {target} && /usr/bin/find . \\( -type f -o -type l \\) | /usr/bin/sort | "
        f'while read -r f; do /sbin/md5 -q "$f" 2>/dev/null | /usr/bin/tr -d \'\\n\'; echo "  $f"; done'
    ).stdout.strip()


@pytest.mark.timeout(180)
def test_geoip_partway_extraction_keeps_the_published_tree_byte_identical(
    deployed_vm: SmokeVM, mock_feeds: _MockFeedServer
) -> None:
    """issue #2668: a corrupt GeoIP archive leaves the published tree byte-identical.

    The GeoIP ZIP branch used to extract straight onto its live target, so an
    extraction that failed after writing some members left a mixture of the old
    publication and a truncated new one. It now extracts into a staging directory
    inside the target and moves the members over only once bsdtar exits clean.

    The fixture is corrupt in the one way that reaches extraction at all: it lists
    cleanly (header-only, so ADR-46's member guard passes) and fails on the second
    member's CRC, with the first member already written.

    Given a published tree in service and a corrupt two-member GeoIP archive
    When  pfb_download() fetches it as a geoip extra
    Then  the download fails, the published tree is byte-identical, neither member
      was published, and no staging directory is left behind.
    """
    workdir = f"{_PFB2668_WORKDIR}_partway"
    target = f"{workdir}/share"
    # Discriminates the stage: a pre-extraction refusal (a rejected member name, a
    # failed structural probe) would satisfy every assertion below, so the run has
    # to prove it reached the extraction the fixture is built to break.
    marker = "geoip zip extraction failed"
    try:
        # Given -- a tree already in service.
        deployed_vm.ssh(f"/bin/rm -rf {workdir} && /bin/mkdir -p {target}")
        deployed_vm.ssh(f"/bin/echo 203.0.113.99 > {target}/served.dat")
        before = _published_tree(deployed_vm, target)
        assert before.endswith("  ./served.dat"), f"fixture tree not in service: {before!r}"
        marker_before = h.count_log_marker(deployed_vm, h.PFB_LOG, marker)

        # When -- the corrupt archive drives the multi-member GeoIP arm.
        out = _adr46_download(
            deployed_vm,
            mock_feeds.feed_url("archive_partial_extract.zip"),
            f"{workdir}/dl.zip",
            target,
            "geoip",
        )

        # Then -- refused, with the publication untouched.
        assert "PFB_DL_FALSE" in out, (
            f"expected pfb_download success flag FALSE for an archive that fails part-way; got: {out!r}"
        )
        marker_after = h.count_log_marker(deployed_vm, h.PFB_LOG, marker)
        assert marker_after > marker_before, (
            f"expected a NEW {marker!r} line — without it the download could have failed "
            f"before extraction, which would satisfy the tree assertion for the wrong reason; "
            f"count before={marker_before} after={marker_after}"
        )
        after = _published_tree(deployed_vm, target)
        assert after == before, (
            "the published tree must be byte-identical after a part-way extraction "
            f"(pre-#2668 the members were written straight onto it)\nbefore: {before!r}\nafter:  {after!r}"
        )
        leftovers = deployed_vm.ssh(f"/bin/ls -A {target}").stdout.split()
        assert leftovers == ["served.dat"], (
            f"expected only the tree in service — no members, no staging directory; found: {leftovers!r}"
        )
    finally:
        deployed_vm.ssh(f"/bin/rm -rf {workdir}")


@pytest.mark.timeout(180)
def test_geoip_healthy_archive_still_publishes_every_member(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """issue #2668: staging is a pass-through for a healthy archive.

    The refusal above is only worth having if a real GeoIP update still lands, and
    the publication is a rename per member on the appliance's own filesystem.

    Given a published tree in service and a healthy two-member GeoIP archive
    When  pfb_download() fetches it as a geoip extra
    Then  the download succeeds, both members are published with --strip=1 applied,
      the unrelated file already in service survives, and nothing is left staged.
    """
    workdir = f"{_PFB2668_WORKDIR}_healthy"
    target = f"{workdir}/share"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("d/pfb2668_a.csv", "192.0.2.31\n")  # inert RFC 5737 data
        z.writestr("d/pfb2668_b.csv", "192.0.2.32\n")
    feed_url = mock_feeds.register("pfb2668_healthy.zip", buf.getvalue())
    try:
        deployed_vm.ssh(f"/bin/rm -rf {workdir} && /bin/mkdir -p {target}")
        deployed_vm.ssh(f"/bin/echo 203.0.113.99 > {target}/served.dat")
        served_before = _published_tree(deployed_vm, target)

        out = _adr46_download(deployed_vm, feed_url, f"{workdir}/dl.zip", target, "geoip")

        assert "PFB_DL_TRUE" in out, (
            f"expected pfb_download success flag TRUE for a healthy GeoIP archive; got: {out!r}"
        )
        published = sorted(deployed_vm.ssh(f"/bin/ls -A {target}").stdout.split())
        assert published == ["pfb2668_a.csv", "pfb2668_b.csv", "served.dat"], (
            f"expected both members published beside the tree in service; found: {published!r}"
        )
        assert "  ./served.dat" in _published_tree(deployed_vm, target), "the file in service was dropped"
        assert served_before.endswith("  ./served.dat")
    finally:
        deployed_vm.ssh(f"/bin/rm -rf {workdir}")


@pytest.mark.timeout(120)
def test_top1m_file_target_rejects_multifile_and_retains_active(
    deployed_vm: SmokeVM, mock_feeds: _MockFeedServer
) -> None:
    """TOP1M file targets accept one payload only; rejected archives leave state untouched."""
    workdir = f"{_ADR46_WORKDIR}_file_reject"
    target = f"{workdir}/top-1m.csv"
    base = f"{workdir}/top-1m.csv.zip"
    marker = f"{h.PFB_DBDIR}/top-1m.update"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("d/top_a.csv", "new-a\n")
        z.writestr("d/top_b.csv", "new-b\n")
    feed_url = mock_feeds.register("top1m_file_reject.zip", buf.getvalue())
    try:
        deployed_vm.ssh(
            f"/bin/rm -rf {workdir} {marker} && /bin/mkdir -p {workdir} && "
            f"/bin/echo 'old active' > {target} && /bin/echo 'old raw' > {base}.orig"
        )
        out = _adr46_download(deployed_vm, feed_url, base, target, "top1m")
        assert "PFB_DL_FALSE" in out, f"multi-member ZIP must reject a file target: {out!r}"
        state = (
            deployed_vm.ssh(
                f"/bin/cat {target}; /bin/cat {base}.orig; "
                f"test -e {marker} && echo MARKER; test -e {base}.raw && echo RAW"
            )
            .stdout.strip()
            .splitlines()
        )
        assert state == ["old active", "old raw"], f"rejected download changed active/baseline: {state!r}"
    finally:
        deployed_vm.ssh(f"/bin/rm -rf {workdir} {marker}")


@pytest.mark.timeout(120)
def test_top1m_file_target_single_member_publishes_atomically(
    deployed_vm: SmokeVM, mock_feeds: _MockFeedServer
) -> None:
    """A single regular ZIP member replaces the active file and records raw/hash after publish."""
    workdir = f"{_ADR46_WORKDIR}_file_single"
    target = f"{workdir}/top-1m.csv"
    base = f"{workdir}/top-1m.csv.zip"
    marker = f"{h.PFB_DBDIR}/top-1m.update"
    body = "1,example.test\n"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("d/top.csv", body)
    feed_url = mock_feeds.register("top1m_file_single.zip", buf.getvalue())
    try:
        deployed_vm.ssh(  # fmt: skip
            f"/bin/rm -rf {workdir} {marker} && /bin/mkdir -p {workdir} && /bin/echo 'old active' > {target}"
        )
        out = _adr46_download(deployed_vm, feed_url, base, target, "top1m")
        assert "PFB_DL_TRUE" in out, f"single-member ZIP must publish: {out!r}"
        state = (
            deployed_vm.ssh(
                f"/bin/cat {target}; test -s {base}.orig && echo ORIG; "
                f"test -s {base}.xxhash128 && echo HASH; test -e {marker} && echo MARKER"
            )
            .stdout.strip()
            .splitlines()
        )
        assert state == [body.rstrip("\n"), "ORIG", "HASH", "MARKER"], (
            f"active/raw/hash/marker publication state unexpected: {state!r}"
        )
    finally:
        deployed_vm.ssh(f"/bin/rm -rf {workdir} {marker}")


@pytest.mark.timeout(120)
def test_top1m_file_target_hostile_and_truncated_archives_retain_active(
    deployed_vm: SmokeVM, mock_feeds: _MockFeedServer
) -> None:
    """Traversal, absolute, symlink-like, empty, and truncated ZIPs never reach active state."""
    workdir = f"{_ADR46_WORKDIR}_file_hostile"
    target = f"{workdir}/top-1m.csv"
    base = f"{workdir}/top-1m.csv.zip"
    marker = f"{h.PFB_DBDIR}/top-1m.update"
    archives: list[tuple[str, bytes]] = []
    for name, member in (("traversal.zip", "../escape.csv"), ("absolute.zip", "/absolute.csv")):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr(member, "escape\n")
        archives.append((name, buf.getvalue()))
    symlink = io.BytesIO()
    with zipfile.ZipFile(symlink, "w") as z:
        info = zipfile.ZipInfo("d/link.csv")
        info.create_system = 3
        info.external_attr = (0o120777 << 16) | 0xA000
        z.writestr(info, "../outside.csv")
    archives.append(("symlink.zip", symlink.getvalue()))
    empty = io.BytesIO()
    with zipfile.ZipFile(empty, "w"):
        pass
    archives.append(("empty.zip", empty.getvalue()))
    valid = io.BytesIO()
    with zipfile.ZipFile(valid, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("d/top.csv", "ok\n")
    archives.append(("truncated.zip", valid.getvalue()[:20]))
    try:
        deployed_vm.ssh(
            f"/bin/rm -rf {workdir} {marker} && /bin/mkdir -p {workdir} && "
            f"/bin/echo 'old active' > {target} && /bin/echo 'old raw' > {base}.orig"
        )
        for name, payload in archives:
            feed_url = mock_feeds.register(name, payload)
            out = _adr46_download(deployed_vm, feed_url, base, target, "top1m")
            assert "PFB_DL_FALSE" in out, f"hostile {name} unexpectedly published: {out!r}"
            active = deployed_vm.ssh(f"/bin/cat {target}").stdout.strip()
            assert active == "old active", f"hostile {name} changed active file: {active!r}"
    finally:
        deployed_vm.ssh(f"/bin/rm -rf {workdir} {marker}")


@pytest.mark.timeout(120)
def test_adr46_hostile_member_geoip_gz_rejected(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """ADR-46: the gzip GeoIP branch rejects a hostile-member tar.gz BEFORE extraction.

    Site-specific wiring pin for the gzip GeoIP branch, which since issue #2668
    stages inside `{geoipshare}` before publishing -- its ADR-45 probe is only
    `gunzip -t` (gzip-stream integrity), so the member guard is the ONLY inner-tar
    inspection on this path. Fixture archive_traversal.tar.gz (see
    fixtures/README.md): benign `cat/domains` + hostile `../pfb_adr46_escape.txt`.
    Deliberately hostile-only: a benign geoip run would extract into the REAL
    /usr/local/share/GeoIP; the benign pass-through is pinned on the ZIP site's
    test_adr46_legit_multifile_zip_still_imports instead.

    Given a clean work dir, no escape file beside the geoipshare dir, and the
      stage=member delta baseline,
    When  pfb_download() fetches the traversal tar.gz as type='geoip',
    Then  its result success flag is FALSE, the canonical stage=member line names the hostile
      member, the archive is unlinked, and no escape file appeared.
    """
    marker = "stage=member reason=unsafe_member_name detected=../pfb_adr46_escape.txt"
    workdir = f"{_ADR46_WORKDIR}_geoipgz"
    # --strip=1 -C /usr/local/share/GeoIP + a '../' member would land here:
    escape_file = "/usr/local/share/pfb_adr46_escape.txt"
    try:
        # Given -- clean slate + delta baseline.
        deployed_vm.ssh(f"/bin/rm -rf {workdir} {escape_file} && /bin/mkdir -p {workdir}")
        before = h.count_log_marker(deployed_vm, h.PFB_LOG, marker)

        # When -- drive the gzip GeoIP branch directly at the traversal fixture.
        out = _adr46_download(
            deployed_vm,
            mock_feeds.feed_url("archive_traversal.tar.gz"),
            f"{workdir}/dl.tgz",
            "adr46geo",
            "geoip",
        )

        # Then -- explicit reject before any disk write.
        assert "PFB_DL_FALSE" in out, (
            f"expected pfb_download success flag FALSE on a '..'-member tar.gz via the gzip GeoIP "
            f"branch (pre-guard it silently reported success); got stdout: {out!r}"
        )
        after = h.count_log_marker(deployed_vm, h.PFB_LOG, marker)
        if not (after > before):
            raise AssertionError(
                f"expected a NEW line matching {marker!r} in {h.PFB_LOG} after the geoip tar.gz "
                f"download; count before={before} after={after}\n"
                f"recent pfb_validate lines actually in the log:\n{_recent_validate_lines(deployed_vm)}"
            )
        leftovers = deployed_vm.ssh(
            f"test -e {workdir}/dl.tgz.raw && echo RAW-PRESENT; test -e {escape_file} && echo ESCAPE-PRESENT"
        ).stdout.strip()
        assert leftovers == "", (
            f"expected the archive unlinked and no escape file beside geoipshare after the "
            f"member-guard reject; found: {leftovers!r}"
        )
    finally:
        deployed_vm.ssh(f"/bin/rm -rf {workdir} {escape_file}")


@pytest.mark.timeout(120)
def test_adr46_hostile_member_blacklist_rejected(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """ADR-46: the UT1/blacklist branch rejects a hostile-member tar.gz BEFORE extraction.

    Site-specific wiring pin for the least-trusted extraction (a THIRD-PARTY archive
    whose member names feed on-disk filenames): the blacklist branch renames the
    download (strips `.raw`), derives the category dir from the file name, then
    extracts with `tar -xf … -C {dbdir}/<name>/`. The guard must list the RENAMED
    path ($file_dwn) and unlink IT on reject -- exactly the variable plumbing a
    generic predicate test cannot see. Same fixture as the geoip case.

    Given a clean work dir and category dir, and the stage=member delta baseline,
    When  pfb_download() fetches the traversal tar.gz as type='blacklist' with a
      file_dwn ending .tar.gz (the branch's naming contract),
    Then  its result success flag is FALSE, the canonical stage=member line is logged, the renamed
      archive is unlinked, and the category dir contains no extracted files.
    """
    marker = "stage=member reason=unsafe_member_name detected=../pfb_adr46_escape.txt"
    workdir = f"{_ADR46_WORKDIR}_ut1"
    category_dir = f"{h.PFB_DBDIR}/adr46ut1"
    escape_file = f"{h.PFB_DBDIR}/pfb_adr46_escape.txt"
    try:
        # Given -- clean slate + delta baseline.
        deployed_vm.ssh(f"/bin/rm -rf {workdir} {category_dir} {escape_file} && /bin/mkdir -p {workdir}")
        before = h.count_log_marker(deployed_vm, h.PFB_LOG, marker)

        # When -- drive the blacklist branch; file_dwn must end .tar.gz (category name source).
        out = _adr46_download(
            deployed_vm,
            mock_feeds.feed_url("archive_traversal.tar.gz"),
            f"{workdir}/adr46ut1.tar.gz",
            "adr46ut1",
            "blacklist",
        )

        # Then -- explicit reject; the renamed archive is gone; nothing extracted.
        assert "PFB_DL_FALSE" in out, (
            f"expected pfb_download success flag FALSE on a '..'-member tar.gz via the blacklist "
            f"branch (pre-guard it silently reported success); got stdout: {out!r}"
        )
        after = h.count_log_marker(deployed_vm, h.PFB_LOG, marker)
        if not (after > before):
            raise AssertionError(
                f"expected a NEW line matching {marker!r} in {h.PFB_LOG} after the blacklist tar.gz "
                f"download; count before={before} after={after}\n"
                f"recent pfb_validate lines actually in the log:\n{_recent_validate_lines(deployed_vm)}"
            )
        leftovers = deployed_vm.ssh(
            f"/bin/ls -A {category_dir} 2>/dev/null; "
            f"test -e {workdir}/adr46ut1.tar.gz && echo RENAMED-ARCHIVE-PRESENT; "
            f"test -e {workdir}/adr46ut1.tar.gz.raw && echo RAW-PRESENT; "
            f"test -e {escape_file} && echo ESCAPE-PRESENT"
        ).stdout.strip()
        assert leftovers == "", (
            f"expected an empty category dir, the renamed archive unlinked, and no escape file "
            f"after the member-guard reject; found: {leftovers!r}"
        )
    finally:
        deployed_vm.ssh(f"/bin/rm -rf {workdir} {category_dir} {escape_file}")


def _blacklist_tar_gz(top: str, category: str, domain: str) -> bytes:
    """A UT1-shaped blacklist archive: gzip(tar) holding ``<top>/<category>/domains``.

    Mirrors the real UT1 layout the blacklist branch's ``-s`` rewrite rules expect,
    so the extracted category file lands at ``{dbdir}/<top>/<top>_<category>``.
    """
    payload = f"{domain}\n".encode()
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tar:
        info = tarfile.TarInfo(f"{top}/{category}/domains")
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    return gzip.compress(raw.getvalue(), mtime=0)


@pytest.mark.timeout(120)
def test_blacklist_archive_survives_gzip_content_encoding(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """issue #2634: a feed labelled Content-Encoding: gzip still ingests as the PUBLISHED archive.

    Given an origin serving a valid UT1-shaped ``.tar.gz`` under a
      ``Content-Encoding: gzip`` label,
    When  pfb_download() fetches it as type='blacklist',
    Then  the download succeeds, the stored archive is still gzip (not its inner tar),
      and the category file is extracted from it.
    """
    domain = h.unique_domain("pfb2634")
    name = "pfb2634.tar.gz"
    workdir = f"{_ADR46_WORKDIR}_2634"
    category_dir = f"{h.PFB_DBDIR}/pfb2634"
    archive = f"{workdir}/pfb2634.tar.gz"
    try:
        # Given -- clean slate; the origin labels the archive as gzip-encoded.
        deployed_vm.ssh(f"/bin/rm -rf {workdir} {category_dir} && /bin/mkdir -p {workdir}")
        feed_url = mock_feeds.register(name, _blacklist_tar_gz("pfb2634", "testcat", domain))
        mock_feeds.enable_content_encoding_gzip(name)

        # When -- the blacklist branch fetches it.
        out = _adr46_download(deployed_vm, feed_url, archive, "pfb2634", "blacklist")

        # Then -- three independently failable asserts (issue #2638 B4 / PR #2639).
        # The stored-mime check must fail on its own if the body is a decoded tar
        # even when download succeeded and categories extracted.
        assert "PFB_DL_TRUE" in out, (
            f"expected pfb_download success on a valid .tar.gz served with Content-Encoding: gzip; got stdout: {out!r}"
        )
        stored = deployed_vm.ssh(f"/usr/bin/file -b --mime-type {archive} 2>&1").stdout.strip()
        assert stored in {"application/gzip", "application/x-gzip"}, (
            f"expected the stored archive to still be the PUBLISHED gzip, not its "
            f"decoded inner tar; /usr/bin/file reported {stored!r} for {archive}"
        )
        extracted = deployed_vm.ssh(f"/bin/cat {category_dir}/pfb2634_testcat 2>&1").stdout
        assert domain in extracted, (
            f"expected {domain!r} in the extracted category file "
            f"{category_dir}/pfb2634_testcat; got: {extracted!r}\n"
            f"category dir now holds: "
            f"{deployed_vm.ssh(f'/bin/ls -A {category_dir} 2>&1').stdout!r}"
        )
    finally:
        deployed_vm.ssh(f"/bin/rm -rf {workdir} {category_dir}")


def _blacklist_tar(top: str, category: str, domain: str) -> bytes:
    """UT1-shaped blacklist archive as a plain tar (issue #2632 / #2638)."""
    payload = f"{domain}\n".encode()
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tar:
        info = tarfile.TarInfo(f"{top}/{category}/domains")
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    return raw.getvalue()


@pytest.mark.timeout(120)
def test_blacklist_plain_tar_extracts_categories(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """issue #2638: a plain-tar Blacklist body extracts categories (the #2632 unpack).

    Given an origin serving a UT1-shaped tar (no gzip wrapper),
    When  pfb_download() fetches it as type='blacklist',
    Then  the download succeeds and the category file is extracted.
    """
    domain = h.unique_domain("pfb2638")
    workdir = "/tmp/pfb2638_dl"
    archive = f"{workdir}/pfb2638.tar"
    category_dir = f"{h.PFB_DBDIR}/pfb2638"
    try:
        deployed_vm.ssh("/bin/rm", "-rf", workdir, category_dir, timeout=30.0)
        mk = deployed_vm.ssh("/bin/mkdir", "-p", workdir)
        assert mk.returncode == 0, f"mkdir failed: rc={mk.returncode} stderr={mk.stderr!r}"
        box_mime = _box_mime_type(deployed_vm, _blacklist_tar("pfb2638", "testcat", domain))
        assert box_mime == "application/x-tar", f"expected application/x-tar, got {box_mime!r}"
        feed_url = mock_feeds.register("pfb2638.tar", _blacklist_tar("pfb2638", "testcat", domain))
        out = _adr46_download(deployed_vm, feed_url, archive, "pfb2638", "blacklist")
        assert "PFB_DL_TRUE" in out, f"expected pfb_download success on a plain-tar Blacklist body; got {out!r}"
        extracted = deployed_vm.ssh(f"/bin/cat {category_dir}/pfb2638_testcat 2>&1").stdout
        assert domain in extracted, (
            f"expected {domain!r} in {category_dir}/pfb2638_testcat; got {extracted!r}; "
            f"ls={deployed_vm.ssh(f'/bin/ls -A {category_dir} 2>&1').stdout!r}"
        )
    finally:
        deployed_vm.ssh("/bin/rm", "-rf", workdir, category_dir)


@pytest.mark.timeout(120)
def test_ip_tar_feed_imports_members(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """issue #2638 / #2510: a tar-wrapped IP list imports member addresses, not framing.

    Fail-before: x-tar was rejected (or scraped as text). Pass-after: tar -xOf
    publishes the inner list and the member IP loads.
    """
    payload = _ADR44_BODY.encode()
    framing_bytes = b"NOT-A-LIST-TOKEN\n"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo("list.txt")
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
        readme = tarfile.TarInfo("README")
        readme.size = len(framing_bytes)
        tar.addfile(readme, io.BytesIO(framing_bytes))
    feed_url = mock_feeds.register("adr2638.tar", buf.getvalue())
    spec = h.IpCase(aliasname="adr2638tar", feed_url=feed_url, header="adr2638tar", family="v4")
    assert spec.alias not in h.pfctl_tables(deployed_vm), f"{spec.alias} present before the tar feed was ever loaded"
    with h.CaseContext(deployed_vm, spec):
        members = h.pfctl_table_members(deployed_vm, spec.alias)
        assert h.member_present(members, _ADR44_MEMBER), (
            f"expected {_ADR44_MEMBER!r} in {spec.alias} after tar extraction, got: {members}"
        )
        assert not any("NOT-A-LIST-TOKEN" in m or "README" in m for m in members), (
            f"tar framing must not reach the alias; members={members}"
        )


def _blacklist_tar_domains_dir_only(top: str, category: str) -> bytes:
    """Case-3 archive: the only *domains match is a directory (issue #2638)."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tar:
        info = tarfile.TarInfo(f"{top}/{category}/domains")
        info.type = tarfile.DIRTYPE
        tar.addfile(info)
    return raw.getvalue()


@pytest.mark.timeout(120)
def test_blacklist_plain_tar_directory_only_keeps_categories(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """issue #2638 case 3: a *domains directory must not publish over live categories.

    Given previously extracted Blacklist category files and a tar whose only
      ``*domains`` match is a directory (bsdtar exit 0, zero files),
    When  pfb_download() fetches it as type='blacklist',
    Then  the download fails and the planted category file is unchanged.
    """
    workdir = "/tmp/pfb2638_c3"
    category_dir = f"{h.PFB_DBDIR}/pfb2638c3"
    sentinel_path = f"{category_dir}/pfb2638c3_testcat"
    sentinel = "keep-me.example.test\n"
    archive = f"{workdir}/pfb2638c3.tar"
    try:
        deployed_vm.ssh("/bin/rm", "-rf", workdir, category_dir, timeout=30.0)
        mk = deployed_vm.ssh("/bin/mkdir", "-p", workdir, category_dir)
        assert mk.returncode == 0, f"mkdir failed: rc={mk.returncode} stderr={mk.stderr!r}"
        _plant_guest_text(deployed_vm, sentinel_path, sentinel)
        before = deployed_vm.ssh(f"/bin/cat {sentinel_path} 2>&1").stdout
        assert before == sentinel
        feed_url = mock_feeds.register("pfb2638c3.tar", _blacklist_tar_domains_dir_only("pfb2638c3", "testcat"))
        out = _adr46_download(deployed_vm, feed_url, archive, "pfb2638c3", "blacklist")
        assert "PFB_DL_TRUE" not in out, f"directory-only tar must not succeed; got {out!r}"
        after = deployed_vm.ssh(f"/bin/cat {sentinel_path} 2>&1").stdout
        assert after == sentinel, f"live category must survive; before={before!r} after={after!r}"
    finally:
        deployed_vm.ssh("/bin/rm", "-rf", workdir, category_dir)


def _plant_guest_text(vm: SmokeVM, path: str, contents: str) -> None:
    """Write ``contents`` to ``path`` on the guest via tee stdin.

    Same plant as ``write_local_feed``: stdin, not a printf format string,
    so the bytes on disk are the contents argument.
    """
    planted = subprocess.run(
        vm.ssh_argv("tee", path),
        input=contents,
        capture_output=True,
        text=True,
        timeout=30.0,
        check=False,
    )
    assert planted.returncode == 0, f"tee {path} failed: rc={planted.returncode} stderr={planted.stderr!r}"


@pytest.mark.timeout(120)
def test_blacklist_nongzip_body_fails_closed(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """issue #2635: a MIME-allowlisted non-archive Blacklist body must fail, not succeed empty.

    Given previously extracted Blacklist category files and an origin answering
      the archive URL with HTTP 200 HTML (allow-listed ``text/html``),
    When  pfb_download() fetches it as type='blacklist',
    Then  the result is failure, a canonical reject names the detected type,
      and the existing category files are left untouched.

    Fail-before: the uncompressed Blacklist branch sets ``$retval = 0`` with no
    extract, so this reports PFB_DL_TRUE (a successful empty update). Pass-after:
    fail-closed return; the planted sentinel stays byte-identical. Finalize writes
    ``{downloadPath}.orig``, not the category file — the untouched contract is
    this sentinel, asserted before and after the download.
    """
    fixture = "html_error_page.html"
    # Staging dir is /tmp, not under dbdir. Gzip Blacklist extracts into
    # {dbdir}/{header}; a downloadPath next to that tree is not the category dir.
    workdir = "/tmp/pfb2635_dl"
    category_dir = f"{h.PFB_DBDIR}/pfb2635"
    sentinel_path = f"{category_dir}/pfb2635_testcat"
    sentinel = "keep-me.example.test\n"
    archive = f"{workdir}/pfb2635.tar.gz"
    marker = "pfb_validate: REJECT feed=pfb2635 stage=extract reason=blacklist_not_archive"
    try:
        deployed_vm.ssh("/bin/rm", "-rf", workdir, category_dir, timeout=30.0)
        mk = deployed_vm.ssh("/bin/mkdir", "-p", workdir, category_dir)
        assert mk.returncode == 0, f"mkdir failed: rc={mk.returncode} stderr={mk.stderr!r}"
        _plant_guest_text(deployed_vm, sentinel_path, sentinel)
        planted = deployed_vm.ssh("/bin/cat", sentinel_path).stdout
        assert planted == sentinel, (
            f"before-state: planted sentinel must be {sentinel!r}, got {planted!r}; "
            f"ls={deployed_vm.ssh('/bin/ls', '-la', category_dir).stdout!r}"
        )
        box_mime = _box_mime_type(deployed_vm, _fixture_bytes(fixture))
        assert box_mime in _SANITY_SCANNED_MIME_TYPES, (
            f"expected {fixture} on-box MIME in {_SANITY_SCANNED_MIME_TYPES}, got {box_mime!r}"
        )
        feed_url = mock_feeds.register("pfb2635.html", _fixture_bytes(fixture))
        before = h.count_log_marker(deployed_vm, h.PFB_LOG, marker)

        out = _adr46_download(deployed_vm, feed_url, archive, "pfb2635", "blacklist")

        assert "PFB_DL_FALSE" in out, (
            f"expected pfb_download failure on a non-gzip Blacklist HTML body; got stdout: {out!r}"
        )
        after = h.count_log_marker(deployed_vm, h.PFB_LOG, marker)
        assert after > before, (
            f"expected a NEW {marker!r} line in {h.PFB_LOG}; before={before} after={after}\n"
            f"recent pfb_validate lines:\n{_recent_validate_lines(deployed_vm)}"
        )
        kept = deployed_vm.ssh("/bin/cat", sentinel_path).stdout
        listing = deployed_vm.ssh("/bin/ls", "-la", category_dir).stdout
        assert kept == sentinel, (
            f"existing category file must be untouched; {sentinel_path} now holds {kept!r}; ls={listing!r}"
        )
    finally:
        deployed_vm.ssh("/bin/rm", "-rf", workdir, category_dir)


def _blacklist_bzip2_body() -> bytes:
    return bz2.compress(b"keep-me.example.test\n")


def _blacklist_zip_body() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("list.txt", "keep-me.example.test\n")
    return buf.getvalue()


@pytest.mark.parametrize(
    ("kind", "suffix", "mime", "body_fn"),
    [
        ("bzip2", ".bz2", "application/x-bzip2", _blacklist_bzip2_body),
        ("zip", ".zip", "application/zip", _blacklist_zip_body),
    ],
)
@pytest.mark.timeout(120)
def test_blacklist_bzip2_or_zip_body_fails_closed(
    deployed_vm: SmokeVM,
    mock_feeds: _MockFeedServer,
    kind: str,
    suffix: str,
    mime: str,
    body_fn: Callable[[], bytes],
) -> None:
    """issue #2739: a bzip2 or zip Blacklist body must fail, not succeed empty.

    Given previously extracted Blacklist category files and an origin answering
      the archive URL with HTTP 200 valid bzip2 or zip bytes,
    When  pfb_download() fetches it as type='blacklist',
    Then  the result is failure, a canonical reject names the detected type,
      and the existing category files are left untouched.

    Fail-before: those arms have no Blacklist branch, so a valid archive
    extracts onto ``.orig`` and returns success while ``{dbdir}/{provider}/``
    is unchanged. Pass-after: the ``blacklist_not_archive`` reject; the planted
    sentinel stays byte-identical.
    """
    header = f"pfb2739{kind}"
    workdir = f"/tmp/{header}_dl"
    category_dir = f"{h.PFB_DBDIR}/{header}"
    sentinel_path = f"{category_dir}/{header}_testcat"
    sentinel = "keep-me.example.test\n"
    archive = f"{workdir}/{header}{suffix}"
    marker = f"pfb_validate: REJECT feed={header} stage=extract reason=blacklist_not_archive"
    body = body_fn()
    try:
        deployed_vm.ssh("/bin/rm", "-rf", workdir, category_dir, timeout=30.0)
        mk = deployed_vm.ssh("/bin/mkdir", "-p", workdir, category_dir)
        assert mk.returncode == 0, f"mkdir failed: rc={mk.returncode} stderr={mk.stderr!r}"
        _plant_guest_text(deployed_vm, sentinel_path, sentinel)
        planted = deployed_vm.ssh("/bin/cat", sentinel_path).stdout
        assert planted == sentinel, (
            f"before-state: planted sentinel must be {sentinel!r}, got {planted!r}; "
            f"ls={deployed_vm.ssh('/bin/ls', '-la', category_dir).stdout!r}"
        )
        box_mime = _box_mime_type(deployed_vm, body)
        assert box_mime == mime, f"expected on-box MIME {mime!r} for {kind}, got {box_mime!r}"
        feed_url = mock_feeds.register(f"{header}{suffix}", body)
        before = h.count_log_marker(deployed_vm, h.PFB_LOG, marker)

        out = _adr46_download(deployed_vm, feed_url, archive, header, "blacklist")

        assert "PFB_DL_FALSE" in out, f"expected pfb_download failure on a {kind} Blacklist body; got stdout: {out!r}"
        after = h.count_log_marker(deployed_vm, h.PFB_LOG, marker)
        assert after > before, (
            f"expected a NEW {marker!r} line in {h.PFB_LOG}; before={before} after={after}\n"
            f"recent pfb_validate lines:\n{_recent_validate_lines(deployed_vm)}"
        )
        kept = deployed_vm.ssh("/bin/cat", sentinel_path).stdout
        listing = deployed_vm.ssh("/bin/ls", "-la", category_dir).stdout
        assert kept == sentinel, (
            f"existing category file must be untouched; {sentinel_path} now holds {kept!r}; ls={listing!r}"
        )
    finally:
        deployed_vm.ssh("/bin/rm", "-rf", workdir, category_dir)


@pytest.mark.timeout(180)
def test_blacklist_download_name_keys_on_provider_id(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """issue #2636: the UT1 download name comes from the provider id, not from a literal feed URL.

    Given a UT1 provider whose feed URL is NOT the historical FTP one,
    When  the Blacklist download runs for it,
    Then  its archive is named for the provider and the categories land in the provider's
      own directory.
    """
    domain = h.unique_domain("pfb2636")
    # The published basename, exactly as the origin serves it -- deliberately not 'ut1'.
    feed_url = mock_feeds.register("blacklists.tar.gz", _blacklist_tar_gz("blacklists", "testcat", domain))
    provider_dir = f"{h.PFB_DBDIR}/ut1"
    stray_dir = f"{h.PFB_DBDIR}/blacklists"
    # Snapshotted OUTSIDE the try so teardown restores what was there rather than deleting
    # it, and so a failure here surfaces as itself instead of an undefined name in finally.
    before = h.php_eval(
        deployed_vm,
        "echo base64_encode(serialize(config_get_path('installedpackages/pfblockerngblacklist', NULL)));",
    ).stdout.strip()
    try:
        # Given -- a UT1 provider pointed at that URL, one category selected.
        deployed_vm.ssh(f"/bin/rm -rf {provider_dir} {stray_dir}")
        provider = h._php_kv_array(  # noqa: SLF001
            {"title": "UT1", "xml": "ut1", "feed": feed_url, "selected": "testcat"}
        )
        h.php_eval(
            deployed_vm,
            "config_set_path('installedpackages/pfblockerngblacklist', array("
            "'blacklist_enable' => 'on', 'blacklist_selected' => 'ut1', "
            f"'item' => array({provider})));\n"
            "write_config('pfBlockerNG smoke: issue #2636 provider fixture');\n"
            "echo 'OK';",
        )

        # When -- the Blacklist download path runs.
        deployed_vm.ssh(f"/usr/local/bin/php -f {h.PFB_CLI} bls ut1", timeout=180)

        # Then -- named for the provider, not for the URL's basename.
        listing = deployed_vm.ssh(f"/bin/ls -A {provider_dir} 2>&1").stdout
        assert "ut1_testcat" in listing, (
            f"expected the category file 'ut1_testcat' in {provider_dir}; got: {listing!r}\n"
            f"{stray_dir} holds: {deployed_vm.ssh(f'/bin/ls -A {stray_dir} 2>&1').stdout!r}"
        )
        archive = deployed_vm.ssh(f"/bin/ls -A {h.PFB_DBDIR}/ut1.tar.gz 2>&1").stdout.strip()
        assert archive.endswith("ut1.tar.gz"), (
            f"expected the download itself to be named for the provider at {h.PFB_DBDIR}/ut1.tar.gz; got: {archive!r}"
        )
        extracted = deployed_vm.ssh(f"/bin/cat {provider_dir}/ut1_testcat 2>&1").stdout
        assert domain in extracted, f"expected {domain!r} in {provider_dir}/ut1_testcat; got: {extracted!r}"
    finally:
        deployed_vm.ssh(f"/bin/rm -rf {provider_dir} {stray_dir}")
        h.php_eval(
            deployed_vm,
            f"$before = unserialize(base64_decode({h._php_str(before)}));\n"  # noqa: SLF001
            "$before === NULL\n"
            "    ? config_del_path('installedpackages/pfblockerngblacklist')\n"
            "    : config_set_path('installedpackages/pfblockerngblacklist', $before);\n"
            "write_config('pfBlockerNG smoke: issue #2636 fixture teardown');\n"
            "echo 'OK';",
        )


# --------------------------------------------------------------------------- #
# Structured-text feed shapes + the reject path (issue #2511)
#
# The download MIME allow-list ($pfb['mime_types'], pfblockerng.inc) admits JSON, NDJSON,
# CSV and XML alongside plain text, because real feeds are served in those shapes and the
# normaliser scrapes address tokens out of the surrounding syntax. That behaviour had no
# live coverage, and neither did the refusal of a type the list does NOT admit.
# --------------------------------------------------------------------------- #

_STRUCTURED_SHAPES = [
    # (label, fixture, the type file(1) must report on the box, the addresses the feed holds)
    ("json", "ip_json.json", "application/json", ("192.0.2.71", "198.51.100.71")),
    ("csv", "ip_csv.csv", "text/csv", ("192.0.2.72", "198.51.100.72", "203.0.113.72")),
    ("xml", "ip_xml.xml", "text/xml", ("192.0.2.73", "198.51.100.73")),
    ("ndjson", "ip_ndjson.ndjson", "application/x-ndjson", ("192.0.2.74", "198.51.100.74")),
]


@pytest.mark.smoke
@pytest.mark.timeout(120)  # a full update + targeted reload exceeds the tier's 30s default
@pytest.mark.parametrize(
    ("label", "fixture", "expected_mime", "expected_members"),
    _STRUCTURED_SHAPES,
    ids=[row[0] for row in _STRUCTURED_SHAPES],
)
def test_structured_text_feed_imports(
    deployed_vm: SmokeVM,
    mock_feeds: _MockFeedServer,
    label: str,
    fixture: str,
    expected_mime: str,
    expected_members: tuple[str, ...],
) -> None:
    """An allow-listed structured-text body loads its addresses into the pf table.

    The MIME gate sniffs the DOWNLOADED FILE (``file -b --mime-type``), not the HTTP
    header, so the fixture's own bytes decide which allow-list entry admits it. The row
    asserts that verdict FIRST, on the exact served bytes: without it a fixture that
    libmagic reports as ``text/plain`` would pass this row while covering nothing but the
    plain-text entry every other case already exercises.

    The table is then compared as a SET. A member-only assertion cannot fail when a feed
    imports more than it should, and the addresses here are the whole feed.
    """
    feed_url = mock_feeds.feed_url(fixture)
    spec = h.IpCase(aliasname=f"smokemime{label}", feed_url=feed_url, header=f"smokemime{label}", family="v4")

    # The branch this row exists to cover, proven on the bytes the guest actually fetches.
    sniffed = _box_mime_type(deployed_vm, _fixture_bytes(fixture))
    assert sniffed == expected_mime, (
        f"{fixture} must reach the {expected_mime!r} allow-list entry, but file(1) on the box "
        f"reports {sniffed!r} — this row would cover that entry instead"
    )

    assert spec.alias not in h.pfctl_tables(deployed_vm), (
        f"{spec.alias} present before the {label} feed was ever loaded"
    )

    with h.CaseContext(deployed_vm, spec):
        # pf reports a /32 host route bare, so the expected set holds plain addresses.
        members = h.pfctl_table_members(deployed_vm, spec.alias)
        assert sorted(members) == sorted(expected_members), (
            f"{spec.alias} must hold exactly the {label} feed's addresses; "
            f"expected {sorted(expected_members)}, got {sorted(members)}"
        )


@pytest.mark.smoke
@pytest.mark.timeout(120)
def test_unsupported_mime_feed_rejected(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """A body whose sniffed type is NOT allow-listed is refused, and no alias is created.

    ``.xz`` is absent from ``$pfb['mime_types']`` by design. Both halves matter: the reject
    line names the detected type, and the table stays absent — a partially imported list
    would be a worse failure than a refusal, and only the second assertion catches it.
    """
    feed_url = mock_feeds.feed_url("ip_unsupported_xz.xz")
    spec = h.IpCase(aliasname="smokemimexz", feed_url=feed_url, header="smokemimexz", family="v4")
    # Scoped to THIS feed and naming the detected type: the smoke VM is session-scoped, so a
    # bare `reason=mime_not_allowed` count would also be satisfied by another case's reject.
    marker = (
        f"pfb_validate: REJECT feed={spec.header}_v4 stage=mime reason=mime_not_allowed detected=application/x-xz rc=0"
    )

    sniffed = _box_mime_type(deployed_vm, _fixture_bytes("ip_unsupported_xz.xz"))
    assert sniffed == "application/x-xz", (
        f"the reject fixture must be sniffed as application/x-xz (a type the allow-list omits); "
        f"file(1) on the box reports {sniffed!r}"
    )

    assert spec.alias not in h.pfctl_tables(deployed_vm), (
        f"{spec.alias} present before the unsupported feed was ever loaded"
    )
    before = h.count_log_marker(deployed_vm, h.PFB_LOG, marker)

    with h.CaseContext(deployed_vm, spec):
        after = h.count_log_marker(deployed_vm, h.PFB_LOG, marker)
        assert after > before, (
            f"expected a NEW {marker!r} line after the .xz feed download; "
            f"before={before} after={after}\n"
            f"recent pfb_validate lines:\n{_recent_validate_lines(deployed_vm)}"
        )
        assert spec.alias not in h.pfctl_tables(deployed_vm), (
            f"{spec.alias} exists after an unsupported-MIME rejection — a refused feed must "
            f"never leave a table behind (a partial import is the failure this row guards)"
        )


# --------------------------------------------------------------------------- #
# issue #2660: the content-sanity verdicts cover an archive feed's EXTRACTED
# payload. A .gz/.bz2/.zip/.tar wire body is never one of the scanned text types,
# so the payload used to reach the parser with no verdict at all. The scan reads
# the STAGED extraction, so a verdict refuses the publication instead of
# replacing it -- pinned here by a '.orig' already in service.
# --------------------------------------------------------------------------- #


def _archive_of(kind: str, payload: bytes) -> bytes:
    """Wrap ``payload`` in each archive kind whose extraction publishes a text '.orig'."""
    if kind == "gz":
        return gzip.compress(payload, mtime=0)
    if kind == "bz2":
        return bz2.compress(payload)
    if kind == "zip":
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("payload.txt", payload)
        return buf.getvalue()
    if kind == "tar":
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            info = tarfile.TarInfo("payload.txt")
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))
        return buf.getvalue()
    raise AssertionError(f"unknown archive kind {kind!r}")


@pytest.mark.parametrize(
    ("kind", "suffix", "mime"),
    [
        ("gz", ".gz", "application/gzip"),
        ("bz2", ".bz2", "application/x-bzip2"),
        ("zip", ".zip", "application/zip"),
        ("tar", ".tar", "application/x-tar"),
    ],
)
@pytest.mark.timeout(180)
def test_extracted_error_page_rejected_and_publication_kept(
    deployed_vm: SmokeVM,
    mock_feeds: _MockFeedServer,
    kind: str,
    suffix: str,
    mime: str,
) -> None:
    """issue #2660: an archive whose payload is an HTML error page must fail the update.

    Both legs serve the SAME body and differ only in the flag, over two separate
    download paths -- each freshly seeded with a healthy '.orig', so the conditional-GET
    validators of one leg can never 304 the other.

    Given the scan OFF (the registered default) and a healthy '.orig' in service,
    When  pfb_download() fetches an archive whose extracted payload is the
      html_error_page fixture,
    Then  the download SUCCEEDS and the error page REPLACES the served payload -- the
      before-state this issue reports.
    Given the scan ON, the same body, and a second healthy '.orig' in service,
    When  the same fetch runs,
    Then  the download FAILS with 'stage=plaintext reason=html_error_page' naming the
      extracted payload, and the served '.orig' is byte-identical.
    """
    payload = _fixture_bytes("html_error_page.html")
    body = _archive_of(kind, payload)
    served = "203.0.113.7/32\n"
    workdir = f"/tmp/pfb2660_{kind}"
    base_off = f"{workdir}/off{kind}"
    base_on = f"{workdir}/on{kind}"
    header_on = f"pfb2660{kind}on"
    marker = f"pfb_validate: REJECT feed={header_on} stage=plaintext reason=html_error_page detected=on{kind}.orig"
    try:
        deployed_vm.ssh(f"/bin/rm -rf {workdir} && /bin/mkdir -p {workdir}")
        # The outer gate must route to the branch under test; a libmagic surprise has to
        # fail loudly rather than silently exercise a different arm.
        box_mime = _box_mime_type(deployed_vm, body)
        assert box_mime == mime, f"expected on-box MIME {mime!r} for the {kind} fixture, got {box_mime!r}"
        feed_url = mock_feeds.register(f"pfb2660_{kind}{suffix}", body)

        # Given -- scan OFF (also the registered default) + a healthy publication.
        h.set_feed_sanity(deployed_vm, False)
        _plant_guest_text(deployed_vm, f"{base_off}.orig", served)
        out_off = _adr46_download(deployed_vm, feed_url, base_off, f"pfb2660{kind}off", "")
        assert "PFB_DL_TRUE" in out_off, (
            f"before-state: with the scan off a {kind} archive carrying an error page must still "
            f"report success (that is the gap #2660 reports); got stdout: {out_off!r}"
        )
        published_off = deployed_vm.ssh("/bin/cat", f"{base_off}.orig").stdout
        assert published_off == payload.decode(), (
            f"before-state: the error page must have replaced the served payload with the scan off; "
            f"{base_off}.orig now holds {published_off!r}"
        )

        # When -- the same bytes with the scan ON, over its own seeded publication.
        h.set_feed_sanity(deployed_vm, True)
        _plant_guest_text(deployed_vm, f"{base_on}.orig", served)
        before = h.count_log_marker(deployed_vm, h.PFB_LOG, marker)
        out_on = _adr46_download(deployed_vm, feed_url, base_on, header_on, "")

        # Then -- refused, named, and the publication untouched.
        assert "PFB_DL_FALSE" in out_on, (
            f"expected pfb_download failure on a {kind} archive whose payload is an error page "
            f"with the scan on; got stdout: {out_on!r}"
        )
        after = h.count_log_marker(deployed_vm, h.PFB_LOG, marker)
        assert after > before, (
            f"expected a NEW {marker!r} line in {h.PFB_LOG}; before={before} after={after}\n"
            f"recent pfb_validate lines:\n{_recent_validate_lines(deployed_vm)}"
        )
        kept = deployed_vm.ssh("/bin/cat", f"{base_on}.orig").stdout
        assert kept == served, (
            f"a refused refresh must leave the served payload byte-identical; {base_on}.orig now "
            f"holds {kept!r}; ls={deployed_vm.ssh('/bin/ls', '-la', workdir).stdout!r}"
        )
    finally:
        h.set_feed_sanity(deployed_vm, False)
        deployed_vm.ssh(f"/bin/rm -rf {workdir}")


@pytest.mark.timeout(240)
def test_scan_on_keeps_ut1_and_geoip_archives_ingesting(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """issue #2660: the scan covers the text '.orig' publications and nothing else.

    A UT1 archive extracts a category tree and a GeoIP archive publishes to the share;
    neither is a text list, and each keeps its own validation. Turning the scan on must
    leave both ingesting and must draw no sanity verdict.

    Given the scan ON,
    When  pfb_download() fetches a UT1-shaped tar.gz and a multi-member GeoIP zip,
    Then  both succeed, the UT1 category file holds its domain, both GeoIP members are
      published, and no NEW 'stage=plaintext' line appears across the window.
    """
    domain = h.unique_domain("pfb2660ut1")
    workdir = "/tmp/pfb2660_regress"
    category_dir = f"{h.PFB_DBDIR}/pfb2660ut1"
    geoip_target = f"{workdir}/share"
    geoip_zip = io.BytesIO()
    with zipfile.ZipFile(geoip_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("d/pfb2660_a.csv", "192.0.2.31\n")  # inert RFC 5737 data
        zf.writestr("d/pfb2660_b.csv", "192.0.2.32\n")
    try:
        deployed_vm.ssh(f"/bin/rm -rf {workdir} {category_dir} && /bin/mkdir -p {workdir} {geoip_target}")
        h.set_feed_sanity(deployed_vm, True)
        before = h.count_log_marker(deployed_vm, h.PFB_LOG, "stage=plaintext")

        ut1_url = mock_feeds.register("pfb2660ut1.tar.gz", _blacklist_tar_gz("pfb2660ut1", "testcat", domain))
        out_ut1 = _adr46_download(deployed_vm, ut1_url, f"{workdir}/pfb2660ut1.tar.gz", "pfb2660ut1", "blacklist")
        assert "PFB_DL_TRUE" in out_ut1, (
            f"a real UT1 archive must still ingest with the scan on; got stdout: {out_ut1!r}"
        )
        extracted = deployed_vm.ssh(f"/bin/cat {category_dir}/pfb2660ut1_testcat 2>&1").stdout
        assert domain in extracted, (
            f"expected {domain!r} in {category_dir}/pfb2660ut1_testcat with the scan on; "
            f"got {extracted!r}; ls={deployed_vm.ssh(f'/bin/ls -A {category_dir} 2>&1').stdout!r}"
        )

        geoip_url = mock_feeds.register("pfb2660geoip.zip", geoip_zip.getvalue())
        out_geoip = _adr46_download(deployed_vm, geoip_url, f"{workdir}/geoip.zip", geoip_target, "geoip")
        assert "PFB_DL_TRUE" in out_geoip, (
            f"a real GeoIP archive must still ingest with the scan on; got stdout: {out_geoip!r}"
        )
        published = sorted(deployed_vm.ssh(f"/bin/ls -A {geoip_target}").stdout.split())
        assert published == ["pfb2660_a.csv", "pfb2660_b.csv"], (
            f"expected both GeoIP members published with the scan on; found: {published!r}"
        )

        after = h.count_log_marker(deployed_vm, h.PFB_LOG, "stage=plaintext")
        assert after == before, (
            f"the scan must not reach the archive paths that publish no text '.orig'; "
            f"stage=plaintext count before={before} after={after}\n"
            f"recent pfb_validate lines:\n{_recent_validate_lines(deployed_vm)}"
        )
    finally:
        h.set_feed_sanity(deployed_vm, False)
        deployed_vm.ssh(f"/bin/rm -rf {workdir} {category_dir}")
