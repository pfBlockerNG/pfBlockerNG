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
are recorded in ``.ADRs/ADR_16_Feeds_Tabs_And_Feed_Smoke/RESULTS/05_Results.txt``;
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
import shlex
import subprocess
import zipfile
from collections.abc import Iterator

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
        # Use wait_pfctl_table instead of the single-shot pfctl_table_members:
        # filter_configure is async so the pf table may not be populated immediately
        # after CaseContext.__enter__ completes the reload.
        members = h.wait_pfctl_table(deployed_vm, spec.alias)
        assert h.member_present(members, member_host), f"{member_host} not in {spec.alias}: {members}"
        assert _covered_by(members, member_in_cidr), f"{member_in_cidr} not covered by {spec.alias}: {members}"
        assert not _covered_by(members, non_member), f"{non_member} unexpectedly in {spec.alias}: {members}"
        assert h.rule_references(deployed_vm, spec.alias), f"no loaded pf rule references {spec.alias}"


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
    # The refusal fires at pfb_download()'s ENTRY URL vetting (pfb_filter PFB_FILTER_URL
    # routes through pfb_feed_host_allowed, pfblockerng.inc:1067), NOT the later
    # download-time gate at :8974 — that '[ header ] … — skipped' line is unreachable
    # for an internal-host URL. The reason-bearing line lands in error.log (logtype 6):
    #   "… Invalid URL (feed host resolves to a non-permitted address) [ <url> ]"
    # Scope it by the reason AND this run's unique mock URL (host:port/fixture), so a
    # sibling feed's failure can never satisfy it.
    refused_marker = f"Invalid URL (feed host resolves to a non-permitted address) [ {feed_url} ]"
    error_log = f"{h.PFB_LOGDIR}/error.log"
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
        refused_before = h.count_log_marker(deployed_vm, error_log, refused_marker)
        h.reload(deployed_vm, "update")
        h.reload(deployed_vm, "updateip")
        assert spec.alias not in h.pfctl_tables(deployed_vm), (
            "filter ON + empty allowlist must BLOCK the internal mock feed (pf table not built)"
        )
        # A missing pf table alone is non-specific — a dead mock server would look identical.
        # Assert the actual refusal reason was logged, so this proves the SSRF guard fired,
        # not merely that nothing happened to load.
        refused_after = h.count_log_marker(deployed_vm, error_log, refused_marker)
        assert refused_after > refused_before, (
            f"Expected {refused_marker!r} in {error_log} after the filtered update "
            f"(before={refused_before}, after={refused_after}) — the pf table being empty does "
            "not by itself prove the SSRF guard refused the download"
        )

        # EXEMPT branch: allowlist the SLIRP net => the SAME feed now downloads + loads.
        h.set_feed_internal_allowlist(deployed_vm, "192.168.89.0/24")
        h.reload(deployed_vm, "update")
        h.reload(deployed_vm, "updateip")
        # Use wait_pfctl_table: filter_configure is async; the table may not be
        # populated immediately after the reloads complete.
        members = h.wait_pfctl_table(deployed_vm, spec.alias)
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
        members = h.wait_pfctl_table(deployed_vm, spec.alias)
        assert _covered_by(members, inside), f"{inside} not covered by the range in {spec.alias}: {members}"
        assert not _covered_by(members, just_past), (
            f"{just_past} (one past the range) unexpectedly in {spec.alias}: {members}"
        )
        assert not _covered_by(members, outside), f"{outside} unexpectedly in {spec.alias}: {members}"
        assert h.rule_references(deployed_vm, spec.alias), f"no loaded pf rule references {spec.alias}"


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
        assert h.rule_references(deployed_vm, spec.alias), f"no loaded pf rule references {spec.alias}"


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
    """DNSBL ABP/EasyList over HTTP: ``dnsbl_abp.txt`` is header-sniffed ABP and loads.

    The body starts with ``[Adblock Plus 2.0]`` -> pfBlockerNG sniffs it as ABP
    (``format_hint='abp'``) and the Python ABP parser runs. The feed BLOCKs
    ``||uuid-22f166f56cca.com^`` and contains a ``||``/``@@`` pair on
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
# ADR-21 — per-line ABP detection inside a NON-ABP (header-less) feed.
# The kill-gate/expand cases above feed a WHOLE-FEED ABP body (it STARTS with
# ``[Adblock Plus 2.0]`` -> ``format_hint='abp'`` -> every line to ``parse_abp``).
# This case proves the orthogonal ADR-21 path: a feed with NO ABP header (it stays
# ``format_hint='plain'``) whose individual lines still carry ``||``/``@@||`` anchors
# is routed line-by-line to the ABP parser (PHP download loop + manifest builder write
# the anchors verbatim; Python ``build()`` routes them to ``parse_abp`` -> ``abp_rules``)
# WHILE its plain-domain lines keep the plain pipeline.
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
# ADR-21 hardening — two review fixes, each pinned by a DISTINGUISHING live
# transition (the pre-fix behaviour would flip the asserted result, so neither is
# mere execution): (1) the whole-feed ABP header sniff peels a leading UTF-8 BOM;
# (2) per-line ABP capture is VERBATIM (a path anchor is skipped, never truncated
# into a domain-wide over-block).
# --------------------------------------------------------------------------- #


@pytest.mark.timeout(300)
def test_abp_bom_header_still_detected(deployed_vm: SmokeVM, client_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """ADR-21: a UTF-8 BOM before ``[Adblock Plus 2.0]`` must not mask ABP detection.

    Scenario: a feed whose first bytes are a UTF-8 BOM (``EF BB BF``) followed by the
    ``[Adblock Plus 2.0]`` header and a single feed regex ``/badword/``. Whole-feed ABP
    detection is the ONLY path that compiles a feed ``/regex/``: it is not a
    ``||``/``@@||`` line, so ADR-21 per-line routing does not catch it, and the plain
    pipeline drops it as an invalid domain. So a VIP block on a ``badword``-bearing name
    proves the BOM was peeled and the header recognised.

    Given (before the feed loads) the regex-target name RESOLVES via the controlled stub
      upstream (``STUB_DNS_A``) — the observable before-state.
    When the BOM-led ABP feed loads (Force Update),
    Then the ``badword``-bearing name returns the VIP block shape and no longer resolves.
      A regression (BOM masks the header -> feed stays ``plain`` -> the regex line is
      dropped) would leave it resolving, failing this assertion.
    """
    uid = h.unique_domain("adr21bom").split(".", 1)[0]  # the unique label only
    blocked = f"xbadwordx-{uid}.com"
    body = h.abp_feed_bom("/badword/")
    feed_url = h.write_local_feed(deployed_vm, "smoke_adr21_bom.txt", body)
    spec = h.DnsblCase(aliasname="smokeadr21bom", feed_url=feed_url, header="smokeadr21bom", mode=h.DnsblMode.VIP)

    # BEFORE: the name is on no feed yet -> it resolves via the stub sentinel.
    before = h.dns_probe_client(client_vm, blocked, "A")
    assert h.resolves_to(before, STUB_DNS_A), f"{blocked} should resolve via stub BEFORE listing, got {before}"
    assert not h.is_vip(before), f"{blocked} unexpectedly VIP-blocked before any feed: {before}"

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
# ADR-22 — the "Lenient feed parsing" toggle (pfb_dnsbl_lenient) over the live box.
#
# The non-lite DNSBL download path strips a ``<scheme>://`` prefix from each feed
# line (pfblockerng.inc:11316-11329). Lenient (toggle ON — the migrated/legacy
# default) keeps today's permissive strip: ANY ``://`` is removed at its first
# occurrence and a URL path is stripped downstream, so a malformed-scheme line
# (digit-start) and a path line are still extracted + blocked. Strict (toggle OFF —
# the new-install default) validates the scheme against RFC 3986 and rejects a URL
# path: a rejected line is SKIPPED, recorded per-line in the DNSBL parse-error log
# (pfb_parsed_fail -> $pfb['dnsbl_parse_err']), and counted into ONE per-feed WARNING
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
    """ADR-22 §2.2 migration on the live box: an existing install lacking the key -> 'on'.

    Proves the SHIPPED migration decision (``pfb_dnsbl_lenient_migrate``, pfblockerng.inc)
    against the REAL on-box config store — exactly the two-line body the upgrade hook in
    pfblockerng_install.inc runs: read the DNSBL-settings section, run the migration, and
    if it returns a (changed) array, persist it. An EXISTING install is one with a
    populated DNSBL config section that merely lacks ``pfb_dnsbl_lenient``; the migration
    must set it to 'on' (preserving the legacy permissive behaviour), never overwriting a
    present value.

    Given the live DNSBL-settings section is populated (it always is on the deployed box —
      pfb_dnsbl etc. are set) and ``pfb_dnsbl_lenient`` is REMOVED (the upgrade-from-an-
      older-version state) — asserted absent as the before-state,
    When  the shipped ``pfb_dnsbl_lenient_migrate`` runs against that section and the
      result is persisted (the install-hook body),
    Then  the live config now reads ``pfb_dnsbl_lenient == 'on'``.

    NOTE (out-of-CI limitation): the FULL ``pfblockerng_install.inc`` require-flow (which
    also runs the unrelated VIP / python-mode / PFBL-03 migrations) is not driven end to
    end here — that would re-run every install side effect on the live box. This case
    drives the migration FUNCTION the hook calls, against the live config store, which is
    the load-bearing ADR-22 behaviour; the surrounding hook plumbing is identical to the
    in-tree PHPUnit migration coverage (PfbDnsblLenientMigrateTest).
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
        "write_config('pfBlockerNG smoke: ADR-22 migration before-state');\n"
        "echo 'OK';"
    )
    res = h.php_eval(deployed_vm, remove)
    assert "OK" in res.stdout, f"could not stage the migration before-state: {res.stdout!r} {res.stderr!r}"
    assert h.config_get(deployed_vm, h.CFG_DNSBL_SETTINGS + "/pfb_dnsbl_lenient") == "", (
        "pfb_dnsbl_lenient should be ABSENT (empty) before the migration runs"
    )

    try:
        # WHEN: run the SHIPPED migration function (the install-hook body) against the live
        # config and persist the (changed) result.
        migrate = (
            "require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');\n"
            f"$cfg = config_get_path({h._php_str(h.CFG_DNSBL_SETTINGS)}, array());\n"
            "$out = pfb_dnsbl_lenient_migrate($cfg);\n"
            "if ($out !== NULL) {\n"
            f"  config_set_path({h._php_str(h.CFG_DNSBL_SETTINGS)}, $out);\n"
            "  write_config('pfBlockerNG: ADR-22 migration (smoke)');\n"
            "}\n"
            f"echo {h._php_str(sentinel_open)} . ($out === NULL ? 'NULL' : 'SET') . {h._php_str(sentinel_close)};"
        )
        res = h.php_eval(deployed_vm, migrate)
        assert sentinel_open in res.stdout, f"migration eval produced no sentinel: {res.stdout!r} {res.stderr!r}"
        verdict = res.stdout[res.stdout.find(sentinel_open) + len(sentinel_open) : res.stdout.find(sentinel_close)]
        assert verdict == "SET", f"migration should SET the missing key (returned {verdict})"

        # THEN: the live config now carries pfb_dnsbl_lenient == 'on'.
        after = h.config_get(deployed_vm, h.CFG_DNSBL_SETTINGS + "/pfb_dnsbl_lenient")
        assert after == "on", f"migration must set pfb_dnsbl_lenient='on' for an existing install, got {after!r}"
    finally:
        # Restore the harness default (lenient ON) — same value the migration set, but make
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


def _pin_cron_due(vm: SmokeVM) -> int:
    """Set pfb_reuse='' and pfb_dailystart=date('G') on the guest so an EveryDay feed is due.

    Returns the guest's wall-clock hour (0-23) pinned into ``pfb_dailystart``, echoed back
    atomically with the write. Callers that later run ``cron`` should fast-guard against an
    hour rollover between this pin and the cron run (see :func:`_guest_hour`) — if the
    wall clock ticked over, the EveryDay feed is no longer due and a "not re-ingested"
    assertion would misread that as a change-detector regression.
    """
    sentinel_open, sentinel_close = "<<<HOUR>>>", "<<<END>>>"
    snippet = (
        f"$g = config_get_path({h._php_str(h.CFG_GLOBAL)}, array());\n"  # noqa: SLF001
        "$g['pfb_reuse'] = '';\n"
        "$hour = date('G');\n"
        "$g['pfb_dailystart'] = $hour;\n"
        f"config_set_path({h._php_str(h.CFG_GLOBAL)}, $g);\n"  # noqa: SLF001
        "write_config('pfBlockerNG smoke #538: due cron');\n"
        f"echo 'OK' . '{sentinel_open}' . $hour . '{sentinel_close}';"
    )
    res = h.php_eval(vm, snippet)
    if res.returncode != 0 or "OK" not in res.stdout or sentinel_open not in res.stdout:
        raise RuntimeError(f"_pin_cron_due failed: rc={res.returncode} {res.stderr!r} {res.stdout!r}")
    raw = res.stdout.split(sentinel_open, 1)[1].split(sentinel_close, 1)[0]
    try:
        return int(raw)
    except ValueError as exc:
        raise RuntimeError(f"_pin_cron_due: could not parse pinned hour from {res.stdout!r}") from exc


def _guest_hour(vm: SmokeVM) -> int:
    """Read the guest's CURRENT wall-clock hour (0-23) via ``date('G')``, delimited."""
    sentinel_open, sentinel_close = "<<<HOUR>>>", "<<<END>>>"
    res = h.php_eval(vm, f"echo '{sentinel_open}' . date('G') . '{sentinel_close}';")
    if sentinel_open not in res.stdout or sentinel_close not in res.stdout:
        raise RuntimeError(f"_guest_hour: no delimited value in output: {res.stdout!r} {res.stderr!r}")
    raw = res.stdout.split(sentinel_open, 1)[1].split(sentinel_close, 1)[0]
    try:
        return int(raw)
    except ValueError as exc:
        raise RuntimeError(f"_guest_hour: could not parse hour from {res.stdout!r}") from exc


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
        _pin_cron_due(deployed_vm)

        # Capture baselines BEFORE the cron run: the per-feed header line (proves the detector
        # actually evaluated THIS feed) and the re-ingest marker.
        hdr_before = h.count_log_marker(deployed_vm, h.PFB_LOG, f"[ {header} ]")
        dl_before = _feed_log_count(deployed_vm, header, "Downloading update")

        # WHEN — run the genuine cron path (NOT force_dnsbl_refetch — that is the shortcut).
        h.reload(deployed_vm, "cron")

        # THEN (fast guard) — the cron actually evaluated this feed. If the EveryDay feed was not
        # due (e.g. the wall-clock hour rolled over between _pin_cron_due and the cron), no
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
        pinned_hour = _pin_cron_due(deployed_vm)

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
        # a rollover between _pin_cron_due and this cron means the EveryDay feed was never due,
        # and the "no re-ingest" assertions below would prove nothing about the change detector.
        hour_after = _guest_hour(deployed_vm)
        assert hour_after == pinned_hour, (
            f"guest hour rolled over between _pin_cron_due ({pinned_hour}) and cron "
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
        pinned_hour = _pin_cron_due(deployed_vm)
        notreq_before = h.count_log_marker(deployed_vm, h.PFB_LOG, "Update not required")
        dl_before = _feed_log_count(deployed_vm, header, "Downloading update")

        # WHEN — cron (the genuine detector path).
        h.reload(deployed_vm, "cron")

        # THEN (fast guard) — the guest hour must still match the pinned hour. This
        # unchanged-content path (like its `test_cron_skips_unchanged_local_feed` sibling) logs
        # no "[ header ]" marker to fast-guard on, so guard on the wall clock itself: a rollover
        # between _pin_cron_due and this cron means the EveryDay feed was never due, and the
        # "Update not required" assertion below would prove nothing about the change detector.
        hour_after = _guest_hour(deployed_vm)
        assert hour_after == pinned_hour, (
            f"guest hour rolled over between _pin_cron_due ({pinned_hour}) and cron "
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
        _pin_cron_due(deployed_vm)

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

        # Feed unchanged; ETag still matches. The "( 304 not modified )" verdict line is
        # logged WITHOUT the "[ header ]" prefix (pfblockerng.php:553, pfb_logger writes it
        # verbatim), so it is not header-scopable — count it globally over the cron window.
        # This test is the only feed set up with a matching ETag, so the before/after delta
        # isolates its conditional GET.
        _pin_cron_due(deployed_vm)
        not_mod_before = h.count_log_marker(deployed_vm, h.PFB_LOG, "304 not modified")
        dl_before = _feed_log_count(deployed_vm, header, "Downloading update")
        hdr_before = h.count_log_marker(deployed_vm, h.PFB_LOG, f"[ {header} ]")

        # WHEN — the conditional-GET 304 needs the validator PERSISTED first, then READ on a
        # later probe. The validator is written by the cron detector (pfb_update_check) on a
        # 200, NOT by the updatednsbl Force ingest above, and only once a {header}.orig baseline
        # exists — so the store-then-read can span a couple of cron passes. Run cron until
        # "304 not modified" appears (the #572 fix aligned the read base to {header}.orig),
        # capped so a genuine failure still surfaces.
        for _pass in range(4):
            h.reload(deployed_vm, "cron")
            if h.count_log_marker(deployed_vm, h.PFB_LOG, "304 not modified") > not_mod_before:
                break

        # Fast guard — the feed was evaluated at least once.
        hdr_after = h.count_log_marker(deployed_vm, h.PFB_LOG, f"[ {header} ]")
        assert hdr_after > hdr_before, (
            f"cron did not evaluate [ {header} ] (before={hdr_before}, after={hdr_after}) — "
            f"EveryDay feed not due (hour rollover?); re-run"
        )

        # THEN — "304 not modified" appeared within the cap (Phase-3 code-path proof).
        not_mod_after = h.count_log_marker(deployed_vm, h.PFB_LOG, "304 not modified")
        assert not_mod_after > not_mod_before, (
            f"Expected '( 304 not modified )' (Phase-3 conditional GET proof) within 4 cron "
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

        _pin_cron_due(deployed_vm)
        hdr_before = h.count_log_marker(deployed_vm, h.PFB_LOG, f"[ {header} ]")
        dl_before = _feed_log_count(deployed_vm, header, "Downloading update")
        # "( content changed )" is the Phase-3 hash-compare verdict itself (not merely its
        # re-ingest side effect) — the docstring's RED premise (a status-only impl that skips
        # the hash compare) would still log "Downloading update" without ever logging this.
        chg_before = h.count_log_marker(deployed_vm, h.PFB_LOG, "content changed")

        h.reload(deployed_vm, "cron")

        hdr_after = h.count_log_marker(deployed_vm, h.PFB_LOG, f"[ {header} ]")
        assert hdr_after > hdr_before, f"cron did not evaluate [ {header} ] — EveryDay feed not due; re-run"

        # THEN — "Downloading update" appeared (feed was re-ingested).
        dl_after = _feed_log_count(deployed_vm, header, "Downloading update")
        assert dl_after > dl_before, (
            f"Expected '[ {header} ] ... Downloading update' after changed-feed cron "
            f"(before={dl_before}, after={dl_after}) — detector did not detect the change"
        )

        # THEN — the hash-compare verdict itself fired: "( content changed )".
        chg_after = h.count_log_marker(deployed_vm, h.PFB_LOG, "content changed")
        assert chg_after > chg_before, (
            f"Expected '( content changed )' verdict after the ETag bump + body change "
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

        # Feed unchanged; no If-None-Match will be sent (no stored ETag).
        _pin_cron_due(deployed_vm)
        not_unch_before = h.count_log_marker(deployed_vm, h.PFB_LOG, "content unchanged")
        dl_before = _feed_log_count(deployed_vm, header, "Downloading update")
        hdr_before = h.count_log_marker(deployed_vm, h.PFB_LOG, f"[ {header} ]")

        h.reload(deployed_vm, "cron")

        hdr_after = h.count_log_marker(deployed_vm, h.PFB_LOG, f"[ {header} ]")
        assert hdr_after > hdr_before, f"cron did not evaluate [ {header} ] — EveryDay feed not due; re-run"

        # THEN — "content unchanged" appeared (full download + hash comparison taken).
        not_unch_after = h.count_log_marker(deployed_vm, h.PFB_LOG, "content unchanged")
        assert not_unch_after > not_unch_before, (
            f"Expected 'content unchanged' log line after no-validator cron "
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
            members_before = h.wait_pfctl_table(deployed_vm, spec.alias)
            assert h.member_present(members_before, member_ip), (
                f"BEFORE: {member_ip} must be in {spec.alias}: {members_before}"
            )

            # Pin cron due (inside CaseContext so config is active).
            _pin_cron_due(deployed_vm)
            not_unch_before = h.count_log_marker(deployed_vm, h.PFB_LOG, "content unchanged")
            dl_before = _feed_log_count(deployed_vm, feed_marker, "Downloading update")
            hdr_before = h.count_log_marker(deployed_vm, h.PFB_LOG, f"[ {feed_marker} ]")

            # WHEN — cron; server returns 200 (no ETag → no If-None-Match → plain 200).
            h.reload(deployed_vm, "cron")

            hdr_after = h.count_log_marker(deployed_vm, h.PFB_LOG, f"[ {feed_marker} ]")
            assert hdr_after > hdr_before, f"cron did not evaluate [ {feed_marker} ] — EveryDay feed not due; re-run"

            # THEN — "content unchanged" appeared (spurious 200 detected by hash).
            not_unch_after = h.count_log_marker(deployed_vm, h.PFB_LOG, "content unchanged")
            assert not_unch_after > not_unch_before, (
                f"Expected 'content unchanged' after spurious-200 cron "
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

        # Feed unchanged; the stored Last-Modified validator still matches. Same global-count
        # rationale as case (a): "( 304 not modified )" is logged without a "[ header ]" prefix,
        # so count it globally over the cron window. No other feed in this run stores a
        # Last-Modified-only validator that the server actually honours, so the delta isolates
        # this feed's conditional GET.
        _pin_cron_due(deployed_vm)
        not_mod_before = h.count_log_marker(deployed_vm, h.PFB_LOG, "304 not modified")
        dl_before = _feed_log_count(deployed_vm, header, "Downloading update")
        hdr_before = h.count_log_marker(deployed_vm, h.PFB_LOG, f"[ {header} ]")

        # WHEN — same store-then-read span as case (a): the .lastmod validator is written by
        # the cron detector (pfb_update_check) on its first 200, not by the updatednsbl Force
        # ingest above. Run cron until "304 not modified" appears, capped so a genuine failure
        # still surfaces.
        for _pass in range(4):
            h.reload(deployed_vm, "cron")
            if h.count_log_marker(deployed_vm, h.PFB_LOG, "304 not modified") > not_mod_before:
                break

        # Fast guard — the feed was evaluated at least once.
        hdr_after = h.count_log_marker(deployed_vm, h.PFB_LOG, f"[ {header} ]")
        assert hdr_after > hdr_before, (
            f"cron did not evaluate [ {header} ] (before={hdr_before}, after={hdr_after}) — "
            f"EveryDay feed not due (hour rollover?); re-run"
        )

        # THEN — "304 not modified" appeared within the cap (CURLOPT_TIMECONDITION proof).
        not_mod_after = h.count_log_marker(deployed_vm, h.PFB_LOG, "304 not modified")
        assert not_mod_after > not_mod_before, (
            f"Expected '( 304 not modified )' (Last-Modified/CURLOPT_TIMECONDITION 304 proof) "
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
        members = h.wait_pfctl_table(deployed_vm, spec.alias)
        # Then — the member IP loaded (fails if zip bytes were misrouted to the wrong decompressor).
        assert h.member_present(members, _ADR44_MEMBER), (
            f"expected {_ADR44_MEMBER!r} in {spec.alias} after zip decompression, got: {members}"
        )
        assert h.rule_references(deployed_vm, spec.alias), (
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
        members = h.wait_pfctl_table(deployed_vm, spec.alias)
        # Then — the member IP loaded (fails if gzip was mis-normalised to application/zip).
        assert h.member_present(members, _ADR44_MEMBER), (
            f"expected {_ADR44_MEMBER!r} in {spec.alias} after gzip decompression, "
            f"got: {members} — "
            f"(regression: pfb_mime_normalise() may have rewritten application/gzip → application/zip, "
            f"routing gzip bytes to bsdtar and loading zero entries)"
        )
        assert h.rule_references(deployed_vm, spec.alias), (
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
        members = h.wait_pfctl_table(deployed_vm, spec.alias)
        # Then — the member IP loaded (fails if bzip2 was mis-normalised to application/zip).
        assert h.member_present(members, _ADR44_MEMBER), (
            f"expected {_ADR44_MEMBER!r} in {spec.alias} after bzip2 decompression, "
            f"got: {members} — "
            f"(regression: pfb_mime_normalise() may have rewritten application/x-bzip2 → application/zip, "
            f"routing bzip2 bytes to bsdtar and loading zero entries)"
        )
        assert h.rule_references(deployed_vm, spec.alias), (
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
# 7z: out-of-CI — /usr/local/bin/7z is not present on the smoke image
# (image ships ldns, bind-tools, python311, unbound, php83, qemu-guest-agent only).
# --------------------------------------------------------------------------- #


@pytest.mark.timeout(120)
def test_corrupt_zip_rejected(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """ADR-45: a corrupt ZIP feed is rejected by the structural probe.

    Scenario: the mock serves a ZIP whose first local-file-header signature
    (``PK\\x03\\x04``) is clobbered but whose central directory + EOCD are intact.
    file(1) still reports ``application/zip`` (it reads the EOCD), so the feed
    enters the ZIP branch; ``bsdtar -tf`` then fails to parse the broken local
    header and exits non-zero. pfb_validate_archive() catches that; pfb_download()
    returns FALSE; the alias is never created.

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
      before extraction and pfb_download() returned FALSE.
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
        # Then — alias still absent; pfb_download returned FALSE; table never created.
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
    non-zero. pfb_validate_archive() catches the failure; pfb_download() returns
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
    returns FALSE; the alias is never created.

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
        members = h.wait_pfctl_table(deployed_vm, spec.alias)
        # Then — member is present regardless of which branch handled it.
        # (When recovery_exercised: proves octet-stream was recovered to application/zip and imported.
        #  When not: proves the normal zip branch handled it — still a valid import assertion.)
        assert h.member_present(members, _ADR45_MEMBER), (
            f"expected {_ADR45_MEMBER!r} in {spec.alias} after junk-prefixed ZIP, got: {members} "
            f"(box file(1) reported {box_mime!r}; recovery_exercised={recovery_exercised})"
        )
        assert h.rule_references(deployed_vm, spec.alias), (
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


# ── ADR-45: first-class 7z (opportunistic — 7-Zip is NOT shipped with pfBlockerNG) ──
# /usr/local/bin/7z is an optional add-on. The CI smoke image bakes it in so the import +
# corrupt cases run; on any box without it those two SKIP. The missing-binary case ALWAYS
# runs (it hides the binary when present) so the default "no 7-Zip → safe reject + clear
# message" reality stays covered even on the 7z-baked image.
_SEVENZIP_BIN = "/usr/local/bin/7z"
# Substring of the pfb_download() "install 7-zip" log line (pfblockerng.inc).
_SEVENZIP_MISSING_MARKER = "Install the 7-Zip package"


def _have_7z(vm: SmokeVM) -> bool:
    """True iff /usr/local/bin/7z is executable on the guest (the opportunistic extractor)."""
    return vm.ssh(f"test -x {_SEVENZIP_BIN} && echo y || echo n").stdout.strip() == "y"


@pytest.mark.timeout(120)  # full update + targeted reload + file-detect/7z-probe/extract > the 30s cap on slow CI
def test_7z_feed_imports(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """ADR-45: a 7z-compressed IP feed imports when 7-Zip is installed.

    7-Zip is an OPTIONAL extractor (not shipped with pfBlockerNG), so this exercises the
    first-class 7z path only when /usr/local/bin/7z is present — it is baked into the CI
    smoke image; on a box without it the test SKIPS (the missing-binary behaviour is pinned
    by ``test_7z_missing_binary_rejected``). Paired with ``test_corrupt_7z_rejected``.

    Given the alias does not exist.
    When the case Force-Updates over the .7z feed (file(1) → application/x-7z-compressed →
      allow-listed → 7z branch → 7z t probe → 7z e -so),
    Then 203.0.113.11 is present in the pf table — the 7z archive was extracted end-to-end.
    """
    if not _have_7z(deployed_vm):
        pytest.skip(f"{_SEVENZIP_BIN} not installed; 7z extraction is opportunistic — skipping import case")
    feed_url = mock_feeds.feed_url("archive_valid.7z")
    spec = h.IpCase(aliasname="adr457z", feed_url=feed_url, header="adr457z", family="v4")

    # Given — alias absent before any load attempt.
    assert spec.alias not in h.pfctl_tables(deployed_vm), f"{spec.alias} present before the 7z feed was ever loaded"

    with h.CaseContext(deployed_vm, spec):
        # When — Force Update fetches + file-detects application/x-7z-compressed + 7z e -so extracts.
        members = h.wait_pfctl_table(deployed_vm, spec.alias)
        # Then — the inner IP loaded, proving the 7z branch extracted end-to-end.
        assert h.member_present(members, _ADR45_MEMBER), (
            f"expected {_ADR45_MEMBER!r} in {spec.alias} after 7z extraction, got: {members}"
        )
        assert h.rule_references(deployed_vm, spec.alias), f"no loaded pf rule references {spec.alias} after 7z import"


@pytest.mark.timeout(120)  # full update + targeted reload + file-detect/7z-probe > the 30s cap on slow CI
def test_corrupt_7z_rejected(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """ADR-45: a corrupt 7z feed is rejected by the structural probe (when 7-Zip is present).

    Skips when 7-Zip is absent (the ``7z t`` probe can't run; the missing-binary path is its
    own test). Paired with ``test_7z_feed_imports`` to prove the probe is a real branch, not
    an always-reject path.

    Given the alias does not exist.
    When the case Force-Updates over a truncated .7z (file(1) → application/x-7z-compressed →
      7z branch → ``7z t`` exits non-zero),
    Then the alias remains absent — the structural probe rejected the corrupt archive.
    """
    if not _have_7z(deployed_vm):
        pytest.skip(f"{_SEVENZIP_BIN} not installed; the 7z probe can't run — skipping corrupt-7z case")
    feed_url = mock_feeds.feed_url("archive_corrupt.7z")
    spec = h.IpCase(aliasname="adr45c7z", feed_url=feed_url, header="adr45c7z", family="v4")

    # Given — alias absent before any load attempt.
    assert spec.alias not in h.pfctl_tables(deployed_vm), f"{spec.alias} present before the corrupt-7z feed"

    with h.CaseContext(deployed_vm, spec):
        # When — Force Update; the 7z t probe fails. Then — alias never created.
        tables_after = h.pfctl_tables(deployed_vm)
        assert spec.alias not in tables_after, (
            f"expected {spec.alias!r} absent after corrupt 7z (7z -t probe must reject), "
            f"found it present — tables: {tables_after}"
        )


@pytest.mark.timeout(120)  # full update + targeted reload + hide/restore the 7z binary > the 30s cap on slow CI
def test_7z_missing_binary_rejected(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """ADR-45: a 7z feed on a box WITHOUT 7-Zip is rejected with a clear "install 7-zip" message.

    7z extraction is opportunistic (pfBlockerNG ships no 7-Zip), so the DEFAULT user reality
    is "no 7-Zip → safe reject". This pins that path AND the message that tells the user how
    to enable 7z — instead of the misleading "corrupt archive". The CI image bakes 7-Zip in
    (for the import case), so this test temporarily HIDES the binary to recreate the
    missing-tool condition, then restores it in a finally.

    Given a valid .7z feed (file(1) → application/x-7z-compressed) and no usable 7-Zip,
    When the case Force-Updates,
    Then the alias is NOT created (rejected before extraction) AND pfblockerng.log gains the
      "Install the 7-Zip package" line — NOT a "corrupt archive" line.
    """
    stash = "/tmp/pfb_7z_hidden_for_test"
    hidden = False
    if _have_7z(deployed_vm):
        # ssh() is check=False; a silent mv failure is caught by the assert below (not a wrong pass).
        deployed_vm.ssh(f"mv {_SEVENZIP_BIN} {stash}")
        hidden = True
    try:
        assert not _have_7z(deployed_vm), (
            f"{_SEVENZIP_BIN} still resolves after hiding it — cannot recreate the missing-7z condition"
        )
        feed_url = mock_feeds.feed_url("archive_valid.7z")
        spec = h.IpCase(aliasname="adr45m7z", feed_url=feed_url, header="adr45m7z", family="v4")

        # Given — alias absent + record the current "install 7-zip" message count.
        assert spec.alias not in h.pfctl_tables(deployed_vm), f"{spec.alias} present before the missing-7z feed"
        before = h.count_log_marker(deployed_vm, h.PFB_LOG, _SEVENZIP_MISSING_MARKER)

        with h.CaseContext(deployed_vm, spec):
            # Then — no extraction is possible, so the alias is never created (safe reject).
            tables_after = h.pfctl_tables(deployed_vm)
            assert spec.alias not in tables_after, (
                f"expected {spec.alias!r} absent when 7-Zip is missing (must safe-reject, not extract), "
                f"found it present — tables: {tables_after}"
            )
            # And — a NEW "install 7-zip" line was logged (clear guidance, not "corrupt archive").
            after = h.count_log_marker(deployed_vm, h.PFB_LOG, _SEVENZIP_MISSING_MARKER)
            assert after > before, (
                f"expected a new {_SEVENZIP_MISSING_MARKER!r} line in {h.PFB_LOG} after a 7z feed with no 7-Zip "
                f"(clear install guidance, not a 'corrupt archive' message); count before={before} after={after}"
            )
    finally:
        if hidden:
            deployed_vm.ssh(f"mv {stash} {_SEVENZIP_BIN}")


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
    (reason=compressed_mime_not_allowed). The zip POST-EXTRACTION sub-path
    cannot be forced live: the re-run probes ``$input[1]`` = the ORIGINAL
    archive (the extracted file rides in the legacy-unused ``$input[0]``), so
    it always passes for a valid zip -- a pre-existing no-op tracked in issue
    #808 (probe-target fix = ADR-46 inner-content scope, not ADR-48's
    message-only scope). The first fan-out proved it live: a valid zip wrapping
    a PDF payload produced NO inner reject on either edition.

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
        members = h.wait_pfctl_table(deployed_vm, spec.alias)
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
