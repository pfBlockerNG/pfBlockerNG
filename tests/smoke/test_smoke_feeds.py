"""ADR-16 Part C — the live HTTP-feed load smoke (the Part-C kill-gate).

Every other smoke case (``test_smoke_matrix.py`` / ``test_smoke_abp.py``) feeds a
LOCAL file (``write_local_feed``) — chosen partly for HTTP-fetch reliability (ADR-16
Context 5). This module is the one place the suite drives the REAL HTTP feed-fetch
path: each case points a ``IpCase``/``DnsblCase`` at a ``mock_feeds.feed_url(<name>)``
URL (the stdlib ``_MockFeedServer`` serving ``tests/smoke/fixtures/``, reachable by
the guest at ``http://10.0.2.2:<port>/<name>`` over SLIRP — survives the egress
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

import ipaddress
import os
from collections.abc import Iterator

import pytest

from . import helpers as h
from .conftest import STUB_DNS_A, SmokeVM, _MockFeedServer, _StubDnsServer

pytestmark = pytest.mark.smoke


@pytest.fixture(scope="module")
def deployed_vm(smoke_vm: SmokeVM, stub_dns: _StubDnsServer) -> Iterator[SmokeVM]:
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
    # The mock feed server is the SLIRP host alias 10.0.2.2 (RFC1918) — the default-ON
    # feed-host internal-address filter (SSRF guard, pfb_feed_internal_filter) would reject
    # every HTTP mock fetch as an internal-resolving host. Allowlist the SLIRP test network
    # so the filter stays ON yet the mock is reachable (the fix for the regression these
    # HTTP-feed tests hit after the filter landed default-on).
    h.set_feed_internal_allowlist(smoke_vm, "10.0.2.0/24")
    h.ensure_dnsbl_vip(smoke_vm)
    h.use_system_dns_upstream(smoke_vm)
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
        members = h.pfctl_table_members(deployed_vm, spec.alias)
        assert h.member_present(members, member_host), f"{member_host} not in {spec.alias}: {members}"
        assert _covered_by(members, member_in_cidr), f"{member_in_cidr} not covered by {spec.alias}: {members}"
        assert not _covered_by(members, non_member), f"{non_member} unexpectedly in {spec.alias}: {members}"
        assert h.rule_references(deployed_vm, spec.alias), f"no loaded pf rule references {spec.alias}"


def test_dnsbl_http_feed_loads(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
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
    before = h.dns_probe(deployed_vm, member, "A")
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
        blocked = h.dns_probe_until(deployed_vm, member, h.is_vip)
        assert not h.resolves_to(blocked, STUB_DNS_A), f"{member} still resolving after the feed block: {blocked}"
        passed = h.dns_probe(deployed_vm, non_member, "A")
        assert h.resolves_to(passed, STUB_DNS_A), f"non-member {non_member} should resolve via stub, got {passed}"
        assert not h.is_vip(passed), f"non-member {non_member} wrongly VIP-blocked: {passed}"


# --------------------------------------------------------------------------- #
# Feed-host internal-address filter (SSRF guard) — BOTH branches over the live box.
# --------------------------------------------------------------------------- #


def test_feed_internal_filter_blocks_then_allowlist_exempts(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """The default-ON feed-host filter BLOCKS an internal-resolving feed; the allowlist EXEMPTS it.

    The mock feed server is the SLIRP host alias 10.0.2.2 (RFC1918) — exactly the
    internal-pivot the filter (``pfb_feed_internal_filter``, default ON) guards against.
    This pins BOTH branches end to end over the live box (the module fixture allowlists
    10.0.2.0/24 so the other HTTP-feed cases load at all; this test brackets it).

    Scenario:
      Given the filter ON and the allowlist EMPTY (so 10.0.2.2 is not exempt),
      When  the mock IP feed is Force-Updated,
      Then  the download is REFUSED and the pf table is never built (the block branch).
      When  the SLIRP net 10.0.2.0/24 is then allowlisted and re-updated,
      Then  the SAME feed downloads and its pf table IS built (the exempt branch).
    """
    feed_url = mock_feeds.feed_url("ip_plain_cidr.txt")
    spec = h.IpCase(aliasname="smokefiltergate", feed_url=feed_url, header="smokefiltergate", family="v4")
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
        h.reload(deployed_vm, "update")
        h.reload(deployed_vm, "updateip")
        assert spec.alias not in h.pfctl_tables(deployed_vm), (
            "filter ON + empty allowlist must BLOCK the internal mock feed (pf table not built)"
        )

        # EXEMPT branch: allowlist the SLIRP net => the SAME feed now downloads + loads.
        h.set_feed_internal_allowlist(deployed_vm, "10.0.2.0/24")
        h.reload(deployed_vm, "update")
        h.reload(deployed_vm, "updateip")
        members = h.pfctl_table_members(deployed_vm, spec.alias)
        assert members, "allowlisting the SLIRP CIDR must EXEMPT the feed (pf table built)"
        assert h.member_present(members, "203.0.113.5"), f"listed host missing after exemption: {members}"
    finally:
        # Restore the module-default allowlist (siblings rely on it) and baseline the box.
        h.set_feed_internal_allowlist(deployed_vm, "10.0.2.0/24")
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


def test_dnsbl_http_hosts_feed_loads(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
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

    before = h.dns_probe(deployed_vm, member, "A")
    assert h.resolves_to(before, STUB_DNS_A), f"{member} should resolve via stub BEFORE listing, got {before}"
    assert not h.is_vip(before), f"{member} unexpectedly VIP-blocked before any feed: {before}"

    with h.CaseContext(deployed_vm, spec):
        h.unblock_egress()  # the non-member "resolves" probe must reach the stub upstream
        # before-probe warmed the C-cache; a feed swap is TTL-bounded (see kill-gate) -> flush + poll.
        h.flush_unbound_name(deployed_vm, member)
        blocked = h.dns_probe_until(deployed_vm, member, h.is_vip)
        assert not h.resolves_to(blocked, STUB_DNS_A), f"{member} still resolving after the feed block: {blocked}"
        passed = h.dns_probe(deployed_vm, non_member, "A")
        assert h.resolves_to(passed, STUB_DNS_A), f"non-member {non_member} should resolve via stub, got {passed}"
        assert not h.is_vip(passed), f"non-member {non_member} wrongly VIP-blocked: {passed}"


def test_dnsbl_http_abp_feed_loads(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
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
    before = h.dns_probe(deployed_vm, blocked_name, "A")
    assert h.resolves_to(before, STUB_DNS_A), f"{blocked_name} should resolve via stub BEFORE listing, got {before}"
    assert not h.is_vip(before), f"{blocked_name} unexpectedly VIP-blocked before any feed: {before}"

    with h.CaseContext(deployed_vm, spec):
        # The two "resolves" probes (the @@ exception + the non-member) must reach the
        # controlled stub: leave egress OPEN. The || block returns the VIP locally, so
        # this is no false-green.
        h.unblock_egress()
        # before-probe warmed the C-cache; a feed swap is TTL-bounded (see kill-gate) -> flush + poll.
        h.flush_unbound_name(deployed_vm, blocked_name)
        ans_blocked = h.dns_probe_until(deployed_vm, blocked_name, h.is_vip)
        assert not h.resolves_to(ans_blocked, STUB_DNS_A), (
            f"{blocked_name} still resolving after the || block: {ans_blocked}"
        )
        ans_allow = h.dns_probe(deployed_vm, allow_exception, "A")
        assert h.resolves_to(ans_allow, STUB_DNS_A), (
            f"ABP @@ allow-exception {allow_exception} must RESOLVE via the stub (@@ beats ||), got {ans_allow}"
        )
        assert not h.is_vip(ans_allow), f"ABP @@ allow-exception {allow_exception} wrongly VIP-blocked: {ans_allow}"
        ans_non = h.dns_probe(deployed_vm, non_member, "A")
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
def test_abp_perline_detection_in_plain_feed(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
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
        before = h.dns_probe(deployed_vm, name, "A")
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

        ans_block = h.dns_probe_until(deployed_vm, block_name, h.is_vip)
        assert not h.resolves_to(ans_block, STUB_DNS_A), f"{block_name} still resolving after ||block^: {ans_block}"

        ans_plain = h.dns_probe_until(deployed_vm, plain_name, h.is_vip)
        assert not h.resolves_to(ans_plain, STUB_DNS_A), f"{plain_name} still resolving after plain block: {ans_plain}"

        ans_allow = h.dns_probe(deployed_vm, allow_name, "A")
        assert h.resolves_to(ans_allow, STUB_DNS_A), (
            f"@@||{allow_name}^ must RESOLVE via the stub (its @@ allow beats the same-feed plain block): {ans_allow}"
        )
        assert not h.is_vip(ans_allow), f"{allow_name} wrongly VIP-blocked despite its @@ allow: {ans_allow}"
