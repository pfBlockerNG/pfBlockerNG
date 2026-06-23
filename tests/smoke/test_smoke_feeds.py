"""ADR-16 Part C — the live HTTP-feed load smoke (the Part-C kill-gate).

Every other smoke case (``test_smoke_matrix.py`` / ``test_smoke_abp.py``) feeds a
LOCAL file (``write_local_feed``) — chosen partly for HTTP-fetch reliability (ADR-16
Context 5). This module is the one place the suite drives the REAL HTTP feed-fetch
path: each case points a ``IpCase``/``DnsblCase`` at a ``mock_feeds.feed_url(<name>)``
URL (the stdlib ``_MockFeedServer`` serving ``tests/smoke/fixtures/``, reachable by
the guest at ``http://10.10.0.2:<port>/<name>`` over SLIRP — survives the egress
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
    # The mock feed server is the SLIRP host alias 10.10.0.2 (RFC1918) — the default-ON
    # feed-host internal-address filter (SSRF guard, pfb_feed_internal_filter) would reject
    # every HTTP mock fetch as an internal-resolving host. Allowlist the SLIRP test network
    # so the filter stays ON yet the mock is reachable (the fix for the regression these
    # HTTP-feed tests hit after the filter landed default-on).
    h.set_feed_internal_allowlist(smoke_vm, "10.10.0.0/24")
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

    The mock feed server is the SLIRP host alias 10.10.0.2 (RFC1918) — exactly the
    internal-pivot the filter (``pfb_feed_internal_filter``, default ON) guards against.
    This pins BOTH branches end to end over the live box (the module fixture allowlists
    10.10.0.0/24 so the other HTTP-feed cases load at all; this test brackets it).

    Scenario:
      Given the filter ON and the allowlist EMPTY (so 10.10.0.2 is not exempt),
      When  the mock IP feed is Force-Updated,
      Then  the download is REFUSED and the pf table is never built (the block branch).
      When  the SLIRP net 10.10.0.0/24 is then allowlisted and re-updated,
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
        h.set_feed_internal_allowlist(deployed_vm, "10.10.0.0/24")
        h.reload(deployed_vm, "update")
        h.reload(deployed_vm, "updateip")
        # Use wait_pfctl_table: filter_configure is async; the table may not be
        # populated immediately after the reloads complete.
        members = h.wait_pfctl_table(deployed_vm, spec.alias)
        assert members, "allowlisting the SLIRP CIDR must EXEMPT the feed (pf table built)"
        assert h.member_present(members, "203.0.113.5"), f"listed host missing after exemption: {members}"
    finally:
        # Restore the module-default allowlist (siblings rely on it) and baseline the box.
        h.set_feed_internal_allowlist(deployed_vm, "10.10.0.0/24")
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
