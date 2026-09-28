"""Issue #3344 live smoke: literal feed hosts refused at entry vetting.

A feed URL whose host is a non-canonical IPv4 literal (a decimal/hex DWORD, a
short a.b.c form, an octal quad, or a leading-zero quad) or a bracketed IPv6
literal is refused before the download ever starts, with the guard's exact
reason logged; a canonical feed URL is unaffected. This module drives the real
entry-vetting path (``pfb_filter`` -> ``pfb_feed_host_literal_reason`` /
``pfb_feed_host_allowed`` -> ``pfb_log_feed_host_reject``) on a real pfSense
box, mirrors ``test_smoke_feeds.py``'s
``test_feed_internal_filter_blocks_then_allowlist_exempts`` shape (IpCase +
inject + reload + a header-scoped main-log marker + ``pfctl_tables``).

DESELECTED from the default ``python -m pytest`` (``--ignore=tests/smoke`` in
pyproject.toml). Run only by the smoke workflow::

    python -m pytest tests/smoke -m smoke --override-ini="addopts="

Requires the booted ``smoke_vm`` fixture and the branch ``.pkg`` (``SMOKE_PKG``);
without it the module fixture skips cleanly. Pure IP-side (no DNSBL, no DNS
probe) -- mirrors the minimal ``test_smoke_ip_recompute.py`` deploy shape, plus
the feed-host allowlist ``test_smoke_feeds.py``'s ``deployed_vm`` sets for its
own HTTP-feed cases (so the canonical control row can still load).
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from . import helpers as h
from .conftest import SmokeVM, _MockFeedServer

pytestmark = pytest.mark.smoke


@pytest.fixture(scope="module")
def deployed_vm(smoke_vm: SmokeVM) -> Iterator[SmokeVM]:
    """Deploy the branch .pkg; allowlist the SLIRP mock net (192.168.89.0/24) so
    the canonical control row can still load while the default-ON feed-host
    filter otherwise stays ON (mirrors ``test_smoke_feeds.py``'s ``deployed_vm``).
    """
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    h.set_feed_internal_allowlist(smoke_vm, "192.168.89.0/24")
    try:
        yield smoke_vm
    finally:
        h.set_feed_internal_allowlist(smoke_vm, "")
        h.collect_host_diagnostics(smoke_vm)


# Exact production reason strings (pfblockerng.inc pfb_feed_host_literal_reason()).
_NON_CANONICAL = "feed host is a non-canonical IP literal"
_BRACKETED_V6 = "feed host is a bracketed IPv6 literal"

# Leading-zero quads: libcurl reads a leading-zero part as octal ('012.0.0.1' dials 10.0.0.1).
_LEADING_ZERO_HOSTS = ["012.0.0.1", "1.2.3.04", "08.08.08.08", "010.010.010.010"]

# (row id, feed-URL host, expected reason). r1-r4 spell the mock 192.168.89.2.
_HOST_ROWS: list[tuple[str, str, str]] = [
    ("r1", "3232258306", _NON_CANONICAL),  # decimal DWORD
    ("r2", "0xC0A85902", _NON_CANONICAL),  # hex DWORD
    ("r3", "192.168.22786", _NON_CANONICAL),  # short a.b.c form
    ("r4", "0300.0250.0131.02", _NON_CANONICAL),  # octal quad
    ("r5", "[::1]", _BRACKETED_V6),  # bracketed IPv6
] + [(f"r6{chr(ord('a') + i)}", host, _NON_CANONICAL) for i, host in enumerate(_LEADING_ZERO_HOSTS)]


def test_feed_literal_host_refused_then_canonical_loads(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """Every non-canonical/bracketed-literal feed host is refused with its exact
    reason and never builds a pf table; the SAME mock, addressed canonically,
    still loads.

    Scenario:
      Given one IP list per row, each pointed at the mock (192.168.89.2) spelled
            a different non-canonical/bracketed way, plus a control row that
            addresses it canonically,
      When  ONE Force Update (``update``) then ONE targeted IP reload
            (``updateip``) runs,
      Then  every row's pf table is never built and its header-scoped
            "<reason> — skipped" line lands in the main log,
      And   the control row's pf table IS built, carrying the fixture's member.
    """
    content_name = "literal_host_probe.txt"
    mock_feeds.register(content_name, "203.0.113.5\n")
    port = mock_feeds.port

    rows: list[tuple[h.IpCase, str]] = []
    for row_id, host, reason in _HOST_ROWS:
        spec = h.IpCase(
            aliasname=f"litfh{row_id}",
            feed_url=f"http://{host}:{port}/{content_name}",
            header=f"litfh{row_id}",
            family="v4",
        )
        rows.append((spec, reason))
    control = h.IpCase(aliasname="litfhc1", feed_url=mock_feeds.feed_url(content_name), header="litfhc1", family="v4")

    main_log = h.PFB_LOG
    markers = {spec.aliasname: f"[ {spec.header}_v4 ] {reason} — skipped" for spec, reason in rows}

    h.unblock_egress()
    try:
        h.inject_ip_lists(deployed_vm, [spec for spec, _reason in rows] + [control])

        for spec, _reason in rows:
            assert spec.alias not in h.pfctl_tables(deployed_vm), f"{spec.aliasname}: pf table present before any load"
        before_counts = {
            spec.aliasname: h.count_log_marker(deployed_vm, main_log, markers[spec.aliasname]) for spec, _r in rows
        }

        h.reload(deployed_vm, "update")
        h.reload(deployed_vm, "updateip")
        h.apply_filter_sync(deployed_vm)

        tables = h.pfctl_tables(deployed_vm)
        for spec, reason in rows:
            marker = markers[spec.aliasname]
            after = h.count_log_marker(deployed_vm, main_log, marker)
            assert after > before_counts[spec.aliasname], (
                f"{spec.aliasname}: expected {marker!r} in {main_log} after the update "
                f"(before={before_counts[spec.aliasname]}, after={after})"
            )
            assert spec.alias not in tables, (
                f"{spec.aliasname}: pf table built despite the literal-host refusal ({reason})"
            )

        members = h.pfctl_table_members(deployed_vm, control.alias)
        assert members, "canonical control feed did not load (pf table empty)"
        assert h.member_present(members, "203.0.113.5"), f"control member missing: {members}"
    finally:
        h.reset(deployed_vm)
