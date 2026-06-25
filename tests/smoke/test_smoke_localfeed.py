"""Live-VM smoke: a changed LOCAL-FILE feed is re-ingested on a plain update (issue #533).

Before the fix, pfBlockerNG only re-parsed a feed when the download path flagged it changed
(remote feeds) or the cache was force-invalidated; an edited *local-file* feed was reused from
cache and never picked up. The fix (`pfb_localfile_feed_changed`) compares the source's md5
against the last ingest and touches `{header}.update` on a change, so the existing reuse gate
re-parses it — WITHOUT the `force_ip_refetch` marker the cache reuse otherwise requires.

The assertion target is pfBlockerNG's parsed member file (``deny/<header>_v4.txt``): that is
the direct output of re-parsing the feed, and proves the re-ingest without depending on the
pf alias-table load (a separate pfSense filter-reload concern in the headless package
context). The first ingest is bootstrapped with ``force_ip_refetch`` (the cache-reuse gate
blocks a brand-new local feed otherwise); the change under test is then a PLAIN ``update``
with no force — run pre-fix it FAILS (member keeps IP_A), post-fix it PASSES (member is IP_B).

DESELECTED from the default ``python -m pytest`` (smoke-only). Run via::

    python -m pytest tests/smoke/test_smoke_localfeed.py -m smoke --override-ini="addopts="
"""

from __future__ import annotations

import os

import pytest

from . import helpers as h
from .conftest import SmokeVM

pytestmark = pytest.mark.smoke

# RFC 5737 TEST-NET-3 (inert). IP_A is the initial feed entry; IP_B replaces it.
IP_A = "203.0.113.10"
IP_B = "203.0.113.20"
HEADER = "pfblocalfeed"
FEED_FILE = "pfb_localfeed_ip.txt"
# pfBlockerNG's parsed member file for this IPv4 feed (the deny-dir cache it serves from).
MEMBER = f"/var/db/pfblockerng/deny/{HEADER}_v4.txt"


def _member(vm: SmokeVM, *, timeout: float = 30.0) -> str:
    """The parsed member file pfBlockerNG built from the feed (empty string if absent)."""
    return vm.ssh(
        "/bin/sh", "-c", f"cat {MEMBER} 2>/dev/null || true", timeout=timeout
    ).stdout


def test_localfile_ip_feed_change_is_reingested(smoke_vm: SmokeVM) -> None:
    """A plain update re-ingests an edited local IP feed — no force/clear needed (#533).

    Given: an IP feed whose URL is a local file containing IP_A, ingested into its member file
           (bootstrapped with force_ip_refetch, since the reuse gate blocks a new local feed).
    When:  the local file is edited in place to IP_B and a PLAIN pfBlockerNG ``update`` runs
           (NOT force_ip_refetch, NOT clearip — the path that previously reused the cache).
    Then:  the parsed member file now contains IP_B and no longer IP_A — the edit was detected
           by the local-file md5 change check and re-parsed.
    """
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")

    vm = smoke_vm
    h.deploy(vm)

    # Given: a local-file IP feed with IP_A. Bootstrap the first ingest (force past the reuse
    # gate that blocks a brand-new local feed); this also seeds the .lmd5 md5 baseline.
    feed = h.write_local_feed(vm, FEED_FILE, f"{IP_A}/32\n")
    h.inject(
        vm,
        h.IpCase(
            aliasname=HEADER,
            feed_url=feed,
            action="Deny_Outbound",
            family="v4",
            header=HEADER,
        ),
    )
    h.force_ip_refetch(vm, f"{HEADER}_v4")
    h.reload(vm, "update")
    before = _member(vm)
    assert IP_A in before, (
        f"precondition: expected {IP_A} in the parsed member {MEMBER}, got:\n{before!r}"
    )

    # When: edit the local file in place to IP_B and run a PLAIN update (no force_ip_refetch).
    h.write_local_feed(vm, FEED_FILE, f"{IP_B}/32\n")
    h.reload(vm, "update")

    # Then: the edit was detected (md5 change) and re-parsed into the member file.
    after = _member(vm)
    assert IP_B in after, (
        f"a changed local feed was NOT re-ingested on a plain update — {IP_B} missing from "
        f"{MEMBER} (the #533 local-file change detection did not fire).\n  after: {after!r}"
    )
    assert IP_A not in after, (
        f"the stale entry {IP_A} survived the re-ingest of the edited local feed.\n  after: {after!r}"
    )
