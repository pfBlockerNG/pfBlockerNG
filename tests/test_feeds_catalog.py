"""Structural guard for src/usr/local/www/pfblockerng/pfblockerng_feeds.json.

Pins that:
- The catalog is valid JSON.
- The ipv4 BlockListDE group exists (regression guard for the ipv4 group itself).
- The ipv6 BlockListDE_6 group exists (issue #318: IPv6 group was missing).
- BlockListDE_6 references the same feed URLs as BlockListDE (same sources, IPv6-capable).
- Every header in the whole catalog is unique (guards the _6-suffixed headers
  added by #318 and all existing headers against collision).
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pytest

_FEEDS_JSON = Path(__file__).parent.parent / "src" / "usr" / "local" / "www" / "pfblockerng" / "pfblockerng_feeds.json"


@pytest.fixture(scope="module")
def catalog() -> dict:  # type: ignore[type-arg]
    """Load the real pfblockerng_feeds.json once per module."""
    return json.loads(_FEEDS_JSON.read_text(encoding="utf-8"))  # type: ignore[return-value]


def _all_headers(catalog: dict) -> list[str]:  # type: ignore[type-arg]
    """Collect every 'header' value from ipv4, ipv6, and dnsbl sections."""
    headers: list[str] = []
    for section in ("ipv4", "ipv6"):
        for grp in catalog.get(section, {}).values():
            for feed in grp.get("feeds", []):
                if h := feed.get("header"):
                    headers.append(h)
                for alt in feed.get("alternate", []):
                    if h2 := alt.get("header"):
                        headers.append(h2)
    for grp in catalog.get("dnsbl", {}).values():
        for feed in grp.get("feeds", []):
            if h := feed.get("header"):
                headers.append(h)
    return headers


def test_catalog_is_valid_json() -> None:
    """pfblockerng_feeds.json must parse as valid JSON."""
    assert _FEEDS_JSON.exists(), f"feeds JSON not found at {_FEEDS_JSON}"
    json.loads(_FEEDS_JSON.read_text(encoding="utf-8"))


def test_ipv4_blocklist_de_group_exists(catalog: dict) -> None:  # type: ignore[type-arg]
    """ipv4 BlockListDE group must be present (baseline for the ipv6 mirror)."""
    assert "BlockListDE" in catalog.get("ipv4", {}), "ipv4 BlockListDE group missing from pfblockerng_feeds.json"


def test_ipv6_blocklist_de_6_group_exists(catalog: dict) -> None:  # type: ignore[type-arg]
    """ipv6 BlockListDE_6 group must exist (issue #318: was missing before fix)."""
    assert "BlockListDE_6" in catalog.get("ipv6", {}), (
        "ipv6 BlockListDE_6 group missing from pfblockerng_feeds.json — "
        "BlockList.DE feeds contain IPv6 addresses but no IPv6 group was shipped"
    )


def test_ipv6_blocklist_de_6_urls_match_ipv4(catalog: dict) -> None:  # type: ignore[type-arg]
    """BlockListDE_6 feed URLs must equal BlockListDE's URLs (same sources)."""
    urls4 = {f["url"] for f in catalog["ipv4"]["BlockListDE"]["feeds"]}
    urls6 = {f["url"] for f in catalog["ipv6"]["BlockListDE_6"]["feeds"]}
    assert urls4 == urls6, (
        f"ipv6 BlockListDE_6 URLs differ from ipv4 BlockListDE URLs.\n"
        f"  Only in ipv4: {urls4 - urls6}\n"
        f"  Only in ipv6: {urls6 - urls4}"
    )


def test_blocklist_de_6_headers_unique_across_catalog(catalog: dict) -> None:  # type: ignore[type-arg]
    """BlockListDE_6 headers must not collide with any other header in the catalog.

    The _6 suffix is the uniqueness mechanism: guards against a future edit that
    reintroduces a non-suffixed or wrong-suffix header for the IPv6 group.
    """
    all_headers = _all_headers(catalog)
    counts = Counter(all_headers)

    ipv6_group = catalog["ipv6"]["BlockListDE_6"]
    colliding = [f["header"] for f in ipv6_group.get("feeds", []) if counts.get(f.get("header", ""), 0) > 1]
    assert not colliding, f"BlockListDE_6 headers collide with other catalog entries: {colliding}"
