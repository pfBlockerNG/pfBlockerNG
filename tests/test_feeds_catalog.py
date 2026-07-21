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
    """Collect every retained legacy header from the normalized catalog."""
    headers: list[str] = []
    if isinstance(catalog.get("feeds"), list):
        for feed in catalog["feeds"]:
            for locator in feed.get("legacy_locators", []):
                if header := locator.get("legacy_header"):
                    headers.append(header)
        return headers
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


def _find_feed_by_url(catalog: dict, url: str) -> dict | None:  # type: ignore[type-arg]
    """Return the first feed object whose 'url' equals url, across all sections."""
    if isinstance(catalog.get("feeds"), list):
        return next((feed for feed in catalog["feeds"] if feed.get("latest_url") == url), None)
    for section in ("ipv4", "ipv6", "dnsbl"):
        for grp in catalog.get(section, {}).values():
            for feed in grp.get("feeds", []):
                if feed.get("url") == url:
                    return feed  # type: ignore[return-value]
    return None


def _urls_for_legacy_key(catalog: dict, legacy_type: str, key: str) -> set[str]:  # type: ignore[type-arg]
    """Return normalized Feed URLs linked from one retained legacy category key."""
    category = next(
        (
            category
            for category in catalog.get("categories", [])
            if any(row.get("type") == legacy_type and row.get("key") == key for row in category.get("legacy_keys", []))
        ),
        None,
    )
    if category is None:
        return set()
    feeds = {feed.get("id"): feed for feed in catalog.get("feeds", [])}
    return {feeds[feed_id]["latest_url"] for feed_id in category.get("feed_ids", []) if feed_id in feeds}


def test_catalog_is_valid_json() -> None:
    """pfblockerng_feeds.json must parse as valid JSON."""
    assert _FEEDS_JSON.exists(), f"feeds JSON not found at {_FEEDS_JSON}"
    json.loads(_FEEDS_JSON.read_text(encoding="utf-8"))


def test_ipv4_blocklist_de_group_exists(catalog: dict) -> None:  # type: ignore[type-arg]
    """ipv4 BlockListDE group must be present (baseline for the ipv6 mirror)."""
    assert _urls_for_legacy_key(catalog, "ipv4", "BlockListDE"), (
        "ipv4 BlockListDE group missing from pfblockerng_feeds.json"
    )


def test_ipv6_blocklist_de_6_group_exists(catalog: dict) -> None:  # type: ignore[type-arg]
    """ipv6 BlockListDE_6 group must exist (issue #318: was missing before fix)."""
    assert _urls_for_legacy_key(catalog, "ipv6", "BlockListDE_6"), (
        "ipv6 BlockListDE_6 group missing from pfblockerng_feeds.json — "
        "BlockList.DE feeds contain IPv6 addresses but no IPv6 group was shipped"
    )


def test_ipv6_blocklist_de_6_urls_match_ipv4(catalog: dict) -> None:  # type: ignore[type-arg]
    """BlockListDE_6 feed URLs must equal BlockListDE's URLs (same sources)."""
    urls4 = _urls_for_legacy_key(catalog, "ipv4", "BlockListDE")
    urls6 = _urls_for_legacy_key(catalog, "ipv6", "BlockListDE_6")
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

    colliding = [header for header in _all_headers(catalog) if header.endswith("_6") and counts.get(header, 0) > 1]
    assert not colliding, f"BlockListDE_6 headers collide with other catalog entries: {colliding}"


def test_dead_malc0de_bl_boot_feed_is_discontinued(catalog: dict) -> None:  # type: ignore[type-arg]
    """The dead Malc0de bl/BOOT feed must carry status 'discontinued' (issue #372).

    The website returns a placeholder; the feed is kept (removal deferred) but
    flagged so the UI shows it as unavailable rather than offering it as active.
    """
    feed = _find_feed_by_url(catalog, "https://malc0de.com/bl/BOOT")
    assert feed is not None, "Malc0de bl/BOOT feed entry not found in catalog"
    assert feed.get("status") == "discontinued", (
        f"Malc0de bl/BOOT feed must be marked 'status': 'discontinued' (issue #372) — got status={feed.get('status')!r}"
    )
