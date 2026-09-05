"""The shipped Maltrail feed URLs must be the ones that still serve (issue #3205).

The scanner trail moved inside ``stamparm/maltrail`` and the malware-domain list
moved out of the retired ``stamparm/aux`` repository into ``stamparm/trails``
release assets. Both former URLs answer HTTP 404, so an update run stores
GitHub's 14-byte error page instead of a list.
"""

from __future__ import annotations

import json
from pathlib import Path

_FEEDS_JSON = Path(__file__).parents[1] / "src/usr/local/www/pfblockerng/pfblockerng_feeds.json"

_LIVE_URLS = (
    "https://raw.githubusercontent.com/stamparm/maltrail/refs/heads/master/data/mass_scanner.txt",
    "https://github.com/stamparm/trails/releases/latest/download/maltrail-malware-domains.txt",
)

_RETIRED_URLS = (
    "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/mass_scanner.txt",
    "https://raw.githubusercontent.com/stamparm/aux/master/maltrail-malware-domains.txt",
)


def _catalog_urls() -> set[str]:
    """Every 'url' the catalogue offers, across sections, feeds, and alternates."""
    urls: set[str] = set()

    def walk(node: object) -> None:
        if isinstance(node, dict):
            url = node.get("url")
            if isinstance(url, str):
                urls.add(url)
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(json.loads(_FEEDS_JSON.read_text(encoding="utf-8")))
    return urls


def test_maltrail_feeds_use_their_live_endpoints() -> None:
    urls = _catalog_urls()
    missing = [url for url in _LIVE_URLS if url not in urls]
    assert missing == [], f"live Maltrail endpoints missing from the catalogue: {missing}"
    stale = [url for url in _RETIRED_URLS if url in urls]
    assert stale == [], f"retired (404) Maltrail endpoints still shipped: {stale}"
