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

# (retired 404 endpoint, live endpoint, section, feed header) per Maltrail feed:
# the ipv4 scanner list and the DNSBL malware-domain list.
_MALTRAIL_FEEDS = (
    (
        "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/mass_scanner.txt",
        "https://raw.githubusercontent.com/stamparm/maltrail/refs/heads/master/data/mass_scanner.txt",
        "ipv4",
        "Maltrail_Scanners_All",
    ),
    (
        "https://raw.githubusercontent.com/stamparm/aux/master/maltrail-malware-domains.txt",
        "https://github.com/stamparm/trails/releases/latest/download/maltrail-malware-domains.txt",
        "dnsbl",
        "Maltrail_BD",
    ),
)


def test_maltrail_feeds_use_their_live_endpoints() -> None:
    text = _FEEDS_JSON.read_text(encoding="utf-8")
    catalog = json.loads(text)
    for retired, live, section, header in _MALTRAIL_FEEDS:
        urls = [
            feed.get("url")
            for group in catalog.get(section, {}).values()
            for feed in group.get("feeds", [])
            if feed.get("header") == header
        ]
        # Pinned to the feed record, not to the catalogue at large: swapping the two
        # Maltrail URLs between their feeds must fail as loudly as dropping one.
        assert urls == [live], f"{header} must carry its live endpoint in the {section} section — got {urls}"
        # Scanned in the file text, not the parsed feed rows: the retired endpoint
        # must be gone from alternates and comments too, not just from a feed row.
        assert retired not in text, f"retired (404) Maltrail endpoint still shipped: {retired}"
