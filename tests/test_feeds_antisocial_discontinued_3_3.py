"""The decommissioned AntiSocial Engineer DNSBL feed must be flagged discontinued (issue #4230).

The publisher decommissioned the list on 30 September 2025 and its catalogue URL now
redirects to a 404 page. ``convert_feeds_json()`` drops feeds whose ``status`` is
``discontinued``, so the flag is what keeps the Feeds picker from offering it.
"""

from __future__ import annotations

import json
from pathlib import Path

_FEEDS_JSON = Path(__file__).parents[1] / "src/usr/local/www/pfblockerng/pfblockerng_feeds.json"


def test_antisocial_feed_is_discontinued() -> None:
    catalog = json.loads(_FEEDS_JSON.read_text(encoding="utf-8"))
    matches = [feed for feed in catalog["dnsbl"]["Malicious2"]["feeds"] if feed.get("header") == "AntiSocial_UK_BD"]
    assert len(matches) == 1, f"AntiSocial_UK_BD must remain in dnsbl/Malicious2 (flagged, not deleted): {matches}"
    assert matches[0].get("status") == "discontinued", "AntiSocial_UK_BD must be marked discontinued (#4230)"
