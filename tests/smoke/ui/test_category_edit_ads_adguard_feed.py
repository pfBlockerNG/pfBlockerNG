"""The Feeds tab's ADs group offers the upstream AdGuard DNS filter (issue #3533).

Adding the ADs group from the Feeds tab opens the category editor with one row
per catalogue feed of that group. The upstream filter must be one of those rows;
the Firebog plain-domain copy belongs to Firebog_Advertising, not to ADs.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from .render_oracle import evaluate_render
from .webui import scrape_form_fields

if TYPE_CHECKING:
    from .webui import WebUI

_ADDGROUP_ADS_PAGE = "/pfblockerng/pfblockerng_category_edit.php?type=dnsbl&act=addgroup&atype=ADs"
_ADGUARD_DNS_URL = "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"
_FIREBOG_ADGUARD_URL = "https://v.firebog.net/hosts/AdguardDNS.txt"


@pytest.mark.ui_render
def test_addgroup_ads_offers_upstream_adguard_dns_filter(webui: WebUI) -> None:
    resp = webui.get(_ADDGROUP_ADS_PAGE)
    result = evaluate_render(_ADDGROUP_ADS_PAGE, resp.status_code, resp.text, ("Override Default Schedule",))
    assert result.ok, f"Tier-A render oracle failed for the ADs addgroup page: {result.detail}"
    fields = scrape_form_fields(resp.text)
    rows = {value: key.removeprefix("url-") for key, value in fields.items() if key.startswith("url-")}
    assert _ADGUARD_DNS_URL in rows, f"ADs addgroup must offer {_ADGUARD_DNS_URL} — got rows {sorted(rows)}"
    header = fields.get(f"header-{rows[_ADGUARD_DNS_URL]}")
    assert header == "AdGuard_DNS_Filter", f"AdGuard row header: expected 'AdGuard_DNS_Filter', got {header!r}"
    assert _FIREBOG_ADGUARD_URL not in rows, "the Firebog copy belongs to Firebog_Advertising, not ADs"
