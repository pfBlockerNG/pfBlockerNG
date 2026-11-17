"""A dashboard widget save with daily/weekly counter clearing installs no crontab entry (#3996).

Core reads the cadences at its day change, so the save only records them and tells Core.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .webui import scrape_form_fields

if TYPE_CHECKING:
    from .webui import WebUI

pytestmark = pytest.mark.ui_e2e

WIDGET_PAGE = "/widgets/widgets/pfblockerng.widget.php"
_IP_CFG = "installedpackages/pfblockerngglobal/widget-clearip"
_DNSBL_CFG = "installedpackages/pfblockerngglobal/widget-cleardnsbl"


def test_widget_save_with_daily_and_weekly_clearing_leaves_no_cron_entry(
    webui: WebUI, smoke_vm: helpers.SmokeVM
) -> None:
    """Given the widget page's own fields with clearip=daily and cleardnsbl=weekly, the save stores both
    cadences and no pfBlockerNG entry exists in root's crontab, /etc/crontab or config.xml afterwards."""
    vm = smoke_vm
    originals = (helpers.config_get(vm, _IP_CFG), helpers.config_get(vm, _DNSBL_CFG))
    try:
        payload = scrape_form_fields(webui.get(WIDGET_PAGE).text)
        payload.update({"pfb_submit": "save", "pfb_clearip": "daily", "pfb_cleardnsbl": "weekly"})
        resp = webui.session.post(
            webui.url(WIDGET_PAGE), data=payload, headers={"Sec-Fetch-Site": "same-origin"}, timeout=30
        )
        assert resp.status_code == 200, f"widget save -> HTTP {resp.status_code}"
        assert helpers.config_get(vm, _IP_CFG) == "daily", "the clearip cadence was not saved"
        assert helpers.config_get(vm, _DNSBL_CFG) == "weekly", "the cleardnsbl cadence was not saved"
        helpers.assert_no_pfb_cron_entry(vm, "widget save daily/weekly")
    finally:
        helpers.config_set(vm, _IP_CFG, originals[0])
        helpers.config_set(vm, _DNSBL_CFG, originals[1])
