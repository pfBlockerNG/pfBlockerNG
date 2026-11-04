"""Issue #3699: explicit VIP-only opt-in, honest client warning, save and safe disable."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .render_oracle import PhpErrorLogGuard, evaluate_render
from .test_dns_general_foreign_list_warning import _put, _snapshot
from .webui import scrape_form_fields

if TYPE_CHECKING:
    from playwright.sync_api import Page

    from ..conftest import SmokeVM
    from .webui import WebUI

PAGE = "/pfblockerng/pfblockerng_dns_general.php"
KEY = "pfb_dns_listen_vip_only"
PATH = f"{helpers.CFG_GLOBAL}/{KEY}"


@pytest.mark.ui_render
def test_vip_only_defaults_off_and_warns_about_plain_dns_and_client_reconfiguration(
    smoke_vm: SmokeVM, webui: WebUI
) -> None:
    original = helpers.config_get_state(smoke_vm, PATH)
    try:
        helpers.config_restore_state(smoke_vm, PATH, (False, ""))
        guard = PhpErrorLogGuard(smoke_vm)
        guard.snapshot()
        response = webui.get(PAGE)
        result = evaluate_render(PAGE, response.status_code, response.text, ("Resolver addresses",))
        assert result.ok, result.detail
        fields = scrape_form_fields(response.text)
        assert f'name="{KEY}"' in response.text, "VIP-only checkbox missing from DNS General"
        assert KEY not in fields, f"absent VIP-only option must render unchecked: {fields}"
        for warning in ("PLAIN DNS", "DHCPv4", "DHCPv6", "RA", "static", "renewal", "DDR", "encrypted DNS"):
            assert warning in response.text, f"VIP-only warning omits {warning!r}"
        guard.assert_no_growth()
    finally:
        helpers.config_restore_state(smoke_vm, PATH, original)


@pytest.mark.ui_browser
def test_vip_only_enable_save_roundtrip_and_disable_with_missing_prerequisites(
    browser_page: Page, smoke_vm: SmokeVM, webui: WebUI
) -> None:
    """Only a disposable smoke VM: manual inert VIP avoids provisioning an address or clearing leases."""
    from .test_browser_dns import _save
    from .test_browser_feeds import _open

    paths = (helpers.CFG_GLOBAL, "installedpackages/pfblockerngdns", "virtualip/vip", "dhcpd", "dhcpdv6", "unbound")
    originals = {path: _snapshot(smoke_vm, path) for path in paths}
    vip = {
        "mode": "ipalias",
        "interface": "lo0",
        "type": "single",
        "subnet": "192.0.2.99",
        "subnet_bits": "32",
        "descr": "pfbsmoke3699",
        "uniqid": "pfbsmoke3699",
    }
    try:
        _put(smoke_vm, "virtualip/vip", [*(originals["virtualip/vip"] or []), vip])
        _put(smoke_vm, "dhcpd", {})
        _put(smoke_vm, "dhcpdv6", {})
        helpers.config_set(smoke_vm, helpers.dns_config_path("pfb_dns"), "on")
        helpers.config_set(smoke_vm, PATH, "")
        _open(browser_page, webui, PAGE)
        toggle = browser_page.get_by_role("checkbox", name="VIP-only mode", exact=True)
        assert toggle.count() == 1 and not toggle.is_checked(), "VIP-only must be an explicit unchecked opt-in"
        browser_page.locator('input[name="pfb_dns_listen_vip"]').check()
        browser_page.locator('select[name="pfb_dns_listen_vip4"]').select_option("_vippfbsmoke3699")
        browser_page.locator('select[name="pfb_dns_listen_vip6"]').select_option("none")
        toggle.check()
        _save(browser_page)
        assert browser_page.locator(".input-errors").count() == 0, browser_page.locator(
            ".input-errors"
        ).all_inner_texts()
        assert helpers.config_get(smoke_vm, PATH) == "on", "enable save did not persist VIP-only policy"
        assert toggle.is_checked(), "saved mode must render checked after redirect"
        helpers.config_set(smoke_vm, helpers.dns_config_path("pfb_dns"), "")
        _open(browser_page, webui, PAGE)
        toggle.uncheck()
        browser_page.locator('input[name="pfb_dns_listen_vip"]').uncheck()
        browser_page.locator('select[name="pfb_dns_listen_vip4"]').select_option("none")
        _save(browser_page)
        assert browser_page.locator(".input-errors").count() == 0, browser_page.locator(
            ".input-errors"
        ).all_inner_texts()
        assert helpers.config_get(smoke_vm, PATH) == "", "disable must remain possible without pfB-DNS or a VIP"
        assert not toggle.is_checked(), "disabled mode must render unchecked"
    finally:
        for path, value in originals.items():
            _put(smoke_vm, path, value)
