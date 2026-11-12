"""Listener-only VIP policy must not reject or rewrite administrator DNS lists."""

from __future__ import annotations

import ipaddress
import json
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .test_browser_dns import _save
from .test_browser_feeds import JS_TIMEOUT_MS, _open, _shot
from .test_dns_general_foreign_list_warning import _put, _snapshot

if TYPE_CHECKING:
    from pathlib import Path

    from playwright.sync_api import Page

    from ..conftest import SmokeVM
    from .webui import WebUI

PAGE = "/pfblockerng/pfblockerng_dns_general.php"
MODE_PATH = f"{helpers.CFG_GLOBAL}/pfb_dns_listen_vip_only"
NOTICES = ("require_once('notices.inc');", "json_encode(get_notices() ?: new stdClass())")  # pending, by filing time


@pytest.mark.ui_browser
def test_listener_only_mode_saves_without_rewriting_foreign_dhcp_or_ra_dns(
    browser_page: Page, smoke_vm: SmokeVM, webui: WebUI, screenshot_dir: Path
) -> None:
    """General saves preserve foreign lists and append-only ownership through listener-mode transitions."""
    paths = (helpers.CFG_GLOBAL, "installedpackages/pfblockerngdns", "virtualip/vip", "dhcpd", "dhcpdv6")
    originals = {path: _snapshot(smoke_vm, path) for path in paths}
    notices = json.loads(helpers._php_read_scalar(smoke_vm, *NOTICES))
    vip = {
        "mode": "ipalias",
        "interface": "lo0",
        "type": "single",
        "subnet": "192.0.2.99",
        "subnet_bits": "32",
        "descr": "pfbsmoke3699listeneronly",
        "uniqid": "pfbsmoke3699listeneronly",
    }
    core_hash = "hash('sha256', serialize([config_get_path('dhcpd', NULL), config_get_path('dhcpdv6', NULL)]))"
    try:
        _put(smoke_vm, "virtualip/vip", [*(originals["virtualip/vip"] or []), vip])
        # The scope keeps the box's own pool: the saves that add the VIP regenerate the DHCP server, and pfSense files a
        # notice for an enabled scope without a valid pool
        lan = (originals["dhcpd"] or {}).get(helpers.IPV6_LOCAL_IFACE, {})
        _put(smoke_vm, "dhcpd", {helpers.IPV6_LOCAL_IFACE: {**lan, "enable": "", "dnsserver": ["192.0.2.53"]}})
        _put(
            smoke_vm,
            "dhcpdv6",
            {
                helpers.IPV6_LOCAL_IFACE: {
                    "enable": "",
                    "dnsserver": ["2001:db8:99::53"],
                    "ramode": "unmanaged",
                    "radvd-dns": "enabled",
                    "radnsserver": ["2001:db8:98::53"],
                }
            },
        )
        helpers.config_set(smoke_vm, helpers.dns_config_path("pfb_dns"), "on")
        helpers.config_set(smoke_vm, MODE_PATH, "")
        before = helpers._php_read_scalar(smoke_vm, "", core_hash)
        _open(browser_page, webui, PAGE)
        browser_page.locator('input[name="pfb_dns_listen_vip"]').check()
        browser_page.locator('select[name="pfb_dns_listen_vip4"]').select_option("_vippfbsmoke3699listeneronly")
        browser_page.locator('select[name="pfb_dns_listen_vip6"]').select_option("none")
        mode = browser_page.get_by_role("checkbox", name="VIP-only mode", exact=True)
        mode.check()
        _save(browser_page)
        after = helpers._php_read_scalar(smoke_vm, "", core_hash)
        print(f"LISTENER_ONLY_CORE_DNS_SHA256 before={before} after={after}")
        errors = browser_page.locator(".input-errors").all_inner_texts()
        assert not errors, f"listener-only activation rejected administrator DNS lists: {errors}"
        assert mode.is_checked(), "successful save did not render VIP-only mode enabled"
        assert helpers.config_get(smoke_vm, MODE_PATH) == "on", "successful save did not persist VIP-only mode"
        assert before == after, "General save rewrote serialized DHCP4/DHCP6/RA configuration"
        help_group = browser_page.locator(".form-group").filter(has=mode)
        help_group.get_by_title("More information", exact=True).click()
        help_group.locator('[class^="infoblock"]').wait_for(state="visible", timeout=JS_TIMEOUT_MS)
        _shot(browser_page, screenshot_dir, "dns_listener_only_warning_full")
        help_group.screenshot(path=str(screenshot_dir / "dns_listener_only_warning_field.png"))
        own_address = helpers._php_read_scalar(
            smoke_vm,
            "require_once('interfaces.inc');",
            f"get_interface_ip({helpers._php_str(helpers.IPV6_LOCAL_IFACE)})",
        )
        assert ipaddress.ip_address(own_address).version == 4
        dns_path = f"dhcpd/{helpers.IPV6_LOCAL_IFACE}/dnsserver"
        _put(smoke_vm, dns_path, [own_address])
        for enabled in (True, False):
            _open(browser_page, webui, PAGE)
            mode.set_checked(enabled)
            _save(browser_page)
            errors = browser_page.locator(".input-errors").all_inner_texts()
            assert not errors, f"listener-mode transition failed: {errors}"
            actual = _snapshot(smoke_vm, dns_path)
            print(f"LISTENER_ONLY_OWN_DNS mode={enabled} servers={actual}")
            assert actual == [own_address, vip["subnet"]], "listener mode deleted a pre-existing DNS address"
            assert helpers.config_get(smoke_vm, MODE_PATH) == ("on" if enabled else "")
        _open(browser_page, webui, PAGE)
        browser_page.locator('input[name="pfb_dns_listen_vip"]').uncheck()
        browser_page.locator('select[name="pfb_dns_listen_vip4"]').select_option("none")
        _save(browser_page)
        errors = browser_page.locator(".input-errors").all_inner_texts()
        assert not errors, f"Resolver VIP removal failed: {errors}"
        actual = _snapshot(smoke_vm, dns_path)
        print(f"LISTENER_ONLY_OWN_DNS removed servers={actual}")
        assert actual == [own_address], "removing package VIPs removed an original DNS address"
    finally:
        for path, value in originals.items():
            _put(smoke_vm, path, value)
    left = {
        key: row for key, row in json.loads(helpers._php_read_scalar(smoke_vm, *NOTICES)).items() if key not in notices
    }
    # Every later page renders a pending notice, a second .modal beside any dialog it opens (issue #3836)
    assert not left, f"the saves left system notices behind: {left}"
