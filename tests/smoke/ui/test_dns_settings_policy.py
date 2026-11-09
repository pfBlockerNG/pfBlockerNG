"""Issue #3699: service VIP exclusions and the active-service DNS Name requirement.

Only config.xml fixtures and unapplied page saves: no interface/service reconfiguration.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .render_oracle import PhpErrorLogGuard, evaluate_render
from .test_dns_general_foreign_list_warning import _put, _snapshot
from .test_dns_readonly_save import _write_state
from .test_dnsbl_blocking_modes import _option_values, _select_block

if TYPE_CHECKING:
    from collections.abc import Iterator

    from playwright.sync_api import Page

    from .webui import WebUI

DNS_PAGE = "/pfblockerng/pfblockerng_dns_general.php"  # holds the pfB-DNS settings since issue #3771
LISTS = ("pfb_dns_interface", "pfb_dns_dot_interface", "pfb_dns_doh_interface", "pfb_dns_doq_interface")
SERVICES = ("dot", "doh", "doq", "ddr")
SAVED_KEYS = (
    "pfb_dns",
    "pfb_dns_name",
    "pfb_dns_sslcertref",
    *LISTS,
    "pfb_dns_dot",
    "pfb_dns_dot_port",
    "pfb_dns_dot_port6",
    "pfb_dns_doh",
    "pfb_dns_doh_port",
    "pfb_dns_doh_port6",
    "pfb_dns_doh_trusted",
    "pfb_dns_doq",
    "pfb_dns_doq_port",
    "pfb_dns_doq_port6",
    "pfb_dns_ddr",
    "pfb_dns_ddr_doh_443_interfaces",
)


@pytest.fixture
def settings_policy_box(smoke_vm: helpers.SmokeVM) -> Iterator[None]:
    """Same native rows include owned v4/v6 service VIPs and a selectable manual VIP."""
    originals = {key: helpers.config_get_state(smoke_vm, helpers.dns_config_path(key)) for key in SAVED_KEYS}
    vips = _snapshot(smoke_vm, "virtualip/vip")
    rows = []
    for suffix, address, description in (
        ("sink4", "192.0.2.221", "pfB_AUTO_VIP_v4"),
        ("sink6", "2001:db8::221", "pfB_AUTO_VIP_v6"),
        ("dns4", "192.0.2.222", "pfB_DNS_LISTEN_VIP_v4"),
        ("dns6", "2001:db8::222", "pfB_DNS_LISTEN_VIP_v6"),
        ("manual", "192.0.2.223", "Manual Resolver VIP"),
    ):
        rows.append(
            {
                "mode": "ipalias",
                "interface": "lo0",
                "type": "single",
                "subnet": address,
                "subnet_bits": "128" if ":" in address else "32",
                "descr": description,
                "uniqid": f"pfb3699{suffix}",
            }
        )
    try:
        _put(smoke_vm, "virtualip/vip", [*(vips or []), *rows])
        stored = "lo0,opt3699gone," + ",".join(f"_vip{row['uniqid']}" for row in rows)
        for key in LISTS:
            helpers.config_set(smoke_vm, helpers.dns_config_path(key), stored)
        yield
    finally:
        _put(smoke_vm, "virtualip/vip", vips)
        for key, state in originals.items():
            helpers.config_restore_state(smoke_vm, helpers.dns_config_path(key), state)


@pytest.mark.ui_render
def test_dns_policy_render_excludes_owned_vips_not_manual_or_unavailable(
    smoke_vm: helpers.SmokeVM, webui: WebUI, settings_policy_box: None
) -> None:
    """Real GET offers manual VIP and unknown stored tokens, never owned service VIPs."""
    guard = PhpErrorLogGuard(smoke_vm)
    guard.snapshot()
    response = webui.get(DNS_PAGE)
    rendered = evaluate_render(DNS_PAGE, response.status_code, response.text, ("pfB-DNS Settings",))
    assert rendered.ok, rendered.detail
    for key in LISTS:
        values = _option_values(_select_block(response.text, key + "[]"))
        assert {"all", "lo0", "opt3699gone", "_vippfb3699manual"} <= values, (key, values)
        assert not values.intersection(f"_vippfb3699{suffix}" for suffix in ("sink4", "sink6", "dns4", "dns6")), (
            key,
            values,
        )
    guard.assert_no_growth()


@pytest.mark.ui_browser
def test_dns_name_rejection_then_disable_and_plain_only_save(
    browser_page: Page, webui: WebUI, smoke_vm: helpers.SmokeVM, settings_policy_box: None
) -> None:
    """Missing Name rejects each active service without writes; disable and plain-only really save."""
    from .test_browser_dns import _save_pfb_dns
    from .test_browser_feeds import _open

    page = browser_page
    _open(page, webui, DNS_PAGE)
    for key in LISTS:
        select = page.locator(f'select[name="{key}[]"], select[name="{key}"]')
        values = select.locator("option").evaluate_all("nodes => nodes.map(node => node.value)")
        assert "_vippfb3699manual" in values, values
        assert not set(values).intersection(f"_vippfb3699{suffix}" for suffix in ("sink4", "sink6", "dns4", "dns6")), (
            values
        )
        select.select_option("lo0")
    cert = page.locator('select[name="pfb_dns_sslcertref"]')
    assert cert.count() == 1, "smoke VM needs a server certificate with private key"
    cert_ref = cert.locator("option").first.get_attribute("value")
    assert cert_ref, "certificate selector has no usable refid"
    cert.select_option(cert_ref)
    page.locator('input[name="pfb_dns_name"]').fill("")
    page.locator('input[name="pfb_dns"]').check()
    page.locator('select[name^="pfb_dns_ddr_doh_443_interfaces"]').evaluate(
        "el => { for (const option of el.options) option.selected = false; }"
    )
    for service in SERVICES:
        page.locator(f'input[name="pfb_dns_{service}"]').set_checked(False)
    before = _write_state(smoke_vm)
    for service in SERVICES:
        page.locator(f'input[name="pfb_dns_{service}"]').check()
        _save_pfb_dns(page)
        errors = page.locator(".input-errors")
        assert errors.count() == 1 and "DNS Name" in errors.inner_text(), f"{service}: missing Name not rejected"
        assert _write_state(smoke_vm) == before, f"{service}: rejected POST changed configuration/markers"
        page.locator(f'input[name="pfb_dns_{service}"]').uncheck()

    for service in SERVICES:
        page.locator(f'input[name="pfb_dns_{service}"]').check()
    page.locator('input[name="pfb_dns"]').uncheck()
    _save_pfb_dns(page)
    assert page.locator(".input-errors").count() == 0, page.locator(".input-errors").all_inner_texts()
    assert helpers.config_get(smoke_vm, helpers.dns_config_path("pfb_dns")) == ""
    assert helpers.config_get(smoke_vm, helpers.dns_config_path("pfb_dns_name")) == ""
    for service in SERVICES:
        assert helpers.config_get(smoke_vm, helpers.dns_config_path(f"pfb_dns_{service}")) == "on", service
        page.locator(f'input[name="pfb_dns_{service}"]').uncheck()
    page.locator('input[name="pfb_dns"]').check()
    _save_pfb_dns(page)
    assert page.locator(".input-errors").count() == 0, page.locator(".input-errors").all_inner_texts()
    assert helpers.config_get(smoke_vm, helpers.dns_config_path("pfb_dns")) == "on"
    assert helpers.config_get(smoke_vm, helpers.dns_config_path("pfb_dns_name")) == ""
