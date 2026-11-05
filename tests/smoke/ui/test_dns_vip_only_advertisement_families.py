"""VIP-only refuses an unselected family's real DNS advertisements without saving config."""

from __future__ import annotations

import base64
import json
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .test_dns_general_foreign_list_warning import _put, _snapshot
from .test_dns_vip_only_mode import PAGE, PATH

if TYPE_CHECKING:
    from collections.abc import Iterator

    from playwright.sync_api import Page

    from ..conftest import SmokeVM
    from .webui import WebUI


@pytest.fixture
def advertisement_fixture(smoke_vm: SmokeVM) -> Iterator[None]:
    """Only the leased disposable guest; restore every changed config node and native RA output."""
    paths = (helpers.CFG_GLOBAL, "installedpackages/pfblockerngdns", "virtualip/vip", "dhcpd", "dhcpdv6", "unbound")
    original = {path: _snapshot(smoke_vm, path) for path in paths}
    ipv6 = helpers.set_interface_ipv6(
        smoke_vm, helpers.IPV6_LOCAL_IFACE, helpers.IPV6_LOCAL_ADDR, helpers.IPV6_LOCAL_BITS
    )
    vip = {
        "mode": "ipalias",
        "interface": "lo0",
        "type": "single",
        "subnet": "192.0.2.99",
        "subnet_bits": "32",
        "descr": "pfbsmoke3699families",
        "uniqid": "pfbsmoke3699families",
    }
    try:
        _put(smoke_vm, "virtualip/vip", [*(original["virtualip/vip"] or []), vip])
        _put(smoke_vm, "dhcpd", {})
        _put(smoke_vm, "dhcpdv6", {})
        helpers.config_set(smoke_vm, "unbound/enable", "")
        helpers.config_set(smoke_vm, helpers.dns_config_path("pfb_dns"), "on")
        helpers.config_set(smoke_vm, PATH, "")
        yield
    finally:
        for path, value in original.items():
            _put(smoke_vm, path, value)
        helpers.restore_interface_ipv6(smoke_vm, helpers.IPV6_LOCAL_IFACE, ipv6)
        result = helpers.php_eval(smoke_vm, "services_radvd_configure(); echo 'RA_RESTORED';")
        assert result.returncode == 0 and "RA_RESTORED" in result.stdout, result


def _native_ra(smoke_vm: SmokeVM) -> str:
    raw = helpers._php_read_scalar(
        smoke_vm,
        "services_radvd_configure();",
        "base64_encode(file_get_contents('/var/etc/radvd.conf'))",
    )
    generated = base64.b64decode(raw).decode()
    print(f"NATIVE_RADVD_CONFIG={generated}")
    return generated


@pytest.mark.ui_browser
@pytest.mark.parametrize("kind", ["foreign", "own", "automatic", "shared_automatic"])
def test_vip_only_other_family_ra_rejection_preserves_whole_config(
    browser_page: Page, smoke_vm: SmokeVM, webui: WebUI, advertisement_fixture: None, kind: str
) -> None:
    from .test_browser_dns import _save
    from .test_browser_feeds import _open

    own = helpers.get_lan_ipv6(smoke_vm)
    settings: dict[str, object] = {"ramode": "unmanaged", "radvd-dns": "enabled"}
    expected = own
    if kind in ("foreign", "own"):
        expected = "2001:db8:99::53" if kind == "foreign" else own
        settings["radnsserver"] = [expected]
    elif kind == "shared_automatic":
        settings.update({"rasamednsasdhcp6": "", "dnsserver": []})
    _put(smoke_vm, "dhcpdv6", {helpers.IPV6_LOCAL_IFACE: settings})
    generated = _native_ra(smoke_vm)
    assert f"RDNSS {expected}" in generated, f"native core did not advertise the test's IPv6 DNS: {generated}"
    # Record the native generator identity, including implementations moved to another core include.
    source = helpers._php_read_scalar(
        smoke_vm,
        "$r = new ReflectionFunction('services_radvd_configure');",
        "json_encode(['file' => $r->getFileName(), 'sha256' => hash_file('sha256', $r->getFileName()), "
        "'source' => implode('', array_slice(file($r->getFileName()), $r->getStartLine()-1, "
        "$r->getEndLine()-$r->getStartLine()+1))])",
    )
    print(f"NATIVE_RA_SOURCE={json.dumps(json.loads(source), sort_keys=True)}")
    _open(browser_page, webui, PAGE)
    browser_page.locator('input[name="pfb_dns_listen_vip"]').check()
    browser_page.locator('select[name="pfb_dns_listen_vip4"]').select_option("_vippfbsmoke3699families")
    browser_page.locator('select[name="pfb_dns_listen_vip6"]').select_option("none")
    browser_page.get_by_role("checkbox", name="VIP-only mode", exact=True).check()
    before = helpers._php_read_scalar(smoke_vm, "", "hash_file('sha256', '/conf/config.xml')")
    _save(browser_page)
    after = helpers._php_read_scalar(smoke_vm, "", "hash_file('sha256', '/conf/config.xml')")
    errors = " ".join(browser_page.locator(".input-errors").all_inner_texts())
    assert "RA" in errors and helpers.IPV6_LOCAL_IFACE in errors, f"missing scoped activation error: {errors!r}"
    assert after == before, f"rejected activation changed config.xml: before={before} after={after}"
    assert helpers.config_get(smoke_vm, PATH) == "", "rejected activation must leave VIP-only off"
    assert _native_ra(smoke_vm) == generated, "rejection changed the actual native DNS advertisement"


@pytest.mark.ui_browser
def test_vip_only_single_family_with_explicit_silent_ra_can_save(
    browser_page: Page, smoke_vm: SmokeVM, webui: WebUI, advertisement_fixture: None
) -> None:
    from .test_browser_dns import _save
    from .test_browser_feeds import _open

    _put(smoke_vm, "dhcpdv6", {helpers.IPV6_LOCAL_IFACE: {"ramode": "unmanaged", "radvd-dns": "disabled"}})
    generated = _native_ra(smoke_vm)
    assert "AdvSendAdvert on" in generated, f"test needs active RA, not a disabled service: {generated}"
    assert "RDNSS" not in generated, f"native DNS-advertisement disable must actually suppress RDNSS: {generated}"
    _open(browser_page, webui, PAGE)
    browser_page.locator('input[name="pfb_dns_listen_vip"]').check()
    browser_page.locator('select[name="pfb_dns_listen_vip4"]').select_option("_vippfbsmoke3699families")
    browser_page.locator('select[name="pfb_dns_listen_vip6"]').select_option("none")
    browser_page.get_by_role("checkbox", name="VIP-only mode", exact=True).check()
    _save(browser_page)
    errors = browser_page.locator(".input-errors").all_inner_texts()
    assert not errors, f"safe single-family activation rejected: {errors}"
    assert helpers.config_get(smoke_vm, PATH) == "on", "safe single-family opt-in did not persist"
    assert "RDNSS" not in _native_ra(smoke_vm), "apply must not invent unsupported-family DNS advertising"
