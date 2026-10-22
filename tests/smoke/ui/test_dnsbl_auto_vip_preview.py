"""Tier-A ``ui_render`` coverage for issue #3565's auto-VIP preview on the DNSBL page.

The page previews the address "Create VIPs automatically" would use and pre-fills the VIP fields with it.
A VIP the package already created (descr ``pfB_AUTO_VIP_v4``/``_v6``) is that address: it must neither disable
the checkbox nor shift the preview to another candidate.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .render_oracle import PhpErrorLogGuard, evaluate_render

if TYPE_CHECKING:
    from collections.abc import Iterator

    from ..conftest import SmokeVM
    from .webui import WebUI

pytestmark = pytest.mark.ui_render

DNSBL_PAGE = "/pfblockerng/pfblockerng_dnsbl.php"
PAGE_MARKER = "DNSBL Webserver Configuration"
CFG = "installedpackages/pfblockerngdnsblsettings/config/0"
AUTO_CHECKBOX = "pfb_dnsvip_auto"

# The package's own sinkhole VIPs, as pfb_manage_dnsbl_vip stores them, at the first candidate of each family.
OWN_V4 = {
    "mode": "ipalias",
    "interface": helpers.SMOKE_VIP_IFACE,
    "type": "single",
    "subnet": helpers.AUTO_VIP_IP4,
    "subnet_bits": "32",
    "descr": helpers.AUTO_VIP_DESCR_V4,
    "uniqid": "pfbsmoke3565own4",
}
OWN_V6 = {
    "mode": "ipalias",
    "interface": helpers.SMOKE_VIP_IFACE,
    "type": "single",
    "subnet": "fd00:53:53:53:53:53:53:53",
    "subnet_bits": "128",
    "descr": "pfB_AUTO_VIP_v6",
    "uniqid": "pfbsmoke3565own6",
}
OWN_VIPS = (OWN_V4, OWN_V6)


class _Inputs(HTMLParser):
    """The attributes of every ``<input>`` by id; a bare attribute (``checked``) maps to ``None``."""

    def __init__(self) -> None:
        super().__init__()
        self.by_id: dict[str, dict[str, str | None]] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if tag == "input" and attributes.get("id"):
            self.by_id[str(attributes["id"])] = attributes


def _set_own_vips(vm: SmokeVM, present: bool) -> None:
    """Drop every marked VIP from config and lo0; then add the two own VIPs back (stored and live) if ``present``.

    The interface_vip_* calls are guarded like ``h.set_dnsbl_vip6``'s; ifconfig then must show exactly the
    expected aliases, with a direct-alias fallback either way (issue #1013).
    """
    markers = [vip["descr"] for vip in OWN_VIPS]
    uniqids = [vip["uniqid"] for vip in OWN_VIPS]
    add = "".join(f"$add[] = {helpers._php_kv_array(vip)};\n" for vip in OWN_VIPS) if present else ""
    snippet = (
        "require_once('interfaces.inc');\n"
        "$keep = array();\n"
        "$add = array();\n"
        "foreach (config_get_path('virtualip/vip', array()) as $v) {\n"
        f"  if (in_array(($v['uniqid'] ?? ''), array({', '.join(map(helpers._php_str, uniqids))}), TRUE)"
        f" || in_array(($v['descr'] ?? ''), array({', '.join(map(helpers._php_str, markers))}), TRUE)) {{\n"
        "    if (function_exists('interface_vip_bring_down')) { interface_vip_bring_down($v); }\n"
        "    continue;\n"
        "  }\n"
        "  $keep[] = $v;\n"
        "}\n"
        f"{add}"
        "config_set_path('virtualip/vip', array_merge($keep, $add));\n"
        "write_config('pfBlockerNG smoke: issue #3565 own auto VIPs');\n"
        "foreach ($add as $v) {\n"
        "  if (function_exists('interface_vip_configure')) { interface_vip_configure($v); }\n"
        "}\n"
        "echo 'OK';"
    )
    result = helpers.php_eval(vm, snippet)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_set_own_vips({present}): rc={result.returncode} {result.stderr!r} {result.stdout!r}")
    for vip in OWN_VIPS:
        address = vip["subnet"]
        if helpers.vip_alias_live(vm, address) == present:
            continue
        verb = "alias" if present else "-alias"
        if ":" in address:
            vm.ssh(f"/sbin/ifconfig {helpers.SMOKE_VIP_IFACE} inet6 {address} prefixlen 128 {verb}")
        else:
            vm.ssh(f"/sbin/ifconfig {helpers.SMOKE_VIP_IFACE} inet {address}/32 {verb}")
    live = [vip["subnet"] for vip in OWN_VIPS if helpers.vip_alias_live(vm, vip["subnet"])]
    expected = [vip["subnet"] for vip in OWN_VIPS] if present else []
    assert live == expected, f"own auto-VIP aliases live on {helpers.SMOKE_VIP_IFACE}: expected {expected}, got {live}"


def _resolver_listens_v6(vm: SmokeVM) -> bool:
    expr = "pfb_unbound_listens_v6() ? 'yes' : 'no'"
    return helpers._php_read_scalar(vm, "require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');", expr) == "yes"


@pytest.fixture
def resolver_on_v6(smoke_vm: SmokeVM) -> Iterator[None]:
    """The v6 preview needs a resolver listening on IPv6: give LAN a static IPv6 if the box has none, restore after."""
    prior = (
        None
        if _resolver_listens_v6(smoke_vm)
        else helpers.set_interface_ipv6(
            smoke_vm, helpers.IPV6_LOCAL_IFACE, helpers.IPV6_LOCAL_ADDR, helpers.IPV6_LOCAL_BITS
        )
    )
    try:
        resolver = helpers.config_get_state(smoke_vm, "unbound/active_interface")
        assert _resolver_listens_v6(smoke_vm), (
            f"precondition: pfb_unbound_listens_v6() must be TRUE for the v6 case; got FALSE "
            f"(unbound/active_interface {resolver!r}, LAN IPv6 provisioned by the test: {prior is not None})"
        )
        yield
    finally:
        if prior is not None:
            helpers.restore_interface_ipv6(smoke_vm, helpers.IPV6_LOCAL_IFACE, prior)


@pytest.fixture
def auto_create_on(smoke_vm: SmokeVM) -> Iterator[None]:
    """Store "Create VIPs automatically" as on; afterwards restore it, drop the own VIPs, re-establish the baseline."""
    path = f"{CFG}/{AUTO_CHECKBOX}"
    saved = helpers.config_get_state(smoke_vm, path)
    try:
        helpers.set_dnsvip_auto(smoke_vm, True)
        yield
    finally:
        helpers.config_restore_state(smoke_vm, path, saved)
        _set_own_vips(smoke_vm, False)
        helpers.ensure_dnsbl_vip(smoke_vm)
        for vip in OWN_VIPS:
            stored = helpers.marked_vip_subnet(smoke_vm, vip["descr"])
            assert stored == "", f"teardown: {vip['descr']} still stored at {stored!r}"


def _render(smoke_vm: SmokeVM, webui: WebUI) -> str:
    guard = PhpErrorLogGuard(smoke_vm)
    guard.snapshot()
    resp = webui.get(DNSBL_PAGE)
    result = evaluate_render(DNSBL_PAGE, resp.status_code, resp.text, (PAGE_MARKER,))
    assert result.ok, f"Tier-A render oracle failed for {DNSBL_PAGE}: {result.detail}"
    guard.assert_no_growth()
    return resp.text


def _observe(html: str) -> dict[str, object]:
    """What the page decided about auto-create: the checkbox state and the two pre-fill addresses."""
    inputs = _Inputs()
    inputs.feed(html)
    checkbox = inputs.by_id.get(AUTO_CHECKBOX)
    assert checkbox is not None, f"no #{AUTO_CHECKBOX} input in the rendered page"
    prefill = {}
    for family in ("4", "6"):
        found = re.search(rf'var pfb_auto_vip{family} = "([^"]*)";', html)
        assert found is not None, f"no pfb_auto_vip{family} pre-fill in the rendered page"
        prefill[f"pfb_auto_vip{family}"] = found.group(1)
    return {"checkbox_disabled": "disabled" in checkbox, "checkbox_checked": "checked" in checkbox, **prefill}


def test_dnsbl_page_previews_the_packages_own_auto_vips(
    smoke_vm: SmokeVM, webui: WebUI, resolver_on_v6: None, auto_create_on: None
) -> None:
    """The preview is the package's own VIP address and auto-create stays usable while those VIPs exist.

    Given: "Create VIPs automatically" stored on, a resolver listening on IPv6, and no own VIP yet
    When:  the package's own VIPs sit at both first candidates (stored and live)
    Then:  the checkbox is enabled and checked, and the pre-fill carries each VIP's own address
    """
    expected = {
        "checkbox_disabled": False,
        "checkbox_checked": True,
        "pfb_auto_vip4": OWN_V4["subnet"],
        "pfb_auto_vip6": OWN_V6["subnet"],
    }

    for vip in OWN_VIPS:
        stored = helpers.marked_vip_subnet(smoke_vm, vip["descr"])
        assert stored == "", (
            f"before-state: {vip['descr']} is stored at {stored!r}" + f"\n{helpers.fwobj_state_snapshot(smoke_vm)}"
        )
    before = _observe(_render(smoke_vm, webui))
    assert before == expected, f"before-state (no own VIP): expected {expected}, got {before}"

    _set_own_vips(smoke_vm, True)
    for vip in OWN_VIPS:
        stored = helpers.marked_vip_subnet(smoke_vm, vip["descr"])
        assert stored == vip["subnet"], (
            f"setup: {vip['descr']} expected at {vip['subnet']}, got {stored!r}"
            + f"\n{helpers.fwobj_state_snapshot(smoke_vm)}"
        )

    after = _observe(_render(smoke_vm, webui))
    assert after == expected, f"with the package's own VIPs stored: expected {expected}, got {after}"
