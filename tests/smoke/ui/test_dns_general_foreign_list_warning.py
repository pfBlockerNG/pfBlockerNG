"""Tier-A ``ui_render`` coverage for issue #3693: DNS General warns of DNS lists Resolver addresses leaves alone.

With Resolver addresses on, a DHCPv4/DHCPv6/RA DNS-server list that names a server the administrator chose (neither
the interface's own address nor one pfBlockerNG added) gets no Resolver VIP. The page then names the list and the
servers it holds, so the administrator can add the VIP by hand.
"""

from __future__ import annotations

import base64
import json
import re
from typing import TYPE_CHECKING, Any

import pytest

from .. import helpers
from .render_oracle import PhpErrorLogGuard, evaluate_render

if TYPE_CHECKING:
    from collections.abc import Iterator

    from ..conftest import SmokeVM
    from .webui import WebUI

pytestmark = pytest.mark.ui_render

DNS_GENERAL_PAGE = "/pfblockerng/pfblockerng_dns_general.php"
SCOPE_INTERFACE = helpers.IPV6_LOCAL_IFACE
VIP_UNIQID = "pfbsmoke3693"
VIP_ADDRESS = "192.0.2.99"  # RFC 5737 TEST-NET-1: never a real address on the box
FOREIGN_SERVER = "192.0.2.53"
WARNING = re.compile(
    r"Resolver addresses: the (?P<type>\S+) DNS servers of (?P<interface>[^<]+?) include (?P<servers>[^<]+?), "
    r"which pfBlockerNG did not add, so the Resolver VIP (?P<vip>\S+) is not added there\. "
    r"Add (?P=vip) to that list by hand if clients should use it\."
)
LISTENER_KEYS = ("pfb_dns_listen_vip", "pfb_dns_listen_vip4")


def _snapshot(vm: SmokeVM, path: str) -> Any:
    """The config node at ``path`` as plain JSON data (``None`` when absent)."""
    raw = helpers._php_read_scalar(
        vm, "", f"base64_encode(json_encode(config_get_path({helpers._php_str(path)}, NULL)))"
    )
    return json.loads(base64.b64decode(raw))


def _put(vm: SmokeVM, path: str, value: Any) -> None:
    """Write ``value`` (or delete the node when ``None``) at ``path`` and save config.xml; no service is regenerated."""
    if value is None:
        change = f"config_del_path({helpers._php_str(path)});"
    else:
        payload = base64.b64encode(json.dumps(value).encode()).decode()
        change = f"config_set_path({helpers._php_str(path)}, json_decode(base64_decode('{payload}'), TRUE));"
    result = helpers.php_eval(
        vm, f"{change}\nwrite_config('pfBlockerNG smoke: issue #3693 foreign DNS list');\necho 'OK';"
    )
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_put({path!r}) failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}")


@pytest.fixture
def resolver_addresses_on(smoke_vm: SmokeVM) -> Iterator[None]:
    """Resolver addresses on with one VIP of the box's own making and one DHCPv4 scope with an empty server list.

    Afterwards every node the test touched is put back exactly as it was found.
    """
    scalars = {key: helpers.config_get_state(smoke_vm, f"{helpers.CFG_GLOBAL}/{key}") for key in LISTENER_KEYS}
    vips = _snapshot(smoke_vm, "virtualip/vip")
    dhcpd = _snapshot(smoke_vm, "dhcpd")
    vip = {
        "mode": "ipalias",
        "interface": SCOPE_INTERFACE,
        "type": "single",
        "subnet": VIP_ADDRESS,
        "subnet_bits": "32",
        "descr": "pfbsmoke3693 resolver VIP",
        "uniqid": VIP_UNIQID,
    }
    try:
        _put(smoke_vm, "virtualip/vip", [*(vips or []), vip])
        _put(smoke_vm, "dhcpd", {SCOPE_INTERFACE: {"dnsserver": []}})
        helpers.config_set(smoke_vm, f"{helpers.CFG_GLOBAL}/pfb_dns_listen_vip4", f"_vip{VIP_UNIQID}")
        helpers.config_set(smoke_vm, f"{helpers.CFG_GLOBAL}/pfb_dns_listen_vip", "on")
        yield
    finally:
        _put(smoke_vm, "dhcpd", dhcpd)
        _put(smoke_vm, "virtualip/vip", vips)
        for key, state in scalars.items():
            helpers.config_restore_state(smoke_vm, f"{helpers.CFG_GLOBAL}/{key}", state)


def _warnings(smoke_vm: SmokeVM, webui: WebUI) -> list[dict[str, str]]:
    """Render DNS General under the Tier-A oracle and return the foreign-list warnings it prints."""
    guard = PhpErrorLogGuard(smoke_vm)
    guard.snapshot()
    response = webui.get(DNS_GENERAL_PAGE)
    rendered = evaluate_render(
        DNS_GENERAL_PAGE, response.status_code, response.text, ("DNS Reply Logging", "Resolver addresses")
    )
    assert rendered.ok, f"DNS General GET: {rendered.detail}"
    guard.assert_no_growth()
    return [match.groupdict() for match in WARNING.finditer(response.text)]


def test_dns_general_warns_of_a_dhcp_list_that_names_a_server_of_the_administrators_own(
    smoke_vm: SmokeVM, webui: WebUI, resolver_addresses_on: None
) -> None:
    """The warning names the interface, the list type, the foreign server and the VIP to add by hand.

    Given: Resolver addresses on with a VIP, and a DHCPv4 scope whose DNS-server list is empty
    When:  the scope's list comes to name a server that is not the interface's own address
    Then:  DNS General warns of that scope, and only then
    """
    before = _warnings(smoke_vm, webui)
    assert before == [], f"before-state (an empty list is not foreign): expected no warning, got {before}"

    _put(smoke_vm, "dhcpd", {SCOPE_INTERFACE: {"dnsserver": [FOREIGN_SERVER]}})

    after = _warnings(smoke_vm, webui)
    assert len(after) == 1, f"expected one warning for the {SCOPE_INTERFACE} scope, got {after}"
    warning = after[0]
    assert warning["type"] == "DHCPv4", warning
    assert warning["interface"] == SCOPE_INTERFACE or warning["interface"].endswith(f"({SCOPE_INTERFACE})"), warning
    assert warning["servers"] == FOREIGN_SERVER, warning
    assert warning["vip"] == VIP_ADDRESS, warning
