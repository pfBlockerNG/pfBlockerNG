"""Tier-A GET proof that shared DNS controls live on General, separate from transports."""

from __future__ import annotations

from html.parser import HTMLParser
from typing import TYPE_CHECKING

import pytest

from .render_oracle import PhpErrorLogGuard, evaluate_render

if TYPE_CHECKING:
    from ..conftest import SmokeVM
    from .webui import WebUI

pytestmark = pytest.mark.ui_render

DNS_PAGE = "/pfblockerng/pfblockerng_dns.php"
DNS_GENERAL_PAGE = "/pfblockerng/pfblockerng_dns_general.php"


class _Checkboxes(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.names: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "input" and values.get("type") == "checkbox":
            self.names.append(values.get("name") or "")


def test_dns_general_owns_reply_logging_and_proxy_keeps_transport_order(smoke_vm: SmokeVM, webui: WebUI) -> None:
    """General owns shared controls; pfB-DNS keeps only transports and DDR."""
    guard = PhpErrorLogGuard(smoke_vm)
    guard.snapshot()
    general = webui.get(DNS_GENERAL_PAGE)
    rendered = evaluate_render(
        DNS_GENERAL_PAGE, general.status_code, general.text, ("DNS Reply Logging", "Resolver addresses")
    )
    assert rendered.ok, f"DNS General GET: {rendered.detail}"
    shared = _Checkboxes()
    shared.feed(general.text)
    shared.close()
    assert shared.names == ["pfb_py_reply", "pfb_dns_listen_vip"], shared.names
    response = webui.get(DNS_PAGE)
    rendered = evaluate_render(DNS_PAGE, response.status_code, response.text, ("pfB-DNS Settings",))
    assert rendered.ok, f"pfB-DNS GET: {rendered.detail}"
    guard.assert_no_growth()
    controls = _Checkboxes()
    controls.feed(response.text)
    controls.close()
    wanted = [
        "pfb_dns",
        "pfb_dns_dot",
        "pfb_dns_doh",
        "pfb_dns_doq",
        "pfb_dns_ddr",
        "pfb_dns_ddr_doh_443",
        "pfb_dns_ddr_doh_443_6",
    ]
    assert controls.names == wanted, f"expected settings checkboxes {wanted}, got {controls.names}"
