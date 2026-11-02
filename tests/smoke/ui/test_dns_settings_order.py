"""Tier-A real GET proof that DNS Reply Logging precedes the experimental proxy settings."""

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


class _Checkboxes(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.names: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "input" and values.get("type") == "checkbox":
            self.names.append(values.get("name") or "")


def test_dns_reply_logging_renders_before_proxy_settings(smoke_vm: SmokeVM, webui: WebUI) -> None:
    """The first settings checkbox is reply logging, followed by the unchanged proxy transport order."""
    guard = PhpErrorLogGuard(smoke_vm)
    guard.snapshot()
    response = webui.get(DNS_PAGE)
    rendered = evaluate_render(DNS_PAGE, response.status_code, response.text, ("DNS Reply Logging", "pfB-DNS Settings"))
    assert rendered.ok, f"DNS settings GET: {rendered.detail}"
    guard.assert_no_growth()
    controls = _Checkboxes()
    controls.feed(response.text)
    controls.close()
    wanted = [
        "pfb_py_reply",
        "pfb_dns",
        "pfb_dns_dot",
        "pfb_dns_doh",
        "pfb_dns_doq",
        "pfb_dns_ddr",
        "pfb_dns_ddr_doh_443",
    ]
    assert controls.names == wanted, f"expected settings checkboxes {wanted}, got {controls.names}"
