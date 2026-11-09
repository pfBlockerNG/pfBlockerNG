"""Tier-A GET proof that DNS General holds two forms: the pfB-DNS settings first, its own settings second (issue #3771).

Each form saves on its own button, so a browser posts only the clicked form: ``save_pfb_dns`` for pfB-DNS and ``save``
for DNS General. The pfSense chrome around the page may carry other forms, so the two are found by their submit button,
never by position among every ``<form>`` on the page.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import TYPE_CHECKING

import pytest

from .render_oracle import PhpErrorLogGuard, evaluate_render

if TYPE_CHECKING:
    from ..conftest import SmokeVM
    from .webui import WebUI

pytestmark = pytest.mark.ui_render

DNS_GENERAL_PAGE = "/pfblockerng/pfblockerng_dns_general.php"
SAVE_PFB_DNS = "save_pfb_dns"
SAVE_GENERAL = "save"
PFB_DNS_SECTIONS = [
    "pfB-DNS Settings",
    "DNS over TLS (DoT)",
    "DNS over HTTPS (DoH)",
    "DNS over QUIC (DoQ)",
    "Discovery of Designated Resolvers (DDR)",
]
GENERAL_SECTIONS = ["DNS Reply Logging", "Resolver addresses"]
PFB_DNS_CHECKBOXES = ["pfb_dns", "pfb_dns_dot", "pfb_dns_doh", "pfb_dns_doq", "pfb_dns_ddr"]
GENERAL_CHECKBOXES = ["pfb_py_reply", "pfb_dns_listen_vip", "pfb_dns_listen_vip_only"]


@dataclass
class _Form:
    checkboxes: list[str] = field(default_factory=list)
    submits: list[str] = field(default_factory=list)
    sections: list[str] = field(default_factory=list)


class _Forms(HTMLParser):
    """Every ``<form>`` of the page in document order: its checkboxes, submit buttons and panel (section) titles."""

    def __init__(self) -> None:
        super().__init__()
        self.forms: list[_Form] = []
        self._open: _Form | None = None
        self._title_tag: str | None = None
        self._title: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "form":
            self._open = _Form()
            self.forms.append(self._open)
        elif self._open is None:
            return
        elif "panel-title" in (values.get("class") or "").split():
            self._title_tag, self._title = tag, []
        elif tag == "input" and values.get("type") == "checkbox":
            self._open.checkboxes.append(values.get("name") or "")
        elif tag == "button" and values.get("type", "submit") == "submit" and values.get("name"):
            self._open.submits.append(values["name"] or "")

    def handle_endtag(self, tag: str) -> None:
        if tag == self._title_tag and self._open is not None:
            self._open.sections.append(" ".join("".join(self._title).split()))
            self._title_tag = None
        elif tag == "form":
            self._open = None

    def handle_data(self, data: str) -> None:
        if self._title_tag is not None:
            self._title.append(data)


def test_dns_general_has_two_forms_pfb_dns_first_each_with_its_own_controls_and_save_button(
    smoke_vm: SmokeVM, webui: WebUI
) -> None:
    """DNS General renders the pfB-DNS form (enable, DoT, DoH, DoQ, DDR) before its own form (reply logging, VIPs).

    Each form has its own submit button, and neither carries the other's controls or sections, so a browser posts
    only the form whose button was clicked.
    """
    guard = PhpErrorLogGuard(smoke_vm)
    guard.snapshot()
    response = webui.get(DNS_GENERAL_PAGE)
    rendered = evaluate_render(
        DNS_GENERAL_PAGE, response.status_code, response.text, ("pfB-DNS Settings", "DNS Reply Logging")
    )
    assert rendered.ok, f"DNS General GET: {rendered.detail}"
    guard.assert_no_growth()

    parser = _Forms()
    parser.feed(response.text)
    parser.close()
    pfb_dns = [form for form in parser.forms if SAVE_PFB_DNS in form.submits]
    general = [form for form in parser.forms if SAVE_GENERAL in form.submits]
    assert len(pfb_dns) == 1, f"expected one form saving with {SAVE_PFB_DNS!r}, got {len(pfb_dns)}"
    assert len(general) == 1, f"expected one form saving with {SAVE_GENERAL!r}, got {len(general)}"
    assert pfb_dns[0] is not general[0], f"{SAVE_PFB_DNS!r} and {SAVE_GENERAL!r} share one form, expected two forms"
    assert pfb_dns[0].submits == [SAVE_PFB_DNS], f"the pfB-DNS form's submit buttons are {pfb_dns[0].submits}"
    assert general[0].submits == [SAVE_GENERAL], f"the DNS General form's submit buttons are {general[0].submits}"

    positions = [parser.forms.index(pfb_dns[0]), parser.forms.index(general[0])]
    assert positions == sorted(positions), f"the pfB-DNS form must precede the DNS General form, got {positions}"
    assert pfb_dns[0].checkboxes == PFB_DNS_CHECKBOXES, (
        f"expected pfB-DNS form checkboxes {PFB_DNS_CHECKBOXES}, got {pfb_dns[0].checkboxes}"
    )
    assert general[0].checkboxes == GENERAL_CHECKBOXES, (
        f"expected DNS General form checkboxes {GENERAL_CHECKBOXES}, got {general[0].checkboxes}"
    )
    assert pfb_dns[0].sections == PFB_DNS_SECTIONS, (
        f"expected pfB-DNS form sections {PFB_DNS_SECTIONS}, got {pfb_dns[0].sections}"
    )
    assert general[0].sections == GENERAL_SECTIONS, (
        f"expected DNS General form sections {GENERAL_SECTIONS}, got {general[0].sections}"
    )
