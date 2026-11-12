"""Tier-A GET proof that DNS General is one form with one Save button, the sections in a fixed order (issue #3856).

The pfB-DNS settings and the DNS General settings (reply logging, Resolver addresses) save together on ``save``,
"Save DNS settings". The pfSense chrome around the page may carry other forms, so the form is found by its submit
button, never by position among every ``<form>`` on the page.
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
SAVE = "save"
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


def test_dns_general_is_one_form_with_one_save_button_holding_every_section_in_order(
    smoke_vm: SmokeVM, webui: WebUI
) -> None:
    """DNS General renders the pfB-DNS sections, then reply logging and Resolver addresses, all in the one form.

    The form's only submit button is ``save``, so a browser always posts every field of the page.
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
    forms = [form for form in parser.forms if SAVE in form.submits]
    assert len(forms) == 1, f"expected one form saving with {SAVE!r}, got {len(forms)}"
    form = forms[0]
    assert form.submits == [SAVE], f"the form's submit buttons are {form.submits}, expected {[SAVE]}"
    checkboxes = [*PFB_DNS_CHECKBOXES, *GENERAL_CHECKBOXES]
    assert form.checkboxes == checkboxes, f"expected form checkboxes {checkboxes}, got {form.checkboxes}"
    sections = [*PFB_DNS_SECTIONS, *GENERAL_SECTIONS]
    assert form.sections == sections, f"expected form sections {sections}, got {form.sections}"
