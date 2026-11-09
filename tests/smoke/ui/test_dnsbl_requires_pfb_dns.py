"""Tier B: DNSBL runs only through pfB-DNS, so the two enable saves refuse what would break that (issue #3770).

The DNSBL page refuses DNSBL On while pfB-DNS is Off, and the pfB-DNS page refuses pfB-DNS Off while DNSBL is On. Each
refusal renders the form with an input error and writes nothing: config.xml and the pending/apply markers are untouched.
"""

from __future__ import annotations

import contextlib
import html
import re
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .render_oracle import NO_INPUT_ERRORS, input_errors_block
from .test_dns_readonly_save import _write_state

if TYPE_CHECKING:
    from collections.abc import Iterator

    from .webui import WebUI

pytestmark = pytest.mark.ui_e2e

DNS_PAGE = "/pfblockerng/pfblockerng_dns.php"
DNSBL_PAGE = "/pfblockerng/pfblockerng_dnsbl.php"
DNSBL_ENABLE = "installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl"
PFB_DNS_ENABLE = helpers.dns_config_path("pfb_dns")
SAVE_TIMEOUT = 300.0
# The pfB-DNS siblings a page Save validates first: valid, so only the DNSBL check can refuse it.
PFB_DNS_SIBLINGS = {
    "pfb_dns_name": "",
    "pfb_dns_dot": "",
    "pfb_dns_doh": "",
    "pfb_dns_doq": "",
    "pfb_dns_ddr": "",
    "pfb_dns_sslcertref": "",
    "pfb_dns_doh_trusted": "",
    "pfb_dns_ddr_doh_443_interfaces": "",
    "pfb_dns_interface": "lo0",
    "pfb_dns_dot_interface": "lo0",
    "pfb_dns_doh_interface": "lo0",
    "pfb_dns_doq_interface": "lo0",
    "pfb_dns_dot_port": "853",
    "pfb_dns_doh_port": "443",
    "pfb_dns_doq_port": "853",
    "pfb_dns_dot_port6": "",
    "pfb_dns_doh_port6": "",
    "pfb_dns_doq_port6": "",
}


def _errors_text(body: str) -> str:
    """The page's input-errors box as one line of plain text (entities decoded), or NO_INPUT_ERRORS."""
    block = input_errors_block(body)
    return " ".join(html.unescape(re.sub(r"<[^>]+>", " ", block)).split()) if block else NO_INPUT_ERRORS


@contextlib.contextmanager
def _seeded(vm: helpers.SmokeVM, values: dict[str, str]) -> Iterator[None]:
    """Store ``values`` directly (the before-state must not depend on the save under test); restore them after."""
    originals = {path: helpers.config_get_state(vm, path) for path in values}
    try:
        for path, value in values.items():
            helpers.config_set(vm, path, value)
        assert {path: helpers.config_get(vm, path) for path in values} == values, "the seed did not take"
        yield
    finally:
        for path, state in originals.items():
            helpers.config_restore_state(vm, path, state)


def test_dnsbl_page_refuses_dnsbl_on_while_pfb_dns_is_off(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """Given pfB-DNS and DNSBL stored Off, When DNSBL On is posted, Then the page names pfB-DNS and writes nothing."""
    vm = smoke_vm
    with _seeded(vm, {DNSBL_ENABLE: "", PFB_DNS_ENABLE: ""}):
        before = _write_state(vm)

        refused = webui.post(DNSBL_PAGE, {"pfb_dnsbl": "on"}, timeout=SAVE_TIMEOUT)

        errors = _errors_text(refused.text)
        assert "pfB-DNS" in errors and "DNS > pfB-DNS" in errors, (
            f"DNSBL On with pfB-DNS Off must be refused naming pfB-DNS and where to turn it on; input errors: {errors}"
        )
        assert (helpers.config_get(vm, DNSBL_ENABLE), helpers.config_get(vm, PFB_DNS_ENABLE)) == ("", ""), (
            "a refused save must leave DNSBL and pfB-DNS Off"
        )
        assert _write_state(vm) == before, "a refused save changed config.xml or a pending/apply marker"


def test_pfb_dns_page_refuses_pfb_dns_off_while_dnsbl_is_on(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """Given DNSBL and pfB-DNS stored On, When pfB-DNS Off is posted, Then the page names DNSBL and writes nothing."""
    vm = smoke_vm
    siblings = {helpers.dns_config_path(key): value for key, value in PFB_DNS_SIBLINGS.items()}
    with _seeded(vm, {DNSBL_ENABLE: "on", PFB_DNS_ENABLE: "on"} | siblings):
        before = _write_state(vm)

        refused = webui.post(DNS_PAGE, {"pfb_dns": ""}, timeout=SAVE_TIMEOUT)

        errors = _errors_text(refused.text)
        assert "DNSBL" in errors and "DNS > DNSBL" in errors, (
            f"pfB-DNS Off with DNSBL On must be refused naming DNSBL and where to turn it off; input errors: {errors}"
        )
        assert (helpers.config_get(vm, DNSBL_ENABLE), helpers.config_get(vm, PFB_DNS_ENABLE)) == ("on", "on"), (
            "a refused save must leave DNSBL and pfB-DNS On"
        )
        assert _write_state(vm) == before, "a refused save changed config.xml or a pending/apply marker"
