"""Tier B: pfB-DNS is the parent switch of DNSBL, as the pfBlockerNG enable is of everything (issue #3770).

DNSBL stored On with pfB-DNS Off is handled like DNSBL On with pfBlockerNG Off: neither enable save is refused, and
DNSBL does not run, which the pfB-DNS status panel and the dashboard widget show. The help texts say so. The pfB-DNS
enable also syncs with the DNSBL enable, so the pfB-DNS and Sync help text list it under Sync Scope, not as a
node-local setting.
"""

from __future__ import annotations

import contextlib
import html
import re
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .render_oracle import NO_INPUT_ERRORS, input_errors_block
from .test_render_smoke import _resolver_address_keys_restored
from .test_render_widget_ledger import ICON_RED, WIDGET_PAGE

if TYPE_CHECKING:
    from collections.abc import Iterator

    from .webui import WebUI

pytestmark = pytest.mark.ui_e2e

DNS_PAGE = "/pfblockerng/pfblockerng_dns_general.php"  # holds the pfB-DNS settings since issue #3771
DNSBL_PAGE = "/pfblockerng/pfblockerng_dnsbl.php"
SYNC_PAGE = "/pfblockerng/pfblockerng_sync.php"
PACKAGE_ENABLE = "installedpackages/pfblockerng/config/0/enable_cb"
DNSBL_ENABLE = "installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl"
PFB_DNS_ENABLE = helpers.dns_config_path("pfb_dns")
SAVE_TIMEOUT = 300.0
# The pfB-DNS siblings a page Save validates first: valid, so no validation error hides the save's effect on the enable
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


def _plain_text(body: str) -> str:
    """The page as one line of plain text: tags stripped, entities decoded, whitespace collapsed."""
    return " ".join(html.unescape(re.sub(r"<[^>]+>", "", body)).split())


def _errors_text(body: str) -> str:
    """The page's input-errors box as one line of plain text (entities decoded), or NO_INPUT_ERRORS."""
    block = input_errors_block(body)
    return _plain_text(block) if block else NO_INPUT_ERRORS


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


def test_dnsbl_page_saves_dnsbl_on_while_pfb_dns_is_off(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """Given pfB-DNS and DNSBL stored Off, When DNSBL On is posted, Then DNSBL is stored On, pfB-DNS stays Off."""
    vm = smoke_vm
    with _seeded(vm, {DNSBL_ENABLE: "", PFB_DNS_ENABLE: ""}):
        saved = webui.post(DNSBL_PAGE, {"pfb_dnsbl": "on"}, timeout=SAVE_TIMEOUT)

        assert _errors_text(saved.text) == NO_INPUT_ERRORS, (
            f"DNSBL On with pfB-DNS Off must save; input errors: {_errors_text(saved.text)}"
        )
        assert (helpers.config_get(vm, DNSBL_ENABLE), helpers.config_get(vm, PFB_DNS_ENABLE)) == ("on", ""), (
            "the DNSBL save must store DNSBL On and leave pfB-DNS Off"
        )


def test_pfb_dns_page_saves_pfb_dns_off_while_dnsbl_is_on(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """Given DNSBL and pfB-DNS stored On, When pfB-DNS Off is posted, Then pfB-DNS is stored Off, DNSBL stays On."""
    vm = smoke_vm
    siblings = {helpers.dns_config_path(key): value for key, value in PFB_DNS_SIBLINGS.items()}
    with _resolver_address_keys_restored(vm), _seeded(vm, {DNSBL_ENABLE: "on", PFB_DNS_ENABLE: "on"} | siblings):
        saved = webui.post(DNS_PAGE, {"pfb_dns": ""}, timeout=SAVE_TIMEOUT)

        assert _errors_text(saved.text) == NO_INPUT_ERRORS, (
            f"pfB-DNS Off with DNSBL On must save; input errors: {_errors_text(saved.text)}"
        )
        assert (helpers.config_get(vm, DNSBL_ENABLE), helpers.config_get(vm, PFB_DNS_ENABLE)) == ("on", ""), (
            "the pfB-DNS save must store pfB-DNS Off and leave DNSBL On"
        )


def test_dnsbl_shows_disabled_while_pfb_dns_is_off(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """Given the package and DNSBL On and pfB-DNS Off, When DNS General and the widget render, Then DNSBL reads off."""
    vm = smoke_vm
    with _seeded(vm, {PACKAGE_ENABLE: "on", DNSBL_ENABLE: "on", PFB_DNS_ENABLE: ""}):
        panel = webui.get(DNS_PAGE).text
        assert re.search(r'id="pfb-dns-status-dnsbl"><th>DNSBL</th><td><i [^>]*title="Off"', panel), (
            "the pfB-DNS status panel must show the DNSBL row Off while pfB-DNS is off, as with pfBlockerNG off"
        )

        widget = webui.get(WIDGET_PAGE).text
        assert re.search(rf'title="DNSBL is Disabled[^"]*"><i class="DNSBLSTATUS {re.escape(ICON_RED)}">', widget), (
            "the dashboard widget must show the DNSBL row red and Disabled while pfB-DNS is off"
        )


def test_dnsbl_page_note_says_dnsbl_runs_in_pfb_dns(webui: WebUI) -> None:
    """When the DNSBL page renders, Then its note says DNSBL runs in pfB-DNS in front of the Resolver."""
    body = webui.get(DNSBL_PAGE).text

    assert (
        "DNSBL runs in pfB-DNS, in front of the DNS Resolver (Unbound), so both must be used as the DNS service."
        in body
    ), "the DNSBL note must say DNSBL runs in pfB-DNS in front of the Resolver"
    assert "DNSBL requires the DNS Resolver (Unbound) to be used as the DNS service." not in body, (
        "the old note, which names the Resolver alone, is still rendered"
    )


def test_dnsbl_enable_help_says_dnsbl_runs_only_while_pfb_dns_is_on(webui: WebUI) -> None:
    """When the DNSBL page renders, Then the enable help says DNSBL needs pfB-DNS and pfBlockerNG enabled."""
    text = _plain_text(webui.get(DNSBL_PAGE).text)

    assert (
        "Block the domains in your DNSBL groups. Requires pfB-DNS (turned on in DNS > General) "
        "and pfBlockerNG enabled on the General tab."
    ) in text, "the DNSBL enable help must say DNSBL requires pfB-DNS and pfBlockerNG"


def test_pfb_dns_help_says_dnsbl_stops_with_it_and_that_a_later_conflict_keeps_it_running(webui: WebUI) -> None:
    """When DNS General renders, Then its pfB-DNS enable help states the parent switch and a later conflict's effect."""
    text = _plain_text(webui.get(DNS_PAGE).text)

    assert "DNSBL runs only through pfB-DNS: turning pfB-DNS off stops DNSBL; the DNSBL setting is kept." in text, (
        "the pfB-DNS enable help must say that turning it off stops DNSBL and keeps the DNSBL setting"
    )
    assert (
        "Adding such a conflict later keeps pfB-DNS running, with the Resolver still moved, and raises a notice."
    ) in text, "the help must say a conflict added later keeps pfB-DNS running and raises a notice"
    assert "Turning the option off is never refused." in text, "turning pfB-DNS off is never refused"
    assert (
        "Disabling the DNS Resolver leaves pfB-DNS running without a backend: DNS queries fail and a notice says so "
        "until the Resolver is enabled or pfB-DNS is turned off."
    ) in text, "the help must say disabling the Resolver leaves pfB-DNS running without a backend"
    for retired in (
        "Adding such a conflict later turns pfB-DNS off",
        "Adding such a conflict later restores the Resolver",
        "its status shows the activation failed",
        "Disabling the DNS Resolver stops pfB-DNS, restores the saved fields and turns this option off",
        "Disabling the DNS Resolver stops pfB-DNS and restores the saved fields",
        "DNSBL requires pfB-DNS, so turn DNSBL off first",
        "turning pfB-DNS off turns DNSBL off too",
    ):
        assert retired not in text, f"the help still carries the retired sentence: {retired}"


def _list_items(body: str) -> list[str]:
    """Every list item of the page as one line of plain text (tags stripped, entities decoded)."""
    items = re.findall(r"<li>(.*?)</li>", body, re.S)
    return [_plain_text(item) for item in items]


def test_help_lists_the_pfb_dns_enable_under_sync_scope_not_as_node_local(webui: WebUI) -> None:
    """Given DNS General and Sync pages, When help renders, Then the enable follows Sync Scope, not the local list."""
    dns_items = _list_items(webui.get(DNS_PAGE).text)
    sync_items = _list_items(webui.get(SYNC_PAGE).text)

    followers = [item for item in dns_items if "enable switch" in item]
    assert followers and all("follow Sync Scope" in item for item in followers), (
        f"DNS General must list the pfB-DNS enable switch among the settings that follow Sync Scope; items: {followers}"
    )
    local = [item for item in dns_items if item.startswith("Saved Resolver settings")]
    assert local and all("enable switch" not in item for item in local), (
        f"DNS General's node-local list must not name the pfB-DNS enable switch; items: {local}"
    )

    assert any(item.startswith("Policy and lists") and "pfB-DNS enable switch" in item for item in sync_items), (
        "the Sync page must list the pfB-DNS enable switch under the Policy and lists scope"
    )
    always_local = [item for item in sync_items if item.startswith("Saved Resolver settings")]
    assert always_local and all("enable switch" not in item for item in always_local), (
        f"the Sync page's every-scope local list must not name the enable switch; items: {always_local}"
    )
