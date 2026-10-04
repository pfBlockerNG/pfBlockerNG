"""Tier-A ``ui_render`` coverage for issue #3441's DNSBL IP HA warning and help."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .render_oracle import PhpErrorLogGuard, evaluate_render

if TYPE_CHECKING:
    from collections.abc import Iterator

    from ..conftest import SmokeVM
    from .webui import WebUI

pytestmark = pytest.mark.ui_render

SYNC_PAGE = "/pfblockerng/pfblockerng_sync.php"
DNSBL_PAGE = "/pfblockerng/pfblockerng_dnsbl.php"
WARNING_MARKER = "DNSBL IP rules may be skipped on the High Availability peer"

CONFIG = {
    "installedpackages/pfblockerngsync/config/0/syncinterfaces": "on",
    "installedpackages/pfblockerngsync/config/0/varsynconchanges": "auto",
    "installedpackages/pfblockerng/config/0/enable_cb": "on",
    "installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl": "on",
    "installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsvip_auto": "",
    "installedpackages/pfblockerngdnsblsettings/config/0/dnsbl_interface": "lo0",
    "installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsvip4": "_vip_test_missing",
    "installedpackages/pfblockerngdnsblsettings/config/0/action": "Deny_Both",
    "hasync/synchronizerules": "on",
}


@pytest.fixture
def dnsblip_mismatch_config(smoke_vm: SmokeVM) -> Iterator[None]:
    """Seed the stored warning conditions with an invalid manual VIP, then restore them."""
    saved = {path: helpers.config_get_state(smoke_vm, path) for path in CONFIG}
    for path, value in CONFIG.items():
        helpers.config_set(smoke_vm, path, value)

    yield

    for path, state in saved.items():
        helpers.config_restore_state(smoke_vm, path, state)
        restored = helpers.config_get_state(smoke_vm, path)
        assert restored == state, f"restore failed for {path}: expected {state!r}, found {restored!r}"


def _render(smoke_vm: SmokeVM, webui: WebUI, path: str, marker: str) -> str:
    guard = PhpErrorLogGuard(smoke_vm)
    guard.snapshot()
    resp = webui.get(path)
    result = evaluate_render(path, resp.status_code, resp.text, (marker,))
    assert result.ok, f"Tier-A render oracle failed for {path}: {result.detail}"
    guard.assert_no_growth()
    return resp.text


def test_sync_page_warns_until_hasync_rule_sync_is_cleared(
    smoke_vm: SmokeVM, webui: WebUI, dnsblip_mismatch_config: None
) -> None:
    """Given every stored condition, a runtime VIP failure must not hide the HA warning."""
    html = _render(smoke_vm, webui, SYNC_PAGE, "XMLRPC Sync Settings")
    assert WARNING_MARKER in html, f"before: expected {WARNING_MARKER!r}, found no marker"
    warning = re.search(
        rf'<div[^>]+class="[^"]*\balert-warning\b[^"]*"[^>]*>.*?{re.escape(WARNING_MARKER)}.*?</div>',
        html,
        re.DOTALL,
    )
    assert warning is not None, (
        f"before: expected {WARNING_MARKER!r} inside an alert-warning element; marker_present={WARNING_MARKER in html}"
    )

    helpers.config_restore_state(smoke_vm, "hasync/synchronizerules", (False, ""))
    html = _render(smoke_vm, webui, SYNC_PAGE, "XMLRPC Sync Settings")
    assert WARNING_MARKER not in html, f"after: expected no {WARNING_MARKER!r}, found the marker"


def test_help_texts_state_the_matching_dnsbl_ip_requirement(smoke_vm: SmokeVM, webui: WebUI) -> None:
    """Given either relevant page, its help states that both HA nodes need matching DNSBL IP settings."""
    sync_html = _render(smoke_vm, webui, SYNC_PAGE, "XMLRPC Sync Settings")
    sync_requirement = "enable DNSBL with the same DNSBL IP settings on both nodes"
    assert sync_requirement in sync_html, f"expected Sync help {sync_requirement!r}, found no matching text"

    dnsbl_html = _render(smoke_vm, webui, DNSBL_PAGE, "DNSBL Webserver Configuration")
    dnsbl_requirement = "configure DNSBL IP identically on both nodes"
    assert dnsbl_requirement in dnsbl_html, f"expected DNSBL help {dnsbl_requirement!r}, found no matching text"
