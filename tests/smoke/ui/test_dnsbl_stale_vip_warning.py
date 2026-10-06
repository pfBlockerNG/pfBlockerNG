"""Tier-A ``ui_render`` coverage for issue #3456's stale DNSBL VIP warning."""

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

DNSBL_PAGE = "/pfblockerng/pfblockerng_dnsbl.php"
PAGE_MARKER = "DNSBL Webserver Configuration"
WARNING_MARKER = "The saved DNSBL Virtual IP no longer exists"
STALE_VIP = "_vip_gone_smoke"
CFG = "installedpackages/pfblockerngdnsblsettings/config/0"


@pytest.fixture
def stale_vip_config(smoke_vm: SmokeVM) -> Iterator[None]:
    """Seed a manual-mode DNSBL config pointing at a VIP id that does not exist, then restore it."""
    config = {f"{CFG}/pfb_dnsvip4": STALE_VIP, f"{CFG}/pfb_dnsvip6": "", f"{CFG}/pfb_dnsvip_auto": ""}
    saved = {path: helpers.config_get_state(smoke_vm, path) for path in config}
    for path, value in config.items():
        helpers.config_set(smoke_vm, path, value)

    yield

    for path, state in saved.items():
        helpers.config_restore_state(smoke_vm, path, state)
        restored = helpers.config_get_state(smoke_vm, path)
        assert restored == state, f"restore failed for {path}: expected {state!r}, found {restored!r}"


def _render(smoke_vm: SmokeVM, webui: WebUI) -> str:
    guard = PhpErrorLogGuard(smoke_vm)
    guard.snapshot()
    resp = webui.get(DNSBL_PAGE)
    result = evaluate_render(DNSBL_PAGE, resp.status_code, resp.text, (PAGE_MARKER,))
    assert result.ok, f"Tier-A render oracle failed for {DNSBL_PAGE}: {result.detail}"
    guard.assert_no_growth()
    return resp.text


def test_dnsbl_page_warns_only_for_a_deleted_vip_in_manual_mode(
    smoke_vm: SmokeVM, webui: WebUI, stale_vip_config: None
) -> None:
    """Manual mode warns naming a deleted VIP; auto mode and a cleared VIP do not."""
    html = _render(smoke_vm, webui)
    # Tempered: the box may not run into another alert div (the pfSense info box nests alert-icon divs, so
    # match only a standalone ``alert`` class token).
    other_alert = r'<div[^>]+class="(?:[^"]*\s)?alert[\s"]'
    warning = re.search(
        rf'<div[^>]+class="[^"]*\balert-warning\b[^"]*"[^>]*>(?:(?!{other_alert}).)*?{re.escape(WARNING_MARKER)}'
        rf"(?:(?!{other_alert}).)*?</div>",
        html,
        re.DOTALL,
    )
    assert warning is not None, (
        f"manual: expected {WARNING_MARKER!r} inside an alert-warning element; marker_present={WARNING_MARKER in html}"
    )
    assert STALE_VIP in warning.group(0), f"manual: expected {STALE_VIP!r} in the warning; found {warning.group(0)!r}"

    helpers.config_set(smoke_vm, f"{CFG}/pfb_dnsvip_auto", "on")
    html = _render(smoke_vm, webui)
    assert WARNING_MARKER not in html, f"auto: expected no {WARNING_MARKER!r}, found the marker"

    helpers.config_set(smoke_vm, f"{CFG}/pfb_dnsvip_auto", "")
    helpers.config_set(smoke_vm, f"{CFG}/pfb_dnsvip4", "")
    helpers.config_set(smoke_vm, f"{CFG}/pfb_dnsvip6", "")
    html = _render(smoke_vm, webui)
    assert WARNING_MARKER not in html, f"no VIP: expected no {WARNING_MARKER!r}, found the marker"
