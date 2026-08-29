"""Tier-A render markers for dark-theme legibility (www colour pairing).

These pages 500'd during the GUI campaign with only php -l green. ui_render
is the tier that sees a loaded page.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from .webui import WebUI

pytestmark = pytest.mark.ui_render

# Path -> a marker the page emits only when it actually rendered.
_LIST_PAGES: dict[str, str] = {
    "/pfblockerng/pfblockerng_dnsbl.php": "DNSBL Webserver Configuration",
    "/pfblockerng/pfblockerng_ip.php": "IP Configuration",
    "/pfblockerng/pfblockerng_log.php": "Log/File Browser selections",
    "/pfblockerng/pfblockerng_edit_hooks.php": "Load an Existing Hook Script",
    "/pfblockerng/pfblockerng_category_edit.php?type=ipv4": "Update Frequency",
}


def test_update_log_viewer_pins_a_light_pane_with_foreground(webui: WebUI) -> None:
    resp = webui.get("/pfblockerng/pfblockerng_update.php")
    assert resp.status_code == 200
    assert "background-color: #fafafa" in resp.text
    assert "color: #212121" in resp.text


def test_support_logo_uses_a_cropped_circle_viewbox(webui: WebUI) -> None:
    resp = webui.get("/pfblockerng/pfblockerng_general.php")
    assert resp.status_code == 200
    assert 'viewBox="128 172 384 384"' in resp.text
    assert 'class="col-sm-9"' in resp.text
    assert 'class="col-sm-3"' in resp.text


def test_list_textareas_do_not_force_unpaired_fafafa(webui: WebUI) -> None:
    for path, marker in _LIST_PAGES.items():
        resp = webui.get(path)
        assert resp.status_code == 200, path
        assert marker in resp.text, path
        assert "background:#fafafa" not in resp.text, path


def test_alerts_page_ships_both_unified_palette_groups(webui: WebUI) -> None:
    """Theme-resolution refactor: both palettes render; ungated rows always present.

    ``pfb_webgui_dark`` chooses which palette paints log rows, but a fresh VM
    has an empty log. The settings form is the reachable surface: light and
    dark groups both ship, and the ungated ``uniblock`` / ``uniblock2``
    placeholders are the ``uni_defaults`` hexes.

    Dark defaults are measured against ``#e0e0e0`` because Alerts tables use
    ``sortable-theme-bootstrap`` (pfSense-dark.css pins that class's colour).
    Ungated events (block/permit/match) always render; dnsbl is gated.
    """
    path = "/pfblockerng/pfblockerng_alerts.php"
    resp = webui.get(path)
    assert resp.status_code == 200, path
    assert "Alert Settings" in resp.text
    assert "Unified Log: Light Background Theme" in resp.text
    assert "Unified Log: Dark Background Theme" in resp.text
    assert 'name="uniblock"' in resp.text
    assert 'name="uniblock2"' in resp.text
    assert "sortable-theme-bootstrap" in resp.text
    assert "#FFF9C4" in resp.text
    assert "#665E17" in resp.text
    assert "#2D6560" in resp.text
    assert "#336279" in resp.text
