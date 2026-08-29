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

_LIST_PAGES = (
    "/pfblockerng/pfblockerng_dnsbl.php",
    "/pfblockerng/pfblockerng_ip.php",
    "/pfblockerng/pfblockerng_log.php",
    "/pfblockerng/pfblockerng_edit_hooks.php",
    "/pfblockerng/pfblockerng_category_edit.php?type=ipv4",
)


def test_update_log_viewer_pins_a_light_pane_with_foreground(webui: WebUI) -> None:
    body = webui.get("/pfblockerng/pfblockerng_update.php").text
    assert "background-color: #fafafa" in body
    assert "color: #212121" in body


def test_support_logo_uses_a_cropped_circle_viewbox(webui: WebUI) -> None:
    body = webui.get("/pfblockerng/pfblockerng_general.php").text
    assert 'viewBox="128 172 384 384"' in body
    assert 'class="col-sm-9"' in body
    assert 'class="col-sm-3"' in body


def test_list_textareas_do_not_force_unpaired_fafafa(webui: WebUI) -> None:
    for path in _LIST_PAGES:
        body = webui.get(path).text
        assert "background:#fafafa" not in body, path
