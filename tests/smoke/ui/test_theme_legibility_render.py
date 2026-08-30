"""Tier-A render markers for dark-theme legibility (www colour pairing).

These pages 500'd during the GUI campaign with only php -l green. ui_render
is the tier that sees a loaded page.
"""

from __future__ import annotations

from html.parser import HTMLParser
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from ..conftest import SmokeVM
from .render_oracle import body_has_php_error
from .webui import extract_csrf_token, looks_like_login_page

if TYPE_CHECKING:
    from .webui import WebUI

pytestmark = [pytest.mark.ui_render, pytest.mark.ui_e2e]

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


CATEGORY_EDIT = "/pfblockerng/pfblockerng_category_edit.php"
_PAIRED_STYLE = "background-color: #FFFF00; color: black;"
_UNPAIRED_STYLE = "background-color: #FFFF00;"
_CFG_DNSBL = "installedpackages/pfblockerngdnsbl/config"
_FAIL_DIR = "/var/db/pfblockerng/dnsbl"
_HEADER = "smokefailedrow"
_SAVE_TIMEOUT = 120.0


def test_category_edit_failed_row_pairs_foreground_with_background(
    webui: WebUI,
    smoke_vm: SmokeVM,
) -> None:
    """A rendered failed-download row ships background AND pinned foreground.

    The pairing is conditional markup: the yellow row only renders when a
    source row's header owns a ``.fail`` file. Seed exactly that state through
    the package's own save handler, assert the rendered body carries the
    PAIRED style (never the bare background), and restore in ``finally``.
    Dual-marked ``ui_e2e``: the seed writes config, so the isolation probe
    rides along.
    """
    vm = smoke_vm
    rowid = _free_rowid(vm, _CFG_DNSBL)
    try:
        _post_form(webui, _dnsbl_payload(rowid, "smokefailedrow", _HEADER))
        touch = vm.ssh(f"touch '{_FAIL_DIR}/{_HEADER}.fail'")
        assert touch.returncode == 0, f"seeding .fail failed: {touch.stderr!r}"

        resp = webui.get(CATEGORY_EDIT, params={"type": "dnsbl", "rowid": str(rowid)})
        assert resp.status_code == 200, CATEGORY_EDIT
        body = resp.text
        assert not body_has_php_error(body), "category_edit.php rendered a PHP error"
        assert _PAIRED_STYLE in body, "failed row rendered without the pinned foreground"
        offenders = _unpaired_yellow_style_attrs(body)
        assert offenders == [], (
            f"an element sets an opaque yellow background without a foreground on the SAME style attribute: {offenders}"
        )
    finally:
        _del_rowid(vm, _CFG_DNSBL, rowid)
        vm.ssh(f"rm -f '{_FAIL_DIR}/{_HEADER}.fail'")


class _StyleAttrCollector(HTMLParser):
    """Collect every inline ``style`` attribute with its tag + id."""

    def __init__(self) -> None:
        super().__init__()
        self.styles: list[tuple[str, str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = {k: v or "" for k, v in attrs}
        style = attr_map.get("style", "")
        if style:
            self.styles.append((tag, attr_map.get("id", ""), style))


def _unpaired_yellow_style_attrs(body: str) -> list[tuple[str, str, str]]:
    """Every element whose inline style declares an OPAQUE ``#FFFF00`` background
    WITHOUT a ``color`` declaration on the SAME style attribute.

    Declaration-order-independent and element-scoped: a correctly paired
    neighbour span (``color: black; background-color: #FFFF00;``) is never
    flagged, and a bare background next to a paired element still fails.
    """
    collector = _StyleAttrCollector()
    collector.feed(body)
    offenders: list[tuple[str, str, str]] = []
    for tag, elem_id, style in collector.styles:
        decls: dict[str, str] = {}
        for part in style.split(";"):
            if ":" in part:
                key, value = part.split(":", 1)
                decls[key.strip().lower()] = value.strip().lower()
        if decls.get("background-color") == "#ffff00" and "color" not in decls:
            offenders.append((tag, elem_id, style))
    return offenders


def _free_rowid(vm: SmokeVM, cfg_root: str) -> int:
    """Return max(numeric keys under cfg_root) + 1 -- a fresh slot this test owns."""
    pre = (
        f"$c = config_get_path({helpers._php_str(cfg_root)}, array());\n"
        "$max = -1;\n"
        "foreach (array_keys($c) as $k) { if (is_numeric($k) && (int)$k > $max) { $max = (int)$k; } }\n"
        "$free = $max + 1;\n"
    )
    return int(helpers._php_read_scalar(vm, pre, "$free", timeout=_SAVE_TIMEOUT))


def _del_rowid(vm: SmokeVM, cfg_root: str, rowid: int) -> None:
    """Delete ``{cfg_root}/{rowid}`` (cleanup of an alias slot this test created)."""
    snippet = (
        f"config_del_path({helpers._php_str(f'{cfg_root}/{rowid}')});\n"
        "write_config('pfBlockerNG smoke: drop test alias');\n"
        "echo 'OK';"
    )
    result = helpers.php_eval(vm, snippet, timeout=_SAVE_TIMEOUT)
    assert result.returncode == 0 and "OK" in result.stdout, "failed to drop the test alias slot"


def _post_form(webui: WebUI, payload: dict[str, str]) -> None:
    """POST a fully-enumerated category-edit payload with a fresh CSRF token."""
    get = webui.get(CATEGORY_EDIT, params={"type": "dnsbl"})
    assert not looks_like_login_page(get.text), "category GET returned the login form (session lost)"
    data = dict(payload)
    data["__csrf_magic"] = extract_csrf_token(get.text)
    data["save"] = "save"
    resp = webui.session.post(webui.url(CATEGORY_EDIT), data=data, verify=webui._verify, timeout=_SAVE_TIMEOUT)
    assert not looks_like_login_page(resp.text), "category POST returned the login form (session lost)"


def _dnsbl_payload(rowid: int, aliasname: str, header: str) -> dict[str, str]:
    """A valid DNSBL alias payload: action=unbound, one Enabled source row."""
    return {
        "type": "dnsbl",
        "rowid": str(rowid),
        "aliasname": aliasname,
        "description": "smoke #2866 failed row (render)",
        "action": "unbound",
        "cron": "Never",
        "schedule_override": "",
        "schedule_weekday": "7",
        "schedule_hour": "0",
        "schedule_minute": "0",
        "sort": "sort",
        "order": "default",
        "logging": "enabled",
        "filter_top1m": "",
        "srcint": "",
        "script_pre": "",
        "script_post": "",
        "custom": "",
        "format-0": "auto",
        "state-0": "Enabled",
        "url-0": f"http://127.0.0.1/{aliasname}.txt",
        "header-0": header,
    }
