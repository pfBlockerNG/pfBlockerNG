"""Tier-B browser proof for #2866: the failed-download row under dark + light.

The category-edit page's failed-download row paints an opaque ``#FFFF00``
background. Before the fix it shipped with NO paired foreground: on
``pfSense-dark.css`` the inherited near-white text scored 1.07:1 against the
saturated yellow. This test seeds the real failed state (a DNSBL alias whose
source-row header owns a ``.fail`` file), switches the effective
webConfigurator theme, measures the row's COMPUTED colours in a real browser
under dark AND light, and restores the exact pre-probe theme and config state
in ``finally``.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .webui import extract_csrf_token, looks_like_login_page

if TYPE_CHECKING:
    from pathlib import Path

    from playwright.sync_api import Page

    from .webui import WebUI

pytestmark = pytest.mark.ui_browser

CATEGORY_PAGE = "/pfblockerng/pfblockerng_category_edit.php"
CFG_DNSBL = "installedpackages/pfblockerngdnsbl/config"
FAIL_DIR = "/var/db/pfblockerng/dnsbl"
ALIAS = "smokefailedrow"
HEADER = "smokefailedrow"
SAVE_TIMEOUT = 120.0
JS_TIMEOUT_MS = 10_000

# WCAG AA floor the issue sets: the paired row must clear it on BOTH themes.
AA_FLOOR = 4.5

_DARK = "pfSense-dark.css"
_LIGHT = "pfSense.css"


def _relative_luminance(rgb: tuple[int, int, int]) -> float:
    """WCAG 2.x relative luminance of an sRGB triple."""

    def chan(c: int) -> float:
        v = c / 255.0
        return v / 12.92 if v <= 0.04045 else ((v + 0.055) / 1.055) ** 2.4

    return 0.2126 * chan(rgb[0]) + 0.7152 * chan(rgb[1]) + 0.0722 * chan(rgb[2])


def _contrast(fg: tuple[int, int, int], bg: tuple[int, int, int]) -> float:
    lo, hi = sorted((_relative_luminance(fg), _relative_luminance(bg)))
    return (hi + 0.05) / (lo + 0.05)


def _parse_rgb(value: str) -> tuple[int, int, int]:
    m = re.match(r"rgba?\((\d+),\s*(\d+),\s*(\d+)", value)
    assert m, f"unexpected computed colour {value!r}"
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


def _open(page: Page, webui: WebUI, path: str) -> None:
    """Navigate the cookie-authenticated browser and settle the DOM."""
    page.goto(webui.url(path), wait_until="domcontentloaded", timeout=JS_TIMEOUT_MS * 3)
    page.wait_for_load_state("networkidle", timeout=JS_TIMEOUT_MS * 3)
    assert page.locator("#usernamefld").count() == 0, f"GET {path} showed the login form -- cookie not authenticated"


def _free_rowid(vm: helpers.SmokeVM, cfg_root: str) -> int:
    """Return max(numeric keys under cfg_root) + 1 -- a fresh slot this test owns."""
    pre = (
        f"$c = config_get_path({helpers._php_str(cfg_root)}, array());\n"
        "$max = -1;\n"
        "foreach (array_keys($c) as $k) { if (is_numeric($k) && (int)$k > $max) { $max = (int)$k; } }\n"
        "$free = $max + 1;\n"
    )
    return int(helpers._php_read_scalar(vm, pre, "$free", timeout=SAVE_TIMEOUT))


def _del_rowid(vm: helpers.SmokeVM, cfg_root: str, rowid: int) -> None:
    """Delete ``{cfg_root}/{rowid}`` (cleanup of an alias slot this test created)."""
    snippet = (
        f"config_del_path({helpers._php_str(f'{cfg_root}/{rowid}')});\n"
        "write_config('pfBlockerNG smoke: drop test alias');\n"
        "echo 'OK';"
    )
    result = helpers.php_eval(vm, snippet, timeout=SAVE_TIMEOUT)
    assert result.returncode == 0 and "OK" in result.stdout, "failed to drop the test alias slot"


def _post_form(webui: WebUI, payload: dict[str, str]) -> None:
    """POST a fully-enumerated category-edit payload with a fresh CSRF token."""
    get = webui.get(CATEGORY_PAGE, params={"type": "dnsbl"})
    assert not looks_like_login_page(get.text), "category GET returned the login form (session lost)"
    data = dict(payload)
    data["__csrf_magic"] = extract_csrf_token(get.text)
    data["save"] = "save"
    resp = webui.session.post(webui.url(CATEGORY_PAGE), data=data, verify=webui._verify, timeout=SAVE_TIMEOUT)
    assert not looks_like_login_page(resp.text), "category POST returned the login form (session lost)"


def _set_theme(vm: helpers.SmokeVM, css: str) -> None:
    """Flip the effective webConfigurator theme (system/webgui/webguicss)."""
    snippet = (
        "$w = config_get_path('system/webgui', array());\n"
        f"$w['webguicss'] = {helpers._php_str(css)};\n"
        "config_set_path('system/webgui', $w);\n"
        "write_config('pfBlockerNG smoke: switch webConfigurator theme');\n"
        "echo 'OK';"
    )
    result = helpers.php_eval(vm, snippet, timeout=SAVE_TIMEOUT)
    assert result.returncode == 0 and "OK" in result.stdout, f"theme switch to {css} failed"


def _active_css(vm: helpers.SmokeVM) -> str:
    """The currently-configured theme (pfSense's default when the key is absent)."""
    present, value = helpers.config_get_state(vm, "system/webgui/webguicss")
    return value if present else _LIGHT


def _head_stylesheets(page: "Page") -> str:
    return page.evaluate(
        "Array.from(document.querySelectorAll('link[rel=stylesheet]')).map(l => l.getAttribute('href')).join(' ')"
    )


def _measure_failed_row(page: Page) -> tuple[tuple[int, int, int], tuple[int, int, int]]:
    """Computed (color, background-color) of the failed-download row input."""
    row = page.locator("input[id^='header-'][style*='#FFFF00']")
    assert row.count() == 1, f"expected exactly one failed-download row, found {row.count()}"
    fg = row.evaluate("el => getComputedStyle(el).color")
    bg = row.evaluate("el => getComputedStyle(el).backgroundColor")
    return _parse_rgb(fg), _parse_rgb(bg)


def test_failed_download_row_is_readable_on_dark_and_light(
    browser_page: Page,
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    screenshot_dir: Path,
) -> None:
    """The failed row renders black-on-yellow (>= AA) under dark AND light."""
    vm = smoke_vm
    original_state = helpers.config_get_state(vm, "system/webgui/webguicss")

    rowid = _free_rowid(vm, CFG_DNSBL)
    fail_file = f"{FAIL_DIR}/{HEADER}.fail"
    try:
        # Seed the failed state through the package's own save handler: a DNSBL
        # alias (action=unbound) with one source row whose header owns a .fail
        # file -- exactly the state a failed download produces. No hand-crafted
        # request; the page is driven as an authenticated admin would drive it.
        payload = {
            "type": "dnsbl",
            "rowid": str(rowid),
            "aliasname": ALIAS,
            "description": "smoke #2866 failed row",
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
            "url-0": "http://127.0.0.1/smokefailedrow.txt",
            "header-0": HEADER,
        }
        _post_form(webui, payload)
        base = f"{CFG_DNSBL}/{rowid}"
        assert helpers.config_get(vm, f"{base}/action") == "unbound", "alias save did not persist action"
        assert helpers.config_get(vm, f"{base}/row/0/header") == HEADER, "source-row header not persisted"

        touch = vm.ssh(f"touch '{FAIL_DIR}/{HEADER}.fail'")
        assert touch.returncode == 0, f"seeding .fail failed: {touch.stderr!r}"

        # ---------------- DARK leg ----------------
        _set_theme(vm, _DARK)
        _open(browser_page, webui, f"{CATEGORY_PAGE}?type=dnsbl&rowid={rowid}")
        assert _DARK in _head_stylesheets(browser_page), "pfSense-dark.css is not the active stylesheet"
        row = browser_page.locator("input[id^='header-'][style*='#FFFF00']")
        assert row.count() == 1, "the failed-download row did not render with the yellow background"
        dark_fg, dark_bg = _measure_failed_row(browser_page)
        dark_contrast = _contrast(dark_fg, dark_bg)
        assert dark_fg == (0, 0, 0), f"dark: foreground is {dark_fg}, expected pinned black"
        assert dark_bg == (255, 255, 0), f"dark background is {dark_bg}, expected #FFFF00"
        assert dark_contrast >= AA_FLOOR, f"dark-theme contrast {dark_contrast:.2f}:1 is below WCAG AA {AA_FLOOR}:1"

        # ---------------- LIGHT leg ----------------
        _set_theme(vm, _LIGHT)
        _open(browser_page, webui, f"{CATEGORY_PAGE}?type=dnsbl&rowid={rowid}")
        assert _LIGHT in _head_stylesheets(browser_page), "pfSense.css is not the active stylesheet"
        light_fg, light_bg = _measure_failed_row(browser_page)
        light_contrast = _contrast(light_fg, light_bg)
        assert light_bg == (255, 255, 0), f"light background is {light_bg}, expected #FFFF00"
        assert light_contrast >= AA_FLOOR, f"light-theme contrast {light_contrast:.2f}:1 is below AA {AA_FLOOR}:1"
        assert light_fg == (0, 0, 0), f"light-theme foreground is {light_fg}, expected pinned black"

        # Contrast evidence recorded for the artifact log.
        print(f"\n#2866 computed contrast: dark {dark_contrast:.2f}:1, light {light_contrast:.2f}:1")
    finally:
        # Restore the exact pre-probe theme state (presence + raw token), then
        # drop the seeded alias slot and the .fail file. The ui_browser marker
        # also arms the config-digest probe, so a leak surfaces either way.
        helpers.config_restore_state(vm, "system/webgui/webguicss", original_state)
        _del_rowid(vm, CFG_DNSBL, rowid)
        vm.ssh(f"rm -f '{fail_file}'")
