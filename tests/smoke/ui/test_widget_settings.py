"""Issue #3646: widget settings save only the controls that actually do something."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .render_oracle import PhpErrorLogGuard
from .webui import looks_like_login_page, scrape_form_fields

if TYPE_CHECKING:
    from playwright.sync_api import Page

    from .webui import WebUI

WIDGET_PAGE = "/widgets/widgets/pfblockerng.widget.php"
GLOBAL_PATH = "installedpackages/pfblockerngglobal"
SETTINGS = {
    "popup": "on",
    "sortmix": "on",
    "show_agg": "on",
    "sortcolumn": "packets",
    "sortdir": "des",
    "clearip": "never",
    "cleardnsbl": "never",
    "maxfails": "7",
    "maxheight": "450",
}


@pytest.mark.ui_render
def test_widget_settings_render_only_effective_controls(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """The live form still offers real settings, but no resolver-query frequency."""
    guard = PhpErrorLogGuard(smoke_vm)
    guard.snapshot()
    response = webui.get(WIDGET_PAGE)
    assert response.status_code == 200, f"widget GET returned {response.status_code}"
    assert not looks_like_login_page(response.text), "widget GET returned the login form"
    fields = scrape_form_fields(response.text)
    for key in ("sortcolumn", "sortdir", "clearip", "cleardnsbl", "maxfails", "maxheight"):
        assert f"pfb_{key}" in fields, f"widget lost its {key} control: {fields.keys()}"
    assert "pfb_dnsblquery" not in fields, f"obsolete control remains: {fields.keys()}"
    guard.assert_no_growth()


@pytest.mark.ui_browser
def test_widget_settings_browser_has_no_obsolete_control(browser_page: Page, webui: WebUI) -> None:
    """The browser receives the remaining controls, not the removed frequency row."""
    response = browser_page.goto(webui.url(WIDGET_PAGE), wait_until="domcontentloaded", timeout=30000)
    assert response is not None and response.status == 200, "widget navigation did not return HTTP 200"
    assert browser_page.locator("#usernamefld").count() == 0, "widget navigation returned the login form"
    form = browser_page.locator(f'form[action="{WIDGET_PAGE}"]')
    assert form.count() == 1, "expected one widget settings form"
    for key in SETTINGS:
        assert form.locator(f'[name="pfb_{key}"]').count() >= 1, f"widget lost its {key} control"
    assert form.locator('[name="pfb_dnsblquery"]').count() == 0, "obsolete query-frequency control remains"
    assert form.get_by_text("Enter DNSBL Resolver Query frequency", exact=False).count() == 0


@pytest.mark.ui_e2e
@pytest.mark.parametrize("stale", [False, True], ids=["fresh", "stale"])
@pytest.mark.parametrize("legacy_post", [False, True], ids=["normal-post", "legacy-post"])
def test_widget_save_ignores_obsolete_frequency_and_keeps_real_settings(
    webui: WebUI, smoke_vm: helpers.SmokeVM, stale: bool, legacy_post: bool
) -> None:
    """Missing or legacy submitted keys cannot retain a dead setting after save."""
    obsolete_path = f"{GLOBAL_PATH}/widget-dnsblquery"
    helpers.config_restore_state(smoke_vm, obsolete_path, (stale, "77" if stale else ""))
    assert helpers.config_get_state(smoke_vm, obsolete_path) == (stale, "77" if stale else "")
    helpers.config_set(smoke_vm, f"{GLOBAL_PATH}/widget-maxheight", "900")
    unrelated = helpers.config_get_state(smoke_vm, f"{GLOBAL_PATH}/enable_cb")
    response = webui.get(WIDGET_PAGE)
    assert response.status_code == 200, f"widget GET returned {response.status_code}"
    assert not looks_like_login_page(response.text), "widget GET returned the login form"
    payload = {f"pfb_{key}": value for key, value in SETTINGS.items()}
    payload["pfb_submit"] = "save"
    if legacy_post:
        payload["pfb_dnsblquery"] = "60"
    saved = webui.session.post(
        webui.url(WIDGET_PAGE), data=payload, headers={"Sec-Fetch-Site": "same-origin"}, timeout=30
    )
    assert saved.status_code == 200, f"widget save returned {saved.status_code}"
    assert not looks_like_login_page(saved.text), "widget save returned the login form"
    assert helpers.config_get_state(smoke_vm, obsolete_path) == (False, ""), "save retained obsolete frequency"
    for key, value in SETTINGS.items():
        actual = helpers.config_get_state(smoke_vm, f"{GLOBAL_PATH}/widget-{key}")
        assert actual == (True, value), f"widget-{key}: expected {value!r}, got {actual!r}"
    assert helpers.config_get_state(smoke_vm, f"{GLOBAL_PATH}/enable_cb") == unrelated
