"""Tier-B browser tests (ADR-14 Phase 4): the DNSBL page's inline show/hide JS.

These exercise the client-side toggles wired in the inline ``<script>`` of
``src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php`` -- the
checkbox-gated ``Form_Section`` show/hide handlers an HTTP POST cannot reach --
against the LIVE webConfigurator on the ADR-04 smoke VM, reusing the Phase-1
authenticated session (the ``PHPSESSID`` cookie the ``browser_context`` fixture
injects, so the browser never logs in a second time).

``test_browser.py`` already covers the ADR-13 ``#pfb_dnsvip_auto`` ->
``#pfb_dnsvip4``/``#pfb_dnsvip6`` *disable* handler (``enable_dnsvip_auto``);
this file covers the OTHER inline handlers, each gating a separate collapsible
section by ``.show()``/``.hide()`` on the section's OUTER panel div (whose id is
the second ``Form_Section`` constructor arg). The JS under test is READ-ONLY
reference (no ``src/`` change); the exact selectors/behaviours are taken from the
page's inline script (line numbers are pfblockerng_dnsbl.php):

* ``enable_python_regex()`` (3099-3105, bound to ``#pfb_regex`` click at
  3151-3154 and run on load at 3154): when ``#pfb_regex`` is CHECKED it
  ``.show()``s the ``Python_regex_list`` section (``Form_Section`` id at 2502),
  UNCHECKED it ``.hide()``s it.
* ``enable_python_noaaaa()`` (3107-3113, bound at 3156-3159): ``#pfb_noaaaa``
  gates the ``Python_noaaaa_list`` section (id at 2524).
* ``enable_python_gp()`` (3115-3121, bound at 3161-3164): ``#pfb_gp`` gates the
  ``Python_Group_Policy`` section (id at 2474).
* ``enable_tld()`` (3067-3075, bound at 3136-3139): ``#pfb_tld`` gates BOTH the
  ``TLD_Exclusion`` (id at 2802) and ``TLD_BW_list`` (id at 2827) sections at
  once.
* ``enable_dnsblip()`` (3123-3133, bound to ``#action`` click at 3166-3169): the
  ``#action`` List-Action select being non-``Disabled`` ``.show()``s BOTH the
  ``advinboundsettings`` and ``advoutboundsettings`` sections (ids built at
  2909); ``Disabled`` ``.hide()``s them.

All five gating controls default OFF on a fresh box (``pfb_regex``/``pfb_noaaaa``/
``pfb_gp``/``pfb_tld`` default ``''`` -> unchecked; ``action`` defaults
``Disabled``), so the on-load handler pass leaves every dependent section HIDDEN
-- the BEFORE state each test asserts before flipping the control, then asserts
the AFTER (shown), then flips back to re-hide (both branches, per CLAUDE.md
"Test coverage"). The section ids ride the section's OUTER panel div (the element
the handler ``.show()``/``.hide()``s), so ``to_be_visible()`` / ``to_be_hidden()``
reads the jQuery-set ``display`` directly.

NO fixed sleeps: every assertion uses Playwright's auto-waiting
(``expect(...).to_be_visible()`` / ``to_be_hidden()`` / ``to_be_checked()``).
Per-state full-page screenshots are written to ``screenshot_dir`` for human
review (ADR §2 "Screenshots (A1)" -- artifacts, NOT asserted pixel baselines).

DEFERRED (noted in the report): ``enable_python_pytld`` (multi-target
``hideMultiClass``/``hideCheckbox``), ``enable_ports`` (gated by the
``#dnsbl_interface`` select, whose non-``lo0`` options depend on the VM's live
interfaces), and the auto-VIP OPTION-INJECTION half of ``enable_dnsvip_auto``.

Playwright is imported lazily via ``pytest.importorskip`` (in ``conftest`` and
here) so importing/collecting this module does not hard-error when Playwright is
absent.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

# Tier-B dep: guard the import so collecting this module without Playwright
# installed (this dev venv, or any host that skips the browser tier) does not
# hard-error. Everything below references `expect` from the imported module.
from .. import helpers
from .conftest import mask_page_identity

sync_api = pytest.importorskip("playwright.sync_api", reason="playwright not installed (Tier-B browser dep)")
expect = sync_api.expect

if TYPE_CHECKING:
    from playwright.sync_api import Page

    from .webui import WebUI

pytestmark = pytest.mark.ui_browser

# The DNSBL settings page hosts the inline show/hide handlers under test.
DNSBL_PAGE = "/pfblockerng/pfblockerng_dnsbl.php"

# A short, explicit timeout (ms) for the JS-driven DOM transitions: the handlers
# fire synchronously on load/click, so this is a flake ceiling, not a wait knob.
JS_TIMEOUT_MS = 10_000


def _open(page: Page, webui: WebUI, path: str) -> None:
    """Navigate the (cookie-authenticated) page to ``path`` and settle the DOM.

    Asserts the load did NOT bounce to the login form -- proving the injected
    session cookie authenticated the browser (no second login). Waits on
    ``networkidle`` so the page's ``events`` handlers (which pfSense runs after
    DOMContentLoaded) have executed before any assertion.
    """
    page.goto(webui.url(path), wait_until="domcontentloaded", timeout=JS_TIMEOUT_MS * 3)
    page.wait_for_load_state("networkidle", timeout=JS_TIMEOUT_MS * 3)
    # The login form carries #usernamefld; its absence proves we are authed.
    assert page.locator("#usernamefld").count() == 0, f"GET {path} showed the login form -- cookie not authenticated"


def _shot(page: Page, screenshot_dir: Path, name: str) -> None:
    """Write a full-page screenshot artifact ``<screenshot_dir>/<name>.png``.

    Value-redacts the Plus VM identity from the DOM first (ADR-24 ``mask_page_identity``);
    a strict no-op on a CE leg (empty redaction set), so CE shots are unchanged.
    """
    mask_page_identity(page)
    page.screenshot(path=str(screenshot_dir / f"{name}.png"), full_page=True)


def _assert_checkbox_gates_section(
    page: Page,
    checkbox_id: str,
    section_id: str,
    screenshot_dir: Path,
    shot_prefix: str,
) -> None:
    """A checkbox whose click handler ``.show()``/``.hide()``s one section by id.

    Drives the full two-way transition with the before-state asserted: normalise
    the checkbox to UNCHECKED (the fresh-box default), assert the section HIDDEN,
    check -> assert SHOWN, uncheck -> assert HIDDEN again. Uses the native
    ``el.click()`` (via ``evaluate``) so the bound jQuery handler fires regardless
    of the control's panel geometry (see test_browser.py's enable_change test).
    """
    box = page.locator(f"#{checkbox_id}")
    section = page.locator(f"#{section_id}")
    expect(box).to_be_attached(timeout=JS_TIMEOUT_MS)
    expect(section).to_be_attached(timeout=JS_TIMEOUT_MS)

    # Normalise to a deterministic start (unchecked) regardless of saved config.
    if box.is_checked():
        box.evaluate("el => el.click()")
        expect(box).not_to_be_checked(timeout=JS_TIMEOUT_MS)

    # BEFORE: checkbox off -> the on-load handler pass left the section hidden.
    expect(box).not_to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(section).to_be_hidden(timeout=JS_TIMEOUT_MS)
    _shot(page, screenshot_dir, f"{shot_prefix}_before_hidden")

    # CHECK -> the handler .show()s the section.
    box.evaluate("el => el.click()")
    expect(box).to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(section).to_be_visible(timeout=JS_TIMEOUT_MS)
    _shot(page, screenshot_dir, f"{shot_prefix}_after_shown")

    # UNCHECK -> re-hidden (proves it is a real two-way branch, not always-shown).
    box.evaluate("el => el.click()")
    expect(box).not_to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(section).to_be_hidden(timeout=JS_TIMEOUT_MS)


def test_regex_checkbox_toggles_regex_list_section(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    """`#pfb_regex` gates the `Python_regex_list` section's visibility.

    ``enable_python_regex()`` (pfblockerng_dnsbl.php:3099-3105): CHECKED ->
    ``.show()`` the section, UNCHECKED -> ``.hide()`` it. Before->after with both
    directions exercised.
    """
    page = browser_page
    _open(page, webui, DNSBL_PAGE)
    _assert_checkbox_gates_section(page, "pfb_regex", "Python_regex_list", screenshot_dir, "dnsbl_regex")


def test_noaaaa_checkbox_toggles_noaaaa_list_section(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    """`#pfb_noaaaa` gates the `Python_noaaaa_list` section's visibility.

    ``enable_python_noaaaa()`` (pfblockerng_dnsbl.php:3107-3113): CHECKED ->
    ``.show()``, UNCHECKED -> ``.hide()``. Both directions, before-state asserted.
    """
    page = browser_page
    _open(page, webui, DNSBL_PAGE)
    _assert_checkbox_gates_section(page, "pfb_noaaaa", "Python_noaaaa_list", screenshot_dir, "dnsbl_noaaaa")


def test_group_policy_checkbox_toggles_group_policy_section(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    """`#pfb_gp` gates the `Python_Group_Policy` section's visibility.

    ``enable_python_gp()`` (pfblockerng_dnsbl.php:3115-3121): CHECKED ->
    ``.show()``, UNCHECKED -> ``.hide()``. Both directions, before-state asserted.
    """
    page = browser_page
    _open(page, webui, DNSBL_PAGE)
    _assert_checkbox_gates_section(page, "pfb_gp", "Python_Group_Policy", screenshot_dir, "dnsbl_gp")


def test_tld_checkbox_toggles_both_tld_sections(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    """`#pfb_tld` gates BOTH the `TLD_Exclusion` and `TLD_BW_list` sections.

    ``enable_tld()`` (pfblockerng_dnsbl.php:3067-3075) ``.show()``/``.hide()``s
    the two collapsible TLD sections together off the one checkbox. Branch
    coverage with the before-state asserted (CLAUDE.md): start unchecked -> BOTH
    sections hidden, check -> BOTH shown, uncheck -> BOTH hidden again.
    """
    page = browser_page
    _open(page, webui, DNSBL_PAGE)

    box = page.locator("#pfb_tld")
    excl = page.locator("#TLD_Exclusion")
    bwl = page.locator("#TLD_BW_list")
    expect(box).to_be_attached(timeout=JS_TIMEOUT_MS)
    expect(excl).to_be_attached(timeout=JS_TIMEOUT_MS)
    expect(bwl).to_be_attached(timeout=JS_TIMEOUT_MS)

    # Normalise to a deterministic start (unchecked) regardless of saved config.
    if box.is_checked():
        box.evaluate("el => el.click()")
        expect(box).not_to_be_checked(timeout=JS_TIMEOUT_MS)

    # BEFORE: checkbox off -> the on-load handler pass left both sections hidden.
    expect(box).not_to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(excl).to_be_hidden(timeout=JS_TIMEOUT_MS)
    expect(bwl).to_be_hidden(timeout=JS_TIMEOUT_MS)
    _shot(page, screenshot_dir, "dnsbl_tld_before_hidden")

    # CHECK -> the handler .show()s both sections.
    box.evaluate("el => el.click()")
    expect(box).to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(excl).to_be_visible(timeout=JS_TIMEOUT_MS)
    expect(bwl).to_be_visible(timeout=JS_TIMEOUT_MS)
    _shot(page, screenshot_dir, "dnsbl_tld_after_shown")

    # UNCHECK -> both re-hidden (proves a real two-way branch).
    box.evaluate("el => el.click()")
    expect(box).not_to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(excl).to_be_hidden(timeout=JS_TIMEOUT_MS)
    expect(bwl).to_be_hidden(timeout=JS_TIMEOUT_MS)


def test_action_select_toggles_advanced_firewall_sections(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    """`#action` != `Disabled` shows the Advanced In/Outbound firewall sections.

    ``enable_dnsblip()`` (pfblockerng_dnsbl.php:3123-3133), bound to the
    ``#action`` List-Action select's click (3166-3169) and run on load: a
    non-``Disabled`` value ``.show()``s BOTH ``advinboundsettings`` and
    ``advoutboundsettings``; ``Disabled`` ``.hide()``s them. The select defaults
    ``Disabled`` (3124 / $pconfig default), so the on-load pass leaves both
    sections hidden -- the asserted BEFORE state. The handler reads the select
    VALUE, so we ``select_option`` then fire the bound ``click`` to run it (a
    ``<select>`` change does not raise ``click``); both branches are exercised.
    """
    page = browser_page
    _open(page, webui, DNSBL_PAGE)

    action = page.locator("#action")
    adv_in = page.locator("#advinboundsettings")
    adv_out = page.locator("#advoutboundsettings")
    expect(action).to_be_attached(timeout=JS_TIMEOUT_MS)
    expect(adv_in).to_be_attached(timeout=JS_TIMEOUT_MS)
    expect(adv_out).to_be_attached(timeout=JS_TIMEOUT_MS)

    # Normalise to a deterministic start (Disabled) regardless of saved config.
    if action.input_value() != "Disabled":
        action.select_option("Disabled")
        action.dispatch_event("click")
        expect(action).to_have_value("Disabled", timeout=JS_TIMEOUT_MS)

    # BEFORE: action Disabled -> the on-load handler pass left both adv sections hidden.
    expect(action).to_have_value("Disabled", timeout=JS_TIMEOUT_MS)
    expect(adv_in).to_be_hidden(timeout=JS_TIMEOUT_MS)
    expect(adv_out).to_be_hidden(timeout=JS_TIMEOUT_MS)
    _shot(page, screenshot_dir, "dnsbl_action_before_hidden")

    # SELECT a Deny action + fire the bound click -> the handler .show()s both.
    action.select_option("Deny_Both")
    action.dispatch_event("click")
    expect(action).to_have_value("Deny_Both", timeout=JS_TIMEOUT_MS)
    expect(adv_in).to_be_visible(timeout=JS_TIMEOUT_MS)
    expect(adv_out).to_be_visible(timeout=JS_TIMEOUT_MS)
    _shot(page, screenshot_dir, "dnsbl_action_after_shown")

    # BACK to Disabled -> both re-hidden (proves a real two-way branch).
    action.select_option("Disabled")
    action.dispatch_event("click")
    expect(action).to_have_value("Disabled", timeout=JS_TIMEOUT_MS)
    expect(adv_in).to_be_hidden(timeout=JS_TIMEOUT_MS)
    expect(adv_out).to_be_hidden(timeout=JS_TIMEOUT_MS)


def test_idn_mode_select_gates_confusable_subtoggles(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    """`#pfb_idn` = "Confusable" SHOWS the two Confusable sub-toggle checkboxes; any
    other mode HIDES them (ADR-08).

    ``enable_idn_mode()`` (pfblockerng_dnsbl.php:3607, bound to ``#pfb_idn.change`` at
    :3670) ``hideCheckbox()``s ``#pfb_idn_block_malicious`` + ``#pfb_idn_escalate_suspicious``
    -- shown ONLY when the select is "confusable". The three option values are 'off'
    (Off) / 'confusable' (Confusable) / 'on' (Always); all three states are asserted
    (Off -> Confusable -> Always) so green proves the sub-toggles are confusable-
    specific, not always-shown nor merely "anything but Off". Playwright ``to_be_hidden``
    on the input holds when hideCheckbox sets ``display:none`` on the enclosing
    ``.form-group`` row. A full-page screenshot is captured at each state.
    """
    page = browser_page
    _open(page, webui, DNSBL_PAGE)

    sel = page.locator("#pfb_idn")
    block_mal = page.locator("#pfb_idn_block_malicious")
    escalate = page.locator("#pfb_idn_escalate_suspicious")
    expect(sel).to_be_attached(timeout=JS_TIMEOUT_MS)
    expect(block_mal).to_be_attached(timeout=JS_TIMEOUT_MS)
    expect(escalate).to_be_attached(timeout=JS_TIMEOUT_MS)

    # Normalise to a deterministic start (Off = 'off') regardless of saved config.
    if sel.input_value() != "off":
        sel.select_option("off")
        sel.dispatch_event("change")
        expect(sel).to_have_value("off", timeout=JS_TIMEOUT_MS)

    # BEFORE: Off -> both sub-toggles hidden.
    expect(sel).to_have_value("off", timeout=JS_TIMEOUT_MS)
    expect(block_mal).to_be_hidden(timeout=JS_TIMEOUT_MS)
    expect(escalate).to_be_hidden(timeout=JS_TIMEOUT_MS)
    _shot(page, screenshot_dir, "dnsbl_idn_off_subtoggles_hidden")

    # SELECT Confusable -> the handler shows both sub-toggles.
    sel.select_option("confusable")
    sel.dispatch_event("change")
    expect(sel).to_have_value("confusable", timeout=JS_TIMEOUT_MS)
    expect(block_mal).to_be_visible(timeout=JS_TIMEOUT_MS)
    expect(escalate).to_be_visible(timeout=JS_TIMEOUT_MS)
    _shot(page, screenshot_dir, "dnsbl_idn_confusable_subtoggles_shown")

    # SELECT Always ('on') -> hidden again (third state: confusable-specific, not just != Off).
    sel.select_option("on")
    sel.dispatch_event("change")
    expect(sel).to_have_value("on", timeout=JS_TIMEOUT_MS)
    expect(block_mal).to_be_hidden(timeout=JS_TIMEOUT_MS)
    expect(escalate).to_be_hidden(timeout=JS_TIMEOUT_MS)
    _shot(page, screenshot_dir, "dnsbl_idn_always_subtoggles_hidden")


# --------------------------------------------------------------------------- #
# ADR-29 gateway save→reload→assert round-trip (pfb_dnsbl_lenient on DNSBL page)
# --------------------------------------------------------------------------- #

# Config path for the pfb_dnsbl_lenient field (DNSBL settings section).
_CFG_LENIENT = "installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl_lenient"

# POST timeout: DNSBL settings save only write_config()s (no reload), so it's fast.
_DNSBL_POST_TIMEOUT = 120.0


@pytest.fixture(scope="module")
def dnsbl_vip_ready_browser(smoke_vm: helpers.SmokeVM) -> None:
    """Ensure the DNSBL sinkhole VIP exists so the DNSBL settings page save validates.

    The DNSBL settings save always runs ``pfb_validate_vips`` (manual mode) before
    writing config.  Without a valid VIP the save fails with an input error and
    config.xml is never written — any gateway assertion would false-fail.
    Module-scoped so it runs once per collection of this module.
    """
    helpers.ensure_dnsbl_vip(smoke_vm)


def test_gateway_dnsbl_lenient_save_roundtrip(
    browser_page: Page,
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    dnsbl_vip_ready_browser: None,
    screenshot_dir: Path,
) -> None:
    """pfb_dnsbl_lenient round-trips through the DNSBL page and the gateway.

    Proves the ADR-29 gateway routing on ``pfblockerng_dnsbl.php`` stores the matching
    checkbox token for ``pfb_dnsbl_lenient`` and that the page re-renders the checkbox
    in the matching state when reloaded.

    NOTE on the stored vocabulary: although ``pfb_dnsbl_lenient`` has a 3-state
    PfbLenient *read* adapter at the ``pfb_global()`` seam ('on'/'off'/''), the DNSBL
    *page* treats it as a plain on/'' checkbox — it saves via ``pfb_filter(...,
    PFB_FILTER_ON_OFF)`` (which rejects 'off') and renders via
    ``pfb_cfg_toggle_read() === PfbToggle::On``. So the only page-reachable stored
    tokens are 'on' (checked) and '' (unchecked); this test round-trips those.

    Scenario: ADR-29 gateway save→reload round-trip for pfb_dnsbl_lenient on the DNSBL page.
      Background: pfBlockerNG deployed; DNSBL VIP seeded; webConfigurator authenticated.

    Given the current checkbox state of pfb_dnsbl_lenient (read via config_get oracle —
      'on' = checked, anything else = unchecked),
    When the DNSBL page is POST-saved with the checkbox flipped,
    Then config.xml holds the matching token ('on' or ''); AND the DNSBL page, navigated
      fresh in the browser, renders the checkbox in the matching state; AND a second POST
      restores the original state with the same two assertions (both directions).
    """
    page = browser_page

    # GIVEN: the page stores this field as a plain on/'' checkbox ('off' is not a
    # page-reachable token — pfb_filter ON_OFF rejects it). Map the stored value to its
    # checkbox token: 'on' = checked, anything else (''/'off'/absent) = unchecked.
    original_raw = helpers.config_get(smoke_vm, _CFG_LENIENT)
    original_box = "on" if original_raw == "on" else ""
    flipped = "" if original_box == "on" else "on"

    try:
        # ---- FLIP: POST the checkbox to the opposite state ---- #
        resp = webui.post(DNSBL_PAGE, {"pfb_dnsbl_lenient": flipped}, timeout=_DNSBL_POST_TIMEOUT)
        assert "Sign In" not in resp.text, "pfb_dnsbl_lenient flip POST lost the session"

        # Config oracle: stored token must equal the flipped checkbox value.
        stored_flip = helpers.config_get(smoke_vm, _CFG_LENIENT)
        assert stored_flip == flipped, (
            f"pfb_dnsbl_lenient gateway FAIL after flip: stored {stored_flip!r}, "
            f"expected {flipped!r} (the DNSBL-page checkbox stores 'on'/'' through the gateway)"
        )

        # DOM oracle: reload the DNSBL page and assert the checkbox state matches.
        _open(page, webui, DNSBL_PAGE)
        box_flip = page.locator("#pfb_dnsbl_lenient")
        expect(box_flip).to_be_attached(timeout=JS_TIMEOUT_MS)
        if flipped == "on":
            expect(box_flip).to_be_checked(timeout=JS_TIMEOUT_MS)
        else:
            expect(box_flip).not_to_be_checked(timeout=JS_TIMEOUT_MS)
        _shot(page, screenshot_dir, "gateway_dnsbl_lenient_after_flip")

        # ---- RESTORE: POST the checkbox back to its original state ---- #
        resp = webui.post(DNSBL_PAGE, {"pfb_dnsbl_lenient": original_box}, timeout=_DNSBL_POST_TIMEOUT)
        assert "Sign In" not in resp.text, "pfb_dnsbl_lenient restore POST lost the session"

        # Config oracle: stored token must equal the original checkbox value.
        stored_restore = helpers.config_get(smoke_vm, _CFG_LENIENT)
        assert stored_restore == original_box, (
            f"pfb_dnsbl_lenient gateway FAIL after restore: stored {stored_restore!r}, expected {original_box!r}"
        )

        # DOM oracle: reload and assert the checkbox matches the restored value.
        _open(page, webui, DNSBL_PAGE)
        box_restore = page.locator("#pfb_dnsbl_lenient")
        expect(box_restore).to_be_attached(timeout=JS_TIMEOUT_MS)
        if original_box == "on":
            expect(box_restore).to_be_checked(timeout=JS_TIMEOUT_MS)
        else:
            expect(box_restore).not_to_be_checked(timeout=JS_TIMEOUT_MS)
        _shot(page, screenshot_dir, "gateway_dnsbl_lenient_after_restore")

    finally:
        # Belt-and-suspenders: restore to the original checkbox value on any mid-flip abort.
        if helpers.config_get(smoke_vm, _CFG_LENIENT) != original_box:
            webui.post(DNSBL_PAGE, {"pfb_dnsbl_lenient": original_box}, timeout=_DNSBL_POST_TIMEOUT)
