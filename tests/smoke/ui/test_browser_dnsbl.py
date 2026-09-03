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
page's inline script — referenced symbolically (handler / checkbox / section id)
so the references cannot rot as pfblockerng_dnsbl.php grows (issue #788):

* ``enable_python_regex()`` (bound to ``#pfb_regex`` click and run once on
  load): when ``#pfb_regex`` is CHECKED it ``.show()``s the
  ``Python_regex_list`` section, UNCHECKED it ``.hide()``s it.
* ``enable_python_noaaaa()``: ``#pfb_noaaaa`` gates the ``Python_noaaaa_list``
  section.
* ``enable_python_gp()``: ``#pfb_gp`` gates the ``Python_Group_Policy`` section.
* ``enable_tld()``: ``#tld_wildcard`` gates BOTH the ``TLD_Exclusion`` and
  ``TLD_BW_list`` sections at once.
* ``enable_tld_allow()``: ``#tld_allow`` ``.show()``/``.hide()``s the
  ``tld_allow_pickers`` section and ``disableInput()``s ``pfb_psl_allow_private``.
* ``enable_dnsblip()`` (bound to ``#action`` click): the ``#action`` List-Action
  select being non-``Disabled`` ``.show()``s BOTH the ``advinboundsettings`` and
  ``advoutboundsettings`` sections; ``Disabled`` ``.hide()``s them.

All six gating controls default OFF on a fresh box (``pfb_regex``/``pfb_noaaaa``/
``pfb_gp``/``tld_wildcard``/``tld_allow`` default ``''`` -> unchecked; ``action`` defaults
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

``enable_tld_allow()`` gates the ``tld_allow_pickers`` section (same
``.show()``/``.hide()`` pattern as Regex / no-AAAA / Group Policy) plus the
``pfb_psl_allow_private`` row via ``disableInput()`` (stays visible, greys out,
still POSTs). The two PSL *feed-policy* selects live in ``dnsbl_suffix`` and
must stay visible regardless of ``#tld_allow`` / ``#tld_wildcard`` (issue #2371).

DEFERRED (noted in the report): ``enable_ports`` (gated by the
``#dnsbl_interface`` select, whose non-``lo0`` options depend on the VM's live
interfaces), and the auto-VIP OPTION-INJECTION half of ``enable_dnsvip_auto``.

Playwright is imported lazily via ``pytest.importorskip`` (in ``conftest`` and
here) so importing/collecting this module does not hard-error when Playwright is
absent.
"""

from __future__ import annotations

import re
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
    from playwright.sync_api import Locator, Page

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


def _expand_section(page: Page, section_id: str) -> None:
    """Expand a COLLAPSIBLE|SEC_CLOSED Form_Section so rows inside are observable.

    The body id is ``{id}_panel-body`` (pfSense Section.class.php), not ``#{id}-panel``:
    that selector matches nothing, and a ``count() == 0`` guard turns it into a silent
    success. Assert the body is attached so a wrong selector fails here, loudly.

    Keep the two copies of this helper byte-identical -- them drifting apart is what left
    the IP page on the broken selector after the DNSBL page was fixed.
    """
    body = page.locator(f"#{section_id}_panel-body")
    expect(body).to_be_attached(timeout=JS_TIMEOUT_MS)
    if "in" not in (body.get_attribute("class") or ""):
        page.locator(f'a[data-toggle="collapse"][href="#{section_id}_panel-body"]').click()
    expect(body).to_be_visible(timeout=JS_TIMEOUT_MS)


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
    """`#tld_wildcard` gates BOTH the `TLD_Exclusion` and `TLD_BW_list` sections.

    ``enable_tld()`` (pfblockerng_dnsbl.php:3067-3075) ``.show()``/``.hide()``s
    the two collapsible TLD sections together off the one checkbox. Branch
    coverage with the before-state asserted (CLAUDE.md): start unchecked -> BOTH
    sections hidden, check -> BOTH shown, uncheck -> BOTH hidden again.
    """
    page = browser_page
    _open(page, webui, DNSBL_PAGE)

    box = page.locator("#tld_wildcard")
    excl = page.locator("#TLD_Exclusion")
    bwl = page.locator("#TLD_BW_list")
    # issue #1541: the PSL PRIVATE recognition row rides the same gate via
    # disableInput() (visible, greys out, still POSTs). The row lives in
    # collapsed AdBlock suffix handling, so expand that panel first.
    psl_row = page.locator("#pfb_psl_include_private")
    expect(box).to_be_attached(timeout=JS_TIMEOUT_MS)
    expect(excl).to_be_attached(timeout=JS_TIMEOUT_MS)
    expect(bwl).to_be_attached(timeout=JS_TIMEOUT_MS)
    expect(psl_row).to_be_attached(timeout=JS_TIMEOUT_MS)
    _expand_section(page, "dnsbl_suffix")

    # Normalise to a deterministic start (unchecked) regardless of saved config.
    if box.is_checked():
        box.evaluate("el => el.click()")
        expect(box).not_to_be_checked(timeout=JS_TIMEOUT_MS)

    # BEFORE: checkbox off -> the on-load handler pass left both sections hidden.
    expect(box).not_to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(excl).to_be_hidden(timeout=JS_TIMEOUT_MS)
    expect(bwl).to_be_hidden(timeout=JS_TIMEOUT_MS)
    expect(psl_row).to_be_visible(timeout=JS_TIMEOUT_MS)
    expect(psl_row).to_be_disabled(timeout=JS_TIMEOUT_MS)
    _shot(page, screenshot_dir, "dnsbl_tld_before_hidden")

    # CHECK -> the handler .show()s both sections; PSL row enables.
    box.evaluate("el => el.click()")
    expect(box).to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(excl).to_be_visible(timeout=JS_TIMEOUT_MS)
    expect(bwl).to_be_visible(timeout=JS_TIMEOUT_MS)
    expect(psl_row).to_be_visible(timeout=JS_TIMEOUT_MS)
    expect(psl_row).to_be_enabled(timeout=JS_TIMEOUT_MS)
    _shot(page, screenshot_dir, "dnsbl_tld_after_shown")

    # UNCHECK -> both re-hidden; PSL row disables (still visible).
    box.evaluate("el => el.click()")
    expect(box).not_to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(excl).to_be_hidden(timeout=JS_TIMEOUT_MS)
    expect(bwl).to_be_hidden(timeout=JS_TIMEOUT_MS)
    expect(psl_row).to_be_visible(timeout=JS_TIMEOUT_MS)
    expect(psl_row).to_be_disabled(timeout=JS_TIMEOUT_MS)


def test_tld_allow_checkbox_gates_psl_allow_private_row(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    """`#tld_allow` gates the PSL PRIVATE allow row via ``disableInput()``.

    Narrow drill for issue #1541's allow-private toggle. The row lives in
    collapsed AdBlock suffix handling, so that panel is expanded first.
    The input stays visible and greys out (it must POST). Before-state
    asserted, then both directions.
    """
    page = browser_page
    _open(page, webui, DNSBL_PAGE)
    _expand_section(page, "dnsbl_suffix")

    box = page.locator("#tld_allow")
    allow_row = page.locator("#pfb_psl_allow_private")
    expect(box).to_be_attached(timeout=JS_TIMEOUT_MS)
    expect(allow_row).to_be_attached(timeout=JS_TIMEOUT_MS)

    if box.is_checked():
        box.evaluate("el => el.click()")
        expect(box).not_to_be_checked(timeout=JS_TIMEOUT_MS)

    expect(allow_row).to_be_visible(timeout=JS_TIMEOUT_MS)
    expect(allow_row).to_be_disabled(timeout=JS_TIMEOUT_MS)
    _shot(page, screenshot_dir, "dnsbl_psl_allow_before_disabled")

    box.evaluate("el => el.click()")
    expect(box).to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(allow_row).to_be_visible(timeout=JS_TIMEOUT_MS)
    expect(allow_row).to_be_enabled(timeout=JS_TIMEOUT_MS)
    _shot(page, screenshot_dir, "dnsbl_psl_allow_after_enabled")

    box.evaluate("el => el.click()")
    expect(box).not_to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(allow_row).to_be_visible(timeout=JS_TIMEOUT_MS)
    expect(allow_row).to_be_disabled(timeout=JS_TIMEOUT_MS)


def test_tld_allow_checkbox_toggles_tld_allow_pickers_section(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    """`#tld_allow` gates the `tld_allow_pickers` section's visibility.

    ``enable_tld_allow()`` (pfblockerng_dnsbl.php) CHECKED -> ``.show()`` the
    picker section, UNCHECKED -> ``.hide()`` it. Same sibling pattern as Regex /
    no-AAAA / Group Policy. Before-state asserted, both directions.
    """
    page = browser_page
    _open(page, webui, DNSBL_PAGE)
    _assert_checkbox_gates_section(page, "tld_allow", "tld_allow_pickers", screenshot_dir, "dnsbl_tld_allow_pickers")


def test_feed_policy_selects_stay_visible_when_tld_gates_flip(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    """issue #2371: PSL feed-policy selects are not hide-gated by Wildcard or TLD Allow.

    They live in collapsed AdBlock suffix handling (a move is allowed) but must
    remain visible inside that expanded panel when ``#tld_wildcard`` and
    ``#tld_allow`` flip. A hideCheckbox on either select is the regression.
    """
    page = browser_page
    _open(page, webui, DNSBL_PAGE)
    _expand_section(page, "dnsbl_suffix")

    private_sel = page.locator("#pfb_psl_feed_private_policy")
    icann_sel = page.locator("#pfb_psl_feed_icann_policy")
    wildcard = page.locator("#tld_wildcard")
    tld_allow = page.locator("#tld_allow")
    expect(private_sel).to_be_attached(timeout=JS_TIMEOUT_MS)
    expect(icann_sel).to_be_attached(timeout=JS_TIMEOUT_MS)

    if wildcard.is_checked():
        wildcard.evaluate("el => el.click()")
        expect(wildcard).not_to_be_checked(timeout=JS_TIMEOUT_MS)
    if tld_allow.is_checked():
        tld_allow.evaluate("el => el.click()")
        expect(tld_allow).not_to_be_checked(timeout=JS_TIMEOUT_MS)

    expect(private_sel).to_be_visible(timeout=JS_TIMEOUT_MS)
    expect(icann_sel).to_be_visible(timeout=JS_TIMEOUT_MS)
    _shot(page, screenshot_dir, "dnsbl_feed_policy_before_gates")

    wildcard.evaluate("el => el.click()")
    expect(wildcard).to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(private_sel).to_be_visible(timeout=JS_TIMEOUT_MS)
    expect(icann_sel).to_be_visible(timeout=JS_TIMEOUT_MS)

    tld_allow.evaluate("el => el.click()")
    expect(tld_allow).to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(private_sel).to_be_visible(timeout=JS_TIMEOUT_MS)
    expect(icann_sel).to_be_visible(timeout=JS_TIMEOUT_MS)
    _shot(page, screenshot_dir, "dnsbl_feed_policy_after_gates")

    wildcard.evaluate("el => el.click()")
    tld_allow.evaluate("el => el.click()")
    expect(wildcard).not_to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(tld_allow).not_to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(private_sel).to_be_visible(timeout=JS_TIMEOUT_MS)
    expect(icann_sel).to_be_visible(timeout=JS_TIMEOUT_MS)


def test_action_select_toggles_advanced_firewall_sections(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    """`#action` != `Disabled` shows the Advanced In/Outbound firewall sections.

    ``enable_dnsblip()`` (pfblockerng_dnsbl.php), bound to the ``#action``
    List-Action select's click and run on load: a non-``Disabled`` value
    ``.show()``s BOTH ``advinboundsettings`` and ``advoutboundsettings``;
    ``Disabled`` ``.hide()``s them. The select defaults ``Disabled``
    ($pconfig default), so the on-load pass leaves both
    sections hidden -- the asserted BEFORE state. The handler reads the select
    VALUE, so we ``select_option`` then fire the bound ``click`` to run it (a
    ``<select>`` change does not raise ``click``); both branches are exercised.
    """
    page = browser_page
    _open(page, webui, DNSBL_PAGE)
    _expand_section(page, "dnsbl_ips")

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


_IN_CLASS = re.compile(r"(^|\s)in(\s|$)")


def test_expand_all_opens_then_collapses_every_form_panel(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    """``#pfb_expand_all`` expands every ``form .panel-body.collapse``, swaps the
    label to Collapse all, and reverses on the second click.

    Source-string tests cannot prove the Bootstrap collapse() call or the label
    swap. Login form must be absent; the button must exist as ``type=button``.
    """
    page = browser_page
    _open(page, webui, DNSBL_PAGE)

    btn = page.locator("#pfb_expand_all")
    expect(btn).to_be_attached(timeout=JS_TIMEOUT_MS)
    expect(btn).to_be_visible(timeout=JS_TIMEOUT_MS)
    assert btn.get_attribute("type") == "button", "Expand all must be a button, not a heading link"

    bodies = page.locator("form .panel-body.collapse")
    n = bodies.count()
    assert n >= 2, f"expected several collapsible DNSBL panels, got {n}"

    expect(btn).to_have_text("Expand all", timeout=JS_TIMEOUT_MS)
    _shot(page, screenshot_dir, "dnsbl_expand_all_before")

    btn.click()
    expect(btn).to_have_text("Collapse all", timeout=JS_TIMEOUT_MS)
    for i in range(n):
        expect(bodies.nth(i)).to_have_class(_IN_CLASS, timeout=JS_TIMEOUT_MS)
    _shot(page, screenshot_dir, "dnsbl_expand_all_open")

    btn.click()
    expect(btn).to_have_text("Expand all", timeout=JS_TIMEOUT_MS)
    for i in range(n):
        expect(bodies.nth(i)).not_to_have_class(_IN_CLASS, timeout=JS_TIMEOUT_MS)
    _shot(page, screenshot_dir, "dnsbl_expand_all_closed")


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

    NOTE on the stored vocabulary (issue #964): the page form sends 'on' (checked) or
    '' (unchecked) — ``pfb_filter(..., PFB_FILTER_ON_OFF)`` rejects 'off' — but the
    save persists the section via ``PfbConfig::writeSection`` (pfblockerng_dnsbl.php:903),
    which round-trips every adapter-carrying key through its read+write adapters;
    unchecked saves store the empty token. Legacy ``'off'`` remains readable.

    Scenario: ADR-29 gateway save→reload round-trip for pfb_dnsbl_lenient on the DNSBL page.
      Background: pfBlockerNG deployed; DNSBL VIP seeded; webConfigurator authenticated.

    Given the current checkbox state of pfb_dnsbl_lenient (read via config_get oracle —
      'on' = checked, anything else = unchecked),
    When the DNSBL page is POST-saved with the checkbox flipped,
    Then config.xml holds the CANONICAL token ('on' or ''); AND the DNSBL page,
      navigated fresh in the browser, renders the checkbox in the matching state; AND a
      second POST restores the original state with the same two assertions (both
      directions).
    """
    page = browser_page

    # GIVEN: the form sends a plain on/'' checkbox, but the save's writeSection adapter
    # Map the stored value to its checkbox token ('on' = checked, anything else =
    # unchecked) and each POSTed token to the value the save will store.
    original_state = helpers.config_get_state(smoke_vm, _CFG_LENIENT)
    original_box = "on" if original_state[0] and original_state[1] == "on" else ""
    flipped = "" if original_box == "on" else "on"
    stored_token = {"on": "on", "": ""}  # POSTed checkbox token -> canonical stored token

    try:
        # ---- FLIP: POST the checkbox to the opposite state ---- #
        resp = webui.post(DNSBL_PAGE, {"pfb_dnsbl_lenient": flipped}, timeout=_DNSBL_POST_TIMEOUT)
        assert "Sign In" not in resp.text, "pfb_dnsbl_lenient flip POST lost the session"

        # Config oracle: stored token must be the CANONICAL form of the flipped value.
        stored_flip = helpers.config_get(smoke_vm, _CFG_LENIENT)
        assert stored_flip == stored_token[flipped], (
            f"pfb_dnsbl_lenient gateway FAIL after flip: stored {stored_flip!r}, "
            f"expected {stored_token[flipped]!r} (the writeSection adapter stores canonical on/empty)"
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

        # Config oracle: stored token must be the CANONICAL form of the original value.
        stored_restore = helpers.config_get(smoke_vm, _CFG_LENIENT)
        assert stored_restore == stored_token[original_box], (
            f"pfb_dnsbl_lenient gateway FAIL after restore: stored {stored_restore!r}, "
            f"expected {stored_token[original_box]!r} (canonical on/empty)"
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
        helpers.config_restore_state(smoke_vm, _CFG_LENIENT, original_state)
        assert helpers.config_get_state(smoke_vm, _CFG_LENIENT) == original_state

    finally:
        # Belt-and-suspenders: restore to the original checkbox value on any mid-flip
        # abort (compare against the canonical stored token an unchecked save leaves).
        if helpers.config_get_state(smoke_vm, _CFG_LENIENT) != original_state:
            helpers.config_restore_state(smoke_vm, _CFG_LENIENT, original_state)


# --------------------------------------------------------------------------- #
# issue #2371 Step 3: ADR-29 gateway save->reload round-trip for BOTH feed-at-suffix
# policy selects (pfb_psl_feed_private_policy / pfb_psl_feed_icann_policy).
# --------------------------------------------------------------------------- #

_CFG_FEED_PRIVATE_POLICY = "installedpackages/pfblockerngdnsblsettings/config/0/pfb_psl_feed_private_policy"
_CFG_FEED_ICANN_POLICY = "installedpackages/pfblockerngdnsblsettings/config/0/pfb_psl_feed_icann_policy"


def test_gateway_dnsbl_feed_suffix_policy_save_roundtrip(
    browser_page: Page,
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    dnsbl_vip_ready_browser: None,
    screenshot_dir: Path,
) -> None:
    """pfb_psl_feed_private_policy / pfb_psl_feed_icann_policy round-trip through the
    DNSBL page and the gateway (issue #2371 Step 3).

    Same idiom as ``test_gateway_dnsbl_lenient_save_roundtrip`` above, extended to TWO
    independent ``<select>`` fields (instead of one checkbox) so a field-swap bug (the
    save binding for one field accidentally writing the other's key) is caught: each
    field is driven to a DIFFERENT non-default token ('apex' for PRIVATE, 'ignore' for
    ICANN).

    Scenario: ADR-29 gateway save->reload round-trip for the feed-at-suffix policy
      selects on the DNSBL page.
      Background: pfBlockerNG deployed; DNSBL VIP seeded; webConfigurator authenticated.

    Given the current stored token of both fields (read via config_get oracle; an
      absent/unrecognised token reads as 'honor' per PfbFeedSuffixPolicy's fail-safe
      default -- see CfgGatewayTest.php),
    When the DNSBL page is POST-saved with BOTH selects set to a non-default value,
    Then config.xml holds the CANONICAL token for both keys; AND the DNSBL page,
      navigated fresh in the browser, renders both selects at the matching value; AND a
      second POST restores each field's original value with the same two assertions
      (both directions).
    """
    page = browser_page

    # issue #1947: capture exact presence + raw token so the teardown restores the
    # stored state VERBATIM (an absent key stays absent, never materialised 'honor').
    original_private_state = helpers.config_get_state(smoke_vm, _CFG_FEED_PRIVATE_POLICY)
    original_icann_state = helpers.config_get_state(smoke_vm, _CFG_FEED_ICANN_POLICY)
    original_private = original_private_state[1] if original_private_state[0] else "honor"
    original_icann = original_icann_state[1] if original_icann_state[0] else "honor"
    flipped_private = "apex" if original_private != "apex" else "honor"
    flipped_icann = "ignore" if original_icann != "ignore" else "honor"

    # #2371 matrix row 15: pre-existing legacy keys must survive the saves
    # byte-identically -- capture sentinel states up front.
    legacy_sentinels = {
        path: helpers.config_get_state(smoke_vm, path)
        for path in (
            "installedpackages/pfblockerngdnsblsettings/config/0/tld_wildcard",
            "installedpackages/pfblockerngdnsblsettings/config/0/tld_allow",
            "installedpackages/pfblockerngdnsblsettings/config/0/pfb_psl_include_private",
        )
    }

    try:
        # ---- FLIP: POST both selects to a non-default, DISTINCT value ---- #
        resp = webui.post(
            DNSBL_PAGE,
            {
                "pfb_psl_feed_private_policy": flipped_private,
                "pfb_psl_feed_icann_policy": flipped_icann,
            },
            timeout=_DNSBL_POST_TIMEOUT,
        )
        assert "Sign In" not in resp.text, "feed-suffix-policy flip POST lost the session"

        # Config oracle: both stored tokens must match the flipped selection.
        stored_private_flip = helpers.config_get(smoke_vm, _CFG_FEED_PRIVATE_POLICY)
        assert stored_private_flip == flipped_private, (
            f"pfb_psl_feed_private_policy gateway FAIL after flip: stored {stored_private_flip!r}, "
            f"expected {flipped_private!r}"
        )
        stored_icann_flip = helpers.config_get(smoke_vm, _CFG_FEED_ICANN_POLICY)
        assert stored_icann_flip == flipped_icann, (
            f"pfb_psl_feed_icann_policy gateway FAIL after flip: stored {stored_icann_flip!r}, "
            f"expected {flipped_icann!r}"
        )

        # DOM oracle: reload the DNSBL page and assert both selects show the flipped value.
        _open(page, webui, DNSBL_PAGE)
        sel_private_flip = page.locator("#pfb_psl_feed_private_policy")
        sel_icann_flip = page.locator("#pfb_psl_feed_icann_policy")
        expect(sel_private_flip).to_be_attached(timeout=JS_TIMEOUT_MS)
        expect(sel_icann_flip).to_be_attached(timeout=JS_TIMEOUT_MS)
        expect(sel_private_flip).to_have_value(flipped_private, timeout=JS_TIMEOUT_MS)
        expect(sel_icann_flip).to_have_value(flipped_icann, timeout=JS_TIMEOUT_MS)
        _shot(page, screenshot_dir, "gateway_dnsbl_feed_suffix_policy_after_flip")

        # ---- RESTORE: POST both selects back to their original values ---- #
        resp = webui.post(
            DNSBL_PAGE,
            {
                "pfb_psl_feed_private_policy": original_private,
                "pfb_psl_feed_icann_policy": original_icann,
            },
            timeout=_DNSBL_POST_TIMEOUT,
        )
        assert "Sign In" not in resp.text, "feed-suffix-policy restore POST lost the session"

        # Config oracle: both stored tokens must match the restored (original) selection.
        stored_private_restore = helpers.config_get(smoke_vm, _CFG_FEED_PRIVATE_POLICY)
        assert stored_private_restore == original_private, (
            f"pfb_psl_feed_private_policy gateway FAIL after restore: stored {stored_private_restore!r}, "
            f"expected {original_private!r}"
        )
        stored_icann_restore = helpers.config_get(smoke_vm, _CFG_FEED_ICANN_POLICY)
        assert stored_icann_restore == original_icann, (
            f"pfb_psl_feed_icann_policy gateway FAIL after restore: stored {stored_icann_restore!r}, "
            f"expected {original_icann!r}"
        )

        # DOM oracle: reload and assert both selects show the restored (original) value.
        _open(page, webui, DNSBL_PAGE)
        sel_private_restore = page.locator("#pfb_psl_feed_private_policy")
        sel_icann_restore = page.locator("#pfb_psl_feed_icann_policy")
        expect(sel_private_restore).to_be_attached(timeout=JS_TIMEOUT_MS)
        expect(sel_icann_restore).to_be_attached(timeout=JS_TIMEOUT_MS)
        expect(sel_private_restore).to_have_value(original_private, timeout=JS_TIMEOUT_MS)
        expect(sel_icann_restore).to_have_value(original_icann, timeout=JS_TIMEOUT_MS)
        _shot(page, screenshot_dir, "gateway_dnsbl_feed_suffix_policy_after_restore")

        # Matrix row 15: the legacy sentinel keys are byte-identical after both saves.
        for path, state in legacy_sentinels.items():
            assert helpers.config_get_state(smoke_vm, path) == state, (
                f"legacy key {path} changed across the feed-suffix-policy saves"
            )

    finally:
        # issue #1947: restore the exact captured presence/raw state on any exit --
        # an originally-absent key is deleted again, never left materialised.
        helpers.config_restore_state(smoke_vm, _CFG_FEED_PRIVATE_POLICY, original_private_state)
        helpers.config_restore_state(smoke_vm, _CFG_FEED_ICANN_POLICY, original_icann_state)


# --------------------------------------------------------------------------- #
# PR #660 (ADR-36/37): DNS-Redirect + DoT/DoQ-Block interface quick-fill and
# Exception-Alias autocomplete. Both are browser-only behaviours an HTTP POST
# cannot reach, so they live in the Tier-B browser tier per the CLAUDE.md mandate.
# Each behaviour is mirrored on the two sections, so every test exercises BOTH the
# DNS-Redirect and the DoT/DoQ-Block widget (branch coverage).
# --------------------------------------------------------------------------- #

# IP-settings interface keys feeding the quick-fill union (inbound ∪ outbound) for
# BOTH the DNS-Redirect and DoT/DoQ-Block sections. 'lan' is the canonical non-WAN
# interface on the smoke VM and is in pfb_build_if_list(FALSE, FALSE) (the option
# list), so it survives the array_intersect that builds the fill sets.
_CFG_INBOUND = "installedpackages/pfblockerngipsettings/config/0/inbound_interface"
_CFG_OUTBOUND = "installedpackages/pfblockerngipsettings/config/0/outbound_interface"
_FILL_IFACE = "lan"

# A host (address-type) alias name for the Exception-Alias autocomplete source. Only
# host/network/urltable aliases land in pfb_alias_names, so a 'host' alias must appear.
_AC_ALIAS = "PfbPr660ExcAlias"


def _php_ok(smoke_vm: helpers.SmokeVM, snippet: str, *, timeout: float = 120.0) -> None:
    """Run a config-mutating PHP snippet (must ``echo 'OK'``) and assert it succeeded."""
    result = helpers.php_eval(smoke_vm, snippet, timeout=timeout)
    assert result.returncode == 0 and "OK" in result.stdout, (
        f"php_eval failed: rc={result.returncode}\nstdout={result.stdout!r}\nstderr={result.stderr!r}"
    )


def _selected_values(sel: Locator) -> list[str]:
    """Return the selected <option> values of a <select> locator."""
    return sel.evaluate("el => Array.from(el.selectedOptions).map(o => o.value)")


def _assert_fill_button_populates(
    page: Page,
    *,
    button_id: str,
    fill_var: str,
    select_name: str,
    screenshot_dir: Path,
    shot_prefix: str,
) -> None:
    """Click a "Fill from IP Interfaces" button and assert it sets its multi-select.

    The multi-select is located **by name** (``select[name="<field>[]"]``), NOT by a
    bracket-free ``#id``: a pfSense ``Form_Select`` with multiple=TRUE renders id AND
    name as ``<field>[]``, so ``$('#dnsbl_redir_int')`` matches nothing — which is the
    actual reason the Fill button "did nothing" before this fix. Drives the full
    transition with the before-state asserted (CLAUDE.md): force the select EMPTY
    (deterministic BEFORE), click Fill, assert it now holds exactly the page-computed
    fill set (AFTER), so green proves the click — not pre-existing state — populated it.
    """
    sel = page.locator(f'select[name="{select_name}"]')
    expect(sel).to_be_attached(timeout=JS_TIMEOUT_MS)

    # The page-computed fill set (intersection of the inbound∪outbound union with the
    # option list). Non-empty because the fixture seeded inbound/outbound = lan.
    fill_set = page.evaluate(fill_var)
    assert fill_set, (
        f"{fill_var} is empty — {_FILL_IFACE!r} is not in the option list on this VM, "
        f"so the fill click has nothing to select"
    )
    assert _FILL_IFACE in fill_set, f"expected {_FILL_IFACE!r} in {fill_var}, got {fill_set!r}"

    # BEFORE: force the multi-select empty so a non-empty AFTER proves the click acted.
    sel.evaluate("el => { for (const o of el.options) o.selected = false; }")
    before = _selected_values(sel)
    assert before == [], f"pre-condition: {select_name} should be empty, got {before!r}"
    _shot(page, screenshot_dir, f"{shot_prefix}_before_empty")

    # CLICK Fill -> the select is set to exactly the fill union.
    page.locator(f"#{button_id}").click()
    after = _selected_values(sel)
    assert sorted(after) == sorted(fill_set), (
        f"Fill button #{button_id} did not populate {select_name}: expected {sorted(fill_set)!r}, got {sorted(after)!r}"
    )
    _shot(page, screenshot_dir, f"{shot_prefix}_after_populated")


def _assert_exclude_autocomplete(
    page: Page,
    *,
    field_id: str,
    screenshot_dir: Path,
    shot_prefix: str,
) -> None:
    """Assert an Exception-Alias field has jQuery-UI autocomplete over the seeded alias.

    (a) Widget initialised: jQuery UI stamps the input with the ``ui-autocomplete-input``
    class on ``.autocomplete()`` (the ``aria-autocomplete`` attr is NOT set by the bundled
    jQuery-UI build, so the class is the reliable init marker). (b) Behaviour: typing the
    alias prefix surfaces the seeded alias in the (visible) ``.ui-autocomplete`` menu —
    there is one menu element per initialised field, so it is scoped to the visible one.
    """
    field = page.locator(f"#{field_id}")
    expect(field).to_be_attached(timeout=JS_TIMEOUT_MS)
    expect(field).to_have_class(re.compile(r"\bui-autocomplete-input\b"), timeout=JS_TIMEOUT_MS)

    field.click()
    field.press_sequentially(_AC_ALIAS[:6], delay=20)
    menu = page.locator("ul.ui-autocomplete:visible")
    expect(menu).to_be_visible(timeout=JS_TIMEOUT_MS)
    expect(menu.locator("li", has_text=_AC_ALIAS)).to_have_count(1, timeout=JS_TIMEOUT_MS)
    _shot(page, screenshot_dir, f"{shot_prefix}_menu")

    # Dismiss the menu so it doesn't overlap the next field's search.
    field.press("Escape")


def test_fill_buttons_populate_interface_selects(
    browser_page: Page,
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    screenshot_dir: Path,
) -> None:
    """ "Fill from IP Interfaces" populates BOTH the DNS-Redirect and DoT/DoQ-Block
    interface multi-selects from the Inbound∪Outbound union — the reported "clicking
    Fill did nothing" bug, on both mirrored sections.

    The shared ``pfb_fill_interfaces(selectName, fillSet)`` helper (pfblockerng_dnsbl.php),
    called by both buttons' ``onclick`` with their own select name + fill-set variable, sets
    the multi-select via ``.val(fillSet).trigger('change')``, targeting it **by name**
    (``select[name="…[]"]``) because a pfSense multi-select's id carries the ``[]`` suffix —
    the bracket-free ``#id`` the code used before matched nothing, which is why the button did
    nothing. Seeds inbound/outbound = lan so both fill unions are the non-empty set {lan};
    restores the original interface config in teardown.
    """
    page = browser_page

    original_in = helpers.config_get(smoke_vm, _CFG_INBOUND)
    original_out = helpers.config_get(smoke_vm, _CFG_OUTBOUND)

    try:
        # GIVEN the IP-settings inbound/outbound interfaces both include the LAN, so each
        # section's quick-fill union (read at page render) is the non-empty set {lan}.
        _php_ok(
            smoke_vm,
            f"config_set_path({helpers._php_str(_CFG_INBOUND)}, {helpers._php_str(_FILL_IFACE)});\n"
            f"config_set_path({helpers._php_str(_CFG_OUTBOUND)}, {helpers._php_str(_FILL_IFACE)});\n"
            "write_config('pfBlockerNG smoke: PR660 fill setup');\n"
            "echo 'OK';",
        )

        _open(page, webui, DNSBL_PAGE)
        _expand_section(page, "dnsbl_bypass")

        # DNS Redirect fill.
        _assert_fill_button_populates(
            page,
            button_id="pfb_redir_fill",
            fill_var="pfb_redir_fill_ifaces",
            select_name="dnsbl_redir_int[]",
            screenshot_dir=screenshot_dir,
            shot_prefix="redir_fill",
        )
        # DoT/DoQ Block fill (the mirrored section — same bug, same fix).
        _assert_fill_button_populates(
            page,
            button_id="pfb_dot_block_fill",
            fill_var="pfb_dot_block_fill_ifaces",
            select_name="dnsbl_dot_block_int[]",
            screenshot_dir=screenshot_dir,
            shot_prefix="dot_block_fill",
        )

    finally:
        _php_ok(
            smoke_vm,
            f"config_set_path({helpers._php_str(_CFG_INBOUND)}, {helpers._php_str(original_in)});\n"
            f"config_set_path({helpers._php_str(_CFG_OUTBOUND)}, {helpers._php_str(original_out)});\n"
            "write_config('pfBlockerNG smoke: PR660 fill restore');\n"
            "echo 'OK';",
        )


def test_exception_fields_have_alias_autocomplete(
    browser_page: Page,
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    screenshot_dir: Path,
) -> None:
    """BOTH Exception-Alias fields (``#dnsbl_redir_exclude`` + ``#dnsbl_dot_block_exclude``)
    get jQuery-UI autocomplete sourced from the firewall's address-type alias names — the
    guidance that was missing (bug 2), whose absence let a typo'd alias save and then break
    the whole pf ruleset.

    ``pfb_redir_exclude_autocomplete()`` wires ``.autocomplete({minLength:0,
    source: pfb_alias_names})`` onto both fields. Seed one host alias so the source is
    non-empty, open the page, and assert each field initialised the widget and surfaces
    the alias in its suggestion menu. Removes the seeded alias in teardown.
    """
    page = browser_page

    try:
        # GIVEN a host (address-type) firewall alias exists, so it is in pfb_alias_names.
        _php_ok(
            smoke_vm,
            "$aliases = config_get_path('aliases/alias', array());\n"
            "$aliases[] = array("
            f"'name' => {helpers._php_str(_AC_ALIAS)}, 'type' => 'host', "
            "'address' => '192.0.2.10', 'detail' => 'PR660 smoke', "
            "'descr' => 'pfBlockerNG PR660 autocomplete smoke');\n"
            "config_set_path('aliases/alias', $aliases);\n"
            "write_config('pfBlockerNG smoke: PR660 autocomplete alias');\n"
            "echo 'OK';",
        )

        _open(page, webui, DNSBL_PAGE)
        _expand_section(page, "dnsbl_bypass")

        # The alias name must have reached the page's JS source array.
        alias_names = page.evaluate("pfb_alias_names")
        assert _AC_ALIAS in alias_names, f"seeded alias {_AC_ALIAS!r} not in pfb_alias_names: {alias_names!r}"

        # DNS Redirect exception field, then the mirrored DoT/DoQ Block exception field.
        _assert_exclude_autocomplete(
            page,
            field_id="dnsbl_redir_exclude",
            screenshot_dir=screenshot_dir,
            shot_prefix="redir_exclude_autocomplete",
        )
        _assert_exclude_autocomplete(
            page,
            field_id="dnsbl_dot_block_exclude",
            screenshot_dir=screenshot_dir,
            shot_prefix="dot_block_exclude_autocomplete",
        )

    finally:
        _php_ok(
            smoke_vm,
            "$aliases = config_get_path('aliases/alias', array());\n"
            "$aliases = array_values(array_filter($aliases, function($a) {\n"
            f"  return ($a['name'] ?? '') !== {helpers._php_str(_AC_ALIAS)};\n"
            "}));\n"
            "config_set_path('aliases/alias', $aliases);\n"
            "write_config('pfBlockerNG smoke: PR660 autocomplete cleanup');\n"
            "echo 'OK';",
        )


# A token string carrying the shapes a hostile paste would use -- an apostrophe, a double
# quote, a shell/JS-interpolation sigil and enough length to rule out a truncating clear --
# so the ``.val('')`` clear is proven against more than a tidy alphanumeric literal.
_TYPED_TOKEN = "pfb'\"${IFS}<token>" + "z" * 256


def test_top1m_token_hidden_and_cleared_for_keyless_providers(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    """``enable_top1m_token()`` HIDES the API Token field for keyless TOP1M types.

    issue #3060: the handler used ``disableInput()``, which greys the field but
    leaves it permanently visible -- dead UI on every install, since the default
    type (Tranco) is keyless. ``cloudflare`` is the only provider whose ``auth``
    descriptor is non-``none`` (``pfblockerng_extra.inc``'s ``pfb_top1m_providers()``).

    The clear is part of the contract, not decoration. A hidden input still POSTs,
    and so does a disabled one on this page -- the submit handler re-enables every
    id in ``pfb_gated_ids`` before submit -- while ``pfblockerng_dnsbl.php``'s save
    path writes any NON-EMPTY ``top1m_token`` to config. So without the clear,
    typing a token and then switching to a keyless provider overwrites the stored
    token and flips the token half of ``$pfb_top1m_identity_changed``, invalidating
    the TOP1M baseline. ADR-59 keeps the field blank on GET, so a value can only
    have been typed this page load.

    The TOP1M section is ``COLLAPSIBLE|SEC_CLOSED``, so it is expanded first --
    otherwise the field is already invisible and ``to_be_hidden()`` would pass for
    the wrong reason. Before-state asserted, then both directions.
    """
    page = browser_page
    _open(page, webui, DNSBL_PAGE)
    _expand_section(page, "TOP1M_Whitelist")

    source = page.locator("#top1m_source")
    token = page.locator("#top1m_token")
    expect(source).to_be_attached(timeout=JS_TIMEOUT_MS)
    expect(token).to_be_attached(timeout=JS_TIMEOUT_MS)

    # BEFORE: the one keyed provider shows the field.
    source.select_option("cloudflare")
    page.evaluate("$('#top1m_source').trigger('change')")
    expect(token).to_be_visible(timeout=JS_TIMEOUT_MS)
    _shot(page, screenshot_dir, "dnsbl_top1m_token_visible_cloudflare")

    # A value typed while the field applied ...
    token.fill(_TYPED_TOKEN)
    expect(token).to_have_value(_TYPED_TOKEN, timeout=JS_TIMEOUT_MS)

    # ... must be hidden AND cleared on the switch to a keyless provider.
    source.select_option("tranco")
    page.evaluate("$('#top1m_source').trigger('change')")
    expect(token).to_be_hidden(timeout=JS_TIMEOUT_MS)
    expect(token).to_have_value("", timeout=JS_TIMEOUT_MS)
    _shot(page, screenshot_dir, "dnsbl_top1m_token_hidden_tranco")

    # Both directions: back to the keyed provider re-shows it, still blank.
    source.select_option("cloudflare")
    page.evaluate("$('#top1m_source').trigger('change')")
    expect(token).to_be_visible(timeout=JS_TIMEOUT_MS)
    expect(token).to_have_value("", timeout=JS_TIMEOUT_MS)
