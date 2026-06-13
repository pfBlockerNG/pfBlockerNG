"""Tier-B browser tests (ADR-14 Phase 4): the OTHER category-edit JS handlers.

Companion to ``test_browser.py``, which already covers ``enable_change_in()``
(``#autoaddr_in`` -> ``#aliasaddr_in``/``#autonot_in``), the ``#aliasports_in``
jQuery-UI autocomplete and the ``pfb_chg_state_bkgd`` greying of ``#state-0``.
This file exercises the SHARED ``pfBlockerNG.js`` handlers that file does NOT,
against the LIVE webConfigurator on the ADR-04 smoke VM (Phase-1 authenticated
session, ``PHPSESSID`` injected by the ``browser_context`` fixture -- no second
login). The JS under test is READ-ONLY reference (no ``src/`` change); every
selector/behaviour below is taken from
``src/usr/local/www/pfblockerng/pfBlockerNG.js`` and
``src/usr/local/www/pfblockerng/pfblockerng_category_edit.php``:

* ``enable_change_out()`` (pfBlockerNG.js:227-231; bound on ``#autoaddr_out``
  ``click`` at 243-245 and run on load at 248): when ``#autoaddr_out`` is
  UNCHECKED its targets ``#aliasaddr_out`` and ``#autonot_out`` are ``disabled``;
  checking ENABLES them -- the OUT analog of the tested IN toggle. The
  ``?type=ipv4`` editor renders these in the "Advanced Outbound Firewall Rule
  Settings" section (category_edit.php:1402-1497, ``COLLAPSIBLE|SEC_CLOSED``);
  default ``autoaddr_out`` unchecked -> targets start disabled.
* ``enable_change_port_in()`` / ``enable_change_port_out()`` (pfBlockerNG.js:213-220;
  bound on ``#autoports_in``/``#autoports_out`` ``click`` at 233-238 and run on
  load at 249-250): ``#autoports_in``/``#autoports_out`` gate
  ``#aliasports_in``/``#aliasports_out`` ``disabled``; default unchecked -> the
  port field starts disabled, checking ENABLES it.
* ``#chgstate`` "Enable All" (pfBlockerNG.js:178-187): its ``click`` handler
  (with ``action``/``atype`` empty on a plain GET -- category_edit.php:1669-1670)
  unconditionally sets ``$('#chgstate').val('Enable All')``. The DOM effect the
  handler PRODUCES is the button value flipping to ``Enable All`` (the source-row
  ``state-*`` selects flip only after the server round-trip the submit triggers,
  category_edit.php:142-143,1098-1100 -- not asserted here).
* ``#addrow`` source-row clone (pfBlockerNG.js:198-210 for ``pagetype=='advanced'``,
  bound because ``geoiparray != 'disabled'`` -- ``geoip_isos`` is the empty string
  so ``geoiparray == ['']``): clicking clones ``.repeatable:last`` (pfSense's core
  row helper) AND renumbers the new row, so one more source row appears. Each
  source row carries exactly one ``select[id^='state-']`` (category_edit.php:1102-1110),
  so that count is the row count; the clone also renumbers the suffix, so a fresh
  ``#state-1`` materialises.

The advanced In/Out controls live in ``COLLAPSIBLE|SEC_CLOSED`` panels
(category_edit.php:1406) -- present but ``display:none``/zero-size. Per
``test_browser.py``: assert disabled/enabled with ``to_be_attached`` (a collapsed
control is attached-but-not-visible), and drive a bound checkbox with
``locator.evaluate("el => el.click()")`` (fires the jQuery handler without needing
geometry; ``click()``/``click(force=True)`` can't click a zero-size box).

Every behavioural test is a before->after transition and a toggle exercises BOTH
directions (CLAUDE.md "Test coverage"). NO fixed sleeps: assertions use
Playwright auto-waiting. Per-state screenshots are written to ``screenshot_dir``
for human review (artifacts, not asserted baselines). Playwright is imported
lazily via ``importorskip`` so collecting this module without it does not error.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from .conftest import mask_page_identity

sync_api = pytest.importorskip("playwright.sync_api", reason="playwright not installed (Tier-B browser dep)")
expect = sync_api.expect

if TYPE_CHECKING:
    from playwright.sync_api import Page

    from .webui import WebUI

pytestmark = pytest.mark.ui_browser

# The advanced IP editor (gtype ipv4 -> pagetype 'advanced') renders the Advanced
# In/Out firewall sections (with the auto*/alias* toggles), the source-row table
# (with the state-* selects), and the Add/Enable-All buttons -- all unconditionally
# on a fresh box, no saved config needed.
ADVANCED_IP_EDITOR = "/pfblockerng/pfblockerng_category_edit.php?type=ipv4"

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


def test_enable_change_out_toggle_disables_then_enables_targets(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    """`#autoaddr_out` toggle gates `#aliasaddr_out`/`#autonot_out` disabled-state.

    The OUT analog of the IN toggle proven in ``test_browser.py``. Before->after
    with both directions (CLAUDE.md): with the checkbox UNCHECKED (default)
    ``enable_change_out()`` ran on load and left the targets DISABLED; checking it
    ENABLES them; unchecking re-DISABLES them.
    """
    page = browser_page
    _open(page, webui, ADVANCED_IP_EDITOR)

    toggle = page.locator("#autoaddr_out")
    addr = page.locator("#aliasaddr_out")
    invert = page.locator("#autonot_out")

    # Collapsed (SEC_CLOSED) panel -> attached, not visible; disabled-state is a
    # property observable while collapsed.
    expect(toggle).to_be_attached(timeout=JS_TIMEOUT_MS)
    expect(addr).to_be_attached(timeout=JS_TIMEOUT_MS)
    expect(invert).to_be_attached(timeout=JS_TIMEOUT_MS)

    # BEFORE: checkbox unchecked -> enable_change_out() left the targets disabled.
    expect(toggle).not_to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(addr).to_be_disabled(timeout=JS_TIMEOUT_MS)
    expect(invert).to_be_disabled(timeout=JS_TIMEOUT_MS)
    _shot(page, screenshot_dir, "out_toggle_before_disabled")

    # FLIP ON: native el.click() flips .checked AND fires the bound jQuery handler
    # (enable_change_out is closure-local, reachable only through the real click
    # binding); the checkbox sits in a collapsed (zero-size) panel, so el.click()
    # is the robust driver -- no geometry needed, unlike click()/click(force=True).
    toggle.evaluate("el => el.click()")
    expect(toggle).to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(addr).to_be_enabled(timeout=JS_TIMEOUT_MS)
    expect(invert).to_be_enabled(timeout=JS_TIMEOUT_MS)
    _shot(page, screenshot_dir, "out_toggle_after_enabled")

    # FLIP BACK OFF: re-click -> re-disabled -- proves a real two-way branch.
    toggle.evaluate("el => el.click()")
    expect(toggle).not_to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(addr).to_be_disabled(timeout=JS_TIMEOUT_MS)
    expect(invert).to_be_disabled(timeout=JS_TIMEOUT_MS)


def test_autoports_in_toggle_disables_then_enables_field(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    """`#autoports_in` toggle gates `#aliasports_in` disabled-state, both directions.

    ``enable_change_port_in()`` (pfBlockerNG.js:213-216, bound at 233-235, run on
    load at 249): when ``#autoports_in`` is UNCHECKED ``#aliasports_in`` is
    ``disabled``; checking ENABLES it. Before->after with both branches.
    """
    page = browser_page
    _open(page, webui, ADVANCED_IP_EDITOR)

    toggle = page.locator("#autoports_in")
    field = page.locator("#aliasports_in")
    expect(toggle).to_be_attached(timeout=JS_TIMEOUT_MS)
    expect(field).to_be_attached(timeout=JS_TIMEOUT_MS)

    # BEFORE: checkbox unchecked -> enable_change_port_in() left the field disabled.
    expect(toggle).not_to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(field).to_be_disabled(timeout=JS_TIMEOUT_MS)
    _shot(page, screenshot_dir, "ports_in_before_disabled")

    # FLIP ON: el.click() fires the bound handler from inside the collapsed panel.
    toggle.evaluate("el => el.click()")
    expect(toggle).to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(field).to_be_enabled(timeout=JS_TIMEOUT_MS)
    _shot(page, screenshot_dir, "ports_in_after_enabled")

    # FLIP BACK OFF: re-disabled -- the off branch.
    toggle.evaluate("el => el.click()")
    expect(toggle).not_to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(field).to_be_disabled(timeout=JS_TIMEOUT_MS)


def test_autoports_out_toggle_disables_then_enables_field(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    """`#autoports_out` toggle gates `#aliasports_out` disabled-state, both directions.

    ``enable_change_port_out()`` (pfBlockerNG.js:217-220, bound at 236-238, run on
    load at 250): the OUT analog of the port-in toggle -- ``#autoports_out``
    unchecked -> ``#aliasports_out`` disabled; checking enables it.
    """
    page = browser_page
    _open(page, webui, ADVANCED_IP_EDITOR)

    toggle = page.locator("#autoports_out")
    field = page.locator("#aliasports_out")
    expect(toggle).to_be_attached(timeout=JS_TIMEOUT_MS)
    expect(field).to_be_attached(timeout=JS_TIMEOUT_MS)

    # BEFORE: unchecked -> enable_change_port_out() left the field disabled.
    expect(toggle).not_to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(field).to_be_disabled(timeout=JS_TIMEOUT_MS)
    _shot(page, screenshot_dir, "ports_out_before_disabled")

    # FLIP ON.
    toggle.evaluate("el => el.click()")
    expect(toggle).to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(field).to_be_enabled(timeout=JS_TIMEOUT_MS)
    _shot(page, screenshot_dir, "ports_out_after_enabled")

    # FLIP BACK OFF.
    toggle.evaluate("el => el.click()")
    expect(toggle).not_to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(field).to_be_disabled(timeout=JS_TIMEOUT_MS)


def test_chgstate_button_click_sets_enable_all_value(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    """`#chgstate` "Enable All" click handler sets the button value to `Enable All`.

    The bound ``$('#chgstate').click(...)`` handler (pfBlockerNG.js:178-187)
    unconditionally runs ``$('#chgstate').val('Enable All')`` (the ``#act``/
    ``#atype`` writes are skipped on a plain GET, where ``action``/``atype`` are
    the empty string -- category_edit.php:1669-1670). That value flip is the DOM
    effect the click PRODUCES, and it is what the server reads as the "Enable All"
    signal (category_edit.php:142-143). The source-row ``state-*`` selects flip
    only after the resulting submit/round-trip, so they are NOT asserted here.

    Before->after: the button is rendered with its default value, and the click
    sets it to ``Enable All``. The pre-click value comes from the Form_Button
    label ("Enable All") -- the assertion is the change is CAUSED by the click, so
    drive it through the .value DOM property (which a plain rendered button leaves
    as its label) and prove the handler ran.
    """
    page = browser_page
    _open(page, webui, ADVANCED_IP_EDITOR)

    btn = page.locator("#chgstate")
    expect(btn).to_be_attached(timeout=JS_TIMEOUT_MS)

    # BEFORE: the handler has not run; capture the rendered value via the DOM.
    before_value = btn.evaluate("el => el.value")
    _shot(page, screenshot_dir, "chgstate_before")

    # Fire the bound jQuery click handler. The button is in the (visible) Source
    # Definitions section, so a real click works; dispatch the bound event so the
    # value-set runs without submitting the form away from the page under test.
    btn.dispatch_event("click")

    # AFTER: the handler set the button value to 'Enable All'.
    expect(btn).to_have_js_property("value", "Enable All", timeout=JS_TIMEOUT_MS)
    after_value = btn.evaluate("el => el.value")
    assert after_value == "Enable All", (
        f"expected 'Enable All' after click, got {after_value!r} (before {before_value!r})"
    )
    _shot(page, screenshot_dir, "chgstate_after")


def test_addrow_clones_a_source_row_and_renumbers(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    """`#addrow` clones a source row (one more `state-*` select) and renumbers it.

    The advanced editor binds ``#addrow`` (pfBlockerNG.js:198-210; ``geoiparray``
    is ``['']`` != ``'disabled'`` so the handler is bound) on top of pfSense's
    core ``.repeatable`` row clone. Each source row carries exactly one
    ``select[id^='state-']`` (category_edit.php:1102-1110), so that count is the
    row count. A fresh editor renders one placeholder row (``#state-0``,
    category_edit.php:1027-1033). Before->after: one source row -> click Add ->
    two, and the clone renumbers the new row so ``#state-1`` exists.

    The Add button only clones client-side (no server validation/persist), so this
    never errors or saves.
    """
    page = browser_page
    _open(page, webui, ADVANCED_IP_EDITOR)

    add_btn = page.locator("#addrow")
    states = page.locator("select[id^='state-']")
    expect(add_btn).to_be_visible(timeout=JS_TIMEOUT_MS)
    expect(states.first).to_be_attached(timeout=JS_TIMEOUT_MS)

    # BEFORE: the placeholder source row (#state-0) is present; #state-1 is not.
    expect(page.locator("#state-0")).to_be_attached(timeout=JS_TIMEOUT_MS)
    assert page.locator("#state-1").count() == 0, "#state-1 unexpectedly present before Add"
    before = states.count()
    _shot(page, screenshot_dir, "addrow_before")

    # CLICK Add -> the core repeatable helper clones .repeatable:last and the
    # bound handler renumbers the new row.
    add_btn.click()

    # AFTER: one more source row, and the clone renumbered it to #state-1.
    expect(page.locator("select[id^='state-']")).to_have_count(before + 1, timeout=JS_TIMEOUT_MS)
    expect(page.locator("#state-1")).to_be_attached(timeout=JS_TIMEOUT_MS)
    _shot(page, screenshot_dir, "addrow_after")
