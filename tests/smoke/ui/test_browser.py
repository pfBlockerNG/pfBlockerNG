"""Tier-B browser tests (ADR-14 Phase 4): headless Chromium drives the JS-only UX.

These exercise the pfBlockerNG client-side behaviours that an HTTP POST cannot
reach -- the field enable/disable toggles, jQuery-UI autocomplete, the
``pfb_chg_state_bkgd`` greying, and the dashboard-widget render -- against the
LIVE webConfigurator on the ADR-04 smoke VM, reusing the Phase-1 authenticated
session (the ``PHPSESSID`` cookie injected into the browser context by the
``browser_context`` fixture, so the browser never logs in a second time).

The JS under test is READ-ONLY reference (no ``src/`` change); the exact
selectors/behaviours are taken from ``src/usr/local/www/pfblockerng/pfBlockerNG.js``
and ``src/usr/local/www/widgets/javascript/pfblockerng.js``:

* ``enable_change_in()`` (pfBlockerNG.js:222-231, called on load + on the
  ``#autoaddr_in`` ``click``): when ``#autoaddr_in`` is UNCHECKED, its targets
  ``#aliasaddr_in`` and ``#autonot_in`` are ``disabled``; checking it ENABLES
  them. The advanced IP editor (``pfblockerng_category_edit.php?type=ipv4``)
  renders these unconditionally (the "Advanced Inbound/Outbound Firewall Rule
  Settings" sections), default ``autoaddr_in`` unchecked -> targets start
  disabled. This is the headline JS UX and a clean before->after transition.
* the jQuery-UI autocomplete bound to ``#aliasports_in`` (pfBlockerNG.js:253-255,
  ``source: portsarray``): focusing the field and typing surfaces a
  ``.ui-autocomplete`` menu in the DOM.
* ``pfb_chg_state_bkgd()`` (pfBlockerNG.js:124-138): a ``select[id^='state-']``
  whose value is ``Disabled`` is greyed (``background-color: lightgrey``) on
  load; selecting a non-``Disabled`` value and clicking the select clears it.
* the dashboard widget (``widgets/widgets/pfblockerng.widget.php`` +
  ``widgets/javascript/pfblockerng.js``): the widget renders ``#pfblockerngack``,
  ``#formicons``, ``.PFBSTATUS`` and the ``#pfBNG-table`` body.

NO fixed sleeps: every assertion uses Playwright's auto-waiting
(``expect(...).to_be_disabled()`` / ``to_be_enabled()`` / ``to_be_visible()``,
``wait_for_selector``, ``wait_for_load_state("networkidle")``).

Per-page full-page screenshots are written to the ``screenshot_dir`` artifact
tree for human review (ADR §2 "Screenshots (A1)" -- artifacts, NOT asserted
pixel baselines).

§7 RELIABILITY/BUDGET (the ADR-01-analog kill gate) is MEASURED in CI, not here:
this dev box has no live VM and cannot run repeated browser legs. The procedure,
the measured numbers, and the keep/demote/drop decision are recorded in
``.ADRs/ADR_14_UI_UX_Testing/RESULTS/04_Results.txt``. The tier is daily/on-demand
and NEVER a PR gate (marker ``ui_browser``, off default collection), so it cannot
block fast iteration regardless of the §7 outcome.

Playwright is imported lazily via ``pytest.importorskip`` (in ``conftest`` and
here) so importing/collecting this module does not hard-error when Playwright is
absent.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from .conftest import mask_page_identity

# Tier-B dep: guard the import so collecting this module without Playwright
# installed (this dev venv, or any host that skips the browser tier) does not
# hard-error. Everything below references `expect` from the imported module.
sync_api = pytest.importorskip("playwright.sync_api", reason="playwright not installed (Tier-B browser dep)")
expect = sync_api.expect

if TYPE_CHECKING:
    from playwright.sync_api import Page

    from .webui import WebUI

pytestmark = pytest.mark.ui_browser

# The advanced IP editor renders the JS-driven toggles + autocomplete + state
# selects unconditionally (gtype ipv4 -> the Advanced In/Out sections + a
# placeholder source row). No saved config needed -- a fresh box serves it.
ADVANCED_IP_EDITOR = "/pfblockerng/pfblockerng_category_edit.php?type=ipv4"
# The dashboard widget renders standalone (auth-gated, $nocsrf) with its hidden
# ack input + status icons + table body.
WIDGET_PAGE = "/widgets/widgets/pfblockerng.widget.php"
# The DNSBL settings page hosts the ADR-13 "Create VIPs automatically" checkbox
# (#pfb_dnsvip_auto) whose click handler (enable_dnsvip_auto) disables the manual
# VIP dropdowns (#pfb_dnsvip4/#pfb_dnsvip6).
DNSBL_PAGE = "/pfblockerng/pfblockerng_dnsbl.php"
# The ADR-12 Update Hooks page: a `.repeatable` hook-row list (pfSense's
# client-side row helper) with an Add button (#addrow) and per-row fields
# (hook_command-<id>, ...).
HOOKS_PAGE = "/pfblockerng/pfblockerng_hooks.php"

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


def test_enable_change_toggle_disables_then_enables_target(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    """`#autoaddr_in` toggle gates `#aliasaddr_in`/`#autonot_in` disabled-state.

    Before->after transition (CLAUDE.md): with the checkbox UNCHECKED (default)
    the targets start DISABLED (``enable_change_in()`` ran on load); checking it
    ENABLES them; unchecking re-DISABLES them -- exercising BOTH branches of the
    toggle, not just the on side.
    """
    page = browser_page
    _open(page, webui, ADVANCED_IP_EDITOR)

    toggle = page.locator("#autoaddr_in")
    addr = page.locator("#aliasaddr_in")
    invert = page.locator("#autonot_in")

    # The elements live in a COLLAPSIBLE|SEC_CLOSED panel: present in the DOM but
    # the panel body may be collapsed. attached() (not visible()) is the right
    # wait -- disabled-state is a property, observable while collapsed.
    expect(toggle).to_be_attached(timeout=JS_TIMEOUT_MS)
    expect(addr).to_be_attached(timeout=JS_TIMEOUT_MS)
    expect(invert).to_be_attached(timeout=JS_TIMEOUT_MS)

    # BEFORE: checkbox unchecked -> enable_change_in() left the targets disabled.
    expect(toggle).not_to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(addr).to_be_disabled(timeout=JS_TIMEOUT_MS)
    expect(invert).to_be_disabled(timeout=JS_TIMEOUT_MS)
    _shot(page, screenshot_dir, "toggle_before_disabled")

    # FLIP ON: drive the element's native click(). This flips .checked AND fires
    # the jQuery click handler bound at pfBlockerNG.js:240-242 -> enable_change_in()
    # enables the targets (`enable_change_in` is a closure-local, reachable only
    # through the real click binding -- so we must click the actual control, not
    # set .checked). The checkbox sits in a Bootstrap panel that is collapsed
    # (display:none -> zero-size), which defeats even Playwright `click(force=True)`
    # ("Element is not visible" -- force can't click a zero-size box). The DOM
    # `el.click()` needs no geometry/visibility, toggles the box, and fires the
    # bound handler, so it is the robust driver here.
    toggle.evaluate("el => el.click()")
    expect(toggle).to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(addr).to_be_enabled(timeout=JS_TIMEOUT_MS)
    expect(invert).to_be_enabled(timeout=JS_TIMEOUT_MS)
    _shot(page, screenshot_dir, "toggle_after_enabled")

    # FLIP BACK OFF: re-click -> re-disabled -- proves it is a real two-way branch.
    toggle.evaluate("el => el.click()")
    expect(toggle).not_to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(addr).to_be_disabled(timeout=JS_TIMEOUT_MS)
    expect(invert).to_be_disabled(timeout=JS_TIMEOUT_MS)


def test_ports_autocomplete_bound_and_menu_opens(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    """`#aliasports_in` is jQuery-UI-autocomplete-bound; searching opens a menu.

    The autocomplete is bound to ``#aliasports_in`` with ``source: portsarray``
    (pfBlockerNG.js:253-255). The PRIMARY, deterministic assertion is that the
    widget INSTANCE exists on the element (the binding ran) -- a fresh box has no
    port aliases, so ``portsarray`` may be empty and a search of the real source
    yields nothing. To still SHOW a populated menu (proving the widget renders),
    a deterministic source is set on the bound widget and searched; the
    ``.ui-autocomplete`` menu then materialises with the supplied items. Before:
    no menu visible; after the search: a menu with our items. No fixed sleep.
    """
    page = browser_page
    _open(page, webui, ADVANCED_IP_EDITOR)

    field = page.locator("#aliasports_in")
    expect(field).to_be_attached(timeout=JS_TIMEOUT_MS)

    # PRIMARY: the autocomplete widget instance is attached (the binding ran).
    bound = page.evaluate(
        "(function(){var $=window.jQuery;return !!($ && $('#aliasports_in').length"
        " && $('#aliasports_in').data('ui-autocomplete'));})()"
    )
    assert bound is True, "#aliasports_in has no jQuery-UI autocomplete instance -- the JS binding did not run"

    # BEFORE: no autocomplete menu is open.
    menu = page.locator("ul.ui-autocomplete")
    assert menu.count() == 0 or not menu.first.is_visible(), "autocomplete menu unexpectedly open before input"

    # AFTER: feed the bound widget a deterministic source (independent of the
    # box's port aliases) and search -> the menu renders our items. The field may
    # be disabled (gated by #autoports_in) and in a collapsed panel; enable it so
    # jQuery-UI will open the menu.
    page.evaluate(
        "(function(){var $=window.jQuery;var f=document.getElementById('aliasports_in');"
        "f.disabled=false;var w=$('#aliasports_in');"
        "w.autocomplete('option','source',['pfb_probe_a','pfb_probe_b']);"
        "f.focus();w.autocomplete('search','pfb_probe');})()"
    )
    expect(page.locator("ul.ui-autocomplete li").first).to_be_visible(timeout=JS_TIMEOUT_MS)
    _shot(page, screenshot_dir, "autocomplete_ports_menu")


def test_state_select_greyed_when_disabled(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    """`pfb_chg_state_bkgd()` greys a `Disabled` `state-*` select; clears otherwise.

    Before: the placeholder source row's ``#state-0`` defaults to ``Disabled``,
    so the on-load ``.each()`` pass greyed it (inline ``background-color`` ==
    ``lightgrey``). After: select a non-``Disabled`` value and fire the bound
    ``click`` handler -> the grey is cleared. Both branches of the greying
    condition are exercised.
    """
    page = browser_page
    _open(page, webui, ADVANCED_IP_EDITOR)

    state = page.locator("#state-0")
    expect(state).to_be_attached(timeout=JS_TIMEOUT_MS)
    expect(state).to_have_value("Disabled", timeout=JS_TIMEOUT_MS)

    # BEFORE: on-load greying of a Disabled select.
    def bg() -> str:
        return page.evaluate("document.getElementById('state-0').style.backgroundColor")

    expect(state).to_have_css("background-color", "rgb(211, 211, 211)", timeout=JS_TIMEOUT_MS)
    assert "grey" in bg().lower() or bg() == "lightgrey", f"expected lightgrey inline bg, got {bg()!r}"
    _shot(page, screenshot_dir, "state_disabled_grey")

    # AFTER: switch to Enabled and fire the bound click handler -> grey cleared.
    state.select_option("Enabled")
    state.dispatch_event("click")
    expect(state).not_to_have_css("background-color", "rgb(211, 211, 211)", timeout=JS_TIMEOUT_MS)
    assert bg() in ("", "rgba(0, 0, 0, 0)"), f"expected cleared inline bg after Enabled, got {bg()!r}"


def test_dashboard_widget_renders(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    """The pfBlockerNG dashboard widget renders its JS-target DOM.

    Asserts the widget served the hidden ack input (``#pfblockerngack``), its
    icon form (``#formicons``), the status icon (``.PFBSTATUS``) and the
    AJAX-refreshed table body (``#pfBNG-table``) -- the elements the widget JS
    (``widgets/javascript/pfblockerng.js``) drives. A render screenshot is
    captured for human review.
    """
    page = browser_page
    _open(page, webui, WIDGET_PAGE)

    expect(page.locator("#pfblockerngack")).to_be_attached(timeout=JS_TIMEOUT_MS)
    expect(page.locator("#formicons")).to_be_attached(timeout=JS_TIMEOUT_MS)
    expect(page.locator("#pfBNG-table")).to_be_attached(timeout=JS_TIMEOUT_MS)
    expect(page.locator(".PFBSTATUS").first).to_be_attached(timeout=JS_TIMEOUT_MS)
    _shot(page, screenshot_dir, "dashboard_widget")


def test_dnsvip_auto_checkbox_disables_manual_dropdowns(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    """ADR-13: ticking 'Create VIPs automatically' disables the manual VIP dropdowns.

    `#pfb_dnsvip_auto`'s click handler (enable_dnsvip_auto, pfblockerng_dnsbl.php)
    disables `#pfb_dnsvip4`/`#pfb_dnsvip6` when checked and re-enables them when
    unchecked. Branch coverage with the before-state asserted (CLAUDE.md): start
    unchecked -> dropdowns ENABLED, check -> DISABLED, uncheck -> ENABLED again.
    Drive the native el.click() (it fires the bound jQuery handler regardless of
    the checkbox's panel visibility -- see the enable_change toggle test).
    """
    page = browser_page
    _open(page, webui, DNSBL_PAGE)

    auto = page.locator("#pfb_dnsvip_auto")
    v4 = page.locator("#pfb_dnsvip4")
    v6 = page.locator("#pfb_dnsvip6")
    expect(auto).to_be_attached(timeout=JS_TIMEOUT_MS)
    expect(v4).to_be_attached(timeout=JS_TIMEOUT_MS)

    # Normalize to a known start (unchecked) so the before-state is deterministic
    # regardless of the saved pfb_dnsvip_auto config the page rendered with.
    if auto.is_checked():
        auto.evaluate("el => el.click()")
        expect(auto).not_to_be_checked(timeout=JS_TIMEOUT_MS)

    # BEFORE: auto off -> the manual dropdowns are enabled.
    expect(v4).to_be_enabled(timeout=JS_TIMEOUT_MS)
    expect(v6).to_be_enabled(timeout=JS_TIMEOUT_MS)
    _shot(page, screenshot_dir, "dnsvip_auto_before_off")

    # CHECK -> the handler disables both manual dropdowns.
    auto.evaluate("el => el.click()")
    expect(auto).to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(v4).to_be_disabled(timeout=JS_TIMEOUT_MS)
    expect(v6).to_be_disabled(timeout=JS_TIMEOUT_MS)
    _shot(page, screenshot_dir, "dnsvip_auto_after_on")

    # UNCHECK -> re-enabled (proves it is a real two-way branch).
    auto.evaluate("el => el.click()")
    expect(auto).not_to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(v4).to_be_enabled(timeout=JS_TIMEOUT_MS)
    expect(v6).to_be_enabled(timeout=JS_TIMEOUT_MS)


def test_update_hooks_section_renders_and_adds_a_row(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    """ADR-12 Update Hooks page renders, and the repeatable-row Add control adds a row.

    Screenshots the section, asserts its key controls render, then clicks Add
    (pfSense's client-side `.repeatable` row helper) and asserts a new hook row
    appears. Each row carries exactly one ``hook_command-<id>`` input, so the count
    of those inputs is the row count (before+after is the transition). The Add /
    Delete buttons skip server validation, so this never persists or errors.
    """
    page = browser_page
    _open(page, webui, HOOKS_PAGE)

    # Render assertions: the section + the Add button + at least one hook row.
    expect(page.get_by_text("Hook Entries").first).to_be_visible(timeout=JS_TIMEOUT_MS)
    add_btn = page.locator("#addrow")
    expect(add_btn).to_be_visible(timeout=JS_TIMEOUT_MS)
    rows = page.locator('input[name^="hook_command-"]')
    expect(rows.first).to_be_attached(timeout=JS_TIMEOUT_MS)
    _shot(page, screenshot_dir, "update_hooks")

    # BEFORE -> exercise the client-side row clone -> AFTER (one more row).
    before = rows.count()
    add_btn.click()
    expect(page.locator('input[name^="hook_command-"]')).to_have_count(before + 1, timeout=JS_TIMEOUT_MS)
    _shot(page, screenshot_dir, "update_hooks_added")
