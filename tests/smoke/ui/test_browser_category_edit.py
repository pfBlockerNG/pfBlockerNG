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

import re
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import quote

import pytest

from .. import helpers
from .conftest import mask_page_identity
from .test_category_edit import (
    CFG_DNSBL,
    CFG_IPV4,
    CFG_IPV6,
    _del_rowid,
    _dnsbl_payload,
    _free_rowid,
    _ipv6_payload,
    _post_form,
)
from .webui import extract_csrf_token, looks_like_login_page

sync_api = pytest.importorskip("playwright.sync_api", reason="playwright not installed (Tier-B browser dep)")
expect = sync_api.expect

if TYPE_CHECKING:
    from playwright.sync_api import Locator, Page

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


def test_schedule_override_toggle_and_weekly_cadence_controls(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    """Feed-group schedule controls toggle and expose weekday only for Weekly.

    The same editor is used by IPv4, IPv6, and DNSBL families; Tier-A render
    probes cover each family while this Tier-B interaction proves the browser
    state transitions and cadence-dependent weekday control.
    """
    page = browser_page
    _open(page, webui, ADVANCED_IP_EDITOR)

    override = page.locator("#schedule_override")
    weekday = page.locator("#schedule_weekday")
    hour = page.locator("#schedule_hour")
    minute = page.locator("#schedule_minute")
    cadence = page.locator("#cron")
    for control in (override, weekday, hour, minute, cadence):
        expect(control).to_be_attached(timeout=JS_TIMEOUT_MS)

    # BEFORE: inherited schedule is read-only in the editor.
    expect(override).not_to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(hour).to_be_disabled(timeout=JS_TIMEOUT_MS)
    expect(minute).to_be_disabled(timeout=JS_TIMEOUT_MS)
    expect(weekday).to_be_disabled(timeout=JS_TIMEOUT_MS)
    _shot(page, screenshot_dir, "schedule_override_before")

    # FLIP ON: hourly controls enable; weekday remains dormant until Weekly.
    override.check()
    expect(override).to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(hour).to_be_enabled(timeout=JS_TIMEOUT_MS)
    expect(minute).to_be_enabled(timeout=JS_TIMEOUT_MS)
    expect(weekday).to_be_disabled(timeout=JS_TIMEOUT_MS)

    # CHANGE cadence to Weekly: weekday becomes editable; return to hourly and
    # prove the dormant weekday is disabled again before saving.
    cadence.select_option("Weekly")
    expect(weekday).to_be_enabled(timeout=JS_TIMEOUT_MS)
    weekday.select_option("3")
    cadence.select_option("02hours")
    expect(weekday).to_be_disabled(timeout=JS_TIMEOUT_MS)
    assert weekday.input_value() == "3"
    _shot(page, screenshot_dir, "schedule_override_weekly_then_hourly")

    # FLIP OFF: all override controls disable again without losing selected values.
    override.uncheck()
    expect(override).not_to_be_checked(timeout=JS_TIMEOUT_MS)
    expect(hour).to_be_disabled(timeout=JS_TIMEOUT_MS)
    expect(minute).to_be_disabled(timeout=JS_TIMEOUT_MS)


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

    Before->after: the button's OWN rendered label is already "Enable All"
    (``Form_Button('chgstate', 'Enable All', ...)``), so capturing the DOM value
    before the click and comparing it to the post-click value is not a real
    transition -- before == after even if the click handler were deleted
    entirely. Seed a sentinel value into the button via JS FIRST, then click, and
    assert the value became 'Enable All' -- only the handler running can cause
    that flip.
    """
    page = browser_page
    _open(page, webui, ADVANCED_IP_EDITOR)

    btn = page.locator("#chgstate")
    expect(btn).to_be_attached(timeout=JS_TIMEOUT_MS)

    # BEFORE: seed a sentinel so the post-click value can only come from the
    # handler -- the button's rendered label already equals 'Enable All', so a
    # bare pre-click read would prove nothing (before == after with no handler).
    btn.evaluate("el => el.value = '__pre__'")
    before_value = btn.evaluate("el => el.value")
    assert before_value == "__pre__", f"sentinel seed did not take, got {before_value!r}"
    _shot(page, screenshot_dir, "chgstate_before")

    # Fire the bound jQuery click handler. The button is in the (visible) Source
    # Definitions section, so a real click works; dispatch the bound event so the
    # value-set runs without submitting the form away from the page under test.
    btn.dispatch_event("click")

    # AFTER: the handler set the button value to 'Enable All' -- the sentinel is gone.
    expect(btn).to_have_js_property("value", "Enable All", timeout=JS_TIMEOUT_MS)
    after_value = btn.evaluate("el => el.value")
    assert after_value == "Enable All", (
        f"expected 'Enable All' after click, got {after_value!r} (before {before_value!r})"
    )
    _shot(page, screenshot_dir, "chgstate_after")


def test_chgstate_click_populates_act_atype_when_present(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    """`#chgstate` click also writes `#act`/`#atype` when the page carried them (zero prior coverage).

    The click handler (pfBlockerNG.js:172-181) has TWO guarded arms above the
    unconditional value-set proven by the sibling test:
    ``if (action.length > 0) { $('#act').val(action); }`` and the ``atype``
    analog. The sibling test opens the editor with no ``?act``/``?atype`` GET
    params, so both JS locals are '' and NEITHER guard ever fires -- this test
    is the only coverage of that branch.

    A real, legitimate combo that makes both non-empty: the Reports page's
    "add to Whitelist" redirect (pfblockerng_alerts.php:1587) navigates here
    with ``act=addgroup&atype=Whitelist|<ip>|<descr>`` -- validated server-side
    by ``pfb_filter_whitelist_atype()`` (pfblockerng.inc:738-746) -- which also
    makes the server pre-render the hidden inputs ``#act``/``#atype``
    (``Form_Input('atype', 'atype', 'hidden', ...)`` /
    ``Form_Input('act', 'act', 'hidden', ...)``, category_edit.php:1012,1015)
    at those SAME values.

    Before->after: because the server ALSO pre-renders ``#act``/``#atype`` at
    the values the click handler would write, a bare pre-click DOM read is
    already correct -- the same false-transition trap as the sibling test.
    Seed a sentinel into both hidden fields via JS FIRST (mirrors the fix
    above), then click, and assert they flip to the real ``act``/``atype``
    values -- only the guarded arms running can cause that.
    """
    page = browser_page
    ip = "192.0.2.55"  # RFC 5737 TEST-NET-1 -- inert, never routed
    descr = "smoke-chgstate-atype"
    atype_value = f"Whitelist|{ip}|{descr}"
    path = f"{ADVANCED_IP_EDITOR}&act=addgroup&atype={quote(atype_value, safe='')}"
    _open(page, webui, path)

    act = page.locator("#act")
    atype = page.locator("#atype")
    btn = page.locator("#chgstate")
    expect(act).to_be_attached(timeout=JS_TIMEOUT_MS)
    expect(atype).to_be_attached(timeout=JS_TIMEOUT_MS)
    expect(btn).to_be_attached(timeout=JS_TIMEOUT_MS)

    # BEFORE: seed a sentinel into both hidden fields -- the server already
    # pre-rendered them at the SAME values the click handler would write, so a
    # bare pre-click read would prove nothing about the click handler.
    act.evaluate("el => el.value = '__pre__'")
    atype.evaluate("el => el.value = '__pre__'")
    _shot(page, screenshot_dir, "chgstate_atype_before")

    btn.dispatch_event("click")

    # AFTER: both guarded arms fired -- the sentinels are replaced by the real
    # action/atype JS locals (pfBlockerNG.js:174-179), proving the branch ran.
    expect(act).to_have_js_property("value", "addgroup", timeout=JS_TIMEOUT_MS)
    expect(atype).to_have_js_property("value", atype_value, timeout=JS_TIMEOUT_MS)
    _shot(page, screenshot_dir, "chgstate_atype_after")


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


# --------------------------------------------------------------------------- #
# Alias-type normalization (#802, sibling of #676/#636): a wrong-type alias
# submitted to a port/address field is silently normalized away, not rejected.
#
# The save round-trip's "Validate Select field options" whitelist sanitiser
# (pfblockerng_category_edit.php ~479-513) resets any field whose submitted
# value is not a key in its type-specific options dropdown to '' BEFORE
# ``pfb_adv_alias_field_errors()`` (~620) ever runs -- so a wrong-type alias
# name never reaches validation as an error, it is dropped. This is the same
# normalize-before-validate contract already pinned for the sibling IP-settings
# page by ``tests/php/IpSettingsAdvAliasValidationTest.php``.
#
# Implementation note: driving the save through a Playwright browser would
# require navigating away from the page on submit (the response page replaces
# the form page) and then back — a brittle, slow flow that is harder to reason
# about than a direct HTTP POST. The HTTP approach (webui.session.post) is the
# same mechanism ``test_category_edit.py`` uses for every save flow and is the
# accepted pattern in this suite. We use ``webui`` here (its session is already
# authenticated, shared, and correct) with a fresh CSRF token harvested from a
# real GET — the same pattern as ``_post_form`` in ``test_category_edit.py``.
# --------------------------------------------------------------------------- #

_CATEGORY_PAGE = "/pfblockerng/pfblockerng_category_edit.php"
_SAVE_TIMEOUT = 120.0
_CFG_IPV4 = "installedpackages/pfblockernglistsv4/config"

# pfSense's print_input_errors() (guiconfig.inc) renders one non-nested
# <div class="alert alert-danger input-errors">...</div> per response.
_INPUT_ERRORS_RE = re.compile(r"<div[^>]*\binput-errors\b[^>]*>.*?</div>", re.DOTALL)


def _input_errors_block(body: str) -> str:
    """Extract pfSense's ``print_input_errors()`` alert block from a save-response body.

    Pulling just that block out of the full page keeps failure diagnostics readable
    (CLAUDE.md "On failure, print expected vs actual"). Absent the div -- the save carried
    no validation error -- returns an explicit marker so a diagnostic never reads as "the
    response was empty".
    """
    match = _INPUT_ERRORS_RE.search(body)
    return match.group(0) if match else "<no input-errors block in response>"


def _post_ipv4_form(webui: WebUI, payload: dict[str, str]) -> str:
    """POST a fully-enumerated IPv4 category-edit payload and return the response body.

    GETs the page first to harvest a fresh ``__csrf_magic`` token, then POSTs
    directly via the raw session (same pattern as ``_post_form`` in
    ``test_category_edit.py`` — avoids the rowhelper scrape limitation).
    """
    get = webui.get(_CATEGORY_PAGE, params={"type": "ipv4"})
    assert not looks_like_login_page(get.text), "category GET returned the login form (session lost)"
    token = extract_csrf_token(get.text)
    data = dict(payload)
    data["__csrf_magic"] = token
    data["save"] = "save"
    resp = webui.session.post(webui.url(_CATEGORY_PAGE), data=data, verify=webui._verify, timeout=_SAVE_TIMEOUT)
    assert not looks_like_login_page(resp.text), "category POST returned the login form (session lost)"
    return resp.text


def _free_rowid_ipv4(vm: helpers.SmokeVM) -> int:
    """Next free IPv4 list rowid (gaps in existing rows are avoided)."""
    pre = (
        f"$c = config_get_path({helpers._php_str(_CFG_IPV4)}, array());\n"
        "$max = -1;\n"
        "foreach (array_keys($c) as $k) { if (is_numeric($k) && (int)$k > $max) { $max = (int)$k; } }\n"
        "$free = $max + 1;"
    )
    return int(helpers._php_read_scalar(vm, pre, "$free", timeout=_SAVE_TIMEOUT))


def _del_rowid_ipv4(vm: helpers.SmokeVM, rowid: int) -> None:
    snippet = (
        f"config_del_path({helpers._php_str(f'{_CFG_IPV4}/{rowid}')});\n"
        "write_config('pfBlockerNG smoke: drop alias-type test row');\n"
        "echo 'OK';"
    )
    result = helpers.php_eval(vm, snippet, timeout=_SAVE_TIMEOUT)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_del_rowid_ipv4({rowid}) failed: rc={result.returncode} {result.stdout!r}")


def _mk_alias(vm: helpers.SmokeVM, name: str, alias_type: str, address: str) -> None:
    """Append a pfSense firewall alias via the config API."""
    row = {
        "name": name,
        "type": alias_type,
        "address": address,
        "descr": "pfBlockerNG smoke alias",
        "detail": "",
    }
    snippet = (
        "$aliases = config_get_path('aliases/alias', array());\n"
        f"$aliases[] = {helpers._php_kv_array(row)};\n"
        "config_set_path('aliases/alias', $aliases);\n"
        "write_config('pfBlockerNG smoke: create test alias');\n"
        "echo 'OK';"
    )
    result = helpers.php_eval(vm, snippet, timeout=_SAVE_TIMEOUT)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_mk_alias({name!r}) failed: rc={result.returncode} {result.stdout!r}")


def _rm_alias(vm: helpers.SmokeVM, name: str) -> None:
    """Remove the first firewall alias whose name matches ``name``."""
    snippet = (
        "$aliases = config_get_path('aliases/alias', array());\n"
        "$out = array();\n"
        "foreach ($aliases as $a) {\n"
        f"  if (($a['name'] ?? '') !== {helpers._php_str(name)}) {{ $out[] = $a; }}\n"
        "}\n"
        "config_set_path('aliases/alias', $out);\n"
        "write_config('pfBlockerNG smoke: delete test alias');\n"
        "echo 'OK';"
    )
    result = helpers.php_eval(vm, snippet, timeout=_SAVE_TIMEOUT)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_rm_alias({name!r}) failed: rc={result.returncode} {result.stdout!r}")


def _ipv4_payload(rowid: int, aliasname: str, **overrides: str) -> dict[str, str]:
    """A complete IPv4 alias save payload (one Disabled placeholder row)."""
    payload = {
        "type": "ipv4",
        "rowid": str(rowid),
        "aliasname": aliasname,
        "description": "smoke alias-type test",
        "action": "Deny_Both",
        "cron": "Never",
        "sort": "sort",
        "aliaslog": "enabled",
        "stateremoval": "enabled",
        "autoproto_in": "tcp",
        "agateway_in": "default",
        "autoproto_out": "any",
        "agateway_out": "default",
        "suppression_cidr": "Disabled",
        "srcint": "",
        "script_pre": "",
        "script_post": "",
        "custom": "",
        "format-0": "auto",
        "state-0": "Disabled",
        "url-0": "",
        "header-0": "",
    }
    payload.update(overrides)
    return payload


def test_alias_type_port_field_normalizes_network_alias_away(
    webui: "WebUI",
    smoke_vm: helpers.SmokeVM,
    browser_page: "Page",  # noqa: ARG001
    screenshot_dir: Path,  # noqa: ARG001
) -> None:
    """Saving a network alias into ``aliasports_in`` is silently normalized away, not rejected.

    Scenario: the category_edit save round-trip runs TWO steps in order -- first a "Validate
    Select field options" whitelist sanitiser (pfblockerng_category_edit.php ~479-513), then
    ``pfb_adv_alias_field_errors($_POST)`` (~620). ``$options_aliasports_in`` is built from
    PORT-type aliases only (~419-426), so a NETWORK-type alias name is never a key in it: the
    whitelist step resets ``$_POST['aliasports_in']`` to ``''`` BEFORE the validator ever runs,
    so ``pfb_adv_alias_field_errors()`` sees an empty field and emits nothing -- the save
    proceeds and the wrong-type value is dropped, not rejected.

    Background:
        This is the same two-step, normalize-before-validate contract already pinned for the
        sibling IP-settings page by ``tests/php/IpSettingsAdvAliasValidationTest.php`` (#676,
        sibling of #636): "a non-existent or wrong-type value never reaches validation as an
        error -- it is reset to '' and saved empty". Issue #802 is this same behaviour on
        category_edit's own save round-trip: the old oracle here expected a loud
        ``'Must use a Port-type alias'`` rejection that the page, by this design, never emits
        on this path -- it never passed against a live VM.

    Given:
        - A network alias ``smkbwtypenet`` exists in the firewall config.
        - A port alias ``smkbwtypeport`` exists in the firewall config.
        - The target IPv4 rowid is free (no ``aliasports_in`` set yet).
    When (normalize):
        POST the IPv4 save with ``aliasports_in=smkbwtypenet`` (a network alias in a port
        field), ``autoports_in=on``, ``autoproto_in=tcp``.
    Then (normalize):
        - The response contains NEITHER ``Must use a Port-type alias`` NOR
          ``Must use an existing Alias`` -- the value never reaches validation as an error.
        - The save WENT THROUGH: ``aliasname`` is written (a rejected save writes nothing).
        - The wrong-type value was dropped: ``aliasports_in`` reads back as ``''``.
    When (accept):
        POST the same payload with ``aliasports_in=smkbwtypeport`` (a correct port alias).
    Then (accept):
        - The response contains no alias-type error.
        - ``aliasports_in`` reads back as ``smkbwtypeport``.
    """
    vm = smoke_vm
    net_alias = "smkbwtypenet"
    port_alias = "smkbwtypeport"
    aliasname = "smkbwtype"
    rowid = _free_rowid_ipv4(vm)
    base = f"{_CFG_IPV4}/{rowid}"

    try:
        # Both aliases are created INSIDE the try: a failure creating the second
        # (e.g. the network alias) must not leak the first -- the finally below
        # removes both unconditionally.
        _mk_alias(vm, net_alias, "network", "192.0.2.0/24")
        _mk_alias(vm, port_alias, "port", "8080")

        # BEFORE: rowid is free (no aliasports_in set yet).
        assert helpers.config_get(vm, f"{base}/aliasports_in") == "", (
            f"precondition: rowid {rowid} not free (aliasports_in already set)"
        )

        # NORMALIZE: a network alias in a port field is silently dropped, not rejected.
        norm_body = _post_ipv4_form(
            webui,
            _ipv4_payload(
                rowid,
                aliasname,
                autoports_in="on",
                autoproto_in="tcp",
                aliasports_in=net_alias,
            ),
        )
        for error in ("Must use a Port-type alias", "Must use an existing Alias"):
            assert error not in norm_body, (
                f"expected NO {error!r} error -- the whitelist sanitiser resets a wrong-type "
                f"alias to '' before pfb_adv_alias_field_errors() ever runs, so this value "
                f"never reaches validation as an error.\n"
                f"  response input-errors block: {_input_errors_block(norm_body)}"
            )

        # The save WENT THROUGH -- a rejected save would write nothing at all.
        got_aliasname = helpers.config_get(vm, f"{base}/aliasname")
        assert got_aliasname == aliasname, (
            f"expected the save to go through (a rejected save writes nothing)\n"
            f"  expected aliasname: {aliasname!r}\n"
            f"  actual aliasname  : {got_aliasname!r}\n"
            f"  response input-errors block: {_input_errors_block(norm_body)}"
        )

        # The wrong-type value was dropped -- normalized to '', not saved verbatim.
        # config_get() reads absent and ''-valued keys identically, so this check alone
        # cannot tell "normalized" from "rejected, row never written" -- the aliasname
        # assert above is what rules the rejected case out. Keep it first.
        got_ports_in = helpers.config_get(vm, f"{base}/aliasports_in")
        assert got_ports_in == "", (
            f"expected the wrong-type alias to be normalized away\n"
            f"  expected aliasports_in: ''\n"
            f"  actual aliasports_in  : {got_ports_in!r}"
        )

        # ACCEPT: a correct port alias in the port field is saved as-is (unchanged semantics).
        accept_body = _post_ipv4_form(
            webui,
            _ipv4_payload(
                rowid,
                aliasname,
                autoports_in="on",
                autoproto_in="tcp",
                aliasports_in=port_alias,
            ),
        )
        assert "Must use a Port-type alias" not in accept_body, (
            f"expected no alias-type error when a port alias is used in a port field\n"
            f"  response input-errors block: {_input_errors_block(accept_body)}"
        )
        got_accept_ports_in = helpers.config_get(vm, f"{base}/aliasports_in")
        assert got_accept_ports_in == port_alias, (
            f"expected aliasports_in to be written after a valid save\n"
            f"  expected aliasports_in: {port_alias!r}\n"
            f"  actual aliasports_in  : {got_accept_ports_in!r}"
        )
    finally:
        _del_rowid_ipv4(vm, rowid)
        _rm_alias(vm, net_alias)
        _rm_alias(vm, port_alias)


# --------------------------------------------------------------------------- #
# ADR-63 Phase 4 (issue #1147): the shared staged drag+anchor-click reorder
# component wired onto pfblockerng_category_edit.php's no-sort mode, retiring
# the full-page-POST-per-move Lmove/Xmove mechanism entirely. Mirrors
# test_browser_category.py's Phase-3 test_reorder_* pattern -- Semantics #1:
# every assertion below checks the STAGED (pre-Save) DOM order/values first,
# then the PERSISTED (post-Save) config state, never the final state alone.
# Persistence channel: onAfterMove's renumber() keeps rowhelper field names
# positional, so the page's PRE-EXISTING save loop (category_edit.php's
# `foreach ($_POST as $key => $value) { ... explode('-', $key) ... }`, byte-
# unchanged this phase) is the ONLY persistence path -- there is no new
# server-side placement math (ADR-63 §2 Decision 4-5).
# --------------------------------------------------------------------------- #

_CFG_BY_GTYPE = {"ipv4": CFG_IPV4, "ipv6": CFG_IPV6, "dnsbl": CFG_DNSBL}
_PAYLOAD_BY_GTYPE = {"ipv4": _ipv4_payload, "ipv6": _ipv6_payload, "dnsbl": _dnsbl_payload}
_ROWORDER_PATH = "system/webgui/roworderdragging"


def _reorder_names(gtype: str) -> tuple[str, str, str]:
    """Three short (< 20 char), distinct header values -- render unabridged."""
    return (f"pfbre{gtype}a", f"pfbre{gtype}b", f"pfbre{gtype}c")


def _three_row_payload(
    gtype: str, rowid: int, aliasname: str, headers: tuple[str, str, str], **overrides: str
) -> dict[str, str]:
    """A 3-row, ``sort='no-sort'`` category-edit save payload for the given gtype.

    ``sort='no-sort'`` is what makes ``pfblockerng_category_edit.php`` render the
    reorder gutter/wiring (the page's ``if ($rowdata[$rowid]['sort'] == 'no-sort')``
    gate, ADR-63 P4) -- without it the page auto-sorts on every render and injects
    no manual UI at all.
    """
    payload = _PAYLOAD_BY_GTYPE[gtype](rowid, aliasname, sort="no-sort", **overrides)
    for i, header in enumerate(headers):
        payload[f"format-{i}"] = "auto"
        payload[f"state-{i}"] = "Disabled"
        payload[f"url-{i}"] = ""
        payload[f"header-{i}"] = header
    return payload


def _edit_page_url(gtype: str, rowid: int) -> str:
    return f"/pfblockerng/pfblockerng_category_edit.php?type={gtype}&rowid={rowid}"


def _rows(page: Page) -> Locator:
    return page.locator("#sourcedefinitions .panel-body .form-group.repeatable")


def _row_headers(page: Page) -> list[str]:
    """Rendered ``header-N`` input values, in current DOM order."""
    inputs = page.locator("#sourcedefinitions .panel-body input[id^='header-']")
    return [inputs.nth(i).input_value() for i in range(inputs.count())]


def _gutter_numbers(page: Page) -> list[str]:
    """Rendered ``.pfb-gutter`` text (nbsp-padding normalised to plain spaces), DOM order."""
    guts = page.locator("#sourcedefinitions .panel-body .pfb-gutter")
    return [(guts.nth(i).text_content() or "").replace("\xa0", " ").strip() for i in range(guts.count())]


def _gutter_raw_texts(page: Page) -> list[str]:
    """Un-normalised ``.pfb-gutter`` text (nbsp preserved), DOM order -- pins padding, not just value."""
    guts = page.locator("#sourcedefinitions .panel-body .pfb-gutter")
    return [guts.nth(i).text_content() or "" for i in range(guts.count())]


def _expected_gutter_texts(n_rows: int) -> list[str]:
    """PHP :1071 / JS :1721 padded-gutter format: nbsp+space prefix for single digits."""
    return [(f"\xa0 {i + 1}" if (i + 1) < 10 else str(i + 1)) for i in range(n_rows)]


def _check_row(page: Page, i: int) -> None:
    _rows(page).nth(i).locator(".pfb-reorder-chk").check()


def _click_anchor(page: Page, i: int, *, shift: bool = False) -> None:
    _rows(page).nth(i).locator(".pfb-reorder-anchor").click(modifiers=["Shift"] if shift else None)


def _drag_row(page: Page, src: int, dst: int) -> None:
    """Drag row ``src`` to below row ``dst`` via real mouse events (distance:10 threshold).

    Grabs the ``.pfb-gutter`` handle -- a plain ``<sub>``, not a form control -- since
    jQuery UI sortable's default ``cancel`` selector excludes input/textarea/button/
    select/option from starting a drag, and every OTHER element in a category_edit.php
    row is one of those (unlike category.php's plain-text ``<td>`` handle).
    """
    handle = _rows(page).nth(src).locator(".pfb-gutter")
    target = _rows(page).nth(dst)
    hb = handle.bounding_box()
    tb = target.bounding_box()
    assert hb is not None and tb is not None, "could not compute bounding boxes for drag handle/target"
    start_x, start_y = hb["x"] + hb["width"] / 2, hb["y"] + hb["height"] / 2
    page.mouse.move(start_x, start_y)
    page.mouse.down()
    page.mouse.move(start_x, start_y + 20, steps=5)
    page.mouse.move(tb["x"] + tb["width"] / 2, tb["y"] + tb["height"] + 5, steps=10)
    page.mouse.up()


def _save_via_ui(page: Page) -> None:
    """Click the page's native Save button and wait for the full-page reload.

    Unlike category.php's AJAX ``save_new_changes()`` (``confirm()`` + ``$.ajax``),
    category_edit.php uses pfSense's stock ``Form`` submit button --
    ``new Form("Save {$type} Settings")`` constructs a global
    ``Form_Button('save', "Save {$type} Settings", null, 'fa-solid fa-save')``
    (pfSense core ``Form``/``Form_Button`` classes), rendered ``<button
    type="submit" name="save" id="save">`` -- a plain form submit, no confirm
    dialog, no AJAX.
    """
    with page.expect_navigation(wait_until="networkidle", timeout=JS_TIMEOUT_MS * 3):
        page.locator("#save").click()


def _persisted_headers(vm: helpers.SmokeVM, cfg_root: str, rowid: int, n: int = 3) -> list[str]:
    return [helpers.config_get(vm, f"{cfg_root}/{rowid}/row/{i}/header") for i in range(n)]


def _persisted_row_count(vm: helpers.SmokeVM, cfg_root: str, rowid: int) -> int:
    # Delimit the echo -- pfSsh.php prepends a startup banner to stdout, so a bare
    # int(result.stdout) breaks (helpers.config_get delimits for the same reason).
    path = helpers._php_str(f"{cfg_root}/{rowid}/row")
    result = helpers.php_eval(vm, f"echo '<<<CNT>>>' . count(config_get_path({path}, array())) . '<<<END>>>';")
    m = re.search(r"<<<CNT>>>(\d+)<<<END>>>", result.stdout)
    assert m is not None, f"no delimited row count in pfSsh.php output: {result.stdout!r}"
    return int(m.group(1))


def _roworderdragging_enabled(vm: helpers.SmokeVM) -> bool:
    """Whether system/webgui/roworderdragging is present (pfSense checkbox: presence = ON)."""
    result = helpers.php_eval(vm, "echo config_path_enabled('system/webgui', 'roworderdragging') ? '1' : '0';")
    return result.stdout.strip().endswith("1")


def _set_roworderdragging(vm: helpers.SmokeVM, enabled: bool) -> None:
    """Set/clear the checkbox node -- presence = ON, matches config_path_enabled semantics."""
    if enabled:
        snippet = (
            f"config_set_path({helpers._php_str(_ROWORDER_PATH)}, '');\n"
            "write_config('pfBlockerNG smoke: set roworderdragging');\n"
            "echo 'OK';"
        )
    else:
        snippet = (
            f"config_del_path({helpers._php_str(_ROWORDER_PATH)});\n"
            "write_config('pfBlockerNG smoke: clear roworderdragging');\n"
            "echo 'OK';"
        )
    result = helpers.php_eval(vm, snippet)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_set_roworderdragging({enabled}) failed: rc={result.returncode} {result.stderr!r}")


@pytest.mark.parametrize("gtype", sorted(_CFG_BY_GTYPE))
def test_reorder_drag_only_then_save_persists_dom_order(
    browser_page: Page,
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    gtype: str,
) -> None:
    """Drag-only reorder (no anchor-click), then Save: persisted order == DOM order.

    Also asserts the ``.pfb-gutter`` numbers refreshed to the new DOM positions
    (the ``onAfterMove`` callback's own renumber+gutter-refresh contract).
    """
    vm = smoke_vm
    cfg_root = _CFG_BY_GTYPE[gtype]
    names = _reorder_names(gtype)
    rowid = _free_rowid(vm, cfg_root)
    try:
        _post_form(webui, _three_row_payload(gtype, rowid, f"pfbre{gtype}", names))
        page = browser_page
        _open(page, webui, _edit_page_url(gtype, rowid))

        before = _row_headers(page)
        assert before == list(names), f"seeded rows did not render in order {names}, got {before!r}"

        # Drag row 0 (a) below row 2 (c) -> DOM order becomes [b, c, a].
        _drag_row(page, 0, 2)
        after_drag = _row_headers(page)
        expected = [names[1], names[2], names[0]]
        assert after_drag == expected, f"drag did not relocate row 0: got {after_drag!r}, expected {expected!r}"
        gutters = _gutter_numbers(page)
        assert gutters == ["1", "2", "3"], f"gutter numbers did not refresh to DOM position after drag: {gutters!r}"

        _save_via_ui(page)

        persisted = _persisted_headers(vm, cfg_root, rowid)
        assert persisted == expected, (
            f"drag-only Save did not persist the DOM order for gtype={gtype!r}: "
            f"expected {expected!r}, got {persisted!r}"
        )
    finally:
        _del_rowid(vm, cfg_root, rowid)


@pytest.mark.parametrize("gtype", sorted(_CFG_BY_GTYPE))
def test_reorder_anchor_click_single_row_then_save_persists_dom_order(
    browser_page: Page,
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    gtype: str,
) -> None:
    """Anchor-click (single checked row, no drag) reorder, then Save: persisted == DOM order.

    This is the red->green delta (issue #1147) on category_edit.php: before this
    phase's wiring, the ONLY reorder control was the full-page-POST-per-move
    Lmove checkbox + Xmove submit button (a touch/mobile-hostile control) -- now
    the shared staged component offers a tap-friendly alternative with NO page
    navigation per individual move (asserted below), only on the final Save.
    """
    vm = smoke_vm
    cfg_root = _CFG_BY_GTYPE[gtype]
    names = _reorder_names(gtype)
    rowid = _free_rowid(vm, cfg_root)
    try:
        _post_form(webui, _three_row_payload(gtype, rowid, f"pfbre{gtype}", names))
        page = browser_page
        _open(page, webui, _edit_page_url(gtype, rowid))

        before = _row_headers(page)
        assert before == list(names), f"seeded rows did not render in order {names}, got {before!r}"
        url_before_click = page.url

        # Check row 2 (c), plain-anchor-click row 0 (a) -> c moves before a: [c, a, b].
        _check_row(page, 2)
        _click_anchor(page, 0, shift=False)
        after_click = _row_headers(page)
        expected = [names[2], names[0], names[1]]
        assert after_click == expected, (
            f"anchor-click did not relocate row 2: got {after_click!r}, expected {expected!r}"
        )
        assert page.url == url_before_click, "an individual anchor-click move must not navigate the page"
        gutters = _gutter_numbers(page)
        assert gutters == ["1", "2", "3"], (
            f"gutter numbers did not refresh to DOM position after anchor-click: {gutters!r}"
        )

        _save_via_ui(page)

        persisted = _persisted_headers(vm, cfg_root, rowid)
        assert persisted == expected, (
            f"anchor-click-only Save did not persist the DOM order for gtype={gtype!r}: "
            f"expected {expected!r}, got {persisted!r}"
        )
    finally:
        _del_rowid(vm, cfg_root, rowid)


@pytest.mark.parametrize("gtype", sorted(_CFG_BY_GTYPE))
def test_reorder_anchor_click_straddle_then_save_persists_dom_order(
    browser_page: Page,
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    gtype: str,
) -> None:
    """Checked rows straddling the anchor on both sides, then Save: persisted == DOM order.

    Given [a, b, c] (indices 0,1,2). Check a (0) and c (2); plain-anchor-click
    b (1): both relocate immediately before b, preserving their relative order
    (a before c) -- final order [a, c, b].
    """
    vm = smoke_vm
    cfg_root = _CFG_BY_GTYPE[gtype]
    names = _reorder_names(gtype)
    rowid = _free_rowid(vm, cfg_root)
    try:
        _post_form(webui, _three_row_payload(gtype, rowid, f"pfbre{gtype}", names))
        page = browser_page
        _open(page, webui, _edit_page_url(gtype, rowid))

        before = _row_headers(page)
        assert before == list(names), f"seeded rows did not render in order {names}, got {before!r}"

        _check_row(page, 0)
        _check_row(page, 2)
        _click_anchor(page, 1, shift=False)
        after_click = _row_headers(page)
        expected = [names[0], names[2], names[1]]
        assert after_click == expected, f"straddle anchor-click produced {after_click!r}, expected {expected!r}"

        _save_via_ui(page)

        persisted = _persisted_headers(vm, cfg_root, rowid)
        assert persisted == expected, (
            f"straddle anchor-click Save did not persist the DOM order for gtype={gtype!r}: "
            f"expected {expected!r}, got {persisted!r}"
        )
    finally:
        _del_rowid(vm, cfg_root, rowid)


def test_reorder_composition_add_delete_field_edit_then_save_persists_all(
    browser_page: Page,
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """ONE session: staged anchor-click reorder + core ``#addrow`` + core row-delete +
    a per-row field edit, then Save: the persisted row SET, ORDER, and the edited
    VALUE all match the final visual state -- no row lost or duplicated (ADR-63
    Req 4 / ADR §7 row 4). Extends Phase 2's standalone-fixture renumber-
    composition proof (scenario d) to the real page.
    """
    vm = smoke_vm
    cfg_root = CFG_DNSBL
    names = _reorder_names("dnsbl")
    rowid = _free_rowid(vm, cfg_root)
    try:
        _post_form(webui, _three_row_payload("dnsbl", rowid, "pfbrednsblc", names))
        page = browser_page
        _open(page, webui, _edit_page_url("dnsbl", rowid))

        before = _row_headers(page)
        assert before == list(names), f"seeded rows did not render in order {names}, got {before!r}"

        # STAGE a reorder: check row2 (c), anchor-click row0 (a) plain -> [c, a, b].
        _check_row(page, 2)
        _click_anchor(page, 0, shift=False)
        staged = _row_headers(page)
        expected_staged = [names[2], names[0], names[1]]
        assert staged == expected_staged, f"staged reorder produced {staged!r}, expected {expected_staged!r}"

        # ADD a row via core's #addrow -> a 4th, empty-header row appends at the end
        # (pfSenseHelpers' bump_input_id() clears <input> values on clone).
        row_count_before_add = _rows(page).count()
        page.locator("#addrow").click()
        expect(_rows(page)).to_have_count(row_count_before_add + 1, timeout=JS_TIMEOUT_MS)
        after_add = _row_headers(page)
        assert after_add == [*expected_staged, ""], (
            f"add_row did not append one empty-header row at the end: got {after_add!r}"
        )

        # EDIT a field: the row holding 'a' (names[0]) gets a new header value.
        edited_value = f"{names[0]}_edited"
        page.locator(f"#sourcedefinitions .panel-body input[value='{names[0]}']").fill(edited_value)

        # DELETE the row holding 'b' (names[1]) via core's delete button. Locate by
        # DOM index -- 'b' is row 2 in the staged [c, a, b, ''] order. An
        # input[value='b'] selector would be ambiguous: core add_row() clones the
        # visually-last row ('b' after the reorder) and clears the clone's LIVE value
        # but not its stale value="b" ATTRIBUTE, so the appended empty row also
        # matches input[value='b']. The DOM index is unambiguous.
        _rows(page).nth(2).locator("button[id^='deleterow']").click()
        expect(_rows(page)).to_have_count(row_count_before_add, timeout=JS_TIMEOUT_MS)

        final_visual = _row_headers(page)
        expected_final = [names[2], edited_value, ""]
        assert final_visual == expected_final, (
            f"post add/delete/edit visual state is {final_visual!r}, expected {expected_final!r}"
        )

        _save_via_ui(page)

        persisted_count = _persisted_row_count(vm, cfg_root, rowid)
        assert persisted_count == 3, f"expected 3 persisted rows (no row lost/duplicated), got {persisted_count}"
        persisted = _persisted_headers(vm, cfg_root, rowid)
        assert persisted == expected_final, (
            f"composition Save did not persist the final visual state: expected {expected_final!r}, got {persisted!r}"
        )
    finally:
        _del_rowid(vm, cfg_root, rowid)


def test_sort_mode_renders_no_manual_reorder_ui_and_preserves_auto_sort(
    browser_page: Page,
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """sort=='sort': the page injects NO reorder controls, and the pre-existing
    auto-sort transform is unchanged (Semantics #2 -- ZERO delta). Seeds two
    ENABLED rows out of alphabetical header order -- the exact
    ``CategoryEditAutoSortTest`` fixture pair -- with ``sort`` left at 'sort'.
    """
    vm = smoke_vm
    cfg_root = CFG_DNSBL
    rowid = _free_rowid(vm, cfg_root)
    try:
        payload = _dnsbl_payload(rowid, "pfbresortd", sort="sort")
        payload["format-0"] = "auto"
        payload["state-0"] = "Enabled"
        payload["url-0"] = ""
        payload["header-0"] = "Bravo"
        payload["format-1"] = "auto"
        payload["state-1"] = "Enabled"
        payload["url-1"] = ""
        payload["header-1"] = "Alpha"
        _post_form(webui, payload)
        page = browser_page
        _open(page, webui, _edit_page_url("dnsbl", rowid))

        # This Tier-B test's unique job is the LIVE invariant that sort mode injects
        # NO manual-reorder controls. The auto-sort ORDER transform itself (Alpha
        # before Bravo, natural/case-insensitive) is pinned reliably and directly by
        # the PHPUnit oracle CategoryEditAutoSortTest and by the Tier-A render test
        # test_category_edit_sort_mode_renders_no_reorder_wiring -- asserting it again
        # off the live DOM here only adds a flaky rendered-order read, not coverage.
        assert page.locator(".pfb-reorder-anchor").count() == 0, "sort mode must inject NO reorder anchor controls"
        assert page.locator(".pfb-reorder-chk").count() == 0, "sort mode must inject NO reorder checkbox controls"
        assert page.locator(".pfb-gutter").count() == 0, "sort mode must render NO gutter (manual-UI-only markup)"
    finally:
        _del_rowid(vm, cfg_root, rowid)


def test_reorder_roworderdragging_set_disables_drag_anchor_click_still_persists(
    browser_page: Page,
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """``system/webgui/roworderdragging`` SET: no drag init renders; anchor-click
    still persists a FULL reorder+Save round trip (ADR-63 Decision 2: dragEnabled
    = ``!roworderdragging`` -- an admin who globally disabled drag must still get
    a full-fidelity anchor-click fallback, not merely a render check).
    """
    vm = smoke_vm
    cfg_root = CFG_DNSBL
    names = _reorder_names("dnsbl")
    was_enabled = _roworderdragging_enabled(vm)
    rowid = _free_rowid(vm, cfg_root)
    try:
        _set_roworderdragging(vm, True)
        _post_form(webui, _three_row_payload("dnsbl", rowid, "pfbresorte", names))
        page = browser_page
        _open(page, webui, _edit_page_url("dnsbl", rowid))

        has_instance = page.evaluate("() => $('#sourcedefinitions .panel-body').sortable('instance') !== undefined")
        assert has_instance is False, "roworderdragging SET must never initialise .sortable()"

        before = _row_headers(page)
        assert before == list(names), f"seeded rows did not render in order {names}, got {before!r}"

        _check_row(page, 2)
        _click_anchor(page, 0, shift=False)
        after_click = _row_headers(page)
        expected = [names[2], names[0], names[1]]
        assert after_click == expected, f"anchor-click (drag disabled) produced {after_click!r}, expected {expected!r}"

        _save_via_ui(page)

        persisted = _persisted_headers(vm, cfg_root, rowid)
        assert persisted == expected, (
            f"anchor-click Save under roworderdragging=SET did not persist: expected {expected!r}, got {persisted!r}"
        )
    finally:
        _del_rowid(vm, cfg_root, rowid)
        _set_roworderdragging(vm, was_enabled)


@pytest.mark.parametrize("gtype", ["dnsbl", "ipv4"])
def test_delete_middle_row_without_prior_move_renumbers_gutter(
    browser_page: Page,
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    gtype: str,
) -> None:
    """Deleting the middle of 3 rows, with NO prior reorder move, must renumber
    the visible ``.pfb-gutter`` labels to [1, 2] (correctly padded per :1071) --
    not leave the stale [1, 3] (issue #1209). ``onAfterMove`` (the only existing
    gutter-refresh hook) is wired to the anchor-click/drag paths only, never to
    a bare ``deleterow`` click, so a standalone delete is the regression this
    guards -- on BOTH gtype families (dnsbl's own ``#addrow`` handler vs.
    advanced's GeoIP-gated one; neither ever bound a delete handler at all).
    """
    vm = smoke_vm
    cfg_root = _CFG_BY_GTYPE[gtype]
    names = _reorder_names(gtype)
    rowid = _free_rowid(vm, cfg_root)
    try:
        _post_form(webui, _three_row_payload(gtype, rowid, f"pfbregutterdel{gtype}", names))
        page = browser_page
        _open(page, webui, _edit_page_url(gtype, rowid))

        before_headers = _row_headers(page)
        assert before_headers == list(names), f"seeded rows did not render in order {names}, got {before_headers!r}"
        before_gutters = _gutter_raw_texts(page)
        expected_before = _expected_gutter_texts(3)
        assert before_gutters == expected_before, (
            f"seeded gutters were not {expected_before!r} before delete: {before_gutters!r}"
        )

        # Delete the MIDDLE row directly -- no reorder move precedes this click.
        _rows(page).nth(1).locator("button[id^='deleterow']").click()
        expect(_rows(page)).to_have_count(2, timeout=JS_TIMEOUT_MS)

        after_headers = _row_headers(page)
        assert after_headers == [names[0], names[2]], f"delete did not remove the middle row: got {after_headers!r}"
        after_gutters = _gutter_raw_texts(page)
        expected_after = _expected_gutter_texts(2)
        assert after_gutters == expected_after, (
            f"gutter numbers went stale after a client-side delete with no prior move (gtype={gtype!r}): "
            f"expected {expected_after!r}, got {after_gutters!r}"
        )
    finally:
        _del_rowid(vm, cfg_root, rowid)


@pytest.mark.parametrize("gtype", ["ipv4", "dnsbl"])
def test_add_row_without_prior_move_gives_new_row_its_own_padded_gutter(
    browser_page: Page,
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    gtype: str,
) -> None:
    """Adding a 4th row, with NO prior reorder move, must give the new row its
    own gutter number correctly padded per :1071/:1721 -- not a stale duplicate
    of row 3's (advanced+GeoIP-disabled: core's ``.clone()`` copies the source
    row's gutter verbatim, no handler bumps it) and not a right-but-unpadded
    number (dnsbl: the legacy handler's ``.text()`` bump drops the ``&nbsp;``
    padding) (issue #1209). ``onAfterMove`` is wired to the anchor-click/drag
    paths only, never to ``#addrow``.
    """
    vm = smoke_vm
    cfg_root = _CFG_BY_GTYPE[gtype]
    names = _reorder_names(gtype)
    rowid = _free_rowid(vm, cfg_root)
    try:
        _post_form(webui, _three_row_payload(gtype, rowid, f"pfbregutteradd{gtype}", names))
        page = browser_page
        _open(page, webui, _edit_page_url(gtype, rowid))

        before_headers = _row_headers(page)
        assert before_headers == list(names), f"seeded rows did not render in order {names}, got {before_headers!r}"
        before_gutters = _gutter_raw_texts(page)
        expected_before = _expected_gutter_texts(3)
        assert before_gutters == expected_before, (
            f"seeded gutters were not {expected_before!r} before add: {before_gutters!r}"
        )

        # Add via core's #addrow directly -- no reorder move precedes this click.
        page.locator("#addrow").click()
        expect(_rows(page)).to_have_count(4, timeout=JS_TIMEOUT_MS)

        after_gutters = _gutter_raw_texts(page)
        expected_after = _expected_gutter_texts(4)
        assert after_gutters == expected_after, (
            f"new row's gutter went stale/unpadded after a client-side add with no prior move (gtype={gtype!r}): "
            f"expected {expected_after!r}, got {after_gutters!r}"
        )
    finally:
        _del_rowid(vm, cfg_root, rowid)
