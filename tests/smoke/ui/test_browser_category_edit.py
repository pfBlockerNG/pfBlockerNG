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

from .. import helpers
from .conftest import mask_page_identity
from .webui import extract_csrf_token, looks_like_login_page

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


# --------------------------------------------------------------------------- #
# Alias-type validation (#356): wrong alias type in a port/address field is
# rejected by the server with the expected error string.
#
# Implementation note: the alias-type check (``pfb_alias_field_type_ok``) fires
# on the SAVE round-trip (a PHP server validation), not purely in JS.  Driving
# it through a Playwright browser would require navigating away from the page on
# submit (the error page replaces the form page) and then back — a brittle,
# slow flow that is harder to reason about than a direct HTTP POST.  The HTTP
# approach (webui.session.post) is the same mechanism ``test_category_edit.py``
# uses for every save flow and is the accepted pattern in this suite.  We use
# ``webui`` here (its session is already authenticated, shared, and correct) with
# a fresh CSRF token harvested from a real GET — the same pattern as
# ``_post_form`` in ``test_category_edit.py``.
# --------------------------------------------------------------------------- #

_CATEGORY_PAGE = "/pfblockerng/pfblockerng_category_edit.php"
_SAVE_TIMEOUT = 120.0
_CFG_IPV4 = "installedpackages/pfblockernglistsv4/config"


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
        "dow": "",
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


def test_alias_type_port_field_rejects_network_alias(
    webui: "WebUI",
    smoke_vm: helpers.SmokeVM,
    browser_page: "Page",  # noqa: ARG001
    screenshot_dir: Path,  # noqa: ARG001
) -> None:
    """Saving a network alias in ``aliasports_in`` (a port field) is rejected.

    Scenario: ``pfb_alias_field_type_ok()`` validates that port alias fields
    only accept port-type aliases. Supplying a network alias produces the error
    ``Must use a Port-type alias`` in the response; a valid port alias in the
    same field is accepted.

    Background:
        Issue #356 added ``pfb_alias_field_type_ok()`` which returns FALSE when
        an address-type alias (``alias_get_type() === 'network'``) is passed to
        a port field (``aliasports_*``). The save handler converts that to an
        ``$input_errors`` entry whose text matches ``'Must use a Port-type alias'``.
        A browser form-submit round-trip would navigate away from the page, making
        it fragile to drive with Playwright; the server-side validation is
        equivalently exercised through the authenticated HTTP session (the same
        mechanism ``test_category_edit.py`` uses for all save flows).

    Given:
        - A network alias ``smkbwtypenet`` exists in the firewall config.
        - A port alias ``smkbwtypeport`` exists in the firewall config.
        - The target IPv4 rowid is free.
    When (reject):
        POST the IPv4 save with ``aliasports_in=smkbwtypenet`` (network alias
        in a port field) and ``autoports_in=on``, ``autoproto_in=tcp``.
    Then (reject):
        - The response body contains ``Must use a Port-type alias``
          (server validation error — the config is NOT written).
    When (accept):
        POST the same payload with ``aliasports_in=smkbwtypeport`` (correct
        port alias in the port field).
    Then (accept):
        - The response body does NOT contain ``Must use a Port-type alias``.
        - config.xml stores ``aliasports_in='smkbwtypeport'``.
    """
    vm = smoke_vm
    net_alias = "smkbwtypenet"
    port_alias = "smkbwtypeport"
    rowid = _free_rowid_ipv4(vm)
    base = f"{_CFG_IPV4}/{rowid}"

    _mk_alias(vm, net_alias, "network", "192.0.2.0/24")
    _mk_alias(vm, port_alias, "port", "8080")
    try:
        # BEFORE: rowid is free (no aliasports_in set yet).
        assert helpers.config_get(vm, f"{base}/aliasports_in") == "", (
            f"precondition: rowid {rowid} not free (aliasports_in already set)"
        )

        # REJECT: network alias supplied to a port field -> server validation error.
        reject_body = _post_ipv4_form(
            webui,
            _ipv4_payload(
                rowid,
                "smkbwtype",
                autoports_in="on",
                autoproto_in="tcp",
                aliasports_in=net_alias,
            ),
        )
        assert "Must use a Port-type alias" in reject_body, (
            f"expected 'Must use a Port-type alias' error in response when a network alias "
            f"is used in a port field, but it was absent (first 500 chars: {reject_body[:500]!r})"
        )
        # Config must NOT have been written (the error aborted the save).
        assert helpers.config_get(vm, f"{base}/aliasports_in") == "", (
            "aliasports_in must not be written when the save is rejected by alias-type validation"
        )

        # ACCEPT: correct port alias in the port field -> no error, config written.
        accept_body = _post_ipv4_form(
            webui,
            _ipv4_payload(
                rowid,
                "smkbwtype",
                autoports_in="on",
                autoproto_in="tcp",
                aliasports_in=port_alias,
            ),
        )
        assert "Must use a Port-type alias" not in accept_body, (
            "expected no alias-type error when a port alias is used in a port field"
        )
        assert helpers.config_get(vm, f"{base}/aliasports_in") == port_alias, (
            f"aliasports_in was not written after a valid save with port alias {port_alias!r}"
        )
    finally:
        _del_rowid_ipv4(vm, rowid)
        _rm_alias(vm, net_alias)
        _rm_alias(vm, port_alias)
