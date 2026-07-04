"""Tier-B functional flows for the DNSBL Category / blacklist page (ADR-14 Phase 3).

Marker ``ui_e2e`` -- daily / on-demand, NOT in the default run nor the PR gate
(the whole ``tests/smoke`` tree is ``--ignore``d in the default
``python -m pytest``; this tier is run with
``pytest tests/smoke -m ui_e2e --override-ini="addopts="``).

Page under test: ``pfblockerng_blacklist.php`` -- the squidguard-style "blacklist
provider" categories page. Its config root is the BARE node
``installedpackages/pfblockerngblacklist`` (NO ``/config/0`` array), holding the
scalar selects (``blacklist_enable`` / ``blacklist_lang`` / ``blacklist_selected``
/ ``blacklist_freq`` / ``blacklist_logging``) and the per-provider ``item`` list
(one entry per ``*_global_usage`` provider: ``{xml, title, feed, size, selected,
...}``). The smoke image ships exactly ONE live provider, ``ut1`` (XML ``ut1``,
TITLE ``UT1``, NO ``REG:`` line -> no subscription, so no username/password
fields); ``shallalist`` is unconditionally dropped by the page (inc note
"Temporarily Discontinue Shallalist"). So ``item/0`` is always ut1's entry and
its categories (``adult``, ``publicite``, ...) are the validated selection set.

As with the sibling Tier-B suites the oracle is the box's EFFECTIVE state --
``config.xml`` read via :func:`tests.smoke.helpers.config_get` (or, for the
``item`` list, a faithful PHP read that walks ``item`` exactly as the page's own
``foreach`` does, immune to single-element list-collapse) -- NEVER the HTTP
response body. Every flow is a TRUE transition test (CLAUDE.md): it asserts the
ORIGINAL value, drives the POST, asserts the NEW value, then restores in a
``finally`` so a mid-test failure cannot poison the session-scoped VM, and a
green proves the POST CAUSED the change rather than the end-state holding already.

Two POST mechanics are needed, and the page forces the choice (Batch-2 lesson:
the form-scrape ``webui.post`` cannot faithfully reproduce a browser's multi-value
same-name POST, and here it would also collide with the ``blacklist_selected``
multi-select and re-check whatever category boxes the form currently renders):

* the SAVE-button path (``isset($_POST['save'])`` -> the full validate/persist
  block, lines 178-296) -- driven with a FULLY-CONTROLLED direct
  ``session.post`` payload (GET for the ``__csrf_magic`` token, then
  ``webui.session.post`` with every required field enumerated), so the test owns
  the exact field set and no scraped checkbox/multi-select sneaks in. This mirrors
  the direct-post pattern the alerts/AJAX flows use for ``act=`` handlers.
* the ENABLE/LANG AUTO-SUBMIT path -- the page's JS ``$('form').submit()`` on a
  ``blacklist_enable`` / ``blacklist_lang`` change fires a POST WITHOUT the Save
  button, and the handler writes those two scalars on ``isset($_POST[field])``
  alone (lines 160-176) then ``write_config()`` at line 288 (``$config_mod &&
  !$input_errors``) -- a config-mod path with NO ``save``. ``webui.post`` always
  appends ``save=save`` so it cannot reproduce that arm; the direct payload OMITS
  ``save`` to exercise it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .webui import extract_csrf_token, looks_like_login_page

if TYPE_CHECKING:
    from .webui import WebUI

pytestmark = pytest.mark.ui_e2e

# Page + config roots (bare node -- NO /config/0).
BLACKLIST_PAGE = "/pfblockerng/pfblockerng_blacklist.php"
CFG_ROOT = "installedpackages/pfblockerngblacklist"
CFG_ENABLE = f"{CFG_ROOT}/blacklist_enable"
CFG_LANG = f"{CFG_ROOT}/blacklist_lang"
CFG_LOGGING = f"{CFG_ROOT}/blacklist_logging"

# The single live provider on the smoke image (ut1_global_usage). shallalist is
# dropped by the page, and ut1 has no REG: line -> no username/password fields.
PROVIDER_XML = "ut1"
# A valid ut1 category token (NAME: adult) and a token that is NOT a ut1 category.
# 'adult' is a real category (it is also a "large" category that triggers the
# page's savemsg redirect AFTER write_config -- the config still persists first).
VALID_CATEGORY = "adult"
BOGUS_CATEGORY = "definitely-not-a-ut1-category"

# Generous POST timeout: the blacklist save only write_config()s (no reload, no
# feed download -- feeds fetch on Force Update/CRON only), but match the sibling
# suites' headroom so a slow round-trip never trips pytest-timeout spuriously.
SAVE_TIMEOUT = 120.0


def _csrf_token(webui: WebUI) -> str:
    """GET the blacklist page and return its freshly-injected ``__csrf_magic`` token.

    The csrf-magic output filter rewrites the token per render, so it MUST be
    re-extracted from a current GET (never cached). Raises via
    :func:`extract_csrf_token` if the page did not render the token (e.g. the
    session lapsed and the login form came back instead).
    """
    resp = webui.get(BLACKLIST_PAGE)
    assert not looks_like_login_page(resp.text), "GET blacklist page returned the login form (session lost)"
    return extract_csrf_token(resp.text)


def _direct_post(webui: WebUI, data: dict[str, str], *, timeout: float = SAVE_TIMEOUT) -> None:
    """POST a FULLY-CONTROLLED payload to the blacklist page (token added here).

    Bypasses the form-scrape ``webui.post`` so the caller owns the EXACT field set
    -- no scraped multi-select / checkbox can perturb a field the test is not
    asserting. The ``__csrf_magic`` token is fetched from a current GET and
    prepended; the caller supplies everything else (``save`` is included only when
    the SAVE path is wanted -- the auto-submit path omits it deliberately). The
    response body is NOT the oracle: callers re-read config.xml.
    """
    token = _csrf_token(webui)
    payload = {"__csrf_magic": token, **data}
    resp = webui.session.post(
        webui.url(BLACKLIST_PAGE),
        data=payload,
        verify=webui._verify,
        timeout=timeout,
        allow_redirects=True,
    )
    assert not looks_like_login_page(resp.text), "blacklist POST returned the login form (session lost)"


def _save_payload(**fields: str) -> dict[str, str]:
    """A minimal SAVE-path payload: the five scalar selects + ``save`` + overrides.

    The save handler writes ``blacklist_selected`` on the ELSE arm when the field
    is ABSENT (line 212 -> stores ''), so it must always be present to avoid an
    accidental clear; the other scalars are written only on ``isset`` and a sane
    value keeps the select-validator (lines 187-194) from coercing them. Callers
    add the per-provider ``blacklist_<xml>[]`` category field (or omit it to clear
    that provider's selection). Defaults keep a quiet, valid baseline; pass
    keyword overrides to change a specific field.
    """
    base = {
        "blacklist_enable": "Disable",
        "blacklist_lang": "EN",
        "blacklist_selected": PROVIDER_XML,
        "blacklist_freq": "Never",
        "blacklist_logging": "enabled",
        "save": "save",
    }
    base.update(fields)
    return base


def _provider_selected(vm: helpers.SmokeVM, xml: str = PROVIDER_XML) -> str:
    """The ``selected`` category CSV stored for provider ``xml``, read the inc's way.

    Walks ``installedpackages/pfblockerngblacklist/item`` exactly as the page and
    ``pfblockerng.inc`` do (``foreach ($item) if ($item['xml'] == $xml)``), so the
    oracle is immune to whether a single-element ``item`` list serialised as a
    1-element list or collapsed to a bare assoc -- either way the matching entry's
    ``selected`` is returned. '' when no entry matches / none is stored.
    """
    pre = (
        f"$items = config_get_path({helpers._php_str(CFG_ROOT + '/item')}, array());\n"
        "if (isset($items['xml'])) { $items = array($items); }\n"  # tolerate single-assoc collapse
        "$out = '';\n"
        "foreach ($items as $it) {\n"
        f"  if (($it['xml'] ?? '') === {helpers._php_str(xml)}) {{ $out = (string) ($it['selected'] ?? ''); break; }}\n"
        "}"
    )
    return helpers._php_read_scalar(vm, pre, "$out")


# --------------------------------------------------------------------------- #
# 1) Settings select toggle -- blacklist_logging (enabled <-> disabled).
#    A pure write_config() select on the SAVE path; branch coverage drives BOTH
#    values and the transition proves each POST caused the change. Driven with a
#    controlled payload so the scrape can't disturb blacklist_selected / item.
# --------------------------------------------------------------------------- #


def test_blacklist_logging_select_toggles_both_ways(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """``blacklist_logging`` stores 'enabled' and 'disabled' -- both save-path arms.

    Options map ``{enabled, disabled}`` (node default 'enabled'). A valid key is
    stored verbatim (line 221 ``?:''`` keeps a truthy key). True transition: assert
    the original, flip to the OTHER value (assert), flip back (assert), restore.
    """
    vm = smoke_vm
    original = helpers.config_get(vm, CFG_LOGGING)
    # The read default is 'enabled'; treat an unset ('') original as 'enabled'.
    baseline = original or "enabled"
    other = "disabled" if baseline == "enabled" else "enabled"
    try:
        # BEFORE: a known value of the two-option set.
        assert baseline in ("enabled", "disabled"), f"unexpected blacklist_logging baseline {original!r}"
        # Flip to the other value.
        _direct_post(webui, _save_payload(blacklist_logging=other))
        assert helpers.config_get(vm, CFG_LOGGING) == other, f"blacklist_logging did not flip to {other!r}"
        # Flip back.
        _direct_post(webui, _save_payload(blacklist_logging=baseline))
        assert helpers.config_get(vm, CFG_LOGGING) == baseline, f"blacklist_logging did not return to {baseline!r}"
    finally:
        _direct_post(webui, _save_payload(blacklist_logging=baseline))


def test_blacklist_logging_select_coerces_bogus_to_default(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """A bogus ``blacklist_logging`` value coerces to the default 'enabled' (save succeeds).

    Select-validator (lines 187-194): a value that is not a key of
    ``$options_blacklist_logging`` is replaced with the field default '' -> the
    trailing ``?:''`` at line 221 leaves it '' as stored... but the validator's
    default for this field is 'enabled' (``$select_options['blacklist_logging'] =>
    'enabled'``), so a bogus value becomes 'enabled' and is written. SOFT coerce,
    NOT an abort: config holds 'enabled' (the default), not the bogus token.

    Transition: drive a valid 'disabled' (assert), THEN a bogus value (assert it
    coerced to 'enabled') -- so the green proves the bogus POST was coerced, not
    that the box already held 'enabled'.
    """
    vm = smoke_vm
    original = helpers.config_get(vm, CFG_LOGGING)
    baseline = original or "enabled"
    try:
        # VALID 'disabled' first so the coercion target ('enabled') is a real change.
        _direct_post(webui, _save_payload(blacklist_logging="disabled"))
        assert helpers.config_get(vm, CFG_LOGGING) == "disabled", "valid 'disabled' did not persist"
        # BOGUS -> coerced to the default 'enabled' (save still succeeds).
        _direct_post(webui, _save_payload(blacklist_logging="bogus_value"))
        got = helpers.config_get(vm, CFG_LOGGING)
        assert got == "enabled", f"bogus blacklist_logging should coerce to default 'enabled', got {got!r}"
    finally:
        _direct_post(webui, _save_payload(blacklist_logging=baseline))


# --------------------------------------------------------------------------- #
# 2) Per-provider category save -- enable a ut1 category, then clear it.
#    The save builds item[] (one entry per provider) and stores the selected CSV.
#    VALID category -> stored; clearing (omit the provider field) -> ''.
# --------------------------------------------------------------------------- #


def test_blacklist_provider_category_enable_and_clear(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """Enabling a valid ut1 category stores it in ``item``; clearing stores ''.

    The Form_Checkbox name is ``blacklist_ut1[]`` -> PHP parses it as the array
    ``$_POST['blacklist_ut1']``. With one value it validates (line 238 is_array
    arm), and ``$list['selected'] = implode(',', (array)...)`` stores 'adult' on
    ``item``'s ut1 entry. Clearing OMITS the ``blacklist_ut1[]`` field entirely (a
    browser sends nothing for an unchecked box) -> ``$_POST['blacklist_ut1']``
    unset -> selected ''. (Posting an EMPTY value would instead make is_array
    ``['']`` validate '' -> a bogus-selection input_error that aborts the save, so
    the clear MUST omit the field, which the controlled payload does.)

    True transition: establish a known clear baseline, assert selected is '', POST
    'adult' (assert 'adult'), POST the clear (assert '' again).
    """
    vm = smoke_vm
    cat_field = f"blacklist_{PROVIDER_XML}[]"
    original = _provider_selected(vm)
    try:
        # BEFORE: drive to a known clear state (no category for ut1) and assert ''.
        _direct_post(webui, _save_payload())  # no blacklist_ut1[] -> selection cleared
        assert _provider_selected(vm) == "", "ut1 selection should be empty after the clearing baseline POST"
        # ENABLE a valid category -> stored on item.
        _direct_post(webui, _save_payload(**{cat_field: VALID_CATEGORY}))
        got = _provider_selected(vm)
        assert got == VALID_CATEGORY, f"ut1 selection should be {VALID_CATEGORY!r} after enabling it, got {got!r}"
        # CLEAR again (omit the field) -> back to ''.
        _direct_post(webui, _save_payload())
        assert _provider_selected(vm) == "", "ut1 selection should be empty again after the clearing POST"
    finally:
        # Restore the original selection (CSV). An empty original clears it; a
        # non-empty original re-sends each token under the array field.
        if original:
            _direct_post(webui, _save_payload(**{cat_field: original}))
        else:
            _direct_post(webui, _save_payload())


# --------------------------------------------------------------------------- #
# 3) Category validation reject -- a bogus category aborts the WHOLE save.
#    The save is all-or-nothing: a category not in the provider's CATEGORIES set
#    appends to $input_errors -> the `if ($config_mod && !isset($input_errors))`
#    guard skips write_config -> config UNCHANGED (the bad POST does not persist).
# --------------------------------------------------------------------------- #


def test_blacklist_bogus_category_rejected_config_unchanged(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """A bogus ut1 category triggers an input_error -> the whole save aborts (config unchanged).

    ``$validate_categories = array_flip($blacklist_types['ut1']['CATEGORIES'])`` is
    the valid set. A submitted token absent from it -> ``$input_errors[]`` (line
    242/249) -> the trailing ``if ($config_mod && !isset($input_errors))`` (line
    288) is false -> NO write_config -> ``item`` keeps its prior value. So the
    reject oracle is "selected == the pre-POST value", NOT the bogus token and NOT
    cleared.

    Transition with a real before-state: first store a VALID category ('adult')
    and assert it; THEN POST the bogus category and assert ``item`` still holds
    'adult' (the bogus POST changed nothing).
    """
    vm = smoke_vm
    cat_field = f"blacklist_{PROVIDER_XML}[]"
    original = _provider_selected(vm)
    try:
        # Seed a known-good selection so "unchanged" is observable (not just '').
        _direct_post(webui, _save_payload(**{cat_field: VALID_CATEGORY}))
        seeded = _provider_selected(vm)
        assert seeded == VALID_CATEGORY, f"failed to seed a valid ut1 category, got {seeded!r}"
        # REJECT: a bogus category aborts the whole save -> item UNCHANGED.
        _direct_post(webui, _save_payload(**{cat_field: BOGUS_CATEGORY}))
        got = _provider_selected(vm)
        assert got == VALID_CATEGORY, (
            f"bogus category must abort the save and leave ut1 selection unchanged at {VALID_CATEGORY!r}, got {got!r}"
        )
    finally:
        if original:
            _direct_post(webui, _save_payload(**{cat_field: original}))
        else:
            _direct_post(webui, _save_payload())


# --------------------------------------------------------------------------- #
# 4) enable / lang AUTO-SUBMIT path -- config_mod WITHOUT the Save button.
#    The page's JS submits the form on a blacklist_enable/blacklist_lang change;
#    that POST carries NO `save`, yet the handler writes those scalars on
#    `isset($_POST[field])` (lines 160-176) and write_config()s at line 288. The
#    direct payload OMITS `save` to exercise exactly this arm (webui.post can't).
# --------------------------------------------------------------------------- #


def test_blacklist_enable_autosubmit_persists_without_save(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """``blacklist_enable`` persists via the auto-submit (no-``save``) path, both ways.

    With ``isset($_POST['blacklist_enable'])`` and NO ``save``, lines 160-167 set
    the node and config_mod=TRUE; the ``save`` block is skipped; line 288 writes
    config. So the scalar persists with NO ``save`` in the payload. Options map
    ``{Disable, Enable}``; an unknown value coerces to 'Disable' (line 161-162).

    Transition + branch coverage: drive 'Enable' (assert), drive 'Disable'
    (assert), and a bogus value (assert it coerced to 'Disable'). The restore
    target is 'Disable' -- equivalent to the read default ('' ``?: 'Disable'``),
    so an originally-unset node is left in its effective default.
    """
    vm = smoke_vm
    original = helpers.config_get(vm, CFG_ENABLE)
    # '' (unset) reads as 'Disable' on the page; restore there.
    restore = original or "Disable"
    try:
        assert restore in ("Disable", "Enable"), f"unexpected blacklist_enable baseline {original!r}"
        # AUTO-SUBMIT 'Enable' (NO save in the payload) -> persists 'Enable'.
        _direct_post(webui, {"blacklist_enable": "Enable"})
        got_enable = helpers.config_get(vm, CFG_ENABLE)
        assert got_enable == "Enable", f"blacklist_enable did not persist 'Enable' (no-save path), got {got_enable!r}"
        # AUTO-SUBMIT 'Disable' -> persists 'Disable'.
        _direct_post(webui, {"blacklist_enable": "Disable"})
        assert helpers.config_get(vm, CFG_ENABLE) == "Disable", "blacklist_enable did not return to 'Disable'"
        # BOGUS value -> coerced to 'Disable' (line 161-162), still written.
        _direct_post(webui, {"blacklist_enable": "Bogus"})
        got = helpers.config_get(vm, CFG_ENABLE)
        assert got == "Disable", f"bogus blacklist_enable should coerce to 'Disable', got {got!r}"
    finally:
        _direct_post(webui, {"blacklist_enable": restore})


def test_blacklist_lang_autosubmit_persists_without_save(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """``blacklist_lang`` persists via the auto-submit (no-``save``) path; bogus coerces to 'EN'.

    Same no-``save`` arm as ``blacklist_enable`` (lines 169-176): the scalar is
    written on ``isset`` alone, an unknown value coerces to the default 'EN' (line
    170-171). Options include EN/DE/FR/... -- a valid 'DE' is a real change from
    the 'EN' default.

    Transition: assert the original, drive a VALID 'DE' (assert), drive a bogus
    value (assert it coerced to 'EN'), restore.
    """
    vm = smoke_vm
    original = helpers.config_get(vm, CFG_LANG)
    restore = original or "EN"
    try:
        assert original != "DE", f"blacklist_lang already 'DE' before the valid POST (original={original!r})"
        # VALID 'DE' via the no-save path.
        _direct_post(webui, {"blacklist_lang": "DE"})
        assert helpers.config_get(vm, CFG_LANG) == "DE", "blacklist_lang did not persist 'DE' (no-save path)"
        # BOGUS -> coerced to the default 'EN'.
        _direct_post(webui, {"blacklist_lang": "ZZ"})
        got = helpers.config_get(vm, CFG_LANG)
        assert got == "EN", f"bogus blacklist_lang should coerce to default 'EN', got {got!r}"
    finally:
        _direct_post(webui, {"blacklist_lang": restore})
