"""Tier-B functional WebUI flows for the alias CRUD page (ADR-14 Phase 3).

Marker ``ui_e2e`` -- daily / on-demand, NOT in the default run nor the PR gate
(the whole ``tests/smoke`` tree is ``--ignore``d in the default
``python -m pytest``; this tier is run with
``pytest tests/smoke -m ui_e2e --override-ini="addopts="``).

This file drives ``pfblockerng_category_edit.php`` -- the alias add/edit form
that is the CRUD heart of pfBlockerNG. Its save handler (gated on
``isset($_POST['save'])``) dispatches on ``$_POST['type']`` (``ipv4`` / ``ipv6``
/ ``dnsbl`` -> ``$conf_type`` ``pfblockernglistsv4`` / ``pfblockernglistsv6`` /
``pfblockerngdnsbl``) and ``$_POST['rowid']``, and writes the alias under
``installedpackages/{conf_type}/config/{rowid}/...`` (aliasname, action, the
source ``row/<n>`` table, plus the DNSBL scalars logging/order/filter_alexa).

As in ``test_functional.py`` the oracle is ALWAYS the box's EFFECTIVE state --
``config.xml`` read via :func:`tests.smoke.helpers.config_get` -- never the HTTP
response body. Every flow is a TRUE transition test (CLAUDE.md): it asserts the
BEFORE-state, drives the POST, asserts the AFTER-state, and restores in a
``finally`` so a mid-test failure cannot poison the session-scoped VM.

POST strategy (Batch-2 learning): the page's source table is a JS rowhelper whose
multi-row ``state-<n>`` / ``url-<n>`` / ``header-<n>`` collision the form-scrape
cannot faithfully reproduce, so these flows do NOT route through
:meth:`WebUI.post` (the scrape "save" helper). Instead -- like
``test_alerts.py``'s ``act=`` pattern -- each GETs the page to harvest a fresh
``__csrf_magic`` token, then POSTs a FULLY-enumerated payload via
``webui.session.post`` (every field the handler reads is supplied a valid value,
so no select coerces and no rowhelper row is dropped). The single placeholder
source row is posted ``state-0='Disabled'`` so the URL/header validation arm
(``$value != 'Disabled'``) is skipped -- a clean, hermetic save with no feed
download.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .webui import extract_csrf_token, looks_like_login_page

if TYPE_CHECKING:
    from .webui import WebUI

pytestmark = pytest.mark.ui_e2e

CATEGORY_PAGE = "/pfblockerng/pfblockerng_category_edit.php"

# config roots the save handler writes (mirrors $conf_type in the PHP).
CFG_DNSBL = "installedpackages/pfblockerngdnsbl/config"
CFG_IPV4 = "installedpackages/pfblockernglistsv4/config"

# Generous POST timeout: the save only write_config()s (no reload / no egress),
# but pfSsh.php-backed config reads around it can run long on a busy box.
SAVE_TIMEOUT = 120.0


def _free_rowid(vm: helpers.SmokeVM, cfg_root: str) -> int:
    """Return an index under ``cfg_root`` that does NOT clobber an existing alias.

    The save handler writes ``{cfg_root}/{rowid}/...`` straight from
    ``$_POST['rowid']``. Other suites (and prior cases) may have left aliases in
    ``cfg_root``, so picking ``rowid=0`` blindly could overwrite a real one.
    Compute ``max(existing numeric keys) + 1`` (or 0 when the list is empty) via
    the pfSense config API -- a fresh, guaranteed-free slot we own and delete.
    """
    pre = (
        f"$c = config_get_path({helpers._php_str(cfg_root)}, array());\n"
        "$max = -1;\n"
        "foreach (array_keys($c) as $k) { if (is_numeric($k) && (int)$k > $max) { $max = (int)$k; } }\n"
        "$free = $max + 1;"
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
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_del_rowid({cfg_root}/{rowid}) failed: rc={result.returncode} {result.stdout!r}")


def _post_form(webui: WebUI, payload: dict[str, str]) -> None:
    """POST a fully-enumerated category-edit payload (token harvested fresh).

    GETs the page to obtain a current ``__csrf_magic`` (the csrf-magic output
    filter rotates it per render), injects it + the ``save`` submit button into
    ``payload``, and POSTs directly via the raw session -- NOT the form-scrape
    (the rowhelper table cannot be reproduced by the scrape). Mirrors the
    ``test_alerts.py`` direct-post pattern.
    """
    get = webui.get(CATEGORY_PAGE, params={"type": payload.get("type", "dnsbl")})
    assert not looks_like_login_page(get.text), "category GET returned the login form (session lost)"
    token = extract_csrf_token(get.text)
    data = dict(payload)
    data["__csrf_magic"] = token
    data["save"] = "save"
    resp = webui.session.post(webui.url(CATEGORY_PAGE), data=data, verify=webui._verify, timeout=SAVE_TIMEOUT)
    assert not looks_like_login_page(resp.text), "category POST returned the login form (session lost)"


def _dnsbl_payload(rowid: int, aliasname: str, **overrides: str) -> dict[str, str]:
    """A complete, valid DNSBL alias save payload (one Disabled placeholder row).

    Every <select> the validator inspects (action/cron/dow/sort/order/logging +
    the ip-only ones) is given a value that is a KEY of its options map, so the
    select-coercion loop (lines 478-488) never rewrites it; the lone source row is
    ``state-0='Disabled'`` so the URL/header validation arm is skipped. ``custom``
    is empty so the custom-list validator is skipped and ``pfb_determine_list_detail``
    is NOT triggered (the base64('')=='' "unchanged" branch).
    """
    payload = {
        "type": "dnsbl",
        "rowid": str(rowid),
        "aliasname": aliasname,
        "description": "smoke category-edit",
        "action": "unbound",
        "cron": "Never",
        "dow": "",
        "sort": "sort",
        "order": "default",
        "logging": "enabled",
        "filter_alexa": "",
        "srcint": "",
        "script_pre": "",
        "script_post": "",
        "custom": "",
        # Single placeholder source row: Disabled -> source validation skipped.
        "format-0": "auto",
        "state-0": "Disabled",
        "url-0": "",
        "header-0": "",
    }
    payload.update(overrides)
    return payload


# --------------------------------------------------------------------------- #
# Representative full SAVE: create a DNSBL alias, assert the KEY persisted nodes.
# --------------------------------------------------------------------------- #


def test_dnsbl_alias_full_save_persists_key_nodes(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """A DNSBL alias save persists aliasname + action + one source row + logging.

    The CRUD heart: drive a complete CSRF form POST for a brand-new DNSBL alias at
    a free rowid and assert the handler wrote the key config nodes
    (``aliasname`` / ``action`` / ``row/0/state`` / ``logging``) under
    ``installedpackages/pfblockerngdnsbl/config/{rowid}``. Transition rule: the
    rowid is FREE first (every target node reads '' before the POST), then the
    POST creates them. Oracle = config.xml over SSH; the slot is deleted in
    ``finally`` so the box is left clean.
    """
    vm = smoke_vm
    rowid = _free_rowid(vm, CFG_DNSBL)
    base = f"{CFG_DNSBL}/{rowid}"
    aliasname = "smokecatedit"
    try:
        # BEFORE: the free slot is empty (the POST must CAUSE every node below).
        assert helpers.config_get(vm, f"{base}/aliasname") == "", f"rowid {rowid} not free (aliasname already set)"
        assert helpers.config_get(vm, f"{base}/action") == "", f"rowid {rowid} not free (action already set)"

        _post_form(webui, _dnsbl_payload(rowid, aliasname))

        # AFTER: the key alias nodes landed in config.xml.
        assert helpers.config_get(vm, f"{base}/aliasname") == aliasname, "aliasname not persisted by the save"
        assert helpers.config_get(vm, f"{base}/action") == "unbound", "action not persisted by the save"
        assert helpers.config_get(vm, f"{base}/logging") == "enabled", "logging not persisted by the save"
        assert helpers.config_get(vm, f"{base}/row/0/state") == "Disabled", "source row state not persisted"
    finally:
        _del_rowid(vm, CFG_DNSBL, rowid)


# --------------------------------------------------------------------------- #
# Negative SAVE: a bad aliasname aborts the whole save (config UNCHANGED).
# --------------------------------------------------------------------------- #


def test_dnsbl_alias_bad_name_rejected_leaves_config_unchanged(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """An aliasname with a non-word char aborts the save -> the alias is UNCHANGED.

    ``preg_match("/\\W/", $_POST['aliasname'])`` (and the empty-name guard) append
    to ``$input_errors``; the ``if (!$input_errors)`` block is then skipped, so NO
    config node is written. Transition: first establish a KNOWN-GOOD alias at the
    rowid (a valid save, aliasname asserted), THEN POST a bad name (a space ->
    ``\\W``) to the SAME rowid and assert the aliasname is UNCHANGED (the save
    aborted) -- proving the reject is a real branch, not an always-unchanged path.
    """
    vm = smoke_vm
    rowid = _free_rowid(vm, CFG_DNSBL)
    base = f"{CFG_DNSBL}/{rowid}"
    good = "smokecatok"
    try:
        # Seed a valid alias through the form so the rowid holds a known good name.
        _post_form(webui, _dnsbl_payload(rowid, good))
        assert helpers.config_get(vm, f"{base}/aliasname") == good, "precondition: valid alias did not persist"

        # REJECT: a space makes aliasname match /\W/ -> the whole save aborts.
        _post_form(webui, _dnsbl_payload(rowid, "bad name"))
        assert helpers.config_get(vm, f"{base}/aliasname") == good, (
            "a bad aliasname must abort the save (alias unchanged), but it changed"
        )
    finally:
        _del_rowid(vm, CFG_DNSBL, rowid)


# --------------------------------------------------------------------------- #
# DNSBL scalar selects/toggle: logging (valid + bogus-coerce), order, filter_alexa.
# --------------------------------------------------------------------------- #


def test_dnsbl_logging_select_valid_and_bogus_coerces_to_default(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """``logging`` stores a valid key, and a bogus value coerces to the default.

    ``$options_logging`` keys are enabled / disabled / disabled_log. The
    select-coercion loop replaces a non-key value with ``$select_options['logging']``
    -- which is the literal ``'Enabled'`` (capital E; NOT itself a key of
    ``$options_logging``), and the save SUCCEEDS storing that default. Branch
    coverage: drive a valid 'enabled', then a valid 'disabled' (the distinct second
    key), then a bogus 'bogus' that coerces to 'Enabled'. Transition: each step
    asserts the value differs before it is driven.
    """
    vm = smoke_vm
    rowid = _free_rowid(vm, CFG_DNSBL)
    base = f"{CFG_DNSBL}/{rowid}"
    cfg = f"{base}/logging"
    try:
        # Create the alias with logging=enabled.
        _post_form(webui, _dnsbl_payload(rowid, "smokelog", logging="enabled"))
        assert helpers.config_get(vm, cfg) == "enabled", "logging not stored as 'enabled'"
        # VALID second key -> stored verbatim (a real transition).
        _post_form(webui, _dnsbl_payload(rowid, "smokelog", logging="disabled"))
        assert helpers.config_get(vm, cfg) == "disabled", "logging not stored as 'disabled'"
        # BOGUS -> coerced to the default 'Enabled' (save SUCCEEDS, value != bogus).
        _post_form(webui, _dnsbl_payload(rowid, "smokelog", logging="bogus"))
        got = helpers.config_get(vm, cfg)
        assert got == "Enabled", f"bogus logging should coerce to default 'Enabled', got {got!r}"
    finally:
        _del_rowid(vm, CFG_DNSBL, rowid)


def test_dnsbl_order_select_transition(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """``order`` stores both option keys (default / primary) across a transition.

    ``$options_order`` = {default, primary}. Branch coverage drives each key:
    create with 'default' (assert), then flip to 'primary' (assert), then back to
    'default' (assert) -- proving the POST causes each change.
    """
    vm = smoke_vm
    rowid = _free_rowid(vm, CFG_DNSBL)
    cfg = f"{CFG_DNSBL}/{rowid}/order"
    try:
        _post_form(webui, _dnsbl_payload(rowid, "smokeord", order="default"))
        assert helpers.config_get(vm, cfg) == "default", "order not stored as 'default'"
        _post_form(webui, _dnsbl_payload(rowid, "smokeord", order="primary"))
        assert helpers.config_get(vm, cfg) == "primary", "order not stored as 'primary'"
        _post_form(webui, _dnsbl_payload(rowid, "smokeord", order="default"))
        assert helpers.config_get(vm, cfg) == "default", "order not restored to 'default'"
    finally:
        _del_rowid(vm, CFG_DNSBL, rowid)


def test_dnsbl_filter_alexa_checkbox_both_ways(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """``filter_alexa`` (TOP1M Whitelist checkbox) stores 'on' when set, '' when clear.

    Written via ``pfb_filter($_POST['filter_alexa'], PFB_FILTER_ON_OFF, ...)`` ->
    'on' iff the POST value is 'on', else ''. Branch coverage: create with it ON
    (assert 'on'), then save with it cleared (assert ''), then ON again. A browser
    omits an unchecked box; the cleared POST sends the empty value, which the
    PFB_FILTER_ON_OFF filter stores as ''.
    """
    vm = smoke_vm
    rowid = _free_rowid(vm, CFG_DNSBL)
    cfg = f"{CFG_DNSBL}/{rowid}/filter_alexa"
    try:
        _post_form(webui, _dnsbl_payload(rowid, "smokealexa", filter_alexa="on"))
        assert helpers.config_get(vm, cfg) == "on", "filter_alexa not stored 'on'"
        _post_form(webui, _dnsbl_payload(rowid, "smokealexa", filter_alexa=""))
        assert helpers.config_get(vm, cfg) == "", "filter_alexa not cleared to ''"
        _post_form(webui, _dnsbl_payload(rowid, "smokealexa", filter_alexa="on"))
        assert helpers.config_get(vm, cfg) == "on", "filter_alexa not re-set 'on'"
    finally:
        _del_rowid(vm, CFG_DNSBL, rowid)


# --------------------------------------------------------------------------- #
# IPv4 alias: a valid Deny_Both save persists, and the Permit_Inbound + 'Any'
# protocol guard aborts the save (config UNCHANGED).
# --------------------------------------------------------------------------- #


def _ipv4_payload(rowid: int, aliasname: str, **overrides: str) -> dict[str, str]:
    """A complete IPv4 alias save payload (one Disabled placeholder row).

    IPv4 ($conf_type pfblockernglistsv4) carries the advanced-firewall fields the
    Permit guard inspects (autoproto_in / aliasports_in / aliasaddr_in). Defaults
    here keep adv-inbound OFF and a concrete-but-unused protocol so a plain
    Deny_Both save is clean; tests override ``action`` / ``autoproto_in`` to drive
    the guard. aliasname stays <= 24 chars (the PF length cap).
    """
    payload = {
        "type": "ipv4",
        "rowid": str(rowid),
        "aliasname": aliasname,
        "description": "smoke ipv4 category-edit",
        "action": "Deny_Both",
        "cron": "Never",
        "dow": "",
        "sort": "sort",
        "aliaslog": "enabled",
        "stateremoval": "enabled",
        "autoproto_in": "any",
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


def test_ipv4_alias_permit_any_guard_rejects_and_valid_persists(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """Permit_Inbound with protocol 'Any' aborts the IPv4 save; Deny_Both persists.

    The guard (lines 623-640): ``action`` in {Permit_Inbound, Permit_Both} AND
    (``autoproto_in`` empty or 'any') OR (no custom port/dest) -> ``$input_errors``
    -> the whole save aborts -> config UNCHANGED. Transition: first a VALID
    Deny_Both save establishes ``action='Deny_Both'`` at the rowid (asserted), then
    a Permit_Inbound + autoproto_in='any' POST (with no custom port/dest) is
    REJECTED, leaving ``action`` UNCHANGED at 'Deny_Both' -- proving the guard is a
    real reject branch, not an always-unchanged path.
    """
    vm = smoke_vm
    rowid = _free_rowid(vm, CFG_IPV4)
    cfg = f"{CFG_IPV4}/{rowid}/action"
    try:
        # BEFORE: free slot, no action stored.
        assert helpers.config_get(vm, cfg) == "", f"ipv4 rowid {rowid} not free (action already set)"
        # VALID Deny_Both -> persisted.
        _post_form(webui, _ipv4_payload(rowid, "smokeip4", action="Deny_Both"))
        assert helpers.config_get(vm, cfg) == "Deny_Both", "valid Deny_Both action did not persist"
        # REJECT: Permit_Inbound + proto 'Any' + no custom port/dest -> save aborts.
        _post_form(webui, _ipv4_payload(rowid, "smokeip4", action="Permit_Inbound", autoproto_in="any"))
        assert helpers.config_get(vm, cfg) == "Deny_Both", (
            "Permit_Inbound + 'Any' must abort the save (action unchanged at Deny_Both)"
        )
    finally:
        _del_rowid(vm, CFG_IPV4, rowid)


# --------------------------------------------------------------------------- #
# ASN autocomplete JSON endpoint (?term=...) -- read-only GET, assert JSON shape.
# --------------------------------------------------------------------------- #


def test_asn_autocomplete_term_returns_json_list(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """The ASN autocomplete (``isAjax`` + ``?term=...``) returns a JSON array.

    The page's top branch (lines 34-66) serves an AJAX JSON list when
    ``isAjax()`` AND ``$_GET['term']`` has length > 2: it filters the cached ASN
    list (``pfblockerng_asn.txt``) by the term and ``echo json_encode($result)``;
    when the file is absent the cache is ``[]`` -> an empty JSON array. Either way
    the RESPONSE SHAPE is a JSON list -- this is read-only (no config write), so
    it is safe to assert directly. ``isAjax()`` keys on the
    ``X-Requested-With: XMLHttpRequest`` header, which we send.
    """
    resp = webui.get(
        CATEGORY_PAGE,
        params={"term": "AS3"},
        headers={"X-Requested-With": "XMLHttpRequest"},
    )
    assert resp.status_code == 200, f"ASN autocomplete -> HTTP {resp.status_code} (expected 200)"
    assert not looks_like_login_page(resp.text), "ASN autocomplete returned the login form (session lost)"
    parsed = json.loads(resp.text)
    assert isinstance(parsed, list), f"ASN autocomplete must return a JSON list, got {type(parsed).__name__}"
    # Each returned entry (if any) is a string ASN line from the cached list.
    assert all(isinstance(item, str) for item in parsed), "ASN autocomplete list entries must be strings"
