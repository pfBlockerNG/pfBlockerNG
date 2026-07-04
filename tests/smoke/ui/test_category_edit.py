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
import re
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
CFG_IPV6 = "installedpackages/pfblockernglistsv6/config"

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


# --------------------------------------------------------------------------- #
# Helpers: create / delete a firewall alias via the pfSense config API.
# --------------------------------------------------------------------------- #

_PORT_ALIAS_ADDR = "8080"
_NET_ALIAS_CIDR = "192.0.2.0/24"  # RFC 5737 — safe, never routed


def _input_tag(body: str, name: str) -> str:
    """Return the single ``<input ... name="<name>" ...>`` tag from a form body.

    Used to assert the RELOADED edit page rendered a field's saved state on the
    field ITSELF (not merely that the attribute exists somewhere on the page) --
    a bare ``'checked' in body`` would pass on any page that has any checked box.
    Returns '' when no such input is present.
    """
    m = re.search(r'<input\b[^>]*\bname="' + re.escape(name) + r'"[^>]*>', body)
    return m.group(0) if m else ""


def _option_selected(body: str, value: str) -> bool:
    """True when a ``<option value="<value>" ... selected ...>`` is rendered."""
    return re.search(r'<option\b[^>]*\bvalue="' + re.escape(value) + r'"[^>]*\bselected\b', body) is not None


def _mk_alias(vm: helpers.SmokeVM, name: str, alias_type: str, address: str) -> None:
    """Append a pfSense firewall alias via the config API.

    Writes a single entry to ``aliases/alias`` and calls ``write_config``.
    ``alias_type`` must be ``'port'`` or ``'network'`` (the values
    ``alias_get_type()`` returns and the category-edit validation checks).
    """
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
    result = helpers.php_eval(vm, snippet, timeout=SAVE_TIMEOUT)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_mk_alias({name!r}) failed: rc={result.returncode} {result.stdout!r}")


def _rm_alias(vm: helpers.SmokeVM, name: str) -> None:
    """Remove the first firewall alias whose name matches ``name`` from the config."""
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
    result = helpers.php_eval(vm, snippet, timeout=SAVE_TIMEOUT)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_rm_alias({name!r}) failed: rc={result.returncode} {result.stdout!r}")


# --------------------------------------------------------------------------- #
# Advanced Inbound/Outbound: full field save + reload persistence.
# --------------------------------------------------------------------------- #


def test_ipv4_advanced_inout_full_save_persists_and_reloads(
    webui: "WebUI",
    smoke_vm: helpers.SmokeVM,
) -> None:
    """Advanced Inbound and Outbound firewall settings persist in config.xml and
    are reflected in the reloaded form.

    Scenario: saving a Deny_Both alias with all Advanced In/Out toggles and
    custom aliases stores the values, and reloading the edit page renders them.

    Background:
        The save handler (lines 741-764) writes each advanced field via
        ``config_set_path`` only when ``$gtype == 'ipv4'``. ``autoproto_*`` /
        ``aliasports_*`` / ``aliasaddr_*`` are validated: a non-'any' protocol is
        required when ``autoports_*`` or ``autoaddr_*`` is set (lines 604-614);
        the alias names must pass ``is_alias()`` + ``alias_get_type() in
        {network,port}`` (lines 593-601). We therefore create a real port alias
        and a real network alias first, use action=Deny_Both (no Permit guard),
        and supply non-any protocols (tcp / udp).

    Given:
        - A port alias and a network alias exist in the firewall config.
        - The target IPv4 rowid is free (all advanced keys read '').
    When:
        ``_post_form`` saves a Deny_Both alias with:
        - autoproto_in=tcp, autoports_in=on, aliasports_in=<port alias>,
          autoaddr_in=on, aliasaddr_in=<net alias>, autonot_in=on.
        - autoproto_out=udp, autoports_out=on, aliasports_out=<port alias>,
          autoaddr_out=on, aliasaddr_out=<net alias>, autonot_out=on.
    Then:
        - config.xml reflects the saved values for all eight advanced fields.
        - A GET of the edit page renders the saved values (checkboxes checked,
          alias names in value attributes, protocols selected).
    """
    vm = smoke_vm
    port_alias = "smkadvport"
    net_alias = "smkadvnet"
    rowid = _free_rowid(vm, CFG_IPV4)
    base = f"{CFG_IPV4}/{rowid}"

    _mk_alias(vm, port_alias, "port", _PORT_ALIAS_ADDR)
    _mk_alias(vm, net_alias, "network", _NET_ALIAS_CIDR)
    try:
        # BEFORE: all advanced keys at the free slot read '' (POST must CAUSE them).
        for key in (
            "autoproto_in",
            "autoports_in",
            "aliasports_in",
            "autoaddr_in",
            "aliasaddr_in",
            "autonot_in",
            "autoproto_out",
            "autoports_out",
            "aliasports_out",
            "autoaddr_out",
            "aliasaddr_out",
            "autonot_out",
        ):
            assert helpers.config_get(vm, f"{base}/{key}") == "", (
                f"rowid {rowid} not free: {key} already set before POST"
            )

        # WHEN: save with all Advanced Inbound and Outbound options populated.
        # action=Deny_Both avoids the Permit guard (lines 631-648).
        # Non-any protocols satisfy the proto guard (lines 604-614).
        _post_form(
            webui,
            _ipv4_payload(
                rowid,
                "smkadv",
                action="Deny_Both",
                autoproto_in="tcp",
                autoports_in="on",
                aliasports_in=port_alias,
                autoaddr_in="on",
                aliasaddr_in=net_alias,
                autonot_in="on",
                autoproto_out="udp",
                autoports_out="on",
                aliasports_out=port_alias,
                autoaddr_out="on",
                aliasaddr_out=net_alias,
                autonot_out="on",
            ),
        )

        # THEN (config.xml): every advanced field landed.
        assert helpers.config_get(vm, f"{base}/autoproto_in") == "tcp", "autoproto_in not persisted as 'tcp'"
        assert helpers.config_get(vm, f"{base}/autoports_in") == "on", "autoports_in toggle not persisted as 'on'"
        assert helpers.config_get(vm, f"{base}/aliasports_in") == port_alias, (
            f"aliasports_in not persisted as {port_alias!r}"
        )
        assert helpers.config_get(vm, f"{base}/autoaddr_in") == "on", "autoaddr_in toggle not persisted as 'on'"
        assert helpers.config_get(vm, f"{base}/aliasaddr_in") == net_alias, (
            f"aliasaddr_in not persisted as {net_alias!r}"
        )
        assert helpers.config_get(vm, f"{base}/autonot_in") == "on", "autonot_in toggle not persisted as 'on'"
        assert helpers.config_get(vm, f"{base}/autoproto_out") == "udp", "autoproto_out not persisted as 'udp'"
        assert helpers.config_get(vm, f"{base}/autoports_out") == "on", "autoports_out toggle not persisted as 'on'"
        assert helpers.config_get(vm, f"{base}/aliasports_out") == port_alias, (
            f"aliasports_out not persisted as {port_alias!r}"
        )
        assert helpers.config_get(vm, f"{base}/autoaddr_out") == "on", "autoaddr_out toggle not persisted as 'on'"
        assert helpers.config_get(vm, f"{base}/aliasaddr_out") == net_alias, (
            f"aliasaddr_out not persisted as {net_alias!r}"
        )
        assert helpers.config_get(vm, f"{base}/autonot_out") == "on", "autonot_out toggle not persisted as 'on'"

        # RELOAD: GET the edit page for this row and assert the form reflects
        # the saved state.  The pfSense form framework renders checked checkboxes
        # as ``<input ... checked>``, alias inputs as ``value="<name>"``, and
        # selected protocol options as ``<option ... selected>``.
        reload_resp = webui.get(CATEGORY_PAGE, params={"type": "ipv4", "rowid": str(rowid)})
        assert not looks_like_login_page(reload_resp.text), (
            "category GET (reload) returned the login form (session lost)"
        )
        body = reload_resp.text

        # The custom-alias text inputs must render with the saved alias name in
        # their OWN value attribute (not merely present somewhere on the page).
        for field, alias in (
            ("aliasports_in", port_alias),
            ("aliasaddr_in", net_alias),
            ("aliasports_out", port_alias),
            ("aliasaddr_out", net_alias),
        ):
            tag = _input_tag(body, field)
            assert tag, f"reloaded form has no input named {field!r}"
            assert f'value="{alias}"' in tag, f"reloaded {field!r} input did not render value={alias!r}: {tag}"

        # Each enabled toggle must render CHECKED on its OWN input (a bare
        # 'checked in body' would pass on any page with any checked box).
        for field in ("autoports_in", "autoaddr_in", "autonot_in", "autoports_out", "autoaddr_out", "autonot_out"):
            tag = _input_tag(body, field)
            assert tag, f"reloaded form has no input named {field!r}"
            assert "checked" in tag, f"reloaded {field!r} toggle did not render checked: {tag}"

        # The protocol <select>s must render the saved option as selected.
        assert _option_selected(body, "tcp"), "reloaded form did not render autoproto_in option 'tcp' as selected"
        assert _option_selected(body, "udp"), "reloaded form did not render autoproto_out option 'udp' as selected"

    finally:
        _del_rowid(vm, CFG_IPV4, rowid)
        _rm_alias(vm, port_alias)
        _rm_alias(vm, net_alias)


def test_ipv4_invert_toggles_persist_with_alias_native(
    webui: "WebUI",
    smoke_vm: helpers.SmokeVM,
) -> None:
    """Invert Source/Destination toggles persist when action=Alias_Native.

    Scenario: saving autoaddrnot_in=on and autoaddrnot_out=on with
    action=Alias_Native stores the values and the reloaded form reflects them.

    Background:
        The UI validation (lines 619-628) requires action=Alias_Native when
        either Invert toggle is set -- any other action results in an
        ``$input_errors`` abort. Alias_Native has no switch case in
        ``pfb_firewall_rule()`` and therefore emits no auto-rule; the alias is
        used directly in user-defined inverted rules. This test confirms the
        persistence path (save handler lines 745/754) stores the invert flags
        correctly when the required action is supplied.

    Given:
        The target IPv4 rowid is free (autoaddrnot_in and autoaddrnot_out read '').
    When:
        ``_post_form`` saves action=Alias_Native with autoaddrnot_in=on and
        autoaddrnot_out=on (the only valid combination per UI validation).
    Then:
        - config.xml stores autoaddrnot_in='on', autoaddrnot_out='on',
          action='Alias_Native'.
        - The reloaded edit page body reflects the saved invert state.
    """
    vm = smoke_vm
    rowid = _free_rowid(vm, CFG_IPV4)
    base = f"{CFG_IPV4}/{rowid}"

    try:
        # BEFORE: invert flags read '' at the free slot (POST must CAUSE them).
        assert helpers.config_get(vm, f"{base}/autoaddrnot_in") == "", (
            f"rowid {rowid} not free: autoaddrnot_in already set"
        )
        assert helpers.config_get(vm, f"{base}/autoaddrnot_out") == "", (
            f"rowid {rowid} not free: autoaddrnot_out already set"
        )

        # WHEN: save Alias_Native with both Invert toggles on.
        # Alias_Native is REQUIRED by validation (lines 619-628); any other action
        # with these flags set would abort the save.
        _post_form(
            webui,
            _ipv4_payload(
                rowid,
                "smkinv",
                action="Alias_Native",
                autoaddrnot_in="on",
                autoaddrnot_out="on",
            ),
        )

        # THEN (config.xml): flags and action persisted.
        assert helpers.config_get(vm, f"{base}/autoaddrnot_in") == "on", "autoaddrnot_in not persisted as 'on'"
        assert helpers.config_get(vm, f"{base}/autoaddrnot_out") == "on", "autoaddrnot_out not persisted as 'on'"
        assert helpers.config_get(vm, f"{base}/action") == "Alias_Native", "action not persisted as 'Alias_Native'"

        # RELOAD: GET the edit page and assert the saved Invert state appears.
        reload_resp = webui.get(CATEGORY_PAGE, params={"type": "ipv4", "rowid": str(rowid)})
        assert not looks_like_login_page(reload_resp.text), (
            "category GET (reload) returned the login form (session lost)"
        )
        body = reload_resp.text

        # Both Invert checkboxes must render CHECKED on their OWN inputs.
        for field in ("autoaddrnot_in", "autoaddrnot_out"):
            tag = _input_tag(body, field)
            assert tag, f"reloaded form has no input named {field!r}"
            assert "checked" in tag, f"reloaded {field!r} Invert toggle did not render checked: {tag}"

    finally:
        _del_rowid(vm, CFG_IPV4, rowid)


# --------------------------------------------------------------------------- #
# IPv6 alias: the issue-#760 §3 "Suppression CIDR Limit" select persists and
# reloads, and is genuinely gtype-gated (v6-only, never rendered on the v4 page;
# the v4-only sibling field never rendered on the v6 page).
# --------------------------------------------------------------------------- #


def _ipv6_payload(rowid: int, aliasname: str, **overrides: str) -> dict[str, str]:
    """A complete IPv6 alias save payload (one Disabled placeholder row).

    Mirrors ``_ipv4_payload``: IPv6 shares the same Advanced In/Out fields (the
    save handler's ``if ($gtype == 'ipv4' || $gtype == 'ipv6')`` block writes
    both ``suppression_cidr`` -- unconditionally, the v4-only field -- and the
    new issue-#760 §3 ``suppression_cidr_v6`` -- gated ``if ($gtype ==
    'ipv6')``). Both are supplied here, same "every field the handler reads
    gets a value" convention as ``_ipv4_payload``'s own placeholder-row fields.
    """
    payload = {
        "type": "ipv6",
        "rowid": str(rowid),
        "aliasname": aliasname,
        "description": "smoke ipv6 category-edit",
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
        "suppression_cidr_v6": "Disabled",
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


def test_ipv6_suppression_cidr_select_persists_and_reloads(
    webui: "WebUI",
    smoke_vm: helpers.SmokeVM,
) -> None:
    """The issue-#760 §3 IPv6 Suppression CIDR Limit select round-trips.

    Scenario: saving an IPv6 alias with ``suppression_cidr_v6`` at its
    documented default persists it, flipping to a numeric floor persists AND
    reloads selected, and restoring to the default round-trips back. The field
    is v6-only (gtype-gated in render/validation/save), so the reloaded v6 page
    must never render the v4-only ``suppression_cidr`` select, and the v4 page
    must never render this new v6-only select.

    Given:
        The target IPv6 rowid is free (``suppression_cidr_v6`` reads '').
    When:
        A valid Deny_Both alias is saved with ``suppression_cidr_v6='Disabled'``
        (the documented default, asserted first), then re-saved with
        ``suppression_cidr_v6='32'`` (a real transition), then restored to
        ``'Disabled'`` (the reverse transition).
    Then:
        - config.xml holds each value in turn -- each POST CAUSED the change.
        - The reloaded v6 edit page renders '32' as the selected option.
        - The v6 page never renders a 'suppression_cidr' <select> (v4-only);
          the v4 page never renders a 'suppression_cidr_v6' <select> (v6-only)
          -- the gating is real, not accidental.
    """
    vm = smoke_vm
    rowid = _free_rowid(vm, CFG_IPV6)
    cfg = f"{CFG_IPV6}/{rowid}/suppression_cidr_v6"
    try:
        # BEFORE: free slot, no value stored (the save must CAUSE it).
        assert helpers.config_get(vm, cfg) == "", f"ipv6 rowid {rowid} not free (suppression_cidr_v6 already set)"

        # Create the alias at the documented default.
        _post_form(webui, _ipv6_payload(rowid, "smokeip6cidr", suppression_cidr_v6="Disabled"))
        assert helpers.config_get(vm, cfg) == "Disabled", "suppression_cidr_v6 not stored as 'Disabled'"

        # WHEN: a real transition to a numeric floor.
        _post_form(webui, _ipv6_payload(rowid, "smokeip6cidr", suppression_cidr_v6="32"))
        assert helpers.config_get(vm, cfg) == "32", "suppression_cidr_v6 not persisted as '32'"

        # THEN: the reloaded v6 edit page renders '32' selected, and the field
        # is genuinely gtype-gated both ways.
        reload_resp = webui.get(CATEGORY_PAGE, params={"type": "ipv6", "rowid": str(rowid)})
        assert not looks_like_login_page(reload_resp.text), (
            "category GET (reload) returned the login form (session lost)"
        )
        body = reload_resp.text
        assert 'name="suppression_cidr_v6"' in body, "reloaded v6 form has no suppression_cidr_v6 select"
        assert _option_selected(body, "32"), (
            "reloaded v6 form did not render suppression_cidr_v6 option '32' as selected"
        )
        assert 'name="suppression_cidr"' not in body, (
            "v6 edit page must not render the v4-only 'suppression_cidr' select"
        )

        v4_resp = webui.get(CATEGORY_PAGE, params={"type": "ipv4"})
        assert not looks_like_login_page(v4_resp.text), "v4 category GET returned the login form (session lost)"
        assert 'name="suppression_cidr_v6"' not in v4_resp.text, (
            "v4 edit page must not render the v6-only 'suppression_cidr_v6' select"
        )

        # Restore to the default (the reverse transition).
        _post_form(webui, _ipv6_payload(rowid, "smokeip6cidr", suppression_cidr_v6="Disabled"))
        assert helpers.config_get(vm, cfg) == "Disabled", "suppression_cidr_v6 not restored to 'Disabled'"
    finally:
        _del_rowid(vm, CFG_IPV6, rowid)


# --------------------------------------------------------------------------- #
# ui_render tier (PR gate): GET the IPv4 category-edit page and assert the
# alias-type help-text and <select> fields added by issue #356.
# --------------------------------------------------------------------------- #


@pytest.mark.ui_render
def test_ipv4_category_edit_renders_alias_type_help_text(
    webui: "WebUI",
    smoke_vm: helpers.SmokeVM,  # noqa: ARG001
) -> None:
    """The IPv4 category-edit page renders the alias-type help-text strings.

    Scenario: a GET of ``pfblockerng_category_edit.php?type=ipv4`` returns a
    200 response with the ``Must be a Port-type alias.`` and
    ``Must be a Network or Host-type alias.`` help strings that were added by
    issue #356 to guide the user when filling the Advanced In/Out alias fields.

    Background:
        ``pfb_alias_field_type_ok()`` validates alias type on save; the matching
        help text was added to the page alongside each alias <select> (one for
        port fields, one for address fields). This render test confirms the text
        is present in the response body and the page is error-free.

    Given:
        The webConfigurator is accessible and the admin session is valid.
    When:
        GET ``pfblockerng_category_edit.php?type=ipv4``.
    Then:
        - HTTP 200.
        - Body contains ``Must be a Port-type alias.``
        - Body contains ``Must be a Network or Host-type alias.``
        - Body free of ``Fatal error``, ``Parse error``, ``Warning``, ``Notice``,
          ``Uncaught`` (standard ui_render guarantee).
    """
    resp = webui.get(CATEGORY_PAGE, params={"type": "ipv4"})
    assert resp.status_code == 200, f"IPv4 category-edit GET returned HTTP {resp.status_code} (expected 200)"
    body = resp.text
    assert not looks_like_login_page(body), "IPv4 category-edit GET returned the login form (session lost)"
    for bad in ("Fatal error", "Parse error", "Warning", "Notice", "Uncaught"):
        assert bad not in body, f"IPv4 category-edit page contains PHP error: {bad!r}"
    assert "Must be a Port-type alias." in body, (
        "IPv4 category-edit page is missing help text 'Must be a Port-type alias.'"
    )
    assert "Must be a Network or Host-type alias." in body, (
        "IPv4 category-edit page is missing help text 'Must be a Network or Host-type alias.'"
    )


@pytest.mark.ui_render
def test_ipv4_category_edit_renders_four_alias_select_fields(
    webui: "WebUI",
    smoke_vm: helpers.SmokeVM,  # noqa: ARG001
) -> None:
    """The IPv4 category-edit page renders all four alias <select> fields.

    Scenario: the four Advanced In/Out alias-reference <select> fields —
    ``aliasports_in``, ``aliasports_out``, ``aliasaddr_in``, ``aliasaddr_out`` —
    are present in the rendered page body.

    Background:
        Issue #356 wires alias-type validation to these four fields. A render
        test confirms the page actually emits <select> tags with those names so
        the validation path is reachable from the UI (not a dead branch).

    Given:
        The webConfigurator is accessible and the admin session is valid.
    When:
        GET ``pfblockerng_category_edit.php?type=ipv4``.
    Then:
        - HTTP 200, no PHP errors.
        - Each of ``aliasports_in``, ``aliasports_out``, ``aliasaddr_in``,
          ``aliasaddr_out`` appears as a ``<select name="...">`` in the body.
    """
    resp = webui.get(CATEGORY_PAGE, params={"type": "ipv4"})
    assert resp.status_code == 200, f"IPv4 category-edit GET returned HTTP {resp.status_code} (expected 200)"
    body = resp.text
    assert not looks_like_login_page(body), "IPv4 category-edit GET returned the login form (session lost)"
    for bad in ("Fatal error", "Parse error", "Warning", "Notice", "Uncaught"):
        assert bad not in body, f"IPv4 category-edit page contains PHP error: {bad!r}"
    for field in ("aliasports_in", "aliasports_out", "aliasaddr_in", "aliasaddr_out"):
        assert f'name="{field}"' in body, f'IPv4 category-edit page is missing <select name="{field}"> field'
