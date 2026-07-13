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
import subprocess
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
# issue #1104: the save-time url-N character guard, end-to-end through a real
# CSRF POST + config.xml round-trip. format=geoip is deliberate -- its OWN
# validation reads only the space-delimited PREFIX (PFB_FILTER_ALNUM), leaving
# a crafted SUFFIX gated solely by the new guard (auto/regex/rsync additionally
# route the whole value through pfb_filter(..., PFB_FILTER_URL), which could
# reject a hostile RFC 5737 literal for an unrelated reason and manufacture a
# false-red test). Every geoip-format row ALSO trips an unrelated MaxMind
# credential-notice check (pfblockerng.inc:pfb_maxmind_credential_notice,
# called unconditionally for format=geoip) that aborts the save when the box
# has no MaxMind key/account configured -- placeholder creds are seeded around
# each test so that check never fires and the guard is the sole variable.
# --------------------------------------------------------------------------- #

_IPSETTINGS_CFG = "installedpackages/pfblockerngipsettings/config/0"


def _capture_maxmind_creds(vm: helpers.SmokeVM) -> tuple[str, str]:
    """Read the current MaxMind (key, account) so a test can restore them (read-only).

    Called BEFORE the test's ``try:`` so the values are captured without any
    write; the placeholder seed (:func:`_seed_maxmind_test_creds`) then runs
    INSIDE the ``try:`` whose ``finally`` restores these -- so even a seed that
    writes then fails its confirmation cannot leak placeholder creds onto the box
    (mirrors the ``_mk_alias`` inside-try convention below).
    """
    return (
        helpers.config_get(vm, f"{_IPSETTINGS_CFG}/maxmind_key"),
        helpers.config_get(vm, f"{_IPSETTINGS_CFG}/maxmind_account"),
    )


def _seed_maxmind_test_creds(vm: helpers.SmokeVM) -> None:
    """Seed placeholder MaxMind key/account (write only; capture originals first).

    A geoip-format row unconditionally runs pfb_maxmind_credential_notice()
    (category_edit.php ~line 604) regardless of url-N content; on a box with
    no MaxMind credentials configured that check alone aborts the save, which
    would confound the url-N guard tests below. The values need not be real --
    the check only tests non-emptiness, never calls the MaxMind API.
    """
    snippet = (
        f"config_set_path({helpers._php_str(f'{_IPSETTINGS_CFG}/maxmind_key')}, 'smoketestkey');\n"
        f"config_set_path({helpers._php_str(f'{_IPSETTINGS_CFG}/maxmind_account')}, 'smoketestaccount');\n"
        "write_config('pfBlockerNG smoke: seed test MaxMind credentials');\n"
        "echo 'OK';"
    )
    result = helpers.php_eval(vm, snippet, timeout=SAVE_TIMEOUT)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_seed_maxmind_test_creds failed: rc={result.returncode} {result.stdout!r}")


def _restore_maxmind_creds(vm: helpers.SmokeVM, key: str, account: str) -> None:
    """Restore the MaxMind key/account values captured by :func:`_capture_maxmind_creds`."""
    snippet = (
        f"config_set_path({helpers._php_str(f'{_IPSETTINGS_CFG}/maxmind_key')}, {helpers._php_str(key)});\n"
        f"config_set_path({helpers._php_str(f'{_IPSETTINGS_CFG}/maxmind_account')}, {helpers._php_str(account)});\n"
        "write_config('pfBlockerNG smoke: restore MaxMind credentials');\n"
        "echo 'OK';"
    )
    result = helpers.php_eval(vm, snippet, timeout=SAVE_TIMEOUT)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_restore_maxmind_creds failed: rc={result.returncode} {result.stdout!r}")


def test_dnsbl_url_geoip_breakout_char_rejected_leaves_config_unchanged(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """A '<script>' suffix on a geoip url-N aborts the save -> config UNCHANGED.

    Scenario: the save-time character guard (pfblockerng_category_edit.php,
    issue #1104) rejects control/HTML-breakout chars in url-N for every
    format; geoip's own validation only checks the prefix before the first
    space, so the suffix is gated SOLELY by this guard.

    Given:
        A known-good geoip row ``'US CA'`` is saved at a free rowid (the
        precondition asserted).
    When:
        The SAME rowid is re-posted with url-0 = ``'US <script>alert(1)</script>'``
        (every other field identical).
    Then:
        The guard's ``$input_errors`` aborts the whole save, so
        ``row/0/url`` in config.xml stays ``'US CA'`` -- UNCHANGED.
    """
    vm = smoke_vm
    rowid = _free_rowid(vm, CFG_DNSBL)
    cfg = f"{CFG_DNSBL}/{rowid}/row/0/url"
    orig_key, orig_account = _capture_maxmind_creds(vm)
    try:
        _seed_maxmind_test_creds(vm)
        # GOOD: a valid geoip row persists (precondition).
        _post_form(
            webui,
            _dnsbl_payload(
                rowid, "smokeurlok", **{"state-0": "Enabled", "header-0": "hdr", "format-0": "geoip", "url-0": "US CA"}
            ),
        )
        assert helpers.config_get(vm, cfg) == "US CA", "precondition: valid geoip url-0 did not persist"

        # REJECT: a '<script>' suffix must abort the save (url UNCHANGED at 'US CA').
        _post_form(
            webui,
            _dnsbl_payload(
                rowid,
                "smokeurlok",
                **{
                    "state-0": "Enabled",
                    "header-0": "hdr",
                    "format-0": "geoip",
                    "url-0": "US <script>alert(1)</script>",
                },
            ),
        )
        assert helpers.config_get(vm, cfg) == "US CA", (
            "a '<script>' breakout in url-0 must abort the save (row/0/url unchanged), but it changed"
        )
    finally:
        _del_rowid(vm, CFG_DNSBL, rowid)
        _restore_maxmind_creds(vm, orig_key, orig_account)


def test_dnsbl_url_geoip_value_persists_byte_identical(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """A legitimate multi-country geoip url-N persists byte-identical (issue #1104).

    Scenario: the save-time character guard must accept a well-formed geoip
    value and never transform it -- proves the guard neither false-rejects a
    legitimate value nor mangles it end-to-end through
    ``config_set_path``/``write_config``.

    Given:
        A free DNSBL rowid (``row/0/url`` reads '').
    When:
        A geoip row is saved with url-0 = ``'US CA MX GB'``.
    Then:
        ``row/0/url`` in config.xml reads ``'US CA MX GB'`` -- byte-identical
        to the posted value.
    """
    vm = smoke_vm
    rowid = _free_rowid(vm, CFG_DNSBL)
    cfg = f"{CFG_DNSBL}/{rowid}/row/0/url"
    orig_key, orig_account = _capture_maxmind_creds(vm)
    try:
        _seed_maxmind_test_creds(vm)
        # BEFORE: free slot, no source row url stored (the save must CAUSE it).
        assert helpers.config_get(vm, cfg) == "", f"rowid {rowid} not free (row/0/url already set)"

        _post_form(
            webui,
            _dnsbl_payload(
                rowid,
                "smokeurlpersist",
                **{"state-0": "Enabled", "header-0": "hdr", "format-0": "geoip", "url-0": "US CA MX GB"},
            ),
        )
        assert helpers.config_get(vm, cfg) == "US CA MX GB", "geoip url-0 not persisted byte-identical"
    finally:
        _del_rowid(vm, CFG_DNSBL, rowid)
        _restore_maxmind_creds(vm, orig_key, orig_account)


# --------------------------------------------------------------------------- #
# DNSBL scalar selects/toggle: logging (valid + bogus-coerce), order, filter_alexa.
# --------------------------------------------------------------------------- #


def test_dnsbl_logging_select_valid_and_bogus_coerces_to_default(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """``logging`` stores each of its FIVE valid keys, and a bogus value coerces to the default.

    ``$options_logging`` (category_edit.php:442-446) has FIVE keys: enabled,
    disabled_log, disabled, nxdomain_log, nxdomain. The select-coercion loop
    replaces a non-key value with ``$select_options['logging']`` -- which is the
    literal ``'Enabled'`` (capital E; NOT itself a key of ``$options_logging``),
    and the save SUCCEEDS storing that default. Branch coverage: drive all FIVE
    valid keys in turn, then a bogus 'bogus' that coerces to 'Enabled'. Transition:
    each step asserts the value differs before it is driven.
    """
    vm = smoke_vm
    rowid = _free_rowid(vm, CFG_DNSBL)
    base = f"{CFG_DNSBL}/{rowid}"
    cfg = f"{base}/logging"
    try:
        # Create the alias with logging=enabled.
        _post_form(webui, _dnsbl_payload(rowid, "smokelog", logging="enabled"))
        assert helpers.config_get(vm, cfg) == "enabled", "logging not stored as 'enabled'"
        # The remaining four valid keys, each a real transition from the previous value.
        for key in ("disabled_log", "disabled", "nxdomain_log", "nxdomain"):
            _post_form(webui, _dnsbl_payload(rowid, "smokelog", logging=key))
            got = helpers.config_get(vm, cfg)
            assert got == key, f"logging not stored as {key!r}, got {got!r}"
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


_ASN_CACHE = "/usr/local/www/pfblockerng/pfblockerng_asn.txt"


def _seed_file(vm: helpers.SmokeVM, path: str, content: str, *, timeout: float = 30.0) -> None:
    """Overwrite (not append) ``path`` on the guest with ``content`` via ``tee``."""
    result = subprocess.run(
        vm.ssh_argv("tee", path),
        input=content,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    assert result.returncode == 0, f"_seed_file({path!r}) failed: rc={result.returncode} {result.stderr!r}"


def test_asn_autocomplete_term_returns_json_list(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """The ASN autocomplete (``isAjax`` + ``?term=...``) returns the cached rows that match.

    The page's top branch (lines 34-66) serves an AJAX JSON list when
    ``isAjax()`` AND ``$_GET['term']`` has length > 2: it filters the cached ASN
    list (``pfblockerng_asn.txt``) by the term and ``echo json_encode($result)``.
    Without seeding the cache file, "returns a JSON list" is vacuously true on the
    empty ``[]`` fallback -- this seeds the file with real rows and asserts a
    matching ``?term=`` returns the seeded entry, and separately proves the
    length gate: a 1-char term must NOT hit the AJAX branch at all (falls through
    to the normal HTML page render, line 34's ``mb_strlen(...) > 2`` guard).

    GOTCHA: the ASN list is cached in ``$_SESSION['pfb_asn_list_data']`` and
    cleared on any PLAIN (non-AJAX) page GET (lines 67-71) -- so the seeded file
    is only actually re-read once that cache has been invalidated. Seed, do ONE
    plain GET, THEN issue the ``?term=`` request.
    """
    vm = smoke_vm
    had_file = vm.ssh("test", "-f", _ASN_CACHE).returncode == 0
    original = helpers.read_log_file(vm, _ASN_CACHE) if had_file else ""
    try:
        _seed_file(vm, _ASN_CACHE, "AS3320  Deutsche Telekom AG\nAS16509 Amazon.com, Inc.\n")

        # Invalidate the per-session cache (a plain, non-AJAX GET) so the NEXT
        # ?term= request re-reads our seeded file instead of a stale session cache.
        plain = webui.get(CATEGORY_PAGE, params={"type": "ipv4"})
        assert not looks_like_login_page(plain.text), "plain GET returned the login form (session lost)"

        resp = webui.get(
            CATEGORY_PAGE,
            params={"term": "AS3320"},
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert resp.status_code == 200, f"ASN autocomplete -> HTTP {resp.status_code} (expected 200)"
        assert not looks_like_login_page(resp.text), "ASN autocomplete returned the login form (session lost)"
        parsed = json.loads(resp.text)
        assert isinstance(parsed, list), f"ASN autocomplete must return a JSON list, got {type(parsed).__name__}"
        assert all(isinstance(item, str) for item in parsed), "ASN autocomplete list entries must be strings"
        assert any("AS3320" in item for item in parsed), (
            f"expected the seeded 'AS3320' row in the ?term= result, got {parsed!r}"
        )

        # BRANCH: a term of length <= 2 must NOT hit the AJAX JSON branch (line 34's
        # `mb_strlen($_GET['term']) > 2` gate) -- it renders the normal HTML page instead.
        short = webui.get(
            CATEGORY_PAGE,
            params={"type": "ipv4", "term": "A"},
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert not looks_like_login_page(short.text), "short-term GET returned the login form (session lost)"
        short_is_json = True
        try:
            json.loads(short.text)
        except json.JSONDecodeError:
            short_is_json = False
        assert not short_is_json, (
            f"a 1-char ?term= must NOT return the JSON autocomplete list, got: {short.text[:200]!r}"
        )
    finally:
        if had_file:
            _seed_file(vm, _ASN_CACHE, original)
        else:
            vm.ssh("rm", "-f", _ASN_CACHE)


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
    ``pfb_alias_type()`` returns and the category-edit validation checks).
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
        required when ``autoports_*`` or ``autoaddr_*`` is set;
        the alias names must resolve via ``pfb_alias_type()`` to a type the
        field accepts (``pfb_adv_alias_field_errors``). We therefore create a real port alias
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

    try:
        # Both aliases are created INSIDE the try: a failure creating the second
        # must not leak the first -- the finally below removes both unconditionally.
        _mk_alias(vm, port_alias, "port", _PORT_ALIAS_ADDR)
        _mk_alias(vm, net_alias, "network", _NET_ALIAS_CIDR)

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
        - The reloaded v6 edit page renders '32' as the selected option, with no
          PHP error in the body.
        - The v6 page never renders a 'suppression_cidr' <select> (v4-only);
          the v4 page (re-opened on an EXISTING row, so the shared GET-render
          block actually reads that row's absent 'suppression_cidr_v6' key)
          never renders a 'suppression_cidr_v6' <select> (v6-only) and stays
          free of PHP errors -- pins the review fix for the undefined-array-key
          Warning that an unguarded read of a v6-only key would raise on a v4
          row (`?? 'Disabled'` in the GET-render block).
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
        for bad in ("Fatal error", "Parse error", "Warning", "Notice", "Uncaught"):
            assert bad not in body, f"reloaded v6 edit page contains PHP error: {bad!r}"
        assert 'name="suppression_cidr_v6"' in body, "reloaded v6 form has no suppression_cidr_v6 select"
        assert _option_selected(body, "32"), (
            "reloaded v6 form did not render suppression_cidr_v6 option '32' as selected"
        )
        assert 'name="suppression_cidr"' not in body, (
            "v6 edit page must not render the v4-only 'suppression_cidr' select"
        )

        # v4-page symmetry: re-open an EXISTING v4 row (not a blank/new-row
        # form) so the shared GET-render block actually reads that row's
        # 'suppression_cidr_v6' key -- absent on every v4 row, since the save
        # handler only ever writes it for gtype=='ipv6'. Pre-fix, this read
        # was unconditional (no `?? 'Disabled'`), so PHP emits an undefined-
        # array-key Warning on every existing-row v4 edit.
        v4_rowid = _free_rowid(vm, CFG_IPV4)
        try:
            _post_form(webui, _ipv4_payload(v4_rowid, "smokeip4sym", action="Deny_Both"))
            v4_resp = webui.get(CATEGORY_PAGE, params={"type": "ipv4", "rowid": str(v4_rowid)})
            assert not looks_like_login_page(v4_resp.text), "v4 category GET returned the login form (session lost)"
            for bad in ("Fatal error", "Parse error", "Warning", "Notice", "Uncaught"):
                assert bad not in v4_resp.text, f"existing-row v4 edit page contains PHP error: {bad!r}"
            assert 'name="suppression_cidr_v6"' not in v4_resp.text, (
                "v4 edit page must not render the v6-only 'suppression_cidr_v6' select"
            )
        finally:
            _del_rowid(vm, CFG_IPV4, v4_rowid)

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
    ``Must be an address-type (Host, Network, URL or URL Table) alias.`` help strings that were added by
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
        - Body contains ``Must be an address-type (Host, Network, URL or URL Table) alias.``
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
    assert "Must be an address-type (Host, Network, URL or URL Table) alias." in body, (
        "IPv4 category-edit page is missing help text "
        "'Must be an address-type (Host, Network, URL or URL Table) alias.'"
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
