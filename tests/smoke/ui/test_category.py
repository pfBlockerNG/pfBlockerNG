"""Tier-B functional flows for the IP/DNSBL Category SUMMARY page (ADR-14).

Marker ``ui_e2e`` -- daily / on-demand, NOT in the default run nor the PR gate
(the whole ``tests/smoke`` tree is ``--ignore``d in the default
``python -m pytest``; this tier is run with
``pytest tests/smoke -m ui_e2e --override-ini="addopts="``).

Subject: ``pfblockerng_category.php`` (the IPv4/IPv6/GeoIP/DNSBL summary table).
Unlike the settings pages exercised by ``test_functional.py``, this page's row
mutations are NOT a normal form save -- they are AJAX ``act=``-dispatched
operations the page's own JavaScript fires (``act=update`` for a per-row
action/cron/log save and an optional drag-reorder ``ids[]``; ``act=del`` for a
row delete). So these tests do NOT use the form-scrape ``webui.post`` helper:
they GET the page to harvest the per-render ``__csrf_magic`` token, then drive a
DIRECT ``webui.session.post`` with a fully-controlled payload (the same pattern
the alerts AJAX flows use), which is the only way to reproduce the AJAX envelope
faithfully (a fully-enumerated payload, no same-name multi-value collision).

Handler facts pinned from the PHP source (read end to end):

* ``act=update`` (pfblockerng_category.php:169-309): the handler is POST-ONLY —
  ``$action``/``postdata``/``ids`` are read exclusively from ``$_POST`` (issue
  #704 removed the historical ``$_POST = $_REQUEST`` fold that let a crafted GET
  drive the config-writing handler past csrf-magic, which validates POST bodies
  only). ``$_POST['postdata']`` -- itself a urlencoded query string -- is parsed
  via ``parse_str`` into ``$post_data``. Each key shaped ``<var>-<rowid>``
  (``var`` in {action,cron,aliaslog,logging}) is validated against that field's
  whitelist; on success it writes
  ``config_set_path("{$rowdata_path}/{$rowid}/{$variable}", ...)``. ANY invalid
  key/value appends to ``$input_errors`` and the ``if (!$input_errors)`` guard
  skips the ENTIRE write (config UNCHANGED) and the handler echoes
  ``json_encode($input_errors)``. ``$rowdata_path`` for ``type=ipv4`` is
  ``installedpackages/pfblockernglistsv4/config``.
* ``act=del`` (pfblockerng_category.php:82-83,158-172): reads the top-level
  ``$_POST['rowid']``, requires the row's ``aliasname`` to be a clean word
  (``PFB_FILTER_WORD``), then ``config_del_path("{$rowdata_path}/{$rowid}")`` and
  302-redirects. Deletes the addressed numeric row.
* The action whitelist for an IP list (pfblockerng_category.php:179-194):
  Disabled, Deny_Inbound, Deny_Outbound, Deny_Both, Permit_*, Match_*, Alias_*,
  unbound.

Every flow is a TRUE transition test (CLAUDE.md): it seeds a known row, asserts
the ORIGINAL effective value, drives the AJAX op, asserts the NEW effective
value, and restores -- the oracle is ALWAYS ``config.xml`` read over SSH
(``helpers.config_get``), NEVER the HTTP response body. The seeded row is removed
in a ``finally`` so a mid-test failure cannot poison the session-scoped VM.

ADR-63 Phase 1 golden oracles (below) additionally pin the ``ids[]`` drag-reorder
AJAX path (pfblockerng_category.php:276-306): the WHOLE row array is replaced
from a ``parse_str``d ``rN`` permutation, gtype-common EXCEPT GeoIP, whose
rowdata is rebuilt fresh from ``$pfb['continents']`` every request and never
reads the persist sink -- an ``ids[]`` POST there is a proven SILENT NO-OP.
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING
from urllib.parse import urlencode

import pytest

from .. import helpers
from .webui import extract_csrf_token, looks_like_login_page

if TYPE_CHECKING:
    from .webui import WebUI

pytestmark = pytest.mark.ui_e2e

# The Category page and the config root it edits for ?type=ipv4 (the page's
# documented default tab). pfblockerng_category.php:99-101 sets
# $conf_type='pfblockernglistsv4' for gtype 'ipv4', so $rowdata_path is this node.
CATEGORY_PAGE = "/pfblockerng/pfblockerng_category.php"
IPV4_PAGE = f"{CATEGORY_PAGE}?type=ipv4"
IPV4_LISTS = "installedpackages/pfblockernglistsv4/config"

# The other two ids[]-persisting gtypes' config nodes (pfblockerng_category.php:92-114
# switch: same $rowdata_path mechanism as ipv4, different $conf_type).
IPV6_LISTS = "installedpackages/pfblockernglistsv6/config"
DNSBL_GROUPS = "installedpackages/pfblockerngdnsbl/config"
CONF_NODE_BY_GTYPE = {"ipv4": IPV4_LISTS, "ipv6": IPV6_LISTS, "dnsbl": DNSBL_GROUPS}

# GeoIP has NO $rowdata_path (pfblockerng_category.php:117-138) -- one representative
# continent node, spot-checked to prove an ids[] POST does not touch it either.
GEOIP_TOPSPAMMERS = "installedpackages/pfblockerngtopspammers/config"

# Generous round-trip bound: the AJAX ops only write_config() (no reload / no
# egress), but the box is shared and pfSsh.php seeding adds latency.
AJAX_TIMEOUT = 120.0

# A snapshot delimiter for round-tripping the whole IPv4-lists array through PHP
# serialize/base64 (config_get only reads scalar leaves, so capture/restore the
# node as a blob to leave the box exactly as found).
_SNAP_OPEN = "<<<SNAP>>>"
_SNAP_CLOSE = "<<<SNAPEND>>>"


def _snapshot_node(vm: helpers.SmokeVM, node: str) -> str:
    """Return a base64(serialize()) blob of the given config node.

    Used to restore the node byte-for-byte in teardown -- a seed helper below
    replaces the node with known rows, so the original (possibly empty) array
    must be captured first and rewritten after, leaving the shared VM as found.
    """
    snippet = (
        f"echo {helpers._php_str(_SNAP_OPEN)} . "
        f"base64_encode(serialize(config_get_path({helpers._php_str(node)}, array()))) . "
        f"{helpers._php_str(_SNAP_CLOSE)};"
    )
    result = helpers.php_eval(vm, snippet, timeout=AJAX_TIMEOUT)
    out = result.stdout
    start = out.find(_SNAP_OPEN)
    end = out.find(_SNAP_CLOSE)
    if start == -1 or end == -1:
        raise RuntimeError(f"_snapshot_node({node!r}): no delimited blob: rc={result.returncode} out={out!r}")
    return out[start + len(_SNAP_OPEN) : end]


def _restore_node(vm: helpers.SmokeVM, node: str, blob: str) -> None:
    """Rewrite ``node`` from a :func:`_snapshot_node` blob."""
    snippet = (
        f"config_set_path({helpers._php_str(node)}, "
        f"unserialize(base64_decode({helpers._php_str(blob)})));\n"
        "write_config('pfBlockerNG smoke: restore category node');\n"
        "echo 'OK';"
    )
    result = helpers.php_eval(vm, snippet, timeout=AJAX_TIMEOUT)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(
            f"_restore_node({node!r}) failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}"
        )


def _snapshot_lists(vm: helpers.SmokeVM) -> str:
    """Return a base64(serialize()) blob of the whole IPv4-lists config node."""
    return _snapshot_node(vm, IPV4_LISTS)


def _restore_lists(vm: helpers.SmokeVM, blob: str) -> None:
    """Rewrite the IPv4-lists config node from a :func:`_snapshot_lists` blob."""
    _restore_node(vm, IPV4_LISTS, blob)


def _seed_single_ipv4_row(vm: helpers.SmokeVM, aliasname: str, action: str) -> None:
    """Replace the IPv4-lists node with exactly ONE known row (index 0).

    A single deterministic row makes ``rowid=0`` address THIS row for both
    ``act=update`` and ``act=del``. ``aliasname`` must be word-only
    (``PFB_FILTER_WORD``) -- the del handler rejects a non-word alias
    (pfblockerng_category.php:160). The row carries a feed row so it is a valid,
    fully-formed list entry.
    """
    row = {
        "aliasname": aliasname,
        "action": action,
        "cron": "Never",
        "aliaslog": "enabled",
        "description": "pfBlockerNG smoke category row",
    }
    feed = {"header": "smoketest", "url": f"{helpers.PFB_DBDIR}/{aliasname}", "state": "Enabled", "format": "auto"}
    snippet = (
        f"$list = {helpers._php_kv_array(row)};\n"
        f"$list['row'] = array({helpers._php_kv_array(feed)});\n"
        f"config_set_path({helpers._php_str(IPV4_LISTS)}, array($list));\n"
        "write_config('pfBlockerNG smoke: seed IPv4 category row');\n"
        "echo 'OK';"
    )
    result = helpers.php_eval(vm, snippet, timeout=AJAX_TIMEOUT)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_seed_single_ipv4_row failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}")


def _page_url(gtype: str) -> str:
    """Return the Category page URL for ``gtype`` (mirrors ``IPV4_PAGE``)."""
    return f"{CATEGORY_PAGE}?type={gtype}"


def _php_row_literal(row: dict[str, str], feed: dict[str, str]) -> str:
    """Render one category-list row (with its single-entry ``row`` sub-array) as a PHP literal."""
    base = ", ".join(f"{helpers._php_str(k)} => {helpers._php_str(v)}" for k, v in row.items())
    return f"array({base}, 'row' => array({helpers._php_kv_array(feed)}))"


def _seed_three_rows(vm: helpers.SmokeVM, node: str, gtype: str, aliasnames: list[str]) -> None:
    """Replace ``node`` with exactly THREE known rows at indices 0, 1, 2.

    Each row is fully-formed (F5): ``logging`` for dnsbl, ``aliaslog`` for
    ipv4/ipv6, plus a local feed row so it is a valid list entry (mirrors
    :func:`_seed_single_ipv4_row`). ``aliasnames`` must be word-only and its
    order becomes the seeded row order (index i <- aliasnames[i]).
    """
    log_field = "logging" if gtype == "dnsbl" else "aliaslog"
    action = "unbound" if gtype == "dnsbl" else "Deny_Inbound"
    entries = []
    for name in aliasnames:
        row = {
            "aliasname": name,
            "action": action,
            "cron": "Never",
            log_field: "enabled",
            "description": f"pfBlockerNG smoke {gtype} row {name}",
        }
        feed = {"header": "smoketest", "url": f"{helpers.PFB_DBDIR}/{name}", "state": "Enabled", "format": "auto"}
        entries.append(_php_row_literal(row, feed))
    list_literal = "array(" + ", ".join(entries) + ")"
    snippet = (
        f"config_set_path({helpers._php_str(node)}, {list_literal});\n"
        "write_config('pfBlockerNG smoke: seed category rows');\n"
        "echo 'OK';"
    )
    result = helpers.php_eval(vm, snippet, timeout=AJAX_TIMEOUT)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(
            f"_seed_three_rows({node!r}) failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}"
        )


def _ajax_post(webui: WebUI, data: dict[str, str], *, page: str = IPV4_PAGE) -> str:
    """Drive a DIRECT CSRF-authenticated POST to the Category AJAX endpoint.

    GET ``page`` for a fresh ``__csrf_magic`` token (csrf-magic injects it per
    render -- never cache it), then ``session.post`` the supplied ``data`` with
    the token at top level so csrf-magic validates the request. Returns the
    response body (callers assert EFFECTIVE config state, never this text).
    """
    resp_page = webui.get(page)
    assert not looks_like_login_page(resp_page.text), "Category GET returned the login form (session lost)"
    token = extract_csrf_token(resp_page.text)
    payload = dict(data)
    payload["__csrf_magic"] = token
    resp = webui.session.post(
        webui.url(CATEGORY_PAGE),
        data=payload,
        verify=webui._verify,
        timeout=AJAX_TIMEOUT,
    )
    assert not looks_like_login_page(resp.text), "Category POST returned the login form (session lost)"
    return resp.text


def _update_action(webui: WebUI, rowid: int, action: str) -> str:
    """Fire ``act=update`` setting ``action-<rowid>=<action>`` via ``postdata``.

    ``postdata`` is itself a urlencoded query string the handler ``parse_str``s,
    so a minimal one-field payload is sent (avoids the multi-value same-name
    collision a full form scrape would introduce). Returns the response body.
    """
    postdata = urlencode({f"action-{rowid}": action})
    return _ajax_post(webui, {"act": "update", "type": "ipv4", "rowid": "0", "postdata": postdata})


def test_category_update_row_action_changes_config(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """``act=update`` saves a valid per-row action; a bogus action leaves config UNCHANGED.

    Branch coverage of the action validator (pfblockerng_category.php:238-243):

    * VALID: ``Deny_Outbound`` passes ``pfb_group_action_valid()`` -> the handler writes
      ``installedpackages/pfblockernglistsv4/config/0/action`` -> config holds the
      new value. The seed starts at ``Deny_Inbound`` so the change is a real
      transition (before != after), proving the POST caused it.
    * REJECT: ``BogusAction`` fails the shared group validator -> ``$input_errors`` -> the
      ``if (!$input_errors)`` guard skips the whole write -> config UNCHANGED
      (stays at the prior valid value, NOT coerced, NOT the bogus token).

    Oracle is config.xml over SSH, never the AJAX response body.
    """
    vm = smoke_vm
    alias = "pfbcatupd"
    cfg = f"{IPV4_LISTS}/0/action"
    snap = _snapshot_lists(vm)
    try:
        _seed_single_ipv4_row(vm, alias, "Deny_Inbound")
        # BEFORE: the seeded row holds the original action.
        assert helpers.config_get(vm, cfg) == "Deny_Inbound", "seed did not land Deny_Inbound at row 0"
        # VALID: a different whitelisted action is written through.
        _update_action(webui, 0, "Deny_Outbound")
        assert helpers.config_get(vm, cfg) == "Deny_Outbound", "valid act=update did not change the row action"
        # Restore the row to its original valid action (reverse transition).
        _update_action(webui, 0, "Deny_Inbound")
        assert helpers.config_get(vm, cfg) == "Deny_Inbound", "restore act=update did not revert the row action"
        # REJECT: a non-whitelisted action aborts the whole save -> config UNCHANGED.
        _update_action(webui, 0, "BogusAction")
        got = helpers.config_get(vm, cfg)
        assert got == "Deny_Inbound", f"bogus action must leave config unchanged at 'Deny_Inbound', got {got!r}"
    finally:
        _restore_lists(vm, snap)


def test_category_update_rejects_cross_group_and_array_actions(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """Issue #1346: Summary AJAX rejects wrong-group and array actions without a 500."""
    vm = smoke_vm
    ipv4_snap = _snapshot_node(vm, IPV4_LISTS)
    dnsbl_snap = _snapshot_node(vm, DNSBL_GROUPS)
    try:
        _seed_single_ipv4_row(vm, "pfbactip", "Deny_Inbound")
        _update_action(webui, 0, "unbound")
        assert helpers.config_get(vm, f"{IPV4_LISTS}/0/action") == "Deny_Inbound"

        row = {
            "aliasname": "pfbactdns",
            "action": "unbound",
            "cron": "Never",
            "logging": "enabled",
            "description": "pfBlockerNG smoke DNSBL action row",
        }
        feed = {"header": "pfbactdns", "url": f"{helpers.PFB_DBDIR}/pfbactdns", "state": "Enabled", "format": "auto"}
        seed = helpers.php_eval(
            vm,
            f"config_set_path({helpers._php_str(DNSBL_GROUPS)}, array({_php_row_literal(row, feed)}));\n"
            "write_config('pfBlockerNG smoke: seed DNSBL category row');\n"
            "echo 'OK';",
            timeout=AJAX_TIMEOUT,
        )
        assert seed.returncode == 0 and "OK" in seed.stdout

        body = _ajax_post(
            webui,
            {"act": "update", "type": "dnsbl", "rowid": "0", "postdata": urlencode({"action-0": "Deny_Both"})},
            page=_page_url("dnsbl"),
        )
        assert helpers.config_get(vm, f"{DNSBL_GROUPS}/0/action") == "unbound"

        body = _ajax_post(
            webui,
            {"act": "update", "type": "dnsbl", "rowid": "0", "postdata": urlencode({"action-0[]": "unbound"})},
            page=_page_url("dnsbl"),
        )
        assert "Fatal error" not in body
        assert helpers.config_get(vm, f"{DNSBL_GROUPS}/0/action") == "unbound"

        ipv4_seeded = _snapshot_node(vm, IPV4_LISTS)
        dnsbl_seeded = _snapshot_node(vm, DNSBL_GROUPS)
        mutation = {"act": "update", "rowid": "0", "postdata": urlencode({"action-0": "Disabled"})}
        for case, type_value in (("missing", None), ("bogus", "not-a-category")):
            payload = dict(mutation)
            if type_value is not None:
                payload["type"] = type_value
            body = _ajax_post(webui, payload, page=_page_url("dnsbl"))
            assert json.loads(body) == ["Failed Type"], f"{case} type returned non-neutral error: {body!r}"
            assert _snapshot_node(vm, IPV4_LISTS) == ipv4_seeded, f"{case} type mutated IPv4 config"
            assert _snapshot_node(vm, DNSBL_GROUPS) == dnsbl_seeded, f"{case} type mutated DNSBL config"
    finally:
        _restore_node(vm, IPV4_LISTS, ipv4_snap)
        _restore_node(vm, DNSBL_GROUPS, dnsbl_snap)


def test_category_update_row_cron_valid_and_reject_unchanged(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """``act=update`` saves a valid per-row cron frequency; a bogus value leaves config UNCHANGED.

    Branch coverage of the cron validator (pfblockerng_category.php:244-248): the
    value must be a key of ``$cron_values`` (Never,01hour,...,Weekly). A valid
    ``12hours`` is written to
    ``installedpackages/pfblockernglistsv4/config/0/cron``; a bogus ``99hours``
    is not a key -> ``$input_errors`` -> the whole save aborts -> config
    UNCHANGED. The seed starts at ``Never`` so ``12hours`` is a real transition.
    """
    vm = smoke_vm
    alias = "pfbcatcron"
    cfg = f"{IPV4_LISTS}/0/cron"
    snap = _snapshot_lists(vm)
    try:
        _seed_single_ipv4_row(vm, alias, "Deny_Both")
        # BEFORE: seeded cron is 'Never'.
        assert helpers.config_get(vm, cfg) == "Never", "seed did not land cron 'Never' at row 0"
        # VALID cron key -> written through.
        postdata = urlencode({"cron-0": "12hours"})
        _ajax_post(webui, {"act": "update", "type": "ipv4", "rowid": "0", "postdata": postdata})
        assert helpers.config_get(vm, cfg) == "12hours", "valid act=update did not change the row cron"
        # Restore (reverse transition).
        postdata = urlencode({"cron-0": "Never"})
        _ajax_post(webui, {"act": "update", "type": "ipv4", "rowid": "0", "postdata": postdata})
        assert helpers.config_get(vm, cfg) == "Never", "restore act=update did not revert the row cron"
        # REJECT: a non-whitelisted cron aborts the whole save -> config UNCHANGED.
        postdata = urlencode({"cron-0": "99hours"})
        _ajax_post(webui, {"act": "update", "type": "ipv4", "rowid": "0", "postdata": postdata})
        got = helpers.config_get(vm, cfg)
        assert got == "Never", f"bogus cron must leave config unchanged at 'Never', got {got!r}"
    finally:
        _restore_lists(vm, snap)


def test_category_update_via_get_does_not_mutate_config(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """An authenticated GET carrying ``act=update`` params mutates NOTHING (#704).

    csrf-magic validates POST bodies only, so a GET reaching the update handler is a
    CSRF hole: a logged-in admin lured to a crafted link would flip real config. The
    fix makes the handler POST-only (``$_POST`` is never populated from ``$_GET``).

    * GET: the full ``act=update&type=ipv4&rowid=0&postdata=action-0%3DPermit_Both``
      query — the exact crafted-link shape — must leave the seeded row's action
      UNCHANGED. Pre-fix, the ``$_POST = $_REQUEST`` fold fed these params to the
      handler and the row flipped to Permit_Both (this assert is the red→green).
    * CONTROL: the SAME parameters via the CSRF-token POST DO change the row —
      proving the GET was rejected for its METHOD, not for its payload.

    Oracle is config.xml over SSH, never the HTTP response body.
    """
    vm = smoke_vm
    alias = "pfbcatcsrf"
    cfg = f"{IPV4_LISTS}/0/action"
    snap = _snapshot_lists(vm)
    try:
        _seed_single_ipv4_row(vm, alias, "Deny_Inbound")
        # BEFORE: the seeded row holds an action the crafted GET would change.
        assert helpers.config_get(vm, cfg) == "Deny_Inbound", "seed did not land Deny_Inbound at row 0"

        # WHEN: the crafted-link GET (authenticated session, no CSRF token — GETs never carry one).
        postdata = urlencode({"action-0": "Permit_Both"})
        query = urlencode({"act": "update", "type": "ipv4", "rowid": "0", "postdata": postdata})
        page = webui.get(f"{CATEGORY_PAGE}?{query}")
        assert not looks_like_login_page(page.text), "Category GET returned the login form (session lost)"

        # THEN: config is UNCHANGED — the update handler must be unreachable via GET.
        got = helpers.config_get(vm, cfg)
        assert got == "Deny_Inbound", (
            f"a GET with act=update params must not mutate config: expected row action to stay "
            f"'Deny_Inbound', got {got!r} — the handler accepted a GET (CSRF hole, #704)"
        )

        # CONTROL: the same parameters via the token POST DO mutate — the branch is the method.
        _update_action(webui, 0, "Permit_Both")
        got = helpers.config_get(vm, cfg)
        assert got == "Permit_Both", (
            f"the CSRF-token POST with identical params must still change the row action, got {got!r}"
        )
    finally:
        _restore_lists(vm, snap)


def test_category_delete_row_removes_config_node(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """``act=del`` deletes the addressed row; the row's config node is gone afterward.

    True lifecycle transition: seed one row, assert it is PRESENT
    (``installedpackages/pfblockernglistsv4/config/0/aliasname`` == the seeded
    name), POST ``act=del`` with ``rowid=0``, then assert the node is GONE
    (config_get returns '' for the removed leaf). The del handler
    (pfblockerng_category.php:158-172) requires the row's aliasname to be a clean
    word and then ``config_del_path("{$rowdata_path}/0")``; it 302-redirects, so
    requests follows to the post-delete page (the oracle is config, not that body).
    """
    vm = smoke_vm
    alias = "pfbcatdel"
    cfg = f"{IPV4_LISTS}/0/aliasname"
    snap = _snapshot_lists(vm)
    try:
        _seed_single_ipv4_row(vm, alias, "Deny_Both")
        # BEFORE: the seeded row is present at index 0.
        assert helpers.config_get(vm, cfg) == alias, "seed did not land the row aliasname at index 0"
        # DELETE the row via the AJAX del op.
        _ajax_post(webui, {"act": "del", "type": "ipv4", "rowid": "0"})
        # AFTER: the row's config node is gone (the only row was at index 0).
        got = helpers.config_get(vm, cfg)
        assert got == "", f"act=del must remove the row node (aliasname now ''), got {got!r}"
    finally:
        _restore_lists(vm, snap)


# --------------------------------------------------------------------------- #
# ADR-63 Phase 1: ``ids[]`` drag-reorder golden oracles (today's exact behaviour,
# to be pinned/exercised before the reorder UX changes in later phases).
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("gtype", sorted(CONF_NODE_BY_GTYPE))
def test_category_ids_order_save_persists_row_permutation(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    gtype: str,
) -> None:
    """``ids[]`` (the drag-reorder AJAX payload) persists a full row permutation.

    Scenario: three fully-formed rows are seeded at indices 0/1/2 (aliasnames
    a/b/c). A ``ids[]=r2&ids[]=r0&ids[]=r1`` POST (pfblockerng_category.php:
    276-306) is the whole-row-array-replace path: ``$new_rows[key] =
    $rowdata[rowid]`` for each parsed ``rN`` in order, so new index 0 <- old
    row 2, new index 1 <- old row 0, new index 2 <- old row 1.

    Given: rows [a, b, c] at indices [0, 1, 2].
    When: ``ids[]=r2&ids[]=r0&ids[]=r1`` is POSTed.
    Then: config order becomes [c, a, b] -- any wrong index mapping fails this.

    Oracle is config.xml over SSH, never the AJAX response body. gtype-common
    per F3 -- GeoIP is covered separately (it never reaches the persist sink).
    """
    vm = smoke_vm
    node = CONF_NODE_BY_GTYPE[gtype]
    page = _page_url(gtype)
    names = [f"pfbord{gtype}a", f"pfbord{gtype}b", f"pfbord{gtype}c"]
    snap = _snapshot_node(vm, node)
    try:
        _seed_three_rows(vm, node, gtype, names)
        # BEFORE: seeded order is [a, b, c] at indices 0, 1, 2.
        before = [helpers.config_get(vm, f"{node}/{i}/aliasname") for i in range(3)]
        assert before == names, f"seed did not land rows in order {names}, got {before!r}"

        # WHEN: the 3-cycle permutation is POSTed.
        _ajax_post(
            webui,
            {"act": "update", "type": gtype, "rowid": "0", "ids": "ids[]=r2&ids[]=r0&ids[]=r1"},
            page=page,
        )

        # THEN: config order is now [c, a, b].
        after = [helpers.config_get(vm, f"{node}/{i}/aliasname") for i in range(3)]
        expected = [names[2], names[0], names[1]]
        assert after == expected, (
            f"ids[] permutation did not persist for gtype={gtype!r}: expected {expected}, got {after!r}"
        )
    finally:
        _restore_node(vm, node, snap)


def test_category_ids_and_postdata_bundle_applies_both_in_one_save(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """A single Save bundles ``ids[]`` (permutation) AND ``postdata`` (field edit) -- both land.

    Mirrors the page's real Save button (pfblockerng_category.php:639-663): one
    AJAX POST carries both ``ids`` and ``postdata``. The postdata field loop
    runs BEFORE the ids[] block (F3), against ORIGINAL row indices -- so an
    edit to ``action-0`` and a permutation moving old-index-0 elsewhere must
    BOTH land on the SAME (now-relocated) row from the ONE POST.

    Given: rows [a, b, c] at indices [0, 1, 2], row 0 (a) has action Deny_Inbound.
    When: one POST carries ``postdata=action-0=Deny_Outbound`` AND
          ``ids[]=r2&ids[]=r0&ids[]=r1``.
    Then: config order becomes [c, a, b] AND the row now at index 1 (a) holds
          action Deny_Outbound -- the edit followed the row through the move.
    """
    vm = smoke_vm
    names = ["pfbordbundlea", "pfbordbundleb", "pfbordbundlec"]
    snap = _snapshot_node(vm, IPV4_LISTS)
    try:
        _seed_three_rows(vm, IPV4_LISTS, "ipv4", names)
        before = [helpers.config_get(vm, f"{IPV4_LISTS}/{i}/aliasname") for i in range(3)]
        assert before == names, f"seed did not land rows in order {names}, got {before!r}"
        before_action = helpers.config_get(vm, f"{IPV4_LISTS}/0/action")
        assert before_action == "Deny_Inbound", f"seed action must start Deny_Inbound, got {before_action!r}"

        postdata = urlencode({"action-0": "Deny_Outbound"})
        _ajax_post(
            webui,
            {
                "act": "update",
                "type": "ipv4",
                "rowid": "0",
                "ids": "ids[]=r2&ids[]=r0&ids[]=r1",
                "postdata": postdata,
            },
        )

        after = [helpers.config_get(vm, f"{IPV4_LISTS}/{i}/aliasname") for i in range(3)]
        expected_order = [names[2], names[0], names[1]]
        assert after == expected_order, (
            f"bundled ids[]+postdata POST did not persist the permutation: expected {expected_order}, got {after!r}"
        )

        # The relocated row (originally at index 0, name a) now sits at index 1 --
        # AND carries the postdata action edit (which targeted the ORIGINAL index 0).
        moved_action = helpers.config_get(vm, f"{IPV4_LISTS}/1/action")
        assert moved_action == "Deny_Outbound", (
            f"the postdata action edit (targeting original index 0) must land on the row now at "
            f"index 1 after the SAME-POST permutation, got {moved_action!r}"
        )
    finally:
        _restore_node(vm, IPV4_LISTS, snap)


def test_category_ids_order_save_geoip_is_silent_no_op(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """GeoIP TODAY: an ``ids[]`` reorder POST is a proven SILENT NO-OP (pins a known quirk).

    pfblockerng_category.php:117-138 rebuilds GeoIP rowdata from
    ``$pfb['continents']`` on EVERY request rather than reading a
    ``$rowdata_path`` -- and the persist sink at 276-306 is gated
    ``if (isset($rowdata_path))``, a condition the GeoIP branch never sets. A
    well-formed reorder POST therefore succeeds (write_config still fires, empty
    response body) but leaves the rendered order, and every continent's config
    node, byte-identical.

    Given: the GeoIP page's rendered row order (harvested from ``id="pfb_rN"``
           occurrence order -- deterministic, driven by the fixed
           ``$pfb['continents']`` iteration).
    When: a well-formed ``ids[]`` permutation POST is sent (``type=geoip``).
    Then: the response reports no input_errors, the re-rendered order is
          UNCHANGED, and a spot-checked continent's config node is UNCHANGED.
    """
    vm = smoke_vm
    page = _page_url("geoip")

    before_page = webui.get(page)
    assert not looks_like_login_page(before_page.text), "GeoIP GET returned the login form (session lost)"
    before_order = re.findall(r'id="pfb_r(\d+)"', before_page.text)
    assert before_order, "GeoIP page rendered no sortable rows to harvest an order from"

    snap = _snapshot_node(vm, GEOIP_TOPSPAMMERS)
    try:
        body = _ajax_post(
            webui,
            {"act": "update", "type": "geoip", "rowid": "0", "ids": "ids[]=r1&ids[]=r0"},
            page=page,
        )
        assert body == "", f"a well-formed GeoIP ids[] POST must not report input_errors, got {body!r}"

        after_page = webui.get(page)
        assert not looks_like_login_page(after_page.text), "GeoIP GET returned the login form (session lost)"
        after_order = re.findall(r'id="pfb_r(\d+)"', after_page.text)
        assert after_order == before_order, (
            f"GeoIP render order must stay unchanged by an ids[] POST (no persist sink): "
            f"before={before_order!r} after={after_order!r}"
        )

        after_snap = _snapshot_node(vm, GEOIP_TOPSPAMMERS)
        assert after_snap == snap, "GeoIP ids[] POST must not mutate any continent's config node"
    finally:
        _restore_node(vm, GEOIP_TOPSPAMMERS, snap)
