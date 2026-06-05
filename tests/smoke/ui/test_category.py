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

* ``act=update`` (pfblockerng_category.php:35-37,174-314): the page does
  ``$_POST = $_REQUEST`` for ``act=update`` then reads ``$_POST['postdata']`` --
  itself a urlencoded query string -- via ``parse_str`` into ``$post_data``.
  Each key shaped ``<var>-<rowid>`` (``var`` in {action,cron,aliaslog,logging})
  is validated against that field's whitelist; on success it writes
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
"""

from __future__ import annotations

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

# Generous round-trip bound: the AJAX ops only write_config() (no reload / no
# egress), but the box is shared and pfSsh.php seeding adds latency.
AJAX_TIMEOUT = 120.0

# A snapshot delimiter for round-tripping the whole IPv4-lists array through PHP
# serialize/base64 (config_get only reads scalar leaves, so capture/restore the
# node as a blob to leave the box exactly as found).
_SNAP_OPEN = "<<<SNAP>>>"
_SNAP_CLOSE = "<<<SNAPEND>>>"


def _snapshot_lists(vm: helpers.SmokeVM) -> str:
    """Return a base64(serialize()) blob of the whole IPv4-lists config node.

    Used to restore the node byte-for-byte in teardown -- the seed below replaces
    the node with a single known row, so the original (possibly empty) array must
    be captured first and rewritten after, leaving the shared VM as found.
    """
    snippet = (
        f"echo {helpers._php_str(_SNAP_OPEN)} . "
        f"base64_encode(serialize(config_get_path({helpers._php_str(IPV4_LISTS)}, array()))) . "
        f"{helpers._php_str(_SNAP_CLOSE)};"
    )
    result = helpers.php_eval(vm, snippet, timeout=AJAX_TIMEOUT)
    out = result.stdout
    start = out.find(_SNAP_OPEN)
    end = out.find(_SNAP_CLOSE)
    if start == -1 or end == -1:
        raise RuntimeError(f"_snapshot_lists: no delimited blob: rc={result.returncode} out={out!r}")
    return out[start + len(_SNAP_OPEN) : end]


def _restore_lists(vm: helpers.SmokeVM, blob: str) -> None:
    """Rewrite the IPv4-lists config node from a :func:`_snapshot_lists` blob."""
    snippet = (
        f"config_set_path({helpers._php_str(IPV4_LISTS)}, "
        f"unserialize(base64_decode({helpers._php_str(blob)})));\n"
        "write_config('pfBlockerNG smoke: restore IPv4 lists');\n"
        "echo 'OK';"
    )
    result = helpers.php_eval(vm, snippet, timeout=AJAX_TIMEOUT)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_restore_lists failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}")


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


def _ajax_post(webui: WebUI, data: dict[str, str]) -> str:
    """Drive a DIRECT CSRF-authenticated POST to the Category AJAX endpoint.

    GET the page for a fresh ``__csrf_magic`` token (csrf-magic injects it per
    render -- never cache it), then ``session.post`` the supplied ``data`` with
    the token at top level so csrf-magic validates the request. Returns the
    response body (callers assert EFFECTIVE config state, never this text).
    """
    page = webui.get(IPV4_PAGE)
    assert not looks_like_login_page(page.text), "Category GET returned the login form (session lost)"
    token = extract_csrf_token(page.text)
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

    * VALID: ``Deny_Outbound`` is a key of ``$action_values`` -> the handler writes
      ``installedpackages/pfblockernglistsv4/config/0/action`` -> config holds the
      new value. The seed starts at ``Deny_Inbound`` so the change is a real
      transition (before != after), proving the POST caused it.
    * REJECT: ``BogusAction`` is NOT a key -> ``$input_errors`` -> the
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
