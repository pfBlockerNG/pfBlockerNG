"""issue #1014/#1019/#2060 -- Tier-B coverage: WebUI alias rename/delete
routes the selected facility/alias key shape through
``pfb_sync_status_close_removed_alias()``. The helper closes both
alias-pass-managed keys (``download`` and ``script``); this is a WebUI event
hook, not tick reconciliation.

Without this hook, deleting or renaming an IP/DNSBL alias via pfBlockerNG's
own category pages could leave its alias-pass-managed ledger entries open
forever because a removed alias never receives another pass. Both mutation
sites call the helper before the row's alias key disappears.

Ledger seeding/probing reuses ``test_render_widget_ledger.py``'s own
conventions (``_ledger_open()`` over the REAL ``pfb_sync_status_open()``,
``clean_ledger`` for backup/restore) -- the KILL-GATE mandate that a
render/behaviour test reflect a manually-seeded entry via the production
writer, not a hand-rolled JSON blob. Row seeding/mutation reuses
``test_category.py``'s AJAX ``act=del`` drive (direct ``webui.session.post``,
NOT the form-scrape helper -- the row's own JS-fired AJAX envelope) and
``test_category_edit.py``'s full-form-POST save drive for the rename case.

Each smoke flow deliberately seeds only a ``download`` entry, so these rows
prove that the WebUI call sites reach the helper for the original regression;
they do not claim a seeded ``script`` transition. The helper's two-key
contract is covered by ``PfbSyncStatusLedgerTest``. Each flow is a true
transition test: it asserts OPEN, drives the mutation, then asserts CLOSED,
proving the mutation caused the close. ``clean_ledger`` wipes and restores the
ledger files around every test regardless of outcome, so a failed assertion
never leaks an open entry into a sibling test.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .test_category import (
    AJAX_TIMEOUT,
    CATEGORY_PAGE,
    _ajax_post,
    _restore_lists,
    _seed_single_ipv4_row,
    _snapshot_lists,
)
from .test_category_edit import CFG_IPV4 as _CE_CFG_IPV4
from .test_category_edit import _del_rowid as _ce_del_rowid
from .test_category_edit import _free_rowid as _ce_free_rowid
from .test_category_edit import _ipv4_payload as _ce_ipv4_payload
from .test_category_edit import _post_form as _ce_post_form
from .test_render_widget_ledger import (  # noqa: F401 -- clean_ledger used as a fixture arg
    _LEDGER_DIR,
    _ledger_open,
    clean_ledger,
)
from .webui import extract_csrf_token, looks_like_login_page

if TYPE_CHECKING:
    from .webui import WebUI

pytestmark = pytest.mark.ui_e2e

DNSBL_LISTS = "installedpackages/pfblockerngdnsbl/config"

_SNAP_OPEN = "<<<SNAP>>>"
_SNAP_CLOSE = "<<<SNAPEND>>>"


def _snapshot_node(vm: helpers.SmokeVM, path: str) -> str:
    """Return a base64(serialize()) blob of the whole config node at ``path``.

    Generic sibling of ``test_category.py``'s own ``_snapshot_lists`` (which is
    hardcoded to the IPv4-lists node) -- used here for the DNSBL-lists node so
    that node can be restored byte-for-byte in teardown.
    """
    snippet = (
        f"echo {helpers._php_str(_SNAP_OPEN)} . "
        f"base64_encode(serialize(config_get_path({helpers._php_str(path)}, array()))) . "
        f"{helpers._php_str(_SNAP_CLOSE)};"
    )
    result = helpers.php_eval(vm, snippet, timeout=AJAX_TIMEOUT)
    out = result.stdout
    start = out.find(_SNAP_OPEN)
    end = out.find(_SNAP_CLOSE)
    if start == -1 or end == -1:
        raise RuntimeError(f"_snapshot_node({path!r}): no delimited blob: rc={result.returncode} out={out!r}")
    return out[start + len(_SNAP_OPEN) : end]


def _restore_node(vm: helpers.SmokeVM, path: str, blob: str) -> None:
    """Rewrite the config node at ``path`` from a :func:`_snapshot_node` blob."""
    snippet = (
        f"config_set_path({helpers._php_str(path)}, "
        f"unserialize(base64_decode({helpers._php_str(blob)})));\n"
        "write_config('pfBlockerNG smoke: restore category ledger-close test node');\n"
        "echo 'OK';"
    )
    result = helpers.php_eval(vm, snippet, timeout=AJAX_TIMEOUT)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(
            f"_restore_node({path!r}) failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}"
        )


def _seed_single_dnsbl_row(vm: helpers.SmokeVM, aliasname: str, action: str) -> None:
    """Replace the DNSBL-groups node with exactly ONE known row (index 0).

    Sibling of ``test_category.py``'s ``_seed_single_ipv4_row`` for the DNSBL
    conf_type (``pfblockerngdnsbl``, not an IP list) -- ``aliasname`` must be
    word-only (``PFB_FILTER_WORD``), same as the IP del handler requires.
    """
    row = {
        "aliasname": aliasname,
        "action": action,
        "cron": "Never",
        "logging": "enabled",
        "description": "pfBlockerNG smoke ledger-close dnsbl row",
    }
    snippet = (
        f"$list = {helpers._php_kv_array(row)};\n"
        f"config_set_path({helpers._php_str(DNSBL_LISTS)}, array($list));\n"
        "write_config('pfBlockerNG smoke: seed DNSBL category row');\n"
        "echo 'OK';"
    )
    result = helpers.php_eval(vm, snippet, timeout=AJAX_TIMEOUT)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_seed_single_dnsbl_row failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}")


def _ajax_post_typed(webui: WebUI, page_type: str, data: dict[str, str]) -> str:
    """Drive a DIRECT CSRF-authenticated POST to the Category AJAX endpoint for ``page_type``.

    Generic sibling of ``test_category.py``'s own ``_ajax_post`` (hardcoded to
    the IPv4 page) -- GETs ``CATEGORY_PAGE?type=<page_type>`` for a fresh
    ``__csrf_magic`` token before posting, so the DNSBL tab's own render is what
    seeds the token.
    """
    page = webui.get(f"{CATEGORY_PAGE}?type={page_type}")
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


def _ledger_is_open(vm: helpers.SmokeVM, facility: str, item: str, stage: str) -> bool:
    """True iff ``{facility,item,stage}`` is currently OPEN in the REAL sync-status ledger.

    Reads through the production ``pfb_sync_status_list_open()`` (KILL-GATE
    mandate: probe the extracted ledger logic itself, never a hand-parsed
    ledger file).
    """
    snippet = (
        "require_once('/usr/local/pkg/pfblockerng/pfblockerng_extra.inc');\n"
        f"$open = pfb_sync_status_list_open({helpers._php_str(_LEDGER_DIR)}, {helpers._php_str(facility)});\n"
        "$hit = 'NO';\n"
        "foreach ($open as $e) {\n"
        f"  if ($e['item'] === {helpers._php_str(item)} && $e['stage'] === {helpers._php_str(stage)}) {{\n"
        "    $hit = 'YES';\n"
        "  }\n"
        "}\n"
        "echo $hit;"
    )
    result = helpers.php_eval(vm, snippet)
    assert result.returncode == 0, f"_ledger_is_open({facility!r}, {item!r}, {stage!r}) failed: {result.stderr!r}"
    if "YES" in result.stdout:
        return True
    if "NO" in result.stdout:
        return False
    raise RuntimeError(f"_ledger_is_open: unexpected pfSsh.php output {result.stdout!r}")


# --------------------------------------------------------------------------- #
# IPv4 DELETE -- act=del closes the removed alias's orphaned download entry.
# --------------------------------------------------------------------------- #


def test_category_delete_closes_orphaned_ipv4_download_ledger_entry(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    clean_ledger: None,
) -> None:
    """``act=del`` on an IPv4 alias closes its orphaned ``ip``/``download`` entry.

    Before this fix, nothing ever closed ``pfB_<alias>_v4``'s download key once
    the alias itself was gone -- it stayed open in the ledger/widget forever.
    """
    vm = smoke_vm
    alias = f"pfbldg{uuid.uuid4().hex[:8]}"
    item = f"pfB_{alias}_v4"
    snap = _snapshot_lists(vm)
    try:
        _seed_single_ipv4_row(vm, alias, "Deny_Both")
        _ledger_open(vm, "ip", item, "download", "smoke: synthetic download failure")
        # BEFORE: the download entry is genuinely open first.
        assert _ledger_is_open(vm, "ip", item, "download"), "seed did not open the download ledger entry"

        _ajax_post(webui, {"act": "del", "type": "ipv4", "rowid": "0"})

        assert not _ledger_is_open(vm, "ip", item, "download"), (
            "act=del must close the removed alias's orphaned stage=download entry"
        )
    finally:
        _restore_lists(vm, snap)


# --------------------------------------------------------------------------- #
# IPv4 RENAME -- category_edit save closes the OLD name's orphaned entry.
# --------------------------------------------------------------------------- #


def test_category_edit_rename_closes_orphaned_ipv4_download_ledger_entry(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    clean_ledger: None,
) -> None:
    """Renaming an IPv4 alias in category_edit closes the OLD name's orphaned download entry.

    True lifecycle transition: save the alias under its OLD name, open the OLD
    name's download entry, assert OPEN, re-save the SAME rowid under a NEW
    aliasname, assert the OLD key is CLOSED -- nothing else re-keys or closes a
    download entry on an aliasname change.
    """
    vm = smoke_vm
    rowid = _ce_free_rowid(vm, _CE_CFG_IPV4)
    old_alias = f"pfbldgold{uuid.uuid4().hex[:6]}"
    new_alias = f"pfbldgnew{uuid.uuid4().hex[:6]}"
    old_item = f"pfB_{old_alias}_v4"
    try:
        _ce_post_form(webui, _ce_ipv4_payload(rowid, old_alias, action="Deny_Both"))
        assert helpers.config_get(vm, f"{_CE_CFG_IPV4}/{rowid}/aliasname") == old_alias, (
            "seed save did not land the old aliasname"
        )
        _ledger_open(vm, "ip", old_item, "download", "smoke: synthetic download failure")
        # BEFORE: the OLD alias's download entry is genuinely open first.
        assert _ledger_is_open(vm, "ip", old_item, "download"), "seed did not open the old alias's download entry"

        _ce_post_form(webui, _ce_ipv4_payload(rowid, new_alias, action="Deny_Both"))
        assert helpers.config_get(vm, f"{_CE_CFG_IPV4}/{rowid}/aliasname") == new_alias, (
            "rename save did not land the new aliasname"
        )

        assert not _ledger_is_open(vm, "ip", old_item, "download"), (
            "renaming the alias must close the OLD name's orphaned stage=download entry"
        )
    finally:
        _ce_del_rowid(vm, _CE_CFG_IPV4, rowid)


# --------------------------------------------------------------------------- #
# DNSBL DELETE -- sibling axis: the download key has NO _v4/_v6 suffix.
# --------------------------------------------------------------------------- #


def test_category_delete_closes_orphaned_dnsbl_download_ledger_entry(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    clean_ledger: None,
) -> None:
    """``act=del`` on a DNSBL group closes its orphaned ``dnsbl``/``download`` entry.

    Sibling axis to the IPv4 delete case, proving the helper's facility='dnsbl'
    branch: the DNSBL download key is ``DNSBL_<alias>`` (no _v4/_v6 suffix).
    """
    vm = smoke_vm
    alias = f"pfbldg{uuid.uuid4().hex[:8]}"
    item = f"DNSBL_{alias}"
    snap = _snapshot_node(vm, DNSBL_LISTS)
    try:
        _seed_single_dnsbl_row(vm, alias, "unbound")
        _ledger_open(vm, "dnsbl", item, "download", "smoke: synthetic download failure")
        assert _ledger_is_open(vm, "dnsbl", item, "download"), "seed did not open the download ledger entry"

        _ajax_post_typed(webui, "dnsbl", {"act": "del", "type": "dnsbl", "rowid": "0"})

        assert not _ledger_is_open(vm, "dnsbl", item, "download"), (
            "act=del must close the removed DNSBL group's orphaned stage=download entry"
        )
    finally:
        _restore_node(vm, DNSBL_LISTS, snap)
