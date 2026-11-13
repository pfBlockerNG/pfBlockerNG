"""Issue #3945: Groups saves and deletes refuse a held config lock; a delete refuses another group."""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .test_category import (
    IPV4_LISTS,
    IPV4_PAGE,
    _ajax_post,
    _restore_lists,
    _seed_single_ipv4_row,
    _seed_three_rows,
    _snapshot_lists,
)
from .test_category_edit import CFG_DNSBL, _del_rowid, _dnsbl_payload, _free_rowid, _post_form

if TYPE_CHECKING:
    from .webui import WebUI

pytestmark = pytest.mark.ui_e2e

REFUSAL = "another save of the pfSense configuration is in progress"
DELETE_REFUSAL = f"The group was not deleted: {REFUSAL}. Try again in a moment."
CHANGED_REFUSAL = "The group was not deleted: it was changed by another save."


def test_group_save_refuses_config_lock_without_changing_stored_group(smoke_vm: helpers.SmokeVM, webui: WebUI) -> None:
    """Given a stored group, a save while another writer holds the lock is rejected and leaves it unchanged."""
    vm = smoke_vm
    rowid = _free_rowid(vm, CFG_DNSBL)
    alias = f"Lock{uuid.uuid4().hex[:16]}"
    path = f"{CFG_DNSBL}/{rowid}/description"
    try:
        _post_form(webui, _dnsbl_payload(rowid, alias, description="before lock"))
        assert helpers.config_get(vm, path) == "before lock", "before-state: the group must be stored"
        with helpers.config_lock_held(vm):
            _post_form(
                webui,
                _dnsbl_payload(rowid, alias, description="must not save"),
                expect_rejection=REFUSAL,
            )
        assert helpers.config_get(vm, path) == "before lock", "a refused save must not change the stored group"
    finally:
        _del_rowid(vm, CFG_DNSBL, rowid)


def test_group_delete_refuses_config_lock_without_removing_stored_group(
    smoke_vm: helpers.SmokeVM, webui: WebUI
) -> None:
    """Given a stored group, a delete while another writer holds the lock reports refusal and keeps the group."""
    vm = smoke_vm
    alias = f"Lock{uuid.uuid4().hex[:16]}"
    snapshot = _snapshot_lists(vm)
    try:
        _seed_single_ipv4_row(vm, alias, "Deny_Both")
        path = f"{IPV4_LISTS}/0/aliasname"
        assert helpers.config_get(vm, path) == alias, "before-state: the group must exist"
        with helpers.config_lock_held(vm):
            response = _ajax_post(webui, {"act": "del", "type": "ipv4", "rowid": "0", "aliasname": alias})
        assert DELETE_REFUSAL in response, f"the delete must report that it did not happen: {response[-3000:]}"
        assert helpers.config_get(vm, path) == alias, "a refused delete must keep the stored group"
    finally:
        _restore_lists(vm, snapshot)


def test_group_delete_refuses_a_name_that_is_not_the_group_at_the_row(smoke_vm: helpers.SmokeVM, webui: WebUI) -> None:
    """A delete whose name is another group's is refused and removes nothing; the right name deletes that row.

    Given: three stored groups
    When:  row 0 is deleted under the name of row 1 (a page that showed row 1 there)
    Then:  the refusal says the group changed, and all three groups remain; naming row 0 then deletes row 0
    """
    vm = smoke_vm
    tag = uuid.uuid4().hex[:8]
    names = [f"lk{tag}{suffix}" for suffix in "abc"]
    snapshot = _snapshot_lists(vm)
    try:
        _seed_three_rows(vm, IPV4_LISTS, "ipv4", names)
        stored = [helpers.config_get(vm, f"{IPV4_LISTS}/{i}/aliasname") for i in range(3)]
        assert stored == names, f"before-state: the three groups must be stored in order: {stored}"

        response = _ajax_post(
            webui, {"act": "del", "type": "ipv4", "rowid": "0", "aliasname": names[1]}, page=IPV4_PAGE
        )
        assert CHANGED_REFUSAL in response, f"the delete must say the group changed: {response[-3000:]}"
        stored = [helpers.config_get(vm, f"{IPV4_LISTS}/{i}/aliasname") for i in range(3)]
        assert stored == names, f"a refused delete must remove nothing: {stored}"

        _ajax_post(webui, {"act": "del", "type": "ipv4", "rowid": "0", "aliasname": names[0]}, page=IPV4_PAGE)
        stored = [helpers.config_get(vm, f"{IPV4_LISTS}/{i}/aliasname") for i in range(3)]
        assert stored == [names[1], names[2], ""], f"naming the group at the row must delete it: {stored}"
    finally:
        _restore_lists(vm, snapshot)
