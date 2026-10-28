"""The DNSBL group Action option for the stored 'unbound' value is labelled Enable.

The stored key stays 'unbound' so existing groups keep resolving; only the rendered
option text changed. Rendered from the live box, so a regression in either page's
option array or its wiring fails here and not only in the hermetic PHP test.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

import pytest

from .test_category import DNSBL_GROUPS, _page_url, _restore_node, _snapshot_node
from .test_category_list_override_preserves_group_choices import _seed_two_dnsbl_rows
from .webui import looks_like_login_page

if TYPE_CHECKING:
    from .. import helpers
    from .webui import WebUI

pytestmark = pytest.mark.ui_render

EDIT_PAGE_URL = "/pfblockerng/pfblockerng_category_edit.php?type=dnsbl"
_LIST_ACTION_SELECT_RE = re.compile(
    r'<select\b[^>]*\bname=["\']action-0["\'][^>]*>(.*?)</select>', re.IGNORECASE | re.DOTALL
)
_EDIT_ACTION_SELECT_RE = re.compile(
    r'<select\b[^>]*\bname=["\']action["\'][^>]*>(.*?)</select>', re.IGNORECASE | re.DOTALL
)
_OPTION_RE = re.compile(r'<option\b[^>]*\bvalue=["\']([^"\']*)["\'][^>]*>(.*?)</option>', re.IGNORECASE | re.DOTALL)
_HELP_BLOCK_RE = re.compile(
    r'class=["\'][^"\']*\bhelp-block\b[^"\']*["\'][^>]*>(.*?)</(?:span|div|p)>', re.IGNORECASE | re.DOTALL
)


def _assert_enable_option(body: str, select_re: re.Pattern[str], where: str) -> None:
    select = select_re.search(body)
    assert select is not None, f"DNSBL group Action select not rendered on {where}"
    options = {value: label.strip() for value, label in _OPTION_RE.findall(select.group(1))}
    assert options.get("unbound") == "Enable", f"{where}: stored unbound value must read Enable, got {options!r}"
    assert options.get("Disabled") == "Disabled", f"{where}: Disabled option missing, got {options!r}"
    assert "Unbound" not in options.values(), f"{where}: an option still reads Unbound: {options!r}"


def test_dnsbl_group_action_list_option_is_labelled_enable(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """The DNSBL category list page shows the stored 'unbound' action as Enable."""
    vm = smoke_vm
    snap = _snapshot_node(vm, DNSBL_GROUPS)
    try:
        _seed_two_dnsbl_rows(vm)
        page = webui.get(_page_url("dnsbl"))
        assert page.status_code == 200, f"DNSBL category page HTTP {page.status_code}"
        assert not looks_like_login_page(page.text), "webConfigurator session not authenticated"
        _assert_enable_option(page.text, _LIST_ACTION_SELECT_RE, "category list")
    finally:
        _restore_node(vm, DNSBL_GROUPS, snap)


def test_dnsbl_group_action_edit_option_is_labelled_enable(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """The DNSBL category edit page offers the stored 'unbound' action as Enable."""
    vm = smoke_vm
    snap = _snapshot_node(vm, DNSBL_GROUPS)
    try:
        _seed_two_dnsbl_rows(vm)
        page = webui.get(EDIT_PAGE_URL)
        assert page.status_code == 200, f"DNSBL category edit page HTTP {page.status_code}"
        assert not looks_like_login_page(page.text), "webConfigurator session not authenticated"
        _assert_enable_option(page.text, _EDIT_ACTION_SELECT_RE, "category edit")
        # The group Action's own help is the first help-block rendered after its select.
        select = _EDIT_ACTION_SELECT_RE.search(page.text)
        assert select is not None
        help_block = _HELP_BLOCK_RE.search(page.text, select.end())
        assert help_block is not None, "group Action help not rendered after its select"
        for word in ("Enable", "Deny", "Permit", "Custom List"):
            assert word in help_block.group(1), f"group Action help lacks {word!r}: {help_block.group(1)!r}"
    finally:
        _restore_node(vm, DNSBL_GROUPS, snap)
