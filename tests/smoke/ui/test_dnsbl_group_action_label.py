"""The DNSBL Category list page labels the stored 'unbound' group action as Block.

The stored key stays 'unbound' so existing groups keep resolving; only the rendered
option text changed. Rendered from the live box, so a regression in the page's option
array or its wiring fails here and not only in the hermetic PHP test.
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

_ACTION_SELECT_RE = re.compile(
    r'<select\b[^>]*\bname=["\']action-0["\'][^>]*>(.*?)</select>', re.IGNORECASE | re.DOTALL
)
_OPTION_RE = re.compile(r'<option\b[^>]*\bvalue=["\']([^"\']*)["\'][^>]*>(.*?)</option>', re.IGNORECASE | re.DOTALL)


def test_dnsbl_group_action_option_is_labelled_block(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """The DNSBL group Action dropdown shows the stored 'unbound' value as Block,
    and no option on the page still reads Unbound."""
    vm = smoke_vm
    snap = _snapshot_node(vm, DNSBL_GROUPS)
    try:
        _seed_two_dnsbl_rows(vm)
        page = webui.get(_page_url("dnsbl"))
        assert page.status_code == 200, f"DNSBL category page HTTP {page.status_code}"
        body = page.text
        assert not looks_like_login_page(body), "webConfigurator session not authenticated"

        select = _ACTION_SELECT_RE.search(body)
        assert select is not None, "DNSBL group Action select (action-0) not rendered"
        options = {value: label.strip() for value, label in _OPTION_RE.findall(select.group(1))}

        assert options.get("unbound") == "Block", f"stored unbound value must read Block, got {options!r}"
        assert options.get("Disabled") == "Disabled", f"Disabled option missing, got {options!r}"
        assert "Unbound" not in options.values(), f"an option still reads Unbound: {options!r}"
    finally:
        _restore_node(vm, DNSBL_GROUPS, snap)
