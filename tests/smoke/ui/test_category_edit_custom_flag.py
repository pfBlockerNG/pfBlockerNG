"""issue #1080 -- a Disabled-action alias save must not write its custom-list
update flag at the filesystem root.

When a saved alias's Custom List changed, ``pfblockerng_category_edit.php``
touch()ed ``{$pfbarr['folder']}/{$aname}_custom{$suffix}.update`` -- but a
Disabled action has no list folder, so ``pfb_determine_list_detail()`` leaves
the array empty and the flag landed at ``/{$aname}_custom.update`` (the
WebGUI runs as root, so the stray write succeeds). The touch is now guarded
on a non-empty folder (off-appliance red/green pinned by
``tests/php/CategoryEditCustomFlagTest.php``; this exercises the same save
end-to-end through the real page).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .test_category_edit import CFG_DNSBL, _del_rowid, _dnsbl_payload, _free_rowid, _post_form

if TYPE_CHECKING:
    from .webui import WebUI

# Tier B: a mutating POST flow whose failure artifact (a stray file at the
# guest's filesystem root) is observable only on-box. Tier A render coverage
# of this page already exists (test_render_smoke.py / test_category_edit.py).
pytestmark = pytest.mark.ui_e2e


def _root_flag_exists(vm: helpers.SmokeVM, path: str) -> bool:
    pre = f"$e = file_exists({helpers._php_str(path)}) ? 'YES' : 'NO';"
    return helpers._php_read_scalar(vm, pre, "$e", timeout=120.0) == "YES"


def test_disabled_action_custom_save_writes_no_root_flag(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """Scenario: saving a Disabled-action DNSBL alias with a fresh Custom List.

    Given a free alias slot and a payload whose ``action`` is ``Disabled`` and
      whose ``custom`` list is non-empty (so the stored-vs-posted comparison
      fires the update-flag branch),

    When the category-edit save is POSTed,

    Then no ``/{alias}_custom.update`` file appears at the guest's filesystem
      root (before the guard, the WebGUI -- running as root -- created it).
    """
    rowid = _free_rowid(smoke_vm, CFG_DNSBL)
    alias = f"RootFlag{rowid}"
    root_flag = f"/{alias}_custom.update"

    try:
        payload = _dnsbl_payload(
            rowid,
            alias,
            action="Disabled",
            custom="custom-1080.example.com",
        )
        _post_form(webui, payload)

        assert not _root_flag_exists(smoke_vm, root_flag), (
            f"the Disabled-action save must not create {root_flag} at the filesystem root"
        )
    finally:
        # Sweep the stray flag a pre-guard build may have written, then the slot.
        helpers.php_eval(
            smoke_vm,
            f"@unlink({helpers._php_str(root_flag)}); echo 'OK';",
            timeout=120.0,
        )
        _del_rowid(smoke_vm, CFG_DNSBL, rowid)
