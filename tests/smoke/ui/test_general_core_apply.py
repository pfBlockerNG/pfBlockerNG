"""Tier-A UI coverage for General save dispatching its feed apply through Core (#3977)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from .. import helpers

if TYPE_CHECKING:
    from ..conftest import SmokeVM
    from .webui import WebUI

pytestmark = pytest.mark.ui_render

GENERAL_PAGE = "/pfblockerng/pfblockerng_general.php"
KEEP_SETTING = "installedpackages/pfblockerng/config/0/pfb_keep"
PENDING_MARKER = "/usr/local/etc/pfb_pending_changes"
UPDATE_START = "UPDATE PROCESS START"
UPDATE_END = "UPDATE PROCESS ENDED"
SAVE_TIMEOUT = 300.0
UPDATE_WATCHDOG = 600.0


def _pending_token(vm: SmokeVM) -> str | None:
    result = vm.ssh(f"/bin/cat {PENDING_MARKER}")
    if result.returncode == 1:
        return None
    assert result.returncode == 0, f"could not read pending marker: {result.stderr!r}"
    return result.stdout.strip()


def test_general_save_uses_core_apply_without_an_inline_feed_pass(smoke_vm: SmokeVM, webui: WebUI) -> None:
    """A save starts Core's apply (or leaves durable pending work), never a PHP feed pass in the request."""
    vm = smoke_vm
    before_view = helpers.core_update_view(vm)
    if before_view["running"]:
        before_view = helpers.await_core_update_end(vm, before=before_view["update"], watchdog=UPDATE_WATCHDOG)
    before_update: dict[str, Any] | None = before_view["update"]
    marker_before = _pending_token(vm)
    start_lines_before = helpers.count_log_marker(vm, helpers.PFB_LOG, UPDATE_START)

    keep_state = helpers.config_get_state(vm, KEEP_SETTING)
    keep_value = "on" if not keep_state[0] or keep_state[1] == "on" else ""
    response = webui.post(GENERAL_PAGE, {"pfb_keep": keep_value}, timeout=SAVE_TIMEOUT)
    assert "Sign In" not in response.text, "General save lost the authenticated UI session"

    after_view = helpers.core_update_view(vm)
    update = after_view["update"]
    started_apply = update is not None and update != before_update and update.get("trigger") == "apply"
    marker_after = _pending_token(vm)
    assert started_apply or (marker_after is not None and marker_after != marker_before), (
        f"General save neither started a Core apply nor recorded pending work: {after_view}"
    )

    if started_apply:
        if after_view["running"]:
            after_view = helpers.await_core_update_end(vm, before=before_update, watchdog=UPDATE_WATCHDOG)
        assert after_view["update"]["trigger"] == "apply", f"Core did not run the saved-settings apply: {after_view}"
        update_log = helpers.core_update_log(vm)
        assert UPDATE_START in update_log and UPDATE_END in update_log, (
            f"Core's apply log is incomplete: {update_log[-2000:]!r}"
        )
        assert helpers.count_log_marker(vm, helpers.PFB_LOG, UPDATE_START) - start_lines_before == 1, (
            "General save must not run a second PHP feed pass inline; the only pass start belongs to Core's apply"
        )
    else:
        assert helpers.count_log_marker(vm, helpers.PFB_LOG, UPDATE_START) == start_lines_before, (
            "a Core-unavailable save must not fall back to an inline PHP feed pass"
        )
