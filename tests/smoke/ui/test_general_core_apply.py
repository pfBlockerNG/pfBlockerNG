"""General-save Core apply coverage, selected by both UI render and functional tiers (#3977)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from .. import helpers
from ..test_smoke_core_api import await_core_up

if TYPE_CHECKING:
    from ..conftest import SmokeVM
    from .webui import WebUI

pytestmark = [pytest.mark.ui_render, pytest.mark.ui_e2e]

GENERAL_PAGE = "/pfblockerng/pfblockerng_general.php"
KEEP_SETTING = "installedpackages/pfblockerng/config/0/pfb_keep"
PENDING_MARKER = "/usr/local/etc/pfb_pending_changes"
APPLY_PHASE = "===[  Aliastables / Rules  ]"
SAVE_TIMEOUT = 300.0
UPDATE_WATCHDOG = 600.0
CORE_RC = "/usr/local/etc/rc.d/pfb_core.sh"


def _pending_token(vm: SmokeVM) -> str | None:
    result = vm.ssh(f"/bin/cat {PENDING_MARKER}")
    if result.returncode == 1:
        return None
    assert result.returncode == 0, f"could not read pending marker: {result.stderr!r}"
    return result.stdout.strip()


@pytest.mark.parametrize("core_available", [True, False], ids=["admitted", "unavailable"])
def test_general_save_uses_core_apply_without_an_inline_feed_pass(
    smoke_vm: SmokeVM, webui: WebUI, core_available: bool
) -> None:
    """A disabled save either completes one Core apply or retains pending work without an inline pass."""
    vm = smoke_vm
    before_view = helpers.core_update_view(vm)
    if before_view["running"]:
        before_view = helpers.await_core_update_end(vm, before=before_view["update"], watchdog=UPDATE_WATCHDOG)
    before_update: dict[str, Any] | None = before_view["update"]
    marker_before = _pending_token(vm)
    package_log_before = helpers.read_log_file(vm, helpers.PFB_LOG)
    keep_state = helpers.config_get_state(vm, KEEP_SETTING)
    keep_value = "" if keep_state[0] and keep_state[1] == "on" else "on"
    try:
        if not core_available:
            stopped = vm.ssh(CORE_RC, "stop", timeout=60)
            assert stopped.returncode == 0, f"cannot stop Core for the unavailable scenario: {stopped}"
            health = helpers.core_call(vm, "GetVersion")
            assert health["status"] == 0 and health["error"], f"Core was not genuinely unavailable: {health}"
        response = webui.post(GENERAL_PAGE, {"pfb_keep": keep_value, "enable_cb": ""}, timeout=SAVE_TIMEOUT)
        assert "Sign In" not in response.text, "General save lost the authenticated UI session"
        assert helpers.config_get(vm, KEEP_SETTING) == keep_value, "General save did not persist Keep"
        assert helpers.config_get(vm, helpers.CFG_GLOBAL + "/enable_cb") != "on", (
            "General save did not disable the package"
        )
        reply = helpers.core_call(vm, "GetUpdate")
        if core_available:
            assert reply["status"] == 200, f"Core became unavailable during the admitted scenario: {reply}"
            after_view = reply["body"]
            update = after_view["update"]
            assert update is not None and update != before_update and update.get("trigger") == "apply", (
                f"General save did not admit its Core apply: {after_view}"
            )
            if after_view["running"]:
                after_view = helpers.await_core_update_end(vm, before=before_update, watchdog=UPDATE_WATCHDOG)
            assert not after_view["running"] and after_view["update"]["result"] == "success", (
                f"Core apply did not finish successfully: {after_view}"
            )
            assert after_view["update"]["trigger"] == "apply", f"Core ran a different Update: {after_view}"
            update_log = helpers.core_update_log(vm)
            assert update_log.count(APPLY_PHASE) == 1, f"Core's apply log lacks one rules phase: {update_log[-2000:]!r}"
        else:
            assert reply["status"] == 0 and reply["error"], (
                f"Core unexpectedly served the unavailable scenario: {reply}"
            )
            marker_after = _pending_token(vm)
            assert marker_after is not None and marker_after != marker_before, "General save lost its new pending token"

        package_log_after = helpers.read_log_file(vm, helpers.PFB_LOG)
        assert package_log_after.startswith(package_log_before), "package log rotated or truncated during General save"
        package_log_window = package_log_after[len(package_log_before) :]
        phase_count = package_log_window.count(APPLY_PHASE)
        expected = 1 if core_available else 0
        assert phase_count == expected, (
            f"General save rules phases={phase_count}, expected {expected}; inline/duplicate pass:\n"
            f"{package_log_window[-2000:]}"
        )
        if not core_available:
            assert _pending_token(vm) == marker_after, "unavailable save did not retain its pending token"
    finally:
        if not core_available:
            restored = vm.ssh(CORE_RC, "start", timeout=60)
            assert restored.returncode == 0, f"cannot restore Core after the unavailable scenario: {restored}"
            await_core_up(vm)
            print("ui_core_availability: Core restored after unavailable scenario", flush=True)
