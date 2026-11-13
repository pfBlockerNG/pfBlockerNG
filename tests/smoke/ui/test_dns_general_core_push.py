"""Tier-A ``ui_render`` coverage for issues #3913, #3924: a DNS General save reaches Core, or says it did not.

config.xml is the only store of the settings Core models; the page that saves one tells Core once the write succeeded,
and Core reads config.xml again through its settings adapter. With Core serving, a save of DNS Reply Logging leaves
Core holding the saved value at the revision config.xml projects. With Core stopped, the save is written anyway and
DNS General shows that Core has not read the settings yet; once Core is started it reads them, and the next tick
(which finds Core at config.xml's revision) clears the notice. The oracle is Core's own answer and config.xml read back
over SSH, never the HTTP body.
"""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING

import pytest

from ..test_smoke_core_api import (
    CORE_RC,
    await_core_dns,
    await_core_up,
    config_dns_settings,
    config_revision,
    core_dns,
    run_tick,
    tell_core,
)
from .render_oracle import NO_INPUT_ERRORS
from .test_dns_general_foreign_list_warning import _render
from .test_dns_general_forms import DNS_GENERAL_PAGE, REPLY_LOGGING, SAVE_TIMEOUT, _both_parts_seeded, _stored
from .test_dnsbl_follows_pfb_dns import _errors_text

if TYPE_CHECKING:
    from collections.abc import Iterator

    from ..conftest import SmokeVM
    from .webui import WebUI

pytestmark = pytest.mark.ui_render

NOTICE = "pfBlockerNG Core has not read the saved settings yet"


@pytest.fixture
def core_serving(smoke_vm: SmokeVM, webui: WebUI) -> None:
    """Core answers (the webui fixture has the package deployed, and its install starts the service)."""
    await_core_up(smoke_vm)


@contextlib.contextmanager
def _core_in_step(vm: SmokeVM) -> Iterator[None]:
    """Whatever the test did, Core ends serving, holding what config.xml says, with no notice pending."""
    try:
        yield
    finally:
        vm.ssh(f"{CORE_RC} start", timeout=60)  # keeps a Core that is serving
        await_core_up(vm)
        tell_core(vm)


def _held_reply_logging(vm: SmokeVM) -> tuple[int, bool]:
    """Core's revision and its replyLogging."""
    held = core_dns(vm)
    assert held is not None and held[1] is not None, f"Core holds no settings/dns: {held}"
    return held[0], bool(held[1]["replyLogging"])


def test_a_dns_general_save_with_core_serving_leaves_core_holding_the_saved_value(
    smoke_vm: SmokeVM, webui: WebUI, core_serving: None
) -> None:
    """Core's replyLogging is the saved value, at the revision config.xml projects.

    Given: DNS Reply Logging On in config.xml and in Core
    When:  DNS General is saved with DNS Reply Logging unticked
    Then:  config.xml holds Off, Core holds Off at config.xml's revision, and the page shows no notice
    """
    vm = smoke_vm
    with _core_in_step(vm), _both_parts_seeded(vm):
        tell_core(vm)
        revision, reply_logging = _held_reply_logging(vm)
        assert reply_logging is True, "before-state: Core must hold DNS Reply Logging On"
        assert revision == config_revision(vm), "before-state: Core must be at config.xml's revision"
        assert _stored(vm, [REPLY_LOGGING])[REPLY_LOGGING] == "on", "before-state: config.xml must hold it On"

        saved = webui.post(DNS_GENERAL_PAGE, {"pfb_py_reply": ""}, timeout=SAVE_TIMEOUT)

        assert _errors_text(saved.text) == NO_INPUT_ERRORS, f"the save was refused: {_errors_text(saved.text)}"
        assert _stored(vm, [REPLY_LOGGING])[REPLY_LOGGING] == "", "config.xml must hold DNS Reply Logging Off"
        held = _held_reply_logging(vm)
        assert held == (config_revision(vm), False), f"Core must hold the saved value at config.xml's revision: {held}"
        assert held[0] != revision, "the save moved the revision"
        assert NOTICE not in _render(vm, webui), "Core has the settings: no notice"


def test_a_dns_general_save_with_core_stopped_is_written_and_says_core_does_not_have_it_yet(
    smoke_vm: SmokeVM, webui: WebUI, core_serving: None
) -> None:
    """A stopped Core never blocks the save; the page says so until Core has read the values.

    Given: DNS Reply Logging On in config.xml and in Core, then Core stopped
    When:  DNS General is saved with DNS Reply Logging unticked
    Then:  config.xml holds Off and DNS General shows the notice; a started Core reads Off, a tick clears the notice
    """
    vm = smoke_vm
    with _core_in_step(vm), _both_parts_seeded(vm):
        tell_core(vm)
        stop = vm.ssh(f"{CORE_RC} stop", timeout=60)
        assert stop.returncode == 0, f"{CORE_RC} stop failed: {stop.stdout}{stop.stderr}"
        assert core_dns(vm) is None, "before-state: Core must be unreachable"
        assert NOTICE not in _render(vm, webui), "before-state: no notice before the save"

        saved = webui.post(DNS_GENERAL_PAGE, {"pfb_py_reply": ""}, timeout=SAVE_TIMEOUT)

        assert _errors_text(saved.text) == NO_INPUT_ERRORS, f"the save was refused: {_errors_text(saved.text)}"
        assert _stored(vm, [REPLY_LOGGING])[REPLY_LOGGING] == "", "config.xml must hold the save while Core is down"
        assert NOTICE in _render(vm, webui), "DNS General must say that Core does not have the saved settings"

        start = vm.ssh(f"{CORE_RC} start", timeout=60)
        assert start.returncode == 0, f"{CORE_RC} start failed: {start.stdout}{start.stderr}"
        await_core_dns(vm, config_dns_settings(vm))
        run_tick(vm)

        assert NOTICE not in _render(vm, webui), "Core holds the settings: the notice must be gone"
