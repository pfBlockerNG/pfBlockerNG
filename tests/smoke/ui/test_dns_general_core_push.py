"""Tier-A ``ui_render`` coverage for issue #3913: a DNS General save reaches pfBlockerNG Core, or says it did not.

config.xml is the authority for the settings Core models; the page that saves one pushes it to Core once the write
succeeded. With Core serving, a save of DNS Reply Logging advances Core's revision by one and leaves Core holding the
saved value. With Core stopped, the save is written anyway and DNS General shows that Core does not have the settings
yet; once Core is started it holds them (the service's start pushes) and the notice is gone. The oracle is Core's own
answer and config.xml read back over SSH, never the HTTP body.
"""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING

import pytest

from ..test_smoke_core_api import CORE_RC, await_core_dns, await_core_up, config_dns_settings, core_dns, push_now
from .render_oracle import NO_INPUT_ERRORS
from .test_dns_general_foreign_list_warning import _render
from .test_dns_general_forms import DNS_GENERAL_PAGE, REPLY_LOGGING, SAVE_TIMEOUT, _both_parts_seeded, _stored
from .test_dnsbl_follows_pfb_dns import _errors_text

if TYPE_CHECKING:
    from collections.abc import Iterator

    from ..conftest import SmokeVM
    from .webui import WebUI

pytestmark = pytest.mark.ui_render

NOTICE = "pfBlockerNG Core does not have the saved settings yet"


@pytest.fixture
def core_serving(smoke_vm: SmokeVM, webui: WebUI) -> None:
    """Core answers (the webui fixture has the package deployed, and its install starts the service)."""
    await_core_up(smoke_vm)


@contextlib.contextmanager
def _core_in_step(vm: SmokeVM) -> Iterator[None]:
    """Whatever the test did, Core ends serving and holding what config.xml says."""
    try:
        yield
    finally:
        vm.ssh(f"{CORE_RC} start", timeout=60)  # keeps a Core that is serving
        await_core_up(vm)
        push_now(vm)


def _held_reply_logging(vm: SmokeVM) -> tuple[int, bool]:
    """Core's revision and its replyLogging."""
    held = core_dns(vm)
    assert held is not None and held[1] is not None, f"Core holds no settings/dns: {held}"
    return held[0], bool(held[1]["replyLogging"])


def test_a_dns_general_save_with_core_serving_leaves_core_holding_the_saved_value(
    smoke_vm: SmokeVM, webui: WebUI, core_serving: None
) -> None:
    """The save advances Core's revision by exactly one and Core's replyLogging is the saved value.

    Given: DNS Reply Logging On in config.xml and in Core
    When:  DNS General is saved with DNS Reply Logging unticked
    Then:  config.xml holds Off, Core holds Off one revision later, and the page shows no push-failure notice
    """
    vm = smoke_vm
    with _core_in_step(vm), _both_parts_seeded(vm):
        push_now(vm)
        revision, reply_logging = _held_reply_logging(vm)
        assert reply_logging is True, "before-state: Core must hold DNS Reply Logging On"
        assert _stored(vm, [REPLY_LOGGING])[REPLY_LOGGING] == "on", "before-state: config.xml must hold it On"

        saved = webui.post(DNS_GENERAL_PAGE, {"pfb_py_reply": ""}, timeout=SAVE_TIMEOUT)

        assert _errors_text(saved.text) == NO_INPUT_ERRORS, f"the save was refused: {_errors_text(saved.text)}"
        assert _stored(vm, [REPLY_LOGGING])[REPLY_LOGGING] == "", "config.xml must hold DNS Reply Logging Off"
        assert _held_reply_logging(vm) == (revision + 1, False), "Core must hold the saved value, one revision later"
        assert NOTICE not in _render(vm, webui), "Core has the settings: no notice"


def test_a_dns_general_save_with_core_stopped_is_written_and_says_core_does_not_have_it_yet(
    smoke_vm: SmokeVM, webui: WebUI, core_serving: None
) -> None:
    """A stopped Core never blocks the save; the page says so until Core has the values.

    Given: DNS Reply Logging On in config.xml and in Core, then Core stopped
    When:  DNS General is saved with DNS Reply Logging unticked
    Then:  config.xml holds Off and DNS General shows the notice; once Core is started it holds Off, the notice is gone
    """
    vm = smoke_vm
    with _core_in_step(vm), _both_parts_seeded(vm):
        push_now(vm)
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

        assert NOTICE not in _render(vm, webui), "Core holds the settings: the notice must be gone"
