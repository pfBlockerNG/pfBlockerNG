"""Failure-path isolation for Alerts whitelist UI coverage."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from . import test_alerts

if TYPE_CHECKING:
    from .webui import WebUI

pytestmark = pytest.mark.ui_e2e

WHITELIST_PATH = "/var/unbound/pfb_py_whitelist.txt"
MANIFEST_PATH = "/var/unbound/pfb_py_sources.json"


def _derived_whitelist_entries(vm: helpers.SmokeVM) -> tuple[set[str], set[str] | None]:
    whitelist = {
        line.partition(",")[0] for line in helpers.read_log_file(vm, WHITELIST_PATH).splitlines() if line.strip()
    }
    manifest_raw = helpers.read_log_file(vm, MANIFEST_PATH)
    if not manifest_raw:
        return whitelist, None
    manifest = json.loads(manifest_raw)
    return whitelist, set(manifest["config"]["user_whitelist"])


def test_addwhitelistdom_failure_restores_derived_unbound_state(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An assertion failure after whitelist POST leaves no derived Unbound entry."""
    original = helpers.config_get(smoke_vm, test_alerts.CFG_WHITELIST)
    original_entries = test_alerts._suppression_entries(smoke_vm, test_alerts.CFG_WHITELIST)
    suppression_entries = test_alerts._suppression_entries
    added_entries: set[str] = set()

    def fail_after_post(vm: helpers.SmokeVM, cfg_path: str) -> set[str]:
        entries = suppression_entries(vm, cfg_path)
        if added := entries - original_entries:
            added_entries.update(added)
            normalised = {entry.removeprefix("www.") for entry in added}
            whitelist, manifest = _derived_whitelist_entries(vm)
            assert normalised <= whitelist, f"POST did not add {normalised!r} to {WHITELIST_PATH}"
            if manifest is not None:
                assert added <= manifest, f"POST did not add {added!r} to manifest user_whitelist"
            raise RuntimeError("injected assertion failure after whitelist POST")
        return entries

    monkeypatch.setattr(test_alerts, "_suppression_entries", fail_after_post)
    with pytest.raises(RuntimeError, match="injected assertion failure after whitelist POST"):
        test_alerts.test_addwhitelistdom_writes_whitelist_and_entry_delete_removes_it(webui, smoke_vm)

    assert helpers.config_get(smoke_vm, test_alerts.CFG_WHITELIST) == original
    assert added_entries, "failure injection did not observe the whitelist POST mutation"
    normalised = {entry.removeprefix("www.") for entry in added_entries}
    whitelist, manifest = _derived_whitelist_entries(smoke_vm)
    assert normalised.isdisjoint(whitelist), f"failed test leaked {normalised!r} into {WHITELIST_PATH}"
    if manifest is not None:
        assert added_entries.isdisjoint(manifest), f"failed test leaked {added_entries!r} into manifest user_whitelist"
