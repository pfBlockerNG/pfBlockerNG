"""Failure-path isolation for Alerts whitelist UI coverage."""

from __future__ import annotations

import base64
import json
import subprocess
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from . import test_alerts
from .conftest import UI_CONFIG_SNAPSHOT

if TYPE_CHECKING:
    from .webui import WebUI

pytestmark = pytest.mark.ui_e2e

WHITELIST_PATH = "/var/unbound/pfb_py_whitelist.txt"
MANIFEST_PATH = "/var/unbound/pfb_py_sources.json"


def _derived_whitelist_entries(vm: helpers.SmokeVM) -> tuple[set[str] | None, set[str] | None]:
    snapshot = test_alerts._snapshot_guest_files(vm)
    whitelist_raw = snapshot[WHITELIST_PATH]
    whitelist = (
        None
        if whitelist_raw is None
        else {line.partition(",")[0] for line in whitelist_raw.splitlines() if line.strip()}
    )
    manifest_raw = snapshot[MANIFEST_PATH]
    if manifest_raw is None:
        return whitelist, None
    manifest = json.loads(manifest_raw)
    return whitelist, set(manifest["config"]["user_whitelist"])


def test_addwhitelistdom_failure_restores_derived_unbound_state(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An assertion failure after whitelist POST leaves no derived Unbound entry."""
    baseline = helpers.unique_domain("uiwlbase")
    session_derived = test_alerts._snapshot_guest_files(smoke_vm)
    try:
        encoded = base64.b64encode(f"{baseline}\n".encode()).decode()
        helpers.config_set(smoke_vm, test_alerts.CFG_WHITELIST, encoded)
        seeded = helpers.php_eval(
            smoke_vm,
            "require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');\n"
            "pfb_unbound_python_whitelist('alerts');\n"
            "echo 'OK';",
        )
        assert seeded.returncode == 0 and "OK" in seeded.stdout, seeded.stderr
        manifest_seed = json.dumps({"version": 1, "config": {"user_whitelist": [baseline]}, "feeds": []}, indent=4)
        written = subprocess.run(
            smoke_vm.ssh_argv("tee", MANIFEST_PATH),
            input=manifest_seed,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert written.returncode == 0, written.stderr

        original = helpers.config_get(smoke_vm, test_alerts.CFG_WHITELIST)
        original_entries = test_alerts._suppression_entries(smoke_vm, test_alerts.CFG_WHITELIST)
        original_derived = test_alerts._snapshot_guest_files(smoke_vm)
        suppression_entries = test_alerts._suppression_entries
        added_entries: set[str] = set()
        reloads_after_post: int | None = None

        def fail_after_post(vm: helpers.SmokeVM, cfg_path: str) -> set[str]:
            nonlocal reloads_after_post
            entries = suppression_entries(vm, cfg_path)
            if added := entries - original_entries:
                added_entries.update(added)
                normalised = {entry.removeprefix("www.") for entry in added}
                whitelist, manifest = _derived_whitelist_entries(vm)
                assert whitelist is not None and normalised <= whitelist, (
                    f"POST did not add {normalised!r} to {WHITELIST_PATH}"
                )
                assert manifest is not None and added <= manifest, (
                    f"POST did not add {added!r} to manifest user_whitelist"
                )
                reloads_after_post = helpers.count_log_marker(vm, helpers.PFB_LOG, "Reloading Unbound Resolver")
                raise RuntimeError("injected assertion failure after whitelist POST")
            return entries

        monkeypatch.setattr(test_alerts, "_suppression_entries", fail_after_post)
        with pytest.raises(RuntimeError, match="injected assertion failure after whitelist POST"):
            test_alerts.test_addwhitelistdom_writes_whitelist_and_entry_delete_removes_it(webui, smoke_vm)

        assert helpers.config_get(smoke_vm, test_alerts.CFG_WHITELIST) == original
        assert added_entries, "failure injection did not observe the whitelist POST mutation"
        assert test_alerts._snapshot_guest_files(smoke_vm) == original_derived
        assert reloads_after_post is not None
        assert helpers.count_log_marker(smoke_vm, helpers.PFB_LOG, "Reloading Unbound Resolver") > reloads_after_post, (
            "failed-test cleanup did not reload Unbound"
        )
    finally:
        try:
            test_alerts._restore_guest_files(smoke_vm, session_derived)
        finally:
            helpers.restore_pfb_config_baseline(smoke_vm, snapshot_path=UI_CONFIG_SNAPSHOT)
