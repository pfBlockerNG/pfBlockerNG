"""Issue #3730: the mixed-build HA evidence reads what every CE release logs and what each build installs.

CE 2.9 writes core's ``Beginning XMLRPC sync data`` / ``XMLRPC reload data success`` through ``logger(LOG_INFO, ...)``,
which never reaches ``system.log``; only the package's own NOTICE lines do. The upgrade also adds the registry
defaults the previous build lacks and drops the keys it retired, and the legacy "all" scope carries one section more
than the previous build's payload did. Off-box: pure helpers, and the one PHP expression run against the real code.
"""

from __future__ import annotations

import importlib
import json
import subprocess
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

BOOTSTRAP = Path(__file__).resolve().parent / "php" / "bootstrap.php"
SYNCSCOPE = "pfblockerngsync/config/0/syncscope"
SYNCINTERFACES = "pfblockerngsync/config/0/syncinterfaces"
NEW_KEY = "pfblockerngipsettings/config/0/only_the_branch_knows"
RETIRED_KEY = "pfblockerngdnsblsettings/config/0/pfb_cache"


@pytest.fixture
def hv() -> ModuleType:
    return importlib.import_module("tests.smoke.ha_versions")


def _line(text: str) -> str:
    return f"Nov  6 15:05:29 pfSense php[35788]: {text}"


# A CE 2.9 window as the guest wrote it: the package's NOTICE lines, and nothing from core's XMLRPC client.
STARTING = _line("NOTICE [pfBlockerNG] XMLRPC sync is starting.")
COMPLETED = _line("NOTICE [pfBlockerNG] XMLRPC sync to [ 172.30.254.2:443 ] completed successfully.")
POLICY_SENT = _line("NOTICE [pfBlockerNG] XMLRPC policy sync to [ 172.30.254.2:443 ] sent, acceptance unconfirmed.")
FAILED = _line(
    "ERROR [pfBlockerNG] XMLRPC sync to [ 172.30.254.2:443 ] terminated due to the following error(s): "
    "| Password parameter missing. | "
)
NOISE = _line("NOTICE [pfBlockerNG] No changes to Firewall rules, skipping Filter Reload")


def test_a_ce29_window_without_core_xmlrpc_lines_still_shows_the_legacy_sync(hv: ModuleType) -> None:
    window = "\n".join([NOISE, STARTING, COMPLETED])

    assert hv.package_xmlrpc(window) == [COMPLETED]


def test_a_policy_scope_send_is_a_package_sync(hv: ModuleType) -> None:
    window = "\n".join([NOISE, STARTING, POLICY_SENT])

    assert hv.package_xmlrpc(window) == [POLICY_SENT]


def test_a_target_the_package_failed_to_sync_to_is_not_hidden(hv: ModuleType) -> None:
    assert hv.package_xmlrpc("\n".join([STARTING, FAILED])) == [FAILED]


def test_a_pass_that_only_announced_a_sync_made_no_call(hv: ModuleType) -> None:
    # Automatic mode: the package logs the start, then hands the send to pfSense HA sync.
    assert list(hv.package_xmlrpc("\n".join([NOISE, STARTING]))) == []


# --------------------------------------------------------------------------- #
# What an upgrade may move beyond the checkbox: the registries' difference
# --------------------------------------------------------------------------- #


def _delta(**moved: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {"changed": {}, "removed": {}, "added": {}, **moved}


PREVIOUS = {SYNCINTERFACES, RETIRED_KEY, "pfblockerngipsettings/config/0/kept"}
BRANCH = {SYNCSCOPE, NEW_KEY, "pfblockerngipsettings/config/0/kept"}


def test_registry_defaults_the_branch_adds_and_keys_it_retires_are_not_unexplained_moves(hv: ModuleType) -> None:
    moved = _delta(
        added={SYNCSCOPE: "all", NEW_KEY: ""},
        removed={SYNCINTERFACES: "", RETIRED_KEY: "x"},
    )

    assert hv.without_registry_moves(moved, PREVIOUS, BRANCH) == hv.migration_delta("", "all")


def test_a_leaf_outside_both_registries_stays_an_unexplained_move(hv: ModuleType) -> None:
    stray_add, stray_loss = "pfblockerngipsettings/config/0/stray", "pfblockerngipsettings/config/0/kept"
    moved = _delta(
        added={SYNCSCOPE: "all", stray_add: "1"},
        removed={SYNCINTERFACES: "", stray_loss: "x"},
    )

    left = hv.without_registry_moves(moved, PREVIOUS, BRANCH)

    assert left["added"] == {SYNCSCOPE: "all", stray_add: "1"} and left["removed"] == {
        SYNCINTERFACES: "",
        stray_loss: "x",
    }


def test_a_rewritten_value_is_never_explained_by_the_registries(hv: ModuleType) -> None:
    moved = _delta(changed={"pfblockerngipsettings/config/0/kept": ("a", "b")}, added={NEW_KEY: ""})

    assert hv.without_registry_moves(moved, PREVIOUS, BRANCH)["changed"] == moved["changed"]


def test_the_registry_paths_expression_spells_paths_the_way_stored_sections_are_flattened(hv: ModuleType) -> None:
    script = "[, $boot, $expr] = $argv; require $boot; echo json_encode(eval('return ' . $expr . ';'));"
    result = subprocess.run(
        ["php", "-r", script, "--", str(BOOTSTRAP), hv.REGISTRY_PATHS_EXPR],
        capture_output=True,
        check=True,
        text=True,
        encoding="utf-8",
    )

    paths = json.loads(result.stdout)

    assert SYNCSCOPE in paths, f"the sync scope leaf must be a registry path as flatten_sections spells it: {paths[:5]}"
    foreign = [path for path in paths if path.startswith("installedpackages/") or not path.startswith("pfblockerng")]
    assert foreign == [], f"every path starts at its stored section, never at installedpackages/: {foreign[:5]}"


# --------------------------------------------------------------------------- #
# The legacy payload is the branch's own, not the previous build's
# --------------------------------------------------------------------------- #


class _Guest:
    """Answers the one pfSsh read the helper makes and remembers what it asked."""

    def __init__(self) -> None:
        self.asked: list[str] = []


@pytest.mark.parametrize(("scope", "all_"), [("all", "TRUE"), ("lists", "FALSE")])
def test_the_legacy_payload_comes_from_the_branch_function_for_the_stored_scope(
    hv: ModuleType, monkeypatch: pytest.MonkeyPatch, scope: str, all_: str
) -> None:
    guest = _Guest()

    def php_json(_vm: Any, php: str, **_kw: Any) -> list[str]:
        guest.asked.append(php)
        return ["pfblockernglistsv4", "pfblockerngdnssettings"]

    monkeypatch.setattr(hv.hp, "php_json", php_json)

    names = hv.legacy_section_names(guest, scope)

    assert names == ["pfblockernglistsv4", "pfblockerngdnssettings"]
    (php,) = guest.asked
    assert f"pfb_sync_legacy_sections({all_})" in php, f"scope {scope!r} must ask for all={all_}: {php}"
