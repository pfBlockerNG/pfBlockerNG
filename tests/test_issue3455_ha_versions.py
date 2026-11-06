"""Issue #3455: hermetic contract of the mixed-build HA smoke helpers (``tests/smoke/ha_versions.py``).

The live proof is ``tests/smoke/test_ha_policy_versions.py`` (two real guests, one on each package build). The rules its
assertions lean on are pure and run here: which build a marker count means, how the previous build's Sync page stores
the legacy checkbox, what the upgrade may move, how the XMLRPC client's and the receiver's syslog lines are read, and
what the previous receive hook merges. A live assertion built on a wrong rule would pass vacuously, so each rule is
pinned with a case that fails when it is dropped.
"""

from __future__ import annotations

import importlib
from types import ModuleType

import pytest


@pytest.fixture
def hv() -> ModuleType:
    return importlib.import_module("tests.smoke.ha_versions")


@pytest.fixture
def hp() -> ModuleType:
    return importlib.import_module("tests.smoke.ha_policy")


# --------------------------------------------------------------------------- #
# build_from_markers: the build is read from the installed code, never from a version string
# --------------------------------------------------------------------------- #


def test_no_marker_is_the_previous_build_and_both_the_branch_build(hv: ModuleType) -> None:
    assert hv.build_from_markers(0, 0) == "previous"
    assert hv.build_from_markers(2, 2) == "branch"


@pytest.mark.parametrize(("extra_hits", "inc_hits"), [(2, 0), (0, 2)])
def test_one_marker_without_the_other_is_a_half_installed_package_not_a_build(
    hv: ModuleType, extra_hits: int, inc_hits: int
) -> None:
    with pytest.raises(AssertionError, match="half-installed"):
        hv.build_from_markers(extra_hits, inc_hits)


# --------------------------------------------------------------------------- #
# legacy_sync_section / migration_delta: the previous page's storage and the only leaves an upgrade may move
# --------------------------------------------------------------------------- #


def test_legacy_sender_stores_the_toggle_and_no_scope_leaf(hv: ModuleType) -> None:
    section = hv.legacy_sync_section("manual", toggle="on", password="pw")

    assert "syncscope" not in section
    assert section["syncinterfaces"] == "on"
    assert section["varsynconchanges"] == "manual"
    assert section["row"][0]["varsyncpassword"] == "pw"


def test_unchecked_legacy_toggle_is_stored_empty_not_absent(hv: ModuleType) -> None:
    section = hv.legacy_sync_section("automatic", toggle="", password="pw")

    assert section["syncinterfaces"] == ""
    assert section["varsynconchanges"] == "auto"
    assert "row" not in section


def test_migration_delta_names_exactly_the_toggle_and_the_scope(hv: ModuleType) -> None:
    assert hv.migration_delta("on", "lists") == {
        "changed": {},
        "removed": {"pfblockerngsync/config/0/syncinterfaces": "on"},
        "added": {"pfblockerngsync/config/0/syncscope": "lists"},
    }


def test_a_migration_that_loses_or_rewrites_anything_else_is_not_the_migration_delta(
    hv: ModuleType, hp: ModuleType
) -> None:
    before = hv.flatten_sections(
        {"pfblockerngsync": {"config": [{"syncinterfaces": "on", "varsynconchanges": "manual"}]}}
    )
    right = hv.flatten_sections({"pfblockerngsync": {"config": [{"varsynconchanges": "manual", "syncscope": "lists"}]}})
    lost = hv.flatten_sections({"pfblockerngsync": {"config": [{"syncscope": "lists"}]}})
    rewritten = hv.flatten_sections(
        {"pfblockerngsync": {"config": [{"varsynconchanges": "auto", "syncscope": "lists"}]}}
    )

    wanted = hv.migration_delta("on", "lists")
    assert hp.diff_leaves(before, right) == wanted
    assert hp.diff_leaves(before, lost) != wanted
    assert hp.diff_leaves(before, rewritten) != wanted


# --------------------------------------------------------------------------- #
# flatten: empty containers are leaves, so an emptied section is not a deleted one
# --------------------------------------------------------------------------- #


def test_flatten_spells_nested_paths_and_keeps_empty_containers_as_leaves(hv: ModuleType) -> None:
    tree = {"config": [{"a": "1", "row": []}, {"a": ""}], "flat": "x"}

    assert hv.flatten(tree, "sec") == {
        "sec/config/0/a": "1",
        "sec/config/0/row": [],
        "sec/config/1/a": "",
        "sec/flat": "x",
    }


def test_flatten_sections_prefixes_each_leaf_with_its_section_name(hv: ModuleType) -> None:
    assert hv.flatten_sections({"s1": {"k": "v"}, "s2": []}) == {"s1/k": "v", "s2": []}


# --------------------------------------------------------------------------- #
# legacy_auto_merge: the previous receive hook is array_merge($old, $new) per section
# --------------------------------------------------------------------------- #


def test_legacy_merge_lets_incoming_keys_win_and_keeps_the_receivers_other_keys(hv: ModuleType) -> None:
    merged = hv.legacy_auto_merge({"keep": "b", "both": "b"}, {"both": "a", "new": "a"})

    assert merged == {"keep": "b", "both": "a", "new": "a"}


def test_legacy_merge_treats_an_absent_or_empty_side_as_nothing(hv: ModuleType) -> None:
    assert hv.legacy_auto_merge(None, {"k": "v"}) == {"k": "v"}
    assert hv.legacy_auto_merge({"k": "v"}, []) == {"k": "v"}
    assert hv.legacy_auto_merge("", {"k": "v"}) == {"k": "v"}


def test_legacy_merge_leaves_a_section_empty_on_both_sides_exactly_as_stored(hv: ModuleType) -> None:
    # The hook skips it, and the config reads an empty element back as '', so '' (not {}) is what B still holds.
    assert hv.legacy_auto_merge("", "") == ""
    assert hv.legacy_auto_merge("", []) == ""
    assert hv.legacy_auto_merge([], None) == []


# --------------------------------------------------------------------------- #
# package_xmlrpc: only the package's own sender lines count as "the package made a call"
# (the CE 2.9 shapes are pinned in tests/test_issue3730_ha_version_evidence.py)
# --------------------------------------------------------------------------- #

PKG = "/usr/local/www/pfblockerng/pfblockerng.php"
BEGIN = "Beginning XMLRPC sync data to https://172.30.254.2:443/xmlrpc.php."
OK = "XMLRPC reload data success with https://172.30.254.2:443/xmlrpc.php (pfsense.{method})."
STARTING = "NOTICE [pfBlockerNG] XMLRPC sync is starting."
SENT = "NOTICE [pfBlockerNG] XMLRPC sync to [ 172.30.254.2:443 ] completed successfully."


def _line(source: str, text: str) -> str:
    return f"Oct 14 17:47:05 pfSense php[80264]: {source}: {text}"


def _notice(text: str) -> str:
    return f"Oct 14 17:47:05 pfSense php[80264]: {text}"


def test_a_ce28_window_counts_each_target_once_not_once_per_core_line_the_package_also_wrote(hv: ModuleType) -> None:
    window = "\n".join(
        [
            _notice(STARTING),
            _line(PKG, BEGIN),
            _line(PKG, OK.format(method="merge_installedpackages_section")),
            _notice(SENT),
        ]
    )

    assert hv.package_xmlrpc(window) == [_notice(SENT)]


def test_core_ha_sync_lines_are_never_a_package_call(hv: ModuleType) -> None:
    window = "\n".join(
        [
            _line("/rc.filter_synchronize", BEGIN),
            _line("/rc.filter_synchronize", OK.format(method="host_firmware_version")),
            _line("/rc.filter_synchronize", OK.format(method="restore_config_section")),
        ]
    )

    assert hv.package_xmlrpc(window) == []


def test_a_second_package_sync_is_visible_to_the_exact_call_assertion(hv: ModuleType) -> None:
    window = "\n".join([_notice(STARTING), _notice(SENT), _notice(STARTING), _notice(SENT)])

    assert hv.package_xmlrpc(window) == [_notice(SENT), _notice(SENT)]


# --------------------------------------------------------------------------- #
# merged_sections / package_writes: the receiver's own record of what a call merged
# --------------------------------------------------------------------------- #


def _merged(keys: str) -> str:
    return (
        f"Oct 14 17:46:39 pfSense php-fpm[439]: /xmlrpc.php: Configuration Change: (system)@172.30.254.1: "
        f"Merged in config ({keys} sections) from XMLRPC client."
    )


def test_merged_sections_lists_the_names_and_reads_a_merge_of_nothing_as_empty(hv: ModuleType) -> None:
    window = "\n".join([_merged("pfblockernglistsv4, pfblockerngglobal"), _merged(""), _merged("aliases, filter")])

    assert hv.merged_sections(window) == [["pfblockernglistsv4", "pfblockerngglobal"], [], ["aliases", "filter"]]


def test_package_writes_keeps_pfblockerng_merges_and_empty_ones_but_not_core_ha_writes(hv: ModuleType) -> None:
    window = "\n".join([_merged("aliases, filter, nat, schedules"), _merged("pfblockernglistsv4"), _merged("")])

    assert hv.package_writes(window) == [["pfblockernglistsv4"], []]


def test_package_writes_sees_nothing_when_only_core_synced(hv: ModuleType) -> None:
    assert hv.package_writes(_merged("aliases, filter, nat, schedules")) == []
