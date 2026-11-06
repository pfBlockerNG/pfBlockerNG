"""Issue #3730 (review): the contracts the mixed-build live assertions lean on, pinned so a dropped rule goes red.

``tests/test_issue3730_ha_version_evidence.py`` pins the CE 2.9-shaped log window and the happy paths. These cases pin
what must NOT be excused: the registry subtraction acts in one direction per key class, the branch's legacy payload may
only grow by what #3649 added, and a send is told apart as legacy or policy by the package's own wording.
"""

from __future__ import annotations

import importlib
from types import ModuleType
from typing import Any

import pytest

SYNCSCOPE = "pfblockerngsync/config/0/syncscope"
SYNCINTERFACES = "pfblockerngsync/config/0/syncinterfaces"
KEPT = "pfblockerngipsettings/config/0/in_both_registries"
ARRIVED = "pfblockerngipsettings/config/0/only_the_branch_knows"
RETIRED = "pfblockerngdnsblsettings/config/0/only_the_previous_knew"
PREVIOUS = {SYNCINTERFACES, KEPT, RETIRED}
BRANCH = {SYNCSCOPE, KEPT, ARRIVED}


@pytest.fixture
def hv() -> ModuleType:
    return importlib.import_module("tests.smoke.ha_versions")


def _moved(**moved: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {"changed": {}, "removed": {}, "added": {}, **moved}


@pytest.mark.parametrize(
    ("direction", "path", "why"),
    [
        ("added", KEPT, "a key both registries know is no arrival, so an upgrade that adds it has written something"),
        ("removed", KEPT, "a key both registries know is no retirement, so an upgrade that removes it lost something"),
        ("added", RETIRED, "a retired key that appears is not a retirement: the upgrade must never create it"),
        (
            "removed",
            ARRIVED,
            "an arrived key that disappears is not an arrival: it came with the upgrade or not at all",
        ),
    ],
    ids=["added-in-both", "removed-in-both", "retired-appears", "arrived-disappears"],
)
def test_a_registry_difference_excuses_each_key_class_only_in_its_own_direction(
    hv: ModuleType, direction: str, path: str, why: str
) -> None:
    moved = _moved(**{direction: {path: "x"}})

    left = hv.without_registry_moves(moved, PREVIOUS, BRANCH)

    assert left[direction] == {path: "x"}, f"{why}; left {left}"


@pytest.mark.parametrize(
    ("direction", "path"), [("added", ARRIVED), ("removed", RETIRED)], ids=["arrival", "retirement"]
)
def test_an_arrival_and_a_retirement_are_each_excused_in_their_own_direction(
    hv: ModuleType, direction: str, path: str
) -> None:
    left = hv.without_registry_moves(_moved(**{direction: {path: "x"}}), PREVIOUS, BRANCH)

    assert left == _moved(), f"the {direction} of {path} follows from the registries and must not be reported: {left}"


# --------------------------------------------------------------------------- #
# The branch build's legacy payload only grows by #3649's section
# --------------------------------------------------------------------------- #

LISTS = ["pfblockernglistsv4", "pfblockernglistsv6", "pfblockerngglobal"]
SETTINGS = ["pfblockerng", "pfblockerngipsettings", "pfblockerngdnsblsettings"]
DNS = "pfblockerngdnssettings"


@pytest.mark.parametrize(
    ("scope", "previous", "branch"),
    [("lists", LISTS, LISTS), ("all", [*SETTINGS, *LISTS], [*SETTINGS, *LISTS, DNS])],
    ids=["lists-unchanged", "all-grows-by-dns-settings"],
)
def test_the_expected_legacy_payloads_are_accepted(
    hv: ModuleType, scope: str, previous: list[str], branch: list[str]
) -> None:
    hv.assert_legacy_payload_growth(previous, branch, scope)


@pytest.mark.parametrize(
    ("scope", "previous", "branch", "complaint"),
    [
        ("lists", LISTS, LISTS[:-1], "dropped"),
        ("all", [*SETTINGS, *LISTS], [*SETTINGS, *LISTS[:-1], DNS], "dropped"),
        ("lists", LISTS, [*LISTS, DNS], "added"),
        ("all", [*SETTINGS, *LISTS], [*SETTINGS, *LISTS], "added"),
        ("all", [*SETTINGS, *LISTS], [*SETTINGS, *LISTS, DNS, "pfblockerngsurprise"], "added"),
    ],
    ids=["lists-drops", "all-drops", "lists-grows", "all-does-not-grow", "all-grows-by-more"],
)
def test_a_legacy_payload_that_drops_a_section_or_grows_otherwise_is_refused(
    hv: ModuleType, scope: str, previous: list[str], branch: list[str], complaint: str
) -> None:
    with pytest.raises(AssertionError, match=complaint):
        hv.assert_legacy_payload_growth(previous, branch, scope)


# --------------------------------------------------------------------------- #
# One send, told legacy from policy by the package's own wording
# --------------------------------------------------------------------------- #

PREFIX = "Nov  6 15:05:29 pfSense php[35788]: NOTICE [pfBlockerNG] XMLRPC "
LEGACY = f"{PREFIX}sync to [ 172.30.254.2:443 ] completed successfully."
POLICY = f"{PREFIX}policy sync to [ 172.30.254.2:443 ] sent, acceptance unconfirmed."


@pytest.mark.parametrize(("line", "policy"), [(LEGACY, False), (POLICY, True)], ids=["legacy", "policy"])
def test_one_send_in_the_expected_scope_wording_is_accepted(hv: ModuleType, line: str, policy: bool) -> None:
    hv.assert_one_send([line], policy=policy)


@pytest.mark.parametrize(
    ("line", "policy"), [(POLICY, False), (LEGACY, True)], ids=["policy-as-legacy", "legacy-as-policy"]
)
def test_a_send_in_the_other_scopes_wording_is_refused(hv: ModuleType, line: str, policy: bool) -> None:
    with pytest.raises(AssertionError, match="send, got"):
        hv.assert_one_send([line], policy=policy)


@pytest.mark.parametrize("calls", [[], [LEGACY, LEGACY]], ids=["none", "two"])
def test_no_send_and_two_sends_are_refused_whatever_the_scope(hv: ModuleType, calls: list[str]) -> None:
    for policy in (False, True):
        with pytest.raises(AssertionError, match="expected one XMLRPC sync"):
            hv.assert_one_send(calls, policy=policy)
