"""Issue #3455: hermetic contract of the pure oracles behind ``tests/smoke/test_ha_policy_authority.py``.

The live proof runs on two real guests. Three of its assertions lean on a helper that computes the expected answer
(the apply window that excludes "now", the labels the copied-object detector gives pfB rules, and the attributes in
which a copied rule differs from the generated one), so each is pinned here with a case that fails when its rule is
dropped: a wrong oracle would let the live test pass vacuously or fail for the wrong reason.
"""

from __future__ import annotations

import importlib
import re
from types import ModuleType
from typing import Any

import pytest

# The Sync page's own window shape (pfblockerng_general.php:74): quarter-hour endpoints only.
_PAGE_WINDOW = re.compile(r"^((?:[01][0-9]|2[0-3]):(?:00|15|30|45))-((?:[01][0-9]|2[0-3]):(?:00|15|30|45))$")


@pytest.fixture(scope="module")
def ha() -> ModuleType:
    return importlib.import_module("tests.smoke.test_ha_policy_authority")


def _inside(window: str, minute_of_day: int) -> bool:
    """The package's own rule (``pfb_quiet_hours_in_window``) over a ``HH:MM-HH:MM`` window."""
    match = re.fullmatch(r"(\d\d):(\d\d)-(\d\d):(\d\d)", window)
    assert match, window
    start = int(match[1]) * 60 + int(match[2])
    end = int(match[3]) * 60 + int(match[4])
    return start <= minute_of_day < end if start < end else minute_of_day >= start or minute_of_day < end


# --------------------------------------------------------------------------- #
# quiet_window
# --------------------------------------------------------------------------- #


def test_the_window_never_contains_the_current_minute(ha: ModuleType) -> None:
    """Every minute of the day, midnight included: the deferral test must start with a window that excludes now."""
    for minute in range(1440):
        clock = f"{minute // 60:02d}:{minute % 60:02d}"

        window = ha.quiet_window(clock)

        assert not _inside(window, minute), f"at {clock} the window {window} contains the current time"


def test_the_window_is_a_shape_the_sync_page_accepts(ha: ModuleType) -> None:
    for minute in range(0, 1440, 7):
        window = ha.quiet_window(f"{minute // 60:02d}:{minute % 60:02d}")

        assert _PAGE_WINDOW.fullmatch(window), f"{window!r} is not a Sync-page window"


def test_the_window_starts_hours_ahead_so_a_slow_receive_cannot_land_inside_it(ha: ModuleType) -> None:
    """A receive that takes minutes to reach B must still find the window closed: at least two hours away."""
    for minute in range(1440):
        window = ha.quiet_window(f"{minute // 60:02d}:{minute % 60:02d}")
        start = int(window[:2]) * 60 + int(window[3:5])

        assert (start - minute) % 1440 >= 120, f"at {minute} the window {window} opens within two hours"


# --------------------------------------------------------------------------- #
# rule_labels / expected_rule_findings
# --------------------------------------------------------------------------- #


def _rule(descr: str, interface: str = "wan", **extra: Any) -> dict[str, Any]:
    return {
        "descr": descr,
        "interface": interface,
        "type": "block",
        "created": {"time": "1"},
        "updated": {"time": "2"},
        **extra,
    }


def test_labels_number_rules_that_share_a_descr_and_drop_the_time_stamps(ha: ModuleType) -> None:
    labels = ha.rule_labels([_rule("pfB_a auto rule"), _rule("pfB_b auto rule"), _rule("pfB_a auto rule", "lan")])

    assert list(labels) == ["pfB_a auto rule#0", "pfB_b auto rule#0", "pfB_a auto rule#1"]
    assert "created" not in labels["pfB_a auto rule#0"] and "updated" not in labels["pfB_a auto rule#0"]
    assert labels["pfB_a auto rule#1"]["interface"] == "lan"


def test_labels_replace_what_the_detector_replaces(ha: ModuleType) -> None:
    """The detector keeps ``[A-Za-z0-9_. ?-]`` and writes ``?`` for the rest (PFB_SYNC_COPIED_LABEL_CLASS)."""
    labels = ha.rule_labels([_rule("pfB_x<y>&z auto rule")])

    assert list(labels) == ["pfB_x?y??z auto rule#0"]


def test_findings_name_each_differing_attribute_and_only_those(ha: ModuleType) -> None:
    copied = [_rule("pfB_a auto rule", "lan", gateway="gw"), _rule("pfB_b auto rule", "lan")]
    generated = [_rule("pfB_a auto rule", "wan"), _rule("pfB_b auto rule", "lan")]

    findings = ha.expected_rule_findings(copied, generated)

    assert findings == {"pfB_a auto rule#0": ["gateway", "interface"]}


def test_identical_copies_have_no_findings(ha: ModuleType) -> None:
    rules = [_rule("pfB_a auto rule"), _rule("pfB_b auto rule", "lan")]

    assert ha.expected_rule_findings(rules, [dict(rule, created={"time": "9"}) for rule in rules]) == {}


def test_a_different_rule_set_is_a_broken_premise_not_an_empty_answer(ha: ModuleType) -> None:
    """If the copy and the node do not generate one rule set, "no findings" would be a vacuous expectation."""
    with pytest.raises(AssertionError, match="not the same rules"):
        ha.expected_rule_findings(
            [_rule("pfB_a auto rule"), _rule("pfB_only_here auto rule")], [_rule("pfB_a auto rule")]
        )
