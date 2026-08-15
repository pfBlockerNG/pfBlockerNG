"""Unit coverage for scripts/live_gate_matrix.py's pure matrix builder (issue #2389).

release-published.yml's prepare-live-gate job imports this module's
``compute_live_gate_matrix`` directly (from an inline ``python3 -`` step) -- these
tests exercise the SAME function, never a re-implementation, so a real regression in
the workflow's logic fails here first.
"""

from __future__ import annotations

from scripts.live_gate_matrix import compute_live_gate_matrix

CE_LEG = {
    "pfsense_version": "2.8.1",
    "variant": "CE",
    "freebsd_major": "15",
    "php_version": "8.3",
    "py_flavor": "py311",
    "image_name": "pfsense-ce",
    "mac": "BC:24:11:37:9C:AC",
    "extra_pkgs": [],
}
PLUS_LEG = {
    "pfsense_version": "26.03",
    "variant": "Plus",
    "freebsd_major": "16",
    "php_version": "8.5",
    "py_flavor": "py311",
    "image_name": "pfsense-plus",
    "mac": "02:00:00:00:00:01",
    "extra_pkgs": ["textproc/py-charset-normalizer"],
}


def test_one_destination_one_leg_matches() -> None:
    matrix, untestable, drifted = compute_live_gate_matrix(["stable"], ["stable/ce-2.8"], [CE_LEG])
    assert matrix == [
        {
            "channel": "stable",
            "varver": "ce-2.8",
            "pfsense_version": "2.8.1",
            "image_name": "pfsense-ce",
            "mac": "BC:24:11:37:9C:AC",
            "freebsd_major": "15",
            "php_version": "8.3",
            "py_flavor": "py311",
            "extra_pkgs": [],
        }
    ]
    assert untestable == []
    assert drifted == []


def test_multi_destination_fans_out_one_row_per_destination() -> None:
    """A final release touches stable+testing+edge for the same varver -- one live
    install test per destination, not one shared row."""
    matrix, untestable, drifted = compute_live_gate_matrix(
        ["stable", "testing", "edge"],
        ["stable/ce-2.8", "testing/ce-2.8", "edge/ce-2.8"],
        [CE_LEG],
    )
    assert [row["channel"] for row in matrix] == ["stable", "testing", "edge"]
    assert {row["varver"] for row in matrix} == {"ce-2.8"}
    assert untestable == []
    assert drifted == []


def test_multi_leg_only_touched_targets_produce_rows() -> None:
    """A leg whose varver was never touched (e.g. only CE was published) is excluded,
    not silently included with a stale/empty identity."""
    matrix, untestable, drifted = compute_live_gate_matrix(["edge"], ["edge/ce-2.8"], [CE_LEG, PLUS_LEG])
    assert len(matrix) == 1
    assert matrix[0]["varver"] == "ce-2.8"
    assert untestable == []
    assert drifted == []


def test_touched_target_with_no_matching_leg_is_untestable() -> None:
    """Something the publisher shipped for a varver no CI leg can install-test."""
    matrix, untestable, drifted = compute_live_gate_matrix(["edge"], ["edge/plus-26.07"], [CE_LEG])
    assert matrix == []
    assert untestable == ["edge/plus-26.07"]
    assert drifted == []


def test_touched_target_outside_destinations_is_drifted_not_untestable() -> None:
    """A touched channel resolve never classified is state drift, distinct from
    'no CI leg exists for this varver' -- must not double-count as untestable too."""
    matrix, untestable, drifted = compute_live_gate_matrix(["stable"], ["testing/ce-2.8"], [CE_LEG])
    assert matrix == []
    assert untestable == []
    assert drifted == ["testing/ce-2.8"]


def test_empty_touched_produces_empty_matrix_and_no_problems() -> None:
    """A pure no-op publish (nothing touched) is a caller-level ('did we publish
    anything testable?') decision, not this function's to flag -- it just returns
    empty."""
    matrix, untestable, drifted = compute_live_gate_matrix(["stable"], [], [CE_LEG])
    assert matrix == []
    assert untestable == []
    assert drifted == []


def test_destination_with_no_touched_target_is_not_an_error() -> None:
    """destinations may legitimately contain a channel the publisher no-op'd for this
    run -- only a TOUCHED target outside destinations is drift."""
    matrix, untestable, drifted = compute_live_gate_matrix(["stable", "testing"], ["stable/ce-2.8"], [CE_LEG])
    assert [row["channel"] for row in matrix] == ["stable"]
    assert untestable == []
    assert drifted == []
