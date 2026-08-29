"""Unit coverage for scripts/live_gate_matrix.py's pure matrix builder (issue #2389).

release-published.yml's prepare-live-gate job imports this module's
``compute_live_gate_matrix`` directly (from an inline ``python3 -`` step) -- these
tests exercise the SAME function, never a re-implementation, so a real regression in
the workflow's logic fails here first.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.live_gate_matrix import compute_live_gate_matrix

_ROOT = Path(__file__).resolve().parents[1]


def test_module_imports_outside_pytest_without_conftest_on_sys_path() -> None:
    """The workflow's prepare-live-gate step imports this module from a bare
    ``python3 -`` invocation -- only tests/conftest.py puts scripts/ on sys.path,
    so importing it that way must not depend on pfb_pkg (build-repo-portable.py's
    own import) being reachable some other way. Runs as a real subprocess, PYTHONPATH
    stripped, cwd at the repo root -- the same shape the workflow step runs under."""
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    result = subprocess.run(
        [sys.executable, "-c", "from scripts.live_gate_matrix import compute_live_gate_matrix"],
        cwd=str(_ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"stdout={result.stdout!r} stderr={result.stderr!r}"


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


def test_leg_missing_image_name_or_mac_raises_instead_of_silently_defaulting() -> None:
    """read-version-matrix.sh already resolves image_name/mac for every real CI leg
    (issue #2389) -- a leg missing either key is this function's own
    caller feeding it a malformed row, which must fail loudly, never silently
    install-test the wrong box under a fallback identity."""
    leg_no_image = {k: v for k, v in CE_LEG.items() if k != "image_name"}
    with pytest.raises(KeyError):
        compute_live_gate_matrix(["stable"], ["stable/ce-2.8"], [leg_no_image])
    leg_no_mac = {k: v for k, v in CE_LEG.items() if k != "mac"}
    with pytest.raises(KeyError):
        compute_live_gate_matrix(["stable"], ["stable/ce-2.8"], [leg_no_mac])
