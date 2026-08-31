"""Unit coverage for scripts/live_gate_matrix.py's pure matrix builder (issue #2389).

release-published.yml's prepare-live-gate job imports this module's
``compute_live_gate_matrix`` directly (from an inline ``python3 -`` step) -- these
tests exercise the SAME function, never a re-implementation, so a real regression in
the workflow's logic fails here first.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from scripts.live_gate_matrix import compute_live_gate_matrix
from tests._workflow_steps import extract_between

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

# Plus 25.11 as the live ci-metadata matrix actually carries it (issue #2926): a
# served, build-role varver with ci:false -- no licensed VM image exists, so it has
# NO leg in ci_matrix and never will. Route rows are the ONLY place that state is
# visible to the live gate.
PLUS_2511_ROUTE = {
    "pfsense_version": "25.11",
    "variant": "Plus",
    "freebsd_major": "16",
    "php_version": "8.4",
    "py_flavor": "py311",
    "ci": False,
}
PLUS_2511_ROUTE_CI_TRUE = {**PLUS_2511_ROUTE, "ci": True}
PLUS_2511_ROUTE_NO_CI = {key: value for key, value in PLUS_2511_ROUTE.items() if key != "ci"}
CE_ROUTE = {
    "pfsense_version": "2.8.1",
    "variant": "CE",
    "freebsd_major": "15",
    "php_version": "8.3",
    "py_flavor": "py311",
    "ci": True,
}


def test_one_destination_one_leg_matches() -> None:
    matrix, untestable, drifted, skipped = compute_live_gate_matrix(["stable"], ["stable/ce-2.8"], [CE_LEG])
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
    assert skipped == []


def test_multi_destination_fans_out_one_row_per_destination() -> None:
    """A final release touches stable+testing+edge for the same varver -- one live
    install test per destination, not one shared row."""
    matrix, untestable, drifted, skipped = compute_live_gate_matrix(
        ["stable", "testing", "edge"],
        ["stable/ce-2.8", "testing/ce-2.8", "edge/ce-2.8"],
        [CE_LEG],
    )
    assert [row["channel"] for row in matrix] == ["stable", "testing", "edge"]
    assert {row["varver"] for row in matrix} == {"ce-2.8"}
    assert untestable == []
    assert drifted == []
    assert skipped == []


def test_multi_leg_only_touched_targets_produce_rows() -> None:
    """A leg whose varver was never touched (e.g. only CE was published) is excluded,
    not silently included with a stale/empty identity."""
    matrix, untestable, drifted, skipped = compute_live_gate_matrix(["edge"], ["edge/ce-2.8"], [CE_LEG, PLUS_LEG])
    assert len(matrix) == 1
    assert matrix[0]["varver"] == "ce-2.8"
    assert untestable == []
    assert drifted == []
    assert skipped == []


def test_touched_target_with_no_matching_leg_is_untestable() -> None:
    """Something the publisher shipped for a varver no CI leg can install-test."""
    matrix, untestable, drifted, skipped = compute_live_gate_matrix(["edge"], ["edge/plus-26.07"], [CE_LEG])
    assert matrix == []
    assert untestable == ["edge/plus-26.07"]
    assert drifted == []
    assert skipped == []


def test_touched_target_outside_destinations_is_drifted_not_untestable() -> None:
    """A touched channel resolve never classified is state drift, distinct from
    'no CI leg exists for this varver' -- must not double-count as untestable too."""
    matrix, untestable, drifted, skipped = compute_live_gate_matrix(["stable"], ["testing/ce-2.8"], [CE_LEG])
    assert matrix == []
    assert untestable == []
    assert drifted == ["testing/ce-2.8"]
    assert skipped == []


def test_empty_touched_produces_empty_matrix_and_no_problems() -> None:
    """A pure no-op publish (nothing touched) is a caller-level ('did we publish
    anything testable?') decision, not this function's to flag -- it just returns
    empty."""
    matrix, untestable, drifted, skipped = compute_live_gate_matrix(["stable"], [], [CE_LEG])
    assert matrix == []
    assert untestable == []
    assert drifted == []
    assert skipped == []


def test_destination_with_no_touched_target_is_not_an_error() -> None:
    """destinations may legitimately contain a channel the publisher no-op'd for this
    run -- only a TOUCHED target outside destinations is drift."""
    matrix, untestable, drifted, skipped = compute_live_gate_matrix(["stable", "testing"], ["stable/ce-2.8"], [CE_LEG])
    assert [row["channel"] for row in matrix] == ["stable"]
    assert untestable == []
    assert drifted == []
    assert skipped == []


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


def test_ci_false_route_row_is_skipped_with_a_warning_not_a_failed_gate() -> None:
    """Plus 25.11 is ci:false on the live matrix -- deliberately no licensed VM image
    (issue #2926), so no CI leg can ever produce it. A stable publish touching that
    varver must classify it as SKIPPED, never as untestable: untestable raises and
    would hard-fail every tagged ingestion that ships plus-25.11."""
    matrix, untestable, drifted, skipped = compute_live_gate_matrix(
        ["stable"], ["stable/plus-25.11"], [CE_LEG], [PLUS_2511_ROUTE]
    )
    assert matrix == []
    assert untestable == []
    assert drifted == []
    assert skipped == ["stable/plus-25.11"]


def test_route_row_with_ci_true_and_no_leg_stays_untestable() -> None:
    """A varver the matrix declares smoke-testable that nevertheless produced no CI
    leg is real disagreement between the two matrices -- fail closed, never a silent
    skip that drops live coverage."""
    matrix, untestable, drifted, skipped = compute_live_gate_matrix(
        ["stable"], ["stable/plus-25.11"], [CE_LEG], [PLUS_2511_ROUTE_CI_TRUE]
    )
    assert matrix == []
    assert untestable == ["stable/plus-25.11"]
    assert drifted == []
    assert skipped == []


def test_route_row_omitting_ci_stays_untestable() -> None:
    """Only an EXPLICIT ``ci: false`` buys tolerance. An absent ``ci`` key is the
    matrix's build-role default (truthy), not a declaration that the varver has no
    smoke image -- so a missing leg is still drift."""
    matrix, untestable, drifted, skipped = compute_live_gate_matrix(
        ["stable"], ["stable/plus-25.11"], [CE_LEG], [PLUS_2511_ROUTE_NO_CI]
    )
    assert matrix == []
    assert untestable == ["stable/plus-25.11"]
    assert drifted == []
    assert skipped == []


def test_route_rows_omitted_keeps_todays_fail_closed_classification() -> None:
    """The route argument is optional: a caller that supplies none gets byte-identical
    classification to before this parameter existed (nothing is ever skipped without
    positive ci:false evidence)."""
    matrix, untestable, drifted, skipped = compute_live_gate_matrix(["stable"], ["stable/plus-25.11"], [CE_LEG])
    assert matrix == []
    assert untestable == ["stable/plus-25.11"]
    assert drifted == []
    assert skipped == []


def test_skipped_target_coexists_with_the_legs_that_do_have_images() -> None:
    """The normal stable publish: several varvers touched, one of them ci:false. The
    testable ones still fan out -- tolerance must not swallow the whole matrix."""
    matrix, untestable, drifted, skipped = compute_live_gate_matrix(
        ["stable"],
        ["stable/ce-2.8", "stable/plus-25.11"],
        [CE_LEG],
        [CE_ROUTE, PLUS_2511_ROUTE],
    )
    assert [row["varver"] for row in matrix] == ["ce-2.8"]
    assert untestable == []
    assert drifted == []
    assert skipped == ["stable/plus-25.11"]


def test_skipped_entries_are_sorted_regardless_of_touched_order() -> None:
    """The skipped list lands in a warning annotation and a step output -- a stable
    order keeps the same publish from rendering two different audit strings."""
    matrix, untestable, drifted, skipped = compute_live_gate_matrix(
        ["stable", "testing"],
        ["testing/plus-25.11", "stable/plus-25.11"],
        [CE_LEG],
        [PLUS_2511_ROUTE],
    )
    assert skipped == ["stable/plus-25.11", "testing/plus-25.11"]
    assert matrix == []
    assert untestable == []
    assert drifted == []


def test_ci_false_route_row_does_not_rescue_a_drifted_channel() -> None:
    """Tolerance is about a missing smoke IMAGE, never about a channel resolve never
    classified: that stays drift and still fails the gate closed."""
    matrix, untestable, drifted, skipped = compute_live_gate_matrix(
        ["stable"], ["testing/plus-25.11"], [CE_LEG], [PLUS_2511_ROUTE]
    )
    assert matrix == []
    assert untestable == []
    assert drifted == ["testing/plus-25.11"]
    assert skipped == []


def test_ci_matrix_stays_the_only_source_of_legs_even_against_a_stale_ci_false_row() -> None:
    """``ci_matrix`` decides what gets install-tested; route rows only classify
    tolerance. A stale ci:false route row for a varver the CI matrix DID produce must
    not delete that leg -- that would silently drop live coverage instead of adding
    tolerance."""
    stale = {**CE_ROUTE, "ci": False}
    matrix, untestable, drifted, skipped = compute_live_gate_matrix(["stable"], ["stable/ce-2.8"], [CE_LEG], [stale])
    assert [row["varver"] for row in matrix] == ["ce-2.8"]
    assert untestable == []
    assert drifted == []
    assert skipped == []


def test_prepare_live_gate_step_feeds_route_rows_and_warns_instead_of_failing(tmp_path: Path) -> None:
    """pkg-tagged-ingest.yml's prepare-live-gate step is the ONLY caller of this
    function (release-published.yml reaches it through that reusable workflow), so the
    tolerance is worthless unless the step actually reads the ROUTE matrix, unpacks the
    skipped list, and turns it into a warning. Runs the step's own inline python as a
    subprocess -- the real bytes the workflow executes, never a paraphrase."""
    workflow = yaml.safe_load((_ROOT / ".github/workflows/pkg-tagged-ingest.yml").read_text(encoding="utf-8"))
    step = next(item for item in workflow["jobs"]["prepare-live-gate"]["steps"] if item.get("id") == "build")
    run = step["run"]
    assert "read-version-matrix.sh --print-route" in run, run
    assert "ROUTE_ROWS" in run, run

    script = extract_between(run, "python3 - <<'PY'\n", "\nPY\n")
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    env["DESTINATIONS"] = '["stable"]'
    env["TOUCHED"] = '["stable/ce-2.8", "stable/plus-25.11"]'
    env["CI_MATRIX"] = json.dumps([CE_LEG])
    env["ROUTE_ROWS"] = json.dumps([CE_ROUTE, PLUS_2511_ROUTE])
    github_output = tmp_path / "github_output"
    github_output.write_text("", encoding="utf-8")
    env["GITHUB_OUTPUT"] = str(github_output)
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=str(_ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    emitted = github_output.read_text(encoding="utf-8")
    assert result.returncode == 0, f"stdout={result.stdout!r} stderr={result.stderr!r}"
    assert "::warning::live gate skipped (ci:false, no smoke image): stable/plus-25.11" in result.stdout, result.stdout
    assert 'matrix=[{"channel":"stable","varver":"ce-2.8"' in emitted, emitted
    assert 'skipped=["stable/plus-25.11"]' in emitted, emitted
