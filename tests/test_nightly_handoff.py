"""Verified Nightly build-record and publisher-handoff contract."""

from __future__ import annotations

from hashlib import sha256
from typing import Any

import pytest

from scripts import nightly_provenance as np

SOURCE_SHA = "a" * 40
PORTS_SHA = "b" * 40
VERSION = f"20260814153045.{SOURCE_SHA[:7]}"


def _row(version: str = "2.8.0", *, role: str | None = None, ci: bool | None = None) -> dict[str, object]:
    row: dict[str, object] = {
        "pfsense_version": version,
        "channel": "CE",
        "freebsd_version": "15.0-RELEASE",
        "freebsd_major": "15",
        "php_version": "8.3",
        "py_flavor": "py311",
        "variant": "CE",
        "status": "GA",
        "extra_pkgs": [],
    }
    if role is not None:
        row["role"] = role
    if ci is not None:
        row["ci"] = ci
    return row


def _record(row: dict[str, object]) -> dict[str, object]:
    return np.make_build_record(
        pkg_version=VERSION,
        source_sha=SOURCE_SHA,
        ports_sha=PORTS_SHA,
        matrix_row=row,
        source_date_epoch=1_800_000_000,
    )


def _result(row: dict[str, object] | None = None) -> dict[str, object]:
    row = row or _row()
    return {
        "matrix_row": row,
        "record": _record(row),
        "artifact": {
            "abi": f"FreeBSD:{row['freebsd_major']}:*",
            "name": f"pfSense-pkg-pfBlockerNG-{VERSION}.pkg",
            "sha256": sha256(f"pkg{row['freebsd_major']}".encode()).hexdigest(),
        },
    }


def _call_handoff(
    results: list[dict[str, object]],
    *,
    build_rows: list[dict[str, object]] | None = None,
    route_rows: list[dict[str, object]] | None = None,
    pkg_version: str = VERSION,
) -> dict[str, Any]:
    return np.build_handoff(
        pkg_version=pkg_version,
        build_rows=build_rows or [_row()],
        route_rows=route_rows or [_row(ci=True)],
        results=results,
        source_sha=SOURCE_SHA,
        ports_sha=PORTS_SHA,
        tools_sha="e" * 40,
        matrix_sha="d" * 40,
        matrix_digest="c" * 64,
        run_id="123",
    )


def test_handoff_accepts_complete_build_and_route_rows() -> None:
    handoff = _call_handoff(
        [_result()],
        route_rows=[_row(ci=True), _row("2.7.0", role="route-only", ci=False)],
    )

    assert handoff["kind"] == "nightly-handoff"
    assert handoff["pkg_version"] == VERSION
    assert handoff["input_digest"] == np.combined_nightly_input_digest(SOURCE_SHA, PORTS_SHA, "c" * 64)
    assert handoff["tools_sha"] == "e" * 40
    builds = handoff["builds"]
    route_matrix = handoff["route_matrix"]
    assert isinstance(builds, list) and len(builds) == 1
    assert isinstance(route_matrix, list)
    assert route_matrix[0]["ci"] is True
    assert route_matrix[1]["role"] == "route-only"
    assert route_matrix[1]["ci"] is False
    assert "role" not in route_matrix[0]
    # issue #2454 step 3a: a BUILD result carries only matrix_row/record/artifact.
    assert set(builds[0]) == {"matrix_row", "record", "artifact"}


def test_handoff_rejects_missing_build_result() -> None:
    with pytest.raises(np.ProvenanceError, match="result count"):
        _call_handoff([])


def test_handoff_rejects_version_for_different_source() -> None:
    with pytest.raises(np.ProvenanceError, match="does not match"):
        _call_handoff([_result()], pkg_version=f"20260814153045.{'f' * 7}")


def test_handoff_rejects_result_with_dep_artifacts_key() -> None:
    """issue #2454 step 3a: dep_artifacts is no longer part of the BUILD result
    shape — a result carrying that key is now REJECTED, not merely tolerated
    empty."""
    result = _result()
    result["dep_artifacts"] = []
    with pytest.raises(np.ProvenanceError, match="unexpected fields"):
        _call_handoff([result])


def test_handoff_rejects_result_with_extra_unknown_field() -> None:
    result = _result()
    result["bogus"] = "nope"
    with pytest.raises(np.ProvenanceError, match="unexpected fields"):
        _call_handoff([result])
