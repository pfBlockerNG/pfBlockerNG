"""Verified Nightly build-record and publisher-handoff contract."""

from __future__ import annotations

from datetime import date
from hashlib import sha256

import pytest

from scripts import nightly_provenance as np


def _row(
    version: str = "2.8.0",
    *,
    role: str | None = None,
    ci: bool | None = None,
) -> dict[str, object]:
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


def _plan() -> tuple[np.Candidate, dict[str, object], dict[str, object]]:
    state = np.empty_state()
    candidate = np.allocate_candidate(
        state,
        build_date=date(2026, 8, 4),
        source_sha="a" * 40,
        ports_sha="b" * 40,
        matrix_digest="c" * 64,
    )
    record = np.make_build_record(
        allocation=candidate.allocation,
        matrix_row=_row(),
        source_date_epoch=1_800_000_000,
    )
    result = {
        "matrix_row": _row(),
        "record": record,
        "artifact": {
            "abi": "FreeBSD:15:*",
            "name": f"pfSense-pkg-pfBlockerNG-{candidate.allocation.pkg_version}.pkg",
            "sha256": sha256(b"pkg").hexdigest(),
        },
        "dep_artifacts": [],
    }
    return candidate, state, result


def _call_handoff(result: dict[str, object], *, candidate: np.Candidate, state: dict[str, object]) -> dict[str, object]:
    return np.build_handoff(
        candidate=candidate,
        state=state,
        build_rows=[_row()],
        route_rows=[_row(ci=True)],
        results=[result],
        source_sha="a" * 40,
        ports_sha="b" * 40,
        tools_sha="e" * 40,
        matrix_sha="d" * 40,
        matrix_digest="c" * 64,
        run_id="123",
    )


def test_handoff_accepts_complete_build_and_route_rows() -> None:
    candidate, state, result = _plan()

    handoff = np.build_handoff(
        candidate=candidate,
        state=state,
        build_rows=[_row()],
        route_rows=[_row(ci=True), _row("2.7.0", role="route-only", ci=False)],
        results=[result],
        source_sha="a" * 40,
        ports_sha="b" * 40,
        tools_sha="e" * 40,
        matrix_sha="d" * 40,
        matrix_digest="c" * 64,
        run_id="123",
    )

    assert handoff["kind"] == "nightly-handoff"
    assert handoff["tools_sha"] == "e" * 40
    assert handoff["matrix_sha"] == "d" * 40
    builds = handoff["builds"]
    route_matrix = handoff["route_matrix"]
    assert isinstance(builds, list) and len(builds) == 1
    assert isinstance(route_matrix, list)
    assert isinstance(route_matrix[0], dict) and route_matrix[0]["ci"] is True
    assert isinstance(route_matrix[1], dict) and route_matrix[1]["role"] == "route-only"
    assert route_matrix[1]["ci"] is False
    assert "role" not in route_matrix[0]
    # R2: a leg with no extra_pkgs (Plus shape) carries an empty dep_artifacts.
    assert builds[0]["dep_artifacts"] == []


def test_handoff_rejects_missing_build_result() -> None:
    candidate, state, _ = _plan()

    with pytest.raises(np.ProvenanceError, match="result count"):
        np.build_handoff(
            candidate=candidate,
            state=state,
            build_rows=[_row()],
            route_rows=[_row()],
            results=[],
            source_sha="a" * 40,
            ports_sha="b" * 40,
            tools_sha="e" * 40,
            matrix_sha="d" * 40,
            matrix_digest="c" * 64,
            run_id="123",
        )


def test_handoff_rejects_forged_input_digest() -> None:
    candidate, state, result = _plan()
    forged = np.Candidate(
        allocation=np.replace_allocation(candidate.allocation, input_digest="f" * 64),
        generation=candidate.generation,
    )

    with pytest.raises(np.ProvenanceError, match="input digest"):
        np.build_handoff(
            candidate=forged,
            state=state,
            build_rows=[_row()],
            route_rows=[_row(ci=True)],
            results=[result],
            source_sha="a" * 40,
            ports_sha="b" * 40,
            tools_sha="e" * 40,
            matrix_sha="d" * 40,
            matrix_digest="c" * 64,
            run_id="123",
        )


def test_handoff_carries_one_dep_artifact_sorted() -> None:
    """R1: a CE-major-15 leg's single extra_pkgs dep .pkg is accepted and
    carried through the handoff."""
    candidate, state, result = _plan()
    dep = {
        "abi": "FreeBSD:15:*",
        "name": "py311-charset-normalizer-3.4.0.pkg",
        "sha256": sha256(b"dep").hexdigest(),
    }
    result["dep_artifacts"] = [dep]

    handoff = _call_handoff(result, candidate=candidate, state=state)

    builds = handoff["builds"]
    assert isinstance(builds, list)
    assert builds[0]["dep_artifacts"] == [dep]


def test_handoff_rejects_result_missing_dep_artifacts_key() -> None:
    """R3: dep_artifacts is a required field on every BUILD result."""
    candidate, state, result = _plan()
    del result["dep_artifacts"]

    with pytest.raises(np.ProvenanceError, match="unexpected fields"):
        _call_handoff(result, candidate=candidate, state=state)


def test_handoff_rejects_result_with_extra_unknown_field() -> None:
    """R4: an unrecognized field on a BUILD result is still rejected."""
    candidate, state, result = _plan()
    result["bogus"] = "nope"

    with pytest.raises(np.ProvenanceError, match="unexpected fields"):
        _call_handoff(result, candidate=candidate, state=state)


def test_handoff_accepts_same_dep_name_across_different_legs() -> None:
    """R10: dep_artifacts uniqueness is per-leg, not global -- two legs on
    different FreeBSD majors may each carry a dep .pkg with the same
    filename."""
    state = np.empty_state()
    candidate = np.allocate_candidate(
        state,
        build_date=date(2026, 8, 4),
        source_sha="a" * 40,
        ports_sha="b" * 40,
        matrix_digest="c" * 64,
    )
    row15 = _row()
    row16 = dict(_row())
    row16["freebsd_major"] = "16"
    row16["freebsd_version"] = "16.0-RELEASE"
    record15 = np.make_build_record(allocation=candidate.allocation, matrix_row=row15, source_date_epoch=1_800_000_000)
    record16 = np.make_build_record(allocation=candidate.allocation, matrix_row=row16, source_date_epoch=1_800_000_000)
    dep_name = "py311-charset-normalizer-3.4.0.pkg"
    result15 = {
        "matrix_row": row15,
        "record": record15,
        "artifact": {
            "abi": "FreeBSD:15:*",
            "name": f"pfSense-pkg-pfBlockerNG-{candidate.allocation.pkg_version}.pkg",
            "sha256": sha256(b"pkg15").hexdigest(),
        },
        "dep_artifacts": [{"abi": "FreeBSD:15:*", "name": dep_name, "sha256": sha256(b"dep15").hexdigest()}],
    }
    result16 = {
        "matrix_row": row16,
        "record": record16,
        "artifact": {
            "abi": "FreeBSD:16:*",
            "name": f"pfSense-pkg-pfBlockerNG-{candidate.allocation.pkg_version}.pkg",
            "sha256": sha256(b"pkg16").hexdigest(),
        },
        "dep_artifacts": [{"abi": "FreeBSD:16:*", "name": dep_name, "sha256": sha256(b"dep16").hexdigest()}],
    }

    handoff = np.build_handoff(
        candidate=candidate,
        state=state,
        build_rows=[row15, row16],
        route_rows=[_row(ci=True)],
        results=[result15, result16],
        source_sha="a" * 40,
        ports_sha="b" * 40,
        tools_sha="e" * 40,
        matrix_sha="d" * 40,
        matrix_digest="c" * 64,
        run_id="123",
    )

    builds = handoff["builds"]
    assert isinstance(builds, list)
    names = {str(b["matrix_row"]["freebsd_major"]): b["dep_artifacts"][0]["name"] for b in builds}
    assert names["15"] == names["16"] == dep_name
