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
    }
    return candidate, state, result


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
