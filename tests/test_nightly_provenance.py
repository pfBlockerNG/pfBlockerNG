"""Durable Nightly allocation and completion contract."""

from __future__ import annotations

from datetime import date
from hashlib import sha256
from typing import Any

import pytest

from scripts import nightly_provenance as np

SOURCE_A = "a" * 40
SOURCE_B = "b" * 40
PORTS_A = "c" * 40
PORTS_B = "d" * 40
MATRIX_A = "e" * 64
MATRIX_B = "f" * 64


def _artifact(allocation: Any, abi: str = "FreeBSD:15:*", payload: bytes = b"pkg") -> dict[str, str]:
    return {
        "abi": abi,
        "name": f"pfSense-pkg-pfBlockerNG-{allocation.pkg_version}.pkg",
        "sha256": sha256(payload).hexdigest(),
    }


def _candidate(
    state: dict[str, object],
    *,
    build_date: date = date(2026, 8, 4),
    source_sha: str = SOURCE_A,
    ports_sha: str = PORTS_A,
    matrix_digest: str = MATRIX_A,
) -> Any:
    return np.allocate_candidate(
        state,
        build_date=build_date,
        source_sha=source_sha,
        ports_sha=ports_sha,
        matrix_digest=matrix_digest,
    )


def test_empty_state_allocates_first_changed_input() -> None:
    candidate = _candidate(np.empty_state())

    assert candidate.allocation.pkg_version == "20260804"
    assert candidate.allocation.outcome == "build"
    assert candidate.generation == 0


def test_unchanged_input_is_noop_even_after_skipped_calendar_days() -> None:
    first = _candidate(np.empty_state())
    state = np.complete(
        np.empty_state(),
        first,
        [_artifact(first.allocation)],
        run_id="100",
    )

    retry = _candidate(state, build_date=date(2026, 8, 7))

    assert retry.allocation.outcome == "unchanged"
    assert retry.allocation.pkg_version == "20260804"
    assert retry.generation == 1


def test_changed_inputs_allocate_same_day_revisions_and_next_day_reset() -> None:
    first = _candidate(np.empty_state())
    state_one = np.complete(np.empty_state(), first, [_artifact(first.allocation)], run_id="100")
    second = _candidate(state_one, source_sha=SOURCE_B)
    state_two = np.complete(state_one, second, [_artifact(second.allocation)], run_id="101")
    third = _candidate(state_two, ports_sha=PORTS_B, matrix_digest=MATRIX_B)
    state_three = np.complete(state_two, third, [_artifact(third.allocation)], run_id="102")
    next_day = _candidate(
        state_three,
        build_date=date(2026, 8, 5),
        source_sha=SOURCE_B,
        ports_sha=PORTS_B,
        matrix_digest=MATRIX_B,
    )

    assert second.allocation.pkg_version == "20260804_1"
    assert third.allocation.pkg_version == "20260804_2"
    assert next_day.allocation.pkg_version == "20260805"


def test_retry_is_idempotent_and_does_not_append_duplicate_state() -> None:
    first = _candidate(np.empty_state())
    state = np.complete(np.empty_state(), first, [_artifact(first.allocation)], run_id="100")
    retry = _candidate(state)
    replay = np.complete(state, retry, [_artifact(retry.allocation)], run_id="100")

    assert replay == state


def test_stale_completion_cannot_replace_newer_state() -> None:
    first = _candidate(np.empty_state())
    state_one = np.complete(np.empty_state(), first, [_artifact(first.allocation)], run_id="100")
    stale = _candidate(state_one, source_sha=SOURCE_B)
    newer = _candidate(state_one, ports_sha=PORTS_B)
    state_two = np.complete(state_one, newer, [_artifact(newer.allocation)], run_id="102")

    with pytest.raises(np.ProvenanceError, match="stale"):
        np.complete(state_two, stale, [_artifact(stale.allocation)], run_id="101")


def test_same_version_with_different_input_or_bytes_fails_closed() -> None:
    first = _candidate(np.empty_state())
    state = np.complete(np.empty_state(), first, [_artifact(first.allocation)], run_id="100")

    forged = np.Candidate(
        allocation=np.replace_allocation(first.allocation, source_sha=SOURCE_B),
        generation=state["generation"],  # type: ignore[arg-type]
    )
    with pytest.raises(np.ProvenanceError, match="collision"):
        np.complete(state, forged, [_artifact(forged.allocation)], run_id="101")

    different_bytes = _candidate(np.empty_state())
    with pytest.raises(np.ProvenanceError, match="artifact"):
        np.complete(state, different_bytes, [_artifact(different_bytes.allocation, payload=b"other")], run_id="100")


def test_ports_only_identity_is_part_of_digest() -> None:
    first = _candidate(np.empty_state())
    changed = _candidate(np.empty_state(), ports_sha=PORTS_B)

    assert first.allocation.input_digest != changed.allocation.input_digest


@pytest.mark.parametrize(
    "state",
    [
        {"schema": 2, "generation": 0, "records": []},
        {"schema": 1, "generation": -1, "records": []},
        {"schema": 1, "generation": 0, "records": [{}]},
    ],
)
def test_malformed_durable_state_fails_closed(state: dict[str, object]) -> None:
    with pytest.raises((TypeError, ValueError, np.ProvenanceError)):
        np.validate_state(state)
