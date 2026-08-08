"""Durable Nightly allocation and completion contract."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import date
from hashlib import sha256
from pathlib import Path
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


def test_completion_rejects_digest_not_verified_by_handoff() -> None:
    first = _candidate(np.empty_state())

    with pytest.raises(np.ProvenanceError, match="completion input digest"):
        np.complete(
            np.empty_state(),
            first,
            [_artifact(first.allocation)],
            run_id="100",
            expected_input_digest="f" * 64,
        )


def test_ports_only_identity_is_part_of_digest() -> None:
    first = _candidate(np.empty_state())
    changed = _candidate(np.empty_state(), ports_sha=PORTS_B)

    assert first.allocation.input_digest != changed.allocation.input_digest


def test_duplicate_json_keys_fail_closed(tmp_path: Path) -> None:
    state_path = tmp_path / "state.json"
    state_path.write_text('{"schema": 1, "schema": 1}', encoding="utf-8")

    with pytest.raises(np.ProvenanceError, match="duplicate JSON key"):
        np._read_json(state_path)


@pytest.mark.parametrize("value", [" 20260804", "+20260804", "2026080", "２０２６０８０４"])
def test_build_date_requires_eight_ascii_digits(value: str) -> None:
    with pytest.raises(np.ProvenanceError, match="build date"):
        np._parse_date(value)


def test_complete_rejects_malformed_artifacts_json(tmp_path: Path) -> None:
    first = _candidate(np.empty_state())
    state = np.complete(np.empty_state(), first, [_artifact(first.allocation)], run_id="100")
    retry = _candidate(state)
    state_path = tmp_path / "state.json"
    candidate_path = tmp_path / "candidate.json"
    artifacts_path = tmp_path / "artifacts.json"
    output_path = tmp_path / "output.json"
    state_path.write_text(json.dumps(state), encoding="utf-8")
    candidate_path.write_text(
        json.dumps({"allocation": asdict(retry.allocation), "generation": retry.generation}),
        encoding="utf-8",
    )
    artifacts_path.write_text("{}", encoding="utf-8")

    assert (
        np.main(
            [
                "complete",
                "--state",
                str(state_path),
                "--candidate",
                str(candidate_path),
                "--artifacts",
                str(artifacts_path),
                "--run-id",
                "100",
                "--output",
                str(output_path),
            ]
        )
        == 1
    )


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


# --- dep_artifacts (issue #2146 S1) -----------------------------------------
# One BUILD leg's dependency .pkgs (issue #1806 extra_pkgs, Nightly-side): a
# leg may ship zero or more, all sharing the leg's OWN wildcard ABI. Unlike
# canonical `artifact` (`_validate_artifacts`, unique ABI across the whole
# handoff), uniqueness here is per (abi, name) WITHIN one leg only.


def _dep(
    *,
    abi: str = "FreeBSD:15:*",
    name: str = "py311-charset-normalizer-3.4.0.pkg",
    sha: str = sha256(b"dep").hexdigest(),
) -> dict[str, str]:
    return {"abi": abi, "name": name, "sha256": sha}


def test_validate_dep_artifacts_accepts_empty_list() -> None:
    assert np._validate_dep_artifacts([], leg_abi="FreeBSD:15:*", canonical_name="canonical.pkg") == []


def test_validate_dep_artifacts_sorts_by_name() -> None:
    deps = [_dep(name="b.pkg"), _dep(name="a.pkg")]
    result = np._validate_dep_artifacts(deps, leg_abi="FreeBSD:15:*", canonical_name="canonical.pkg")
    assert [item["name"] for item in result] == ["a.pkg", "b.pkg"]


@pytest.mark.parametrize("abi", ["FreeBSD:16:*", "FreeBSD:15:amd64"])
def test_validate_dep_artifacts_rejects_abi_not_equal_to_leg(abi: str) -> None:
    with pytest.raises(np.ProvenanceError, match="abi"):
        np._validate_dep_artifacts([_dep(abi=abi)], leg_abi="FreeBSD:15:*", canonical_name="canonical.pkg")


def test_validate_dep_artifacts_rejects_duplicate_name_within_leg() -> None:
    deps = [_dep(), _dep()]
    with pytest.raises(np.ProvenanceError, match="unique"):
        np._validate_dep_artifacts(deps, leg_abi="FreeBSD:15:*", canonical_name="canonical.pkg")


def test_validate_dep_artifacts_rejects_name_equal_to_canonical() -> None:
    with pytest.raises(np.ProvenanceError, match="canonical"):
        np._validate_dep_artifacts([_dep(name="canonical.pkg")], leg_abi="FreeBSD:15:*", canonical_name="canonical.pkg")


@pytest.mark.parametrize("name", ["../evil.pkg", "a/b.pkg", "a\\b.pkg", "evil\n.pkg", "no-suffix", ""])
def test_validate_dep_artifacts_rejects_hostile_names(name: str) -> None:
    with pytest.raises(np.ProvenanceError, match="name"):
        np._validate_dep_artifacts([_dep(name=name)], leg_abi="FreeBSD:15:*", canonical_name="canonical.pkg")


@pytest.mark.parametrize("sha", [sha256(b"dep").hexdigest().upper(), sha256(b"dep").hexdigest()[:-1], "z" * 64])
def test_validate_dep_artifacts_rejects_malformed_sha256(sha: str) -> None:
    with pytest.raises(np.ProvenanceError, match="sha256"):
        np._validate_dep_artifacts([_dep(sha=sha)], leg_abi="FreeBSD:15:*", canonical_name="canonical.pkg")


def test_validate_dep_artifacts_rejects_non_list() -> None:
    with pytest.raises(np.ProvenanceError, match="list"):
        np._validate_dep_artifacts(
            {"abi": "FreeBSD:15:*", "name": "x.pkg", "sha256": sha256(b"x").hexdigest()},
            leg_abi="FreeBSD:15:*",
            canonical_name="canonical.pkg",
        )


def test_complete_never_receives_dep_artifacts_only_canonical() -> None:
    """R12: durable state is fed ONLY canonical per-leg artifacts (nightly.yml's
    ``jq '[.builds[].artifact]'`` step) -- dep_artifacts never reaches
    np.complete or persisted state, regardless of how many dep .pkgs a leg
    built."""
    first = _candidate(np.empty_state())
    canonical = _artifact(first.allocation)
    state = np.complete(np.empty_state(), first, [canonical], run_id="100")

    records = state["records"]
    assert isinstance(records, list) and len(records) == 1
    artifacts = records[0]["artifacts"]
    assert artifacts == [canonical]
    assert all(set(item) == {"abi", "name", "sha256"} for item in artifacts)
