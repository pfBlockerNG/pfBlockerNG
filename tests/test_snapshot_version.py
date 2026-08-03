"""Snapshot identity and sequencing contracts for release_version.py."""

from __future__ import annotations

from dataclasses import fields, replace
from datetime import date, datetime

import pytest

from scripts.release_version import (
    PACKAGE,
    ReleaseInfo,
    SnapshotRecord,
    generate_snapshot,
    next_patch_target,
    validate_release_info,
)

TARGET = "4.0.0"
EDGE_LINE = "release/4.0"
SOURCE_A = "a" * 40
SOURCE_B = "b" * 64
DAY_ONE = date(2026, 8, 4)
DAY_TWO = date(2026, 8, 5)
DAY_ZERO = date(2026, 8, 3)


def _generate_edge(
    source_sha: str = SOURCE_A,
    build_date: date = DAY_ONE,
    existing: tuple[SnapshotRecord, ...] = (),
    release_line: str = EDGE_LINE,
) -> ReleaseInfo:
    return generate_snapshot(
        channel="edge",
        target_final=TARGET,
        release_line=release_line,
        source_sha=source_sha,
        build_date=build_date,
        existing=existing,
    )


def _generate_nightly(
    source_sha: str = SOURCE_A,
    build_date: date = DAY_ONE,
    existing: tuple[SnapshotRecord, ...] = (),
    release_line: str = "devel",
) -> ReleaseInfo:
    return generate_snapshot(
        channel="nightly",
        target_final=TARGET,
        release_line=release_line,
        source_sha=source_sha,
        build_date=build_date,
        existing=existing,
    )


def test_next_patch_target_accepts_only_bare_strict_core() -> None:
    assert next_patch_target("4.0.0") == "4.0.1"
    for invalid in ("v4.0.0", "4.0.0.alpha.1", "4.0", "4.00.0", "4.0.00", "", "1" * 129 + ".0.0"):
        with pytest.raises(ValueError):
            next_patch_target(invalid)


def test_snapshot_record_is_frozen() -> None:
    assert [field.name for field in fields(SnapshotRecord)] == ["source_sha", "result"]
    assert SnapshotRecord.__dataclass_params__.frozen  # type: ignore[attr-defined]


def test_edge_snapshot_has_exact_frozen_shape_and_pkg_identity() -> None:
    result = _generate_edge()
    assert result == ReleaseInfo(
        tag="v4.0.0.edge.20260804.1",
        version="4.0.0.edge.20260804.1",
        stage="edge",
        sequence="20260804.1",
        target_final=TARGET,
        release_line=EDGE_LINE,
        channel="edge",
        prerelease=True,
        final=False,
        notes_required=True,
        github_release="prerelease",
        pkg_version="4.0.0.snapshot.1.20260804.1",
        package=PACKAGE,
    )


def test_nightly_snapshot_has_distinct_nightly_and_pkg_versions() -> None:
    result = _generate_nightly(source_sha=SOURCE_B)
    assert result == ReleaseInfo(
        tag=None,
        version="4.0.0.nightly.20260804.1",
        stage="nightly",
        sequence="20260804.1",
        target_final=TARGET,
        release_line="devel",
        channel="nightly",
        prerelease=True,
        final=False,
        notes_required=False,
        github_release="none",
        pkg_version="4.0.0.snapshot.2.20260804.1",
        package=PACKAGE,
    )


def test_oversized_but_valid_target_is_rejected_before_edge_emission() -> None:
    major = "1" * 110
    with pytest.raises(ValueError):
        generate_snapshot(
            channel="edge",
            target_final=f"{major}.0.0",
            release_line=f"release/{major}.0",
            source_sha=SOURCE_A,
            build_date=DAY_ONE,
        )


@pytest.mark.parametrize("generator", [_generate_edge, _generate_nightly])
def test_snapshot_results_are_canonical_and_tampering_is_rejected(generator: object) -> None:
    result = generator()  # type: ignore[operator]
    validate_release_info(result)
    tampered = [
        replace(result, version=result.version + ".forged"),
        replace(result, target_final="4.0.1"),
        replace(result, release_line=result.release_line + "/forged"),
        replace(result, pkg_version=result.pkg_version + ".forged"),
        replace(result, sequence="20260804.2"),
    ]
    for forged in tampered:
        with pytest.raises(ValueError):
            validate_release_info(forged)


def test_same_source_is_idempotent_even_when_requested_later() -> None:
    first = _generate_edge()
    existing = (SnapshotRecord(SOURCE_A, first),)
    assert _generate_edge(build_date=DAY_TWO, existing=existing) == first
    assert existing == (SnapshotRecord(SOURCE_A, first),)


def test_same_source_requested_before_latest_date_is_stale() -> None:
    first = _generate_edge()
    with pytest.raises(ValueError, match="older"):
        _generate_edge(build_date=DAY_ZERO, existing=(SnapshotRecord(SOURCE_A, first),))


def test_different_source_same_day_increments_count_without_trigger_context() -> None:
    first = _generate_edge()
    second = _generate_edge(source_sha=SOURCE_B, existing=(SnapshotRecord(SOURCE_A, first),))
    assert second.sequence == "20260804.2"
    assert second.pkg_version == "4.0.0.snapshot.1.20260804.2"


def test_later_date_resets_sequence_to_one() -> None:
    first = _generate_edge()
    later = _generate_edge(source_sha=SOURCE_B, build_date=DAY_TWO, existing=(SnapshotRecord(SOURCE_A, first),))
    assert later.sequence == "20260805.1"


def test_same_day_count_ignores_higher_count_from_an_older_day() -> None:
    records: tuple[SnapshotRecord, ...] = ()
    for index in range(9):
        source = f"{index + 1:040x}"
        result = _generate_edge(source_sha=source, existing=records)
        records += (SnapshotRecord(source, result),)
    current = _generate_edge(source_sha=SOURCE_B, build_date=DAY_TWO, existing=records)
    next_current = _generate_edge(
        source_sha="c" * 40,
        build_date=DAY_TWO,
        existing=records + (SnapshotRecord(SOURCE_B, current),),
    )
    assert records[-1].result.sequence == "20260804.9"
    assert current.sequence == "20260805.1"
    assert next_current.sequence == "20260805.2"


def test_older_date_than_latest_relevant_snapshot_is_rejected() -> None:
    latest = _generate_edge(build_date=DAY_TWO)
    with pytest.raises(ValueError, match="older"):
        _generate_edge(source_sha=SOURCE_B, build_date=DAY_ONE, existing=(SnapshotRecord(SOURCE_A, latest),))


def test_edge_requires_exact_target_release_line_and_nightly_requires_devel() -> None:
    with pytest.raises(ValueError):
        _generate_edge(release_line="release/4.1")
    with pytest.raises(ValueError):
        _generate_nightly(release_line="release/4.0")
    assert _generate_edge().release_line == EDGE_LINE
    assert _generate_nightly().release_line == "devel"


@pytest.mark.parametrize("source_sha", ["", "A" * 40, "a" * 39, "a" * 41, "a" * 63, "a" * 65, "g" * 40])
def test_source_sha_must_be_lowercase_40_or_64_hex(source_sha: str) -> None:
    with pytest.raises(ValueError):
        _generate_edge(source_sha=source_sha)


@pytest.mark.parametrize(
    "target_final,build_date,channel,release_line",
    [
        ("v4.0.0", DAY_ONE, "edge", EDGE_LINE),
        ("4.00.0", DAY_ONE, "edge", EDGE_LINE),
        ("4.0.0", datetime(2026, 8, 4), "edge", EDGE_LINE),
        ("4.0.0", "2026-08-04", "edge", EDGE_LINE),
        ("4.0.0", DAY_ONE, "unknown", EDGE_LINE),
        ("4.0.0", DAY_ONE, "edge", "release/4.1"),
        ("4.0.0", DAY_ONE, "nightly", EDGE_LINE),
        ("1" * 129 + ".0.0", DAY_ONE, "edge", EDGE_LINE),
    ],
)
def test_snapshot_inputs_reject_wrong_target_date_channel_or_line(
    target_final: str, build_date: object, channel: str, release_line: str
) -> None:
    with pytest.raises((TypeError, ValueError)):
        generate_snapshot(
            channel=channel,  # type: ignore[arg-type]
            target_final=target_final,
            release_line=release_line,
            source_sha=SOURCE_A,
            build_date=build_date,  # type: ignore[arg-type]
        )


def test_same_source_conflicting_records_are_rejected() -> None:
    first = _generate_edge()
    second = _generate_edge(source_sha=SOURCE_B, existing=(SnapshotRecord(SOURCE_A, first),))
    conflict = SnapshotRecord(SOURCE_A, second)
    with pytest.raises(ValueError, match="conflicting"):
        _generate_edge(existing=(SnapshotRecord(SOURCE_A, first), conflict))


def test_same_emitted_version_from_different_sources_is_rejected() -> None:
    first = _generate_edge()
    collision = SnapshotRecord(SOURCE_B, first)
    with pytest.raises(ValueError, match="collision"):
        _generate_edge(existing=(SnapshotRecord(SOURCE_A, first), collision))


def test_malformed_existing_records_are_rejected_and_input_tuple_stays_unchanged() -> None:
    first = _generate_edge()
    original = (SnapshotRecord(SOURCE_A, first),)
    malformed = ("not a record",)  # type: ignore[assignment]
    with pytest.raises(ValueError):
        _generate_edge(existing=malformed)  # type: ignore[arg-type]
    assert original == (SnapshotRecord(SOURCE_A, first),)


def test_malformed_nightly_result_is_rejected_at_validation_boundary() -> None:
    nightly = _generate_nightly()
    malformed = replace(nightly, sequence=None)
    with pytest.raises(ValueError):
        _generate_nightly(existing=(SnapshotRecord(SOURCE_A, malformed),))


def test_nightly_sequence_scopes_independently_from_edge() -> None:
    edge = _generate_edge()
    nightly = _generate_nightly(source_sha=SOURCE_B, existing=(SnapshotRecord(SOURCE_A, edge),))
    assert nightly.sequence == "20260804.1"
    assert nightly.version == "4.0.0.nightly.20260804.1"
