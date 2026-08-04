"""Independent Nightly allocation contract for issue #2140."""

from __future__ import annotations

from dataclasses import fields, replace
from datetime import date, datetime
from typing import Any

import pytest

from scripts import release_version as rv

API: Any = rv
DAY_ONE = date(2026, 8, 4)
DAY_TWO = date(2026, 8, 5)
DAY_ZERO = date(2026, 8, 3)
SOURCE_A = "a" * 40
SOURCE_B = "b" * 64
PORTS_A = "c" * 40
PORTS_B = "d" * 64
MATRIX_A = "e" * 64
MATRIX_B = "f" * 64


def _allocate(
    build_date: date = DAY_ONE,
    source_sha: str = SOURCE_A,
    ports_sha: str = PORTS_A,
    input_digest: str = MATRIX_A,
    existing: tuple[Any, ...] = (),
) -> Any:
    return API.allocate_nightly(build_date, source_sha, ports_sha, input_digest, existing)


def test_nightly_allocation_is_frozen_with_exact_public_shape() -> None:
    allocation_type = API.NightlyAllocation
    assert [field.name for field in fields(allocation_type)] == [
        "outcome",
        "portversion",
        "portrevision",
        "pkg_version",
        "source_sha",
        "ports_sha",
        "input_digest",
    ]
    assert allocation_type.__dataclass_params__.frozen  # type: ignore[attr-defined]


def test_first_changed_input_uses_date_with_zero_revision() -> None:
    result = _allocate()
    assert result == API.NightlyAllocation("build", "20260804", 0, "20260804", SOURCE_A, PORTS_A, MATRIX_A)


def test_distinct_same_day_inputs_increment_port_revision() -> None:
    first = _allocate()
    second = _allocate(source_sha=SOURCE_B, existing=(first,))
    third = _allocate(ports_sha=PORTS_B, input_digest=MATRIX_B, existing=(first, second))
    assert (second.portversion, second.portrevision, second.pkg_version) == ("20260804", 1, "20260804_1")
    assert (third.portversion, third.portrevision, third.pkg_version) == ("20260804", 2, "20260804_2")


def test_changed_date_resets_revision_and_skipped_dates_need_no_records() -> None:
    first = _allocate()
    later = _allocate(build_date=DAY_TWO, source_sha=SOURCE_B, existing=(first,))
    assert (later.portversion, later.portrevision, later.pkg_version) == ("20260805", 0, "20260805")


def test_exact_input_is_explicit_unchanged_even_when_requested_later() -> None:
    first = _allocate()
    retry = _allocate(build_date=DAY_TWO, existing=(first,))
    assert retry == replace(first, outcome="unchanged")
    assert retry.pkg_version == first.pkg_version


def test_each_build_input_component_is_identity_and_changes_version() -> None:
    first = _allocate()
    for kwargs in (
        {"source_sha": SOURCE_B},
        {"ports_sha": PORTS_B},
        {"input_digest": MATRIX_B},
    ):
        result = _allocate(existing=(first,), **kwargs)  # type: ignore[arg-type]
        assert result.outcome == "build"
        assert result.portrevision == 1


def test_combined_input_digest_is_deterministic_and_changes_for_any_component() -> None:
    digest = API.combined_nightly_input_digest(SOURCE_A, PORTS_A, MATRIX_A)
    assert digest == API.combined_nightly_input_digest(SOURCE_A, PORTS_A, MATRIX_A)
    assert len(digest) == 64 and digest == digest.lower()
    assert digest != API.combined_nightly_input_digest(SOURCE_B, PORTS_A, MATRIX_A)
    assert digest != API.combined_nightly_input_digest(SOURCE_A, PORTS_B, MATRIX_A)
    assert digest != API.combined_nightly_input_digest(SOURCE_A, PORTS_A, MATRIX_B)


def test_older_changed_date_is_rejected() -> None:
    latest = _allocate(build_date=DAY_TWO)
    with pytest.raises(ValueError, match="older"):
        _allocate(build_date=DAY_ONE, source_sha=SOURCE_B, existing=(latest,))


def test_duplicate_version_with_different_input_is_rejected() -> None:
    first = _allocate()
    collision = replace(first, source_sha=SOURCE_B, outcome="build")
    with pytest.raises(ValueError, match="collision"):
        _allocate(existing=(first, collision))


def test_same_input_with_different_version_is_rejected() -> None:
    first = _allocate()
    conflict = replace(first, portversion="20260805", pkg_version="20260805", outcome="build")
    with pytest.raises(ValueError, match="conflicting"):
        _allocate(existing=(first, conflict))


@pytest.mark.parametrize("source_sha", ["", "A" * 40, "a" * 39, "a" * 41, "g" * 40, "a" * 63, "a" * 65])
def test_source_sha_is_strict_lowercase_hex(source_sha: str) -> None:
    with pytest.raises(ValueError):
        _allocate(source_sha=source_sha)


@pytest.mark.parametrize("ports_sha", ["", "A" * 40, "c" * 39, "c" * 41, "g" * 40, "c" * 63, "c" * 65])
def test_ports_sha_is_strict_lowercase_hex(ports_sha: str) -> None:
    with pytest.raises(ValueError):
        _allocate(ports_sha=ports_sha)


@pytest.mark.parametrize("input_digest", ["", "A" * 64, "e" * 63, "e" * 65, "g" * 64, "e" * 40])
def test_input_digest_is_strict_lowercase_64_hex(input_digest: str) -> None:
    with pytest.raises(ValueError):
        _allocate(input_digest=input_digest)


@pytest.mark.parametrize("build_date", [datetime(2026, 8, 4), "2026-08-04", None])
def test_build_date_requires_exact_date_type(build_date: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        _allocate(build_date=build_date)  # type: ignore[arg-type]


@pytest.mark.parametrize("bad_version", ["20230229", "2026080", "20260804_0", "20260804_01", "20260804-1"])
def test_malformed_durable_version_shape_fails_closed(bad_version: str) -> None:
    malformed = replace(_allocate(), portversion=bad_version, pkg_version=bad_version)
    with pytest.raises((TypeError, ValueError)):
        _allocate(existing=(malformed,))


@pytest.mark.parametrize("record_kind", ["object", "string", "tampered"])
def test_malformed_durable_records_fail_closed(record_kind: str) -> None:
    record: object = {"object": object(), "string": "record", "tampered": replace(_allocate(), pkg_version="bad")}[
        record_kind
    ]
    with pytest.raises((TypeError, ValueError)):
        _allocate(existing=(record,))  # type: ignore[arg-type]


def test_oversized_durable_nightly_version_fails_closed() -> None:
    revision = int("9" * 120)
    malformed = replace(_allocate(), portrevision=revision, pkg_version=f"20260804_{revision}")
    with pytest.raises(ValueError, match="128"):
        _allocate(existing=(malformed,))


def test_next_nightly_revision_cannot_cross_the_identity_limit() -> None:
    revision = int("9" * 119)
    existing = replace(_allocate(), portrevision=revision, pkg_version=f"20260804_{revision}")
    with pytest.raises(ValueError, match="128"):
        _allocate(source_sha=SOURCE_B, existing=(existing,))


def test_nightly_noop_result_can_be_replayed_with_its_build_result() -> None:
    first = _allocate()
    retry = _allocate(existing=(first,))
    assert retry.outcome == "unchanged"
    assert _allocate(existing=(first, retry)) == retry


@pytest.mark.parametrize(
    "field,value",
    [
        ("outcome", "skip"),
        ("portrevision", -1),
        ("portrevision", True),
        ("portversion", "20260804_1"),
        ("pkg_version", "20260804_1"),
        ("source_sha", "A" * 40),
        ("ports_sha", "A" * 40),
        ("input_digest", "A" * 64),
    ],
)
def test_malformed_allocation_result_fields_fail_closed(field: str, value: object) -> None:
    malformed = replace(_allocate(), **{field: value})
    with pytest.raises((TypeError, ValueError)):
        _allocate(existing=(malformed,))


def test_edge_snapshot_generation_and_target_final_are_removed() -> None:
    with pytest.raises((AttributeError, TypeError, ValueError)):
        API.generate_snapshot(
            channel="edge",
            target_final="4.0.0",
            release_line="release/4.0",
            source_sha=SOURCE_A,
            build_date=DAY_ONE,
        )
