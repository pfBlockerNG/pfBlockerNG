"""Stateless Nightly package-version contract."""

from __future__ import annotations

import pytest

from scripts import release_version as rv

SOURCE_A = "a" * 40
SOURCE_B = "b" * 64
SOURCE_MIXED = ("0123abcdef" * 4)[:40]
PORTS_A = "c" * 40
PORTS_B = "d" * 64
MATRIX_A = "e" * 64
MATRIX_B = "f" * 64


@pytest.mark.parametrize("source_sha", [SOURCE_A, SOURCE_B, SOURCE_MIXED])
def test_nightly_version_accepts_utc_seconds_and_short_source_sha(source_sha: str) -> None:
    version = f"20260804153045.{source_sha[:7]}"
    assert rv.validate_nightly_version(version, source_sha=source_sha) == version


@pytest.mark.parametrize(
    "version",
    [
        "20260804",
        "20260804_1",
        f"2026080415304.{SOURCE_A[:7]}",
        f"202608041530450.{SOURCE_A[:7]}",
        f"20260229153045.{SOURCE_A[:7]}",
        f"20260804246000.{SOURCE_A[:7]}",
        f"20260804153045.{'A' * 7}",
        f"20260804153045.{'a' * 6}",
        f"20260804153045.{'a' * 8}",
        f"20260804153045.{'g' * 7}",
        f"20260804153045.{SOURCE_A}",
    ],
)
def test_nightly_version_rejects_old_or_malformed_shapes(version: str) -> None:
    with pytest.raises(ValueError):
        rv.validate_nightly_version(version)


def test_nightly_version_must_name_the_pinned_source() -> None:
    with pytest.raises(ValueError, match="does not match"):
        rv.validate_nightly_version(f"20260804153045.{SOURCE_A[:7]}", source_sha="b" * 40)


def test_combined_input_digest_is_deterministic_and_changes_for_any_component() -> None:
    digest = rv.combined_nightly_input_digest(SOURCE_A, PORTS_A, MATRIX_A)
    assert digest == rv.combined_nightly_input_digest(SOURCE_A, PORTS_A, MATRIX_A)
    assert len(digest) == 64 and digest == digest.lower()
    assert digest != rv.combined_nightly_input_digest(SOURCE_B, PORTS_A, MATRIX_A)
    assert digest != rv.combined_nightly_input_digest(SOURCE_A, PORTS_B, MATRIX_A)
    assert digest != rv.combined_nightly_input_digest(SOURCE_A, PORTS_A, MATRIX_B)


def test_edge_snapshot_generation_is_removed() -> None:
    with pytest.raises((AttributeError, TypeError, ValueError)):
        getattr(rv, "generate_snapshot")(
            channel="edge",
            target_final="4.0.0",
            release_line="release/4.0",
            source_sha=SOURCE_A,
            build_date="20260804",
        )
