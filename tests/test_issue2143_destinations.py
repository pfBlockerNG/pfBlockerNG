"""Issue #2143 destination derivation and package-record contract."""

from __future__ import annotations

import pytest

from scripts.release_version import derive_destinations, primary_channel_for_tag


def _destinations(
    tag: str, tags: list[str], *, branch: str = "release/4.0", branches: dict[str, str] | None = None
) -> tuple[str, ...]:
    tag_branches = (
        branches
        if branches is not None
        else {
            candidate: f"release/{candidate.split('.')[0][1:]}.{candidate.split('.')[1]}"
            for candidate in tags
            if candidate.startswith("v") and len(candidate.split(".")) >= 3
        }
    )
    return derive_destinations(tag, branch=branch, ordered_tags=tags, tag_branches=tag_branches)


@pytest.mark.parametrize(
    ("tag", "expected"),
    [
        ("v4.0.0.a1", ("edge",)),
        ("v4.0.0.b1", ("edge",)),
        ("v4.0.0.r1", ("edge",)),
        ("v4.0.1.a1", ("testing", "edge")),
        ("v4.0.1.b1", ("testing", "edge")),
        ("v4.0.1.r1", ("testing", "edge")),
        ("v4.0.0", ("stable", "testing", "edge")),
    ],
)
def test_no_later_tags_derives_destinations_by_shape_alone(tag: str, expected: tuple[str, ...]) -> None:
    assert _destinations(tag, []) == expected


def test_later_family_patch_zero_prerelease_no_longer_narrows_destinations() -> None:
    assert _destinations("v4.0.1.a1", ["v4.0.0"]) == ("testing", "edge")
    assert _destinations("v4.0.0", ["v4.0.0"]) == ("stable", "testing", "edge")
    tags = ["v4.0.0", "v4.1.0.a1"]
    assert _destinations("v4.0.1.a1", tags) == ("testing", "edge")
    assert _destinations("v4.0.0", tags) == ("stable", "testing", "edge")


def test_nonzero_prerelease_and_final_keep_edge_regardless_of_later_zero_tags() -> None:
    assert _destinations("v4.0.1.a1", ["v4.0.0"]) == ("testing", "edge")
    assert _destinations("v4.0.1.a1", ["v4.0.0", "v4.1.0.a1", "v4.1.0.r1"]) == ("testing", "edge")
    assert _destinations("v4.0.1", ["v4.0.0", "v4.1.0.r1"]) == ("stable", "testing", "edge")


def test_patch_zero_prerelease_stays_edge_only_regardless_of_later_families() -> None:
    tags = ["v4.0.0", "v4.1.0.a1", "v4.1.0.r1"]
    assert _destinations("v4.0.0.a1", tags) == ("edge",)


def test_current_tag_branch_mismatch_fails_before_classification() -> None:
    with pytest.raises(ValueError, match="current tag.*release/4.0"):
        _destinations("v4.0.1.a1", [], branches={"v4.0.1.a1": "release/4.1"})


def test_current_tag_branch_argument_mismatch_fails() -> None:
    with pytest.raises(ValueError, match="current tag.*release/4.0"):
        _destinations("v4.0.1.a1", [], branch="release/9.9")


@pytest.mark.parametrize(
    ("tag", "expected"),
    [("v4.0.0", "stable"), ("v4.0.1.a1", "testing"), ("v4.0.0.a1", "edge")],
)
def test_primary_channel_for_tag_matches_release_shape(tag: str, expected: str) -> None:
    assert primary_channel_for_tag(tag) == expected


@pytest.mark.parametrize("tag", ["v4.0", "v4.0.0.x1", "v04.0.0"])
def test_primary_channel_for_tag_rejects_malformed_tag(tag: str) -> None:
    with pytest.raises(ValueError, match="invalid release tag"):
        primary_channel_for_tag(tag)
