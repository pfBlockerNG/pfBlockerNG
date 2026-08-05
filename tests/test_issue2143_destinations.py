"""Issue #2143 destination derivation and package-record contract."""

from __future__ import annotations

import pytest

from scripts.release_version import derive_destinations


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
def test_missing_zero_anchor_derives_all_required_destinations(tag: str, expected: tuple[str, ...]) -> None:
    assert _destinations(tag, []) == expected


def test_later_zero_prerelease_transitions_both_prerelease_and_final() -> None:
    assert _destinations("v4.0.1.a1", ["v4.0.0"]) == ("testing", "edge")
    assert _destinations("v4.0.0", ["v4.0.0"]) == ("stable", "testing", "edge")
    tags = ["v4.0.0", "v4.1.0.a1"]
    assert _destinations("v4.0.1.a1", tags) == ("testing",)
    assert _destinations("v4.0.0", tags) == ("stable", "testing")


def test_nonzero_prerelease_and_final_drop_edge_after_later_zero_tag() -> None:
    assert _destinations("v4.0.1.a1", ["v4.0.0"]) == ("testing", "edge")
    assert _destinations("v4.0.1.a1", ["v4.0.0", "v4.1.0.a1", "v4.1.0.r1"]) == ("testing",)
    assert _destinations("v4.0.1", ["v4.0.0", "v4.1.0.r1"]) == ("stable", "testing")


def test_malformed_nonzero_and_wrong_branch_tags_do_not_count() -> None:
    tags = ["v4.0.0", "v4.1.0.a1", "v4.1.0.gamma.9", "v4.1.0.1", "v4.1.0.r2"]
    branches = {"v4.0.0": "release/4.0", "v4.1.0.a1": "release/4.2", "v4.1.0.r2": "release/4.1"}
    assert _destinations("v4.0.1.a1", tags, branches=branches) == ("testing",)


def test_current_tag_branch_mismatch_fails_before_classification() -> None:
    with pytest.raises(ValueError, match="current tag.*release/4.0"):
        _destinations("v4.0.1.a1", [], branches={"v4.0.1.a1": "release/4.1"})


def test_missing_anchor_is_none_safe() -> None:
    assert _destinations("v4.0.1.a1", ["v4.0.0.a1"]) == ("testing", "edge")
