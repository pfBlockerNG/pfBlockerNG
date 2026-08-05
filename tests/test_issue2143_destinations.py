"""Issue #2143 destination derivation and package-record contract."""

from __future__ import annotations

import pfb_pkg
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


def test_build_record_requires_ordered_destinations_and_digest_binding() -> None:
    record = {
        "schema": 1,
        "channel": "testing",
        "release_line": "release/4.0",
        "classification": "alpha",
        "source_tag": "v4.0.1.a1",
        "source_sha": "a" * 40,
        "canonical_package_version": "4.0.1.a1",
        "native_recipe_identity": "pfSense-pkg-pfBlockerNG-testing",
        "emitted_identity": "pfSense-pkg-pfBlockerNG",
        "matrix_row": {
            "pfsense_version": "2.8",
            "channel": "CE",
            "freebsd_version": "15.0-RELEASE",
            "freebsd_major": "15",
            "php_version": "8.3",
            "py_flavor": "py311",
            "variant": "CE",
            "status": "active",
            "extra_pkgs": [],
        },
        "freebsd_ports_sha": "b" * 40,
        "route": "testing/ce-2.8",
        "source_date_epoch": 0,
        "destinations": ["testing", "edge"],
        "build_input_digest": "",
    }
    record["build_input_digest"] = pfb_pkg.build_input_digest(record)
    assert pfb_pkg.validate_build_record(record)["destinations"] == ["testing", "edge"]
    for forged in (["edge", "testing"], ["testing", "testing"], ["stable"], ["testing", "nightly"]):
        bad = dict(record, destinations=forged)
        bad["build_input_digest"] = pfb_pkg.build_input_digest(bad)
        with pytest.raises(pfb_pkg.PkgError):
            pfb_pkg.validate_build_record(bad)
