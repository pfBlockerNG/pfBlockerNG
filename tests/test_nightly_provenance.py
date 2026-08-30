"""Stateless Nightly build-provenance helpers."""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path

import pytest

from scripts import nightly_provenance as np

SOURCE_SHA = "a" * 40
PORTS_SHA = "b" * 40
VERSION = f"20260814153045.{SOURCE_SHA[:7]}"
DEPENDENCY_BUILDER = {
    "python": "3.11.15",
    "pip": "26.2.1",
    "setuptools": "75.6.0",
    "wheel": "0.45.1",
    "zstandard": "0.25.0",
    "uv": "0.12.6",
    "uv_lock_sha256": "d" * 64,
}


def _row() -> dict[str, object]:
    return {
        "pfsense_version": "2.8",
        "channel": "CE",
        "freebsd_version": "15.0-RELEASE",
        "freebsd_major": "15",
        "php_version": "8.3",
        "py_flavor": "py311",
        "variant": "CE",
        "status": "active",
        "extra_pkgs": [],
    }


def _dep(
    *,
    abi: str = "FreeBSD:15:*",
    name: str = "py311-charset-normalizer-3.4.0.pkg",
    digest: str = sha256(b"dep").hexdigest(),
) -> dict[str, str]:
    return {"abi": abi, "name": name, "sha256": digest}


def test_build_record_binds_stateless_snapshot_identity() -> None:
    record = np.make_build_record(
        pkg_version=VERSION,
        source_sha=SOURCE_SHA,
        ports_sha=PORTS_SHA,
        matrix_row=_row(),
        source_date_epoch=1_800_000_000,
        dependency_builder=DEPENDENCY_BUILDER,
    )

    assert record["canonical_package_version"] == VERSION
    assert record["source_sha"] == SOURCE_SHA
    assert record["freebsd_ports_sha"] == PORTS_SHA
    assert record["source_date_epoch"] == 1_800_000_000
    assert record["dependency_builder"] == DEPENDENCY_BUILDER


@pytest.mark.parametrize("ports_sha", ["B" * 40, "b" * 39, "b" * 41, "g" * 40, "b" * 64])
def test_build_record_requires_exact_lowercase_40_hex_ports_sha(ports_sha: str) -> None:
    with pytest.raises(np.ProvenanceError, match="ports_sha"):
        np.make_build_record(
            pkg_version=VERSION,
            source_sha=SOURCE_SHA,
            ports_sha=ports_sha,
            matrix_row=_row(),
            source_date_epoch=1_800_000_000,
            dependency_builder=DEPENDENCY_BUILDER,
        )


def test_build_record_rejects_version_for_different_source() -> None:
    with pytest.raises(np.ProvenanceError, match="does not match"):
        np.make_build_record(
            pkg_version=VERSION,
            source_sha="c" * 40,
            ports_sha=PORTS_SHA,
            matrix_row=_row(),
            source_date_epoch=1_800_000_000,
            dependency_builder=DEPENDENCY_BUILDER,
        )


def test_duplicate_json_keys_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "value.json"
    path.write_text('{"schema": 1, "schema": 1}', encoding="utf-8")

    with pytest.raises(np.ProvenanceError, match="duplicate JSON key"):
        np._read_json(path)


def test_validate_dep_artifacts_accepts_empty_list() -> None:
    assert np._validate_dep_artifacts([], leg_abi="FreeBSD:15:*", canonical_name="canonical.pkg") == []


def test_validate_dep_artifacts_sorts_by_name() -> None:
    result = np._validate_dep_artifacts(
        [_dep(name="b.pkg"), _dep(name="a.pkg")],
        leg_abi="FreeBSD:15:*",
        canonical_name="canonical.pkg",
    )
    assert [item["name"] for item in result] == ["a.pkg", "b.pkg"]


@pytest.mark.parametrize("abi", ["FreeBSD:16:*", "FreeBSD:15:amd64"])
def test_validate_dep_artifacts_rejects_abi_not_equal_to_leg(abi: str) -> None:
    with pytest.raises(np.ProvenanceError, match="abi"):
        np._validate_dep_artifacts([_dep(abi=abi)], leg_abi="FreeBSD:15:*", canonical_name="canonical.pkg")


def test_validate_dep_artifacts_rejects_duplicate_name_within_leg() -> None:
    with pytest.raises(np.ProvenanceError, match="unique"):
        np._validate_dep_artifacts([_dep(), _dep()], leg_abi="FreeBSD:15:*", canonical_name="canonical.pkg")


def test_validate_dep_artifacts_rejects_name_equal_to_canonical() -> None:
    with pytest.raises(np.ProvenanceError, match="canonical"):
        np._validate_dep_artifacts([_dep(name="canonical.pkg")], leg_abi="FreeBSD:15:*", canonical_name="canonical.pkg")


@pytest.mark.parametrize("name", ["../evil.pkg", "a/b.pkg", "a\\b.pkg", "evil\n.pkg", "no-suffix", ""])
def test_validate_dep_artifacts_rejects_hostile_names(name: str) -> None:
    with pytest.raises(np.ProvenanceError, match="name"):
        np._validate_dep_artifacts([_dep(name=name)], leg_abi="FreeBSD:15:*", canonical_name="canonical.pkg")


@pytest.mark.parametrize("digest", [sha256(b"dep").hexdigest().upper(), "f" * 63, "z" * 64])
def test_validate_dep_artifacts_rejects_malformed_sha256(digest: str) -> None:
    with pytest.raises(np.ProvenanceError, match="sha256"):
        np._validate_dep_artifacts([_dep(digest=digest)], leg_abi="FreeBSD:15:*", canonical_name="canonical.pkg")


def _record(row: dict[str, object]) -> dict[str, object]:
    return np.make_build_record(
        pkg_version=VERSION,
        source_sha=SOURCE_SHA,
        ports_sha=PORTS_SHA,
        matrix_row=row,
        source_date_epoch=1_800_000_000,
        dependency_builder=DEPENDENCY_BUILDER,
    )


def _result(row: dict[str, object]) -> dict[str, object]:
    return {
        "matrix_row": row,
        "record": _record(row),
        "artifact": {
            "abi": f"FreeBSD:{row['freebsd_major']}:*",
            "name": f"pfSense-pkg-pfBlockerNG-{VERSION}.pkg",
            "sha256": sha256(f"pkg{row['freebsd_major']}{row['php_version']}".encode()).hexdigest(),
        },
        "dep_artifacts": [],
    }


def _call_handoff(
    results: list[dict[str, object]],
    *,
    build_rows: list[dict[str, object]],
    route_rows: list[dict[str, object]],
) -> dict[str, object]:
    return np.build_handoff(
        pkg_version=VERSION,
        build_rows=build_rows,
        route_rows=route_rows,
        results=results,
        source_sha=SOURCE_SHA,
        ports_sha=PORTS_SHA,
        tools_sha="e" * 40,
        matrix_sha="d" * 40,
        matrix_digest="c" * 64,
        dependency_builder=DEPENDENCY_BUILDER,
        source_date_epoch=1_800_000_000,
        run_id="123",
    )


def test_handoff_accepts_freebsd_16_php_84_and_85_tuples() -> None:
    """issue #2926: FreeBSD 16 with PHP 8.4 and 8.5 are two DISTINCT build
    tuples — handoff accepts one result per tuple and keeps both builds."""
    row84 = _row()
    row84.update(
        freebsd_major="16",
        php_version="8.4",
        freebsd_version="16.0-RELEASE",
        pfsense_version="26.03",
        variant="Plus",
        channel="Plus",
    )
    row85 = _row()
    row85.update(
        freebsd_major="16",
        php_version="8.5",
        freebsd_version="16.0-RELEASE",
        pfsense_version="26.05",
        variant="Plus",
        channel="Plus",
    )
    handoff = _call_handoff(
        [_result(row84), _result(row85)],
        build_rows=[row84, row85],
        route_rows=[row84, row85],
    )
    builds = handoff["builds"]
    assert isinstance(builds, list)
    keys = sorted(
        (
            str(b["matrix_row"]["freebsd_major"]),
            str(b["matrix_row"]["php_version"]),
            str(b["matrix_row"]["py_flavor"]),
        )
        for b in builds
    )
    assert keys == [("16", "8.4", "py311"), ("16", "8.5", "py311")], f"both runtime tuples expected; got {keys!r}"


def test_handoff_rejects_duplicate_exact_tuple_matrix_rows() -> None:
    """issue #2926: an identical (major, php, py) tuple twice in the BUILD
    matrix rejects — one build per exact tuple."""
    row = _row()
    with pytest.raises(np.ProvenanceError, match="duplicate build tuple"):
        _call_handoff([_result(row)], build_rows=[row, row], route_rows=[row])


def test_handoff_rejects_duplicate_exact_tuple_results() -> None:
    """issue #2926: two results carrying the SAME exact tuple reject — the
    matrix declares one row per tuple, so a second result is a duplicate."""
    row_a = _row()
    row_b = _row()
    row_b.update(php_version="8.4")
    with pytest.raises(np.ProvenanceError, match="duplicated"):
        _call_handoff(
            [_result(row_a), _result(row_a)],
            build_rows=[row_a, row_b],
            route_rows=[row_a],
        )


def test_handoff_accepts_same_major_same_php_different_py_flavor() -> None:
    """issue #2926: the Python flavor participates in the build key — two rows
    differing ONLY in py_flavor are two builds, not one (a (major, php)-only
    implementation would reject these as duplicates)."""
    row_a = _row()
    row_b = _row()
    row_b.update(py_flavor="py312")
    handoff = _call_handoff(
        [_result(row_a), _result(row_b)],
        build_rows=[row_a, row_b],
        route_rows=[row_a],
    )
    builds = handoff["builds"]
    assert isinstance(builds, list)
    keys = sorted(
        (
            str(b["matrix_row"]["freebsd_major"]),
            str(b["matrix_row"]["php_version"]),
            str(b["matrix_row"]["py_flavor"]),
        )
        for b in builds
    )
    assert keys == [("15", "8.3", "py311"), ("15", "8.3", "py312")], f"both py-flavor tuples expected; got {keys!r}"


def test_handoff_rejects_duplicate_py_flavor_tuple_results() -> None:
    """issue #2926: same-major/same-PHP rows differing ONLY in py_flavor are
    distinct tuples; two results carrying the SAME py-flavor tuple reject."""
    row_a = _row()
    row_b = _row()
    row_b.update(py_flavor="py312")
    with pytest.raises(np.ProvenanceError, match="duplicated"):
        _call_handoff(
            [_result(row_a), _result(row_a)],
            build_rows=[row_a, row_b],
            route_rows=[row_a],
        )
