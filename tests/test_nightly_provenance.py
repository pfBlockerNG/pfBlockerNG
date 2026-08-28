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
