"""Stateless Nightly build-provenance helpers."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts import nightly_provenance as np

SOURCE_SHA = "a" * 40
PORTS_SHA = "b" * 40
VERSION = f"20260814153045.{SOURCE_SHA[:7]}"


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


def test_build_record_binds_stateless_snapshot_identity() -> None:
    record = np.make_build_record(
        pkg_version=VERSION,
        source_sha=SOURCE_SHA,
        ports_sha=PORTS_SHA,
        matrix_row=_row(),
        source_date_epoch=1_800_000_000,
    )

    assert record["canonical_package_version"] == VERSION
    assert record["source_sha"] == SOURCE_SHA
    assert record["freebsd_ports_sha"] == PORTS_SHA


def test_build_record_rejects_version_for_different_source() -> None:
    with pytest.raises(np.ProvenanceError, match="does not match"):
        np.make_build_record(
            pkg_version=VERSION,
            source_sha="c" * 40,
            ports_sha=PORTS_SHA,
            matrix_row=_row(),
            source_date_epoch=1_800_000_000,
        )


def test_duplicate_json_keys_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "value.json"
    path.write_text('{"schema": 1, "schema": 1}', encoding="utf-8")

    with pytest.raises(np.ProvenanceError, match="duplicate JSON key"):
        np._read_json(path)
