"""Verified Nightly build-record and publisher-handoff contract."""

from __future__ import annotations

import json
from hashlib import sha256
from typing import Any

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
    "uv_lock_sha256": "f" * 64,
}


def _row(version: str = "2.8.0", *, role: str | None = None, ci: bool | None = None) -> dict[str, object]:
    row: dict[str, object] = {
        "pfsense_version": version,
        "channel": "CE",
        "freebsd_version": "15.0-RELEASE",
        "freebsd_major": "15",
        "php_version": "8.3",
        "py_flavor": "py311",
        "variant": "CE",
        "status": "GA",
        "extra_pkgs": [],
    }
    if role is not None:
        row["role"] = role
    if ci is not None:
        row["ci"] = ci
    return row


def _record(row: dict[str, object]) -> dict[str, object]:
    return np.make_build_record(
        pkg_version=VERSION,
        source_sha=SOURCE_SHA,
        ports_sha=PORTS_SHA,
        matrix_row=row,
        source_date_epoch=1_800_000_000,
        dependency_builder=DEPENDENCY_BUILDER,
    )


def _result(row: dict[str, object] | None = None) -> dict[str, object]:
    row = row or _row()
    return {
        "matrix_row": row,
        "record": _record(row),
        "artifact": {
            "abi": f"FreeBSD:{row['freebsd_major']}:*",
            "name": f"pfSense-pkg-pfBlockerNG-{VERSION}.pkg",
            "sha256": sha256(f"pkg{row['freebsd_major']}".encode()).hexdigest(),
        },
        "dep_artifacts": [],
    }


def _call_handoff(
    results: list[dict[str, object]],
    *,
    build_rows: list[dict[str, object]] | None = None,
    route_rows: list[dict[str, object]] | None = None,
    pkg_version: str = VERSION,
    source_date_epoch: int = 1_800_000_000,
    dependency_builder: dict[str, str] | None = None,
) -> dict[str, Any]:
    return np.build_handoff(
        pkg_version=pkg_version,
        build_rows=build_rows or [_row()],
        route_rows=route_rows or [_row(ci=True)],
        results=results,
        source_sha=SOURCE_SHA,
        ports_sha=PORTS_SHA,
        tools_sha="e" * 40,
        matrix_sha="d" * 40,
        matrix_digest="c" * 64,
        dependency_builder=DEPENDENCY_BUILDER if dependency_builder is None else dependency_builder,
        source_date_epoch=source_date_epoch,
        run_id="123",
    )


def test_handoff_accepts_complete_build_and_route_rows() -> None:
    handoff = _call_handoff(
        [_result()],
        route_rows=[_row(ci=True), _row("2.7.0", role="route-only", ci=False)],
    )

    assert handoff["kind"] == "nightly-handoff"
    assert handoff["pkg_version"] == VERSION
    handoff_inputs = json.dumps(
        {
            "matrix_digest": "c" * 64,
            "source_date_epoch": 1_800_000_000,
            "dependency_builder": DEPENDENCY_BUILDER,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    nested_digest = sha256(handoff_inputs).hexdigest()
    expected_digest = sha256("\0".join((SOURCE_SHA, PORTS_SHA, nested_digest)).encode("ascii")).hexdigest()
    assert handoff["input_digest"] == expected_digest
    assert handoff["source_date_epoch"] == 1_800_000_000
    assert handoff["dependency_builder"] == DEPENDENCY_BUILDER
    assert handoff["tools_sha"] == "e" * 40
    builds = handoff["builds"]
    route_matrix = handoff["route_matrix"]
    assert isinstance(builds, list) and len(builds) == 1
    assert isinstance(route_matrix, list)
    assert route_matrix[0]["ci"] is True
    assert route_matrix[1]["role"] == "route-only"
    assert route_matrix[1]["ci"] is False
    assert "role" not in route_matrix[0]
    assert builds[0]["dep_artifacts"] == []


def test_handoff_rejects_missing_build_result() -> None:
    with pytest.raises(np.ProvenanceError, match="result count"):
        _call_handoff([])


def test_handoff_rejects_version_for_different_source() -> None:
    with pytest.raises(np.ProvenanceError, match="does not match"):
        _call_handoff([_result()], pkg_version=f"20260814153045.{'f' * 7}")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source_date_epoch", 1_800_000_001),
        ("dependency_builder", {**DEPENDENCY_BUILDER, "wheel": "0.45.2"}),
    ],
)
def test_handoff_rejects_per_leg_epoch_or_builder_drift(field: str, value: object) -> None:
    result = _result()
    record = result["record"]
    assert isinstance(record, dict)
    record[field] = value
    record["build_input_digest"] = np.build_input_digest(record)

    with pytest.raises(np.ProvenanceError, match="provenance"):
        _call_handoff([result])


def test_handoff_input_digest_binds_epoch_and_dependency_builder() -> None:
    baseline = _call_handoff([_result()])
    epoch_result = _result()
    epoch_record = epoch_result["record"]
    assert isinstance(epoch_record, dict)
    epoch_record["source_date_epoch"] = 1_800_000_001
    epoch_record["build_input_digest"] = np.build_input_digest(epoch_record)
    changed_epoch = _call_handoff([epoch_result], source_date_epoch=1_800_000_001)

    changed_builder_identity = {**DEPENDENCY_BUILDER, "wheel": "0.45.2"}
    builder_result = _result()
    builder_record = builder_result["record"]
    assert isinstance(builder_record, dict)
    builder_record["dependency_builder"] = changed_builder_identity
    builder_record["build_input_digest"] = np.build_input_digest(builder_record)
    changed_builder = _call_handoff([builder_result], dependency_builder=changed_builder_identity)

    assert changed_epoch["input_digest"] != baseline["input_digest"]
    assert changed_builder["input_digest"] != baseline["input_digest"]


def test_handoff_carries_one_dep_artifact_sorted() -> None:
    row = _row()
    row["extra_pkgs"] = ["textproc/py-charset-normalizer"]
    result = _result(row)
    dep = {
        "abi": "FreeBSD:15:*",
        "name": "py311-charset-normalizer-3.4.0.pkg",
        "sha256": sha256(b"dep").hexdigest(),
    }
    result["dep_artifacts"] = [dep]
    handoff = _call_handoff([result], build_rows=[row])
    assert handoff["builds"][0]["dep_artifacts"] == [dep]


def test_handoff_rejects_result_missing_dep_artifacts_key() -> None:
    result = _result()
    del result["dep_artifacts"]
    with pytest.raises(np.ProvenanceError, match="unexpected fields"):
        _call_handoff([result])


def test_handoff_rejects_result_with_extra_unknown_field() -> None:
    result = _result()
    result["bogus"] = "nope"
    with pytest.raises(np.ProvenanceError, match="unexpected fields"):
        _call_handoff([result])


CHARSET_ORIGIN = "textproc/py-charset-normalizer"
CHARSET_PKG = "py311-charset-normalizer-3.4.0.pkg"


def _plus_row() -> dict[str, object]:
    return {
        "pfsense_version": "26.03",
        "channel": "Plus",
        "freebsd_version": "16.0-RELEASE",
        "freebsd_major": "16",
        "php_version": "8.3",
        "py_flavor": "py311",
        "variant": "Plus",
        "status": "GA",
        "extra_pkgs": [],
    }


def _charset_dep(*, abi: str = "FreeBSD:15:*") -> dict[str, str]:
    return {
        "abi": abi,
        "name": CHARSET_PKG,
        "sha256": sha256(b"dep").hexdigest(),
    }


def test_handoff_rejects_empty_dep_artifacts_when_extra_pkgs_declared() -> None:
    """issue #2405: extra_pkgs=[charset] with dep_artifacts=[] must fail-close."""
    row = _row()
    row["extra_pkgs"] = [CHARSET_ORIGIN]
    result = _result(row)
    assert result["dep_artifacts"] == []
    with pytest.raises(np.ProvenanceError, match="extra_pkgs"):
        _call_handoff([result], build_rows=[row])


def test_handoff_accepts_one_dep_artifact_for_declared_charset_extra() -> None:
    """issue #2405: declared charset extra_pkgs with matching dep .pkg is accepted."""
    row = _row()
    row["extra_pkgs"] = [CHARSET_ORIGIN]
    result = _result(row)
    result["dep_artifacts"] = [_charset_dep()]
    handoff = _call_handoff([result], build_rows=[row])
    assert handoff["builds"][0]["dep_artifacts"] == [_charset_dep()]


def test_handoff_rejects_undeclared_dep_artifact_when_extra_pkgs_empty() -> None:
    """issue #2405: extra_pkgs=[] still requires dep_artifacts == []."""
    row = _row()
    assert row["extra_pkgs"] == []
    result = _result(row)
    result["dep_artifacts"] = [_charset_dep()]
    with pytest.raises(np.ProvenanceError, match="extra_pkgs"):
        _call_handoff([result], build_rows=[row])


def test_handoff_rejects_extra_pkgs_length_two_with_one_dep_artifact() -> None:
    """issue #2405: two origins / one .pkg (overwrite) is a count mismatch."""
    row = _row()
    row["extra_pkgs"] = ["net/py-foo", CHARSET_ORIGIN]
    result = _result(row)
    result["dep_artifacts"] = [_charset_dep()]
    with pytest.raises(np.ProvenanceError, match="extra_pkgs"):
        _call_handoff([result], build_rows=[row])


def test_handoff_accepts_two_legs_only_ce_declares_charset() -> None:
    """issue #2405: CE carries charset extra; Plus extra_pkgs=[] stays empty."""
    ce_row = _row()
    ce_row["extra_pkgs"] = [CHARSET_ORIGIN]
    plus_row = _plus_row()
    ce_result = _result(ce_row)
    ce_result["dep_artifacts"] = [_charset_dep()]
    plus_result = _result(plus_row)
    assert plus_result["dep_artifacts"] == []

    handoff = _call_handoff(
        [ce_result, plus_result],
        build_rows=[ce_row, plus_row],
        route_rows=[ce_row, plus_row],
    )
    by_major = {str(build["matrix_row"]["freebsd_major"]): build for build in handoff["builds"]}
    assert by_major["15"]["dep_artifacts"] == [_charset_dep()]
    assert by_major["16"]["dep_artifacts"] == []
    assert by_major["15"]["matrix_row"]["extra_pkgs"] == [CHARSET_ORIGIN]
    assert by_major["16"]["matrix_row"]["extra_pkgs"] == []


def test_handoff_accepts_same_dep_name_across_different_legs() -> None:
    row15 = _row()
    row15["extra_pkgs"] = [CHARSET_ORIGIN]
    row16 = {**_row(), "freebsd_major": "16", "freebsd_version": "16.0-RELEASE", "extra_pkgs": [CHARSET_ORIGIN]}
    result15 = _result(row15)
    result16 = _result(row16)
    dep_name = "py311-charset-normalizer-3.4.0.pkg"
    result15["dep_artifacts"] = [{"abi": "FreeBSD:15:*", "name": dep_name, "sha256": sha256(b"dep15").hexdigest()}]
    result16["dep_artifacts"] = [{"abi": "FreeBSD:16:*", "name": dep_name, "sha256": sha256(b"dep16").hexdigest()}]

    handoff = _call_handoff([result15, result16], build_rows=[row15, row16])

    names = {
        str(build["matrix_row"]["freebsd_major"]): build["dep_artifacts"][0]["name"] for build in handoff["builds"]
    }
    assert names["15"] == names["16"] == dep_name
