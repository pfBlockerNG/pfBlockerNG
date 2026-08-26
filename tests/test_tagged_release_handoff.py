"""Tagged release handoff identity and fail-closed validation."""

from __future__ import annotations

import importlib.util
import io
import json
import lzma
import subprocess
import sys
import tarfile
from pathlib import Path
from typing import Any

import pfb_pkg
import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/tagged_release_handoff.py"
TAG = "v4.0.0.b1"
SOURCE_SHA = "a" * 40
CI_METADATA_SHA = "b" * 40
PORTS_SHA = "c" * 40
SOURCE_DATE_EPOCH = 1_700_000_000
DEPENDENCY_BUILDER = {
    "python": "3.11.15",
    "pip": "26.2.1",
    "setuptools": "75.6.0",
    "wheel": "0.45.1",
    "zstandard": "0.25.0",
    "uv": "0.12.6",
    "uv_lock_sha256": "d" * 64,
}
ROW = {
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


def _module() -> Any:
    spec = importlib.util.spec_from_file_location("tagged_release_handoff", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _payload() -> dict[str, object]:
    return _module().build_handoff(
        release_tag=TAG,
        source_sha=SOURCE_SHA,
        ci_metadata_sha=CI_METADATA_SHA,
        ports_sha=PORTS_SHA,
        route_matrix=[ROW],
        source_date_epoch=SOURCE_DATE_EPOCH,
        dependency_builder=DEPENDENCY_BUILDER,
    )


def _write(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_cli_creates_canonical_build_time_handoff(tmp_path: Path) -> None:
    route = tmp_path / "route.json"
    output = tmp_path / "handoff.json"
    _write(route, [ROW])
    dependency_builder = tmp_path / "dependency-builder.json"
    _write(dependency_builder, DEPENDENCY_BUILDER)

    completed = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--release-tag",
            TAG,
            "--source-sha",
            SOURCE_SHA,
            "--ci-metadata-sha",
            CI_METADATA_SHA,
            "--ports-sha",
            PORTS_SHA,
            "--source-date-epoch",
            str(SOURCE_DATE_EPOCH),
            "--dependency-builder",
            str(dependency_builder),
            "--route-matrix",
            str(route),
            "--output",
            str(output),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert set(payload) == {
        "schema",
        "kind",
        "release_tag",
        "source_sha",
        "ci_metadata_sha",
        "ports_sha",
        "route_matrix",
        "source_date_epoch",
        "dependency_builder",
    }
    assert payload["kind"] == "tagged-release-handoff"
    assert payload["release_tag"] == TAG
    assert payload["source_sha"] == SOURCE_SHA
    assert payload["ci_metadata_sha"] == CI_METADATA_SHA
    assert payload["ports_sha"] == PORTS_SHA
    assert payload["route_matrix"] == [ROW]

    assert payload["source_date_epoch"] == SOURCE_DATE_EPOCH
    assert payload["dependency_builder"] == DEPENDENCY_BUILDER


def test_load_accepts_exact_release_and_source(tmp_path: Path) -> None:
    path = tmp_path / "handoff.json"
    _write(path, _payload())

    handoff = _module().load_handoff(path, expected_release_tag=TAG, expected_source_sha=SOURCE_SHA)

    assert handoff["route_matrix"] == [ROW]
    assert handoff["ports_sha"] == PORTS_SHA


@pytest.mark.parametrize(
    ("case", "message"),
    [
        ("missing", "cannot read"),
        ("malformed", "valid JSON"),
        ("schema-bool", "schema"),
        ("schema-float", "schema"),
        ("wrong-release", "release_tag"),
        ("wrong-source", "source_sha"),
        ("wrong-ci-shape", "ci_metadata_sha"),
        ("wrong-ports-shape", "ports_sha"),
        ("extra-field", "unexpected fields"),
    ],
)
def test_load_fails_closed_on_invalid_handoff(tmp_path: Path, case: str, message: str) -> None:
    module = _module()
    path = tmp_path / "handoff.json"
    expected_tag = TAG
    expected_source = SOURCE_SHA
    if case == "missing":
        pass
    elif case == "malformed":
        path.write_text("not json", encoding="utf-8")
    else:
        payload = _payload()
        if case == "schema-bool":
            payload["schema"] = True
        elif case == "schema-float":
            payload["schema"] = 1.0
        elif case == "wrong-release":
            expected_tag = "v4.0.0.b2"
        elif case == "wrong-source":
            expected_source = "d" * 40
        elif case == "wrong-ci-shape":
            payload["ci_metadata_sha"] = "not-a-sha"
        elif case == "wrong-ports-shape":
            payload["ports_sha"] = "c" * 64
        elif case == "extra-field":
            payload["live_route"] = []
        _write(path, payload)

    with pytest.raises(module.HandoffError, match=message):
        module.load_handoff(path, expected_release_tag=expected_tag, expected_source_sha=expected_source)


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"source_tag": "v4.0.0.b2"}, "source_tag"),
        ({"source_sha": "d" * 40}, "source_sha"),
        ({"freebsd_ports_sha": "e" * 40}, "freebsd_ports_sha"),
        ({"source_date_epoch": SOURCE_DATE_EPOCH + 1}, "source_date_epoch"),
        ({"dependency_builder": {**DEPENDENCY_BUILDER, "pip": "26.2.2"}}, "dependency_builder"),
    ],
)
def test_build_records_must_match_handoff_identities(changes: dict[str, object], message: str) -> None:
    module = _module()
    record = {
        "source_tag": TAG,
        "source_sha": SOURCE_SHA,
        "freebsd_ports_sha": PORTS_SHA,
        "source_date_epoch": SOURCE_DATE_EPOCH,
        "dependency_builder": DEPENDENCY_BUILDER,
        **changes,
    }

    with pytest.raises(module.HandoffError, match=message):
        module.validate_build_records(_payload(), [record])


def test_build_records_accept_exact_handoff_identities() -> None:
    module = _module()
    records = [
        {
            "source_tag": TAG,
            "source_sha": SOURCE_SHA,
            "freebsd_ports_sha": PORTS_SHA,
            "source_date_epoch": SOURCE_DATE_EPOCH,
            "dependency_builder": DEPENDENCY_BUILDER,
        },
        {
            "source_tag": TAG,
            "source_sha": SOURCE_SHA,
            "freebsd_ports_sha": PORTS_SHA,
            "source_date_epoch": SOURCE_DATE_EPOCH,
            "dependency_builder": DEPENDENCY_BUILDER,
        },
    ]

    module.validate_build_records(_payload(), records)


def _canonical_record(**changes: object) -> dict[str, object]:
    record: dict[str, object] = {
        "schema": 1,
        "channel": "edge",
        "release_line": "release/4.0",
        "classification": "beta",
        "source_tag": TAG,
        "source_sha": SOURCE_SHA,
        "canonical_package_version": "4.0.0.b1",
        "native_recipe_identity": "pfSense-pkg-pfBlockerNG-edge",
        "emitted_identity": pfb_pkg.CANONICAL_EMITTED_IDENTITY,
        "matrix_row": ROW,
        "freebsd_ports_sha": PORTS_SHA,
        "route": "edge/ce-2.8",
        "source_date_epoch": SOURCE_DATE_EPOCH,
        "dependency_builder": DEPENDENCY_BUILDER,
        "build_input_digest": "",
    }
    record.update(changes)
    record["build_input_digest"] = pfb_pkg.build_input_digest(record)
    return record


def _write_package(path: Path, record: dict[str, object], *, name: str) -> None:
    manifest = {
        "name": name,
        "version": "4.0.0.b1",
        "origin": "net/pfSense-pkg-pfBlockerNG",
        "abi": "FreeBSD:15:*",
        "arch": "freebsd:15:*",
        "prefix": "/usr/local",
        "annotations": {pfb_pkg.PFB_BUILD_RECORD_KEY: json.dumps(record)},
    }
    payload = json.dumps(manifest).encode()
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w") as tf:
        member = tarfile.TarInfo("+COMPACT_MANIFEST")
        member.size = len(payload)
        tf.addfile(member, io.BytesIO(payload))
    path.write_bytes(lzma.compress(archive.getvalue()))


@pytest.mark.parametrize(
    ("changes", "field"),
    [
        ({"source_date_epoch": SOURCE_DATE_EPOCH + 1}, "source_date_epoch"),
        ({"dependency_builder": {**DEPENDENCY_BUILDER, "wheel": "0.45.2"}}, "dependency_builder"),
    ],
)
def test_actual_package_records_must_match_tagged_handoff(
    tmp_path: Path,
    changes: dict[str, object],
    field: str,
) -> None:
    module = _module()
    exact = tmp_path / "exact.pkg"
    dependency = tmp_path / "dependency.pkg"
    drifted = tmp_path / "drifted.pkg"
    _write_package(exact, _canonical_record(), name=pfb_pkg.CANONICAL_EMITTED_IDENTITY)
    _write_package(dependency, {}, name="py311-charset-normalizer")
    _write_package(drifted, _canonical_record(**changes), name=pfb_pkg.CANONICAL_EMITTED_IDENTITY)

    module.validate_packages(_payload(), [exact, dependency])
    with pytest.raises(module.BuildRecordIdentityError, match=field):
        module.validate_packages(_payload(), [drifted])
    with pytest.raises(module.HandoffError, match="no canonical"):
        module.validate_packages(_payload(), [dependency])
