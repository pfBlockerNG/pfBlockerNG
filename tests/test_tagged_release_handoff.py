"""Tagged release handoff identity and fail-closed validation."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import lzma
import subprocess
import sys
import tarfile
from collections.abc import Mapping
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
DEP_ORIGIN = "textproc/py-charset-normalizer"
DEP_NAME = "py311-charset-normalizer"
DEP_VERSION = "3.4.7"
DEP_SUFFIX = "-CE-2.8.pkg"
DEP_ASSET = f"{DEP_NAME}-{DEP_VERSION}{DEP_SUFFIX}"
CANONICAL_ASSET = "pfSense-pkg-pfBlockerNG-4.0.0.b1-CE-2.8.pkg"
DEP_RECORD_KEY = "pfb_dep_build_record"
DEP_PAYLOAD = "/usr/local/lib/python3.11/site-packages/charset_normalizer/__init__.py"


def _dependency_identity(row: Mapping[str, object] = ROW) -> dict[str, object]:
    suffix = f"-{row['variant']}-{row['pfsense_version']}.pkg"
    package_name = f"{row['py_flavor']}-charset-normalizer"
    return {
        "portname": "charset-normalizer",
        "port_version": DEP_VERSION,
        "distfile": f"charset_normalizer-{DEP_VERSION}.tar.gz",
        "distfile_sha256": "ae89db9e5f98a11a4bf50407d4363e7b09b31e55bc117b4f7d80aab97ba009e5",
        "distfile_size": 144_271,
        "package_name": package_name,
        "package_version": DEP_VERSION,
        "filename": f"{package_name}-{DEP_VERSION}{suffix}",
        "freebsd_ports_sha": PORTS_SHA,
        "source_date_epoch": SOURCE_DATE_EPOCH,
        "toolchain": DEPENDENCY_BUILDER,
        "abi": f"FreeBSD:{row['freebsd_major']}:*",
        "freebsd_major": row["freebsd_major"],
        "py_flavor": row["py_flavor"],
    }


DEP_IDENTITY = _dependency_identity()


def _module() -> Any:
    spec = importlib.util.spec_from_file_location("tagged_release_handoff", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _payload(
    route_matrix: object | None = None,
    dependency_packages: object | None = None,
) -> dict[str, object]:
    return _module().build_handoff(
        release_tag=TAG,
        source_sha=SOURCE_SHA,
        ci_metadata_sha=CI_METADATA_SHA,
        ports_sha=PORTS_SHA,
        route_matrix=[ROW] if route_matrix is None else route_matrix,
        dependency_packages={} if dependency_packages is None else dependency_packages,
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
    dependency_packages = tmp_path / "dependency-packages.json"
    _write(dependency_packages, {})

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
            "--dependency-packages",
            str(dependency_packages),
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
        "dependency_packages",
        "source_date_epoch",
        "dependency_builder",
    }
    assert payload["kind"] == "tagged-release-handoff"
    assert payload["release_tag"] == TAG
    assert payload["source_sha"] == SOURCE_SHA
    assert payload["ci_metadata_sha"] == CI_METADATA_SHA
    assert payload["ports_sha"] == PORTS_SHA
    assert payload["route_matrix"] == [ROW]
    assert payload["dependency_packages"] == {}

    assert payload["source_date_epoch"] == SOURCE_DATE_EPOCH
    assert payload["dependency_builder"] == DEPENDENCY_BUILDER


def test_dependency_free_handoff_may_omit_builder() -> None:
    module = _module()
    handoff = module.build_handoff(
        release_tag=TAG,
        source_sha=SOURCE_SHA,
        ci_metadata_sha=CI_METADATA_SHA,
        ports_sha=PORTS_SHA,
        route_matrix=[ROW],
        dependency_packages={},
        source_date_epoch=SOURCE_DATE_EPOCH,
        dependency_builder=None,
    )

    assert handoff["dependency_builder"] is None


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


def test_dependency_free_package_record_may_omit_builder(tmp_path: Path) -> None:
    module = _module()
    package = tmp_path / CANONICAL_ASSET
    record = _canonical_record()
    record.pop("dependency_builder")
    record["build_input_digest"] = pfb_pkg.build_input_digest(record)
    _write_package(package, record, name=pfb_pkg.CANONICAL_EMITTED_IDENTITY)

    module.validate_packages(_payload(), [package])


def _dependency_record(**changes: object) -> dict[str, object]:
    record: dict[str, object] = {
        "schema": 1,
        "freebsd_ports_sha": PORTS_SHA,
        "port_origin": DEP_ORIGIN,
        "port_version": DEP_VERSION,
        "distfile": f"charset_normalizer-{DEP_VERSION}.tar.gz",
        "distfile_sha256": "ae89db9e5f98a11a4bf50407d4363e7b09b31e55bc117b4f7d80aab97ba009e5",
        "distfile_size": 144_271,
        "py_flavor": "py311",
        "freebsd_major": "15",
        "abi": "FreeBSD:15:*",
        "source_date_epoch": SOURCE_DATE_EPOCH,
        "toolchain": DEPENDENCY_BUILDER,
    }
    record.update(changes)
    return record


def _write_dependency_package(
    path: Path,
    *,
    record_changes: dict[str, object] | None = None,
    manifest_changes: dict[str, object] | None = None,
    full_manifest_changes: dict[str, object] | None = None,
    file_changes: dict[str, object] | None = None,
    member_changes: dict[str, object] | None = None,
    annotation: str | None = "record",
    checksum: str | None = None,
    duplicate_annotation_key: bool = False,
) -> None:
    record = _dependency_record(**(record_changes or {}))
    annotations = {}
    if annotation is not None:
        annotations[DEP_RECORD_KEY] = (
            json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            if annotation == "record"
            else annotation
        )
    payload = f"__version__ = '{DEP_VERSION}'\n".encode()
    compact: dict[str, object] = {
        "name": DEP_NAME,
        "version": DEP_VERSION,
        "origin": DEP_ORIGIN,
        "comment": "Real First Universal Charset Detector",
        "maintainer": "sunpoet@FreeBSD.org",
        "www": "https://charset-normalizer.readthedocs.io/",
        "abi": "FreeBSD:15:*",
        "arch": "freebsd:15:*",
        "prefix": "/usr/local",
        "flatsize": len(payload),
        "licenselogic": "single",
        "licenses": ["MIT"],
        "desc": "A library that helps you read text from an unknown charset encoding.",
        "categories": ["textproc", "python"],
        "annotations": annotations,
        "deps": {"python311": {"origin": "lang/python311", "version": "3.11.13"}},
    }
    compact.update(manifest_changes or {})
    file_entry: dict[str, object] = {
        "sum": checksum or f"1${hashlib.sha256(payload).hexdigest()}",
        "uname": "root",
        "gname": "wheel",
        "perm": "0644",
        "fflags": 0,
        "mtime": SOURCE_DATE_EPOCH,
    }
    file_entry.update(file_changes or {})
    full = {
        **compact,
        "files": {DEP_PAYLOAD: file_entry},
    }
    full.update(full_manifest_changes or {})
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w") as tf:
        for name, value in (("+COMPACT_MANIFEST", compact), ("+MANIFEST", full)):
            data = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
            if duplicate_annotation_key:
                marker = f'"{DEP_RECORD_KEY}":'
                data = data.replace(marker.encode(), f'{marker}"duplicate",{marker}'.encode(), 1)
            member = tarfile.TarInfo(name)
            member.size = len(data)
            tf.addfile(member, io.BytesIO(data))
        member = tarfile.TarInfo(DEP_PAYLOAD)
        member.size = len(payload)
        member.mode = 0o644
        member.mtime = SOURCE_DATE_EPOCH
        member.uid = 0
        member.gid = 0
        member.uname = "root"
        member.gname = "wheel"
        for field, field_value in (member_changes or {}).items():
            setattr(member, field, field_value)
        tf.addfile(member, io.BytesIO(payload))
    path.write_bytes(lzma.compress(archive.getvalue()))


def _payload_with_dependency(origin: str = DEP_ORIGIN) -> dict[str, object]:
    return _payload(
        [{**ROW, "extra_pkgs": [origin]}],
        {DEP_SUFFIX: {origin: DEP_IDENTITY}},
    )


def test_same_origin_on_distinct_route_rows_requires_distinct_assets(tmp_path: Path) -> None:
    module = _module()
    second_row = {**ROW, "pfsense_version": "2.9", "extra_pkgs": [DEP_ORIGIN]}
    first_row = {**ROW, "extra_pkgs": [DEP_ORIGIN]}
    second_suffix = "-CE-2.9.pkg"
    handoff = _payload(
        [first_row, second_row],
        {
            DEP_SUFFIX: {DEP_ORIGIN: _dependency_identity(first_row)},
            second_suffix: {DEP_ORIGIN: _dependency_identity(second_row)},
        },
    )
    first_canonical = tmp_path / CANONICAL_ASSET
    first_dependency = tmp_path / DEP_ASSET
    second_canonical = tmp_path / "pfSense-pkg-pfBlockerNG-4.0.0.b1-CE-2.9.pkg"
    second_dependency = tmp_path / f"{DEP_NAME}-{DEP_VERSION}{second_suffix}"
    _write_package(first_canonical, _canonical_record(), name=pfb_pkg.CANONICAL_EMITTED_IDENTITY)
    _write_dependency_package(first_dependency)
    _write_package(
        second_canonical,
        _canonical_record(matrix_row=second_row, route="edge/ce-2.9"),
        name=pfb_pkg.CANONICAL_EMITTED_IDENTITY,
    )
    _write_dependency_package(second_dependency)

    module.validate_packages(
        handoff,
        [first_canonical, first_dependency, second_canonical, second_dependency],
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("package_name", "py311-wrong"),
        ("package_version", "9.9"),
        ("filename", "py311-wrong-9.9-CE-2.8.pkg"),
        ("freebsd_ports_sha", "f" * 40),
        ("source_date_epoch", SOURCE_DATE_EPOCH + 1),
        ("toolchain", {**DEPENDENCY_BUILDER, "wheel": "0.45.2"}),
        ("abi", "FreeBSD:16:*"),
        ("freebsd_major", "16"),
        ("py_flavor", "py312"),
    ],
)
def test_dependency_identity_map_rejects_drift(field: str, value: object) -> None:
    identity = {**DEP_IDENTITY, field: value}

    with pytest.raises(ValueError, match=field):
        _payload(
            [{**ROW, "extra_pkgs": [DEP_ORIGIN]}],
            {DEP_SUFFIX: {DEP_ORIGIN: identity}},
        )


def test_coherent_dependency_identity_drift_fails_against_actual_package(tmp_path: Path) -> None:
    module = _module()
    identity = {
        **DEP_IDENTITY,
        "portname": "wrong",
        "package_name": "py311-wrong",
        "filename": f"py311-wrong-{DEP_VERSION}{DEP_SUFFIX}",
    }
    handoff = _payload(
        [{**ROW, "extra_pkgs": [DEP_ORIGIN]}],
        {DEP_SUFFIX: {DEP_ORIGIN: identity}},
    )
    canonical = tmp_path / CANONICAL_ASSET
    dependency = tmp_path / DEP_ASSET
    _write_package(canonical, _canonical_record(), name=pfb_pkg.CANONICAL_EMITTED_IDENTITY)
    _write_dependency_package(dependency)

    with pytest.raises(module.HandoffError, match="package name"):
        module.validate_packages(handoff, [canonical, dependency])


def test_dependency_package_is_bound_to_exact_route_handoff(tmp_path: Path) -> None:
    module = _module()
    canonical = tmp_path / CANONICAL_ASSET
    dependency = tmp_path / DEP_ASSET
    _write_package(canonical, _canonical_record(), name=pfb_pkg.CANONICAL_EMITTED_IDENTITY)
    _write_dependency_package(dependency)

    module.validate_packages(_payload_with_dependency(), [canonical, dependency])


@pytest.mark.parametrize(
    ("record_changes", "version", "field"),
    [
        ({"port_version": "3.4"}, "3.4", "port_version"),
        ({"distfile": "other-3.4.7.tar.gz"}, DEP_VERSION, "distfile"),
        ({"distfile_sha256": "a" * 64}, DEP_VERSION, "distfile_sha256"),
        ({"distfile_size": 1}, DEP_VERSION, "distfile_size"),
    ],
)
def test_dependency_recipe_identity_must_match_handoff(
    tmp_path: Path,
    record_changes: dict[str, object],
    version: str,
    field: str,
) -> None:
    module = _module()
    canonical = tmp_path / CANONICAL_ASSET
    dependency = tmp_path / f"{DEP_NAME}-{version}-CE-2.8.pkg"
    _write_package(canonical, _canonical_record(), name=pfb_pkg.CANONICAL_EMITTED_IDENTITY)
    _write_dependency_package(
        dependency,
        record_changes=record_changes,
        manifest_changes={"version": version},
    )

    with pytest.raises(module.HandoffError, match=field):
        module.validate_packages(_payload_with_dependency(), [canonical, dependency])


def test_dependency_portname_is_bound_through_actual_package_name_and_filename(tmp_path: Path) -> None:
    module = _module()
    canonical = tmp_path / CANONICAL_ASSET
    dependency = tmp_path / f"py311-wrong-{DEP_VERSION}{DEP_SUFFIX}"
    _write_package(canonical, _canonical_record(), name=pfb_pkg.CANONICAL_EMITTED_IDENTITY)
    _write_dependency_package(dependency, manifest_changes={"name": "py311-wrong"})

    with pytest.raises(module.HandoffError, match="package name"):
        module.validate_packages(_payload_with_dependency(), [canonical, dependency])


def test_handoff_rejects_blank_dependency_origin() -> None:
    with pytest.raises(ValueError, match="extra_pkgs"):
        _payload_with_dependency("")


def test_handoff_rejects_unsafe_route_identity() -> None:
    with pytest.raises(ValueError, match="variant"):
        _payload([{**ROW, "variant": ".."}], {})


def test_handoff_accepts_route_only_row() -> None:
    route_only = {**ROW, "role": "route-only", "ci": False, "last_tag": "v3.3.3"}

    handoff = _payload([route_only], {})

    assert handoff["route_matrix"] == [route_only]


def test_unrequested_canonical_named_asset_fails_closed(tmp_path: Path) -> None:
    module = _module()
    package = tmp_path / "unrequested-CE-2.8.pkg"
    _write_package(package, _canonical_record(), name=pfb_pkg.CANONICAL_EMITTED_IDENTITY)

    with pytest.raises(module.HandoffError, match="canonical package filename"):
        module.validate_packages(_payload(), [package])


@pytest.mark.parametrize(
    ("case", "message"),
    [
        ("missing", "missing dependency"),
        ("duplicate", "duplicate dependency"),
        ("unrequested", "unrequested dependency"),
        ("missing-record", "build record"),
        ("malformed-record", "build record"),
        ("duplicate-record-key", "duplicate JSON key"),
        ("extra-annotation-key", "annotation keys"),
        ("synchronized-scripts", "scripts"),
        ("synchronized-directories", "directories"),
        ("synchronized-lua-scripts", "lua_scripts"),
        ("synchronized-users", "users"),
        ("synchronized-groups", "groups"),
        ("duplicate-annotation-key", "duplicate JSON key"),
        ("ports", "freebsd_ports_sha"),
        ("epoch", "source_date_epoch"),
        ("toolchain", "toolchain"),
        ("abi", "abi"),
        ("major", "freebsd_major"),
        ("flavor", "py_flavor"),
        ("origin", "unrequested dependency"),
        ("manifest-origin", "origin"),
        ("version", "version"),
        ("distfile", "distfile"),
        ("distfile-sha", "distfile_sha256"),
        ("distfile-size", "distfile_size"),
        ("asset", "filename"),
        ("checksum", "checksum"),
        ("manifest", "compact/full manifest"),
        ("manifest-mode", "metadata"),
        ("manifest-mtime", "metadata"),
        ("manifest-size", "metadata"),
        ("scripts", "compact/full manifest"),
        ("directories", "compact/full manifest"),
        ("deps", "dependencies"),
        ("owner", "metadata"),
        ("group", "metadata"),
        ("fflags", "metadata"),
        ("tar-owner", "metadata"),
        ("tar-group", "metadata"),
        ("tar-mode", "metadata"),
        ("tar-mtime", "metadata"),
    ],
)
def test_dependency_package_validation_fails_closed(tmp_path: Path, case: str, message: str) -> None:
    module = _module()
    canonical = tmp_path / CANONICAL_ASSET
    dependency = tmp_path / (DEP_ASSET if case != "asset" else f"wrong-{DEP_VERSION}-CE-2.8.pkg")
    _write_package(canonical, _canonical_record(), name=pfb_pkg.CANONICAL_EMITTED_IDENTITY)
    handoff = _payload_with_dependency()
    packages = [canonical]
    if case != "missing":
        record_changes: dict[str, object] = {}
        manifest_changes: dict[str, object] = {}
        full_manifest_changes: dict[str, object] = {}
        file_changes: dict[str, object] = {}
        annotation: str | None = "record"
        checksum = None
        member_changes: dict[str, object] = {}
        duplicate_annotation_key = False
        if case == "missing-record":
            annotation = None
        elif case == "malformed-record":
            annotation = "{"
        elif case == "duplicate-record-key":
            annotation = json.dumps(
                _dependency_record(),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).replace('"schema":1', '"schema":1,"schema":1')
        elif case == "extra-annotation-key":
            manifest_changes["annotations"] = {
                DEP_RECORD_KEY: json.dumps(
                    _dependency_record(),
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                "extra": "bad",
            }
        elif case == "duplicate-annotation-key":
            duplicate_annotation_key = True
        elif case == "ports":
            record_changes["freebsd_ports_sha"] = "f" * 40
        elif case == "epoch":
            record_changes["source_date_epoch"] = SOURCE_DATE_EPOCH + 1
        elif case == "toolchain":
            record_changes["toolchain"] = {**DEPENDENCY_BUILDER, "wheel": "0.45.2"}
        elif case == "abi":
            record_changes["abi"] = "FreeBSD:16:*"
        elif case == "major":
            record_changes["freebsd_major"] = "16"
        elif case == "flavor":
            record_changes["py_flavor"] = "py312"
        elif case == "origin":
            record_changes["port_origin"] = "textproc/py-wrong"
        elif case == "manifest-origin":
            manifest_changes["origin"] = "textproc/py-wrong"
        elif case == "version":
            record_changes["port_version"] = "3.4.8"
            record_changes["distfile"] = "charset_normalizer-3.4.8.tar.gz"
        elif case == "synchronized-scripts":
            manifest_changes["scripts"] = {"post-install": "#!/bin/sh\nid > /root/pwned\n"}
        elif case == "synchronized-directories":
            manifest_changes["directories"] = {"/": "y"}
        elif case == "synchronized-lua-scripts":
            manifest_changes["lua_scripts"] = {"post-install": "os.execute('id > /root/pwned')"}
        elif case == "synchronized-users":
            manifest_changes["users"] = ["root"]
        elif case == "synchronized-groups":
            manifest_changes["groups"] = ["wheel"]
        elif case == "distfile":
            record_changes["distfile"] = "../charset_normalizer.tar.gz"
        elif case == "distfile-sha":
            record_changes["distfile_sha256"] = "e" * 63
        elif case == "distfile-size":
            record_changes["distfile_size"] = 0
        elif case == "checksum":
            checksum = "1$" + "0" * 64
        elif case == "manifest-mode":
            file_changes["perm"] = "0755"
        elif case == "manifest-mtime":
            file_changes["mtime"] = SOURCE_DATE_EPOCH + 1
        elif case == "manifest-size":
            file_changes["size"] = 0
        elif case == "manifest":
            full_manifest_changes["origin"] = "textproc/py-wrong"
        elif case == "scripts":
            full_manifest_changes["scripts"] = {"install": "#!/bin/sh\nexit 0\n"}
        elif case == "directories":
            full_manifest_changes["directories"] = {"/usr/local/share/demo": "y"}
        elif case == "deps":
            manifest_changes["deps"] = {"evil": {"origin": "security/evil", "version": "1"}}
        elif case == "owner":
            file_changes["uname"] = "nobody"
        elif case == "group":
            file_changes["gname"] = "evil"
        elif case == "fflags":
            file_changes["fflags"] = 1
        elif case == "tar-owner":
            member_changes["uname"] = "nobody"
        elif case == "tar-group":
            member_changes["gname"] = "evil"
        elif case == "tar-mode":
            member_changes["mode"] = 0o755
        elif case == "tar-mtime":
            member_changes["mtime"] = SOURCE_DATE_EPOCH + 1
        _write_dependency_package(
            dependency,
            record_changes=record_changes,
            manifest_changes=manifest_changes,
            full_manifest_changes=full_manifest_changes,
            file_changes=file_changes,
            member_changes=member_changes,
            annotation=annotation,
            checksum=checksum,
            duplicate_annotation_key=duplicate_annotation_key,
        )
        packages.append(dependency)
        if case == "duplicate":
            duplicate_dir = tmp_path / "duplicate"
            duplicate_dir.mkdir()
            duplicate = duplicate_dir / dependency.name
            duplicate.write_bytes(dependency.read_bytes())
            packages.append(duplicate)
        if case == "unrequested":
            handoff = _payload()

    with pytest.raises(module.HandoffError, match=message):
        module.validate_packages(handoff, packages)


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
    exact = tmp_path / CANONICAL_ASSET
    dependency = tmp_path / DEP_ASSET
    drifted_dir = tmp_path / "drifted"
    drifted_dir.mkdir()
    drifted = drifted_dir / CANONICAL_ASSET
    _write_package(exact, _canonical_record(), name=pfb_pkg.CANONICAL_EMITTED_IDENTITY)
    _write_dependency_package(dependency)
    _write_package(drifted, _canonical_record(**changes), name=pfb_pkg.CANONICAL_EMITTED_IDENTITY)

    module.validate_packages(_payload(), [exact])
    with pytest.raises(module.HandoffError, match=field):
        module.validate_packages(_payload(), [drifted])
    with pytest.raises(module.HandoffError, match="no canonical"):
        module.validate_packages(_payload_with_dependency(), [dependency])
