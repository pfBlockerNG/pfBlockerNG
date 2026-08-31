"""Tests for scripts/pfb_pkg.py — the shared libpkg .pkg manifest reader.

Pins every error path of read_compact_manifest and the zstd decoder's fallback
chain: the roundtrip uses whichever decoder the environment has (the `zstandard`
module if installed, else the `zstd` binary), and the no-decoder case is forced
deterministically to assert the PkgError. This is the single copy of the reader
that both build-repo-portable.py and gen_landing.py now depend on.
"""

from __future__ import annotations

import builtins
import hashlib
import io
import json
import lzma
import shutil
import subprocess
import tarfile
from collections.abc import Callable
from pathlib import Path

import pfb_pkg
import pytest

DEPENDENCY_BUILDER = {
    "python": "3.11.15",
    "pip": "26.2.1",
    "setuptools": "75.6.0",
    "wheel": "0.45.1",
    "zstandard": "0.25.0",
    "uv": "0.12.6",
    "uv_lock_sha256": "d" * 64,
}


def _record(**overrides: object) -> dict:
    row = {
        "variant": "CE",
        "pfsense_version": "2.8",
        "channel": "CE",
        "freebsd_version": "15.0-RELEASE",
        "freebsd_major": "15",
        "php_version": "8.3",
        "py_flavor": "py311",
        "status": "active",
        "extra_pkgs": ["textproc/py-charset-normalizer"],
        "upgrade": {"available": False},
    }
    record: dict[str, object] = {
        "schema": 1,
        "channel": "stable",
        "release_line": "release/2.8",
        "classification": "final",
        "source_tag": "v2.8.0",
        "source_sha": "a" * 40,
        "canonical_package_version": "2.8.0",
        "native_recipe_identity": "pfSense-pkg-pfBlockerNG",
        "emitted_identity": "pfSense-pkg-pfBlockerNG",
        "matrix_row": row,
        "freebsd_ports_sha": "b" * 40,
        "route": "stable/ce-2.8",
        "source_date_epoch": 0,
        "dependency_builder": DEPENDENCY_BUILDER,
        "build_input_digest": "",
    }
    record.update(overrides)
    channel = str(record["channel"])
    if channel != "stable" and "route" not in overrides:
        record["route"] = f"{channel}/ce-2.8"
    record["build_input_digest"] = pfb_pkg.build_input_digest(record)
    return record


def test_build_record_valid_and_digest_is_canonical() -> None:
    record = _record()
    assert pfb_pkg.validate_build_record(record) == record
    changed = dict(record, source_sha="c" * 40)
    assert pfb_pkg.build_input_digest(changed) != record["build_input_digest"]


def test_build_record_allows_missing_dependency_builder_without_extra_packages() -> None:
    record = _record()
    record["matrix_row"] = {**record["matrix_row"], "extra_pkgs": []}
    record.pop("dependency_builder")
    record["build_input_digest"] = pfb_pkg.build_input_digest(record)

    assert pfb_pkg.validate_build_record(record) == record


def test_build_record_allows_valid_dependency_builder_without_extra_packages() -> None:
    record = _record()
    record["matrix_row"] = {**record["matrix_row"], "extra_pkgs": []}
    record["build_input_digest"] = pfb_pkg.build_input_digest(record)

    assert pfb_pkg.validate_build_record(record) == record


def test_build_record_rejects_malformed_dependency_builder_without_extra_packages() -> None:
    record = _record(dependency_builder={**DEPENDENCY_BUILDER, "wheel": "not-a-version"})
    record["matrix_row"] = {**record["matrix_row"], "extra_pkgs": []}
    record["build_input_digest"] = pfb_pkg.build_input_digest(record)

    with pytest.raises(pfb_pkg.PkgError, match="dependency_builder"):
        pfb_pkg.validate_build_record(record)


def test_build_record_requires_dependency_builder_with_extra_packages() -> None:
    record = _record()
    record.pop("dependency_builder")
    record["build_input_digest"] = pfb_pkg.build_input_digest(record)

    with pytest.raises(pfb_pkg.PkgError, match="dependency_builder"):
        pfb_pkg.validate_build_record(record)


def test_build_record_rejects_malformed_dependency_builder() -> None:
    record = _record(dependency_builder={**DEPENDENCY_BUILDER, "wheel": "not-a-version"})
    with pytest.raises(pfb_pkg.PkgError, match="dependency_builder"):
        pfb_pkg.validate_build_record(record)
    with pytest.raises(pfb_pkg.PkgError, match="dependency_builder"):
        pfb_pkg.load_build_record(json.dumps(record))


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("source_date_epoch", 1),
        ("freebsd_ports_sha", "c" * 40),
        ("dependency_builder", {**DEPENDENCY_BUILDER, "wheel": "0.45.2"}),
    ],
)
def test_build_input_digest_binds_reproducibility_fields(field: str, replacement: object) -> None:
    record = _record()
    changed = dict(record, **{field: replacement})
    assert pfb_pkg.build_input_digest(changed) != record["build_input_digest"]


@pytest.mark.parametrize("field", sorted(DEPENDENCY_BUILDER))
def test_dependency_builder_rejects_non_string_fields(field: str) -> None:
    malformed: dict[str, object] = dict(DEPENDENCY_BUILDER)
    malformed[field] = 1
    with pytest.raises(pfb_pkg.PkgError, match=field):
        pfb_pkg.validate_dependency_builder(malformed)


@pytest.mark.parametrize(
    "malformed",
    [
        {key: value for key, value in DEPENDENCY_BUILDER.items() if key != "pip"},
        {**DEPENDENCY_BUILDER, "extra": "1.0"},
        {**DEPENDENCY_BUILDER, "python": "not a version"},
        {**DEPENDENCY_BUILDER, "uv_lock_sha256": "D" * 64},
    ],
)
def test_dependency_builder_requires_exact_well_formed_fields(malformed: dict[str, object]) -> None:
    with pytest.raises(pfb_pkg.PkgError):
        pfb_pkg.validate_dependency_builder(malformed)


@pytest.mark.parametrize("ports_sha", ["B" * 40, "b" * 39, "b" * 41, "g" * 40, "b" * 64])
def test_build_record_requires_exact_lowercase_40_hex_ports_sha(ports_sha: str) -> None:
    record = _record(freebsd_ports_sha=ports_sha)
    with pytest.raises(pfb_pkg.PkgError, match="freebsd_ports_sha"):
        pfb_pkg.validate_build_record(record)


@pytest.mark.parametrize(
    "row",
    [
        {
            "pfsense_version": "2.8",
            "channel": "CE",
            "freebsd_version": "15.0-RELEASE",
            "freebsd_major": "15",
            "php_version": "8.3",
            "py_flavor": "py311",
            "variant": "CE",
            "status": "active",
            "extra_pkgs": ["textproc/py-charset-normalizer"],
            "upgrade": {"available": False},
        },
        {
            "pfsense_version": "26.07",
            "channel": "Plus",
            "freebsd_version": "16.0-RELEASE",
            "freebsd_major": "16",
            "php_version": "8.5",
            "py_flavor": "py311",
            "variant": "Plus",
            "status": "beta",
            "extra_pkgs": [],
            "upgrade": {"available": False},
            "image_name": "pfsense-plus",
            "role": "build",
            "last_tag": "v4.0.0.a1",
        },
    ],
)
def test_build_matrix_row_accepts_live_and_supported_optional_fields(row: dict[str, object]) -> None:
    assert pfb_pkg.validate_build_matrix_row(row) == row


@pytest.mark.parametrize(
    "mutator",
    [
        lambda row: row.pop("freebsd_version"),
        lambda row: row.update(ci=True),
        lambda row: row.update(extra_pkgs=["textproc/py-charset-normalizer", 1]),
        lambda row: row.update(channel="Plus"),
        lambda row: row.update(freebsd_major="16"),
        lambda row: row.update(image_name="pfsense plus"),
        lambda row: row.update(upgrade={"available": "false"}),
        lambda row: row.update(last_tag="bad\ntag"),
    ],
)
def test_build_matrix_row_rejects_missing_unknown_wrong_type_and_non_live(mutator: Callable[..., object]) -> None:
    row = {
        "pfsense_version": "2.8",
        "channel": "CE",
        "freebsd_version": "15.0-RELEASE",
        "freebsd_major": "15",
        "php_version": "8.3",
        "py_flavor": "py311",
        "variant": "CE",
        "status": "active",
        "extra_pkgs": ["textproc/py-charset-normalizer"],
        "upgrade": {"available": False},
    }
    mutator(row)
    with pytest.raises(pfb_pkg.PkgError):
        pfb_pkg.validate_build_matrix_row(row)


@pytest.mark.parametrize(
    "channel,tag,classification,version,recipe",
    [
        ("stable", "v2.8.0", "final", "2.8.0", "pfSense-pkg-pfBlockerNG"),
        ("testing", "v2.8.1.a1", "alpha", "2.8.1.a1", "pfSense-pkg-pfBlockerNG-testing"),
        ("edge", "v2.8.0.r1", "rc", "2.8.0.r1", "pfSense-pkg-pfBlockerNG-edge"),
        ("nightly", None, "nightly", f"20260804153045.{'a' * 7}", "pfSense-pkg-pfBlockerNG-nightly"),
    ],
)
def test_build_record_channel_identities(
    channel: str, tag: str | None, classification: str, version: str, recipe: str
) -> None:
    record = _record(
        channel=channel,
        source_tag=tag,
        release_line="release/4.0" if channel == "nightly" else "release/2.8",
        classification=classification,
        canonical_package_version=version,
        native_recipe_identity=recipe,
    )
    record["build_input_digest"] = pfb_pkg.build_input_digest(record)
    assert pfb_pkg.validate_build_record(record)["emitted_identity"] == pfb_pkg.CANONICAL_EMITTED_IDENTITY


@pytest.mark.parametrize(
    "mutator",
    [
        lambda r: r.pop("route"),
        lambda r: r.update(unknown=True),
        lambda r: r.update(schema=True),
        lambda r: r["matrix_row"].update(extra=1.25),
        lambda r: r.update(source_sha="A" * 40),
        lambda r: r.update(build_input_digest="0" * 64),
        lambda r: r.update(source_tag="v2.8.0.r1"),
        lambda r: r.update(route="stable/../ce-2.8"),
    ],
)
def test_build_record_rejects_malformed_or_tampered(mutator: Callable[..., object]) -> None:
    record = _record()
    mutator(record)
    with pytest.raises(pfb_pkg.PkgError):
        pfb_pkg.validate_build_record(record)


def test_build_record_nightly_timestamp_sha_and_null_rules() -> None:
    for value in (
        "20260230153045." + "a" * 7,
        "20260804246000." + "a" * 7,
        "20260804153045." + "b" * 7,
        "20260804153045." + "a" * 40,
        "20260804_1",
        "4.0.0.alpha.24",
    ):
        record = _record(
            channel="nightly",
            source_tag=None,
            release_line="release/4.0",
            classification="nightly",
            canonical_package_version=value,
            native_recipe_identity="pfSense-pkg-pfBlockerNG-nightly",
        )
        record["build_input_digest"] = pfb_pkg.build_input_digest(record)
        with pytest.raises(pfb_pkg.PkgError):
            pfb_pkg.validate_build_record(record)

    record = _record(
        channel="nightly",
        source_tag=None,
        release_line="release/4.0",
        classification="nightly",
        canonical_package_version=f"20260101153045.{'a' * 7}",
        native_recipe_identity="pfSense-pkg-pfBlockerNG-nightly",
    )
    record["build_input_digest"] = pfb_pkg.build_input_digest(record)
    assert pfb_pkg.validate_build_record(record)["canonical_package_version"] == f"20260101153045.{'a' * 7}"


def test_load_build_record_json_and_path(tmp_path: Path) -> None:
    record = _record()
    raw = json.dumps(record)
    assert pfb_pkg.load_build_record(raw) == record
    path = tmp_path / "record.json"
    path.write_text(raw)
    assert pfb_pkg.load_build_record(path) == record
    for bad in ("[]", "not-json", "{bad"):
        with pytest.raises(pfb_pkg.PkgError):
            pfb_pkg.load_build_record(bad)


@pytest.mark.parametrize(
    ("script", "valid"),
    [
        ("#!/bin/sh\n/usr/local/bin/php -f /etc/rc.packages pfSense-pkg-pfBlockerNG ${2}\n", True),
        (
            '#!/bin/sh\n\nif [ "${2}" != "POST-INSTALL" ]; then\n\texit 0\nfi\n\n'
            "${PKG_ROOTDIR}/usr/local/bin/php -f ${PKG_ROOTDIR}/etc/rc.packages "
            "pfSense-pkg-pfBlockerNG ${2}\n",
            True,
        ),
        ("#!/bin/sh\n/usr/local/bin/php -f /etc/rc.packages pfSense-pkg-pfBlockerNG ${2} # comment\n", True),
        ("#!/usr/bin/env python\n/usr/local/bin/php -f /etc/rc.packages pfSense-pkg-pfBlockerNG ${2}\n", False),
        ("#!/bin/sh -c evil\n/usr/local/bin/php -f /etc/rc.packages pfSense-pkg-pfBlockerNG ${2}\n", False),
        ("/usr/local/bin/php -f /etc/rc.packages pfSense-pkg-pfBlockerNG ${2}\n", False),
        ("#!/bin/sh\n# /etc/rc.packages pfSense-pkg-pfBlockerNG\necho safe\n", False),
        ("#!/bin/sh\n/usr/local/bin/php -f '/etc/rc.packages' 'pfSense-pkg-pfBlockerNG' ${2}\n", True),
        ("#!/bin/sh\n/usr/local/bin/php -f /etc/rc.packages 'pfSense-pkg-pfBlockerNG; echo pwned' ${2}\n", False),
        (
            "#!/bin/sh\n/usr/local/bin/php -f /etc/rc.packages pfSense-pkg-pfBlockerNG ${2}\necho '# ignored'\n",
            False,
        ),
        ("#!/bin/sh\n/usr/local/bin/php -f /etc/rc.packages pfSense-pkg-pfBlockerNG-testing ${2}\n", False),
        ("#!/bin/sh\n/usr/local/bin/php -f /etc/rc.packages\npfSense-pkg-pfBlockerNG ${2}\n", False),
        ("#!/bin/sh\n/usr/local/bin/php -f /etc/rc.packages pfSense-pkg-pfBlockerNG ${2} extra\n", False),
        ("#!/bin/sh\necho safe; /usr/local/bin/php -f /etc/rc.packages pfSense-pkg-pfBlockerNG ${2}\n", False),
        ("#!/bin/sh\n/usr/local/bin/php -f /etc/rc.packages pfSense-pkg-pfBlockerNG ${2} $(echo pwned)\n", False),
        (
            "#!/bin/sh\necho safe; echo pwned\n/usr/local/bin/php -f /etc/rc.packages pfSense-pkg-pfBlockerNG ${2}\n",
            False,
        ),
        (
            "#!/bin/sh\necho $(echo pwned)\n/usr/local/bin/php -f /etc/rc.packages pfSense-pkg-pfBlockerNG ${2}\n",
            False,
        ),
        (
            "#!/bin/sh\necho pwned > /tmp/x\n/usr/local/bin/php -f /etc/rc.packages pfSense-pkg-pfBlockerNG ${2}\n",
            False,
        ),
        (
            "#!/bin/sh\necho pwned | cat\n/usr/local/bin/php -f /etc/rc.packages pfSense-pkg-pfBlockerNG ${2}\n",
            False,
        ),
    ],
)
def test_lifecycle_hooks_accept_only_safe_canonical_commands(script: str, valid: bool) -> None:
    if valid:
        pfb_pkg._check_script(script, "fixture.pkg")
    else:
        with pytest.raises(pfb_pkg.PkgError):
            pfb_pkg._check_script(script, "fixture.pkg")


def _synthetic_pkg(
    tmp_path: Path,
    record: dict | None = None,
    *,
    compression: str = "zstd",
    compact: dict | None = None,
    full: dict | None = None,
    payload: dict[str, bytes] | None = None,
    members: list[tuple[str, bytes, int, int, bool]] | None = None,
) -> tuple[Path, dict, dict]:
    record = record or _record()
    payload = payload or {
        "/usr/local/share/pfSense-pkg-pfBlockerNG/info.xml": (
            "<pfsensepkgs><package><name>pfBlockerNG</name><version>2.8.0</version></package></pfsensepkgs>"
        ).encode(),
        "/usr/local/pkg/pfblockerng/pfb_stub.py": b"print('ok')\n",
    }
    common = {
        "name": pfb_pkg.CANONICAL_EMITTED_IDENTITY,
        "origin": "net/pfSense-pkg-pfBlockerNG",
        "version": "2.8.0",
        "abi": "FreeBSD:15:*",
        "arch": "freebsd:15:*",
        "prefix": "/usr/local",
        "annotations": {pfb_pkg.PFB_BUILD_RECORD_KEY: json.dumps(record, separators=(",", ":"), sort_keys=True)},
    }
    deps = {
        "php83": {"origin": "lang/php83", "version": "8.3.0"},
        "python311": {"origin": "lang/python311", "version": "3.11.0"},
    }
    file_manifest = {
        path: {
            "sum": "1$" + hashlib.sha256(data).hexdigest(),
            "perm": "0644",
            "mtime": 0,
            "size": len(data),
        }
        for path, data in payload.items()
    }
    full_obj = {
        **common,
        "deps": deps,
        "files": file_manifest,
        "scripts": {
            "install": "#!/bin/sh\n/usr/local/bin/php -f /etc/rc.packages pfSense-pkg-pfBlockerNG ${2}\n",
            "deinstall": "#!/bin/sh\n/usr/local/bin/php -f /etc/rc.packages pfSense-pkg-pfBlockerNG ${2}\n",
        },
    }
    compact_obj = {**common, "deps": deps}
    compact_obj = compact if compact is not None else compact_obj
    full_obj = full if full is not None else full_obj
    tar_members = [
        ("+COMPACT_MANIFEST", json.dumps(compact_obj, separators=(",", ":")).encode(), 0o644, 0, True),
        ("+MANIFEST", json.dumps(full_obj, separators=(",", ":")).encode(), 0o644, 0, True),
    ]
    if members is None:
        tar_members.extend((name, data, 0o644, 0, True) for name, data in payload.items())
    else:
        tar_members.extend(members)
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tf:
        for name, data, mode, mtime, regular in tar_members:
            ti = tarfile.TarInfo(name=name)
            ti.size = len(data)
            ti.mode = mode
            ti.mtime = mtime
            if not regular:
                ti.type = tarfile.SYMTYPE
                ti.linkname = "target"
                tf.addfile(ti)
            else:
                tf.addfile(ti, io.BytesIO(data))
    pkg = tmp_path / f"{pfb_pkg.CANONICAL_EMITTED_IDENTITY}-2.8.0.pkg"
    pkg.write_bytes(
        lzma.compress(raw.getvalue())
        if compression == "xz"
        else (_zstd_frame(raw.getvalue()) if compression == "zstd" else raw.getvalue())
    )
    return pkg, record, full_obj


@pytest.mark.parametrize("compression", ["zstd", "xz", "plain"])
def test_inspect_and_validate_project_pkg_full_cascade(tmp_path: Path, compression: str) -> None:
    pkg, record, full = _synthetic_pkg(tmp_path, compression=compression)
    evidence = pfb_pkg.inspect_pkg(pkg)
    assert evidence["manifest"] == full
    assert pfb_pkg.validate_project_pkg(pkg, record, expected_manifest=full)["record"] == record


@pytest.mark.parametrize(
    "native_path",
    [
        "/usr/local/share/pfSense-pkg-pfBlockerNG-testing/rogue",
        "/usr/local/pkg/pfSense-pkg-pfBlockerNG-testing/rogue",
        "/usr/local/pkg/rogue-pfSense-pkg-pfBlockerNG-testing/file",
    ],
)
def test_validate_project_pkg_rejects_native_identity_in_payload_path(tmp_path: Path, native_path: str) -> None:
    payload = {
        "/usr/local/share/pfSense-pkg-pfBlockerNG/info.xml": (
            b"<pfsensepkgs><package><name>pfBlockerNG</name><version>2.8.0</version></package></pfsensepkgs>"
        ),
        native_path: b"native payload",
        "/usr/local/pkg/pfblockerng/pfb_stub.py": b"print('ok')\n",
    }
    pkg, record, _ = _synthetic_pkg(tmp_path, payload=payload, compression="plain")
    with pytest.raises(pfb_pkg.PkgError, match="native identity"):
        pfb_pkg.validate_project_pkg(pkg, record)


@pytest.mark.parametrize(
    ("dependency_name", "dependency_origin"),
    [
        ("pfSense-pkg-pfBlockerNG-testing", "net/harmless"),
        ("harmless", "net/pfSense-pkg-pfBlockerNG-testing"),
    ],
)
def test_validate_project_pkg_rejects_native_identity_in_dependency(
    tmp_path: Path, dependency_name: str, dependency_origin: str
) -> None:
    pkg, record, baseline = _synthetic_pkg(tmp_path, compression="plain")
    compact = json.loads(json.dumps(baseline))
    compact.pop("files", None)
    compact.pop("scripts", None)
    full = json.loads(json.dumps(baseline))
    dependency = {"origin": dependency_origin, "version": "1"}
    compact["deps"][dependency_name] = dependency
    full["deps"][dependency_name] = dependency
    pkg, _, _ = _synthetic_pkg(tmp_path, record, compression="plain", compact=compact, full=full)
    with pytest.raises(pfb_pkg.PkgError, match="native identity"):
        pfb_pkg.validate_project_pkg(pkg, record)


def test_inspect_pkg_decodes_archive_once_and_returns_only_used_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pkg, _, _ = _synthetic_pkg(tmp_path, compression="zstd")
    calls = 0
    real_decompress = pfb_pkg.zstd_decompress

    def count_decompress(data: bytes) -> bytes:
        nonlocal calls
        calls += 1
        return real_decompress(data)

    monkeypatch.setattr(pfb_pkg, "zstd_decompress", count_decompress)
    evidence = pfb_pkg.inspect_pkg(pkg)
    assert calls == 1
    assert set(evidence) == {"path", "members", "compact_manifest", "manifest", "payload", "member_info"}


@pytest.mark.parametrize(
    ("mutate", "error"),
    [
        (
            lambda c, f, p: (
                c.update(name="pfSense-pkg-pfBlockerNG-testing"),
                f.update(name="pfSense-pkg-pfBlockerNG-testing"),
            ),
            "canonical package identity/origin mismatch",
        ),
        (
            lambda c, f, p: (c.update(origin="evil/origin"), f.update(origin="evil/origin")),
            "canonical package identity/origin mismatch",
        ),
        (
            lambda c, f, p: (c.update(version="9.9.9"), f.update(version="9.9.9")),
            "package version mismatch",
        ),
        (
            lambda c, f, p: (c.update(abi="FreeBSD:16:*"), f.update(abi="FreeBSD:16:*")),
            "ABI/arch mismatch",
        ),
        (
            lambda c, f, p: (c.update(arch="freebsd:16:*"), f.update(arch="freebsd:16:*")),
            "ABI/arch mismatch",
        ),
        (
            lambda c, f, p: (
                c["annotations"].update({pfb_pkg.PFB_BUILD_RECORD_KEY: "{}"}),
                f["annotations"].update({pfb_pkg.PFB_BUILD_RECORD_KEY: "{}"}),
            ),
            "annotation mismatch",
        ),
        (
            lambda c, f, p: (
                c["annotations"].update(channel_alias="pfSense-pkg-pfBlockerNG-testing"),
                f["annotations"].update(channel_alias="pfSense-pkg-pfBlockerNG-testing"),
            ),
            "native identity.*annotation",
        ),
        (
            lambda c, f, p: (
                c["annotations"].update({"pfSense-pkg-pfBlockerNG-testing": "legacy"}),
                f["annotations"].update({"pfSense-pkg-pfBlockerNG-testing": "legacy"}),
            ),
            "native identity.*annotation",
        ),
        (
            lambda c, f, p: p.update({"/usr/local/pkg/new": b"x"}),
            "payload inventory differs",
        ),
        (
            lambda c, f, p: f["scripts"].update(
                install="#!/bin/sh\n/usr/local/bin/php -f /etc/rc.packages pfSense-pkg-pfBlockerNG-testing ${2}\n"
            ),
            "suffixed native identity",
        ),
        (
            lambda c, f, p: f["scripts"].update({"pre-install": "#!/bin/sh\necho pfSense-pkg-pfBlockerNG-testing\n"}),
            "unexpected lifecycle scripts",
        ),
        (
            lambda c, f, p: (
                c["deps"].update({"python312": {"origin": "lang/python312", "version": "0"}}),
                f["deps"].update({"python312": {"origin": "lang/python312", "version": "0"}}),
            ),
            "Python dependency flavor mismatch",
        ),
        (
            lambda c, f, p: f["files"][next(iter(f["files"]))].update(sum="1$" + "0" * 64),
            "checksum mismatch",
        ),
        (
            lambda c, f, p: f["files"][next(iter(f["files"]))].update(perm="0755"),
            "mode/mtime mismatch",
        ),
        (
            lambda c, f, p: f["files"][next(iter(f["files"]))].update(mtime=1),
            "mode/mtime mismatch",
        ),
        (
            lambda c, f, p: p.update({next(iter(p)): b"tampered"}),
            "checksum mismatch",
        ),
    ],
)
def test_validate_project_pkg_tamper_rows(tmp_path: Path, mutate: Callable[..., object], error: str) -> None:
    record = _record()
    payload = {
        "/usr/local/share/pfSense-pkg-pfBlockerNG/info.xml": (
            b"<pfsensepkgs><package><name>pfBlockerNG</name><version>2.8.0</version></package></pfsensepkgs>"
        ),
        "/usr/local/pkg/pfblockerng/pfb_stub.py": b"print('ok')\n",
    }
    _, _, baseline = _synthetic_pkg(tmp_path, record, compression="plain", payload=payload)
    compact = {k: v for k, v in baseline.items() if k not in ("files", "scripts")}
    full = json.loads(json.dumps(baseline))
    mutate(compact, full, payload)
    pkg, _, _ = _synthetic_pkg(tmp_path, record, compression="plain", compact=compact, full=full, payload=payload)
    with pytest.raises(pfb_pkg.PkgError, match=error):
        pfb_pkg.validate_project_pkg(pkg, record)


@pytest.mark.parametrize("bad_member", ["+MANIFEST", "../escape", "/tmp/../extra"])
def test_inspect_pkg_rejects_duplicate_or_unsafe_members(tmp_path: Path, bad_member: str) -> None:
    record = _record()
    pkg, _, _ = _synthetic_pkg(tmp_path, record, compression="plain", members=[(bad_member, b"x", 0o644, 0, True)])
    with pytest.raises(pfb_pkg.PkgError):
        pfb_pkg.inspect_pkg(pkg)


@pytest.mark.parametrize(
    ("payload_path", "canonical"),
    [
        ("/usr/local//pkg/x", False),
        ("/usr/local/pkg/x/", False),
        ("/", False),
        ("/usr/local/pkg/x", True),
    ],
)
def test_inspect_pkg_requires_canonical_absolute_payload_paths(
    tmp_path: Path, payload_path: str, canonical: bool
) -> None:
    pkg, _, _ = _synthetic_pkg(
        tmp_path,
        compression="plain",
        members=[(payload_path, b"x", 0o644, 0, True)],
    )
    if canonical:
        assert pfb_pkg.inspect_pkg(pkg)["payload"] == {payload_path: b"x"}
    else:
        with pytest.raises(pfb_pkg.PkgError, match="unsafe archive member"):
            pfb_pkg.inspect_pkg(pkg)


def test_inspect_pkg_rejects_nonregular_payload(tmp_path: Path) -> None:
    record = _record()
    pkg, _, _ = _synthetic_pkg(
        tmp_path, record, compression="plain", members=[("/usr/local/pkg/link", b"", 0o777, 0, False)]
    )
    with pytest.raises(pfb_pkg.PkgError):
        pfb_pkg.inspect_pkg(pkg)


def test_validate_project_pkg_expected_manifest_mismatch(tmp_path: Path) -> None:
    pkg, record, full = _synthetic_pkg(tmp_path)
    wrong = dict(full, version="2.8.1")
    with pytest.raises(pfb_pkg.PkgError):
        pfb_pkg.validate_project_pkg(pkg, record, expected_manifest=wrong)


def test_validate_project_pkg_binds_payload_mtime_to_record_epoch(tmp_path: Path) -> None:
    """Project provenance is incomplete when payload mtimes ignore source_date_epoch."""
    record = _record(source_date_epoch=1)
    pkg, _, _ = _synthetic_pkg(tmp_path, record)

    with pytest.raises(pfb_pkg.PkgError, match="source_date_epoch"):
        pfb_pkg.validate_project_pkg(pkg, record)


def _zstd_frame(data: bytes) -> bytes:
    """Compress with whatever zstd encoder is available (mirrors the decoder fallback)."""
    try:
        import zstandard

        return zstandard.ZstdCompressor().compress(data)
    except ImportError:
        zstd = shutil.which("zstd")
        # CI/dev always ships one encoder; the assert both guards and narrows
        # str|None -> str for the type checker (pytest.skip isn't NoReturn under CI mypy).
        assert zstd, "no zstd encoder (binary or module) available to build the fixture"
        return subprocess.run([zstd, "-q", "-c"], input=data, stdout=subprocess.PIPE, check=True).stdout


def _tar_with(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, payload in members.items():
            ti = tarfile.TarInfo(name=name)
            ti.size = len(payload)
            tf.addfile(ti, io.BytesIO(payload))
    return buf.getvalue()


def test_zstd_decompress_roundtrip() -> None:
    """A real zstd frame decompresses back to the original bytes."""
    original = b"the quick brown fox " * 50
    assert pfb_pkg.zstd_decompress(_zstd_frame(original)) == original


def test_zstd_decompress_passes_through_non_zstd() -> None:
    """Non-zstd input is returned verbatim (an already-uncompressed tar — defensive)."""
    plain = b"not a zstd frame"
    assert pfb_pkg.zstd_decompress(plain) == plain


def test_zstd_decompress_errors_when_no_decoder(monkeypatch: pytest.MonkeyPatch) -> None:
    """With neither the zstandard module nor the zstd binary, a clear PkgError naming both
    remedies — not a bare ImportError/OSError. Build the fixture while an encoder exists,
    then remove BOTH decoders."""
    frame = _zstd_frame(b"payload")
    real_import = builtins.__import__

    def _no_zstandard(name: str, *a: object, **k: object) -> object:
        if name == "zstandard":
            raise ImportError("forced: zstandard unavailable")
        return real_import(name, *a, **k)  # type: ignore[arg-type]

    monkeypatch.setattr(builtins, "__import__", _no_zstandard)
    monkeypatch.setattr(pfb_pkg.shutil, "which", lambda _name: None)
    with pytest.raises(pfb_pkg.PkgError, match="zstd"):
        pfb_pkg.zstd_decompress(frame)


def test_zstd_decompress_wraps_a_module_decoder_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """A decoder failure raised by the `zstandard` module becomes PkgError, exactly as the
    `zstd` binary path's does. Callers that convert read failures into a verdict — the
    signature-only comparison of issue #2675 is one — would otherwise behave differently
    depending on which of the two decoders the runner happens to have installed."""
    frame = _zstd_frame(b"payload")

    class _ZstdError(Exception):
        pass

    class _FakeZstandard:
        ZstdError = _ZstdError

        class ZstdDecompressor:
            def stream_reader(self, _fileobj: object) -> object:
                raise _ZstdError("zstd decompress error: Restored data doesn't match checksum")

    real_import = builtins.__import__

    def _fake_zstandard(name: str, *a: object, **k: object) -> object:
        if name == "zstandard":
            return _FakeZstandard
        return real_import(name, *a, **k)  # type: ignore[arg-type]

    monkeypatch.setattr(builtins, "__import__", _fake_zstandard)
    # The injected text, not just "zstd": the no-decoder message carries that word too,
    # so a code path that swallowed the module's error and fell through to a missing
    # binary would satisfy a looser pattern without normalising anything.
    with pytest.raises(pfb_pkg.PkgError, match=r"zstd decompression failed: .*Restored data"):
        pfb_pkg.zstd_decompress(frame)


def test_read_compact_manifest_roundtrip(tmp_path: Path) -> None:
    """The +COMPACT_MANIFEST (first tar member) is returned as a dict."""
    man = {"name": "pfSense-pkg-pfBlockerNG-devel", "version": "9.9.9", "abi": "FreeBSD:16:amd64"}
    pkg = tmp_path / "x.pkg"
    pkg.write_bytes(_zstd_frame(_tar_with({"+COMPACT_MANIFEST": json.dumps(man).encode()})))
    assert pfb_pkg.read_compact_manifest(pkg) == man


def test_read_compact_manifest_missing_member(tmp_path: Path) -> None:
    """A .pkg without a +COMPACT_MANIFEST member is a clear PkgError, not a KeyError."""
    pkg = tmp_path / "x.pkg"
    pkg.write_bytes(_zstd_frame(_tar_with({"other": b"x"})))
    with pytest.raises(pfb_pkg.PkgError, match="COMPACT_MANIFEST"):
        pfb_pkg.read_compact_manifest(pkg)


def test_read_compact_manifest_invalid_json(tmp_path: Path) -> None:
    """A non-JSON manifest is a clear PkgError, not a bare ValueError."""
    pkg = tmp_path / "x.pkg"
    pkg.write_bytes(_zstd_frame(_tar_with({"+COMPACT_MANIFEST": b"{not json"})))
    with pytest.raises(pfb_pkg.PkgError, match="JSON"):
        pfb_pkg.read_compact_manifest(pkg)


def test_read_compact_manifest_non_object(tmp_path: Path) -> None:
    """Valid JSON that is not an object (e.g. a list) is a clear PkgError."""
    pkg = tmp_path / "x.pkg"
    pkg.write_bytes(_zstd_frame(_tar_with({"+COMPACT_MANIFEST": b"[1, 2, 3]"})))
    with pytest.raises(pfb_pkg.PkgError, match="not an object"):
        pfb_pkg.read_compact_manifest(pkg)


def test_read_compact_manifest_malformed_xz_is_pkg_error(tmp_path: Path) -> None:
    pkg = tmp_path / "broken.pkg"
    pkg.write_bytes(pfb_pkg.XZ_MAGIC + b"not-an-xz-stream")
    with pytest.raises(pfb_pkg.PkgError, match="invalid package archive"):
        pfb_pkg.read_compact_manifest(pkg)
