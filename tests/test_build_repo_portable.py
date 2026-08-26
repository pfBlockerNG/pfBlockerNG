"""Tests for scripts/build-repo-portable.py — the pure-Python pkg catalog generator (ADR-17 Phase 3a).

The generator turns a dir of `.pkg` files into a per-ABI FreeBSD `pkg` repository
tree (meta.conf + packagesite.pkg + data.pkg + the .pkg) WITHOUT libpkg, so a real
pfSense `pkg update`/`pkg install` accepts it. These tests pin the FORMAT against
facts captured from real `pkg repo` output (ADR-17 RESULTS/03a) — they do not
merely run the code:

  * the catalog descriptor (meta.conf, and its identical `meta` copy) is byte-exact;
  * the `sum` field is libpkg checksum type 2 = `2$` + z-base-32(blake2b(file)),
    anchored to a GOLDEN (.pkg-bytes -> sum) vector emitted by the REAL `pkg repo`
    binary (so the algorithm matches libpkg, not just itself);
  * packagesite.yaml is newline-delimited JSON, one object per package, = the
    pkg's +COMPACT_MANIFEST with sum/flatsize/path/repopath/pkgsize spliced in at
    libpkg's field positions (order asserted);
  * data.pkg wraps a single JSON object {groups, expired_packages, packages} with
    NO trailing newline;
  * per-ABI bucketing, determinism (two runs byte-identical), and the
    flavor-collision guard (fail-loud) — each branch asserted.

All fixtures are SYNTHETIC and authored here (a made-up package built in pure
Python), except the single golden sum vector — a tiny package built by the real
`pkg create`/`pkg repo` from a made-up manifest (this repo's own synthetic
artifact; no FreeBSD source vendored). No network, no FreeBSD host, no `pkg` binary.

The tool is a hyphen-named CLI script, so it is loaded by path via importlib.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path
from typing import Any

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

# --------------------------------------------------------------------------- #
# Load the hyphen-named tool as a module.
# --------------------------------------------------------------------------- #

_TOOL = Path(__file__).resolve().parent.parent / "scripts" / "build-repo-portable.py"
_spec = importlib.util.spec_from_file_location("build_repo_portable", _TOOL)
assert _spec is not None and _spec.loader is not None
brp = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = brp
_spec.loader.exec_module(brp)


# --------------------------------------------------------------------------- #
# A synthetic .pkg writer (pure Python; mirrors libpkg framing) — so the tests
# vendor no real packages. A .pkg is a zstd tar with +COMPACT_MANIFEST first.
# --------------------------------------------------------------------------- #


def make_pkg(
    path: Path,
    *,
    name: str = "demo",
    version: str = "1.0_1",
    abi: str = "FreeBSD:15:*",
    deps: dict[str, dict[str, str]] | None = None,
    extra: dict[str, Any] | None = None,
    payload: bytes = b"hey",
) -> dict:
    """Write a minimal but libpkg-shaped .pkg to ``path``; return its compact manifest."""
    # Key order mirrors a real +COMPACT_MANIFEST: ...licenselogic, desc, deps,
    # categories. The generator preserves the input manifest's order (libpkg's
    # native order), so the fixture must use it for the order assertion to be real.
    manifest: dict[str, Any] = {
        "name": name,
        "origin": f"net/{name}",
        "version": version,
        "comment": "demo package",
        "maintainer": "dev@example.com",
        "www": "https://example.com",
        "abi": abi,
        "arch": "freebsd:15:x86:64",
        "prefix": "/usr/local",
        "flatsize": 3,
        "licenselogic": "single",
        "desc": "demo",
    }
    if deps:
        manifest["deps"] = deps
    manifest["categories"] = ["net"]
    if extra:
        manifest.update(extra)
    compact = json.dumps(manifest, separators=(",", ":")).encode() + b"\n"

    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        ti = tarfile.TarInfo(name="+COMPACT_MANIFEST")
        ti.size = len(compact)
        ti.mode = 0o644
        tf.addfile(ti, io.BytesIO(compact))
        tf2 = tarfile.TarInfo(name="/usr/local/bin/demo")
        tf2.size = len(payload)
        tf2.mode = 0o555
        tf.addfile(tf2, io.BytesIO(payload))

    path.write_bytes(brp.zstd_compress(raw.getvalue(), brp.BuildRepoError, "zstd unavailable"))
    return manifest


def _read_member(zstd_tar: Path, member: str) -> bytes:
    import pfb_pkg

    data = pfb_pkg.zstd_decompress(zstd_tar.read_bytes())
    with tarfile.open(fileobj=io.BytesIO(data)) as tf:
        f = tf.extractfile(member)
        assert f is not None
        return f.read()


# --------------------------------------------------------------------------- #
# Golden sum vector — anchors the checksum algorithm to REAL `pkg repo` output.
#
# This tiny .pkg (built by the real `pkg create` from a synthetic manifest) and
# its catalog `sum` (emitted by the real `pkg repo`) pin that build-repo-portable's
# pkg_checksum reproduces libpkg's checksum type 2 EXACTLY — not merely a
# self-consistent hash. If libpkg's algorithm ever changed, this fails.
# --------------------------------------------------------------------------- #

_GOLDEN_PKG_B64 = (
    "KLUv/QRoNREA9pxcIfDUPOhS5WqLHaV/3qBKLFU2tEy1GhRsBj8AeDKR3UWWGFMAUABTAHakOv9O"
    "9fC1Fm/V0EMVMd//qS7HOsQeLkwPHA2fr93i5OZrG87RlP+/cuqiuCmdtu2cnCg1XdplVUpRysow"
    "6roySul0sTwgkclCork0FhUJpUEIIeaTmxd7Yn4e/sV5FrbKzRdh3m3mZHvFXG1OVpObIMz5PXLZ"
    "Bur4hvPdfWWdthxWOYeF8b8heGOriuNj719ZlofPo7agV0xu7u8htvo9C94cXeJOZ4Vuz7ztCseL"
    "c9Uv25R6Wy8r683ErQxVDIIDxOSmJrmY839ViDfVZ2xVC0FrrYSplJkYbvL3vttSadaDVXmhzbVa"
    "ofj10DhH3OQjiX+XvQD8UeJ3H/DxgCCztEurGa0IrFIIxFQqlTBLy7aMbprGHcMwqvd75CzM8I67"
    "76t2HKyfB7Q9Vu/oBOgRdS231tFCECjaru43B+Gvu3hDaiFL2mprKEkggGYER6sHM+jiB7XNp/z+"
    "BTwGKgkAaOAYhAp4bBZ+wKBgaGmAlutf6g7qXsnAWCEA3y6QnRwioQTwCchg3AAXApK0AW+CcQSA"
    "aleEd/QGSAr7F7kJTgSqW30ByIDhYWA2PMBdlOMVgIjqnhixoVfWm4HgXs4agdsAAwQLYPwy5wVm"
    "MAA6cJ4C/QPaYOAfF6YG/QfFOXQGIEGASUUBOARsFww/IPlAZUOBYUEAxqMgDH9Rop0="
)
_GOLDEN_SUM = (
    "2$km8wbgp6pmfiaoywsfk3dzx9mhuok6ipj1nkfh9d48fsgy6y67c3yw8zofub9r5g99gy1d46oq8bonwtqzjcu69mzjcic6mncj68w9y"
)


def test_pkg_checksum_matches_real_pkg_repo_golden() -> None:
    """pkg_checksum reproduces libpkg's catalog `sum` (type 2) for a real-pkg vector.

    The expected value was emitted by the real `pkg repo` over this exact .pkg, so
    a green here proves the blake2b + z-base-32(LSB) chain matches libpkg byte-for-byte.
    """
    pkg_bytes = base64.b64decode(_GOLDEN_PKG_B64)
    assert brp.pkg_checksum(pkg_bytes) == _GOLDEN_SUM


def test_pkg_checksum_is_blake2b_zbase32() -> None:
    """The sum is `2$` + 103-char z-base-32 of a 64-byte blake2b digest (independent recompute)."""
    data = b"the quick brown fox"
    got = brp.pkg_checksum(data)
    assert got.startswith("2$")
    body = got[2:]
    assert len(body) == 103  # ceil(64 bytes * 8 / 5)
    assert set(body) <= set(brp._ZBASE32)
    # Independent reference: z-base-32 over blake2b, 5-bit groups packed LSB-first
    # within each byte (libpkg's pkg_checksum_encode_base32).
    digest = hashlib.blake2b(data).digest()
    ref: list[str] = []
    total_bits = len(digest) * 8
    for i in range(0, total_bits, 5):
        v = 0
        for k in range(5):
            bi = i + k
            if bi < total_bits:
                v |= ((digest[bi // 8] >> (bi % 8)) & 1) << k
        ref.append(brp._ZBASE32[v])
    assert body == "".join(ref)


# --------------------------------------------------------------------------- #
# meta.conf / meta — the catalog descriptor
# --------------------------------------------------------------------------- #


def test_meta_conf_is_byte_exact(tmp_path: Path) -> None:
    """meta.conf matches real `pkg repo` exactly, and `meta` is an identical copy."""
    in_dir = tmp_path / "in"
    in_dir.mkdir()
    make_pkg(in_dir / "demo-1.0_1.pkg")
    out = tmp_path / "out"
    brp.build_repo(in_dir, out)
    bucket = out  # arch-less (issue #1806/#1786): catalog lands directly at out_dir
    expected = (
        "version = 2;\n"
        'packing_format = "tzst";\n'
        'manifests = "packagesite.yaml";\n'
        'data = "data";\n'
        'filesite = "files";\n'
        'manifests_archive = "packagesite";\n'
        'filesite_archive = "files";\n'
    )
    assert (bucket / "meta.conf").read_text() == expected
    assert (bucket / "meta").read_text() == expected


def test_published_pkg_preserves_source_mtime(tmp_path: Path) -> None:
    """The published .pkg keeps the SOURCE artifact's mtime (its real build time).

    A cache-restored nightly must keep its original datetime instead of jumping to
    the catalog-regeneration run. Set a fixed past mtime on the input and assert it
    rides through to the published copy.
    """
    in_dir = tmp_path / "in"
    in_dir.mkdir()
    src = in_dir / "demo-1.0_1.pkg"
    make_pkg(src)
    build_mtime = 1700000000  # 2023-11-14, clearly before "now"
    os.utime(src, (build_mtime, build_mtime))

    out = tmp_path / "out"
    brp.build_repo(in_dir, out)

    dest = out / "demo-1.0_1.pkg"  # arch-less (issue #1806/#1786): no ABI subdir
    assert dest.is_file()
    assert int(dest.stat().st_mtime) == build_mtime


# --------------------------------------------------------------------------- #
# packagesite.yaml — field set + ORDER + injected repo fields
# --------------------------------------------------------------------------- #


def test_packagesite_object_order_and_injected_fields(tmp_path: Path) -> None:
    """packagesite.yaml = compact manifest + sum/path/repopath/pkgsize at libpkg positions.

    Pins the EXACT key order real `pkg repo` emits: ...prefix, sum, flatsize, path,
    repopath, licenselogic, pkgsize, desc... so the catalog is faithful + diffable.
    """
    in_dir = tmp_path / "in"
    in_dir.mkdir()
    pkg = in_dir / "demo-1.0_1.pkg"
    make_pkg(pkg, deps={"python311": {"origin": "lang/python311", "version": "3.11.0"}})
    out = tmp_path / "out"
    brp.build_repo(in_dir, out)

    raw = _read_member(out / "packagesite.pkg", "packagesite.yaml")  # arch-less: flat at out_dir
    assert raw.endswith(b"\n"), "packagesite.yaml is newline-delimited JSON"
    lines = [ln for ln in raw.decode().splitlines() if ln]
    assert len(lines) == 1
    obj = json.loads(lines[0])

    # Injected repo fields, with the correct values.
    pkg_bytes = pkg.read_bytes()
    assert obj["sum"] == brp.pkg_checksum(pkg_bytes)
    assert obj["path"] == "demo-1.0_1.pkg"
    assert obj["repopath"] == "demo-1.0_1.pkg"
    assert obj["pkgsize"] == len(pkg_bytes)
    assert obj["flatsize"] == 3  # from the manifest, carried through

    # Exact key order (the libpkg splice).
    keys = list(obj.keys())
    assert keys == [
        "name",
        "origin",
        "version",
        "comment",
        "maintainer",
        "www",
        "abi",
        "arch",
        "prefix",
        "sum",
        "flatsize",
        "path",
        "repopath",
        "licenselogic",
        "pkgsize",
        "desc",
        "deps",
        "categories",
    ]


def test_packagesite_is_compact_json_no_spaces(tmp_path: Path) -> None:
    """libpkg emits compact JSON (no separator spaces); reproduce that."""
    in_dir = tmp_path / "in"
    in_dir.mkdir()
    make_pkg(in_dir / "demo-1.0_1.pkg")
    out = tmp_path / "out"
    brp.build_repo(in_dir, out)
    raw = _read_member(out / "packagesite.pkg", "packagesite.yaml").decode()
    assert '", "' not in raw and '": "' not in raw  # no ", " / ": " separators


# --------------------------------------------------------------------------- #
# data.pkg — the data blob shape
# --------------------------------------------------------------------------- #


def test_data_blob_shape_and_no_trailing_newline(tmp_path: Path) -> None:
    """data = {groups:[], expired_packages:[], packages:[<objs>]} with NO trailing newline."""
    in_dir = tmp_path / "in"
    in_dir.mkdir()
    make_pkg(in_dir / "demo-1.0_1.pkg")
    out = tmp_path / "out"
    brp.build_repo(in_dir, out)
    raw = _read_member(out / "data.pkg", "data")  # arch-less: flat at out_dir
    assert not raw.endswith(b"\n"), "data has no trailing newline (matches real pkg repo)"
    obj = json.loads(raw)
    assert obj["groups"] == []
    assert obj["expired_packages"] == []
    assert len(obj["packages"]) == 1
    # The package object equals the packagesite object.
    psite = json.loads(_read_member(out / "packagesite.pkg", "packagesite.yaml").decode())
    assert obj["packages"][0] == psite


# --------------------------------------------------------------------------- #
# Arch-less catalog contract (issue #1786): plain build_repo() is now NO_ARCH-only
# and flat — every real pfBlockerNG .pkg carries a wildcard ABI (issue #1806), so
# there is no per-ABI subdirectory to bucket into; a concrete ABI or a mixed-major
# run is a hard error, mirroring build-repo.sh's require_noarch_abi + "mixed ABIs
# in one run" guards.
# --------------------------------------------------------------------------- #


def test_layout_and_verbatim_pkg_copy(tmp_path: Path) -> None:
    """A NO_ARCH (wildcard-ABI) pkg emits the catalog DIRECTLY at out_dir — no
    per-ABI subdirectory — holding the .pkg (byte-verbatim) + the catalog triple
    + meta."""
    in_dir = tmp_path / "in"
    in_dir.mkdir()
    pkg = in_dir / "demo-1.0_1.pkg"
    original = make_pkg(pkg, abi="FreeBSD:15:*")
    del original
    out = tmp_path / "out"
    abis = brp.build_repo(in_dir, out)
    assert abis == ["FreeBSD:15:*"]
    for fname in ("meta.conf", "meta", "packagesite.pkg", "data.pkg", "demo-1.0_1.pkg"):
        assert (out / fname).is_file(), f"missing {fname}"
    # The .pkg is copied verbatim (no re-archiving).
    assert (out / "demo-1.0_1.pkg").read_bytes() == pkg.read_bytes()
    # No per-ABI subdirectory of any shape is created.
    assert not (out / "FreeBSD:15:amd64").exists()
    assert not (out / "FreeBSD:15:*").exists()


def test_catalog_name_places_flat_catalog_under_out_dir(tmp_path: Path) -> None:
    """catalog_name="release/ce-2.8" writes the flat catalog at out_dir/release/ce-2.8/
    — still no ABI subdir beneath it."""
    in_dir = tmp_path / "in"
    in_dir.mkdir()
    make_pkg(in_dir / "demo-1.0_1.pkg", abi="FreeBSD:15:*")
    out = tmp_path / "out"
    brp.build_repo(in_dir, out, catalog_name="release/ce-2.8")
    bucket = out / "release" / "ce-2.8"
    for fname in ("meta.conf", "meta", "packagesite.pkg", "data.pkg", "demo-1.0_1.pkg"):
        assert (bucket / fname).is_file(), f"missing {fname}"
    assert not (bucket / "FreeBSD:15:amd64").exists()
    assert not (bucket / "FreeBSD:15:*").exists()


@pytest.mark.parametrize("kind", ["traversal", "absolute", "empty-segment", "bare-dotdot"])
def test_catalog_name_rejects_unsafe_paths(tmp_path: Path, kind: str) -> None:
    """An unsafe ``--catalog-name`` is rejected BEFORE it becomes ``out_dir / catalog_name``
    (issue #1786): ``_write_catalog_dir`` ``shutil.rmtree()``s that path, so an unvalidated
    segment lets a caller wipe an arbitrary directory — ``"../victim"`` escapes sideways to a
    sibling of ``out_dir``, and an ABSOLUTE value makes ``Path.__truediv__`` discard ``out_dir``
    entirely, replacing it outright. A sentinel file OUTSIDE ``out_dir`` must survive every one
    of these attempts, and every one of them must raise ``BuildRepoError`` (never silently
    proceed, even the ones that happen not to escape, like a doubled-slash empty segment)."""
    in_dir = tmp_path / "in"
    in_dir.mkdir()
    make_pkg(in_dir / "demo-1.0_1.pkg", abi="FreeBSD:15:*")
    out = tmp_path / "out"
    out.mkdir()

    # A sentinel directory the traversal/absolute/bare-".." cases must never touch.
    victim = tmp_path / "victim"
    victim.mkdir()
    sentinel = victim / "sentinel.txt"
    sentinel.write_text("do not delete me")

    bad = {
        "traversal": "../victim",
        "absolute": str(victim),
        "empty-segment": "a//b",
        "bare-dotdot": "..",
    }[kind]

    exc: Exception | None = None
    try:
        brp.build_repo(in_dir, out, catalog_name=bad)
    except Exception as e:  # capture ANY failure mode, including an unvalidated crash
        exc = e

    assert sentinel.is_file(), f"catalog_name={bad!r} ({kind}) let the catalog write escape out_dir"
    assert isinstance(exc, brp.BuildRepoError) and "unsafe" in str(exc).lower(), (
        f"catalog_name={bad!r} ({kind}) must be rejected with a clear BuildRepoError; got {exc!r}"
    )


def test_catalog_name_with_channel_prefix_still_works(tmp_path: Path) -> None:
    """A legitimate channel-prefixed catalog_name ("release/ce-2.8") still works — the
    traversal guard must allow '/' BETWEEN segments (issue #1786), never just a bare varver."""
    in_dir = tmp_path / "in"
    in_dir.mkdir()
    make_pkg(in_dir / "demo-1.0_1.pkg", abi="FreeBSD:15:*")
    out = tmp_path / "out"
    brp.build_repo(in_dir, out, catalog_name="release/ce-2.8")
    assert (out / "release" / "ce-2.8" / "meta.conf").is_file()


def test_concrete_abi_pkg_is_rejected(tmp_path: Path) -> None:
    """A CONCRETE-ABI package (not NO_ARCH) is rejected — the catalog is
    arch-less/NO_ARCH-only since issue #1806; a concrete-ABI .pkg would silently
    install on only one arch."""
    in_dir = tmp_path / "in"
    in_dir.mkdir()
    make_pkg(in_dir / "demo-1.0_1.pkg", abi="FreeBSD:15:amd64")
    out = tmp_path / "out"
    with pytest.raises(brp.BuildRepoError, match="NO_ARCH"):
        brp.build_repo(in_dir, out)


def test_mixed_majors_in_one_run_are_rejected(tmp_path: Path) -> None:
    """Two wildcard-ABI pkgs of DIFFERENT FreeBSD majors in one build_repo() call
    is a hard error (mirrors build-repo.sh's "mixed ABIs in one run" guard): the
    caller must filter the input to one major and invoke once per major."""
    in_dir = tmp_path / "in"
    in_dir.mkdir()
    make_pkg(in_dir / "a15.pkg", name="a", abi="FreeBSD:15:*")
    make_pkg(in_dir / "b16.pkg", name="b", abi="FreeBSD:16:*")
    out = tmp_path / "out"
    with pytest.raises(brp.BuildRepoError, match="mixed"):
        brp.build_repo(in_dir, out)


def test_duplicate_sources_dedup_to_one_canonical(tmp_path: Path) -> None:
    """The SAME package staged from two sources (the publish job's `built-<source>-`
    prefixed copies of the branch build + a release artifact) publishes exactly ONE
    canonical `.pkg` + ONE catalog entry — not two prefixed duplicates (the bug the
    first live deploy surfaced) — flat at out_dir (arch-less, issue #1806/#1786)."""
    in_dir = tmp_path / "in"
    in_dir.mkdir()
    # Same name+version+ABI+flavor; different staging input filenames.
    make_pkg(in_dir / "built-incoming_branch-pfb.pkg", name="pfb", version="3.2.16", abi="FreeBSD:15:*")
    make_pkg(in_dir / "built-incoming_release-freebsd-pfb.pkg", name="pfb", version="3.2.16", abi="FreeBSD:15:*")
    out = tmp_path / "out"
    brp.build_repo(in_dir, out)
    # Exactly one package .pkg on disk, canonically named (no `built-incoming_*`
    # prefix); the catalog files (packagesite.pkg/data.pkg) also end in `.pkg`.
    catalog_files = {"packagesite.pkg", "data.pkg", "meta.pkg"}
    pkgs = sorted(p.name for p in out.glob("*.pkg") if p.name not in catalog_files)
    assert pkgs == ["pfb-3.2.16.pkg"]
    # The catalog lists it once, at the canonical path/repopath.
    raw = _read_member(out / "packagesite.pkg", "packagesite.yaml").decode()
    objs = [json.loads(ln) for ln in raw.splitlines() if ln]
    assert len(objs) == 1
    assert objs[0]["path"] == "pfb-3.2.16.pkg"
    assert objs[0]["repopath"] == "pfb-3.2.16.pkg"


# --------------------------------------------------------------------------- #
# Determinism
# --------------------------------------------------------------------------- #


def test_deterministic_two_runs_byte_identical(tmp_path: Path) -> None:
    """Same inputs -> byte-identical tree across runs (re-runnable, no drift)."""
    in_dir = tmp_path / "in"
    in_dir.mkdir()
    make_pkg(in_dir / "demo-1.0_1.pkg")
    out1, out2 = tmp_path / "o1", tmp_path / "o2"
    brp.build_repo(in_dir, out1)
    brp.build_repo(in_dir, out2)
    for rel in ("meta.conf", "meta", "packagesite.pkg", "data.pkg", "demo-1.0_1.pkg"):
        a = (out1 / rel).read_bytes()
        b = (out2 / rel).read_bytes()
        assert a == b, f"{rel} differs between runs"


def test_rebuild_wipes_removed_pkg(tmp_path: Path) -> None:
    """A re-run after removing a .pkg drops it from the bucket (wipe-and-rebuild)."""
    in_dir = tmp_path / "in"
    in_dir.mkdir()
    make_pkg(in_dir / "a-1.0.pkg", name="a")
    make_pkg(in_dir / "b-1.0.pkg", name="b")
    out = tmp_path / "out"
    brp.build_repo(in_dir, out)
    assert (out / "b-1.0_1.pkg").is_file()  # canonical <name>-<version>, flat at out_dir
    # Remove one input and rebuild.
    (in_dir / "b-1.0.pkg").unlink()
    brp.build_repo(in_dir, out)
    assert not (out / "b-1.0_1.pkg").exists(), "stale .pkg lingered after rebuild"
    raw = _read_member(out / "packagesite.pkg", "packagesite.yaml").decode()
    assert [json.loads(ln)["name"] for ln in raw.splitlines() if ln] == ["a"]


# --------------------------------------------------------------------------- #
# Flavor-collision guard — BOTH branches (collide -> fail; same-flavor -> pass)
# --------------------------------------------------------------------------- #


def test_flavor_collision_fails_loud(tmp_path: Path) -> None:
    """Two .pkg same name+version+ABI but different php flavor -> hard error (no silent drop)."""
    in_dir = tmp_path / "in"
    in_dir.mkdir()
    make_pkg(in_dir / "x-a.pkg", name="x", version="1.0", deps={"php83": {"origin": "lang/php83", "version": "8.3"}})
    make_pkg(in_dir / "x-b.pkg", name="x", version="1.0", deps={"php84": {"origin": "lang/php84", "version": "8.4"}})
    out = tmp_path / "out"
    with pytest.raises(brp.BuildRepoError, match="FLAVOR COLLISION"):
        brp.build_repo(in_dir, out)


def test_same_flavor_duplicate_passes(tmp_path: Path) -> None:
    """Same name+version+ABI AND same flavor is a harmless duplicate -> no error."""
    in_dir = tmp_path / "in"
    in_dir.mkdir()
    deps = {"php83": {"origin": "lang/php83", "version": "8.3"}}
    make_pkg(in_dir / "x-a.pkg", name="x", version="1.0", deps=deps)
    make_pkg(in_dir / "x-b.pkg", name="x", version="1.0", deps=deps)
    out = tmp_path / "out"
    abis = brp.build_repo(in_dir, out)  # must not raise
    assert abis == ["FreeBSD:15:*"]


def test_same_flavor_payload_collision_fails_loud(tmp_path: Path) -> None:
    """Same identity and flavor with one differing payload byte is a hard collision."""
    in_dir = tmp_path / "in"
    in_dir.mkdir()
    make_pkg(in_dir / "x-a.pkg", name="x", version="1.0", payload=b"hey")
    make_pkg(in_dir / "x-b.pkg", name="x", version="1.0", payload=b"heY")
    out = tmp_path / "out"
    with pytest.raises(brp.BuildRepoError, match="PACKAGE COLLISION"):
        brp.build_repo(in_dir, out)


def test_same_flavor_annotation_collision_fails_loud(tmp_path: Path) -> None:
    """Same identity and flavor with differing annotation bytes is a hard collision."""
    in_dir = tmp_path / "in"
    in_dir.mkdir()
    make_pkg(
        in_dir / "x-a.pkg",
        name="x",
        version="1.0",
        extra={"annotation": "path;$(printf collision)"},
    )
    make_pkg(
        in_dir / "x-b.pkg",
        name="x",
        version="1.0",
        extra={"annotation": "path;$(printf different)"},
    )
    out = tmp_path / "out"
    with pytest.raises(brp.BuildRepoError, match="PACKAGE COLLISION"):
        brp.build_repo(in_dir, out)


def test_unsafe_abi_is_rejected(tmp_path: Path) -> None:
    """A traversal/odd (and, since issue #1786, any non-wildcard) ABI in manifest
    data is rejected. The ABI is no longer used as a directory name (arch-less
    catalog), but every one of these shapes still fails ``_is_wildcard_abi`` and
    is rejected by the NO_ARCH gate — the valid wildcard form (`FreeBSD:15:*`) is
    accepted by every other test, so this pins the reject side of the branch."""
    # Non-empty but unsafe/non-wildcard values (traversal / slash / space). A
    # missing/empty ABI is rejected by this SAME NO_ARCH gate (_require_wildcard_abi),
    # not by some separate upstream guard — build_repo()'s ABI loop runs before
    # _emit_catalog_from_paths ever reaches _check_collisions' missing-field check.
    out = tmp_path / "out"
    for i, bad in enumerate(("../../evil", "FreeBSD/15/amd64", "a b")):
        in_dir = tmp_path / f"in{i}"
        in_dir.mkdir()
        make_pkg(in_dir / "p.pkg", name="p", version="1.0", abi=bad)
        with pytest.raises(brp.BuildRepoError, match="NO_ARCH"):
            brp.build_repo(in_dir, out)


@pytest.mark.parametrize(
    ("abi", "expected"),
    [
        ("FreeBSD:15:*", True),
        ("FreeBSD:16:*", True),
        ("FreeBSD:15:amd64", False),  # concrete — not wildcarded at all
        ("FreeBSD:*:amd64", False),  # '*' not in the final segment
        ("*", False),  # bare '*' — not a 3-part ABI
        ("FreeBSD:15:*extra", False),  # '*' not the WHOLE final segment
        (None, False),  # non-string
        (123, False),  # non-string
    ],
)
def test_is_wildcard_abi_tight_shape(abi: object, expected: bool) -> None:
    """``_is_wildcard_abi`` accepts '*' ONLY as the whole final (CPU) segment —
    tight, per issue #1806 (a real Netgate NO_ARCH package's manifest ABI)."""
    assert brp._is_wildcard_abi(abi) is expected


def test_pkg_matches_abi_by_os_and_major_only() -> None:
    """``_pkg_matches_abi`` compares OS+major ONLY — the CPU/arch segment (concrete
    or wildcarded) never affects the match; a different major never matches."""
    # A wildcarded manifest matches any row of the same major, any arch.
    assert brp._pkg_matches_abi({"abi": "FreeBSD:15:*"}, "FreeBSD:15:amd64") is True
    assert brp._pkg_matches_abi({"abi": "FreeBSD:15:*"}, "FreeBSD:15:aarch64") is True
    # A concrete manifest also matches by major only (arch segment ignored).
    assert brp._pkg_matches_abi({"abi": "FreeBSD:15:amd64"}, "FreeBSD:15:aarch64") is True
    # A different major never matches, wildcard or not.
    assert brp._pkg_matches_abi({"abi": "FreeBSD:16:*"}, "FreeBSD:15:amd64") is False
    # A missing/non-string abi never matches.
    assert brp._pkg_matches_abi({}, "FreeBSD:15:amd64") is False


def test_flavor_signature_classifies_dep_names() -> None:
    """The flavor signature picks ONLY php*/python*/py*- dep names, sorted."""
    assert brp._flavor_signature({"deps": {}}) == ""
    assert brp._flavor_signature({"deps": {"php83": {}, "php83-intl": {}}}) == "php83,php83-intl"
    assert brp._flavor_signature({"deps": {"python311": {}}}) == "python311"
    assert brp._flavor_signature({"deps": {"py311-sqlite3": {}}}) == "py311-sqlite3"
    # Non-flavor deps (e.g. grepcidr, a bare 'python' without a version) are ignored.
    assert brp._flavor_signature({"deps": {"grepcidr": {}, "rsync": {}}}) == ""


# --------------------------------------------------------------------------- #
# Manifest reader + error paths
# --------------------------------------------------------------------------- #


def test_read_compact_manifest_roundtrip(tmp_path: Path) -> None:
    """read_compact_manifest returns the .pkg's +COMPACT_MANIFEST as a dict."""
    pkg = tmp_path / "demo-1.0_1.pkg"
    written = make_pkg(pkg, name="demo", version="2.0", abi="FreeBSD:16:amd64")
    got = brp.read_compact_manifest(pkg)
    assert got["name"] == "demo"
    assert got["version"] == "2.0"
    assert got["abi"] == "FreeBSD:16:amd64"
    assert got == written


def test_empty_input_dir_errors(tmp_path: Path) -> None:
    """An input dir with no .pkg is a hard error (fail-closed, never an empty repo)."""
    in_dir = tmp_path / "in"
    in_dir.mkdir()
    with pytest.raises(brp.BuildRepoError, match="no .pkg files"):
        brp.build_repo(in_dir, tmp_path / "out")


# --------------------------------------------------------------------------- #
# CLI surface
# --------------------------------------------------------------------------- #


def test_print_conf_matches_template(capsys: pytest.CaptureFixture[str]) -> None:
    """--print-conf emits the signed, plain-HTTP Pages URL / priority-100 client stanza.

    ADR-39: the url is fully resolved (no ${ABI} token) — supply --catalog-path to
    determine the <varver> segment (arch-less; issue #1806). The default base is the
    direct GitHub Pages URL.
    """
    rc = brp.main(["--print-conf", "--catalog-path", "ce-2.8/amd64"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "pfblockerng: {" in out  # the shared release repo (stable + testing)
    assert 'url: "http://pkg.pfblockerng.com/release/ce-2.8/amd64"' in out
    assert "${ABI}" not in out, "ADR-39: ${ABI} must not appear in the resolved conf"
    assert "signature_type: fingerprints," in out
    assert 'fingerprints: "/usr/local/etc/pkg/fingerprints/pfblockerng",' in out
    assert "priority: 100," in out
    assert "enabled: yes" in out


def test_print_conf_base_url_override(capsys: pytest.CaptureFixture[str]) -> None:
    """--base-url overrides the host; --catalog-path supplies the varver segment (arch-less)."""
    rc = brp.main(["--print-conf", "--base-url", "https://fork.example.io/p/", "--catalog-path", "ce-2.8/amd64"])
    assert rc == 0
    out = capsys.readouterr().out
    assert 'url: "https://fork.example.io/p/release/ce-2.8/amd64"' in out
    assert "${ABI}" not in out


def test_print_conf_accepts_selected_channel_root(capsys: pytest.CaptureFixture[str]) -> None:
    """A selected channel root stays exact instead of gaining the legacy release segment."""
    rc = brp.main(
        [
            "--print-conf",
            "--base-url",
            "http://pkg.pfblockerng.com/docs/edge",
            "--channel",
            "edge",
            "--catalog-path",
            "ce-2.8",
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "pfblockerng-edge: {" in out
    assert 'url: "http://pkg.pfblockerng.com/docs/edge/ce-2.8"' in out


def test_print_conf_infers_selected_channel_root(capsys: pytest.CaptureFixture[str]) -> None:
    """A trailing channel selects that channel when --channel is omitted."""
    rc = brp.main(
        [
            "--print-conf",
            "--base-url",
            "http://pkg.pfblockerng.com/docs/edge",
            "--catalog-path",
            "ce-2.8",
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "pfblockerng-edge: {" in out
    assert 'url: "http://pkg.pfblockerng.com/docs/edge/ce-2.8"' in out


def test_print_conf_does_not_treat_host_as_channel(capsys: pytest.CaptureFixture[str]) -> None:
    """A channel-named host is not a selected channel path."""
    rc = brp.main(["--print-conf", "--base-url", "https://edge", "--catalog-path", "ce-2.8"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "pfblockerng: {" in out
    assert 'url: "https://edge/release/ce-2.8"' in out


def test_cli_requires_in_and_out(capsys: pytest.CaptureFixture[str]) -> None:
    """Without --in/--out (and no --print-conf) the CLI errors."""
    with pytest.raises(SystemExit):
        brp.main([])


# --------------------------------------------------------------------------- #
# ADR-20 Phase 3: version-keyed catalog dirs + routing manifest
# --------------------------------------------------------------------------- #


def test_catalog_name_from_version() -> None:
    """catalog_name_from_version derives major.minor, prefixed by lowercased variant.

    CE and Plus both strip any trailing patch component:
      "2.8.1"  + "CE"   -> "ce-2.8"
      "2.8.x"  + "CE"   -> "ce-2.8"
      "26.03"  + "Plus" -> "plus-26.03"
      "26.03.1"+ "Plus" -> "plus-26.03"
    """
    assert brp.catalog_name_from_version("2.8.1", "CE") == "ce-2.8"
    assert brp.catalog_name_from_version("2.8.x", "CE") == "ce-2.8"
    assert brp.catalog_name_from_version("26.03", "Plus") == "plus-26.03"
    assert brp.catalog_name_from_version("26.03.1", "Plus") == "plus-26.03"


def test_catalog_name_from_version_strips_prerelease_suffix() -> None:
    """A pre-release publishes under the SAME catalog as its release line (issue #1965).

    A pfSense pre-release carries a dash suffix inside the minor field
    ("26.07-BETA", "2.9-RC1"), so a bare major.minor split keeps it. The consumer
    side — the rc.d repo-generate hook — strips the suffix before deriving the
    varver, so a box on 26.07-BETA resolves ``release/plus-26.07/``. The producer
    must strip identically, or it publishes ``release/plus-26.07-BETA/`` that no
    box ever asks for.
    """
    assert brp.catalog_name_from_version("26.07-BETA", "Plus") == "plus-26.07"
    assert brp.catalog_name_from_version("2.9-RC1", "CE") == "ce-2.9"
    assert brp.catalog_name_from_version("2.8.1-RELEASE", "CE") == "ce-2.8"
    # The channel prefix rides along unchanged.
    assert brp.catalog_name_from_version("26.07-BETA", "Plus", channel="nightly") == "nightly/plus-26.07"


def test_catalog_name_from_version_rejects_unsafe_segment() -> None:
    """The derived varver becomes an rmtree'd path segment — a hostile version is refused.

    ``pfsense_version``/``variant`` come from the ci-metadata matrix, so a bad entry
    would otherwise be joined straight onto the output root. Same safety rule as
    build-repo.sh's ``--varver`` guard: no traversal, no separator, lowercase class
    only, and never a leading '-' (an empty variant yields "-2.8").
    """
    for version, variant in (
        ("/etc", "CE"),  # separator surviving the major.minor split
        ("2.8", "../evil"),  # traversal in the variant
        ("2.8", "CE/x"),  # separator in the variant
        ("2.8", ""),  # empty variant -> a segment starting with '-'
        ("", "CE"),  # empty version -> the mirror case, a segment ending in '-'
        ("-BETA", "CE"),  # a version that is nothing BUT a pre-release suffix
    ):
        with pytest.raises(brp.BuildRepoError):
            brp.catalog_name_from_version(version, variant)

    # The channel is an argument too — it must not ride into the path unchecked.
    for channel in ("../evil", "/abs", "nightly/../.."):
        with pytest.raises(brp.BuildRepoError):
            brp.catalog_name_from_version("2.8", "CE", channel=channel)
    # ...while the legitimate channel still composes.
    assert brp.catalog_name_from_version("2.8", "CE", channel="nightly") == "nightly/ce-2.8"


def test_catalog_name_rejects_pkg_catalog_plumbing_names(tmp_path: Path) -> None:
    """A catalog name equal to a pkg(8) catalog file is refused, not a raw traceback.

    ``meta`` / ``meta.conf`` / ``data.pkg`` / ``packagesite.pkg`` are written at the
    catalog root, so ``out_dir / catalog_name`` would name an existing FILE and the
    rmtree/mkdir would escape this module's BuildRepoError contract.
    """
    in_dir = tmp_path / "in"
    in_dir.mkdir()
    make_pkg(in_dir / "ce-pkg.pkg", name="pfBlockerNG-testing", abi="FreeBSD:15:*")
    out = tmp_path / "out"
    out.mkdir()
    brp.build_repo(in_dir, out)  # lay a root-level catalog, so the names exist as FILES
    assert (out / "meta.conf").is_file()

    for reserved in ("meta", "meta.conf", "data.pkg", "packagesite.pkg"):
        with pytest.raises(brp.BuildRepoError, match="catalog plumbing"):
            brp.build_repo(in_dir, out, catalog_name=reserved)
        assert (out / reserved).is_file(), f"{reserved} must survive the rejected call"


def test_catalog_dest_symlinked_prefix_cannot_escape_out(tmp_path: Path) -> None:
    """A symlink at an INTERMEDIATE path component must not steer the write out of --out.

    The catalog name is validated as a string, so every component is a legitimate
    varver token — but the filesystem decides where that string lands. With
    ``<out>/nightly`` a symlink to a directory outside ``--out``, the whole catalog
    (which is rmtree'd and rebuilt) is written through it (issue #1972).

    Scenario: an attacker plants a symlink inside the CI output root
      Given <out>/nightly is a symlink to an outside directory holding a file
       When build_repo() is called with the legitimate name 'nightly/ce-2.8'
       Then BuildRepoError is raised
        And the outside directory keeps its file and gains no catalog.
    """
    in_dir = tmp_path / "in"
    in_dir.mkdir()
    make_pkg(in_dir / "ce-pkg.pkg", name="pfBlockerNG-testing", abi="FreeBSD:15:*")
    out = tmp_path / "out"
    out.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "precious.txt").write_text("must survive")
    (out / "nightly").symlink_to(outside, target_is_directory=True)

    with pytest.raises(brp.BuildRepoError, match="escapes"):
        brp.build_repo(in_dir, out, catalog_name="nightly/ce-2.8")

    assert (outside / "precious.txt").read_text() == "must survive"
    assert sorted(p.name for p in outside.iterdir()) == ["precious.txt"], (
        f"the write escaped --out: {sorted(p.name for p in outside.iterdir())}"
    )


def test_catalog_dest_symlinked_leaf_cannot_escape_out(tmp_path: Path) -> None:
    """The LEAF is a symlink too: rmtree refuses it, but with a raw OSError.

    ``shutil.rmtree`` declines to follow a symlinked leaf, so nothing outside is
    deleted — but the failure escapes this module's BuildRepoError contract, and the
    caller cannot tell a hostile layout from a bad input. Refuse it up front instead
    (issue #1972).
    """
    in_dir = tmp_path / "in"
    in_dir.mkdir()
    make_pkg(in_dir / "ce-pkg.pkg", name="pfBlockerNG-testing", abi="FreeBSD:15:*")
    out = tmp_path / "out"
    out.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "precious.txt").write_text("must survive")
    (out / "ce-2.8").symlink_to(outside, target_is_directory=True)

    with pytest.raises(brp.BuildRepoError, match="escapes"):
        brp.build_repo(in_dir, out, catalog_name="ce-2.8")

    assert sorted(p.name for p in outside.iterdir()) == ["precious.txt"]


def test_catalog_dest_symlinked_leaf_inside_root_is_still_refused(tmp_path: Path) -> None:
    """A symlinked leaf is refused even when it points back INSIDE the output root.

    Containment cannot decide this one — the target is legitimately inside --out — but
    the catalog directory is wiped and recreated, so it has to be a real directory this
    tool owns. ``shutil.rmtree`` declines to follow a symlink, which would otherwise
    surface as a raw OSError instead of a BuildRepoError (issue #1972).
    """
    in_dir = tmp_path / "in"
    in_dir.mkdir()
    make_pkg(in_dir / "ce-pkg.pkg", name="pfBlockerNG-testing", abi="FreeBSD:15:*")
    out = tmp_path / "out"
    out.mkdir()
    real = out / "real"
    real.mkdir()
    (real / "keep.txt").write_text("must survive")
    (out / "ce-2.8").symlink_to(real, target_is_directory=True)

    with pytest.raises(brp.BuildRepoError, match="is a symlink"):
        brp.build_repo(in_dir, out, catalog_name="ce-2.8")

    assert (real / "keep.txt").read_text() == "must survive"
    assert not list(real.glob("*.pkg")), f"the symlinked leaf was written through: {list(real.iterdir())}"


def test_catalog_dest_that_is_a_plain_file_is_refused(tmp_path: Path) -> None:
    """A catalog name naming an existing FILE is refused, not a raw traceback.

    ``_RESERVED_CATALOG_NAMES`` covers only the four pkg(8) plumbing names, but any
    regular file at the destination (a stray published .pkg, say) hits the same path:
    ``mkdir`` on it raises NotADirectoryError, escaping the BuildRepoError contract.
    """
    in_dir = tmp_path / "in"
    in_dir.mkdir()
    make_pkg(in_dir / "ce-pkg.pkg", name="pfBlockerNG-testing", abi="FreeBSD:15:*")
    out = tmp_path / "out"
    out.mkdir()
    (out / "ce-2.8").write_text("not a directory")

    with pytest.raises(brp.BuildRepoError, match="not a directory"):
        brp.build_repo(in_dir, out, catalog_name="ce-2.8")

    assert (out / "ce-2.8").read_text() == "not a directory"


def test_catalog_dest_with_a_non_directory_parent_is_refused(tmp_path: Path) -> None:
    """A plain FILE at an INTERMEDIATE component is refused, like one at the leaf.

    ``dest.exists()`` is False when an ancestor is a file (it does not raise), and
    ``resolve()`` passes straight through such a component, so a leaf-only check misses
    this — ``mkdir(parents=True)`` then raises a raw NotADirectoryError from inside the
    writer. Same contract hole as the leaf case, one path level up (issue #1972).
    """
    in_dir = tmp_path / "in"
    in_dir.mkdir()
    make_pkg(in_dir / "ce-pkg.pkg", name="pfBlockerNG-testing", abi="FreeBSD:15:*")
    out = tmp_path / "out"
    out.mkdir()
    (out / "release").write_text("not a directory")

    with pytest.raises(brp.BuildRepoError, match="not a directory"):
        brp.build_repo(in_dir, out, catalog_name="release/ce-2.8")

    assert (out / "release").read_text() == "not a directory"


def test_output_root_that_is_not_a_directory_is_refused(tmp_path: Path) -> None:
    """The output ROOT is a component too — a file there is refused, with or without a name.

    The root is where the walk stops, so it is the component most easily excluded from
    its own check. Both shapes reach it: without a catalog name the destination IS the
    root, and with one the root is its furthest ancestor (issue #1972).
    """
    in_dir = tmp_path / "in"
    in_dir.mkdir()
    make_pkg(in_dir / "ce-pkg.pkg", name="pfBlockerNG-testing", abi="FreeBSD:15:*")

    for catalog_name in (None, "release/ce-2.8"):
        out = tmp_path / f"out_{catalog_name or 'bare'}".replace("/", "_")
        out.write_text("not a directory")
        with pytest.raises(brp.BuildRepoError, match="not a directory"):
            brp.build_repo(in_dir, out, catalog_name=catalog_name)
        assert out.read_text() == "not a directory"


def test_catalog_dest_containment_allows_a_real_nested_dir(tmp_path: Path) -> None:
    """The containment guard must not refuse the layout the publisher actually writes.

    ``release/<varver>/`` and ``nightly/<varver>/`` are ordinary nested directories
    under --out; only a symlink escaping the root is hostile. Pins that the guard
    added for issue #1972 costs the legitimate case nothing.
    """
    in_dir = tmp_path / "in"
    in_dir.mkdir()
    make_pkg(in_dir / "ce-pkg.pkg", name="pfBlockerNG-testing", abi="FreeBSD:15:*")
    out = tmp_path / "out"
    out.mkdir()

    brp.build_repo(in_dir, out, catalog_name="release/ce-2.8")
    assert (out / "release" / "ce-2.8" / "meta.conf").is_file()

    # Idempotent: a rebuild over the existing (real) directory still works.
    brp.build_repo(in_dir, out, catalog_name="release/ce-2.8")
    assert (out / "release" / "ce-2.8" / "meta.conf").is_file()


def test_build_repo_rejects_unsafe_catalog_name(tmp_path: Path) -> None:
    """``--catalog-name`` is an rmtree'd path segment — traversal/absolute/foreign chars refused.

    A channel prefix ("release/ce-2.8", "nightly/ce-2.8") is legitimate, so the value
    is a relative path — but every component still has to clear the varver class.

    Scenario: a hostile or malformed --catalog-name reaches the generator
      Given a sibling directory holding a file that must survive
      When build_repo() is called with '../victim', an absolute path, or a component
        outside build-repo.sh's ``[a-z0-9.-]`` class
      Then BuildRepoError is raised BEFORE anything is written
      And the sibling directory is untouched (the rmtree never escaped --out)
      And a legitimate channel-prefixed name still builds.
    """
    in_dir = tmp_path / "in"
    in_dir.mkdir()
    make_pkg(in_dir / "ce-pkg.pkg", name="pfBlockerNG-testing", abi="FreeBSD:15:*")
    out = tmp_path / "out"
    out.mkdir()
    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / "keep.txt").write_text("must survive")

    unsafe = (
        "../victim",  # traversal: wipes a sibling of --out
        str(tmp_path / "victim"),  # absolute: Path.__truediv__ discards --out entirely
        "ce-2.8/../../victim",  # traversal after a legitimate-looking prefix
        "CE-2.8",  # outside the lowercase class build-repo.sh enforces
        "ce 2.8",  # whitespace
        "release/CE-2.8",  # a bad component behind a legitimate channel prefix
        "",  # empty: never silently "no catalog name"
    )
    for bad in unsafe:
        with pytest.raises(brp.BuildRepoError):
            brp.build_repo(in_dir, out, catalog_name=bad)

    assert (victim / "keep.txt").read_text() == "must survive"

    # The legitimate channel-prefixed form is NOT collateral damage.
    brp.build_repo(in_dir, out, catalog_name="nightly/ce-2.8")
    assert (out / "nightly" / "ce-2.8" / "meta.conf").is_file()


def test_catalog_rejects_unsafe_manifest_name_and_version(tmp_path: Path) -> None:
    """A manifest's name/version becomes the published .pkg filename — traversal is refused.

    ``<name>-<version>.pkg`` is written into the catalog directory, so an input .pkg
    whose manifest carries a separator or traversal in either field would write
    OUTSIDE the catalog. The manifest is attacker-controlled input (it is read from
    the .pkg, never derived), so it gets the same segment guard as the varver.
    """
    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / "keep.txt").write_text("must survive")

    for field in ("name", "version"):
        in_dir = tmp_path / f"in_{field}"
        in_dir.mkdir()
        kwargs = {field: "../victim/evil"}
        make_pkg(in_dir / "evil.pkg", abi="FreeBSD:15:*", **kwargs)  # type: ignore[arg-type]
        out = tmp_path / f"out_{field}"
        out.mkdir()
        with pytest.raises(brp.BuildRepoError, match=f"manifest {field}"):
            brp.build_repo(in_dir, out)

    # The pre-fix defect WRITES into victim/ rather than deleting from it, so the
    # failable oracle is "no package landed here" — a surviving keep.txt would be
    # true either way.
    assert not list(victim.glob("*.pkg")), f"a manifest field escaped the catalog dir: {list(victim.iterdir())}"
    assert (victim / "keep.txt").read_text() == "must survive"


def test_catalog_under_versioned_subdir(tmp_path: Path) -> None:
    """--catalog-name writes the FLAT catalog directly at <out>/<catalog-name>/, no ABI subdir.

    Scenario: CE 2.8 build
      Given no ce-2.8/ dir exists in <out>
      When build_repo(catalog_name="ce-2.8") is called with a CE NO_ARCH pkg (ABI=FreeBSD:15:*)
      Then meta.conf exists at ce-2.8/meta.conf
      And no meta.conf exists at the plain root-level out/meta.conf
    """
    in_dir = tmp_path / "in"
    in_dir.mkdir()
    make_pkg(in_dir / "ce-pkg.pkg", name="pfBlockerNG-testing", abi="FreeBSD:15:*")
    out = tmp_path / "out"
    out.mkdir()

    # Before-state: no ce-2.8/ dir
    assert not (out / "ce-2.8").exists()

    brp.build_repo(in_dir, out, catalog_name="ce-2.8")

    # Versioned path exists, flat (no ABI subdir)
    assert (out / "ce-2.8" / "meta.conf").is_file()
    # Root-level path does NOT exist
    assert not (out / "meta.conf").exists()


def test_plus_catalog_under_versioned_subdir(tmp_path: Path) -> None:
    """--catalog-name plus-26.03 writes flat under plus-26.03/, no ce-2.8/ dir created.

    Scenario: Plus 26.03 build
      Given no plus-26.03/ or ce-2.8/ dir exists
      When build_repo(catalog_name="plus-26.03") with Plus NO_ARCH pkg (ABI=FreeBSD:16:*)
      Then meta.conf at plus-26.03/meta.conf
      And no ce-2.8/ dir exists
    """
    in_dir = tmp_path / "in"
    in_dir.mkdir()
    make_pkg(in_dir / "plus-pkg.pkg", name="pfBlockerNG-testing", abi="FreeBSD:16:*")
    out = tmp_path / "out"
    out.mkdir()

    # Before-state: neither versioned dir exists
    assert not (out / "plus-26.03").exists()
    assert not (out / "ce-2.8").exists()

    brp.build_repo(in_dir, out, catalog_name="plus-26.03")

    assert (out / "plus-26.03" / "meta.conf").is_file()
    # CE dir must NOT have been created as a side-effect
    assert not (out / "ce-2.8").exists()


def test_legacy_path_retained(tmp_path: Path) -> None:
    """Without --catalog-name, meta.conf lands DIRECTLY at <out>/meta.conf (flat, arch-less).

    This is the regression guard: passing catalog_name=None must NOT change existing behaviour
    beyond the arch-less layout change (issue #1806/#1786).
    """
    in_dir = tmp_path / "in"
    in_dir.mkdir()
    make_pkg(in_dir / "demo.pkg", abi="FreeBSD:15:*")
    out = tmp_path / "out"

    brp.build_repo(in_dir, out)  # no catalog_name

    assert (out / "meta.conf").is_file()
    # No versioned subdirs created
    assert not (out / "ce-2.8").exists()
    assert not (out / "plus-26.03").exists()


def test_wrong_variant_pkg_excluded(tmp_path: Path) -> None:
    """A CE pkg built into ce-2.8/ does NOT appear in plus-26.03/ and vice-versa.

    Scenario: cross-variant contamination guard
      Given a CE pkg named "pfBlockerNG-ce" (NO_ARCH ABI FreeBSD:15:*)
        And a Plus pkg named "pfBlockerNG-plus" (NO_ARCH ABI FreeBSD:16:*)
      When each is built into its own versioned catalog dir
      Then the CE packagesite contains only "pfBlockerNG-ce"
       And the Plus packagesite contains only "pfBlockerNG-plus"
       And "pfBlockerNG-plus" is NOT in the CE packagesite
       And "pfBlockerNG-ce" is NOT in the Plus packagesite
    """
    ce_dir = tmp_path / "ce_in"
    ce_dir.mkdir()
    plus_dir = tmp_path / "plus_in"
    plus_dir.mkdir()
    make_pkg(ce_dir / "ce.pkg", name="pfBlockerNG-ce", abi="FreeBSD:15:*")
    make_pkg(plus_dir / "plus.pkg", name="pfBlockerNG-plus", abi="FreeBSD:16:*")
    out = tmp_path / "out"

    brp.build_repo(ce_dir, out, catalog_name="ce-2.8")
    brp.build_repo(plus_dir, out, catalog_name="plus-26.03")

    # CE packagesite names
    ce_raw = _read_member(out / "ce-2.8" / "packagesite.pkg", "packagesite.yaml").decode()
    ce_names = {json.loads(ln)["name"] for ln in ce_raw.splitlines() if ln}
    assert "pfBlockerNG-ce" in ce_names
    assert "pfBlockerNG-plus" not in ce_names

    # Plus packagesite names
    plus_raw = _read_member(out / "plus-26.03" / "packagesite.pkg", "packagesite.yaml").decode()
    plus_names = {json.loads(ln)["name"] for ln in plus_raw.splitlines() if ln}
    assert "pfBlockerNG-plus" in plus_names
    assert "pfBlockerNG-ce" not in plus_names


def test_two_ce_entries_produce_two_versioned_dirs(tmp_path: Path) -> None:
    """Two CE builds (different versions, different majors) each get their own flat versioned dir.

    Scenario: transition window with two active CE versions
      Given no ce-2.8/ or ce-2.9/ dir exists
      When build_repo(catalog_name="ce-2.8") with NO_ARCH ABI=FreeBSD:15:*
       And build_repo(catalog_name="ce-2.9") with NO_ARCH ABI=FreeBSD:16:*
      Then ce-2.8/meta.conf exists
       And ce-2.9/meta.conf exists
       And each packagesite contains only its own pkg (no cross-contamination)
    """
    in28 = tmp_path / "in28"
    in28.mkdir()
    in29 = tmp_path / "in29"
    in29.mkdir()
    make_pkg(in28 / "pkg28.pkg", name="pfBlockerNG-2.8", abi="FreeBSD:15:*")
    make_pkg(in29 / "pkg29.pkg", name="pfBlockerNG-2.9", abi="FreeBSD:16:*")
    out = tmp_path / "out"

    # Before-state: neither dir exists
    assert not (out / "ce-2.8").exists()
    assert not (out / "ce-2.9").exists()

    brp.build_repo(in28, out, catalog_name="ce-2.8")
    brp.build_repo(in29, out, catalog_name="ce-2.9")

    assert (out / "ce-2.8" / "meta.conf").is_file()
    assert (out / "ce-2.9" / "meta.conf").is_file()

    # No cross-contamination: each packagesite has only its pkg
    raw28 = _read_member(out / "ce-2.8" / "packagesite.pkg", "packagesite.yaml").decode()
    names28 = [json.loads(ln)["name"] for ln in raw28.splitlines() if ln]
    assert names28 == ["pfBlockerNG-2.8"]

    raw29 = _read_member(out / "ce-2.9" / "packagesite.pkg", "packagesite.yaml").decode()
    names29 = [json.loads(ln)["name"] for ln in raw29.splitlines() if ln]
    assert names29 == ["pfBlockerNG-2.9"]


# --------------------------------------------------------------------------- #
# Nightly channel: CE/Plus variant split with nightly/ path prefix
# --------------------------------------------------------------------------- #


def test_catalog_name_from_version_nightly() -> None:
    """catalog_name_from_version with channel="nightly" prepends "nightly/" prefix.

    CE and Plus both get the nightly/ prefix; the variant-keyed name is unchanged:
      "2.8.1"  + "CE"   + channel="nightly" -> "nightly/ce-2.8"
      "26.03.1"+ "Plus" + channel="nightly" -> "nightly/plus-26.03"
    Without channel= the behaviour is unchanged (no prefix):
      "2.8.1"  + "CE"                       -> "ce-2.8"
    """
    # Nightly CE: prefix applied
    assert brp.catalog_name_from_version("2.8.1", "CE", channel="nightly") == "nightly/ce-2.8"
    # Nightly Plus: prefix applied
    assert brp.catalog_name_from_version("26.03.1", "Plus", channel="nightly") == "nightly/plus-26.03"
    # No channel: unchanged
    assert brp.catalog_name_from_version("2.8.1", "CE") == "ce-2.8"
    # Patch stripping still works with nightly
    assert brp.catalog_name_from_version("2.8.x", "CE", channel="nightly") == "nightly/ce-2.8"


def test_nightly_catalog_under_versioned_subdir(tmp_path: Path) -> None:
    """build_repo with catalog_name="nightly/ce-2.8" writes the flat tree under nightly/ce-2.8/.

    Scenario: nightly CE build
      Given no nightly/ dir exists in <out>
      When build_repo(catalog_name="nightly/ce-2.8") with a CE NO_ARCH pkg (ABI=FreeBSD:15:*)
      Then meta.conf exists at nightly/ce-2.8/meta.conf
       And no meta.conf exists at ce-2.8/meta.conf (release path untouched)
       And no meta.conf exists at the legacy root out/meta.conf
    """
    in_dir = tmp_path / "in"
    in_dir.mkdir()
    make_pkg(in_dir / "nightly-ce.pkg", name="pfBlockerNG-nightly", abi="FreeBSD:15:*")
    out = tmp_path / "out"
    out.mkdir()

    # Before-state: no nightly/ dir
    assert not (out / "nightly").exists()

    brp.build_repo(in_dir, out, catalog_name="nightly/ce-2.8")

    # Nightly versioned path exists, flat (no ABI subdir)
    assert (out / "nightly" / "ce-2.8" / "meta.conf").is_file()
    # Release path NOT created as side-effect
    assert not (out / "ce-2.8").exists()
    # Legacy root-level path NOT created
    assert not (out / "meta.conf").exists()


def test_nightly_plus_catalog_under_versioned_subdir(tmp_path: Path) -> None:
    """build_repo with catalog_name="nightly/plus-26.03" writes flat under nightly/plus-26.03/.

    Scenario: nightly Plus build, nightly CE build in same output tree
      Given no nightly/ dir exists
      When build_repo(catalog_name="nightly/ce-2.8") with CE NO_ARCH pkg (FreeBSD:15:*)
       And build_repo(catalog_name="nightly/plus-26.03") with Plus NO_ARCH pkg (FreeBSD:16:*)
      Then nightly/ce-2.8/meta.conf exists
       And nightly/plus-26.03/meta.conf exists
       And the CE and Plus nightly packagesite contents do not cross-contaminate
    """
    ce_dir = tmp_path / "ce_in"
    ce_dir.mkdir()
    plus_dir = tmp_path / "plus_in"
    plus_dir.mkdir()
    make_pkg(ce_dir / "ce-nightly.pkg", name="pfBlockerNG-nightly-ce", abi="FreeBSD:15:*")
    make_pkg(plus_dir / "plus-nightly.pkg", name="pfBlockerNG-nightly-plus", abi="FreeBSD:16:*")
    out = tmp_path / "out"

    # Before-state: no nightly dir
    assert not (out / "nightly").exists()

    brp.build_repo(ce_dir, out, catalog_name="nightly/ce-2.8")
    brp.build_repo(plus_dir, out, catalog_name="nightly/plus-26.03")

    assert (out / "nightly" / "ce-2.8" / "meta.conf").is_file()
    assert (out / "nightly" / "plus-26.03" / "meta.conf").is_file()

    ce_raw = _read_member(out / "nightly" / "ce-2.8" / "packagesite.pkg", "packagesite.yaml").decode()
    ce_names = {json.loads(ln)["name"] for ln in ce_raw.splitlines() if ln}
    assert "pfBlockerNG-nightly-ce" in ce_names
    assert "pfBlockerNG-nightly-plus" not in ce_names

    plus_raw = _read_member(out / "nightly" / "plus-26.03" / "packagesite.pkg", "packagesite.yaml").decode()
    plus_names = {json.loads(ln)["name"] for ln in plus_raw.splitlines() if ln}
    assert "pfBlockerNG-nightly-plus" in plus_names
    assert "pfBlockerNG-nightly-ce" not in plus_names


# --------------------------------------------------------------------------- #
# ADR-20 routing rework: the matrix-driven brain (build_repo_matrix + helpers)
#
# These pin the LITERAL projection of the version matrix onto the tree
# (release/<varver>/ + nightly/<varver>/ — arch-less since issue #1806: all
# three pfSense-pkg-pfBlockerNG ports are NO_ARCH, so one varver directory
# serves every arch of its FreeBSD major), the release channel-group (testing +
# stable in one catalog), full-matrix/no-dedup placement, and nightly
# retention. The DUMB pkg builder is stubbed so the tests exercise the BRAIN
# (arrangement) without a ports tree — build-pkg-portable.py's own behaviour
# (including the NO_ARCH wildcard stamp) is covered by its own suite.
# --------------------------------------------------------------------------- #

# The live matrix shape (subset of fields build_repo_matrix consumes). `arch`
# still drives which concrete --abi the (stubbed) builder receives per row —
# it no longer selects a catalog bucket (arch-less; issue #1806).
_CE = {
    "pfsense_version": "2.8",
    "variant": "CE",
    "freebsd_major": "15",
    "php_version": "8.3",
    "py_flavor": "py311",
    "status": "active",
    "arch": "amd64",
}
_PLUS = {
    "pfsense_version": "26.03",
    "variant": "Plus",
    "freebsd_major": "16",
    "php_version": "8.5",
    "py_flavor": "py311",
    "status": "active",
    "arch": "amd64",
}
_PLUS_ARM = {**_PLUS, "arch": "aarch64", "status": "active"}

_CHANNEL_NAME = {
    "testing": "pfBlockerNG-testing",
    "stable": "pfBlockerNG",
    "edge": "pfBlockerNG-edge",
    "nightly": "pfBlockerNG-nightly",
}


def _stub_builder(
    channel: str,
    *,
    abi: str,
    php: str,
    py_flavor: str,
    out_dir: Path,
    varver: str,
    arch: str,
    pkgversion: str | None = None,
    **_kw: Any,
) -> Path:
    """Stand-in for build-pkg-portable.py: drop a libpkg-shaped .pkg, return its path.

    The package NAME encodes the channel (so a subtree's catalog reveals which channels
    landed there); the manifest carries a versioned php guard dep (so a wrong-flavor mix
    would trip the collision guard, as in a real build). The manifest ABI is stamped
    CPU-WILDCARDED (``FreeBSD:<major>:*``) regardless of the incoming concrete ``abi``'s
    CPU segment — a real build-pkg-portable.py run does exactly this for a NO_ARCH port
    (issue #1806 B1), and the catalog now hard-requires it (``_is_wildcard_abi``).
    """
    name = _CHANNEL_NAME[channel]
    version = pkgversion or "1.0_1"
    php_dep = "php" + php.replace(".", "")
    deps = {
        php_dep: {"origin": f"lang/{php_dep}", "version": "0"},
        py_flavor: {"origin": f"lang/{py_flavor}", "version": "0"},
    }
    major = abi.split(":")[1]
    wildcard_abi = f"FreeBSD:{major}:*"
    # Distinct on-disk filename per (channel, varver, arch) so concurrent staging never clashes;
    # the catalog copies it CANONICALLY as <name>-<version>.pkg regardless.
    out = out_dir / f"{name}-{version}-{varver}-{arch}-{channel}.pkg"
    make_pkg(out, name=name, version=version, abi=wildcard_abi, deps=deps)
    return out


def _build_record_for(entry: dict[str, Any], channel: str, version: str) -> dict[str, object]:
    row = {key: value for key, value in entry.items() if key != "arch"}
    record: dict[str, object] = {
        "schema": 1,
        "channel": channel,
        "release_line": "release/4.0",
        "classification": (
            "nightly" if channel == "nightly" else {"stable": "final", "testing": "alpha", "edge": "beta"}[channel]
        ),
        "source_tag": (
            None if channel == "nightly" else {"stable": "v4.0.0", "testing": "v4.0.1.a1", "edge": "v4.0.0.b1"}[channel]
        ),
        "source_sha": "a" * 40,
        "canonical_package_version": version,
        "native_recipe_identity": (
            "pfSense-pkg-pfBlockerNG" if channel == "stable" else f"pfSense-pkg-pfBlockerNG-{channel}"
        ),
        "emitted_identity": "pfSense-pkg-pfBlockerNG",
        "matrix_row": row,
        "freebsd_ports_sha": "b" * 40,
        "route": f"{channel}/ce-2.8",
        "source_date_epoch": 1_700_000_000,
        "dependency_builder": DEPENDENCY_BUILDER,
        "build_input_digest": "",
    }
    record["build_input_digest"] = pfb_pkg.build_input_digest(record)
    return record


def _names_in(catalog_pkg: Path) -> set[str]:
    raw = _read_member(catalog_pkg, "packagesite.yaml").decode()
    return {json.loads(ln)["name"] for ln in raw.splitlines() if ln}


def test_build_matrix_forwards_records_for_testing_stable_edge_nightly(tmp_path: Path) -> None:
    """Every source route receives its matching validated record and canonical version."""
    entry = {**_CE, "channel": "CE", "freebsd_version": "15.0-RELEASE", "extra_pkgs": []}
    entry.pop("arch")
    records = [
        _build_record_for(entry, "testing", "4.0.1.a1"),
        _build_record_for(entry, "stable", "4.0.0"),
        _build_record_for(entry, "edge", "4.0.0.b1"),
        _build_record_for(entry, "nightly", f"20260804153045.{'a' * 7}"),
    ]
    calls: dict[str, tuple[str | None, str | None]] = {}

    def recording_builder(
        channel: str, *, build_record: str | None = None, pkgversion: str | None = None, **kwargs: Any
    ) -> Path:
        calls[channel] = (build_record, pkgversion)
        return _stub_builder(channel, **kwargs)

    brp.build_repo_matrix(
        [entry],
        tmp_path / "site",
        builder=recording_builder,
        stable_tag="v4.0.0",
        build_records=records,
    )

    assert set(calls) == {"testing", "stable", "edge", "nightly"}
    expected_versions = {
        "testing": "4.0.1.a1",
        "stable": "4.0.0",
        "edge": "4.0.0.b1",
        "nightly": f"20260804153045.{'a' * 7}",
    }
    for channel, record in zip(("testing", "stable", "edge", "nightly"), records):
        forwarded, pkgversion = calls[channel]
        assert isinstance(forwarded, str)
        assert json.loads(forwarded) == record
        assert pkgversion == expected_versions[channel]


def test_build_matrix_rejects_mismatched_record_row(tmp_path: Path) -> None:
    """A record with the right route but a different matrix row fails closed."""
    entry = {**_CE, "channel": "CE", "freebsd_version": "15.0-RELEASE", "extra_pkgs": []}
    entry.pop("arch")
    mismatched = _build_record_for(entry, "testing", "4.0.1.a1")
    mismatched["matrix_row"] = {**entry, "status": "beta"}
    mismatched["build_input_digest"] = pfb_pkg.build_input_digest(mismatched)

    with pytest.raises(brp.BuildRepoError, match="matrix_row does not exactly match"):
        brp.build_repo_matrix(
            [entry],
            tmp_path / "site",
            builder=_stub_builder,
            build_records=[mismatched],
        )


def test_build_matrix_ignores_legacy_arch_when_matching_record_row(tmp_path: Path) -> None:
    """The documented legacy arch input is separate from the normalized BUILD row."""
    entry = {**_CE, "channel": "CE", "freebsd_version": "15.0-RELEASE", "extra_pkgs": []}
    record_row = {key: value for key, value in entry.items() if key != "arch"}
    record = _build_record_for(record_row, "testing", "4.0.1.a1")

    brp.build_repo_matrix(
        [entry],
        tmp_path / "site",
        builder=_stub_builder,
        build_records=[record],
    )


def test_retain_by_channel_rejects_legacy_devel_identity(tmp_path: Path) -> None:
    """Legacy ``-devel`` package names are not silently treated as Testing."""
    legacy = _make_pkg_channel(tmp_path, "pfBlockerNG-devel", "4.0.1.a1")

    with pytest.raises(brp.BuildRepoError, match="legacy.*-devel"):
        brp.retain_by_channel([legacy], keep_testing=1, keep_stable=1)


def test_pkg_version_key_orders_nightlies_chronologically() -> None:
    """_pkg_version_key sorts nightly <target>.YYYYMMDD.N so a later build ranks higher."""
    older = brp._pkg_version_key("3.2.16.20260606.2")
    newer_day = brp._pkg_version_key("3.2.16.20260607.1")
    newer_counter = brp._pkg_version_key("3.2.16.20260606.3")
    # A later date outranks an earlier date even with a lower counter.
    assert newer_day > older
    # Same date, higher counter outranks (the bug a naive lexicographic compare hits at .10 vs .2).
    assert newer_counter > older
    assert brp._pkg_version_key("3.2.16.20260606.10") > brp._pkg_version_key("3.2.16.20260606.2")


@pytest.mark.parametrize(
    "versions",
    [
        ["4.0.0.a1", "4.0.0.b1", "4.0.0.r1", "4.0.0"],
        ["4.0.0.alpha.1", "4.0.0.beta.1", "4.0.0.rc.1", "4.0.0"],
    ],
    ids=["canonical-compact", "legacy-expanded"],
)
def test_pkg_version_key_orders_prerelease_stages_alpha_beta_rc_then_release(versions: list[str]) -> None:
    """Canonical compact and retained legacy versions order alpha < beta < rc < final."""
    keys = [brp._pkg_version_key(version) for version in versions]
    assert all(keys[index] < keys[index + 1] for index in range(len(keys) - 1))
    next_alpha = versions[0].replace("1", "2")
    assert brp._pkg_version_key(versions[0]) < brp._pkg_version_key(next_alpha) < brp._pkg_version_key(versions[1])


def test_pkg_version_key_preserves_numeric_prefix_ordering() -> None:
    """A shorter all-numeric version must sort BELOW its longer prefix-extension.

    A flat `[*base, stage_rank, stage_num]` key breaks this: '2.8' -> [2, 8, 3, 0]
    compares its OWN stage_rank (index 2 = 3) against '2.8.1' -> [2, 8, 1, 3, 0]'s
    THIRD version component (index 2 = 1) at the same list position, so '2.8'
    wrongly sorts ABOVE '2.8.1'. The nested (base, stage_rank, stage_num) tuple
    compares `base` as a whole list first (Python's list-prefix rule), so the
    shorter numeric run correctly sorts below its extension.
    """
    assert brp._pkg_version_key("2.8") < brp._pkg_version_key("2.8.1")
    assert brp._pkg_version_key("4.0.0") < brp._pkg_version_key("4.0.0.1")


def test_pkg_version_key_full_multi_version_sort_matches_pkg_order() -> None:
    """A shuffled multi-version list sorts into the exact pkg-defined order."""
    shuffled = [
        "4.0.0",
        "4.0.0.rc.1",
        "4.0.0.alpha.2",
        "4.0.0.beta.1",
        "4.0.0.alpha.1",
        "4.0.1.alpha.1",
    ]
    expected = [
        "4.0.0.alpha.1",
        "4.0.0.alpha.2",
        "4.0.0.beta.1",
        "4.0.0.rc.1",
        "4.0.0",
        "4.0.1.alpha.1",
    ]
    assert sorted(shuffled, key=brp._pkg_version_key) == expected


def test_retain_by_channel_testing_retains_prerelease_stages_in_pkg_order(tmp_path: Path) -> None:
    """retain_by_channel(keep_testing>1) keeps the newest N testing builds in REAL pkg order.

    Scenario: a testing series progressing alpha.1 -> alpha.2 -> beta.1 -> rc.1, retained 3-deep,
    with mtimes set ADVERSARIALLY (oldest-stage file gets the NEWEST mtime) so the result can
    only be right via the VERSION key, never via _retain_newest's mtime tie-break falling back
    on file-creation order.
      Given 4 testing .pkg spanning the alpha/beta/rc lifecycle of one series
        And keep_testing=3 (artifact retention, --release-keep-testing > 1)
        And mtimes DELIBERATELY inverted vs. stage order (alpha.1 is newest-on-disk)
      When retain_by_channel is called
      Then the 3 NEWEST BY VERSION survive: alpha.2, beta.1, rc.1
       And the oldest BY VERSION (alpha.1) is dropped, despite having the newest mtime —
       proving the primary key (not the mtime tie-break) drives the decision
    """
    d = tmp_path / "pkgs"
    d.mkdir()
    a1 = _make_pkg_channel(d, "pfBlockerNG-testing", "4.0.0.alpha.1")
    a2 = _make_pkg_channel(d, "pfBlockerNG-testing", "4.0.0.alpha.2")
    b1 = _make_pkg_channel(d, "pfBlockerNG-testing", "4.0.0.beta.1")
    r1 = _make_pkg_channel(d, "pfBlockerNG-testing", "4.0.0.rc.1")
    # Invert mtimes vs. version-stage order: the OLDEST version (alpha.1) gets the
    # NEWEST mtime, and vice versa. A tie-break-by-mtime alone would then pick the
    # WRONG 3 (a1, a2, b1) — only a version key that keeps alpha/beta/rc DISTINCT
    # (never tying) picks the right 3 (a2, b1, r1) regardless of mtime.
    base = 1_700_000_000.0
    for path, offset in ((r1, 0), (b1, 10), (a2, 20), (a1, 30)):
        os.utime(path, (base + offset, base + offset))

    # Before-state: all 4 present.
    all_paths = [a1, a2, b1, r1]
    kept_all = brp.retain_by_channel(all_paths, keep_testing=0, keep_stable=0)
    assert len(kept_all) == 4

    kept = brp.retain_by_channel(all_paths, keep_testing=3, keep_stable=0)
    kept_versions = {brp.read_compact_manifest(p)["version"] for p in kept}
    assert kept_versions == {"4.0.0.alpha.2", "4.0.0.beta.1", "4.0.0.rc.1"}
    assert "4.0.0.alpha.1" not in kept_versions


def test_build_matrix_tree_layout_arch_less(tmp_path: Path) -> None:
    """build_repo_matrix projects the matrix onto an ARCH-LESS tree (issue #1806).

    Scenario: a CE + a Plus entry
      Given an empty output root
      When build_repo_matrix runs over [CE, Plus]
      Then release/ce-2.8/ and release/plus-26.03/ catalogs exist DIRECTLY
       And there is NO arch subdirectory, and NO full-ABI subdirectory either
       And the matching nightly subtrees exist
    """
    out = tmp_path / "site"
    # Before-state: nothing built.
    assert not out.exists()

    brp.build_repo_matrix([_CE, _PLUS], out, builder=_stub_builder)

    # The catalog lives directly at release/<varver>/ — no arch leaf.
    assert (out / "release" / "ce-2.8" / "meta.conf").is_file()
    assert (out / "release" / "plus-26.03" / "meta.conf").is_file()
    assert (out / "nightly" / "ce-2.8" / "meta.conf").is_file()
    assert (out / "nightly" / "plus-26.03" / "meta.conf").is_file()
    # Neither an arch leaf nor the full ABI ever appears as a path segment.
    assert not (out / "release" / "ce-2.8" / "amd64").exists()
    assert not (out / "release" / "ce-2.8" / "FreeBSD:15:amd64").exists()
    assert not (out / "release" / "plus-26.03" / "amd64").exists()
    assert not (out / "release" / "plus-26.03" / "FreeBSD:16:amd64").exists()


def test_build_matrix_release_holds_testing_and_stable(tmp_path: Path) -> None:
    """The release channel-group is testing-only without a stable tag, testing+stable with one.

    Scenario: stable tag absent -> present (the branch + the before/after)
      Given build_repo_matrix([CE]) with NO stable_tag
      Then release/ce-2.8 holds ONLY the testing package
      When re-run WITH stable_tag set
      Then the release catalog holds BOTH the testing and the stable package
    """
    out = tmp_path / "site"

    # Off branch: no stable tag -> testing only.
    brp.build_repo_matrix([_CE], out, builder=_stub_builder)
    rel = out / "release" / "ce-2.8" / "packagesite.pkg"
    assert _names_in(rel) == {"pfBlockerNG-testing", "pfBlockerNG-edge"}

    # On branch: a stable tag -> testing + stable coexist in ONE catalog.
    brp.build_repo_matrix([_CE], out, builder=_stub_builder, stable_tag="v3.2.15")
    assert _names_in(rel) == {"pfBlockerNG-testing", "pfBlockerNG-edge", "pfBlockerNG"}


def test_build_matrix_calls_all_live_channels(tmp_path: Path) -> None:
    """Every build-role row invokes stable, testing, edge, and nightly seams."""
    seen: list[str] = []

    def recording_builder(channel: str, **kwargs: Any) -> Path:
        seen.append(channel)
        return _stub_builder(channel, **kwargs)

    brp.build_repo_matrix([_CE], tmp_path / "site", builder=recording_builder, stable_tag="v3.2.15")

    assert seen == ["testing", "stable", "edge", "nightly"]


def test_build_matrix_full_matrix_no_dedup(tmp_path: Path) -> None:
    """Two versions sharing ABI+php+py still get their OWN subtree (full matrix, no dedup)."""
    ce_28 = _CE
    ce_29 = {**_CE, "pfsense_version": "2.9"}  # same FreeBSD major/php/py as 2.8
    out = tmp_path / "site"
    brp.build_repo_matrix([ce_28, ce_29], out, builder=_stub_builder)
    # Distinct version segments, each populated independently.
    assert (out / "release" / "ce-2.8" / "meta.conf").is_file()
    assert (out / "release" / "ce-2.9" / "meta.conf").is_file()


def test_build_matrix_multi_arch_rows_share_one_varver_catalog(tmp_path: Path) -> None:
    """Multiple arch rows of the SAME varver converge on ONE catalog (arch-less; issue #1806).

    Before the redesign, an aarch64 Plus entry landed under its own arch leaf,
    separate from amd64. Under the arch-less contract every arch row of a
    varver targets the SAME ``release/<varver>/`` directory — there is no
    per-arch leaf left to be distinct.

    Scenario: a Plus amd64 row + a Plus aarch64 row, same varver
      When build_repo_matrix runs over [Plus(amd64), Plus(aarch64)]
      Then exactly ONE release/plus-26.03/ catalog exists (no amd64/aarch64 subdirs)
       And it carries the (wildcard-ABI) testing package
    """
    out = tmp_path / "site"
    brp.build_repo_matrix([_PLUS, _PLUS_ARM], out, builder=_stub_builder, build_nightly=False)
    rel = out / "release" / "plus-26.03"
    assert (rel / "meta.conf").is_file()
    assert not (rel / "amd64").exists()
    assert not (rel / "aarch64").exists()
    assert _names_in(rel / "packagesite.pkg") == {"pfBlockerNG-testing", "pfBlockerNG-edge"}


def test_build_matrix_no_nightly(tmp_path: Path) -> None:
    """build_nightly=False builds the release subtree but NO nightly/ tree."""
    out = tmp_path / "site"
    brp.build_repo_matrix([_CE], out, builder=_stub_builder, build_nightly=False)
    assert (out / "release" / "ce-2.8" / "meta.conf").is_file()
    assert not (out / "nightly").exists()


def test_build_matrix_nightly_retention(tmp_path: Path) -> None:
    """Nightly subtree retains only the N newest builds across runs (a later build supersedes).

    Scenario: nightly_keep=2, three successive nightly versions
      Given build #1 (.1) -> the subtree holds 1 nightly
       When build #2 (.2) lands -> it holds 2
       When build #3 (.3) lands -> it is pruned back to 2, keeping the 2 NEWEST (.2, .3)
    """
    out = tmp_path / "site"
    nl = out / "nightly" / "ce-2.8" / "packagesite.pkg"

    def run(counter: int) -> None:
        brp.build_repo_matrix(
            [_CE],
            out,
            builder=_stub_builder,
            nightly_keep=2,
            nightly_pkgversion=lambda _e: f"3.2.16.2026060{counter}.{counter}",
        )

    run(1)
    assert _versions_in_nightly(nl) == {"3.2.16.20260601.1"}
    run(2)
    assert _versions_in_nightly(nl) == {"3.2.16.20260601.1", "3.2.16.20260602.2"}
    run(3)
    # Pruned to the 2 NEWEST; the oldest (.1) dropped.
    assert _versions_in_nightly(nl) == {"3.2.16.20260602.2", "3.2.16.20260603.3"}


def _versions_in_nightly(catalog_pkg: Path) -> set[str]:
    raw = _read_member(catalog_pkg, "packagesite.yaml").decode()
    return {json.loads(ln)["version"] for ln in raw.splitlines() if ln}


def test_retain_newest_dedups_and_truncates(tmp_path: Path) -> None:
    """_retain_newest keeps the N highest versions, deduping (name,version)."""
    paths = []
    for i in (1, 2, 3, 4):
        p = tmp_path / f"n{i}.pkg"
        make_pkg(p, name="pfBlockerNG-nightly", version=f"3.2.16.2026060{i}.{i}", abi="FreeBSD:15:amd64")
        paths.append(p)
    kept = brp._retain_newest(paths, 2)
    kept_versions = {brp.read_compact_manifest(p)["version"] for p in kept}
    assert kept_versions == {"3.2.16.20260603.3", "3.2.16.20260604.4"}


def test_cli_build_matrix_requires_matrix_and_out(capsys: pytest.CaptureFixture[str]) -> None:
    """--build-matrix without --matrix-json/--out is a usage error."""
    with pytest.raises(SystemExit):
        brp.main(["--build-matrix", "--out", "/tmp/x"])  # missing --matrix-json


def test_cli_build_matrix_unwraps_versions(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The CLI accepts a {versions:[...]} matrix file and forwards the array to the brain."""
    captured: dict[str, Any] = {}

    def fake_brain(matrix: list[dict], out_dir: Path, **kw: Any) -> dict:
        captured["matrix"] = matrix
        captured["kw"] = kw
        return {"routes": [], "built": []}

    monkeypatch.setattr(brp, "build_repo_matrix", fake_brain)
    mfile = tmp_path / "m.json"
    mfile.write_text(json.dumps({"versions": [_CE, _PLUS]}))
    rc = brp.main(["--build-matrix", "--matrix-json", str(mfile), "--out", str(tmp_path / "site"), "--no-nightly"])
    assert rc == 0
    assert captured["matrix"] == [_CE, _PLUS]  # unwrapped from {versions:[...]}
    assert captured["kw"]["build_nightly"] is False


def test_cli_build_matrix_catches_pkg_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A PkgError reading a malformed .pkg in the --build-matrix path (the publish
    pipeline's entry point) must exit 1 cleanly, not escape as an uncaught traceback.

    PkgError now comes from the shared pfb_pkg reader; the matrix handler must catch
    it just like the BuildRepoError it replaced for these paths.
    """

    def boom(matrix: list[dict], out_dir: Path, **kw: Any) -> dict:
        raise brp.PkgError("bad.pkg: no +COMPACT_MANIFEST member — not a libpkg .pkg?")

    monkeypatch.setattr(brp, "build_repo_matrix", boom)
    mfile = tmp_path / "m.json"
    mfile.write_text("[]")
    rc = brp.main(["--build-matrix", "--matrix-json", str(mfile), "--out", str(tmp_path / "site")])
    assert rc == 1  # caught + reported, not propagated


def test_build_matrix_annotate_passthrough(tmp_path: Path) -> None:
    """annotate kwargs reach every builder call (so publish.yml's commit/created stamp lands).

    Given a recording builder,
      When build_repo_matrix runs with annotate={commit, created},
      Then every build (testing + edge + nightly) receives that exact annotate dict.
    """
    seen: list[dict] = []

    def recording_builder(channel: str, *, annotate: dict | None = None, **kw: Any) -> Path:
        seen.append({"channel": channel, "annotate": annotate})
        return _stub_builder(channel, **kw)

    brp.build_repo_matrix(
        [_CE], tmp_path / "site", builder=recording_builder, annotate={"commit": "deadbeef", "created": "123"}
    )
    assert seen, "builder was never called"
    for call in seen:
        assert call["annotate"] == {"commit": "deadbeef", "created": "123"}
    assert {c["channel"] for c in seen} == {"testing", "edge", "nightly"}


def test_default_builder_forwards_project_record_contract(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The repository's default seam must pass the project-build contract through unchanged."""
    out = tmp_path / "staging"
    out.mkdir()
    record = tmp_path / "record.json"
    record.write_text("{}\n")
    record_data = {
        "channel": "testing",
        "canonical_package_version": "4.0.1.a1",
        "emitted_identity": "pfSense-pkg-pfBlockerNG",
        "matrix_row": {"variant": "CE"},
    }
    seen: list[str] = []

    monkeypatch.setattr(brp, "load_build_record", lambda _source: record_data, raising=False)
    monkeypatch.setattr(brp, "validate_build_record", lambda value, **_kw: value, raising=False)

    def fake_run(cmd: list[str], *, check: bool) -> None:
        seen.extend(cmd)
        (out / "pfSense-pkg-pfBlockerNG-4.0.1.a1.pkg").touch()
        assert check is True

    monkeypatch.setattr(brp.subprocess, "run", fake_run)

    result = brp._subprocess_pkg_builder(
        "testing",
        abi="FreeBSD:15:amd64",
        php="8.3",
        py_flavor="py311",
        variant="CE",
        build_record=record,
        pkgversion="4.0.1.a1",
        out_dir=out,
    )

    assert result.name == "pfSense-pkg-pfBlockerNG-4.0.1.a1.pkg"
    assert seen[seen.index("--channel") + 1] == "testing"
    assert "devel" not in seen
    assert seen[seen.index("--variant") + 1] == "CE"
    assert seen[seen.index("--build-record") + 1] == str(record)
    assert seen[seen.index("--pkgversion") + 1] == "4.0.1.a1"


def test_default_matrix_builder_fails_closed_without_record(tmp_path: Path) -> None:
    """The default source seam cannot invent provenance absent a matching record."""
    with pytest.raises(brp.BuildRepoError, match="requires normalized build record.*testing/ce-2.8"):
        brp.build_repo_matrix([_CE], tmp_path / "site")


def test_default_builder_reuses_existing_exact_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """An idempotent package-builder rerun returns its pre-existing exact output."""
    out = tmp_path / "staging"
    out.mkdir()
    record_path = tmp_path / "record.json"
    record_path.write_text("{}\n")
    expected = out / "pfSense-pkg-pfBlockerNG-4.0.1.a1.pkg"
    expected.write_bytes(b"already-built")
    record = {
        "channel": "testing",
        "canonical_package_version": "4.0.1.a1",
        "emitted_identity": "pfSense-pkg-pfBlockerNG",
        "matrix_row": {"variant": "CE"},
    }

    monkeypatch.setattr(brp, "load_build_record", lambda _source: record, raising=False)
    monkeypatch.setattr(brp, "validate_build_record", lambda value, **_kw: value, raising=False)

    def fake_run(_cmd: list[str], *, check: bool) -> None:
        assert check is True

    monkeypatch.setattr(brp.subprocess, "run", fake_run)

    result = brp._subprocess_pkg_builder(
        "testing",
        abi="FreeBSD:15:amd64",
        php="8.3",
        py_flavor="py311",
        variant="CE",
        build_record=record_path,
        pkgversion="4.0.1.a1",
        out_dir=out,
    )

    assert result == expected


# --------------------------------------------------------------------------- #
# ADR-27 Phase 1: retain_by_channel — channel-keyed release-retention helper
#
# These tests pin the helper in isolation (no call-site change in build_repo_matrix
# yet — Phase 2 wires it in). They cover every branch:
#   * testing vs stable bucketed independently (one does not affect the other)
#   * keep < len(bucket) → prune to newest keep (version order + determinism)
#   * keep >= len(bucket) → no-op (keep all)
#   * keep == 0 → keep all of that channel (the "unbounded/disabled" sentinel)
#   * mixed testing+stable+nightly input: nightly left untouched regardless
#   * before-state assertions where the outcome depends on keep value
# --------------------------------------------------------------------------- #


def _make_pkg_channel(
    tmp_path: Path,
    name: str,
    version: str,
    *,
    abi: str = "FreeBSD:15:*",
) -> Path:
    """Write a minimal .pkg and return its path (name encodes the channel).

    Default ABI is wildcard (NO_ARCH; issue #1806) — most callers feed these
    paths through build_repo_matrix, whose catalog now hard-requires it. The
    pure retention-helper tests (_retain_newest/retain_by_channel/_line_pins)
    never inspect the abi field, so the wildcard default is harmless there too.
    """
    p = tmp_path / f"{name}-{version}.pkg"
    make_pkg(p, name=name, version=version, abi=abi)
    return p


def _canonical_retention_record(channel: str, version: str) -> dict[str, object]:
    row = {
        "pfsense_version": "2.8",
        "channel": "CE",
        "freebsd_version": "15.0-RELEASE",
        "freebsd_major": "15",
        "php_version": "8.3",
        "py_flavor": "py311",
        "variant": "CE",
        "status": "active",
        "extra_pkgs": [],
        "upgrade": {"available": False},
    }
    source_tag = "v" + version
    record: dict[str, object] = {
        "schema": 1,
        "channel": channel,
        "release_line": "release/4.0",
        "classification": {"stable": "final", "testing": "alpha", "edge": "beta"}[channel],
        "source_tag": source_tag,
        "source_sha": "a" * 40,
        "canonical_package_version": version,
        "native_recipe_identity": (
            "pfSense-pkg-pfBlockerNG" if channel == "stable" else f"pfSense-pkg-pfBlockerNG-{channel}"
        ),
        "emitted_identity": "pfSense-pkg-pfBlockerNG",
        "matrix_row": row,
        "freebsd_ports_sha": "b" * 40,
        "route": f"{channel}/ce-2.8",
        "source_date_epoch": 1_700_000_000,
        "dependency_builder": DEPENDENCY_BUILDER,
        "build_input_digest": "",
    }
    record["build_input_digest"] = pfb_pkg.build_input_digest(record)
    return record


def _make_annotated_project_pkg(tmp_path: Path, channel: str, version: str, filename: str) -> Path:
    record = _canonical_retention_record(channel, version)
    path = tmp_path / filename
    make_pkg(
        path,
        name="pfSense-pkg-pfBlockerNG",
        version=version,
        extra={"annotations": {"pfb_build_record": json.dumps(record, sort_keys=True, separators=(",", ":"))}},
    )
    return path


def test_retain_by_channel_uses_validated_annotation_for_canonical_packages(tmp_path: Path) -> None:
    """Canonical project packages retain testing and stable independently of filenames.

    Given canonical packages whose filenames carry misleading channel suffixes
      And each package has a validated ``pfb_build_record`` annotation
      When one package per retention channel is requested
      Then testing is retained in the testing bucket and stable in the stable bucket
    """
    testing = _make_annotated_project_pkg(tmp_path, "testing", "4.0.1.a1", "pfSense-pkg-pfBlockerNG-stable-looking.pkg")
    stable = _make_annotated_project_pkg(tmp_path, "stable", "4.0.0", "pfSense-pkg-pfBlockerNG-testing-looking.pkg")

    kept = brp.retain_by_channel([testing, stable], keep_testing=1, keep_stable=1)

    assert set(kept) == {testing, stable}


def test_retain_by_channel_keeps_annotated_edge_outside_testing_window(tmp_path: Path) -> None:
    """Canonical edge packages remain untouched while testing is retention-limited."""
    testing = _make_annotated_project_pkg(tmp_path, "testing", "4.0.1.a1", "testing.pkg")
    edge_old = _make_annotated_project_pkg(tmp_path, "edge", "4.0.0.b1", "edge-old.pkg")
    edge_new = _make_annotated_project_pkg(tmp_path, "edge", "4.0.0.b2", "edge-new.pkg")

    kept = brp.retain_by_channel([testing, edge_old, edge_new], keep_testing=1, keep_stable=1)

    assert set(kept) == {testing, edge_old, edge_new}


def test_retention_annotation_cannot_be_interpreted_as_a_record_path(tmp_path: Path) -> None:
    record_path = tmp_path / "record.json"
    record_path.write_text(json.dumps(_canonical_retention_record("stable", "4.0.0")))
    manifest = {
        "name": pfb_pkg.CANONICAL_EMITTED_IDENTITY,
        "annotations": {pfb_pkg.PFB_BUILD_RECORD_KEY: str(record_path)},
    }

    with pytest.raises(brp.BuildRepoError, match="JSON object"):
        brp._retention_channel(tmp_path / "fixture.pkg", manifest)


def test_retention_rejects_divergent_duplicate_before_pruning(tmp_path: Path) -> None:
    """Retention must not discard one divergent archive before collision checking."""
    first = tmp_path / "first.pkg"
    duplicate = tmp_path / "duplicate.pkg"
    make_pkg(first, name="pfBlockerNG-testing", version="4.0.0", payload=b"hey")
    make_pkg(duplicate, name="pfBlockerNG-testing", version="4.0.0", payload=b"heY")

    with pytest.raises(brp.BuildRepoError, match="PACKAGE COLLISION"):
        brp.retain_by_channel([first, duplicate], keep_testing=1, keep_stable=0)


def test_emit_rejects_partial_annotated_canonical_package(tmp_path: Path) -> None:
    """A canonical package carrying a build record must pass full archive validation."""
    in_dir = tmp_path / "in"
    in_dir.mkdir()
    _make_annotated_project_pkg(in_dir, "stable", "4.0.0", "partial.pkg")

    with pytest.raises(brp.BuildRepoError, match="manifests must be the first two archive members"):
        brp.build_repo(in_dir, tmp_path / "out")


def test_emit_allows_legacy_canonical_package_without_record(tmp_path: Path) -> None:
    """Native legacy stable packages without provenance remain publishable."""
    in_dir = tmp_path / "in"
    in_dir.mkdir()
    make_pkg(
        in_dir / "legacy.pkg",
        name=pfb_pkg.CANONICAL_EMITTED_IDENTITY,
        version="4.0.0",
        abi="FreeBSD:15:*",
    )

    brp.build_repo(in_dir, tmp_path / "out")
    assert (tmp_path / "out" / "pfSense-pkg-pfBlockerNG-4.0.0.pkg").is_file()


def test_retention_rejects_malformed_annotation_container(tmp_path: Path) -> None:
    manifest = {"name": pfb_pkg.CANONICAL_EMITTED_IDENTITY, "annotations": []}

    with pytest.raises(brp.BuildRepoError, match="annotations must be an object"):
        brp._retention_channel(tmp_path / "fixture.pkg", manifest)


def test_retain_by_channel_testing_pruned_independently(tmp_path: Path) -> None:
    """Testing bucket is pruned to keep_testing; stable bucket is untouched when keep_stable=0.

    Scenario: 3 testing versions + 2 stable versions; keep_testing=2, keep_stable=0
      Given 3 testing pkgs (v1, v2, v3) and 2 stable pkgs (s1.0, s2.0)
        And keep_testing=2, keep_stable=0 (stable unbounded)
      When retain_by_channel is called
      Then testing result contains only the 2 newest (v2, v3) — v1 dropped
       And stable result contains BOTH stable pkgs (keep_stable=0 = keep all)
    """
    d = tmp_path / "pkgs"
    d.mkdir()
    dv1 = _make_pkg_channel(d, "pfBlockerNG-testing", "3.0.1")
    dv2 = _make_pkg_channel(d, "pfBlockerNG-testing", "3.0.2")
    dv3 = _make_pkg_channel(d, "pfBlockerNG-testing", "3.0.3")
    sv1 = _make_pkg_channel(d, "pfBlockerNG", "2.0.1")
    sv2 = _make_pkg_channel(d, "pfBlockerNG", "2.0.2")

    # Before-state: all 5 paths provided.
    all_paths = [dv1, dv2, dv3, sv1, sv2]

    kept = brp.retain_by_channel(all_paths, keep_testing=2, keep_stable=0)

    kept_names_versions = {
        (brp.read_compact_manifest(p)["name"], brp.read_compact_manifest(p)["version"]) for p in kept
    }
    # Testing: newest 2 kept (v2, v3); v1 dropped.
    assert ("pfBlockerNG-testing", "3.0.3") in kept_names_versions
    assert ("pfBlockerNG-testing", "3.0.2") in kept_names_versions
    assert ("pfBlockerNG-testing", "3.0.1") not in kept_names_versions
    # Stable: both kept (keep_stable=0 = unbounded).
    assert ("pfBlockerNG", "2.0.1") in kept_names_versions
    assert ("pfBlockerNG", "2.0.2") in kept_names_versions


def test_retain_by_channel_stable_pruned_independently(tmp_path: Path) -> None:
    """Stable bucket is pruned to keep_stable; testing bucket is untouched when keep_testing=0.

    Scenario: 2 testing versions + 3 stable versions; keep_testing=0, keep_stable=1
      Given 2 testing pkgs (v1, v2) and 3 stable pkgs (s1.0, s2.0, s3.0)
        And keep_testing=0 (unbounded), keep_stable=1
      When retain_by_channel is called
      Then stable result contains only s3.0 (newest 1); s1.0 and s2.0 dropped
       And testing result contains BOTH testing pkgs (keep_testing=0 = keep all)
    """
    d = tmp_path / "pkgs"
    d.mkdir()
    dv1 = _make_pkg_channel(d, "pfBlockerNG-testing", "3.0.1")
    dv2 = _make_pkg_channel(d, "pfBlockerNG-testing", "3.0.2")
    sv1 = _make_pkg_channel(d, "pfBlockerNG", "2.0.1")
    sv2 = _make_pkg_channel(d, "pfBlockerNG", "2.0.2")
    sv3 = _make_pkg_channel(d, "pfBlockerNG", "2.0.3")

    # Before-state: all 5 paths.
    all_paths = [dv1, dv2, sv1, sv2, sv3]

    kept = brp.retain_by_channel(all_paths, keep_testing=0, keep_stable=1)

    kept_nv = {(brp.read_compact_manifest(p)["name"], brp.read_compact_manifest(p)["version"]) for p in kept}
    # Stable: only newest (s3.0).
    assert ("pfBlockerNG", "2.0.3") in kept_nv
    assert ("pfBlockerNG", "2.0.2") not in kept_nv
    assert ("pfBlockerNG", "2.0.1") not in kept_nv
    # Testing: both kept.
    assert ("pfBlockerNG-testing", "3.0.1") in kept_nv
    assert ("pfBlockerNG-testing", "3.0.2") in kept_nv


def test_retain_by_channel_keep_zero_is_unbounded_sentinel(tmp_path: Path) -> None:
    """keep==0 for a channel keeps ALL of that channel (the unbounded/disabled sentinel).

    Scenario: keep_testing=0, keep_stable=0
      Given 3 testing pkgs and 3 stable pkgs
      When retain_by_channel with both keeps=0
      Then ALL 6 paths are returned (no pruning)
    """
    d = tmp_path / "pkgs"
    d.mkdir()
    all_paths = [_make_pkg_channel(d, "pfBlockerNG-testing", f"3.0.{i}") for i in range(1, 4)] + [
        _make_pkg_channel(d, "pfBlockerNG", f"2.0.{i}") for i in range(1, 4)
    ]

    # Before-state: 6 paths in.
    assert len(all_paths) == 6

    kept = brp.retain_by_channel(all_paths, keep_testing=0, keep_stable=0)

    # All 6 kept.
    assert len(kept) == 6
    kept_versions_testing = {
        brp.read_compact_manifest(p)["version"]
        for p in kept
        if brp.read_compact_manifest(p)["name"] == "pfBlockerNG-testing"
    }
    kept_versions_stable = {
        brp.read_compact_manifest(p)["version"] for p in kept if brp.read_compact_manifest(p)["name"] == "pfBlockerNG"
    }
    assert kept_versions_testing == {"3.0.1", "3.0.2", "3.0.3"}
    assert kept_versions_stable == {"2.0.1", "2.0.2", "2.0.3"}


def test_retain_by_channel_keep_larger_than_bucket_is_noop(tmp_path: Path) -> None:
    """keep >= len(bucket) is a no-op — all paths in that bucket are retained.

    Scenario: keep_testing=100, keep_stable=100 with only 2 testing and 2 stable pkgs
      Given 2 testing pkgs and 2 stable pkgs
        And keep values far larger than the buckets
      When retain_by_channel is called
      Then all 4 paths are returned (no pruning)
    """
    d = tmp_path / "pkgs"
    d.mkdir()
    dv1 = _make_pkg_channel(d, "pfBlockerNG-testing", "3.0.1")
    dv2 = _make_pkg_channel(d, "pfBlockerNG-testing", "3.0.2")
    sv1 = _make_pkg_channel(d, "pfBlockerNG", "2.0.1")
    sv2 = _make_pkg_channel(d, "pfBlockerNG", "2.0.2")

    # Before-state: 4 inputs.
    all_paths = [dv1, dv2, sv1, sv2]

    kept = brp.retain_by_channel(all_paths, keep_testing=100, keep_stable=100)

    assert len(kept) == 4


def test_retain_by_channel_version_order_deterministic(tmp_path: Path) -> None:
    """The newest-N selection uses version order (not filesystem order or name order).

    Scenario: testing pkgs with non-lexicographic versions, keep_testing=2
      Given testing pkgs at versions 3.0.1, 3.0.9, 3.0.10 (lexicographic order differs)
        And keep_testing=2
      When retain_by_channel is called
      Then 3.0.10 and 3.0.9 are kept (numerically newest 2), 3.0.1 dropped
    """
    d = tmp_path / "pkgs"
    d.mkdir()
    # Write in reverse order so filesystem order can't accidentally "win".
    p10 = _make_pkg_channel(d, "pfBlockerNG-testing", "3.0.10")
    p9 = _make_pkg_channel(d, "pfBlockerNG-testing", "3.0.9")
    p1 = _make_pkg_channel(d, "pfBlockerNG-testing", "3.0.1")

    # Before-state: all 3 present.
    kept_all = brp.retain_by_channel([p10, p9, p1], keep_testing=0, keep_stable=0)
    assert len(kept_all) == 3

    # With keep_testing=2: 3.0.10 and 3.0.9 must survive; 3.0.1 dropped.
    kept = brp.retain_by_channel([p10, p9, p1], keep_testing=2, keep_stable=0)
    kept_versions = {brp.read_compact_manifest(p)["version"] for p in kept}
    assert kept_versions == {"3.0.10", "3.0.9"}
    assert "3.0.1" not in kept_versions


def test_retain_by_channel_nightly_untouched(tmp_path: Path) -> None:
    """Nightly pkgs pass through unchanged regardless of keep_testing / keep_stable.

    Scenario: mixed input with testing, stable, AND nightly pkgs
      Given 1 testing, 1 stable, 2 nightly pkgs; keep_testing=1, keep_stable=1
      When retain_by_channel is called
      Then testing: 1 kept (the only one)
       And stable: 1 kept (the only one)
       And BOTH nightly pkgs pass through — nightly is left untouched
    """
    d = tmp_path / "pkgs"
    d.mkdir()
    dv = _make_pkg_channel(d, "pfBlockerNG-testing", "3.0.1")
    sv = _make_pkg_channel(d, "pfBlockerNG", "2.0.1")
    nv1 = _make_pkg_channel(d, "pfBlockerNG-nightly", "3.0.20260601.1")
    nv2 = _make_pkg_channel(d, "pfBlockerNG-nightly", "3.0.20260602.1")

    all_paths = [dv, sv, nv1, nv2]

    kept = brp.retain_by_channel(all_paths, keep_testing=1, keep_stable=1)

    kept_nv = {(brp.read_compact_manifest(p)["name"], brp.read_compact_manifest(p)["version"]) for p in kept}
    # Testing: the one testing pkg kept.
    assert ("pfBlockerNG-testing", "3.0.1") in kept_nv
    # Stable: the one stable pkg kept.
    assert ("pfBlockerNG", "2.0.1") in kept_nv
    # Both nightly pkgs retained untouched.
    assert ("pfBlockerNG-nightly", "3.0.20260601.1") in kept_nv
    assert ("pfBlockerNG-nightly", "3.0.20260602.1") in kept_nv
    assert len(kept) == 4


def test_retain_by_channel_mixed_prune_nightly_untouched(tmp_path: Path) -> None:
    """Mixed input: testing pruned, stable pruned, nightly passed through.

    Scenario: prune both channels from a 3+3+2 mixed input
      Given 3 testing pkgs, 3 stable pkgs, 2 nightly pkgs
        And keep_testing=1, keep_stable=2
      When retain_by_channel is called
      Then testing: only the newest 1 kept
       And stable: only the newest 2 kept
       And both nightly pkgs pass through (untouched)
       AND each channel is pruned independently (testing prune does not affect stable)
    """
    d = tmp_path / "pkgs"
    d.mkdir()
    d1 = _make_pkg_channel(d, "pfBlockerNG-testing", "3.0.1")
    d2 = _make_pkg_channel(d, "pfBlockerNG-testing", "3.0.2")
    d3 = _make_pkg_channel(d, "pfBlockerNG-testing", "3.0.3")
    s1 = _make_pkg_channel(d, "pfBlockerNG", "2.0.1")
    s2 = _make_pkg_channel(d, "pfBlockerNG", "2.0.2")
    s3 = _make_pkg_channel(d, "pfBlockerNG", "2.0.3")
    n1 = _make_pkg_channel(d, "pfBlockerNG-nightly", "3.0.20260601.1")
    n2 = _make_pkg_channel(d, "pfBlockerNG-nightly", "3.0.20260602.1")

    # Before-state: 8 pkgs in, each channel has its full set.
    all_paths = [d1, d2, d3, s1, s2, s3, n1, n2]

    kept = brp.retain_by_channel(all_paths, keep_testing=1, keep_stable=2)

    kept_nv = {(brp.read_compact_manifest(p)["name"], brp.read_compact_manifest(p)["version"]) for p in kept}

    # Testing: only newest 1 (3.0.3).
    assert ("pfBlockerNG-testing", "3.0.3") in kept_nv
    assert ("pfBlockerNG-testing", "3.0.2") not in kept_nv
    assert ("pfBlockerNG-testing", "3.0.1") not in kept_nv

    # Stable: newest 2 (2.0.2, 2.0.3); 2.0.1 dropped.
    assert ("pfBlockerNG", "2.0.3") in kept_nv
    assert ("pfBlockerNG", "2.0.2") in kept_nv
    assert ("pfBlockerNG", "2.0.1") not in kept_nv

    # Nightly: both pass through.
    assert ("pfBlockerNG-nightly", "3.0.20260601.1") in kept_nv
    assert ("pfBlockerNG-nightly", "3.0.20260602.1") in kept_nv

    # Total: 1 testing + 2 stable + 2 nightly = 5.
    assert len(kept) == 5


def test_retain_by_channel_empty_channel_is_noop(tmp_path: Path) -> None:
    """An empty channel bucket is a no-op — no KeyError, no side effects.

    Scenario: only stable pkgs provided, no testing, no nightly
      Given 2 stable pkgs and keep_testing=5
      When retain_by_channel is called
      Then both stable pkgs are returned; no error from the empty testing bucket
    """
    d = tmp_path / "pkgs"
    d.mkdir()
    sv1 = _make_pkg_channel(d, "pfBlockerNG", "2.0.1")
    sv2 = _make_pkg_channel(d, "pfBlockerNG", "2.0.2")

    kept = brp.retain_by_channel([sv1, sv2], keep_testing=5, keep_stable=0)

    kept_nv = {(brp.read_compact_manifest(p)["name"], brp.read_compact_manifest(p)["version"]) for p in kept}
    assert kept_nv == {("pfBlockerNG", "2.0.1"), ("pfBlockerNG", "2.0.2")}
    assert len(kept) == 2


@pytest.mark.parametrize(
    ("keep_testing", "keep_stable"),
    [(-1, 1), (1, -1), (-1, -1)],
)
def test_retain_by_channel_rejects_negative_keep(tmp_path: Path, keep_testing: int, keep_stable: int) -> None:
    """A negative keep value is rejected up front (fail fast), not slice-applied silently.

    A negative ``keep`` would otherwise reach ``_retain_newest``'s ``[:keep]`` slice — e.g.
    ``keep=-1`` drops the NEWEST build instead of pruning the oldest — losing data with no
    error. ``retain_by_channel`` must raise ``BuildRepoError`` for any negative input.

    Scenario: 2 testing + 2 stable pkgs, one (or both) keep value negative
      Given a valid set of pkgs
      When retain_by_channel is called with a negative keep_testing and/or keep_stable
      Then it raises BuildRepoError (no silent slice, no partial result)
    """
    d = tmp_path / "pkgs"
    d.mkdir()
    dv1 = _make_pkg_channel(d, "pfBlockerNG-testing", "3.0.1")
    dv2 = _make_pkg_channel(d, "pfBlockerNG-testing", "3.0.2")
    sv1 = _make_pkg_channel(d, "pfBlockerNG", "2.0.1")
    sv2 = _make_pkg_channel(d, "pfBlockerNG", "2.0.2")

    # Positive control: the non-negative call DOES return (proves the inputs are valid and
    # only the negative value triggers the raise — not some unrelated failure).
    assert len(brp.retain_by_channel([dv1, dv2, sv1, sv2], keep_testing=1, keep_stable=1)) == 2

    with pytest.raises(brp.BuildRepoError, match=">= 0"):
        brp.retain_by_channel([dv1, dv2, sv1, sv2], keep_testing=keep_testing, keep_stable=keep_stable)


# --------------------------------------------------------------------------- #
# Issue #1676 slice 1: per-major/minor line-pin retention in retain_by_channel
#
# Spec (docs/specs/reversible-settings-transitions-v3-v4.md:189-192): each channel
# retains its newest-N rolling window PLUS the newest package of every major/minor
# LINE, so a version like v3.2.15 stays available after it ages out of the window.
# These tests cover: the union of window + pins, per-channel isolation (a testing
# pin can't satisfy stable), multi-patch lines (only the newest patch pins),
# prerelease version ordering, the keep=0/nightly no-op paths, and the malformed
# major/minor fail-closed guard.
# --------------------------------------------------------------------------- #


def test_retain_by_channel_line_pin_survives_outside_window(tmp_path: Path) -> None:
    """A line's newest package pins even after it ages out of the newest-N window.

    Scenario: one channel, 13 versions across 3 lines (3.0.x x2, 3.2.x x3, 4.0.x x8),
    keep=10 — the newest-10 window is by GLOBAL version order across all lines, so
    it covers all of 4.0.x (8) plus the 2 newest 3.2.x (3.2.15, 3.2.14).
      Given stable pkgs: 3.0.1, 3.0.2, 3.2.13, 3.2.14, 3.2.15, 4.0.0..4.0.7 (13 total)
        And keep_stable=10
      When retain_by_channel is called
      Then the newest-10 window keeps 4.0.0..4.0.7 (8) + 3.2.15 + 3.2.14 (2) = 10
       And 3.2.13 (aged out, NOT the newest of its line) is pruned
       And 3.0.2 (aged out, but IS the newest of the 3.0 line) survives as the pin
       And 3.0.1 (aged out, not the line's newest) is pruned
    """
    d = tmp_path / "pkgs"
    d.mkdir()
    versions = ["3.0.1", "3.0.2", "3.2.13", "3.2.14", "3.2.15"] + [f"4.0.{i}" for i in range(8)]
    assert len(versions) == 13
    paths = {v: _make_pkg_channel(d, "pfBlockerNG", v) for v in versions}

    kept = brp.retain_by_channel(list(paths.values()), keep_testing=0, keep_stable=10)
    kept_versions = {brp.read_compact_manifest(p)["version"] for p in kept}

    # Window: newest 10 by global version order = 4.0.0..4.0.7, 3.2.15, 3.2.14.
    for v in [f"4.0.{i}" for i in range(8)] + ["3.2.15", "3.2.14"]:
        assert v in kept_versions, v
    # 3.2.13 is aged out AND not its line's newest -> pruned.
    assert "3.2.13" not in kept_versions
    # 3.0.2 is aged out but IS its line's newest -> survives as the pin.
    assert "3.0.2" in kept_versions
    # 3.0.1 is aged out and not its line's newest -> pruned.
    assert "3.0.1" not in kept_versions
    assert len(kept_versions) == 11  # 10-window + 1 pin (3.2.15/3.2.14 already in window)


def test_retain_by_channel_line_pin_is_channel_specific(tmp_path: Path) -> None:
    """The spec's named case: v3.2.15 Stable and v3.2.16 Testing both pin, independently.

    Scenario: Stable pfBlockerNG-3.2.15 and Testing pfBlockerNG-testing-3.2.16, both far
    outside a keep=1 window built from many newer versions in each channel.
      Given a Stable channel: 3.2.15 (old) + 5 newer 5.0.x releases; keep_stable=1
        And a Testing channel: 3.2.16 (old) + 5 newer 5.0.x testing builds; keep_testing=1
      When retain_by_channel is called
      Then BOTH 3.2.15 (stable) and 3.2.16 (testing) survive as their channel's 3.2 pin
       And neither channel's pin satisfies the other (no cross-channel leakage)
    """
    d = tmp_path / "pkgs"
    d.mkdir()
    stable_old = _make_pkg_channel(d, "pfBlockerNG", "3.2.15")
    stable_new = [_make_pkg_channel(d, "pfBlockerNG", f"5.0.{i}") for i in range(5)]
    testing_old = _make_pkg_channel(d, "pfBlockerNG-testing", "3.2.16")
    testing_new = [_make_pkg_channel(d, "pfBlockerNG-testing", f"5.0.{i}") for i in range(5)]

    kept = brp.retain_by_channel([stable_old, *stable_new, testing_old, *testing_new], keep_testing=1, keep_stable=1)
    kept_nv = {(brp.read_compact_manifest(p)["name"], brp.read_compact_manifest(p)["version"]) for p in kept}

    assert ("pfBlockerNG", "3.2.15") in kept_nv
    assert ("pfBlockerNG-testing", "3.2.16") in kept_nv
    # Each channel's window (newest 1) plus its own 3.2 pin only — no cross bleed.
    assert ("pfBlockerNG", "5.0.4") in kept_nv
    assert ("pfBlockerNG-testing", "5.0.4") in kept_nv
    assert len(kept_nv) == 4


def test_retain_by_channel_line_pin_keeps_only_newest_patch(tmp_path: Path) -> None:
    """Multiple aged-out patches in one line: only the newest patch pins; older follow the window.

    Scenario: 3.2.13, 3.2.14, 3.2.15 all in one old line, plus enough 5.0.x to push
    all three out of a keep=2 window.
      Given stable pkgs 3.2.13, 3.2.14, 3.2.15, 5.0.0, 5.0.1; keep_stable=2
      When retain_by_channel is called
      Then the window keeps 5.0.1, 5.0.0
       And ONLY 3.2.15 (the line's newest) pins
       And 3.2.14 and 3.2.13 are pruned (rolling policy, not the line's newest)
    """
    d = tmp_path / "pkgs"
    d.mkdir()
    p13 = _make_pkg_channel(d, "pfBlockerNG", "3.2.13")
    p14 = _make_pkg_channel(d, "pfBlockerNG", "3.2.14")
    p15 = _make_pkg_channel(d, "pfBlockerNG", "3.2.15")
    p50_0 = _make_pkg_channel(d, "pfBlockerNG", "5.0.0")
    p50_1 = _make_pkg_channel(d, "pfBlockerNG", "5.0.1")

    kept = brp.retain_by_channel([p13, p14, p15, p50_0, p50_1], keep_testing=0, keep_stable=2)
    kept_versions = {brp.read_compact_manifest(p)["version"] for p in kept}

    assert kept_versions == {"5.0.1", "5.0.0", "3.2.15"}


def test_retain_by_channel_line_pin_uses_pkg_version_order_for_prerelease(tmp_path: Path) -> None:
    """The line pin picks the newest by pkg version order, not lexical order.

    Scenario: an old 4.0 line with alpha.9 and alpha.10 (lexically "10" < "9"),
    pushed out of the window by newer 5.0.x releases.
      Given testing pkgs 4.0.0.alpha.9, 4.0.0.alpha.10, 5.0.0, 5.0.1; keep_testing=2
      When retain_by_channel is called
      Then the window keeps 5.0.1, 5.0.0
       And the 4.0 pin is 4.0.0.alpha.10 (pkg version order), NOT alpha.9
    """
    d = tmp_path / "pkgs"
    d.mkdir()
    a9 = _make_pkg_channel(d, "pfBlockerNG-testing", "4.0.0.alpha.9")
    a10 = _make_pkg_channel(d, "pfBlockerNG-testing", "4.0.0.alpha.10")
    n0 = _make_pkg_channel(d, "pfBlockerNG-testing", "5.0.0")
    n1 = _make_pkg_channel(d, "pfBlockerNG-testing", "5.0.1")

    kept = brp.retain_by_channel([a9, a10, n0, n1], keep_testing=2, keep_stable=0)
    kept_versions = {brp.read_compact_manifest(p)["version"] for p in kept}

    assert kept_versions == {"5.0.1", "5.0.0", "4.0.0.alpha.10"}
    assert "4.0.0.alpha.9" not in kept_versions


def test_retain_by_channel_keep_zero_sentinel_unaffected_by_line_pins(tmp_path: Path) -> None:
    """keep==0 (unbounded) still keeps everything; line pins are moot (nothing pruned).

    Extends the existing sentinel coverage: a multi-line pool under keep=0 must not
    trip the malformed-version guard or drop anything — the pin path is never entered
    because nothing is pruned.
    """
    d = tmp_path / "pkgs"
    d.mkdir()
    all_paths = [_make_pkg_channel(d, "pfBlockerNG", v) for v in ["3.0.1", "3.2.15", "5.0.0", "5.0.1"]]

    kept = brp.retain_by_channel(all_paths, keep_testing=0, keep_stable=0)

    assert len(kept) == 4


def test_retain_by_channel_nightly_never_gets_line_pins(tmp_path: Path) -> None:
    """Nightly is passed through untouched — no line-pin logic applies to it at all.

    A nightly VERSION (<target>.YYYYMMDD.N) has no major/minor line concept; if pin
    logic ever leaked into the nightly path it would either misbucket (numeric date
    treated as a line) or crash on the malformed-version guard. Assert nightly count
    is exactly the input count, unchanged, even with a testing/stable prune alongside.
    """
    d = tmp_path / "pkgs"
    d.mkdir()
    dv = _make_pkg_channel(d, "pfBlockerNG-testing", "3.0.1")
    sv = _make_pkg_channel(d, "pfBlockerNG", "2.0.1")
    nightlies = [_make_pkg_channel(d, "pfBlockerNG-nightly", f"amd64.2026060{i}.1") for i in range(1, 4)]

    kept = brp.retain_by_channel([dv, sv, *nightlies], keep_testing=1, keep_stable=1)
    kept_nightly_versions = {
        brp.read_compact_manifest(p)["version"]
        for p in kept
        if brp.read_compact_manifest(p)["name"] == "pfBlockerNG-nightly"
    }

    assert kept_nightly_versions == {f"amd64.2026060{i}.1" for i in range(1, 4)}


def test_retain_by_channel_malformed_line_version_raises(tmp_path: Path) -> None:
    """A malformed major/minor version fails closed with BuildRepoError, never silent misbucketing.

    ``_pkg_version_key``/``pkg_version_sort_key`` maps any non-numeric component to
    ``0`` for SORT stability (never raises) — so a garbage version like "weird" would
    otherwise silently land in some bucket rather than being rejected. The line-pin
    parse is stricter: it must fail closed and name the offending package.

    Scenario: a pool that needs pruning (so the line-pin path actually runs) contains
    one package with an unparseable version.
      Given stable pkgs 1.0.0, 2.0.0, 3.0.0 (valid) + "garbage-weird" (malformed); keep_stable=1
      When retain_by_channel is called
      Then BuildRepoError is raised, naming the malformed package
    """
    d = tmp_path / "pkgs"
    d.mkdir()
    p1 = _make_pkg_channel(d, "pfBlockerNG", "1.0.0")
    p2 = _make_pkg_channel(d, "pfBlockerNG", "2.0.0")
    p3 = _make_pkg_channel(d, "pfBlockerNG", "3.0.0")
    bad = _make_pkg_channel(d, "pfBlockerNG", "weird")

    with pytest.raises(brp.BuildRepoError, match="weird"):
        brp.retain_by_channel([p1, p2, p3, bad], keep_testing=0, keep_stable=1)


def test_retain_by_channel_line_pin_determinism(tmp_path: Path) -> None:
    """Two runs over the same multi-line pool produce byte-identical (path-set) results.

    Extends the existing version-order-determinism coverage to the line-pin path:
    the pin selection must not depend on dict/set iteration order.
    """
    d = tmp_path / "pkgs"
    d.mkdir()
    versions = ["3.0.1", "3.0.2", "3.2.13", "3.2.14", "3.2.15"] + [f"4.0.{i}" for i in range(8)]
    paths = [_make_pkg_channel(d, "pfBlockerNG", v) for v in versions]

    kept1 = brp.retain_by_channel(list(paths), keep_testing=0, keep_stable=10)
    kept2 = brp.retain_by_channel(list(reversed(paths)), keep_testing=0, keep_stable=10)

    assert {p.name for p in kept1} == {p.name for p in kept2}
    assert len(kept1) == len(kept2) == 11


def test_retain_by_channel_duplicate_identity_resolves_to_one_path(tmp_path: Path) -> None:
    """A same-(name, version) duplicate pair (tied mtime) must resolve to the SAME
    file for both the window (_retain_newest) and the line pin (_line_pins) —
    the retained set holds one path for that identity, never two.

    Regression guard: both helpers dedup on a first-wins tie-break (`>`, strict).
    They agree only because they iterate the same bucket in the same order with
    the same strictness. If _line_pins' tie-break ever flips to `>=`, it keeps the
    LAST-processed file on a tie while _retain_newest (unchanged) keeps the FIRST —
    two distinct files for one (name, version) then both reach _check_collisions
    (which runs before _emit_catalog_from_paths' own dedup), aborting the build
    with a false FLAVOR COLLISION whenever the duplicates happen to differ in
    php/py flavor.

    Scenario: one (name, version) identity, two files, tied mtime
      Given two .pkg files for pfBlockerNG-testing 3.0.1 with identical mtime
        And keep_testing=1 (keep < bucket size, so the window+line-pin union runs)
      When retain_by_channel is called
      Then exactly one path is retained for that identity
       And it is the first-processed file (deterministic first-wins tie-break)
    """
    d = tmp_path / "pkgs"
    d.mkdir()
    first = _make_pkg_channel(d, "pfBlockerNG-testing", "3.0.1")
    duplicate = d / "pfBlockerNG-testing-3.0.1-dup.pkg"
    make_pkg(duplicate, name="pfBlockerNG-testing", version="3.0.1", abi="FreeBSD:15:amd64")
    # Force an exact tie: without it, the higher-mtime file would legitimately win
    # in both helpers and the test would prove nothing about the tie-break itself.
    tie_mtime = first.stat().st_mtime
    os.utime(duplicate, (tie_mtime, tie_mtime))

    kept = brp.retain_by_channel([first, duplicate], keep_testing=1, keep_stable=0)

    assert len(kept) == 1, f"one (name, version) identity must resolve to one file, got {len(kept)}: {kept}"
    assert kept[0] == first, "first-processed file must win the tie deterministically"


# --------------------------------------------------------------------------- #
# ADR-27 Phase 2: release-subtree retention in build_repo_matrix
#
# These tests pin the retention behaviour of the release subtree:
#   * defaults (release_keep_testing=1, release_keep_stable=1) reproduce today's
#     latest-only output — the BEFORE state (inert change)
#   * with N=M=3 and 4 of each channel provided, the catalog lists exactly the
#     newest 3 of each — the 4th is absent (AFTER state)
#   * newest-wins: pkg install <name> (no version) still gets the highest version
#     across all retained entries (contract §2.2.2)
#   * generator drift pins (conf bytes) still hold
# --------------------------------------------------------------------------- #


def _catalog_objects(catalog_pkg: Path) -> list[dict]:
    """Return all packagesite NDJSON objects from a catalog .pkg."""
    raw = _read_member(catalog_pkg, "packagesite.yaml").decode()
    return [json.loads(ln) for ln in raw.splitlines() if ln]


def _versions_in_release(catalog_pkg: Path) -> set[str]:
    return {o["version"] for o in _catalog_objects(catalog_pkg)}


def _names_versions_in_release(catalog_pkg: Path) -> set[tuple[str, str]]:
    return {(o["name"], o["version"]) for o in _catalog_objects(catalog_pkg)}


def test_release_default_is_latest_only(tmp_path: Path) -> None:
    """Defaults (release_keep_testing=1, release_keep_stable=1) produce exactly one testing +
    one stable in the release catalog — the BEFORE state (latest-only retention).

    Scenario: default keep values with testing + stable
      Given build_repo_matrix with NO release_extra_pkgs and default keep values
        And a stable tag is set (so one stable is built)
      When the matrix runs
      Then the release catalog lists exactly ONE testing version (before-state)
       And exactly ONE stable version (before-state)
       And the total entry count is 2
    """
    out = tmp_path / "site"

    # Before-state: no release dir yet.
    assert not (out / "release").exists()

    brp.build_repo_matrix([_CE], out, builder=_stub_builder, stable_tag="v3.2.15")

    rel = out / "release" / "ce-2.8" / "packagesite.pkg"
    assert rel.is_file()

    objs = _catalog_objects(rel)
    names = {o["name"] for o in objs}

    # Exactly one testing + one stable (latest-only — the before/default state).
    assert "pfBlockerNG-testing" in names
    assert "pfBlockerNG" in names
    assert "pfBlockerNG-edge" in names
    assert len(objs) == 3


def test_release_subtree_retains_testing_and_stable(tmp_path: Path) -> None:
    """With release_keep_testing=3, release_keep_stable=3 and 4 of each provided,
    the catalog lists the newest 3 of each channel — the 4th (oldest) is absent.

    Scenario: retention depth 3, 4 candidates per channel
      Given 4 pre-built testing pkgs (versions 3.0.1..3.0.4)
        And 4 pre-built stable pkgs (versions 2.0.1..2.0.4)
        And release_keep_testing=3, release_keep_stable=3
      When build_repo_matrix runs with those extra pkgs + the fresh build
      Then testing: versions 3.0.2, 3.0.3, 3.0.4 are in the catalog
       And testing: version 3.0.1 (the oldest) is NOT in the catalog
       And stable: versions 2.0.2, 2.0.3, 2.0.4 are in the catalog
       And stable: version 2.0.1 (the oldest) is NOT in the catalog
    """
    extras = tmp_path / "extras"
    extras.mkdir()
    abi = "FreeBSD:15:*"

    # 4 pre-built testing candidates (the fresh build will be version "1.0_1" from the
    # stub, so all 4 extras sit below "1.0_1" as older versions). Use 3.0.1..3.0.4 as
    # clearly ordered versions to make the test readable.
    testing_extras = [_make_pkg_channel(extras, "pfBlockerNG-testing", f"3.0.{i}", abi=abi) for i in range(1, 5)]
    # 4 pre-built stable candidates.
    stable_extras = [_make_pkg_channel(extras, "pfBlockerNG", f"2.0.{i}", abi=abi) for i in range(1, 5)]

    all_extras = testing_extras + stable_extras

    # Before-state: with defaults (keep=1), only the freshest 1 of each is kept.
    out_before = tmp_path / "before"
    brp.build_repo_matrix(
        [_CE],
        out_before,
        builder=_stub_builder,
        stable_tag="v3.2.15",
        release_extra_pkgs=all_extras,
        release_keep_testing=1,
        release_keep_stable=1,
    )
    rel_before = out_before / "release" / "ce-2.8" / "packagesite.pkg"
    objs_before = _catalog_objects(rel_before)
    # Testing and Stable each keep 1 window entry + 1 line pin; Edge keeps 1.
    # The stub's fresh build is version "1.0_1", a major/minor line ("1.0")
    # distinct from the 3.0.x/2.0.x extras, so it survives as that line's pin.
    assert len(objs_before) == 5

    # After-state: with keep=3, the newest 3 of each channel are retained.
    out = tmp_path / "site"
    brp.build_repo_matrix(
        [_CE],
        out,
        builder=_stub_builder,
        stable_tag="v3.2.15",
        release_extra_pkgs=all_extras,
        release_keep_testing=3,
        release_keep_stable=3,
    )
    rel = out / "release" / "ce-2.8" / "packagesite.pkg"
    nv_set = _names_versions_in_release(rel)

    # Testing: 3.0.2, 3.0.3, 3.0.4 present; 3.0.1 dropped (4th/oldest).
    assert ("pfBlockerNG-testing", "3.0.4") in nv_set
    assert ("pfBlockerNG-testing", "3.0.3") in nv_set
    assert ("pfBlockerNG-testing", "3.0.2") in nv_set
    assert ("pfBlockerNG-testing", "3.0.1") not in nv_set

    # Stable: 2.0.2, 2.0.3, 2.0.4 present; 2.0.1 dropped.
    assert ("pfBlockerNG", "2.0.4") in nv_set
    assert ("pfBlockerNG", "2.0.3") in nv_set
    assert ("pfBlockerNG", "2.0.2") in nv_set
    assert ("pfBlockerNG", "2.0.1") not in nv_set


def test_release_catalog_lists_all_kept_versions(tmp_path: Path) -> None:
    """The release packagesite NDJSON has one object per (name, version) kept —
    newest is still the highest version (newest-wins default, contract §2.2.2).

    Scenario: multi-version catalog integrity
      Given release_keep_testing=2, release_keep_stable=2, 3 of each provided as extras
        And a fresh testing build (the stub produces version "1.0_1")
        And the newest extras are 3.0.3 (testing) and 2.0.3 (stable)
      When build_repo_matrix runs
      Then the catalog has exactly 7 objects: 2-window + 1 line-pin testing,
        2-window + 1 line-pin stable, and 1 edge (the stub's fresh build "1.0_1"
        is its own major/minor line "1.0", distinct from the 3.0.x/2.0.x extras,
        so it survives as that line's pin alongside the newest-2 window)
       And the highest-version testing object is at least 3.0.3
       And the highest-version stable object is at least 2.0.3
       And every kept (name, version) pair appears exactly once (no duplicates)
    """
    extras = tmp_path / "extras"
    extras.mkdir()
    abi = "FreeBSD:15:*"

    # 3 extras each channel; with keep=2 only the newest 2 survive per channel.
    testing_extras = [_make_pkg_channel(extras, "pfBlockerNG-testing", f"3.0.{i}", abi=abi) for i in range(1, 4)]
    stable_extras = [_make_pkg_channel(extras, "pfBlockerNG", f"2.0.{i}", abi=abi) for i in range(1, 4)]

    out = tmp_path / "site"
    brp.build_repo_matrix(
        [_CE],
        out,
        builder=_stub_builder,
        stable_tag="v3.2.15",
        release_extra_pkgs=testing_extras + stable_extras,
        release_keep_testing=2,
        release_keep_stable=2,
    )

    rel = out / "release" / "ce-2.8" / "packagesite.pkg"
    objs = _catalog_objects(rel)

    # 7 catalog entries: (2-window + 1 line-pin) testing + (2-window + 1 line-pin)
    # stable + 1 edge.
    # The stub's fresh build ("1.0_1") is its own major/minor line ("1.0"), distinct
    # from the 3.0.x/2.0.x extras, so it survives as that line's pin alongside the
    # newest-2 window.
    assert len(objs) == 7

    testing_objs = [o for o in objs if o["name"] == "pfBlockerNG-testing"]
    edge_objs = [o for o in objs if o["name"] == "pfBlockerNG-edge"]
    stable_objs = [o for o in objs if o["name"] == "pfBlockerNG"]
    assert len(testing_objs) == 3
    assert len(edge_objs) == 1
    assert len(stable_objs) == 3

    # No duplicate (name, version) pairs.
    nv_list = [(o["name"], o["version"]) for o in objs]
    assert len(nv_list) == len(set(nv_list)), "duplicate (name, version) pair in catalog"

    # Newest-wins: the highest testing version in the catalog is 3.0.3 (the extras newest).
    testing_versions = sorted(
        [brp._pkg_version_key(o["version"]) for o in testing_objs],
        reverse=True,
    )
    stable_versions = sorted(
        [brp._pkg_version_key(o["version"]) for o in stable_objs],
        reverse=True,
    )
    # The retained top versions must be at least 3.0.3 and 2.0.3 respectively.
    assert testing_versions[0] >= brp._pkg_version_key("3.0.3")
    assert stable_versions[0] >= brp._pkg_version_key("2.0.3")


# --------------------------------------------------------------------------- #
# ADR-27 Phase 3: CLI dry-run — --release-extra-pkgs end-to-end
#
# These tests exercise the DOCUMENTED PUBLISH.YML INPUT PATH through the CLI
# (brp.main([...])) rather than the Python API, so the actual command-line
# wiring (argparse → extra_pkgs conversion → build_repo_matrix) is proven.
#
# Pattern: synthetic testing_1..4 + stable_1..4 passed as --release-extra-pkgs;
# --release-keep-testing / --release-keep-stable assert that the catalog holds
# exactly the newest N/M and the oldest candidate is absent. Before-and-after
# assertions confirm the pruning is genuine, not a coincidental match.
# --------------------------------------------------------------------------- #


def _with_stub_builder(monkeypatch: pytest.MonkeyPatch) -> None:
    """Patch brp.build_repo_matrix so CLI calls use _stub_builder (no subprocess)."""
    _real = brp.build_repo_matrix

    def _patched(matrix: list[dict], out_dir: Path, **kw: Any) -> dict:
        kw.setdefault("builder", _stub_builder)
        return _real(matrix, out_dir, **kw)

    monkeypatch.setattr(brp, "build_repo_matrix", _patched)


def test_cli_release_extra_pkgs_default_keeps_latest_plus_line_pins(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """CLI defaults (--release-keep-testing 1, --release-keep-stable 1) keep only the
    latest release PER CHANNEL WINDOW when --release-extra-pkgs carry older versions
    too — plus any major/minor line pin outside that window (issue #1676).

    Scenario: CLI latest-only default with older extras supplied
      Given 3 pre-built testing extras (3.0.1, 3.0.2, 3.0.3) passed via --release-extra-pkgs
        And 3 pre-built stable extras (2.0.1, 2.0.2, 2.0.3) passed via --release-extra-pkgs
        And no --release-keep-testing / --release-keep-stable override (default 1)
      When brp.main([--build-matrix, ...]) is called
      Then the release catalog has exactly 2 testing entries: the 1-window entry
        plus the stub's own fresh build as a line pin (its version "1.0_1" is
        major/minor line "1.0", distinct from the 3.0.x extras)
       And the release catalog has exactly 1 stable entry (no --stable-tag on this
        CLI path, so no fresh build and no phantom pin)
       And the highest-version testing (3.0.3) is the one retained by the window
       And the highest-version stable (2.0.3) is the one retained
    """
    _with_stub_builder(monkeypatch)

    extras = tmp_path / "extras"
    extras.mkdir()
    testing_extras = [_make_pkg_channel(extras, "pfBlockerNG-testing", f"3.0.{i}") for i in range(1, 4)]
    stable_extras = [_make_pkg_channel(extras, "pfBlockerNG", f"2.0.{i}") for i in range(1, 4)]

    # Before-state: confirm the extra pkgs exist and span all 6 versions.
    assert len(testing_extras) == 3
    assert len(stable_extras) == 3

    out = tmp_path / "site"
    mfile = tmp_path / "matrix.json"
    mfile.write_text(json.dumps({"versions": [_CE]}))

    extra_flags: list[str] = []
    for p in testing_extras + stable_extras:
        extra_flags += ["--release-extra-pkgs", str(p)]

    rc = brp.main(
        [
            "--build-matrix",
            "--matrix-json",
            str(mfile),
            "--out",
            str(out),
            "--no-nightly",
            # No --release-keep-testing / --release-keep-stable  → default 1
        ]
        + extra_flags
    )
    assert rc == 0

    rel = out / "release" / "ce-2.8" / "packagesite.pkg"
    assert rel.is_file()
    objs = _catalog_objects(rel)

    testing_objs = [o for o in objs if o["name"] == "pfBlockerNG-testing"]
    stable_objs = [o for o in objs if o["name"] == "pfBlockerNG"]

    # Before-state (default keep=1): testing gets the 1-window entry PLUS the stub's own
    # fresh build as a line pin ("1.0_1" is major/minor line "1.0", distinct from the
    # 3.0.x extras). No --stable-tag is passed on this CLI path, so no stable build is
    # produced — stable stays a plain 1-window result (no phantom pin).
    assert len(testing_objs) == 2, f"expected 2 testing (window + line pin), got {len(testing_objs)}"
    assert len(stable_objs) == 1, f"expected 1 stable, got {len(stable_objs)}"

    # The window's retained entry is the highest-version one (newest-wins).
    testing_versions = {o["version"] for o in testing_objs}
    assert "3.0.3" in testing_versions
    assert stable_objs[0]["version"] >= "2.0.3"


def test_cli_release_extra_pkgs_keeps_newest_n(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The CLI correctly prunes to newest N/M when --release-keep-testing/stable are set.

    Scenario: retention depth 3, 4 candidates per channel via CLI
      Given 4 pre-built testing extras (3.0.1..3.0.4) passed as --release-extra-pkgs
        And 4 pre-built stable extras (2.0.1..2.0.4) passed as --release-extra-pkgs
        And --release-keep-testing 3, --release-keep-stable 3
      When brp.main([--build-matrix, ...]) is called
      Then the release catalog has exactly 4 testing entries: the 3-window plus
        1 line pin (the stub's "1.0_1" fresh build, its own major/minor line)
       And the release catalog has exactly 3 stable entries (no fresh build on
        this CLI path, so a plain 3-window, no phantom pin)
       And the oldest testing (3.0.1) is absent from the catalog
       And the oldest stable (2.0.1) is absent from the catalog
       And the 3 newest testing versions (3.0.2, 3.0.3, 3.0.4) are present
       And the 3 newest stable versions (2.0.2, 2.0.3, 2.0.4) are present
    """
    _with_stub_builder(monkeypatch)

    extras = tmp_path / "extras"
    extras.mkdir()
    testing_extras = [_make_pkg_channel(extras, "pfBlockerNG-testing", f"3.0.{i}") for i in range(1, 5)]
    stable_extras = [_make_pkg_channel(extras, "pfBlockerNG", f"2.0.{i}") for i in range(1, 5)]

    out = tmp_path / "site"
    mfile = tmp_path / "matrix.json"
    mfile.write_text(json.dumps({"versions": [_CE]}))

    extra_flags: list[str] = []
    for p in testing_extras + stable_extras:
        extra_flags += ["--release-extra-pkgs", str(p)]

    # Before-state: with default keep=1 only 1 testing + 1 stable appear.
    out_before = tmp_path / "before"
    mfile_before = tmp_path / "matrix_before.json"
    mfile_before.write_text(json.dumps({"versions": [_CE]}))
    rc_before = brp.main(
        [
            "--build-matrix",
            "--matrix-json",
            str(mfile_before),
            "--out",
            str(out_before),
            "--no-nightly",
        ]
        + extra_flags
    )
    assert rc_before == 0
    before_objs = _catalog_objects(out_before / "release" / "ce-2.8" / "packagesite.pkg")
    before_testing = [o for o in before_objs if o["name"] == "pfBlockerNG-testing"]
    before_stable = [o for o in before_objs if o["name"] == "pfBlockerNG"]
    # No --stable-tag on this CLI path, so only testing gets a fresh build: default
    # keep=1 window + the stub fresh build's own line pin ("1.0_1" is line "1.0",
    # distinct from the 3.0.x extras). Stable has no fresh build, so no phantom pin.
    assert len(before_testing) == 2, "before-state: default keep=1 must yield 1 window + 1 line pin testing"
    assert len(before_stable) == 1, "before-state: default keep=1 must yield exactly 1 stable"

    # After-state: with keep=3 the catalog lists 3 testing + 3 stable.
    rc = brp.main(
        [
            "--build-matrix",
            "--matrix-json",
            str(mfile),
            "--out",
            str(out),
            "--no-nightly",
            "--release-keep-testing",
            "3",
            "--release-keep-stable",
            "3",
        ]
        + extra_flags
    )
    assert rc == 0

    rel = out / "release" / "ce-2.8" / "packagesite.pkg"
    assert rel.is_file()
    objs = _catalog_objects(rel)
    nv = {(o["name"], o["version"]) for o in objs}

    testing_objs = [o for o in objs if o["name"] == "pfBlockerNG-testing"]
    stable_objs = [o for o in objs if o["name"] == "pfBlockerNG"]

    # After-state: testing = 3-window + 1 line pin (the stub's "1.0_1" fresh build) = 4;
    # stable has no fresh build on this CLI path, so it's a plain 3-window = 3.
    assert len(testing_objs) == 4, f"expected 4 testing after (window + line pin), got {len(testing_objs)}"
    assert len(stable_objs) == 3, f"expected 3 stable after, got {len(stable_objs)}"

    # Oldest excluded.
    assert ("pfBlockerNG-testing", "3.0.1") not in nv, "oldest testing must be pruned"
    assert ("pfBlockerNG", "2.0.1") not in nv, "oldest stable must be pruned"

    # Newest 3 present.
    for v in ("3.0.2", "3.0.3", "3.0.4"):
        assert ("pfBlockerNG-testing", v) in nv, f"testing {v} must be retained"
    for v in ("2.0.2", "2.0.3", "2.0.4"):
        assert ("pfBlockerNG", v) in nv, f"stable {v} must be retained"


def test_cli_release_extra_pkgs_newest_wins(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """With multiple retained testing versions the highest version ranks first (newest-wins).

    Scenario: pkg install <name> without version must resolve to the highest kept version
      Given 4 testing extras (3.0.1..3.0.4) and keep=2
        And 4 stable extras (2.0.1..2.0.4) and keep=2
      When brp.main([--build-matrix, ...]) is called
      Then the catalog lists exactly 3 testing entries (2-window + 1 line pin,
        the stub's "1.0_1" fresh build on its own line) and 2 stable entries
        (no fresh build on this CLI path, so a plain 2-window, no phantom pin)
       And the highest testing version in the catalog is >= 3.0.4 (newest-wins)
       And the highest stable version in the catalog is >= 2.0.4 (newest-wins)
       And no (name, version) pair is duplicated in the catalog
    """
    _with_stub_builder(monkeypatch)

    extras = tmp_path / "extras"
    extras.mkdir()
    testing_extras = [_make_pkg_channel(extras, "pfBlockerNG-testing", f"3.0.{i}") for i in range(1, 5)]
    stable_extras = [_make_pkg_channel(extras, "pfBlockerNG", f"2.0.{i}") for i in range(1, 5)]

    out = tmp_path / "site"
    mfile = tmp_path / "matrix.json"
    mfile.write_text(json.dumps({"versions": [_CE]}))

    extra_flags: list[str] = []
    for p in testing_extras + stable_extras:
        extra_flags += ["--release-extra-pkgs", str(p)]

    rc = brp.main(
        [
            "--build-matrix",
            "--matrix-json",
            str(mfile),
            "--out",
            str(out),
            "--no-nightly",
            "--release-keep-testing",
            "2",
            "--release-keep-stable",
            "2",
        ]
        + extra_flags
    )
    assert rc == 0

    rel = out / "release" / "ce-2.8" / "packagesite.pkg"
    objs = _catalog_objects(rel)

    testing_objs = [o for o in objs if o["name"] == "pfBlockerNG-testing"]
    stable_objs = [o for o in objs if o["name"] == "pfBlockerNG"]

    # testing = 2-window + 1 line pin (the stub's "1.0_1" fresh build, its own line "1.0") = 3.
    # No --stable-tag on this CLI path, so stable has no fresh build: plain 2-window.
    assert len(testing_objs) == 3
    assert len(stable_objs) == 2

    # No duplicate (name, version) pairs.
    nv_list = [(o["name"], o["version"]) for o in objs]
    assert len(nv_list) == len(set(nv_list)), "duplicate (name, version) pair in catalog"

    # Newest-wins: highest version in the retained set is >= 3.0.4 / 2.0.4.
    testing_top = max(brp._pkg_version_key(o["version"]) for o in testing_objs)
    stable_top = max(brp._pkg_version_key(o["version"]) for o in stable_objs)
    assert testing_top >= brp._pkg_version_key("3.0.4")
    assert stable_top >= brp._pkg_version_key("2.0.4")


# --------------------------------------------------------------------------- #
# ADR-27 Phase 7: route-only catalog generation from frozen .pkg
#
# A route-only entry (role="route-only") is an EOL pfSense version whose last
# .pkg is served from a frozen GitHub Release asset — no fresh build, no nightly.
#
# These tests pin every guarantee of the route-only path:
#   * release/<varver>/ catalog lists exactly the frozen .pkg version(s)
#   * NO nightly/<varver>/ subtree ever exists for a route-only entry
#   * build-entry parity: with route-only entries added, the build entry's release
#     + nightly subtrees are BYTE-IDENTICAL to a run without the route-only entries
#     (proves route-only is purely additive — not a regression)
#   * a route-only entry with no frozen .pkg provided raises BuildRepoError (fail
#     loud — never emit an empty or stale catalog for an EOL version)
# --------------------------------------------------------------------------- #

# EOL CE entry (pfSense 2.7, FreeBSD 14, PHP 8.2) — route-only role.
_CE_EOL = {
    "pfsense_version": "2.7",
    "variant": "CE",
    "freebsd_major": "14",
    "php_version": "8.2",
    "py_flavor": "py311",
    "status": "EOL",
    "arch": "amd64",
    "role": "route-only",
}
# EOL Plus entry (Plus 25.03, FreeBSD 15, PHP 8.3) — route-only role.
_PLUS_EOL = {
    "pfsense_version": "25.03",
    "variant": "Plus",
    "freebsd_major": "15",
    "php_version": "8.3",
    "py_flavor": "py311",
    "status": "EOL",
    "arch": "amd64",
    "role": "route-only",
}


def test_route_only_release_catalog_contains_exactly_frozen_pkg(tmp_path: Path) -> None:
    """A route-only entry's release catalog lists ONLY the frozen .pkg, nothing else.

    Scenario: EOL CE 2.7 with one frozen .pkg
      Given a frozen CE 2.7 .pkg (version 3.1.0_5) in route_only_pkgs
       When build_repo_matrix runs with role=route-only for CE 2.7
      Then release/ce-2.7/packagesite.pkg lists exactly that one package
       And the name is pfBlockerNG-testing and the version is 3.1.0_5
    """
    out = tmp_path / "site"
    frozen_pkg = tmp_path / "frozen" / "pfBlockerNG-testing-3.1.0_5.pkg"
    frozen_pkg.parent.mkdir()
    make_pkg(frozen_pkg, name="pfBlockerNG-testing", version="3.1.0_5", abi="FreeBSD:14:*")

    # Before-state: no release subtree yet.
    assert not (out / "release" / "ce-2.7").exists()

    brp.build_repo_matrix(
        [_CE_EOL],
        out,
        builder=_stub_builder,
        route_only_pkgs={"ce-2.7": [frozen_pkg]},
    )

    rel = out / "release" / "ce-2.7" / "packagesite.pkg"
    assert rel.is_file(), "release catalog must exist for a route-only entry"
    objs = _catalog_objects(rel)

    # Exactly one entry, the frozen .pkg.
    assert len(objs) == 1
    assert objs[0]["name"] == "pfBlockerNG-testing"
    assert objs[0]["version"] == "3.1.0_5"


def test_route_only_no_nightly_subtree(tmp_path: Path) -> None:
    """A route-only entry NEVER produces a nightly/ subtree.

    Scenario: EOL CE 2.7 + active CE 2.8 — build_nightly=True (default)
      Given route-only CE 2.7 and build CE 2.8
       When build_repo_matrix runs (build_nightly=True)
      Then nightly/ce-2.7/ does NOT exist  (route-only: no nightly — ever)
       And nightly/ce-2.8/ DOES exist      (build entry: nightly built as normal)
    """
    out = tmp_path / "site"
    frozen_pkg = tmp_path / "frozen" / "pfBlockerNG-testing-3.1.0_5.pkg"
    frozen_pkg.parent.mkdir()
    make_pkg(frozen_pkg, name="pfBlockerNG-testing", version="3.1.0_5", abi="FreeBSD:14:*")

    # Before-state: neither nightly subtree exists.
    assert not (out / "nightly" / "ce-2.7").exists()
    assert not (out / "nightly" / "ce-2.8").exists()

    brp.build_repo_matrix(
        [_CE_EOL, _CE],
        out,
        builder=_stub_builder,
        route_only_pkgs={"ce-2.7": [frozen_pkg]},
    )

    # Route-only entry: NO nightly subtree.
    assert not (out / "nightly" / "ce-2.7").exists(), "route-only must never produce a nightly/"
    # Build entry: nightly subtree present as normal.
    assert (out / "nightly" / "ce-2.8" / "meta.conf").is_file()


def test_route_only_additive_parity_build_entry_unchanged(tmp_path: Path) -> None:
    """Adding route-only entries leaves build-entry subtrees BYTE-IDENTICAL.

    Scenario: before = CE 2.8 (build) only; after = CE 2.8 + CE 2.7 (route-only)
      Given build_repo_matrix([CE 2.8]) -> capture release + nightly catalogs for ce-2.8
       When re-run with the same CE 2.8 + route-only CE 2.7 added
      Then release/ce-2.8/ catalog bytes == before bytes
       And nightly/ce-2.8/ catalog bytes == before bytes
      (route-only is purely additive — no regression on the build path)
    """
    out = tmp_path / "site"
    frozen_ce = tmp_path / "frozen_ce" / "pfBlockerNG-testing-3.1.0_5.pkg"
    frozen_ce.parent.mkdir()
    make_pkg(frozen_ce, name="pfBlockerNG-testing", version="3.1.0_5", abi="FreeBSD:14:*")

    # BEFORE: build-only matrix (CE 2.8 only).
    brp.build_repo_matrix([_CE], out, builder=_stub_builder)
    rel_before = (out / "release" / "ce-2.8" / "packagesite.pkg").read_bytes()
    nightly_before = (out / "nightly" / "ce-2.8" / "packagesite.pkg").read_bytes()

    # AFTER: same matrix + route-only CE 2.7 added.
    brp.build_repo_matrix(
        [_CE, _CE_EOL],
        out,
        builder=_stub_builder,
        route_only_pkgs={"ce-2.7": [frozen_ce]},
    )
    rel_after = (out / "release" / "ce-2.8" / "packagesite.pkg").read_bytes()
    nightly_after = (out / "nightly" / "ce-2.8" / "packagesite.pkg").read_bytes()

    # Build-entry subtrees are byte-identical — route-only is additive, not a regression.
    assert rel_after == rel_before, "route-only must not alter the build entry's release catalog"
    assert nightly_after == nightly_before, "route-only must not alter the build entry's nightly catalog"

    # Route-only CE 2.7 release catalog now exists (the additive part).
    assert (out / "release" / "ce-2.7" / "packagesite.pkg").is_file()


def test_route_only_ce_and_plus_both_served(tmp_path: Path) -> None:
    """route-only works for BOTH CE and Plus variants.

    Scenario: one build CE 2.8 + route-only CE 2.7 + route-only Plus 25.03
      Given separate frozen .pkg for each route-only entry
       When build_repo_matrix runs
      Then release/ce-2.7/ catalog lists the frozen CE pkg
       And release/plus-25.03/ catalog lists the frozen Plus pkg
       And NO nightly/ subtrees exist for either route-only entry
    """
    out = tmp_path / "site"
    frozen_ce = tmp_path / "frozen_ce" / "pfBlockerNG-testing-3.1.0_5.pkg"
    frozen_ce.parent.mkdir()
    make_pkg(frozen_ce, name="pfBlockerNG-testing", version="3.1.0_5", abi="FreeBSD:14:*")

    frozen_plus = tmp_path / "frozen_plus" / "pfBlockerNG-testing-3.0.9_1.pkg"
    frozen_plus.parent.mkdir()
    make_pkg(frozen_plus, name="pfBlockerNG-testing", version="3.0.9_1", abi="FreeBSD:15:*")

    brp.build_repo_matrix(
        [_CE, _CE_EOL, _PLUS_EOL],
        out,
        builder=_stub_builder,
        route_only_pkgs={
            "ce-2.7": [frozen_ce],
            "plus-25.03": [frozen_plus],
        },
    )

    # CE route-only: correct frozen version served.
    ce_objs = _catalog_objects(out / "release" / "ce-2.7" / "packagesite.pkg")
    assert len(ce_objs) == 1
    assert ce_objs[0]["version"] == "3.1.0_5"

    # Plus route-only: correct frozen version served.
    plus_objs = _catalog_objects(out / "release" / "plus-25.03" / "packagesite.pkg")
    assert len(plus_objs) == 1
    assert plus_objs[0]["version"] == "3.0.9_1"

    # No nightly for either route-only entry.
    assert not (out / "nightly" / "ce-2.7").exists()
    assert not (out / "nightly" / "plus-25.03").exists()


def test_route_only_missing_frozen_pkg_raises_build_repo_error(tmp_path: Path) -> None:
    """A route-only entry with no frozen .pkg provided raises BuildRepoError.

    Scenario: route-only CE 2.7 with NO entry in route_only_pkgs
      Given a route-only CE 2.7 matrix entry
        And route_only_pkgs is empty (or missing that varver key)
       When build_repo_matrix runs
      Then BuildRepoError is raised immediately — no catalog emitted, no silent empty output
    """
    out = tmp_path / "site"

    # route_only_pkgs completely absent.
    with pytest.raises(brp.BuildRepoError, match="route-only"):
        brp.build_repo_matrix([_CE_EOL], out, builder=_stub_builder)

    # route_only_pkgs present but missing the relevant varver key.
    with pytest.raises(brp.BuildRepoError, match="route-only"):
        brp.build_repo_matrix(
            [_CE_EOL],
            out,
            builder=_stub_builder,
            route_only_pkgs={"plus-26.03": []},  # wrong key
        )

    # route_only_pkgs has the key but with an EMPTY list.
    with pytest.raises(brp.BuildRepoError, match="route-only"):
        brp.build_repo_matrix(
            [_CE_EOL],
            out,
            builder=_stub_builder,
            route_only_pkgs={"ce-2.7": []},  # empty list
        )

    # No output dir created on error (fail loud, fail clean).
    assert not (out / "release" / "ce-2.7").exists()


def test_route_only_multiple_frozen_pkgs_all_indexed(tmp_path: Path) -> None:
    """Multiple frozen .pkg files in route_only_pkgs are ALL indexed in the release catalog.

    This is the retention use-case: a route-only entry can carry more than one frozen
    version (e.g. the last two builds before EOL) — both appear in the catalog.
    """
    out = tmp_path / "site"
    frozen_dir = tmp_path / "frozen"
    frozen_dir.mkdir()
    frozen_a = frozen_dir / "pfBlockerNG-testing-3.1.0_4.pkg"
    frozen_b = frozen_dir / "pfBlockerNG-testing-3.1.0_5.pkg"
    make_pkg(frozen_a, name="pfBlockerNG-testing", version="3.1.0_4", abi="FreeBSD:14:*")
    make_pkg(frozen_b, name="pfBlockerNG-testing", version="3.1.0_5", abi="FreeBSD:14:*")

    brp.build_repo_matrix(
        [_CE_EOL],
        out,
        builder=_stub_builder,
        route_only_pkgs={"ce-2.7": [frozen_a, frozen_b]},
    )

    objs = _catalog_objects(out / "release" / "ce-2.7" / "packagesite.pkg")
    versions = {o["version"] for o in objs}
    assert versions == {"3.1.0_4", "3.1.0_5"}


def test_invalid_role_raises_build_repo_error(tmp_path: Path) -> None:
    """An unknown role (e.g. a ``route_only`` typo) is rejected, not silently built.

    Fail-closed contract: only ``build`` / ``route-only`` (or absent ⇒ build) are valid.
    A typo must NOT fall through to the build path and re-enable a fresh build for an EOL
    version.
    """
    out = tmp_path / "site"
    typo_entry = {**_CE, "role": "route_only"}  # underscore, not hyphen

    with pytest.raises(brp.BuildRepoError, match="invalid role"):
        brp.build_repo_matrix([typo_entry], out, builder=_stub_builder)


def test_route_only_wildcard_frozen_pkg_serves_all_arch_rows_of_varver(tmp_path: Path) -> None:
    """ONE wildcard-ABI frozen .pkg serves EVERY arch row of a route-only varver
    (arch-less; issue #1806) — matched by OS+major, never exact-string.

    Before the redesign, a per-arch frozen pool was filtered into SEPARATE
    arch-specific catalogs. Under the arch-less contract there is only ONE
    release catalog per varver: a single NO_ARCH frozen package serves both
    the amd64 AND the aarch64 route-only matrix row.

    Scenario: Plus 25.03 EOL on BOTH amd64 and aarch64 (one varver, two arch rows)
      Given ONE wildcard-ABI (FreeBSD:15:*) frozen .pkg under "plus-25.03"
       When build_repo_matrix runs for both arch rows
      Then release/plus-25.03/ (no arch subdir) holds exactly that one package
    """
    out = tmp_path / "site"
    plus_amd64 = {**_PLUS_EOL, "freebsd_major": "15", "arch": "amd64"}
    plus_arm = {**_PLUS_EOL, "freebsd_major": "15", "arch": "aarch64"}
    frozen_dir = tmp_path / "frozen"
    frozen_dir.mkdir()
    frozen_pkg = frozen_dir / "plus-testing.pkg"
    make_pkg(frozen_pkg, name="pfBlockerNG-testing", version="3.1.0_5", abi="FreeBSD:15:*")

    brp.build_repo_matrix(
        [plus_amd64, plus_arm],
        out,
        builder=_stub_builder,
        build_nightly=False,
        route_only_pkgs={"plus-25.03": [frozen_pkg]},
    )

    rel = out / "release" / "plus-25.03"
    assert not (rel / "amd64").exists()
    assert not (rel / "aarch64").exists()
    objs = _catalog_objects(rel / "packagesite.pkg")
    assert [o["abi"] for o in objs] == ["FreeBSD:15:*"]
    assert [o["version"] for o in objs] == ["3.1.0_5"]


def test_route_only_pre_1806_concrete_abi_fails_explicitly(tmp_path: Path) -> None:
    """A concrete-ABI frozen .pkg identifies a pre-#1806 tag, which is explicitly
    unservable as route-only rather than emitted into an arch-less catalog.

    Scenario: a concrete FreeBSD:14:amd64 frozen .pkg served via route_only_pkgs
      When build_repo_matrix runs
      Then it raises BuildRepoError naming the concrete ABI and settled policy
       And it emits no route-only catalog
    """
    out = tmp_path / "site"
    frozen_pkg = tmp_path / "frozen" / "pfBlockerNG-testing-3.1.0_5.pkg"
    frozen_pkg.parent.mkdir()
    make_pkg(frozen_pkg, name="pfBlockerNG-testing", version="3.1.0_5", abi="FreeBSD:14:amd64")

    with pytest.raises(brp.BuildRepoError, match=r"pre-#1806 tag is unservable as route-only") as exc_info:
        brp.build_repo_matrix(
            [_CE_EOL],
            out,
            builder=_stub_builder,
            route_only_pkgs={"ce-2.7": [frozen_pkg]},
        )

    assert "FreeBSD:14:amd64" in str(exc_info.value)
    assert not (out / "release" / "ce-2.7").exists()


def test_route_only_no_frozen_pkg_for_abi_raises(tmp_path: Path) -> None:
    """A route-only entry whose frozen pool has NO .pkg matching the entry's ABI fails loud.

    A non-empty pool that matches a different ABI must not silently yield an empty catalog.
    """
    out = tmp_path / "site"
    frozen = tmp_path / "wrong-abi.pkg"
    # _CE_EOL is FreeBSD:14:amd64; supply only a FreeBSD:16:amd64 .pkg → no ABI match.
    make_pkg(frozen, name="pfBlockerNG-testing", version="3.1.0_5", abi="FreeBSD:16:amd64")

    with pytest.raises(brp.BuildRepoError, match="none match ABI"):
        brp.build_repo_matrix(
            [_CE_EOL],
            out,
            builder=_stub_builder,
            route_only_pkgs={"ce-2.7": [frozen]},
        )


# --------------------------------------------------------------------------- #
# ADR-27 Phase 10: --route-only-pkgs CLI flag
#
# The Python API accepts route_only_pkgs as a dict; publish.yml calls the CLI,
# so the --route-only-pkgs VARVER:PATH flag (repeatable) must be wired end-to-end.
# --------------------------------------------------------------------------- #


def test_cli_route_only_pkgs_flag_builds_frozen_catalog(tmp_path: Path) -> None:
    """``--route-only-pkgs VARVER:PATH`` wires route_only_pkgs through the CLI.

    Scenario: CE 2.7 route-only entry + one frozen .pkg supplied via CLI flag
      Given a route-only CE 2.7 matrix entry (role=route-only) and a frozen .pkg
        And --route-only-pkgs ce-2.7:<path> passed on the CLI
      When ``brp.main(["--build-matrix", ...])`` is called
      Then rc == 0
       And release/ce-2.7/ catalog exists with the frozen version
       And nightly/ce-2.7/ does NOT exist (no nightly for route-only)
    """
    out = tmp_path / "site"
    frozen_dir = tmp_path / "frozen"
    frozen_dir.mkdir()
    frozen_pkg = frozen_dir / "pfBlockerNG-testing-3.1.0_5.pkg"
    make_pkg(frozen_pkg, name="pfBlockerNG-testing", version="3.1.0_5", abi="FreeBSD:14:*")

    matrix_json = json.dumps([_CE_EOL])
    matrix_file = tmp_path / "matrix.json"
    matrix_file.write_text(matrix_json)

    # BEFORE: site dir does not exist yet.
    assert not out.exists()

    rc = brp.main(
        [
            "--build-matrix",
            "--matrix-json",
            str(matrix_file),
            "--out",
            str(out),
            "--no-nightly",
            "--route-only-pkgs",
            f"ce-2.7:{frozen_pkg}",
        ]
    )

    # THEN: CLI exits 0, catalog present, no nightly.
    assert rc == 0
    catalog = out / "release" / "ce-2.7" / "packagesite.pkg"
    assert catalog.is_file(), f"route-only release catalog not emitted: {catalog}"
    objs = _catalog_objects(catalog)
    assert len(objs) == 1
    assert objs[0]["version"] == "3.1.0_5"
    assert not (out / "nightly" / "ce-2.7").exists(), "nightly subtree must not exist for route-only entry"


def test_cli_route_only_pkgs_flag_repeatable_for_multiple_frozen(tmp_path: Path) -> None:
    """``--route-only-pkgs`` is repeatable: two flags for the same varver fold both .pkg files in.

    Scenario: same varver supplied twice — the retention use-case (last two frozen builds).
      Given two frozen .pkg files for ce-2.7
        And --route-only-pkgs ce-2.7:<a> --route-only-pkgs ce-2.7:<b> on the CLI
      When brp.main is called
      Then the catalog lists BOTH versions.
    """
    out = tmp_path / "site"
    frozen_dir = tmp_path / "frozen"
    frozen_dir.mkdir()
    frozen_a = frozen_dir / "pfBlockerNG-testing-3.1.0_4.pkg"
    frozen_b = frozen_dir / "pfBlockerNG-testing-3.1.0_5.pkg"
    make_pkg(frozen_a, name="pfBlockerNG-testing", version="3.1.0_4", abi="FreeBSD:14:*")
    make_pkg(frozen_b, name="pfBlockerNG-testing", version="3.1.0_5", abi="FreeBSD:14:*")

    matrix_file = tmp_path / "matrix.json"
    matrix_file.write_text(json.dumps([_CE_EOL]))

    rc = brp.main(
        [
            "--build-matrix",
            "--matrix-json",
            str(matrix_file),
            "--out",
            str(out),
            "--no-nightly",
            "--route-only-pkgs",
            f"ce-2.7:{frozen_a}",
            "--route-only-pkgs",
            f"ce-2.7:{frozen_b}",
        ]
    )

    assert rc == 0
    objs = _catalog_objects(out / "release" / "ce-2.7" / "packagesite.pkg")
    assert {o["version"] for o in objs} == {"3.1.0_4", "3.1.0_5"}


def test_cli_route_only_pkgs_bad_format_errors(tmp_path: Path) -> None:
    """``--route-only-pkgs`` without a colon separator is a usage error (SystemExit).

    Scenario: malformed VARVER:PATH argument (no colon).
      Given --route-only-pkgs ce-2.7-without-colon (missing ':')
      When brp.main is called
      Then it raises SystemExit (argparse usage error).
    """
    frozen_dir = tmp_path / "frozen"
    frozen_dir.mkdir()
    matrix_file = tmp_path / "matrix.json"
    matrix_file.write_text(json.dumps([_CE_EOL]))

    with pytest.raises(SystemExit):
        brp.main(
            [
                "--build-matrix",
                "--matrix-json",
                str(matrix_file),
                "--out",
                str(tmp_path / "site"),
                "--route-only-pkgs",
                "ce-2.7-no-colon",  # missing ':' separator
            ]
        )


# --------------------------------------------------------------------------- #
# Consume-mode: release_pkgs= parameter
#
# When release_pkgs is supplied to build_repo_matrix, the release/<varver>/
# catalog is served from caller-supplied pre-built .pkg files (ABI-filtered, pruned
# via retain_by_channel) instead of rebuilding testing+stable from source.
# Nightly is always built from source regardless.
#
# These tests pin every guarantee of the consume-mode path:
#   * release/<varver>/ catalog lists exactly the consumed .pkg(s)
#   * ABI filter: a mixed-ABI pool is filtered to the matching FreeBSD major
#   * testing + stable both present in one pool -> retain_by_channel keeps both
#   * empty pool for a varver -> no release catalog emitted, no exception, nightly OK
#   * nightly is still built from source when build_nightly=True
#   * back-compat: release_pkgs=None reproduces the build-from-source path
#   * CLI: --release-pkgs VARVER:PATH wires through end-to-end
#   * CLI: bad format (no colon) is a usage error (SystemExit)
# --------------------------------------------------------------------------- #


def test_consume_mode_release_catalog_contains_consumed_pkg(tmp_path: Path) -> None:
    """Consume mode places the pool into release/<varver>/ under the canonical name.

    Scenario: CE 2.8 build entry + one pre-built testing .pkg supplied via release_pkgs
      Given a pre-built pfBlockerNG-testing 4.0.0_1 .pkg (amd64)
        And release_pkgs={"ce-2.8": [pkg]} passed to build_repo_matrix
       When build_repo_matrix runs with build_nightly=False
      Then release/ce-2.8/packagesite.pkg lists that package
       And the catalog entry name is pfBlockerNG-testing and version is 4.0.0_1
       And the builder was NOT called for testing/stable (consume, not rebuild)
    """
    out = tmp_path / "site"
    pkg_dir = tmp_path / "pkgs"
    pkg_dir.mkdir()
    prebuilt = pkg_dir / "pfBlockerNG-testing-4.0.0_1.pkg"
    make_pkg(prebuilt, name="pfBlockerNG-testing", version="4.0.0_1", abi="FreeBSD:15:*")

    # Before-state: no release subtree yet.
    assert not (out / "release" / "ce-2.8").exists()

    builder_calls: list[str] = []

    def tracking_builder(channel: str, **kw: object) -> Path:
        builder_calls.append(channel)
        return _stub_builder(channel, **kw)  # type: ignore[arg-type]

    brp.build_repo_matrix(
        [_CE],
        out,
        builder=tracking_builder,
        build_nightly=False,
        release_pkgs={"ce-2.8": [prebuilt]},
    )

    # Catalog must exist and list the consumed package.
    catalog = out / "release" / "ce-2.8" / "packagesite.pkg"
    assert catalog.is_file(), "release catalog must exist in consume mode"
    objs = _catalog_objects(catalog)
    assert len(objs) == 1
    assert objs[0]["name"] == "pfBlockerNG-testing"
    assert objs[0]["version"] == "4.0.0_1"

    # Builder must NOT have been called for testing or stable.
    assert "testing" not in builder_calls, "builder must not be called for testing in consume mode"
    assert "stable" not in builder_calls, "builder must not be called for stable in consume mode"


def test_consume_mode_wildcard_pkg_serves_all_arch_rows_of_varver(tmp_path: Path) -> None:
    """ONE wildcard-ABI pool entry serves EVERY arch row of a varver (arch-less; issue #1806).

    Before the redesign, a mixed-ABI pool was filtered per (varver, arch) into
    SEPARATE arch-specific catalogs. Under the arch-less contract there is only
    ONE catalog per varver — a single NO_ARCH package (matched by OS+major)
    serves both the amd64 AND the aarch64 matrix row.

    Scenario: Plus 26.03 on amd64 + aarch64 (two arch rows, one varver)
      Given a pool with ONE wildcard-ABI (FreeBSD:16:*) testing .pkg under "plus-26.03"
       When build_repo_matrix runs for both _PLUS (amd64) + _PLUS_ARM (aarch64)
      Then release/plus-26.03/ (no arch subdir) holds exactly that one package
    """
    out = tmp_path / "site"
    pkg_dir = tmp_path / "pkgs"
    pkg_dir.mkdir()
    pkg = pkg_dir / "pfBlockerNG-testing-4.0.0_1.pkg"
    make_pkg(pkg, name="pfBlockerNG-testing", version="4.0.0_1", abi="FreeBSD:16:*")

    # Before-state: no catalog exists.
    assert not (out / "release" / "plus-26.03").exists()

    brp.build_repo_matrix(
        [_PLUS, _PLUS_ARM],
        out,
        builder=_stub_builder,
        build_nightly=False,
        release_pkgs={"plus-26.03": [pkg]},
    )

    rel = out / "release" / "plus-26.03"
    assert not (rel / "amd64").exists()
    assert not (rel / "aarch64").exists()
    objs = _catalog_objects(rel / "packagesite.pkg")
    assert [o["abi"] for o in objs] == ["FreeBSD:16:*"]
    assert [o["version"] for o in objs] == ["4.0.0_1"]


def test_consume_mode_concrete_abi_pkg_rejected_at_emission(tmp_path: Path) -> None:
    """A concrete-ABI pool entry is a hard error — the arch-less catalog HARD-REQUIRES
    a NO_ARCH (wildcard-ABI) package (issue #1806): a concrete one would silently
    install on only one arch.

    Scenario: a concrete FreeBSD:16:amd64 testing .pkg served via release_pkgs
      When build_repo_matrix runs
      Then it raises BuildRepoError with generic NO_ARCH guidance
       And it does not mislabel the package as a pre-#1806 route-only asset
    """
    out = tmp_path / "site"
    pkg_dir = tmp_path / "pkgs"
    pkg_dir.mkdir()
    pkg = pkg_dir / "pfBlockerNG-testing-4.0.0_1.pkg"
    make_pkg(pkg, name="pfBlockerNG-testing", version="4.0.0_1", abi="FreeBSD:16:amd64")

    with pytest.raises(brp.BuildRepoError, match="NO_ARCH") as exc_info:
        brp.build_repo_matrix(
            [_PLUS],
            out,
            builder=_stub_builder,
            build_nightly=False,
            release_pkgs={"plus-26.03": [pkg]},
        )

    message = str(exc_info.value)
    assert "Ship a wildcard-ABI (NO_ARCH) build instead." in message
    assert "pre-#1806" not in message
    assert "route-only" not in message


def test_consume_mode_testing_and_stable_both_retained(tmp_path: Path) -> None:
    """With a testing + stable .pkg in the pool, retain_by_channel keeps both.

    Scenario: pool carries one testing and one stable .pkg for ce-2.8
      Given pfBlockerNG-testing (testing channel) + pfBlockerNG (stable channel) .pkg in pool
       When build_repo_matrix runs in consume mode (release_keep_testing=1, release_keep_stable=1)
      Then release/ce-2.8 catalog lists BOTH the testing and stable packages
    """
    out = tmp_path / "site"
    pkg_dir = tmp_path / "pkgs"
    pkg_dir.mkdir()
    testing_pkg = pkg_dir / "pfBlockerNG-testing-4.0.0_1.pkg"
    stable_pkg = pkg_dir / "pfBlockerNG-4.0.0.pkg"
    # testing channel: name ends in "-testing" (retain_by_channel uses the name to classify)
    make_pkg(testing_pkg, name="pfBlockerNG-testing", version="4.0.0_1", abi="FreeBSD:15:*")
    # stable channel: base name without "-testing" suffix
    make_pkg(stable_pkg, name="pfBlockerNG", version="4.0.0", abi="FreeBSD:15:*")

    # Before-state: no release catalog.
    assert not (out / "release" / "ce-2.8").exists()

    brp.build_repo_matrix(
        [_CE],
        out,
        builder=_stub_builder,
        build_nightly=False,
        release_pkgs={"ce-2.8": [testing_pkg, stable_pkg]},
    )

    catalog = out / "release" / "ce-2.8" / "packagesite.pkg"
    assert catalog.is_file()
    objs = _catalog_objects(catalog)
    names = {o["name"] for o in objs}

    # Both channels present in the catalog.
    assert "pfBlockerNG-testing" in names, "testing package must be in release catalog"
    assert "pfBlockerNG" in names, "stable package must be in release catalog"
    assert len(objs) == 2, "exactly one testing + one stable expected"


def test_consume_mode_release_extra_pkgs_abi_filtered(tmp_path: Path) -> None:
    """release_extra_pkgs is ABI-filtered before channel retention in consume mode.

    Scenario: a wrong-major extra with a HIGHER version must not contaminate this catalog
      Given a ce-2.8 (FreeBSD major 15) entry, a correct-major testing pkg in the pool, and
            release_extra_pkgs carrying a correct-major stable pkg PLUS a wrong-major
            (FreeBSD:16) testing pkg whose version (9.9.9) is higher than the pool's testing (4.0.0_1)
       When build_repo_matrix runs in consume mode (keep_testing=1, keep_stable=1)
      Then the release catalog holds ONLY the FreeBSD:15:* packages — the higher-version
           wrong-major testing is excluded by the ABI filter, not retained over the right-major testing
           (without the filter, retain_by_channel would pick the 9.9.9 wrong-major testing).
    """
    out = tmp_path / "site"
    pkg_dir = tmp_path / "pkgs"
    pkg_dir.mkdir()
    testing_pkg = pkg_dir / "pfBlockerNG-testing-4.0.0_1.pkg"
    stable_extra = pkg_dir / "pfBlockerNG-4.0.0.pkg"
    wrong_abi_testing = pkg_dir / "pfBlockerNG-testing-9.9.9.pkg"
    make_pkg(testing_pkg, name="pfBlockerNG-testing", version="4.0.0_1", abi="FreeBSD:15:*")
    make_pkg(stable_extra, name="pfBlockerNG", version="4.0.0", abi="FreeBSD:15:*")
    make_pkg(wrong_abi_testing, name="pfBlockerNG-testing", version="9.9.9", abi="FreeBSD:16:*")

    assert not (out / "release" / "ce-2.8").exists()

    brp.build_repo_matrix(
        [_CE],  # FreeBSD:15:amd64
        out,
        builder=_stub_builder,
        build_nightly=False,
        release_pkgs={"ce-2.8": [testing_pkg]},
        release_extra_pkgs=[stable_extra, wrong_abi_testing],
    )

    objs = _catalog_objects(out / "release" / "ce-2.8" / "packagesite.pkg")
    abis = {o["abi"] for o in objs}
    versions = {(o["name"], o["version"]) for o in objs}
    assert abis == {"FreeBSD:15:*"}, "only this major's ABI may appear in the catalog"
    assert ("pfBlockerNG-testing", "4.0.0_1") in versions, "right-ABI testing must be kept"
    assert ("pfBlockerNG", "4.0.0") in versions, "right-ABI stable extra must be kept"
    assert ("pfBlockerNG-testing", "9.9.9") not in versions, "wrong-ABI extra must be filtered out"
    assert len(objs) == 2


def test_consume_mode_empty_pool_skips_release_catalog_no_exception(tmp_path: Path) -> None:
    """An empty pool for a build varver skips the release catalog — no raise, nightly still runs.

    Scenario: CE 2.8 entry with release_pkgs={"ce-2.8": []} (empty pool)
      Given release_pkgs maps ce-2.8 to an empty list
       When build_repo_matrix runs with build_nightly=True
      Then NO release catalog is emitted (the release dir is absent or has no packagesite)
       And NO exception is raised
       And the nightly/ce-2.8/ catalog IS still built from source
    """
    out = tmp_path / "site"

    # Before-state: neither subtree exists.
    assert not (out / "release" / "ce-2.8").exists()
    assert not (out / "nightly" / "ce-2.8").exists()

    # Should not raise even with empty pool.
    brp.build_repo_matrix(
        [_CE],
        out,
        builder=_stub_builder,
        build_nightly=True,
        release_pkgs={"ce-2.8": []},
    )

    # Release catalog must NOT be emitted for an empty pool.
    release_catalog = out / "release" / "ce-2.8" / "packagesite.pkg"
    assert not release_catalog.exists(), "release catalog must not be emitted for empty pool"

    # Nightly must still be built.
    nightly_catalog = out / "nightly" / "ce-2.8" / "packagesite.pkg"
    assert nightly_catalog.is_file(), "nightly catalog must still be built in consume mode"


def test_consume_mode_nightly_still_built_from_source(tmp_path: Path) -> None:
    """Nightly is always built from source in consume mode, even when release is consumed.

    Scenario: CE 2.8 in consume mode with build_nightly=True
      Given a pre-built testing .pkg in release_pkgs for ce-2.8
        And build_nightly=True
       When build_repo_matrix runs
      Then nightly/ce-2.8/ catalog exists (builder called for 'nightly')
       And release/ce-2.8/ catalog lists only the consumed pkg (not a nightly build)
    """
    out = tmp_path / "site"
    pkg_dir = tmp_path / "pkgs"
    pkg_dir.mkdir()
    prebuilt = pkg_dir / "pfBlockerNG-testing-4.0.0_1.pkg"
    make_pkg(prebuilt, name="pfBlockerNG-testing", version="4.0.0_1", abi="FreeBSD:15:*")

    builder_channels: list[str] = []

    def tracking_builder(channel: str, **kw: object) -> Path:
        builder_channels.append(channel)
        return _stub_builder(channel, **kw)  # type: ignore[arg-type]

    brp.build_repo_matrix(
        [_CE],
        out,
        builder=tracking_builder,
        build_nightly=True,
        release_pkgs={"ce-2.8": [prebuilt]},
    )

    # Builder called for nightly but NOT for testing/stable.
    assert "nightly" in builder_channels, "builder must be called for nightly in consume mode"
    assert "testing" not in builder_channels, "builder must NOT be called for testing in consume mode"

    # Nightly catalog exists.
    assert (out / "nightly" / "ce-2.8" / "packagesite.pkg").is_file()

    # Release catalog exists and lists the consumed pkg (not the nightly build).
    rel_objs = _catalog_objects(out / "release" / "ce-2.8" / "packagesite.pkg")
    assert len(rel_objs) == 1
    assert rel_objs[0]["name"] == "pfBlockerNG-testing"
    assert rel_objs[0]["version"] == "4.0.0_1"


def test_consume_mode_none_reproduces_source_build_path(tmp_path: Path) -> None:
    """release_pkgs=None (default) reproduces the build-from-source path unchanged.

    Back-compat guard: omitting release_pkgs (or passing None explicitly) must produce a
    release catalog via the builder, not the consume path.

    Scenario: CE 2.8 entry, release_pkgs omitted
      Given build_repo_matrix called WITHOUT release_pkgs (default None)
       When the matrix runs with the stub builder
      Then release/ce-2.8/ catalog exists (built via _stub_builder for 'testing')
       And nightly/ce-2.8/ catalog exists (built via _stub_builder for 'nightly')
    """
    out = tmp_path / "site"

    # Before-state: no subtrees.
    assert not (out / "release" / "ce-2.8").exists()
    assert not (out / "nightly" / "ce-2.8").exists()

    brp.build_repo_matrix([_CE], out, builder=_stub_builder)

    # Both subtrees present, built from source via stub.
    assert (out / "release" / "ce-2.8" / "packagesite.pkg").is_file()
    assert (out / "nightly" / "ce-2.8" / "packagesite.pkg").is_file()

    # Verify the catalog lists the stub-built testing package (confirms source-build path ran).
    rel_objs = _catalog_objects(out / "release" / "ce-2.8" / "packagesite.pkg")
    assert any(o["name"] == "pfBlockerNG-testing" for o in rel_objs), (
        "testing package from stub builder must appear in release catalog on source-build path"
    )


def test_cli_release_pkgs_flag_serves_consumed_catalog(tmp_path: Path) -> None:
    """``--release-pkgs VARVER:PATH`` wires release_pkgs through the CLI end-to-end.

    Scenario: CE 2.8 build entry + one pre-built .pkg supplied via --release-pkgs flag
      Given a pre-built pfBlockerNG-testing 4.0.0_1 .pkg
        And --release-pkgs ce-2.8:<path> passed on the CLI
       When brp.main is called with --no-nightly
      Then rc == 0
       And release/ce-2.8/ catalog exists with the consumed version
    """
    out = tmp_path / "site"
    pkg_dir = tmp_path / "pkgs"
    pkg_dir.mkdir()
    prebuilt = pkg_dir / "pfBlockerNG-testing-4.0.0_1.pkg"
    make_pkg(prebuilt, name="pfBlockerNG-testing", version="4.0.0_1", abi="FreeBSD:15:*")

    matrix_file = tmp_path / "matrix.json"
    matrix_file.write_text(json.dumps([_CE]))

    # Before-state: site dir does not exist yet.
    assert not out.exists()

    rc = brp.main(
        [
            "--build-matrix",
            "--matrix-json",
            str(matrix_file),
            "--out",
            str(out),
            "--no-nightly",
            "--release-pkgs",
            f"ce-2.8:{prebuilt}",
        ]
    )

    assert rc == 0
    catalog = out / "release" / "ce-2.8" / "packagesite.pkg"
    assert catalog.is_file(), f"consumed release catalog not emitted: {catalog}"
    objs = _catalog_objects(catalog)
    assert len(objs) == 1
    assert objs[0]["version"] == "4.0.0_1"


def test_cli_release_pkgs_bad_format_errors(tmp_path: Path) -> None:
    """``--release-pkgs`` without a colon separator is a usage error (SystemExit).

    Scenario: malformed VARVER:PATH argument (no colon).
      Given --release-pkgs ce-2.8-without-colon (missing ':')
       When brp.main is called
      Then it raises SystemExit (argparse usage error).
    """
    matrix_file = tmp_path / "matrix.json"
    matrix_file.write_text(json.dumps([_CE]))

    with pytest.raises(SystemExit):
        brp.main(
            [
                "--build-matrix",
                "--matrix-json",
                str(matrix_file),
                "--out",
                str(tmp_path / "site"),
                "--no-nightly",
                "--release-pkgs",
                "ce-2.8-no-colon",  # missing ':' separator
            ]
        )


# --------------------------------------------------------------------------- #
# issue #1806 step A2: --dep-pkgs — fold a pre-built dependency .pkg (e.g.
# py311-charset-normalizer, built by build-dep-pkg-portable.py) into BOTH the
# release AND nightly catalogs of its matching ABI train, AFTER retention.
#
# A NO_ARCH dependency package records a CPU-wildcarded ABI (e.g.
# "FreeBSD:15:*") — it works on every arch of that FreeBSD major — so the fold
# matches by OS+major, not exact ABI string equality like the existing
# per-arch release_extra_pkgs/release_pkgs candidates.
#
# These tests pin:
#   * the dep lands in BOTH release/<varver>/ and nightly/<varver>/ (arch-less;
#     issue #1806 — no <arch> leaf) of its OWN ABI train (source-build mode +
#     the nightly fold)
#   * it is ABSENT from a different variant's catalogs (different FreeBSD major)
#   * it does NOT consume a --release-keep-stable retention slot (folded AFTER
#     retain_by_channel, not before — the bug this design deliberately avoids:
#     folding pre-retention would let the dep's version compete for the window
#     and evict a real release) — covers consume mode's fold point
#   * --dep-pkgs is repeatable (mirrors --release-extra-pkgs's arg style)
#   * a dep pkg whose ABI matches no emitted catalog is a hard error
# --------------------------------------------------------------------------- #


def test_cli_dep_pkgs_lands_in_release_and_nightly_same_abi_train(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """--dep-pkgs folds a NO_ARCH dependency .pkg into BOTH the release and
    nightly catalogs of its OWN ABI train (CE, FreeBSD 15) and NEITHER of a
    different variant's catalogs (Plus, FreeBSD 16).

    Scenario: CE + Plus entries, one CE-major dep pkg (source-build mode, the
              default path with no --release-pkgs/--release-extra-pkgs)
      Given a py311-charset-normalizer dep .pkg with a NO_ARCH-wildcarded ABI
            "FreeBSD:15:*" (matches CE's FreeBSD major, not Plus's 16)
       When brp.main([--build-matrix, --dep-pkgs <path>, ...]) runs for [CE, Plus]
      Then release/ce-2.8/amd64 AND nightly/ce-2.8/amd64 both list the dep pkg
       And release/plus-26.03/amd64 and nightly/plus-26.03/amd64 do NOT
    """
    _with_stub_builder(monkeypatch)

    dep_dir = tmp_path / "deps"
    dep_dir.mkdir()
    dep_pkg = dep_dir / "py311-charset-normalizer-3.4.4.pkg"
    make_pkg(dep_pkg, name="py311-charset-normalizer", version="3.4.4", abi="FreeBSD:15:*")

    out = tmp_path / "site"
    mfile = tmp_path / "matrix.json"
    ce = {**_CE, "extra_pkgs": ["net/py-charset-normalizer"]}
    plus = {**_PLUS, "extra_pkgs": []}
    mfile.write_text(json.dumps({"versions": [ce, plus]}))

    # Before-state: nothing built yet.
    assert not out.exists()

    rc = brp.main(
        [
            "--build-matrix",
            "--matrix-json",
            str(mfile),
            "--out",
            str(out),
            "--dep-pkgs",
            str(dep_pkg),
        ]
    )
    assert rc == 0

    ce_release = _names_in(out / "release" / "ce-2.8" / "packagesite.pkg")
    ce_nightly = _names_in(out / "nightly" / "ce-2.8" / "packagesite.pkg")
    plus_release = _names_in(out / "release" / "plus-26.03" / "packagesite.pkg")
    plus_nightly = _names_in(out / "nightly" / "plus-26.03" / "packagesite.pkg")

    assert "py311-charset-normalizer" in ce_release, "dep must land in the release catalog of its own ABI train"
    assert "py311-charset-normalizer" in ce_nightly, "dep must ALSO land in the nightly catalog of its own ABI train"
    assert "py311-charset-normalizer" not in plus_release, "dep must be absent from a different FreeBSD major"
    assert "py311-charset-normalizer" not in plus_nightly, "dep must be absent from a different FreeBSD major"


def test_cli_dep_pkgs_flag_is_repeatable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """--dep-pkgs is repeatable (mirrors --release-extra-pkgs's arg style):
    multiple dependency packages all fold into the matching catalog."""
    _with_stub_builder(monkeypatch)

    dep_dir = tmp_path / "deps"
    dep_dir.mkdir()
    dep_a = dep_dir / "py311-charset-normalizer-3.4.4.pkg"
    make_pkg(dep_a, name="py311-charset-normalizer", version="3.4.4", abi="FreeBSD:15:*")
    dep_b = dep_dir / "py311-idna-3.7.pkg"
    make_pkg(dep_b, name="py311-idna", version="3.7", abi="FreeBSD:15:*")

    out = tmp_path / "site"
    mfile = tmp_path / "matrix.json"
    ce = {**_CE, "extra_pkgs": ["net/py-charset-normalizer", "net/py-idna"]}
    mfile.write_text(json.dumps({"versions": [ce]}))

    rc = brp.main(
        [
            "--build-matrix",
            "--matrix-json",
            str(mfile),
            "--out",
            str(out),
            "--no-nightly",
            "--dep-pkgs",
            str(dep_a),
            "--dep-pkgs",
            str(dep_b),
        ]
    )
    assert rc == 0
    names = _names_in(out / "release" / "ce-2.8" / "packagesite.pkg")
    assert {"py311-charset-normalizer", "py311-idna"} <= names


def test_dep_pkgs_fold_after_retention_stable_pin_survives(tmp_path: Path) -> None:
    """--dep-pkgs folds AFTER retain_by_channel — it never competes for a
    --release-keep-stable slot (consume mode's fold point).

    issue #1806 gate-A finding: the ORIGINAL version of this test used a dep
    version (3.4.4) on a DIFFERENT major/minor line ("3.4") than the real
    stable's (3.0.1, line "3.0") — vacuous, because ``_line_pins`` pins the
    newest package of EVERY line on top of the retention window regardless of
    fold order, so the stable pin would survive even under a (buggy)
    pre-retention fold. This version uses a dep version on the SAME line
    ("3.0") as the real stable, which DOES discriminate: proven below by
    directly simulating a pre-retention fold via ``retain_by_channel`` and
    showing it evicts the real stable pin (a real production bug would look
    like this) — then showing ``build_repo_matrix``'s actual AFTER-retention
    fold point does not.

    Scenario: keep_stable=1, one real stable release, one same-line dep pkg
      Given a pfBlockerNG stable .pkg at version 3.0.1 (consume-mode pool)
        And a py311-charset-normalizer dep .pkg at version 3.0.5 (SAME line "3.0")
       When build_repo_matrix runs with release_keep_stable=1 (default)
      Then release/ce-2.8 lists BOTH the stable pin (3.0.1, intact) AND
           the dep pkg — the stable pin was never evicted by the dep's higher
           version number
    """
    out = tmp_path / "site"
    pkg_dir = tmp_path / "pkgs"
    pkg_dir.mkdir()
    stable_pkg = pkg_dir / "pfBlockerNG-3.0.1.pkg"
    make_pkg(stable_pkg, name="pfBlockerNG", version="3.0.1", abi="FreeBSD:15:*")
    dep_pkg = pkg_dir / "py311-charset-normalizer-3.0.5.pkg"
    make_pkg(dep_pkg, name="py311-charset-normalizer", version="3.0.5", abi="FreeBSD:15:*")

    # Before-state: confirm the dep's version really is higher AND on the SAME
    # major/minor line as the stable's — the scenario's discriminating premise.
    assert brp._pkg_version_key("3.0.5") > brp._pkg_version_key("3.0.1")
    assert brp._line_key("3.0.5", "dep") == brp._line_key("3.0.1", "stable") == "3.0"

    # Simulated pre-retention fold (the bug this design deliberately avoids):
    # folding the dep into the candidate pool BEFORE retain_by_channel runs lets
    # its higher version win the keep=1 window; the line-pin logic then finds
    # NOTHING left outside the window for line "3.0" (the dep IS that line's
    # newest) — so the real stable pin is evicted. This proves the scenario
    # actually discriminates between fold-before and fold-after.
    pre_retention_result = brp.retain_by_channel([stable_pkg, dep_pkg], keep_testing=1, keep_stable=1)
    pre_retention_versions = {brp.read_compact_manifest(p)["version"] for p in pre_retention_result}
    assert "3.0.1" not in pre_retention_versions, (
        "simulated pre-retention fold must evict the stable pin (proves the scenario discriminates)"
    )

    # The ACTUAL production fold point: dep_pkgs never enters retain_by_channel's
    # candidate pool — it folds in strictly AFTER, so the stable pin is untouched.
    brp.build_repo_matrix(
        [{**_CE, "extra_pkgs": ["net/py-charset-normalizer"]}],
        out,
        builder=_stub_builder,
        build_nightly=False,
        release_pkgs={"ce-2.8": [stable_pkg]},
        dep_pkgs=[dep_pkg],
    )

    rel = out / "release" / "ce-2.8" / "packagesite.pkg"
    names_versions = _names_versions_in_release(rel)
    assert ("pfBlockerNG", "3.0.1") in names_versions, "the real stable pin must survive intact"
    assert ("py311-charset-normalizer", "3.0.5") in names_versions, "the dep pkg must still be present"
    assert len(names_versions) == 2, "no other package should have appeared or been evicted"


def test_dep_pkgs_mismatched_abi_raises_hard_error(tmp_path: Path) -> None:
    """A --dep-pkgs entry whose ABI matches NO emitted catalog is a hard error
    (never a silent drop) — e.g. built for a FreeBSD major nothing in the
    matrix targets."""
    out = tmp_path / "site"
    pkg_dir = tmp_path / "pkgs"
    pkg_dir.mkdir()
    # FreeBSD major 99 never appears in [_CE] (major 15) — matches no catalog.
    dep_pkg = pkg_dir / "py311-charset-normalizer-3.4.4.pkg"
    make_pkg(dep_pkg, name="py311-charset-normalizer", version="3.4.4", abi="FreeBSD:99:*")

    with pytest.raises(brp.BuildRepoError, match="dep"):
        brp.build_repo_matrix([_CE], out, builder=_stub_builder, dep_pkgs=[dep_pkg])


def test_dep_pkgs_matched_but_never_emitted_still_raises(tmp_path: Path) -> None:
    """issue #1806 gate-A finding: a dep whose ABI MATCHES a row must still raise
    if it never actually lands in an EMITTED catalog for that row — a matched-but-
    unemitted dep is exactly as silent a drop as an unmatched one.

    The gap: ``dep_pkgs_matched`` was updated unconditionally the moment a dep's
    ABI matched a row's major, even on the consume-mode branch that can skip
    emitting the release catalog entirely (an empty pool -> ``if kept_release:``
    warns and skips). Combined with ``build_nightly=False`` on that SAME entry,
    the dep landed in NEITHER catalog, yet was marked "matched" — so the
    end-of-run unmatched check never fired. The fix tracks ``dep_pkgs_matched``
    only at each site that actually folds the dep into an emitted catalog.

    Scenario: consume mode, EMPTY pool (release skipped), nightly off
      Given the CE 2.8 entry, release_pkgs={"ce-2.8": []} (nothing serves this
            major, so kept_release is empty and the release catalog is skipped)
        And build_nightly=False (no nightly catalog either)
        And a dep pkg whose ABI matches CE 2.8's major (FreeBSD:15)
       When build_repo_matrix runs
      Then it raises BuildRepoError — the dep never landed in ANY catalog, even
           though its ABI matched this entry
    """
    out = tmp_path / "site"
    pkg_dir = tmp_path / "pkgs"
    pkg_dir.mkdir()
    dep_pkg = pkg_dir / "py311-charset-normalizer-3.4.4.pkg"
    make_pkg(dep_pkg, name="py311-charset-normalizer", version="3.4.4", abi="FreeBSD:15:*")

    with pytest.raises(brp.BuildRepoError, match="dep"):
        brp.build_repo_matrix(
            [{**_CE, "extra_pkgs": ["net/py-charset-normalizer"]}],
            out,
            builder=_stub_builder,
            build_nightly=False,
            release_pkgs={"ce-2.8": []},  # empty pool -> kept_release empty -> release skipped
            dep_pkgs=[dep_pkg],
        )


def test_dep_pkgs_route_only_entry_never_folds_dep_shared_major_build_entry_does(
    tmp_path: Path,
) -> None:
    """A route-only (frozen EOL) entry NEVER receives a dep pkg, even when it shares
    its FreeBSD major with a build entry that DOES (issue #1806 coverage gap: B0.3).

    Scenario: a route-only CE 2.7 entry (FreeBSD major 15) + a build Plus entry
              ALSO on FreeBSD major 15, one dep pkg wildcarded to FreeBSD:15:*
      Given a frozen CE 2.7 .pkg served via route_only_pkgs
        And a py311-charset-normalizer dep pkg matching major 15 by OS+major
       When build_repo_matrix runs over [route-only CE 2.7, build Plus-on-15]
      Then the dep lands in the BUILD entry's release catalog (release/plus-15/)
       And the route-only entry's release catalog (release/ce-2.7/) holds ONLY
           the frozen .pkg — never the dep
       And no error is raised (the dep WAS emitted somewhere)
    """
    out = tmp_path / "site"
    frozen_pkg = tmp_path / "frozen" / "pfBlockerNG-testing-3.1.0_5.pkg"
    frozen_pkg.parent.mkdir()
    make_pkg(frozen_pkg, name="pfBlockerNG-testing", version="3.1.0_5", abi="FreeBSD:15:*")

    dep_pkg = tmp_path / "py311-charset-normalizer-3.4.4.pkg"
    make_pkg(dep_pkg, name="py311-charset-normalizer", version="3.4.4", abi="FreeBSD:15:*")

    # A route-only entry pinned to major 15 (CE 2.7 is major 14 by default; override
    # so it shares its major with the build entry below) + a build entry that shares
    # that SAME major (hypothetical: a Plus edition also targeting major 15).
    ce_eol_on_15 = {**_CE_EOL, "freebsd_major": "15"}
    plus_on_15 = {
        **_PLUS,
        "pfsense_version": "15.0",
        "freebsd_major": "15",
        "extra_pkgs": ["net/py-charset-normalizer"],
    }

    brp.build_repo_matrix(
        [ce_eol_on_15, plus_on_15],
        out,
        builder=_stub_builder,
        build_nightly=False,
        route_only_pkgs={"ce-2.7": [frozen_pkg]},
        dep_pkgs=[dep_pkg],
    )

    # Build entry: dep folded in alongside the fresh testing build.
    build_names = _names_in(out / "release" / "plus-15.0" / "packagesite.pkg")
    assert "py311-charset-normalizer" in build_names, "dep must land in the build entry's release catalog"

    # Route-only entry: frozen .pkg ONLY — the dep must never be folded in.
    route_only_objs = _catalog_objects(out / "release" / "ce-2.7" / "packagesite.pkg")
    assert {o["name"] for o in route_only_objs} == {"pfBlockerNG-testing"}, (
        "a route-only entry must never receive a dep pkg, even sharing a major with a build entry"
    )


def test_dep_pkgs_same_major_plus_empty_extra_pkgs_does_not_receive_ce_extra(tmp_path: Path) -> None:
    """issue #2403: --dep-pkgs is dest-scoped by extra_pkgs, not ABI alone.

    CE extra_pkgs declares textproc/py-charset-normalizer; Plus on the same
    freebsd_major leaves extra_pkgs=[]. The extra must land only on CE.
    """
    out = tmp_path / "site"
    dep_pkg = tmp_path / "py311-charset-normalizer-3.4.4.pkg"
    make_pkg(
        dep_pkg,
        name="py311-charset-normalizer",
        version="3.4.4",
        abi="FreeBSD:15:*",
        extra={"origin": "textproc/py-charset-normalizer"},
    )
    ce = {**_CE, "extra_pkgs": ["textproc/py-charset-normalizer"]}
    plus = {**_PLUS, "freebsd_major": "15", "extra_pkgs": []}

    brp.build_repo_matrix(
        [ce, plus],
        out,
        builder=_stub_builder,
        build_nightly=False,
        dep_pkgs=[dep_pkg],
    )

    ce_names = _names_in(out / "release" / "ce-2.8" / "packagesite.pkg")
    plus_names = _names_in(out / "release" / "plus-26.03" / "packagesite.pkg")
    assert "py311-charset-normalizer" in ce_names
    assert "py311-charset-normalizer" not in plus_names


def test_dep_pkgs_category_mismatch_is_undeclared(tmp_path: Path) -> None:
    """www/py-foo does not satisfy a textproc/py-foo extra_pkgs row."""
    out = tmp_path / "site"
    dep_pkg = tmp_path / "py311-charset-normalizer-3.4.4.pkg"
    make_pkg(
        dep_pkg,
        name="py311-charset-normalizer",
        version="3.4.4",
        abi="FreeBSD:15:*",
        extra={"origin": "www/py311-charset-normalizer"},
    )
    ce = {**_CE, "extra_pkgs": ["textproc/py-charset-normalizer"]}

    with pytest.raises(brp.BuildRepoError, match="ABI matches no emitted catalog"):
        brp.build_repo_matrix(
            [ce],
            out,
            builder=_stub_builder,
            build_nightly=False,
            dep_pkgs=[dep_pkg],
        )


# --------------------------------------------------------------------------- #
# Catalogue signing (issue #2675) — `signature_type: fingerprints` with an
# ECDSA key, so authenticity stops depending on TLS (and therefore on the CA
# store `pkg` was pinned to on pfSense Plus).
#
# The wire contract is read off freebsd/pkg (13f9f98), not inferred:
#   * the client scans a catalogue archive for members ending `.sig` / `.pub`
#     and pairs them by basename (pkg_repo_meta_extract_signature_fingerprints);
#     `pkg repo` names them after the MEMBER, so `packagesite.yaml.{sig,pub}`
#     inside packagesite.pkg and `data.{sig,pub}` inside data.pkg;
#   * the signed message is the 64-character ASCII SHA256 HEX of the
#     uncompressed catalogue member, ECDSA-SHA256 over it (pkgsign_ecc.c:
#     ecc_new pins sig_hash = SHA256; ecc_verify_cert_cb hashes with
#     PKG_HASH_TYPE_SHA256_HEX and passes it at strlen(), so no NUL). The
#     BLAKE2b-512 chain in ecc_sign_file/ecc_verify_file serves PUBKEY mode,
#     whose catalogue carries a single `signature` member instead;
#   * BOTH the `.sig` and `.pub` members carry the `$PKGSIGN:<type>$` prefix
#     (PKGSIGN_HEAD in libpkg/private/pkgsign.h): pkg_repo_parse_sigkeys()
#     sets the signer type from every member it parses, so a bare `.pub`
#     resets it to the "rsa" default;
#   * the public half is DER PKCS#8 for ECDSA — the loader calls libder_read()
#     and understands no PEM — and the trusted fingerprint is the SHA256 of
#     exactly those bytes (pkg_repo_check_fingerprint).
# --------------------------------------------------------------------------- #

_PKGSIGN_ECDSA_HEAD = b"$PKGSIGN:ecdsa$"


def _gen_key(path: Path, curve: str = "secp384r1") -> Path:
    """An EC private key in PEM, via openssl (what the publisher will use)."""
    subprocess.run(
        ["openssl", "ecparam", "-name", curve, "-genkey", "-noout", "-out", str(path)],
        check=True,
        capture_output=True,
    )
    return path


def _pkg_signed_message(catalog: bytes) -> bytes:
    """What pkg's FINGERPRINTS path actually signs: the SHA256 HEX string, 64 ASCII bytes.

    `ecc_verify_cert_cb()` does `pkg_checksum_fd(fd, PKG_HASH_TYPE_SHA256_HEX)` and passes
    it with `strlen()`, so the message is the hex text with NO NUL terminator. The
    BLAKE2b-512 convention belongs to `ecc_verify_file()`, which serves PUBKEY mode — a
    different signature_type than ours.
    """
    return hashlib.sha256(catalog).hexdigest().encode()


def _openssl_verify(digest: bytes, sig: bytes, pub_der: bytes, tmp_path: Path) -> bool:
    """Reproduce pkg's ECDSA cert check: ECDSA-SHA256 over the SHA256-hex message."""
    d = tmp_path / "verify.msg"
    s = tmp_path / "verify.sig"
    p = tmp_path / "verify.pub.der"
    d.write_bytes(digest)
    s.write_bytes(sig)
    p.write_bytes(pub_der)
    proc = subprocess.run(
        [
            "openssl",
            "dgst",
            "-sha256",
            "-verify",
            str(p),
            "-keyform",
            "DER",
            "-signature",
            str(s),
            str(d),
        ],
        capture_output=True,
    )
    return proc.returncode == 0


def _sig_members(archive: Path) -> dict[str, bytes]:
    """Every `.sig`/`.pub` member of a catalogue archive, by member name."""
    data = pfb_pkg.zstd_decompress(archive.read_bytes())
    out: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(data)) as tf:
        for ti in tf.getmembers():
            if ti.name.endswith((".sig", ".pub")):
                f = tf.extractfile(ti)
                assert f is not None
                out[ti.name] = f.read()
    return out


def _build_signed(tmp_path: Path, curve: str = "secp384r1") -> tuple[Path, Path]:
    in_dir = tmp_path / "in"
    in_dir.mkdir()
    make_pkg(in_dir / "demo-1.0_1.pkg")
    key = _gen_key(tmp_path / "repo.key", curve)
    out = tmp_path / "out"
    brp.build_repo(in_dir, out, sign_key=key)
    return out, key


def test_catalog_is_unsigned_without_a_key(tmp_path: Path) -> None:
    """No key, no signature members — signing must stay opt-in.

    Local and offline catalogues (the smoke guests' file:// repos) are built with
    no key at all, and a stray unverifiable signature member would make a
    `signature_type: none` client's catalogue differ for no reason.
    """
    in_dir = tmp_path / "in"
    in_dir.mkdir()
    make_pkg(in_dir / "demo-1.0_1.pkg")
    out = tmp_path / "out"
    brp.build_repo(in_dir, out)

    assert _sig_members(out / "packagesite.pkg") == {}
    assert _sig_members(out / "data.pkg") == {}


def test_signed_catalog_carries_the_member_names_pkg_repo_emits(tmp_path: Path) -> None:
    """`<member>.sig` + `<member>.pub`, named after the catalogue MEMBER.

    pkg_repo_pack_db() is called with meta->manifests ("packagesite.yaml") and
    meta->data ("data"), and pack_command_sign() derives "%s.sig"/"%s.pub" from
    that — NOT from the archive name. Getting this wrong leaves the client with
    an unpaired signature and a fatal "No signature found".
    """
    out, _ = _build_signed(tmp_path)

    assert sorted(_sig_members(out / "packagesite.pkg")) == [
        "packagesite.yaml.pub",
        "packagesite.yaml.sig",
    ]
    assert sorted(_sig_members(out / "data.pkg")) == ["data.pub", "data.sig"]


def test_signature_carries_the_pkgsign_ecdsa_header(tmp_path: Path) -> None:
    """A non-RSA signature is prefixed `$PKGSIGN:ecdsa$`; the client parses it to pick the signer."""
    out, _ = _build_signed(tmp_path)
    for archive, member in ((out / "packagesite.pkg", "packagesite.yaml.sig"), (out / "data.pkg", "data.sig")):
        assert _sig_members(archive)[member].startswith(_PKGSIGN_ECDSA_HEAD)


def test_signature_verifies_over_the_sha256_hex_message(tmp_path: Path) -> None:
    """The real cryptographic check, exactly as libpkg's FINGERPRINTS path does it.

    The signed message is the 64-character ASCII SHA256 HEX of the uncompressed
    catalogue member, ECDSA-SHA256 over that. The BLAKE2b-512 digest is the PUBKEY-mode
    convention (`ecc_verify_file()`); signing it here yields a catalogue that a real
    `pkg update` rejects with "ecc signature verification failure".
    """
    out, _ = _build_signed(tmp_path)

    for archive, member in (
        (out / "packagesite.pkg", "packagesite.yaml"),
        (out / "data.pkg", "data"),
    ):
        sigs = _sig_members(archive)
        sig = sigs[f"{member}.sig"][len(_PKGSIGN_ECDSA_HEAD) :]
        pub = sigs[f"{member}.pub"][len(_PKGSIGN_ECDSA_HEAD) :]
        message = _pkg_signed_message(_read_member(archive, member))
        assert len(message) == 64, "the signed message is the hex text, not a raw digest"
        assert _openssl_verify(message, sig, pub, tmp_path), f"{member} signature did not verify"


def test_signature_does_not_verify_for_a_tampered_catalog(tmp_path: Path) -> None:
    """Flip one byte of the catalogue and the signature must stop verifying.

    Without this, the test above would pass just as happily against a signature
    over the wrong bytes.
    """
    out, _ = _build_signed(tmp_path)
    sigs = _sig_members(out / "packagesite.pkg")
    sig = sigs["packagesite.yaml.sig"][len(_PKGSIGN_ECDSA_HEAD) :]
    pub = sigs["packagesite.yaml.pub"][len(_PKGSIGN_ECDSA_HEAD) :]
    tampered = _read_member(out / "packagesite.pkg", "packagesite.yaml") + b"x"
    assert not _openssl_verify(_pkg_signed_message(tampered), sig, pub, tmp_path)


def test_public_member_is_der_on_the_signing_curve(tmp_path: Path) -> None:
    """The `.pub` member is DER (no PEM armour) and matches the key we signed with.

    The loader calls libder_read() directly, so PEM would be unparseable; and the
    trusted fingerprint is the SHA256 of these exact bytes, so any re-encoding
    silently invalidates every deployed fingerprint file.
    """
    out, key = _build_signed(tmp_path)
    # The member carries the `$PKGSIGN:ecdsa$` header ahead of the key; the fingerprint is
    # computed over what remains, which must be the DER byte-for-byte.
    pub = _sig_members(out / "packagesite.pkg")["packagesite.yaml.pub"][len(_PKGSIGN_ECDSA_HEAD) :]

    assert not pub.startswith(b"-----BEGIN"), "the .pub member must be DER, not PEM"
    expected = subprocess.run(
        ["openssl", "ec", "-in", str(key), "-pubout", "-outform", "DER"],
        check=True,
        capture_output=True,
    ).stdout
    assert pub == expected


def test_signing_refuses_a_curve_pkg_cannot_verify(tmp_path: Path) -> None:
    """prime256v1 must be refused at build time, loudly.

    P-256 is the curve nearly every tool defaults to, and pkg's OID switch
    (ecc_read_pkgkey) does not accept it — only secp256k1/secp384r1/secp521r1 and
    the brainpool set. Signing with it would publish a catalogue that every box
    rejects, so this has to fail where we can see it: in the build.
    """
    in_dir = tmp_path / "in"
    in_dir.mkdir()
    make_pkg(in_dir / "demo-1.0_1.pkg")
    key = _gen_key(tmp_path / "p256.key", "prime256v1")

    with pytest.raises(brp.BuildRepoError, match="cannot verify signatures on curve"):
        brp.build_repo(in_dir, tmp_path / "out", sign_key=key)


def test_build_matrix_signs_every_catalog_it_emits(tmp_path: Path) -> None:
    """The matrix path is what the publisher runs, so the key has to reach it.

    Threading `sign_key` only as far as build_repo() would leave every published
    catalogue unsigned while the unit tests stayed green.
    """
    key = _gen_key(tmp_path / "repo.key")
    out = tmp_path / "site"
    brp.build_repo_matrix([_CE], out, builder=_stub_builder, sign_key=key)

    for catalog in (out / "release" / "ce-2.8", out / "nightly" / "ce-2.8"):
        assert sorted(_sig_members(catalog / "packagesite.pkg")) == [
            "packagesite.yaml.pub",
            "packagesite.yaml.sig",
        ], f"{catalog} packagesite.pkg is unsigned"
        assert sorted(_sig_members(catalog / "data.pkg")) == ["data.pub", "data.sig"]


def test_cli_sign_key_flag_signs_the_catalog(tmp_path: Path) -> None:
    """`--sign-key` is the publisher's entry point; without it nothing is signed."""
    in_dir = tmp_path / "in"
    in_dir.mkdir()
    make_pkg(in_dir / "demo-1.0_1.pkg")
    key = _gen_key(tmp_path / "repo.key")
    out = tmp_path / "out"

    rc = brp.main(["--in", str(in_dir), "--out", str(out), "--sign-key", str(key)])
    assert rc == 0
    assert sorted(_sig_members(out / "packagesite.pkg")) == [
        "packagesite.yaml.pub",
        "packagesite.yaml.sig",
    ]


def test_public_member_also_carries_the_pkgsign_header(tmp_path: Path) -> None:
    """The `.pub` member needs the `$PKGSIGN:ecdsa$` prefix too, not just `.sig`.

    With the header on `.sig` only, a real `pkg update` fails with

        pkg: error reading public key: error:1E08010C:DECODER routines::unsupported
        pkg: No trusted certificate has been used to sign the repository

    Cause: `pkg_repo_parse_sigkeys()` assigns `s->type` for EVERY member it parses,
    keyed by basename. The `.pub` entry is parsed after `.sig`, and with no header it
    defaults to "rsa", overwriting the "ecdsa" the `.sig` established. Verification
    then runs the RSA/ossl signer, whose `_load_public_key_buf()` uses
    `PEM_read_bio_PUBKEY` and cannot read our DER key.

    Upstream avoids this by accident of implementation: `pack_command_sign()` never
    resets `offset` between appends, so `iov[0]` still holds the header when it writes
    the `.pub` member — i.e. real `pkg repo` prefixes BOTH members for non-RSA.
    """
    out, _ = _build_signed(tmp_path)

    for archive, member in (
        (out / "packagesite.pkg", "packagesite.yaml"),
        (out / "data.pkg", "data"),
    ):
        sigs = _sig_members(archive)
        assert sigs[f"{member}.pub"].startswith(_PKGSIGN_ECDSA_HEAD), (
            f"{member}.pub lacks the header, so libpkg resets the signer type to rsa"
        )
        # The fingerprint is the sha256 of the cert bytes AFTER the header is stripped,
        # so the DER must still be recoverable exactly.
        assert sigs[f"{member}.pub"][len(_PKGSIGN_ECDSA_HEAD) :].startswith(b"\x30")


def test_openssl_that_cannot_be_executed_raises_build_error(tmp_path: Path, monkeypatch: Any) -> None:
    """An `openssl` on PATH that is not executable must still surface as BuildRepoError.

    `subprocess.run` raises PermissionError, not FileNotFoundError, for this case, so
    catching only the latter let a bare traceback escape the wrapper. Shadow PATH with a
    directory holding a non-executable `openssl` to exercise it.
    """
    shadow = tmp_path / "bin"
    shadow.mkdir()
    fake = shadow / "openssl"
    fake.write_text("#!/bin/sh\nexit 0\n")
    fake.chmod(0o644)  # present, findable, NOT executable
    monkeypatch.setenv("PATH", str(shadow))

    with pytest.raises(brp.BuildRepoError, match="cannot run `openssl`"):
        brp.catalog_signature(b"payload", tmp_path / "irrelevant.key")
