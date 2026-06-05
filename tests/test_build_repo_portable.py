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
import sys
import tarfile
from pathlib import Path
from typing import Any

import pytest

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
    abi: str = "FreeBSD:15:amd64",
    deps: dict[str, dict[str, str]] | None = None,
    extra: dict[str, Any] | None = None,
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
        payload = b"hey"
        tf2 = tarfile.TarInfo(name="/usr/local/bin/demo")
        tf2.size = len(payload)
        tf2.mode = 0o555
        tf.addfile(tf2, io.BytesIO(payload))
    path.write_bytes(brp._zstd_compress(raw.getvalue()))
    return manifest


def _read_member(zstd_tar: Path, member: str) -> bytes:
    data = brp._zstd_decompress(zstd_tar.read_bytes())
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
    bucket = out / "FreeBSD:15:amd64"
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

    raw = _read_member(out / "FreeBSD:15:amd64" / "packagesite.pkg", "packagesite.yaml")
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
    raw = _read_member(out / "FreeBSD:15:amd64" / "packagesite.pkg", "packagesite.yaml").decode()
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
    raw = _read_member(out / "FreeBSD:15:amd64" / "data.pkg", "data")
    assert not raw.endswith(b"\n"), "data has no trailing newline (matches real pkg repo)"
    obj = json.loads(raw)
    assert obj["groups"] == []
    assert obj["expired_packages"] == []
    assert len(obj["packages"]) == 1
    # The package object equals the packagesite object.
    psite = json.loads(_read_member(out / "FreeBSD:15:amd64" / "packagesite.pkg", "packagesite.yaml").decode())
    assert obj["packages"][0] == psite


# --------------------------------------------------------------------------- #
# Layout + ABI bucketing + the verbatim .pkg copy
# --------------------------------------------------------------------------- #


def test_layout_and_verbatim_pkg_copy(tmp_path: Path) -> None:
    """Each <ABI>/ holds the .pkg (byte-verbatim) + the catalog triple + meta."""
    in_dir = tmp_path / "in"
    in_dir.mkdir()
    pkg = in_dir / "demo-1.0_1.pkg"
    original = make_pkg(pkg)
    del original
    out = tmp_path / "out"
    abis = brp.build_repo(in_dir, out)
    assert abis == ["FreeBSD:15:amd64"]
    bucket = out / "FreeBSD:15:amd64"
    for fname in ("meta.conf", "meta", "packagesite.pkg", "data.pkg", "demo-1.0_1.pkg"):
        assert (bucket / fname).is_file(), f"missing {fname}"
    # The .pkg is copied verbatim (no re-archiving).
    assert (bucket / "demo-1.0_1.pkg").read_bytes() == pkg.read_bytes()


def test_per_abi_bucketing(tmp_path: Path) -> None:
    """Two ABIs -> two <ABI>/ subtrees, each catalog scoped to its own ABI's pkg."""
    in_dir = tmp_path / "in"
    in_dir.mkdir()
    make_pkg(in_dir / "a15.pkg", name="a", abi="FreeBSD:15:amd64")
    make_pkg(in_dir / "b16.pkg", name="b", abi="FreeBSD:16:amd64")
    out = tmp_path / "out"
    abis = brp.build_repo(in_dir, out)
    assert abis == ["FreeBSD:15:amd64", "FreeBSD:16:amd64"]
    # Each bucket's packagesite names exactly its own package; its .pkg lands there.
    for abi, pkgname, fname in (("FreeBSD:15:amd64", "a", "a15.pkg"), ("FreeBSD:16:amd64", "b", "b16.pkg")):
        raw = _read_member(out / abi / "packagesite.pkg", "packagesite.yaml").decode()
        objs = [json.loads(ln) for ln in raw.splitlines() if ln]
        assert [o["name"] for o in objs] == [pkgname]
        assert (out / abi / fname).is_file()


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
        a = (out1 / "FreeBSD:15:amd64" / rel).read_bytes()
        b = (out2 / "FreeBSD:15:amd64" / rel).read_bytes()
        assert a == b, f"{rel} differs between runs"


def test_rebuild_wipes_removed_pkg(tmp_path: Path) -> None:
    """A re-run after removing a .pkg drops it from the bucket (wipe-and-rebuild)."""
    in_dir = tmp_path / "in"
    in_dir.mkdir()
    make_pkg(in_dir / "a-1.0.pkg", name="a")
    make_pkg(in_dir / "b-1.0.pkg", name="b")
    out = tmp_path / "out"
    brp.build_repo(in_dir, out)
    assert (out / "FreeBSD:15:amd64" / "b-1.0.pkg").is_file()
    # Remove one input and rebuild.
    (in_dir / "b-1.0.pkg").unlink()
    brp.build_repo(in_dir, out)
    assert not (out / "FreeBSD:15:amd64" / "b-1.0.pkg").exists(), "stale .pkg lingered after rebuild"
    raw = _read_member(out / "FreeBSD:15:amd64" / "packagesite.pkg", "packagesite.yaml").decode()
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
    assert abis == ["FreeBSD:15:amd64"]


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
    """--print-conf emits the NONE-signed ${ABI}/priority-100 client stanza."""
    rc = brp.main(["--print-conf"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "pfblockerng-devel: {" in out
    assert 'url: "https://andrebrait.github.io/pfBlockerNG/${ABI}"' in out
    assert "signature_type: none," in out
    assert "priority: 100," in out
    assert "enabled: yes" in out


def test_print_conf_base_url_override(capsys: pytest.CaptureFixture[str]) -> None:
    """--base-url overrides the host while keeping the literal ${ABI} suffix."""
    rc = brp.main(["--print-conf", "--base-url", "https://fork.example.io/p/"])
    assert rc == 0
    out = capsys.readouterr().out
    assert 'url: "https://fork.example.io/p/${ABI}"' in out  # trailing slash trimmed


def test_cli_requires_in_and_out(capsys: pytest.CaptureFixture[str]) -> None:
    """Without --in/--out (and no --print-conf) the CLI errors."""
    with pytest.raises(SystemExit):
        brp.main([])
