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


def test_published_pkg_preserves_source_mtime(tmp_path: Path) -> None:
    """The published .pkg keeps the SOURCE artifact's mtime (its real build time).

    The landing page reads this mtime as the publish datetime, so it must survive
    catalog generation — otherwise a cache-restored nightly would wrongly show the
    regeneration run's time. Set a fixed past mtime on the input and assert it rides
    through to the published copy.
    """
    in_dir = tmp_path / "in"
    in_dir.mkdir()
    src = in_dir / "demo-1.0_1.pkg"
    make_pkg(src)
    build_mtime = 1700000000  # 2023-11-14, clearly before "now"
    os.utime(src, (build_mtime, build_mtime))

    out = tmp_path / "out"
    brp.build_repo(in_dir, out)

    dest = out / "FreeBSD:15:amd64" / "demo-1.0_1.pkg"
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
    # Each bucket's packagesite names exactly its own package; its .pkg lands there
    # under the CANONICAL `<name>-<version>.pkg` (NOT the staging input filename
    # `a15.pkg`/`b16.pkg`).
    for abi, pkgname, fname in (("FreeBSD:15:amd64", "a", "a-1.0_1.pkg"), ("FreeBSD:16:amd64", "b", "b-1.0_1.pkg")):
        raw = _read_member(out / abi / "packagesite.pkg", "packagesite.yaml").decode()
        objs = [json.loads(ln) for ln in raw.splitlines() if ln]
        assert [o["name"] for o in objs] == [pkgname]
        assert [o["path"] for o in objs] == [fname]
        assert (out / abi / fname).is_file()


def test_duplicate_sources_dedup_to_one_canonical(tmp_path: Path) -> None:
    """The SAME package staged from two sources (the publish job's `built-<source>-`
    prefixed copies of the branch build + a release artifact) publishes exactly ONE
    canonical `.pkg` + ONE catalog entry — not two prefixed duplicates (the bug the
    first live deploy surfaced)."""
    in_dir = tmp_path / "in"
    in_dir.mkdir()
    # Same name+version+ABI+flavor; different staging input filenames.
    make_pkg(in_dir / "built-incoming_branch-pfb.pkg", name="pfb", version="3.2.16")
    make_pkg(in_dir / "built-incoming_release-freebsd-pfb.pkg", name="pfb", version="3.2.16")
    out = tmp_path / "out"
    brp.build_repo(in_dir, out)
    bucket = out / "FreeBSD:15:amd64"
    # Exactly one package .pkg on disk, canonically named (no `built-incoming_*`
    # prefix); the catalog files (packagesite.pkg/data.pkg) also end in `.pkg`.
    catalog_files = {"packagesite.pkg", "data.pkg", "meta.pkg"}
    pkgs = sorted(p.name for p in bucket.glob("*.pkg") if p.name not in catalog_files)
    assert pkgs == ["pfb-3.2.16.pkg"]
    # The catalog lists it once, at the canonical path/repopath.
    raw = _read_member(bucket / "packagesite.pkg", "packagesite.yaml").decode()
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
    assert (out / "FreeBSD:15:amd64" / "b-1.0_1.pkg").is_file()  # canonical <name>-<version>
    # Remove one input and rebuild.
    (in_dir / "b-1.0.pkg").unlink()
    brp.build_repo(in_dir, out)
    assert not (out / "FreeBSD:15:amd64" / "b-1.0_1.pkg").exists(), "stale .pkg lingered after rebuild"
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


def test_unsafe_abi_is_rejected(tmp_path: Path) -> None:
    """A traversal/odd ABI in manifest data is rejected BEFORE it becomes a path
    segment — `out_dir / abi` is rmtree'd + rebuilt, so an unsafe value could escape
    out_dir. The valid form (`FreeBSD:15:amd64`, with colons) is accepted by every
    other test, so this pins the reject side of the branch."""
    # Non-empty but unsafe values (traversal / slash / space) — an empty ABI is
    # already rejected upstream by the missing-name/version/abi guard.
    out = tmp_path / "out"
    for i, bad in enumerate(("../../evil", "FreeBSD/15/amd64", "a b")):
        in_dir = tmp_path / f"in{i}"
        in_dir.mkdir()
        make_pkg(in_dir / "p.pkg", name="p", version="1.0", abi=bad)
        with pytest.raises(brp.BuildRepoError, match="unsafe or invalid ABI"):
            brp.build_repo(in_dir, out)


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
    assert "pfblockerng: {" in out  # the shared release repo (stable + devel)
    assert 'url: "https://pkg.pfblockerng.workers.dev/release/${ABI}"' in out  # Worker URL + release prefix (ADR-20)
    assert "signature_type: none," in out
    assert "priority: 100," in out
    assert "enabled: yes" in out


def test_print_conf_base_url_override(capsys: pytest.CaptureFixture[str]) -> None:
    """--base-url overrides the host while keeping the literal ${ABI} suffix."""
    rc = brp.main(["--print-conf", "--base-url", "https://fork.example.io/p/"])
    assert rc == 0
    out = capsys.readouterr().out
    assert 'url: "https://fork.example.io/p/release/${ABI}"' in out  # trailing slash trimmed + release prefix


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


def test_catalog_under_versioned_subdir(tmp_path: Path) -> None:
    """--catalog-name writes the ABI tree under <out>/<catalog-name>/<ABI>/, not <out>/<ABI>/.

    Scenario: CE 2.8 build
      Given no ce-2.8/ dir exists in <out>
      When build_repo(catalog_name="ce-2.8") is called with a CE pkg (ABI=FreeBSD:15:amd64)
      Then meta.conf exists at ce-2.8/FreeBSD:15:amd64/meta.conf
      And no meta.conf exists at the plain FreeBSD:15:amd64/meta.conf (root-level)
    """
    in_dir = tmp_path / "in"
    in_dir.mkdir()
    make_pkg(in_dir / "ce-pkg.pkg", name="pfBlockerNG-devel", abi="FreeBSD:15:amd64")
    out = tmp_path / "out"
    out.mkdir()

    # Before-state: no ce-2.8/ dir
    assert not (out / "ce-2.8").exists()

    brp.build_repo(in_dir, out, catalog_name="ce-2.8")

    # Versioned path exists
    assert (out / "ce-2.8" / "FreeBSD:15:amd64" / "meta.conf").is_file()
    # Legacy root-level path does NOT exist
    assert not (out / "FreeBSD:15:amd64" / "meta.conf").exists()


def test_plus_catalog_under_versioned_subdir(tmp_path: Path) -> None:
    """--catalog-name plus-26.03 writes under plus-26.03/<ABI>/, no ce-2.8/ dir created.

    Scenario: Plus 26.03 build
      Given no plus-26.03/ or ce-2.8/ dir exists
      When build_repo(catalog_name="plus-26.03") with Plus pkg (ABI=FreeBSD:16:amd64)
      Then meta.conf at plus-26.03/FreeBSD:16:amd64/meta.conf
      And no ce-2.8/ dir exists
    """
    in_dir = tmp_path / "in"
    in_dir.mkdir()
    make_pkg(in_dir / "plus-pkg.pkg", name="pfBlockerNG-devel", abi="FreeBSD:16:amd64")
    out = tmp_path / "out"
    out.mkdir()

    # Before-state: neither versioned dir exists
    assert not (out / "plus-26.03").exists()
    assert not (out / "ce-2.8").exists()

    brp.build_repo(in_dir, out, catalog_name="plus-26.03")

    assert (out / "plus-26.03" / "FreeBSD:16:amd64" / "meta.conf").is_file()
    # CE dir must NOT have been created as a side-effect
    assert not (out / "ce-2.8").exists()


def test_legacy_path_retained(tmp_path: Path) -> None:
    """Without --catalog-name, meta.conf lands at <out>/<ABI>/meta.conf (legacy layout unchanged).

    This is the regression guard: passing catalog_name=None must NOT change existing behaviour.
    """
    in_dir = tmp_path / "in"
    in_dir.mkdir()
    make_pkg(in_dir / "demo.pkg", abi="FreeBSD:15:amd64")
    out = tmp_path / "out"

    brp.build_repo(in_dir, out)  # no catalog_name

    assert (out / "FreeBSD:15:amd64" / "meta.conf").is_file()
    # No versioned subdirs created
    assert not (out / "ce-2.8").exists()
    assert not (out / "plus-26.03").exists()


def test_wrong_variant_pkg_excluded(tmp_path: Path) -> None:
    """A CE pkg built into ce-2.8/ does NOT appear in plus-26.03/ and vice-versa.

    Scenario: cross-variant contamination guard
      Given a CE pkg named "pfBlockerNG-ce" (ABI FreeBSD:15:amd64)
        And a Plus pkg named "pfBlockerNG-plus" (ABI FreeBSD:16:amd64)
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
    make_pkg(ce_dir / "ce.pkg", name="pfBlockerNG-ce", abi="FreeBSD:15:amd64")
    make_pkg(plus_dir / "plus.pkg", name="pfBlockerNG-plus", abi="FreeBSD:16:amd64")
    out = tmp_path / "out"

    brp.build_repo(ce_dir, out, catalog_name="ce-2.8")
    brp.build_repo(plus_dir, out, catalog_name="plus-26.03")

    # CE packagesite names
    ce_raw = _read_member(out / "ce-2.8" / "FreeBSD:15:amd64" / "packagesite.pkg", "packagesite.yaml").decode()
    ce_names = {json.loads(ln)["name"] for ln in ce_raw.splitlines() if ln}
    assert "pfBlockerNG-ce" in ce_names
    assert "pfBlockerNG-plus" not in ce_names

    # Plus packagesite names
    plus_raw = _read_member(out / "plus-26.03" / "FreeBSD:16:amd64" / "packagesite.pkg", "packagesite.yaml").decode()
    plus_names = {json.loads(ln)["name"] for ln in plus_raw.splitlines() if ln}
    assert "pfBlockerNG-plus" in plus_names
    assert "pfBlockerNG-ce" not in plus_names


def test_two_ce_entries_produce_two_versioned_dirs(tmp_path: Path) -> None:
    """Two CE builds (different versions, different ABIs) each get their own versioned dir.

    Scenario: transition window with two active CE versions
      Given no ce-2.8/ or ce-2.9/ dir exists
      When build_repo(catalog_name="ce-2.8") with ABI=FreeBSD:15:amd64
       And build_repo(catalog_name="ce-2.9") with ABI=FreeBSD:16:amd64
      Then ce-2.8/FreeBSD:15:amd64/meta.conf exists
       And ce-2.9/FreeBSD:16:amd64/meta.conf exists
       And each packagesite contains only its own pkg (no cross-contamination)
    """
    in28 = tmp_path / "in28"
    in28.mkdir()
    in29 = tmp_path / "in29"
    in29.mkdir()
    make_pkg(in28 / "pkg28.pkg", name="pfBlockerNG-2.8", abi="FreeBSD:15:amd64")
    make_pkg(in29 / "pkg29.pkg", name="pfBlockerNG-2.9", abi="FreeBSD:16:amd64")
    out = tmp_path / "out"

    # Before-state: neither dir exists
    assert not (out / "ce-2.8").exists()
    assert not (out / "ce-2.9").exists()

    brp.build_repo(in28, out, catalog_name="ce-2.8")
    brp.build_repo(in29, out, catalog_name="ce-2.9")

    assert (out / "ce-2.8" / "FreeBSD:15:amd64" / "meta.conf").is_file()
    assert (out / "ce-2.9" / "FreeBSD:16:amd64" / "meta.conf").is_file()

    # No cross-contamination: each packagesite has only its pkg
    raw28 = _read_member(out / "ce-2.8" / "FreeBSD:15:amd64" / "packagesite.pkg", "packagesite.yaml").decode()
    names28 = [json.loads(ln)["name"] for ln in raw28.splitlines() if ln]
    assert names28 == ["pfBlockerNG-2.8"]

    raw29 = _read_member(out / "ce-2.9" / "FreeBSD:16:amd64" / "packagesite.pkg", "packagesite.yaml").decode()
    names29 = [json.loads(ln)["name"] for ln in raw29.splitlines() if ln]
    assert names29 == ["pfBlockerNG-2.9"]


def test_routing_json_correct_entries(tmp_path: Path) -> None:
    """generate_routing_json writes all entries with correct catalog/pattern/status fields.

    Scenario: two active + one legacy entry
      Given entries with two "active" and one "legacy" status
      When generate_routing_json is called
      Then routing.json contains all three entries
       And each has the correct catalog, pattern, and status fields
       And both active and legacy entries are present (legacy routes retained)
    """
    entries = [
        {"pattern": "pfSense/2.8", "catalog": "ce-2.8", "status": "active"},
        {"pattern": "pfSense/26.03", "catalog": "plus-26.03", "status": "active"},
        {"pattern": "pfSense/2.7", "catalog": "ce-2.7", "status": "legacy"},
    ]
    output_path = str(tmp_path / "routing.json")

    brp.generate_routing_json(entries, output_path)

    with open(output_path) as f:
        doc = json.load(f)

    assert "routes" in doc
    routes = doc["routes"]
    assert len(routes) == 3

    by_catalog = {r["catalog"]: r for r in routes}
    assert by_catalog["ce-2.8"]["pattern"] == "pfSense/2.8"
    assert by_catalog["ce-2.8"]["status"] == "active"
    assert by_catalog["plus-26.03"]["pattern"] == "pfSense/26.03"
    assert by_catalog["plus-26.03"]["status"] == "active"
    assert by_catalog["ce-2.7"]["pattern"] == "pfSense/2.7"
    assert by_catalog["ce-2.7"]["status"] == "legacy"


def test_routing_json_legacy_retained(tmp_path: Path) -> None:
    """Legacy entries are present in routing.json with status="legacy" — NOT omitted.

    Scenario: legacy entry preservation
      Given a single entry with status "legacy"
      When generate_routing_json is called
      Then routing.json contains the entry
       And its status is "legacy" (not absent, not "active")
    """
    entries = [{"pattern": "pfSense/2.7", "catalog": "ce-2.7", "status": "legacy"}]
    output_path = str(tmp_path / "routing.json")

    brp.generate_routing_json(entries, output_path)

    with open(output_path) as f:
        doc = json.load(f)

    routes = doc["routes"]
    assert len(routes) == 1
    assert routes[0]["status"] == "legacy"
    assert routes[0]["catalog"] == "ce-2.7"


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
    """build_repo with catalog_name="nightly/ce-2.8" writes tree under nightly/ce-2.8/<ABI>/.

    Scenario: nightly CE build
      Given no nightly/ dir exists in <out>
      When build_repo(catalog_name="nightly/ce-2.8") with a CE pkg (ABI=FreeBSD:15:amd64)
      Then meta.conf exists at nightly/ce-2.8/FreeBSD:15:amd64/meta.conf
       And no meta.conf exists at ce-2.8/FreeBSD:15:amd64/meta.conf (release path untouched)
       And no meta.conf exists at FreeBSD:15:amd64/meta.conf (legacy root untouched)
    """
    in_dir = tmp_path / "in"
    in_dir.mkdir()
    make_pkg(in_dir / "nightly-ce.pkg", name="pfBlockerNG-nightly", abi="FreeBSD:15:amd64")
    out = tmp_path / "out"
    out.mkdir()

    # Before-state: no nightly/ dir
    assert not (out / "nightly").exists()

    brp.build_repo(in_dir, out, catalog_name="nightly/ce-2.8")

    # Nightly versioned path exists
    assert (out / "nightly" / "ce-2.8" / "FreeBSD:15:amd64" / "meta.conf").is_file()
    # Release path NOT created as side-effect
    assert not (out / "ce-2.8").exists()
    # Legacy root-level ABI path NOT created
    assert not (out / "FreeBSD:15:amd64" / "meta.conf").exists()


def test_nightly_plus_catalog_under_versioned_subdir(tmp_path: Path) -> None:
    """build_repo with catalog_name="nightly/plus-26.03" writes under nightly/plus-26.03/<ABI>/.

    Scenario: nightly Plus build, nightly CE build in same output tree
      Given no nightly/ dir exists
      When build_repo(catalog_name="nightly/ce-2.8") with CE pkg (FreeBSD:15:amd64)
       And build_repo(catalog_name="nightly/plus-26.03") with Plus pkg (FreeBSD:16:amd64)
      Then nightly/ce-2.8/FreeBSD:15:amd64/meta.conf exists
       And nightly/plus-26.03/FreeBSD:16:amd64/meta.conf exists
       And the CE and Plus nightly packagesite contents do not cross-contaminate
    """
    ce_dir = tmp_path / "ce_in"
    ce_dir.mkdir()
    plus_dir = tmp_path / "plus_in"
    plus_dir.mkdir()
    make_pkg(ce_dir / "ce-nightly.pkg", name="pfBlockerNG-nightly-ce", abi="FreeBSD:15:amd64")
    make_pkg(plus_dir / "plus-nightly.pkg", name="pfBlockerNG-nightly-plus", abi="FreeBSD:16:amd64")
    out = tmp_path / "out"

    # Before-state: no nightly dir
    assert not (out / "nightly").exists()

    brp.build_repo(ce_dir, out, catalog_name="nightly/ce-2.8")
    brp.build_repo(plus_dir, out, catalog_name="nightly/plus-26.03")

    assert (out / "nightly" / "ce-2.8" / "FreeBSD:15:amd64" / "meta.conf").is_file()
    assert (out / "nightly" / "plus-26.03" / "FreeBSD:16:amd64" / "meta.conf").is_file()

    ce_raw = _read_member(
        out / "nightly" / "ce-2.8" / "FreeBSD:15:amd64" / "packagesite.pkg", "packagesite.yaml"
    ).decode()
    ce_names = {json.loads(ln)["name"] for ln in ce_raw.splitlines() if ln}
    assert "pfBlockerNG-nightly-ce" in ce_names
    assert "pfBlockerNG-nightly-plus" not in ce_names

    plus_raw = _read_member(
        out / "nightly" / "plus-26.03" / "FreeBSD:16:amd64" / "packagesite.pkg", "packagesite.yaml"
    ).decode()
    plus_names = {json.loads(ln)["name"] for ln in plus_raw.splitlines() if ln}
    assert "pfBlockerNG-nightly-plus" in plus_names
    assert "pfBlockerNG-nightly-ce" not in plus_names


# --------------------------------------------------------------------------- #
# ADR-20 routing rework: the matrix-driven brain (build_repo_matrix + helpers)
#
# These pin the LITERAL 1:1 projection of the version matrix onto the tree
# (release/<varver>/<arch>/ + nightly/<varver>/<arch>/, arch leaf — NOT full ABI),
# the routing.json contents, the release channel-group (devel + stable in one
# catalog), full-matrix/no-dedup placement, and nightly retention. The DUMB pkg
# builder is stubbed so the tests exercise the BRAIN (arrangement) without a ports
# tree — build-pkg-portable.py's own behaviour is covered by its own suite.
# --------------------------------------------------------------------------- #

# The live matrix shape (subset of fields build_repo_matrix consumes).
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

_CHANNEL_NAME = {"devel": "pfBlockerNG-devel", "stable": "pfBlockerNG", "nightly": "pfBlockerNG-nightly"}


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
    landed there); the manifest carries the requested ABI + a versioned php guard dep
    (so a wrong-flavor mix would trip the collision guard, as in a real build).
    """
    name = _CHANNEL_NAME[channel]
    version = pkgversion or "1.0_1"
    php_dep = "php" + php.replace(".", "")
    deps = {
        php_dep: {"origin": f"lang/{php_dep}", "version": "0"},
        py_flavor: {"origin": f"lang/{py_flavor}", "version": "0"},
    }
    # Distinct on-disk filename per (channel, varver, arch) so concurrent staging never clashes;
    # the catalog copies it CANONICALLY as <name>-<version>.pkg regardless.
    out = out_dir / f"{name}-{version}-{varver}-{arch}-{channel}.pkg"
    make_pkg(out, name=name, version=version, abi=abi, deps=deps)
    return out


def _names_in(catalog_pkg: Path) -> set[str]:
    raw = _read_member(catalog_pkg, "packagesite.yaml").decode()
    return {json.loads(ln)["name"] for ln in raw.splitlines() if ln}


def test_ua_pattern_ce_vs_plus() -> None:
    """_ua_pattern: CE -> 'pfSense/<mm>'; Plus -> 'Netgate pfSense Plus/<mm>'."""
    assert brp._ua_pattern("CE", "2.8") == "pfSense/2.8"
    assert brp._ua_pattern("CE", "2.8.1") == "pfSense/2.8"
    assert brp._ua_pattern("Plus", "26.03") == "Netgate pfSense Plus/26.03"
    assert brp._ua_pattern("Plus", "26.03.1") == "Netgate pfSense Plus/26.03"


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


def test_dedup_routes_collapses_and_orders_most_specific_first() -> None:
    """_dedup_routes collapses identical (pattern,catalog,status) and longest-pattern-first.

    Two Plus entries (amd64 + aarch64) share the same UA pattern/catalog/status -> ONE route.
    The longer Plus pattern precedes the shorter CE pattern (Worker first-match-wins).
    """
    routes = [
        {"pattern": "pfSense/2.8", "catalog": "ce-2.8", "status": "active"},
        {"pattern": "Netgate pfSense Plus/26.03", "catalog": "plus-26.03", "status": "active"},
        {"pattern": "Netgate pfSense Plus/26.03", "catalog": "plus-26.03", "status": "active"},
    ]
    out = brp._dedup_routes(routes)
    assert len(out) == 2  # the duplicate Plus route collapsed
    assert out[0]["pattern"] == "Netgate pfSense Plus/26.03"  # most specific first
    assert out[1]["pattern"] == "pfSense/2.8"


def test_build_matrix_tree_layout_arch_leaf(tmp_path: Path) -> None:
    """build_repo_matrix projects the matrix 1:1 with the bare ARCH as the leaf.

    Scenario: a CE + a Plus entry
      Given an empty output root
      When build_repo_matrix runs over [CE, Plus]
      Then release/ce-2.8/amd64/ and release/plus-26.03/amd64/ catalogs exist
       And the leaf is the bare arch — NOT the full ABI (no FreeBSD:NN:amd64 dir)
       And the matching nightly subtrees exist
    """
    out = tmp_path / "site"
    # Before-state: nothing built.
    assert not out.exists()

    brp.build_repo_matrix([_CE, _PLUS], out, builder=_stub_builder)

    # Arch leaf, version segment implies the FreeBSD major.
    assert (out / "release" / "ce-2.8" / "amd64" / "meta.conf").is_file()
    assert (out / "release" / "plus-26.03" / "amd64" / "meta.conf").is_file()
    assert (out / "nightly" / "ce-2.8" / "amd64" / "meta.conf").is_file()
    assert (out / "nightly" / "plus-26.03" / "amd64" / "meta.conf").is_file()
    # The full ABI must NOT appear as a path segment (this is the arch-leaf reconciliation).
    assert not (out / "release" / "ce-2.8" / "FreeBSD:15:amd64").exists()
    assert not (out / "release" / "plus-26.03" / "FreeBSD:16:amd64").exists()


def test_build_matrix_routing_json(tmp_path: Path) -> None:
    """routing.json carries one deduped route per variant, catalog=varver, with status.

    Scenario: CE + Plus(amd64) + Plus(aarch64)
      When build_repo_matrix runs
      Then routing.json has TWO routes (the two Plus arches collapse to one),
           each {pattern: UA, catalog: varver, status}, most specific first.
    """
    out = tmp_path / "site"
    brp.build_repo_matrix([_CE, _PLUS, _PLUS_ARM], out, builder=_stub_builder)

    routing = json.loads((out / "routing.json").read_text())
    routes = routing["routes"]
    assert len(routes) == 2  # Plus amd64 + aarch64 collapsed to one route
    # Most-specific (Plus) first.
    assert routes[0] == {"pattern": "Netgate pfSense Plus/26.03", "catalog": "plus-26.03", "status": "active"}
    assert routes[1] == {"pattern": "pfSense/2.8", "catalog": "ce-2.8", "status": "active"}


def test_build_matrix_routing_status_passthrough(tmp_path: Path) -> None:
    """A legacy entry's status flows into its route verbatim (not dropped, not rewritten)."""
    legacy_ce = {**_CE, "status": "legacy"}
    out = tmp_path / "site"
    brp.build_repo_matrix([legacy_ce], out, builder=_stub_builder)
    routes = json.loads((out / "routing.json").read_text())["routes"]
    assert routes == [{"pattern": "pfSense/2.8", "catalog": "ce-2.8", "status": "legacy"}]


def test_build_matrix_release_holds_devel_and_stable(tmp_path: Path) -> None:
    """The release channel-group is devel-only without a stable tag, devel+stable with one.

    Scenario: stable tag absent -> present (the branch + the before/after)
      Given build_repo_matrix([CE]) with NO stable_tag
      Then release/ce-2.8/amd64 holds ONLY the devel package
      When re-run WITH stable_tag set
      Then the release catalog holds BOTH the devel and the stable package
    """
    out = tmp_path / "site"

    # Off branch: no stable tag -> devel only.
    brp.build_repo_matrix([_CE], out, builder=_stub_builder)
    rel = out / "release" / "ce-2.8" / "amd64" / "packagesite.pkg"
    assert _names_in(rel) == {"pfBlockerNG-devel"}

    # On branch: a stable tag -> devel + stable coexist in ONE catalog.
    brp.build_repo_matrix([_CE], out, builder=_stub_builder, stable_tag="v3.2.15")
    assert _names_in(rel) == {"pfBlockerNG-devel", "pfBlockerNG"}


def test_build_matrix_full_matrix_no_dedup(tmp_path: Path) -> None:
    """Two versions sharing ABI+php+py still get their OWN subtree (full matrix, no dedup)."""
    ce_28 = _CE
    ce_29 = {**_CE, "pfsense_version": "2.9"}  # same FreeBSD major/php/py as 2.8
    out = tmp_path / "site"
    brp.build_repo_matrix([ce_28, ce_29], out, builder=_stub_builder)
    # Distinct version segments, each populated independently.
    assert (out / "release" / "ce-2.8" / "amd64" / "meta.conf").is_file()
    assert (out / "release" / "ce-2.9" / "amd64" / "meta.conf").is_file()


def test_build_matrix_aarch64_distinct_leaf(tmp_path: Path) -> None:
    """An aarch64 Plus entry lands under its own arch leaf, separate from amd64."""
    out = tmp_path / "site"
    brp.build_repo_matrix([_PLUS, _PLUS_ARM], out, builder=_stub_builder)
    assert (out / "release" / "plus-26.03" / "amd64" / "meta.conf").is_file()
    assert (out / "release" / "plus-26.03" / "aarch64" / "meta.conf").is_file()


def test_build_matrix_no_nightly(tmp_path: Path) -> None:
    """build_nightly=False builds the release subtree + routing but NO nightly/ tree."""
    out = tmp_path / "site"
    brp.build_repo_matrix([_CE], out, builder=_stub_builder, build_nightly=False)
    assert (out / "release" / "ce-2.8" / "amd64" / "meta.conf").is_file()
    assert (out / "routing.json").is_file()
    assert not (out / "nightly").exists()


def test_build_matrix_nightly_retention(tmp_path: Path) -> None:
    """Nightly subtree retains only the N newest builds across runs (a later build supersedes).

    Scenario: nightly_keep=2, three successive nightly versions
      Given build #1 (.1) -> the subtree holds 1 nightly
       When build #2 (.2) lands -> it holds 2
       When build #3 (.3) lands -> it is pruned back to 2, keeping the 2 NEWEST (.2, .3)
    """
    out = tmp_path / "site"
    nl = out / "nightly" / "ce-2.8" / "amd64" / "packagesite.pkg"

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


def test_build_matrix_annotate_passthrough(tmp_path: Path) -> None:
    """annotate kwargs reach every builder call (so publish.yml's commit/created stamp lands).

    Given a recording builder,
      When build_repo_matrix runs with annotate={commit, created},
      Then every build (devel + nightly) receives that exact annotate dict.
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
    assert {c["channel"] for c in seen} == {"devel", "nightly"}


# --------------------------------------------------------------------------- #
# ADR-27 Phase 1: retain_by_channel — channel-keyed release-retention helper
#
# These tests pin the helper in isolation (no call-site change in build_repo_matrix
# yet — Phase 2 wires it in). They cover every branch:
#   * devel vs stable bucketed independently (one does not affect the other)
#   * keep < len(bucket) → prune to newest keep (version order + determinism)
#   * keep >= len(bucket) → no-op (keep all)
#   * keep == 0 → keep all of that channel (the "unbounded/disabled" sentinel)
#   * mixed devel+stable+nightly input: nightly left untouched regardless
#   * before-state assertions where the outcome depends on keep value
# --------------------------------------------------------------------------- #


def _make_pkg_channel(
    tmp_path: Path,
    name: str,
    version: str,
    *,
    abi: str = "FreeBSD:15:amd64",
) -> Path:
    """Write a minimal .pkg and return its path (name encodes the channel)."""
    p = tmp_path / f"{name}-{version}.pkg"
    make_pkg(p, name=name, version=version, abi=abi)
    return p


def test_retain_by_channel_devel_pruned_independently(tmp_path: Path) -> None:
    """Devel bucket is pruned to keep_devel; stable bucket is untouched when keep_stable=0.

    Scenario: 3 devel versions + 2 stable versions; keep_devel=2, keep_stable=0
      Given 3 devel pkgs (v1, v2, v3) and 2 stable pkgs (s1.0, s2.0)
        And keep_devel=2, keep_stable=0 (stable unbounded)
      When retain_by_channel is called
      Then devel result contains only the 2 newest (v2, v3) — v1 dropped
       And stable result contains BOTH stable pkgs (keep_stable=0 = keep all)
    """
    d = tmp_path / "pkgs"
    d.mkdir()
    dv1 = _make_pkg_channel(d, "pfBlockerNG-devel", "3.0.1")
    dv2 = _make_pkg_channel(d, "pfBlockerNG-devel", "3.0.2")
    dv3 = _make_pkg_channel(d, "pfBlockerNG-devel", "3.0.3")
    sv1 = _make_pkg_channel(d, "pfBlockerNG", "2.0.1")
    sv2 = _make_pkg_channel(d, "pfBlockerNG", "2.0.2")

    # Before-state: all 5 paths provided.
    all_paths = [dv1, dv2, dv3, sv1, sv2]

    kept = brp.retain_by_channel(all_paths, keep_devel=2, keep_stable=0)

    kept_names_versions = {
        (brp.read_compact_manifest(p)["name"], brp.read_compact_manifest(p)["version"]) for p in kept
    }
    # Devel: newest 2 kept (v2, v3); v1 dropped.
    assert ("pfBlockerNG-devel", "3.0.3") in kept_names_versions
    assert ("pfBlockerNG-devel", "3.0.2") in kept_names_versions
    assert ("pfBlockerNG-devel", "3.0.1") not in kept_names_versions
    # Stable: both kept (keep_stable=0 = unbounded).
    assert ("pfBlockerNG", "2.0.1") in kept_names_versions
    assert ("pfBlockerNG", "2.0.2") in kept_names_versions


def test_retain_by_channel_stable_pruned_independently(tmp_path: Path) -> None:
    """Stable bucket is pruned to keep_stable; devel bucket is untouched when keep_devel=0.

    Scenario: 2 devel versions + 3 stable versions; keep_devel=0, keep_stable=1
      Given 2 devel pkgs (v1, v2) and 3 stable pkgs (s1.0, s2.0, s3.0)
        And keep_devel=0 (unbounded), keep_stable=1
      When retain_by_channel is called
      Then stable result contains only s3.0 (newest 1); s1.0 and s2.0 dropped
       And devel result contains BOTH devel pkgs (keep_devel=0 = keep all)
    """
    d = tmp_path / "pkgs"
    d.mkdir()
    dv1 = _make_pkg_channel(d, "pfBlockerNG-devel", "3.0.1")
    dv2 = _make_pkg_channel(d, "pfBlockerNG-devel", "3.0.2")
    sv1 = _make_pkg_channel(d, "pfBlockerNG", "2.0.1")
    sv2 = _make_pkg_channel(d, "pfBlockerNG", "2.0.2")
    sv3 = _make_pkg_channel(d, "pfBlockerNG", "2.0.3")

    # Before-state: all 5 paths.
    all_paths = [dv1, dv2, sv1, sv2, sv3]

    kept = brp.retain_by_channel(all_paths, keep_devel=0, keep_stable=1)

    kept_nv = {(brp.read_compact_manifest(p)["name"], brp.read_compact_manifest(p)["version"]) for p in kept}
    # Stable: only newest (s3.0).
    assert ("pfBlockerNG", "2.0.3") in kept_nv
    assert ("pfBlockerNG", "2.0.2") not in kept_nv
    assert ("pfBlockerNG", "2.0.1") not in kept_nv
    # Devel: both kept.
    assert ("pfBlockerNG-devel", "3.0.1") in kept_nv
    assert ("pfBlockerNG-devel", "3.0.2") in kept_nv


def test_retain_by_channel_keep_zero_is_unbounded_sentinel(tmp_path: Path) -> None:
    """keep==0 for a channel keeps ALL of that channel (the unbounded/disabled sentinel).

    Scenario: keep_devel=0, keep_stable=0
      Given 3 devel pkgs and 3 stable pkgs
      When retain_by_channel with both keeps=0
      Then ALL 6 paths are returned (no pruning)
    """
    d = tmp_path / "pkgs"
    d.mkdir()
    all_paths = [_make_pkg_channel(d, "pfBlockerNG-devel", f"3.0.{i}") for i in range(1, 4)] + [
        _make_pkg_channel(d, "pfBlockerNG", f"2.0.{i}") for i in range(1, 4)
    ]

    # Before-state: 6 paths in.
    assert len(all_paths) == 6

    kept = brp.retain_by_channel(all_paths, keep_devel=0, keep_stable=0)

    # All 6 kept.
    assert len(kept) == 6
    kept_versions_devel = {
        brp.read_compact_manifest(p)["version"]
        for p in kept
        if brp.read_compact_manifest(p)["name"] == "pfBlockerNG-devel"
    }
    kept_versions_stable = {
        brp.read_compact_manifest(p)["version"] for p in kept if brp.read_compact_manifest(p)["name"] == "pfBlockerNG"
    }
    assert kept_versions_devel == {"3.0.1", "3.0.2", "3.0.3"}
    assert kept_versions_stable == {"2.0.1", "2.0.2", "2.0.3"}


def test_retain_by_channel_keep_larger_than_bucket_is_noop(tmp_path: Path) -> None:
    """keep >= len(bucket) is a no-op — all paths in that bucket are retained.

    Scenario: keep_devel=100, keep_stable=100 with only 2 devel and 2 stable pkgs
      Given 2 devel pkgs and 2 stable pkgs
        And keep values far larger than the buckets
      When retain_by_channel is called
      Then all 4 paths are returned (no pruning)
    """
    d = tmp_path / "pkgs"
    d.mkdir()
    dv1 = _make_pkg_channel(d, "pfBlockerNG-devel", "3.0.1")
    dv2 = _make_pkg_channel(d, "pfBlockerNG-devel", "3.0.2")
    sv1 = _make_pkg_channel(d, "pfBlockerNG", "2.0.1")
    sv2 = _make_pkg_channel(d, "pfBlockerNG", "2.0.2")

    # Before-state: 4 inputs.
    all_paths = [dv1, dv2, sv1, sv2]

    kept = brp.retain_by_channel(all_paths, keep_devel=100, keep_stable=100)

    assert len(kept) == 4


def test_retain_by_channel_version_order_deterministic(tmp_path: Path) -> None:
    """The newest-N selection uses version order (not filesystem order or name order).

    Scenario: devel pkgs with non-lexicographic versions, keep_devel=2
      Given devel pkgs at versions 3.0.1, 3.0.9, 3.0.10 (lexicographic order differs)
        And keep_devel=2
      When retain_by_channel is called
      Then 3.0.10 and 3.0.9 are kept (numerically newest 2), 3.0.1 dropped
    """
    d = tmp_path / "pkgs"
    d.mkdir()
    # Write in reverse order so filesystem order can't accidentally "win".
    p10 = _make_pkg_channel(d, "pfBlockerNG-devel", "3.0.10")
    p9 = _make_pkg_channel(d, "pfBlockerNG-devel", "3.0.9")
    p1 = _make_pkg_channel(d, "pfBlockerNG-devel", "3.0.1")

    # Before-state: all 3 present.
    kept_all = brp.retain_by_channel([p10, p9, p1], keep_devel=0, keep_stable=0)
    assert len(kept_all) == 3

    # With keep_devel=2: 3.0.10 and 3.0.9 must survive; 3.0.1 dropped.
    kept = brp.retain_by_channel([p10, p9, p1], keep_devel=2, keep_stable=0)
    kept_versions = {brp.read_compact_manifest(p)["version"] for p in kept}
    assert kept_versions == {"3.0.10", "3.0.9"}
    assert "3.0.1" not in kept_versions


def test_retain_by_channel_nightly_untouched(tmp_path: Path) -> None:
    """Nightly pkgs pass through unchanged regardless of keep_devel / keep_stable.

    Scenario: mixed input with devel, stable, AND nightly pkgs
      Given 1 devel, 1 stable, 2 nightly pkgs; keep_devel=1, keep_stable=1
      When retain_by_channel is called
      Then devel: 1 kept (the only one)
       And stable: 1 kept (the only one)
       And BOTH nightly pkgs pass through — nightly is left untouched
    """
    d = tmp_path / "pkgs"
    d.mkdir()
    dv = _make_pkg_channel(d, "pfBlockerNG-devel", "3.0.1")
    sv = _make_pkg_channel(d, "pfBlockerNG", "2.0.1")
    nv1 = _make_pkg_channel(d, "pfBlockerNG-nightly", "3.0.20260601.1")
    nv2 = _make_pkg_channel(d, "pfBlockerNG-nightly", "3.0.20260602.1")

    all_paths = [dv, sv, nv1, nv2]

    kept = brp.retain_by_channel(all_paths, keep_devel=1, keep_stable=1)

    kept_nv = {(brp.read_compact_manifest(p)["name"], brp.read_compact_manifest(p)["version"]) for p in kept}
    # Devel: the one devel pkg kept.
    assert ("pfBlockerNG-devel", "3.0.1") in kept_nv
    # Stable: the one stable pkg kept.
    assert ("pfBlockerNG", "2.0.1") in kept_nv
    # Both nightly pkgs retained untouched.
    assert ("pfBlockerNG-nightly", "3.0.20260601.1") in kept_nv
    assert ("pfBlockerNG-nightly", "3.0.20260602.1") in kept_nv
    assert len(kept) == 4


def test_retain_by_channel_mixed_prune_nightly_untouched(tmp_path: Path) -> None:
    """Mixed input: devel pruned, stable pruned, nightly passed through.

    Scenario: prune both channels from a 3+3+2 mixed input
      Given 3 devel pkgs, 3 stable pkgs, 2 nightly pkgs
        And keep_devel=1, keep_stable=2
      When retain_by_channel is called
      Then devel: only the newest 1 kept
       And stable: only the newest 2 kept
       And both nightly pkgs pass through (untouched)
       AND each channel is pruned independently (devel prune does not affect stable)
    """
    d = tmp_path / "pkgs"
    d.mkdir()
    d1 = _make_pkg_channel(d, "pfBlockerNG-devel", "3.0.1")
    d2 = _make_pkg_channel(d, "pfBlockerNG-devel", "3.0.2")
    d3 = _make_pkg_channel(d, "pfBlockerNG-devel", "3.0.3")
    s1 = _make_pkg_channel(d, "pfBlockerNG", "2.0.1")
    s2 = _make_pkg_channel(d, "pfBlockerNG", "2.0.2")
    s3 = _make_pkg_channel(d, "pfBlockerNG", "2.0.3")
    n1 = _make_pkg_channel(d, "pfBlockerNG-nightly", "3.0.20260601.1")
    n2 = _make_pkg_channel(d, "pfBlockerNG-nightly", "3.0.20260602.1")

    # Before-state: 8 pkgs in, each channel has its full set.
    all_paths = [d1, d2, d3, s1, s2, s3, n1, n2]

    kept = brp.retain_by_channel(all_paths, keep_devel=1, keep_stable=2)

    kept_nv = {(brp.read_compact_manifest(p)["name"], brp.read_compact_manifest(p)["version"]) for p in kept}

    # Devel: only newest 1 (3.0.3).
    assert ("pfBlockerNG-devel", "3.0.3") in kept_nv
    assert ("pfBlockerNG-devel", "3.0.2") not in kept_nv
    assert ("pfBlockerNG-devel", "3.0.1") not in kept_nv

    # Stable: newest 2 (2.0.2, 2.0.3); 2.0.1 dropped.
    assert ("pfBlockerNG", "2.0.3") in kept_nv
    assert ("pfBlockerNG", "2.0.2") in kept_nv
    assert ("pfBlockerNG", "2.0.1") not in kept_nv

    # Nightly: both pass through.
    assert ("pfBlockerNG-nightly", "3.0.20260601.1") in kept_nv
    assert ("pfBlockerNG-nightly", "3.0.20260602.1") in kept_nv

    # Total: 1 devel + 2 stable + 2 nightly = 5.
    assert len(kept) == 5


def test_retain_by_channel_empty_channel_is_noop(tmp_path: Path) -> None:
    """An empty channel bucket is a no-op — no KeyError, no side effects.

    Scenario: only stable pkgs provided, no devel, no nightly
      Given 2 stable pkgs and keep_devel=5
      When retain_by_channel is called
      Then both stable pkgs are returned; no error from the empty devel bucket
    """
    d = tmp_path / "pkgs"
    d.mkdir()
    sv1 = _make_pkg_channel(d, "pfBlockerNG", "2.0.1")
    sv2 = _make_pkg_channel(d, "pfBlockerNG", "2.0.2")

    kept = brp.retain_by_channel([sv1, sv2], keep_devel=5, keep_stable=0)

    kept_nv = {(brp.read_compact_manifest(p)["name"], brp.read_compact_manifest(p)["version"]) for p in kept}
    assert kept_nv == {("pfBlockerNG", "2.0.1"), ("pfBlockerNG", "2.0.2")}
    assert len(kept) == 2


@pytest.mark.parametrize(
    ("keep_devel", "keep_stable"),
    [(-1, 1), (1, -1), (-1, -1)],
)
def test_retain_by_channel_rejects_negative_keep(tmp_path: Path, keep_devel: int, keep_stable: int) -> None:
    """A negative keep value is rejected up front (fail fast), not slice-applied silently.

    A negative ``keep`` would otherwise reach ``_retain_newest``'s ``[:keep]`` slice — e.g.
    ``keep=-1`` drops the NEWEST build instead of pruning the oldest — losing data with no
    error. ``retain_by_channel`` must raise ``BuildRepoError`` for any negative input.

    Scenario: 2 devel + 2 stable pkgs, one (or both) keep value negative
      Given a valid set of pkgs
      When retain_by_channel is called with a negative keep_devel and/or keep_stable
      Then it raises BuildRepoError (no silent slice, no partial result)
    """
    d = tmp_path / "pkgs"
    d.mkdir()
    dv1 = _make_pkg_channel(d, "pfBlockerNG-devel", "3.0.1")
    dv2 = _make_pkg_channel(d, "pfBlockerNG-devel", "3.0.2")
    sv1 = _make_pkg_channel(d, "pfBlockerNG", "2.0.1")
    sv2 = _make_pkg_channel(d, "pfBlockerNG", "2.0.2")

    # Positive control: the non-negative call DOES return (proves the inputs are valid and
    # only the negative value triggers the raise — not some unrelated failure).
    assert len(brp.retain_by_channel([dv1, dv2, sv1, sv2], keep_devel=1, keep_stable=1)) == 2

    with pytest.raises(brp.BuildRepoError, match=">= 0"):
        brp.retain_by_channel([dv1, dv2, sv1, sv2], keep_devel=keep_devel, keep_stable=keep_stable)


# --------------------------------------------------------------------------- #
# ADR-27 Phase 2: release-subtree retention in build_repo_matrix
#
# These tests pin the retention behaviour of the release subtree:
#   * defaults (release_keep_devel=1, release_keep_stable=1) reproduce today's
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
    """Defaults (release_keep_devel=1, release_keep_stable=1) produce exactly one devel +
    one stable in the release catalog — the BEFORE state (inert change, no rollback).

    Scenario: default keep values with devel + stable
      Given build_repo_matrix with NO release_extra_pkgs and default keep values
        And a stable tag is set (so one stable is built)
      When the matrix runs
      Then the release catalog lists exactly ONE devel version (before-state)
       And exactly ONE stable version (before-state)
       And the total entry count is 2
    """
    out = tmp_path / "site"

    # Before-state: no release dir yet.
    assert not (out / "release").exists()

    brp.build_repo_matrix([_CE], out, builder=_stub_builder, stable_tag="v3.2.15")

    rel = out / "release" / "ce-2.8" / "amd64" / "packagesite.pkg"
    assert rel.is_file()

    objs = _catalog_objects(rel)
    names = {o["name"] for o in objs}

    # Exactly one devel + one stable (latest-only — the before/default state).
    assert "pfBlockerNG-devel" in names
    assert "pfBlockerNG" in names
    assert len(objs) == 2


def test_release_subtree_retains_devel_and_stable(tmp_path: Path) -> None:
    """With release_keep_devel=3, release_keep_stable=3 and 4 of each provided,
    the catalog lists the newest 3 of each channel — the 4th (oldest) is absent.

    Scenario: rollback depth 3, 4 candidates per channel
      Given 4 pre-built devel pkgs (versions 3.0.1..3.0.4)
        And 4 pre-built stable pkgs (versions 2.0.1..2.0.4)
        And release_keep_devel=3, release_keep_stable=3
      When build_repo_matrix runs with those extra pkgs + the fresh build
      Then devel: versions 3.0.2, 3.0.3, 3.0.4 are in the catalog
       And devel: version 3.0.1 (the oldest) is NOT in the catalog
       And stable: versions 2.0.2, 2.0.3, 2.0.4 are in the catalog
       And stable: version 2.0.1 (the oldest) is NOT in the catalog
    """
    extras = tmp_path / "extras"
    extras.mkdir()
    abi = "FreeBSD:15:amd64"

    # 4 pre-built devel candidates (the fresh build will be version "1.0_1" from the
    # stub, so all 4 extras sit below "1.0_1" as older versions). Use 3.0.1..3.0.4 as
    # clearly ordered versions to make the test readable.
    devel_extras = [_make_pkg_channel(extras, "pfBlockerNG-devel", f"3.0.{i}", abi=abi) for i in range(1, 5)]
    # 4 pre-built stable candidates.
    stable_extras = [_make_pkg_channel(extras, "pfBlockerNG", f"2.0.{i}", abi=abi) for i in range(1, 5)]

    all_extras = devel_extras + stable_extras

    # Before-state: with defaults (keep=1), only the freshest 1 of each is kept.
    out_before = tmp_path / "before"
    brp.build_repo_matrix(
        [_CE],
        out_before,
        builder=_stub_builder,
        stable_tag="v3.2.15",
        release_extra_pkgs=all_extras,
        release_keep_devel=1,
        release_keep_stable=1,
    )
    rel_before = out_before / "release" / "ce-2.8" / "amd64" / "packagesite.pkg"
    objs_before = _catalog_objects(rel_before)
    assert len(objs_before) == 2  # 1 devel + 1 stable with keep=1

    # After-state: with keep=3, the newest 3 of each channel are retained.
    out = tmp_path / "site"
    brp.build_repo_matrix(
        [_CE],
        out,
        builder=_stub_builder,
        stable_tag="v3.2.15",
        release_extra_pkgs=all_extras,
        release_keep_devel=3,
        release_keep_stable=3,
    )
    rel = out / "release" / "ce-2.8" / "amd64" / "packagesite.pkg"
    nv_set = _names_versions_in_release(rel)

    # Devel: 3.0.2, 3.0.3, 3.0.4 present; 3.0.1 dropped (4th/oldest).
    assert ("pfBlockerNG-devel", "3.0.4") in nv_set
    assert ("pfBlockerNG-devel", "3.0.3") in nv_set
    assert ("pfBlockerNG-devel", "3.0.2") in nv_set
    assert ("pfBlockerNG-devel", "3.0.1") not in nv_set

    # Stable: 2.0.2, 2.0.3, 2.0.4 present; 2.0.1 dropped.
    assert ("pfBlockerNG", "2.0.4") in nv_set
    assert ("pfBlockerNG", "2.0.3") in nv_set
    assert ("pfBlockerNG", "2.0.2") in nv_set
    assert ("pfBlockerNG", "2.0.1") not in nv_set


def test_release_catalog_lists_all_kept_versions(tmp_path: Path) -> None:
    """The release packagesite NDJSON has one object per (name, version) kept —
    newest is still the highest version (newest-wins default, contract §2.2.2).

    Scenario: multi-version catalog integrity
      Given release_keep_devel=2, release_keep_stable=2, 3 of each provided as extras
        And a fresh devel build (the stub produces version "1.0_1")
        And the newest extras are 3.0.3 (devel) and 2.0.3 (stable)
      When build_repo_matrix runs
      Then the catalog has exactly 4 objects (2 devel + 2 stable)
       And the highest-version devel object is at least 3.0.3
       And the highest-version stable object is at least 2.0.3
       And every kept (name, version) pair appears exactly once (no duplicates)
    """
    extras = tmp_path / "extras"
    extras.mkdir()
    abi = "FreeBSD:15:amd64"

    # 3 extras each channel; with keep=2 only the newest 2 survive per channel.
    devel_extras = [_make_pkg_channel(extras, "pfBlockerNG-devel", f"3.0.{i}", abi=abi) for i in range(1, 4)]
    stable_extras = [_make_pkg_channel(extras, "pfBlockerNG", f"2.0.{i}", abi=abi) for i in range(1, 4)]

    out = tmp_path / "site"
    brp.build_repo_matrix(
        [_CE],
        out,
        builder=_stub_builder,
        stable_tag="v3.2.15",
        release_extra_pkgs=devel_extras + stable_extras,
        release_keep_devel=2,
        release_keep_stable=2,
    )

    rel = out / "release" / "ce-2.8" / "amd64" / "packagesite.pkg"
    objs = _catalog_objects(rel)

    # Exactly 4 catalog entries: 2 devel + 2 stable.
    assert len(objs) == 4

    devel_objs = [o for o in objs if o["name"] == "pfBlockerNG-devel"]
    stable_objs = [o for o in objs if o["name"] == "pfBlockerNG"]
    assert len(devel_objs) == 2
    assert len(stable_objs) == 2

    # No duplicate (name, version) pairs.
    nv_list = [(o["name"], o["version"]) for o in objs]
    assert len(nv_list) == len(set(nv_list)), "duplicate (name, version) pair in catalog"

    # Newest-wins: the highest devel version in the catalog is 3.0.3 (the extras newest).
    devel_versions = sorted(
        [brp._pkg_version_key(o["version"]) for o in devel_objs],
        reverse=True,
    )
    stable_versions = sorted(
        [brp._pkg_version_key(o["version"]) for o in stable_objs],
        reverse=True,
    )
    # The retained top versions must be at least 3.0.3 and 2.0.3 respectively.
    assert devel_versions[0] >= brp._pkg_version_key("3.0.3")
    assert stable_versions[0] >= brp._pkg_version_key("2.0.3")


# --------------------------------------------------------------------------- #
# ADR-27 Phase 3: CLI dry-run — --release-extra-pkgs end-to-end
#
# These tests exercise the DOCUMENTED PUBLISH.YML INPUT PATH through the CLI
# (brp.main([...])) rather than the Python API, so the actual command-line
# wiring (argparse → extra_pkgs conversion → build_repo_matrix) is proven.
#
# Pattern: synthetic devel_1..4 + stable_1..4 passed as --release-extra-pkgs;
# --release-keep-devel / --release-keep-stable assert that the catalog holds
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


def test_cli_release_extra_pkgs_default_is_latest_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """CLI defaults (--release-keep-devel 1, --release-keep-stable 1) keep only the
    latest release when --release-extra-pkgs carry older versions too.

    Scenario: CLI latest-only default with older extras supplied
      Given 3 pre-built devel extras (3.0.1, 3.0.2, 3.0.3) passed via --release-extra-pkgs
        And 3 pre-built stable extras (2.0.1, 2.0.2, 2.0.3) passed via --release-extra-pkgs
        And no --release-keep-devel / --release-keep-stable override (default 1)
      When brp.main([--build-matrix, ...]) is called
      Then the release catalog has exactly 1 devel entry (before-state: default is latest-only)
       And the release catalog has exactly 1 stable entry
       And the highest-version devel (3.0.3) is the one retained
       And the highest-version stable (2.0.3) is the one retained
    """
    _with_stub_builder(monkeypatch)

    extras = tmp_path / "extras"
    extras.mkdir()
    devel_extras = [_make_pkg_channel(extras, "pfBlockerNG-devel", f"3.0.{i}") for i in range(1, 4)]
    stable_extras = [_make_pkg_channel(extras, "pfBlockerNG", f"2.0.{i}") for i in range(1, 4)]

    # Before-state: confirm the extra pkgs exist and span all 6 versions.
    assert len(devel_extras) == 3
    assert len(stable_extras) == 3

    out = tmp_path / "site"
    mfile = tmp_path / "matrix.json"
    mfile.write_text(json.dumps({"versions": [_CE]}))

    extra_flags: list[str] = []
    for p in devel_extras + stable_extras:
        extra_flags += ["--release-extra-pkgs", str(p)]

    rc = brp.main(
        [
            "--build-matrix",
            "--matrix-json",
            str(mfile),
            "--out",
            str(out),
            "--no-nightly",
            # No --release-keep-devel / --release-keep-stable  → default 1
        ]
        + extra_flags
    )
    assert rc == 0

    rel = out / "release" / "ce-2.8" / "amd64" / "packagesite.pkg"
    assert rel.is_file()
    objs = _catalog_objects(rel)

    devel_objs = [o for o in objs if o["name"] == "pfBlockerNG-devel"]
    stable_objs = [o for o in objs if o["name"] == "pfBlockerNG"]

    # Before-state (default keep=1): exactly one devel entry, one stable entry.
    assert len(devel_objs) == 1, f"expected 1 devel, got {len(devel_objs)}"
    assert len(stable_objs) == 1, f"expected 1 stable, got {len(stable_objs)}"

    # The retained entries are the highest-version ones (newest-wins).
    assert devel_objs[0]["version"] >= "3.0.3"
    assert stable_objs[0]["version"] >= "2.0.3"


def test_cli_release_extra_pkgs_keeps_newest_n(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The CLI correctly prunes to newest N/M when --release-keep-devel/stable are set.

    Scenario: rollback depth 3, 4 candidates per channel via CLI
      Given 4 pre-built devel extras (3.0.1..3.0.4) passed as --release-extra-pkgs
        And 4 pre-built stable extras (2.0.1..2.0.4) passed as --release-extra-pkgs
        And --release-keep-devel 3, --release-keep-stable 3
      When brp.main([--build-matrix, ...]) is called
      Then the release catalog has exactly 3 devel entries (AFTER state: rollback enabled)
       And the release catalog has exactly 3 stable entries
       And the oldest devel (3.0.1) is absent from the catalog
       And the oldest stable (2.0.1) is absent from the catalog
       And the 3 newest devel versions (3.0.2, 3.0.3, 3.0.4) are present
       And the 3 newest stable versions (2.0.2, 2.0.3, 2.0.4) are present
    """
    _with_stub_builder(monkeypatch)

    extras = tmp_path / "extras"
    extras.mkdir()
    devel_extras = [_make_pkg_channel(extras, "pfBlockerNG-devel", f"3.0.{i}") for i in range(1, 5)]
    stable_extras = [_make_pkg_channel(extras, "pfBlockerNG", f"2.0.{i}") for i in range(1, 5)]

    out = tmp_path / "site"
    mfile = tmp_path / "matrix.json"
    mfile.write_text(json.dumps({"versions": [_CE]}))

    extra_flags: list[str] = []
    for p in devel_extras + stable_extras:
        extra_flags += ["--release-extra-pkgs", str(p)]

    # Before-state: with default keep=1 only 1 devel + 1 stable appear.
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
    before_objs = _catalog_objects(out_before / "release" / "ce-2.8" / "amd64" / "packagesite.pkg")
    before_devel = [o for o in before_objs if o["name"] == "pfBlockerNG-devel"]
    before_stable = [o for o in before_objs if o["name"] == "pfBlockerNG"]
    assert len(before_devel) == 1, "before-state: default keep=1 must yield exactly 1 devel"
    assert len(before_stable) == 1, "before-state: default keep=1 must yield exactly 1 stable"

    # After-state: with keep=3 the catalog lists 3 devel + 3 stable.
    rc = brp.main(
        [
            "--build-matrix",
            "--matrix-json",
            str(mfile),
            "--out",
            str(out),
            "--no-nightly",
            "--release-keep-devel",
            "3",
            "--release-keep-stable",
            "3",
        ]
        + extra_flags
    )
    assert rc == 0

    rel = out / "release" / "ce-2.8" / "amd64" / "packagesite.pkg"
    assert rel.is_file()
    objs = _catalog_objects(rel)
    nv = {(o["name"], o["version"]) for o in objs}

    devel_objs = [o for o in objs if o["name"] == "pfBlockerNG-devel"]
    stable_objs = [o for o in objs if o["name"] == "pfBlockerNG"]

    # After-state: 3 devel + 3 stable.
    assert len(devel_objs) == 3, f"expected 3 devel after, got {len(devel_objs)}"
    assert len(stable_objs) == 3, f"expected 3 stable after, got {len(stable_objs)}"

    # Oldest excluded.
    assert ("pfBlockerNG-devel", "3.0.1") not in nv, "oldest devel must be pruned"
    assert ("pfBlockerNG", "2.0.1") not in nv, "oldest stable must be pruned"

    # Newest 3 present.
    for v in ("3.0.2", "3.0.3", "3.0.4"):
        assert ("pfBlockerNG-devel", v) in nv, f"devel {v} must be retained"
    for v in ("2.0.2", "2.0.3", "2.0.4"):
        assert ("pfBlockerNG", v) in nv, f"stable {v} must be retained"


def test_cli_release_extra_pkgs_newest_wins(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """With multiple retained devel versions the highest version ranks first (newest-wins).

    Scenario: pkg install <name> without version must resolve to the highest kept version
      Given 4 devel extras (3.0.1..3.0.4) and keep=2
        And 4 stable extras (2.0.1..2.0.4) and keep=2
      When brp.main([--build-matrix, ...]) is called
      Then the catalog lists exactly 2 devel + 2 stable entries
       And the highest devel version in the catalog is >= 3.0.4 (newest-wins)
       And the highest stable version in the catalog is >= 2.0.4 (newest-wins)
       And no (name, version) pair is duplicated in the catalog
    """
    _with_stub_builder(monkeypatch)

    extras = tmp_path / "extras"
    extras.mkdir()
    devel_extras = [_make_pkg_channel(extras, "pfBlockerNG-devel", f"3.0.{i}") for i in range(1, 5)]
    stable_extras = [_make_pkg_channel(extras, "pfBlockerNG", f"2.0.{i}") for i in range(1, 5)]

    out = tmp_path / "site"
    mfile = tmp_path / "matrix.json"
    mfile.write_text(json.dumps({"versions": [_CE]}))

    extra_flags: list[str] = []
    for p in devel_extras + stable_extras:
        extra_flags += ["--release-extra-pkgs", str(p)]

    rc = brp.main(
        [
            "--build-matrix",
            "--matrix-json",
            str(mfile),
            "--out",
            str(out),
            "--no-nightly",
            "--release-keep-devel",
            "2",
            "--release-keep-stable",
            "2",
        ]
        + extra_flags
    )
    assert rc == 0

    rel = out / "release" / "ce-2.8" / "amd64" / "packagesite.pkg"
    objs = _catalog_objects(rel)

    devel_objs = [o for o in objs if o["name"] == "pfBlockerNG-devel"]
    stable_objs = [o for o in objs if o["name"] == "pfBlockerNG"]

    # Exactly 2 devel + 2 stable.
    assert len(devel_objs) == 2
    assert len(stable_objs) == 2

    # No duplicate (name, version) pairs.
    nv_list = [(o["name"], o["version"]) for o in objs]
    assert len(nv_list) == len(set(nv_list)), "duplicate (name, version) pair in catalog"

    # Newest-wins: highest version in the retained set is >= 3.0.4 / 2.0.4.
    devel_top = max(brp._pkg_version_key(o["version"]) for o in devel_objs)
    stable_top = max(brp._pkg_version_key(o["version"]) for o in stable_objs)
    assert devel_top >= brp._pkg_version_key("3.0.4")
    assert stable_top >= brp._pkg_version_key("2.0.4")
