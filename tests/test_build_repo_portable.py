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
    assert 'url: "https://pfblockerng.github.io/pkg/${ABI}"' in out
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
