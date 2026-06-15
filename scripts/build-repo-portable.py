#!/usr/bin/env python3
# build-repo-portable.py — turn a directory of pfBlockerNG .pkg files into a
# per-ABI FreeBSD `pkg` repository tree WITHOUT libpkg or the `pkg` binary, in
# pure Python (stdlib + the `zstd` binary, exactly like scripts/build-pkg-portable.py).
# ADR-17 Phase 3a. This is the catalog generator the Phase-3b publish job runs on
# a plain Linux runner that has NO libpkg.
#
# WHY A PURE-PYTHON GENERATOR
#   `pkg repo` is a libpkg op. On FreeBSD (or the pfSense VM) `pkg` is present —
#   scripts/build-repo.sh (Phase 2) drives it and STAYS the FreeBSD-VM fallback.
#   On a plain Linux runner there is no apt `pkg` and no official prebuilt; the
#   Phase-2 path needs `pkg` built from source + an ABI forced in the env. So,
#   mirroring how build-pkg-portable.py hand-rolls the .pkg archive in pure Python,
#   this tool hand-rolls the REPOSITORY CATALOG: it reads each .pkg's manifest
#   directly (no libpkg, no ABI guessing) and emits a `pkg`-format catalog a real
#   pfSense `pkg update`/`pkg install` accepts.
#
# WHAT IT EMITS (verified byte-structurally against real `pkg repo` output — see
# ADR-17 RESULTS/03a): for each distinct ABI, under <out>/<ABI>/:
#   * the input .pkg file(s),
#   * meta.conf  (+ an identical copy named `meta`) — the catalog descriptor:
#       version = 2; packing_format = "tzst"; manifests = "packagesite.yaml";
#       data = "data"; filesite = "files"; manifests_archive = "packagesite";
#       filesite_archive = "files";
#   * packagesite.pkg — a zstd-compressed tar holding `packagesite.yaml`:
#       newline-delimited JSON, ONE object per package = that pkg's
#       +COMPACT_MANIFEST plus the repo fields `sum`/`flatsize`/`path`/`repopath`/
#       `pkgsize` libpkg injects, in libpkg's field order.
#   * data.pkg — a zstd-compressed tar holding `data`:
#       {"groups":[], "expired_packages":[], "packages":[<the same objects>]}.
#
# THE `sum` FIELD (load-bearing — `pkg install` validates the downloaded .pkg
# against it): libpkg checksum type 2 = `2$` + z-base-32(blake2b(file)). blake2b
# is the 64-byte default digest; the base32 is z-base-32 (alphabet
# "ybndrfg8ejkmcpqxot1uwisza345h769") packed LSB-first. Reproduced exactly here
# (cracked against a real `pkg repo` oracle), so a real box accepts the .pkg.
#
# Deterministic + re-runnable + NO network: same inputs -> byte-identical tree;
# a re-run wipes and rebuilds each ABI bucket so a removed .pkg never lingers.
#
# FLAVOR-COLLISION GUARD: identical to build-repo.sh — two .pkg sharing
# name+version+ABI but differing in php/py flavor (their php*/python*/py*-
# dependency names) CANNOT coexist in one catalog (the second would silently
# shadow the first). We FAIL LOUD (exit 1) rather than drop a build. No colliding
# combo exists today (CE 2.8 + Plus 25.03 are both FreeBSD:15:amd64 / php83 /
# py311); the fix when one arises is a flavored layout <out>/<ABI>-<php><py>/,
# intentionally NOT implemented here.
#
# VERSION-KEYED CATALOG DIRS (ADR-20 Phase 3)
#   Pass --catalog-name <name> (e.g. "ce-2.8", "plus-26.03") to write the catalog
#   under <out>/<catalog-name>/<ABI>/ instead of <out>/<ABI>/.
#   When absent, behaviour is UNCHANGED (writes to <ABI>/ — the legacy path).
#
#   Catalog name derivation rule (use catalog_name_from_version()):
#     Both CE and Plus strip any trailing patch component, taking only major.minor:
#       "2.8.1"  + "CE"   -> "ce-2.8"
#       "2.8.x"  + "CE"   -> "ce-2.8"
#       "26.03"  + "Plus" -> "plus-26.03"
#       "26.03.1"+ "Plus" -> "plus-26.03"
#
#   The publish pipeline loops over all active ci-metadata entries and calls this
#   tool once per entry with the appropriate --catalog-name. Each versioned subdir
#   is self-contained; multiple coexist under the same <out> root.
#
# ROUTING MANIFEST (ADR-20 Phase 3)
#   Pass --generate-routing-json with --routing-entries '<JSON array>' and
#   --routing-json-path <path> to write a routing manifest instead of building a
#   catalog. Entries have {pattern, catalog, status}; output is {"routes": [...]}.
#   Also callable from Python as generate_routing_json(entries, output_path).
#
# MATRIX-DRIVEN BUILD (ADR-20 routing rework) — the BRAIN
#   Pass --build-matrix --matrix-json <file|-> --out <dir> to drive the DUMB
#   build-pkg-portable.py per (matrix entry × channel) and project the version matrix
#   1:1 onto the tree:
#       release/<variant>-<major.minor>/<arch>/<catalog files>   (devel + stable)
#       nightly/<variant>-<major.minor>/<arch>/<catalog files>   (retained to N)
#   plus routing.json at the pkg root. The LEAF is the bare arch (amd64/aarch64) —
#   the version segment already implies the FreeBSD major, and each .pkg's manifest
#   carries its real ABI. Also callable from Python as build_repo_matrix(...).
#
# Requires: python3 (stdlib only) + a zstd encoder (the `zstd` binary, or the
# python `zstandard` module) — the same compressor contract as build-pkg-portable.py.
#
# Usage:
#   build-repo-portable.py --in <dir-of-.pkg> --out <dir>   # build the per-ABI tree
#   build-repo-portable.py --in <dir> --out <dir> --catalog-name ce-2.8  # versioned
#   build-repo-portable.py --print-conf [--base-url <url>]  # print the client repo-conf
#   build-repo-portable.py --generate-routing-json \        # write routing manifest
#     --routing-entries '[{"pattern":"pfSense/2.8","catalog":"ce-2.8","status":"active"}]' \
#     --routing-json-path routing.json
#
# This is a developer tool (not shipped in release archives). See --help.

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from collections.abc import Callable
from pathlib import Path

# --------------------------------------------------------------------------- #
# Catalog descriptor (meta.conf / meta) — byte-identical to real `pkg repo`.
# --------------------------------------------------------------------------- #

META_CONF = (
    "version = 2;\n"
    'packing_format = "tzst";\n'
    'manifests = "packagesite.yaml";\n'
    'data = "data";\n'
    'filesite = "files";\n'
    'manifests_archive = "packagesite";\n'
    'filesite_archive = "files";\n'
)

# The shared client repo-conf template (the SINGLE source Phase 4's add-repo.sh +
# the README reuse). Kept byte-identical to scripts/build-repo.sh --print-conf so
# the two generators are interchangeable. ${ABI} is the literal pkg(8) variable
# (expanded by pkg, not the shell), so one conf follows the box across an OS
# upgrade; priority 100 sits above the base Netgate `pfSense` repo (priority 0) —
# Phase 1 proved priority dominates version, so this is the precedence lever.
# The published GitHub Pages base — the repo's standard project Pages URL
# The canonical client conf URL is the Cloudflare Worker (ADR-20 Phase 4), which routes
# by pfSense User-Agent — written once, never needs updating on an OS upgrade. Kept
# identical to scripts/build-repo.sh / add-repo.sh DEFAULT_BASE_URL so all three
# generators emit a byte-equal --print-conf.
DEFAULT_BASE_URL = "https://pkg.pfblockerng.workers.dev"
CONF_PRIORITY = 100

# A safe single path segment: an ABI is used UNVALIDATED from manifest data as a
# directory name (out_dir / abi) that is rmtree'd + rebuilt, so reject anything
# that could escape out_dir. FreeBSD ABIs look like `FreeBSD:15:amd64` (the `:` is
# allowed); `/`, `\`, whitespace, and traversal are not.
_ABI_RE = re.compile(r"^[A-Za-z0-9:._+-]+$")


class BuildRepoError(Exception):
    """A fatal, user-facing error (bad input / collision / missing tool)."""


# --------------------------------------------------------------------------- #
# libpkg checksum type 2:  "2$" + z-base-32(blake2b(file bytes))
#
# blake2b default digest = 64 bytes; z-base-32 (RFC-less human base32, alphabet
# "ybndrfg8ejkmcpqxot1uwisza345h769") packs the bit stream LSB-FIRST within each
# byte — matching libpkg's pkg_checksum_encode_base32(). Cracked against a real
# `pkg repo` oracle (RESULTS/03a). 64 bytes -> 103 base32 chars (ceil(64*8/5)).
# --------------------------------------------------------------------------- #

_ZBASE32 = "ybndrfg8ejkmcpqxot1uwisza345h769"


def _zbase32_lsb(data: bytes) -> str:
    out: list[str] = []
    total_bits = len(data) * 8
    for i in range(0, total_bits, 5):
        val = 0
        for b in range(5):
            bit_index = i + b
            if bit_index < total_bits:
                bit = (data[bit_index // 8] >> (bit_index % 8)) & 1
                val |= bit << b
        out.append(_ZBASE32[val])
    return "".join(out)


def pkg_checksum(pkg_bytes: bytes) -> str:
    """The catalog `sum` for a .pkg file: libpkg checksum type 2 over the file bytes."""
    return "2$" + _zbase32_lsb(hashlib.blake2b(pkg_bytes).digest())


# --------------------------------------------------------------------------- #
# Pure-Python .pkg reader (no libpkg) — read the +COMPACT_MANIFEST JSON.
#
# A .pkg is a zstd-compressed tar whose first member is +COMPACT_MANIFEST (UCL,
# which is JSON for our packages). build-pkg-portable.py writes exactly this; this
# is the inverse read. ABI/name/version/flavor all come from that manifest — never
# guessed from the filename (matches build-repo.sh's `pkg query -F`).
# --------------------------------------------------------------------------- #


def _zstd_decompress(data: bytes) -> bytes:
    if data[:4] != b"\x28\xb5\x2f\xfd":
        # Not zstd-framed: assume an already-uncompressed tar (defensive).
        return data
    try:
        import zstandard

        return zstandard.ZstdDecompressor().stream_reader(io.BytesIO(data)).read()
    except ImportError:
        zstd = shutil.which("zstd")
        if not zstd:
            raise BuildRepoError(
                "a .pkg is zstd-compressed; install the `zstd` binary or the python `zstandard` module"
            ) from None
        return subprocess.run([zstd, "-dc"], input=data, stdout=subprocess.PIPE, check=True).stdout


def read_compact_manifest(pkg_path: Path) -> dict:
    """Return the +COMPACT_MANIFEST JSON object of a .pkg (pure Python, no libpkg)."""
    raw = pkg_path.read_bytes()
    tar_bytes = _zstd_decompress(raw)
    with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tf:
        try:
            member = tf.extractfile("+COMPACT_MANIFEST")
        except KeyError:
            member = None
        if member is None:
            raise BuildRepoError(f"{pkg_path.name}: no +COMPACT_MANIFEST member — not a libpkg .pkg?")
        data = member.read()
    try:
        obj = json.loads(data)
    except ValueError as e:
        raise BuildRepoError(f"{pkg_path.name}: +COMPACT_MANIFEST is not valid JSON/UCL: {e}") from None
    if not isinstance(obj, dict):
        raise BuildRepoError(f"{pkg_path.name}: +COMPACT_MANIFEST is not an object")
    return obj


# --------------------------------------------------------------------------- #
# Catalog object (one packagesite.yaml / data line per package)
#
# libpkg's packagesite object = the +COMPACT_MANIFEST with the repo fields
# sum/flatsize/path/repopath/pkgsize spliced in at libpkg's positions:
#   ...prefix, SUM, flatsize, PATH, REPOPATH, licenselogic, PKGSIZE, desc...
# We reproduce that exact key order (clients parse JSON order-independently, but
# matching the oracle keeps the output faithful + diffable).
# --------------------------------------------------------------------------- #


def catalog_object(manifest: dict, *, pkg_name: str, sum_: str, pkgsize: int) -> dict:
    """Build the packagesite object for one package from its compact manifest."""
    obj: dict = {}
    for key, value in manifest.items():
        obj[key] = value
        if key == "prefix":
            # sum immediately follows prefix; flatsize (already in the manifest)
            # then path + repopath follow.
            obj["sum"] = sum_
        if key == "flatsize":
            # path/repopath land right after flatsize (which sits right after sum).
            obj["path"] = pkg_name
            obj["repopath"] = pkg_name
        if key == "licenselogic":
            obj["pkgsize"] = pkgsize
    # Defensive: if a manifest lacked `prefix`/`flatsize`/`licenselogic`, the repo
    # fields still MUST be present (libpkg always emits them). Append any missing.
    if "sum" not in obj:
        obj["sum"] = sum_
    if "path" not in obj:
        obj["path"] = pkg_name
    if "repopath" not in obj:
        obj["repopath"] = pkg_name
    if "pkgsize" not in obj:
        obj["pkgsize"] = pkgsize
    return obj


def _ndjson(objs: list[dict]) -> bytes:
    # newline-delimited JSON, compact (libpkg emits no spaces), trailing newline.
    return b"".join(json.dumps(o, separators=(",", ":"), ensure_ascii=False).encode() + b"\n" for o in objs)


def _data_blob(objs: list[dict]) -> bytes:
    # The `data` member is a SINGLE JSON object with NO trailing newline (unlike
    # packagesite.yaml's NDJSON) — matches real `pkg repo` output exactly.
    payload = {"groups": [], "expired_packages": [], "packages": objs}
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()


# --------------------------------------------------------------------------- #
# Archive emission (zstd tar) — same framing contract as build-pkg-portable.py:
# USTAR, leading-slash-free member name, root:wheel, mode 0644, deterministic
# mtime 0 (the install/index clock is irrelevant to clients; 0 keeps re-runs
# byte-identical). USTAR is the proven-accepted framing (build-pkg-portable.py's
# .pkg uses it and a real pfSense box installs it).
# --------------------------------------------------------------------------- #


def _zstd_compress(data: bytes) -> bytes:
    try:
        import zstandard

        return zstandard.ZstdCompressor(level=19).compress(data)
    except ImportError:
        pass
    zstd = shutil.which("zstd")
    if not zstd:
        raise BuildRepoError(
            "zstd compression needs the `zstd` binary or the python `zstandard` module "
            "(brew install zstd / apt install zstd)"
        )
    return subprocess.run([zstd, "-q", "-19", "-c"], input=data, stdout=subprocess.PIPE, check=True).stdout


def _tar_one(member_name: str, data: bytes) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        ti = tarfile.TarInfo(name=member_name)
        ti.size = len(data)
        ti.mode = 0o644
        ti.uid = ti.gid = 0
        ti.uname, ti.gname = "root", "wheel"
        ti.mtime = 0
        ti.type = tarfile.REGTYPE
        tf.addfile(ti, io.BytesIO(data))
    return raw.getvalue()


def write_zstd_tar(member_name: str, data: bytes, out_path: Path) -> None:
    out_path.write_bytes(_zstd_compress(_tar_one(member_name, data)))


# --------------------------------------------------------------------------- #
# Flavor-collision guard (same semantics as build-repo.sh)
# --------------------------------------------------------------------------- #


def _flavor_signature(manifest: dict) -> str:
    """The php*/python*/py*- dependency NAMES of a pkg, sorted + comma-joined.

    Two builds of the same name+version+ABI that differ here are different flavors
    and cannot share a catalog. Empty for a flavor-free pkg. Mirrors build-repo.sh's
    `pkg query %dn | grep -E '^(php[0-9]+|python[0-9]+|py[0-9]+-)'`.
    """
    deps = manifest.get("deps")
    if not isinstance(deps, dict):
        return ""
    flavored: list[str] = []
    for name in deps:
        # php<digits>, python<digits>, or py<digits>-<...>
        if name.startswith("python") and name[len("python") :][:1].isdigit():
            flavored.append(name)
        elif name.startswith("php") and name[len("php") :][:1].isdigit():
            flavored.append(name)
        elif name.startswith("py") and "-" in name and name[len("py") :].split("-", 1)[0].isdigit():
            flavored.append(name)
    return ",".join(sorted(flavored))


def _check_collisions(entries: list[tuple[Path, dict]]) -> None:
    """Fail loud if two .pkg share name+version+ABI but differ in php/py flavor."""
    seen: dict[str, str] = {}  # "name|version|ABI" -> flavor signature
    for path, manifest in entries:
        name = manifest.get("name")
        version = manifest.get("version")
        abi = manifest.get("abi")
        if not (name and version and abi):
            raise BuildRepoError(
                f"{path.name}: manifest missing name/version/abi (name={name!r} version={version!r} abi={abi!r})"
            )
        key = f"{name}|{version}|{abi}"
        sig = _flavor_signature(manifest)
        prev = seen.get(key)
        if prev is None:
            seen[key] = sig
        elif prev != sig:
            raise BuildRepoError(
                f"FLAVOR COLLISION — two packages share name+version+ABI '{key}'\n"
                f"  but differ in php/py flavor:\n"
                f"    flavor A: {prev or '<none>'}\n"
                f"    flavor B: {sig or '<none>'}\n"
                f"  They cannot coexist in one catalog (the second would shadow the first).\n"
                f"  Resolve by splitting into a flavored layout: <out>/<ABI>-<php><py>/\n"
                f"  (not implemented — no colliding combo exists today; teach the tool when one does)."
            )


# --------------------------------------------------------------------------- #
# ADR-20 Phase 3: catalog name derivation + routing manifest
# --------------------------------------------------------------------------- #


def catalog_name_from_version(pfsense_version: str, variant: str, *, channel: str = "") -> str:
    """Derive catalog dir name: major.minor only, prefixed by variant.

    Both CE and Plus strip any trailing patch component:
      "2.8.1"  + "CE"             -> "ce-2.8"
      "2.8.x"  + "CE"             -> "ce-2.8"
      "26.03"  + "Plus"           -> "plus-26.03"
      "26.03.1"+ "Plus"           -> "plus-26.03"

    When channel is supplied (e.g. "nightly"), it is prepended as a path prefix:
      "2.8.1"  + "CE"   + "nightly" -> "nightly/ce-2.8"
      "26.03.1"+ "Plus" + "nightly" -> "nightly/plus-26.03"
    """
    major_minor = ".".join(pfsense_version.split(".")[:2])
    name = f"{variant.lower()}-{major_minor}"
    return f"{channel}/{name}" if channel else name


def generate_routing_json(entries: list[dict], output_path: str) -> None:
    """Write a routing manifest JSON file from a list of routing entry dicts.

    Each entry must have keys: pattern, catalog, status.
    Output schema: {"routes": [{"pattern": ..., "catalog": ..., "status": ...}, ...]}.
    Pure Python stdlib; no network I/O.
    """
    payload = {"routes": list(entries)}
    Path(output_path).write_text(json.dumps(payload, separators=(",", ":"), ensure_ascii=False) + "\n")


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #


def build_repo(in_dir: Path, out_dir: Path, *, catalog_name: str | None = None) -> list[str]:
    """Build the per-ABI catalog tree. Returns the list of ABIs built (sorted).

    When ``catalog_name`` is supplied (e.g. ``"ce-2.8"``), the ABI subtrees are
    written under ``out_dir / catalog_name / <ABI>/`` instead of ``out_dir / <ABI>/``.
    When absent, the legacy ``out_dir / <ABI>/`` layout is used (unchanged behaviour).
    """
    pkgs = sorted(p for p in in_dir.glob("*.pkg") if p.is_file())
    if not pkgs:
        raise BuildRepoError(f"no .pkg files in {in_dir}")

    # Read every manifest ONCE (the ABI/name/version/flavor source of truth).
    entries: list[tuple[Path, dict]] = [(p, read_compact_manifest(p)) for p in pkgs]

    # Collision guard before laying anything out (fail-closed, never a silent drop).
    _check_collisions(entries)

    # Bucket by ABI, deduping by (name, version). The same package from multiple
    # sources (e.g. the branch build + a release artifact) is interchangeable —
    # `_check_collisions` already rejected a same-name+version+ABI/different-flavor
    # clash — so keep ONE. The published .pkg is named CANONICALLY
    # (`<name>-<version>.pkg`), never the staging input filename, so the catalog path
    # is clean + stable regardless of how the publish job staged the inputs.
    by_abi: dict[str, dict[tuple[str, str], tuple[Path, dict]]] = {}
    for path, manifest in entries:
        abi = manifest["abi"]
        # Validate before it becomes a filesystem path segment (rmtree target below).
        if not isinstance(abi, str) or not _ABI_RE.fullmatch(abi) or ".." in abi:
            raise BuildRepoError(f"{path.name}: unsafe or invalid ABI segment {abi!r}")
        nv = (manifest["name"], manifest["version"])
        bucket_nv = by_abi.setdefault(abi, {})
        if nv in bucket_nv:
            sys.stderr.write(
                f"==> dedup: {path.name} duplicates {bucket_nv[nv][0].name} "
                f"({nv[0]}-{nv[1]}, {abi}) — keeping the first\n"
            )
            continue
        bucket_nv[nv] = (path, manifest)

    # When catalog_name is given, place all ABI subtrees under out_dir/catalog_name/.
    catalog_root = out_dir / catalog_name if catalog_name else out_dir
    catalog_root.mkdir(parents=True, exist_ok=True)
    for abi in sorted(by_abi):
        bucket = catalog_root / abi
        n = _write_catalog_dir(bucket, by_abi[abi])
        sys.stderr.write(f"==> built catalog {bucket} ({n} package(s))\n")

    return sorted(by_abi)


def _write_catalog_dir(dest: Path, items: dict[tuple[str, str], tuple[Path, dict]]) -> int:
    """Write one pkg catalog at ``dest`` from a ``{(name, version): (path, manifest)}`` map.

    Wipes + rebuilds ``dest`` for determinism (a removed .pkg never lingers), copies each
    package CANONICALLY (``<name>-<version>.pkg``, source mtime preserved), and emits the
    catalog descriptor (``meta.conf`` + its identical ``meta``) plus ``packagesite.pkg``
    (NDJSON) and ``data.pkg`` (one JSON object). Returns the package count.

    All source bytes are read BEFORE the wipe so a source .pkg living inside ``dest``
    (e.g. nightly-retention inputs already in the bucket) survives the rebuild.
    """
    # Read every source up front (sources may live inside dest — see nightly retention).
    staged: list[tuple[str, bytes, float, dict]] = []
    for (name, version), (path, manifest) in sorted(items.items()):
        canonical = f"{name}-{version}.pkg"
        staged.append((canonical, path.read_bytes(), path.stat().st_mtime, manifest))

    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)

    catalog_objs: list[dict] = []
    for canonical, pkg_bytes, src_mtime, manifest in staged:
        target = dest / canonical
        target.write_bytes(pkg_bytes)
        # Preserve the source .pkg's mtime so the published artifact reflects its real
        # build time — a cache-restored nightly keeps its original datetime instead of
        # jumping to this catalog-regeneration run. The landing page reads this mtime
        # as the artifact's publish date.
        os.utime(target, (src_mtime, src_mtime))
        catalog_objs.append(
            catalog_object(manifest, pkg_name=canonical, sum_=pkg_checksum(pkg_bytes), pkgsize=len(pkg_bytes))
        )

    # meta.conf + its identical `meta` copy (real `pkg repo` writes both).
    (dest / "meta.conf").write_text(META_CONF)
    (dest / "meta").write_text(META_CONF)
    # packagesite.pkg (packagesite.yaml = NDJSON) + data.pkg (data = one JSON object).
    write_zstd_tar("packagesite.yaml", _ndjson(catalog_objs), dest / "packagesite.pkg")
    write_zstd_tar("data", _data_blob(catalog_objs), dest / "data.pkg")
    return len(catalog_objs)


# --------------------------------------------------------------------------- #
# ADR-20 routing rework: the matrix-driven BRAIN
#
# build_repo_matrix() is the single orchestrator. It reads the ci-metadata version
# matrix and, per (entry × channel), drives the DUMB build-pkg-portable.py builder,
# places each .pkg into a literal 1:1 projection of the matrix —
#     release/<variant>-<major.minor>/<arch>/<catalog files>
#     nightly/<variant>-<major.minor>/<arch>/<catalog files>
# — generates each subtree's catalog, and writes routing.json at the pkg root.
#
# Layout decisions (maintainer-confirmed):
#   * channel-group "release" = the production (stable-tag) + devel packages in ONE
#     catalog (Netgate-style; both coexist). "nightly" = nightly only, retained to N.
#   * the version segment = catalog_name_from_version() ("ce-2.8" / "plus-26.03").
#   * the LEAF is the bare ARCH (amd64 / aarch64), NOT the full ABI: the version
#     segment already implies the FreeBSD major, and each .pkg's real ABI lives in
#     its own manifest (pkg validates the ABI from the package), so the directory is
#     purely the routing path.
#   * FULL MATRIX, NO DEDUP — each entry populates its own (version, arch) subtree
#     independently, even if two pfSense versions share ABI+PHP+PY.
# --------------------------------------------------------------------------- #


# A builder produces ONE .pkg for a given channel/target into out_dir and returns its
# path. The default subprocess builder drives build-pkg-portable.py; tests inject a
# stub. Keyword-only target args keep call sites self-documenting.
PkgBuilder = Callable[..., Path]

_THIS_DIR = Path(__file__).resolve().parent
_BUILD_PKG = _THIS_DIR / "build-pkg-portable.py"

# Catalog files that are *.pkg but NOT libpkg packages — skip them when re-scanning a
# built subtree (e.g. for nightly retention).
_CATALOG_PKG_FILES = {"packagesite.pkg", "data.pkg"}


def _ua_pattern(variant: str, pfsense_version: str) -> str:
    """The pfSense User-Agent prefix the Worker matches a request against.

    CE   -> "pfSense/<major.minor>"               (e.g. "pfSense/2.8")
    Plus -> "Netgate pfSense Plus/<major.minor>"  (e.g. "Netgate pfSense Plus/26.03")
    """
    major_minor = ".".join(pfsense_version.split(".")[:2])
    if variant.lower() == "plus":
        return f"Netgate pfSense Plus/{major_minor}"
    return f"pfSense/{major_minor}"


def _pkg_version_key(version: str) -> list[int]:
    """A monotone sort key for a pkg version, component-wise on ``.`` / ``_`` / ``,``.

    Nightly versions are ``<target>.YYYYMMDD.N`` (all-numeric components), so a plain
    numeric component compare orders them chronologically — a later build sorts higher.
    Non-numeric components degrade to 0 (good enough for the nightly retention sort,
    the only caller).
    """
    return [int(c) if c.isdigit() else 0 for c in re.split(r"[._,]", version)]


def _dedup_routes(routes: list[dict]) -> list[dict]:
    """Dedup routing entries and order most-specific (longest pattern) first.

    Two matrix entries that share a UA pattern + catalog + status (e.g. a Plus
    version's amd64 and aarch64 entries) collapse to ONE route. Ordering longest
    pattern first lets the Worker's first-match win for overlapping prefixes
    ("Netgate pfSense Plus/26.03" before "pfSense/2.8").
    """
    seen: set[tuple[str, str, str]] = set()
    unique: list[dict] = []
    for r in routes:
        key = (r["pattern"], r["catalog"], r["status"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(r)
    return sorted(unique, key=lambda r: (-len(r["pattern"]), r["pattern"]))


def _emit_catalog_from_paths(dest: Path, pkg_paths: list[Path]) -> int:
    """Read each .pkg's manifest, dedup by (name, version), collision-check, emit at dest."""
    entries: list[tuple[Path, dict]] = [(p, read_compact_manifest(p)) for p in sorted(set(pkg_paths))]
    _check_collisions(entries)
    items: dict[tuple[str, str], tuple[Path, dict]] = {}
    for path, manifest in entries:
        nv = (manifest["name"], manifest["version"])
        if nv in items:
            sys.stderr.write(f"==> dedup: {path.name} duplicates {items[nv][0].name} ({nv[0]}-{nv[1]})\n")
            continue
        items[nv] = (path, manifest)
    return _write_catalog_dir(dest, items)


def _retain_newest(pkg_paths: list[Path], keep: int) -> list[Path]:
    """Keep the ``keep`` newest .pkg by version (a later nightly supersedes an older one).

    Dedup by (name, version) first; tie-break the version sort by mtime then name so the
    result is deterministic. Returns the kept paths (≤ keep).
    """
    by_nv: dict[tuple[str, str], tuple[Path, float]] = {}
    for p in pkg_paths:
        m = read_compact_manifest(p)
        nv = (m["name"], m["version"])
        mt = p.stat().st_mtime
        # On a (name, version) dup, keep the newer-on-disk file.
        if nv not in by_nv or mt > by_nv[nv][1]:
            by_nv[nv] = (p, mt)
    ordered = sorted(
        by_nv.items(),
        key=lambda kv: (_pkg_version_key(kv[0][1]), kv[1][1], kv[0][0]),
        reverse=True,
    )
    return [path for _nv, (path, _mt) in ordered[:keep]]


def _subprocess_pkg_builder(
    channel: str,
    *,
    abi: str,
    php: str,
    py_flavor: str,
    out_dir: Path,
    ports: Path | None = None,
    local_src: Path | None = None,
    pkgversion: str | None = None,
    annotate: dict[str, str] | None = None,
    **_ignored: object,
) -> Path:
    """Default builder: drive build-pkg-portable.py to produce ONE .pkg, return its path."""
    cmd = [
        sys.executable, str(_BUILD_PKG),
        "--channel", channel,
        "--abi", abi,
        "--php", php,
        "--py-flavor", py_flavor,
        "--out", str(out_dir),
    ]  # fmt: skip
    if ports is not None:
        cmd += ["--ports", str(ports)]
    if local_src is not None:
        cmd += ["--local-src", str(local_src)]
    if pkgversion is not None:
        cmd += ["--pkgversion", pkgversion]
    for k, v in (annotate or {}).items():
        cmd += ["--annotate", f"{k}={v}"]
    before = set(out_dir.glob("*.pkg"))
    subprocess.run(cmd, check=True)
    produced = sorted(set(out_dir.glob("*.pkg")) - before)
    if not produced:
        raise BuildRepoError(f"builder produced no .pkg (channel={channel}, abi={abi})")
    return produced[-1]


def build_repo_matrix(
    matrix: list[dict],
    out_dir: Path,
    *,
    builder: PkgBuilder = _subprocess_pkg_builder,
    ports: Path | None = None,
    local_src: Path | None = None,
    stable_src: Path | None = None,
    stable_tag: str | None = None,
    nightly_keep: int = 14,
    nightly_pkgversion: Callable[[dict], str] | None = None,
    build_nightly: bool = True,
    **builder_kwargs: object,
) -> dict:
    """Build the full variant/arch repository tree + routing.json from the version matrix.

    For each matrix entry (each carrying pfsense_version, variant, freebsd_major, arch,
    php_version, py_flavor, status):

      * RELEASE subtree ``release/<varver>/<arch>/`` — the devel .pkg, plus the stable
        .pkg built from ``stable_tag`` (skipped when no stable tag exists), in one catalog.
      * NIGHTLY subtree ``nightly/<varver>/<arch>/`` — the freshly built nightly folded in
        with any pre-existing nightlies in that subtree (cache-restored by the caller),
        pruned to the ``nightly_keep`` newest. Skipped when ``build_nightly`` is False.
      * a routing.json route ``{pattern, catalog: <varver>, status}`` (deduped, most
        specific first).

    ``builder`` is injectable (tests pass a stub); the default drives build-pkg-portable.py.
    Extra ``builder_kwargs`` pass through to every builder call. Returns a summary dict.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    routes: list[dict] = []
    built: list[str] = []

    for entry in matrix:
        version = entry["pfsense_version"]
        variant = entry["variant"]
        arch = entry.get("arch") or "amd64"
        major = entry["freebsd_major"]
        abi = f"FreeBSD:{major}:{arch}"
        php = entry["php_version"]
        py_flavor = entry["py_flavor"]
        status = entry.get("status", "active")
        varver = catalog_name_from_version(version, variant)  # e.g. "ce-2.8"
        common = dict(abi=abi, php=php, py_flavor=py_flavor, varver=varver, arch=arch, **builder_kwargs)

        # --- release subtree: devel + (optional) stable, one channel-group catalog ---
        release_dir = out_dir / "release" / varver / arch
        with tempfile.TemporaryDirectory() as td:
            staging = Path(td)
            release_pkgs: list[Path] = [builder("devel", out_dir=staging, ports=ports, local_src=local_src, **common)]
            if stable_tag:
                release_pkgs.append(
                    builder("stable", out_dir=staging, ports=ports, local_src=stable_src or local_src, **common)
                )
            _emit_catalog_from_paths(release_dir, release_pkgs)
        built.append(str(release_dir))
        sys.stderr.write(f"==> release catalog {release_dir} ({len(release_pkgs)} package(s))\n")

        # --- nightly subtree: fold the new build in with retained prior nightlies ---
        if build_nightly:
            nightly_dir = out_dir / "nightly" / varver / arch
            # Glob the retained package files, EXCLUDING the catalog files (which are also
            # named *.pkg: packagesite.pkg / data.pkg) — they are not libpkg archives.
            existing = (
                sorted(p for p in nightly_dir.glob("*.pkg") if p.name not in _CATALOG_PKG_FILES)
                if nightly_dir.is_dir()
                else []
            )
            with tempfile.TemporaryDirectory() as td:
                staging = Path(td)
                pkgver = nightly_pkgversion(entry) if nightly_pkgversion else None
                new_nightly = builder(
                    "nightly", out_dir=staging, ports=ports, local_src=local_src, pkgversion=pkgver, **common
                )
                kept = _retain_newest([*existing, new_nightly], nightly_keep)
                n = _emit_catalog_from_paths(nightly_dir, kept)
            built.append(str(nightly_dir))
            sys.stderr.write(f"==> nightly catalog {nightly_dir} ({n} package(s), kept ≤{nightly_keep})\n")

        routes.append({"pattern": _ua_pattern(variant, version), "catalog": varver, "status": status})

    routes = _dedup_routes(routes)
    generate_routing_json(routes, str(out_dir / "routing.json"))
    sys.stderr.write(f"==> wrote routing.json ({len(routes)} route(s))\n")
    return {"routes": routes, "built": built}


def print_conf(base_url: str) -> None:
    base = base_url.rstrip("/")
    sys.stdout.write(
        "# pfBlockerNG (release channel) — self-hosted pkg repository (ADR-17).\n"
        "# NONE-signed: trust anchor is HTTPS to the host (no signing key). The ${ABI}\n"
        "# variable is expanded by pkg(8) and follows the box across a pfSense OS upgrade.\n"
        f"# priority {CONF_PRIORITY} sits above the base Netgate `pfSense` repo so cross-repo\n"
        "# resolution (pkg install/upgrade, GUI Install) selects our build.\n"
        "pfblockerng: {\n"
        f'  url: "{base}/${{ABI}}",\n'
        "  mirror_type: none,\n"
        "  signature_type: none,\n"
        f"  priority: {CONF_PRIORITY},\n"
        "  enabled: yes\n"
        "}\n"
    )


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        prog="build-repo-portable.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Generate a per-ABI FreeBSD pkg repository catalog in pure Python (no libpkg). ADR-17 Phase 3a.",
        epilog=(
            "examples:\n"
            "  # build a catalog tree from a dir of release .pkg\n"
            "  build-repo-portable.py --in ./pkgs --out ./site\n\n"
            "  # build under a version-keyed subdir (ADR-20)\n"
            "  build-repo-portable.py --in ./pkgs --out ./site --catalog-name ce-2.8\n\n"
            "  # print the client repo-conf (Phase 4 add-repo.sh + README reuse it)\n"
            "  build-repo-portable.py --print-conf --base-url https://example.github.io/pkg\n\n"
            "  # write a routing manifest (ADR-20)\n"
            "  build-repo-portable.py --generate-routing-json \\\n"
            '    --routing-entries \'[{"pattern":"pfSense/2.8","catalog":"ce-2.8","status":"active"}]\' \\\n'
            "    --routing-json-path routing.json\n\n"
            "  # matrix-driven: build the full variant/arch tree + routing.json (ADR-20)\n"
            "  read-version-matrix.sh --print-build | build-repo-portable.py --build-matrix \\\n"
            "    --matrix-json - --out ./site --ports ./ports --local-src . \\\n"
            "    --nightly-pkgversion 3.2.16.20260615.1\n"
        ),
    )
    ap.add_argument("--in", dest="in_dir", help="directory holding the input .pkg files (searched, non-recursive)")
    ap.add_argument("--out", dest="out_dir", help="output root; one <ABI>/ catalog subtree is created per ABI")
    ap.add_argument("--print-conf", action="store_true", help="print the client repo-conf template to stdout and exit")
    ap.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help="base URL for --print-conf (the conf appends the literal ${ABI} pkg variable)",
    )
    ap.add_argument(
        "--catalog-name",
        dest="catalog_name",
        default=None,
        help=(
            "when supplied, write the per-ABI tree under <out>/<catalog-name>/<ABI>/ "
            "instead of the legacy <out>/<ABI>/ path (e.g. 'ce-2.8', 'plus-26.03'). "
            "Derive from pfsense_version + variant via catalog_name_from_version()."
        ),
    )
    ap.add_argument(
        "--generate-routing-json",
        action="store_true",
        help=(
            "write a routing manifest JSON file from --routing-entries to "
            "--routing-json-path and exit (does NOT build a catalog)"
        ),
    )
    ap.add_argument(
        "--routing-entries",
        default=None,
        help="JSON array of routing entry dicts ({pattern, catalog, status}) for --generate-routing-json",
    )
    ap.add_argument(
        "--routing-json-path",
        default=None,
        help="output file path for --generate-routing-json",
    )
    g_matrix = ap.add_argument_group("matrix-driven build (ADR-20 routing rework)")
    g_matrix.add_argument(
        "--build-matrix",
        action="store_true",
        help=(
            "drive build-pkg-portable.py per (matrix entry × channel), lay out the "
            "release/<varver>/<arch>/ + nightly/<varver>/<arch>/ tree under --out, and "
            "write routing.json. Requires --matrix-json + --out."
        ),
    )
    g_matrix.add_argument(
        "--matrix-json",
        default=None,
        help="path to the BUILD matrix JSON (a JSON array, or {versions:[...]}); '-' reads stdin",
    )
    g_matrix.add_argument("--ports", default=None, help="FreeBSD-ports tree passed to build-pkg-portable.py --ports")
    g_matrix.add_argument(
        "--local-src", default=None, help="local pfBlockerNG source passed to build-pkg-portable.py --local-src"
    )
    g_matrix.add_argument(
        "--stable-tag",
        default=None,
        help="latest stable release tag; when set, a stable .pkg joins each release catalog",
    )
    g_matrix.add_argument(
        "--stable-src", default=None, help="source tree checked out at --stable-tag (defaults to --local-src)"
    )
    g_matrix.add_argument(
        "--nightly-keep", type=int, default=14, help="nightlies retained per (version, arch) (default 14)"
    )
    g_matrix.add_argument(
        "--nightly-pkgversion",
        default=None,
        help="full pkg-safe nightly version <target>.YYYYMMDD.N applied to every entry's nightly build",
    )
    g_matrix.add_argument("--no-nightly", action="store_true", help="skip the nightly subtree (release + routing only)")
    args = ap.parse_args(argv)

    if args.print_conf:
        print_conf(args.base_url)
        return 0

    if args.generate_routing_json:
        if not args.routing_entries or not args.routing_json_path:
            ap.error("--generate-routing-json requires --routing-entries and --routing-json-path")
        try:
            entries = json.loads(args.routing_entries)
        except ValueError as e:
            sys.stderr.write(f"build-repo-portable: --routing-entries is not valid JSON: {e}\n")
            return 1
        if not isinstance(entries, list):
            sys.stderr.write("build-repo-portable: --routing-entries must be a JSON array\n")
            return 1
        generate_routing_json(entries, args.routing_json_path)
        sys.stderr.write(f"==> wrote routing manifest: {args.routing_json_path} ({len(entries)} route(s))\n")
        return 0

    if args.build_matrix:
        if not args.matrix_json or not args.out_dir:
            ap.error("--build-matrix requires --matrix-json and --out")
        raw = sys.stdin.read() if args.matrix_json == "-" else Path(args.matrix_json).read_text()
        try:
            parsed = json.loads(raw)
        except ValueError as e:
            sys.stderr.write(f"build-repo-portable: --matrix-json is not valid JSON: {e}\n")
            return 1
        matrix = parsed.get("versions") if isinstance(parsed, dict) else parsed
        if not isinstance(matrix, list):
            sys.stderr.write("build-repo-portable: matrix must be a JSON array (or {versions:[...]})\n")
            return 1
        pkgver = args.nightly_pkgversion
        try:
            build_repo_matrix(
                matrix,
                Path(args.out_dir),
                ports=Path(args.ports) if args.ports else None,
                local_src=Path(args.local_src) if args.local_src else None,
                stable_tag=args.stable_tag,
                stable_src=Path(args.stable_src) if args.stable_src else None,
                nightly_keep=args.nightly_keep,
                nightly_pkgversion=(lambda _e: pkgver) if pkgver else None,
                build_nightly=not args.no_nightly,
            )
        except (BuildRepoError, subprocess.CalledProcessError) as e:
            sys.stderr.write(f"build-repo-portable: {e}\n")
            return 1
        return 0

    if not args.in_dir or not args.out_dir:
        ap.error("--in and --out are required (or use --print-conf / --generate-routing-json)")
    in_dir = Path(args.in_dir)
    if not in_dir.is_dir():
        sys.stderr.write(f"build-repo-portable: --in is not a directory: {in_dir}\n")
        return 1

    try:
        abis = build_repo(in_dir, Path(args.out_dir), catalog_name=args.catalog_name)
    except BuildRepoError as e:
        sys.stderr.write(f"build-repo-portable: {e}\n")
        return 1
    sys.stderr.write(f"==> built catalogs for ABI: {' '.join(abis)}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
