#!/usr/bin/env python3
# build-repo-portable.py — turn a directory of pfBlockerNG .pkg files into an
# ARCH-LESS FreeBSD `pkg` repository catalog WITHOUT libpkg, in pure Python
# (ADR-17): for a plain Linux CI runner with no real `pkg` binary, hand-rolling
# the same catalog `pkg repo` produces (meta.conf/packagesite.pkg/data.pkg,
# incl. the libpkg `sum` checksum — see pkg_checksum()) from each .pkg's
# manifest, deterministically and without network. Every pfBlockerNG .pkg is
# NO_ARCH (issue #1806): its manifest ABI is CPU-wildcarded (e.g.
# "FreeBSD:15:*"), so the catalog has no per-ABI subdirectory — one directory
# serves every arch of a FreeBSD major (see _is_wildcard_abi / build_repo).
# (scripts/build-repo.sh drives a real `pkg repo` and stays the FreeBSD/
# pfSense-side fallback; this is the CI/release builder.) FLAVOR-COLLISION
# GUARD, version-keyed catalogs (ADR-20), the matrix-driven build, and release
# retention are each documented at their own function; see --help for full CLI
# usage.

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
from typing import TypeGuard

from pfb_pkg import PkgError, pkg_version_sort_key, read_compact_manifest, zstd_compress

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

# The shared client repo-conf template — kept byte-identical to
# scripts/build-repo.sh / add-repo.sh --print-conf (pinned by
# tests/test_add_repo_conf.py) so all three generators are interchangeable.
# ${ABI} is the literal pkg(8) variable (expanded by pkg, never the shell), so
# one conf follows the box across an OS upgrade; priority 100 sits above the
# base Netgate `pfSense` repo (priority 0) because priority — not version —
# decides cross-repo resolution. Base URL is this repo's GitHub Pages root
# (ADR-39; the Cloudflare Worker has been retired).
DEFAULT_BASE_URL = "https://pfblockerng.github.io/pkg"
CONF_PRIORITY = 100

# A NO_ARCH package's manifest ABI wildcards ONLY the final CPU segment — e.g.
# "FreeBSD:15:*" (probed live against a real Netgate noarch package; issue
# #1806). Tight: '*' is valid ONLY as the whole final segment, never elsewhere
# and never partial — "FreeBSD:*:amd64" / "*" / "FreeBSD:15:*extra" are not ABIs.
_ABI_WILDCARD_RE = re.compile(r"^[A-Za-z0-9._+-]+:[A-Za-z0-9._+-]+:\*$")


def _is_wildcard_abi(abi: object) -> TypeGuard[str]:
    """True if ``abi`` is a NO_ARCH package's tight, CPU-wildcarded ABI string."""
    return isinstance(abi, str) and bool(_ABI_WILDCARD_RE.fullmatch(abi))


class BuildRepoError(Exception):
    """A fatal, user-facing error (bad input / collision / missing tool)."""


def _require_wildcard_abi(path: Path, abi: object) -> str:
    """Validate ``abi`` is a NO_ARCH package's wildcard ABI, or raise ``BuildRepoError``.

    Shared by ``build_repo()`` and ``_emit_catalog_from_paths()`` so the reject wording
    (and the NO_ARCH policy behind it) has exactly one canonical source instead of two
    verbatim-duplicated copies. Returns the validated ABI as ``str`` (narrowed via
    ``_is_wildcard_abi``'s ``TypeGuard``) so callers need no further cast.
    """
    if not _is_wildcard_abi(abi):
        raise BuildRepoError(
            f"{path.name}: catalog requires a NO_ARCH (wildcard-ABI) package — got "
            f"concrete ABI {abi!r}. The catalog tree is arch-less (one directory serves "
            f"every arch of a FreeBSD major); a concrete-ABI package would silently "
            f"install on only one arch. Ship a wildcard-ABI (NO_ARCH) build instead."
        )
    return abi


# --------------------------------------------------------------------------- #
# libpkg checksum type 2:  "2$" + z-base-32(blake2b(file bytes))
#
# blake2b default digest = 64 bytes; z-base-32 (RFC-less human base32, alphabet
# "ybndrfg8ejkmcpqxot1uwisza345h769") packs the bit stream LSB-FIRST within each
# byte — matching libpkg's pkg_checksum_encode_base32(). Cracked against a real
# `pkg repo` oracle. 64 bytes -> 103 base32 chars (ceil(64*8/5)).
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
# .pkg reading (zstd framing + +COMPACT_MANIFEST) lives in pfb_pkg, shared with
# gen_landing.py. zstd_decompress / read_compact_manifest are imported above.
# --------------------------------------------------------------------------- #


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
    out_path.write_bytes(
        zstd_compress(
            _tar_one(member_name, data),
            BuildRepoError,
            "zstd compression needs the `zstd` binary or the python `zstandard` module "
            "(brew install zstd / apt install zstd)",
        )
    )


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


def _pkg_matches_abi(manifest: dict, row_abi: str) -> bool:
    """True if a pre-supplied package's manifest ABI belongs to ``row_abi``'s
    FreeBSD major (OS+major only — the CPU/arch segment is never compared).

    Every package the matrix-driven catalog handles is NO_ARCH (issue #1806):
    its manifest abi is CPU-wildcarded (e.g. ``"FreeBSD:15:*"``, see
    ``_is_wildcard_abi``), so an exact string compare against a matrix row's
    concrete ``"FreeBSD:15:amd64"`` abi would never match. Matching by OS+major
    is what decides which VARVER catalog(s) a pre-built/frozen/dep package
    lands in (``route_only_pkgs``/``release_pkgs``/``release_extra_pkgs``/
    ``dep_pkgs``) — the catalog tree is arch-less, so there is no arch bucket
    to route into, only a varver.
    """
    abi = manifest.get("abi", "")
    return isinstance(abi, str) and abi.split(":")[:2] == row_abi.split(":")[:2]


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
# ADR-20: catalog name derivation + routing manifest
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


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #

# A catalog_name segment is a rm-rf'd + rebuilt path component (_write_catalog_dir
# shutil.rmtree()s it) — same safety rule as build-repo.sh's --varver guard, tightened
# to lowercase-only. '/' is allowed only BETWEEN segments (a legitimate catalog_name
# carries a channel prefix, e.g. "nightly/plus-26.03").
_CATALOG_NAME_SEGMENT_RE = re.compile(r"[a-z0-9.-]+")


def _validate_catalog_name(name: str) -> None:
    """Reject an unsafe ``catalog_name`` before it becomes ``out_dir / catalog_name``
    (issue #1786): a ``".."`` segment escapes sideways/upward, and an ABSOLUTE value
    makes ``Path.__truediv__`` discard ``out_dir`` entirely — either lets a caller
    point ``_write_catalog_dir``'s ``shutil.rmtree()`` at an arbitrary directory.
    """
    segments = name.split("/")
    if any(not seg or seg in (".", "..") or not _CATALOG_NAME_SEGMENT_RE.fullmatch(seg) for seg in segments):
        raise BuildRepoError(
            f"unsafe catalog_name {name!r}: each '/'-separated segment must be non-empty, "
            f"not '.'/'..', and match [a-z0-9.-]+ (e.g. 'ce-2.8', 'release/ce-2.8')"
        )


def build_repo(in_dir: Path, out_dir: Path, *, catalog_name: str | None = None) -> list[str]:
    """Build the arch-less (NO_ARCH-only) catalog from a directory of .pkg files.

    Every pfBlockerNG .pkg is NO_ARCH (issue #1806): its manifest ABI is
    CPU-wildcarded (e.g. ``"FreeBSD:15:*"``, see ``_is_wildcard_abi``), so the
    catalog has no per-ABI subdirectory to bucket into — one directory serves
    every CPU arch of a FreeBSD major (mirrors ``scripts/build-repo.sh``'s
    ``require_noarch_abi``). A concrete-ABI package is a hard error — the
    tripwire that would otherwise let it install silently on only one arch.
    Mixing more than one ABI in a single call is also a hard error: filter
    ``in_dir`` to one ABI and invoke once per major (mirrors build-repo.sh's
    "mixed ABIs in one run" guard).

    The catalog is written DIRECTLY at ``out_dir`` (or ``out_dir / catalog_name``
    when supplied, e.g. ``"ce-2.8"``) — meta.conf, meta, packagesite.pkg, data.pkg,
    plus each canonically-named ``<name>-<version>.pkg``. ``catalog_name`` is
    validated (``_validate_catalog_name``, issue #1786) before anything is read or
    written — it becomes a ``shutil.rmtree()``d path segment. Emission (dedup by
    (name, version), the flavor-collision guard, the catalog descriptor) is
    delegated to ``_emit_catalog_from_paths``. Returns the single wildcard ABI
    built, as a one-element sorted list.
    """
    if catalog_name:
        _validate_catalog_name(catalog_name)

    pkgs = sorted(p for p in in_dir.glob("*.pkg") if p.is_file())
    if not pkgs:
        raise BuildRepoError(f"no .pkg files in {in_dir}")

    # Validate every input is NO_ARCH and shares one ABI BEFORE emitting anything
    # (fail-closed; mirrors build-repo.sh's require_noarch_abi + mixed-ABI guard).
    abis: set[str] = set()
    for path in pkgs:
        manifest = read_compact_manifest(path)
        abis.add(_require_wildcard_abi(path, manifest.get("abi")))
    if len(abis) > 1:
        raise BuildRepoError(
            f"mixed ABIs in one build_repo() call: {sorted(abis)} — filter in_dir to one "
            f"ABI and invoke once per major (mirrors build-repo.sh's per-run ABI requirement)."
        )

    catalog_root = out_dir / catalog_name if catalog_name else out_dir
    n = _emit_catalog_from_paths(catalog_root, pkgs)
    sys.stderr.write(f"==> built catalog {catalog_root} ({n} package(s))\n")
    return sorted(abis)


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
# ADR-20: the matrix-driven BRAIN. build_repo_matrix() drives the DUMB
# build-pkg-portable.py builder per (ci-metadata entry x channel) and projects
# the matrix onto release/<variant>-<major.minor>/... (stable+devel, one
# catalog) and nightly/<variant>-<major.minor>/... (retained to N). Arch-less
# since issue #1806 (NO_ARCH): the leaf is the varver, not an ABI/arch — every
# package here is CPU-wildcarded, so one directory serves every arch of that
# FreeBSD major (each .pkg's real, wildcarded ABI still lives in its own
# manifest; see _is_wildcard_abi / _emit_catalog_from_paths).
# FULL MATRIX, NO DEDUP: every entry gets its own subtree.
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


def _pkg_version_key(version: str) -> tuple[list[int], int, int]:
    """A monotone sort key for a pkg version — see ``pfb_pkg.pkg_version_sort_key``.

    Used for nightly retention (``<target>.YYYYMMDD.N``, all-numeric — a later build
    sorts higher) AND release-channel retention (``vX.Y.Z(.alpha|beta|rc.N)?`` tags,
    via ``retain_by_channel``'s ``--release-keep-devel``/``--release-keep-stable`` >
    1), so it must also order the alpha/beta/rc prerelease stages correctly, not just
    the nightly date/counter shape. Kept as a thin alias — this module's ``_retain_newest``
    callers reference it by this name.
    """
    return pkg_version_sort_key(version)


def _emit_catalog_from_paths(dest: Path, pkg_paths: list[Path]) -> int:
    """Read each .pkg's manifest, dedup by (name, version), collision-check, emit at dest.

    Every package here MUST carry a NO_ARCH (wildcard) ABI (``_is_wildcard_abi``,
    issue #1806) — the matrix-driven catalog tree is arch-less: one directory
    (``release/<varver>/`` / ``nightly/<varver>/``) serves every arch of a
    FreeBSD major, so a concrete-ABI package would silently install on only
    one. A concrete ABI reaching catalog emission is a hard error — the
    tripwire that forces a conscious layout decision if a compiled, per-arch
    dependency is ever added.
    """
    entries: list[tuple[Path, dict]] = [(p, read_compact_manifest(p)) for p in sorted(set(pkg_paths))]
    _check_collisions(entries)
    for path, manifest in entries:
        _require_wildcard_abi(path, manifest.get("abi"))
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


def _non_negative_int(value: str) -> int:
    """argparse ``type`` for the ``--release-keep-*`` flags: reject a negative count up front."""
    iv = int(value)
    if iv < 0:
        raise argparse.ArgumentTypeError("must be >= 0")
    return iv


def _line_key(version: str, pkg_name: str) -> str:
    """The major/minor "line" grouping key for a pfBlockerNG pkg VERSION.

    Split on the same ``[._,]`` separator set as ``pkg_version_sort_key`` (a port
    revision like ``1.0_1`` is still major=1/minor=0), then take the first two
    numeric components, e.g. ``3.2.15`` -> ``"3.2"``, ``4.0.0.alpha.3`` -> ``"4.0"``.
    Unlike ``_pkg_version_key``/``pkg_version_sort_key`` (which maps any non-numeric
    component to ``0`` — fine for a SORT tie-break, never raises), this parse FAILS
    CLOSED: a version whose first two components aren't both plain digit strings can
    never silently misbucket into some line or get dropped — it raises naming the
    offending package instead.
    """
    parts = re.split(r"[._,]", version)
    if len(parts) < 2 or not parts[0].isdigit() or not parts[1].isdigit():
        raise BuildRepoError(f"{pkg_name}: malformed major/minor version {version!r} — cannot compute line pin")
    return f"{parts[0]}.{parts[1]}"


def _line_pins(bucket: list[Path]) -> list[Path]:
    """The newest package of every major/minor VERSION line in ``bucket``.

    ``bucket`` is already channel-scoped by the caller, so pins never cross channels.
    Line key = ``_line_key`` (fails closed on a malformed major/minor). Tie-break
    within a line mirrors ``_retain_newest``: version order, then mtime, then name.
    Returns newest-first, deterministic regardless of input order.
    """
    lines: dict[str, tuple[Path, tuple]] = {}
    for p in bucket:
        m = read_compact_manifest(p)
        version: str = m.get("version", "")
        name: str = m.get("name", "")
        line = _line_key(version, name)
        rank = (_pkg_version_key(version), p.stat().st_mtime, name)
        if line not in lines or rank > lines[line][1]:
            lines[line] = (p, rank)
    return [p for p, _rank in sorted(lines.values(), key=lambda pr: pr[1], reverse=True)]


def retain_by_channel(
    pkg_paths: list[Path],
    *,
    keep_devel: int,
    keep_stable: int,
) -> list[Path]:
    """Bucket paths by package-name channel and keep the newest ``keep_*`` per channel,
    PLUS the newest package of every major/minor line (the "line pin").

    Channel detection (by the package ``name`` field in each path's manifest):
      * name ending ``-devel``   → devel channel
      * name ending ``-nightly`` → nightly channel (left untouched: not pruned here,
        no line pins either)
      * anything else            → stable channel

    Pruning rules (reuses ``_retain_newest`` for version-sorted ordering):
      * ``keep == 0`` → keep ALL of that channel (the "unbounded / disabled" sentinel).
      * ``keep >= len(bucket)`` → keep all (no-op).
      * ``keep < len(bucket)`` → prune to the ``keep`` newest, THEN union in each
        major/minor line's newest package (``_line_pins``) that isn't already in that
        window — e.g. an aged-out v3.2.15 stays available after newer lines push it
        out of the rolling window. Pins are per-channel: a devel pin can never satisfy
        stable or vice versa. A malformed version in a bucket that needs pruning raises
        ``BuildRepoError`` (fail closed, never silently misbucketed or dropped).

    ``keep_devel`` / ``keep_stable`` must be ``>= 0``; a negative value is rejected (it would
    otherwise flow into ``_retain_newest``'s ``[:keep]`` slice and silently drop the newest
    builds — fail fast instead).

    Returns the kept paths in a deterministic stable order (devel first, then stable, then
    nightly; within each bucket the window newest-first, then any line pins newest-first).
    """
    if keep_devel < 0 or keep_stable < 0:
        raise BuildRepoError(
            f"release keep values must be >= 0 (got keep_devel={keep_devel}, keep_stable={keep_stable})"
        )

    devel: list[Path] = []
    stable: list[Path] = []
    nightly: list[Path] = []

    for p in pkg_paths:
        m = read_compact_manifest(p)
        name: str = m.get("name", "")
        if name.endswith("-nightly"):
            nightly.append(p)
        elif name.endswith("-devel"):
            devel.append(p)
        else:
            stable.append(p)

    def _prune(bucket: list[Path], keep: int) -> list[Path]:
        if keep == 0 or keep >= len(bucket):
            # keep==0 is the "unbounded" sentinel; keep>=len is a no-op — nothing is
            # pruned, so line pins are moot (everything already survives).
            return _retain_newest(bucket, len(bucket)) if bucket else []
        window = _retain_newest(bucket, keep)
        seen = set(window)
        pins = [p for p in _line_pins(bucket) if p not in seen]
        return window + pins

    kept_devel = _prune(devel, keep_devel)
    kept_stable = _prune(stable, keep_stable)
    # Nightly is left untouched (caller handles its own retention).
    return kept_devel + kept_stable + nightly


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
    release_keep_devel: int = 1,
    release_keep_stable: int = 1,
    release_extra_pkgs: list[Path] | None = None,
    route_only_pkgs: dict[str, list[Path]] | None = None,
    release_pkgs: dict[str, list[Path]] | None = None,
    dep_pkgs: list[Path] | None = None,
    **builder_kwargs: object,
) -> dict:
    """Build the full variant repository tree from the version matrix.

    issue #1806: the catalog tree is ARCH-LESS — ``release/<varver>/`` and
    ``nightly/<varver>/`` hold the catalog directly (meta.conf, packagesite.pkg,
    data.pkg, the .pkg files), with NO per-arch subdirectory. All three
    pfSense-pkg-pfBlockerNG ports are NO_ARCH: a real package's manifest abi is
    CPU-wildcarded (``"FreeBSD:<major>:*"``, see ``_is_wildcard_abi``) — one
    varver directory serves every arch of that FreeBSD major, so there is
    nothing left to bucket by arch. ``_emit_catalog_from_paths`` hard-rejects a
    concrete-ABI package at emission (never a silent single-arch install).
    ``arch`` is retired from the matrix (issue #1806) — a row no longer carries
    it. This function still needs a literal CPU segment for the concrete
    ``--abi`` fed to the builder, per-row, so build-pkg-portable.py can derive
    the FreeBSD major: it defaults to ``"amd64"`` (a stray legacy ``arch`` key,
    if a row still carries one, is honored instead) — either way it no longer
    selects a catalog bucket.

    For each matrix entry (each carrying pfsense_version, variant, freebsd_major,
    php_version, py_flavor, optionally arch, and optionally role):

    **build entries** (``role`` absent or ``"build"`` — the default, unchanged path):

      * RELEASE subtree ``release/<varver>/`` — the devel .pkg, plus the stable
        .pkg built from ``stable_tag`` (skipped when no stable tag exists), optionally
        folded with pre-built older-release .pkg from ``release_extra_pkgs``, pruned to
        the ``release_keep_devel`` newest devel + ``release_keep_stable`` newest stable.
        Defaults (1/1) reproduce today's latest-only behaviour; setting higher values
        retains older artifacts in the catalog for diagnostics and reproducibility.
      * NIGHTLY subtree ``nightly/<varver>/`` — the freshly built nightly folded in
        with any pre-existing nightlies in that subtree (cache-restored by the caller),
        pruned to the ``nightly_keep`` newest. Skipped when ``build_nightly`` is False.
    **route-only entries** (``role == "route-only"`` — EOL versions served from frozen .pkg):

      * NO builder call for a fresh devel-HEAD .pkg — the version is EOL, no new build.
      * NO nightly subtree — a route-only entry never gets a nightly build.
      * RELEASE subtree ``release/<varver>/`` — built EXCLUSIVELY from the frozen
        .pkg supplied in ``route_only_pkgs[varver]`` (pre-downloaded Release assets
        provided by publish.yml — must be NO_ARCH/wildcard-ABI, same as every other
        catalog input; a concrete-ABI frozen .pkg is rejected at emission). The
        existing ``_emit_catalog_from_paths`` machinery handles the rest.
      * If ``route_only_pkgs`` has no entry for this ``varver`` (or is ``None``), the call
        raises ``BuildRepoError`` — a route-only entry with no frozen .pkg is a hard error.

    Frozen-.pkg input contract (``route_only_pkgs``):
      Callers (e.g. publish.yml) supply a ``dict[varver, list[Path]]`` mapping the
      ``catalog_name_from_version()`` key (e.g. ``"ce-2.7"``) to the ordered list of
      pre-downloaded .pkg files for that version. publish.yml downloads these from the
      corresponding GitHub Release tag and passes them here. Each path must be a valid,
      NO_ARCH .pkg (readable by ``read_compact_manifest``). The mapping is keyed by
      ``varver`` so multiple matrix rows of the same version share the same frozen .pkg
      pool (``_emit_catalog_from_paths`` deduplicates by (name, version)).

    ``release_pkgs`` (optional) — consume pre-built Release .pkg files instead of
      rebuilding devel/stable from source for build-entry matrix rows:
      ``dict[varver, list[Path]]`` mapping ``catalog_name_from_version()`` keys to lists
      of pre-built Release .pkg paths (e.g. all assets downloaded from GitHub Releases
      by publish.yml). When provided, the ``release/<varver>/`` catalog is SERVED
      from these (matched by OS+major via ``_pkg_matches_abi``, then pruned by
      ``retain_by_channel`` with ``release_keep_devel`` / ``release_keep_stable``)
      instead of calling the builder for devel/stable. ``release_extra_pkgs`` is
      still folded in after the pool.
      An empty pool for a varver skips that release catalog with a warning
      (no exception raised — a newly-added version with no Release asset yet simply has
      no release-channel package until the next release covers it; nightly still covers
      it from HEAD). Nightly is unaffected — the nightly subtree is always built from
      source when ``build_nightly`` is True, regardless of ``release_pkgs``.
      When ``None`` (the default), the existing build-from-source path is used unchanged.

    ``dep_pkgs`` (optional, issue #1806) — pre-built dependency .pkg files (e.g.
      py311-charset-normalizer, built by build-dep-pkg-portable.py) folded into BOTH
      the release AND nightly catalogs of every build-role matrix entry whose ABI
      matches (OS+major; see ``_pkg_matches_abi`` — a NO_ARCH dep's abi is CPU-
      wildcarded). Folded AFTER retention (``retain_by_channel`` / ``_retain_newest``)
      — NEVER before, or a dep would compete with real releases/nightlies for a
      retention slot. Route-only (frozen EOL) entries never receive a dep pkg. A
      dep pkg whose ABI matches no catalog it actually landed in is a hard
      ``BuildRepoError`` (fail loud, never a silent drop) — matched is tracked only
      at the point a dep is folded into an EMITTED catalog, never merely because its
      ABI matched a row (issue #1806 gate-A finding: a matched-but-unemitted dep must
      still raise).

    ``builder`` is injectable (tests pass a stub); the default drives build-pkg-portable.py.
    Extra ``builder_kwargs`` pass through to every builder call. Returns a summary dict.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    built: list[str] = []

    dep_entries: list[tuple[Path, dict]] = [(p, read_compact_manifest(p)) for p in (dep_pkgs or [])]
    dep_pkgs_matched: set[Path] = set()

    for entry in matrix:
        version = entry["pfsense_version"]
        variant = entry["variant"]
        arch = entry.get("arch") or "amd64"
        major = entry["freebsd_major"]
        abi = f"FreeBSD:{major}:{arch}"
        php = entry["php_version"]
        py_flavor = entry["py_flavor"]
        role = entry.get("role", "build")
        if role not in ("build", "route-only"):
            # Fail closed: an unknown role (e.g. a "route_only" typo) must NOT fall through
            # to the build path and silently re-enable a fresh build for an EOL version.
            raise BuildRepoError(
                f"invalid role {role!r} for version {version} ({variant}); expected 'build' or 'route-only'"
            )
        varver = catalog_name_from_version(version, variant)  # e.g. "ce-2.8"
        common = dict(abi=abi, php=php, py_flavor=py_flavor, varver=varver, arch=arch, **builder_kwargs)

        if role == "route-only":
            # --- route-only: serve a frozen .pkg from a prior release; no rebuild, no nightly ---
            # The frozen .pkg must be provided by the caller via route_only_pkgs[varver].
            # Fail loud when absent — never emit an empty catalog for an EOL version.
            frozen_pool = list((route_only_pkgs or {}).get(varver) or [])
            if not frozen_pool:
                raise BuildRepoError(
                    f"route-only entry for {varver!r} (version {version}, variant {variant}) "
                    f"has no frozen .pkg provided — supply it via route_only_pkgs[{varver!r}]. "
                    f"A route-only entry without a frozen .pkg would produce an empty or stale "
                    f"catalog; refusing to proceed."
                )
            # A varver's frozen pool may carry entries for other majors too (matched by
            # OS+major, never exact-string — every catalog input is NO_ARCH/wildcard-ABI;
            # _emit_catalog_from_paths hard-rejects a concrete one at emission).
            frozen = [p for p in frozen_pool if _pkg_matches_abi(read_compact_manifest(p), abi)]
            if not frozen:
                raise BuildRepoError(
                    f"route-only entry for {varver!r} (version {version}, variant {variant}) has "
                    f"frozen .pkg, but none match ABI {abi!r} — supply a frozen .pkg for this ABI."
                )
            release_dir = out_dir / "release" / varver
            n_release = _emit_catalog_from_paths(release_dir, frozen)
            built.append(str(release_dir))
            sys.stderr.write(f"==> route-only release catalog {release_dir} ({n_release} package(s), frozen)\n")
            # No nightly subtree — route-only entries never get a nightly build.

        else:
            # --- build entry (role absent or "build") ---

            release_dir = out_dir / "release" / varver

            # --dep-pkgs (issue #1806) ABI-filtered for THIS entry's ABI train (OS+major;
            # _pkg_matches_abi tolerates a NO_ARCH dep's CPU wildcard). Folded into
            # release/nightly AFTER retention below — never before, see build_repo_matrix's
            # docstring. dep_pkgs_matched is updated ONLY where dep_for_abi actually lands
            # in an emitted catalog (below), never merely because it matched this row —
            # marking it matched here unconditionally would let a matched-but-never-emitted
            # dep escape the end-of-run unmatched check (issue #1806 gate-A finding).
            dep_for_abi = [p for p, m in dep_entries if _pkg_matches_abi(m, abi)]

            if release_pkgs is not None:
                # --- consume mode: serve release/<varver>/ from caller-supplied pre-built .pkg ---
                # Matched exactly like the route-only branch; release_extra_pkgs still folded in.
                # An empty pool is a warning + skip (not an error) — a newly-added version with no
                # Release asset yet simply has no release-channel package until the next release.
                pool = [p for p in (release_pkgs.get(varver) or []) if _pkg_matches_abi(read_compact_manifest(p), abi)]
                extras = [p for p in (release_extra_pkgs or []) if _pkg_matches_abi(read_compact_manifest(p), abi)]
                candidates = pool + extras
                kept_release = retain_by_channel(
                    candidates,
                    keep_devel=release_keep_devel,
                    keep_stable=release_keep_stable,
                )
                if kept_release:
                    # dep_for_abi folds in AFTER retention (never competes for a slot).
                    n_release = _emit_catalog_from_paths(release_dir, kept_release + dep_for_abi)
                    built.append(str(release_dir))
                    sys.stderr.write(f"==> release catalog {release_dir} ({n_release} package(s), consumed)\n")
                    dep_pkgs_matched.update(dep_for_abi)
                else:
                    sys.stderr.write(f"==> WARNING: no Release .pkg for {varver} {abi} — release catalog skipped\n")
            else:
                # --- source-build mode (legacy / back-compat): devel + (optional) stable + extras ---
                # The freshly built devel (+ stable when a stable_tag exists) are always present.
                # release_extra_pkgs supplies pre-built older releases (e.g. downloaded from GitHub
                # Releases by publish.yml); together they form the full candidate pool, pruned via
                # retain_by_channel to keep the newest release_keep_devel devel + release_keep_stable
                # stable versions. Defaults of 1/1 reproduce today's latest-only behaviour.
                with tempfile.TemporaryDirectory() as td:
                    staging = Path(td)
                    built_pkgs: list[Path] = [
                        builder("devel", out_dir=staging, ports=ports, local_src=local_src, **common)
                    ]
                    if stable_tag:
                        built_pkgs.append(
                            builder("stable", out_dir=staging, ports=ports, local_src=stable_src or local_src, **common)
                        )
                    # Fold in pre-built older-release candidates (caller-provided, e.g. from GitHub
                    # Releases), matched by OS+major (see _pkg_matches_abi).
                    extras = [p for p in (release_extra_pkgs or []) if _pkg_matches_abi(read_compact_manifest(p), abi)]
                    all_release_pkgs = built_pkgs + extras
                    kept_release = retain_by_channel(
                        all_release_pkgs,
                        keep_devel=release_keep_devel,
                        keep_stable=release_keep_stable,
                    )
                    # dep_for_abi folds in AFTER retention (never competes for a slot).
                    n_release = _emit_catalog_from_paths(release_dir, kept_release + dep_for_abi)
                built.append(str(release_dir))
                sys.stderr.write(f"==> release catalog {release_dir} ({n_release} package(s))\n")
                dep_pkgs_matched.update(dep_for_abi)

            # --- nightly subtree: fold the new build in with retained prior nightlies ---
            if build_nightly:
                nightly_dir = out_dir / "nightly" / varver
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
                    # dep_for_abi folds in AFTER retention here too — the SAME dep pkg
                    # belongs in both the release and nightly catalogs of this ABI train.
                    n = _emit_catalog_from_paths(nightly_dir, kept + dep_for_abi)
                built.append(str(nightly_dir))
                sys.stderr.write(f"==> nightly catalog {nightly_dir} ({n} package(s), kept ≤{nightly_keep})\n")
                dep_pkgs_matched.update(dep_for_abi)

    # A --dep-pkgs entry whose ABI matched no build-role matrix entry is a hard
    # error — never a silent drop (it would otherwise mean a real user's
    # `pkg install` never sees the dependency it was built for).
    unmatched = [p for p, _m in dep_entries if p not in dep_pkgs_matched]
    if unmatched:
        raise BuildRepoError(
            "--dep-pkgs ABI matches no emitted catalog (checked every build-role matrix "
            "entry's ABI; route-only entries never receive a dep pkg): " + ", ".join(str(p) for p in unmatched)
        )

    return {"built": built}


def print_conf(resolved_url: str) -> None:
    """Emit the release-channel repo-conf stanza.

    ``resolved_url`` is the fully-resolved URL for the box's edition/version
    (ADR-39; arch-less since issue #1806 — the catalog is NO_ARCH):
    ``<base>/release/<varver>`` — no ``${ABI}`` token.
    Supply ``--catalog-path <varver>`` so tests can pin the exact bytes.
    """
    url = resolved_url.rstrip("/")
    sys.stdout.write(
        "# Generated at boot by pfblockerng_repo_generate (ADR-39) — do not edit; re-run add-repo.sh to change.\n"
        "# pfBlockerNG (release channel) — self-hosted pkg repository (ADR-17).\n"
        "# NONE-signed: trust anchor is HTTPS to the host (no signing key). The URL is\n"
        "# fully resolved for this box's edition/version (ADR-39; arch-less/NO_ARCH,\n"
        "# issue #1806); the boot rc.d hook updates it on a pfSense OS upgrade.\n"
        f"# priority {CONF_PRIORITY} sits above the base Netgate `pfSense` repo so cross-repo\n"
        "# resolution (pkg install/upgrade, GUI Install) selects the pfBlockerNG build.\n"
        "pfblockerng: {\n"
        f'  url: "{url}",\n'
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
        description="Generate an arch-less FreeBSD pkg repository catalog in pure Python (no libpkg). ADR-17.",
        epilog=(
            "examples:\n"
            "  # build a catalog tree from a dir of release .pkg\n"
            "  build-repo-portable.py --in ./pkgs --out ./site\n\n"
            "  # build under a version-keyed subdir (ADR-20)\n"
            "  build-repo-portable.py --in ./pkgs --out ./site --catalog-name ce-2.8\n\n"
            "  # print the client repo-conf (add-repo.sh + README reuse it)\n"
            "  build-repo-portable.py --print-conf --base-url https://example.github.io/pkg\n\n"
            "  # matrix-driven: build the full variant tree, arch-less (ADR-20; issue #1806)\n"
            "  read-version-matrix.sh --print-build | build-repo-portable.py --build-matrix \\\n"
            "    --matrix-json - --out ./site --ports ./ports --local-src . \\\n"
            "    --nightly-pkgversion 3.2.16.20260615.1\n"
        ),
    )
    ap.add_argument("--in", dest="in_dir", help="directory holding the input .pkg files (searched, non-recursive)")
    ap.add_argument("--out", dest="out_dir", help="output root; the flat, arch-less catalog is written directly here")
    ap.add_argument("--print-conf", action="store_true", help="print the client repo-conf template to stdout and exit")
    ap.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help="base URL for --print-conf (default: the ADR-39 direct Pages base)",
    )
    ap.add_argument(
        "--catalog-path",
        default="",
        dest="catalog_path",
        help=(
            "catalog subtree for --print-conf, a bare '<varver>' (e.g. 'ce-2.8', "
            "'plus-26.03') — the catalog is arch-less (NO_ARCH; issue #1806). "
            "When supplied, the emitted url is <base-url>/release/<catalog-path>. "
            "Required for byte-identical output across all four generators."
        ),
    )
    ap.add_argument(
        "--catalog-name",
        dest="catalog_name",
        default=None,
        help=(
            "when supplied, write the flat catalog under <out>/<catalog-name>/ "
            "instead of directly at <out>/ (e.g. 'ce-2.8', 'plus-26.03'); the "
            "catalog is arch-less (NO_ARCH; issue #1806), so there is no <ABI>/ "
            "subdir either way. Derive from pfsense_version + variant via "
            "catalog_name_from_version()."
        ),
    )
    g_matrix = ap.add_argument_group("matrix-driven build (ADR-20 routing rework)")
    g_matrix.add_argument(
        "--build-matrix",
        action="store_true",
        help=(
            "drive build-pkg-portable.py per (matrix entry x channel), lay out the "
            "release/<varver>/ + nightly/<varver>/ tree under --out (arch-less; NO_ARCH, "
            "issue #1806). Requires --matrix-json + --out."
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
    g_matrix.add_argument("--nightly-keep", type=int, default=14, help="nightlies retained per varver (default 14)")
    g_matrix.add_argument(
        "--nightly-pkgversion",
        default=None,
        help="full pkg-safe nightly version <target>.YYYYMMDD.N applied to every entry's nightly build",
    )
    g_matrix.add_argument("--no-nightly", action="store_true", help="skip the nightly subtree (release + routing only)")
    g_matrix.add_argument(
        "--release-keep-devel",
        type=_non_negative_int,
        default=1,
        dest="release_keep_devel",
        help=(
            "devel releases retained per varver in the release catalog (default 1 = latest-only). "
            "Set >1 to retain multiple devel artifacts for diagnostics and reproducibility. "
            "The publish job must supply the older .pkg via --release-extra-pkgs. "
            "The newest package of every major/minor line is pinned on top of this window, "
            "so the catalog can hold more than N devel packages."
        ),
    )
    g_matrix.add_argument(
        "--release-keep-stable",
        type=_non_negative_int,
        default=1,
        dest="release_keep_stable",
        help=(
            "stable releases retained per varver in the release catalog (default 1 = latest-only). "
            "Set >1 to retain multiple stable artifacts for diagnostics and reproducibility. "
            "The publish job must supply the older .pkg via --release-extra-pkgs. "
            "The newest package of every major/minor line is pinned on top of this window, "
            "so the catalog can hold more than M stable packages."
        ),
    )
    g_matrix.add_argument(
        "--release-extra-pkgs",
        action="append",
        default=[],
        dest="release_extra_pkgs",
        metavar="PATH",
        help=(
            "pre-built older-release .pkg file to fold into the release catalog alongside the fresh build "
            "(repeatable; e.g. downloaded from GitHub Releases by publish.yml). "
            "Pruned by --release-keep-devel / --release-keep-stable after folding."
        ),
    )
    g_matrix.add_argument(
        "--dep-pkgs",
        action="append",
        default=[],
        dest="dep_pkgs",
        metavar="PATH",
        help=(
            "pre-built dependency .pkg (e.g. py311-charset-normalizer, built by "
            "build-dep-pkg-portable.py) to fold into BOTH the release AND nightly catalogs "
            "of every matrix entry whose ABI matches (repeatable). Folded in AFTER "
            "--release-keep-*/--nightly-keep retention runs — NEVER before, or the dep would "
            "compete with real releases/nightlies for a retention slot. A dep whose ABI "
            "matches no emitted catalog is a hard error."
        ),
    )
    g_matrix.add_argument(
        "--route-only-pkgs",
        action="append",
        default=[],
        dest="route_only_pkgs",
        metavar="VARVER:PATH",
        help=(
            "frozen .pkg for a route-only (EOL) catalog entry, in VARVER:PATH form "
            "(repeatable; e.g. --route-only-pkgs ce-2.7:/path/to/frozen.pkg). "
            "publish.yml downloads these from GitHub Releases and passes them here. "
            "Required for every route-only matrix entry; raises BuildRepoError when absent."
        ),
    )
    g_matrix.add_argument(
        "--release-pkgs",
        action="append",
        default=[],
        dest="release_pkgs",
        metavar="VARVER:PATH",
        help=(
            "pre-built Release .pkg to SERVE the release/<varver>/ catalog from, "
            "in VARVER:PATH form (repeatable; matched by OS+major, arch-less; issue #1806). "
            "When supplied, devel+stable are consumed from these instead of rebuilt from source. "
            "An empty pool for a varver skips that release catalog (no error)."
        ),
    )
    g_matrix.add_argument(
        "--annotate",
        action="append",
        default=[],
        metavar="K=V",
        help="manifest annotation K=V applied to EVERY build (repeatable; e.g. commit=<sha> created=<epoch>)",
    )
    args = ap.parse_args(argv)

    if args.print_conf:
        if not args.catalog_path or not args.catalog_path.strip("/"):
            ap.error("--print-conf requires --catalog-path <varver>")
        _base = args.base_url.rstrip("/")
        _cat = args.catalog_path.strip("/")
        print_conf(f"{_base}/release/{_cat}")
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
        annotate: dict[str, str] = {}
        for item in args.annotate:
            if "=" not in item:
                ap.error(f"--annotate must be K=V (got {item!r})")
            k, v = item.split("=", 1)
            annotate[k] = v
        extra_pkgs = [Path(p) for p in args.release_extra_pkgs] if args.release_extra_pkgs else None
        dep_pkgs_arg = [Path(p) for p in args.dep_pkgs] if args.dep_pkgs else None
        route_only: dict[str, list[Path]] | None = None
        if args.route_only_pkgs:
            route_only = {}
            for item in args.route_only_pkgs:
                if ":" not in item:
                    ap.error(f"--route-only-pkgs must be VARVER:PATH (got {item!r})")
                varver_key, _, pkg_path = item.partition(":")
                route_only.setdefault(varver_key, []).append(Path(pkg_path))
        release_pkgs_arg: dict[str, list[Path]] | None = None
        if args.release_pkgs:
            release_pkgs_arg = {}
            for item in args.release_pkgs:
                if ":" not in item:
                    ap.error(f"--release-pkgs must be VARVER:PATH (got {item!r})")
                varver_key, _, pkg_path = item.partition(":")
                release_pkgs_arg.setdefault(varver_key, []).append(Path(pkg_path))
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
                release_keep_devel=args.release_keep_devel,
                release_keep_stable=args.release_keep_stable,
                release_extra_pkgs=extra_pkgs,
                dep_pkgs=dep_pkgs_arg,
                route_only_pkgs=route_only,
                release_pkgs=release_pkgs_arg,
                annotate=annotate or None,
            )
        except (BuildRepoError, PkgError, subprocess.CalledProcessError) as e:
            sys.stderr.write(f"build-repo-portable: {e}\n")
            return 1
        return 0

    if not args.in_dir or not args.out_dir:
        ap.error("--in and --out are required (or use --print-conf / --build-matrix)")
    in_dir = Path(args.in_dir)
    if not in_dir.is_dir():
        sys.stderr.write(f"build-repo-portable: --in is not a directory: {in_dir}\n")
        return 1

    try:
        abis = build_repo(in_dir, Path(args.out_dir), catalog_name=args.catalog_name)
    except (BuildRepoError, PkgError) as e:
        sys.stderr.write(f"build-repo-portable: {e}\n")
        return 1
    sys.stderr.write(f"==> built catalog for ABI: {' '.join(abis)}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
