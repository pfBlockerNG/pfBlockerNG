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
import re
import shutil
import subprocess
import sys
import tarfile
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
# (gh api repos/.../pages -> html_url https://pfblockerng.github.io/pkg/);
# we serve over HTTPS, so the base is https://pfblockerng.github.io/pkg. Kept identical
# to scripts/build-repo.sh DEFAULT_BASE_URL so the two generators stay byte-equal.
DEFAULT_BASE_URL = "https://pfblockerng.github.io/pkg"
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
        # Wipe + rebuild for determinism (a removed .pkg never lingers).
        if bucket.exists():
            shutil.rmtree(bucket)
        bucket.mkdir(parents=True)

        catalog_objs: list[dict] = []
        # Deterministic order: by (name, version).
        for (name, version), (path, manifest) in sorted(by_abi[abi].items()):
            canonical = f"{name}-{version}.pkg"
            pkg_bytes = path.read_bytes()
            dest = bucket / canonical
            dest.write_bytes(pkg_bytes)
            obj = catalog_object(
                manifest,
                pkg_name=canonical,
                sum_=pkg_checksum(pkg_bytes),
                pkgsize=len(pkg_bytes),
            )
            catalog_objs.append(obj)

        # meta.conf + its identical `meta` copy (real `pkg repo` writes both).
        (bucket / "meta.conf").write_text(META_CONF)
        (bucket / "meta").write_text(META_CONF)
        # packagesite.pkg (packagesite.yaml = NDJSON) + data.pkg (data = one JSON object).
        write_zstd_tar("packagesite.yaml", _ndjson(catalog_objs), bucket / "packagesite.pkg")
        write_zstd_tar("data", _data_blob(catalog_objs), bucket / "data.pkg")
        sys.stderr.write(f"==> built catalog {bucket} ({len(catalog_objs)} package(s))\n")

    return sorted(by_abi)


def print_conf(base_url: str) -> None:
    base = base_url.rstrip("/")
    sys.stdout.write(
        "# pfBlockerNG (devel channel) — self-hosted pkg repository (ADR-17).\n"
        "# NONE-signed: trust anchor is HTTPS to the host (no signing key). The ${ABI}\n"
        "# variable is expanded by pkg(8) and follows the box across a pfSense OS upgrade.\n"
        f"# priority {CONF_PRIORITY} sits above the base Netgate `pfSense` repo so cross-repo\n"
        "# resolution (pkg install/upgrade, GUI Install) selects our build.\n"
        "pfblockerng-devel: {\n"
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
            "    --routing-json-path routing.json\n"
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
