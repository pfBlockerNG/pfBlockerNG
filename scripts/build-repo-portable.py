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
import urllib.parse
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import TypeGuard

from pfb_pkg import (
    CANONICAL_EMITTED_IDENTITY,
    PFB_BUILD_RECORD_KEY,
    PkgError,
    load_build_record,
    pkg_version_sort_key,
    read_compact_manifest,
    validate_build_record,
    validate_project_pkg,
    zstd_compress,
)

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
# scripts/build-repo.sh --print-conf (pinned by tests/test_repo_conf_generators.py)
# so both generators are interchangeable.
# ${ABI} is the literal pkg(8) variable (expanded by pkg, never the shell), so
# one conf follows the box across an OS upgrade; priority 100 sits above the
# base Netgate `pfSense` repo (priority 0) because priority — not version —
# decides cross-repo resolution. Base URL is this repo's GitHub Pages root
# (ADR-39; the Cloudflare Worker has been retired).
# The pkg repository domain. Scheme is chosen per use: the catalogue is fetched over
# plain HTTP (pkg's CA store is Netgate-pinned on pfSense Plus, so TLS is not a trust
# anchor we can rely on — the catalogue signature is, issue #2675), while anything a
# human or a root shell fetches from the same host stays HTTPS.
REPO_HOST = "pkg.pfblockerng.com"
DEFAULT_BASE_URL = f"http://{REPO_HOST}"
CONF_PRIORITY = 100

# Per-channel repo-conf stanza key (issue #2147 step B): the four channels
# (stable/testing/edge/nightly) plus the legacy "release" default all carry the
# ONE canonical pfSense-pkg-pfBlockerNG identity — channel only picks the
# stanza name + URL path segment. Mirrors install.sh's PROJECT_CONFS keying.
_CHANNEL_REPO_NAMES = {
    "release": "pfblockerng",
    "nightly": "pfblockerng-nightly",
    "stable": "pfblockerng-stable",
    "testing": "pfblockerng-testing",
    "edge": "pfblockerng-edge",
}

# A NO_ARCH package's manifest ABI wildcards ONLY the final CPU segment — e.g.
# "FreeBSD:15:*" (probed live against a real Netgate noarch package; issue
# #1806). Tight: '*' is valid ONLY as the whole final segment, never elsewhere
# and never partial — "FreeBSD:*:amd64" / "*" / "FreeBSD:15:*extra" are not ABIs.
_ABI_WILDCARD_RE = re.compile(r"^[A-Za-z0-9._+-]+:[A-Za-z0-9._+-]+:\*$")


def _is_wildcard_abi(abi: object) -> TypeGuard[str]:
    """True if ``abi`` is a NO_ARCH package's tight, CPU-wildcarded ABI string."""
    return isinstance(abi, str) and bool(_ABI_WILDCARD_RE.fullmatch(abi))


# A .pkg's manifest name/version become the published filename ``<name>-<version>.pkg``.
# The manifest is READ from the package (attacker-controlled input, never derived), so
# both fields get a segment guard too. Wider class than a varver — real pkg names and
# versions carry uppercase, '_' (port revision, "1.0_1") and ',' (PORTEPOCH, "1.0,1").
_PKG_SEGMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._,+-]*$")


class BuildRepoError(Exception):
    """A fatal, user-facing error (bad input / collision / missing tool)."""


def _require_wildcard_abi(path: Path, abi: object, *, route_only: bool = False) -> str:
    """Validate ``abi`` is a NO_ARCH package's wildcard ABI, or raise ``BuildRepoError``.

    Shared by ``build_repo()`` and ``_emit_catalog_from_paths()`` so the reject wording
    (and the NO_ARCH policy behind it) has exactly one canonical source instead of two
    verbatim-duplicated copies. Returns the validated ABI as ``str`` (narrowed via
    ``_is_wildcard_abi``'s ``TypeGuard``) so callers need no further cast. ``route_only``
    selects the settled pre-#1806 frozen-tag remedy without mislabeling other inputs.
    """
    if not _is_wildcard_abi(abi):
        remedy = (
            "For a frozen route-only package, a concrete ABI identifies a pre-#1806 tag; "
            "a pre-#1806 tag is unservable as route-only. Refusing to emit it."
            if route_only
            else "Ship a wildcard-ABI (NO_ARCH) build instead."
        )
        raise BuildRepoError(
            f"{path.name}: catalog requires a NO_ARCH (wildcard-ABI) package — got "
            f"concrete ABI {abi!r}. The catalog tree is arch-less (one directory serves "
            f"every arch of a FreeBSD major); a concrete-ABI package would silently "
            f"install on only one arch. {remedy}"
        )
    return abi


def _safe_segment(value: object, *, what: str, pattern: re.Pattern[str]) -> str:
    """Return ``value`` if it is safe to use as ONE path segment, else raise.

    Everything joined onto the output root here is either read from an untrusted
    manifest or passed in from the CLI/matrix, and the destination directory is
    ``rmtree``'d before it is rebuilt — so an unvalidated segment is an arbitrary
    directory wipe (``".."``) or an escape from the output root entirely (an
    absolute path makes ``Path.__truediv__`` discard its left operand). Mirrors the
    guard ``scripts/build-repo.sh`` applies to ``--varver``.
    """
    if not isinstance(value, str) or not pattern.fullmatch(value) or ".." in value:
        raise BuildRepoError(
            f"unsafe or invalid {what}: {value!r} — must be a single path segment "
            f"matching {pattern.pattern} with no '..' (it becomes an rm -rf'd directory)"
        )
    return value


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
# the pkg-owned catalogue renderer. zstd_decompress / read_compact_manifest are imported above.
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
# Catalogue signing (issue #2675) — `signature_type: fingerprints`, ECDSA.
#
# Authenticity used to rest on HTTPS to the host, which is exactly what breaks
# on pfSense Plus: `pfSense-repo-setup` pins pkg to a Netgate-only CA bundle,
# and no environment-based workaround can reach the GUI (php-fpm scrubs the
# worker environment, and pfSense's own pkg_call() replaces it outright). A
# signed catalogue moves the trust anchor onto our own key, so the fetch itself
# no longer has to be TLS.
#
# Every byte below follows freebsd/pkg (13f9f98); the details are unforgiving
# because a mismatch fails only at verification, on the box:
#   * the signed message is the 64-character ASCII SHA256 HEX of the
#     UNCOMPRESSED catalogue member, signed ECDSA-SHA256 (`ecc_new()` pins
#     sig_hash = SHA256 for ecdsa regardless of curve). It is the CERT path —
#     `ecc_verify_cert_cb()` — that FINGERPRINTS mode runs, and it hashes with
#     PKG_HASH_TYPE_SHA256_HEX passed at `strlen()`, so no NUL terminator.
#     The BLAKE2b-512 chain in `ecc_sign_file()`/`ecc_verify_file()` belongs to
#     PUBKEY mode (single `signature` member) — signing that instead yields a
#     catalogue a real pkg rejects with "ecc signature verification failure".
#   * a non-RSA signature is prefixed `$PKGSIGN:<type>$` (PKGSIGN_HEAD,
#     libpkg/private/pkgsign.h), which is how the client selects the signer.
#   * the public half is DER for ECDSA (exported as PKCS#8 "for interoperability
#     with OpenSSL"); the ECC loader calls libder_read() and knows no PEM.
#   * the trusted fingerprint is the SHA256 of exactly those DER bytes, so any
#     re-encoding invalidates every fingerprint file already deployed.
# --------------------------------------------------------------------------- #

# The signature member carries this before the raw DER signature.
PKGSIGN_ECDSA_HEAD = b"$PKGSIGN:ecdsa$"

# pkg accepts far fewer curves than OpenSSL offers: `ecc_read_pkgkey()` matches
# the curve OID against this set and nothing else. prime256v1/secp256r1 — the
# curve almost every tool defaults to — is NOT among them, which is why signing
# validates the curve up front rather than shipping a catalogue no box can
# verify.
PKG_ACCEPTED_CURVES = frozenset(
    {
        "secp256k1",
        "secp384r1",
        "secp521r1",
        "brainpoolP256r1",
        "brainpoolP256t1",
        "brainpoolP320r1",
        "brainpoolP320t1",
        "brainpoolP384r1",
        "brainpoolP384t1",
        "brainpoolP512r1",
        "brainpoolP512t1",
    }
)


def _openssl(args: list[str], *, stdin: bytes | None = None) -> bytes:
    """Run `openssl` and return stdout; every failure becomes a BuildRepoError."""
    try:
        proc = subprocess.run(
            ["openssl", *args],
            input=stdin,
            capture_output=True,
            check=False,
        )
    except OSError as exc:  # pragma: no cover - environment-dependent
        # OSError, not FileNotFoundError: an `openssl` that exists on PATH but is not
        # executable raises PermissionError, which would otherwise escape this wrapper
        # as a bare traceback instead of a BuildRepoError.
        raise BuildRepoError(f"cannot run `openssl` for catalogue signing: {exc}") from exc
    if proc.returncode != 0:
        detail = proc.stderr.decode(errors="replace").strip() or f"exit {proc.returncode}"
        raise BuildRepoError(f"openssl {args[0]} failed: {detail}")
    return proc.stdout


def signing_public_der(sign_key: Path) -> bytes:
    """The signing key's public half as RAW DER, after checking pkg accepts its curve.

    Raw, with no `$PKGSIGN:` header, because these exact bytes are what the client hashes
    for the trusted fingerprint (`pkg_repo_check_fingerprint` hashes the cert AFTER the
    extractor strips any header). The header belongs to the archive MEMBER, and
    write_zstd_tar() adds it there — keeping it out of here means a fingerprint file can
    never be generated over the wrong bytes.
    """
    text = _openssl(["ec", "-in", str(sign_key), "-noout", "-text"]).decode(errors="replace")
    # `openssl ec -text` names the curve on an "ASN1 OID:" line. Keying on that
    # rather than the "NIST CURVE:" line keeps brainpool curves (which have no
    # NIST name) readable by the same parse.
    match = re.search(r"^\s*ASN1 OID:\s*(\S+)\s*$", text, re.MULTILINE)
    if match is None:
        raise BuildRepoError(
            f"{sign_key}: cannot determine the EC curve — `openssl ec -text` printed no "
            "`ASN1 OID:` line. Either this is not an EC private key, or it carries explicit "
            "curve parameters (`-param_enc explicit`) rather than naming a curve; pkg matches "
            "curves by OID, so the key must name one."
        )
    curve = match.group(1)
    if curve not in PKG_ACCEPTED_CURVES:
        raise BuildRepoError(
            f"{sign_key}: pkg cannot verify signatures on curve {curve!r} — "
            f"choose one of {', '.join(sorted(PKG_ACCEPTED_CURVES))} (secp384r1 recommended)"
        )
    return _openssl(["ec", "-in", str(sign_key), "-pubout", "-outform", "DER"])


def catalog_signature(data: bytes, sign_key: Path) -> bytes:
    """The `.sig` member body for ``data``: header + ECDSA-SHA256 over its SHA256 HEX text.

    The signed message is the 64-character ASCII hex of the catalogue's SHA256 — not a raw
    digest, and not BLAKE2b. `ecc_verify_cert_cb()`, which is what FINGERPRINTS mode runs,
    does `pkg_checksum_fd(fd, PKG_HASH_TYPE_SHA256_HEX)` and passes the result with
    `strlen()`, so there is no NUL terminator either. libecc then hashes that text with
    SHA256 internally, which is what `openssl dgst -sha256 -sign` reproduces.

    Do not reach for the BLAKE2b-512 chain in `ecc_sign_file()`/`ecc_verify_file()`: those
    serve PUBKEY mode, whose catalogue carries a single `signature` member instead of our
    `.sig`/`.pub` pair. Signing the wrong one still produces a well-formed catalogue that a
    real `pkg update` rejects with "ecc signature verification failure".
    """
    message = hashlib.sha256(data).hexdigest().encode()
    return PKGSIGN_ECDSA_HEAD + _openssl(["dgst", "-sha256", "-sign", str(sign_key)], stdin=message)


# Archive emission (zstd tar) — same framing contract as build-pkg-portable.py:
# USTAR, leading-slash-free member name, root:wheel, mode 0644, deterministic
# mtime 0 (the install/index clock is irrelevant to clients; 0 keeps re-runs
# byte-identical). USTAR is the proven-accepted framing (build-pkg-portable.py's
# .pkg uses it and a real pfSense box installs it).
#
# Byte-identical re-runs hold for UNSIGNED output only: ECDSA signatures are
# randomised (OpenSSL does not implement deterministic RFC 6979), so a signed
# catalogue differs between builds even when the package set does not — see
# issue #2675 for what that costs the publisher's NOOP detection.
# --------------------------------------------------------------------------- #


def _tar_one(members: list[tuple[str, bytes]]) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        for member_name, data in members:
            ti = tarfile.TarInfo(name=member_name)
            ti.size = len(data)
            ti.mode = 0o644
            ti.uid = ti.gid = 0
            ti.uname, ti.gname = "root", "wheel"
            ti.mtime = 0
            ti.type = tarfile.REGTYPE
            tf.addfile(ti, io.BytesIO(data))
    return raw.getvalue()


def write_zstd_tar(member_name: str, data: bytes, out_path: Path, *, sign_key: Path | None = None) -> None:
    """Write ``data`` as a one-member zstd tar, signed when ``sign_key`` is given.

    With a key, the archive gains ``<member_name>.sig`` and ``<member_name>.pub``
    AHEAD of the catalogue member — the order real `pkg repo` writes (pack_sign()
    runs before packing_append_file_attr()), and the names it derives from the
    MEMBER rather than the archive. Without a key the output is unchanged, so
    local and offline catalogues stay exactly as they were.
    """
    members: list[tuple[str, bytes]] = []
    if sign_key is not None:
        # BOTH members carry the `$PKGSIGN:ecdsa$` header. Not symmetry for its own sake:
        # pkg_repo_parse_sigkeys() sets the signer type from EVERY member it parses, keyed
        # by basename, so a bare `.pub` (parsed after `.sig`) resets the type to its "rsa"
        # default. Verification then runs the RSA signer, whose _load_public_key_buf() is
        # PEM_read_bio_PUBKEY, and a real `pkg update` dies with "error reading public key
        # ... DECODER routines::unsupported". Real `pkg repo` prefixes both too, because
        # pack_command_sign() never resets its iovec offset between the two appends.
        members.append((f"{member_name}.sig", catalog_signature(data, sign_key)))
        members.append((f"{member_name}.pub", PKGSIGN_ECDSA_HEAD + signing_public_der(sign_key)))
    members.append((member_name, data))
    out_path.write_bytes(
        zstd_compress(
            _tar_one(members),
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


_PY_FLAVOR_ORIGIN = re.compile(r"^(py)(?:\d+)?-")


def _origin_key(value: object) -> tuple[str, str] | None:
    """(category, unflavored last) for a port origin. Same rule as publish_release."""
    if not isinstance(value, str) or "/" not in value:
        return None
    category, last = value.rsplit("/", 1)
    if not category or not last:
        return None
    stripped = _PY_FLAVOR_ORIGIN.sub("", last, count=1)
    return (category, stripped or last)


def _row_declares_origin(row: Mapping[str, object], origin: object) -> bool:
    """True iff this matrix row lists ``origin`` in extra_pkgs (issue #2403)."""
    extras = row.get("extra_pkgs")
    if not isinstance(extras, list):
        return False
    if origin in extras:
        return True
    key = _origin_key(origin)
    if key is None:
        return False
    return any(_origin_key(extra) == key for extra in extras)


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
    """Fail loud if same-identity packages differ in flavor or archive bytes."""
    seen: dict[str, tuple[str, Path, bytes]] = {}  # key -> flavor, source, archive
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
            seen[key] = (sig, path, path.read_bytes())
        elif prev[0] != sig:
            raise BuildRepoError(
                f"FLAVOR COLLISION — two packages share name+version+ABI '{key}'\n"
                f"  but differ in php/py flavor:\n"
                f"    flavor A: {prev[0] or '<none>'}\n"
                f"    flavor B: {sig or '<none>'}\n"
                f"  They cannot coexist in one catalog (the second would shadow the first).\n"
                f"  Resolve by splitting into a flavored layout: <out>/<ABI>-<php><py>/\n"
                f"  (not implemented — no colliding combo exists today; teach the tool when one does)."
            )
        elif prev[2] != path.read_bytes():
            raise BuildRepoError(
                f"PACKAGE COLLISION — two packages share name+version+ABI+flavor '{key}'\n"
                f"  but archive bytes differ: {prev[1].name} vs {path.name}"
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

    A pre-release suffix is stripped BEFORE the split, so a pre-release publishes
    under its release line's catalog — the same strip the rc.d repo-generate hook
    applies on the box (issue #1965; the suffix sits inside the minor field, so a
    bare split would keep it and publish a directory no box ever resolves):
      "26.07-BETA" + "Plus"       -> "plus-26.07"
      "2.8.1-RELEASE" + "CE"      -> "ce-2.8"

    When channel is supplied (e.g. "nightly"), it is prepended as a path prefix:
      "2.8.1"  + "CE"   + "nightly" -> "nightly/ce-2.8"
      "26.03.1"+ "Plus" + "nightly" -> "nightly/plus-26.03"

    The derived name becomes an rmtree'd path segment, so it goes through the same
    ``_validate_catalog_name`` guard a caller-supplied ``--catalog-name`` does — the
    matrix fields it is built from are inputs, not constants.
    """
    major_minor = ".".join(pfsense_version.split("-")[0].split(".")[:2])
    name = f"{variant.lower()}-{major_minor}"
    _validate_catalog_name(name, single_segment=True)
    if not channel:
        return name
    # The channel is an argument like any other — validate the COMPOSED value, or a
    # caller-supplied channel would ride into the path unchecked (issue #1965).
    composed = f"{channel}/{name}"
    _validate_catalog_name(composed)
    return composed


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #

# A catalog_name segment is a rm-rf'd + rebuilt path component (_write_catalog_dir
# shutil.rmtree()s it) — same safety rule as build-repo.sh's --varver guard, tightened
# to lowercase-only. '/' is allowed only BETWEEN segments (a legitimate catalog_name
# carries a channel prefix, e.g. "nightly/plus-26.03"). BOTH ends are alphanumeric so a
# segment can never open or close with '-' or '.': every real varver does (ce-2.8,
# plus-26.03, nightly, release), while an absent variant would otherwise derive the
# silently-wrong "-2.8" and an absent version the equally wrong "ce-" (issue #1965).
_CATALOG_NAME_SEGMENT_RE = re.compile(r"[a-z0-9]([a-z0-9.-]*[a-z0-9])?")

# pkg(8) catalog plumbing: a catalog_name equal to one of these collides with a file
# _write_catalog_dir writes at the catalog root, so `out_dir / catalog_name` would name
# an existing FILE and rmtree/mkdir would escape this module's BuildRepoError contract
# with a raw NotADirectoryError. A manifest can never reach these (the published name is
# always "<name>-<version>.pkg"), so this guards the catalog_name path only.
_RESERVED_CATALOG_NAMES = frozenset({"meta", "meta.conf", "data.pkg", "packagesite.pkg"})


def _validate_catalog_name(name: str, *, single_segment: bool = False) -> None:
    """Reject an unsafe ``catalog_name`` before it becomes ``out_dir / catalog_name``
    (issue #1786): a ``".."`` segment escapes sideways/upward, and an ABSOLUTE value
    makes ``Path.__truediv__`` discard ``out_dir`` entirely — either lets a caller
    point ``_write_catalog_dir``'s ``shutil.rmtree()`` at an arbitrary directory.

    ``single_segment`` additionally forbids the channel prefix. A value DERIVED from
    matrix fields (``catalog_name_from_version``) is one segment by construction, so a
    '/' there means a field carried a separator — which this guard would otherwise read
    as a legitimate prefix and wave through (issue #1965).
    """
    segments = name.split("/")
    if single_segment and len(segments) != 1:
        raise BuildRepoError(
            f"unsafe catalog_name {name!r}: a derived varver is ONE segment — a '/' means "
            f"an input field carried a path separator"
        )
    if any(seg in _RESERVED_CATALOG_NAMES for seg in segments):
        raise BuildRepoError(
            f"unsafe catalog_name {name!r}: a segment collides with pkg(8) catalog plumbing "
            f"({', '.join(sorted(_RESERVED_CATALOG_NAMES))}) — it would name an existing file, not a directory"
        )
    if any(not seg or seg in (".", "..") or not _CATALOG_NAME_SEGMENT_RE.fullmatch(seg) for seg in segments):
        raise BuildRepoError(
            f"unsafe catalog_name {name!r}: each '/'-separated segment must be non-empty, "
            f"not '.'/'..', and match [a-z0-9][a-z0-9.-]* (e.g. 'ce-2.8', 'release/ce-2.8')"
        )


def build_repo(
    in_dir: Path,
    out_dir: Path,
    *,
    catalog_name: str | None = None,
    sign_key: Path | None = None,
) -> list[str]:
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
    # `is not None`, not truthiness: an empty catalog_name is a caller bug, and
    # silently treating it as "no catalog name" would publish at the output root.
    if catalog_name is not None:
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
    n = _emit_catalog_from_paths(catalog_root, pkgs, root=out_dir, sign_key=sign_key)
    sys.stderr.write(f"==> built catalog {catalog_root} ({n} package(s))\n")
    return sorted(abis)


def _write_catalog_dir(
    dest: Path,
    items: dict[tuple[str, str], tuple[Path, dict]],
    *,
    root: Path,
    sign_key: Path | None = None,
) -> int:
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
        # name/version come from the .pkg's own manifest and become the published
        # filename — guard both before either is joined onto dest (issue #1965).
        _safe_segment(name, what=f"{path.name}: manifest name", pattern=_PKG_SEGMENT_RE)
        _safe_segment(version, what=f"{path.name}: manifest version", pattern=_PKG_SEGMENT_RE)
        canonical = f"{name}-{version}.pkg"
        staged.append((canonical, path.read_bytes(), path.stat().st_mtime, manifest))

    # Re-checked HERE, immediately before the wipe, not only at the caller: staging above
    # reads every input .pkg, and a layout that changed under us in that window would
    # otherwise be acted on. This narrows the race to no intervening I/O; it does not
    # eliminate it (only an O_NOFOLLOW/dir_fd walk would). Issue #1972.
    _require_contained(root, dest)
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)

    catalog_objs: list[dict] = []
    for canonical, pkg_bytes, src_mtime, manifest in staged:
        target = dest / canonical
        target.write_bytes(pkg_bytes)
        # Preserve the source .pkg's mtime so the published artifact reflects its real
        # build time — a cache-restored nightly keeps its original datetime instead of
        # jumping to this catalog-regeneration run.
        os.utime(target, (src_mtime, src_mtime))
        catalog_objs.append(
            catalog_object(manifest, pkg_name=canonical, sum_=pkg_checksum(pkg_bytes), pkgsize=len(pkg_bytes))
        )

    # meta.conf + its identical `meta` copy (real `pkg repo` writes both).
    (dest / "meta.conf").write_text(META_CONF)
    (dest / "meta").write_text(META_CONF)
    # packagesite.pkg (packagesite.yaml = NDJSON) + data.pkg (data = one JSON object).
    write_zstd_tar("packagesite.yaml", _ndjson(catalog_objs), dest / "packagesite.pkg", sign_key=sign_key)
    write_zstd_tar("data", _data_blob(catalog_objs), dest / "data.pkg", sign_key=sign_key)
    return len(catalog_objs)


# --------------------------------------------------------------------------- #
# ADR-20: the matrix-driven BRAIN. build_repo_matrix() drives the DUMB
# build-pkg-portable.py builder per (ci-metadata entry x channel) and projects
# the matrix onto release/<variant>-<major.minor>/... (stable+testing+edge, one
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

    Used for nightly retention (timestamp plus source SHA — a later build
    sorts higher) AND release-channel retention (canonical ``X.Y.Z.aN|bN|rN`` and
    retained legacy expanded versions,
    via ``retain_by_channel``'s ``--release-keep-testing``/``--release-keep-stable`` >
    1), so it must also order the alpha/beta/rc prerelease stages correctly, not just
    the Nightly timestamp shape. Kept as a thin alias — this module's ``_retain_newest``
    callers reference it by this name.
    """
    return pkg_version_sort_key(version)


def _require_contained(root: Path, dest: Path) -> Path:
    """Return ``dest`` if it really lands inside ``root``, else raise (issue #1972).

    ``_validate_catalog_name`` checks the catalog name as a STRING; the FILESYSTEM
    decides where that string lands. A symlink at any component — including an
    intermediate one, which ``shutil.rmtree`` follows happily — redirects the
    wipe-and-rebuild outside the output root while every segment still looks like a
    legitimate varver. Resolving both sides and requiring containment is the check the
    name guard structurally cannot make.

    A symlinked LEAF is refused outright even when it points back inside the root: the
    catalog directory is wiped and recreated, so it has to be a real directory this
    tool owns (``rmtree`` declines a symlink, which would surface as a raw ``OSError``).
    """
    resolved_root = root.resolve()
    resolved_dest = dest.resolve()
    if not resolved_dest.is_relative_to(resolved_root):
        raise BuildRepoError(
            f"catalog destination {str(dest)!r} escapes the output root {str(root)!r} "
            f"(resolves to {str(resolved_dest)!r}) — a symlinked path component redirects "
            f"the rmtree+rebuild outside --out"
        )
    if dest.is_symlink():
        raise BuildRepoError(
            f"catalog destination {str(dest)!r} is a symlink — the catalog directory is wiped "
            f"and rebuilt, so it must be a real directory"
        )
    # Every component, not just the leaf: `dest.exists()` is False when an ANCESTOR is a
    # file (it does not raise), and resolve() passes straight through such a component, so
    # a leaf-only check lets `mkdir(parents=True)` raise a raw NotADirectoryError from
    # inside the writer. Walk from the root outwards so the message names the real culprit.
    # `is_relative_to` alone is the stop condition: the root IS a component that must be a
    # real directory (without a catalog name the destination simply IS the root), and the
    # first ancestor ABOVE it is not relative to it, so the walk never inspects anything
    # outside the output root.
    for component in (dest, *dest.parents):
        if not component.is_relative_to(root):
            break
        if component.exists() and not component.is_dir():
            raise BuildRepoError(
                f"catalog destination {str(dest)!r} is unusable: {str(component)!r} exists and is "
                f"not a directory — the catalog directory is wiped and rebuilt, so every component "
                f"of its path must be a real directory"
            )
    return dest


def _emit_catalog_from_paths(
    dest: Path,
    pkg_paths: list[Path],
    *,
    root: Path,
    route_only: bool = False,
    sign_key: Path | None = None,
) -> int:
    """Read each .pkg's manifest, dedup by (name, version), collision-check, emit at dest.

    Every package here MUST carry a NO_ARCH (wildcard) ABI (``_is_wildcard_abi``,
    issue #1806) — the matrix-driven catalog tree is arch-less: one directory
    (``release/<varver>/`` / ``nightly/<varver>/``) serves every arch of a
    FreeBSD major, so a concrete-ABI package would silently install on only
    one. A concrete ABI reaching catalog emission is a hard error — the
    tripwire that forces a conscious layout decision if a compiled, per-arch
    dependency is ever added.

    ``root`` is the output root ``dest`` must stay inside. Checked here to fail before
    reading every input package, and again in ``_write_catalog_dir`` immediately before
    the wipe — that second one is authoritative, so the guard holds even for a future
    caller that reaches the writer by another route (issue #1972).
    """
    _require_contained(root, dest)
    entries: list[tuple[Path, dict]] = [(p, read_compact_manifest(p)) for p in sorted(set(pkg_paths))]
    for path, manifest in entries:
        _validate_annotated_project_pkg(path, manifest)
    _check_collisions(entries)
    for path, manifest in entries:
        _require_wildcard_abi(path, manifest.get("abi"), route_only=route_only)
    items: dict[tuple[str, str], tuple[Path, dict]] = {}
    for path, manifest in entries:
        nv = (manifest["name"], manifest["version"])
        if nv in items:
            sys.stderr.write(f"==> dedup: {path.name} duplicates {items[nv][0].name} ({nv[0]}-{nv[1]})\n")
            continue
        items[nv] = (path, manifest)
    return _write_catalog_dir(dest, items, root=root, sign_key=sign_key)


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


def _retention_channel(path: Path, manifest: Mapping[str, object]) -> str:
    """Return a package's retention bucket from provenance, with native fallback."""
    record = _canonical_build_record(path, manifest)
    if record is not None:
        channel = record["channel"]
        if channel == "stable":
            return "stable"
        if channel == "nightly":
            return "nightly"
        if channel == "edge":
            return "edge"
        if channel == "testing":
            return "testing"
        raise BuildRepoError(f"{path.name}: unsupported retention channel {channel!r}")

    name = manifest.get("name")
    if isinstance(name, str):
        if name.endswith("-nightly"):
            return "nightly"
        if name.endswith("-devel"):
            raise BuildRepoError(f"{path.name}: legacy -devel package identity is unsupported; use -testing")
        if name.endswith("-testing"):
            return "testing"
        if name.endswith("-edge"):
            return "edge"
    return "stable"


def _canonical_build_record(path: Path, manifest: Mapping[str, object]) -> dict[str, object] | None:
    """Load a canonical package's optional provenance annotation, if present."""
    name = manifest.get("name")
    if name != CANONICAL_EMITTED_IDENTITY:
        return None
    annotations = manifest.get("annotations")
    if annotations is not None and not isinstance(annotations, Mapping):
        raise BuildRepoError(f"{path.name}: annotations must be an object")
    annotation = annotations.get(PFB_BUILD_RECORD_KEY) if isinstance(annotations, Mapping) else None
    if annotation is None:
        # Native stable artifacts predate the provenance annotation.
        return None
    if not isinstance(annotation, str):
        raise BuildRepoError(f"{path.name}: {PFB_BUILD_RECORD_KEY} annotation must be JSON text")
    if not annotation.lstrip().startswith("{"):
        raise BuildRepoError(f"{path.name}: {PFB_BUILD_RECORD_KEY} annotation must be a JSON object")
    try:
        return load_build_record(annotation)
    except (PkgError, TypeError, ValueError) as exc:
        raise BuildRepoError(f"{path.name}: invalid {PFB_BUILD_RECORD_KEY} annotation: {exc}") from None


def _validate_annotated_project_pkg(path: Path, manifest: Mapping[str, object]) -> None:
    """Require full archive validation for canonical packages carrying provenance."""
    record = _canonical_build_record(path, manifest)
    if record is None:
        return
    try:
        validate_project_pkg(path, record)
    except (PkgError, OSError, TypeError, ValueError) as exc:
        raise BuildRepoError(f"{path.name}: project package validation failed: {exc}") from None


def retain_by_channel(
    pkg_paths: list[Path],
    *,
    keep_testing: int,
    keep_stable: int,
) -> list[Path]:
    """Bucket paths by package provenance/name and keep the newest ``keep_*`` per channel,
    PLUS the newest package of every major/minor line (the "line pin").

    Canonical project packages use their validated ``pfb_build_record`` annotation:
      * ``stable`` → stable channel
      * ``testing`` → testing retention bucket
      * ``edge``/``nightly`` → untouched channels
    Native packages fall back to manifest-name suffixes (``-testing``, ``-edge``,
    ``-nightly``); legacy ``-devel`` identities are rejected and an unsuffixed native package
    is stable. Filenames are never
    consulted. Edge and nightly are passthrough channels because no retention limit exists
    for either one.

    Pruning rules (reuses ``_retain_newest`` for version-sorted ordering):
      * ``keep == 0`` → keep ALL of that channel (the "unbounded / disabled" sentinel).
      * ``keep >= len(bucket)`` → keep all (no-op).
      * ``keep < len(bucket)`` → prune to the ``keep`` newest, THEN union in each
        major/minor line's newest package (``_line_pins``) that isn't already in that
        window — e.g. an aged-out v3.2.15 stays available after newer lines push it
        out of the rolling window. Pins are per-channel: a testing pin can never satisfy
        stable or vice versa. A malformed version in a bucket that needs pruning raises
        ``BuildRepoError`` (fail closed, never silently misbucketed or dropped).

    ``keep_testing`` / ``keep_stable`` must be ``>= 0``; a negative value is rejected (it would
    otherwise flow into ``_retain_newest``'s ``[:keep]`` slice and silently drop the newest
    builds — fail fast instead).

    Returns the kept paths in a deterministic stable order (testing first, then stable, edge,
    and nightly; within each pruned bucket the window newest-first, then any line pins
    newest-first).
    """
    if keep_testing < 0 or keep_stable < 0:
        raise BuildRepoError(
            f"release keep values must be >= 0 (got keep_testing={keep_testing}, keep_stable={keep_stable})"
        )

    _check_collisions([(path, read_compact_manifest(path)) for path in sorted(set(pkg_paths))])

    testing: list[Path] = []
    stable: list[Path] = []
    edge: list[Path] = []
    nightly: list[Path] = []

    for p in pkg_paths:
        m = read_compact_manifest(p)
        channel = _retention_channel(p, m)
        if channel == "nightly":
            nightly.append(p)
        elif channel == "testing":
            testing.append(p)
        elif channel == "edge":
            edge.append(p)
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

    kept_testing = _prune(testing, keep_testing)
    kept_stable = _prune(stable, keep_stable)
    # Edge and nightly are left untouched (no retention limits for either channel).
    return kept_testing + kept_stable + edge + nightly


BuildRecordInput = str | Path | Mapping[str, object]


def _load_build_record_input(source: BuildRecordInput) -> tuple[dict[str, object], str]:
    """Load one normalized record and retain the exact source passed downstream."""
    try:
        if isinstance(source, Mapping):
            record = validate_build_record(dict(source))
            forwarded = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        else:
            record = load_build_record(source)
            forwarded = str(source)
    except (PkgError, OSError, TypeError, ValueError) as exc:
        raise BuildRepoError(f"invalid normalized build record {source!r}: {exc}") from None
    return record, forwarded


def _load_build_records(inputs: list[BuildRecordInput] | None) -> dict[tuple[str, str], tuple[dict[str, object], str]]:
    """Load normalized records and index them by their route and channel.

    The record is forwarded to the package builder using its original path/text where
    possible.  A mapping supplied by a programmatic caller is serialized once so the
    subprocess receives the same validated bytes represented by the caller.
    """
    indexed: dict[tuple[str, str], tuple[dict[str, object], str]] = {}
    for source in inputs or []:
        record, forwarded = _load_build_record_input(source)
        route = record.get("route")
        channel = record.get("channel")
        if not isinstance(route, str) or not isinstance(channel, str):
            raise BuildRepoError(f"normalized build record {source!r} has no route/channel")
        key = (route, channel)
        if key in indexed:
            raise BuildRepoError(f"duplicate normalized build record for route {route!r} and channel {channel!r}")
        indexed[key] = (record, forwarded)
    return indexed


def _subprocess_pkg_builder(
    channel: str,
    *,
    abi: str,
    php: str,
    py_flavor: str,
    variant: str | None = None,
    build_record: str | Path | Mapping[str, object] | None = None,
    out_dir: Path,
    ports: Path | None = None,
    local_src: Path | None = None,
    pkgversion: str | None = None,
    annotate: dict[str, str] | None = None,
    **_ignored: object,
) -> Path:
    """Default builder: drive build-pkg-portable.py to produce ONE .pkg, return its path."""
    if channel not in ("stable", "testing", "edge", "nightly"):
        raise BuildRepoError(f"default package builder requires a supported channel, got {channel!r}")
    if not variant:
        raise BuildRepoError(f"default package builder requires --variant for {channel!r}; pass the matrix row variant")
    if build_record is None:
        raise BuildRepoError(
            f"default package builder requires a normalized --build-record for {channel!r}; "
            "the caller must supply one record per build route"
        )
    if not pkgversion:
        raise BuildRepoError(
            f"default package builder requires canonical --pkgversion for {channel!r}; "
            "use the normalized build record's canonical_package_version"
        )
    record, forwarded = _load_build_record_input(build_record)
    try:
        record = validate_build_record(record, abi=abi, php_version=php, py_flavor=py_flavor)
    except PkgError as exc:
        raise BuildRepoError(f"invalid normalized build record for {channel!r}: {exc}") from None
    if record.get("channel") != channel:
        raise BuildRepoError(f"normalized build record channel {record.get('channel')!r} does not match {channel!r}")
    row = record.get("matrix_row")
    if not isinstance(row, Mapping) or row.get("variant") != variant:
        raise BuildRepoError(
            f"normalized build record variant {row.get('variant') if isinstance(row, Mapping) else None!r} "
            f"does not match {variant!r}"
        )
    record_pkgversion = record.get("canonical_package_version")
    emitted_identity = record.get("emitted_identity")
    if not isinstance(record_pkgversion, str) or not isinstance(emitted_identity, str):
        raise BuildRepoError("normalized build record lacks canonical package identity/version")
    if record_pkgversion != pkgversion:
        raise BuildRepoError(
            f"canonical --pkgversion {pkgversion!r} does not match normalized record {record_pkgversion!r}"
        )
    expected = out_dir / f"{emitted_identity}-{record_pkgversion}.pkg"
    record_arg = forwarded
    cmd = [
        sys.executable, str(_BUILD_PKG),
        "--channel", channel,
        "--variant", variant,
        "--abi", abi,
        "--php", php,
        "--py-flavor", py_flavor,
        "--out", str(out_dir),
        "--build-record", record_arg,
    ]  # fmt: skip
    if ports is not None:
        cmd += ["--ports", str(ports)]
    if local_src is not None:
        cmd += ["--local-src", str(local_src)]
    if pkgversion is not None:
        cmd += ["--pkgversion", pkgversion]
    for k, v in (annotate or {}).items():
        cmd += ["--annotate", f"{k}={v}"]
    subprocess.run(cmd, check=True)
    if not expected.is_file():
        raise BuildRepoError(f"builder produced no expected .pkg at {expected} (channel={channel}, abi={abi})")
    return expected


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
    release_keep_testing: int = 1,
    release_keep_stable: int = 1,
    release_extra_pkgs: list[Path] | None = None,
    route_only_pkgs: dict[str, list[Path]] | None = None,
    release_pkgs: dict[str, list[Path]] | None = None,
    dep_pkgs: list[Path] | None = None,
    build_records: list[BuildRecordInput] | None = None,
    sign_key: Path | None = None,
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

      * RELEASE subtree ``release/<varver>/`` — the testing and edge .pkgs, plus the stable
        .pkg built from ``stable_tag`` (skipped when no stable tag exists), optionally
        folded with pre-built older-release .pkg from ``release_extra_pkgs``, pruned to
        the ``release_keep_testing`` newest testing + ``release_keep_stable`` newest stable.
        Defaults (1/1) reproduce today's latest-only behaviour; setting higher values
        retains older artifacts in the catalog for diagnostics and reproducibility.
      * NIGHTLY subtree ``nightly/<varver>/`` — the freshly built nightly folded in
        with any pre-existing nightlies in that subtree (cache-restored by the caller),
        pruned to the ``nightly_keep`` newest. Skipped when ``build_nightly`` is False.
    **route-only entries** (``role == "route-only"`` — EOL versions served from frozen .pkg):

      * NO builder call for a fresh testing-HEAD .pkg — the version is EOL, no new build.
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
      rebuilding testing/stable from source for build-entry matrix rows:
      ``dict[varver, list[Path]]`` mapping ``catalog_name_from_version()`` keys to lists
      of pre-built Release .pkg paths (e.g. all assets downloaded from GitHub Releases
      by publish.yml). When provided, the ``release/<varver>/`` catalog is SERVED
      from these (matched by OS+major via ``_pkg_matches_abi``, then pruned by
      ``retain_by_channel`` with ``release_keep_testing`` / ``release_keep_stable``)
      instead of calling the builder for testing/stable. ``release_extra_pkgs`` is
      still folded in after the pool.
      An empty pool for a varver skips that release catalog with a warning
      (no exception raised — a newly-added version with no Release asset yet simply has
      no release-channel package until the next release covers it; nightly still covers
      it from HEAD). Nightly is unaffected — the nightly subtree is always built from
      source when ``build_nightly`` is True, regardless of ``release_pkgs``.
      When ``None`` (the default), the existing build-from-source path is used unchanged.

    ``dep_pkgs`` (optional, issue #1806 / #2403) — pre-built dependency .pkg files
      (e.g. py311-charset-normalizer, built by build-dep-pkg-portable.py) folded
      into BOTH the release AND nightly catalogs of every build-role matrix entry
      whose ABI matches (OS+major; see ``_pkg_matches_abi`` — a NO_ARCH dep's abi
      is CPU-wildcarded) AND whose ``extra_pkgs`` declares the dep's origin (same
      ``_row_declares_origin`` rule as ``publish_release`` / ``publish_nightly`` —
      same-major ABI is not enough). Folded AFTER retention
      (``retain_by_channel`` / ``_retain_newest``) — NEVER before, or a dep would
      compete with real releases/nightlies for a retention slot. Route-only
      (frozen EOL) entries never receive a dep pkg. A dep pkg that ABI-matches
      and is declared by no catalog it actually landed in is a hard
      ``BuildRepoError`` (fail loud, never a silent drop) — matched is tracked only
      at the point a dep is folded into an EMITTED catalog, never merely because its
      ABI matched a row (issue #1806 gate-A finding: a matched-but-unemitted dep must
      still raise).

    ``builder`` is injectable (tests pass a stub); the default drives build-pkg-portable.py.
    Default builds require one validated normalized record per emitted channel route; pass
    those paths through ``build_records``. Extra ``builder_kwargs`` pass through to every
    builder call. Returns a summary dict.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    built: list[str] = []
    record_index = _load_build_records(build_records)
    use_default_builder = builder is _subprocess_pkg_builder

    def _record_for(entry: dict, varver: str, channel: str) -> tuple[dict[str, object], str] | None:
        key = (f"{channel}/{varver}", channel)
        found = record_index.get(key)
        if found is None:
            if use_default_builder:
                raise BuildRepoError(
                    f"default package builder requires normalized build record for {key[0]!r}; "
                    "supply one via --build-record PATH (one record per channel route)"
                )
            return None
        record, forwarded = found
        if record.get("matrix_row") != {key: value for key, value in entry.items() if key != "arch"}:
            raise BuildRepoError(
                f"normalized build record {key[0]!r} matrix_row does not exactly match the supplied BUILD row"
            )
        if record.get("channel") != channel:
            raise BuildRepoError(f"normalized build record {key[0]!r} channel does not match requested {channel!r}")
        return record, forwarded

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
        common = dict(
            abi=abi,
            php=php,
            py_flavor=py_flavor,
            variant=variant,
            varver=varver,
            arch=arch,
            **builder_kwargs,
        )

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
            n_release = _emit_catalog_from_paths(release_dir, frozen, root=out_dir, route_only=True, sign_key=sign_key)
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
            dep_for_abi = [
                p for p, m in dep_entries if _pkg_matches_abi(m, abi) and _row_declares_origin(entry, m.get("origin"))
            ]

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
                    keep_testing=release_keep_testing,
                    keep_stable=release_keep_stable,
                )
                if kept_release:
                    # dep_for_abi folds in AFTER retention (never competes for a slot).
                    n_release = _emit_catalog_from_paths(
                        release_dir, kept_release + dep_for_abi, root=out_dir, sign_key=sign_key
                    )
                    built.append(str(release_dir))
                    sys.stderr.write(f"==> release catalog {release_dir} ({n_release} package(s), consumed)\n")
                    dep_pkgs_matched.update(dep_for_abi)
                else:
                    sys.stderr.write(f"==> WARNING: no Release .pkg for {varver} {abi} — release catalog skipped\n")
            else:
                # --- source-build mode: testing + edge + (optional) stable + extras ---
                # The freshly built testing and edge (+ stable when a stable_tag exists) are always present.
                # release_extra_pkgs supplies pre-built older releases (e.g. downloaded from GitHub
                # Releases by publish.yml); together they form the full candidate pool, pruned via
                # retain_by_channel to keep the newest release_keep_testing testing + release_keep_stable
                # stable versions. Defaults of 1/1 reproduce today's latest-only behaviour.
                with tempfile.TemporaryDirectory() as td:
                    staging = Path(td)
                    testing_record = _record_for(entry, varver, "testing")
                    testing_kwargs = dict(common)
                    if testing_record is not None:
                        record, forwarded = testing_record
                        testing_kwargs.update(
                            build_record=forwarded,
                            pkgversion=record["canonical_package_version"],
                        )
                    built_pkgs: list[Path] = [
                        builder("testing", out_dir=staging, ports=ports, local_src=local_src, **testing_kwargs)
                    ]
                    if stable_tag:
                        stable_record = _record_for(entry, varver, "stable")
                        stable_kwargs = dict(common)
                        if stable_record is not None:
                            record, forwarded = stable_record
                            source_tag = record.get("source_tag")
                            if source_tag != stable_tag:
                                raise BuildRepoError(
                                    f"stable_tag {stable_tag!r} does not match normalized record source_tag "
                                    f"{source_tag!r} for {varver!r}"
                                )
                            stable_kwargs.update(
                                build_record=forwarded,
                                pkgversion=record["canonical_package_version"],
                            )
                        built_pkgs.append(
                            builder(
                                "stable",
                                out_dir=staging,
                                ports=ports,
                                local_src=stable_src or local_src,
                                **stable_kwargs,
                            )
                        )
                    edge_record = _record_for(entry, varver, "edge")
                    edge_kwargs = dict(common)
                    if edge_record is not None:
                        record, forwarded = edge_record
                        edge_kwargs.update(
                            build_record=forwarded,
                            pkgversion=record["canonical_package_version"],
                        )
                    built_pkgs.append(
                        builder(
                            "edge",
                            out_dir=staging,
                            ports=ports,
                            local_src=local_src,
                            **edge_kwargs,
                        )
                    )
                    # Fold in pre-built older-release candidates (caller-provided, e.g. from GitHub
                    # Releases), matched by OS+major (see _pkg_matches_abi).
                    extras = [p for p in (release_extra_pkgs or []) if _pkg_matches_abi(read_compact_manifest(p), abi)]
                    all_release_pkgs = built_pkgs + extras
                    kept_release = retain_by_channel(
                        all_release_pkgs,
                        keep_testing=release_keep_testing,
                        keep_stable=release_keep_stable,
                    )
                    # dep_for_abi folds in AFTER retention (never competes for a slot).
                    n_release = _emit_catalog_from_paths(
                        release_dir, kept_release + dep_for_abi, root=out_dir, sign_key=sign_key
                    )
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
                    nightly_record = _record_for(entry, varver, "nightly")
                    nightly_kwargs = dict(common)
                    pkgver = nightly_pkgversion(entry) if nightly_pkgversion else None
                    if nightly_record is not None:
                        record, forwarded = nightly_record
                        record_pkgver = record["canonical_package_version"]
                        if pkgver is not None and pkgver != record_pkgver:
                            raise BuildRepoError(
                                f"nightly pkgversion {pkgver!r} does not match normalized record "
                                f"{record_pkgver!r} for {varver!r}"
                            )
                        pkgver = record_pkgver
                        nightly_kwargs.update(build_record=forwarded)
                    new_nightly = builder(
                        "nightly",
                        out_dir=staging,
                        ports=ports,
                        local_src=local_src,
                        pkgversion=pkgver,
                        **nightly_kwargs,
                    )
                    kept = _retain_newest([*existing, new_nightly], nightly_keep)
                    # dep_for_abi folds in AFTER retention here too — the SAME dep pkg
                    # belongs in both the release and nightly catalogs of this ABI train.
                    n = _emit_catalog_from_paths(nightly_dir, kept + dep_for_abi, root=out_dir, sign_key=sign_key)
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


def _is_signed_host(base_url: str) -> bool:
    """Whether *base_url* is the host whose catalogues our signing key signs.

    A fork base (gen_landing.write_site bakes one) serves a catalogue our key never
    touched, so pinning our fingerprint to it would leave that fork unusable.
    """
    for scheme in ("https://", "http://"):
        prefix = scheme + REPO_HOST
        if base_url == prefix or base_url.startswith(prefix + "/"):
            return True
    return False


# Where the client keeps the trusted fingerprint(s) of the catalogue signing key. The
# rc.d hook writes `<dir>/trusted/<name>`; `pkg` also reads `<dir>/revoked/`.
CONF_FINGERPRINT_DIR = "/usr/local/etc/pkg/fingerprints/pfblockerng"


def _conf_signature_lines(url: str) -> str:
    """The signature fields for *url*. Only our own host's catalogues are signed."""
    if not _is_signed_host(url):
        return "  signature_type: none,\n"
    return f'  signature_type: fingerprints,\n  fingerprints: "{CONF_FINGERPRINT_DIR}",\n'


def _conf_trust_comment(url: str) -> str:
    if not _is_signed_host(url):
        return "# Unsigned catalogue: this base is not the signed project host.\n"
    return (
        "# Signed catalogue (issue #2675): the trust anchor is our own ECDSA key, whose\n"
        "# fingerprint the boot rc.d hook installs; the fetch is plain HTTP because pkg's\n"
        "# CA store is Netgate-pinned on pfSense Plus and unreachable from the GUI.\n"
    )


def print_conf(resolved_url: str, *, channel: str = "release") -> None:
    """Emit the repo-conf stanza for ``channel`` (default: the legacy release channel).

    ``resolved_url`` is the fully-resolved URL for the box's edition/version
    (ADR-39; arch-less since issue #1806 — the catalog is NO_ARCH):
    ``<base>/<channel>/<varver>`` — no ``${ABI}`` token.
    Supply ``--catalog-path <varver>`` so tests can pin the exact bytes.
    """
    url = resolved_url.rstrip("/")
    repo_name = _CHANNEL_REPO_NAMES[channel]
    # install.sh --channel rejects "release" (issue #2384) — the legacy release
    # default's hint keeps a literal <channel> placeholder instead of naming a
    # channel install.sh refuses.
    channel_hint = "<channel>" if channel == "release" else channel
    sys.stdout.write(
        f"# Generated at boot by pfblockerng_repo_generate (ADR-39) — do not edit;"
        f" re-run install.sh --channel {channel_hint} to change.\n"
        f"# pfBlockerNG ({channel} channel) — self-hosted pkg repository (ADR-17).\n"
        + _conf_trust_comment(url)
        + "# The URL is fully resolved for this box's edition/version (ADR-39; arch-less/NO_ARCH,\n"
        "# issue #1806); the boot rc.d hook updates it on a pfSense OS upgrade.\n"
        f"# priority {CONF_PRIORITY} sits above the base Netgate `pfSense` repo so cross-repo\n"
        "# resolution (pkg install/upgrade, GUI Install) selects the pfBlockerNG build.\n"
        f"{repo_name}: {{\n"
        f'  url: "{url}",\n'
        "  mirror_type: none,\n" + _conf_signature_lines(url) + f"  priority: {CONF_PRIORITY},\n"
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
            "  # print the client repo-conf (the README reuses it)\n"
            "  build-repo-portable.py --print-conf --base-url https://example.github.io/pkg\n\n"
            "  # matrix-driven: build the full variant tree, arch-less (ADR-20; issue #1806)\n"
            "  read-version-matrix.sh --print-build | build-repo-portable.py --build-matrix \\\n"
            "    --matrix-json - --out ./site --ports ./ports --local-src . \\\n"
            "    --nightly-pkgversion 20260615153045.<7-character-source-sha>\n"
        ),
    )
    ap.add_argument("--in", dest="in_dir", help="directory holding the input .pkg files (searched, non-recursive)")
    ap.add_argument("--out", dest="out_dir", help="output root; the flat, arch-less catalog is written directly here")
    ap.add_argument("--print-conf", action="store_true", help="print the client repo-conf template to stdout and exit")
    ap.add_argument(
        "--sign-key",
        default="",
        dest="sign_key",
        help=(
            "ECDSA private key (PEM) to sign each catalogue with, for a client conf using "
            "signature_type: fingerprints (issue #2675). Omitted = unsigned catalogues, "
            "which is what local and offline (file://) catalogues want. pkg accepts only "
            "secp256k1/secp384r1/secp521r1 and the brainpool curves — NOT prime256v1."
        ),
    )
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
            "The emitted URL is <base-url>/<channel>/<catalog-path>; a base URL already "
            "ending in a channel is accepted as that selected channel root. "
            "Required for byte-identical output across all four generators."
        ),
    )
    ap.add_argument(
        "--channel",
        choices=["stable", "testing", "edge", "nightly"],
        default=None,
        dest="channel",
        help=(
            "catalogue channel for --print-conf (stable|testing|edge|nightly); default "
            "is the legacy release channel (repo `pfblockerng`, carries both stable+devel). "
            "All four channels resolve to the ONE canonical pfSense-pkg-pfBlockerNG package."
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
        help="pkg-safe nightly version YYYYMMDDHHMMSS.<7-character source SHA> applied to every nightly build",
    )
    g_matrix.add_argument("--no-nightly", action="store_true", help="skip the nightly subtree (release + routing only)")
    g_matrix.add_argument(
        "--release-keep-testing",
        type=_non_negative_int,
        default=1,
        dest="release_keep_testing",
        help=(
            "testing releases retained per varver in the release catalog (default 1 = latest-only). "
            "Set >1 to retain multiple testing artifacts for diagnostics and reproducibility. "
            "The publish job must supply the older .pkg via --release-extra-pkgs. "
            "The newest package of every major/minor line is pinned on top of this window, "
            "so the catalog can hold more than N testing packages."
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
            "Pruned by --release-keep-testing / --release-keep-stable after folding."
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
        "--build-record",
        action="append",
        default=[],
        dest="build_records",
        metavar="PATH",
        help=(
            "normalized #2142 build record JSON file for a source-built channel route "
            "(repeatable; one record per stable/testing/edge/nightly route)"
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
            "When supplied, testing+stable are consumed from these instead of rebuilt from source. "
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
        _parts = urllib.parse.urlsplit(_base)
        _parent, _sep, _selected = _parts.path.rpartition("/")
        if _sep and _selected in _CHANNEL_REPO_NAMES and args.channel in {None, _selected}:
            _base = urllib.parse.urlunsplit(_parts._replace(path=_parent))
            _channel = _selected
        else:
            _channel = args.channel or "release"
        print_conf(f"{_base}/{_channel}/{_cat}", channel=_channel)
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
        build_records_arg = [Path(p) for p in args.build_records] if args.build_records else None
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
                release_keep_testing=args.release_keep_testing,
                release_keep_stable=args.release_keep_stable,
                release_extra_pkgs=extra_pkgs,
                dep_pkgs=dep_pkgs_arg,
                build_records=build_records_arg,
                route_only_pkgs=route_only,
                release_pkgs=release_pkgs_arg,
                annotate=annotate or None,
                sign_key=Path(args.sign_key) if args.sign_key else None,
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
        abis = build_repo(
            in_dir,
            Path(args.out_dir),
            catalog_name=args.catalog_name,
            sign_key=Path(args.sign_key) if args.sign_key else None,
        )
    except (BuildRepoError, PkgError) as e:
        sys.stderr.write(f"build-repo-portable: {e}\n")
        return 1
    sys.stderr.write(f"==> built catalog for ABI: {' '.join(abis)}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
