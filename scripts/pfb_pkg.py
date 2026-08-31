"""Shared libpkg .pkg helpers — zstd framing + the +COMPACT_MANIFEST reader.

A libpkg .pkg is a zstd-compressed tar whose first member is +COMPACT_MANIFEST,
the package metadata. Scripts/build-repo-portable.py reads those manifests
off-FreeBSD through this single implementation. Direct script execution puts
scripts/ on sys.path, so ``import pfb_pkg`` resolves here.

stdlib-only, with an optional fast path: the `zstandard` module if installed,
else the `zstd` binary.
"""

from __future__ import annotations

import hashlib
import io
import json
import lzma
import posixpath
import re
import shlex
import shutil
import subprocess
import tarfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Mapping

try:
    from scripts.release_version import parse_release_tag, validate_nightly_version
except ImportError:  # script directory is also a direct import root
    from release_version import parse_release_tag, validate_nightly_version

ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
XZ_MAGIC = b"\xfd7zXZ\x00"
CANONICAL_EMITTED_IDENTITY = "pfSense-pkg-pfBlockerNG"
PFB_BUILD_RECORD_KEY = "pfb_build_record"
_RECORD_FIELDS = {
    "schema",
    "channel",
    "release_line",
    "classification",
    "source_tag",
    "source_sha",
    "canonical_package_version",
    "native_recipe_identity",
    "emitted_identity",
    "matrix_row",
    "freebsd_ports_sha",
    "route",
    "source_date_epoch",
    "dependency_builder",
    "build_input_digest",
}
_RECORD_SHA = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_RECORD_PORTS_SHA = re.compile(r"^[0-9a-f]{40}$")
_RECORD_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_DEPENDENCY_BUILDER_FIELDS = {"python", "pip", "setuptools", "wheel", "zstandard", "uv", "uv_lock_sha256"}
_TOOL_VERSION = re.compile(r"^[0-9]+(?:\.[0-9]+)+(?:[A-Za-z0-9._+-]*)?$")
_VARIANT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
_PF_VERSION = re.compile(r"^[0-9]+(?:\.[0-9]+)+$")
_MATRIX_FIELDS = {
    "pfsense_version",
    "channel",
    "freebsd_version",
    "freebsd_major",
    "php_version",
    "py_flavor",
    "variant",
    "status",
    "extra_pkgs",
}
_MATRIX_OPTIONAL_FIELDS = {"image_name", "upgrade", "role", "last_tag"}
_MATRIX_ORIGIN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+_.-]*/[A-Za-z0-9][A-Za-z0-9+_.-]*$")
_MATRIX_FREEBSD_VERSION = re.compile(r"^[0-9]+\.[0-9]+-[A-Za-z0-9][A-Za-z0-9._-]*$")
_MATRIX_PHP_VERSION = re.compile(r"^[0-9]+\.[0-9]+$")
_MATRIX_PY_FLAVOR = re.compile(r"^py[0-9]+$")
_MATRIX_IMAGE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_HOOK_UNPREFIXED = ("/usr/local/bin/php", "-f", "/etc/rc.packages", CANONICAL_EMITTED_IDENTITY, "${2}")
_HOOK_PREFIXED = (
    "${PKG_ROOTDIR}/usr/local/bin/php",
    "-f",
    "${PKG_ROOTDIR}/etc/rc.packages",
    CANONICAL_EMITTED_IDENTITY,
    "${2}",
)
_DEP_PHP = re.compile(r"^php[0-9]+(?:[-+_.].*)?$")
_DEP_PYTHON = re.compile(r"^python[0-9]+(?:[-+_.].*)?$")
_DEP_PY_FLAVOR = re.compile(r"^py[0-9]+-")
_INFO_PATH = "/usr/local/share/pfSense-pkg-pfBlockerNG/info.xml"


class PkgError(Exception):
    """A .pkg could not be read (no zstd decoder available, or malformed)."""


def _json_safe(value: object, *, path: str = "$") -> None:
    if isinstance(value, float):
        raise PkgError(f"{path}: floating point values are not allowed")
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, list):
        for i, item in enumerate(value):
            _json_safe(item, path=f"{path}[{i}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise PkgError(f"{path}: JSON object keys must be strings")
            _json_safe(item, path=f"{path}.{key}")
        return
    raise PkgError(f"{path}: unsupported JSON type {type(value).__name__}")


def _canonical_json(value: object) -> str:
    _json_safe(value)
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise PkgError(f"invalid JSON value: {exc}") from None


def validate_dependency_builder(value: object) -> dict[str, str]:
    """Validate the immutable Python/wheel tool contract carried by release records."""
    if not isinstance(value, dict) or set(value) != _DEPENDENCY_BUILDER_FIELDS:
        raise _record_error("dependency_builder exact fields required")
    for name in _DEPENDENCY_BUILDER_FIELDS - {"uv_lock_sha256"}:
        version = value[name]
        if not isinstance(version, str) or not _TOOL_VERSION.fullmatch(version):
            raise _record_error(f"dependency_builder.{name} is malformed")
    lock_sha = value["uv_lock_sha256"]
    if not isinstance(lock_sha, str) or not _RECORD_DIGEST.fullmatch(lock_sha):
        raise _record_error("dependency_builder.uv_lock_sha256 must be lowercase SHA-256")
    return dict(value)


def build_input_digest(record: Mapping[str, object]) -> str:
    """Hash a normalized record without its self-referential digest field."""
    if not isinstance(record, Mapping):
        raise PkgError("build record must be an object")
    payload = {key: value for key, value in record.items() if key != "build_input_digest"}
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _record_error(message: str) -> PkgError:
    return PkgError(f"invalid build record: {message}")


def _require_string(record: Mapping[str, object], key: str) -> str:
    value = record.get(key)
    if not isinstance(value, str) or not value:
        raise _record_error(f"{key} must be a non-empty string")
    return value


def validate_build_matrix_row(row: Mapping[str, object]) -> dict[str, object]:
    """Validate one complete row emitted by ``read-version-matrix.sh --print-build``."""
    if not isinstance(row, dict):
        raise _record_error("matrix_row must be an object")
    _json_safe(row, path="$.matrix_row")
    keys = set(row)
    allowed = _MATRIX_FIELDS | _MATRIX_OPTIONAL_FIELDS
    missing = sorted(_MATRIX_FIELDS - keys)
    unknown = sorted(keys - allowed)
    if missing or unknown:
        raise _record_error(f"matrix_row exact fields required (missing={missing}, unknown={unknown})")

    text_fields = ("pfsense_version", "channel", "freebsd_version", "freebsd_major", "php_version", "py_flavor")
    for field in text_fields:
        value = row[field]
        if not isinstance(value, str) or not value:
            raise _record_error(f"matrix_row.{field} must be a non-empty string")
    if row["channel"] not in ("CE", "Plus"):
        raise _record_error("matrix_row.channel is invalid")
    if row["variant"] != row["channel"]:
        raise _record_error("matrix_row.variant must match channel")
    if not _PF_VERSION.fullmatch(row["pfsense_version"]):
        raise _record_error("matrix_row.pfsense_version is malformed")
    if not re.fullmatch(r"[0-9]+", row["freebsd_major"]):
        raise _record_error("matrix_row.freebsd_major is malformed")
    if not _MATRIX_FREEBSD_VERSION.fullmatch(row["freebsd_version"]):
        raise _record_error("matrix_row.freebsd_version is malformed")
    if row["freebsd_version"].split(".", 1)[0] != row["freebsd_major"]:
        raise _record_error("matrix_row.freebsd_version does not match freebsd_major")
    if not _MATRIX_PHP_VERSION.fullmatch(row["php_version"]):
        raise _record_error("matrix_row.php_version is malformed")
    if not _MATRIX_PY_FLAVOR.fullmatch(row["py_flavor"]):
        raise _record_error("matrix_row.py_flavor is malformed")
    if row["status"] not in ("active", "beta", "GA"):
        raise _record_error("matrix_row.status is invalid")

    extra_pkgs = row["extra_pkgs"]
    if not isinstance(extra_pkgs, list) or any(
        not isinstance(origin, str) or not _MATRIX_ORIGIN.fullmatch(origin) for origin in extra_pkgs
    ):
        raise _record_error("matrix_row.extra_pkgs must be a list of safe origins")
    if extra_pkgs != sorted(set(extra_pkgs)):
        raise _record_error("matrix_row.extra_pkgs must be sorted and unique")

    if "image_name" in row and (
        not isinstance(row["image_name"], str)
        or not row["image_name"]
        or not _MATRIX_IMAGE.fullmatch(row["image_name"])
    ):
        raise _record_error("matrix_row.image_name is malformed")
    if "role" in row and row["role"] != "build":
        raise _record_error("matrix_row.role must be build")
    if "last_tag" in row and (
        not isinstance(row["last_tag"], str)
        or not row["last_tag"]
        or len(row["last_tag"]) > 128
        or any(ord(char) < 0x20 or ord(char) == 0x7F for char in row["last_tag"])
    ):
        raise _record_error("matrix_row.last_tag is malformed")
    if "upgrade" in row:
        upgrade = row["upgrade"]
        if not isinstance(upgrade, dict):
            raise _record_error("matrix_row.upgrade must be an object")
        upgrade_keys = set(upgrade)
        if not upgrade_keys <= {"available", "branch", "target", "from"} or "available" not in upgrade:
            raise _record_error("matrix_row.upgrade has unknown or missing fields")
        if type(upgrade["available"]) is not bool:
            raise _record_error("matrix_row.upgrade.available must be boolean")
        for field in ("branch", "target", "from"):
            if field in upgrade and (not isinstance(upgrade[field], str) or not upgrade[field]):
                raise _record_error(f"matrix_row.upgrade.{field} must be a non-empty string")
    return dict(row)


def _route_for(record: Mapping[str, object]) -> str:
    row = record.get("matrix_row")
    if not isinstance(row, dict):
        raise _record_error("matrix_row must be an object")
    variant = row.get("variant")
    version = row.get("pfsense_version")
    if not isinstance(variant, str) or not _VARIANT.fullmatch(variant) or ".." in variant:
        raise _record_error("matrix_row.variant is unsafe")
    if not isinstance(version, str) or not _PF_VERSION.fullmatch(version):
        raise _record_error("matrix_row.pfsense_version is malformed")
    parts = version.split(".")
    return f"{record['channel']}/{variant.lower()}-{parts[0]}.{parts[1]}"


def validate_build_record(
    record: Mapping[str, object],
    *,
    abi: str | None = None,
    php_version: str | None = None,
    py_flavor: str | None = None,
) -> dict[str, object]:
    """Validate one strict, digest-bound normalized build record."""
    if not isinstance(record, dict):
        raise _record_error("record must be an object")
    _json_safe(record)
    keys = set(record)
    missing = sorted((_RECORD_FIELDS - {"dependency_builder"}) - keys)
    unknown = sorted(keys - _RECORD_FIELDS)
    if missing or unknown:
        raise _record_error(f"exact fields required (missing={missing}, unknown={unknown})")
    if type(record["schema"]) is not int or record["schema"] != 1:
        raise _record_error("schema must be integer 1")
    channel = record["channel"]
    if channel not in ("stable", "testing", "edge", "nightly"):
        raise _record_error("channel is invalid")
    row = validate_build_matrix_row(record["matrix_row"])
    if row["extra_pkgs"] and "dependency_builder" not in record:
        raise _record_error("dependency_builder is required when matrix_row.extra_pkgs is non-empty")
    if abi is not None:
        if not isinstance(abi, str) or not re.fullmatch(r"FreeBSD:[0-9]+:[A-Za-z0-9._+-]+", abi):
            raise _record_error("abi is malformed")
        if abi.split(":")[1] != row["freebsd_major"]:
            raise _record_error("matrix_row.freebsd_major does not match abi")
    if php_version is not None and row["php_version"] != php_version:
        raise _record_error("matrix_row.php_version does not match php_version")
    if py_flavor is not None and row["py_flavor"] != py_flavor:
        raise _record_error("matrix_row.py_flavor does not match py_flavor")

    source_sha = record["source_sha"]
    ports_sha = record["freebsd_ports_sha"]
    if not isinstance(source_sha, str) or not _RECORD_SHA.fullmatch(source_sha):
        raise _record_error("source_sha must be lowercase 40- or 64-character hex")
    if not isinstance(ports_sha, str) or not _RECORD_PORTS_SHA.fullmatch(ports_sha):
        raise _record_error("freebsd_ports_sha must be lowercase 40-character hex")
    epoch = record["source_date_epoch"]
    if type(epoch) is not int or epoch < 0:
        raise _record_error("source_date_epoch must be a non-negative integer")
    if "dependency_builder" in record:
        validate_dependency_builder(record["dependency_builder"])

    expected_recipe = CANONICAL_EMITTED_IDENTITY if channel == "stable" else f"{CANONICAL_EMITTED_IDENTITY}-{channel}"
    if record["emitted_identity"] != CANONICAL_EMITTED_IDENTITY or record["native_recipe_identity"] != expected_recipe:
        raise _record_error("package identities do not match channel")
    source_tag = record["source_tag"]
    version = record["canonical_package_version"]
    release_line = record["release_line"]
    classification = record["classification"]
    if not isinstance(version, str) or not isinstance(release_line, str) or not isinstance(classification, str):
        raise _record_error("version, release_line, and classification must be strings")
    if channel == "nightly":
        if source_tag is not None or not release_line or classification != "nightly":
            raise _record_error("nightly source/provenance fields are invalid")
        try:
            validate_nightly_version(version, source_sha=source_sha)
        except ValueError as exc:
            raise _record_error(str(exc)) from None
    else:
        if not isinstance(source_tag, str):
            raise _record_error("release source_tag must be a string")
        try:
            parsed = parse_release_tag(source_tag, channel)
        except (TypeError, ValueError) as exc:
            raise _record_error(str(exc)) from None
        if version != parsed.pkg_version or release_line != parsed.release_line or classification != parsed.stage:
            raise _record_error("release fields do not match source_tag")
    expected_route = _route_for(record)
    if record["route"] != expected_route:
        raise _record_error(f"route must be {expected_route!r}")
    digest = record["build_input_digest"]
    if not isinstance(digest, str) or not _RECORD_DIGEST.fullmatch(digest) or digest != build_input_digest(record):
        raise _record_error("build_input_digest is not the canonical digest")
    validated = dict(record)
    validated["matrix_row"] = row
    return validated


def _load_json_object(raw: bytes, what: str) -> dict[str, object]:
    try:
        value = json.loads(raw, object_pairs_hook=_reject_duplicate_json_keys)
    except (TypeError, ValueError, UnicodeError) as exc:
        raise PkgError(f"{what} is not valid JSON: {exc}") from None
    if not isinstance(value, dict):
        raise PkgError(f"{what} is not an object")
    return value


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key {key!r}")
        value[key] = item
    return value


def load_build_record(source: str | Path) -> dict[str, object]:
    """Load and validate one build record from raw JSON or a path."""
    try:
        if isinstance(source, Path) or (isinstance(source, str) and not source.lstrip().startswith(("{", "["))):
            raw = Path(source).read_bytes()
        elif isinstance(source, str):
            raw = source.encode("utf-8")
        else:
            raise TypeError("source must be JSON text or a path")
    except (OSError, TypeError, UnicodeError) as exc:
        raise PkgError(f"cannot load build record: {exc}") from None
    return validate_build_record(_load_json_object(raw, "build record"))


def zstd_decompress(data: bytes) -> bytes:
    """Decompress a zstd frame. Non-zstd input is returned as-is (an already
    uncompressed tar — defensive). Prefers the `zstandard` module, falls back to
    the `zstd` binary; raises PkgError if neither is available."""
    if data[:4] != ZSTD_MAGIC:
        return data
    try:
        import zstandard
    except ImportError:
        pass
    else:
        try:
            return zstandard.ZstdDecompressor().stream_reader(io.BytesIO(data)).read()
        except Exception as exc:  # zstandard.ZstdError, and whatever it wraps
            # Normalised to PkgError exactly as the binary path's failure below is:
            # a caller that turns a read failure into a verdict must not answer
            # differently depending on which decoder the host happens to carry.
            raise PkgError(f"zstd decompression failed: {exc}") from None
    zstd = shutil.which("zstd")
    if not zstd:
        raise PkgError("a .pkg is zstd-compressed; install the `zstd` binary or the python `zstandard` module")
    try:
        return subprocess.run([zstd, "-dc"], input=data, stdout=subprocess.PIPE, check=True).stdout
    except subprocess.CalledProcessError as exc:
        raise PkgError(f"zstd decompression failed: {exc}") from None


def zstd_compress(data: bytes, err_cls: type[Exception], err_msg: str) -> bytes:
    """Compress a zstd frame at level 19. Prefers the `zstandard` module, falls
    back to the `zstd` binary; raises err_cls(err_msg) if neither is available
    (each caller owns its own error class + message)."""
    try:
        import zstandard

        return zstandard.ZstdCompressor(level=19).compress(data)
    except ImportError:
        pass
    zstd = shutil.which("zstd")
    if not zstd:
        raise err_cls(err_msg)
    return subprocess.run([zstd, "-q", "-19", "-c"], input=data, stdout=subprocess.PIPE, check=True).stdout


def read_compact_manifest(pkg_path: str | Path) -> dict:
    """Return the +COMPACT_MANIFEST JSON object of a .pkg (pure Python, no libpkg)."""
    pkg_path = Path(pkg_path)
    try:
        raw = pkg_path.read_bytes()
        tar_bytes = lzma.decompress(raw) if raw[:6] == XZ_MAGIC else zstd_decompress(raw)
        with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tf:
            try:
                member = tf.extractfile("+COMPACT_MANIFEST")
            except KeyError:
                member = None
            if member is None:
                raise PkgError(f"{pkg_path.name}: no +COMPACT_MANIFEST member — not a libpkg .pkg?")
            data = member.read()
        return _load_json_object(data, f"{pkg_path.name}: +COMPACT_MANIFEST")
    except PkgError:
        raise
    except (OSError, EOFError, lzma.LZMAError, tarfile.TarError, ValueError) as exc:
        raise PkgError(f"{pkg_path.name}: invalid package archive: {exc}") from None


def _archive_tar(path: Path) -> tuple[bytes, list[tarfile.TarInfo]]:
    try:
        raw = path.read_bytes()
        if raw[:6] == XZ_MAGIC:
            raw = lzma.decompress(raw)
        else:
            raw = zstd_decompress(raw)
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tf:
            members = tf.getmembers()
            if [member.name for member in members[:2]] != ["+COMPACT_MANIFEST", "+MANIFEST"]:
                raise PkgError(f"{path.name}: manifests must be the first two archive members")
            seen: set[str] = set()
            for member in members:
                name = member.name
                if name in seen:
                    raise PkgError(f"{path.name}: duplicate archive member {name!r}")
                seen.add(name)
                if not name or "\\" in name or "\x00" in name:
                    raise PkgError(f"{path.name}: unsafe archive member {name!r}")
                pieces = name.split("/")
                if ".." in pieces or "." in pieces:
                    raise PkgError(f"{path.name}: unsafe archive member {name!r}")
                if name.startswith("+") and name not in ("+COMPACT_MANIFEST", "+MANIFEST"):
                    raise PkgError(f"{path.name}: unexpected metadata member {name!r}")
                if not name.startswith("+") and not name.startswith("/"):
                    raise PkgError(f"{path.name}: payload member must be absolute {name!r}")
                if not name.startswith("+") and (name == "/" or "" in pieces[1:] or posixpath.normpath(name) != name):
                    raise PkgError(f"{path.name}: unsafe archive member {name!r}")
                if not member.isreg():
                    raise PkgError(f"{path.name}: non-regular archive member {name!r}")
            return raw, members
    except PkgError:
        raise
    except (OSError, EOFError, lzma.LZMAError, tarfile.TarError, ValueError) as exc:
        raise PkgError(f"{path.name}: invalid package archive: {exc}") from None


def inspect_pkg(path: str | Path) -> dict[str, object]:
    """Strictly parse metadata and payload evidence from a libpkg archive."""
    pkg_path = Path(path)
    tar_raw, members = _archive_tar(pkg_path)
    by_name: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(tar_raw), mode="r:") as tf:
        for member in members:
            extracted = tf.extractfile(member)
            if extracted is None:
                raise PkgError(f"{pkg_path.name}: cannot read member {member.name!r}")
            by_name[member.name] = extracted.read()
    for metadata_name in ("+COMPACT_MANIFEST", "+MANIFEST"):
        if metadata_name not in by_name:
            raise PkgError(f"{pkg_path.name}: missing {metadata_name}")
    compact = _load_json_object(by_name["+COMPACT_MANIFEST"], f"{pkg_path.name}: +COMPACT_MANIFEST")
    manifest = _load_json_object(by_name["+MANIFEST"], f"{pkg_path.name}: +MANIFEST")
    payload = {name: data for name, data in by_name.items() if not name.startswith("+")}
    return {
        "path": pkg_path,
        "members": tuple(member.name for member in members),
        "compact_manifest": compact,
        "manifest": manifest,
        "payload": payload,
        "member_info": {member.name: member for member in members},
    }


def _manifest_annotation(manifest: Mapping[str, object], record: Mapping[str, object], pkg_name: str) -> None:
    annotations = manifest.get("annotations")
    if not isinstance(annotations, dict):
        raise PkgError(f"{pkg_name}: manifest annotations missing")
    expected = _canonical_json(record)
    if annotations.get(PFB_BUILD_RECORD_KEY) != expected:
        raise PkgError(f"{pkg_name}: {PFB_BUILD_RECORD_KEY} annotation mismatch")
    native_marker = f"{CANONICAL_EMITTED_IDENTITY}-"
    for key, value in annotations.items():
        if key != PFB_BUILD_RECORD_KEY and (native_marker in key or native_marker in _canonical_json(value)):
            raise PkgError(f"{pkg_name}: native identity leaked into annotation {key!r}")


def _check_script(script: object, pkg_name: str) -> None:
    if not isinstance(script, str):
        raise PkgError(f"{pkg_name}: install/deinstall script is not text")
    if not script.startswith("#!/bin/sh\n"):
        raise PkgError(f"{pkg_name}: lifecycle hook must use an exact #!/bin/sh shebang")
    commands: list[tuple[str, ...]] = []
    for line in script.splitlines():
        try:
            tokens = shlex.split(line, comments=True, posix=True)
        except ValueError as exc:
            raise PkgError(f"{pkg_name}: hook is not valid shell text: {exc}") from None
        if not tokens:
            continue
        if any(token.startswith(f"{CANONICAL_EMITTED_IDENTITY}-") for token in tokens):
            raise PkgError(f"{pkg_name}: hook contains a suffixed native identity")
        commands.append(tuple(tokens))
    allowed = (
        (_HOOK_UNPREFIXED,),
        (_HOOK_PREFIXED,),
        (
            ("if", "[", "${2}", "!=", "POST-INSTALL", "];", "then"),
            ("exit", "0"),
            ("fi",),
            _HOOK_PREFIXED,
        ),
    )
    if tuple(commands) not in allowed:
        raise PkgError(f"{pkg_name}: hook must invoke rc.packages {CANONICAL_EMITTED_IDENTITY}")


def validate_project_pkg(
    path: str | Path,
    expected_record: Mapping[str, object],
    expected_manifest: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Validate one canonical pfBlockerNG package against record and manifest evidence."""
    record = validate_build_record(expected_record)
    evidence = inspect_pkg(path)
    pkg_path = Path(path)
    compact = evidence["compact_manifest"]
    manifest = evidence["manifest"]
    payload = evidence["payload"]
    member_info = evidence["member_info"]
    if not isinstance(compact, dict) or not isinstance(manifest, dict) or not isinstance(payload, dict):
        raise PkgError(f"{pkg_path.name}: malformed inspection evidence")
    native_marker = f"{CANONICAL_EMITTED_IDENTITY}-"
    for name in payload:
        if any(native_marker in component for component in name.split("/")):
            raise PkgError(f"{pkg_path.name}: native identity leaked into payload path {name}")
    expected_name = f"{CANONICAL_EMITTED_IDENTITY}-{record['canonical_package_version']}"
    if pkg_path.name != expected_name + ".pkg":
        raise PkgError(f"{pkg_path.name}: filename must be {expected_name}.pkg")
    compact_from_full = {
        key: value for key, value in manifest.items() if key not in ("files", "directories", "scripts")
    }
    if compact != compact_from_full:
        raise PkgError(f"{pkg_path.name}: compact/full manifest mismatch")
    if expected_manifest is not None and manifest != dict(expected_manifest):
        raise PkgError(f"{pkg_path.name}: full manifest differs from expected manifest")
    if manifest.get("name") != CANONICAL_EMITTED_IDENTITY or manifest.get("origin") != "net/pfSense-pkg-pfBlockerNG":
        raise PkgError(f"{pkg_path.name}: canonical package identity/origin mismatch")
    if manifest.get("version") != record["canonical_package_version"]:
        raise PkgError(f"{pkg_path.name}: package version mismatch")
    major = record["matrix_row"]["freebsd_major"]
    if manifest.get("abi") != f"FreeBSD:{major}:*" or manifest.get("arch") != f"freebsd:{major}:*":
        raise PkgError(f"{pkg_path.name}: ABI/arch mismatch")
    _manifest_annotation(manifest, record, pkg_path.name)
    files = manifest.get("files")
    if not isinstance(files, dict) or set(files) != set(payload):
        raise PkgError(f"{pkg_path.name}: payload inventory differs from +MANIFEST files")
    for name, entry in files.items():
        if not isinstance(name, str) or not name.startswith("/") or not isinstance(entry, dict):
            raise PkgError(f"{pkg_path.name}: malformed file manifest entry {name!r}")
        data = payload[name]
        checksum = entry.get("sum")
        if not isinstance(checksum, str) or not re.fullmatch(r"1\$[0-9a-f]{64}", checksum):
            raise PkgError(f"{pkg_path.name}: malformed checksum for {name}")
        if checksum[2:] != hashlib.sha256(data).hexdigest():
            raise PkgError(f"{pkg_path.name}: checksum mismatch for {name}")
        member = member_info[name]
        try:
            mode = int(entry["perm"], 8)
            mtime = int(entry["mtime"])
        except (KeyError, TypeError, ValueError):
            raise PkgError(f"{pkg_path.name}: malformed mode/mtime for {name}") from None
        if member.mode != mode or int(member.mtime) != mtime or mtime != record["source_date_epoch"]:
            raise PkgError(f"{pkg_path.name}: mode/mtime mismatch for {name} (source_date_epoch)")
        if "size" in entry and (type(entry["size"]) is not int or entry["size"] != len(data)):
            raise PkgError(f"{pkg_path.name}: size mismatch for {name}")
    if _INFO_PATH not in payload or any(name.endswith("/info.xml") and name != _INFO_PATH for name in payload):
        raise PkgError(f"{pkg_path.name}: canonical package info.xml path missing or suffixed")
    try:
        root = ET.fromstring(payload[_INFO_PATH])
    except ET.ParseError as exc:
        raise PkgError(f"{pkg_path.name}: info.xml is not valid XML: {exc}") from None
    if root.findtext(".//name") != "pfBlockerNG" or root.findtext(".//version") != record["canonical_package_version"]:
        raise PkgError(f"{pkg_path.name}: info.xml name/version mismatch")
    scripts = manifest.get("scripts")
    if not isinstance(scripts, dict) or set(scripts) != {"install", "deinstall"}:
        raise PkgError(f"{pkg_path.name}: unexpected lifecycle scripts; require install/deinstall only")
    _check_script(scripts["install"], pkg_path.name)
    _check_script(scripts["deinstall"], pkg_path.name)
    deps = manifest.get("deps")
    if not isinstance(deps, dict):
        raise PkgError(f"{pkg_path.name}: dependency manifest missing")
    for name, dependency in deps.items():
        if (
            not isinstance(name, str)
            or not isinstance(dependency, dict)
            or not isinstance(dependency.get("origin"), str)
            or not isinstance(dependency.get("version"), str)
        ):
            raise PkgError(f"{pkg_path.name}: malformed dependency {name!r}")
        if CANONICAL_EMITTED_IDENTITY in name or CANONICAL_EMITTED_IDENTITY in dependency["origin"]:
            raise PkgError(f"{pkg_path.name}: native identity leaked into dependency {name!r}")
    row = record["matrix_row"]
    expected_php = "php" + row["php_version"].replace(".", "")
    py_digits = row["py_flavor"][2:] if row["py_flavor"].startswith("py") else row["py_flavor"]
    expected_python = "python" + py_digits
    php_deps = [name for name in deps if _DEP_PHP.fullmatch(name)]
    python_deps = [name for name in deps if _DEP_PYTHON.fullmatch(name) or _DEP_PY_FLAVOR.match(name)]
    if not php_deps or any(name != expected_php and not name.startswith(expected_php + "-") for name in php_deps):
        raise PkgError(f"{pkg_path.name}: PHP dependency flavor mismatch")
    if not python_deps or any(
        name != expected_python
        and not name.startswith(expected_python + "-")
        and not name.startswith(f"py{py_digits}-")
        for name in python_deps
    ):
        raise PkgError(f"{pkg_path.name}: Python dependency flavor mismatch")
    return {"record": record, "inspection": evidence}


# --------------------------------------------------------------------------- #
# Version sort key — shared by source package builds/retention and the pkg-owned
# landing renderer's "newest build" selection.
# --------------------------------------------------------------------------- #

# FreeBSD pkg ranks a prerelease stage BELOW the bare release, and alpha < beta <
# rc between themselves (see scripts/release_version.py, whose canonical tags use
# vX.Y.Z.aN|bN|rN). Retained legacy expanded package versions remain sortable.
# A version with no stage keyword —
# a genuine stable release, a bare edition version like "2.8.1", or a Nightly
# timestamp-plus-SHA version — ranks as RELEASE (highest).
_STAGE_RANK = {"alpha": 0, "beta": 1, "rc": 2}
_COMPACT_STAGE_RANK = {"a": 0, "b": 1, "r": 2}
_COMPACT_STAGE = re.compile(r"^([abr])([1-9][0-9]*)$", re.IGNORECASE)
_RELEASE_RANK = 3


def pkg_version_sort_key(version: str) -> tuple[list[int], int, int]:
    """Monotone sort key for a pfBlockerNG pkg VERSION string.

    Splits on ``.``/``_``/``,`` like a plain numeric-run compare, but a component
    matching a canonical compact prerelease (``aN``/``bN``/``rN``), or a retained
    legacy stage keyword (``alpha.N``/``beta.N``/``rc.N``), is pulled OUT of the
    numeric base and turned into a stage rank + number. The historical bug this
    fixes: a plain
    ``re.findall(r"\\d+", v)``-style key drops the keyword entirely, so
    ``4.0.0.alpha.1`` / ``.beta.1`` / ``.rc.1`` all collapsed to the SAME key, and
    the bare ``4.0.0`` release (whose key was a *shorter* list) sorted BELOW every
    prerelease. This key instead reproduces pkg's real ordering::

        4.0.0.a1 < 4.0.0.a2 < 4.0.0.b1 < 4.0.0.r1 < 4.0.0

    A version with no stage keyword (a Nightly timestamp-plus-SHA version, a bare
    ``pfsense_version`` like ``2.8.1``, or a
    genuine stable release) keeps its full numeric run as the base and ranks as
    RELEASE — unchanged ordering vs. the historical key for that case. Any
    non-numeric, non-stage-keyword component maps to ``0`` (same fallback the
    historical key used), so a malformed component never raises.

    Returns a NESTED ``(base, stage_rank, stage_num)`` tuple, NOT a flat list.
    A flat ``[*base, stage_rank, stage_num]`` breaks the "shorter all-numeric
    version sorts below its longer prefix-extension" rule: Python compares
    lists element-by-element, so ``2.8`` -> ``[2, 8, 3, 0]`` would compare its
    OWN stage_rank (index 2 = 3) against ``2.8.1``'s THIRD version component
    (index 2 = 1) and wrongly sort ``2.8`` above ``2.8.1``. Tuple comparison
    instead compares ``base`` as a whole LIST first (Python's list-prefix rule:
    ``[2, 8] < [2, 8, 1]``), so a bare edition version like ``2.8`` still sorts
    below its extension ``2.8.1``; stage_rank/stage_num only break ties within
    an equal base.
    """
    parts = re.split(r"[._,]", version)
    base: list[int] = []
    stage_rank = _RELEASE_RANK
    stage_num = 0
    i = 0
    while i < len(parts):
        part = parts[i]
        rank = _STAGE_RANK.get(part.lower())
        if rank is not None:
            stage_rank = rank
            if i + 1 < len(parts) and parts[i + 1].isdigit():
                stage_num = int(parts[i + 1])
                i += 2
            else:
                i += 1
            continue
        compact = _COMPACT_STAGE.fullmatch(part)
        if compact is not None:
            stage_rank = _COMPACT_STAGE_RANK[compact.group(1).lower()]
            stage_num = int(compact.group(2))
            i += 1
            continue
        base.append(int(part) if part.isdigit() else 0)
        i += 1
    return (base, stage_rank, stage_num)
