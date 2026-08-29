#!/usr/bin/env python3
# build-dep-pkg-portable.py — build a pfSense-installable FreeBSD .pkg for a
# single RUN_DEPENDS dependency port DIRECTLY FROM ITS PORT DEFINITION, without
# a FreeBSD host or the ports framework. Companion to build-pkg-portable.py
# (which builds the pfBlockerNG port itself); this tool is deliberately narrow:
# it only understands a pure-Python, NO_ARCH, USE_PYTHON=pep517 port (e.g.
# textproc/py-charset-normalizer) — anything else is a hard refusal, not a
# best-effort guess.
#
# pfSense CE's own repo does not carry every py3xx- dependency our port needs
# (Netgate builds some only for Plus). Rather than vendor the wheel, this tool
# builds the REAL upstream sdist the port's distinfo pins (verified sha256+size)
# with the exact Python/pip/setuptools/wheel environment installed from uv.lock,
# then emits a libpkg archive with a real ${PYTHON_PKGNAMEPREFIX}-prefixed name.
# A real pfSense box therefore resolves the RUN_DEPENDS from OUR repo
# (build-repo-portable.py --dep-pkgs folds the result into the release/nightly
# catalogs).
#
# Steps: (1) parse the port Makefile (reusing build-pkg-portable.py's Makefile
# class) for PORTNAME/PORTVERSION/DISTNAME/COMMENT/WWW/LICENSE/MASTER_SITES,
# requiring NO_ARCH=yes + USE_PYTHON containing pep517; (2) read distinfo for
# the pinned sha256+size; (3) fetch the sdist from a MASTER_SITES-derived URL
# (PYPI -> the pypi.io redirector; anything else -> the literal site + distfile)
# and verify it byte-for-byte against distinfo; (4) `pip wheel
# --no-build-isolation --no-deps` the sdist and require pure py3-none-any metadata;
# (5) unzip it to its site-packages install paths + generate the wheel's [console_scripts]
# entry-point stubs; (6) emit via build-pkg-portable.py's Build/Dep/StagedFile/
# write_pkg (NO_ARCH -> abi/arch wildcarded on CPU, python<NNN> RUN_DEPENDS).
#
# Requires the exact `.python-version` environment from
# `uv sync --locked --only-group dep-pkg-build`. Network is used only to fetch the
# distinfo-verified sdist; backend packages and zstd come from uv.lock.

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unicodedata
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

_THIS_DIR = Path(__file__).resolve().parent
_BUILD_PKG_PATH = _THIS_DIR / "build-pkg-portable.py"


def _load_build_pkg_portable() -> Any:
    """Load build-pkg-portable.py (hyphen-named, not import-able normally) as a
    library, reusing its Makefile parser + Build/Dep/StagedFile/write_pkg —
    the SAME manifest/archive emission the pfBlockerNG port build uses, so the
    two tools stay byte-format-identical. Registering in sys.modules BEFORE
    exec_module (not after) matters: its @dataclass classes need the module
    resolvable in sys.modules while they're being defined, or dataclass's
    field-type resolution breaks (the loader convention pinned by
    tests/test_build_repo_portable.py:49-54).
    """
    spec = importlib.util.spec_from_file_location("build_pkg_portable", _BUILD_PKG_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


bpp = _load_build_pkg_portable()

_REPO_ROOT = _THIS_DIR.parent
_BUILD_TOOLCHAIN = {
    "python": "3.11.15",
    "pip": "26.2.1",
    "setuptools": "75.6.0",
    "wheel": "0.45.1",
    "zstandard": "0.25.0",
}
_UV_VERSION = "0.12.6"


def _installed_build_toolchain() -> dict[str, str]:
    try:
        uv = subprocess.run(
            [str(Path(sys.executable).with_name("uv")), "--version"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise DepPkgError("uv build tool is unavailable") from exc
    match = re.match(r"^uv ([0-9]+(?:\.[0-9]+)+)\b", uv.stdout)
    if uv.returncode != 0 or match is None:
        raise DepPkgError(f"cannot determine uv build tool version: {uv.stderr.strip() or uv.stdout.strip()!r}")
    return {
        "python": ".".join(str(part) for part in sys.version_info[:3]),
        **{name: importlib.metadata.version(name) for name in ("pip", "setuptools", "wheel", "zstandard")},
        "uv": match.group(1),
    }


def build_toolchain_identity() -> dict[str, str]:
    lock = _REPO_ROOT / "uv.lock"
    return {
        **_BUILD_TOOLCHAIN,
        "uv": _UV_VERSION,
        "uv_lock_sha256": hashlib.sha256(lock.read_bytes()).hexdigest(),
    }


def validate_build_toolchain() -> None:
    try:
        installed = _installed_build_toolchain()
    except importlib.metadata.PackageNotFoundError as exc:
        raise DepPkgError(
            "dependency build toolchain is incomplete; run `uv sync --locked --only-group dep-pkg-build`"
        ) from exc
    for name, expected in {**_BUILD_TOOLCHAIN, "uv": _UV_VERSION}.items():
        if installed.get(name) != expected:
            raise DepPkgError(
                f"{name} build tool is {installed.get(name)!r}, expected {expected!r}; run "
                "`uv sync --locked --only-group dep-pkg-build`"
            )


class DepPkgError(Exception):
    """A fatal, user-facing error (bad port shape / checksum mismatch / bad wheel)."""


# --------------------------------------------------------------------------- #
# Port parsing — deliberately narrow: refuse anything not NO_ARCH + pep517.
# --------------------------------------------------------------------------- #


@dataclass
class PortFacts:
    portname: str
    portversion: str
    distname: str
    comment: str
    maintainer: str
    www: str
    license: str
    categories: list[str]
    master_sites: list[str]


def read_port(port_dir: Path) -> PortFacts:
    makefile = port_dir / "Makefile"
    if not makefile.is_file():
        raise DepPkgError(f"port Makefile not found: {makefile}")
    mk = bpp.Makefile(makefile, {})

    no_arch = mk.get("NO_ARCH").strip().lower()
    if no_arch not in ("yes", "true", "1", "on"):
        raise DepPkgError(
            f"{port_dir}: NO_ARCH is not set (got {mk.get('NO_ARCH')!r}) — this tool only "
            f"builds pure-Python NO_ARCH ports; teach it (or use build-pkg-portable.py's "
            f"recipe machinery) for anything else"
        )
    use_python = mk.get("USE_PYTHON").split()
    if "pep517" not in use_python:
        raise DepPkgError(
            f"{port_dir}: USE_PYTHON does not contain pep517 (got {use_python!r}) — this "
            f"tool only builds USE_PYTHON=pep517 ports"
        )

    portname = mk.get("PORTNAME")
    portversion = mk.get("PORTVERSION")
    if not portname or not portversion:
        raise DepPkgError(f"{port_dir}: Makefile missing PORTNAME/PORTVERSION")
    distname = mk.get("DISTNAME") or f"{portname}-{portversion}"
    for label, value in (("PORTNAME", portname), ("PORTVERSION", portversion), ("DISTNAME", distname)):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*", value):
            raise DepPkgError(f"{port_dir}: {label} is not a safe distfile component")

    www_all = mk.get("WWW").split()
    licenses = mk.get("LICENSE").split()
    if not licenses:
        raise DepPkgError(f"{port_dir}: Makefile has no LICENSE set")
    master_sites = mk.get("MASTER_SITES").split()
    if not master_sites:
        raise DepPkgError(f"{port_dir}: Makefile has no MASTER_SITES set")

    return PortFacts(
        portname=portname,
        portversion=portversion,
        distname=distname,
        comment=mk.get("COMMENT"),
        maintainer=mk.get("MAINTAINER"),
        www=www_all[0] if www_all else "",
        license=" ".join(licenses),
        categories=mk.get("CATEGORIES").split(),
        master_sites=master_sites,
    )


def read_descr(port_dir: Path, fallback: str) -> str:
    """The pkg-descr body (verbatim, like make package's `desc`), or ``fallback``
    (COMMENT) when the port has none — reuses build-pkg-portable.py's parser."""
    descr_path = port_dir / "pkg-descr"
    if not descr_path.is_file():
        return fallback
    desc, _www = bpp.parse_descr(descr_path.read_text())
    return desc or fallback


# --------------------------------------------------------------------------- #
# distinfo — the pinned sha256 + size for ${DISTNAME}.tar.gz.
# --------------------------------------------------------------------------- #


def read_distinfo(port_dir: Path, distfile: str) -> tuple[str, int]:
    distinfo = port_dir / "distinfo"
    if not distinfo.is_file():
        raise DepPkgError(f"distinfo not found: {distinfo}")
    text = distinfo.read_text()
    sha_m = re.search(rf"^SHA256 \({re.escape(distfile)}\) = ([0-9a-f]{{64}})$", text, re.M)
    size_m = re.search(rf"^SIZE \({re.escape(distfile)}\) = (\d+)$", text, re.M)
    if not sha_m or not size_m:
        raise DepPkgError(f"distinfo has no SHA256/SIZE entry for {distfile!r} in {distinfo}")
    return sha_m.group(1), int(size_m.group(1))


# --------------------------------------------------------------------------- #
# Source acquisition — MASTER_SITES-derived URL(s), sha256+size verified.
# --------------------------------------------------------------------------- #


def candidate_urls(port: PortFacts, distfile: str) -> list[str]:
    """URL(s) to try, in MASTER_SITES order.

    A bare ``PYPI`` entry is the ports-framework macro (expanded by
    Mk/bsd.sites.mk, which this tool's Makefile evaluator does not model) —
    resolved here as the canonical https://pypi.io/packages/source/<letter>/
    <pypi-name>/<distfile> redirector (the pypi-name is DISTNAME with its
    trailing "-<version>" stripped: PyPI sdist filenames use the underscore-
    normalized project name, e.g. "charset_normalizer" for PORTNAME
    "charset-normalizer"). Any other entry is used literally + distfile.
    """
    pypi_name = port.distname
    suffix = f"-{port.portversion}"
    if pypi_name.endswith(suffix):
        pypi_name = pypi_name[: -len(suffix)]

    urls: list[str] = []
    for site in port.master_sites:
        if site.strip().upper() == "PYPI":
            first_letter = (pypi_name[:1] or "_").lower()
            urls.append(f"https://pypi.io/packages/source/{first_letter}/{pypi_name}/{distfile}")
        else:
            urls.append(site.rstrip("/") + "/" + distfile)
    return urls


def _urlopen(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": "build-dep-pkg-portable"})
    return urllib.request.urlopen(req)


def fetch_verified_sdist(port: PortFacts, dest_dir: Path, *, sha256: str, size: int) -> Path:
    """Fetch ${DISTNAME}.tar.gz from a MASTER_SITES candidate and verify it
    against distinfo. A connection failure falls through to the next candidate;
    a checksum/size MISMATCH is a hard refusal (never silently tried elsewhere —
    that would mask a poisoned or wrong-version mirror)."""
    distfile = f"{port.distname}.tar.gz"
    dest = dest_dir / distfile
    errors: list[str] = []
    for url in candidate_urls(port, distfile):
        try:
            with _urlopen(url) as r, open(dest, "wb") as f:
                shutil.copyfileobj(r, f)
        except OSError as e:
            errors.append(f"{url}: {e}")
            continue
        got_sha = hashlib.sha256(dest.read_bytes()).hexdigest()
        got_size = dest.stat().st_size
        if got_sha != sha256 or got_size != size:
            raise DepPkgError(
                f"{distfile} fetched from {url} does not match distinfo — refusing "
                f"(sha256 expected {sha256} got {got_sha}; size expected {size} got {got_size})"
            )
        sys.stderr.write(f"==> fetched + verified {url}\n")
        return dest
    raise DepPkgError(f"failed to fetch {distfile} from any MASTER_SITES candidate:\n  " + "\n  ".join(errors))


# --------------------------------------------------------------------------- #
# Wheel build — BUILD_DEPENDS py-setuptools/py-wheel equivalent: `pip wheel`.
# --------------------------------------------------------------------------- #


def _run_relayed(cmd: list[str], **kwargs: Any) -> None:
    """Run ``cmd`` with its stdout+stderr CAPTURED (never inherited) and relayed
    to OUR stderr, then raise ``CalledProcessError`` on a nonzero exit — same
    contract as ``subprocess.run(cmd, check=True)`` for the caller. Extra
    ``kwargs`` (e.g. ``env=``) pass through to ``subprocess.run`` verbatim.

    A tool this script shells out to (pip, venv) is chatty on stdout
    ("Processing ...", "Created wheel ..."). ``main()``'s stdout contract is
    exactly one line — the emitted .pkg path — because an on-box caller
    captures this whole process's stdout as that path (``PKG="$(python3
    build-dep-pkg-portable.py ...)"``); an inherited child stdout leaks that
    chatter into the captured value and word-splits it into garbage.
    """
    result = subprocess.run(cmd, capture_output=True, text=True, **kwargs)
    if result.stdout:
        sys.stderr.write(result.stdout)
    if result.stderr:
        sys.stderr.write(result.stderr)
    if result.returncode != 0:
        raise subprocess.CalledProcessError(result.returncode, cmd, output=result.stdout, stderr=result.stderr)


def build_wheel(sdist: Path, work_dir: Path, *, source_date_epoch: int | None = None) -> Path:
    wheel_dir = work_dir / "wheel"
    wheel_dir.mkdir(parents=True, exist_ok=True)
    python = sys.executable
    blocked_env_prefixes = ("LC_", "PIP_", "PYTHON", "SETUPTOOLS_", "SOURCE_DATE_EPOCH", "TZ", "WHEEL_")
    env = {
        key: value
        for key, value in os.environ.items()
        if key not in ("LANG",) and not key.startswith(blocked_env_prefixes)
    }
    env.update(
        LANG="C",
        LC_ALL="C",
        PIP_CONFIG_FILE=os.devnull,
        PIP_DISABLE_PIP_VERSION_CHECK="1",
        PIP_NO_INDEX="1",
        PYTHONHASHSEED="0",
        TZ="UTC",
    )
    if source_date_epoch is not None:
        env["SOURCE_DATE_EPOCH"] = str(source_date_epoch)
    cmd = [
        python,
        "-m",
        "pip",
        "wheel",
        "--no-cache-dir",
        "--no-build-isolation",
        "--no-index",
        "--no-deps",
        str(sdist),
        "-w",
        str(wheel_dir),
    ]
    sys.stderr.write(f"==> building wheel: {' '.join(cmd)}\n")
    _run_relayed(cmd, env=env)
    wheels = sorted(wheel_dir.glob("*.whl"))
    if len(wheels) != 1:
        raise DepPkgError(f"expected exactly one wheel from `pip wheel`, got {[w.name for w in wheels]}")
    wheel = wheels[0]
    if not wheel.name.endswith("-py3-none-any.whl"):
        raise DepPkgError(
            f"{wheel.name}: not a pure-Python wheel (expected *-py3-none-any.whl) — "
            f"this tool refuses to package a platform-specific wheel"
        )
    return wheel


# --------------------------------------------------------------------------- #
# Staging: unzip the wheel to its site-packages install paths, generate
# [console_scripts] entry-point stubs. No .pyc compilation: the build host's
# python is not necessarily the target's python3.11 (the magic number in a
# .pyc header is interpreter-version-specific), so a build-host-compiled .pyc
# would silently fail to load / get ignored on the target — ship .py only,
# same as a real pep517 port's staged (uncompiled) payload.
# --------------------------------------------------------------------------- #

_PY_FLAVOR_RE = re.compile(r"^py(\d)(\d+)$")


def python_dotted_version(py_flavor: str) -> str:
    """``py311`` -> ``"3.11"`` (the site-packages dir + shebang interpreter
    version). Refuses anything that doesn't look like a pyNNN flavor."""
    m = _PY_FLAVOR_RE.match(py_flavor)
    if not m:
        raise DepPkgError(f"unknown --py-flavor {py_flavor!r} (expected pyNNN, e.g. py311)")
    return f"{m.group(1)}.{m.group(2)}"


_ENTRY_POINT_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*=\s*([A-Za-z0-9_.]+):([A-Za-z0-9_.]+)\s*$")


def parse_console_scripts(entry_points_text: str) -> dict[str, tuple[str, str]]:
    """Return ``{script_name: (module, function)}`` for the wheel's
    ``[console_scripts]`` entry_points.txt section. Empty dict if the wheel
    carries no entry_points.txt or no such section (a library-only wheel)."""
    scripts: dict[str, tuple[str, str]] = {}
    section: str | None = None
    for raw in entry_points_text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            continue
        if section != "console_scripts":
            continue
        m = _ENTRY_POINT_RE.match(line)
        if not m:
            raise DepPkgError(f"unparseable entry_points.txt console_scripts line: {raw!r}")
        name = m.group(1)
        if name in scripts:
            raise DepPkgError(f"duplicate console-script name: {name}")
        scripts[name] = (m.group(2), m.group(3))
    return scripts


# The standard pip/setuptools console-script launcher shape (8 lines incl.
# shebang) — what a real `pip install` of this wheel would generate.
_SCRIPT_STUB = """#!/usr/local/bin/python{py_dotted}
# -*- coding: utf-8 -*-
import re
import sys
from {module} import {func}
if __name__ == '__main__':
    sys.argv[0] = re.sub(r'(-script\\.pyw|\\.exe)?$', '', sys.argv[0])
    sys.exit({func}())
"""


def _validated_wheel_files(zf: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    files = [info for info in zf.infolist() if not info.is_dir()]
    names = [info.filename for info in files]
    if len(names) != len(set(names)):
        raise DepPkgError("wheel contains duplicate member names")
    canonical_names = [unicodedata.normalize("NFC", name).casefold() for name in names]
    if len(canonical_names) != len(set(canonical_names)):
        raise DepPkgError("wheel contains host-canonical member collision")

    compiled_suffixes = (".dll", ".dylib", ".pyc", ".pyd", ".so")
    for info in files:
        if (
            not info.filename
            or info.filename.startswith("/")
            or "\\" in info.filename
            or any(part in ("", ".", "..") for part in info.filename.split("/"))
        ):
            raise DepPkgError(f"wheel contains unsafe member path: {info.filename!r}")
        if stat.S_ISLNK(info.external_attr >> 16):
            raise DepPkgError(f"wheel contains symlink member: {info.filename!r}")
        if info.filename.lower().endswith(compiled_suffixes):
            raise DepPkgError(f"wheel contains compiled member: {info.filename!r}")

    wheel_metadata = [info for info in files if info.filename.endswith(".dist-info/WHEEL")]
    if len(wheel_metadata) != 1:
        raise DepPkgError(f"wheel must contain exactly one .dist-info/WHEEL member, got {len(wheel_metadata)}")
    try:
        metadata = zf.read(wheel_metadata[0]).decode("utf-8")
    except UnicodeDecodeError:
        raise DepPkgError("wheel .dist-info/WHEEL metadata is not UTF-8") from None
    root_is_purelib = [
        line.partition(":")[2].strip().lower()
        for line in metadata.splitlines()
        if line.lower().startswith("root-is-purelib:")
    ]
    tags = [line.partition(":")[2].strip() for line in metadata.splitlines() if line.lower().startswith("tag:")]
    if root_is_purelib != ["true"]:
        raise DepPkgError("wheel metadata must declare Root-Is-Purelib: true")
    if tags != ["py3-none-any"]:
        raise DepPkgError(f"wheel metadata Tag must be exactly py3-none-any, got {tags!r}")
    return sorted(files, key=lambda info: info.filename)


def stage_wheel(wheel: Path, stage_dir: Path, py_dotted: str) -> tuple[list[Path], list[Path]]:
    """Unzip a validated pure wheel into target site-packages and script paths."""
    site_root = stage_dir / "usr/local/lib" / f"python{py_dotted}" / "site-packages"
    site_root.mkdir(parents=True, exist_ok=True)

    site_files: list[Path] = []
    entry_points_text = ""
    with zipfile.ZipFile(wheel) as zf:
        for info in _validated_wheel_files(zf):
            target = site_root / info.filename
            target.parent.mkdir(parents=True, exist_ok=True)
            data = zf.read(info)
            target.write_bytes(data)
            site_files.append(target)
            if info.filename.endswith(".dist-info/entry_points.txt"):
                try:
                    entry_points_text = data.decode("utf-8")
                except UnicodeDecodeError:
                    raise DepPkgError("wheel entry_points.txt is not UTF-8") from None

    bin_root = stage_dir / "usr/local/bin"
    script_files: list[Path] = []
    scripts = parse_console_scripts(entry_points_text)
    canonical_scripts = [unicodedata.normalize("NFC", name).casefold() for name in scripts]
    if len(canonical_scripts) != len(set(canonical_scripts)):
        raise DepPkgError("wheel contains host-canonical console-script collision")
    for name, (module, func) in sorted(scripts.items()):
        bin_root.mkdir(parents=True, exist_ok=True)
        script = bin_root / name
        script.write_text(_SCRIPT_STUB.format(py_dotted=py_dotted, module=module, func=func))
        script.chmod(0o555)
        script_files.append(script)

    return site_files, script_files


# --------------------------------------------------------------------------- #
# Orchestration + manifest emission (reuses build-pkg-portable.py's Build/Dep/
# StagedFile/write_pkg — same libpkg archive format, same checksum/tar framing).
# --------------------------------------------------------------------------- #


def _source_date_epoch(args: argparse.Namespace) -> int:
    epoch = bpp._checked_mtime(args.source_date_epoch, "--source-date-epoch")
    if "SOURCE_DATE_EPOCH" in os.environ:
        raw = os.environ["SOURCE_DATE_EPOCH"].strip()
        try:
            ambient = int(raw)
        except ValueError:
            raise DepPkgError("ambient SOURCE_DATE_EPOCH must match --source-date-epoch") from None
        if ambient != epoch:
            raise DepPkgError("ambient SOURCE_DATE_EPOCH must match --source-date-epoch")
    return epoch


def _dep_build_record(
    args: argparse.Namespace,
    port: PortFacts,
    *,
    distfile: str,
    distfile_sha256: str,
    distfile_size: int,
) -> str:
    record = {
        "schema": 1,
        "freebsd_ports_sha": args.ports_sha,
        "port_origin": args.port,
        "port_version": port.portversion,
        "distfile": distfile,
        "distfile_sha256": distfile_sha256,
        "distfile_size": distfile_size,
        "py_flavor": args.py_flavor,
        "freebsd_major": args.freebsd_major,
        "abi": f"FreeBSD:{args.freebsd_major}:*",
        "source_date_epoch": args.source_date_epoch,
        "toolchain": build_toolchain_identity(),
    }
    return json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _checked_origin(value: str) -> PurePosixPath:
    origin = PurePosixPath(value)
    if (
        not value
        or "\\" in value
        or origin.is_absolute()
        or len(origin.parts) != 2
        or any(part in ("", ".", "..") for part in origin.parts)
        or origin.as_posix() != value
    ):
        raise DepPkgError("--port must be a safe category/name port origin")
    return origin


def dependency_port_identity(args: argparse.Namespace) -> dict[str, object]:
    if not re.fullmatch(r"[0-9a-f]{40}", args.ports_sha):
        raise DepPkgError("--ports-sha must be a lowercase 40-character Git SHA")
    origin = _checked_origin(args.port)
    ports_root = Path(args.ports).resolve()
    port_payload = ports_root / origin
    bpp._attest_checkout(ports_root, args.ports_sha, "FreeBSD-ports", payload_root=port_payload)
    with tempfile.TemporaryDirectory(prefix="pfbng-depidentity-") as td:
        snapshot_root = bpp._snapshot_checkout(
            ports_root,
            args.ports_sha,
            Path(td) / "ports-snapshot",
            payload_root=port_payload,
        )
        port_dir = snapshot_root / origin
        port = read_port(port_dir)
        distfile = f"{port.distname}.tar.gz"
        sha256, size = read_distinfo(port_dir, distfile)
    return {
        "port_origin": args.port,
        "portname": port.portname,
        "port_version": port.portversion,
        "distfile": distfile,
        "distfile_sha256": sha256,
        "distfile_size": size,
    }


def build_dep_pkg(args: argparse.Namespace) -> Path:
    epoch = _source_date_epoch(args)
    if not re.fullmatch(r"[0-9a-f]{40}", args.ports_sha):
        raise DepPkgError("--ports-sha must be a lowercase 40-character Git SHA")
    origin = _checked_origin(args.port)
    ports_root = Path(args.ports).resolve()
    port_payload = ports_root / origin
    py_dotted = python_dotted_version(args.py_flavor)  # validates the flavor too
    validate_build_toolchain()
    bpp._attest_checkout(ports_root, args.ports_sha, "FreeBSD-ports", payload_root=port_payload)
    with tempfile.TemporaryDirectory(prefix="pfbng-deppkg-") as td:
        tmp = Path(td)
        snapshot_root = bpp._snapshot_checkout(
            ports_root,
            args.ports_sha,
            tmp / "ports-snapshot",
            payload_root=port_payload,
        )
        port_dir = snapshot_root / origin
        port = read_port(port_dir)
        distfile = f"{port.distname}.tar.gz"
        sha256, size = read_distinfo(port_dir, distfile)
        sdist = fetch_verified_sdist(port, tmp, sha256=sha256, size=size)
        wheel = build_wheel(sdist, tmp, source_date_epoch=epoch)

        stage = tmp / "stage"
        site_files, script_files = stage_wheel(wheel, stage, py_dotted)
        for staged_file in site_files + script_files:
            os.utime(staged_file, (epoch, epoch))

        portname = f"{args.py_flavor}-{port.portname}"
        pyv = args.py_flavor[2:]  # "py311" -> "311"

        files: list[Any] = []
        for f in site_files:
            files.append(bpp.StagedFile(install_path="/" + str(f.relative_to(stage)), src_in_stage=f, perm="0644"))
        for f in script_files:
            files.append(bpp.StagedFile(install_path="/" + str(f.relative_to(stage)), src_in_stage=f, perm="0555"))

        build = bpp.Build(
            portname=portname,
            pkgversion=port.portversion,
            origin=args.port,
            comment=port.comment,
            maintainer=port.maintainer,
            categories=port.categories,
            licenses=port.license.split(),
            www=port.www,
            desc=read_descr(port_dir, port.comment),
            prefix="/usr/local",
            # NO_ARCH: wildcard the CPU so one build serves every arch on this
            # FreeBSD major (real `pkg create` does the same for a NO_ARCH port).
            abi=f"FreeBSD:{args.freebsd_major}:*",
            arch=f"freebsd:{args.freebsd_major}:*",
            deps=[
                bpp.Dep(name=f"python{pyv}", origin=f"lang/python{pyv}", version=args.python_dep_version),
            ],
            files=files,
            annotations={
                "pfb_dep_build_record": _dep_build_record(
                    args,
                    port,
                    distfile=distfile,
                    distfile_sha256=sha256,
                    distfile_size=size,
                )
            },
        )

        out_dir = Path(args.out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"{build.pkgname}.pkg"
        bpp.write_pkg(build, out_path, args.compression)
        sys.stderr.write(f"==> wrote {out_path}  ({out_path.stat().st_size} bytes, {len(build.files)} files)\n")
        return out_path


def main(argv: list[str]) -> int:
    if argv == ["--print-toolchain"]:
        print(json.dumps(build_toolchain_identity(), ensure_ascii=False, sort_keys=True, separators=(",", ":")))
        return 0
    if argv[:1] == ["--print-port-identity"]:
        identity_parser = argparse.ArgumentParser(prog="build-dep-pkg-portable.py --print-port-identity")
        identity_parser.add_argument("--ports", required=True)
        identity_parser.add_argument("--ports-sha", required=True, dest="ports_sha")
        identity_parser.add_argument("--port", required=True)
        try:
            identity = dependency_port_identity(identity_parser.parse_args(argv[1:]))
        except (DepPkgError, bpp.BuildError) as exc:
            sys.stderr.write(f"build-dep-pkg-portable: {exc}\n")
            return 1
        print(json.dumps(identity, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
        return 0
    ap = argparse.ArgumentParser(
        prog="build-dep-pkg-portable.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Build a pfSense-installable, pure-Python NO_ARCH FreeBSD .pkg for a single "
            "RUN_DEPENDS port, straight from its FreeBSD ports definition — no FreeBSD "
            "host, no ports framework. Narrow by design: refuses anything that isn't "
            "NO_ARCH + USE_PYTHON=pep517."
        ),
        epilog=(
            "example:\n"
            "  build-dep-pkg-portable.py --ports ../FreeBSD-ports \\\n"
            "      --ports-sha <40-hex SHA> --port textproc/py-charset-normalizer \\\n"
            "      --py-flavor py311 --source-date-epoch <source commit epoch> \\\n"
            "      --freebsd-major 15 --out-dir /tmp\n"
        ),
    )
    ap.add_argument("--ports", required=True, help="FreeBSD-ports checkout root")
    ap.add_argument("--port", required=True, help="port origin, e.g. textproc/py-charset-normalizer")
    ap.add_argument("--py-flavor", required=True, dest="py_flavor", help="Python flavor, e.g. py311 (pyNNN)")
    ap.add_argument(
        "--freebsd-major", required=True, dest="freebsd_major", help="target FreeBSD major, e.g. 15 (CE 2.8)"
    )
    ap.add_argument(
        "--python-dep-version",
        default="0",
        dest="python_dep_version",
        help=(
            "version recorded for the python<NNN> RUN_DEPENDS. Informational only -- "
            "pkg(8) resolves a dependency by NAME, never by the version recorded in "
            "another package's manifest, so this is never enforced at install. Default "
            "'0' (unknown at build time): lang/python<NNN>'s real PORTVERSION is not a "
            "literal in its Makefile (it's ${PYTHON_DISTVERSION}, indirect via Mk/Uses/"
            "python.mk) and deriving it honestly needs the ports framework this tool "
            "deliberately avoids. Pass an explicit version only if a caller has one."
        ),
    )
    ap.add_argument("--ports-sha", required=True, dest="ports_sha", help="exact FreeBSD-ports Git SHA")
    ap.add_argument(
        "--source-date-epoch",
        required=True,
        type=int,
        dest="source_date_epoch",
        help="source-derived package timestamp in whole Unix seconds",
    )
    ap.add_argument("--out-dir", required=True, dest="out_dir", help="output directory for the .pkg")
    ap.add_argument("--compression", choices=("zstd", "xz"), default="zstd", help="output compression (default: zstd)")
    args = ap.parse_args(argv)

    try:
        out_path = build_dep_pkg(args)
    except (DepPkgError, bpp.BuildError, subprocess.CalledProcessError) as e:
        sys.stderr.write(f"build-dep-pkg-portable: {e}\n")
        return 1
    print(out_path)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
