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
# builds the REAL upstream sdist the port's distinfo pins (verified sha256+size),
# via the port's own BUILD_DEPENDS toolchain (pip wheel, using py-setuptools/
# py-wheel exactly like `make package` would), and emits a libpkg archive with
# a real ${PYTHON_PKGNAMEPREFIX}-prefixed name — so a real pfSense box's
# `pkg install` resolves the RUN_DEPENDS from OUR repo (build-repo-portable.py
# --dep-pkgs folds the result into the release/nightly catalogs).
#
# Steps: (1) parse the port Makefile (reusing build-pkg-portable.py's Makefile
# class) for PORTNAME/PORTVERSION/DISTNAME/COMMENT/WWW/LICENSE/MASTER_SITES,
# requiring NO_ARCH=yes + USE_PYTHON containing pep517; (2) read distinfo for
# the pinned sha256+size; (3) fetch the sdist from a MASTER_SITES-derived URL
# (PYPI -> the pypi.io redirector; anything else -> the literal site + distfile)
# and verify it byte-for-byte against distinfo; (4) `pip wheel --no-deps` the
# sdist and assert the result is a single pure (py3-none-any) wheel; (5) unzip
# it to its site-packages install paths + generate the wheel's [console_scripts]
# entry-point stubs; (6) emit via build-pkg-portable.py's Build/Dep/StagedFile/
# write_pkg (NO_ARCH -> abi/arch wildcarded on CPU, python<NNN> RUN_DEPENDS).
#
# Requires: python3 (stdlib) + pip (BUILD_DEPENDS equivalent) + a zstd encoder
# (see build-pkg-portable.py). Network is required (sdist fetch + pip's own
# fetch of its build backend). Developer tool — not shipped in release archives.

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
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


def _run_relayed(cmd: list[str]) -> None:
    """Run ``cmd`` with its stdout+stderr CAPTURED (never inherited) and relayed
    to OUR stderr, then raise ``CalledProcessError`` on a nonzero exit — same
    contract as ``subprocess.run(cmd, check=True)`` for the caller.

    A tool this script shells out to (pip, venv) is chatty on stdout
    ("Processing ...", "Created wheel ..."). ``main()``'s stdout contract is
    exactly one line — the emitted .pkg path — because an on-box caller
    captures this whole process's stdout as that path (``PKG="$(python3
    build-dep-pkg-portable.py ...)"``); an inherited child stdout leaks that
    chatter into the captured value and word-splits it into garbage.
    """
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.stdout:
        sys.stderr.write(result.stdout)
    if result.stderr:
        sys.stderr.write(result.stderr)
    if result.returncode != 0:
        raise subprocess.CalledProcessError(result.returncode, cmd, output=result.stdout, stderr=result.stderr)


def _pip_python(work_dir: Path) -> str:
    """A python executable with a working ``pip`` module.

    ``sys.executable`` (the fast path — true on every CI runner) when it
    already has one. Some build hosts (the PFB_BOXES minimal Debian pool) ship
    ``python3-venv`` but not ``pip`` on the system interpreter; there, bootstrap
    a throwaway venv under ``work_dir`` (a venv's own pip is always present)
    and return ITS python instead. A venv-creation failure too is a loud
    refusal, never a silent fall-through.
    """
    probe = subprocess.run([sys.executable, "-m", "pip", "--version"], capture_output=True)
    if probe.returncode == 0:
        return sys.executable
    venv_dir = work_dir / "pip-venv"
    sys.stderr.write(f"==> {sys.executable} has no pip module; bootstrapping a venv at {venv_dir}\n")
    try:
        _run_relayed([sys.executable, "-m", "venv", str(venv_dir)])
    except subprocess.CalledProcessError as e:
        raise DepPkgError(f"{sys.executable} has no pip and venv creation failed: {e}") from e
    return str(venv_dir / "bin" / "python")


def build_wheel(sdist: Path, work_dir: Path) -> Path:
    wheel_dir = work_dir / "wheel"
    wheel_dir.mkdir(parents=True, exist_ok=True)
    python = _pip_python(work_dir)
    cmd = [python, "-m", "pip", "wheel", "--no-deps", str(sdist), "-w", str(wheel_dir)]
    sys.stderr.write(f"==> building wheel: {' '.join(cmd)}\n")
    _run_relayed(cmd)
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


_ENTRY_POINT_RE = re.compile(r"^([^=\s]+)\s*=\s*([A-Za-z0-9_.]+):([A-Za-z0-9_.]+)\s*$")


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
        scripts[m.group(1)] = (m.group(2), m.group(3))
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


def stage_wheel(wheel: Path, stage_dir: Path, py_dotted: str) -> tuple[list[Path], list[Path]]:
    """Unzip ``wheel`` into ``stage_dir`` at its real install paths (site-packages
    for every wheel member, ``/usr/local/bin/<name>`` for each console-script
    entry point). Returns ``(site_package_files, script_files)`` — absolute
    Paths under ``stage_dir`` the caller turns into ``StagedFile`` entries."""
    site_root = stage_dir / "usr/local/lib" / f"python{py_dotted}" / "site-packages"
    site_root.mkdir(parents=True, exist_ok=True)

    site_files: list[Path] = []
    entry_points_text = ""
    with zipfile.ZipFile(wheel) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            target = site_root / info.filename
            target.parent.mkdir(parents=True, exist_ok=True)
            data = zf.read(info.filename)
            target.write_bytes(data)
            site_files.append(target)
            if info.filename.endswith(".dist-info/entry_points.txt"):
                entry_points_text = data.decode("utf-8")

    bin_root = stage_dir / "usr/local/bin"
    script_files: list[Path] = []
    for name, (module, func) in parse_console_scripts(entry_points_text).items():
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


def build_dep_pkg(args: argparse.Namespace) -> Path:
    port_dir = Path(args.ports).resolve() / args.port
    port = read_port(port_dir)
    py_dotted = python_dotted_version(args.py_flavor)  # validates the flavor too

    distfile = f"{port.distname}.tar.gz"
    sha256, size = read_distinfo(port_dir, distfile)

    with tempfile.TemporaryDirectory(prefix="pfbng-deppkg-") as td:
        tmp = Path(td)
        sdist = fetch_verified_sdist(port, tmp, sha256=sha256, size=size)
        wheel = build_wheel(sdist, tmp)

        stage = tmp / "stage"
        site_files, script_files = stage_wheel(wheel, stage, py_dotted)
        if not site_files:
            raise DepPkgError(f"{wheel.name}: wheel contained no files")

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
        )

        out_dir = Path(args.out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"{build.pkgname}.pkg"
        bpp.write_pkg(build, out_path, args.compression)
        sys.stderr.write(f"==> wrote {out_path}  ({out_path.stat().st_size} bytes, {len(build.files)} files)\n")
        return out_path


def main(argv: list[str]) -> int:
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
            "      --port textproc/py-charset-normalizer --py-flavor py311 \\\n"
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
