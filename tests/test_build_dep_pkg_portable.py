"""Tests for scripts/build-dep-pkg-portable.py — the port-driven dependency
package builder (issue #1806 step A).

The fixture Makefile/distinfo/pkg-descr mirror the REAL
textproc/py-charset-normalizer port (captured 2026-07-28 from the
pfBlockerNG/FreeBSD-ports fork, commit 3a57c58d82c8's parent). Network (sdist
fetch, `pip wheel`) is mocked everywhere here — see the module docstring in
build-dep-pkg-portable.py for the tool's real network behavior; a real build
against an actual ports checkout (genuine sdist fetch + pip wheel) is
validated separately, outside this hermetic suite.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import Any

import pfb_pkg
import pytest

# --------------------------------------------------------------------------- #
# Load the hyphen-named tool as a module (same convention as
# tests/test_build_repo_portable.py:49-54 — register in sys.modules BEFORE
# exec_module, or the tool's own dataclass-based import of build-pkg-portable.py
# breaks).
# --------------------------------------------------------------------------- #

_TOOL = Path(__file__).resolve().parent.parent / "scripts" / "build-dep-pkg-portable.py"
_spec = importlib.util.spec_from_file_location("build_dep_pkg_portable", _TOOL)
assert _spec is not None and _spec.loader is not None
bdp = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = bdp
_spec.loader.exec_module(bdp)


# --------------------------------------------------------------------------- #
# Fixture port dir — the REAL textproc/py-charset-normalizer Makefile/distinfo/
# pkg-descr shape, with two knobs (`use_python`, `no_arch_line`) for the
# refusal tests.
# --------------------------------------------------------------------------- #


def _port_makefile(*, use_python: str = "autoplist concurrent pep517", no_arch_line: str = "NO_ARCH=\tyes") -> str:
    return (
        "PORTNAME=\tcharset-normalizer\n"
        "PORTVERSION=\t3.4.4\n"
        "CATEGORIES=\ttextproc python\n"
        "MASTER_SITES=\tPYPI \\\n"
        "\t\thttps://github.com/jawah/charset_normalizer/releases/download/${PORTVERSION}/\n"
        "PKGNAMEPREFIX=\t${PYTHON_PKGNAMEPREFIX}\n"
        "DISTNAME=\tcharset_normalizer-${PORTVERSION}\n"
        "\n"
        "MAINTAINER=\tsunpoet@FreeBSD.org\n"
        "COMMENT=\tReal First Universal Charset Detector\n"
        "WWW=\t\thttps://charset-normalizer.readthedocs.io/en/latest/ \\\n"
        "\t\thttps://github.com/Ousret/charset_normalizer\n"
        "\n"
        "LICENSE=\tMIT\n"
        "LICENSE_FILE=\t${WRKSRC}/LICENSE\n"
        "\n"
        "BUILD_DEPENDS=\t${PYTHON_PKGNAMEPREFIX}setuptools>=61:devel/py-setuptools@${PY_FLAVOR} \\\n"
        "\t\t${PYTHON_PKGNAMEPREFIX}wheel>=0:devel/py-wheel@${PY_FLAVOR}\n"
        "\n"
        "USES=\t\tpython\n"
        f"USE_PYTHON=\t{use_python}\n"
        "\n"
        f"{no_arch_line}\n"
        "\n"
        ".include <bsd.port.mk>\n"
    )


_REAL_DISTINFO = (
    "TIMESTAMP = 1759774719\n"
    "SHA256 (charset_normalizer-3.4.4.tar.gz) = 94537985111c35f28720e43603b8e7b43a6ecfb2ce1d3058bbe955b73404e21a\n"
    "SIZE (charset_normalizer-3.4.4.tar.gz) = 129418\n"
)

_REAL_PKG_DESCR = (
    "A library that helps you read text from an unknown charset encoding. Motivated\n"
    "by chardet, I'm trying to resolve the issue by taking a new approach. All IANA\n"
    "character set names for which the Python core library provides codecs are\n"
    "supported.\n"
)


def _write_port(
    ports_root: Path,
    *,
    use_python: str = "autoplist concurrent pep517",
    no_arch_line: str = "NO_ARCH=\tyes",
    with_descr: bool = True,
) -> Path:
    port_dir = ports_root / "textproc" / "py-charset-normalizer"
    port_dir.mkdir(parents=True)
    (port_dir / "Makefile").write_text(_port_makefile(use_python=use_python, no_arch_line=no_arch_line))
    (port_dir / "distinfo").write_text(_REAL_DISTINFO)
    if with_descr:
        (port_dir / "pkg-descr").write_text(_REAL_PKG_DESCR)
    return port_dir


def _write_wheel(path: Path, *, files: dict[str, bytes], entry_points: str | None) -> None:
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
        if entry_points is not None:
            zf.writestr("mypkg-1.0.dist-info/entry_points.txt", entry_points)


def _read_full_manifest(pkg_path: Path) -> dict:
    """Read the +MANIFEST (file listing + perms) of a .pkg written by write_pkg."""
    tar_bytes = pfb_pkg.zstd_decompress(pkg_path.read_bytes())
    with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tf:
        member = tf.extractfile("+MANIFEST")
        assert member is not None
        return json.loads(member.read())


# --------------------------------------------------------------------------- #
# Makefile parsing — every extracted field, and the two hard refusals.
# --------------------------------------------------------------------------- #


def test_read_port_extracts_facts(tmp_path: Path) -> None:
    port_dir = _write_port(tmp_path)
    facts = bdp.read_port(port_dir)
    assert facts.portname == "charset-normalizer"
    assert facts.portversion == "3.4.4"
    assert facts.distname == "charset_normalizer-3.4.4"
    assert facts.comment == "Real First Universal Charset Detector"
    assert facts.maintainer == "sunpoet@FreeBSD.org"
    # WWW carries the FIRST url only, even though the port lists two.
    assert facts.www == "https://charset-normalizer.readthedocs.io/en/latest/"
    assert facts.license == "MIT"
    assert facts.categories == ["textproc", "python"]
    assert facts.master_sites == [
        "PYPI",
        "https://github.com/jawah/charset_normalizer/releases/download/3.4.4/",
    ]


def test_read_port_refuses_missing_no_arch(tmp_path: Path) -> None:
    port_dir = _write_port(tmp_path, no_arch_line="")
    with pytest.raises(bdp.DepPkgError, match="NO_ARCH"):
        bdp.read_port(port_dir)


def test_read_port_refuses_no_arch_explicitly_no(tmp_path: Path) -> None:
    port_dir = _write_port(tmp_path, no_arch_line="NO_ARCH=\tno")
    with pytest.raises(bdp.DepPkgError, match="NO_ARCH"):
        bdp.read_port(port_dir)


def test_read_port_refuses_non_pep517(tmp_path: Path) -> None:
    port_dir = _write_port(tmp_path, use_python="autoplist concurrent distutils")
    with pytest.raises(bdp.DepPkgError, match="pep517"):
        bdp.read_port(port_dir)


def test_read_port_requires_makefile(tmp_path: Path) -> None:
    missing = tmp_path / "textproc" / "does-not-exist"
    with pytest.raises(bdp.DepPkgError, match="Makefile"):
        bdp.read_port(missing)


# --------------------------------------------------------------------------- #
# distinfo parsing
# --------------------------------------------------------------------------- #


def test_read_distinfo_parses_sha256_and_size(tmp_path: Path) -> None:
    port_dir = _write_port(tmp_path)
    sha, size = bdp.read_distinfo(port_dir, "charset_normalizer-3.4.4.tar.gz")
    assert sha == "94537985111c35f28720e43603b8e7b43a6ecfb2ce1d3058bbe955b73404e21a"
    assert size == 129418


def test_read_distinfo_missing_entry_raises(tmp_path: Path) -> None:
    port_dir = _write_port(tmp_path)
    with pytest.raises(bdp.DepPkgError, match="distinfo"):
        bdp.read_distinfo(port_dir, "nonexistent-9.9.9.tar.gz")


def test_read_descr_uses_pkg_descr_when_present(tmp_path: Path) -> None:
    port_dir = _write_port(tmp_path)
    assert bdp.read_descr(port_dir, "fallback").startswith("A library that helps you read text")


def test_read_descr_falls_back_to_comment_when_missing(tmp_path: Path) -> None:
    port_dir = _write_port(tmp_path, with_descr=False)
    assert bdp.read_descr(port_dir, "fallback comment") == "fallback comment"


# --------------------------------------------------------------------------- #
# URL derivation (MASTER_SITES -> candidate download URLs)
# --------------------------------------------------------------------------- #


def _demo_port(**overrides: object) -> Any:
    base: dict[str, Any] = dict(
        portname="charset-normalizer",
        portversion="3.4.4",
        distname="charset_normalizer-3.4.4",
        comment="x",
        maintainer="",
        www="",
        license="MIT",
        categories=["textproc", "python"],
        master_sites=["PYPI", "https://github.com/jawah/charset_normalizer/releases/download/3.4.4/"],
    )
    base.update(overrides)
    return bdp.PortFacts(**base)  # type: ignore[arg-type]


def test_candidate_urls_pypi_redirector_then_literal_fallback() -> None:
    port = _demo_port()
    urls = bdp.candidate_urls(port, "charset_normalizer-3.4.4.tar.gz")
    assert urls == [
        "https://pypi.io/packages/source/c/charset_normalizer/charset_normalizer-3.4.4.tar.gz",
        "https://github.com/jawah/charset_normalizer/releases/download/3.4.4/charset_normalizer-3.4.4.tar.gz",
    ]


def test_candidate_urls_literal_only_site_has_no_pypi_entry() -> None:
    port = _demo_port(master_sites=["https://example.com/dist/"])
    urls = bdp.candidate_urls(port, "charset_normalizer-3.4.4.tar.gz")
    assert urls == ["https://example.com/dist/charset_normalizer-3.4.4.tar.gz"]


# --------------------------------------------------------------------------- #
# Source acquisition — verify-or-refuse, mismatch never retried, connection
# failure DOES fall through to the next mirror.
# --------------------------------------------------------------------------- #


def test_fetch_verified_sdist_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data = b"a fake sdist tarball payload"
    sha = hashlib.sha256(data).hexdigest()
    monkeypatch.setattr(bdp, "_urlopen", lambda url: io.BytesIO(data))
    got = bdp.fetch_verified_sdist(_demo_port(), tmp_path, sha256=sha, size=len(data))
    assert got.read_bytes() == data


def test_fetch_verified_sdist_mismatch_refuses_without_trying_other_mirrors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A checksum/size MISMATCH is a hard refusal — it must NOT silently fall
    through to the next MASTER_SITES candidate (that would mask a poisoned or
    wrong-version mirror). Only the connection-failure branch falls through."""
    good = b"correct payload"
    bad = b"WRONG payload!!"
    calls: list[str] = []

    def fake_urlopen(url: str) -> io.BytesIO:
        calls.append(url)
        return io.BytesIO(bad)

    monkeypatch.setattr(bdp, "_urlopen", fake_urlopen)
    port = _demo_port(master_sites=["PYPI", "https://example.com/fallback/"])
    with pytest.raises(bdp.DepPkgError, match="does not match distinfo"):
        bdp.fetch_verified_sdist(port, tmp_path, sha256=hashlib.sha256(good).hexdigest(), size=len(good))
    assert len(calls) == 1, "a checksum mismatch must refuse immediately, never retry another mirror"


def test_fetch_verified_sdist_connection_failure_falls_through_to_next_mirror(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    good = b"correct payload"
    calls: list[str] = []

    def fake_urlopen(url: str) -> io.BytesIO:
        calls.append(url)
        if len(calls) == 1:
            raise OSError("connection refused")
        return io.BytesIO(good)

    monkeypatch.setattr(bdp, "_urlopen", fake_urlopen)
    port = _demo_port(master_sites=["PYPI", "https://example.com/fallback/"])
    got = bdp.fetch_verified_sdist(port, tmp_path, sha256=hashlib.sha256(good).hexdigest(), size=len(good))
    assert got.read_bytes() == good
    assert len(calls) == 2


def test_fetch_verified_sdist_all_mirrors_failing_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bdp, "_urlopen", lambda url: (_ for _ in ()).throw(OSError("unreachable")))
    port = _demo_port(master_sites=["PYPI"])
    with pytest.raises(bdp.DepPkgError, match="failed to fetch"):
        bdp.fetch_verified_sdist(port, tmp_path, sha256="0" * 64, size=1)


# --------------------------------------------------------------------------- #
# sdist_epoch — the dependency's OWN timestamp (newest member mtime inside the
# verified sdist), never the build clock or ambient SOURCE_DATE_EPOCH
# (issue #2454).
# --------------------------------------------------------------------------- #


def _write_sdist_tar(dest: Path, mtimes: list[int]) -> None:
    with tarfile.open(dest, "w:gz") as tf:
        for i, mtime in enumerate(mtimes):
            data = f"member {i}".encode()
            info = tarfile.TarInfo(name=f"pkg/file{i}.txt")
            info.size = len(data)
            info.mtime = mtime
            tf.addfile(info, io.BytesIO(data))


def test_sdist_epoch_is_the_newest_member_mtime(tmp_path: Path) -> None:
    sdist = tmp_path / "fake.tar.gz"
    _write_sdist_tar(sdist, [100, 300, 200])
    assert bdp.sdist_epoch(sdist) == 300


def test_sdist_epoch_refuses_empty_tar(tmp_path: Path) -> None:
    sdist = tmp_path / "empty.tar.gz"
    with tarfile.open(sdist, "w:gz"):
        pass
    with pytest.raises(bdp.DepPkgError, match="mtime"):
        bdp.sdist_epoch(sdist)


def test_sdist_epoch_refuses_all_zero_mtimes(tmp_path: Path) -> None:
    sdist = tmp_path / "zero.tar.gz"
    _write_sdist_tar(sdist, [0, 0])
    with pytest.raises(bdp.DepPkgError, match="mtime"):
        bdp.sdist_epoch(sdist)


# --------------------------------------------------------------------------- #
# Wheel build — exactly one PURE wheel, or refuse.
# --------------------------------------------------------------------------- #


def test_build_wheel_accepts_single_pure_wheel(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bdp.subprocess, "run", lambda cmd, **k: subprocess.CompletedProcess(cmd, 0))
    wheel_dir = tmp_path / "wheel"
    wheel_dir.mkdir()
    wheel = wheel_dir / "charset_normalizer-3.4.4-py3-none-any.whl"
    wheel.write_bytes(b"")
    got = bdp.build_wheel(tmp_path / "sdist.tar.gz", tmp_path)
    assert got == wheel


def test_build_wheel_refuses_zero_wheels(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bdp.subprocess, "run", lambda cmd, **k: subprocess.CompletedProcess(cmd, 0))
    with pytest.raises(bdp.DepPkgError, match="exactly one wheel"):
        bdp.build_wheel(tmp_path / "sdist.tar.gz", tmp_path)


def test_build_wheel_refuses_multiple_wheels(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bdp.subprocess, "run", lambda cmd, **k: subprocess.CompletedProcess(cmd, 0))
    wheel_dir = tmp_path / "wheel"
    wheel_dir.mkdir()
    (wheel_dir / "a-1.0-py3-none-any.whl").write_bytes(b"")
    (wheel_dir / "b-1.0-py3-none-any.whl").write_bytes(b"")
    with pytest.raises(bdp.DepPkgError, match="exactly one wheel"):
        bdp.build_wheel(tmp_path / "sdist.tar.gz", tmp_path)


def test_build_wheel_refuses_platform_wheel(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bdp.subprocess, "run", lambda cmd, **k: subprocess.CompletedProcess(cmd, 0))
    wheel_dir = tmp_path / "wheel"
    wheel_dir.mkdir()
    (wheel_dir / "charset_normalizer-3.4.4-cp311-cp311-macosx_11_0_arm64.whl").write_bytes(b"")
    with pytest.raises(bdp.DepPkgError, match="not a pure-Python wheel"):
        bdp.build_wheel(tmp_path / "sdist.tar.gz", tmp_path)


def test_build_wheel_sets_pip_constraint_pinning_setuptools_and_wheel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """W4 (supply chain, honest middle ground): `pip wheel`'s pep517 isolated
    build env otherwise fetches whatever's newest on PyPI for the build backend
    itself (setuptools/wheel) -- PIP_CONSTRAINT pins it to exact versions.
    Assert the env var is actually passed on the pip call, pointing at a real
    constraints file naming both packages."""
    captured_envs: list[dict[str, str]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        captured_envs.append(kwargs.get("env") or {})
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(bdp.subprocess, "run", fake_run)
    wheel_dir = tmp_path / "wheel"
    wheel_dir.mkdir()
    (wheel_dir / "charset_normalizer-3.4.4-py3-none-any.whl").write_bytes(b"")

    bdp.build_wheel(tmp_path / "sdist.tar.gz", tmp_path)

    # The pip-wheel call (the last of the two subprocess.run calls: the pip
    # probe in _pip_python, then the actual build) carries PIP_CONSTRAINT.
    pip_wheel_env = captured_envs[-1]
    assert "PIP_CONSTRAINT" in pip_wheel_env, "pip wheel call was not given PIP_CONSTRAINT"
    constraints_path = Path(pip_wheel_env["PIP_CONSTRAINT"])
    assert constraints_path.is_file(), f"PIP_CONSTRAINT points at a nonexistent file: {constraints_path}"
    text = constraints_path.read_text()
    assert "setuptools==" in text
    assert "wheel==" in text


# --------------------------------------------------------------------------- #
# _pip_python — venv fallback when the interpreter has no pip module
# (issue #1806: the PFB_BOXES minimal Debian pool ships python3-venv but not
# pip on /usr/bin/python3; a venv's own bootstrapped pip is always present).
# --------------------------------------------------------------------------- #


def test_pip_python_falls_back_to_venv_when_direct_pip_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        calls.append(cmd)
        if cmd[1:3] == ["-m", "pip"]:
            return subprocess.CompletedProcess(cmd, 1)  # no pip module on sys.executable
        if cmd[1:3] == ["-m", "venv"]:
            return subprocess.CompletedProcess(cmd, 0)  # venv created fine
        raise AssertionError(f"unexpected subprocess.run call: {cmd}")

    monkeypatch.setattr(bdp.subprocess, "run", fake_run)
    python = bdp._pip_python(tmp_path)

    assert python == str(tmp_path / "pip-venv" / "bin" / "python")
    assert python != sys.executable
    assert any(c[1:3] == ["-m", "venv"] for c in calls), f"venv path was not exercised: {calls}"


def test_pip_python_uses_sys_executable_when_pip_already_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The fast path (CI runners): a direct pip probe success skips the venv entirely."""
    monkeypatch.setattr(bdp.subprocess, "run", lambda cmd, **k: subprocess.CompletedProcess(cmd, 0))
    assert bdp._pip_python(tmp_path) == sys.executable


def test_pip_python_raises_when_venv_creation_also_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        if cmd[1:3] == ["-m", "pip"]:
            return subprocess.CompletedProcess(cmd, 1)
        if cmd[1:3] == ["-m", "venv"]:
            raise subprocess.CalledProcessError(1, cmd)
        raise AssertionError(f"unexpected subprocess.run call: {cmd}")

    monkeypatch.setattr(bdp.subprocess, "run", fake_run)
    with pytest.raises(bdp.DepPkgError, match="no pip"):
        bdp._pip_python(tmp_path)


# --------------------------------------------------------------------------- #
# [console_scripts] entry_points.txt parsing
# --------------------------------------------------------------------------- #


def test_parse_console_scripts_basic() -> None:
    text = (
        "[console_scripts]\n"
        "normalizer = charset_normalizer.cli:cli_detect\n"
        "\n"
        "[some.other.group]\n"
        "plugin = charset_normalizer.plugins:register\n"
    )
    assert bdp.parse_console_scripts(text) == {"normalizer": ("charset_normalizer.cli", "cli_detect")}


def test_parse_console_scripts_ignores_comments_and_blank_lines() -> None:
    text = "# a comment\n\n[console_scripts]\n; also a comment\nnormalizer = charset_normalizer.cli:cli_detect\n"
    assert bdp.parse_console_scripts(text) == {"normalizer": ("charset_normalizer.cli", "cli_detect")}


def test_parse_console_scripts_empty_when_no_section() -> None:
    assert bdp.parse_console_scripts("[some.other.group]\nx = y:z\n") == {}


def test_parse_console_scripts_unparseable_line_raises() -> None:
    with pytest.raises(bdp.DepPkgError, match="unparseable"):
        bdp.parse_console_scripts("[console_scripts]\nthis line has no colon target\n")


# --------------------------------------------------------------------------- #
# --py-flavor -> python3.NN dotted version
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("flavor", "dotted"),
    [("py311", "3.11"), ("py310", "3.10"), ("py39", "3.9")],
)
def test_python_dotted_version_derives_from_flavor(flavor: str, dotted: str) -> None:
    assert bdp.python_dotted_version(flavor) == dotted


def test_python_dotted_version_refuses_unknown_flavor() -> None:
    with pytest.raises(bdp.DepPkgError, match="py-flavor"):
        bdp.python_dotted_version("cp311")


# --------------------------------------------------------------------------- #
# Staging: wheel -> site-packages files + console-script stub(s)
# --------------------------------------------------------------------------- #


def test_stage_wheel_lays_out_site_packages_and_console_script(tmp_path: Path) -> None:
    wheel = tmp_path / "mypkg-1.0-py3-none-any.whl"
    _write_wheel(
        wheel,
        files={"mypkg/__init__.py": b"X = 1\n", "mypkg-1.0.dist-info/METADATA": b"Metadata-Version: 2.1\n"},
        entry_points="[console_scripts]\nmycli = mypkg.cli:main\n",
    )
    stage = tmp_path / "stage"
    site_files, script_files = bdp.stage_wheel(wheel, stage, "3.11")

    site_pkg_init = stage / "usr/local/lib/python3.11/site-packages/mypkg/__init__.py"
    assert site_pkg_init in site_files
    assert site_pkg_init.read_bytes() == b"X = 1\n"
    dist_info_meta = stage / "usr/local/lib/python3.11/site-packages/mypkg-1.0.dist-info/METADATA"
    assert dist_info_meta in site_files

    script = stage / "usr/local/bin/mycli"
    assert script_files == [script]
    # Compare against the SAME stub template the production code fills in — a
    # single source of truth, and it never re-embeds the appliance interpreter
    # path as a literal in test code (scripts/check_appliance_python.py scans
    # tests/ for exactly that; the production template lives in scripts/,
    # which is intentionally out of its scope).
    expected = bdp._SCRIPT_STUB.format(py_dotted="3.11", module="mypkg.cli", func="main")
    assert script.read_text() == expected
    assert expected.count("\n") == 8, "the console-script stub must be the standard 8-line launcher"
    assert (script.stat().st_mode & 0o777) == 0o555


def test_stage_wheel_without_entry_points_yields_no_scripts(tmp_path: Path) -> None:
    wheel = tmp_path / "mypkg-1.0-py3-none-any.whl"
    _write_wheel(wheel, files={"mypkg/__init__.py": b"X = 1\n"}, entry_points=None)
    stage = tmp_path / "stage"
    site_files, script_files = bdp.stage_wheel(wheel, stage, "3.11")
    assert script_files == []
    assert len(site_files) == 1


# --------------------------------------------------------------------------- #
# Full orchestration: manifest correctness of the emitted .pkg, read back via
# pfb_pkg.read_compact_manifest (the SAME contract tests/test_pfb_pkg.py pins).
# Network (fetch + `pip wheel`) is mocked; the staging/manifest/write_pkg path
# is REAL.
# --------------------------------------------------------------------------- #


# The sdist's own release stamp — fixed so `sdist_epoch()` has a real member
# mtime to read, independent of whatever ambient SOURCE_DATE_EPOCH a test sets.
_FAKE_SDIST_MTIME = 1700000000


def _write_fake_sdist(dest: Path, *, mtime: int = _FAKE_SDIST_MTIME) -> None:
    with tarfile.open(dest, "w:gz") as tf:
        data = b"Metadata-Version: 1.0\n"
        info = tarfile.TarInfo(name="charset_normalizer-3.4.4/PKG-INFO")
        info.size = len(data)
        info.mtime = mtime
        tf.addfile(info, io.BytesIO(data))


def _mock_network(
    monkeypatch: pytest.MonkeyPatch, *, console_scripts: str | None, sdist_mtime: int = _FAKE_SDIST_MTIME
) -> None:
    def fake_fetch(port: Any, dest_dir: Path, *, sha256: str, size: int) -> Path:
        dest = dest_dir / f"{port.distname}.tar.gz"
        _write_fake_sdist(dest, mtime=sdist_mtime)
        return dest

    def fake_build_wheel(sdist: Path, work_dir: Path) -> Path:
        wheel_dir = work_dir / "wheel"
        wheel_dir.mkdir(parents=True, exist_ok=True)
        wheel = wheel_dir / "charset_normalizer-3.4.4-py3-none-any.whl"
        _write_wheel(
            wheel,
            files={
                "charset_normalizer/__init__.py": b"__version__ = '3.4.4'\n",
                "charset_normalizer-3.4.4.dist-info/METADATA": b"Metadata-Version: 2.1\n",
            },
            entry_points=console_scripts,
        )
        return wheel

    monkeypatch.setattr(bdp, "fetch_verified_sdist", fake_fetch)
    monkeypatch.setattr(bdp, "build_wheel", fake_build_wheel)


def _build_args(ports_root: Path, out_dir: Path) -> argparse.Namespace:
    return argparse.Namespace(
        ports=str(ports_root),
        port="textproc/py-charset-normalizer",
        py_flavor="py311",
        freebsd_major="15",
        python_dep_version="3.11.13",
        out_dir=str(out_dir),
        compression="zstd",
    )


def test_build_dep_pkg_emits_correct_manifest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ports_root = tmp_path / "ports"
    _write_port(ports_root)
    _mock_network(monkeypatch, console_scripts="[console_scripts]\nnormalizer = charset_normalizer.cli:cli_detect\n")

    out_dir = tmp_path / "out"
    out_path = bdp.build_dep_pkg(_build_args(ports_root, out_dir))

    # Canonical <name>-<version>.pkg output filename.
    assert out_path == out_dir / "py311-charset-normalizer-3.4.4.pkg"
    assert out_path.is_file()

    manifest = pfb_pkg.read_compact_manifest(out_path)
    assert manifest["name"] == "py311-charset-normalizer"
    assert manifest["version"] == "3.4.4"
    assert manifest["origin"] == "textproc/py-charset-normalizer"
    assert manifest["abi"] == "FreeBSD:15:*"
    assert manifest["arch"] == "freebsd:15:*"
    assert manifest["categories"] == ["textproc", "python"]
    assert manifest["licenses"] == ["MIT"]
    assert manifest["deps"] == {"python311": {"origin": "lang/python311", "version": "3.11.13"}}

    # File listing + perms live in the FULL +MANIFEST, not the compact one.
    full = _read_full_manifest(out_path)
    files = full["files"]
    assert "/usr/local/lib/python3.11/site-packages/charset_normalizer/__init__.py" in files
    assert "/usr/local/bin/normalizer" in files
    assert files["/usr/local/bin/normalizer"]["perm"] == "0555"
    assert files["/usr/local/lib/python3.11/site-packages/charset_normalizer/__init__.py"]["perm"] == "0644"


def test_build_dep_pkg_no_console_scripts_still_emits_valid_pkg(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A pure-library dependency (no entry points) still produces a valid .pkg
    with no /usr/local/bin files — the console-script stage is optional."""
    ports_root = tmp_path / "ports"
    _write_port(ports_root)
    _mock_network(monkeypatch, console_scripts=None)

    out_dir = tmp_path / "out"
    out_path = bdp.build_dep_pkg(_build_args(ports_root, out_dir))

    full = _read_full_manifest(out_path)
    assert not any(p.startswith("/usr/local/bin/") for p in full["files"])


def test_build_dep_pkg_derives_portname_from_flavor_prefix(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """portname = PKGNAMEPREFIX (from --py-flavor) + PORTNAME — never hardcoded."""
    ports_root = tmp_path / "ports"
    _write_port(ports_root)
    _mock_network(monkeypatch, console_scripts=None)

    out_dir = tmp_path / "out"
    args = _build_args(ports_root, out_dir)
    args.py_flavor = "py310"
    args.python_dep_version = "3.10.9"
    out_path = bdp.build_dep_pkg(args)

    assert out_path.name == "py310-charset-normalizer-3.4.4.pkg"
    manifest = pfb_pkg.read_compact_manifest(out_path)
    assert manifest["name"] == "py310-charset-normalizer"
    assert manifest["deps"] == {"python310": {"origin": "lang/python310", "version": "3.10.9"}}


# --------------------------------------------------------------------------- #
# Ambient SOURCE_DATE_EPOCH independence (issue #2454): dep .pkg bytes are a
# function of the pinned sdist ONLY, never the caller's ambient project epoch.
# --------------------------------------------------------------------------- #


def test_build_dep_pkg_bytes_do_not_depend_on_ambient_source_date_epoch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ports_root = tmp_path / "ports"
    _write_port(ports_root)
    _mock_network(monkeypatch, console_scripts=None)

    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1")
    out_path1 = bdp.build_dep_pkg(_build_args(ports_root, tmp_path / "out1"))
    assert os.environ["SOURCE_DATE_EPOCH"] == "1", "ambient value must be restored after the call"

    monkeypatch.setenv("SOURCE_DATE_EPOCH", "2")
    out_path2 = bdp.build_dep_pkg(_build_args(ports_root, tmp_path / "out2"))
    assert os.environ["SOURCE_DATE_EPOCH"] == "2", "ambient value must be restored after the call"

    assert out_path1.read_bytes() == out_path2.read_bytes(), (
        "two builds of the same dep under different ambient SOURCE_DATE_EPOCH must be byte-identical"
    )

    for out_path in (out_path1, out_path2):
        full = _read_full_manifest(out_path)
        for install_path, entry in full["files"].items():
            assert entry["mtime"] == _FAKE_SDIST_MTIME, f"{install_path}: manifest mtime must be the sdist epoch"

        tar_bytes = pfb_pkg.zstd_decompress(out_path.read_bytes())
        with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tf:
            for member in tf.getmembers():
                if member.name in ("+MANIFEST", "+COMPACT_MANIFEST"):
                    continue
                assert member.mtime == _FAKE_SDIST_MTIME, f"{member.name}: tar mtime must be the sdist epoch"


def test_build_dep_pkg_restores_absent_source_date_epoch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ports_root = tmp_path / "ports"
    _write_port(ports_root)
    _mock_network(monkeypatch, console_scripts=None)
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)

    bdp.build_dep_pkg(_build_args(ports_root, tmp_path / "out"))

    assert "SOURCE_DATE_EPOCH" not in os.environ


def test_build_wheel_runs_pip_with_the_dep_epoch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """build_wheel() is stubbed entirely here (like _mock_network does) — so
    assert the dep epoch is live in os.environ["SOURCE_DATE_EPOCH"] at the
    moment build_wheel() is called (the mechanism that makes the real `pip
    wheel` subprocess, which copies os.environ, stamp the wheel with it)."""
    ports_root = tmp_path / "ports"
    _write_port(ports_root)

    def fake_fetch(port: Any, dest_dir: Path, *, sha256: str, size: int) -> Path:
        dest = dest_dir / f"{port.distname}.tar.gz"
        _write_fake_sdist(dest)
        return dest

    captured: list[str | None] = []

    def fake_build_wheel(sdist: Path, work_dir: Path) -> Path:
        captured.append(os.environ.get("SOURCE_DATE_EPOCH"))
        wheel_dir = work_dir / "wheel"
        wheel_dir.mkdir(parents=True, exist_ok=True)
        wheel = wheel_dir / "charset_normalizer-3.4.4-py3-none-any.whl"
        _write_wheel(wheel, files={"charset_normalizer/__init__.py": b"x = 1\n"}, entry_points=None)
        return wheel

    monkeypatch.setattr(bdp, "fetch_verified_sdist", fake_fetch)
    monkeypatch.setattr(bdp, "build_wheel", fake_build_wheel)
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "999")

    bdp.build_dep_pkg(_build_args(ports_root, tmp_path / "out"))

    assert captured == [str(_FAKE_SDIST_MTIME)]


# --------------------------------------------------------------------------- #
# CLI wiring
# --------------------------------------------------------------------------- #


def test_main_prints_out_path_as_last_stdout_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    ports_root = tmp_path / "ports"
    _write_port(ports_root)
    _mock_network(monkeypatch, console_scripts=None)

    out_dir = tmp_path / "out"
    rc = bdp.main(
        [
            "--ports", str(ports_root),
            "--port", "textproc/py-charset-normalizer",
            "--py-flavor", "py311",
            "--freebsd-major", "15",
            "--python-dep-version", "3.11.13",
            "--out-dir", str(out_dir),
        ]
    )  # fmt: skip
    assert rc == 0
    last_line = capsys.readouterr().out.strip().splitlines()[-1]
    assert last_line == str(out_dir / "py311-charset-normalizer-3.4.4.pkg")


def test_main_stdout_is_only_the_pkg_path_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """main()'s ENTIRE stdout is the emitted .pkg path + newline -- NOTHING else,
    even when a shelled-out tool (pip) is chatty on ITS OWN stdout. An on-box
    caller captures this whole process's stdout as the path (``PKG="$(python3
    build-dep-pkg-portable.py ...)"``); pip's "Processing ...", "Created wheel
    ..." lines leaking onto an inherited stdout got word-split into that
    captured value as garbage (issue #1806 live-leg RED #4). The real
    build_wheel()/_pip_python() run here (not mocked out) so the actual
    subprocess-output-relay path is exercised; ``--compression xz`` sidesteps
    the ALSO-real zstd_compress() subprocess call (stdlib lzma, no subprocess)
    so only the two calls under test need a fake.
    """
    ports_root = tmp_path / "ports"
    _write_port(ports_root)

    def fake_fetch(port: Any, dest_dir: Path, *, sha256: str, size: int) -> Path:
        dest = dest_dir / f"{port.distname}.tar.gz"
        _write_fake_sdist(dest)
        return dest

    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        """Simulates a REAL child's fd-inheritance semantics (not just a canned
        return value): with ``capture_output=True`` its chatter comes back on
        ``.stdout``/``.stderr`` (what a fixed caller relays itself); WITHOUT it,
        a real child would write straight through the inherited fd -- so this
        writes directly to ``sys.stdout``, reproducing the pre-fix leak if the
        caller ever regresses to an uncaptured ``subprocess.run(cmd, check=True)``.
        """
        if cmd[1:3] == ["-m", "pip"] and cmd[3:] == ["--version"]:
            chatter = "pip 24.0\n"
        elif cmd[1:3] == ["-m", "pip"] and "wheel" in cmd:
            wheel_dir = Path(cmd[cmd.index("-w") + 1])
            wheel_dir.mkdir(parents=True, exist_ok=True)
            _write_wheel(
                wheel_dir / "charset_normalizer-3.4.4-py3-none-any.whl",
                files={"charset_normalizer/__init__.py": b"__version__ = '3.4.4'\n"},
                entry_points=None,
            )
            chatter = "Processing /tmp/x.tar.gz\nCreated wheel for charset-normalizer\n"
        else:
            raise AssertionError(f"unexpected subprocess.run call: {cmd}")

        if kwargs.get("capture_output"):
            return subprocess.CompletedProcess(cmd, 0, stdout=chatter, stderr="")
        sys.stdout.write(chatter)
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(bdp, "fetch_verified_sdist", fake_fetch)
    monkeypatch.setattr(bdp.subprocess, "run", fake_run)

    out_dir = tmp_path / "out"
    rc = bdp.main(
        [
            "--ports", str(ports_root),
            "--port", "textproc/py-charset-normalizer",
            "--py-flavor", "py311",
            "--freebsd-major", "15",
            "--compression", "xz",
            "--out-dir", str(out_dir),
        ]
    )  # fmt: skip
    assert rc == 0

    captured = capsys.readouterr()
    assert captured.out == f"{out_dir / 'py311-charset-normalizer-3.4.4.pkg'}\n", (
        f"stdout must be ONLY the .pkg path line; got {captured.out!r}"
    )
    # The pip chatter must still be VISIBLE -- relayed to stderr, never dropped.
    assert "Processing /tmp/x.tar.gz" in captured.err
    assert "Created wheel for charset-normalizer" in captured.err


def test_main_defaults_python_dep_version_to_0_when_omitted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """--python-dep-version is optional (issue #1806 D-fix): pkg(8) resolves a
    dependency by NAME, never by the version recorded in another package's
    manifest, so this field is never enforced at install. lang/python<NNN>'s
    real PORTVERSION also isn't a literal in its Makefile (it's
    ${PYTHON_DISTVERSION}, indirect via Mk/Uses/python.mk) -- deriving it
    honestly needs the ports framework this tool deliberately avoids.
    Omitting the flag must not error, and must record version "0"
    (unknown-at-build), not silently invent a plausible-looking value."""
    ports_root = tmp_path / "ports"
    _write_port(ports_root)
    _mock_network(monkeypatch, console_scripts=None)

    out_dir = tmp_path / "out"
    rc = bdp.main(
        [
            "--ports", str(ports_root),
            "--port", "textproc/py-charset-normalizer",
            "--py-flavor", "py311",
            "--freebsd-major", "15",
            "--out-dir", str(out_dir),
        ]
    )  # fmt: skip
    assert rc == 0
    manifest = pfb_pkg.read_compact_manifest(out_dir / "py311-charset-normalizer-3.4.4.pkg")
    assert manifest["deps"] == {"python311": {"origin": "lang/python311", "version": "0"}}


def test_main_returns_1_and_reports_refusal_on_stderr(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    ports_root = tmp_path / "ports"
    _write_port(ports_root, no_arch_line="")  # missing NO_ARCH -> refusal, no network involved
    rc = bdp.main(
        [
            "--ports", str(ports_root),
            "--port", "textproc/py-charset-normalizer",
            "--py-flavor", "py311",
            "--freebsd-major", "15",
            "--python-dep-version", "3.11.13",
            "--out-dir", str(tmp_path / "out"),
        ]
    )  # fmt: skip
    assert rc == 1
    assert "NO_ARCH" in capsys.readouterr().err
