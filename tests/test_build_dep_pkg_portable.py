"""Tests for scripts/build-dep-pkg-portable.py — the port-driven dependency
package builder (issue #1806 step A).

The fixture Makefile/distinfo/pkg-descr mirror the REAL
textproc/py-charset-normalizer port (captured 2026-08-29 from
freebsd/freebsd-ports commit 0b5f0ee3679181a759e854605154dd6b512e2e9a).
Network (sdist fetch, `pip wheel`) is mocked everywhere here — see the module docstring in
build-dep-pkg-portable.py for the tool's real network behavior; a real build
against an actual ports checkout (genuine sdist fetch + pip wheel) is
validated separately, outside this hermetic suite.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import io
import json
import lzma
import os
import subprocess
import sys
import tarfile
import tomllib
import zipfile
from pathlib import Path
from typing import Any

import pfb_pkg
import pytest

from scripts import tagged_release_handoff as trh
from tests.gitenv import scrubbed_git_env

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
        "PORTVERSION=\t3.4.7\n"
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
    "TIMESTAMP = 1775587602\n"
    "SHA256 (charset_normalizer-3.4.7.tar.gz) = ae89db9e5f98a11a4bf50407d4363e7b09b31e55bc117b4f7d80aab97ba009e5\n"
    "SIZE (charset_normalizer-3.4.7.tar.gz) = 144271\n"
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
        if not any(name.endswith(".dist-info/WHEEL") for name in files):
            zf.writestr(
                "mypkg-1.0.dist-info/WHEEL",
                "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
            )
        if entry_points is not None:
            zf.writestr("mypkg-1.0.dist-info/entry_points.txt", entry_points)


def _read_full_manifest(pkg_path: Path) -> dict:
    """Read the +MANIFEST (file listing + perms) of a .pkg written by write_pkg."""
    tar_bytes = pfb_pkg.zstd_decompress(pkg_path.read_bytes())
    with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tf:
        member = tf.extractfile("+MANIFEST")
        assert member is not None
        return json.loads(member.read())


def _write_compact_package(path: Path, manifest: dict[str, object]) -> None:
    payload = json.dumps(manifest).encode()
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w") as tf:
        member = tarfile.TarInfo("+COMPACT_MANIFEST")
        member.size = len(payload)
        tf.addfile(member, io.BytesIO(payload))
    path.write_bytes(lzma.compress(archive.getvalue()))


def _mutate_xz_dependency_metadata(source: Path, destination: Path, field: str) -> None:
    entries: list[tuple[tarfile.TarInfo, bytes]] = []
    with tarfile.open(fileobj=io.BytesIO(lzma.decompress(source.read_bytes())), mode="r:") as archive:
        for member in archive.getmembers():
            extracted = archive.extractfile(member)
            entries.append((copy.copy(member), b"" if extracted is None else extracted.read()))
    if field == "build-record":
        for index, (manifest_member, manifest_data) in enumerate(entries):
            if manifest_member.name not in ("+COMPACT_MANIFEST", "+MANIFEST"):
                continue
            manifest = json.loads(manifest_data)
            record = json.loads(manifest["annotations"]["pfb_dep_build_record"])
            record["distfile_size"] += 1
            manifest["annotations"]["pfb_dep_build_record"] = json.dumps(
                record,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            manifest_data = json.dumps(
                manifest,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
            manifest_member.size = len(manifest_data)
            entries[index] = (manifest_member, manifest_data)
    else:
        manifest_index = next(index for index, (member, _) in enumerate(entries) if member.name == "+MANIFEST")
        manifest_member, manifest_data = entries[manifest_index]
        manifest = json.loads(manifest_data)
        target = next(iter(manifest["files"]))
        metadata = manifest["files"][target]
        if field == "mode":
            metadata["perm"] = "0755"
        elif field == "mtime":
            metadata["mtime"] = int(metadata["mtime"]) + 1
        elif field == "owner":
            metadata["uname"] = "nobody"
        elif field == "group":
            metadata["gname"] = "evil"
        elif field == "fflags":
            metadata["fflags"] = 1
        elif field == "checksum":
            metadata["sum"] = "1$" + "0" * 64
        else:
            raise AssertionError(field)
        manifest_data = json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        manifest_member.size = len(manifest_data)
        entries[manifest_index] = (manifest_member, manifest_data)
        for member, _ in entries:
            if "/" + member.name.lstrip("/") != target:
                continue
            if field == "mode":
                member.mode = 0o755
            elif field == "mtime":
                member.mtime += 1
            elif field == "owner":
                member.uname = "nobody"
            elif field == "group":
                member.gname = "evil"
            break
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for member, data in entries:
            archive.addfile(member, io.BytesIO(data) if member.isfile() else None)
    destination.write_bytes(lzma.compress(output.getvalue()))


# --------------------------------------------------------------------------- #
# Makefile parsing — every extracted field, and the two hard refusals.
# --------------------------------------------------------------------------- #


def test_read_port_extracts_facts(tmp_path: Path) -> None:
    port_dir = _write_port(tmp_path)
    facts = bdp.read_port(port_dir)
    assert facts.portname == "charset-normalizer"
    assert facts.portversion == "3.4.7"
    assert facts.distname == "charset_normalizer-3.4.7"
    assert facts.comment == "Real First Universal Charset Detector"
    assert facts.maintainer == "sunpoet@FreeBSD.org"
    # WWW carries the FIRST url only, even though the port lists two.
    assert facts.www == "https://charset-normalizer.readthedocs.io/en/latest/"
    assert facts.license == "MIT"
    assert facts.categories == ["textproc", "python"]
    assert facts.master_sites == [
        "PYPI",
        "https://github.com/jawah/charset_normalizer/releases/download/3.4.7/",
    ]


def test_read_port_refuses_missing_no_arch(tmp_path: Path) -> None:
    port_dir = _write_port(tmp_path, no_arch_line="")
    with pytest.raises(bdp.DepPkgError, match="NO_ARCH"):
        bdp.read_port(port_dir)


def test_read_port_refuses_no_arch_explicitly_no(tmp_path: Path) -> None:
    port_dir = _write_port(tmp_path, no_arch_line="NO_ARCH=\tno")
    with pytest.raises(bdp.DepPkgError, match="NO_ARCH"):
        bdp.read_port(port_dir)


def test_read_port_refuses_unsafe_distname(tmp_path: Path) -> None:
    port_dir = _write_port(tmp_path)
    makefile = port_dir / "Makefile"
    makefile.write_text(
        makefile.read_text().replace("DISTNAME=\tcharset_normalizer-${PORTVERSION}", "DISTNAME=\t../../escaped")
    )

    with pytest.raises(bdp.DepPkgError, match="DISTNAME"):
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
    sha, size = bdp.read_distinfo(port_dir, "charset_normalizer-3.4.7.tar.gz")
    assert sha == "ae89db9e5f98a11a4bf50407d4363e7b09b31e55bc117b4f7d80aab97ba009e5"
    assert size == 144271


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
        portversion="3.4.7",
        distname="charset_normalizer-3.4.7",
        comment="x",
        maintainer="",
        www="",
        license="MIT",
        categories=["textproc", "python"],
        master_sites=["PYPI", "https://github.com/jawah/charset_normalizer/releases/download/3.4.7/"],
    )
    base.update(overrides)
    return bdp.PortFacts(**base)  # type: ignore[arg-type]


def test_candidate_urls_pypi_redirector_then_literal_fallback() -> None:
    port = _demo_port()
    urls = bdp.candidate_urls(port, "charset_normalizer-3.4.7.tar.gz")
    assert urls == [
        "https://pypi.io/packages/source/c/charset_normalizer/charset_normalizer-3.4.7.tar.gz",
        "https://github.com/jawah/charset_normalizer/releases/download/3.4.7/charset_normalizer-3.4.7.tar.gz",
    ]


def test_candidate_urls_literal_only_site_has_no_pypi_entry() -> None:
    port = _demo_port(master_sites=["https://example.com/dist/"])
    urls = bdp.candidate_urls(port, "charset_normalizer-3.4.7.tar.gz")
    assert urls == ["https://example.com/dist/charset_normalizer-3.4.7.tar.gz"]


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
# Wheel build — exactly one PURE wheel, or refuse.
# --------------------------------------------------------------------------- #


def test_build_wheel_accepts_single_pure_wheel(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bdp.subprocess, "run", lambda cmd, **k: subprocess.CompletedProcess(cmd, 0))
    wheel_dir = tmp_path / "wheel"
    wheel_dir.mkdir()
    wheel = wheel_dir / "charset_normalizer-3.4.7-py3-none-any.whl"
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
    (wheel_dir / "charset_normalizer-3.4.7-cp311-cp311-macosx_11_0_arm64.whl").write_bytes(b"")
    with pytest.raises(bdp.DepPkgError, match="not a pure-Python wheel"):
        bdp.build_wheel(tmp_path / "sdist.tar.gz", tmp_path)


def test_build_wheel_pins_command_and_sanitized_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[tuple[list[str], dict[str, str]]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        captured.append((cmd, kwargs["env"]))
        return subprocess.CompletedProcess(cmd, 0)

    for name in (
        "LANG",
        "LC_CTYPE",
        "PIP_INDEX_URL",
        "PIP_CONSTRAINT",
        "PYTHONPATH",
        "SETUPTOOLS_SCM_PRETEND_VERSION",
        "SOURCE_DATE_EPOCH",
        "TZ",
        "WHEEL_TOOL",
    ):
        monkeypatch.setenv(name, "hostile")
    monkeypatch.setattr(bdp.subprocess, "run", fake_run)
    wheel_dir = tmp_path / "wheel"
    wheel_dir.mkdir()
    (wheel_dir / "charset_normalizer-3.4.7-py3-none-any.whl").write_bytes(b"")
    sdist = tmp_path / "sdist.tar.gz"

    bdp.build_wheel(sdist, tmp_path, source_date_epoch=1_700_000_000)

    cmd, env = captured[-1]
    assert cmd == [
        sys.executable,
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
    assert env["LANG"] == env["LC_ALL"] == "C"
    assert env["PIP_CONFIG_FILE"] == os.devnull
    assert env["PIP_DISABLE_PIP_VERSION_CHECK"] == env["PIP_NO_INDEX"] == "1"
    assert env["PYTHONHASHSEED"] == "0"
    assert env["SOURCE_DATE_EPOCH"] == "1700000000"
    assert env["TZ"] == "UTC"
    for name in (
        "LC_CTYPE",
        "PIP_INDEX_URL",
        "PIP_CONSTRAINT",
        "PYTHONPATH",
        "SETUPTOOLS_SCM_PRETEND_VERSION",
        "WHEEL_TOOL",
    ):
        assert name not in env


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


def test_parse_console_scripts_refuses_exact_duplicate_name() -> None:
    text = "[console_scripts]\nnormalizer = first:main\nnormalizer = second:main\n"

    with pytest.raises(bdp.DepPkgError, match="duplicate console-script"):
        bdp.parse_console_scripts(text)


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


def test_stage_wheel_refuses_console_script_host_collision(tmp_path: Path) -> None:
    wheel = tmp_path / "mypkg-1.0-py3-none-any.whl"
    _write_wheel(
        wheel,
        files={"mypkg/__init__.py": b"X = 1\n"},
        entry_points="[console_scripts]\nFoo = mypkg:main\nfoo = mypkg:main\n",
    )

    with pytest.raises(bdp.DepPkgError, match="console-script.*collision"):
        bdp.stage_wheel(wheel, tmp_path / "stage", "3.11")


def test_stage_wheel_refuses_non_utf8_entry_points(tmp_path: Path) -> None:
    wheel = tmp_path / "mypkg-1.0-py3-none-any.whl"
    _write_wheel(
        wheel,
        files={
            "mypkg/__init__.py": b"X = 1\n",
            "mypkg-1.0.dist-info/entry_points.txt": b"\xff",
        },
        entry_points=None,
    )

    with pytest.raises(bdp.DepPkgError, match="entry_points.*UTF-8"):
        bdp.stage_wheel(wheel, tmp_path / "stage", "3.11")


def test_stage_wheel_without_entry_points_yields_no_scripts(tmp_path: Path) -> None:
    wheel = tmp_path / "mypkg-1.0-py3-none-any.whl"
    _write_wheel(wheel, files={"mypkg/__init__.py": b"X = 1\n"}, entry_points=None)
    stage = tmp_path / "stage"
    site_files, script_files = bdp.stage_wheel(wheel, stage, "3.11")
    assert script_files == []
    assert len(site_files) == 2


@pytest.mark.parametrize(
    ("member", "data", "message"),
    [
        ("mypkg-1.0.dist-info/WHEEL", b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: cp311-cp311-any\n", "Tag"),
        ("mypkg-1.0.dist-info/WHEEL", b"Wheel-Version: 1.0\nRoot-Is-Purelib: false\nTag: py3-none-any\n", "Pure"),
        ("mypkg/native.so", b"compiled", "compiled"),
        ("../escaped.py", b"escape", "unsafe"),
    ],
)
def test_stage_wheel_refuses_nonportable_members(tmp_path: Path, member: str, data: bytes, message: str) -> None:
    wheel = tmp_path / "mypkg-1.0-py3-none-any.whl"
    files = {
        "mypkg/__init__.py": b"X = 1\n",
        "mypkg-1.0.dist-info/WHEEL": b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        member: data,
    }
    _write_wheel(wheel, files=files, entry_points=None)

    with pytest.raises(bdp.DepPkgError, match=message):
        bdp.stage_wheel(wheel, tmp_path / "stage", "3.11")


def test_stage_wheel_refuses_missing_or_duplicate_metadata(tmp_path: Path) -> None:
    missing = tmp_path / "missing-1.0-py3-none-any.whl"
    with zipfile.ZipFile(missing, "w") as archive:
        archive.writestr("missing/__init__.py", b"")
    with pytest.raises(bdp.DepPkgError, match="exactly one.*WHEEL"):
        bdp.stage_wheel(missing, tmp_path / "missing-stage", "3.11")

    duplicate = tmp_path / "duplicate-1.0-py3-none-any.whl"
    with pytest.warns(UserWarning, match="Duplicate name"):
        with zipfile.ZipFile(duplicate, "w") as archive:
            archive.writestr("duplicate/__init__.py", b"first")
            archive.writestr("duplicate/__init__.py", b"second")
            archive.writestr(
                "duplicate-1.0.dist-info/WHEEL",
                "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
            )
    with pytest.raises(bdp.DepPkgError, match="duplicate"):
        bdp.stage_wheel(duplicate, tmp_path / "duplicate-stage", "3.11")


@pytest.mark.parametrize(
    ("first", "second"),
    [
        ("Demo/module.py", "demo/module.py"),
        ("demo/café.py", "demo/cafe\u0301.py"),
        ("demo/module.py", "demo//module.py"),
        ("demo/module.py", "demo/./module.py"),
    ],
)
def test_stage_wheel_refuses_host_canonical_member_collisions(
    tmp_path: Path,
    first: str,
    second: str,
) -> None:
    wheel = tmp_path / "collision-1.0-py3-none-any.whl"
    _write_wheel(wheel, files={first: b"first", second: b"second"}, entry_points=None)

    with pytest.raises(bdp.DepPkgError, match="unsafe member path|collision"):
        bdp.stage_wheel(wheel, tmp_path / "stage", "3.11")


# --------------------------------------------------------------------------- #
# Full orchestration: manifest correctness of the emitted .pkg, read back via
# pfb_pkg.read_compact_manifest (the SAME contract tests/test_pfb_pkg.py pins).
# Network (fetch + `pip wheel`) is mocked; the staging/manifest/write_pkg path
# is REAL.
# --------------------------------------------------------------------------- #


def _mock_network(monkeypatch: pytest.MonkeyPatch, *, console_scripts: str | None) -> None:
    def fake_fetch(port: Any, dest_dir: Path, *, sha256: str, size: int) -> Path:
        dest = dest_dir / f"{port.distname}.tar.gz"
        dest.write_bytes(b"mocked sdist bytes -- fetch is not exercised here")
        return dest

    def fake_build_wheel(_sdist: Path, work_dir: Path, **_kwargs: Any) -> Path:
        wheel_dir = work_dir / "wheel"
        wheel_dir.mkdir(parents=True, exist_ok=True)
        wheel = wheel_dir / "charset_normalizer-3.4.7-py3-none-any.whl"
        _write_wheel(
            wheel,
            files={
                "charset_normalizer/__init__.py": b"__version__ = '3.4.7'\n",
                "charset_normalizer-3.4.7.dist-info/METADATA": b"Metadata-Version: 2.1\n",
                "charset_normalizer-3.4.7.dist-info/WHEEL": (
                    b"Wheel-Version: 1.0\nGenerator: bdist_wheel (0.45.1)\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
                ),
            },
            entry_points=console_scripts,
        )
        return wheel

    monkeypatch.setattr(bdp, "fetch_verified_sdist", fake_fetch)
    monkeypatch.setattr(bdp, "build_wheel", fake_build_wheel)
    monkeypatch.setattr(bdp.bpp, "_attest_checkout", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        bdp.bpp,
        "_snapshot_checkout",
        lambda checkout, _sha, _dest, payload_root=None: checkout,
    )
    monkeypatch.setattr(bdp, "validate_build_toolchain", lambda: None)


def _build_args(ports_root: Path, out_dir: Path) -> argparse.Namespace:
    return argparse.Namespace(
        ports=str(ports_root),
        port="textproc/py-charset-normalizer",
        py_flavor="py311",
        freebsd_major="15",
        python_dep_version="3.11.13",
        ports_sha="d" * 40,
        source_date_epoch=1_700_000_000,
        out_dir=str(out_dir),
        compression="zstd",
    )


def test_build_dep_pkg_forwards_epoch_and_requires_exact_ports_attestation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ports_root = tmp_path / "ports"
    _write_port(ports_root)
    _mock_network(monkeypatch, console_scripts=None)
    fake_build_wheel = bdp.build_wheel
    calls: list[tuple[object, ...]] = []

    def validate_toolchain() -> None:
        calls.append(("toolchain",))

    def attest_ports(path: Path, sha: str, label: str, *, payload_root: Path) -> None:
        calls.append(("attest", path, sha, label, payload_root))

    def snapshot_ports(path: Path, sha: str, dest: Path, payload_root: Path) -> Path:
        calls.append(("snapshot", path, sha, dest, payload_root))
        return path

    def build_wheel(sdist: Path, work_dir: Path, *, source_date_epoch: int) -> Path:
        calls.append(("wheel", source_date_epoch))
        return fake_build_wheel(sdist, work_dir, source_date_epoch=source_date_epoch)

    monkeypatch.setattr(bdp, "validate_build_toolchain", validate_toolchain)
    monkeypatch.setattr(bdp.bpp, "_attest_checkout", attest_ports)
    monkeypatch.setattr(bdp.bpp, "_snapshot_checkout", snapshot_ports)
    monkeypatch.setattr(bdp, "build_wheel", build_wheel)
    args = _build_args(ports_root, tmp_path / "out")

    bdp.build_dep_pkg(args)

    assert calls[0] == ("toolchain",)
    assert calls[1] == ("attest", Path(args.ports), args.ports_sha, "FreeBSD-ports", ports_root / args.port)
    assert calls[2][:3] == ("snapshot", Path(args.ports), args.ports_sha)
    snapshot_dest = calls[2][3]
    assert isinstance(snapshot_dest, Path)
    assert snapshot_dest.name == "ports-snapshot"
    assert calls[2][4] == ports_root / args.port
    assert calls[3] == ("wheel", args.source_date_epoch)


def test_build_dep_pkg_consumes_the_pinned_ports_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ports_root = tmp_path / "ports"
    _write_port(ports_root)
    snapshot_root = tmp_path / "snapshot"
    snapshot_port = _write_port(snapshot_root)
    for name in ("Makefile", "distinfo"):
        path = snapshot_port / name
        path.write_text(path.read_text().replace("3.4.7", "9.9.9"))
    _mock_network(monkeypatch, console_scripts=None)
    monkeypatch.setattr(
        bdp.bpp,
        "_snapshot_checkout",
        lambda *_args, **_kwargs: snapshot_root,
    )

    package = bdp.build_dep_pkg(_build_args(ports_root, tmp_path / "out"))
    manifest = pfb_pkg.read_compact_manifest(package)
    record = json.loads(manifest["annotations"]["pfb_dep_build_record"])

    assert manifest["version"] == "9.9.9"
    assert record["distfile"] == "charset_normalizer-9.9.9.tar.gz"


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        env=scrubbed_git_env(drop_git_vars=True),
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def test_build_dep_pkg_refuses_tracked_port_symlink_escape(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    external_port = _write_port(tmp_path / "external")
    ports_root = tmp_path / "ports"
    (ports_root / "textproc").mkdir(parents=True)
    (ports_root / "textproc" / "py-charset-normalizer").symlink_to(external_port, target_is_directory=True)
    _git(ports_root, "init", "-q")
    _git(ports_root, "config", "user.name", "test")
    _git(ports_root, "config", "user.email", "test@example.invalid")
    _git(ports_root, "add", ".")
    _git(ports_root, "commit", "-q", "-m", "fixture")
    ports_sha = _git(ports_root, "rev-parse", "HEAD")
    real_attest = bdp.bpp._attest_checkout
    real_snapshot = bdp.bpp._snapshot_checkout
    _mock_network(monkeypatch, console_scripts=None)
    monkeypatch.setattr(bdp.bpp, "_attest_checkout", real_attest)
    args = _build_args(ports_root, tmp_path / "out")
    monkeypatch.setattr(bdp.bpp, "_snapshot_checkout", real_snapshot)
    args.ports_sha = ports_sha

    with pytest.raises(bdp.bpp.BuildError, match="payload root|symlink|escapes"):
        bdp.build_dep_pkg(args)


def test_build_dep_pkg_refuses_unsafe_port_origin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write_port(tmp_path / "external")
    ports_root = tmp_path / "ports"
    ports_root.mkdir()
    _mock_network(monkeypatch, console_scripts=None)
    args = _build_args(ports_root, tmp_path / "out")
    args.port = "../external/textproc/py-charset-normalizer"

    with pytest.raises(bdp.DepPkgError, match="port origin"):
        bdp.build_dep_pkg(args)


def test_source_epoch_changes_normalized_payload_mtimes_and_package_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ports_root = tmp_path / "ports"
    _write_port(ports_root)
    _mock_network(monkeypatch, console_scripts=None)
    first_args = _build_args(ports_root, tmp_path / "first")
    second_args = _build_args(ports_root, tmp_path / "second")
    second_args.source_date_epoch += 1

    first = bdp.build_dep_pkg(first_args)
    second = bdp.build_dep_pkg(second_args)
    first_evidence = pfb_pkg.inspect_pkg(first)
    second_evidence = pfb_pkg.inspect_pkg(second)

    assert hashlib.sha256(first.read_bytes()).digest() != hashlib.sha256(second.read_bytes()).digest()
    for evidence, epoch in (
        (first_evidence, first_args.source_date_epoch),
        (second_evidence, second_args.source_date_epoch),
    ):
        member_info = evidence["member_info"]
        assert isinstance(member_info, dict)
        payload_mtimes = {int(member.mtime) for name, member in member_info.items() if not name.startswith("+")}
        assert payload_mtimes == {epoch}


def test_build_dep_pkg_emits_correct_manifest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ports_root = tmp_path / "ports"
    _write_port(ports_root)
    _mock_network(monkeypatch, console_scripts="[console_scripts]\nnormalizer = charset_normalizer.cli:cli_detect\n")

    out_dir = tmp_path / "out"
    out_path = bdp.build_dep_pkg(_build_args(ports_root, out_dir))

    # Canonical <name>-<version>.pkg output filename.
    assert out_path == out_dir / "py311-charset-normalizer-3.4.7.pkg"
    assert out_path.is_file()

    manifest = pfb_pkg.read_compact_manifest(out_path)
    assert manifest["name"] == "py311-charset-normalizer"
    assert manifest["version"] == "3.4.7"
    assert manifest["origin"] == "textproc/py-charset-normalizer"
    assert manifest["abi"] == "FreeBSD:15:*"
    assert manifest["arch"] == "freebsd:15:*"
    assert manifest["categories"] == ["textproc", "python"]
    assert manifest["licenses"] == ["MIT"]
    assert manifest["deps"] == {"python311": {"origin": "lang/python311", "version": "3.11.13"}}
    dep_record = json.loads(manifest["annotations"]["pfb_dep_build_record"])
    assert dep_record == {
        "schema": 1,
        "freebsd_ports_sha": "d" * 40,
        "port_origin": "textproc/py-charset-normalizer",
        "port_version": "3.4.7",
        "distfile": "charset_normalizer-3.4.7.tar.gz",
        "distfile_sha256": "ae89db9e5f98a11a4bf50407d4363e7b09b31e55bc117b4f7d80aab97ba009e5",
        "distfile_size": 144271,
        "py_flavor": "py311",
        "freebsd_major": "15",
        "abi": "FreeBSD:15:*",
        "source_date_epoch": 1_700_000_000,
        "toolchain": bdp.build_toolchain_identity(),
    }

    # File listing + perms live in the FULL +MANIFEST, not the compact one.
    full = _read_full_manifest(out_path)
    files = full["files"]
    assert "/usr/local/lib/python3.11/site-packages/charset_normalizer/__init__.py" in files
    assert "/usr/local/bin/normalizer" in files
    assert files["/usr/local/bin/normalizer"]["perm"] == "0555"
    assert files["/usr/local/lib/python3.11/site-packages/charset_normalizer/__init__.py"]["perm"] == "0644"


def _tagged_handoff_for_real_dependency(tagged_package: Path) -> tuple[dict[str, object], Path]:
    row = {
        "pfsense_version": "2.8",
        "channel": "CE",
        "freebsd_version": "15.0-RELEASE",
        "freebsd_major": "15",
        "php_version": "8.3",
        "py_flavor": "py311",
        "variant": "CE",
        "status": "active",
        "extra_pkgs": ["textproc/py-charset-normalizer"],
    }
    toolchain = bdp.build_toolchain_identity()
    handoff = trh.build_handoff(
        release_tag="v4.0.0.b1",
        source_sha="a" * 40,
        ci_metadata_sha="b" * 40,
        ports_sha="d" * 40,
        route_matrix=[row],
        dependency_packages={
            "-CE-2.8.pkg": {
                "textproc/py-charset-normalizer": {
                    "portname": "charset-normalizer",
                    "port_version": "3.4.7",
                    "distfile": "charset_normalizer-3.4.7.tar.gz",
                    "distfile_sha256": ("ae89db9e5f98a11a4bf50407d4363e7b09b31e55bc117b4f7d80aab97ba009e5"),
                    "distfile_size": 144_271,
                    "package_name": "py311-charset-normalizer",
                    "package_version": "3.4.7",
                    "filename": "py311-charset-normalizer-3.4.7-CE-2.8.pkg",
                    "freebsd_ports_sha": "d" * 40,
                    "source_date_epoch": 1_700_000_000,
                    "toolchain": toolchain,
                    "abi": "FreeBSD:15:*",
                    "freebsd_major": "15",
                    "py_flavor": "py311",
                }
            }
        },
        source_date_epoch=1_700_000_000,
        dependency_builder=toolchain,
    )
    normalized_rows = handoff["route_matrix"]
    assert isinstance(normalized_rows, list)
    normalized_row = normalized_rows[0]
    assert isinstance(normalized_row, dict)
    record: dict[str, object] = {
        "schema": 1,
        "channel": "edge",
        "release_line": "release/4.0",
        "classification": "beta",
        "source_tag": "v4.0.0.b1",
        "source_sha": "a" * 40,
        "canonical_package_version": "4.0.0.b1",
        "native_recipe_identity": "pfSense-pkg-pfBlockerNG-edge",
        "emitted_identity": pfb_pkg.CANONICAL_EMITTED_IDENTITY,
        "matrix_row": normalized_row,
        "freebsd_ports_sha": "d" * 40,
        "route": "edge/ce-2.8",
        "source_date_epoch": 1_700_000_000,
        "dependency_builder": toolchain,
        "build_input_digest": "",
    }
    record["build_input_digest"] = pfb_pkg.build_input_digest(record)
    canonical_package = tagged_package.with_name("pfSense-pkg-pfBlockerNG-4.0.0.b1-CE-2.8.pkg")
    _write_compact_package(
        canonical_package,
        {
            "name": pfb_pkg.CANONICAL_EMITTED_IDENTITY,
            "version": "4.0.0.b1",
            "origin": "net/pfSense-pkg-pfBlockerNG",
            "abi": "FreeBSD:15:*",
            "arch": "freebsd:15:*",
            "prefix": "/usr/local",
            "annotations": {pfb_pkg.PFB_BUILD_RECORD_KEY: json.dumps(record)},
        },
    )
    return handoff, canonical_package


def test_real_dependency_builder_output_passes_tagged_dependency_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ports_root = tmp_path / "ports"
    _write_port(ports_root)
    _mock_network(monkeypatch, console_scripts=None)
    args = _build_args(ports_root, tmp_path / "out")
    args.compression = "xz"
    package = bdp.build_dep_pkg(args)
    tagged_package = package.with_name(f"{package.stem}-CE-2.8.pkg")
    package.rename(tagged_package)
    handoff, canonical_package = _tagged_handoff_for_real_dependency(tagged_package)

    trh.validate_packages(handoff, [canonical_package, tagged_package])


@pytest.mark.parametrize(
    ("field", "message"),
    [
        ("mode", "metadata"),
        ("mtime", "metadata"),
        ("owner", "metadata"),
        ("group", "metadata"),
        ("fflags", "metadata"),
        ("checksum", "checksum"),
        ("build-record", "distfile_size"),
    ],
)
def test_real_dependency_package_mutations_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    message: str,
) -> None:
    ports_root = tmp_path / "ports"
    _write_port(ports_root)
    _mock_network(monkeypatch, console_scripts=None)
    args = _build_args(ports_root, tmp_path / "out")
    args.compression = "xz"
    package = bdp.build_dep_pkg(args)
    tagged_package = package.with_name(f"{package.stem}-CE-2.8.pkg")
    package.rename(tagged_package)
    handoff, canonical_package = _tagged_handoff_for_real_dependency(tagged_package)
    mutated_dir = tmp_path / field
    mutated_dir.mkdir()
    mutated_package = mutated_dir / tagged_package.name
    _mutate_xz_dependency_metadata(tagged_package, mutated_package, field)

    with pytest.raises(trh.HandoffError, match=message):
        trh.validate_packages(handoff, [canonical_package, mutated_package])


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

    assert out_path.name == "py310-charset-normalizer-3.4.7.pkg"
    manifest = pfb_pkg.read_compact_manifest(out_path)
    assert manifest["name"] == "py310-charset-normalizer"
    assert manifest["deps"] == {"python310": {"origin": "lang/python310", "version": "3.10.9"}}


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
            "--ports-sha", "d" * 40,
            "--source-date-epoch", "1700000000",
            "--python-dep-version", "3.11.13",
            "--out-dir", str(out_dir),
        ]
    )  # fmt: skip
    assert rc == 0
    last_line = capsys.readouterr().out.strip().splitlines()[-1]
    assert last_line == str(out_dir / "py311-charset-normalizer-3.4.7.pkg")


def test_main_stdout_is_only_the_pkg_path_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """main()'s ENTIRE stdout is the emitted .pkg path + newline -- NOTHING else,
    even when a shelled-out tool (pip) is chatty on ITS OWN stdout. An on-box
    caller captures this whole process's stdout as the path (``PKG="$(python3
    build-dep-pkg-portable.py ...)"``); pip's "Processing ...", "Created wheel
    ..." lines leaking onto an inherited stdout got word-split into that
    captured value as garbage (issue #1806 live-leg RED #4). The real
    build_wheel() runs here (not mocked out), so the actual subprocess-output
    relay path is exercised; ``--compression xz`` sidesteps the ALSO-real
    zstd_compress() subprocess call (stdlib lzma), leaving one child call.
    """
    ports_root = tmp_path / "ports"
    _write_port(ports_root)

    def fake_fetch(port: Any, dest_dir: Path, *, sha256: str, size: int) -> Path:
        dest = dest_dir / f"{port.distname}.tar.gz"
        dest.write_bytes(b"mocked sdist bytes")
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
                wheel_dir / "charset_normalizer-3.4.7-py3-none-any.whl",
                files={"charset_normalizer/__init__.py": b"__version__ = '3.4.7'\n"},
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
    monkeypatch.setattr(bdp.bpp, "_attest_checkout", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        bdp.bpp,
        "_snapshot_checkout",
        lambda checkout, _sha, _dest, payload_root=None: checkout,
    )
    monkeypatch.setattr(bdp, "validate_build_toolchain", lambda: None)

    out_dir = tmp_path / "out"
    rc = bdp.main(
        [
            "--ports", str(ports_root),
            "--port", "textproc/py-charset-normalizer",
            "--py-flavor", "py311",
            "--freebsd-major", "15",
            "--ports-sha", "d" * 40,
            "--source-date-epoch", "1700000000",
            "--compression", "xz",
            "--out-dir", str(out_dir),
        ]
    )  # fmt: skip
    assert rc == 0

    captured = capsys.readouterr()
    assert captured.out == f"{out_dir / 'py311-charset-normalizer-3.4.7.pkg'}\n", (
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
            "--ports-sha", "d" * 40,
            "--source-date-epoch", "1700000000",
            "--out-dir", str(out_dir),
        ]
    )  # fmt: skip
    assert rc == 0
    manifest = pfb_pkg.read_compact_manifest(out_dir / "py311-charset-normalizer-3.4.7.pkg")
    assert manifest["deps"] == {"python311": {"origin": "lang/python311", "version": "0"}}


def test_main_returns_1_and_reports_refusal_on_stderr(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ports_root = tmp_path / "ports"
    _write_port(ports_root, no_arch_line="")  # missing NO_ARCH -> refusal, no network involved
    monkeypatch.setattr(bdp, "validate_build_toolchain", lambda: None)
    monkeypatch.setattr(bdp.bpp, "_attest_checkout", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        bdp.bpp,
        "_snapshot_checkout",
        lambda checkout, _sha, _dest, payload_root=None: checkout,
    )
    rc = bdp.main(
        [
            "--ports", str(ports_root),
            "--port", "textproc/py-charset-normalizer",
            "--py-flavor", "py311",
            "--freebsd-major", "15",
            "--ports-sha", "d" * 40,
            "--source-date-epoch", "1700000000",
            "--python-dep-version", "3.11.13",
            "--out-dir", str(tmp_path / "out"),
        ]
    )  # fmt: skip
    assert rc == 1
    assert "NO_ARCH" in capsys.readouterr().err


def test_freebsd_majors_retain_target_specific_identity(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ports_root = tmp_path / "ports"
    _write_port(ports_root)
    _mock_network(monkeypatch, console_scripts=None)
    first = bdp.build_dep_pkg(_build_args(ports_root, tmp_path / "major-15"))
    second_args = _build_args(ports_root, tmp_path / "major-16")
    second_args.freebsd_major = "16"
    second = bdp.build_dep_pkg(second_args)

    assert hashlib.sha256(first.read_bytes()).digest() != hashlib.sha256(second.read_bytes()).digest()
    for pkg, major in ((first, "15"), (second, "16")):
        manifest = pfb_pkg.read_compact_manifest(pkg)
        assert manifest["abi"] == f"FreeBSD:{major}:*"
        assert manifest["arch"] == f"freebsd:{major}:*"
        dep_record = json.loads(manifest["annotations"]["pfb_dep_build_record"])
        assert dep_record["abi"] == f"FreeBSD:{major}:*"
        assert dep_record["freebsd_major"] == major


@pytest.mark.parametrize("name", ["python", "pip", "setuptools", "wheel", "zstandard", "uv"])
def test_build_toolchain_rejects_explicit_drift(name: str, monkeypatch: pytest.MonkeyPatch) -> None:
    installed = {**bdp._BUILD_TOOLCHAIN, "uv": bdp._UV_VERSION}
    installed[name] = "999.0"
    monkeypatch.setattr(bdp, "_installed_build_toolchain", lambda: installed)

    with pytest.raises(bdp.DepPkgError, match=name):
        bdp.validate_build_toolchain()


def test_installed_toolchain_uses_uv_from_the_active_locked_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []

    def fake_run(cmd: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="uv 0.12.6\n", stderr="")

    monkeypatch.setattr(bdp.subprocess, "run", fake_run)
    monkeypatch.setattr(bdp.importlib.metadata, "version", lambda name: bdp._BUILD_TOOLCHAIN[name])

    bdp._installed_build_toolchain()

    assert calls == [[str(Path(sys.executable).with_name("uv")), "--version"]]


def test_source_epoch_and_ports_identity_fail_closed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    args = _build_args(tmp_path / "ports", tmp_path / "out")
    for invalid in (-1, bdp.bpp._USTAR_MAX_MTIME + 1):
        args.source_date_epoch = invalid
        with pytest.raises(bdp.bpp.BuildError, match="source-date-epoch"):
            bdp._source_date_epoch(args)

    args.source_date_epoch = 1_700_000_000
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000001")
    with pytest.raises(bdp.DepPkgError, match="must match"):
        bdp._source_date_epoch(args)
    monkeypatch.delenv("SOURCE_DATE_EPOCH")
    _write_port(Path(args.ports))
    _mock_network(monkeypatch, console_scripts=None)

    for ports_sha in ("D" * 40, "d" * 39, "d" * 41, "g" * 40, "d" * 64):
        args.ports_sha = ports_sha
        with pytest.raises(bdp.DepPkgError, match="ports-sha"):
            bdp.build_dep_pkg(args)


def test_cli_requires_an_explicit_source_epoch(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        bdp.main(
            [
                "--ports",
                str(tmp_path / "ports"),
                "--ports-sha",
                "d" * 40,
                "--port",
                "textproc/py-charset-normalizer",
                "--py-flavor",
                "py311",
                "--freebsd-major",
                "15",
                "--out-dir",
                str(tmp_path / "out"),
            ]
        )


def test_print_toolchain_binds_the_lock_file(capsys: pytest.CaptureFixture[str]) -> None:
    assert bdp.main(["--print-toolchain"]) == 0
    identity = json.loads(capsys.readouterr().out)
    assert identity == bdp.build_toolchain_identity()
    assert identity["uv_lock_sha256"] == hashlib.sha256((bdp._REPO_ROOT / "uv.lock").read_bytes()).hexdigest()


def test_print_port_identity_reads_the_pinned_recipe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ports_root = tmp_path / "ports"
    _write_port(ports_root)
    _mock_network(monkeypatch, console_scripts=None)

    assert (
        bdp.main(
            [
                "--print-port-identity",
                "--ports",
                str(ports_root),
                "--ports-sha",
                "d" * 40,
                "--port",
                "textproc/py-charset-normalizer",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out) == {
        "port_origin": "textproc/py-charset-normalizer",
        "portname": "charset-normalizer",
        "port_version": "3.4.7",
        "distfile": "charset_normalizer-3.4.7.tar.gz",
        "distfile_sha256": "ae89db9e5f98a11a4bf50407d4363e7b09b31e55bc117b4f7d80aab97ba009e5",
        "distfile_size": 144_271,
    }


def test_print_port_identity_consumes_pinned_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ports_root = tmp_path / "ports"
    _write_port(ports_root)
    snapshot_root = tmp_path / "snapshot"
    snapshot_port = _write_port(snapshot_root)
    for name in ("Makefile", "distinfo"):
        path = snapshot_port / name
        path.write_text(path.read_text().replace("3.4.7", "9.9.9"))
    calls: list[tuple[object, ...]] = []

    def attest(path: Path, sha: str, label: str, *, payload_root: Path) -> None:
        calls.append(("attest", path, sha, label, payload_root))

    def snapshot(path: Path, sha: str, dest: Path, *, payload_root: Path) -> Path:
        calls.append(("snapshot", path, sha, dest, payload_root))
        return snapshot_root

    monkeypatch.setattr(bdp.bpp, "_attest_checkout", attest)
    monkeypatch.setattr(bdp.bpp, "_snapshot_checkout", snapshot)
    args = argparse.Namespace(
        ports=str(ports_root),
        ports_sha="d" * 40,
        port="textproc/py-charset-normalizer",
    )

    identity = bdp.dependency_port_identity(args)

    assert identity["port_version"] == "9.9.9"
    assert identity["distfile"] == "charset_normalizer-9.9.9.tar.gz"
    port_payload = ports_root / args.port
    assert calls[0] == ("attest", ports_root, args.ports_sha, "FreeBSD-ports", port_payload)
    assert calls[1][0:3] == ("snapshot", ports_root, args.ports_sha)
    assert isinstance(calls[1][3], Path)
    assert calls[1][3].name == "ports-snapshot"
    assert calls[1][4] == port_payload


def test_dependency_build_group_and_lock_use_exact_pins() -> None:
    root = bdp._REPO_ROOT
    assert (root / ".python-version").read_text(encoding="utf-8") == "3.11.15\n"
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    assert project["dependency-groups"]["dep-pkg-build"] == [
        "pip==26.2.1",
        "setuptools==75.6.0",
        "wheel==0.45.1",
        "zstandard==0.25.0",
        "uv==0.12.6",
    ]
    lock = tomllib.loads((root / "uv.lock").read_text(encoding="utf-8"))
    versions = {package["name"]: package["version"] for package in lock["package"]}
    assert {name: versions[name] for name in ("pip", "setuptools", "uv", "wheel", "zstandard")} == {
        "pip": "26.2.1",
        "setuptools": "75.6.0",
        "uv": "0.12.6",
        "wheel": "0.45.1",
        "zstandard": "0.25.0",
    }
