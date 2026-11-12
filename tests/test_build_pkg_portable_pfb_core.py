"""The pfb-core payload of the portable package build (issue #3841, the Core daemon's own binary).

A source carrying `go/pfb_core` beside the gateway gets pfb-core cross-built by build-pfb-dns.py. A port recipe
without `do-build` has the builder stage both architectures' pfb-core under pkg/pfblockerng/core/bin, executable,
as it stages pfb-dns; the go recipe installs what its own `do-build` built. A pfb-core committed to the source is
refused like a committed pfb-dns. Every case drives the real builder and Go toolchain and reads the `.pkg` back.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from tests.elf_facts import ELFOSABI_FREEBSD, ET_EXEC, elf_facts
from tests.test_build_pkg_portable import _read_pkg
from tests.test_build_pkg_portable_pfb_dns import FORGED, PKG_NAME, TARGETS, build, make_fixture, member

CORE = "usr/local/pkg/pfblockerng/core"
CORE_BIN = f"/{CORE}/bin"
TINY_CORE = {
    "go/pfb_core/go.mod": b"module example.test/pfbcore\n\ngo 1.21\n",
    "go/pfb_core/main.go": b'package main\n\nvar marker = "CORE-SOURCE"\n\nfunc main() { println(marker) }\n',
}


@pytest.mark.parametrize("mode", ["native", "project"])
def test_builder_staging_ships_pfb_core_for_both_architectures(tmp_path: Path, mode: str) -> None:
    """
    Scenario: a port without do-build, over a source that carries the Core module
      When the package is built
      Then pfb-core ships for both FreeBSD architectures under core/bin, mode 0555, each the right static ELF
    """
    fx = make_fixture(tmp_path, source_files=TINY_CORE)
    assert build(fx, mode, tmp_path / "out") == 0
    full, _compact, tf = _read_pkg(tmp_path / "out" / PKG_NAME)
    shipped = sorted(path for path in full["files"] if path.startswith(f"{CORE_BIN}/"))
    assert shipped == sorted(f"{CORE_BIN}/{target}/pfb-core" for target in TARGETS)
    for target, machine in TARGETS.items():
        path = f"{CORE_BIN}/{target}/pfb-core"
        assert full["files"][path]["perm"] == "0555", f"{path} manifest perm {full['files'][path]['perm']}"
        data = member(tf, path)
        assert full["files"][path]["sum"] == "1$" + hashlib.sha256(data).hexdigest()
        assert b"CORE-SOURCE" in data, f"{path} is not the Core binary"
        assert elf_facts(data) == {
            "osabi": ELFOSABI_FREEBSD,
            "type": ET_EXEC,
            "machine": machine,
            "has_interpreter": False,
            "has_freebsd_abi_note": True,
        }, f"{path} is not the {target} ELF"


@pytest.mark.parametrize("mode", ["native", "project"])
def test_a_source_without_the_core_module_ships_no_pfb_core(tmp_path: Path, mode: str) -> None:
    fx = make_fixture(tmp_path)
    assert build(fx, mode, tmp_path / "out") == 0
    full, _compact, _tf = _read_pkg(tmp_path / "out" / PKG_NAME)
    assert [path for path in full["files"] if path.startswith(f"/{CORE}/")] == []


@pytest.mark.parametrize("recipe", ["legacy", "go"])
def test_a_pfb_core_committed_to_the_source_fails_the_build(
    tmp_path: Path, capfd: pytest.CaptureFixture[str], recipe: str
) -> None:
    forged = {**TINY_CORE, f"src/{CORE}/bin/freebsd-amd64/pfb-core": FORGED}
    fx = make_fixture(tmp_path, source_files=forged, recipe=recipe)
    assert build(fx, "native", tmp_path / "out") == 1
    assert "core/bin" in capfd.readouterr().err
    assert not list((tmp_path / "out").glob("*.pkg")), "a package shipped a source-tree binary"
