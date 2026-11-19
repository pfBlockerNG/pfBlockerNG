"""The pfb_crowdsec payload of the portable package build (issue #4069, the CrowdSec bouncer daemon).

A source carrying `go/pfb_crowdsec` gets it cross-built by build-pfb-dns.py beside pfb-dns. A port recipe without
`do-build` has the builder stage both architectures' binary under pkg/pfblockerng/crowdsec/bin, executable; the go
recipe installs what its own `do-build` built. A binary committed to the source is refused like a committed pfb-dns.
Every case drives the real builder and Go toolchain and reads the `.pkg` back.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from tests.elf_facts import ELFOSABI_FREEBSD, ET_EXEC, elf_facts
from tests.test_build_pkg_portable import _read_pkg
from tests.test_build_pkg_portable_pfb_dns import FORGED, PKG_NAME, TARGETS, build, make_fixture, member

CROWDSEC = "usr/local/pkg/pfblockerng/crowdsec"
CROWDSEC_BIN = f"/{CROWDSEC}/bin"
TINY_CROWDSEC = {
    "go/pfb_crowdsec/go.mod": b"module example.test/pfbcrowdsec\n\ngo 1.21\n",
    "go/pfb_crowdsec/main.go": b'package main\n\nvar marker = "CROWDSEC-SOURCE"\n\nfunc main() { println(marker) }\n',
}


@pytest.mark.parametrize("mode", ["native", "project"])
def test_builder_staging_ships_pfb_crowdsec_for_both_architectures(tmp_path: Path, mode: str) -> None:
    """
    Scenario: a port without do-build, over a source that carries the CrowdSec module
      When the package is built
      Then pfb_crowdsec ships for both FreeBSD architectures under crowdsec/bin, mode 0555, each the right static ELF
    """
    fx = make_fixture(tmp_path, source_files=TINY_CROWDSEC)
    assert build(fx, mode, tmp_path / "out") == 0
    full, _compact, tf = _read_pkg(tmp_path / "out" / PKG_NAME)
    shipped = sorted(path for path in full["files"] if path.startswith(f"{CROWDSEC_BIN}/"))
    assert shipped == sorted(f"{CROWDSEC_BIN}/{target}/pfb_crowdsec" for target in TARGETS)
    for target, machine in TARGETS.items():
        path = f"{CROWDSEC_BIN}/{target}/pfb_crowdsec"
        assert full["files"][path]["perm"] == "0555", f"{path} manifest perm {full['files'][path]['perm']}"
        data = member(tf, path)
        assert full["files"][path]["sum"] == "1$" + hashlib.sha256(data).hexdigest()
        assert b"CROWDSEC-SOURCE" in data, f"{path} is not the CrowdSec binary"
        assert elf_facts(data) == {
            "osabi": ELFOSABI_FREEBSD,
            "type": ET_EXEC,
            "machine": machine,
            "has_interpreter": False,
            "has_freebsd_abi_note": True,
        }, f"{path} is not the {target} ELF"


@pytest.mark.parametrize("mode", ["native", "project"])
def test_a_source_without_the_crowdsec_module_ships_no_pfb_crowdsec(tmp_path: Path, mode: str) -> None:
    fx = make_fixture(tmp_path)
    assert build(fx, mode, tmp_path / "out") == 0
    full, _compact, _tf = _read_pkg(tmp_path / "out" / PKG_NAME)
    assert [path for path in full["files"] if path.startswith(f"/{CROWDSEC}/")] == []


@pytest.mark.parametrize("recipe", ["legacy", "go"])
def test_a_pfb_crowdsec_committed_to_the_source_fails_the_build(
    tmp_path: Path, capfd: pytest.CaptureFixture[str], recipe: str
) -> None:
    forged = {**TINY_CROWDSEC, f"src/{CROWDSEC}/bin/freebsd-amd64/pfb_crowdsec": FORGED}
    fx = make_fixture(tmp_path, source_files=forged, recipe=recipe)
    assert build(fx, "native", tmp_path / "out") == 1
    assert "crowdsec/bin" in capfd.readouterr().err
    assert not list((tmp_path / "out").glob("*.pkg")), "a package shipped a source-tree binary"
