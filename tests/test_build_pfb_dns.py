"""Tests for scripts/build-pfb-dns.py (issue #3513, dual-architecture package).

The helper cross-compiles the pfB-DNS gateway for FreeBSD amd64 and arm64 from a source tree's
`go/pfb_dns_gateway` module. Every case here drives the REAL Go toolchain and reads the produced
files' own ELF headers; nothing stands in for the compiler. A tiny throwaway module keeps the
failure-mode cases quick, and one module-scoped build of this checkout's real gateway proves the
actual product cross-compiles for both targets.

The helper is a hyphen-named CLI script, so it is run as a subprocess, the way the package builder
and CI run it.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from tests.elf_facts import ELFOSABI_FREEBSD, EM_AARCH64, EM_X86_64, ET_EXEC, elf_facts

ROOT = Path(__file__).resolve().parent.parent
HELPER = ROOT / "scripts" / "build-pfb-dns.py"
TARGETS = {"freebsd-amd64": EM_X86_64, "freebsd-arm64": EM_AARCH64}
MAIN_GO = "package main\n\nfunc main() {}\n"

# Outer salvage watchdog only (a cold module download plus two cross-compiles is the slow case):
# subprocess.run kills and reaps the child on expiry. It is never an assertion about duration.
WATCHDOG_SECONDS = 1800


def run_helper(
    source_root: Path, out_dir: Path, *, go: str | None = None, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    argv = [sys.executable, str(HELPER), "--source-root", str(source_root), "--out-dir", str(out_dir)]
    if go is not None:
        argv += ["--go", go]
    return subprocess.run(argv, capture_output=True, text=True, env=env, check=False, timeout=WATCHDOG_SECONDS)


def write_tiny_module(root: Path, *, go_directive: str = "1.21", extra: dict[str, str] | None = None) -> Path:
    """A dependency-free `go/pfb_dns_gateway` module under ``root``; returns ``root``."""
    module = root / "go" / "pfb_dns_gateway"
    module.mkdir(parents=True)
    (module / "go.mod").write_text(f"module example.test/tiny\n\ngo {go_directive}\n")
    (module / "main.go").write_text(MAIN_GO)
    for name, text in (extra or {}).items():
        (module / name).write_text(text)
    return root


def expected_facts(machine: int) -> dict[str, object]:
    return {
        "osabi": ELFOSABI_FREEBSD,
        "type": ET_EXEC,
        "machine": machine,
        "has_interpreter": False,
        "has_freebsd_abi_note": True,
    }


def assert_freebsd_elf(out_dir: Path) -> None:
    for target, machine in TARGETS.items():
        binary = out_dir / target / "pfb-dns"
        assert elf_facts(binary.read_bytes()) == expected_facts(machine), f"{binary} is not the {target} ELF"


@pytest.fixture(scope="module")
def real_build(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, dict[str, Any]]:
    """This checkout's real gateway, cross-built once for the module."""
    out_dir = tmp_path_factory.mktemp("pfb-dns-real")
    result = run_helper(ROOT, out_dir)
    assert result.returncode == 0, f"real gateway cross-build failed:\n{result.stderr}"
    return out_dir, json.loads(result.stdout)


def test_real_gateway_cross_builds_a_freebsd_elf_for_each_architecture(
    real_build: tuple[Path, dict[str, Any]],
) -> None:
    out_dir, _record = real_build
    assert_freebsd_elf(out_dir)
    for target in TARGETS:
        assert os.access(out_dir / target / "pfb-dns", os.X_OK), f"{target}/pfb-dns is not executable"


def test_reported_sha256_and_size_are_those_of_the_written_files(real_build: tuple[Path, dict[str, Any]]) -> None:
    out_dir, record = real_build
    targets = record["targets"]
    assert sorted(targets) == sorted(TARGETS)
    for target in TARGETS:
        data = (out_dir / target / "pfb-dns").read_bytes()
        assert targets[target]["path"] == str(out_dir / target / "pfb-dns")
        assert targets[target]["sha256"] == hashlib.sha256(data).hexdigest()
        assert targets[target]["size"] == len(data)
    assert str(record["go"]).startswith("go1."), f"toolchain version missing from the record: {record}"


def test_the_same_source_builds_the_same_bytes(real_build: tuple[Path, dict[str, Any]], tmp_path: Path) -> None:
    _out_dir, first = real_build
    again = run_helper(ROOT, tmp_path / "again")
    assert again.returncode == 0, again.stderr
    second = json.loads(again.stdout)
    for target in TARGETS:
        assert second["targets"][target]["sha256"] == first["targets"][target]["sha256"], (
            f"{target} is not reproducible from the same source"
        )


def test_binary_mtime_follows_the_module_not_the_build_clock(tmp_path: Path) -> None:
    root = write_tiny_module(tmp_path / "src-tree")
    os.utime(root / "go" / "pfb_dns_gateway" / "go.mod", (1_600_000_000, 1_600_000_000))
    result = run_helper(root, tmp_path / "out")
    assert result.returncode == 0, result.stderr
    stamps = {t: int((tmp_path / "out" / t / "pfb-dns").stat().st_mtime) for t in TARGETS}
    assert stamps == {t: 1_600_000_000 for t in TARGETS}


def test_legacy_source_without_a_go_module_builds_nothing_and_needs_no_go(tmp_path: Path) -> None:
    root = tmp_path / "legacy"
    (root / "src" / "usr").mkdir(parents=True)
    result = run_helper(root, tmp_path / "out", go="/nonexistent/go")
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["targets"] == {}
    assert not (tmp_path / "out").exists() or not list((tmp_path / "out").rglob("*")), "legacy build wrote files"


def test_go_source_without_a_go_toolchain_fails_loudly_and_writes_nothing(tmp_path: Path) -> None:
    root = write_tiny_module(tmp_path / "src-tree")
    result = run_helper(root, tmp_path / "out", go="/nonexistent/go")
    assert result.returncode != 0, "a Go source tree built without a Go toolchain"
    assert "/nonexistent/go" in result.stderr, f"error does not name the missing toolchain:\n{result.stderr}"
    assert result.stdout.strip() == ""
    assert list((tmp_path / "out").rglob("pfb-dns")) == []


def test_toolchain_older_than_go_mod_requires_fails_loudly_and_writes_nothing(tmp_path: Path) -> None:
    root = write_tiny_module(tmp_path / "src-tree", go_directive="1.99.0")
    result = run_helper(root, tmp_path / "out")
    assert result.returncode != 0, "a too-old toolchain built the module"
    assert "1.99.0" in result.stderr, f"error does not name the required Go version:\n{result.stderr}"
    assert list((tmp_path / "out").rglob("pfb-dns")) == []


def test_compile_error_in_one_architecture_leaves_no_partial_payload(tmp_path: Path) -> None:
    # `_arm64.go` compiles only for arm64, so amd64 builds first and the arm64 build then fails.
    root = write_tiny_module(
        tmp_path / "src-tree", extra={"broken_arm64.go": "package main\n\nvar _ = undefinedSymbol\n"}
    )
    result = run_helper(root, tmp_path / "out")
    assert result.returncode != 0, "a failing arm64 compile still exited 0"
    assert "freebsd-arm64" in result.stderr, f"error does not name the failing target:\n{result.stderr}"
    assert list((tmp_path / "out").rglob("pfb-dns")) == [], "the amd64 binary was left behind after the arm64 failure"


def test_ambient_go_environment_cannot_steer_the_build(tmp_path: Path) -> None:
    # Each ambient value, if honoured, would break the build or change what it builds:
    # GOFLAGS selects the file that fails to compile, GOOS/GOARCH/CGO_ENABLED change the target,
    # GOTOOLCHAIN asks Go to download a toolchain that does not exist.
    root = write_tiny_module(
        tmp_path / "src-tree",
        extra={"evil.go": "//go:build evil\n\npackage main\n\nvar _ = undefinedSymbol\n"},
    )
    hostile = dict(
        os.environ,
        GOFLAGS="-tags=evil",
        GOOS="linux",
        GOARCH="386",
        CGO_ENABLED="1",
        GOTOOLCHAIN="go1.99.0",
        GOWORK="/nonexistent/go.work",
    )
    result = run_helper(root, tmp_path / "out", env=hostile)
    assert result.returncode == 0, f"ambient Go environment leaked into the build:\n{result.stderr}"
    assert_freebsd_elf(tmp_path / "out")


def test_a_go_sum_entry_missing_from_the_gateway_fails_the_build_and_is_not_repaired(tmp_path: Path) -> None:
    # Given a copy of the real gateway whose go.sum has lost the hash of the quic-go module it compiles against
    source = tmp_path / "src-tree"
    shutil.copytree(ROOT / "go", source / "go")
    go_sum = source / "go" / "pfb_dns_gateway" / "go.sum"
    lines = go_sum.read_text(encoding="utf-8").splitlines(keepends=True)
    kept = [line for line in lines if not line.startswith("github.com/quic-go/quic-go ") or "/go.mod " in line]
    assert len(kept) == len(lines) - 1, "the gateway's go.sum has no quic-go module hash to remove"
    go_sum.write_text("".join(kept), encoding="utf-8")
    before = go_sum.read_bytes()

    # When it is cross-built
    result = run_helper(source, tmp_path / "out")

    # Then the unverifiable module stops the build, and go.sum is not rewritten to let it through
    assert result.returncode != 0, "a build with a go.sum entry missing succeeded"
    assert "go.sum" in result.stderr, f"the error does not name go.sum:\n{result.stderr}"
    assert go_sum.read_bytes() == before, "the build rewrote go.sum"


def test_a_go_env_file_in_the_users_config_cannot_change_the_build(
    real_build: tuple[Path, dict[str, Any]], tmp_path: Path
) -> None:
    # Given a user config file that sets a compile flag, which Go would apply if the builder read the file
    config = tmp_path / "config"
    (config / "go").mkdir(parents=True)
    (config / "go" / "env").write_text("GOFLAGS=-gcflags=-N -l\n", encoding="utf-8")

    # When the real gateway is cross-built with that config in place
    _out_dir, first = real_build
    result = run_helper(ROOT, tmp_path / "out", env=dict(os.environ, XDG_CONFIG_HOME=str(config)))

    # Then the build succeeds with the same bytes as the build without it
    assert result.returncode == 0, f"a user GOENV file broke the build:\n{result.stderr}"
    second = json.loads(result.stdout)
    for target in TARGETS:
        assert second["targets"][target]["sha256"] == first["targets"][target]["sha256"], (
            f"{target} was built differently under a user GOENV file"
        )


@pytest.mark.parametrize("wrong", ["linux-elf", "other-architecture"])
def test_an_output_that_is_not_the_targets_freebsd_elf_is_rejected_and_removed(
    real_build: tuple[Path, dict[str, Any]], tmp_path: Path, wrong: str
) -> None:
    """The ELF check is the last line against a toolchain that built something else than asked.

    A stand-in `go` writes a fixed file for every target: a Linux binary (wrong OS ABI), or the amd64
    FreeBSD binary (right OS, wrong CPU once it is offered for arm64).
    """
    real_out, _record = real_build
    offered = Path("/bin/true").resolve() if wrong == "linux-elf" else real_out / "freebsd-amd64" / "pfb-dns"
    fake_go = tmp_path / "go"
    fake_go.write_text(
        '#!/bin/sh\nif [ "$1" = env ]; then echo go1.99.0; exit 0; fi\n'
        'while [ $# -gt 0 ]; do [ "$1" = -o ] && out=$2; shift; done\n'
        'cp "$OFFERED_ELF" "$out"\n'
    )
    fake_go.chmod(0o755)
    root = write_tiny_module(tmp_path / "src-tree")
    result = run_helper(root, tmp_path / "out", go=str(fake_go), env=dict(os.environ, OFFERED_ELF=str(offered)))
    assert result.returncode != 0, "a file that is not the target's FreeBSD ELF was accepted"
    assert "is not a FreeBSD ELF" in result.stderr, result.stderr
    assert list((tmp_path / "out").rglob("pfb-dns")) == [], "a rejected build left binaries behind"
