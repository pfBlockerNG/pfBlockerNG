"""Tests for scripts/build-pfb-dns.py (issue #3513, dual-architecture package).

The helper cross-compiles the pfB-DNS gateway for FreeBSD amd64 and arm64 from a source tree's
`go/pfb_dns_gateway` module for the FreeBSD major the caller targets. Every case here drives the REAL
Go toolchain (the ones that lie about a result wrap it, tests/go_wrapper.py) and reads the produced
files' own ELF headers, program headers and ABI tag; nothing stands in for the compiler. A tiny
throwaway module keeps the failure-mode cases quick, and one module-scoped build of this checkout's
real gateway proves the actual product cross-compiles for both targets.

The helper is a hyphen-named CLI script, so it is run as a subprocess, the way the package builder
and CI run it.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from tests.elf_facts import ELFOSABI_FREEBSD, EM_AARCH64, EM_X86_64, ET_EXEC, elf_facts, freebsd_abi_note, section_names
from tests.gitenv import scrubbed_git_env
from tests.go_wrapper import write_go_wrapper

ROOT = Path(__file__).resolve().parent.parent
HELPER = ROOT / "scripts" / "build-pfb-dns.py"
TARGETS = {"freebsd-amd64": EM_X86_64, "freebsd-arm64": EM_AARCH64}
MAIN_GO = "package main\n\nfunc main() {}\n"
TARGET_MAJOR = 15

# Outer salvage watchdog only (a cold module download plus two cross-compiles is the slow case):
# subprocess.run kills and reaps the child on expiry. It is never an assertion about duration.
WATCHDOG_SECONDS = 1800


def run_helper(
    source_root: Path,
    out_dir: Path | str,
    *,
    go: str | None = None,
    env: dict[str, str] | None = None,
    extra: list[str] | None = None,
    cwd: Path | None = None,
    major: int | None = TARGET_MAJOR,
) -> subprocess.CompletedProcess[str]:
    argv = [sys.executable, str(HELPER), "--source-root", str(source_root), "--out-dir", str(out_dir)]
    if major is not None:
        argv += ["--freebsd-major", str(major)]
    if go is not None:
        argv += ["--go", go]
    argv += extra or []
    return subprocess.run(argv, capture_output=True, text=True, env=env, cwd=cwd, check=False, timeout=WATCHDOG_SECONDS)


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
    (config / "go" / "env").write_text("GOFLAGS=-gcflags=-N\n", encoding="utf-8")

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
    FreeBSD binary (right OS, wrong CPU once it is offered for arm64). It leaves `go version -m` to the
    real toolchain, which reads the file it is handed.
    """
    real_out, _record = real_build
    offered = Path("/bin/true").resolve() if wrong == "linux-elf" else real_out / "freebsd-amd64" / "pfb-dns"
    fake_go = tmp_path / "go"
    fake_go.write_text(
        '#!/bin/sh\nif [ "$1" = env ]; then echo go1.99.0; exit 0; fi\n'
        'if [ "$1" = mod ]; then exit 0; fi\n'
        'if [ "$1" = version ]; then exec "$REAL_GO" "$@"; fi\n'
        'while [ $# -gt 0 ]; do [ "$1" = -o ] && out=$2; shift; done\n'
        'cp "$OFFERED_ELF" "$out"\n'
    )
    fake_go.chmod(0o755)
    root = write_tiny_module(tmp_path / "src-tree")
    env = dict(os.environ, OFFERED_ELF=str(offered), REAL_GO=str(shutil.which("go")))
    result = run_helper(root, tmp_path / "out", go=str(fake_go), env=env)
    assert result.returncode != 0, "a file that is not the target's FreeBSD ELF was accepted"
    assert "is not a FreeBSD ELF" in result.stderr, result.stderr
    assert list((tmp_path / "out").rglob("pfb-dns")) == [], "a rejected build left binaries behind"


def written_files(directory: Path) -> list[Path]:
    return [p for p in directory.rglob("*") if p.is_file()] if directory.exists() else []


@pytest.fixture(scope="module")
def vendored_gateway(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, bytes]:
    """A copy of the real gateway beside its `go mod vendor` tree, plus the vendor/modules.txt Go wrote.

    Tests that change the tree copy it first; this one stays pristine for the module.
    """
    root = tmp_path_factory.mktemp("pfb-dns-vendored")
    shutil.copytree(ROOT / "go", root / "go")
    module = root / "go" / "pfb_dns_gateway"
    vendor = subprocess.run(
        ["go", "mod", "vendor"], cwd=module, capture_output=True, text=True, check=False, timeout=WATCHDOG_SECONDS
    )
    assert vendor.returncode == 0, f"go mod vendor failed on the real gateway:\n{vendor.stderr}"
    return root, (module / "vendor" / "modules.txt").read_bytes()


def test_vendored_and_builder_modes_build_identical_bytes(
    real_build: tuple[Path, dict[str, Any]], vendored_gateway: tuple[Path, bytes], tmp_path: Path
) -> None:
    # Given the bytes the builder produces by vendoring the real gateway itself
    _out_dir, builder = real_build
    root, _modules_txt = vendored_gateway

    # When the same gateway is built from a ready-made vendor tree, as the ports recipe does
    result = run_helper(root, tmp_path / "out", extra=["--vendored"])

    # Then both modes ship the same bytes for both architectures
    assert result.returncode == 0, f"--vendored build failed:\n{result.stderr}"
    vendored = json.loads(result.stdout)
    for target in TARGETS:
        assert vendored["targets"][target]["sha256"] == builder["targets"][target]["sha256"], (
            f"{target}: --vendored and builder modes differ"
        )
    assert_freebsd_elf(tmp_path / "out")


def test_builder_mode_accepts_a_modules_txt_equal_to_the_one_go_generates_and_records_its_digest(
    real_build: tuple[Path, dict[str, Any]], vendored_gateway: tuple[Path, bytes], tmp_path: Path
) -> None:
    _out_dir, builder = real_build
    _root, modules_txt = vendored_gateway
    given = tmp_path / "modules.txt"
    given.write_bytes(modules_txt)

    result = run_helper(ROOT, tmp_path / "out", extra=["--modules-txt", str(given)])

    assert result.returncode == 0, f"a matching modules.txt was refused:\n{result.stderr}"
    record = json.loads(result.stdout)
    assert record["modules_txt_sha256"] == hashlib.sha256(modules_txt).hexdigest()
    assert builder["modules_txt_sha256"] == record["modules_txt_sha256"], (
        "the digest differs from the unchecked build's"
    )
    for target in TARGETS:
        assert record["targets"][target]["sha256"] == builder["targets"][target]["sha256"]


def test_vendored_mode_installs_the_given_modules_txt_into_a_tree_that_lacks_it(
    real_build: tuple[Path, dict[str, Any]], vendored_gateway: tuple[Path, bytes], tmp_path: Path
) -> None:
    # Given the ports shape: module zips unpacked under vendor/ (GH_TUPLE) without Go's modules.txt
    _out_dir, builder = real_build
    root, modules_txt = vendored_gateway
    tree = tmp_path / "tuple-tree"
    shutil.copytree(root / "go", tree / "go")
    vendor = tree / "go" / "pfb_dns_gateway" / "vendor"
    (vendor / "modules.txt").unlink()
    given = tmp_path / "modules.txt"
    given.write_bytes(modules_txt)

    # When it is built in place with the port's own modules.txt
    result = run_helper(tree, tmp_path / "out", extra=["--vendored", "--modules-txt", str(given)])

    # Then Go builds from it, to the bytes of the builder mode, and the file went where Go reads it
    assert result.returncode == 0, f"the GH_TUPLE-shaped tree did not build:\n{result.stderr}"
    record = json.loads(result.stdout)
    for target in TARGETS:
        assert record["targets"][target]["sha256"] == builder["targets"][target]["sha256"]
    assert (vendor / "modules.txt").read_bytes() == modules_txt
    assert record["modules_txt_sha256"] == hashlib.sha256(modules_txt).hexdigest()


def altered_modules_txt(kind: str, modules_txt: bytes) -> bytes:
    text = modules_txt.decode("utf-8")
    if kind == "quic-go-version":
        changed = re.sub(r"(# github\.com/quic-go/quic-go )v\S+", r"\1v0.0.1", text)
    elif kind == "trailing-newline-stripped":
        changed = text.rstrip("\n")
    else:
        changed = text.replace("\n", "\r\n")
    assert changed != text, f"{kind} did not alter the gateway's modules.txt"
    return changed.encode("utf-8")


@pytest.mark.parametrize("mode", ["builder", "vendored"])
@pytest.mark.parametrize("kind", ["quic-go-version", "trailing-newline-stripped", "crlf"])
def test_a_modules_txt_that_differs_from_the_source_fails_and_writes_nothing(
    vendored_gateway: tuple[Path, bytes], tmp_path: Path, mode: str, kind: str
) -> None:
    # Given a port modules.txt that is not the one the source's go.mod and go.sum vendor to
    root, modules_txt = vendored_gateway
    given = tmp_path / "modules.txt"
    given.write_bytes(altered_modules_txt(kind, modules_txt))
    source, extra = (ROOT, []) if mode == "builder" else (root, ["--vendored"])
    before = (root / "go" / "pfb_dns_gateway" / "vendor" / "modules.txt").read_bytes()

    # When the gateway is built with it
    result = run_helper(source, tmp_path / "out", extra=[*extra, "--modules-txt", str(given)])

    # Then the build stops on the mismatch, prints no record, and leaves no file behind or changed
    assert result.returncode == 1, f"a differing modules.txt was accepted ({mode}, {kind}):\n{result.stderr}"
    assert "modules.txt" in result.stderr, f"the error does not name modules.txt:\n{result.stderr}"
    assert result.stdout.strip() == ""
    assert written_files(tmp_path / "out") == [], "a rejected modules.txt left files behind"
    assert (root / "go" / "pfb_dns_gateway" / "vendor" / "modules.txt").read_bytes() == before


def test_a_modules_txt_for_a_module_that_vendors_nothing_fails(tmp_path: Path) -> None:
    root = write_tiny_module(tmp_path / "src-tree")
    given = tmp_path / "modules.txt"
    given.write_text("# example.test/dep v1.0.0\n")

    result = run_helper(root, tmp_path / "out", extra=["--modules-txt", str(given)])

    assert result.returncode == 1, f"a modules.txt was accepted for a dependency-free module:\n{result.stderr}"
    assert "modules.txt" in result.stderr
    assert written_files(tmp_path / "out") == []


def test_a_missing_modules_txt_file_fails_and_writes_nothing(tmp_path: Path) -> None:
    root = write_tiny_module(tmp_path / "src-tree")

    result = run_helper(root, tmp_path / "out", extra=["--modules-txt", str(tmp_path / "absent.txt")])

    assert result.returncode == 1, f"a --modules-txt that is not a file was ignored:\n{result.stderr}"
    assert "absent.txt" in result.stderr
    assert written_files(tmp_path / "out") == []


def test_a_dependency_free_module_records_no_modules_txt_digest(tmp_path: Path) -> None:
    root = write_tiny_module(tmp_path / "src-tree")
    for extra in ([], ["--vendored"]):
        result = run_helper(root, tmp_path / f"out{len(extra)}", extra=extra)
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout)["modules_txt_sha256"] is None


@pytest.mark.parametrize("outcome", ["builds", "fails"])
def test_a_relative_out_dir_writes_nothing_into_the_source_tree(tmp_path: Path, outcome: str) -> None:
    # Given an --out-dir relative to the caller's directory, which is not the module's directory
    extra = {"broken_arm64.go": "package main\n\nvar _ = undefinedSymbol\n"} if outcome == "fails" else None
    root = write_tiny_module(tmp_path / "src-tree", extra=extra)

    # When the gateway is built, successfully or not
    result = run_helper(root, "out", cwd=tmp_path)

    # Then the binaries land (or are cleaned up) under that directory and nothing is stranded in the source
    assert (result.returncode == 0) == (outcome == "builds"), result.stderr
    assert list(root.rglob("pfb-dns")) == [], "a build artefact was written into the source tree"
    if outcome == "builds":
        assert_freebsd_elf(tmp_path / "out")
    else:
        assert written_files(tmp_path / "out") == []


def test_the_target_freebsd_major_is_required(tmp_path: Path) -> None:
    root = write_tiny_module(tmp_path / "src-tree")

    result = run_helper(root, tmp_path / "out", major=None)

    assert result.returncode == 2, f"a build without a target FreeBSD major ran:\n{result.stderr}"
    assert "--freebsd-major" in result.stderr
    assert written_files(tmp_path / "out") == []


@pytest.mark.parametrize("major", ["abc", "0", "-3", "15.2", ""])
def test_a_target_freebsd_major_that_is_not_a_positive_integer_is_refused(tmp_path: Path, major: str) -> None:
    root = write_tiny_module(tmp_path / "src-tree")

    result = run_helper(root, tmp_path / "out", major=None, extra=["--freebsd-major", major])

    assert result.returncode == 2, f"--freebsd-major {major!r} was accepted:\n{result.stderr}"
    assert "--freebsd-major" in result.stderr
    assert written_files(tmp_path / "out") == []


def test_the_record_names_the_target_freebsd_and_the_abi_tag_each_binary_carries(
    real_build: tuple[Path, dict[str, Any]],
) -> None:
    out_dir, record = real_build
    assert record["freebsd_major"] == TARGET_MAJOR
    for target in TARGETS:
        carried = freebsd_abi_note((out_dir / target / "pfb-dns").read_bytes())
        assert carried is not None, f"{target} carries no FreeBSD ABI tag"
        assert record["targets"][target]["freebsd_abi_note"] == carried
        assert carried // 100000 <= TARGET_MAJOR, f"{target} needs FreeBSD {carried // 100000}"


def test_the_real_gateway_builds_the_same_bytes_for_the_next_freebsd_major(
    real_build: tuple[Path, dict[str, Any]], tmp_path: Path
) -> None:
    _out_dir, first = real_build

    result = run_helper(ROOT, tmp_path / "out", major=TARGET_MAJOR + 1)

    assert result.returncode == 0, result.stderr
    record = json.loads(result.stdout)
    assert record["freebsd_major"] == TARGET_MAJOR + 1
    for target in TARGETS:
        assert record["targets"][target]["sha256"] == first["targets"][target]["sha256"], (
            f"{target} differs between FreeBSD majors"
        )


def build_with_a_lying_go(
    tmp_path: Path, *, major: int = TARGET_MAJOR, **lie: Any
) -> tuple[subprocess.CompletedProcess[str], Path]:
    root = write_tiny_module(tmp_path / "src-tree")
    go = write_go_wrapper(tmp_path / "wrapper" / "go", **lie)
    return run_helper(root, tmp_path / "out", go=str(go), major=major), tmp_path / "out"


# (forgery, value, what the error must say): each binary is the right architecture's FreeBSD ELF
# except for the one thing forged.
FORGED_BINARIES = [
    ("abi-note", 1600000, "ABI tag 1600000"),
    ("no-abi-note", None, "no FreeBSD ABI tag"),
    ("foreign-note-name", None, "no FreeBSD ABI tag"),
    ("interpreter", None, "PT_INTERP"),
    ("dynamic-section", None, "PT_DYNAMIC"),
    ("shared-object", None, "ET_EXEC"),
    ("truncated", None, "program header"),
    ("program-headers-outside-file", None, "program header"),
    ("program-header-entry-size", None, "program header"),
    ("truncated-note", None, "no FreeBSD ABI tag"),
    ("abi-note-wrong-size", None, "no FreeBSD ABI tag"),
]


@pytest.mark.parametrize(("forgery", "value", "says"), FORGED_BINARIES, ids=[row[0] for row in FORGED_BINARIES])
def test_a_binary_that_is_not_a_static_executable_for_the_target_freebsd_is_rejected_and_removed(
    tmp_path: Path, forgery: str, value: int | None, says: str
) -> None:
    result, out = build_with_a_lying_go(tmp_path, forgery=forgery, value=value)

    assert result.returncode == 1, f"a {forgery} binary was accepted:\n{result.stderr}"
    assert says in result.stderr, f"the error does not say {says!r}:\n{result.stderr}"
    assert "Traceback" not in result.stderr, result.stderr
    assert result.stdout.strip() == ""
    assert written_files(out) == [], "a rejected binary left files behind"


@pytest.mark.parametrize(
    ("note", "major", "accepted"),
    [(1599999, 15, True), (1600000, 16, True), (1500000, 14, False), (1300000, 12, False)],
)
def test_the_abi_tag_may_not_name_a_freebsd_newer_than_the_target_major(
    tmp_path: Path, note: int, major: int, accepted: bool
) -> None:
    result, out = build_with_a_lying_go(tmp_path, major=major, forgery="abi-note", value=note)

    if accepted:
        assert result.returncode == 0, f"ABI tag {note} was refused for FreeBSD {major}:\n{result.stderr}"
        record = json.loads(result.stdout)
        assert {t: v["freebsd_abi_note"] for t, v in record["targets"].items()} == dict.fromkeys(TARGETS, note)
    else:
        assert result.returncode == 1, f"ABI tag {note} was accepted for FreeBSD {major}"
        assert f"ABI tag {note}" in result.stderr and f"FreeBSD {major}" in result.stderr, result.stderr
        assert written_files(out) == []


@pytest.mark.parametrize(
    ("second", "major", "accepted"), [(1600000, 15, False), (1600000, 16, True), (1100000, 15, True)]
)
def test_the_newest_of_several_abi_tags_decides(tmp_path: Path, second: int, major: int, accepted: bool) -> None:
    # Given Go's own ABI tag and a second one, forged beside it, that is newer or older than it
    root = write_tiny_module(tmp_path / "src-tree")
    clean = run_helper(root, tmp_path / "clean")
    assert clean.returncode == 0, clean.stderr
    own = json.loads(clean.stdout)["targets"]["freebsd-amd64"]["freebsd_abi_note"]
    go = write_go_wrapper(tmp_path / "wrapper" / "go", forgery="second-abi-note", value=second)

    # When the module is built for the FreeBSD major
    result = run_helper(root, tmp_path / "out", go=str(go), major=major)

    # Then the newest tag is the one held against the major and recorded
    newest = max(own, second)
    if accepted:
        assert result.returncode == 0, f"ABI tags {own} and {second} were refused for FreeBSD {major}:\n{result.stderr}"
        targets = json.loads(result.stdout)["targets"]
        assert {t: v["freebsd_abi_note"] for t, v in targets.items()} == dict.fromkeys(TARGETS, newest)
    else:
        assert result.returncode == 1, f"ABI tags {own} and {second} were accepted for FreeBSD {major}"
        assert f"ABI tag {newest}" in result.stderr and f"FreeBSD {major}" in result.stderr, result.stderr
        assert written_files(tmp_path / "out") == []


# (text in `go version -m` output, what it is made to say, the setting the error must name, the target
# that carries it)
SETTING_LIES = [
    ("CGO_ENABLED=0", "CGO_ENABLED=1", "CGO_ENABLED", "freebsd-amd64"),
    ("GOOS=freebsd", "GOOS=linux", "GOOS", "freebsd-amd64"),
    ("GOARCH=amd64", "GOARCH=386", "GOARCH", "freebsd-amd64"),
    ("GOAMD64=v1", "GOAMD64=v3", "GOAMD64", "freebsd-amd64"),
    ("GOAMD64=v1", "", "GOAMD64", "freebsd-amd64"),
    ("GOARM64=v8.0", "GOARM64=v8.5", "GOARM64", "freebsd-arm64"),
]


@pytest.mark.parametrize(("truth", "lie", "setting", "target"), SETTING_LIES)
def test_a_binary_whose_build_settings_are_not_the_pinned_ones_is_rejected_and_removed(
    tmp_path: Path, truth: str, lie: str, setting: str, target: str
) -> None:
    result, out = build_with_a_lying_go(tmp_path, replace=(truth, lie))

    assert result.returncode == 1, f"build settings {lie!r} were accepted:\n{result.stderr}"
    assert setting in result.stderr and target in result.stderr, result.stderr
    assert written_files(out) == [], "a rejected build left binaries behind, even those of the other architecture"


def test_the_go_environment_pins_the_microarchitecture_levels_whatever_the_caller_exports(tmp_path: Path) -> None:
    # Given a caller whose environment asks for newer CPU levels than the package may assume
    root = write_tiny_module(tmp_path / "src-tree")
    clean = run_helper(root, tmp_path / "clean")
    assert clean.returncode == 0, clean.stderr
    builds = tmp_path / "builds.jsonl"
    go = write_go_wrapper(tmp_path / "wrapper" / "go", record=builds)

    # When the gateway is built through a Go that records the environment of every build
    result = run_helper(root, tmp_path / "hostile", go=str(go), env=dict(os.environ, GOAMD64="v3", GOARM64="v8.5"))

    # Then each architecture is built at its baseline level, and the bytes are the clean environment's
    assert result.returncode == 0, result.stderr
    seen = {build["GOARCH"]: build for build in map(json.loads, builds.read_text().splitlines())}
    assert seen["amd64"]["GOAMD64"] == "v1", seen
    assert seen["arm64"]["GOARM64"] == "v8.0", seen
    for target in TARGETS:
        assert (
            json.loads(result.stdout)["targets"][target]["sha256"]
            == json.loads(clean.stdout)["targets"][target]["sha256"]
        ), f"{target} was built differently under GOAMD64=v3 GOARM64=v8.5"


def test_vendored_mode_compiles_the_vendor_tree_without_the_module_cache_or_network(tmp_path: Path) -> None:
    # Given a module whose only dependency exists nowhere but in its vendor tree, as in a port's offline build
    root = write_tiny_module(tmp_path / "src-tree")
    module = root / "go" / "pfb_dns_gateway"
    module.joinpath("go.mod").write_text("module example.test/tiny\n\ngo 1.21\n\nrequire example.test/dep v1.0.0\n")
    module.joinpath("main.go").write_text(
        'package main\n\nimport "example.test/dep"\n\nfunc main() { println(dep.Marker) }\n'
    )
    dep = module / "vendor" / "example.test" / "dep"
    dep.mkdir(parents=True)
    dep.joinpath("dep.go").write_text('package dep\n\nconst Marker = "FROM-THE-VENDOR-TREE"\n')
    module.joinpath("vendor", "modules.txt").write_text(
        "# example.test/dep v1.0.0\n## explicit; go 1.21\nexample.test/dep\n"
    )

    # When it is built in place with module downloads switched off
    result = run_helper(root, tmp_path / "out", extra=["--vendored"], env=dict(os.environ, GOPROXY="off"))

    # Then both binaries carry the vendored code
    assert result.returncode == 0, f"the vendor tree was not what Go compiled:\n{result.stderr}"
    for target in TARGETS:
        assert b"FROM-THE-VENDOR-TREE" in (tmp_path / "out" / target / "pfb-dns").read_bytes()


@pytest.mark.parametrize("mode", ["builder", "vendored"])
def test_an_out_dir_inside_the_module_is_refused_and_writes_nothing(tmp_path: Path, mode: str) -> None:
    # Given a caller whose directory is the module itself and whose --out-dir is relative to it
    root = write_tiny_module(tmp_path / "src-tree")
    module = root / "go" / "pfb_dns_gateway"

    # When the gateway is built (in place or from a copy)
    result = run_helper(root, "out", extra=["--vendored"] if mode == "vendored" else [], cwd=module)

    # Then the build says so, instead of copying the module into itself or building into its own tree
    assert result.returncode == 1, f"an --out-dir inside the module was accepted ({mode}):\n{result.stderr}"
    assert "inside the module" in result.stderr, result.stderr
    assert "Traceback" not in result.stderr, result.stderr
    assert sorted(p.name for p in module.iterdir()) == ["go.mod", "main.go"], "the module tree was written to"


def test_a_relative_go_is_resolved_from_the_callers_directory(tmp_path: Path) -> None:
    # Given a Go reached by a path relative to the caller, which is not the module's directory
    root = write_tiny_module(tmp_path / "src-tree")
    link = tmp_path / "relgo" / "go"
    link.parent.mkdir()
    link.symlink_to(str(shutil.which("go")))

    # When the gateway is built with that --go
    result = run_helper(root, tmp_path / "out", go="relgo/go", cwd=tmp_path)

    # Then it is the Go that runs, in the module's directory as well
    assert result.returncode == 0, f"a relative --go that exists was not run:\n{result.stderr}"
    assert_freebsd_elf(tmp_path / "out")


def test_a_vendored_modules_txt_for_a_tree_without_a_vendor_directory_is_refused_cleanly(tmp_path: Path) -> None:
    root = write_tiny_module(tmp_path / "src-tree")
    given = tmp_path / "modules.txt"
    given.write_text("# example.test/dep v1.0.0\n")

    result = run_helper(root, tmp_path / "out", extra=["--vendored", "--modules-txt", str(given)])

    assert result.returncode == 1, f"a modules.txt was installed into a tree without vendor/:\n{result.stderr}"
    assert "modules.txt" in result.stderr and "Traceback" not in result.stderr, result.stderr
    assert written_files(tmp_path / "out") == []
    assert not (root / "go" / "pfb_dns_gateway" / "vendor").exists(), "a vendor/ directory was created"


def test_the_go_environment_pins_workspace_toolchain_and_config_off_whatever_the_caller_exports(tmp_path: Path) -> None:
    # Given a caller whose environment points Go at a workspace, a newer toolchain, a config file and another target
    root = write_tiny_module(tmp_path / "src-tree")
    builds = tmp_path / "builds.jsonl"
    go = write_go_wrapper(tmp_path / "wrapper" / "go", record=builds)
    hostile = dict(
        os.environ,
        GOWORK="/nonexistent/go.work",
        GOTOOLCHAIN="go1.99.0",
        GOENV="/nonexistent/env",
        GO111MODULE="off",
        CGO_ENABLED="1",
        GOOS="linux",
    )

    # When the gateway is built through a Go that records the environment of every build
    result = run_helper(root, tmp_path / "out", go=str(go), env=hostile)

    # Then every build ran with the builder's own pins
    assert result.returncode == 0, result.stderr
    seen = [json.loads(line) for line in builds.read_text().splitlines()]
    assert len(seen) == len(TARGETS), seen
    pins = {
        "GOWORK": "off",
        "GOTOOLCHAIN": "local",
        "GOENV": "off",
        "GO111MODULE": "on",
        "CGO_ENABLED": "0",
        "GOOS": "freebsd",
    }
    for build in seen:
        assert {key: build[key] for key in pins} == pins, build


def test_a_vendored_build_inside_a_git_checkout_stamps_no_version_control_state(tmp_path: Path) -> None:
    # Given the same module twice: once in a plain directory, once in a committed git checkout
    plain = write_tiny_module(tmp_path / "plain")
    tracked = write_tiny_module(tmp_path / "tracked")
    git = ["git", "-c", "user.name=test", "-c", "user.email=test@example.org", "-c", "commit.gpgsign=false"]
    env = scrubbed_git_env(drop_git_vars=True)
    for args in (["init", "-q"], ["add", "-A"], ["commit", "-qm", "tracked"]):
        subprocess.run([*git, *args], cwd=tracked, env=env, check=True, capture_output=True)

    # When each is built in place
    sums = {}
    for name, root in (("plain", plain), ("tracked", tracked)):
        result = run_helper(root, tmp_path / f"out-{name}", extra=["--vendored"])
        assert result.returncode == 0, result.stderr
        sums[name] = json.loads(result.stdout)["targets"]["freebsd-amd64"]["sha256"]

    # Then the bytes do not depend on the checkout around the module
    assert sums["tracked"] == sums["plain"], "the binary carries version-control state of the checkout it was built in"


def test_the_binaries_are_stripped(real_build: tuple[Path, dict[str, Any]]) -> None:
    # The ports recipe installs with an empty STRIP=, so the helper's own -ldflags is what strips them.
    out_dir, _record = real_build
    for target in TARGETS:
        names = section_names((out_dir / target / "pfb-dns").read_bytes())
        assert ".text" in names, f"{target}: the section headers were not read: {names}"
        assert ".symtab" not in names, f"{target} ships a symbol table: {names}"
        assert [n for n in names if n.startswith(".debug")] == [], f"{target} ships debug sections: {names}"
