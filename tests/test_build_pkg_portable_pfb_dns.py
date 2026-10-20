"""The pfB-DNS payload of the portable package build (issue #3513, dual-architecture package).

pfBlockerNG stays ONE architecture-independent (NO_ARCH) package. build-pkg-portable.py
cross-compiles the gateway from the attested source for FreeBSD amd64 and arm64 and stages both
ELFs, executable, beside the Python proxy; the runtime picks the one that matches the machine.

Every case drives the real builder with a synthetic port and a throwaway git source repo, the real
Go toolchain, and reads the produced `.pkg` back. Nothing stands in for the compiler or the
package writer. Fixtures reuse the synthetic channel port of test_build_pkg_portable.py.
"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import os
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path
from typing import Any, NamedTuple

import pfb_pkg
import pytest

from tests.elf_facts import ELFOSABI_FREEBSD, EM_AARCH64, EM_X86_64, ET_EXEC, elf_facts, freebsd_abi_note
from tests.go_wrapper import write_go_wrapper
from tests.test_build_pkg_portable import (
    _LIVE_BUILD_ROWS,
    _git,
    _make_channel_port,
    _project_args,
    _read_pkg,
    _record,
    bpp,
)

ROOT = Path(__file__).resolve().parent.parent
DNS_PROXY = "usr/local/pkg/pfblockerng/dns_proxy"
BIN = f"/{DNS_PROXY}/bin"
TARGETS = {"freebsd-amd64": EM_X86_64, "freebsd-arm64": EM_AARCH64}
PKG_NAME = "pfSense-pkg-pfBlockerNG-4.0.0.pkg"
EPOCH = 1700000000

TINY_GO = {
    "go.mod": "module example.test/pfbdns\n\ngo 1.21\n",
    "main.go": 'package main\n\nvar marker = "COMMITTED-SOURCE"\n\nfunc main() { println(marker) }\n',
}
FORGED = b"\x7fELF-forged-by-the-source-tree"
RECIPES = ["legacy", "go"]
by_recipe = pytest.mark.parametrize("recipe", RECIPES)
GO_VENDOR = "../go/pfb_dns_gateway/vendor"


class Fixture(NamedTuple):
    ports: Path
    portdir: Path
    ports_sha: str
    source: Path
    source_sha: str


def commit_all(repo: Path, message: str) -> str:
    _git(repo, "add", "-A")
    _git(repo, "-c", "commit.gpgsign=false", "commit", "-qm", message)
    return _git(repo, "rev-parse", "HEAD")


def go_do_build(*, modules_txt: bool) -> str:
    """The `do-build` body of the ports recipe that builds pfb-dns: one `make` command over three lines."""
    modules = "--modules-txt ${FILESDIR}/modules.txt " if modules_txt else ""
    return (
        "\t(cd ${WRKSRC:H} && ${SETENVI} ${WRK_ENV} ${GO_ENV} ${PYTHON_CMD} scripts/build-pfb-dns.py \\\n"
        "\t\t--source-root . --out-dir ${WRKDIR}/pfb-dns --go ${GO_CMD} --vendored \\\n"
        f"\t\t{modules}--freebsd-major ${{OSREL:R}})\n"
    )


def make_fixture(
    root: Path,
    *,
    go_files: dict[str, str] | None = TINY_GO,
    ships_dns_proxy: bool = True,
    source_files: dict[str, bytes] | None = None,
    gitignore: str | None = None,
    php_version: str = "8.3",
    recipe: str = "legacy",
    gh_tuple: tuple[str, ...] = (),
    modules_txt: str | None = None,
    do_build: str | None = None,
) -> Fixture:
    """A GitHub-style stable port plus its source repo.

    ``ships_dns_proxy`` gives the port the nightly/edge recipe shape (COPYTREE_SHARE of the pkg tree and
    a plist derived from the stage); without it the port is the static-plist shape that installs only
    info.xml. ``go_files`` is the `go/pfb_dns_gateway` module the source repo carries (None: legacy source).
    ``php_version`` is the PHP the target's dependency ports are for (a matrix row's).
    ``recipe`` "legacy" installs no binaries (the builder stages them itself); "go" is the recipe that
    builds them in `do-build` (``do_build`` replaces its body) and installs them with INSTALL_PROGRAM, with
    the vendored modules named by ``gh_tuple`` and the port's ``modules_txt`` file.
    """
    ports, portdir, ports_sha, _ = _make_channel_port(root, "stable", github=True, php_version=php_version)
    if ships_dns_proxy:
        (portdir / "pkg-plist").unlink()
        makefile = portdir / "Makefile"
        text = makefile.read_text()
        text = text.replace("USES=\tphp python", "NO_ARCH=\tyes\nUSES=\tphp python")
        install = "do-install:\n\t(cd ${WRKSRC}/usr/local/pkg && ${COPYTREE_SHARE} . ${STAGEDIR}${PREFIX}/pkg)\n"
        if recipe == "go":
            bindir = "${STAGEDIR}${PREFIX}/pkg/pfblockerng/dns_proxy/bin"
            tuples = "GH_TUPLE=\t" + " \\\n\t\t".join(gh_tuple) + "\n" if gh_tuple else ""
            body = do_build if do_build is not None else go_do_build(modules_txt=modules_txt is not None)
            text = text.replace(
                "do-install:\n", f"NO_ARCH_IGNORE=\tpfb-dns\nSTRIP=\n{tuples}do-build:\n{body}\ndo-install:\n"
            )
            install += f"\t${{MKDIR}} {bindir}/freebsd-amd64 {bindir}/freebsd-arm64\n"
            for target in TARGETS:
                install += f"\t${{INSTALL_PROGRAM}} ${{WRKDIR}}/pfb-dns/{target}/pfb-dns {bindir}/{target}\n"
        makefile.write_text(text.replace("do-install:\n", install))
        if modules_txt is not None:
            (portdir / "files" / "modules.txt").write_text(modules_txt)
        ports_sha = commit_all(ports, "ship the pkg tree")
    source = root / "source"
    proxy = source / "src" / DNS_PROXY
    proxy.mkdir(parents=True)
    (proxy / "pfb_dns_proxy.py").write_text("print('python proxy')\n")
    for name, text in (go_files or {}).items():
        path = source / "go" / "pfb_dns_gateway" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    for relative, data in (source_files or {}).items():
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    if gitignore is not None:
        (source / ".gitignore").write_text(gitignore)
    source_sha = commit_all(source, "pfB-DNS source")
    _git(source, "tag", "-f", "v4.0.0")
    return Fixture(ports, portdir, ports_sha, source, source_sha)


def without_go_on_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A PATH that still finds git (the attestation needs it) but no Go toolchain."""
    bindir = tmp_path / "path-without-go"
    bindir.mkdir()
    git = shutil.which("git")
    assert git is not None, "git is required to run the builder's project attestation"
    (bindir / "git").symlink_to(git)
    monkeypatch.setenv("PATH", str(bindir))
    assert shutil.which("go") is None


def native_args(fx: Fixture, out: Path) -> list[str]:
    return [
        "--ports", str(fx.ports),
        "--port-dir", str(fx.portdir),
        "--channel", "stable",
        "--abi", "FreeBSD:15:amd64",
        "--py-flavor", "py311",
        "--php", "8.3",
        "--compression", "xz",
        "--local-src", str(fx.source),
        "--out", str(out),
    ]  # fmt: skip


def project_record(fx: Fixture) -> dict[str, Any]:
    return _record("stable", fx.ports_sha, source_sha=fx.source_sha)


def project_args(fx: Fixture, out: Path) -> list[str]:
    return _project_args(fx.ports, fx.portdir, project_record(fx), source=fx.source, dry_run=False, out=out)


def build(fx: Fixture, mode: str, out: Path) -> int:
    return bpp.main(native_args(fx, out) if mode == "native" else project_args(fx, out))


def assert_same_package_bytes(first: Path, second: Path) -> None:
    """Compare digests: pytest's byte-string diff of two multi-megabyte archives never finishes."""
    digests = [hashlib.sha256(path.read_bytes()).hexdigest() for path in (first, second)]
    assert digests[0] == digests[1], f"{first.name} is not reproducible: sha256 {digests[0]} != {digests[1]}"


def member(tf: tarfile.TarFile, name: str) -> bytes:
    extracted = tf.extractfile(name)
    assert extracted is not None, f"{name} is not a regular file in the package"
    return extracted.read()


def assert_dual_arch_payload(pkg: Path) -> None:
    """Both binaries ship at their layout path: executable, intact, and each the right ELF."""
    full, _compact, tf = _read_pkg(pkg)
    for target, machine in TARGETS.items():
        path = f"{BIN}/{target}/pfb-dns"
        assert path in full["files"], f"{path} missing; package files: {sorted(full['files'])}"
        assert full["files"][path]["perm"] == "0555", f"{path} manifest perm {full['files'][path]['perm']}"
        assert tf.getmember(path).mode & 0o777 == 0o555, f"{path} tar mode {oct(tf.getmember(path).mode)}"
        data = member(tf, path)
        assert full["files"][path]["sum"] == "1$" + hashlib.sha256(data).hexdigest()
        assert elf_facts(data) == {
            "osabi": ELFOSABI_FREEBSD,
            "type": ET_EXEC,
            "machine": machine,
            "has_interpreter": False,
            "has_freebsd_abi_note": True,
        }, f"{path} is not the {target} ELF"


def shipped_binaries(pkg: Path) -> list[str]:
    full, _compact, _tf = _read_pkg(pkg)
    return sorted(path for path in full["files"] if path.startswith(f"{BIN}/"))


@pytest.mark.parametrize("mode", ["native", "project"])
@by_recipe
def test_package_ships_both_architectures_and_keeps_its_existing_metadata(
    tmp_path: Path, mode: str, recipe: str
) -> None:
    """
    Scenario: a source tree with the gateway module, built by a port that ships the DNS proxy
      When the package is built
      Then both FreeBSD binaries are in it, executable and intact
       And the package is still NO_ARCH with every other manifest field unchanged
    """
    with_go = make_fixture(tmp_path / "with-go", recipe=recipe)
    legacy = make_fixture(tmp_path / "legacy", go_files=None)
    assert build(legacy, mode, tmp_path / "legacy-out") == 0
    assert build(with_go, mode, tmp_path / "go-out") == 0
    before, after = tmp_path / "legacy-out" / PKG_NAME, tmp_path / "go-out" / PKG_NAME

    assert_dual_arch_payload(after)
    full_before, _, _ = _read_pkg(before)
    full_after, _, tf = _read_pkg(after)
    assert full_after["abi"] == "FreeBSD:15:*" and full_after["arch"] == "freebsd:15:*"
    # flatsize is the installed size, so it grows with the payload; every other field must not move.
    shared = {k: v for k, v in full_after.items() if k not in ("files", "annotations", "flatsize")}
    assert shared == {k: v for k, v in full_before.items() if k not in ("files", "annotations", "flatsize")}
    assert full_after["flatsize"] == sum(tf.getmember(path).size for path in full_after["files"])
    assert set(full_after["files"]) - set(full_before["files"]) == {f"{BIN}/{t}/pfb-dns" for t in TARGETS}
    assert set(full_before["files"]) <= set(full_after["files"])
    proxy = f"/{DNS_PROXY}/pfb_dns_proxy.py"
    assert full_after["files"][proxy]["perm"] == "0644"
    assert member(tf, proxy) == b"print('python proxy')\n"
    assert not [p for p in full_after["files"] if "/go/" in p or p.endswith(("go.mod", "main.go"))], (
        "the Go source tree leaked into the package"
    )


@by_recipe
def test_project_package_validates_against_its_record_and_pins_every_mtime(tmp_path: Path, recipe: str) -> None:
    fx = make_fixture(tmp_path, recipe=recipe)
    assert build(fx, "project", tmp_path / "out") == 0
    pkg = tmp_path / "out" / PKG_NAME
    assert_dual_arch_payload(pkg)
    pfb_pkg.validate_project_pkg(pkg, project_record(fx))
    full, _, _ = _read_pkg(pkg)
    assert {entry["mtime"] for entry in full["files"].values()} == {EPOCH}


@by_recipe
def test_project_package_with_binaries_is_byte_reproducible(tmp_path: Path, recipe: str) -> None:
    fx = make_fixture(tmp_path, recipe=recipe)
    assert build(fx, "project", tmp_path / "one") == 0
    assert build(fx, "project", tmp_path / "two") == 0
    assert_dual_arch_payload(tmp_path / "one" / PKG_NAME)
    assert_same_package_bytes(tmp_path / "one" / PKG_NAME, tmp_path / "two" / PKG_NAME)


@by_recipe
def test_real_gateway_source_cross_builds_into_the_package(tmp_path: Path, recipe: str) -> None:
    """The shipped gateway itself, not a stand-in, rides the package for both architectures."""
    fx = make_fixture(tmp_path, go_files=None, recipe=recipe)
    shutil.copytree(ROOT / "go" / "pfb_dns_gateway", fx.source / "go" / "pfb_dns_gateway")
    sha = commit_all(fx.source, "the real gateway module")
    _git(fx.source, "tag", "-f", "v4.0.0")
    real = fx._replace(source_sha=sha)
    assert build(real, "project", tmp_path / "out") == 0
    pkg = tmp_path / "out" / PKG_NAME
    assert_dual_arch_payload(pkg)
    _full, _compact, tf = _read_pkg(pkg)
    for target in TARGETS:
        assert tf.getmember(f"{BIN}/{target}/pfb-dns").size > 1_000_000, f"{target} binary is implausibly small"


@by_recipe
def test_project_build_compiles_the_attested_commit_not_the_mutated_worktree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, recipe: str
) -> None:
    fx = make_fixture(tmp_path, recipe=recipe)
    real_attest = bpp._attest_checkout

    def attest_then_mutate(*args: Any, **kwargs: Any) -> None:
        real_attest(*args, **kwargs)
        if args[2] == "source":
            (fx.source / "go" / "pfb_dns_gateway" / "main.go").write_text(
                TINY_GO["main.go"].replace("COMMITTED", "TAMPERED")
            )

    monkeypatch.setattr(bpp, "_attest_checkout", attest_then_mutate)
    assert build(fx, "project", tmp_path / "out") == 0
    _full, _compact, tf = _read_pkg(tmp_path / "out" / PKG_NAME)
    for target in TARGETS:
        data = member(tf, f"{BIN}/{target}/pfb-dns")
        assert b"COMMITTED-SOURCE" in data, f"{target} was not built from the attested commit"
        assert b"TAMPERED-SOURCE" not in data, f"{target} compiled the post-attestation worktree"


@by_recipe
def test_untracked_binary_cannot_bypass_project_attestation(tmp_path: Path, recipe: str) -> None:
    fx = make_fixture(tmp_path, recipe=recipe)
    assert build(fx, "project", tmp_path / "clean") == 0
    assert_dual_arch_payload(tmp_path / "clean" / PKG_NAME)

    forged = fx.source / "src" / DNS_PROXY / "bin" / "freebsd-amd64" / "pfb-dns"
    forged.parent.mkdir(parents=True)
    forged.write_bytes(FORGED)
    assert build(fx, "project", tmp_path / "dirty") == 1
    assert not list((tmp_path / "dirty").glob("*.pkg")), "a package was written from a dirty source tree"


@by_recipe
def test_ignored_binary_in_the_tree_is_neither_shipped_nor_trusted(tmp_path: Path, recipe: str) -> None:
    fx = make_fixture(tmp_path, gitignore="bin/\n", recipe=recipe)
    forged = fx.source / "src" / DNS_PROXY / "bin" / "freebsd-amd64" / "pfb-dns"
    forged.parent.mkdir(parents=True)
    forged.write_bytes(FORGED)
    assert _git(fx.source, "status", "--porcelain", "--untracked-files=all") == "", "the forged file is not ignored"

    assert build(fx, "project", tmp_path / "out") == 0
    assert_dual_arch_payload(tmp_path / "out" / PKG_NAME)
    _full, _compact, tf = _read_pkg(tmp_path / "out" / PKG_NAME)
    assert member(tf, f"{BIN}/freebsd-amd64/pfb-dns") != FORGED


@pytest.mark.parametrize("mode", ["native", "project"])
@by_recipe
def test_binary_already_in_the_source_tree_fails_the_build(
    tmp_path: Path, capfd: pytest.CaptureFixture[str], mode: str, recipe: str
) -> None:
    forged = {f"src/{DNS_PROXY}/bin/freebsd-amd64/pfb-dns": FORGED}
    fx = make_fixture(tmp_path, source_files=forged, recipe=recipe)
    assert build(fx, mode, tmp_path / "out") == 1
    assert "dns_proxy/bin" in capfd.readouterr().err
    assert not list((tmp_path / "out").glob("*.pkg")), "a package shipped a source-tree binary"


@pytest.mark.parametrize("mode", ["native", "project"])
def test_legacy_source_without_a_go_module_needs_no_go_and_ships_no_binaries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    fx = make_fixture(tmp_path, go_files=None)
    without_go_on_path(tmp_path, monkeypatch)
    assert build(fx, mode, tmp_path / "one") == 0
    assert build(fx, mode, tmp_path / "two") == 0
    assert shipped_binaries(tmp_path / "one" / PKG_NAME) == []
    assert_same_package_bytes(tmp_path / "one" / PKG_NAME, tmp_path / "two" / PKG_NAME)


@pytest.mark.parametrize("mode", ["native", "project"])
@by_recipe
def test_go_source_without_a_go_toolchain_fails_and_writes_no_package(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capfd: pytest.CaptureFixture[str], mode: str, recipe: str
) -> None:
    fx = make_fixture(tmp_path, recipe=recipe)
    without_go_on_path(tmp_path, monkeypatch)
    assert build(fx, mode, tmp_path / "out") == 1
    assert "pfB-DNS" in capfd.readouterr().err
    assert not list((tmp_path / "out").glob("*.pkg")), "a Go source tree was packaged without its binaries"


@pytest.mark.parametrize("mode", ["native", "project"])
@by_recipe
def test_go_compile_error_fails_the_build_and_writes_no_package(
    tmp_path: Path, capfd: pytest.CaptureFixture[str], mode: str, recipe: str
) -> None:
    broken = {**TINY_GO, "broken.go": "package main\n\nvar _ = undefinedSymbol\n"}
    fx = make_fixture(tmp_path, go_files=broken, recipe=recipe)
    assert build(fx, mode, tmp_path / "out") == 1
    assert "pfB-DNS" in capfd.readouterr().err
    assert not list((tmp_path / "out").glob("*.pkg")), "a package was written after the Go build failed"


@pytest.mark.parametrize("mode", ["native", "project"])
def test_port_that_does_not_ship_the_dns_proxy_skips_the_go_build(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    """A static-plist channel installs no dns_proxy payload, so Go source in the tree changes nothing for it."""
    fx = make_fixture(tmp_path, ships_dns_proxy=False)
    without_go_on_path(tmp_path, monkeypatch)
    assert build(fx, mode, tmp_path / "out") == 0
    assert shipped_binaries(tmp_path / "out" / PKG_NAME) == []


@by_recipe
def test_remote_tag_source_includes_the_go_module(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, recipe: str) -> None:
    """The codeload tarball carries go/ beside src/, so a tag build gets the binaries too."""
    fx = make_fixture(tmp_path, recipe=recipe)
    archive = subprocess.run(
        ["git", "-C", str(fx.source), "archive", "--format=tar", "--prefix=pfsense-4.0.0/", "HEAD"],
        capture_output=True,
        check=True,
    ).stdout

    def fake_download(_url: str, dest: Path) -> None:
        with tarfile.open(fileobj=io.BytesIO(archive)) as src, tarfile.open(dest, "w:gz") as out:
            for info in src.getmembers():
                out.addfile(info, src.extractfile(info) if info.isfile() else None)

    monkeypatch.setattr(bpp, "_download", fake_download)
    args = [a for a in native_args(fx, tmp_path / "out") if a not in ("--local-src", str(fx.source))]
    assert bpp.main([*args, "--gh-tagname", "v4.0.0"]) == 0
    assert_dual_arch_payload(tmp_path / "out" / PKG_NAME)


@by_recipe
def test_project_rejects_a_go_tree_that_is_a_symlink(tmp_path: Path, recipe: str) -> None:
    """The snapshot now carries `go/` too, so a tracked link there must fail like one under src/."""
    fx = make_fixture(tmp_path, go_files=None, recipe=recipe)
    outside = tmp_path / "outside-module"
    outside.mkdir()
    for name, text in TINY_GO.items():
        (outside / name).write_text(text)
    (fx.source / "go").mkdir()
    (fx.source / "go" / "pfb_dns_gateway").symlink_to(outside)
    sha = commit_all(fx.source, "go module behind a link")
    _git(fx.source, "tag", "-f", "v4.0.0")
    assert build(fx._replace(source_sha=sha), "project", tmp_path / "out") == 1
    assert not list((tmp_path / "out").glob("*.pkg")), "a package was built from a symlinked Go tree"


def test_selector_and_builder_agree_on_the_binary_layout() -> None:
    """The architecture directories and binary name the wrapper looks for are the ones the builder writes."""
    spec = importlib.util.spec_from_file_location("build_pfb_dns", ROOT / "scripts" / "build-pfb-dns.py")
    assert spec is not None and spec.loader is not None
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    wrapper = (ROOT / "src" / DNS_PROXY / "pfb_dns.sh").read_text()
    assert set(re.findall(r"target=(freebsd-[a-z0-9]+)", wrapper)) == set(helper.TARGETS)
    assert f'/bin/${{target}}/{helper.BINARY}"' in wrapper
    assert helper.BINARY == "pfb-dns" and BIN.endswith("/dns_proxy/bin")


def forged_go_on_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, **lie: Any) -> None:
    """Put a `go` first on PATH that is the real toolchain plus one lie about what it built."""
    write_go_wrapper(tmp_path / "forged-go" / "go", **lie)
    monkeypatch.setenv("PATH", f"{tmp_path / 'forged-go'}{os.pathsep}{os.environ['PATH']}")


def matrix_row(major: int) -> dict[str, object]:
    return dict(next(r for r in _LIVE_BUILD_ROWS if r["freebsd_major"] == str(major) and r["variant"] == "CE"))


def leg_make_fixture(root: Path, major: int, recipe: str) -> Fixture:
    return make_fixture(root, php_version=str(matrix_row(major)["php_version"]), recipe=recipe)


def leg_args(fx: Fixture, mode: str, out: Path, major: int) -> list[str]:
    """Builder arguments for the matrix leg that targets FreeBSD ``major`` (the abi / record row it names)."""
    row = matrix_row(major)
    if mode == "native":
        args = native_args(fx, out)
    else:
        record = _record("stable", fx.ports_sha, source_sha=fx.source_sha, row=row)
        args = _project_args(fx.ports, fx.portdir, record, source=fx.source, dry_run=False, out=out)
        args[args.index("--arch") + 1] = f"freebsd:{major}:*"
    args[args.index("--abi") + 1] = f"FreeBSD:{major}:amd64"
    args[args.index("--php") + 1] = str(row["php_version"])
    return args


@pytest.mark.parametrize("mode", ["native", "project"])
@by_recipe
def test_a_binary_linked_for_a_newer_freebsd_than_the_leg_fails_and_writes_no_package(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capfd: pytest.CaptureFixture[str], mode: str, recipe: str
) -> None:
    # Given a toolchain whose binaries carry the ABI tag of FreeBSD 16
    fx = leg_make_fixture(tmp_path, 15, recipe)
    forged_go_on_path(tmp_path, monkeypatch, forgery="abi-note", value=1600000)

    # When the FreeBSD 15 leg builds the package
    assert bpp.main(leg_args(fx, mode, tmp_path / "out", 15)) == 1

    # Then the build names the mismatch and ships nothing
    err = capfd.readouterr().err
    assert "ABI tag 1600000" in err and "FreeBSD 15" in err, err
    assert not list((tmp_path / "out").glob("*.pkg")), "a package was written with a binary too new for its leg"


@pytest.mark.parametrize("mode", ["native", "project"])
@by_recipe
def test_the_same_binaries_ship_on_the_leg_whose_freebsd_is_new_enough(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str, recipe: str
) -> None:
    # Given the same toolchain, which the FreeBSD 15 leg refuses
    fx = leg_make_fixture(tmp_path, 16, recipe)
    forged_go_on_path(tmp_path, monkeypatch, forgery="abi-note", value=1600000)

    # When the FreeBSD 16 leg builds the package
    assert bpp.main(leg_args(fx, mode, tmp_path / "out", 16)) == 0

    # Then both binaries ship, and the manifest targets FreeBSD 16
    pkg = tmp_path / "out" / PKG_NAME
    assert_dual_arch_payload(pkg)
    full, _compact, tf = _read_pkg(pkg)
    assert full["abi"] == "FreeBSD:16:*"
    assert {freebsd_abi_note(member(tf, f"{BIN}/{target}/pfb-dns")) for target in TARGETS} == {1600000}


def direct_helper_binaries(source: Path, out: Path) -> dict[str, bytes]:
    """What build-pfb-dns.py itself writes for ``source`` at the default leg (FreeBSD 15)."""
    helper = ROOT / "scripts" / "build-pfb-dns.py"
    argv = [sys.executable, str(helper), "--source-root", str(source), "--out-dir", str(out), "--freebsd-major", "15"]
    subprocess.run(argv, check=True, capture_output=True)
    return {target: (out / target / "pfb-dns").read_bytes() for target in TARGETS}


@pytest.mark.parametrize("mode", ["native", "project"])
def test_recipe_do_build_and_install_program_ship_both_binaries(tmp_path: Path, mode: str) -> None:
    """
    Scenario: a port whose `do-build` builds pfb-dns and whose `do-install` uses INSTALL_PROGRAM
      When the package is built
      Then both binaries ship at mode 0555, byte for byte what build-pfb-dns.py writes for that source
    """
    fx = make_fixture(tmp_path, recipe="go")

    assert build(fx, mode, tmp_path / "out") == 0

    pkg = tmp_path / "out" / PKG_NAME
    assert_dual_arch_payload(pkg)
    _full, _compact, tf = _read_pkg(pkg)
    for target, direct in direct_helper_binaries(fx.source, tmp_path / "direct").items():
        assert member(tf, f"{BIN}/{target}/pfb-dns") == direct, f"{target} is not what the helper builds"


def test_the_go_recipe_ships_the_same_package_as_the_builders_own_staging(tmp_path: Path) -> None:
    legacy = make_fixture(tmp_path / "legacy")
    recipe = make_fixture(tmp_path / "recipe", recipe="go")

    assert build(legacy, "native", tmp_path / "legacy-out") == 0
    assert build(recipe, "native", tmp_path / "recipe-out") == 0

    assert_same_package_bytes(tmp_path / "legacy-out" / PKG_NAME, tmp_path / "recipe-out" / PKG_NAME)


def modules_txt_for(*modules: tuple[str, str]) -> str:
    return "".join(f"# {path} {version}\n## explicit; go 1.21\n{path}\n" for path, version in modules)


def gh_tuples_for(*modules: tuple[str, str]) -> tuple[str, ...]:
    """GH_TUPLE entries that unpack the given (module path, version) pairs into the vendor tree."""
    return tuple(
        f"owner:project{index}:{version}:group{index}/{GO_VENDOR}/{path}"
        for index, (path, version) in enumerate(modules)
    )


QUIC = ("github.com/quic-go/quic-go", "v0.64.0")
OLDER_QUIC = ("github.com/quic-go/quic-go", "v0.63.0")
NET = ("golang.org/x/net", "v0.56.0")
PSEUDO = ("example.test/dep", "v0.0.0-20260101000000-0123456789ab")
REPLACED = "# github.com/quic-go/quic-go v0.64.0 => example.test/fork v1.0.0\n## explicit; go 1.21\n"
UNVENDORED = "o:p:v0.64.0:g/vendor/github.com/quic-go/quic-go"
THREE_FIELDS = "o:p:v0.64.0"

# (id, the port's GH_TUPLE, the port's modules.txt (None: the recipe names none), what the error must say)
PARITY_FAILURES = [
    ("version-differs", gh_tuples_for(OLDER_QUIC, NET), modules_txt_for(QUIC, NET), "quic-go"),
    ("tuple-missing", gh_tuples_for(NET), modules_txt_for(QUIC, NET), "quic-go"),
    ("module-missing-from-modules-txt", gh_tuples_for(QUIC, NET), modules_txt_for(NET), "quic-go"),
    ("empty-gh-tuple", (), modules_txt_for(QUIC), "quic-go"),
    ("no-modules-txt", gh_tuples_for(QUIC), None, "quic-go"),
    ("replace-directive", gh_tuples_for(QUIC), REPLACED + "github.com/quic-go/quic-go\n", "=>"),
    ("pseudo-version", gh_tuples_for(PSEUDO), modules_txt_for(PSEUDO), "pseudo-version"),
    ("tuple-outside-the-vendor-tree", (UNVENDORED,), modules_txt_for(QUIC), "vendor"),
    ("tuple-with-three-fields", (THREE_FIELDS,), modules_txt_for(QUIC), "account:project:tag"),
]


@pytest.mark.parametrize("mode", ["native", "project"])
@pytest.mark.parametrize(
    ("gh_tuple", "modules_txt", "says"), [row[1:] for row in PARITY_FAILURES], ids=[row[0] for row in PARITY_FAILURES]
)
def test_gh_tuple_that_disagrees_with_modules_txt_fails_before_go_runs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
    mode: str,
    gh_tuple: tuple[str, ...],
    modules_txt: str | None,
    says: str,
) -> None:
    fx = make_fixture(tmp_path, recipe="go", gh_tuple=gh_tuple, modules_txt=modules_txt)
    without_go_on_path(tmp_path, monkeypatch)

    assert build(fx, mode, tmp_path / "out") == 1

    err = capfd.readouterr().err
    assert says in err, err
    assert "Go toolchain not found" not in err, "Go was started although the recipe's modules disagree"
    assert not list((tmp_path / "out").glob("*.pkg")), "a package was written from disagreeing modules"


@pytest.mark.parametrize("mode", ["native", "project"])
def test_a_gh_tuple_that_matches_modules_txt_goes_on_to_the_go_build(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capfd: pytest.CaptureFixture[str], mode: str
) -> None:
    fx = make_fixture(tmp_path, recipe="go", gh_tuple=gh_tuples_for(QUIC, NET), modules_txt=modules_txt_for(QUIC, NET))
    without_go_on_path(tmp_path, monkeypatch)

    assert build(fx, mode, tmp_path / "out") == 1

    assert "Go toolchain not found" in capfd.readouterr().err, "the matching modules were refused before Go"


DO_BUILD = go_do_build(modules_txt=False)
UNRECOGNISED_DO_BUILD = {
    "raw-go-build": "\t${GO_CMD} build -o ${WRKDIR}/pfb-dns/freebsd-amd64/pfb-dns .\n",
    "extra-flag": DO_BUILD.replace("--vendored", "--vendored --debug"),
    "other-source-root": DO_BUILD.replace("--source-root .", "--source-root .."),
    "not-vendored": DO_BUILD.replace(" --vendored", ""),
    "other-go": DO_BUILD.replace("${GO_CMD}", "/opt/go/bin/go"),
    "other-major": DO_BUILD.replace("${OSREL:R}", "99"),
    "out-dir-outside-wrkdir": DO_BUILD.replace("${WRKDIR}/pfb-dns", "${STAGEDIR}/pfb-dns"),
    "second-command": DO_BUILD + "\t${ECHO_MSG} done\n",
    "command-after-the-closing-paren": DO_BUILD.rstrip("\n") + " ; ${RM} -rf ${WRKDIR}\n",
}


@pytest.mark.parametrize("do_build", UNRECOGNISED_DO_BUILD.values(), ids=UNRECOGNISED_DO_BUILD.keys())
def test_an_unrecognised_do_build_fails(tmp_path: Path, capfd: pytest.CaptureFixture[str], do_build: str) -> None:
    fx = make_fixture(tmp_path, recipe="go", do_build=do_build)

    assert build(fx, "native", tmp_path / "out") == 1

    assert "do-build" in capfd.readouterr().err
    assert not list((tmp_path / "out").glob("*.pkg")), "a package was built from a do-build the builder cannot follow"


@pytest.mark.parametrize("mode", ["native", "project"])
def test_go_recipe_with_a_legacy_source_fails(tmp_path: Path, capfd: pytest.CaptureFixture[str], mode: str) -> None:
    fx = make_fixture(tmp_path, go_files=None, recipe="go")

    assert build(fx, mode, tmp_path / "out") == 1

    err = capfd.readouterr().err
    assert "go/pfb_dns_gateway" in err and "rebase" in err, err
    assert not list((tmp_path / "out").glob("*.pkg")), "a package without pfb-dns was built from a go recipe"


@pytest.fixture(scope="module")
def real_modules_txt(tmp_path_factory: pytest.TempPathFactory) -> str:
    """The vendor/modules.txt Go writes for this checkout's real gateway."""
    module = tmp_path_factory.mktemp("real-modules") / "pfb_dns_gateway"
    shutil.copytree(ROOT / "go" / "pfb_dns_gateway", module)
    subprocess.run(["go", "mod", "vendor"], cwd=module, check=True, capture_output=True, timeout=1800)
    return (module / "vendor" / "modules.txt").read_text()


def real_gateway_fixture(root: Path, modules_txt: str) -> Fixture:
    """The go recipe over the real gateway, its GH_TUPLE naming the modules ``modules_txt`` lists."""
    modules = [tuple(line[2:].split()) for line in modules_txt.splitlines() if line.startswith("# ")]
    pairs = [(path, version) for path, version in modules]
    fx = make_fixture(root, go_files=None, recipe="go", gh_tuple=gh_tuples_for(*pairs), modules_txt=modules_txt)
    shutil.copytree(ROOT / "go" / "pfb_dns_gateway", fx.source / "go" / "pfb_dns_gateway")
    sha = commit_all(fx.source, "the real gateway module")
    _git(fx.source, "tag", "-f", "v4.0.0")
    return fx._replace(source_sha=sha)


@pytest.mark.parametrize("mode", ["native", "project"])
def test_the_ports_modules_of_the_real_gateway_build_the_package(
    tmp_path: Path, real_modules_txt: str, mode: str
) -> None:
    fx = real_gateway_fixture(tmp_path, real_modules_txt)

    assert build(fx, mode, tmp_path / "out") == 0

    assert_dual_arch_payload(tmp_path / "out" / PKG_NAME)


def test_port_modules_txt_that_differs_from_the_source_fails(
    tmp_path: Path, capfd: pytest.CaptureFixture[str], real_modules_txt: str
) -> None:
    # Given a port whose tuples still match its modules.txt headers, but whose file lost a package line
    lines = real_modules_txt.splitlines(keepends=True)
    del lines[next(index for index, line in enumerate(lines) if not line.startswith("#"))]
    fx = real_gateway_fixture(tmp_path, "".join(lines))

    assert build(fx, "project", tmp_path / "out") == 1

    assert "modules.txt" in capfd.readouterr().err
    assert not list((tmp_path / "out").glob("*.pkg")), (
        "a package was built from a modules.txt the source disagrees with"
    )
