"""Tests for scripts/go_toolchain.py (issue #3513): the pinned Go compiler for a runner that has none.

A leased smoke box builds the pfB-DNS payload (build-pfb-dns.py needs Go) before any test runs, so the one
place that knows how to fetch, check and unpack the compiler is this helper. These cases drive its real code
with a fake download (a few bytes of tarball, a `go` that is a shell script), never the network:

* the archive is hashed as it downloads and nothing is extracted unless the hash is the pinned one;
* what is extracted cannot leave the root: `..`, absolute names, links and devices are refused;
* a platform with no pinned archive fails by name, without a download and without picking another archive;
* a failed install leaves nothing behind, and `remove` deletes only a directory this helper made.
"""

from __future__ import annotations

import hashlib
import io
import os
import stat
import subprocess
import tarfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from scripts import go_toolchain
from tests.test_ci_tool_pins import GO_PIN

ARCHIVE = f"{go_toolchain.GO_VERSION}.linux-amd64.tar.gz"
GO_SCRIPT = "#!/bin/sh\necho 'go version {version} linux/amd64'\n"


def add_file(tar: tarfile.TarFile, name: str, data: bytes, mode: int = 0o644) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = mode
    tar.addfile(info, io.BytesIO(data))


def add_special(tar: tarfile.TarFile, name: str, kind: bytes, target: str = "") -> None:
    info = tarfile.TarInfo(name)
    info.type = kind
    info.linkname = target
    tar.addfile(info)


def archive_bytes(
    version: str = go_toolchain.GO_VERSION, extra: Callable[[tarfile.TarFile], None] | None = None
) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        add_file(tar, "go/bin/go", GO_SCRIPT.format(version=version).encode(), 0o755)
        add_file(tar, "go/VERSION", f"{version}\n".encode())
        if extra:
            extra(tar)
    return buffer.getvalue()


class Fetch:
    """A download double: records every URL asked for and answers with ``payload`` (or raises it)."""

    def __init__(self, payload: bytes | Exception) -> None:
        self.payload = payload
        self.urls: list[str] = []

    def __call__(self, url: str) -> io.BytesIO:
        self.urls.append(url)
        if isinstance(self.payload, Exception):
            raise self.payload
        return io.BytesIO(self.payload)


@pytest.fixture
def pin(monkeypatch: pytest.MonkeyPatch) -> Callable[[bytes], None]:
    """Make ``payload`` the archive the helper believes in for Linux/x86_64."""

    def pin_payload(payload: bytes) -> None:
        monkeypatch.setitem(go_toolchain.ARCHIVES, ("Linux", "x86_64"), (ARCHIVE, hashlib.sha256(payload).hexdigest()))

    return pin_payload


def install(parent: Path, fetch: Fetch, machine: str = "x86_64", system: str = "Linux") -> Path:
    return go_toolchain.install(parent, system=system, machine=machine, fetch=fetch)


def test_the_pin_is_the_one_ci_installs_and_names_a_real_archive_per_platform() -> None:
    assert go_toolchain.GO_VERSION == f"go{GO_PIN}"
    assert go_toolchain.ARCHIVES, "no platform has a pinned archive"
    for (system, machine), (archive, digest) in go_toolchain.ARCHIVES.items():
        assert archive.startswith(go_toolchain.GO_VERSION + "."), (system, machine, archive)
        assert len(digest) == 64 and set(digest) <= set("0123456789abcdef"), (system, machine, digest)


def test_it_installs_the_checked_archive_and_answers_with_the_run_environment(
    tmp_path: Path, pin: Callable[[bytes], None]
) -> None:
    # Given an archive whose hash is the pinned one
    payload = archive_bytes()
    pin(payload)
    fetch = Fetch(payload)

    # When it is installed
    root = install(tmp_path, fetch)

    # Then it was downloaded once from go.dev, lives under the parent, and is a managed directory
    assert fetch.urls == [f"https://go.dev/dl/{ARCHIVE}"]
    assert root.parent == tmp_path and root.name.startswith("pfb-go-")
    assert (root / "go" / "bin" / "go").stat().st_mode & stat.S_IXUSR
    assert not (root / ARCHIVE).exists(), "the downloaded archive is not kept"
    assert (root / go_toolchain.MARKER).is_file()
    env = go_toolchain.environment(root)
    assert env["PFB_GO_ROOT"] == str(root)
    assert env["GOROOT"] == str(root / "go")
    assert env["PATH"].startswith(f"{root / 'go' / 'bin'}{os.pathsep}")
    assert env["GOTOOLCHAIN"] == "local"
    for key in ("GOPATH", "GOCACHE", "GOMODCACHE", "GOTMPDIR"):
        assert Path(env[key]).parent == root and Path(env[key]).is_dir(), (key, env[key])
    assert "HOME" not in env, "the user's home and its caches are never redirected, let alone cleaned"


def test_a_wrong_checksum_fails_closed_before_anything_is_extracted(
    tmp_path: Path, pin: Callable[[bytes], None], monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given a download that is not the pinned archive
    pin(archive_bytes())
    tampered = archive_bytes(extra=lambda tar: add_file(tar, "go/bin/backdoor", b"x", 0o755))

    def refuse_to_open(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("an archive that failed its checksum was opened")

    monkeypatch.setattr(go_toolchain.tarfile, "open", refuse_to_open)

    # When it is installed
    with pytest.raises(go_toolchain.ToolchainError, match="sha256"):
        install(tmp_path, Fetch(tampered))

    # Then it was refused before extraction, and nothing is left under the parent
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "plant",
    [
        pytest.param(lambda tar: add_file(tar, "../escape", b"x"), id="parent-relative name"),
        pytest.param(lambda tar: add_file(tar, "go/../../escape", b"x"), id="name that climbs out"),
        pytest.param(lambda tar: add_file(tar, "/tmp/pfb-go-escape-absolute", b"x"), id="absolute name"),
        pytest.param(lambda tar: add_special(tar, "go/link", tarfile.SYMTYPE, "../../outside"), id="symlink out"),
        pytest.param(lambda tar: add_special(tar, "go/abs", tarfile.SYMTYPE, "/etc/passwd"), id="absolute symlink"),
        pytest.param(lambda tar: add_special(tar, "go/hard", tarfile.LNKTYPE, "../../outside"), id="hardlink out"),
        pytest.param(lambda tar: add_special(tar, "go/dev", tarfile.CHRTYPE), id="device node"),
        pytest.param(lambda tar: add_special(tar, "go/fifo", tarfile.FIFOTYPE), id="fifo"),
    ],
)
def test_a_member_that_could_leave_the_root_is_refused_even_with_the_right_checksum(
    tmp_path: Path, pin: Callable[[bytes], None], plant: Callable[[tarfile.TarFile], None]
) -> None:
    # Given an archive that passes its checksum but carries a hostile member
    payload = archive_bytes(extra=plant)
    pin(payload)
    parent = tmp_path / "scratch"
    parent.mkdir()

    # When it is installed
    with pytest.raises(go_toolchain.ToolchainError, match="unsafe|refus"):
        install(parent, Fetch(payload))

    # Then nothing was written outside the root, and the root itself is gone
    assert not (tmp_path / "escape").exists()
    assert not Path("/tmp/pfb-go-escape-absolute").exists()
    assert list(parent.iterdir()) == []
    assert sorted(p.name for p in tmp_path.iterdir()) == ["scratch"]


@pytest.mark.parametrize(
    ("system", "machine"),
    [("Linux", "aarch64"), ("Linux", "armv7l"), ("Darwin", "arm64"), ("FreeBSD", "amd64"), ("Windows", "AMD64")],
)
def test_a_platform_without_a_pinned_archive_fails_by_name_and_downloads_nothing(
    tmp_path: Path, system: str, machine: str
) -> None:
    fetch = Fetch(archive_bytes())

    with pytest.raises(go_toolchain.ToolchainError) as raised:
        install(tmp_path, fetch, machine=machine, system=system)

    message = str(raised.value)
    assert f"{system}/{machine}" in message, "the message names the platform it refused"
    assert "Linux/x86_64" in message, "and the platforms it can serve"
    assert fetch.urls == [], "no other platform's archive was fetched instead"
    assert list(tmp_path.iterdir()) == []


def test_a_download_that_fails_is_reported_and_leaves_nothing(tmp_path: Path) -> None:
    with pytest.raises(go_toolchain.ToolchainError, match="go.dev"):
        install(tmp_path, Fetch(OSError("connection refused")))
    assert list(tmp_path.iterdir()) == []


def test_a_compiler_that_reports_another_version_is_refused(tmp_path: Path, pin: Callable[[bytes], None]) -> None:
    payload = archive_bytes(version="go1.26.0")
    pin(payload)

    with pytest.raises(go_toolchain.ToolchainError, match=go_toolchain.GO_VERSION):
        install(tmp_path, Fetch(payload))

    assert list(tmp_path.iterdir()) == []


def installed_root(tmp_path: Path, pin: Callable[[bytes], None]) -> Path:
    payload = archive_bytes()
    pin(payload)
    return install(tmp_path, Fetch(payload))


def test_remove_deletes_a_root_it_made_including_a_read_only_module_cache(
    tmp_path: Path, pin: Callable[[bytes], None]
) -> None:
    # Given an installed root whose module cache is read-only, as go leaves it
    root = installed_root(tmp_path, pin)
    cached = root / "gomodcache" / "example.com" / "mod@v1.0.0"
    cached.mkdir(parents=True)
    (cached / "file.go").write_text("package mod\n")
    (cached / "file.go").chmod(0o444)
    cached.chmod(0o555)
    cached.parent.chmod(0o555)

    # When it is removed
    go_toolchain.remove(root)

    # Then none of it remains
    assert not root.exists()
    assert list(tmp_path.iterdir()) == []


def test_remove_is_idempotent(tmp_path: Path, pin: Callable[[bytes], None]) -> None:
    root = installed_root(tmp_path, pin)
    go_toolchain.remove(root)
    go_toolchain.remove(root)
    go_toolchain.remove(tmp_path / "never-existed")


def test_remove_refuses_a_directory_this_helper_did_not_make(tmp_path: Path) -> None:
    # Given a directory that merely looks like one of ours
    foreign = tmp_path / "pfb-go-lookalike"
    (foreign / "keep").mkdir(parents=True)
    unprefixed = tmp_path / "somebody-elses"
    unprefixed.mkdir()
    (unprefixed / go_toolchain.MARKER).write_text(go_toolchain.MARKER_TEXT)
    wrong_marker = tmp_path / "pfb-go-wrong"
    wrong_marker.mkdir()
    (wrong_marker / go_toolchain.MARKER).write_text("something else\n")

    for path in (foreign, unprefixed, wrong_marker):
        with pytest.raises(go_toolchain.ToolchainError, match="not a directory this tool made|refus"):
            go_toolchain.remove(path)
        assert path.is_dir(), f"{path} was deleted"
    assert (foreign / "keep").is_dir()


def test_remove_does_not_follow_a_symlink_to_a_managed_root(tmp_path: Path, pin: Callable[[bytes], None]) -> None:
    root = installed_root(tmp_path, pin)
    link = tmp_path / "pfb-go-link"
    link.symlink_to(root, target_is_directory=True)

    with pytest.raises(go_toolchain.ToolchainError):
        go_toolchain.remove(link)

    assert (root / go_toolchain.MARKER).is_file(), "the target of the link survived"


def test_remove_refuses_a_root_owned_by_someone_else(
    tmp_path: Path, pin: Callable[[bytes], None], monkeypatch: pytest.MonkeyPatch
) -> None:
    root = installed_root(tmp_path, pin)
    someone_else = os.geteuid() + 1
    monkeypatch.setattr(go_toolchain.os, "geteuid", lambda: someone_else)

    with pytest.raises(go_toolchain.ToolchainError, match="owner|uid"):
        go_toolchain.remove(root)

    assert root.is_dir()


def test_the_install_command_prints_exports_a_posix_shell_evaluates_back_to_the_same_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Given a root whose path holds a space and a quote, the characters that break naive exports
    root = tmp_path / "it's here" / "pfb-go-abc"
    (root / "go" / "bin").mkdir(parents=True)
    monkeypatch.setattr(go_toolchain, "install", lambda *args, **kwargs: root)

    # When the install command runs
    assert go_toolchain.main(["install"]) == 0

    # Then stdout is nothing but exports, and `eval` of it gives the helper's own environment
    out = capsys.readouterr().out
    assert out.strip() and all(line.startswith("export ") for line in out.splitlines()), out
    shell = subprocess.run(
        ["sh", "-c", f'{out}\nprintf "%s\\n" "$PFB_GO_ROOT" "$GOROOT" "$GOCACHE" "$GOTOOLCHAIN"'],
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    )
    assert shell.stdout.splitlines() == [str(root), str(root / "go"), str(root / "gocache"), "local"]


def test_the_install_command_fails_with_nothing_on_stdout_when_the_install_fails(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fail(*args: Any, **kwargs: Any) -> Path:
        raise go_toolchain.ToolchainError("boom")

    monkeypatch.setattr(go_toolchain, "install", fail)

    assert go_toolchain.main(["install"]) == 1

    captured = capsys.readouterr()
    assert captured.out == "", "nothing for a caller's eval to run"
    assert "boom" in captured.err


def test_the_remove_command_fails_loudly_on_a_directory_it_did_not_make(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    foreign = tmp_path / "pfb-go-lookalike"
    foreign.mkdir()

    assert go_toolchain.main(["remove", str(foreign)]) == 1

    assert foreign.is_dir()
    assert "go_toolchain" in capsys.readouterr().err
