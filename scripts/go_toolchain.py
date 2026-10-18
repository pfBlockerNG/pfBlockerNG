#!/usr/bin/env python3
# go_toolchain.py — the pinned Go compiler, for a runner that has none (issue #3513).
#
# usage: go_toolchain.py install [--parent DIR]
#        go_toolchain.py remove ROOT
#
#   install  creates a private directory under DIR (default: the system temp directory), downloads the pinned
#            archive into it, hashes it as it arrives and extracts it ONLY when the sha256 is the pinned one,
#            checks `go version`, and prints `export` lines (PFB_GO_ROOT, GOROOT, PATH, GOPATH, GOCACHE,
#            GOMODCACHE, GOTMPDIR, GOTOOLCHAIN) for a POSIX shell to `eval`. The compiler and every Go cache sit
#            inside that directory; nothing is installed system-wide and the user's own caches are not touched.
#            Any failure removes what it made and prints nothing on stdout.
#   remove   deletes a ROOT that `install` made, and nothing else: it must be a real directory (not a link)
#            named like ours, owned by the caller, and hold the marker `install` wrote.
#
# A platform with no pinned archive fails by name; no other platform's archive is ever substituted.
# Stdlib only.

from __future__ import annotations

import argparse
import hashlib
import os
import platform
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import BinaryIO

GO_VERSION = "go1.27.0"
# (platform.system(), platform.machine()) -> (archive, sha256); https://go.dev/dl/?mode=json&include=all lists both.
ARCHIVES = {
    ("Linux", "x86_64"): (
        f"{GO_VERSION}.linux-amd64.tar.gz",
        "675c26c449cbb18fc24b74650de1eabbae6e16f64326fd85a283fb3b58280685",
    ),
}
URL = "https://go.dev/dl/{}"
PREFIX = "pfb-go-"
MARKER = ".pfb-managed-go-toolchain"
MARKER_TEXT = "a Go toolchain go_toolchain.py installed; go_toolchain.py remove may delete this directory\n"
CACHES = ("gopath", "gocache", "gomodcache", "gotmp")


class ToolchainError(Exception):
    pass


def _download(url: str) -> BinaryIO:
    return urllib.request.urlopen(url, timeout=120)


def environment(root: Path) -> dict[str, str]:
    goroot = root / "go"
    return {
        "PFB_GO_ROOT": str(root),
        "GOROOT": str(goroot),
        "PATH": f"{goroot / 'bin'}{os.pathsep}{os.environ.get('PATH', os.defpath)}",
        "GOPATH": str(root / "gopath"),
        "GOCACHE": str(root / "gocache"),
        "GOMODCACHE": str(root / "gomodcache"),
        "GOTMPDIR": str(root / "gotmp"),
        "GOTOOLCHAIN": "local",
    }


def _inside(root: Path, path: str) -> bool:
    return os.path.commonpath([str(root), path]) == str(root)


def _check_member(member: tarfile.TarInfo, root: Path) -> None:
    where = f"archive member {member.name!r}"
    if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
        raise ToolchainError(f"refusing {where}: unsafe type (a device, fifo or other special file)")
    target = os.path.normpath(os.path.join(root, member.name))
    if not _inside(root, target):
        raise ToolchainError(f"refusing {where}: unsafe name, it leaves {root}")
    if member.issym() or member.islnk():
        # A symlink resolves from its own directory, a hard link from the archive root.
        base = os.path.dirname(target) if member.issym() else str(root)
        link = os.path.normpath(os.path.join(base, member.linkname))
        if os.path.isabs(member.linkname) or not _inside(root, link):
            raise ToolchainError(f"refusing {where}: unsafe link to {member.linkname!r}, it leaves {root}")


def _extract(archive: Path, root: Path) -> None:
    with tarfile.open(archive) as tar:
        members = tar.getmembers()
        for member in members:
            _check_member(member, root)
        if hasattr(tarfile, "data_filter"):
            tar.extractall(root, members=members, filter="data")
        else:
            tar.extractall(root, members=members)  # every member was checked above


def _fetch_verified(fetch: Callable[[str], BinaryIO], url: str, sha256: str, dest: Path) -> None:
    digest = hashlib.sha256()
    try:
        with fetch(url) as response, dest.open("wb") as out:
            while chunk := response.read(1 << 20):
                digest.update(chunk)
                out.write(chunk)
    except OSError as exc:
        raise ToolchainError(f"cannot download {url}: {exc}") from exc
    if digest.hexdigest() != sha256:
        raise ToolchainError(f"{url}: sha256 expected {sha256}, got {digest.hexdigest()}")


def _check_version(root: Path) -> None:
    go = root / "go" / "bin" / "go"
    if not go.is_file():
        raise ToolchainError(f"the archive holds no {go.relative_to(root)}")
    try:
        result = subprocess.run(
            [str(go), "version"],
            env={**os.environ, **environment(root)},
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ToolchainError(f"cannot run {go}: {exc}") from exc
    if GO_VERSION not in result.stdout:
        raise ToolchainError(f"expected {GO_VERSION}, `go version` says {result.stdout!r} {result.stderr!r}")


def install(
    parent: Path | None = None,
    *,
    system: str | None = None,
    machine: str | None = None,
    fetch: Callable[[str], BinaryIO] = _download,
) -> Path:
    """Install the pinned toolchain into a new private directory under ``parent``; return that directory."""
    system = platform.system() if system is None else system
    machine = platform.machine() if machine is None else machine
    entry = ARCHIVES.get((system, machine))
    if entry is None:
        known = ", ".join(f"{s}/{m}" for s, m in ARCHIVES)
        raise ToolchainError(f"no pinned Go archive for {system}/{machine}; this tool serves {known}")
    archive, sha256 = entry
    root = Path(tempfile.mkdtemp(prefix=PREFIX, dir=parent))
    try:
        (root / MARKER).write_text(MARKER_TEXT, encoding="utf-8")
        _fetch_verified(fetch, URL.format(archive), sha256, root / archive)
        _extract(root / archive, root)
        (root / archive).unlink()
        for name in CACHES:
            (root / name).mkdir()
        _check_version(root)
    except BaseException:
        _delete(root)
        raise
    return root


def _delete(root: Path) -> None:
    # go leaves its module cache read-only; a directory must be writable before its entries can go.
    os.chmod(root, 0o700)
    for directory, names, _files in os.walk(root):
        for name in names:
            path = os.path.join(directory, name)
            if not os.path.islink(path):
                os.chmod(path, 0o700)
    shutil.rmtree(root)


def remove(root: Path) -> None:
    """Delete ``root`` if, and only if, ``install`` made it; a missing ``root`` is fine."""
    root = Path(root)
    try:
        info = root.lstat()
    except FileNotFoundError:
        return
    marker = root / MARKER
    try:
        ours = (
            root.is_dir()
            and not root.is_symlink()
            and root.name.startswith(PREFIX)
            and marker.is_file()
            and not marker.is_symlink()
            and marker.read_text(encoding="utf-8") == MARKER_TEXT
        )
    except (OSError, UnicodeDecodeError):
        ours = False
    if not ours:
        raise ToolchainError(f"refusing to delete {root}: not a directory this tool made")
    if info.st_uid != os.geteuid():
        raise ToolchainError(f"refusing to delete {root}: owner uid {info.st_uid} is not this user's ({os.geteuid()})")
    try:
        _delete(root)
    except OSError as exc:
        raise ToolchainError(f"cannot delete {root}: {exc}") from exc


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="The pinned Go compiler for a runner that has none (issue #3513).")
    commands = ap.add_subparsers(dest="command", required=True)
    install_cmd = commands.add_parser("install", help="install it and print the shell exports for it")
    install_cmd.add_argument("--parent", type=Path, default=None, help="where its private directory is made")
    remove_cmd = commands.add_parser("remove", help="delete a directory `install` made")
    remove_cmd.add_argument("root", type=Path)
    args = ap.parse_args(argv)
    try:
        if args.command == "install":
            root = install(args.parent)
            sys.stderr.write(f"go_toolchain: {GO_VERSION} installed in {root}\n")
            for key, value in environment(root).items():
                print(f"export {key}={shlex.quote(value)}")
        else:
            remove(args.root)
    except ToolchainError as exc:
        sys.stderr.write(f"go_toolchain: {exc}\n")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
