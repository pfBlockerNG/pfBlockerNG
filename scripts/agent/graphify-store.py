#!/usr/bin/env python3
"""Store opaque Graphify snapshots in a local Git repository."""

from __future__ import annotations

import argparse
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from collections.abc import Callable
from pathlib import Path

SHA_RE = re.compile(r"^[0-9a-fA-F]{40,64}$")
CANONICAL_ARTIFACTS = ("graph.json", "GRAPH_REPORT.md")


class StoreError(RuntimeError):
    """A caller-actionable Graphify store failure."""


def _run(root: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        text=True,
        capture_output=True,
    )
    if check and result.returncode:
        detail = result.stderr.strip() or result.stdout.strip() or "git failed"
        raise StoreError(detail)
    return result


def _valid_sha(sha: str) -> str:
    if not SHA_RE.fullmatch(sha):
        raise StoreError(f"invalid source SHA: {sha!r}")
    return sha.lower()


def _valid_branch(root: Path, branch: str) -> None:
    if not branch or _run(root, "check-ref-format", f"refs/heads/{branch}", check=False).returncode:
        raise StoreError(f"invalid graph branch: {branch!r}")


def _tag(branch: str, sha: str) -> str:
    return f"source/{branch}/{sha}"


def _physical_path(path: Path, label: str) -> Path:
    absolute = Path(os.path.abspath(path))
    if absolute != absolute.resolve(strict=False):
        raise StoreError(f"refusing symlinked {label} path: {absolute}")
    return absolute


def _store_root(path: Path) -> Path:
    return _physical_path(path, "Graphify store root")


def _ensure_store(path: Path) -> Path:
    path = _store_root(path)
    if path.exists() and not path.is_dir():
        raise StoreError(f"Graphify store root is not a directory: {path}")
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.mkdir()
        _run(path.parent, "init", "-q", str(path))
        _run(path, "config", "user.name", "Graphify Store")
        _run(path, "config", "user.email", "graphify-store@localhost")
    if not path.is_dir() or _run(path, "rev-parse", "--is-inside-work-tree", check=False).stdout.strip() != "true":
        raise StoreError(f"not a normal Git repository: {path}")
    return path


def _source_payload(builder: Path) -> Path:
    builder = _physical_path(builder, "builder")
    if not builder.is_dir() or builder.is_symlink():
        raise StoreError(f"builder is not a directory: {builder}")
    validate_builder(builder)
    payload = builder / "graphify-out"
    if not payload.is_dir() or payload.is_symlink():
        raise StoreError(f"builder has no managed graphify-out directory: {payload}")
    return payload


def validate_builder(builder: Path) -> None:
    builder = _physical_path(builder, "builder")
    if not builder.is_dir() or builder.is_symlink():
        raise StoreError(f"builder is not a directory: {builder}")
    output = builder / "graphify-out"
    try:
        mode = output.lstat().st_mode
    except FileNotFoundError:
        return
    if not stat.S_ISDIR(mode):
        raise StoreError(f"refusing unmanaged graphify-out path: {output}")
    memory = output / "memory"
    try:
        memory.lstat()
    except FileNotFoundError:
        return
    raise StoreError(f"refusing Graphify work memory: {memory}")


def _canonical_files(payload: Path) -> tuple[Path, ...]:
    files: list[Path] = []
    for name in CANONICAL_ARTIFACTS:
        path = payload / name
        try:
            mode = path.lstat().st_mode
        except FileNotFoundError as error:
            raise StoreError(f"missing canonical Graphify artifact: {path}") from error
        if not stat.S_ISREG(mode):
            raise StoreError(f"canonical Graphify artifact is not a regular file: {path}")
        files.append(path)
    return tuple(files)


def _remove_scratch(scratch: Path) -> None:
    """Remove a swap scratch directory, never raising; residue would block `git worktree remove`."""

    def retry(function: Callable[[str], object], path: str, _excinfo: object) -> None:
        try:
            if os.fspath(path) != os.fspath(scratch):
                # An unwritable parent is what blocks the unlink -- but the scratch's own
                # parent belongs to the caller, so leave residue rather than widen it.
                os.chmod(os.path.dirname(path), stat.S_IRWXU)
            os.chmod(path, stat.S_IRWXU)
            function(path)
        except OSError:
            pass

    shutil.rmtree(scratch, onerror=retry)


def _swap_payload(artifacts: tuple[Path, ...], target: Path) -> None:
    """Stage the canonical artifacts, then swap them in, keeping the old payload on failure."""
    scratch = Path(tempfile.mkdtemp(dir=target.parent, prefix=".graphify-swap-"))
    staged = scratch / "graphify-out"
    previous = scratch / "previous"
    try:
        staged.mkdir()
        for source_file in artifacts:
            shutil.copy2(source_file, staged / source_file.name)
        if target.exists():
            os.replace(target, previous)
        try:
            os.replace(staged, target)
        except OSError:
            if previous.exists():
                os.replace(previous, target)
            raise
    except OSError as error:
        if previous.exists():
            raise StoreError(f"the previous Graphify payload is kept at {previous}") from error
        _remove_scratch(scratch)
        raise
    _remove_scratch(scratch)


def _replace_payload(source: Path, target_root: Path) -> None:
    target_root = _physical_path(target_root, "restore target")
    if not target_root.is_dir() or target_root.is_symlink():
        raise StoreError(f"target is not a directory: {target_root}")
    validate_builder(target_root)
    artifacts = _canonical_files(source)
    target = target_root / "graphify-out"
    if target.is_symlink() or (target.exists() and not target.is_dir()):
        raise StoreError(f"refusing unmanaged graphify-out target: {target}")
    _swap_payload(artifacts, target)


def _branch_exists(store: Path, branch: str) -> bool:
    return _run(store, "show-ref", "--verify", "--quiet", f"refs/heads/{branch}", check=False).returncode == 0


def _commit_for(store: Path, ref: str) -> str | None:
    result = _run(store, "rev-parse", "--verify", f"{ref}^{{commit}}", check=False)
    return result.stdout.strip() if result.returncode == 0 else None


def _archive_payload(store: Path, commit: str, destination: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="graphify-restore-") as temporary:
        archive = Path(temporary) / "snapshot.tar"
        _run(store, "archive", "--format=tar", "-o", str(archive), commit, "graphify-out")
        unpacked = Path(temporary) / "unpacked"
        unpacked.mkdir()
        with tarfile.open(archive) as tar:
            members = tar.getmembers()
            for member in members:
                member_path = Path(member.name)
                if member_path.is_absolute() or ".." in member_path.parts:
                    raise StoreError("store snapshot contains an unsafe path")
            tar.extractall(unpacked, filter="data")
        payload = unpacked / "graphify-out"
        if not payload.is_dir():
            raise StoreError(f"store snapshot has no graphify-out payload: {commit}")
        _replace_payload(payload, destination)


def has_exact(store_root: Path, branch: str, sha: str) -> bool:
    sha = _valid_sha(sha)
    store_root = _store_root(store_root)
    if not store_root.is_dir():
        return False
    _valid_branch(store_root, branch)
    tag = _tag(branch, sha)
    return _commit_for(store_root, f"refs/tags/{tag}") is not None


def restore_exact(store_root: Path, branch: str, sha: str, target: Path) -> None:
    sha = _valid_sha(sha)
    store_root = _store_root(store_root)
    target = _physical_path(target, "restore target")
    if not store_root.is_dir():
        raise StoreError(f"Graphify store is missing: {store_root}")
    _valid_branch(store_root, branch)
    commit = _commit_for(store_root, f"refs/tags/{_tag(branch, sha)}")
    if commit is None:
        raise StoreError(f"no exact Graphify snapshot for branch={branch} sha={sha}")
    _archive_payload(store_root, commit, target)


def seed(store_root: Path, branch: str, sha: str, target: Path) -> bool:
    sha = _valid_sha(sha)
    store_root = _store_root(store_root)
    target = _physical_path(target, "restore target")
    if not store_root.is_dir():
        return False
    _valid_branch(store_root, branch)
    commit = _commit_for(store_root, f"refs/tags/{_tag(branch, sha)}")
    if commit is None:
        commit = _commit_for(store_root, f"refs/heads/{branch}")
    if commit is None:
        return False
    _archive_payload(store_root, commit, target)
    return True


def publish(store_root: Path, builder: Path, branch: str, sha: str) -> None:
    sha = _valid_sha(sha)
    builder = _physical_path(builder, "builder")
    payload = _source_payload(builder)
    artifacts = _canonical_files(payload)
    head = _run(builder, "rev-parse", "HEAD").stdout.strip()
    if head != sha:
        raise StoreError(f"builder HEAD {head} does not match source SHA {sha}")
    store = _ensure_store(store_root)
    _valid_branch(store, branch)
    if _branch_exists(store, branch):
        _run(store, "switch", "--quiet", branch)
    else:
        _run(store, "switch", "--quiet", "--create", branch)
    target = store / "graphify-out"
    if target.is_symlink() or (target.exists() and not target.is_dir()):
        raise StoreError(f"refusing unmanaged store payload: {target}")
    _swap_payload(artifacts, target)
    _run(store, "add", "-A", "--", "graphify-out")
    if _run(store, "diff", "--cached", "--quiet", check=False).returncode:
        _run(store, "commit", "--quiet", "-m", sha)
    _run(store, "tag", "--force", _tag(branch, sha), branch)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("has-exact", "restore-exact", "seed"):
        subparser = subparsers.add_parser(command)
        subparser.add_argument("--store-root", type=Path, required=True)
        subparser.add_argument("--branch", required=True)
        subparser.add_argument("--sha", required=True)
        if command != "has-exact":
            subparser.add_argument("--target", type=Path, required=True)
    publish_parser = subparsers.add_parser("publish")
    publish_parser.add_argument("--store-root", type=Path, required=True)
    publish_parser.add_argument("--builder", type=Path, required=True)
    publish_parser.add_argument("--branch", required=True)
    publish_parser.add_argument("--sha", required=True)
    validate_parser = subparsers.add_parser("validate-builder")
    validate_parser.add_argument("--builder", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "has-exact":
            return 0 if has_exact(args.store_root, args.branch, args.sha) else 1
        if args.command == "restore-exact":
            restore_exact(args.store_root, args.branch, args.sha, args.target)
            return 0
        if args.command == "seed":
            return 0 if seed(args.store_root, args.branch, args.sha, args.target) else 1
        if args.command == "validate-builder":
            validate_builder(args.builder)
            return 0
        publish(args.store_root, args.builder, args.branch, args.sha)
        return 0
    except StoreError as error:
        print(f"graphify-store: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
