from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / "scripts" / "agent" / "graphify-store.py"
SPEC = importlib.util.spec_from_file_location("graphify_store", SCRIPT)
assert SPEC and SPEC.loader
store = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(store)


def git(path: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(path), *args],
        check=True,
        text=True,
        capture_output=True,
    )
    return result.stdout.strip()


def run_store(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["python3", str(SCRIPT), *args],
        text=True,
        capture_output=True,
    )


def make_repo(path: Path, branch: str = "devel") -> str:
    path.mkdir()
    git(path, "init", "-q", "-b", branch)
    git(path, "config", "user.email", "test@example.com")
    git(path, "config", "user.name", "Graphify Test")
    (path / "graphify-out").mkdir()
    (path / "graphify-out" / "graph.json").write_text('{"version":1}\n', encoding="utf-8")
    git(path, "add", "graphify-out")
    git(path, "commit", "-q", "-m", "source")
    return git(path, "rev-parse", "HEAD")


def publish(source: Path, store_root: Path, branch: str, sha: str) -> None:
    result = run_store(
        "publish",
        "--store-root",
        str(store_root),
        "--builder",
        str(source),
        "--branch",
        branch,
        "--sha",
        sha,
    )
    assert result.returncode == 0, result.stderr


def test_publish_and_restore_preserve_opaque_state_and_source_tag(tmp_path: Path) -> None:
    source = tmp_path / "source tree"
    sha = make_repo(source)
    (source / "graphify-out" / "cache").mkdir()
    (source / "graphify-out" / "cache" / "payload.txt").write_text("payload\n", encoding="utf-8")
    (source / "graphify-out" / "current").symlink_to("cache")
    store_root = source / ".git" / "graphify-store"

    publish(source, store_root, "devel", sha)

    tag = "source/devel/" + sha
    assert run_store("has-exact", "--store-root", str(store_root), "--branch", "devel", "--sha", sha).returncode == 0
    assert git(store_root, "rev-parse", tag) == git(store_root, "rev-parse", "devel")
    target = tmp_path / "new worktree"
    target.mkdir()
    result = run_store(
        "restore-exact",
        "--store-root",
        str(store_root),
        "--branch",
        "devel",
        "--sha",
        sha,
        "--target",
        str(target),
    )
    assert result.returncode == 0, result.stderr
    assert (target / "graphify-out" / "cache" / "payload.txt").read_text(encoding="utf-8") == "payload\n"
    assert (target / "graphify-out" / "current").is_symlink()
    assert (target / "graphify-out" / "current").readlink() == Path("cache")


def test_republish_same_sha_moves_tag_and_keeps_history(tmp_path: Path) -> None:
    source = tmp_path / "source"
    sha = make_repo(source)
    store_root = tmp_path / "store"
    publish(source, store_root, "devel", sha)
    first = git(store_root, "rev-parse", "source/devel/" + sha)
    (source / "graphify-out" / "graph.json").write_text('{"version":2}\n', encoding="utf-8")
    publish(source, store_root, "devel", sha)
    second = git(store_root, "rev-parse", "source/devel/" + sha)
    assert second != first
    assert int(git(store_root, "rev-list", "--count", "devel")) == 2


def test_seed_prefers_exact_then_latest_snapshot_of_same_branch(tmp_path: Path) -> None:
    source = tmp_path / "source"
    sha = make_repo(source)
    store_root = tmp_path / "store"
    publish(source, store_root, "devel", sha)
    (source / "graphify-out" / "graph.json").write_text("devel\n", encoding="utf-8")
    sha2 = git(source, "rev-parse", "HEAD")
    publish(source, store_root, "devel", sha2)
    release_sha = sha2
    git(source, "switch", "-c", "release/4.0")
    (source / "graphify-out" / "graph.json").write_text("release\n", encoding="utf-8")
    publish(source, store_root, "release/4.0", release_sha)

    target = tmp_path / "builder"
    target.mkdir()
    result = run_store(
        "seed",
        "--store-root",
        str(store_root),
        "--branch",
        "release/4.0",
        "--sha",
        "b" * 40,
        "--target",
        str(target),
    )
    assert result.returncode == 0, result.stderr
    assert (target / "graphify-out" / "graph.json").read_text(encoding="utf-8") == "release\n"


def test_missing_exact_and_corrupt_store_fail_without_touching_target(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    marker = target / "keep.txt"
    marker.write_text("keep\n", encoding="utf-8")
    empty_store = tmp_path / "empty-store"
    result = run_store(
        "restore-exact",
        "--store-root",
        str(empty_store),
        "--branch",
        "devel",
        "--sha",
        "a" * 40,
        "--target",
        str(target),
    )
    assert result.returncode != 0
    assert marker.read_text(encoding="utf-8") == "keep\n"


def test_restore_rejects_unmanaged_graphify_target_symlink(tmp_path: Path) -> None:
    source = tmp_path / "source"
    sha = make_repo(source)
    store_root = tmp_path / "store"
    publish(source, store_root, "devel", sha)
    target = tmp_path / "target"
    target.mkdir()
    external = tmp_path / "external"
    external.mkdir()
    (target / "graphify-out").symlink_to(external)
    result = run_store(
        "restore-exact",
        "--store-root",
        str(store_root),
        "--branch",
        "devel",
        "--sha",
        sha,
        "--target",
        str(target),
    )
    assert result.returncode != 0
    assert not any(external.iterdir())


@pytest.mark.parametrize("branch", ["origin/devel", "origin/release/4.0", "feature/with-slash"])
def test_store_accepts_branch_names_as_opaque_refs(tmp_path: Path, branch: str) -> None:
    source = tmp_path / "source"
    sha = make_repo(source)
    store_root = tmp_path / "store"
    graph_branch = branch.removeprefix("origin/")
    publish(source, store_root, graph_branch, sha)
    assert (
        run_store("has-exact", "--store-root", str(store_root), "--branch", graph_branch, "--sha", sha).returncode == 0
    )
