from __future__ import annotations

import importlib.util
import os
import stat
import subprocess
import tarfile
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
    (path / "graphify-out" / "GRAPH_REPORT.md").write_text("report\n", encoding="utf-8")
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


def make_target(root: Path) -> Path:
    """A restore target whose graphify-out already holds a previous payload."""
    root.mkdir()
    payload = root / "graphify-out"
    payload.mkdir()
    (payload / "graph.json").write_text('{"version":"previous"}\n', encoding="utf-8")
    (payload / "GRAPH_REPORT.md").write_text("previous report\n", encoding="utf-8")
    return payload


def make_payload(path: Path) -> Path:
    """A canonical replacement payload."""
    path.mkdir()
    (path / "graph.json").write_text('{"version":"next"}\n', encoding="utf-8")
    (path / "GRAPH_REPORT.md").write_text("next report\n", encoding="utf-8")
    return path


def fail_copy_of(monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    """Fail the canonical copy of `name`, the way a full disk or a revoked permission would."""
    original_copy2 = store.shutil.copy2

    def failing_copy2(src: object, dst: object, **kwargs: object) -> object:
        if Path(str(dst)).name == name:
            raise OSError("injected copy failure")
        return original_copy2(src, dst, **kwargs)

    monkeypatch.setattr(store.shutil, "copy2", failing_copy2)


def fail_replace_into(monkeypatch: pytest.MonkeyPatch, target: Path, sources: tuple[str, ...]) -> None:
    """Fail the renames of `sources` into `target`, the way a concurrent writer would."""
    original_replace = store.os.replace

    def failing_replace(src: object, dst: object, **kwargs: object) -> object:
        if Path(str(dst)) == target and Path(str(src)).name in sources:
            raise OSError("injected replacement failure")
        return original_replace(src, dst, **kwargs)

    monkeypatch.setattr(store.os, "replace", failing_replace)


def assert_previous_payload_intact(target_root: Path) -> None:
    payload = target_root / "graphify-out"
    assert (payload / "graph.json").read_text(encoding="utf-8") == '{"version":"previous"}\n'
    assert (payload / "GRAPH_REPORT.md").read_text(encoding="utf-8") == "previous report\n"
    assert sorted(entry.name for entry in target_root.iterdir()) == ["graphify-out"]


def test_publish_and_restore_keep_only_canonical_artifacts_and_source_tag(tmp_path: Path) -> None:
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
    assert (target / "graphify-out" / "graph.json").exists()
    assert (target / "graphify-out" / "GRAPH_REPORT.md").read_text(encoding="utf-8") == "report\n"
    assert not (target / "graphify-out" / "cache").exists()
    assert not (target / "graphify-out" / "current").exists()
    assert git(store_root, "ls-tree", "-r", "--name-only", "devel", "graphify-out").splitlines() == [
        "graphify-out/GRAPH_REPORT.md",
        "graphify-out/graph.json",
    ]


def test_restore_uses_safe_tar_filter(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "source"
    sha = make_repo(source)
    store_root = tmp_path / "store"
    publish(source, store_root, "devel", sha)
    target = tmp_path / "target"
    target.mkdir()
    observed: dict[str, object] = {}
    original_extractall = store.tarfile.TarFile.extractall

    def extractall(tar: tarfile.TarFile, *args: object, **kwargs: object) -> None:
        observed["filter"] = kwargs["filter"]
        original_extractall(tar, *args, **kwargs)

    monkeypatch.setattr(store.tarfile.TarFile, "extractall", extractall)
    store.restore_exact(store_root, "devel", sha, target)
    assert observed["filter"] == "data"


def test_uppercase_source_sha_is_normalized_for_publish_lookup_and_restore(tmp_path: Path) -> None:
    source = tmp_path / "source"
    sha = make_repo(source)
    uppercase_sha = sha.upper()
    store_root = tmp_path / "store"
    result = run_store(
        "publish",
        "--store-root",
        str(store_root),
        "--builder",
        str(source),
        "--branch",
        "devel",
        "--sha",
        uppercase_sha,
    )
    assert result.returncode == 0, result.stderr
    assert git(store_root, "rev-parse", "source/devel/" + sha) == git(store_root, "rev-parse", "devel")
    assert (
        run_store("has-exact", "--store-root", str(store_root), "--branch", "devel", "--sha", uppercase_sha).returncode
        == 0
    )
    target = tmp_path / "target"
    target.mkdir()
    result = run_store(
        "restore-exact",
        "--store-root",
        str(store_root),
        "--branch",
        "devel",
        "--sha",
        uppercase_sha,
        "--target",
        str(target),
    )
    assert result.returncode == 0, result.stderr
    assert (target / "graphify-out" / "graph.json").exists()


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


def test_publish_rejects_builder_sha_mismatch_before_store_mutation(tmp_path: Path) -> None:
    source = tmp_path / "source"
    sha = make_repo(source)
    store_root = tmp_path / "store"
    publish(source, store_root, "devel", sha)
    before = git(store_root, "rev-parse", "devel")
    (source / "graphify-out" / "graph.json").write_text("changed\n", encoding="utf-8")
    result = run_store(
        "publish",
        "--store-root",
        str(store_root),
        "--builder",
        str(source),
        "--branch",
        "devel",
        "--sha",
        "b" * 40,
    )
    assert result.returncode != 0
    assert git(store_root, "rev-parse", "devel") == before
    assert git(store_root, "tag", "--list", "source/devel/" + "b" * 40) == ""


def test_seed_prefers_exact_then_latest_snapshot_of_same_branch(tmp_path: Path) -> None:
    source = tmp_path / "source"
    sha = make_repo(source)
    store_root = tmp_path / "store"
    publish(source, store_root, "devel", sha)
    (source / "graphify-out" / "graph.json").write_text("devel\n", encoding="utf-8")
    git(source, "add", "graphify-out")
    git(source, "commit", "-q", "-m", "devel graph")
    sha2 = git(source, "rev-parse", "HEAD")
    publish(source, store_root, "devel", sha2)
    exact_target = tmp_path / "exact-target"
    exact_target.mkdir()
    result = run_store(
        "seed",
        "--store-root",
        str(store_root),
        "--branch",
        "devel",
        "--sha",
        sha,
        "--target",
        str(exact_target),
    )
    assert result.returncode == 0, result.stderr
    assert (exact_target / "graphify-out" / "graph.json").read_text(encoding="utf-8") == '{"version":1}\n'

    git(source, "switch", "-c", "release/4.0")
    (source / "graphify-out" / "graph.json").write_text("release\n", encoding="utf-8")
    git(source, "add", "graphify-out")
    git(source, "commit", "-q", "-m", "release graph")
    release_sha = git(source, "rev-parse", "HEAD")
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


def test_restore_replaces_old_target_junk_with_only_canonical_artifacts(tmp_path: Path) -> None:
    source = tmp_path / "source"
    sha = make_repo(source)
    store_root = tmp_path / "store"
    publish(source, store_root, "devel", sha)
    target = tmp_path / "target"
    target.mkdir()
    old = target / "graphify-out"
    old.mkdir()
    (old / "history").mkdir()
    (old / "history" / "old.txt").write_text("old\n", encoding="utf-8")
    (old / "secret.txt").write_text("secret\n", encoding="utf-8")

    store.restore_exact(store_root, "devel", sha, target)

    assert sorted(path.name for path in (target / "graphify-out").iterdir()) == ["GRAPH_REPORT.md", "graph.json"]


@pytest.mark.parametrize("memory_kind", ["directory", "symlink"])
def test_work_memory_is_rejected_before_validate_seed_or_publish_mutation(tmp_path: Path, memory_kind: str) -> None:
    source = tmp_path / "source"
    sha = make_repo(source)
    store_root = tmp_path / "store"
    publish(source, store_root, "devel", sha)
    target = tmp_path / "target"
    target.mkdir()
    assert run_store("validate-builder", "--builder", str(target)).returncode == 0
    memory = target / "graphify-out" / "memory"
    memory.parent.mkdir()
    if memory_kind == "directory":
        memory.mkdir()
        marker = memory / "secret.md"
        marker.write_text("private\n", encoding="utf-8")
    else:
        memory.symlink_to("missing-memory")

    validate = run_store("validate-builder", "--builder", str(target))
    seeded = run_store(
        "seed",
        "--store-root",
        str(store_root),
        "--branch",
        "devel",
        "--sha",
        sha,
        "--target",
        str(target),
    )

    assert validate.returncode != 0
    assert seeded.returncode != 0
    assert memory.exists() or memory.is_symlink()

    builder = tmp_path / "builder"
    builder_sha = make_repo(builder)
    builder_memory = builder / "graphify-out" / "memory"
    builder_memory.mkdir()
    clean_store = tmp_path / "clean-store"
    published = run_store(
        "publish",
        "--store-root",
        str(clean_store),
        "--builder",
        str(builder),
        "--branch",
        "devel",
        "--sha",
        builder_sha,
    )
    assert published.returncode != 0
    assert not clean_store.exists()


@pytest.mark.parametrize("artifact", ["graph.json", "GRAPH_REPORT.md"])
@pytest.mark.parametrize("invalid_kind", ["missing", "symlink", "directory"])
def test_publish_rejects_invalid_canonical_artifact_before_store_mutation(
    tmp_path: Path, artifact: str, invalid_kind: str
) -> None:
    source = tmp_path / "source"
    sha = make_repo(source)
    invalid = source / "graphify-out" / artifact
    invalid.unlink()
    if invalid_kind == "symlink":
        invalid.symlink_to("missing-artifact")
    elif invalid_kind == "directory":
        invalid.mkdir()
    store_root = tmp_path / "store"
    result = run_store(
        "publish",
        "--store-root",
        str(store_root),
        "--builder",
        str(source),
        "--branch",
        "devel",
        "--sha",
        sha,
    )
    assert result.returncode != 0
    assert not store_root.exists()


@pytest.mark.parametrize("artifact", ["graph.json", "GRAPH_REPORT.md"])
@pytest.mark.parametrize("invalid_kind", ["symlink", "directory"])
def test_replace_rejects_invalid_canonical_artifact_before_target_mutation(
    tmp_path: Path, artifact: str, invalid_kind: str
) -> None:
    source = tmp_path / "payload"
    source.mkdir()
    (source / "graph.json").write_text("{}\n", encoding="utf-8")
    (source / "GRAPH_REPORT.md").write_text("report\n", encoding="utf-8")
    invalid = source / artifact
    invalid.unlink()
    if invalid_kind == "symlink":
        invalid.symlink_to("missing-artifact")
    else:
        invalid.mkdir()
    target = tmp_path / "target"
    target.mkdir()
    old = target / "graphify-out"
    old.mkdir()
    keep = old / "keep.txt"
    keep.write_text("keep\n", encoding="utf-8")

    with pytest.raises(store.StoreError, match="canonical Graphify artifact"):
        store._replace_payload(source, target)

    assert keep.read_text(encoding="utf-8") == "keep\n"


@pytest.mark.parametrize("corrupt_kind", ["directory", "file"])
def test_corrupt_store_fail_without_touching_target(tmp_path: Path, corrupt_kind: str) -> None:
    target = tmp_path / "target"
    target.mkdir()
    marker = target / "keep.txt"
    marker.write_text("keep\n", encoding="utf-8")
    corrupt_store = tmp_path / "corrupt-store"
    if corrupt_kind == "directory":
        corrupt_store.mkdir()
    else:
        corrupt_store.write_text("not a git repository\n", encoding="utf-8")
    result = run_store(
        "restore-exact",
        "--store-root",
        str(corrupt_store),
        "--branch",
        "devel",
        "--sha",
        "a" * 40,
        "--target",
        str(target),
    )
    assert result.returncode != 0
    assert marker.read_text(encoding="utf-8") == "keep\n"


def test_symlink_store_root_is_rejected_before_any_write(tmp_path: Path) -> None:
    source = tmp_path / "source"
    sha = make_repo(source)
    real_store_parent = tmp_path / "real-store-parent"
    real_store_parent.mkdir()
    real_store = real_store_parent / "real-store"
    publish(source, real_store, "devel", sha)
    before = git(real_store, "rev-parse", "devel")
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(real_store_parent, target_is_directory=True)
    linked_store = linked_parent / "real-store"
    (source / "graphify-out" / "graph.json").write_text("changed\n", encoding="utf-8")

    for command in ("has-exact", "restore-exact", "seed", "publish"):
        args = [command, "--store-root", str(linked_store), "--branch", "devel", "--sha", sha]
        if command == "publish":
            args.extend(["--builder", str(source)])
        else:
            target = tmp_path / f"target-{command}"
            target.mkdir()
            marker = target / "keep.txt"
            marker.write_text("keep\n", encoding="utf-8")
            args.extend(["--target", str(target)])
        result = run_store(*args)
        assert result.returncode != 0, command
        if command != "publish":
            assert marker.read_text(encoding="utf-8") == "keep\n"

    assert git(real_store, "rev-parse", "devel") == before


def test_symlinked_builder_parent_is_rejected_before_store_creation(tmp_path: Path) -> None:
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    source = real_parent / "source"
    sha = make_repo(source)
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(real_parent, target_is_directory=True)
    result = run_store(
        "publish",
        "--store-root",
        str(tmp_path / "store"),
        "--builder",
        str(linked_parent / "source"),
        "--branch",
        "devel",
        "--sha",
        sha,
    )
    assert result.returncode != 0
    assert not (tmp_path / "store").exists()


def test_validate_rejects_unmanaged_graphify_file_without_traceback(tmp_path: Path) -> None:
    builder = tmp_path / "builder"
    builder.mkdir()
    (builder / "graphify-out").write_text("unmanaged\n", encoding="utf-8")

    result = run_store("validate-builder", "--builder", str(builder))

    assert result.returncode != 0
    assert result.stderr.startswith("graphify-store:")
    assert "Traceback" not in result.stderr


def test_symlinked_restore_target_parent_is_rejected_before_delete(tmp_path: Path) -> None:
    source = tmp_path / "source"
    sha = make_repo(source)
    store_root = tmp_path / "store"
    publish(source, store_root, "devel", sha)
    real_parent = tmp_path / "real-target-parent"
    real_parent.mkdir()
    target = real_parent / "target"
    target.mkdir()
    marker = target / "keep.txt"
    marker.write_text("keep\n", encoding="utf-8")
    linked_parent = tmp_path / "linked-target-parent"
    linked_parent.symlink_to(real_parent, target_is_directory=True)
    result = run_store(
        "restore-exact",
        "--store-root",
        str(store_root),
        "--branch",
        "devel",
        "--sha",
        sha,
        "--target",
        str(linked_parent / "target"),
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


def test_replace_keeps_previous_payload_when_a_canonical_copy_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = make_payload(tmp_path / "payload")
    target_root = tmp_path / "target"
    make_target(target_root)
    fail_copy_of(monkeypatch, "GRAPH_REPORT.md")

    with pytest.raises(OSError, match="injected copy failure"):
        store._replace_payload(source, target_root)

    assert_previous_payload_intact(target_root)


def test_replace_keeps_previous_payload_when_the_swap_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = make_payload(tmp_path / "payload")
    target_root = tmp_path / "target"
    target = make_target(target_root)
    fail_replace_into(monkeypatch, target, ("graphify-out",))

    with pytest.raises(OSError, match="injected replacement failure"):
        store._replace_payload(source, target_root)

    assert_previous_payload_intact(target_root)


def test_replace_keeps_the_previous_payload_recoverable_when_the_rollback_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = make_payload(tmp_path / "payload")
    target_root = tmp_path / "target"
    target = make_target(target_root)
    fail_replace_into(monkeypatch, target, ("graphify-out", "previous"))

    with pytest.raises(store.StoreError, match="previous Graphify payload is kept at") as failure:
        store._replace_payload(source, target_root)

    kept = Path(str(failure.value).split("kept at ", 1)[1])
    assert (kept / "graph.json").read_text(encoding="utf-8") == '{"version":"previous"}\n'
    assert (kept / "GRAPH_REPORT.md").read_text(encoding="utf-8") == "previous report\n"


def test_publish_keeps_previous_store_payload_when_a_canonical_copy_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    sha = make_repo(source)
    store_root = tmp_path / "store"
    publish(source, store_root, "devel", sha)
    (source / "graphify-out" / "graph.json").write_text('{"version":"next"}\n', encoding="utf-8")
    (source / "graphify-out" / "GRAPH_REPORT.md").write_text("next report\n", encoding="utf-8")
    git(source, "commit", "-q", "-a", "-m", "next")
    next_sha = git(source, "rev-parse", "HEAD")
    fail_copy_of(monkeypatch, "GRAPH_REPORT.md")

    with pytest.raises(OSError, match="injected copy failure"):
        store.publish(store_root, source, "devel", next_sha)

    payload = store_root / "graphify-out"
    assert (payload / "graph.json").read_text(encoding="utf-8") == '{"version":1}\n'
    assert (payload / "GRAPH_REPORT.md").read_text(encoding="utf-8") == "report\n"
    assert git(store_root, "status", "--porcelain") == ""


@pytest.mark.skipif(os.geteuid() == 0, reason="root bypasses the directory permissions this test revokes")
def test_scratch_removal_survives_an_unwritable_directory(tmp_path: Path) -> None:
    scratch = tmp_path / "scratch"
    locked = scratch / "previous"
    locked.mkdir(parents=True)
    (locked / "graph.json").write_text("previous\n", encoding="utf-8")
    locked.chmod(0o500)

    try:
        store._remove_scratch(scratch)
    finally:
        if locked.exists():
            locked.chmod(0o700)

    assert not scratch.exists()


@pytest.mark.skipif(os.geteuid() == 0, reason="root bypasses the directory permissions this test revokes")
def test_scratch_removal_never_widens_the_directory_it_sits_in(tmp_path: Path) -> None:
    parent = tmp_path / "worktree"
    parent.mkdir()
    scratch = parent / ".graphify-swap-probe"
    scratch.mkdir()
    (scratch / "graph.json").write_text("previous\n", encoding="utf-8")
    parent.chmod(0o500)

    try:
        store._remove_scratch(scratch)
        mode = stat.S_IMODE(parent.lstat().st_mode)
    finally:
        parent.chmod(0o700)

    assert mode == 0o500
