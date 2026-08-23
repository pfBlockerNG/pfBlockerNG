from __future__ import annotations

import fcntl
import importlib.util
import os
import select
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


def lock_state(lock: Path) -> str:
    """Report whether the Graphify store lock is free at this instant.

    flock(2) ties the lock to the open file description, so a descriptor opened here
    conflicts with a hold taken through another one even inside this same process --
    the probe therefore reads the real extent of the critical section rather than
    inferring it from one caller out-racing another.
    """
    if not lock.exists():
        return "absent"
    handle = os.open(lock, os.O_RDWR)
    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return "held"
    else:
        fcntl.flock(handle, fcntl.LOCK_UN)
        return "free"
    finally:
        os.close(handle)


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
    assert not (scratch / "graph.json").exists()  # the cleanup ran; it just could not remove the root


@pytest.mark.skipif(os.geteuid() == 0, reason="root bypasses the directory permissions this test revokes")
def test_scratch_removal_never_follows_a_symlink_out_of_the_scratch(tmp_path: Path) -> None:
    enclosing = tmp_path / "enclosing"  # a mode of its own, so widening it to S_IRWXU is visible
    enclosing.mkdir()
    external = enclosing / "external"
    external.mkdir()
    external.chmod(0o755)
    enclosing.chmod(0o755)
    scratch = tmp_path / "scratch"
    locked = scratch / "previous"
    locked.mkdir(parents=True)
    (locked / "link").symlink_to(external)
    locked.chmod(0o500)

    store._remove_scratch(scratch)

    assert stat.S_IMODE(external.lstat().st_mode) == 0o755
    assert stat.S_IMODE(enclosing.lstat().st_mode) == 0o755  # nor anything above the link's target
    assert not scratch.exists()


@pytest.mark.skipif(os.geteuid() == 0, reason="root bypasses the directory permissions this test revokes")
def test_scratch_removal_never_chmods_a_hardlinked_file(tmp_path: Path) -> None:
    external = tmp_path / "external.txt"
    external.write_text("external\n", encoding="utf-8")
    external.chmod(0o644)
    scratch = tmp_path / "scratch"
    locked = scratch / "previous"
    locked.mkdir(parents=True)
    os.link(external, locked / "link")
    locked.chmod(0o500)

    store._remove_scratch(scratch)

    assert stat.S_IMODE(external.lstat().st_mode) == 0o644
    assert not scratch.exists()


@pytest.mark.skipif(os.geteuid() == 0, reason="root bypasses the directory permissions this test revokes")
def test_scratch_removal_survives_an_unreadable_directory(tmp_path: Path) -> None:
    scratch = tmp_path / "scratch"
    unreadable = scratch / "previous"
    unreadable.mkdir(parents=True)
    (unreadable / "graph.json").write_text("previous\n", encoding="utf-8")
    unreadable.chmod(0o000)

    try:
        store._remove_scratch(scratch)
    finally:
        if unreadable.exists():
            unreadable.chmod(0o700)

    assert not scratch.exists()


def test_publish_holds_the_store_lock_while_it_mutates_the_store(tmp_path: Path) -> None:
    """Scenario: two agents publish into the one store a primary checkout shares.

    Given the store lock is the sibling `.lock` file `work-branch.sh` already takes,
    When publish swaps the new payload into the store,
    Then the lock is held for that window, so the second agent waits instead of
    racing the swap (issue #2657).
    """
    source = tmp_path / "source"
    sha = make_repo(source)
    store_root = tmp_path / ".git" / "graphify-store"
    lock = tmp_path / ".git" / "graphify-store.lock"
    observed: list[str] = []
    swap_payload = store._swap_payload

    def probing_swap(artifacts: tuple[Path, ...], target: Path) -> None:
        observed.append(lock_state(lock))
        swap_payload(artifacts, target)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(store, "_swap_payload", probing_swap)
        store.publish(store_root, source, "devel", sha)

    assert observed == ["held"], f"store lock during the publish swap: {observed}"


def test_reads_never_block_on_the_store_lock_their_caller_holds(tmp_path: Path) -> None:
    """`work-branch.sh` holds the store lock across has-exact and restore-exact, so a
    second flock(2) taken from inside those commands would deadlock against their own
    caller. They must stay lock-free (issue #2657).
    """
    source = tmp_path / "source"
    sha = make_repo(source)
    store_root = tmp_path / ".git" / "graphify-store"
    publish(source, store_root, "devel", sha)
    target = tmp_path / "worktree"
    target.mkdir()

    lock = tmp_path / ".git" / "graphify-store.lock"
    handle = os.open(lock, os.O_CREAT | os.O_RDWR, 0o644)
    try:
        fcntl.flock(handle, fcntl.LOCK_EX)
        assert lock_state(lock) == "held", "the probe must see the caller's own hold"
        common = ("--store-root", str(store_root), "--branch", "devel", "--sha", sha)
        # The timeout is a salvage cap for a deadlock, never the assertion: a blocked
        # read raises TimeoutExpired, which reads as "stuck", not as a wrong result.
        has_exact = subprocess.run(
            ["python3", str(SCRIPT), "has-exact", *common],
            text=True,
            capture_output=True,
            timeout=60,
        )
        restore = subprocess.run(
            ["python3", str(SCRIPT), "restore-exact", *common, "--target", str(target)],
            text=True,
            capture_output=True,
            timeout=60,
        )
    finally:
        os.close(handle)

    assert has_exact.returncode == 0, has_exact.stderr
    assert restore.returncode == 0, restore.stderr
    assert (target / "graphify-out" / "GRAPH_REPORT.md").read_text(encoding="utf-8") == "report\n"


def test_a_second_publish_waits_for_the_lock_instead_of_racing_or_dying(tmp_path: Path) -> None:
    """Scenario: a publish starts while another caller already holds the store lock.

    Given `work-branch.sh`'s own idiom -- an exclusive hold on `.git/graphify-store.lock` --
    When a second caller publishes into that store,
    Then it announces the wait and leaves the store untouched until the hold is released,
    and only then completes; it neither races the holder nor dies on contention (#2657).
    """
    source = tmp_path / "source"
    sha = make_repo(source)
    store_root = tmp_path / ".git" / "graphify-store"
    lock = tmp_path / ".git" / "graphify-store.lock"
    lock.parent.mkdir(parents=True, exist_ok=True)

    handle = os.open(lock, os.O_CREAT | os.O_RDWR, 0o644)
    fcntl.flock(handle, fcntl.LOCK_EX)
    waiting = subprocess.Popen(
        [
            "python3",
            str(SCRIPT),
            "publish",
            "--store-root",
            str(store_root),
            "--builder",
            str(source),
            "--branch",
            "devel",
            "--sha",
            sha,
        ],
        text=True,
        stderr=subprocess.PIPE,
    )
    stderr = waiting.stderr
    assert stderr is not None
    try:
        try:
            # The announcement IS the synchronisation event: it is emitted from the contended
            # branch itself, so consuming it proves the second caller reached the wait. An
            # unblocked publish exits instead and readline() returns "" at EOF. select() only
            # caps the read so a publish that neither announces nor exits reports "stuck"
            # instead of hanging the suite; it never stands in for an assertion.
            if not select.select([stderr], [], [], 60)[0]:
                raise AssertionError("the second publish neither announced a wait nor exited: stuck")
            announced = stderr.readline()
            assert "waiting for the store lock" in announced, f"second publish did not wait: {announced!r}"
            assert not store_root.exists(), "the second publish mutated the store under a foreign hold"
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)
            os.close(handle)
        assert waiting.wait(timeout=60) == 0, stderr.read()
    finally:
        if waiting.poll() is None:
            waiting.kill()
            waiting.wait(timeout=60)
        stderr.close()

    assert (store_root / "graphify-out" / "graph.json").exists()


@pytest.mark.parametrize("lock_kind", ["directory", "symlink", "unusable-parent"])
def test_an_unusable_store_lock_is_reported_without_a_traceback(tmp_path: Path, lock_kind: str) -> None:
    """Taking the lock is the one path in this module that could follow a symlink out of the
    store, crash on a stray directory, or crash creating the directory it lives in; each must
    fail the way every other rejection here does -- one `graphify-store:` line, no traceback
    (#2657).
    """
    source = tmp_path / "source"
    sha = make_repo(source)
    store_root = tmp_path / ".git" / "graphify-store"
    lock = tmp_path / ".git" / "graphify-store.lock"
    outside = tmp_path / "outside"
    if lock_kind == "unusable-parent":
        lock.parent.write_text("not a directory\n", encoding="utf-8")
    else:
        lock.parent.mkdir(parents=True, exist_ok=True)
        if lock_kind == "directory":
            lock.mkdir()
        else:
            lock.symlink_to(outside)

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

    assert result.returncode == 1, result.stdout
    assert result.stderr.startswith("graphify-store: "), result.stderr
    assert "Traceback" not in result.stderr, result.stderr
    assert not store_root.exists(), "a rejected publish must not create the store"
    assert not outside.exists(), "the lock open must not follow a symlink out of the store"
