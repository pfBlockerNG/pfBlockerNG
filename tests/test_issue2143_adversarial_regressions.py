"""Issue #2143 adversarial workflow and tag-validation regressions."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from scripts.release_version import derive_destinations, derive_destinations_from_git
from tests._workflow_steps import extract_between
from tests.gitenv import scrubbed_git_env

ROOT = Path(__file__).resolve().parents[1]
PUBLISHED = (ROOT / ".github/workflows/release-published.yml").read_text(encoding="utf-8")
DOCS = (ROOT / "docs/misc/release-channels.md").read_text(encoding="utf-8")


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        env=scrubbed_git_env(),
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _tag_repo(tmp_path: Path, tag: str, *, annotated_message: str | None) -> tuple[Path, str]:
    repo = tmp_path / tag.replace(".", "-")
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.name", "Issue 2143")
    _git(repo, "config", "user.email", "issue2143@example.invalid")
    (repo / "marker").write_text("source\n", encoding="utf-8")
    _git(repo, "add", "marker")
    _git(repo, "commit", "-qm", "source")
    _git(repo, "branch", "release/4.0")
    _git(repo, "checkout", "-q", "release/4.0")
    (repo / "marker").write_text("current\n", encoding="utf-8")
    _git(repo, "commit", "-qam", "current")
    current = _git(repo, "rev-parse", "HEAD")
    if annotated_message is None:
        _git(repo, "tag", tag)
    else:
        _git(repo, "tag", "-a", "-m", annotated_message, tag)
    return repo, current


@pytest.mark.parametrize("tag", ["v4.0.0", "v4.0.1.a1"])
@pytest.mark.parametrize("message", [None, "pfBlockerNG-Release-Channel: edge"])
def test_existing_current_stable_or_testing_tag_requires_exact_annotated_primary_trailer(
    tmp_path: Path, tag: str, message: str | None
) -> None:
    repo, current = _tag_repo(tmp_path, tag, annotated_message=message)
    with pytest.raises(ValueError, match="annotated|trailer"):
        derive_destinations_from_git(tag, "release/4.0", repo, current_commit=current)


def test_pre_tag_source_sha_remains_allowed(tmp_path: Path) -> None:
    repo, current = _tag_repo(tmp_path, "v4.0.1.a1", annotated_message=None)
    _git(repo, "tag", "-d", "v4.0.1.a1")
    assert derive_destinations_from_git("v4.0.1.a1", "release/4.0", repo, current_commit=current) == (
        "testing",
        "edge",
    )


def test_other_tags_ordered_or_branch_mapped_never_change_current_tag_destinations() -> None:
    tags = ["v4.0.0", "v4.1.0.a1"]
    wrong = {"v4.0.0": "release/4.0", "v4.1.0.a1": "release/4.2"}
    valid = {**wrong, "v4.1.0.a1": "release/4.1"}
    assert derive_destinations("v4.0.1.a1", branch="release/4.0", ordered_tags=tags, tag_branches=wrong) == (
        "testing",
        "edge",
    )
    assert derive_destinations("v4.0.1.a1", branch="release/4.0", ordered_tags=tags, tag_branches=valid) == (
        "testing",
        "edge",
    )


def test_sync_ports_uses_only_exact_channel_recipe_paths() -> None:
    sync = extract_between(PUBLISHED, "\n  sync-ports-fork:\n", "\n  publish-pkg:\n")
    assert '"stable") PORT_PATH="net/pfSense-pkg-pfBlockerNG"' in sync
    assert '"testing") PORT_PATH="net/pfSense-pkg-pfBlockerNG-testing"' in sync
    assert '"edge") PORT_PATH="net/pfSense-pkg-pfBlockerNG-edge"' in sync
    assert "pfSense-pkg-pfBlockerNG-devel" not in sync
    assert '"stable")' in sync and '"testing")' in sync and '"edge")' in sync
    assert "*)" in sync and "unknown channel" in sync


def test_docs_describe_manifest_derived_edge_without_follower_line() -> None:
    assert "Edge patch-zero" in DOCS
    assert "not stored in the package" in DOCS
    assert "separate metadata file" in DOCS
    assert "exactly one explicitly configured line supplies Edge" not in DOCS
