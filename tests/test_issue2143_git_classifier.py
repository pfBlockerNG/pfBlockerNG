"""Git-backed issue #2143 source-SHA and moved-tag gates."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from scripts.release_version import derive_destinations_from_git
from tests.gitenv import scrubbed_git_env


def _git(repo: Path, *args: str, extra_env: dict[str, str] | None = None) -> str:
    env = scrubbed_git_env()
    if extra_env:
        env.update(extra_env)
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _commit(repo: Path, message: str) -> str:
    (repo / "marker").write_text(message + "\n", encoding="utf-8")
    _git(repo, "add", "marker")
    _git(repo, "commit", "-qm", message)
    return _git(repo, "rev-parse", "HEAD")


def _repo_with_release_line(tmp_path: Path) -> tuple[Path, str, str]:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.name", "Issue 2143")
    _git(repo, "config", "user.email", "issue2143@example.invalid")
    anchor = _commit(repo, "anchor")
    _git(repo, "branch", "release/4.0")
    _git(repo, "tag", "v4.0.0", anchor)
    _git(repo, "checkout", "-q", "release/4.0")
    current = _commit(repo, "selected source")
    return repo, anchor, current


def test_classifier_validates_selected_sha_before_tag_classification(tmp_path: Path) -> None:
    repo, _anchor, current = _repo_with_release_line(tmp_path)
    assert derive_destinations_from_git("v4.0.1.a1", "release/4.0", repo, current_commit=current) == (
        "testing",
        "edge",
    )


def test_classifier_accepts_a_signed_tag_with_the_exact_channel_trailer(tmp_path: Path) -> None:
    repo, _anchor, current = _repo_with_release_line(tmp_path)
    signing_key = tmp_path / "signing-key"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(signing_key)],
        check=True,
        env=scrubbed_git_env(),
    )
    _git(repo, "config", "gpg.format", "ssh")
    _git(repo, "config", "user.signingkey", str(signing_key))
    _git(repo, "config", "tag.gpgSign", "true")
    _git(
        repo,
        "tag",
        "-a",
        "-m",
        "v4.0.1.a1",
        "-m",
        "pfBlockerNG-Release-Channel: testing",
        "v4.0.1.a1",
        current,
    )
    assert "BEGIN SSH SIGNATURE" in _git(repo, "cat-file", "tag", "v4.0.1.a1")
    assert derive_destinations_from_git("v4.0.1.a1", "release/4.0", repo, current_commit=current) == (
        "testing",
        "edge",
    )


@pytest.mark.parametrize(
    ("relative_path", "expected_readers"),
    [
        (".githooks/pre-push", 1),
        (".github/workflows/release-published.yml", 1),
        (".github/workflows/release.yml", 3),
        ("scripts/release_version.py", 1),
    ],
)
def test_all_release_channel_trailer_readers_ignore_signature_blocks(relative_path: str, expected_readers: int) -> None:
    source = (Path(__file__).resolve().parents[1] / relative_path).read_text(encoding="utf-8")
    assert "%(contents)" not in source
    assert source.count("%(trailers:unfold)") + source.count("%(trailers)") == expected_readers


def test_classifier_rejects_tag_commit_off_release_branch(tmp_path: Path) -> None:
    repo, _anchor, _current = _repo_with_release_line(tmp_path)
    _git(repo, "checkout", "-q", "main")
    off_branch = _commit(repo, "off branch")
    _git(
        repo,
        "tag",
        "-a",
        "-m",
        "testing",
        "-m",
        "pfBlockerNG-Release-Channel: testing",
        "v4.0.1.a1",
        off_branch,
    )
    with pytest.raises(ValueError, match="is not reachable from"):
        derive_destinations_from_git("v4.0.1.a1", "release/4.0", repo, current_commit=off_branch)


def test_classifier_rejects_moved_existing_tag(tmp_path: Path) -> None:
    repo, _anchor, current = _repo_with_release_line(tmp_path)
    moved = _commit(repo, "moved tag")
    _git(repo, "tag", "-a", "-m", "testing", "v4.0.1.a1", moved)
    with pytest.raises(ValueError, match="does not match the selected source commit"):
        derive_destinations_from_git("v4.0.1.a1", "release/4.0", repo, current_commit=current)


def test_classifier_ignores_lower_family_even_when_created_later(tmp_path: Path) -> None:
    repo, _anchor, current = _repo_with_release_line(tmp_path)
    _git(repo, "checkout", "-q", "main")
    _git(repo, "branch", "release/3.9")
    _git(repo, "checkout", "-q", "release/3.9")
    _commit(repo, "lower family")
    _git(
        repo,
        "tag",
        "-a",
        "-m",
        "edge",
        "-m",
        "pfBlockerNG-Release-Channel: edge",
        "v3.9.0.a1",
        extra_env={"GIT_COMMITTER_DATE": "2099-01-01T00:00:00Z"},
    )
    assert derive_destinations_from_git("v4.0.1.a1", "release/4.0", repo, current_commit=current) == (
        "testing",
        "edge",
    )


@pytest.mark.parametrize("trailer", ["pfBlockerNG-Release-Channel: testing", "plain annotation"])
def test_classifier_rejects_patch_zero_prerelease_without_the_edge_trailer(tmp_path: Path, trailer: str) -> None:
    repo, _anchor, current = _repo_with_release_line(tmp_path)
    _git(repo, "tag", "-a", "-m", trailer, "v4.0.0.a1", current)
    with pytest.raises(ValueError, match="lacks the exact edge release trailer"):
        derive_destinations_from_git("v4.0.0.a1", "release/4.0", repo, current_commit=current)


def test_classifier_rejects_a_lightweight_current_tag(tmp_path: Path) -> None:
    repo, _anchor, current = _repo_with_release_line(tmp_path)
    _git(repo, "tag", "v4.0.0.a1", current)
    with pytest.raises(ValueError, match="must be an annotated tag"):
        derive_destinations_from_git("v4.0.0.a1", "release/4.0", repo, current_commit=current)


def _blob_tag_repo(tmp_path: Path, trailer: str) -> tuple[Path, str]:
    """Annotate the current tag onto a blob, so `refs/tags/<tag>^{commit}` cannot peel."""
    repo, _anchor, current = _repo_with_release_line(tmp_path)
    blob = _git(repo, "hash-object", "-w", "marker")
    _git(repo, "tag", "-a", "-m", trailer, "v4.0.0.a1", blob)
    return repo, current


@pytest.mark.parametrize(
    "trailer",
    ["plain annotation", "pfBlockerNG-Release-Channel: testing", "pfBlockerNG-Release-Channel: edge"],
)
def test_classifier_rejects_a_current_tag_that_does_not_point_at_a_commit(tmp_path: Path, trailer: str) -> None:
    repo, current = _blob_tag_repo(tmp_path, trailer)
    with pytest.raises(ValueError, match="does not point at a commit"):
        derive_destinations_from_git("v4.0.0.a1", "release/4.0", repo, current_commit=current)
