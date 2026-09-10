"""Metadata writers retain commit enforcement across orphan-branch transitions."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from tests._workflow_steps import extract_after, extract_step
from tests.gitenv import scrubbed_git_env

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
IMAGE_REFRESH = (WORKFLOWS / "image-refresh.yml").read_text(encoding="utf-8")
VERSION_TRACKER = (WORKFLOWS / "version-tracker.yml").read_text(encoding="utf-8")

_GOOD_NAME = "Writer Bot"
_GOOD_EMAIL = "writer-bot@pfblockerng.ci"


def _activate_hooks_command(workflow: str) -> str:
    """The literal single-line ``run:`` command of the "Activate git hooks" step."""
    step = extract_step(workflow, "Activate git hooks")
    return extract_after(step, "run: ").splitlines()[0].strip()


def _run(args: list[str], *, cwd: Path | None = None, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, env=env, capture_output=True, text=True, check=False)


def _git(repo: Path, *args: str, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return _run(["git", *args], cwd=repo, env=env)


def _make_signing_key(tmp_path: Path, env: dict[str, str]) -> Path:
    key = tmp_path / "signing_key"
    result = _run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], env=env)
    assert result.returncode == 0, result.stdout + result.stderr
    return key


def _configure_good_identity(repo: Path, key: Path, env: dict[str, str]) -> None:
    _git(repo, "config", "user.name", _GOOD_NAME, env=env)
    _git(repo, "config", "user.email", _GOOD_EMAIL, env=env)
    _git(repo, "config", "gpg.format", "ssh", env=env)
    _git(repo, "config", "user.signingkey", str(key), env=env)
    _git(repo, "config", "commit.gpgsign", "true", env=env)


def _seed_writer_repo(tmp_path: Path, *, name: str = "repo") -> Path:
    """Track the real hook corpus so checkout-B genuinely removes it."""
    repo = tmp_path / name
    repo.mkdir()
    (repo / "scripts").mkdir()
    (repo / "scripts" / "setup-hooks.sh").symlink_to(ROOT / "scripts" / "setup-hooks.sh")

    hooks_dir = repo / ".githooks"
    hooks_dir.mkdir()
    for corpus_name in ("check-commit-identity.sh", "prepare-commit-msg", "commit-msg"):
        dest = hooks_dir / corpus_name
        dest.write_text((ROOT / ".githooks" / corpus_name).read_text(encoding="utf-8"), encoding="utf-8")
        dest.chmod(0o755)
    writer_pre_commit_src = ROOT / ".githooks" / "ci-writer" / "pre-commit"
    if writer_pre_commit_src.exists():
        (hooks_dir / "ci-writer").mkdir()
        dest = hooks_dir / "ci-writer" / "pre-commit"
        dest.write_text(writer_pre_commit_src.read_text(encoding="utf-8"), encoding="utf-8")
        dest.chmod(0o755)

    env = scrubbed_git_env(drop_git_vars=True)
    assert _git(repo, "init", "-q", "-b", "devel", env=env).returncode == 0
    _git(repo, "config", "pfblockerng.allowprimarycommit", "true", env=env)
    _git(repo, "config", "user.name", _GOOD_NAME, env=env)
    _git(repo, "config", "user.email", _GOOD_EMAIL, env=env)
    assert _git(repo, "add", ".githooks", env=env).returncode == 0
    commit = _git(repo, "-c", "commit.gpgsign=false", "commit", "-qm", "seed .githooks", env=env)
    assert commit.returncode == 0, commit.stdout + commit.stderr
    return repo


def _seed_ci_metadata_remote(tmp_path: Path, env: dict[str, str]) -> Path:
    """Create an orphan metadata remote containing only the supported-version matrix."""
    bare = tmp_path / "origin.git"
    assert _run(["git", "init", "-q", "--bare", "-b", "ci-metadata", str(bare)], env=env).returncode == 0

    seed = tmp_path / "ci-metadata-seed"
    seed.mkdir()
    assert _git(seed, "init", "-q", "-b", "ci-metadata", env=env).returncode == 0
    _git(seed, "config", "user.name", "Seed", env=env)
    _git(seed, "config", "user.email", "seed@pfblockerng.ci", env=env)
    (seed / "supported-versions.json").write_text('{"versions": [{"ci": false}]}\n', encoding="utf-8")
    _git(seed, "add", "supported-versions.json", env=env)
    assert _git(seed, "-c", "commit.gpgsign=false", "commit", "-qm", "seed", env=env).returncode == 0
    _git(seed, "remote", "add", "origin", str(bare), env=env)
    assert _git(seed, "push", "-q", "origin", "ci-metadata", env=env).returncode == 0
    return bare


def _fetch_ci_metadata(repo: Path, bare: Path, env: dict[str, str]) -> None:
    _git(repo, "remote", "add", "origin", str(bare), env=env)
    assert _git(repo, "fetch", "-q", "origin", "ci-metadata", env=env).returncode == 0


def _activate_writer_hooks(
    repo: Path, profile: str, hook_dir: Path, env: dict[str, str]
) -> subprocess.CompletedProcess[str]:
    return _run(["sh", "scripts/setup-hooks.sh", "--writer", profile, str(hook_dir)], cwd=repo, env=env)


def _activated_ci_metadata_repo(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    """Activate the real writer setup in an isolated Git repository."""
    repo = _seed_writer_repo(tmp_path)
    env = scrubbed_git_env(drop_git_vars=True)
    activation = _activate_writer_hooks(repo, "ci-metadata", tmp_path / "hookdir", env)
    assert activation.returncode == 0, activation.stdout + activation.stderr
    return repo, env


def test_image_refresh_writer_hook_survives_the_linked_ci_metadata_worktree(tmp_path: Path) -> None:
    """Linked metadata worktrees reject invalid identity and accept signed updates."""
    repo = _seed_writer_repo(tmp_path)
    env = scrubbed_git_env(drop_git_vars=True)
    bare = _seed_ci_metadata_remote(tmp_path, env)
    _fetch_ci_metadata(repo, bare, env)

    runner_temp = tmp_path / "runner_temp"
    runner_temp.mkdir()
    activation_env = dict(env)
    activation_env["RUNNER_TEMP"] = str(runner_temp)
    command = _activate_hooks_command(IMAGE_REFRESH)
    activation = _run(["sh", "-c", command], cwd=repo, env=activation_env)
    assert activation.returncode == 0, activation.stdout + activation.stderr

    wt = tmp_path / "wt"
    added = _git(repo, "worktree", "add", "--force", "-B", "activate-ce", str(wt), "origin/ci-metadata", env=env)
    assert added.returncode == 0, added.stdout + added.stderr
    assert not (wt / ".githooks").exists(), "the orphan ci-metadata branch never tracked .githooks"

    # A generic placeholder identity (issue #2982's own deny-list) must be rejected --
    # proof the activated hook actually executes in this worktree, not a no-op.
    (wt / "supported-versions.json").write_text('{"versions": [{"ci": true}]}\n', encoding="utf-8")
    _git(wt, "add", "supported-versions.json", env=env)
    _git(wt, "config", "user.name", "root", env=env)
    _git(wt, "config", "user.email", "root@pfblockerng.ci", env=env)
    bad = _git(wt, "-c", "commit.gpgsign=false", "commit", "-qm", "bad identity", env=env)
    assert bad.returncode != 0, "a placeholder ('root') identity must be rejected by the activated writer hook"

    # A valid, signed commit touching only supported-versions.json succeeds -- and
    # nothing in this tree ever mentions graphify-out/graph.json.
    key = _make_signing_key(tmp_path, env)
    _configure_good_identity(wt, key, env)
    good = _git(wt, "commit", "-qm", "activate CE", env=env)
    assert good.returncode == 0, good.stdout + good.stderr


def test_version_tracker_writer_hook_survives_checkout_b_even_as_githooks_vanishes(tmp_path: Path) -> None:
    """Checkout-B removes source hooks but retains commit enforcement."""
    repo = _seed_writer_repo(tmp_path)
    env = scrubbed_git_env(drop_git_vars=True)
    bare = _seed_ci_metadata_remote(tmp_path, env)
    _fetch_ci_metadata(repo, bare, env)
    assert (repo / ".githooks" / "check-commit-identity.sh").exists()

    runner_temp = tmp_path / "runner_temp"
    runner_temp.mkdir()
    activation_env = dict(env)
    activation_env["RUNNER_TEMP"] = str(runner_temp)
    command = _activate_hooks_command(VERSION_TRACKER)
    activation = _run(["sh", "-c", command], cwd=repo, env=activation_env)
    assert activation.returncode == 0, activation.stdout + activation.stderr

    switched = _git(repo, "checkout", "-B", "matrix-activate-ce", "origin/ci-metadata", env=env)
    assert switched.returncode == 0, switched.stdout + switched.stderr
    assert not (repo / ".githooks").exists(), (
        "checkout onto the orphan ci-metadata branch must delete the tracked .githooks/ "
        "from disk -- this is the exact persistence scenario issue #3240 covers"
    )

    (repo / "supported-versions.json").write_text('{"versions": [{"ci": true}]}\n', encoding="utf-8")
    _git(repo, "add", "supported-versions.json", env=env)
    _git(repo, "config", "user.name", "root", env=env)
    _git(repo, "config", "user.email", "root@pfblockerng.ci", env=env)
    bad = _git(repo, "-c", "commit.gpgsign=false", "commit", "-qm", "bad identity", env=env)
    assert bad.returncode != 0, "a placeholder identity must be rejected even after .githooks disappeared"

    key = _make_signing_key(tmp_path, env)
    _configure_good_identity(repo, key, env)
    good = _git(repo, "commit", "-qm", "activate CE", env=env)
    assert good.returncode == 0, good.stdout + good.stderr


@pytest.mark.parametrize("bad_profile", ["", "bogus"])
def test_setup_hooks_writer_rejects_a_bad_profile_without_installing_anything(tmp_path: Path, bad_profile: str) -> None:
    repo = _seed_writer_repo(tmp_path)
    env = scrubbed_git_env(drop_git_vars=True)
    hook_dir = tmp_path / "hookdir"

    result = _activate_writer_hooks(repo, bad_profile, hook_dir, env)
    assert result.returncode != 0, result.stdout + result.stderr
    assert not hook_dir.exists(), "a rejected profile must never create HOOK_DIR"
    assert _git(repo, "config", "core.hooksPath", env=env).returncode != 0, "core.hooksPath must stay unset"


def test_setup_hooks_writer_fails_closed_on_a_missing_corpus_file(tmp_path: Path) -> None:
    repo = _seed_writer_repo(tmp_path)
    (repo / ".githooks" / "commit-msg").unlink()
    env = scrubbed_git_env(drop_git_vars=True)
    hook_dir = tmp_path / "hookdir"

    result = _activate_writer_hooks(repo, "ci-metadata", hook_dir, env)
    assert result.returncode != 0, result.stdout + result.stderr
    assert not hook_dir.exists(), "a missing corpus file must never produce a partial install"
    assert _git(repo, "config", "core.hooksPath", env=env).returncode != 0, "core.hooksPath must stay unset"


def test_setup_hooks_writer_hook_dir_containing_a_space_still_activates(tmp_path: Path) -> None:
    repo = _seed_writer_repo(tmp_path)
    env = scrubbed_git_env(drop_git_vars=True)
    hook_dir = tmp_path / "pfb writer hooks" / "dir"

    result = _activate_writer_hooks(repo, "ci-metadata", hook_dir, env)
    assert result.returncode == 0, result.stdout + result.stderr
    _git(repo, "config", "user.name", "root", env=env)
    bad = _git(repo, "-c", "commit.gpgsign=false", "commit", "--allow-empty", "-qm", "bad identity", env=env)
    assert bad.returncode != 0, "hooks installed at a space-containing path must execute"

    # And the space-containing hook path actually fires on a real commit.
    (repo / "supported-versions.json").write_text('{"versions": []}\n', encoding="utf-8")
    _git(repo, "add", "supported-versions.json", env=env)
    key = _make_signing_key(tmp_path, env)
    _configure_good_identity(repo, key, env)
    good = _git(repo, "commit", "-qm", "activate CE", env=env)
    assert good.returncode == 0, good.stdout + good.stderr


def test_writer_hook_rejects_a_staged_path_outside_the_allowlist_even_with_an_embedded_newline(tmp_path: Path) -> None:
    """Newlines in staged filenames cannot bypass the writer's path restrictions."""
    repo, env = _activated_ci_metadata_repo(tmp_path)
    (repo / "supported-versions.json").write_text('{"versions": []}\n', encoding="utf-8")
    evil_name = "evil\nname.json"
    (repo / evil_name).write_text("{}", encoding="utf-8")
    added = _git(repo, "add", "supported-versions.json", evil_name, env=env)
    assert added.returncode == 0, added.stdout + added.stderr

    key = _make_signing_key(tmp_path, env)
    _configure_good_identity(repo, key, env)
    result = _git(repo, "commit", "-qm", "sneaky", env=env)
    assert result.returncode != 0, "a staged path outside the allowlist (even a newline-named one) must be rejected"
    assert "allowlist" in result.stderr


def test_writer_hook_rejects_disabled_signing_with_an_otherwise_valid_identity(tmp_path: Path) -> None:
    """Signing remains mandatory even with a valid identity."""
    repo, env = _activated_ci_metadata_repo(tmp_path)
    (repo / "supported-versions.json").write_text('{"versions": []}\n', encoding="utf-8")
    _git(repo, "add", "supported-versions.json", env=env)
    _git(repo, "config", "user.name", _GOOD_NAME, env=env)
    _git(repo, "config", "user.email", _GOOD_EMAIL, env=env)

    result = _git(repo, "-c", "commit.gpgsign=false", "commit", "-qm", "unsigned", env=env)
    assert result.returncode != 0, "an unsigned commit must be rejected even with a valid, non-placeholder identity"


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("{} \n", "metadata: reject trailing whitespace"),
        ("{}\n", "metadata: reject attribution\n\nCo-authored-by: Other <other@pfblockerng.ci>"),
    ],
    ids=["whitespace", "coauthor"],
)
def test_writer_rejects_invalid_content_or_message(tmp_path: Path, content: str, message: str) -> None:
    repo, env = _activated_ci_metadata_repo(tmp_path)
    (repo / "supported-versions.json").write_text(content, encoding="utf-8")
    _git(repo, "add", "supported-versions.json", env=env)
    key = _make_signing_key(tmp_path, env)
    _configure_good_identity(repo, key, env)
    before = _git(repo, "rev-parse", "HEAD", env=env).stdout
    result = _git(repo, "commit", "-qm", message, env=env)
    assert result.returncode != 0, "writer hooks must reject invalid content or commit trailers"
    assert _git(repo, "rev-parse", "HEAD", env=env).stdout == before
