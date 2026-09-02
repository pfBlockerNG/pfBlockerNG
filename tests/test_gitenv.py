"""Every scratch-repo git helper stays usable on a hostile developer machine (issue #1967).

The per-suite helpers each build a throwaway repository and commit into it. If any one of
them inherits the developer's global/system Git configuration, that whole suite fails for a
reason unrelated to what it tests — `commit.gpgsign=true` alone took out 55 tests across
five files, and a global `core.hooksPath` that resolves makes a scratch commit run foreign
hooks.

Fixing the helpers is not enough on its own: deleting a single `env=scrubbed_git_env()`
leaves the suite green on a clean CI machine, so the regression would sail back in. These
cases are the pin — each exercises a real helper against a hostile config, so removing that
helper's scrub turns THIS file red no matter how clean the environment running it is.
"""

from __future__ import annotations

import importlib
import os
import subprocess
from pathlib import Path

import pytest

from tests.gitenv import scrubbed_git_env

_HOSTILE = (
    "[commit]\n\tgpgsign = true\n[tag]\n\tgpgsign = true\n"
    "[gpg]\n\tformat = ssh\n[user]\n\tsigningkey = /nonexistent/key\n"
)

# Every module owning a scratch-repo helper of the shape ``_git(repo, *args)``.
_GIT_HELPER_MODULES = (
    "tests.test_agent_roles_check",
    "tests.test_comment_narration_check",
    "tests.test_guard_erosion_check",
    "tests.test_release_tag_after_verify",
    "tests.test_version_literal_check",
)


def _hostile_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Point both Git config scopes at a config that demands an impossible signature."""
    cfg = tmp_path / "hostile-gitconfig"
    cfg.write_text(_HOSTILE)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(cfg))
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", str(cfg))


def test_scrubbed_git_env_neutralises_both_config_scopes() -> None:
    """Both scopes, always — one alone still lets the other's config through."""
    env = scrubbed_git_env()
    assert env["GIT_CONFIG_GLOBAL"] == os.devnull
    assert env["GIT_CONFIG_SYSTEM"] == os.devnull


def test_scrubbed_git_env_drop_git_vars_keeps_the_two_config_scopes(monkeypatch: pytest.MonkeyPatch) -> None:
    """``drop_git_vars`` strips inherited GIT_* — but never the two keys it exists to set.

    They are themselves ``GIT_*`` names, so a strip applied after them would silently
    re-arm the very defect this module prevents.
    """
    monkeypatch.setenv("GIT_DIR", "/somewhere/.git")
    monkeypatch.setenv("GIT_WORK_TREE", "/somewhere")

    kept = scrubbed_git_env()
    assert kept["GIT_DIR"] == "/somewhere/.git"

    dropped = scrubbed_git_env(drop_git_vars=True)
    assert "GIT_DIR" not in dropped
    assert "GIT_WORK_TREE" not in dropped
    assert dropped["GIT_CONFIG_GLOBAL"] == os.devnull
    assert dropped["GIT_CONFIG_SYSTEM"] == os.devnull


@pytest.mark.parametrize("module_name", _GIT_HELPER_MODULES)
def test_scratch_git_helper_commits_under_a_hostile_config(
    module_name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Each suite's ``_git`` helper still reaches a commit when the global config signs.

    Given a global+system config demanding a signature from an unusable key,
    When the module's own scratch-repo helper inits, stages and commits,
    Then the commit succeeds — the helper neutralised both scopes rather than inheriting.

    The identity is set repo-locally rather than relied upon: only some of these helpers
    inject ``-c user.email``/``-c user.name`` themselves (the others configure it on the
    scratch repo), and with both config scopes neutralised there is no global identity to
    fall back on — git's implicit username@hostname guess is not available everywhere.
    """
    _hostile_config(tmp_path, monkeypatch)
    git = importlib.import_module(module_name)._git

    repo = tmp_path / module_name.rsplit(".", 1)[-1]
    repo.mkdir()
    git(repo, "init", "-q", "-b", "devel")
    git(repo, "config", "user.email", "t@example.invalid")
    git(repo, "config", "user.name", "t")
    (repo / "a.txt").write_text("one\n")
    git(repo, "add", "a.txt")
    git(repo, "commit", "-qm", "base")

    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo,
        capture_output=True,
        text=True,
        check=True,
        env=scrubbed_git_env(),
    ).stdout.strip()
    assert len(head) == 40, f"{module_name}: scratch commit produced no HEAD ({head!r})"


def test_context_budget_scratch_commit_survives_a_hostile_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``test_context_budget`` owns a differently-shaped helper; pin it the same way."""
    _hostile_config(tmp_path, monkeypatch)
    mod = importlib.import_module("tests.test_context_budget")

    root = mod._scratch_repo(tmp_path)
    mod._git_commit(root, "base")

    head = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
        env=scrubbed_git_env(),
    ).stdout.strip()
    assert len(head) == 40, f"context-budget scratch commit produced no HEAD ({head!r})"


def test_read_version_matrix_env_neutralises_config_too(monkeypatch: pytest.MonkeyPatch) -> None:
    """The matrix suite's env helper strips GIT_* AND neutralises the config scopes.

    It kept its own definition for the GIT_DIR/GIT_WORK_TREE strip its scratch repo needs;
    stripping those alone still let a global ``core.hooksPath`` reach the scratch commit,
    which repo-local ``commit.gpgsign false`` never covered.
    """
    monkeypatch.setenv("GIT_DIR", "/somewhere/.git")
    env = importlib.import_module("tests.test_read_version_matrix")._clean_git_env()

    assert "GIT_DIR" not in env
    assert env["GIT_CONFIG_GLOBAL"] == os.devnull
    assert env["GIT_CONFIG_SYSTEM"] == os.devnull
