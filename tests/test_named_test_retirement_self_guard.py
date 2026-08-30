from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from tests.gitenv import scrubbed_git_env

ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts" / "check_named_test_retirement.py"


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        env=scrubbed_git_env(drop_git_vars=True),
        capture_output=True,
        check=True,
    )


def test_checker_test_file_remains_guarded(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    path = "tests/test_named_test_retirement.py"
    target = repo / path
    target.parent.mkdir(parents=True)
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "tests@example.invalid")
    _git(repo, "config", "user.name", "Named retirement tests")
    target.write_text("def test_self_guarded():\n    assert True\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "baseline")
    base = _git(repo, "rev-parse", "HEAD").stdout.decode().strip()
    target.unlink()
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "retire checker test")

    result = subprocess.run(
        [sys.executable, str(CHECKER), "--diff", base],
        cwd=repo,
        env=scrubbed_git_env(drop_git_vars=True),
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1, result.stdout + result.stderr
    assert f"{path}::test_self_guarded" in result.stdout
