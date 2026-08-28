"""Repository-owned ignore contracts for local code-intelligence output."""

from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_understand_anything_output_is_ignored_without_global_git_rules() -> None:
    result = subprocess.run(
        ["git", "-c", "core.excludesFile=/dev/null", "check-ignore", "-v", ".ua/index.json"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert ".gitignore" in result.stdout
    assert ".ua/" in result.stdout
