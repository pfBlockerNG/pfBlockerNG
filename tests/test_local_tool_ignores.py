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


def _go_modules() -> list[str]:
    return sorted(p.parent.name for p in (ROOT / "go").glob("*/go.mod"))


def test_every_go_module_is_found() -> None:
    assert {"pfb_core", "pfb_crowdsec", "pfb_dns_gateway"} <= set(_go_modules())


def test_a_bare_go_build_output_is_ignored_and_untracked() -> None:
    """A bare `go build` in go/<module> writes go/<module>/<module>; it is never part of the tree (issue #4082)."""
    problems = []
    for module in _go_modules():
        output = f"go/{module}/{module}"
        ignored = subprocess.run(
            ["git", "-c", "core.excludesFile=/dev/null", "check-ignore", "--no-index", "-v", output],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        if ignored.returncode != 0 or not ignored.stdout.startswith(".gitignore:"):
            problems.append(f"{output} is not ignored by .gitignore (check-ignore: {ignored.stdout!r})")
        tracked = subprocess.run(
            ["git", "ls-files", "--", output], cwd=ROOT, capture_output=True, text=True, check=True
        ).stdout
        if tracked:
            problems.append(f"{output} is tracked")
    assert problems == [], "\n".join(problems)
