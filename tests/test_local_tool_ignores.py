"""Repository-owned ignore contracts for local code-intelligence and build output."""

from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _check_ignore(path: str, *flags: str) -> subprocess.CompletedProcess[str]:
    """`git check-ignore` with global excludes off. With -v it prints the deciding rule, even a `!` re-include
    that leaves the path unignored; only the exit status without -v says whether the path is ignored."""
    return subprocess.run(
        ["git", "-c", "core.excludesFile=/dev/null", "check-ignore", *flags, path],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def test_understand_anything_output_is_ignored_without_global_git_rules() -> None:
    result = _check_ignore(".ua/index.json", "-v")
    assert result.returncode == 0, result.stderr
    assert ".gitignore" in result.stdout
    assert ".ua/" in result.stdout
    assert _check_ignore(".ua/index.json").returncode == 0, "a later rule re-includes .ua/index.json"


def test_a_bare_go_build_output_is_ignored_and_untracked() -> None:
    """A bare `go build` in go/<module> writes go/<module>/<module>; it is never part of the tree (issue #4082)."""
    modules = sorted(p.parent.name for p in (ROOT / "go").glob("*/go.mod"))
    assert {"pfb_core", "pfb_crowdsec", "pfb_dns_gateway"} <= set(modules), modules
    problems = []
    for module in modules:
        output = f"go/{module}/{module}"
        rule = _check_ignore(output, "--no-index", "-v").stdout
        if _check_ignore(output, "--no-index").returncode != 0 or not rule.startswith(".gitignore:"):
            problems.append(f"{output} is not ignored by .gitignore (deciding rule: {rule!r})")
        tracked = subprocess.run(
            ["git", "ls-files", "--", output], cwd=ROOT, capture_output=True, text=True, check=True
        ).stdout
        if tracked:
            problems.append(f"{output} is tracked")
    assert problems == [], "\n".join(problems)
