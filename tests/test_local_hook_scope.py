import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_local_git_hooks_leave_tests_and_static_analysis_to_ci() -> None:
    commands = re.compile(r"\b(pytest|phpunit|shellspec|mypy|phpstan)\b")

    for name in ("pre-commit", "pre-push"):
        hook = (ROOT / ".githooks" / name).read_text(encoding="utf-8")
        executable = "\n".join(line for line in hook.splitlines() if not line.lstrip().startswith("#"))
        assert not commands.search(executable), f"{name} runs a CI-only test or static-analysis command"
