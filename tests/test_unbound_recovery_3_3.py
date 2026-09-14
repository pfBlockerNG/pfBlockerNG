"""issue #3292: bounded Unbound restart/recovery assertions for release/3.3."""

from __future__ import annotations

import subprocess
from pathlib import Path


def test_php_assertion_runner() -> None:
    root = Path(__file__).parents[1]
    for rel in (
        "src/usr/local/pkg/pfblockerng/pfblockerng.inc",
        "src/usr/local/pkg/pfblockerng/pfblockerng_install.inc",
    ):
        lint = subprocess.run(
            ["php", "-l", str(root / rel)],
            check=False,
            capture_output=True,
            text=True,
        )
        assert lint.returncode == 0, lint.stdout + lint.stderr

    runner = Path(__file__).with_name("php") / "assert_unbound_recovery_3_3.php"
    result = subprocess.run(
        ["php", str(runner)],
        check=False,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "ALL PASS" in result.stdout
