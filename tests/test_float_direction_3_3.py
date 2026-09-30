"""Release/3.3 floating auto-rule direction and firewall-traffic twins (issue #3382)."""

from __future__ import annotations

import subprocess
from pathlib import Path


def test_php_assertion_runner() -> None:
    runner = Path(__file__).with_name("php") / "assert_float_direction_3_3.php"
    result = subprocess.run(
        ["php", str(runner)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "ALL PASS" in result.stdout
