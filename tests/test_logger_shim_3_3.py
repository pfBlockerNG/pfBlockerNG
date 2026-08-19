"""logger()/localize_text() fallbacks for pfSense CE <= 2.8.1."""

from __future__ import annotations

import subprocess
from pathlib import Path


def test_php_logger_and_localize_text_fallbacks_defined() -> None:
    runner = Path(__file__).with_name("php") / "assert_logger_shim_3_3.php"
    result = subprocess.run(
        ["php", str(runner)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "ALL PASS" in result.stdout
