"""Adversarial settings-family slot and installer-order subprocess seam."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path


def test_php_adversarial_settings_family_assertions() -> None:
    runner = (
        Path(__file__).with_name("php") / "assert_settings_family_adversarial_3_3.php"
    )
    result = subprocess.run(
        ["php", str(runner)],
        check=False,
        capture_output=True,
        text=True,
        env=os.environ.copy(),
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "ALL PASS" in result.stdout
