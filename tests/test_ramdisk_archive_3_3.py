from __future__ import annotations

import subprocess
from pathlib import Path


def test_ramdisk_archive_runner() -> None:
    runner = Path(__file__).with_name("php") / "assert_ramdisk_archive_3_3.php"
    result = subprocess.run(["php", str(runner)], check=False, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "ALL PASS" in result.stdout
