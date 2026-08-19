"""pfb_software_read_cache() drops non-scalar values (issue #2377)."""

from __future__ import annotations

import subprocess
from pathlib import Path


def test_php_software_cache_drops_non_scalar_values() -> None:
    runner = (
        Path(__file__).with_name("php") / "assert_software_cache_scalar_filter_3_3.php"
    )
    result = subprocess.run(
        ["php", str(runner)], check=False, capture_output=True, text=True
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "ALL PASS" in result.stdout
