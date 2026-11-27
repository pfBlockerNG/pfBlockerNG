"""Release/3.3 DNSBL VIP validation treats a stored 'none' as unset (issue #4276)."""

from __future__ import annotations

import subprocess
from pathlib import Path


def test_dnsbl_vip_validation_treats_none_as_unset() -> None:
    runner = Path(__file__).with_name("php") / "assert_dnsbl_vip_none_3_3.php"
    result = subprocess.run(
        ["php", str(runner)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "ALL PASS" in result.stdout
