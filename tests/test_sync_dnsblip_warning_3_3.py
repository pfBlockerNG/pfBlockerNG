"""Release/3.3 Sync-page DNSBL IP HA sync-mismatch warning and help text (issue #3442)."""

from __future__ import annotations

import subprocess
from pathlib import Path


def test_sync_page_warns_when_ha_rule_sync_outruns_dnsbl_ip_settings() -> None:
    runner = Path(__file__).with_name("php") / "assert_sync_dnsblip_warning_3_3.php"
    result = subprocess.run(
        ["php", str(runner)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "ALL PASS" in result.stdout
