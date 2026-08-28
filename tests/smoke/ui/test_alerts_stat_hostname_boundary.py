"""Tier-A coverage for the Alerts IP Block Stats hostname boundary (#2117).

The stats pipeline reads resolved hostnames from ``ip_block.log`` field 18 and
renders them through ``pfb_stat_hostname_cell()``. Exact 44/45/46-code-point
rows pin the public page contract: only the 46-character hostname truncates.
"""

from __future__ import annotations

import subprocess
from typing import TYPE_CHECKING

import pytest

from .render_oracle import PhpErrorLogGuard, evaluate_render
from .webui import row_containing

if TYPE_CHECKING:
    from collections.abc import Iterator

    from ..conftest import SmokeVM
    from .webui import WebUI

pytestmark = pytest.mark.ui_render

IP_BLOCK_LOG = "/var/log/pfblockerng/ip_block.log"
IP_BLOCK_STATS = "/pfblockerng/pfblockerng_alerts.php?view=ip_block_stat"
FIXED_TS = "2030-08-03 00:00:00"

CASES = (
    ("192.0.2.211", "a" * 44),
    ("192.0.2.212", "b" * 45),
    ("192.0.2.213", "c" * 46),
)


def _ip_row(ip: str, hostname: str) -> str:
    """Return one current-schema inbound IP block row with ``hostname`` as rhost."""
    return (
        f"{FIXED_TS},100,em0,WAN,block,4,6,TCP,{ip},10.0.0.5,12345,443,"
        f"in,US,pfB2117Alias,{ip},PFB2117Feed,{hostname},Unknown,Unknown,,,+\n"
    )


@pytest.fixture
def exact_ip_block_log(smoke_vm: SmokeVM) -> Iterator[None]:
    """Replace ``ip_block.log`` with the three rows, then restore exact prior state."""
    vm = smoke_vm
    backup = f"{IP_BLOCK_LOG}.bak-2117"
    had_file = vm.ssh("test", "-f", IP_BLOCK_LOG, timeout=15).returncode == 0
    no_stale_backup = vm.ssh("test", "!", "-e", backup, timeout=15)
    assert no_stale_backup.returncode == 0, f"refusing to overwrite stale backup {backup!r}"

    ensure = vm.ssh("mkdir", "-p", IP_BLOCK_LOG.rsplit("/", 1)[0], timeout=15)
    assert ensure.returncode == 0, f"failed to create log directory: {ensure.stderr!r}"
    if had_file:
        moved = vm.ssh("mv", IP_BLOCK_LOG, backup, timeout=15)
        assert moved.returncode == 0, f"failed to back up {IP_BLOCK_LOG}: {moved.stderr!r}"

    try:
        written = subprocess.run(
            vm.ssh_argv("tee", IP_BLOCK_LOG),
            input="".join(_ip_row(ip, hostname) for ip, hostname in CASES),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert written.returncode == 0, f"failed to seed {IP_BLOCK_LOG}: {written.stderr!r}"

        yield
    finally:
        removed = vm.ssh("rm", "-f", IP_BLOCK_LOG, timeout=15)
        assert removed.returncode == 0, f"failed to remove seeded {IP_BLOCK_LOG}: {removed.stderr!r}"
        if had_file:
            restored = vm.ssh("mv", backup, IP_BLOCK_LOG, timeout=15)
            assert restored.returncode == 0, f"failed to restore {IP_BLOCK_LOG}: {restored.stderr!r}"
        assert vm.ssh("test", "!", "-e", backup, timeout=15).returncode == 0, (
            f"{IP_BLOCK_LOG} restore did not take; backup {backup!r} remains"
        )


def test_ip_block_stats_truncates_only_beyond_45_characters(
    smoke_vm: SmokeVM, webui: WebUI, exact_ip_block_log: None
) -> None:
    guard = PhpErrorLogGuard(smoke_vm)
    guard.snapshot()

    response = webui.get(IP_BLOCK_STATS)
    result = evaluate_render(IP_BLOCK_STATS, response.status_code, response.text, ("IP Block Stats",))
    assert result.ok, f"Tier-A render oracle failed for IP Block Stats: {result.detail}"

    for ip, hostname in CASES[:2]:
        row = row_containing(response.text, ip)
        expected = f"<br /><span ><small>{hostname}</small></span>"
        assert expected in row, f"{len(hostname)}-character hostname did not render in full:\n{row}"

    ip, hostname = CASES[2]
    row = row_containing(response.text, ip)
    expected = f'<br /><span title="{hostname}"><small>{hostname[:45]}<small>...</small></small></span>'
    assert expected in row, f"46-character hostname did not keep 45 characters plus ellipsis:\n{row}"

    guard.assert_no_growth()
