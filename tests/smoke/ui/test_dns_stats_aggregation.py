"""Tier A: DNS statistics decode CSV labels and combine repeated hours."""

from __future__ import annotations

import csv
import html
import io
import re
import subprocess
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .render_oracle import PhpErrorLogGuard, evaluate_render
from .test_alerts_render_verify import _backup_seeded_files, _restore_seeded_files
from .test_dns_stats_review import _stats_data

if TYPE_CHECKING:
    from ..conftest import SmokeVM
    from .webui import WebUI

pytestmark = pytest.mark.ui_render


@pytest.mark.parametrize(
    ("view", "log", "preference", "title", "label", "rows"),
    [
        (
            "dnsbl_stat",
            "dnsbl.log",
            "pfbdnsblstat",
            "DNSBL Block Stats",
            "Stats,QuotedFeed",
            [
                [
                    "DNSBL-python",
                    "2031-02-15 09:01:02",
                    "stats.example.test",
                    "192.0.2.1",
                    "Python",
                    "DNSBL",
                    "StatsGroup",
                    "Match",
                    "Stats,QuotedFeed",
                    "+",
                    "A",
                ],
                [
                    "DNSBL-python",
                    "2031-02-16 10:01:02",
                    "other.example.test",
                    "192.0.2.2",
                    "Python",
                    "DNSBL",
                    "StatsGroup",
                    "Match",
                    "Stats,QuotedFeed",
                    "+",
                    "A",
                    "TCP",
                ],
                [
                    "DNSBL-python",
                    "2031-02-15 09:02:02",
                    "stats.example.test",
                    "192.0.2.1",
                    "Python",
                    "DNSBL",
                    "StatsGroup",
                    "Match",
                    "Stats,QuotedFeed",
                    "+",
                    "A",
                    "UDP",
                ],
            ],
        ),
        (
            "dnsbl_reply_stat",
            "dns_reply.log",
            "pfbdnsblreplystat",
            "DNS Reply Stats",
            "Stats,QuotedType",
            [
                [
                    "DNS-reply",
                    "2031-02-15 09:01:02",
                    "Stats,QuotedType",
                    "A",
                    "A",
                    "0",
                    "stats.example.test",
                    "192.0.2.1",
                    "192.0.2.53",
                    "US",
                ],
                [
                    "DNS-reply",
                    "2031-02-16 10:01:02",
                    "Stats,QuotedType",
                    "AAAA",
                    "AAAA",
                    "60",
                    "other.example.test",
                    "192.0.2.2",
                    "192.0.2.53",
                    "US",
                    "TCP",
                ],
                [
                    "DNS-reply",
                    "2031-02-15 09:02:02",
                    "Stats,QuotedType",
                    "A",
                    "A",
                    "0",
                    "stats.example.test",
                    "192.0.2.1",
                    "192.0.2.53",
                    "US",
                    "UDP",
                ],
            ],
        ),
    ],
)
def test_dns_stats_csv_labels_and_exact_hour_counts(
    smoke_vm: SmokeVM,
    webui: WebUI,
    view: str,
    log: str,
    preference: str,
    title: str,
    label: str,
    rows: list[list[str]],
) -> None:
    vm = smoke_vm
    path = f"/var/log/pfblockerng/{log}"
    cfg = f"installedpackages/pfblockerngglobal/{preference}"
    original = helpers.config_get_state(vm, cfg)
    backups = _backup_seeded_files(vm, (path,))
    guard = PhpErrorLogGuard(vm)
    guard.snapshot()
    try:
        enable = helpers.php_eval(
            vm, f"config_set_path('{cfg}', ''); write_config('DNS stats smoke setup'); echo 'OK';"
        )
        assert enable.returncode == 0 and "OK" in enable.stdout, enable.stdout + enable.stderr
        stream = io.StringIO()
        csv.writer(stream, lineterminator="\n").writerows(rows)
        seeded = subprocess.run(
            vm.ssh_argv("tee", path),
            input=stream.getvalue(),
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        assert seeded.returncode == 0, seeded.stderr
        page = f"/pfblockerng/pfblockerng_alerts.php?view={view}"
        response = webui.get(page)
        result = evaluate_render(page, response.status_code, response.text, (title,))
        assert result.ok, result.detail
        # Labels and their counts must survive CSV quoting, not split at the comma.
        payload = _stats_data(webui, view)
        text = html.unescape("".join(panel["html"] for panel in payload["panels"]))
        assert label in text, f"CSV label {label!r} missing from {view}"
        assert re.search(r"<td[^>]*>\s*3\s*</td>\s*<td[^>]*>" + re.escape(label) + r"</td>", text), (
            f"CSV label {label!r} did not render an exact count of 3 in {view}"
        )
        assert payload["timeline"] == [
            {"edate": "2031-02-15 (09)", "ecount": 2},
            {"edate": "2031-02-16 (10)", "ecount": 1},
        ]
        guard.assert_no_growth()
    finally:
        errors = _restore_seeded_files(vm, backups)
        try:
            helpers.config_restore_state(vm, cfg, original)
            assert helpers.config_get_state(vm, cfg) == original, f"config restore failed for {cfg}"
        finally:
            assert not errors, f"file restore failed: {errors}"
