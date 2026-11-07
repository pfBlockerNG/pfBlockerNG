"""Transport report columns and actual filter POST/reset (#3751)."""

from __future__ import annotations

import csv
import io
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .test_alerts_render_verify import (
    DNS_REPLY_LOG,
    DNSBL_LOG,
    UNIFIED_LOG,
    _append,
    _backup_seeded_files,
    _ip_line,
    _restore_seeded_files,
)
from .webui import row_containing

if TYPE_CHECKING:
    from .webui import WebUI

pytestmark = [pytest.mark.ui_render, pytest.mark.ui_e2e]
PAGE = "/pfblockerng/pfblockerng_alerts.php"


def test_transport_columns_filter_and_reset(smoke_vm: helpers.SmokeVM, webui: WebUI) -> None:
    """Tier A columns/controls and Tier B POST narrow and restore mixed rows."""
    vm = smoke_vm
    dnsbl_cfg = "installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl"
    original = helpers.config_get_state(vm, dnsbl_cfg)
    backups = _backup_seeded_files(vm, (DNSBL_LOG, DNS_REPLY_LOG, UNIFIED_LOG))
    try:
        helpers.ensure_dnsbl_vip(vm)
        helpers.set_dnsbl_enabled(vm, True)
        groups: dict[bool, list[str]] = {}
        tokens: dict[bool, list[str]] = {}
        for reply in (False, True):
            lines = []
            names = []
            for transport in ("TCP", "UDP", "DoT", "DoH", "DoQ", None):
                name = helpers.unique_domain()
                names.append(name)
                row = (
                    ["DNS-reply", "Jan 01 00:00:00", "reply", "A", "A", "123", name, "10.0.0.5", "1.2.3.4", "US"]
                    if reply
                    else [
                        "DNSBL-python",
                        "Jan 01 00:00:00",
                        name,
                        "10.0.0.5",
                        "Python",
                        "DNSBL",
                        "Group",
                        name,
                        "Feed",
                        "0",
                        "A",
                    ]
                )
                if transport is not None:
                    row.append(transport)
                out = io.StringIO()
                csv.writer(out, lineterminator="\n").writerow(row)
                lines.append(out.getvalue())
            groups[reply] = lines
            tokens[reply] = names
            _append(vm, DNS_REPLY_LOG if reply else DNSBL_LOG, "".join(lines))
        _append(vm, UNIFIED_LOG, "".join(groups[False] + groups[True]))
        ip = "198.51.100.251"
        _append(
            vm,
            UNIFIED_LOG,
            "Block,"
            + _ip_line(
                src_ip=ip,
                dst_ip="10.0.0.5",
                direction="in",
                alias="pfB_Transport_v4",
                ip_eval=ip,
                feed="TransportFeed",
            ),
        )

        for view, reply in (("alert", False), ("reply", True), ("unified", False), ("unified", True)):
            path = f"{PAGE}?view={view}"
            field = "filterlogentries_replytransport" if reply else "filterlogentries_dnsbltransport"
            response = webui.get(path)
            assert response.status_code == 200
            assert f'name="{field}"' in response.text, f"missing transport control: {view}"
            assert ">Transport</th>" in response.text, f"missing transport header: {view}"
            for name, value in zip(tokens[reply], ("TCP", "UDP", "DoT", "DoH", "DoQ", "—"), strict=True):
                rendered = row_containing(response.text, name)
                assert f"<td>{value}</td>" in rendered, (view, name, value, rendered)
                assert rendered.count("<td") == (10 if view == "unified" else 11 if reply else 7), rendered
            if view == "unified":
                ip_row = row_containing(response.text, ip)
                assert ip_row.count("<td") == 10 and "<td>—</td>" in ip_row, ip_row
            filtered = webui.post(path, {field: "^DoH$"}, submit=("filterlogentries_submit", "Apply Filter"))
            assert filtered.status_code == 200
            assert tokens[reply][3] in filtered.text
            for name in tokens[reply][:3] + tokens[reply][4:]:
                assert name not in filtered.text, f"nonmatching transport survived POST: {name}"
            reset = webui.post(path, {}, submit=("filterlogentries_clear", "Clear Filter"))
            assert reset.status_code == 200
            for name in tokens[reply]:
                assert name in reset.text, f"clear filter failed to restore {name}"
            unavailable = webui.post(path, {field: "^—$"}, submit=("filterlogentries_submit", "Apply Filter"))
            assert unavailable.status_code == 200
            assert tokens[reply][-1] in unavailable.text, f"unavailable row missing: {view}"
            for name in tokens[reply][:-1]:
                assert name not in unavailable.text, f"canonical transport survived unavailable POST: {name}"
            reset = webui.post(path, {}, submit=("filterlogentries_clear", "Clear Filter"))
            assert reset.status_code == 200
            for name in tokens[reply]:
                assert name in reset.text, f"clear unavailable filter failed to restore {name}"
    finally:
        helpers.config_restore_state(vm, dnsbl_cfg, original)
        errors = _restore_seeded_files(vm, backups)
        assert not errors, errors
