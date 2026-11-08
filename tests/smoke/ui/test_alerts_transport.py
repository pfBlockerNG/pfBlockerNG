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
                    row.extend(["2001:db8::53" if transport == "DoH" else "192.0.2.53", 'LAN, "旧" <b>event</b>'])
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
            prefix = "reply" if reply else "dnsbl"
            for suffix in ("listenerip", "listenerinterface"):
                assert f'name="filterlogentries_{prefix}{suffix}"' in response.text
            assert ">Receiving IP</th>" in response.text
            assert ">Receiving interface</th>" in response.text
            for name, value in zip(tokens[reply], ("TCP", "UDP", "DoT", "DoH", "DoQ", "—"), strict=True):
                rendered = row_containing(response.text, name)
                assert f"<td>{value}</td>" in rendered, (view, name, value, rendered)
                assert rendered.count("<td") == (12 if view == "unified" else 13 if reply else 9), rendered
                expected_ip = "—" if value == "—" else "2001:db8::53" if value == "DoH" else "192.0.2.53"
                assert f"<td>{expected_ip}</td>" in rendered, rendered
                assert "<b>event</b>" not in rendered
                if value != "—":
                    assert "LAN, &quot;旧&quot; &lt;b&gt;event&lt;/b&gt;" in rendered
            if view == "unified":
                ip_row = row_containing(response.text, ip)
                assert ip_row.count("<td") == 12 and ip_row.count("<td>—</td>") == 3, ip_row
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
            for suffix, expression, selected in (
                ("listenerip", "^2001:db8::53$", tokens[reply][3:4]),
                ("listenerinterface", "^LAN,", tokens[reply][:-1]),
                ("listenerip", "^—$", tokens[reply][-1:]),
                ("listenerinterface", "^—$", tokens[reply][-1:]),
                ("listenerinterface", "^not-this-interface$", []),
            ):
                filtered = webui.post(
                    path,
                    {f"filterlogentries_{prefix}{suffix}": expression},
                    submit=("filterlogentries_submit", "Apply Filter"),
                )
                assert filtered.status_code == 200
                for name in tokens[reply]:
                    assert (name in filtered.text) == (name in selected), (view, suffix, name, filtered.text)
                reset = webui.post(path, {}, submit=("filterlogentries_clear", "Clear Filter"))
                assert reset.status_code == 200
                assert all(name in reset.text for name in tokens[reply])
    finally:
        helpers.config_restore_state(vm, dnsbl_cfg, original)
        errors = _restore_seeded_files(vm, backups)
        assert not errors, errors
