"""Logging's historical loopback fallback must not invent a metric client."""

from __future__ import annotations

import csv
import io
import sqlite3
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace

import pytest

import pfb_unbound as P
from tests import test_dns_metric_breakdown as breakdown
from tests.test_pfb_unbound import make_qstate

metric_databases = breakdown.metric_databases
flush_metrics = breakdown.flush_metrics


@pytest.mark.parametrize("address", ["Unknown", "0.0.0.0", "::", "bad", "[::1]", "fe80::1%em0", "192.0.2.10"])
def test_upstream_client_labels_require_valid_addresses(
    metric_databases: tuple[Path, Path], address: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, path = metric_databases
    P.pfb["metrics_client_ip"] = True
    with sqlite3.connect(path) as con:
        con.execute("UPDATE dns_metric_settings SET client_ip=1")
    P._db_capture_privacy_epochs()
    lines: list[str] = []
    monkeypatch.setattr(P, "pfb_log", lambda path, line: lines.append(line))
    P._log_upstream_block(
        "example.com",
        address,
        P.UpstreamBlock("NXRA", "NXRA", ""),
        "A",
        group_epoch=P._snapshot.group_epochs[("Upstream", "builtin")],
        listener_ip="192.0.2.53",
        listener_interface="LAN",
    )
    with sqlite3.connect(path) as con:
        assert con.execute("SELECT listener_ip,client_ip,count FROM dns_metric_blocks").fetchall() == [
            ("192.0.2.53", address if address == "192.0.2.10" else "", 1)
        ]
    if address == "Unknown":
        assert lines[0].split(",")[3] == "127.0.0.1"


@pytest.mark.parametrize("address", [None, "", "Unknown", "127.0.0.1", "192.0.2.10", "2001:db8::10"])
def test_upstream_callback_keeps_missing_client_separate_from_real_loopback(
    metric_databases: tuple[Path, Path],
    flush_metrics: Callable[[], None],
    address: str | None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, path = metric_databases
    monkeypatch.setitem(P.pfb, "forwarding", True)
    monkeypatch.setitem(P.pfb, "metrics_client_ip", True)
    with sqlite3.connect(path) as con:
        con.execute("UPDATE dns_metric_settings SET client_ip=1")
    P._db_capture_privacy_epochs()
    lines: list[str] = []
    monkeypatch.setattr(P, "pfb_log", lambda path, line: lines.append(line))
    state = make_qstate("example.com.", q_ip=address or "")
    state.qinfo.qtype_str = "A"
    if address is None:
        state.mesh_info.reply_list = None
    assert P.inplace_cb_query_response(state, SimpleNamespace(rep=SimpleNamespace(flags=3)))
    flush_metrics()
    expected_client = address if address not in (None, "", "Unknown") else ""
    with sqlite3.connect(path) as con:
        assert con.execute("SELECT counter FROM dnsbl WHERE groupname='Upstream'").fetchall() == [(1,)]
        assert con.execute(
            "SELECT owner,origin,groupname,qtype,transport,listener_ip,listener_interface,client_ip,count "
            "FROM dns_metric_blocks"
        ).fetchall() == [("Upstream", "builtin", "Upstream", "A", "", "", "", expected_client, 1)]
    assert len(lines) == 1
    row = next(csv.reader(io.StringIO(lines[0])))
    assert row[3] == (expected_client or "127.0.0.1")
    assert row[10:] == ["A", "Unknown", "", ""]
