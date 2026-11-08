"""Logging's historical loopback fallback must not invent a metric client."""

from __future__ import annotations

import sqlite3
from typing import Any

import pytest

import pfb_unbound as P
from tests import test_dns_metric_breakdown as breakdown

metric_databases = breakdown.metric_databases


@pytest.mark.parametrize("address", ["Unknown", "0.0.0.0", "::", "bad", "[::1]", "fe80::1%em0"])
def test_unavailable_upstream_client_stays_unavailable(metric_databases: Any, address: str, monkeypatch: Any) -> None:
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
            ("192.0.2.53", "", 1)
        ]
    if address == "Unknown":
        assert lines[0].split(",")[3] == "127.0.0.1"
