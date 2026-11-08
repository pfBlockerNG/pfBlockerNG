"""Listener dimensions and process-incarnation client privacy authority."""

from __future__ import annotations

import csv
import io
import sqlite3
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import pfb_unbound as P
from tests import test_dns_metric_breakdown as breakdown
from tests.test_pfb_unbound import block_decision, make_qstate

metric_databases = breakdown.metric_databases
flush_metrics = breakdown.flush_metrics


@pytest.mark.parametrize("transport", ["UDP", "TCP", "DoT", "DoH", "DoQ", None])
@pytest.mark.parametrize("endpoint", ["192.0.2.53", "2001:db8::53", "::ffff:192.0.2.53", ""])
def test_endpoint_counting(metric_databases: Any, flush_metrics: Any, transport: Any, endpoint: str) -> None:
    resolver, dnsbl = metric_databases
    P.pfb["metrics_client_ip"] = False
    P._db_capture_privacy_epochs()
    state = make_qstate("blocked.example.", q_ip="2001:db8::10")
    state.pfb_listener_ip, state.pfb_listener_interface = endpoint, "LAN"
    state.pfb_transport = transport
    kwargs = {"pfb_addr": "2001:db8::10"}
    assert P.get_details_reply("cache", None, state, None, kwargs)
    assert P.get_details_dnsbl(
        "reply",
        None,
        state,
        kwargs,
        block_decision(group="First", log_type="2").dnsbl,
        P._snapshot.group_epochs[("First", "custom")],
    )
    flush_metrics()
    expected = "192.0.2.53" if endpoint.startswith("::ffff:") else endpoint
    for path, table, count in [(resolver, "dns_metric_queries", 2), (dnsbl, "dns_metric_blocks", 1)]:
        with sqlite3.connect(path) as con:
            assert con.execute(f"SELECT listener_ip,listener_interface,client_ip,count FROM {table}").fetchall() == [
                (expected, "LAN" if expected else "", "", count)
            ]


@pytest.mark.parametrize(
    "bad", ["bad", "192.0.2.1/24", "[::1]", "fe80::1%em0", "192.0.2.1:53", "0.0.0.0", "::", "::ffff:0.0.0.0"]
)
def test_listener_rejects_invalid_address_independently(bad: str) -> None:
    assert P.get_q_listener(None, {"pfb_listener_ip": bad, "pfb_listener_interface": "LAN"}) == ("", "")
    assert P._metric_ip(bad) == ""


@pytest.mark.parametrize(
    "label,expected", [('LAN, "主"\\', 'LAN, "主"\\'), ("bad\nlabel", ""), ("bad\x85", ""), ("bad\udcff", "")]
)
def test_listener_interface_validation(label: str, expected: str) -> None:
    assert P.get_q_listener(
        SimpleNamespace(pfb_listener_ip="::ffff:192.0.2.53", pfb_listener_interface=label), None
    ) == ("192.0.2.53", expected)
    assert P.get_q_listener(None, {"pfb_listener_interface": label}) == ("", "")
    assert P.get_q_listener(SimpleNamespace(repinfo=SimpleNamespace(addr="192.0.2.53")), None) == ("", "")


def test_privacy_epoch_never_relabels_old_clients(metric_databases: Any, flush_metrics: Any) -> None:
    resolver, dnsbl = metric_databases
    P.pfb["metrics_client_ip"] = True
    for path in (resolver, dnsbl):
        with sqlite3.connect(path) as con:
            con.execute("UPDATE dns_metric_settings SET client_ip=1,epoch=?", ("a" * 32,))
    P._db_capture_privacy_epochs()
    for address in ("192.0.2.10", "2001:db8::10"):
        state = make_qstate("blocked.example.", q_ip=address)
        state.pfb_listener_ip, state.pfb_listener_interface = "192.0.2.53", "LAN"
        assert P.get_details_dnsbl(
            "reply",
            None,
            state,
            {"pfb_addr": address},
            block_decision(group="First", log_type="2").dnsbl,
            P._snapshot.group_epochs[("First", "custom")],
        )
    flush_metrics()
    for path, table in [(resolver, "dns_metric_queries"), (dnsbl, "dns_metric_blocks")]:
        with sqlite3.connect(path) as con:
            assert con.execute(f"SELECT client_ip,count FROM {table} ORDER BY 1").fetchall() == [
                ("192.0.2.10", 1),
                ("2001:db8::10", 1),
            ]
            # Simulate the Save transaction's irreversible OFF purge followed by ON.
            con.execute(f"DELETE FROM {table}")
            con.execute("UPDATE dns_metric_settings SET client_ip=1,epoch=?", ("b" * 32,))
    # The old process still holds a, even for events produced after OFF -> ON.
    for address in ("192.0.2.10", "2001:db8::10"):
        state = make_qstate("blocked.example.", q_ip=address)
        state.pfb_listener_ip, state.pfb_listener_interface = "192.0.2.53", "LAN"
        assert P.get_details_dnsbl(
            "reply",
            None,
            state,
            {"pfb_addr": address},
            block_decision(group="First", log_type="2").dnsbl,
            P._snapshot.group_epochs[("First", "custom")],
        )
    flush_metrics()
    for path, table in [(resolver, "dns_metric_queries"), (dnsbl, "dns_metric_blocks")]:
        with sqlite3.connect(path) as con:
            assert con.execute(f"SELECT listener_ip,listener_interface,client_ip,count FROM {table}").fetchall() == [
                ("192.0.2.53", "LAN", "", 2)
            ]
            assert con.execute("SELECT client_ip,epoch FROM dns_metric_settings").fetchall() == [(1, "b" * 32)]


@pytest.mark.parametrize(
    "db,table,old_sql,old_row",
    [
        (
            P.DB_RESOLVER,
            "dns_metric_queries",
            "qtype TEXT,transport TEXT,count INTEGER,PRIMARY KEY(qtype,transport)",
            "'A','UDP',7",
        ),
        (
            P.DB_DNSBL,
            "dns_metric_blocks",
            "owner TEXT,origin TEXT,groupname TEXT,qtype TEXT,transport TEXT,count INTEGER,"
            "PRIMARY KEY(owner,origin,groupname,qtype,transport)",
            "'First','custom','First','A','UDP',7",
        ),
    ],
)
def test_endpoint_migration(tmp_path: Path, db: int, table: str, old_sql: str, old_row: str) -> None:
    con = sqlite3.connect(tmp_path / "old.sqlite")
    try:
        con.execute(f"CREATE TABLE {table} ({old_sql})")
        con.execute(f"INSERT INTO {table} VALUES ({old_row})")
        con.commit()
        P._db_create(db, con.cursor())
        con.commit()
        assert con.execute(f"SELECT listener_ip,listener_interface,client_ip,count FROM {table}").fetchall() == [
            ("", "", "", 7)
        ]
        assert con.execute("SELECT client_ip,length(epoch) FROM dns_metric_settings").fetchall() == [(0, 32)]
        P._db_create(db, con.cursor())
        assert con.execute(f"SELECT SUM(count) FROM {table}").fetchone() == (7,)
    finally:
        con.close()


def test_endpoint_csv_all_writers_and_dedup(monkeypatch: pytest.MonkeyPatch) -> None:
    lines: list[list[str]] = []
    monkeypatch.setattr(P, "pfb_log", lambda path, line: lines.append(next(csv.reader(io.StringIO(line)))))
    P.pfb.update(sqlite3_dnsbl_con=False, sqlite3_resolver_con=False, python_reply=True, python_nolog=False)
    label = 'LAN, "主"\\'
    endpoint = {"listener_ip": "192.0.2.53", "listener_interface": label}
    P._log_idn_alert("a.example", "192.0.2.10", ("feed", "group", "eval"), "A", **endpoint)
    P._log_upstream_block("a.example", "192.0.2.10", P.UpstreamBlock("NXRA", "NXRA", ""), "A", **endpoint)
    state = make_qstate("blocked.example.")
    state.pfb_listener_ip, state.pfb_listener_interface = "192.0.2.53", label
    decision = block_decision(group="First").dnsbl
    for address in ("192.0.2.10", "192.0.2.11"):
        assert P.get_details_dnsbl("reply", None, state, {"pfb_addr": address}, decision)
    assert all(row[12:] == ["192.0.2.53", label] for row in lines)
    assert [row[9] for row in lines[-2:]] == ["+", "+"]
    assert P.get_details_reply("cache", None, state, None, {"pfb_addr": "192.0.2.10"})
    assert lines[-1][11:] == ["192.0.2.53", label]
