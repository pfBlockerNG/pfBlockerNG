"""Upstream metrics retain numeric query types without changing Reports CSV."""

from __future__ import annotations

import csv
import io
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

import pfb_unbound
from tests.test_pfb_unbound import make_qstate


def test_upstream_callback_keeps_numeric_metric_type_and_csv_unknown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "dnsbl.sqlite"
    pfb_unbound.pfb.update(pfb_py_dnsbl=str(path), sqlite3_dnsbl_con=True, db_worker=False, forwarding=True)
    assert pfb_unbound.pfb_db_validate(pfb_unbound.DB_DNSBL)
    pfb_unbound._snapshot.group_epochs.update(pfb_unbound._db_group_epochs(True, {}))
    lines: list[str] = []
    monkeypatch.setattr(pfb_unbound, "pfb_log", lambda destination, line: lines.append(line))
    try:
        for number, name in [(1, "A"), (65400, ""), (65401, "")]:
            state = make_qstate("example.com.", qtype=number, q_ip="192.0.2.10")
            state.qinfo.qtype_str = name
            state.pfb_transport = "DoH"
            assert pfb_unbound.inplace_cb_query_response(state, SimpleNamespace(rep=SimpleNamespace(flags=3)))
        with sqlite3.connect(path) as connection:
            assert connection.execute("SELECT counter FROM dnsbl WHERE groupname = 'Upstream'").fetchall() == [(3,)]
            assert connection.execute(
                "SELECT qtype, transport, count FROM dns_metric_blocks ORDER BY qtype"
            ).fetchall() == [("A", "DoH", 1), ("TYPE65400", "DoH", 1), ("TYPE65401", "DoH", 1)]
        assert [next(csv.reader(io.StringIO(line)))[10:] for line in lines] == [
            ["A", "DoH", "", ""],
            ["Unknown", "DoH", "", ""],
            ["Unknown", "DoH", "", ""],
        ]
    finally:
        pfb_unbound._db_close(pfb_unbound.DB_DNSBL)
