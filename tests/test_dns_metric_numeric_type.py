"""Unknown DNS RR numbers remain distinct in query metrics."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pfb_unbound
from tests.test_pfb_unbound import make_qstate


def test_unnamed_rr_type_is_recorded_by_number(tmp_path: Path) -> None:
    path = tmp_path / "resolver.sqlite"
    pfb_unbound.pfb.update(pfb_py_resolver=str(path), sqlite3_resolver_con=True, db_worker=False)
    assert pfb_unbound.pfb_db_validate(pfb_unbound.DB_RESOLVER)
    try:
        for number in (0, 65400, 65401, 65535):
            state = make_qstate("example.com.", qtype=number, q_ip="192.0.2.10")
            state.qinfo.qtype_str = ""
            assert pfb_unbound.get_q_type(state, None) == "Unknown"
            assert pfb_unbound.get_details_reply("cache", None, state, None, {"pfb_addr": "192.0.2.10"})
        with sqlite3.connect(path) as con:
            assert con.execute("SELECT qtype, transport, count FROM dns_metric_queries ORDER BY qtype").fetchall() == [
                ("TYPE0", "", 1),
                ("TYPE65400", "", 1),
                ("TYPE65401", "", 1),
                ("TYPE65535", "", 1),
            ]
    finally:
        pfb_unbound._db_close(pfb_unbound.DB_RESOLVER)
