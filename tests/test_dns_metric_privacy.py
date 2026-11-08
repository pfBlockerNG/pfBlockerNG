"""Real SQLite transactions fence retained queue/batch client identifiers."""

from __future__ import annotations

import queue
import sqlite3
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
import unboundmodule

import pfb_unbound as P
from tests import test_dns_metric_breakdown as breakdown
from tests.test_pfb_unbound import block_decision, make_qstate

metric_databases = breakdown.metric_databases


def policy(path: Any, enabled: bool, epoch: str) -> None:
    with sqlite3.connect(path) as con:
        con.execute("BEGIN IMMEDIATE")
        if not enabled:
            table = "dns_metric_queries" if "resolver" in str(path) else "dns_metric_blocks"
            labels = "qtype,transport,listener_ip,listener_interface"
            if table == "dns_metric_blocks":
                labels = "owner,origin,groupname," + labels
            con.execute(
                f"CREATE TEMP TABLE merged AS SELECT {labels},'' AS client_ip,SUM(count) AS count "
                f"FROM {table} GROUP BY {labels}"
            )
            con.execute(f"DELETE FROM {table}")
            con.execute(f"INSERT INTO {table} SELECT * FROM merged")
        con.execute("UPDATE dns_metric_settings SET client_ip=?,epoch=? WHERE row=0", (int(enabled), epoch))


def emit(address: str) -> None:
    state = make_qstate("blocked.example.", q_ip=address)
    state.pfb_transport = "DoH"
    state.pfb_listener_ip, state.pfb_listener_interface = "2001:db8::53", "LAN"
    assert P.get_details_dnsbl(
        "reply",
        None,
        state,
        {"pfb_addr": address},
        block_decision(group="First", log_type="2").dnsbl,
        P._snapshot.group_epochs[("First", "custom")],
    )


def detail(path: Any, table: str) -> list[tuple[Any, ...]]:
    with sqlite3.connect(path) as con:
        return con.execute(
            f"SELECT listener_ip,listener_interface,client_ip,count FROM {table} ORDER BY client_ip"
        ).fetchall()


@pytest.mark.parametrize("retained", ["queue", "batch", "failed-batch"])
@pytest.mark.parametrize("activate_before_retry", [False, True], ids=["old-cache", "new-cache"])
def test_old_queue_and_failed_transaction_cannot_resurrect_client_ips(
    metric_databases: Any, monkeypatch: Any, retained: str, activate_before_retry: bool
) -> None:
    resolver, dnsbl = metric_databases
    P.pfb["metrics_client_ip"] = True
    for path in (resolver, dnsbl):
        policy(path, True, "a" * 32)
    P._db_capture_privacy_epochs()
    # Persist real client rows, then keep additional events from the old incarnation.
    emit("192.0.2.10")
    emit("2001:db8::10")
    for path, table in ((resolver, "dns_metric_queries"), (dnsbl, "dns_metric_blocks")):
        assert detail(path, table) == [
            ("2001:db8::53", "LAN", "192.0.2.10", 1),
            ("2001:db8::53", "LAN", "2001:db8::10", 1),
        ]
        P._db_close(P.DB_RESOLVER if path == resolver else P.DB_DNSBL)
    # A normal process restart captures the same persistent authority.
    P._db_capture_privacy_epochs()
    assert P.pfb["metrics_privacy_epochs"] == {P.DB_RESOLVER: "a" * 32, P.DB_DNSBL: "a" * 32}
    P.pfb["db_worker"] = True
    emit("192.0.2.10")
    emit("2001:db8::10")
    with P.pfb_db_queue.mutex:
        emitted = tuple(P.pfb_db_queue.queue)
    assert len(emitted) == 4
    assert {task[0] for task in emitted} == {"resolver", "dnsbl"}
    assert {task[-2] for task in emitted} == {"192.0.2.10", "2001:db8::10"}
    assert {task[-1] for task in emitted} == {"a" * 32}
    snapshots: dict[int, dict[tuple, int]] = {P.DB_RESOLVER: {}, P.DB_DNSBL: {}}
    deltas: dict[tuple, int] = {}
    if retained != "queue":
        while not P.pfb_db_queue.empty():
            task = P.pfb_db_queue.get_nowait()
            P.pfb_db_queue.task_done()
            db = P.DB_RESOLVER if task[0] == "resolver" else P.DB_DNSBL
            key = task[1:]
            snapshots[db][key] = snapshots[db].get(key, 0) + 1
            if db == P.DB_DNSBL:
                deltas[key[:4]] = deltas.get(key[:4], 0) + 1
        retained_keys = {db: dict(rows) for db, rows in snapshots.items()}
        retained_deltas = dict(deltas)
        if retained == "failed-batch":
            monkeypatch.setattr(P.time, "sleep", lambda _: None)
            for path, table in ((resolver, "dns_metric_queries"), (dnsbl, "dns_metric_blocks")):
                with sqlite3.connect(path) as con:
                    con.execute(
                        f"CREATE TRIGGER reject_detail BEFORE INSERT ON {table} "
                        "BEGIN SELECT RAISE(ABORT,'real failure'); END"
                    )
            assert not P._db_flush_resolver(2, snapshots[P.DB_RESOLVER])
            assert not P._db_flush_dnsbl(deltas, snapshots[P.DB_DNSBL])
            assert sum(snapshots[P.DB_RESOLVER].values()) == sum(snapshots[P.DB_DNSBL].values()) == 2
            assert snapshots == retained_keys
            assert deltas == retained_deltas
            for path in (resolver, dnsbl):
                with sqlite3.connect(path) as con:
                    con.execute("DROP TRIGGER reject_detail")
    for path, table in ((resolver, "dns_metric_queries"), (dnsbl, "dns_metric_blocks")):
        policy(path, False, "b" * 32)
        assert detail(path, table) == [("2001:db8::53", "LAN", "", 2)]
        with sqlite3.connect(path) as con:
            assert con.execute("SELECT client_ip,epoch FROM dns_metric_settings WHERE row=0").fetchall() == [
                (0, "b" * 32)
            ]
        policy(path, True, "c" * 32)
        with sqlite3.connect(path) as con:
            assert con.execute("SELECT client_ip,epoch FROM dns_metric_settings WHERE row=0").fetchall() == [
                (1, "c" * 32)
            ]
    if activate_before_retry:
        P._db_capture_privacy_epochs()
    expected_epoch = ("c" if activate_before_retry else "a") * 32
    assert P.pfb["metrics_privacy_epochs"] == {P.DB_RESOLVER: expected_epoch, P.DB_DNSBL: expected_epoch}
    if retained == "queue":
        with P.pfb_db_queue.mutex:
            assert tuple(P.pfb_db_queue.queue) == emitted
    else:
        assert snapshots == retained_keys
        assert deltas == retained_deltas
        assert {key[-1] for rows in snapshots.values() for key in rows} == {"a" * 32}
    if retained == "queue":
        P.pfb_db_queue.put(("stop",))
        P.pfb_db_worker()
    else:
        assert P._db_flush_resolver(2, snapshots[P.DB_RESOLVER])
        assert P._db_flush_dnsbl(deltas, snapshots[P.DB_DNSBL])
    for path, table in ((resolver, "dns_metric_queries"), (dnsbl, "dns_metric_blocks")):
        assert detail(path, table) == [("2001:db8::53", "LAN", "", 4)]
    with sqlite3.connect(resolver) as con:
        assert con.execute("SELECT totalqueries FROM resolver").fetchall() == [(14,)]
    with sqlite3.connect(dnsbl) as con:
        assert con.execute("SELECT counter FROM dnsbl WHERE groupname='First'").fetchall() == [(11,)]
        assert con.execute("SELECT SUM(count) FROM dns_metric_totals WHERE groupname='First'").fetchall() == [(4,)]
    # Fresh authority labels only new events, never the retained A tuples above.
    if not activate_before_retry:
        P._db_capture_privacy_epochs()
    assert P.pfb["metrics_privacy_epochs"] == {P.DB_RESOLVER: "c" * 32, P.DB_DNSBL: "c" * 32}
    P.pfb["db_worker"] = False
    emit("192.0.2.99")
    for path, table in ((resolver, "dns_metric_queries"), (dnsbl, "dns_metric_blocks")):
        assert detail(path, table) == [("2001:db8::53", "LAN", "", 4), ("2001:db8::53", "LAN", "192.0.2.99", 1)]
    with sqlite3.connect(resolver) as con:
        assert con.execute("SELECT totalqueries FROM resolver").fetchall() == [(15,)]
    with sqlite3.connect(dnsbl) as con:
        assert con.execute("SELECT counter FROM dnsbl WHERE groupname='First'").fetchall() == [(12,)]
        assert con.execute("SELECT SUM(count) FROM dns_metric_totals WHERE groupname='First'").fetchall() == [(5,)]
    for path, table in ((resolver, "dns_metric_queries"), (dnsbl, "dns_metric_blocks")):
        with sqlite3.connect(path) as con:
            con.execute(f"DELETE FROM {table}")
    emit("192.0.2.99")
    for path, table in ((resolver, "dns_metric_queries"), (dnsbl, "dns_metric_blocks")):
        assert detail(path, table) == [("2001:db8::53", "LAN", "192.0.2.99", 1)]


def test_initial_ini_opt_in_cannot_promote_default_off_database(metric_databases: Any) -> None:
    P.pfb["metrics_client_ip"] = True
    P._db_capture_privacy_epochs()
    assert P.pfb["metrics_privacy_epochs"] == {}
    emit("192.0.2.10")
    for path, table in zip(metric_databases, ("dns_metric_queries", "dns_metric_blocks"), strict=True):
        assert detail(path, table) == [("2001:db8::53", "LAN", "", 1)]


OPTED_IN_EPOCH = "0123456789abcdef0123456789abcdef"


@pytest.fixture
def init_over_opted_in_databases(
    tmp_path: Path, monkeypatch: Any
) -> Iterator[Callable[[str | None], tuple[Path, Path]]]:
    """Run the real init_standard over a real INI file and real metric databases already stored as client_ip=1."""
    monkeypatch.chdir(tmp_path)
    # init_standard() replaces sys.stderr; register monkeypatch's auto-restore.
    monkeypatch.setattr(sys, "stderr", sys.stderr)
    monkeypatch.setattr(P, "pfb_db_queue", queue.Queue(), raising=False)
    resolver, dnsbl = tmp_path / "pfb_py_resolver.sqlite", tmp_path / "pfb_py_dnsbl.sqlite"
    P.pfb.update(pfb_py_resolver=str(resolver), pfb_py_dnsbl=str(dnsbl), sqlite3_resolver_con=True)
    P.pfb.update(sqlite3_dnsbl_con=True, db_worker=False, mod_threading=False)
    for key in ("mod_threading_e", "mod_maxminddb_e"):
        P.pfb[key] = "stub"
    for database in (P.DB_RESOLVER, P.DB_DNSBL):
        assert P.pfb_db_validate(database)
        P._db_close(database)
    with sqlite3.connect(dnsbl) as con:
        con.execute("INSERT INTO dnsbl (groupname, timestamp, entries, counter) VALUES ('First', '', 1, 0)")
        con.execute("INSERT INTO dnsbl_group_epochs VALUES ('First', 'custom', lower(hex(randomblob(16))))")
    for path in (resolver, dnsbl):
        policy(path, True, OPTED_IN_EPOCH)
    started = []

    def init(metrics_client_ip: str | None) -> tuple[Path, Path]:
        # forwarding makes the DNSBL statistics database wanted without needing a feed manifest.
        lines = ["[MAIN]", "python_enable = true", "forwarding = true"]
        if metrics_client_ip is not None:
            lines.append(f"metrics_client_ip = {metrics_client_ip}")
        (tmp_path / "pfb_unbound.ini").write_text("\n".join(lines) + "\n", encoding="utf-8")
        started.append(True)
        assert P.init_standard(0, unboundmodule.module_env()) is True
        for path in (resolver, dnsbl):
            with sqlite3.connect(path) as con:
                assert con.execute("SELECT client_ip,epoch FROM dns_metric_settings").fetchall() == [
                    (1, OPTED_IN_EPOCH)
                ], "init must leave the stored policy opted in so only the INI gate can withhold client IPs"
        return resolver, dnsbl

    yield init
    if started:
        P.deinit(0)


@pytest.mark.parametrize("ini_option", [None, "false"], ids=["ini-absent", "ini-false"])
def test_ini_without_client_ip_opt_in_withholds_authority_from_opted_in_database(
    init_over_opted_in_databases: Callable[[str | None], tuple[Path, Path]], ini_option: str | None
) -> None:
    databases = init_over_opted_in_databases(ini_option)
    assert P.pfb["metrics_privacy_epochs"] == {}
    emit("192.0.2.10")
    for path, table in zip(databases, ("dns_metric_queries", "dns_metric_blocks"), strict=True):
        assert detail(path, table) == [("2001:db8::53", "LAN", "", 1)]


def test_ini_client_ip_opt_in_grants_authority_to_opted_in_database(
    init_over_opted_in_databases: Callable[[str | None], tuple[Path, Path]],
) -> None:
    databases = init_over_opted_in_databases("true")
    assert P.pfb["metrics_privacy_epochs"] == {P.DB_RESOLVER: OPTED_IN_EPOCH, P.DB_DNSBL: OPTED_IN_EPOCH}
    emit("192.0.2.10")
    for path, table in zip(databases, ("dns_metric_queries", "dns_metric_blocks"), strict=True):
        assert detail(path, table) == [("2001:db8::53", "LAN", "192.0.2.10", 1)]


@pytest.mark.parametrize("db", [P.DB_RESOLVER, P.DB_DNSBL])
def test_schema_failure_rolls_back_old_detail_and_aggregate(tmp_path: Any, db: int) -> None:
    with sqlite3.connect(tmp_path / "migration.sqlite") as con:
        if db == P.DB_RESOLVER:
            table, columns, values = "dns_metric_queries", "qtype TEXT,transport TEXT,count INTEGER", "'A','UDP',7"
        else:
            table = "dns_metric_blocks"
            columns = "owner TEXT,origin TEXT,groupname TEXT,qtype TEXT,transport TEXT,count INTEGER"
            values = "'First','custom','First','A','UDP',7"
        con.execute(f"CREATE TABLE {table} ({columns})")
        con.execute(f"INSERT INTO {table} VALUES ({values})")
        # A real naming collision makes the final settings seed fail after detail migration.
        con.execute("CREATE TABLE dns_metric_settings (wrong TEXT)")
        con.commit()
        before = con.execute(f"SELECT * FROM {table}").fetchall()
        with pytest.raises(sqlite3.Error):
            P._db_create(db, con.cursor())
        assert con.execute(f"SELECT * FROM {table}").fetchall() == before
        assert "listener_ip" not in [r[1] for r in con.execute(f"PRAGMA table_info({table})")]
        assert con.execute("SELECT name FROM sqlite_master WHERE name LIKE '%_old'").fetchall() == []


def test_optional_authority_failure_never_breaks_dns(metric_databases: Any, monkeypatch: Any) -> None:
    P.pfb["metrics_client_ip"] = True
    P._db_close(P.DB_RESOLVER)
    P._db_close(P.DB_DNSBL)
    monkeypatch.setattr(P, "_db_connect", lambda db: (_ for _ in ()).throw(sqlite3.OperationalError("unavailable")))
    P._db_capture_privacy_epochs()
    assert P.pfb["metrics_privacy_epochs"] == {}
    P.pfb.update(sqlite3_resolver_con=False, sqlite3_dnsbl_con=False)
    emit("192.0.2.10")


@pytest.mark.parametrize("label", ["bad\u2028name", "bad\u2029name", "bad\u200ename", b"bad\xff"])
def test_unicode_control_interface_is_unavailable(label: Any) -> None:
    assert P.get_q_listener(None, {"pfb_listener_ip": "192.0.2.53", "pfb_listener_interface": label}) == (
        "192.0.2.53",
        "",
    )
