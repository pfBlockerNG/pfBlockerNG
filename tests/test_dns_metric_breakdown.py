"""DNS metric dimensions must survive real counting and SQLite batching paths."""

from __future__ import annotations

import queue
import sqlite3
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from unboundmodule import MODULE_EVENT_NEW, MODULE_FINISHED

import pfb_unbound
from tests.test_pfb_unbound import add_data, block_decision, make_qstate, set_feed_group


@pytest.fixture
def metric_databases(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[Path, Path]]:
    resolver = tmp_path / "resolver.sqlite"
    dnsbl = tmp_path / "dnsbl.sqlite"
    pfb_unbound.pfb.update(
        pfb_py_resolver=str(resolver),
        pfb_py_dnsbl=str(dnsbl),
        sqlite3_resolver_con=True,
        sqlite3_dnsbl_con=True,
        db_worker=False,
    )
    monkeypatch.setattr(pfb_unbound, "pfb_db_queue", queue.Queue(), raising=False)
    for database in (pfb_unbound.DB_RESOLVER, pfb_unbound.DB_DNSBL):
        assert pfb_unbound.pfb_db_validate(database), f"failed to initialize metric database {database}"
    with sqlite3.connect(resolver) as connection:
        connection.execute("UPDATE resolver SET totalqueries = 10 WHERE row = 0")
    with sqlite3.connect(dnsbl) as connection:
        connection.executemany(
            "INSERT INTO dnsbl (groupname, timestamp, entries, counter) VALUES (?, '', 1, ?)",
            [("First", 7), ("Second", 3)],
        )
        pfb_unbound._db_create(pfb_unbound.DB_DNSBL, connection.cursor())
        connection.executemany(
            "INSERT INTO dnsbl_group_epochs VALUES (?, 'custom', lower(hex(randomblob(16))))",
            [("First",), ("Second",)],
        )
    pfb_unbound._snapshot.group_epochs.update(pfb_unbound._db_group_epochs(True, {}))
    try:
        yield resolver, dnsbl
    finally:
        pfb_unbound.pfb["db_worker"] = False
        for database in (pfb_unbound.DB_RESOLVER, pfb_unbound.DB_DNSBL):
            pfb_unbound._db_close(database)


@pytest.fixture(params=[False, True], ids=["synchronous", "queued"])
def flush_metrics(request: pytest.FixtureRequest) -> Iterator[Callable[[], None]]:
    queued = request.param
    pfb_unbound.pfb["db_worker"] = queued

    def flush() -> None:
        if queued:
            # Run the real worker against a finite queue; stop is its commit/drain barrier.
            pfb_unbound.pfb_db_queue.put(("stop",))
            pfb_unbound.pfb_db_worker()
            assert pfb_unbound.pfb_db_queue.unfinished_tasks == 0, "worker did not drain every metric task"

    try:
        yield flush
    finally:
        pfb_unbound.pfb["db_worker"] = False


def _query(qtype: int, name: str, transport: str | None) -> Any:
    state = make_qstate("blocked.example.", qtype=qtype, q_ip="192.0.2.10")
    state.qinfo.qtype_str = name
    if transport is not None:
        # #3751 supplies the original-client value; no listener/upstream inference.
        state.pfb_transport = transport
    return state


def _rows(path: Path, table: str, columns: str) -> list[tuple[Any, ...]]:
    with sqlite3.connect(path) as connection:
        tables = connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
        assert (table,) in tables, f"missing persistent metric table {table!r}; found {tables!r}"
        return connection.execute(f"SELECT {columns} FROM {table} ORDER BY 1, 2, 3").fetchall()


def test_reply_counters_preserve_all_query_types_and_original_transport(
    metric_databases: tuple[Path, Path], flush_metrics: Callable[[], None]
) -> None:
    resolver, _ = metric_databases
    # Given historical totals, count queries even when reply logging is disabled.
    for qtype, name, transport in [
        (1, "A", "UDP"),
        (28, "AAAA", "TCP"),
        (16, "TXT", "DoT"),
        (65, "HTTPS", "DoH"),
        (64, "SVCB", "DoQ"),
        (65400, "TYPE65400", "DoH"),
        (65401, "TYPE65401", None),
        (65400, "TYPE65400", ""),
        (1, "A", "UDP"),
    ]:
        state = _query(qtype, name, transport)
        assert pfb_unbound.get_details_reply("cache", None, state, None, {"pfb_addr": "192.0.2.10"})
    flush_metrics()

    with sqlite3.connect(resolver) as connection:
        assert connection.execute("SELECT totalqueries FROM resolver WHERE row = 0").fetchall() == [(19,)]
    assert _rows(resolver, "dns_metric_queries", "qtype, transport, count") == [
        ("A", "UDP", 2),
        ("AAAA", "TCP", 1),
        ("HTTPS", "DoH", 1),
        ("SVCB", "DoQ", 1),
        ("TXT", "DoT", 1),
        ("TYPE65400", "", 1),
        ("TYPE65400", "DoH", 1),
        ("TYPE65401", "", 1),
    ]


def test_operate_block_counters_keep_groups_query_types_and_transport(
    metric_databases: tuple[Path, Path], flush_metrics: Callable[[], None]
) -> None:
    resolver, dnsbl = metric_databases
    pfb_unbound.pfb.update(python_blacklist=True, python_blocking=True)
    add_data("blocked.example", log="2", index=0)
    set_feed_group(0, "FirstFeed", "First")
    # Silent blocks still count; the memoized verdict must not retain the first query's dimensions.
    for qtype, name, transport in [(1, "A", "UDP"), (16, "TXT", "DoH"), (65, "HTTPS", None), (1, "A", "TCP")]:
        state = _query(qtype, name, transport)
        assert pfb_unbound.operate(0, MODULE_EVENT_NEW, state, None)
        assert state.ext_state[0] == MODULE_FINISHED, f"query {name} was not blocked: {state.ext_state!r}"

    # Counting accepts arbitrary types without broadening operate()'s DNS blocking policy.
    state = _query(65400, "TYPE65400", "DoQ")
    assert pfb_unbound.get_details_dnsbl(
        "reply",
        None,
        state,
        None,
        block_decision(group="Second", log_type="2").dnsbl,
        pfb_unbound._snapshot.group_epochs[("Second", "custom")],
    )
    flush_metrics()

    with sqlite3.connect(resolver) as connection:
        assert connection.execute("SELECT totalqueries FROM resolver WHERE row = 0").fetchall() == [(15,)]
    with sqlite3.connect(dnsbl) as connection:
        assert connection.execute(
            "SELECT groupname, counter FROM dnsbl WHERE groupname IN ('First', 'Second') ORDER BY groupname"
        ).fetchall() == [("First", 11), ("Second", 4)]
    assert _rows(dnsbl, "dns_metric_blocks", "groupname, qtype, transport, count") == [
        ("First", "A", "TCP", 1),
        ("First", "A", "UDP", 1),
        ("First", "HTTPS", "", 1),
        ("First", "TXT", "DoH", 1),
        ("Second", "TYPE65400", "DoQ", 1),
    ]
    assert _rows(resolver, "dns_metric_queries", "qtype, transport, count") == [
        ("A", "TCP", 1),
        ("A", "UDP", 1),
        ("HTTPS", "", 1),
        ("TXT", "DoH", 1),
        ("TYPE65400", "DoQ", 1),
    ]


def test_metric_counts_survive_reconnect_without_reclassifying_history(
    metric_databases: tuple[Path, Path], flush_metrics: Callable[[], None]
) -> None:
    resolver, dnsbl = metric_databases
    state = _query(65400, "TYPE65400", "DoT")
    decision = block_decision(group="First", log_type="2").dnsbl
    assert pfb_unbound.get_details_dnsbl(
        "reply", None, state, None, decision, pfb_unbound._snapshot.group_epochs[("First", "custom")]
    )
    flush_metrics()
    assert _rows(resolver, "dns_metric_queries", "qtype, transport, count") == [("TYPE65400", "DoT", 1)]
    assert _rows(dnsbl, "dns_metric_blocks", "groupname, qtype, transport, count") == [("First", "TYPE65400", "DoT", 1)]

    # When connections reopen, existing detail counts and unattributed history both survive.
    for database in (pfb_unbound.DB_RESOLVER, pfb_unbound.DB_DNSBL):
        pfb_unbound._db_close(database)
        assert pfb_unbound.pfb_db_validate(database), f"failed to reopen metric database {database}"
    assert pfb_unbound.get_details_dnsbl(
        "reply", None, state, None, decision, pfb_unbound._snapshot.group_epochs[("First", "custom")]
    )
    flush_metrics()
    assert _rows(resolver, "dns_metric_queries", "qtype, transport, count") == [("TYPE65400", "DoT", 2)]
    assert _rows(dnsbl, "dns_metric_blocks", "groupname, qtype, transport, count") == [("First", "TYPE65400", "DoT", 2)]
    with sqlite3.connect(resolver) as connection:
        assert connection.execute(
            "SELECT totalqueries - (SELECT SUM(count) FROM dns_metric_queries) FROM resolver WHERE row = 0"
        ).fetchall() == [(10,)]
    with sqlite3.connect(dnsbl) as connection:
        assert connection.execute(
            "SELECT groupname, counter - COALESCE((SELECT SUM(count) FROM dns_metric_blocks AS detail "
            "WHERE detail.groupname = dnsbl.groupname), 0) "
            "FROM dnsbl WHERE groupname IN ('First', 'Second') ORDER BY groupname"
        ).fetchall() == [("First", 7), ("Second", 3)]


def test_qinfo_only_cache_reply_preserves_callback_transport(
    metric_databases: tuple[Path, Path], flush_metrics: Callable[[], None]
) -> None:
    resolver, _ = metric_databases
    state = _query(65400, "TYPE65400", None)
    assert pfb_unbound.get_details_reply(
        "cache", state.qinfo, None, None, {"pfb_addr": "192.0.2.10", "pfb_transport": "DoH"}
    )
    assert pfb_unbound.get_details_reply("cache", state.qinfo, None, None, {"pfb_addr": "192.0.2.10"})
    flush_metrics()
    assert _rows(resolver, "dns_metric_queries", "qtype, transport, count") == [
        ("TYPE65400", "", 1),
        ("TYPE65400", "DoH", 1),
    ]


def test_upstream_metrics_keep_transport_without_changing_csv(
    metric_databases: tuple[Path, Path], flush_metrics: Callable[[], None], monkeypatch: pytest.MonkeyPatch
) -> None:
    _, dnsbl = metric_databases
    lines: list[str] = []
    monkeypatch.setattr(pfb_unbound, "pfb_log", lambda path, line: lines.append(line))
    result = pfb_unbound.UpstreamBlock("NXRA", "provider", "external")
    for transport in ("UDP", "TCP", "DoT", "DoH", "DoQ", "Unknown"):
        pfb_unbound._log_upstream_block(
            "example.com",
            "192.0.2.1",
            result,
            "TXT",
            transport,
            group_epoch=pfb_unbound._snapshot.group_epochs[("Upstream", "builtin")],
        )
    flush_metrics()
    assert _rows(dnsbl, "dns_metric_blocks", "groupname, qtype, transport, count") == [
        ("Upstream", "TXT", "", 1),
        ("Upstream", "TXT", "DoH", 1),
        ("Upstream", "TXT", "DoQ", 1),
        ("Upstream", "TXT", "DoT", 1),
        ("Upstream", "TXT", "TCP", 1),
        ("Upstream", "TXT", "UDP", 1),
    ]
    assert lines[-1].rstrip().endswith(",TXT,Unknown,,")


def test_local_resolver_requests_are_not_counted(
    metric_databases: tuple[Path, Path], flush_metrics: Callable[[], None]
) -> None:
    resolver, _ = metric_databases
    state = _query(1, "A", "UDP")
    for address in ("127.0.0.1", "Unknown"):
        assert pfb_unbound.get_details_reply("cache", None, state, None, {"pfb_addr": address})
    flush_metrics()
    assert _rows(resolver, "dns_metric_queries", "qtype, transport, count") == []
    with sqlite3.connect(resolver) as connection:
        assert connection.execute("SELECT totalqueries FROM resolver").fetchall() == [(10,)]


def test_python_nolog_preserves_existing_webserver_counter_contract(
    metric_databases: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    resolver, dnsbl = metric_databases
    monkeypatch.setitem(pfb_unbound.pfb, "python_nolog", True)
    state = _query(1, "A", "UDP")
    assert pfb_unbound.get_details_dnsbl(
        "dnsbl",
        None,
        state,
        None,
        block_decision(group="First", log_type="1", null_blocking=False).dnsbl,
        pfb_unbound._snapshot.group_epochs[("First", "custom")],
    )
    assert _rows(resolver, "dns_metric_queries", "qtype, transport, count") == [("A", "UDP", 1)]
    assert _rows(dnsbl, "dns_metric_blocks", "groupname, qtype, transport, count") == []
    with sqlite3.connect(dnsbl) as connection:
        assert connection.execute("SELECT counter FROM dnsbl WHERE groupname = 'First'").fetchall() == [(7,)]


@pytest.mark.parametrize("database", [pfb_unbound.DB_RESOLVER, pfb_unbound.DB_DNSBL])
@pytest.mark.parametrize("retry", [False, True], ids=["rollback", "retry"])
def test_detail_failure_rolls_back_aggregate_before_retry(
    metric_databases: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch, database: int, retry: bool
) -> None:
    resolver, dnsbl = metric_databases
    path = resolver if database == pfb_unbound.DB_RESOLVER else dnsbl
    table = "dns_metric_queries" if database == pfb_unbound.DB_RESOLVER else "dns_metric_blocks"
    # A real SQLite failure after the aggregate UPDATE must roll the whole event back.
    with sqlite3.connect(path) as connection:
        connection.execute(
            f"CREATE TRIGGER reject_detail BEFORE INSERT ON {table} BEGIN SELECT RAISE(ABORT, 'detail rejected'); END"
        )

    def release_trigger(delay: float) -> None:
        if retry:
            with sqlite3.connect(path) as connection:
                connection.execute("DROP TRIGGER IF EXISTS reject_detail")

    monkeypatch.setattr(pfb_unbound.time, "sleep", release_trigger)
    task = (
        ("resolver", "A", "UDP", "", "", "", "")
        if database == pfb_unbound.DB_RESOLVER
        else (
            "dnsbl",
            "First",
            "First",
            "custom",
            pfb_unbound._snapshot.group_epochs[("First", "custom")],
            "A",
            "UDP",
            "",
            "",
            "",
            "",
        )
    )
    pfb_unbound.pfb_db_enqueue(task)
    with sqlite3.connect(path) as connection:
        if database == pfb_unbound.DB_RESOLVER:
            assert connection.execute("SELECT totalqueries FROM resolver").fetchall() == [(10 + int(retry),)]
        else:
            assert connection.execute("SELECT counter FROM dnsbl WHERE groupname = 'First'").fetchall() == [
                (7 + int(retry),)
            ]
        assert connection.execute(f"SELECT count FROM {table}").fetchall() == ([(1,)] if retry else [])


@pytest.mark.parametrize("mode", ["threshold", "idle", "stop", "retry"])
def test_worker_flushes_dimensions_once(
    metric_databases: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    resolver, dnsbl = metric_databases
    monkeypatch.setitem(pfb_unbound.pfb, "db_worker", True)
    monkeypatch.setattr(pfb_unbound, "PFB_DB_MAX_BATCH", 2 if mode in ("threshold", "retry") else 100)
    monkeypatch.setattr(pfb_unbound.time, "sleep", lambda delay: None)
    if mode == "retry":
        with sqlite3.connect(resolver) as connection:
            connection.execute(
                "CREATE TRIGGER reject_detail BEFORE INSERT ON dns_metric_queries "
                "BEGIN SELECT RAISE(ABORT, 'detail rejected'); END"
            )

    class FlushQueue(queue.Queue):
        def get(self, block: bool = True, timeout: float | None = None) -> Any:
            if block and self.qsize() == 1:
                if mode == "retry" and not getattr(self, "idle_seen", False):
                    with sqlite3.connect(resolver) as connection:
                        assert connection.execute("SELECT totalqueries FROM resolver").fetchall() == [(10,)]
                        connection.execute("DROP TRIGGER reject_detail")
                if mode in ("idle", "retry") and not getattr(self, "idle_seen", False):
                    self.idle_seen = True
                    raise queue.Empty
                if mode != "stop":
                    assert _rows(resolver, "dns_metric_queries", "qtype, transport, count") == [("A", "UDP", 1)]
                    assert _rows(dnsbl, "dns_metric_blocks", "groupname, qtype, transport, count") == [
                        ("First", "A", "UDP", 1)
                    ]
            return super().get(block, timeout)

    work = FlushQueue()
    monkeypatch.setattr(pfb_unbound, "pfb_db_queue", work)
    pfb_unbound.pfb_db_enqueue(("resolver", "A", "UDP", "", "", "", ""))
    pfb_unbound.pfb_db_enqueue(
        (
            "dnsbl",
            "First",
            "First",
            "custom",
            pfb_unbound._snapshot.group_epochs[("First", "custom")],
            "A",
            "UDP",
            "",
            "",
            "",
            "",
        )
    )
    work.put(("stop",))
    pfb_unbound.pfb_db_worker()
    assert work.unfinished_tasks == 0
    assert _rows(resolver, "dns_metric_queries", "qtype, transport, count") == [("A", "UDP", 1)]
    assert _rows(dnsbl, "dns_metric_blocks", "groupname, qtype, transport, count") == [("First", "A", "UDP", 1)]
    with sqlite3.connect(resolver) as connection:
        assert connection.execute("SELECT totalqueries FROM resolver").fetchall() == [(11,)]
    with sqlite3.connect(dnsbl) as connection:
        assert connection.execute("SELECT counter FROM dnsbl WHERE groupname = 'First'").fetchall() == [(8,)]
