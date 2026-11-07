"""Deleted groups must stay absent from detail metrics despite late queued blocks."""

from __future__ import annotations

import queue
import sqlite3
from collections.abc import Iterator
from pathlib import Path

import pytest

import pfb_unbound


@pytest.fixture
def removal_database(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    database = tmp_path / "dnsbl.sqlite"
    pfb_unbound.pfb.update(
        pfb_py_dnsbl=str(database),
        sqlite3_dnsbl_con=True,
        sqlite3_resolver_con=False,
        db_worker=True,
    )
    monkeypatch.setattr(pfb_unbound, "pfb_db_queue", queue.Queue(), raising=False)
    assert pfb_unbound.pfb_db_validate(pfb_unbound.DB_DNSBL), "failed to initialize DNSBL database"
    with sqlite3.connect(database) as connection:
        connection.executemany(
            "INSERT INTO dnsbl (groupname, timestamp, entries, counter) VALUES (?, '', 1, ?)",
            [("Removed", 7), ("Active", 3)],
        )
    try:
        yield database
    finally:
        pfb_unbound.pfb["db_worker"] = False
        pfb_unbound._db_close(pfb_unbound.DB_DNSBL)


def _drain_worker() -> None:
    # No consumer runs before this call; stop commits all preceding queued events.
    pfb_unbound.pfb_db_queue.put(("stop",))
    pfb_unbound.pfb_db_worker()
    assert pfb_unbound.pfb_db_queue.unfinished_tasks == 0, "worker left unconsumed metric tasks"


def _aggregates(database: Path) -> list[tuple[str, int]]:
    with sqlite3.connect(database) as connection:
        return connection.execute("SELECT groupname, counter FROM dnsbl ORDER BY groupname").fetchall()


def _details(database: Path) -> list[tuple[str, str, str, int]]:
    with sqlite3.connect(database) as connection:
        return connection.execute(
            "SELECT groupname, qtype, transport, count FROM dns_metric_blocks ORDER BY groupname, qtype, transport"
        ).fetchall()


def test_removed_group_rejects_queued_details_until_explicit_reactivation(removal_database: Path) -> None:
    database = removal_database
    # Given both groups have counted detail and unattributed legacy history.
    pfb_unbound.pfb_db_enqueue(("dnsbl", "Removed", "A", "UDP"))
    pfb_unbound.pfb_db_enqueue(("dnsbl", "Active", "A", "UDP"))
    _drain_worker()
    assert _aggregates(database) == [("Active", 4), ("Removed", 8), ("Upstream", 0)]
    assert _details(database) == [("Active", "A", "UDP", 1), ("Removed", "A", "UDP", 1)]

    # When an event is already queued before PHP commits group removal.
    pfb_unbound.pfb_db_enqueue(("dnsbl", "Removed", "TXT", "DoH"))
    pfb_unbound.pfb_db_enqueue(("dnsbl", "Active", "AAAA", "TCP"))
    pfb_unbound.pfb_db_enqueue(("dnsbl", "Upstream", "HTTPS", "DoQ"))
    assert pfb_unbound.pfb_db_queue.qsize() == 3, "events must still be queued at removal"
    assert _details(database) == [("Active", "A", "UDP", 1), ("Removed", "A", "UDP", 1)]
    with sqlite3.connect(database) as connection:
        # Model the committed PHP boundary, including its retained disabled aggregate row.
        connection.execute("CREATE TABLE IF NOT EXISTS dns_metric_removed_groups (groupname TEXT PRIMARY KEY)")
        connection.execute("INSERT INTO dns_metric_removed_groups (groupname) VALUES ('Removed')")
        connection.execute("DELETE FROM dns_metric_blocks WHERE groupname = 'Removed'")
        connection.execute("UPDATE dnsbl SET timestamp = 'disabled', entries = 0 WHERE groupname = 'Removed'")
    assert _aggregates(database) == [("Active", 4), ("Removed", 8), ("Upstream", 0)]
    assert _details(database) == [("Active", "A", "UDP", 1)]
    _drain_worker()

    # Then legacy totals keep their old semantics, but no deleted detail is resurrected.
    assert _aggregates(database) == [("Active", 5), ("Removed", 9), ("Upstream", 1)]
    assert _details(database) == [
        ("Active", "A", "UDP", 1),
        ("Active", "AAAA", "TCP", 1),
        ("Upstream", "HTTPS", "DoQ", 1),
    ]
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT timestamp, entries FROM dnsbl WHERE groupname = 'Removed'").fetchall() == [
            ("disabled", 0)
        ]

    # A reopened worker connection must still respect the persisted removal.
    pfb_unbound._db_close(pfb_unbound.DB_DNSBL)
    assert pfb_unbound.pfb_db_validate(pfb_unbound.DB_DNSBL), "failed to reopen DNSBL database"
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT groupname FROM dns_metric_removed_groups").fetchall() == [("Removed",)]
    pfb_unbound.pfb_db_enqueue(("dnsbl", "Removed", "A", "UDP"))
    _drain_worker()
    assert _aggregates(database) == [("Active", 5), ("Removed", 10), ("Upstream", 1)]
    assert _details(database) == [
        ("Active", "A", "UDP", 1),
        ("Active", "AAAA", "TCP", 1),
        ("Upstream", "HTTPS", "DoQ", 1),
    ]

    # Explicit re-addition clears the tombstone without resetting legacy totals.
    with sqlite3.connect(database) as connection:
        connection.execute("DELETE FROM dns_metric_removed_groups WHERE groupname = 'Removed'")
        connection.execute("UPDATE dnsbl SET timestamp = '', entries = 1 WHERE groupname = 'Removed'")
    assert _aggregates(database) == [("Active", 5), ("Removed", 10), ("Upstream", 1)]
    pfb_unbound.pfb_db_enqueue(("dnsbl", "Removed", "A", "UDP"))
    _drain_worker()
    assert _aggregates(database) == [("Active", 5), ("Removed", 11), ("Upstream", 1)]
    assert _details(database) == [
        ("Active", "A", "UDP", 1),
        ("Active", "AAAA", "TCP", 1),
        ("Removed", "A", "UDP", 1),
        ("Upstream", "HTTPS", "DoQ", 1),
    ]
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT groupname FROM dns_metric_removed_groups").fetchall() == []
