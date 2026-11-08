"""Incarnation authority follows the served Snapshot, not the current group name."""

from __future__ import annotations

import json
import queue
import sqlite3
import subprocess
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from unboundmodule import MODULE_EVENT_NEW, MODULE_FINISHED

import pfb_unbound as P
from tests.test_pfb_unbound import make_qstate

ROOT = Path(__file__).resolve().parents[1]


def membership(path: Path, groups: list[str], *, disabled: bool = False) -> None:
    program = r"""
$args = $argv;
require $args[1] . '/tests/php/bootstrap.php';
$GLOBALS['pfb']['dnsbl_info'] = $args[2];
$GLOBALS['pfb']['sqlite_timeout'] = 2000;
$GLOBALS['pfb']['log'] = dirname($args[2]) . '/php.log';
$GLOBALS['pfb']['errlog'] = dirname($args[2]) . '/php.err';
$GLOBALS['pfb']['alias_dnsbl_configured'] = json_decode($args[3], true);
$GLOBALS['pfb']['alias_dnsbl_all'] = ['DNSBL_A', 'DNSBL_B'];
$GLOBALS['pfb']['dnsbl_info_stats'] = [
 ['groupname'=>'DNSBL_A', 'timestamp'=>'now', 'entries'=>$args[4] === 'yes' ? 'disabled' : 1],
 ['groupname'=>'DNSBL_B', 'timestamp'=>'now', 'entries'=>1]
];
if (!dnsbl_save_stats()) { exit(3); }
"""
    result = subprocess.run(
        ["php", "-r", program, str(ROOT), str(path), json.dumps(groups), "yes" if disabled else "no"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"PHP membership failed: {result.stdout}\n{result.stderr}"


def rows(path: Path, sql: str) -> list[tuple[Any, ...]]:
    with sqlite3.connect(path) as con:
        return con.execute(sql).fetchall()


def epochs(path: Path) -> dict[tuple[str, str], str]:
    return {
        (owner, origin): epoch
        for owner, origin, epoch in rows(path, "SELECT owner,origin,epoch FROM dnsbl_group_epochs")
    }


@pytest.fixture
def lifecycle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[Path, Path]]:
    dnsbl, resolver = tmp_path / "dnsbl.sqlite", tmp_path / "resolver.sqlite"
    P.pfb.update(
        pfb_py_dnsbl=str(dnsbl),
        pfb_py_resolver=str(resolver),
        sqlite3_dnsbl_con=True,
        sqlite3_resolver_con=True,
        db_worker=True,
        python_blocking=True,
        python_blacklist=True,
    )
    monkeypatch.setattr(P, "pfb_db_queue", queue.Queue(), raising=False)
    assert P.pfb_db_validate(P.DB_DNSBL)
    assert P.pfb_db_validate(P.DB_RESOLVER)
    membership(dnsbl, ["DNSBL_A", "DNSBL_B"])
    for name in ("A", "B"):
        (tmp_path / f"{name}.raw").write_text(f"{name.lower()}.example\n", encoding="utf-8")
    manifest = {
        "version": 1,
        "config": {},
        "feeds": [
            {"raw": f"{name}.raw", "feed": name, "group": f"DNSBL_{name}", "log_flag": "2", "provenance": "feed"}
            for name in ("A", "B")
        ],
    }
    source = tmp_path / "sources.json"
    source.write_text(json.dumps(manifest), encoding="utf-8")
    P.pfb.update(pfb_py_sources=str(source), **{"pfb_unbound.ini": str(tmp_path / "absent.ini")})
    yield dnsbl, resolver
    P.pfb["db_worker"] = False
    for db in (P.DB_DNSBL, P.DB_RESOLVER):
        P._db_close(db)


def publish() -> P.Snapshot:
    assert P.rebuild_and_swap(P._build_swap_snapshot, emit_counts=False)
    return P._snapshot


def block(name: str) -> None:
    state = make_qstate(f"{name}.example.", q_ip="192.0.2.10")
    state.qinfo.qtype_str = "A"
    state.pfb_transport = "DoH"
    assert P.operate(0, MODULE_EVENT_NEW, state, None)
    assert state.ext_state[0] == MODULE_FINISHED, f"{name} was not blocked: {state.ext_state}"


def drain() -> None:
    P.pfb_db_queue.put(("stop",))
    P.pfb_db_worker()
    assert P.pfb_db_queue.unfinished_tasks == 0


def test_migration_seeds_existing_groups_without_reset_and_never_resurrects(tmp_path: Path) -> None:
    path = tmp_path / "old.sqlite"
    P.pfb.update(pfb_py_dnsbl=str(path), sqlite3_dnsbl_con=True)
    with sqlite3.connect(path) as con:
        con.execute("CREATE TABLE dnsbl (groupname TEXT, timestamp TEXT, entries INTEGER, counter INTEGER)")
        con.execute("INSERT INTO dnsbl VALUES ('DNSBL_A', '', 2, 17)")
    try:
        assert P.pfb_db_validate(P.DB_DNSBL)
        tables = rows(path, "SELECT name FROM sqlite_master WHERE type='table'")
        assert ("dnsbl_group_epochs",) in tables, "migration must create persistent incarnation authority"
        before = epochs(path)
        assert len(before[("DNSBL_A", "custom")]) == 32 and len(before[("Upstream", "builtin")]) == 32
        assert rows(path, "SELECT counter FROM dnsbl WHERE groupname='DNSBL_A'") == [(17,)]
        membership(path, ["DNSBL_B"])
        P._db_close(P.DB_DNSBL)
        assert P.pfb_db_validate(P.DB_DNSBL)
        assert ("DNSBL_A", "custom") not in epochs(path)
        assert rows(path, "SELECT counter FROM dnsbl WHERE groupname='DNSBL_A'") == []
    finally:
        P._db_close(P.DB_DNSBL)


def test_inflight_old_snapshot_and_old_new_events_share_one_batch(
    lifecycle: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    dnsbl, resolver = lifecycle
    old = publish()
    assert getattr(old, "group_epochs", None) == epochs(dnsbl), "runtime Snapshot must capture the DB epochs"
    old_token = old.group_epochs[("DNSBL_A", "custom")]
    block("a")
    block("b")
    # Force a fresh evaluation after capturing old snap; hold exactly at the serve boundary.
    P.decisionDB.clear()
    entered, resume = threading.Event(), threading.Event()
    original = P.evaluate_domain
    failures: list[BaseException] = []

    def held(*args: Any, **kwargs: Any) -> Any:
        decision = original(*args, **kwargs)
        entered.set()
        assert resume.wait(10), "old serving query never resumed"
        return decision

    def query() -> None:
        try:
            block("a")
        except BaseException as error:
            failures.append(error)

    monkeypatch.setattr(P, "evaluate_domain", held)
    worker = threading.Thread(target=query)
    worker.start()
    try:
        assert entered.wait(10), "old query did not reach actual evaluation"
        membership(dnsbl, ["DNSBL_B"])
        membership(dnsbl, ["DNSBL_A", "DNSBL_B"])
        fresh = publish()
        assert fresh.group_epochs[("DNSBL_A", "custom")] != old_token
        monkeypatch.setattr(P, "evaluate_domain", original)
    finally:
        resume.set()
        worker.join(10)
    assert not worker.is_alive() and not failures, failures
    block("a")
    drain()
    assert rows(dnsbl, "SELECT groupname, counter FROM dnsbl WHERE groupname LIKE 'DNSBL_%' ORDER BY 1") == [
        ("DNSBL_A", 1),
        ("DNSBL_B", 1),
    ]
    assert rows(dnsbl, "SELECT groupname,qtype,transport,count FROM dns_metric_blocks ORDER BY 1") == [
        ("DNSBL_A", "A", "DoH", 1),
        ("DNSBL_B", "A", "DoH", 1),
    ]
    assert rows(resolver, "SELECT totalqueries FROM resolver") == [(4,)]
    assert rows(resolver, "SELECT qtype,transport,count FROM dns_metric_queries") == [("A", "DoH", 4)]


def test_query_channel_uses_original_snapshot_even_when_replaced_mid_evaluation(
    lifecycle: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    dnsbl, _ = lifecycle
    old = publish()
    token = epochs(dnsbl)[("DNSBL_A", "custom")]
    entered, resume = threading.Event(), threading.Event()
    original = P.evaluate_domain
    replies: list[dict[str, Any]] = []

    def held(*args: Any, **kwargs: Any) -> Any:
        decision = original(*args, **kwargs)
        entered.set()
        assert resume.wait(10)
        return decision

    monkeypatch.setattr(P, "evaluate_domain", held)
    worker = threading.Thread(target=lambda: replies.append(P.dnsbl_query_answer("a.example", "A")))
    worker.start()
    try:
        assert entered.wait(10)
        membership(dnsbl, ["DNSBL_B"])
        membership(dnsbl, ["DNSBL_A", "DNSBL_B"])
        fresh = publish()
        assert fresh is not old
    finally:
        resume.set()
        worker.join(10)
    assert not worker.is_alive()
    assert replies and replies[0].get("group_epoch") == token, replies
    monkeypatch.setattr(P, "evaluate_domain", original)
    assert P.dnsbl_query_answer("a.example", "A")["group_epoch"] == epochs(dnsbl)[("DNSBL_A", "custom")]
    assert P.dnsbl_query_answer("allowed.example", "A")["group_epoch"] == ""


def test_retry_rejects_deleted_incarnation_atomically_and_counts_new_once(
    lifecycle: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    dnsbl, _ = lifecycle
    snap = publish()
    token = epochs(dnsbl)[("DNSBL_A", "custom")]
    # Public accounting creates the retained task; failed real SQLite writes roll back both tables.
    block("a")
    task = P.pfb_db_queue.get_nowait()
    P.pfb_db_queue.task_done()
    assert task[0] == "resolver"
    task = P.pfb_db_queue.get_nowait()
    P.pfb_db_queue.task_done()
    assert task == ("dnsbl", "DNSBL_A", "DNSBL_A", "custom", token, "A", "DoH"), task
    with sqlite3.connect(dnsbl) as con:
        con.execute(
            "CREATE TRIGGER fail_detail BEFORE INSERT ON dns_metric_blocks "
            "BEGIN SELECT RAISE(ABORT, 'real lifecycle retry'); END"
        )
    monkeypatch.setattr(P.time, "sleep", lambda _: None)
    delta = {("DNSBL_A", "DNSBL_A", "custom", token): 1}
    detail = {("DNSBL_A", "DNSBL_A", "custom", token, "A", "DoH"): 1}
    assert not P._db_flush_dnsbl(delta, detail)
    assert rows(dnsbl, "SELECT counter FROM dnsbl WHERE groupname='DNSBL_A'") == [(0,)]
    assert rows(dnsbl, "SELECT * FROM dns_metric_blocks") == []
    membership(dnsbl, ["DNSBL_B"])
    membership(dnsbl, ["DNSBL_A", "DNSBL_B"])
    with sqlite3.connect(dnsbl) as con:
        con.execute("DROP TRIGGER fail_detail")
    assert P._db_flush_dnsbl(delta, detail)
    assert rows(dnsbl, "SELECT counter FROM dnsbl WHERE groupname='DNSBL_A'") == [(0,)]
    assert rows(dnsbl, "SELECT * FROM dns_metric_blocks") == []
    assert snap.group_epochs[("DNSBL_A", "custom")] == token
    publish()
    P.pfb["db_worker"] = False
    block("a")
    assert rows(dnsbl, "SELECT counter FROM dnsbl WHERE groupname='DNSBL_A'") == [(1,)]
    assert rows(dnsbl, "SELECT groupname,qtype,transport,count FROM dns_metric_blocks") == [("DNSBL_A", "A", "DoH", 1)]


def test_disable_reenable_and_restart_keep_epochs_and_counts(lifecycle: tuple[Path, Path]) -> None:
    dnsbl, _ = lifecycle
    first = publish()
    assert getattr(first, "group_epochs", None) == epochs(dnsbl), "runtime Snapshot must capture epochs"
    block("a")
    drain()
    before = epochs(dnsbl)
    membership(dnsbl, ["DNSBL_A", "DNSBL_B"], disabled=True)
    P.pfb["python_blacklist"] = False
    assert epochs(dnsbl) == before
    membership(dnsbl, ["DNSBL_A", "DNSBL_B"])
    P._db_close(P.DB_DNSBL)
    assert P.pfb_db_validate(P.DB_DNSBL)
    fresh = publish()
    assert fresh.group_epochs == before
    block("a")
    drain()
    assert rows(dnsbl, "SELECT counter FROM dnsbl WHERE groupname='DNSBL_A'") == [(2,)]
    assert rows(dnsbl, "SELECT groupname,qtype,transport,count FROM dns_metric_blocks") == [("DNSBL_A", "A", "DoH", 2)]


def test_epoch_read_failure_keeps_dns_available_without_accounting(
    lifecycle: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    dnsbl, _ = lifecycle
    old = publish()
    with sqlite3.connect(dnsbl) as con:
        con.execute("DROP TABLE dnsbl_group_epochs")
    assert P.rebuild_and_swap(P._build_swap_snapshot, emit_counts=False), (
        "optional accounting must not reject DNS filtering updates"
    )
    assert P._snapshot is not old
    assert P._snapshot.group_epochs == {}
    assert "DNSBL accounting unavailable" in capsys.readouterr().err
    before = rows(dnsbl, "SELECT groupname,counter FROM dnsbl ORDER BY groupname")
    block("a")
    drain()
    assert rows(dnsbl, "SELECT groupname,counter FROM dnsbl ORDER BY groupname") == before, (
        "a serving snapshot without authority must not invent or credit counter incarnations"
    )
