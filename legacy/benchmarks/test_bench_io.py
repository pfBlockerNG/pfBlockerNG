"""I/O-pattern benchmark: per-call open/connect (pre-ADR-03) vs persistent + batched.

Run with:  python -m pip install -r benchmarks/requirements.txt
           python -m pytest benchmarks/test_bench_io.py
(Not collected by the default `pytest` run; testpaths is ["tests"].)

Self-contained: it reproduces the two I/O *patterns* rather than importing the
production module, so the benchmark of record stays stable as pfb_unbound evolves.
The comparison is deliberately the whole optimisation: the old path made N
connect()+CREATE+commit+close cycles (and N open/write/close for logs) where the
new path keeps one persistent handle and (for counters) collapses N increments
into a single relative UPDATE + commit. The companion CI tests
(tests/test_pfb_unbound.py::TestDbConcurrencyAndPerf) prove the connect-count and
WAL-coexistence properties deterministically; this just puts wall-clock on them.
"""

from __future__ import annotations

import sqlite3

N = 500  # writes per timed batch


def _make_db(path: str) -> None:
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE IF NOT EXISTS resolver (row integer, totalqueries integer, queries integer)")
    con.execute("INSERT INTO resolver (row, totalqueries, queries) VALUES (0, 0, 0)")
    con.commit()
    con.close()


# --- DB write pattern: per-call connect vs persistent + batched ------------- #


def test_db_per_call_connect(benchmark, tmp_path):
    db = str(tmp_path / "r.sqlite")
    _make_db(db)

    def run():
        for _ in range(N):
            con = sqlite3.connect(db, timeout=100)
            con.execute("CREATE TABLE IF NOT EXISTS resolver (row integer, totalqueries integer, queries integer)")
            con.execute("UPDATE resolver SET totalqueries = totalqueries + 1 WHERE row = 0")
            con.commit()
            con.close()

    benchmark(run)


def test_db_persistent_batched(benchmark, tmp_path):
    db = str(tmp_path / "r.sqlite")
    _make_db(db)
    con = sqlite3.connect(db, timeout=100, check_same_thread=False)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA synchronous=NORMAL")

    def run():
        con.execute("UPDATE resolver SET totalqueries = totalqueries + ? WHERE row = 0", (N,))
        con.commit()

    benchmark(run)
    con.close()


# --- Log write pattern: open-per-line vs persistent handle ------------------ #


def test_log_open_per_line(benchmark, tmp_path):
    log = str(tmp_path / "a.log")

    def run():
        for i in range(N):
            with open(log, "a") as fh:
                fh.write("line-%d\n" % i)

    benchmark(run)


def test_log_persistent_handle(benchmark, tmp_path):
    log = str(tmp_path / "b.log")
    fh = open(log, "a")

    def run():
        for i in range(N):
            fh.write("line-%d\n" % i)
        fh.flush()

    benchmark(run)
    fh.close()
