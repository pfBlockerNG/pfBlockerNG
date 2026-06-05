"""ADR-10 Phase 3 -- the fail-closed ``rebuild_and_swap()`` build -> atomic-swap step.

WHY THIS FILE EXISTS
--------------------
Phase 3 factors the build->install step into ONE reusable, fail-closed
``rebuild_and_swap(build_snapshot)`` that, ON SUCCESS only: atomically rebinds the
single ``_snapshot`` ref to a freshly-built Snapshot, clears the unified ``decisionDB``
query memo, resets the DNSBL Reports sqlite (through ``_db_lock``), and re-emits the UI
counts; ON FAILURE (the builder returns ``None`` or raises) keeps the OLD snapshot and
leaves BOTH caches intact (fail-closed). It is still called synchronously at init this
phase, so net init behaviour is unchanged; Phase 4's background watcher reuses it.

Following the repo test-coverage rules, every transition test asserts the BEFORE-state
first (the old snapshot is live, a decisionDB entry is present, a Reports row exists),
THEN flips (calls rebuild_and_swap), THEN asserts the AFTER-state -- so a green proves
the swap CAUSED the change rather than the end-state happening to hold already. Both
branches of the success/failure toggle are covered (success path AND each failure
shape -- None and raising builder).
"""

from __future__ import annotations

import re
import sqlite3
import threading
from typing import Any

import pfb_unbound as P

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _snapshot(*, data: dict[str, Any] | None = None, counts: int = 0, regex_count: int = 0) -> P.Snapshot:
    """A populated Snapshot with distinct identity + counts so the swap is observable."""
    return P.Snapshot(
        data_db=data if data is not None else {},
        zone_db={},
        white_db={},
        regex_db={},
        allow_regex_db={},
        feed_group_index_db={},
        hsts_db={},
        important_rules=False,
        counts=counts,
        regex_count=regex_count,
    )


def _seed_decision(name: str) -> P.Decision:
    """Put a STALE verdict on the live decisionDB (the unified LRU query memo)."""
    dec = P.Decision()
    dec.dnsbl = P.DnsblDecision(
        is_found=True,
        in_whitelist=False,
        in_hsts=False,
        null_blocking=False,
        nxdomain=False,
        log_type="1",
        b_type="DNSBL",
        p_type="DNSBL",
        feed="staleFeed",
        group="staleGroup",
        b_eval="data",
    )
    P.decisionDB[name] = dec
    return dec


def _seed_cache_row(db_path: str) -> None:
    """Write one row into the Reports cache via the real enqueue path (sync fallback,
    no worker running in tests) so the persistent _db_conns[DB_CACHE] connection holds
    the row the swap must clear."""
    P.pfb["pfb_py_cache"] = db_path
    P.pfb_db_enqueue(("cache", ("DNSBL", "stale.example.com", "G", "data", "feed")))


def _set_count_paths(tmp_path: Any) -> None:
    """init_standard sets these UI-count path keys; the autouse reset fixture does not,
    so a test exercising the count re-emit must set them itself."""
    P.pfb["pfb_py_count"] = str(tmp_path / "pfb_py_count")
    P.pfb["pfb_py_regex_count"] = str(tmp_path / "pfb_py_regex_count")


def _cache_rowcount() -> int:
    con = P._db_conns[P.DB_CACHE]
    return con.execute("SELECT COUNT(*) FROM dnsblcache").fetchone()[0]


class _CountingLock:
    """An instrument standing in for ``_db_lock`` -- records every acquisition so a test
    can PROVE the Reports-cache reset serializes through the db lock (no off-thread file
    touch / no race with the worker)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.acquired = 0

    def __enter__(self) -> Any:
        self.acquired += 1
        return self._lock.__enter__()

    def __exit__(self, *exc: Any) -> None:
        self._lock.__exit__(*exc)


# --------------------------------------------------------------------------- #
# Success path: rebind + clear decisionDB + reset Reports + recount
# --------------------------------------------------------------------------- #


class TestRebuildAndSwapSuccess:
    def test_swaps_ref_clears_decisiondb_resets_reports_recounts(self, tmp_path: Any, monkeypatch: Any) -> None:
        # ---- arrange: a live OLD snapshot + a STALE decisionDB entry + a Reports row.
        old = _snapshot(data={"old.example.com": {"log": "1", "index": 0, "important": False}}, counts=1)
        P._snapshot = old
        _seed_decision("stale.example.com")
        _seed_cache_row(str(tmp_path / "cache.sqlite"))
        _set_count_paths(tmp_path)

        emitted: dict[str, int] = {}
        monkeypatch.setattr(P, "dnsbl_emit_count", lambda path, count: emitted.update({path: count}) or True)

        # ---- BEFORE-state (must hold so a green proves the swap caused the change).
        assert P._snapshot is old
        assert "stale.example.com" in P.decisionDB
        assert P.decisionDB.get("stale.example.com") is not None
        assert _cache_rowcount() == 1

        new = _snapshot(
            data={"new.example.com": {"log": "1", "index": 0, "important": False}},
            counts=42,
            regex_count=7,
        )

        # ---- act: swap.
        result = P.rebuild_and_swap(lambda: new)

        # ---- AFTER-state.
        assert result is True
        # (a) the single ref now points at the NEW snapshot (atomic rebind).
        assert P._snapshot is new
        assert P._snapshot is not old
        # (b) the unified decisionDB query memo was CLEARED (stale verdict gone).
        assert "stale.example.com" not in P.decisionDB
        assert P.decisionDB.get("stale.example.com") is None
        assert len(P.decisionDB) == 0
        # (c) the Reports sqlite was reset (the stale row is gone).
        assert _cache_rowcount() == 0
        # (d) the UI counts were re-emitted from the NEW snapshot.
        assert emitted[P.pfb["pfb_py_count"]] == 42
        assert emitted[P.pfb["pfb_py_regex_count"]] == 7

    def test_swap_enables_master_dnsbl_gate_when_new_lists_load(self, tmp_path: Any, monkeypatch: Any) -> None:
        # ADR-10: operate() gates ALL DNSBL evaluation on pfb["python_blacklist"], which
        # is otherwise written only at init. A swap that loads lists into a previously-
        # empty/disabled module (e.g. a regex-ONLY feed when the last init had no lists)
        # MUST flip it True, or the newly-swapped lists never block (the live abp_regex
        # smoke failure: snap_regex=1 but pyblacklist=False -> the regex was skipped).
        # Cover BOTH branches (CLAUDE.md): a list-bearing swap enables it; an EMPTY swap
        # leaves it untouched (no spurious enable).
        _set_count_paths(tmp_path)
        monkeypatch.setattr(P, "dnsbl_emit_count", lambda *a, **k: True)

        # ---- regex-only NEW snapshot (no data/zone) over an empty live one.
        P._snapshot = _snapshot(counts=0)
        P.pfb["python_blacklist"] = False  # BEFORE: master gate OFF (last init had no lists)
        regex_only = P.Snapshot(
            data_db={},
            zone_db={},
            white_db={},
            regex_db={"feed#0": {"re": re.compile("badword"), "important": False, "band": 1}},
            allow_regex_db={},
            feed_group_index_db={},
            hsts_db={},
            important_rules=True,
            counts=0,
            regex_count=1,
        )
        assert P.pfb["python_blacklist"] is False
        assert P.rebuild_and_swap(lambda: regex_only) is True
        assert P.pfb["python_blacklist"] is True, "a regex-only swap must enable the master DNSBL gate"

        # ---- an EMPTY swap must NOT spuriously enable the gate (other-branch coverage).
        P._snapshot = regex_only
        P.pfb["python_blacklist"] = False
        empty = _snapshot(counts=0)
        assert P.pfb["python_blacklist"] is False
        assert P.rebuild_and_swap(lambda: empty) is True
        assert P.pfb["python_blacklist"] is False, "an empty swap must leave the master gate untouched"

    def test_reports_reset_serializes_through_db_lock(self, tmp_path: Any, monkeypatch: Any) -> None:
        # Prove the Reports-cache reset goes through _db_lock (no race with the worker /
        # no off-thread file touch): instrument the lock and assert the swap acquired it
        # while emptying the populated cache table.
        P._snapshot = _snapshot(counts=1)
        _seed_cache_row(str(tmp_path / "cache.sqlite"))
        _set_count_paths(tmp_path)
        monkeypatch.setattr(P, "dnsbl_emit_count", lambda *a, **k: True)

        instrumented = _CountingLock()
        monkeypatch.setattr(P, "_db_lock", instrumented)

        assert _cache_rowcount() == 1  # BEFORE: a row is present.
        before_acquired = instrumented.acquired

        assert P.rebuild_and_swap(lambda: _snapshot(counts=2)) is True

        assert instrumented.acquired > before_acquired  # the reset took the db lock.
        assert _cache_rowcount() == 0  # AFTER: the table was emptied under the lock.

    def test_db_reset_cache_empties_table_via_db_run(self, tmp_path: Any) -> None:
        # Unit-level: _db_reset_cache clears all rows through the persistent connection
        # (_db_run/_db_lock), and the table survives (schema kept -- next insert works).
        P.pfb["pfb_py_cache"] = str(tmp_path / "cache.sqlite")
        for d in ("a.com", "b.com"):
            P.pfb_db_enqueue(("cache", ("DNSBL", d, "G", "data", "feed")))
        assert _cache_rowcount() == 2  # BEFORE.

        assert P._db_reset_cache() is True

        assert _cache_rowcount() == 0  # AFTER: cleared.
        # The schema is intact -- a subsequent enqueue still inserts (DELETE, not DROP).
        P.pfb_db_enqueue(("cache", ("DNSBL", "c.com", "G", "data", "feed")))
        assert _cache_rowcount() == 1


# --------------------------------------------------------------------------- #
# Failure paths: keep the old snapshot AND both caches intact (fail-closed)
# --------------------------------------------------------------------------- #


class TestRebuildAndSwapFailClosed:
    def test_builder_returns_none_keeps_everything(self, tmp_path: Any, monkeypatch: Any) -> None:
        old = _snapshot(data={"old.example.com": {"log": "1", "index": 0, "important": False}}, counts=1)
        P._snapshot = old
        _seed_decision("stale.example.com")
        _seed_cache_row(str(tmp_path / "cache.sqlite"))

        emitted: dict[str, int] = {}
        monkeypatch.setattr(P, "dnsbl_emit_count", lambda path, count: emitted.update({path: count}) or True)

        # BEFORE: old snapshot live, stale memo present, Reports row present.
        assert P._snapshot is old
        assert "stale.example.com" in P.decisionDB
        assert _cache_rowcount() == 1

        # act: a None build (absent/unparseable manifest, build error).
        result = P.rebuild_and_swap(lambda: None)

        # AFTER (fail-closed): NOTHING changed.
        assert result is False
        assert P._snapshot is old  # old snapshot kept.
        assert "stale.example.com" in P.decisionDB  # STALE memo SURVIVES a failed build.
        assert P.decisionDB.get("stale.example.com") is not None
        assert _cache_rowcount() == 1  # Reports row SURVIVES.
        assert emitted == {}  # no recount on failure.

    def test_builder_raises_keeps_everything(self, tmp_path: Any, monkeypatch: Any) -> None:
        old = _snapshot(data={"old.example.com": {"log": "1", "index": 0, "important": False}}, counts=1)
        P._snapshot = old
        _seed_decision("stale.example.com")
        _seed_cache_row(str(tmp_path / "cache.sqlite"))

        emitted: dict[str, int] = {}
        monkeypatch.setattr(P, "dnsbl_emit_count", lambda path, count: emitted.update({path: count}) or True)

        def _boom() -> P.Snapshot:
            raise RuntimeError("build blew up")

        # BEFORE.
        assert P._snapshot is old
        assert "stale.example.com" in P.decisionDB
        assert _cache_rowcount() == 1

        # act: a raising build must be caught (no bare except leak) and fail-closed.
        result = P.rebuild_and_swap(_boom)

        # AFTER (fail-closed): identical to the None case -- nothing touched.
        assert result is False
        assert P._snapshot is old
        assert "stale.example.com" in P.decisionDB  # STALE memo SURVIVES a raising build.
        assert _cache_rowcount() == 1
        assert emitted == {}

    def test_failed_build_does_not_touch_db_lock(self, tmp_path: Any, monkeypatch: Any) -> None:
        # Fail-closed reaches NEITHER cache: the Reports reset (which takes _db_lock) must
        # NOT run on a None/raising build. Instrument the lock and assert zero acquires.
        P._snapshot = _snapshot(counts=1)
        _seed_cache_row(str(tmp_path / "cache.sqlite"))
        monkeypatch.setattr(P, "dnsbl_emit_count", lambda *a, **k: True)

        instrumented = _CountingLock()
        monkeypatch.setattr(P, "_db_lock", instrumented)
        baseline = instrumented.acquired

        assert P.rebuild_and_swap(lambda: None) is False
        assert instrumented.acquired == baseline  # no reset -> lock never taken.
        assert _cache_rowcount() == 1  # row still present.


# --------------------------------------------------------------------------- #
# emit_counts toggle (init opts out to stay byte-identical; Phase 4 default emits)
# --------------------------------------------------------------------------- #


class TestEmitCountsToggle:
    def test_emit_counts_false_skips_recount(self, tmp_path: Any, monkeypatch: Any) -> None:
        # init calls with emit_counts=False (keeps its own inline path-specific emits).
        P._snapshot = _snapshot(counts=1)
        _seed_cache_row(str(tmp_path / "cache.sqlite"))
        emitted: dict[str, int] = {}
        monkeypatch.setattr(P, "dnsbl_emit_count", lambda path, count: emitted.update({path: count}) or True)

        new = _snapshot(counts=99, regex_count=5)
        assert P.rebuild_and_swap(lambda: new, emit_counts=False) is True

        # The swap + cache reset still happened, but counts were NOT re-emitted.
        assert P._snapshot is new
        assert _cache_rowcount() == 0
        assert emitted == {}

    def test_emit_counts_true_recounts(self, tmp_path: Any, monkeypatch: Any) -> None:
        # Branch pair: with the default (Phase 4 caller) the counts ARE re-emitted.
        P._snapshot = _snapshot(counts=1)
        _seed_cache_row(str(tmp_path / "cache.sqlite"))
        _set_count_paths(tmp_path)
        emitted: dict[str, int] = {}
        monkeypatch.setattr(P, "dnsbl_emit_count", lambda path, count: emitted.update({path: count}) or True)

        new = _snapshot(counts=99, regex_count=5)
        assert P.rebuild_and_swap(lambda: new) is True
        assert emitted[P.pfb["pfb_py_count"]] == 99
        assert emitted[P.pfb["pfb_py_regex_count"]] == 5


# --------------------------------------------------------------------------- #
# Single-rebind invariant: rebuild_and_swap is the only place _snapshot is bound
# --------------------------------------------------------------------------- #


class TestSingleRebindPoint:
    def test_only_rebuild_and_swap_rebinds_snapshot(self) -> None:
        # Static guard: ``_snapshot = `` (a rebind) appears in the module source ONLY
        # inside rebuild_and_swap, never in init_standard or operate (operate reads
        # ``snap = _snapshot``; init now installs via rebuild_and_swap).
        import inspect

        src = inspect.getsource(P)
        rebind_lines = [
            ln.strip() for ln in src.splitlines() if ln.strip().startswith("_snapshot =") and "==" not in ln
        ]
        assert rebind_lines == ["_snapshot = new_snapshot"], rebind_lines


# --------------------------------------------------------------------------- #
# ADR-10 swap-visibility guard: operate()'s per-stratum presence gates + the
# important_rules fast-path flag MUST be derived from the captured snapshot (which
# a background swap replaces), NOT from the pfb[...] booleans (written only at
# init_standard and never refreshed by a swap). Reading them from pfb froze the
# gate at the last restart's state, so a zero-downtime swap that introduced a NEW
# stratum (feed/user regex, or data/zone when the prior init had none) left its gate
# False and evaluate_domain skipped it -- the newly-swapped block never applied (the
# live regex/important/custom-list smoke failures). Pinned at source level because
# operate() needs a full live qstate to exercise end-to-end (covered by the live smoke).
# --------------------------------------------------------------------------- #


class TestSwapGatesFromSnapshot:
    def test_operate_cfg_gates_read_snapshot_not_pfb(self) -> None:
        import inspect

        src = inspect.getsource(P.operate)
        # The cfg dict each query builds must source the list-presence gates + the
        # important_rules flag from ``snap`` (the swapped snapshot), not ``pfb``.
        for key, field in (
            ("dataDB", "snap.data_db"),
            ("zoneDB", "snap.zone_db"),
            ("regexDB", "snap.regex_db"),
            ("whiteDB", "snap.white_db"),
            ("allowRegexDB", "snap.allow_regex_db"),
            ("important_rules", "snap.important_rules"),
            ("hstsDB", "snap.hsts_db"),
        ):
            assert f'"{key}": bool({field})' in src, (
                f'operate() cfg["{key}"] must be derived from {field} (the swapped snapshot), '
                f"not from the stale pfb[...] flag"
            )
        # And must NOT regress to reading these gates back off pfb[...]. Strip comment
        # lines first (the rationale comment legitimately names the pfb[...] keys).
        code = "\n".join(ln for ln in src.splitlines() if not ln.lstrip().startswith("#"))
        for stale in (
            'pfb["dataDB"]',
            'pfb["zoneDB"]',
            'pfb["regexDB"]',
            'pfb["whiteDB"]',
            'pfb["allowRegexDB"]',
            'pfb["important_rules"]',
            'pfb["hstsDB"]',
        ):
            assert stale not in code, f"operate() must not read the stale {stale} gate (swap-invisible)"


# --------------------------------------------------------------------------- #
# Reports row survives a real round-trip read (sanity: the cache the UI reads)
# --------------------------------------------------------------------------- #


def test_reset_then_real_reader_sees_empty(tmp_path: Any, monkeypatch: Any) -> None:
    # The Reports tab opens the cache db read-only and reads dnsblcache. After a swap
    # reset, a fresh independent reader sees an empty table (the reset is durable on
    # the file, not just the cached connection).
    db_path = str(tmp_path / "cache.sqlite")
    P._snapshot = _snapshot(counts=1)
    _seed_cache_row(db_path)
    _set_count_paths(tmp_path)
    monkeypatch.setattr(P, "dnsbl_emit_count", lambda *a, **k: True)

    # BEFORE: an independent reader sees the row.
    reader = sqlite3.connect(db_path)
    assert reader.execute("SELECT COUNT(*) FROM dnsblcache").fetchone()[0] == 1

    assert P.rebuild_and_swap(lambda: _snapshot(counts=2)) is True

    # AFTER: the same independent reader (new query) sees an empty table.
    assert reader.execute("SELECT COUNT(*) FROM dnsblcache").fetchone()[0] == 0
    reader.close()
