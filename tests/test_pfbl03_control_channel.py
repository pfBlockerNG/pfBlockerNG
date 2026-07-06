"""PFBL-03 -- the local privileged DNSBL-control command channel (reader + shared handler).

WHY THIS FILE EXISTS
--------------------
PFBL-03 moves DNSBL control off the DNS-TXT transport onto a local privileged command
FILE consumed by a daemon reader (``pfb_control_watcher``), mirroring the ADR-10 reload
watcher. The command SEMANTICS are preserved byte-for-byte; only the transport +
authentication change. These tests pin:

  * the SHARED handler ``pfb_apply_control_command`` -- the SINGLE implementation both the
    legacy DNS-TXT branch and the new reader call -- exercised independent of transport,
    every command + every validation branch (BEFORE/AFTER state asserted);
  * the reader's JSON record -> token translation + re-validation;
  * the reader thread: a FRESH seq is applied, a replayed/stale seq (<= last applied) is
    IGNORED, the pre-existing record at startup is adopted as the baseline (not replayed);
  * the applied-seq marker handshake the writer confirms execution with.

Per the repo coverage rules every transition test asserts the BEFORE state first, so a
green proves the command CAUSED the change. The reader runs on its own daemon thread; it
is gated on ``pfb["mod_threading"]`` and only a test that explicitly starts it runs it.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from typing import Any

import pytest

import pfb_unbound as P


def _await_control_thread_stopped(name: str, timeout: float = 2.0) -> None:
    """Wait (bounded) for a spawned control timer thread to stop.

    The duration commands start a real background timer thread; without awaiting it the
    async state leaks into later tests. Poll the module's own predicate until the thread
    is no longer active or the timeout elapses.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not P.python_control_thread(name):
            return
        time.sleep(0.01)


# --------------------------------------------------------------------------- #
# The shared handler -- exercised INDEPENDENT of transport (a plain token list).
# Both the DNS-TXT branch and the file reader build the SAME ["python_control", ...]
# list and call this; here we call it directly, proving it is transport-agnostic.
# --------------------------------------------------------------------------- #


class TestSharedHandlerDisableEnable:
    def test_disable_then_enable_toggles_blacklist(self) -> None:
        # Scenario: disable turns DNSBL blocking off; enable restores it.
        # Given: DNSBL blocking is ON (BEFORE).
        P.pfb["python_blacklist"] = True

        # When: a disable command (no duration) is applied.
        applied, msg = P.pfb_apply_control_command(["python_control", "disable"])

        # Then: it took effect and blocking is OFF.
        assert applied is True
        assert "disabled" in msg.lower()
        assert P.pfb["python_blacklist"] is False

        # When: an enable command is applied. Then: blocking is restored ON.
        applied, msg = P.pfb_apply_control_command(["python_control", "enable"])
        assert applied is True
        assert P.pfb["python_blacklist"] is True

    def test_disable_with_valid_duration_starts_sleep_thread(self) -> None:
        # Given: blocking ON, no live "sleep" thread.
        P.pfb["python_blacklist"] = True
        P.pfb["mod_threading"] = True

        # When: disable.<sec> with a valid duration.
        applied, msg = P.pfb_apply_control_command(["python_control", "disable", "1"])

        # Then: applied, blocking off, and a timed re-enable thread is running.
        assert applied is True
        assert P.pfb["python_blacklist"] is False
        assert "second" in msg
        assert P.python_control_thread("sleep") is True

        # Cleanup: await the spawned timer thread so its async state does not leak.
        _await_control_thread_stopped("sleep")

    def test_disable_with_out_of_range_duration_rejected(self) -> None:
        # The toggle still flips (semantics preserved) but the command is NOT marked
        # applied and no timer is started -- the duration is out of range (1-3600).
        P.pfb["python_blacklist"] = True
        applied, msg = P.pfb_apply_control_command(["python_control", "disable", "3601"])
        assert applied is False
        assert "out of range" in msg
        # The toggle still flipped (the legacy semantics: disable takes effect, only the
        # TIMED re-enable is refused for the bad duration).
        assert P.pfb["python_blacklist"] is False


class TestControlEnableOpensDnsblStatsDb:
    """Scenario: enabling DNSBL via the PFBL-03 control channel (or the timed re-enable)
    opens the dnsbl stats DB that init left closed at boot, so a subsequent counter flush
    lands.

    Background:
        init_standard opens ``sqlite3_dnsbl_con`` only when ``_dnsbl_stats_wanted()``
        (python_blacklist OR forwarding) holds AT INIT; a forwarding-off / no-feeds boot
        leaves it False. A later control-channel ``enable`` -- or the ``disable.<dur>``
        timed re-enable -- raises ``python_blacklist``, newly satisfying the predicate.
        Pre-fix neither control site re-opened the DB, so ``_db_flush_dnsbl`` (and
        ``_log_upstream_block``, both gated on ``sqlite3_dnsbl_con``) silently dropped
        every counter until a full restart -- the same silent-loss class #862 fixed for
        the ADR-10 swap path, reached via the control channel instead (issue #870).

    Each test asserts the BEFORE-state (DB closed, stats not wanted) first, so a green
    proves the enable CAUSED the open. Every input of the shared open guard is covered:
    the enable opens it, the timed re-enable opens it, mod_sqlite3=False keeps it closed,
    and an already-open DB is not reconnected.
    """

    def test_control_enable_opens_db_and_flush_lands_counter(self, tmp_path: Any) -> None:
        """A control-channel ``enable`` on a boot that left the stats DB closed opens it,
        and a counter flush then lands -- the exact effect the bug silently lost.

        RED pre-fix: the enable branch raised python_blacklist but left sqlite3_dnsbl_con
        False, so the ``assert ... sqlite3_dnsbl_con`` below fails.
        """
        # Given: a forwarding-off, no-feeds boot -> init left the stats DB closed.
        P.pfb["mod_sqlite3"] = True  # pin every guard input so "closed" is provably the predicate, not sqlite off
        P.pfb["pfb_py_dnsbl"] = str(tmp_path / "dnsbl.sqlite")
        P.pfb["python_blacklist"] = False
        P.pfb["forwarding"] = False
        assert not P.pfb["sqlite3_dnsbl_con"]
        assert not P._dnsbl_stats_wanted()

        # When: DNSBL is enabled over the control channel.
        applied, _ = P.pfb_apply_control_command(["python_control", "enable"])
        assert applied is True

        # Then: the gate flipped AND the stats DB is now open.
        assert P.pfb["python_blacklist"] is True
        assert P.pfb["sqlite3_dnsbl_con"], (
            "a control-channel enable that newly wants stats must open the dnsbl DB (issue #870)"
        )

        # And a counter flush actually lands now (pre-fix: guarded no-op).
        assert P._db_flush_dnsbl({"Upstream": 1})
        con = P._db_conns[P.DB_DNSBL]
        row = con.execute("SELECT counter FROM dnsbl WHERE groupname = 'Upstream'").fetchone()
        assert row == (1,), f"Upstream counter not incremented after enable opened the DB: {row!r}"

    def test_timed_reenable_opens_db(self, tmp_path: Any) -> None:
        """The other post-init control site: the ``disable.<dur>`` timed re-enable
        (python_control_sleep) also newly wants stats and must open the DB. Called with
        duration 0 so it returns immediately -- no real wait, no spawned thread.

        RED pre-fix: sqlite3_dnsbl_con stays False across the re-enable.
        """
        P.pfb["mod_sqlite3"] = True  # pin every guard input so "closed" is provably the predicate, not sqlite off
        P.pfb["pfb_py_dnsbl"] = str(tmp_path / "dnsbl.sqlite")
        P.pfb["python_blacklist"] = False
        P.pfb["forwarding"] = False
        assert not P.pfb["sqlite3_dnsbl_con"]

        # When: the timed re-enable fires (duration 0 -> returns immediately).
        assert P.python_control_sleep(0, None) is True

        # Then: blocking is back on AND the stats DB opened.
        assert P.pfb["python_blacklist"] is True
        assert P.pfb["sqlite3_dnsbl_con"], (
            "the timed re-enable that newly wants stats must open the dnsbl DB (issue #870)"
        )

    def test_control_enable_does_not_open_db_when_mod_sqlite3_unavailable(self, tmp_path: Any) -> None:
        """mod_sqlite3 conjunct: with the sqlite3 module unavailable, an enable that WOULD
        otherwise want stats must still NOT open the DB -- matching init's own gate.

        Failable guard: drop the ``mod_sqlite3 and`` conjunct and this fails -- sqlite3 is
        importable in the test env, so the open would succeed and sqlite3_dnsbl_con flip True.
        """
        P.pfb["mod_sqlite3"] = False  # sqlite3 module unavailable on this install
        P.pfb["pfb_py_dnsbl"] = str(tmp_path / "dnsbl.sqlite")
        P.pfb["python_blacklist"] = False
        P.pfb["forwarding"] = False
        assert not P.pfb["sqlite3_dnsbl_con"]

        applied, _ = P.pfb_apply_control_command(["python_control", "enable"])
        assert applied is True

        # The gate flips and stats ARE wanted, but mod_sqlite3=False keeps the DB closed.
        assert P.pfb["python_blacklist"] is True
        assert P._dnsbl_stats_wanted()
        assert not P.pfb["sqlite3_dnsbl_con"], "mod_sqlite3=False must gate the control-enable DB open"
        assert P.DB_DNSBL not in P._db_conns, "no connection may open when the sqlite3 module is unavailable"

    def test_control_enable_does_not_reopen_an_already_open_db(self, tmp_path: Any) -> None:
        """Idempotency: when the stats DB is already open (init opened it), an enable must
        NOT reconnect -- the not-sqlite3_dnsbl_con guard makes the open a no-op, preserving
        the existing connection and its accumulated counter."""
        P.pfb["mod_sqlite3"] = True  # pin every guard input so "closed" is provably the predicate, not sqlite off
        P.pfb["pfb_py_dnsbl"] = str(tmp_path / "dnsbl.sqlite")

        # Given: the DB is already open with an accumulated Upstream counter.
        P.pfb["python_blacklist"] = True
        P.pfb["sqlite3_dnsbl_con"] = True
        assert P._db_flush_dnsbl({"Upstream": 7})
        first_con = P._db_conns[P.DB_DNSBL]
        assert first_con.execute("SELECT counter FROM dnsbl WHERE groupname = 'Upstream'").fetchone() == (7,)

        # When: an enable is applied while the DB is already open.
        applied, _ = P.pfb_apply_control_command(["python_control", "enable"])
        assert applied is True

        # Then: same connection object (no reconnect), counter preserved.
        assert P.pfb["sqlite3_dnsbl_con"]
        assert P._db_conns[P.DB_DNSBL] is first_con, "an already-open stats DB must not be reconnected by enable"
        assert first_con.execute("SELECT counter FROM dnsbl WHERE groupname = 'Upstream'").fetchone() == (7,)

    def test_open_helper_survives_a_losing_race_on_corrupt_db_delete(self, tmp_path: Any, monkeypatch: Any) -> None:
        """Concurrency guard: the shared open helper now runs from three threads (the
        ADR-10 swap, the control-channel enable, the timed re-enable). Two racing to
        recover the SAME corrupt stats DB can both fail ``_validate_db_with_recovery``'s
        first validate, so the loser's ``os.remove()`` hits an already-deleted file. That
        FileNotFoundError must NOT escape the helper -- from the un-wrapped enable call
        site it would propagate out of ``pfb_apply_control_command``, kill
        ``pfb_control_watcher``'s thread, and silently disable the control channel until
        Unbound restarts (issue #870).

        Issue #900: ``pfb_db_validate`` -> ``_db_run`` swallows every fault internally and
        never raises in production, so (unlike the test this replaces) it is NOT
        monkeypatched here -- a genuinely corrupt file on disk drives its first, real
        False. Only ``os.remove`` -- the boundary the guard actually protects -- is
        monkeypatched, to simulate the losing race (another thread got there first).
        """
        monkeypatch.setattr(P.time, "sleep", lambda *_a, **_k: None)  # skip _db_run's real retry backoff
        db = tmp_path / "dnsbl.sqlite"
        db.write_text("corrupt")  # genuinely invalid sqlite file -> validate() really fails
        P.pfb["mod_sqlite3"] = True
        P.pfb["pfb_py_dnsbl"] = str(db)
        P.pfb["python_blacklist"] = True  # stats wanted -> the open path runs
        P.pfb["sqlite3_dnsbl_con"] = False

        def _already_removed(_path: str) -> None:
            raise FileNotFoundError(_path)

        monkeypatch.setattr(P.os, "remove", _already_removed)

        # Must not raise, even though the delete step lost the race.
        P._open_dnsbl_stats_db_if_wanted()

        # os.remove was faked (not a real delete), so the corrupt bytes are still on disk --
        # the revalidate genuinely fails too, so the DB stays closed. The point of this test
        # is the FIRST assertion (no exception escaped), not this one.
        assert P.pfb["sqlite3_dnsbl_con"] is False


class TestCorruptDnsblStatsDbRecovery:
    """Issue #900: a genuinely corrupt ``pfb_py_dnsbl.sqlite`` on disk (e.g. after a power
    loss) is recovered by the shared open helper -- deleted and rebuilt -- instead of
    silently leaving the stats DB closed forever.

    Background: ``pfb_db_validate`` -> ``_db_run`` swallows every connect/PRAGMA fault
    internally and returns ``False``; it never raises. The old ``except Exception``
    recovery around ``pfb_db_validate`` in both the helper and ``init_standard`` was
    therefore dead code -- a corrupt file was never deleted, every DNSBL counter was
    silently dropped forever, and each swap/enable re-paid a ~1.5s stall inside
    ``_db_lock`` for nothing. ``_validate_db_with_recovery`` (shared by both call sites)
    fixes this: a ``False`` validate is treated as the corrupt case (delete + one
    revalidate).

    Each test monkeypatches ``time.sleep`` to a no-op -- ``_db_run``'s internal retry
    backoff is real production behaviour being exercised here, not test/production
    concurrency to coordinate, so there is nothing to actually wait for.
    """

    def test_corrupt_db_is_deleted_rebuilt_and_flush_lands(self, tmp_path: Any, monkeypatch: Any) -> None:
        """Positive branch: recovery deletes the corrupt file, the retry connects, the
        flag goes True, and a counter flush lands.

        RED pre-fix (confirmed by stashing this fix and re-running): the corrupt file
        was NOT deleted (still on disk after the call) and
        ``assert P.pfb["sqlite3_dnsbl_con"] is True`` failed -- actual: ``False`` --
        because the recovery lived in a dead ``except`` branch ``pfb_db_validate``
        never raises into.
        """
        monkeypatch.setattr(P.time, "sleep", lambda *_a, **_k: None)
        db = tmp_path / "dnsbl.sqlite"
        db.write_bytes(b"not a sqlite database")  # garbage bytes -> genuinely corrupt
        # Stale WAL/SHM sidecars beside the corrupt main file (the DBs run
        # journal_mode=WAL): recovery must sweep these too, or they linger next
        # to the freshly recreated main file (#900 review).
        wal = tmp_path / "dnsbl.sqlite-wal"
        shm = tmp_path / "dnsbl.sqlite-shm"
        wal.write_bytes(b"stale wal")
        shm.write_bytes(b"stale shm")
        P.pfb["mod_sqlite3"] = True
        P.pfb["pfb_py_dnsbl"] = str(db)
        P.pfb["python_blacklist"] = True  # stats wanted -> the open path runs
        P.pfb["sqlite3_dnsbl_con"] = False

        # ---- BEFORE: the corrupt file genuinely fails validation and the flag is off.
        assert P.pfb_db_validate(P.DB_DNSBL) is False
        assert db.exists(), "a failed validate alone must not touch the file"
        assert P.pfb["sqlite3_dnsbl_con"] is False

        # ---- act: drive the shared helper (the swap / control-enable / timed-re-enable
        # entry point -- see _open_dnsbl_stats_db_if_wanted's docstring for its callers).
        P._open_dnsbl_stats_db_if_wanted()

        # ---- AFTER: the corrupt file was deleted+rebuilt, the retry connected, flag True.
        assert P.pfb["sqlite3_dnsbl_con"] is True, "recovery must delete + revalidate a corrupt DB (issue #900)"
        assert P.DB_DNSBL in P._db_conns
        # Pinned invariant (behaviour-preserving, not red->green): the planted
        # stale sidecar bytes never survive recovery. sqlite itself resets a
        # salt-mismatched WAL pair on the fresh connect, and recovery now also
        # sweeps them explicitly (#900 review) so the guarantee does not hinge
        # on sqlite version behaviour. A fresh WAL pair for the recreated DB
        # may exist -- only the planted bytes must be gone.
        assert not wal.exists() or wal.read_bytes() != b"stale wal", (
            f"stale -wal sidecar survived recovery: {wal.read_bytes()[:20]!r}"
        )
        assert not shm.exists() or shm.read_bytes() != b"stale shm", (
            f"stale -shm sidecar survived recovery: {shm.read_bytes()[:20]!r}"
        )

        # ---- and a counter flush actually lands on the recovered DB.
        assert P._db_flush_dnsbl({"Upstream": 1})
        con = P._db_conns[P.DB_DNSBL]
        row = con.execute("SELECT counter FROM dnsbl WHERE groupname = 'Upstream'").fetchone()
        assert row == (1,), f"Upstream counter not incremented after corrupt-DB recovery: {row!r}"

    def test_recovery_delete_failure_leaves_flag_false_with_no_crash(self, tmp_path: Any, monkeypatch: Any) -> None:
        """Negative branch: when the recovery's own delete step itself fails (an
        unremovable path), the helper must not crash -- it just leaves the stats DB
        closed, no infinite retry, no uncaught exception.

        Simulated by pointing ``pfb_py_dnsbl`` at a directory: sqlite3 can never open a
        directory as a database (so validate() genuinely, always fails) and
        ``os.remove()`` on a directory always fails too (``IsADirectoryError`` on Linux,
        ``PermissionError`` on macOS) -- exercising the guard's ``except OSError``
        without depending on a real file-permission model.
        """
        monkeypatch.setattr(P.time, "sleep", lambda *_a, **_k: None)
        P.pfb["mod_sqlite3"] = True
        P.pfb["pfb_py_dnsbl"] = str(tmp_path)  # a directory, never a valid sqlite file
        P.pfb["python_blacklist"] = True
        P.pfb["sqlite3_dnsbl_con"] = False

        # Must not raise.
        P._open_dnsbl_stats_db_if_wanted()

        assert P.pfb["sqlite3_dnsbl_con"] is False
        assert tmp_path.exists(), "the unremovable path (a directory) must survive the failed delete"

    def test_racing_second_recovery_cannot_delete_the_winners_rebuilt_db(self, tmp_path: Any, monkeypatch: Any) -> None:
        """Concurrency: two threads recovering the SAME corrupt stats DB must not
        interleave -- without serialization, both validate False, the winner deletes +
        rebuilds the file, and the LOSER's delete then unlinks the winner's freshly
        rebuilt LIVE file while the cached connection in ``_db_conns`` keeps writing to
        the unlinked inode: every counter silently lost, the exact class #900 fixes.
        ``_db_recovery_lock`` makes validate -> remove -> revalidate atomic; the loser's
        first validate inside the lock doubles as its recheck (succeeds via the winner's
        cached connection, no second delete).

        Deterministic choreography (no sleeps; every wait carries a loud-timeout assert):
        T1's ``os.remove`` parks on an Event between its validate-False and its delete --
        the exact window the lock must close. T2 then enters the helper: WITH the lock it
        blocks at the (instrumented) recovery lock, signalling ``t2_progressed`` on the
        contended acquire; WITHOUT the lock it runs straight through the parked T1's
        window (validate False -> second delete -> rebuild) and signals ``t2_progressed``
        on return. Either way main can then release T1 and join both -- no branch waits
        on wall-clock time. The instrumented lock is a behaviourally identical stand-in
        installed with ``raising=False`` so the same test runs against pre-fix code
        (where the attribute does not exist and is simply never consulted).

        RED pre-fix (confirmed by stashing the lock and re-running): both threads
        performed a delete -- ``assert len(remove_calls) == 1`` failed with 2 calls,
        T2's second delete having unlinked the winner's rebuilt live DB.
        """
        monkeypatch.setattr(P.time, "sleep", lambda *_a, **_k: None)
        db = tmp_path / "dnsbl.sqlite"
        db.write_bytes(b"not a sqlite database")  # garbage bytes -> genuinely corrupt
        P.pfb["mod_sqlite3"] = True
        P.pfb["pfb_py_dnsbl"] = str(db)
        P.pfb["python_blacklist"] = True  # stats wanted -> the open path runs
        P.pfb["sqlite3_dnsbl_con"] = False

        t1_parked = threading.Event()  # T1 is inside its recovery delete
        release_t1 = threading.Event()  # main lets T1's delete proceed
        t2_progressed = threading.Event()  # T2 blocked on the lock OR completed
        errors: list[BaseException] = []

        real_remove = P.os.remove
        remove_calls: list[str] = []

        def choreographed_remove(path: str) -> None:
            remove_calls.append(path)
            if len(remove_calls) == 1:  # T1: park in the validate->delete window
                t1_parked.set()
                assert release_t1.wait(5), "loud timeout: T1 was never released from its parked delete"
            real_remove(path)

        class _SignallingLock:
            """Same mutual exclusion as the real recovery lock, plus a signal on a
            contended acquire so main knows (deterministically) that T2 is waiting."""

            def __init__(self) -> None:
                self._lock = threading.Lock()

            def __enter__(self) -> None:
                if not self._lock.acquire(blocking=False):
                    t2_progressed.set()  # contended: the loser is waiting on the winner
                    self._lock.acquire()

            def __exit__(self, *_exc: object) -> None:
                self._lock.release()

        monkeypatch.setattr(P.os, "remove", choreographed_remove)
        monkeypatch.setattr(P, "_db_recovery_lock", _SignallingLock(), raising=False)

        def t1_run() -> None:
            try:
                P._open_dnsbl_stats_db_if_wanted()
            except BaseException as e:  # noqa: BLE001 -- surface thread faults in main
                errors.append(e)

        def t2_run() -> None:
            try:
                P._open_dnsbl_stats_db_if_wanted()
            except BaseException as e:  # noqa: BLE001 -- surface thread faults in main
                errors.append(e)
            finally:
                t2_progressed.set()  # pre-fix path: T2 ran straight through and returned

        t1 = threading.Thread(target=t1_run, daemon=True)
        t1.start()
        assert t1_parked.wait(5), "loud timeout: T1 never reached its recovery delete"

        t2 = threading.Thread(target=t2_run, daemon=True)
        t2.start()
        assert t2_progressed.wait(5), "loud timeout: T2 neither blocked on the recovery lock nor completed"

        release_t1.set()
        t1.join(5)
        t2.join(5)
        assert not t1.is_alive() and not t2.is_alive(), "loud timeout: recovery threads did not finish"
        assert not errors, f"a recovery thread raised: {errors!r}"

        # Then: exactly ONE recovery ran -- the loser revalidated instead of deleting
        # the winner's rebuilt DB. Recovery sweeps the WAL/SHM sidecars alongside the
        # main file (#900 review), so count MAIN-file removes: one recovery = one.
        main_removes = [c for c in remove_calls if c == str(db)]
        assert len(main_removes) == 1, (
            f"racing recovery must delete the corrupt DB exactly once, got {len(main_removes)}: {remove_calls!r}"
        )
        assert P.pfb["sqlite3_dnsbl_con"] is True

        # And: a flush lands AND is visible through a FRESH connection to the on-disk
        # path -- proving the cached connection's file IS the live on-disk file, not an
        # unlinked-inode ghost.
        assert P._db_flush_dnsbl({"Upstream": 1})
        fresh = sqlite3.connect(str(db))
        try:
            row = fresh.execute("SELECT counter FROM dnsbl WHERE groupname = 'Upstream'").fetchone()
        finally:
            fresh.close()
        assert row == (1,), f"flush not visible via a fresh connection to the on-disk DB (ghost inode?): {row!r}"


class TestSharedHandlerBypass:
    def test_addbypass_adds_ip_to_gplistdb(self) -> None:
        # Given: the IP is NOT in the bypass DB (BEFORE).
        assert P.gpListDB.get("192.0.2.10") is None

        # When: addbypass without a duration.
        applied, msg = P.pfb_apply_control_command(["python_control", "addbypass", "192.0.2.10"])

        # Then: applied and the IP is now a bypass entry.
        assert applied is True
        assert P.gpListDB.get("192.0.2.10") == 0
        assert P.pfb["gpListDB"] is True

    def test_removebypass_removes_ip(self) -> None:
        # Given: the IP IS a bypass entry (BEFORE).
        P.gpListDB["192.0.2.10"] = 0
        P.pfb["gpListDB"] = True
        assert P.gpListDB.get("192.0.2.10") == 0

        # When: removebypass. Then: the IP is gone.
        applied, msg = P.pfb_apply_control_command(["python_control", "removebypass", "192.0.2.10"])
        assert applied is True
        assert P.gpListDB.get("192.0.2.10") is None

    def test_removebypass_absent_ip_reports_not_in_policy(self) -> None:
        # An IP not in the DB still validates (applied True) but the message says so.
        assert P.gpListDB.get("198.51.100.7") is None
        applied, msg = P.pfb_apply_control_command(["python_control", "removebypass", "198.51.100.7"])
        assert applied is True
        assert "not in Group Policy" in msg

    def test_addbypass_with_duration_starts_remove_thread(self) -> None:
        P.pfb["mod_threading"] = True
        applied, msg = P.pfb_apply_control_command(["python_control", "addbypass", "192.0.2.10", "1"])
        assert applied is True
        assert "second" in msg
        assert P.python_control_thread("addbypass192.0.2.10") is True

        # Cleanup: await the spawned timer thread so its async state does not leak.
        _await_control_thread_stopped("addbypass192.0.2.10")

    def test_addbypass_with_duration_adds_ip_then_expires(self) -> None:
        # Scenario: a timed addbypass must insert the IP into the bypass set immediately
        # (so DNSBL is bypassed for the duration), then the expiry thread removes it.
        # Background: the no-duration path inserts synchronously; the timed path must too.

        # Given: the IP is NOT in the bypass DB before the command (BEFORE state).
        assert P.gpListDB.get("198.51.100.20") is None

        # When: addbypass with a 1-second duration is applied.
        P.pfb["mod_threading"] = True
        applied, msg = P.pfb_apply_control_command(["python_control", "addbypass", "198.51.100.20", "1"])

        # Then (insert): the command succeeds and the IP is in the bypass set immediately --
        # before the expiry thread's sleep elapses. This assertion fails on pre-fix code.
        assert applied is True
        assert "second" in msg
        assert P.gpListDB.get("198.51.100.20") == 0
        assert P.pfb["gpListDB"] is True

        # Then (expiry): once the timer thread finishes, the IP is removed.
        _await_control_thread_stopped("addbypass198.51.100.20")
        assert P.gpListDB.get("198.51.100.20") is None

    def test_addbypass_dash_encoded_ipv4_is_unmapped(self) -> None:
        # The DNS-TXT transport encodes the dotted IPv4 with '-'; the shared handler
        # un-maps it. Proves the legacy encoding still resolves to the real IP.
        applied, _ = P.pfb_apply_control_command(["python_control", "addbypass", "192-0-2-10"])
        assert applied is True
        assert P.gpListDB.get("192.0.2.10") == 0

    def test_malformed_bypass_rejected_without_raising(self) -> None:
        # PFBL-03: a malformed bypass command must be REJECTED (returned), never RAISED --
        # a missing IP (IndexError) or a non-IP (ValueError) would otherwise crash the
        # control watcher thread. Both classes return (False, <message>) and leave the
        # bypass DB untouched.
        # Given: the would-be IP is NOT in the bypass DB (BEFORE).
        assert P.gpListDB.get("not-an-ip") is None

        # When: a 2-token command (missing IP) is applied. Then: rejected, no raise.
        applied, msg = P.pfb_apply_control_command(["python_control", "addbypass"])
        assert applied is False
        assert "Missing bypass IP" in msg

        # When: a command with a non-IP token is applied. Then: rejected, no raise.
        applied, msg = P.pfb_apply_control_command(["python_control", "addbypass", "not-an-ip"])
        assert applied is False
        assert "Invalid IP" in msg

        # Then: neither malformed command mutated the bypass DB.
        assert P.gpListDB.get("not-an-ip") is None

    def test_unknown_command_is_noop(self) -> None:
        applied, msg = P.pfb_apply_control_command(["python_control", "frobnicate"])
        assert applied is False
        assert msg == ""

    def test_too_short_token_list_is_noop(self) -> None:
        applied, msg = P.pfb_apply_control_command(["python_control"])
        assert applied is False
        assert msg == ""


# --------------------------------------------------------------------------- #
# Record reader + record->token translation (the reader's plumbing).
# --------------------------------------------------------------------------- #


class TestControlReadRecord:
    def test_absent_file_is_none(self, tmp_path: Any) -> None:
        assert P._control_read_record(str(tmp_path / "nope")) is None

    def test_empty_file_is_none(self, tmp_path: Any) -> None:
        p = tmp_path / "ctl"
        p.write_text("")
        assert P._control_read_record(str(p)) is None

    def test_malformed_json_is_none(self, tmp_path: Any) -> None:
        p = tmp_path / "ctl"
        p.write_text("not json {")
        assert P._control_read_record(str(p)) is None

    def test_non_object_json_is_none(self, tmp_path: Any) -> None:
        p = tmp_path / "ctl"
        p.write_text("[1, 2, 3]")
        assert P._control_read_record(str(p)) is None

    def test_valid_record_parsed(self, tmp_path: Any) -> None:
        p = tmp_path / "ctl"
        p.write_text('{"seq": 3, "cmd": "enable"}\n')
        rec = P._control_read_record(str(p))
        assert rec == {"seq": 3, "cmd": "enable"}


class TestRecordToCommand:
    def test_enable(self) -> None:
        assert P._control_record_to_command({"cmd": "enable"}) == ["python_control", "enable"]

    def test_disable_without_duration(self) -> None:
        assert P._control_record_to_command({"cmd": "disable"}) == ["python_control", "disable"]

    def test_disable_with_duration(self) -> None:
        assert P._control_record_to_command({"cmd": "disable", "duration": 60}) == [
            "python_control",
            "disable",
            "60",
        ]

    def test_addbypass_with_ip_and_duration(self) -> None:
        assert P._control_record_to_command({"cmd": "addbypass", "ip": "192.0.2.10", "duration": 30}) == [
            "python_control",
            "addbypass",
            "192.0.2.10",
            "30",
        ]

    def test_removebypass_with_ip(self) -> None:
        assert P._control_record_to_command({"cmd": "removebypass", "ip": "192.0.2.10"}) == [
            "python_control",
            "removebypass",
            "192.0.2.10",
        ]

    def test_unknown_cmd_is_none(self) -> None:
        assert P._control_record_to_command({"cmd": "wipe"}) is None

    def test_missing_cmd_is_none(self) -> None:
        assert P._control_record_to_command({"seq": 1}) is None

    def test_bypass_without_ip_is_none(self) -> None:
        assert P._control_record_to_command({"cmd": "addbypass"}) is None
        assert P._control_record_to_command({"cmd": "addbypass", "ip": ""}) is None


class TestControlWriteApplied:
    def test_writes_seq_first_line(self, tmp_path: Any) -> None:
        applied = str(tmp_path / "pfb_py_control.applied")
        P.pfb["pfb_py_control_applied"] = applied
        P._control_write_applied(7)
        with open(applied, encoding="utf-8") as fh:
            assert fh.readline().strip() == "7"


# --------------------------------------------------------------------------- #
# The reader thread -- drive a real daemon with a temp channel; assert the FRESH
# command applies, a replayed/stale seq is ignored, the baseline is not replayed.
# --------------------------------------------------------------------------- #


class _ControlHarness:
    """Run pfb_control_watcher on a real daemon thread against a temp channel file.
    Mirrors init's start + deinit's stop/join."""

    def __init__(self, tmp_path: Any, monkeypatch: Any) -> None:
        self.channel = str(tmp_path / "pfb_py_control")
        self.applied = str(tmp_path / "pfb_py_control.applied")
        P.pfb["pfb_py_control"] = self.channel
        P.pfb["pfb_py_control_applied"] = self.applied
        # Short cadence so the poll/kqueue timeout (hence stop + apply) is prompt.
        monkeypatch.setattr(P, "RELOAD_POLL_INTERVAL", 0.05)
        P.pfb_control_stop = threading.Event()
        self.thread: Any = None

    def publish(self, record: dict[str, Any]) -> None:
        import json
        import os

        tmp = self.channel + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
        os.replace(tmp, self.channel)

    def read_applied(self) -> int | None:
        try:
            with open(self.applied, encoding="utf-8") as fh:
                return int(fh.readline().strip())
        except (OSError, ValueError):
            return None

    def start(self) -> None:
        self.thread = threading.Thread(name="pfb_control_watcher_test", target=P.pfb_control_watcher, daemon=True)
        self.thread.start()

    def wait_started(self, timeout: float = 5.0) -> bool:
        """Wait until the watcher has written its startup baseline to the applied file.

        The watcher writes its baseline applied marker (seq 0, or the seq of any
        pre-existing channel record) at startup -- before entering its poll loop.
        Commands published before this baseline is written may be treated as
        pre-existing records (adopted without being applied) rather than fresh
        commands to execute.  Always call this after ``start()`` and before the
        first ``publish()`` to guarantee correct ordering under CPU contention."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.read_applied() is not None:
                return True
            time.sleep(0.005)
        return False

    def wait_applied(self, seq: int, timeout: float = 3.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if (self.read_applied() or -1) >= seq:
                return True
            time.sleep(0.01)
        return False

    def stop_join(self) -> bool:
        """Signal the watcher to stop and wait until it dies.

        Loops in 0.5-second slices for up to 10 seconds so that CPU contention
        does not cause a single long join to return prematurely.  Returns True
        when the thread has fully exited, False when it outlived the budget."""
        P.pfb_control_stop.set()
        if self.thread is None:
            return True
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            self.thread.join(timeout=0.5)
            if not self.thread.is_alive():
                return True
        return False


# Sentinel used in the snapshot below to distinguish "key absent" from "key = None"
# so the restore step can faithfully delete keys that were not present.
_ABSENT: object = object()


@pytest.fixture
def control_harness(tmp_path: Any, monkeypatch: Any) -> Any:
    """Isolated, guaranteed-teardown fixture for TestControlWatcherLoop.

    Setup:
      - Refuses to proceed if a prior ``pfb_control_watcher_test`` thread is still
        alive (converts any upstream leak into a loud, deterministic failure).
      - Snapshots the shared module-globals that the harness + tests mutate so
        teardown can restore them faithfully regardless of test outcome.
      - Constructs a ``_ControlHarness`` against ``tmp_path`` and yields it.

    Teardown (ALWAYS runs, even when the test body raises):
      - Calls the hardened ``stop_join`` and asserts the watcher thread is dead,
        so a slow thread under CPU contention cannot bleed into the next test.
      - Re-scans ``threading.enumerate()`` to confirm no leaked watcher survives.
      - Restores every snapshotted global to its pre-test value.
    """
    # Guard: refuse to start if a prior test's watcher is still alive.
    live_before = [t for t in threading.enumerate() if t.name == "pfb_control_watcher_test"]
    assert not live_before, (
        "control_harness setup: a pfb_control_watcher_test thread from a PREVIOUS test "
        f"is still alive: {live_before!r}.  A prior test leaked its watcher."
    )

    # Snapshot the module-globals this fixture (via _ControlHarness) and the tests mutate.
    # Use _ABSENT so we can distinguish "was not set" from "was set to None".
    _pfb_keys = ("pfb_py_control", "pfb_py_control_applied", "python_blacklist")
    snapshot_pfb: dict[str, Any] = {k: P.pfb.get(k, _ABSENT) for k in _pfb_keys}
    snapshot_gp_list_db: dict[Any, Any] = dict(P.gpListDB)
    snapshot_control_stop: Any = getattr(P, "pfb_control_stop", _ABSENT)
    snapshot_control_thread: Any = getattr(P, "pfb_control_watcher_thread", _ABSENT)

    h = _ControlHarness(tmp_path, monkeypatch)
    try:
        yield h
    finally:
        # Guaranteed teardown. Collect invariant failures rather than asserting
        # inline so a failed check can never skip the global restoration below --
        # restore ALWAYS runs (inner finally), then we surface any failures.
        teardown_errors: list[str] = []
        try:
            # Stop the watcher and confirm it is dead.
            died = h.stop_join()
            if not died:
                teardown_errors.append(
                    f"control_harness teardown: watcher thread '{h.thread!r}' did not exit "
                    "within 10 s — the watcher is still alive after stop_join."
                )
            elif h.thread is not None and h.thread.is_alive():
                teardown_errors.append(
                    f"control_harness teardown: thread {h.thread!r} is still alive after stop_join reported death."
                )

            # Confirm no pfb_control_watcher_test thread survives in the process.
            live_after = [t for t in threading.enumerate() if t.name == "pfb_control_watcher_test"]
            if live_after:
                teardown_errors.append(
                    f"control_harness teardown: leaked watcher thread(s) still alive: {live_after!r}"
                )
        finally:
            # Restore snapshotted pfb keys.
            for k, v in snapshot_pfb.items():
                if v is _ABSENT:
                    P.pfb.pop(k, None)
                else:
                    P.pfb[k] = v

            # Restore gpListDB in place (callers hold a reference to this dict).
            P.gpListDB.clear()
            P.gpListDB.update(snapshot_gp_list_db)

            # Restore pfb_control_stop and pfb_control_watcher_thread.
            if snapshot_control_stop is _ABSENT:
                try:
                    del P.pfb_control_stop  # type: ignore[attr-defined]
                except AttributeError:
                    pass
            else:
                P.pfb_control_stop = snapshot_control_stop

            if snapshot_control_thread is _ABSENT:
                try:
                    del P.pfb_control_watcher_thread  # type: ignore[attr-defined]
                except AttributeError:
                    pass
            else:
                P.pfb_control_watcher_thread = snapshot_control_thread

        assert not teardown_errors, "\n".join(teardown_errors)


class TestControlWatcherLoop:
    def test_fresh_command_is_applied(self, control_harness: _ControlHarness) -> None:
        # Scenario: a root-issued command arriving on the channel performs the action.
        h = control_harness
        # Given: DNSBL blocking is ON (BEFORE).
        P.pfb["python_blacklist"] = True
        h.start()
        # Wait for the watcher's startup baseline before publishing -- prevents the
        # command from being mistaken for a pre-existing record under CPU contention.
        assert h.wait_started()

        assert P.pfb["python_blacklist"] is True  # BEFORE: still on, nothing applied.

        # When: a disable command (seq 1) is published.
        h.publish({"seq": 1, "cmd": "disable"})

        # Then: the reader applies it -- blocking goes OFF and the applied marker reaches 1.
        assert h.wait_applied(1)
        assert P.pfb["python_blacklist"] is False

    def test_addbypass_then_removebypass_via_channel(self, control_harness: _ControlHarness) -> None:
        h = control_harness
        # Given: the IP is NOT bypassed (BEFORE).
        assert P.gpListDB.get("192.0.2.10") is None
        h.start()
        # Wait for the watcher's startup baseline before publishing.
        assert h.wait_started()

        h.publish({"seq": 1, "cmd": "addbypass", "ip": "192.0.2.10"})
        assert h.wait_applied(1)
        assert P.gpListDB.get("192.0.2.10") == 0  # AFTER add: bypassed.

        h.publish({"seq": 2, "cmd": "removebypass", "ip": "192.0.2.10"})
        assert h.wait_applied(2)
        assert P.gpListDB.get("192.0.2.10") is None  # AFTER remove: gone again.

    def test_stale_seq_is_ignored_fresh_is_applied(self, control_harness: _ControlHarness) -> None:
        # Scenario: replay safety -- a record whose seq <= last applied is IGNORED; only
        # a strictly-advancing seq takes effect.
        h = control_harness
        P.pfb["python_blacklist"] = True
        h.start()
        # Wait for the watcher's startup baseline before publishing.
        assert h.wait_started()

        # Apply seq 5 (disable): blocking OFF.
        h.publish({"seq": 5, "cmd": "disable"})
        assert h.wait_applied(5)
        assert P.pfb["python_blacklist"] is False

        # Re-arm blocking out-of-band, then replay an OLD seq (3, enable). The reader
        # must NOT apply it (3 <= 5), so blocking stays as we set it.
        P.pfb["python_blacklist"] = True
        h.publish({"seq": 3, "cmd": "enable"})
        time.sleep(0.3)  # give the watcher a few poll cycles
        assert P.pfb["python_blacklist"] is True  # unchanged: stale seq ignored.
        assert (h.read_applied() or 0) == 5  # applied marker did NOT regress.

        # A genuinely fresh seq (6, disable) IS applied -> blocking OFF again.
        h.publish({"seq": 6, "cmd": "disable"})
        assert h.wait_applied(6)
        assert P.pfb["python_blacklist"] is False

    def test_preexisting_record_adopted_as_baseline_not_replayed(self, control_harness: _ControlHarness) -> None:
        # A record already on disk at startup (e.g. from a prior run) is the baseline --
        # the reader adopts its seq WITHOUT applying it; only a future advance acts.
        h = control_harness
        # Pre-existing disable at seq 9, but blocking is ON: if it were replayed, blocking
        # would be flipped OFF. It must NOT be.
        h.publish({"seq": 9, "cmd": "disable"})
        P.pfb["python_blacklist"] = True
        h.start()
        # wait_applied(9) itself is the started gate here (seq 9 = baseline): the
        # watcher adopts it and publishes it without applying the command.
        assert h.wait_applied(9)  # baseline adopted + published.
        time.sleep(0.2)
        assert P.pfb["python_blacklist"] is True  # NOT replayed.

        # A future advance (seq 10) DOES apply.
        h.publish({"seq": 10, "cmd": "disable"})
        assert h.wait_applied(10)
        assert P.pfb["python_blacklist"] is False

    def test_unknown_command_record_consumed_without_side_effect(self, control_harness: _ControlHarness) -> None:
        # A record with an unknown cmd advances the seq (consumed) but performs no action.
        h = control_harness
        P.pfb["python_blacklist"] = True
        h.start()
        assert h.wait_started()  # ensure baseline before publishing
        assert P.pfb["python_blacklist"] is True  # BEFORE: on, nothing applied yet.
        h.publish({"seq": 1, "cmd": "wipe-everything"})
        assert h.wait_applied(1)  # consumed (marker advances) ...
        assert P.pfb["python_blacklist"] is True  # ... but no side effect.


# --------------------------------------------------------------------------- #
# Permission boundary modelled at unit level: authorization is "only root may
# write" -- the reader NEVER writes the channel, it only writes the applied
# marker. This pins the read/write split the on-box 0640 root:unbound perms enforce.
# --------------------------------------------------------------------------- #


class TestPermissionBoundaryModel:
    def test_reader_does_not_write_the_channel(self, tmp_path: Any, monkeypatch: Any) -> None:
        # Given: a channel published by the (root) writer with a known record.
        h = _ControlHarness(tmp_path, monkeypatch)
        h.publish({"seq": 1, "cmd": "enable"})
        import os

        before = os.stat(h.channel)
        before_bytes = open(h.channel, "rb").read()
        h.start()
        try:
            assert h.wait_applied(1)
            time.sleep(0.2)
            # Then: the reader consumed the command and wrote ONLY the applied marker --
            # the command channel itself is byte-for-byte unchanged (the reader is a
            # read-only consumer of it; only root writes the channel).
            after = os.stat(h.channel)
            assert open(h.channel, "rb").read() == before_bytes
            assert after.st_mtime == before.st_mtime
            # The applied marker (which the reader DOES own) was written.
            assert os.path.exists(h.applied)
        finally:
            h.stop_join()

    def test_applied_marker_is_separate_file_from_channel(self) -> None:
        # The reader's only write target is the .applied marker, a DIFFERENT path from the
        # command channel -- so the reader needs no write access to the channel at all.
        assert P.pfb["pfb_py_control"] != P.pfb["pfb_py_control_applied"]
        assert P.pfb["pfb_py_control_applied"].endswith(".applied")
