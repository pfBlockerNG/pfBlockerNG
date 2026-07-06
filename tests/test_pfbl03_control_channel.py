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
