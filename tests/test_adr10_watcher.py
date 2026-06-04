"""ADR-10 Phase 4 -- the zero-downtime reload-watcher (daemon thread + background swap).

WHY THIS FILE EXISTS
--------------------
Phase 4 adds a daemon thread (``pfb_reload_watcher``) that waits on a reload SENTINEL
and, on a generation-id ADVANCE, runs the Phase-3 fail-closed ``rebuild_and_swap()``
OFF the query threads -- so a DNSBL data update applies with NO Unbound restart. The
swap is single-flight (coalesced) and RAM-gated (declines fail-closed on a constrained
box, keeping the old snapshot). These tests pin that logic WITHOUT a live Unbound, with
a stubbed builder + a temp sentinel dir.

Per the repo test-coverage rules every transition test asserts the BEFORE-state first
(the OLD snapshot is live) and the AFTER-state second (NEW after a successful swap; OLD
retained after a failed/declined build), so a green proves the trigger CAUSED the change
rather than the end-state happening to hold already. Each branch of every toggle is
covered: RAM gate fits / declines / unknown-RAM; generation absent / non-int / advance /
no-advance; build success / None; kqueue vs the mtime-poll fallback; clean ``deinit``
join. The watcher does NOT auto-run during the normal suite -- it is gated on
``pfb["mod_threading"]`` and only a test that explicitly starts the thread runs it.
"""

from __future__ import annotations

import threading
import time
from typing import Any

import pfb_unbound as P

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _snapshot(*, tag: str, counts: int = 0, regex_count: int = 0) -> P.Snapshot:
    """A populated Snapshot with a distinct identity (tag baked into data_db) so a swap
    is observable by object identity AND content."""
    return P.Snapshot(
        data_db={tag: {"log": "1", "index": 0, "important": False}},
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


def _write_generation(path: str, gen: int) -> None:
    """Atomically publish a generation id into the sentinel (mirrors Phase-5 PHP: write
    a temp file then os.replace -- so the watcher's dir-watch sees a RENAME/WRITE)."""
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write("{}\n".format(gen))
    import os

    os.replace(tmp, path)


def _no_emit(monkeypatch: Any) -> None:
    # rebuild_and_swap re-emits the UI counts on success: it reads pfb["pfb_py_count"] /
    # pfb["pfb_py_regex_count"] (set by init, NOT by the autouse reset fixture) as the
    # emit args, so set them, then stub the writer to a no-op so no file is touched.
    P.pfb["pfb_py_count"] = "pfb_py_count"
    P.pfb["pfb_py_regex_count"] = "pfb_py_regex_count"
    monkeypatch.setattr(P, "dnsbl_emit_count", lambda *a, **k: True)


# --------------------------------------------------------------------------- #
# RAM gate -- fits / declines / unknown-RAM (every branch)
# --------------------------------------------------------------------------- #


class TestRamGate:
    def test_gate_ok_when_ram_fits(self) -> None:
        # 1000 entries -> projected 2 * 1000 * 276 + 64 MiB headroom. Plenty of RAM.
        assert P._reload_ram_gate_ok(1000, available_ram=lambda: 4 * 1024 * 1024 * 1024) is True

    def test_gate_declines_when_ram_insufficient(self) -> None:
        # ABP-scale list on a tiny box: 1.5M entries needs ~786 MiB transient; offer 200 MiB.
        assert P._reload_ram_gate_ok(1_500_000, available_ram=lambda: 200 * 1024 * 1024) is False

    def test_gate_declines_when_ram_unknown(self) -> None:
        # Fail-closed: a platform that cannot report available RAM must NOT build.
        assert P._reload_ram_gate_ok(1000, available_ram=lambda: None) is False

    def test_gate_boundary(self) -> None:
        # Exactly projected + headroom fits; one byte short declines.
        entries = 10
        projected = 2 * entries * P.RELOAD_BYTES_PER_ENTRY + P.RELOAD_RAM_HEADROOM_BYTES
        assert P._reload_ram_gate_ok(entries, available_ram=lambda: projected) is True
        assert P._reload_ram_gate_ok(entries, available_ram=lambda: projected - 1) is False

    def test_available_ram_probe_returns_int_or_none(self) -> None:
        # The real stdlib probe must return a non-negative int or None (never raise).
        val = P._reload_available_ram_bytes()
        assert val is None or (isinstance(val, int) and val >= 0)


# --------------------------------------------------------------------------- #
# Generation reader -- absent / empty / non-int / integer / first-line-only
# --------------------------------------------------------------------------- #


class TestGenerationReader:
    def test_absent_sentinel_is_none(self, tmp_path: Any) -> None:
        assert P._reload_read_generation(str(tmp_path / "nope")) is None

    def test_empty_sentinel_is_none(self, tmp_path: Any) -> None:
        p = tmp_path / "sentinel"
        p.write_text("")
        assert P._reload_read_generation(str(p)) is None

    def test_non_integer_is_none(self, tmp_path: Any) -> None:
        p = tmp_path / "sentinel"
        p.write_text("not-a-number\n")
        assert P._reload_read_generation(str(p)) is None

    def test_integer_generation_parsed(self, tmp_path: Any) -> None:
        p = tmp_path / "sentinel"
        p.write_text("42\n")
        assert P._reload_read_generation(str(p)) == 42

    def test_only_first_line_used(self, tmp_path: Any) -> None:
        p = tmp_path / "sentinel"
        p.write_text("7\nignored second line\n")
        assert P._reload_read_generation(str(p)) == 7


# --------------------------------------------------------------------------- #
# _reload_run_swap -- gate-ok swaps, gate-declines keeps old, build-fail keeps old
# --------------------------------------------------------------------------- #


class TestRunSwap:
    def test_gate_ok_swaps_old_to_new(self, monkeypatch: Any) -> None:
        _no_emit(monkeypatch)
        monkeypatch.setattr(P, "_reload_available_ram_bytes", lambda: 8 * 1024 * 1024 * 1024)
        old = _snapshot(tag="old.example.com", counts=1)
        new = _snapshot(tag="new.example.com", counts=2)
        P._snapshot = old

        assert P._snapshot is old  # BEFORE: old snapshot live.
        assert P._reload_run_swap(lambda: new) is True  # reports the swap happened.
        assert P._snapshot is new  # AFTER: new snapshot installed.
        assert P._snapshot is not old

    def test_gate_declines_keeps_old(self, monkeypatch: Any) -> None:
        # RAM-constrained box: the swap is DECLINED fail-closed; the old snapshot stays
        # live and the builder is NEVER called (no transient build attempted at all).
        _no_emit(monkeypatch)
        monkeypatch.setattr(P, "_reload_available_ram_bytes", lambda: 1 * 1024 * 1024)  # 1 MiB
        old = _snapshot(tag="old.example.com", counts=1_000_000)
        P._snapshot = old
        built = {"n": 0}

        def _builder() -> P.Snapshot:
            built["n"] += 1
            return _snapshot(tag="new.example.com")

        assert P._snapshot is old  # BEFORE.
        assert P._reload_run_swap(_builder) is False  # declined -> no swap reported.
        assert P._snapshot is old  # AFTER: declined -> old kept.
        assert built["n"] == 0  # builder never ran (RAM gate is BEFORE the build).

    def test_build_fail_keeps_old(self, monkeypatch: Any) -> None:
        # Gate OK but the builder returns None (bad manifest): rebuild_and_swap is
        # fail-closed, so the old snapshot is retained.
        _no_emit(monkeypatch)
        monkeypatch.setattr(P, "_reload_available_ram_bytes", lambda: 8 * 1024 * 1024 * 1024)
        old = _snapshot(tag="old.example.com", counts=1)
        P._snapshot = old

        assert P._snapshot is old  # BEFORE.
        assert P._reload_run_swap(lambda: None) is False  # build failed -> no swap reported.
        assert P._snapshot is old  # AFTER: build failed -> old kept.


# --------------------------------------------------------------------------- #
# The watcher loop -- drive a real thread with a stubbed builder + temp sentinel
# --------------------------------------------------------------------------- #


class _Harness:
    """Run pfb_reload_watcher on a real daemon thread with a counting/blocking stub
    builder and a temp sentinel. Mirrors init's start + deinit's stop/join."""

    def __init__(self, tmp_path: Any, monkeypatch: Any, *, ram_ok: bool = True) -> None:
        import os

        self.sentinel = str(tmp_path / "pfb_py_reload")
        P.pfb["pfb_py_reload"] = self.sentinel
        # ADR-10: the watcher publishes the applied generation here after each swap.
        self.applied = str(tmp_path / "pfb_py_reload.applied")
        P.pfb["pfb_py_reload_applied"] = self.applied
        # Short wait cadence so the kqueue/poll timeout (hence stop observation + the
        # blocking-build release) is prompt and the suite stays fast. Best-effort by
        # design; the generation compare -- not the cadence -- is what drives the swap.
        monkeypatch.setattr(P, "RELOAD_POLL_INTERVAL", 0.05)
        _no_emit(monkeypatch)
        monkeypatch.setattr(
            P,
            "_reload_available_ram_bytes",
            (lambda: 8 * 1024 * 1024 * 1024) if ram_ok else (lambda: 1),
        )
        self.builds: list[int] = []
        self._gate = threading.Event()
        self._gate.set()  # un-gated by default; tests can clear() to make a build block
        self._lock = threading.Lock()
        self.fail = False
        self.os = os
        P.pfb_reload_stop = threading.Event()
        self.thread: Any = None

    def builder(self) -> P.Snapshot | None:
        # Record the generation observed at build time; optionally block to simulate a
        # slow ABP build so a concurrent trigger can be tested for coalescing.
        gen = P._reload_read_generation(self.sentinel) or 0
        with self._lock:
            self.builds.append(gen)
        self._gate.wait(1.0)
        if self.fail:
            return None
        return _snapshot(tag="gen{}.example.com".format(gen), counts=gen)

    def start(self) -> None:
        self.thread = threading.Thread(
            name="pfb_reload_watcher_test", target=P.pfb_reload_watcher, args=(self.builder,), daemon=True
        )
        self.thread.start()

    def publish(self, gen: int) -> None:
        _write_generation(self.sentinel, gen)

    def read_applied(self) -> int | None:
        # The applied marker uses the same int-on-first-line format as the sentinel.
        return P._reload_read_generation(self.applied)

    def wait_builds(self, n: int, timeout: float = 3.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                if len(self.builds) >= n:
                    return
            time.sleep(0.01)

    def stop_join(self, timeout: float = 5.0) -> None:
        P.pfb_reload_stop.set()
        self._gate.set()  # release a blocked build so the thread can exit promptly
        if self.thread is not None:
            self.thread.join(timeout=timeout)


class TestWatcherLoop:
    def test_generation_advance_triggers_swap(self, tmp_path: Any, monkeypatch: Any) -> None:
        h = _Harness(tmp_path, monkeypatch)
        old = _snapshot(tag="old.example.com", counts=0)
        P._snapshot = old
        h.start()
        try:
            assert P._snapshot is old  # BEFORE: old snapshot live, no advance yet.
            time.sleep(0.1)
            assert h.builds == []  # no sentinel -> no build.

            h.publish(1)  # ADVANCE.
            h.wait_builds(1)
            # AFTER: a new snapshot for generation 1 is installed.
            assert "gen1.example.com" in P._snapshot.data_db
            assert P._snapshot is not old
        finally:
            h.stop_join()
        assert not h.thread.is_alive()  # clean join.

    def test_no_advance_no_swap(self, tmp_path: Any, monkeypatch: Any) -> None:
        # Re-publishing the SAME generation (best-effort duplicate event) must NOT rebuild.
        h = _Harness(tmp_path, monkeypatch)
        h.start()  # no sentinel yet -> baseline generation is None.
        try:
            h.publish(5)  # first ADVANCE (None -> 5): builds once.
            h.wait_builds(1)
            assert h.builds == [5]
            h.publish(5)  # same generation again (duplicate/best-effort event).
            time.sleep(0.2)
            assert h.builds == [5]  # NO additional build for an unchanged generation.
        finally:
            h.stop_join()
        assert not h.thread.is_alive()

    def test_preexisting_generation_adopted_as_baseline_no_build(self, tmp_path: Any, monkeypatch: Any) -> None:
        # A sentinel ALREADY at a generation at startup is the baseline (init loaded the
        # lists synchronously) -- the watcher adopts it WITHOUT a redundant rebuild, and
        # only a FUTURE advance triggers one.
        h = _Harness(tmp_path, monkeypatch)
        h.publish(5)  # sentinel pre-exists at gen 5 BEFORE the watcher starts.
        h.start()
        try:
            time.sleep(0.2)
            assert h.builds == []  # baseline adopted, NO build for the pre-existing gen.
            h.publish(6)  # a genuine future advance.
            h.wait_builds(1)
            assert h.builds == [6]  # only the advance past the baseline builds.
        finally:
            h.stop_join()
        assert not h.thread.is_alive()

    def test_single_flight_coalesces_concurrent_triggers(self, tmp_path: Any, monkeypatch: Any) -> None:
        # A trigger arriving DURING a build is coalesced: the build for gen 2 is blocked;
        # gen 3 is published while it runs; after gen 2 completes the watcher re-checks
        # and builds ONCE MORE for gen 3 -- never two builds in parallel.
        h = _Harness(tmp_path, monkeypatch)
        h._gate.clear()  # make builds block until released.
        h.start()
        try:
            h.publish(2)
            h.wait_builds(1)  # the gen-2 build has started and is blocking.
            assert h.builds == [2]

            h.publish(3)  # advance WHILE gen-2 build is in flight.
            time.sleep(0.2)
            assert h.builds == [2]  # still single-flight: no parallel gen-3 build.

            h._gate.set()  # release gen-2 build; watcher re-checks -> builds gen-3 once.
            h.wait_builds(2)
            assert h.builds == [2, 3]
            assert "gen3.example.com" in P._snapshot.data_db  # latest generation won.
        finally:
            h.stop_join()
        assert not h.thread.is_alive()

    def test_build_fail_keeps_old_snapshot(self, tmp_path: Any, monkeypatch: Any) -> None:
        h = _Harness(tmp_path, monkeypatch)
        h.fail = True  # builder returns None -> fail-closed.
        old = _snapshot(tag="old.example.com", counts=0)
        P._snapshot = old
        h.start()
        try:
            assert P._snapshot is old  # BEFORE.
            h.publish(9)
            h.wait_builds(1)
            time.sleep(0.1)
            assert P._snapshot is old  # AFTER: failed build kept the old snapshot.
        finally:
            h.stop_join()
        assert not h.thread.is_alive()

    def test_ram_gate_declines_keeps_old_snapshot(self, tmp_path: Any, monkeypatch: Any) -> None:
        # On a RAM-constrained box the watcher declines: old snapshot kept, builder unused.
        h = _Harness(tmp_path, monkeypatch, ram_ok=False)
        old = _snapshot(tag="old.example.com", counts=1)
        P._snapshot = old
        h.start()
        try:
            assert P._snapshot is old  # BEFORE.
            h.publish(1)
            time.sleep(0.3)
            assert P._snapshot is old  # AFTER: declined -> old kept.
            assert h.builds == []  # the builder was never invoked (gate is pre-build).
        finally:
            h.stop_join()
        assert not h.thread.is_alive()

    def test_poll_fallback_path_when_kqueue_absent(self, tmp_path: Any, monkeypatch: Any) -> None:
        # Force the mtime-poll fallback (kqueue unavailable, e.g. Linux/CI) by hiding
        # select.kqueue, and prove the same generation-advance -> swap behaviour holds.
        import select

        monkeypatch.delattr(select, "kqueue", raising=False)
        assert not hasattr(select, "kqueue")
        # Speed the poll so the test does not wait the full default interval.
        monkeypatch.setattr(P, "RELOAD_POLL_INTERVAL", 0.05)
        h = _Harness(tmp_path, monkeypatch)
        old = _snapshot(tag="old.example.com", counts=0)
        P._snapshot = old
        h.start()
        try:
            assert P._snapshot is old  # BEFORE.
            h.publish(1)
            h.wait_builds(1)
            assert "gen1.example.com" in P._snapshot.data_db  # AFTER: swapped via poll path.
        finally:
            h.stop_join()
        assert not h.thread.is_alive()  # clean join on the poll path too.

    def test_deinit_joins_watcher_cleanly(self, tmp_path: Any, monkeypatch: Any) -> None:
        # Wire the thread the way init does, then drive deinit's stop/join and assert the
        # thread is gone and the flag cleared (no leaked thread).
        h = _Harness(tmp_path, monkeypatch)
        h.start()
        P.pfb["reload_watcher"] = True
        P.pfb_reload_watcher_thread = h.thread
        P.pfb["python_maxmind"] = False
        try:
            assert h.thread.is_alive()  # BEFORE: watcher running.
            assert P.deinit(0) is True
            # AFTER: deinit set the stop Event, woke + joined the watcher.
            assert not h.thread.is_alive()
            assert P.pfb.get("reload_watcher") is False
        finally:
            h.stop_join()


# --------------------------------------------------------------------------- #
# ADR-10 readiness handshake: the applied-generation marker the watcher publishes
# after each swap (PHP's data fast path waits on it, so the ADR-12 post hook / the
# #51 alert page / the smoke suite observe LIVE lists, not a pending async swap).
# --------------------------------------------------------------------------- #


class TestAppliedMarker:
    def test_write_applied_roundtrips_and_overwrites(self, tmp_path: Any) -> None:
        # The marker is an int on the first line, atomically (re)written in place.
        path = str(tmp_path / "pfb_py_reload.applied")
        P.pfb["pfb_py_reload_applied"] = path
        P._reload_write_applied(5)
        assert P._reload_read_generation(path) == 5
        P._reload_write_applied(9)  # a later swap overwrites.
        assert P._reload_read_generation(path) == 9
        assert not (tmp_path / "pfb_py_reload.applied.tmp").exists()  # no stale temp.

    def test_write_applied_is_noop_when_path_unset(self, monkeypatch: Any) -> None:
        # No marker path configured -> silent no-op, never raises.
        monkeypatch.setitem(P.pfb, "pfb_py_reload_applied", "")
        P._reload_write_applied(3)

    def test_baseline_published_at_startup(self, tmp_path: Any, monkeypatch: Any) -> None:
        # A sentinel already at gen 5 at startup: the watcher adopts it as baseline
        # WITHOUT a rebuild AND publishes 5 as the applied generation, so PHP's first
        # wait-for-apply has a floor (does not block on an absent marker).
        h = _Harness(tmp_path, monkeypatch)
        h.publish(5)
        assert h.read_applied() is None  # BEFORE: no marker yet.
        h.start()
        try:
            deadline = time.monotonic() + 2.0
            while time.monotonic() < deadline and h.read_applied() != 5:
                time.sleep(0.01)
            assert h.read_applied() == 5  # AFTER: baseline published.
            assert h.builds == []  # baseline adoption did NOT rebuild.
        finally:
            h.stop_join()

    def test_marker_advances_only_on_successful_swap(self, tmp_path: Any, monkeypatch: Any) -> None:
        h = _Harness(tmp_path, monkeypatch)
        P._snapshot = _snapshot(tag="old.example.com", counts=0)
        h.start()
        try:
            assert h.read_applied() is None  # BEFORE: nothing applied (no sentinel yet).
            h.publish(1)
            h.wait_builds(1)
            deadline = time.monotonic() + 2.0
            while time.monotonic() < deadline and h.read_applied() != 1:
                time.sleep(0.01)
            assert h.read_applied() == 1  # AFTER: marker advanced to the swapped gen.
        finally:
            h.stop_join()

    def test_marker_not_advanced_on_ram_decline(self, tmp_path: Any, monkeypatch: Any) -> None:
        # RAM-constrained box: the swap is DECLINED, so the marker is NOT advanced --
        # PHP's wait then times out and falls back to the restart (fail-safe).
        h = _Harness(tmp_path, monkeypatch, ram_ok=False)
        P._snapshot = _snapshot(tag="old.example.com", counts=1_000_000)
        h.start()
        try:
            h.publish(7)
            time.sleep(0.4)  # several poll cycles.
            assert h.read_applied() is None  # declined -> never written.
        finally:
            h.stop_join()

    def test_marker_not_advanced_on_build_fail(self, tmp_path: Any, monkeypatch: Any) -> None:
        # Gate OK but the build returns None (bad manifest): fail-closed, marker stays.
        h = _Harness(tmp_path, monkeypatch)
        h.fail = True
        P._snapshot = _snapshot(tag="old.example.com", counts=0)
        h.start()
        try:
            h.publish(3)
            h.wait_builds(1)  # the builder ran (returned None).
            time.sleep(0.2)
            assert h.read_applied() is None  # build failed -> marker not advanced.
        finally:
            h.stop_join()
