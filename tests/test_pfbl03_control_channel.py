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

import pfb_unbound as P

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

    def test_addbypass_dash_encoded_ipv4_is_unmapped(self) -> None:
        # The DNS-TXT transport encodes the dotted IPv4 with '-'; the shared handler
        # un-maps it. Proves the legacy encoding still resolves to the real IP.
        applied, _ = P.pfb_apply_control_command(["python_control", "addbypass", "192-0-2-10"])
        assert applied is True
        assert P.gpListDB.get("192.0.2.10") == 0

    def test_addbypass_invalid_ip_raises(self) -> None:
        # ipaddress.ip_address() rejects a non-IP -- the shared handler re-validates the
        # bypass IP (the reader also screens it, but the handler is the last gate).
        import pytest

        with pytest.raises(ValueError):
            P.pfb_apply_control_command(["python_control", "addbypass", "not-an-ip"])

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

    def wait_applied(self, seq: int, timeout: float = 3.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if (self.read_applied() or -1) >= seq:
                return True
            time.sleep(0.01)
        return False

    def stop_join(self, timeout: float = 5.0) -> None:
        P.pfb_control_stop.set()
        if self.thread is not None:
            self.thread.join(timeout=timeout)


class TestControlWatcherLoop:
    def test_fresh_command_is_applied(self, tmp_path: Any, monkeypatch: Any) -> None:
        # Scenario: a root-issued command arriving on the channel performs the action.
        h = _ControlHarness(tmp_path, monkeypatch)
        # Given: DNSBL blocking is ON (BEFORE).
        P.pfb["python_blacklist"] = True
        h.start()
        try:
            assert P.pfb["python_blacklist"] is True  # BEFORE: still on, nothing applied.

            # When: a disable command (seq 1) is published.
            h.publish({"seq": 1, "cmd": "disable"})

            # Then: the reader applies it -- blocking goes OFF and the applied marker reaches 1.
            assert h.wait_applied(1)
            assert P.pfb["python_blacklist"] is False
        finally:
            h.stop_join()
        assert not h.thread.is_alive()

    def test_addbypass_then_removebypass_via_channel(self, tmp_path: Any, monkeypatch: Any) -> None:
        h = _ControlHarness(tmp_path, monkeypatch)
        # Given: the IP is NOT bypassed (BEFORE).
        assert P.gpListDB.get("192.0.2.10") is None
        h.start()
        try:
            h.publish({"seq": 1, "cmd": "addbypass", "ip": "192.0.2.10"})
            assert h.wait_applied(1)
            assert P.gpListDB.get("192.0.2.10") == 0  # AFTER add: bypassed.

            h.publish({"seq": 2, "cmd": "removebypass", "ip": "192.0.2.10"})
            assert h.wait_applied(2)
            assert P.gpListDB.get("192.0.2.10") is None  # AFTER remove: gone again.
        finally:
            h.stop_join()
        assert not h.thread.is_alive()

    def test_stale_seq_is_ignored_fresh_is_applied(self, tmp_path: Any, monkeypatch: Any) -> None:
        # Scenario: replay safety -- a record whose seq <= last applied is IGNORED; only
        # a strictly-advancing seq takes effect.
        h = _ControlHarness(tmp_path, monkeypatch)
        P.pfb["python_blacklist"] = True
        h.start()
        try:
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
        finally:
            h.stop_join()
        assert not h.thread.is_alive()

    def test_preexisting_record_adopted_as_baseline_not_replayed(self, tmp_path: Any, monkeypatch: Any) -> None:
        # A record already on disk at startup (e.g. from a prior run) is the baseline --
        # the reader adopts its seq WITHOUT applying it; only a future advance acts.
        h = _ControlHarness(tmp_path, monkeypatch)
        # Pre-existing disable at seq 9, but blocking is ON: if it were replayed, blocking
        # would be flipped OFF. It must NOT be.
        h.publish({"seq": 9, "cmd": "disable"})
        P.pfb["python_blacklist"] = True
        h.start()
        try:
            assert h.wait_applied(9)  # baseline adopted + published.
            time.sleep(0.2)
            assert P.pfb["python_blacklist"] is True  # NOT replayed.

            # A future advance (seq 10) DOES apply.
            h.publish({"seq": 10, "cmd": "disable"})
            assert h.wait_applied(10)
            assert P.pfb["python_blacklist"] is False
        finally:
            h.stop_join()
        assert not h.thread.is_alive()

    def test_unknown_command_record_consumed_without_side_effect(self, tmp_path: Any, monkeypatch: Any) -> None:
        # A record with an unknown cmd advances the seq (consumed) but performs no action.
        h = _ControlHarness(tmp_path, monkeypatch)
        P.pfb["python_blacklist"] = True
        h.start()
        try:
            h.publish({"seq": 1, "cmd": "wipe-everything"})
            assert h.wait_applied(1)  # consumed (marker advances) ...
            assert P.pfb["python_blacklist"] is True  # ... but no side effect.
        finally:
            h.stop_join()
        assert not h.thread.is_alive()


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
