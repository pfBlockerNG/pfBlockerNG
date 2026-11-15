"""Off-box fault injection through the actual native IPv4 recovery test (H1)."""

from __future__ import annotations

import subprocess
from contextlib import nullcontext
from typing import Any

import pytest

from tests.smoke import test_core_update as core

OLD_BODY = "198.51.100.45\n"
NEW_BODY = "198.51.100.99\n"
HEADER = "coreupdfailipv4"
STEM = f"{HEADER}_v4"
ORIGINAL = f"{core.DB}/original/{STEM}.orig"
PARSED = f"{core.DB}/original/{STEM}.parsed.ip"
ACTION = f"{core.DB}/deny/{STEM}.txt"
FAIL = f"{core.DB}/deny/{STEM}.fail"
UPDATE = f"{core.DB}/deny/{STEM}.update"
FEED = core._OneFeed("source", f"ipv4:{STEM}", "ip", [ORIGINAL, PARSED, ACTION], PARSED, FAIL)


class _RecoveryBoundary:
    def __init__(self, recovered_body: str) -> None:
        self.recovered_body = recovered_body
        self.phase = "baseline"
        self.codes = [200]
        self.source_body = OLD_BODY
        self.source_status: int | None = None
        self.runs: list[str] = []

    def statuses(self, name: str) -> list[int]:
        assert name == FEED.mock
        return self.codes.copy()

    def set_status(self, name: str, status: int | None) -> None:
        assert name == FEED.mock
        self.source_status = status

    def set_content(self, name: str, body: str) -> None:
        assert name == FEED.mock
        self.source_body = body

    def run(self, vm: Any, trigger: str = "manual", scope: str = "both") -> tuple[dict[str, Any], str]:
        assert vm is self
        self.runs.append(trigger)
        if trigger == "manual":
            assert self.source_status == 503
            self.phase = "failed"
            self.codes.append(503)
            disposition = "failed"
        else:
            assert trigger == "retry" and self.source_status is None and self.source_body == NEW_BODY
            self.phase = "recovered"
            self.codes.append(200)
            disposition = "changed"
        return {"trigger": trigger, "result": "success"}, f"feed {FEED.feed_id}: {disposition}\n"

    def ssh(self, *args: str, timeout: float = 30.0) -> subprocess.CompletedProcess[str]:
        body = self.recovered_body if self.phase == "recovered" else OLD_BODY
        if args[0] == "cat" and args[1] in FEED.files:
            return subprocess.CompletedProcess(args, 0, body, "")
        if args[:3] == ("stat", "-f", "%i %.9Fm %.9Fc %z") and args[3] in FEED.files:
            stat = "2 2.000000000 2.000000000 14" if self.phase == "recovered" else "1 1.000000000 1.000000000 14"
            return subprocess.CompletedProcess(args, 0, stat, "")
        if args == ("cat", "/usr/local/etc/pfb_core/schedule_state.json"):
            assert self.phase == "failed"
            return subprocess.CompletedProcess(args, 0, '{"items":{}}', "")
        if args[0] == "test" and args[-1] in (FAIL, UPDATE):
            exists = self.phase == "failed"
            absent_query = args[1:] == ("!", "-f", args[-1])
            assert absent_query or args[1:] == ("-f", args[-1]), args
            return subprocess.CompletedProcess(args, int(exists == absent_query), "", "")
        if args[:1] == (core.h.PFCTL,) and args[1:2] == ("-t",):
            assert args[2] == f"pfB_{HEADER}_v4"
            if args[3:] == ("-T", "show"):
                return subprocess.CompletedProcess(args, 0, body, "")
            if args[3:5] == ("-T", "test"):
                matches = args[5] in body.splitlines()
                return subprocess.CompletedProcess(args, 0, "", f"{int(matches)}/1 addresses match.\n")
        raise AssertionError(f"unmodelled external observation: {args!r}")


def _exercise_actual_recovery_test(monkeypatch: pytest.MonkeyPatch, recovered_body: str) -> _RecoveryBoundary:
    boundary = _RecoveryBoundary(recovered_body)
    monkeypatch.setattr(core, "_arrange_one_feed", lambda *_args: FEED)
    monkeypatch.setattr(core, "_run_manual_update", lambda *_args: "")
    monkeypatch.setattr(core, "_run_update", boundary.run)
    monkeypatch.setattr(core.h, "tell_core_the_settings_changed", lambda *_args: None)
    monkeypatch.setattr(core.h, "due_feed_group", lambda *_args: nullcontext())
    monkeypatch.setattr(core.h, "core_call", lambda *_args: {"status": 200, "body": {"lastSuccessfulCheck": {}}})
    core.test_core_failed_transfer_keeps_last_good_files_and_retry_state_until_recovery(
        boundary,  # type: ignore[arg-type]
        boundary,  # type: ignore[arg-type]
        "ipv4",
    )
    assert boundary.runs == ["manual", "retry"]
    return boundary


def test_recovery_oracle_rejects_old_bytes_with_new_stats(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(AssertionError, match="recovered|published"):
        _exercise_actual_recovery_test(monkeypatch, OLD_BODY)


def test_recovery_oracle_accepts_published_new_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    boundary = _exercise_actual_recovery_test(monkeypatch, NEW_BODY)
    assert boundary.codes == [200, 503, 200]
    assert boundary.source_body == NEW_BODY
