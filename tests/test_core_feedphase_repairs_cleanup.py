"""Hermetic control-flow tests for the #3977 native repair fixture cleanup."""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from typing import cast

import pytest
from pytest import MonkeyPatch

from tests.smoke import test_core_feedphase_repairs as repairs
from tests.smoke.conftest import SmokeVM


class CleanupFailure(RuntimeError):
    pass


class FakeVM:
    def __init__(self, events: list[str], *, owned_rm: bool = False, snapshot_rm: bool = False) -> None:
        self.events = events
        self.owned_rm = owned_rm
        self.snapshot_rm = snapshot_rm

    def ssh(self, *args: str, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        if args[:3] == ("/bin/cp", "-p", "/conf/config.xml"):
            self.events.append("snapshot")
            return subprocess.CompletedProcess(args, 0, "", "")
        if args[:2] == ("/bin/rm", "-rf"):
            self.events.append("remove-owned:" + ",".join(args[2:]))
            return subprocess.CompletedProcess(args, 1 if self.owned_rm else 0, "", "owned-rm")
        if args[:2] == ("/bin/rm", "-f"):
            self.events.append("remove-snapshot")
            return subprocess.CompletedProcess(args, 1 if self.snapshot_rm else 0, "", "snapshot-rm")
        raise AssertionError(f"unexpected VM command: {args!r}")


def _vm(fake: FakeVM) -> SmokeVM:
    return cast(SmokeVM, fake)


def _patch_cleanup(
    monkeypatch: MonkeyPatch,
    events: list[str],
    *,
    restore_error: BaseException | None = None,
    refresh_error: BaseException | None = None,
) -> None:
    def restore(_vm: SmokeVM, *, snapshot_path: str) -> None:
        events.append(f"restore:{snapshot_path}")
        if restore_error is not None:
            raise restore_error

    def refresh(_vm: SmokeVM) -> None:
        events.append("refresh")
        if refresh_error is not None:
            raise refresh_error

    monkeypatch.setattr(repairs.h, "restore_pfb_config_baseline", restore)
    monkeypatch.setattr(repairs.h, "tell_core_the_settings_changed", refresh)


def _messages(error: BaseException) -> str:
    nested = getattr(error, "exceptions", ())
    return "\n".join((str(error), *(_messages(item) for item in nested)))


def _run_context(fake: FakeVM, body: Callable[[list[str]], None]) -> None:
    with repairs._restored_case(_vm(fake)) as (_token, owned):
        body(owned)


def test_owned_path_removal_failure_still_restores_refreshes_and_removes_snapshot(
    monkeypatch: MonkeyPatch,
) -> None:
    events: list[str] = []
    fake = FakeVM(events, owned_rm=True)
    _patch_cleanup(monkeypatch, events)

    with pytest.raises(BaseException, match="owned-rm"):
        _run_context(fake, lambda owned: owned.append("/owned/feed"))

    assert len(events) == 5, events
    assert events[0] == "snapshot"
    assert events[1] == "remove-owned:/owned/feed"
    assert events[2].startswith("restore:/tmp/pfb3977-")
    assert events[3:] == ["refresh", "remove-snapshot"]


def test_restore_failure_still_removes_snapshot(monkeypatch: MonkeyPatch) -> None:
    events: list[str] = []
    fake = FakeVM(events)
    _patch_cleanup(monkeypatch, events, restore_error=CleanupFailure("restore-failure"))

    with pytest.raises(CleanupFailure, match="restore-failure"):
        _run_context(fake, lambda _owned: None)

    assert events[0] == "snapshot"
    assert events[1].startswith("restore:/tmp/pfb3977-")
    assert events[-1] == "remove-snapshot"


def test_refresh_failure_still_removes_snapshot(monkeypatch: MonkeyPatch) -> None:
    events: list[str] = []
    fake = FakeVM(events)
    _patch_cleanup(monkeypatch, events, refresh_error=CleanupFailure("refresh-failure"))

    with pytest.raises(CleanupFailure, match="refresh-failure"):
        _run_context(fake, lambda _owned: None)

    assert events[0] == "snapshot"
    assert events[1].startswith("restore:/tmp/pfb3977-")
    assert events[2:] == ["refresh", "remove-snapshot"]


def test_body_and_every_cleanup_failure_remain_visible(monkeypatch: MonkeyPatch) -> None:
    events: list[str] = []
    fake = FakeVM(events, owned_rm=True, snapshot_rm=True)
    _patch_cleanup(
        monkeypatch,
        events,
        restore_error=CleanupFailure("restore-failure"),
        refresh_error=CleanupFailure("refresh-failure"),
    )

    def fail_body(owned: list[str]) -> None:
        owned.append("/owned/feed")
        raise CleanupFailure("body-failure")

    with pytest.raises(BaseException) as caught:
        _run_context(fake, fail_body)

    messages = _messages(caught.value)
    for marker in ("body-failure", "owned-rm", "restore-failure", "refresh-failure", "snapshot-rm"):
        assert marker in messages
    assert events[1:] == [
        "remove-owned:/owned/feed",
        next(event for event in events if event.startswith("restore:/tmp/pfb3977-")),
        "refresh",
        "remove-snapshot",
    ]


def test_second_source_write_failure_removes_first_registered_path(monkeypatch: MonkeyPatch) -> None:
    events: list[str] = []
    fake = FakeVM(events)
    _patch_cleanup(monkeypatch, events)
    monkeypatch.setattr(repairs, "await_idle", lambda _vm: None)
    monkeypatch.setattr(repairs, "_prepare_mock_feeds", lambda _vm, *, dnsbl: None)
    monkeypatch.setattr(repairs.h, "unique_domain", lambda prefix: f"{prefix}.invalid")
    writes = 0

    def write_local_feed(_vm: SmokeVM, _name: str, _body: str) -> str:
        nonlocal writes
        writes += 1
        if writes == 1:
            return "/owned/source1"
        raise CleanupFailure("second-write-failure")

    monkeypatch.setattr(repairs.h, "write_local_feed", write_local_feed)

    with pytest.raises(CleanupFailure, match="second-write-failure"):
        repairs.test_native_two_feed_scripts_preserve_per_feed_side_effect_order(
            _vm(fake), "same-group", "pre1\npost1\npre2\npost2\n"
        )

    assert "remove-owned:/owned/source1" in events
    assert events[-1] == "remove-snapshot"
