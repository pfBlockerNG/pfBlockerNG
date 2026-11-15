"""Hermetic GetSchedule shape canaries through the actual post-only native fixture path."""

from __future__ import annotations

import subprocess
from contextlib import nullcontext
from typing import Any, cast

import pytest
from pytest import MonkeyPatch

from tests.smoke import test_core_feedphase_repairs as repairs
from tests.smoke.conftest import SmokeVM

_MISSING = object()
_TOKEN = "0" * 12
_HEADER = f"repairpost{_TOKEN}"
_ALIAS = f"repairpostgrp{_TOKEN}"
_FEED_ID = f"dnsbl:{_HEADER}"


class FakeVM:
    def __init__(self, files: dict[str, str]) -> None:
        self.files = files

    def ssh(self, *args: str, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        if args[:3] == ("/bin/cp", "-p", "/conf/config.xml"):
            return subprocess.CompletedProcess(args, 0, "", "")
        if args[:2] in (("/bin/rm", "-rf"), ("/bin/rm", "-f")):
            return subprocess.CompletedProcess(args, 0, "", "")
        if args[:1] == ("cat",):
            return subprocess.CompletedProcess(args, 0, self.files.get(args[1], ""), "")
        raise AssertionError(f"unexpected VM command: {args!r}")


def _vm(fake: FakeVM) -> SmokeVM:
    return cast(SmokeVM, fake)


class MockFeeds:
    def register(self, _name: str, _body: str) -> str:
        return "http://fixture.invalid/feed"

    def enable_etag(self, _name: str, _etag: str) -> None:
        return None

    def statuses(self, _name: str) -> list[int]:
        return [200]


def _run_post_only_with_schedule_shapes(
    monkeypatch: MonkeyPatch,
    before_shape: object,
    after_shape: object = _MISSING,
) -> dict[str, int]:
    files: dict[str, str] = {}
    fake = FakeVM(files)
    calls = {"updates": 0, "schedule": 0, "ledger": 0}
    after_shape = before_shape if after_shape is _MISSING else after_shape

    monkeypatch.setattr(repairs.uuid, "uuid4", lambda: repairs.uuid.UUID(int=0))
    monkeypatch.setattr(repairs, "await_idle", lambda _vm: None)
    monkeypatch.setattr(repairs, "_prepare_mock_feeds", lambda _vm, *, dnsbl: None)
    monkeypatch.setattr(repairs.h, "unique_domain", lambda _prefix: "post-only.invalid")
    monkeypatch.setattr(repairs, "_install_list_script", lambda _vm, _owned, name, _body: name)
    monkeypatch.setattr(repairs.h, "set_update_hooks", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(repairs.h, "inject_dnsbl_lists", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(repairs, "_set_group_scripts", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(repairs, "await_idle", lambda _vm: None)
    monkeypatch.setattr(repairs.h, "restore_pfb_config_baseline", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(repairs.h, "tell_core_the_settings_changed", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        repairs.h,
        "php_eval",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, "OK", ""),
    )
    monkeypatch.setattr(repairs, "_assert_feed_disposition", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        repairs.h,
        "due_feed_group",
        lambda *_args, **_kwargs: nullcontext(),
    )

    def write_guest(_vm: SmokeVM, path: str, body: str, *, executable: bool = False) -> None:
        del executable
        files[path] = body

    monkeypatch.setattr(repairs, "_write_guest", write_guest)

    def snapshot(_vm: SmokeVM, paths: list[str]) -> dict[str, tuple[bytes, str]]:
        return {path: (b"post-only.invalid\n", "inode times size") for path in paths}

    monkeypatch.setattr(repairs, "_snapshot", snapshot)
    monkeypatch.setattr(repairs, "_dnsbl_payloads", lambda _vm, _header: ["post-only.invalid"])

    def run_update(_vm: SmokeVM, trigger: str = "manual", scope: str = "both") -> tuple[dict[str, Any], str]:
        del trigger, scope
        calls["updates"] += 1
        trace = next(path for path in files if "/repair-post-" in path)
        if calls["updates"] == 1:
            files[trace] += "post\n"
        elif calls["updates"] == 2:
            files[trace] += "post\n"
            hook = next(path for path in files if "/repair-hooks-" in path)
            files[hook] += "pre\npost|0|0||\n"
        else:
            files[trace] += "post-fail\n"
        return {"result": "success", "startedAt": 1, "finishedAt": 2}, ""

    monkeypatch.setattr(repairs, "_run_update", run_update)

    def ledger(_vm: SmokeVM) -> list[dict[str, Any]]:
        calls["ledger"] += 1
        if calls["ledger"] == 1:
            return []
        return [{"facility": "dnsbl", "item": f"DNSBL_{_ALIAS}", "stage": "script"}]

    monkeypatch.setattr(repairs, "_open_dnsbl_ledger", ledger)

    def core_call(_vm: SmokeVM, method: str, _params: dict[str, Any] | None = None) -> dict[str, Any]:
        assert method == "GetSchedule"
        calls["schedule"] += 1
        shape = before_shape if calls["schedule"] == 1 else after_shape
        body: dict[str, Any] = {"scheduled": False, "feeds": None, "extras": {}}
        if shape is not _MISSING:
            body["lastSuccessfulCheck"] = shape
        return {"status": 200, "body": body, "error": None}

    monkeypatch.setattr(repairs.h, "core_call", core_call)

    repairs.test_post_only_unchanged_reparse_runs_once_without_refetch_and_failure_stays_pending(_vm(fake), MockFeeds())
    return calls


@pytest.mark.parametrize(
    "shape",
    (
        [],
        {_FEED_ID: 1700000000},
    ),
    ids=("php-bridge-empty-object", "ordinary-nonempty-map"),
)
def test_post_only_schedule_shape_preserves_pending_and_no_success_advance(
    monkeypatch: MonkeyPatch,
    shape: object,
) -> None:
    calls = _run_post_only_with_schedule_shapes(monkeypatch, shape)

    assert calls == {"updates": 3, "schedule": 2, "ledger": 2}


@pytest.mark.parametrize(
    "shape",
    (
        _MISSING,
        None,
        [[_FEED_ID, 1700000000]],
        [_FEED_ID],
        "not-a-map",
        1,
        True,
    ),
    ids=("missing", "null", "nonempty-pairs", "nonempty-values", "string", "integer", "boolean"),
)
def test_post_only_schedule_shape_rejects_every_malformed_nonmap_before_retry(
    monkeypatch: MonkeyPatch,
    shape: object,
) -> None:
    with pytest.raises(AssertionError, match="lastSuccessfulCheck"):
        _run_post_only_with_schedule_shapes(monkeypatch, shape)


@pytest.mark.parametrize("before", ({}, {_FEED_ID: 1700000000}), ids=("new-success", "advanced-success"))
def test_post_failure_rejects_new_or_advanced_successful_check(monkeypatch: MonkeyPatch, before: object) -> None:
    with pytest.raises(AssertionError, match="post failure was reported as successful"):
        _run_post_only_with_schedule_shapes(monkeypatch, before, {_FEED_ID: 1700000001})
