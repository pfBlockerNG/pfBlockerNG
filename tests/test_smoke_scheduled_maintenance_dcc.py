"""Hermetic contract for #3996's supported DCC maintenance-window setup."""

from __future__ import annotations

import base64
import hashlib
import json
import shlex
import subprocess
from pathlib import Path
from typing import Any

import pytest

from tests.smoke import helpers as h
from tests.smoke import test_core_scheduled_maintenance as acceptance

NOW = 1_800_000_000
DCC = "extra:dcc"
BLACKLIST = "extra:bl"
HOUR = f"{h.CFG_GLOBAL}/pfb_schedule_hour"
MINUTE = f"{h.CFG_GLOBAL}/pfb_schedule_minute"
BLACKLIST_ENABLE = "installedpackages/pfblockerngblacklist/blacklist_enable"

UPDATE_REQUEST = f"{h.CORE_STATE_DIR}/update.log.request"
UPDATE_RESULT = f"{h.CORE_STATE_DIR}/update.log.result"
UPDATE_STATUS = f"{h.CORE_STATE_DIR}/update.log.status"
EXTRAS_LOG = f"{h.PFB_LOGDIR}/extras.log"
DIAGNOSTIC_CHUNK = 16_384


def schedule_reply(extras: dict[str, Any], successful: Any) -> dict[str, Any]:
    return {
        "status": 200,
        "body": {
            "scheduled": False,
            "feeds": None,
            "extras": extras,
            "lastSuccessfulCheck": successful,
        },
        "error": None,
    }


def dcc_entry(*, last_run: int, next_due: int) -> dict[str, int]:
    return {"lastRun": last_run, "nextDue": next_due}


class DccSetup:
    def __init__(
        self,
        monkeypatch: pytest.MonkeyPatch,
        *,
        before: dict[str, Any] | None = None,
        after: dict[str, Any] | None = None,
        successful: Any = None,
        update_result: str = "success",
        previous_install_fails: bool = False,
        current_restore_fails: bool = False,
        missing_receipts: set[str] | None = None,
        extras_delta: bytes | None = None,
    ) -> None:
        self.config: dict[str, str] = {}
        self.installs: list[dict[str, str]] = []
        self.config_reads: list[tuple[int, str]] = []
        self.core_calls: list[tuple[str, dict[str, Any]]] = []
        self.install_attempts: list[str] = []
        self.installed_package = "current"
        self.previous_install_fails = previous_install_fails
        self.current_restore_fails = current_restore_fails
        self.phases: list[str] = []
        self.settings_notices = 0
        self.start_reply = {"status": 200, "body": [], "error": None}
        self.update_result = update_result
        self.missing_receipts = missing_receipts or set()
        self.extras_before = b"existing extras\n"
        self.extras_delta = extras_delta if extras_delta is not None else b"DCC child stderr: download failed\n"
        self.public_update_log = "outer PHP update warning\n"
        self.public_log_reads = 0
        self.diagnostic_commands: list[str] = []
        self.range_sizes: list[int] = []
        self.retry_started = False
        request = {"trigger": "retry", "scope": "both", "force": "none", "extras": [DCC]}
        self.private_files = {
            UPDATE_REQUEST: (
                json.dumps(
                    {
                        "version": 1,
                        "nonce": "a" * 64,
                        "path": "/usr/local/pkg/pfblockerng/pfb_core_update.sh",
                        "request": request,
                        "startedAt": NOW,
                        "logGen": 1,
                    }
                )
                + "\n"
            ).encode(),
            UPDATE_RESULT: (json.dumps({"version": 1, "attempted": [DCC], "geoipReady": True}) + "\n").encode(),
            UPDATE_STATUS: (
                json.dumps(
                    {
                        "version": 1,
                        "nonce": "a" * 64,
                        "path": "/usr/local/pkg/pfblockerng/pfb_core_update.sh",
                        "request": request,
                        "startedAt": NOW,
                        "logGen": 1,
                        "settled": True,
                        "finishedAt": NOW,
                        "exitCode": 1,
                        "result": {"attempted": [DCC], "geoipReady": True},
                    }
                )
                + "\n"
            ).encode(),
        }
        completed = after or schedule_reply(
            {DCC: dcc_entry(last_run=NOW + 5, next_due=NOW + 80_000)},
            {DCC: NOW + 5} if successful is None else successful,
        )
        self.schedules = [
            before or schedule_reply({DCC: dcc_entry(last_run=0, next_due=NOW)}, []),
            completed,
            completed,
        ]
        self.vm = self

        def ssh(*argv: str, **_kwargs: Any) -> subprocess.CompletedProcess[str]:
            if argv == ("date", "-v+23H", "-v0M", "+%H"):
                return subprocess.CompletedProcess(argv, 0, "04\n", "")
            if argv == ("date", "+%s"):
                return subprocess.CompletedProcess(argv, 0, f"{NOW}\n", "")
            if argv == ("ps ax -o command",):
                return subprocess.CompletedProcess(
                    argv,
                    0,
                    "root 1 pfb_core --maintenance-cmd /usr/local/pkg/pfblockerng/pfb_core_maintenance.sh\n",
                    "",
                )
            if argv == ("test", "-f", acceptance.SENTINEL):
                return subprocess.CompletedProcess(argv, 0, "", "")
            if len(argv) != 1:
                pytest.fail(f"unapproved fake guest command: {argv!r}")

            command = argv[0]
            self.diagnostic_commands.append(command)
            tokens = shlex.split(command)

            def file_data(path: str) -> bytes | None:
                if path in self.missing_receipts:
                    return None
                if path == EXTRAS_LOG:
                    return self.extras_before + (self.extras_delta if self.retry_started else b"")
                return self.private_files.get(path)

            if tokens[0] == "stat":
                path = tokens[-1]
                data = file_data(path)
                if data is None:
                    return subprocess.CompletedProcess(argv, 1, "", f"missing diagnostic file: {path}\n")
                inode = 7001 if path == EXTRAS_LOG else 7002
                return subprocess.CompletedProcess(argv, 0, f"{inode} {len(data)}\n", "")
            if tokens[0] == "head":
                limit, path = int(tokens[2]), tokens[3]
                data = file_data(path)
                if data is None:
                    return subprocess.CompletedProcess(argv, 1, "", f"missing diagnostic file: {path}\n")
                return subprocess.CompletedProcess(argv, 0, data[:limit].decode("utf-8"), "")
            if tokens[0] == "sha256":
                path = tokens[-1]
                data = file_data(path)
                if data is None:
                    return subprocess.CompletedProcess(argv, 1, "", f"missing diagnostic file: {path}\n")
                return subprocess.CompletedProcess(argv, 0, hashlib.sha256(data).hexdigest() + "\n", "")
            if tokens[0] == "tail":
                path = tokens[3] if "|" not in tokens else tokens[3]
                data = file_data(path)
                if data is None:
                    return subprocess.CompletedProcess(argv, 1, "", f"missing diagnostic file: {path}\n")
                if "|" not in tokens:
                    count = int(tokens[2])
                    return subprocess.CompletedProcess(argv, 0, data[-count:].decode("utf-8"), "")
                offset = int(tokens[2].removeprefix("+")) - 1
                head_index = tokens.index("head")
                count = int(tokens[head_index + 2])
                self.range_sizes.append(count)
                selected = data[offset : offset + count]
                if "base64" in tokens:
                    output = base64.b64encode(selected).decode("ascii") + "\n"
                else:
                    output = hashlib.sha256(selected).hexdigest() + "\n"
                return subprocess.CompletedProcess(argv, 0, output, "")
            pytest.fail(f"unapproved fake guest diagnostic command: {command!r}")

        self.ssh = ssh

        def config_set(_vm: Any, path: str, value: str) -> None:
            self.config[path] = value

        def config_get(_vm: Any, path: str) -> str:
            self.config_reads.append((len(self.installs), path))
            return self.config.get(path, "")

        def force_install(_vm: Any, pkg: Path) -> None:
            self.install_attempts.append(pkg.name)
            self.installs.append(self.config.copy())
            if pkg.name == "previous.pkg":
                self.installed_package = "previous"
                if self.previous_install_fails:
                    raise RuntimeError("previous package install failed after partial replacement")
            elif self.current_restore_fails:
                self.installed_package = "partial-current"
                raise RuntimeError("current package restoration failed")
            else:
                self.installed_package = "current"

        def core_call(_vm: Any, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
            self.core_calls.append((method, dict(params or {})))
            if method == "GetSchedule":
                return self.schedules.pop(0)
            if method == "StartUpdate":
                self.retry_started = True
                return self.start_reply
            pytest.fail(f"unexpected public Core method: {method}")

        monkeypatch.setenv("SMOKE_PKG", "/tmp/current.pkg")
        monkeypatch.setenv("SMOKE_SCHEDULED_EXCEPTION", "allow")
        for name in (
            "deploy",
            "ensure_dnsbl_vip",
            "use_stub_for_safesearch",
            "inject",
            "set_package_enabled",
            "reload",
            "set_pfb_keep",
            "wait_unbound_ready",
            "unblock_egress",
            "collect_host_diagnostics",
        ):
            monkeypatch.setattr(h, name, lambda *_args, **_kwargs: None)
        monkeypatch.setattr(h, "unique_domain", lambda label: f"{label}.example")
        monkeypatch.setattr(h, "write_local_feed", lambda *_args, **_kwargs: "file:///local/feed")
        monkeypatch.setattr(h, "config_set", config_set)
        monkeypatch.setattr(h, "config_get", config_get)
        monkeypatch.setattr(
            h,
            "tell_core_the_settings_changed",
            lambda _vm: setattr(self, "settings_notices", self.settings_notices + 1),
        )
        monkeypatch.setattr(h, "core_call", core_call)
        monkeypatch.setattr(h, "core_update_view", lambda _vm: {"update": None})

        def core_update_log(_vm: Any) -> str:
            self.public_log_reads += 1
            return self.public_update_log

        monkeypatch.setattr(h, "core_update_log", core_update_log)
        monkeypatch.setattr(
            h,
            "await_core_update_end",
            lambda *_args, **_kwargs: {
                "running": False,
                "update": {"trigger": "retry", "result": self.update_result},
            },
        )
        monkeypatch.setattr(h, "dns_probe", lambda *_args, **_kwargs: "198.51.100.9")
        monkeypatch.setattr(h, "is_vip", lambda _answer: True)
        monkeypatch.setattr(acceptance, "_assert_no_dispatch", lambda _vm, phase: self.phases.append(phase))
        monkeypatch.setattr(acceptance, "_force_install", force_install)
        monkeypatch.setattr(acceptance, "await_core_up", lambda _vm: None)

    def run(self) -> tuple[Any, Any]:
        fixture = getattr(acceptance.maintenance_vm, "__wrapped__")
        generator = fixture(self.vm, object(), Path("/tmp/previous.pkg"))
        return generator, next(generator)


def test_dcc_setup_canonicalizes_the_guest_hour_and_uses_public_retry(monkeypatch: pytest.MonkeyPatch) -> None:
    setup = DccSetup(monkeypatch)
    generator, yielded = setup.run()
    try:
        assert yielded is setup.vm
        assert setup.config[HOUR] == "4" and setup.config[MINUTE] == "0"
        assert setup.config[f"{h.CFG_GLOBAL}/pfb_scheduled_feed_updates"] == ""
        assert setup.config[BLACKLIST_ENABLE] == "Disable"
        assert [snapshot[HOUR] for snapshot in setup.installs] == ["4", "4"]
        assert [snapshot[MINUTE] for snapshot in setup.installs] == ["0", "0"]
        assert [(n, key) for n, key in setup.config_reads if key in (HOUR, MINUTE)] == [
            (1, HOUR),
            (1, MINUTE),
            (2, HOUR),
            (2, MINUTE),
        ]
        assert setup.settings_notices >= 1
        assert [call for call in setup.core_calls if call[0] == "StartUpdate"] == [
            ("StartUpdate", {"trigger": "retry"})
        ]
    finally:
        generator.close()


@pytest.mark.parametrize(
    ("case", "after", "update_result", "message"),
    [
        (
            "still-due",
            schedule_reply({DCC: dcc_entry(last_run=NOW + 5, next_due=NOW)}, {DCC: NOW + 5}),
            "success",
            "DCC nextDue is not outside",
        ),
        (
            "failed-retry",
            schedule_reply({DCC: dcc_entry(last_run=0, next_due=NOW)}, []),
            "failed",
            "retry Update failed",
        ),
        (
            "other-extra",
            schedule_reply(
                {
                    DCC: dcc_entry(last_run=NOW + 5, next_due=NOW + 80_000),
                    BLACKLIST: dcc_entry(last_run=0, next_due=NOW),
                },
                {DCC: NOW + 5},
            ),
            "success",
            "enabled extras are not DCC-only",
        ),
        (
            "too-soon",
            schedule_reply({DCC: dcc_entry(last_run=NOW + 5, next_due=NOW + 2160)}, {DCC: NOW + 5}),
            "success",
            "DCC nextDue is not outside",
        ),
    ],
)
def test_dcc_setup_rejects_unsafe_public_state(
    monkeypatch: pytest.MonkeyPatch, case: str, after: dict[str, Any], update_result: str, message: str
) -> None:
    setup = DccSetup(monkeypatch, after=after, update_result=update_result)
    with pytest.raises(AssertionError, match=message):
        setup.run()
    assert any(method == "StartUpdate" for method, _params in setup.core_calls), case


def test_due_other_extra_blocks_public_retry(monkeypatch: pytest.MonkeyPatch) -> None:
    before = schedule_reply(
        {
            DCC: dcc_entry(last_run=0, next_due=NOW),
            BLACKLIST: dcc_entry(last_run=0, next_due=NOW),
        },
        [],
    )
    setup = DccSetup(monkeypatch, before=before)
    with pytest.raises(AssertionError, match="enabled extras are not DCC-only"):
        setup.run()
    assert not any(method == "StartUpdate" for method, _params in setup.core_calls)


def test_naturally_completed_dcc_needs_no_private_reset(monkeypatch: pytest.MonkeyPatch) -> None:
    setup = DccSetup(monkeypatch)
    finished = schedule_reply(
        {DCC: dcc_entry(last_run=NOW - 10, next_due=NOW + 80_000)},
        {DCC: NOW - 10},
    )
    setup.schedules = [finished, finished]
    generator, yielded = setup.run()
    try:
        assert yielded is setup.vm
        assert not any(method == "StartUpdate" for method, _params in setup.core_calls)
    finally:
        generator.close()


def test_partial_previous_install_failure_still_restores_current_package(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    setup = DccSetup(monkeypatch, previous_install_fails=True)
    with pytest.raises(RuntimeError, match="previous package install failed after partial replacement"):
        setup.run()
    assert setup.install_attempts == ["previous.pkg", "current.pkg"]
    assert setup.installed_package == "current"


def test_current_restore_failure_reports_primary_and_cleanup_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    setup = DccSetup(
        monkeypatch,
        previous_install_fails=True,
        current_restore_fails=True,
    )
    with pytest.raises(ExceptionGroup) as raised:
        setup.run()
    assert [str(error) for error in raised.value.exceptions] == [
        "previous package install failed after partial replacement",
        "current package restoration failed",
    ]
    assert setup.install_attempts == ["previous.pkg", "current.pkg"]


def test_failed_retry_diagnostics_capture_worker_receipts_and_child_stderr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    setup = DccSetup(monkeypatch, update_result="failed")
    with pytest.raises(AssertionError, match="retry Update failed") as raised:
        setup.run()

    message = str(raised.value)
    for evidence in (
        "update.log.request",
        "update.log.result",
        "update.log.status",
        "extra:dcc",
        "DCC child stderr: download failed",
        "outer PHP update warning",
    ):
        assert evidence in message, evidence
    assert setup.public_log_reads == 1
    assert any(EXTRAS_LOG in command for command in setup.diagnostic_commands)
    assert setup.retry_started


def test_failed_retry_captures_worker_receipts_and_child_stderr_before_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    setup = DccSetup(monkeypatch, update_result="failed")
    with pytest.raises(AssertionError, match="retry Update failed") as raised:
        setup.run()

    message = str(raised.value)
    for evidence in (
        "update.log.request",
        "update.log.result",
        "update.log.status",
        "extra:dcc",
        "DCC child stderr: download failed",
        "outer PHP update warning",
    ):
        assert evidence in message, evidence
    assert setup.public_log_reads == 1
    assert any(EXTRAS_LOG in command for command in setup.diagnostic_commands)
    assert setup.retry_started


def test_missing_worker_receipt_is_diagnostic_not_primary_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    setup = DccSetup(monkeypatch, update_result="failed", missing_receipts={UPDATE_STATUS})
    with pytest.raises(AssertionError, match="retry Update failed") as raised:
        setup.run()

    message = str(raised.value)
    assert "update.log.status" in message and "missing diagnostic file" in message
    assert "DCC child stderr: download failed" in message


def test_large_extras_delta_is_hashed_with_bounded_tail(monkeypatch: pytest.MonkeyPatch) -> None:
    delta = b"x" * 70_000 + b"DCC-LARGE-TAIL"
    setup = DccSetup(monkeypatch, update_result="failed", extras_delta=delta)
    with pytest.raises(AssertionError, match="retry Update failed") as raised:
        setup.run()

    message = str(raised.value)
    assert str(len(delta)) in message
    assert hashlib.sha256(delta).hexdigest() in message
    assert "DCC-LARGE-TAIL" in message
    assert len(message) < 50_000
    assert setup.range_sizes and max(setup.range_sizes) <= DIAGNOSTIC_CHUNK
