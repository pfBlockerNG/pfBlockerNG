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
        seed_fails: bool = False,
        geoip_teardown_fails: bool = False,
        unblock_fails: bool = False,
        diagnostics_fails: bool = False,
        worker_result: dict[str, Any] | None = None,
        worker_request: dict[str, Any] | None = None,
        worker_status: dict[str, Any] | None = None,
        result_payload: bytes | None = None,
        missing_receipts: set[str] | None = None,
        read_error_paths: set[str] | None = None,
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
        self.seed_fails = seed_fails
        self.geoip_teardown_fails = geoip_teardown_fails
        self.unblock_fails = unblock_fails
        self.diagnostics_fails = diagnostics_fails
        self.worker_result = worker_result
        self.worker_request = worker_request
        self.worker_status = worker_status
        self.result_payload = result_payload
        self.events: list[str] = []
        self.seed_state: dict[str, Any] | None = None
        self.fixture_generator: Any = None
        self.phases: list[str] = []
        self.settings_notices = 0
        self.start_reply = {"status": 200, "body": [], "error": None}
        self.update_result = update_result
        self.missing_receipts = missing_receipts or set()
        self.read_error_paths = read_error_paths or set()
        self.extras_before = b"existing extras\n"
        self.extras_delta = extras_delta if extras_delta is not None else b"DCC child stderr: download failed\n"
        self.public_update_log = "outer PHP update warning\n"
        self.public_log_reads = 0
        self.diagnostic_commands: list[str] = []
        self.range_requests: list[tuple[str, int]] = []
        self.range_sizes: list[int] = []
        self.retry_started = False
        request = dict(
            self.worker_request
            if self.worker_request is not None
            else {"trigger": "retry", "scope": "both", "force": "none", "extras": [DCC]}
        )
        default_worker_result = (
            {"outcomes": {DCC: "success"}, "attempted": [], "geoipReady": True}
            if update_result == "success"
            else {"outcomes": {}, "attempted": [DCC], "geoipReady": True}
        )
        worker_result = dict(self.worker_result if self.worker_result is not None else default_worker_result)
        status_receipt = {
            "version": 1,
            "nonce": "a" * 64,
            "path": "/usr/local/pkg/pfblockerng/pfb_core_update.sh",
            "request": request,
            "startedAt": NOW,
            "logGen": 1,
            "settled": True,
            "finishedAt": NOW,
            "exitCode": 0 if update_result == "success" else 1,
            "result": worker_result,
        }
        if self.worker_status is not None:
            status_receipt.update(self.worker_status)
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
            UPDATE_RESULT: (
                self.result_payload
                if self.result_payload is not None
                else (json.dumps({"version": 1, **worker_result}) + "\n").encode()
            ),
            UPDATE_STATUS: (json.dumps(status_receipt) + "\n").encode(),
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
                if path in self.read_error_paths and "|" in tokens:
                    return subprocess.CompletedProcess(argv, 1, "", f"diagnostic read failed: {path}\n")
                if "|" not in tokens:
                    count = int(tokens[2])
                    return subprocess.CompletedProcess(argv, 0, data[-count:].decode("utf-8"), "")
                offset = int(tokens[2].removeprefix("+")) - 1
                head_index = tokens.index("head")
                count = int(tokens[head_index + 2])
                self.range_requests.append((path, count))
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
            self.events.append(f"install:{pkg.name}")
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
                self.events.append("retry-start")
                return self.start_reply
            pytest.fail(f"unexpected public Core method: {method}")

        def reload(_vm: Any, scope: str, **_kwargs: Any) -> None:
            self.events.append(f"reload:{scope}")

        def tell_settings(_vm: Any) -> None:
            self.settings_notices += 1
            self.events.append("settings-refresh")

        def await_core_up(_vm: Any) -> None:
            self.events.append("core-ready")

        def seed_geoip_dataset(_vm: Any, **_kwargs: Any) -> None:
            self.seed_state = {
                "installed_package": self.installed_package,
                "install_attempts": self.install_attempts.copy(),
                "settings_notices": self.settings_notices,
                "events": self.events.copy(),
            }
            self.events.append("geoip-seed")
            if self.seed_fails:
                raise RuntimeError("GeoIP seed failed")

        def teardown_geoip_dataset(_vm: Any, **_kwargs: Any) -> None:
            self.events.append("geoip-teardown")
            if self.geoip_teardown_fails:
                raise RuntimeError("GeoIP teardown failed")

        def unblock_egress() -> None:
            self.events.append("egress-unblock")
            if self.unblock_fails:
                raise RuntimeError("egress unblock failed")

        def collect_host_diagnostics(_vm: Any) -> None:
            self.events.append("host-diagnostics")
            if self.diagnostics_fails:
                raise RuntimeError("host diagnostics failed")

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
        monkeypatch.setattr(h, "reload", reload)
        monkeypatch.setattr(h, "seed_geoip_dataset", seed_geoip_dataset)
        monkeypatch.setattr(h, "teardown_geoip_dataset", teardown_geoip_dataset)
        monkeypatch.setattr(h, "unblock_egress", unblock_egress)
        monkeypatch.setattr(h, "collect_host_diagnostics", collect_host_diagnostics)
        monkeypatch.setattr(h, "unique_domain", lambda label: f"{label}.example")
        monkeypatch.setattr(h, "write_local_feed", lambda *_args, **_kwargs: "file:///local/feed")
        monkeypatch.setattr(h, "config_set", config_set)
        monkeypatch.setattr(h, "config_get", config_get)
        monkeypatch.setattr(h, "tell_core_the_settings_changed", tell_settings)
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
        monkeypatch.setattr(acceptance, "await_core_up", await_core_up)

    def run(self) -> tuple[Any, Any]:
        fixture = getattr(acceptance.maintenance_vm, "__wrapped__")
        generator = fixture(self.vm, object(), Path("/tmp/previous.pkg"))
        self.fixture_generator = generator
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


def test_worker_receipt_diagnostics_read_in_bounded_chunks(monkeypatch: pytest.MonkeyPatch) -> None:
    setup = DccSetup(monkeypatch, update_result="failed")
    with pytest.raises(AssertionError, match="retry Update failed"):
        setup.run()

    receipt_paths = {UPDATE_REQUEST, UPDATE_RESULT, UPDATE_STATUS}
    receipt_reads = [(path, count) for path, count in setup.range_requests if path in receipt_paths]
    assert {path for path, _count in receipt_reads} == receipt_paths
    assert receipt_reads and max(count for _path, count in receipt_reads) <= DIAGNOSTIC_CHUNK


def test_small_binary_receipt_diagnostic_preserves_exact_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    setup = DccSetup(monkeypatch)
    payload = b"\x00\xffstatus\x80\xfe\n"
    setup.private_files[UPDATE_RESULT] = payload

    report = acceptance._diagnostic_file(setup.vm, "result", UPDATE_RESULT, 1024)

    assert f"data={payload!r}" in report
    assert setup.range_requests == [(UPDATE_RESULT, len(payload))]


def test_oversized_receipt_diagnostic_uses_bounded_head_and_tail_samples(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    setup = DccSetup(monkeypatch)
    limit = 32 * 1024
    payload = bytes(index % 251 for index in range(limit + 70_000))
    setup.private_files[UPDATE_REQUEST] = payload

    report = acceptance._diagnostic_file(setup.vm, "request", UPDATE_REQUEST, limit)

    head = payload[:DIAGNOSTIC_CHUNK]
    tail = payload[-acceptance.DIAGNOSTIC_TAIL :]
    assert f"bytes={len(payload)}" in report
    assert hashlib.sha256(head).hexdigest() in report
    assert hashlib.sha256(tail).hexdigest() in report
    assert f"head_data={head!r}" in report
    assert f"tail_data={tail!r}" in report
    assert len(setup.range_requests) == 2
    assert sum(count for _path, count in setup.range_requests) <= DIAGNOSTIC_CHUNK + acceptance.DIAGNOSTIC_TAIL
    assert max(count for _path, count in setup.range_requests) <= DIAGNOSTIC_CHUNK
    assert not any("sha256 -q" in command for command in setup.diagnostic_commands)


def test_receipt_read_error_does_not_replace_retry_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    setup = DccSetup(monkeypatch, update_result="failed", read_error_paths={UPDATE_STATUS})
    with pytest.raises(AssertionError, match="retry Update failed") as raised:
        setup.run()

    message = str(raised.value)
    assert "update.log.status" in message and "diagnostic read failed" in message


@pytest.mark.parametrize(
    ("case", "worker_result", "worker_request", "worker_status", "missing_receipts"),
    [
        ("missing-outcome", {"outcomes": {}, "attempted": [], "geoipReady": True}, None, None, None),
        (
            "retry-cap",
            {"outcomes": {DCC: "retry-cap-reached"}, "attempted": [], "geoipReady": True},
            None,
            None,
            None,
        ),
        (
            "other-outcome",
            {"outcomes": {DCC: "success", BLACKLIST: "success"}, "attempted": [], "geoipReady": True},
            None,
            None,
            None,
        ),
        (
            "other-attempt",
            {"outcomes": {DCC: "success"}, "attempted": [DCC, BLACKLIST], "geoipReady": True},
            None,
            None,
            None,
        ),
        ("geoip-not-ready", {"outcomes": {DCC: "success"}, "attempted": [], "geoipReady": False}, None, None, None),
        (
            "other-request-extra",
            None,
            {"trigger": "retry", "scope": "both", "force": "none", "extras": [DCC, BLACKLIST]},
            None,
            None,
        ),
        ("unsettled", None, None, {"settled": False}, None),
        ("worker-exit-failed", None, None, {"exitCode": 1}, None),
        ("missing-status", None, None, None, {UPDATE_STATUS}),
    ],
)
def test_retry_requires_exclusive_success_receipt(
    monkeypatch: pytest.MonkeyPatch,
    case: str,
    worker_result: dict[str, Any] | None,
    worker_request: dict[str, Any] | None,
    worker_status: dict[str, Any] | None,
    missing_receipts: set[str] | None,
) -> None:
    setup = DccSetup(
        monkeypatch,
        worker_result=worker_result,
        worker_request=worker_request,
        worker_status=worker_status,
        missing_receipts=missing_receipts,
    )
    try:
        with pytest.raises(AssertionError, match="DCC retry receipt"):
            setup.run()
    finally:
        if setup.fixture_generator is not None:
            setup.fixture_generator.close()
    assert setup.retry_started, case


def test_success_receipt_requires_last_successful_check_advancement(monkeypatch: pytest.MonkeyPatch) -> None:
    previous = NOW - 100
    before = schedule_reply({DCC: dcc_entry(last_run=previous, next_due=NOW)}, {DCC: previous})
    after = schedule_reply({DCC: dcc_entry(last_run=previous, next_due=NOW + 80_000)}, {DCC: previous})
    setup = DccSetup(monkeypatch, before=before, after=after)

    with pytest.raises(AssertionError, match="retry did not complete DCC successfully"):
        setup.run()


def test_geoip_seed_runs_after_current_install_refresh_and_before_retry(monkeypatch: pytest.MonkeyPatch) -> None:
    setup = DccSetup(monkeypatch)
    generator, yielded = setup.run()
    try:
        assert yielded is setup.vm
        assert setup.seed_state is not None
        assert setup.seed_state["installed_package"] == "current"
        assert setup.seed_state["install_attempts"] == ["previous.pkg", "current.pkg"]
        assert setup.seed_state["settings_notices"] >= 1
        events = setup.seed_state["events"]
        current_install = max(index for index, event in enumerate(events) if event == "install:current.pkg")
        current_reload = max(index for index, event in enumerate(events) if event == "reload:update")
        assert current_install < current_reload < events.index("settings-refresh") < events.index("core-ready")
        assert setup.events.index("geoip-seed") < setup.events.index("retry-start")
        assert setup.retry_started
    finally:
        generator.close()
    assert setup.events.index("geoip-seed") < setup.events.index("geoip-teardown")


def test_geoip_seed_failure_blocks_retry_and_runs_teardown(monkeypatch: pytest.MonkeyPatch) -> None:
    setup = DccSetup(monkeypatch, seed_fails=True, geoip_teardown_fails=True)
    try:
        with pytest.raises(ExceptionGroup) as raised:
            setup.run()
    finally:
        if setup.fixture_generator is not None:
            setup.fixture_generator.close()

    assert [str(error) for error in raised.value.exceptions] == ["GeoIP seed failed", "GeoIP teardown failed"]
    assert not setup.retry_started
    assert setup.events.index("geoip-seed") < setup.events.index("geoip-teardown")


def test_geoip_teardown_failure_is_visible_after_successful_retry(monkeypatch: pytest.MonkeyPatch) -> None:
    setup = DccSetup(monkeypatch, geoip_teardown_fails=True)
    generator, _yielded = setup.run()

    with pytest.raises(ExceptionGroup) as raised:
        next(generator)

    assert [str(error) for error in raised.value.exceptions] == ["GeoIP teardown failed"]
    assert setup.retry_started


def test_geoip_cleanup_groups_every_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    setup = DccSetup(
        monkeypatch,
        geoip_teardown_fails=True,
        unblock_fails=True,
        diagnostics_fails=True,
    )
    generator, _yielded = setup.run()

    with pytest.raises(ExceptionGroup) as raised:
        next(generator)

    assert [str(error) for error in raised.value.exceptions] == [
        "GeoIP teardown failed",
        "egress unblock failed",
        "host diagnostics failed",
    ]


def _jsonl_payload(*lines: dict[str, Any] | str) -> bytes:
    return ("\n".join(line if isinstance(line, str) else json.dumps(line) for line in lines) + "\n").encode()


def test_incremental_and_final_success_result_records_are_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    final = {"version": 1, "outcomes": {DCC: "success"}, "attempted": [], "geoipReady": True}
    payload = _jsonl_payload({"version": 1, "outcomes": {DCC: "success"}}, final)
    setup = DccSetup(monkeypatch, result_payload=payload)
    generator, yielded = setup.run()
    try:
        assert yielded is setup.vm
        assert setup.retry_started
    finally:
        generator.close()


def test_single_line_aggregate_result_remains_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    final = {"version": 1, "outcomes": {DCC: "success"}, "attempted": [], "geoipReady": True}
    setup = DccSetup(monkeypatch, result_payload=_jsonl_payload({"version": 1, **final}))
    generator, yielded = setup.run()
    try:
        assert yielded is setup.vm
        assert setup.retry_started
    finally:
        generator.close()


@pytest.mark.parametrize(
    ("case", "payload"),
    [
        (
            "malformed-middle",
            _jsonl_payload(
                {"version": 1, "outcomes": {DCC: "success"}},
                "{not-json",
                {"version": 1, "outcomes": {DCC: "success"}, "attempted": [], "geoipReady": True},
            ),
        ),
        (
            "trailing-garbage",
            _jsonl_payload(
                {"version": 1, "outcomes": {DCC: "success"}, "attempted": [], "geoipReady": True},
                "garbage",
            ),
        ),
        (
            "wrong-version",
            _jsonl_payload(
                {"version": 2, "outcomes": {DCC: "success"}},
                {"version": 1, "outcomes": {DCC: "success"}, "attempted": [], "geoipReady": True},
            ),
        ),
        (
            "contradicting-outcome",
            _jsonl_payload(
                {"version": 1, "outcomes": {DCC: "retry-cap-reached"}},
                {"version": 1, "outcomes": {DCC: "success"}, "attempted": [], "geoipReady": True},
            ),
        ),
        ("missing-final-aggregate", _jsonl_payload({"version": 1, "outcomes": {DCC: "success"}})),
        ("empty-result", b"\n \n"),
    ],
)
def test_jsonl_result_rejects_bad_prefix_or_missing_aggregate(
    monkeypatch: pytest.MonkeyPatch, case: str, payload: bytes
) -> None:
    setup = DccSetup(monkeypatch, result_payload=payload)
    with pytest.raises(AssertionError, match="DCC retry receipt result"):
        setup.run()


def test_anchored_ledger_accepts_observed_non_epoch_aligned_due() -> None:
    before = {"last_run": 900, "next_due": 1001, "jitter": 0}
    current = {"last_run": 1301, "next_due": 1901, "jitter": 0}

    acceptance._assert_duty_ledger_advance("ss_refresh", before, current)


@pytest.mark.parametrize(
    ("case", "current"),
    [
        ("last-run-before-due", {"last_run": 1000, "next_due": 1901, "jitter": 0}),
        ("late-catchup", {"last_run": 1901, "next_due": 2801, "jitter": 0}),
        ("last-run-plus-interval", {"last_run": 1301, "next_due": 2201, "jitter": 0}),
        ("wrong-interval", {"last_run": 1301, "next_due": 1900, "jitter": 0}),
        ("next-due-not-future", {"last_run": 1301, "next_due": 1300, "jitter": 0}),
        ("nonzero-jitter", {"last_run": 1301, "next_due": 1901, "jitter": 1}),
    ],
)
def test_anchored_ledger_rejects_phase_or_interval_errors(case: str, current: dict[str, int]) -> None:
    before = {"last_run": 900, "next_due": 1001, "jitter": 0}
    with pytest.raises(AssertionError):
        acceptance._assert_duty_ledger_advance("ss_refresh", before, current)
