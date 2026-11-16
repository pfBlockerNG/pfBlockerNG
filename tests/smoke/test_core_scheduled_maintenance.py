"""#3996 real quarter-hour acceptance; no scheduler clock/state injection.

Only the exact explicitly opted-in case may enter scheduled_maintenance.
SafeSearch CSV effects and real 900-second duty ledgers are the live oracles.
Other duty branches remain covered by the real PHP suite, not claimed here.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shlex
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from . import helpers as h
from .conftest import SmokeVM, _StubDnsServer
from .test_smoke_core_api import await_core_up
from .test_smoke_tick import (
    _drain_pending_apply,
    _read_ledger,
    _remove_ss_row,
    _reset_ss_extdns,
    _seed_ss_refresh_positive_control,
)

SENTINEL = "/var/db/pfblockerng/.pfb_cron_disable"
PHP = "/usr/local/bin/php"
CLI = "/usr/local/www/pfblockerng/pfblockerng.php"
DISPATCH = re.compile(r"pfblockerng\.php\s+(?:cron-tick|tick|cron)(?:\s|$)")
DUTIES = ("ss_refresh", "apply_reconcile")
MARKER = "SafeSearch CNAME fallback IPs refreshed"
SCHEDULE_HOUR = f"{h.CFG_GLOBAL}/pfb_schedule_hour"
SCHEDULE_MINUTE = f"{h.CFG_GLOBAL}/pfb_schedule_minute"
DCC_ID = "extra:dcc"
WINDOW_BOUND_SECONDS = 2160
EXTRAS_LOG = f"{h.PFB_LOGDIR}/extras.log"
DIAGNOSTIC_CHUNK = 16_384
DIAGNOSTIC_SMALL_EXTRAS = 64 * 1024
DIAGNOSTIC_TAIL = 16 * 1024
DIAGNOSTIC_TIMEOUT = 10
UPDATE_RECEIPTS = (
    ("request", f"{h.CORE_STATE_DIR}/update.log.request", 4 * 1024 * 1024),
    ("result", f"{h.CORE_STATE_DIR}/update.log.result", 1 * 1024 * 1024),
    ("status", f"{h.CORE_STATE_DIR}/update.log.status", 4 * 1024 * 1024),
)


def _schedule_view(
    vm: SmokeVM, phase: str, reply: dict[str, Any] | None = None
) -> tuple[dict[str, int], dict[str, int], dict[str, Any]]:
    reply = h.core_call(vm, "GetSchedule", {}) if reply is None else reply
    assert reply["status"] == 200, f"{phase}: GetSchedule failed: {reply}"
    body = reply["body"]
    assert isinstance(body, dict), f"{phase}: malformed GetSchedule body: {reply}"
    assert body.get("scheduled") is False and body.get("feeds") is None, f"{phase}: feeds remain eligible: {reply}"
    extras = body.get("extras")
    assert isinstance(extras, dict) and set(extras) == {DCC_ID}, f"{phase}: enabled extras are not DCC-only: {reply}"
    dcc = extras[DCC_ID]
    assert isinstance(dcc, dict) and type(dcc.get("lastRun")) is int and type(dcc.get("nextDue")) is int, (
        f"{phase}: malformed DCC schedule entry: {reply}"
    )
    checks = body.get("lastSuccessfulCheck")
    if type(checks) is list:
        assert checks == [], f"{phase}: malformed empty lastSuccessfulCheck: {reply}"
        checks = {}
    assert isinstance(checks, dict) and all(
        isinstance(item, str) and type(stamp) is int and stamp > 0 for item, stamp in checks.items()
    ), f"{phase}: malformed lastSuccessfulCheck: {reply}"
    return dcc, checks, reply


def _diagnostic_command(vm: SmokeVM, command: str) -> tuple[subprocess.CompletedProcess[str] | None, str | None]:
    try:
        result = vm.ssh(command, timeout=DIAGNOSTIC_TIMEOUT)
    except Exception as error:
        return None, f"{type(error).__name__}: {error}"
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "no command output"
        return None, f"rc={result.returncode}: {detail}"
    return result, None


def _diagnostic_file_state(vm: SmokeVM, path: str) -> tuple[tuple[int, int] | None, str | None]:
    result, error = _diagnostic_command(vm, f"stat -f '%i %z' {shlex.quote(path)}")
    if error is not None or result is None:
        return None, error
    fields = result.stdout.split()
    if len(fields) != 2 or not all(field.isdigit() for field in fields):
        return None, f"malformed stat response: {result.stdout!r}"
    return (int(fields[0]), int(fields[1])), None


def _read_diagnostic_range(vm: SmokeVM, path: str, offset: int, length: int) -> tuple[bytes | None, str | None]:
    data = bytearray()
    for start in range(0, length, DIAGNOSTIC_CHUNK):
        count = min(DIAGNOSTIC_CHUNK, length - start)
        command = f"tail -c +{offset + start + 1} {shlex.quote(path)} | head -c {count} | base64"
        result, error = _diagnostic_command(vm, command)
        if error is not None or result is None:
            return None, error
        try:
            block = base64.b64decode(result.stdout)
        except ValueError as error:
            return None, f"base64 decode failed: {error}"
        if len(block) != count:
            return None, f"short diagnostic read: expected {count} bytes, got {len(block)}"
        data.extend(block)
    return bytes(data), None


def _hash_diagnostic_range(
    vm: SmokeVM, path: str, offset: int, length: int
) -> tuple[str | None, bytes | None, str | None]:
    digest = hashlib.sha256()
    tail = bytearray()
    for start in range(0, length, DIAGNOSTIC_CHUNK):
        count = min(DIAGNOSTIC_CHUNK, length - start)
        data, error = _read_diagnostic_range(vm, path, offset + start, count)
        if error is not None or data is None:
            return None, None, error
        digest.update(data)
        tail.extend(data)
        if len(tail) > DIAGNOSTIC_TAIL:
            del tail[:-DIAGNOSTIC_TAIL]
    return digest.hexdigest(), bytes(tail), None


def _diagnostic_file(vm: SmokeVM, name: str, path: str, limit: int) -> str:
    label = f"{name} {path}"
    state, error = _diagnostic_file_state(vm, path)
    if state is None:
        return f"{label}: missing/unavailable: {error}"
    inode, size = state
    if size <= limit:
        data, error = _read_diagnostic_range(vm, path, 0, size)
        if error is not None or data is None:
            return f"{label}: read unavailable: {error}"
        return f"{label} inode={inode} bytes={size} sha256={hashlib.sha256(data).hexdigest()} data={data!r}"

    head_length = min(size, DIAGNOSTIC_CHUNK)
    head, head_error = _read_diagnostic_range(vm, path, 0, head_length)
    tail_length = min(size, DIAGNOSTIC_TAIL)
    tail, tail_error = _read_diagnostic_range(vm, path, size - tail_length, tail_length)
    head_hash = hashlib.sha256(head).hexdigest() if head is not None else f"unavailable: {head_error}"
    tail_hash = hashlib.sha256(tail).hexdigest() if tail is not None else f"unavailable: {tail_error}"
    head_data = repr(head) if head is not None else f"unavailable: {head_error}"
    tail_data = repr(tail) if tail is not None else f"unavailable: {tail_error}"
    return (
        f"{label} inode={inode} bytes={size} "
        f"head_sample_bytes={head_length} head_sha256={head_hash} head_data={head_data} "
        f"tail_sample_bytes={tail_length} tail_sha256={tail_hash} tail_data={tail_data}"
    )


def _read_worker_receipt(vm: SmokeVM, name: str) -> dict[str, Any]:
    for receipt_name, path, limit in UPDATE_RECEIPTS:
        if receipt_name == name:
            break
    else:
        raise AssertionError(f"unknown DCC retry receipt {name!r}")

    state, error = _diagnostic_file_state(vm, path)
    if state is None:
        raise AssertionError(f"DCC retry receipt {name} {path} unavailable: {error}")
    _, size = state
    if size > limit:
        raise AssertionError(f"DCC retry receipt {name} {path} exceeds {limit} bytes: {size}")
    data, error = _read_diagnostic_range(vm, path, 0, size)
    if error is not None or data is None:
        raise AssertionError(f"DCC retry receipt {name} {path} read failed: {error}")
    try:
        receipt = json.loads(data)
    except ValueError as error:
        raise AssertionError(f"DCC retry receipt {name} {path} is invalid JSON: {error}") from error
    if not isinstance(receipt, dict):
        raise AssertionError(f"DCC retry receipt {name} {path} is not an object")
    return receipt


def _assert_dcc_retry_receipts(vm: SmokeVM) -> None:
    request = _read_worker_receipt(vm, "request")
    result = _read_worker_receipt(vm, "result")
    status = _read_worker_receipt(vm, "status")
    expected_request = {"trigger": "retry", "scope": "both", "force": "none", "extras": [DCC_ID]}
    expected_result = {"outcomes": {DCC_ID: "success"}, "attempted": [], "geoipReady": True}

    assert request.get("version") == 1 and request.get("request") == expected_request, (
        f"DCC retry receipt request is not DCC-only: {request!r}"
    )
    assert all(status.get(field) == request.get(field) for field in ("version", "nonce", "path", "startedAt")), (
        f"DCC retry receipt request/status identity mismatch: request={request!r}, status={status!r}"
    )
    assert status.get("request") == expected_request, f"DCC retry receipt status request is not DCC-only: {status!r}"
    assert status.get("settled") is True and type(status.get("finishedAt")) is int and status["finishedAt"] > 0, (
        f"DCC retry receipt worker status is not settled: {status!r}"
    )
    assert status.get("exitCode") == 0, f"DCC retry receipt worker did not exit successfully: {status!r}"
    assert result == {"version": 1, **expected_result} and status.get("result") == expected_result, (
        f"DCC retry receipt result is not exactly a successful DCC outcome: result={result!r}, status={status!r}"
    )


def _extras_log_delta(vm: SmokeVM, before: tuple[int, int] | None, before_error: str | None) -> str:
    after, error = _diagnostic_file_state(vm, EXTRAS_LOG)
    if after is None:
        return f"extras.log unavailable after retry: {error}; before={before!r} {before_error!r}"
    inode, size = after
    if before is not None and before[0] == inode and size >= before[1]:
        offset, length, mode = before[1], size - before[1], "append"
    else:
        offset, length = 0, size
        mode = "new-or-replaced"
    if length <= DIAGNOSTIC_SMALL_EXTRAS:
        data, read_error = _read_diagnostic_range(vm, EXTRAS_LOG, offset, length)
        if read_error is not None or data is None:
            return f"extras.log {mode} bytes={length} read unavailable: {read_error}"
        return f"extras.log {mode} bytes={length} sha256={hashlib.sha256(data).hexdigest()} data={data!r}"
    digest_text, tail, capture_error = _hash_diagnostic_range(vm, EXTRAS_LOG, offset, length)
    tail_text = repr(tail) if tail is not None else f"unavailable: {capture_error}"
    digest_text = digest_text if digest_text is not None else f"unavailable: {capture_error}"
    return f"extras.log {mode} bytes={length} sha256={digest_text} bounded_tail={tail_text}"


def _retry_failure_diagnostics(vm: SmokeVM, extras_before: tuple[tuple[int, int] | None, str | None]) -> str:
    parts: list[str] = []
    try:
        parts.append(f"GetUpdate log={h.core_update_log(vm)!r}")
    except Exception as error:
        parts.append(f"GetUpdate log unavailable: {type(error).__name__}: {error}")
    for name, path, limit in UPDATE_RECEIPTS:
        try:
            parts.append(_diagnostic_file(vm, name, path, limit))
        except Exception as error:
            parts.append(f"{name} {path}: capture raised {type(error).__name__}: {error}")
    try:
        parts.append(_extras_log_delta(vm, *extras_before))
    except Exception as error:
        parts.append(f"extras.log capture raised {type(error).__name__}: {error}")
    return "\n".join(parts)


def _complete_due_dcc(vm: SmokeVM) -> int:
    dcc, checks, reply = _schedule_view(vm, "before-DCC-setup")
    previous = checks.get(DCC_ID)
    now = _epoch(vm, "before-DCC-setup")
    if previous is not None and dcc["lastRun"] > 0 and dcc["nextDue"] > now:
        assert dcc["nextDue"] > now + WINDOW_BOUND_SECONDS, (
            f"DCC nextDue is not outside the full bounded window: {reply}"
        )
        return previous

    before = h.core_update_view(vm)["update"]
    extras_before = _diagnostic_file_state(vm, EXTRAS_LOG)
    started = h.core_call(vm, "StartUpdate", {"trigger": "retry"})
    assert started["status"] == 200 and not started["body"], f"public StartUpdate retry was not admitted: {started}"
    ended = h.await_core_update_end(vm, before=before)
    update = ended.get("update")
    retry_succeeded = (
        ended.get("running") is False
        and isinstance(update, dict)
        and (update.get("trigger") == "retry" and update.get("result") == "success")
    )
    if not retry_succeeded:
        try:
            diagnostics = _retry_failure_diagnostics(vm, extras_before)
        except Exception as error:
            diagnostics = f"diagnostic capture failed: {type(error).__name__}: {error}"
        try:
            schedule = h.core_call(vm, "GetSchedule", {})
        except Exception as error:
            schedule = {"capture_error": f"{type(error).__name__}: {error}"}
        assert retry_succeeded, (
            f"retry Update failed: start={started!r}, end={ended!r}, schedule={schedule!r}; diagnostics:\n{diagnostics}"
        )
    _assert_dcc_retry_receipts(vm)
    after_dcc, after_checks, after = _schedule_view(vm, "after-DCC-retry")
    successful = after_checks.get(DCC_ID)
    assert successful is not None and (previous is None or successful > previous) and after_dcc["lastRun"] > 0, (
        f"retry did not complete DCC successfully: prior={previous!r}, schedule={after!r}"
    )
    return successful


def _assert_dcc_window_safe(vm: SmokeVM, successful: int) -> None:
    dcc, checks, reply = _schedule_view(vm, "immediately-before-yield")
    now = _epoch(vm, "immediately-before-yield")
    assert checks.get(DCC_ID, 0) >= successful and dcc["lastRun"] > 0, (
        f"DCC has no retained terminal success: expected at least {successful}, schedule={reply!r}"
    )
    assert dcc["nextDue"] > now + WINDOW_BOUND_SECONDS, (
        f"DCC nextDue is not outside the full bounded window: now={now}, schedule={reply!r}"
    )


def _schedule_hour_far_from_window(vm: SmokeVM) -> str:
    result = vm.ssh("date", "-v+23H", "-v0M", "+%H")
    assert result.returncode == 0 and result.stdout.strip().isdigit(), (
        f"could not derive a future local daily schedule slot: {result}"
    )
    hour = result.stdout.strip()
    assert 0 <= int(hour) <= 23, f"invalid guest local hour {hour!r}"
    return str(int(hour))


def _epoch(vm: SmokeVM, phase: str) -> int:
    result = vm.ssh("date", "+%s")
    assert result.returncode == 0 and result.stdout.strip().isdigit(), result
    now = int(result.stdout.strip())
    print(f"PFB_MAINTENANCE_TIME phase={phase} guest_epoch={now}", flush=True)
    return now


def _assert_no_dispatch(vm: SmokeVM, phase: str) -> None:
    result = vm.ssh("/usr/bin/crontab", "-l")
    if result.returncode == 0:
        root_crontab = result.stdout
    elif result.returncode == 1 and result.stdout == "" and result.stderr == "crontab: no crontab for root\n":
        # FreeBSD crontab(1) uses this exact ENOENT result when root has no per-user tab.
        root_crontab = ""
    else:
        raise AssertionError(f"{phase}: unreadable root crontab: {result}")

    effective = vm.ssh("/bin/cat", "/etc/crontab")
    assert effective.returncode == 0, f"{phase}: unreadable effective crontab: {effective}"
    commands = h._php_read_scalar(
        vm,
        "",
        "json_encode(array_column(config_get_path('cron/item', array()), 'command'))",
    )
    parsed = json.loads(commands)
    assert isinstance(parsed, list) and all(isinstance(command, str) for command in parsed), commands
    active_lines = [
        line
        for source in (root_crontab, effective.stdout)
        for line in source.splitlines()
        if not line.lstrip().startswith("#")
    ]
    assert not any(DISPATCH.search(command) for command in [*parsed, *active_lines]), (
        f"{phase}: competing config/effective dispatch job: {commands}"
    )
    assert vm.ssh("test", "-f", SENTINEL).returncode == 0, f"{phase}: sentinel missing"


def _force_install(vm: SmokeVM, pkg: Path) -> None:
    """Same forced pkg replacement as ha_versions, without its unrelated HA markers."""
    assert vm.ssh("test", "-f", SENTINEL).returncode == 0
    remote = f"/tmp/pfb-maintenance-{pkg.name}"
    with pkg.open("rb") as stream:
        copied = subprocess.run(
            vm.ssh_argv(f"cat > {shlex.quote(remote)}"),
            stdin=stream,
            capture_output=True,
            timeout=300,
            check=False,
        )
    assert copied.returncode == 0, copied.stderr
    try:
        abi = os.environ.get("SMOKE_ABI", "")
        add = f"pkg -o ABI={shlex.quote(abi)} add" if abi else "pkg add"
        result = vm.ssh(f"env ASSUME_ALWAYS_YES=yes {add} -f {shlex.quote(remote)}", timeout=600)
        assert result.returncode == 0, result.stdout + result.stderr
        assert not re.search(r"(?:POST-INSTALL|PRE-DEINSTALL) script failed", result.stdout + result.stderr)
        assert vm.ssh("test", "-f", SENTINEL).returncode == 0, "install removed sentinel"
        h.wait_unbound_ready(vm)
    finally:
        removed = vm.ssh("rm", "-f", remote)
        assert removed.returncode == 0, removed.stderr


def _install_package_transition(vm: SmokeVM, previous: Path, current: Path, hour: str) -> None:
    try:
        _force_install(vm, previous)
        assert h.config_get(vm, SCHEDULE_HOUR) == hour, "previous forced install changed the daily schedule hour"
        assert h.config_get(vm, SCHEDULE_MINUTE) == "0", "previous forced install changed the daily schedule minute"
        _force_install(vm, current)
        assert h.config_get(vm, SCHEDULE_HOUR) == hour, "current forced install changed the daily schedule hour"
        assert h.config_get(vm, SCHEDULE_MINUTE) == "0", "current forced install changed the daily schedule minute"
    except Exception as primary:
        try:
            _force_install(vm, current)
        except Exception as restoration:
            raise ExceptionGroup(
                "package transition failed and restoring the current package also failed",
                [primary, restoration],
            ) from None
        raise


@pytest.fixture(scope="module")
def maintenance_vm(smoke_vm: SmokeVM, stub_dns: _StubDnsServer, prev_pkg: Path) -> Iterator[SmokeVM]:
    del stub_dns  # starts the real hermetic DNS boundary before install
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built package")
    if os.environ.get("SMOKE_SCHEDULED_EXCEPTION") != "allow":
        pytest.fail("scheduled maintenance requires explicit --scheduled-exception allow")
    vm = smoke_vm
    h.deploy(vm)
    _assert_no_dispatch(vm, "branch-install")
    h.ensure_dnsbl_vip(vm)
    h.use_stub_for_safesearch(vm, False)
    blocked = h.unique_domain("maintenanceblocked")
    feed = h.write_local_feed(vm, "smoke_maintenance.txt", blocked + "\n")
    h.inject(vm, h.DnsblCase(aliasname="smokemaint", header="smokemaint", feed_url=feed, mode=h.DnsblMode.VIP))
    h.set_package_enabled(vm, True)
    # Supported settings isolate feeds/blacklist and keep DCC's next daily slot outside this test.
    h.config_set(vm, f"{h.CFG_GLOBAL}/pfb_scheduled_feed_updates", "")
    h.config_set(vm, "installedpackages/pfblockerngblacklist/blacklist_enable", "Disable")
    hour = _schedule_hour_far_from_window(vm)
    h.config_set(vm, SCHEDULE_HOUR, hour)
    h.config_set(vm, SCHEDULE_MINUTE, "0")
    h.reload(vm, "update")
    _assert_no_dispatch(vm, "enabled-apply")
    h.set_pfb_keep(vm, True)
    current_pkg = Path(os.environ["SMOKE_PKG"])
    geoip_cleanup_registered = False
    setup_error: Exception | None = None
    cleanup_errors: list[Exception] = []

    def cleanup(action: Any) -> None:
        try:
            action()
        except Exception as error:
            cleanup_errors.append(error)

    def require_sentinel() -> None:
        assert vm.ssh("test", "-f", SENTINEL).returncode == 0, "unsafe cleanup: sentinel absent"

    try:
        _install_package_transition(vm, prev_pkg, current_pkg, hour)
        _assert_no_dispatch(vm, "enabled-upgrade")
        h.reload(vm, "update")
        h.tell_core_the_settings_changed(vm)
        _assert_no_dispatch(vm, "repeated-enabled-apply")
        await_core_up(vm)
        process = vm.ssh("ps ax -o command")
        assert process.returncode == 0, process.stderr
        assert any(
            "pfb_core" in line and "--maintenance-cmd /usr/local/pkg/pfblockerng/pfb_core_maintenance.sh" in line
            for line in process.stdout.splitlines()
        ), f"installed Core is not wired to real maintenance: {process.stdout}"
        # Register before seeding: teardown is idempotent if the helper fails mid-copy.
        geoip_cleanup_registered = True
        h.seed_geoip_dataset(vm)
        dcc_success = _complete_due_dcc(vm)
        h.wait_unbound_ready(vm)
        # First answer is authoritative: never retry toward the expected DNS value.
        answer = h.dns_probe(vm, blocked, "A", attempts=1)
        assert h.is_vip(answer), f"DNSBL gate failed before cadence acceptance: {answer}"
        _assert_dcc_window_safe(vm, dcc_success)
        yield vm
    except Exception as error:
        setup_error = error
    finally:
        cleanup(require_sentinel)
        if geoip_cleanup_registered:
            cleanup(lambda: h.teardown_geoip_dataset(vm))
        cleanup(h.unblock_egress)
        cleanup(lambda: h.collect_host_diagnostics(vm))
        if cleanup_errors:
            errors = ([setup_error] if setup_error is not None else []) + cleanup_errors
            message = (
                "maintenance setup and cleanup failed"
                if setup_error is not None
                else "maintenance fixture cleanup failed"
            )
            raise ExceptionGroup(message, errors)
    if setup_error is not None:
        raise setup_error


def _row(vm: SmokeVM, source: str) -> str:
    result = vm.ssh("cat", h.UNBOUND_PY_SS_FILE)
    assert result.returncode == 0, result.stderr
    rows = [row for row in result.stdout.splitlines() if row.startswith(source + ",")]
    assert len(rows) == 1, f"expected exact seeded CSV source {source}: {rows}"
    return rows[0]


@pytest.mark.smoke
@pytest.mark.tick
@pytest.mark.timeout(2100)
def test_core_scheduled_maintenance_preserves_tick_duties(maintenance_vm: SmokeVM, stub_dns: _StubDnsServer) -> None:
    vm = maintenance_vm
    h.block_egress()
    target = h.unique_domain("maintenancetarget")
    stub_dns.set_records(target, a=(h.SS_TARGET_A,))
    answer = h.dns_probe(vm, target, "A", attempts=1)
    assert h.resolves_to(answer, h.SS_TARGET_A), f"first target DNS answer failed: {answer}"
    _drain_pending_apply(vm)
    # Only the Outpost's PHP duty ledger is reset, as in test_smoke_tick.
    # Core's scheduler state and clock are never written.
    cleared = vm.ssh("rm", "-f", "/var/db/pfblockerng/pfb_due_ledger.json")
    assert cleared.returncode == 0, cleared.stderr
    source = _seed_ss_refresh_positive_control(vm, target, h.SS_BAKED_A)
    try:
        # Direct tick is a manual control ONLY, never scheduled proof.
        direct = vm.ssh(PHP, CLI, "tick", timeout=180)
        assert direct.returncode == 0, direct.stdout + direct.stderr
        assert h.SS_TARGET_A in _row(vm, source), "manual tick was incorrectly sentinel-gated"
        _remove_ss_row(vm, source)
        source = _seed_ss_refresh_positive_control(vm, target, h.SS_BAKED_A)
        before = _read_ledger(vm)
        assert all(job in before for job in DUTIES), before
        assert h.SS_BAKED_A in _row(vm, source)
        marker_before = h.count_log_marker(vm, h.PFB_LOG, MARKER)
        last_update = h.core_update_view(vm)["update"]
        # Observe an actual production timer boundary with the sentinel STILL PRESENT.
        guarded_start = _epoch(vm, "sentinel-present-start")
        guarded_end = (guarded_start // 900 + 1) * 900 + 30
        deadline = time.monotonic() + 960
        while _epoch(vm, "sentinel-present-poll") < guarded_end:
            assert time.monotonic() < deadline, "guest clock did not cross guarded quarter-hour"
            time.sleep(5)
        assert _read_ledger(vm) == before, "sentinel-present maintenance changed duty ledger"
        assert h.SS_BAKED_A in _row(vm, source), "sentinel-present maintenance performed SafeSearch duty"
        assert h.count_log_marker(vm, h.PFB_LOG, MARKER) == marker_before
        assert h.core_update_view(vm)["update"] == last_update, "guarded maintenance created an Update"
        _assert_no_dispatch(vm, "before-scheduled-window")
        with vm.scheduled_maintenance():
            started = _epoch(vm, "scheduled-window-start")
            deadline = time.monotonic() + 990
            while True:
                after = _read_ledger(vm)
                if all(after.get(job, {}).get("last_run", 0) > before[job]["last_run"] for job in DUTIES):
                    break
                assert time.monotonic() < deadline, f"real Core quarter-hour did not advance duties: {after}"
                time.sleep(5)
            ended = _epoch(vm, "scheduled-window-end")
            assert ended // 900 > started // 900, "effect appeared before an actual production boundary"
            assert h.SS_TARGET_A in _row(vm, source), "ledger advanced without real SafeSearch CSV effect"
            assert h.count_log_marker(vm, h.PFB_LOG, MARKER) > marker_before
            for job in DUTIES:
                assert started <= after[job]["last_run"] <= ended, (job, after[job], started, ended)
                assert after[job]["next_due"] > after[job]["last_run"]
                assert after[job]["next_due"] % 900 == 0, (job, after[job])
            assert h.core_update_view(vm)["update"] == last_update, "maintenance minted a public Update"
        _assert_no_dispatch(vm, "after-scheduled-window")
    finally:
        # Context finally MUST have restored+verified sentinel before any config cleanup.
        assert vm.ssh("test", "-f", SENTINEL).returncode == 0, "refusing unsafe configuration cleanup"
        _remove_ss_row(vm, source)
        _reset_ss_extdns(vm)
        stub_dns.clear_cname()
