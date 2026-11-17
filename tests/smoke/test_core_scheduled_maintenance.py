"""#3996 real quarter-hour acceptance; no scheduler clock/state injection.

Only the exact explicitly opted-in case may enter scheduled_maintenance.
SafeSearch CSV effects, the Outpost's duty lock files and Core's maintenance receipts are the live
oracles (the tick keeps no duty ledger). Other duty branches remain covered by the real PHP suite.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shlex
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from . import helpers as h
from .conftest import SmokeVM, _StubDnsServer
from .test_smoke_core_api import CORE_RC, await_core_up
from .test_smoke_tick import (
    _drain_pending_apply,
    _remove_ss_row,
    _reset_ss_extdns,
    _seed_ss_refresh_positive_control,
)

SENTINEL = "/var/db/pfblockerng/.pfb_cron_disable"
PHP = "/usr/local/bin/php"
CLI = "/usr/local/www/pfblockerng/pfblockerng.php"
DUTY_LOCKS = (f"{h.PFB_DBDIR}/pfb_ss_refresh.lock", f"{h.PFB_DBDIR}/pfb_apply_reconcile.lock")
CORE_LOG = "/var/log/pfblockerng/core.log"
FLIP_RUNS = "maintenance runs again:"
FLIP_SKIPS = "maintenance skips its runs:"
MAINTENANCE_RECEIPT = f"{h.CORE_STATE_DIR}/maintenance.log.result"
MARKER = "SafeSearch CNAME fallback IPs refreshed"
SCHEDULE_HOUR = f"{h.CFG_GLOBAL}/pfb_schedule_hour"
SCHEDULE_MINUTE = f"{h.CFG_GLOBAL}/pfb_schedule_minute"
DCC_ID = "extra:dcc"
WINDOW_BOUND_SECONDS = 3360  # the 3300 s body cap of the three-boundary case, plus a minute
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


def _read_worker_file(vm: SmokeVM, name: str) -> bytes:
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
    return data


def _read_worker_receipt(vm: SmokeVM, name: str) -> dict[str, Any]:
    data = _read_worker_file(vm, name)
    try:
        receipt = json.loads(data)
    except ValueError as error:
        raise AssertionError(f"DCC retry receipt {name} is invalid JSON: {error}") from error
    if not isinstance(receipt, dict):
        raise AssertionError(f"DCC retry receipt {name} is not an object")
    return receipt


def _read_worker_result(vm: SmokeVM) -> dict[str, Any]:
    data = _read_worker_file(vm, "result")
    records: list[dict[str, Any]] = []
    merged_outcomes: dict[str, str] = {}
    seen_attempted: list[str] | None = None
    seen_geoip_ready: bool | None = None
    allowed = {"version", "outcomes", "attempted", "geoipReady"}

    # PHP emits incremental outcomes and a final aggregate; identical repeats are valid, contradictions are not.
    for line_number, line in enumerate(data.split(b"\n"), 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except ValueError as error:
            raise AssertionError(f"DCC retry receipt result line {line_number} is invalid JSON: {error}") from error
        if not isinstance(record, dict):
            raise AssertionError(f"DCC retry receipt result line {line_number} is not an object")
        if type(record.get("version")) is not int or record["version"] != 1:
            raise AssertionError(f"DCC retry receipt result line {line_number} has an unsupported version")
        if set(record) - allowed:
            raise AssertionError(f"DCC retry receipt result line {line_number} has unknown fields")

        outcomes = record.get("outcomes")
        if outcomes is not None:
            if not isinstance(outcomes, dict) or any(
                type(outcome) is not str or outcome not in ("success", "retry-cap-reached")
                for outcome in outcomes.values()
            ):
                raise AssertionError(f"DCC retry receipt result line {line_number} has invalid outcomes")
            for item, outcome in outcomes.items():
                if item in merged_outcomes and merged_outcomes[item] != outcome:
                    raise AssertionError(f"DCC retry receipt result line {line_number} contradicts outcome {item!r}")
                merged_outcomes[item] = outcome

        attempted = record.get("attempted")
        if attempted is not None:
            if not isinstance(attempted, list) or any(type(item) is not str for item in attempted):
                raise AssertionError(f"DCC retry receipt result line {line_number} has invalid attempted ids")
            if seen_attempted is not None and seen_attempted != attempted:
                raise AssertionError(f"DCC retry receipt result line {line_number} contradicts attempted ids")
            seen_attempted = attempted

        geoip_ready = record.get("geoipReady")
        if geoip_ready is not None:
            if type(geoip_ready) is not bool:
                raise AssertionError(f"DCC retry receipt result line {line_number} has invalid GeoIP readiness")
            if seen_geoip_ready is not None and seen_geoip_ready != geoip_ready:
                raise AssertionError(f"DCC retry receipt result line {line_number} contradicts GeoIP readiness")
            seen_geoip_ready = geoip_ready
        records.append(record)

    if not records:
        raise AssertionError("DCC retry receipt result has no nonempty records")
    final = records[-1]
    if not all(field in final and final[field] is not None for field in ("outcomes", "attempted", "geoipReady")):
        raise AssertionError("DCC retry receipt result has no complete final aggregate")
    if (
        merged_outcomes != final["outcomes"]
        or seen_attempted != final["attempted"]
        or seen_geoip_ready != final["geoipReady"]
    ):
        raise AssertionError("DCC retry receipt result incremental records contradict the final aggregate")
    return final


def _assert_dcc_retry_receipts(vm: SmokeVM) -> None:
    request = _read_worker_receipt(vm, "request")
    result = _read_worker_result(vm)
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


def _receipt_signature(vm: SmokeVM) -> str:
    """Identity of Core's last maintenance receipt (inode, size, mtime), or ``absent``."""
    result = vm.ssh("stat", "-f", "%i %z %m", MAINTENANCE_RECEIPT)
    return result.stdout.strip() if result.returncode == 0 else "absent"


def _duty_locks(vm: SmokeVM) -> list[str]:
    """Duty lock files that exist; the tick opens them with ``c`` on every run."""
    return [path for path in DUTY_LOCKS if vm.ssh("test", "-f", path).returncode == 0]


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
    h.assert_no_pfb_cron_entry(vm, phase)
    assert vm.ssh("test", "-f", SENTINEL).returncode == 0, f"{phase}: sentinel missing"


def _update_page_status(vm: SmokeVM) -> str:
    """The Update page body, fetched through the webConfigurator with the admin credentials of the environment."""
    from .ui.credgate import admin_password_decision
    from .ui.webui import WebUI

    action, password = admin_password_decision(os.environ)
    if action == "fail":
        pytest.fail(password)
    protocol = h.config_get(vm, "system/webgui/protocol").strip().lower() or "http"
    client = WebUI(
        host=vm.host,
        port=vm.web_port,
        username=os.environ.get("SMOKE_ADMIN_USER") or "admin",
        password=password,
        scheme=protocol,
        verify=protocol != "https",
    )
    client.login()
    return client.get("/pfblockerng/pfblockerng_update.php").text


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
        pytest.skip("scheduled maintenance runs only under local-smoke.sh --scheduled-exception allow")
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
@pytest.mark.timeout(3300)
def test_core_scheduled_maintenance_preserves_tick_duties(maintenance_vm: SmokeVM, stub_dns: _StubDnsServer) -> None:
    """Core, with no crontab entry anywhere, runs the quarter-hour maintenance (#3996).

    Three observed quarter-hour boundaries of the guest clock: sentinel present (Core starts nothing),
    sentinel absent (Core runs the tick: duty locks, a new maintenance receipt, the SafeSearch effect),
    package disabled with the sentinel absent (Core starts nothing).
    """
    vm = maintenance_vm
    h.block_egress()
    target = h.unique_domain("maintenancetarget")
    stub_dns.set_records(target, a=(h.SS_TARGET_A,))
    answer = h.dns_probe(vm, target, "A", attempts=1)
    assert h.resolves_to(answer, h.SS_TARGET_A), f"first target DNS answer failed: {answer}"
    _drain_pending_apply(vm)
    source = _seed_ss_refresh_positive_control(vm, target, h.SS_BAKED_A)
    enabled_original = h.config_get(vm, "installedpackages/pfblockerng/config/0/enable_cb")
    try:
        # Direct tick is a manual control ONLY, never scheduled proof.
        direct = vm.ssh(PHP, CLI, "tick", timeout=180)
        assert direct.returncode == 0, direct.stdout + direct.stderr
        assert h.SS_TARGET_A in _row(vm, source), "manual tick was incorrectly sentinel-gated"
        assert _duty_locks(vm) == list(DUTY_LOCKS), "the tick left no duty lock evidence"
        _remove_ss_row(vm, source)
        source = _seed_ss_refresh_positive_control(vm, target, h.SS_BAKED_A)
        cleared = vm.ssh("rm", "-f", *DUTY_LOCKS)
        assert cleared.returncode == 0, cleared.stderr
        receipt_before = _receipt_signature(vm)
        assert h.SS_BAKED_A in _row(vm, source)
        marker_before = h.count_log_marker(vm, h.PFB_LOG, MARKER)
        last_update = h.core_update_view(vm)["update"]

        def assert_core_started_nothing(phase: str) -> None:
            assert _duty_locks(vm) == [], f"{phase}: a maintenance worker ran (duty locks exist)"
            assert _receipt_signature(vm) == receipt_before, f"{phase}: Core started a maintenance worker"
            assert h.SS_BAKED_A in _row(vm, source), f"{phase}: SafeSearch duty ran"
            assert h.count_log_marker(vm, h.PFB_LOG, MARKER) == marker_before, f"{phase}: SafeSearch marker grew"
            assert h.core_update_view(vm)["update"] == last_update, f"{phase}: maintenance minted an Update"
            h.assert_no_pfb_cron_entry(vm, phase)

        # Observe an actual production quarter-hour boundary with the sentinel STILL PRESENT. Core logs only a flip
        # (lanegate.go), and a freshly started Core's gate starts as running, so after a restart its first skip
        # decision is logged: that line is the event that the boundary was decided.
        runs_logged = h.count_log_marker(vm, CORE_LOG, FLIP_RUNS)
        skips_logged = h.count_log_marker(vm, CORE_LOG, FLIP_SKIPS)
        for verb in ("stop", "start"):
            done = vm.ssh(f"{CORE_RC} {verb}", timeout=60)
            assert done.returncode == 0, f"{CORE_RC} {verb} failed: {done.stdout}{done.stderr}"
        await_core_up(vm)
        guarded_start = _epoch(vm, "sentinel-present-start")
        h.wait_until(
            lambda: h.count_log_marker(vm, CORE_LOG, FLIP_SKIPS) > skips_logged,
            timeout=990,
            interval=5,
            what="Core's quarter-hour logging its skip with the sentinel present",
        )
        guarded_end = _epoch(vm, "sentinel-present-end")
        assert guarded_end // 900 > guarded_start // 900, "Core's skip came before an actual production boundary"
        assert_core_started_nothing("sentinel-present")
        _assert_no_dispatch(vm, "sentinel-present")
        assert h.count_log_marker(vm, CORE_LOG, FLIP_RUNS) == runs_logged, "Core logged a flip to running"
        with vm.scheduled_maintenance():
            started = _epoch(vm, "scheduled-window-start")
            h.wait_until(
                lambda: _receipt_signature(vm) != receipt_before and _duty_locks(vm) == list(DUTY_LOCKS),
                timeout=990,
                interval=5,
                what="Core's quarter-hour running the maintenance (a new receipt and both duty locks)",
            )
            ended = _epoch(vm, "scheduled-window-end")
            assert ended // 900 > started // 900, "effect appeared before an actual production boundary"
            assert h.SS_TARGET_A in _row(vm, source), "maintenance ran without the real SafeSearch CSV effect"
            assert h.count_log_marker(vm, h.PFB_LOG, MARKER) > marker_before
            assert h.core_update_view(vm)["update"] == last_update, "maintenance minted a public Update"
            assert h.count_log_marker(vm, CORE_LOG, FLIP_RUNS) > runs_logged, "Core logged no flip to running"
            h.assert_no_pfb_cron_entry(vm, "scheduled-window")
            # Enabled package, sentinel absent, no crontab entry: the page shows the next check, not a missing task.
            page = _update_page_status(vm)
            assert "Next schedule check" in page, "the Update page lost its Next schedule check status"
            assert "Missing cron task" not in page, "the Update page reports a cron task Core replaced as missing"
            assert "[ Disabled" not in page, "the Update page reports the enabled package as disabled"
            # A disabled package: Core re-reads the settings at the boundary and starts nothing; its flip line is
            # the event that its decision was taken.
            skips_logged = h.count_log_marker(vm, CORE_LOG, FLIP_SKIPS)
            h.set_package_enabled(vm, False)
            vm.ssh("rm", "-f", *DUTY_LOCKS)
            _remove_ss_row(vm, source)
            source = _seed_ss_refresh_positive_control(vm, target, h.SS_BAKED_A)
            receipt_before = _receipt_signature(vm)
            marker_before = h.count_log_marker(vm, h.PFB_LOG, MARKER)
            _epoch(vm, "package-disabled-start")
            h.wait_until(
                lambda: h.count_log_marker(vm, CORE_LOG, FLIP_SKIPS) > skips_logged,
                timeout=990,
                interval=5,
                what="Core's quarter-hour logging the flip to skipping for the disabled package",
            )
            _epoch(vm, "package-disabled-end")
            assert_core_started_nothing("package-disabled")
        _assert_no_dispatch(vm, "after-scheduled-window")
    finally:
        # Context finally MUST have restored+verified sentinel before any config cleanup.
        assert vm.ssh("test", "-f", SENTINEL).returncode == 0, "refusing unsafe configuration cleanup"
        h.config_set(vm, "installedpackages/pfblockerng/config/0/enable_cb", enabled_original)
        _remove_ss_row(vm, source)
        _reset_ss_extdns(vm)
        stub_dns.clear_cname()
