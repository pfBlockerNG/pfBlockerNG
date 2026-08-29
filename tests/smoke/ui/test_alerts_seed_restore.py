"""Regression coverage for preserving Alerts render-verification seed files."""

from __future__ import annotations

import csv
import inspect
import os
import shlex
import stat
import subprocess
import traceback
import uuid
from pathlib import Path
from typing import Any, Callable, cast

import pytest

from . import test_alerts_render_verify as alerts
from . import test_alerts_stat_hostname_boundary as hostname_boundary


def test_alert_fixture_ip_rows_match_current_csv_schema() -> None:
    direct_lines = alerts._ip_scenarios() + alerts._permit_lines() + alerts._match_lines()
    direct_rows = list(csv.reader(direct_lines))
    unified_rows = [
        row for row in csv.reader(alerts._unified_lines()) if row and row[0] in {"Block", "Permit", "Match"}
    ]

    direct_counts = {len(row) for row in direct_rows}
    unified_counts = {len(row) for row in unified_rows}
    assert direct_counts == {23}, f"raw direct IP field counts: expected {{23}}, got {direct_counts}"
    assert unified_counts == {24}, f"raw Unified IP field counts: expected {{24}}, got {unified_counts}"


class _LocalVM:
    """Small SmokeVM-compatible shell adapter for hermetic filesystem tests."""

    def ssh_argv(self, *remote: str) -> list[str]:
        if remote and remote[0] == "/usr/bin/truncate":
            return ["/usr/bin/true"]
        return list(remote)

    def ssh(self, *remote: str, timeout: float = 15.0) -> subprocess.CompletedProcess[str]:
        if len(remote) == 1:
            return subprocess.run(
                remote[0],
                shell=True,
                executable="/bin/sh",
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        return subprocess.run(
            remote,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )


class _WrappedVM:
    def __init__(
        self,
        inner: _LocalVM,
        fail: Callable[[tuple[str, ...]], bool] | None = None,
        raise_before: Callable[[tuple[str, ...]], bool] | None = None,
        raise_after: Callable[[tuple[str, ...]], bool] | None = None,
    ) -> None:
        self.inner = inner
        self.fail = fail
        self.raise_before = raise_before
        self.raise_after = raise_after
        self.calls: list[tuple[str, ...]] = []

    def ssh_argv(self, *remote: str) -> list[str]:
        return self.inner.ssh_argv(*remote)

    def ssh(self, *remote: str, timeout: float = 15.0) -> subprocess.CompletedProcess[str]:
        self.calls.append(remote)
        if self.raise_before is not None and self.raise_before(remote):
            raise subprocess.TimeoutExpired(remote, timeout)
        if self.fail is not None and self.fail(remote):
            return subprocess.CompletedProcess(remote, 1, "", f"injected failure: {remote!r}")
        result = self.inner.ssh(*remote, timeout=timeout)
        if self.raise_after is not None and self.raise_after(remote):
            raise subprocess.TimeoutExpired(remote, timeout)
        return result


def test_hostname_boundary_fixture_restores_log_after_seed_write_failure(tmp_path: Path, monkeypatch: Any) -> None:
    log = tmp_path / "ip_block.log"
    original = b"original log contents\n"
    log.write_bytes(original)

    class _SeedWriteFailure:
        @staticmethod
        def run(*args: Any, **_kwargs: Any) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(args[0], 1, "", "injected seed failure")

    monkeypatch.setattr(hostname_boundary, "IP_BLOCK_LOG", str(log))
    monkeypatch.setattr(hostname_boundary, "subprocess", _SeedWriteFailure)
    fixture = cast(Any, hostname_boundary.exact_ip_block_log).__wrapped__(_LocalVM())

    with pytest.raises(AssertionError, match="failed to seed"):
        next(fixture)

    assert log.read_bytes() == original
    assert not Path(f"{log}.bak-2117").exists()


def _matrix_paths(tmp_path: Path) -> tuple[list[Path], Path, Path]:
    paths = [tmp_path / f"seed-{index}.txt" for index in range(8)]
    live_target = tmp_path / "live-target"
    dangling_target = tmp_path / "missing-target"
    return paths, live_target, dangling_target


def _create_matrix(paths: list[Path], live_target: Path, dangling_target: Path) -> None:
    paths[0].write_bytes(b"regular nonempty\n")
    paths[1].write_bytes(b"")
    paths[2].write_bytes(b"no-final-newline")
    paths[3].write_bytes(b"first line\nsecond line\n")
    # paths[4] and paths[5] deliberately absent.
    live_target.write_bytes(b"live target\n")
    paths[6].symlink_to(live_target)
    paths[7].symlink_to(dangling_target)

    for index, path in enumerate(paths[:4]):
        path.chmod(0o600 + index * 0o10)
        timestamp = 1_700_000_000_000_000_000 + index * 1_000_000_000
        os.utime(path, ns=(timestamp, timestamp))
    for index, path in enumerate(paths[6:]):
        timestamp = 1_700_000_010_000_000_000 + index * 1_000_000_000
        os.utime(path, ns=(timestamp, timestamp), follow_symlinks=False)


def _snapshot(path: Path) -> dict[str, Any]:
    if not os.path.lexists(path):
        return {"kind": "absent"}
    info = os.lstat(path)
    snapshot: dict[str, Any] = {
        "uid": info.st_uid,
        "gid": info.st_gid,
        "mode": stat.S_IMODE(info.st_mode),
        "mtime_ns": info.st_mtime_ns,
    }
    if hasattr(info, "st_birthtime"):
        snapshot["birthtime"] = getattr(info, "st_birthtime")
    if path.is_symlink():
        return {"kind": "symlink", "target": os.readlink(path), **snapshot}
    if path.is_file():
        return {"kind": "file", "bytes": path.read_bytes(), **snapshot}
    return {"kind": "unsupported", **snapshot}


def _snapshots(paths: list[Path]) -> dict[str, dict[str, Any]]:
    return {str(path): _snapshot(path) for path in paths}


def _seed_replacements(paths: list[Path]) -> None:
    for index, path in enumerate(paths):
        path.write_bytes(f"replacement {index}\n".encode())


def test_fixture_preserves_files_around_baseline_seed_and_yield() -> None:
    source = inspect.getsource(cast(Any, alerts.render_diff_state).__wrapped__)

    backup_at = source.index("_backup_seeded_files(vm, SEEDED_FILES)")
    try_at = source.index("    try:\n")
    ensure_log_at = source.index("_ensure_log(vm, path)")
    dnsbl_at = source.index("helpers.ensure_dnsbl_vip(vm)")
    baseline_get_at = source.index("for key, path in GET_MATRIX")
    yield_at = source.index('yield {"baseline": baseline, "captures": captures}')
    finally_at = source.index("    finally:\n", yield_at)
    restore_at = source.index("_restore_seeded_files(vm, seeded_backups)")

    assert try_at < backup_at < ensure_log_at < dnsbl_at < baseline_get_at < yield_at < finally_at < restore_at


class _WebUI:
    def __init__(self, fail_get: bool = False) -> None:
        self.fail_get = fail_get

    def get(self, _path: str) -> Any:
        if self.fail_get:
            raise RuntimeError("get")
        return type("Response", (), {"text": "Alert Settings", "status_code": 200})()


def _fixture_harness(
    monkeypatch: Any,
    paths: list[Path],
    failure_point: str,
) -> tuple[Any, list[str]]:
    events: list[str] = []

    class _LogGuard:
        def __init__(self, _vm: Any) -> None:
            pass

        def snapshot(self) -> None:
            events.append("log_snapshot")

        def assert_no_growth(self) -> None:
            events.append("log_teardown")
            if failure_point in {"teardown", "post_yield_cleanup"}:
                raise AssertionError("teardown")

    def assert_backed_up(event: str) -> None:
        events.append(event)
        assert all(not os.path.lexists(path) for path in paths)

    def ensure_log(_vm: Any, _path: str) -> str:
        assert_backed_up("ensure_log")
        if failure_point == "ensure_log":
            raise RuntimeError("ensure_log")
        return "0"

    def ensure_dnsbl(_vm: Any) -> None:
        assert_backed_up("dnsbl")
        if failure_point == "dnsbl":
            raise RuntimeError("dnsbl")

    monkeypatch.setattr(alerts, "SEEDED_FILES", tuple(map(str, paths)))
    monkeypatch.setattr(alerts, "GET_MATRIX", (("alert", "/alerts"),))
    monkeypatch.setattr(alerts, "PhpErrorLogGuard", _LogGuard)
    monkeypatch.setattr(alerts, "_ensure_log", ensure_log)
    monkeypatch.setattr(alerts.helpers, "config_get", lambda _vm, _path: "")
    monkeypatch.setattr(alerts.helpers, "ensure_dnsbl_vip", ensure_dnsbl)
    monkeypatch.setattr(alerts.helpers, "set_dnsbl_enabled", lambda _vm, _enabled: events.append("dnsbl_set"))
    monkeypatch.setattr(alerts.helpers, "php_eval", lambda _vm, _code: subprocess.CompletedProcess([], 0, "OK", ""))
    monkeypatch.setattr(alerts, "_seed_feed_files", lambda _vm: _seed_replacements(paths))
    monkeypatch.setattr(alerts, "_append", lambda _vm, _path, _content: None)
    monkeypatch.setattr(alerts, "_write_diagnostics", lambda _baseline, _captures: None)

    fixture = cast(Any, alerts.render_diff_state).__wrapped__(_LocalVM(), _WebUI(failure_point == "get"))
    return fixture, events


def _seeded_fixture_matrix(tmp_path: Path) -> tuple[list[Path], dict[str, dict[str, Any]]]:
    paths, live_target, dangling_target = _matrix_paths(tmp_path)
    _create_matrix(paths, live_target, dangling_target)
    return paths, _snapshots(paths)


def test_fixture_restores_exact_matrix_after_normal_completion(tmp_path: Path, monkeypatch: Any) -> None:
    paths, before = _seeded_fixture_matrix(tmp_path)
    fixture, _events = _fixture_harness(monkeypatch, paths, "normal")

    next(fixture)
    with pytest.raises(StopIteration):
        next(fixture)

    assert _snapshots(paths) == before


@pytest.mark.parametrize("failure_point", ["ensure_log", "dnsbl", "get", "post_yield", "teardown"])
def test_fixture_restores_exact_matrix_after_any_lifecycle_failure(
    tmp_path: Path,
    monkeypatch: Any,
    failure_point: str,
) -> None:
    paths, before = _seeded_fixture_matrix(tmp_path)
    fixture, events = _fixture_harness(monkeypatch, paths, failure_point)

    if failure_point in {"ensure_log", "dnsbl", "get"}:
        with pytest.raises(RuntimeError, match=failure_point):
            next(fixture)
    else:
        next(fixture)
        if failure_point == "post_yield":
            with pytest.raises(RuntimeError, match="post_yield"):
                fixture.throw(RuntimeError("post_yield"))
        else:
            with pytest.raises(AssertionError, match="teardown"):
                next(fixture)

    assert events
    assert _snapshots(paths) == before


def test_fixture_preserves_body_error_when_cleanup_also_fails(tmp_path: Path, monkeypatch: Any) -> None:
    paths, before = _seeded_fixture_matrix(tmp_path)
    fixture, _events = _fixture_harness(monkeypatch, paths, "post_yield_cleanup")
    next(fixture)

    original: RuntimeError | None = None
    try:
        raise RuntimeError("post_yield")
    except RuntimeError as exc:
        original = exc
    assert original is not None
    original_tail = traceback.extract_tb(original.__traceback__)[-1]

    with pytest.raises(RuntimeError, match="post_yield") as caught:
        fixture.throw(original)

    assert caught.value is original
    assert traceback.extract_tb(caught.value.__traceback__)[-1] == original_tail
    assert any("teardown" in note for note in getattr(caught.value, "__notes__", []))
    assert _snapshots(paths) == before


def test_backup_failure_rolls_back_prior_moves(tmp_path: Path) -> None:
    paths, live_target, dangling_target = _matrix_paths(tmp_path)
    _create_matrix(paths, live_target, dangling_target)
    before = _snapshots(paths)
    failed_path = str(paths[2])
    vm = _WrappedVM(
        _LocalVM(),
        fail=lambda remote: len(remote) >= 2 and remote[0] == "mv" and remote[1] == failed_path,
    )

    with pytest.raises(AssertionError, match="injected failure"):
        alerts._backup_seeded_files(vm, tuple(map(str, paths)))

    assert _snapshots(paths) == before


def test_fixture_backup_failure_does_not_delete_rolled_back_files(tmp_path: Path, monkeypatch: Any) -> None:
    first = tmp_path / "a.txt"
    second = tmp_path / "b.txt"
    first.write_bytes(b"first original\n")
    second.write_bytes(b"second original\n")
    vm = _WrappedVM(
        _LocalVM(),
        fail=lambda remote: len(remote) >= 2 and remote[0] == "mv" and remote[1] == str(second),
    )

    class _NoopLogGuard:
        def __init__(self, _vm: Any) -> None:
            pass

        def snapshot(self) -> None:
            pass

        def assert_no_growth(self) -> None:
            pass

    monkeypatch.setattr(alerts, "SEEDED_FILES", (str(first), str(second)))
    monkeypatch.setattr(alerts, "PhpErrorLogGuard", _NoopLogGuard)
    monkeypatch.setattr(alerts, "_ensure_log", lambda _vm, _path: "0")
    monkeypatch.setattr(alerts.helpers, "config_get", lambda _vm, _path: "")
    monkeypatch.setattr(alerts.helpers, "ensure_dnsbl_vip", lambda _vm: None)
    monkeypatch.setattr(alerts.helpers, "set_dnsbl_enabled", lambda _vm, _enabled: None)
    monkeypatch.setattr(
        alerts.helpers,
        "php_eval",
        lambda _vm, _code: subprocess.CompletedProcess([], 0, "OK", ""),
    )

    fixture = cast(Any, alerts.render_diff_state).__wrapped__(vm, object())
    with pytest.raises(AssertionError, match="injected failure"):
        next(fixture)

    assert first.read_bytes() == b"first original\n"
    assert second.read_bytes() == b"second original\n"
    assert set(tmp_path.iterdir()) == {first, second}


def test_fixture_backup_timeout_after_ambiguous_move_restores_all_files(tmp_path: Path, monkeypatch: Any) -> None:
    first = tmp_path / "a.txt"
    second = tmp_path / "b.txt"
    first.write_bytes(b"first original\n")
    second.write_bytes(b"second original\n")
    before = _snapshots([first, second])
    vm = _WrappedVM(
        _LocalVM(),
        raise_after=lambda remote: len(remote) >= 2 and remote[0] == "mv" and remote[1] == str(second),
    )

    monkeypatch.setattr(alerts, "SEEDED_FILES", (str(first), str(second)))
    fixture = cast(Any, alerts.render_diff_state).__wrapped__(vm, object())

    with pytest.raises(subprocess.TimeoutExpired):
        next(fixture)

    assert _snapshots([first, second]) == before
    assert set(tmp_path.iterdir()) == {first, second}


def test_ambiguous_backup_rollback_timeout_after_success_is_confirmed(tmp_path: Path) -> None:
    first = tmp_path / "a.txt"
    second = tmp_path / "b.txt"
    first.write_bytes(b"first original\n")
    second.write_bytes(b"second original\n")
    before = _snapshots([first, second])

    def raise_after(remote: tuple[str, ...]) -> bool:
        return len(remote) >= 3 and remote[0] == "mv" and (remote[1] == str(second) or remote[2] == str(second))

    vm = _WrappedVM(_LocalVM(), raise_after=raise_after)

    with pytest.raises(subprocess.TimeoutExpired) as caught:
        alerts._backup_seeded_files(vm, (str(first), str(second)))

    assert getattr(caught.value, "__notes__", []) == []
    assert _snapshots([first, second]) == before
    assert set(tmp_path.iterdir()) == {first, second}


def test_restore_remove_failure_keeps_backup_at_recorded_path(tmp_path: Path) -> None:
    target = tmp_path / "seed.txt"
    target.write_bytes(b"original\n")
    backups = alerts._backup_seeded_files(_LocalVM(), (str(target),))
    backup_path = Path(backups[0].backup_path or "")
    target.mkdir()

    errors = alerts._restore_seeded_files(_LocalVM(), backups)

    assert len(errors) == 1
    assert str(target) in errors[0]
    assert backup_path.read_bytes() == b"original\n"
    assert list(target.iterdir()) == []


def test_restore_runs_in_reverse_and_aggregates_failures(tmp_path: Path) -> None:
    paths, live_target, dangling_target = _matrix_paths(tmp_path)
    _create_matrix(paths, live_target, dangling_target)
    backups = alerts._backup_seeded_files(_LocalVM(), tuple(map(str, paths)))
    _seed_replacements(paths)

    failed_rm = str(paths[4])
    failed_mv = str(paths[1])

    def fail(remote: tuple[str, ...]) -> bool:
        return (len(remote) >= 3 and remote[:2] == ("rm", "-f") and remote[2] == failed_rm) or (
            len(remote) >= 3 and remote[0] == "mv" and remote[2] == failed_mv and ".pfb-alerts-backup-" in remote[1]
        )

    vm = _WrappedVM(_LocalVM(), fail=fail)
    errors = alerts._restore_seeded_files(vm, backups)

    assert len(errors) == 2
    assert any(failed_rm in error for error in errors)
    assert any(failed_mv in error for error in errors)
    restored_targets = [
        remote[2]
        for remote in vm.calls
        if len(remote) >= 3 and remote[0] == "mv" and ".pfb-alerts-backup-" in remote[1]
    ]
    existing_targets = [backup.path for backup in backups if backup.backup_path is not None]
    assert restored_targets == list(reversed(existing_targets))


def test_restore_timeout_keeps_affected_backup_and_continues_full_matrix(tmp_path: Path) -> None:
    paths, live_target, dangling_target = _matrix_paths(tmp_path)
    _create_matrix(paths, live_target, dangling_target)
    before = _snapshots(paths)
    backups = alerts._backup_seeded_files(_LocalVM(), tuple(map(str, paths)))
    affected = backups[-1]
    affected_backup = Path(affected.backup_path or "")
    _seed_replacements(paths)
    vm = _WrappedVM(
        _LocalVM(),
        raise_before=lambda remote: len(remote) >= 3 and remote[:2] == ("rm", "-f") and remote[2] == affected.path,
    )

    errors = alerts._restore_seeded_files(vm, backups)

    assert len(errors) == 1
    assert affected.path in errors[0]
    assert "timed out" in errors[0]
    assert paths[-1].read_bytes() == b"replacement 7\n"
    assert affected_backup.is_symlink()
    assert _snapshots(paths[:-1]) == {path: state for path, state in before.items() if path != str(paths[-1])}
    assert all(
        backup.backup_path == affected.backup_path or not os.path.lexists(backup.backup_path)
        for backup in backups
        if backup.backup_path is not None
    )


def test_restore_timeout_after_success_confirms_exact_original(tmp_path: Path) -> None:
    paths, live_target, dangling_target = _matrix_paths(tmp_path)
    _create_matrix(paths, live_target, dangling_target)
    before = _snapshots(paths)
    backups = alerts._backup_seeded_files(_LocalVM(), tuple(map(str, paths)))
    affected = backups[-1]
    _seed_replacements(paths)
    vm = _WrappedVM(
        _LocalVM(),
        raise_after=lambda remote: (
            len(remote) >= 3 and remote[0] == "mv" and remote[1] == affected.backup_path and remote[2] == affected.path
        ),
    )

    errors = alerts._restore_seeded_files(vm, backups)

    assert errors == []
    assert _snapshots(paths) == before
    assert all(not os.path.lexists(backup.backup_path) for backup in backups if backup.backup_path is not None)


@pytest.mark.parametrize("destination_kind", ["absent", "unsupported"])
def test_restore_timeout_with_unresolved_state_retains_exact_backup(
    tmp_path: Path,
    destination_kind: str,
) -> None:
    paths, live_target, dangling_target = _matrix_paths(tmp_path)
    _create_matrix(paths, live_target, dangling_target)
    before = _snapshots(paths)
    backups = alerts._backup_seeded_files(_LocalVM(), tuple(map(str, paths)))
    affected = backups[-1]
    affected_backup = Path(affected.backup_path or "")
    _seed_replacements(paths)

    def raise_after(remote: tuple[str, ...]) -> bool:
        if not (
            len(remote) >= 3 and remote[0] == "mv" and remote[1] == affected.backup_path and remote[2] == affected.path
        ):
            return False
        Path(affected.path).rename(affected_backup)
        if destination_kind == "unsupported":
            Path(affected.path).mkdir()
        return True

    errors = alerts._restore_seeded_files(_WrappedVM(_LocalVM(), raise_after=raise_after), backups)

    assert len(errors) == 1
    assert affected.path in errors[0]
    assert "unresolved" in errors[0]
    assert f"path={destination_kind}" in errors[0]
    assert "backup=symlink" in errors[0]
    assert "retained for recovery" in errors[0]
    assert "timed out" in errors[0]
    assert _snapshot(affected_backup) == before[affected.path]
    assert _snapshots(paths[:-1]) == {path: state for path, state in before.items() if path != affected.path}


@pytest.mark.parametrize("unsupported", ["directory", "fifo", "device"])
def test_unsupported_type_rejected_before_any_mutation(tmp_path: Path, unsupported: str) -> None:
    regular = tmp_path / "first.txt"
    regular.write_bytes(b"must stay put\n")
    if unsupported == "directory":
        invalid = tmp_path / "directory.txt"
        invalid.mkdir()
    elif unsupported == "fifo":
        invalid = tmp_path / "fifo.txt"
        os.mkfifo(invalid)
    else:
        invalid = Path("/dev/null")

    with pytest.raises(AssertionError, match="unsupported"):
        alerts._backup_seeded_files(_LocalVM(), (str(regular), str(invalid)))

    assert regular.read_bytes() == b"must stay put\n"


def _remote_write(vm: Any, path: str, content: str) -> None:
    result = subprocess.run(
        vm.ssh_argv("tee", path),
        input=content,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert result.returncode == 0, f"write {path!r} failed: {result.stderr!r}"


def _remote_kind(vm: Any, path: str) -> str:
    quoted = shlex.quote(path)
    result = vm.ssh(
        f"if [ -L {quoted} ]; then printf symlink; "
        f"elif [ -f {quoted} ]; then printf file; "
        f"elif [ -e {quoted} ]; then printf unsupported; "
        "else printf absent; fi",
        timeout=15,
    )
    assert result.returncode == 0, f"inspect {path!r} failed: {result.stderr!r}"
    assert result.stdout in {"absent", "file", "symlink", "unsupported"}
    return result.stdout


def _remote_snapshot(vm: Any, path: str) -> dict[str, Any]:
    kind = _remote_kind(vm, path)
    if kind == "absent":
        return {"kind": kind}

    metadata = vm.ssh("stat", "-f", "%u\t%g\t%Lp\t%m\t%B", path, timeout=15)
    birthtime = True
    if metadata.returncode != 0:
        metadata = vm.ssh("stat", "-f", "%u\t%g\t%Lp\t%m", path, timeout=15)
        birthtime = False
    assert metadata.returncode == 0, f"stat {path!r} failed: {metadata.stderr!r}"
    fields = metadata.stdout.strip().split("\t")
    snapshot: dict[str, Any] = {
        "kind": kind,
        "uid": int(fields[0]),
        "gid": int(fields[1]),
        "mode": int(fields[2], 8),
        "mtime": int(fields[3]),
    }
    if birthtime:
        snapshot["birthtime"] = int(fields[4])

    command = "readlink" if kind == "symlink" else "cat"
    payload = vm.ssh(command, path, timeout=15)
    assert payload.returncode == 0, f"snapshot {path!r} failed: {payload.stderr!r}"
    snapshot["target" if kind == "symlink" else "bytes"] = (
        payload.stdout if kind == "symlink" else payload.stdout.encode()
    )
    return snapshot


def _remote_snapshots(vm: Any, paths: list[str]) -> dict[str, dict[str, Any]]:
    return {path: _remote_snapshot(vm, path) for path in paths}


def _remote_move_aside(vm: Any, paths: list[str], token: str) -> list[tuple[str, str | None]]:
    backups: list[tuple[str, str | None]] = []
    try:
        for path in paths:
            kind = _remote_kind(vm, path)
            assert kind != "unsupported", f"unsupported live seeded path: {path!r}"
            backup = None if kind == "absent" else f"{path}.seed-restore-outer-{token}"
            if backup is not None:
                assert _remote_kind(vm, backup) == "absent", f"outer backup collision: {backup!r}"
                move = vm.ssh("mv", path, backup, timeout=15)
                assert move.returncode == 0, f"outer backup {path!r} failed: {move.stderr!r}"
            backups.append((path, backup))
    except BaseException:
        rollback = _remote_restore_aside(vm, backups)
        assert rollback == [], "outer backup rollback failed: " + "\n".join(rollback)
        raise
    return backups


def _remote_restore_aside(vm: Any, backups: list[tuple[str, str | None]]) -> list[str]:
    errors: list[str] = []
    for path, backup in reversed(backups):
        remove = vm.ssh("rm", "-f", path, timeout=15)
        if remove.returncode != 0:
            errors.append(f"remove controlled path {path!r} failed: {remove.stderr!r}")
            continue
        if backup is not None:
            restore = vm.ssh("mv", backup, path, timeout=15)
            if restore.returncode != 0:
                errors.append(f"restore outer backup {backup!r} failed: {restore.stderr!r}")
    return errors


def _remote_create_matrix(vm: Any, paths: list[str], live_target: str, dangling_target: str) -> None:
    parents = sorted({str(Path(path).parent) for path in paths})
    mkdir = vm.ssh("mkdir", "-p", *parents, timeout=15)
    assert mkdir.returncode == 0, f"mkdir failed: {mkdir.stderr!r}"
    for path, content in zip(
        paths[:4],
        ("regular nonempty\n", "", "no-final-newline", "first line\nsecond line\n"),
        strict=True,
    ):
        _remote_write(vm, path, content)
    for path, mode, timestamp in zip(
        paths[:4],
        ("0600", "0640", "0644", "0660"),
        ("202401010101.01", "202401010102.02", "202401010103.03", "202401010104.04"),
        strict=True,
    ):
        metadata = vm.ssh(f"chmod {mode} {shlex.quote(path)} && touch -t {timestamp} {shlex.quote(path)}", timeout=15)
        assert metadata.returncode == 0, f"metadata seed {path!r} failed: {metadata.stderr!r}"
    _remote_write(vm, live_target, "live target\n")
    for path, target, timestamp in (
        (paths[6], live_target, "202401010105.05"),
        (paths[7], dangling_target, "202401010106.06"),
    ):
        link = vm.ssh("ln", "-s", target, path, timeout=15)
        assert link.returncode == 0, f"symlink {path!r} failed: {link.stderr!r}"
        metadata = vm.ssh("touch", "-h", "-t", timestamp, path, timeout=15)
        assert metadata.returncode == 0, f"symlink metadata seed {path!r} failed: {metadata.stderr!r}"


@pytest.mark.ui_e2e
def test_seeded_files_restore_live(smoke_vm: Any, webui: Any) -> None:
    """Leased-box fixture proof over all eight production seed paths."""
    vm = smoke_vm
    paths = list(alerts.SEEDED_FILES)
    token = uuid.uuid4().hex
    live_target = f"{paths[6]}.seed-restore-live-{token}"
    dangling_target = f"{paths[7]}.seed-restore-missing-{token}"
    auxiliary = (live_target, dangling_target)
    outer_backups = _remote_move_aside(vm, paths, token)
    cleanup_errors: list[str] = []

    try:
        _remote_create_matrix(vm, paths, live_target, dangling_target)
        before = _remote_snapshots(vm, paths)

        fixture = cast(Any, alerts.render_diff_state).__wrapped__(vm, webui)
        next(fixture)
        with pytest.raises(StopIteration):
            next(fixture)

        assert _remote_snapshots(vm, paths) == before
    finally:
        cleanup = vm.ssh("rm", "-f", *auxiliary, timeout=15)
        if cleanup.returncode != 0:
            cleanup_errors.append(f"live matrix cleanup failed: {cleanup.stderr!r}")
        cleanup_errors.extend(_remote_restore_aside(vm, outer_backups))

    assert cleanup_errors == []
