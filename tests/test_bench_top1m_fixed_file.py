"""Contract checks for the issue #1542 fixed-file benchmark harness."""

from __future__ import annotations

import contextlib
import importlib.util
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "bench_top1m_fixed_file.py"
_SPEC = importlib.util.spec_from_file_location("bench_top1m_fixed_file", _SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
_BENCH = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _BENCH
_SPEC.loader.exec_module(_BENCH)


def _pid_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def _wait_pid_gone(pid: int, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _pid_exists(pid):
            return
        time.sleep(0.05)
    if not _pid_exists(pid):
        return
    raise RuntimeError(f"stuck/environment: pid={pid}; expected absence, actual presence")


def test_benchmark_default_is_exactly_one_million() -> None:
    assert _BENCH.DEFAULT_LINES == 1_000_000


def test_generated_input_is_bounded_at_one_million() -> None:
    assert _BENCH._line_count("1000000") == 1_000_000
    with pytest.raises(_BENCH.argparse.ArgumentTypeError, match="must not exceed"):
        _BENCH._line_count("1000001")


def test_wait_pid_gone_reports_stuck_environment_for_live_pid() -> None:
    with pytest.raises(RuntimeError, match=r"stuck/environment.*pid=.*expected absence.*actual presence"):
        _wait_pid_gone(os.getpid(), timeout=0)


def test_streamed_fixture_is_deterministic_unique_and_bounded(tmp_path: Path) -> None:
    fixture = tmp_path / "pfbalexawhitelist.txt"

    byte_count = _BENCH.generate_top1m(fixture, 10_000)
    lines = fixture.read_text(encoding="ascii").splitlines()

    assert len(lines) == 10_000
    assert len(set(lines)) == 10_000
    assert lines[0] == _BENCH.SAMPLE_FIRST
    assert lines[-1] == _BENCH.domain_for(9_999)
    assert byte_count == fixture.stat().st_size


def test_report_line_carries_fresh_process_trials_wall_and_rss() -> None:
    trials = [
        _BENCH.TrialResult(2.0, 10_000, {}),
        _BENCH.TrialResult(1.0, 20_000, {}),
        _BENCH.TrialResult(3.0, 15_000, {}),
    ]

    line = _BENCH._format_result("phase", trials)

    assert "trials=3" in line
    assert "wall_median=2.000000s" in line
    assert "wall_range=1.000000..3.000000s" in line
    assert "peak_rss_max=20000B" in line


def test_php_worker_disables_host_memory_ceiling_for_rss_measurement() -> None:
    command = _BENCH._php_worker_command(
        "/usr/bin/php",
        "write",
        "embedded",
        Path("/base"),
        Path("/sandbox"),
        1_000_000,
    )

    assert command[:3] == ["/usr/bin/php", "-d", "memory_limit=-1"]
    assert command[3:] == [
        str(_BENCH.PHP_WORKER),
        "write",
        "embedded",
        "/base",
        "/sandbox",
        "1000000",
    ]


def test_each_native_manifest_contract_is_validated_without_cross_feeding(tmp_path: Path) -> None:
    embedded_dir = tmp_path / "embedded"
    embedded_dir.mkdir()
    embedded_manifest = embedded_dir / "pfb_py_sources.json"
    embedded_manifest.write_text(
        json.dumps(
            {
                "version": 1,
                "config": {"top1m_enabled": True, "top1m_list": [_BENCH.domain_for(i) for i in range(3)]},
                "feeds": [],
            }
        ),
        encoding="utf-8",
    )

    fixed_dir = tmp_path / "fixed"
    fixed_dir.mkdir()
    fixed_manifest = fixed_dir / "pfb_py_sources.json"
    fixed_manifest.write_text(
        json.dumps({"version": 1, "config": {"top1m_enabled": True}, "feeds": []}), encoding="utf-8"
    )
    _BENCH.generate_top1m(fixed_dir / "pfb_py_top1m.txt", 3)

    assert _BENCH._assert_native_contract(embedded_manifest, "embedded", 3) == (embedded_manifest.stat().st_size, 0)
    assert _BENCH._assert_native_contract(fixed_manifest, "fixed", 3) == (
        fixed_manifest.stat().st_size,
        (fixed_dir / "pfb_py_top1m.txt").stat().st_size,
    )
    with pytest.raises(RuntimeError, match="embedded TOP1M contract"):
        _BENCH._assert_native_contract(fixed_manifest, "embedded", 3)
    with pytest.raises(RuntimeError, match="fixed-file TOP1M contract"):
        _BENCH._assert_native_contract(embedded_manifest, "fixed", 3)


def test_timed_timeout_kills_descendant_process_group(tmp_path: Path) -> None:
    child_pid_path = tmp_path / "child.pid"
    child_code = "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(300)"
    parent_code = (
        "import pathlib,subprocess,sys,time; "
        "child=subprocess.Popen([sys.executable,'-c',sys.argv[2]]); "
        "pathlib.Path(sys.argv[1]).write_text(str(child.pid)); "
        "time.sleep(300)"
    )
    time_bin = shutil.which("time") or "/usr/bin/time"
    time_flag = _BENCH._time_flag(time_bin, 10)

    with pytest.raises(subprocess.TimeoutExpired):
        _BENCH._run_timed(
            [sys.executable, "-c", parent_code, str(child_pid_path), child_code],
            2,
            time_bin,
            time_flag,
            kill_grace_seconds=0.2,
        )

    child_pid = int(child_pid_path.read_text())
    try:
        _wait_pid_gone(child_pid)
    finally:
        if _pid_exists(child_pid):
            with contextlib.suppress(ProcessLookupError):
                os.kill(child_pid, signal.SIGKILL)


def test_timed_parent_signal_kills_worker_process_group(tmp_path: Path) -> None:
    worker_pid_path = tmp_path / "signal-worker.pid"
    driver_code = "\n".join(
        (
            "import importlib.util, os, pathlib, signal, subprocess, sys",
            "spec = importlib.util.spec_from_file_location('bench_signal_driver', sys.argv[1])",
            "bench = importlib.util.module_from_spec(spec)",
            "sys.modules[spec.name] = bench",
            "spec.loader.exec_module(bench)",
            "def interrupted(signum, frame):",
            "    raise KeyboardInterrupt(f'signal {signum}')",
            "signal.signal(signal.SIGTERM, interrupted)",
            "worker = 'import os,pathlib,sys,time; "
            "pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(300)'",
            "time_bin = '/usr/bin/time'",
            "try:",
            "    bench._run_timed([sys.executable, '-c', worker, sys.argv[2]], "
            "300, time_bin, bench._time_flag(time_bin, 10))",
            "except KeyboardInterrupt:",
            "    raise SystemExit(77)",
        )
    )
    driver = subprocess.Popen(  # noqa: S603
        [sys.executable, "-c", driver_code, str(_SCRIPT), str(worker_pid_path)]
    )
    worker_pid: int | None = None
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and not worker_pid_path.exists():
            time.sleep(0.05)
        marker_exists = worker_pid_path.exists()
        if not marker_exists:
            raise RuntimeError(
                f"salvage cap expired / stuck or environment: timed worker startup marker {worker_pid_path}; "
                f"observed exists={marker_exists}"
            )
        worker_pid = int(worker_pid_path.read_text())

        os.kill(driver.pid, signal.SIGTERM)
        assert driver.wait(timeout=10) == 77
        _wait_pid_gone(worker_pid)
    finally:
        with contextlib.suppress(ProcessLookupError):
            os.kill(driver.pid, signal.SIGKILL)
        with contextlib.suppress(subprocess.TimeoutExpired):
            driver.wait(timeout=2)
        if worker_pid is not None:
            with contextlib.suppress(ProcessLookupError):
                os.kill(worker_pid, signal.SIGKILL)
