#!/usr/bin/env python3
"""Issue #1542 benchmark for the fixed-file TOP1M manifest contract.

Runs four fresh-process phases on deterministic unique domains:

1. PHP full manifest + fixed-file writer (branch only; old contract N/A)
2. PHP scalar manifest patcher (base and branch)
3. Python JSON parse + manifest validation only (base and branch)
4. Python full fixed-file build (branch only; old contract N/A)

No threshold or verdict is applied. Measurements are dev-host observations.
"""

from __future__ import annotations

import argparse
import builtins
import hashlib
import json
import os
import platform
import re
import shutil
import signal
import statistics
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType

REPO_ROOT = Path(__file__).resolve().parent.parent
PHP_WORKER = REPO_ROOT / "scripts" / "bench_top1m_fixed_file.php"
DEFAULT_LINES = 1_000_000
DEFAULT_TRIALS = 3
DEFAULT_TIMEOUT_SECONDS = 900
SAMPLE_FIRST = "top1m-0000000.benchmark.invalid"

_BSD_RSS_RE = re.compile(r"^\s*(\d+)\s+maximum resident set size", re.MULTILINE)
_GNU_RSS_RE = re.compile(r"Maximum resident set size \(kbytes\):\s*(\d+)", re.MULTILINE)


@dataclass
class TrialResult:
    wall_seconds: float
    peak_rss_bytes: int
    values: dict[str, str] = field(repr=False)


def domain_for(index: int) -> str:
    """Return one deterministic domain; the fixture is streamed, never listed in JSON."""
    return f"top1m-{index:07d}.benchmark.invalid"


def generate_top1m(path: Path, lines: int) -> int:
    """Write exactly ``lines`` unique domains using bounded memory; return bytes."""
    with path.open("w", encoding="ascii", newline="\n") as handle:
        for index in range(lines):
            handle.write(domain_for(index) + "\n")
    return path.stat().st_size


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("value must be at least 1")
    return parsed


def _line_count(value: str) -> int:
    parsed = _positive_int(value)
    if parsed > DEFAULT_LINES:
        raise argparse.ArgumentTypeError(f"value must not exceed {DEFAULT_LINES}")
    return parsed


def _load_python_target(worktree: Path) -> ModuleType:
    sys.path.insert(0, str(worktree / "stubs" / "python"))
    import unboundmodule

    for name in unboundmodule.__all__:
        setattr(builtins, name, getattr(unboundmodule, name))

    sys.path.insert(0, str(worktree / "src" / "usr" / "local" / "pkg" / "pfblockerng"))
    import pfb_unbound

    return pfb_unbound


def worker_python(phase: str, worktree: Path, manifest_path: Path, expected_lines: int) -> int:
    pfb_unbound = _load_python_target(worktree)
    sample_last = domain_for(expected_lines - 1)

    if phase == "validate":
        start = time.perf_counter()
        with manifest_path.open(encoding="utf-8") as handle:
            manifest = json.load(handle)
        pfb_unbound._dnsbl_validate_manifest_raws(manifest, str(manifest_path.parent))
        elapsed = time.perf_counter() - start
        encoded = manifest_path.read_text(encoding="utf-8")
        if "top1m_list" in encoded or "top1m_ref" in encoded or SAMPLE_FIRST in encoded:
            raise RuntimeError("compact manifest contract violated during Python validation")
        print(f"wall_seconds={elapsed:.9f}")
        print(f"manifest_bytes={manifest_path.stat().st_size}")
        return 0

    start = time.perf_counter()
    result = pfb_unbound.dnsbl_build_from_manifest(str(manifest_path))
    elapsed = time.perf_counter() - start
    if result is None:
        raise RuntimeError("dnsbl_build_from_manifest returned failure")
    if len(result.white_db) != expected_lines:
        raise RuntimeError(
            f"full build consumed {len(result.white_db)} unique TOP1M domains; expected {expected_lines}"
        )
    if SAMPLE_FIRST not in result.white_db or sample_last not in result.white_db:
        raise RuntimeError("full build omitted deterministic boundary samples")
    print(f"wall_seconds={elapsed:.9f}")
    print(f"unique_top1m_domains={len(result.white_db)}")
    print(f"manifest_bytes={manifest_path.stat().st_size}")
    print(f"fixed_bytes={(manifest_path.parent / 'pfb_py_top1m.txt').stat().st_size}")
    return 0


def _time_flag(time_bin: str, timeout_seconds: int) -> str:
    probe = subprocess.run(  # noqa: S603
        [time_bin, "-l", "true"],
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout_seconds,
        env={**os.environ, "LC_ALL": "C"},
    )
    return "-l" if probe.returncode == 0 else "-v"


def _run_timed(cmd: list[str], timeout_seconds: int, time_bin: str, time_flag: str) -> TrialResult:
    proc = subprocess.run(  # noqa: S603
        [time_bin, time_flag, *cmd],
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout_seconds,
        env={**os.environ, "LC_ALL": "C"},
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"timed worker failed ({proc.returncode}): {' '.join(cmd)}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )

    values: dict[str, str] = {}
    for line in proc.stdout.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    if "wall_seconds" not in values:
        raise RuntimeError(f"worker omitted wall_seconds:\n{proc.stdout}")

    match = _BSD_RSS_RE.search(proc.stderr)
    if match is not None:
        peak_rss_bytes = int(match.group(1))
    else:
        match = _GNU_RSS_RE.search(proc.stderr)
        if match is None:
            raise RuntimeError(f"could not parse peak RSS from {time_bin}:\n{proc.stderr}")
        peak_rss_bytes = int(match.group(1)) * 1024
    return TrialResult(float(values["wall_seconds"]), peak_rss_bytes, values)


def _copy_fixture(source: Path, sandbox: Path) -> None:
    target = sandbox / "db" / "pfbalexawhitelist.txt"
    target.parent.mkdir(parents=True)
    try:
        os.link(source, target)
    except OSError:
        shutil.copyfile(source, target)


def _copy_contract(manifest: Path, fixed: Path | None, sandbox: Path) -> Path:
    sandbox.mkdir(parents=True)
    target_manifest = sandbox / "pfb_py_sources.json"
    shutil.copyfile(manifest, target_manifest)
    if fixed is not None:
        target_fixed = sandbox / "pfb_py_top1m.txt"
        try:
            os.link(fixed, target_fixed)
        except OSError:
            shutil.copyfile(fixed, target_fixed)
    return target_manifest


def _run_php_phase(
    phase: str,
    worktree: Path,
    sandboxes: list[Path],
    expected_lines: int,
    timeout_seconds: int,
    time_bin: str,
    time_flag: str,
) -> list[TrialResult]:
    php = shutil.which("php")
    if php is None:
        raise RuntimeError("php executable not found")
    return [
        _run_timed(
            [php, str(PHP_WORKER), phase, str(worktree), str(sandbox), str(expected_lines)],
            timeout_seconds,
            time_bin,
            time_flag,
        )
        for sandbox in sandboxes
    ]


def _run_python_phase(
    phase: str,
    worktree: Path,
    manifests: list[Path],
    expected_lines: int,
    timeout_seconds: int,
    time_bin: str,
    time_flag: str,
) -> list[TrialResult]:
    return [
        _run_timed(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "worker-python",
                phase,
                str(worktree),
                str(manifest),
                str(expected_lines),
            ],
            timeout_seconds,
            time_bin,
            time_flag,
        )
        for manifest in manifests
    ]


def _git_output(args: list[str]) -> str:
    return subprocess.run(  # noqa: S603
        ["git", *args], cwd=REPO_ROOT, capture_output=True, text=True, check=True, timeout=60
    ).stdout.strip()


def _runtime_line(command: list[str]) -> str:
    return subprocess.run(  # noqa: S603
        command, capture_output=True, text=True, check=True, timeout=60
    ).stdout.strip()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _format_result(label: str, trials: list[TrialResult]) -> str:
    walls = [trial.wall_seconds for trial in trials]
    rss_values = [trial.peak_rss_bytes for trial in trials]
    return (
        f"{label}: trials={len(trials)} wall_median={statistics.median(walls):.6f}s "
        f"wall_range={min(walls):.6f}..{max(walls):.6f}s "
        f"peak_rss_max={max(rss_values)}B ({max(rss_values) / 1_048_576:.2f}MiB)"
    )


def run(args: argparse.Namespace) -> int:
    base_ref = args.base_ref or _git_output(["merge-base", "HEAD", "origin/devel"])
    branch_sha = _git_output(["rev-parse", "HEAD"])
    branch_dirty = bool(_git_output(["status", "--porcelain"]))
    time_bin = shutil.which("time") or "/usr/bin/time"
    time_flag = _time_flag(time_bin, args.timeout_seconds)
    temp_root = Path(tempfile.mkdtemp(prefix="pfb_bench_top1m_"))
    base_worktree = temp_root / "base_ref"
    worktree_added = False

    previous_handlers: dict[int, object] = {}

    def interrupted(signum: int, frame: object) -> None:
        del frame
        raise KeyboardInterrupt(f"signal {signum}")

    for signum in (signal.SIGINT, signal.SIGTERM):
        previous_handlers[signum] = signal.signal(signum, interrupted)

    try:
        subprocess.run(  # noqa: S603
            ["git", "worktree", "add", "--detach", str(base_worktree), base_ref],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        )
        worktree_added = True

        fixture = temp_root / "pfbalexawhitelist.txt"
        generated_bytes = generate_top1m(fixture, args.lines)
        if args.lines == DEFAULT_LINES and generated_bytes <= 0:
            raise RuntimeError("million-domain fixture generation failed")

        writer_sandboxes = [temp_root / f"writer_branch_{trial}" for trial in range(args.trials)]
        for sandbox in writer_sandboxes:
            _copy_fixture(fixture, sandbox)
        writer = _run_php_phase(
            "write",
            REPO_ROOT,
            writer_sandboxes,
            args.lines,
            args.timeout_seconds,
            time_bin,
            time_flag,
        )
        contract_manifest = writer_sandboxes[0] / "pfb_py_sources.json"
        contract_fixed = writer_sandboxes[0] / "pfb_py_top1m.txt"

        patch: dict[str, list[TrialResult]] = {}
        validate: dict[str, list[TrialResult]] = {}
        for label, worktree in (("base", base_worktree), ("branch", REPO_ROOT)):
            patch_sandboxes = [temp_root / f"patch_{label}_{trial}" for trial in range(args.trials)]
            for sandbox in patch_sandboxes:
                _copy_contract(contract_manifest, None, sandbox)
            patch[label] = _run_php_phase(
                "patch",
                worktree,
                patch_sandboxes,
                args.lines,
                args.timeout_seconds,
                time_bin,
                time_flag,
            )

            validate_manifests = [
                _copy_contract(contract_manifest, None, temp_root / f"validate_{label}_{trial}")
                for trial in range(args.trials)
            ]
            validate[label] = _run_python_phase(
                "validate",
                worktree,
                validate_manifests,
                args.lines,
                args.timeout_seconds,
                time_bin,
                time_flag,
            )

        build_manifests = [
            _copy_contract(contract_manifest, contract_fixed, temp_root / f"build_branch_{trial}")
            for trial in range(args.trials)
        ]
        build = _run_python_phase(
            "build",
            REPO_ROOT,
            build_manifests,
            args.lines,
            args.timeout_seconds,
            time_bin,
            time_flag,
        )

        manifest_bytes = int(writer[0].values["manifest_bytes"])
        fixed_bytes = int(writer[0].values["fixed_bytes"])
        if any(int(trial.values["fixed_lines"]) != args.lines for trial in writer):
            raise RuntimeError("writer trials did not publish exact requested line count")
        if any(int(trial.values["manifest_bytes"]) != manifest_bytes for trial in writer):
            raise RuntimeError("writer trials produced different manifest sizes")
        if any(int(trial.values["fixed_bytes"]) != fixed_bytes for trial in writer):
            raise RuntimeError("writer trials produced different fixed-file sizes")
        if any(int(trial.values["unique_top1m_domains"]) != args.lines for trial in build):
            raise RuntimeError("full-build trials did not consume exact unique TOP1M count")

        command = (
            f"python3 scripts/bench_top1m_fixed_file.py run --base-ref {base_ref} "
            f"--lines {args.lines} --trials {args.trials} --timeout-seconds {args.timeout_seconds}"
        )
        report = [
            "ISSUE #1542 -- FIXED-FILE TOP1M BENCHMARK",
            "==========================================",
            f"command: {command}",
            f"base_sha: {base_ref}",
            f"branch_sha: {branch_sha}",
            f"branch_worktree_dirty: {'yes' if branch_dirty else 'no'}",
            "branch_pfblockerng_inc_sha256: " + _sha256(REPO_ROOT / "src/usr/local/pkg/pfblockerng/pfblockerng.inc"),
            "branch_pfb_unbound_py_sha256: " + _sha256(REPO_ROOT / "src/usr/local/pkg/pfblockerng/pfb_unbound.py"),
            f"host: {platform.platform()} machine={platform.machine()} logical_cpus={os.cpu_count()}",
            f"python: {platform.python_version()} ({sys.executable})",
            f"php: {_runtime_line([shutil.which('php') or 'php', '-r', 'echo PHP_VERSION;'])}",
            f"time: {time_bin} {time_flag}",
            f"fixture: deterministic unique domains={args.lines} generated_bytes={generated_bytes}",
            f"manifest_bytes: {manifest_bytes}",
            f"fixed_file_bytes: {fixed_bytes}",
            f"trials_per_phase_ref: {args.trials}",
            f"per_process_deadline_seconds: {args.timeout_seconds}",
            "",
            "Measurements (isolated seam wall time; whole fresh-process peak RSS)",
            "------------------------------------------------------------------",
            "phase1.php_full_writer base: N/A -- old contract embeds TOP1M and has no fixed-file writer",
            _format_result("phase1.php_full_writer branch", writer),
            _format_result("phase2.php_scalar_patch base", patch["base"]),
            _format_result("phase2.php_scalar_patch branch", patch["branch"]),
            _format_result("phase3.python_json_validate base", validate["base"]),
            _format_result("phase3.python_json_validate branch", validate["branch"]),
            "phase4.python_full_build base: N/A -- old contract cannot consume the fixed TOP1M file",
            _format_result("phase4.python_full_build branch", build),
            "",
            "Contract assertions executed in every applicable trial",
            "------------------------------------------------------",
            "manifest has no top1m_list, top1m_ref, or sampled TOP1M domain: PASS",
            f"fixed file has exactly {args.lines} lines: PASS",
            f"full build exposes exactly {args.lines} unique TOP1M white_db domains: PASS",
            "thresholds: none (measurements only; no invented pass/fail gate)",
        ]
        print("\n".join(report))
        return 0
    finally:
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)
        if worktree_added:
            subprocess.run(  # noqa: S603
                ["git", "worktree", "remove", "--force", str(base_worktree)],
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
                text=True,
                timeout=60,
            )
        shutil.rmtree(temp_root, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="run the base-versus-branch benchmark")
    run_parser.add_argument("--base-ref")
    run_parser.add_argument("--lines", type=_line_count, default=DEFAULT_LINES)
    run_parser.add_argument("--trials", type=_positive_int, default=DEFAULT_TRIALS)
    run_parser.add_argument("--timeout-seconds", type=_positive_int, default=DEFAULT_TIMEOUT_SECONDS)

    worker_parser = subparsers.add_parser("worker-python", help=argparse.SUPPRESS)
    worker_parser.add_argument("phase", choices=("validate", "build"))
    worker_parser.add_argument("worktree", type=Path)
    worker_parser.add_argument("manifest", type=Path)
    worker_parser.add_argument("expected_lines", type=_positive_int)

    args = parser.parse_args()
    if args.command == "worker-python":
        return worker_python(args.phase, args.worktree, args.manifest, args.expected_lines)
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
