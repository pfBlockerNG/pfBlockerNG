#!/usr/bin/env python3
"""ADR-62 perf-regression harness: DNSBL per-line parsing at 1M-line scale.

Compares TWO git refs (a base ref, typically origin/devel's merge-base, vs the
working tree) on the two off-appliance surfaces the ADR's broadened per-line
capture touches:

  (a) PHP  -- pfb_unbound_python_sources() (the manifest writer) over a staged
      ``.txt`` feed. The DNSBL download loop itself has no off-appliance
      driver (ADR.md SS1), so the writer is the earliest driveable
      surface for the PHP-side cost.
  (b) Python -- dnsbl_build_from_manifest() over the resulting ``.raw``.

Fixture: a synthetic 'plain' feed, 97% unique bare-domain lines / 2% '||d^' /
1% '@@||d^' -- every bare-domain line (the majority case) must run the full
capture-predicate rejection path on both sides, which is exactly the added
per-line cost this benchmark exists to measure (ADR.md SS3 "Consequences").

Each (ref, surface) trial: --iterations internal repeats in one process
(isolated wall-clock via a monotonic clock around JUST the timed call, so
process/import startup is excluded) wrapped once by ``/usr/bin/time`` for
whole-process peak RSS. --trials independent process invocations are run and
the median-of-medians is reported, to average out OS scheduling/disk-cache
noise; peak RSS is the max across trials.

Usage:
    python3 scripts/bench_dnsbl_line_parsing.py run [--base-ref SHA]
        [--lines N] [--iterations N] [--trials N] [--threshold-pct PCT] [--keep]

    # internal worker entry point (spawned as a subprocess, do not call directly)
    python3 scripts/bench_dnsbl_line_parsing.py worker-python WORKTREE RAW_PATH ITERATIONS
"""

from __future__ import annotations

import argparse
import builtins
import json
import os
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PHP_WORKER = os.path.join(REPO_ROOT, "scripts", "bench_dnsbl_line_parsing.php")


# --------------------------------------------------------------------------- #
# Fixture generation -- deterministic (no RNG), so both fixtures are
# byte-reproducible across runs and refs.
# --------------------------------------------------------------------------- #


def _txt_line(i: int) -> str:
    """NDJSON schema v1 (issue #1083) row shape -- see pfb_dnsbl_ndjson_emit_domain_row()/
    pfb_dnsbl_ndjson_emit_abp_row() in pfblockerng.inc for the contract."""
    m = i % 100
    if m < 97:
        domain = f"uuid-bench-{i}.example.com"
        return f'{{"kind":"domain","domain":"{domain}","log":"1","feed":"benchfeed","group":"benchfeed"}}\n'
    if m < 99:
        return f'{{"kind":"abp","raw":"||uuid-bench-{i}.example.com^"}}\n'
    return f'{{"kind":"abp","raw":"@@||uuid-bench-{i}.example.com^"}}\n'


def _raw_line(i: int) -> str:
    m = i % 100
    if m < 97:
        return f"uuid-bench-{i}.example.com\n"
    if m < 99:
        return f"||uuid-bench-{i}.example.com^\n"
    return f"@@||uuid-bench-{i}.example.com^\n"


def generate_fixtures(lines: int, txt_out: str, raw_out: str) -> None:
    with open(txt_out, "w", encoding="utf-8") as fh:
        fh.writelines(_txt_line(i) for i in range(lines))
    with open(raw_out, "w", encoding="utf-8") as fh:
        fh.writelines(_raw_line(i) for i in range(lines))


# --------------------------------------------------------------------------- #
# Python-side worker (run as a fresh subprocess per (ref, trial) so each gets
# a clean RSS baseline and imports the TARGET worktree's pfb_unbound.py).
# --------------------------------------------------------------------------- #


def worker_python(worktree: str, raw_path: str, iterations: int) -> int:
    import resource

    sys.path.insert(0, os.path.join(worktree, "stubs", "python"))
    import unboundmodule

    for name in unboundmodule.__all__:
        setattr(builtins, name, getattr(unboundmodule, name))

    sys.path.insert(0, os.path.join(worktree, "src", "usr", "local", "pkg", "pfblockerng"))
    import pfb_unbound

    sandbox = os.path.dirname(raw_path)
    manifest_path = os.path.join(sandbox, "pfb_py_sources.json")
    manifest = {
        "version": 1,
        "config": {
            "tld_master": [],
            "tld_blacklist": [],
            "tld_exclusion": [],
            "user_whitelist": [],
            "user_unlock": [],
            "top1m_list": [],
            "top1m_enabled": False,
        },
        "feeds": [
            {
                "raw": os.path.basename(raw_path),
                "feed": "benchfeed",
                "group": "grp",
                "format_hint": "plain",
                "provenance": "feed",
                "log_flag": "1",
            }
        ],
    }
    with open(manifest_path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh)

    durations = []
    result = None
    for i in range(iterations):
        t0 = time.perf_counter()
        result = pfb_unbound.dnsbl_build_from_manifest(manifest_path)
        dt = time.perf_counter() - t0
        if result is None:
            raise RuntimeError("DNSBL benchmark build failed (dnsbl_build_from_manifest returned None)")
        durations.append(dt)
        print(f"[py] iter {i}: {dt:.4f}s", file=sys.stderr)

    durations.sort()
    print(f"isolated_median_seconds={statistics.median(durations):.4f}")
    print(f"isolated_min_seconds={durations[0]:.4f}")
    print(f"isolated_max_seconds={durations[-1]:.4f}")
    if result is not None:
        print(f"data_db_size={len(result.data_db)}")
        print(f"zone_db_size={len(result.zone_db)}")
        print(f"white_db_size={len(result.white_db)}")
    # Also self-report via getrusage as a cross-check against the /usr/bin/time
    # wrapper the caller applies around this whole process (ru_maxrss is BYTES
    # on macOS/BSD, KILOBYTES on Linux -- the caller's /usr/bin/time reading is
    # authoritative and platform-normalised; this line is diagnostic only).
    ru = resource.getrusage(resource.RUSAGE_SELF)
    print(f"self_ru_maxrss={ru.ru_maxrss}")
    return 0


# --------------------------------------------------------------------------- #
# /usr/bin/time wrapping -- BSD (macOS, `-l`) and GNU (Linux, `-v`) formats.
# --------------------------------------------------------------------------- #

_BSD_RSS_RE = re.compile(r"^\s*(\d+)\s+maximum resident set size", re.MULTILINE)
_GNU_RSS_RE = re.compile(r"Maximum resident set size \(kbytes\):\s*(\d+)", re.MULTILINE)


@dataclass
class TrialResult:
    isolated_median_s: float
    isolated_min_s: float
    isolated_max_s: float
    peak_rss_bytes: int
    stdout: str = field(repr=False, default="")


def _run_timed(cmd: list[str]) -> TrialResult:
    """Run cmd wrapped by the platform's /usr/bin/time, parse its stdout
    key=value lines plus the wrapper's peak-RSS line (bytes, normalised).
    """
    time_bin = shutil.which("time") or "/usr/bin/time"
    # BSD time takes -l, GNU time takes -v; probe instead of assuming per-OS
    # (a BSD host is not necessarily macOS). LC_ALL=C pins the GNU output
    # format so the RSS regex cannot miss on a localized label.
    env = {**os.environ, "LC_ALL": "C"}
    probe = subprocess.run([time_bin, "-l", "true"], capture_output=True, text=True, env=env, check=False)  # noqa: S603
    flag = "-l" if probe.returncode == 0 else "-v"
    proc = subprocess.run([time_bin, flag, *cmd], capture_output=True, text=True, check=True, env=env)  # noqa: S603

    values: dict[str, str] = {}
    for line in proc.stdout.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            values[k] = v

    m = _BSD_RSS_RE.search(proc.stderr)
    if m:
        rss_bytes = int(m.group(1))
    else:
        m = _GNU_RSS_RE.search(proc.stderr)
        if m is None:
            # A silent 0 would make pct_delta(0, 0) read as "no regression".
            raise RuntimeError(f"could not parse peak RSS from {time_bin} output:\n{proc.stderr}")
        rss_bytes = int(m.group(1)) * 1024

    return TrialResult(
        isolated_median_s=float(values["isolated_median_seconds"]),
        isolated_min_s=float(values["isolated_min_seconds"]),
        isolated_max_s=float(values["isolated_max_seconds"]),
        peak_rss_bytes=rss_bytes,
        stdout=proc.stdout,
    )


def bench_php(worktree: str, sandbox: str, iterations: int) -> TrialResult:
    return _run_timed(["php", PHP_WORKER, worktree, sandbox, str(iterations)])


def bench_python(worktree: str, raw_path: str, iterations: int) -> TrialResult:
    return _run_timed([sys.executable, os.path.abspath(__file__), "worker-python", worktree, raw_path, str(iterations)])


def aggregate_trials(trials: list[TrialResult]) -> TrialResult:
    return TrialResult(
        isolated_median_s=statistics.median(t.isolated_median_s for t in trials),
        isolated_min_s=min(t.isolated_min_s for t in trials),
        isolated_max_s=max(t.isolated_max_s for t in trials),
        peak_rss_bytes=max(t.peak_rss_bytes for t in trials),
    )


def pct_delta(base: float, new: float) -> float:
    if base == 0:
        return 0.0 if new == 0 else float("inf")
    return (new - base) / base * 100.0


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #


def run(args: argparse.Namespace) -> int:
    base_ref = args.base_ref
    if base_ref is None:
        base_ref = subprocess.run(  # noqa: S603
            ["git", "merge-base", "HEAD", "origin/devel"], cwd=REPO_ROOT, capture_output=True, text=True, check=True
        ).stdout.strip()

    workdir = tempfile.mkdtemp(prefix="pfb_bench_dnsbl_")
    base_worktree = os.path.join(workdir, "base_ref")
    print(f"# base_ref={base_ref}", file=sys.stderr)
    print(f"# workdir={workdir}", file=sys.stderr)
    subprocess.run(  # noqa: S603
        ["git", "worktree", "add", "--detach", base_worktree, base_ref], cwd=REPO_ROOT, check=True, capture_output=True
    )

    try:
        txt_path = os.path.join(workdir, "benchfeed.txt")
        raw_path = os.path.join(workdir, "benchfeed.raw")
        print(f"# generating {args.lines} lines ...", file=sys.stderr)
        generate_fixtures(args.lines, txt_path, raw_path)

        refs = {"base": base_worktree, "branch": REPO_ROOT}
        php_results: dict[str, TrialResult] = {}
        py_results: dict[str, TrialResult] = {}

        for label, worktree in refs.items():
            sandbox = os.path.join(workdir, f"sandbox_php_{label}")
            os.makedirs(os.path.join(sandbox, "dnsbl"), exist_ok=True)
            shutil.copy(txt_path, os.path.join(sandbox, "dnsbl", "benchfeed.txt"))
            trials = [bench_php(worktree, sandbox, args.iterations) for _ in range(args.trials)]
            php_results[label] = aggregate_trials(trials)
            print(f"# php[{label}]: {php_results[label]}", file=sys.stderr)

            py_sandbox = os.path.join(workdir, f"sandbox_py_{label}", "pfb_py_raw")
            os.makedirs(py_sandbox, exist_ok=True)
            ref_raw = os.path.join(py_sandbox, "benchfeed.raw")
            shutil.copy(raw_path, ref_raw)
            trials = [bench_python(worktree, ref_raw, args.iterations) for _ in range(args.trials)]
            py_results[label] = aggregate_trials(trials)
            print(f"# python[{label}]: {py_results[label]}", file=sys.stderr)

        return 0 if report(php_results, py_results, args.threshold_pct) else 1
    finally:
        if not args.keep:
            subprocess.run(["git", "worktree", "remove", "--force", base_worktree], cwd=REPO_ROOT, check=False)  # noqa: S603
            shutil.rmtree(workdir, ignore_errors=True)
        else:
            print(f"# --keep: leaving {workdir} and worktree {base_worktree} in place", file=sys.stderr)


def report(php_results: dict[str, TrialResult], py_results: dict[str, TrialResult], threshold_pct: float) -> bool:
    print("\n=== ADR-62 perf benchmark ===")
    verdict_pass = True
    surfaces = (
        ("PHP  pfb_unbound_python_sources()", php_results),
        ("Python dnsbl_build_from_manifest()", py_results),
    )
    for surface, results in surfaces:
        base, branch = results["base"], results["branch"]
        wall_delta = pct_delta(base.isolated_median_s, branch.isolated_median_s)
        rss_delta = pct_delta(base.peak_rss_bytes, branch.peak_rss_bytes)
        print(f"\n-- {surface} --")
        print(f"  base:   wall={base.isolated_median_s:.4f}s  peak_rss={base.peak_rss_bytes / 1_048_576:.1f} MiB")
        print(f"  branch: wall={branch.isolated_median_s:.4f}s  peak_rss={branch.peak_rss_bytes / 1_048_576:.1f} MiB")
        print(f"  delta:  wall={wall_delta:+.2f}%  peak_rss={rss_delta:+.2f}%")
        if wall_delta > threshold_pct or rss_delta > threshold_pct:
            verdict_pass = False

    print(f"\nkill-threshold: >{threshold_pct:.0f}% wall-clock OR RSS (ADR.md SS7 criterion 2)")
    print("VERDICT: PASS" if verdict_pass else "VERDICT: REJECT-criterion-2-triggered")
    return verdict_pass


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("value must be at least 1")
    return parsed


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    run_p = sub.add_parser("run", help="run the full base-ref vs working-tree comparison")
    run_p.add_argument(
        "--base-ref", default=None, help="git ref to compare against (default: merge-base with origin/devel)"
    )
    run_p.add_argument("--lines", type=_positive_int, default=1_000_000)
    run_p.add_argument("--iterations", type=_positive_int, default=5, help="internal repeats per trial process")
    run_p.add_argument(
        "--trials", type=_positive_int, default=2, help="independent process invocations per (ref, surface)"
    )
    run_p.add_argument("--threshold-pct", type=float, default=25.0)
    run_p.add_argument("--keep", action="store_true", help="keep the temp worktree/fixtures for inspection")

    worker_p = sub.add_parser("worker-python", help=argparse.SUPPRESS)
    worker_p.add_argument("worktree")
    worker_p.add_argument("raw_path")
    worker_p.add_argument("iterations", type=int)

    args = ap.parse_args()
    if args.cmd == "worker-python":
        return worker_python(args.worktree, args.raw_path, args.iterations)
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
