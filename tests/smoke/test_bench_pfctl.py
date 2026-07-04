"""ADR-40 pfctl table benchmark + reject-loop data-plane bench (dispatch-only, NOT PR-gating).

Two benchmark tests, both marked ``pfctl_bench``:

``test_pfctl_bench``
    Original Phase 2 broad matrix: replace + delta at multiple batch/churn/size
    combos + recompute cost.  Single-pass, single-rep per cell.  Kept for
    historical comparison and quick orientation runs.

``test_pfctl_reject_loop``
    Definitive ADR-40 data-plane bench using a REJECT-based closed measurement
    loop (no timeout artifacts).  Two pf rules ensure every probe packet returns
    immediately via TCP RST regardless of table membership:
      - LAN reject: block return on the LAN interface for traffic from civm to
        addresses in the bench table (in-table → RST at LAN rule).
      - WAN floating reject: block return out on WAN for all outbound traffic
        (not-in-table → routes toward WAN → WAN RST).
    Both variants (LAN interface rule vs floating rule) are compared.
    Probe: asyncio TCP connect loop on civm to IPs drawn from both the stable
    in-table set (11.x) and the churn set (13.x).  Time to ECONNREFUSED = RTT.
    20 reps per cell; op-aligned windows; pooled distribution stats.

``test_pfctl_knee_sweep``
    Production-calibrated, well-sampled benchmark added in the follow-up review
    run.  Measures:
      - Replace baselines at 100k, 462k, 1M (production sizes).
      - Batch-size knee sweep: {256,384,512,768,1024,2048,4096} at churn=46k/462k
        and 100k/1M (the two production-relevant knee cells).
      - Realistic small-churn reference: ~1% and ~5% at 100k/462k at the
        recommended batch and at 256 (contrast).
    20 repeats per cell; 500 pps ICMP probe (ping -i 0.002); op-aligned windows
    (CR#12).  Per-cell pooled RTT distribution: n, mean, stddev (pstdev), min,
    p50, p95, p99, p99.9, max, loss%, spikes.  Percentile method: nearest-rank.
    Confidence flags: p99 [unreliable] when n<100; p99.9 [low-confidence] when
    n<1000.

PRIMARY SIGNAL: ICMP RTT distribution + packet loss from civm (192.168.1.10)
  to pfSense LAN IP (192.168.1.1) during each pfctl op.
SECONDARY SIGNAL: pfctl -T show latency on the pfSense guest (control-plane
  lock proxy).

Marker: pfctl_bench — NEVER PR-gating.
Run via:
    scripts/local-smoke.sh tests/smoke/test_bench_pfctl.py -m pfctl_bench \\
        --override-ini="addopts="

For the reject-loop bench:
    SMOKE_VM_SMP="3,sockets=1,cores=3" SMOKE_VM_MEM=6144 \\
    SMOKE_CLIENT_SMP="3,sockets=1,cores=3" \\
    scripts/local-smoke.sh tests/smoke/test_bench_pfctl.py \\
        -m pfctl_bench -k test_pfctl_reject_loop --override-ini="addopts="

For the production-calibrated knee sweep with 3 cores/VM and 6 GiB pfSense RAM:
    SMOKE_VM_SMP="3,sockets=1,cores=3" SMOKE_VM_MEM=6144 \\
    SMOKE_CLIENT_SMP="3,sockets=1,cores=3" \\
    scripts/local-smoke.sh tests/smoke/test_bench_pfctl.py \\
        -m pfctl_bench -k test_pfctl_knee_sweep --override-ini="addopts="

Requires: smoke_vm + client_vm (two-VM topology) + lan_interface.  Skips
cleanly when civm is unavailable (pfSense-only environments).

Design notes for Phase 4 (recorded here per ADR §7):
  - Boot / enable-disable: one-shot -T replace is correct (no delta needed).
  - Incremental feed updates: this benchmark's verdict decides replace vs delta.
  - Recommended batch size + mode recorded in RESULTS/02_Results.txt.
"""

from __future__ import annotations

import math
import re
import shlex
import statistics
import subprocess
import threading
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from .conftest import PFSENSE_LAN_IP, SmokeVM

pytestmark = pytest.mark.pfctl_bench

# Path to the bench script relative to repo root.
_BENCH_SH = Path(__file__).parents[2] / "scripts" / "bench_pfctl_tables.sh"

# Spike threshold: RTT > baseline_p99 * this factor counts as a stall event.
_SPIKE_FACTOR = 3.0

# Table sizes for the original broad-matrix benchmark.
_SIZES = [10_000, 100_000, 1_000_000]

# Batch sizes for the original benchmark.  0 = single-giant-op.
_BATCH_SIZES = [0, 1, 64, 256, 1024, 4096]

# --------------------------------------------------------------------------- #
# Production-calibrated knee sweep parameters
# --------------------------------------------------------------------------- #

# Production-realistic table sizes (100k = common, 462k = QFeeds max, 1M = stress).
_KNEE_SIZES = [100_000, 462_000, 1_000_000]

# Batch sizes to sweep for the knee curve.
_KNEE_BATCHES = [256, 384, 512, 768, 1024, 2048, 4096]

# Churn cells: (table_size, churn) for the knee sweep.
# 46k/462k = 10% of the production-max table.
# 100k/1M  = 10% of the stress table.
# Both are large enough that every batch genuinely chunks (churn >> 4096).
_KNEE_CELLS = [(462_000, 46_000), (1_000_000, 100_000)]

# Small-churn reference cells: (table_size, churn_pct_label, churn).
# Validates the everyday daily-feed-update case.
_SMALL_CHURN_CELLS = [
    (100_000, "1pct", 1_000),
    (100_000, "5pct", 5_000),
    (462_000, "1pct", 4_620),
    (462_000, "5pct", 23_100),
]

# Repeats per cell.  20 reps × 500 pps yields ≥1000 pooled samples for ops ≥100ms.
# Short ops (replace 100k ~90ms → ~45 samples/rep → ~900 total) may fall below 1000;
# confidence flags mark those cells.
_REPS = 20

# Ping interval for the knee sweep: 0.002s = 500 pps.
_KNEE_INTERVAL = 0.002


# --------------------------------------------------------------------------- #
# Data types
# --------------------------------------------------------------------------- #


@dataclass
class IcmpProbe:
    """Per-packet ICMP RTT sample collected from civm."""

    rtt_ms: float  # round-trip time in milliseconds
    seq: int  # ping sequence number
    recv_epoch: float = 0.0  # Unix timestamp of packet receipt (from ping -D; 0 if unavailable)


@dataclass
class ProbeWindow:
    """Statistics for a probe window (baseline or during-op)."""

    samples: list[IcmpProbe] = field(default_factory=list)
    lost: int = 0  # packets sent but no reply received

    def p50(self) -> float:
        return _percentile(self.samples, 0.50)

    def p99(self) -> float:
        return _percentile(self.samples, 0.99)

    def pmax(self) -> float:
        if not self.samples:
            return 0.0
        return max(s.rtt_ms for s in self.samples)

    def sent(self) -> int:
        return len(self.samples) + self.lost

    def loss_pct(self) -> float:
        total = self.sent()
        return 100.0 * self.lost / total if total > 0 else 0.0

    def spike_count(self, threshold_ms: float) -> int:
        """Count RTT samples exceeding threshold_ms (data-plane stall events)."""
        return sum(1 for s in self.samples if s.rtt_ms > threshold_ms)


def _percentile(samples: list[IcmpProbe], p: float) -> float:
    if not samples:
        return 0.0
    vals = sorted(s.rtt_ms for s in samples)
    idx = min(int(len(vals) * p), len(vals) - 1)
    return vals[idx]


@dataclass
class BenchRow:
    """One benchmark measurement row."""

    op: str  # replace | delta | recompute
    size: int  # table size
    churn: int  # entries changed (0 for replace/recompute)
    batch: str  # giant | int | - (for replace/recompute)
    wall_ms: int  # total wall time of the op in ms (timeout budget if timed_out)
    # Data-plane (ICMP) probe results.
    icmp_baseline: ProbeWindow = field(default_factory=ProbeWindow)
    icmp_during: ProbeWindow = field(default_factory=ProbeWindow)
    # Control-plane (pfctl -T show) probe results from the guest.
    ctrl_p50_ms: int = 0
    ctrl_p99_ms: int = 0
    ctrl_max_ms: int = 0
    ctrl_n: int = 0
    timed_out: bool = False  # True if the op exceeded its timeout budget

    def stall_added_p99(self) -> float:
        """p99 RTT during-op minus p99 RTT baseline (added latency)."""
        return max(0.0, self.icmp_during.p99() - self.icmp_baseline.p99())


# --------------------------------------------------------------------------- #
# Pooled-distribution stats (for the knee sweep)
# --------------------------------------------------------------------------- #


@dataclass
class PooledStats:
    """Full RTT distribution pooled across all repeats of a cell.

    Percentile method: nearest-rank (floor(n*p) index, 0-based, clamped to n-1).
    Confidence:
      n < 100  → p99 [unreliable]; p99.9 meaningless.
      n < 1000 → p99.9 [low-confidence].
    """

    n: int = 0
    mean_ms: float = 0.0
    stddev_ms: float = 0.0  # population stdev (statistics.pstdev)
    min_ms: float = 0.0
    p50_ms: float = 0.0
    p95_ms: float = 0.0
    p99_ms: float = 0.0
    p999_ms: float = 0.0  # p99.9
    max_ms: float = 0.0
    total_loss: int = 0
    total_sent: int = 0
    spikes: int = 0
    spike_threshold_ms: float = 0.0

    def loss_pct(self) -> float:
        return 100.0 * self.total_loss / self.total_sent if self.total_sent > 0 else 0.0

    def p99_conf(self) -> str:
        return "unreliable" if self.n < 100 else "ok"

    def p999_conf(self) -> str:
        return "low-confidence" if self.n < 1000 else "ok"


def _compute_pooled(
    windows: list[ProbeWindow],
    baseline_windows: list[ProbeWindow],
) -> PooledStats:
    """Pool RTT samples from all repeat windows; compute full distribution."""
    all_samples: list[IcmpProbe] = []
    for w in windows:
        all_samples.extend(w.samples)

    total_loss = sum(w.lost for w in windows)
    total_sent = sum(w.sent() for w in windows)

    baseline_p99s = [w.p99() for w in baseline_windows if w.samples]
    median_bp99 = statistics.median(baseline_p99s) if baseline_p99s else 0.0
    spike_thresh = median_bp99 * _SPIKE_FACTOR

    n = len(all_samples)
    if n == 0:
        return PooledStats(total_loss=total_loss, total_sent=total_sent)

    rtts = sorted(s.rtt_ms for s in all_samples)
    spikes = sum(1 for r in rtts if r > spike_thresh) if spike_thresh > 0 else 0

    def pct(p: float) -> float:
        idx = min(int(math.floor(n * p)), n - 1)
        return rtts[idx]

    return PooledStats(
        n=n,
        mean_ms=statistics.mean(rtts),
        stddev_ms=statistics.pstdev(rtts),
        min_ms=rtts[0],
        p50_ms=pct(0.50),
        p95_ms=pct(0.95),
        p99_ms=pct(0.99),
        p999_ms=pct(0.999),
        max_ms=rtts[-1],
        total_loss=total_loss,
        total_sent=total_sent,
        spikes=spikes,
        spike_threshold_ms=spike_thresh,
    )


def _fmt_pct(label: str, val: float, conf: str) -> str:
    flag = "" if conf == "ok" else f" [{conf}]"
    return f"{label}={val:.1f}ms{flag}"


def _print_pooled(tag: str, n_reps: int, med_wall: float, ps: PooledStats) -> None:
    print(
        f"  {tag}"
        f"\n    wall_ms (median/{n_reps} reps): {med_wall:.0f}ms"
        f"\n    pooled n={ps.n} (loss {ps.total_loss}/{ps.total_sent} = {ps.loss_pct():.1f}%)"
        f" spikes>{ps.spike_threshold_ms:.0f}ms={ps.spikes}"
        f"\n    mean={ps.mean_ms:.1f}ms stddev={ps.stddev_ms:.1f}ms"
        f"\n    min={ps.min_ms:.1f}ms {_fmt_pct('p50', ps.p50_ms, 'ok')}"
        f" {_fmt_pct('p95', ps.p95_ms, 'ok')}"
        f" {_fmt_pct('p99', ps.p99_ms, ps.p99_conf())}"
        f" {_fmt_pct('p99.9', ps.p999_ms, ps.p999_conf())}"
        f" max={ps.max_ms:.1f}ms"
    )


# --------------------------------------------------------------------------- #
# ICMP probe runner (civm side)
# --------------------------------------------------------------------------- #


def _run_icmp_probe(
    client_vm: SmokeVM,
    target: str,
    duration_s: float,
    interval_s: float = 0.02,
) -> ProbeWindow:
    """Run ping from civm to target for duration_s; return per-packet stats.

    Uses ``ping -i <interval> -W 1 <target>`` on the civm Debian guest (as root,
    civm is Debian not pfSense so /bin/sh parses it correctly).
    -D: prefix each reply line with [unix_ts.us] for op-window slicing.
    """
    count = max(1, int(duration_s / interval_s))
    cmd = f"LC_ALL=C ping -D -c {count} -i {interval_s} -W 1 {shlex.quote(target)} 2>&1"
    result = client_vm.ssh(cmd, timeout=duration_s + 30.0)
    return _parse_ping(result.stdout)


def _parse_ping(output: str) -> ProbeWindow:
    """Parse ``ping -D`` output into per-packet RTT samples + loss count."""
    window = ProbeWindow()
    for m in re.finditer(r"(?:\[([\d.]+)\]\s+)?.*?icmp_seq=(\d+).*?time=([\d.]+)\s+ms", output):
        recv_epoch = float(m.group(1)) if m.group(1) else 0.0
        window.samples.append(IcmpProbe(seq=int(m.group(2)), rtt_ms=float(m.group(3)), recv_epoch=recv_epoch))
    summary = re.search(r"(\d+) packets transmitted, (\d+) received", output)
    if summary:
        sent = int(summary.group(1))
        recv = int(summary.group(2))
        window.lost = max(0, sent - recv)
    return window


# --------------------------------------------------------------------------- #
# Background ICMP probe (runs concurrently with pfctl ops)
# --------------------------------------------------------------------------- #


class _LiveProbe:
    """Continuous ping on civm in a background thread.

    Accumulates per-packet samples; caller calls ``start()``, then
    ``slice_window(t0, t1)`` to get op-aligned samples, then ``stop()``.
    """

    def __init__(self, client_vm: SmokeVM, target: str, interval_s: float = 0.02) -> None:
        self._client = client_vm
        self._target = target
        self._interval = interval_s
        self._samples: list[IcmpProbe] = []
        self._lost: int = 0
        self._lock = threading.Lock()
        self._stop_evt = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def _run(self) -> None:
        # Fire batches of ~100 pings with per-packet timestamps (-D), collect, repeat until stopped.
        # LC_ALL=C: pin locale so ping output matches the RTT regex on any Debian locale.
        batch_count = 100
        while not self._stop_evt.is_set():
            cmd = f"LC_ALL=C ping -D -c {batch_count} -i {self._interval} -W 1 {shlex.quote(self._target)} 2>&1"
            duration = batch_count * self._interval + 5.0
            result = self._client.ssh(cmd, timeout=duration + 10.0)
            pw = _parse_ping(result.stdout)
            with self._lock:
                self._samples.extend(pw.samples)
                self._lost += pw.lost

    def snapshot_since(self, since_epoch: float) -> ProbeWindow:
        """Return samples whose recv_epoch >= since_epoch (gracefully degrades when epoch=0)."""
        with self._lock:
            pw = ProbeWindow()
            pw.samples = [s for s in self._samples if s.recv_epoch == 0.0 or s.recv_epoch >= since_epoch]
            pw.lost = self._lost
            return pw

    def slice_window(self, t0: float, t1: float) -> ProbeWindow:
        """Return samples in [t0, t1] by civm clock (op-aligned, CR#12)."""
        with self._lock:
            pw = ProbeWindow()
            pw.samples = [
                s for s in self._samples if s.recv_epoch == 0.0 or (s.recv_epoch >= t0 and s.recv_epoch <= t1)
            ]
            pw.lost = 0  # lost packets: not attributable to a window
            return pw

    def stop(self) -> None:
        self._stop_evt.set()
        self._thread.join(timeout=30.0)


# --------------------------------------------------------------------------- #
# Guest script wrapper
# --------------------------------------------------------------------------- #


def _bench(smoke_vm: SmokeVM, *args: str, timeout: float = 600.0) -> dict[str, str]:
    """Run bench_pfctl_tables.sh <args> on the pfSense guest; parse key=val output."""
    script_content = _BENCH_SH.read_text()
    _upload_bench_script(smoke_vm, script_content)
    cmd = "/tmp/bench_pfctl_tables.sh " + " ".join(shlex.quote(str(a)) for a in args)
    try:
        result = smoke_vm.ssh(cmd, timeout=timeout)
    except subprocess.TimeoutExpired:
        op = args[0] if args else "unknown"
        size = args[1] if len(args) > 1 else "0"
        churn = args[2] if len(args) > 2 else "0"
        batch = args[3] if len(args) > 3 else "-"
        print(
            f"\n  [TIMEOUT] op={op} size={size} churn={churn} batch={batch} "
            f"after {timeout:.0f}s — op too slow; recording as wall_ms=TIMEOUT"
        )
        return {
            "timeout": "true",
            "op": op,
            "size": size,
            "churn": churn,
            "batch": batch if batch != "0" else "giant",
            "wall_ms": str(int(timeout * 1000)),
        }
    if result.returncode not in (0,) and "error=" not in result.stdout:
        raise RuntimeError(
            f"bench_pfctl_tables.sh {args!r} failed rc={result.returncode}\n"
            f"stdout={result.stdout!r}\nstderr={result.stderr!r}"
        )
    return _parse_kv(result.stdout)


_SCRIPT_UPLOADED = False


def _upload_bench_script(smoke_vm: SmokeVM, content: str) -> None:
    global _SCRIPT_UPLOADED  # noqa: PLW0603  # ponytail: module-level flag; reset per session
    if _SCRIPT_UPLOADED:
        return
    proc = subprocess.run(
        smoke_vm.ssh_argv("tee /tmp/bench_pfctl_tables.sh > /dev/null && chmod +x /tmp/bench_pfctl_tables.sh"),
        input=content,
        capture_output=True,
        text=True,
        timeout=30.0,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"Failed to upload bench script: {proc.stderr!r}")
    _SCRIPT_UPLOADED = True


def _parse_kv(text: str) -> dict[str, str]:
    """Parse key=val output; last writer wins on duplicate keys."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        for token in line.split():
            if "=" in token:
                k, _, v = token.partition("=")
                if k:
                    out[k] = v
    return out


def _parse_guest_row(kv: dict[str, str]) -> dict[str, object]:
    return {
        "op": kv.get("op", ""),
        "size": int(kv.get("size", 0)),
        "churn": int(kv.get("churn", 0)),
        "batch": kv.get("batch", "-"),
        "wall_ms": int(kv.get("wall_ms", 0)),
        "epoch_start": float(kv.get("epoch_start", 0)),
        "epoch_end": float(kv.get("epoch_end", 0)),
        "ctrl_p50_ms": int(kv.get("ctrl_p50", 0)),
        "ctrl_p99_ms": int(kv.get("ctrl_p99", 0)),
        "ctrl_max_ms": int(kv.get("ctrl_max", 0)),
        "ctrl_n": int(kv.get("ctrl_n", 0)),
        "error": kv.get("error", ""),
        "timed_out": kv.get("timeout", "") == "true",
    }


# --------------------------------------------------------------------------- #
# Probe orchestration: baseline window then concurrent measurement
# --------------------------------------------------------------------------- #


def _measure_with_probe(
    smoke_vm: SmokeVM,
    client_vm: SmokeVM | None,
    bench_args: tuple[str, ...],
    baseline_duration_s: float = 3.0,
    op_timeout_s: float = 600.0,
    interval_s: float = 0.02,
) -> BenchRow:
    """Run one bench op while capturing ICMP baseline and during-op windows.

    If client_vm is None, skips the ICMP probe (returns empty ProbeWindows).
    interval_s controls the ping send rate (default 0.02s = 50 pps).
    The during-window is op-aligned via civm's own clock (CR#12 fix).
    """
    # ---- baseline probe ---- #
    baseline_window = ProbeWindow()
    if client_vm is not None:
        baseline_window = _run_icmp_probe(
            client_vm, PFSENSE_LAN_IP, duration_s=baseline_duration_s, interval_s=interval_s
        )

    # ---- launch background probe ---- #
    probe: _LiveProbe | None = None
    if client_vm is not None:
        probe = _LiveProbe(client_vm, PFSENSE_LAN_IP, interval_s=interval_s)
        probe.start()

    # ---- bracket the op with civm's own clock (CR#12 fix) ---- #
    t0_civm: float = 0.0
    if client_vm is not None:
        res = client_vm.ssh("date +%s.%N", timeout=5.0)
        try:
            t0_civm = float(res.stdout.strip())
        except ValueError:
            t0_civm = 0.0

    # ---- run the pfctl op on the guest ---- #
    kv = _bench(smoke_vm, *bench_args, timeout=op_timeout_s)

    # ---- record op-end on civm clock ---- #
    t1_civm: float = 0.0
    if client_vm is not None:
        res = client_vm.ssh("date +%s.%N", timeout=5.0)
        try:
            t1_civm = float(res.stdout.strip())
        except ValueError:
            t1_civm = 0.0

    # ---- stop probe; build op-aligned during-window ---- #
    during_window = ProbeWindow()
    if probe is not None:
        probe.stop()
        if t0_civm > 0.0 and t1_civm > t0_civm:
            during_window = probe.slice_window(t0_civm, t1_civm)
            print(
                f"\n  [probe-align] t0={t0_civm:.3f} t1={t1_civm:.3f}"
                f" op_wall={(t1_civm - t0_civm) * 1000:.0f}ms"
                f" during_samples={len(during_window.samples)}"
                f" (expected ≈{(t1_civm - t0_civm) / probe._interval:.0f})"
            )
        else:
            during_window = probe.slice_window(0.0, float("inf"))

    # ---- build result row ---- #
    gd = _parse_guest_row(kv)
    row = BenchRow(
        op=str(gd["op"]),
        size=int(gd["size"]),
        churn=int(gd["churn"]),
        batch=str(gd["batch"]),
        wall_ms=int(gd["wall_ms"]),
        icmp_baseline=baseline_window,
        icmp_during=during_window,
        ctrl_p50_ms=int(gd["ctrl_p50_ms"]),
        ctrl_p99_ms=int(gd["ctrl_p99_ms"]),
        ctrl_max_ms=int(gd["ctrl_max_ms"]),
        ctrl_n=int(gd["ctrl_n"]),
        timed_out=bool(gd.get("timed_out", False)),
    )

    error_str = "TIMEOUT" if gd.get("timed_out") else str(gd.get("error", ""))
    _print_row(row, baseline_window, error_str)
    return row


def _print_row(row: BenchRow, baseline: ProbeWindow, error: str) -> None:
    """Print a diagnostic row so failures show expected vs actual."""
    spike_thresh = baseline.p99() * _SPIKE_FACTOR if baseline.samples else 0.0
    spikes = row.icmp_during.spike_count(spike_thresh) if spike_thresh > 0 else -1
    print(
        f"\n[bench] op={row.op} size={row.size:,} churn={row.churn:,} batch={row.batch}"
        f"\n  wall_ms={row.wall_ms:,}"
        f"\n  ICMP baseline  p50={baseline.p50():.1f}ms p99={baseline.p99():.1f}ms"
        f" max={baseline.pmax():.1f}ms n={baseline.sent()} loss={baseline.loss_pct():.1f}%"
        f"\n  ICMP during-op p50={row.icmp_during.p50():.1f}ms"
        f" p99={row.icmp_during.p99():.1f}ms"
        f" max={row.icmp_during.pmax():.1f}ms n={row.icmp_during.sent()}"
        f" loss={row.icmp_during.loss_pct():.1f}%"
        f" spikes(>{spike_thresh:.0f}ms)={spikes}"
        f"\n  ctrl probe: p50={row.ctrl_p50_ms}ms p99={row.ctrl_p99_ms}ms"
        f" max={row.ctrl_max_ms}ms n={row.ctrl_n}" + (f"\n  ERROR: {error}" if error else "")
    )


# --------------------------------------------------------------------------- #
# TCP-RST probe (reject-loop data-plane bench)
# --------------------------------------------------------------------------- #

# Python probe script uploaded to civm and run there.
# Fires TCP connect to a rotating set of IPs; measures time-to-RST (ECONNREFUSED).
# Emits one JSON line per connection: {"t": <recv_epoch>, "rtt_ms": <float>, "ip": "<ip>"}
# Runs for a specified duration then exits cleanly.
_TCP_PROBE_SCRIPT = r"""
#!/usr/bin/env python3
# TCP RST probe for ADR-40 reject-loop bench.
# Fires asyncio TCP connects to IPs in in_table_ips and out_table_ips,
# rotating through both sets.  Time-to-ECONNREFUSED = RST RTT.
# Prints one JSON line per connection:
#   {"start_t": epoch, "t": recv_epoch, "rtt_ms": float, "ip": str}
# start_t = wall-clock time when the connect was submitted (used for op-window
# slicing by START time rather than completion time, so stalled connections
# that started during the op but complete after it are still captured).
from __future__ import annotations
import asyncio
import json
import sys
import time

PORT = 9  # discard port — destination port for probes (RST regardless of state)

# Probe timeout: 5.0s gives headroom for real stalls (replace lock ≤~700ms at
# 1M; dropped SYN can retransmit at ~1s).  Only genuine ≥5s failures count as
# timeouts (should be ~none with reject rules returning RST).
_TIMEOUT = 5.0

async def probe_once(ip: str) -> tuple[float, float, float]:
    # Return (start_epoch, recv_epoch, rtt_ms); rtt_ms=-1 on asyncio.TimeoutError.
    start_epoch = time.time()
    t0 = time.monotonic()
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, PORT), timeout=_TIMEOUT
        )
        writer.close()
        await writer.wait_closed()
        rtt_ms = (time.monotonic() - t0) * 1000.0
    # Timeout MUST be caught before OSError: on Python 3.11+ asyncio.TimeoutError
    # IS the builtin TimeoutError, which subclasses OSError — with OSError first,
    # a genuine ≥5s stall lands in the RTT clause as a ~5000ms "valid" sample and
    # the -1 loss record is dead code (the #738 F5 masked-loss bug).
    except TimeoutError:
        rtt_ms = -1.0  # genuine ≥5s timeout — no RST received
    except (ConnectionRefusedError, OSError):
        rtt_ms = (time.monotonic() - t0) * 1000.0  # RST → ECONNREFUSED; time is RTT
    return start_epoch, time.time(), rtt_ms

async def run(in_ips: list[str], out_ips: list[str], duration: float) -> None:
    all_ips = in_ips + out_ips  # rotate through both sets
    idx = 0
    deadline = time.monotonic() + duration
    # High concurrency pool so even a short op window (e.g. replace@50k = ~52ms)
    # captures a healthy sample count.  With timeout=5.0s and a lock-hold stall,
    # 400 slots keep the pipeline full without starving submission.
    # ponytail: 400 chosen so 500 conn/s × 5s ≤ 2500 but we cap at 400; if
    # stall < 400ms * (400/500) the pipeline cycles through.
    sem = asyncio.Semaphore(400)

    async def one(ip: str) -> None:
        async with sem:
            start_epoch, recv_epoch, rtt_ms = await probe_once(ip)
            # Print to stdout — one JSON per line, INCLUDING timeouts (rtt_ms=-1):
            # a genuine >=5s timeout is a real loss and must be counted, not
            # silently dropped.  start_t is used for op-aligned windowing by
            # start time; a negative rtt_ms marks "no RST received".
            print(json.dumps({
                "start_t": round(start_epoch, 4),
                "t": round(recv_epoch, 4),
                "rtt_ms": round(rtt_ms, 3),
                "ip": ip,
            }), flush=True)

    tasks: list[asyncio.Task[None]] = []
    while time.monotonic() < deadline:
        ip = all_ips[idx % len(all_ips)]
        idx += 1
        tasks.append(asyncio.create_task(one(ip)))
        # Throttle submission: aim for ~500 conn/s (2ms between submissions).
        await asyncio.sleep(0.002)
        # Reap completed tasks periodically.
        if len(tasks) > 800:
            done = [t for t in tasks if t.done()]
            for t in done:
                tasks.remove(t)
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)

def main() -> None:
    in_ips = sys.argv[1].split(",")
    out_ips = sys.argv[2].split(",")
    duration = float(sys.argv[3])
    asyncio.run(run(in_ips, out_ips, duration))

if __name__ == "__main__":
    main()
"""

# IPs used in the reject-loop probe.
# in-table: samples from the stable 11.0.0.0/8 baseline block (spread across /8).
# out-table: samples from 13.0.0.0/8 (the add/churn block in do_delta).
_PROBE_IN_TABLE_IPS = [
    "11.0.0.1",
    "11.0.0.128",
    "11.1.0.1",
    "11.2.0.1",
    "11.5.0.1",
    "11.10.0.1",
    "11.20.0.1",
    "11.30.0.1",
    "11.50.0.1",
    "11.100.0.1",
]
_PROBE_OUT_TABLE_IPS = [
    "13.0.0.1",
    "13.0.0.50",
    "13.1.0.1",
    "13.2.0.1",
    "13.5.0.1",
    "13.10.0.1",
    "13.20.0.1",
    "13.30.0.1",
    "13.50.0.1",
    "13.100.0.1",
]

_TCP_PROBE_UPLOADED = False


def _upload_tcp_probe(client_vm: SmokeVM) -> None:
    global _TCP_PROBE_UPLOADED  # noqa: PLW0603  # ponytail: module-level flag; reset per session
    if _TCP_PROBE_UPLOADED:
        return
    proc = subprocess.run(
        client_vm.ssh_argv("tee /tmp/tcp_rst_probe.py > /dev/null && chmod +x /tmp/tcp_rst_probe.py"),
        input=_TCP_PROBE_SCRIPT,
        capture_output=True,
        text=True,
        timeout=30.0,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"Failed to upload tcp probe: {proc.stderr!r}")
    _TCP_PROBE_UPLOADED = True


@dataclass
class TcpRstSample:
    """One TCP RST RTT measurement from the reject-loop probe."""

    recv_epoch: float
    rtt_ms: float
    ip: str
    start_epoch: float = 0.0  # wall-clock time when connect was submitted


@dataclass
class TcpRstWindow:
    """Samples from a single op-aligned window of the TCP RST probe.

    ``lost`` is the count of genuine >=5s timeouts (rtt_ms=-1 probe records)
    pooled across the WHOLE probe run that produced this window, not
    attributed to this window's [t0, t1] slice — the maintainer-chosen
    pooled-per-run semantics (#738 F5). NOTE this deliberately DIVERGES from
    ICMP's ``_LiveProbe.slice_window``, which zeroes ``lost`` on op-aligned
    windows (its pooled op-aligned loss is always 0); do not "re-align" TCP
    to that — it would resurrect the fabricated-0.0 loss column. Because the
    run total rides on each sliced window, ``loss_pct()`` for a SHORT op
    window divides run-scoped losses by window-scoped sends and is an upper
    bound, not the window's own loss rate.
    """

    samples: list[TcpRstSample] = field(default_factory=list)
    total_attempts: int = 0  # incremented on collection
    lost: int = 0  # genuine >=5s timeouts, pooled per probe run (see docstring)

    def sent(self) -> int:
        return len(self.samples) + self.lost


@dataclass
class TcpProbeParse:
    """Result of parsing tcp_rst_probe.py output: RTT samples plus timeouts.

    A record with rtt_ms < 0 marks a genuine >=5s timeout (no RST received):
    counted in ``lost``, never added to ``samples``.
    """

    samples: list[TcpRstSample] = field(default_factory=list)
    lost: int = 0


def _parse_tcp_probe_output(text: str) -> TcpProbeParse:
    """Parse JSON lines from the tcp_rst_probe.py output.

    Returns the kept RTT samples plus the count of genuine >=5s timeouts
    (rtt_ms=-1 records) — those never enter the RTT sample list, since they
    have no RTT to report, but they are real losses and must be counted.
    """
    import json as _json

    samples: list[TcpRstSample] = []
    lost = 0
    for line in text.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            obj = _json.loads(line)
            if "rtt_ms" not in obj:
                continue
            rtt_ms = float(obj["rtt_ms"])
            if rtt_ms < 0:
                lost += 1
                continue
            samples.append(
                TcpRstSample(
                    recv_epoch=float(obj.get("t", 0)),
                    rtt_ms=rtt_ms,
                    ip=str(obj.get("ip", "")),
                    start_epoch=float(obj.get("start_t", 0)),
                )
            )
        except Exception:
            pass
    return TcpProbeParse(samples=samples, lost=lost)


class _LiveTcpProbe:
    """Continuous TCP-RST probe on civm in a background thread.

    Runs tcp_rst_probe.py in batches; caller calls ``start()``,
    then ``slice_window(t0, t1)`` to get op-aligned samples, then ``stop()``.
    """

    def __init__(
        self,
        client_vm: SmokeVM,
        in_ips: list[str],
        out_ips: list[str],
        batch_duration_s: float = 5.0,
    ) -> None:
        self._client = client_vm
        self._in_ips = in_ips
        self._out_ips = out_ips
        self._batch_dur = batch_duration_s
        self._samples: list[TcpRstSample] = []
        self._lost: int = 0  # genuine >=5s timeouts, pooled across the whole probe run
        self._lock = threading.Lock()
        self._stop_evt = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def _run(self) -> None:
        in_arg = ",".join(self._in_ips)
        out_arg = ",".join(self._out_ips)
        while not self._stop_evt.is_set():
            cmd = f"python3 /tmp/tcp_rst_probe.py {in_arg} {out_arg} {self._batch_dur:.1f} 2>/dev/null"
            result = self._client.ssh(cmd, timeout=self._batch_dur + 15.0)
            parsed = _parse_tcp_probe_output(result.stdout)
            with self._lock:
                self._samples.extend(parsed.samples)
                self._lost += parsed.lost

    def slice_window(self, t0: float, t1: float) -> TcpRstWindow:
        """Return samples whose connection was STARTED during [t0, t1] (op-aligned).

        Filtering by start_epoch rather than recv_epoch (completion time) is
        critical for short op windows (e.g. replace@50k = ~52ms): connections
        that start during the op but stall for 100-700ms complete after t1 and
        would be missed if filtered by completion time.  start_epoch captures
        exactly "connections that were in-flight when the op ran".
        Falls back to recv_epoch when start_epoch is 0 (old probe format).

        ``lost`` on the returned window is the probe's TOTAL genuine-timeout
        count across its whole run, not filtered to [t0, t1] — pooled-per-run
        by design (see ``TcpRstWindow`` docstring; deliberately unlike ICMP's
        ``slice_window``, which zeroes lost). INVARIANT: call at most once per
        probe run — the returned window carries the run's whole lost tally, so
        pooling summers (``_compute_pooled_tcp*``) that sum ``w.lost`` over
        windows rely on one window per run to avoid double-counting.
        """
        with self._lock:
            w = TcpRstWindow()
            w.samples = [s for s in self._samples if t0 <= (s.start_epoch if s.start_epoch > 0 else s.recv_epoch) <= t1]
            w.total_attempts = len(w.samples)
            w.lost = self._lost
            return w

    def all_samples(self) -> list[TcpRstSample]:
        with self._lock:
            return list(self._samples)

    def total_lost(self) -> int:
        """Total genuine >=5s timeouts observed across this probe's whole run."""
        with self._lock:
            return self._lost

    def stop(self) -> None:
        self._stop_evt.set()
        self._thread.join(timeout=30.0)


def _compute_pooled_tcp(
    windows: list[TcpRstWindow],
    baseline_windows: list[TcpRstWindow],
) -> PooledStats:
    """Pool TCP RST RTT samples from all repeat windows.

    ``total_loss``/``total_sent`` are pooled per-run (summed from each
    window's own ``.lost``, per-run tally — see ``TcpRstWindow`` docstring),
    not attributed to a narrower sub-window.
    """
    all_samples: list[TcpRstSample] = []
    for w in windows:
        all_samples.extend(w.samples)

    total_loss = sum(w.lost for w in windows)
    total_sent = sum(w.sent() for w in windows)

    baseline_rtts: list[float] = []
    for w in baseline_windows:
        baseline_rtts.extend(s.rtt_ms for s in w.samples)
    baseline_p99 = 0.0
    if baseline_rtts:
        baseline_rtts_s = sorted(baseline_rtts)
        idx = min(int(len(baseline_rtts_s) * 0.99), len(baseline_rtts_s) - 1)
        baseline_p99 = baseline_rtts_s[idx]
    spike_thresh = baseline_p99 * _SPIKE_FACTOR

    n = len(all_samples)
    if n == 0:
        return PooledStats(total_loss=total_loss, total_sent=total_sent)

    rtts = sorted(s.rtt_ms for s in all_samples)
    spikes = sum(1 for r in rtts if r > spike_thresh) if spike_thresh > 0 else 0

    def pct(p: float) -> float:
        idx = min(int(math.floor(n * p)), n - 1)
        return rtts[idx]

    return PooledStats(
        n=n,
        mean_ms=statistics.mean(rtts),
        stddev_ms=statistics.pstdev(rtts),
        min_ms=rtts[0],
        p50_ms=pct(0.50),
        p95_ms=pct(0.95),
        p99_ms=pct(0.99),
        p999_ms=pct(0.999),
        max_ms=rtts[-1],
        total_loss=total_loss,
        total_sent=total_sent,
        spikes=spikes,
        spike_threshold_ms=spike_thresh,
    )


def _measure_with_rst_probe(
    smoke_vm: SmokeVM,
    client_vm: SmokeVM,
    bench_args: tuple[str, ...],
    op_timeout_s: float = 600.0,
    batch_dur_s: float = 5.0,
) -> tuple[BenchRow, TcpRstWindow, TcpRstWindow]:
    """Run a bench op while capturing TCP-RST baseline and during-op windows.

    Returns (BenchRow, baseline_window, during_window).
    The baseline is collected before the op (same batch_dur_s duration).
    The during window is op-aligned via civm's clock (same as CR#12 fix).
    """
    # ---- baseline: collect a batch of RST samples before the op ---- #
    in_arg = ",".join(_PROBE_IN_TABLE_IPS)
    out_arg = ",".join(_PROBE_OUT_TABLE_IPS)
    baseline_cmd = f"python3 /tmp/tcp_rst_probe.py {in_arg} {out_arg} {batch_dur_s:.1f} 2>/dev/null"
    baseline_result = client_vm.ssh(baseline_cmd, timeout=batch_dur_s + 15.0)
    baseline_parsed = _parse_tcp_probe_output(baseline_result.stdout)
    baseline_samples = baseline_parsed.samples
    baseline_w = TcpRstWindow(samples=baseline_samples, total_attempts=len(baseline_samples), lost=baseline_parsed.lost)
    bl_p50 = 0.0
    if baseline_samples:
        sorted_bl = sorted(s.rtt_ms for s in baseline_samples)
        bl_p50 = sorted_bl[len(sorted_bl) // 2]
    print(f"\n  [rst-baseline] n={len(baseline_samples)} p50={bl_p50:.2f}ms")

    # ---- launch background probe ---- #
    probe = _LiveTcpProbe(client_vm, _PROBE_IN_TABLE_IPS, _PROBE_OUT_TABLE_IPS, batch_dur_s)
    probe.start()

    # ---- bracket the op with civm's clock ---- #
    res = client_vm.ssh("date +%s.%N", timeout=5.0)
    try:
        t0_civm = float(res.stdout.strip())
    except ValueError:
        t0_civm = 0.0

    # ---- run the pfctl op on the guest ---- #
    kv = _bench(smoke_vm, *bench_args, timeout=op_timeout_s)

    # ---- record op-end on civm clock ---- #
    res = client_vm.ssh("date +%s.%N", timeout=5.0)
    try:
        t1_civm = float(res.stdout.strip())
    except ValueError:
        t1_civm = 0.0

    # ---- stop probe; build op-aligned during-window ---- #
    probe.stop()
    if t0_civm > 0.0 and t1_civm > t0_civm:
        during_w = probe.slice_window(t0_civm, t1_civm)
        print(
            f"  [rst-probe-align] t0={t0_civm:.3f} t1={t1_civm:.3f}"
            f" op_wall={(t1_civm - t0_civm) * 1000:.0f}ms"
            f" during_samples={len(during_w.samples)}"
        )
    else:
        during_w = TcpRstWindow(samples=probe.all_samples(), lost=probe.total_lost())

    # ---- build result row ---- #
    gd = _parse_guest_row(kv)
    row = BenchRow(
        op=str(gd["op"]),
        size=int(gd["size"]),
        churn=int(gd["churn"]),
        batch=str(gd["batch"]),
        wall_ms=int(gd["wall_ms"]),
        ctrl_p50_ms=int(gd["ctrl_p50_ms"]),
        ctrl_p99_ms=int(gd["ctrl_p99_ms"]),
        ctrl_max_ms=int(gd["ctrl_max_ms"]),
        ctrl_n=int(gd["ctrl_n"]),
        timed_out=bool(gd.get("timed_out", False)),
    )
    print(
        f"\n[rst-bench] op={row.op} size={row.size:,} churn={row.churn:,} batch={row.batch}"
        f"\n  wall_ms={row.wall_ms:,}"
        f"\n  RST during-op n={len(during_w.samples)}"
    )
    return row, baseline_w, during_w


# --------------------------------------------------------------------------- #
# Original broad-matrix benchmark (Phase 2, single-rep per cell)
# --------------------------------------------------------------------------- #


@pytest.mark.pfctl_bench
def test_pfctl_bench(
    smoke_vm: SmokeVM,
    lan_interface: SmokeVM,
    client_vm: SmokeVM,
    request: pytest.FixtureRequest,
) -> None:
    """ADR-40 Phase 2: broad-matrix pfctl replace vs chunked delta + recompute.

    Scenario:
      Given a pfSense VM with a synthetic pf table
      And a civm client probing via ICMP through pfSense
      When a pfctl table op (replace / chunked delta / recompute) runs
      Then we capture wall-time + ICMP stall profile + control-plane lock latency

    Single-rep per cell; kept for historical comparison and quick orientation.
    Always passes — measurement harness; results recorded in RESULTS/02_Results.txt.
    """
    print("\n=== ADR-40 Phase 2: pfctl table benchmark (original broad matrix) ===")

    kv = _bench(smoke_vm, "system_info")
    print(f"  Guest: {kv.get('hostname')} RAM={kv.get('ram_mib')}MiB CPUs={kv.get('ncpu')}")

    kv = _bench(smoke_vm, "raise_limits", "10000000")
    print(f"  pf table limit raised to: {kv.get('pf_table_limit')}")
    # Guarantees the 1M-entry table + raised sysctl/pf limits are torn down even if a
    # sweep iteration below throws — a bare end-of-function cleanup call never runs on
    # a mid-sweep failure (issue #582). Runs during test teardown regardless of outcome.
    request.addfinalizer(lambda: _bench(smoke_vm, "cleanup", timeout=30.0))

    for sz in _SIZES:
        kv = _bench(smoke_vm, "gen", str(sz), timeout=120.0)
        print(f"  gen {sz:,}: {kv.get('generated', kv.get('cached', '?'))}")

    rows: list[BenchRow] = []

    print("\n--- (a) -T replace ---")
    for sz in _SIZES:
        row = _measure_with_probe(
            smoke_vm,
            client_vm,
            bench_args=("replace", str(sz)),
            baseline_duration_s=3.0,
            op_timeout_s=600.0,
        )
        rows.append(row)

    print("\n--- (b) -T delta (chunked) ---")
    delta_plan = [
        (10_000, 1, [0, 256]),
        (10_000, 1_000, [0, 256]),
        (100_000, 1, [0, 256]),
        (100_000, 1_000, _BATCH_SIZES),
        (100_000, 100_000, _BATCH_SIZES),
        (1_000_000, 1, [0, 256]),
        (1_000_000, 1_000, _BATCH_SIZES),
        (1_000_000, 100_000, _BATCH_SIZES),
    ]
    for sz, churn, batch_sizes in delta_plan:
        for batch in batch_sizes:
            op_timeout = 600.0
            if batch == 1 and churn >= 1_000:
                op_timeout = 1200.0
            row = _measure_with_probe(
                smoke_vm,
                client_vm,
                bench_args=("delta", str(sz), str(churn), str(batch)),
                baseline_duration_s=2.0,
                op_timeout_s=op_timeout,
            )
            rows.append(row)

    print("\n--- (c) recompute (sort -u) ---")
    for sz in _SIZES:
        kv = _bench(smoke_vm, "recompute", str(sz), timeout=120.0)
        gd = _parse_guest_row(kv)
        row = BenchRow(
            op="recompute",
            size=int(gd["size"]),
            churn=0,
            batch="-",
            wall_ms=int(gd["wall_ms"]),
        )
        rows.append(row)
        print(f"\n[bench] op=recompute size={row.size:,} wall_ms={row.wall_ms:,}")

    _print_summary(rows)

    assert rows, "expected at least one benchmark row"


def _print_summary(rows: list[BenchRow]) -> None:
    print("\n\n=== BENCHMARK SUMMARY ===")
    print(
        f"{'op':<10} {'size':>9} {'churn':>7} {'batch':>6} "
        f"{'wall_ms':>9} "
        f"{'ICMP_p50':>9} {'ICMP_p99':>9} {'ICMP_max':>9} "
        f"{'loss%':>6} {'spikes':>7} {'ctrl_p99':>9}"
    )
    print("-" * 105)
    for row in rows:
        baseline_p99 = row.icmp_baseline.p99()
        spike_thresh = baseline_p99 * _SPIKE_FACTOR
        spikes = row.icmp_during.spike_count(spike_thresh) if spike_thresh > 0 else -1
        wall_str = "TIMEOUT" if row.timed_out else f"{row.wall_ms:,}"
        print(
            f"{row.op:<10} {row.size:>9,} {row.churn:>7,} {row.batch:>6} "
            f"{wall_str:>9} "
            f"{row.icmp_during.p50():>9.1f} {row.icmp_during.p99():>9.1f} "
            f"{row.icmp_during.pmax():>9.1f} "
            f"{row.icmp_during.loss_pct():>6.1f} {spikes:>7} "
            f"{row.ctrl_p99_ms:>9}"
        )
    print("")


# --------------------------------------------------------------------------- #
# Production-calibrated knee sweep (follow-up run)
# --------------------------------------------------------------------------- #


@pytest.mark.pfctl_bench
def test_pfctl_knee_sweep(
    smoke_vm: SmokeVM,
    lan_interface: SmokeVM,
    client_vm: SmokeVM,
    request: pytest.FixtureRequest,
) -> None:
    """ADR-40 production-calibrated batch-size knee sweep with pooled distributions.

    Scenario:
      Given pfSense with synthetic pf tables at production sizes (100k, 462k, 1M)
      And a civm client probing at 500 pps ICMP to pfSense LAN (192.168.1.1)
      When replace baselines, batch-knee cells, and small-churn reference cells
        are each run for 20 repeats with op-aligned probe windows (CR#12)
      Then per-cell pooled RTT distributions are reported (n, mean, stddev,
        min, p50, p95, p99, p99.9, max, loss%, spikes) with confidence flags
      And the batch-knee curve (stall vs batch at 462k/46k and 1M/100k) reveals
        the recommended default batch for the production 100k–462k range

    Always passes — measurement harness; results + verdict in RESULTS/02_Results.txt.
    Confidence: p99 [unreliable] when n<100; p99.9 [low-confidence] when n<1000.
    Percentile method: nearest-rank (floor(n*p), clamped to [0, n-1]).
    """
    pps = int(1.0 / _KNEE_INTERVAL)
    print("\n=== ADR-40 production-calibrated knee sweep ===")
    print(f"  Sizes: {[f'{s:,}' for s in _KNEE_SIZES]}")
    print(f"  Batches: {_KNEE_BATCHES}")
    print(f"  Knee cells: {[f'{s:,}/{c:,}' for s, c in _KNEE_CELLS]}")
    print(f"  Small-churn ref: {[f'{s:,}/{c:,}({lbl})' for s, lbl, c in _SMALL_CHURN_CELLS]}")
    print(f"  {_REPS} reps per cell | {pps} pps ICMP | op-aligned window (CR#12)")

    kv = _bench(smoke_vm, "system_info")
    print(f"  Guest: {kv.get('hostname')} RAM={kv.get('ram_mib')}MiB CPUs={kv.get('ncpu')}")

    kv = _bench(smoke_vm, "raise_limits", "10000000")
    print(f"  pf table limit: {kv.get('pf_table_limit')}")
    # Guarantees the 1M-entry table + raised sysctl/pf limits are torn down even if a
    # sweep cell below throws — a bare end-of-function cleanup call never runs on a
    # mid-sweep failure (issue #582). Runs during test teardown regardless of outcome.
    request.addfinalizer(lambda: _bench(smoke_vm, "cleanup", timeout=30.0))

    # Generate all needed tables (gen is idempotent/cached).
    for sz in _KNEE_SIZES:
        kv = _bench(smoke_vm, "gen", str(sz), timeout=300.0)
        print(f"  gen {sz:,}: {kv.get('generated', kv.get('cached', '?'))}")

    # ------------------------------------------------------------------ #
    # A: Replace baselines
    # ------------------------------------------------------------------ #
    print(f"\n--- A: replace baselines ({_REPS} reps each, {pps} pps) ---")
    replace_rows: dict[int, list[BenchRow]] = {sz: [] for sz in _KNEE_SIZES}
    replace_stats: dict[int, PooledStats] = {}

    for sz in _KNEE_SIZES:
        for rep in range(_REPS):
            print(f"  replace {sz:,} rep={rep + 1}/{_REPS}", flush=True)
            row = _measure_with_probe(
                smoke_vm,
                client_vm,
                bench_args=("replace", str(sz)),
                baseline_duration_s=2.0,
                op_timeout_s=300.0,
                interval_s=_KNEE_INTERVAL,
            )
            replace_rows[sz].append(row)
        ps = _compute_pooled(
            [r.icmp_during for r in replace_rows[sz]],
            [r.icmp_baseline for r in replace_rows[sz]],
        )
        replace_stats[sz] = ps
        med_wall = statistics.median(r.wall_ms for r in replace_rows[sz])
        _print_pooled(f"replace size={sz:,}", _REPS, med_wall, ps)

    # ------------------------------------------------------------------ #
    # B: Batch-knee sweep
    # ------------------------------------------------------------------ #
    print(f"\n--- B: batch-knee sweep ({_REPS} reps per cell, {pps} pps) ---")
    # key = (size, churn, batch)
    knee_rows: dict[tuple[int, int, int], list[BenchRow]] = {}
    knee_stats: dict[tuple[int, int, int], PooledStats] = {}

    for sz, churn in _KNEE_CELLS:
        print(f"\n  == knee size={sz:,} churn={churn:,} ==")
        for batch in _KNEE_BATCHES:
            key = (sz, churn, batch)
            knee_rows[key] = []
            for rep in range(_REPS):
                print(f"  delta {sz:,}/{churn:,}/batch={batch} rep={rep + 1}/{_REPS}", flush=True)
                row = _measure_with_probe(
                    smoke_vm,
                    client_vm,
                    bench_args=("delta", str(sz), str(churn), str(batch)),
                    baseline_duration_s=2.0,
                    op_timeout_s=600.0,
                    interval_s=_KNEE_INTERVAL,
                )
                knee_rows[key].append(row)
            ps = _compute_pooled(
                [r.icmp_during for r in knee_rows[key]],
                [r.icmp_baseline for r in knee_rows[key]],
            )
            knee_stats[key] = ps
            med_wall = statistics.median(r.wall_ms for r in knee_rows[key])
            _print_pooled(f"delta {sz:,}/{churn:,}/batch={batch}", _REPS, med_wall, ps)

    # ------------------------------------------------------------------ #
    # C: Small-churn reference (everyday feed-update case)
    # ------------------------------------------------------------------ #
    print(f"\n--- C: small-churn reference ({_REPS} reps, {pps} pps) ---")
    # Key batches for small-churn: recommended (1024) and contrast (256).
    _SC_BATCHES = [256, 1024]
    # key = (size, churn_label, churn, batch)
    sc_rows: dict[tuple[int, str, int, int], list[BenchRow]] = {}
    sc_stats: dict[tuple[int, str, int, int], PooledStats] = {}

    for sz, lbl, churn in _SMALL_CHURN_CELLS:
        print(f"\n  == small-churn size={sz:,} churn={churn:,} ({lbl}) ==")
        for batch in _SC_BATCHES:
            key = (sz, lbl, churn, batch)
            sc_rows[key] = []
            for rep in range(_REPS):
                print(f"  delta {sz:,}/{churn:,}/batch={batch} rep={rep + 1}/{_REPS}", flush=True)
                row = _measure_with_probe(
                    smoke_vm,
                    client_vm,
                    bench_args=("delta", str(sz), str(churn), str(batch)),
                    baseline_duration_s=2.0,
                    op_timeout_s=300.0,
                    interval_s=_KNEE_INTERVAL,
                )
                sc_rows[key].append(row)
            ps = _compute_pooled(
                [r.icmp_during for r in sc_rows[key]],
                [r.icmp_baseline for r in sc_rows[key]],
            )
            sc_stats[key] = ps
            med_wall = statistics.median(r.wall_ms for r in sc_rows[key])
            _print_pooled(f"delta {sz:,}/{churn:,}({lbl})/batch={batch}", _REPS, med_wall, ps)

    # ------------------------------------------------------------------ #
    # Summary table
    # ------------------------------------------------------------------ #
    print("\n\n=== KNEE SWEEP SUMMARY (pooled distribution, nearest-rank percentile) ===")
    print("Percentile confidence: p99 [!] when n<100; p99.9 [?] when n<1000.")
    _hdr = (
        f"{'op':<7} {'size':>9} {'churn':>7} {'batch':>6} "
        f"{'wall_ms':>9} {'n':>5} "
        f"{'mean':>7} {'std':>7} {'p50':>7} {'p95':>7} "
        f"{'p99':>13} {'p99.9':>17} {'max':>7} "
        f"{'loss%':>6} {'spk':>5}"
    )
    print(_hdr)
    print("-" * len(_hdr))

    def _row_str(op: str, sz: int, churn: int | str, batch: int | str, ps: PooledStats, med_wall: float) -> str:
        p99f = "!" if ps.p99_conf() != "ok" else " "
        p999f = "?" if ps.p999_conf() != "ok" else " "
        churn_s = f"{churn:,}" if isinstance(churn, int) else str(churn)
        batch_s = f"{batch}" if isinstance(batch, int) else str(batch)
        return (
            f"{op:<7} {sz:>9,} {churn_s:>7} {batch_s:>6} "
            f"{med_wall:>9.0f} {ps.n:>5} "
            f"{ps.mean_ms:>7.1f} {ps.stddev_ms:>7.1f} {ps.p50_ms:>7.1f} {ps.p95_ms:>7.1f} "
            f"{p99f}{ps.p99_ms:>12.1f} {p999f}{ps.p999_ms:>16.1f} {ps.max_ms:>7.1f} "
            f"{ps.loss_pct():>6.1f} {ps.spikes:>5}"
        )

    print("\n-- A: replace baselines --")
    for sz in _KNEE_SIZES:
        ps = replace_stats[sz]
        med_wall = statistics.median(r.wall_ms for r in replace_rows[sz])
        print(_row_str("replace", sz, "—", "—", ps, med_wall))

    print("\n-- B: batch-knee sweep --")
    for sz, churn in _KNEE_CELLS:
        print(f"  --- size={sz:,} churn={churn:,} ---")
        for batch in _KNEE_BATCHES:
            key = (sz, churn, batch)
            ps = knee_stats[key]
            med_wall = statistics.median(r.wall_ms for r in knee_rows[key])
            print(_row_str("delta", sz, churn, batch, ps, med_wall))

    print("\n-- C: small-churn reference --")
    for sz, lbl, churn in _SMALL_CHURN_CELLS:
        print(f"  --- size={sz:,} churn={churn:,} ({lbl}) ---")
        for batch in _SC_BATCHES:
            key = (sz, lbl, churn, batch)
            ps = sc_stats[key]
            med_wall = statistics.median(r.wall_ms for r in sc_rows[key])
            print(_row_str("delta", sz, churn, batch, ps, med_wall))

    print(
        f"\n! = p99 unreliable (n<100)"
        f"\n? = p99.9 low-confidence (n<1000)"
        f"\nSpike threshold = median baseline p99 × {_SPIKE_FACTOR} per cell."
        f"\n{_REPS} reps × {pps} pps; op-aligned window (CR#12)."
        f"\nBaseline addr block: 11.0.0.0/8; add block: 13.0.0.0/8 (disjoint)."
    )

    assert knee_stats, "expected at least one knee measurement"


# --------------------------------------------------------------------------- #
# Reject-loop data-plane bench (definitive ADR-40 measurement)
# --------------------------------------------------------------------------- #

# Rule types to compare (A vs B: interface rule vs floating rule).
_REJECT_RULE_TYPES = ["lan_if", "floating"]

# Subset of the knee matrix run under each rule type for A/B comparison.
# Representative cell: replace@462k and delta@462k/46k at batch=512.
_RULE_AB_CELLS: list[tuple[str, tuple[str, ...]]] = [
    # (label, bench_args)
    ("replace@462k", ("replace", "462000")),
    ("delta@462k/46k/512", ("delta", "462000", "46000", "512")),
    ("delta@462k/46k/1024", ("delta", "462000", "46000", "1024")),
]

# Full knee sweep under the primary condition (LAN floating reject + WAN floating reject).
_REJECT_KNEE_CELLS = _KNEE_CELLS  # reuse: [(462k,46k), (1M,100k)]
_REJECT_KNEE_BATCHES = _KNEE_BATCHES  # reuse: [256,384,512,768,1024,2048,4096]
_REJECT_KNEE_SIZES = [100_000, 462_000, 1_000_000]
_REJECT_REPS = 20  # reps per cell

# Small-churn refs under primary condition.
_REJECT_SMALL_CHURN = _SMALL_CHURN_CELLS  # reuse


@pytest.mark.pfctl_bench
def test_pfctl_reject_loop(
    smoke_vm: SmokeVM,
    lan_interface: SmokeVM,
    client_vm: SmokeVM,
    request: pytest.FixtureRequest,
) -> None:
    """ADR-40 definitive data-plane bench: reject-based closed measurement loop.

    Scenario:
      Given pfSense with pf REJECT rules (LAN block-return + WAN block-return-out)
      And a civm client firing TCP connects to in-table (11.x) and out-table (13.x) IPs
      When pfctl table ops run (replace, chunked delta at various batch sizes)
      Then every probe returns a fast TCP RST — no timeout artifacts
      And we capture per-connection RTT with op-aligned windows (pooled distribution)

    Measurement loop:
      - In-table path (11.x stable set): civm → pfSense LAN → LAN block-return rule
        → immediate TCP RST → civm (measures lock-hold stall during table mutation).
      - Not-in-table path (13.x churn set): civm → pfSense LAN → no match → routes
        to WAN → WAN block-return-out → TCP RST back to civm (measures transition).
      - Both paths return RST immediately: measurement is continuous across ops.

    Control path protection: port 22 PASS rule fires before any block; SSH to
    pfSense mgmt (192.168.43.15 via MGMT/net1 SLIRP) is on a separate interface not
    covered by the LAN rule, so it is doubly protected.

    Verification before measurement:
      (i)  in-table IPs confirm RST (fast RTT ≤ 50ms).
      (ii) not-in-table IPs confirm RST (fast RTT ≤ 50ms).
      (iii) SSH to pfSense still works.

    Matrix:
      A/B rule-type comparison (lan_if vs floating) at replace@462k + delta@462k/46k/512.
      Full knee sweep [256,384,512,768,1024,2048,4096] at (462k,46k) and (1M,100k)
        under the primary condition (floating LAN + WAN floating reject).
      Replace baselines at 100k/462k/1M.
      Small-churn refs ~1%/5% at 100k/462k.

    Always passes — measurement harness; results in RESULTS/02_Results.txt.
    """
    pps_label = "~500 conn/s TCP-RST"
    print("\n=== ADR-40 reject-loop data-plane bench ===")
    print(f"  Probe: {pps_label} from civm via asyncio TCP connect")
    print(f"  In-table IPs (11.x): {_PROBE_IN_TABLE_IPS[:3]}…")
    print(f"  Out-table IPs (13.x): {_PROBE_OUT_TABLE_IPS[:3]}…")
    print(f"  {_REJECT_REPS} reps per cell | op-aligned window (CR#12)")

    # Upload the TCP probe script to civm.
    _upload_tcp_probe(client_vm)

    # Ensure probe traffic (11.0.0.0/8 and 13.0.0.0/8) is routed through pfSense
    # LAN, not via the SLIRP default route (ens4).  civm has two default routes at
    # equal metric 100 (ECMP: ens4 via SLIRP + ens5 via pfSense LAN).  Without
    # explicit routes, Linux ECMP may send probe packets via ens4 where pfSense
    # never sees them and RST never comes back.
    print("  civm: adding explicit routes for 11.0.0.0/8 and 13.0.0.0/8 via pfSense LAN")
    route_result = client_vm.ssh(
        "ip route replace 11.0.0.0/8 via 192.168.1.1 dev ens5"
        " && ip route replace 13.0.0.0/8 via 192.168.1.1 dev ens5"
        " && echo routes_ok",
        timeout=10.0,
    )
    print(f"  civm routes: {route_result.stdout.strip()!r}")

    kv = _bench(smoke_vm, "system_info")
    print(f"  Guest: {kv.get('hostname')} RAM={kv.get('ram_mib')}MiB CPUs={kv.get('ncpu')}")

    kv = _bench(smoke_vm, "raise_limits", "10000000")
    print(f"  pf table limit: {kv.get('pf_table_limit')}")
    # Guarantees the 1M-entry table + raised sysctl/pf limits are torn down even if a
    # sweep cell below throws — a bare end-of-function cleanup call never runs on a
    # mid-sweep failure (issue #582). Runs during test teardown regardless of outcome.
    request.addfinalizer(lambda: _bench(smoke_vm, "cleanup", timeout=30.0))

    # Generate tables.
    for sz in sorted({s for s, _ in _REJECT_KNEE_CELLS} | set(_REJECT_KNEE_SIZES)):
        kv = _bench(smoke_vm, "gen", str(sz), timeout=300.0)
        print(f"  gen {sz:,}: {kv.get('generated', kv.get('cached', '?'))}")

    # Also need the adds files for delta ops (generated lazily by bench_pfctl_tables.sh
    # the first time delta is called, but gen_adds pre-populates them).
    # The bench script's do_delta() creates them on demand; nothing extra needed here.

    # ------------------------------------------------------------------ #
    # Verify reject loop before measuring
    # ------------------------------------------------------------------ #
    print("\n--- Verify: loading bench table and checking table membership ---")
    # Load the 462k table first so verify_reject can check table membership.
    kv = _bench(smoke_vm, "replace", "462000", timeout=120.0)
    print(f"  Loaded 462k table: wall_ms={kv.get('wall_ms')} loaded={kv.get('loaded')}")

    print("\n--- Verify: setting up floating reject rules ---")
    kv = _bench(smoke_vm, "setup_rules", "floating", timeout=30.0)
    print(f"  setup_rules: {kv}")
    if "error" in kv:
        pytest.skip(f"Cannot set up reject rules: {kv.get('error')} — STOP (reject loop not working)")

    kv = _bench(smoke_vm, "verify_reject", timeout=30.0)
    print(f"  verify: {kv}")

    # Verify the RST loop by running a short TCP probe and checking latency.
    print("\n--- Verify: TCP RST probe to in-table and out-table IPs ---")
    in_arg = ",".join(_PROBE_IN_TABLE_IPS[:3])
    out_arg = ",".join(_PROBE_OUT_TABLE_IPS[:3])
    # Keep stderr visible (no 2>/dev/null) for diagnostic purposes on failure.
    verify_cmd = f"python3 /tmp/tcp_rst_probe.py {in_arg} {out_arg} 2.0"
    verify_result = client_vm.ssh(verify_cmd, timeout=10.0)
    verify_samples = _parse_tcp_probe_output(verify_result.stdout).samples
    if not verify_samples:
        _bench(smoke_vm, "teardown_rules", timeout=30.0)
        pytest.skip(
            f"TCP RST probe returned no samples — reject loop not working. "
            f"stdout={verify_result.stdout!r} stderr={verify_result.stderr!r} "
            f"rc={verify_result.returncode}. STOP."
        )
    verify_rtts = sorted(s.rtt_ms for s in verify_samples)
    verify_p99 = verify_rtts[min(int(len(verify_rtts) * 0.99), len(verify_rtts) - 1)]
    print(
        f"  verify probe: n={len(verify_samples)} p50={verify_rtts[len(verify_rtts) // 2]:.2f}ms p99={verify_p99:.2f}ms"
    )
    if verify_p99 > 100.0:
        _bench(smoke_vm, "teardown_rules", timeout=30.0)
        pytest.skip(
            f"RST p99={verify_p99:.1f}ms > 100ms — reject loop too slow or not firing. "
            "Expected sub-ms to low-ms RST. STOP."
        )
    print(f"  VERIFY PASSED: RST p99={verify_p99:.2f}ms ✓")

    # Verify SSH to pfSense still works (port 22 PASS rule must be in place).
    try:
        ssh_check = smoke_vm.ssh("echo ssh_ok", timeout=10.0)
        print(f"  SSH control path: {ssh_check.stdout.strip()!r} ✓")
    except Exception as exc:
        _bench(smoke_vm, "teardown_rules", timeout=30.0)
        pytest.skip(f"SSH to pfSense lost after loading reject rules: {exc} — STOP.")

    # Tear down for now; we re-load per rule type.
    _bench(smoke_vm, "teardown_rules", timeout=30.0)
    print("  Verification complete — reject loop working.\n")

    # ------------------------------------------------------------------ #
    # A/B: rule-type comparison (lan_if vs floating)
    # ------------------------------------------------------------------ #
    print(f"--- A/B: rule-type comparison ({_RULE_AB_CELLS}) ---")
    ab_results: dict[str, dict[str, tuple[list[TcpRstWindow], list[TcpRstWindow], list[int]]]] = {}
    # key: rule_type → {cell_label: ([baseline_windows], [during_windows], [wall_ms])}

    for rule_type in _REJECT_RULE_TYPES:
        print(f"\n  == Rule type: {rule_type} ==")
        ab_results[rule_type] = {}

        # Re-load 462k table (do_replace loads it as baseline before the replace op).
        kv = _bench(smoke_vm, "replace", "462000", timeout=120.0)
        print(f"  baseline 462k loaded: wall_ms={kv.get('wall_ms')}")

        kv = _bench(smoke_vm, "setup_rules", rule_type, timeout=30.0)
        if "error" in kv:
            print(f"  SKIP rule_type={rule_type}: {kv.get('error')}")
            continue

        try:
            for lbl, bench_args in _RULE_AB_CELLS:
                bl_wins: list[TcpRstWindow] = []
                dur_wins: list[TcpRstWindow] = []
                walls: list[int] = []

                # For A/B comparison: 5 reps (enough to see the distribution pattern).
                ab_reps = 5
                for rep in range(ab_reps):
                    print(f"  {rule_type}/{lbl} rep={rep + 1}/{ab_reps}", flush=True)
                    row, bl_w, dur_w = _measure_with_rst_probe(smoke_vm, client_vm, bench_args, op_timeout_s=300.0)
                    bl_wins.append(bl_w)
                    dur_wins.append(dur_w)
                    walls.append(row.wall_ms)

                ps = _compute_pooled_tcp(dur_wins, bl_wins)
                med_wall = statistics.median(walls)
                _print_pooled(f"RST {rule_type}/{lbl}", ab_reps, med_wall, ps)
                ab_results[rule_type][lbl] = (bl_wins, dur_wins, walls)
        finally:
            _bench(smoke_vm, "teardown_rules", timeout=30.0)

    # ------------------------------------------------------------------ #
    # Full knee sweep under primary condition (floating)
    # ------------------------------------------------------------------ #
    primary_rule = "floating"
    print(f"\n--- Full knee sweep under primary condition ({primary_rule}) ---")

    kv = _bench(smoke_vm, "setup_rules", primary_rule, timeout=30.0)
    if "error" in kv:
        print(f"  Cannot set up primary rules: {kv.get('error')} — skipping knee sweep")
        knee_stats_rst: dict[tuple[int, int, int], PooledStats] = {}
        replace_stats_rst: dict[int, PooledStats] = {}
        sc_stats_rst: dict[tuple[int, str, int, int], PooledStats] = {}
    else:
        # --- Replace baselines --- #
        print(f"\n-- A: replace baselines ({_REJECT_REPS} reps, {primary_rule}) --")
        replace_rows_rst: dict[int, list[tuple[TcpRstWindow, TcpRstWindow, int]]] = {
            sz: [] for sz in _REJECT_KNEE_SIZES
        }
        replace_stats_rst = {}
        for sz in _REJECT_KNEE_SIZES:
            for rep in range(_REJECT_REPS):
                print(f"  replace {sz:,} rep={rep + 1}/{_REJECT_REPS}", flush=True)
                row, bl_w, dur_w = _measure_with_rst_probe(
                    smoke_vm, client_vm, ("replace", str(sz)), op_timeout_s=300.0
                )
                replace_rows_rst[sz].append((bl_w, dur_w, row.wall_ms))
            bl_wins = [r[0] for r in replace_rows_rst[sz]]
            dur_wins = [r[1] for r in replace_rows_rst[sz]]
            ps = _compute_pooled_tcp(dur_wins, bl_wins)
            replace_stats_rst[sz] = ps
            med_wall = statistics.median(r[2] for r in replace_rows_rst[sz])
            _print_pooled(f"RST replace {sz:,}", _REJECT_REPS, med_wall, ps)

        # --- Batch-knee sweep --- #
        print(f"\n-- B: batch-knee sweep ({_REJECT_REPS} reps, {primary_rule}) --")
        knee_rows_rst: dict[tuple[int, int, int], list[tuple[TcpRstWindow, TcpRstWindow, int]]] = {}
        knee_stats_rst = {}
        for sz, churn in _REJECT_KNEE_CELLS:
            print(f"\n  == knee size={sz:,} churn={churn:,} ==")
            for batch in _REJECT_KNEE_BATCHES:
                key = (sz, churn, batch)
                knee_rows_rst[key] = []
                for rep in range(_REJECT_REPS):
                    print(f"  delta {sz:,}/{churn:,}/batch={batch} rep={rep + 1}/{_REJECT_REPS}", flush=True)
                    row, bl_w, dur_w = _measure_with_rst_probe(
                        smoke_vm,
                        client_vm,
                        ("delta", str(sz), str(churn), str(batch)),
                        op_timeout_s=600.0,
                    )
                    knee_rows_rst[key].append((bl_w, dur_w, row.wall_ms))
                bl_wins = [r[0] for r in knee_rows_rst[key]]
                dur_wins = [r[1] for r in knee_rows_rst[key]]
                ps = _compute_pooled_tcp(dur_wins, bl_wins)
                knee_stats_rst[key] = ps
                med_wall = statistics.median(r[2] for r in knee_rows_rst[key])
                _print_pooled(f"RST delta {sz:,}/{churn:,}/batch={batch}", _REJECT_REPS, med_wall, ps)

        # --- Small-churn refs --- #
        print(f"\n-- C: small-churn reference ({_REJECT_REPS} reps, {primary_rule}) --")
        _SC_BATCHES_RST = [256, 512, 1024]
        sc_rows_rst: dict[tuple[int, str, int, int], list[tuple[TcpRstWindow, TcpRstWindow, int]]] = {}
        sc_stats_rst = {}
        for sz, lbl, churn in _REJECT_SMALL_CHURN:
            print(f"\n  == small-churn size={sz:,} churn={churn:,} ({lbl}) ==")
            for batch in _SC_BATCHES_RST:
                key2 = (sz, lbl, churn, batch)
                sc_rows_rst[key2] = []
                for rep in range(_REJECT_REPS):
                    print(f"  delta {sz:,}/{churn:,}/batch={batch} rep={rep + 1}/{_REJECT_REPS}", flush=True)
                    row, bl_w, dur_w = _measure_with_rst_probe(
                        smoke_vm,
                        client_vm,
                        ("delta", str(sz), str(churn), str(batch)),
                        op_timeout_s=300.0,
                    )
                    sc_rows_rst[key2].append((bl_w, dur_w, row.wall_ms))
                bl_wins = [r[0] for r in sc_rows_rst[key2]]
                dur_wins = [r[1] for r in sc_rows_rst[key2]]
                ps = _compute_pooled_tcp(dur_wins, bl_wins)
                sc_stats_rst[key2] = ps
                med_wall = statistics.median(r[2] for r in sc_rows_rst[key2])
                _print_pooled(f"RST delta {sz:,}/{churn:,}({lbl})/batch={batch}", _REJECT_REPS, med_wall, ps)

        _bench(smoke_vm, "teardown_rules", timeout=30.0)

    # ------------------------------------------------------------------ #
    # Summary table (TCP-RST pooled distribution)
    # ------------------------------------------------------------------ #
    print("\n\n=== REJECT-LOOP BENCH SUMMARY (TCP-RST pooled distribution) ===")
    print("Probe: asyncio TCP connect to 11.x (in-table) and 13.x (out-table) IPs.")
    print("BOTH return RST: in-table via LAN block-return, out-table via WAN block-return-out.")
    print("Spike threshold = median baseline p99 × 3.0.")

    _hdr2 = (
        f"{'rule':<10} {'op':<8} {'size':>9} {'churn':>7} {'batch':>6} "
        f"{'wall_ms':>9} {'n':>5} "
        f"{'p50':>7} {'p95':>7} {'p99':>13} {'p99.9':>17} {'max':>7} {'spk':>5}"
    )
    print(_hdr2)
    print("-" * len(_hdr2))

    def _rst_row(
        rule: str, op: str, sz: int, churn: int | str, batch: int | str, ps: PooledStats, med_wall: float
    ) -> str:
        p99f = "!" if ps.p99_conf() != "ok" else " "
        p999f = "?" if ps.p999_conf() != "ok" else " "
        churn_s = f"{churn:,}" if isinstance(churn, int) else str(churn)
        batch_s = str(batch)
        return (
            f"{rule:<10} {op:<8} {sz:>9,} {churn_s:>7} {batch_s:>6} "
            f"{med_wall:>9.0f} {ps.n:>5} "
            f"{ps.p50_ms:>7.2f} {ps.p95_ms:>7.2f} "
            f"{p99f}{ps.p99_ms:>12.2f} {p999f}{ps.p999_ms:>16.2f} "
            f"{ps.max_ms:>7.2f} {ps.spikes:>5}"
        )

    print("\n-- A/B: rule-type comparison --")
    for rule_type in _REJECT_RULE_TYPES:
        if rule_type not in ab_results:
            continue
        for lbl, bench_args in _RULE_AB_CELLS:
            if lbl not in ab_results[rule_type]:
                continue
            bl_wins, dur_wins, walls = ab_results[rule_type][lbl]
            ps = _compute_pooled_tcp(dur_wins, bl_wins)
            med_wall = statistics.median(walls)
            op = bench_args[0]
            sz = int(bench_args[1])
            churn = int(bench_args[2]) if len(bench_args) > 2 else 0
            batch = bench_args[3] if len(bench_args) > 3 else "-"
            print(_rst_row(rule_type, op, sz, churn, batch, ps, med_wall))

    if replace_stats_rst:
        print("\n-- A: replace baselines (floating) --")
        for sz in _REJECT_KNEE_SIZES:
            if sz not in replace_stats_rst:
                continue
            ps = replace_stats_rst[sz]
            med_wall = statistics.median(r[2] for r in replace_rows_rst[sz])
            print(_rst_row("floating", "replace", sz, "—", "—", ps, med_wall))

    if knee_stats_rst:
        print("\n-- B: batch-knee sweep (floating) --")
        for sz, churn in _REJECT_KNEE_CELLS:
            print(f"  --- size={sz:,} churn={churn:,} ---")
            for batch in _REJECT_KNEE_BATCHES:
                key = (sz, churn, batch)
                if key not in knee_stats_rst:
                    continue
                ps = knee_stats_rst[key]
                med_wall = statistics.median(r[2] for r in knee_rows_rst[key])
                print(_rst_row("floating", "delta", sz, churn, batch, ps, med_wall))

    if sc_stats_rst:
        print("\n-- C: small-churn reference (floating) --")
        for sz, lbl, churn in _REJECT_SMALL_CHURN:
            for batch in _SC_BATCHES_RST:
                key2 = (sz, lbl, churn, batch)
                if key2 not in sc_stats_rst:
                    continue
                ps = sc_stats_rst[key2]
                med_wall = statistics.median(r[2] for r in sc_rows_rst[key2])
                print(_rst_row("floating", "delta", sz, churn, batch, ps, med_wall))

    print(
        f"\n! = p99 unreliable (n<100)"
        f"\n? = p99.9 low-confidence (n<1000)"
        f"\nProbe: in-table 11.x ({len(_PROBE_IN_TABLE_IPS)} IPs) + out-table 13.x ({len(_PROBE_OUT_TABLE_IPS)} IPs)."
        f"\n{_REJECT_REPS} reps per cell | op-aligned windows (CR#12)."
    )

    assert verify_samples, "expected at least one TCP RST sample in verification"


# --------------------------------------------------------------------------- #
# Replace-only service-disruption baseline (ADR-40 follow-up)
# --------------------------------------------------------------------------- #

# Table sizes for the replace disruption curve.
# Finer sweep than the existing 3-point baseline: 8 sizes spanning 10k–1M.
# 462k = production max; most real tables ≤100k.
_REPLACE_DISRUPT_SIZES = [10_000, 50_000, 100_000, 200_000, 350_000, 462_000, 750_000, 1_000_000]

# Reps per size; 20 reps × ~500 conn/s gives large pooled n at op durations ≥20ms.
_REPLACE_DISRUPT_REPS = 20

# Disruption latency buckets for the service-disruption signal.
# These are the concrete "how many connections were stalled, and how badly" metrics.
_DISRUPT_BUCKETS_MS = [50, 100, 250, 500]

# Spike threshold factor applied to the quiescent baseline p95 (not p99 — p99
# was polluted by occasional SYN-retransmit yielding ~500ms, causing 3× p99 ≈ 1505ms
# which is never exceeded, making the spike count 0 everywhere and the metric useless).
# Baseline p95 ≈ 10–20ms in quiescent conditions; × 3.0 ≈ 30–60ms is a meaningful
# threshold that will be exceeded by connections landing during a lock-hold window.
_DISRUPT_SPIKE_FACTOR = 3.0


def _compute_disrupt_buckets(rtts: list[float]) -> dict[int, tuple[int, float]]:
    """Return {threshold_ms: (count, pct)} for each threshold in _DISRUPT_BUCKETS_MS."""
    n = len(rtts)
    result: dict[int, tuple[int, float]] = {}
    for thresh in _DISRUPT_BUCKETS_MS:
        cnt = sum(1 for r in rtts if r > thresh)
        pct = 100.0 * cnt / n if n > 0 else 0.0
        result[thresh] = (cnt, pct)
    return result


def _compute_pooled_tcp_full(
    windows: list[TcpRstWindow],
    baseline_windows: list[TcpRstWindow],
) -> tuple[PooledStats, dict[int, tuple[int, float]], float]:
    """Pool TCP RST RTT samples; return (PooledStats, bucket_counts, spike_threshold_ms).

    spike_threshold_ms is derived from the quiescent baseline p95 × _DISRUPT_SPIKE_FACTOR
    (NOT p99 × 3.0, which was degenerate in the prior run — see 02b_Replace_Disruption_Baseline.txt).

    ``total_loss``/``total_sent`` are pooled per-run from each window's own
    ``.lost`` (see ``TcpRstWindow`` docstring) — not attributed to a narrower
    sub-window; the disruption buckets stay RTT-only.
    """
    all_rtts: list[float] = []
    for w in windows:
        all_rtts.extend(s.rtt_ms for s in w.samples)

    total_loss = sum(w.lost for w in windows)
    total_sent = sum(w.sent() for w in windows)

    # Compute spike threshold from baseline p95.
    baseline_rtts: list[float] = []
    for w in baseline_windows:
        baseline_rtts.extend(s.rtt_ms for s in w.samples)
    baseline_p95 = 0.0
    if baseline_rtts:
        sbl = sorted(baseline_rtts)
        idx = min(int(math.floor(len(sbl) * 0.95)), len(sbl) - 1)
        baseline_p95 = sbl[idx]
    spike_thresh = baseline_p95 * _DISRUPT_SPIKE_FACTOR

    n = len(all_rtts)
    if n == 0:
        return (
            PooledStats(total_loss=total_loss, total_sent=total_sent),
            {t: (0, 0.0) for t in _DISRUPT_BUCKETS_MS},
            spike_thresh,
        )

    rtts_s = sorted(all_rtts)
    spikes = sum(1 for r in rtts_s if r > spike_thresh) if spike_thresh > 0 else 0

    def pct(p: float) -> float:
        idx = min(int(math.floor(n * p)), n - 1)
        return rtts_s[idx]

    ps = PooledStats(
        n=n,
        mean_ms=statistics.mean(rtts_s),
        stddev_ms=statistics.pstdev(rtts_s),
        min_ms=rtts_s[0],
        p50_ms=pct(0.50),
        p95_ms=pct(0.95),
        p99_ms=pct(0.99),
        p999_ms=pct(0.999),
        max_ms=rtts_s[-1],
        total_loss=total_loss,
        total_sent=total_sent,
        spikes=spikes,
        spike_threshold_ms=spike_thresh,
    )
    buckets = _compute_disrupt_buckets(rtts_s)
    return ps, buckets, spike_thresh


@pytest.mark.pfctl_bench
def test_pfctl_replace_disruption_baseline(
    smoke_vm: SmokeVM,
    lan_interface: SmokeVM,
    client_vm: SmokeVM,
    request: pytest.FixtureRequest,
) -> None:
    """ADR-40 follow-up: replace-only service-disruption baseline across table sizes.

    Scenario:
      Given pfSense with floating reject rules (same as test_pfctl_reject_loop)
      And a civm client firing TCP connects at ~500 conn/s to in-table (11.x) IPs
      When pfctl -T replace is run at 8 table sizes (10k–1M) for 20 reps each
      Then we capture the full RTT distribution + concrete disruption buckets
        (>50ms, >100ms, >250ms, >500ms count + %) per size
      And the disruption-vs-size curve reveals how service stall scales with table size

    This is the REPLACE-ONLY baseline that the ADR-40 delta apply aims to reduce.
    The delta comparison data lives in RESULTS/02_Results.txt.
    Results here: RESULTS/02b_Replace_Disruption_Baseline.txt.

    Key difference from prior spike metric: spike_threshold = baseline p95 × 3.0
    (NOT baseline p99 × 3.0 — p99 was ~500ms from occasional SYN-retransmit, making
    3×p99 ≈ 1505ms a threshold never exceeded and the spike count always 0/useless).
    Baseline p95 ≈ 10–20ms yields a ~30–60ms threshold that genuinely fires on
    connections stalled during a lock-hold window.

    Always passes — measurement harness; results in RESULTS/02b_Replace_Disruption_Baseline.txt.
    """
    print("\n=== ADR-40 replace-only service-disruption baseline ===")
    print(f"  Sizes: {[f'{s:,}' for s in _REPLACE_DISRUPT_SIZES]}")
    print(f"  {_REPLACE_DISRUPT_REPS} reps per size | ~500 conn/s TCP-RST | op-aligned (CR#12)")
    print(f"  Disruption buckets: >{_DISRUPT_BUCKETS_MS}ms")
    print(f"  Spike threshold: baseline p95 × {_DISRUPT_SPIKE_FACTOR} (not p99 — see docstring)")

    # Upload TCP probe to civm.
    _upload_tcp_probe(client_vm)

    # Route probe IPs through pfSense LAN on civm (same as test_pfctl_reject_loop).
    print("  civm: adding explicit routes for 11.0.0.0/8 and 13.0.0.0/8 via pfSense LAN")
    client_vm.ssh(
        "ip route replace 11.0.0.0/8 via 192.168.1.1 dev ens5"
        " && ip route replace 13.0.0.0/8 via 192.168.1.1 dev ens5"
        " && echo routes_ok",
        timeout=10.0,
    )

    kv = _bench(smoke_vm, "system_info")
    print(f"  Guest: {kv.get('hostname')} RAM={kv.get('ram_mib')}MiB CPUs={kv.get('ncpu')}")

    kv = _bench(smoke_vm, "raise_limits", "10000000")
    print(f"  pf table limit: {kv.get('pf_table_limit')}")
    # Guarantees the 1M-entry table + raised sysctl/pf limits are torn down even if a
    # sweep rep below throws — a bare end-of-function cleanup call never runs on a
    # mid-sweep failure (issue #582). Runs during test teardown regardless of outcome
    # (the explicit pre-skip cleanup calls below stay — this is the catch-all for
    # everything past them: the main measurement loop had no cleanup at all before).
    request.addfinalizer(lambda: _bench(smoke_vm, "cleanup", timeout=30.0))

    # Generate all needed tables (idempotent).
    for sz in _REPLACE_DISRUPT_SIZES:
        kv = _bench(smoke_vm, "gen", str(sz), timeout=300.0)
        print(f"  gen {sz:,}: {kv.get('generated', kv.get('cached', '?'))}")

    # Load the largest table first so setup_rules can verify table is loaded.
    kv = _bench(smoke_vm, "replace", "1000000", timeout=120.0)
    print(f"  Loaded 1M table: wall_ms={kv.get('wall_ms')} loaded={kv.get('loaded')}")

    # Set up floating reject rules (same ruleset as test_pfctl_reject_loop).
    print("\n--- Setting up floating reject rules ---")
    kv = _bench(smoke_vm, "setup_rules", "floating", timeout=30.0)
    print(f"  setup_rules: {kv}")
    if "error" in kv:
        pytest.skip(f"Cannot set up reject rules: {kv.get('error')} — STOP")

    # Verify the reject loop with a short probe.
    print("\n--- Verifying reject loop ---")
    in_arg = ",".join(_PROBE_IN_TABLE_IPS[:3])
    out_arg = ",".join(_PROBE_OUT_TABLE_IPS[:3])
    verify_result = client_vm.ssh(f"python3 /tmp/tcp_rst_probe.py {in_arg} {out_arg} 2.0", timeout=10.0)
    verify_samples_disrupt = _parse_tcp_probe_output(verify_result.stdout).samples
    if not verify_samples_disrupt:
        _bench(smoke_vm, "teardown_rules", timeout=30.0)
        _bench(smoke_vm, "cleanup", timeout=30.0)
        pytest.skip(
            f"TCP RST probe returned no samples — reject loop not working. "
            f"stdout={verify_result.stdout!r} rc={verify_result.returncode}. STOP."
        )
    verify_rtts = sorted(s.rtt_ms for s in verify_samples_disrupt)
    verify_p99 = verify_rtts[min(int(len(verify_rtts) * 0.99), len(verify_rtts) - 1)]
    print(
        f"  verify probe: n={len(verify_samples_disrupt)}"
        f" p50={verify_rtts[len(verify_rtts) // 2]:.2f}ms p99={verify_p99:.2f}ms"
    )
    if verify_p99 > 100.0:
        _bench(smoke_vm, "teardown_rules", timeout=30.0)
        _bench(smoke_vm, "cleanup", timeout=30.0)
        pytest.skip(f"RST p99={verify_p99:.1f}ms > 100ms — reject loop too slow. STOP.")
    print(f"  VERIFY PASSED: RST p99={verify_p99:.2f}ms")

    # Verify SSH still works after loading reject rules.
    try:
        smoke_vm.ssh("echo ssh_ok", timeout=10.0)
        print("  SSH control path: ok")
    except Exception as exc:
        _bench(smoke_vm, "teardown_rules", timeout=30.0)
        _bench(smoke_vm, "cleanup", timeout=30.0)
        pytest.skip(f"SSH to pfSense lost after loading reject rules: {exc} — STOP.")

    # ------------------------------------------------------------------ #
    # Main measurement loop: replace at each size, 20 reps
    # ------------------------------------------------------------------ #
    # Collect per-size: list of (baseline_window, during_window, wall_ms)
    size_data: dict[int, list[tuple[TcpRstWindow, TcpRstWindow, int]]] = {sz: [] for sz in _REPLACE_DISRUPT_SIZES}
    size_stats: dict[int, PooledStats] = {}
    size_buckets: dict[int, dict[int, tuple[int, float]]] = {}
    size_spike_thresh: dict[int, float] = {}
    size_wall_ms: dict[int, list[int]] = {sz: [] for sz in _REPLACE_DISRUPT_SIZES}

    print(f"\n--- Replace disruption measurement ({_REPLACE_DISRUPT_REPS} reps per size) ---")
    for sz in _REPLACE_DISRUPT_SIZES:
        print(f"\n  == size={sz:,} ==")
        for rep in range(_REPLACE_DISRUPT_REPS):
            print(f"  replace {sz:,} rep={rep + 1}/{_REPLACE_DISRUPT_REPS}", flush=True)
            row, bl_w, dur_w = _measure_with_rst_probe(
                smoke_vm,
                client_vm,
                ("replace", str(sz)),
                op_timeout_s=300.0,
            )
            size_data[sz].append((bl_w, dur_w, row.wall_ms))
            size_wall_ms[sz].append(row.wall_ms)

        # Compute pooled stats for this size.
        bl_wins = [r[0] for r in size_data[sz]]
        dur_wins = [r[1] for r in size_data[sz]]
        ps, buckets, spike_thresh = _compute_pooled_tcp_full(dur_wins, bl_wins)
        size_stats[sz] = ps
        size_buckets[sz] = buckets
        size_spike_thresh[sz] = spike_thresh
        med_wall = statistics.median(size_wall_ms[sz])
        print(
            f"  [size={sz:,}] wall_ms(med)={med_wall:.0f} n={ps.n}"
            f" p50={ps.p50_ms:.2f}ms p95={ps.p95_ms:.2f}ms"
            f" p99={ps.p99_ms:.2f}ms p99.9={ps.p999_ms:.2f}ms max={ps.max_ms:.2f}ms"
            f" spike_thresh={spike_thresh:.1f}ms spikes={ps.spikes}"
        )
        for thresh in _DISRUPT_BUCKETS_MS:
            cnt, pct = buckets[thresh]
            print(f"    >{thresh}ms: {cnt} ({pct:.2f}%)")

    _bench(smoke_vm, "teardown_rules", timeout=30.0)

    # ------------------------------------------------------------------ #
    # Quiescent baseline (no-op, table loaded, rules active but no pfctl op)
    # Collect quiescent RTT distribution per size for reference.
    # We reuse the verify windows collected before measurement as the reference,
    # but also collect a dedicated quiescent window per size here.
    # ------------------------------------------------------------------ #
    print("\n--- Quiescent baseline (no pfctl op, rules active) per size ---")
    # Reload rules for quiescent measurement.
    kv = _bench(smoke_vm, "setup_rules", "floating", timeout=30.0)
    quiet_stats: dict[int, PooledStats] = {}
    quiet_buckets: dict[int, dict[int, tuple[int, float]]] = {}

    for sz in _REPLACE_DISRUPT_SIZES:
        # Load the table for this size (so the quiescent baseline matches the same table).
        _bench(smoke_vm, "replace", str(sz), timeout=120.0)
        # Kill civm states before quiescent probe.
        smoke_vm.ssh("/sbin/pfctl -k 192.168.1.10 2>/dev/null || true", timeout=10.0)
        # Collect quiescent samples: 5s at ~500 conn/s.
        in_arg2 = ",".join(_PROBE_IN_TABLE_IPS)
        out_arg2 = ",".join(_PROBE_OUT_TABLE_IPS)
        qcmd = f"python3 /tmp/tcp_rst_probe.py {in_arg2} {out_arg2} 5.0 2>/dev/null"
        qresult = client_vm.ssh(qcmd, timeout=20.0)
        q_parsed = _parse_tcp_probe_output(qresult.stdout)
        q_samples = q_parsed.samples
        if q_samples:
            q_rtts = sorted(s.rtt_ms for s in q_samples)
            q_n = len(q_rtts)
            q_p95 = q_rtts[min(int(math.floor(q_n * 0.95)), q_n - 1)]
            q_p99 = q_rtts[min(int(math.floor(q_n * 0.99)), q_n - 1)]
            q_p50 = q_rtts[q_n // 2]
            # Compute stats.
            q_ps = PooledStats(
                n=q_n,
                mean_ms=statistics.mean(q_rtts),
                stddev_ms=statistics.pstdev(q_rtts),
                min_ms=q_rtts[0],
                p50_ms=q_p50,
                p95_ms=q_p95,
                p99_ms=q_p99,
                p999_ms=q_rtts[min(int(math.floor(q_n * 0.999)), q_n - 1)],
                max_ms=q_rtts[-1],
                total_loss=q_parsed.lost,
                total_sent=q_n + q_parsed.lost,
                spikes=0,
                spike_threshold_ms=0.0,
            )
            q_buckets = _compute_disrupt_buckets(q_rtts)
        else:
            q_ps = PooledStats(total_loss=q_parsed.lost, total_sent=q_parsed.lost)
            q_buckets = {t: (0, 0.0) for t in _DISRUPT_BUCKETS_MS}
        quiet_stats[sz] = q_ps
        quiet_buckets[sz] = q_buckets
        print(
            f"  quiescent size={sz:,}: n={q_ps.n}"
            f" p50={q_ps.p50_ms:.2f}ms p95={q_ps.p95_ms:.2f}ms"
            f" p99={q_ps.p99_ms:.2f}ms max={q_ps.max_ms:.2f}ms"
        )

    _bench(smoke_vm, "teardown_rules", timeout=30.0)

    # ------------------------------------------------------------------ #
    # Summary table
    # ------------------------------------------------------------------ #
    print("\n\n=== REPLACE DISRUPTION BASELINE SUMMARY ===")
    print("Replace-only ops; floating reject rules; TCP-RST probe at ~500 conn/s.")
    print("Spike threshold = quiescent baseline p95 × 3.0 (per cell).")
    print("Disruption buckets = connections stalled DURING the replace op.")
    print()
    _hdr3 = (
        f"{'size':>9} {'wall_ms':>9} {'n':>6} "
        f"{'mean':>7} {'std':>7} {'p50':>8} {'p95':>8} {'p99':>8} "
        f"{'p99.9':>9} {'max':>8} "
        f"{'spk_thr':>8} {'spikes':>7} "
        f"{'|>50ms':>10} {'|>100ms':>10} {'|>250ms':>10} {'|>500ms':>10}"
    )
    print(_hdr3)
    print("-" * len(_hdr3))
    for sz in _REPLACE_DISRUPT_SIZES:
        ps = size_stats[sz]
        bkts = size_buckets[sz]
        med_wall = statistics.median(size_wall_ms[sz])
        st = size_spike_thresh[sz]
        b50_cnt, b50_pct = bkts.get(50, (0, 0.0))
        b100_cnt, b100_pct = bkts.get(100, (0, 0.0))
        b250_cnt, b250_pct = bkts.get(250, (0, 0.0))
        b500_cnt, b500_pct = bkts.get(500, (0, 0.0))
        print(
            f"{sz:>9,} {med_wall:>9.0f} {ps.n:>6} "
            f"{ps.mean_ms:>7.2f} {ps.stddev_ms:>7.2f} {ps.p50_ms:>8.2f} {ps.p95_ms:>8.2f} "
            f"{ps.p99_ms:>8.2f} {ps.p999_ms:>9.2f} {ps.max_ms:>8.2f} "
            f"{st:>8.1f} {ps.spikes:>7} "
            f"{b50_cnt:>5}({b50_pct:>4.1f}%) "
            f"{b100_cnt:>5}({b100_pct:>4.1f}%) "
            f"{b250_cnt:>5}({b250_pct:>4.1f}%) "
            f"{b500_cnt:>5}({b500_pct:>4.1f}%)"
        )
    print()
    print("Quiescent baseline (no-op, rules active):")
    _hdr4 = f"{'size':>9} {'n':>6} {'p50':>8} {'p95':>8} {'p99':>8} {'max':>8}"
    print(_hdr4)
    print("-" * len(_hdr4))
    for sz in _REPLACE_DISRUPT_SIZES:
        q_ps = quiet_stats[sz]
        print(f"{sz:>9,} {q_ps.n:>6} {q_ps.p50_ms:>8.2f} {q_ps.p95_ms:>8.2f} {q_ps.p99_ms:>8.2f} {q_ps.max_ms:>8.2f}")

    # Final assertions: data was collected.
    assert any(size_stats[sz].n > 0 for sz in _REPLACE_DISRUPT_SIZES), (
        "expected non-empty pooled samples for at least one size"
    )


# --------------------------------------------------------------------------- #
# Uncensored disruption magnitudes (ADR-40 follow-up 02c)
# --------------------------------------------------------------------------- #

# Replace sweep sizes for the uncensored run (same as 02b but now uncensored).
_UNCENSORED_REPLACE_SIZES = [10_000, 50_000, 100_000, 200_000, 462_000, 750_000, 1_000_000]

# Delta comparison cells (table_size, churn_pct_label, churn, batch).
# Production-relevant: 1% and 5% churn at 100k and 462k, batch=512 (shipped default).
_UNCENSORED_DELTA_CELLS = [
    (100_000, "1pct", 1_000, 512),
    (462_000, "1pct", 4_620, 512),
    (100_000, "5pct", 5_000, 512),
    (462_000, "5pct", 23_100, 512),
]

# Disruption buckets: the uncensored run adds >1s and >2s buckets.
_UNCENSORED_BUCKETS_MS = [50, 100, 250, 500, 1_000, 2_000]

# Reps per cell.
_UNCENSORED_REPS = 20


def _compute_disrupt_buckets_full(rtts: list[float]) -> dict[int, tuple[int, float]]:
    """Return {threshold_ms: (count, pct)} for _UNCENSORED_BUCKETS_MS."""
    n = len(rtts)
    result: dict[int, tuple[int, float]] = {}
    for thresh in _UNCENSORED_BUCKETS_MS:
        cnt = sum(1 for r in rtts if r > thresh)
        result[thresh] = (cnt, 100.0 * cnt / n if n > 0 else 0.0)
    return result


@pytest.mark.pfctl_bench
def test_pfctl_disruption_uncensored(
    smoke_vm: SmokeVM,
    lan_interface: SmokeVM,
    client_vm: SmokeVM,
    request: pytest.FixtureRequest,
) -> None:
    """ADR-40 02c: uncensored disruption magnitudes — replace vs delta.

    Scenario:
      Given pfSense with floating reject rules (LAN block-return + WAN block-return-out)
      And a civm TCP-RST probe at ~500 conn/s with 5s timeout (uncensored) and 400
        concurrent in-flight connections (no probe starvation at short op windows)
      And connections sliced by START time so stalled connections are captured even
        if they complete after the op window ends
      When pfctl -T replace runs at 7 sizes (10k–1M) for 20 reps each
      And pfctl delta runs at 4 production cells (100k/1%, 462k/1%, 100k/5%, 462k/5%)
        at batch=512 (shipped default) for 20 reps each
      Then per-cell pooled distribution is reported: n, mean, stddev, min, p50, p95,
        p99, p99.9, max, AND disruption buckets (>50ms, >100ms, >250ms, >500ms,
        >1s, >2s count + %) with quiescent baseline for reference

    Fixes two issues in 02b (test_pfctl_replace_disruption_baseline):
      1. PROBE CENSORING: prior timeout=0.5s clamped every stall ≥500ms to ~500ms.
         True replace disruption was invisible (100k→1M all flat ~500ms, 100%).
         Now timeout=5.0s records the REAL stall duration; only genuine ≥5s losses
         are excluded from the RTT distribution (they have no RTT to report) —
         counted instead in the pooled loss tally (should be ~none with RST
         reject rules).
      2. PROBE STARVATION (50k n=4): prior sem=64 with 0.5s timeout starved short
         op windows.  Now sem=400 with start-time slicing: connections STARTED during
         the op are captured regardless of when they complete (a 200ms stall on a
         52ms op window is still recorded).

    This run SUPERSEDES 02b's censored disruption numbers and directly ANSWERS:
      - TRUE replace stall vs table size (does it grow? floor at TCP RTO ~1s?).
      - How much does delta reduce disruption at 1% and 5% churn?
      - Does the picture support the shipped defaults (5% threshold, batch 512)?

    Results: .ADRs/ADR_40_Content_Addressed_Alias_Updates/RESULTS/02c_Disruption_Magnitude_Uncensored.txt
    Always passes — measurement harness.
    """
    print("\n=== ADR-40 02c: uncensored disruption magnitudes ===")
    print("  SUPERSEDES 02b (censored at 500ms); complements 02_Results.")
    print("  Probe: 5s timeout, 400 concurrent, start-time slice (no starvation).")
    print(f"  Replace sizes: {[f'{s:,}' for s in _UNCENSORED_REPLACE_SIZES]}")
    print(f"  Delta cells: {[(s, lbl, c, b) for s, lbl, c, b in _UNCENSORED_DELTA_CELLS]}")
    print(f"  {_UNCENSORED_REPS} reps per cell | op-aligned (start-time slice)")
    print(f"  Disruption buckets: >{_UNCENSORED_BUCKETS_MS}ms")

    # Upload TCP probe script (refreshed version with 5s timeout + start_t).
    # Force re-upload so the updated script replaces any cached version.
    global _TCP_PROBE_UPLOADED  # noqa: PLW0603
    _TCP_PROBE_UPLOADED = False
    _upload_tcp_probe(client_vm)

    # Route probe IPs through pfSense LAN on civm.
    client_vm.ssh(
        "ip route replace 11.0.0.0/8 via 192.168.1.1 dev ens5"
        " && ip route replace 13.0.0.0/8 via 192.168.1.1 dev ens5"
        " && echo routes_ok",
        timeout=10.0,
    )

    kv = _bench(smoke_vm, "system_info")
    print(f"  Guest: {kv.get('hostname')} RAM={kv.get('ram_mib')}MiB CPUs={kv.get('ncpu')}")

    kv = _bench(smoke_vm, "raise_limits", "10000000")
    print(f"  pf table limit: {kv.get('pf_table_limit')}")
    # Guarantees the 1M-entry table + raised sysctl/pf limits are torn down even if a
    # sweep rep below throws — a bare end-of-function cleanup call never runs on a
    # mid-sweep failure (issue #582). Runs during test teardown regardless of outcome.
    request.addfinalizer(lambda: _bench(smoke_vm, "cleanup", timeout=30.0))

    # Generate all needed tables.
    all_sizes = sorted(set(_UNCENSORED_REPLACE_SIZES) | {s for s, _, _, _ in _UNCENSORED_DELTA_CELLS})
    for sz in all_sizes:
        kv = _bench(smoke_vm, "gen", str(sz), timeout=300.0)
        print(f"  gen {sz:,}: {kv.get('generated', kv.get('cached', '?'))}")

    # Load largest table and set up floating reject rules.
    kv = _bench(smoke_vm, "replace", "1000000", timeout=120.0)
    print(f"  Loaded 1M table: wall_ms={kv.get('wall_ms')}")

    print("\n--- Setting up floating reject rules ---")
    kv = _bench(smoke_vm, "setup_rules", "floating", timeout=30.0)
    if "error" in kv:
        pytest.skip(f"Cannot set up reject rules: {kv.get('error')} — STOP")

    # Verify RST loop with 5s timeout.
    in_arg = ",".join(_PROBE_IN_TABLE_IPS[:3])
    out_arg = ",".join(_PROBE_OUT_TABLE_IPS[:3])
    verify_result = client_vm.ssh(f"python3 /tmp/tcp_rst_probe.py {in_arg} {out_arg} 3.0", timeout=15.0)
    verify_samples_unc = _parse_tcp_probe_output(verify_result.stdout).samples
    if not verify_samples_unc:
        _bench(smoke_vm, "teardown_rules", timeout=30.0)
        pytest.skip("TCP RST probe returned no samples — reject loop not working. STOP.")
    v_rtts = sorted(s.rtt_ms for s in verify_samples_unc)
    v_p99 = v_rtts[min(int(len(v_rtts) * 0.99), len(v_rtts) - 1)]
    print(f"  verify probe: n={len(verify_samples_unc)} p50={v_rtts[len(v_rtts) // 2]:.2f}ms p99={v_p99:.2f}ms")
    if v_p99 > 200.0:
        _bench(smoke_vm, "teardown_rules", timeout=30.0)
        pytest.skip(f"RST p99={v_p99:.1f}ms > 200ms quiescent — loop too slow. STOP.")
    print(f"  VERIFY PASSED: RST p99={v_p99:.2f}ms ✓")

    try:
        smoke_vm.ssh("echo ssh_ok", timeout=10.0)
    except Exception as exc:
        _bench(smoke_vm, "teardown_rules", timeout=30.0)
        pytest.skip(f"SSH to pfSense lost after reject rules: {exc} — STOP.")

    # ------------------------------------------------------------------ #
    # Helper: run one uncensored probe cell (replace or delta)
    # ------------------------------------------------------------------ #
    def _run_uncensored_cell(
        label: str,
        bench_args: tuple[str, ...],
        reps: int,
    ) -> tuple[PooledStats, dict[int, tuple[int, float]], float, list[int]]:
        """Run reps measurements; return (PooledStats, buckets, spike_thresh, wall_ms_list).

        buckets uses _UNCENSORED_BUCKETS_MS (adds >1s, >2s vs the older 4-bucket set).
        """
        bl_wins: list[TcpRstWindow] = []
        dur_wins: list[TcpRstWindow] = []
        wall_ms_list: list[int] = []

        for rep in range(reps):
            print(f"  {label} rep={rep + 1}/{reps}", flush=True)
            row, bl_w, dur_w = _measure_with_rst_probe(
                smoke_vm,
                client_vm,
                bench_args,
                op_timeout_s=600.0,
                batch_dur_s=5.0,
            )
            bl_wins.append(bl_w)
            dur_wins.append(dur_w)
            wall_ms_list.append(row.wall_ms)
            print(f"    wall_ms={row.wall_ms} n_during={len(dur_w.samples)}")

        # Compute pooled stats + extended bucket set.
        all_rtts: list[float] = [s.rtt_ms for w in dur_wins for s in w.samples]
        baseline_rtts: list[float] = [s.rtt_ms for w in bl_wins for s in w.samples]
        baseline_p95 = 0.0
        if baseline_rtts:
            sbl = sorted(baseline_rtts)
            idx_bl = min(int(math.floor(len(sbl) * 0.95)), len(sbl) - 1)
            baseline_p95 = sbl[idx_bl]
        spike_thresh = baseline_p95 * _DISRUPT_SPIKE_FACTOR

        ps_base, _, _ = _compute_pooled_tcp_full(dur_wins, bl_wins)
        buckets = _compute_disrupt_buckets_full(all_rtts)

        med_wall = statistics.median(wall_ms_list)
        print(
            f"  [{label}] wall_ms(med)={med_wall:.0f} n={ps_base.n}"
            f" p50={ps_base.p50_ms:.2f}ms p95={ps_base.p95_ms:.2f}ms"
            f" p99={ps_base.p99_ms:.2f}ms p99.9={ps_base.p999_ms:.2f}ms max={ps_base.max_ms:.2f}ms"
        )
        for thresh in _UNCENSORED_BUCKETS_MS:
            cnt, pct = buckets[thresh]
            print(f"    >{thresh}ms: {cnt} ({pct:.2f}%)")
        return ps_base, buckets, spike_thresh, wall_ms_list

    # ------------------------------------------------------------------ #
    # A: Replace size sweep (uncensored disruption curve)
    # ------------------------------------------------------------------ #
    print(f"\n--- A: replace size sweep ({_UNCENSORED_REPS} reps, uncensored) ---")
    replace_ps: dict[int, PooledStats] = {}
    replace_buckets: dict[int, dict[int, tuple[int, float]]] = {}
    replace_spike_thresh: dict[int, float] = {}
    replace_wall_ms: dict[int, list[int]] = {}

    for sz in _UNCENSORED_REPLACE_SIZES:
        print(f"\n  == replace size={sz:,} ==")
        ps, bkts, st, walls = _run_uncensored_cell(f"replace {sz:,}", ("replace", str(sz)), _UNCENSORED_REPS)
        replace_ps[sz] = ps
        replace_buckets[sz] = bkts
        replace_spike_thresh[sz] = st
        replace_wall_ms[sz] = walls

    # ------------------------------------------------------------------ #
    # B: Delta comparison (replace vs delta at 1% and 5% churn)
    # ------------------------------------------------------------------ #
    print(f"\n--- B: delta comparison ({_UNCENSORED_REPS} reps per cell, batch=512) ---")
    delta_ps: dict[tuple[int, str, int, int], PooledStats] = {}
    delta_buckets: dict[tuple[int, str, int, int], dict[int, tuple[int, float]]] = {}
    delta_spike_thresh: dict[tuple[int, str, int, int], float] = {}
    delta_wall_ms: dict[tuple[int, str, int, int], list[int]] = {}

    for sz, lbl, churn, batch in _UNCENSORED_DELTA_CELLS:
        print(f"\n  == delta size={sz:,} churn={churn:,} ({lbl}) batch={batch} ==")
        key = (sz, lbl, churn, batch)
        ps, bkts, st, walls = _run_uncensored_cell(
            f"delta {sz:,}/{churn:,}({lbl})/b{batch}",
            ("delta", str(sz), str(churn), str(batch)),
            _UNCENSORED_REPS,
        )
        delta_ps[key] = ps
        delta_buckets[key] = bkts
        delta_spike_thresh[key] = st
        delta_wall_ms[key] = walls

    # ------------------------------------------------------------------ #
    # Quiescent baseline per replace size
    # ------------------------------------------------------------------ #
    print("\n--- Quiescent baseline (no pfctl op, rules active) ---")
    quiet_ps_unc: dict[int, PooledStats] = {}
    for sz in _UNCENSORED_REPLACE_SIZES:
        _bench(smoke_vm, "replace", str(sz), timeout=120.0)
        smoke_vm.ssh("/sbin/pfctl -k 192.168.1.10 2>/dev/null || true", timeout=10.0)
        in_arg2 = ",".join(_PROBE_IN_TABLE_IPS)
        out_arg2 = ",".join(_PROBE_OUT_TABLE_IPS)
        qresult = client_vm.ssh(
            f"python3 /tmp/tcp_rst_probe.py {in_arg2} {out_arg2} 5.0 2>/dev/null",
            timeout=30.0,
        )
        q_parsed = _parse_tcp_probe_output(qresult.stdout)
        q_samples = q_parsed.samples
        if q_samples:
            q_rtts = sorted(s.rtt_ms for s in q_samples)
            qn = len(q_rtts)

            def _qpct(p: float) -> float:
                return q_rtts[min(int(math.floor(qn * p)), qn - 1)]

            quiet_ps_unc[sz] = PooledStats(
                n=qn,
                mean_ms=statistics.mean(q_rtts),
                stddev_ms=statistics.pstdev(q_rtts),
                min_ms=q_rtts[0],
                p50_ms=_qpct(0.50),
                p95_ms=_qpct(0.95),
                p99_ms=_qpct(0.99),
                p999_ms=_qpct(0.999),
                max_ms=q_rtts[-1],
                total_loss=q_parsed.lost,
                total_sent=qn + q_parsed.lost,
            )
        else:
            quiet_ps_unc[sz] = PooledStats(total_loss=q_parsed.lost, total_sent=q_parsed.lost)
        qp = quiet_ps_unc[sz]
        print(
            f"  quiescent size={sz:,}: n={qp.n}"
            f" p50={qp.p50_ms:.2f}ms p95={qp.p95_ms:.2f}ms"
            f" p99={qp.p99_ms:.2f}ms max={qp.max_ms:.2f}ms"
        )

    _bench(smoke_vm, "teardown_rules", timeout=30.0)

    # ------------------------------------------------------------------ #
    # Summary table
    # ------------------------------------------------------------------ #
    _hdr_unc = (
        f"{'op':<8} {'size':>9} {'churn':>7} {'batch':>6} "
        f"{'wall_ms':>9} {'n':>6} "
        f"{'mean':>7} {'std':>7} {'p50':>8} {'p95':>8} {'p99':>8} "
        f"{'p99.9':>9} {'max':>8} "
        f"{'spk_thr':>8} {'spikes':>7} "
        f"{'|>50ms':>10} {'|>100ms':>10} {'|>250ms':>10} {'|>500ms':>10} {'|>1s':>9} {'|>2s':>9}"
    )

    def _print_unc_row(
        op: str,
        sz: int,
        churn: int | str,
        batch: int | str,
        ps: PooledStats,
        bkts: dict[int, tuple[int, float]],
        st: float,
        med_wall: float,
    ) -> None:
        churn_s = f"{churn:,}" if isinstance(churn, int) else str(churn)
        batch_s = str(batch)
        b50_cnt, b50_pct = bkts.get(50, (0, 0.0))
        b100_cnt, b100_pct = bkts.get(100, (0, 0.0))
        b250_cnt, b250_pct = bkts.get(250, (0, 0.0))
        b500_cnt, b500_pct = bkts.get(500, (0, 0.0))
        b1k_cnt, b1k_pct = bkts.get(1_000, (0, 0.0))
        b2k_cnt, b2k_pct = bkts.get(2_000, (0, 0.0))
        print(
            f"{op:<8} {sz:>9,} {churn_s:>7} {batch_s:>6} "
            f"{med_wall:>9.0f} {ps.n:>6} "
            f"{ps.mean_ms:>7.2f} {ps.stddev_ms:>7.2f} {ps.p50_ms:>8.2f} {ps.p95_ms:>8.2f} "
            f"{ps.p99_ms:>8.2f} {ps.p999_ms:>9.2f} {ps.max_ms:>8.2f} "
            f"{st:>8.1f} {ps.spikes:>7} "
            f"{b50_cnt:>5}({b50_pct:>4.1f}%) "
            f"{b100_cnt:>5}({b100_pct:>4.1f}%) "
            f"{b250_cnt:>5}({b250_pct:>4.1f}%) "
            f"{b500_cnt:>5}({b500_pct:>4.1f}%) "
            f"{b1k_cnt:>4}({b1k_pct:>4.1f}%) "
            f"{b2k_cnt:>4}({b2k_pct:>4.1f}%)"
        )

    print("\n\n=== UNCENSORED DISRUPTION MAGNITUDE SUMMARY (02c) ===")
    print("Probe: 5s timeout, 400 concurrent, start-time slice (CR#12 + starvation fix).")
    print("SUPERSEDES 02b (censored at 500ms via 0.5s timeout).")
    print("Spike threshold = quiescent baseline p95 × 3.0.")
    print()
    print(_hdr_unc)
    print("-" * len(_hdr_unc))

    print("\n-- A: replace size sweep --")
    for sz in _UNCENSORED_REPLACE_SIZES:
        ps = replace_ps[sz]
        _print_unc_row(
            "replace",
            sz,
            "—",
            "—",
            ps,
            replace_buckets[sz],
            replace_spike_thresh[sz],
            statistics.median(replace_wall_ms[sz]),
        )

    print("\n-- B: delta vs replace comparison (batch=512) --")
    for sz, lbl, churn, batch in _UNCENSORED_DELTA_CELLS:
        key = (sz, lbl, churn, batch)
        # Also print the matching replace row for direct comparison.
        if sz in replace_ps:
            _print_unc_row(
                "replace",
                sz,
                "—",
                "—",
                replace_ps[sz],
                replace_buckets[sz],
                replace_spike_thresh[sz],
                statistics.median(replace_wall_ms[sz]),
            )
        ps = delta_ps[key]
        _print_unc_row(
            "delta",
            sz,
            f"{churn:,}({lbl})",
            batch,
            ps,
            delta_buckets[key],
            delta_spike_thresh[key],
            statistics.median(delta_wall_ms[key]),
        )
        # Compute reduction factor.
        rps = replace_ps.get(sz)
        if rps and rps.p99_ms > 0 and ps.p99_ms > 0:
            factor = rps.p99_ms / ps.p99_ms
            print(f"    → delta p99 vs replace: {factor:.1f}× (replace={rps.p99_ms:.1f}ms delta={ps.p99_ms:.1f}ms)")
        print()

    print("\nQuiescent baseline (no pfctl op, rules active):")
    qhdr = f"{'size':>9} {'n':>6} {'p50':>8} {'p95':>8} {'p99':>8} {'p99.9':>9} {'max':>8}"
    print(qhdr)
    print("-" * len(qhdr))
    for sz in _UNCENSORED_REPLACE_SIZES:
        qp = quiet_ps_unc[sz]
        print(
            f"{sz:>9,} {qp.n:>6} {qp.p50_ms:>8.2f} {qp.p95_ms:>8.2f}"
            f" {qp.p99_ms:>8.2f} {qp.p999_ms:>9.2f} {qp.max_ms:>8.2f}"
        )

    print(
        "\nProbe: in-table 11.x + out-table 13.x; both paths RST."
        "\nTimeout: 5.0s (loss = genuine ≥5s failures only)."
        "\nWindow: connections STARTED in [t0, t1] (start-time slice) — RTT samples only;"
        "\n  loss is pooled per RUN (not attributed to this start-time slice), by design."
        f"\n{_UNCENSORED_REPS} reps per cell | op-aligned."
    )

    assert any(replace_ps[sz].n > 0 for sz in _UNCENSORED_REPLACE_SIZES), "expected non-empty pooled replace samples"
