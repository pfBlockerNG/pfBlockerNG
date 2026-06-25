"""ADR-40 Phase 2 — pfctl table benchmark (dispatch-only, NOT PR-gating).

Measures on the real two-VM topology:
  (a) -T replace wall-time + data-plane stall at 10k / 100k / 1M entries.
  (b) Chunked -T add/-T delete at batch sizes {giant, 1, 64, 256, 1024, 4096}
      × churn {1, 1k, 100k} × table {100k, 1M} — sweep batch sizes at larger
      tables where it matters; 10k × small churn for context.
  (c) LC_ALL=C sort -u recompute cost (pfb_canonical_alias_set proxy).

PRIMARY SIGNAL: ICMP RTT distribution (p50/p99/max) + packet loss from civm
to pfSense LAN IP (192.168.1.1) during each pfctl op.  Captures whether a
table replace/delta stalls the data plane while pf holds the rules write lock.

SECONDARY SIGNAL: concurrent pfctl -T show latency on the pfSense guest
(control-plane lock proxy) — emitted by the shell script, reported here.

Marker: pfctl_bench — NEVER PR-gating (not in default -m smoke/-m reboot/etc.).
Run via:
    scripts/local-smoke.sh tests/smoke/test_bench_pfctl.py -m pfctl_bench \\
        --override-ini="addopts="

Requires: smoke_vm + client_vm (two-VM topology) + lan_interface.  Skips
cleanly when civm is unavailable (pfSense-only environments).

Design notes for Phase 4 (recorded here per ADR §7):
  - Boot / enable-disable: one-shot -T replace is correct (no delta needed).
  - Incremental feed updates: this benchmark's verdict decides replace vs delta.
  - Recommended batch size + mode recorded in the verdict section of the
    handoff (RESULTS/02_Results.txt).
"""

from __future__ import annotations

import re
import shlex
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

# Table sizes to benchmark.
_SIZES = [10_000, 100_000, 1_000_000]

# Batch sizes for delta apply.  0 = single-giant-op (one pfctl call for all).
# Sweep is done at 100k and 1M tables with churn 1k and 100k (most informative).
_BATCH_SIZES = [0, 1, 64, 256, 1024, 4096]


# --------------------------------------------------------------------------- #
# Data types
# --------------------------------------------------------------------------- #


@dataclass
class IcmpProbe:
    """Per-packet ICMP RTT sample collected from civm."""

    rtt_ms: float  # round-trip time in milliseconds
    seq: int  # ping sequence number


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
    civm is Debian not pfSense so /bin/sh parses it correctly).  Interval 0.02s
    (~50 pps) gives enough resolution to catch sub-100ms stalls.

    The probe is ALLOWED traffic — ICMP to pfSense LAN IP.  We measure whether
    the pfctl table op stalls the data plane, not whether packets are blocked.
    """
    count = max(1, int(duration_s / interval_s))
    # LC_ALL=C: pin locale so the ping summary and RTT lines match the regex
    # regardless of the civm Debian locale setting.
    cmd = f"LC_ALL=C ping -c {count} -i {interval_s} -W 1 {shlex.quote(target)} 2>&1"
    result = client_vm.ssh(cmd, timeout=duration_s + 30.0)
    return _parse_ping(result.stdout)


def _parse_ping(output: str) -> ProbeWindow:
    """Parse ``ping`` output into per-packet RTT samples + loss count."""
    window = ProbeWindow()
    # Match per-packet lines: "64 bytes from ...: icmp_seq=N ttl=T time=X ms"
    for m in re.finditer(r"icmp_seq=(\d+).*?time=([\d.]+)\s+ms", output):
        window.samples.append(IcmpProbe(seq=int(m.group(1)), rtt_ms=float(m.group(2))))
    # Loss from summary: "N packets transmitted, M received, P% packet loss"
    m = re.search(r"(\d+) packets transmitted, (\d+) received", output)
    if m:
        sent = int(m.group(1))
        recv = int(m.group(2))
        window.lost = max(0, sent - recv)
    return window


# --------------------------------------------------------------------------- #
# Background ICMP probe (runs concurrently with pfctl ops)
# --------------------------------------------------------------------------- #


class _LiveProbe:
    """Runs a continuous ping on civm in a background thread.

    Accumulates per-packet samples; the caller snapshots windows by
    calling ``snapshot()`` at op-start and ``stop()`` at op-end.
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
        # Fire batches of ~100 pings, collect, repeat until stopped.
        # LC_ALL=C: pin locale so ping output matches the RTT regex on any Debian locale.
        batch_count = 100
        while not self._stop_evt.is_set():
            cmd = f"LC_ALL=C ping -c {batch_count} -i {self._interval} -W 1 {shlex.quote(self._target)} 2>&1"
            duration = batch_count * self._interval + 5.0
            result = self._client.ssh(cmd, timeout=duration + 10.0)
            pw = _parse_ping(result.stdout)
            with self._lock:
                self._samples.extend(pw.samples)
                self._lost += pw.lost

    def snapshot_since(self, since_epoch: float) -> ProbeWindow:
        """Return samples collected at or after since_epoch.

        We do not have per-packet timestamps from the probe; the caller aligns
        the "during" window to the op by recording ``epoch_start``/``epoch_end``
        from the guest bench script and calling ``stop()`` (which bounds the
        collection to the op duration).  ``snapshot_since`` is provided for
        future callers that want a finer sub-window; it currently returns all
        accumulated samples as a coarse approximation.
        """
        with self._lock:
            pw = ProbeWindow()
            pw.samples = list(self._samples)
            pw.lost = self._lost
            return pw

    def stop(self) -> ProbeWindow:
        self._stop_evt.set()
        self._thread.join(timeout=30.0)
        with self._lock:
            pw = ProbeWindow()
            pw.samples = list(self._samples)
            pw.lost = self._lost
            return pw


# --------------------------------------------------------------------------- #
# Guest script wrapper
# --------------------------------------------------------------------------- #


def _bench(smoke_vm: SmokeVM, *args: str, timeout: float = 600.0) -> dict[str, str]:
    """Run bench_pfctl_tables.sh <args> on the pfSense guest; parse key=val output.

    Returns ``{"timeout": "true", ...op=, size=, ...}`` when the op exceeds ``timeout``.
    This lets very-slow batch cases (e.g. batch=1 at large churn) be recorded as TIMEOUT
    rather than crashing the whole benchmark run.
    """
    script_content = _BENCH_SH.read_text()
    # Upload the script to the guest on first call (idempotent: write same path).
    _upload_bench_script(smoke_vm, script_content)
    cmd = "/tmp/bench_pfctl_tables.sh " + " ".join(shlex.quote(str(a)) for a in args)
    try:
        result = smoke_vm.ssh(cmd, timeout=timeout)
    except subprocess.TimeoutExpired:
        # Record the timeout as a special row so the summary table stays intact.
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
    # Write via tee (avoids scp dependency and works via ssh stdio).
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
    """Parse key=val output; each token of the form key=val is extracted.

    Each line may contain one or more space-separated key=val tokens.
    Tokens without '=' are silently ignored (progress messages, etc.).
    Last writer wins when a key appears on multiple lines.
    """
    out: dict[str, str] = {}
    for line in text.splitlines():
        for token in line.split():
            if "=" in token:
                k, _, v = token.partition("=")
                if k:
                    out[k] = v
    return out


def _parse_guest_row(kv: dict[str, str]) -> dict[str, object]:
    """Extract typed fields from the key=val dict returned by the bench script."""
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
) -> BenchRow:
    """Run one bench op while capturing ICMP baseline and during-op windows.

    If client_vm is None, skips the ICMP probe (returns empty ProbeWindows).
    """
    # ---- baseline probe ---- #
    baseline_window = ProbeWindow()
    if client_vm is not None:
        baseline_window = _run_icmp_probe(client_vm, PFSENSE_LAN_IP, duration_s=baseline_duration_s)

    # ---- launch background probe ---- #
    probe: _LiveProbe | None = None
    if client_vm is not None:
        probe = _LiveProbe(client_vm, PFSENSE_LAN_IP)
        probe.start()

    # ---- run the pfctl op on the guest ---- #
    kv = _bench(smoke_vm, *bench_args, timeout=op_timeout_s)

    # ---- stop background probe ---- #
    during_window = ProbeWindow()
    if probe is not None:
        during_window = probe.stop()

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
# The benchmark test
# --------------------------------------------------------------------------- #


@pytest.mark.pfctl_bench
def test_pfctl_bench(
    smoke_vm: SmokeVM,
    lan_interface: SmokeVM,
    client_vm: SmokeVM,
) -> None:
    """ADR-40 Phase 2: measure pfctl replace vs chunked delta + recompute cost.

    Scenario:
      Given a pfSense VM with a synthetic pf table
      And a civm client probing via ICMP through pfSense
      When a pfctl table op (replace / chunked delta / recompute) runs
      Then we capture wall-time + ICMP stall profile + control-plane lock latency

    The test always passes (it is a measurement harness, not a correctness gate).
    All numbers are printed so the verdict can be read from the test output.
    """
    # ---- setup ---- #
    print("\n=== ADR-40 Phase 2: pfctl table benchmark ===")

    kv = _bench(smoke_vm, "system_info")
    print(f"  Guest: {kv.get('hostname')} RAM={kv.get('ram_mib')}MiB CPUs={kv.get('ncpu')}")

    kv = _bench(smoke_vm, "raise_limits", "10000000")
    print(f"  pf table limit raised to: {kv.get('pf_table_limit')}")

    # Generate all needed tables.
    for sz in _SIZES:
        kv = _bench(smoke_vm, "gen", str(sz), timeout=120.0)
        print(f"  gen {sz:,}: {kv.get('generated', kv.get('cached', '?'))}")

    rows: list[BenchRow] = []

    # ---- (a) replace at all sizes ---- #
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

    # ---- (b) delta at multiple batch sizes and churn levels ---- #
    print("\n--- (b) -T delta (chunked) ---")

    # Full sweep at 100k and 1M (where it matters most).
    # At 10k, only do 1 and 256 batches to keep matrix tractable.
    delta_plan = [
        # (size, churn, batch_sizes_for_this_size_churn)
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
            # Timeout: large churn + small batch = many pfctl calls; allow 10min.
            op_timeout = 600.0
            if batch == 1 and churn >= 1_000:
                op_timeout = 1200.0  # 1-by-1 at 100k churn can be very slow

            row = _measure_with_probe(
                smoke_vm,
                client_vm,
                bench_args=("delta", str(sz), str(churn), str(batch)),
                baseline_duration_s=2.0,
                op_timeout_s=op_timeout,
            )
            rows.append(row)

    # ---- (c) recompute at all sizes ---- #
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

    # ---- summary table ---- #
    _print_summary(rows)

    # ---- cleanup ---- #
    _bench(smoke_vm, "cleanup", timeout=30.0)

    # The test always passes — it is a measurement harness.
    # The verdict (build/drop Phase 4; keep/re-scope cross-list arm) is derived
    # from the printed numbers and recorded in RESULTS/02_Results.txt.
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
