"""Issue #738 F5 — the pfctl bench's TCP-RST probe must count genuine timeouts as loss.

Pins the PURE, off-VM parsing/aggregation seam of ``tests/smoke/test_bench_pfctl.py``'s
TCP-RST reject-loop probe: before this fix, a connection that genuinely stalled for
>=5s (``rtt_ms=-1`` in the probe's JSON output) was silently dropped by both the
guest-side ``if rtt_ms >= 0:`` print filter and the harness-side ``_parse_tcp_probe_output``
filter, and every TCP ``PooledStats`` hardcoded ``total_loss=0`` — so the printed loss%
column always read 0.0 even when connections blackholed.

The maintainer's decision (recorded in the issue): SIMPLER pooled semantics — count
>=5s losses per RUN (summed across a probe's whole capture) and report an honest
pooled loss%/total_sent, WITHOUT redesigning per-op-window attribution. NOTE this
deliberately diverges from ICMP's ``_LiveProbe.slice_window`` (which zeroes ``lost``
on op-aligned windows); see the ``TcpRstWindow`` docstring for the divergence and the
one-slice-per-run invariant.

These tests exercise ``_parse_tcp_probe_output`` and ``_compute_pooled_tcp``/
``_compute_pooled_tcp_full`` directly (pure functions, no VM needed) — importing
``tests.smoke.test_bench_pfctl`` is import-safe off-VM (see ``tests/test_smoke_diag_redaction.py``
for the established pattern of pulling pure seams out of ``tests/smoke/`` for the default suite).
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from tests.smoke.test_bench_pfctl import (
    _TCP_PROBE_SCRIPT,
    PooledStats,
    TcpRstWindow,
    _compute_pooled_tcp,
    _compute_pooled_tcp_full,
    _parse_tcp_probe_output,
)


def _probe_line(*, start_t: float, t: float, rtt_ms: float, ip: str = "11.0.0.1") -> str:
    """Build one JSON line in the exact shape tcp_rst_probe.py emits on the guest."""
    return json.dumps({"start_t": start_t, "t": t, "rtt_ms": rtt_ms, "ip": ip})


# --------------------------------------------------------------------------- #
# _parse_tcp_probe_output — a -1 timeout record is a loss, not a dropped line
# --------------------------------------------------------------------------- #


def test_parse_tcp_probe_output_counts_timeout_as_loss_not_sample() -> None:
    """A genuine >=5s timeout (rtt_ms=-1) is tallied as a loss and excluded from samples.

    Given probe output with one real RTT record and one -1 timeout record
    When the output is parsed
    Then the timeout is counted in ``lost`` (not silently dropped) and never
      appears in the RTT ``samples`` list (it has no RTT to report).
    """
    output = "\n".join(
        [
            _probe_line(start_t=100.0, t=100.005, rtt_ms=5.25, ip="11.0.0.1"),
            _probe_line(start_t=100.1, t=105.1, rtt_ms=-1.0, ip="13.0.0.1"),
        ]
    )

    parsed = _parse_tcp_probe_output(output)

    assert parsed.lost == 1, f"expected lost=1 (one genuine >=5s timeout record) but got lost={parsed.lost}"
    assert len(parsed.samples) == 1, (
        f"expected 1 kept RTT sample (the timeout must be excluded) but got {len(parsed.samples)}: "
        f"{[s.rtt_ms for s in parsed.samples]}"
    )
    assert parsed.samples[0].rtt_ms == 5.25, (
        f"expected the surviving sample to be the real RTT record (5.25ms) but got {parsed.samples[0].rtt_ms}ms"
    )
    assert all(s.rtt_ms >= 0 for s in parsed.samples), (
        f"a negative-rtt (timeout) record leaked into samples: {[s.rtt_ms for s in parsed.samples]}"
    )


def test_parse_tcp_probe_output_multiple_losses_all_counted() -> None:
    """Every -1 record in a batch is tallied, not just the first/last one.

    Given probe output with three timeout records interleaved among two real ones
    When the output is parsed
    Then lost == 3 and samples contains exactly the two real RTT records.
    """
    lines = [
        _probe_line(start_t=1.0, t=1.01, rtt_ms=2.0),
        _probe_line(start_t=1.1, t=6.1, rtt_ms=-1.0),
        _probe_line(start_t=1.2, t=6.2, rtt_ms=-1.0),
        _probe_line(start_t=1.3, t=1.31, rtt_ms=3.5),
        _probe_line(start_t=1.4, t=6.4, rtt_ms=-1.0),
    ]
    parsed = _parse_tcp_probe_output("\n".join(lines))

    assert parsed.lost == 3, f"expected lost=3 (three -1 records) but got lost={parsed.lost}"
    assert len(parsed.samples) == 2, f"expected 2 RTT samples but got {len(parsed.samples)}"
    assert sorted(s.rtt_ms for s in parsed.samples) == [2.0, 3.5], (
        f"expected kept RTT samples [2.0, 3.5] but got {sorted(s.rtt_ms for s in parsed.samples)}"
    )


def test_parse_tcp_probe_output_no_losses_stays_zero() -> None:
    """Branch coverage: output with no timeouts still parses correctly (lost stays 0).

    Given probe output containing only successful RTT records
    When the output is parsed
    Then lost == 0 and every record survives into samples.
    """
    lines = [
        _probe_line(start_t=1.0, t=1.001, rtt_ms=1.0),
        _probe_line(start_t=1.1, t=1.102, rtt_ms=2.2),
        _probe_line(start_t=1.2, t=1.204, rtt_ms=0.4),
    ]
    parsed = _parse_tcp_probe_output("\n".join(lines))

    assert parsed.lost == 0, f"expected lost=0 (no timeout records present) but got lost={parsed.lost}"
    assert len(parsed.samples) == 3, f"expected all 3 records kept as samples but got {len(parsed.samples)}"


# --------------------------------------------------------------------------- #
# _compute_pooled_tcp / _compute_pooled_tcp_full — real total_loss/total_sent
# --------------------------------------------------------------------------- #


def test_compute_pooled_tcp_reports_real_loss_from_windows() -> None:
    """Pooled TCP stats surface the windows' real loss tally, not a hardcoded 0.

    Given two per-rep TcpRstWindows: one with 2 samples + 1 loss, one with
      1 sample + 2 losses (mirrors two probe runs pooled together)
    When the pooled stats are computed
    Then total_loss/total_sent reflect the real sums and loss_pct() is the
      honest percentage — never 0.0 just because losses exist.
    """
    parsed_a = _parse_tcp_probe_output(
        "\n".join(
            [
                _probe_line(start_t=0.0, t=0.01, rtt_ms=4.0),
                _probe_line(start_t=0.1, t=0.11, rtt_ms=6.0),
                _probe_line(start_t=0.2, t=5.2, rtt_ms=-1.0),
            ]
        )
    )
    parsed_b = _parse_tcp_probe_output(
        "\n".join(
            [
                _probe_line(start_t=1.0, t=1.02, rtt_ms=3.0),
                _probe_line(start_t=1.1, t=6.1, rtt_ms=-1.0),
                _probe_line(start_t=1.2, t=6.2, rtt_ms=-1.0),
            ]
        )
    )
    window_a = TcpRstWindow(samples=parsed_a.samples, lost=parsed_a.lost)
    window_b = TcpRstWindow(samples=parsed_b.samples, lost=parsed_b.lost)

    ps = _compute_pooled_tcp([window_a, window_b], baseline_windows=[])

    expected_loss = 3  # 1 (window_a) + 2 (window_b)
    expected_sent = 6  # 3 samples + 3 losses total
    assert ps.total_loss == expected_loss, (
        f"expected total_loss={expected_loss} (real per-run tally, not hardcoded 0) but got {ps.total_loss}"
    )
    assert ps.total_sent == expected_sent, f"expected total_sent={expected_sent} but got {ps.total_sent}"
    expected_pct = 100.0 * expected_loss / expected_sent
    assert ps.loss_pct() == expected_pct, (
        f"expected loss_pct()={expected_pct:.2f}% (nonzero — connections genuinely blackholed) "
        f"but got {ps.loss_pct():.2f}%"
    )
    assert ps.loss_pct() > 0.0, "expected a nonzero loss_pct() when the pooled windows contain real losses"


def test_compute_pooled_tcp_zero_loss_still_correct() -> None:
    """Branch coverage: the off side — no losses in any window still reports 0.0% cleanly.

    Given windows built from probe output with zero timeout records
    When the pooled stats are computed
    Then total_loss == 0 and loss_pct() == 0.0 (a real zero, not a masked one).
    """
    parsed = _parse_tcp_probe_output(
        "\n".join(
            [
                _probe_line(start_t=0.0, t=0.01, rtt_ms=4.0),
                _probe_line(start_t=0.1, t=0.11, rtt_ms=6.0),
            ]
        )
    )
    window = TcpRstWindow(samples=parsed.samples, lost=parsed.lost)

    ps = _compute_pooled_tcp([window], baseline_windows=[])

    assert ps.total_loss == 0, f"expected total_loss=0 (no timeouts in input) but got {ps.total_loss}"
    assert ps.total_sent == 2, f"expected total_sent=2 (2 samples, 0 losses) but got {ps.total_sent}"
    assert ps.loss_pct() == 0.0, f"expected loss_pct()=0.0% but got {ps.loss_pct():.2f}%"


def test_compute_pooled_tcp_full_reports_real_loss_from_windows() -> None:
    """The disruption-bucket pooling path (_compute_pooled_tcp_full) also gets real loss.

    Given a during-op window with 2 samples + 2 losses
    When the full-pooled disruption stats are computed
    Then total_loss/total_sent are real (this is the second of the three sites
      that hardcoded total_loss=0 before the fix) and loss_pct() > 0.
    """
    parsed = _parse_tcp_probe_output(
        "\n".join(
            [
                _probe_line(start_t=0.0, t=0.01, rtt_ms=10.0),
                _probe_line(start_t=0.1, t=0.11, rtt_ms=20.0),
                _probe_line(start_t=0.2, t=5.2, rtt_ms=-1.0),
                _probe_line(start_t=0.3, t=5.3, rtt_ms=-1.0),
            ]
        )
    )
    window = TcpRstWindow(samples=parsed.samples, lost=parsed.lost)

    ps, _buckets, _spike_thresh = _compute_pooled_tcp_full([window], baseline_windows=[])

    assert ps.total_loss == 2, f"expected total_loss=2 but got {ps.total_loss}"
    assert ps.total_sent == 4, f"expected total_sent=4 (2 samples + 2 losses) but got {ps.total_sent}"
    assert ps.loss_pct() == 50.0, f"expected loss_pct()=50.0% but got {ps.loss_pct():.2f}%"


def test_compute_pooled_tcp_empty_windows_yields_zero_stats() -> None:
    """Edge case pinned alongside the fix: no windows at all still returns a clean zero.

    Given no windows (n == 0 short-circuit path in _compute_pooled_tcp)
    When the pooled stats are computed
    Then a default (all-zero) PooledStats is returned — not an exception.
    """
    ps = _compute_pooled_tcp([], baseline_windows=[])
    assert ps == PooledStats(), f"expected an all-zero PooledStats() for no windows but got {ps}"


def test_compute_pooled_tcp_all_lost_window_reports_full_loss() -> None:
    """A fully blackholed run (only -1 records, zero RTT samples) reports 100% loss.

    This is the n==0-samples branch where the fix changes the early-return's
    output: pre-fix it returned an all-zero PooledStats (loss invisible); now
    the losses ride total_loss/total_sent and loss_pct() reads 100%.
    """
    parsed = _parse_tcp_probe_output(
        "\n".join(
            [
                _probe_line(start_t=0.0, t=5.0, rtt_ms=-1.0),
                _probe_line(start_t=0.1, t=5.1, rtt_ms=-1.0),
            ]
        )
    )
    window = TcpRstWindow(samples=parsed.samples, lost=parsed.lost)

    ps = _compute_pooled_tcp([window], baseline_windows=[])
    assert ps.total_loss == 2, f"expected total_loss=2 (all records timed out) but got {ps.total_loss}"
    assert ps.total_sent == 2, f"expected total_sent=2 but got {ps.total_sent}"
    assert ps.loss_pct() == 100.0, f"expected loss_pct()=100.0% (fully blackholed) but got {ps.loss_pct():.2f}%"

    ps_full, _buckets, _spike = _compute_pooled_tcp_full([window], baseline_windows=[])
    assert ps_full.total_loss == 2, f"full-pooled: expected total_loss=2 but got {ps_full.total_loss}"
    assert ps_full.loss_pct() == 100.0, f"full-pooled: expected 100.0% but got {ps_full.loss_pct():.2f}%"


# --------------------------------------------------------------------------- #
# probe_once — the guest-side except-order (the loss records must be emittable)
# --------------------------------------------------------------------------- #


def _guest_probe_once() -> Any:
    """Materialize the guest script's probe_once by exec'ing _TCP_PROBE_SCRIPT.

    The script is __main__-guarded, so exec with a test __name__ defines its
    functions without running main() — the same code the civm guest executes.
    """
    ns: dict[str, Any] = {"__name__": "tcp_probe_under_test"}
    exec(compile(_TCP_PROBE_SCRIPT, "tcp_rst_probe.py", "exec"), ns)  # noqa: S102
    return ns["probe_once"]


def _run_probe_once_with_connect(raiser: BaseException) -> float:
    """Drive the guest probe_once with asyncio.open_connection raising `raiser`."""
    probe_once = _guest_probe_once()
    real_open = asyncio.open_connection

    async def fake_open(*args: Any, **kwargs: Any) -> Any:
        raise raiser

    async def drive() -> float:
        asyncio.open_connection = fake_open  # type: ignore[assignment]
        try:
            _start, _recv, rtt_ms = await probe_once("192.0.2.1")
            return float(rtt_ms)
        finally:
            asyncio.open_connection = real_open  # type: ignore[assignment]

    return asyncio.run(drive())


def test_probe_once_timeout_yields_loss_record() -> None:
    """A >=5s stall must produce the rtt_ms=-1 LOSS record, not a "valid" RTT sample.

    On Python 3.11+ asyncio.TimeoutError IS the builtin TimeoutError, which
    subclasses OSError — with the OSError clause first (the pre-fix order) the
    timeout was swallowed as a positive ~5000ms RTT and the -1 branch was dead
    code, so no loss could EVER be emitted (the root of the fabricated 0.0
    loss%). Red on the pre-fix order: rtt_ms >= 0 here.
    """
    assert issubclass(asyncio.TimeoutError, OSError), (
        "precondition: on the targeted Python (3.11+) asyncio.TimeoutError is the "
        "builtin TimeoutError and subclasses OSError — the except-order trap this pins"
    )
    rtt_ms = _run_probe_once_with_connect(asyncio.TimeoutError())
    assert rtt_ms == -1.0, (
        f"expected rtt_ms=-1.0 (timeout recorded as a LOSS) but got {rtt_ms} — "
        "the timeout was caught by the OSError clause and recorded as a valid RTT sample"
    )


def test_probe_once_refused_yields_rtt_sample() -> None:
    """Branch pair: a fast RST/ECONNREFUSED is a genuine RTT sample, never a loss.

    The RST-reject rules make refused connections the MEASURED behaviour — the
    refusal time IS the RTT the bench characterizes.
    """
    rtt_ms = _run_probe_once_with_connect(ConnectionRefusedError())
    assert rtt_ms >= 0.0, (
        f"expected a non-negative RTT for a refused (RST) connection but got {rtt_ms} — "
        "a refusal must never be tallied as a >=5s loss"
    )
