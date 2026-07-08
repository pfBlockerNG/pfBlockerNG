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
    DualPathSample,
    DualPathStats,
    PooledStats,
    TcpRstWindow,
    _compute_disrupt_buckets,
    _compute_pooled_tcp,
    _compute_pooled_tcp_full,
    _dualpath_stats,
    _parse_dualpath_probe_output,
    _parse_tcp_probe_output,
    _slice_to_window,
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


# --------------------------------------------------------------------------- #
# issue #584 Step 1 — dual-path (allowed vs blocked) full-lifecycle bench:
# _parse_dualpath_probe_output / _dualpath_stats / _slice_to_window
# --------------------------------------------------------------------------- #


def _dp_line(label: str, start: float, end: float, outcome: str) -> str:
    """Build one line in the exact shape the dual-path probe emits on the guest."""
    return f"S {label} {start:.4f} {end:.4f} {outcome}"


# ---- _parse_dualpath_probe_output -------------------------------------------


def test_parse_dualpath_well_formed_multi_label_produces_correct_samples() -> None:
    """Well-formed multi-label output parses into the right per-label samples.

    Given output with samples for two different labels (flip, ctrl)
    When the output is parsed
    Then each sample keeps its own label/start/end/outcome, in order, and
      parse_errors stays 0.
    """
    text = "\n".join(
        [
            _dp_line("flip", 100.0, 100.010, "ok"),
            _dp_line("ctrl", 100.1, 100.104, "ok"),
            _dp_line("flip", 100.2, 100.201, "refused"),
        ]
    )

    parsed = _parse_dualpath_probe_output(text)

    assert parsed.parse_errors == 0, f"expected 0 parse errors on well-formed input but got {parsed.parse_errors}"
    assert len(parsed.samples) == 3, f"expected 3 samples but got {len(parsed.samples)}: {parsed.samples}"
    assert [s.label for s in parsed.samples] == ["flip", "ctrl", "flip"], (
        f"expected labels in order [flip, ctrl, flip] but got {[s.label for s in parsed.samples]}"
    )
    assert [s.outcome for s in parsed.samples] == ["ok", "ok", "refused"], (
        f"expected outcomes [ok, ok, refused] but got {[s.outcome for s in parsed.samples]}"
    )
    assert parsed.samples[0].start_epoch == 100.0 and parsed.samples[0].end_epoch == 100.010, (
        f"expected the first sample's epoch pair (100.0, 100.010) but got "
        f"({parsed.samples[0].start_epoch}, {parsed.samples[0].end_epoch})"
    )


def test_parse_dualpath_empty_text_yields_empty_samples_and_zero_errors() -> None:
    """Empty input is valid (not an error) — empty samples, zero parse_errors.

    Given an empty string (no probe output at all)
    When it is parsed
    Then samples is empty and parse_errors is 0 — never an exception.
    """
    parsed = _parse_dualpath_probe_output("")

    assert parsed.samples == [], f"expected no samples for empty input but got {parsed.samples}"
    assert parsed.parse_errors == 0, f"expected 0 parse errors for empty input but got {parsed.parse_errors}"


def test_parse_dualpath_malformed_line_counts_as_parse_error_not_dropped_silently() -> None:
    """A malformed line (wrong field count) increments parse_errors, never silently vanishes.

    Given one well-formed line and one malformed line (missing the outcome field)
    When the output is parsed
    Then the well-formed line survives as a sample, the malformed line is
      counted in parse_errors (not just dropped with no trace), and the EOF
      trailer line is recognized and ignored (no penalty).
    """
    text = "\n".join(
        [
            _dp_line("flip", 1.0, 1.005, "ok"),
            "S ctrl 2.0 2.001",  # missing the outcome field — 4 tokens, not 5
            "EOF n=2",
        ]
    )

    parsed = _parse_dualpath_probe_output(text)

    assert parsed.parse_errors == 1, f"expected 1 parse error (the malformed line) but got {parsed.parse_errors}"
    assert len(parsed.samples) == 1, f"expected 1 surviving sample but got {len(parsed.samples)}: {parsed.samples}"
    assert parsed.samples[0].label == "flip", (
        f"expected the surviving sample's label 'flip' but got {parsed.samples[0].label}"
    )


def test_parse_dualpath_truncated_final_line_counts_as_parse_error() -> None:
    """A truncated final line (SSH output cut mid-write) is a parse error, not silently dropped.

    Given a well-formed first line and a truncated final line with only 3 of
      the 5 expected tokens (as if the SSH transport cut the connection mid-print)
    When the output is parsed
    Then the truncation is counted in parse_errors and never becomes a fabricated sample.
    """
    text = "\n".join(
        [
            _dp_line("ctrl", 5.0, 5.002, "ok"),
            "S flip 6.0",  # truncated: only 3 tokens
        ]
    )

    parsed = _parse_dualpath_probe_output(text)

    assert parsed.parse_errors == 1, f"expected 1 parse error (the truncated line) but got {parsed.parse_errors}"
    assert len(parsed.samples) == 1, f"expected 1 surviving sample but got {len(parsed.samples)}: {parsed.samples}"


def test_parse_dualpath_end_before_start_is_flagged_as_parse_error() -> None:
    """A sample whose end_epoch < start_epoch is impossible and must be flagged.

    Given a line where the end timestamp precedes the start timestamp (clock
      skew / corrupted line)
    When the output is parsed
    Then it is counted in parse_errors and excluded from samples — never
      silently accepted as a negative-duration sample.
    """
    text = "\n".join(
        [
            _dp_line("flip", 10.0, 9.5, "ok"),  # end < start
            _dp_line("ctrl", 20.0, 20.010, "ok"),
        ]
    )

    parsed = _parse_dualpath_probe_output(text)

    assert parsed.parse_errors == 1, f"expected 1 parse error (end<start) but got {parsed.parse_errors}"
    assert len(parsed.samples) == 1, f"expected 1 surviving sample but got {len(parsed.samples)}: {parsed.samples}"
    assert parsed.samples[0].label == "ctrl", (
        f"expected the surviving sample's label 'ctrl' but got {parsed.samples[0].label}"
    )


def test_parse_dualpath_unknown_outcome_token_is_parse_error() -> None:
    """An outcome token outside {ok,bad_echo,refused,timeout,error} is a parse error.

    Given a line whose outcome field is a token the probe script never emits
      (a corrupted/foreign line)
    When the output is parsed
    Then it is counted in parse_errors and excluded from samples.
    """
    text = _dp_line("flip", 1.0, 1.001, "mystery")

    parsed = _parse_dualpath_probe_output(text)

    assert parsed.parse_errors == 1, f"expected 1 parse error (unknown outcome token) but got {parsed.parse_errors}"
    assert parsed.samples == [], f"expected no samples for an unknown-outcome line but got {parsed.samples}"


# ---- _dualpath_stats ---------------------------------------------------------


def test_dualpath_stats_mixed_outcomes_counted_correctly() -> None:
    """Every outcome bucket is counted independently — branch coverage for all five.

    Given one sample of each outcome (ok, bad_echo, refused, timeout, error)
    When stats are computed
    Then n==5 and each per-outcome count is exactly 1.
    """
    samples = [
        DualPathSample(label="flip", start_epoch=0.0, end_epoch=0.010, outcome="ok"),
        DualPathSample(label="flip", start_epoch=1.0, end_epoch=1.010, outcome="bad_echo"),
        DualPathSample(label="flip", start_epoch=2.0, end_epoch=2.001, outcome="refused"),
        DualPathSample(label="flip", start_epoch=3.0, end_epoch=18.0, outcome="timeout"),
        DualPathSample(label="flip", start_epoch=4.0, end_epoch=4.002, outcome="error"),
    ]

    ps = _dualpath_stats(samples)

    assert ps.n == 5, f"expected n=5 but got {ps.n}"
    assert ps.n_ok == 1, f"expected n_ok=1 but got {ps.n_ok}"
    assert ps.n_bad_echo == 1, f"expected n_bad_echo=1 but got {ps.n_bad_echo}"
    assert ps.n_refused == 1, f"expected n_refused=1 but got {ps.n_refused}"
    assert ps.n_timeout == 1, f"expected n_timeout=1 but got {ps.n_timeout}"
    assert ps.n_error == 1, f"expected n_error=1 but got {ps.n_error}"


def test_dualpath_stats_timeouts_are_censored_out_of_latency_percentiles() -> None:
    """A timeout's huge wall-clock span must NEVER pollute the ok-only latency percentiles.

    Given 2 ok samples (5ms, 15ms) and 3 timeout samples whose end-start span
      is 15000ms (a realistic ``timeout_s`` stall)
    When stats are computed
    Then max_ms comes from the ok samples only (15ms) — never 15000ms — and
      n_timeout records the 3 timeouts separately (counted, not averaged in).
    """
    samples = [
        DualPathSample(label="ctrl", start_epoch=0.0, end_epoch=0.005, outcome="ok"),
        DualPathSample(label="ctrl", start_epoch=1.0, end_epoch=1.015, outcome="ok"),
        DualPathSample(label="ctrl", start_epoch=2.0, end_epoch=17.0, outcome="timeout"),
        DualPathSample(label="ctrl", start_epoch=3.0, end_epoch=18.0, outcome="timeout"),
        DualPathSample(label="ctrl", start_epoch=4.0, end_epoch=19.0, outcome="timeout"),
    ]

    ps = _dualpath_stats(samples)

    assert ps.n_ok == 2, f"expected n_ok=2 but got {ps.n_ok}"
    assert ps.n_timeout == 3, f"expected n_timeout=3 but got {ps.n_timeout}"
    # round() absorbs float (end-start)*1000 representation error (e.g. 1.015-1.0 -> 14.999999999999902).
    assert round(ps.max_ms, 3) == 15.0, (
        f"expected max_ms≈15.0 (the ok-only max) but got {ps.max_ms} — a timeout leaked into latency"
    )
    assert ps.p99_ms <= 15.0 + 1e-6, (
        f"expected p99_ms<=15.0 (ok-only) but got {ps.p99_ms} — a timeout leaked into latency"
    )


def test_dualpath_stats_n_ok_zero_returns_explicit_zero_stats_no_exception() -> None:
    """An empty ok-set (everything refused/timeout) returns a clean zero, never crashes.

    Given samples where none has outcome=='ok' (a fully blocked cell)
    When stats are computed
    Then n_ok==0 and every latency figure is an explicit 0.0 — no
      ZeroDivisionError / IndexError, and the outcome counts are still real.
    """
    samples = [
        DualPathSample(label="flip", start_epoch=0.0, end_epoch=0.001, outcome="refused"),
        DualPathSample(label="flip", start_epoch=1.0, end_epoch=1.001, outcome="refused"),
        DualPathSample(label="flip", start_epoch=2.0, end_epoch=17.0, outcome="timeout"),
    ]

    ps = _dualpath_stats(samples)

    assert ps.n_ok == 0, f"expected n_ok=0 but got {ps.n_ok}"
    assert ps.n == 3, f"expected n=3 but got {ps.n}"
    assert ps.n_refused == 2, f"expected n_refused=2 but got {ps.n_refused}"
    assert ps.n_timeout == 1, f"expected n_timeout=1 but got {ps.n_timeout}"
    assert ps.p50_ms == 0.0, f"expected p50_ms=0.0 (explicit zero, empty ok-set) but got {ps.p50_ms}"
    assert ps.p95_ms == 0.0, f"expected p95_ms=0.0 but got {ps.p95_ms}"
    assert ps.p99_ms == 0.0, f"expected p99_ms=0.0 but got {ps.p99_ms}"
    assert ps.max_ms == 0.0, f"expected max_ms=0.0 but got {ps.max_ms}"


def test_dualpath_stats_empty_input_returns_explicit_zero_stats() -> None:
    """Branch pair to the above: an entirely empty sample list is also a clean zero, not a crash."""
    ps = _dualpath_stats([])

    expected = DualPathStats(buckets=_compute_disrupt_buckets([]))
    assert ps == expected, f"expected an all-zero DualPathStats() (zeroed buckets) for no samples but got {ps}"


def test_dualpath_stats_bucket_counts_exact_on_hand_built_distribution() -> None:
    """Disruption bucket counts (>50/100/250/500ms) are exact on a known distribution.

    Given 5 ok samples with durations [10, 60, 120, 300, 600] ms
    When stats are computed
    Then each bucket's count matches hand-computed values exactly:
      >50ms: 4 (60,120,300,600)   >100ms: 3 (120,300,600)
      >250ms: 2 (300,600)         >500ms: 1 (600)
    """
    durations_ms = [10.0, 60.0, 120.0, 300.0, 600.0]
    samples = [
        DualPathSample(label="flip", start_epoch=float(i), end_epoch=float(i) + d / 1000.0, outcome="ok")
        for i, d in enumerate(durations_ms)
    ]

    ps = _dualpath_stats(samples)

    expected = {50: 4, 100: 3, 250: 2, 500: 1}
    for threshold, expected_count in expected.items():
        actual_count, _pct = ps.buckets[threshold]
        assert actual_count == expected_count, (
            f"bucket >{threshold}ms: expected count={expected_count} but got {actual_count} (full buckets={ps.buckets})"
        )


# ---- _slice_to_window ---------------------------------------------------------


def test_slice_to_window_boundary_inclusive_both_ends() -> None:
    """A sample whose start_epoch lands EXACTLY on t0 or t1 is included (inclusive bounds).

    Given samples at start_epoch 5.0 (before), 10.0 (== t0), 20.0 (== t1), and
      25.0 (after), windowed to [10.0, 20.0]
    When sliced
    Then exactly the 10.0 and 20.0 samples survive — the boundary values are
      IN, not excluded by an off-by-one.
    """
    samples = [
        DualPathSample(label="x", start_epoch=5.0, end_epoch=5.001, outcome="ok"),
        DualPathSample(label="x", start_epoch=10.0, end_epoch=10.001, outcome="ok"),
        DualPathSample(label="x", start_epoch=20.0, end_epoch=20.001, outcome="ok"),
        DualPathSample(label="x", start_epoch=25.0, end_epoch=25.001, outcome="ok"),
    ]

    window = _slice_to_window(samples, 10.0, 20.0)

    assert [s.start_epoch for s in window] == [10.0, 20.0], (
        f"expected start_epoch values [10.0, 20.0] (inclusive boundaries) but got {[s.start_epoch for s in window]}"
    )


def test_slice_to_window_excludes_samples_outside_the_window() -> None:
    """Branch pair to the boundary test: samples clearly outside [t0, t1] are excluded.

    Given samples well before and well after the window
    When sliced
    Then neither survives.
    """
    samples = [
        DualPathSample(label="x", start_epoch=1.0, end_epoch=1.001, outcome="ok"),
        DualPathSample(label="x", start_epoch=99.0, end_epoch=99.001, outcome="ok"),
    ]

    window = _slice_to_window(samples, 10.0, 20.0)

    assert window == [], f"expected an empty window (both samples outside [10.0, 20.0]) but got {window}"


def test_slice_to_window_empty_input_returns_empty_list() -> None:
    """An empty sample list slices to an empty window — never an exception."""
    assert _slice_to_window([], 0.0, 100.0) == [], "expected [] for an empty input sample list"


def test_dualpath_server_carries_a_timeout_mark_above_the_global_cap() -> None:
    """The dual-path bench test MUST carry a @pytest.mark.timeout override.

    The pyproject addopts set a 30s global pytest-timeout budget. Local bench
    runs always pass --override-ini="addopts=" (which drops it), but a CI
    dispatch does not — issue #584 dispatch run 28906541336 was killed at 30s
    mid-first-probe because the mark was missing. This pins the mark so it
    cannot silently regress.
    """
    from tests.smoke.test_bench_pfctl import test_pfctl_dualpath_server

    marks = getattr(test_pfctl_dualpath_server, "pytestmark", [])
    timeouts = [m for m in marks if m.name == "timeout"]
    assert timeouts, f"expected a @pytest.mark.timeout on test_pfctl_dualpath_server, marks={[m.name for m in marks]}"
    budget = timeouts[0].args[0]
    assert budget >= 600, f"expected a timeout budget >= 600s (full dual-path matrix), got {budget}"
