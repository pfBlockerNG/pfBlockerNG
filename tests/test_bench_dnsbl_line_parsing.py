"""Benchmark fixture pins the compact DNSBL interchange shape."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "bench_dnsbl_line_parsing.py"
_SPEC = importlib.util.spec_from_file_location("bench_dnsbl_line_parsing", _SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
_BENCH = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _BENCH
_SPEC.loader.exec_module(_BENCH)


def test_txt_line_uses_compact_domain_shape() -> None:
    assert _BENCH._txt_line(0) == '["d","uuid-bench-0.example.com"]\n'


def test_txt_line_uses_compact_abp_shapes() -> None:
    assert _BENCH._txt_line(97) == '["a","||uuid-bench-97.example.com^"]\n'
    assert _BENCH._txt_line(99) == '["a","@@||uuid-bench-99.example.com^"]\n'


def _trial(raw_line_count: int | None) -> object:
    return _BENCH.TrialResult(
        isolated_median_s=1.0,
        isolated_min_s=0.9,
        isolated_max_s=1.1,
        peak_rss_bytes=1024,
        raw_line_count=raw_line_count,
    )


def test_php_trial_aggregation_rejects_dropped_rows() -> None:
    with pytest.raises(RuntimeError, match=r"expected 1,000,000.*999,999"):
        _BENCH.aggregate_trials([_trial(1_000_000), _trial(999_999)], expected_raw_line_count=1_000_000)
    with pytest.raises(RuntimeError, match=r"expected 1,000,000.*missing"):
        _BENCH.aggregate_trials([_trial(1_000_000), _trial(None)], expected_raw_line_count=1_000_000)


def test_timing_only_base_preserves_its_consistent_observed_count() -> None:
    result = _BENCH.aggregate_trials([_trial(2_000_000), _trial(2_000_000)])

    assert result.raw_line_count == 2_000_000


def test_report_exposes_validated_raw_line_count(capsys: pytest.CaptureFixture[str]) -> None:
    php = {"base": _trial(1_000_000), "branch": _trial(1_000_000)}
    python = {
        "base": _BENCH.TrialResult(1.0, 0.9, 1.1, 1024),
        "branch": _BENCH.TrialResult(1.0, 0.9, 1.1, 1024),
    }

    assert _BENCH.report(php, python, 25.0)
    assert "raw_lines=1,000,000" in capsys.readouterr().out
