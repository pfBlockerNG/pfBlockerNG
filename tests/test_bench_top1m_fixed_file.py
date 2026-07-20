"""Contract checks for the issue #1542 fixed-file benchmark harness."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "bench_top1m_fixed_file.py"
_SPEC = importlib.util.spec_from_file_location("bench_top1m_fixed_file", _SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
_BENCH = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _BENCH
_SPEC.loader.exec_module(_BENCH)


def test_benchmark_default_is_exactly_one_million() -> None:
    assert _BENCH.DEFAULT_LINES == 1_000_000


def test_generated_input_is_bounded_at_one_million() -> None:
    assert _BENCH._line_count("1000000") == 1_000_000
    with pytest.raises(_BENCH.argparse.ArgumentTypeError, match="must not exceed"):
        _BENCH._line_count("1000001")


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
