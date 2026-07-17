"""Benchmark fixture pins the compact DNSBL interchange shape."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

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
