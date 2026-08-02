"""Regression coverage for ADR-10 torn-scan diagnostics."""

from __future__ import annotations

from tests import test_adr10_concurrency as concurrency


def test_torn_sample_reports_divergence_from_each_complete_generation() -> None:
    expected_gen1 = {
        "block.gen1.example": True,
        "allow.gen1.example": False,
        "block.gen2.example": True,
        "allow.gen2.example": False,
        "control.example": True,
    }
    expected_gen2 = {
        "block.gen1.example": False,
        "allow.gen1.example": True,
        "block.gen2.example": False,
        "allow.gen2.example": True,
        "control.example": True,
    }
    got = {
        "block.gen1.example": True,
        "allow.gen1.example": False,
        "block.gen2.example": False,
        "allow.gen2.example": True,
        "control.example": True,
    }

    assert got["block.gen1.example"] is True
    assert got["allow.gen1.example"] is False
    assert got["block.gen2.example"] is False
    assert got["allow.gen2.example"] is True
    assert got["control.example"] is True
    assert concurrency._torn_sample(got, expected_gen1, expected_gen2) == {
        "not_gen1": {"block.gen2.example": False, "allow.gen2.example": True},
        "not_gen2": {"block.gen1.example": True, "allow.gen1.example": False},
    }
