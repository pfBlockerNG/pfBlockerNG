"""ADR-60 Phase 1 -- pins make_timestamp()'s current (no-year) output shape and its
"" fallback as the "before" oracle for Phase 4's red->green proof. No production
behaviour changes in this phase; also exercises the new (unwired) iso_timestamp()
helper Phase 4 will call.
"""

from __future__ import annotations

import re

import pytest

import pfb_unbound


def test_make_timestamp_matches_no_year_format() -> None:
    """§1.3: dnslog/dnsreplylog get make_timestamp()'s '%b %-d %H:%M:%S' -- no year."""
    result = pfb_unbound.make_timestamp()

    assert re.match(r"^[A-Za-z]{3} +\d{1,2} \d{2}:\d{2}:\d{2}$", result), result
    assert not re.search(r"\d{4}", result), f"make_timestamp() must carry no year, got: {result}"


def test_make_timestamp_returns_empty_string_after_two_type_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    """§1.3: a real code path -- '%-d' raising TypeError twice falls back to "" (the
    ``for _ in range(2)`` loop shape), never propagating the exception.
    """

    class _RaisingNow:
        def strftime(self, _fmt: str) -> str:
            raise TypeError("simulated strftime '%-d' failure")

    class _FakeDatetime:
        @staticmethod
        def now() -> _RaisingNow:
            return _RaisingNow()

    monkeypatch.setattr(pfb_unbound, "datetime", _FakeDatetime)

    assert pfb_unbound.make_timestamp() == ""


def test_iso_timestamp_matches_iso8601_format() -> None:
    """The new (unwired) iso_timestamp() helper Phases 2-4 will call: same shape as
    make_timestamp() but 'YYYY-MM-DD HH:MM:SS'.
    """
    result = pfb_unbound.iso_timestamp()

    assert re.match(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$", result), result
