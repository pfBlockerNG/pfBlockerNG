"""ADR-60 Phase 1 pinned make_timestamp()'s old (no-year) output shape as the
"before" oracle for Phase 4's red->green proof. Phase 4 has since flipped
make_timestamp() itself to the shared ISO-8601 'YYYY-MM-DD HH:MM:SS' shape
(the last of the 10 log types to convert) and deleted the separate unwired
iso_timestamp() helper Phase 1 added beside it -- one canonical timestamp
function, not two.
"""

from __future__ import annotations

import re

import pytest

import pfb_unbound


def test_make_timestamp_matches_iso8601_format() -> None:
    """ADR-60 P4: dnslog/dnsreplylog now get the same 'YYYY-MM-DD HH:MM:SS' shape
    as every other log type -- year present, unambiguous.
    """
    result = pfb_unbound.make_timestamp()

    assert re.match(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$", result), result


def test_make_timestamp_returns_empty_string_after_two_type_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    """§1.3: a real code path -- '%Y'/'%d'/etc. raising TypeError twice falls back to
    "" (the ``for _ in range(2)`` loop shape), never propagating the exception. The
    format string changed (ADR-60 P4); this fallback shape did not.
    """

    class _RaisingNow:
        def strftime(self, _fmt: str) -> str:
            raise TypeError("simulated strftime failure")

    class _FakeDatetime:
        @staticmethod
        def now() -> _RaisingNow:
            return _RaisingNow()

    monkeypatch.setattr(pfb_unbound, "datetime", _FakeDatetime)

    assert pfb_unbound.make_timestamp() == ""
