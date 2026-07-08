"""ADR-60 P10: init_standard()'s unwritable-log rename filename (pfb_unbound.py:893,
898 -- the ownership-repair path that renames dnsbl.log/dns_reply.log/unified.log
aside when they are not writable) used ``strftime("_%Y%m%-d%H%M%S.log")``. ``%-d``
(no leading zero) makes the filename VARIABLE-width across single-vs-double-digit
days -- not lexically sortable. Both call sites now use ``%Y%m%d`` (fixed-width).

Not directly callable: the rename lives inline in ``init_standard()``, which needs a
live Unbound ``env``/``id`` and is not driveable off-appliance. Pinned via a source
tripwire (goes red if the format string drifts again) plus a reproduction of the
exact ``strftime()`` call at a controlled instant, mirroring the PHP debug-filename
site's equivalent proof (TimestampCosmeticNormalizationTest.php).
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

_PFB_UNBOUND_PY = Path(__file__).resolve().parent.parent / "src/usr/local/pkg/pfblockerng/pfb_unbound.py"


def test_source_uses_fixed_width_format_at_both_call_sites() -> None:
    source = _PFB_UNBOUND_PY.read_text()

    assert source.count('str(datetime.now().strftime("_%Y%m%d%H%M%S.log"))') == 2, (
        "expected exactly 2 fixed-width rename-filename call sites; update this oracle if the count changed"
    )
    assert "%-d" not in source, "the OLD variable-width '%-d' day format must be gone"


def test_new_format_is_fixed_width_for_single_and_double_digit_days() -> None:
    single_digit_day = datetime(2026, 3, 4, 9, 5, 3).strftime("_%Y%m%d%H%M%S.log")
    double_digit_day = datetime(2026, 3, 14, 9, 5, 3).strftime("_%Y%m%d%H%M%S.log")

    assert single_digit_day == "_20260304090503.log"
    assert double_digit_day == "_20260314090503.log"
    assert len(single_digit_day) == len(double_digit_day), (
        "the rename filename must be fixed-width regardless of day-of-month"
    )


def test_old_format_was_variable_width_for_single_vs_double_digit_days() -> None:
    """Red-proof characterization: the OLD '%-d' format really did vary in width."""
    old_single_digit_day = datetime(2026, 3, 4, 9, 5, 3).strftime("_%Y%m%-d%H%M%S.log")
    old_double_digit_day = datetime(2026, 3, 14, 9, 5, 3).strftime("_%Y%m%-d%H%M%S.log")

    assert len(old_single_digit_day) != len(old_double_digit_day), "sanity: the OLD format really was variable-width"
