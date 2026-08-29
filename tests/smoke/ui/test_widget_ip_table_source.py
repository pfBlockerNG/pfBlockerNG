"""Tier-A ``ui_render`` markers for the widget IP-table rewrite (issue #2645).

``pfblockerng.widget.php`` is not require()-able off-appliance, and the live
GET in ``test_render_smoke.py``'s PAGE_TABLE cannot fail if count/update/
pfctlerr go back to per-alias grep/Tshow. This is a **source-text pin**:
it catches a revert of those call sites, not the same calls moved into
unreachable code. No VM: same shape as ``test_render_oracle.py``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytestmark = pytest.mark.ui_render

_WIDGET = Path(__file__).resolve().parents[3] / "src/usr/local/www/widgets/widgets/pfblockerng.widget.php"


def _src() -> str:
    text = _WIDGET.read_text(encoding="utf-8")
    assert text, f"empty widget source at {_WIDGET}"
    return text


def test_widget_ip_table_uses_single_pfctl_tables_parse() -> None:
    src = _src()
    assert "pfb_pfctl_tables_parse(pfb_pfctl_tables_raw())" in src, (
        "IP table must parse one pfctl -vvsTables dump, not per-alias execs"
    )
    assert "pfb_widget_alias_display_count(" in src
    assert "pfb_placeholder_for_family(" in src
    assert "pfb_file_mtime(" in src
    assert "$pfb['pfctlerr']" in src


def test_widget_ip_table_does_not_reintroduce_per_alias_execs() -> None:
    src = _src()
    assert "grep -cv" not in src
    assert "-Tshow" not in src
    assert "filemtime($alias_file)" not in src
