"""ADR-60 Phase 1 pinned make_timestamp()'s old (no-year) output shape as the
"before" oracle for Phase 4's red->green proof. Phase 4 has since flipped
make_timestamp() itself to the shared ISO-8601 'YYYY-MM-DD HH:MM:SS' shape
(the last of the 10 log types to convert) and deleted the separate unwired
iso_timestamp() helper Phase 1 added beside it -- one canonical timestamp
function, not two.
"""

from __future__ import annotations

import re

import pfb_unbound


def test_make_timestamp_matches_iso8601_format() -> None:
    """ADR-60 P4: dnslog/dnsreplylog now get the same 'YYYY-MM-DD HH:MM:SS' shape
    as every other log type -- year present, unambiguous.
    """
    result = pfb_unbound.make_timestamp()

    assert re.match(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$", result), result
