"""``_dnsbl_is_numeric_host()``: Python shape twin of PHP ``pfb_ipv4_numeric_host()``.

A name a client parses as an IPv4 literal ('0xc0.0xa8.0x1.0x64', '192.168.356') is never a
domain; the PHP side decodes it. Both halves read tests/fixtures/ipv4_numeric_host.json, so a
drift in either classifier fails here or in tests/php/Ipv4NumericHostTest.php.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import pfb_unbound as P

_TABLE = json.loads((Path(__file__).parent / "fixtures" / "ipv4_numeric_host.json").read_text())["cases"]


@pytest.mark.parametrize(("host", "expected"), _TABLE, ids=[repr(c[0]) for c in _TABLE])
def test_shape_matches_shared_table(host: str, expected: str | bool | None) -> None:
    want = expected is not None
    assert P._dnsbl_is_numeric_host(host) is want, f"host {host!r}: expected {want}, PHP result {expected!r}"
