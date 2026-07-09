"""issue #1071: a feed line with a non-decimal Unicode digit must not abort the DNSBL build.

``_dnsbl_is_ipv4`` guards ``int()`` behind ``str.isdigit()``, but ``str.isdigit()`` is True
for non-decimal Unicode digits (superscripts, circled digits) that ``int()`` then rejects
with ``ValueError`` -- and True for non-ASCII decimal digits (Arabic-Indic) that ``int()``
accepts, wrongly recognising them as an IPv4 literal. Feeds are decoded UTF-8
(``errors='replace'``), so such a code point reaches the parser intact; before the fix the
``ValueError`` unwound ``build()``'s per-line loop and discarded every feed. These pin the
recogniser to ASCII-decimal-only semantics: it returns False (never raises) for any
non-ASCII-digit octet, while genuine IPv4 recognition is unchanged.
"""

from __future__ import annotations

import pytest

import pfb_unbound


@pytest.mark.parametrize(
    "token",
    [
        "1.1.1.²",  # superscript two: isdigit() True, int() raises ValueError (the report)
        "².².².²",
        "1.1.1.②",  # circled digit two: isdigit() True, int() raises ValueError
        "١.١.١.١",  # Arabic-Indic one: isdigit() True, int() == 1 (wrongly True before)
    ],
)
def test_non_ascii_digit_octet_rejected_not_raised(token: str) -> None:
    # Before the fix the superscript/circled cases raised ValueError inside build()'s
    # per-line loop (aborting the entire manifest build) and the Arabic-Indic case was
    # wrongly accepted as an IPv4 literal. All must now be a plain "not an IPv4 literal".
    assert pfb_unbound._dnsbl_is_ipv4(token) is False


@pytest.mark.parametrize(
    ("token", "expected"),
    [
        ("1.1.1.1", True),
        ("255.255.255.255", True),
        ("0.0.0.0", True),
        ("192.168.0.1", True),
        ("1.1.1.256", False),  # octet out of range
        ("01.1.1.1", False),  # leading zero
        ("1.1.1", False),  # too few octets
        ("1.1.1.1.1", False),  # too many octets
        ("1.1.1.", False),  # empty octet
        ("a.b.c.d", False),
    ],
)
def test_ascii_ipv4_recognition_unchanged(token: str, expected: bool) -> None:
    assert pfb_unbound._dnsbl_is_ipv4(token) is expected
