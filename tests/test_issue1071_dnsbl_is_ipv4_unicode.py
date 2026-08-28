"""issue #1071: a feed line with a non-decimal Unicode digit must not abort the DNSBL build.

``_dnsbl_is_ipv4`` guards ``int()`` behind ``str.isdigit()``, but ``str.isdigit()`` is True
for non-decimal Unicode digits (superscripts, circled digits) that ``int()`` then rejects
with ``ValueError`` -- and True for non-ASCII decimal digits (Arabic-Indic) that ``int()``
accepts, wrongly recognising them as an IPv4 literal. Feeds are decoded UTF-8
(``errors='replace'``), so such a code point reaches the parser intact; before the fix the
``ValueError`` unwound ``build()``'s per-line loop and discarded every feed. The same
abort also fired for an all-ASCII octet longer than CPython's int-conversion limit
(``sys.get_int_max_str_digits()``, 4300 by default on 3.11+), so the recogniser also caps
octet length before ``int()``. These pin the recogniser to ASCII-decimal, length-bounded
semantics: it returns False (never raises) for any such octet, while genuine IPv4
recognition is unchanged.
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
        "1².1.1.1",  # mixed ASCII + non-ASCII digits in one octet
        "１.１.１.１",  # full-width digits: isdigit() True, int() == 1
    ],
)
def test_non_ascii_digit_octet_rejected_not_raised(token: str) -> None:
    # Before the fix the superscript/circled cases raised ValueError inside build()'s
    # per-line loop (aborting the entire manifest build) and the Arabic-Indic case was
    # wrongly accepted as an IPv4 literal. All must now be a plain "not an IPv4 literal".
    assert pfb_unbound._dnsbl_is_ipv4(token) is False


@pytest.mark.parametrize(
    "token",
    [
        "1.1.1." + "9" * 4301,  # over CPython's default int-conversion limit (4300)
        "9" * 4301 + ".1.1.1",
        "1.1.1." + "0" * 4301,
    ],
)
def test_oversized_ascii_octet_rejected_not_raised(token: str) -> None:
    # All-ASCII digits pass the isascii/isdigit gate; without the length cap int() raises
    # "Exceeds the limit (4300 digits) for integer string conversion" and aborts build()
    # exactly like the Unicode cases above.
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
        ("+1.1.1.1", False),  # sign prefix: isdigit() False, int() would accept
        ("1.1.1.-1", False),
        ("1.1.1.1000", False),  # 4 digits: len cap and range check agree
    ],
)
def test_ascii_ipv4_recognition_unchanged(token: str, expected: bool) -> None:
    assert pfb_unbound._dnsbl_is_ipv4(token) is expected
