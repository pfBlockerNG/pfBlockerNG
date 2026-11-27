"""issue #4272: AdGuard's extended cosmetic markers are cosmetic rules.

The capture guard (``_dnsbl_is_abp_rule_line()``, the twin of PHP's
``pfb_dnsbl_is_abp_rule_line()``, pinned to the same rows by
tests/php/DnsblAbpExtendedCosmeticMarkerTest.php) routes them to ``parse_abp()``,
and ``parse_abp()`` skips them, so none becomes a domain block. Before, the AdGuard
Turkish filter's ``eksisozluk.com#$?#...`` reached the plain path, where Lenient cut
``eksisozluk.com`` out of it.
"""

from __future__ import annotations

import pytest

import pfb_unbound as P

COSMETIC = [
    "eksisozluk.com#$?#.ads",
    '#$?#div:has(> a[href*="ads"])',
    "site.com#@$?#.ads",
    "site.com#@?#div:has(.ad)",
    "site.com#@$#body { color: red }",
    "site.com#@%#//scriptlet('abort-on-property-read', 'ads')",
    "a.com,b.com#$?#.ads",
]


@pytest.mark.parametrize("line", COSMETIC)
def test_an_adguard_extended_cosmetic_rule_is_captured_and_never_a_rule(line: str) -> None:
    assert P._dnsbl_is_abp_rule_line(line)
    assert P.parse_abp(line) is None


def test_a_comment_or_a_plain_line_is_not_captured() -> None:
    assert not P._dnsbl_is_abp_rule_line("#$?# comment")
    assert not P._dnsbl_is_abp_rule_line("example.com/path#$?#x")
