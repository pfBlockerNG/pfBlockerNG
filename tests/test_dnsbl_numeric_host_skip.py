"""Numeric IPv4 spellings are never DNSBL domain rules on the Python side.

A client parses '0xc0.0xa8.0x1.0x64' or '192.168.356' as an IPv4 literal and never sends a DNS
query for it, so a domain rule for it blocks nothing. PHP decodes these hosts to the firewall path
(tests/php/DnsblNumericHostTest.php); Python must skip an ABP/hosts anchor of that shape silently,
exactly like a dotted-quad anchor (no double-handling, no shape tally), and ``_normalise_verdict()``
rejects the shape for every other caller.
"""

from __future__ import annotations

import pytest

import pfb_unbound as P


@pytest.mark.parametrize(
    "line",
    [
        "||0xC0A80164^",
        "||0xc0.0xa8.0x1.0x64^",
        "||192.168.356^$important",
        "||3232235876^",
        "||08.08.08.08^",
        "@@||0xC0A80164^",
        "0.0.0.0 0xc0.0xa8.0x1.0x64",
        "0.0.0.0 192.168.356",
    ],
)
def test_numeric_anchor_is_skipped_without_a_tally(line: str) -> None:
    tally: dict = {}
    assert P.parse_abp(line, feed="f", group="g", tally=tally) is None, line
    assert tally == {}, f"{line}: numeric anchors are PHP-owned and must not count as shape rejects, got {tally}"


@pytest.mark.parametrize("name", ["0xc0.0xa8.0x1.0x64", "0300.0250.01.0144", "192.168.356", "192.168.01.100", "a.0x1"])
def test_normalise_rejects_numeric_names_as_shape(name: str) -> None:
    assert P._normalise_verdict(name) == (None, "shape"), name
    assert P.normalise(name) is None, name


@pytest.mark.parametrize("name", ["1.2.example.com", "example.com", "0xg.com"])
def test_names_with_an_alphabetic_last_label_still_normalise(name: str) -> None:
    assert P.normalise(name) == name


def test_domain_anchor_still_parses() -> None:
    assert P.parse_abp("||1.2.example.com^") is not None
