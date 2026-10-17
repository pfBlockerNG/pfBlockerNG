"""proxyv2.header against hand-computed byte vectors (spec: haproxy proxy-protocol.txt, section 2.2)."""

from __future__ import annotations

import proxyv2
import pytest

SIGNATURE = bytes.fromhex("0d0a0d0a000d0a515549540a")

# signature | 0x21 (v2, PROXY) | family+protocol | length | src addr | dst addr | src port | dst port
IPV4_UDP = SIGNATURE + bytes.fromhex("2112000cc000020ac0000201d4310035")
IPV4_TCP = SIGNATURE + bytes.fromhex("2111000ccb007105c63364019c400035")
IPV6_UDP = SIGNATURE + bytes.fromhex("2122002420010db800000000000000000000000120010db800000000000000000000005314e90035")
IPV6_TCP = SIGNATURE + bytes.fromhex("2121002420010db800000000000000000000000120010db80000000000000000000000539c400035")


def test_signature_constant() -> None:
    assert proxyv2.SIGNATURE == SIGNATURE


def test_ipv4_udp() -> None:
    assert proxyv2.header(("192.0.2.10", 54321), ("192.0.2.1", 53), tcp=False) == IPV4_UDP


def test_ipv4_tcp() -> None:
    assert proxyv2.header(("203.0.113.5", 40000), ("198.51.100.1", 53), tcp=True) == IPV4_TCP


def test_ipv6_udp() -> None:
    assert proxyv2.header(("2001:db8::1", 5353), ("2001:db8::53", 53), tcp=False) == IPV6_UDP


def test_ipv6_tcp() -> None:
    assert proxyv2.header(("2001:db8::1", 40000), ("2001:db8::53", 53), tcp=True) == IPV6_TCP


def test_length_field_counts_everything_after_the_fixed_16_bytes() -> None:
    for header in (IPV4_UDP, IPV6_TCP):
        assert int.from_bytes(header[14:16], "big") == len(header) - 16
    assert proxyv2.header(("192.0.2.10", 1), ("192.0.2.1", 53), tcp=False)[14:16] == b"\x00\x0c"


def test_mixed_address_families_are_rejected() -> None:
    with pytest.raises(ValueError, match="family"):
        proxyv2.header(("192.0.2.10", 1), ("2001:db8::53", 53), tcp=False)


def test_non_address_host_is_rejected() -> None:
    with pytest.raises(ValueError):
        proxyv2.header(("not-an-ip", 1), ("192.0.2.1", 53), tcp=False)
