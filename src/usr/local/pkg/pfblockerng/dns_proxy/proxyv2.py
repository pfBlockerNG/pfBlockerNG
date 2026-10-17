"""PROXY protocol v2 header builder (haproxy proxy-protocol.txt, section 2.2): PROXY command, INET/INET6, TCP/UDP."""

from __future__ import annotations

import ipaddress
import struct

SIGNATURE = b"\r\n\r\n\x00\r\nQUIT\n"
_VERSION_PROXY = 0x21  # version 2, command PROXY


def header(src: tuple[str, int], dst: tuple[str, int], *, tcp: bool) -> bytes:
    """Header announcing that `src` (the real client) reached `dst`; both hosts must be the same IP family."""
    src_ip, dst_ip = ipaddress.ip_address(src[0]), ipaddress.ip_address(dst[0])
    if src_ip.version != dst_ip.version:
        raise ValueError(f"address family mismatch: {src_ip} vs {dst_ip}")
    family = 0x10 if src_ip.version == 4 else 0x20
    addresses = src_ip.packed + dst_ip.packed + struct.pack("!HH", src[1], dst[1])
    return SIGNATURE + struct.pack("!BBH", _VERSION_PROXY, family | (0x1 if tcp else 0x2), len(addresses)) + addresses
