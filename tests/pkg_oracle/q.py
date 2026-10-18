#!/usr/bin/env python3
"""q.py <server> <name>: one UDP A query; prints the answer address or the failure."""

import socket
import struct
import sys

srv, name = sys.argv[1], sys.argv[2]
labels = b"".join(bytes([len(p)]) + p.encode() for p in name.rstrip(".").split("."))
q = struct.pack("!HHHHHH", 0x4242, 0x0100, 1, 0, 0, 0) + labels + b"\0" + struct.pack("!HH", 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2.0)
try:
    s.sendto(q, (srv, 53))
    d = s.recvfrom(512)[0]
    rc = d[3] & 15
    an = struct.unpack("!H", d[6:8])[0]
    last4 = ".".join(str(b) for b in d[-4:]) if an else "-"
    print(f"ANSWERED rcode={rc} answers={an} last4={last4}")
except OSError as e:
    print(f"NO ANSWER ({e.__class__.__name__})")
