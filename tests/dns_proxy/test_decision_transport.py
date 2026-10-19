"""Issue #3517: the decision protocol's QUERY names the client's transport, and the decider holds the answers it builds
itself to a datagram client's UDP size and to nothing for a stream client.

The REAL `pfb_dns_proxy.py --decision-fd` process runs with the shipped pfb_unbound.py (SafeSearch loaded) or with no
module; this test plays the gateway on the other end of its socketpair. The QUERY payload is packed here from
docs/misc/dns-gateway-protocol.md: u8 transport (0 stream, 1 datagram), u8 n, n bytes of client IP text, the DNS wire.
"""

from __future__ import annotations

import socket
import struct
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import dnswire
import pytest
from frontend_constants import ALLOWED, PROTO_DIR
from frontend_helpers import WATCHDOG, FakeUnbound, build_query, watched

QUERY, FORWARD, REPLY, ANSWER, DROP, READY = 1, 2, 3, 4, 5, 6
STREAM, DATAGRAM = 0, 1
CLIENT = "192.0.2.10"
DUCK, TARGET = "duck.example.", "safe.duck.example."
ZONE = {
    (DUCK, dnswire.TYPE_A): [f"{DUCK} 300 IN A 192.0.2.50"],
    (TARGET, dnswire.TYPE_A): [f"{TARGET} 300 IN A 192.0.2.88"],
    (ALLOWED, dnswire.TYPE_A): [f"{ALLOWED} 300 IN A 192.0.2.77"],
}


def _target_zone(count: int) -> dict[tuple[str, int], list[str]]:
    """ZONE with `count` addresses for the SafeSearch target, each an A record of its own."""
    return ZONE | {(TARGET, dnswire.TYPE_A): [f"{TARGET} 300 IN A 10.0.{n // 250}.{n % 250 + 1}" for n in range(count)]}


def frame(ftype: int, fid: int, payload: bytes = b"") -> bytes:
    return struct.pack("!IBI", 5 + len(payload), ftype, fid) + payload


def query_frame(fid: int, wire: bytes, transport: int, ip: str = CLIENT) -> bytes:
    return frame(QUERY, fid, bytes([transport, len(ip)]) + ip.encode("ascii") + wire)


class Gateway:
    """The Go side of the socketpair, played synchronously against the real decider process."""

    def __init__(self, sock: socket.socket, child: subprocess.Popen[str]) -> None:
        self.sock, self.child = sock, child

    def _read(self, size: int) -> bytes:
        data = b""
        while len(data) < size:
            with watched("the decider's frame"):
                chunk = self.sock.recv(size - len(data))
            assert chunk, f"the decider closed the socket after {len(data)} of {size} expected bytes"
            data += chunk
        return data

    def recv(self) -> tuple[int, int, bytes]:
        (size,) = struct.unpack("!I", self._read(4))
        body = self._read(size)
        ftype, fid = struct.unpack_from("!BI", body)
        return ftype, fid, body[5:]

    def send(self, data: bytes) -> None:
        self.sock.sendall(data)

    def answer_to(self, query: bytes, fid: int, transport: int, unbound: FakeUnbound) -> bytes:
        """Send QUERY, answer every FORWARD from `unbound`, and return the wire of the final ANSWER."""
        self.send(query_frame(fid, query, transport))
        while True:
            ftype, got, payload = self.recv()
            assert got == fid
            if ftype == ANSWER:
                return payload
            assert ftype == FORWARD, f"frame type {ftype}: want FORWARD or ANSWER"
            self.send(frame(REPLY, fid, unbound.answer(payload)))


@contextmanager
def running_decider(module_dir: Path, *flags: str) -> Iterator[Gateway]:
    """The real decider on one end of a socketpair, READY read; ended by EOF, and required to exit 0."""
    go, py = socket.socketpair()
    go.settimeout(WATCHDOG)
    command = [sys.executable, str(PROTO_DIR / "pfb_dns_proxy.py"), "--decision-fd", str(py.fileno())]
    child = subprocess.Popen(
        [*command, "--module-dir", str(module_dir), *flags],
        pass_fds=[py.fileno()],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    py.close()
    gateway = Gateway(go, child)
    try:
        assert gateway.recv() == (READY, 0, b"")
        yield gateway
        go.close()
        with watched("the decider to exit after EOF"):
            _, stderr = child.communicate(timeout=WATCHDOG)
        assert child.returncode == 0, stderr
    finally:
        go.close()
        if child.poll() is None:
            child.kill()
            child.communicate()


# (client's EDNS size or None, target addresses, whether the reply has to be truncated). The reply holds the CNAME and
# every address: 92 + 16 per further address bytes without an OPT, 11 more with the decider's own OPT.
UDP_SIZES = [
    pytest.param(None, 40, True, id="no-edns-limit-512"),
    pytest.param(512, 40, True, id="edns-512"),
    pytest.param(100, 26, False, id="edns-below-512-counts-as-512"),
    pytest.param(1232, 60, False, id="edns-1232-fits"),
    pytest.param(4096, 94, True, id="edns-4096-is-held-to-the-1232-the-decider-advertises"),
    pytest.param(65535, 94, True, id="edns-65535-is-held-to-1232-too"),
]


def _query(size: int | None) -> bytes:
    return build_query(DUCK) if size is None else build_query(DUCK, edns=True, udp_size=size)


@pytest.mark.parametrize(("size", "count", "truncated"), UDP_SIZES)
def test_a_datagram_clients_answer_is_cut_to_the_udp_size_it_advertised(
    safesearch_csv: None, module_dir: Path, size: int | None, count: int, truncated: bool
) -> None:
    """Issue #3517 review: a no-EDNS client was sent 530 bytes and one advertising 512 was sent 796, TC clear."""
    with running_decider(module_dir) as gateway:
        wire = gateway.answer_to(_query(size), 1, DATAGRAM, FakeUnbound(_target_zone(count)))
    reply = dnswire.parse(wire)
    limit = min(max(size or 512, 512), 1232)
    assert (reply.id, reply.rcode, reply.flags & dnswire.RD, reply.questions) == (
        0x1234,
        0,
        dnswire.RD,
        [dnswire.Question(DUCK, dnswire.TYPE_A)],
    )
    if truncated:
        assert (reply.flags & dnswire.TC, reply.answers, reply.authority) == (dnswire.TC, [], [])
    else:
        assert (reply.flags & dnswire.TC, len(reply.answers)) == (0, 1 + count)
    assert len(wire) <= limit
    assert [(rr.rtype, rr.rclass) for rr in reply.additional] == ([] if size is None else [(dnswire.TYPE_OPT, 1232)])


def test_a_stream_clients_answer_is_sent_whole_however_big(safesearch_csv: None, module_dir: Path) -> None:
    with running_decider(module_dir) as gateway:
        wire = gateway.answer_to(build_query(DUCK), 1, STREAM, FakeUnbound(_target_zone(94)))
    reply = dnswire.parse(wire)
    assert len(wire) > 1232
    assert (reply.flags & dnswire.TC, len(reply.answers)) == (0, 95)


def test_an_answer_exactly_as_big_as_the_datagram_clients_size_is_not_truncated_and_one_byte_less_is(
    safesearch_csv: None, module_dir: Path
) -> None:
    unbound = FakeUnbound(_target_zone(45))
    with running_decider(module_dir) as gateway:
        full = gateway.answer_to(build_query(DUCK, edns=True, udp_size=4096), 1, STREAM, unbound)
        assert 512 < len(full) < 1232
        verdicts = [
            (size, bool(dnswire.parse(gateway.answer_to(_query(size), fid, DATAGRAM, unbound)).flags & dnswire.TC))
            for fid, size in ((2, len(full)), (3, len(full) - 1))
        ]
    assert verdicts == [(len(full), False), (len(full) - 1, True)]


@pytest.mark.parametrize("transport", [STREAM, DATAGRAM], ids=["stream", "datagram"])
def test_with_no_module_either_transport_gets_unbounds_reply_relayed_as_it_is(tmp_path: Path, transport: int) -> None:
    query = build_query(ALLOWED, qid=0x0A0A)
    unbound = FakeUnbound(ZONE)
    with running_decider(tmp_path / "absent", "--no-module") as gateway:
        gateway.send(query_frame(7, query, transport))
        assert gateway.recv() == (FORWARD, 7, query)
        gateway.send(frame(REPLY, 7, unbound.answer(query)))
        assert gateway.recv() == (ANSWER, 7, unbound.answer(query))


@pytest.mark.parametrize("transport", [2, 255], ids=["two", "255"])
def test_a_transport_byte_that_is_neither_stream_nor_datagram_is_a_protocol_error_and_exit_1(transport: int) -> None:
    go, py = socket.socketpair()
    go.settimeout(WATCHDOG)
    child = subprocess.Popen(
        [sys.executable, str(PROTO_DIR / "pfb_dns_proxy.py"), "--decision-fd", str(py.fileno()), "--no-module"],
        pass_fds=[py.fileno()],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    py.close()
    try:
        gateway = Gateway(go, child)
        assert gateway.recv() == (READY, 0, b"")
        gateway.send(query_frame(1, build_query(ALLOWED), transport))
        tail = b""
        with watched("the decider to end its session"):
            while chunk := go.recv(4096):
                tail += chunk
            _, stderr = child.communicate(timeout=WATCHDOG)
    finally:
        go.close()
        if child.poll() is None:
            child.kill()
            child.communicate()
    assert tail == b"", "a QUERY with an unknown transport gets no ANSWER and no DROP: the session is over"
    assert child.returncode == 1
    assert "decision protocol error:" in stderr
