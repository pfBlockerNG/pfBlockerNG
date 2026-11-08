"""Issue #3517: the decision protocol's QUERY names the client's transport, and the decider holds the answers it builds
itself to a datagram client's UDP size and to nothing for a stream client.

The REAL `pfb_dns_proxy.py --decision-fd` process runs with the shipped pfb_unbound.py (SafeSearch loaded) or with no
module; this test plays the gateway on the other end of its socketpair. The QUERY payload is packed here from
docs/misc/dns-gateway-protocol.md: transport, client IP, listener IP/interface, DNS wire.
"""

from __future__ import annotations

import asyncio
import socket
import struct
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import decision_service
import dnswire
import pfb_dns_proxy
import pytest
from frontend_constants import ALLOWED, PROTO_DIR
from frontend_helpers import WATCHDOG, FakeUnbound, build_query, watchdog, watched
from test_decision_service import _start_with

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
    return frame(QUERY, fid, bytes([transport, len(ip)]) + ip.encode("ascii") + b"\x00\x00\x00" + wire)


class Gateway:
    """The Go side of the socketpair, played synchronously against the real decider process."""

    def __init__(self, sock: socket.socket, child: subprocess.Popen[str]) -> None:
        self.sock, self.child = sock, child
        self.forwards: list[int] = []  # the payload size of each FORWARD the decider sent

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
            self.forwards.append(len(payload))


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


@pytest.mark.parametrize("transport", [0, 2, 3, 4], ids=["TCP", "DoT", "DoH", "DoQ"])
def test_a_stream_clients_answer_is_sent_whole_however_big(
    safesearch_csv: None, module_dir: Path, transport: int
) -> None:
    with running_decider(module_dir) as gateway:
        wire = gateway.answer_to(build_query(DUCK), 1, transport, FakeUnbound(_target_zone(94)))
    reply = dnswire.parse(wire)
    assert len(wire) > 1232
    assert (reply.flags & dnswire.TC, len(reply.answers)) == (0, 95)


# A records on this name grow the rebuilt answer by 16 bytes, so one TXT is what lands it on an exact length:
# 4091 addresses encode to 65522, an empty TXT adds 13 (the message maximum) and a one-character TXT adds 14.
_AT_MESSAGE_MAXIMUM = 4091
_MESSAGE_MAXIMUM = 65535


def _zone_at(txt: str) -> dict[tuple[str, int], list[str]]:
    zone = _target_zone(_AT_MESSAGE_MAXIMUM)
    zone[(TARGET, dnswire.TYPE_A)].append(f"{TARGET} 300 IN TXT {txt}")
    return zone


def test_a_rebuilt_stream_answer_over_the_message_maximum_is_an_error(safesearch_csv: None, module_dir: Path) -> None:
    """A rebuilt stream answer at the message maximum is sent whole; one byte over is a bare SERVFAIL.

    The same oversized answer to a datagram client stays a TC reply with rcode 0. That is the UDP path, and it
    is what fails if the stream-only guard is applied to datagram clients too.
    """
    question = dnswire.Question(DUCK, dnswire.TYPE_A)
    with running_decider(module_dir) as gateway:
        exact = gateway.answer_to(build_query(DUCK), 1, STREAM, FakeUnbound(_zone_at('""')))
        over = gateway.answer_to(build_query(DUCK), 2, STREAM, FakeUnbound(_zone_at('"x"')))
        over_datagram = gateway.answer_to(build_query(DUCK), 3, DATAGRAM, FakeUnbound(_zone_at('"x"')))
    exact_reply = dnswire.parse(exact)
    assert (len(exact), exact_reply.rcode, exact_reply.flags & dnswire.TC, len(exact_reply.answers)) == (
        _MESSAGE_MAXIMUM,
        0,
        0,
        1 + _AT_MESSAGE_MAXIMUM + 1,
    )
    over_reply = dnswire.parse(over)
    got = (len(over), over_reply.rcode, len(over_reply.answers), over_reply.questions)
    assert len(over) <= _MESSAGE_MAXIMUM and got[1:] == (2, 0, [question]), got
    datagram_reply = dnswire.parse(over_datagram)
    assert (
        datagram_reply.flags & dnswire.TC,
        datagram_reply.rcode,
        datagram_reply.answers,
    ) == (dnswire.TC, 0, []), datagram_reply
    assert len(over_datagram) <= _MESSAGE_MAXIMUM


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


PADDING_OPTION = 12  # RFC 7830: the EDNS option a client pads its query with


def _padded(size: int) -> bytes:
    """A query for DUCK of exactly `size` bytes: its EDNS padding option (RFC 7830) fills the OPT record."""
    data = size - 45  # header 12, question 18, OPT record 11 and the option's own 4-byte header
    return build_query(DUCK, edns=True, options=struct.pack("!HH", PADDING_OPTION, data) + bytes(data))


def test_a_safesearch_chase_over_one_dns_message_is_servfail_and_never_forwarded(
    safesearch_csv: None, module_dir: Path
) -> None:
    """Issue #3641: the chase repeats the client's EDNS options and its target name is 5 bytes longer than DUCK, so a
    65535-byte query makes a 65540-byte FORWARD. The gateway treats an oversized FORWARD as a protocol error and exits;
    the client gets SERVFAIL instead and the decider keeps running."""
    query = _padded(_MESSAGE_MAXIMUM)
    assert len(query) == _MESSAGE_MAXIMUM
    with running_decider(module_dir) as gateway:
        wire = gateway.answer_to(query, 1, STREAM, FakeUnbound(_target_zone(1)))
    reply = dnswire.parse(wire)
    assert gateway.forwards == [_MESSAGE_MAXIMUM], f"FORWARD sizes {gateway.forwards}: the chase must not be sent"
    assert (reply.rcode, reply.answers) == (pfb_dns_proxy.RCODE_SERVFAIL, [])


def test_a_safesearch_chase_of_exactly_one_dns_message_is_forwarded(safesearch_csv: None, module_dir: Path) -> None:
    """The guard is over 65535 bytes, not at it: a chase of exactly that size is still forwarded and answered."""
    query = _padded(_MESSAGE_MAXIMUM - 5)  # its chase is 5 bytes longer than the query
    assert len(query) == _MESSAGE_MAXIMUM - 5
    with running_decider(module_dir) as gateway:
        wire = gateway.answer_to(query, 1, STREAM, FakeUnbound(_target_zone(1)))
    reply = dnswire.parse(wire)
    assert gateway.forwards == [_MESSAGE_MAXIMUM - 5, _MESSAGE_MAXIMUM]
    assert (reply.rcode, len(reply.answers)) == (0, 2)


@pytest.mark.parametrize("transport", range(5), ids=["TCP", "UDP", "DoT", "DoH", "DoQ"])
def test_with_no_module_either_transport_gets_unbounds_reply_relayed_as_it_is(tmp_path: Path, transport: int) -> None:
    query = build_query(ALLOWED, qid=0x0A0A)
    unbound = FakeUnbound(ZONE)
    with running_decider(tmp_path / "absent", "--no-module") as gateway:
        gateway.send(query_frame(7, query, transport))
        assert gateway.recv() == (FORWARD, 7, query)
        gateway.send(frame(REPLY, 7, unbound.answer(query)))
        assert gateway.recv() == (ANSWER, 7, unbound.answer(query))


@pytest.mark.parametrize("transport", [5, 255], ids=["five", "255"])
def test_an_undefined_transport_byte_is_a_protocol_error_and_exit_1(transport: int) -> None:
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


def endpoint_payload(
    client: bytes = b"192.0.2.10", listener: bytes = b"192.0.2.53", interface: bytes = b"", transport: int = 0
) -> bytes:
    """Pack the endpoint QUERY contract independently of the service parser."""
    return (
        bytes([transport, len(client)])
        + client
        + bytes([len(listener)])
        + listener
        + struct.pack("!H", len(interface))
        + interface
        + build_query(ALLOWED, qid=0x3757)
    )


def endpoint_exchange(payloads: list[bytes]) -> tuple[list[tuple[int, int, bytes]], list[tuple]]:
    """Real socketpair → serve → resolve, draining each decision before sending the next."""
    calls: list[tuple] = []

    async def resolve(
        wire: bytes,
        client_ip: str,
        forward: decision_service.Forward,
        *,
        transport: str,
        listener_ip: str = "<missing>",
        listener_interface: str = "<missing>",
    ) -> bytes:
        calls.append((wire, client_ip, transport, listener_ip, listener_interface))
        return b"endpoint-answer"

    async def scenario() -> list[tuple[int, int, bytes]]:
        gateway, service, problems = await _start_with(resolve)
        replies = []
        try:
            for fid, payload in enumerate(payloads, 1):
                await gateway.send(frame(QUERY, fid, payload))
                replies.append(await gateway.recv())
        finally:
            gateway.close()
            await watchdog(service, "the endpoint decision service to end")
        assert problems == []
        return replies

    return asyncio.run(scenario()), calls


@pytest.mark.parametrize(("transport", "name"), list(enumerate(("TCP", "UDP", "DoT", "DoH", "DoQ"))))
@pytest.mark.parametrize(
    ("client", "listener", "want_client", "want_listener"),
    [
        ("2001:db8::10", "192.0.2.53", "2001:db8::10", "192.0.2.53"),
        ("192.0.2.10", "2001:0DB8:0000::53", "192.0.2.10", "2001:db8::53"),
        ("::ffff:192.0.2.10", "::ffff:192.0.2.53", "192.0.2.10", "192.0.2.53"),
    ],
    ids=["v4-listener-v6-client", "v6-listener-v4-client", "mapped-endpoints"],
)
def test_endpoint_query_preserves_wire_and_independent_endpoint_metadata(
    transport: int, name: str, client: str, listener: str, want_client: str, want_listener: str
) -> None:
    interface = '内网, "guest"\\vlan'
    replies, calls = endpoint_exchange(
        [endpoint_payload(client.encode("ascii"), listener.encode("ascii"), interface.encode("utf-8"), transport)]
    )
    assert calls == [(build_query(ALLOWED, qid=0x3757), want_client, name, want_listener, interface)]
    assert replies == [(ANSWER, 1, b"endpoint-answer")]


@pytest.mark.parametrize(("listener", "want_listener"), [(b"", ""), (b"192.0.2.53", "192.0.2.53")])
def test_endpoint_unavailable_metadata_is_empty_not_inferred(listener: bytes, want_listener: str) -> None:
    replies, calls = endpoint_exchange([endpoint_payload(listener=listener)])
    assert calls == [(build_query(ALLOWED, qid=0x3757), CLIENT, "TCP", want_listener, "")]
    assert replies == [(ANSWER, 1, b"endpoint-answer")]


BAD_ENDPOINT_IPS = [
    pytest.param(b"\xff", id="non-ascii"),
    pytest.param(b"not-an-ip", id="invalid-ip"),
    pytest.param(b"192.0.2.53/24", id="cidr"),
    pytest.param(b"fe80::53%em0", id="zone"),
    pytest.param(b"[2001:db8::53]", id="brackets"),
    pytest.param(b"192.0.2.53:53", id="port"),
    pytest.param(b"0.0.0.0", id="unspecified-v4"),
    pytest.param(b"::", id="unspecified-v6"),
    pytest.param(b"::ffff:0.0.0.0", id="unspecified-mapped"),
]


@pytest.mark.parametrize("bad_ip", BAD_ENDPOINT_IPS)
@pytest.mark.parametrize("field", ["client", "listener"])
def test_endpoint_invalid_address_drops_only_that_query(field: str, bad_ip: bytes) -> None:
    replies, calls = endpoint_exchange([endpoint_payload(**{field: bad_ip}), endpoint_payload()])
    assert replies == [(DROP, 1, b""), (ANSWER, 2, b"endpoint-answer")]
    assert calls == [(build_query(ALLOWED, qid=0x3757), CLIENT, "TCP", "192.0.2.53", "")]


@pytest.mark.parametrize(
    "interface",
    [
        pytest.param(b"\xff", id="invalid-utf8"),
        pytest.param(b"lan\ninjected", id="newline"),
        pytest.param(b"lan\x00", id="nul"),
        pytest.param(b"lan\t", id="c0-tab"),
        pytest.param(b"lan\x7f", id="delete"),
        pytest.param("lan\u0085".encode(), id="c1"),
    ],
)
def test_endpoint_invalid_interface_drops_only_that_query(interface: bytes) -> None:
    replies, calls = endpoint_exchange([endpoint_payload(interface=interface), endpoint_payload()])
    assert replies == [(DROP, 1, b""), (ANSWER, 2, b"endpoint-answer")]
    assert calls == [(build_query(ALLOWED, qid=0x3757), CLIENT, "TCP", "192.0.2.53", "")]


def test_endpoint_interface_without_listener_drops_only_that_query() -> None:
    replies, calls = endpoint_exchange([endpoint_payload(listener=b"", interface=b"LAN"), endpoint_payload()])
    assert replies == [(DROP, 1, b""), (ANSWER, 2, b"endpoint-answer")]
    assert calls == [(build_query(ALLOWED, qid=0x3757), CLIENT, "TCP", "192.0.2.53", "")]


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param(b"", id="missing-transport"),
        pytest.param(b"\x00", id="missing-client-length"),
        pytest.param(b"\x00\x00", id="empty-client"),
        pytest.param(b"\x00\x09short", id="short-client"),
        pytest.param(b"\x00\x09192.0.2.1", id="missing-listener-length"),
        pytest.param(b"\x00\x09192.0.2.1\x09short", id="short-listener"),
        pytest.param(b"\x00\x09192.0.2.1\x00", id="empty-listener-missing-interface-length"),
        pytest.param(b"\x00\x09192.0.2.1\x00\x00", id="empty-listener-short-interface-length"),
        pytest.param(b"\x00\x09192.0.2.1\x0a192.0.2.53", id="listener-missing-interface-length"),
        pytest.param(b"\x00\x09192.0.2.1\x0a192.0.2.53\x00", id="listener-short-interface-length"),
        pytest.param(b"\x00\x09192.0.2.1\x00\x00\x05LAN", id="empty-listener-short-interface"),
        pytest.param(b"\x00\x09192.0.2.1\x0a192.0.2.53\x00\x05LAN", id="listener-short-interface"),
        pytest.param(endpoint_payload(transport=5), id="invalid-transport-five"),
        pytest.param(endpoint_payload(transport=255), id="invalid-transport-255"),
    ],
)
def test_endpoint_structural_errors_are_fatal(payload: bytes) -> None:
    async def resolve(wire: bytes, client_ip: str, forward: decision_service.Forward, **metadata: object) -> None:
        return None

    async def scenario() -> None:
        gateway, service, _ = await _start_with(resolve)
        try:
            await gateway.send(frame(QUERY, 1, payload))
            gateway.writer.write_eof()
            with pytest.raises(decision_service.ProtocolError):
                await watchdog(service, "the malformed endpoint session to end")
        finally:
            gateway.close()
            if not service.done():
                service.cancel()
                await asyncio.gather(service, return_exceptions=True)

    asyncio.run(scenario())
