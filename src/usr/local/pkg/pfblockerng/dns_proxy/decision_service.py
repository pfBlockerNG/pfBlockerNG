"""Decision protocol service (issue #3513): the Go gateway sends each client query, the module decides.

One AF_UNIX stream carries length-prefixed frames both ways; docs/misc/dns-gateway-protocol.md is normative. The
gateway sends QUERY (the client's transport, its IP text and its DNS wire) and REPLY (Unbound's answer to the last
FORWARD, empty = none). For each QUERY `resolve` runs in its own task; its `forward` sends FORWARD and waits for the
REPLY, and the result goes back as ANSWER (bytes) or DROP (None). Standard library only; Python 3.11+.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import socket
import struct
from collections.abc import Awaitable, Callable
from time import monotonic
from typing import Protocol

QUERY, FORWARD, REPLY, ANSWER, DROP, READY = 1, 2, 3, 4, 5, 6
STREAM, DATAGRAM = (
    0,
    1,
)  # the QUERY's transport byte: TCP, DoT, DoH and DoQ clients have no size limit, plain UDP has one
# type + id, then transport + n + up to 255 IP text bytes + up to 65535 DNS wire bytes
MAX_FRAME_LEN = 5 + 1 + 1 + 255 + 65535
FAILURE_LOG_INTERVAL = 30.0  # seconds between two "query N failed" lines: the decider's no-reply window

Forward = Callable[[bytes], Awaitable[bytes | None]]


class Resolve(Protocol):
    """Decide one client query: the answer to send it, or None to send nothing. `datagram`: the client is a plain-UDP
    one, whose answer has to fit the UDP size it advertised."""

    def __call__(self, wire: bytes, client_ip: str, forward: Forward, *, datagram: bool) -> Awaitable[bytes | None]: ...


class ProtocolError(Exception):
    """The gateway sent something the protocol does not allow; the session cannot be trusted any further."""


def encode_frame(ftype: int, fid: int, payload: bytes = b"") -> bytes:
    return struct.pack("!IBI", 5 + len(payload), ftype, fid) + payload


async def _read_frame(reader: asyncio.StreamReader) -> tuple[int, int, bytes] | None:
    """The next (type, id, payload); None when the gateway closed the stream, even half way through a frame."""
    try:
        (size,) = struct.unpack("!I", await reader.readexactly(4))
        if not 5 <= size <= MAX_FRAME_LEN:
            raise ProtocolError(f"frame length {size} is outside 5..{MAX_FRAME_LEN}")
        body = await reader.readexactly(size)
    except asyncio.IncompleteReadError:
        return None
    ftype, fid = struct.unpack_from("!BI", body)
    return ftype, fid, body[5:]


def _split_query(payload: bytes) -> tuple[bool, bytes, bytes]:
    """(client is a datagram one, client IP text, DNS wire) of a QUERY payload: u8 transport (STREAM or DATAGRAM), u8 n,
    n IP text bytes, the rest is the wire."""
    if len(payload) < 2 or payload[0] not in (STREAM, DATAGRAM):
        raise ProtocolError(
            "QUERY payload does not start with a transport byte (0 stream, 1 datagram) and an IP length"
        )
    if payload[1] == 0 or payload[1] > len(payload) - 2:
        raise ProtocolError("QUERY payload does not hold a client IP of its stated length")
    return payload[0] == DATAGRAM, payload[2 : 2 + payload[1]], payload[2 + payload[1] :]


def _client_ip(text: bytes) -> str | None:
    try:
        decoded = text.decode("ascii")
        ipaddress.ip_address(decoded)
    except ValueError:  # UnicodeDecodeError is one
        return None
    return decoded


async def serve(sock: socket.socket, resolve: Resolve, timeout: float, log: Callable[[str], object]) -> None:
    """Send READY, then answer QUERYs until the gateway closes the stream; always closes `sock`.

    `timeout` is the module's wait for Unbound: a FORWARD gets no REPLY within twice that and `forward` returns None.
    A task that fails is logged to `log` and its query is dropped. Raises ProtocolError on malformed framing; a peer
    that goes away (EOF, reset) ends the session quietly.
    """
    reader, writer = await asyncio.open_connection(sock=sock)
    tasks: set[asyncio.Task[None]] = set()
    inflight: set[int] = set()
    replies: dict[int, asyncio.Future[bytes | None]] = {}
    failed_logged = float("-inf")  # when a failed query was last logged

    async def send(ftype: int, fid: int, payload: bytes = b"") -> None:
        writer.write(encode_frame(ftype, fid, payload))  # one write() per frame: tasks cannot interleave bytes
        await writer.drain()

    async def decide(fid: int, datagram: bool, ip: str | None, wire: bytes) -> None:
        nonlocal failed_logged

        async def forward(request: bytes) -> bytes | None:
            waiter = replies[fid] = asyncio.get_running_loop().create_future()
            try:
                await send(FORWARD, fid, request)
                return await asyncio.wait_for(waiter, 2 * timeout)
            except TimeoutError:
                return None
            finally:
                del replies[fid]

        answer: bytes | None = None
        try:
            if ip is not None:
                answer = await resolve(wire, ip, forward, datagram=datagram)
        except Exception as exc:
            if (now := monotonic()) - failed_logged >= FAILURE_LOG_INTERVAL:
                failed_logged = now
                log(f"query {fid} failed: {exc!r}")
        inflight.discard(fid)  # before the final frame: the gateway may reuse the id the moment it has it
        try:
            await (send(DROP, fid) if answer is None else send(ANSWER, fid, answer))
        except OSError:
            pass  # the gateway is gone; the read loop is about to see it

    try:
        await send(READY, 0)
        while (frame := await _read_frame(reader)) is not None:
            ftype, fid, payload = frame
            if ftype == REPLY:
                waiter = replies.get(fid)
                if waiter is not None and not waiter.done():
                    waiter.set_result(payload or None)
            elif ftype == QUERY:
                datagram, ip_text, wire = _split_query(payload)
                if fid in inflight:
                    raise ProtocolError(f"QUERY id {fid} is already in flight")
                inflight.add(fid)
                task = asyncio.ensure_future(decide(fid, datagram, _client_ip(ip_text), wire))
                tasks.add(task)
                task.add_done_callback(tasks.discard)
            else:
                raise ProtocolError(f"frame type 0x{ftype:02x} is not valid from the gateway")
    except OSError:
        pass  # reset or broken pipe: the gateway went away, as on EOF
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        writer.close()
        with contextlib.suppress(OSError):
            await writer.wait_closed()
