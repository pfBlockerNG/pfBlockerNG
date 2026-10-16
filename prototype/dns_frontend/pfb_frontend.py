"""pfBlockerNG DNS front end prototype (issue #3512): UDP+TCP, runs the SHIPPED pfb_unbound.py unchanged.

DNSBL decisions are answered here; every other query is forwarded to Unbound (moved off the client port) behind
a PROXYv2 header carrying the real client address, so Unbound's cache, access control and query log see the client.

  python3 pfb_frontend.py --listen 192.0.2.1 --listen ::1 --port 53 --upstream 127.0.0.1:5353 --module-dir /var/unbound

  --listen ADDR      address to serve on, repeatable (default 127.0.0.1)
  --port N           client-facing UDP and TCP port (default 53)
  --upstream H:P     Unbound with `proxy-protocol-port: P` (default 127.0.0.1:5353)
  --module-dir DIR   dir holding pfb_unbound.py, pfb_dnsbl_regex_rules.py, pfb_unbound.ini and the manifest
                     (default /var/unbound); the process works in that directory, as Unbound's chroot does
  --timeout SECONDS  wait for Unbound before answering SERVFAIL (default 5)
  --dot              also serve DNS over TLS, as the pfSense DNS Resolver is set up for (see below)
  --pfsense-config P pfSense config.xml to read the DNS Resolver's DoT settings from (/cf/conf/config.xml)

--dot reads unbound/enablessl, unbound/sslcertref and unbound/tlsport (853 if unset) from config.xml, serves the
referenced certificate on every --listen address at that port (TLS 1.2+), and forwards a DoT query to Unbound like a
TCP one, with the TLS peer's address in the PROXYv2 header. If the Resolver does not have DoT enabled or the
certificate is missing or unusable, it exits 1 with the reason: there is no self-signed fallback.

The module expects /var/log/pfblockerng to exist, as on pfSense. Standard library only; Python 3.11+.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import logging
import os
import secrets
import signal
import ssl
import struct
import sys
import traceback
from collections.abc import Awaitable, Callable, Coroutine, Sequence
from functools import partial
from types import ModuleType
from typing import Any

import dnswire
import pfsense_dot
import proxyv2
import unbound_shim as shim

LOG_DIR = "/var/log/pfblockerng"
TCP_IDLE_TIMEOUT = 30.0  # Unbound's tcp-idle-timeout default
RCODE_FORMERR = 1
RCODE_SERVFAIL = 2
MAX_QUERY_RRS = 8  # answer, authority and additional records together; a real query carries an OPT, maybe a TSIG
MAX_UDP_INFLIGHT = 512  # concurrent UDP queries, each holding an upstream socket; more are dropped
Forward = Callable[[bytes], Awaitable[bytes | None]]


# --- module lifecycle ----------------------------------------------------------------------------


def ensure_stderr_sink() -> None:
    """init_standard() points sys.stderr at a logger writing to py_error.log. If LOG_DIR is unusable no handler is
    installed, and the logger's last-resort handler writes back into sys.stderr: endless recursion. Give it one."""
    if not os.access(LOG_DIR, os.W_OK):
        logging.basicConfig(stream=sys.__stderr__, format="%(asctime)s|%(levelname)s| %(message)s")


_stderr_before_boot: Any = None


def boot(module_dir: str) -> ModuleType:
    """Install the Unbound API shim, import the shipped module from `module_dir` and run its init_standard()."""
    global _stderr_before_boot
    ensure_stderr_sink()
    _stderr_before_boot = sys.stderr  # init_standard() replaces it with a logger that has no flush()
    module = shim.install(module_dir)
    try:
        if not module.init_standard(shim.MODULE_ID, shim.module_env()):
            raise RuntimeError("pfb_unbound.init_standard() failed")
    except BaseException:
        shim.uninstall()
        sys.stderr = _stderr_before_boot
        raise
    return module


def shutdown(module: ModuleType) -> None:
    try:
        module.deinit(shim.MODULE_ID)
    finally:
        shim.uninstall()
        sys.stderr = _stderr_before_boot


# --- addressing ----------------------------------------------------------------------------------


def _unmapped(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    ip = ipaddress.ip_address(host.partition("%")[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def proxy_endpoints(client: tuple[str, int], local: tuple[str, int]) -> tuple[tuple[str, int], tuple[str, int]]:
    """(client, local) as one IP family for the PROXYv2 header: IPv4-mapped IPv6 becomes IPv4, scope ids go, and a
    local address of the other family (a dual-stack wildcard) becomes the client family's unspecified address."""
    src, dst = _unmapped(client[0]), _unmapped(local[0])
    if src.version != dst.version:
        dst = ipaddress.ip_address("0.0.0.0" if src.version == 4 else "::")
    return (str(src), client[1]), (str(dst), local[1])


def parse_hostport(value: str) -> tuple[str, int]:
    host, sep, port = value.rpartition(":")
    if not sep or not host or not port.isdigit() or not 0 < int(port) < 65536:
        raise ValueError(f"expected HOST:PORT, got {value!r}")
    return host.removeprefix("[").removesuffix("]"), int(port)


# --- replies the front end builds itself ---------------------------------------------------------


def _edns_for(query: dnswire.Message) -> list[dnswire.RR]:
    opt = next((rr for rr in query.additional if rr.rtype == dnswire.TYPE_OPT), None)
    return [] if opt is None else [dnswire.make_opt(do=bool(opt.ttl & 0x8000))]


def _error(query: dnswire.Message, rcode: int) -> bytes:
    """A bare error reply as Unbound's error_encode builds it: question echoed, RD and CD copied, EDNS echoed."""
    flags = dnswire.QR | dnswire.RA | (query.flags & (dnswire.RD | dnswire.CD)) | rcode
    return dnswire.encode(dnswire.Message(query.id, flags, query.questions, additional=_edns_for(query)))


def _answer(query: dnswire.Message, msg: shim.DnsMsg) -> bytes:
    """The module's replacement message, addressed to this client."""
    flags = dnswire.QR | dnswire.RA | (msg.rep.flags & dnswire.AA) | (query.flags & (dnswire.RD | dnswire.CD))
    additional = [*msg.additional, *_edns_for(query)]
    return dnswire.encode(dnswire.Message(query.id, flags, query.questions, msg.answer, msg.authority, additional))


# --- the front end -------------------------------------------------------------------------------


class Frontend:
    def __init__(
        self,
        module: ModuleType,
        upstream: tuple[str, int],
        timeout: float = 5.0,
        max_udp_inflight: int = MAX_UDP_INFLIGHT,
    ) -> None:
        self.module = module
        self.upstream = upstream
        self.timeout = timeout
        self.max_udp_inflight = max_udp_inflight
        self.udp_inflight = 0
        self.udp_overloaded = False
        self._servers: list[asyncio.Server] = []
        self._udp: list[asyncio.DatagramTransport] = []
        self._clients: set[asyncio.StreamWriter] = set()
        self._tasks: set[asyncio.Task[None]] = set()

    def _operate(self, qstate: shim.module_qstate, event: int) -> int:
        self.module.operate(shim.MODULE_ID, event, qstate, None)
        return qstate.ext_state[shim.MODULE_ID]

    async def resolve(self, wire: bytes, client_ip: str, forward: Forward) -> bytes | None:
        """Answer one client query: parse it, let the module decide, forward to Unbound when it defers.

        None means the packet is dropped. `forward` sends the client's own bytes to Unbound (with its PROXYv2
        header) and returns Unbound's reply bytes, or None if there is none. The header is checked before anything
        is parsed, so a hostile packet costs a constant, and every FORMERR is header-only.
        """
        if len(wire) < 12 or wire[2] & 0x80:  # no header, or a response: never answered (no reflection loops)
            return None
        msg_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", wire[:12])
        if (flags >> 11) & 0xF:
            return await forward(wire)
        if qdcount != 1 or ancount + nscount + arcount > MAX_QUERY_RRS:
            return _error(dnswire.Message(msg_id, flags), RCODE_FORMERR)
        try:
            query = dnswire.parse(wire)
        except dnswire.WireError:
            return _error(dnswire.Message(msg_id, flags), RCODE_FORMERR)

        question = query.questions[0]
        qstate = shim.module_qstate(
            shim.query_info(question.name, question.qtype, question.qclass), client_ip, 0, query.flags
        )
        relay: bytes | None = None
        try:
            state = self._operate(qstate, shim.MODULE_EVENT_NEW)
            if state == shim.MODULE_WAIT_MODULE:
                upstream_reply = await forward(wire)
                if upstream_reply is None:
                    shim.log_warn(f"no reply from Unbound for {question.name} {dnswire.type_str(question.qtype)}")
                    state = shim.MODULE_ERROR
                else:
                    reply = dnswire.parse(upstream_reply)
                    # An error rcode from Unbound (SERVFAIL, REFUSED...) is the module's return_rcode; NXDOMAIN stays
                    # in the reply flags, as Unbound's iterator leaves it.
                    base_rcode = reply.rcode if reply.rcode not in (shim.RCODE_NOERROR, shim.RCODE_NXDOMAIN) else 0
                    qstate.return_msg = shim.DnsMsg.from_message(reply, question)
                    qstate.return_rcode = base_rcode
                    unchanged = qstate.return_msg
                    state = self._operate(qstate, shim.MODULE_EVENT_MODDONE)
                    if qstate.return_msg is unchanged and qstate.return_rcode == base_rcode:
                        relay = upstream_reply  # the module left Unbound's answer alone: pass its bytes through
            if state == shim.MODULE_RESTART_NEXT:
                state = await self._chase_cname(query, qstate, forward)
        except Exception:
            shim.log_err(traceback.format_exc())
            state = shim.MODULE_ERROR
        if state != shim.MODULE_FINISHED:
            qstate.return_msg, qstate.return_rcode, relay = None, RCODE_SERVFAIL, None
        return self._send(query, qstate, relay)

    async def _chase_cname(self, query: dnswire.Message, qstate: shim.module_qstate, forward: Forward) -> int:
        """Emulate MODULE_RESTART_NEXT as the SafeSearch CNAME redirect uses it (safesearch_cname_redirect).

        The module planted `orig -> CNAME -> target` and expects Unbound's iterator to chase the target, then runs
        its post-resolution pass on the combined answer. Unbound will not chase a CNAME a module hands it, so this
        plays the iterator: ask Unbound for the target as the same client, give the module the planted CNAME plus the
        target's answer records, and run that pass once. A chase that finds nothing leaves the CNAME alone in the
        message, which is what makes the module answer with its baked address. Returns the module's state.
        """
        planted = qstate.return_msg
        if planted is None or len(planted.answer) != 1 or planted.answer[0].rtype != dnswire.TYPE_CNAME:
            shim.log_err("MODULE_RESTART_NEXT without a planted CNAME referral")
            return shim.MODULE_ERROR
        cname = planted.answer[0]
        target = dnswire.Question(dnswire.name_from_rdata(cname.rdata), planted.qinfo.qtype, planted.qinfo.qclass)
        chase = dnswire.Message(secrets.randbits(16), dnswire.RD, [target], additional=_edns_for(query))
        wire = await forward(dnswire.encode(chase))
        answers = [] if wire is None else dnswire.parse(wire).answers  # an unparseable reply is a SERVFAIL, as above
        qstate.return_msg = shim.DnsMsg(planted.qinfo, planted.rep.flags, [cname, *answers], [], [])
        # A module that asks for yet another restart is not obeyed: the chased answer is final, so that is a SERVFAIL.
        return self._operate(qstate, shim.MODULE_EVENT_MODDONE)

    def _send(self, query: dnswire.Message, qstate: shim.module_qstate, relay: bytes | None) -> bytes:
        """Reply to the client the way mesh_send_reply does: rcode != 0 is a bare error, no message is SERVFAIL."""
        msg, rcode = qstate.return_msg, qstate.return_rcode
        if msg is None and rcode == shim.RCODE_NOERROR:
            rcode = RCODE_SERVFAIL
        shim.fire_reply_callback(
            "reply_servfail" if rcode == RCODE_SERVFAIL else "reply", qstate, msg and msg.rep, rcode
        )
        if relay is not None:
            return relay
        if rcode != shim.RCODE_NOERROR or msg is None:
            return _error(query, rcode)
        return _answer(query, msg)

    # --- sockets ---

    def spawn(self, coro: Coroutine[Any, Any, None]) -> None:
        task = asyncio.ensure_future(coro)
        self._tasks.add(task)
        task.add_done_callback(self._task_done)

    def _task_done(self, task: asyncio.Task[None]) -> None:
        self._tasks.discard(task)
        if not task.cancelled() and task.exception() is not None:
            shim.log_err(f"query task failed: {task.exception()!r}")

    async def start_dot(self, listen: Sequence[str], port: int, context: ssl.SSLContext) -> list[tuple[str, int]]:
        """Serve DNS over TLS (the same framing as TCP) on each address; returns the bound (host, port)s."""
        bound = []
        for host in listen:
            server = await asyncio.start_server(self._tcp_client, host, port, ssl=context)
            self._servers.append(server)
            bound.append((host, server.sockets[0].getsockname()[1]))
        return bound

    async def start(self, listen: Sequence[str], port: int) -> list[tuple[str, int]]:
        """Serve UDP and TCP on each address (port 0 picks one port per address); returns the bound (host, port)s."""
        loop = asyncio.get_running_loop()
        bound = []
        for host in listen:
            server = await asyncio.start_server(self._tcp_client, host, port)
            self._servers.append(server)
            bound_port = server.sockets[0].getsockname()[1]
            transport, _ = await loop.create_datagram_endpoint(lambda: _UdpServer(self), local_addr=(host, bound_port))
            self._udp.append(transport)  # type: ignore[arg-type]
            bound.append((host, bound_port))
        return bound

    async def stop(self) -> None:
        for server in self._servers:
            server.close()
        for writer in list(self._clients):
            writer.close()
        for transport in self._udp:
            transport.close()
        tasks = list(self._tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _tcp_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """One client connection: length-framed queries answered one at a time, one upstream connection reused."""
        self._clients.add(writer)
        src, dst = proxy_endpoints(writer.get_extra_info("peername")[:2], writer.get_extra_info("sockname")[:2])
        upstream = _TcpUpstream(self.upstream, proxyv2.header(src, dst, tcp=True), self.timeout)
        try:
            while True:
                try:
                    size = struct.unpack("!H", await asyncio.wait_for(reader.readexactly(2), TCP_IDLE_TIMEOUT))[0]
                    wire = await asyncio.wait_for(reader.readexactly(size), TCP_IDLE_TIMEOUT)
                except (asyncio.IncompleteReadError, TimeoutError, OSError):
                    return
                reply = await self.resolve(wire, src[0], upstream)
                if reply is not None:
                    writer.write(struct.pack("!H", len(reply)) + reply)
                    await asyncio.wait_for(writer.drain(), TCP_IDLE_TIMEOUT)  # a client that never reads is dropped
        except OSError:
            pass
        finally:
            upstream.close()
            writer.close()
            self._clients.discard(writer)


class _UdpServer(asyncio.DatagramProtocol):
    def __init__(self, frontend: Frontend) -> None:
        self.frontend = frontend
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: Any) -> None:
        frontend = self.frontend
        if frontend.udp_inflight >= frontend.max_udp_inflight:
            if not frontend.udp_overloaded:  # one line per flood, not per packet
                frontend.udp_overloaded = True
                shim.log_warn(f"{frontend.udp_inflight} UDP queries in flight: dropping new ones until they drain")
            return
        frontend.udp_inflight += 1
        frontend.spawn(self._handle(data, addr))

    async def _handle(self, data: bytes, addr: Any) -> None:
        assert self.transport is not None
        try:
            src, dst = proxy_endpoints(addr[:2], self.transport.get_extra_info("sockname")[:2])
            forward = partial(
                _forward_udp, self.frontend.upstream, proxyv2.header(src, dst, tcp=False), self.frontend.timeout
            )
            reply = await self.frontend.resolve(data, src[0], forward)
            if reply is not None:
                self.transport.sendto(reply, addr)
        finally:
            self.frontend.udp_inflight -= 1
            if self.frontend.udp_inflight == 0:
                self.frontend.udp_overloaded = False


class _ReplyCatcher(asyncio.DatagramProtocol):
    def __init__(self, query_id: bytes, result: asyncio.Future[bytes]) -> None:
        self.query_id = query_id
        self.result = result

    def datagram_received(self, data: bytes, addr: Any) -> None:
        if data[:2] == self.query_id and not self.result.done():
            self.result.set_result(data)

    def error_received(self, exc: Exception) -> None:
        if not self.result.done():
            self.result.set_exception(exc)


async def _forward_udp(upstream: tuple[str, int], header: bytes, timeout: float, wire: bytes) -> bytes | None:
    """One query to Unbound over its own connected UDP socket, PROXYv2 header in front; None on silence or error."""
    loop = asyncio.get_running_loop()
    result: asyncio.Future[bytes] = loop.create_future()
    try:
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _ReplyCatcher(wire[:2], result), remote_addr=upstream
        )
    except OSError:  # out of descriptors: the caller says so once, as for any silence from Unbound
        return None
    try:
        transport.sendto(header + wire)
        return await asyncio.wait_for(result, timeout)
    except (TimeoutError, OSError):
        return None
    finally:
        transport.close()


class _TcpUpstream:
    """The upstream TCP connection of one client connection: opened on first use, PROXYv2 header first, reused."""

    def __init__(self, upstream: tuple[str, int], header: bytes, timeout: float) -> None:
        self.upstream = upstream
        self.header = header
        self.timeout = timeout
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None

    async def __call__(self, wire: bytes) -> bytes | None:
        for _ in range(2):
            reused = self._writer is not None
            try:
                if self._reader is None or self._writer is None:
                    self._reader, self._writer = await asyncio.wait_for(
                        asyncio.open_connection(*self.upstream), self.timeout
                    )
                    self._writer.write(self.header)
                self._writer.write(struct.pack("!H", len(wire)) + wire)
                await self._writer.drain()
                size = struct.unpack("!H", await asyncio.wait_for(self._reader.readexactly(2), self.timeout))[0]
                return await asyncio.wait_for(self._reader.readexactly(size), self.timeout)
            except (OSError, asyncio.IncompleteReadError, TimeoutError):
                self.close()
                if not reused:  # a connection Unbound closed while idle gets one fresh try, nothing else does
                    return None
        return None

    def close(self) -> None:
        if self._writer is not None:
            self._writer.close()
        self._reader = self._writer = None


# --- CLI -----------------------------------------------------------------------------------------


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="pfb_frontend", description="pfBlockerNG DNS front end prototype (issue #3512)"
    )
    parser.add_argument("--listen", action="append", metavar="ADDR", help="address to serve on, repeatable (127.0.0.1)")
    parser.add_argument("--port", type=int, default=53, help="client-facing UDP and TCP port (53)")
    parser.add_argument("--upstream", default="127.0.0.1:5353", metavar="HOST:PORT", help="Unbound's PROXYv2 port")
    parser.add_argument(
        "--module-dir", default="/var/unbound", help="dir with pfb_unbound.py and its ini (/var/unbound)"
    )
    parser.add_argument("--timeout", type=float, default=5.0, help="seconds to wait for Unbound (5)")
    parser.add_argument("--dot", action="store_true", help="also serve DNS over TLS as the DNS Resolver is set up for")
    parser.add_argument(
        "--pfsense-config",
        default="/cf/conf/config.xml",
        metavar="PATH",
        help="pfSense config.xml (/cf/conf/config.xml)",
    )
    args = parser.parse_args(argv)
    try:
        parse_hostport(args.upstream)
    except ValueError as exc:
        parser.error(str(exc))
    return args


async def serve(
    args: argparse.Namespace,
    *,
    stop: asyncio.Event | None = None,
    on_ready: Callable[[list[tuple[str, int]]], object] | None = None,
) -> None:
    """Boot the module, serve until `stop` is set (SIGINT/SIGTERM when not given), then shut everything down.

    `on_ready` gets the bound (host, port)s: the UDP+TCP listeners first, then the DoT ones. A DoT configuration that
    cannot be served raises DotConfigError before the module boots.
    """
    dot = pfsense_dot.read_settings(args.pfsense_config) if args.dot else None
    dot_context = pfsense_dot.server_context(dot) if dot is not None else None
    module = boot(args.module_dir)
    frontend = Frontend(module, parse_hostport(args.upstream), args.timeout)
    try:
        listen = args.listen or ["127.0.0.1"]
        bound = await frontend.start(listen, args.port)
        dot_bound = await frontend.start_dot(listen, dot.port, dot_context) if dot is not None else []
        listening = [f"{host}:{port}" for host, port in bound] + [f"{host}:{port} (DoT)" for host, port in dot_bound]
        shim.log_info(f"listening on {', '.join(listening)}; upstream {args.upstream}")
        if on_ready is not None:
            on_ready(bound + dot_bound)
        if stop is None:
            stop = asyncio.Event()
            for sig in (signal.SIGINT, signal.SIGTERM):
                asyncio.get_running_loop().add_signal_handler(sig, stop.set)
        await stop.wait()
    finally:
        await frontend.stop()
        shutdown(module)


def main(argv: Sequence[str] | None = None) -> int:
    try:
        asyncio.run(serve(parse_args(argv)))
    except pfsense_dot.DotConfigError as exc:
        print(f"pfb_frontend: DNS over TLS: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
