"""pfBlockerNG DNS proxy (issue #3512): UDP+TCP+DoT, runs the SHIPPED pfb_unbound.py unchanged.

DNSBL decisions are answered here; every other query is forwarded to Unbound (moved off the client port) behind
a PROXYv2 header carrying the real client address, so Unbound's cache, access control and query log see the client.

  /usr/local/pkg/pfblockerng/pfb_python.sh -u /usr/local/pkg/pfblockerng/dns_proxy/pfb_dns_proxy.py
      --listen 192.0.2.1 --listen ::1 --port 53 --upstream 127.0.0.1:5353 --module-dir /var/unbound

  --listen ADDR      address to serve on, repeatable (default 127.0.0.1)
  --port N           client-facing UDP and TCP port (default 53)
  --upstream H:P     Unbound with `proxy-protocol-port: P` (default 127.0.0.1:5353)
  --module-dir DIR   dir holding pfb_unbound.py, pfb_dnsbl_regex_rules.py, pfb_unbound.ini and the manifest
                     (default /var/unbound); the process works in that directory, as Unbound's chroot does, and
                     with --observer creates the observer socket pfb_upstream.sock there (see below)
  --timeout SECONDS  wait for Unbound before answering SERVFAIL (default 5)
  --dot              also serve DNS over TLS, as the pfSense DNS Resolver is set up for (see below)
  --pfsense-config P pfSense config.xml to read the DNS Resolver's DoT settings from (/cf/conf/config.xml)
  --no-module        pfB-DNS with DNSBL off: boot no pfb_unbound.py and forward every query to Unbound (see below)
  --observer         create the observer socket (see below); not with --no-module
  --reply-log        with --no-module: log each reply it relays to dns_reply.log, as the module does (see below)
  --user NAME        give up root for NAME after binding the sockets and before the module boots (default: keep it)

--user: the sockets (port 53, DoT) and the TLS context are made as the starting user, then the supplementary groups
are cleared and group and user are set to NAME's, then the module boots, so every file it creates belongs to NAME.
An unknown NAME (or '') or a switch the OS refuses exits 1 with the reason; nothing is bound for an unknown NAME.

--no-module: no module is imported or booted, so --module-dir is neither read nor needs to exist, the working directory
stays where it is and there is no observer socket (--observer is refused with it). A query that passes the header
checks and parses is forwarded to Unbound as it is and Unbound's reply relayed as it is (silence is a SERVFAIL, as in
the module mode); there are no decisions and no MODDONE pass. Listeners, DoT, the caps, the timeouts and --user are
the same as without it.

--reply-log (only with --no-module): the DNS Reply log of the module mode without the module (issue #3515). The proxy
imports the shipped pfb_unbound.py from its own source directory (--module-dir stays unread), reads no feed and decides
nothing, and logs each reply it relays with the module's own row writer into /var/log/pfblockerng/dns_reply.log, so
Reports and Stats read the same rows (client, name, type, TTL, answer, GeoIP). It is for the pfSense DNS Reply Logging
preference being on; without the flag nothing is imported, started or written. Logging cannot change an answer: a row
that fails costs one error line and the rows after it still try. A reply log that cannot start (the shipped source
missing, the log pipeline refusing) is one error line and the proxy forwards without it.

Upstream blocks (issue #267): Unbound rewrites every reply it sends (RA set, AA clear, the upstream's EDNS options
dropped), so the proxy cannot tell from a relayed reply that the upstream blocked it. While the Resolver forwards,
Unbound runs pfb_upstream_observer.py, which sends each RAW upstream response to the Unix socket pfb_upstream.sock
that the proxy creates in --module-dir when it is started with --observer (mode 0600, replacing a stale one); the proxy
fires the module's own inplace_cb_query_response on it, so the log line, the Upstream counter and the forwarding gate
are the module's. Without --observer there is no socket, and the observer script, which may stay loaded in Unbound,
does nothing. A socket that cannot be made is one error line, and the proxy serves without upstream-block detection.
Trust boundary: the socket's owner (the user Unbound runs as) and root can write to it, so any process running as
that user can forge a report. A forged report adds an Upstream_Block log row and moves the Upstream counter; it
cannot change an answer, because the callback only observes and logs, and a malformed one is dropped.

Each --listen address is bound on its own: one that cannot be bound (no longer an address of this box, port in use)
is logged as a warning and skipped, and DoT is bound per address the same way. It exits 1 only when no address binds
UDP+TCP; DoT that binds nowhere leaves the plain listeners serving.

--dot reads unbound/sslcertref and unbound/tlsport (853 if unset) from config.xml, serves the referenced certificate
on every --listen address at that port (TLS 1.2+), and forwards a DoT query to Unbound like a TCP one, with the TLS
peer's address in the PROXYv2 header. unbound/enablessl is not read: --dot decides, since the Resolver's own DoT is
off while the proxy runs. If the certificate is missing, unusable or its key is passphrase-protected, DoT stays off:
one error line with the reason, and the plain listeners serve (exiting would only make the supervisor relaunch every
5 s with LAN DNS down). There is no self-signed fallback and no passphrase prompt.

Limits: at most 128 TCP and DoT connections at once and 64 per client address, and 512 UDP queries in flight and 256
per client address. An address that is over its own limit is turned away (a UDP query is dropped, a connection is
closed before its DoT handshake) and work that may still finish is never cancelled for it; only stalled work makes
room, for the newcomer of its own address: a UDP query that has waited half --timeout for Unbound, a TCP or DoT client
(one in its handshake too) that has been silent for half the idle timeout and has no query at Unbound. Over a global
limit the same holds for an address that holds as much as the busiest one; an address that holds less takes the
place of the busiest address's oldest UDP query, or of its longest silent client with no query at Unbound, whatever
its age, and is turned away when every client of the busier addresses has a query at Unbound. One log line per
burst. This is a fair share, not immunity: many addresses (spoofed ones, for UDP) that hold little each can still fill
the global limits, and the busiest address pays for them. A DoT handshake must finish within 10 s.

The module expects /var/log/pfblockerng to exist, as on pfSense. Standard library only; Python 3.11+.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import errno
import ipaddress
import json
import logging
import os
import pwd
import secrets
import signal
import socket
import ssl
import stat
import struct
import sys
import traceback
from collections import Counter
from collections.abc import Awaitable, Callable, Coroutine, Sequence
from dataclasses import dataclass
from functools import partial
from time import monotonic
from types import ModuleType
from typing import Any, NamedTuple

import dns_reply_log
import dnswire
import pfsense_dot
import proxyv2
import unbound_shim as shim

LOG_DIR = "/var/log/pfblockerng"
TCP_IDLE_TIMEOUT = 30.0  # Unbound's tcp-idle-timeout default
RCODE_FORMERR = 1
RCODE_SERVFAIL = 2
MAX_QUERY_RRS = 8  # answer, authority and additional records together; a real query carries an OPT, maybe a TSIG
MAX_UDP_INFLIGHT = 512  # concurrent UDP queries, each holding an upstream socket; over it a newcomer is dropped
MAX_UDP_PER_SOURCE = 256  # ... of which one client address may hold this many (a NAT'd network at 400 qps holds ~120)
MAX_TCP_CLIENTS = 128  # TCP and DoT connections at once; each opens one Unbound connection lazily
MAX_TCP_PER_SOURCE = 64  # ... of which one client address may hold this many; over either a newcomer is refused
SILENCE_LOG_INTERVAL = 30.0  # seconds between two "no reply from Unbound" lines, whatever Unbound answers in between
TLS_HANDSHAKE_TIMEOUT = 10.0  # a DoT client that has not finished its handshake by then is dropped (asyncio: 60 s)
TLS_SHUTDOWN_TIMEOUT = 2.0  # a DoT client that does not answer our close by then is cut off (asyncio: 30 s)
OBSERVER_SOCKET = (
    "pfb_upstream.sock"  # in --module-dir, which is the working directory; pfb_upstream_observer.py SOCKET
)
MAX_REPORT_OPTIONS = 8  # EDNS options in one observer report; an upstream reply carries a handful
MAX_REPORT_OPTION_HEX = 8192  # hex digits of one option's data (4 KiB: more than an upstream UDP reply holds)
MAX_REPORT_QNAME = 1024  # a name in text form with every byte escaped as \DDD is at most 4 * 255
Forward = Callable[[bytes], Awaitable[bytes | None]]
ReplyLogger = Callable[[dnswire.Message, str, bytes | None], None]  # query, client, Unbound's reply


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


class DropError(Exception):
    """The user to run as does not exist, or the OS refused to become it; the message is what the operator sees."""


def lookup_user(name: str) -> pwd.struct_passwd:
    try:
        return pwd.getpwnam(name)
    except KeyError:
        raise DropError(f"unknown user {name!r}") from None


def drop_privileges(account: pwd.struct_passwd) -> None:
    """Become `account`: supplementary groups first, then the group, then the user, which takes away the right to
    do the other two. Becoming the user the process already is (root to root) works and changes nothing."""
    try:
        os.setgroups([])
        os.setgid(account.pw_gid)
        os.setuid(account.pw_uid)
    except OSError as exc:
        raise DropError(f"cannot switch to user {account.pw_name!r}: {exc}") from None


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


# --- listening sockets ---------------------------------------------------------------------------


class Listener(NamedTuple):
    host: str
    tcp: socket.socket
    udp: socket.socket | None

    def close(self) -> None:
        for sock in (self.tcp, self.udp):
            if sock is not None:
                sock.close()


class ListenError(Exception):
    """A listening socket could not be made; the message names the address and says why."""


def bind(host: str, port: int, *, udp: bool) -> Listener:
    """Bound sockets for the address `host`, not yet served: TCP listening, and UDP on the same port when `udp`.

    Binding is its own step so it happens as the starting user (port 53 needs root) and before the privilege drop;
    UDP datagrams wait in the socket until serve_listeners() reads them, so none is lost while the module boots.
    """
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    opened: list[socket.socket] = []
    try:
        tcp = socket.create_server((host, port), family=family, backlog=100)
        opened.append(tcp)
        datagrams = None
        if udp:
            datagrams = socket.socket(family, socket.SOCK_DGRAM)
            opened.append(datagrams)
            datagrams.bind((host, tcp.getsockname()[1]))
    except BaseException as exc:
        for sock in opened:
            sock.close()
        if isinstance(exc, OSError):
            reason = os.strerror(exc.errno) if exc.errno else str(exc)  # create_server() decorates exc.strerror
            raise ListenError(f"cannot listen on {host}:{port}: {reason}") from None
        raise
    return Listener(host, tcp, datagrams)


def bind_all(listen: Sequence[str], port: int, *, udp: bool) -> list[Listener]:
    """bind() on each address on its own: one that cannot be bound is logged as a warning and left out, so the result
    may be empty."""
    bound: list[Listener] = []
    for host in listen:
        try:
            bound.append(bind(host, port, udp=udp))
        except ListenError as exc:
            shim.log_warn(exc)
    return bound


# --- replies the proxy builds itself -------------------------------------------------------------


def _opt_of(query: dnswire.Message) -> dnswire.RR | None:
    return next((rr for rr in query.additional if rr.rtype == dnswire.TYPE_OPT), None)


def _edns_for(query: dnswire.Message, *, options: bool = False) -> list[dnswire.RR]:
    """The OPT record for a message this proxy sends: none when the client sent none, else the proxy's UDP size, the
    client's DO bit and, with `options` (the SafeSearch chase), the client's EDNS options such as ECS."""
    opt = _opt_of(query)
    if opt is None:
        return []
    return [dnswire.make_opt(do=bool(opt.ttl & 0x8000), options=opt.rdata if options else b"")]


def _udp_limit(query: dnswire.Message) -> int:
    """The bytes a UDP reply to `query` may have: 512 without EDNS, else the client's size, at least 512 and at most
    the size this proxy advertises."""
    opt = _opt_of(query)
    return 512 if opt is None else min(max(opt.rclass, 512), dnswire.EDNS_UDP_SIZE)


def _error(query: dnswire.Message, rcode: int) -> bytes:
    """A bare error reply as Unbound's error_encode builds it: question echoed, RD and CD copied, EDNS echoed."""
    flags = dnswire.QR | dnswire.RA | (query.flags & (dnswire.RD | dnswire.CD)) | rcode
    return dnswire.encode(dnswire.Message(query.id, flags, query.questions, additional=_edns_for(query)))


def _answer(query: dnswire.Message, msg: shim.DnsMsg, limit: int | None) -> bytes:
    """The module's replacement message, addressed to this client. Over `limit` bytes (a UDP client's) it becomes the
    question alone with TC set, which makes the client ask again over TCP."""
    flags = (
        dnswire.QR
        | dnswire.RA
        | (msg.rep.flags & (dnswire.AA | dnswire.TC))
        | (query.flags & (dnswire.RD | dnswire.CD))
    )
    additional = [*msg.additional, *_edns_for(query)]
    wire = dnswire.encode(dnswire.Message(query.id, flags, query.questions, msg.answer, msg.authority, additional))
    if limit is None or len(wire) <= limit:
        return wire
    return dnswire.encode(dnswire.Message(query.id, flags | dnswire.TC, query.questions, additional=_edns_for(query)))


def _is_u16(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 0xFFFF


def _upstream_report(data: bytes) -> tuple[shim.module_qstate, shim.DnsMsg]:
    """What pythonmod would give inplace_cb_query_response for one observer report: the qstate carrying the upstream's
    EDNS options and the raw response. ValueError if the datagram is not a well-formed report."""
    try:
        report = json.loads(data)
        client, qname, qtype, flags, opts = (report[key] for key in ("client", "qname", "qtype", "flags", "opts"))
    except (ValueError, TypeError, KeyError, RecursionError) as exc:
        raise ValueError(f"not a report: {exc!r}") from exc
    if not (isinstance(qname, str) and 0 < len(qname) <= MAX_REPORT_QNAME and _is_u16(qtype) and _is_u16(flags)):
        raise ValueError("qname, qtype or flags is not valid")
    if not (isinstance(client, str) and isinstance(opts, list) and len(opts) <= MAX_REPORT_OPTIONS):
        raise ValueError("client or opts is not valid")
    if client:
        ipaddress.ip_address(client)  # ValueError
    options = []
    for opt in opts:
        if not (isinstance(opt, list) and len(opt) == 2 and _is_u16(opt[0])):
            raise ValueError("option is not [code, hex data]")
        if not (isinstance(opt[1], str) and len(opt[1]) <= MAX_REPORT_OPTION_HEX):
            raise ValueError("option data is not hex of a sane size")
        options.append(shim.EdnsOpt(opt[0], bytes.fromhex(opt[1])))  # ValueError
    qinfo = shim.query_info(qname, qtype)
    qstate = shim.module_qstate(qinfo, client, 0, 0)
    qstate.edns_opts_back_in_iter = options
    return qstate, shim.DnsMsg(qinfo, flags, [], [], [])


# --- the proxy -----------------------------------------------------------------------------------


@dataclass(slots=True)
class _Client:
    src: str
    active: float  # monotonic time of its connection or last reply: the smaller, the longer it has been silent
    busy: bool = False  # a query of it is with Unbound: it is waiting, not silent


class Frontend:
    def __init__(
        self,
        module: ModuleType | None,
        upstream: tuple[str, int],
        timeout: float = 5.0,
        reply_log: ReplyLogger | None = None,
    ) -> None:
        self.module = module
        self.reply_log = reply_log  # the module logs its own replies; this is only for module is None
        self.upstream = upstream
        self.timeout = timeout
        self.udp_overloaded = False
        self.tcp_overloaded = False
        self._servers: list[asyncio.Server] = []
        self._udp: list[asyncio.DatagramTransport] = []
        self._queries: dict[
            asyncio.Task[None], tuple[str, float]
        ] = {}  # UDP queries in flight, oldest first: source, start
        self._per_source: dict[str, int] = {}  # how many of them each source holds
        self._clients: dict[asyncio.StreamWriter, _Client] = {}
        self._tasks: set[asyncio.Task[None]] = set()
        self._observer: tuple[asyncio.DatagramTransport, str] | None = None
        self._malformed_reported = False
        self._silence_logged = float("-inf")  # when "no reply from Unbound" was last logged

    def _operate(self, qstate: shim.module_qstate, event: int) -> int:
        module = self.module
        assert module is not None  # resolve() relays instead when there is no module
        module.operate(shim.MODULE_ID, event, qstate, None)
        return qstate.ext_state[shim.MODULE_ID]

    async def _ask(self, forward: Forward, wire: bytes, question: dnswire.Question) -> bytes | None:
        """Unbound's reply to the client's query, or None. A reply too short to have a DNS header (a zero-length TCP
        frame) is no reply. Silence is logged at most once per SILENCE_LOG_INTERVAL, whatever Unbound answers in
        between: a flood of queries it never answers would otherwise fill the unrotated log, and so would one that
        it answers a few of."""
        reply = await forward(wire)
        if reply is not None and len(reply) < 12:
            reply = None
        if reply is None and (now := monotonic()) - self._silence_logged >= SILENCE_LOG_INTERVAL:
            self._silence_logged = now
            shim.log_warn(f"no reply from Unbound for {question.name} {dnswire.type_str(question.qtype)}")
        return reply

    async def resolve(
        self, wire: bytes, client_ip: str, forward: Forward, *, over_tcp: Forward | None = None
    ) -> bytes | None:
        """Answer one client query: parse it, let the module decide, forward to Unbound when it defers.

        None means the packet is dropped. `forward` sends the client's own bytes to Unbound (with its PROXYv2
        header) and returns Unbound's reply bytes, or None if there is none. The header is checked before anything
        is parsed, so a hostile packet costs a constant, and every FORMERR is header-only. `over_tcp` is given for a
        UDP client only: it asks Unbound over TCP, for a SafeSearch chase that came back truncated, and its presence
        holds a reply built here to the client's UDP size (a relayed reply already is: Unbound saw the client's size).
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
        if self.module is None:
            reply = await self._ask(forward, wire, question)
            if self.reply_log is not None:
                self.reply_log(query, client_ip, reply)
            return _error(query, RCODE_SERVFAIL) if reply is None else reply
        qstate = shim.module_qstate(
            shim.query_info(question.name, question.qtype, question.qclass), client_ip, 0, query.flags
        )
        relay: bytes | None = None
        try:
            state = self._operate(qstate, shim.MODULE_EVENT_NEW)
            if state == shim.MODULE_WAIT_MODULE:
                upstream_reply = await self._ask(forward, wire, question)
                if upstream_reply is None:
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
                state = await self._chase_cname(query, qstate, forward, over_tcp)
        except Exception:
            shim.log_err(traceback.format_exc())
            state = shim.MODULE_ERROR
        if state != shim.MODULE_FINISHED:
            qstate.return_msg, qstate.return_rcode, relay = None, RCODE_SERVFAIL, None
        return self._send(query, qstate, relay, None if over_tcp is None else _udp_limit(query))

    async def _chase_cname(
        self, query: dnswire.Message, qstate: shim.module_qstate, forward: Forward, over_tcp: Forward | None
    ) -> int:
        """Emulate MODULE_RESTART_NEXT as the SafeSearch CNAME redirect uses it (safesearch_cname_redirect).

        The module planted `orig -> CNAME -> target` and expects Unbound's iterator to chase the target, then runs
        its post-resolution pass on the combined answer. Unbound will not chase a CNAME a module hands it, so this
        plays the iterator: ask Unbound for the target as the same client, give the module the planted CNAME plus the
        target's answer records, and run that pass once. A chase that finds nothing leaves the CNAME alone in the
        message, which is what makes the module answer with its baked address. The chase carries the client's CD bit
        and EDNS options; one that comes back truncated is asked again over `over_tcp`. Returns the module's state.
        """
        planted = qstate.return_msg
        if planted is None or len(planted.answer) != 1 or planted.answer[0].rtype != dnswire.TYPE_CNAME:
            shim.log_err("MODULE_RESTART_NEXT without a planted CNAME referral")
            return shim.MODULE_ERROR
        cname = planted.answer[0]
        target = dnswire.Question(dnswire.name_from_rdata(cname.rdata), planted.qinfo.qtype, planted.qinfo.qclass)
        chase = dnswire.Message(
            secrets.randbits(16),
            dnswire.RD | (query.flags & dnswire.CD),
            [target],
            additional=_edns_for(query, options=True),
        )
        wire = dnswire.encode(chase)
        reply = await forward(wire)
        message = None if reply is None else dnswire.parse(reply)  # an unparseable reply is a SERVFAIL, as above
        if message is not None and message.flags & dnswire.TC and over_tcp is not None:
            reply = await over_tcp(wire)  # too big for a datagram: a truncated reply says nothing about the addresses
            message = None if reply is None else dnswire.parse(reply)
        answers = [] if message is None else message.answers
        qstate.return_msg = shim.DnsMsg(planted.qinfo, planted.rep.flags, [cname, *answers], [], [])
        # A module that asks for yet another restart is not obeyed: the chased answer is final, so that is a SERVFAIL.
        return self._operate(qstate, shim.MODULE_EVENT_MODDONE)

    def _send(
        self, query: dnswire.Message, qstate: shim.module_qstate, relay: bytes | None, limit: int | None
    ) -> bytes:
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
        return _answer(query, msg, limit)

    def relay_upstream_response(self, data: bytes) -> None:
        """Handle one datagram from pfb_upstream_observer.py: fire the module's query_response callback on the raw
        upstream response it reports, so the module logs an upstream block (and counts it) exactly as inside Unbound.
        A malformed datagram is dropped; the first one is warned about, not every one."""
        try:
            report = _upstream_report(data)
        except ValueError as exc:
            if not self._malformed_reported:
                self._malformed_reported = True
                shim.log_warn(f"malformed upstream report from the observer, ignored (further ones silently): {exc}")
            return
        shim.fire_query_response(*report)

    async def serve_observer(self, path: str) -> None:
        """Receive the observer's reports on the Unix datagram socket `path`: mode 0600, so only its owner (the user
        Unbound runs as) can report. A socket left by a previous proxy is replaced; anything else at `path` raises
        OSError and is left alone."""
        try:
            mode = os.lstat(path).st_mode
        except FileNotFoundError:
            pass
        else:
            if not stat.S_ISSOCK(mode):
                raise OSError(errno.EEXIST, f"{path} exists and is not a socket")
            os.unlink(path)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            sock.bind(path)
            os.chmod(path, 0o600)
            sock.setblocking(False)
            transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                lambda: _ObserverServer(self), sock=sock
            )
        except BaseException:
            sock.close()
            raise
        self._observer = (transport, path)  # type: ignore[assignment]

    # --- sockets ---

    def spawn(self, coro: Coroutine[Any, Any, None]) -> asyncio.Task[None]:
        task = asyncio.ensure_future(coro)
        self._tasks.add(task)
        task.add_done_callback(self._task_done)
        return task

    def spawn_udp_query(self, coro: Coroutine[Any, Any, None], src: str) -> None:
        """Run the query of one UDP datagram from `src`, unless the table is full for it.

        Over the limit for `src` the newcomer is dropped without a reply, as a lost datagram is: the queries waiting
        may still be answered. Over the global limit so is it, unless `src` holds fewer queries than the busiest
        address, whose oldest query then goes for it whatever its age: a flood of queries nobody answers can only push
        out its own. The one exception is a query that has waited half the timeout for Unbound, as an unanswered name
        does to the end: the oldest of `src` goes for its newcomer if it is that old. The scan for an address's oldest
        runs only when the table or the address is full, over at most MAX_UDP_INFLIGHT entries.
        """
        now = monotonic()
        held = self._per_source.get(src, 0)
        displaces = False  # the newcomer takes a query of a busier address, whatever its age
        if held >= MAX_UDP_PER_SOURCE:
            owner, why = src, f"{src} has {held}"
        elif len(self._queries) >= MAX_UDP_INFLIGHT:
            busiest = max(self._per_source, key=self._per_source.__getitem__)
            displaces = self._per_source[busiest] > held
            owner, why = busiest if displaces else src, f"{len(self._queries)}"
        else:
            owner, why = None, ""
        if owner is not None:
            oldest = next(task for task, (holder, _) in self._queries.items() if holder == owner)
            reclaim = displaces or now - self._queries[oldest][1] >= self.timeout / 2
            if reclaim:
                oldest.cancel()
                self._forget_udp_query(oldest)
            if not self.udp_overloaded:  # one line per flood, not per packet
                self.udp_overloaded = True
                shim.log_warn(
                    f"{why} UDP queries in flight: a new one takes the place of the oldest of a busier address, or "
                    "of its own once that has waited half the timeout, and is dropped otherwise, until they drain"
                )
            if not reclaim:
                coro.close()
                return
        task = self.spawn(coro)
        self._queries[task] = (src, now)
        self._per_source[src] = self._per_source.get(src, 0) + 1
        task.add_done_callback(self._forget_udp_query)

    def _forget_udp_query(self, task: asyncio.Task[None]) -> None:
        entry = self._queries.pop(task, None)
        if entry is None:  # dropped for a newer query: already forgotten
            return
        src = entry[0]
        if self._per_source[src] == 1:
            del self._per_source[src]
        else:
            self._per_source[src] -= 1
        if not self._queries:
            self.udp_overloaded = False

    def _task_done(self, task: asyncio.Task[None]) -> None:
        self._tasks.discard(task)
        if not task.cancelled() and task.exception() is not None:
            shim.log_err(f"query task failed: {task.exception()!r}")

    async def serve_listeners(
        self, listeners: Sequence[Listener], context: ssl.SSLContext | None = None
    ) -> list[tuple[str, int]]:
        """Start serving sockets from bind(): TCP, and UDP where the listener has one. With `context` the TCP side is
        DoT (the same framing as TCP), each client's handshake running in its handler. Returns the bound (host, port)s.
        """
        loop = asyncio.get_running_loop()
        handler = self._tcp_client if context is None else partial(self._tcp_client, context=context)
        bound = []
        for listener in listeners:
            self._servers.append(await asyncio.start_server(handler, sock=listener.tcp))
            if listener.udp is not None:
                transport, _ = await loop.create_datagram_endpoint(lambda: _UdpServer(self), sock=listener.udp)
                self._udp.append(transport)  # type: ignore[arg-type]
            bound.append((listener.host, listener.tcp.getsockname()[1]))
        return bound

    async def stop(self) -> None:
        for server in self._servers:
            server.close()
        for writer in list(self._clients):
            _hang_up(writer)
        for transport in self._udp:
            transport.close()
        if self._observer is not None:
            transport, path = self._observer
            self._observer = None
            transport.close()
            with contextlib.suppress(FileNotFoundError):
                os.unlink(path)
        tasks = list(self._tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    def _make_room(self, src: str) -> bool:
        """A TCP or DoT connection from `src` is about to be served: False if it is to be turned away.

        Over the limit for `src` it is, so a client that is using its connection is never closed for it; so it is over
        the global one, unless `src` holds fewer connections than the busiest address. Only a client with no query at
        Unbound can be closed for a newcomer: the longest silent of the busiest address, whatever its age, for a
        lighter newcomer; for one that is over its own limit or as heavy as the busiest address, a client of its own
        that has been silent for half the idle timeout. A pass over at most MAX_TCP_CLIENTS entries per connection.
        """
        held = Counter(client.src for client in self._clients.values())
        own = held[src]
        if own >= MAX_TCP_PER_SOURCE:
            why, busier = f"{src} holds {own} TCP connections", False
        elif len(self._clients) >= MAX_TCP_CLIENTS:
            why, busier = f"TCP client limit of {MAX_TCP_CLIENTS} reached", max(held.values()) > own
        else:
            return True
        if not self.tcp_overloaded:  # one line per burst, not per connection
            self.tcp_overloaded = True
            shim.log_warn(
                f"{why}: a new connection takes the place of a silent client of a busier address, or of its own once "
                "that has been silent for half the idle timeout, and is turned away otherwise, until the clients drain"
            )
        now = monotonic()
        victim: asyncio.StreamWriter | None
        if busier:
            candidates = [w for w, client in self._clients.items() if not client.busy and held[client.src] > own]
            victim = max(candidates, key=lambda w: (held[self._clients[w].src], -self._clients[w].active), default=None)
        else:
            candidates = [
                w
                for w, client in self._clients.items()
                if client.src == src and not client.busy and now - client.active >= TCP_IDLE_TIMEOUT / 2
            ]
            victim = min(candidates, key=lambda w: self._clients[w].active, default=None)
        if victim is None:
            return False
        del self._clients[victim]
        _hang_up(victim)
        return True

    async def _tcp_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, context: ssl.SSLContext | None = None
    ) -> None:
        """One client connection: length-framed queries answered one at a time, one upstream connection reused.

        `context` makes it DoT: the TLS handshake runs here, after the limits were applied, and a handshake in
        progress counts as an idle client; one that fails or times out just closes the connection.
        """
        peer, local = writer.get_extra_info("peername"), writer.get_extra_info("sockname")
        if peer is None or local is None:  # the peer reset the connection before this handler ran
            writer.close()
            return
        src, dst = proxy_endpoints(peer[:2], local[:2])
        if not self._make_room(src[0]):
            writer.close()
            return
        upstream = _TcpUpstream(self.upstream, proxyv2.header(src, dst, tcp=True), self.timeout)
        client = self._clients[writer] = _Client(src[0], monotonic())
        try:
            # Nothing may be awaited before this: the ClientHello must still be on the socket, not in `reader`.
            if context is not None:
                await writer.start_tls(context, ssl_handshake_timeout=TLS_HANDSHAKE_TIMEOUT)
            while True:
                await asyncio.sleep(0)  # reading buffered bytes never yields: a pipelined burst would hold the loop
                try:
                    size = struct.unpack("!H", await asyncio.wait_for(reader.readexactly(2), TCP_IDLE_TIMEOUT))[0]
                    wire = await asyncio.wait_for(reader.readexactly(size), TCP_IDLE_TIMEOUT)
                except (asyncio.IncompleteReadError, TimeoutError, OSError):
                    return
                client.busy = True
                reply = await self.resolve(wire, src[0], upstream)
                client.active, client.busy = monotonic(), False
                if reply is not None:
                    writer.write(struct.pack("!H", len(reply)) + reply)
                    await asyncio.wait_for(writer.drain(), TCP_IDLE_TIMEOUT)  # a client that never reads is dropped
        except OSError:
            pass
        finally:
            upstream.close()
            _hang_up(writer)
            self._clients.pop(writer, None)
            if not self._clients:
                self.tcp_overloaded = False


def _hang_up(writer: asyncio.StreamWriter) -> None:
    """Close a client connection. A TLS peer that does not answer our close_notify is cut off after
    TLS_SHUTDOWN_TIMEOUT: StreamWriter.start_tls takes no ssl_shutdown_timeout before Python 3.12, and asyncio's own
    wait is 30 s."""
    tls = writer.get_extra_info("ssl_object") is not None  # gone once the transport is closed
    writer.close()
    if tls:
        asyncio.get_running_loop().call_later(TLS_SHUTDOWN_TIMEOUT, writer.transport.abort)


class _UdpServer(asyncio.DatagramProtocol):
    def __init__(self, frontend: Frontend) -> None:
        self.frontend = frontend
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: Any) -> None:
        self.frontend.spawn_udp_query(self._handle(data, addr), addr[0])

    async def _handle(self, data: bytes, addr: Any) -> None:
        assert self.transport is not None
        src, dst = proxy_endpoints(addr[:2], self.transport.get_extra_info("sockname")[:2])
        forward = partial(
            _forward_udp, self.frontend.upstream, proxyv2.header(src, dst, tcp=False), self.frontend.timeout
        )
        over_tcp = partial(_forward_tcp_once, self.frontend.upstream, src, dst, self.frontend.timeout)
        reply = await self.frontend.resolve(data, src[0], forward, over_tcp=over_tcp)
        if reply is not None:
            self.transport.sendto(reply, addr)


class _ObserverServer(asyncio.DatagramProtocol):
    def __init__(self, frontend: Frontend) -> None:
        self.frontend = frontend

    def datagram_received(self, data: bytes, addr: Any) -> None:
        self.frontend.relay_upstream_response(data)


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


async def _forward_tcp_once(
    upstream: tuple[str, int], src: tuple[str, int], dst: tuple[str, int], timeout: float, wire: bytes
) -> bytes | None:
    """One query to Unbound over a TCP connection of its own, PROXYv2 header first, for a UDP client's query whose
    answer does not fit a datagram; None on silence or error."""
    connection = _TcpUpstream(upstream, proxyv2.header(src, dst, tcp=True), timeout)
    try:
        return await connection(wire)
    finally:
        connection.close()


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
    parser = argparse.ArgumentParser(prog="pfb_dns_proxy", description="pfBlockerNG DNS proxy (issue #3512)")
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
    parser.add_argument("--user", metavar="NAME", help="give up root for this user once the sockets are bound")
    parser.add_argument("--no-module", action="store_true", help="boot no pfb_unbound.py: forward every query")
    parser.add_argument(
        "--observer", action="store_true", help="listen for the upstream observer's reports (needs the module)"
    )
    parser.add_argument(
        "--reply-log", action="store_true", help="log each relayed reply to dns_reply.log (needs --no-module)"
    )
    args = parser.parse_args(argv)
    if args.observer and args.no_module:
        parser.error("--observer cannot be used with --no-module")
    if args.reply_log and not args.no_module:
        parser.error("--reply-log needs --no-module: the module logs its own replies")
    try:
        parse_hostport(args.upstream)
    except ValueError as exc:
        parser.error(str(exc))
    return args


def _dot_setup(config_path: str) -> tuple[pfsense_dot.DotSettings | None, ssl.SSLContext | None]:
    """The DoT settings and TLS context, or (None, None) after one error line when the Resolver's DoT setup cannot be
    served: the plain listeners must not go down with it, and a supervisor restart would not fix it."""
    try:
        settings = pfsense_dot.read_settings(config_path)
        return settings, pfsense_dot.server_context(settings)
    except pfsense_dot.DotConfigError as exc:
        shim.log_err(f"DNS over TLS is off, serving plain DNS only: {exc}")
        return None, None


def _open_reply_log() -> dns_reply_log.ReplyLog | None:
    """The reply log, or None after one error line: DNS must not go down with its log; a restart would not fix it."""
    try:
        return dns_reply_log.ReplyLog()
    except Exception as exc:
        shim.log_err(f"DNS Reply logging is off, serving without it: {exc!r}")
        return None


async def serve(args: argparse.Namespace) -> None:
    """Bind, drop root for `args.user`, boot the module (not with `args.no_module`), serve until SIGINT or SIGTERM,
    then shut everything down.

    The sockets and the TLS context are made as the user the process started as; the drop comes after them and
    before the boot, so what init_standard() and the watchers create belongs to `args.user`. The bound (host, port)s
    are logged in the "listening on" line, UDP+TCP first, then DoT. A user that does not exist, a drop the OS refuses
    (DropError) or no address that can be bound for UDP+TCP (ListenError) raises before the module boots; an address
    that cannot be bound is logged and skipped, and a DoT configuration that cannot be served (DotConfigError) is
    logged as one error line and leaves DoT off. With `args.reply_log` the reply log starts after the drop too, so the
    log file it writes belongs to `args.user`; one that cannot start is logged as one error line and left off.
    """
    account = lookup_user(args.user) if args.user is not None else None
    dot, dot_context = _dot_setup(args.pfsense_config) if args.dot else (None, None)
    listen = args.listen or ["127.0.0.1"]
    listeners: list[Listener] = []
    dot_listeners: list[Listener] = []
    try:
        listeners.extend(bind_all(listen, args.port, udp=True))
        if not listeners:
            raise ListenError("no address could be bound")
        if dot is not None:
            dot_listeners.extend(bind_all(listen, dot.port, udp=False))
        if account is not None:
            drop_privileges(account)
        module = None if args.no_module else boot(args.module_dir)
        reply_log = _open_reply_log() if args.reply_log else None
    except BaseException:
        for listener in (*listeners, *dot_listeners):
            listener.close()
        raise
    frontend = Frontend(module, parse_hostport(args.upstream), args.timeout, reply_log)
    try:
        bound = await frontend.serve_listeners(listeners)
        dot_bound = await frontend.serve_listeners(dot_listeners, dot_context)
        if args.observer:
            try:
                await frontend.serve_observer(OBSERVER_SOCKET)  # relative: boot() made --module-dir the working dir
            except OSError as exc:
                shim.log_err(f"upstream-block detection is off: cannot listen on {OBSERVER_SOCKET}: {exc}")
        stop = asyncio.Event()
        for sig in (signal.SIGINT, signal.SIGTERM):  # before the line below: a supervisor signals on reading it
            asyncio.get_running_loop().add_signal_handler(sig, stop.set)
        listening = [f"{host}:{port}" for host, port in bound] + [f"{host}:{port} (DoT)" for host, port in dot_bound]
        shim.log_info(f"listening on {', '.join(listening)}; upstream {args.upstream}")
        await stop.wait()
    finally:
        await frontend.stop()
        if module is not None:
            shutdown(module)
        if reply_log is not None:
            reply_log.close()


def main(argv: Sequence[str] | None = None) -> int:
    try:
        asyncio.run(serve(parse_args(argv)))
    except (DropError, ListenError) as exc:
        print(f"pfb_dns_proxy: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
