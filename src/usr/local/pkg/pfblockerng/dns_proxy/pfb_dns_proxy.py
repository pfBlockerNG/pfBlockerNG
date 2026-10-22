"""pfBlockerNG DNS decider (issue #3512, #3517): the Python half of pfB-DNS, the gateway's decision service.

pfB-DNS is the Go gateway `pfb-dns`: it owns every client-facing and Unbound-facing socket,
applies the Resolver ACL and forwards to Unbound behind a PROXYv2 header carrying the real client. This process is its
child. It runs the SHIPPED pfb_unbound.py unchanged and answers the DNSBL decisions; for every other query it asks the
gateway to put the client's wire on the way to Unbound and hand the reply back (docs/misc/dns-gateway-protocol.md).

  /usr/local/pkg/pfblockerng/pfb_python.sh -u /usr/local/pkg/pfblockerng/dns_proxy/pfb_dns_proxy.py
      --decision-fd 3 --module-dir /var/unbound --user unbound      (behind pfb-dns, started by it)

  --decision-fd N    the inherited AF_UNIX stream socket N the decision protocol is served on (required)
  --module-dir DIR   dir holding pfb_unbound.py, pfb_dnsbl_regex_rules.py, pfb_unbound.ini and the manifest
                     (default /var/unbound); the process works in that directory, as Unbound's chroot does, and
                     with --observer creates the observer socket pfb_upstream.sock there (see below)
  --user NAME        give up root for NAME before the module boots (default: keep it)
  --no-module        pfB-DNS with DNSBL off: boot no pfb_unbound.py and forward every query to Unbound (see below)
  --observer         create the observer socket (see below); not with --no-module
  --reply-log        with --no-module: log each reply it relays to dns_reply.log, as the module does (see below)

The gateway appends --no-module, --reply-log and --observer to the command it is given, from its own flags of the same
names. Nothing else is a flag: there is no DNS listener, so no address, port, upstream, timeout, DoT or ready-file
option.

--user: the supplementary groups are cleared and group and user are set to NAME's, then the module boots, so every
file it creates belongs to NAME. A non-root process that already is NAME, as the decider the gateway respawns after its
own drop, switches nothing. An unknown NAME (or '') or a switch the OS refuses exits 1 with the reason.

--no-module: no module is imported or booted, so --module-dir does not need to exist (it is read only for the code
record below), the working directory stays where it is and there is no observer socket (--observer is refused with
it). A query that passes the header checks and parses is forwarded to Unbound as it is and Unbound's reply relayed as
it is (silence is a SERVFAIL, as in the module mode); there are no decisions and no MODDONE pass.

--reply-log (only with --no-module): the DNS Reply log of the module mode without the module (issue #3515). The decider
imports the shipped pfb_unbound.py from its own source directory (--module-dir stays unread), reads no feed and decides
nothing, and logs each reply it relays with the module's own row writer into /var/log/pfblockerng/dns_reply.log, so
Reports and Stats read the same rows (client, name, type, TTL, answer, GeoIP). It is for the pfSense DNS Reply Logging
preference being on; without the flag nothing is imported, started or written. Logging cannot change an answer: a row
that fails costs one error line and the rows after it still try. A reply log that cannot start (the shipped source
missing, the log pipeline refusing) is one error line and the decider forwards without it.

Upstream blocks (issue #267): Unbound rewrites every reply it sends (RA set, AA clear, the upstream's EDNS options
dropped), so the decider cannot tell from a relayed reply that the upstream blocked it. While the Resolver forwards,
Unbound runs pfb_upstream_observer.py, which sends each RAW upstream response to the Unix socket pfb_upstream.sock
that the decider creates in --module-dir when it is started with --observer (mode 0600, replacing a stale one); the
decider fires the module's own inplace_cb_query_response on it, so the log line, the Upstream counter and the
forwarding gate are the module's. Without --observer there is no socket, and the observer script, which may stay
loaded in Unbound, does nothing. A socket that cannot be made is one error line, and the decider serves without
upstream-block detection.
Trust boundary: the socket's owner (the user Unbound runs as) and root can write to it, so any process running as
that user can forge a report. A forged report adds an Upstream_Block log row and moves the Upstream counter; it
cannot change an answer, because the callback only observes and logs, and a malformed one is dropped.

The session: the user drop, the boot (not with --no-module) and the reply log (with --reply-log) come first, then the
observer socket (with --observer), then READY goes to the gateway and each QUERY it sends is answered with an ANSWER or
a DROP, a FORWARD/REPLY exchange standing in for the Unbound round trip where the module defers or there is no
module. EOF on the socket exits 0; malformed framing is logged and exits 1. A REPLY is waited for twice
UNBOUND_TIMEOUT.

The code record: frontend sources are fingerprinted before import, and the seven-file fingerprint is captured before
boot. Only after successful boot, while those files remain unchanged, is their md5 hex concatenation published as
pfb_dns_decider.applied in --module-dir, before READY. A change during initialization or a read/write failure removes
the record and its temp file and logs one error, so the next update cannot mistake replacement files for loaded code.

The module expects /var/log/pfblockerng to exist, as on pfSense. Standard library only; Python 3.11+.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import errno
import hashlib
import ipaddress
import json
import logging
import os
import pwd
import secrets
import socket
import stat
import struct
import sys
import traceback
from collections.abc import Awaitable, Callable, Sequence
from time import monotonic
from types import ModuleType
from typing import Any

# Capture frontend sources before importing them: initialization may overlap a package replacing their files.
CODE_RECORD_FILES: tuple[tuple[str | None, str], ...] = tuple(
    (os.path.dirname(os.path.abspath(__file__)), name)
    for name in ("pfb_dns_proxy.py", "decision_service.py", "dns_reply_log.py", "dnswire.py", "unbound_shim.py")
) + ((None, "pfb_unbound.py"), (None, "pfb_dnsbl_regex_rules.py"))
CODE_RECORD = "pfb_dns_decider.applied"  # in --module-dir


def code_fingerprint(module_dir: str | None = None) -> str:
    digests = []
    for directory, name in CODE_RECORD_FILES:
        if directory is None and module_dir is None:
            continue
        with open(os.path.join(directory or module_dir or "", name), "rb") as handle:
            digests.append(hashlib.md5(handle.read()).hexdigest())
    return "".join(digests)


try:
    IMPORTED_CODE_FINGERPRINT = code_fingerprint()
    # Python compiled this script before its imports: disk bytes must still describe the executing module.
    with open(__file__, "rb") as source:
        if (
            compile(source.read(), __file__, "exec", dont_inherit=True, optimize=sys.flags.optimize)
            != sys._getframe().f_code
        ):
            IMPORTED_CODE_FINGERPRINT = None
except (OSError, SyntaxError):
    IMPORTED_CODE_FINGERPRINT = None

import decision_service  # noqa: E402 -- source fingerprint must precede frontend imports
import dns_reply_log  # noqa: E402
import dnswire  # noqa: E402
import unbound_shim as shim  # noqa: E402

LOG_DIR = "/var/log/pfblockerng"
RCODE_FORMERR = 1
RCODE_SERVFAIL = 2
SILENCE_LOG_INTERVAL = 30.0  # seconds between two "no reply from Unbound" lines, whatever Unbound answers in between
UNBOUND_TIMEOUT = 5.0  # the gateway's default wait for Unbound (--timeout): a FORWARD waits twice that for the REPLY
OBSERVER_SOCKET = (
    "pfb_upstream.sock"  # in --module-dir, which is the working directory; pfb_upstream_observer.py SOCKET
)
MAX_REPORT_OPTIONS = 8  # EDNS options in one observer report; an upstream reply carries a handful
MAX_REPORT_OPTION_HEX = 1024  # hex of one option's data: fits a 2 KiB datagram with a typical name
MAX_REPORT_BYTES = 2048  # one report is one datagram from the observer, which never sends more
OBSERVER_RCVBUF = 256 * 1024  # bytes asked for the observer socket, so a burst queues in it
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
    do the other two. Becoming the user the process already is (root to root) works and changes nothing; a non-root
    process that already is `account` (the gateway's respawn after its drop) switches nothing, as it could not."""
    if account.pw_uid != 0 and os.geteuid() == account.pw_uid and os.getegid() == account.pw_gid:
        return
    try:
        os.setgroups([])
        os.setgid(account.pw_gid)
        os.setuid(account.pw_uid)
    except OSError as exc:
        raise DropError(f"cannot switch to user {account.pw_name!r}: {exc}") from None


def write_code_record(module_dir: str, loaded: str | None) -> None:
    """Publish only code unchanged across boot. Read/write failures remove stale records and never stop DNS."""
    record = os.path.join(module_dir, CODE_RECORD)
    try:
        if (
            loaded is None
            or IMPORTED_CODE_FINGERPRINT is None
            or not loaded.startswith(IMPORTED_CODE_FINGERPRINT)
            or code_fingerprint(module_dir) != loaded
        ):
            raise OSError("code changed or could not be read during initialization")
        with open(f"{record}.tmp", "w", encoding="ascii") as handle:
            handle.write(loaded)
        os.replace(f"{record}.tmp", record)
    except OSError as exc:
        shim.log_err(f"cannot write the code record {record}: {exc}")
        for stale in (record, f"{record}.tmp"):
            with contextlib.suppress(OSError):
                os.unlink(stale)


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
    """A bare error reply as Unbound's error_encode builds it: question echoed, RD and CD copied, opcode kept,
    EDNS echoed."""
    flags = dnswire.QR | dnswire.RA | (query.flags & (dnswire.RD | dnswire.CD | dnswire.OPCODE_MASK)) | rcode
    return dnswire.encode(dnswire.Message(query.id, flags, query.questions, additional=_edns_for(query)))


def _answer(query: dnswire.Message, msg: shim.DnsMsg, limit: int | None) -> bytes:
    """The module's replacement message, addressed to this client, with its rcode. AD is not kept: the data is no longer
    the one Unbound validated. Over `limit` bytes (a UDP client's) it becomes the question alone with TC set, so the
    client asks again over TCP."""
    flags = (
        dnswire.QR
        | dnswire.RA
        | (msg.rep.flags & (dnswire.AA | dnswire.TC | 0xF))  # 0xF: the rcode, NXDOMAIN included
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
    if len(data) > MAX_REPORT_BYTES:
        raise ValueError(f"{len(data)} bytes: a report is one datagram of at most {MAX_REPORT_BYTES}")
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


def _module_decides(query: dnswire.Message) -> bool:
    """Whether the module decides this query. Unbound answers a class other than IN or ANY itself, and an additional
    record that is not one root OPT of EDNS version 0, so those go to it unchanged."""
    if any(question.qclass not in (dnswire.CLASS_IN, dnswire.CLASS_ANY) for question in query.questions):
        return False
    return all(
        rr.name == "." and rr.rtype == dnswire.TYPE_OPT and ((rr.ttl >> 16) & 0xFF) == 0  # EDNS version: TTL bits 16-23
        for rr in query.additional
    )


# --- the decider ---------------------------------------------------------------------------------


class Frontend:
    """Decides one client query at a time: the module answers it, or Unbound does through the gateway's `forward`."""

    def __init__(self, module: ModuleType | None, reply_log: ReplyLogger | None = None) -> None:
        self.module = module
        self.reply_log = reply_log  # the module logs its own replies; this is only for module is None
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

    async def _unchanged(self, wire: bytes, query: dnswire.Message, forward: Forward) -> bytes:
        """Unbound's reply to a query it answers itself, relayed as it is; SERVFAIL when it gives none, as the module
        path does for a query Unbound does not answer."""
        reply = await forward(wire)
        return _error(query, RCODE_SERVFAIL) if reply is None else reply

    async def resolve(self, wire: bytes, client_ip: str, forward: Forward, *, datagram: bool = False) -> bytes | None:
        """Answer one client query: parse it, let the module decide, forward to Unbound when it defers.

        None means the packet is dropped. `forward` has the gateway send the client's own bytes to Unbound as that
        client and returns Unbound's reply bytes, or None if there is none. The header is checked before anything is
        parsed, so a hostile packet costs a constant, and every FORMERR is header-only. `datagram` is for a plain-UDP
        client: a reply built here is held to the UDP size it advertised (a relayed reply already is: Unbound saw the
        client's size). The gateway asks Unbound again over TCP for a truncated reply to a SafeSearch chase.
        A query Unbound answers itself (see _module_decides) is forwarded unchanged: its reply is the client's answer.
        """
        if len(wire) < 12 or wire[2] & 0x80:  # no header, or a response: never answered (no reflection loops)
            return None
        msg_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", wire[:12])
        if (flags >> 11) & 0xF:
            return await self._unchanged(wire, dnswire.Message(msg_id, flags), forward)
        if qdcount != 1:
            return _error(dnswire.Message(msg_id, flags), RCODE_FORMERR)
        if flags & dnswire.TC or ancount or nscount or arcount > 1:
            return await self._unchanged(wire, dnswire.Message(msg_id, flags), forward)  # refused before it is read
        try:
            query = dnswire.parse(wire)
        except dnswire.WireError:
            return _error(dnswire.Message(msg_id, flags), RCODE_FORMERR)
        if not _module_decides(query):
            return await self._unchanged(wire, query, forward)

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
                state = await self._chase_cname(query, qstate, forward)
        except Exception:
            shim.log_err(traceback.format_exc())
            state = shim.MODULE_ERROR
        if state != shim.MODULE_FINISHED:
            qstate.return_msg, qstate.return_rcode, relay = None, RCODE_SERVFAIL, None
        return self._send(query, qstate, relay, _udp_limit(query) if datagram else None)

    async def _chase_cname(self, query: dnswire.Message, qstate: shim.module_qstate, forward: Forward) -> int:
        """Emulate MODULE_RESTART_NEXT as the SafeSearch CNAME redirect uses it (safesearch_cname_redirect).

        The module planted `orig -> CNAME -> target` and expects Unbound's iterator to chase the target, then runs
        its post-resolution pass on the combined answer. Unbound will not chase a CNAME a module hands it, so this
        plays the iterator: ask Unbound for the target as the same client, give the module the planted CNAME plus the
        target's answer records, and run that pass once. A chase that finds nothing leaves the CNAME alone in the
        message, which is what makes the module answer with its baked address. The chase carries the client's CD bit
        and EDNS options. Returns the module's state.
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
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, OBSERVER_RCVBUF)
            sock.setblocking(False)
            transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                lambda: _ObserverServer(self), sock=sock
            )
        except BaseException:
            sock.close()
            raise
        self._observer = (transport, path)  # type: ignore[assignment]

    async def stop(self) -> None:
        if self._observer is not None:
            transport, path = self._observer
            self._observer = None
            transport.close()
            with contextlib.suppress(FileNotFoundError):
                os.unlink(path)


class _ObserverServer(asyncio.DatagramProtocol):
    def __init__(self, frontend: Frontend) -> None:
        self.frontend = frontend

    def datagram_received(self, data: bytes, addr: Any) -> None:
        self.frontend.relay_upstream_response(data)


# --- CLI -----------------------------------------------------------------------------------------


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="pfb_dns_proxy", description="pfBlockerNG DNS decider (issues #3512, #3517)")
    parser.add_argument(
        "--decision-fd", type=int, required=True, metavar="N", help="serve the decision protocol on inherited socket N"
    )
    parser.add_argument(
        "--module-dir", default="/var/unbound", help="dir with pfb_unbound.py and its ini (/var/unbound)"
    )
    parser.add_argument("--user", metavar="NAME", help="give up root for this user before the module boots")
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
    return args


def _open_reply_log() -> dns_reply_log.ReplyLog | None:
    """The reply log, or None after one error line: DNS must not go down with its log; a restart would not fix it."""
    try:
        return dns_reply_log.ReplyLog()
    except Exception as exc:
        shim.log_err(f"DNS Reply logging is off, serving without it: {exc!r}")
        return None


async def _serve_observer(frontend: Frontend) -> None:
    """Listen for Unbound's upstream-block reports at OBSERVER_SOCKET, relative: boot() made --module-dir the working
    directory. Without the socket DNS is still served, only upstream blocks go unlogged."""
    try:
        await frontend.serve_observer(OBSERVER_SOCKET)
    except OSError as exc:
        shim.log_err(f"upstream-block detection is off: cannot listen on {OBSERVER_SOCKET}: {exc}")


async def serve_decisions(args: argparse.Namespace) -> None:
    """Serve the decision protocol on the inherited socket until the gateway closes it. The user drop, the module
    boot (not with `args.no_module`), the code record and the reply log (with `args.reply_log`) come first, in that
    order; the observer socket is made only with `args.observer`, before READY. A ProtocolError is logged here and
    re-raised for exit 1; all that was started is shut down."""
    account = lookup_user(args.user) if args.user is not None else None
    sock = socket.socket(fileno=args.decision_fd)
    if account is not None:
        drop_privileges(account)
    module_dir = os.path.abspath(args.module_dir)  # boot() makes it the working directory
    try:
        loaded_code = code_fingerprint(module_dir)
    except OSError:
        loaded_code = None
    module = None if args.no_module else boot(args.module_dir)
    write_code_record(module_dir, loaded_code)
    reply_log = _open_reply_log() if args.reply_log else None
    frontend = Frontend(module, reply_log)
    try:
        if args.observer:
            await _serve_observer(frontend)  # before READY: the gateway serves only once the module can hear Unbound
        await decision_service.serve(sock, frontend.resolve, UNBOUND_TIMEOUT, shim.log_err)
    except decision_service.ProtocolError as exc:
        shim.log_err(f"decision protocol error: {exc}")
        raise
    finally:
        await frontend.stop()
        if module is not None:
            shutdown(module)
        if reply_log is not None:
            reply_log.close()


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = parse_args(argv)
        asyncio.run(serve_decisions(args))
    except DropError as exc:
        print(f"pfb_dns_proxy: {exc}", file=sys.stderr)
        return 1
    except decision_service.ProtocolError:
        return 1  # serve_decisions has logged it
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
