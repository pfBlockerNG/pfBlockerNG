"""End-to-end (issue #3513): the Go gateway, built here with `go build`, in front of a REAL Unbound (Docker, host
network, PROXYv2 port) with the REAL Python decider (`pfb_dns_proxy.py --decision-fd 3`) as its child, Unbound's
config laid out as pfSense lays it out (`unbound.conf` includes `access_lists.conf` and has rows of its own).

No Go toolchain and no Docker are FAILURES, never skips: these tests are the evidence that the three pieces
agree. The module writes its logs under /var/log/pfblockerng, which a developer machine does not have (and a test
must not create), so the decider runs with a sitecustomize.py that redirects those paths into the test's tmp dir.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import csv
import http.client
import os
import shutil
import signal
import socket
import ssl
import stat
import struct
import subprocess
import sys
import threading
import time
import uuid
from collections.abc import Callable, Coroutine, Iterator
from pathlib import Path
from typing import Any

import dnswire
import pytest
from dot_helpers import control_socket, dot_exchange, make_certificate, push_certificate, write_certificate_file
from frontend_constants import (
    ALLOWED,
    BLOCKED,
    BYPASSED_CLIENT,
    DNSBL_IPV4,
    FILTERED_CLIENT,
    PROTO_DIR,
    REPO_ROOT,
)
from frontend_helpers import WATCHDOG, build_query, tcp_concurrent, tcp_exchange, udp_concurrent, udp_exchange
from test_integration_unbound import (  # noqa: F401  (fixtures: the Docker Unbound and its gated zone)
    ALLOWED_CLIENT,
    ALLOWED_CLIENT_TCP,
    REFUSED_CLIENT,
    VIP4,
    RunningUnbound,
    _open_gate_once_logged,
    gated_authoritative,
    unbound,
)

GO_DIR = REPO_ROOT / "go" / "pfb_dns_gateway"
BOOT_WATCHDOG = 45.0  # for the decider to boot the real module; under hang_guard's 60 s so this reports what was seen
DENIED_CLIENT = "127.0.0.10"
ALLOWED_ANSWER = (ALLOWED, dnswire.TYPE_A, bytes([192, 0, 2, 77]))

# The control socket takes a push only from uid 0 (ctl.go ctlUID); the pytest job's root step runs that test as root.
NEEDS_ROOT = pytest.mark.skipif(
    os.geteuid() != 0, reason="the control socket takes pushes from uid 0 only; the pytest job's root step runs it"
)

# What pfSense's unbound_acls_config() writes into access_lists.conf (note the trailing space after `allow_snoop`),
# plus one client refused.
ACL_FILE = "\n".join([
    "#LAN",
    "access-control: 127.0.0.1/32 allow_snoop",
    "access-control: 127.0.0.0/8 allow_snoop ",
    "access-control: 192.0.2.0/24 allow ",  # the rig Unbound's own grant: the clients behind a front end
    f"access-control: {REFUSED_CLIENT}/32 refuse",
    "",
])  # fmt: skip
# Rows in unbound.conf itself, outside access_lists.conf: an admin's custom option, here one client denied.
CLAUSE_ROWS = f"access-control: {DENIED_CLIENT}/32 deny\n"

# Redirects what the module opens under /var/log/pfblockerng into PFB_TEST_LOG_DIR; imported first by every
# interpreter that has this directory on PYTHONPATH.
SITECUSTOMIZE = """
import builtins
import os

_open = builtins.open
_prefix = "/var/log/pfblockerng/"
_target = os.environ["PFB_TEST_LOG_DIR"] + "/"


def _redirected(file, *args, **kwargs):
    if isinstance(file, str) and file.startswith(_prefix):
        file = _target + file[len(_prefix):]
    return _open(file, *args, **kwargs)


builtins.open = _redirected
"""
MODULE_EXIT_LINE = "[pfBlockerNG]: pfb_unbound.py script exiting"


def _go_build(tmp: Path, package: str, name: str) -> Path:
    go = shutil.which("go") or "/usr/local/go/bin/go"
    if not os.access(go, os.X_OK):
        pytest.fail("the Go toolchain is required (this must fail, not skip): `go` not on PATH or in /usr/local/go/bin")
    binary = tmp / name
    build = subprocess.run(
        [go, "build", "-o", str(binary), package],
        cwd=GO_DIR,
        env={**os.environ, "CGO_ENABLED": "0"},
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    if build.returncode != 0:
        pytest.fail(f"cannot build {name}:\n{build.stdout}\n{build.stderr}")
    return binary


@pytest.fixture(scope="module")
def gateway_binary(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return _go_build(tmp_path_factory.mktemp("gateway-bin"), ".", "pfb_dns_gateway")


@pytest.fixture(scope="module")
def doq_probe_binary(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return _go_build(tmp_path_factory.mktemp("doq-probe-bin"), "./cmd/pfb_doq_probe", "pfb_doq_probe")


class GatewayProcess:
    """The gateway as a child process; its stderr (and the decider's, which shares it) is read line by line."""

    def __init__(self, argv: list[str], env: dict[str, str]) -> None:
        self.proc = subprocess.Popen(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, env=env
        )
        self.lines: list[str] = []
        self._cond = threading.Condition()
        self._pump_thread = threading.Thread(target=self._pump, daemon=True)
        self._pump_thread.start()

    def _pump(self) -> None:
        assert self.proc.stderr is not None
        for line in self.proc.stderr:
            with self._cond:
                self.lines.append(line.rstrip("\n"))
                self._cond.notify_all()
        self.proc.wait()  # EOF on stderr: the process is ending; wake whoever waits for a line that will never come
        with self._cond:
            self._cond.notify_all()

    def wait_for(self, prefix: str, timeout: float = BOOT_WATCHDOG) -> str:
        """The first line starting with `prefix`; fails with the lines seen if the process ends or the watchdog hits."""

        def seen() -> str | None:
            return next((line for line in self.lines if line.startswith(prefix)), None)

        with self._cond:
            self._cond.wait_for(lambda: seen() is not None or self.proc.poll() is not None, timeout)
            match = seen()
            if match is None:
                state = (
                    f"exited with {self.proc.returncode}" if self.proc.poll() is not None else "STUCK at the watchdog"
                )
                raise AssertionError(f"no line starting {prefix!r} ({state}); saw {self.lines!r}")
            return match

    def listening(self, kind: str) -> tuple[str, int]:
        """The address of the `listening <kind> host:port` line (udp+tcp, dot, doh or doq)."""
        prefix = f"listening {kind} "
        host, _, port = self.wait_for(prefix).removeprefix(prefix).rpartition(":")
        return host, int(port)

    def server(self) -> tuple[str, int]:
        return self.listening("udp+tcp")

    def finish(self) -> int:
        """Wait for the process to end (it must have been told to); returns its exit status, with stderr fully read."""
        status = self.proc.wait(timeout=WATCHDOG)
        self._pump_thread.join(WATCHDOG)
        return status

    def stop(self) -> None:
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=WATCHDOG)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        self._pump_thread.join(WATCHDOG)

    def children(self) -> list[int]:
        # A multi-threaded process lists a child under the thread that forked it, so read every thread's list.
        lists = list(Path(f"/proc/{self.proc.pid}/task").glob("*/children"))
        if lists:
            return sorted({int(pid) for path in lists for pid in path.read_text().split()})
        found = subprocess.run(["pgrep", "-P", str(self.proc.pid)], capture_output=True, text=True, check=False)
        return [int(pid) for pid in found.stdout.split()]


class Running:
    def __init__(self, process: GatewayProcess, server: tuple[str, int], log_dir: Path) -> None:
        self.process = process
        self.server = server
        self.log_dir = log_dir

    def dnsbl_rows(self, count: int) -> list[list[str]]:
        """The decider's dnsbl.log rows once there are `count` of them: the module logs from a thread of its own."""
        path = self.log_dir / "dnsbl.log"
        deadline = time.monotonic() + WATCHDOG
        while True:
            rows = [next(csv.reader([line])) for line in path.read_text().splitlines()] if path.exists() else []
            if len(rows) >= count or time.monotonic() > deadline:
                return rows
            time.sleep(0.02)  # polling a file another process appends to; the watchdog bounds the loop


@contextlib.contextmanager
def _gateway_process(
    gateway_binary: Path,
    module_dir: Path,
    unbound: RunningUnbound,
    tmp_path: Path,
    acl_text: str,
    flags: list[str],
    clause_rows: str = CLAUSE_ROWS,
) -> Iterator[tuple[GatewayProcess, Path]]:
    """The gateway with `flags` added: the REAL decider on the module dir, Unbound's PROXYv2 port upstream.

    The gateway is given an unbound.conf that includes access_lists.conf (`acl_text`) and carries `clause_rows`.
    """
    acl = tmp_path / "access_lists.conf"
    acl.write_text(acl_text, encoding="utf-8")
    conf = tmp_path / "unbound.conf"
    conf.write_text(f'server:\n    include: "{acl}"\n{clause_rows}', encoding="utf-8")
    log_dir = tmp_path / "pfb-logs"
    log_dir.mkdir()
    site = tmp_path / "site"
    site.mkdir()
    (site / "sitecustomize.py").write_text(SITECUSTOMIZE, encoding="utf-8")
    env = {**os.environ, "PYTHONPATH": str(site), "PFB_TEST_LOG_DIR": str(log_dir)}
    argv = [
        str(gateway_binary), "--listen", "127.0.0.1", "--port", "0",
        "--upstream", f"127.0.0.1:{unbound.port}", "--unbound-conf", str(conf), *flags,
        "--",
        sys.executable, str(PROTO_DIR / "pfb_dns_proxy.py"), "--decision-fd", "3", "--module-dir", str(module_dir),
    ]  # fmt: skip
    process = GatewayProcess(argv, env)
    try:
        process.wait_for("ready upstream ")
        yield process, log_dir
    finally:
        process.stop()


@pytest.fixture
def gateway(
    gateway_binary: Path, module_dir: Path, unbound: RunningUnbound, tmp_path: Path, acl_text: str
) -> Iterator[Running]:
    """The gateway on a loopback port: the REAL decider on the module dir, Unbound's PROXYv2 port upstream.

    Fixtures that change what the module loads at boot (`safesearch_csv`, `bypass_list`) must come first in a test's
    parameters: pytest builds them in order and the module reads its files once.
    """
    with _gateway_process(gateway_binary, module_dir, unbound, tmp_path, acl_text, []) as (process, log_dir):
        yield Running(process, process.server(), log_dir)


def _answers(wire: bytes) -> list[tuple[str, int, bytes]]:
    return [(rr.name, rr.rtype, rr.rdata) for rr in dnswire.parse(wire).answers]


def _ask(exchange: Callable[..., Coroutine[Any, Any, Any]], server: tuple[str, int], wire: bytes, source: str) -> bytes:
    reply: bytes = asyncio.run(exchange(server, wire, source=source))[0]
    return reply


def _udp(server: tuple[str, int], name: str, source: str) -> bytes:
    return _ask(udp_exchange, server, build_query(name), source)


def _tcp(server: tuple[str, int], name: str, source: str) -> bytes:
    return _ask(tcp_exchange, server, build_query(name), source)


def test_readiness_lines_name_the_bound_address_and_the_upstream(gateway: Running, unbound: RunningUnbound) -> None:
    assert gateway.server[0] == "127.0.0.1"
    assert gateway.server[1] > 0
    assert gateway.process.wait_for("ready upstream ") == f"ready upstream 127.0.0.1:{unbound.port}"


# E1
def test_blocked_name_gets_the_block_answer_over_udp_and_tcp_and_unbound_never_sees_it(
    gateway: Running, unbound: RunningUnbound
) -> None:
    mark = unbound.tail.mark()
    udp = _udp(gateway.server, BLOCKED, ALLOWED_CLIENT)
    tcp = _tcp(gateway.server, BLOCKED, ALLOWED_CLIENT_TCP)
    _tcp(gateway.server, ALLOWED, ALLOWED_CLIENT_TCP)  # the barrier: Unbound is asked about the next name
    for reply in (udp, tcp):
        assert _answers(reply) == [(BLOCKED, dnswire.TYPE_A, VIP4)]
    logged = unbound.tail.wait_for(f"{ALLOWED_CLIENT_TCP} {ALLOWED} A IN", since=mark)
    assert [line for line in logged if "blocked.example" in line] == []
    rows = gateway.dnsbl_rows(2)
    assert sorted((row[2], row[3]) for row in rows) == [
        ("blocked.example", ALLOWED_CLIENT),
        ("blocked.example", ALLOWED_CLIENT_TCP),
    ]


# E2
def test_allowed_name_carries_unbounds_answer_and_unbounds_log_names_the_client(
    gateway: Running, unbound: RunningUnbound
) -> None:
    mark = unbound.tail.mark()
    udp = _udp(gateway.server, ALLOWED, ALLOWED_CLIENT)
    tcp = _tcp(gateway.server, ALLOWED, ALLOWED_CLIENT_TCP)
    for reply in (udp, tcp):
        parsed = dnswire.parse(reply)
        assert (parsed.rcode, parsed.flags & dnswire.RA) == (0, dnswire.RA)  # Unbound's own flags, relayed
        assert _answers(reply) == [ALLOWED_ANSWER]
    logged = unbound.tail.wait_for(f"{ALLOWED_CLIENT_TCP} {ALLOWED} A IN", since=mark)
    assert any(f"{ALLOWED_CLIENT} {ALLOWED} A IN" in line for line in logged)
    assert not any(f"127.0.0.1 {ALLOWED}" in line for line in logged)  # the real client, not the gateway


# E3: the #3512 leak, closed
def test_refused_client_asking_for_a_blocked_name_gets_refused_never_the_vip(gateway: Running) -> None:
    for send in (_udp, _tcp):
        parsed = dnswire.parse(send(gateway.server, BLOCKED, REFUSED_CLIENT))
        assert (parsed.rcode, parsed.answers) == (5, [])


# E4
def test_denied_client_gets_no_reply_over_udp_and_a_closed_connection_over_tcp(gateway: Running) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as denied:
        denied.bind((DENIED_CLIENT, 0))
        denied.sendto(build_query(BLOCKED), gateway.server)
        # Datagrams are read in order and a deny is judged on receipt: this answered query is the barrier.
        assert _answers(_udp(gateway.server, ALLOWED, ALLOWED_CLIENT)) == [ALLOWED_ANSWER]
        denied.setblocking(False)
        with pytest.raises(BlockingIOError):
            denied.recv(65535)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as stream:
        stream.settimeout(WATCHDOG)
        stream.bind((DENIED_CLIENT, 0))
        stream.connect(gateway.server)
        try:
            assert stream.recv(1) == b""
        except ConnectionResetError:
            pass  # the gateway shut the connection before reading anything


@pytest.fixture(scope="module")
def nomatch_client() -> str:
    """A non-loopback address of this host that reaches the gateway as itself and that no ACL row names.

    A loopback address will not do: Unbound's own defaults allow 127.0.0.0/8 and ::1. An address of an interface that
    is down (docker0 without containers) is sent as the host's primary address instead, so each candidate is tried:
    the one a loopback receiver sees as the datagram's source is the one that works.
    """
    found = subprocess.run(
        ["ip", "-4", "-o", "addr", "show", "up", "scope", "global"],
        capture_output=True, text=True, timeout=60, check=False,
    )  # fmt: skip
    candidates = [
        fields[3].split("/")[0] for fields in (row.split() for row in found.stdout.splitlines()) if fields[3:]
    ]
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
        receiver.bind(("127.0.0.1", 0))
        receiver.settimeout(WATCHDOG)  # a datagram that never comes marks a candidate that cannot send
        for address in candidates:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
                try:
                    sender.bind((address, 0))
                    sender.sendto(b"probe", receiver.getsockname())
                    seen = receiver.recvfrom(16)[1][0]
                except OSError:
                    continue
            if seen == address:
                return address
    pytest.fail(f"no non-loopback IPv4 address of this host reaches a loopback listener as itself: {candidates}")


def _is_refused(wire: bytes) -> bool:
    parsed = dnswire.parse(wire)
    return (parsed.rcode, parsed.answers) == (5, [])


# E9: Unbound refuses a client that matches no `access-control` row; so does the gateway, listed name or not
@pytest.mark.parametrize("send", [_udp, _tcp], ids=["udp", "tcp"])
def test_a_client_no_acl_row_names_is_refused_even_for_a_listed_name(
    gateway: Running, nomatch_client: str, send: Callable[..., bytes]
) -> None:
    assert _answers(send(gateway.server, BLOCKED, ALLOWED_CLIENT)) == [(BLOCKED, dnswire.TYPE_A, VIP4)]  # before-state
    for name in (BLOCKED, ALLOWED):
        wire = send(gateway.server, name, nomatch_client)
        assert _is_refused(wire), (
            f"{nomatch_client} matches no row: want REFUSED with no answer for {name}, got rcode "
            f"{dnswire.parse(wire).rcode} answers {_answers(wire)}"
        )


@pytest.mark.parametrize("transport", ["dot", "doh-get", "doh-post"])
def test_a_client_no_acl_row_names_is_refused_over_dot_and_doh(
    tls_gateway: TlsRunning, nomatch_client: str, transport: str
) -> None:
    assert tls_gateway.a_records(transport, BLOCKED) == [
        f"{BLOCKED} A {DNSBL_IPV4}"
    ]  # before-state: a client with a row
    if transport == "dot":
        wire = tls_gateway.dot_wire(BLOCKED, nomatch_client)
    else:
        wire = tls_gateway.doh_wire(BLOCKED, transport.removeprefix("doh-").upper(), source=nomatch_client)
    assert _is_refused(wire), (
        f"{nomatch_client} matches no row: want REFUSED with no answer over {transport}, got rcode "
        f"{dnswire.parse(wire).rcode} answers {_answers(wire)}"
    )


@pytest.fixture
def granted_gateway(
    gateway_binary: Path, module_dir: Path, unbound: RunningUnbound, tmp_path: Path, nomatch_client: str
) -> Iterator[Running]:
    """The gateway whose unbound.conf itself (no included file) grants `nomatch_client`, as pfBlockerNG's clause."""
    clause = f"access-control: {nomatch_client}/32 allow\n" + CLAUSE_ROWS
    with _gateway_process(gateway_binary, module_dir, unbound, tmp_path, ACL_FILE, [], clause) as (process, log_dir):
        yield Running(process, process.server(), log_dir)


def test_a_client_granted_only_by_a_row_of_unbound_conf_itself_gets_the_vip(
    granted_gateway: Running, nomatch_client: str
) -> None:
    """The same client and name as E9, refused there: only this unbound.conf row (in no included file) differs."""
    for send in (_udp, _tcp):
        assert _answers(send(granted_gateway.server, BLOCKED, nomatch_client)) == [(BLOCKED, dnswire.TYPE_A, VIP4)]


# E5
def test_cname_chain_reaching_a_blocked_name_gets_the_block_answer(gateway: Running, unbound: RunningUnbound) -> None:
    mark = unbound.tail.mark()
    reply = _udp(gateway.server, "alias.example.", ALLOWED_CLIENT)
    assert _answers(reply) == [("alias.example.", dnswire.TYPE_A, VIP4)]
    unbound.tail.wait_for(f"{ALLOWED_CLIENT} alias.example. A IN", since=mark)  # Unbound resolved the chain
    [row] = gateway.dnsbl_rows(1)
    assert (row[0], row[2], row[3]) == ("DNSBL-python", "alias.example", ALLOWED_CLIENT)


# E6
def test_safesearch_name_gets_the_planted_cname_and_the_chased_address(
    safesearch_csv: None, gateway: Running, unbound: RunningUnbound
) -> None:
    mark = unbound.tail.mark()
    reply = _udp(gateway.server, "duck.example.", ALLOWED_CLIENT)
    assert _answers(reply) == [
        ("duck.example.", dnswire.TYPE_CNAME, dnswire.encode_name("safe.duck.example.")),
        ("safe.duck.example.", dnswire.TYPE_A, bytes([192, 0, 2, 88])),  # Unbound's answer, not the baked address
    ]
    logged = unbound.tail.wait_for(f"{ALLOWED_CLIENT} safe.duck.example. A IN", since=mark)  # the chase, as the client
    assert any(f"{ALLOWED_CLIENT} duck.example. A IN" in line for line in logged)


# E7: issue #3508 through the gateway. A Group Policy bypassed client and a filtered client query the same
# CNAME-to-a-listed-name at the same moment, Unbound resolves it (once or twice: merging is not asserted), and each
# client is answered from its own verdict: the filtered one the block, the bypassed one Unbound's real reply. One round
# catches a verdict handed from one asker to the other only about half the time (TCP's two connections are accepted one
# after the other, so even less), so each transport runs 20 rounds on fresh names, in both orders.
ROUNDS = {"udp": 20, "tcp": 20}


@pytest.mark.parametrize("filtered_first", [False, True], ids=["bypassed-first", "filtered-first"])
@pytest.mark.parametrize("transport", ["udp", "tcp"])
def test_bypassed_and_filtered_clients_asking_at_once_each_get_their_own_answer(
    bypass_list: None,
    gateway: Running,
    unbound: RunningUnbound,
    gated_authoritative: None,
    transport: str,
    filtered_first: bool,
) -> None:
    exchange = udp_concurrent if transport == "udp" else tcp_concurrent
    clients = [FILTERED_CLIENT, BYPASSED_CLIENT] if filtered_first else [BYPASSED_CLIENT, FILTERED_CLIENT]
    names = [f"shared-{uuid.uuid4().hex[:12]}.example." for _ in range(ROUNDS[transport])]  # fresh: nothing cached
    for name in names:
        unbound.zone[(name, dnswire.TYPE_A)] = [f"{name} 300 IN CNAME {BLOCKED}", f"{BLOCKED} 300 IN A 192.0.2.99"]
    mark = unbound.tail.mark()

    async def scenario() -> list[list[bytes]]:
        rounds = []
        for name in names:
            # the reply waits for the gate: both queries are in flight together, however fast Unbound is
            gate = unbound.authoritative.gate = threading.Event()
            opened = asyncio.create_task(asyncio.to_thread(_open_gate_once_logged, unbound, gate, clients, name, mark))
            rounds.append(await exchange(gateway.server, [(client, build_query(name)) for client in clients]))
            await opened
        return rounds

    rounds = asyncio.run(scenario())

    for name, replies in zip(names, rounds, strict=True):
        by_client = dict(zip(clients, replies, strict=True))
        assert _answers(by_client[FILTERED_CLIENT]) == [(name, dnswire.TYPE_A, VIP4)], name
        assert _answers(by_client[BYPASSED_CLIENT]) == [
            (name, dnswire.TYPE_CNAME, dnswire.encode_name(BLOCKED)),
            (BLOCKED, dnswire.TYPE_A, bytes([192, 0, 2, 99])),
        ], name
    # the block was decided for the filtered client alone, once per name: the bypassed client was never blocked
    rows = gateway.dnsbl_rows(len(names))
    assert [(row[2], row[3]) for row in rows] == [(n.rstrip("."), FILTERED_CLIENT) for n in names]


# hostile input: a header with no question is the decider's to judge
@pytest.mark.parametrize("exchange", [udp_exchange, tcp_exchange], ids=["udp", "tcp"])
def test_query_without_a_question_reaches_the_client_as_formerr_from_the_decider(
    gateway: Running, exchange: Callable[..., Coroutine[Any, Any, Any]]
) -> None:
    header_only = struct.pack("!HHHHHH", 0x0ABC, 0x0100, 0, 0, 0, 0)
    reply = _ask(exchange, gateway.server, header_only, ALLOWED_CLIENT)
    msg_id, flags = struct.unpack("!HH", reply[:4])
    assert (msg_id, flags & 0x8000, flags & 0xF) == (0x0ABC, 0x8000, 1)  # id kept, QR set, FORMERR


# Unbound refuses a truncated query before it reads the question: the blocked name gets its FORMERR, not the block.
@pytest.mark.parametrize(
    ("exchange", "source"), [(udp_exchange, ALLOWED_CLIENT), (tcp_exchange, ALLOWED_CLIENT_TCP)], ids=["udp", "tcp"]
)
def test_a_truncated_query_for_a_blocked_name_gets_unbounds_formerr_from_the_real_unbound(
    gateway: Running, exchange: Callable[..., Coroutine[Any, Any, Any]], source: str
) -> None:
    query = bytearray(build_query(BLOCKED))
    query[2] |= 0x02  # the TC bit
    reply = dnswire.parse(_ask(exchange, gateway.server, bytes(query), source))
    assert (reply.rcode, reply.answers) == (1, [])


# Unbound answers an opcode it does not implement itself (NOTIMP), so the decider must forward it and not block it.
@pytest.mark.parametrize(
    ("exchange", "source"), [(udp_exchange, ALLOWED_CLIENT), (tcp_exchange, ALLOWED_CLIENT_TCP)], ids=["udp", "tcp"]
)
@pytest.mark.parametrize("opcode", [5, 1, 2], ids=["update", "iquery", "status"])
def test_an_opcode_unbound_does_not_implement_gets_unbounds_notimp_for_a_blocked_name(
    gateway: Running, exchange: Callable[..., Coroutine[Any, Any, Any]], source: str, opcode: int
) -> None:
    query = bytearray(build_query(BLOCKED))
    query[2] |= opcode << 3  # the opcode sits in bits 11-14 of the header flags
    reply = dnswire.parse(_ask(exchange, gateway.server, bytes(query), source))
    assert (reply.rcode, reply.answers) == (4, [])


# E8
def test_sigterm_ends_the_gateway_and_the_decider_and_the_module_shuts_down(gateway: Running) -> None:
    [decider_pid] = gateway.process.children()
    gateway.process.proc.send_signal(signal.SIGTERM)
    assert gateway.process.finish() == 0
    with pytest.raises(ProcessLookupError):
        os.kill(decider_pid, 0)  # gone, and reaped by the gateway
    assert any(line.endswith(MODULE_EXIT_LINE) for line in gateway.process.lines), gateway.process.lines


# --- DoT, DoH and DoQ with the Resolver's certificate (S4b) ------------------------------------------------------

FRONT_END_CLIENT = "192.0.2.55"  # a client address behind a trusted front end (PROXYv2): not a loopback one
FORWARDED_CLIENT = "192.0.2.56"  # the same through X-Forwarded-For
LOOPBACK_REFUSED_ACL = "access-control: 127.0.0.0/8 allow_snoop\naccess-control: 127.0.0.1/32 refuse\n"
PROXY_V2_SIGNATURE = b"\r\n\r\n\x00\r\nQUIT\n"


def _proxy_v2(src: str, sport: int, dst: str, dport: int) -> bytes:
    """The PROXYv2 header (spec section 2.2) a trusted front end puts in front of a TCP connection."""
    addresses = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!HH", sport, dport)
    return PROXY_V2_SIGNATURE + bytes([0x21, 0x11]) + struct.pack("!H", len(addresses)) + addresses


class _FrontEndConnection(http.client.HTTPSConnection):
    """HTTPS to the DoH listener over a socket that starts with `header` (empty = nothing), from `source`."""

    def __init__(self, port: int, trust: Path, source: str, header: bytes) -> None:
        super().__init__("localhost", port, timeout=WATCHDOG)
        self._trust = ssl.create_default_context(cafile=str(trust))
        self._source = source
        self._header = header

    def connect(self) -> None:
        sock = socket.create_connection(("127.0.0.1", self.port), self.timeout, (self._source, 0))
        if self._header:
            sock.sendall(self._header)
        self.sock = self._trust.wrap_socket(sock, server_hostname=self.host)


class TlsRunning(Running):
    """The gateway with DoT, DoH (127.0.0.1 trusted as a front end) and DoQ on loopback ports."""

    def __init__(self, base: Running, ca: Path, probe: Path, ctl: Path) -> None:
        super().__init__(base.process, base.server, base.log_dir)
        self.ctl = ctl
        self.dot = base.process.listening("dot")
        self.doh = base.process.listening("doh")
        self.doq = base.process.listening("doq")
        self.ca = ca
        self.probe = probe

    def dot_wire(self, name: str, source: str) -> bytes:
        reply: bytes = asyncio.run(dot_exchange(self.dot, build_query(name), self.ca, source=source))[0]
        return reply

    def doh_wire(self, name: str, method: str, *, source: str = "127.0.0.1", front_end: str | None = None,
                 forwarded_for: str | None = None) -> bytes:  # fmt: skip
        wire = build_query(name)
        header = _proxy_v2(front_end, 51000, "192.0.2.1", 443) if front_end else b""
        headers = {"Accept": "application/dns-message"}
        if forwarded_for:
            headers["X-Forwarded-For"] = forwarded_for
        conn = _FrontEndConnection(self.doh[1], self.ca, source, header)
        try:
            if method == "GET":
                conn.request(
                    "GET", "/dns-query?dns=" + base64.urlsafe_b64encode(wire).rstrip(b"=").decode(), headers=headers
                )
            else:
                conn.request(
                    "POST", "/dns-query", body=wire, headers={**headers, "Content-Type": "application/dns-message"}
                )
            response = conn.getresponse()
            assert (response.status, response.getheader("Content-Type")) == (200, "application/dns-message")
            body: bytes = response.read()
            return body
        finally:
            conn.close()

    def doq_lines(self, name: str) -> list[str]:
        """pfb_doq_probe's output for `name`: `rcode X`, then one `answer ...` line per record."""
        run = subprocess.run(
            [str(self.probe), "-server", f"{self.doq[0]}:{self.doq[1]}", "-name", name, "-ca", str(self.ca)]
            + ["-sni", "localhost", "-timeout", f"{WATCHDOG}s"],
            capture_output=True, text=True, timeout=2 * WATCHDOG, check=False,
        )  # fmt: skip
        assert run.returncode == 0, (run.returncode, run.stdout, run.stderr)
        return run.stdout.splitlines()

    def a_records(self, transport: str, name: str, source: str = ALLOWED_CLIENT) -> list[str]:
        """The A records answering `name` over `transport`, as `name A address` lines."""
        if transport == "doq":
            lines = self.doq_lines(name)
            assert lines[0] == "rcode NOERROR", lines
            return [line.removeprefix("answer ") for line in lines[1:]]
        if transport == "dot":
            wire = self.dot_wire(name, source)
        elif transport == "doh-get":
            wire = self.doh_wire(name, "GET", source=source)
        elif transport == "doh-post":
            wire = self.doh_wire(name, "POST", source=source)
        elif transport == "doh-proxy":
            wire = self.doh_wire(name, "GET", front_end=FRONT_END_CLIENT)
        else:
            wire = self.doh_wire(name, "GET", forwarded_for=FORWARDED_CLIENT)
        assert dnswire.parse(wire).rcode == 0
        return [f"{n} A {socket.inet_ntoa(rdata)}" for n, rtype, rdata in _answers(wire) if rtype == dnswire.TYPE_A]


@pytest.fixture
def acl_text() -> str:
    return ACL_FILE


@pytest.fixture
def tls_gateway(
    gateway_binary: Path,
    doq_probe_binary: Path,
    module_dir: Path,
    unbound: RunningUnbound,
    tmp_path: Path,
    acl_text: str,
) -> Iterator[TlsRunning]:
    """The gateway with the certificate file pfBlockerNG writes serving DoT, DoH and DoQ."""
    certificate, key = make_certificate(tmp_path)
    pem = write_certificate_file(tmp_path, certificate, key)
    with control_socket() as ctl:
        flags = [
            "--dot", "--dot-port", "0", "--tls-pem", str(pem), "--ctl-socket", str(ctl),
            "--doh-listen", "127.0.0.1", "--doh-port", "0", "--doh-trusted", "127.0.0.1/32",
            "--doq-listen", "127.0.0.1", "--doq-port", "0",
        ]  # fmt: skip
        with _gateway_process(gateway_binary, module_dir, unbound, tmp_path, acl_text, flags) as (process, log_dir):
            yield TlsRunning(
                Running(process, process.server(), log_dir), tmp_path / "server.crt", doq_probe_binary, ctl
            )


@NEEDS_ROOT
def test_a_certificate_pushed_on_the_control_socket_is_served_by_the_next_handshake_and_a_bad_push_changes_nothing(
    tls_gateway: TlsRunning, tmp_path: Path
) -> None:
    renewed = tmp_path / "renewed"
    renewed.mkdir()
    certificate, key = make_certificate(renewed)
    # The socket and its directory as the gateway made them: nobody but the user that started it
    assert stat.S_IMODE(tls_gateway.ctl.stat().st_mode) == 0o600
    assert stat.S_IMODE(tls_gateway.ctl.parent.stat().st_mode) == 0o700

    assert push_certificate(tls_gateway.ctl, certificate, key) == "ok"

    reply = asyncio.run(
        dot_exchange(tls_gateway.dot, build_query(ALLOWED), renewed / "server.crt", source=ALLOWED_CLIENT_TCP)
    )[0]
    assert dnswire.parse(reply).rcode == 0, "a handshake that trusts only the pushed certificate succeeds"
    with pytest.raises(ssl.SSLCertVerificationError):
        asyncio.run(dot_exchange(tls_gateway.dot, build_query(ALLOWED), tls_gateway.ca, source=ALLOWED_CLIENT_TCP))
    assert push_certificate(tls_gateway.ctl, certificate, b"not a key").startswith("error: ")
    reply = asyncio.run(
        dot_exchange(tls_gateway.dot, build_query(ALLOWED), renewed / "server.crt", source=ALLOWED_CLIENT_TCP)
    )[0]
    assert dnswire.parse(reply).rcode == 0, "the refused push left the pushed certificate in place"


def test_readiness_lines_name_every_tls_listener_before_ready(tls_gateway: TlsRunning) -> None:
    lines = tls_gateway.process.lines
    kinds = [line.split()[1] for line in lines if line.startswith("listening ")]
    assert kinds == ["udp+tcp", "dot", "doh", "doq"], lines
    assert max(i for i, line in enumerate(lines) if line.startswith("listening ")) < next(
        i for i, line in enumerate(lines) if line.startswith("ready upstream ")
    )
    assert all(port > 0 for _, port in (tls_gateway.dot, tls_gateway.doh, tls_gateway.doq))


# X1
@pytest.mark.parametrize("transport", ["dot", "doh-get", "doh-post", "doq"])
def test_blocked_name_gets_the_block_answer_over_every_tls_transport(
    tls_gateway: TlsRunning, unbound: RunningUnbound, transport: str
) -> None:
    mark = unbound.tail.mark()
    assert tls_gateway.a_records(transport, BLOCKED) == [f"{BLOCKED} A {DNSBL_IPV4}"]
    _tcp(tls_gateway.server, ALLOWED, ALLOWED_CLIENT_TCP)  # the barrier: Unbound is asked about the next name
    logged = unbound.tail.wait_for(f"{ALLOWED_CLIENT_TCP} {ALLOWED} A IN", since=mark)
    assert [line for line in logged if "blocked.example" in line] == []


# X2
@pytest.mark.parametrize(
    ("transport", "logged_client"),
    [("dot", ALLOWED_CLIENT_TCP), ("doh-proxy", FRONT_END_CLIENT), ("doh-xff", FORWARDED_CLIENT), ("doq", "127.0.0.1")],
)
def test_allowed_name_over_every_tls_transport_carries_unbounds_answer_and_log_names_the_client(
    tls_gateway: TlsRunning, unbound: RunningUnbound, transport: str, logged_client: str
) -> None:
    mark = unbound.tail.mark()
    source = ALLOWED_CLIENT_TCP if transport == "dot" else "127.0.0.1"
    assert tls_gateway.a_records(transport, ALLOWED, source) == [f"{ALLOWED} A 192.0.2.77"]
    logged = unbound.tail.wait_for(f"{logged_client} {ALLOWED} A IN", since=mark)
    if logged_client != "127.0.0.1":  # the client, never the gateway's own address
        assert not any(f"127.0.0.1 {ALLOWED}" in line for line in logged)


# X3
@pytest.mark.parametrize("via", ["front_end", "forwarded_for"])
def test_refused_client_over_doh_gets_refused_never_the_vip(tls_gateway: TlsRunning, via: str) -> None:
    wire = tls_gateway.doh_wire(BLOCKED, "GET", **{via: REFUSED_CLIENT})
    parsed = dnswire.parse(wire)
    assert (parsed.rcode, parsed.answers) == (5, [])


# X4
def test_refused_client_over_dot_gets_refused_never_the_vip(tls_gateway: TlsRunning) -> None:
    parsed = dnswire.parse(tls_gateway.dot_wire(BLOCKED, REFUSED_CLIENT))
    assert (parsed.rcode, parsed.answers) == (5, [])


@pytest.mark.parametrize("acl_text", [LOOPBACK_REFUSED_ACL])
def test_refused_client_over_doq_gets_refused_never_the_vip(tls_gateway: TlsRunning, acl_text: str) -> None:
    assert tls_gateway.doq_lines(BLOCKED) == ["rcode REFUSED"]


def test_denied_client_gets_a_closed_connection_before_any_tls_handshake(tls_gateway: TlsRunning) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as stream:
        stream.settimeout(WATCHDOG)
        stream.bind((DENIED_CLIENT, 0))
        stream.connect(tls_gateway.dot)
        try:
            assert stream.recv(1) == b""
        except ConnectionResetError:
            pass  # the gateway shut the connection before reading anything


def test_sigterm_with_tls_listeners_ends_the_gateway_and_the_decider(tls_gateway: TlsRunning) -> None:
    [decider_pid] = tls_gateway.process.children()
    tls_gateway.process.proc.send_signal(signal.SIGTERM)
    assert tls_gateway.process.finish() == 0
    with pytest.raises(ProcessLookupError):
        os.kill(decider_pid, 0)
