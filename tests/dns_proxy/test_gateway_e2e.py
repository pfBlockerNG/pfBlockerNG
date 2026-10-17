"""End-to-end (issue #3513): the Go gateway, built here with `go build`, in front of a REAL Unbound (Docker, host
network, PROXYv2 port) with the REAL Python decider (`pfb_dns_proxy.py --decision-fd 3`) as its child, the ACL
file written in pfSense's shape.

No Go toolchain and no Docker are FAILURES, never skips: these tests are the evidence that the three pieces
agree. The module writes its logs under /var/log/pfblockerng, which a developer machine does not have (and a test
must not create), so the decider runs with a sitecustomize.py that redirects those paths into the test's tmp dir.
"""

from __future__ import annotations

import asyncio
import csv
import os
import shutil
import signal
import socket
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
from frontend_constants import ALLOWED, BLOCKED, BYPASSED_CLIENT, FILTERED_CLIENT, PROTO_DIR, REPO_ROOT
from frontend_helpers import WATCHDOG, build_query, tcp_concurrent, tcp_exchange, udp_concurrent, udp_exchange
from test_integration_unbound import (  # noqa: F401  (fixtures: the Docker Unbound and its slow zone)
    ALLOWED_CLIENT,
    ALLOWED_CLIENT_TCP,
    REFUSED_CLIENT,
    VIP4,
    RunningUnbound,
    slow_authoritative,
    unbound,
)

GO_DIR = REPO_ROOT / "go" / "pfb_dns_gateway"
BOOT_WATCHDOG = 45.0  # for the decider to boot the real module; under hang_guard's 60 s so this reports what was seen
DENIED_CLIENT = "127.0.0.10"
ALLOWED_ANSWER = (ALLOWED, dnswire.TYPE_A, bytes([192, 0, 2, 77]))

# What pfSense's unbound_acls_config() writes (note the trailing space after `allow_snoop`), plus two custom rows:
# one client refused, one denied.
ACL_FILE = "\n".join([
    "#LAN",
    "access-control: 127.0.0.1/32 allow_snoop",
    "access-control: 127.0.0.0/8 allow_snoop ",
    f"access-control: {REFUSED_CLIENT}/32 refuse",
    f"access-control: {DENIED_CLIENT}/32 deny",
    "",
])  # fmt: skip

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


@pytest.fixture(scope="module")
def gateway_binary(tmp_path_factory: pytest.TempPathFactory) -> Path:
    go = shutil.which("go") or "/usr/local/go/bin/go"
    if not os.access(go, os.X_OK):
        pytest.fail("the Go toolchain is required (this must fail, not skip): `go` not on PATH or in /usr/local/go/bin")
    binary = tmp_path_factory.mktemp("gateway-bin") / "pfb_dns_gateway"
    build = subprocess.run(
        [go, "build", "-o", str(binary), "."],
        cwd=GO_DIR,
        env={**os.environ, "CGO_ENABLED": "0"},
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    if build.returncode != 0:
        pytest.fail(f"cannot build the gateway:\n{build.stdout}\n{build.stderr}")
    return binary


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

    def server(self) -> tuple[str, int]:
        host, _, port = self.wait_for("listening udp+tcp ").removeprefix("listening udp+tcp ").rpartition(":")
        return host, int(port)

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


@pytest.fixture
def gateway(gateway_binary: Path, module_dir: Path, unbound: RunningUnbound, tmp_path: Path) -> Iterator[Running]:
    """The gateway on a loopback port: the REAL decider on the module dir, Unbound's PROXYv2 port upstream.

    Fixtures that change what the module loads at boot (`safesearch_csv`, `bypass_list`) must come first in a test's
    parameters: pytest builds them in order and the module reads its files once.
    """
    acl = tmp_path / "access_lists.conf"
    acl.write_text(ACL_FILE, encoding="utf-8")
    log_dir = tmp_path / "pfb-logs"
    log_dir.mkdir()
    site = tmp_path / "site"
    site.mkdir()
    (site / "sitecustomize.py").write_text(SITECUSTOMIZE, encoding="utf-8")
    env = {**os.environ, "PYTHONPATH": str(site), "PFB_TEST_LOG_DIR": str(log_dir)}
    argv = [
        str(gateway_binary), "--listen", "127.0.0.1", "--port", "0",
        "--upstream", f"127.0.0.1:{unbound.port}", "--acl-file", str(acl),
        "--",
        sys.executable, str(PROTO_DIR / "pfb_dns_proxy.py"), "--decision-fd", "3", "--module-dir", str(module_dir),
    ]  # fmt: skip
    process = GatewayProcess(argv, env)
    try:
        process.wait_for("ready upstream ")
        yield Running(process, process.server(), log_dir)
    finally:
        process.stop()


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


# E7: issue #3508 through the gateway
@pytest.mark.parametrize("transport", ["udp", "tcp"])
def test_bypassed_and_filtered_clients_asking_at_once_each_get_their_own_answer(
    bypass_list: None, gateway: Running, unbound: RunningUnbound, slow_authoritative: None, transport: str
) -> None:
    exchange = udp_concurrent if transport == "udp" else tcp_concurrent
    name = f"shared-{uuid.uuid4().hex[:12]}.example."  # fresh: nothing cached
    unbound.zone[(name, dnswire.TYPE_A)] = [f"{name} 300 IN CNAME {BLOCKED}", f"{BLOCKED} 300 IN A 192.0.2.99"]
    clients = [BYPASSED_CLIENT, FILTERED_CLIENT]
    replies = asyncio.run(exchange(gateway.server, [(client, build_query(name)) for client in clients]))
    by_client = dict(zip(clients, replies, strict=True))
    assert _answers(by_client[FILTERED_CLIENT]) == [(name, dnswire.TYPE_A, VIP4)]
    assert _answers(by_client[BYPASSED_CLIENT]) == [
        (name, dnswire.TYPE_CNAME, dnswire.encode_name(BLOCKED)),
        (BLOCKED, dnswire.TYPE_A, bytes([192, 0, 2, 99])),
    ]
    [row] = gateway.dnsbl_rows(1)  # the block was decided for the filtered client alone
    assert (row[2], row[3]) == (name.rstrip("."), FILTERED_CLIENT)


# hostile input: a header with no question is the decider's to judge
@pytest.mark.parametrize("exchange", [udp_exchange, tcp_exchange], ids=["udp", "tcp"])
def test_query_without_a_question_reaches_the_client_as_formerr_from_the_decider(
    gateway: Running, exchange: Callable[..., Coroutine[Any, Any, Any]]
) -> None:
    header_only = struct.pack("!HHHHHH", 0x0ABC, 0x0100, 0, 0, 0, 0)
    reply = _ask(exchange, gateway.server, header_only, ALLOWED_CLIENT)
    msg_id, flags = struct.unpack("!HH", reply[:4])
    assert (msg_id, flags & 0x8000, flags & 0xF) == (0x0ABC, 0x8000, 1)  # id kept, QR set, FORMERR


# E8
def test_sigterm_ends_the_gateway_and_the_decider_and_the_module_shuts_down(gateway: Running) -> None:
    [decider_pid] = gateway.process.children()
    gateway.process.proc.send_signal(signal.SIGTERM)
    assert gateway.process.finish() == 0
    with pytest.raises(ProcessLookupError):
        os.kill(decider_pid, 0)  # gone, and reaped by the gateway
    assert any(line.endswith(MODULE_EXIT_LINE) for line in gateway.process.lines), gateway.process.lines
