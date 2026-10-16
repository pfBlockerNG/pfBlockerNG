"""Integration: the front end in front of a REAL Unbound (Docker, host network) using proxy-protocol-port.

No Docker (or an image that cannot be built) is a FAILURE, never a skip: these tests are the evidence that
Unbound accepts the front end's PROXYv2 header and applies cache, access control and logging to the real client.
"""

from __future__ import annotations

import asyncio
import csv
import socket
import subprocess
import threading
import uuid
from collections.abc import Awaitable, Callable, Iterator
from pathlib import Path
from typing import TypeVar

import dnswire
import pfb_frontend
import pfsense_dot
import pytest
from dot_helpers import b64, cert_element, config_xml, dot_exchange, make_certificate
from frontend_constants import ALLOWED, BLOCKED, DNSBL_IPV4, Booted
from frontend_helpers import WATCHDOG, FakeAuthoritative, FakeUnbound, build_query, tcp_exchange, udp_exchange

IMAGE = "pfb-dns-frontend-unbound:trixie"
DOCKERFILE = (
    "FROM debian:trixie-slim\n"
    "RUN apt-get update && apt-get install -y --no-install-recommends unbound && rm -rf /var/lib/apt/lists/*\n"
)
BUILD_TIMEOUT = 900
ALLOWED_CLIENT = "127.0.0.5"
ALLOWED_CLIENT_TCP = "127.0.0.6"
REFUSED_CLIENT = "127.0.0.9"
VIP4 = bytes(int(octet) for octet in DNSBL_IPV4.split("."))
T = TypeVar("T")

# What the zone's "authoritative server" says. Unbound answers a local-data CNAME as a lone CNAME (the target is
# not chased), which CNAME validation never looks at; a forwarded zone gives the real CNAME + target reply.
AUTHORITATIVE = {
    (ALLOWED, 1): [f"{ALLOWED} 300 IN A 192.0.2.77"],
    ("alias.example.", 1): ["alias.example. 300 IN CNAME blocked.example.", "blocked.example. 300 IN A 192.0.2.99"],
    (BLOCKED, 1): ["blocked.example. 300 IN A 192.0.2.99"],
    # SafeSearch (SAFESEARCH_CSV): the redirected names, their CNAME targets, and targets with no address.
    ("duck.example.", 1): ["duck.example. 300 IN A 192.0.2.50"],
    ("safe.duck.example.", 1): ["safe.duck.example. 300 IN A 192.0.2.88"],
    ("nodata.example.", 1): ["nodata.example. 300 IN A 192.0.2.51"],
    ("nodata-target.example.", 1): [],
    ("nx.example.", 1): ["nx.example. 300 IN A 192.0.2.52"],  # nx-target.example. is absent: NXDOMAIN
}


def _conf(port: int, authoritative_port: int) -> str:
    """Loopback only, PROXYv2 on the same port, access-control applied to the PROXIED client address."""
    return f"""server:
    verbosity: 1
    interface: 127.0.0.1@{port}
    proxy-protocol-port: {port}
    do-ip6: no
    do-not-query-localhost: no
    chroot: ""
    username: ""
    pidfile: ""
    do-daemonize: no
    use-syslog: no
    logfile: ""
    log-queries: yes
    access-control: 0.0.0.0/0 refuse
    access-control: 127.0.0.0/8 allow
    access-control: {REFUSED_CLIENT}/32 refuse
forward-zone:
    name: "example."
    forward-addr: 127.0.0.1@{authoritative_port}
"""


class LogTail:
    """Follows `docker logs -f`; tests wait on a condition for a line instead of sleeping."""

    def __init__(self, container: str) -> None:
        self.lines: list[str] = []
        self._cond = threading.Condition()
        self._proc = subprocess.Popen(
            ["docker", "logs", "-f", container],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        self._thread = threading.Thread(target=self._pump, daemon=True)
        self._thread.start()

    def _pump(self) -> None:
        assert self._proc.stdout is not None
        for line in self._proc.stdout:
            with self._cond:
                self.lines.append(line.rstrip("\n"))
                self._cond.notify_all()

    def mark(self) -> int:
        with self._cond:
            return len(self.lines)

    def wait_for(self, needle: str, *, since: int = 0) -> list[str]:
        """Lines since `since`, once one of them contains `needle`; raises after the watchdog with what was seen."""
        with self._cond:
            if not self._cond.wait_for(lambda: any(needle in line for line in self.lines[since:]), WATCHDOG):
                raise AssertionError(f"no log line containing {needle!r}; saw {self.lines[since:]!r}")
            return self.lines[since:]

    def close(self) -> None:
        self._proc.kill()
        self._proc.wait()
        self._thread.join()


def _docker(*args: str, stdin: str | None = None, timeout: float = 120) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["docker", *args], input=stdin, capture_output=True, text=True, timeout=timeout, check=False
        )
    except FileNotFoundError:
        pytest.fail("docker is required for the integration test (this must fail, not skip): `docker` not found")


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class RunningUnbound:
    def __init__(self, port: int, tail: LogTail) -> None:
        self.port = port
        self.tail = tail


@pytest.fixture(scope="module")
def unbound(tmp_path_factory: pytest.TempPathFactory) -> Iterator[RunningUnbound]:
    probe = _docker("version", "--format", "{{.Server.Version}}")
    if probe.returncode != 0:
        pytest.fail(f"docker daemon unreachable (this must fail, not skip): {probe.stderr.strip()}")
    if _docker("image", "inspect", IMAGE).returncode != 0:
        build = _docker("build", "-t", IMAGE, "-", stdin=DOCKERFILE, timeout=BUILD_TIMEOUT)
        if build.returncode != 0:
            pytest.fail(f"cannot build the Unbound test image:\n{build.stdout}\n{build.stderr}")

    authoritative = FakeAuthoritative(FakeUnbound(AUTHORITATIVE))
    port = _free_port()
    conf_dir: Path = tmp_path_factory.mktemp("unbound-conf")
    (conf_dir / "unbound.conf").write_text(_conf(port, authoritative.port), encoding="utf-8")
    name = f"pfb-frontend-unbound-{uuid.uuid4().hex[:8]}"
    run = _docker(
        "run", "-d", "--rm", "--network", "host", "--name", name, "-v", f"{conf_dir}:/conf:ro",
        IMAGE, "unbound", "-d", "-c", "/conf/unbound.conf",
    )  # fmt: skip
    if run.returncode != 0:
        authoritative.close()
        pytest.fail(f"cannot start Unbound: {run.stderr}")
    tail = LogTail(name)
    try:
        tail.wait_for("start of service")
        yield RunningUnbound(port, tail)
    finally:
        _docker("rm", "-f", name)
        tail.close()
        authoritative.close()


def _through_frontend(
    booted: Booted, unbound: RunningUnbound, scenario: Callable[[tuple[str, int]], Awaitable[T]]
) -> T:
    async def main() -> T:
        frontend = pfb_frontend.Frontend(booted.module, ("127.0.0.1", unbound.port), timeout=WATCHDOG)
        [server] = await frontend.start(["127.0.0.1"], 0)
        try:
            return await scenario(server)
        finally:
            await frontend.stop()

    return asyncio.run(main())


def _answers(wire: bytes) -> list[tuple[str, int, bytes]]:
    return [(rr.name, rr.rtype, rr.rdata) for rr in dnswire.parse(wire).answers]


def _dnsbl_rows(booted: Booted) -> list[list[str]]:
    return [next(csv.reader([line])) for name, line in booted.log if name.endswith("dnsbl.log")]


def test_blocked_name_is_answered_by_the_front_end_and_unbound_never_logs_it(
    booted: Booted, unbound: RunningUnbound
) -> None:
    mark = unbound.tail.mark()

    async def scenario(server: tuple[str, int]) -> tuple[bytes, bytes]:
        blocked, _ = await udp_exchange(server, build_query(BLOCKED), source=ALLOWED_CLIENT)
        allowed, _ = await udp_exchange(server, build_query(ALLOWED), source=ALLOWED_CLIENT)  # the ordering barrier
        return blocked, allowed

    blocked, allowed = _through_frontend(booted, unbound, scenario)
    assert _answers(blocked) == [(BLOCKED, dnswire.TYPE_A, VIP4)]
    assert _answers(allowed) == [(ALLOWED, dnswire.TYPE_A, bytes([192, 0, 2, 77]))]
    logged = unbound.tail.wait_for(f"{ALLOWED_CLIENT} {ALLOWED} A IN", since=mark)
    assert [line for line in logged if "blocked.example" in line] == []
    assert [row[2] for row in _dnsbl_rows(booted)] == ["blocked.example"]


def test_allowed_name_carries_unbounds_answer_and_unbounds_log_shows_the_real_client(
    booted: Booted, unbound: RunningUnbound
) -> None:
    mark = unbound.tail.mark()

    async def scenario(server: tuple[str, int]) -> tuple[bytes, bytes]:
        udp, _ = await udp_exchange(server, build_query(ALLOWED), source=ALLOWED_CLIENT)
        tcp, _ = await tcp_exchange(server, build_query(ALLOWED), source=ALLOWED_CLIENT_TCP)
        return udp, tcp

    udp, tcp = _through_frontend(booted, unbound, scenario)
    for reply in (udp, tcp):
        parsed = dnswire.parse(reply)
        assert (parsed.rcode, parsed.flags & dnswire.RA) == (0, dnswire.RA)  # Unbound's own flags, relayed
        assert _answers(reply) == [(ALLOWED, dnswire.TYPE_A, bytes([192, 0, 2, 77]))]
    logged = unbound.tail.wait_for(f"{ALLOWED_CLIENT_TCP} {ALLOWED} A IN", since=mark)
    assert any(f"{ALLOWED_CLIENT} {ALLOWED} A IN" in line for line in logged)  # not the front end's 127.0.0.1


def test_client_in_a_refused_subnet_gets_refused_through_the_front_end(booted: Booted, unbound: RunningUnbound) -> None:
    async def scenario(server: tuple[str, int]) -> tuple[bytes, bytes]:
        udp, _ = await udp_exchange(server, build_query(ALLOWED), source=REFUSED_CLIENT)
        tcp, _ = await tcp_exchange(server, build_query(ALLOWED), source=REFUSED_CLIENT)
        return udp, tcp

    udp, tcp = _through_frontend(booted, unbound, scenario)
    assert [dnswire.parse(reply).rcode for reply in (udp, tcp)] == [5, 5]
    assert [dnswire.parse(reply).answers for reply in (udp, tcp)] == [[], []]


def test_cname_chain_reaching_a_blocked_name_gets_the_block_answer(booted: Booted, unbound: RunningUnbound) -> None:
    mark = unbound.tail.mark()

    async def scenario(server: tuple[str, int]) -> bytes:
        return (await udp_exchange(server, build_query("alias.example."), source=ALLOWED_CLIENT))[0]

    reply = _through_frontend(booted, unbound, scenario)
    assert _answers(reply) == [("alias.example.", dnswire.TYPE_A, VIP4)]
    unbound.tail.wait_for(f"{ALLOWED_CLIENT} alias.example. A IN", since=mark)  # Unbound resolved the chain
    [row] = _dnsbl_rows(booted)
    assert (row[0], row[2], row[3]) == ("DNSBL-python", "alias.example", ALLOWED_CLIENT)


def test_safesearch_cname_redirect_gives_the_client_the_cname_and_the_chased_address(
    ss_booted: Booted, unbound: RunningUnbound
) -> None:
    mark = unbound.tail.mark()

    async def scenario(server: tuple[str, int]) -> bytes:
        return (await udp_exchange(server, build_query("duck.example."), source=ALLOWED_CLIENT))[0]

    reply = _through_frontend(ss_booted, unbound, scenario)
    assert _answers(reply) == [
        ("duck.example.", dnswire.TYPE_CNAME, dnswire.encode_name("safe.duck.example.")),
        ("safe.duck.example.", dnswire.TYPE_A, bytes([192, 0, 2, 88])),  # Unbound's answer, not the baked 198.51.100.7
    ]
    logged = unbound.tail.wait_for(f"{ALLOWED_CLIENT} safe.duck.example. A IN", since=mark)  # the chase, as the client
    assert any(f"{ALLOWED_CLIENT} duck.example. A IN" in line for line in logged)


@pytest.mark.parametrize(
    ("name", "target", "baked"),
    [
        ("nodata.example.", "nodata-target.example.", "198.51.100.8"),
        ("nx.example.", "nx-target.example.", "198.51.100.10"),
    ],
    ids=["target-has-no-data", "target-does-not-exist"],
)
def test_safesearch_target_without_an_address_gets_the_modules_baked_address(
    ss_booted: Booted, unbound: RunningUnbound, name: str, target: str, baked: str
) -> None:
    mark = unbound.tail.mark()

    async def scenario(server: tuple[str, int]) -> bytes:
        return (await tcp_exchange(server, build_query(name), source=ALLOWED_CLIENT_TCP))[0]

    reply = _through_frontend(ss_booted, unbound, scenario)
    assert _answers(reply) == [(name, dnswire.TYPE_A, bytes(int(octet) for octet in baked.split(".")))]
    unbound.tail.wait_for(f"{ALLOWED_CLIENT_TCP} {target} A IN", since=mark)  # the chase happened and found nothing


def test_dot_client_gets_dnsbl_and_unbound_answers_and_unbounds_log_shows_the_tls_client(
    booted: Booted, unbound: RunningUnbound, tmp_path: Path
) -> None:
    crt, key = make_certificate(tmp_path)
    trust = tmp_path / "trust.pem"
    trust.write_bytes(crt)
    config = tmp_path / "config.xml"
    config.write_text(config_xml(tlsport=_free_port(), entries=cert_element("5f0a1b2c3d4e5", b64(crt), b64(key))))
    settings = pfsense_dot.read_settings(config)
    mark = unbound.tail.mark()

    async def main() -> tuple[bytes, bytes]:
        frontend = pfb_frontend.Frontend(booted.module, ("127.0.0.1", unbound.port), timeout=WATCHDOG)
        [server] = await frontend.start_dot(["127.0.0.1"], settings.port, pfsense_dot.server_context(settings))
        try:
            blocked, _, _ = await dot_exchange(server, build_query(BLOCKED), trust, source=ALLOWED_CLIENT)
            allowed, _, _ = await dot_exchange(server, build_query(ALLOWED), trust, source=ALLOWED_CLIENT_TCP)
            return blocked, allowed
        finally:
            await frontend.stop()

    blocked, allowed = asyncio.run(main())
    assert _answers(blocked) == [(BLOCKED, dnswire.TYPE_A, VIP4)]
    assert _answers(allowed) == [(ALLOWED, dnswire.TYPE_A, bytes([192, 0, 2, 77]))]
    logged = unbound.tail.wait_for(f"{ALLOWED_CLIENT_TCP} {ALLOWED} A IN", since=mark)
    assert [line for line in logged if "blocked.example" in line] == []
    assert not any(f"127.0.0.1 {ALLOWED}" in line for line in logged)  # the TLS client, not the front end
    assert [row[2] for row in _dnsbl_rows(booted)] == ["blocked.example"]
