"""Integration: the DNS proxy in front of a REAL Unbound (Docker, host network) using proxy-protocol-port.

No Docker (or an image that cannot be built) is a FAILURE, never a skip: these tests are the evidence that
Unbound accepts the proxy's PROXYv2 header and applies cache, access control and logging to the real client.
"""

from __future__ import annotations

import asyncio
import csv
import shutil
import socket
import struct
import subprocess
import threading
import uuid
from collections.abc import Awaitable, Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import TypeVar

import dnswire
import pfb_dns_proxy
import pfsense_dot
import pytest
from dot_helpers import b64, cert_element, config_xml, dot_exchange, make_certificate
from frontend_constants import ALLOWED, BLOCKED, BYPASSED_CLIENT, DNSBL_IPV4, FILTERED_CLIENT, PROTO_DIR, Booted
from frontend_helpers import (
    WATCHDOG,
    FakeAuthoritative,
    FakeUnbound,
    UpstreamVerdict,
    build_query,
    serve_dot,
    serve_plain,
    tcp_concurrent,
    tcp_exchange,
    udp_concurrent,
    udp_exchange,
)

IMAGE = "pfb-dns-frontend-unbound:trixie-py"
DOCKERFILE = (
    "FROM debian:trixie-slim\n"
    "RUN apt-get update && apt-get install -y --no-install-recommends unbound python3-unbound"
    " && rm -rf /var/lib/apt/lists/*\n"
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


def _conf(port: int, authoritative_port: int, *, observer: bool = False) -> str:
    """Loopback only, PROXYv2 on the same port, access-control applied to the PROXIED client address.

    `observer`: the python module is the upstream observer, as pfSense runs Unbound in proxy mode with forwarding on:
    working directory = the dir holding the script and the proxy's socket, both named relative to it.
    """
    server_extra = '    directory: "/conf"\n    module-config: "python iterator"\n' if observer else ""
    python_clause = 'python:\n    python-script: "pfb_upstream_observer.py"\n' if observer else ""
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
{server_extra}{python_clause}forward-zone:
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
    def __init__(
        self, port: int, tail: LogTail, authoritative: FakeAuthoritative, conf_dir: Path, observed: bool
    ) -> None:
        self.port = port
        self.tail = tail
        self.authoritative = authoritative
        self.zone = authoritative.unbound.zone  # what the fake authoritative answers; tests may add names
        self.verdicts = authoritative.unbound.verdicts  # raw replies it gives instead, by lower-case name
        self.observed = observed  # Unbound runs the upstream observer script
        self.conf_dir = conf_dir

    @property
    def socket_path(self) -> Path:
        """Where the proxy listens for the observer: beside the script, the working directory Unbound runs in."""
        return self.conf_dir / pfb_dns_proxy.OBSERVER_SOCKET


def _run_unbound(tmp_path_factory: pytest.TempPathFactory, *, observer: bool) -> Iterator[RunningUnbound]:
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
    (conf_dir / "unbound.conf").write_text(_conf(port, authoritative.port, observer=observer), encoding="utf-8")
    if observer:
        shutil.copy(PROTO_DIR / "pfb_upstream_observer.py", conf_dir)  # as the installer stages it into /var/unbound
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
        yield RunningUnbound(port, tail, authoritative, conf_dir, observer)
    finally:
        _docker("rm", "-f", name)
        tail.close()
        authoritative.close()


@pytest.fixture(scope="module")
def unbound(tmp_path_factory: pytest.TempPathFactory) -> Iterator[RunningUnbound]:
    """Unbound as the proxy fronts it with the Resolver not forwarding: no python module at all."""
    yield from _run_unbound(tmp_path_factory, observer=False)


@pytest.fixture(scope="module")
def observed_unbound(tmp_path_factory: pytest.TempPathFactory) -> Iterator[RunningUnbound]:
    """Unbound as the proxy fronts it with the Resolver forwarding: the python module is the upstream observer."""
    yield from _run_unbound(tmp_path_factory, observer=True)


AUTHORITATIVE_DELAY = 0.3  # long enough that two queries sent together are both in flight until it elapses


@pytest.fixture
def slow_authoritative(unbound: RunningUnbound) -> Iterator[None]:
    unbound.authoritative.delay = AUTHORITATIVE_DELAY
    try:
        yield
    finally:
        unbound.authoritative.delay = 0.0


def _through_frontend(
    booted: Booted, unbound: RunningUnbound, scenario: Callable[[tuple[str, int]], Awaitable[T]]
) -> T:
    async def main() -> T:
        frontend = pfb_dns_proxy.Frontend(booted.module, ("127.0.0.1", unbound.port), timeout=WATCHDOG)
        [server] = await serve_plain(frontend, ["127.0.0.1"], 0)
        if unbound.observed:
            await frontend.serve_observer(str(unbound.socket_path))
        try:
            return await scenario(server)
        finally:
            await frontend.stop()

    return asyncio.run(main())


def _answers(wire: bytes) -> list[tuple[str, int, bytes]]:
    return [(rr.name, rr.rtype, rr.rdata) for rr in dnswire.parse(wire).answers]


def _dnsbl_rows(booted: Booted) -> list[list[str]]:
    return [next(csv.reader([line])) for name, line in booted.log if name.endswith("dnsbl.log")]


def test_blocked_name_is_answered_by_the_proxy_and_unbound_never_logs_it(
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
    assert any(f"{ALLOWED_CLIENT} {ALLOWED} A IN" in line for line in logged)  # not the proxy's 127.0.0.1


def test_client_in_a_refused_subnet_gets_refused_through_the_proxy(booted: Booted, unbound: RunningUnbound) -> None:
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
        frontend = pfb_dns_proxy.Frontend(booted.module, ("127.0.0.1", unbound.port), timeout=WATCHDOG)
        [server] = await serve_dot(frontend, ["127.0.0.1"], settings.port, pfsense_dot.server_context(settings))
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
    assert not any(f"127.0.0.1 {ALLOWED}" in line for line in logged)  # the TLS client, not the proxy
    assert [row[2] for row in _dnsbl_rows(booted)] == ["blocked.example"]


ROUNDS = {"udp": 20, "tcp": 1}


@pytest.mark.parametrize("filtered_first", [False, True], ids=["bypassed-first", "filtered-first"])
@pytest.mark.parametrize("transport", ["udp", "tcp"])
def test_two_clients_asking_for_one_name_at_once_each_get_their_own_answer(
    gp_booted: Booted, unbound: RunningUnbound, slow_authoritative: None, transport: str, filtered_first: bool
) -> None:
    """Issue #3508 through the proxy: a Group Policy bypassed client and a filtered client query the same
    CNAME-to-a-listed-name at the same moment, Unbound resolves it (once or twice: merging is not asserted), and each
    client is answered from its own verdict: the filtered one the block, the bypassed one Unbound's real reply."""
    exchange = udp_concurrent if transport == "udp" else tcp_concurrent
    clients = [FILTERED_CLIENT, BYPASSED_CLIENT] if filtered_first else [BYPASSED_CLIENT, FILTERED_CLIENT]
    names = [f"shared-{uuid.uuid4().hex[:12]}.example." for _ in range(ROUNDS[transport])]  # fresh: nothing cached
    for name in names:
        unbound.zone[(name, dnswire.TYPE_A)] = [f"{name} 300 IN CNAME {BLOCKED}", f"{BLOCKED} 300 IN A 192.0.2.99"]
    mark = unbound.tail.mark()

    async def scenario(server: tuple[str, int]) -> list[list[bytes]]:
        return [await exchange(server, [(client, build_query(name)) for client in clients]) for name in names]

    rounds = _through_frontend(gp_booted, unbound, scenario)

    for name, replies in zip(names, rounds, strict=True):
        by_client = dict(zip(clients, replies, strict=True))
        assert _answers(by_client[FILTERED_CLIENT]) == [(name, dnswire.TYPE_A, VIP4)], name
        assert _answers(by_client[BYPASSED_CLIENT]) == [
            (name, dnswire.TYPE_CNAME, dnswire.encode_name(BLOCKED)),
            (BLOCKED, dnswire.TYPE_A, bytes([192, 0, 2, 99])),
        ], name
        for client in clients:  # Unbound logs each client query on receipt, merged into one resolution or not
            unbound.tail.wait_for(f"{client} {name} A IN", since=mark)
    # the block was decided for the filtered client alone, once per name: the bypassed client was never blocked
    assert [(row[2], row[3]) for row in _dnsbl_rows(gp_booted)] == [(n.rstrip("."), FILTERED_CLIENT) for n in names]


# --- upstream blocks (issue #267) behind the proxy -------------------------------------------------
#
# Unbound rewrites every reply it sends (RA set, AA clear, the upstream's EDNS options dropped), so the proxy cannot
# classify the reply it relays. In forwarding mode Unbound therefore runs pfb_upstream_observer.py, which reports each
# RAW upstream response to the proxy; the proxy logs it as the module logs one inside Unbound.

NXDOMAIN, SERVFAIL, REFUSED = 3, 2, 5
EDE_BLOCKED, EDE_CENSORED, EDE_FILTERED = 15, 16, 17
NULL_ADDRESS = ("{name} 60 IN A 0.0.0.0",)
REAL_ADDRESS = ("{name} 60 IN A 192.0.2.1",)
SENTINEL = UpstreamVerdict(NXDOMAIN, ede=((EDE_BLOCKED, "sentinel"),))


@dataclass(frozen=True)
class Signature:
    verdict: UpstreamVerdict  # what the upstream answers
    block: tuple[str, str] | None  # the (label, feed) the log row carries; None: not an upstream block
    retried: bool = False  # Unbound asks again after a SERVFAIL/REFUSED and the callback fires, and logs, per try


# Pinned from the module's own verdict on the raw response, observed inside the same Unbound 1.26.1 (not computed here).
SIGNATURES = {
    "nxra": Signature(UpstreamVerdict(NXDOMAIN, ra=False), ("NXRA", "External")),
    "nxdomain-recursive": Signature(UpstreamVerdict(NXDOMAIN), None),
    "nxdomain-authoritative": Signature(UpstreamVerdict(NXDOMAIN, ra=False, aa=True), None),
    "nxdomain-authoritative-and-recursive": Signature(UpstreamVerdict(NXDOMAIN, aa=True), None),
    "ede15-nxdomain": Signature(
        UpstreamVerdict(NXDOMAIN, ede=((EDE_BLOCKED, "Blocked by Quad9"),)), ("EDE15 (Blocked)", "Blocked by Quad9")
    ),
    "ede15-nxdomain-no-text": Signature(
        UpstreamVerdict(NXDOMAIN, ede=((EDE_BLOCKED, ""),)), ("EDE15 (Blocked)", "External")
    ),
    "ede15-null-address": Signature(
        UpstreamVerdict(0, ede=((EDE_BLOCKED, "Blocked"),), answers=NULL_ADDRESS), ("EDE15 (Blocked)", "Blocked")
    ),
    "ede15-nodata": Signature(UpstreamVerdict(0, ede=((EDE_BLOCKED, "Blocked"),)), ("EDE15 (Blocked)", "Blocked")),
    "ede17-nxdomain": Signature(
        UpstreamVerdict(NXDOMAIN, ede=((EDE_FILTERED, "Filtered by X"),)), ("EDE17 (Filtered)", "Filtered by X")
    ),
    "ede17-null-address": Signature(
        UpstreamVerdict(0, ede=((EDE_FILTERED, ""),), answers=NULL_ADDRESS), ("EDE17 (Filtered)", "External")
    ),
    "ede15-and-ede17": Signature(
        UpstreamVerdict(NXDOMAIN, ede=((EDE_FILTERED, "second"), (EDE_BLOCKED, "first"))), ("EDE15 (Blocked)", "first")
    ),
    "ede15-on-nxra": Signature(
        UpstreamVerdict(NXDOMAIN, ra=False, ede=((EDE_BLOCKED, "Blocked nxra"),)), ("EDE15 (Blocked)", "Blocked nxra")
    ),
    "unrecognised-ede-on-nxra": Signature(
        UpstreamVerdict(NXDOMAIN, ra=False, ede=((EDE_CENSORED, "Censored"),)), ("NXRA", "External")
    ),
    "unrecognised-ede-on-an-answer": Signature(
        UpstreamVerdict(0, ede=((EDE_CENSORED, "Censored"),), answers=REAL_ADDRESS), None
    ),
    "null-address-without-ede": Signature(UpstreamVerdict(0, answers=NULL_ADDRESS), None),
    "answer-with-ra-clear-without-ede": Signature(UpstreamVerdict(0, ra=False, answers=REAL_ADDRESS), None),
    "ede15-refused": Signature(
        UpstreamVerdict(REFUSED, ede=((EDE_BLOCKED, "Blocked refused"),)), ("EDE15 (Blocked)", "Blocked refused"), True
    ),
    "ede15-servfail": Signature(
        UpstreamVerdict(SERVFAIL, ede=((EDE_BLOCKED, "Blocked servfail"),)),
        ("EDE15 (Blocked)", "Blocked servfail"),
        True,
    ),
}


def _fresh(prefix: str) -> str:
    """A name nothing has asked for yet (Unbound's cache would answer a repeat without asking upstream)."""
    return f"{prefix}-{uuid.uuid4().hex[:10]}.example."


def _upstream_blocks(booted: Booted, name: str) -> list[tuple[str, str, str, str, str]]:
    """(b_type, label, feed, client, query type) of each upstream-block row logged for `name`."""
    rows = _dnsbl_rows(booted)
    return [(r[5], r[7], r[8], r[3], r[10]) for r in rows if r[5] == "Upstream_Block" and r[2] == name.rstrip(".")]


async def _logged_through(booted: Booted, name: str) -> None:
    """Return once `name`'s upstream-block row is logged: the observer's reports reach the proxy in the order Unbound
    made them, so every report of a query answered BEFORE `name` was asked is logged by then."""
    await asyncio.to_thread(booted.log.wait_for, lambda _log: bool(_upstream_blocks(booted, name)))


@pytest.mark.parametrize("edns", [False, True], ids=["client-without-edns", "client-with-edns"])
@pytest.mark.parametrize("signature", SIGNATURES.values(), ids=SIGNATURES.keys())
def test_each_upstream_signature_is_logged_as_the_module_logs_it_inside_unbound(
    fwd_booted: Booted, observed_unbound: RunningUnbound, signature: Signature, edns: bool
) -> None:
    name, sentinel = _fresh("signature"), _fresh("sentinel")
    observed_unbound.verdicts[name] = signature.verdict
    observed_unbound.verdicts[sentinel] = SENTINEL

    async def scenario(server: tuple[str, int]) -> None:
        await udp_exchange(server, build_query(name, edns=edns), source=ALLOWED_CLIENT)
        await udp_exchange(server, build_query(sentinel), source=ALLOWED_CLIENT)
        await _logged_through(fwd_booted, sentinel)

    _through_frontend(fwd_booted, observed_unbound, scenario)

    rows = _upstream_blocks(fwd_booted, name)
    if signature.block is None:
        assert rows == []
        return
    label, feed = signature.block
    assert set(rows) == {("Upstream_Block", label, feed, ALLOWED_CLIENT, "A")}
    assert signature.retried or len(rows) == 1


def test_an_upstream_block_is_logged_for_the_client_that_asked_over_udp_and_over_tcp(
    fwd_booted: Booted, observed_unbound: RunningUnbound
) -> None:
    udp_name, tcp_name, sentinel = _fresh("udp"), _fresh("tcp"), _fresh("sentinel")
    for name in (udp_name, tcp_name):
        observed_unbound.verdicts[name] = UpstreamVerdict(NXDOMAIN, ede=((EDE_BLOCKED, "Blocked"),))
    observed_unbound.verdicts[sentinel] = SENTINEL

    async def scenario(server: tuple[str, int]) -> None:
        await udp_exchange(server, build_query(udp_name), source=ALLOWED_CLIENT)
        await tcp_exchange(server, build_query(tcp_name), source=ALLOWED_CLIENT_TCP)
        await udp_exchange(server, build_query(sentinel), source=ALLOWED_CLIENT)
        await _logged_through(fwd_booted, sentinel)

    _through_frontend(fwd_booted, observed_unbound, scenario)
    block = ("Upstream_Block", "EDE15 (Blocked)", "Blocked")
    assert _upstream_blocks(fwd_booted, udp_name) == [(*block, ALLOWED_CLIENT, "A")]  # not the proxy's 127.0.0.1
    assert _upstream_blocks(fwd_booted, tcp_name) == [(*block, ALLOWED_CLIENT_TCP, "A")]


def test_an_upstream_block_is_logged_once_when_unbound_fetched_it_not_for_each_client_it_answers(
    fwd_booted: Booted, observed_unbound: RunningUnbound
) -> None:
    """As inside Unbound: the callback fires per upstream fetch, so a repeat answered from the cache logs nothing."""
    name, sentinel = _fresh("cached"), _fresh("sentinel")
    observed_unbound.verdicts[name] = UpstreamVerdict(NXDOMAIN, ede=((EDE_BLOCKED, "Blocked"),))
    observed_unbound.verdicts[sentinel] = SENTINEL
    upstream = observed_unbound.authoritative.unbound

    def asked_upstream() -> int:
        return [dnswire.parse(wire).questions[0].name.lower() for wire in upstream.queries].count(name)

    async def scenario(server: tuple[str, int]) -> int:
        await udp_exchange(server, build_query(name), source=ALLOWED_CLIENT)
        fetched = asked_upstream()
        await udp_exchange(server, build_query(name), source=ALLOWED_CLIENT_TCP)
        await udp_exchange(server, build_query(sentinel), source=ALLOWED_CLIENT)
        await _logged_through(fwd_booted, sentinel)
        return fetched

    fetched = _through_frontend(fwd_booted, observed_unbound, scenario)
    assert (fetched, asked_upstream()) == (1, 1)  # the second client was answered from Unbound's cache
    assert _upstream_blocks(fwd_booted, name) == [("Upstream_Block", "EDE15 (Blocked)", "Blocked", ALLOWED_CLIENT, "A")]


def _ede_codes(message: dnswire.Message) -> list[int]:
    codes = []
    for rr in message.additional:
        data = rr.rdata if rr.rtype == dnswire.TYPE_OPT else b""
        while len(data) >= 4:
            code, size = struct.unpack("!HH", data[:4])
            if code == 15:
                codes.append(struct.unpack("!H", data[4:6])[0])
            data = data[4 + size :]
    return codes


@pytest.mark.parametrize(
    "verdict",
    [UpstreamVerdict(NXDOMAIN, ra=False), UpstreamVerdict(NXDOMAIN, ede=((EDE_BLOCKED, "Blocked"),))],
    ids=["nxra", "ede15"],
)
def test_unbound_hides_the_upstream_signals_from_the_proxy_which_is_why_the_observer_exists(
    fwd_booted: Booted, unbound: RunningUnbound, verdict: UpstreamVerdict
) -> None:
    """The probe result the design rests on, pinned: a reply Unbound builds from an upstream block carries RA set, AA
    clear and no Extended DNS Error, even to a client that sent EDNS, so the proxy cannot classify what it relays. If an
    Unbound release starts passing them on, this fails and the observer can go."""
    name = _fresh("hidden")
    unbound.verdicts[name] = verdict

    async def scenario(server: tuple[str, int]) -> bytes:
        return (await udp_exchange(server, build_query(name, edns=True), source=ALLOWED_CLIENT))[0]

    reply = dnswire.parse(_through_frontend(fwd_booted, unbound, scenario))
    assert (reply.rcode, bool(reply.flags & dnswire.RA), bool(reply.flags & dnswire.AA), _ede_codes(reply)) == (
        NXDOMAIN,
        True,
        False,
        [],
    )
