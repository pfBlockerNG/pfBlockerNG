"""The real Unbound (Docker, host network, proxy-protocol-port) the gateway's end-to-end tests run against, with a fake
authoritative server behind it: test_gateway_e2e.py, test_gateway_modes.py, test_gateway_chase.py and
test_gateway_upstream_blocks.py import their fixtures from here.

No Docker (or an image that cannot be built) is a FAILURE, never a skip: those tests are the evidence that Unbound
accepts the gateway's PROXYv2 header and applies cache, access control and logging to the real client.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import threading
import uuid
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import TypeVar

import pfb_dns_proxy
import pytest
from dot_helpers import retry_on_taken_port
from frontend_constants import ALLOWED, BLOCKED, DNSBL_IPV4, PROTO_DIR
from frontend_helpers import (
    WATCHDOG,
    FakeAuthoritative,
    FakeUnbound,
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
# SafeSearch target with 94 addresses: 1,569 bytes in the reply, more than any UDP size the proxy advertises (1232).
BIG_ADDRESSES = [bytes([10, 1, 0, n]) for n in range(1, 95)]
AUTHORITATIVE[("big.example.", 1)] = ["big.example. 300 IN A 192.0.2.60"]
AUTHORITATIVE[("big-target.example.", 1)] = [
    f"big-target.example. 300 IN A {'.'.join(map(str, a))}" for a in BIG_ADDRESSES
]


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
    access-control: 192.0.2.0/24 allow
    access-control: {REFUSED_CLIENT}/32 refuse
{server_extra}{python_clause}forward-zone:
    name: "example."
    forward-addr: 127.0.0.1@{authoritative_port}
"""


def first_needle_seen(needles: tuple[str, ...], lines: list[str]) -> str | None:
    """The first of `needles` (lower case) that some line contains, in any case: Unbound spells "address already in use"
    both ways, "error: bind: address already in use" for one socket and "can't bind socket: Address already in use"."""
    return next((n for n in needles if any(n in line.lower() for line in lines)), None)


class LogTail:
    """Follows `docker logs -f`; tests wait on a condition for a line instead of sleeping. The stream ends when the
    container stops, and the waits say so at once: a dead container is 'log ended', never a stuck run."""

    def __init__(self, container: str) -> None:
        self.lines: list[str] = []
        self.ended = False
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
        with self._cond:
            self.ended = True
            self._cond.notify_all()

    def mark(self) -> int:
        with self._cond:
            return len(self.lines)

    def _wait_until(self, expected: str, found: Callable[[list[str]], T | None], since: int = 0) -> T:
        """What `found` returns for the lines since `since`, once it does. A stream that ends first means the container
        stopped; no result within the watchdog is a stuck run. Both raise with the lines seen."""
        with self._cond:
            if not self._cond.wait_for(lambda: found(self.lines[since:]) is not None or self.ended, WATCHDOG):
                raise AssertionError(
                    f"STUCK/ENVIRONMENT: no {expected} within {WATCHDOG:g} s; saw {self.lines[since:]!r}"
                )
            result = found(self.lines[since:])
            if result is None:
                raise AssertionError(f"log ended (the container stopped) before {expected}; saw {self.lines[since:]!r}")
            return result

    def wait_for(self, needle: str, *, since: int = 0) -> list[str]:
        """Lines since `since`, once one of them contains `needle`."""

        def seen(lines: list[str]) -> list[str] | None:
            return lines if any(needle in line for line in lines) else None

        return self._wait_until(f"a log line containing {needle!r}", seen, since)

    def wait_for_any(self, needles: tuple[str, ...]) -> str:
        """The first of `needles` (lower case) that a line contains, in any case."""
        return self._wait_until(
            f"a log line containing any of {needles!r}", lambda lines: first_needle_seen(needles, lines)
        )

    def close(self) -> None:
        self._proc.kill()
        self._proc.wait()
        self._thread.join()


def test_a_log_that_ends_before_its_line_is_reported_as_ended_not_stuck(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A container that stopped: its log stream ends, and the wait says so at once instead of spending the watchdog."""
    docker = tmp_path / "docker"
    docker.write_text("#!/bin/sh\necho booting\n", encoding="utf-8")
    docker.chmod(0o755)
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")
    tail = LogTail("pfb-stopped")
    try:
        with pytest.raises(AssertionError, match="log ended") as raised:
            tail.wait_for("start of service")
    finally:
        tail.close()
    assert "STUCK" not in str(raised.value) and "booting" in str(raised.value), str(raised.value)


def _docker(*args: str, stdin: str | None = None, timeout: float = 120) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["docker", *args], input=stdin, capture_output=True, text=True, timeout=timeout, check=False
        )
    except FileNotFoundError:
        pytest.fail("docker is required for the integration test (this must fail, not skip): `docker` not found")


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
    conf_dir: Path = tmp_path_factory.mktemp("unbound-conf")
    if observer:
        shutil.copy(PROTO_DIR / "pfb_upstream_observer.py", conf_dir)  # as the installer stages it into /var/unbound
    try:
        port, name, tail = retry_on_taken_port(lambda port: _start_unbound(port, authoritative, conf_dir, observer))
    except BaseException:
        authoritative.close()
        raise
    try:
        yield RunningUnbound(port, tail, authoritative, conf_dir, observer)
    finally:
        _docker("rm", "-f", name)
        tail.close()
        authoritative.close()


def _start_unbound(
    port: int, authoritative: FakeAuthoritative, conf_dir: Path, observer: bool
) -> tuple[int, str, LogTail] | None:
    """Unbound on `port`, once it serves; None when it exited because another process holds the port."""
    (conf_dir / "unbound.conf").write_text(_conf(port, authoritative.port, observer=observer), encoding="utf-8")
    name = f"pfb-frontend-unbound-{uuid.uuid4().hex[:8]}"
    run = _docker(
        "run", "-d", "--network", "host", "--name", name, "-v", f"{conf_dir}:/conf:ro",
        IMAGE, "unbound", "-d", "-c", "/conf/unbound.conf",
    )  # fmt: skip
    if run.returncode != 0:
        pytest.fail(f"cannot start Unbound: {run.stderr}")
    tail = LogTail(name)
    try:
        served = tail.wait_for_any(("start of service", "address already in use")) == "start of service"
    except BaseException:
        _docker("rm", "-f", name)
        tail.close()
        raise
    if served:
        return port, name, tail
    _docker("rm", "-f", name)
    tail.close()
    return None


@pytest.fixture(scope="module")
def unbound(tmp_path_factory: pytest.TempPathFactory) -> Iterator[RunningUnbound]:
    """Unbound as the proxy fronts it with the Resolver not forwarding: no python module at all."""
    yield from _run_unbound(tmp_path_factory, observer=False)


@pytest.fixture(scope="module")
def observed_unbound(tmp_path_factory: pytest.TempPathFactory) -> Iterator[RunningUnbound]:
    """Unbound as the proxy fronts it with the Resolver forwarding: the python module is the upstream observer."""
    yield from _run_unbound(tmp_path_factory, observer=True)


@pytest.fixture
def gated_authoritative(unbound: RunningUnbound) -> Iterator[None]:
    """The test sets `unbound.authoritative.gate` before each round; it is cleared again when the test is over."""
    try:
        yield
    finally:
        unbound.authoritative.gate = None


def _open_gate_once_logged(
    unbound: RunningUnbound, gate: threading.Event, clients: list[str], name: str, mark: int
) -> None:
    """Unbound logs each client query on receipt, so once every client's line is there all their queries are in flight
    at Unbound, and the authoritative may answer. The gate opens on a stuck run too, which then fails at the wait."""
    try:
        for client in clients:
            unbound.tail.wait_for(f"{client} {name} A IN", since=mark)
    finally:
        gate.set()


# Verdict numbers and Extended DNS Error codes the upstream-block tests use (test_gateway_upstream_blocks.py,
# test_gateway_modes.py).
NXDOMAIN, SERVFAIL, REFUSED = 3, 2, 5
EDE_BLOCKED, EDE_CENSORED, EDE_FILTERED = 15, 16, 17
