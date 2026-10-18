"""Integration: the clause pfb_dns_proxy_resolver() adds to the Resolver's Custom Options, in a REAL Unbound (Docker).

pfSense keeps `port: 53` and `interface: 127.0.0.1` / `::1` for a Resolver moved onto lo0. Our marked clause then sets
`port: 5354` and listens on loopback 5353 for the proxy's PROXYv2, so Unbound must hold exactly loopback 5353 and 5354
and leave loopback 53 to the proxy. unbound-checkconf accepts both a clause that does that and one that does not, so
the sockets are what is asserted, read from the container's own /proc/net (its own network namespace: no host port is
touched). No Docker (or an image that cannot be built) is a FAILURE, never a skip, like the other integration tests.
"""

from __future__ import annotations

import ast
import contextlib
import re
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from test_integration_unbound import BUILD_TIMEOUT, DOCKERFILE, IMAGE, LogTail, _docker

REPO = Path(__file__).resolve().parents[2]
MOVE_TEST = REPO / "tests/php/DnsProxyResolverMoveTest.php"

# What pfSense (2.8) writes for a Resolver on lo0 that forwards, then the Custom Options text, which it writes last.
PREAMBLE = """server:
    verbosity: 1
    chroot: ""
    username: ""
    pidfile: ""
    do-daemonize: no
    use-syslog: no
    logfile: ""
    do-ip6: yes
    port: 53
    interface: 127.0.0.1
    interface: ::1
    access-control: 127.0.0.0/8 allow
    access-control: ::1/128 allow

forward-zone:
    name: "."
    forward-addr: 192.0.2.53
"""

LOOPBACK_V4 = "0100007F"  # /proc/net/{tcp,udp}: the address as a host-order hex word
LOOPBACK_V6 = "00000000000000000000000001000000"  # /proc/net/{tcp6,udp6}: four host-order words
LISTEN = "0A"  # tcp socket state; a udp socket is simply bound


def _our_clause() -> str:
    """The clause the move writes with no IPv6 grant, as pinned by DnsProxyResolverMoveTest::BLOCK (never a copy)."""
    source = MOVE_TEST.read_text(encoding="utf-8")
    declaration = re.search(r"private const BLOCK = (.*?);\n", source, re.DOTALL)
    assert declaration, "DnsProxyResolverMoveTest::BLOCK not found"
    literals = re.findall(r'"(?:[^"\\]|\\.)*"', declaration.group(1))
    assert literals, declaration.group(1)
    return "".join(ast.literal_eval(literal) for literal in literals)


def _sockets(container: str) -> set[tuple[str, str, int]]:
    """(tcp|udp, address, port) of every LISTENing tcp / bound udp socket on a loopback address, from /proc/net."""
    found: set[tuple[str, str, int]] = set()
    for table, proto, loopback, shown in (
        ("tcp", "tcp", LOOPBACK_V4, "127.0.0.1"),
        ("udp", "udp", LOOPBACK_V4, "127.0.0.1"),
        ("tcp6", "tcp", LOOPBACK_V6, "::1"),
        ("udp6", "udp", LOOPBACK_V6, "::1"),
    ):
        text = _docker("exec", container, "cat", f"/proc/net/{table}").stdout
        for line in text.splitlines()[1:]:
            fields = line.split()
            address, _, port = fields[1].partition(":")
            if address == loopback and (proto == "udp" or fields[3] == LISTEN):
                found.add((proto, shown, int(port, 16)))
    return found


@contextlib.contextmanager
def _unbound(conf_dir: Path) -> Iterator[str]:
    """A running Unbound on `conf_dir`/unbound.conf in its own network namespace; yields the container name."""
    probe = _docker("version", "--format", "{{.Server.Version}}")
    if probe.returncode != 0:
        pytest.fail(f"docker daemon unreachable (this must fail, not skip): {probe.stderr.strip()}")
    if _docker("image", "inspect", IMAGE).returncode != 0:
        build = _docker("build", "-t", IMAGE, "-", stdin=DOCKERFILE, timeout=BUILD_TIMEOUT)
        if build.returncode != 0:
            pytest.fail(f"cannot build the Unbound test image:\n{build.stdout}\n{build.stderr}")
    check = _docker("run", "--rm", "--network", "none", "-v", f"{conf_dir}:/conf:ro", IMAGE,
                    "unbound-checkconf", "/conf/unbound.conf")  # fmt: skip
    assert check.returncode == 0, f"unbound-checkconf rejected the configuration:\n{check.stdout}\n{check.stderr}"
    name = f"pfb-clause-shape-{uuid.uuid4().hex[:8]}"
    run = _docker(
        "run", "-d", "--rm", "--network", "none", "--sysctl", "net.ipv6.conf.all.disable_ipv6=0",
        "--name", name, "-v", f"{conf_dir}:/conf:ro", IMAGE, "unbound", "-d", "-c", "/conf/unbound.conf",
    )  # fmt: skip
    if run.returncode != 0:
        pytest.fail(f"cannot start Unbound: {run.stderr}")
    tail = LogTail(name)
    try:
        tail.wait_for("start of service")  # every listener is bound before Unbound says so
        yield name
    finally:
        _docker("rm", "-f", name)
        tail.close()


def _conf_dir(tmp_path: Path, text: str) -> Path:
    (tmp_path / "unbound.conf").write_text(text, encoding="utf-8")
    return tmp_path


def test_clause_text_is_the_one_the_php_move_pins() -> None:
    clause = _our_clause()
    assert clause.startswith("server:\n# pfBlockerNG DNS proxy\nport: 5354\n"), clause
    assert clause.endswith("# end pfBlockerNG DNS proxy"), clause


def test_without_our_clause_unbound_holds_loopback_53(tmp_path: Path) -> None:
    """The premise: pfSense's own preamble puts Unbound on loopback 53, the port the proxy needs for the firewall."""
    with _unbound(_conf_dir(tmp_path, PREAMBLE)) as name:
        sockets = _sockets(name)
    assert {("tcp", "127.0.0.1", 53), ("udp", "127.0.0.1", 53), ("tcp", "::1", 53), ("udp", "::1", 53)} <= sockets, (
        sockets
    )


def test_with_our_clause_unbound_holds_only_loopback_5353_and_5354(tmp_path: Path) -> None:
    """Our clause moves Unbound to 5354 and adds the PROXYv2 port 5353; loopback 53 is left free for the proxy."""
    with _unbound(_conf_dir(tmp_path, PREAMBLE + "\n" + _our_clause() + "\n")) as name:
        sockets = _sockets(name)
    expected = {
        (proto, host, port) for proto in ("tcp", "udp") for host in ("127.0.0.1", "::1") for port in (5353, 5354)
    }
    assert sockets == expected, f"loopback sockets: {sorted(sockets)}; expected {sorted(expected)}"
