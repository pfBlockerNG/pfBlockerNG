"""Startup when a socket cannot be bound: that address is skipped with one log line and the others are served; the
proxy exits 1 (nothing booted) only when no UDP+TCP address binds at all. DoT is bound per address the same way, and
a DoT setup that cannot be served (no certificate, an unusable one) is one error line with the plain listeners serving.

The rc script bakes the addresses of the last apply, so an address that has since gone away (a DHCP or PPPoE
change, a VIP on a disabled interface) must not take DNS down on the addresses that are still there.
"""

from __future__ import annotations

import argparse
import asyncio
import errno
import os
import socket
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import dnswire
import pfb_dns_proxy
import pytest
from dot_helpers import REFID, b64, cert_element, config_xml
from frontend_constants import BLOCKED, DNSBL_IPV4, PROTO_DIR
from frontend_helpers import _bind_strict, build_query, serving, udp_exchange

IN_USE = os.strerror(errno.EADDRINUSE)
NOT_ON_THIS_BOX = os.strerror(errno.EADDRNOTAVAIL)
SKIPPED = "pfb_dns_proxy warning: cannot listen on {host}:{port}: {reason}"
NONE_BOUND = "pfb_dns_proxy: no address could be bound"
DOT_OFF = "pfb_dns_proxy error: DNS over TLS is off, serving plain DNS only: "
DNSBL_VIP4 = socket.inet_aton(DNSBL_IPV4)


@pytest.fixture
def busy_port() -> Iterator[int]:
    """A port something is listening on at 127.0.0.2 and nothing is bound to at 127.0.0.1, tcp and udp: the ephemeral
    port the kernel gave 127.0.0.2 can be in use at the other address, so that is checked, not assumed."""
    for _ in range(100):
        with socket.create_server(("127.0.0.2", 0)) as occupant:
            port = occupant.getsockname()[1]
            try:
                with socket.create_server(("127.0.0.1", port)), socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                    udp.bind(("127.0.0.1", port))
            except OSError:
                continue
            yield port
            return
    pytest.fail("no port is free at 127.0.0.1 and takeable at 127.0.0.2")


@pytest.fixture
def no_boot(monkeypatch: pytest.MonkeyPatch) -> None:
    """A boot() that fails the test: nothing boots when no address could be bound."""
    monkeypatch.setattr(pfb_dns_proxy, "boot", lambda *_: pytest.fail("the module must not boot"))


@pytest.fixture
def quiet_boot(module_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The real module, booted from `module_dir` without its /var/log files."""
    real_boot = pfb_dns_proxy.boot

    def boot_without_log_files(directory: str) -> Any:
        module = real_boot(directory)
        monkeypatch.setattr(module, "pfb_log", lambda name, line: None)  # the module logs to /var/log/pfblockerng
        return module

    monkeypatch.chdir(module_dir)
    monkeypatch.setattr(sys, "stderr", sys.stderr)  # init_standard() replaces it; register the auto-restore
    monkeypatch.setattr(pfb_dns_proxy, "boot", boot_without_log_files)


def _serve(argv: list[str]) -> tuple[list[tuple[str, int]], list[bytes]]:
    """Run serve() until it is ready, ask its first address for a blocked name, stop it: (listening on, answers)."""
    args: argparse.Namespace = pfb_dns_proxy.parse_args(["--upstream", "127.0.0.1:9", *argv])

    async def scenario() -> tuple[list[tuple[str, int]], list[bytes]]:
        async with serving(args) as bound:
            reply = (await udp_exchange(bound[0], build_query(BLOCKED)))[0]
            return bound, [rr.rdata for rr in dnswire.parse(reply).answers]

    return asyncio.run(scenario())


def _skip_lines(stderr: str) -> list[str]:
    return [line for line in stderr.splitlines() if "cannot listen" in line]


def _dot_config(directory: Path, certificate: tuple[bytes, bytes], tls_port: int) -> Path:
    crt, key = certificate
    config = directory / "config.xml"
    config.write_text(config_xml(tlsport=tls_port, entries=cert_element(REFID, b64(crt), b64(key))), encoding="utf-8")
    return config


UNBINDABLE = [
    pytest.param("127.0.0.2", IN_USE, id="port in use"),
    pytest.param("203.0.113.9", NOT_ON_THIS_BOX, id="not an address of this box"),
]


@pytest.mark.parametrize(("host", "reason"), UNBINDABLE)
def test_an_address_that_cannot_bind_is_skipped_with_one_line_and_the_others_are_served(
    host: str,
    reason: str,
    busy_port: int,
    module_dir: Path,
    quiet_boot: None,
    capfd: pytest.CaptureFixture[str],
) -> None:
    argv = ["--listen", "127.0.0.1", "--listen", host, "--port", str(busy_port), "--module-dir", str(module_dir)]

    bound, answers = _serve(argv)

    assert bound == [("127.0.0.1", busy_port)]  # the address that exists is served, the one that does not is not ...
    assert answers == [DNSBL_VIP4]  # ... and answers: the module booted and DNSBL decisions are made there
    err = capfd.readouterr().err
    assert _skip_lines(err) == [SKIPPED.format(host=host, port=busy_port, reason=reason)]  # once, one line
    assert "Traceback" not in err


def test_an_address_that_cannot_bind_is_skipped_wherever_it_is_in_the_list(
    busy_port: int, module_dir: Path, quiet_boot: None, capfd: pytest.CaptureFixture[str]
) -> None:
    argv = ["--listen", "127.0.0.2", "--listen", "127.0.0.1", "--port", str(busy_port), "--module-dir", str(module_dir)]

    bound, _ = _serve(argv)

    assert bound == [("127.0.0.1", busy_port)]
    assert _skip_lines(capfd.readouterr().err) == [SKIPPED.format(host="127.0.0.2", port=busy_port, reason=IN_USE)]


def test_a_dot_address_that_cannot_bind_is_skipped_and_the_other_dot_addresses_are_served(
    tmp_path: Path,
    module_dir: Path,
    certificate: tuple[bytes, bytes],
    quiet_boot: None,
    capfd: pytest.CaptureFixture[str],
) -> None:
    with socket.create_server(("127.0.0.2", 0)) as occupant:
        tls_port = occupant.getsockname()[1]  # 127.0.0.2 has a DoT listener already; 127.0.0.1 has none
        config = _dot_config(tmp_path, certificate, tls_port)
        argv = ["--listen", "127.0.0.1", "--listen", "127.0.0.2", "--port", "0", "--module-dir", str(module_dir)]

        bound, _ = _serve([*argv, "--dot", "--pfsense-config", str(config)])

    assert [address for address in bound if address[1] == tls_port] == [("127.0.0.1", tls_port)]
    assert len(bound) == 3  # the plain pair on both addresses, DoT on one
    assert _skip_lines(capfd.readouterr().err) == [SKIPPED.format(host="127.0.0.2", port=tls_port, reason=IN_USE)]


def test_dot_that_binds_nowhere_does_not_stop_the_plain_listeners(
    tmp_path: Path,
    module_dir: Path,
    certificate: tuple[bytes, bytes],
    quiet_boot: None,
    capfd: pytest.CaptureFixture[str],
) -> None:
    with socket.create_server(("127.0.0.1", 0)) as occupant:
        tls_port = occupant.getsockname()[1]
        config = _dot_config(tmp_path, certificate, tls_port)
        argv = ["--listen", "127.0.0.1", "--port", "0", "--module-dir", str(module_dir)]

        bound, answers = _serve([*argv, "--dot", "--pfsense-config", str(config)])

    assert [port for _, port in bound if port == tls_port] == []  # no DoT, ...
    assert len(bound) == 1 and answers == [DNSBL_VIP4]  # ... and the plain listener still answers
    assert _skip_lines(capfd.readouterr().err) == [SKIPPED.format(host="127.0.0.1", port=tls_port, reason=IN_USE)]


@pytest.mark.parametrize(
    ("config_kwargs", "reason"),
    [({"certref": None}, "sslcertref is empty"), ({"certref": "nope"}, "refid 'nope'")],
    ids=["no-certref", "missing-cert"],
)
def test_a_dot_setup_that_cannot_be_served_is_one_error_line_and_plain_dns_keeps_serving(
    tmp_path: Path,
    module_dir: Path,
    quiet_boot: None,
    capfd: pytest.CaptureFixture[str],
    config_kwargs: dict[str, Any],
    reason: str,
) -> None:
    config = tmp_path / "config.xml"
    config.write_text(config_xml(**config_kwargs), encoding="utf-8")
    argv = ["--listen", "127.0.0.1", "--port", "0", "--module-dir", str(module_dir)]

    bound, answers = _serve([*argv, "--dot", "--pfsense-config", str(config)])

    assert len(bound) == 1 and answers == [DNSBL_VIP4]  # the plain listener only, and its DNSBL decisions are made
    err = capfd.readouterr().err
    [line] = [line for line in err.splitlines() if "DNS over TLS" in line]  # once
    assert line.startswith(DOT_OFF + str(config)) and reason in line
    assert "Traceback" not in err


def test_when_no_address_binds_each_is_logged_once_and_it_exits_1_without_booting(
    busy_port: int, no_boot: None, capfd: pytest.CaptureFixture[str]
) -> None:
    argv = ["--listen", "127.0.0.2", "--listen", "203.0.113.9", "--port", str(busy_port)]

    assert pfb_dns_proxy.main(argv) == 1

    assert capfd.readouterr().err.splitlines() == [
        SKIPPED.format(host="127.0.0.2", port=busy_port, reason=IN_USE),
        SKIPPED.format(host="203.0.113.9", port=busy_port, reason=NOT_ON_THIS_BOX),
        NONE_BOUND,
    ]


def test_the_real_process_exits_1_with_one_line_per_address_when_none_can_be_bound(
    busy_port: int, tmp_path: Path
) -> None:
    run = subprocess.run(
        [sys.executable, str(PROTO_DIR / "pfb_dns_proxy.py"), "--listen", "127.0.0.2", "--listen", "203.0.113.9"]
        + ["--port", str(busy_port), "--module-dir", str(tmp_path)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    expected = [
        SKIPPED.format(host="127.0.0.2", port=busy_port, reason=IN_USE),
        SKIPPED.format(host="203.0.113.9", port=busy_port, reason=NOT_ON_THIS_BOX),
        NONE_BOUND,
    ]
    assert (run.returncode, run.stdout, run.stderr.splitlines()) == (1, "", expected)


def _counting_binds(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, int]]:
    """Every pfb_dns_proxy.bind() call as (host, port), each passed on to the real bind()."""
    real, calls = pfb_dns_proxy.bind, []

    def counted(host: str, port: int, *, udp: bool) -> pfb_dns_proxy.Listener:
        calls.append((host, port))
        return real(host, port, udp=udp)

    monkeypatch.setattr(pfb_dns_proxy, "bind", counted)
    return calls


def test_a_port_zero_bind_whose_udp_twin_is_taken_is_tried_again_and_the_retry_serves(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Port 0 hands TCP a port and UDP must take the same number. Another process holding that UDP port fails the first
    attempt; the retry, on the port the kernel picks now, serves a real datagram."""
    real, calls = pfb_dns_proxy.bind, []
    holder: list[socket.socket] = []  # the other process: UDP on the port the first attempt's TCP socket got

    def first_attempt_meets_the_taken_port(host: str, port: int, *, udp: bool) -> pfb_dns_proxy.Listener:
        calls.append((host, port))
        if holder:
            return real(host, port, udp=udp)
        probe = real(host, 0, udp=False)  # the port a port-0 TCP bind gets
        number = probe.tcp.getsockname()[1]
        probe.close()
        holder.append(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        holder[0].bind((host, number))
        return real(host, number, udp=True)  # its UDP twin is taken: EADDRINUSE

    monkeypatch.setattr(pfb_dns_proxy, "bind", first_attempt_meets_the_taken_port)
    bound: list[pfb_dns_proxy.Listener] = []
    try:
        bound = _bind_strict(["127.0.0.1"], 0, udp=True)
        [listener] = bound
        assert calls == [("127.0.0.1", 0), ("127.0.0.1", 0)]  # the first attempt, then the retry
        assert listener.udp is not None
        assert listener.udp.getsockname()[1] == listener.tcp.getsockname()[1]
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            sender.sendto(b"ping", listener.udp.getsockname())
            listener.udp.settimeout(2.0)
            assert listener.udp.recvfrom(64)[0] == b"ping"
    finally:
        for listener in bound:
            listener.close()
        for sock in holder:
            sock.close()


def test_an_explicit_port_in_use_is_raised_at_once_and_never_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _counting_binds(monkeypatch)
    with socket.create_server(("127.0.0.1", 0)) as occupant:
        port = occupant.getsockname()[1]
        with pytest.raises(pfb_dns_proxy.ListenError, match=IN_USE):
            _bind_strict(["127.0.0.1"], port, udp=True)
    assert calls == [("127.0.0.1", port)]


def test_a_port_zero_bind_refused_for_another_reason_is_raised_at_once_and_never_retried(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _counting_binds(monkeypatch)
    with pytest.raises(pfb_dns_proxy.ListenError, match=NOT_ON_THIS_BOX):
        _bind_strict(["203.0.113.9"], 0, udp=True)
    assert calls == [("203.0.113.9", 0)]
