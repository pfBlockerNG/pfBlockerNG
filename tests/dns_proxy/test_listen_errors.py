"""Startup when a socket cannot be bound: exit 1 with one line on stderr, nothing left open, the module never boots."""

from __future__ import annotations

import errno
import os
import socket
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pfb_dns_proxy
import pytest
from dot_helpers import REFID, b64, cert_element, config_xml
from frontend_constants import PROTO_DIR

IN_USE = os.strerror(errno.EADDRINUSE)


@pytest.fixture
def busy_port() -> Iterator[int]:
    """A port something is listening on at 127.0.0.2 (and nothing at 127.0.0.1)."""
    with socket.create_server(("127.0.0.2", 0)) as occupant:
        yield occupant.getsockname()[1]


@pytest.fixture
def recorded_binds(monkeypatch: pytest.MonkeyPatch) -> list[pfb_dns_proxy.Listener]:
    """Every Listener bind() hands out; and a boot() that fails the test: nothing boots after a failed bind."""
    bound: list[pfb_dns_proxy.Listener] = []
    real = pfb_dns_proxy.bind

    def recording(host: str, port: int, *, udp: bool) -> pfb_dns_proxy.Listener:
        listener = real(host, port, udp=udp)
        bound.append(listener)
        return listener

    monkeypatch.setattr(pfb_dns_proxy, "bind", recording)
    monkeypatch.setattr(pfb_dns_proxy, "boot", lambda *_: pytest.fail("the module must not boot"))
    return bound


def _closed(listener: pfb_dns_proxy.Listener) -> bool:
    return listener.tcp.fileno() == -1 and (listener.udp is None or listener.udp.fileno() == -1)


def test_a_port_in_use_on_the_second_address_exits_1_with_one_line_and_releases_the_first(
    busy_port: int, recorded_binds: list[pfb_dns_proxy.Listener], capsys: pytest.CaptureFixture[str]
) -> None:
    argv = ["--listen", "127.0.0.1", "--listen", "127.0.0.2", "--port", str(busy_port)]
    assert pfb_dns_proxy.main(argv) == 1
    assert capsys.readouterr().err == f"pfb_dns_proxy: cannot listen on 127.0.0.2:{busy_port}: {IN_USE}\n"
    assert len(recorded_binds) == 1  # 127.0.0.1 was bound before 127.0.0.2 failed ...
    assert [_closed(listener) for listener in recorded_binds] == [True]  # ... and is given back


def test_a_dot_port_in_use_exits_1_with_one_line_and_releases_the_plain_listeners(
    tmp_path: Path,
    certificate: tuple[bytes, bytes],
    recorded_binds: list[pfb_dns_proxy.Listener],
    capsys: pytest.CaptureFixture[str],
) -> None:
    crt, key = certificate
    with socket.create_server(("127.0.0.1", 0)) as occupant:
        port = occupant.getsockname()[1]
        config = tmp_path / "config.xml"
        config.write_text(config_xml(tlsport=port, entries=cert_element(REFID, b64(crt), b64(key))), encoding="utf-8")
        status = pfb_dns_proxy.main(["--listen", "127.0.0.1", "--port", "0", "--dot", "--pfsense-config", str(config)])
    assert status == 1
    assert capsys.readouterr().err == f"pfb_dns_proxy: cannot listen on 127.0.0.1:{port}: {IN_USE}\n"
    assert len(recorded_binds) == 1  # the UDP+TCP listener of 127.0.0.1 was bound before the DoT one failed ...
    assert [_closed(listener) for listener in recorded_binds] == [True]  # ... and is given back


def test_the_real_process_exits_1_with_one_line_when_a_port_is_in_use(busy_port: int, tmp_path: Path) -> None:
    run = subprocess.run(
        [sys.executable, str(PROTO_DIR / "pfb_dns_proxy.py"), "--listen", "127.0.0.1", "--listen", "127.0.0.2"]
        + ["--port", str(busy_port), "--module-dir", str(tmp_path)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    expected = f"pfb_dns_proxy: cannot listen on 127.0.0.2:{busy_port}: {IN_USE}\n"
    assert (run.returncode, run.stdout, run.stderr) == (1, "", expected)
