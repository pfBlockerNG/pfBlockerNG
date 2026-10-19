"""A test certificate, the certificate file the gateway serves and a DoT client for the DNS over TLS tests.

The certificate comes from the `openssl` CLI, which the tests REQUIRE: its absence fails the test, never skips it.
"""

from __future__ import annotations

import asyncio
import contextlib
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import TypeVar

import pytest
from frontend_helpers import WATCHDOG, watchdog, watched

T = TypeVar("T")


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


PORT_PICKS = 8  # ports tried before a port that keeps being taken is given up on


def free_loopback_port(pick: Callable[[], int] = free_port) -> int:
    """A port on 127.0.0.1 that is free for UDP and for TCP: Unbound binds both, and `pick` answers for TCP alone."""
    for _ in range(PORT_PICKS * 8):
        port = pick()
        try:
            with (
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp,
                socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp,
            ):
                udp.bind(("127.0.0.1", port))
                tcp.bind(("127.0.0.1", port))
        except OSError:
            continue
        return port
    raise RuntimeError("no port free for UDP and TCP")


def retry_on_taken_port(attempt: Callable[[int], T | None], pick: Callable[[], int] = free_loopback_port) -> T:
    """`attempt(port)` on a picked port, and on another when it returns None: the port was taken by someone else
    after it was picked (picking and binding are two steps). Up to PORT_PICKS picks; nothing else is retried."""
    for _ in range(PORT_PICKS):
        result = attempt(pick())
        if result is not None:
            return result
    raise RuntimeError(f"the port picked was taken {PORT_PICKS} times in a row")


def make_certificate(directory: Path, name: str = "server", *, passphrase: str | None = None) -> tuple[bytes, bytes]:
    """A self-signed certificate valid for `localhost` and 127.0.0.1 as (certificate PEM, private key PEM).

    The key is plain unless `passphrase` is given: then it is the PKCS#8 encrypted form the openssl CLI writes.
    """
    if shutil.which("openssl") is None:
        pytest.fail("the openssl CLI is required for the DoT tests (this must fail, not skip): `openssl` not found")
    cert, key = directory / f"{name}.crt", directory / f"{name}.key"
    protection = ["-passout", f"pass:{passphrase}"] if passphrase else ["-nodes"]
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", *protection]
        + ["-keyout", str(key), "-out", str(cert), "-days", "2", "-subj", "/CN=localhost"]
        + ["-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
        check=True,
        capture_output=True,
        timeout=60,
    )
    return cert.read_bytes(), key.read_bytes()


def write_certificate_file(directory: Path, certificate: bytes, key: bytes) -> Path:
    """The file pfBlockerNG writes for the gateway's `--tls-pem` (root only, read once at start): the certificate
    PEM, then the key PEM, mode 0600."""
    pem = directory / "tls.pem"
    pem.write_bytes(certificate + key)
    pem.chmod(0o600)
    return pem


@contextlib.contextmanager
def control_socket() -> Iterator[Path]:
    """A path for the gateway's `--ctl-socket` that is short enough for a Unix socket (pytest's tmp_path can be too
    long) and is removed with its directory, so that no test makes a socket under the real /var/run."""
    with tempfile.TemporaryDirectory(prefix="pfbctl") as directory:
        yield Path(directory) / "run" / "ctl.sock"


def push_certificate(socket_path: Path, certificate: bytes, key: bytes) -> str:
    """What pfBlockerNG's pfb_dns_proxy_certificate_push() sends the gateway: one frame, the length of the PEM as
    4 bytes big-endian and then the certificate chain and the key as PEM; returns the one reply line, `ok` or
    `error: <reason>`."""
    pem = certificate + key
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(WATCHDOG)
        with watched("the certificate push to the gateway"):
            client.connect(str(socket_path))
            client.sendall(struct.pack("!I", len(pem)) + pem)
            reply = b""
            while not reply.endswith(b"\n"):
                chunk = client.recv(256)
                if not chunk:
                    break
                reply += chunk
    return reply.decode().strip()


async def dot_exchange(
    server: tuple[str, int],
    wire: bytes,
    trust: Path,
    *,
    source: str = "127.0.0.1",
    max_version: ssl.TLSVersion | None = None,
) -> tuple[bytes, tuple[str, int], str]:
    """One length-framed query over TLS to `server`, trusting only the certificate PEM at `trust`.

    Returns (reply, the client's socket address, negotiated TLS version). A stuck run fails at the watchdog.
    """
    context = ssl.create_default_context(cafile=str(trust))
    if max_version is not None:
        context.maximum_version = max_version
    reader, writer = await watchdog(
        asyncio.open_connection(*server, ssl=context, server_hostname="localhost", local_addr=(source, 0)),
        "the TLS connection",
    )
    try:
        writer.write(struct.pack("!H", len(wire)) + wire)
        await writer.drain()
        size = struct.unpack("!H", await watchdog(reader.readexactly(2), "the TLS reply length"))[0]
        reply = await watchdog(reader.readexactly(size), "the TLS reply")
        return reply, writer.get_extra_info("sockname")[:2], writer.get_extra_info("ssl_object").version()
    finally:
        writer.close()


async def open_dot(
    server: tuple[str, int], trust: Path, *, source: str = "127.0.0.1"
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """A TLS connection to `server` that stays open, trusting only the certificate PEM at `trust`."""
    context = ssl.create_default_context(cafile=str(trust))
    return await watchdog(
        asyncio.open_connection(*server, ssl=context, server_hostname="localhost", local_addr=(source, 0)),
        "the TLS connection",
    )
