"""A test certificate, the certificate file the gateway serves and a DoT client for the DNS over TLS tests.

The certificate comes from the `openssl` CLI, which the tests REQUIRE: its absence fails the test, never skips it.
"""

from __future__ import annotations

import asyncio
import shutil
import socket
import ssl
import struct
import subprocess
from pathlib import Path

import pytest
from frontend_helpers import WATCHDOG


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


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
    """The file pfBlockerNG writes for the gateway's `--tls-pem`: the certificate PEM, then the key PEM, mode 0600."""
    pem = directory / "pfb_dns_cert.pem"
    pem.write_bytes(certificate + key)
    pem.chmod(0o600)
    return pem


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
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(*server, ssl=context, server_hostname="localhost", local_addr=(source, 0)), WATCHDOG
    )
    try:
        writer.write(struct.pack("!H", len(wire)) + wire)
        await writer.drain()
        size = struct.unpack("!H", await asyncio.wait_for(reader.readexactly(2), WATCHDOG))[0]
        reply = await asyncio.wait_for(reader.readexactly(size), WATCHDOG)
        return reply, writer.get_extra_info("sockname")[:2], writer.get_extra_info("ssl_object").version()
    finally:
        writer.close()


async def open_dot(
    server: tuple[str, int], trust: Path, *, source: str = "127.0.0.1"
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """A TLS connection to `server` that stays open, trusting only the certificate PEM at `trust`."""
    context = ssl.create_default_context(cafile=str(trust))
    return await asyncio.wait_for(
        asyncio.open_connection(*server, ssl=context, server_hostname="localhost", local_addr=(source, 0)), WATCHDOG
    )
