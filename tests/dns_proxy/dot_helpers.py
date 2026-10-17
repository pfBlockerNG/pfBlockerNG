"""A test certificate, pfSense config.xml text and a DoT client for the DNS over TLS tests.

The certificate comes from the `openssl` CLI, which the tests REQUIRE: its absence fails the test, never skips it.
"""

from __future__ import annotations

import asyncio
import base64
import shutil
import socket
import ssl
import struct
import subprocess
from pathlib import Path

import pytest
from frontend_helpers import WATCHDOG

REFID = "5f0a1b2c3d4e5"


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


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def cert_element(refid: str, crt: str | None, prv: str | None, caref: str | None = None) -> str:
    """A config.xml <cert> entry; `crt`/`prv` are the element TEXT (base64), None leaves the element out."""
    parts = [f"<refid>{refid}</refid>", "<descr>DoT test cert</descr>", "<type>server</type>"]
    parts += [f"<caref>{caref}</caref>"] if caref else []
    parts += [f"<crt>{crt}</crt>"] if crt is not None else []
    parts += [f"<prv>{prv}</prv>"] if prv is not None else []
    return "<cert>" + "".join(parts) + "</cert>"


def ca_element(refid: str, crt: str, caref: str | None = None) -> str:
    return (
        f"<ca><refid>{refid}</refid><descr>CA {refid}</descr>"
        + (f"<caref>{caref}</caref>" if caref else "")
        + (f"<crt>{crt}</crt></ca>")
    )


def config_xml(
    *,
    enablessl: bool = True,
    certref: str | None = REFID,
    tlsport: object | None = 853,
    entries: str = "",
    unbound: bool = True,
) -> str:
    """The relevant slice of a pfSense config.xml: <unbound> DoT settings plus whatever <cert>/<ca> `entries` say."""
    settings = ["<enable></enable>"]
    settings += ["<enablessl></enablessl>"] if enablessl else []
    settings += [f"<sslcertref>{certref}</sslcertref>"] if certref is not None else []
    settings += [f"<tlsport>{tlsport}</tlsport>"] if tlsport is not None else []
    section = f"<unbound>{''.join(settings)}</unbound>" if unbound else ""
    return f'<?xml version="1.0"?>\n<pfsense><version>23.3</version>{section}{entries}</pfsense>\n'


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
