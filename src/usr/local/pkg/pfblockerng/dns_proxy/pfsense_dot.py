"""The pfSense DNS Resolver's DNS over TLS settings, read from config.xml, as a TLS server context.

Two of the settings Unbound is configured from (pfSense src/etc/inc/unbound.inc): `unbound/sslcertref` (the refid of a
top-level <cert>) and `unbound/tlsport` (853 unless it is not a port). `unbound/enablessl` is not read: the caller's
--dot decides, and the Resolver's own DoT is off while the proxy serves it. Unbound is given the certificate followed
by its CA chain; so is this. Standard library only.
"""

from __future__ import annotations

import base64
import binascii
import os
import ssl
import tempfile
import xml.etree.ElementTree as ET  # config.xml is the box's own trusted file
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn

DEFAULT_PORT = 853


class DotConfigError(Exception):
    """DoT cannot be served from this config.xml; the message says why and names the file."""


@dataclass(frozen=True)
class DotSettings:
    port: int
    chain_pem: bytes  # the server certificate, then each CA up its chain, joined by newlines
    key_pem: bytes


def _text(element: ET.Element, child: str) -> str:
    return (element.findtext(child) or "").strip()


def _decode(entry: ET.Element, kind: str, field: str, where: str) -> bytes:
    text = "".join(_text(entry, field).split())
    label = f"<{kind}> {_text(entry, 'refid')!r}"
    if not text:
        raise DotConfigError(f"{where}: {label} has no {field}")
    try:
        return base64.b64decode(text, validate=True)
    except binascii.Error:
        raise DotConfigError(f"{where}: {field} of {label} is not valid base64") from None


def _ca_chain(root: ET.Element, cert: ET.Element, where: str) -> list[bytes]:
    """Each CA the certificate's `caref` leads to, nearest first; a missing CA or a loop ends the chain."""
    authorities = {_text(ca, "refid"): ca for ca in root.findall("ca")}
    chain, seen = [], set()
    caref = _text(cert, "caref")
    while caref and caref not in seen and caref in authorities:
        seen.add(caref)
        chain.append(_decode(authorities[caref], "ca", "crt", where))
        caref = _text(authorities[caref], "caref")
    return chain


def read_settings(path: str | os.PathLike[str]) -> DotSettings:
    """The DoT settings of the DNS Resolver in the pfSense config.xml at `path`, or DotConfigError."""
    where = str(path)
    try:
        root = ET.parse(path).getroot()
    except OSError as exc:
        raise DotConfigError(f"{where}: cannot read: {exc.strerror or exc}") from None
    except ET.ParseError as exc:
        raise DotConfigError(f"{where}: not well-formed XML: {exc}") from None

    unbound = root.find("unbound")
    if unbound is None:
        unbound = ET.Element("unbound")
    refid = _text(unbound, "sslcertref")
    if not refid:
        raise DotConfigError(f"{where}: unbound/sslcertref is empty; pick the SSL/TLS Certificate of the DNS Resolver")
    cert = next((entry for entry in root.findall("cert") if _text(entry, "refid") == refid), None)
    if cert is None:
        raise DotConfigError(f"{where}: no <cert> with refid {refid!r} (unbound/sslcertref)")

    chain = [_decode(cert, "cert", "crt", where), *_ca_chain(root, cert, where)]
    key = _decode(cert, "cert", "prv", where)
    port = _text(unbound, "tlsport")
    return DotSettings(
        int(port) if port.isdecimal() and 0 < int(port) < 65536 else DEFAULT_PORT, b"\n".join(chain), key
    )


def _refuse_passphrase() -> NoReturn:
    """Password callback: without one OpenSSL prompts on the terminal, which a daemon cannot answer."""
    raise DotConfigError(
        "the private key of the DNS Resolver's certificate is encrypted with a passphrase; use a key without one"
    )


def server_context(settings: DotSettings) -> ssl.SSLContext:
    """A TLS 1.2+ server context for the settings. load_cert_chain() wants files, so the PEMs go through a private
    (0700) directory of 0600 files that is gone before this returns, however the load ends."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        with tempfile.TemporaryDirectory(prefix="pfb-dot-") as directory:
            paths = []
            for name, pem in (("chain.pem", settings.chain_pem), ("key.pem", settings.key_pem)):
                path = Path(directory, name)
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as handle:
                    handle.write(pem)
                paths.append(path)
            context.load_cert_chain(*paths, password=_refuse_passphrase)
    except OSError as exc:  # a full or read-only /tmp, or ssl.SSLError (an OSError): DoT is off, plain DNS is not
        raise DotConfigError(f"cannot load the DNS Resolver's certificate and key: {exc}") from None
    return context
