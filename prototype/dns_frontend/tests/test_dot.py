"""DNS over TLS on the client side: the pfSense DNS Resolver's own DoT settings (config.xml), a TLS listener, and the
PROXYv2 hop to Unbound that carries the TLS client's address."""

from __future__ import annotations

import asyncio
import os
import re
import ssl
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

import dnswire
import pfb_frontend
import pfsense_dot
import proxyv2
import pytest
from dot_helpers import (
    REFID,
    b64,
    ca_element,
    cert_element,
    config_xml,
    dot_exchange,
    free_port,
    make_certificate,
)
from frontend_constants import ALLOWED, BLOCKED, DNSBL_IPV4, PROTO_DIR
from frontend_helpers import WATCHDOG, FakeProxyUpstream, FakeUnbound, build_query

CRT = b"-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n"
KEY = b"-----BEGIN PRIVATE KEY-----\nREVG\n-----END PRIVATE KEY-----\n"
CA1 = b"-----BEGIN CERTIFICATE-----\nQ0ExCg==\n-----END CERTIFICATE-----\n"
CA2 = b"-----BEGIN CERTIFICATE-----\nQ0EyCg==\n-----END CERTIFICATE-----\n"
VIP4 = bytes(int(octet) for octet in DNSBL_IPV4.split("."))
ZONE = {(ALLOWED, dnswire.TYPE_A): [f"{ALLOWED} 300 IN A 192.0.2.77"]}
OTHER = cert_element("0000other", b64(b"other crt"), b64(b"other key"))


def _write_config(tmp_path: Path, *, entries: str | None = None, **kwargs: Any) -> Path:
    """config.xml with the wanted DoT settings; by default the matching <cert> sits behind a decoy."""
    if entries is None:
        entries = OTHER + cert_element(REFID, b64(CRT), b64(KEY))
    path = tmp_path / "config.xml"
    path.write_text(config_xml(entries=entries, **kwargs), encoding="utf-8")
    return path


@pytest.fixture(scope="module")
def certificate(tmp_path_factory: pytest.TempPathFactory) -> tuple[bytes, bytes]:
    return make_certificate(tmp_path_factory.mktemp("dot-cert"))


# --- config.xml ----------------------------------------------------------------------------------


def test_enabled_resolver_gives_its_port_certificate_and_key(tmp_path: Path) -> None:
    settings = pfsense_dot.read_settings(_write_config(tmp_path, tlsport=8853))
    assert (settings.port, settings.chain_pem, settings.key_pem) == (8853, CRT, KEY)


@pytest.mark.parametrize(
    ("tlsport", "expected"),
    [(None, 853), ("", 853), ("abc", 853), ("0", 853), ("65536", 853), ("-1", 853), (1, 1), (65535, 65535), (443, 443)],
)
def test_tls_port_is_pfsenses_tlsport_and_falls_back_to_853_when_it_is_not_a_port(
    tmp_path: Path, tlsport: object, expected: int
) -> None:
    assert pfsense_dot.read_settings(_write_config(tmp_path, tlsport=tlsport)).port == expected


def test_the_ca_chain_follows_the_certificate_as_unbound_is_given_it(tmp_path: Path) -> None:
    entries = (
        cert_element(REFID, b64(CRT), b64(KEY), caref="ca1")
        + ca_element("ca1", b64(CA1), caref="ca2")
        + ca_element("ca2", b64(CA2))
    )
    settings = pfsense_dot.read_settings(_write_config(tmp_path, entries=entries))
    assert settings.chain_pem == b"\n".join([CRT, CA1, CA2])


def test_a_ca_chain_that_loops_or_breaks_ends_instead_of_hanging(tmp_path: Path) -> None:
    looping = cert_element(REFID, b64(CRT), b64(KEY), caref="ca1") + ca_element("ca1", b64(CA1), caref="ca1")
    assert pfsense_dot.read_settings(_write_config(tmp_path, entries=looping)).chain_pem == b"\n".join([CRT, CA1])
    broken = cert_element(REFID, b64(CRT), b64(KEY), caref="gone")
    assert pfsense_dot.read_settings(_write_config(tmp_path, entries=broken)).chain_pem == CRT


GOOD = cert_element(REFID, b64(CRT), b64(KEY))


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        pytest.param({"enablessl": False}, r"unbound/enablessl is not set", id="disabled"),
        pytest.param({"unbound": False}, r"unbound/enablessl is not set", id="no-unbound-section"),
        pytest.param({"certref": None}, r"unbound/sslcertref is empty", id="no-certref"),
        pytest.param({"certref": ""}, r"unbound/sslcertref is empty", id="empty-certref"),
        pytest.param({"certref": "nope"}, r"no <cert> with refid 'nope'", id="wrong-refid"),
        pytest.param({"entries": ""}, rf"no <cert> with refid '{REFID}'", id="no-certs-at-all"),
        pytest.param({"entries": cert_element(REFID, None, b64(KEY))}, r"has no crt", id="no-crt"),
        pytest.param({"entries": cert_element(REFID, "", b64(KEY))}, r"has no crt", id="empty-crt"),
        pytest.param({"entries": cert_element(REFID, b64(CRT), None)}, r"has no prv", id="no-prv"),
        pytest.param(
            {"entries": cert_element(REFID, "!!not base64!!", b64(KEY))}, r"crt .*not valid base64", id="bad-crt"
        ),
        pytest.param({"entries": cert_element(REFID, b64(CRT), "QUJD=Z")}, r"prv .*not valid base64", id="bad-prv"),
        pytest.param(
            {"entries": cert_element(REFID, b64(CRT), b64(KEY), caref="ca1") + ca_element("ca1", "%%%")},
            r"ca1.*not valid base64",
            id="bad-ca-crt",
        ),
    ],
)
def test_a_resolver_that_cannot_serve_dot_is_a_clear_error(
    tmp_path: Path, kwargs: dict[str, Any], message: str
) -> None:
    kwargs.setdefault("entries", GOOD)
    path = _write_config(tmp_path, **kwargs)
    with pytest.raises(pfsense_dot.DotConfigError, match=message) as error:
        pfsense_dot.read_settings(path)
    assert str(path) in str(error.value)


def test_a_missing_or_malformed_config_is_a_clear_error(tmp_path: Path) -> None:
    with pytest.raises(pfsense_dot.DotConfigError, match=re.escape(str(tmp_path / "absent.xml"))):
        pfsense_dot.read_settings(tmp_path / "absent.xml")
    broken = tmp_path / "broken.xml"
    broken.write_text("<pfsense><unbound>", encoding="utf-8")
    with pytest.raises(pfsense_dot.DotConfigError, match="not well-formed XML"):
        pfsense_dot.read_settings(broken)


# --- the TLS context -----------------------------------------------------------------------------


def test_the_context_is_loaded_from_private_files_that_do_not_outlive_it(
    certificate: tuple[bytes, bytes], monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[tuple[int, int, int]] = []
    paths: list[Path] = []
    real = ssl.SSLContext.load_cert_chain

    def spy(self: ssl.SSLContext, certfile: Any, keyfile: Any = None, password: Any = None) -> None:
        cert, key = Path(certfile), Path(keyfile)
        paths.extend([cert, key])
        seen.append(tuple(stat.S_IMODE(os.stat(p).st_mode) for p in (cert.parent, cert, key)))  # type: ignore[arg-type]
        real(self, certfile, keyfile, password)

    monkeypatch.setattr(ssl.SSLContext, "load_cert_chain", spy)
    context = pfsense_dot.server_context(pfsense_dot.DotSettings(853, *certificate))
    assert seen == [(0o700, 0o600, 0o600)]
    assert [p.exists() for p in paths] == [False, False] and not paths[0].parent.exists()
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2
    assert context.protocol == ssl.PROTOCOL_TLS_SERVER


def test_a_certificate_that_does_not_load_is_a_clear_error(certificate: tuple[bytes, bytes]) -> None:
    junk = pfsense_dot.DotSettings(853, CRT, KEY)
    with pytest.raises(pfsense_dot.DotConfigError, match="cannot load"):
        pfsense_dot.server_context(junk)
    mismatched = pfsense_dot.DotSettings(853, certificate[0], KEY)
    with pytest.raises(pfsense_dot.DotConfigError, match="cannot load"):
        pfsense_dot.server_context(mismatched)


# --- real sockets --------------------------------------------------------------------------------


def test_serve_with_dot_answers_a_tls_client_and_forwards_with_the_tls_peers_address(
    module_dir: Path, tmp_path: Path, certificate: tuple[bytes, bytes], monkeypatch: pytest.MonkeyPatch
) -> None:
    crt, key = certificate
    trust = tmp_path / "trust.pem"
    trust.write_bytes(crt)
    port = free_port()
    config = _write_config(tmp_path, tlsport=port, entries=OTHER + cert_element(REFID, b64(crt), b64(key)))
    monkeypatch.chdir(module_dir)
    monkeypatch.setattr(sys, "stderr", sys.stderr)
    real_boot = pfb_frontend.boot

    def boot_without_log_files(directory: str) -> Any:
        module = real_boot(directory)
        monkeypatch.setattr(module, "pfb_log", lambda name, line: None)  # the module logs to /var/log/pfblockerng
        return module

    monkeypatch.setattr(pfb_frontend, "boot", boot_without_log_files)

    async def scenario() -> tuple[Any, ...]:
        async with FakeProxyUpstream(FakeUnbound(ZONE)) as upstream:
            args = pfb_frontend.parse_args(
                ["--listen", "127.0.0.1", "--port", "0", "--upstream", f"127.0.0.1:{upstream.port}"]
                + ["--module-dir", str(module_dir), "--dot", "--pfsense-config", str(config)]
            )
            stop = asyncio.Event()
            ready: asyncio.Future[list[tuple[str, int]]] = asyncio.get_running_loop().create_future()
            task = asyncio.create_task(pfb_frontend.serve(args, stop=stop, on_ready=ready.set_result))
            try:
                [plain, dot] = await asyncio.wait_for(ready, WATCHDOG)
                blocked, _, _ = await dot_exchange(dot, build_query(BLOCKED), trust, source="127.0.0.5")
                headers_after_block = list(upstream.headers)
                allowed, client, _ = await dot_exchange(dot, build_query(ALLOWED), trust, source="127.0.0.5")
                return plain, dot, blocked, headers_after_block, allowed, client, list(upstream.headers)
            finally:
                stop.set()
                await asyncio.wait_for(task, WATCHDOG)

    plain, dot, blocked, headers_after_block, allowed, client, headers = asyncio.run(scenario())
    assert dot == ("127.0.0.1", port) and plain[1] != port  # DoT is its own listener on the resolver's tlsport
    assert [(rr.name, rr.rtype, rr.rdata) for rr in dnswire.parse(blocked).answers] == [(BLOCKED, 1, VIP4)]
    assert headers_after_block == []  # a blocked name never leaves the front end
    assert allowed == FakeUnbound(ZONE).answer(build_query(ALLOWED))
    assert client[0] == "127.0.0.5"
    assert headers == [proxyv2.header(client, dot, tcp=True)]  # PROXYv2 TCP header with the TLS client's address


@pytest.mark.parametrize(
    ("max_version", "negotiated"), [(ssl.TLSVersion.TLSv1_2, "TLSv1.2"), (None, "TLSv1.3")], ids=["tls1.2", "tls1.3"]
)
def test_tls_1_2_and_1_3_clients_are_both_served(
    booted: Any, tmp_path: Path, certificate: tuple[bytes, bytes], max_version: Any, negotiated: str
) -> None:
    crt, _ = certificate
    trust = tmp_path / "trust.pem"
    trust.write_bytes(crt)

    async def scenario() -> tuple[bytes, str]:
        frontend = pfb_frontend.Frontend(booted.module, ("127.0.0.1", 9), timeout=WATCHDOG)
        [server] = await frontend.start_dot(
            ["127.0.0.1"], 0, pfsense_dot.server_context(pfsense_dot.DotSettings(853, *certificate))
        )
        try:
            reply, _, version = await dot_exchange(server, build_query(BLOCKED), trust, max_version=max_version)
            return reply, version
        finally:
            await frontend.stop()

    reply, version = asyncio.run(scenario())
    assert (dnswire.parse(reply).rcode, version) == (0, negotiated)


# --- the CLI -------------------------------------------------------------------------------------


def test_cli_dot_options_default_to_off_and_pfsenses_config_path() -> None:
    args = pfb_frontend.parse_args([])
    assert (args.dot, args.pfsense_config) == (False, "/cf/conf/config.xml")
    args = pfb_frontend.parse_args(["--dot", "--pfsense-config", "/tmp/c.xml"])
    assert (args.dot, args.pfsense_config) == (True, "/tmp/c.xml")


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [({"enablessl": False}, "enablessl"), ({"certref": "nope"}, "refid 'nope'")],
    ids=["disabled", "missing-cert"],
)
def test_dot_misconfiguration_exits_1_with_a_message_before_the_module_boots(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    kwargs: dict[str, Any],
    message: str,
) -> None:
    monkeypatch.setattr(pfb_frontend, "boot", lambda *_: pytest.fail("the module must not boot"))
    config = _write_config(tmp_path, **kwargs)
    assert pfb_frontend.main(["--dot", "--pfsense-config", str(config), "--listen", "127.0.0.1", "--port", "0"]) == 1
    err = capsys.readouterr().err
    assert message in err and str(config) in err and "Traceback" not in err


def test_dot_misconfiguration_makes_the_real_process_exit_non_zero(tmp_path: Path) -> None:
    config = _write_config(tmp_path, enablessl=False)
    run = subprocess.run(
        [sys.executable, str(PROTO_DIR / "pfb_frontend.py"), "--dot", "--pfsense-config", str(config)]
        + ["--listen", "127.0.0.1", "--port", "0", "--module-dir", str(tmp_path)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert run.returncode == 1 and "unbound/enablessl is not set" in run.stderr and "Traceback" not in run.stderr
