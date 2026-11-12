"""Issue #3513, step 5: the Go DNS gateway in front of Unbound on a live pfSense, asked from a LAN client over every
transport.

The package ships the gateway as ``pfb-dns``, one raw FreeBSD binary per architecture under ``dns_proxy/bin/``, and
``pfb_dns.sh``, which runs the one for the machine; with the DNS Proxy toggle on, pfBlockerNG's rc script runs that
wrapper under daemon(8). The gateway decides in-process and has no child. This module installs nothing of its own for
the gateway, so a broken package cannot hide behind an uploaded binary: it asserts the INSTALLED package's payload,
turns DoH and DoQ on next to the toggle, and watches the box and the LAN client VM. Only the client's DoQ probe,
``pfb_doq_probe``, is built here, from ``go/``, with the Go that built the package (smoke-on-box.sh's, CI's, or, when
there is none, the pinned one scripts/go_toolchain.py installs in this module's scratch directory and deletes).

Module setup, put back in ``finally`` (``test_smoke_dns_proxy.py`` drives the same gateway through the toggle's
lifecycle: modes, restarts, boot, removal)::

    Resolver: DoT on with a self-signed certificate, ``log-queries: yes`` in Custom Options
    DNSBL:    one feed listing every name the tests expect to be blocked; DoH on 4443 and DoQ on 853 on the LAN

What it proves, in file order:

* package: both ``pfb-dns`` binaries are 0555 and byte-equal to the built ``.pkg``'s members, ``pfb_dns.sh`` is 0644
  (run as ``/bin/sh``), and the installed package's ABI is a wildcard (``NO_ARCH``);
* service: the daemon supervises ``pfb-dns``, the binary ``pfb_dns.sh`` chose for ``uname -p`` (the wrapper exec'd, so
  the pidfile's pid is the gateway's), which published that pid in ``/var/unbound/pfb_dns_ready``; it runs as
  ``unbound`` with ``--module-dir /var/unbound`` and no `` -- `` decider command, has no child, and no process runs
  ``pfb_dns_proxy.py``; ``dns_proxy.log`` has the ``listening`` lines and
  ``ready upstream 127.0.0.1:5353 pid N``, N the gateway's; the gateway owns every client-facing socket (DoH and DoQ on
  loopback too, for a local HAProxy) and Unbound listens on loopback 5353 and 5354 only;
* DNS General's status panel is one table per transport with a Localhost row (loopbacks plus the served lo0 VIP
  for plain DNS and DoT) and a LAN row (the LAN address), each reading ``Listening`` for a screen reader (issue #3555);
* when Unbound stops under the live gateway (issues #3560, #3848), the status panel names the lost backend and every
  table keeps its ``Listening`` rows; the Resolver is restored afterwards and an allowed name resolves again;
* Unbound runs the upstream observer, an upstream EDE block is logged with the real client, and the firewall's own
  lookup of a listed name gets the VIP, logged as 127.0.0.1;
* from the LAN client (192.168.1.10), over UDP, TCP, DoT, DoH (POST and GET) and DoQ: a listed name gets the VIP and a
  ``dnsbl.log`` row naming the client; an allowed name gets the upstream's answer and ``resolver.log`` names the client;
* hostile: DoQ from a client that does not trust the certificate, and DoH spoken as plain HTTP, get no answer;
* a Resolver ACL row for the client: ``refuse`` gets REFUSED on every transport (never the VIP, no ``dnsbl.log`` row)
  and removing it brings the VIP back; ``deny`` gets no answer on any transport while a second LAN address that no
  row names still gets the VIP on every transport (DoQ from it through a host route that sets its source address);
* a client no row names (the automatic LAN rows off, the only list naming 203.0.113.0/24) gets REFUSED on every
  transport for a listed and for an unlisted name, as Unbound refuses it, while an IPv6 LAN client that only
  pfBlockerNG's marked clause in unbound.conf grants still gets the VIP (the firewall asking its own LAN IPv6 address
  over UDP and TCP; the client VM too, on every transport, through the fixture's scoped leased IPv6 DNS pass rules);
* DDR (issue #3583, its target name issue #3694), with ``dns_shared/pfb_dns_ddr`` on, the DNS name set
  (``dns/pfb_dns_name``) and the gateway restarted with ``--dns-name NAME --ddr``: ``_dns.resolver.arpa. SVCB``
  over UDP and TCP gets the DoH, DoT and DoQ records for the LAN address (alpn, ``port`` only off its default,
  ``dohpath``, ``ipv4hint``, the DNS name as TargetName, its A record in Additional); another type or name under
  ``resolver.arpa.`` and the SVCB query over DoT and DoH get NODATA with the 300-second SOA, apex SOA and NS are
  answered, and Unbound's query log never names ``resolver.arpa``, so Unbound saw none of them; a client the Resolver
  ACL refuses gets REFUSED; with the toggle off the client gets what Unbound itself answers, asked on the box at
  port 5354; with the LAN in ``dns/pfb_dns_ddr_doh_443_interfaces`` (issue #3694) the DoH record at its address has no
  ``port`` and keeps its hint and path;
* the DNS name (issue #3694) is answered over plain DNS with the address the query reached: A at the LAN address is
  the LAN address and A at an automatic Resolver VIP is the VIP, in any letter case; a subdomain of it is Unbound's;
* automatic Resolver VIPs use only standard transport ports, and DDR advertises those actual bound ports while ordinary
  interfaces retain their configured ports;
* ``rc stop`` ends the gateway and the supervisor; toggle off gives the Resolver back, no gateway left.

DESELECTED from the default ``python -m pytest``. Run it on the pool::

    scripts/local-smoke.sh --ref <branch or sha> --filter test_smoke_dns_gateway
"""

from __future__ import annotations

import contextlib
import csv
import hashlib
import html
import ipaddress
import json
import os
import re
import secrets
import shlex
import shutil
import subprocess
import xml.etree.ElementTree as ET
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from scripts import go_toolchain as pinned_go

from . import helpers as h
from .conftest import CLIENT_LAN_IP, PFSENSE_LAN_IP, STUB_DNS_A, SmokeVM, _StubDnsServer
from .pkg_identity import branch_pkg_name
from .test_smoke_dns_proxy import (
    ACCESS_LISTS,
    CERT_CLIENT,
    CERT_GUEST,
    CERT_NAME,
    CFG_REPLY_LOG,
    DAEMON_PID_FILE,
    LAN_V6_ADDR,
    LAN_V6_ROW,
    MODULE_LINE,
    OBSERVER_SCRIPT,
    PROXY_PID_FILE,
    PROXY_RC,
    RESOLVER_LOG,
    SNAPSHOT_PATHS,
    UNIFIED_LOG,
    UPSTREAM_PORT,
    Listener,
    State,
    _apply,
    _assert_no_python_module,
    _capture,
    _client_alias,
    _configure_resolver,
    _create_cert,
    _diagnostics,
    _dnsbl_rows,
    _firewall_lookup,
    _force_stop_proxy,
    _is_on,
    _lines,
    _listeners,
    _php_ok,
    _pid_file,
    _proxy_log,
    _put_reply_logging,
    _reply_rows,
    _set_proxy_toggle,
    _sh,
    _unbound_conf_report,
    _wait_dnsbl_row,
    _wait_unbound_logged,
)
from .test_syslog_export import CFG_GENERAL, PFB_SYSLOG_LOG, _capture_raw_syslog_history, _set_syslog_enabled
from .ui.credgate import admin_password_decision
from .ui.webui import WebUI, row_containing

pytestmark = [pytest.mark.smoke, pytest.mark.timeout(180)]

GO_DIR = Path(__file__).resolve().parents[2] / "go" / "pfb_dns_gateway"
# the client VM's `uname -m`
GOARCH_OF_UNAME = {"amd64": "amd64", "x86_64": "amd64", "arm64": "arm64", "aarch64": "arm64"}

PACKAGE_DIR = "/usr/local/pkg/pfblockerng/dns_proxy"
WRAPPER = f"{PACKAGE_DIR}/pfb_dns.sh"
# `uname -p` on the guest -> the directory pfb_dns.sh must have chosen: the package's contract, restated here so a
# wrapper that picked wrongly cannot agree with itself
TARGET_OF_UNAME_P = {"amd64": "freebsd-amd64", "aarch64": "freebsd-arm64", "arm64": "freebsd-arm64"}
PAYLOAD_TARGETS = ("freebsd-amd64", "freebsd-arm64")
READY_FILE = "/var/unbound/pfb_dns_ready"  # pfb-dns writes its own pid here once it serves
PROBE_BIN = "/tmp/pfb_doq_probe"  # on the client VM
DOT_PORT, DOH_PORT, DOQ_PORT = 853, 4443, 853
FEED_HEADER = "smoke3513"
BYPASSED_ALIAS_IP = "192.168.1.12"  # a second LAN address on the client: no ACL row names it
ACL_NAME = "pfb3513 smoke"
LAN_V6_CLIENT = h.IPV6_LOCAL_HOST  # taken by the client inside the LAN's IPv6 /64, which only the marked clause grants
OTHER_ACL_NET = ("203.0.113.0", "24")  # TEST-NET-3: an access list that names nobody on the LAN
AUTO_ROWS_OFF = "unbound/disable_auto_added_access_control"  # pfSense's switch for the LAN rows it adds by itself
LOOPBACK = {"127.0.0.1", "::1"}  # DoH and DoQ always listen here too, whatever interfaces they are given
LAN_CONFIG_DESCRIPTION = "PFB3757LAN"
LAN_DESCRIPTION = "PFB3757LAN"  # pfSense's interface API canonicalizes descriptions to uppercase
SYSLOG_OWNER_DESCRIPTION = 'LAN, "旧" & OWNER'
SNAPSHOT_FILE = "/tmp/pfb3513_cfg_snapshot.json"  # on the guest: survives a dead test process

LISTENER_SETTINGS = {
    "pfb_dns_doh": "on",
    "pfb_dns_doh_port": str(DOH_PORT),
    "pfb_dns_doh_interface": "lan",
    "pfb_dns_doq": "on",
    "pfb_dns_doq_port": str(DOQ_PORT),
    "pfb_dns_doq_interface": "lan",
}
CFG_DDR = h.dns_config_path("pfb_dns_ddr")  # issue #3583: the DDR toggle
CFG_DDR_DOH_443 = h.dns_config_path("pfb_dns_ddr_doh_443_interfaces")  # issue #3694: "Advertise DoH on port 443"
DDR_443_INTERFACES = "lan"  # the DoH interface the 443 advertisement is selected for
CFG_DNS_NAME = h.dns_config_path("pfb_dns_name")  # issue #3694: DDR's target name, and the name the gateway answers
DDR_DNS_NAME = h.unique_domain("ddrname")  # inert: not RFC 6761, not HSTS-preloaded, listed in no feed
DDR_TARGET = f"{DDR_DNS_NAME}."  # the SVCB TargetName and the Additional record's owner, as dig prints them
# SNAPSHOT_PATHS already holds the interface lists, which LISTENER_SETTINGS names again
CONFIG_PATHS = tuple(
    dict.fromkeys(
        (
            *SNAPSHOT_PATHS,
            *(h.dns_config_path(key) for key in LISTENER_SETTINGS),
            "unbound/acls",
            AUTO_ROWS_OFF,
            CFG_DDR,
            CFG_DDR_DOH_443,
            CFG_DNS_NAME,
            CFG_REPLY_LOG,
            "interfaces/lan/descr",
            "filter/rule",
            h.dns_config_path("pfb_dns_doh_trusted"),
            # DNS General's Resolver addresses: the tests switch them on, and the apply pass records the VIP row it adds
            f"{h.CFG_GLOBAL}/pfb_dns_listen_vip",
            f"{h.CFG_GLOBAL}/pfb_dns_listen_vip_only",
            f"{h.CFG_GLOBAL}/pfb_dns_listen_vip4",
            f"{h.CFG_GLOBAL}/pfb_dns_listen_vip6",
            f"{h.CFG_GLOBAL}/pfb_dns_listen_interface",
            f"{h.CFG_GLOBAL}/pfb_dns_listen_auto4",
            f"{h.CFG_GLOBAL}/pfb_dns_listen_auto6",
            f"{h.CFG_GLOBAL}/pfb_dns_listen_added",
            "virtualip/vip",
        )
    )
)

TRANSPORTS = ("udp", "tcp", "dot", "doh-post", "doh-get", "doq")
LOG_TRANSPORT = {"udp": "UDP", "tcp": "TCP", "dot": "DoT", "doh-post": "DoH", "doh-get": "DoH", "doq": "DoQ"}


def _drain_logs(gw: Gateway, *, port: int = 53) -> None:
    """A fresh completed reply drains the gateway's earlier log writes."""
    name = h.unique_domain("transport-log-barrier")
    answer, raw = _ask(gw.client, "udp", name, port=port)
    assert h.resolves_to(answer, STUB_DNS_A), f"log barrier {name}: {answer}\n{raw}"
    h.wait_until(lambda: bool(_reply_rows(gw.vm, name, UNIFIED_LOG)), timeout=30.0)


def _assert_unified_row(vm: SmokeVM, row: list[str], name: str, name_col: int) -> None:
    feature = "dnsbl.log" if name_col == 2 else "dns_reply.log"
    lines = h.read_log_file(vm, f"{h.PFB_LOGDIR}/{feature}").splitlines()
    originals = [line for line in lines if next(csv.reader([line])) == row]
    assert originals, f"{feature} lacks {name} row: {row}"
    original = originals[0]
    try:
        h.wait_until(
            lambda: h.read_log_file(vm, UNIFIED_LOG).splitlines().count(original) == len(originals), timeout=30.0
        )
    except RuntimeError as exc:
        raise RuntimeError(f"unified.log lacks byte-identical {name} row: {original!r}") from exc


def _assert_report_row(
    gui: WebUI, name: str, client: str, transport: str, listener: str = PFSENSE_LAN_IP, interface: str = LAN_DESCRIPTION
) -> None:
    response = gui.get("/pfblockerng/pfblockerng_alerts.php?view=unified")
    assert response.status_code == 200, f"Reports GET: {response.status_code}"
    row = row_containing(response.text, name)
    cells = [
        html.unescape(re.sub(r"<[^>]*>", "", cell)).strip()
        for cell in re.findall(r"<td\b[^>]*>(.*?)</td>", row, re.DOTALL)
    ]
    assert re.search(r"<th\b[^>]*>\s*Transport\s*</th>", response.text), "Reports lacks a Transport column"
    assert cells[-3:] == [transport, listener, interface], f"Reports endpoint snapshot for {name}: {cells}"
    assert len(cells) == 12, cells
    assert re.search(r"<th\b[^>]*>\s*Receiving IP\s*</th>", response.text)
    assert re.search(r"<th\b[^>]*>\s*Receiving interface\s*</th>", response.text)
    assert len(cells) > 2 and re.search(rf"(?<![\d.:]){re.escape(client)}(?![\d.:])", cells[2]), (
        f"Reports client cell for {name}: expected {client}, got {cells}"
    )


_TLS = (f"+tls-ca={CERT_CLIENT}", f"+tls-hostname={CERT_NAME}")
# dig options and port per transport; DoQ has no dig (pfb_doq_probe). "doh-plain" is DoH spoken without TLS.
DIG_TRANSPORTS: dict[str, tuple[tuple[str, ...], int | None]] = {
    "udp": ((), None),
    "tcp": (("+tcp",), None),
    "dot": (("+tls", *_TLS), None),
    "doh-post": (("+https", *_TLS), DOH_PORT),
    "doh-get": (("+https-get", *_TLS), DOH_PORT),
    "doh-plain": (("+http-plain",), DOH_PORT),
}


def _say(message: str) -> None:
    print(f"[3513] {message}", flush=True)


@dataclass(frozen=True)
class Names:
    """Every listed name has its own case; allowed names are made where they are asked."""

    ready: str  # asked until the gateway serves
    blocked: dict[str, str]  # per transport
    logged: dict[str, str]  # reserved for the one-query-per-transport log assertions
    logged_v6: dict[str, str]  # dedicated endpoint metadata coverage
    syslog: dict[str, str]  # never reused: one exported endpoint event per transport
    refused: dict[str, str]  # per transport, asked while the ACL refuses the client
    denied: dict[str, str]  # per transport, asked while the ACL denies the client
    restored: dict[str, str]  # per transport, asked after the refuse row is gone
    alive: dict[str, str]  # per transport, asked from a second LAN address while the ACL denies the client
    nomatch: dict[str, str]  # per transport, asked while no ACL row names the client
    nomatch_restored: dict[str, str]  # per transport, asked after the lists are back
    v6: dict[str, str]  # per transport, asked by the IPv6 LAN client while no ACL row names the IPv4 one
    fw_v6: tuple[str, str]  # UDP and TCP, asked by the firewall itself of its own LAN IPv6 address
    refuse_poll: str  # asked until the refuse row shows
    deny_poll: str
    nomatch_poll: str  # asked until no row names the client
    refuse_barrier: str  # asked by an address the ACL does not name, to drain dnsbl.log
    deny_barrier: str
    v6_barrier: str  # asked last by the IPv6 client, to drain dnsbl.log
    firewall: str  # only the firewall's own lookups ask for it
    hostile: tuple[str, str]  # DoQ without trust; DoH over plain HTTP

    def listed(self) -> list[str]:
        per_transport = (
            *self.logged.values(),
            *self.logged_v6.values(),
            *self.syslog.values(),
            *self.blocked.values(),
            *self.refused.values(),
            *self.denied.values(),
            *self.restored.values(),
            *self.alive.values(),
            *self.nomatch.values(),
            *self.nomatch_restored.values(),
            *self.v6.values(),
        )
        return [
            self.ready,
            *per_transport,
            self.refuse_poll,
            self.deny_poll,
            self.nomatch_poll,
            self.refuse_barrier,
            self.deny_barrier,
            self.v6_barrier,
            *self.fw_v6,
            self.firewall,
            *self.hostile,
        ]


def _make_names() -> Names:
    def per_transport(label: str) -> dict[str, str]:
        return {transport: h.unique_domain(f"{label}-{transport}") for transport in TRANSPORTS}

    return Names(
        ready=h.unique_domain("ready"),
        blocked=per_transport("blocked"),
        logged=per_transport("logged"),
        logged_v6=per_transport("logged-v6"),
        syslog=per_transport("endpoint-syslog"),
        refused=per_transport("refused"),
        denied=per_transport("denied"),
        restored=per_transport("restored"),
        alive=per_transport("alive"),
        nomatch=per_transport("nomatch"),
        nomatch_restored=per_transport("nmback"),
        v6=per_transport("v6"),
        fw_v6=(h.unique_domain("fwv6-udp"), h.unique_domain("fwv6-tcp")),
        refuse_poll=h.unique_domain("refpoll"),
        deny_poll=h.unique_domain("denpoll"),
        nomatch_poll=h.unique_domain("nmpoll"),
        refuse_barrier=h.unique_domain("refbar"),
        deny_barrier=h.unique_domain("denbar"),
        v6_barrier=h.unique_domain("v6bar"),
        firewall=h.unique_domain("firewall"),
        hostile=(h.unique_domain("nocert"), h.unique_domain("plain")),
    )


@dataclass(frozen=True)
class Gateway:
    vm: SmokeVM
    client: SmokeVM
    names: Names
    before: State  # the Resolver with the toggle off (DNSBL is off with it): Unbound plain on 53 and 853


# --------------------------------------------------------------------------- #
# The DoQ probe for the client VM, built on the box where pytest runs
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class GoToolchain:
    go: Path
    env: dict[str, str]


@pytest.fixture(scope="module")
def go_toolchain(tmp_path_factory: pytest.TempPathFactory) -> Iterator[GoToolchain]:
    """The Go that built the package, reused: the `go` on PATH (smoke-on-box.sh's pinned one, or the CI image's).

    A run with none installs the pinned toolchain (scripts/go_toolchain.py) in this module's scratch directory and
    removes it after; a toolchain it did not install is never touched.
    """
    found = shutil.which("go")
    if found:
        version = subprocess.run([found, "version"], capture_output=True, text=True, timeout=60, check=False)
        _say(f"toolchain: {version.stdout.strip()} ({found}, already installed)")
        yield GoToolchain(Path(found), {**os.environ, "GOTOOLCHAIN": "local", "CGO_ENABLED": "0"})
        return
    root = pinned_go.install(tmp_path_factory.mktemp("go-toolchain"))
    try:
        _say(f"toolchain: {pinned_go.GO_VERSION} installed in {root}")
        yield GoToolchain(root / "go" / "bin" / "go", {**os.environ, **pinned_go.environment(root), "CGO_ENABLED": "0"})
    finally:
        pinned_go.remove(root)
    assert not root.exists(), f"the Go toolchain directory {root} is still there after the delete"


def _go_build(toolchain: GoToolchain, package: str, goos: str, goarch: str, out: Path) -> None:
    result = subprocess.run(
        [str(toolchain.go), "build", "-trimpath", "-ldflags=-s -w", "-o", str(out), package],
        cwd=GO_DIR,
        env={**toolchain.env, "GOOS": goos, "GOARCH": goarch},
        capture_output=True,
        text=True,
        timeout=900,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"go build {package} for {goos}/{goarch} failed:\n{result.stdout}\n{result.stderr}")


def _goarch(vm: SmokeVM, role: str) -> str:
    machine = vm.ssh("uname -m").stdout.strip()
    if machine not in GOARCH_OF_UNAME:
        raise RuntimeError(f"{role}: `uname -m` says {machine!r}; known: {sorted(GOARCH_OF_UNAME)}")
    return GOARCH_OF_UNAME[machine]


@pytest.fixture(scope="module")
def probe_binary(go_toolchain: GoToolchain, client_vm: SmokeVM, tmp_path_factory: pytest.TempPathFactory) -> Path:
    """pfb_doq_probe for the client VM's architecture (Linux): the one binary this module builds."""
    probe = tmp_path_factory.mktemp("go-binaries") / "pfb_doq_probe"
    arch = _goarch(client_vm, "client VM")
    _go_build(go_toolchain, "./cmd/pfb_doq_probe", "linux", arch, probe)
    _say(f"pfb_doq_probe linux/{arch}: {probe.stat().st_size} bytes")
    return probe


def _upload(vm: SmokeVM, binary: Path, dest: str, owner: str) -> None:
    """Copy `binary` to `dest` (0755) and check the copy's sha256 against the built file's."""
    payload = binary.read_bytes()
    command = f"cat > {dest}.new && chmod 0755 {dest}.new && chown {owner} {dest}.new && mv {dest}.new {dest}"
    result = subprocess.run(vm.ssh_argv(command), input=payload, capture_output=True, timeout=180, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"installing {dest} failed: rc={result.returncode} {result.stderr!r}")
    digest = vm.ssh(f"sha256 -q {dest} 2>/dev/null || sha256sum {dest}").stdout.split()
    expected = hashlib.sha256(payload).hexdigest()
    assert digest[:1] == [expected], f"{dest} on the guest: sha256 {digest}, built {expected}"


def _guest_mode(vm: SmokeVM, path: str) -> str:
    return vm.ssh(f"stat -f '%Lp' {path}").stdout.strip()


def _package_member_sha256(pkg: str, suffix: str) -> str:
    """sha256 of the one member of the built .pkg whose path ends in `/<suffix>`; tar finds its compression."""
    listing = subprocess.run(["tar", "-tf", pkg], capture_output=True, text=True, timeout=180, check=True)
    members = [name for name in listing.stdout.splitlines() if name.endswith(f"/{suffix}")]
    assert len(members) == 1, f"{pkg} members ending in {suffix}: {members}"
    data = subprocess.run(["tar", "-xOf", pkg, "--", members[0]], capture_output=True, timeout=180, check=True).stdout
    return hashlib.sha256(data).hexdigest()


def _selected_binary(vm: SmokeVM) -> str:
    """The pfb-dns pfb_dns.sh must run on this machine: the table above, applied to the guest's own `uname -p`."""
    machine = vm.ssh("uname -p").stdout.strip()
    assert machine in TARGET_OF_UNAME_P, f"`uname -p` says {machine!r}; the package knows {sorted(TARGET_OF_UNAME_P)}"
    return f"{PACKAGE_DIR}/bin/{TARGET_OF_UNAME_P[machine]}/pfb-dns"


def _record_client_tools(client: SmokeVM) -> None:
    out = client.ssh(
        "uname -m; dig -v 2>&1; dig -h 2>&1 | grep -E 'https|tls'; kdig -V 2>&1 | head -1; "
        "curl --version 2>&1 | head -1; python3 -V 2>&1; openssl version 2>&1"
    ).stdout
    _say(f"client VM tools:\n{out}")


# --------------------------------------------------------------------------- #
# Queries
# --------------------------------------------------------------------------- #


def _host_port(server: str, port: int) -> str:
    return f"[{server}]:{port}" if ":" in server else f"{server}:{port}"


def _ask_doq(
    client: SmokeVM, name: str, ca: str | None = CERT_CLIENT, server: str = PFSENSE_LAN_IP, port: int = DOQ_PORT
) -> tuple[h.DnsAnswer, str]:
    """pfb_doq_probe from the client; its stdout is `rcode X` then `answer <name> <type> <rdata>` lines."""
    args = [PROBE_BIN, "-server", _host_port(server, port), "-name", name, "-sni", CERT_NAME, "-timeout", "5s"]
    if ca:
        args += ["-ca", ca]
    result = client.ssh(shlex.join(args) + " 2>&1", timeout=40.0)
    output = f"{result.stdout}\n[exit {result.returncode}]"
    lines = result.stdout.splitlines()
    if result.returncode != 0 or not lines or not lines[0].startswith("rcode "):
        return h.DnsAnswer("UNKNOWN", []), output
    fields = (line.split() for line in lines[1:])
    return h.DnsAnswer(lines[0].split()[1], [f[3] for f in fields if len(f) == 4 and f[:1] == ["answer"]]), output


def _ask(
    client: SmokeVM,
    transport: str,
    name: str,
    *,
    source: str | None = None,
    server: str = PFSENSE_LAN_IP,
    port: int | None = None,
) -> tuple[h.DnsAnswer, str]:
    """The parsed answer and the tool's full output; no answer reads as rcode UNKNOWN with the tool's complaint.

    `port` replaces the transport's configured port.
    """
    if transport == "doq":
        return _ask_doq(client, name, server=server, port=port or DOQ_PORT)
    options, default_port = DIG_TRANSPORTS[transport]
    port = port or default_port
    args = ["dig", "+tries=1", "+time=5", *options]
    if source:
        args += ["-b", source]
    if port:
        args += ["-p", str(port)]
    args += ["A", name, f"@{server}"]
    result = client.ssh(shlex.join(args) + " 2>&1", timeout=40.0)
    return h._parse_dig(result.stdout, "A"), f"{result.stdout}\n[exit {result.returncode}]"


def _ask_all(gw: Gateway, names: dict[str, str]) -> dict[str, tuple[h.DnsAnswer, str]]:
    return {transport: _ask(gw.client, transport, names[transport]) for transport in TRANSPORTS}


def _expect_everywhere(
    what: str, results: dict[str, tuple[h.DnsAnswer, str]], ok: Callable[[h.DnsAnswer], bool], expected: str
) -> None:
    for transport, (answer, raw) in results.items():
        tail = " | ".join([line for line in raw.splitlines() if line.strip()][-2:])
        tail = f" ({tail})" if answer.rcode == "UNKNOWN" else ""
        _say(f"{what}, {transport}: {answer.rcode} {answer.records}{tail}")
    wrong = {transport: result for transport, result in results.items() if not ok(result[0])}
    assert not wrong, f"{what}: expected {expected} on every transport; differing:\n" + "\n".join(
        f"{transport}: got {answer}\n{raw}" for transport, (answer, raw) in wrong.items()
    )


def _no_answer(answer: h.DnsAnswer) -> bool:
    return answer.rcode == "UNKNOWN" and not answer.records


def _refused(answer: h.DnsAnswer) -> bool:
    return answer.rcode == "REFUSED" and not answer.records


def _assert_answered_by_upstream(gw: Gateway, name: str, answer: h.DnsAnswer, raw: str, how: str) -> None:
    assert h.resolves_to(answer, STUB_DNS_A), f"{how}: {name} expected the upstream's {STUB_DNS_A}, got {answer}\n{raw}"
    clients = _wait_unbound_logged(gw.vm, name)
    assert clients == [CLIENT_LAN_IP], f"{how}: resolver.log for {name} should name {CLIENT_LAN_IP}, got {clients}"


# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #


def _snapshot(vm: SmokeVM) -> None:
    paths = ", ".join(h._php_str(p) for p in CONFIG_PATHS)
    _php_ok(
        vm,
        f"$snap = array();\n"
        f"foreach (array({paths}) as $p) {{\n"
        "  $v = config_get_path($p, NULL);\n"
        "  $snap[$p] = array('present' => $v !== NULL, 'value' => $v);\n"
        "}\n"
        f"file_put_contents({h._php_str(SNAPSHOT_FILE)}, json_encode($snap));\n"
        f"chmod({h._php_str(SNAPSHOT_FILE)}, 0600);",
        "config snapshot",
    )


def _restore(vm: SmokeVM) -> None:
    _php_ok(
        vm,
        f"$snap = json_decode(file_get_contents({h._php_str(SNAPSHOT_FILE)}), true);\n"
        "foreach ($snap as $p => $e) {\n"
        "  if ($e['present']) { config_set_path($p, $e['value']); } else { config_del_path($p); }\n"
        "}\n"
        "write_config('pfBlockerNG smoke: restore the config after the #3513 DNS gateway smoke');",
        "config restore",
    )


def _set_listeners(vm: SmokeVM) -> None:
    """DoH and DoQ on, on the LAN, as the pfB-DNS form's seven settings store them."""
    assignments = "".join(
        f"config_set_path({h._php_str(h.dns_config_path(k))}, {h._php_str(v)});\n" for k, v in LISTENER_SETTINGS.items()
    )
    _php_ok(
        vm,
        assignments + "write_config('pfBlockerNG smoke: pfB-DNS DoH and DoQ for the #3513 gateway smoke');",
        "DoH/DoQ settings",
    )


def _lan_addresses(vm: SmokeVM) -> set[str]:
    """The addresses of the LAN interface as ifconfig lists them, link-local ones left out: what `lan` comes to."""
    out = _php_ok(vm, "echo 'IF=' . get_real_interface('lan') . ';';", "LAN interface")
    match = re.search(r"IF=(\w+);", out)
    assert match, f"no interface name in the output: {out!r}"
    found = {
        m.group(1).split("%")[0] for m in re.finditer(r"\binet6? (\S+)", vm.ssh("ifconfig", match.group(1)).stdout)
    }
    return {address for address in found if not address.startswith("fe80:")}


def _lan_interface(client: SmokeVM) -> str:
    rows = client.ssh("ip -o -4 addr show").stdout.splitlines()
    interface = next((row.split()[1] for row in rows if f" {CLIENT_LAN_IP}/" in row), None)
    assert interface, f"no client interface carries {CLIENT_LAN_IP}: {rows}"
    return interface


@contextlib.contextmanager
def _client_v6(client: SmokeVM) -> Iterator[None]:
    """`LAN_V6_CLIENT` as an IPv6 address of the client inside the LAN's /64 (no DAD wait), taken off on the way out."""
    interface = _lan_interface(client)
    address = f"{LAN_V6_CLIENT}/{h.IPV6_LOCAL_BITS}"
    added = client.ssh(f"ip -6 addr add {address} dev {interface} nodad")
    assert added.returncode == 0, f"cannot add {address} to {interface} on the client: {added.stderr!r}"
    try:
        _say(f"client IPv6: {client.ssh(f'ip -6 addr show dev {interface}').stdout.strip()}")
        yield
    finally:
        client.ssh(f"ip -6 addr del {address} dev {interface}")


def _firewall_ask(vm: SmokeVM, name: str, *, tcp: bool) -> tuple[h.DnsAnswer, str]:
    """`name` asked by the firewall itself of its own LAN IPv6 address, so the client is that address (drill)."""
    out = vm.ssh(f"drill {'-t ' if tcp else ''}@{LAN_V6_ADDR} {name} A 2>&1").stdout
    return h._parse_drill(out, "A"), out


def _naming(rows: list[str], address: str) -> list[str]:
    """The `access-control` rows whose network holds `address`."""
    ip, found = ipaddress.ip_address(address), []
    for row in rows:
        fields = row.split()
        if len(fields) >= 2 and fields[0] == "access-control:":
            try:
                network = ipaddress.ip_network(fields[1], strict=False)
            except ValueError:
                continue
            if ip in network:
                found.append(row)
    return found


def _acl(name: str, action: str, network: str, mask: str) -> dict[str, object]:
    """One Resolver access list as config.xml stores it."""
    return {
        "aclname": name,
        "aclaction": action,
        "description": "pfBlockerNG 3513 smoke",
        "row": [{"acl_network": network, "mask": mask, "description": ""}],
    }


@contextlib.contextmanager
def _resolver_acls(vm: SmokeVM, added: list[dict[str, object]], *, auto_rows: bool = True) -> Iterator[None]:
    """`added` after the Resolver's access lists as they are; unless `auto_rows`, pfSense's own LAN rows are off too.

    Unbound rewrote access_lists.conf from them. The lists as they were and the setting of the automatic rows are put
    back (and Unbound restarted on them) on the way out.
    """
    read = _php_ok(
        vm,
        "echo '<<<ACLS>>>' . json_encode(array('acls' => config_get_path('unbound/acls', array()), "
        f"'auto' => config_get_path({h._php_str(AUTO_ROWS_OFF)}, NULL))) . '<<<END>>>';",
        "read ACLs",
    )
    match = re.search(r"<<<ACLS>>>(.*?)<<<END>>>", read, re.DOTALL)
    assert match, f"no ACL list in the output: {read!r}"
    prior = json.loads(match.group(1))
    prior_acls = prior["acls"] if isinstance(prior["acls"], list) else [prior["acls"]]

    def write(acls: list[object], auto_off: str | None) -> None:
        _php_ok(
            vm,
            f"$acls = json_decode({h._php_str(json.dumps(acls))}, true);\n"
            "if ($acls) { config_set_path('unbound/acls', $acls); } else { config_del_path('unbound/acls'); }\n"
            f"$off = json_decode({h._php_str(json.dumps(auto_off))}, true);\n"
            f"if ($off === NULL) {{ config_del_path({h._php_str(AUTO_ROWS_OFF)}); }} "
            f"else {{ config_set_path({h._php_str(AUTO_ROWS_OFF)}, $off); }}\n"
            "write_config('pfBlockerNG smoke: Resolver access lists for the #3513 gateway smoke');\n"
            "services_unbound_configure(FALSE);",
            "Resolver ACLs",
        )
        h.wait_unbound_ready(vm)

    write([*prior_acls, *added], prior["auto"] if auto_rows else "yes")
    try:
        yield
    finally:
        write(prior_acls, prior["auto"])


@contextlib.contextmanager
def _resolver_acl(vm: SmokeVM, action: str) -> Iterator[None]:
    """The Resolver's access lists name the LAN client with `action` after whatever lists were there."""
    with _resolver_acls(vm, [_acl(ACL_NAME, action, CLIENT_LAN_IP, "32")]):
        row = f"access-control: {CLIENT_LAN_IP}/32 {action}"
        written = _lines(vm.ssh("cat", ACCESS_LISTS).stdout)
        _say(f"{ACCESS_LISTS} with the {action} row: {written}")
        assert row in written, f"{ACCESS_LISTS} should have {row!r}; it has:\n{written}"
        yield


def _wait_udp(gw: Gateway, name: str, ok: Callable[[h.DnsAnswer], bool], expected: str) -> tuple[h.DnsAnswer, str]:
    """Ask over UDP until the answer is the one the gateway gives once it has re-read the ACL file (its 1 s ticker)."""
    last: list[tuple[h.DnsAnswer, str]] = []

    def seen() -> bool:
        last[:] = [_ask(gw.client, "udp", name)]
        return ok(last[0][0])

    try:
        h.wait_until(seen, timeout=60.0, interval=1.0)
    except RuntimeError as exc:
        raise RuntimeError(f"{exc}\nUDP never gave {expected}; last answer {last}\n{_proxy_log(gw.vm)}") from exc
    return last[0]


def _ask_from_alias(gw: Gateway, transport: str, name: str) -> tuple[h.DnsAnswer, str]:
    """`name` over `transport` from the second LAN address.

    The DoQ probe has no source flag: a host route to the firewall carries the second address as its preferred source
    for the one query instead, and the kernel's own route lookup is asserted to say so.
    """
    if transport != "doq":
        return _ask(gw.client, transport, name, source=BYPASSED_ALIAS_IP)
    route = f"{PFSENSE_LAN_IP}/32 dev {_lan_interface(gw.client)} src {BYPASSED_ALIAS_IP}"
    added = gw.client.ssh(f"ip route add {route}")
    assert added.returncode == 0, f"cannot add the route {route!r} on the client: {added.stderr!r}"
    try:
        chosen = gw.client.ssh(f"ip route get {PFSENSE_LAN_IP}").stdout
        assert f"src {BYPASSED_ALIAS_IP}" in chosen, (
            f"the client would not send DoQ from {BYPASSED_ALIAS_IP}: {chosen!r}"
        )
        return _ask(gw.client, "doq", name)
    finally:
        gw.client.ssh(f"ip route del {route}")


def _assert_no_rows_for(gw: Gateway, barrier: str, names: dict[str, str], alive: dict[str, str] | None = None) -> None:
    """A client no ACL row names asks for a listed name, and its dnsbl.log row drains the log: no row for `names`.

    With `alive` (a listed name per transport) it asks on every transport first: a transport whose listener is dead
    would otherwise look like one that refuses the row's client.
    """
    with _client_alias(gw.client, BYPASSED_ALIAS_IP):
        if alive:
            results = {transport: _ask_from_alias(gw, transport, alive[transport]) for transport in TRANSPORTS}
            _expect_everywhere(f"{BYPASSED_ALIAS_IP}, named by no row,", results, h.is_vip, "the VIP")
        answer, raw = _ask(gw.client, "udp", barrier, source=BYPASSED_ALIAS_IP)
    assert h.is_vip(answer), f"{BYPASSED_ALIAS_IP} is named by no ACL row and should get the VIP: {answer}\n{raw}"
    _wait_dnsbl_row(gw.vm, barrier)
    rows = {name: _dnsbl_rows(gw.vm, name) for name in names.values()}
    assert not any(rows.values()), f"dnsbl.log has rows for names the gateway answered itself: {rows}"


# --------------------------------------------------------------------------- #
# The fixtures
# --------------------------------------------------------------------------- #


def _toggle_on(gw: Gateway) -> None:
    _set_proxy_toggle(gw.vm, True)
    try:
        _apply(gw.vm)
    except RuntimeError as exc:
        raise RuntimeError(f"{exc}\n{_unbound_conf_report(gw.vm)}") from exc

    def serves() -> bool:
        return h.is_vip(_ask(gw.client, "udp", gw.names.ready)[0])

    try:
        h.wait_until(serves, timeout=240.0, interval=3.0)
    except RuntimeError as exc:
        raise RuntimeError(f"{exc}\n{_diagnostics(gw.vm)}") from exc


@pytest.fixture(scope="module")
def gw(smoke_vm: SmokeVM, client_vm: SmokeVM, stub_dns: _StubDnsServer, probe_binary: Path) -> Iterator[Gateway]:
    """Deploy the package, a feed, DoT, the gateway and the DoH/DoQ settings; apply once with the toggle off."""
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    vm = smoke_vm
    h.deploy(vm)
    h.ensure_dnsbl_vip(vm)
    h.use_system_dns_upstream(vm)  # Unbound forwards to the stub upstream; nothing needs the internet
    h.assert_link_health(client_vm, vm, control_name=h.unique_domain())
    _record_client_tools(client_vm)
    _say(f"pfSense VM: {vm.ssh('uname -mrs').stdout.strip()}")
    names = _make_names()
    # New names must not reuse another module fixture's cached feed.
    feed_header = f"{FEED_HEADER}_{secrets.token_hex(4)}"
    feed_url = h.write_local_feed(vm, f"{feed_header}.txt", "".join(f"{name}\n" for name in names.listed()))
    _snapshot(vm)
    lan_v6_prior: dict[str, str] | None = None
    try:
        lan_v6_prior = h.set_interface_ipv6(vm, h.IPV6_LOCAL_IFACE, LAN_V6_ADDR, h.IPV6_LOCAL_BITS)
        _php_ok(
            vm,
            f"config_set_path('interfaces/lan/descr', {h._php_str(LAN_CONFIG_DESCRIPTION)});"
            "write_config('pfBlockerNG smoke: event interface description');",
            "set known interface description",
        )
        _php_ok(
            vm,
            "$rules = config_get_path('filter/rule', array());"
            "foreach (array('53', '853', '443', '4443', '1053', '1853', '1953', '5443', "
            "'5543', '2853', '2953') as $port) {"
            "$rules[] = array('type' => 'pass', 'interface' => 'lan', 'ipprotocol' => 'inet6',"
            "'protocol' => 'tcp/udp', 'descr' => 'pfB leased endpoint smoke IPv6 DNS',"
            f"'source' => array('address' => {h._php_str(h.IPV6_LOCAL_SUBNET)}),"
            "'destination' => array('any' => '', 'port' => $port)); }"
            "config_set_path('filter/rule', $rules); write_config('pfBlockerNG smoke: leased LAN IPv6 DNS');",
            "allow leased IPv6 DNS traffic",
        )
        h.apply_filter_sync(vm)
        syntax = vm.ssh("pfctl -nf /tmp/rules.debug")
        assert syntax.returncode == 0, f"generated PF syntax is invalid:\n{syntax.stdout}\n{syntax.stderr}"
        installed = vm.ssh("pfctl -sr")
        assert installed.returncode == 0, f"cannot inspect installed PF rules: {installed.stderr}"
        scoped = [line for line in installed.stdout.splitlines() if "pfB leased endpoint smoke IPv6 DNS" in line]
        assert scoped, f"leased IPv6 DNS allow rule is not installed:\n{installed.stdout}"
        assert all(
            "pass in" in line and "inet6" in line and f"from {h.IPV6_LOCAL_SUBNET} " in line for line in scoped
        ), f"leased IPv6 DNS rules must remain scoped to the client subnet: {scoped}"
        refid = _create_cert(vm)
        pem = _sh(vm, f"cat {CERT_GUEST}").stdout
        trusted = subprocess.run(
            client_vm.ssh_argv("tee", CERT_CLIENT), input=pem, capture_output=True, text=True, timeout=30, check=False
        )
        assert trusted.returncode == 0, f"copying the certificate to the client failed: {trusted.stderr!r}"
        _configure_resolver(vm, refid)
        _put_reply_logging(vm, "on")
        h.inject(vm, h.DnsblCase(aliasname=feed_header, feed_url=feed_url, header=feed_header, mode=h.DnsblMode.VIP))
        # inject turns pfB-DNS on with DNSBL; this module starts from pfB-DNS off and toggles it itself
        _set_proxy_toggle(vm, False)
        _set_listeners(vm)
        _upload(client_vm, probe_binary, PROBE_BIN, "root:root")  # the gateway itself is the package's, never uploaded
        _apply(vm)  # toggle off: DNSBL is off with it (#3770), Unbound runs plain
        yield Gateway(vm, client_vm, names, _capture(vm))
    finally:
        try:
            _force_stop_proxy(vm)
            _sh(vm, f"pkill -KILL -f '{PACKAGE_DIR}/bin/freebsd-[a-z0-9]*/pfb-dn[s]'\nrm -f {READY_FILE}\n")
        finally:
            _say("gateway log:\n" + _proxy_log(vm, 80))
            try:
                _restore(vm)
                h.apply_filter_sync(vm)
                _php_ok(vm, "services_unbound_configure();", "services_unbound_configure (restore)")
                h.wait_unbound_ready(vm)
                on53 = {s.local for s in _listeners(vm) if s.command == "unbound" and s.port == 53}
                assert on53, f"Unbound is not back on port 53 after the restore: {_listeners(vm)}"
            finally:
                if lan_v6_prior is not None:
                    h.restore_interface_ipv6(vm, h.IPV6_LOCAL_IFACE, lan_v6_prior)
                _sh(vm, f"rm -f {SNAPSHOT_FILE} {CERT_GUEST}")
                client_vm.ssh(f"rm -f {CERT_CLIENT} {PROBE_BIN}")
                h.collect_host_diagnostics(vm)


@pytest.fixture
def gateway_on(gw: Gateway) -> State:
    """The box with the toggle on (applied now if an earlier test left it off), as it is when the test starts."""
    state = _capture(gw.vm)
    if not _is_on(state):
        _toggle_on(gw)
        state = _capture(gw.vm)
    return state


# --------------------------------------------------------------------------- #
# The service: what runs, what listens, what it logged
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Process:
    pid: int
    ppid: int
    user: str
    args: str


def _processes(vm: SmokeVM) -> list[Process]:
    rows = (line.split(None, 3) for line in vm.ssh("ps -axww -o pid,ppid,user,args").stdout.splitlines()[1:])
    return [Process(int(r[0]), int(r[1]), r[2], r[3] if len(r) > 3 else "") for r in rows if len(r) >= 3]


def test_the_installed_package_ships_both_pfb_dns_binaries_and_the_dispatcher(gw: Gateway) -> None:
    """The payload is the package's own: both raw binaries 0555, the wrapper 0644, a wildcard ABI, the .pkg's bytes.

    Then `pfb_dns.sh` is 0644 (it is run as `/bin/sh`, never executed); `bin/freebsd-amd64/pfb-dns` and
      `bin/freebsd-arm64/pfb-dns` are 0555 and sha256-equal to the same members of the .pkg this run built; and the
      installed package's ABI is `FreeBSD:<major>:*` (NO_ARCH), so one package serves both architectures.
    """
    vm, pkg = gw.vm, os.environ["SMOKE_PKG"]
    assert _guest_mode(vm, WRAPPER) == "644", f"{WRAPPER}: mode {_guest_mode(vm, WRAPPER)!r}"
    for target in PAYLOAD_TARGETS:
        path = f"{PACKAGE_DIR}/bin/{target}/pfb-dns"
        assert _guest_mode(vm, path) == "555", f"{path}: mode {_guest_mode(vm, path)!r}"
        on_guest = vm.ssh(f"sha256 -q {path}").stdout.strip()
        built = _package_member_sha256(pkg, f"dns_proxy/bin/{target}/pfb-dns")
        _say(f"{target}/pfb-dns: sha256 {on_guest} (the .pkg's {built})")
        assert on_guest == built, f"{path} on the guest is not the .pkg's member: {on_guest} vs {built}"
    name = branch_pkg_name(pkg)
    abi = vm.ssh(f"pkg query '%q' {name}").stdout.strip()
    assert re.fullmatch(r"FreeBSD:\d+:\*", abi), f"the installed {name} has ABI {abi!r}, not a NO_ARCH wildcard"


def test_the_daemon_supervises_the_gateway_and_the_gateway_is_the_one_process_that_decides(
    gw: Gateway, gateway_on: State
) -> None:
    """The service is the one Go gateway: a supervisor and a gateway with no child, and no Python decider anywhere.

    Then Status > Services says `pfb_dns_proxy` runs; the supervisor's ps title is `daemon: pfb_dns_proxy[<child pid>]`;
      the child (the pidfile's pid) is the pfb-dns `pfb_dns.sh` chose for this machine, as `unbound`, started with
      `--module-dir /var/unbound` and no ` -- ` decider command; it has no child process; no process runs
      `pfb_dns_proxy.py`; dns_proxy.log has a `listening` line per transport and
      `ready upstream 127.0.0.1:5353 pid <gateway>` after them.
    """
    state = gateway_on
    assert state.service == "running", f"service pfb_dns_proxy: {state.service}"
    assert state.proxy_pid and state.daemon_pid, f"pidfiles: gateway={state.proxy_pid} daemon={state.daemon_pid}"
    procs = _processes(gw.vm)
    by_pid = {p.pid: p for p in procs}
    supervisor, gateway = by_pid.get(state.daemon_pid), by_pid.get(state.proxy_pid)
    assert supervisor and re.search(rf"\bdaemon: pfb_dns_proxy\[{state.proxy_pid}\]", supervisor.args), (
        f"supervisor {supervisor}; ps: {procs}"
    )
    assert gateway and gateway.args.split()[0] == _selected_binary(gw.vm), (
        f"the pidfile's process is not this machine's pfb-dns ({_selected_binary(gw.vm)}): {gateway}"
    )
    assert gateway.user == "unbound", f"the gateway should have dropped root to unbound: {gateway}"
    assert "--module-dir /var/unbound" in gateway.args and " -- " not in gateway.args, (
        f"the gateway's command line names no module dir, or still carries a decider command: {gateway.args}"
    )
    children = [p for p in procs if p.ppid == state.proxy_pid]
    assert not children, f"the gateway has children: {children}"
    # The cutover's live proof: no Python decider (or listener) runs, whoever started it
    deciders = [p for p in procs if "pfb_dns_proxy.py" in p.args]
    assert not deciders, f"a Python decider runs next to the gateway: {deciders}"

    log = _proxy_log(gw.vm, 400).splitlines()
    ready_line = f"ready upstream 127.0.0.1:{UPSTREAM_PORT} pid {state.proxy_pid}"
    readies = [i for i, line in enumerate(log) if line.endswith(ready_line)]
    assert readies, f"no `{ready_line}` line in dns_proxy.log:\n" + "\n".join(log)
    ready = readies[-1]
    start = max((i for i, line in enumerate(log[:ready]) if "ready upstream" in line), default=-1) + 1
    found = (re.search(r"listening (udp\+tcp|dot|doh|doq) (\S+)$", line) for line in log[start:ready])
    heard = {m.group(1, 2) for m in found if m}
    _say(f"readiness lines: {sorted(heard)}")
    wanted = {
        ("udp+tcp", f"{PFSENSE_LAN_IP}:53"),
        ("udp+tcp", "127.0.0.1:53"),
        ("dot", f"{PFSENSE_LAN_IP}:{DOT_PORT}"),
        ("doh", f"{PFSENSE_LAN_IP}:{DOH_PORT}"),
        ("doh", f"127.0.0.1:{DOH_PORT}"),
        ("doq", f"{PFSENSE_LAN_IP}:{DOQ_PORT}"),
        ("doq", f"127.0.0.1:{DOQ_PORT}"),
    }
    assert wanted <= heard, f"missing readiness lines: {sorted(wanted - heard)}; the start's lines:\n" + "\n".join(
        log[start : ready + 1]
    )


def test_the_dispatcher_ran_this_machines_binary_and_the_gateway_published_its_pid(
    gw: Gateway, gateway_on: State
) -> None:
    """`pfb_dns.sh` exec'd the package's binary for `uname -p`, and that process is the one the ready file names.

    Then the executable of the pidfile's process (`procstat -b`, not its argv) is the package's
      `bin/<target for uname -p>/pfb-dns`; `/var/unbound/pfb_dns_ready` holds exactly that pid, mode 0600, owned by
      `unbound` (the gateway wrote it after dropping root), so the marker names the daemon(8) child itself.
    """
    vm, state = gw.vm, gateway_on
    assert state.proxy_pid, f"no proxy pidfile: {state}"
    expected = _selected_binary(vm)
    executable = vm.ssh(f"procstat -b {state.proxy_pid}").stdout
    _say(f"procstat -b {state.proxy_pid}: {executable.strip()}")
    assert expected in executable.split(), f"pid {state.proxy_pid} does not run {expected}:\n{executable}"
    marker = vm.ssh(f"cat {READY_FILE}").stdout.strip()
    assert marker == str(state.proxy_pid), f"{READY_FILE} holds {marker!r}, the gateway is {state.proxy_pid}"
    facts = vm.ssh(f"stat -f '%Lp %Su' {READY_FILE}").stdout.strip()
    assert facts == "600 unbound", f"{READY_FILE}: mode and owner {facts!r}"


def test_the_gateway_owns_the_client_facing_sockets_and_unbound_only_loopback(gw: Gateway, gateway_on: State) -> None:
    """The gateway holds every client-facing port; Unbound hides on loopback 5353 (PROXYv2) and 5354.

    Then the gateway holds UDP and TCP 53 on the LAN address and on loopback and TCP 853 (DoT) on the LAN address, and
      nothing else holds port 53; DoH (TCP 4443) and DoQ (UDP 853) are on exactly the LAN interface's addresses and on
      loopback (127.0.0.1 and ::1, a stable backend for a local HAProxy); Unbound's DNS sockets are loopback 5353 and
      5354 only.
    """
    state = gateway_on
    sockets = state.proxy_sockets()
    _say(f"gateway sockets: {sorted(sockets)}")
    _say(f"access_lists.conf with the gateway serving: {_lines(state.access_lists)}")
    wanted = {(proto, f"{PFSENSE_LAN_IP}:53") for proto in ("udp4", "tcp4")}
    wanted |= {(proto, "127.0.0.1:53") for proto in ("udp4", "tcp4")} | {
        (proto, "::1:53") for proto in ("udp6", "tcp6")
    }
    wanted.add(("tcp4", f"{PFSENSE_LAN_IP}:{DOT_PORT}"))
    assert wanted <= sockets, f"missing gateway sockets: {sorted(wanted - sockets)}; has {sorted(sockets)}"
    on53 = {s.pid for s in state.listeners if s.local.endswith(":53")}
    assert on53 == {state.proxy_pid}, f"port 53 is held by pids {on53}, the gateway is {state.proxy_pid}"
    lan = _lan_addresses(gw.vm) | LOOPBACK
    doh = {a.rsplit(":", 1)[0] for p, a in sockets if p.startswith("tcp") and a.endswith(f":{DOH_PORT}")}
    doq = {a.rsplit(":", 1)[0] for p, a in sockets if p.startswith("udp") and a.endswith(f":{DOQ_PORT}")}
    _say(f"LAN interface addresses and loopback {sorted(lan)}; DoH on {sorted(doh)}; DoQ on {sorted(doq)}")
    assert doh == lan and doq == lan, (
        f"DoH on {sorted(doh)}, DoQ on {sorted(doq)}; the LAN interface and loopback have {sorted(lan)}"
    )
    unbound = state.unbound_dns()
    _say(f"Unbound DNS sockets: {sorted(unbound)}")
    assert any(local == f"127.0.0.1:{UPSTREAM_PORT}" for _, local in unbound), f"Unbound sockets: {sorted(unbound)}"
    stray = {(p, a) for p, a in unbound if not re.fullmatch(r"(127\.0\.0\.1|::1):(5353|5354)", a)}
    assert not stray, f"Unbound listens beyond loopback 5353 and 5354: {sorted(stray)}"


STATUS_PAGE = "/pfblockerng/pfblockerng_dns_general.php"  # the pfB-DNS settings and status page since issue #3771


@pytest.fixture
def gui(gw: Gateway) -> WebUI:
    """A logged-in webConfigurator session against the gateway's box (the credentials the UI tier uses)."""
    action, password = admin_password_decision(os.environ)
    if action == "fail":
        pytest.fail(password)
    https = (h.config_get(gw.vm, "system/webgui/protocol").strip().lower() or "http") == "https"
    client = WebUI(
        host=gw.vm.host,
        port=gw.vm.web_port,
        username=os.environ.get("SMOKE_ADMIN_USER") or "admin",
        password=password,
        scheme="https" if https else "http",
        verify=not https,
    )
    client.login()
    return client


def _status_rows(page: str, transport: str) -> list[tuple[str, list[str], str]]:
    """The rows of one transport's table in DNS General's status panel, as (interface, one address per line, what a
    screen reader says for the state)."""
    # the table inside this section, never one of the next section (a transport on with no listener has none)
    table = re.search(rf'id="pfb-dns-status-{transport}">(?:(?!class="panel ).)*?(<table .*?</table>)', page, re.DOTALL)
    assert table, f"the pfB-DNS status panel has no {transport} table"
    rows = []
    for tr in ET.fromstring(table.group(1)).findall("./tbody/tr"):
        interface, address, state = tr.findall("td")
        lines = [address.text or "", *(br.tail or "" for br in address.findall("br"))]
        said = state.find("span[@class='sr-only']")
        rows.append((interface.text or "", lines, (said.text if said is not None else "") or ""))
    return rows


def test_the_status_panel_lists_each_transport_the_gateway_serves_with_a_localhost_row_and_a_lan_row(
    gateway_on: State, gui: WebUI
) -> None:
    """issue #3555: the status panel is one table per transport, a row per interface.

    Given the gateway serves plain DNS and DoT, DoH and DoQ (the toggles this module turns on, none off),
    Then each table has a Localhost row with exactly its served lo0 VIP and loopbacks at the transport's port and a LAN
      row that holds the LAN address at it, both reading `Listening` for a screen reader.
    """
    ports = {"plain": 53, "dot": DOT_PORT, "doh": DOH_PORT, "doq": DOQ_PORT}
    page = ""

    def listed() -> bool:
        nonlocal page
        page = gui.get(STATUS_PAGE).text
        return any(state == "Listening" for _, _, state in _status_rows(page, "plain"))

    h.wait_until(listed, timeout=60.0, interval=2.0)
    for transport, port in ports.items():
        rows = _status_rows(page, transport)
        _say(f"status panel, {transport}: {rows}")
        loopback = [row for row in rows if row[0] == "Localhost"]
        localhost_addresses = [f"127.0.0.1:{port}", f"[::1]:{port}"]
        # Plain DNS and DoT select all addresses; the LAN-only DoH/DoQ lists exclude the lo0 VIP.
        if transport in ("plain", "dot"):
            localhost_addresses.insert(0, f"{h.DEFAULT_DNSBL_VIP4}:{port}")
        assert loopback == [("Localhost", localhost_addresses, "Listening")], (
            f"{transport}: the Localhost row is {loopback}; all rows: {rows}"
        )
        lan = [row for row in rows if row[0] == LAN_DESCRIPTION and f"{PFSENSE_LAN_IP}:{port}" in row[1]]
        assert lan and all(state == "Listening" for _, _, state in lan), (
            f"{transport}: no LAN row listening on {PFSENSE_LAN_IP}:{port}; all rows: {rows}"
        )


@pytest.mark.timeout(900)
def test_the_status_panel_keeps_live_gateway_bindings_when_the_upstream_stops(
    gw: Gateway, gateway_on: State, gui: WebUI
) -> None:
    """issues #3560, #3848: Unbound stopping under a live gateway names the lost backend; the rows stay Listening.

    Given the gateway serves every transport: its pid is the ready file's, it owns the LAN front sockets, the proxy is
      ready, and the status panel reads Running with all four tables Listening,
    When `unbound-control stop` ends the Unbound behind it while the gateway keeps its pid, ready file and sockets,
    Then the panel reads `Resolver backend not answering: Unbound does not answer on ...`, and each table keeps the
      same rows as before, each reading `Listening`.
    Finally Unbound is running again and allowed names resolve over UDP and TCP.
    """
    vm, client = gw.vm, gw.client
    assert vm.ssh("test", "-f", h.PFB_CRON_DISABLE_PATH).returncode == 0, f"{h.PFB_CRON_DISABLE_PATH} is missing"
    tables = ("plain", "dot", "doh", "doq")
    proxy, unbound = gateway_on.proxy_pid, gateway_on.unbound_pid
    assert proxy, f"no gateway pidfile: {gateway_on}"
    front = {
        ("udp4", f"{PFSENSE_LAN_IP}:53"),
        ("tcp4", f"{PFSENSE_LAN_IP}:53"),
        ("tcp4", f"{PFSENSE_LAN_IP}:{DOT_PORT}"),
        ("tcp4", f"{PFSENSE_LAN_IP}:{DOH_PORT}"),
        ("udp4", f"{PFSENSE_LAN_IP}:{DOQ_PORT}"),
    }
    assert front <= gateway_on.proxy_sockets(), (
        f"the gateway {proxy} does not own the LAN front sockets; it owns {sorted(gateway_on.proxy_sockets())}"
    )

    def proxy_serving() -> bool:
        pre = "require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');"
        return h._php_read_scalar(vm, pre, "pfb_dns_proxy_serving_ready() ? '1' : '0'") == "1"

    def service_of(page: str) -> str | None:
        found = re.search(r'<tr id="pfb-dns-status-service"><th>Service</th><td>([^<]*)</td>', page)
        return found.group(1) if found else None

    assert vm.ssh("cat", READY_FILE).stdout.strip() == str(proxy), (
        f"{READY_FILE} does not hold the gateway's pid {proxy}"
    )
    assert proxy_serving(), "pfb_dns_proxy_serving_ready() is false while the gateway and Unbound both run"
    healthy: dict[str, list[tuple[str, list[str], str]]] = {}

    def panel_ready() -> bool:
        page = gui.get(STATUS_PAGE).text
        if service_of(page) != "Running":
            return False
        healthy.update({t: _status_rows(page, t) for t in tables})
        return all(rows and {said for _, _, said in rows} == {"Listening"} for rows in healthy.values())

    h.wait_until(panel_ready, timeout=60.0, interval=2.0)
    _say(f"status panel with the gateway serving: {healthy}")

    try:
        stop = vm.ssh("/usr/local/sbin/unbound-control", "-c", h.UNBOUND_CONF, "stop", timeout=30)
        assert stop.returncode == 0, f"unbound-control stop: rc={stop.returncode} {stop.stdout!r} {stop.stderr!r}"

        def backend_down() -> bool:
            listeners = _listeners(vm)
            live = {p.pid for p in _processes(vm)}
            return (
                unbound not in live
                and not any(s.command == "unbound" for s in listeners)
                and proxy in live
                and _pid_file(vm, PROXY_PID_FILE) == proxy
                and vm.ssh("cat", READY_FILE).stdout.strip() == str(proxy)
                and {(s.proto, s.local) for s in listeners if s.pid == proxy} == gateway_on.proxy_sockets()
                and not proxy_serving()
            )

        h.wait_until(backend_down, timeout=60.0, interval=2.0)
        down_page = gui.get(STATUS_PAGE).text
        said = service_of(down_page) or ""
        assert said.startswith("Resolver backend not answering: Unbound does not answer on "), (
            f"backend down: the service reads {said!r}"
        )
        down = {t: _status_rows(down_page, t) for t in tables}
        _say(f"status panel with Unbound stopped: {down}")
        assert down == healthy, (
            "the gateway's front sockets remain bound with Unbound stopped, and the rows differ\n"
            f"healthy: {healthy}\ndown: {down}"
        )
    finally:
        _php_ok(vm, "services_unbound_configure();", "services_unbound_configure (restore)")
        h.wait_unbound_ready(vm)
        allowed = {t: h.unique_domain(f"restored-{t}") for t in ("udp", "tcp")}
        last: dict[str, tuple[h.DnsAnswer, str]] = {}

        def upstream_answers() -> bool:
            last.update({t: _ask(client, t, name) for t, name in allowed.items()})
            _say(f"allowed names after the restore: {[(t, a.rcode, a.records) for t, (a, _) in last.items()]}")
            return all(h.resolves_to(answer, STUB_DNS_A) for answer, _ in last.values())

        h.wait_until(upstream_answers, timeout=120.0, interval=3.0)


# --------------------------------------------------------------------------- #
# Unbound as the gateway's upstream: the observer, upstream EDE blocks, the firewall itself
# --------------------------------------------------------------------------- #


def test_unbound_runs_the_upstream_observer_never_the_module_in_gateway_mode(gw: Gateway, gateway_on: State) -> None:
    """The gateway does not change what Unbound loads: the observer while forwarding, never the retired pfb_unbound.py.

    Given the Resolver forwards to the System DNS server and the gateway serves,
    Then unbound.conf's only `python-script` is `pfb_upstream_observer.py` (the module is in the chain) and
      `pfb_unbound.py` is not named and is not staged (#3791); the observer is staged in the chroot.
    """
    scripts = re.findall(r"^\s*python-script\s*:\s*(\S+)", gateway_on.conf, re.MULTILINE)
    assert scripts == [OBSERVER_SCRIPT], f"python-script lines: {scripts}\n{gateway_on.conf}"
    assert MODULE_LINE.search(gateway_on.conf), f"the python module is not in the module chain:\n{gateway_on.conf}"
    assert "pfb_unbound.py" not in gateway_on.conf, gateway_on.conf
    staged = gw.vm.ssh(f"ls -l /var/unbound/{OBSERVER_SCRIPT} 2>&1").stdout
    assert OBSERVER_SCRIPT in staged and "No such file" not in staged, f"staged files: {staged}"
    retired = gw.vm.ssh("ls /var/unbound/pfb_unbound.py 2>&1").stdout
    assert "No such file" in retired, f"the retired module is still staged: {retired}"


def test_an_upstream_ede_block_is_logged_with_the_real_client_in_gateway_mode(
    gw: Gateway, gateway_on: State, stub_dns: _StubDnsServer
) -> None:
    """A block the upstream signals with EDE 15 reaches dnsbl.log with the LAN client's address.

    Given the stub upstream answers a unique name with NXDOMAIN and an EDE option (info-code 15, text `Quad9`),
    When the LAN client asks the gateway,
    Then it gets NXDOMAIN and dnsbl.log gains the observer's upstream-block row for the client.
    """
    name = h.unique_domain("pfbsmoke-3513-ede")
    stub_dns.register_nxdomain(name, ede_info_code=15, ede_text="Quad9")
    answer, raw = _ask(gw.client, "udp", name)
    assert answer.rcode == "NXDOMAIN", f"{name}: expected NXDOMAIN from the upstream, got {answer}\n{raw}"

    def upstream_rows() -> list[list[str]]:
        return [row for row in _dnsbl_rows(gw.vm, name) if row[5:6] == ["Upstream_Block"]]

    try:
        h.wait_until(lambda: bool(upstream_rows()), timeout=30.0)
    except RuntimeError as exc:
        raise RuntimeError(f"{exc}\ndnsbl.log gained no Upstream_Block row for {name}:\n{_proxy_log(gw.vm)}") from exc
    [row] = upstream_rows()
    assert row[0] == "DNSBL-python" and row[6] == "Upstream", row
    assert row[7] == "EDE15 (Blocked)" and row[8] == "Quad9", f"evaluation / extra text: {row}"
    assert row[3] == CLIENT_LAN_IP, f"the row names {row[3]!r}, not the real client {CLIENT_LAN_IP}: {row}"


def test_the_firewalls_own_lookup_of_a_listed_name_gets_the_vip_from_the_gateway_on_loopback(
    gw: Gateway, gateway_on: State
) -> None:
    """The gateway serves loopback at the Listen Port, so the firewall's own lookups are DNSBL-filtered.

    When pfSense regenerates /etc/resolv.conf (a reboot, a WAN event, a settings save do the same) and the box asks
      `drill @127.0.0.1` (and gethostbyname through /etc/resolv.conf) for a listed name,
    Then resolv.conf still names 127.0.0.1 (pfSense lists it while the Resolver's port is 53 and lo0 is bound: both
      stay), the answer is the DNSBL VIP and dnsbl.log names 127.0.0.1 as the client.
    """
    _php_ok(gw.vm, "require_once('system.inc');\nsystem_resolvconf_generate();", "system_resolvconf_generate")
    resolv = gw.vm.ssh("cat /etc/resolv.conf").stdout
    assert re.search(r"^nameserver\s+127\.0\.0\.1\s*$", resolv, re.MULTILINE), f"/etc/resolv.conf:\n{resolv}"
    name = gw.names.firewall
    drilled = gw.vm.ssh(f"drill @127.0.0.1 {name} A 2>&1").stdout
    assert h.DEFAULT_DNSBL_VIP4 in drilled, f"drill @127.0.0.1 {name}:\n{drilled}"
    looked_up = _firewall_lookup(gw.vm, name)
    assert looked_up == h.DEFAULT_DNSBL_VIP4, f"the firewall's own lookup of the listed {name}: {looked_up!r}"
    _wait_dnsbl_row(gw.vm, name)
    clients = {row[3] for row in _dnsbl_rows(gw.vm, name)}
    assert clients == {"127.0.0.1"}, f"dnsbl.log rows for {name} name {sorted(clients)}, not the firewall's 127.0.0.1"
    assert all(row[12:14] == ["127.0.0.1", "Localhost"] for row in _dnsbl_rows(gw.vm, name))


# --------------------------------------------------------------------------- #
# From the LAN client, over every transport
# --------------------------------------------------------------------------- #


def _publish_listener_owner_table(vm: SmokeVM, overrides: dict[str, str] | None) -> None:
    """Publish the full trusted table, or restore canonical owners when overrides is None."""
    override = "".join(
        f"if (!array_key_exists({h._php_str(address)}, $owners)) {{"
        "throw new RuntimeException('override owner address is absent'); }"
        f"$owners[{h._php_str(address)}] = {h._php_str(description)};"
        for address, description in (overrides or {}).items()
    )
    _php_ok(
        vm,
        "require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');"
        "pfb_global();"
        "$table = pfb_dns_proxy_command_name_answers() ?? [];"
        "$owners = pfb_dns_proxy_address_interfaces();" + override + "foreach ($owners as $ip => $descr) {"
        "if (pfb_dns_listener_label_valid($descr)) {"
        "$table[] = 'listener-interface ' . $ip . '=' . base64_encode($descr); }}"
        "$error = pfb_dns_proxy_address_table($table);"
        "if ($error !== NULL) { throw new RuntimeException($error); }",
        "replace trusted listener owner table",
    )


def test_receiving_endpoint_survives_dedicated_syslog_export(gw: Gateway, gateway_on: State, gui: WebUI) -> None:
    """Trusted admin owner metadata tests control/log encoding, not physical interface API admission."""
    vm = gw.vm
    path = CFG_GENERAL + "/log_syslog"
    prior = h.config_get_state(vm, path)
    names = gw.names.syslog
    tokens = {transport: f"qname={name} ".encode("ascii") for transport, name in names.items()}

    def exported() -> bool:
        # Observe bytes first: unrelated malformed records must not mask our event.
        script = (
            "set -e\n"
            f"for file in {PFB_SYSLOG_LOG} {PFB_SYSLOG_LOG}.[0-9]*; do\n"
            '  [ -f "$file" ] || continue\n'
            '  /usr/bin/bsdcat "$file"\n'
            "done\n"
        )
        result = subprocess.run(vm.ssh_argv("/bin/sh", "-c", script), capture_output=True, timeout=30, check=False)
        assert result.returncode == 0, (result.returncode, result.stdout, result.stderr)
        lines = result.stdout.splitlines()
        return all(any(b"act=dnsbl " in line and token in line for line in lines) for token in tokens.values())

    try:
        _set_syslog_enabled(vm, on=True)
        _publish_listener_owner_table(vm, {PFSENSE_LAN_IP: SYSLOG_OWNER_DESCRIPTION})
        for transport, name in names.items():
            answer, raw = _ask(gw.client, transport, name)
            assert h.is_vip(answer), f"{transport} {name}: expected DNSBL VIP, got {answer}\n{raw}"
        _drain_logs(gw)
        try:
            h.wait_until(exported, timeout=30.0)
        finally:
            history = _capture_raw_syslog_history(vm, "gateway-owned-endpoint")
        for transport, name in names.items():
            token = tokens[transport]
            own = [line for line in history["dedicated"].splitlines() if b"act=dnsbl " in line and token in line]
            assert len(own) == 1, f"{transport} {name}: expected exactly one dedicated event: {own!r}"
            [interface_token] = re.findall(rb'(?:^| )listener_interface=("(?:\\.|[^"\\])*")(?= |$)', own[0])
            serialized_interface = interface_token.decode("ascii")
            assert json.loads(serialized_interface) == SYSLOG_OWNER_DESCRIPTION, interface_token
            line = own[0].decode("utf-8")
            body = line[line.index("act=dnsbl ") :]
            fields = [part.split("=", 1) for part in shlex.split(body)]
            for key, value in (
                ("qname", name),
                ("qip", CLIENT_LAN_IP),
                ("listener_ip", PFSENSE_LAN_IP),
                # JSON string decoding above, not shell unquoting, owns listener_interface.
                ("transport", LOG_TRANSPORT[transport]),
            ):
                assert [pair[1] for pair in fields if pair[0] == key] == [value], line
            assert "listener_interface=" + serialized_interface in body, line
            leaks = [record for record in history["system"].splitlines() if b"act=dnsbl " in record and token in record]
            assert not leaks, f"owned security event leaked to system destination: {leaks!r}"
            [row] = _dnsbl_rows(vm, name)
            assert len(row) == 14 and row[3] == CLIENT_LAN_IP, row
            assert row[11:14] == [LOG_TRANSPORT[transport], PFSENSE_LAN_IP, SYSLOG_OWNER_DESCRIPTION], row
            _assert_unified_row(vm, row, name, 2)
            _assert_report_row(
                gui, name, CLIENT_LAN_IP, LOG_TRANSPORT[transport], PFSENSE_LAN_IP, SYSLOG_OWNER_DESCRIPTION
            )
    finally:
        try:
            _publish_listener_owner_table(vm, None)
        finally:
            h.config_restore_state(vm, path, prior)


@pytest.mark.parametrize("transport", TRANSPORTS)
def test_receiving_ipv6_endpoint_survives_logs_unified_and_reports(
    gw: Gateway, gateway_on: State, transport: str, gui: WebUI
) -> None:
    """The leased LAN's IPv6 traffic is mandatory, not a reachability-dependent skip."""
    with _client_v6(gw.client):
        name = h.unique_domain("endpoint-v6")
        answer, raw = _ask(gw.client, transport, name, server=LAN_V6_ADDR)
        assert h.resolves_to(answer, STUB_DNS_A), raw
        _drain_logs(gw)
        [row] = _reply_rows(gw.vm, name)
        assert len(row) == 13 and row[7] == LAN_V6_CLIENT and row[8] == STUB_DNS_A, row
        assert row[10:13] == [LOG_TRANSPORT[transport], LAN_V6_ADDR, LAN_DESCRIPTION], row
        _assert_unified_row(gw.vm, row, name, 6)
        _assert_report_row(gui, name, LAN_V6_CLIENT, LOG_TRANSPORT[transport], LAN_V6_ADDR, LAN_DESCRIPTION)
        blocked = gw.names.logged_v6[transport]
        answer, raw = _ask(gw.client, transport, blocked, server=LAN_V6_ADDR)
        assert h.is_vip(answer), raw
        _drain_logs(gw)
        [row] = _dnsbl_rows(gw.vm, blocked)
        assert len(row) == 14 and row[3] == LAN_V6_CLIENT, row
        assert row[11:14] == [LOG_TRANSPORT[transport], LAN_V6_ADDR, LAN_DESCRIPTION], row
        _assert_unified_row(gw.vm, row, blocked, 2)
        _assert_report_row(gui, blocked, LAN_V6_CLIENT, LOG_TRANSPORT[transport], LAN_V6_ADDR, LAN_DESCRIPTION)


def test_receiving_interface_is_the_event_snapshot_after_interface_rename(
    gw: Gateway, gateway_on: State, gui: WebUI
) -> None:
    old_name = h.unique_domain("before-interface-rename")
    answer, raw = _ask(gw.client, "udp", old_name)
    assert h.resolves_to(answer, STUB_DNS_A), raw
    _drain_logs(gw)
    [old_row] = _reply_rows(gw.vm, old_name)
    assert old_row[11:13] == [PFSENSE_LAN_IP, LAN_DESCRIPTION], old_row
    renamed = "PFB3757RENAMED"
    renamed_api = "PFB3757RENAMED"
    try:
        _php_ok(
            gw.vm,
            f"config_set_path('interfaces/lan/descr', {h._php_str(renamed)});"
            "write_config('pfBlockerNG smoke: rename endpoint owner');",
            "rename interface",
        )
        _apply(gw.vm)
        new_name = h.unique_domain("after-interface-rename")
        answer, raw = _ask(gw.client, "udp", new_name)
        assert h.resolves_to(answer, STUB_DNS_A), raw
        _drain_logs(gw)
        [new_row] = _reply_rows(gw.vm, new_name)
        assert new_row[11:13] == [PFSENSE_LAN_IP, renamed_api], new_row
        assert _reply_rows(gw.vm, old_name) == [old_row], "interface rename rewrote historical metadata"
        _assert_report_row(gui, old_name, CLIENT_LAN_IP, "UDP", PFSENSE_LAN_IP, LAN_DESCRIPTION)
        _assert_report_row(gui, new_name, CLIENT_LAN_IP, "UDP", PFSENSE_LAN_IP, renamed_api)
    finally:
        _php_ok(
            gw.vm,
            f"config_set_path('interfaces/lan/descr', {h._php_str(LAN_CONFIG_DESCRIPTION)});"
            "write_config('pfBlockerNG smoke: restore endpoint owner');",
            "restore interface description",
        )
        _apply(gw.vm)


@pytest.mark.parametrize("transport", TRANSPORTS)
def test_a_listed_name_gets_the_vip_and_a_log_row_naming_the_client(
    gw: Gateway, gateway_on: State, transport: str, gui: WebUI
) -> None:
    """A listed name is answered by the gateway itself: the VIP and a dnsbl.log row for the LAN client.

    When the LAN client asks over UDP, TCP, DoT, DoH (POST and GET) or DoQ,
    Then it gets the DNSBL VIP and dnsbl.log has a row for the name that names 192.168.1.10.
    """
    name = gw.names.logged[transport]
    answer, raw = _ask(gw.client, transport, name)
    _say(f"listed name, {transport}: {answer.rcode} {answer.records}")
    assert h.is_vip(answer), f"{transport} {name}: expected VIP {h.DEFAULT_DNSBL_VIP4}, got {answer}\n{raw}"
    _drain_logs(gw)
    [row] = _dnsbl_rows(gw.vm, name)
    assert len(row) == 14 and row[3] == CLIENT_LAN_IP and row[11] == LOG_TRANSPORT[transport], row
    assert row[12:14] == [PFSENSE_LAN_IP, LAN_DESCRIPTION], row
    _assert_unified_row(gw.vm, row, name, 2)
    _assert_report_row(gui, name, CLIENT_LAN_IP, LOG_TRANSPORT[transport])


@pytest.mark.parametrize("transport", TRANSPORTS)
def test_an_allowed_name_is_answered_by_the_upstream_and_unbound_logs_the_client(
    gw: Gateway, gateway_on: State, transport: str, gui: WebUI, stub_dns: _StubDnsServer
) -> None:
    """An allowed name goes to Unbound behind a PROXYv2 header naming the LAN client, whatever the transport.

    When the LAN client asks for a name no feed lists over UDP, TCP, DoT, DoH (POST and GET) or DoQ,
    Then the reply is the upstream stub's answer, and `resolver.log` names 192.168.1.10, never 127.0.0.1.
    """
    name = h.unique_domain(f"allowed-{transport}")
    answer, raw = _ask(gw.client, transport, name)
    _say(f"allowed name, {transport}: {answer.rcode} {answer.records}")
    _assert_answered_by_upstream(gw, name, answer, raw, transport)
    h.wait_until(lambda: len(_reply_rows(gw.vm, name)) == 1, timeout=30.0)
    [forwarded] = _reply_rows(gw.vm, name)
    upstream_queries = stub_dns.received(name, "A")
    assert upstream_queries, f"fresh {name} never reached the upstream"
    answer, raw = _ask(gw.client, transport, name)
    assert h.resolves_to(answer, STUB_DNS_A), f"cached {transport} {name}: {answer}\n{raw}"
    _drain_logs(gw)
    assert stub_dns.received(name, "A") == upstream_queries, f"repeated {name} was not cached by Unbound"
    rows = _reply_rows(gw.vm, name)
    assert len(rows) == 2, f"one row per forwarded/cached query: {rows}"
    assert rows[0] == forwarded, f"first forwarded row changed: {forwarded} -> {rows}"
    # The gateway sees a forwarded reply for both; Unbound alone knows which it cached.
    assert [row[2] for row in rows] == ["reply", "reply"], rows
    for row in rows:
        assert len(row) == 13 and row[3:5] == ["A", "A"] and row[5].isdigit(), row
        assert row[6:9] == [name, CLIENT_LAN_IP, STUB_DNS_A], row
        assert row[9] == forwarded[9] and row[9] in ("unk", "prv"), row
        assert row[10] == LOG_TRANSPORT[transport], row
        assert row[11:13] == [PFSENSE_LAN_IP, LAN_DESCRIPTION], row
        _assert_unified_row(gw.vm, row, name, 6)
    _assert_report_row(gui, name, CLIENT_LAN_IP, LOG_TRANSPORT[transport])


# --------------------------------------------------------------------------- #
# Hostile clients
# --------------------------------------------------------------------------- #


def test_doh_forwarded_client_is_believed_only_from_a_trusted_front_end(
    gw: Gateway, gateway_on: State, gui: WebUI
) -> None:
    """XFF changes attribution only for a trusted peer; it never changes DoH to TCP."""
    path = h.dns_config_path("pfb_dns_doh_trusted")
    present, prior = h.config_get_state(gw.vm, path)
    try:
        for trusted, forwarded, denied in (
            (False, "2001:db8::3757", False),
            (True, LAN_V6_CLIENT, False),
            (True, "2001:db8::3757", True),
        ):
            _php_ok(
                gw.vm,
                f"config_set_path({h._php_str(path)}, {h._php_str(CLIENT_LAN_IP if trusted else '')});\n"
                "write_config('pfBlockerNG smoke: trusted DoH front end');",
                "DoH trusted front end",
            )
            _apply(gw.vm)
            name = h.unique_domain("doh-denied" if denied else "doh-trusted" if trusted else "doh-untrusted")
            wire = bytes.fromhex("375101000001000000000000")
            wire += b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\0\0\1\0\1"
            args = [
                "curl",
                "--silent",
                "--show-error",
                "--fail",
                "--max-time",
                "10",
                "--noproxy",
                "*",
                "--cacert",
                CERT_CLIENT,
                "--resolve",
                f"{CERT_NAME}:{DOH_PORT}:{PFSENSE_LAN_IP}",
                "-H",
                "Content-Type: application/dns-message",
                "-H",
                f"X-Forwarded-For: {forwarded}",
                "--data-binary",
                "@-",
                f"https://{CERT_NAME}:{DOH_PORT}/dns-query",
            ]
            result = subprocess.run(
                gw.client.ssh_argv(shlex.join(args)), input=wire, capture_output=True, timeout=40, check=False
            )
            assert result.returncode == 0, f"DoH trusted={trusted}: {result.stderr!r}"
            assert len(result.stdout) >= 12 and result.stdout[3] & 15 == (5 if denied else 0), result.stdout.hex()
            if denied:
                assert result.stdout[6:8] == b"\0\0", result.stdout.hex()
                _drain_logs(gw)
                assert not _reply_rows(gw.vm, name), name
                assert not _dnsbl_rows(gw.vm, name), name
                continue
            assert ipaddress.ip_address(STUB_DNS_A).packed in result.stdout, result.stdout.hex()
            _drain_logs(gw)
            [row] = _reply_rows(gw.vm, name)
            client = forwarded if trusted else CLIENT_LAN_IP
            assert len(row) == 13 and row[7] == client and row[10] == "DoH", row
            assert row[11:13] == [PFSENSE_LAN_IP, LAN_DESCRIPTION], row
            _assert_unified_row(gw.vm, row, name, 6)
            _assert_report_row(gui, name, client, "DoH")
    finally:
        op = (
            f"config_set_path({h._php_str(path)}, {h._php_str(prior)});"
            if present
            else f"config_del_path({h._php_str(path)});"
        )
        _php_ok(gw.vm, op + "\nwrite_config('pfBlockerNG smoke: restore DoH trust');", "restore DoH trust")
        _apply(gw.vm)


def test_doq_from_a_client_that_does_not_trust_the_certificate_gets_no_answer(gw: Gateway, gateway_on: State) -> None:
    """A DoQ client that verifies the certificate against roots which do not include the Resolver's gets nothing.

    Given the same name answered with the VIP to a client that trusts the Resolver's certificate,
    When a client with only the system roots asks,
    Then the probe exits without an answer and says why (an x509 verification error), and no VIP.
    """
    name = gw.names.hostile[0]
    trusted, raw = _ask_doq(gw.client, name)
    assert h.is_vip(trusted), f"premise: DoQ with the Resolver's certificate trusted: {trusted}\n{raw}"
    answer, raw = _ask_doq(gw.client, name, ca=None)
    _say(f"DoQ without trust in the certificate: {raw.strip()}")
    assert _no_answer(answer) and "x509" in raw, f"DoQ without trust in the certificate: {answer}\n{raw}"


def test_doh_spoken_as_plain_http_gets_no_answer(gw: Gateway, gateway_on: State) -> None:
    """The DoH port speaks TLS only: a client that sends HTTP without TLS to it gets no answer.

    Given the same name answered with the VIP over DoH with TLS,
    When the client speaks plain HTTP/2 to the port,
    Then the connection fails and nothing is answered.
    """
    name = gw.names.hostile[1]
    tls, raw = _ask(gw.client, "doh-post", name)
    assert h.is_vip(tls), f"premise: DoH with TLS: {tls}\n{raw}"
    answer, raw = _ask(gw.client, "doh-plain", name)
    _say(f"DoH without TLS: {raw.strip()}")
    assert _no_answer(answer) and "no servers could be reached" in raw, (
        f"DoH without TLS: expected a failed connection and no answer, got {answer}\n{raw}"
    )


# --------------------------------------------------------------------------- #
# The Resolver's access list, applied before anyone is asked
# --------------------------------------------------------------------------- #


@pytest.mark.timeout(900)
def test_a_resolver_refuse_row_gets_refused_on_every_transport_and_removing_it_brings_the_vip_back(
    gw: Gateway, gateway_on: State
) -> None:
    """The gateway enforces the Resolver's `refuse` row itself: REFUSED, never the DNSBL answer, nothing logged.

    Given the LAN client gets the VIP for a listed name on every transport,
    When the Resolver's access list refuses 192.168.1.10/32 and Unbound rewrites access_lists.conf,
    Then once the gateway has re-read it the client gets REFUSED on every transport (a TCP query to port 53 echoes the
      question), an address no row names still gets the VIP, and dnsbl.log has no row for the refused names;
    When the row is removed,
    Then the VIP is back on every transport.
    """
    names = gw.names
    _expect_everywhere("before the refuse row", _ask_all(gw, names.blocked), h.is_vip, "the VIP")
    with _resolver_acl(gw.vm, "refuse"):
        _wait_udp(gw, names.refuse_poll, _refused, "REFUSED")
        results = _ask_all(gw, names.refused)
        _expect_everywhere("refuse row", results, _refused, "REFUSED")
        question = names.refused["tcp"]
        tcp_raw = results["tcp"][1]
        assert re.search(rf"^;{re.escape(question)}\.\s+IN\s+A\b", tcp_raw, re.MULTILINE), (
            f"the REFUSED reply to the TCP query on port 53 should echo the question {question}:\n{tcp_raw}"
        )
        _assert_no_rows_for(gw, names.refuse_barrier, names.refused)
    _wait_udp(gw, names.refuse_poll, h.is_vip, "the VIP again")
    _expect_everywhere("after the refuse row", _ask_all(gw, names.restored), h.is_vip, "the VIP")


@pytest.mark.timeout(900)
def test_a_resolver_deny_row_gets_no_answer_on_every_transport(gw: Gateway, gateway_on: State) -> None:
    """The gateway enforces the Resolver's `deny` row itself: nothing comes back on any transport.

    Given the LAN client gets the VIP for a listed name on every transport,
    When the Resolver's access list denies 192.168.1.10/32,
    Then once the gateway has re-read it every transport yields no answer (UDP times out, TCP and DoT are closed, the
      DoH request is aborted, the DoQ connection is refused), a second LAN address that no row names gets the VIP on
      every transport (so no listener is dead), and dnsbl.log has no row for the denied names.
    """
    names = gw.names
    _expect_everywhere("before the deny row", _ask_all(gw, names.blocked), h.is_vip, "the VIP")
    with _resolver_acl(gw.vm, "deny"):
        _wait_udp(gw, names.deny_poll, _no_answer, "no answer")
        _expect_everywhere("deny row", _ask_all(gw, names.denied), _no_answer, "no answer")
        _assert_no_rows_for(gw, names.deny_barrier, names.denied, alive=names.alive)


@pytest.mark.timeout(900)
def test_a_client_no_resolver_acl_row_names_is_refused_on_every_transport_and_an_ipv6_lan_client_gets_the_vip(
    gw: Gateway, gateway_on: State
) -> None:
    """A client that matches no `access-control` row is refused as Unbound refuses it, whatever it asks.

    Given the LAN client gets the VIP for a listed name on every transport, and the marked clause in unbound.conf, not
      access_lists.conf, grants the LAN's IPv6 /64,
    When the automatic LAN rows are off and the Resolver's only access list names 203.0.113.0/24, so that
      access_lists.conf has no row for 192.168.1.10,
    Then once the gateway has re-read the config the client gets REFUSED on every transport, for a listed name and for
      an unlisted one, and dnsbl.log has no row for them; an IPv6 client of the LAN, which only the clause grants, still
      gets the VIP, logged with its address: the firewall itself asking its own LAN IPv6 address over UDP and TCP, and
      the client VM on every transport through the fixture's scoped leased IPv6 DNS pass rules;
    When the lists are put back,
    Then the IPv4 client gets the VIP on every transport again.
    """
    names, vm = gw.names, gw.vm
    assert LAN_V6_ROW in _lines(gateway_on.conf), f"premise: the marked clause grants the LAN's /64:\n{gateway_on.conf}"
    assert LAN_V6_ROW not in _lines(gateway_on.access_lists), (
        f"premise: so does access_lists.conf:\n{gateway_on.access_lists}"
    )
    _expect_everywhere("before the lists change", _ask_all(gw, names.blocked), h.is_vip, "the VIP")
    unlisted = {transport: h.unique_domain(f"nomatch-allowed-{transport}") for transport in TRANSPORTS}
    with _resolver_acls(vm, [_acl(f"{ACL_NAME} other", "allow", *OTHER_ACL_NET)], auto_rows=False):
        written = _lines(vm.ssh("cat", ACCESS_LISTS).stdout)
        _say(f"{ACCESS_LISTS} with no row for {CLIENT_LAN_IP}: {written}")
        assert not _naming(written, CLIENT_LAN_IP), f"premise: a row names {CLIENT_LAN_IP}: {written}"
        assert _naming(written, OTHER_ACL_NET[0]), f"premise: the other list is not in {ACCESS_LISTS}: {written}"
        _wait_udp(gw, names.nomatch_poll, _refused, "REFUSED")
        _expect_everywhere("no row, listed name", _ask_all(gw, names.nomatch), _refused, "REFUSED")
        _expect_everywhere("no row, unlisted name", _ask_all(gw, unlisted), _refused, "REFUSED")
        with _client_v6(gw.client):
            via_vm = {
                transport: _ask(gw.client, transport, names.v6[transport], source=LAN_V6_CLIENT, server=LAN_V6_ADDR)
                for transport in TRANSPORTS
            }
            _expect_everywhere("IPv6 LAN client, the client VM", via_vm, h.is_vip, "the VIP")
        via_firewall = {
            transport: _firewall_ask(vm, name, tcp=transport == "tcp")
            for transport, name in zip(("udp", "tcp"), names.fw_v6)
        }
        _expect_everywhere("IPv6 LAN client, the firewall itself", via_firewall, h.is_vip, "the VIP")
        barrier, raw = _firewall_ask(vm, names.v6_barrier, tcp=False)
        assert h.is_vip(barrier), f"the firewall's last IPv6 query should get the VIP: {barrier}\n{raw}"
        _wait_dnsbl_row(vm, names.v6_barrier)
        refused_rows = {name: _dnsbl_rows(vm, name) for name in (*names.nomatch.values(), *unlisted.values())}
        assert not any(refused_rows.values()), f"dnsbl.log has rows for names the gateway refused: {refused_rows}"

        def logged_clients(asked: list[str]) -> set[ipaddress.IPv6Address | ipaddress.IPv4Address]:
            return {ipaddress.ip_address(row[3]) for name in asked for row in _dnsbl_rows(vm, name)}

        assert logged_clients(list(names.fw_v6)) == {ipaddress.ip_address(LAN_V6_ADDR)}, (
            "dnsbl.log: the firewall's rows"
        )
        assert logged_clients(list(names.v6.values())) == {ipaddress.ip_address(LAN_V6_CLIENT)}, "dnsbl.log: the VM"
        for transport, name in zip(("udp", "tcp"), names.fw_v6):
            [row] = _dnsbl_rows(vm, name)
            assert len(row) == 14 and row[11] == LOG_TRANSPORT[transport], row
            assert row[12:14] == [LAN_V6_ADDR, LAN_DESCRIPTION], row
        for transport, name in names.v6.items():
            [row] = _dnsbl_rows(vm, name)
            assert len(row) == 14 and row[11] == LOG_TRANSPORT[transport], row
            assert row[12:14] == [LAN_V6_ADDR, LAN_DESCRIPTION], row
    _wait_udp(gw, names.nomatch_poll, h.is_vip, "the VIP again")
    _expect_everywhere("after the lists are back", _ask_all(gw, names.nomatch_restored), h.is_vip, "the VIP")


# --------------------------------------------------------------------------- #
# DDR: the gateway answers resolver.arpa. itself (issue #3583)
# --------------------------------------------------------------------------- #

DDR_NAME = "_dns.resolver.arpa"
DDR_SOA = ("resolver.arpa.", 300, "SOA", "localhost. nobody.invalid. 1 3600 1200 604800 300")
UNBOUND_PLAIN_PORT = 5354  # Unbound's own loopback port for plain DNS while the gateway holds the Resolver's
# A dig that does not know RFC 9461's `dohpath` prints that SvcParamKey by its number.
SVCB_KEY_NAMES = {"key7": "dohpath"}


@dataclass(frozen=True)
class Record:
    owner: str
    ttl: int
    rtype: str
    rdata: str


@dataclass(frozen=True)
class Reply:
    """What dig printed: the header's rcode and flags, the three sections, and its own output for a failure message."""

    rcode: str  # UNKNOWN: no reply at all
    flags: frozenset[str]
    answer: tuple[Record, ...]
    authority: tuple[Record, ...]
    additional: tuple[Record, ...]
    raw: str


@dataclass(frozen=True)
class Svcb:
    priority: int
    target: str
    params: dict[str, str]  # SvcParamKey -> value, quotes removed


def _parse_reply(output: str) -> Reply:
    """dig's, or drill's, text for one query: `status:` or `rcode:` in the header, then the sections' record lines."""
    rcode, flags = "UNKNOWN", frozenset[str]()
    sections: dict[str, list[Record]] = {"ANSWER": [], "AUTHORITY": [], "ADDITIONAL": []}
    current: list[Record] | None = None
    for line in output.splitlines():
        status = re.search(r"\b(?:status|rcode): ([A-Z]+)", line)
        header = re.match(r";; (ANSWER|AUTHORITY|ADDITIONAL) SECTION:", line)
        if status:
            rcode = status.group(1)
        elif line.startswith(";; flags:"):
            flags = frozenset(line[len(";; flags:") :].split(";")[0].split())
        elif header:
            current = sections[header.group(1)]
        elif not line.strip() or line.startswith(";"):
            current = None
        elif current is not None:
            fields = line.split(None, 4)
            if len(fields) == 5 and fields[1].isdigit():
                current.append(Record(fields[0], int(fields[1]), fields[3], " ".join(fields[4].split())))
    return Reply(
        rcode, flags, tuple(sections["ANSWER"]), tuple(sections["AUTHORITY"]), tuple(sections["ADDITIONAL"]), output
    )


def _dig(client: SmokeVM, transport: str, rtype: str, name: str, *, server: str = PFSENSE_LAN_IP) -> Reply:
    """`name` of type `rtype` over one of DIG_TRANSPORTS; no answer reads as rcode UNKNOWN with dig's complaint."""
    options, port = DIG_TRANSPORTS[transport]
    args = ["dig", "+tries=1", "+time=5", "+noall", "+comments", "+answer", "+authority", "+additional", *options]
    if port:
        args += ["-p", str(port)]
    args += [rtype, name, f"@{server}"]
    result = client.ssh(shlex.join(args) + " 2>&1", timeout=40.0)
    return _parse_reply(f"{result.stdout}\n[exit {result.returncode}]")


def _unbound_reply(vm: SmokeVM, rtype: str, name: str) -> Reply:
    """Unbound's own answer, asked on the box at its loopback port, where the gateway is not in the way (drill)."""
    result = vm.ssh(f"drill -p {UNBOUND_PLAIN_PORT} {shlex.quote(name)} {shlex.quote(rtype)} @127.0.0.1 2>&1")
    return _parse_reply(f"{result.stdout}\n[exit {result.returncode}]")


def _svcb_records(reply: Reply) -> list[Svcb]:
    """The answer's SVCB records by priority (dig prints them in rotating order): `<priority> <target> key=value`."""
    found = []
    for record in reply.answer:
        if record.rtype != "SVCB":
            continue
        priority, target, *rest = record.rdata.split(None, 2)
        assert priority.isdigit(), f"dig printed {record} in a form this parser does not read:\n{reply.raw}"
        params = {
            SVCB_KEY_NAMES.get(key, key): quoted or bare
            for key, quoted, bare in re.findall(r'([\w-]+)=(?:"([^"]*)"|(\S+))', rest[0] if rest else "")
        }
        found.append(Svcb(int(priority), target.lower(), params))
    return sorted(found, key=lambda svcb: svcb.priority)


def _port(port: int, default: int) -> dict[str, str]:
    """The `port` SvcParam: only a transport off its default port has one (RFC 9460 leaves out the default)."""
    return {} if port == default else {"port": str(port)}


def _expected_svcb(target: str, *, doh_443: bool = False, address: str = PFSENSE_LAN_IP) -> list[Svcb]:
    """The records a query gets at `address` (the LAN's by default): DoH, DoT and DoQ, each with `target` as
    TargetName and that address as hint; `doh_443` leaves the DoH port out."""
    hint = {"ipv6hint" if ipaddress.ip_address(address).version == 6 else "ipv4hint": address}
    doh_port = {} if doh_443 else _port(DOH_PORT, 443)
    return [
        Svcb(1, target, {"alpn": "h2", **doh_port, "dohpath": "/dns-query{?dns}", **hint}),
        Svcb(2, target, {"alpn": "dot", **_port(DOT_PORT, 853), **hint}),
        Svcb(3, target, {"alpn": "doq", **_port(DOQ_PORT, 853), **hint}),
    ]


def _rows(section: tuple[Record, ...]) -> list[tuple[str, int, str, str]]:
    return [(r.owner.lower(), r.ttl, r.rtype, r.rdata.lower()) for r in section]


def _gateway_ddr_on(vm: SmokeVM) -> bool | None:
    """`--ddr` is on the running gateway's command line; None: no gateway runs.

    Only `--ddr` can be read there: `--ddr-doh-443` and the name answers are taken live, the process keeps the command
    line it started with.
    """
    pid = _pid_file(vm, PROXY_PID_FILE)
    gateway = next((p for p in _processes(vm) if p.pid == pid), None)
    if gateway is None:
        return None
    return "--ddr" in gateway.args.split()


def _ddr_doh_port_shown(client: SmokeVM, server: str = PFSENSE_LAN_IP) -> bool | None:
    """Whether the DoH designation a DDR query at `server` gets has a `port`; None: not exactly one DoH record."""
    reply = _dig(client, "udp", "SVCB", DDR_NAME, server=server)
    doh = [svcb for svcb in _svcb_records(reply) if svcb.params.get("alpn") == "h2"]
    return "port" in doh[0].params if len(doh) == 1 else None


def _set_ddr(vm: SmokeVM, on: bool, doh_443: bool) -> None:
    """The pfB-DNS form's DDR settings as its Save stores them: the toggle ('on' or the empty Off token) and the
    interface list of "Advertise DoH on port 443".

    DDR on is saved with the DNS name, its target (issue #3694); DDR off leaves the stored name as it is.
    """
    name = f"config_set_path({h._php_str(CFG_DNS_NAME)}, {h._php_str(DDR_DNS_NAME)});\n" if on else ""
    _php_ok(
        vm,
        name
        + f"config_set_path({h._php_str(CFG_DDR)}, {h._php_str('on' if on else '')});\n"
        + f"config_set_path({h._php_str(CFG_DDR_DOH_443)}, {h._php_str(DDR_443_INTERFACES if doh_443 else '')});\n"
        + "write_config('pfBlockerNG smoke: pfB-DNS DDR for the #3583 gateway smoke');",
        "DDR settings",
    )


def _ensure_ddr(gw: Gateway, *, on: bool, doh_443: bool = False) -> None:
    """Have the gateway run with `--ddr`, and DDR advertise DoH on 443 at the LAN address (`doh_443`), as asked.

    Stores and applies if it does not. DDR on also needs the module's DNS name stored (issue #3694). The running
    gateway takes the 443 selection live, so that is read from its DDR answer, not its command line. A gateway that
    never took the settings fails the first assertion of the test with what it runs, advertises and logged, not a later
    query. The module's snapshot puts the settings back with the rest of its config.
    """
    vm, client = gw.vm, gw.client
    selected = DDR_443_INTERFACES if doh_443 else ""
    if (
        _gateway_ddr_on(vm) != on
        or (on and h.config_get(vm, CFG_DNS_NAME) != DDR_DNS_NAME)
        or h.config_get(vm, CFG_DDR_DOH_443) != selected
    ):
        _set_ddr(vm, on, doh_443)
        _apply(vm)
        # Not raised here: the assertion below says what the gateway runs and logged.
        with contextlib.suppress(RuntimeError):
            h.wait_until(lambda: _gateway_ddr_on(vm) == on, timeout=60.0, interval=2.0)
    seen = _gateway_ddr_on(vm)
    stored = (h.config_get(vm, CFG_DDR), h.config_get(vm, CFG_DDR_DOH_443), h.config_get(vm, CFG_DNS_NAME))
    assert seen == on, (
        f"after the apply the gateway should run with --ddr = {on}, runs with {seen}; stored "
        f"(dns_shared/pfb_dns_ddr, dns/pfb_dns_ddr_doh_443_interfaces, dns/pfb_dns_name) = {stored}\n"
        f"{_proxy_log(vm, 30)}"
    )

    def serves() -> bool:
        return h.is_vip(_ask(client, "udp", gw.names.ready)[0])

    try:
        h.wait_until(serves, timeout=240.0, interval=3.0)
    except RuntimeError as exc:
        raise RuntimeError(f"{exc}\n{_diagnostics(vm)}") from exc
    if not on:
        return
    port_shown = not doh_443
    with contextlib.suppress(RuntimeError):
        h.wait_until(lambda: _ddr_doh_port_shown(client) is port_shown, timeout=60.0, interval=2.0)
    shown = _ddr_doh_port_shown(client)
    reads = {True: "carries a `port`", False: "has no `port`", None: "is not exactly one record"}
    assert shown is port_shown, (
        f"after the apply DDR's DoH designation for {PFSENSE_LAN_IP} should "
        f"{f'carry port {DOH_PORT}' if port_shown else 'have no `port` (443)'}; it {reads[shown]}; stored "
        f"(dns_shared/pfb_dns_ddr, dns/pfb_dns_ddr_doh_443_interfaces, dns/pfb_dns_name) = {stored}\n"
        f"{_proxy_log(vm, 30)}"
    )


def _assert_nodata(reply: Reply, what: str) -> None:
    assert reply.rcode == "NOERROR" and not reply.answer and _rows(reply.authority) == [DDR_SOA], (
        f"{what}: expected NOERROR, no answer and the Authority SOA {DDR_SOA}; got {reply.rcode}, answer "
        f"{_rows(reply.answer)}, authority {_rows(reply.authority)}\n{reply.raw}"
    )


@pytest.mark.timeout(900)
@pytest.mark.parametrize("transport", ["udp", "tcp"])
def test_ddr_svcb_query_over_plain_dns_gets_one_record_per_encrypted_transport_on_the_queried_address(
    gw: Gateway, gateway_on: State, transport: str
) -> None:
    """Criterion 1: `_dns.resolver.arpa. SVCB` from the LAN client, over UDP and over TCP, is answered with DDR.

    Given the gateway runs with `--ddr`,
    Then NOERROR, authoritative, three SVCB records for the owner asked: DoH priority 1 (`alpn=h2`, `port` only off
      443, `dohpath=/dns-query{?dns}`), DoT priority 2 (`alpn=dot`, `port` only off 853) and DoQ priority 3
      (`alpn=doq`, `port` only off 853), each with TargetName the DNS name (`dns/pfb_dns_name`), `ipv4hint` the LAN
      address and TTL 300, and the Additional section holds that name's A record, the LAN address, TTL 300.
    """
    _ensure_ddr(gw, on=True)
    reply = _dig(gw.client, transport, "SVCB", DDR_NAME)
    _say(f"DDR SVCB over {transport}: {reply.rcode} {sorted(reply.flags)} {_rows(reply.answer)}")
    assert reply.rcode == "NOERROR" and "aa" in reply.flags, (
        f"{transport}: expected NOERROR with the aa flag, got {reply.rcode} {sorted(reply.flags)}\n{reply.raw}"
    )
    assert _svcb_records(reply) == _expected_svcb(DDR_TARGET), (
        f"{transport}: SVCB records expected {_expected_svcb(DDR_TARGET)}, got {_svcb_records(reply)}\n{reply.raw}"
    )
    assert {(r.owner.lower(), r.ttl) for r in reply.answer} == {(f"{DDR_NAME}.", 300)}, (
        f"{transport}: every answer should be owned by {DDR_NAME}. with TTL 300, got {_rows(reply.answer)}"
    )
    addresses = [row for row in _rows(reply.additional) if row[2] in ("A", "AAAA")]
    assert addresses == [(DDR_TARGET, 300, "A", PFSENSE_LAN_IP)], (
        f"{transport}: Additional should hold only {(DDR_TARGET, 300, 'A', PFSENSE_LAN_IP)}, got {addresses}\n"
        f"{reply.raw}"
    )


@pytest.mark.timeout(900)
@pytest.mark.parametrize(
    ("transport", "rtype", "name"),
    [
        pytest.param("udp", "A", DDR_NAME, id="another-type-at-the-ddr-name"),
        pytest.param("udp", "SVCB", "foo.resolver.arpa", id="another-name-under-resolver-arpa"),
        pytest.param("dot", "SVCB", DDR_NAME, id="svcb-over-dot"),
        pytest.param("doh-post", "SVCB", DDR_NAME, id="svcb-over-doh"),
    ],
)
def test_ddr_other_queries_under_resolver_arpa_get_nodata_with_the_300_second_soa(
    gw: Gateway, gateway_on: State, transport: str, rtype: str, name: str
) -> None:
    """Criterion 2: anything under `resolver.arpa.` that is not the plain-DNS DDR query is NODATA with the SOA.

    Given the gateway runs with `--ddr`,
    When the client asks another type at `_dns.resolver.arpa.`, another name under `resolver.arpa.`, or the SVCB query
      over DoT or DoH,
    Then NOERROR, no answer, and `resolver.arpa. 300 IN SOA localhost. nobody.invalid. 1 3600 1200 604800 300` in
      Authority.
    """
    _ensure_ddr(gw, on=True)
    reply = _dig(gw.client, transport, rtype, name)
    _say(f"DDR {rtype} {name} over {transport}: {reply.rcode} {_rows(reply.answer)} {_rows(reply.authority)}")
    _assert_nodata(reply, f"{rtype} {name} over {transport}")


@pytest.mark.timeout(900)
@pytest.mark.parametrize(
    ("rtype", "row"),
    [
        pytest.param("SOA", DDR_SOA, id="soa"),
        pytest.param("NS", ("resolver.arpa.", 300, "NS", "localhost."), id="ns"),
    ],
)
def test_ddr_apex_soa_and_ns_queries_get_the_300_second_records(
    gw: Gateway, gateway_on: State, rtype: str, row: tuple[str, int, str, str]
) -> None:
    """Criterion 2: `resolver.arpa.` SOA and NS are answered with the records of Unbound's default zone, TTL 300."""
    _ensure_ddr(gw, on=True)
    reply = _dig(gw.client, "udp", rtype, "resolver.arpa")
    assert reply.rcode == "NOERROR" and _rows(reply.answer) == [row], (
        f"resolver.arpa {rtype}: expected NOERROR and the answer {[row]}, got {reply.rcode} {_rows(reply.answer)}\n"
        f"{reply.raw}"
    )


def _resolver_arpa_log_lines(vm: SmokeVM) -> list[str]:
    """Unbound's query-log lines that name resolver.arpa (the module's Custom Options turn `log-queries` on)."""
    return vm.ssh("grep", "-F", "--", "resolver.arpa", RESOLVER_LOG).stdout.splitlines()


@pytest.mark.timeout(900)
def test_ddr_answers_are_never_forwarded_so_unbounds_query_log_names_none_of_them(
    gw: Gateway, gateway_on: State
) -> None:
    """Criterion 2, "Unbound saw none": Unbound's query log gains no line for any DDR-answered query.

    Given the gateway runs with `--ddr` and every query below is answered NOERROR by the gateway itself,
    When the client asks them all and then an allowed name that the upstream answers (so that the log has drained
      past them, Unbound logging in the order it receives),
    Then the log lines naming `resolver.arpa` are the ones it had before.
    """
    _ensure_ddr(gw, on=True)
    vm, client = gw.vm, gw.client
    asked = (
        ("udp", "SVCB", DDR_NAME),
        ("tcp", "SVCB", DDR_NAME),
        ("dot", "SVCB", DDR_NAME),
        ("udp", "A", DDR_NAME),
        ("udp", "SVCB", "foo.resolver.arpa"),
        ("udp", "SOA", "resolver.arpa"),
        ("udp", "NS", "resolver.arpa"),
    )
    before = _resolver_arpa_log_lines(vm)
    for transport, rtype, name in asked:
        reply = _dig(client, transport, rtype, name)
        assert reply.rcode == "NOERROR", (
            f"premise: the gateway answers {rtype} {name} over {transport} itself, got {reply.rcode}\n{reply.raw}"
        )
    barrier = h.unique_domain("ddr-barrier")
    answer, raw = _ask(client, "udp", barrier)
    _assert_answered_by_upstream(gw, barrier, answer, raw, "the allowed name after the DDR queries")
    gained = _resolver_arpa_log_lines(vm)[len(before) :]
    assert not gained, f"Unbound's query log gained lines for names the gateway answers itself: {gained}"


@pytest.mark.timeout(900)
def test_ddr_query_from_a_client_the_resolver_acl_refuses_gets_refused(gw: Gateway, gateway_on: State) -> None:
    """Criterion 4: the ACL comes before DDR, so a refused client gets REFUSED, not the SVCB records.

    Given the gateway runs with `--ddr` and the LAN client gets the three SVCB records,
    When the Resolver's access list refuses 192.168.1.10/32 and the gateway has re-read it,
    Then the DDR query gets REFUSED, no answer, over UDP and over TCP; and once the row is removed the VIP is back.
    """
    _ensure_ddr(gw, on=True)
    before = _dig(gw.client, "udp", "SVCB", DDR_NAME)
    assert len(_svcb_records(before)) == 3, (
        f"premise: with no refuse row the client gets three SVCB records\n{before.raw}"
    )
    with _resolver_acl(gw.vm, "refuse"):
        _wait_udp(gw, gw.names.refuse_poll, _refused, "REFUSED")
        for transport in ("udp", "tcp"):
            reply = _dig(gw.client, transport, "SVCB", DDR_NAME)
            assert reply.rcode == "REFUSED" and not reply.answer, (
                f"{transport}: the refused client should get REFUSED and no answer, got {reply.rcode} "
                f"{_rows(reply.answer)}\n{reply.raw}"
            )
    _wait_udp(gw, gw.names.refuse_poll, h.is_vip, "the VIP again")


@pytest.mark.timeout(900)
def test_ddr_off_leaves_resolver_arpa_to_unbound_and_relays_its_answer_unchanged(
    gw: Gateway, gateway_on: State
) -> None:
    """Criterion 3: with the toggle off (pfB-DNS still on) the client gets what Unbound itself answers.

    Given the gateway runs with `--ddr` and answers the SVCB query itself with three records (the before-state: the
      toggle changes the answer),
    When the toggle is turned off and applied,
    Then the gateway's answer to `_dns.resolver.arpa. SVCB`, whatever this Unbound version says, has the rcode, the
      number of answer records and the Authority records (TTL aside) of Unbound's own answer, asked on the box at
      127.0.0.1 port 5354.
    """
    _ensure_ddr(gw, on=True)
    on = _dig(gw.client, "udp", "SVCB", DDR_NAME)
    assert len(_svcb_records(on)) == 3, f"premise: with DDR on the gateway answers with three SVCB records\n{on.raw}"
    _ensure_ddr(gw, on=False)
    relayed = _dig(gw.client, "udp", "SVCB", DDR_NAME)
    own = _unbound_reply(gw.vm, "TYPE64", DDR_NAME)
    _say(f"Unbound's own answer: {own.rcode} {_rows(own.answer)} {_rows(own.authority)}")
    _say(f"the gateway's answer, DDR off: {relayed.rcode} {_rows(relayed.answer)} {_rows(relayed.authority)}")
    assert own.rcode != "UNKNOWN", f"no answer from Unbound on 127.0.0.1:{UNBOUND_PLAIN_PORT}\n{own.raw}"

    def shape(reply: Reply) -> tuple[str, int, list[tuple[str, str, str]]]:
        return reply.rcode, len(reply.answer), [(o, t, d) for o, _, t, d in _rows(reply.authority)]

    assert shape(relayed) == shape(own), (
        f"DDR off: the client's answer (rcode, answers, Authority) {shape(relayed)} differs from Unbound's own "
        f"{shape(own)}\nclient:\n{relayed.raw}\nUnbound:\n{own.raw}"
    )


@pytest.mark.timeout(900)
def test_ddr_doh_on_port_443_leaves_the_port_out_of_the_doh_record_and_nothing_else_changed(
    gw: Gateway, gateway_on: State
) -> None:
    """Criterion 9 (revised): an interface selected for "Advertise DoH on port 443" has DoH advertised without `port`.

    Given DoH listens on 4443 and the gateway runs with `--ddr` and no interface selected, whose DoH record carries
      `port=4443` (the before-state: the selection is what removes it),
    When `lan` is selected in `dns/pfb_dns_ddr_doh_443_interfaces` and applied,
    Then the DoH record for the LAN address has no `port` but the same TargetName (the DNS name), `ipv4hint` (the LAN
      address) and `dohpath=/dns-query{?dns}`; DoT and DoQ are as before; Additional holds the DNS name's A record; and
      the gateway still answers DoH at the LAN address on 4443.
    """
    _ensure_ddr(gw, on=True)
    before = _dig(gw.client, "udp", "SVCB", DDR_NAME)
    assert _svcb_records(before) == _expected_svcb(DDR_TARGET), (
        f"premise: without the toggle the DoH record carries port {DOH_PORT}: expected {_expected_svcb(DDR_TARGET)}, "
        f"got {_svcb_records(before)}\n{before.raw}"
    )
    _ensure_ddr(gw, on=True, doh_443=True)
    reply = _dig(gw.client, "udp", "SVCB", DDR_NAME)
    expected = _expected_svcb(DDR_TARGET, doh_443=True)
    assert reply.rcode == "NOERROR" and _svcb_records(reply) == expected, (
        f"expected NOERROR and {expected}, got {reply.rcode} {_svcb_records(reply)}\n{reply.raw}"
    )
    addresses = [row for row in _rows(reply.additional) if row[2] in ("A", "AAAA")]
    assert addresses == [(DDR_TARGET, 300, "A", PFSENSE_LAN_IP)], (
        f"Additional should hold only the DNS name's {(DDR_TARGET, 300, 'A', PFSENSE_LAN_IP)}, got {addresses}\n"
        f"{reply.raw}"
    )
    answer, raw = _ask(gw.client, "doh-post", gw.names.ready)
    assert h.is_vip(answer), (
        f"DoH at {PFSENSE_LAN_IP}:{DOH_PORT} after the selection: expected the DNSBL VIP, got {answer}\n{raw}"
    )


# --------------------------------------------------------------------------- #
# A Resolver VIP joins the interface addresses (issue #3694)
# --------------------------------------------------------------------------- #

DNS_GENERAL_PAGE = "/pfblockerng/pfblockerng_dns_general.php"
CFG_LISTEN_AUTO4 = f"{h.CFG_GLOBAL}/pfb_dns_listen_auto4"  # the address the automatic IPv4 Resolver VIP took
LAN_ONLY_LISTS = {
    "pfb_dns_interface": "lan",
    "pfb_dns_dot_interface": "lan",
}  # plain DNS and DoT on the LAN, as the issue asks


def _set_lists(vm: SmokeVM, lists: dict[str, str]) -> None:
    """pfB-DNS's interface lists as its Save stores them."""
    assignments = "".join(
        f"config_set_path({h._php_str(h.dns_config_path(key))}, {h._php_str(value)});\n" for key, value in lists.items()
    )
    _php_ok(
        vm,
        assignments + "write_config('pfBlockerNG smoke: pfB-DNS interface lists for the #3694 smoke');",
        "interface lists",
    )


@contextlib.contextmanager
def _client_route(client: SmokeVM, address: str) -> Iterator[None]:
    """Route an owned VIP through the firewall, with an authorized source for IPv6."""
    if ipaddress.ip_address(address).version == 6:
        source = h.pin_client_route6(client, address, LAN_V6_ADDR)
        try:
            route = client.ssh("ip", "-6", "route", "get", address)
            selected = re.search(r"\bsrc (\S+)", route.stdout)
            assert route.returncode == 0 and selected and selected.group(1) == source == LAN_V6_CLIENT, (
                f"VIP route must use the authorized client {LAN_V6_CLIENT}: {route.stdout!r} {route.stderr!r}"
            )
            yield
        finally:
            h.unpin_client_route6(client, address)
        return
    destination = f"{address}/32"
    added = client.ssh(f"ip route replace {destination} via {PFSENSE_LAN_IP}")
    assert added.returncode == 0, f"cannot route {address} through {PFSENSE_LAN_IP} on the client: {added.stderr!r}"
    try:
        yield
    finally:
        client.ssh(f"ip route del {destination}")


def _sockets_on_dns_ports(vm: SmokeVM) -> str:
    """What holds the DNS ports of this module, and on which address: the evidence of which listeners exist."""
    return vm.ssh(f"sockstat -46lw | grep -E ':(53|443|{DOT_PORT}|{DOH_PORT}) ' | sort").stdout


def _serves(gw: Gateway, server: str = PFSENSE_LAN_IP) -> bool:
    return h.is_vip(_ask(gw.client, "udp", gw.names.ready, server=server)[0])


@pytest.mark.timeout(1500)
def test_a_resolver_vip_joins_the_interface_addresses_and_ddr_follows_the_address_asked(
    gw: Gateway, gateway_on: State, gui: WebUI
) -> None:
    """issue #3694: the Resolver VIP is listened on besides the LAN address, for plain DNS, DoT, DoH and DoQ.

    Given the gateway serves plain DNS and DoT on the LAN, DoH and DoQ on the LAN, and DDR is on,
    When the DNS General page turns on the Resolver addresses with an automatic IPv4 VIP and the update pass applies it,
    Then the gateway is the same process (the listen addresses changed live, no restart) and holds plain DNS (UDP and
      TCP), DoT, DoH and DoQ on the LAN address and on the VIP; a LAN client querying the LAN address gets an answer
      (its ACL row admits it, and the answer is the gateway's, not a refusal), as it does at the VIP; a DDR SVCB query
      to the LAN address returns the DoH, DoT and DoQ designations for the LAN address and one to the VIP returns the
      VIP's, its DoH record without `port` (the automatic VIP serves DoH on 443 too); and the status panel lists both
      addresses as listening.
    Every observation is taken before any is judged, so a failing run names each wrong one, with the sockets the box
    holds (no listener on the LAN address, and the client's query unanswered, is the VIP having taken its place; a
    REFUSED would be the ACL).
    """
    vm, client = gw.vm, gw.client
    _ensure_ddr(gw, on=True)
    prior = {key: h.config_get(vm, h.dns_config_path(key)) for key in LAN_ONLY_LISTS}
    assert all(prior.values()), f"premise: pfB-DNS's interface lists are seeded, got {prior}"
    problems: list[str] = []

    def expect(ok: bool, what: str) -> None:
        if not ok:
            problems.append(what)

    try:
        _set_lists(vm, LAN_ONLY_LISTS)
        _apply(vm)
        h.wait_until(lambda: _serves(gw), timeout=240.0, interval=3.0)
        pid = _capture(vm).proxy_pid
        before = _dig(client, "udp", "SVCB", DDR_NAME)
        assert _svcb_records(before) == _expected_svcb(DDR_TARGET), (
            f"premise: with no VIP the LAN address gets the DoH, DoT and DoQ designations: "
            f"{_svcb_records(before)}\n{before.raw}"
        )

        gui.post(
            DNS_GENERAL_PAGE,
            {"pfb_dns_listen_vip": "on", "pfb_dns_listen_vip4": "auto", "pfb_dns_listen_interface": "lo0"},
        )
        vip = h.config_get(vm, CFG_LISTEN_AUTO4)
        assert vip and ipaddress.ip_address(vip).version == 4, (
            f"the DNS General save made no IPv4 Resolver VIP: {vip!r}"
        )
        _apply(vm)
        with _client_route(client, vip):
            h.wait_until(lambda: _serves(gw, vip), timeout=240.0, interval=3.0)
            now = _capture(vm)
            sockets = now.proxy_sockets()
            held = _sockets_on_dns_ports(vm)
            _say(f"VIP {vip}; gateway pid {pid} -> {now.proxy_pid}; sockets on the DNS ports:\n{held}")
            expect(
                now.proxy_pid == pid,
                f"the gateway restarted (pid {pid} -> {now.proxy_pid}): its listen addresses should change live",
            )
            for address in (PFSENSE_LAN_IP, vip):
                wanted = {
                    ("udp4", f"{address}:53"),
                    ("tcp4", f"{address}:53"),
                    ("tcp4", f"{address}:{DOT_PORT}"),
                    ("tcp4", f"{address}:{443 if address == vip else DOH_PORT}"),
                    ("udp4", f"{address}:{DOQ_PORT}"),
                }
                expect(not wanted - sockets, f"the gateway holds no socket for {sorted(wanted - sockets)}")
            expect(
                ("tcp4", f"{vip}:{DOH_PORT}") not in sockets,
                f"managed VIP still serves the configured DoH port {DOH_PORT}: {sorted(sockets)}",
            )

            for address in (PFSENSE_LAN_IP, vip):
                for transport in ("udp", "tcp", "dot"):
                    answer, raw = _ask(client, transport, gw.names.ready, server=address)
                    _say(f"{transport} to {address}: {answer.rcode} {answer.records}")
                    expect(
                        h.is_vip(answer),
                        f"{transport} to {address}: expected the VIP, got {answer} "
                        f"(UNKNOWN is no answer, REFUSED the ACL)\n{raw}",
                    )
                allowed = h.unique_domain("vipkeeps")
                answer, raw = _ask(client, "udp", allowed, server=address)
                expect(
                    h.resolves_to(answer, STUB_DNS_A),
                    f"udp to {address}: {allowed} expected the upstream's {STUB_DNS_A}, got {answer}\n{raw}",
                )

                reply = _dig(client, "udp", "SVCB", DDR_NAME, server=address)
                records = _svcb_records(reply)
                _say(f"DDR SVCB to {address}: {reply.rcode} {records}")
                # The managed VIP serves only standard transport ports.
                designations = _expected_svcb(DDR_TARGET, doh_443=address == vip, address=address)
                expect(
                    records == designations,
                    f"DDR to {address}: expected {designations}, got {records}\n{reply.raw}",
                )
                addresses = [row for row in _rows(reply.additional) if row[2] in ("A", "AAAA")]
                expect(
                    addresses == [(DDR_TARGET, 300, "A", address)],
                    f"DDR to {address}: Additional holds {addresses}\n{reply.raw}",
                )

            page = gui.get(STATUS_PAGE).text
            listed = {at: state for _, ats, state in _status_rows(page, "plain") for at in ats}
            _say(f"status panel, plain DNS: {_status_rows(page, 'plain')}")
            for address in (PFSENSE_LAN_IP, vip):
                expect(
                    listed.get(f"{address}:53") == "Listening",
                    f"the status panel does not list {address}:53 as Listening: {listed}",
                )

            lan_global = [a for a in _lan_addresses(vm) if ":" in a and ipaddress.ip_address(a).is_global]
            if lan_global:
                for address in lan_global:
                    own = _parse_reply(vm.ssh(f"drill @{address} {DDR_NAME} TYPE64 2>&1").stdout)
                    expected = _expected_svcb(DDR_TARGET, address=address)
                    expect(
                        own.rcode == "NOERROR" and _svcb_records(own) == expected,
                        f"DDR to the public IPv6 address {address}: expected {expected}, "
                        f"got {_svcb_records(own)}\n{own.raw}",
                    )
                    additional = [row for row in _rows(own.additional) if row[2] in ("A", "AAAA")]
                    expect(
                        additional == [(DDR_TARGET, 300, "AAAA", address.lower())],
                        f"DDR to the public IPv6 address {address}: expected its AAAA additional, "
                        f"got {additional}\n{own.raw}",
                    )
            else:
                _say(f"the LAN has no public IPv6 address; only its configured IPv6 {LAN_V6_ADDR} is available")
        assert not problems, "\n".join(problems) + f"\nsockets on the DNS ports:\n{_sockets_on_dns_ports(vm)}"
    finally:
        gui.post(DNS_GENERAL_PAGE, {"pfb_dns_listen_vip": "", "pfb_dns_listen_vip4": "none"})
        _set_lists(vm, prior)
        _apply(vm)
        with contextlib.suppress(RuntimeError):
            h.wait_until(lambda: _serves(gw), timeout=240.0, interval=3.0)


def _a_answers(reply: Reply) -> list[str]:
    return [record.rdata for record in reply.answer if record.rtype == "A"]


@pytest.mark.timeout(1500)
def test_the_dns_name_is_answered_with_the_address_the_query_reached(
    gw: Gateway, gateway_on: State, gui: WebUI
) -> None:
    """issue #3694: pfB-DNS answers A for its DNS name with the address the query arrived on.

    Given the gateway serves plain DNS and DoT on the LAN, DDR is on with the DNS name set, and the DNS General page
      has turned on an automatic IPv4 Resolver VIP that the client reaches through a host route,
    When the LAN client asks A for the name over UDP at the LAN address and at the VIP (lower case, then mixed case),
      A for a subdomain of the name at the LAN address, and the DDR SVCB query at the LAN address,
    Then A for the name at the LAN address is that address and no other, at the VIP the VIP and no other, mixed case
      the same; the subdomain gets the upstream's answer through Unbound, not the LAN address; and every SVCB
      record's TargetName is the name.
    Every observation is taken before any is judged, so a failing run names each wrong one. Everything the test
    changes is put back.
    """
    vm, client = gw.vm, gw.client
    _ensure_ddr(gw, on=True)
    prior = {key: h.config_get(vm, h.dns_config_path(key)) for key in LAN_ONLY_LISTS}
    assert all(prior.values()), f"premise: pfB-DNS's interface lists are seeded, got {prior}"
    mixed = "".join(c.upper() if i % 2 else c for i, c in enumerate(DDR_DNS_NAME))
    subdomain = f"sub.{DDR_DNS_NAME}"
    problems: list[str] = []

    def expect(ok: bool, what: str) -> None:
        if not ok:
            problems.append(what)

    try:
        _set_lists(vm, LAN_ONLY_LISTS)
        _apply(vm)
        h.wait_until(lambda: _serves(gw), timeout=240.0, interval=3.0)
        gui.post(
            DNS_GENERAL_PAGE,
            {"pfb_dns_listen_vip": "on", "pfb_dns_listen_vip4": "auto", "pfb_dns_listen_interface": "lo0"},
        )
        vip = h.config_get(vm, CFG_LISTEN_AUTO4)
        assert vip and ipaddress.ip_address(vip).version == 4, (
            f"the DNS General save made no IPv4 Resolver VIP: {vip!r}"
        )
        _apply(vm)
        with _client_route(client, vip):
            h.wait_until(lambda: _serves(gw, vip), timeout=240.0, interval=3.0)
            for address in (PFSENSE_LAN_IP, vip):
                for asked in (DDR_DNS_NAME, mixed):
                    reply = _dig(client, "udp", "A", asked, server=address)
                    _say(f"A {asked} to {address}: {reply.rcode} {_rows(reply.answer)}")
                    expect(
                        reply.rcode == "NOERROR" and _a_answers(reply) == [address],
                        f"A {asked} to {address}: expected NOERROR and exactly {[address]}, got {reply.rcode} "
                        f"{_a_answers(reply)} (the upstream's {STUB_DNS_A} is Unbound's answer: the gateway did "
                        f"not answer the name)\n{reply.raw}",
                    )

            reply = _dig(client, "udp", "A", subdomain, server=PFSENSE_LAN_IP)
            _say(f"A {subdomain} to {PFSENSE_LAN_IP}: {reply.rcode} {_rows(reply.answer)}")
            expect(
                reply.rcode == "NOERROR" and _a_answers(reply) == [STUB_DNS_A],
                f"A {subdomain} to {PFSENSE_LAN_IP}: expected Unbound's answer, the upstream's {STUB_DNS_A} (not "
                f"{PFSENSE_LAN_IP}), got {reply.rcode} {_a_answers(reply)}\n{reply.raw}",
            )

            reply = _dig(client, "udp", "SVCB", DDR_NAME, server=PFSENSE_LAN_IP)
            targets = sorted({svcb.target for svcb in _svcb_records(reply)})
            _say(f"DDR SVCB to {PFSENSE_LAN_IP}: {reply.rcode} {_svcb_records(reply)}")
            expect(
                targets == [DDR_TARGET],
                f"DDR SVCB to {PFSENSE_LAN_IP}: expected every TargetName to be {DDR_TARGET}, got {targets}\n"
                f"{reply.raw}",
            )
        assert not problems, "\n".join(problems) + f"\nsockets on the DNS ports:\n{_sockets_on_dns_ports(vm)}"
    finally:
        gui.post(DNS_GENERAL_PAGE, {"pfb_dns_listen_vip": "", "pfb_dns_listen_vip4": "none"})
        _set_lists(vm, prior)
        _apply(vm)
        with contextlib.suppress(RuntimeError):
            h.wait_until(lambda: _serves(gw), timeout=240.0, interval=3.0)


@pytest.mark.timeout(1500)
def test_an_automatic_resolver_vip_serves_doh_on_443_and_ddr_advertises_it_there(
    gw: Gateway, gateway_on: State, gui: WebUI
) -> None:
    """issue #3699: an automatically created Resolver VIP serves DoH only on port 443.

    Given DoH listens on the LAN at 4443, DDR is on and no interface is selected for "Advertise DoH on port 443",
    When the DNS General page turns on an automatic IPv4 Resolver VIP and the update pass applies it,
    Then the gateway holds a tcp4 socket on the VIP at 443, none there at 4443 and none on the LAN address at 443;
      DDR at the VIP advertises DoH without `port` and at the LAN address with `port=4443`; a DoH query to the VIP
      at 443 is answered by the gateway (a listed name gets the DNSBL VIP, an allowed one the upstream's answer).
    Every observation is taken before any is judged, so a failing run names each wrong one, with the sockets the box
    holds. Everything the test changes is put back.
    """
    vm, client = gw.vm, gw.client
    _ensure_ddr(gw, on=True)
    prior = {key: h.config_get(vm, h.dns_config_path(key)) for key in LAN_ONLY_LISTS}
    assert all(prior.values()), f"premise: pfB-DNS's interface lists are seeded, got {prior}"
    problems: list[str] = []

    def expect(ok: bool, what: str) -> None:
        if not ok:
            problems.append(what)

    try:
        _set_lists(vm, LAN_ONLY_LISTS)
        _apply(vm)
        h.wait_until(lambda: _serves(gw), timeout=240.0, interval=3.0)
        gui.post(
            DNS_GENERAL_PAGE,
            {"pfb_dns_listen_vip": "on", "pfb_dns_listen_vip4": "auto", "pfb_dns_listen_interface": "lo0"},
        )
        vip = h.config_get(vm, CFG_LISTEN_AUTO4)
        assert vip and ipaddress.ip_address(vip).version == 4, (
            f"the DNS General save made no IPv4 Resolver VIP: {vip!r}"
        )
        _apply(vm)
        with _client_route(client, vip):
            h.wait_until(lambda: _serves(gw, vip), timeout=240.0, interval=3.0)
            on_443 = ("tcp4", f"{vip}:443")
            # Not raised here: the observations below name what the gateway holds.
            with contextlib.suppress(RuntimeError):
                h.wait_until(lambda: on_443 in _capture(vm).proxy_sockets(), timeout=30.0, interval=2.0)
            sockets = _capture(vm).proxy_sockets()
            _say(f"VIP {vip}; sockets on the DNS ports:\n{_sockets_on_dns_ports(vm)}")
            wanted = {on_443}
            expect(not wanted - sockets, f"the gateway holds no socket for {sorted(wanted - sockets)}")
            expect(
                ("tcp4", f"{vip}:{DOH_PORT}") not in sockets,
                f"managed VIP still serves the configured DoH port {DOH_PORT}: {sorted(sockets)}",
            )
            lan_443 = ("tcp4", f"{PFSENSE_LAN_IP}:443")
            expect(
                lan_443 not in sockets, f"the gateway holds {lan_443}, but DoH listens on the LAN at {DOH_PORT} only"
            )

            for port in (443,):
                answer, raw = _ask(client, "doh-post", gw.names.ready, server=vip, port=port)
                _say(f"DoH to {vip}:{port}, listed name: {answer.rcode} {answer.records}")
                expect(
                    h.is_vip(answer),
                    f"DoH to https://{vip}:{port}/dns-query, listed name: expected the DNSBL VIP, got {answer} "
                    f"(UNKNOWN is no answer)\n{raw}",
                )
                allowed = h.unique_domain("dohvip")
                answer, raw = _ask(client, "doh-post", allowed, server=vip, port=port)
                _say(f"DoH to {vip}:{port}, allowed name: {answer.rcode} {answer.records}")
                expect(
                    h.resolves_to(answer, STUB_DNS_A),
                    f"DoH to https://{vip}:{port}/dns-query: {allowed} expected the upstream's {STUB_DNS_A}, got "
                    f"{answer}\n{raw}",
                )

            wanted_records = {
                vip: _expected_svcb(DDR_TARGET, doh_443=True, address=vip),
                PFSENSE_LAN_IP: _expected_svcb(DDR_TARGET),
            }
            for address, expected in wanted_records.items():
                reply = _dig(client, "udp", "SVCB", DDR_NAME, server=address)
                records = _svcb_records(reply)
                _say(f"DDR SVCB to {address}: {reply.rcode} {records}")
                expect(
                    records == expected,
                    f"DDR to {address}: expected {expected}, got {records}\n{reply.raw}",
                )
        assert not problems, "\n".join(problems) + f"\nsockets on the DNS ports:\n{_sockets_on_dns_ports(vm)}"
    finally:
        gui.post(DNS_GENERAL_PAGE, {"pfb_dns_listen_vip": "", "pfb_dns_listen_vip4": "none"})
        _set_lists(vm, prior)
        _apply(vm)
        with contextlib.suppress(RuntimeError):
            h.wait_until(lambda: _serves(gw), timeout=240.0, interval=3.0)


# --------------------------------------------------------------------------- #
# Stop and toggle off
# --------------------------------------------------------------------------- #


def test_rc_stop_ends_the_gateway_and_the_supervisor(gw: Gateway, gateway_on: State) -> None:
    """`pfb_dns_proxy.sh stop` waits for the whole tree to go: no process, no pidfile, service stopped.

    Given the gateway and the supervisor running,
    When the rc script stops them,
    Then it exits 0 (its own wait ended with both gone), neither pid is alive, both pidfiles are gone and Status >
      Services says stopped.
    """
    state, vm = gateway_on, gw.vm
    tree = {state.daemon_pid, state.proxy_pid}
    assert None not in tree and len(tree) == 2, f"supervisor and gateway pids: {tree}"
    stop = vm.ssh(PROXY_RC, "stop")
    assert stop.returncode == 0, f"{PROXY_RC} stop: rc={stop.returncode} {stop.stdout!r} {stop.stderr!r}"
    survivors = [p for p in _processes(vm) if p.pid in tree]
    assert not survivors, f"still alive after the rc stop: {survivors}"
    assert _pid_file(vm, PROXY_PID_FILE) is None and _pid_file(vm, DAEMON_PID_FILE) is None, "a pidfile is left"
    after = _capture(vm)
    assert after.service == "stopped" and after.ps == [], f"service {after.service}, processes {after.ps}"


@pytest.mark.timeout(900)
def test_toggle_off_gives_the_resolver_back_and_leaves_no_gateway(gw: Gateway, gateway_on: State) -> None:
    """Turning the toggle off and applying gives the Resolver back as it was and leaves no gateway behind.

    Given the toggle on (the Resolver moved, the gateway serving),
    When the toggle is turned off and applied,
    Then no gateway or supervisor runs and no pidfile is left; every Resolver key equals its pre-toggle value;
      the marker is cleared; unbound.conf has no python module (pfB-DNS off is DNSBL off, #3770); Unbound listens
      where it did before the toggle; And the client's blocked, allowed and DoT queries are answered by the upstream:
      Unbound blocks nothing again.
    """
    vm, before = gw.vm, gw.before
    assert _is_on(gateway_on) and gateway_on.marker, f"the toggle is not on before the test turns it off: {gateway_on}"
    _set_proxy_toggle(vm, False)
    _apply(vm)
    state = _capture(vm)
    assert state.service == "stopped" and state.ps == [], f"gateway left running: {state.service} {state.ps}"
    assert state.proxy_pid is None and state.daemon_pid is None, (state.proxy_pid, state.daemon_pid)
    assert not [s for s in state.listeners if s.command == "pfb-dns"], "the gateway still holds a socket"
    assert state.resolver == before.resolver, (
        f"Resolver keys after the toggle off:\n{state.resolver}\nbefore:\n{before.resolver}"
    )
    assert state.marker == "", f"pfb_dns_proxy_saved is not cleared: {state.marker!r}"
    _assert_no_python_module(state.conf, "toggle off")
    assert state.unbound_dns() == before.unbound_dns(), (
        f"Unbound sockets {sorted(state.unbound_dns())}, before the toggle {sorted(before.unbound_dns())}"
    )
    blocked, raw = _ask(gw.client, "udp", gw.names.ready)
    assert h.resolves_to(blocked, STUB_DNS_A), f"listed name through Unbound after the toggle off: {blocked}\n{raw}"
    allowed, raw = _ask(gw.client, "udp", h.unique_domain("restored"))
    assert h.resolves_to(allowed, STUB_DNS_A), f"allowed name through Unbound again: {allowed}\n{raw}"
    dot, raw = _ask(gw.client, "dot", gw.names.ready)
    assert h.resolves_to(dot, STUB_DNS_A), f"listed name over Unbound's own DoT after the toggle off: {dot}\n{raw}"


def test_a_listener_on_a_wildcard_socket_has_no_port() -> None:
    """sockstat lists an unbound UDP socket as `*:*`; asking for its port used to raise `int('*')`."""
    assert Listener("unbound", 1, "udp4", "*:*").port is None
    assert Listener("unbound", 1, "tcp4", "127.0.0.1:53").port == 53
    assert Listener("unbound", 1, "tcp6", "::1:5353").port == 5353


class _SockstatBox:
    """Stands in for the box: ``_listeners`` asks it for ``sockstat -46lw`` or ``-46w`` and nothing else."""

    def __init__(self, stdout: str, connected: str | None = None) -> None:
        self._listening = stdout
        self._all = stdout if connected is None else connected

    def ssh(self, *args: str, **kwargs: object) -> SimpleNamespace:
        command = " ".join(args)
        assert command in ("sockstat -46lw", "sockstat -46w"), command
        return SimpleNamespace(stdout=self._listening if command == "sockstat -46lw" else self._all)


def test_an_ipv6_local_address_in_brackets_reads_as_the_bare_form() -> None:
    """FreeBSD 16 writes an IPv6 local address as ``[::1]:53``; the listener carries ``::1:53``, the form IPv4 and the
    expected socket sets use."""
    sockstat = (
        "USER     COMMAND    PID   FD PROTO  LOCAL ADDRESS         FOREIGN ADDRESS\n"
        "unbound  unbound    9001  5  tcp6   [::1]:53              *:*\n"
        "unbound  unbound    9001  6  udp6   [::1]:53              *:*\n"
        "unbound  unbound    9001  7  tcp4   127.0.0.1:53         *:*\n"
        "root     sshd       9002  3  tcp4   *:22                  *:*\n"
    )
    listeners = _listeners(cast(SmokeVM, _SockstatBox(sockstat)))
    got = [(s.proto, s.local) for s in listeners]
    assert got == [("tcp6", "::1:53"), ("udp6", "::1:53"), ("tcp4", "127.0.0.1:53"), ("tcp4", "*:22")], got


def test_a_udp_listener_that_connected_to_its_first_sender_still_holds_its_port() -> None:
    """``nc -u -l`` connect()s to its first sender and ``sockstat -l`` then skips it; it still holds the port, so a
    holder check reads the connected sockets too."""
    header = "USER     COMMAND    PID   FD PROTO  LOCAL ADDRESS         FOREIGN ADDRESS\n"
    listening = header + "root     nc         14564 3  tcp4   127.0.0.1:5353        *:*\n"
    everything = listening + "root     nc         14868 3  udp4   127.0.0.1:5353        127.0.0.1:31701\n"
    box = cast(SmokeVM, _SockstatBox(listening, everything))
    held = ("udp4", "127.0.0.1:5353")

    assert held not in {(s.proto, s.local) for s in _listeners(box)}, "before: sockstat -l hides the connected socket"
    assert held in {(s.proto, s.local) for s in _listeners(box, connected=True)}


@pytest.mark.timeout(1500)
def test_managed_vips_exclude_all_custom_ports_and_ddr_uses_bound_standard_ports(
    gw: Gateway, gateway_on: State, gui: WebUI
) -> None:
    """Issue #3699: interfaces keep custom ports; managed IPv4/IPv6 VIPs use only live standard-port listeners."""
    vm, client = gw.vm, gw.client
    _ensure_ddr(gw, on=True)
    settings = {
        **LAN_ONLY_LISTS,
        "pfb_dns_doh_interface": "lan",
        "pfb_dns_doq_interface": "lan",
        "pfb_dns_dot_port": "1853",
        "pfb_dns_doh_port": "5443",
        "pfb_dns_doq_port": "2853",
        "pfb_dns_dot_port6": "1953",
        "pfb_dns_doh_port6": "5543",
        "pfb_dns_doq_port6": "2953",
    }
    prior = {key: h.config_get(vm, h.dns_config_path(key)) for key in settings}
    plain_prior = h.config_get(vm, "unbound/port")
    try:
        _set_lists(vm, settings)
        _php_ok(vm, "config_set_path('unbound/port', '1053'); write_config('smoke: custom plain port');", "plain port")
        _apply(vm)
        ordinary = _capture(vm)
        for transport, port in (("udp", 1053), ("tcp", 1053), ("dot", 1853), ("doh-post", 5443), ("doq", 2853)):
            answer, raw = _ask(client, transport, gw.names.ready, port=port)
            _say(f"ordinary {transport} at {PFSENSE_LAN_IP}:{port}\n{raw}")
            assert h.is_vip(answer), f"ordinary {transport} on {port}: expected DNSBL VIP, got {answer}\n{raw}"
        gui.post(
            DNS_GENERAL_PAGE,
            {
                "pfb_dns_listen_vip": "on",
                "pfb_dns_listen_vip4": "auto",
                "pfb_dns_listen_vip6": "auto",
                "pfb_dns_listen_interface": "lo0",
            },
        )
        vips = [h.config_get(vm, f"{h.CFG_GLOBAL}/pfb_dns_listen_auto{family}") for family in (4, 6)]
        assert all(vips), f"missing managed IPv4/IPv6 VIPs: {vips}"
        _apply(vm)
        live = _capture(vm)
        assert live.proxy_pid == ordinary.proxy_pid, (
            f"managed endpoints should reconcile live, gateway pid {ordinary.proxy_pid} -> {live.proxy_pid}"
        )
        sockets = live.proxy_sockets()
        _say(f"managed VIP standard-port sockets: {sorted(sockets)}")
        for family, vip in zip((4, 6), vips, strict=True):
            wanted = {
                (f"udp{family}", f"{vip}:53"),
                (f"tcp{family}", f"{vip}:53"),
                (f"tcp{family}", f"{vip}:853"),
                (f"tcp{family}", f"{vip}:443"),
                (f"udp{family}", f"{vip}:853"),
            }
            assert wanted <= sockets, f"managed IPv{family}: missing {sorted(wanted - sockets)}; got {sorted(sockets)}"
            custom = {1053, 1853, 5443, 2853, 1953, 5543, 2953}
            stray = {
                (proto, at)
                for proto, at in sockets
                if at.rsplit(":", 1)[0] == vip and int(at.rsplit(":", 1)[1]) in custom
            }
            assert not stray, f"managed IPv{family} still binds configured custom ports: {sorted(stray)}"
            source = "-6 -I::1" if family == 6 else "-I127.0.0.1"
            result = vm.ssh(f"drill -b1232 {source} {DDR_NAME} @{shlex.quote(vip)} SVCB 2>&1")
            reply = _parse_reply(result.stdout)
            _say(f"managed IPv{family} DDR at {vip}:53\n{reply.raw}")
            expected = _expected_svcb(DDR_TARGET, doh_443=True, address=vip)
            assert reply.rcode == "NOERROR" and _svcb_records(reply) == expected, (
                f"IPv{family} local DDR must advertise actual 53/853/443 listeners: expected {expected}, "
                f"got {_svcb_records(reply)}\n{reply.raw}"
            )
        ordinary_wanted = {
            ("udp4", f"{PFSENSE_LAN_IP}:1053"),
            ("tcp4", f"{PFSENSE_LAN_IP}:1053"),
            ("tcp4", f"{PFSENSE_LAN_IP}:1853"),
            ("tcp4", f"{PFSENSE_LAN_IP}:5443"),
            ("udp4", f"{PFSENSE_LAN_IP}:2853"),
        }
        assert ordinary_wanted <= sockets, (
            f"ordinary configured endpoints disappeared: {sorted(ordinary_wanted - sockets)}"
        )
        with _client_route(client, vips[0]):
            for transport, port in (("udp", 53), ("tcp", 53), ("dot", 853), ("doh-post", 443), ("doq", 853)):
                answer, raw = _ask(client, transport, gw.names.ready, server=vips[0], port=port)
                _say(f"managed {transport} at {vips[0]}:{port}\n{raw}")
                assert h.is_vip(answer), f"managed {transport} on {port}: expected DNSBL VIP, got {answer}\n{raw}"
                name = h.unique_domain("vip-endpoint")
                answer, raw = _ask(client, transport, name, server=vips[0], port=port)
                assert h.resolves_to(answer, STUB_DNS_A), raw
                _drain_logs(gw, port=1053)
                [row] = _reply_rows(vm, name)
                assert len(row) == 13 and row[7] == CLIENT_LAN_IP, row
                assert row[10:13] == [LOG_TRANSPORT[transport], vips[0], "Localhost"], row
                _assert_unified_row(vm, row, name, 6)
                _assert_report_row(gui, name, CLIENT_LAN_IP, LOG_TRANSPORT[transport], vips[0], "Localhost")
        with _client_v6(client), _client_route(client, vips[1]):
            for transport, port in (("udp", 53), ("tcp", 53), ("dot", 853), ("doh-post", 443), ("doq", 853)):
                name = h.unique_domain("vip-endpoint-v6")
                answer, raw = _ask(client, transport, name, server=vips[1], port=port)
                assert h.resolves_to(answer, STUB_DNS_A), raw
                _drain_logs(gw, port=1053)
                [row] = _reply_rows(vm, name)
                assert len(row) == 13 and row[7] == LAN_V6_CLIENT and row[8] == STUB_DNS_A, row
                assert row[10:13] == [LOG_TRANSPORT[transport], vips[1], "Localhost"], row
                _assert_unified_row(vm, row, name, 6)
                _assert_report_row(gui, name, LAN_V6_CLIENT, LOG_TRANSPORT[transport], vips[1], "Localhost")
        gui.post(
            DNS_GENERAL_PAGE,
            {
                "pfb_dns_listen_vip": "on",
                "pfb_dns_listen_vip_only": "on",
                "pfb_dns_listen_vip4": "auto",
                "pfb_dns_listen_vip6": "auto",
                "pfb_dns_listen_interface": "lo0",
            },
        )
        assert h.config_get(vm, f"{h.CFG_GLOBAL}/pfb_dns_listen_vip_only") == "on", (
            "VIP-only activation must be accepted before its listener behavior is tested"
        )
        _apply(vm)
        exclusive = _capture(vm)
        assert exclusive.proxy_pid == live.proxy_pid, "VIP-only address changes must reconcile without a restart"
        exclusive_sockets = exclusive.proxy_sockets()
        _say(f"VIP-only standard-port sockets: {sorted(exclusive_sockets)}")
        assert not (ordinary_wanted & exclusive_sockets), (
            f"VIP-only still binds ordinary interface endpoints: {sorted(ordinary_wanted & exclusive_sockets)}"
        )
        for family, vip in zip((4, 6), vips, strict=True):
            source = "-6 -I::1" if family == 6 else "-I127.0.0.1"
            result = vm.ssh(f"drill -b1232 {source} {DDR_NAME} @{shlex.quote(vip)} SVCB 2>&1")
            reply = _parse_reply(result.stdout)
            _say(f"VIP-only IPv{family} DDR at {vip}:53\n{reply.raw}")
            assert reply.rcode == "NOERROR" and _svcb_records(reply) == _expected_svcb(
                DDR_TARGET, doh_443=True, address=vip
            ), reply.raw
        for address, port in [(vips[0], 53), (vips[1], 53), ("127.0.0.1", 1053), ("::1", 1053)]:
            source = "-6 -I::1" if ":" in address else "-I127.0.0.1"
            for kind, expected_address in zip(("A", "AAAA"), vips, strict=True):
                result = vm.ssh(
                    f"drill -b1232 {source} -p {port} {shlex.quote(DDR_DNS_NAME)} @{shlex.quote(address)} {kind} 2>&1"
                )
                reply = _parse_reply(result.stdout)
                answers = [ipaddress.ip_address(r.rdata) for r in reply.answer if r.rtype == kind]
                _say(f"VIP-only {kind} at {address}:{port}\n{reply.raw}")
                assert reply.rcode == "NOERROR" and answers == [ipaddress.ip_address(expected_address)], (
                    f"VIP-only {kind}: expected only {expected_address}, got {answers}\n{reply.raw}"
                )
        with _client_route(client, vips[0]):
            for transport, port in (("udp", 53), ("tcp", 53), ("dot", 853), ("doh-post", 443), ("doq", 853)):
                answer, raw = _ask(client, transport, gw.names.ready, server=vips[0], port=port)
                _say(f"VIP-only managed {transport} at {vips[0]}:{port}\n{raw}")
                assert h.is_vip(answer), f"VIP-only {transport} failed: {answer}\n{raw}"
        status = gui.get(STATUS_PAGE)
        assert status.status_code == 200, status.text
        refreshed = gui.get(f"{STATUS_PAGE}?ajax=ddr")
        assert refreshed.status_code == 200, refreshed.text
        from .ui.test_sync_status_panels import panel

        # PR #3851: the page and its refresh both render the applied snapshot; no row waits for a per-address check
        for view, html in (("page", status.text), ("refresh", refreshed.json()["html"])):
            section = panel(html, "pfb-dns-status-ddr")
            assert section is not None, html
            table = re.search(r"<table\b.*?</table>", section, re.DOTALL)
            assert table, section
            rows = ET.fromstring(table.group()).findall("./tbody/tr")
            observations = {row.attrib["data-address"]: row for row in rows}
            assert "<pre" not in section and "Refresh DDR advertisements" not in section, section
            for vip in vips:
                endpoint = f"[{vip}]:53" if ":" in vip else f"{vip}:53"
                status_row = observations.get(endpoint)
                assert status_row is not None, f"DDR status ({view}) omitted {endpoint}: {observations}"
                _say(f"VIP-only DDR status ({view}) {endpoint}: {ET.tostring(status_row, encoding='unicode')}")
                assert status_row.attrib["data-state"] == "matched", ET.tostring(status_row, encoding="unicode")
        applied = re.search(r'<tr id="pfb-dns-status-name"><th>DNS Name</th><td>([^<]*)</td></tr>', status.text)
        assert applied and applied.group(1).rstrip(".").lower() == DDR_TARGET.rstrip(".").lower(), status.text
    finally:
        gui.post(
            DNS_GENERAL_PAGE,
            {
                "pfb_dns_listen_vip": "",
                "pfb_dns_listen_vip_only": "",
                "pfb_dns_listen_vip4": "none",
                "pfb_dns_listen_vip6": "none",
            },
        )
        _set_lists(vm, prior)
        _php_ok(
            vm,
            f"config_set_path('unbound/port', {h._php_str(plain_prior)}); write_config('smoke: restore plain port');",
            "restore plain port",
        )
        _apply(vm)
        cleanup = (
            h.config_get(vm, f"{h.CFG_GLOBAL}/pfb_dns_listen_vip_only"),
            h.config_get(vm, f"{h.CFG_GLOBAL}/pfb_dns_listen_vip"),
        )
        _say(f"managed-VIP cleanup mode/Resolver addresses: {cleanup!r}")
        assert cleanup == ("", ""), f"managed-VIP cleanup did not disable both settings: {cleanup!r}"
