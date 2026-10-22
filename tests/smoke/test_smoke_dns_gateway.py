"""Issue #3513, step 5: the Go DNS gateway in front of Unbound on a live pfSense, asked from a LAN client over every
transport.

The package ships the gateway as ``pfb-dns``, one raw FreeBSD binary per architecture under ``dns_proxy/bin/``, and
``pfb_dns.sh``, which runs the one for the machine; with the DNS Proxy toggle on, pfBlockerNG's rc script runs that
wrapper under daemon(8) with the Python decider as the gateway's child. This module installs nothing of its own for the
gateway, so a broken package cannot hide behind an uploaded binary: it asserts the INSTALLED package's payload, turns
DoH and DoQ on next to the toggle, and watches the box and the LAN client VM. Only the client's DoQ probe,
``pfb_doq_probe``, is built here, from ``go/``, with the Go that built the package (smoke-on-box.sh's, CI's, or, when
there is none, the pinned one scripts/go_toolchain.py installs in this module's scratch directory and deletes).

Module setup, put back in ``finally`` (``test_smoke_dns_proxy.py`` drives the same gateway through the toggle's
lifecycle: modes, restarts, boot, rollback, removal)::

    Resolver: DoT on with a self-signed certificate, ``log-queries: yes`` in Custom Options
    DNSBL:    one feed listing every name the tests expect to be blocked; DoH on 4443 and DoQ on 853 on the LAN

What it proves, in file order:

* package: both ``pfb-dns`` binaries are 0555 and byte-equal to the built ``.pkg``'s members, ``pfb_dns.sh`` is 0644
  (run as ``/bin/sh``), and the installed package's ABI is a wildcard (``NO_ARCH``);
* service: the daemon supervises ``pfb-dns``, the binary ``pfb_dns.sh`` chose for ``uname -p`` (the wrapper exec'd, so
  the pidfile's pid is the gateway's), which published that pid in ``/var/unbound/pfb_dns_ready``; its child is
  ``pfb_dns_proxy.py --decision-fd 3``, both as ``unbound``; ``dns_proxy.log`` has the ``listening`` lines and
  ``ready upstream 127.0.0.1:5353 pid N``, N the gateway's; the gateway owns every client-facing socket (DoH and DoQ on
  loopback too, for a local HAProxy) and Unbound listens on loopback 5353 and 5354 only;
* the pfB-DNS tab's status panel is one table per transport with a Localhost row (127.0.0.1 and [::1] at the transport's
  port) and a LAN row (the LAN address), each reading ``Listening`` for a screen reader (issue #3555);
* when Unbound stops under the live gateway (issue #3560), the status panel reads ``Starting`` and every table keeps its
  ``Listening`` rows; the Resolver is restored afterwards and an allowed name resolves again;
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
  over UDP and TCP; the client VM too, on every transport, where its IPv6 address reaches the firewall: the smoke
  pfSense's pf carries `block drop in log inet6 all` and no LAN pass rule, so there it does not and the diagnostics
  are logged);
* DDR (issue #3583), with ``dns/pfb_dns_ddr`` on and the gateway restarted with ``--ddr``: ``_dns.resolver.arpa. SVCB``
  over UDP and TCP gets the DoH, DoT and DoQ records for the LAN address (alpn, ``port`` only off its default,
  ``dohpath``, ``ipv4hint``, the firewall's FQDN as TargetName, its A record in Additional); another type or name under
  ``resolver.arpa.`` and the SVCB query over DoT and DoH get NODATA with the 300-second SOA, apex SOA and NS are
  answered, and Unbound's query log never names ``resolver.arpa``, so the decider saw none of it; a client the Resolver
  ACL refuses gets REFUSED; with the toggle off the client gets what Unbound itself answers, asked on the box at
  port 5354; with ``dns/pfb_dns_ddr_doh_443`` on the DoH record has no ``port`` and keeps its hint and path;
* ``rc stop`` ends the gateway, its decider and the supervisor; toggle off gives the Resolver back, no gateway left.

DESELECTED from the default ``python -m pytest``. Run it on the pool::

    scripts/local-smoke.sh --ref <branch or sha> --filter test_smoke_dns_gateway
"""

from __future__ import annotations

import contextlib
import hashlib
import ipaddress
import json
import os
import re
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
    CFG_PFB_DNS,
    DAEMON_PID_FILE,
    LAN_V6_ADDR,
    LAN_V6_ROW,
    MODULE_LINE,
    OBSERVER_SCRIPT,
    PROXY_PID_FILE,
    PROXY_RC,
    RESOLVER_LOG,
    SCRIPT_LINE,
    SNAPSHOT_PATHS,
    UPSTREAM_PORT,
    Listener,
    State,
    _apply,
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
    _set_proxy_toggle,
    _sh,
    _unbound_conf_report,
    _wait_dnsbl_row,
    _wait_unbound_logged,
)
from .ui.credgate import admin_password_decision
from .ui.webui import WebUI

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
SNAPSHOT_FILE = "/tmp/pfb3513_cfg_snapshot.json"  # on the guest: survives a dead test process

LISTENER_SETTINGS = {
    "pfb_dns_doh": "on",
    "pfb_dns_doh_port": str(DOH_PORT),
    "pfb_dns_doh_interface": "lan",
    "pfb_dns_doq": "on",
    "pfb_dns_doq_port": str(DOQ_PORT),
    "pfb_dns_doq_interface": "lan",
}
CFG_DDR = f"{CFG_PFB_DNS}/pfb_dns_ddr"  # issue #3583: the DDR toggle and the DoH-on-port-443 toggle
CFG_DDR_DOH_443 = f"{CFG_PFB_DNS}/pfb_dns_ddr_doh_443"
# SNAPSHOT_PATHS already holds the interface lists, which LISTENER_SETTINGS names again
CONFIG_PATHS = tuple(
    dict.fromkeys(
        (
            *SNAPSHOT_PATHS,
            *(f"{CFG_PFB_DNS}/{key}" for key in LISTENER_SETTINGS),
            "unbound/acls",
            AUTO_ROWS_OFF,
            CFG_DDR,
            CFG_DDR_DOH_443,
        )
    )
)

TRANSPORTS = ("udp", "tcp", "dot", "doh-post", "doh-get", "doq")
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
    before: State  # the Resolver as pfBlockerNG leaves it with DNSBL on and the toggle off


# --------------------------------------------------------------------------- #
# The DoQ probe for the client VM, built on the box where pytest runs
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class GoToolchain:
    go: Path
    env: dict[str, str]


@pytest.fixture(scope="module")
def go_toolchain(tmp_path_factory: pytest.TempPathFactory) -> Iterator[GoToolchain]:
    """The Go that built the package, reused: the `go` on PATH (smoke-on-box.sh's pinned one, or CI's setup-go).

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
    client: SmokeVM, name: str, ca: str | None = CERT_CLIENT, server: str = PFSENSE_LAN_IP
) -> tuple[h.DnsAnswer, str]:
    """pfb_doq_probe from the client; its stdout is `rcode X` then `answer <name> <type> <rdata>` lines."""
    args = [PROBE_BIN, "-server", _host_port(server, DOQ_PORT), "-name", name, "-sni", CERT_NAME, "-timeout", "5s"]
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
    client: SmokeVM, transport: str, name: str, *, source: str | None = None, server: str = PFSENSE_LAN_IP
) -> tuple[h.DnsAnswer, str]:
    """The parsed answer and the tool's full output; no answer reads as rcode UNKNOWN with the tool's complaint."""
    if transport == "doq":
        return _ask_doq(client, name, server=server)
    options, port = DIG_TRANSPORTS[transport]
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
    """DoH and DoQ on, on the LAN, as the pfB-DNS tab's seven settings store them."""
    assignments = "".join(f"$d[{h._php_str(k)}] = {h._php_str(v)};\n" for k, v in LISTENER_SETTINGS.items())
    _php_ok(
        vm,
        f"$d = config_get_path({h._php_str(CFG_PFB_DNS)}, array());\n{assignments}"
        f"config_set_path({h._php_str(CFG_PFB_DNS)}, $d);\n"
        "write_config('pfBlockerNG smoke: pfB-DNS DoH and DoQ for the #3513 gateway smoke');",
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


def _v6_diagnostics(gw: Gateway) -> str:
    """Why the client VM may not reach the firewall's LAN IPv6 address: ping, neighbours and routes, the IPv6 rules."""
    client = gw.client.ssh(
        f"ping -6 -c 2 -W 3 -I {LAN_V6_CLIENT} {LAN_V6_ADDR} 2>&1; ip -6 neigh show; ip -6 route show"
    ).stdout
    firewall = gw.vm.ssh("ndp -an | grep 2001:db8; pfctl -sr 2>&1 | grep inet6 | head -20").stdout
    return f"client VM:\n{client}\nfirewall:\n{firewall}"


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
    feed_url = h.write_local_feed(vm, "smoke_3513_dns_gateway.txt", "".join(f"{name}\n" for name in names.listed()))
    _snapshot(vm)
    lan_v6_prior: dict[str, str] | None = None
    try:
        lan_v6_prior = h.set_interface_ipv6(vm, h.IPV6_LOCAL_IFACE, LAN_V6_ADDR, h.IPV6_LOCAL_BITS)
        refid = _create_cert(vm)
        pem = _sh(vm, f"cat {CERT_GUEST}").stdout
        trusted = subprocess.run(
            client_vm.ssh_argv("tee", CERT_CLIENT), input=pem, capture_output=True, text=True, timeout=30, check=False
        )
        assert trusted.returncode == 0, f"copying the certificate to the client failed: {trusted.stderr!r}"
        _configure_resolver(vm, refid)
        h.inject(vm, h.DnsblCase(aliasname=FEED_HEADER, feed_url=feed_url, header=FEED_HEADER, mode=h.DnsblMode.VIP))
        _set_listeners(vm)
        _upload(client_vm, probe_binary, PROBE_BIN, "root:root")  # the gateway itself is the package's, never uploaded
        _apply(vm)  # toggle off: pfBlockerNG's own wiring, the module inside Unbound
        yield Gateway(vm, client_vm, names, _capture(vm))
    finally:
        try:
            _force_stop_proxy(vm)
            _sh(vm, f"pkill -KILL -f '{PACKAGE_DIR}/bin/freebsd-[a-z0-9]*/pfb-dn[s]'\nrm -f {READY_FILE}\n")
        finally:
            _say("gateway log:\n" + _proxy_log(vm, 80))
            try:
                _restore(vm)
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


def test_the_daemon_supervises_the_gateway_and_the_gateway_runs_the_python_decider(
    gw: Gateway, gateway_on: State
) -> None:
    """The service is the Go gateway, not the Python listener: supervisor, gateway and decider, all as they should be.

    Then Status > Services says `pfb_dns_proxy` runs; the supervisor's ps title is `daemon: pfb_dns_proxy[<child pid>]`;
      the child (the pidfile's pid) is the pfb-dns `pfb_dns.sh` chose for this machine, as `unbound`; its only child is
      the decider
      `pfb_dns_proxy.py --decision-fd 3`, also `unbound`; no process runs the Python listener; dns_proxy.log has a
      `listening` line per transport and `ready upstream 127.0.0.1:5353 pid <gateway>` after them.
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
    deciders = [p for p in procs if p.ppid == state.proxy_pid]
    assert len(deciders) == 1, f"the gateway's children: {deciders}"
    assert "pfb_dns_proxy.py" in deciders[0].args and "--decision-fd 3" in deciders[0].args, deciders[0]
    assert deciders[0].user == "unbound", f"the decider should have dropped root to unbound: {deciders[0]}"
    listeners = [
        p for p in procs if "pfb_dns_proxy.py" in p.args and "--decision-fd" not in p.args and "daemon:" not in p.args
    ]
    assert not listeners, f"a Python listener runs next to the gateway: {listeners}"

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


STATUS_PAGE = "/pfblockerng/pfblockerng_dns.php"


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
    """The rows of one transport's table in the pfB-DNS tab's status panel, as (interface, one address per line, what a
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
    Then each table has a Localhost row that is exactly 127.0.0.1 and [::1] at the transport's port and a LAN row that
      holds the LAN address at it, both reading `Listening` for a screen reader.
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
        assert loopback == [("Localhost", [f"127.0.0.1:{port}", f"[::1]:{port}"], "Listening")], (
            f"{transport}: the Localhost row is {loopback}; all rows: {rows}"
        )
        lan = [row for row in rows if row[0] == "LAN" and f"{PFSENSE_LAN_IP}:{port}" in row[1]]
        assert lan and all(state == "Listening" for _, _, state in lan), (
            f"{transport}: no LAN row listening on {PFSENSE_LAN_IP}:{port}; all rows: {rows}"
        )


@pytest.mark.timeout(900)
def test_the_status_panel_keeps_live_gateway_bindings_when_the_upstream_stops(
    gw: Gateway, gateway_on: State, gui: WebUI
) -> None:
    """issue #3560: Unbound stopping under a live gateway reads Starting; the gateway's rows stay Listening.

    Given the gateway serves every transport: its pid is the ready file's, it owns the LAN front sockets, the proxy is
      ready, and the status panel reads Running with all four tables Listening,
    When `unbound-control stop` ends the Unbound behind it while the gateway keeps its pid, ready file and sockets,
    Then the panel reads Starting and each table keeps the same rows as before, each reading `Listening`.
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
        assert service_of(down_page) == "Starting", f"backend down: the service reads {service_of(down_page)!r}"
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
    """The gateway does not change what Unbound loads: the observer while forwarding, never pfb_unbound.py.

    Given the Resolver forwards to the System DNS server and the gateway serves,
    Then unbound.conf's only `python-script` is `pfb_upstream_observer.py` (the module is in the chain) and
      `pfb_unbound.py` is not named; the observer is staged in the chroot beside the shipped module.
    """
    scripts = re.findall(r"^\s*python-script\s*:\s*(\S+)", gateway_on.conf, re.MULTILINE)
    assert scripts == [OBSERVER_SCRIPT], f"python-script lines: {scripts}\n{gateway_on.conf}"
    assert MODULE_LINE.search(gateway_on.conf), f"the python module is not in the module chain:\n{gateway_on.conf}"
    assert "pfb_unbound.py" not in gateway_on.conf, gateway_on.conf
    staged = gw.vm.ssh(f"ls -l /var/unbound/{OBSERVER_SCRIPT} /var/unbound/pfb_unbound.py 2>&1").stdout
    assert OBSERVER_SCRIPT in staged and "No such file" not in staged, f"staged files: {staged}"


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


# --------------------------------------------------------------------------- #
# From the LAN client, over every transport
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("transport", TRANSPORTS)
def test_a_listed_name_gets_the_vip_and_a_log_row_naming_the_client(
    gw: Gateway, gateway_on: State, transport: str
) -> None:
    """A listed name is answered by the gateway's decider: the VIP and a dnsbl.log row for the LAN client.

    When the LAN client asks over UDP, TCP, DoT, DoH (POST and GET) or DoQ,
    Then it gets the DNSBL VIP and dnsbl.log has a row for the name that names 192.168.1.10.
    """
    name = gw.names.blocked[transport]
    answer, raw = _ask(gw.client, transport, name)
    _say(f"listed name, {transport}: {answer.rcode} {answer.records}")
    assert h.is_vip(answer), f"{transport} {name}: expected VIP {h.DEFAULT_DNSBL_VIP4}, got {answer}\n{raw}"
    _wait_dnsbl_row(gw.vm, name)
    clients = {row[3] for row in _dnsbl_rows(gw.vm, name)}
    assert clients == {CLIENT_LAN_IP}, (
        f"{transport}: dnsbl.log client for {name}: expected {CLIENT_LAN_IP}, got {clients}"
    )


@pytest.mark.parametrize("transport", TRANSPORTS)
def test_an_allowed_name_is_answered_by_the_upstream_and_unbound_logs_the_client(
    gw: Gateway, gateway_on: State, transport: str
) -> None:
    """An allowed name goes to Unbound behind a PROXYv2 header naming the LAN client, whatever the transport.

    When the LAN client asks for a name no feed lists over UDP, TCP, DoT, DoH (POST and GET) or DoQ,
    Then the reply is the upstream stub's answer, and `resolver.log` names 192.168.1.10, never 127.0.0.1.
    """
    name = h.unique_domain(f"allowed-{transport}")
    answer, raw = _ask(gw.client, transport, name)
    _say(f"allowed name, {transport}: {answer.rcode} {answer.records}")
    _assert_answered_by_upstream(gw, name, answer, raw, transport)


# --------------------------------------------------------------------------- #
# Hostile clients
# --------------------------------------------------------------------------- #


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
      the client VM on every transport when its IPv6 address reaches the firewall (this smoke pfSense's pf blocks IPv6
      from the LAN: `block drop in log inet6 all` and no LAN pass rule, neighbour discovery works; the diagnostics
      are logged then);
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
                for transport in ("udp", "tcp")
            }
            vm_reaches = not all(_no_answer(answer) for answer, _ in via_vm.values())
            if vm_reaches:
                for transport in TRANSPORTS[2:]:
                    via_vm[transport] = _ask(
                        gw.client, transport, names.v6[transport], source=LAN_V6_CLIENT, server=LAN_V6_ADDR
                    )
                _expect_everywhere("IPv6 LAN client, the client VM", via_vm, h.is_vip, "the VIP")
            else:
                _say(
                    f"the client VM reaches nothing on {LAN_V6_ADDR}; no IPv6 client is asked from it:\n"
                    + _v6_diagnostics(gw)
                )
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
        if vm_reaches:
            assert logged_clients(list(names.v6.values())) == {ipaddress.ip_address(LAN_V6_CLIENT)}, "dnsbl.log: the VM"
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


def _expected_svcb(fqdn: str, *, doh_443: bool = False) -> list[Svcb]:
    """The records a LAN query gets: DoH, DoT and DoQ, each with the LAN hint; `doh_443` leaves the DoH port out."""
    hint = {"ipv4hint": PFSENSE_LAN_IP}
    doh_port = {} if doh_443 else _port(DOH_PORT, 443)
    return [
        Svcb(1, fqdn, {"alpn": "h2", **doh_port, "dohpath": "/dns-query{?dns}", **hint}),
        Svcb(2, fqdn, {"alpn": "dot", **_port(DOT_PORT, 853), **hint}),
        Svcb(3, fqdn, {"alpn": "doq", **_port(DOQ_PORT, 853), **hint}),
    ]


def _firewall_fqdn(vm: SmokeVM) -> str:
    """`system/hostname` + `.` + `system/domain` + `.`: the TargetName the gateway is given, from the box's config."""
    return f"{h.config_get(vm, 'system/hostname')}.{h.config_get(vm, 'system/domain')}.".lower()


def _rows(section: tuple[Record, ...]) -> list[tuple[str, int, str, str]]:
    return [(r.owner.lower(), r.ttl, r.rtype, r.rdata.lower()) for r in section]


def _gateway_ddr_flags(vm: SmokeVM) -> tuple[bool, bool] | None:
    """(`--ddr` and `--ddr-doh-443` are on the running gateway's command line); None: no gateway runs."""
    pid = _pid_file(vm, PROXY_PID_FILE)
    gateway = next((p for p in _processes(vm) if p.pid == pid), None)
    if gateway is None:
        return None
    args = gateway.args.split()
    return "--ddr" in args, "--ddr-doh-443" in args


def _set_ddr(vm: SmokeVM, on: bool, doh_443: bool) -> None:
    """The pfB-DNS tab's two DDR toggles as its Save stores them: 'on' or the empty Off token."""
    _php_ok(
        vm,
        f"$d = config_get_path({h._php_str(CFG_PFB_DNS)}, array());\n"
        f"$d['pfb_dns_ddr'] = {h._php_str('on' if on else '')};\n"
        f"$d['pfb_dns_ddr_doh_443'] = {h._php_str('on' if doh_443 else '')};\n"
        f"config_set_path({h._php_str(CFG_PFB_DNS)}, $d);\n"
        "write_config('pfBlockerNG smoke: pfB-DNS DDR for the #3583 gateway smoke');",
        "DDR settings",
    )


def _ensure_ddr(gw: Gateway, *, on: bool, doh_443: bool = False) -> None:
    """Have the gateway run with `--ddr` (and `--ddr-doh-443`) as asked, then serve: store and apply if it does not.

    A gateway that never took the flags fails the first assertion of the test with its command line and log, not a
    later query. The module's snapshot puts the two settings back with the rest of its config.
    """
    vm, want = gw.vm, (on, doh_443)
    if _gateway_ddr_flags(vm) != want:
        _set_ddr(vm, on, doh_443)
        _apply(vm)
        # Not raised here: the assertion below says what the gateway runs and logged.
        with contextlib.suppress(RuntimeError):
            h.wait_until(lambda: _gateway_ddr_flags(vm) == want, timeout=60.0, interval=2.0)
    seen = _gateway_ddr_flags(vm)
    stored = (h.config_get(vm, CFG_DDR), h.config_get(vm, CFG_DDR_DOH_443))
    assert seen == want, (
        f"after the apply the gateway should run with (--ddr, --ddr-doh-443) = {want}, runs with {seen}; stored "
        f"(dns/pfb_dns_ddr, dns/pfb_dns_ddr_doh_443) = {stored}\n{_proxy_log(vm, 30)}"
    )

    def serves() -> bool:
        return h.is_vip(_ask(gw.client, "udp", gw.names.ready)[0])

    try:
        h.wait_until(serves, timeout=240.0, interval=3.0)
    except RuntimeError as exc:
        raise RuntimeError(f"{exc}\n{_diagnostics(vm)}") from exc


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
      (`alpn=doq`, `port` only off 853), each with TargetName the firewall's `hostname.domain.`, `ipv4hint` the LAN
      address and TTL 300, and the Additional section holds that name's A record, the LAN address, TTL 300.
    """
    _ensure_ddr(gw, on=True)
    fqdn = _firewall_fqdn(gw.vm)
    reply = _dig(gw.client, transport, "SVCB", DDR_NAME)
    _say(f"DDR SVCB over {transport}: {reply.rcode} {sorted(reply.flags)} {_rows(reply.answer)}")
    assert reply.rcode == "NOERROR" and "aa" in reply.flags, (
        f"{transport}: expected NOERROR with the aa flag, got {reply.rcode} {sorted(reply.flags)}\n{reply.raw}"
    )
    assert _svcb_records(reply) == _expected_svcb(fqdn), (
        f"{transport}: SVCB records expected {_expected_svcb(fqdn)}, got {_svcb_records(reply)}\n{reply.raw}"
    )
    assert {(r.owner.lower(), r.ttl) for r in reply.answer} == {(f"{DDR_NAME}.", 300)}, (
        f"{transport}: every answer should be owned by {DDR_NAME}. with TTL 300, got {_rows(reply.answer)}"
    )
    addresses = [row for row in _rows(reply.additional) if row[2] in ("A", "AAAA")]
    assert addresses == [(fqdn, 300, "A", PFSENSE_LAN_IP)], (
        f"{transport}: Additional should hold only {(fqdn, 300, 'A', PFSENSE_LAN_IP)}, got {addresses}\n{reply.raw}"
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
    """Criterion 2, "the decider saw none": Unbound's query log gains no line for any DDR-answered query.

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
    """Criterion 9 (revised): with `dns/pfb_dns_ddr_doh_443` on, the DoH record has no `port`, whatever DoH listens on.

    Given DoH listens on 4443 and the gateway runs with `--ddr`, whose DoH record carries `port=4443`
      (the before-state: the toggle is what removes it),
    When `dns/pfb_dns_ddr_doh_443` is turned on and applied, so that the gateway runs with `--ddr --ddr-doh-443`,
    Then the DoH record has no `port` but the same TargetName (the firewall's `hostname.domain.`), `ipv4hint` (the LAN
      address) and `dohpath=/dns-query{?dns}`; DoT and DoQ are as before; Additional holds the firewall's A record.
    """
    _ensure_ddr(gw, on=True)
    fqdn = _firewall_fqdn(gw.vm)
    before = _dig(gw.client, "udp", "SVCB", DDR_NAME)
    assert _svcb_records(before) == _expected_svcb(fqdn), (
        f"premise: without the toggle the DoH record carries port {DOH_PORT}: expected {_expected_svcb(fqdn)}, got "
        f"{_svcb_records(before)}\n{before.raw}"
    )
    _ensure_ddr(gw, on=True, doh_443=True)
    reply = _dig(gw.client, "udp", "SVCB", DDR_NAME)
    expected = _expected_svcb(fqdn, doh_443=True)
    assert reply.rcode == "NOERROR" and _svcb_records(reply) == expected, (
        f"expected NOERROR and {expected}, got {reply.rcode} {_svcb_records(reply)}\n{reply.raw}"
    )
    addresses = [row for row in _rows(reply.additional) if row[2] in ("A", "AAAA")]
    assert addresses == [(fqdn, 300, "A", PFSENSE_LAN_IP)], (
        f"Additional should hold only the firewall's {(fqdn, 300, 'A', PFSENSE_LAN_IP)}, got {addresses}\n{reply.raw}"
    )


# --------------------------------------------------------------------------- #
# Stop and toggle off
# --------------------------------------------------------------------------- #


def test_rc_stop_ends_the_gateway_the_decider_and_the_supervisor(gw: Gateway, gateway_on: State) -> None:
    """`pfb_dns_proxy.sh stop` waits for the whole tree to go: no process, no pidfile, service stopped.

    Given the gateway, its decider and the supervisor running,
    When the rc script stops them,
    Then it exits 0 (its own wait ended with all of them gone), none of the three pids is alive, both pidfiles are
      gone and Status > Services says stopped.
    """
    state, vm = gateway_on, gw.vm
    tree = {state.daemon_pid, state.proxy_pid} | {p.pid for p in _processes(vm) if p.ppid == state.proxy_pid}
    assert None not in tree and len(tree) == 3, f"supervisor, gateway and decider pids: {tree}"
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
    Then no gateway, decider or supervisor runs and no pidfile is left; every Resolver key equals its pre-toggle value;
      the marker is cleared; unbound.conf has the python module again; Unbound listens where it did before the toggle;
      And the client's blocked, allowed and DoT queries work against Unbound again.
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
    assert MODULE_LINE.search(state.conf) and SCRIPT_LINE.search(state.conf), f"module not back:\n{state.conf}"
    assert state.unbound_dns() == before.unbound_dns(), (
        f"Unbound sockets {sorted(state.unbound_dns())}, before the toggle {sorted(before.unbound_dns())}"
    )
    blocked, raw = _ask(gw.client, "udp", gw.names.ready)
    assert h.is_vip(blocked), f"blocked name through Unbound again: {blocked}\n{raw}"
    allowed, raw = _ask(gw.client, "udp", h.unique_domain("restored"))
    assert h.resolves_to(allowed, STUB_DNS_A), f"allowed name through Unbound again: {allowed}\n{raw}"
    dot, raw = _ask(gw.client, "dot", gw.names.ready)
    assert h.is_vip(dot), f"blocked name over Unbound's own DoT again: {dot}\n{raw}"


def test_a_listener_on_a_wildcard_socket_has_no_port() -> None:
    """sockstat lists an unbound UDP socket as `*:*`; asking for its port used to raise `int('*')`."""
    assert Listener("unbound", 1, "udp4", "*:*").port is None
    assert Listener("unbound", 1, "tcp4", "127.0.0.1:53").port == 53
    assert Listener("unbound", 1, "tcp6", "::1:5353").port == 5353


class _SockstatBox:
    """Stands in for the box: ``_listeners`` asks it for ``sockstat -46lw`` and nothing else."""

    def __init__(self, stdout: str) -> None:
        self._stdout = stdout

    def ssh(self, *args: str, **kwargs: object) -> SimpleNamespace:
        return SimpleNamespace(stdout=self._stdout)


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
