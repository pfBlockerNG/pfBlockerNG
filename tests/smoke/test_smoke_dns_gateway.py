"""Issue #3513, step 5: the Go DNS gateway in front of Unbound on a live pfSense, asked from a LAN client over every
transport.

With the DNS Proxy toggle on and ``pfb_dns_gateway`` installed, pfBlockerNG's rc script runs the gateway under
daemon(8) with the Python decider as its child. This module builds the gateway from ``go/`` on the box (a pinned,
sha256-verified Go toolchain in the run's own scratch directory, deleted afterwards), installs it where the rc script
looks for it, turns DoH and DoQ on next to the toggle, and watches the box and the LAN client VM. The client reaches
DoQ with ``pfb_doq_probe``, built from the same module.

Module setup, put back in ``finally`` (the gateway binary is removed, so ``test_smoke_dns_proxy.py`` sees the Python
fallback)::

    Resolver: DoT on with a self-signed certificate, ``log-queries: yes`` in Custom Options
    DNSBL:    one feed listing every name the tests expect to be blocked; DoH on 4443 and DoQ on 853 on the LAN

What it proves, in file order:

* service: the daemon supervises ``pfb_dns_gateway``, whose child is ``pfb_dns_proxy.py --decision-fd 3``, both as
  ``unbound``; ``dns_proxy.log`` has the ``listening`` lines and ``ready upstream 127.0.0.1:5353``; the gateway owns
  every client-facing socket (DoH and DoQ on loopback too, for a local HAProxy) and Unbound listens on loopback 5353
  and 5354 only;
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
  pfBlockerNG's marked clause in unbound.conf grants still gets the VIP on every transport;
* ``rc stop`` ends the gateway, its decider and the supervisor; toggle off gives the Resolver back, no gateway left.

DESELECTED from the default ``python -m pytest``. Run it on the pool::

    scripts/local-smoke.sh --ref issue/3513-go-connectivity-layer --filter test_smoke_dns_gateway
"""

from __future__ import annotations

import contextlib
import hashlib
import ipaddress
import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import tarfile
import urllib.request
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from . import helpers as h
from .conftest import CLIENT_LAN_IP, PFSENSE_LAN_IP, STUB_DNS_A, SmokeVM, _StubDnsServer
from .test_smoke_dns_proxy import (
    ACCESS_LISTS,
    CERT_CLIENT,
    CERT_GUEST,
    CERT_NAME,
    DAEMON_PID_FILE,
    LAN_V6_ADDR,
    LAN_V6_ROW,
    MODULE_LINE,
    OBSERVER_SCRIPT,
    PROXY_PID_FILE,
    PROXY_RC,
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

pytestmark = [pytest.mark.smoke, pytest.mark.timeout(180)]

# The pinned toolchain: https://go.dev/dl/?mode=json&include=all lists this archive with this digest.
GO_VERSION = "go1.27.0"
GO_ARCHIVE = f"{GO_VERSION}.linux-amd64.tar.gz"
GO_URL = f"https://go.dev/dl/{GO_ARCHIVE}"
GO_SHA256 = "675c26c449cbb18fc24b74650de1eabbae6e16f64326fd85a283fb3b58280685"
GO_DIR = Path(__file__).resolve().parents[2] / "go" / "pfb_dns_gateway"
GOARCH_OF_UNAME = {"amd64": "amd64", "x86_64": "amd64", "arm64": "arm64", "aarch64": "arm64"}

GATEWAY_BIN = "/usr/local/pkg/pfblockerng/dns_proxy/pfb_dns_gateway"  # where the rc script looks for it
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

CFG_DNSBL = h.CFG_DNSBL_SETTINGS
LISTENER_SETTINGS = {
    "pfb_dns_proxy_doh": "on",
    "pfb_dns_proxy_doh_port": str(DOH_PORT),
    "pfb_dns_proxy_doh_interface": "lan",
    "pfb_dns_proxy_doq": "on",
    "pfb_dns_proxy_doq_port": str(DOQ_PORT),
    "pfb_dns_proxy_doq_interface": "lan",
}
CONFIG_PATHS = (*SNAPSHOT_PATHS, *(f"{CFG_DNSBL}/{key}" for key in LISTENER_SETTINGS), "unbound/acls", AUTO_ROWS_OFF)

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


@dataclass(frozen=True)
class Binaries:
    gateway: Path
    probe: Path


# --------------------------------------------------------------------------- #
# The toolchain and the binaries, built on the box where pytest runs
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class GoToolchain:
    go: Path
    env: dict[str, str]


def _download_go(dest: Path) -> None:
    """Fetch the pinned archive; nothing is extracted unless its sha256 is the pinned one."""
    digest = hashlib.sha256()
    with urllib.request.urlopen(GO_URL, timeout=120) as response, dest.open("wb") as out:
        while chunk := response.read(1 << 20):
            digest.update(chunk)
            out.write(chunk)
    if digest.hexdigest() != GO_SHA256:
        raise RuntimeError(f"{GO_URL}: sha256 expected {GO_SHA256}, got {digest.hexdigest()}")


@pytest.fixture(scope="module")
def go_toolchain(tmp_path_factory: pytest.TempPathFactory) -> Iterator[GoToolchain]:
    """The pinned Go in this run's scratch directory; every cache lives beside it and all of it is deleted after."""
    if platform.machine() not in ("x86_64", "AMD64"):
        raise RuntimeError(f"the pinned toolchain is {GO_ARCHIVE}; this box is {platform.machine()}")
    root = tmp_path_factory.mktemp("go-toolchain")
    try:
        archive = root / GO_ARCHIVE
        _download_go(archive)
        with tarfile.open(archive) as tar:
            tar.extractall(root, filter="data")
        archive.unlink()
        goroot = root / "go"
        env = {
            **os.environ,
            "GOROOT": str(goroot),
            "PATH": f"{goroot / 'bin'}{os.pathsep}{os.environ['PATH']}",
            "GOPATH": str(root / "gopath"),
            "GOCACHE": str(root / "gocache"),
            "GOMODCACHE": str(root / "gomodcache"),
            "GOTMPDIR": str(root / "gotmp"),
            "GOTOOLCHAIN": "local",
            "GOENV": "off",
            "GOFLAGS": "-modcacherw",  # a read-only module cache would defeat the delete below
            "HOME": str(root / "home"),  # keeps go's telemetry counters out of the real home
            "XDG_CONFIG_HOME": str(root / "config"),
            "XDG_CACHE_HOME": str(root / "cache"),
            "CGO_ENABLED": "0",
        }
        for key in ("GOPATH", "GOCACHE", "GOMODCACHE", "GOTMPDIR", "HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME"):
            Path(env[key]).mkdir()
        go = goroot / "bin" / "go"
        version = subprocess.run([str(go), "version"], env=env, capture_output=True, text=True, timeout=60, check=False)
        if GO_VERSION not in version.stdout:
            raise RuntimeError(f"expected {GO_VERSION}, `go version` says {version.stdout!r} {version.stderr!r}")
        _say(f"toolchain: {version.stdout.strip()}")
        yield GoToolchain(go, env)
    finally:
        shutil.rmtree(root, ignore_errors=True)
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
def binaries(
    go_toolchain: GoToolchain, smoke_vm: SmokeVM, client_vm: SmokeVM, tmp_path_factory: pytest.TempPathFactory
) -> Binaries:
    """The gateway for the pfSense VM's architecture (FreeBSD) and the DoQ probe for the client VM's (Linux)."""
    out = tmp_path_factory.mktemp("go-binaries")
    gateway_arch, probe_arch = _goarch(smoke_vm, "pfSense VM"), _goarch(client_vm, "client VM")
    gateway, probe = out / "pfb_dns_gateway", out / "pfb_doq_probe"
    _go_build(go_toolchain, ".", "freebsd", gateway_arch, gateway)
    _go_build(go_toolchain, "./cmd/pfb_doq_probe", "linux", probe_arch, probe)
    _say(
        f"binary sizes: pfb_dns_gateway freebsd/{gateway_arch} {gateway.stat().st_size} bytes, "
        f"pfb_doq_probe linux/{probe_arch} {probe.stat().st_size} bytes"
    )
    return Binaries(gateway, probe)


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
    """DoH and DoQ on, on the LAN, as the DNSBL page's seven settings store them."""
    assignments = "".join(f"$d[{h._php_str(k)}] = {h._php_str(v)};\n" for k, v in LISTENER_SETTINGS.items())
    _php_ok(
        vm,
        f"$d = config_get_path({h._php_str(CFG_DNSBL)}, array());\n{assignments}"
        f"config_set_path({h._php_str(CFG_DNSBL)}, $d);\n"
        "write_config('pfBlockerNG smoke: DNS proxy DoH and DoQ for the #3513 gateway smoke');",
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
    except RuntimeError:
        raise AssertionError(f"UDP never gave {expected}; last answer {last}\n{_proxy_log(gw.vm)}") from None
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
def gw(smoke_vm: SmokeVM, client_vm: SmokeVM, stub_dns: _StubDnsServer, binaries: Binaries) -> Iterator[Gateway]:
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
        _upload(vm, binaries.gateway, GATEWAY_BIN, "root:wheel")  # before the first apply writes the rc script
        _upload(client_vm, binaries.probe, PROBE_BIN, "root:root")
        _apply(vm)  # toggle off: pfBlockerNG's own wiring, the module inside Unbound
        yield Gateway(vm, client_vm, names, _capture(vm))
    finally:
        try:
            _force_stop_proxy(vm)
            _sh(vm, f"pkill -KILL -f 'pfb_dns_gatewa[y]'\nrm -f {GATEWAY_BIN}\n")
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


def test_the_daemon_supervises_the_gateway_and_the_gateway_runs_the_python_decider(
    gw: Gateway, gateway_on: State
) -> None:
    """The service is the Go gateway, not the Python listener: supervisor, gateway and decider, all as they should be.

    Then Status > Services says `pfb_dns_proxy` runs; the supervisor's ps title is `daemon: pfb_dns_proxy[<child pid>]`;
      the child (the pidfile's pid) is `pfb_dns_gateway` as `unbound`; its only child is the decider
      `pfb_dns_proxy.py --decision-fd 3`, also `unbound`; no process runs the Python listener; dns_proxy.log has a
      `listening` line per transport and `ready upstream 127.0.0.1:5353` after them.
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
    assert gateway and gateway.args.startswith(GATEWAY_BIN), f"the pidfile's process is not the gateway: {gateway}"
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
    readies = [i for i, line in enumerate(log) if line.endswith(f"ready upstream 127.0.0.1:{UPSTREAM_PORT}")]
    assert readies, f"no `ready upstream 127.0.0.1:{UPSTREAM_PORT}` line in dns_proxy.log:\n" + "\n".join(log)
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


# --------------------------------------------------------------------------- #
# Unbound as the gateway's upstream: the observer, upstream EDE blocks, the firewall itself
# --------------------------------------------------------------------------- #


def test_unbound_runs_the_upstream_observer_never_the_module_in_gateway_mode(gw: Gateway, gateway_on: State) -> None:
    """The gateway does not change what Unbound loads: the observer while forwarding, never pfb_unbound.py.

    Given the Resolver forwards to the System DNS server and the gateway serves,
    Then unbound.conf's only `python-script` is `pfb_upstream_observer.py` (the module is in the chain) and
      `pfb_unbound.py` is not named.
    """
    scripts = re.findall(r"^\s*python-script\s*:\s*(\S+)", gateway_on.conf, re.MULTILINE)
    assert scripts == [OBSERVER_SCRIPT], f"python-script lines: {scripts}\n{gateway_on.conf}"
    assert MODULE_LINE.search(gateway_on.conf), f"the python module is not in the module chain:\n{gateway_on.conf}"
    assert "pfb_unbound.py" not in gateway_on.conf, gateway_on.conf


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
    except RuntimeError:
        raise AssertionError(f"dnsbl.log gained no Upstream_Block row for {name}:\n{_proxy_log(gw.vm)}") from None
    [row] = upstream_rows()
    assert row[0] == "DNSBL-python" and row[6] == "Upstream", row
    assert row[7] == "EDE15 (Blocked)" and row[8] == "Quad9", f"evaluation / extra text: {row}"
    assert row[3] == CLIENT_LAN_IP, f"the row names {row[3]!r}, not the real client {CLIENT_LAN_IP}: {row}"


def test_the_firewalls_own_lookup_of_a_listed_name_gets_the_vip_from_the_gateway_on_loopback(
    gw: Gateway, gateway_on: State
) -> None:
    """The gateway serves loopback at the Listen Port, so the firewall's own lookups are DNSBL-filtered.

    When the box asks `drill @127.0.0.1` (and gethostbyname through /etc/resolv.conf) for a listed name,
    Then the answer is the DNSBL VIP and dnsbl.log names 127.0.0.1 as the client.
    """
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
      gets the VIP on every transport, logged with its address;
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
            v6 = {
                transport: _ask(gw.client, transport, names.v6[transport], source=LAN_V6_CLIENT, server=LAN_V6_ADDR)
                for transport in TRANSPORTS
            }
            _expect_everywhere("IPv6 LAN client", v6, h.is_vip, "the VIP")
            barrier, raw = _ask(gw.client, "udp", names.v6_barrier, source=LAN_V6_CLIENT, server=LAN_V6_ADDR)
        assert h.is_vip(barrier), f"the IPv6 client's last query should get the VIP: {barrier}\n{raw}"
        _wait_dnsbl_row(vm, names.v6_barrier)
        refused_rows = {name: _dnsbl_rows(vm, name) for name in (*names.nomatch.values(), *unlisted.values())}
        assert not any(refused_rows.values()), f"dnsbl.log has rows for names the gateway refused: {refused_rows}"
        v6_clients = {ipaddress.ip_address(row[3]) for name in names.v6.values() for row in _dnsbl_rows(vm, name)}
        assert v6_clients == {ipaddress.ip_address(LAN_V6_CLIENT)}, f"dnsbl.log names {v6_clients} for the IPv6 client"
    _wait_udp(gw, names.nomatch_poll, h.is_vip, "the VIP again")
    _expect_everywhere("after the lists are back", _ask_all(gw, names.nomatch_restored), h.is_vip, "the VIP")


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
    assert not [s for s in state.listeners if s.command == "pfb_dns_gateway"], "the gateway still holds a socket"
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
