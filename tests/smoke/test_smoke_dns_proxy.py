"""Issue #3515, step 6: the experimental DNS Proxy toggle, driven the way an operator drives it, proven live.

The toggle (``dnsbl/pfb_dns_proxy``) moves the DNS Resolver onto loopback (its port stays 53, so the firewall keeps
resolving through it) and runs pfBlockerNG's DNS proxy on the Resolver's client-facing addresses: the proxy answers
DNSBL decisions itself (the SHIPPED ``pfb_unbound.py`` through its Unbound API shim) and forwards every other query
to Unbound on loopback 5353 with a PROXYv2 header. This module sets the real config keys, runs the real apply
(``pfb_trigger scope=dnsbl``) and watches the box and a LAN client VM, with no hand-made proxy process and no
hand-edited ``unbound.conf``.

Module setup, put back in ``finally``::

    Resolver: DoT on with a self-signed certificate, ``log-queries: yes`` in Custom Options (which starts with the
              ``server:`` clause pfSense documents), Listen Port and Network Interfaces absent (their defaults)
    LAN:      a static IPv6 address (the IPv6 locality tests' 2001:db8:51:1::1/64), so pfSense grants the LAN's IPv6
              subnet to Unbound clients
    DNSBL:    one feed listing five names, Group Policy on with 192.168.1.12 on the bypass list

What it proves, in file order:

* before the toggle: Unbound hosts the python module and listens on 53 and 853 (the baseline every "not any more"
  below is measured against);
* toggle on + apply: config.xml shows the Resolver moved (interfaces, DoT, Custom Options; NOT the port) and the
  snapshot, ``unbound.conf`` has no python module, Unbound listens on loopback 53 and 5353 only, service
  ``pfb_dns_proxy`` runs under ``daemon -t``, the proxy owns 53/853 on the LAN address and NOT on loopback;
* the firewall keeps resolving through Unbound: ``/etc/resolv.conf`` still names 127.0.0.1 after pfSense regenerates
  it, and the firewall's own lookup of a listed name is answered by the upstream (not DNSBL-filtered: a known limit);
* pfSense's IPv6 grant for the LAN subnet disappears from its generated ``access_lists.conf`` with the Resolver on
  loopback, and the same ``access-control`` row is in our marked ``custom_options`` clause instead (so IPv6 clients
  relayed by the proxy are not REFUSED); no IPv6 client query is sent: the client VM has no IPv6 address on the LAN,
  and ``DnsProxyAclTest`` pins the derivation;
* from the LAN client (192.168.1.10): a listed name gets the VIP and a feed-attributed ``dnsbl.log`` row, an allowed
  name gets the upstream's answer and ``resolver.log`` names the client, the same over TCP and over DoT with the
  Resolver's certificate; a Group Policy bypassed address (192.168.1.12, an alias on the client) and the filtered
  client asking for the same names at the same moment each get their own answer (the #3508 shape);
* the Alerts page's whitelist reload takes the zero-downtime swap: neither the proxy nor Unbound restarts;
* toggle off + apply: the proxy and its pidfiles are gone, every Resolver key is back to its pre-toggle value (absent
  stays absent), the marker is cleared, the module is back in ``unbound.conf``, Unbound is on 53 and 853 again.

The Settings page checkbox (below DNSBL Group Policy, help says it is experimental) is covered by the Tier A render
test ``test_dnsbl_dns_proxy_option_renders_below_group_policy`` (tests/smoke/ui/test_render_smoke.py) and the toggle
flow ``dnsbl_dns_proxy`` (tests/smoke/ui/test_functional.py).

Every test asks ``proxy_on`` for the toggle to be on and turns it on (one apply) if an earlier test left it off.

DESELECTED from the default ``python -m pytest``. Run it on the pool::

    scripts/local-smoke.sh --ref issue/3515-dnsbl-proxy-toggle --filter test_smoke_dns_proxy
"""

from __future__ import annotations

import base64
import contextlib
import csv
import io
import json
import os
import re
import shlex
import subprocess
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

import pytest

from . import helpers as h
from .conftest import CLIENT_LAN_IP, PFSENSE_LAN_IP, STUB_DNS_A, SmokeVM, _StubDnsServer

pytestmark = [pytest.mark.smoke, pytest.mark.timeout(180)]

PROXY_PID_FILE = "/var/run/pfb_dns_proxy.pid"  # the python child (daemon -p)
DAEMON_PID_FILE = "/var/run/pfb_dns_proxy_daemon.pid"  # its supervisor (daemon -P)
PROXY_LOG = f"{h.PFB_LOGDIR}/dns_proxy.log"
PROXY_RC = "/usr/local/etc/rc.d/pfb_dns_proxy.sh"
SERVICE = "pfb_dns_proxy"
CONFIG_XML = "/cf/conf/config.xml"
RESOLVER_LOG = "/var/log/resolver.log"
DNSBL_LOG = f"{h.PFB_LOGDIR}/dnsbl.log"
SNAPSHOT_FILE = "/tmp/pfb3515_cfg_snapshot.json"  # on the guest: survives a dead test process
CERT_GUEST = "/tmp/pfb3515_cert.pem"
CERT_CLIENT = "/tmp/pfb3515_ca.pem"

CFG_PROXY = f"{h.CFG_DNSBL_SETTINGS}/pfb_dns_proxy"
CFG_MARKER = f"{h.CFG_DNSBL_SETTINGS}/pfb_dns_proxy_saved"
CFG_GROUP_POLICY = f"{h.CFG_DNSBL_SETTINGS}/pfb_gp"
CFG_GROUP_POLICY_LIST = f"{h.CFG_DNSBL_SETTINGS}/pfb_gp_bypass_list"
CFG_WHITELIST = f"{h.CFG_DNSBL_SETTINGS}/whitelist"

UPSTREAM_PORT = "5353"  # Unbound's loopback port for the proxy's PROXYv2 stream
PROXY_LINE = f"proxy-protocol-port: {UPSTREAM_PORT}"
MARKER = "# pfBlockerNG DNS proxy"  # first line of the block the toggle appends to Custom Options
MARKER_END = "# end pfBlockerNG DNS proxy"
CUSTOM_OPTIONS = "server:\nlog-queries: yes\n"
# The keys the toggle moves, in the order the marker lists them (the Listen Port is not among them), and the keys it
# leaves alone.
MOVED_KEYS = ("active_interface", "enablessl", "custom_options")
RESOLVER_KEYS = (*MOVED_KEYS, "port", "sslcertref", "tlsport")
ACCESS_LISTS = "/var/unbound/access_lists.conf"  # pfSense's generated auto-added `access-control` rows
LAN_V6_ADDR = h.IPV6_LOCAL_ADDR  # the address the module gives the LAN, so pfSense grants its /64 to clients
LAN_V6_ROW = f"access-control: {h.IPV6_LOCAL_SUBNET} allow"
DNS_PORTS = (53, 853, 5353)
CERT_NAME = "pfsense-3515.pfb.localdomain"
FEED_HEADER = "smoke3515"
BYPASSED_ALIAS_IP = "192.168.1.12"  # a second LAN address on the client; on the Group Policy bypass list
DONE = "PFB3515-DONE"

# What pfSense and pfBlockerNG write: the python module in unbound.conf (module-config + the python clause).
MODULE_LINE = re.compile(r'^\s*module-config:\s*"\s*python\b', re.MULTILINE)
SCRIPT_LINE = re.compile(r"^\s*python-script\s*:", re.MULTILINE)

# Everything the module touches outside pfBlockerNG's own reset, snapshotted whole and put back verbatim.
SNAPSHOT_PATHS = (
    *(f"unbound/{key}" for key in RESOLVER_KEYS),
    "cert",
    CFG_PROXY,
    CFG_MARKER,
    CFG_GROUP_POLICY,
    CFG_GROUP_POLICY_LIST,
    CFG_WHITELIST,
)


def _say(message: str) -> None:
    print(f"[3515] {message}", flush=True)


@dataclass(frozen=True)
class Listener:
    command: str
    pid: int
    proto: str
    local: str

    @property
    def host(self) -> str:
        return self.local.rsplit(":", 1)[0]

    @property
    def port(self) -> int:
        return int(self.local.rsplit(":", 1)[1])


@dataclass(frozen=True)
class State:
    """What the box shows at one moment; every field is read from the box, none from what the test did."""

    conf: str  # unbound.conf
    access_lists: str  # the generated access_lists.conf
    resolver: dict[str, str | None]  # config.xml unbound/<key>: the element's text, None when the element is absent
    marker: str  # config.xml pfb_dns_proxy_saved ('' when empty or absent)
    listeners: list[Listener]
    ps: list[str]  # "pid user args" of every process whose command line names pfb_dns_proxy
    proxy_pid: int | None
    daemon_pid: int | None
    unbound_pid: int
    service: str  # 'running' | 'stopped' | 'missing': Status > Services' verdict on pfb_dns_proxy

    def unbound_dns(self) -> set[tuple[str, str]]:
        """(proto, local address) of the Unbound sockets on a DNS port: control sockets stay out of it."""
        return {(s.proto, s.local) for s in self.listeners if s.command == "unbound" and s.port in DNS_PORTS}

    def proxy_sockets(self) -> set[tuple[str, str]]:
        return {(s.proto, s.local) for s in self.listeners if self.proxy_pid and s.pid == self.proxy_pid}

    def ps_line(self, pid: int | None) -> str:
        return next((line for line in self.ps if pid is not None and line.split()[0] == str(pid)), "")


@dataclass(frozen=True)
class Names:
    blocked: str  # listed; the plain-query tests
    whitelisted: str  # listed; the whitelist-reload test
    group_policy: tuple[str, ...]  # listed; one per Group Policy round


@dataclass(frozen=True)
class Rig:
    vm: SmokeVM
    client: SmokeVM
    names: Names
    before: State  # the Resolver as pfBlockerNG leaves it with DNSBL on and the toggle off
    baseline: dict[str, h.DnsAnswer]  # what the client got from that Resolver


# --------------------------------------------------------------------------- #
# Guest plumbing
# --------------------------------------------------------------------------- #


def _sh(vm: SmokeVM, script: str, *, timeout: float = 120.0) -> subprocess.CompletedProcess[str]:
    """Run a POSIX sh script on the guest, fed on stdin (the guest's login shell is tcsh)."""
    return subprocess.run(
        vm.ssh_argv("/bin/sh"), input=script, capture_output=True, text=True, timeout=timeout, check=False
    )


def _php_ok(vm: SmokeVM, snippet: str, what: str, *, timeout: float = 180.0) -> str:
    result = h.php_eval(vm, snippet + f"\necho {h._php_str(DONE)};", timeout=timeout)
    if result.returncode != 0 or DONE not in result.stdout:
        raise RuntimeError(f"{what} failed: rc={result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}")
    return result.stdout


def _snapshot_config(vm: SmokeVM) -> None:
    paths = ", ".join(h._php_str(p) for p in SNAPSHOT_PATHS)
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


def _restore_config(vm: SmokeVM) -> None:
    _php_ok(
        vm,
        f"$snap = json_decode(file_get_contents({h._php_str(SNAPSHOT_FILE)}), true);\n"
        "foreach ($snap as $p => $e) {\n"
        "  if ($e['present']) { config_set_path($p, $e['value']); } else { config_del_path($p); }\n"
        "}\n"
        "write_config('pfBlockerNG smoke: restore the config after the #3515 DNS proxy smoke');",
        "config restore",
    )


def _create_cert(vm: SmokeVM) -> str:
    """A self-signed server certificate in the config (the way pfb_create_dnsbl_cert() makes one); returns its refid."""
    out = h.php_eval(
        vm,
        "require_once('certs.inc');\n"
        "$cert = array();\n"
        "$cert['refid'] = uniqid();\n"
        "$cert['descr'] = 'pfBlockerNG 3515 DNS proxy smoke';\n"
        "$dn = array('organizationName' => 'pfBlockerNG 3515 smoke',"
        f" 'commonName' => {h._php_str(CERT_NAME)}, 'subjectAltName' => {h._php_str('DNS:' + CERT_NAME)});\n"
        "$old = error_reporting(0);\n"
        "$made = cert_create($cert, null, 2048, 398, $dn, 'self-signed', 'sha256');\n"
        "error_reporting($old);\n"
        "if (!$made) { echo '<<<FAILED>>>'; } else {\n"
        "  $all = config_get_path('cert', array());\n"
        "  $all[] = $cert;\n"
        "  config_set_path('cert', $all);\n"
        "  write_config('pfBlockerNG smoke: DoT certificate for the #3515 DNS proxy smoke');\n"
        f"  file_put_contents({h._php_str(CERT_GUEST)}, base64_decode($cert['crt']));\n"
        "  echo '<<<REFID>>>' . $cert['refid'] . '<<<END>>>';\n"
        "}",
        timeout=180.0,
    )
    match = re.search(r"<<<REFID>>>(\w+)<<<END>>>", out.stdout)
    if out.returncode != 0 or match is None:
        raise RuntimeError(f"cert_create failed: rc={out.returncode}\nstdout:\n{out.stdout}\nstderr:\n{out.stderr}")
    return match.group(1)


def _configure_resolver(vm: SmokeVM, refid: str) -> None:
    """Save the Resolver page the way an operator with DoT does: port and interfaces at their defaults, DoT on,
    queries logged, Custom Options in the `server:` form pfSense documents; then let Unbound pick it up."""
    _php_ok(
        vm,
        "$u = config_get_path('unbound', array());\n"
        "unset($u['port'], $u['active_interface']);\n"
        "$u['enablessl'] = 'yes';\n"
        f"$u['sslcertref'] = {h._php_str(refid)};\n"
        f"$u['custom_options'] = {h._php_str(base64.b64encode(CUSTOM_OPTIONS.encode()).decode())};\n"
        "config_set_path('unbound', $u);\n"
        "write_config('pfBlockerNG smoke: Resolver DoT and log-queries for the #3515 smoke');\n"
        "services_unbound_configure();",
        "Resolver settings",
    )
    h.wait_unbound_ready(vm)


def _configure_group_policy(vm: SmokeVM) -> None:
    """Group Policy on, with the client's alias address as the one bypassed address."""
    bypass = h._b64_textarea([BYPASSED_ALIAS_IP])
    _php_ok(
        vm,
        f"$d = config_get_path({h._php_str(h.CFG_DNSBL_SETTINGS)}, array());\n"
        "$d['pfb_gp'] = 'on';\n"
        f"$d['pfb_gp_bypass_list'] = {h._php_str(bypass)};\n"
        f"config_set_path({h._php_str(h.CFG_DNSBL_SETTINGS)}, $d);\n"
        "write_config('pfBlockerNG smoke: Group Policy bypass list for the #3515 smoke');",
        "Group Policy settings",
    )


def _set_proxy_toggle(vm: SmokeVM, on: bool) -> None:
    """The Settings page's save, minus the page: the registered toggle token, 'on' or the empty Off token."""
    _php_ok(
        vm,
        f"config_set_path({h._php_str(CFG_PROXY)}, {h._php_str('on' if on else '')});\n"
        f"write_config('pfBlockerNG smoke: DNS Proxy toggle {'on' if on else 'off'}');",
        "DNS Proxy toggle",
    )


def _config_xml(vm: SmokeVM) -> ET.Element:
    result = vm.ssh("cat", CONFIG_XML)
    if result.returncode != 0:
        raise RuntimeError(f"cannot read {CONFIG_XML}: rc={result.returncode} {result.stderr!r}")
    return ET.fromstring(result.stdout)


def _xml_text(root: ET.Element, path: str) -> str | None:
    element = root.find(path)
    return None if element is None else (element.text or "")


def _listeners(vm: SmokeVM) -> list[Listener]:
    """Every socket `sockstat -46l` shows: USER COMMAND PID FD PROTO LOCAL FOREIGN."""
    rows = (line.split() for line in vm.ssh("sockstat -46l").stdout.splitlines()[1:])
    return [Listener(row[1], int(row[2]), row[4], row[5]) for row in rows if len(row) >= 6 and row[2].isdigit()]


def _pid_file(vm: SmokeVM, path: str) -> int | None:
    result = vm.ssh("cat", path)
    text = result.stdout.strip()
    return int(text) if result.returncode == 0 and text.isdigit() else None


def _service_status(vm: SmokeVM) -> str:
    """Status > Services' verdict on the package service: the XML's own status command decides."""
    out = h.php_eval(
        vm,
        "require_once('service-utils.inc');\n"
        "$verdict = 'missing';\n"
        "foreach (get_services() as $s) {\n"
        f"  if (($s['name'] ?? '') === {h._php_str(SERVICE)}) {{\n"
        "    $verdict = get_service_status($s) ? 'running' : 'stopped';\n"
        "  }\n"
        "}\n"
        "echo '<<<SVC>>>' . $verdict . '<<<END>>>';",
    )
    match = re.search(r"<<<SVC>>>(\w+)<<<END>>>", out.stdout)
    if out.returncode != 0 or match is None:
        raise RuntimeError(f"service status failed: rc={out.returncode}\nstdout:\n{out.stdout}\nstderr:\n{out.stderr}")
    return match.group(1)


def _capture(vm: SmokeVM) -> State:
    root = _config_xml(vm)
    # The bracket keeps grep from matching its own command line.
    ps = vm.ssh("ps -axww -o pid,user,args | grep -E 'pfb_dns_prox[y]'").stdout.splitlines()
    return State(
        conf=vm.ssh("cat", h.UNBOUND_CONF).stdout,
        access_lists=vm.ssh("cat", ACCESS_LISTS).stdout,
        resolver={key: _xml_text(root, f"unbound/{key}") for key in RESOLVER_KEYS},
        marker=_xml_text(root, "installedpackages/pfblockerngdnsblsettings/config/pfb_dns_proxy_saved") or "",
        listeners=_listeners(vm),
        ps=[line.strip() for line in ps],
        proxy_pid=_pid_file(vm, PROXY_PID_FILE),
        daemon_pid=_pid_file(vm, DAEMON_PID_FILE),
        unbound_pid=h.unbound_pid(vm),
        service=_service_status(vm),
    )


def _proxy_log(vm: SmokeVM, lines: int = 60) -> str:
    return vm.ssh(f"tail -n {lines} {PROXY_LOG} 2>&1").stdout


def _force_stop_proxy(vm: SmokeVM) -> None:
    """Best-effort cleanup for a run that died with the proxy up: the service stop, then the pids, then the files."""
    _sh(
        vm,
        f"[ -x {PROXY_RC} ] && {PROXY_RC} stop\n"
        f"for f in {DAEMON_PID_FILE} {PROXY_PID_FILE}; do [ -f $f ] && kill -KILL $(cat $f) 2>/dev/null; done\n"
        "pkill -KILL -f 'pfb_dns_prox[y][.]py'\n"
        f"rm -f {DAEMON_PID_FILE} {PROXY_PID_FILE}\n",
    )


# --------------------------------------------------------------------------- #
# Queries and the logs that show who asked
# --------------------------------------------------------------------------- #


def _query(
    client: SmokeVM,
    name: str,
    *,
    tcp: bool = False,
    dot: bool = False,
    source: str | None = None,
    server: str = PFSENSE_LAN_IP,
) -> tuple[h.DnsAnswer, str]:
    """dig from the LAN client at pfSense's LAN IP; returns the parsed answer and dig's full output."""
    args = ["dig", "+tries=1", "+time=5"]
    if source:
        args += ["-b", source]
    if tcp:
        args.append("+tcp")
    if dot:
        # +tls-ca makes dig verify the server against the Resolver's own certificate, not just talk TLS.
        args += ["+tls", f"+tls-ca={CERT_CLIENT}", f"+tls-hostname={CERT_NAME}"]
    args += ["A", name, f"@{server}"]
    result = client.ssh(shlex.join(args) + " 2>&1", timeout=40.0)
    return h._parse_dig(result.stdout, "A"), result.stdout


def _unbound_clients(vm: SmokeVM, name: str) -> list[str]:
    """The client address Unbound's query log names, for each logged query of `name`."""
    lines = vm.ssh("grep", "-F", "--", name, RESOLVER_LOG).stdout.splitlines()
    pattern = re.compile(rf"info:\s+(\S+)\s+{re.escape(name)}\.?\s+\S+\s+IN\b")
    return [m.group(1) for m in (pattern.search(line) for line in lines) if m]


def _wait_unbound_logged(vm: SmokeVM, name: str) -> list[str]:
    try:
        h.wait_until(lambda: bool(_unbound_clients(vm, name)), timeout=30.0, interval=2.0)
    except RuntimeError:
        grep = vm.ssh(f"grep -F -- {shlex.quote(name)} {RESOLVER_LOG} 2>&1; tail -n 15 {RESOLVER_LOG} 2>&1").stdout
        logging = vm.ssh(f"grep -E 'log-|logfile|use-syslog|verbosity|proxy' {h.UNBOUND_CONF}").stdout
        raise AssertionError(
            f"{RESOLVER_LOG} has no query line for {name}.\nmatching and last lines:\n{grep}\nlogging conf:\n{logging}"
        ) from None
    return _unbound_clients(vm, name)


def _dnsbl_rows(vm: SmokeVM, name: str) -> list[list[str]]:
    """dnsbl.log rows for `name`: DNSBL-python,timestamp,name,client,p_type,b_type,group,b_eval,feed,dup,qtype."""
    return [row for row in csv.reader(io.StringIO(h.read_log_file(vm, DNSBL_LOG))) if row[2:3] == [name]]


def _wait_dnsbl_row(vm: SmokeVM, name: str) -> None:
    try:
        h.wait_until(lambda: bool(_dnsbl_rows(vm, name)), timeout=30.0)
    except RuntimeError:
        raise AssertionError(f"dnsbl.log gained no row for {name}:\n{_proxy_log(vm)}") from None


def _assert_answered_by_upstream(rig: Rig, name: str, answer: h.DnsAnswer, raw: str, how: str) -> None:
    assert h.resolves_to(answer, STUB_DNS_A), f"{how}: {name} expected the upstream's {STUB_DNS_A}, got {answer}\n{raw}"
    clients = _wait_unbound_logged(rig.vm, name)
    assert clients == [CLIENT_LAN_IP], (
        f"{how}: Unbound's query log for {name} should name the client {CLIENT_LAN_IP} (PROXYv2), got {clients}"
    )


# --------------------------------------------------------------------------- #
# The toggle, applied the way the Settings page applies it
# --------------------------------------------------------------------------- #


def _diagnostics(vm: SmokeVM) -> str:
    state = _capture(vm)
    return (
        f"proxy log:\n{_proxy_log(vm)}\n"
        f"ps: {state.ps}\nservice: {state.service}\nmarker set: {bool(state.marker)}\n"
        f"resolver keys: {state.resolver}\n"
        f"unbound sockets: {sorted(state.unbound_dns())}\nproxy sockets: {sorted(state.proxy_sockets())}\n"
        f"pfblockerng.log tail:\n{vm.ssh(f'tail -n 40 {h.PFB_LOG} 2>&1').stdout}"
    )


def _apply(vm: SmokeVM) -> None:
    """The DNSBL apply the Settings page triggers on save: pfb_trigger scope=dnsbl, then wait for Unbound."""
    h.reload(vm, "updatednsbl")


def _unbound_conf_report(vm: SmokeVM) -> str:
    """Why Unbound would not start: its own config check, and the lines around the error."""
    check = vm.ssh(f"/usr/local/sbin/unbound-checkconf {h.UNBOUND_CONF} 2>&1").stdout
    numbered = vm.ssh(f"cat -n {h.UNBOUND_CONF} | sed -n '85,130p'").stdout
    return f"unbound-checkconf:\n{check}\nunbound.conf lines 85-130:\n{numbered}"


def _wait_proxy_serves(rig: Rig) -> None:
    """Poll until the LAN client gets the VIP for a listed name: the proxy booted its module and loaded the feed."""

    def serves() -> bool:
        answer, _ = _query(rig.client, rig.names.blocked)
        return h.is_vip(answer)

    try:
        h.wait_until(serves, timeout=240.0, interval=3.0)
    except RuntimeError as exc:
        raise RuntimeError(f"{exc}\n{_diagnostics(rig.vm)}") from exc


def _toggle_on(rig: Rig) -> None:
    _set_proxy_toggle(rig.vm, True)
    try:
        _apply(rig.vm)
    except RuntimeError as exc:
        raise RuntimeError(f"{exc}\n{_unbound_conf_report(rig.vm)}") from exc
    _wait_proxy_serves(rig)


def _is_on(state: State) -> bool:
    return state.service == "running" and state.resolver["active_interface"] == "lo0"


# --------------------------------------------------------------------------- #
# The fixtures
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def rig(smoke_vm: SmokeVM, client_vm: SmokeVM, stub_dns: _StubDnsServer) -> Iterator[Rig]:
    """Deploy the package, a DNSBL feed, DoT and Group Policy; apply once with the toggle off; undo it in `finally`."""
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    vm = smoke_vm
    h.deploy(vm)
    h.ensure_dnsbl_vip(vm)
    h.use_system_dns_upstream(vm)  # Unbound forwards to the stub upstream; nothing needs the internet
    h.assert_link_health(client_vm, vm, control_name=h.unique_domain())
    names = Names(
        blocked=h.unique_domain("blocked"),
        whitelisted=h.unique_domain("whitelisted"),
        group_policy=tuple(h.unique_domain("gp") for _ in range(3)),
    )
    listed = (names.blocked, names.whitelisted, *names.group_policy)
    feed_url = h.write_local_feed(vm, "smoke_3515_dns_proxy.txt", "".join(f"{name}\n" for name in listed))
    _snapshot_config(vm)
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
        _configure_group_policy(vm)
        _apply(vm)  # toggle off: pfBlockerNG's own wiring, the module inside Unbound
        before = _capture(vm)
        baseline = {
            "blocked": _query(client_vm, names.blocked)[0],
            "allowed": _query(client_vm, h.unique_domain("baseline"))[0],
            "blocked_dot": _query(client_vm, names.blocked, dot=True)[0],
        }
        yield Rig(vm, client_vm, names, before, baseline)
    finally:
        try:
            _force_stop_proxy(vm)
        finally:
            _say("proxy log:\n" + _proxy_log(vm, 80))
            try:
                _restore_config(vm)
                _php_ok(vm, "services_unbound_configure();", "services_unbound_configure (restore)")
                h.wait_unbound_ready(vm)
                on53 = {s.local for s in _listeners(vm) if s.command == "unbound" and s.port == 53}
                assert on53, f"Unbound is not back on port 53 after the restore: {_listeners(vm)}"
            finally:
                if lan_v6_prior is not None:
                    h.restore_interface_ipv6(vm, h.IPV6_LOCAL_IFACE, lan_v6_prior)
                _sh(vm, f"rm -f {SNAPSHOT_FILE} {CERT_GUEST}")
                client_vm.ssh(f"rm -f {CERT_CLIENT}")
                h.collect_host_diagnostics(vm)


@pytest.fixture
def proxy_on(rig: Rig) -> State:
    """The box with the toggle on (applied now if an earlier test left it off), as it is when the test starts."""
    state = _capture(rig.vm)
    if not _is_on(state):
        _toggle_on(rig)
        state = _capture(rig.vm)
    return state


# --------------------------------------------------------------------------- #
# Before the toggle: the baseline every "not any more" is measured against
# --------------------------------------------------------------------------- #


def test_before_the_toggle_unbound_hosts_the_module_and_serves_53_and_853(rig: Rig) -> None:
    """With DNSBL on and the toggle off, the Resolver is untouched and Unbound runs the python module itself.

    Given the Resolver at its defaults with DoT on, DNSBL active, and the toggle off,
    Then unbound.conf has the python module, Unbound listens on 53 and 853 (not 5353), the Resolver keys are
      unmoved, no snapshot exists, and no proxy runs; the client's blocked / allowed / DoT queries all work.
    """
    before = rig.before
    assert MODULE_LINE.search(before.conf) and SCRIPT_LINE.search(before.conf), before.conf
    _say(f"Unbound DNS sockets, toggle off: {sorted(before.unbound_dns())}")
    ports = {int(local.rsplit(":", 1)[1]) for _, local in before.unbound_dns()}
    assert {53, 853} <= ports and 5353 not in ports, f"Unbound DNS sockets: {sorted(before.unbound_dns())}"
    assert before.resolver["port"] is None and before.resolver["active_interface"] is None, before.resolver
    assert before.resolver["enablessl"] == "yes" and before.resolver["sslcertref"], before.resolver
    assert before.marker == "" and before.ps == [] and before.proxy_pid is None and before.service == "stopped", before
    assert h.is_vip(rig.baseline["blocked"]), f"baseline blocked name: {rig.baseline['blocked']}"
    assert h.resolves_to(rig.baseline["allowed"], STUB_DNS_A), f"baseline allowed name: {rig.baseline['allowed']}"
    assert h.is_vip(rig.baseline["blocked_dot"]), f"baseline blocked name over DoT: {rig.baseline['blocked_dot']}"


# --------------------------------------------------------------------------- #
# Toggle on + apply: what the box looks like
# --------------------------------------------------------------------------- #


def _lines(text: str) -> list[str]:
    """The stripped lines of a config text (pfSense writes its access-control rows with a trailing space)."""
    return [line.strip() for line in text.splitlines()]


def test_toggle_on_moves_the_resolver_in_config_xml_and_snapshots_what_it_moved(rig: Rig, proxy_on: State) -> None:
    """The apply writes the move into config.xml and keeps the previous values in the marker.

    Given the Resolver with port and active_interface absent, DoT on, and Custom Options starting `server:`,
    When the toggle is on and applied,
    Then config.xml has active_interface lo0, no enablessl, the Listen Port exactly as it was (absent) and
      Custom Options with the user's own lines first and our marked `server:` clause last (loopback 5353
      listeners, the PROXYv2 port and the LAN's IPv6 grant); DoT's certificate keys are unchanged;
      And the marker holds the previous values: presence and value of each moved key, as they were.
    """
    state, before = proxy_on, rig.before
    assert state.resolver["port"] == before.resolver["port"] is None, state.resolver
    assert state.resolver["active_interface"] == "lo0", state.resolver
    assert state.resolver["enablessl"] is None, state.resolver
    assert (state.resolver["sslcertref"], state.resolver["tlsport"]) == (
        before.resolver["sslcertref"],
        before.resolver["tlsport"],
    ), state.resolver
    options = base64.b64decode(state.resolver["custom_options"] or "").decode().replace("\r\n", "\n")
    lines = options.splitlines()
    assert MARKER in lines and MARKER_END in lines, f"Custom Options: {options!r}"
    start, end = lines.index(MARKER), lines.index(MARKER_END)
    assert lines[:start] == [*CUSTOM_OPTIONS.splitlines(), "server:"], f"Custom Options: {options!r}"
    assert lines[start + 1 : start + 4] == [
        f"interface: 127.0.0.1@{UPSTREAM_PORT}",
        f"interface: ::1@{UPSTREAM_PORT}",
        PROXY_LINE,
    ]
    grants = lines[start + 4 : end]
    assert all(re.fullmatch(r"access-control: \S+ allow", row) for row in grants), f"Custom Options: {options!r}"
    assert lines[end + 1 :] == [], f"nothing follows our block: {options!r}"
    assert state.marker, "pfb_dns_proxy_saved is empty after the toggle moved the Resolver"
    saved = json.loads(base64.b64decode(state.marker))
    expected = {key: {"present": before.resolver[key] is not None, "value": before.resolver[key]} for key in MOVED_KEYS}
    assert saved == expected, f"snapshot in the marker:\n{saved}\nResolver before the toggle:\n{expected}"


def test_toggle_on_leaves_unbound_without_the_module_on_loopback_53_and_5353(rig: Rig, proxy_on: State) -> None:
    """Unbound no longer runs the python module and listens on loopback only; it accepts the proxy's PROXYv2.

    Then unbound.conf has neither `module-config: "python` nor `python-script` (the baseline test pins both
      present with the toggle off); the Unbound DNS sockets are exactly loopback 53 (the firewall's own resolver)
      and loopback 5353 (the proxy's upstream), IPv4 and IPv6, UDP and TCP, none on 853 or any LAN address;
      And the running Unbound reports proxy-protocol-port 5353.
    """
    assert not MODULE_LINE.search(proxy_on.conf), f"unbound.conf still loads the python module:\n{proxy_on.conf}"
    assert not SCRIPT_LINE.search(proxy_on.conf), f"unbound.conf still names a python-script:\n{proxy_on.conf}"
    sockets = proxy_on.unbound_dns()
    _say(f"Unbound DNS sockets, toggle on: {sorted(sockets)}")
    wanted = {
        (f"{transport}{family}", f"{host}:{port}")
        for transport in ("udp", "tcp")
        for family, host in (("4", "127.0.0.1"), ("6", "::1"))
        for port in (53, int(UPSTREAM_PORT))
    }
    assert wanted <= sockets, f"missing Unbound sockets: {sorted(wanted - sockets)}; has {sorted(sockets)}"
    stray = {(proto, local) for proto, local in sockets if not re.fullmatch(r"(127\.0\.0\.1|::1):(53|5353)", local)}
    assert not stray, f"Unbound listens beyond loopback 53 and 5353: {sorted(stray)} (all: {sorted(sockets)})"
    option = rig.vm.ssh(f"/usr/local/sbin/unbound-control -c {h.UNBOUND_CONF} get_option proxy-protocol-port 2>&1")
    assert option.stdout.strip() == UPSTREAM_PORT, f"unbound-control get_option proxy-protocol-port: {option.stdout!r}"


def test_toggle_on_runs_the_proxy_as_a_supervised_service_on_53_and_853(rig: Rig, proxy_on: State) -> None:
    """Service pfb_dns_proxy runs under daemon(8) with its ps title, and owns the client-facing ports.

    Then Status > Services says `pfb_dns_proxy` runs; the supervisor's ps title is `daemon: pfb_dns_proxy[<pid>]`
      (daemon `-t`); the child is the proxy script, run as `unbound`, with `--dot` (the saved Resolver had DoT);
      the proxy holds UDP and TCP 53 on the LAN's IPv4 and IPv6 addresses and TCP 853 on the LAN address,
      and nothing on loopback (that is Unbound's).
    """
    state = proxy_on
    assert state.service == "running", f"service pfb_dns_proxy: {state.service}"
    assert state.proxy_pid and state.daemon_pid, f"pidfiles: proxy={state.proxy_pid} daemon={state.daemon_pid}"
    supervisor = state.ps_line(state.daemon_pid)
    assert re.search(rf"\bdaemon: pfb_dns_proxy\[{state.proxy_pid}\]", supervisor), (
        f"supervisor ps line {supervisor!r}; ps: {state.ps}"
    )
    child = state.ps_line(state.proxy_pid)
    assert "pfb_dns_proxy.py" in child and "--dot" in child and "--upstream 127.0.0.1:5353" in child, child
    assert child.split()[1] == "unbound", f"the proxy should have dropped root to unbound: {child!r}"
    sockets = state.proxy_sockets()
    _say(f"proxy sockets, toggle on: {sorted(sockets)}")
    wanted = {(proto, f"{PFSENSE_LAN_IP}:53") for proto in ("udp4", "tcp4")}
    wanted |= {(proto, f"{LAN_V6_ADDR}:53") for proto in ("udp6", "tcp6")}
    wanted.add(("tcp4", f"{PFSENSE_LAN_IP}:853"))
    assert wanted <= sockets, f"missing proxy sockets: {sorted(wanted - sockets)}; has {sorted(sockets)}"
    on_loopback = {(proto, local) for proto, local in sockets if re.match(r"(127\.0\.0\.1|::1):", local)}
    assert not on_loopback, f"the proxy must leave loopback to Unbound: {sorted(on_loopback)}"


def _firewall_lookup(vm: SmokeVM, name: str) -> str:
    """What the firewall's OWN resolver (gethostbyname, i.e. /etc/resolv.conf) answers for `name`."""
    out = _php_ok(vm, f"echo 'FW=' . gethostbyname({h._php_str(name + '.')}) . ';';", "firewall lookup")
    match = re.search(r"FW=([^;]*);", out)
    assert match, f"no answer line in the firewall lookup output: {out!r}"
    return match.group(1)


def test_the_firewall_keeps_resolving_through_unbound_and_is_not_dnsbl_filtered(rig: Rig, proxy_on: State) -> None:
    """The firewall's own lookups keep going to Unbound on loopback 53, which no longer sits behind the proxy.

    When pfSense regenerates /etc/resolv.conf (a reboot, a WAN event, a settings save do the same),
    Then it still names 127.0.0.1 (pfSense lists it only while the Resolver's port is 53);
      And the firewall's lookup of a listed name gets the upstream's answer, not the DNSBL VIP: the firewall's own
      queries are not DNSBL-filtered (a known limit, see architecture-notes "Experimental DNS proxy mode").
    """
    _php_ok(rig.vm, "require_once('system.inc');\nsystem_resolvconf_generate();", "system_resolvconf_generate")
    resolv = rig.vm.ssh("cat /etc/resolv.conf").stdout
    assert re.search(r"^nameserver\s+127\.0\.0\.1\s*$", resolv, re.MULTILINE), f"/etc/resolv.conf:\n{resolv}"
    answer = _firewall_lookup(rig.vm, rig.names.blocked)
    assert answer == STUB_DNS_A, f"the firewall's own lookup of the listed {rig.names.blocked}: {answer!r}"


def test_the_lans_ipv6_grant_moves_from_pfsenses_access_list_into_our_clause(rig: Rig, proxy_on: State) -> None:
    """With the Resolver on loopback pfSense stops granting the LAN's IPv6 subnet; our clause grants it instead.

    Given the LAN has a global IPv6 address (module setup), so pfSense grants its /64 with the Resolver on the LAN,
    When the toggle is on and applied,
    Then pfSense's generated access_lists.conf no longer has that row (the premise: without our clause IPv6 clients
      relayed by the proxy would be REFUSED), the row is in unbound.conf inside our marked clause, and the running
      Unbound was started from it.
    """
    assert LAN_V6_ROW in _lines(rig.before.access_lists), (
        f"premise: access_lists.conf with the toggle off:\n{rig.before.access_lists}"
    )
    assert LAN_V6_ROW not in _lines(proxy_on.access_lists), (
        f"access_lists.conf with the toggle on:\n{proxy_on.access_lists}"
    )
    conf = _lines(proxy_on.conf)
    assert MARKER in conf and conf.index(MARKER) < conf.index(LAN_V6_ROW) < conf.index(MARKER_END), (
        f"{LAN_V6_ROW} is not inside our clause of unbound.conf:\n{proxy_on.conf}"
    )


# --------------------------------------------------------------------------- #
# Toggle on: queries from the LAN client
# --------------------------------------------------------------------------- #


def test_listed_name_gets_the_vip_and_a_feed_attributed_log_row(rig: Rig, proxy_on: State) -> None:
    """A listed name is answered by the proxy: VIP, a feed-attributed dnsbl.log row, no query at Unbound.

    Given a feed listing `blocked` and no dnsbl.log row for it yet,
    When the LAN client asks the proxy over UDP,
    Then it gets the DNSBL VIP and dnsbl.log gains a row naming the feed and the client,
      And Unbound's query log, which has an allowed query asked after it, gains no line for the listed name
      (the baseline queries asked before the toggle are in that log already: only new lines count).
    """
    rows_before = len(_dnsbl_rows(rig.vm, rig.names.blocked))
    unbound_lines_before = _unbound_clients(rig.vm, rig.names.blocked)
    answer, raw = _query(rig.client, rig.names.blocked)
    assert h.is_vip(answer), f"{rig.names.blocked}: expected VIP {h.DEFAULT_DNSBL_VIP4}, got {answer}\n{raw}"
    try:
        h.wait_until(lambda: len(_dnsbl_rows(rig.vm, rig.names.blocked)) > rows_before, timeout=30.0)
    except RuntimeError:
        raise AssertionError(f"dnsbl.log gained no row for {rig.names.blocked}:\n{_proxy_log(rig.vm)}") from None
    new_rows = _dnsbl_rows(rig.vm, rig.names.blocked)[rows_before:]
    assert {row[3] for row in new_rows} == {CLIENT_LAN_IP}, f"dnsbl.log client: expected {CLIENT_LAN_IP}: {new_rows}"
    assert {row[8] for row in new_rows} == {FEED_HEADER}, f"dnsbl.log feed: expected {FEED_HEADER}: {new_rows}"
    # Barrier: Unbound logs the allowed query after any earlier arrival of the listed one would have been logged.
    after = h.unique_domain("after")
    _assert_answered_by_upstream(rig, after, *_query(rig.client, after), how="UDP barrier")
    unbound_lines_after = _unbound_clients(rig.vm, rig.names.blocked)
    assert unbound_lines_after == unbound_lines_before, (
        f"Unbound logged {rig.names.blocked} for this query: {unbound_lines_before} -> {unbound_lines_after}"
    )


def test_allowed_name_is_answered_by_the_upstream_and_unbound_logs_the_client(rig: Rig, proxy_on: State) -> None:
    """An allowed name is forwarded to Unbound with PROXYv2: the upstream's answer comes back for the real client.

    Given a name no feed lists,
    When the LAN client asks the proxy over UDP,
    Then the reply is the upstream stub's answer relayed from Unbound,
      And `resolver.log` names 192.168.1.10, not the proxy's 127.0.0.1.
    """
    name = h.unique_domain("allowed")
    _assert_answered_by_upstream(rig, name, *_query(rig.client, name), how="UDP")


def test_tcp_queries_are_blocked_and_forwarded_like_udp(rig: Rig, proxy_on: State) -> None:
    """Over TCP the listed name gets the VIP and an allowed name gets Unbound's answer for the real client."""
    answer, raw = _query(rig.client, rig.names.blocked, tcp=True)
    assert h.is_vip(answer), f"TCP {rig.names.blocked}: expected VIP {h.DEFAULT_DNSBL_VIP4}, got {answer}\n{raw}"
    name = h.unique_domain("tcp")
    _assert_answered_by_upstream(rig, name, *_query(rig.client, name, tcp=True), how="TCP")


def test_dot_queries_work_with_the_resolvers_certificate(rig: Rig, proxy_on: State) -> None:
    """Over DoT, verified against the Resolver's own certificate, a listed name gets the VIP and an allowed one passes.

    The saved Resolver had DoT on, so the proxy serves 853 with the certificate `unbound/sslcertref` names; the TLS
    peer address becomes the PROXYv2 client, so Unbound's log names the LAN client for the DoT query too.
    """
    answer, raw = _query(rig.client, rig.names.blocked, dot=True)
    assert h.is_vip(answer), f"DoT {rig.names.blocked}: expected VIP {h.DEFAULT_DNSBL_VIP4}, got {answer}\n{raw}"
    name = h.unique_domain("dot")
    _assert_answered_by_upstream(rig, name, *_query(rig.client, name, dot=True), how="DoT")


@contextlib.contextmanager
def _client_alias(client: SmokeVM, address: str) -> Iterator[None]:
    """`address` as a second LAN address of the client, so the proxy sees a second client."""
    rows = client.ssh("ip -o -4 addr show").stdout.splitlines()
    interface = next((row.split()[1] for row in rows if f" {CLIENT_LAN_IP}/" in row), None)
    assert interface, f"no client interface carries {CLIENT_LAN_IP}: {rows}"
    added = client.ssh(f"ip addr add {address}/24 dev {interface}")
    assert added.returncode == 0, f"cannot add {address} to {interface} on the client: {added.stderr!r}"
    try:
        yield
    finally:
        client.ssh(f"ip addr del {address}/24 dev {interface}")


def test_group_policy_bypassed_and_filtered_clients_asking_at_once_each_get_their_own_answer(
    rig: Rig, proxy_on: State
) -> None:
    """Issue #3508 through the live proxy: a Group Policy bypassed address and a filtered client share names.

    Given 192.168.1.12 on the Group Policy bypass list and 192.168.1.10 filtered, three listed names,
    When both clients ask for the same name at the same moment (the order they start in alternates per round),
    Then the filtered client always gets the VIP and the bypassed one always gets the upstream's answer;
      And dnsbl.log has rows for the filtered client only, and Unbound's log names the bypassed address only.
    """
    names = rig.names.group_policy
    with _client_alias(rig.client, BYPASSED_ALIAS_IP):
        for round_number, name in enumerate(names):
            jobs = [("bypassed", BYPASSED_ALIAS_IP), ("filtered", None)]
            if round_number % 2:
                jobs.reverse()
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = {label: pool.submit(_query, rig.client, name, source=source) for label, source in jobs}
                answers = {label: future.result() for label, future in futures.items()}
            filtered, filtered_raw = answers["filtered"]
            bypassed, bypassed_raw = answers["bypassed"]
            assert h.is_vip(filtered), f"{name}: filtered client expected the VIP, got {filtered}\n{filtered_raw}"
            assert h.resolves_to(bypassed, STUB_DNS_A), (
                f"{name}: bypassed client expected the upstream's {STUB_DNS_A}, got {bypassed}\n{bypassed_raw}"
            )
    for name in names:
        _wait_dnsbl_row(rig.vm, name)
        assert {row[3] for row in _dnsbl_rows(rig.vm, name)} == {CLIENT_LAN_IP}, _dnsbl_rows(rig.vm, name)
        assert _wait_unbound_logged(rig.vm, name) == [BYPASSED_ALIAS_IP], _unbound_clients(rig.vm, name)


# --------------------------------------------------------------------------- #
# Toggle on: the Alerts page's whitelist reload
# --------------------------------------------------------------------------- #


@pytest.mark.timeout(600)
def test_alerts_whitelist_reload_takes_the_zero_downtime_swap_without_restarting_anything(
    rig: Rig, proxy_on: State
) -> None:
    """Whitelisting a listed name through the Alerts page's own PHP is a data swap: nothing restarts.

    Given a listed name the client gets the VIP for, and the proxy and Unbound pids,
    When the whitelist is written and reloaded the way pfblockerng_alerts.php does it,
    Then the reload reports the zero-downtime swap (and logs it), the proxy, its supervisor and Unbound keep their
      pids, and the client now gets the upstream's answer for the name.
    """
    vm, name = rig.vm, rig.names.whitelisted
    answer, raw = _query(rig.client, name)
    assert h.is_vip(answer), f"{name}: expected the VIP before the whitelist, got {answer}\n{raw}"
    pids = (proxy_on.proxy_pid, proxy_on.daemon_pid, h.unbound_pid(vm))
    swaps = h.count_log_marker(vm, h.PFB_LOG, h.SWAP_LOG_MARKER)
    original = h.config_get_state(vm, CFG_WHITELIST)
    try:
        out = h.php_eval(
            vm,
            "require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');\n"
            f"config_set_path({h._php_str(CFG_WHITELIST)}, {h._php_str(h._b64_textarea([name]))});\n"
            "write_config('pfBlockerNG smoke: DNSBL whitelist for the #3515 swap');\n"
            "pfb_unbound_python_whitelist('alerts');\n"
            "$patched = pfb_unbound_python_sources_whitelist();\n"
            "$swapped = pfb_reload_unbound('enabled', FALSE, FALSE, TRUE);\n"
            "echo '<<<WL>>>' . ($patched ? 'patched' : 'unpatched') . ',' . ($swapped ? 'swapped' : 'restarted')"
            " . '<<<END>>>';",
            timeout=300.0,
        )
        match = re.search(r"<<<WL>>>(\w+),(\w+)<<<END>>>", out.stdout)
        assert out.returncode == 0 and match, (
            f"whitelist reload failed: rc={out.returncode}\n{out.stdout}\n{out.stderr}"
        )
        assert match.groups() == ("patched", "swapped"), f"whitelist reload: {match.groups()}\n{_diagnostics(vm)}"
        h.wait_zero_downtime_swap(vm, since=swaps)
        after = (_pid_file(vm, PROXY_PID_FILE), _pid_file(vm, DAEMON_PID_FILE), h.unbound_pid(vm))
        assert after == pids, f"pids (proxy, supervisor, unbound) changed across the swap: {pids} -> {after}"
        allowed, raw = _query(rig.client, name)
        assert h.resolves_to(allowed, STUB_DNS_A), f"{name} after the whitelist: {allowed}\n{raw}"
    finally:
        h.config_restore_state(vm, CFG_WHITELIST, original)


# --------------------------------------------------------------------------- #
# Toggle off + apply: everything is back
# --------------------------------------------------------------------------- #


@pytest.mark.timeout(900)
def test_toggle_off_stops_the_proxy_and_puts_the_resolver_back_exactly(rig: Rig, proxy_on: State) -> None:
    """Turning the toggle off and applying gives the Resolver back as it was and leaves no proxy behind.

    Given the toggle on (the Resolver moved, the proxy running, a snapshot in the marker),
    When the toggle is turned off and applied,
    Then the proxy and the supervisor are gone with both pidfiles and the service reads stopped;
      every Resolver key equals its pre-toggle value (absent keys absent again, Custom Options byte for byte);
      the marker is cleared; unbound.conf has the python module again; Unbound listens where it did before
      the toggle (53 and 853, not 5353);
      And the client's blocked / allowed / DoT queries work against Unbound again.
    """
    vm, before = rig.vm, rig.before
    assert _is_on(proxy_on) and proxy_on.marker, f"the toggle is not on before the test turns it off: {proxy_on}"
    _set_proxy_toggle(vm, False)
    _apply(vm)
    state = _capture(vm)
    assert state.service == "stopped" and state.ps == [], f"proxy left running: {state.service} {state.ps}"
    assert state.proxy_pid is None and state.daemon_pid is None, (state.proxy_pid, state.daemon_pid)
    assert state.resolver == before.resolver, (
        f"Resolver keys after the toggle off:\n{state.resolver}\nbefore:\n{before.resolver}"
    )
    assert state.marker == "", f"pfb_dns_proxy_saved is not cleared: {state.marker!r}"
    assert MODULE_LINE.search(state.conf) and SCRIPT_LINE.search(state.conf), f"module not back:\n{state.conf}"
    assert state.unbound_dns() == before.unbound_dns(), (
        f"Unbound sockets {sorted(state.unbound_dns())}, before the toggle {sorted(before.unbound_dns())}"
    )
    blocked, raw = _query(rig.client, rig.names.blocked)
    assert h.is_vip(blocked), f"blocked name through Unbound again: {blocked}\n{raw}"
    allowed, raw = _query(rig.client, h.unique_domain("restored"))
    assert h.resolves_to(allowed, STUB_DNS_A), f"allowed name through Unbound again: {allowed}\n{raw}"
    dot, raw = _query(rig.client, rig.names.blocked, dot=True)
    assert h.is_vip(dot), f"blocked name over Unbound's own DoT again: {dot}\n{raw}"
