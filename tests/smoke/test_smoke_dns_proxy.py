"""Issue #3515: pfB-DNS, the experimental DNS proxy, driven the way an operator drives it, proven live.

pfB-DNS (``dns/pfb_dns``, the pfB-DNS tab) moves the DNS Resolver onto loopback (its port stays 53, so the firewall
keeps resolving through it) and runs pfBlockerNG's DNS proxy on the Resolver's client-facing addresses. It is
independent of DNSBL: with DNSBL on the proxy answers DNSBL decisions itself (the SHIPPED ``pfb_unbound.py`` through
its Unbound API shim) and forwards every other query to Unbound on loopback 5353 with a PROXYv2 header; with DNSBL off
it boots no module and forwards every query. Unbound runs the inert ``pfb_upstream_observer.py`` in every pfB-DNS
mode, because pfSense runs the start hook ``<python_script>_include.inc`` only for a python script, and that hook
starts the proxy in boot. This module sets the real config keys, runs the real apply (``pfb_trigger scope=dnsbl``)
and watches the box and a LAN client VM, with no hand-made proxy process and no hand-edited ``unbound.conf``.

Module setup, put back in ``finally``::

    Resolver: DoT on with a self-signed certificate, ``log-queries: yes`` in Custom Options (which starts with the
              ``server:`` clause pfSense documents), Listen Port and Network Interfaces absent (their defaults)
    LAN:      a static IPv6 address (the IPv6 locality tests' 2001:db8:51:1::1/64), so pfSense grants the LAN's IPv6
              subnet to Unbound clients
    DNSBL:    one feed listing the test names, Group Policy on with 192.168.1.12 on the bypass list

What it proves, in file order:

* pfB-DNS off, DNSBL on (devel's behaviour): Unbound hosts the python module and listens on 53 and 853 (the baseline
  every "not any more" below is measured against);
* pfB-DNS on, DNSBL on + apply: config.xml shows the Resolver moved (interfaces, DoT, Custom Options; NOT the port) and
  the snapshot, ``unbound.conf`` never loads ``pfb_unbound.py``, Unbound listens on loopback 5353 and 5354 only (our
  clause's ``port: 5354``), service ``pfb_dns_proxy`` runs under ``daemon -t``, the proxy owns 53/853 on the LAN address
  and 53 on loopback;
* the firewall resolves through the proxy: ``/etc/resolv.conf`` still names 127.0.0.1 after pfSense regenerates
  it, and the firewall's own lookup of a listed name is answered with the DNSBL VIP and logged;
* pfSense's IPv6 grant for the LAN subnet disappears from its generated ``access_lists.conf`` with the Resolver on
  loopback, and the same ``access-control`` row is in our marked ``custom_options`` clause instead (so IPv6 clients
  relayed by the proxy are not REFUSED); no IPv6 client query is sent: the client VM has no IPv6 address on the LAN,
  and ``DnsProxyAclTest`` pins the derivation;
* from the LAN client (192.168.1.10): a listed name gets the VIP and a feed-attributed ``dnsbl.log`` row, an allowed
  name gets the upstream's answer and ``resolver.log`` names the client, the same over TCP and over DoT with the
  Resolver's certificate; a Group Policy bypassed address (192.168.1.12, an alias on the client) and the filtered
  client asking for the same names at the same moment each get their own answer (the #3508 shape);
* the Alerts page's whitelist reload takes the zero-downtime swap: neither the proxy nor Unbound restarts;
* pfB-DNS on, DNSBL off: the proxy runs with ``--no-module``, Unbound has no ``pfb_unbound.py`` (only the inert
  observer), a listed name is NOT blocked (UDP, TCP, DoT), Unbound's log names the real client, the firewall's own
  lookup goes through the proxy (Unbound has no socket on 53), and no DNSBL decision is logged;
* pfB-DNS on, DNSBL off, DNS Reply Logging on (the pfB-DNS tab's preference, ``dnsbl/pfb_py_reply``): the proxy
  runs with ``--no-module --reply-log``, a LAN client's query is answered and dns_reply.log and unified.log (the
  Reports and Stats pipeline) each gain one row naming the client, the name, the type and the upstream's answer, and
  dnsbl.log none; with the preference off the proxy runs without ``--reply-log``, answers the same and no row is
  written;
* a Resolver restart (the GUI's apply) brings a stopped proxy back through the observer's start hook;
* a reboot, once with DNSBL off and once on: a bounded probe the test plants in /etc/rc.custom_boot_early asks the proxy
  on 127.0.0.1:53 from early boot (a listed name and a name nobody asked before, the upstream a stub on the host). Its
  first correct answers come before ``rc.start_packages`` begins (a "DNS proxy started" log line is a launch, not an
  answer), the package stage neither restarts the proxy nor drops a query, the times of the launch, the listening
  socket, the first answers and Unbound's sync are printed apart, and a lookup from the box right after boot succeeds;
* pfB-DNS off + apply: the proxy and its pidfiles are gone, every Resolver key is back to its pre-toggle value (absent
  stays absent), the marker is cleared, the module is back in ``unbound.conf``, Unbound is on 53 and 853 again.

The pfB-DNS tab (enable checkbox, help that says it is experimental, status panel) is covered by the Tier A render
test ``test_pfb_dns_page_renders_the_toggle_the_experimental_help_and_the_status``
(tests/smoke/ui/test_render_smoke.py) and the toggle flow ``pfb_dns``
(tests/smoke/ui/test_functional.py).

Every test asks ``proxy_on`` for pfB-DNS to be on and turns it on (one apply) if an earlier test left it off.

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

CFG_PFB_DNS = "installedpackages/pfblockerngdns/config/0"  # the pfB-DNS section: local, not synced
CFG_PROXY = f"{CFG_PFB_DNS}/pfb_dns"
CFG_MARKER = f"{CFG_PFB_DNS}/pfb_dns_saved"
CFG_DNSBL = f"{h.CFG_DNSBL_SETTINGS}/pfb_dnsbl"
CFG_GROUP_POLICY = f"{h.CFG_DNSBL_SETTINGS}/pfb_gp"
CFG_GROUP_POLICY_LIST = f"{h.CFG_DNSBL_SETTINGS}/pfb_gp_bypass_list"
CFG_WHITELIST = f"{h.CFG_DNSBL_SETTINGS}/whitelist"
CFG_FORWARDING = "unbound/forwarding"  # present (on) while the Resolver forwards to the System DNS server
OBSERVER_SCRIPT = "pfb_upstream_observer.py"  # Unbound's python-script in proxy mode while it forwards

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
DNS_PORTS = (53, 853, 5353, 5354)
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
    CFG_DNSBL,
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
    firewall: str  # listed; only the firewall's own lookups ask for it
    dnsbl_off_client: str  # listed; only the DNSBL-off test asks for it, from the client
    dnsbl_off_firewall: str  # listed; only the DNSBL-off test asks for it, from the firewall
    boot_probe: str  # listed; only the early-boot probe asks for it


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
    """The pfB-DNS tab's save, minus the page: the registered toggle token, 'on' or the empty Off token."""
    _php_ok(
        vm,
        f"config_set_path({h._php_str(CFG_PROXY)}, {h._php_str('on' if on else '')});\n"
        f"write_config('pfBlockerNG smoke: pfB-DNS toggle {'on' if on else 'off'}');",
        "pfB-DNS toggle",
    )


def _set_dnsbl(vm: SmokeVM, on: bool) -> None:
    """The DNSBL tab's enable checkbox, minus the page: the registered toggle token, 'on' or the empty Off token."""
    _php_ok(
        vm,
        f"config_set_path({h._php_str(CFG_DNSBL)}, {h._php_str('on' if on else '')});\n"
        f"write_config('pfBlockerNG smoke: DNSBL {'on' if on else 'off'} for the #3515 smoke');",
        "DNSBL toggle",
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
        marker=_xml_text(root, "installedpackages/pfblockerngdns/config/pfb_dns_saved") or "",
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
        firewall=h.unique_domain("firewall"),
        dnsbl_off_client=h.unique_domain("dnsbloff"),
        dnsbl_off_firewall=h.unique_domain("dnsbloff-fw"),
        boot_probe=h.unique_domain("bootprobe-listed"),
    )
    listed = (
        names.blocked,
        names.whitelisted,
        names.firewall,
        names.dnsbl_off_client,
        names.dnsbl_off_firewall,
        names.boot_probe,
        *names.group_policy,
    )
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
    assert lines[start + 1 : start + 5] == [
        "port: 5354",
        f"interface: 127.0.0.1@{UPSTREAM_PORT}",
        f"interface: ::1@{UPSTREAM_PORT}",
        PROXY_LINE,
    ]
    grants = lines[start + 5 : end]
    assert all(re.fullmatch(r"access-control: \S+ allow", row) for row in grants), f"Custom Options: {options!r}"
    assert lines[end + 1 :] == [], f"nothing follows our block: {options!r}"
    assert state.marker, "pfb_dns_proxy_saved is empty after the toggle moved the Resolver"
    saved = json.loads(base64.b64decode(state.marker))
    expected = {key: {"present": before.resolver[key] is not None, "value": before.resolver[key]} for key in MOVED_KEYS}
    assert saved == expected, f"snapshot in the marker:\n{saved}\nResolver before the toggle:\n{expected}"


def test_toggle_on_leaves_unbound_on_loopback_5353_and_5354_only(rig: Rig, proxy_on: State) -> None:
    """Unbound moves off the Resolver's port onto loopback 5354 (plain) and 5353 (PROXYv2); the clause did it.

    Then unbound.conf has `port: 5354` in our marked clause and never `python-script: pfb_unbound.py` (with
      forwarding on it runs the upstream observer instead; the observer test pins that); the Unbound DNS sockets are
      exactly loopback 5353 and 5354, IPv4 and IPv6, UDP and TCP, none on 53, 853 or any LAN address (loopback 53
      is the proxy's); And the running Unbound reports proxy-protocol-port 5353.
    """
    assert "pfb_unbound.py" not in proxy_on.conf, f"unbound.conf still loads pfb_unbound.py:\n{proxy_on.conf}"
    assert re.search(r"^port:\s*5354\s*$", proxy_on.conf, re.MULTILINE), (
        f"no `port: 5354` in unbound.conf:\n{proxy_on.conf}"
    )
    sockets = proxy_on.unbound_dns()
    _say(f"Unbound DNS sockets, toggle on: {sorted(sockets)}")
    wanted = {
        (f"{transport}{family}", f"{host}:{port}")
        for transport in ("udp", "tcp")
        for family, host in (("4", "127.0.0.1"), ("6", "::1"))
        for port in (5354, int(UPSTREAM_PORT))
    }
    assert wanted <= sockets, f"missing Unbound sockets: {sorted(wanted - sockets)}; has {sorted(sockets)}"
    stray = {(proto, local) for proto, local in sockets if not re.fullmatch(r"(127\.0\.0\.1|::1):(5353|5354)", local)}
    assert not stray, f"Unbound listens beyond loopback 5353 and 5354: {sorted(stray)} (all: {sorted(sockets)})"
    option = rig.vm.ssh(f"/usr/local/sbin/unbound-control -c {h.UNBOUND_CONF} get_option proxy-protocol-port 2>&1")
    assert option.stdout.strip() == UPSTREAM_PORT, f"unbound-control get_option proxy-protocol-port: {option.stdout!r}"


def test_toggle_on_runs_the_proxy_as_a_supervised_service_on_53_and_853(rig: Rig, proxy_on: State) -> None:
    """Service pfb_dns_proxy runs under daemon(8) with its ps title, and owns the client-facing ports.

    Then Status > Services says `pfb_dns_proxy` runs; the supervisor's ps title is `daemon: pfb_dns_proxy[<pid>]`
      (daemon `-t`); the child is the proxy script, run as `unbound`, with `--dot` (the saved Resolver had DoT);
      the proxy holds UDP and TCP 53 on the LAN's IPv4 and IPv6 addresses and on loopback (127.0.0.1 and ::1: the
      firewall's own resolver entry), and TCP 853 on the LAN address.
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
    wanted |= {(proto, "127.0.0.1:53") for proto in ("udp4", "tcp4")}
    wanted |= {(proto, "::1:53") for proto in ("udp6", "tcp6")}
    wanted.add(("tcp4", f"{PFSENSE_LAN_IP}:853"))
    assert wanted <= sockets, f"missing proxy sockets: {sorted(wanted - sockets)}; has {sorted(sockets)}"


def test_forwarding_on_gives_unbound_the_upstream_observer_never_the_module(rig: Rig, proxy_on: State) -> None:
    """In proxy mode Unbound runs the upstream observer while the Resolver forwards; pfb_unbound.py stays out.

    Given the Resolver forwards to the System DNS server (the rig's wiring) and the toggle is applied,
    Then unbound.conf loads the python module with `python-script: pfb_upstream_observer.py` as its only script,
      never `pfb_unbound.py`, and the observer is staged in the chroot beside the shipped module.
    """
    scripts = re.findall(r"^\s*python-script\s*:\s*(\S+)", proxy_on.conf, re.MULTILINE)
    assert scripts == [OBSERVER_SCRIPT], f"python-script lines: {scripts}\n{proxy_on.conf}"
    assert MODULE_LINE.search(proxy_on.conf), f"the python module is not in the module chain:\n{proxy_on.conf}"
    assert "pfb_unbound.py" not in proxy_on.conf, f"unbound.conf names pfb_unbound.py:\n{proxy_on.conf}"
    staged = rig.vm.ssh(f"ls -l /var/unbound/{OBSERVER_SCRIPT} /var/unbound/pfb_unbound.py 2>&1").stdout
    assert OBSERVER_SCRIPT in staged and "No such file" not in staged, f"staged files: {staged}"


def test_forwarding_off_still_gives_unbound_the_inert_observer(rig: Rig, proxy_on: State) -> None:
    """With the Resolver recursing there is no upstream block to observe, yet Unbound keeps the observer script.

    Given the toggle applied and the Resolver switched from forwarding to recursion,
    When the DNSBL apply runs,
    Then unbound.conf still names `pfb_upstream_observer.py` as its only python-script (it stays inert: the proxy
      does not listen for reports) and never pfb_unbound.py: pfSense's start hook is looked up by that name, so
      dropping it would drop pfB-DNS from the boot; the forwarding setting is put back afterwards.
    """
    vm = rig.vm
    original = h.config_get_state(vm, CFG_FORWARDING)
    try:
        _php_ok(
            vm,
            "config_del_path('unbound/forwarding');\n"
            "write_config('pfBlockerNG smoke: Resolver recursing for the #3515 observer gate');\n"
            "services_unbound_configure(FALSE);",
            "Resolver forwarding off",
        )
        _apply(vm)
        state = _capture(vm)
        scripts = re.findall(r"^\s*python-script\s*:\s*(\S+)", state.conf, re.MULTILINE)
        assert scripts == [OBSERVER_SCRIPT], f"python-script lines: {scripts}\n{state.conf}"
        assert "pfb_unbound.py" not in state.conf, state.conf
        child = state.ps_line(state.proxy_pid)
        assert "--observer" not in child, f"the proxy listens for reports while the Resolver recurses: {child!r}"
    finally:
        h.config_restore_state(vm, CFG_FORWARDING, original)
        _php_ok(vm, "services_unbound_configure(FALSE);", "Resolver forwarding restored")
        _apply(vm)
    restored = _capture(vm)
    assert re.findall(r"^\s*python-script\s*:\s*(\S+)", restored.conf, re.MULTILINE) == [OBSERVER_SCRIPT], restored.conf
    assert "--observer" in restored.ps_line(restored.proxy_pid), restored.ps


def test_an_upstream_ede_block_is_logged_with_the_real_client(
    rig: Rig, proxy_on: State, stub_dns: _StubDnsServer
) -> None:
    """A block the upstream signals with EDE 15 is invisible in Unbound's reply; the observer makes it loggable.

    Given the stub upstream answers a unique name with NXDOMAIN and an EDE option (info-code 15, text `Quad9`),
    When the LAN client queries it through the proxy,
    Then the client gets NXDOMAIN, and dnsbl.log gains the module's upstream-block row: source DNSBL-python, type
      Upstream_Block, group Upstream, evaluation `EDE15 (Blocked)`, the extra text, and the client's own address.
    """
    name = h.unique_domain("pfbsmoke-3515-ede")
    stub_dns.register_nxdomain(name, ede_info_code=15, ede_text="Quad9")
    answer, raw = _query(rig.client, name)
    assert answer.rcode == "NXDOMAIN", f"{name}: expected NXDOMAIN from the upstream, got {answer}\n{raw}"

    def upstream_rows() -> list[list[str]]:
        return [row for row in _dnsbl_rows(rig.vm, name) if row[5:6] == ["Upstream_Block"]]

    try:
        h.wait_until(lambda: bool(upstream_rows()), timeout=30.0)
    except RuntimeError:
        raise AssertionError(f"dnsbl.log gained no Upstream_Block row for {name}:\n{_proxy_log(rig.vm)}") from None
    [row] = upstream_rows()
    assert row[0] == "DNSBL-python" and row[6] == "Upstream", row
    assert row[7] == "EDE15 (Blocked)" and row[8] == "Quad9", f"evaluation / extra text: {row}"
    assert row[3] == CLIENT_LAN_IP, f"the row names {row[3]!r}, not the real client {CLIENT_LAN_IP}: {row}"


def _firewall_lookup(vm: SmokeVM, name: str) -> str:
    """What the firewall's OWN resolver (gethostbyname, i.e. /etc/resolv.conf) answers for `name`."""
    out = _php_ok(vm, f"echo 'FW=' . gethostbyname({h._php_str(name + '.')}) . ';';", "firewall lookup")
    match = re.search(r"FW=([^;]*);", out)
    assert match, f"no answer line in the firewall lookup output: {out!r}"
    return match.group(1)


def test_the_firewalls_own_lookups_go_through_the_proxy_and_are_dnsbl_filtered(rig: Rig, proxy_on: State) -> None:
    """The firewall's own lookups reach the proxy on loopback 53, so DNSBL filters them.

    When pfSense regenerates /etc/resolv.conf (a reboot, a WAN event, a settings save do the same),
    Then it still names 127.0.0.1 (pfSense lists it while the Resolver's port is 53 and lo0 is bound: both stay);
      And the firewall's lookup of a listed name (resolv.conf, then drill @127.0.0.1) gets the DNSBL VIP, and
      dnsbl.log gains a row for it that names 127.0.0.1 as the client.
    """
    _php_ok(rig.vm, "require_once('system.inc');\nsystem_resolvconf_generate();", "system_resolvconf_generate")
    resolv = rig.vm.ssh("cat /etc/resolv.conf").stdout
    assert re.search(r"^nameserver\s+127\.0\.0\.1\s*$", resolv, re.MULTILINE), f"/etc/resolv.conf:\n{resolv}"
    name = rig.names.firewall
    answer = _firewall_lookup(rig.vm, name)
    assert answer == h.DEFAULT_DNSBL_VIP4, f"the firewall's own lookup of the listed {name}: {answer!r}"
    drilled = rig.vm.ssh(f"drill @127.0.0.1 {name} A 2>&1").stdout
    assert h.DEFAULT_DNSBL_VIP4 in drilled, f"drill @127.0.0.1 {name}:\n{drilled}"
    _wait_dnsbl_row(rig.vm, name)
    clients = {row[3] for row in _dnsbl_rows(rig.vm, name)}
    assert clients == {"127.0.0.1"}, f"dnsbl.log rows for {name} name {sorted(clients)}, not the firewall's 127.0.0.1"


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
# pfB-DNS on, DNSBL off: the proxy only forwards
# --------------------------------------------------------------------------- #


def _wait_forwards(rig: Rig, name: str) -> None:
    """Poll until the LAN client gets the upstream's answer for a LISTED name: the proxy forwards and blocks nothing."""

    def forwards() -> bool:
        answer, _ = _query(rig.client, name)
        return h.resolves_to(answer, STUB_DNS_A)

    try:
        h.wait_until(forwards, timeout=240.0, interval=3.0)
    except RuntimeError as exc:
        raise RuntimeError(f"{exc}\n{_diagnostics(rig.vm)}") from exc


@contextlib.contextmanager
def _dnsbl_off(rig: Rig) -> Iterator[State]:
    """pfB-DNS stays on and DNSBL goes off (applied); DNSBL is turned back on and applied afterwards."""
    _set_dnsbl(rig.vm, False)
    try:
        _apply(rig.vm)
        _wait_forwards(rig, rig.names.dnsbl_off_client)
        yield _capture(rig.vm)
    finally:
        _set_dnsbl(rig.vm, True)
        _apply(rig.vm)
        _wait_proxy_serves(rig)


def test_pfb_dns_without_dnsbl_forwards_everything_and_blocks_nothing(rig: Rig, proxy_on: State) -> None:
    """pfB-DNS on + DNSBL off: the proxy takes the client port, boots no module and forwards every query.

    Given pfB-DNS on and DNSBL turned off and applied (the Resolver stays moved: pfB-DNS does not follow DNSBL),
    Then the proxy runs with `--no-module` (and no `--observer`); unbound.conf has no pfb_unbound.py and only the
      inert observer as its python-script; Unbound has no socket on 53, so the firewall's resolv.conf entry 127.0.0.1
      is answered by the proxy;
      And a LISTED name is not blocked: the client gets the upstream's answer over UDP, TCP and DoT, Unbound's query
      log names the real client, and no DNSBL decision reaches dnsbl.log;
      And the firewall's own lookup of another listed name gets the upstream's answer, logged by Unbound as 127.0.0.1.
    """
    vm, client, names = rig.vm, rig.client, rig.names
    with _dnsbl_off(rig) as state:
        assert _is_on(state) and state.marker, f"pfB-DNS is not fronting the Resolver with DNSBL off: {state}"
        child = state.ps_line(state.proxy_pid)
        assert "--no-module" in child and "--observer" not in child, f"proxy command line: {child!r}"
        assert "pfb_unbound.py" not in state.conf, f"unbound.conf names pfb_unbound.py:\n{state.conf}"
        scripts = re.findall(r"^\s*python-script\s*:\s*(\S+)", state.conf, re.MULTILINE)
        assert scripts == [OBSERVER_SCRIPT], f"python-script lines: {scripts}\n{state.conf}"
        on53 = sorted(local for _, local in state.unbound_dns() if local.endswith(":53"))
        assert not on53, f"Unbound still listens on 53: {on53}"

        for how, tcp, dot in (("UDP", False, False), ("TCP", True, False), ("DoT", False, True)):
            answer, raw = _query(client, names.dnsbl_off_client, tcp=tcp, dot=dot)
            assert h.resolves_to(answer, STUB_DNS_A), (
                f"{how}: listed {names.dnsbl_off_client} was blocked: {answer}\n{raw}"
            )
        clients = _wait_unbound_logged(vm, names.dnsbl_off_client)
        assert set(clients) == {CLIENT_LAN_IP}, f"Unbound's query log names {clients}, not the client {CLIENT_LAN_IP}"
        assert _dnsbl_rows(vm, names.dnsbl_off_client) == [], "DNSBL is off: dnsbl.log must gain no row"

        _php_ok(vm, "require_once('system.inc');\nsystem_resolvconf_generate();", "system_resolvconf_generate")
        resolv = vm.ssh("cat /etc/resolv.conf").stdout
        assert re.search(r"^nameserver\s+127\.0\.0\.1\s*$", resolv, re.MULTILINE), f"/etc/resolv.conf:\n{resolv}"
        firewall_answer = _firewall_lookup(vm, names.dnsbl_off_firewall)
        assert firewall_answer == STUB_DNS_A, (
            f"the firewall's lookup of the listed {names.dnsbl_off_firewall}: {firewall_answer!r}"
        )
        firewall_clients = _wait_unbound_logged(vm, names.dnsbl_off_firewall)
        assert set(firewall_clients) == {"127.0.0.1"}, f"Unbound's query log names {firewall_clients}, not 127.0.0.1"
        assert _dnsbl_rows(vm, names.dnsbl_off_firewall) == [], "DNSBL is off: dnsbl.log must gain no row"


# --------------------------------------------------------------------------- #
# DNS Reply Logging with DNSBL off: the one preference both DNS modes read, as the proxy's --reply-log
# --------------------------------------------------------------------------- #

CFG_REPLY_LOG = (
    f"{h.CFG_DNSBL_SETTINGS}/pfb_py_reply"  # the pfB-DNS tab's DNS Reply Logging: 'on', or the empty Off token
)
REPLY_LOG = f"{h.PFB_LOGDIR}/dns_reply.log"
UNIFIED_LOG = (
    f"{h.PFB_LOGDIR}/unified.log"  # the filterlog daemon's copy of dns_reply.log rows: Reports and Stats read it
)


def _put_reply_logging(vm: SmokeVM, value: str | None) -> None:
    """The pfB-DNS tab's save of DNS Reply Logging, minus the page: 'on' or the empty Off token; None puts back an
    absent key."""
    path = h._php_str(CFG_REPLY_LOG)
    op = f"config_del_path({path});" if value is None else f"config_set_path({path}, {h._php_str(value)});"
    _php_ok(vm, f"{op}\nwrite_config('pfBlockerNG smoke: DNS Reply Logging');", "DNS Reply Logging preference")


def _proxy_args(vm: SmokeVM) -> str:
    """The command line of the running proxy child, from its pidfile ('' when none runs)."""
    pid = _pid_file(vm, PROXY_PID_FILE)
    return vm.ssh(f"ps -ww -o args= -p {pid}").stdout.strip() if pid is not None else ""


@contextlib.contextmanager
def _reply_logging(rig: Rig, on: bool) -> Iterator[str]:
    """DNS Reply Logging set and applied (the apply restarts a live proxy whose rc script changed), yielding the proxy's
    command line; the preference as it was (absent stays absent) is put back and applied afterwards."""
    present, prior = h.config_get_state(rig.vm, CFG_REPLY_LOG)
    _put_reply_logging(rig.vm, "on" if on else "")
    try:
        _apply(rig.vm)
        try:
            h.wait_until(lambda: ("--reply-log" in _proxy_args(rig.vm)) == on, timeout=90.0, interval=3.0)
        except RuntimeError as exc:
            raise RuntimeError(f"{exc}\nproxy: {_proxy_args(rig.vm)!r}\n{_diagnostics(rig.vm)}") from exc
        yield _proxy_args(rig.vm)
    finally:
        _put_reply_logging(rig.vm, prior if present else None)
        _apply(rig.vm)


def _reply_rows(vm: SmokeVM, name: str, path: str = REPLY_LOG) -> list[list[str]]:
    """The DNS-reply rows of `name` in dns_reply.log (or unified.log, same ten columns):
    DNS-reply,timestamp,type,orig_type,final_type,ttl,name,client,answer,geoip."""
    rows = csv.reader(io.StringIO(h.read_log_file(vm, path)))
    return [row for row in rows if row[:1] == ["DNS-reply"] and row[6:7] == [name]]


def test_pfb_dns_without_dnsbl_logs_replies_for_the_client_only_while_dns_reply_logging_is_on(
    rig: Rig, proxy_on: State
) -> None:
    """pfB-DNS on + DNSBL off: DNS Reply Logging on gives Reports and Stats the client's replies; off writes nothing.

    Given pfB-DNS on and DNSBL off and applied, and DNS Reply Logging switched on and applied,
    Then the proxy runs with `--no-module --reply-log`; a LAN client's query for a name nobody asked before is
      answered by the upstream, and dns_reply.log gains one row (type reply, A, A, a TTL, the name, the CLIENT's
      address, the upstream's answer) which the filterlog daemon copies into unified.log, the log Reports and Stats
      read; dnsbl.log gains none;
    When DNS Reply Logging is switched off and applied,
    Then the proxy runs without `--reply-log`, a second new name is answered the same way, and neither log has a row
      for it (checked after the answer and Unbound's own query log both name the query: the proxy had finished with it).
    """
    vm, client = rig.vm, rig.client
    logged, silent = h.unique_domain("replylog-on"), h.unique_domain("replylog-off")
    with _dnsbl_off(rig):
        with _reply_logging(rig, True) as args:
            assert "--no-module" in args and "--reply-log" in args and "--observer" not in args, f"proxy: {args!r}"
            answer, raw = _query(client, logged)
            assert h.resolves_to(answer, STUB_DNS_A), f"{logged} was not answered by the upstream: {answer}\n{raw}"
            try:
                h.wait_until(lambda: bool(_reply_rows(vm, logged)), timeout=30.0)
            except RuntimeError:
                raise AssertionError(f"dns_reply.log gained no row for {logged}:\n{_proxy_log(vm)}") from None
            [row] = _reply_rows(vm, logged)
            assert row[2:5] == ["reply", "A", "A"] and row[5].isdigit(), f"row: {row}"
            assert row[6:9] == [logged, CLIENT_LAN_IP, STUB_DNS_A], f"row: {row}"
            try:
                h.wait_until(lambda: bool(_reply_rows(vm, logged, UNIFIED_LOG)), timeout=30.0)
            except RuntimeError:
                raise AssertionError(f"unified.log (Reports, Stats) gained no row for {logged}") from None
            assert _reply_rows(vm, logged, UNIFIED_LOG) == [row], "unified.log keeps the row as it was written"
            assert _dnsbl_rows(vm, logged) == [], "DNSBL is off: dnsbl.log must gain no row"
        with _reply_logging(rig, False) as args:
            assert "--no-module" in args and "--reply-log" not in args, f"proxy: {args!r}"
            answer, raw = _query(client, silent)
            assert h.resolves_to(answer, STUB_DNS_A), f"{silent} was not answered by the upstream: {answer}\n{raw}"
            assert set(_wait_unbound_logged(vm, silent)) == {CLIENT_LAN_IP}
            assert _reply_rows(vm, silent) == [], "DNS Reply Logging is off: dns_reply.log must gain no row"
            assert _reply_rows(vm, silent, UNIFIED_LOG) == [], "and neither must unified.log"
            assert _dnsbl_rows(vm, silent) == [], "DNSBL is off: dnsbl.log must gain no row"


# --------------------------------------------------------------------------- #
# The start hook: pfSense runs <python_script>_include.inc whenever it starts Unbound
# --------------------------------------------------------------------------- #

HOOK = "/var/unbound/pfb_upstream_observer_include.inc"


def test_a_resolver_restart_brings_a_stopped_proxy_back_through_the_start_hook(rig: Rig, proxy_on: State) -> None:
    """services_unbound_configure() (the GUI's apply, a boot) requires the observer's include, which starts the proxy.

    Given pfB-DNS on with the hook staged in the chroot and the proxy stopped,
    When the Resolver is restarted the way the Resolver page's Apply restarts it,
    Then the proxy is running again without any pfBlockerNG apply, and serves.
    """
    vm = rig.vm
    staged = vm.ssh(f"ls -l {HOOK} 2>&1").stdout
    assert "No such file" not in staged, f"the hook is not staged: {staged}"
    _force_stop_proxy(vm)
    gone = _capture(vm)
    assert gone.proxy_pid is None and gone.service == "stopped", f"the proxy is still up: {gone.ps}"
    _php_ok(vm, "services_unbound_configure();", "services_unbound_configure (the Resolver's Apply)")
    h.wait_unbound_ready(vm)
    try:
        h.wait_until(lambda: _pid_file(vm, PROXY_PID_FILE) is not None, timeout=60.0, interval=2.0)
    except RuntimeError:
        raise AssertionError(f"the Resolver restart did not start the proxy:\n{_diagnostics(vm)}") from None
    _wait_proxy_serves(rig)


# The reboot. The test's own SSH session only exists once the boot is over, so the interval that matters (Unbound
# started, packages not yet) is asked about by a probe planted in the one early hook pfSense offers.
EARLY_HOOK = "/etc/rc.custom_boot_early"  # pfSense-rc runs it before rc.bootup: before Unbound and before the packages
PROBE_DIR = "/conf/pfb3515_boot_probe.d"  # /conf is on disk: a RAM-backed /var does not survive the reboot
PROBE_LOG = f"{PROBE_DIR}/log"
PROBE_ORIG = f"{PROBE_DIR}/hook.orig"  # the hook as it was, bytes and mode (PROBE_NO_HOOK exists if it was absent)
PROBE_NO_HOOK = f"{PROBE_DIR}/hook.absent"
PROBE_PROCESS = "pfb3515_boot_probe[.]d/probe[.]sh"  # for pgrep/pkill -f; the brackets keep it off its own command
PROBE_DEADLINE = 300  # s from the hook: the probe exits by then whatever happens
PROBE_GRACE = (
    45  # s the probe keeps asking after rc.start_packages begins: the package rc scripts start in the background
)
BOOT_ID_SLACK = 5  # s: the probe's kern.boottime may differ this much from the one read later
_PROBE_TEMPLATE = r"""#!/bin/sh
# Issue #3515 smoke probe, test-only: /etc/rc.custom_boot_early starts it detached. From early boot it asks the DNS
# proxy on 127.0.0.1:53 for a LISTED name and a never-asked ALLOWED name twice a second and logs what answers, until
# GRACE s after rc.start_packages began or DEADLINE s have passed: it always exits.
DIR=/conf/pfb3515_boot_probe.d
LOG=$DIR/log
DEADLINE=@DEADLINE@
GRACE=@GRACE@
LISTED=${PROBE_LISTED:?}
STEM=${PROBE_STEM:?}
# kern.boottime is "{ sec = N, usec = M } <date>": the first number is N (a greedy "sec = " would catch usec)
BOOT=$(/sbin/sysctl -n kern.boottime | /usr/bin/sed 's/^[^0-9]*\([0-9]*\).*/\1/')
START=$(/bin/date +%s)
n=0 seen_at='' last=''
# rc.start_packages logs this when it begins; system.log outlives a reboot, so count against what it holds now
MARK='Restarting/Starting all packages'
packages() { c=$(/usr/bin/grep -c "$MARK" /var/log/system.log 2>/dev/null); echo "${c:-0}"; }
base=$(packages)
say() { printf '@@ %s boot=%s %s\n' "$(/bin/date +%s)" "$BOOT" "$*" >>"$LOG"; }
# RCODE:addresses of the A answer, NONE:- when nothing answered in 3 s
ask() {
	/usr/bin/timeout 3 /usr/local/bin/drill "$1" A @127.0.0.1 2>/dev/null | /usr/bin/awk '
		/rcode:/ { sub(/.*rcode: */, ""); sub(/,.*/, ""); rc = $0 }
		/^;; ANSWER SECTION/ { ans = 1; next }
		ans && (NF == 0 || /^;;/) { ans = 0 }
		ans && $4 == "A" { a = a (a == "" ? "" : ",") $5 }
		END { print (rc == "" ? "NONE" : rc) ":" (a == "" ? "-" : a) }'
}
# the proxy child ($p) holds 127.0.0.1:53: sockstat columns are USER COMMAND PID FD PROTO LOCAL FOREIGN
held='$3 == p && $6 == "127.0.0.1:53" { f = 1 } END { exit !f }'
say "start pid=$$ deadline=$DEADLINE"
while true; do
	now=$(/bin/date +%s)
	if [ $((now - START)) -ge "$DEADLINE" ]; then say "end reason=deadline"; exit 0; fi
	ub=$(/bin/pgrep -x unbound | /usr/bin/head -n 1)
	px=$(/bin/cat /var/run/pfb_dns_proxy.pid 2>/dev/null)
	dm=$(/bin/cat /var/run/pfb_dns_proxy_daemon.pid 2>/dev/null)
	up=0
	if [ -n "$px" ] && /usr/bin/sockstat -4l -p 53 | /usr/bin/awk -v p="$px" "$held"; then up=1; fi
	pk=0
	if [ -n "$seen_at" ]; then
		pk=1
	elif [ "$(packages)" -gt "$base" ]; then
		pk=1 seen_at=$now
	fi
	cur="unbound=$ub proxy=$px daemon=$dm listening=$up pkg=$pk"
	if [ "$cur" != "$last" ]; then
		age=
		[ -n "$ub" ] && age=$(/bin/ps -o etimes= -p "$ub" | /usr/bin/tr -d ' ')
		say "state $cur unbound_age=$age"
		last=$cur
	fi
	n=$((n + 1))
	a=$STEM-$n.com
	say "query n=$n allowed=$a listed=$(ask "$LISTED") answer=$(ask "$a")"
	if [ -n "$seen_at" ] && [ $((now - seen_at)) -ge "$GRACE" ]; then say "end reason=packages"; exit 0; fi
	/bin/sleep 0.5
done
"""
PROBE_SCRIPT = _PROBE_TEMPLATE.replace("@DEADLINE@", str(PROBE_DEADLINE)).replace("@GRACE@", str(PROBE_GRACE))

BOOT_TIMELINE_PHP = r"""
$boot = 0;
if (preg_match('/sec = (\d+)/', (string) shell_exec('/sbin/sysctl -n kern.boottime'), $m)) { $boot = (int) $m[1]; }
$epochs = function (string $re) use ($boot) {
    $found = array();
    foreach (@file('/var/log/system.log', FILE_IGNORE_NEW_LINES) ?: array() as $line) {
        if (preg_match($re, $line, $m) && ($t = strtotime($m[1])) !== false && $t >= $boot) { $found[] = $t; }
    }
    return $found;
};
$when = '/^(\w{3}\s+\d+\s+[\d:]{8})\s';
echo '<<<TL>>>' . json_encode(array(
    'boot' => $boot,
    'sync_unbound_done' => $epochs($when . '.*sync unbound done/'),
    'daemon_launches' => $epochs($when . '.*pfb_dns_proxy.*DNS proxy started/'),
    'packages_started' => $epochs($when . '.*Restarting\/Starting all packages/'),
)) . '<<<END>>>';
"""


def _boot_timeline(vm: SmokeVM) -> tuple[int, dict[str, list[int]]]:
    """This boot's kern.boottime second, and the epoch seconds of the events in its system log."""
    out = h.php_eval(vm, BOOT_TIMELINE_PHP)
    match = re.search(r"<<<TL>>>(.*?)<<<END>>>", out.stdout, re.DOTALL)
    if out.returncode != 0 or match is None:
        raise RuntimeError(f"boot timeline failed: rc={out.returncode}\nstdout:\n{out.stdout}\nstderr:\n{out.stderr}")
    events = json.loads(match.group(1))
    return events.pop("boot"), events


def _plant_probe_script(listed: str, stem: str) -> str:
    """POSIX sh for the guest: snapshot the hook (bytes and mode), put the probe in /conf, prepend its launcher."""
    launcher = (
        f"/usr/sbin/daemon -f /usr/bin/env PROBE_LISTED={shlex.quote(listed)} PROBE_STEM={shlex.quote(stem)} "
        f"/bin/sh {PROBE_DIR}/probe.sh"
    )
    return (
        "set -e\n"
        "for tool in /usr/local/bin/drill /usr/bin/timeout /usr/bin/sockstat /bin/pgrep /usr/sbin/daemon; do\n"
        '    [ -x "$tool" ] || { echo "missing $tool"; exit 1; }\n'
        "done\n"
        f"mkdir -p {PROBE_DIR}\n"
        f"if [ -e {EARLY_HOOK} ]; then cp -p {EARLY_HOOK} {PROBE_ORIG}; else true > {PROBE_NO_HOOK}; fi\n"
        f"cat > {PROBE_DIR}/probe.sh <<'PROBE_EOF'\n{PROBE_SCRIPT}PROBE_EOF\n"
        f"chmod 755 {PROBE_DIR}/probe.sh\n"
        f"{{ printf '%s\\n' '#!/bin/sh' {shlex.quote(launcher)}; [ ! -e {PROBE_ORIG} ] || cat {PROBE_ORIG}; }}"
        f" > {EARLY_HOOK}\n"
        f"chmod 755 {EARLY_HOOK}\n"
    )


def _unplant_probe_script() -> str:
    """POSIX sh for the guest: kill the probe, put the hook back byte for byte, delete the probe's files."""
    return (
        "rc=0\n"
        f"pkill -KILL -f '{PROBE_PROCESS}'\n"
        f"for i in 1 2 3 4 5; do pgrep -f '{PROBE_PROCESS}' >/dev/null || break; sleep 0.2; done\n"
        f"if pgrep -f '{PROBE_PROCESS}' >/dev/null; then echo 'probe still running'; rc=1; fi\n"
        f"if [ -e {PROBE_NO_HOOK} ]; then\n"
        f"    rm -f {EARLY_HOOK}\n"
        f"    [ ! -e {EARLY_HOOK} ] || {{ echo 'hook not removed'; rc=1; }}\n"
        f"elif [ -e {PROBE_ORIG} ]; then\n"
        f"    cp -p {PROBE_ORIG} {EARLY_HOOK} && cmp -s {PROBE_ORIG} {EARLY_HOOK} \\\n"
        f"        && [ \"$(stat -f '%p %u %g' {PROBE_ORIG})\" = \"$(stat -f '%p %u %g' {EARLY_HOOK})\" ] \\\n"
        "        || { echo 'hook not restored'; rc=1; }\n"
        "fi\n"
        f"rm -rf {PROBE_DIR}\n"
        "exit $rc\n"
    )


@contextlib.contextmanager
def _early_boot_probe(vm: SmokeVM, *, listed: str, stem: str) -> Iterator[None]:
    """Plant the probe in /etc/rc.custom_boot_early; `finally` kills it and puts the hook back as it was."""
    try:
        planted = _sh(vm, _plant_probe_script(listed, stem))
        assert planted.returncode == 0, (
            f"planting the early-boot probe: rc={planted.returncode} {planted.stdout}{planted.stderr}"
        )
        yield
    finally:
        removed = _sh(vm, _unplant_probe_script())
        assert removed.returncode == 0, (
            f"removing the early-boot probe: rc={removed.returncode} {removed.stdout}{removed.stderr}"
        )


def _probe_log(vm: SmokeVM) -> str:
    return vm.ssh("cat", PROBE_LOG).stdout


def _wait_probe_end(vm: SmokeVM) -> None:
    """The probe logs `end` as its last act; it is bounded by PROBE_DEADLINE, so this wait is bounded too."""
    try:
        h.wait_until(
            lambda: re.search(r"^@@ \d+ boot=\d+ end\b", _probe_log(vm), re.MULTILINE) is not None,
            timeout=PROBE_DEADLINE + 60.0,
            interval=3.0,
        )
    except RuntimeError:
        raise AssertionError(f"the early-boot probe did not end:\n{_probe_log(vm)[-4000:]}") from None


# One probe record: (epoch, the kern.boottime second the probe read, kind, key=value fields).
#   start   pid, deadline
#   state   unbound/proxy/daemon pids, listening (the proxy child holds 127.0.0.1:53), pkg (rc.start_packages began),
#           unbound_age (ps etimes of Unbound); written on every change
#   query   n, allowed (the fresh name), listed and answer (RCODE:addresses for the listed and the fresh name)
#   end     reason
ProbeRow = tuple[int, int, str, dict[str, str]]


def _probe_rows(log: str) -> list[ProbeRow]:
    rows: list[ProbeRow] = []
    for line in log.splitlines():
        match = re.fullmatch(r"@@ (\d+) boot=(\d+) (\w+)\s*(.*)", line)
        if match:
            fields = {k: v for k, _, v in (word.partition("=") for word in match[4].split())}
            rows.append((int(match[1]), int(match[2]), match[3], fields))
    return rows


def _answered(answer: str, address: str) -> bool:
    """`RCODE:addr,addr` is a NOERROR answer carrying `address`."""
    rcode, _, addresses = answer.partition(":")
    return rcode == "NOERROR" and address in addresses.split(",")


def _digest(rows: list[ProbeRow]) -> str:
    """The rows as logged, minus the query rows that repeat the answers of the query before them."""
    kept: list[str] = []
    previous: tuple[str | None, str | None] | None = None
    for epoch, boot, kind, fields in rows:
        shape = (fields.get("listed"), fields.get("answer"))
        if kind == "query":
            if shape == previous:
                continue
            previous = shape
        kept.append(f"@@ {epoch} boot={boot} {kind} " + " ".join(f"{k}={v}" for k, v in fields.items()))
    return "\n".join(kept)


@dataclass(frozen=True)
class BootProbe:
    """What the early probe established about one boot (epoch seconds)."""

    ready: int  # the first record whose answers were all correct
    ready_name: str  # its fresh name
    listening: int  # the first sample that found the proxy child on 127.0.0.1:53
    unbound_start: int | None  # first sight of the Unbound serving at `ready`, minus its age; None when ps gave no age
    pids: tuple[str, str]  # proxy child, supervisor: the same in every sample from `listening` to the end
    packages_seen: int  # the first sample after rc.start_packages logged that it began


def _judge_boot_probe(log: str, *, boot: int, packages: int, listed_address: str, upstream_address: str) -> BootProbe:
    """Raise AssertionError unless the probe saw correct answers before `packages` and an undisturbed proxy after."""
    rows = _probe_rows(log)
    assert rows and rows[0][2] == "start", f"the early-boot probe never started; its log:\n{log}"
    digest = _digest(rows)
    assert all(abs(row[1] - boot) <= BOOT_ID_SLACK for row in rows), (
        f"records of another boot (this one began at {boot}):\n{digest}"
    )
    assert rows[-1][2] == "end", f"the early-boot probe did not finish:\n{digest}"
    queries = [row for row in rows if row[2] == "query"]
    states = [row for row in rows if row[2] == "state"]

    def served(row: ProbeRow) -> bool:
        return _answered(row[3].get("listed", ""), listed_address) and _answered(
            row[3].get("answer", ""), upstream_address
        )

    ready = next((row for row in queries if served(row)), None)
    assert ready is not None, f"none of {len(queries)} probe queries was answered as expected:\n{digest}"
    assert ready[0] < packages, (
        f"the first correct answers came at boot+{ready[0] - boot} s, not before rc.start_packages began at "
        f"boot+{packages - boot} s:\n{digest}"
    )
    heard = next((i for i, row in enumerate(states) if row[3].get("listening") == "1"), None)
    assert heard is not None and states[heard][0] <= ready[0], (
        f"the probe never saw the proxy listening by the first answers:\n{digest}"
    )
    pair = (states[heard][3].get("proxy", ""), states[heard][3].get("daemon", ""))
    disturbed = [
        row
        for row in states[heard:]
        if (row[3].get("proxy"), row[3].get("daemon"), row[3].get("listening")) != (*pair, "1")
    ]
    assert not disturbed, (
        f"the proxy (child, supervisor) {pair} was listening, then the probe saw {len(disturbed)} other state(s) "
        f"before it ended (query rows that repeat the answers before them are left out):\n{digest}"
    )
    began = next((row for row in states if row[3].get("pkg") == "1"), None)
    assert began is not None, f"the probe never saw rc.start_packages begin:\n{digest}"
    failed = [row for row in queries[queries.index(ready) :] if not served(row)]
    assert not failed, f"{len(failed)} quer(ies) failed after the first correct answers, first {failed[0]}:\n{digest}"
    assert rows[-1][3].get("reason") == "packages", (
        f"the probe hit its deadline before it had watched the package stage for {PROBE_GRACE} s:\n{digest}"
    )
    unbound = [
        row
        for row in states
        if row[0] <= ready[0] and row[3].get("unbound") and row[3].get("unbound_age", "").isdigit()
    ]
    return BootProbe(
        ready=ready[0],
        ready_name=ready[3]["allowed"],
        listening=states[heard][0],
        unbound_start=unbound[-1][0] - int(unbound[-1][3]["unbound_age"]) if unbound else None,
        pids=pair,
        packages_seen=began[0],
    )


def _boot_report(boot: int, probe: BootProbe, events: dict[str, list[int]]) -> str:
    """Each event on its own line, as seconds since kern.boottime; an interval only where both ends were observed."""

    def at(epoch: int | None) -> str:
        return "unknown" if epoch is None else f"boot+{epoch - boot} s"

    until = "unknown" if probe.unbound_start is None else f"{probe.ready - probe.unbound_start} s"
    return (
        f"daemon launch, system.log (not serving): {[at(e) for e in events['daemon_launches']]}\n"
        f"Unbound process start (probe: first sight of its pid minus ps etimes): {at(probe.unbound_start)}\n"
        f"proxy listening on 127.0.0.1:53 (probe: first sample that found it): {at(probe.listening)}\n"
        f"first correct answers (probe asks twice a second): {at(probe.ready)}\n"
        f"sync unbound done, system.log: {[at(e) for e in events['sync_unbound_done']]}\n"
        f"rc.start_packages begins, system.log: {[at(e) for e in events['packages_started']]}\n"
        f"rc.start_packages marker first seen by the probe: {at(probe.packages_seen)}\n"
        f"Unbound process start to first correct answers: {until}\n"
        f"proxy pids (child, supervisor) from listening to the end of the probe: {probe.pids}"
    )


@pytest.mark.timeout(1500)
@pytest.mark.parametrize("dnsbl_on", [False, True], ids=["dnsbl-off", "dnsbl-on"])
def test_after_a_reboot_the_proxy_answers_before_the_packages_start_and_the_package_stage_leaves_it_be(
    rig: Rig, proxy_on: State, stub_dns: _StubDnsServer, dnsbl_on: bool
) -> None:
    """pfSense starts Unbound in rc.bootup, the packages later: pfB-DNS must answer in between, and keep answering.

    Given pfB-DNS on, with DNSBL on or off, applied, and a bounded probe in /etc/rc.custom_boot_early that asks
      127.0.0.1:53 from early boot for a listed name and for a fresh allowed name (the upstream is a stub on the host),
    When the firewall reboots,
    Then the probe's first correct answers are logged before `Restarting/Starting all packages` (rc.start_packages):
      the DNSBL VIP for the listed name with DNSBL on, the upstream's address for it with DNSBL off, and with both
      the upstream's address for the fresh name, which the stub saw; a `DNS proxy started` line is a launch and does
      not count;
      And from the first answers to the end of the probe (45 s after rc.start_packages began, which covers the package
      rc scripts it launches in the background) the proxy keeps its child and supervisor pids, stays on 127.0.0.1:53,
      and no probe query fails;
      And the launch, the listening socket, the first answers and Unbound's sync are reported as separate times;
      And the Resolver is still moved and the proxy runs, and a lookup from the firewall after the boot succeeds
      through the proxy (the upstream's answer with DNSBL off, the DNSBL VIP for a listed name with it on), and so
      does the client's.
    """
    vm = rig.vm
    expected = h.DEFAULT_DNSBL_VIP4 if dnsbl_on else STUB_DNS_A
    stem = h.unique_domain("bootprobe").removesuffix(".com")  # the probe asks <stem>-<n>.com, a new name every time
    _set_dnsbl(vm, dnsbl_on)
    try:
        _apply(vm)
        if dnsbl_on:
            _wait_proxy_serves(rig)
        else:
            _wait_forwards(rig, rig.names.dnsbl_off_client)
        with _early_boot_probe(vm, listed=rig.names.boot_probe, stem=stem):
            h.reboot_vm(vm)
            _wait_probe_end(vm)
            log = _probe_log(vm)
        boot, events = _boot_timeline(vm)
        assert events["packages_started"], f"no `Restarting/Starting all packages` line this boot: {events}"
        probe = _judge_boot_probe(
            log,
            boot=boot,
            packages=events["packages_started"][0],
            listed_address=expected,
            upstream_address=STUB_DNS_A,
        )
        state = _capture(vm)
        upstream_saw = stub_dns.received(probe.ready_name)
        _say(
            f"boot timeline, DNSBL {'on' if dnsbl_on else 'off'} (kern.boottime {boot}):\n"
            f"{_boot_report(boot, probe, events)}\n"
            f"proxy pids after the package stage (pid files): {(state.proxy_pid, state.daemon_pid)}\n"
            f"the upstream stub saw {probe.ready_name}: {upstream_saw}\n"
            f"probe records (query rows that repeat the answers before them left out):\n{_digest(_probe_rows(log))}"
        )
        assert upstream_saw, f"the upstream never saw {probe.ready_name}, so the answer was not its own"
        assert (str(state.proxy_pid), str(state.daemon_pid)) == probe.pids, (
            f"proxy pids after the package stage (child, supervisor) {(state.proxy_pid, state.daemon_pid)}, "
            f"while it was listening before it {probe.pids}"
        )
        assert _is_on(state) and state.marker, f"pfB-DNS is not in place after the reboot: {state}"
        if dnsbl_on:
            name = rig.names.firewall
            _wait_proxy_serves(rig)
        else:
            name = rig.names.dnsbl_off_firewall
            _wait_forwards(rig, rig.names.dnsbl_off_client)
        answer = _firewall_lookup(vm, name)
        assert answer == expected, f"the firewall's own lookup of {name} after the reboot: {answer!r}, not {expected}"
    finally:
        if not dnsbl_on:
            _set_dnsbl(vm, True)
            _apply(vm)
            _wait_proxy_serves(rig)


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
