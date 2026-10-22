"""Issue #3515: pfB-DNS, the experimental DNS proxy, driven the way an operator drives it, proven live.

pfB-DNS (``dns/pfb_dns``, the pfB-DNS tab) moves the DNS Resolver onto loopback (its port stays 53, so the firewall
keeps resolving through it) and runs the Go gateway ``pfb-dns`` on the Resolver's client-facing addresses; its child,
the Python decider, answers the DNSBL decisions. It is independent of DNSBL: with DNSBL on the decider answers DNSBL
decisions itself (the SHIPPED ``pfb_unbound.py`` through its Unbound API shim) and the gateway forwards every other
query to Unbound on loopback 5353 with a PROXYv2 header; with DNSBL off the decider boots no module and every query is
forwarded. Unbound runs the inert ``pfb_upstream_observer.py`` in every pfB-DNS mode, because pfSense runs the start
hook ``<python_script>_include.inc`` only for a python script, and that hook starts the gateway in boot. This module
sets the real config keys, runs the real apply (``pfb_trigger scope=dnsbl``) and watches the box and a LAN client VM,
with no hand-made process and no hand-edited ``unbound.conf``.

Module setup, put back in ``finally``::

    Resolver: DoT on with a self-signed certificate, ``log-queries: yes`` in Custom Options (which starts with the
              ``server:`` clause pfSense documents), Listen Port and Network Interfaces absent (their defaults)
    LAN:      a static IPv6 address (the IPv6 locality tests' 2001:db8:51:1::1/64), so pfSense grants the LAN's IPv6
              subnet to Unbound clients
    DNSBL:    one feed listing the test names, Group Policy on with 192.168.1.12 on the bypass list
    Package:  the installed ``dns_proxy/bin`` (the pfb-dns payload) is asserted present: pfB-DNS runs only through
              the Go gateway, whose decider is the Python process, and a package without it cannot start it

What it proves, in file order:

* pfB-DNS off, DNSBL on (devel's behaviour): Unbound hosts the python module and listens on 53 and 853 (the baseline
  every "not any more" below is measured against);
* pfB-DNS on, DNSBL on + apply: config.xml shows the Resolver moved (interfaces, DoT, Custom Options; NOT the port) and
  the snapshot, ``unbound.conf`` never loads ``pfb_unbound.py``, Unbound listens on loopback 5353 and 5354 only (our
  clause's ``port: 5354``); the service, its processes and sockets, the observer, the firewall's own lookups and the
  client's queries over every transport are test_smoke_dns_gateway.py's;
* pfSense's IPv6 grant for the LAN subnet disappears from its generated ``access_lists.conf`` with the Resolver on
  loopback, and the same ``access-control`` row is in our marked ``custom_options`` clause instead (so IPv6 clients
  relayed by the proxy are not REFUSED); no IPv6 client query is sent: the client VM has no IPv6 address on the LAN,
  and ``DnsProxyAclTest`` pins the derivation;
* from the LAN client (192.168.1.10): a listed name gets the VIP and a feed-attributed ``dnsbl.log`` row, and Unbound
  never sees it; a Group Policy bypassed address (192.168.1.12, an alias on the client) and the filtered client asking
  for the same names at the same moment each get their own answer (the #3508 shape);
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
* readiness: a serving proxy has published its ready marker (``/var/unbound/pfb_dns_ready``: its own child pid, mode
  600, owned by unbound) and a healthy second ``start`` changes neither pids nor marker; ``lockf`` hands the start
  lock to the one run of the rc script and not to the daemon it launches (the lock is free while the proxy runs); two
  ``start`` verbs racing leave exactly one supervisor and one child, and the same race without the lock is printed as
  evidence;
* pfB-DNS off + apply: the proxy and its pidfiles are gone, every Resolver key is back to its pre-toggle value (absent
  stays absent), the marker is cleared, the module is back in ``unbound.conf``, Unbound is on 53 and 853 again;
* a failed activation: pfB-DNS requested, the Resolver already moved, every address the proxy would serve held by nc(1)
  on the guest, then the real apply: the proxy cannot bind and never becomes ready, pfB-DNS is turned off, the Resolver
  and Unbound are back exactly as before the toggle, and the client's listed name still gets the VIP from Unbound.
* a decision service that exits before READY at every start (issue #3561): the supervisor waiting out its restart
  delay still names pfb_dns_proxy and the rc stop ends it; started by the Resolver's start hook, with the package's
  service entry registered or absent (an install's window, where pfSense's stop_service() does nothing), the real
  apply's rollback leaves no supervisor, the Resolver as before the toggle and the snapshot marker empty.
* a restore that config.xml refuses (issue #3561's recovery): with the package's service entry absent and a process
  whose write_config() answers -1, pfb_dns_proxy_resolver(FALSE) stops the proxy, abandons the restore (the snapshot and
  the moved Resolver stay in config.xml) and starts the proxy again through its rc script: a new child publishes the
  ready marker, pfb-dns alone holds port 53 on the LAN address and the client's listed name gets the VIP.
* issue #3566, staying up across updates: a package upgrade and the update pass after it restart neither the
  gateway, its supervisor nor its decider and no query for a listed name goes unanswered; a changed decider module
  restarts the decider alone; a changed gateway binary restarts the pair once.

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
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

import pytest

from . import helpers as h
from .conftest import CLIENT_LAN_IP, PFSENSE_LAN_IP, STUB_DNS_A, SmokeVM, _StubDnsServer
from .test_repo_install import (
    NETGATE_REPO_NAME,
    OURS_REPO_NAME,
    PKG_NAME,
    REPO_CONF,
    UPGRADE_REPO_DIR,
    build_guest_repo,
    pkg_installed_version,
    read_compact_version,
    repo_priority,
    reversion_pkg,
    write_repo_conf,
)

pytestmark = [pytest.mark.smoke, pytest.mark.timeout(180)]

PROXY_PID_FILE = "/var/run/pfb_dns_proxy.pid"  # the gateway, pfb-dns exec'd by pfb_dns.sh (daemon -p)
DAEMON_PID_FILE = "/var/run/pfb_dns_proxy_daemon.pid"  # its supervisor (daemon -P)
# the package's pfb-dns binaries, one directory per architecture
PAYLOAD_DIR = "/usr/local/pkg/pfblockerng/dns_proxy/bin"
PROXY_LOG = f"{h.PFB_LOGDIR}/dns_proxy.log"
PROXY_RC = "/usr/local/etc/rc.d/pfb_dns_proxy.sh"
SERVICE = "pfb_dns_proxy"
CONFIG_XML = "/cf/conf/config.xml"
RESOLVER_LOG = "/var/log/resolver.log"
DNSBL_LOG = f"{h.PFB_LOGDIR}/dnsbl.log"
# on the guest: survives a dead test process and the reboot test (pfSense CE 2.9 empties /tmp at boot, CE 2.8 does not)
SNAPSHOT_FILE = "/var/tmp/pfb3515_cfg_snapshot.json"
CERT_GUEST = "/tmp/pfb3515_cert.pem"
CERT_CLIENT = "/tmp/pfb3515_ca.pem"

CFG_PFB_DNS = "installedpackages/pfblockerngdns/config/0"  # the pfB-DNS section: local, not synced
CFG_PROXY = f"{CFG_PFB_DNS}/pfb_dns"
CFG_MARKER = f"{CFG_PFB_DNS}/pfb_dns_saved"
# pfB-DNS's own listener settings: the interface lists, whose emptiness (pfb_dns_interface first) marks them unseeded,
# and what the first turn-on seeds from the Resolver beside them.
LISTENER_LISTS = ("pfb_dns_interface", "pfb_dns_dot_interface", "pfb_dns_doh_interface", "pfb_dns_doq_interface")
LISTENER_KEYS = (*LISTENER_LISTS, "pfb_dns_dot", "pfb_dns_dot_port", "pfb_dns_sslcertref")
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
UNBOUND_EDNS_LINE = re.compile(r"^\s*edns-buffer-size:\s*(\d+)\s*$", re.MULTILINE)
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
    *(f"{CFG_PFB_DNS}/{key}" for key in LISTENER_KEYS),
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
    def port(self) -> int | None:
        """The port; None for a wildcard socket, which sockstat lists as `*:*`."""
        port = self.local.rsplit(":", 1)[1]
        return int(port) if port.isdigit() else None


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


def _discard_own_feed_cache(vm: SmokeVM) -> None:
    """Remove the derived files of this module's own feed (`.orig`, `.norm`, `.txt`, markers) and nothing else."""
    prefixes = (f"{h.PFB_DBDIR}/{folder}/{FEED_HEADER}." for folder in ("dnsblorig", "dnsbl"))
    result = _sh(vm, "rm -f " + " ".join(f"{shlex.quote(prefix)}*" for prefix in prefixes))
    if result.returncode != 0:
        raise RuntimeError(f"discarding the {FEED_HEADER} feed cache failed: rc={result.returncode} {result.stderr!r}")


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
    queries logged, Custom Options in the `server:` form pfSense documents; then let Unbound pick it up. pfB-DNS's
    interface lists are emptied, so that its turn-on seeds its listener settings, certificate included, from this
    Resolver."""
    _php_ok(
        vm,
        "$u = config_get_path('unbound', array());\n"
        "unset($u['port'], $u['active_interface']);\n"
        "$u['enablessl'] = 'yes';\n"
        f"$u['sslcertref'] = {h._php_str(refid)};\n"
        f"$u['custom_options'] = {h._php_str(base64.b64encode(CUSTOM_OPTIONS.encode()).decode())};\n"
        "config_set_path('unbound', $u);\n"
        # pfB-DNS seeds its listener settings from the Resolver at the first turn-on, while pfb_dns_interface is empty:
        # a value an earlier rig left would keep the turn-on from taking this Resolver's certificate and interfaces
        f"$d = config_get_path({h._php_str(CFG_PFB_DNS)}, array());\n"
        f"foreach (array({', '.join(h._php_str(key) for key in LISTENER_LISTS)}) as $k) {{ $d[$k] = ''; }}\n"
        f"config_set_path({h._php_str(CFG_PFB_DNS)}, $d);\n"
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
    """Every socket `sockstat -46lw` shows: USER COMMAND PID FD PROTO LOCAL FOREIGN.

    FreeBSD 16 cuts a long local address at 21 columns unless `-w` widens the columns. It also brackets an IPv6 local
    address (``[::1]:53``); the listener keeps it bare (``::1:53``), as IPv4 does.
    """
    rows = (line.split() for line in vm.ssh("sockstat -46lw").stdout.splitlines()[1:])
    return [
        Listener(row[1], int(row[2]), row[4], re.sub(r"^\[(.+)\]:", r"\1:", row[5]))
        for row in rows
        if len(row) >= 6 and row[2].isdigit()
    ]


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
        # a supervisor no pidfile names (a lost start race) would respawn the child
        "pkill -KILL -f 'daemon: pfb_dns_prox[y]'\n"
        "pkill -KILL -f 'pfb_dns_prox[y][.]py'\n"
        "pkill -KILL -f 'dns_proxy/bin/freebsd-[a-z0-9]*/pfb-dn[s]'\n"
        f"rm -f {DAEMON_PID_FILE} {PROXY_PID_FILE}\n",
    )


def _require_payload(vm: SmokeVM) -> None:
    """The installed package ships a pfb-dns for this machine: pfB-DNS has no other front end, so nothing below can
    run without it (a package without it fails here, not with a proxy that never becomes ready)."""
    result = _sh(vm, f"ls {PAYLOAD_DIR}/*/pfb-dns")
    assert result.returncode == 0 and result.stdout.strip(), f"the package installed no pfb-dns under {PAYLOAD_DIR}"


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
    except RuntimeError as exc:
        grep = vm.ssh(f"grep -F -- {shlex.quote(name)} {RESOLVER_LOG} 2>&1; tail -n 15 {RESOLVER_LOG} 2>&1").stdout
        logging = vm.ssh(f"grep -E 'log-|logfile|use-syslog|verbosity|proxy' {h.UNBOUND_CONF}").stdout
        raise RuntimeError(
            f"{exc}\n{RESOLVER_LOG} has no query line for {name}.\nmatching and last lines:\n{grep}\n"
            f"logging conf:\n{logging}"
        ) from exc
    return _unbound_clients(vm, name)


def _dnsbl_rows(vm: SmokeVM, name: str) -> list[list[str]]:
    """dnsbl.log rows for `name`: DNSBL-python,timestamp,name,client,p_type,b_type,group,b_eval,feed,dup,qtype."""
    return [row for row in csv.reader(io.StringIO(h.read_log_file(vm, DNSBL_LOG))) if row[2:3] == [name]]


def _wait_dnsbl_row(vm: SmokeVM, name: str) -> None:
    try:
        h.wait_until(lambda: bool(_dnsbl_rows(vm, name)), timeout=30.0)
    except RuntimeError as exc:
        raise RuntimeError(f"{exc}\ndnsbl.log gained no row for {name}:\n{_proxy_log(vm)}") from exc


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
        _require_payload(vm)
        lan_v6_prior = h.set_interface_ipv6(vm, h.IPV6_LOCAL_IFACE, LAN_V6_ADDR, h.IPV6_LOCAL_BITS)
        refid = _create_cert(vm)
        pem = _sh(vm, f"cat {CERT_GUEST}").stdout
        trusted = subprocess.run(
            client_vm.ssh_argv("tee", CERT_CLIENT), input=pem, capture_output=True, text=True, timeout=30, check=False
        )
        assert trusted.returncode == 0, f"copying the certificate to the client failed: {trusted.stderr!r}"
        _configure_resolver(vm, refid)
        h.inject(vm, h.DnsblCase(aliasname=FEED_HEADER, feed_url=feed_url, header=FEED_HEADER, mode=h.DnsblMode.VIP))
        # A package delete drops the manifest, so the next apply reuses a cached `.orig` of the module that ran
        # before and ignores the feed offered now: start from this module's own cache, then force the re-read.
        _discard_own_feed_cache(vm)
        h.force_dnsbl_refetch(vm, FEED_HEADER)
        h.reload(vm, "update")
        _configure_group_policy(vm)
        _apply(vm)  # toggle off: pfBlockerNG's own wiring, the module inside Unbound
        before = _capture(vm)
        baseline = {
            "blocked": _query(client_vm, names.blocked)[0],
            "allowed": _query(client_vm, h.unique_domain("baseline"))[0],
            "blocked_dot": _query(client_vm, names.blocked, dot=True)[0],
        }
        # An invalid setup fails here at once, not as a 240 s `_wait_proxy_serves` timeout in every toggle test.
        assert h.is_vip(baseline["blocked"]), f"baseline: {names.blocked} should answer the VIP: {baseline['blocked']}"
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
    # pfSense's automatic size for the saved interfaces: the size Unbound advertised natively before the move (its last
    # edns-buffer-size line in unbound.conf). The clause's first row, then only access-control grants.
    natives = UNBOUND_EDNS_LINE.findall(before.conf)
    assert natives, f"before the move unbound.conf named no edns-buffer-size: {before.conf}"
    rows = lines[start + 5 : end]
    assert rows[:1] == [f"edns-buffer-size: {natives[-1]}"], f"Custom Options: {options!r}"
    grants = rows[1:]
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


def _firewall_lookup(vm: SmokeVM, name: str) -> str:
    """What the firewall's OWN resolver (gethostbyname, i.e. /etc/resolv.conf) answers for `name`."""
    out = _php_ok(vm, f"echo 'FW=' . gethostbyname({h._php_str(name + '.')}) . ';';", "firewall lookup")
    match = re.search(r"FW=([^;]*);", out)
    assert match, f"no answer line in the firewall lookup output: {out!r}"
    return match.group(1)


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
    except RuntimeError as exc:
        raise RuntimeError(f"{exc}\ndnsbl.log gained no row for {rig.names.blocked}:\n{_proxy_log(rig.vm)}") from exc
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
            except RuntimeError as exc:
                raise RuntimeError(f"{exc}\ndns_reply.log gained no row for {logged}:\n{_proxy_log(vm)}") from exc
            [row] = _reply_rows(vm, logged)
            assert row[2:5] == ["reply", "A", "A"] and row[5].isdigit(), f"row: {row}"
            assert row[6:9] == [logged, CLIENT_LAN_IP, STUB_DNS_A], f"row: {row}"
            try:
                h.wait_until(lambda: bool(_reply_rows(vm, logged, UNIFIED_LOG)), timeout=30.0)
            except RuntimeError as exc:
                raise RuntimeError(f"{exc}\nunified.log (Reports, Stats) gained no row for {logged}") from exc
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
    except RuntimeError as exc:
        raise RuntimeError(f"{exc}\nthe Resolver restart did not start the proxy:\n{_diagnostics(vm)}") from exc
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
PROBE_REAP_CAP = (
    30  # s: a SIGKILLed probe is gone as soon as pgrep says so; only a process stuck in the kernel outlasts it
)
BOOT_ID_SLACK = 5  # s: the probe's kern.boottime may differ this much from the one read later
_PROBE_TEMPLATE = r"""#!/bin/sh
# Issue #3515 smoke probe, test-only: /etc/rc.custom_boot_early starts it detached. From early boot it asks the DNS
# proxy on 127.0.0.1:53 for a LISTED name and a never-asked ALLOWED name twice a second and logs what answers, until the
# package stage is over (rc.start_packages has returned, the proxy's own rc start it launched has exited and the boot is
# complete) or DEADLINE s have passed: it always exits.
DIR=/conf/pfb3515_boot_probe.d
LOG=$DIR/log
DEADLINE=@DEADLINE@
LISTED=${PROBE_LISTED:?}
STEM=${PROBE_STEM:?}
# kern.boottime is "{ sec = N, usec = M } <date>": the first number is N (a greedy "sec = " would catch usec)
BOOT=$(/sbin/sysctl -n kern.boottime | /usr/bin/sed 's/^[^0-9]*\([0-9]*\).*/\1/')
START=$(/bin/date +%s)
n=0 pkg=0 last=''
# rc.start_packages logs this when it begins; system.log outlives a reboot, so count against what it holds now. CE 2.9's
# syslog drops INFO and never writes it: there RUNNING (below) is what shows the stage begun.
MARK='Restarting/Starting all packages'
packages() { c=$(/usr/bin/grep -c "$MARK" /var/log/system.log 2>/dev/null); echo "${c:-0}"; }
base=$(packages)
# rc.start_packages creates RUNNING before it logs MARK and removes it as its last act, after it has started every other
# package rc script in the background (`<script> start &`); the proxy's rc script is one of them, and its repeated start
# is the one thing in that stage that can replace the proxy. The package stage is over when RUNNING is gone and that
# start is not running. Other package rc scripts are no measure: pfb_filter.sh stays resident with its own daemons.
# shortcut: a start forked but not yet exec'd still shows as a bare `/bin/sh`, so one sample can miss it; the proxy pids
# the test compares after the probe's end still show a proxy that start replaced
RUNNING=/tmp/.rc.start_packages.running
STAGE_RC='@PROXY_START@'
# is_platform_booting() holds while this file exists: rc.bootup removes it when the boot is complete
BOOTING=/var/run/booting
# RUNNING can exist for less than one sampling round (two queries and a pause), so the watcher latches its first sight
# in SEEN, which `stage` reads; it ends with the probe, or as soon as it has seen RUNNING
SEEN=$DIR/stage_seen
/bin/rm -f "$SEEN"
(
	while [ ! -e "$RUNNING" ] && kill -0 $$ 2>/dev/null; do /bin/sleep 0.05; done
	[ ! -e "$RUNNING" ] || true >"$SEEN"
) &
# pkg: 0 the package stage has not begun, 1 it has, 2 it is over and the boot is complete
stage() {
	if [ "$pkg" -eq 0 ] && { [ -e "$SEEN" ] || [ "$(packages)" -gt "$base" ]; }; then pkg=1; fi
	if [ "$pkg" -eq 1 ] && [ ! -e "$RUNNING" ] && [ ! -e "$BOOTING" ] \
		&& ! /bin/pgrep -f "$STAGE_RC" >/dev/null; then pkg=2; fi
}
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
	n=$((n + 1))
	a=$STEM-$n.com
	l=$(ask "$LISTED")
	r=$(ask "$a")
	# sampled after the answers: the state row logged before this query row is what the proxy and the package stage
	# were by the time the query had been answered
	ub=$(/bin/pgrep -x unbound | /usr/bin/head -n 1)
	px=$(/bin/cat /var/run/pfb_dns_proxy.pid 2>/dev/null)
	dm=$(/bin/cat /var/run/pfb_dns_proxy_daemon.pid 2>/dev/null)
	up=0
	if [ -n "$px" ] && /usr/bin/sockstat -4l -p 53 | /usr/bin/awk -v p="$px" "$held"; then up=1; fi
	stage
	cur="unbound=$ub proxy=$px daemon=$dm listening=$up pkg=$pkg"
	if [ "$cur" != "$last" ]; then
		age=
		[ -n "$ub" ] && age=$(/bin/ps -o etimes= -p "$ub" | /usr/bin/tr -d ' ')
		say "state $cur unbound_age=$age"
		last=$cur
	fi
	say "query n=$n allowed=$a listed=$l answer=$r"
	if [ "$pkg" -eq 2 ]; then say "end reason=packages"; exit 0; fi
	/bin/sleep 0.5
done
"""
PROBE_SCRIPT = _PROBE_TEMPLATE.replace("@DEADLINE@", str(PROBE_DEADLINE)).replace(
    "@PROXY_START@", f"{PROXY_RC.replace('.', '[.]')} start"
)

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
        "n=0\n"
        f"while pgrep -f '{PROBE_PROCESS}' >/dev/null; do\n"
        "    n=$((n + 1))\n"
        f'    if [ "$n" -gt {PROBE_REAP_CAP * 5} ]; then\n'
        f"        echo 'STUCK/ENVIRONMENT: the probe is still running {PROBE_REAP_CAP} s after SIGKILL'; rc=1; break\n"
        "    fi\n"
        f"    pkill -KILL -f '{PROBE_PROCESS}'\n"
        "    sleep 0.2\n"
        "done\n"
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
        if "STUCK/ENVIRONMENT" in removed.stdout:
            raise RuntimeError(f"{removed.stdout.strip()} (removing the early-boot probe: rc={removed.returncode})")
        assert removed.returncode == 0, (
            f"removing the early-boot probe: rc={removed.returncode} {removed.stdout}{removed.stderr}"
        )


def _probe_log(vm: SmokeVM) -> str:
    return vm.ssh("cat", PROBE_LOG).stdout


def _probe_over(vm: SmokeVM) -> bool:
    """The probe logged `end`, or is gone without having logged it: either way nothing is left to wait for."""
    if re.search(r"^@@ \d+ boot=\d+ end\b", _probe_log(vm), re.MULTILINE):
        return True
    return vm.ssh(f"pgrep -f '{PROBE_PROCESS}'").returncode == 1  # pgrep's 1 is no process; ssh's own failure is 255


def _wait_probe_end(vm: SmokeVM) -> None:
    """Wait for the probe to log `end` as its last act, or to be gone; the judge reads what it wrote either way.

    The probe is bounded by PROBE_DEADLINE; this wait's own cap, a minute past it, only salvages a stuck poll.
    """
    try:
        h.wait_until(lambda: _probe_over(vm), timeout=PROBE_DEADLINE + 60.0, interval=3.0)
    except RuntimeError as exc:
        raise RuntimeError(f"{exc}\nthe early-boot probe did not end:\n{_probe_log(vm)[-4000:]}") from exc


# One probe record: (epoch, the kern.boottime second the probe read, kind, key=value fields).
#   start   pid, deadline
#   state   unbound/proxy/daemon pids, listening (the proxy child holds 127.0.0.1:53), pkg (0 the package stage has not
#           begun, 1 rc.start_packages began, 2 it is over), unbound_age (ps etimes of Unbound); written on every
#           change, sampled after the answers of the query row that follows it
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
    packages_seen: int  # the first sample that found rc.start_packages begun


def _judge_boot_probe(log: str, *, boot: int, listed_address: str, upstream_address: str) -> BootProbe:
    """Raise AssertionError unless the probe saw correct answers before the package stage and an undisturbed proxy.

    Order is the order of the probe's own log, which one process wrote in sequence; each `state` row is sampled after
    the answers of the `query` row that follows it, so a `state` row that shows the package stage begun comes before
    every answer that may have been given after it. No epoch and no other clock decides an order.
    """
    rows = _probe_rows(log)
    assert rows and rows[0][2] == "start", f"the early-boot probe never started; its log:\n{log}"
    digest = _digest(rows)
    assert all(abs(row[1] - boot) <= BOOT_ID_SLACK for row in rows), (
        f"records of another boot (this one began at {boot}):\n{digest}"
    )
    assert rows[-1][2] == "end", f"STUCK/ENVIRONMENT: the early-boot probe did not finish (it was killed?):\n{digest}"
    position = {id(row): at for at, row in enumerate(rows)}
    queries = [row for row in rows if row[2] == "query"]
    states = [row for row in rows if row[2] == "state"]

    def served(row: ProbeRow) -> bool:
        return _answered(row[3].get("listed", ""), listed_address) and _answered(
            row[3].get("answer", ""), upstream_address
        )

    ready = next((row for row in queries if served(row)), None)
    assert ready is not None, f"none of {len(queries)} probe queries was answered as expected:\n{digest}"
    began = next((row for row in states if row[3].get("pkg") in ("1", "2")), None)
    assert began is not None, (
        f"the probe never saw rc.start_packages begin (it ended: {rows[-1][3].get('reason')}):\n{digest}"
    )
    assert position[id(ready)] < position[id(began)], (
        f"the first correct answers came at boot+{ready[0] - boot} s, not before rc.start_packages began "
        f"(the probe saw it begun at boot+{began[0] - boot} s):\n{digest}"
    )
    heard = next((i for i, row in enumerate(states) if row[3].get("listening") == "1"), None)
    assert heard is not None and position[id(states[heard])] < position[id(ready)], (
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
    failed = [row for row in queries[queries.index(ready) :] if not served(row)]
    assert not failed, f"{len(failed)} quer(ies) failed after the first correct answers, first {failed[0]}:\n{digest}"
    assert rows[-1][3].get("reason") == "packages", (
        f"STUCK/ENVIRONMENT: the probe hit its {PROBE_DEADLINE} s deadline before the package stage was over "
        f"(rc.start_packages returned, the proxy's own rc start exited and the boot completed):\n{digest}"
    )
    unbound = [
        row
        for row in states
        if position[id(row)] < position[id(ready)] and row[3].get("unbound") and row[3].get("unbound_age", "").isdigit()
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
    Then the probe's first correct answers come before rc.start_packages begins (it creates its running marker and,
      on CE 2.8, logs `Restarting/Starting all packages`; CE 2.9's syslog drops that line):
      the DNSBL VIP for the listed name with DNSBL on, the upstream's address for it with DNSBL off, and with both
      the upstream's address for the fresh name, which the stub saw; a `DNS proxy started` line is a launch and does
      not count;
      And from the first answers to the end of the probe (the package stage over: rc.start_packages has returned, the
      proxy's own rc start, which it launches in the background, has exited and the boot is complete) the proxy keeps
      its child and supervisor pids, stays on 127.0.0.1:53, and no probe query fails;
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
        probe = _judge_boot_probe(log, boot=boot, listed_address=expected, upstream_address=STUB_DNS_A)
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
# Readiness: the listener-ready marker, and starts that do not race
# --------------------------------------------------------------------------- #

READY_FILE = "/var/unbound/pfb_dns_ready"  # the gateway's own pid, written by it (--ready-file) once it serves
START_LOCK = "/var/run/pfb_dns_proxy.lock"  # lockf(1): `rc start` runs under it, the file is kept between starts
RACE_ROUNDS = 6
RACE_READY_CAP = 90  # s per round: a start whose proxy has not published its ready marker by then is stuck, not slow


def _marker(vm: SmokeVM) -> str | None:
    result = vm.ssh("cat", READY_FILE)
    return result.stdout if result.returncode == 0 else None


def _stat(vm: SmokeVM, path: str, fmt: str) -> str:
    return vm.ssh(f"stat -f {shlex.quote(fmt)} {shlex.quote(path)} 2>&1").stdout.strip()


def test_a_serving_proxy_has_published_its_ready_marker_and_a_repeated_start_keeps_everything(
    rig: Rig, proxy_on: State
) -> None:
    """The proxy writes its own pid, mode 0600 as `unbound`, once it serves; a healthy second start changes nothing.

    Given the toggle on and the proxy answering,
    Then the ready marker holds exactly the child pid the supervisor's pidfile names, is mode 600 and owned by
      unbound (the proxy wrote it after dropping root);
    When the service is started again (the package start after the boot hook),
    Then it exits 0 and the supervisor pid, the child pid, the marker's bytes and its mtime are all unchanged.
    """
    vm = rig.vm
    child = proxy_on.proxy_pid
    assert child is not None, f"no proxy child pid: {proxy_on}"
    marker = _marker(vm)
    assert marker == f"{child}\n", f"ready marker {marker!r}, expected the child pid {child}\n{_diagnostics(vm)}"
    assert _stat(vm, READY_FILE, "%Lp %Su") == "600 unbound", _stat(vm, READY_FILE, "%Lp %Su %N")
    mtime = _stat(vm, READY_FILE, "%m")

    started = _sh(vm, f"{PROXY_RC} start; echo rc=$?")

    assert "rc=0" in started.stdout, f"a repeated start failed: {started.stdout!r} {started.stderr!r}"
    after = _capture(vm)
    assert (after.proxy_pid, after.daemon_pid) == (proxy_on.proxy_pid, proxy_on.daemon_pid), (
        f"a repeated start replaced the proxy: {proxy_on.proxy_pid}/{proxy_on.daemon_pid} -> "
        f"{after.proxy_pid}/{after.daemon_pid}"
    )
    assert _marker(vm) == marker and _stat(vm, READY_FILE, "%m") == mtime, "a repeated start rewrote the marker"


def test_the_start_lock_is_free_while_the_proxy_runs(rig: Rig, proxy_on: State) -> None:
    """lockf(1) holds the start lock for the one run of the rc script, not for the daemon that script launches.

    FreeBSD's lockf closes its lock descriptor before it runs the command, so the launched proxy does not
    inherit the lock; the rc script also closes descriptors 3-9 at launch, defensively. Were a proxy to keep
    the lock, every later start would wait the whole 10 s and fail (lockf's status 75). The proxy has been
    running since before this test, so this probe checks that the lock is free; the race probe below proves
    the lock itself.

    Given the proxy running,
    When the lock is tried without waiting (`lockf -t 0` is a state probe: status 75 means held),
    Then lockf gets it (status 0).
    """
    probe = _sh(rig.vm, f"/usr/bin/lockf -k -t 0 {START_LOCK} /usr/bin/true; echo rc=$?")
    assert "rc=0" in probe.stdout, (
        f"the start lock is still held while the proxy runs (rc 75 = held): {probe.stdout!r} {probe.stderr!r}\n"
        f"{_sh(rig.vm, f'ls -l {START_LOCK}; fstat {START_LOCK} 2>&1').stdout}"
    )


DECIDER_DIR = "/usr/local/pkg/pfblockerng/dns_proxy"
DECIDER_APPLIED = "/var/unbound/pfb_dns_decider.applied"  # the decider's code record
GATEWAY_APPLIED = f"{READY_FILE}.sha256"  # the gateway's binary record
RESTART_PENDING = "/var/run/pfb_dns_proxy_restart_pending"
DECIDER_RESTART_LOGGED = "Restarting the DNS proxy's decider: the package installed other decider code"
SAVE_DIR = "/var/tmp/pfb3566_saved"  # the installed file a test edits, as it was
UPGRADE_PROBE_DIR = "/var/tmp/pfb3566_probe"
UPGRADE_PROBE_LOG = f"{UPGRADE_PROBE_DIR}/log"
UPGRADE_PROBE_PROCESS = "pfb3566_probe[.]sh"  # for pkill -f; the brackets keep it off its own command
UPGRADE_PROBE_SPAN = 800  # s: the probe ends itself by then whatever happens
UPGRADE_PROBE_MIN_ROWS = 5

# One row per answer: "<epoch> <RCODE>:<addresses>", NONE:- when nothing answered in 3 s.
UPGRADE_PROBE_SCRIPT = r"""#!/bin/sh
while [ "$(/bin/date +%s)" -lt "$PROBE_END" ]; do
	a=$(/usr/bin/timeout 3 /usr/local/bin/drill "$PROBE_NAME" A @127.0.0.1 2>/dev/null | /usr/bin/awk '
		/rcode:/ { sub(/.*rcode: */, ""); sub(/,.*/, ""); rc = $0 }
		/^;; ANSWER SECTION/ { ans = 1; next }
		ans && (NF == 0 || /^;;/) { ans = 0 }
		ans && $4 == "A" { a = a (a == "" ? "" : ",") $5 }
		END { print (rc == "" ? "NONE" : rc) ":" (a == "" ? "-" : a) }')
	printf '%s %s\n' "$(/bin/date +%s)" "$a" >>"$PROBE_LOG"
	/bin/sleep 0.2
done
"""


@dataclass(frozen=True)
class Pids:
    """The three processes of a serving pfB-DNS: the supervisor, the gateway it keeps up, the gateway's decider."""

    gateway: int | None
    supervisor: int | None
    decider: int | None

    def complete(self) -> bool:
        return None not in (self.gateway, self.supervisor, self.decider)


def _pids(vm: SmokeVM) -> Pids:
    """The pidfiles name the gateway and its supervisor; the decider is its one child running pfb_dns_proxy.py.

    A replaced decider drains for a while beside the new one: two children are no decider yet, never a guess.
    """
    gateway = _pid_file(vm, PROXY_PID_FILE)
    children: list[int] = []
    for line in vm.ssh("ps -axww -o pid,ppid,args").stdout.splitlines()[1:]:
        fields = line.split(None, 2)
        if len(fields) == 3 and gateway is not None and fields[1] == str(gateway) and "pfb_dns_proxy.py" in fields[2]:
            children.append(int(fields[0]))
    return Pids(gateway, _pid_file(vm, DAEMON_PID_FILE), children[0] if len(children) == 1 else None)


def _settled_pids(vm: SmokeVM) -> Pids:
    """The pids once a gateway, a supervisor and exactly one decider are there (a drained decider has left)."""
    seen: list[Pids] = []

    def settled() -> bool:
        seen.append(_pids(vm))
        return seen[-1].complete()

    try:
        h.wait_until(settled, timeout=60.0, interval=2.0)
    except RuntimeError as exc:
        raise RuntimeError(
            f"{exc}\nexpected a gateway, a supervisor and exactly one decider within 60 s, last read: {seen[-1]}\n"
            f"{_diagnostics(vm)}"
        ) from exc
    return seen[-1]


def _cat(vm: SmokeVM, path: str) -> str | None:
    result = vm.ssh("cat", path)
    return result.stdout if result.returncode == 0 else None


class _Probe:
    """An on-box loop (daemon(8)) asking the proxy at 127.0.0.1 for a name every 0.2 s; `stop` returns its log."""

    def __init__(self, vm: SmokeVM, name: str) -> None:
        self.vm = vm
        self.name = name
        self.rows: list[str] | None = None

    def start(self) -> None:
        script = (
            "set -e\n"
            "for tool in /usr/local/bin/drill /usr/bin/timeout /usr/sbin/daemon; do\n"
            '    [ -x "$tool" ] || { echo "missing $tool"; exit 1; }\n'
            "done\n"
            f"rm -rf {UPGRADE_PROBE_DIR}\n"
            f"mkdir -p {UPGRADE_PROBE_DIR}\n"
            f"cat > {UPGRADE_PROBE_DIR}/pfb3566_probe.sh <<'PROBE_EOF'\n" + UPGRADE_PROBE_SCRIPT + "PROBE_EOF\n"
            f"true > {UPGRADE_PROBE_LOG}\n"
            f"end=$(($(/bin/date +%s) + {UPGRADE_PROBE_SPAN}))\n"
            f"/usr/sbin/daemon -f /usr/bin/env PROBE_NAME={shlex.quote(self.name)} PROBE_END=$end "
            f"PROBE_LOG={UPGRADE_PROBE_LOG} /bin/sh {UPGRADE_PROBE_DIR}/pfb3566_probe.sh\n"
        )
        started = _sh(self.vm, script)
        assert started.returncode == 0, f"starting the probe: rc={started.returncode} {started.stdout}{started.stderr}"
        h.wait_until(lambda: bool((_cat(self.vm, UPGRADE_PROBE_LOG) or "").strip()), timeout=30.0, interval=1.0)

    def stop(self) -> list[str]:
        """Kill the loop, read its log, delete its files; repeated calls return the first read."""
        if self.rows is None:
            _sh(self.vm, f"pkill -KILL -f '{UPGRADE_PROBE_PROCESS}'; true")
            self.rows = (_cat(self.vm, UPGRADE_PROBE_LOG) or "").splitlines()
            _sh(self.vm, f"rm -rf {UPGRADE_PROBE_DIR}")
        return self.rows


def _assert_probe_answered(rows: list[str], what: str) -> None:
    """Every probe row got the VIP, and there were enough rows for that to mean something."""
    misses = [row for row in rows if not _answered(row.partition(" ")[2], h.DEFAULT_DNSBL_VIP4)]
    assert len(rows) >= UPGRADE_PROBE_MIN_ROWS, (
        f"{what}: the probe logged {len(rows)} rows, expected at least {UPGRADE_PROBE_MIN_ROWS}"
    )
    assert not misses, (
        f"{what}: {len(misses)} of {len(rows)} probes did not get NOERROR:{h.DEFAULT_DNSBL_VIP4} "
        f"(row = epoch answer):\n" + "\n".join(misses[:20])
    )


@pytest.mark.timeout(900)  # a pkg upgrade with its install hooks, an update pass, then the branch build put back
def test_a_package_upgrade_keeps_pfb_dns_on_and_serving(rig: Rig, proxy_on: State, tmp_path: Path) -> None:
    """A package upgrade with pfB-DNS on leaves it on and serving (issue #3562).

    pfSense's delete_package_xml() stops and deregisters the package's services, and install_package_xml() runs the
    install command before it registers them again; start_service() acts only on a registered service, so the
    installer's restart of the proxy has to reach the service all the same, or the readiness wait times out and
    pfB-DNS is rolled back off. Only a real version move runs pfSense's removal step: `pkg add -f` of the installed
    version is an in-place overwrite that skips it.

    Given the toggle on and the proxy serving, its gateway, supervisor and decider pids, and an on-box probe asking for
      a listed name every 0.2 s,
    When the branch package, re-versioned higher, comes in by `pkg upgrade` from a file:// repo,
    Then the toggle is still on, the Resolver still moved, the proxy running, a listed name still gets the VIP, the
      three pids are the ones from before, and every probe got the VIP (the upgrade restarted nothing, dropped nothing);
    When the next update pass runs,
    Then the three pids are still the same (the re-versioned package changed neither the binary nor the decider's code,
      and nothing was deferred) and no restart is pending.
    """
    vm = rig.vm
    pkg = Path(os.environ["SMOKE_PKG"])
    higher = reversion_pkg(pkg, f"{read_compact_version(pkg)}_9", tmp_path)
    h._write_cron_disable_flag(vm)
    before = _settled_pids(vm)
    assert before.complete(), f"before: expected a gateway, a supervisor and a decider: {before}\n{_diagnostics(vm)}"
    probe = _Probe(vm, rig.names.blocked)
    try:
        probe.start()
        try:
            build_guest_repo(vm, UPGRADE_REPO_DIR, [higher])
            write_repo_conf(vm, UPGRADE_REPO_DIR, ours_priority=repo_priority(vm, NETGATE_REPO_NAME) + 100)
            updated = vm.ssh("env", "ASSUME_ALWAYS_YES=yes", "pkg", "update", "-f", "-r", OURS_REPO_NAME, timeout=240.0)
            assert updated.returncode == 0, f"pkg update failed: {updated.stdout[-1500:]}{updated.stderr[-1500:]}"
            upgraded = vm.ssh(
                "env", "ASSUME_ALWAYS_YES=yes", "pkg", "upgrade", "-y", "-r", OURS_REPO_NAME, PKG_NAME, timeout=600.0
            )
        finally:
            h._write_cron_disable_flag(vm)
            vm.ssh("/bin/rm", "-rf", UPGRADE_REPO_DIR, REPO_CONF, timeout=60.0)
        output = upgraded.stdout + upgraded.stderr
        assert upgraded.returncode == 0, f"pkg upgrade failed: rc={upgraded.returncode}\n{output[-3000:]}"
        assert re.search(r"Removing \S+ components", output), f"before: pkg ran no removal step:\n{output[-3000:]}"
        h.wait_unbound_ready(vm)

        diagnostics = f"pkg upgrade output:\n{output[-3000:]}\n{_diagnostics(vm)}"
        toggle = _xml_text(_config_xml(vm), "installedpackages/pfblockerngdns/config/pfb_dns") or ""
        assert toggle == "on", f"the upgrade turned pfB-DNS off: {toggle!r}\n{diagnostics}"
        after = _capture(vm)
        assert _is_on(after), (
            f"the proxy is not serving the moved Resolver after the upgrade: {after.service}\n{diagnostics}"
        )
        blocked, raw = _query(rig.client, rig.names.blocked)
        assert h.is_vip(blocked), f"after the upgrade the listed name is not blocked: {blocked}\n{raw}\n{diagnostics}"
        during = _settled_pids(vm)
        assert during == before, (
            f"the upgrade restarted pfB-DNS: (gateway, supervisor, decider) {before} -> {during}\n{diagnostics}"
        )
        _assert_probe_answered(probe.stop(), "the package upgrade")
        h.reload(vm, "update")  # the next update
        later = _settled_pids(vm)
        assert later == before, (
            f"the update after the upgrade restarted pfB-DNS: (gateway, supervisor, decider) {before} -> {later}\n"
            f"{_diagnostics(vm)}"
        )
        assert not _restart_pending(vm), f"{RESTART_PENDING} exists after the next update: nothing was to be deferred"
    finally:
        try:
            probe.stop()
        finally:
            # the branch build again, at its own version, for the tests after this one
            h.deploy(vm)


def _restart_pending(vm: SmokeVM) -> bool:
    result = vm.ssh(f"test -e {RESTART_PENDING}")
    assert result.returncode in (0, 1), f"cannot test {RESTART_PENDING}: rc={result.returncode} {result.stderr!r}"
    return result.returncode == 0


@pytest.mark.timeout(900)  # an update pass to restart the decider, and another to put it back
def test_a_decider_code_change_restarts_only_the_decider(rig: Rig, proxy_on: State) -> None:
    """A changed decider module restarts the decider and nothing else, with no query lost (issue #3566).

    Given pfB-DNS on and serving, its three pids and the decider's code record,
    When a comment is appended to the installed dnswire.py and an update pass runs, an on-box probe asking for a listed
      name every 0.2 s the whole time,
    Then the gateway and its supervisor keep their pids, the decider has a new one, every probe got the VIP, the
      listed name is still blocked, the decider's code record changed, and the update's log names the running decider's
      pid and RSS and hw.usermem, the memory check it passed (issue #3580).
    """
    vm = rig.vm
    target = f"{DECIDER_DIR}/dnswire.py"
    before = _settled_pids(vm)
    assert before.complete(), f"before: expected a gateway, a supervisor and a decider: {before}\n{_diagnostics(vm)}"
    record_before = _cat(vm, DECIDER_APPLIED)
    assert record_before is not None, f"{DECIDER_APPLIED} is absent before the change: the decider wrote no record"
    saved = _sh(vm, f"mkdir -p {SAVE_DIR} && cp -p {target} {SAVE_DIR}/dnswire.py")
    assert saved.returncode == 0, f"saving {target}: rc={saved.returncode} {saved.stdout}{saved.stderr}"
    probe = _Probe(vm, rig.names.blocked)
    try:
        edited = _sh(vm, f"printf '\\n# pfb3566 smoke: a decider code change\\n' >> {target}")
        assert edited.returncode == 0, f"editing {target}: rc={edited.returncode} {edited.stdout}{edited.stderr}"
        logged = _sh(vm, f"wc -c < {h.PFB_LOG}")
        assert logged.returncode == 0 and logged.stdout.strip().isdigit(), (
            f"reading the size of {h.PFB_LOG}: rc={logged.returncode} {logged.stdout!r}{logged.stderr!r}"
        )
        size = int(logged.stdout)
        probe.start()
        h.reload(vm, "update")
        rows = probe.stop()
        after = _settled_pids(vm)
        diagnostics = _diagnostics(vm)
        assert (after.gateway, after.supervisor) == (before.gateway, before.supervisor), (
            f"a decider code change restarted the gateway or its supervisor: (gateway, supervisor) "
            f"{(before.gateway, before.supervisor)} -> {(after.gateway, after.supervisor)}\n{diagnostics}"
        )
        assert after.decider is not None and after.decider != before.decider, (
            f"a decider code change left the decider running: pid {before.decider} -> {after.decider}\n{diagnostics}"
        )
        _assert_probe_answered(rows, "the decider's restart")
        blocked, raw = _query(rig.client, rig.names.blocked)
        assert h.is_vip(blocked), f"after the decider restart {rig.names.blocked} is not blocked: {blocked}\n{raw}"
        record_after = _cat(vm, DECIDER_APPLIED)
        assert record_after is not None and record_after != record_before, (
            f"{DECIDER_APPLIED} did not change: before {record_before!r}, after {record_after!r}"
        )
        added = _sh(vm, f"tail -c +{size + 1} {h.PFB_LOG} | grep -F {shlex.quote(DECIDER_RESTART_LOGGED)}")
        lines = added.stdout.splitlines()
        assert added.returncode == 0 and len(lines) == 1, (
            f"expected one {DECIDER_RESTART_LOGGED!r} line added to {h.PFB_LOG} by the update, got {len(lines)} "
            f"(grep rc={added.returncode}): {lines}\n{diagnostics}"
        )
        checked = re.search(r"\(decider pid (\d+) uses (\d+) KiB, hw\.usermem is (\d+) bytes\)", lines[0])
        assert checked is not None, (
            f"the decider restart's log line names no pid, RSS and hw.usermem: expected '(decider pid N uses R KiB, "
            f"hw.usermem is U bytes)', got {lines[0]!r}\n{diagnostics}"
        )
        pid, rss, usermem = (int(group) for group in checked.groups())
        assert pid == before.decider, (
            f"the memory check measured another process than the running decider: expected pid {before.decider}, "
            f"got {pid}: {lines[0]!r}\n{diagnostics}"
        )
        assert rss > 0 and usermem > 0, (
            f"the memory check read no RSS or hw.usermem: expected both > 0, got RSS {rss} KiB and hw.usermem "
            f"{usermem} bytes: {lines[0]!r}\n{diagnostics}"
        )
        _say(f"the decider restart's memory check read: {lines[0]}")
    finally:
        try:
            probe.stop()
        finally:
            restored = _sh(vm, f"cp -p {SAVE_DIR}/dnswire.py {target} && cmp {SAVE_DIR}/dnswire.py {target}")
            assert restored.returncode == 0, f"restoring {target}: rc={restored.returncode} {restored.stdout}"
            _sh(vm, f"rm -rf {SAVE_DIR}")
            h.reload(vm, "update")  # the decider on the restored code again


@pytest.mark.timeout(1200)  # three update passes: the change, the check that it was once, the put-back
def test_a_gateway_binary_change_restarts_the_pair_once(rig: Rig, proxy_on: State) -> None:
    """A changed gateway binary restarts the gateway and its decider once, and the next pass leaves them (issue #3566).

    Given pfB-DNS on and serving, its three pids,
    When trailing bytes are appended to the installed pfb-dns (a file the kernel still runs) and an update pass runs,
    Then the gateway has a new pid, its binary record holds the installed binary's sha256, the proxy serves and the
      listed name is blocked;
    When a second update pass runs,
    Then no pid changed: the pair was restarted once.
    """
    vm = rig.vm
    before = _settled_pids(vm)
    assert before.complete(), f"before: expected a gateway, a supervisor and a decider: {before}\n{_diagnostics(vm)}"
    command = vm.ssh(f"ps -o args= -p {before.gateway}").stdout.split()
    binary = command[0] if command else ""
    assert binary.startswith(f"{PAYLOAD_DIR}/") and binary.endswith("/pfb-dns"), (
        f"the gateway (pid {before.gateway}) does not run a binary of {PAYLOAD_DIR}: {command}"
    )
    saved = _sh(vm, f"mkdir -p {SAVE_DIR} && cp -p {binary} {SAVE_DIR}/pfb-dns")
    assert saved.returncode == 0, f"saving {binary}: rc={saved.returncode} {saved.stdout}{saved.stderr}"
    try:
        # a rename, not a write: the kernel refuses to open a running executable for writing
        edited = _sh(vm, f"cp -p {binary} {binary}.new && printf 'x' >> {binary}.new && mv {binary}.new {binary}")
        assert edited.returncode == 0, f"editing {binary}: rc={edited.returncode} {edited.stdout}{edited.stderr}"
        h.reload(vm, "update")
        after = _settled_pids(vm)
        diagnostics = _diagnostics(vm)
        assert after.complete(), (
            f"after the update pass: expected a gateway, a supervisor and a decider: {after}\n{diagnostics}"
        )
        assert after.gateway != before.gateway, (
            f"a gateway binary change left the gateway running: pid {before.gateway} -> {after.gateway}\n{diagnostics}"
        )
        assert after.supervisor != before.supervisor and after.decider != before.decider, (
            f"the pair was not restarted: (supervisor, decider) {(before.supervisor, before.decider)} -> "
            f"{(after.supervisor, after.decider)}\n{diagnostics}"
        )
        installed = _sh(vm, f"sha256 -q {binary}").stdout.strip()
        assert re.fullmatch(r"[0-9a-f]{64}", installed), (
            f"sha256 -q {binary} printed {installed!r}, expected 64 hex digits"
        )
        record = _cat(vm, GATEWAY_APPLIED)
        assert record is not None and record.strip() == installed, (
            f"{GATEWAY_APPLIED} expected the installed binary's sha256 {installed!r}, got {record!r}\n{diagnostics}"
        )
        assert _is_on(_capture(vm)), f"the proxy is not serving after its restart\n{diagnostics}"
        blocked, raw = _query(rig.client, rig.names.blocked)
        assert h.is_vip(blocked), f"after the restart {rig.names.blocked} is not blocked: {blocked}\n{raw}"
        h.reload(vm, "update")
        again = _settled_pids(vm)
        assert again == after, f"a second update pass restarted the pair again: {after} -> {again}\n{_diagnostics(vm)}"
    finally:
        restored = _sh(
            vm, f"cp -p {SAVE_DIR}/pfb-dns {binary}.new && mv {binary}.new {binary} && cmp {SAVE_DIR}/pfb-dns {binary}"
        )
        assert restored.returncode == 0, f"restoring {binary}: rc={restored.returncode} {restored.stdout}"
        _sh(vm, f"rm -rf {SAVE_DIR}")
        h.reload(vm, "update")  # the gateway on the restored binary again


def _race(vm: SmokeVM, *, locked: bool) -> list[tuple[int, int, str]]:
    """RACE_ROUNDS times: stop the proxy, run two `start`s at once, count what is left running.

    Returns (supervisors, children, the two exit statuses) per round. The unlocked variant sets the rc script's own
    inner-run variable, which makes it skip lockf: the same script, with only the serialization taken away.
    A start returns once it has launched the proxy, not once the proxy serves. The locked race, which is asserted,
    is therefore counted when a proxy has published its ready marker naming a live process; a round whose proxy never
    does is stuck, not a count. The unlocked race is evidence only and promises no settled state (two supervisors
    whose children cannot bind keep restarting them, and a start's removal of the marker can follow a proxy's
    write of it), so it is counted when both starts have returned and awaits nothing.
    """
    env = "" if locked else "PFB_DNS_PROXY_START_LOCKED=1 "
    wait_for_proxy = (
        "  t=0\n"
        f"  until pid=''; {{ read -r pid < {READY_FILE}; }} 2>/dev/null \\\n"
        '    && [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; do\n'
        "    t=$((t + 1))\n"
        f"    if [ $t -gt {RACE_READY_CAP * 5} ]; then\n"
        f'      echo "round=$i stuck: no live proxy published {READY_FILE} in {RACE_READY_CAP} s"; exit 1\n'
        "    fi\n"
        "    sleep 0.2\n"
        "  done\n"
    )
    script = (
        f"i=0\nwhile [ $i -lt {RACE_ROUNDS} ]; do\n"
        f"  {PROXY_RC} stop || {{ echo 'round='$i' stop-failed'; exit 1; }}\n"
        f"  s1=$(mktemp /tmp/pfb3515_race.XXXXXX); s2=$(mktemp /tmp/pfb3515_race.XXXXXX)\n"
        f"  ( {env}{PROXY_RC} start; echo $? > $s1 ) &\n"
        f"  ( {env}{PROXY_RC} start; echo $? > $s2 ) &\n"
        "  wait\n"
        f"{wait_for_proxy if locked else ''}"
        "  sup=$(ps -axww -o args= | grep -c 'daemon: pfb_dns_prox[y]')\n"
        "  kids=$(ps -axww -o args= | awk '$1 ~ /python/ && /pfb_dns_prox[y][.]py/' | wc -l | tr -d ' ')\n"
        '  echo "round=$i supervisors=$sup children=$kids rc=$(cat $s1)/$(cat $s2)"\n'
        "  rm -f $s1 $s2\n"
        "  i=$((i + 1))\n"
        "done\n"
    )
    try:
        out = _sh(vm, script, timeout=RACE_ROUNDS * (RACE_READY_CAP + 30.0) + 60.0).stdout
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"STUCK/ENVIRONMENT: the race probe did not return within {exc.timeout:.0f}s") from exc
    stuck = [line for line in out.splitlines() if " stuck: " in line]
    if stuck:
        raise RuntimeError(f"STUCK/ENVIRONMENT: {stuck[0]}\nrace probe output:\n{out}")
    rounds = [re.fullmatch(r"round=\d+ supervisors=(\d+) children=(\d+) rc=(\S+)", line) for line in out.splitlines()]
    parsed = [(int(m.group(1)), int(m.group(2)), m.group(3)) for m in rounds if m]
    assert len(parsed) == RACE_ROUNDS, f"race probe output:\n{out}"
    return parsed


@pytest.mark.timeout(900)
def test_starts_that_race_each_other_leave_exactly_one_proxy(rig: Rig, proxy_on: State) -> None:
    """The boot hook's background start and an apply's start_service() both run `rc start`, at about the same moment.

    Given the proxy stopped before each of RACE_ROUNDS rounds,
    When two `start`s run at once,
    Then both exit 0 and exactly one supervisor and one child are left, in every round;
      the same starts with the serialization taken away are printed too, as a snapshot taken when both starts had
      returned (not a race finding and not asserted: the proxies they launched may not have settled, and a race may
      or may not fire in a given run).
    """
    vm = rig.vm
    try:
        unlocked = _race(vm, locked=False)
        _say(
            "unlocked starts, snapshot taken when both had returned (not a race finding; supervisors, children, "
            f"exit statuses), per round: {unlocked}"
        )
        _force_stop_proxy(vm)
        locked = _race(vm, locked=True)
        _say(f"locked start race (supervisors, children, exit statuses), per round: {locked}")
        assert all(round_ == (1, 1, "0/0") for round_ in locked), (
            f"two racing starts did not leave exactly one proxy: {locked}\n{_diagnostics(vm)}"
        )
    finally:
        _force_stop_proxy(vm)
        _sh(vm, f"{PROXY_RC} start")
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


# --------------------------------------------------------------------------- #
# A proxy that cannot serve: the activation is rolled back to the Unbound DNSBL that ran before
# --------------------------------------------------------------------------- #

OCCUPANTS = "/tmp/pfb3515_occupants"  # on the guest: pidfiles of the nc(1) listeners that hold the client-facing ports
MOVE_PHP = "/tmp/pfb3515_move.php"
# The Resolver step of the apply and nothing after it: pfb_unbound_python() moves the Resolver, stages the proxy's rc
# script and restarts Unbound on loopback 5353/5354; the observer include that restart loads starts the proxy, which the
# caller stops again. Prints the addresses the proxy would serve, and its port.
MOVE_ONLY_PHP = r"""<?php
require_once('util.inc');
require_once('functions.inc');
require_once('pkg-utils.inc');
require_once('globals.inc');
require_once('services.inc');
require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');
require_once('/usr/local/pkg/pfblockerng/pfblockerng_extra.inc');
global $g, $pfb;
pfb_global();
pfb_unbound_python('enabled', TRUE);
$addresses = array_merge(pfb_dns_proxy_listen(), PFB_DNS_PROXY_LOOPBACK);
echo '<<<ADDR>>>' . implode(',', $addresses) . '|' . pfb_dns_proxy_port() . '<<<END>>>';
"""


def _occupy(vm: SmokeVM, addresses: list[str], port: str) -> None:
    """Hold <address>:<port> on tcp and udp for every address with nc(1) listeners, until each shows in sockstat.

    A real process failure on the guest: the proxy skips an address it cannot bind and exits only when none binds,
    so every address it would serve is taken.
    """
    lines = [f"rm -rf {OCCUPANTS}; mkdir -p {OCCUPANTS}"]
    for n, address in enumerate(addresses):
        family = "-6" if ":" in address else "-4"
        for proto, flag in (("tcp", ""), ("udp", "-u ")):
            # daemon -f: without it nc keeps the ssh session's stdout open and the session never ends
            lines.append(
                f"/usr/sbin/daemon -f -p {OCCUPANTS}/{proto}-{n}.pid /usr/bin/nc {family} {flag}-l {address} {port}"
                " </dev/null >/dev/null 2>&1"
            )
    started = _sh(vm, "\n".join(lines) + "\n")
    assert started.returncode == 0, f"starting the listeners failed: {started.stdout!r} {started.stderr!r}"
    wanted = {(f"{proto}{'6' if ':' in a else '4'}", f"{a}:{port}") for a in addresses for proto in ("tcp", "udp")}

    def held() -> bool:
        return wanted <= {(s.proto, s.local) for s in _listeners(vm) if s.command == "nc"}

    try:
        h.wait_until(held, timeout=30.0, interval=1.0)
    except RuntimeError as exc:
        have = sorted((s.command, s.proto, s.local) for s in _listeners(vm) if s.port == int(port))
        raise RuntimeError(f"{exc}\nthe listeners do not hold {sorted(wanted)}; sockets on {port}: {have}") from exc


def _release(vm: SmokeVM) -> None:
    _sh(
        vm,
        f"for f in {OCCUPANTS}/*.pid; do [ -f $f ] && kill $(cat $f) 2>/dev/null; done; rm -rf {OCCUPANTS} {MOVE_PHP}",
    )


def _stop_the_proxy_the_move_started(vm: SmokeVM) -> None:
    """Stop the proxy the move's Unbound restart started, bounded, so the test holds the ports before it occupies them.

    pfb_unbound_python() stages the rc script before it restarts Unbound, and the observer include that restart loads
    starts the script when it exists (issue #3515, P4b): an absent rc script no longer keeps the proxy down. Stops
    repeat until nothing is left, so a start still in flight cannot survive the stop.
    """
    h.wait_until(lambda: bool(_capture(vm).ps), timeout=60.0, interval=1.0)
    _say("the move's Unbound restart started the proxy; stopping it before the test takes the ports")

    def stopped() -> bool:
        _force_stop_proxy(vm)
        return _capture(vm).ps == []

    h.wait_until(stopped, timeout=60.0, interval=2.0)


@pytest.mark.timeout(1500)
def test_a_proxy_that_cannot_bind_after_the_move_is_rolled_back_and_dnsbl_keeps_blocking_in_unbound(rig: Rig) -> None:
    """A proxy that never serves leaves the Resolver, and the DNSBL in Unbound, exactly as they were.

    Given pfB-DNS requested and the Resolver already moved (the first half of an activation), the proxy stopped again
      (the move's Unbound restart had started it), and every address the proxy would serve held by another process on
      port 53,
    When the real apply runs (pfb_trigger scope=dnsbl) and the proxy, which cannot bind, never becomes ready,
    Then pfB-DNS is turned off in config.xml, the proxy and its supervisor are gone with their pidfiles, every Resolver
      key equals its pre-toggle value, the marker is cleared, unbound.conf loads the python module again and Unbound
      listens on 53 and 853 as before; the proxy's own log says no address could be bound and the package log says it
      did not become ready;
      And the LAN client's listed name still gets the DNSBL VIP from that Unbound, an allowed name resolves, and DoT
      works: the original mode answers, not merely a config file that says so.
    """
    vm, before = rig.vm, rig.before
    if _is_on(_capture(vm)):  # an earlier test left pfB-DNS on: start from the baseline the rig recorded
        _set_proxy_toggle(vm, False)
        _apply(vm)
    try:
        _set_proxy_toggle(vm, True)
        written = _sh(vm, f"cat > {MOVE_PHP} <<'PHPEOF'\n{MOVE_ONLY_PHP}PHPEOF\n")
        assert written.returncode == 0, f"writing {MOVE_PHP} failed: {written.stderr!r}"
        moved = _sh(vm, f"/usr/local/bin/php {MOVE_PHP}", timeout=300.0)
        found = re.search(r"<<<ADDR>>>(.*)\|(\d+)<<<END>>>", moved.stdout)
        assert found, f"the move step printed no addresses: rc={moved.returncode}\n{moved.stdout}\n{moved.stderr}"
        addresses, port = found.group(1).split(","), found.group(2)
        _say(f"moved; the proxy would serve {addresses} on port {port}")
        h.wait_unbound_ready(vm)
        _stop_the_proxy_the_move_started(vm)
        state = _capture(vm)
        assert state.resolver["active_interface"] == "lo0" and state.marker, f"the Resolver was not moved: {state}"
        assert state.ps == [], f"a proxy is already running: {state.ps}"
        _occupy(vm, addresses, port)

        _apply(vm)

        after = _capture(vm)
        diagnostics = _diagnostics(vm)
        root = _config_xml(vm)
        toggle = _xml_text(root, "installedpackages/pfblockerngdns/config/pfb_dns") or ""
        assert toggle == "", f"pfB-DNS was not turned off: {toggle!r}\n{diagnostics}"
        assert after.service == "stopped" and after.ps == [], f"proxy left running: {after.service} {after.ps}"
        assert after.proxy_pid is None and after.daemon_pid is None, (after.proxy_pid, after.daemon_pid)
        assert after.resolver == before.resolver, (
            f"Resolver keys after the rollback:\n{after.resolver}\nbefore the toggle:\n{before.resolver}"
        )
        assert after.marker == "", f"pfb_dns_proxy_saved is not cleared: {after.marker!r}"
        assert MODULE_LINE.search(after.conf) and SCRIPT_LINE.search(after.conf), f"module not back:\n{after.conf}"
        assert after.unbound_dns() == before.unbound_dns(), (
            f"Unbound sockets {sorted(after.unbound_dns())}, before the toggle {sorted(before.unbound_dns())}"
        )
        assert "no address could be bound" in _proxy_log(vm, 200), (
            f"the proxy did not fail on the held ports:\n{diagnostics}"
        )
        logs = vm.ssh(f"cat {h.PFB_LOG} {h.PFB_LOGDIR}/error.log 2>&1").stdout
        assert "did not become ready" in logs and "was restored to its previous settings" in logs, (
            f"the package logs do not report the rollback:\n{diagnostics}"
        )
        # The holders are this test's own LAN-address listeners: left up, they answer the client checks, not Unbound.
        _release(vm)

        blocked, raw = _query(rig.client, rig.names.blocked)
        assert h.is_vip(blocked), f"blocked name through Unbound again: {blocked}\n{raw}"
        allowed, raw = _query(rig.client, h.unique_domain("rolledback"))
        assert h.resolves_to(allowed, STUB_DNS_A), f"allowed name through Unbound again: {allowed}\n{raw}"
        dot, raw = _query(rig.client, rig.names.blocked, dot=True)
        assert h.is_vip(dot), f"blocked name over Unbound's own DoT again: {dot}\n{raw}"
    finally:
        _release(vm)
        _force_stop_proxy(vm)
        _set_proxy_toggle(vm, False)


@pytest.mark.timeout(1200)
def test_boot_check_without_a_gateway_restores_the_resolver_and_dns(rig: Rig, proxy_on: State) -> None:
    """Given a moved Resolver whose gateway fails every start, the boot start hook's own check restores DNS and files
    both failure notices.

    services_unbound_configure() is what rc.bootup runs: it requires the staged start hook, which backgrounds the rc
    start and the bounded `dns_check` beside it. Scheduled ticks are off on a smoke box and nothing here applies, so
    only that check can roll pfB-DNS back.
    """
    vm, before = rig.vm, rig.before
    notice_ids = ("pfBlockerNG DNS Proxy startup", "pfBlockerNG DNS Proxy")
    clear_notices = (
        "require_once('notices.inc');\n"
        "foreach ((get_notices() ?: []) as $key => $row) {\n"
        f"  if (in_array($row['id'] ?? '', array({', '.join(h._php_str(i) for i in notice_ids)}), TRUE)) {{\n"
        "    close_notice($key);\n"
        "  }\n"
        "}\n"
    )
    read_notices = (
        "require_once('notices.inc');\n"
        "echo '<<<NOTICES>>>' . json_encode(array_values(get_notices() ?: [])) . '<<<END>>>';"
    )
    try:
        assert _is_on(proxy_on) and proxy_on.marker, f"pfB-DNS is not serving with a saved Resolver: {proxy_on}"
        saved = json.loads(base64.b64decode(proxy_on.marker, validate=True))
        assert set(saved) == set(MOVED_KEYS), f"unexpected saved Resolver keys: {saved}"
        valid = _php_ok(
            vm,
            "require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');\n"
            "echo '<<<SAVED>>>' . json_encode(pfb_dns_proxy_saved()) . '<<<END>>>';",
            "validate original Resolver snapshot",
        )
        found = re.search(r"<<<SAVED>>>(.*?)<<<END>>>", valid, re.DOTALL)
        assert found is not None, f"no validated Resolver snapshot in {valid!r}"
        assert json.loads(found.group(1)) == saved, f"the shipped validator rejected the original snapshot: {valid}"
        blocked, raw = _query(rig.client, rig.names.blocked)
        assert h.is_vip(blocked), f"blocked name before stopping pfB-DNS: {blocked}\n{raw}"
        allowed, raw = _query(rig.client, h.unique_domain("bootcheck-before"))
        assert h.resolves_to(allowed, STUB_DNS_A), f"allowed name before stopping pfB-DNS: {allowed}\n{raw}"
        notices = _php_ok(vm, clear_notices + read_notices, "clear startup and rollback notices")
        found = re.search(r"<<<NOTICES>>>(.*?)<<<END>>>", notices, re.DOTALL)
        assert found is not None, f"no notices in {notices!r}"
        rows = json.loads(found.group(1))
        assert not any(row["id"] in notice_ids for row in rows), f"stale failure notices remain: {rows}"

        stopped = _sh(vm, f"{PROXY_RC} stop")
        assert stopped.returncode == 0, f"rc stop failed: {stopped.stdout!r} {stopped.stderr!r}"
        state = _capture(vm)
        assert state.marker == proxy_on.marker, f"rc stop changed the saved Resolver: {state.marker!r}"
        assert state.resolver == proxy_on.resolver, f"rc stop changed the moved Resolver: {state.resolver}"
        assert state.resolver["active_interface"] == "lo0", f"Resolver is not moved: {state.resolver}"
        assert state.proxy_pid is None and state.daemon_pid is None, (state.proxy_pid, state.daemon_pid)
        assert state.service == "stopped" and state.ps == [], f"rc stop left a proxy: {state.service} {state.ps}"

        def rolled_back() -> bool:
            return h.config_get(vm, CFG_PROXY) == "" and _capture(vm).marker == ""

        with _decider_exits_at_every_start(vm):
            _php_ok(vm, "services_unbound_configure();", "services_unbound_configure (the boot start hook)")
            try:
                h.wait_until(rolled_back, timeout=420.0, interval=5.0)
            except RuntimeError as exc:
                raise AssertionError(
                    f"{exc}\nthe boot start hook did not roll pfB-DNS back: toggle {h.config_get(vm, CFG_PROXY)!r}, "
                    f"snapshot kept {bool(_capture(vm).marker)}\n{_diagnostics(vm)}"
                ) from exc
            # The check files its notices after the Unbound restart that ends its rollback: let it finish (360 s cap)
            h.wait_until(
                lambda: _sh(vm, "pgrep -f 'pfblockerng.inc dns_check' >/dev/null").returncode != 0,
                timeout=420.0,
                interval=5.0,
            )
            h.wait_unbound_ready(vm)
            # Read before the decider is put back: putting it back force-stops any proxy a failed rollback left
            after = _capture(vm)
            toggle = h.config_get(vm, CFG_PROXY)
            diagnostics = _diagnostics(vm)

        assert toggle == "", f"pfB-DNS did not stay off:\n{diagnostics}"
        assert after.resolver == before.resolver, (
            f"Resolver after boot-check rollback:\n{after.resolver}\nbefore:\n{before.resolver}"
        )
        assert after.marker == "", f"boot check did not consume the saved Resolver: {after.marker!r}"
        assert after.proxy_pid is None and after.daemon_pid is None, (after.proxy_pid, after.daemon_pid)
        assert after.service == "stopped" and after.ps == [], f"proxy left running: {after.service} {after.ps}"
        assert MODULE_LINE.search(after.conf) and SCRIPT_LINE.search(after.conf), f"module not back:\n{after.conf}"
        assert after.unbound_dns() == before.unbound_dns(), (
            f"Unbound sockets {sorted(after.unbound_dns())}, before the toggle {sorted(before.unbound_dns())}"
        )
        notices = _php_ok(vm, read_notices, "read boot-check failure notices")
        found = re.search(r"<<<NOTICES>>>(.*?)<<<END>>>", notices, re.DOTALL)
        assert found is not None, f"no notices in {notices!r}"
        rows = json.loads(found.group(1))
        for notice_id, phrase in zip(notice_ids, ("did not become ready", "DNS Resolver was restored"), strict=True):
            assert any(row["id"] == notice_id and phrase in row["notice"] for row in rows), (
                f"missing {notice_id!r} notice containing {phrase!r}: {rows}"
            )
        blocked, raw = _query(rig.client, rig.names.blocked)
        assert h.is_vip(blocked), f"first blocked query after boot-check rollback: {blocked}\n{raw}"
        allowed, raw = _query(rig.client, h.unique_domain("bootcheck-restored"))
        assert h.resolves_to(allowed, STUB_DNS_A), f"allowed name after boot-check rollback: {allowed}\n{raw}"
    finally:
        try:
            _force_stop_proxy(vm)
            _set_proxy_toggle(vm, False)
            _apply(vm)
        finally:
            _php_ok(vm, clear_notices, "clear this test's startup and rollback notices")


@pytest.mark.timeout(900)
def test_restored_valid_marker_starts_the_existing_rc_script_and_serves_dns(rig: Rig, proxy_on: State) -> None:
    """Given an rc script staged for snapshot A, a different valid snapshot B still starts it and serves LAN DNS."""
    vm = rig.vm
    marker_a = proxy_on.marker
    try:
        assert _is_on(proxy_on) and marker_a, f"pfB-DNS is not serving with a saved Resolver: {proxy_on}"
        saved_a = json.loads(base64.b64decode(marker_a, validate=True))
        assert set(saved_a) == set(MOVED_KEYS), f"unexpected saved Resolver keys: {saved_a}"
        valid = _php_ok(
            vm,
            "require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');\n"
            "echo '<<<SAVED>>>' . json_encode(pfb_dns_proxy_saved()) . '<<<END>>>';",
            "validate original Resolver snapshot",
        )
        found = re.search(r"<<<SAVED>>>(.*?)<<<END>>>", valid, re.DOTALL)
        assert found is not None, f"no validated Resolver snapshot in {valid!r}"
        assert json.loads(found.group(1)) == saved_a, f"the shipped validator rejected snapshot A: {valid}"
        blocked, raw = _query(rig.client, rig.names.blocked)
        assert h.is_vip(blocked), f"blocked name before replacing the saved Resolver: {blocked}\n{raw}"
        allowed, raw = _query(rig.client, h.unique_domain("marker-before"))
        assert h.resolves_to(allowed, STUB_DNS_A), f"allowed name before replacing the saved Resolver: {allowed}\n{raw}"
        original_rc = vm.ssh("cat", PROXY_RC)
        assert original_rc.returncode == 0, f"reading the staged rc script failed: {original_rc.stderr!r}"

        stopped = _sh(vm, f"{PROXY_RC} stop")
        assert stopped.returncode == 0, f"rc stop failed: {stopped.stdout!r} {stopped.stderr!r}"
        state = _capture(vm)
        assert state.proxy_pid is None and state.daemon_pid is None, (state.proxy_pid, state.daemon_pid)
        assert state.service == "stopped" and state.ps == [], f"rc stop left a proxy: {state.service} {state.ps}"
        assert state.marker == marker_a and state.resolver == proxy_on.resolver, (
            f"rc stop changed Resolver state: {state}"
        )
        saved_b = json.loads(base64.b64decode(marker_a, validate=True))
        custom = saved_b["custom_options"]
        options = base64.b64decode(custom["value"], validate=True) if custom["present"] else b""
        saved_b["custom_options"] = {
            "present": True,
            "value": base64.b64encode(options + b"\n# smoke: restored Resolver snapshot B\n").decode(),
        }
        assert saved_b != saved_a, f"replacement snapshot is not semantically different: {saved_b}"
        marker_b = base64.b64encode(json.dumps(saved_b).encode()).decode()
        _php_ok(
            vm,
            f"config_set_path({h._php_str(CFG_MARKER)}, {h._php_str(marker_b)});\n"
            "write_config('pfBlockerNG smoke: restore a different valid Resolver snapshot');",
            "store replacement Resolver snapshot",
        )
        stored = h.config_get(vm, CFG_MARKER)
        assert stored == marker_b and stored != marker_a, f"replacement marker did not persist: {stored!r}"
        valid = _php_ok(
            vm,
            "require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');\n"
            "echo '<<<SAVED>>>' . json_encode(pfb_dns_proxy_saved()) . '<<<END>>>';",
            "validate replacement Resolver snapshot",
        )
        found = re.search(r"<<<SAVED>>>(.*?)<<<END>>>", valid, re.DOTALL)
        assert found is not None, f"no validated replacement snapshot in {valid!r}"
        assert json.loads(found.group(1)) == saved_b, f"the shipped validator rejected snapshot B: {valid}"
        staged_rc = vm.ssh("cat", PROXY_RC)
        assert staged_rc.returncode == 0, f"reading rc before start failed: {staged_rc.stderr!r}"
        assert staged_rc.stdout == original_rc.stdout, "replacing the saved Resolver rewrote the staged rc script"

        started = _sh(vm, f"{PROXY_RC} start")
        assert started.returncode == 0, f"rc start failed: {started.stdout!r} {started.stderr!r}"
        _wait_proxy_serves(rig)

        after = _capture(vm)
        assert _is_on(after) and after.proxy_pid is not None and after.daemon_pid is not None, (
            f"the existing rc script did not start a live gateway and supervisor: {after}"
        )
        assert after.marker == marker_b, f"rc start changed snapshot B: {after.marker!r}"
        assert after.resolver == proxy_on.resolver, f"rc start changed the moved Resolver: {after.resolver}"
        running_rc = vm.ssh("cat", PROXY_RC)
        assert running_rc.returncode == 0, f"reading rc after start failed: {running_rc.stderr!r}"
        assert running_rc.stdout == original_rc.stdout, "rc start rewrote the staged rc script"
        blocked, raw = _query(rig.client, rig.names.blocked)
        assert h.is_vip(blocked), f"blocked name with restored snapshot B: {blocked}\n{raw}"
        allowed, raw = _query(rig.client, h.unique_domain("marker-restored"))
        assert h.resolves_to(allowed, STUB_DNS_A), f"allowed name with restored snapshot B: {allowed}\n{raw}"
    finally:
        _force_stop_proxy(vm)
        _php_ok(
            vm,
            f"config_set_path({h._php_str(CFG_MARKER)}, {h._php_str(marker_a)});\n"
            "write_config('pfBlockerNG smoke: restore original Resolver snapshot');",
            "restore original Resolver snapshot",
        )
        _set_proxy_toggle(vm, False)
        _apply(vm)
        restored = _capture(vm)
        assert restored.resolver == rig.before.resolver, (
            f"Resolver after restoring snapshot A:\n{restored.resolver}\nbefore:\n{rig.before.resolver}"
        )
        assert restored.marker == "", f"cleanup did not consume snapshot A: {restored.marker!r}"


# --------------------------------------------------------------------------- #
# A decision service that exits before READY at every start (issue #3561)
# --------------------------------------------------------------------------- #

DECIDER = "/usr/local/pkg/pfblockerng/dns_proxy/pfb_dns_proxy.py"  # the gateway's decider, run by pfb_python.sh
DECIDER_ASIDE = "/var/tmp/pfb3561_decider.py"  # the shipped decider while the failing one stands in for it
SERVICES_ASIDE = "/var/tmp/pfb3561_services.json"  # installedpackages/service while the proxy's entry is taken out
FAILING_DECIDER = 'raise SystemExit("pfBlockerNG smoke #3561: the decision service exits before READY")\n'
BETWEEN_STARTS_CAP = 60  # s: a supervisor restarting every 5 s waits between two starts well within this


@contextlib.contextmanager
def _decider_exits_at_every_start(vm: SmokeVM) -> Iterator[None]:
    """The shipped decider replaced by one that exits at once, so every start of the gateway fails before READY (the
    issue's `decider failed before READY: EOF`); the shipped file is put back, mode and owner kept, however the test
    ends."""
    try:
        # An aside an interrupted case left holds the shipped decider: keep it, never copy the failing one over it
        swapped = _sh(
            vm,
            f"[ -e {DECIDER_ASIDE} ] || cp -p {DECIDER} {DECIDER_ASIDE}; "
            f"[ -e {DECIDER_ASIDE} ] && printf '%s' {shlex.quote(FAILING_DECIDER)} > {DECIDER}",
        )
        assert swapped.returncode == 0, f"replacing {DECIDER} failed: {swapped.stderr!r}"
        yield
    finally:
        _force_stop_proxy(vm)
        back = _sh(vm, f"[ ! -e {DECIDER_ASIDE} ] || {{ cp -p {DECIDER_ASIDE} {DECIDER} && rm -f {DECIDER_ASIDE}; }}")
        assert back.returncode == 0, f"putting the shipped {DECIDER} back failed: {back.stderr!r}"


@contextlib.contextmanager
def _proxy_service_entry(vm: SmokeVM, *, registered: bool) -> Iterator[None]:
    """The package's pfb_dns_proxy service entry as it is, or taken out of installedpackages/service the way an install
    or upgrade has it until pfSense's services block registers it (after the package's install and resync commands);
    pfSense's start_service()/stop_service() act only on a registered service. The entries are put back afterwards."""
    if registered:
        yield
        return
    _php_ok(
        vm,
        "$all = config_get_path('installedpackages/service', array());\n"
        f"file_put_contents({h._php_str(SERVICES_ASIDE)}, json_encode($all));\n"
        "config_set_path('installedpackages/service', array_values(array_filter($all,\n"
        f"  static fn ($s) => (is_array($s) ? ($s['name'] ?? '') : '') !== {h._php_str(SERVICE)})));\n"
        "write_config('pfBlockerNG smoke: the DNS proxy service entry taken out, as during an install');",
        "taking the service entry out",
    )
    try:
        assert SERVICE not in _registered_services(vm), "the service entry is still registered"
        yield
    finally:
        aside = h._php_str(SERVICES_ASIDE)
        _php_ok(
            vm,
            f"config_set_path('installedpackages/service', json_decode(file_get_contents({aside}), true));\n"
            "write_config('pfBlockerNG smoke: the DNS proxy service entry registered again');\n"
            f"unlink({aside});",
            "registering the service entry again",
        )


def _between_starts(vm: SmokeVM) -> tuple[int, str]:
    """Wait (bounded) until the supervisor is alive while no child runs, its restart delay, and return its pid with what
    `ps -axww -o pid,ppid,command`, the child pidfile's size and the supervisor pidfile show at that moment."""
    script = (
        f"deadline=$(( $(date +%s) + {BETWEEN_STARTS_CAP} ))\n"
        "while true; do\n"
        f"  d=$(cat {DAEMON_PID_FILE} 2>/dev/null); c=$(cat {PROXY_PID_FILE} 2>/dev/null)\n"
        '  if [ -n "$d" ] && kill -0 "$d" 2>/dev/null && { [ -z "$c" ] || ! kill -0 "$c" 2>/dev/null; }; then\n'
        f'    echo "SUPERVISOR=$d CHILD=[$c] CHILD_PIDFILE_BYTES=$(wc -c < {PROXY_PID_FILE} 2>/dev/null)"\n'
        "    ps -axww -o pid,ppid,command; exit 0\n"
        "  fi\n"
        '  if [ "$(date +%s)" -ge "$deadline" ]; then\n'
        '    echo "no restart delay seen"; ps -axww -o pid,ppid,command; exit 1\n'
        "  fi\n"
        "  sleep 0.2\n"
        "done\n"
    )
    seen = _sh(vm, script, timeout=BETWEEN_STARTS_CAP + 30.0)
    found = re.search(r"^SUPERVISOR=(\d+) ", seen.stdout, re.MULTILINE)
    assert seen.returncode == 0 and found, (
        f"the supervisor never waited between two starts:\n{seen.stdout}\n{_diagnostics(vm)}"
    )
    _say(f"between two failed starts:\n{seen.stdout}")
    return int(found.group(1)), seen.stdout


def _alive(vm: SmokeVM, pid: int) -> bool:
    return vm.ssh(f"kill -0 {pid}").returncode == 0


@pytest.mark.timeout(600)
def test_a_supervisor_waiting_between_failed_starts_still_names_the_proxy_and_the_rc_stop_ends_it(
    rig: Rig, proxy_on: State
) -> None:
    """daemon(8) -r keeps the title it set at its last start through the restart delay; the rc stop must match it.

    Given pfB-DNS on and a decision service that exits before READY at every start,
    When the rc script starts the proxy and its supervisor waits out the restart delay (no child running),
    Then the supervisor's command line still names pfb_dns_proxy, the pattern the rc stop signals by,
      And `pfb_dns_proxy.sh stop` exits 0 with the supervisor gone and both pidfiles removed.
    """
    vm = rig.vm
    _force_stop_proxy(vm)
    with _decider_exits_at_every_start(vm):
        start = vm.ssh(PROXY_RC, "start")
        assert start.returncode == 0, f"{PROXY_RC} start: rc={start.returncode} {start.stdout!r} {start.stderr!r}"
        supervisor, seen = _between_starts(vm)
        line = next((row for row in seen.splitlines() if row.split()[:1] == [str(supervisor)]), "")
        assert "pfb_dns_proxy" in line, (
            f"the waiting supervisor's command line does not name the proxy: {line!r}\n{seen}"
        )

        stop = vm.ssh(PROXY_RC, "stop")

        assert stop.returncode == 0, f"{PROXY_RC} stop: rc={stop.returncode} {stop.stdout!r} {stop.stderr!r}"
        assert not _alive(vm, supervisor), f"the supervisor {supervisor} outlived the rc stop:\n{_diagnostics(vm)}"
        assert _pid_file(vm, DAEMON_PID_FILE) is None and _pid_file(vm, PROXY_PID_FILE) is None, "a pidfile is left"


@pytest.mark.timeout(1500)
@pytest.mark.parametrize("registered", [True, False], ids=["service-registered", "service-entry-absent"])
def test_a_decider_that_exits_at_every_start_is_rolled_back_with_no_supervisor_left(
    rig: Rig, proxy_on: State, registered: bool
) -> None:
    """A failed activation ends with the supervisor gone and the Resolver restored, registered service entry or not.

    Given pfB-DNS on, a decision service that exits before READY at every start, the package's service entry
      registered or taken out (an install's window: pfSense's stop_service() then does nothing), and the proxy started
      by the Resolver's start hook (services_unbound_configure(), as the install's resync restarts Unbound),
    When the real apply runs (pfb_trigger scope=dnsbl) and the proxy never becomes ready,
    Then pfB-DNS is turned off, no supervisor or gateway runs and no pidfile is left (nothing keeps respawning), every
      Resolver key equals its pre-toggle value and the snapshot marker is empty.
    """
    vm, before = rig.vm, rig.before
    _force_stop_proxy(vm)
    try:
        with _decider_exits_at_every_start(vm), _proxy_service_entry(vm, registered=registered):
            _php_ok(vm, "services_unbound_configure();", "services_unbound_configure (the start hook)")
            h.wait_unbound_ready(vm)
            supervisor, _ = _between_starts(vm)

            _apply(vm)

            after = _capture(vm)
            diagnostics = _diagnostics(vm)
            toggle = _xml_text(_config_xml(vm), "installedpackages/pfblockerngdns/config/pfb_dns") or ""
            assert toggle == "", f"pfB-DNS was not turned off: {toggle!r}\n{diagnostics}"
            assert not _alive(vm, supervisor), (
                f"the hook's supervisor {supervisor} survived the rollback:\n{diagnostics}"
            )
            assert after.ps == [] and after.daemon_pid is None and after.proxy_pid is None, (
                f"a proxy is left after the rollback: {after.ps} {after.daemon_pid} {after.proxy_pid}\n{diagnostics}"
            )
            assert after.resolver == before.resolver, (
                f"Resolver keys after the rollback:\n{after.resolver}\nbefore the toggle:\n{before.resolver}\n"
                f"{diagnostics}"
            )
            assert after.marker == "", f"pfb_dns_saved is not cleared: {after.marker!r}\n{diagnostics}"
    finally:
        _force_stop_proxy(vm)
        _set_proxy_toggle(vm, False)


# $g['cf_conf_path'] is per process (pfsense/pfsense@209b8baa8 config.lib.inc): a scratch dir with a writable backup/
# and a directory as config.xml lets backup_config() finish (:936-961) while safe_write_file()'s rename fails (:516), so
# write_config() answers -1 (:607-610); the reads use conf_path (:1287), which stays.
REFUSE_DIR = "/tmp/pfb3561_cf"
REFUSED_RESTORE_PHP = (
    "require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');\n"
    "require_once('/usr/local/pkg/pfblockerng/pfblockerng_extra.inc');\n"
    "global $pfb;\n"
    "pfb_global();\n"
    f"g_set('cf_conf_path', {h._php_str(REFUSE_DIR)}, TRUE);\n"
    "$restored = pfb_dns_proxy_resolver(FALSE);\n"
    "echo '<<<RESTORED>>>' . var_export($restored, TRUE) . '<<<END>>>';"
)
# pfb_dns_proxy_resolver_unchanged()'s line for a restore that config.xml did not take
NOT_PUT_BACK = "the DNS Resolver was not put back because config.xml could not be written"
RECOVERY_CAP = 90.0  # s: the restore's start returns at once, the ready marker follows the decider's boot


def _logged(vm: SmokeVM, text: str) -> int:
    """How often `text` stands in pfblockerng.log and error.log together (a line may be in either, or both)."""
    return sum(h.count_log_marker(vm, path, text) for path in (h.PFB_LOG, f"{h.PFB_LOGDIR}/error.log"))


@contextlib.contextmanager
def _config_dir_that_refuses_config_xml(vm: SmokeVM) -> Iterator[None]:
    """A scratch config directory: backup/ takes writes, config.xml is a directory nothing can be renamed onto."""
    try:
        made = _sh(vm, f"rm -rf {REFUSE_DIR} && mkdir -p {REFUSE_DIR}/backup {REFUSE_DIR}/config.xml")
        assert made.returncode == 0, f"creating {REFUSE_DIR} failed: {made.stdout!r} {made.stderr!r}"
        yield
    finally:
        _sh(vm, f"rm -rf {REFUSE_DIR}")


@pytest.mark.timeout(1500)
def test_a_refused_restore_starts_the_proxy_again_with_the_service_entry_absent(rig: Rig, proxy_on: State) -> None:
    """A restore that config.xml refuses leaves the proxy serving the still-moved Resolver, whatever pfSense registers.

    Given pfB-DNS on and serving, the package's service entry absent (an install's window: pfSense's restart_service()
      starts nothing), and a process whose write_config() answers -1,
    When pfb_dns_proxy_resolver(FALSE) runs in it (the restore of an apply or a rollback: it stops the proxy, then its
      write of the restored Resolver is refused),
    Then it answers FALSE and logs that the Resolver was not put back, config.xml still holds the snapshot and the moved
      Resolver, and the proxy serves again: a new child whose pid is the ready marker, pfb-dns alone holding port 53 on
      the LAN address, and the client's listed name getting the VIP.

    Fault limit: no refusal is seen by one process only, except through that process's own $g['cf_conf_path'] (pfSense
    CE 2.8.1, pfsense/pfsense@209b8baa8, src/etc/inc/config.lib.inc). A path nothing can be created under is fatal; a
    scratch directory with a writable backup/ and a directory as config.xml is not: backup_config() (:936-961) warns
    and returns, config_write_file() (:1244-1265) fails at safe_write_file()'s rename (:516), write_config() answers
    -1 (:607-610), and /cf, the real config.xml and the files' modes are untouched. Its FALSE answers are a read-only
    user (a web session: ui/test_dns_readonly_save.py) and reset_factory_defaults, which the fresh read under the config
    lock erases; pfb_dns_config_write_failed() treats -1 and FALSE alike. The refusal raises a config.xml notice
    and PHP warnings (filesize(), copy() of the directory) that stay on the box.
    """
    vm = rig.vm
    child = proxy_on.proxy_pid
    assert child is not None and _marker(vm) == f"{child}\n", f"the proxy does not serve at the start: {proxy_on}"
    refused = _logged(vm, NOT_PUT_BACK)
    try:
        with _config_dir_that_refuses_config_xml(vm), _proxy_service_entry(vm, registered=False):
            result = h.php_eval(vm, REFUSED_RESTORE_PHP, timeout=300.0)
            found = re.search(r"<<<RESTORED>>>(\w+)<<<END>>>", result.stdout)
            assert found and result.returncode == 0, (
                f"the restore did not finish: rc={result.returncode}\n{result.stdout}\n{result.stderr}"
            )
            assert found.group(1) == "false", f"pfb_dns_proxy_resolver(FALSE) answered {found.group(1)}, not FALSE"
            assert _logged(vm, NOT_PUT_BACK) > refused, (
                f"the logs do not say the restore was refused:\n{_diagnostics(vm)}"
            )

            def serving() -> bool:
                pid = _pid_file(vm, PROXY_PID_FILE)
                return pid is not None and _marker(vm) == f"{pid}\n" and _alive(vm, pid)

            try:
                h.wait_until(serving, timeout=RECOVERY_CAP, interval=3.0)
            except RuntimeError as exc:
                raise RuntimeError(f"{exc}\nno proxy serves after the refused restore:\n{_diagnostics(vm)}") from exc

            after = _capture(vm)
            assert after.proxy_pid is not None and after.proxy_pid != child, (
                f"the serving proxy {after.proxy_pid} is not a new one (was {child}):\n{_diagnostics(vm)}"
            )
            assert after.marker == proxy_on.marker and after.resolver == proxy_on.resolver, (
                f"config.xml changed although the write was refused:\nmarker set: {bool(after.marker)}\n"
                f"{after.resolver}\nbefore:\n{proxy_on.resolver}"
            )
            assert after.resolver["active_interface"] == "lo0", f"the Resolver is not moved: {after.resolver}"
            on53 = {s.pid for s in after.listeners if s.local.endswith(":53")}
            assert on53 == {after.proxy_pid}, f"port 53 is held by pids {on53}, the proxy is {after.proxy_pid}"
            lan = {s.command for s in after.listeners if s.pid == after.proxy_pid and s.local == f"{PFSENSE_LAN_IP}:53"}
            assert lan == {"pfb-dns"}, f"{PFSENSE_LAN_IP}:53 is held by {lan}, not pfb-dns"
            _wait_proxy_serves(rig)
    finally:
        # The refused restore keeps the Resolver moved and the snapshot: a real apply with the toggle off puts them back
        _force_stop_proxy(vm)
        _set_proxy_toggle(vm, False)
        _apply(vm)


# --------------------------------------------------------------------------- #
# An aborted removal: pfSense's own half of `pkg delete` ran, the hook stopped the removal, pfB-DNS must still serve
# --------------------------------------------------------------------------- #

_ABORT_DIR = "/tmp/pfb3515_abort"
_LOCK_HELD = f"{_ABORT_DIR}/lock_held"
_LOCK_GO = f"{_ABORT_DIR}/lock_go"
_LOCK_FAILED = f"{_ABORT_DIR}/lock_failed"
_DELETE_OUT = f"{_ABORT_DIR}/delete.out"
_RECOVERING = "restoring the DNS proxy, the package's service entries and its menu entry"
# The lines of the shipped /etc/inc/pkg-utils.inc delete_package_xml() that run BEFORE the package's hook, and its call
_CORE_PRELUDE_LINES = (
    r"stop_service(\$service\['name'\])\|unlink_if_exists(\$prefix\|config_del_path(\"installedpackages/service"
    r"\|eval_once(\$pkg_config\['custom_php_pre_deinstall_command'\])"
)


def _await_delete(vm: SmokeVM, done: Callable[[str], bool], *, timeout: float) -> str:
    """Poll pkg delete's output until ``done`` holds and return it; an expiry carries the output so far.

    The diagnostics archive omits /tmp, so this error is the only record of what pkg printed.
    """
    try:
        h.wait_until(lambda: done(h.read_log_file(vm, _DELETE_OUT)), timeout=timeout, interval=2.0)
    except RuntimeError as exc:
        raise RuntimeError(f"{exc}\n{_DELETE_OUT} so far:\n{h.read_log_file(vm, _DELETE_OUT)}") from exc
    return h.read_log_file(vm, _DELETE_OUT)


def _delete_in_background(vm: SmokeVM) -> str:
    """Start `pkg delete` detached; returns the pid of the shell that runs it and then writes `RC=`."""
    command = f"env ASSUME_ALWAYS_YES=yes pkg delete -y {PKG_NAME} > {_DELETE_OUT} 2>&1; echo RC=$? >> {_DELETE_OUT}"
    started = vm.ssh(f"nohup /bin/sh -c '{command}' >/dev/null 2>&1 & echo $!")
    pid = started.stdout.strip()
    assert pid.isdigit(), f"no pid for the background pkg delete: {started.stdout!r} {started.stderr!r}"
    return pid


def _registered_services(vm: SmokeVM) -> list[str]:
    root = _config_xml(vm)
    return [(s.findtext("name") or "") for s in root.findall("./installedpackages/service")]


@pytest.mark.timeout(1500)
def test_an_aborted_removal_keeps_pfb_dns_serving_and_a_retry_removes_the_package(rig: Rig) -> None:
    """`pkg delete` while another save holds the config lock: the removal stops, pfB-DNS keeps answering, a retry works.

    Given pfB-DNS on with DNSBL on (the Resolver moved, the proxy answering a listed name with the VIP),
      and another process holding pfSense's `pfb_dns_config` lock,
    When `pkg delete` runs (pfSense stops and deregisters the services before the hook; the hook cannot restore the
      Resolver),
    Then pkg leaves the package installed, its output says the removal stopped and that the service entries and the
      proxy are back, the three services are registered in config.xml, the proxy runs and answers the listed name with
      the VIP and an allowed name with the upstream's answer, the Resolver is still moved and the snapshot kept;
    When the lock is free and `pkg delete` runs again,
    Then the package is removed, the proxy is stopped, the Resolver is back and Unbound answers the client.

    Records the box's pkg version and the shipped core lines this depends on. Always releases the lock and redeploys.
    """
    vm, client = rig.vm, rig.client
    _toggle_on(rig)
    _sh(vm, f"rm -rf {_ABORT_DIR} && mkdir -p {_ABORT_DIR}")
    _say(f"pkg: {vm.ssh('pkg --version').stdout.strip()}; pfSense: {vm.ssh('cat /etc/version').stdout.strip()}")
    _say(
        "shipped core, /etc/inc/pkg-utils.inc:\n"
        + vm.ssh("grep", "-n", _CORE_PRELUDE_LINES, "/etc/inc/pkg-utils.inc").stdout
    )
    delete_pid = ""  # the background pkg delete the `finally` must see finished
    try:
        before, raw = _query(client, rig.names.blocked)
        assert h.is_vip(before), f"before: the listed name is not blocked with the VIP: {before}\n{raw}"
        assert pkg_installed_version(vm) is not None, "before: the package is not installed"

        # lock() takes "{$g['tmp_path']}/pfb_dns_config.lock": $g needs globals.inc first, as pkg-utils.inc loads it.
        holder = (
            'require_once("globals.inc"); require_once("util.inc"); $k = lock("pfb_dns_config", LOCK_EX); '
            f'if (!is_resource($k)) {{ touch("{_LOCK_FAILED}"); exit(1); }} touch("{_LOCK_HELD}"); $i = 0; '
            f'while (!file_exists("{_LOCK_GO}") && $i++ < 1800) {{ usleep(100000); }} unlock($k);'
        )
        vm.ssh(f"nohup {h.PHP_BIN} -r '{holder}' >/dev/null 2>&1 &")
        h.wait_until(
            lambda: h.hook_marker_exists(vm, _LOCK_HELD) or h.hook_marker_exists(vm, _LOCK_FAILED),
            timeout=60.0,
            interval=1.0,
        )
        assert h.hook_marker_exists(vm, _LOCK_HELD), "the holder could not take pfb_dns_config: lock() gave no handle"
        # Fail fast unless a fresh process, started as pkg's hook is, finds the lock taken.
        probe_php = (
            'require_once("globals.inc"); require_once("util.inc"); '
            '$x = try_lock("pfb_dns_config", 1); echo is_resource($x) ? "ACQUIRED" : "NULL";'
        )
        probe = vm.ssh(f"{h.PHP_BIN} -r '{probe_php}'").stdout.strip()
        assert probe == "NULL", (
            f"a fresh process got pfb_dns_config while the holder has it ({probe}); lock files:\n"
            + vm.ssh("ls -l /tmp/pfb_dns_config.lock /pfb_dns_config.lock 2>&1").stdout
        )

        delete_pid = _delete_in_background(vm)
        # The recovery announces itself before it waits for the lock; an RC= first means it never waited.
        out = _await_delete(vm, lambda text: _RECOVERING in text or "RC=" in text, timeout=300.0)
        assert _RECOVERING in out, f"pkg delete finished without the recovery waiting for the config lock:\n{out}"
        vm.ssh(f"touch {_LOCK_GO}")
        out = _await_delete(vm, lambda text: "RC=" in text, timeout=300.0)

        assert "removal was stopped" in out, f"pkg delete did not stop the removal:\n{out}"
        assert "service entries were registered again and the DNS proxy is running" in out, (
            f"recovery did not report success:\n{out}"
        )
        assert pkg_installed_version(vm) is not None, f"pkg removed the package although the hook aborted:\n{out}"
        state = _capture(vm)
        assert state.service == "running", f"the proxy is not running after the aborted removal:\n{_diagnostics(vm)}"
        assert {"pfb_dnsbl", "pfb_dns_proxy", "pfb_filter"} <= set(_registered_services(vm)), _registered_services(vm)
        assert state.resolver["active_interface"] == "lo0" and state.marker, (
            f"the Resolver is not still moved: {state.resolver}"
        )
        blocked, raw = _query(client, rig.names.blocked)
        assert h.is_vip(blocked), f"after the aborted removal the listed name is not blocked: {blocked}\n{raw}"
        allowed, raw = _query(client, h.unique_domain("aborted"))
        assert h.resolves_to(allowed, STUB_DNS_A), (
            f"after the aborted removal an allowed name is not answered: {allowed}\n{raw}"
        )

        delete_pid = _delete_in_background(vm)
        h.wait_until(lambda: "RC=" in h.read_log_file(vm, _DELETE_OUT), timeout=600.0, interval=2.0)
        out = h.read_log_file(vm, _DELETE_OUT)
        assert out.rstrip().endswith("RC=0"), f"the retry's pkg delete failed:\n{out}"
        assert pkg_installed_version(vm) is None, f"the retry did not remove the package:\n{out}"
        state = _capture(vm)
        assert state.service != "running" and state.marker == "", f"the retry left the proxy or the snapshot: {state}"
        allowed, raw = _query(client, h.unique_domain("retried"))
        assert h.resolves_to(allowed, STUB_DNS_A), f"after the removal Unbound does not answer: {allowed}\n{raw}"
    finally:
        vm.ssh(f"mkdir -p {_ABORT_DIR}; touch {_LOCK_GO}")
        stuck: RuntimeError | None = None
        if delete_pid:
            try:
                h.wait_until(lambda: vm.ssh(f"kill -0 {delete_pid}").returncode != 0, timeout=300.0, interval=2.0)
            except RuntimeError as exc:
                stuck = exc
                # shortcut: kills the shell and pkg, not what pkg's own hooks started; upgrade when a hook outlives it
                vm.ssh(f"pkill -KILL -P {delete_pid}; kill -KILL {delete_pid}")
        vm.ssh(f"rm -rf {_ABORT_DIR}")
        if pkg_installed_version(vm) is None:
            h.deploy(vm)
        if stuck is not None:
            raise RuntimeError(
                f"STUCK/ENVIRONMENT: pkg delete (pid {delete_pid}) was still running 300 s after the config lock was "
                f"released; it was killed and the cleanup finished: {stuck}"
            ) from stuck
