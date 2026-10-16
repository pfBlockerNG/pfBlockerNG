"""Issue #3512 (map #3511), step C: the DNS front end prototype, proven live on a pfSense VM with a LAN client.

The prototype (``prototype/dns_frontend/``) is a pure-Python DNS server on the client-facing ports. It runs the
SHIPPED ``pfb_unbound.py`` unchanged, answers DNSBL decisions itself and forwards everything else to Unbound,
moved to ``127.0.0.1:5353``, with a PROXYv2 header so Unbound still sees the real client address.

Module fixture, restored in ``finally``::

    pfSense Resolver: port 5353, Localhost only, DoT on with a self-signed certificate,
                      ``proxy-protocol-port: 5353`` + ``log-queries: yes``, python module and DoT listeners removed
    front end:        192.168.1.1 + 127.0.0.1, port 53 (UDP+TCP) and 853 (DoT), started with ``daemon(8)``

What the tests prove, from the LAN client VM (192.168.1.10):

* a listed name gets the DNSBL VIP, ``dnsbl.log`` names the feed and the client, and Unbound never saw the name;
* an allowed name gets Unbound's answer, and Unbound's query log names the CLIENT, not 127.0.0.1 (PROXYv2 over UDP);
* the same over TCP and over DoT with the Resolver's own certificate (PROXYv2 TCP header, TLS peer address);
* an Unbound ACL that refuses the client reaches it as REFUSED through the front end.

Every live discovery is printed as ``[3512] ...`` lines for the ticket's findings. The prototype directory is read
from the git object store (``git archive``): the smoke box's sparse checkout leaves ``prototype/`` out of the
working tree.

DESELECTED from the default ``python -m pytest``. Run it on the pool::

    scripts/local-smoke.sh --ref issue/3512-dns-frontend-prototype --filter test_smoke_dns_frontend
"""

from __future__ import annotations

import base64
import csv
import io
import os
import re
import shlex
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from . import helpers as h
from .conftest import CLIENT_LAN_IP, PFSENSE_LAN_IP, STUB_DNS_A, SmokeVM, _StubDnsServer

pytestmark = [pytest.mark.smoke, pytest.mark.timeout(180)]

REPO_ROOT = Path(__file__).resolve().parents[2]
PROTOTYPE_GLOB = ":(glob)prototype/dns_frontend/*.py"  # the code, not prototype/dns_frontend/tests/

GUEST_DIR = "/root/pfb3512_frontend"
PID_FILE = "/var/run/pfb_frontend.pid"
LOG_FILE = "/var/log/pfb_frontend.log"
SNAPSHOT_FILE = "/tmp/pfb3512_cfg_snapshot.json"  # on the guest: survives a dead test process
CERT_GUEST = "/tmp/pfb3512_cert.pem"
CERT_CLIENT = "/tmp/pfb3512_ca.pem"
RESOLVER_LOG = "/var/log/resolver.log"
DNSBL_LOG = f"{h.PFB_LOGDIR}/dnsbl.log"
PY_LAUNCHER = "/usr/local/pkg/pfblockerng/pfb_python.sh"

UNBOUND_PORT = 5353  # where the front end finds Unbound; also its proxy-protocol-port
DOT_PORT = 853
CERT_NAME = "pfsense-3512.pfb.localdomain"
FEED_HEADER = "smoke3512"
DONE = "PFB3512-DONE"

# Everything the fixture touches, snapshotted whole and put back verbatim.
SNAPSHOT_PATHS = (
    "unbound/port",
    "unbound/active_interface",
    "unbound/enablessl",
    "unbound/sslcertref",
    "unbound/tlsport",
    "unbound/custom_options",
    "unbound/acls",
    "cert",
)

PFSENSE_LAN_NET = "192.168.1.0/24"  # pfSense allows it in access_lists.conf even with the Resolver on Localhost only

Acl = tuple[str, str, str, str]  # (name, action, network, mask)


@dataclass
class Rig:
    vm: SmokeVM
    client: SmokeVM
    blocked: str  # the one listed domain
    findings: dict[str, str] = field(default_factory=dict)


def _say(message: str) -> None:
    print(f"[3512] {message}", flush=True)


# --------------------------------------------------------------------------- #
# Guest plumbing
# --------------------------------------------------------------------------- #


def _sh(vm: SmokeVM, script: str, *, timeout: float = 120.0) -> subprocess.CompletedProcess[str]:
    """Run a POSIX sh script on the guest, fed on stdin (the guest's login shell is tcsh)."""
    return subprocess.run(
        vm.ssh_argv("/bin/sh"), input=script, capture_output=True, text=True, timeout=timeout, check=False
    )


def _sh_ok(vm: SmokeVM, script: str, what: str, *, timeout: float = 120.0) -> str:
    result = _sh(vm, script, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(f"{what} failed: rc={result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}")
    return result.stdout


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
        "write_config('pfBlockerNG smoke: restore the Resolver config after the #3512 front end');",
        "config restore",
    )


def _create_cert(vm: SmokeVM) -> str:
    """A self-signed server certificate in the config (the way pfb_create_dnsbl_cert() makes one); returns its refid."""
    out = h.php_eval(
        vm,
        "require_once('certs.inc');\n"
        "$cert = array();\n"
        "$cert['refid'] = uniqid();\n"
        "$cert['descr'] = 'pfBlockerNG 3512 front end smoke';\n"
        "$dn = array('organizationName' => 'pfBlockerNG 3512 smoke',"
        f" 'commonName' => {h._php_str(CERT_NAME)}, 'subjectAltName' => {h._php_str('DNS:' + CERT_NAME)});\n"
        "$old = error_reporting(0);\n"
        "$made = cert_create($cert, null, 2048, 398, $dn, 'self-signed', 'sha256');\n"
        "error_reporting($old);\n"
        "if (!$made) { echo '<<<FAILED>>>'; } else {\n"
        "  $all = config_get_path('cert', array());\n"
        "  $all[] = $cert;\n"
        "  config_set_path('cert', $all);\n"
        "  write_config('pfBlockerNG smoke: DoT certificate for the #3512 front end');\n"
        f"  file_put_contents({h._php_str(CERT_GUEST)}, base64_decode($cert['crt']));\n"
        "  echo '<<<REFID>>>' . $cert['refid'] . '<<<END>>>';\n"
        "}",
        timeout=180.0,
    )
    match = re.search(r"<<<REFID>>>(\w+)<<<END>>>", out.stdout)
    if out.returncode != 0 or match is None:
        raise RuntimeError(f"cert_create failed: rc={out.returncode}\nstdout:\n{out.stdout}\nstderr:\n{out.stderr}")
    return match.group(1)


def _set_resolver(vm: SmokeVM, refid: str) -> None:
    """Resolver: port 5353, Localhost only, DoT on with the certificate, PROXYv2 accepted, queries logged."""
    custom = f"server:\nlog-queries: yes\nproxy-protocol-port: {UNBOUND_PORT}\n"
    _php_ok(
        vm,
        "$u = config_get_path('unbound', array());\n"
        f"$u['port'] = {h._php_str(str(UNBOUND_PORT))};\n"
        "$u['active_interface'] = 'lo0';\n"
        "$u['enablessl'] = 'yes';\n"
        f"$u['sslcertref'] = {h._php_str(refid)};\n"
        f"$u['tlsport'] = {h._php_str(str(DOT_PORT))};\n"
        f"$u['custom_options'] = {h._php_str(base64.b64encode(custom.encode()).decode())};\n"
        "unset($u['acls']);\n"
        "config_set_path('unbound', $u);\n"
        "write_config('pfBlockerNG smoke: Resolver set up for the #3512 front end');",
        "Resolver settings",
    )


def _set_acls(vm: SmokeVM, acls: list[Acl]) -> None:
    """The DNS Resolver > Access Lists, replaced by `acls` (one network per list)."""
    lists = ", ".join(
        f"array('aclname' => {h._php_str(name)}, 'aclaction' => {h._php_str(action)},"
        f" 'description' => {h._php_str(name)},"
        f" 'row' => array(array('acl_network' => {h._php_str(net)}, 'mask' => {h._php_str(mask)},"
        f" 'description' => {h._php_str(name)})))"
        for name, action, net, mask in acls
    )
    snippet = f"config_set_path('unbound/acls', array({lists}));\n" if acls else "config_del_path('unbound/acls');\n"
    _php_ok(
        vm,
        snippet + "write_config('pfBlockerNG smoke: Resolver access lists for the #3512 front end');",
        "Resolver access lists",
    )


def strip_front_end_conflicts(conf: str, tls_port: int) -> tuple[str, list[str]]:
    """`conf` without what the front end replaces: Unbound's python module and its own DoT listeners.

    PROTOTYPE ONLY. The front end runs pfb_unbound.py itself, so Unbound must not run it a second time, and it owns
    the DoT port, so Unbound must not bind it. A real integration would generate this configuration, not patch it.
    Returns the new text and the removed or changed lines.
    """
    kept: list[str] = []
    changed: list[str] = []
    for line in conf.splitlines():
        if re.match(r"\s*(python|python-script|tls-service-key|tls-service-pem|tls-port)\s*:", line) or re.match(
            rf"\s*interface\s*:\s*\S+@{tls_port}\s*$", line
        ):
            changed.append(f"removed: {line.strip()}")
            continue
        if re.match(r"\s*module-config\s*:", line) and re.search(r"\bpython\b", line):
            new = re.sub(r"\bpython\s+", "", line)
            changed.append(f"changed: {line.strip()} -> {new.strip()}")
            kept.append(new)
            continue
        kept.append(line)
    return "\n".join(kept) + "\n", changed


def _restart_unbound(vm: SmokeVM) -> None:
    """TERM Unbound, wait, then start it from its conf (as pfb_stop_start_unbound() does, minus the python mounts)."""
    _sh_ok(
        vm,
        "[ -f /var/run/unbound.pid ] && kill -TERM $(cat /var/run/unbound.pid) 2>/dev/null\n"
        "i=0\n"
        "while pgrep -x unbound >/dev/null && [ $i -lt 30 ]; do sleep 1; i=$((i+1)); done\n"
        "if pgrep -x unbound >/dev/null; then echo 'unbound did not stop' >&2; exit 1; fi\n"
        f"/usr/local/sbin/unbound -c {h.UNBOUND_CONF} 2>&1\n",
        "restart Unbound",
        timeout=90.0,
    )
    h.wait_unbound_ready(vm)


def _apply_resolver(rig: Rig, label: str) -> None:
    """services_unbound_configure(), then Unbound without the python module and DoT listeners, restarted by hand.

    pfSense's own restart may fail to bind a DoT port the front end already holds, so the config is patched and
    Unbound started directly; nothing between the two waits for pfSense's Unbound.
    """
    vm = rig.vm
    _php_ok(vm, "services_unbound_configure();", f"services_unbound_configure ({label})")
    conf = vm.ssh("cat", h.UNBOUND_CONF).stdout
    patched, changed = strip_front_end_conflicts(conf, DOT_PORT)
    _say(f"{label}: unbound.conf edits: {changed or 'none'}")
    if changed:
        write = subprocess.run(
            vm.ssh_argv("tee", h.UNBOUND_CONF), input=patched, capture_output=True, text=True, timeout=30, check=False
        )
        if write.returncode != 0:
            raise RuntimeError(f"rewriting {h.UNBOUND_CONF} failed: rc={write.returncode} {write.stderr!r}")
    check = vm.ssh(f"/usr/local/sbin/unbound-checkconf {h.UNBOUND_CONF} 2>&1")
    _say(f"{label}: unbound-checkconf rc={check.returncode}: {check.stdout.strip()}")
    assert check.returncode == 0, f"Unbound rejects its configuration with proxy-protocol-port:\n{check.stdout}"
    assert not re.search(r"^\s*(python|python-script)\s*:|module-config:.*python", patched, re.MULTILINE), patched
    _restart_unbound(vm)


# --------------------------------------------------------------------------- #
# The front end process
# --------------------------------------------------------------------------- #


def _frontend_sources() -> bytes:
    """The prototype's code at HEAD as a tar stream, `prototype/dns_frontend/*.py`."""
    proc = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "archive", "--format=tar", "HEAD", PROTOTYPE_GLOB],
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0 or not proc.stdout:
        raise RuntimeError(f"git archive of the prototype failed: rc={proc.returncode} {proc.stderr!r}")
    return proc.stdout


def _install_frontend(vm: SmokeVM) -> None:
    result = subprocess.run(
        vm.ssh_argv("/bin/sh", "-c", f"mkdir -p {GUEST_DIR} && tar -xf - -C {GUEST_DIR} --strip-components 2"),
        input=_frontend_sources(),
        capture_output=True,
        timeout=60,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"copying the prototype failed: rc={result.returncode} {result.stderr!r}")
    _say("front end files: " + " ".join(sorted(_sh_ok(vm, f"ls {GUEST_DIR}", "list the front end").split())))


def _start_frontend(vm: SmokeVM) -> None:
    command = (
        f'"$PY" -u {GUEST_DIR}/pfb_frontend.py --listen {PFSENSE_LAN_IP} --listen 127.0.0.1 --port 53'
        f" --upstream 127.0.0.1:{UNBOUND_PORT} --module-dir /var/unbound --dot --pfsense-config /cf/conf/config.xml"
    )
    _sh_ok(
        vm,
        f"PY=$({PY_LAUNCHER} --print-interpreter) || exit 1\n"
        f"rm -f {PID_FILE}\n"
        f": > {LOG_FILE}\n"
        # daemon(8) holds the session's stdio open otherwise, and ssh then waits for it forever.
        f"/usr/sbin/daemon -p {PID_FILE} -o {LOG_FILE} {command} </dev/null >/dev/null 2>&1\n",
        "start the front end",
    )


def _frontend_log(vm: SmokeVM, lines: int = 60) -> str:
    return vm.ssh(f"tail -n {lines} {LOG_FILE} 2>&1").stdout


def _stop_frontend(vm: SmokeVM) -> None:
    _sh(
        vm,
        f"if [ -f {PID_FILE} ]; then kill $(cat {PID_FILE}) 2>/dev/null; fi\n"
        "i=0\n"
        "while pgrep -f 'pfb_frontend[.]py' >/dev/null && [ $i -lt 20 ]; do sleep 1; i=$((i+1)); done\n"
        "pkill -9 -f 'pfb_frontend[.]py'\n"
        f"rm -f {PID_FILE}\n",
    )


def _wait_frontend_answers(vm: SmokeVM, blocked: str) -> None:
    """Poll until 127.0.0.1:53 answers the listed name with the VIP: the module booted, the feed is loaded."""

    def answers() -> bool:
        if vm.ssh(f"kill -0 $(cat {PID_FILE})").returncode != 0:
            raise RuntimeError(f"the front end exited:\n{_frontend_log(vm)}")
        result = vm.ssh(f"/usr/local/bin/dig +tries=1 +time=2 +short A {shlex.quote(blocked)} @127.0.0.1")
        return result.stdout.strip() == h.DEFAULT_DNSBL_VIP4

    try:
        h.wait_until(answers, timeout=120.0, interval=3.0)
    except RuntimeError as exc:
        listeners = vm.ssh("sockstat -46l | grep -E ':(53|853|5353)[[:space:]]'").stdout
        raise RuntimeError(f"{exc}\nlisteners:\n{listeners}\nfront end log:\n{_frontend_log(vm)}") from exc


def _listeners(vm: SmokeVM) -> list[tuple[str, str]]:
    """(command, local address) of every listening socket on this box."""
    rows = (line.split() for line in vm.ssh("sockstat -46l").stdout.splitlines()[1:])
    return [(row[1], row[5]) for row in rows if len(row) >= 6]


def _record_versions(rig: Rig) -> None:
    out = _sh_ok(
        rig.vm,
        'echo "unbound: $(/usr/local/sbin/unbound -V 2>&1 | head -1)"\n'
        "/usr/local/sbin/unbound -V 2>&1 | grep -i 'linked modules'\n"
        f"PY=$({PY_LAUNCHER} --print-interpreter)\n"
        'echo "python interpreter: $PY"\n'
        'echo "python version: $($PY --version 2>&1)"\n'
        "echo \"python ssl: $($PY -c 'import ssl; print(ssl.OPENSSL_VERSION)' 2>&1)\"\n"
        'echo "pfSense: $(cat /etc/version 2>&1)"\n',
        "record versions",
    )
    for line in out.strip().splitlines():
        _say(line)
        key, _, value = line.partition(": ")
        rig.findings[key] = value


# --------------------------------------------------------------------------- #
# Queries and the logs that show who asked
# --------------------------------------------------------------------------- #


def _query(
    client: SmokeVM, name: str, *, tcp: bool = False, dot: bool = False, rtype: str = "A"
) -> tuple[h.DnsAnswer, str]:
    """dig from the LAN client at pfSense's LAN IP; returns the parsed answer and dig's full output."""
    args = ["dig", "+tries=1", "+time=5"]
    if tcp:
        args.append("+tcp")
    if dot:
        # +tls-ca makes dig verify the server against the Resolver's own certificate, not just talk TLS.
        args += ["+tls", f"+tls-ca={CERT_CLIENT}", f"+tls-hostname={CERT_NAME}"]
    args += [rtype, name, f"@{PFSENSE_LAN_IP}"]
    result = client.ssh(shlex.join(args) + " 2>&1", timeout=40.0)
    return h._parse_dig(result.stdout, rtype), result.stdout


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
        logging = vm.ssh(f"grep -E 'log-|logfile|use-syslog|verbosity' {h.UNBOUND_CONF}").stdout
        raise AssertionError(
            f"{RESOLVER_LOG} has no query line for {name}.\nmatching and last lines:\n{grep}\nlogging conf:\n{logging}"
        ) from None
    return _unbound_clients(vm, name)


def _dnsbl_rows(vm: SmokeVM, name: str) -> list[list[str]]:
    """dnsbl.log rows for `name`: DNSBL-python,timestamp,name,client,p_type,b_type,group,b_eval,feed,dup,qtype."""
    return [row for row in csv.reader(io.StringIO(h.read_log_file(vm, DNSBL_LOG))) if row[2:3] == [name]]


def _assert_allowed_through_unbound(rig: Rig, name: str, answer: h.DnsAnswer, raw: str, how: str) -> None:
    assert h.resolves_to(answer, STUB_DNS_A), f"{how}: {name} expected the upstream's {STUB_DNS_A}, got {answer}\n{raw}"
    clients = _wait_unbound_logged(rig.vm, name)
    assert clients == [CLIENT_LAN_IP], (
        f"{how}: Unbound's query log for {name} should name the client {CLIENT_LAN_IP} (PROXYv2), got {clients}"
    )


# --------------------------------------------------------------------------- #
# The fixture
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def rig(smoke_vm: SmokeVM, client_vm: SmokeVM, stub_dns: _StubDnsServer) -> Iterator[Rig]:
    """Deploy the package and a DNSBL feed, then put the Resolver behind the front end; undo it all in `finally`."""
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    vm = smoke_vm
    h.deploy(vm)
    h.ensure_dnsbl_vip(vm)
    h.use_system_dns_upstream(vm)  # Unbound forwards to the stub upstream; nothing needs the internet
    h.assert_link_health(client_vm, vm, control_name=h.unique_domain())
    blocked = h.unique_domain("blocked")
    feed_url = h.write_local_feed(vm, "smoke_3512_frontend.txt", f"{blocked}\n")
    h.inject(vm, h.DnsblCase(aliasname=FEED_HEADER, feed_url=feed_url, header=FEED_HEADER, mode=h.DnsblMode.VIP))
    h.reload(vm, "updatednsbl")  # builds the manifest and ini the front end's module reads
    current = Rig(vm, client_vm, blocked)
    _record_versions(current)
    _snapshot_config(vm)
    try:
        refid = _create_cert(vm)
        _say(
            "certificate: "
            + _sh(vm, f"/usr/bin/openssl x509 -in {CERT_GUEST} -noout -subject -ext subjectAltName 2>&1").stdout
        )
        pem = _sh_ok(vm, f"cat {CERT_GUEST}", "read the certificate")
        trusted = subprocess.run(
            client_vm.ssh_argv("tee", CERT_CLIENT), input=pem, capture_output=True, text=True, timeout=30, check=False
        )
        assert trusted.returncode == 0, f"copying the certificate to the client failed: {trusted.stderr!r}"
        _set_resolver(vm, refid)
        _apply_resolver(current, "Resolver on 5353")
        acl = vm.ssh("cat /var/unbound/access_lists.conf 2>&1").stdout
        current.findings["access_lists.conf"] = acl.strip()
        _say(f"access_lists.conf with active_interface=lo0 and no explicit ACL:\n{acl}")
        assert f"access-control: {PFSENSE_LAN_NET} allow" in acl, f"pfSense did not allow the LAN network:\n{acl}"
        _say("unbound listeners: " + " ".join(f"{cmd}@{addr}" for cmd, addr in _listeners(vm) if cmd == "unbound"))
        _install_frontend(vm)
        _start_frontend(vm)
        _wait_frontend_answers(vm, blocked)
        _say("front end listeners: " + " ".join(f"{cmd}@{addr}" for cmd, addr in _listeners(vm) if "python" in cmd))
        proxy = vm.ssh(f"/usr/local/sbin/unbound-control -c {h.UNBOUND_CONF} get_option proxy-protocol-port 2>&1")
        _say(f"unbound-control get_option proxy-protocol-port: {proxy.stdout.strip()}")
        yield current
    finally:
        try:
            _stop_frontend(vm)
        finally:
            _say("front end log:\n" + _frontend_log(vm, 80))
            try:
                _restore_config(vm)
                _php_ok(vm, "services_unbound_configure();", "services_unbound_configure (restore)")
                h.wait_unbound_ready(vm)
                on53 = [addr for cmd, addr in _listeners(vm) if cmd == "unbound" and addr.endswith(":53")]
                assert on53, f"Unbound is not back on port 53 after the restore: {_listeners(vm)}"
            finally:
                _sh(vm, f"rm -rf {GUEST_DIR} {SNAPSHOT_FILE} {CERT_GUEST}")
                client_vm.ssh(f"rm -f {CERT_CLIENT}")
                _say("FINDINGS " + repr(current.findings))
                h.collect_host_diagnostics(vm)


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #


def test_listed_name_gets_the_vip_and_never_reaches_unbound(rig: Rig) -> None:
    """A listed name is answered by the front end: VIP, a feed-attributed dnsbl.log row, no query at Unbound.

    Given a feed listing ``rig.blocked``,
    When the LAN client asks the front end over UDP,
    Then it gets the DNSBL VIP, dnsbl.log gains a row naming the feed and the client,
      And Unbound's query log, which has the allowed query asked after it, never saw the listed name.
    """
    rows_before = len(_dnsbl_rows(rig.vm, rig.blocked))
    answer, raw = _query(rig.client, rig.blocked)
    assert h.is_vip(answer), f"{rig.blocked}: expected VIP {h.DEFAULT_DNSBL_VIP4}, got {answer}\n{raw}"
    try:
        h.wait_until(lambda: len(_dnsbl_rows(rig.vm, rig.blocked)) > rows_before, timeout=30.0)
    except RuntimeError:
        raise AssertionError(f"dnsbl.log gained no row for {rig.blocked}:\n{_frontend_log(rig.vm)}") from None
    new_rows = _dnsbl_rows(rig.vm, rig.blocked)[rows_before:]
    assert {row[3] for row in new_rows} == {CLIENT_LAN_IP}, (
        f"dnsbl.log client: expected {CLIENT_LAN_IP}, got {new_rows}"
    )
    assert {row[8] for row in new_rows} == {FEED_HEADER}, f"dnsbl.log feed: expected {FEED_HEADER}, got {new_rows}"
    # Barrier: Unbound logs the allowed query after any earlier arrival of the listed one would have been logged.
    after = h.unique_domain("after")
    _assert_allowed_through_unbound(rig, after, *_query(rig.client, after), how="UDP barrier")
    assert _unbound_clients(rig.vm, rig.blocked) == [], f"Unbound saw the listed name {rig.blocked}"


def test_allowed_name_is_answered_by_unbound_for_the_real_client(rig: Rig) -> None:
    """An allowed name is forwarded to Unbound with PROXYv2: its answer comes back and its log names the client.

    Given a name no feed lists,
    When the LAN client asks the front end over UDP,
    Then the reply is the upstream's answer relayed from Unbound,
      And Unbound's query log names 192.168.1.10, not the front end's 127.0.0.1.
    """
    name = h.unique_domain("allowed")
    _assert_allowed_through_unbound(rig, name, *_query(rig.client, name), how="UDP")


def test_tcp_queries_are_blocked_and_forwarded_like_udp(rig: Rig) -> None:
    """Over TCP the listed name gets the VIP and an allowed name gets Unbound's answer for the real client."""
    answer, raw = _query(rig.client, rig.blocked, tcp=True)
    assert h.is_vip(answer), f"TCP {rig.blocked}: expected VIP {h.DEFAULT_DNSBL_VIP4}, got {answer}\n{raw}"
    name = h.unique_domain("tcp")
    _assert_allowed_through_unbound(rig, name, *_query(rig.client, name, tcp=True), how="TCP")


def test_dot_queries_are_blocked_and_forwarded_with_the_resolvers_certificate(rig: Rig) -> None:
    """Over DoT, verified against the Resolver's certificate, a listed name gets the VIP and an allowed one passes.

    The TLS peer address becomes the PROXYv2 client, so Unbound's log names the LAN client for the DoT query too.
    """
    answer, raw = _query(rig.client, rig.blocked, dot=True)
    assert h.is_vip(answer), f"DoT {rig.blocked}: expected VIP {h.DEFAULT_DNSBL_VIP4}, got {answer}\n{raw}"
    name = h.unique_domain("dot")
    _assert_allowed_through_unbound(rig, name, *_query(rig.client, name, dot=True), how="DoT")
    # For the findings: what the client negotiated and was shown (best effort, never asserted).
    tls = rig.client.ssh(
        f"echo | openssl s_client -connect {PFSENSE_LAN_IP}:{DOT_PORT} -CAfile {CERT_CLIENT} "
        f"-verify_hostname {CERT_NAME} 2>&1 | grep -E 'Protocol|Cipher is|Verification|subject=|Verify return'"
    )
    _say(f"DoT handshake seen by the client:\n{tls.stdout}")


@pytest.mark.timeout(300)
def test_unbound_acl_refusal_reaches_the_client_through_the_front_end(rig: Rig) -> None:
    """An Unbound ACL that refuses the client's address makes the front end relay REFUSED.

    Given the LAN client resolving an allowed name through the front end (before-state),
    When the Resolver's access lists refuse 192.168.1.10/32 (more specific than the LAN /24 pfSense allows),
    Then the same kind of query comes back REFUSED with no records,
      And a listed name still gets the VIP, because the front end decides DNSBL itself (recorded as a finding),
    Finally the access lists are empty again and the client resolves.
    """
    name = h.unique_domain("beforeacl")
    _assert_allowed_through_unbound(rig, name, *_query(rig.client, name), how="before the ACL")
    try:
        _set_acls(rig.vm, [("pfb3512 refuse client", "refuse", CLIENT_LAN_IP, "32")])
        _apply_resolver(rig, "Resolver refusing the client")
        refused, raw = _query(rig.client, h.unique_domain("refused"))
        assert refused.rcode == "REFUSED" and not refused.records, (
            f"expected REFUSED with no records, got {refused}\n{raw}"
        )
        listed, raw = _query(rig.client, rig.blocked)
        rig.findings["listed name, client refused by Unbound ACL"] = f"{listed.rcode} {listed.records}"
        assert h.is_vip(listed), f"the front end answers listed names itself, expected the VIP, got {listed}\n{raw}"
    finally:
        _set_acls(rig.vm, [])
        _apply_resolver(rig, "Resolver, access lists empty again")
    again = h.unique_domain("afteracl")
    _assert_allowed_through_unbound(rig, again, *_query(rig.client, again), how="after the ACL is removed")
