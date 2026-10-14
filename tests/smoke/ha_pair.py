"""Two real pfSense guests joined as an HA pair (issue #3454).

``smoke_vm`` is node A (primary), ``peer_vm`` node B (secondary); boot_vm.sh joins their net3/vtnet3 with
a UDP point-to-point link (SMOKE_SYNC_PORT / SMOKE_SYNC_PEER_PORT). :func:`ha_pair_session` puts both on a
SYNC interface (``opt2``) with a CARP VIP, serves XMLRPC over HTTPS, creates the sync users on B and the
``hasync`` target on A, and ALWAYS restores each node's pre-pair config.xml afterwards.

Secrets travel only on pfSsh stdin (never argv) and every error text built from guest output is redacted.
Imported lazily by ``conftest.ha_pair`` and by ``test_ha_topology``: helpers imports conftest, so conftest
must not import this module at load time.
"""

# ruff: noqa: E501 -- the embedded PHP is one live-verified statement per line (pfSsh buffers by line).

from __future__ import annotations

import contextlib
import json
import re
import secrets
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

from . import helpers
from .conftest import SmokeVM

SYNC_IF = "opt2"
SYNC_NIC = "vtnet3"
PRIMARY_SYNC_IP = "172.30.254.1"
SECONDARY_SYNC_IP = "172.30.254.2"
CARP_VIP = "172.30.254.254"
CARP_VHID = "54"
HA_USER = "pfbhasync"
NOPRIV_USER = "pfbnopriv"
BASELINE = "/root/pfb-smoke-ha-baseline.xml"

_END = "<<<END>>>"


@dataclass
class HaPair:
    primary: SmokeVM
    secondary: SmokeVM
    sync_password: str = field(repr=False)
    nopriv_password: str = field(repr=False)
    carp_password: str = field(repr=False)


class HaSetupError(RuntimeError):
    """A pair-setup step failed; the text names the node and stage and carries no secret."""


# --------------------------------------------------------------------------- #
# Guest plumbing
# --------------------------------------------------------------------------- #


def _redact(text: str, secret_values: Iterable[str]) -> str:
    """Replace each secret, raw and percent-encoded (PHP echoes URL userinfo encoded), with ``REDACTED``."""
    for value in filter(None, secret_values):
        text = text.replace(value, "REDACTED").replace(quote(value, safe=""), "REDACTED")
    return text


def _ssh_ok(vm: SmokeVM, command: str, *, timeout: float = 60.0) -> str:
    """Run ``command`` under ``/bin/sh`` on the guest; return stdout, raise on a non-zero exit."""
    result = vm.ssh(command, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(
            f"{command!r} failed: rc={result.returncode} "
            f"stdout={result.stdout[-300:]!r} stderr={result.stderr[-300:]!r}"
        )
    return result.stdout


def _php_ok(vm: SmokeVM, snippet: str, secret_values: Iterable[str], *, timeout: float = 60.0) -> None:
    """Run a pfSsh snippet that ends in ``echo 'OK'``; a failure carries rc + output tails with secrets redacted."""
    result = helpers.php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        # Redact BEFORE truncating (a cut could leave half a secret) and before repr (it would re-escape one).
        out = _redact(result.stdout, secret_values)[-600:]
        err = _redact(result.stderr, secret_values)[-300:]
        raise RuntimeError(f"pfSsh snippet failed: rc={result.returncode} stdout={out!r} stderr={err!r}")


def _php_json(
    vm: SmokeVM, marker: str, snippet: str, secret_values: Iterable[str] = (), *, timeout: float = 60.0
) -> Any:
    """Run a pfSsh snippet and return the JSON it printed between ``<<<marker>>>`` and ``<<<END>>>``."""
    result = helpers.php_eval(vm, snippet, timeout=timeout)
    opening = f"<<<{marker}>>>"
    start = result.stdout.find(opening)
    end = result.stdout.find(_END, start)
    if start == -1 or end == -1:
        out = _redact(result.stdout, secret_values)[-600:]
        err = _redact(result.stderr, secret_values)[-300:]
        raise RuntimeError(f"no {marker} block in pfSsh output: rc={result.returncode} stdout={out!r} stderr={err!r}")
    return json.loads(result.stdout[start + len(opening) : end])


@contextlib.contextmanager
def _stage(node: str, stage: str) -> Iterator[None]:
    """Label any failure inside as ``ha_pair setup failed: node=<node> stage=<stage>``."""
    try:
        yield
    except HaSetupError:
        raise
    except Exception as exc:
        raise HaSetupError(f"ha_pair setup failed: node={node} stage={stage}: {exc}") from exc


def _baseline_exists(vm: SmokeVM, node: str) -> bool:
    """Whether this node holds a pre-pair snapshot; an unreadable answer is an error, never "absent"."""
    out = _ssh_ok(vm, f"test -f {BASELINE} && echo present || echo absent").strip()
    if out not in ("present", "absent"):
        raise RuntimeError(f"node={node}: cannot tell whether {BASELINE} exists: {out!r}")
    return out == "present"


# --------------------------------------------------------------------------- #
# Setup
# --------------------------------------------------------------------------- #

_BUSY_PHP = f"""$busy = array();
foreach (config_get_path('interfaces', array()) as $k => $i) {{ if ($k == '{SYNC_IF}' || (is_array($i) && ($i['if'] ?? '') == '{SYNC_NIC}')) {{ $busy[] = $k; }} }}
echo '<<<HABUSY>>>' . json_encode($busy) . '{_END}';"""


def _sync_php(sync_ip: str, advskew: str, carp_password: str) -> str:
    """SYNC interface + HTTPS webgui + XMLRPC pass rule + CARP VIP, applied to the running system."""
    q = helpers._php_str
    return f"""config_set_path('interfaces/{SYNC_IF}', array('enable' => '', 'if' => '{SYNC_NIC}', 'descr' => 'SYNC', 'ipaddr' => {q(sync_ip)}, 'subnet' => '24', 'spoofmac' => ''));
config_set_path('system/webgui/protocol', 'https');
$rules = config_get_path('filter/rule', array());
$rules[] = array('type' => 'pass', 'interface' => '{SYNC_IF}', 'ipprotocol' => 'inet', 'protocol' => 'tcp', 'source' => array('network' => '{SYNC_IF}'), 'destination' => array('network' => '{SYNC_IF}ip', 'port' => '443'), 'descr' => 'pfb smoke HA XMLRPC', 'tracker' => '1770003454');
config_set_path('filter/rule', $rules);
$vips = config_get_path('virtualip/vip', array());
$vips[] = array('mode' => 'carp', 'interface' => '{SYNC_IF}', 'vhid' => '{CARP_VHID}', 'advskew' => {q(advskew)}, 'advbase' => '1', 'password' => {q(carp_password)}, 'uniqid' => 'pfbsmokeha{CARP_VHID}', 'descr' => 'pfb smoke HA', 'type' => 'single', 'subnet_bits' => '24', 'subnet' => '{CARP_VIP}');
config_set_path('virtualip/vip', $vips);
write_config('pfBlockerNG smoke: HA sync topology');
interface_configure('{SYNC_IF}', true);
foreach (config_get_path('virtualip/vip', array()) as $v) {{ if ($v['interface'] == '{SYNC_IF}') {{ interface_carp_configure($v); }} }}
echo 'OK';"""


def configure_node(vm: SmokeVM, node: str, *, sync_ip: str, advskew: str, carp_password: str) -> None:
    """Refuse a node whose SYNC NIC is taken, snapshot config.xml, then give ``vm`` the SYNC interface, CARP VIP and HTTPS webgui."""
    with _stage(node, "sync-interface"):
        busy = _php_json(vm, "HABUSY", _BUSY_PHP)
        if busy:
            raise RuntimeError(f"{SYNC_IF}/{SYNC_NIC} already in use by {busy}; refusing to overlay the HA topology")
    with _stage(node, "snapshot"):
        if _baseline_exists(vm, node):
            raise RuntimeError(f"{BASELINE} already exists: an earlier pair was never restored; not overwriting it")
        _ssh_ok(vm, f"cp -p /conf/config.xml {BASELINE}.tmp && mv {BASELINE}.tmp {BASELINE}")
    with _stage(node, "sync-interface"):
        _php_ok(vm, _sync_php(sync_ip, advskew, carp_password), [carp_password])
    with _stage(node, "filter"):
        helpers.apply_filter_sync(vm)
    with _stage(node, "webgui"):
        _ssh_ok(vm, "/etc/rc.restart_webgui", timeout=120.0)


def configure_secondary_users(vm: SmokeVM, sync_password: str, nopriv_password: str) -> None:
    """Create the HA-privileged and the unprivileged user on node B.

    The bcrypt hash is written directly: ``local_user_set_password()`` takes ``['item' => $user]`` on CE 2.8
    and silently stores the hash under ``item`` when handed a bare user, so authentication then fails.
    """
    q = helpers._php_str
    snippet = f"""$accounts = array({q(HA_USER)} => array({q(sync_password)}, array('system-xmlrpc-ha-sync')), {q(NOPRIV_USER)} => array({q(nopriv_password)}, array()));
$users = config_get_path('system/user', array());
$uid = (int) config_get_path('system/nextuid', '2000');
foreach ($accounts as $name => $a) {{ $u = array('name' => $name, 'descr' => 'pfb smoke HA', 'scope' => 'user', 'uid' => (string) $uid, 'bcrypt-hash' => password_hash($a[0], PASSWORD_BCRYPT)); if ($a[1]) {{ $u['priv'] = $a[1]; }} $users[] = $u; $uid++; }}
config_set_path('system/user', $users);
config_set_path('system/nextuid', (string) $uid);
write_config('pfBlockerNG smoke: HA sync users');
echo 'OK';"""
    with _stage("secondary", "users"):
        _php_ok(vm, snippet, (sync_password, nopriv_password))


def configure_primary_hasync(vm: SmokeVM, sync_password: str) -> None:
    """Point node A's HA sync at node B with the HA user and the sections core's automatic sync replicates."""
    q = helpers._php_str
    snippet = f"""config_set_path('hasync', array('synchronizetoip' => {q(SECONDARY_SYNC_IP)}, 'username' => {q(HA_USER)}, 'password' => {q(sync_password)}, 'synchronizerules' => 'on', 'synchronizenat' => 'on', 'synchronizealiases' => 'on'));
write_config('pfBlockerNG smoke: HA sync target');
echo 'OK';"""
    with _stage("primary", "hasync"):
        _php_ok(vm, snippet, [sync_password])


# --------------------------------------------------------------------------- #
# Restore
# --------------------------------------------------------------------------- #

_TEARDOWN_PHP = f"""interfaces_carp_set_maintenancemode(false);
foreach (config_get_path('virtualip/vip', array()) as $v) {{ if ($v['interface'] == '{SYNC_IF}') {{ interface_vip_bring_down($v); }} }}
interface_bring_down('{SYNC_IF}', true);
echo 'OK';"""

_VERIFY_PHP = f"""echo '<<<HARESTORE>>>' . json_encode(array('protocol' => config_get_path('system/webgui/protocol', ''), '{SYNC_IF}' => config_get_path('interfaces/{SYNC_IF}') !== null)) . '{_END}';"""


def clear_sshguard(vm: SmokeVM) -> None:
    """Drop sshguard's block of the sync IP: it trips after 3 deliberate XMLRPC auth failures."""
    _ssh_ok(vm, "pfctl -t sshguard -T flush")


def _verify_baseline(vm: SmokeVM) -> None:
    state = _php_json(vm, "HARESTORE", _VERIFY_PHP)
    if state.get("protocol") != "http" or state.get(SYNC_IF):
        raise RuntimeError(f"config is not back at the baseline: expected protocol=http {SYNC_IF}=False, got {state}")


def restore_node(vm: SmokeVM, node: str) -> None:
    """Put ``vm`` back to its pre-pair state; a node that was never snapshotted is left alone.

    EVERY step runs even when an earlier one fails (a half-restored node must not also skip the config
    copy-back); the failures are raised together, naming the node and each failed step.
    """
    if not _baseline_exists(vm, node):
        return
    steps: tuple[tuple[str, Callable[[], object]], ...] = (
        ("runtime-teardown", lambda: _php_ok(vm, _TEARDOWN_PHP, ())),
        (
            "config-restore",
            lambda: _ssh_ok(vm, f"cp -p {BASELINE} /conf/config.xml && rm -f /tmp/config.cache && rm -f {BASELINE}"),
        ),
        ("sshguard-flush", lambda: clear_sshguard(vm)),
        ("webgui-restart", lambda: _ssh_ok(vm, "/etc/rc.restart_webgui", timeout=120.0)),
        ("filter-reload", lambda: helpers.apply_filter_sync(vm)),
        ("verify", lambda: _verify_baseline(vm)),
    )
    failures: list[str] = []
    for name, run in steps:
        try:
            run()
        except Exception as exc:
            failures.append(f"{name} ({exc})")
    if failures:
        raise RuntimeError(f"ha_pair restore failed: node={node}: " + "; ".join(failures))


def _restore_pair(primary: SmokeVM, secondary: SmokeVM) -> list[str]:
    """Restore B then A (A held the CARP master role); return every node's failure text."""
    failures: list[str] = []
    for vm, node in ((secondary, "secondary"), (primary, "primary")):
        try:
            restore_node(vm, node)
        except Exception as exc:
            failures.append(str(exc))
    return failures


@contextlib.contextmanager
def ha_pair_session(primary: SmokeVM, secondary: SmokeVM) -> Iterator[HaPair]:
    """Configure the two guests as an HA pair, yield it, and restore both nodes on the way out."""
    pair = HaPair(
        primary,
        secondary,
        sync_password=secrets.token_urlsafe(18),
        nopriv_password=secrets.token_urlsafe(18),
        carp_password=secrets.token_urlsafe(18),
    )
    try:
        configure_node(primary, "primary", sync_ip=PRIMARY_SYNC_IP, advskew="0", carp_password=pair.carp_password)
        configure_node(
            secondary, "secondary", sync_ip=SECONDARY_SYNC_IP, advskew="100", carp_password=pair.carp_password
        )
        configure_secondary_users(secondary, pair.sync_password, pair.nopriv_password)
        configure_primary_hasync(primary, pair.sync_password)
    except BaseException as exc:
        failures = _restore_pair(primary, secondary)
        if failures and isinstance(exc, Exception):
            raise HaSetupError(f"{exc}; restore also failed: {'; '.join(failures)}") from exc
        raise
    try:
        yield pair
    finally:
        failures = _restore_pair(primary, secondary)
        if failures:
            raise RuntimeError("; ".join(failures))


# --------------------------------------------------------------------------- #
# Probes
# --------------------------------------------------------------------------- #


def xmlrpc_call(
    pair_or_vm: HaPair | SmokeVM, *, user: str, password: str, method: str, params_php: str = "''"
) -> dict[str, Any]:
    """One XMLRPC call from the primary to the secondary over HTTPS, single-shot (no pfSense 4x retry).

    pfSense's own client retries a failed login four times, which trips sshguard on the first bad attempt; this
    uses the raw ``XML_RPC2`` client. Returns ``{"ok": True, "resp": ...}``, ``{"fault": code, "msg": ...}``
    (-1 bad credentials, -2 missing ``system-xmlrpc-ha-sync`` privilege) or ``{"error": class, "msg": ...}``.
    ``params_php`` is a PHP expression for the method's first argument.
    """
    vm = pair_or_vm.primary if isinstance(pair_or_vm, HaPair) else pair_or_vm
    q = helpers._php_str
    snippet = f"""require_once("XML/RPC2/Client.php");
$m = {q(method)};
$cli = XML_RPC2_Client::create('https://' . rawurlencode({q(user)}) . ':' . rawurlencode({q(password)}) . '@{SECONDARY_SYNC_IP}:443/xmlrpc.php', array('prefix' => 'pfsense.', 'sslverify' => false, 'connectionTimeout' => 20));
try {{ $out = array('ok' => true, 'resp' => $cli->{{$m}}({params_php}, 20)); }} catch (XML_RPC2_FaultException $e) {{ $out = array('fault' => $e->getFaultCode(), 'msg' => $e->getFaultString()); }} catch (Exception $e) {{ $out = array('error' => get_class($e), 'msg' => substr($e->getMessage(), 0, 300)); }}
echo '<<<HAXMLRPC>>>' . json_encode($out) . '{_END}';"""
    result: dict[str, Any] = _php_json(vm, "HAXMLRPC", snippet, [password], timeout=90.0)
    # Redact after parsing: json.dumps escapes backslashes, so the raw secret would not match the raw JSON text.
    if "msg" in result:
        result["msg"] = _redact(str(result["msg"]), [password])
    return result


def carp_state(vm: SmokeVM) -> str:
    """The CARP state of the smoke VHID on the sync NIC: ``MASTER``, ``BACKUP`` or ``INIT``."""
    out = _ssh_ok(vm, f"ifconfig {SYNC_NIC}")
    match = re.search(rf"carp: (\w+) vhid {CARP_VHID}\b", out)
    if match is None:
        raise RuntimeError(f"no 'carp: <state> vhid {CARP_VHID}' on {SYNC_NIC}: {out!r}")
    return match.group(1)


def set_carp_maintenance(vm: SmokeVM, on: bool) -> None:
    """Enter or leave CARP maintenance mode (advskew 254 while on); written to config, so a restore undoes it."""
    _php_ok(vm, f"interfaces_carp_set_maintenancemode({'true' if on else 'false'});\necho 'OK';", ())


def wait_carp_state(vm: SmokeVM, expected: str, timeout: float = 60.0, *, node: str = "node") -> None:
    """Block until ``vm`` reports ``expected``; a bounded poll, as CARP has no completion signal."""
    last = ""

    def reached() -> bool:
        nonlocal last
        try:
            last = carp_state(vm)
        except RuntimeError as exc:
            last = f"unreadable ({exc})"
        return last == expected

    try:
        helpers.wait_until(reached, timeout=timeout)
    except RuntimeError as exc:  # wait_until's expiry is the only RuntimeError left: reached() swallows the rest
        raise RuntimeError(f"stuck/environment: expected CARP {expected} on {node}, last observed {last}") from exc
