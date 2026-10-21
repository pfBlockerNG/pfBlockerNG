"""Issue #3539 — live proof that the DNSBL web server and its VIP exist only while a block needs them.

lighttpd (``lighttpd_pfb``), the DNSBL NAT, the certificate and the managed (auto) VIP are wanted
only while some effective DNSBL block answers with the VIP (the "DNSBL WebServer/VIP" mechanism, token
``enabled``). A block that answers ``0.0.0.0`` / NXDOMAIN / NODATA needs none of them, and DNSBL must
stay on without any VIP configured.

Coverage (each test asserts its before-state first; every block is a transition, not a final state):

* ``test_dropping_vip_demand_stops_web_server_only_after_new_generation_is_live`` — a group switched
  from the VIP answer to Null Blocking: the VIP, certificate and lighttpd go, and lighttpd stops only
  after the new DNSBL generation is live.
* ``test_rc_start_cannot_launch_web_server_without_vip_demand`` — the rc script and ``start_service()``.
* ``test_boot_does_not_start_web_server_without_vip_demand`` — a reboot (marker ``reboot``).
* ``test_dnsbl_stays_enabled_without_vip_demand_when_manual_vip_is_missing`` — no VIP, no ports, no
  force-disable and no ``DNSBL disabled:`` notice.
* ``test_vip_demand_returning_via_group_restores_vip_and_web_server``
* ``test_builtin_block_with_vip_mechanism_creates_vip_demand`` — a regex block under the global VIP mechanism.
* ``test_no_vip_demand_removes_dnsbl_nat`` — on a non-lo0 DNSBL interface.

The package-reinstall leg lives in ``test_smoke_dnsbl_vip_demand_install.py`` (it needs the ``repo_vm`` fixture).

Run: ``scripts/local-smoke.sh --filter vip_demand`` (marker ``smoke``) and ``--marker reboot --filter vip_demand``.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
from collections.abc import Iterator
from dataclasses import dataclass

import pytest

from . import helpers as h
from .conftest import SmokeVM, _StubDnsServer
from .test_smoke_dnsbl_policy_default_override import _group_php, _set_global_policy

_LIGHTY_PROC = "lighttpd_pfb"
_LIGHTY_CONF = "/var/unbound/pfb_dnsbl_lighty.conf"
_DNSBL_CERT = "/var/unbound/dnsbl_cert.pem"
_DNSBL_RC = "/usr/local/etc/rc.d/pfb_dnsbl.sh"
_NAT_DESCR = "pfB DNSBL - DO NOT EDIT"
_NOTICE_ID = "pfBlockerNG DNSBL"
_NOTICE_PREFIX = "DNSBL disabled:"
_ALIAS = "smokevipdemand"
_MANAGED_VIP_PREFIX = "pfB_AUTO_VIP_"
_STOP_LINE = "Stop Service DNSBL"
# A completed resolver reload in the main log: the swap path's "... [ zero-downtime swap ]" + " completed", or
# the restart path's "Starting Unbound Resolver" followed by ".." + " completed" (see _generation_handoff_problem).
_RELOAD_DONE = re.compile(r"\[ zero-downtime swap \] completed|Starting Unbound Resolver[\s\S]*?\.\. completed")

# What every test starts from and restores (see _restore_baseline): DNSBL on under an enabled package,
# the harness's manual lo0 VIP and ports, no managed VIP, no groups, DNSBL interface lo0, NAT allowed.
_BASELINE = {
    "enable_cb": "on",
    "pfb_dnsbl": "on",
    "pfb_dnsvip_auto": "",
    "dnsbl_interface": "lo0",
    "pfb_dnsbl_nonat": "",
    "pfb_dnsport": h.DNSBL_PORT,
    "pfb_dnsport_ssl": h.DNSBL_PORT_SSL,
    "dnsbl_vip4": h.DEFAULT_DNSBL_VIP4,
    "auto_vip": "",
    "groups": "0",
}


@pytest.fixture(scope="module")
def deployed_vm(smoke_vm: SmokeVM, stub_dns: _StubDnsServer) -> Iterator[SmokeVM]:
    """Deploy the branch .pkg once and bring the box to the module baseline (:data:`_BASELINE`)."""
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    h.snapshot_unbound_conf(smoke_vm)
    h.ensure_dnsbl_vip(smoke_vm)
    h.set_package_enabled(smoke_vm, True)
    h.set_dnsbl_enabled(smoke_vm, True)
    h.use_system_dns_upstream(smoke_vm)
    try:
        yield smoke_vm
    finally:
        h.unblock_egress()
        h.collect_host_diagnostics(smoke_vm)


@pytest.fixture(autouse=True)
def _vip_demand_baseline(deployed_vm: SmokeVM) -> None:
    """Fail loudly unless the box is at the baseline: a test never inherits a sibling's state."""
    _close_dnsbl_notices(deployed_vm)
    actual = _baseline_snapshot(deployed_vm)
    drift = {key: (want, actual.get(key)) for key, want in _BASELINE.items() if actual.get(key) != want}
    assert not drift, f"module baseline not in place at test entry (key: (expected, actual)): {drift}"


# --------------------------------------------------------------------------- #
# State: config writes, Force Update, baseline restore
# --------------------------------------------------------------------------- #


def _write_state(
    vm: SmokeVM,
    *,
    feed: str,
    logging: str,
    auto_vip: bool,
    settings: dict[str, str] | None = None,
    timeout: float = 90.0,
) -> None:
    """One config write: a single feed group answering with ``logging`` and the DNSBL settings.

    ``logging`` is the group's stored mechanism token (``enabled`` = the VIP). The global mechanism is
    ``disabled_log`` unless ``settings`` says otherwise, so no built-in block creates VIP demand by default.
    """
    base = {
        "global_log_mode": "default",
        "global_log": "disabled_log",
        "pfb_dnsbl": "on",
        "pfb_dnsvip_auto": "on" if auto_vip else "",
    }
    group = _group_php(aliasname=_ALIAS, header=_ALIAS, url=feed, logging=logging)
    snippet = (
        f"$g = config_get_path({h._php_str(h.CFG_GLOBAL)}, array());\n"
        "$g['enable_cb'] = 'on';\n"
        f"config_set_path({h._php_str(h.CFG_GLOBAL)}, $g);\n"
        f"{h._dnsbl_settings_replace_php({**base, **(settings or {})})}"
        f"config_set_path({h._php_str(h.CFG_DNSBL_LISTS)}, array({group}));\n"
        "write_config('pfBlockerNG smoke #3539: VIP demand state');\n"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_write_state failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}")


def _set_group_logging(vm: SmokeVM, logging: str, *, timeout: float = 60.0) -> None:
    """Change ONLY the stored mechanism of the group :func:`_write_state` wrote (index 0)."""
    snippet = (
        f"$l = config_get_path({h._php_str(h.CFG_DNSBL_LISTS)}, array());\n"
        f"$l[0]['logging'] = {h._php_str(logging)};\n"
        f"config_set_path({h._php_str(h.CFG_DNSBL_LISTS)}, $l);\n"
        "write_config('pfBlockerNG smoke #3539: group mechanism');\n"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_set_group_logging failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}")


def _clear_vip_and_ports(vm: SmokeVM, *, timeout: float = 60.0) -> None:
    """The user's "manual VIP missing" state: both VIP references and both web server ports emptied."""
    snippet = (
        f"$d = config_get_path({h._php_str(h.CFG_DNSBL_SETTINGS)}, array());\n"
        "foreach (array('pfb_dnsvip4', 'pfb_dnsvip6', 'pfb_dnsport', 'pfb_dnsport_ssl') as $k) { $d[$k] = ''; }\n"
        f"config_set_path({h._php_str(h.CFG_DNSBL_SETTINGS)}, $d);\n"
        "write_config('pfBlockerNG smoke #3539: manual VIP and ports cleared');\n"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_clear_vip_and_ports failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}")


def _force_update(vm: SmokeVM) -> None:
    """The GUI's Force Update (Reload scope DNSBL): applies the stored config and always reloads the resolver."""
    h.reload(vm, "updatednsbl")


def _baseline_snapshot(vm: SmokeVM) -> dict[str, str]:
    """The stored facts :data:`_BASELINE` pins, read in one on-box round trip."""
    pre = (
        f"$d = config_get_path({h._php_str(h.CFG_DNSBL_SETTINGS)}, array());\n"
        f"$g = config_get_path({h._php_str(h.CFG_GLOBAL)}, array());\n"
        "$auto = '';\n"
        "foreach (config_get_path('virtualip/vip', array()) as $v) {\n"
        f"  if (($v['descr'] ?? '') === {h._php_str(h.AUTO_VIP_DESCR_V4)}) "
        "{ $auto = (string) ($v['subnet'] ?? ''); break; }\n"
        "}\n"
        "$snap = array(\n"
        "  'enable_cb' => (string) ($g['enable_cb'] ?? ''),\n"
        "  'pfb_dnsbl' => (string) ($d['pfb_dnsbl'] ?? ''),\n"
        "  'pfb_dnsvip_auto' => (string) ($d['pfb_dnsvip_auto'] ?? ''),\n"
        "  'dnsbl_interface' => (string) (($d['dnsbl_interface'] ?? '') ?: 'lo0'),\n"
        "  'pfb_dnsbl_nonat' => (string) ($d['pfb_dnsbl_nonat'] ?? ''),\n"
        "  'pfb_dnsport' => (string) ($d['pfb_dnsport'] ?? ''),\n"
        "  'pfb_dnsport_ssl' => (string) ($d['pfb_dnsport_ssl'] ?? ''),\n"
        "  'dnsbl_vip4' => (string) (get_configured_vip_ipv4($d['pfb_dnsvip4'] ?? '') ?? ''),\n"
        "  'auto_vip' => $auto,\n"
        f"  'groups' => (string) count(config_get_path({h._php_str(h.CFG_DNSBL_LISTS)}, array())),\n"
        ");"
    )
    snap: dict[str, str] = json.loads(h._php_read_scalar(vm, pre, "json_encode($snap)"))
    return snap


def _vip_alias_devices(vm: SmokeVM, ip: str) -> list[str]:
    """Every interface device of the box carrying ``ip`` as an ``inet``/``inet6`` address (``ifconfig -a``)."""
    family = "inet6" if ":" in ip else "inet"
    devices: list[str] = []
    dev = ""
    for line in vm.ssh("/sbin/ifconfig", "-a", timeout=30.0).stdout.splitlines():
        if line and not line[0].isspace():
            dev = line.split(":", 1)[0]
            continue
        toks = line.split()
        if len(toks) > 1 and toks[0] == family and toks[1] == ip:
            devices.append(dev)
    return devices


def _drop_managed_vips(vm: SmokeVM) -> None:
    """Remove every package-owned (marked) VIP from config and from the interfaces it was brought up on.

    The restore does not lean on the package's own delete path: that is the code under test, and it only
    deletes the VIP ``pfb_dnsvip4`` still points at.
    """
    pre = (
        "require_once('interfaces.inc');\n"
        "$keep = $dropped = array();\n"
        "foreach (config_get_path('virtualip/vip', array()) as $v) {\n"
        f"  if (strpos((string) ($v['descr'] ?? ''), {h._php_str(_MANAGED_VIP_PREFIX)}) === 0) {{\n"
        "    if (function_exists('interface_vip_bring_down')) { interface_vip_bring_down($v); }\n"
        "    $dropped[] = (string) ($v['subnet'] ?? '');\n"
        "    continue;\n"
        "  }\n"
        "  $keep[] = $v;\n"
        "}\n"
        "if ($dropped) {\n"
        "  config_set_path('virtualip/vip', $keep);\n"
        "  write_config('pfBlockerNG smoke #3539: drop managed VIPs');\n"
        "}"
    )
    dropped: list[str] = json.loads(h._php_read_scalar(vm, pre, "json_encode($dropped)"))
    for ip in dropped:
        # interface_vip_bring_down() has been observed to leave the OS alias up (issue #1013): finish it by hand.
        for dev in _vip_alias_devices(vm, ip):
            inet = ["inet6", ip, "prefixlen", "128"] if ":" in ip else ["inet", ip]
            vm.ssh("/sbin/ifconfig", dev, *inet, "-alias", timeout=30.0)
        left = _vip_alias_devices(vm, ip)
        if left:
            raise RuntimeError(f"_drop_managed_vips: {ip} is still an alias on {left} after bring-down and -alias")


def _restore_baseline(vm: SmokeVM) -> None:
    """Put the box back at :data:`_BASELINE`, with the manual VIP, ports and interface in place BEFORE the apply.

    Order: config (groups, auto-VIP, interface, NAT opt-out cleared) -> managed VIPs dropped -> the manual VIP
    and both ports restored by :func:`helpers.ensure_dnsbl_vip` -> one Force Update, which therefore never runs
    with a cleared VIP or empty ports -> notices and derived state cleared.
    """
    settings = {
        "pfb_dnsbl": "on",
        "pfb_dnsvip_auto": "",
        "pfb_dnsvip6": "",
        "dnsbl_interface": "lo0",
        "pfb_dnsbl_nonat": "",
    }
    snippet = (
        f"$g = config_get_path({h._php_str(h.CFG_GLOBAL)}, array());\n"
        "$g['enable_cb'] = 'on';\n"
        f"config_set_path({h._php_str(h.CFG_GLOBAL)}, $g);\n"
        f"{h._dnsbl_settings_replace_php(settings)}"
        f"config_set_path({h._php_str(h.CFG_DNSBL_LISTS)}, array());\n"
        "write_config('pfBlockerNG smoke #3539: restore baseline');\n"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet, timeout=90.0)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_restore_baseline failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}")
    _drop_managed_vips(vm)
    h.ensure_dnsbl_vip(vm)
    _force_update(vm)
    _close_dnsbl_notices(vm)
    h.reset(vm)


@contextlib.contextmanager
def _restoring_baseline(vm: SmokeVM) -> Iterator[None]:
    """Restore the baseline on the way out; a restore failure never masks the failure already in flight."""
    try:
        yield
    except BaseException:
        try:
            _restore_baseline(vm)
        except Exception as exc:  # noqa: BLE001 -- teardown must not bury the test's own failure
            print(f"[smoke] baseline restore failed after a test failure (suppressed): {exc!r}")
        raise
    else:
        _restore_baseline(vm)


# --------------------------------------------------------------------------- #
# Observations
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class _Web:
    """The DNSBL web server's footprint on the box."""

    running: bool
    conf: bool
    cert: bool

    def __str__(self) -> str:
        return (
            f"{_LIGHTY_PROC} running={self.running}, "
            f"{_LIGHTY_CONF} exists={self.conf}, {_DNSBL_CERT} exists={self.cert}"
        )


def _exit_code(output: str, tag: str) -> int:
    match = re.search(rf"^{tag}=(\d+)$", output, re.MULTILINE)
    if match is None:
        raise RuntimeError(f"no {tag}= exit code in probe output: {output!r}")
    return int(match.group(1))


def _lighty_state(vm: SmokeVM) -> _Web:
    """One round trip; pgrep/test exit codes other than 0 (yes) and 1 (no) are errors, never "absent"."""
    result = vm.ssh(
        f"/bin/pgrep -x {_LIGHTY_PROC} >/dev/null 2>&1; echo R=$?; "
        f"/bin/test -f {_LIGHTY_CONF}; echo C=$?; "
        f"/bin/test -f {_DNSBL_CERT}; echo K=$?",
        timeout=30.0,
    )
    codes = {tag: _exit_code(result.stdout, tag) for tag in ("R", "C", "K")}
    bad = {tag: code for tag, code in codes.items() if code not in (0, 1)}
    if bad:
        raise RuntimeError(f"web server probe exit codes {bad} are neither yes (0) nor no (1): {result.stdout!r}")
    return _Web(running=codes["R"] == 0, conf=codes["C"] == 0, cert=codes["K"] == 0)


def _stop_lighttpd(vm: SmokeVM) -> None:
    """Stop the web server by hand so the start path under test is the only thing that can bring it up."""
    result = vm.ssh("/bin/sh", _DNSBL_RC, "stop", timeout=60.0)
    assert result.returncode == 0, (
        f"{_DNSBL_RC} stop failed: rc={result.returncode} {result.stdout!r} {result.stderr!r}"
    )
    web = _lighty_state(vm)
    assert not web.running, f"{_LIGHTY_PROC} survived {_DNSBL_RC} stop: {web}"


def _http_status(vm: SmokeVM, vip: str) -> str:
    result = vm.ssh(
        h.GUEST_CURL,
        "-s",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}",
        "--connect-timeout",
        "3",
        "--max-time",
        "8",
        f"http://{vip}/",
        timeout=20.0,
    )
    return result.stdout.strip()


def _answers_http(status: str) -> bool:
    return re.fullmatch(r"[1-5]\d\d", status) is not None


def _wait_http(vm: SmokeVM, vip: str, *, timeout: float = 30.0) -> str:
    """The block page's HTTP status, polling lighttpd's fork-then-bind readiness (#1013).

    Returns the last status seen when none came in time.
    """
    seen = ""

    def answered() -> bool:
        nonlocal seen
        seen = _http_status(vm, vip)
        return _answers_http(seen)

    with contextlib.suppress(RuntimeError):  # wait_until's salvage-cap error: the caller asserts on `seen`
        h.wait_until(answered, timeout=timeout, interval=1.0)
    return seen


def _web_down_problems(web: _Web, *, conf: bool = False, cert: bool = False) -> list[str]:
    problems = [f"{_LIGHTY_PROC} is running"] if web.running else []
    if conf and web.conf:
        problems.append(f"{_LIGHTY_CONF} exists")
    if cert and web.cert:
        problems.append(f"{_DNSBL_CERT} exists")
    return problems


def _vip_served_problems(vm: SmokeVM, domain: str, vip: str = h.AUTO_VIP_IP4) -> list[str]:
    """Everything that must hold while a block answers with the managed VIP; empty when all of it does."""
    problems: list[str] = []
    marked = h.marked_vip_subnet(vm, h.AUTO_VIP_DESCR_V4)
    if marked != vip:
        problems.append(f"managed VIP in config is {marked!r}, expected {vip!r}")
    if not h.vip_alias_live(vm, vip):
        problems.append(f"{vip} is not live on lo0")
    pointed = h.dnsvip4_address(vm)
    if pointed != vip:
        problems.append(f"pfb_dnsvip4 resolves to {pointed!r}, expected {vip!r}")
    web = _lighty_state(vm)
    if not (web.running and web.conf and web.cert):
        problems.append(f"web server not fully up: {web}")
    if web.running:
        status = _wait_http(vm, vip)
        if not _answers_http(status):
            problems.append(f"http://{vip}/ answered {status!r}, not an HTTP status")
    answer = h.dns_probe(vm, domain, "A")
    if not h.is_vip(answer, vip=vip):
        problems.append(f"{domain} answers {answer}, expected the VIP {vip}")
    return problems


def _vip_withdrawn_problems(vm: SmokeVM, domain: str, vip: str = h.AUTO_VIP_IP4) -> list[str]:
    """Everything that must hold while no block needs the VIP: it is gone, DNSBL is on and blocks with 0.0.0.0."""
    problems: list[str] = []
    marked = h.marked_vip_subnet(vm, h.AUTO_VIP_DESCR_V4)
    if marked:
        problems.append(f"managed VIP {marked!r} still in config")
    if h.vip_alias_live(vm, vip):
        problems.append(f"{vip} still live on lo0")
    problems += _web_down_problems(_lighty_state(vm), conf=True, cert=True)
    stored = h.config_get(vm, f"{h.CFG_DNSBL_SETTINGS}/pfb_dnsbl")
    if stored != "on":
        problems.append(f"stored pfb_dnsbl is {stored!r}, expected 'on'")
    answer = h.dns_probe(vm, domain, "A")
    if not h.is_null_ip(answer):
        problems.append(f"{domain} answers {answer}, expected {h.NULL_IP4} (Null Blocking)")
    return problems


def _expect_no_problems(vm: SmokeVM, context: str, problems: list[str]) -> None:
    assert not problems, f"{context}:\n  - " + "\n  - ".join(problems) + f"\n{h.fwobj_state_snapshot(vm)}"


def _log_size(vm: SmokeVM) -> int:
    result = vm.ssh("/usr/bin/wc", "-c", h.PFB_LOG, timeout=30.0)
    return int(result.stdout.split()[0]) if result.returncode == 0 and result.stdout.split() else 0


def _log_since(vm: SmokeVM, size: int) -> str:
    return vm.ssh("/usr/bin/tail", "-c", f"+{size + 1}", h.PFB_LOG, timeout=30.0).stdout


def _generation_handoff_problem(pass_log: str) -> str | None:
    """None when the web server stop comes after the pass's last COMPLETED resolver reload.

    ``pfb_reload_unbound()`` completes on either path: the zero-downtime swap logs
    ``... [ zero-downtime swap ] completed`` once the new generation is applied; the restart path logs
    ``Starting Unbound Resolver`` and, once the daemon answers ``status``, ``..`` + `` completed``.
    """
    done = [m.end() for m in _RELOAD_DONE.finditer(pass_log)]
    stop_at = pass_log.find(_STOP_LINE)
    excerpt = f"\n--- pass log (last 4000 bytes) ---\n{pass_log[-4000:]}"
    if not done:
        return f"the pass logged no completed resolver reload (swap or restart){excerpt}"
    if stop_at == -1:
        return f"the pass logged no {_STOP_LINE!r} line{excerpt}"
    if stop_at < done[-1]:
        return (
            f"{_STOP_LINE!r} (offset {stop_at}) precedes the last completed resolver reload "
            f"(ends at offset {done[-1]}){excerpt}"
        )
    return None


def _disabled_notices(vm: SmokeVM) -> list[str]:
    pre = (
        "$out = array();\n"
        "foreach ((get_notices() ?: array()) as $row) {\n"
        "  $t = (string) ($row['notice'] ?? '');\n"
        f"  if (strpos($t, {h._php_str(_NOTICE_PREFIX)}) === 0) {{ $out[] = $t; }}\n"
        "}"
    )
    notices: list[str] = json.loads(h._php_read_scalar(vm, pre, "json_encode($out)"))
    return notices


def _close_dnsbl_notices(vm: SmokeVM) -> None:
    snippet = (
        "foreach ((get_notices() ?: array()) as $key => $row) {\n"
        f"  if ((string) ($row['id'] ?? '') === {h._php_str(_NOTICE_ID)}) {{ close_notice($key); }}\n"
        "}\n"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet, timeout=60.0)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_close_dnsbl_notices failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}")


def _reach_no_demand_web_stopped(vm: SmokeVM, feed: str) -> None:
    """No-demand config (one group answering 0.0.0.0, auto-VIP on), applied, web server stopped by hand.

    The hand stop makes the path a caller exercises (rc start, boot, reinstall) the only thing that can
    start lighttpd; on a correct build the apply has already stopped it.
    """
    _write_state(vm, feed=feed, logging="disabled_log", auto_vip=True)
    _force_update(vm)
    _stop_lighttpd(vm)


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #


@pytest.mark.smoke
@pytest.mark.timeout(900)
def test_dropping_vip_demand_stops_web_server_only_after_new_generation_is_live(deployed_vm: SmokeVM) -> None:
    """Scenario: the last VIP-answering group becomes a Null Blocking group.

    Given auto-VIP on and one group answering with the VIP: the managed VIP is provisioned and live,
      the name answers it, lighttpd runs with its conf and certificate and the block page answers,
    When the group is switched to ``disabled_log`` and a Force Update runs,
    Then lighttpd is not running and its conf and certificate are gone, the managed VIP is out of
      config and off lo0, DNSBL is still on and the name answers 0.0.0.0,
      And that pass reloaded the resolver before it stopped lighttpd (the old generation kept
      serving the VIP until the new one was live).
    """
    vm = deployed_vm
    domain = h.unique_domain("vipdrop")
    feed = h.write_local_feed(vm, "smoke_vip_demand_drop.txt", f"{domain}\n")
    with _restoring_baseline(vm):
        _write_state(vm, feed=feed, logging="enabled", auto_vip=True)
        _force_update(vm)
        _expect_no_problems(vm, "before: a VIP-answering group", _vip_served_problems(vm, domain))

        _set_group_logging(vm, "disabled_log")
        log_mark = _log_size(vm)
        _force_update(vm)

        problems = _vip_withdrawn_problems(vm, domain)
        handoff = _generation_handoff_problem(_log_since(vm, log_mark))
        if handoff is not None:
            problems.append(handoff)
        _expect_no_problems(vm, "after: no group answers with the VIP", problems)


@pytest.mark.smoke
@pytest.mark.timeout(600)
def test_rc_start_cannot_launch_web_server_without_vip_demand(deployed_vm: SmokeVM) -> None:
    """Scenario: nothing that runs the rc script can start lighttpd while no block needs it.

    Given the no-demand state with lighttpd stopped,
    When the rc script is run with ``start``, and again via PHP ``start_service('pfb_dnsbl')``,
    Then lighttpd is not running after either.
    """
    vm = deployed_vm
    feed = h.write_local_feed(vm, "smoke_vip_demand_rc.txt", f"{h.unique_domain('vipsrc')}\n")
    with _restoring_baseline(vm):
        _reach_no_demand_web_stopped(vm, feed)

        rc = vm.ssh("/bin/sh", _DNSBL_RC, "start", timeout=60.0)
        after_rc = _lighty_state(vm)
        _stop_lighttpd(vm)  # judge the second path on its own

        service = h.php_eval(vm, "require_once('service-utils.inc');\nstart_service('pfb_dnsbl');\necho 'OK';")
        after_service = _lighty_state(vm)

        problems = [f"rc start (rc={rc.returncode}): {p}" for p in _web_down_problems(after_rc)]
        problems += [f"start_service (rc={service.returncode}): {p}" for p in _web_down_problems(after_service)]
        _expect_no_problems(vm, "after trying to start the web server with no VIP demand", problems)


@pytest.mark.reboot
@pytest.mark.timeout(900)
def test_boot_does_not_start_web_server_without_vip_demand(deployed_vm: SmokeVM) -> None:
    """Scenario: a reboot with no block needing the VIP leaves lighttpd off.

    Given the no-demand state with lighttpd stopped,
    When the box reboots and finishes booting,
    Then lighttpd is not running and its conf is absent.
    """
    vm = deployed_vm
    feed = h.write_local_feed(vm, "smoke_vip_demand_boot.txt", f"{h.unique_domain('vipboot')}\n")
    with _restoring_baseline(vm):
        _reach_no_demand_web_stopped(vm, feed)
        h.reboot_vm(vm)
        _expect_no_problems(vm, "after reboot with no VIP demand", _web_down_problems(_lighty_state(vm), conf=True))


@pytest.mark.smoke
@pytest.mark.timeout(900)
def test_dnsbl_stays_enabled_without_vip_demand_when_manual_vip_is_missing(deployed_vm: SmokeVM) -> None:
    """Scenario: with no group answering the VIP, a missing VIP and empty ports do not disable DNSBL.

    Given a VIP-answering group served by the manual VIP: the name answers that VIP,
    When auto-VIP is off, both VIP references and both ports are cleared, the group answers
      ``disabled_log`` and a Force Update runs,
    Then DNSBL still blocks (the name answers 0.0.0.0) and no ``DNSBL disabled:`` notice was filed.
    """
    vm = deployed_vm
    domain = h.unique_domain("vipmissing")
    feed = h.write_local_feed(vm, "smoke_vip_demand_missing.txt", f"{domain}\n")
    with _restoring_baseline(vm):
        _write_state(vm, feed=feed, logging="enabled", auto_vip=False)
        _force_update(vm)
        given = h.dns_probe(vm, domain, "A")
        assert h.is_vip(given, vip=h.DEFAULT_DNSBL_VIP4), (
            f"before: {domain} answers {given}, expected the manual VIP {h.DEFAULT_DNSBL_VIP4}"
        )
        assert _disabled_notices(vm) == [], f"before: a {_NOTICE_PREFIX!r} notice exists: {_disabled_notices(vm)}"

        _set_group_logging(vm, "disabled_log")
        _clear_vip_and_ports(vm)
        _force_update(vm)

        problems: list[str] = []
        answer = h.dns_probe(vm, domain, "A")
        if not h.is_null_ip(answer):
            problems.append(f"{domain} answers {answer}, expected {h.NULL_IP4}: DNSBL is not blocking")
        notices = _disabled_notices(vm)
        if notices:
            problems.append(f"notice(s) starting {_NOTICE_PREFIX!r} were filed: {notices}")
        _expect_no_problems(vm, "after: no VIP demand, manual VIP and ports missing", problems)


@pytest.mark.smoke
@pytest.mark.timeout(900)
def test_vip_demand_returning_via_group_restores_vip_and_web_server(deployed_vm: SmokeVM) -> None:
    """Scenario: a group answering with the VIP again brings the VIP and the web server back.

    Given the no-demand state: no managed VIP, no web server, the name answers 0.0.0.0,
    When the group is switched back to ``enabled`` and a Force Update runs,
    Then the managed VIP is provisioned and live, lighttpd runs with conf and certificate, the name
      answers the VIP and the block page answers.
    """
    vm = deployed_vm
    domain = h.unique_domain("vipback")
    feed = h.write_local_feed(vm, "smoke_vip_demand_back.txt", f"{domain}\n")
    with _restoring_baseline(vm):
        _write_state(vm, feed=feed, logging="disabled_log", auto_vip=True)
        _force_update(vm)
        _expect_no_problems(vm, "before: no group answers with the VIP", _vip_withdrawn_problems(vm, domain))

        _set_group_logging(vm, "enabled")
        _force_update(vm)
        _expect_no_problems(vm, "after: a group answers with the VIP again", _vip_served_problems(vm, domain))


@pytest.mark.smoke
@pytest.mark.timeout(900)
def test_builtin_block_with_vip_mechanism_creates_vip_demand(deployed_vm: SmokeVM) -> None:
    """Scenario: a built-in block (user regex) resolves to the global mechanism, so it can create VIP demand.

    Given every group answering ``disabled_log`` and a regex rule matching a unique name under the
      global mechanism ``disabled_log`` (Default mode): no VIP, no web server, the name answers 0.0.0.0,
    When the global mechanism becomes ``enabled`` (the VIP) and a Force Update runs,
    Then the managed VIP is provisioned, lighttpd runs and the regex-matched name answers the VIP.
    """
    vm = deployed_vm
    domain = h.unique_domain("vipregex")
    label = domain.split(".", 1)[0]
    inert = h.write_local_feed(vm, "smoke_vip_demand_regex_group.txt", f"{h.unique_domain('vipinert')}\n")
    regex = {"pfb_regex": "on", "pfb_regex_list": h._b64_textarea([f"^{re.escape(label)}\\."])}
    with _restoring_baseline(vm):
        _write_state(vm, feed=inert, logging="disabled_log", auto_vip=True, settings=regex)
        _force_update(vm)
        _expect_no_problems(vm, "before: the regex block answers 0.0.0.0", _vip_withdrawn_problems(vm, domain))

        _set_global_policy(vm, mode="default", mechanism="enabled")
        _force_update(vm)
        _expect_no_problems(vm, "after: the regex block answers the VIP", _vip_served_problems(vm, domain))


def _dnsbl_nat_rows(vm: SmokeVM) -> list[str]:
    """Destination addresses of the ``pfB DNSBL - DO NOT EDIT`` rows in config ``nat/rule``."""
    pre = (
        "$rows = array();\n"
        "foreach (config_get_path('nat/rule', array()) as $r) {\n"
        f"  if (($r['descr'] ?? '') === {h._php_str(_NAT_DESCR)}) "
        "{ $rows[] = (string) ($r['destination']['address'] ?? ''); }\n"
        "}"
    )
    rows: list[str] = json.loads(h._php_read_scalar(vm, pre, "json_encode($rows)"))
    return rows


def _live_rdr_lines(vm: SmokeVM, vip: str) -> list[str]:
    """Loaded ``pfctl -sn`` redirects to the 127.0.0.1 web server for destination ``vip``."""
    result = vm.ssh("/sbin/pfctl", "-sn", timeout=30.0)
    if result.returncode != 0:
        raise RuntimeError(f"pfctl -sn failed: rc={result.returncode} {result.stderr!r}")
    return [
        line
        for line in result.stdout.splitlines()
        if line.startswith("rdr") and re.search(rf"\bto {re.escape(vip)}\b", line) and "127.0.0.1" in line
    ]


@pytest.mark.smoke
@pytest.mark.timeout(900)
def test_no_vip_demand_removes_dnsbl_nat(deployed_vm: SmokeVM, lan_interface: SmokeVM) -> None:
    """Scenario: on a non-lo0 DNSBL interface the NAT port-forwards follow VIP demand.

    Given the DNSBL interface ``lan`` and a VIP-answering group: the two ``pfB DNSBL - DO NOT EDIT``
      rows are in config and the matching redirects are loaded in pf,
    When the group is switched to ``disabled_log`` and a Force Update runs,
    Then no such row remains in config and no redirect to the VIP is loaded.
    """
    vm = deployed_vm
    feed = h.write_local_feed(vm, "smoke_vip_demand_nat.txt", f"{h.unique_domain('vipnat')}\n")
    with _restoring_baseline(vm):
        _write_state(vm, feed=feed, logging="enabled", auto_vip=True, settings={"dnsbl_interface": "lan"})
        _force_update(vm)
        h.apply_filter_sync(vm)
        vip = h.marked_vip_subnet(vm, h.AUTO_VIP_DESCR_V4)
        assert vip, f"before: no managed VIP was provisioned\n{h.fwobj_state_snapshot(vm)}"
        before_rows = _dnsbl_nat_rows(vm)
        before_live = _live_rdr_lines(vm, vip)
        assert len(before_rows) == 2 and before_live, (
            f"before: expected two {_NAT_DESCR!r} rows in config and loaded redirects to {vip}; "
            f"config rows={before_rows} pfctl -sn={before_live}\n{h.fwobj_state_snapshot(vm)}"
        )

        _set_group_logging(vm, "disabled_log")
        _force_update(vm)
        h.apply_filter_sync(vm)

        after_rows = _dnsbl_nat_rows(vm)
        after_live = _live_rdr_lines(vm, vip)
        assert not after_rows and not after_live, (
            f"after: no VIP demand, yet {_NAT_DESCR!r} rows remain in config={after_rows} "
            f"or redirects to {vip} are loaded={after_live}\n{h.fwobj_state_snapshot(vm)}"
        )
