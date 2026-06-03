"""Per-case loop primitives for the ADR-04 live-VM smoke matrix (Phase 4).

The Phase-5 matrix composes these into one call per case:

    deploy(vm)                      # install the branch-under-test .pkg
    with case(vm, feeds, spec):     # inject -> reload -> (probe) -> reset
        dns_probe(vm, name, "A")
        pfctl_table_members(vm, alias)

Everything here drives the REAL production paths:

* deploy wraps ``scripts/install-pkg.sh`` (``pkg add`` -> POST-INSTALL -> the
  package is registered, Unbound rewired) — the EVOLVED deploy. The superseded
  ``scripts/deploy.sh`` rsync overlay is NOT used (it does not register the
  package or run POST-INSTALL). The .pkg path comes from a parameter / the
  ``SMOKE_PKG`` env (Phase 6 provides it; the FreeBSD build job emits it).
* inject() writes pfBlockerNG config AND the case's Unbound control records via
  the pfSense config API over ``php -r`` (``parse_config`` /
  ``config_set_path`` / ``write_config``). Control records go into the Unbound
  Custom Options (``local-zone:`` / ``local-data:``) IN CONFIG, BEFORE the feed
  update, so they survive the reload that regenerates ``unbound.conf`` (the
  Phase-1 spike used live ``unbound-control``, which a reload wipes).
* reload() runs the PHP CLI cron verbs (``update`` / ``updateip`` /
  ``updatednsbl``) — the exact cron entry point, no wrapper. reset() runs
  ``clearip`` / ``cleardnsbl`` then a forced ``update`` (pfBlockerNG caches
  feeds; an edited fixture is re-fetched only on a force) — the Phase-3
  session-isolation reset.
* dns_probe / pfctl probes + their assert helpers observe the two paths.

Import-safety: this module is imported only by the smoke suite (which is
``--ignore``d at default collection). Its only non-stdlib touch (dnspython,
via :func:`tests.smoke.conftest.resolve_a`) is deferred into the probe call,
so importing this module does not require the smoke deps.
"""

from __future__ import annotations

import os
import shlex
import subprocess
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from .conftest import SMOKE_DIR, SmokeVM, resolve_a

# --------------------------------------------------------------------------- #
# Paths / constants
# --------------------------------------------------------------------------- #

INSTALL_PKG_SH = SMOKE_DIR.parent.parent / "scripts" / "install-pkg.sh"
PHP_BIN = "/usr/local/bin/php"
PFB_CLI = "/usr/local/www/pfblockerng/pfblockerng.php"
PFCTL = "/sbin/pfctl"

# pfSense config API roots (see pfblockerng.inc).
CFG_DNSBL_SETTINGS = "installedpackages/pfblockerngdnsblsettings/config/0"
CFG_DNSBL_LISTS = "installedpackages/pfblockerngdnsbl/config"
CFG_IP_V4_LISTS = "installedpackages/pfblockernglistsv4/config"
CFG_IP_V6_LISTS = "installedpackages/pfblockernglistsv6/config"
CFG_UNBOUND_CUSTOM = "unbound/custom_options"

# The configured DNSBL VIP a "vip" block answers with (must match the baked
# image's pfb_dnsvip4 / the lighttpd sinkhole VIP). Env-overridable so the
# probe is not pinned to one baked image.
DEFAULT_DNSBL_VIP4 = os.environ.get("SMOKE_DNSBL_VIP4", "10.10.10.1")
NULL_IP4 = "0.0.0.0"


# --------------------------------------------------------------------------- #
# Case specification (declarative input the matrix fills in)
# --------------------------------------------------------------------------- #


class DnsblMode(str, Enum):
    """The block shape a DNSBL case expects for a matched name.

    Maps to pfBlockerNG config + the ``pfb_unbound.py`` response shapes
    (ADR §1 fact 4): NXDOMAIN (python-block mode), a null IP (``0.0.0.0`` /
    ``::0``, per-list ``logging='disabled'``), or the DNSBL webserver VIP
    (per-list ``logging=''`` -> ``pfb_dnsvip4``).
    """

    NXDOMAIN = "nxdomain"
    NULL = "null"
    VIP = "vip"


@dataclass
class DnsblCase:
    """A DNSBL matrix case: one feed (served by mock_feeds) + its block mode.

    Fields and the config path each one sets:

      aliasname     -> CFG_DNSBL_LISTS/<n>/aliasname  (alias = DNSBL_<aliasname>)
      feed_url      -> CFG_DNSBL_LISTS/<n>/row/0/url  (a mock_feeds.feed_url)
      header        -> CFG_DNSBL_LISTS/<n>/row/0/header
      mode          -> response shape: NXDOMAIN/NULL/VIP, set via
                       CFG_DNSBL_SETTINGS (dnsbl_mode/pfb_py_block) +
                       per-list 'logging'
      wildcard      -> feed entry style; a wildcard feed line blocks subdomains
      whitelist     -> CFG_DNSBL_SETTINGS/suppression (newline list; a leading
                       '.' suppresses the whole subtree)
      control_local_data -> {name: {"A": ip, "AAAA": ip6}} Unbound local-data
                       baked into CFG_UNBOUND_CUSTOM BEFORE update
      control_local_zone -> {zone: type} e.g. {"pass.test": "transparent"}
    """

    aliasname: str
    feed_url: str
    mode: DnsblMode = DnsblMode.NXDOMAIN
    header: str = "smoketest"
    wildcard: bool = False
    whitelist: list[str] = field(default_factory=list)
    control_local_data: dict[str, dict[str, str]] = field(default_factory=dict)
    control_local_zone: dict[str, str] = field(default_factory=dict)

    @property
    def alias(self) -> str:
        return f"DNSBL_{self.aliasname}"


@dataclass
class IpCase:
    """An IP matrix case: a feed of IPs -> a pf alias table + a rule.

    Fields and the config path each one sets:

      aliasname  -> CFG_IP_V4_LISTS/<n>/aliasname  (alias table = pfB_<aliasname>)
      feed_url   -> CFG_IP_V4_LISTS/<n>/row/0/url
      header     -> CFG_IP_V4_LISTS/<n>/row/0/header
      action     -> CFG_IP_V4_LISTS/<n>/action  (Deny_Both, etc.)
      family     -> "v4" (CFG_IP_V4_LISTS) or "v6" (CFG_IP_V6_LISTS)
      control_local_data / control_local_zone -> as DnsblCase
    """

    aliasname: str
    feed_url: str
    header: str = "smoketest"
    action: str = "Deny_Both"
    family: str = "v4"
    control_local_data: dict[str, dict[str, str]] = field(default_factory=dict)
    control_local_zone: dict[str, str] = field(default_factory=dict)

    @property
    def alias(self) -> str:
        return f"pfB_{self.aliasname}"


# --------------------------------------------------------------------------- #
# Deploy — install the branch-under-test .pkg (evolved; NOT deploy.sh rsync)
# --------------------------------------------------------------------------- #


def deploy(vm: SmokeVM, pkg_path: str | None = None, *, timeout: float = 600.0) -> None:
    """Install the branch's built .pkg onto the guest via install-pkg.sh.

    ``pkg add`` registers the package in pkg's DB, resolves RUN_DEPENDS from the
    repos, and runs POST-INSTALL (menus, services, Unbound wiring) — fidelity
    the rsync overlay (``deploy.sh``) does not give. The .pkg is produced by the
    FreeBSD build job (build-pkg.yml); its path is ``pkg_path`` or ``SMOKE_PKG``.
    install-pkg.sh polls ``unbound-control status`` after POST-INSTALL, so on
    return Unbound is ready.
    """
    pkg = pkg_path or os.environ.get("SMOKE_PKG")
    if not pkg or not Path(pkg).is_file():
        raise RuntimeError(f"deploy needs a built .pkg (pkg_path or SMOKE_PKG); got {pkg!r}")

    argv = [
        "sh",
        str(INSTALL_PKG_SH),
        vm.ssh_target,
        "--pkg",
        pkg,
        "--port",
        str(vm.ssh_port),
        "--ssh-key",
        vm.ssh_key_path,
    ]
    result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    if result.returncode != 0:
        raise RuntimeError(
            f"install-pkg.sh failed (rc={result.returncode})\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )


# --------------------------------------------------------------------------- #
# PHP helpers — run a snippet through the pfSense config API over SSH
# --------------------------------------------------------------------------- #


def php_eval(vm: SmokeVM, snippet: str, *, timeout: float = 60.0) -> subprocess.CompletedProcess[str]:
    """Run a PHP snippet on the guest with the config API pre-loaded.

    ``parse_config(true)`` is called first so ``config_get_path`` /
    ``config_set_path`` operate on the live config; the snippet that mutates is
    responsible for ``write_config``. The snippet is passed as a single
    ``php -r`` argument (shell-quoted on the runner; the guest receives it
    verbatim).
    """
    program = "require_once('config.inc'); require_once('util.inc'); parse_config(true);\n" + snippet
    # `php -r` wants the program WITHOUT <?php tags. shlex.quote keeps it intact
    # through the SSH client-side expansion install-pkg.sh's callers rely on.
    remote = f"{PHP_BIN} -r {shlex.quote(program)}"
    return vm.ssh(remote, timeout=timeout)


def config_get(vm: SmokeVM, path: str, *, timeout: float = 60.0) -> str:
    """Read a scalar config value back via the config API (for self-tests)."""
    snippet = f"echo (string) config_get_path({_php_str(path)}, '');"
    result = php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(f"config_get({path!r}) failed: {result.stderr!r}")
    return result.stdout


def _php_str(value: str) -> str:
    """Render a Python str as a single-quoted PHP string literal."""
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _php_kv_array(data: dict[str, str]) -> str:
    """Render a flat dict as a PHP associative-array literal."""
    items = ", ".join(f"{_php_str(k)} => {_php_str(v)}" for k, v in data.items())
    return f"array({items})"


# --------------------------------------------------------------------------- #
# Control records — Unbound local-zone/local-data, set IN CONFIG before update
# --------------------------------------------------------------------------- #


def _control_lines(local_data: dict[str, dict[str, str]], local_zone: dict[str, str]) -> list[str]:
    """Build the Unbound Custom Options lines for a case's control records."""
    lines: list[str] = []
    for zone, kind in local_zone.items():
        lines.append(f'local-zone: "{zone}" {kind}')
    for name, records in local_data.items():
        for rtype, value in records.items():
            lines.append(f'local-data: "{name} IN {rtype} {value}"')
    return lines


def set_control_records(
    vm: SmokeVM,
    local_data: dict[str, dict[str, str]],
    local_zone: dict[str, str],
    *,
    timeout: float = 60.0,
) -> None:
    """Persist control local-zone/local-data into ``unbound/custom_options``.

    pfSense stores Custom Options base64-encoded; pfBlockerNG appends its own
    include there too (see pfblockerng.inc:2092). We DECODE, append the control
    lines (idempotent — skip lines already present), RE-ENCODE, and
    ``write_config``. Doing this in CONFIG (not live ``unbound-control``) means
    the records survive the reload that regenerates ``unbound.conf``.
    """
    lines = _control_lines(local_data, local_zone)
    if not lines:
        return
    php_lines = "array(" + ", ".join(_php_str(line) for line in lines) + ")"
    snippet = (
        f"$cur = (string) config_get_path({_php_str(CFG_UNBOUND_CUSTOM)}, '');\n"
        "$decoded = $cur !== '' ? base64_decode($cur) : '';\n"
        "$existing = $decoded === '' ? array() : explode(\"\\n\", $decoded);\n"
        f"foreach ({php_lines} as $line) {{ if (!in_array($line, $existing, true)) {{ $existing[] = $line; }} }}\n"
        "$joined = implode(\"\\n\", array_filter($existing, fn($l) => $l !== ''));\n"
        f"config_set_path({_php_str(CFG_UNBOUND_CUSTOM)}, base64_encode($joined));\n"
        "write_config('pfBlockerNG smoke: control records');\n"
        "echo 'OK';"
    )
    result = php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"set_control_records failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}")


# --------------------------------------------------------------------------- #
# Config injection — emit exactly the fields a case sets
# --------------------------------------------------------------------------- #


def _dnsbl_mode_settings(mode: DnsblMode) -> dict[str, str]:
    """The DNSBL global-settings fields for a response mode."""
    if mode is DnsblMode.NXDOMAIN:
        # Python blocking mode synthesises NXDOMAIN for matched names.
        return {"dnsbl_mode": "dnsbl_python", "pfb_py_block": "on"}
    if mode is DnsblMode.NULL:
        # Unbound mode + per-list logging='disabled' -> null IP 0.0.0.0 / ::0.
        return {"dnsbl_mode": "dnsbl_unbound", "pfb_py_block": ""}
    # VIP: Unbound mode, per-list logging='' -> sinkhole to pfb_dnsvip4.
    return {"dnsbl_mode": "dnsbl_unbound", "pfb_py_block": ""}


def _dnsbl_list_logging(mode: DnsblMode) -> str:
    """The per-list ``logging`` value that selects null vs VIP."""
    return "disabled" if mode is DnsblMode.NULL else "enabled"


def inject(vm: SmokeVM, spec: DnsblCase | IpCase, *, timeout: float = 90.0) -> None:
    """Apply a case's pfBlockerNG config AND control records, then write_config.

    Control records are written FIRST (so a reload regenerating unbound.conf
    keeps them), then the pfBlockerNG list/settings config, in one write_config.
    """
    # 1) Control records (their own write_config — safe to persist first).
    set_control_records(vm, spec.control_local_data, spec.control_local_zone, timeout=timeout)

    # 2) The pfBlockerNG list + settings config.
    if isinstance(spec, DnsblCase):
        snippet = _dnsbl_inject_snippet(spec)
    else:
        snippet = _ip_inject_snippet(spec)
    result = php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"inject failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}")


def _dnsbl_inject_snippet(spec: DnsblCase) -> str:
    settings = _dnsbl_mode_settings(spec.mode)
    settings["pfb_dnsbl"] = "on"
    if spec.whitelist:
        settings["suppression"] = "\n".join(spec.whitelist)
    row = {
        "header": spec.header,
        "url": spec.feed_url,
        "state": "Enabled",
        "format": "auto",
    }
    listcfg = {
        "aliasname": spec.aliasname,
        "action": "Enabled",
        "cron": "EveryDay",
        "order": "primary",
    }
    return (
        f"$s = config_get_path({_php_str(CFG_DNSBL_SETTINGS)}, array());\n"
        f"$s = array_merge($s, {_php_kv_array(settings)});\n"
        f"config_set_path({_php_str(CFG_DNSBL_SETTINGS)}, $s);\n"
        f"$list = {_php_kv_array(listcfg)};\n"
        f"$list['row'] = array({_php_kv_array(row)});\n"
        f"$list['row'][0]['logging'] = {_php_str(_dnsbl_list_logging(spec.mode))};\n"
        f"config_set_path({_php_str(CFG_DNSBL_LISTS)}, array($list));\n"
        "write_config('pfBlockerNG smoke: DNSBL case');\n"
        "echo 'OK';"
    )


def _ip_inject_snippet(spec: IpCase) -> str:
    root = CFG_IP_V6_LISTS if spec.family == "v6" else CFG_IP_V4_LISTS
    row = {
        "header": spec.header,
        "url": spec.feed_url,
        "state": "Enabled",
        "format": "auto",
    }
    listcfg = {
        "aliasname": spec.aliasname,
        "action": spec.action,
        "cron": "EveryDay",
    }
    return (
        f"$list = {_php_kv_array(listcfg)};\n"
        f"$list['row'] = array({_php_kv_array(row)});\n"
        f"config_set_path({_php_str(root)}, array($list));\n"
        "write_config('pfBlockerNG smoke: IP case');\n"
        "echo 'OK';"
    )


# --------------------------------------------------------------------------- #
# Reload / reset — the PHP CLI cron verbs (no wrapper)
# --------------------------------------------------------------------------- #


def reload(vm: SmokeVM, scope: str = "update", *, timeout: float = 600.0) -> None:
    """Run a pfBlockerNG reload via the PHP CLI cron verb.

    ``scope`` is the verb: ``updatednsbl`` / ``updateip`` (targeted, faster per
    case) or ``update`` (full force, IP+DNSBL). The reload restarts Unbound; we
    wait on its readiness afterwards (no fixed sleep).
    """
    if scope not in ("update", "updateip", "updatednsbl"):
        raise ValueError(f"reload scope must be update/updateip/updatednsbl, got {scope!r}")
    result = vm.ssh(PHP_BIN, PFB_CLI, scope, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(f"reload({scope}) failed: rc={result.returncode} stderr={result.stderr!r}")
    wait_unbound_ready(vm)


def reset(vm: SmokeVM, *, timeout: float = 600.0) -> None:
    """Return the VM to the per-case baseline (Phase-3 isolation strategy).

    ``clearip`` + ``cleardnsbl`` drop the accumulated tables/sqlite, then a
    forced ``update`` rebuilds from config — required because pfBlockerNG caches
    feeds, so an edited mock fixture is re-fetched only on a force.
    """
    for verb in ("clearip", "cleardnsbl"):
        result = vm.ssh(PHP_BIN, PFB_CLI, verb, timeout=120.0)
        if result.returncode != 0:
            raise RuntimeError(f"reset {verb} failed: rc={result.returncode} stderr={result.stderr!r}")
    reload(vm, "update", timeout=timeout)


def wait_unbound_ready(vm: SmokeVM, *, attempts: int = 30, delay: float = 2.0) -> None:
    """Poll ``unbound-control status`` until ready (mirrors install-pkg.sh)."""
    cmd = "/usr/local/sbin/unbound-control -c /var/unbound/unbound.conf status"
    for _ in range(attempts):
        result = vm.ssh(cmd, timeout=15.0)
        if result.returncode == 0:
            return
        time.sleep(delay)
    raise RuntimeError("Unbound did not become ready after reload")


# --------------------------------------------------------------------------- #
# DNS probe + assert helpers (rcode/record shapes)
# --------------------------------------------------------------------------- #


@dataclass
class DnsAnswer:
    """A resolved DNS answer: rcode name + the A/AAAA records returned."""

    rcode: str
    records: list[str]


def dns_probe(vm: SmokeVM, name: str, rtype: str = "A", *, timeout: float = 5.0) -> DnsAnswer:
    """Query the guest's real Unbound for (name, rtype) -> (rcode, records).

    Uses dnspython (deferred import inside, via conftest.resolve_a for A; a
    direct query for other types) so importing this module needs no smoke deps.
    """
    import dns.message
    import dns.query
    import dns.rcode
    import dns.rdatatype

    query = dns.message.make_query(name, dns.rdatatype.from_text(rtype))
    response = dns.query.tcp(query, vm.host, port=vm.dns_port, timeout=timeout)
    rcode = dns.rcode.to_text(response.rcode())
    wanted = dns.rdatatype.from_text(rtype)
    records: list[str] = []
    for rrset in response.answer:
        if rrset.rdtype == wanted:
            records.extend(str(item) for item in rrset)
    return DnsAnswer(rcode=rcode, records=records)


def is_nxdomain(answer: DnsAnswer) -> bool:
    """True iff the resolver returned NXDOMAIN with no records."""
    return answer.rcode == "NXDOMAIN" and not answer.records


def is_null_ip(answer: DnsAnswer, null_ip: str = NULL_IP4) -> bool:
    """True iff the answer is the null-block IP (default ``0.0.0.0``)."""
    return null_ip in answer.records


def is_vip(answer: DnsAnswer, vip: str = DEFAULT_DNSBL_VIP4) -> bool:
    """True iff the answer is the DNSBL webserver VIP."""
    return vip in answer.records


def resolves_to(answer: DnsAnswer, addr: str) -> bool:
    """True iff ``addr`` is among the returned records (a real pass)."""
    return addr in answer.records


def resolve_control(vm: SmokeVM, name: str) -> list[str]:
    """A control/whitelist passthrough A lookup (reuses conftest.resolve_a)."""
    return resolve_a(name, vm.host, vm.dns_port)


# --------------------------------------------------------------------------- #
# IP probe — pfctl table members + rule references
# --------------------------------------------------------------------------- #


def pfctl_table_members(vm: SmokeVM, alias: str, *, timeout: float = 30.0) -> list[str]:
    """Return the members of a pf alias table (``pfctl -t <alias> -T show``)."""
    result = vm.ssh(PFCTL, "-t", alias, "-T", "show", timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(f"pfctl -t {alias} -T show failed: rc={result.returncode} stderr={result.stderr!r}")
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def pfctl_tables(vm: SmokeVM, *, timeout: float = 30.0) -> list[str]:
    """Return all defined pf table names (``pfctl -sTables``)."""
    result = vm.ssh(PFCTL, "-sTables", timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(f"pfctl -sTables failed: rc={result.returncode} stderr={result.stderr!r}")
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def rule_references(vm: SmokeVM, alias: str, *, timeout: float = 30.0) -> bool:
    """True iff a loaded pf rule references ``alias`` (``pfctl -sr`` | grep)."""
    result = vm.ssh(PFCTL, "-sr", timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(f"pfctl -sr failed: rc={result.returncode} stderr={result.stderr!r}")
    return any(f"<{alias}>" in line or alias in line for line in result.stdout.splitlines())


def member_present(members: list[str], ip: str) -> bool:
    """True iff ``ip`` appears in a table's members (CIDR-tolerant exact/prefix)."""
    return ip in members or any(m.split("/", 1)[0] == ip for m in members)


# --------------------------------------------------------------------------- #
# Composed per-case context manager
# --------------------------------------------------------------------------- #


class CaseContext:
    """One matrix case: inject -> reload -> (probe in the body) -> reset.

    Usage::

        with CaseContext(vm, spec) as ctx:
            answer = dns_probe(vm, "blocked.test")
            assert is_nxdomain(answer)

    On enter: inject(spec) then reload(scope). On exit: reset(vm) so the next
    case starts from the baseline (Phase-3 session-isolation). ``scope`` is
    auto-chosen (``updatednsbl`` for a DnsblCase, ``updateip`` for an IpCase)
    for the faster targeted reload; override via ``scope=``.
    """

    def __init__(self, vm: SmokeVM, spec: DnsblCase | IpCase, *, scope: str | None = None) -> None:
        self.vm = vm
        self.spec = spec
        if scope is not None:
            self.scope = scope
        elif isinstance(spec, DnsblCase):
            self.scope = "updatednsbl"
        else:
            self.scope = "updateip"

    def __enter__(self) -> CaseContext:
        inject(self.vm, self.spec)
        reload(self.vm, self.scope)
        return self

    def __exit__(self, *exc: object) -> None:
        reset(self.vm)
