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
  the pfSense config API over ``pfSsh.php`` (``config_set_path`` /
  ``write_config``). Control records go in as DNS-Resolver Host Overrides
  (``unbound/hosts``) IN CONFIG, BEFORE the feed update: host overrides are the
  supported name->IP mechanism, they generate ``host_entries.conf`` (Unbound-
  included), and they survive the pfBlockerNG reload — which manages its OWN
  ``unbound.conf`` via ``pfb_stop_start_unbound`` and never calls
  ``services_unbound_configure``, so set_control_records() runs that itself to
  regenerate ``host_entries.conf`` before the reload re-adds the DNSBL python.
  (Custom Options were tried first; a pfBlockerNG reload never re-applies them.)
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

import base64
import ipaddress
import os
import re
import shlex
import subprocess
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from .conftest import GUEST_TO_HOST_ALIAS, SMOKE_DIR, STUB_DNS_A, SmokeVM, resolve_a

# --------------------------------------------------------------------------- #
# Paths / constants
# --------------------------------------------------------------------------- #

INSTALL_PKG_SH = SMOKE_DIR.parent.parent / "scripts" / "install-pkg.sh"
PHP_BIN = "/usr/local/bin/php"
# pfSense developer shell — runs PHP in the fully-bootstrapped env (config
# loaded + locked), so config_set_path/write_config persist a valid config.xml.
PFSSH_BIN = "/usr/local/sbin/pfSsh.php"
PFB_CLI = "/usr/local/www/pfblockerng/pfblockerng.php"
PFCTL = "/sbin/pfctl"

# pfSense config API roots (see pfblockerng.inc).
CFG_GLOBAL = "installedpackages/pfblockerng/config/0"
CFG_DNSBL_SETTINGS = "installedpackages/pfblockerngdnsblsettings/config/0"
CFG_DNSBL_LISTS = "installedpackages/pfblockerngdnsbl/config"
CFG_IP_V4_LISTS = "installedpackages/pfblockernglistsv4/config"
CFG_IP_V6_LISTS = "installedpackages/pfblockernglistsv6/config"
CFG_IP_SETTINGS = "installedpackages/pfblockerngipsettings/config/0"
# DNS-Resolver Host Overrides: control names go here (see set_control_records).
CFG_UNBOUND_HOSTS = "unbound/hosts"

# The configured DNSBL VIP a "vip" block answers with == the IPv4 the harness-
# injected lo0 IP-Alias VIP carries (ensure_dnsbl_vip). Env-overridable, but
# `or` (not get's default): smoke.yml SETS this var to "" when the secret/var is
# unset, and get(key, default) returns "" for a set-but-empty var — which left
# the VIP subnet blank ("invalid IPv4 VIP"). Treat empty as unset.
DEFAULT_DNSBL_VIP4 = os.environ.get("SMOKE_DNSBL_VIP4") or "10.10.10.1"
NULL_IP4 = "0.0.0.0"

# The pfSense Virtual IP the harness injects so DNSBL has the sinkhole VIP it
# requires (pfb_validate_vips, inc:725). By default pfBlockerNG does NOT
# auto-create one (pfb_dnsvip_auto is OFF by default; when ON, pfb_manage_dnsbl_vip
# auto-creates it), so we add an lo0 IP-Alias VIP and point pfb_dnsvip4 at it via
# the "_vip<uniqid>" id convention get_configured_vip_list() uses. Kept OUT of the
# image so the "no VIP configured" scenario stays testable (just skip ensure_dnsbl_vip).
SMOKE_VIP_UNIQID = "pfbsmokevip"
SMOKE_VIP_IFACE = "lo0"
# DNSBL lighttpd sinkhole ports — DNSBL skips ALL feed processing if these are
# empty (inc:7558). GUI defaults (pfblockerng_dnsbl.php:47).
DNSBL_PORT = "8081"
DNSBL_PORT_SSL = "8443"

# pfBlockerNG only builds the IP deny rule when an inbound/outbound interface is
# configured (inc:10132 "Inbound interface option not configured"); the alias
# table builds regardless. The wizard sets these — the harness must too.
# Env-overridable; "wan" is the one interface a default single-NIC pfSense has.
# `or` (not get's default) so a set-but-empty env var still falls back.
SMOKE_IP_IFACE = os.environ.get("SMOKE_IP_IFACE") or "wan"


def unique_domain(label: str = "pfbsmoke") -> str:
    """A collision-proof, NON-reserved test domain, e.g. ``blocked-<uuid4hex>.com``.

    Test domains MUST avoid the RFC 6761 special-use TLDs (``.test``, ``.example``,
    ``.invalid``, ``.localhost``, ``.onion``) and ``home.arpa``: Unbound serves
    those as built-in ``local-zone``s and answers them (NXDOMAIN/NODATA) BEFORE the
    pfBlockerNG python module runs — shadowing the DNSBL block entirely. A random
    UUIDv4 under ``.com`` can't collide with a real domain and isn't on the HSTS
    preload list (which would flip the block shape to NULL when HSTS is on). The
    ``<label>-`` prefix keeps the first label from starting with a digit.
    """
    return f"{label}-{uuid.uuid4().hex}.com"


# --------------------------------------------------------------------------- #
# ABP feed construction (ADR-07)
# --------------------------------------------------------------------------- #
# A feed is parsed as Adblock-Plus syntax ONLY when pfBlockerNG header-sniffs an
# ABP marker on the first non-'!' line of the downloaded body (inc:7934-7938:
# '[Adblock Plus ' / '[Adblock Plus]' / '[uBlock Origin' / '! Title: AdGuard').
# That sets $easylist -> the feed is tagged format_hint='abp' in the manifest
# (inc:8414) and its RAW lines flow to the Python ABP parser (parse_abp); the old
# PHP lite parser is gone. So an ABP smoke feed is just a plain local feed whose
# body STARTS with this header line — no per-row 'format' override is needed (the
# row stays 'auto'; detection is content-based, not config-based).

ABP_HEADER = "[Adblock Plus 2.0]"


def abp_feed(*lines: str) -> str:
    """Build an ABP-tagged feed body: the ``[Adblock Plus 2.0]`` header sniffed by
    pfBlockerNG (inc:7934) followed by raw ABP ``lines`` (``||d^`` / ``@@||d^`` /
    ``/re/`` / ``||d^$important`` / ``0.0.0.0 host`` ...), one per line.

    Deliver via :func:`write_local_feed` and pass the path as a feed/extra-row URL;
    the body's header makes pfBlockerNG tag the feed ABP so the lines reach
    ``parse_abp`` intact.
    """
    return ABP_HEADER + "\n" + "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- #
# Case specification (declarative input the matrix fills in)
# --------------------------------------------------------------------------- #


class DnsblMode(str, Enum):
    """The block shape a DNSBL case expects for a matched name.

    On ``next`` (python-mode-only) the two shapes are:

    * ``NULL`` — NOERROR + ``0.0.0.0`` / ``::0``; per-list
      ``logging='disabled'`` → ``logging_type='2'`` → ``null_blocking=True``
      in ``pfb_unbound.py:evaluate_domain``.
    * ``VIP`` — NOERROR + the DNSBL sinkhole VIP (``pfb_dnsvip4``); per-list
      ``logging='enabled'`` → ``logging_type='1'`` → ``null_blocking=False``.

    NXDOMAIN is NOT a valid python-mode output for a normal feed match
    (verified on the live box; the only NXDOMAIN path in pfb_unbound.py is
    SafeSearch).  The ``NXDOMAIN`` entry has been removed on ``next``.
    """

    NULL = "null"
    VIP = "vip"


@dataclass
class DnsblCase:
    """A DNSBL matrix case: one feed (served by mock_feeds) + its block mode.

    Fields and the config path each one sets:

      aliasname     -> CFG_DNSBL_LISTS/<n>/aliasname  (alias = DNSBL_<aliasname>)
      feed_url      -> CFG_DNSBL_LISTS/<n>/row/0/url  (a mock_feeds.feed_url)
      header        -> CFG_DNSBL_LISTS/<n>/row/0/header
      mode          -> response shape: NULL/VIP, set via per-list 'logging'
                       (on ``next`` python mode is always on; dnsbl_mode /
                       pfb_py_block are dead config keys)
      wildcard      -> feed entry style; a wildcard feed line blocks subdomains
      whitelist     -> CFG_DNSBL_SETTINGS/suppression (newline list; a leading
                       '.' suppresses the whole subtree)
      dnsbl_ip_action -> CFG_DNSBL_SETTINGS/action (the "DNSBL IP" firewall
                       feature): "" (Disabled) or e.g. "Deny_Both". When set,
                       IP literals embedded in the DNSBL feed populate the
                       pfB_DNSBLIP_{v4,v6} alias tables (dual-stack contract).
      control_local_data -> {name: {"A": ip, "AAAA": ip6}} injected as DNS-
                       Resolver Host Overrides (unbound/hosts) BEFORE update
      control_local_zone -> unused by the matrix; host overrides can't express a
                       local-zone (DNSBL builds its own blocking zones)

    ADR-07 ABP extensions (all default-empty -> the existing matrix is byte-for-
    byte unchanged; only an ABP case populates them):

      extra_rows    -> additional (header, feed_url) ROWS appended to the SAME
                       DNSBL list group. Each row is downloaded + header-sniffed
                       INDEPENDENTLY, so two ABP-bodied rows == two ABP feeds whose
                       rules the Python build MERGES — this is how a cross-feed
                       ``@@``/``$badfilter`` (an exception/prune in feed B acting on
                       a block in feed A) is exercised end-to-end.
      user_regex    -> the user "Python Regex List" (CFG_DNSBL_SETTINGS/pfb_regex
                       'on' + pfb_regex_list, newline list, inc:849-850,2711). User
                       regex are sovereign block patterns; they load into regexDB
                       and count toward pfb_py_regex_count.
      regex_cap     -> the opt-in "Limit long/complex regex" static cap
                       (CFG_DNSBL_SETTINGS/pfb_regex_cap 'on', inc:2685 -> ini
                       regex_cap=on). When on, an over-length (>200) / nested-
                       quantifier / alternation-overlap pattern is DROPPED at load
                       for FEED and USER regex (pfb_unbound.py:_regex_exceeds_
                       static_cap), so it never enters regexDB or the admitted count.
      custom_domains -> the DNSBL Group "Custom_List" (the list's base64 'custom'
                       field). pfBlockerNG auto-generates a synthetic
                       '{aliasname}_custom' row from it (inc:7752) which the manifest
                       tags provenance='user' -> the Python build bands those domains
                       as a SOVEREIGN user block (5), beating any feed allow (the user
                       is the sovereign; lists are automated). This is the GUI
                       Custom_List / the alerts "add to DNSBL customlist" button.
    """

    aliasname: str
    feed_url: str
    mode: DnsblMode = DnsblMode.VIP
    header: str = "smoketest"
    wildcard: bool = False
    whitelist: list[str] = field(default_factory=list)
    dnsbl_ip_action: str = ""
    control_local_data: dict[str, dict[str, str]] = field(default_factory=dict)
    control_local_zone: dict[str, str] = field(default_factory=dict)
    extra_rows: list[tuple[str, str]] = field(default_factory=list)
    user_regex: list[str] = field(default_factory=list)
    regex_cap: bool = False
    custom_domains: list[str] = field(default_factory=list)
    # cname_validation -> the "CNAME Validation" toggle (CFG_DNSBL_SETTINGS/pfb_cname
    # 'on', inc:852 -> ini python_cname). When on, pfb_unbound.py walks a resolved
    # answer's CNAME chain (operate(), gated on python_cname + an_numrrsets>1) and
    # blocks the ORIGINAL name if any CNAME target is on the blocklist (re-attributed
    # to the queried name, b_type '_CNAME'). Off (default): only the queried name is
    # checked, so a name whose CNAME target is blocked still resolves.
    cname_validation: bool = False
    # hsts -> the "HSTS via Null Block mode" toggle (CFG_DNSBL_SETTINGS/pfb_hsts,
    # inc:847 -> ini python_hsts). When on, pfb_unbound.py loads pfb_py_hsts.txt into
    # hstsDB; a VIP-mode (logging='enabled', log_type '1') block on an HSTS-preload
    # name keeps null_blocking=True -> NULL instead of the VIP (evaluate_domain:
    # ``log_type == '1' and not in_hsts``). ``None`` (default) emits nothing -> the
    # existing matrix is byte-for-byte unchanged; True/False forces pfb_hsts on/off.
    hsts: bool | None = None

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
        # pfBlockerNG suffixes IP alias tables by family: pfB_<aliasname>_<family>
        # (confirmed). The thin-slice IP case is IPv4, so the table + rule
        # reference pfB_<aliasname>_v4.
        return f"pfB_{self.aliasname}_{self.family}"


# --------------------------------------------------------------------------- #
# Deploy — install the branch-under-test .pkg (evolved; NOT deploy.sh rsync)
# --------------------------------------------------------------------------- #


def deploy(vm: SmokeVM, pkg_path: str | None = None, *, timeout: float = 300.0) -> None:
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
# Local feed file — write a list directly under /var/db/pfblockerng/<name> and
# use its PATH as the source (pfBlockerNG accepts a local path in a source's URL
# field, re-read each update). More reliable in CI than the HTTP mock fetch.
# --------------------------------------------------------------------------- #


PFB_DBDIR = "/var/db/pfblockerng"


def write_local_feed(vm: SmokeVM, name: str, contents: str, *, timeout: float = 30.0) -> str:
    """Write ``contents`` to /var/db/pfblockerng/<name> on the guest; return the path.

    The file goes DIRECTLY under /var/db/pfblockerng (NOT the deny/permit/native
    subdirs — those are pfBlockerNG's own reload output). The path is then used
    as the feed source's URL field.

    ``mkdir -p`` the data dir first: pfBlockerNG's POST-INSTALL does NOT create it
    (only a reload/update does), so a case that writes its feed BEFORE its first
    reload — e.g. the whole ABP matrix's first test — would otherwise hit
    ``tee: …: No such file or directory``.
    """
    path = f"{PFB_DBDIR}/{name}"
    # Ensure the data dir exists FIRST, as its own simple round-trip. Do NOT fold it
    # into the tee with `sh -c "mkdir … && tee …"`: ssh space-joins the remote argv
    # and the remote LOGIN shell (tcsh for pfSense root) re-parses it, so `sh -c`
    # would capture only the first token (and tcsh chokes on the POSIX `'\''` idiom).
    # A bare `mkdir -p <dir>` argv (no &&/redirect/nested quotes) is shell-agnostic.
    mk = subprocess.run(
        vm.ssh_argv("/bin/mkdir", "-p", PFB_DBDIR),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if mk.returncode != 0:
        raise RuntimeError(f"write_local_feed({path}): mkdir {PFB_DBDIR} failed: rc={mk.returncode} {mk.stderr!r}")
    result = subprocess.run(
        vm.ssh_argv("tee", path),
        input=contents,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"write_local_feed({path}) failed: rc={result.returncode} {result.stderr!r}")
    return path


# --------------------------------------------------------------------------- #
# HSTS preload set — pin a name into the in-chroot list pfb_unbound.py reads
# --------------------------------------------------------------------------- #
# pfb_unbound.py loads /var/unbound/pfb_py_hsts.txt (chroot-relative
# ``pfb_py_hsts.txt``, init line ~752) into hstsDB on every reload. pfBlockerNG
# copies the shipped list into the chroot ONLY when it is missing
# (inc:2238 ``if (!file_exists(...))``), so a name appended here SURVIVES a DNSBL
# reload — letting a test put an arbitrary domain into the EFFECTIVE HSTS set
# instead of coupling to whatever the shipped preload list happens to contain.

UNBOUND_HSTS_FILE = "/var/unbound/pfb_py_hsts.txt"
UNBOUND_PFB_INI = "/var/unbound/pfb_unbound.ini"


def add_hsts_name(vm: SmokeVM, name: str, *, timeout: float = 30.0) -> None:
    """Append ``name`` (one line) to the in-chroot HSTS preload list.

    Use AFTER the case's first reload has (re)created ``pfb_py_hsts.txt`` from the
    shipped list, then reload again so the module re-reads hstsDB with ``name``
    included (copy-if-missing won't clobber the now-existing file). ``tee -a``
    appends and creates the file if absent (mirrors :func:`write_local_feed`).
    """
    result = subprocess.run(
        vm.ssh_argv("tee", "-a", UNBOUND_HSTS_FILE),
        input=f"{name}\n",
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"add_hsts_name({name}) failed: rc={result.returncode} {result.stderr!r}")


def assert_hsts_loaded(vm: SmokeVM, name: str, *, timeout: float = 30.0) -> None:
    """Precondition guard: ``name`` is in the effective HSTS set the module loads.

    Confirms BOTH halves of the load path so a failed end-to-end assertion can be
    attributed to the HSTS branch and not to a load miss: ``name`` is an exact line
    in ``pfb_py_hsts.txt`` (the file the chrooted module reads), AND ``python_hsts``
    is ``on`` in the generated ini (else pfb_unbound.py never opens the file).
    """
    in_file = vm.ssh("grep", "-Fxq", name, UNBOUND_HSTS_FILE, timeout=timeout)
    if in_file.returncode != 0:
        raise AssertionError(f"{name} not a line in {UNBOUND_HSTS_FILE} (rc={in_file.returncode})")
    ini = vm.ssh("cat", UNBOUND_PFB_INI, timeout=timeout)
    if not re.search(r"(?im)^\s*python_hsts\s*=\s*on\b", ini.stdout):
        raise AssertionError(f"python_hsts not 'on' in {UNBOUND_PFB_INI}:\n{ini.stdout}")


# --------------------------------------------------------------------------- #
# Hermetic gate — block the runner's egress for the test phase (ADR §4 req 4)
# --------------------------------------------------------------------------- #
# MUST run only AFTER deploy(): `pkg add` pulls pfBlockerNG's RUN_DEPENDS from
# the pfSense repo, and the guest reaches the internet THROUGH the runner's
# SLIRP NAT — so blocking the runner's egress before the package is installed
# hangs the install. Guarded by SMOKE_BLOCK_EGRESS (CI sets it) so a local
# `pytest -m smoke` never touches the dev machine's firewall. Loopback stays up
# (the mock feed server is reached via SLIRP 10.0.2.2 -> runner 127.0.0.1) and
# established flows (the live SSH session) are kept.


def block_egress() -> None:
    """Drop the runner's new outbound traffic (loopback + established kept)."""
    if not os.environ.get("SMOKE_BLOCK_EGRESS"):
        return
    for argv in (
        ["sudo", "iptables", "-P", "OUTPUT", "DROP"],
        ["sudo", "iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
        ["sudo", "iptables", "-A", "OUTPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
    ):
        subprocess.run(argv, check=True, timeout=30)


def unblock_egress() -> None:
    """Restore egress (teardown counterpart of :func:`block_egress`)."""
    if not os.environ.get("SMOKE_BLOCK_EGRESS"):
        return
    subprocess.run(["sudo", "iptables", "-P", "OUTPUT", "ACCEPT"], check=False, timeout=30)
    subprocess.run(["sudo", "iptables", "-F", "OUTPUT"], check=False, timeout=30)


# --------------------------------------------------------------------------- #
# PHP helpers — run a snippet through the pfSense config API over SSH
# --------------------------------------------------------------------------- #


def php_eval(vm: SmokeVM, snippet: str, *, timeout: float = 60.0) -> subprocess.CompletedProcess[str]:
    """Run a PHP snippet in the FULLY-bootstrapped pfSense env via pfSsh.php.

    pfSsh.php is the pfSense developer shell: it loads AND locks the config, so
    config_set_path/write_config persist a complete, valid config.xml. A bare
    ``php -r`` (even requiring globals/config) wrote a partial config that the
    next read could not recover ("A valid config file could not be recovered").

    The PHP is fed on stdin; pfSsh.php buffers typed lines, ``exec`` compiles +
    runs the buffer, ``exit`` quits. pfSsh.php prints a startup banner on stdout,
    so a snippet that READS a value must delimit it (see :func:`config_get`);
    writers just emit an 'OK' sentinel the caller greps for.
    """
    program = snippet + "\nexec\nexit\n"
    return subprocess.run(
        vm.ssh_argv(PFSSH_BIN),
        input=program,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


_CFG_VAL_OPEN = "<<<CFGVAL>>>"
_CFG_VAL_CLOSE = "<<<CFGEND>>>"


def config_get(vm: SmokeVM, path: str, *, timeout: float = 60.0) -> str:
    """Read a scalar config value back via the config API (for self-tests).

    Delimited so pfSsh.php's startup banner doesn't pollute the value.
    """
    snippet = (
        f"echo {_php_str(_CFG_VAL_OPEN)} . (string) config_get_path({_php_str(path)}, '') . {_php_str(_CFG_VAL_CLOSE)};"
    )
    result = php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(f"config_get({path!r}) failed: {result.stderr!r}")
    out = result.stdout
    start = out.find(_CFG_VAL_OPEN)
    end = out.find(_CFG_VAL_CLOSE)
    if start == -1 or end == -1:
        raise RuntimeError(f"config_get({path!r}): no delimited value in pfSsh.php output: {out!r}")
    return out[start + len(_CFG_VAL_OPEN) : end]


def _php_str(value: str) -> str:
    """Render a Python str as a single-quoted PHP string literal."""
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _php_kv_array(data: dict[str, str]) -> str:
    """Render a flat dict as a PHP associative-array literal."""
    items = ", ".join(f"{_php_str(k)} => {_php_str(v)}" for k, v in data.items())
    return f"array({items})"


def _b64_textarea(lines: list[str]) -> str:
    """Base64-encode a CRLF-joined textarea value — the shape pfBlockerNG stores.

    pfBlockerNG TEXTAREA settings (``suppression``, ``pfb_regex_list``, ``custom``, …)
    are kept base64-encoded in config (the GUI base64_encodes on save) and decoded by
    ``pfbng_text_area_decode()`` (``base64_decode`` then ``explode("\\r\\n", …)``). A
    PLAIN value injected here would be base64_decoded into GARBAGE — invalid bytes that
    crash the python module's INI load (``Failed to load ini configuration: 'utf-8'
    codec can't decode byte``) and silently disable DNSBL. Encode with CRLF separators
    so the decode splits into the right lines. Empty list -> '' (no entries)."""
    return base64.b64encode("\r\n".join(lines).encode()).decode()


# --------------------------------------------------------------------------- #
# Control records — DNS-Resolver Host Overrides, set IN CONFIG before update
# --------------------------------------------------------------------------- #


def _host_override_rows(local_data: dict[str, dict[str, str]]) -> list[dict[str, str]]:
    """Build ``unbound/hosts`` rows from ``{name: {rtype: ip}}``.

    One row per name: host = first label, domain = the rest, ip = a comma list
    of every A/AAAA value (pfSense expands a multi-IP host override into one
    ``local-data`` line per address). rtype is implicit in the address family,
    so the keys ("A"/"AAAA") are advisory only.
    """
    rows: list[dict[str, str]] = []
    for name, records in local_data.items():
        ips = [v for v in records.values() if v]
        if not ips:
            continue
        label, _, domain = name.partition(".")
        rows.append(
            {
                "host": label,
                "domain": domain,
                "ip": ",".join(ips),
                "descr": "pfBlockerNG smoke control",
                "aliases": "",
            }
        )
    return rows


def set_control_records(
    vm: SmokeVM,
    local_data: dict[str, dict[str, str]],
    local_zone: dict[str, str],
    *,
    timeout: float = 120.0,
) -> None:
    """Persist control names as DNS-Resolver Host Overrides (``unbound/hosts``).

    Host overrides are the supported pfSense name->IP mechanism: they generate
    ``host_entries.conf`` (Unbound-included) and survive the pfBlockerNG reload,
    which manages its OWN ``unbound.conf`` (``pfb_reload_unbound`` ->
    ``pfb_stop_start_unbound``) and never calls ``services_unbound_configure``.
    So we add the rows to CONFIG (idempotent on host+domain) and run
    ``services_unbound_configure()`` ourselves to regenerate
    ``host_entries.conf``; the later pfBlockerNG ``update`` re-adds the DNSBL
    python on top (inject() does control records first, reload second).

    ``local_zone`` is unsupported here — a host override can't express a
    local-zone, and no matrix case needs one (DNSBL builds its own blocking
    zones). A non-empty one is rejected rather than silently dropped.
    """
    if local_zone:
        raise ValueError(f"set_control_records: local_zone unsupported via host overrides: {local_zone!r}")
    rows = _host_override_rows(local_data)
    if not rows:
        return
    php_rows = "array(" + ", ".join(_php_kv_array(r) for r in rows) + ")"
    snippet = (
        f"$cur = config_get_path({_php_str(CFG_UNBOUND_HOSTS)}, array());\n"
        f"foreach ({php_rows} as $row) {{\n"
        "  $dup = FALSE;\n"
        "  foreach ($cur as $e) {\n"
        "    if (($e['host'] ?? '') === $row['host']\n"
        "        && ($e['domain'] ?? '') === $row['domain']) { $dup = TRUE; break; }\n"
        "  }\n"
        "  if (!$dup) { $cur[] = $row; }\n"
        "}\n"
        f"config_set_path({_php_str(CFG_UNBOUND_HOSTS)}, $cur);\n"
        "write_config('pfBlockerNG smoke: control host overrides');\n"
        "services_unbound_configure();\n"
        "echo 'OK';"
    )
    result = php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"set_control_records failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}")


def ensure_dnsbl_vip(vm: SmokeVM, *, ip4: str = DEFAULT_DNSBL_VIP4, timeout: float = 120.0) -> None:
    """Inject the lo0 IP-Alias VIP DNSBL requires and point pfb_dnsvip4 at it.

    pfBlockerNG force-disables DNSBL when ``pfb_validate_vips`` finds no VIP
    (inc:725). By default (``pfb_dnsvip_auto`` OFF) it does not auto-create one;
    the harness adds it exactly as a user would in Firewall > Virtual IPs: a
    ``virtualip/vip`` entry on the DNSBL interface (lo0), referenced by
    ``pfb_dnsvip4`` as ``_vip<uniqid>`` (the ``get_configured_vip_list()`` id
    convention). When ``pfb_dnsvip_auto`` is ON, ``pfb_manage_dnsbl_vip`` creates
    a marked VIP automatically (ADR-13). Idempotent on the uniqid.

    Then APPLY it (as the GUI's Firewall > Virtual IPs save does): the VIP must
    be realized for ``pfb_get_vips`` (-> ``get_specialnet``) to list it —
    config-only left it "invalid IPv4 VIP". ``interface_vip_configure`` lives in
    ``interfaces.inc`` (not auto-loaded by pfSsh.php), so require_once it first
    and guard the call so a missing symbol can't abort the eval.
    """
    vip = {
        "mode": "ipalias",
        "interface": SMOKE_VIP_IFACE,
        "type": "single",
        "subnet": ip4,
        "subnet_bits": "32",
        "descr": "pfBlockerNG DNSBL",
        "uniqid": SMOKE_VIP_UNIQID,
    }
    vip_id = f"_vip{SMOKE_VIP_UNIQID}"
    snippet = (
        "$vips = config_get_path('virtualip/vip', array());\n"
        "$found = FALSE;\n"
        f"foreach ($vips as $v) {{\n"
        f"  if (($v['uniqid'] ?? '') === {_php_str(SMOKE_VIP_UNIQID)}) {{ $found = TRUE; break; }}\n"
        "}\n"
        f"if (!$found) {{ $vips[] = {_php_kv_array(vip)}; config_set_path('virtualip/vip', $vips); }}\n"
        f"$d = config_get_path({_php_str(CFG_DNSBL_SETTINGS)}, array());\n"
        f"$d['pfb_dnsvip4'] = {_php_str(vip_id)};\n"
        # DNSBL aborts ("DNSBL Ports are not defined. Exiting", inc:7558 ->
        # $dnsbl_error) and skips ALL feed processing when the lighttpd sinkhole
        # ports are empty. The GUI defaults them; the harness must too.
        f"$d['pfb_dnsport'] = {_php_str(DNSBL_PORT)};\n"
        f"$d['pfb_dnsport_ssl'] = {_php_str(DNSBL_PORT_SSL)};\n"
        f"config_set_path({_php_str(CFG_DNSBL_SETTINGS)}, $d);\n"
        "write_config('pfBlockerNG smoke: DNSBL VIP');\n"
        "require_once('interfaces.inc');\n"
        f"if (function_exists('interface_vip_configure')) {{ interface_vip_configure({_php_kv_array(vip)}); }}\n"
        "echo 'OK';"
    )
    result = php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"ensure_dnsbl_vip failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}")


# --------------------------------------------------------------------------- #
# ADR-13 auto-VIP ("Create VIPs automatically") — live introspection helpers
# --------------------------------------------------------------------------- #

# The descr marker the package stamps on an auto-created v4 sinkhole VIP and the
# first candidate address pfb_pick_free_dnsbl_vip() returns. Mirror the PHP
# constants (PFB_AUTO_VIP_DESCR_V4) / candidate sweep in pfblockerng.inc. The
# matrix's MANUAL VIP sits at 10.10.10.1 (DEFAULT_DNSBL_VIP4), so the first auto
# candidate 10.10.10.53 is free and is the one auto-create picks — the two
# coexist, which is exactly what lets the auto-VIP case run on the same VM
# without disturbing the manual-VIP matrix.
AUTO_VIP_DESCR_V4 = "pfB_AUTO_VIP_v4"
AUTO_VIP_IP4 = "10.10.10.53"


def _php_read_scalar(vm: SmokeVM, pre: str, expr: str, *, timeout: float = 60.0) -> str:
    """Run PHP statements ``pre`` then echo the DELIMITED string value of ``expr``.

    Same delimiter trick as :func:`config_get` (pfSsh.php prints a banner, so a
    read must be fenced). Returns the inner string; raises if the fence is absent.
    """
    snippet = pre + f"\necho {_php_str(_CFG_VAL_OPEN)} . (string) ({expr}) . {_php_str(_CFG_VAL_CLOSE)};"
    result = php_eval(vm, snippet, timeout=timeout)
    out = result.stdout
    start = out.find(_CFG_VAL_OPEN)
    end = out.find(_CFG_VAL_CLOSE)
    if start == -1 or end == -1:
        raise RuntimeError(
            f"_php_read_scalar: no delimited value: rc={result.returncode} out={out!r} err={result.stderr!r}"
        )
    return out[start + len(_CFG_VAL_OPEN) : end]


def set_dnsvip_auto(vm: SmokeVM, on: bool, *, timeout: float = 60.0) -> None:
    """Toggle the ADR-13 'Create VIPs automatically' setting (``pfb_dnsvip_auto``)."""
    val = "on" if on else ""
    snippet = (
        f"$d = config_get_path({_php_str(CFG_DNSBL_SETTINGS)}, array());\n"
        f"$d['pfb_dnsvip_auto'] = {_php_str(val)};\n"
        f"config_set_path({_php_str(CFG_DNSBL_SETTINGS)}, $d);\n"
        "write_config('pfBlockerNG smoke: toggle pfb_dnsvip_auto');\n"
        "echo 'OK';"
    )
    result = php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"set_dnsvip_auto({on}) failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}")


def set_dnsbl_enabled(vm: SmokeVM, on: bool, *, timeout: float = 60.0) -> None:
    """Toggle the DNSBL component (``pfb_dnsbl``) so the next reload runs
    pfb_create_dnsbl in 'enabled' / 'disabled' mode (mode keys on dnsbl=='on')."""
    val = "on" if on else ""
    snippet = (
        f"$d = config_get_path({_php_str(CFG_DNSBL_SETTINGS)}, array());\n"
        f"$d['pfb_dnsbl'] = {_php_str(val)};\n"
        f"config_set_path({_php_str(CFG_DNSBL_SETTINGS)}, $d);\n"
        "write_config('pfBlockerNG smoke: toggle pfb_dnsbl');\n"
        "echo 'OK';"
    )
    result = php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(
            f"set_dnsbl_enabled({on}) failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}"
        )


def marked_vip_subnet(vm: SmokeVM, descr: str = AUTO_VIP_DESCR_V4, *, timeout: float = 60.0) -> str:
    """Subnet (IP) of the first ``virtualip/vip`` entry whose ``descr`` == ``descr``, or '' if none.

    The marker is package-owned, so a non-empty return is the live proof an auto
    VIP exists; '' proves it was never created / already removed.
    """
    pre = (
        "$out = '';\n"
        "foreach (config_get_path('virtualip/vip', array()) as $v) {\n"
        f"  if (($v['descr'] ?? '') === {_php_str(descr)}) {{ $out = (string) ($v['subnet'] ?? ''); break; }}\n"
        "}"
    )
    return _php_read_scalar(vm, pre, "$out", timeout=timeout)


def dnsvip4_address(vm: SmokeVM, *, timeout: float = 60.0) -> str:
    """The IPv4 the stored ``pfb_dnsvip4`` id currently resolves to (or '')."""
    pre = f"$d = config_get_path({_php_str(CFG_DNSBL_SETTINGS)}, array());"
    return _php_read_scalar(vm, pre, "get_configured_vip_ipv4($d['pfb_dnsvip4'] ?? '') ?? ''", timeout=timeout)


def vip_alias_live(vm: SmokeVM, ip: str, iface: str = "lo0", *, timeout: float = 30.0) -> bool:
    """True iff ``ip`` is a live alias on ``iface`` per ``ifconfig`` (the realized VIP).

    Matches the address as a whole ``inet``/``inet6`` token, NOT a bare substring:
    ``ip in stdout`` would prefix-false-positive (e.g. ``10.10.10.53`` reported live
    because the iface carries ``10.10.10.530`` or ``110.10.10.53``). ``ifconfig``
    prints ``inet <ip> netmask ...`` / ``inet6 <ip> prefixlen ...``, so an exact
    token right after ``inet``/``inet6`` is the address itself.
    """
    result = vm.ssh("/sbin/ifconfig", iface, timeout=timeout)
    for line in result.stdout.splitlines():
        toks = line.split()
        for i, tok in enumerate(toks[:-1]):
            if tok in ("inet", "inet6") and toks[i + 1] == ip:
                return True
    return False


def use_system_dns_upstream(vm: SmokeVM, *, timeout: float = 120.0) -> None:
    """Point pfSense at the runner-side mock via its REAL System-DNS path (no custom zone).

    The realistic wiring: pfSense forwards (forwarding mode) to its System DNS server
    ``10.0.2.2`` — QEMU/libslirp's host alias — which NATs ``guest->10.0.2.2:53`` straight
    to the mock on the runner's loopback (``127.0.0.1:53``), port-preserving. This is the
    SAME host-alias path the in-runner mock-feed HTTP server already rides
    (``http://10.0.2.2:<port>/...``), so the chain is:

        guest Unbound --(forward)--> 10.0.2.2:53 (SLIRP host alias) --(NAT)--> 127.0.0.1:53 (mock)

    Crucially this needs NO ``/etc/resolv.conf`` override on the runner (the SLIRP virtual
    DNS at 10.0.2.3 would read resolv.conf; the 10.0.2.2 host alias does not) — the runner's
    own resolver is left fully intact, so nothing on the host loses DNS during the run and
    there is no teardown to restore. No custom ``forward-zone`` and no guestfwd either. The
    mock records every query (``stub.received(...)``), so blocking is read off the upstream.
    Loopback survives the per-case egress block (``-o lo ACCEPT``), so it stays hermetic.

    Config set (idempotent; written + ``services_unbound_configure``):
      * ``system/dnsserver = [10.0.2.2]`` and DHCP-override OFF — so ``10.0.2.2`` is the
        SOLE forwarder (drops the baked image's dead 1.1.1.1/1.0.0.1, which egress-block
        makes unreachable and would only add forward timeouts).
      * ``unbound/forwarding = on`` — forward to the System DNS server.
      * ``unset unbound/dnssec`` — the mock's answers are unsigned; a validator would
        mark them bogus (SERVFAIL).
      * ``unset unbound/custom_options`` — drop any prior custom forward-zone.
    """
    snippet = (
        "$s = config_get_path('system', array());\n"
        f"$s['dnsserver'] = array({_php_str(GUEST_TO_HOST_ALIAS)});\n"
        # Disable 'Allow DNS server list to be overridden by DHCP' so only 10.0.2.2 is used.
        "unset($s['dnsallowoverride']);\n"
        "config_set_path('system', $s);\n"
        "$u = config_get_path('unbound', array());\n"
        "$u['forwarding'] = 'on';\n"
        "unset($u['dnssec']);\n"
        "unset($u['custom_options']);\n"
        "config_set_path('unbound', $u);\n"
        "write_config('pfBlockerNG smoke: system-DNS upstream (SLIRP host alias -> mock)');\n"
        "services_unbound_configure();\n"
        "echo 'OK';"
    )
    result = php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(
            f"use_system_dns_upstream failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}"
        )
    # services_unbound_configure restarts Unbound — wait for it before any probe.
    wait_unbound_ready(vm)
    # READINESS + RELAY SELF-CHECK (fail fast, don't let the matrix hang): resolve one
    # throwaway name on-box. With the mock as upstream it MUST come back as the sentinel
    # (pfSense -> 10.0.2.2 SLIRP host alias -> runner 127.0.0.1:53 mock). The FIRST response
    # is authoritative; if it isn't the sentinel, the relay isn't wired — raise NOW with
    # the answer, rather than letting every per-case forward time out (~300s each).
    probe = unique_domain("sysdnsselfcheck")
    ans = dns_probe(vm, probe, "A", timeout=10.0, attempts=3, delay=3.0)
    if not resolves_to(ans, STUB_DNS_A):
        raise RuntimeError(
            f"System-DNS relay self-check FAILED: {probe} -> {ans} (expected the mock sentinel "
            f"{STUB_DNS_A}). pfSense's 10.0.2.2 host alias -> runner 127.0.0.1:53 mock path is not "
            f"working (libslirp not NATing the host alias to the mock, or unbound not forwarding)."
        )


# --------------------------------------------------------------------------- #
# Update hooks (ADR-12) — pre/post command hooks fired from the update pass
# --------------------------------------------------------------------------- #
# pfBlockerNG runs admin-configured pre/post commands once per update pass from
# sync_package_pfblockerng (inc:7388 pre, inc:11227 post). The hooks live as a
# PLAIN NUMERIC array under the 'row' listtag at CFG_GLOBAL/hooks/row (NOT a bare
# list under <hooks>: 'hooks' is not a pfSense listtag, so a bare list serializes
# to invalid <0> XML and never reloads — see pfb_get_hooks()). pfb_get_hooks()
# reads ``$pfbconfig['hooks']['row']`` and runs ONLY entries with enabled==='on'
# whose ``when`` matches the fire point and whose ``command`` is non-empty. Each
# hook runs AS ROOT in the HOST context (NOT
# chrooted) via ``PFB_<K>=<v> … /usr/bin/timeout … /bin/sh -c <command>`` — so a
# hook that writes /tmp/<file> on the guest is plainly readable back over SSH,
# which is exactly how these smoke tests observe a hook's environment and that it
# ran. The env carries PFB_WHEN plus one PFB_<UPPER(key)> per ctx entry
# (inc:1797): pre ⇒ {WHEN, TRIGGER}; post ⇒ {WHEN, TRIGGER, IP_CHANGED,
# DNSBL_CHANGED, STATUS, CHANGED_IP_ALIASES, CHANGED_DNSBL_GROUPS}. reload(vm, scope) fires the hooks
# because it runs the same ``pfblockerng.php <scope>`` CLI the GUI/cron use.

HOOK_MARKER_DIR = "/tmp"


def hook_marker_path(token: str, when: str) -> str:
    """Path of a hook's marker file on the guest, e.g. ``/tmp/pfb_hook_<token>_<when>``.

    The marker lives under ``/tmp`` on the HOST (not a chroot): a hook runs as root
    in host context, so an env-dump hook writing here is read straight back over
    SSH. ``token`` is per-test (unique) so concurrent/leftover markers can't collide;
    ``when`` ('pre'/'post' or any label) lets one test use distinct pre/post markers.
    """
    return f"{HOOK_MARKER_DIR}/pfb_hook_{token}_{when}"


def env_dump_hook(
    token: str, when: str, *, enabled: str = "on", timeout: str = "60", description: str = ""
) -> dict[str, str]:
    """A hook entry whose command dumps the env to this test's ``when`` marker.

    The command is ``/usr/bin/env > <marker>`` (absolute ``env``; the redirect runs
    inside the hook's ``/bin/sh -c``). read_hook_env() then parses the PFB_* lines
    back. Matches the exact config shape pfb_get_hooks() reads — a flat
    ``{command, when, enabled, description, timeout}`` assoc array — so the entry
    runs (or is skipped) by the real production gate.
    """
    return {
        "command": f"/usr/bin/env > {hook_marker_path(token, when)}",
        "when": when,
        "enabled": enabled,
        "description": description or f"smoke {token} {when}",
        "timeout": timeout,
    }


# curl on pfSense (FreeBSD ports prefix) lives at /usr/local/bin/curl — the GUI/pkg
# download path uses it. The hook runs in HOST context (not chrooted), as root, so
# this absolute path is correct (CLAUDE.md: absolute binary paths, no $PATH).
GUEST_CURL = "/usr/local/bin/curl"


def webhook_hook(
    url: str,
    *,
    when: str = "post",
    guard: str = "IP",
    enabled: str = "on",
    timeout: str = "60",
    description: str = "",
) -> dict[str, str]:
    """A recipe-shaped ``post`` hook that POSTs the changed-alias context to ``url``.

    Mirrors the README webhook recipe's SHAPE (minus HAProxy): a guard on the
    NON-EMPTY ``PFB_CHANGED_*`` list for the side (``guard='IP'`` ⇒
    ``[ -n "$PFB_CHANGED_IP_ALIASES" ]``; ``'DNSBL'`` ⇒
    ``[ -n "$PFB_CHANGED_DNSBL_GROUPS" ]``), then a synchronous ``curl`` that forwards
    the four post-context fields. Each field goes through its OWN ``--data-urlencode``
    so the space-separated ``PFB_CHANGED_*`` lists (which may be empty) are URL-encoded
    — NEVER interpolated naked into the URL (a naked ``?ip=$VAR`` breaks on the
    embedded space). Default verb is POST ``application/x-www-form-urlencoded``,
    which the sink decodes with ``parse_qs`` on the body.

    GUARD = non-empty changed-list, NOT ``PFB_IP_CHANGED=1``: ``PFB_IP_CHANGED`` is a
    firewall-RULE-change signal (``$pfb['filter_configure']``) and stays ``0`` on a
    pure alias-CONTENT change (the ``pfctl -T replace`` else-branch, inc:11277, never
    sets it), even though the table changed and ``PFB_CHANGED_IP_ALIASES`` IS
    populated. Guarding on the rule flag would MISS the content-only reload — the exact
    "blocklist data changed" case a webhook wants — so the recipe (and this helper)
    keys off the non-empty changed-list, which tracks the genuinely-updated set on both
    sides. ``PFB_IP_CHANGED`` / ``PFB_DNSBL_CHANGED`` are still forwarded as payload.

    The command is POSIX-sh-safe (``[ … ] && curl …``): when the changed list is empty
    the ``&&`` short-circuits and ``curl`` never runs (so the sink gets no callback —
    the OFF branch). ``-sS`` keeps it quiet but surfaces errors; ``-m 5`` bounds it well
    under the per-hook ``timeout``.
    """
    guard_var = "PFB_CHANGED_IP_ALIASES" if guard == "IP" else "PFB_CHANGED_DNSBL_GROUPS"
    command = (
        f'[ -n "${guard_var}" ] && {GUEST_CURL} -sS -m 5 '
        '--data-urlencode "ip_aliases=$PFB_CHANGED_IP_ALIASES" '
        '--data-urlencode "dnsbl_groups=$PFB_CHANGED_DNSBL_GROUPS" '
        '--data-urlencode "ip_changed=$PFB_IP_CHANGED" '
        '--data-urlencode "dnsbl_changed=$PFB_DNSBL_CHANGED" '
        f"{url}"
    )
    return {
        "command": command,
        "when": when,
        "enabled": enabled,
        "description": description or f"smoke webhook {guard} {when}",
        "timeout": timeout,
    }


# Hook entries are stored under the 'row' listtag: config/0/hooks/row. A list
# stored DIRECTLY under the non-listtag <hooks> serializes to invalid <0> child
# tags that never round-trip through config.xml (see pfb_get_hooks()); 'row' is a
# pfSense listtag, so <hooks><row>...</row>...</hooks> parses back as a list for
# any count. clear deletes the parent <hooks> node entirely (UI's empty case).
CFG_HOOKS = CFG_GLOBAL + "/hooks"
CFG_HOOKS_ROW = CFG_HOOKS + "/row"


def set_update_hooks(vm: SmokeVM, hooks: list[dict[str, str]], *, timeout: float = 60.0) -> None:
    """Persist ``hooks`` as the pfBlockerNG update-hook list (CFG_GLOBAL/hooks/row).

    Writes the ``hooks/row`` SUBPATH directly (``config_set_path(.../hooks/row, …)``),
    matching the canonical UI save path (pfblockerng_hooks.php) byte-for-byte. Storing
    under the ``row`` listtag is what makes the list survive a config.xml round-trip:
    a list set straight under the non-listtag ``<hooks>`` dumps to numeric child tags
    (``<hooks><0>...</0></hooks>``) which are INVALID XML (a name can't start with a
    digit) and silently fail to reload — that was the live-smoke failure. ``row`` is a
    listtag, so ``<hooks><row>...</row>...</hooks>`` round-trips for 1..N rows. Each
    dict is emitted as a PHP assoc via _php_kv_array and the rows as a PLAIN NUMERIC
    array; only enabled==='on' + matching ``when`` + non-empty ``command`` entries
    actually run (inc gate).

    READ-BACK GUARD: after writing, reads ``hooks/row`` back and computes the effective
    hook count the SAME way pfb_get_hooks() does (a lone <row> stays a 1-element list
    because 'row' is a listtag; a flat single-hook collapse is wrapped). Raises with
    the raw persisted value if that count != len(hooks) — turning a silent non-persist
    into an early, precise failure. An empty list routes to clear_update_hooks()
    (config_del_path), so this guard runs only for >=1 hook.
    """
    if not hooks:
        clear_update_hooks(vm, timeout=timeout)
        return
    hooks_php = "array(" + ", ".join(_php_kv_array(h) for h in hooks) + ")"
    snippet = (
        f"config_set_path({_php_str(CFG_HOOKS_ROW)}, {hooks_php});\n"
        "write_config('pfBlockerNG smoke: set update hooks');\n"
        "echo 'OK';"
    )
    result = php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"set_update_hooks failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}")

    # Read back and count the way pfb_get_hooks() sees it (row listtag, with the same
    # single-assoc-collapse tolerance the inc applies defensively).
    pre = (
        f"$r = config_get_path({_php_str(CFG_HOOKS_ROW)}, array());\n"
        "if (isset($r['command']) || isset($r['when']) || isset($r['enabled'])) { $r = array($r); }\n"
        "$n = is_array($r) ? count($r) : -1;"
    )
    count = _php_read_scalar(vm, pre, "$n", timeout=timeout)
    if count != str(len(hooks)):
        raw = config_get(vm, CFG_HOOKS_ROW, timeout=timeout)
        raise RuntimeError(
            f"set_update_hooks: persisted hook count {count!r} != {len(hooks)} written; raw persisted value: {raw!r}"
        )


def clear_update_hooks(vm: SmokeVM, *, timeout: float = 60.0) -> None:
    """Delete CFG_GLOBAL/hooks so NO hook fires (no hooks node remains).

    Mirrors the UI's empty-list case (pfblockerng_hooks.php,
    ``config_del_path('installedpackages/pfblockerng/config/0/hooks')``) — deletes the
    whole <hooks> node (including its <row> children) so an "absent" assertion is
    clean. Call at the start of each hook test (so a stale hook can't false-green this
    one) and on teardown (so a leftover hook can't fire during another module's
    reloads). No hooks node ⇒ pfb_get_hooks() returns empty ⇒ a byte-identical no-op
    pass (inc:1783).
    """
    snippet = (
        f"config_del_path({_php_str(CFG_HOOKS)});\nwrite_config('pfBlockerNG smoke: clear update hooks');\necho 'OK';"
    )
    result = php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"clear_update_hooks failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}")


def clear_dnsbl_settings(vm: SmokeVM, *, timeout: float = 60.0) -> None:
    """Delete the whole CFG_DNSBL_SETTINGS node so DNSBL settings return to baseline.

    ``inject()`` MERGES into ``installedpackages/pfblockerngdnsblsettings/config/0``
    (``array_merge``, inc-side ``config_set_path``), so a setting one case turns on —
    ``pfb_regex`` + ``pfb_regex_list`` (user-regex), ``pfb_regex_cap``, ``pfb_cname``,
    and any IDN/pytld toggles — STAYS on for every later case/module, because a plain
    (non-regex) ``DnsblCase`` never sets those keys to clear them. ``reset()`` only does
    ``clearip``/``cleardnsbl`` + a forced update (it drops tables/sqlite, NOT config
    settings), so the toggle bleeds across modules: e.g. a leftover ``pfb_regex=on``
    rebuilds ``DNSBL_Regex`` and flips ``PFB_DNSBL_CHANGED`` on an unrelated module's
    reloads. Deleting the node (the UI "all-default" state) isolates modules; the next
    module's ``inject()`` rebuilds the settings it needs from scratch. Call from a
    MODULE FINALIZER of any module that enables non-default DNSBL settings.
    """
    snippet = (
        f"config_del_path({_php_str(CFG_DNSBL_SETTINGS)});\n"
        "write_config('pfBlockerNG smoke: clear DNSBL settings');\necho 'OK';"
    )
    result = php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"clear_dnsbl_settings failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}")


def clear_hook_markers(vm: SmokeVM, token: str, *, timeout: float = 30.0) -> None:
    """``rm -f`` every marker for ``token`` so an "absent" assertion is meaningful.

    Removes both the ``pre`` and ``post`` markers (and is harmless if neither
    exists). Run BEFORE the reload under test: asserting a marker is ABSENT only
    proves "the hook did not run" if the file was cleared first.
    """
    vm.ssh("/bin/rm", "-f", hook_marker_path(token, "pre"), hook_marker_path(token, "post"), timeout=timeout)


def hook_marker_exists(vm: SmokeVM, path: str, *, timeout: float = 30.0) -> bool:
    """True iff ``path`` exists on the guest (``test -f`` rc==0).

    The proof a hook ran (marker present) or did not (absent) — read off the host
    filesystem, since the hook writes there as root in host context.
    """
    return vm.ssh("test", "-f", path, timeout=timeout).returncode == 0


def read_hook_env(vm: SmokeVM, path: str, *, timeout: float = 30.0) -> dict[str, str] | None:
    """Parse a hook's env-dump marker into its ``PFB_*`` vars, or None if absent.

    ``cat`` the marker; a non-zero rc (file missing ⇒ the hook never ran) returns
    None so callers can distinguish "did not fire" from "fired with empty PFB_*".
    Only ``PFB_*`` lines are kept (the rest of root's env is noise); each is split
    on the FIRST ``=`` so an empty value (``PFB_CHANGED_DNSBL_GROUPS=``) parses to ''
    and a value containing ``=`` is preserved.
    """
    result = vm.ssh("cat", path, timeout=timeout)
    if result.returncode != 0:
        return None
    env: dict[str, str] = {}
    for line in result.stdout.splitlines():
        if not line.startswith("PFB_"):
            continue
        key, sep, value = line.partition("=")
        if sep:
            env[key] = value
    return env


# --------------------------------------------------------------------------- #
# Config injection — emit exactly the fields a case sets
# --------------------------------------------------------------------------- #


def _dnsbl_mode_settings(mode: DnsblMode) -> dict[str, str]:  # noqa: ARG001
    """Global-settings fields for a response mode.

    On ``next`` python mode is always on (pfblockerng.inc enforces it);
    ``dnsbl_mode`` / ``pfb_py_block`` are dead config keys.  The response
    shape (VIP vs null) is driven entirely by per-list ``logging`` —
    see ``_dnsbl_list_logging``.
    """
    return {}


def _dnsbl_list_logging(mode: DnsblMode) -> str:
    """Per-list ``logging`` value: 'disabled' → null 0.0.0.0; 'enabled' → VIP."""
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
        # suppression is a pfBlockerNG TEXTAREA field: config stores it base64-encoded
        # (GUI pfblockerng_dnsbl.php:555) and pfbng_text_area_decode() base64_decodes +
        # splits on CRLF. A PLAIN value here decodes to GARBAGE — so encode it.
        settings["suppression"] = _b64_textarea(spec.whitelist)
    if spec.dnsbl_ip_action:
        # The "DNSBL IP" firewall feature: collect IP literals from the DNSBL
        # feed into the pfB_DNSBLIP_{v4,v6} alias tables (inc:7022 reads this
        # from CFG_DNSBL_SETTINGS/action; != 'Disabled' enables it).
        settings["action"] = spec.dnsbl_ip_action
    if spec.user_regex:
        # The user "Python Regex List" (inc:849-850,2711). pfb_regex must be 'on' AND
        # pfb_regex_list non-empty for the [REGEX] ini section to be written. Like
        # suppression it is a base64 TEXTAREA field — a PLAIN value decodes to garbage
        # and crashes the ini load. User regex are sovereign block patterns (band 5).
        settings["pfb_regex"] = "on"
        settings["pfb_regex_list"] = _b64_textarea(spec.user_regex)
    if spec.regex_cap:
        # Opt-in static cap (inc:2685 -> ini regex_cap=on). Drops over-cap feed AND
        # user regex at load (pfb_unbound.py:_regex_exceeds_static_cap).
        settings["pfb_regex_cap"] = "on"
    if spec.cname_validation:
        # "CNAME Validation" (inc:852 -> ini python_cname). Walk a resolved answer's
        # CNAME chain and block the original name if a target is blocklisted.
        settings["pfb_cname"] = "on"
    if spec.hsts is not None:
        # "HSTS via Null Block mode" (inc:847 -> ini python_hsts). On: a VIP-mode
        # block on an HSTS-preload name is forced to NULL (pfb_unbound.py loads
        # pfb_py_hsts.txt -> hstsDB). Only emitted when the case sets it explicitly,
        # so the default matrix stays byte-for-byte unchanged. See add_hsts_name.
        settings["pfb_hsts"] = "on" if spec.hsts else "off"
    # The primary feed row + any ABP extra rows, all in ONE DNSBL list group. Each
    # row is downloaded + header-sniffed independently (inc:7934), so an ABP body
    # per row yields one ABP feed per row whose rules the Python build merges.
    rows = [{"header": spec.header, "url": spec.feed_url, "state": "Enabled", "format": "auto"}]
    rows += [{"header": hdr, "url": url, "state": "Enabled", "format": "auto"} for (hdr, url) in spec.extra_rows]
    rows_php = "array(" + ", ".join(_php_kv_array(r) for r in rows) + ")"
    listcfg = {
        "aliasname": spec.aliasname,
        # A DNSBL group's action MUST be 'unbound' — that's the only value
        # pfb_determine_list_detail maps to the DNSBL folder (dnsdir/dnsorigdir).
        # "Enabled" passes the != 'Disabled' gate but yields an empty $pfbarr, so
        # the feed silently writes nowhere -> 0 domains (empty blocklist).
        "action": "unbound",
        "cron": "EveryDay",
        "order": "primary",
    }
    # The DNSBL Group Custom_List: a base64 'custom' field (CRLF-joined domains, the
    # exact shape pfbng_text_area_decode expects, inc:1120). A non-empty 'custom'
    # makes pfBlockerNG auto-generate the sovereign '{aliasname}_custom' row.
    custom_line = ""
    if spec.custom_domains:
        crlf = "\r\n".join(spec.custom_domains)
        custom_line = f"$list['custom'] = base64_encode({_php_str(crlf)});\n"
    return (
        # pfBlockerNG must be globally enabled for the DNSBL (and DNSBL-IP)
        # paths to run (inc:793 reads enable_cb; inc:3389/9307 gate on it).
        f"$g = config_get_path({_php_str(CFG_GLOBAL)}, array());\n"
        "$g['enable_cb'] = 'on';\n"
        f"config_set_path({_php_str(CFG_GLOBAL)}, $g);\n"
        f"$s = config_get_path({_php_str(CFG_DNSBL_SETTINGS)}, array());\n"
        f"$s = array_merge($s, {_php_kv_array(settings)});\n"
        f"config_set_path({_php_str(CFG_DNSBL_SETTINGS)}, $s);\n"
        f"$list = {_php_kv_array(listcfg)};\n"
        f"$list['row'] = {rows_php};\n"
        # 'logging' is a per-LIST field — pfBlockerNG reads $list['logging']
        # (inc: 'if ($list[\\'logging\\'] == \\'disabled\\')'), NOT a per-row value.
        # 'disabled' -> logging_type 2 -> null 0.0.0.0; else -> VIP.
        f"$list['logging'] = {_php_str(_dnsbl_list_logging(spec.mode))};\n"
        f"{custom_line}"
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
    # The IP deny rule is built per inbound/outbound interface; with none
    # configured pfBlockerNG logs "Inbound interface option not configured" and
    # builds the alias table but NO rule (inc:10132). The wizard sets these — so
    # the harness must too (a Deny_Both case needs both directions).
    ipset = {"inbound_interface": SMOKE_IP_IFACE, "outbound_interface": SMOKE_IP_IFACE}
    return (
        # pfBlockerNG must be globally enabled for the IP path to build the
        # alias table + rule (inc:793 enable_cb).
        f"$g = config_get_path({_php_str(CFG_GLOBAL)}, array());\n"
        "$g['enable_cb'] = 'on';\n"
        f"config_set_path({_php_str(CFG_GLOBAL)}, $g);\n"
        f"$ip = config_get_path({_php_str(CFG_IP_SETTINGS)}, array());\n"
        f"$ip = array_merge($ip, {_php_kv_array(ipset)});\n"
        f"config_set_path({_php_str(CFG_IP_SETTINGS)}, $ip);\n"
        f"$list = {_php_kv_array(listcfg)};\n"
        f"$list['row'] = array({_php_kv_array(row)});\n"
        f"config_set_path({_php_str(root)}, array($list));\n"
        "write_config('pfBlockerNG smoke: IP case');\n"
        "echo 'OK';"
    )


# --------------------------------------------------------------------------- #
# Reload / reset — the PHP CLI cron verbs (no wrapper)
# --------------------------------------------------------------------------- #


def reload(vm: SmokeVM, scope: str = "update", *, data_path: bool = False, timeout: float = 600.0) -> None:
    """Run a pfBlockerNG reload via the PHP CLI cron verb.

    ``scope`` is the verb: ``updatednsbl`` / ``updateip`` (targeted, faster per
    case) or ``update`` (full force, IP+DNSBL).

    READINESS depends on whether a restart is expected (ADR-10):

    * ``data_path=False`` (default — keeps every existing caller byte-identical): treat
      this as a RESTART-class reload and wait on ``wait_unbound_ready`` (poll
      ``unbound-control status``). This is correct for IP-only updates, config-changing
      updates, and the conservative default; a python-mode data update that happens to
      take the no-restart swap still leaves Unbound up, so the status poll is satisfied
      either way (it just doesn't PROVE no-restart).
    * ``data_path=True``: this is a pure DNSBL-DATA update in python mode that the package
      routes through the ADR-10 zero-downtime fast path — ``pfb_update_unbound`` calls
      ``pfb_reload_unbound($mode, TRUE, $pfbpython, !$pfbpython)`` (inc:4151), so a
      config-clean feed/cron update flips the sentinel and swaps with NO restart. We
      capture the fast-path log baseline BEFORE the verb runs and afterwards wait on
      :func:`wait_zero_downtime_swap` (the swap-applied signal). The caller is asserting
      the no-restart invariant (pid unchanged), so use this only when a config-clean
      python-mode DNSBL data update is expected; it RAISES if the swap line never appears.
    """
    if scope not in ("update", "updateip", "updatednsbl"):
        raise ValueError(f"reload scope must be update/updateip/updatednsbl, got {scope!r}")
    swap_before = count_log_marker(vm, PFB_LOG, SWAP_LOG_MARKER) if data_path else 0
    deadline = time.monotonic() + timeout
    result = vm.ssh(PHP_BIN, PFB_CLI, scope, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(f"reload({scope}) failed: rc={result.returncode} stderr={result.stderr!r}")
    if data_path:
        # Forward the caller's remaining budget so a slow box honours `timeout` instead
        # of wait_zero_downtime_swap's shorter default.
        wait_zero_downtime_swap(vm, since=swap_before, timeout=max(1.0, deadline - time.monotonic()))
    else:
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


UNBOUND_CONF = "/var/unbound/unbound.conf"
UNBOUND_BEFORE = "/tmp/pfb_unbound_before.conf"
# Snapshot of the EFFECTIVE unbound config (unbound.conf + every file it pulls in
# via `include:`) captured before any DNSBL reload; assert_unbound_adds_only_
# python_config diffs the post-reload effective config against it. unbound.conf
# alone is NOT enough: pfSense splits config across includes (access_lists.conf =
# the DNS Resolver ACLs, host_entries.conf, domainoverrides.conf, remotecontrol.conf).
UNBOUND_SETUP = "/tmp/pfb_unbound_setup.conf"
# Dump the whole resolver config the daemon loads by FOLLOWING the actual
# `include:` directives from unbound.conf (recursively), rather than assuming a
# fixed `*.conf` glob — so an include outside /var/unbound, a non-.conf name, a
# glob include, or a nested include is still covered. Handles quoted/unquoted and
# glob targets; `echo` between files guards a missing trailing newline.
# `for inc in $pat` is UNQUOTED ON PURPOSE — word-splitting is what expands an
# `include:` glob (e.g. `/var/unbound/*.conf`). pfSense/Unbound include paths
# never contain whitespace, and this is read-only diagnostic code, so the
# split-on-spaces tradeoff is safe here.
UNBOUND_EFFECTIVE_CMD = (
    '_dump() { cat "$1" 2>/dev/null; '
    "awk '/^[[:space:]]*include:/{print $2}' \"$1\" 2>/dev/null | tr -d '\"' | "
    'while read -r pat; do for inc in $pat; do [ -f "$inc" ] && { echo; _dump "$inc"; }; done; done; }; '
    "_dump /var/unbound/unbound.conf"
)
CONFIG_XML = "/conf/config.xml"
# Per-step state snapshots: config.xml + unbound.conf are copied here at each
# harness step so dump_diagnostics can diff consecutive states and show EXACTLY
# what each step (deploy / VIP inject / case inject / each reload) changes — full
# visibility instead of inference. Gated by SMOKE_STATE_DIFF to keep normal runs
# lean. See snap_state / dump_state_diffs.
SNAP_DIR = "/tmp/pfb_snap"
_snap_seq = 0


def snapshot_unbound_conf(vm: SmokeVM, *, timeout: float = 30.0) -> None:
    """Snapshot the DNSBL-OFF unbound.conf so a later diff shows what DNSBL changed.

    Captured right after deploy (before any DNSBL reload); dump_diagnostics diffs
    it against the live unbound.conf to reveal EXACTLY what pfBlockerNG's DNSBL
    reload adds/removes — including whether it drops custom access-control.
    """
    vm.ssh("cp", UNBOUND_CONF, UNBOUND_BEFORE, timeout=timeout)


PFB_LOGDIR = "/var/log/pfblockerng"


def snap_state(vm: SmokeVM, tag: str, *, timeout: float = 30.0) -> None:
    """Snapshot full state into SNAP_DIR/<NN>_<tag>/ (best-effort).

    Captures config.xml, unbound.conf AND every pfBlockerNG log file
    (/var/log/pfblockerng/*) so dump_state_diffs can recursively diff consecutive
    steps — showing config/unbound changes AND each log's appended lines (incl.
    py_error.log for python-mode failures). No-op unless SMOKE_STATE_DIFF is set.
    """
    if not os.environ.get("SMOKE_STATE_DIFF"):
        return
    global _snap_seq
    dest = f"{SNAP_DIR}/{_snap_seq:02d}_{tag}"
    _snap_seq += 1
    # Files + every pfBlockerNG log + live runtime state (firewall rules/NAT/
    # tables, interface aliases incl. the DNSBL VIP, :53 listeners). All land in
    # one per-step dir so the recursive diff shows every change at each step.
    cmd = (
        f"/bin/mkdir -p {dest} && "
        f"cp {CONFIG_XML} {dest}/config.xml 2>/dev/null; "
        f"cp {UNBOUND_CONF} {dest}/unbound.conf 2>/dev/null; "
        # The DNSBL python ini (python_blocking flag the module reads) + the
        # unbound-mode block file (local-zone/local-data) + the python blocklist.
        f"cp /var/unbound/pfb_unbound.ini {dest}/ 2>/dev/null; "
        f"cp /var/unbound/pfb_dnsbl.conf {dest}/ 2>/dev/null; "
        f"cp /var/unbound/pfb_py_data.txt {dest}/ 2>/dev/null; "
        f"cp -p {PFB_LOGDIR}/* {dest}/ 2>/dev/null; "
        f"/sbin/pfctl -sr  > {dest}/pf_rules.txt   2>/dev/null; "
        f"/sbin/pfctl -sn  > {dest}/pf_nat.txt     2>/dev/null; "
        f"/sbin/pfctl -sTables > {dest}/pf_tables.txt 2>/dev/null; "
        f"/sbin/ifconfig > {dest}/ifconfig.txt 2>/dev/null; "
        f"/usr/bin/sockstat | /usr/bin/grep -E ':53|unbound|lighttpd' > {dest}/sockets.txt 2>/dev/null; "
        "true"
    )
    vm.ssh(cmd, timeout=timeout)


def dump_state_diffs(vm: SmokeVM, *, timeout: float = 120.0) -> None:
    """Recursively diff consecutive per-step snapshot dirs (config + unbound + logs)."""
    if not os.environ.get("SMOKE_STATE_DIFF"):
        return
    print("\n========== PER-STEP STATE DIFFS (config + unbound + logs) ==========")
    cmd = (
        f"cd {SNAP_DIR} 2>/dev/null || exit 0; prev=''; "
        f"for d in $(ls -d */ 2>/dev/null | sort); do "
        f'  if [ -n "$prev" ]; then echo "########## ${{prev%/}} -> ${{d%/}} ##########"; '
        f'  diff -ruN "$prev" "$d" 2>/dev/null | head -150; fi; prev="$d"; done'
    )
    try:
        result = vm.ssh(cmd, timeout=timeout)
        print(result.stdout + result.stderr)
    except Exception as exc:  # noqa: BLE001
        print(f"state diffs failed: {exc}")
    print("========== END PER-STEP STATE DIFFS ==========\n")


def snapshot_unbound_effective(vm: SmokeVM, dest: str = UNBOUND_SETUP, *, timeout: float = 30.0) -> None:
    """Snapshot the EFFECTIVE unbound config (unbound.conf + every *.conf include).

    Capture this BEFORE a DNSBL reload so assert_unbound_adds_only_python_config
    can diff the post-reload effective config against it. Reading unbound.conf
    alone misses the ACLs (they live in the included access_lists.conf).
    """
    vm.ssh("/bin/sh", "-c", f"{UNBOUND_EFFECTIVE_CMD} > {dest}", timeout=timeout)


def unbound_access_control(vm: SmokeVM, *, timeout: float = 30.0) -> set[str]:
    """The ACLs the RUNNING daemon actually enforces, via ``unbound-control``.

    This is the authoritative source (includes resolved, live state) — not a
    grep of one generated file. Returns the normalised set of access-control
    entries (e.g. ``{"10.0.2.0/24 allow", ...}``).
    """
    result = vm.ssh(
        "/usr/local/sbin/unbound-control",
        "-c",
        UNBOUND_CONF,
        "get_option",
        "access-control",
        timeout=timeout,
    )
    return {ln.strip() for ln in result.stdout.splitlines() if ln.strip()}


def assert_unbound_adds_only_python_config(vm: SmokeVM, *, timeout: float = 30.0) -> None:
    """Assert a DNSBL reload only adds python-module config to the EFFECTIVE config.

    Compares ``UNBOUND_SETUP`` (the effective config — unbound.conf + all *.conf
    includes — captured by snapshot_unbound_effective BEFORE the DNSBL reload)
    against the current effective config. Reading the full include set is the
    point: the DNS Resolver ACLs live in access_lists.conf, host overrides in
    host_entries.conf, etc. — diffing unbound.conf alone would miss a dropped ACL.

    1. **Nothing removed except module-config**: pfBlockerNG legitimately replaces
       ``module-config: "iterator"`` with ``module-config: "python iterator"``.
       Everything else (access-control, forward-zones, host entries, server
       tuning) must be preserved.
    2. **Only python additions**: added lines must be python module directives,
       includes of pfBlockerNG-managed files, or the DNSBL VIP ``interface:`` entry.
    """
    setup_result = vm.ssh("cat", UNBOUND_SETUP, timeout=timeout)
    current_result = vm.ssh("/bin/sh", "-c", UNBOUND_EFFECTIVE_CMD, timeout=timeout)
    if setup_result.returncode != 0 or not setup_result.stdout:
        # No baseline => snapshot_unbound_effective() wasn't called before the
        # DNSBL reload (a test-setup bug). Make it LOUD rather than silently
        # "passing" — a missing baseline must never read as immutability proven.
        print(
            "[smoke] WARNING: assert_unbound_adds_only_python_config skipped — "
            f"baseline {UNBOUND_SETUP} missing (snapshot_unbound_effective not called?)"
        )
        return
    setup_lines = {ln.strip() for ln in setup_result.stdout.splitlines() if ln.strip()}
    current_lines = {ln.strip() for ln in current_result.stdout.splitlines() if ln.strip()}

    # module-config is legitimately REPLACED (iterator → python iterator).
    removed = {ln for ln in (setup_lines - current_lines) if "module-config" not in ln.lower()}
    assert not removed, (
        f"pfBlockerNG DNSBL reload REMOVED lines from the effective unbound config "
        f"(access-control / forward-zone / host entries / server config must be preserved): {sorted(removed)}"
    )

    added = current_lines - setup_lines

    # Allow: python module directives, pfBlockerNG managed includes, VIP interface.
    def _is_allowed(line: str) -> bool:
        low = line.lower()
        return (
            "python" in low
            or "module-config" in low
            or ("include:" in low and "pfb" in low)
            or (low.startswith("interface:") and DEFAULT_DNSBL_VIP4 in low)
        )

    unexpected = [ln for ln in added if not _is_allowed(ln)]
    assert not unexpected, (
        f"pfBlockerNG DNSBL reload made unexpected changes to the effective unbound config "
        f"(only python-module config is allowed): {sorted(unexpected)}"
    )


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
# ADR-10 zero-downtime swap — no-restart readiness + invariants
# --------------------------------------------------------------------------- #
# The ADR-04 readiness model ("first response is authoritative, never loop") rests
# on the RESTART era: after a reload Unbound went down and back up, so the first
# answer post-readiness was the new decision. The ADR-10 swap is ASYNC and never
# restarts — PHP flips a generation sentinel (/var/unbound/pfb_py_reload), the
# in-module watcher rebuilds + atomically swaps the snapshot a moment later, "briefly
# stale by design" (ADR.md SS2). So a no-restart data update needs two different
# primitives: (1) wait for the swap to APPLY (the fast-path log line appears), and
# (2) poll the decision until it flips within a bounded window. The Unbound pid is the
# hard no-restart proof: UNCHANGED across a data update, CHANGED across a config one.

UNBOUND_PID_FILE = "/var/run/unbound.pid"
# The pfBlockerNG main log; PHP's pfb_reload_unbound writes the fast-path markers here
# (inc:3956 "[ zero-downtime swap ]" then inc:3962 " completed [ NOW ]"). Their
# appearance proves the no-restart data path was TAKEN (vs the restart fallback).
PFB_LOG = f"{PFB_LOGDIR}/pfblockerng.log"
# The Python module's stderr is redirected here (pfb_unbound.py:590); a FAILED build
# (bad/partial manifest) writes "Failed to load DNSBL manifest" / "DNSBL rebuild
# failed, keeping current snapshot" here — the fail-closed signal.
PY_ERROR_LOG = f"{PFB_LOGDIR}/py_error.log"
# The fast-path swap marker PHP logs when the no-restart path is TAKEN: inc:3956 writes
# "Reloading Unbound Resolver (DNSBL python) [ zero-downtime swap ]". Match the BRACKETED
# form specifically — the RAM-decline RESTART-fallback line (inc:3974) also contains the
# bare phrase "the zero-downtime swap", so matching the unbracketed substring would
# false-positive on a fallback (restart) as if the swap had been taken.
SWAP_LOG_MARKER = "[ zero-downtime swap ]"


def unbound_pid(vm: SmokeVM, *, timeout: float = 30.0) -> int:
    """Return Unbound's current pid from /var/run/unbound.pid (raises if absent/bad).

    The hard no-restart proof for ADR-10: capture it before a data update and assert
    it is UNCHANGED after (the swap reuses the running process); across a CONFIG
    change it CHANGES (pfb_stop_start_unbound restarts the daemon). Reading the pid
    file is exactly what the ADR §7 smoke checklist tracks (``cat /var/run/unbound.pid``).
    """
    result = vm.ssh("cat", UNBOUND_PID_FILE, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(f"unbound_pid: cannot read {UNBOUND_PID_FILE}: rc={result.returncode} {result.stderr!r}")
    text = result.stdout.strip()
    try:
        return int(text)
    except ValueError as exc:
        raise RuntimeError(f"unbound_pid: {UNBOUND_PID_FILE} not an integer: {text!r}") from exc


def count_log_marker(vm: SmokeVM, path: str, marker: str, *, timeout: float = 30.0) -> int:
    """Count lines in the file ``path`` on the guest that CONTAIN ``marker``.

    Capture this BEFORE a no-restart data update and pass the value as ``since`` to
    :func:`wait_zero_downtime_swap`: a NEW matching line (count strictly greater than
    the captured baseline) proves the swap log line was appended AFTER the trigger,
    not left over from an earlier reload. ``grep -Fc`` does a fixed-string (non-regex)
    count; a missing file / no match yields 0 (grep exits non-zero) — never raises.
    """
    # Count OCCURRENCES, not matching lines: the Python module writes its failure strings
    # to py_error.log via sys.stderr.write WITHOUT a trailing newline (pfb_unbound.py:3679),
    # so two failures can share a physical line — `grep -c` (line count) would under-count
    # them. `grep -Fo` prints one line per match; `wc -l` counts those. Run as ONE shell
    # string (the guest login shell handles the pipe); a missing file / no match -> 0.
    quoted_marker = shlex.quote(marker)
    quoted_path = shlex.quote(path)
    cmd = f"/usr/bin/grep -Fo {quoted_marker} {quoted_path} 2>/dev/null | /usr/bin/wc -l"
    result = vm.ssh(cmd, timeout=timeout)
    text = result.stdout.strip()
    try:
        return int(text)
    except ValueError:
        return 0


def wait_zero_downtime_swap(vm: SmokeVM, *, since: int, timeout: float = 60.0, interval: float = 2.0) -> None:
    """Block until a NEW fast-path swap line appears in the pfBlockerNG log (no restart).

    ``since`` is the :func:`count_log_marker` count of ``SWAP_LOG_MARKER`` captured
    BEFORE the trigger. This proves the ZERO-DOWNTIME DATA FAST PATH ran: PHP's
    ``pfb_reload_unbound`` logs ``"...[ zero-downtime swap ]"`` (inc:3956) only when it
    publishes the manifest + flips the sentinel WITHOUT ``pfb_stop_start_unbound`` —
    i.e. no Unbound restart. If instead it took the restart fallback (config change,
    RAM-gate decline, sentinel-flip failure) this line is NOT written and the wait
    raises on timeout — surfacing "the swap did not apply", never masking it.

    NOTE: this confirms the PHP fast path was TAKEN (the all-or-nothing publish + flip);
    the watcher's own ``log_info("...reloaded with no restart (zero-downtime swap)")``
    (pfb_unbound.py:422) goes to Unbound's resolver log and proves the snapshot was
    APPLIED, but its path is not hard-depended on here — the decision-flip is asserted
    separately via :func:`dns_probe_until`.
    """
    deadline = time.time() + timeout
    last = since
    while time.time() < deadline:
        last = count_log_marker(vm, PFB_LOG, SWAP_LOG_MARKER)
        if last > since:
            return
        time.sleep(interval)
    raise RuntimeError(
        f"wait_zero_downtime_swap timed out after {timeout}s: no new '{SWAP_LOG_MARKER}' line in {PFB_LOG} "
        f"(baseline count {since}, last seen {last}) — the no-restart data fast path did not run "
        f"(restart fallback taken, or the trigger never reached pfb_reload_unbound's data path?)"
    )


def flush_unbound_name(vm: SmokeVM, name: str, *, timeout: float = 30.0) -> None:
    """Flush a SINGLE name from Unbound's C message cache (``unbound-control flush <name>``).

    The targeted analog of :func:`flush_unbound_cache`. ADR-10 only flushes the
    allow->block delta where it is cheaply known (the #51 alerts paths — one domain);
    a feed/cron allow->block is TTL-bounded by design (the prior resolved answer serves
    until its TTL — RESULTS/05 SS3, explicitly NOT a regression vs today's restart,
    which preserves the resolved cache too). A test that pre-resolved such a name (to
    assert the before-state) then lists it must clear that one cached real answer to
    OBSERVE the swapped block within the test window — mirroring exactly what a #51
    Lock's targeted delta-flush does on the box.
    """
    result = vm.ssh("/usr/local/sbin/unbound-control", "-c", UNBOUND_CONF, "flush", name, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(f"flush_unbound_name({name}) failed: rc={result.returncode} {result.stderr!r}")


def force_dnsbl_refetch(vm: SmokeVM, header: str, *, timeout: float = 30.0) -> None:
    """Force pfBlockerNG to RE-INGEST a feed whose local source file was edited mid-case.

    pfBlockerNG caches each feed's parsed output at ``{dnsdir}/{header}.txt`` and, on an
    ``update``, REUSES that cache (skips the re-fetch) when the ``.txt`` exists and no
    per-feed ``.update`` marker is present (inc:8884). A test that rewrites the local feed
    fixture in place (``write_local_feed``) therefore would NOT see the edit applied by a
    plain ``update`` — the manifest is never rewritten, so no zero-downtime swap fires.
    Touching the ``{dnsdir}/{header}.update`` marker makes the next ``update`` re-read the
    edited source into the manifest (a pure DATA change -> the no-restart swap fork), which
    is what a live box does when the cron download detects the feed changed.
    """
    marker = f"{PFB_DBDIR}/dnsbl/{header}.update"
    result = vm.ssh("/usr/bin/touch", marker, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(f"force_dnsbl_refetch({header}) failed: rc={result.returncode} {result.stderr!r}")


def force_ip_refetch(vm: SmokeVM, header: str, *, timeout: float = 30.0) -> None:
    """Force pfBlockerNG to RE-INGEST an IP feed whose local source was edited mid-case.

    The IP side caches each feed's downloaded copy at ``{denydir}/{header}.txt`` and, on
    an ``update``, REUSES that cache (logs ``exists``, skips the re-parse) when the
    ``.txt`` exists, no per-feed ``.update``/``.fail`` marker is present, and ``$pfbreuse``
    is empty (inc:10211-10222). Crucially this holds even for a FULL ``update`` (the
    ``cron`` verb leaves ``$pfb['reuse']`` at its default empty), so a test that merely
    rewrites the local feed fixture (``write_local_feed``) would NOT see the edit
    re-parsed — the feed's alias is never appended to ``$pfb_alias_lists`` and so never
    reaches ``PFB_CHANGED_IP_ALIASES``. Touching ``{denydir}/{header}.update`` defeats the
    reuse gate, forcing the next ``update`` down the re-download/re-parse fork (inc:10223+)
    so the genuinely-changed feed populates the changed-IP-alias set — the IP-side
    equivalent of ``force_dnsbl_refetch``.

    NOTE on ``header``: the IP loop names each on-disk feed file ``{row.header}{vtype}``
    (vtype = ``_v4`` / ``_v6``; inc:10126), so an IPv4 ``IpCase(header='x')`` writes
    ``x_v4.txt`` / ``x_v4.update``. Pass the FULL on-disk header INCLUDING the family
    suffix (e.g. ``f"{spec.header}_v4"``), not the bare ``IpCase.header``. (DNSBL feed
    files carry no vtype suffix, so ``force_dnsbl_refetch`` takes the bare header.)
    """
    marker = f"{PFB_DBDIR}/deny/{header}.update"
    result = vm.ssh("/usr/bin/touch", marker, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(f"force_ip_refetch({header}) failed: rc={result.returncode} {result.stderr!r}")


def dnsbl_alert_lock_toggle(vm: SmokeVM, domain: str, action: str, *, timeout: float = 300.0) -> None:
    """Drive the alerts-page temporary Lock/Unlock for a DNSBL ``domain`` (#51).

    The per-alert temporary Unlock/Lock has NO CLI verb — it is the
    ``pfblockerng_alerts.php`` ``dnsbl_remove`` web handler. In python mode that handler
    toggles the ``pfb_unlock`` state store (``$pfb['dnsbl_unlock']``), regenerates the
    manifest's ``config.user_unlock`` (a band-6 whiteDB allow), then reloads Unbound. We
    replay that EXACT production sequence over ``pfSsh.php`` (the fully-bootstrapped
    pfSense shell) with ``pfblockerng.inc`` loaded — driving the SAME functions the
    handler calls, so the smoke test exercises the real #51 path end-to-end.

    ZERO-DOWNTIME (ADR-10, #51): the handler reloads via the data fast path — it computes
    the allow->block delta exactly as the page does (``$newly_blocked = ($ua['mode'] ===
    'lock') ? array($domain) : array()``) and calls ``pfb_reload_unbound('enabled', FALSE,
    FALSE, TRUE, $newly_blocked)`` (alerts.php:1410-1411). ``$datapath=TRUE`` routes a #51
    custom-list edit through the no-restart swap: PHP publishes the patched manifest, flips
    the generation sentinel, and (for a Lock) targeted-flushes that one name from the
    C-cache — Unbound's pid is UNCHANGED. So the helper waits on the SWAP-APPLIED signal
    (the fast-path log line), NOT on a restart. The old unlock-only cache flush is gone:
    block->allow (Unlock) is immediate since #43 stopped C-caching blocks, and a Lock's
    prior resolved answer is cleared by the production targeted delta-flush inside
    ``pfb_reload_unbound`` itself — no belt-and-suspenders flush is needed here.

    ``action`` is one of the four icon labels: ``'unlock'`` / ``'relock'`` (temporarily
    allow — ADD to the store, block->allow) or ``'lock'`` / ``'reunlock'`` (re-block —
    REMOVE, allow->block). The action -> store-mode mapping is resolved on-box by the SAME
    production helper the handler uses (``pfb_dnsbl_unlock_action``), so this exercises the
    real dispatch, not a copy. On return the no-restart swap has been applied.
    """
    if action not in ("unlock", "lock", "relock", "reunlock"):
        raise ValueError(f"action must be one of unlock/lock/relock/reunlock, got {action!r}")
    # Capture the fast-path log baseline BEFORE the toggle so wait_zero_downtime_swap can
    # detect the NEW swap line (proving the no-restart path ran, not a stale prior line).
    swap_before = count_log_marker(vm, PFB_LOG, SWAP_LOG_MARKER)
    # Mirror the handler exactly: resolve the action -> store-mode via the production
    # pfb_dnsbl_unlock_action(), read the store, toggle it, regenerate user_unlock, then
    # reload through the ADR-10 data fast path with the allow->block delta. pfb_global()
    # populates $pfb (paths + config) as the page/CLI bootstrap.
    snippet = (
        "require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');\n"
        "pfb_global();\n"
        f"$ua = pfb_dnsbl_unlock_action({_php_str(action)});\n"
        "$u = pfb_unlock('read', 'dnsbl', '', '', '');\n"
        f"pfb_unlock($ua['mode'], 'dnsbl', {_php_str(domain)}, 'python', $u);\n"
        "pfb_unbound_python_sources_unlock();\n"
        f"$newly_blocked = ($ua['mode'] === 'lock') ? array({_php_str(domain)}) : array();\n"
        "pfb_reload_unbound('enabled', FALSE, FALSE, TRUE, $newly_blocked);\n"
        "echo 'OK';"
    )
    deadline = time.monotonic() + timeout
    result = php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(
            f"dnsbl_alert_lock_toggle({domain}, {action}) failed: "
            f"rc={result.returncode} {result.stderr!r} {result.stdout!r}"
        )
    # No restart — wait on the SWAP-APPLIED signal (fast-path log line), not unbound
    # readiness. Unbound never goes down, so the swap lands a moment after the flip.
    # Forward the caller's remaining budget (not the helper's shorter default).
    wait_zero_downtime_swap(vm, since=swap_before, timeout=max(1.0, deadline - time.monotonic()))


def flush_unbound_cache(vm: SmokeVM, *, timeout: float = 30.0) -> None:
    """Flush Unbound's whole cache so the NEXT probe is evaluated FRESH by the module.

    Unbound answers a message-cache HIT directly, AHEAD of the pfBlockerNG python
    module — so a name cached as a side effect of an earlier query is served from
    cache and skips the DNSBL block check. This bites the CNAME case: resolving the
    SOURCE (A→CNAME→B) caches B's chained A record, so a later DIRECT query for B is
    served that cached value instead of being blocked. Flush between such probes to
    keep each one independent. (``flush_zone .`` drops every cached name.)
    """
    result = vm.ssh("/usr/local/sbin/unbound-control", "-c", UNBOUND_CONF, "flush_zone", ".", timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(f"flush_unbound_cache failed: rc={result.returncode} {result.stderr!r}")


# --------------------------------------------------------------------------- #
# DNS probe + assert helpers (rcode/record shapes)
# --------------------------------------------------------------------------- #


@dataclass
class DnsAnswer:
    """A resolved DNS answer: rcode name + the A/AAAA records returned."""

    rcode: str
    records: list[str]


DRILL_BIN = "/usr/local/bin/drill"


def _parse_drill(output: str, rtype: str) -> DnsAnswer:
    """Parse ``drill`` text output into an rcode + the records of ``rtype``."""
    rcode = "UNKNOWN"
    records: list[str] = []
    in_answer = False
    for line in output.splitlines():
        if "rcode:" in line:
            m = re.search(r"rcode:\s*([A-Z]+)", line)
            if m:
                rcode = m.group(1)
        if line.startswith(";; ANSWER SECTION"):
            in_answer = True
            continue
        if in_answer:
            stripped = line.strip()
            if not stripped or line.startswith(";;"):
                in_answer = False
                continue
            # "<name>. <ttl> IN <type> <rdata>"
            parts = stripped.split()
            if len(parts) >= 5 and parts[3] == rtype:
                records.append(parts[4])
    return DnsAnswer(rcode=rcode, records=records)


def dns_probe(
    vm: SmokeVM, name: str, rtype: str = "A", *, timeout: float = 30.0, attempts: int = 3, delay: float = 5.0
) -> DnsAnswer:
    """Resolve (name, rtype) ON the guest via ``drill <name> <rtype> @127.0.0.1`` over SSH.

    Verified on a live box: python-mode DNSBL has **no localhost exemption** — a
    blocked domain returns its block shape (VIP / NULL) even for a 127.0.0.1-sourced
    query. So the on-box query is sufficient AND avoids the QEMU SLIRP WAN-hostfwd
    path (which, unlike a real LAN client, does not get answered in CI — that path,
    not Unbound being slow, is what produced the earlier transport TIMEOUTs).

    Caller MUST use a non-RFC-6761, non-HSTS-preload domain (see ``unique_domain``):
    Unbound's built-in ``local-zone``s for ``.test`` / ``.example`` / etc. shadow
    those names (NXDOMAIN/NODATA) before DNSBL, and HSTS-preload names flip a VIP
    block to NULL when HSTS is on (the default).

    Probe semantics (load-bearing): the caller has already waited for Unbound to be
    ready after the reload (``reload`` -> ``wait_unbound_ready``). The FIRST parsed
    DNS response is therefore authoritative — whatever Unbound returns is the real
    answer, so we return it and let the caller assert/error on it. We do NOT re-query
    hoping the answer becomes the expected value (that could loop forever). The only
    retry is a short settle for the window where ``drill`` got NO DNS response at all
    (e.g. queried during the restart) — bounded at ``attempts`` x ``delay`` (~5s).
    """
    cmd = f"{DRILL_BIN} {shlex.quote(name)} {shlex.quote(rtype)} @127.0.0.1"
    last = ""
    for attempt in range(attempts):
        result = vm.ssh(cmd, timeout=timeout)
        if "rcode:" in result.stdout:
            # A DNS response came back -> it IS Unbound's answer. Return it as-is;
            # the caller asserts the shape. Never loop for a "better" answer.
            return _parse_drill(result.stdout, rtype)
        # No DNS response at all (drill produced no rcode) — only here do we wait +
        # retry, to ride out the brief post-restart window.
        last = f"rc={result.returncode} stdout={result.stdout!r} stderr={result.stderr!r}"
        if attempt < attempts - 1:
            time.sleep(delay)
    raise RuntimeError(f"dns_probe({name}, {rtype}) got no drill answer after {attempts} attempts: {last}")


def dns_probe_until(
    vm: SmokeVM,
    name: str,
    predicate: Callable[[DnsAnswer], bool],
    rtype: str = "A",
    *,
    timeout: float = 60.0,
    interval: float = 3.0,
) -> DnsAnswer:
    """Poll ``drill <name> <rtype> @127.0.0.1`` until ``predicate(answer)`` holds; raise on timeout.

    The ZERO-DOWNTIME analog of :func:`dns_probe`'s authoritative single-shot. ADR-10's
    swap is ASYNC: after a data update Unbound never restarts and the new decision lands a
    moment later (the watcher rebuilds + atomically swaps the snapshot once the sentinel
    advances — "briefly stale by design", ADR.md SS2). So the restart-era "first response
    is authoritative, never loop" rule does NOT apply to the swap transition: there is no
    down/up edge to make the first post-readiness answer the new one. The guarantee under
    test is "the new decision applies within a BOUNDED window WITHOUT a restart" — so we
    poll until it does, and RAISE on timeout (a real failure: the swap did not apply in
    budget — never a mask that loops forever).

    Use ONLY for the swap transition (a data update / #51 toggle whose decision must flip).
    Keep :func:`dns_probe` for steady-state and restart-class reads where the first answer
    is authoritative. Caller MUST pass a non-RFC-6761, non-HSTS-preload name (see
    :func:`unique_domain`).
    """
    deadline = time.time() + timeout
    last: DnsAnswer | None = None
    while time.time() < deadline:
        last = dns_probe(vm, name, rtype, timeout=15.0, attempts=2, delay=2.0)
        if predicate(last):
            return last
        time.sleep(interval)
    raise RuntimeError(
        f"dns_probe_until({name}, {rtype}) predicate never held within {timeout}s "
        f"(last answer: {last}) — the zero-downtime swap decision did not apply in budget"
    )


def is_nxdomain(answer: DnsAnswer) -> bool:
    """True iff the resolver returned NXDOMAIN with no records."""
    return answer.rcode == "NXDOMAIN" and not answer.records


def is_null_ip(answer: DnsAnswer, null_ip: str = NULL_IP4) -> bool:
    """True iff the answer is the null-block IP (default ``0.0.0.0`` / ``::``).

    Compares by VALUE, not string: pfb_unbound.py emits the IPv6 null as ``::``
    and drill prints the canonical ``::``, but callers may pass ``::0`` — same
    address, different text. Normalise both via ``ipaddress`` so representation
    never matters (``::`` == ``::0``, ``0.0.0.0`` == ``0.0.0.0``).
    """
    try:
        target = ipaddress.ip_address(null_ip)
    except ValueError:
        return null_ip in answer.records
    for record in answer.records:
        try:
            if ipaddress.ip_address(record) == target:
                return True
        except ValueError:
            continue
    return False


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
# Python-emitted counts (ADR-06/07) — the values the DNSBL UI aliases read.
# pfb_unbound.py writes these as BARE relative names ("pfb_py_count",
# "pfb_py_regex_count"), which resolve against Unbound's chroot CWD (/var/unbound),
# so on the HOST they live at /var/unbound/<name> — exactly what PHP reads
# (inc:113-114 unbound_py_count / unbound_py_regex_count). Read them over SSH.
# --------------------------------------------------------------------------- #

PY_COUNT_FILE = "/var/unbound/pfb_py_count"
PY_REGEX_COUNT_FILE = "/var/unbound/pfb_py_regex_count"


def read_py_int(vm: SmokeVM, path: str, *, timeout: float = 30.0) -> int | None:
    """Read an integer count file on the guest; ``None`` if absent/empty/non-int."""
    result = vm.ssh("cat", path, timeout=timeout)
    if result.returncode != 0:
        return None
    text = result.stdout.strip()
    try:
        return int(text)
    except ValueError:
        return None


def regex_admitted_count(vm: SmokeVM, *, timeout: float = 30.0) -> int | None:
    """The ADMITTED feed+user regex total the DNSBL_Regex alias renders.

    pfb_unbound.py emits ``len(regexDB) + len(allowRegexDB)`` AFTER the user
    REGEX-ini load and the feed-regex merge AND after the opt-in static cap drops
    over-cap patterns — so this is the *admitted* count, which legitimately shrinks
    when ``regex_cap`` is on (pfb_unbound.py:755; ADR-07 "Counts change by design").
    """
    return read_py_int(vm, PY_REGEX_COUNT_FILE, timeout=timeout)


def py_loaded_count(vm: SmokeVM, *, timeout: float = 30.0) -> int | None:
    """The LOADED DNSBL entry total pfb_py_count renders (ADR-06; pfb_unbound.py:635)."""
    return read_py_int(vm, PY_COUNT_FILE, timeout=timeout)


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


def rule_references(vm: SmokeVM, alias: str, *, timeout: float = 30.0, attempts: int = 10, delay: float = 2.0) -> bool:
    """True iff a loaded pf rule references ``alias`` (``pfctl -sr`` | grep).

    pfBlockerNG's ``filter_configure`` lands the auto-rule slightly AFTER the
    update CLI returns, so poll rather than read once (the rule was observed
    present in on-failure diagnostics dumped moments after a single-shot read
    returned False — a pure timing race).
    """
    for attempt in range(attempts):
        result = vm.ssh(PFCTL, "-sr", timeout=timeout)
        if result.returncode != 0:
            raise RuntimeError(f"pfctl -sr failed: rc={result.returncode} stderr={result.stderr!r}")
        if any(f"<{alias}>" in line or alias in line for line in result.stdout.splitlines()):
            return True
        if attempt < attempts - 1:
            time.sleep(delay)
    return False


def member_present(members: list[str], ip: str) -> bool:
    """True iff ``ip`` appears in a table's members (CIDR-tolerant exact/prefix)."""
    return ip in members or any(m.split("/", 1)[0] == ip for m in members)


# --------------------------------------------------------------------------- #
# Diagnostics — dump live box state on a failed case (printed to the CI log)
# --------------------------------------------------------------------------- #


def collect_host_diagnostics(vm: SmokeVM, dest_dir: str = "smoke-diag", *, timeout: float = 240.0) -> None:
    """Tar a COMPREHENSIVE pfSense-GUEST snapshot and pull it to ``dest_dir/`` on
    the runner, for the workflow to upload as an artifact.

    Collected ALWAYS (even on a green run): we might need it to debug a failure,
    and even when we don't, an after-the-fact analysis of the full logs can surface
    issues we didn't know to look for. Best-effort — never raises (diagnostics, not
    a gate). The guest VM is torn down at session end, so this must run in-process
    before teardown; a workflow step after pytest can't reach the guest.

    Captures: ALL of /var/log (system / filter(firewall) / resolver / pfBlockerNG /
    …), dmesg + boot, full pf state (``pfctl -sa``), network (ifconfig / sockstat /
    netstat), Unbound + pfBlockerNG runtime files (``*.conf`` / ``*.ini`` /
    ``pfb_py_*``), the process table, and a SECRET-SCRUBBED config.xml (bcrypt hash,
    cert private keys, authorized keys redacted before it leaves the box).
    """
    remote_tar = "/tmp/pfb_smoke_diag.tgz"
    script = (
        'set +e; D=/tmp/pfb_smoke_diag; rm -rf "$D"; mkdir -p "$D/unbound"; '
        'tar czf "$D/var_log.tgz" -C /var log 2>/dev/null; '
        '/sbin/dmesg > "$D/dmesg.txt" 2>&1; cp /var/run/dmesg.boot "$D/dmesg.boot" 2>/dev/null; '
        '/sbin/pfctl -sa > "$D/pfctl_sa.txt" 2>&1; '
        '/sbin/ifconfig -a > "$D/ifconfig.txt" 2>&1; '
        '/usr/bin/sockstat > "$D/sockstat.txt" 2>&1; /usr/bin/netstat -rn > "$D/netstat_rn.txt" 2>&1; '
        'cp /var/unbound/*.conf /var/unbound/*.ini "$D/unbound/" 2>/dev/null; '
        'cp /var/unbound/pfb_py_* "$D/unbound/" 2>/dev/null; '
        # pfBlockerNG database (feeds / masterfiles / orig / deny / dnsbl / …) and
        # pfSense's pf alias-table files — the IP/domain state behind the rules.
        'tar czf "$D/var_db_pfblockerng.tgz" -C /var/db pfblockerng 2>/dev/null; '
        'tar czf "$D/var_db_aliastables.tgz" -C /var/db aliastables 2>/dev/null; '
        '/bin/ps auxww > "$D/ps.txt" 2>&1; '
        # Scrub secrets from config.xml BEFORE it leaves the box.
        "sed -E 's#(<bcrypt-hash>)[^<]*#\\1REDACTED#g; s#(<prv>)[^<]*#\\1REDACTED#g; "
        "s#(<authorizedkeys>)[^<]*#\\1REDACTED#g; s#(<tls_certificate>)[^<]*#\\1REDACTED#g' "
        '/conf/config.xml > "$D/config.scrubbed.xml" 2>/dev/null; '
        f"tar czf {remote_tar} -C /tmp pfb_smoke_diag 2>/dev/null; true"
    )
    try:
        vm.ssh("/bin/sh", "-c", script, timeout=timeout)
        os.makedirs(dest_dir, exist_ok=True)
        scp_argv = [
            "scp",
            "-i",
            vm.ssh_key_path,
            "-P",
            str(vm.ssh_port),
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "BatchMode=yes",
            "-o",
            "LogLevel=ERROR",
            f"{vm.ssh_target}:{remote_tar}",
            os.path.join(dest_dir, "pfb_smoke_diag.tgz"),
        ]
        result = subprocess.run(scp_argv, capture_output=True, text=True, timeout=timeout, check=False)
        if result.returncode == 0:
            print(f"[smoke] collected full guest diagnostics -> {dest_dir}/pfb_smoke_diag.tgz")
        else:
            print(f"[smoke] guest-diagnostics scp failed (non-fatal): {result.stderr!r}")
    except Exception as exc:  # noqa: BLE001
        print(f"[smoke] collect_host_diagnostics failed (non-fatal): {exc!r}")


def dump_diagnostics(vm: SmokeVM) -> None:
    """Print key pfSense/pfBlockerNG/Unbound state for post-mortem on failure.

    The session VM is torn down at the end of pytest, so a failed case must
    capture state here (within the run) — a workflow step after pytest can't
    reach the guest. Best-effort; never raises.
    """
    # Each probe is ONE shell string run by the guest's login shell. Passing
    # ("sh","-c",cmd) as separate args fails: ssh re-joins remote args with
    # spaces and the remote shell re-parses, so a pipeline lands as sh's $0/$1.
    probes: list[tuple[str, str]] = [
        ("pfctl -sTables", "/sbin/pfctl -sTables"),
        ("pf rules (pfB_/DNSBL refs)", "/sbin/pfctl -sr 2>/dev/null | grep -iE 'pfB_|DNSBL' || true"),
        ("/var/db/pfblockerng listing", "ls -lR /var/db/pfblockerng 2>/dev/null | head -80 || true"),
        (
            # Target unbound.conf only — a recursive grep over /var/unbound is slow
            # (large python data files) and timed out. Include the forward config.
            "unbound.conf: forward/local-data/access",
            "grep -nE 'forward-zone|forward-addr|forward-tcp|local-(zone|data):|access-control|do-not-query' "
            "/var/unbound/unbound.conf 2>/dev/null | head -40 || true",
        ),
        ("unbound pfb includes", "ls -l /var/unbound/pfb_dnsbl* /var/unbound/pfb_py* 2>/dev/null || true"),
        (
            # Direct before/after: what pfBlockerNG's DNSBL reload changed in
            # unbound.conf — crucially whether it dropped any access-control.
            "unbound.conf DNSBL diff (before -> after)",
            f"diff -u {UNBOUND_BEFORE} {UNBOUND_CONF} 2>/dev/null | head -80 || true",
        ),
        (
            "access-control lines (before vs after)",
            f"echo '== before =='; grep -nE 'access-control' {UNBOUND_BEFORE} 2>/dev/null | head; "
            f"echo '== after =='; grep -nE 'access-control' {UNBOUND_CONF} 2>/dev/null | head",
        ),
        (
            "DNSBL python data (pfb_py_data/zone) — what python mode blocks",
            "wc -l /var/unbound/pfb_py_data.txt /var/unbound/pfb_py_zone.txt 2>/dev/null; "
            "echo '--- data head ---'; head -8 /var/unbound/pfb_py_data.txt 2>/dev/null; "
            "echo '--- blocked refs ---'; "
            "grep -nE 'blocked-|null-|guard-|allowed-' "
            "/var/unbound/pfb_py_data.txt /var/unbound/pfb_py_zone.txt 2>/dev/null | head",
        ),
        (
            # THE enable gate: pfb_unbound.ini drives the module. python_enable=on
            # (mode=='enabled') is what makes operate() load the blocklist + block;
            # if it's off, every name is forwarded (SERVFAIL under egress block).
            "pfb_unbound.ini ([MAIN] — python_enable / python_blocking / VIPs)",
            "cat /var/unbound/pfb_unbound.ini 2>/dev/null | head -60 || true",
        ),
        (
            # ADR-06 manifest the module BUILDS dataDB from on next (not pfb_py_data
            # directly) + the per-load count it emits + any python load/build error.
            "DNSBL python manifest + count + py_error",
            "echo '--- pfb_py_sources.json ---'; head -c 1200 /var/unbound/pfb_py_sources.json 2>/dev/null; echo; "
            "echo '--- pfb_py_count ---'; cat /var/unbound/pfb_py_count 2>/dev/null; echo; "
            "echo '--- py_error.log ---'; tail -n 40 /var/log/pfblockerng/py_error.log 2>/dev/null || true",
        ),
        (
            # mode=='enabled' needs unbound_state == config_path_enabled('unbound').
            "DNS Resolver enabled? (<unbound><enable>)",
            "sed -n '/<unbound>/,/<\\/unbound>/p' /conf/config.xml 2>/dev/null "
            "| grep -nE '<enable|<python|forwarding' | head || true",
        ),
        (
            "DNSBL unbound.conf blocks — what unbound mode builds (local-zone/data)",
            "wc -l /var/unbound/pfb_dnsbl.conf 2>/dev/null; "
            "grep -nE 'blocked-|local-zone|local-data' /var/unbound/pfb_dnsbl.conf 2>/dev/null | head -15",
        ),
        (
            "guest-local DNS query (does the resolver answer NON-quiet?)",
            # localhost always resolves locally -> a clean liveness check, with no
            # RFC 6761 local-zone or per-case-domain confusion.
            "/usr/local/bin/drill localhost A @127.0.0.1 2>&1 | "
            "grep -iE 'rcode|ANSWER SECTION|^[a-z].*IN' | head -6 || true",
        ),
        (
            "unbound process + :53 sockets",
            "ps auxww 2>/dev/null | grep -i '[u]nbound'; sockstat 2>/dev/null | grep -E 'unbound|:53' | head",
        ),
        (
            "DNSBL python chroot (mounts + interpreter present?)",
            "mount 2>/dev/null | grep -i unbound; "
            "ls -l /var/unbound/usr/local/bin/ /var/unbound/usr/local/lib/ 2>/dev/null | head -20 || true",
        ),
        (
            "DNSBL db files (orig + parsed)",
            "ls -lR /var/db/pfblockerng/dnsbl /var/db/pfblockerng/dnsblorig 2>/dev/null | head -60 || true",
        ),
        (
            "DNSBL parsed/orig sample",
            "for f in /var/db/pfblockerng/dnsbl/*.txt /var/db/pfblockerng/dnsblorig/*; do "
            'echo "== $f =="; head -3 "$f" 2>/dev/null; done 2>/dev/null | head -40 || true',
        ),
        (
            "DNSBL log summary (counts/skips)",
            "grep -iE 'DNSBL|domain|unique|final|skip|TLD|invalid' "
            "/var/log/pfblockerng/pfblockerng.log 2>/dev/null | tail -50 || true",
        ),
        (
            "config.xml virtualip section",
            "sed -n '/<virtualip>/,/<\\/virtualip>/p' /conf/config.xml 2>/dev/null | head -40 || true",
        ),
        ("config.xml pfb_dnsvip refs", "grep -nE 'pfb_dnsvip|ifconfig.*alias' /conf/config.xml 2>/dev/null || true"),
        ("lo0 aliases (is the VIP plumbed?)", "/sbin/ifconfig lo0 2>/dev/null || true"),
        (
            "config.xml pfBlockerNG section",
            "sed -n '/<pfblockerng>/,/<\\/pfblockerng>/p' /conf/config.xml 2>/dev/null | head -120 || true",
        ),
        ("pfBlockerNG log tail", "tail -n 120 /var/log/pfblockerng/pfblockerng.log 2>/dev/null || true"),
        ("pfBlockerNG error log tail", "tail -n 40 /var/log/pfblockerng/error.log 2>/dev/null || true"),
    ]
    # Stub-upstream reachability: can the guest reach the runner-side stub, and
    # does forwarding through it resolve a random (non-blocked, non-local) name
    # to the sentinel? Proves the forward path end-to-end.
    if vm.upstream_dns_port:
        p = vm.upstream_dns_port
        probes += [
            (
                f"guest -> stub directly (@{GUEST_TO_HOST_ALIAS} -p {p})",
                f"/usr/local/bin/drill pfbsmoke-nonblocked-probe.com A @{GUEST_TO_HOST_ALIAS} -p {p} 2>&1 | "
                "grep -iE 'rcode|ANSWER|IN.A' | head -5 || true",
            ),
            (
                "forwarding resolves a non-blocked name to the sentinel?",
                "/usr/local/bin/drill pfbsmoke-nonblocked-probe.com A @127.0.0.1 2>&1 | "
                "grep -iE 'rcode|ANSWER|IN.A' | head -5 || true",
            ),
        ]
    print("\n========== VM DIAGNOSTICS (case failed) ==========")
    for label, cmd in probes:
        try:
            result = vm.ssh(cmd, timeout=30)
            print(f"----- {label} -----\n{result.stdout}{result.stderr}")
        except Exception as exc:  # noqa: BLE001 (diagnostics must never mask the real failure)
            print(f"----- {label}: dump failed: {exc}")
    print("========== END VM DIAGNOSTICS ==========\n")
    dump_state_diffs(vm)


# --------------------------------------------------------------------------- #
# Composed per-case context manager
# --------------------------------------------------------------------------- #


class CaseContext:
    """One matrix case: inject -> reload -> (probe in the body) -> reset.

    Usage::

        with CaseContext(vm, spec) as ctx:
            answer = dns_probe(vm, "blocked.test")
            assert is_nxdomain(answer)

    On enter: inject(spec) then a Force Update (``update``) FOLLOWED BY the
    targeted Force Reload (``updatednsbl``/``updateip``). The full ``update``
    re-reads the source (incl. our local feed file) and drives
    ``filter_configure`` — which is what loads the pf table AND creates the
    Deny rule for an IP case; the targeted reload alone (``reuse='on'``) does
    not settle those synchronously. On exit: reset(vm) so the next case starts
    from the baseline (Phase-3 session-isolation). ``scope`` is auto-chosen
    (``updatednsbl`` for a DnsblCase, ``updateip`` for an IpCase); override via
    ``scope=``.
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
        # Egress stays OPEN across inject + reload: the DNSBL update path needs a
        # working resolver/network and deadlocks the guest if egress is dark.
        unblock_egress()
        snap_state(self.vm, f"{self.spec.aliasname}_pre")
        inject(self.vm, self.spec)
        snap_state(self.vm, f"{self.spec.aliasname}_injected")
        # IP needs the full Force Update first (filter_configure loads the table +
        # rule; a lone targeted reload left "Table does not exist"), THEN the
        # targeted updateip. DNSBL only needs the single targeted updatednsbl —
        # the extra full update was just doubling the heavy python-chroot reload.
        if isinstance(self.spec, IpCase):
            reload(self.vm, "update")
        reload(self.vm, self.scope)
        snap_state(self.vm, f"{self.spec.aliasname}_reloaded")
        # NOW block egress: the per-case probe must prove the block/pass with no
        # upstream (a non-blocked name would hang, not silently resolve upstream).
        # ISOLATION (temporary): SMOKE_HERMETIC_PROBE=0 leaves egress OPEN for the
        # probe to separate "egress is the cause" from "DNSBL/hostfwd is the cause".
        if os.environ.get("SMOKE_HERMETIC_PROBE", "1") != "0":
            block_egress()
        return self

    def __exit__(self, *exc: object) -> None:
        # Restore egress before reset() — its forced update reloads pfBlockerNG.
        unblock_egress()
        # Don't let a reset() failure during teardown MASK a failure the case body
        # already raised — pytest would report the teardown error and bury the real
        # one. If an exception is in flight, log the reset failure and let the
        # original propagate; otherwise reset errors surface normally.
        try:
            reset(self.vm)
        except Exception as reset_exc:  # noqa: BLE001
            if exc and exc[0] is not None:
                print(f"[smoke] reset() failed during teardown (suppressed; original error stands): {reset_exc!r}")
            else:
                raise
