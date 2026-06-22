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
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import NamedTuple

from .conftest import (
    DEFAULT_BOOT_TIMEOUT,
    GUEST_TO_HOST_ALIAS,
    SMOKE_DIR,
    STUB_DNS_A,
    WAIT_READY_SH,
    SmokeVM,
    resolve_a,
)

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


# UTF-8 BOM (EF BB BF). Real-world feeds occasionally emit it before the first line;
# the header sniff (pfb_dnsbl_is_abp_header) must look THROUGH it (ADR-21 hardening).
ABP_BOM = "\ufeff"


def abp_feed_bom(*lines: str) -> str:
    """:func:`abp_feed` with a leading UTF-8 BOM before the ``[Adblock Plus 2.0]``
    header. A BOM that masked the header would leave the feed tagged ``plain``, so a
    non-anchor ABP rule (e.g. a feed ``/regex/``) would be DROPPED instead of compiled
    — the live distinguisher for the header sniff's BOM tolerance."""
    return ABP_BOM + abp_feed(*lines)


# --------------------------------------------------------------------------- #
# Case specification (declarative input the matrix fills in)
# --------------------------------------------------------------------------- #


class DnsblMode(str, Enum):
    """The block shape a DNSBL case expects for a matched name.

    On ``devel`` (python-mode-only) the shapes are:

    * ``NULL`` — NOERROR + ``0.0.0.0`` / ``::0``; per-list
      ``logging='disabled'`` → ``logging_type='2'`` → ``null_blocking=True``
      in ``pfb_unbound.py:evaluate_domain``.
    * ``VIP`` — NOERROR + the DNSBL sinkhole VIP (``pfb_dnsvip4``); per-list
      ``logging='enabled'`` → ``logging_type='1'`` → ``null_blocking=False``.
    * ``NXDOMAIN`` — a bare NXDOMAIN rcode, no records (issue #31); per-list
      ``logging='nxdomain_log'`` → ``logging_type='3'`` → ``operate()`` returns
      ``RCODE_NXDOMAIN`` with no DNSMessage. (The ``nxdomain`` / no-logging
      variant '4' yields the IDENTICAL shape — only the dnsbl.log line differs,
      which this on-box DNS-shape probe cannot observe, so it is unit-pinned in
      ``tests/test_pfb_unbound.py`` rather than duplicated here.)

    Before issue #31, NXDOMAIN was only reachable via SafeSearch; it is now a
    selectable per-list DNSBL block response.
    """

    NULL = "null"
    VIP = "vip"
    NXDOMAIN = "nxdomain"


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
    # hsts -> the "HSTS via Null Blocking mode" toggle (CFG_DNSBL_SETTINGS/pfb_hsts,
    # inc:847 -> ini python_hsts). When on, pfb_unbound.py loads pfb_py_hsts.txt into
    # hstsDB; a VIP-mode (logging='enabled', log_type '1') block on an HSTS-preload
    # name keeps null_blocking=True -> NULL instead of the VIP (evaluate_domain:
    # ``log_type == '1' and not in_hsts``). ``None`` (default) emits nothing -> the
    # existing matrix is byte-for-byte unchanged; True/False forces pfb_hsts on/off.
    hsts: bool | None = None
    # idn_mode -> the "IDN Blocking" selector (CFG_DNSBL_SETTINGS/pfb_idn, ADR-08).
    # 'off'/'' -> no IDN action; 'all' -> block every xn-- (legacy blunt); 'confusable'
    # -> the TR39 mixed-script homoglyph analyzer (pfb_unbound.py classify_idn). ``None``
    # (default) emits nothing -> the existing matrix is unchanged. The two sub-toggles
    # apply only in Confusable mode (pfb_unbound.py idn_confusable_action): block_malicious
    # (default ON) blocks a clearly-malicious homoglyph, else alerts; escalate_suspicious
    # (default OFF) escalates the suspicious/flagged tier from alert to block.
    idn_mode: str | None = None
    idn_block_malicious: bool | None = None
    idn_escalate_suspicious: bool | None = None

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


class SafeSearchEntry(NamedTuple):
    """One SafeSearch CNAME-redirect row for :func:`inject_safesearch_cname_entries`.

    Stored as a 5-column CSV row in ``pfb_py_ss.txt``:
    ``domain,cname,target,baked_v4,baked_v6`` — where column 2 is the LITERAL
    token ``cname`` (the routing marker ``isSafeSearch["A"] == "cname"``), column 3
    is the CNAME target fqdn that Unbound chases (#1 redirect), and columns 4/5 are
    the #2 baked-fallback IPs used when the chase yields only a bare CNAME (no address).
    Leave ``baked_v4`` / ``baked_v6`` empty when the test does not exercise the fallback.
    """

    domain: str
    target: str
    baked_v4: str = ""
    baked_v6: str = ""


# --------------------------------------------------------------------------- #
# Deploy — install the branch-under-test .pkg (evolved; NOT deploy.sh rsync)
# --------------------------------------------------------------------------- #


def deploy(vm: SmokeVM, pkg_path: str | None = None, *, timeout: float = 300.0) -> None:
    """Install the branch's built .pkg onto the guest via install-pkg.sh.

    ``pkg add`` registers the package in pkg's DB, resolves RUN_DEPENDS from the
    repos, and runs POST-INSTALL (menus, services, Unbound wiring) — fidelity
    the rsync overlay (``deploy.sh``) does not give. The .pkg is produced by the
    portable Linux build job (build-pkg-linux.yml); its path is ``pkg_path`` or ``SMOKE_PKG``.
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
# pfb_unbound.py loads SafeSearch redirect entries from this chroot-relative CSV
# (5-col format: domain,cname,target,baked_v4,baked_v6; see inject_safesearch_cname_entries).
UNBOUND_PY_SS_FILE = "/var/unbound/pfb_py_ss.txt"

# SafeSearch test IPs — each is DISTINCT from the stub sentinel (STUB_DNS_A /
# STUB_DNS_AAAA) so a test can tell "chase reached the target" from "sentinel default",
# and from each other so a test can tell "#1 chase result" from "#2 baked fallback".
SS_TARGET_A = "198.51.100.10"  # RFC 5737 TEST-NET-2: the CNAME chase target address (#1)
SS_TARGET_AAAA = "2001:db8:5350::10"  # RFC 3849: the CNAME chase target address (#1)
SS_BAKED_A = "203.0.113.20"  # RFC 5737 TEST-NET-3 (≠ STUB_DNS_A .99): baked fallback (#2)
SS_BAKED_AAAA = "2001:db8:5350::20"  # RFC 3849 (≠ STUB_DNS_AAAA ::99): baked fallback (#2)


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


def set_dnsbl_lenient(vm: SmokeVM, on: bool, *, timeout: float = 60.0) -> None:
    """Set the ADR-22 ``pfb_dnsbl_lenient`` toggle in the DNSBL-settings section.

    ``on`` -> lenient (today's permissive scheme strip; nothing skipped, no new log).
    ``off`` -> strict: ``pfb_dnsbl_strip_scheme`` validates the scheme against RFC 3986
    and rejects URL paths, recording each rejected line in the DNSBL parse-error log and
    emitting one per-feed WARNING. Written via ``array_merge`` so it never clobbers the
    rest of the DNSBL settings ``inject()`` already wrote. Set BEFORE the reload that
    rebuilds the feed (``pfb_global`` reads it once per run)."""
    val = "on" if on else "off"
    snippet = (
        f"$d = config_get_path({_php_str(CFG_DNSBL_SETTINGS)}, array());\n"
        f"$d['pfb_dnsbl_lenient'] = {_php_str(val)};\n"
        f"config_set_path({_php_str(CFG_DNSBL_SETTINGS)}, $d);\n"
        "write_config('pfBlockerNG smoke: set pfb_dnsbl_lenient');\n"
        "echo 'OK';"
    )
    result = php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(
            f"set_dnsbl_lenient({on}) failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}"
        )


def read_log_file(vm: SmokeVM, path: str, *, timeout: float = 30.0) -> str:
    """Return the full text of a guest log file (empty string if absent).

    Used to assert ADR-22 strict-mode skips landed in the DNSBL parse-error log:
    a rejected line's original text (its ``uuid-*`` label) appears in the CSV record
    pfb_parsed_fail() appended. ``cat`` a missing file -> '' (never raises)."""
    result = vm.ssh("cat", path, timeout=timeout)
    return result.stdout if result.returncode == 0 else ""


CFG_SAFESEARCH_ENABLE = "installedpackages/pfblockerngsafesearch/safesearch_enable"


def set_safesearch_enabled(vm: SmokeVM, on: bool, *, timeout: float = 60.0) -> None:
    """Toggle DNSBL SafeSearch (``safesearch_enable`` = 'Enable' / 'Disable').

    SafeSearch lives at its OWN config root (``pfblockerngsafesearch``), a scalar
    (not under ``config/0``) read by pfb_global() as
    ``config_get_path('installedpackages/pfblockerngsafesearch/safesearch_enable')``.
    When 'Enable', the next DNSBL update writes the SafeSearch python CSV
    (``pfb_py_ss.txt``) — including the duckduckgo/pixabay CNAME redirect rows
    (issue #149) — which pfb_unbound.py loads as ``safeSearchDB``.
    """
    val = "Enable" if on else "Disable"
    snippet = (
        f"config_set_path({_php_str(CFG_SAFESEARCH_ENABLE)}, {_php_str(val)});\n"
        "write_config('pfBlockerNG smoke: toggle safesearch_enable');\n"
        "echo 'OK';"
    )
    result = php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(
            f"set_safesearch_enabled({on}) failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}"
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


def set_feed_internal_allowlist(vm: SmokeVM, value: str, *, timeout: float = 60.0) -> None:
    """Set the General-settings feed-host internal-address ALLOWLIST (``pfb_feed_internal_allowlist``).

    The feed-host filter (``pfb_feed_internal_filter``, default-ON SSRF guard) rejects a feed
    whose host resolves to an internal/private address — but EXEMPTS any IP covered by this
    allowlist (IPs/CIDRs, whitespace/comma-separated, stored base64-encoded; ``pfb_feed_internal_allowlist()``
    parses it, ``pfb_ip_in_allowlist()`` matches by CIDR). The smoke mock feed server is the SLIRP
    host alias ``10.0.2.2`` (RFC1918, and NOT the box's own IP, so the self-exemption does not
    apply), so the HTTP-feed smoke allowlists the SLIRP test network ``10.0.2.0/24`` — keeping the
    filter ON while letting the mock fetch through.

    The field is stored base64-encoded (the pfBlockerNG textarea convention; the reader
    base64_decodes it), so ``value`` is encoded here before it is written.
    """
    encoded = base64.b64encode(value.encode()).decode()
    snippet = (
        f"config_set_path({_php_str(CFG_GLOBAL + '/pfb_feed_internal_allowlist')}, {_php_str(encoded)});\n"
        "write_config('pfBlockerNG smoke: set feed internal allowlist');\necho 'OK';"
    )
    result = php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(
            f"set_feed_internal_allowlist failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}"
        )


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


def set_unbound_forwarding(vm: SmokeVM, on: bool, *, upstream: str = "1.1.1.1", timeout: float = 120.0) -> None:
    """Set Unbound to RECURSIVE (``on=False``) or FORWARDING (``on=True``) mode.

    Toggles ``unbound/forwarding`` while holding the System DNS server CONSTANT
    (``system/dnsserver = [upstream]``) and DNSSEC OFF, so a recursive-vs-forwarding
    comparison of the SafeSearch CNAME redirect (issue #149) varies exactly one thing.
    ``on=False`` = recursive (the constant dnsserver is then unused); ``on=True`` =
    forward every query to ``upstream`` (a REAL resolver — the redirect chase then
    resolves the real SafeSearch target, unlike the mock stub which answers every name
    identically and would mask the result).

    The redirect works in BOTH modes (the iterator checks the message cache — where the
    module plants the CNAME — before forwarding or recursing; the chase then forwards/
    recurses the TARGET). Forcing the mode in the SafeSearch fixture only makes the
    smoke order-independent on the SHARED session VM (a prior matrix module may have
    set use_system_dns_upstream's catch-all forward-to-stub, which masks the result by
    answering every name identically).

    Idempotent; written + ``services_unbound_configure`` (restarts Unbound). NOTE: that
    regenerates the base unbound.conf WITHOUT pfBlockerNG's python module, so the caller
    MUST run a pfBlockerNG reload afterwards to re-add the module + reload safeSearchDB.
    """
    snippet = (
        "$s = config_get_path('system', array());\n"
        f"$s['dnsserver'] = array({_php_str(upstream)});\n"
        "unset($s['dnsallowoverride']);\n"
        "config_set_path('system', $s);\n"
        "$u = config_get_path('unbound', array());\n"
        + ("$u['forwarding'] = 'on';\n" if on else "unset($u['forwarding']);\n")
        + "unset($u['dnssec']);\n"  # held OFF in both states (unsigned upstream answers)
        "unset($u['custom_options']);\n"  # drop any leftover forward-zone
        "config_set_path('unbound', $u);\n"
        "write_config('pfBlockerNG smoke: set unbound forwarding');\n"
        "services_unbound_configure();\n"
        "echo 'OK';"
    )
    result = php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(
            f"set_unbound_forwarding({on}) failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}"
        )
    # services_unbound_configure restarts Unbound — wait for it before any probe.
    wait_unbound_ready(vm)


def use_stub_for_safesearch(vm: SmokeVM, forwarding_on: bool, *, timeout: float = 120.0) -> None:
    """Wire Unbound to the stub DNS so SafeSearch CNAME redirects resolve hermetically.

    Supports BOTH resolver modes so a test can vary forwarding without touching
    the stub wiring:

    ``forwarding_on=True`` (FORWARDING mode): delegates to the same config as
    :func:`use_system_dns_upstream` — sets ``system/dnsserver = [10.0.2.2]``,
    ``unbound/forwarding = on``, clears ``dnssec`` and ``custom_options``.
    Queries forward to ``10.0.2.2`` (the SLIRP host alias), which NATs
    ``guest->10.0.2.2:53`` to the stub on the runner's loopback.

    ``forwarding_on=False`` (RECURSIVE mode): keeps ``unbound/forwarding`` UNSET
    (Unbound recurses normally) but injects a catch-all ``forward-zone`` in
    ``unbound/custom_options`` pointing every query at ``10.0.2.2``, so the stub
    still answers all queries while Unbound operates in recursive mode.
    ``custom_options`` is stored base64-encoded in ``config.xml`` (the pfBlockerNG
    textarea convention: the GUI base64-encodes on save, the renderer decodes on
    read); the encoded value is written here.  ``dnssec`` is cleared in both
    modes — the stub's answers are unsigned and a validator would mark them bogus.

    In BOTH modes: runs ``services_unbound_configure()`` + :func:`wait_unbound_ready`,
    then probes a throwaway name to confirm the stub relay is live before returning.
    A failed self-check raises immediately with the mode and the answer received.

    NOTE: ``services_unbound_configure`` regenerates ``unbound.conf`` WITHOUT
    pfBlockerNG's python module.  The caller MUST run a pfBlockerNG reload AFTER
    this call to re-add the module and reload ``safeSearchDB`` before any
    SafeSearch probe.
    """
    if forwarding_on:
        # Forwarding mode: identical to use_system_dns_upstream — delegate so
        # the self-check and config shape stay in sync with that helper.
        use_system_dns_upstream(vm, timeout=timeout)
        return

    # Recursive mode: no unbound/forwarding, but route every query to the stub
    # via a catch-all forward-zone in custom_options.  pfSense stores
    # custom_options base64-encoded (pfbng_text_area_decode / base64_encode on
    # save), so encode before writing.
    forward_zone = 'forward-zone:\n    name: "."\n    forward-addr: 10.0.2.2\n'
    encoded = base64.b64encode(forward_zone.encode()).decode()
    snippet = (
        "$s = config_get_path('system', array());\n"
        f"$s['dnsserver'] = array({_php_str(GUEST_TO_HOST_ALIAS)});\n"
        "unset($s['dnsallowoverride']);\n"
        "config_set_path('system', $s);\n"
        "$u = config_get_path('unbound', array());\n"
        "unset($u['forwarding']);\n"
        "unset($u['dnssec']);\n"
        f"$u['custom_options'] = {_php_str(encoded)};\n"
        "config_set_path('unbound', $u);\n"
        "write_config('pfBlockerNG smoke: stub-DNS SafeSearch recursive mode');\n"
        "services_unbound_configure();\n"
        "echo 'OK';"
    )
    result = php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(
            f"use_stub_for_safesearch(forwarding_on=False) failed: "
            f"rc={result.returncode} {result.stderr!r} {result.stdout!r}"
        )
    # services_unbound_configure restarts Unbound — wait for it before any probe.
    wait_unbound_ready(vm)
    # RELAY SELF-CHECK: resolve a throwaway name; in recursive mode every query
    # routes to the stub via the catch-all forward-zone and MUST return the sentinel.
    probe = unique_domain("ssstubselfcheck")
    ans = dns_probe(vm, probe, "A", timeout=10.0, attempts=3, delay=3.0)
    if not resolves_to(ans, STUB_DNS_A):
        raise RuntimeError(
            f"SafeSearch stub relay self-check FAILED (recursive mode): "
            f"{probe} -> {ans} (expected sentinel {STUB_DNS_A}). "
            f"The catch-all forward-zone -> 10.0.2.2 -> runner 127.0.0.1:53 path is not working."
        )


def inject_safesearch_cname_entries(
    vm: SmokeVM,
    entries: Sequence[SafeSearchEntry],
    *,
    timeout: float = 60.0,
) -> None:
    """Append fabricated SafeSearch CNAME-redirect rows to ``pfb_py_ss.txt`` and reload.

    Each entry is written as a 5-column CSV row:
    ``domain,cname,target,baked_v4,baked_v6`` where column 2 is the LITERAL token
    ``cname`` (the routing marker ``isSafeSearch["A"] == "cname"`` in
    ``pfb_unbound.py``), column 3 is the CNAME target fqdn that Unbound chases
    (#1 redirect), and columns 4/5 are the #2 baked-fallback IPs used when the chase
    yields only a bare CNAME with no address.  Empty strings for ``baked_v4``/
    ``baked_v6`` are valid when the test does not exercise the fallback path.

    Rows are APPENDED (``tee -a``) so any package-written rows survive; the file is
    created if absent.  Appending is idempotent-friendly within a session as long as
    each test uses unique domain names (:func:`unique_domain`).

    After writing, the Unbound daemon is bounced RAW (TERM the pid, wait, restart)
    to reload ``safeSearchDB`` from the updated file — identical to
    ``pfb_stop_start_unbound`` (``pfblockerng.inc:5444``).  This is NOT a pfBlockerNG
    update (which would overwrite the file with package-generated content); the raw
    bounce re-runs the python module's ``init()`` which re-reads ``pfb_py_ss.txt`` as
    written.  For ``safeSearchDB`` to take effect the DNSBL python module must already
    be loaded in ``unbound.conf`` — DNSBL must be enabled and a pfBlockerNG reload run
    before this call.
    """
    csv_lines = "\n".join(f"{e.domain},cname,{e.target},{e.baked_v4},{e.baked_v6}" for e in entries)
    contents = csv_lines + "\n"
    # Append to the SafeSearch CSV (chroot-relative; Unbound is chrooted at /var/unbound).
    result = subprocess.run(
        vm.ssh_argv("tee", "-a", UNBOUND_PY_SS_FILE),
        input=contents,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"inject_safesearch_cname_entries: tee to {UNBOUND_PY_SS_FILE} failed: "
            f"rc={result.returncode} {result.stderr!r}"
        )
    # Raw Unbound bounce to reload safeSearchDB from the updated file.
    # Mirrors pfb_stop_start_unbound (pfblockerng.inc:5444): TERM the pid, wait
    # up to 30 s for exit, then restart the daemon (which re-daemonizes and returns).
    # Fed on stdin to a remote /bin/sh (the php_eval idiom) so the multi-token POSIX
    # script — $(...), `;`, the for-loop — is parsed by sh itself, never the SSH
    # login shell (pfSense root defaults to tcsh, which would mangle it).
    bounce_cmd = (
        "kill -TERM $(cat /var/run/unbound.pid)\n"
        "for i in $(seq 1 30); do\n"
        "  pgrep -x unbound >/dev/null || break\n"
        "  sleep 1\n"
        "done\n"
        "/usr/local/sbin/unbound -c /var/unbound/unbound.conf\n"
    )
    bounce = subprocess.run(
        vm.ssh_argv("/bin/sh"),
        input=bounce_cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if bounce.returncode != 0:
        raise RuntimeError(
            f"inject_safesearch_cname_entries: Unbound bounce failed: rc={bounce.returncode} {bounce.stderr!r}"
        )
    wait_unbound_ready(vm)


# --------------------------------------------------------------------------- #
# Update hooks (ADR-12) — pre/post script hooks fired from the update pass
# --------------------------------------------------------------------------- #
# pfBlockerNG runs admin-VETTED pre/post SCRIPTS once per update pass from
# sync_package_pfblockerng (inc:7388 pre, inc:11227 post). The hooks live as a
# PLAIN NUMERIC array under the 'row' listtag at CFG_GLOBAL/hooks/row (NOT a bare
# list under <hooks>: 'hooks' is not a pfSense listtag, so a bare list serializes
# to invalid <0> XML and never reloads — see pfb_get_hooks()). pfb_get_hooks()
# reads ``$pfbconfig['hooks']['row']`` and runs ONLY entries with enabled==='on'
# whose ``when`` matches the fire point and whose ``script`` is non-empty; the
# runner additionally requires that ``script`` be a hook_<when>_*.{sh,py} file
# present in HOOK_SCRIPT_DIR (ADR-12 security model: a hook runs an on-box script,
# never a GUI-typed command). Each hook runs AS ROOT in the HOST context (NOT
# chrooted) via ``PFB_<K>=<v> … /usr/bin/timeout … <script>`` — so a hook that
# writes /tmp/<file> on the guest is plainly readable back over SSH, which is
# exactly how these smoke tests observe a hook's environment and that it ran. The
# env carries PFB_WHEN plus one PFB_<UPPER(key)> per ctx entry (inc:1797): pre ⇒
# {WHEN, TRIGGER}; post ⇒ {WHEN, TRIGGER, IP_CHANGED, DNSBL_CHANGED, STATUS,
# CHANGED_IP_ALIASES, CHANGED_DNSBL_GROUPS}. reload(vm, scope) fires the hooks
# because it runs the same ``pfblockerng.php <scope>`` CLI the GUI/cron use.

HOOK_MARKER_DIR = "/tmp"

# On-box dir holding the admin-authored hook scripts (PFB_HOOK_SCRIPT_DIR in the
# inc). The picker/runner accept ONLY hook_<when>_*.{sh,py} files that live here, so
# a smoke hook installs its script here before referencing it (see install_hook_script).
HOOK_SCRIPT_DIR = "/usr/local/pkg/pfblockerng/list_scripts"


def install_hook_script(vm: SmokeVM, name: str, body: str, *, timeout: float = 60.0) -> str:
    """Write an executable hook script ``name`` into the on-box hook-script dir; return ``name``.

    The runner and GUI picker accept ONLY scripts that live in ``HOOK_SCRIPT_DIR`` and
    match ``hook_<when>_*.{sh,py}`` (the ADR-12 allow-list), so a smoke hook must
    install its script before set_update_hooks() references it. Writes via ``tee`` (the
    same file-write pattern used elsewhere) and ``chmod 0755`` so the script runs via
    its shebang (the list_scripts convention).
    """
    # A bare basename only -- never let a caller's ``name`` (``..``/``/``) escape
    # HOOK_SCRIPT_DIR and write elsewhere on the guest.
    if name != os.path.basename(name) or name in ("", ".", ".."):
        raise ValueError(f"install_hook_script: unsafe script name {name!r}")
    path = f"{HOOK_SCRIPT_DIR}/{name}"
    res = subprocess.run(
        vm.ssh_argv("tee", path), input=body, capture_output=True, text=True, timeout=timeout, check=False
    )
    if res.returncode != 0:
        raise RuntimeError(f"install_hook_script({name}): tee failed: rc={res.returncode} {res.stderr!r}")
    chmod = subprocess.run(
        vm.ssh_argv("/bin/chmod", "0755", path), capture_output=True, text=True, timeout=timeout, check=False
    )
    if chmod.returncode != 0:
        raise RuntimeError(f"install_hook_script({name}): chmod failed: rc={chmod.returncode} {chmod.stderr!r}")
    return name


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
    """A hook whose installed SCRIPT dumps the env to this test's ``when`` marker.

    Returns the config entry referencing a ``hook_<when>_<token>.sh`` script plus a
    transient ``_body`` (the script source) that set_update_hooks() writes into the
    on-box hook-script dir before persisting (so the runner finds + execs it). The
    script runs ``/usr/bin/env > <marker>``; read_hook_env() then parses the PFB_*
    lines back. The persisted shape == what pfb_get_hooks() reads (a flat
    ``{script, when, enabled, description, timeout}`` assoc array), so the entry runs
    (or is skipped) by the real production gate.
    """
    return {
        "script": f"hook_{when}_{token}.sh",
        "_body": f"#!/bin/sh\n/usr/bin/env > {hook_marker_path(token, when)}\n",
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
    token: str,
    *,
    when: str = "post",
    guard: str = "IP",
    enabled: str = "on",
    timeout: str = "60",
    description: str = "",
) -> dict[str, str]:
    """A recipe-shaped ``post`` hook SCRIPT that POSTs the changed-alias context to ``url``.

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

    The script is POSIX-sh-safe (``[ … ] && curl …``): when the changed list is empty
    the ``&&`` short-circuits and ``curl`` never runs (so the sink gets no callback —
    the OFF branch). ``-sS`` keeps it quiet but surfaces errors; ``-m 5`` bounds it well
    under the per-hook ``timeout``. The body is installed (via the ``_body`` key that
    set_update_hooks() writes to the hook-script dir) as ``hook_<when>_<token>_webhook_<guard>.sh``.
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
        "script": f"hook_{when}_{token}_webhook_{guard.lower()}.sh",
        "_body": f"#!/bin/sh\n{command}\n",
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
    array; only enabled==='on' + matching ``when`` + non-empty ``script`` entries (and a vetted script file)
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
    # Install each hook's script file FIRST (the transient ``_body`` key carries the
    # source; the runner only execs a hook_<when>_*.{sh,py} present in HOOK_SCRIPT_DIR),
    # then persist the entry WITHOUT ``_body`` (config stores only {script, when, ...}).
    persist: list[dict[str, str]] = []
    for hook in hooks:
        entry = dict(hook)
        body = entry.pop("_body", None)
        if body is not None:
            install_hook_script(vm, entry["script"], body, timeout=timeout)
        persist.append(entry)
    hooks_php = "array(" + ", ".join(_php_kv_array(h) for h in persist) + ")"
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
        "if (isset($r['script']) || isset($r['when']) || isset($r['enabled'])) { $r = array($r); }\n"
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
# Aggregate ("Uber") aliases (ADR-11) — the opt-in per-type aggregate selector
# --------------------------------------------------------------------------- #
# The IP-settings multi-select ``pfb_agg_types`` is a CSV SCALAR at
# CFG_GLOBAL/pfb_agg_types (e.g. "Deny,Permit"; default "" = none) — a single string
# (NOT a listtag) so it round-trips with no '<0>' list XML (mirrors blacklist_selected;
# see pfblockerng.inc:1174). For each selected Type x family, the update pass
# (sync_package_pfblockerng -> pfb_build_aggregate_aliases, inc:2144) builds the Native
# urltable alias ``pfB_<Type>_Aggregated_<family>`` (Type in {Deny,Permit,Match,Native},
# family in {v4,v6}) = the deduped/iprange'd union of that type's dir, loads it inline
# (``pfctl -T replace``), and writes a never-empty ``.lst`` consumer file under
# PFB_DBDIR. NO firewall rule (Native). Deselect/disable tears the aggregate down. A
# rebuilt aggregate's name merges into the post-hook PFB_CHANGED_IP_ALIASES.

AGG_TYPES = ("Deny", "Permit", "Match", "Native")
CFG_AGG_TYPES = CFG_GLOBAL + "/pfb_agg_types"


def aggregate_table(agg_type: str, family: str) -> str:
    """The pf table / urltable alias name for a (type, family) aggregate.

    Matches the PHP ``"pfB_{$type}_Aggregated_{$family}"`` (inc:2158) exactly — this
    is BOTH the pf table queried via ``pfctl_tables``/``pfctl_table_members`` and the
    alias name that lands in ``PFB_CHANGED_IP_ALIASES`` when the aggregate is rebuilt.
    """
    return f"pfB_{agg_type}_Aggregated_{family}"


def aggregate_consumer_path(agg_type: str, family: str) -> str:
    """The never-empty ``.lst`` consumer file path for a (type, family) aggregate.

    ``{PFB_DBDIR}/pfB_<Type>_Aggregated_<family>.lst`` — the ADR-12 HAProxy ``-f``
    consumer pfBlockerNG writes on every selected build (a ``#`` placeholder line when
    the union is empty, so the file is never empty; inc:2160, pfblockerng.sh:392).
    """
    return f"{PFB_DBDIR}/{aggregate_table(agg_type, family)}.lst"


def set_aggregate_types(vm: SmokeVM, types: list[str], *, timeout: float = 60.0) -> None:
    """Persist the ADR-11 ``pfb_agg_types`` CSV scalar at CFG_GLOBAL/pfb_agg_types.

    Mirrors :func:`set_update_hooks`'s shape: write via ``config_set_path`` +
    ``write_config``, then a READ-BACK GUARD that raises if the value did not persist —
    turning a silent non-persist into an early, precise failure. ``types`` is validated
    against the four legal action types ({Deny,Permit,Match,Native}); the stored value
    is ``implode(',', types)`` (the GUI save shape, pfblockerng_general.php:162). An
    EMPTY list stores ``""`` (the default "none" / OFF branch — no aggregate is built).

    The order is preserved as given (the PHP read intersects against the canonical
    {Deny,Permit,Match,Native} order, so functional behaviour is order-independent; we
    keep the caller's order for a faithful round-trip the read-back can compare).
    """
    bad = [t for t in types if t not in AGG_TYPES]
    if bad:
        raise ValueError(f"set_aggregate_types: invalid type(s) {bad!r}; legal: {AGG_TYPES}")
    csv = ",".join(types)
    snippet = (
        f"config_set_path({_php_str(CFG_AGG_TYPES)}, {_php_str(csv)});\n"
        "write_config('pfBlockerNG smoke: set aggregate types');\n"
        "echo 'OK';"
    )
    result = php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"set_aggregate_types failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}")
    # READ-BACK GUARD: the persisted scalar must equal the CSV we wrote.
    persisted = config_get(vm, CFG_AGG_TYPES, timeout=timeout)
    if persisted != csv:
        raise RuntimeError(f"set_aggregate_types: persisted {persisted!r} != {csv!r} written — did not round-trip")


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
    """Per-list ``logging`` value driving the block shape: 'disabled' → null
    0.0.0.0; 'nxdomain_log' → NXDOMAIN rcode (issue #31); 'enabled' → VIP."""
    return {
        DnsblMode.NULL: "disabled",
        DnsblMode.NXDOMAIN: "nxdomain_log",
        DnsblMode.VIP: "enabled",
    }[mode]


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


def _ip_list_php(spec: IpCase) -> str:
    """One IP list-group as a PHP assoc-array literal (aliasname/action/cron + its 'row')."""
    base = ", ".join(
        f"{_php_str(k)} => {_php_str(v)}"
        for k, v in (("aliasname", spec.aliasname), ("action", spec.action), ("cron", "EveryDay"))
    )
    row = {"header": spec.header, "url": spec.feed_url, "state": "Enabled", "format": "auto"}
    return f"array({base}, 'row' => array({_php_kv_array(row)}))"


def inject_ip_lists(vm: SmokeVM, specs: list[IpCase], *, timeout: float = 90.0) -> None:
    """Inject MULTIPLE IP lists in ONE config write, preserving every one.

    ``inject()`` (via ``_ip_inject_snippet``) writes a SINGLE-element array to a family's
    list-config root (``config_set_path(root, array($list))``), so calling it twice for the
    SAME family REPLACES the first list with the second. When a test needs two same-family
    lists to coexist -- e.g. a Deny + a Permit IPv4 feed for the additive-combination
    aggregate test -- use this: it groups the specs by family root and writes each root with
    ALL its list groups at once (and still sets enable_cb + the inbound/outbound interface,
    like ``inject``). Control records are applied first, per IpCase, mirroring ``inject``.
    """
    for spec in specs:
        set_control_records(vm, spec.control_local_data, spec.control_local_zone, timeout=timeout)
    by_root: dict[str, list[str]] = {}
    for spec in specs:
        root = CFG_IP_V6_LISTS if spec.family == "v6" else CFG_IP_V4_LISTS
        by_root.setdefault(root, []).append(_ip_list_php(spec))
    ipset = {"inbound_interface": SMOKE_IP_IFACE, "outbound_interface": SMOKE_IP_IFACE}
    set_roots = "".join(
        f"config_set_path({_php_str(root)}, array({', '.join(groups)}));\n" for root, groups in by_root.items()
    )
    snippet = (
        f"$g = config_get_path({_php_str(CFG_GLOBAL)}, array());\n"
        "$g['enable_cb'] = 'on';\n"
        f"config_set_path({_php_str(CFG_GLOBAL)}, $g);\n"
        f"$ip = config_get_path({_php_str(CFG_IP_SETTINGS)}, array());\n"
        f"$ip = array_merge($ip, {_php_kv_array(ipset)});\n"
        f"config_set_path({_php_str(CFG_IP_SETTINGS)}, $ip);\n"
        f"{set_roots}"
        "write_config('pfBlockerNG smoke: IP cases');\n"
        "echo 'OK';"
    )
    result = php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"inject_ip_lists failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}")


def _dnsbl_list_php(spec: DnsblCase, row_action: str = "Deny") -> str:
    """One DNSBL list-group as a PHP literal for use in :func:`inject_dnsbl_lists`.

    Mirrors ``_dnsbl_inject_snippet`` at the single-list level: builds the group's
    ``$list`` array (aliasname / action='unbound' / cron / order / logging / custom /
    row) and returns it as a PHP expression suitable for embedding in an array literal.

    ``row_action`` sets the per-primary-row ``action`` key (``'Deny'`` or ``'Permit'``).
    The default ``'Deny'`` is byte-identical to the absent-key behaviour (Phase 4 reads
    ``$row['action'] ?? ''`` and treats any non-'Permit' value as Deny); ``'Permit'``
    marks this feed as an allow-list (band 2 whiteDB, overrides block feeds).

    Only the primary feed row's action is settable here; ``extra_rows`` carry no action
    override (they inherit the Deny default). Custom_List (``spec.custom_domains``) is
    rendered as a PHP ``base64_encode()`` call for correctness across PHP string escaping.
    """
    row: dict[str, str] = {
        "header": spec.header,
        "url": spec.feed_url,
        "state": "Enabled",
        "format": "auto",
    }
    if row_action == "Permit":
        row["action"] = "Permit"
    rows = [row]
    rows += [{"header": hdr, "url": url, "state": "Enabled", "format": "auto"} for (hdr, url) in spec.extra_rows]
    rows_php = "array(" + ", ".join(_php_kv_array(r) for r in rows) + ")"
    logging_php = _php_str(_dnsbl_list_logging(spec.mode))
    if spec.custom_domains:
        crlf = "\r\n".join(spec.custom_domains)
        # base64_encode is a PHP built-in; encoding here avoids double-escaping.
        custom_php = f", 'custom' => base64_encode({_php_str(crlf)})"
    else:
        custom_php = ""
    # Build the list-group PHP array literal directly (no _php_kv_array for the outer
    # shell so we can embed the non-string 'row' and 'logging' PHP expressions).
    alias_php = _php_str(spec.aliasname)
    return (
        f"array('aliasname' => {alias_php}, 'action' => 'unbound', 'cron' => 'EveryDay',"
        f" 'order' => 'primary', 'logging' => {logging_php}, 'row' => {rows_php}{custom_php})"
    )


def inject_dnsbl_lists(
    vm: SmokeVM,
    specs_and_actions: list[tuple[DnsblCase, str]],
    *,
    timeout: float = 90.0,
) -> None:
    """Inject MULTIPLE DNSBL list-groups in ONE config write, preserving every one.

    :func:`inject` (via ``_dnsbl_inject_snippet``) calls
    ``config_set_path(CFG_DNSBL_LISTS, array($list))``, which replaces the entire DNSBL
    config with a SINGLE list-group. Calling it twice for two groups therefore discards
    the first. Use this helper when a test needs two (or more) DNSBL groups to coexist —
    for example a Deny feed and a Permit feed that share a domain (the ADR-31 §2.2.2
    contract: the Permit allow overrides the block).

    ``specs_and_actions`` is a list of ``(DnsblCase, row_action)`` pairs, where
    ``row_action`` is ``'Deny'`` (default block feed) or ``'Permit'`` (allow feed that
    loads its domains into whiteDB at band 2). Settings from the FIRST spec are used for
    the DNSBL-settings section (``pfb_dnsbl``, whitelist, etc.); per-list settings
    (logging, aliasname, custom_domains) come from each spec individually.

    Control records are applied per-spec, mirroring :func:`inject`.
    """
    if not specs_and_actions:
        raise ValueError("inject_dnsbl_lists: at least one (spec, action) pair required")
    for spec, _ in specs_and_actions:
        set_control_records(vm, spec.control_local_data, spec.control_local_zone, timeout=timeout)

    # Build the DNSBL-settings snippet from the FIRST spec (the primary block feed).
    primary_spec, _ = specs_and_actions[0]
    settings = _dnsbl_mode_settings(primary_spec.mode)
    settings["pfb_dnsbl"] = "on"
    if primary_spec.whitelist:
        settings["suppression"] = _b64_textarea(primary_spec.whitelist)
    if primary_spec.dnsbl_ip_action:
        settings["action"] = primary_spec.dnsbl_ip_action
    if primary_spec.user_regex:
        settings["pfb_regex"] = "on"
        settings["pfb_regex_list"] = _b64_textarea(primary_spec.user_regex)
    if primary_spec.regex_cap:
        settings["pfb_regex_cap"] = "on"
    if primary_spec.cname_validation:
        settings["pfb_cname"] = "on"
    if primary_spec.hsts is not None:
        settings["pfb_hsts"] = "on" if primary_spec.hsts else "off"
    if primary_spec.idn_mode is not None:
        settings["pfb_idn"] = primary_spec.idn_mode
    if primary_spec.idn_block_malicious is not None:
        settings["pfb_idn_block_malicious"] = "on" if primary_spec.idn_block_malicious else ""
    if primary_spec.idn_escalate_suspicious is not None:
        settings["pfb_idn_escalate_suspicious"] = "on" if primary_spec.idn_escalate_suspicious else ""

    # Build each list-group PHP literal.
    lists_php = ", ".join(_dnsbl_list_php(spec, action) for spec, action in specs_and_actions)
    snippet = (
        f"$g = config_get_path({_php_str(CFG_GLOBAL)}, array());\n"
        "$g['enable_cb'] = 'on';\n"
        f"config_set_path({_php_str(CFG_GLOBAL)}, $g);\n"
        f"$s = config_get_path({_php_str(CFG_DNSBL_SETTINGS)}, array());\n"
        f"$s = array_merge($s, {_php_kv_array(settings)});\n"
        f"config_set_path({_php_str(CFG_DNSBL_SETTINGS)}, $s);\n"
        f"config_set_path({_php_str(CFG_DNSBL_LISTS)}, array({lists_php}));\n"
        "write_config('pfBlockerNG smoke: DNSBL multi-list (ADR-31)');\n"
        "echo 'OK';"
    )
    result = php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"inject_dnsbl_lists failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}")


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
        # Opt-in length cap (inc:2685 -> ini regex_cap=on). Drops over-LENGTH feed AND
        # user regex at load. The catastrophic-SHAPE gate is separate and ALWAYS on
        # (pfb_unbound.py:_regex_is_catastrophic_shape), independent of this flag.
        settings["pfb_regex_cap"] = "on"
    if spec.cname_validation:
        # "CNAME Validation" (inc:852 -> ini python_cname). Walk a resolved answer's
        # CNAME chain and block the original name if a target is blocklisted.
        settings["pfb_cname"] = "on"
    if spec.hsts is not None:
        # "HSTS via Null Blocking mode" (inc:847 -> ini python_hsts). On: a VIP-mode
        # block on an HSTS-preload name is forced to NULL (pfb_unbound.py loads
        # pfb_py_hsts.txt -> hstsDB). Only emitted when the case sets it explicitly,
        # so the default matrix stays byte-for-byte unchanged. See add_hsts_name.
        settings["pfb_hsts"] = "on" if spec.hsts else "off"
    if spec.idn_mode is not None:
        # "IDN Blocking" selector (ADR-08; CFG_DNSBL_SETTINGS/pfb_idn -> ini idn_mode).
        # 'confusable' runs the TR39 homoglyph analyzer; the two sub-toggles map to the
        # ini keys the matcher reads (python_idn_block_malicious / _escalate_suspicious).
        # Only emitted when the case sets it, so the default matrix is unchanged.
        settings["pfb_idn"] = spec.idn_mode
    if spec.idn_block_malicious is not None:
        settings["pfb_idn_block_malicious"] = "on" if spec.idn_block_malicious else ""
    if spec.idn_escalate_suspicious is not None:
        settings["pfb_idn_escalate_suspicious"] = "on" if spec.idn_escalate_suspicious else ""
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
    case), ``update`` (full force, IP+DNSBL), or ``cron`` (the scheduled cron
    tick, ``pfblockerng_sync_cron()``). NOTE: ``cron`` is the ONLY verb that runs
    the ADR-30 per-log scheduled reset (``pfb_log_reset()``); ``update`` calls
    ``sync_package_pfblockerng('cron')`` directly and bypasses it, so a test that
    needs a scheduled log reset to fire MUST use ``cron``, not ``update``.

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
    if scope not in ("update", "updateip", "updatednsbl", "cron"):
        raise ValueError(f"reload scope must be update/updateip/updatednsbl/cron, got {scope!r}")
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


# --------------------------------------------------------------------------- #
# Reboot — restart the guest OS, then wait until it is fully usable again
# --------------------------------------------------------------------------- #
# conftest.smoke_vm is ONE long-lived boot whose copy-on-write overlay IS the guest
# disk, so a guest ``/sbin/reboot`` restarts the OS while QEMU, the overlay,
# /conf/config.xml and /var/db all survive -- exactly the boot path issue #334 is
# about (``is_platform_booting()`` true). A test that reboots carries the ``reboot``
# marker (deselected from ``-m smoke``): the reboot mutates the SHARED session VM, so
# it must run in its own dispatch, not interleaved with the per-case smoke matrix.


def kern_boottime(vm: SmokeVM, *, timeout: float = 15.0) -> str:
    """The guest's ``kern.boottime`` sysctl -- a token unique to each boot.

    It changes on every real reboot, so comparing it before/after PROVES the box
    actually went down and came back, rather than the harness reconnecting to a
    still-alive pre-reboot sshd. Returns '' when unreadable (SSH down mid-reboot)."""
    result = vm.ssh("/sbin/sysctl", "-n", "kern.boottime", timeout=timeout)
    return result.stdout.strip() if result.returncode == 0 else ""


def reboot_vm(vm: SmokeVM, *, timeout: float = DEFAULT_BOOT_TIMEOUT, poll: float = 5.0) -> None:
    """Reboot the guest OS and block until it is usable again (SSH + web + Unbound).

    Each step guards against a FALSE "ready":

      1. Capture ``kern.boottime`` BEFORE the reboot.
      2. Issue ``/sbin/reboot`` -- best-effort: the command tears down our SSH
         session, so a non-zero / dropped result is EXPECTED, not an error.
      3. Poll ``kern.boottime`` until it is readable AND differs from the captured
         value. This proves the OS rebooted and cleanly steps over the brief window
         where the OLD sshd still answers (same boottime) before it dies.
      4. Run ``wait_ready.sh`` (watching the QEMU pid + the web port) so the
         webConfigurator (nginx + PHP) is up, then ``wait_unbound_ready`` -- the
         same full-readiness gate the initial boot uses.
    """
    # Capture a NON-EMPTY boottime baseline first: an empty '' baseline (SSH transiently
    # unreadable) would let the first readable post-reboot boottime compare unequal and
    # falsely report a reboot that never happened. The box is known-ready here, so a short
    # retry is enough.
    before = ""
    baseline_deadline = time.monotonic() + 30.0
    while time.monotonic() < baseline_deadline:
        before = kern_boottime(vm)
        if before:
            break
        time.sleep(poll)
    if not before:
        raise RuntimeError("reboot_vm: could not read a kern.boottime baseline before rebooting")
    # The reboot drops the SSH connection; ignore the result (best-effort).
    vm.ssh("/sbin/reboot", timeout=30.0)

    deadline = time.monotonic() + timeout
    rebooted = False
    while time.monotonic() < deadline:
        now = kern_boottime(vm)
        if now and now != before:
            rebooted = True
            break
        time.sleep(poll)
    if not rebooted:
        raise RuntimeError(f"reboot_vm: guest did not reboot within {timeout}s (kern.boottime stayed {before!r})")

    # Full readiness via the same shell gate the initial boot uses. wait_ready.sh's
    # positional args are <ssh-key> [host] [port] [timeout] [vm-pid] [web-port]; pass
    # the vm-pid + web-port pair only when the pid is known (so a dead boot fails fast
    # AND web readiness requires nginx+PHP, not just sshd).
    wait_budget = int(max(1.0, deadline - time.monotonic()))
    argv = [
        "sh",
        str(WAIT_READY_SH),
        vm.ssh_key_path,
        vm.host,
        str(vm.ssh_port),
        str(wait_budget),
    ]
    if vm.vm_pid is not None:
        argv += [str(vm.vm_pid), str(vm.web_port)]
    # Cap the subprocess itself a little past the script's own budget, so a stalled
    # wait_ready.sh can never hang the (timeout-exempt) module fixture indefinitely.
    try:
        result = subprocess.run(argv, capture_output=True, text=True, check=False, timeout=wait_budget + 30)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"reboot_vm: wait_ready.sh did not return within {wait_budget + 30}s") from exc
    if result.returncode != 0:
        raise RuntimeError(
            f"reboot_vm: VM not ready after reboot (wait_ready exit {result.returncode}); stderr={result.stderr!r}"
        )
    wait_unbound_ready(vm)


# pfBlockerNG archives its IP aliastables + DNSBL DB here for RAMDISK installs; the
# earlyshellcmd `pfblockerng.sh aliastables` restores it on boot (pfblockerng.inc:7791,
# pfblockerng.sh:208). Present only after an `update` runs with use_mfs_tmpvar enabled.
ALIASARCHIVE = "/usr/local/etc/aliastables.tar.bz2"


def set_ramdisk(vm: SmokeVM, on: bool, *, var_size: int = 512, tmp_size: int = 128, timeout: float = 60.0) -> None:
    """Enable/disable pfSense RAM disks for /tmp and /var (takes effect on next boot).

    pfSense mounts /tmp and /var as memory filesystems when ``<system><use_mfs_tmpvar>``
    is present (``system_advanced_misc.php``); sizes are MiB (GUI minimums: /tmp 40,
    /var 60). The element's mere PRESENCE is "enabled" — both pfSense's
    ``config_path_enabled('system', 'use_mfs_tmpvar')`` (pfblockerng.inc:7777) and the
    shell's ``grep -c use_mfs_tmpvar`` (pfblockerng.sh:101) key on it.

    On the conversion reboot pfSense WIPES /var, so pfBlockerNG's earlyshellcmd restores
    its aliastables from :data:`ALIASARCHIVE` — the exact path issue #334 exercises on a
    RAMDISK install. ``var_size`` is generous (the default 60 MiB is tight for the
    unbound chroot + pfBlockerNG DB on a 4 GB box).
    """
    if on:
        snippet = (
            f"config_set_path('system/use_mfs_tmpvar', '');\n"
            f"config_set_path('system/use_mfs_var_size', {_php_str(str(var_size))});\n"
            f"config_set_path('system/use_mfs_tmp_size', {_php_str(str(tmp_size))});\n"
            "write_config('pfBlockerNG smoke: enable RAM disks');\necho 'OK';"
        )
    else:
        snippet = (
            "config_del_path('system/use_mfs_tmpvar');\n"
            "write_config('pfBlockerNG smoke: disable RAM disks');\necho 'OK';"
        )
    result = php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"set_ramdisk({on}) failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}")


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
# The DNSBL per-line parse-error log: pfb_parsed_fail() appends one CSV record
# ({date},{header},{line},{oline}) here for every rejected line — including an ADR-22
# strict-mode scheme/path skip. Mirrors $pfb['dnsbl_parse_err'] (inc:88,
# "{$pfb['logdir']}/dnsbl_parsed_error.log"), the established per-line failure sink.
DNSBL_PARSE_ERR_LOG = f"{PFB_LOGDIR}/dnsbl_parsed_error.log"


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
# DNSBL Control channel (PFBL-03) — CLI driver + applied-marker observation
# --------------------------------------------------------------------------- #
# PFBL-03 moved DNSBL runtime control (disable/enable/addbypass/removebypass) off
# in-band DNS-TXT queries onto a local privileged command channel + a CLI. The
# operator CLI is the ``dnsbl-control`` action of the package shell script
# (``pfblockerng.sh dnsbl-control …``), which forwards to ``pfblockerng.php
# dnsbl-control …`` — the PHP writer validates the command and atomically publishes
# a JSON record to the chroot channel ``/var/unbound/pfb_py_control``; the in-module
# reader thread (``pfb_control_watcher``) applies it and writes the applied sequence
# to ``/var/unbound/pfb_py_control.applied``. The reader thread starts only when the
# DNSBL Control toggle (``pfb_control`` -> ini ``python_control``) is on.

PFB_SH = "/usr/local/pkg/pfblockerng/pfblockerng.sh"
# Host paths of the in-chroot channel + applied-sequence marker (Unbound's CWD is
# /var/unbound, so the module's relative names live here on the host).
UNBOUND_CONTROL_FILE = "/var/unbound/pfb_py_control"
UNBOUND_CONTROL_APPLIED_FILE = "/var/unbound/pfb_py_control.applied"


def set_dnsbl_control(vm: SmokeVM, on: bool, *, timeout: float = 60.0) -> None:
    """Toggle the DNSBL Control feature (``pfb_control`` -> ini ``python_control``).

    On: the next reload writes ``python_control = on`` to pfb_unbound.ini and the
    reader thread (``pfb_control_watcher``) starts, so CLI commands take effect.
    Off: the thread never starts and the channel is ignored.
    """
    val = "on" if on else ""
    snippet = (
        f"$d = config_get_path({_php_str(CFG_DNSBL_SETTINGS)}, array());\n"
        f"$d['pfb_control'] = {_php_str(val)};\n"
        f"config_set_path({_php_str(CFG_DNSBL_SETTINGS)}, $d);\n"
        "write_config('pfBlockerNG smoke: toggle pfb_control');\n"
        "echo 'OK';"
    )
    result = php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(
            f"set_dnsbl_control({on}) failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}"
        )


def set_dnsbl_control_legacy(vm: SmokeVM, on: bool, *, timeout: float = 60.0) -> None:
    """Toggle the deprecated DNS-TXT control sub-path (``pfb_control_legacy`` -> ini
    ``python_control_legacy``).

    The ini key is written ``on`` only when BOTH ``pfb_control`` and
    ``pfb_control_legacy`` are on (inc:4744); with it off (default) the in-band
    ``python_control.*`` DNS-TXT branch in ``operate()`` is inert.
    """
    val = "on" if on else ""
    snippet = (
        f"$d = config_get_path({_php_str(CFG_DNSBL_SETTINGS)}, array());\n"
        f"$d['pfb_control_legacy'] = {_php_str(val)};\n"
        f"config_set_path({_php_str(CFG_DNSBL_SETTINGS)}, $d);\n"
        "write_config('pfBlockerNG smoke: toggle pfb_control_legacy');\n"
        "echo 'OK';"
    )
    result = php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(
            f"set_dnsbl_control_legacy({on}) failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}"
        )


def assert_control_ini(vm: SmokeVM, *, control: bool, legacy: bool, timeout: float = 30.0) -> None:
    """Precondition guard: the generated ini matches the expected control flags.

    Confirms ``python_control`` / ``python_control_legacy`` are ``on``/``off`` in
    ``pfb_unbound.ini`` so a control assertion can be attributed to the feature gate
    (not a config-write miss). The reader thread keys on ``python_control``; the
    DNS-TXT branch keys on ``python_control_legacy``.
    """
    ini = vm.ssh("cat", UNBOUND_PFB_INI, timeout=timeout)
    want_control = "on" if control else "off"
    want_legacy = "on" if legacy else "off"
    if not re.search(rf"(?im)^\s*python_control\s*=\s*{want_control}\b", ini.stdout):
        raise AssertionError(f"python_control != {want_control} in {UNBOUND_PFB_INI}:\n{ini.stdout}")
    if not re.search(rf"(?im)^\s*python_control_legacy\s*=\s*{want_legacy}\b", ini.stdout):
        raise AssertionError(f"python_control_legacy != {want_legacy} in {UNBOUND_PFB_INI}:\n{ini.stdout}")


def dnsbl_control_cli(vm: SmokeVM, *args: str, timeout: float = 30.0) -> int:
    """Run the operator CLI ``pfblockerng.sh dnsbl-control <args…>`` ON the guest as root.

    This is the REAL operator entry point: the shell action forwards the positional
    args to ``pfblockerng.php dnsbl-control``, whose writer validates and publishes the
    command record to the control channel. Returns the published sequence number parsed
    from the CLI's ``queued (seq N)`` line. Raises on a non-zero exit or unparsable output
    so an invalid/rejected command is a hard failure, never a silent pass.
    """
    result = vm.ssh("/bin/sh", PFB_SH, "dnsbl-control", *args, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(
            f"dnsbl-control {args} failed: rc={result.returncode} stdout={result.stdout!r} stderr={result.stderr!r}"
        )
    m = re.search(r"\(seq\s+(\d+)\)", result.stdout)
    if not m:
        raise RuntimeError(f"dnsbl-control {args}: no '(seq N)' in CLI output: {result.stdout!r}")
    return int(m.group(1))


def read_control_applied(vm: SmokeVM, *, timeout: float = 30.0) -> int | None:
    """The applied-sequence marker the reader publishes, or ``None`` if absent/empty."""
    return read_py_int(vm, UNBOUND_CONTROL_APPLIED_FILE, timeout=timeout)


def wait_control_applied(vm: SmokeVM, seq: int, *, timeout: float = 30.0, interval: float = 1.0) -> int:
    """Poll the applied marker until it has advanced to (at least) ``seq``; raise on timeout.

    The reader applies the command then republishes the consumed sequence — so the
    marker reaching ``seq`` proves the command was CONSUMED. A bounded poll (no fixed
    sleep) mirrors the other async-settle primitives; raising on timeout surfaces "the
    command was never applied" rather than masking it.
    """
    deadline = time.monotonic() + timeout
    last: int | None = None
    while time.monotonic() < deadline:
        last = read_control_applied(vm, timeout=timeout)
        if last is not None and last >= seq:
            return last
        time.sleep(interval)
    raise RuntimeError(
        f"wait_control_applied: applied marker never reached seq {seq} within {timeout}s "
        f"(last seen {last}) — the control reader did not consume the command"
    )


def drill_txt(vm: SmokeVM, name: str, *, timeout: float = 30.0) -> subprocess.CompletedProcess[str]:
    """Issue a TXT query for ``name`` against the on-box resolver (``drill <name> TXT @127.0.0.1``).

    Used to drive the deprecated in-band ``python_control.<cmd>`` DNS-TXT path: the side
    effect (whether DNSBL blocking changes) is what the test asserts via a follow-up
    A-record probe, NOT the TXT answer — so this returns the raw process for diagnostics.
    """
    return vm.ssh(f"{DRILL_BIN} {shlex.quote(name)} TXT @127.0.0.1", timeout=timeout)


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


def wait_pfctl_table(vm: SmokeVM, name: str, *, timeout: float = 30.0, interval: float = 2.0) -> list[str]:
    """Poll ``pfctl -t <name> -T show`` until the table EXISTS and is NON-EMPTY.

    Returns the members once populated, or ``[]`` on timeout — the caller asserts
    on the result, so a genuine failure surfaces as a clear assertion (with the
    per-run diagnostics snapshot already uploaded), never an open-ended hang.

    A BOUNDED poll is the right primitive here precisely because DNSBL-IP table
    population is legitimately ASYNC: ``filter_configure`` lands ``pfB_DNSBLIP_v4``/
    ``pfB_DNSBLIP_v6`` slightly AFTER ``pfblockerng.php update`` returns (the tables
    are absent on a synchronous read right after the reload, but present in teardown
    diagnostics — issue #35). This is NOT the ADR-04 "first response is authoritative"
    DNS case (that holds after :func:`wait_unbound_ready`, where the first answer is
    the truth); it mirrors the :func:`rule_references` reload-lag poll instead.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if name in pfctl_tables(vm):
            members = pfctl_table_members(vm, name)
            if members:
                return members
        time.sleep(interval)
    return []


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


def member_covers(members: list[str], ip: str) -> bool:
    """True iff ``ip`` is CONTAINED in any member entry, treating each as a network.

    Stronger than :func:`member_present` (which matches an exact IP or a member's network
    *address*): this tests CIDR containment, needed when an aggregate's ``iprange`` collapse
    has folded ``ip`` into a SUPERNET. E.g. an aggregate holding ``198.51.100.16/31`` covers
    both ``.16`` and ``.17`` — an exact check for ``.17`` misses it, but ``.17`` is genuinely
    in the set. Malformed members / a bad ``ip`` are skipped (return False), never raise.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for m in members:
        try:
            if addr in ipaddress.ip_network(m, strict=False):
                return True
        except ValueError:
            continue
    return False


# --------------------------------------------------------------------------- #
# Diagnostics — dump live box state on a failed case (printed to the CI log)
# --------------------------------------------------------------------------- #

REDACTED = "REDACTED"

# ADR-24: Spring-Boot-Actuator-style sensitive-KEY redaction. Scrubs the inner text
# of any config.xml element whose TAG NAME looks sensitive — auto-catching unknown
# Plus license/token/secret tags by name, without enumerating them. Mirrors Spring
# Boot Actuator's default keys-to-sanitize
# (password / secret / key / token / *credentials* — suffix/regex match on the key
# name, value -> placeholder). Lowercase; the lone `key` entry is a deliberately
# broad Actuator-style suffix that may over-redact (e.g. `<monkey>`): over-redaction
# in diagnostics is safe, under-redaction of a secret is not.
_SENSITIVE_TAG_WORDS: tuple[str, ...] = (
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "authkey",
    "privatekey",
    "passphrase",
    "psk",
    "credential",
    "key",
)

# Built ONCE from _SENSITIVE_TAG_WORDS so the Python and `sed` redactors below share
# the exact same alternation and can never drift. A tag name is `[a-z0-9_:-]*`
# ending in one of the words, optionally followed by a single plural `s`.
_SENSITIVE_TAG_ALTERNATION = "|".join(_SENSITIVE_TAG_WORDS)
_SENSITIVE_TAG_PATTERN = re.compile(r"(<[a-z0-9_:-]*(?:" + _SENSITIVE_TAG_ALTERNATION + r")s?>)[^<]*", re.IGNORECASE)


def redact_sensitive_xml_tags(text: str) -> str:
    """Replace the inner text of every config.xml element whose OPENING tag name
    looks sensitive (Spring-Boot-Actuator style) with ``REDACTED``.

    A tag name is matched when it is composed of ``[a-z0-9_:-]`` and ENDS WITH one
    of :data:`_SENSITIVE_TAG_WORDS`, optionally followed by a single plural ``s``
    (so ``<token>`` and ``<tokens>`` both match, as do compound names like
    ``<api_token>`` / ``<wg_privatekey>``). The opening tag is preserved verbatim;
    only the inner text up to the next ``<`` is replaced. Only OPENING tags
    (``<name>…``) match — never closing tags (``</name>``, excluded because the name
    charset omits ``/``) — so element structure is never corrupted.

    Match is CASE-INSENSITIVE (``re.IGNORECASE`` here, the ``I`` sed flag in the
    counterpart): pfSense ``config.xml`` tag names are machine-generated lowercase,
    but matching any case is strictly safer (a stray ``<TOKEN>`` is still scrubbed)
    and costs nothing.

    Pure Python — the in-guest scrub uses the equivalent ``sed`` program from
    :func:`sensitive_tag_sed_program`; the two are pinned together by a parity test.
    """
    return _SENSITIVE_TAG_PATTERN.sub(r"\1" + REDACTED, text)


def sensitive_tag_sed_program() -> str:
    """Return the ``sed -E`` substitution that performs the SAME redaction as
    :func:`redact_sensitive_xml_tags`.

    Delimiter ``#``, constant replacement ``REDACTED``, alternation built from
    :data:`_SENSITIVE_TAG_WORDS` (so the shell and Python redactors cannot drift).
    The ``I`` flag makes it case-insensitive — supported by both FreeBSD ``sed``
    (in-guest) and GNU ``sed`` — mirroring the Python pattern's ``re.IGNORECASE``.
    """
    return "s#(<[a-z0-9_:-]*(" + _SENSITIVE_TAG_ALTERNATION + ")s?>)[^<]*#\\1" + REDACTED + "#gI"


# --------------------------------------------------------------------------- #
# ADR-24 — value-based redaction of the pfSense Plus secret VM identity
# --------------------------------------------------------------------------- #
# The Plus source-VM MAC + SMBIOS uuid (and, if supplied, the Netgate Device ID)
# are LICENSE/NDI-keyed secrets — they come from the SMOKE_PLUS_MAC /
# SMOKE_PLUS_SMBIOS_UUID (/ SMOKE_PLUS_NDI) GitHub secrets, NEVER the public
# ci-metadata matrix. Booting the licensed Plus image in CI puts those values into
# the diagnostics bundle (the MAC lands in ifconfig.txt, the uuid in dmesg.txt,
# both can surface in /var/log), so a live Plus run would otherwise LEAK them in an
# uploaded artifact. The set is supplied newline-/comma-joined via
# SMOKE_REDACT_VALUES (smoke.yml builds it for the Plus leg only) plus the live
# in-guest serial; a CE leg sets it empty -> the parsed set is empty -> every
# redactor below is a strict no-op and the CE bundle stays byte-identical.

# Generic SMBIOS placeholders that are NOT secrets — `kenv smbios.system.serial`
# returns one of these on hardware/VMs without a real serial. Redacting them would
# scrub harmless ubiquitous strings out of the logs (and could even no-op-mangle
# unrelated text), so they are dropped from the redaction set.
_SMBIOS_PLACEHOLDERS = frozenset(
    {
        "not specified",
        "to be filled by o.e.m.",
        "0",
        "none",
        "default string",
    }
)


def _sed_escape_literal(value: str) -> str:
    """Escape ``value`` so it is safe as the PATTERN of a ``sed`` BRE ``s###``
    substitution (the in-guest/runner shell redactor).

    The substitution uses ``#`` as the delimiter and a constant replacement
    (``REDACTED``), so only the PATTERN side needs escaping. In a POSIX BRE the
    active metacharacters are ``\\ . * [ ] ^ $`` (``^``/``$`` only as anchors, but
    escaping them unconditionally is safe and simpler); the chosen delimiter ``#``
    must also be escaped so a value containing it cannot terminate the pattern.
    Backslash is escaped FIRST so the escapes we add are not themselves re-escaped.
    """
    out = value.replace("\\", "\\\\")
    for ch in (".", "*", "[", "]", "^", "$", "#"):
        out = out.replace(ch, "\\" + ch)
    return out


def redact_values(text: str, values: Iterable[str]) -> str:
    """Replace every non-empty ``value`` (matched LITERALLY, not as a regex, and
    CASE-INSENSITIVELY) in ``text`` with ``REDACTED``.

    Case-insensitive to mirror the ``s###REDACTED###gI`` sed flag the shell paths
    use, so an upper-case MAC/uuid secret still scrubs its lower-case rendering.
    Pure Python — pinned in the unit suite against the shell ``sed`` redactor
    (:func:`_sed_escape_literal` parity). Empty / whitespace-only values are ignored
    (an empty needle would otherwise match everywhere). With an empty ``values`` this
    is the identity function — the load-bearing CE no-op.
    """
    out = text
    for value in values:
        if value and value.strip():
            # Case-insensitive (mirrors the `s###gI` sed flag) so an upper-case secret
            # still matches the lower-case MAC/uuid that ifconfig/dmesg/logs emit.
            out = re.sub(re.escape(value), REDACTED, out, flags=re.IGNORECASE)
    return out


def parse_redact_values(raw: str | None) -> list[str]:
    """Parse ``SMOKE_REDACT_VALUES`` into the de-duplicated literal redaction set.

    The raw env value is newline- and/or comma-separated. Each token is stripped;
    empties and obviously-generic SMBIOS placeholders (``Not Specified``,
    ``To Be Filled By O.E.M.``, ``0``, ``None``, ``Default string``,
    case-insensitive) are dropped — they are not secrets and redacting them would
    mangle unrelated diagnostics. ``None`` / empty -> ``[]`` (the CE no-op).
    """
    if not raw:
        return []
    seen: set[str] = set()
    values: list[str] = []
    for token in raw.replace(",", "\n").split("\n"):
        value = token.strip()
        if not value or value.lower() in _SMBIOS_PLACEHOLDERS:
            continue
        if value not in seen:
            seen.add(value)
            values.append(value)
    return values


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
    # ADR-24: value-based redaction of the Plus secret VM identity. Active IFF
    # SMOKE_REDACT_VALUES parses to a non-empty set; CE legs (no secret) -> empty
    # -> redaction is a strict no-op and the emitted script below is byte-identical
    # to before (the CE bundle is unchanged).
    redact_values_set = parse_redact_values(os.environ.get("SMOKE_REDACT_VALUES"))

    # config.xml secret scrub. The explicit credential substitutions
    # (bcrypt/prv/authorizedkeys/tls_certificate) stay belt-and-suspenders — they are
    # NOT name-matched by the sensitive-tag pass. ADR-24: the Actuator-style
    # sensitive-TAG pass (sensitive_tag_sed_program) is APPENDED to the SAME single
    # sed invocation, after the explicit ones, so it runs for EVERY leg.
    config_scrub = (
        "sed -E 's#(<bcrypt-hash>)[^<]*#\\1REDACTED#g; s#(<prv>)[^<]*#\\1REDACTED#g; "
        "s#(<authorizedkeys>)[^<]*#\\1REDACTED#g; s#(<tls_certificate>)[^<]*#\\1REDACTED#g; "
        + sensitive_tag_sed_program()
        + "' "
        '/conf/config.xml > "$D/config.scrubbed.xml" 2>/dev/null; '
    )

    # /var/log: tarred directly when value-redaction is OFF; when ON it is STAGED
    # (cp -a) so the per-bundle redaction pass below can scrub the log text in place
    # before the stage is tarred — the secret MAC/uuid can surface in /var/log too.
    var_log_capture = 'tar czf "$D/var_log.tgz" -C /var log 2>/dev/null; '

    # Value-redaction pass (Plus only). The MAC lives in ifconfig.txt, the SMBIOS
    # uuid in dmesg.txt, and either can land in the staged /var/log — so the WHOLE
    # bundle (config.scrubbed.xml, the var_log stage, ifconfig/dmesg/ps/sockstat/
    # netstat, the unbound *.conf copies, …) is scrubbed, not just config + logs.
    # A redact.sed program (one literal s###REDACTED### per maintainer value, BRE-
    # escaped) is emitted once, the live in-guest serial appended (escaped the same
    # way), then run over every TEXT file in $D (grep -Iq . detects text).
    build_redact_sed = ""
    redact_bundle = ""
    if redact_values_set:
        # `I` flag = case-insensitive (supported by both FreeBSD sed in-guest and GNU
        # sed on the runner), so an upper-case secret still matches the lower-case
        # MAC/uuid that ifconfig/dmesg/logs emit.
        sed_prog = "".join(f"s#{_sed_escape_literal(v)}#{REDACTED}#gI;" for v in redact_values_set)
        # In-guest BRE-escape of the live serial — SAME metachar set + order as
        # _sed_escape_literal (`\` first, then `. * [ ] ^ $ #`), one `-e` per
        # metachar (NOT a bracket-class: a class like `[\.*[]^$#]` closes early at
        # the first `]` and escapes nothing) — so the shell and Python redactors
        # agree (pinned by the parity test).
        serial_esc = (
            "sed -e 's/\\\\/\\\\\\\\/g' -e 's/\\./\\\\./g' -e 's/\\*/\\\\*/g' "
            "-e 's/\\[/\\\\[/g' -e 's/\\]/\\\\]/g' -e 's/\\^/\\\\^/g' "
            "-e 's/\\$/\\\\$/g' -e 's/#/\\\\#/g'"
        )
        build_redact_sed = (
            f"printf '%s' {shlex.quote(sed_prog)} > \"$D/redact.sed\"; "
            "S=$(kenv -q smbios.system.serial 2>/dev/null); "
            # Drop generic SMBIOS placeholders case-insensitively (mirror parse_redact_values).
            "SL=$(printf '%s' \"$S\" | tr '[:upper:]' '[:lower:]'); "
            "case \"$SL\" in 'not specified'|'to be filled by o.e.m.'|'0'|'none'|'default string'|'') S='' ;; esac; "
            'if [ -n "$S" ]; then '
            f"ES=$(printf '%s' \"$S\" | {serial_esc}); "
            # `I` flag → case-insensitive, so a differently-cased serial rendering scrubs too.
            'printf \'s#%s#REDACTED#gI;\' "$ES" >> "$D/redact.sed"; '
            "fi; "
        )
        var_log_capture = 'cp -a /var/log "$D/var_log_stage" 2>/dev/null; '
        # Run AFTER every file is collected (so it also catches the var_log stage,
        # ifconfig.txt, dmesg.txt, the unbound confs, …) and BEFORE the final tar.
        # redact.sed itself is removed so the program (which embeds the literals) is
        # never shipped in the bundle. Then the staged /var/log is tarred + dropped.
        redact_bundle = (
            'find "$D" -type f ! -name redact.sed 2>/dev/null | while IFS= read -r f; do '
            'LC_ALL=C grep -Iq . "$f" 2>/dev/null && sed -i \'\' -f "$D/redact.sed" "$f" 2>/dev/null; '
            "done; "
            'rm -f "$D/redact.sed" 2>/dev/null; '
            'tar czf "$D/var_log.tgz" -C "$D" var_log_stage 2>/dev/null; '
            'rm -rf "$D/var_log_stage" 2>/dev/null; '
        )

    script = (
        'set +e; D=/tmp/pfb_smoke_diag; rm -rf "$D"; mkdir -p "$D/unbound"; '
        + build_redact_sed
        + var_log_capture
        + '/sbin/dmesg > "$D/dmesg.txt" 2>&1; cp /var/run/dmesg.boot "$D/dmesg.boot" 2>/dev/null; '
        '/sbin/pfctl -sa > "$D/pfctl_sa.txt" 2>&1; '
        '/sbin/ifconfig -a > "$D/ifconfig.txt" 2>&1; '
        '/usr/bin/sockstat > "$D/sockstat.txt" 2>&1; /usr/bin/netstat -rn > "$D/netstat_rn.txt" 2>&1; '
        'cp /var/unbound/*.conf /var/unbound/*.ini "$D/unbound/" 2>/dev/null; '
        'cp /var/unbound/pfb_py_* "$D/unbound/" 2>/dev/null; '
        # The chroot python script + its include — NOT matched by the globs above, yet
        # central to a "pythonmod: can't open file" resolver failure, so capture them
        # explicitly (their presence/absence is the ground truth for a staging desync).
        'cp /var/unbound/pfb_unbound.py "$D/unbound/" 2>/dev/null; '
        'cp /var/unbound/pfb_unbound_include.inc "$D/unbound/" 2>/dev/null; '
        # pfBlockerNG database (feeds / masterfiles / orig / deny / dnsbl / …) and
        # pfSense's pf alias-table files — the IP/domain state behind the rules.
        'tar czf "$D/var_db_pfblockerng.tgz" -C /var/db pfblockerng 2>/dev/null; '
        'tar czf "$D/var_db_aliastables.tgz" -C /var/db aliastables 2>/dev/null; '
        '/bin/ps auxww > "$D/ps.txt" 2>&1; '
        # Scrub secrets from config.xml BEFORE it leaves the box.
        + config_scrub
        # ADR-24: value-redact the Plus secret identity across the WHOLE bundle
        # (no-op for CE — redact_bundle is empty), then tar.
        + redact_bundle
        + f"tar czf {remote_tar} -C /tmp pfb_smoke_diag 2>/dev/null; true"
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


# --------------------------------------------------------------------------- #
# IPv6 locality helpers — issue #361 live-VM coverage
# --------------------------------------------------------------------------- #

# RFC 3849 documentation-range constants used by the locality smoke tests.
# These are inert (documentation range only; no internet routing).
IPV6_LOCAL_IFACE = "lan"  # LAN — never touches the WAN/SSH path
IPV6_LOCAL_ADDR = "2001:db8:51:1::1"  # static address on the LAN interface
IPV6_LOCAL_BITS = 64  # prefix length → /64
IPV6_LOCAL_SUBNET = "2001:db8:51:1::"  # network address of the /64
IPV6_LOCAL_HOST = "2001:db8:51:1::1234"  # a host INSIDE the /64
IPV6_FOREIGN = "2001:db8:dead:beef::1"  # OUTSIDE the /64 → must be foreign

# ip_block.log lives here on a pfSense guest (pfblockerng.inc:81).
IP_BLOCK_LOG = "/var/log/pfblockerng/ip_block.log"


def set_interface_ipv6(
    vm: SmokeVM,
    iface: str,
    addr: str,
    bits: int,
    *,
    timeout: float = 120.0,
) -> dict[str, str]:
    """Set a static IPv6 address on ``iface`` and return the prior IPv6 config.

    Writes ``ipaddrv6 = addr`` and ``subnetv6 = str(bits)`` to the
    ``interfaces/<iface>`` config section, calls ``interface_configure()`` to
    apply the address to the OS, then polls ``get_configured_ipv6_addresses()``
    until the address is live (up to 20 s).

    Only the LAN interface (``IPV6_LOCAL_IFACE``) should be used here: the WAN
    interface carries the SLIRP-NAT SSH path; changing its IPv6 config risks
    disconnecting the guest.

    Returns the *prior* IPv6 keys so the caller can restore them in ``finally``:
    ``{"ipaddrv6": <old_ipaddrv6>, "subnetv6": <old_subnetv6>}`` (empty strings
    when the keys were absent).
    """
    # Read the prior IPv6 config first so the caller can restore on teardown.
    prior_snippet = (
        f"$iface = config_get_path({_php_str('interfaces/' + iface)}, array());\n"
        f"echo {_php_str(_CFG_VAL_OPEN)}"
        " . ($iface['ipaddrv6'] ?? '')"
        f" . {_php_str('|||')}"
        " . ($iface['subnetv6'] ?? '')"
        f" . {_php_str(_CFG_VAL_CLOSE)};"
    )
    prior_result = php_eval(vm, prior_snippet, timeout=timeout)
    out = prior_result.stdout
    start = out.find(_CFG_VAL_OPEN)
    end = out.find(_CFG_VAL_CLOSE)
    if start == -1 or end == -1:
        raise RuntimeError(f"set_interface_ipv6: could not read prior config: rc={prior_result.returncode} out={out!r}")
    inner = out[start + len(_CFG_VAL_OPEN) : end]
    parts = inner.split("|||", 1)
    prior = {"ipaddrv6": parts[0], "subnetv6": parts[1] if len(parts) > 1 else ""}

    # Apply the new static IPv6 via pfSsh.php → the pfSense config API.
    # interface_configure() brings the address up on the OS level.
    snippet = (
        "require_once('interfaces.inc');\n"
        f"$iface = config_get_path({_php_str('interfaces/' + iface)}, array());\n"
        f"$iface['ipaddrv6'] = {_php_str(addr)};\n"
        f"$iface['subnetv6'] = {_php_str(str(bits))};\n"
        f"config_set_path({_php_str('interfaces/' + iface)}, $iface);\n"
        "write_config('pfBlockerNG smoke: set static IPv6 for locality test');\n"
        f"if (function_exists('interface_configure')) {{ interface_configure({_php_str(iface)}); }}\n"
        "echo 'OK';"
    )
    result = php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(
            f"set_interface_ipv6({iface}, {addr}/{bits}) failed: "
            f"rc={result.returncode} {result.stderr!r} {result.stdout!r}"
        )

    # Poll until get_configured_ipv6_addresses() returns the address (≤20 s).
    deadline = time.monotonic() + 20.0
    while time.monotonic() < deadline:
        live_snippet = (
            "$addrs = get_configured_ipv6_addresses();\n"
            f"echo {_php_str(_CFG_VAL_OPEN)}"
            " . (isset($addrs[" + _php_str(iface) + "]) ? $addrs[" + _php_str(iface) + "] : '')"
            f" . {_php_str(_CFG_VAL_CLOSE)};"
        )
        live_result = php_eval(vm, live_snippet, timeout=30.0)
        lout = live_result.stdout
        ls = lout.find(_CFG_VAL_OPEN)
        le = lout.find(_CFG_VAL_CLOSE)
        if ls != -1 and le != -1:
            live_addr = lout[ls + len(_CFG_VAL_OPEN) : le].strip()
            if live_addr == addr:
                return prior
        time.sleep(1.0)
    raise RuntimeError(
        f"set_interface_ipv6({iface}, {addr}/{bits}): address never appeared in "
        f"get_configured_ipv6_addresses() within 20 s"
    )


def restore_interface_ipv6(
    vm: SmokeVM,
    iface: str,
    prior: dict[str, str],
    *,
    timeout: float = 120.0,
) -> None:
    """Restore the IPv6 config on ``iface`` to the state saved by :func:`set_interface_ipv6`.

    When ``prior["ipaddrv6"]`` is empty the keys are removed (the interface had no
    static IPv6 before the test). Calls ``interface_configure()`` to make the
    removal/change effective on the OS.
    """
    if prior.get("ipaddrv6"):
        snippet = (
            "require_once('interfaces.inc');\n"
            f"$iface = config_get_path({_php_str('interfaces/' + iface)}, array());\n"
            f"$iface['ipaddrv6'] = {_php_str(prior['ipaddrv6'])};\n"
            f"$iface['subnetv6'] = {_php_str(prior.get('subnetv6', ''))};\n"
            f"config_set_path({_php_str('interfaces/' + iface)}, $iface);\n"
            "write_config('pfBlockerNG smoke: restore IPv6 after locality test');\n"
            f"if (function_exists('interface_configure')) {{ interface_configure({_php_str(iface)}); }}\n"
            "echo 'OK';"
        )
    else:
        snippet = (
            "require_once('interfaces.inc');\n"
            f"$iface = config_get_path({_php_str('interfaces/' + iface)}, array());\n"
            "unset($iface['ipaddrv6'], $iface['subnetv6']);\n"
            f"config_set_path({_php_str('interfaces/' + iface)}, $iface);\n"
            "write_config('pfBlockerNG smoke: restore IPv6 after locality test');\n"
            f"if (function_exists('interface_configure')) {{ interface_configure({_php_str(iface)}); }}\n"
            "echo 'OK';"
        )
    result = php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(
            f"restore_interface_ipv6({iface}) failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}"
        )


def collect_localip(
    vm: SmokeVM,
    *,
    timeout: float = 60.0,
) -> tuple[set[str], list[str]]:
    """Call the REAL ``pfb_collect_localip()`` on the box and return its two structures.

    Returns ``(pfb_local, pfb_localsub)`` where:

    * ``pfb_local``   — a :class:`set` of exact local IP strings (the keys of the
      PHP hash; ``$pfb_local`` after the ``array_flip`` in the function).
    * ``pfb_localsub`` — a :class:`list` of local CIDR subnet strings
      (``$pfb_localsub``).

    Both are serialized from PHP as JSON so the boundary is explicit and survives
    any value that might contain the sentinel delimiters.  The function is called
    via ``pfSsh.php`` so it runs in the FULLY bootstrapped pfSense + pfBlockerNG
    environment (config loaded, all includes available).
    """
    snippet = (
        "require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');\n"
        "list($pfb_local, $pfb_localsub) = pfb_collect_localip();\n"
        # pfb_local is an array_flip'd hash: keys are the IPs, values are indices.
        # json_encode a plain array of its keys so Python gets clean strings.
        "$out_local  = array_keys($pfb_local);\n"
        "$out_sub    = array_values($pfb_localsub);\n"
        f"echo {_php_str(_CFG_VAL_OPEN)}"
        " . json_encode(array('local' => $out_local, 'localsub' => $out_sub))"
        f" . {_php_str(_CFG_VAL_CLOSE)};"
    )
    result = php_eval(vm, snippet, timeout=timeout)
    out = result.stdout
    start = out.find(_CFG_VAL_OPEN)
    end = out.find(_CFG_VAL_CLOSE)
    if start == -1 or end == -1:
        raise RuntimeError(
            f"collect_localip: no delimited JSON in pfSsh.php output: "
            f"rc={result.returncode} out={out!r} err={result.stderr!r}"
        )
    import json

    payload = json.loads(out[start + len(_CFG_VAL_OPEN) : end])
    pfb_local: set[str] = set(payload["local"])
    pfb_localsub: list[str] = list(payload["localsub"])
    return pfb_local, pfb_localsub


def ip_in_localsub(addr: str, pfb_localsub: list[str]) -> bool:
    """Return True iff ``addr`` falls inside any subnet in ``pfb_localsub``.

    Pure Python mirror of ``pfb_local_ip()`` (``ip_in_subnet()`` in PHP).
    Uses :mod:`ipaddress` so IPv6 normalisation (``::`` == ``::0``) is handled
    correctly.  Only the CIDR-subnet side (``pfb_localsub``) is checked; the
    exact-match side (``pfb_local``) is tested by simple set membership.
    """
    import ipaddress

    try:
        target = ipaddress.ip_address(addr)
    except ValueError:
        return False
    for cidr in pfb_localsub:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            if target in net:
                return True
        except ValueError:
            continue
    return False


def get_lan_ipv4(vm: SmokeVM, *, timeout: float = 30.0) -> str:
    """Return the configured IPv4 address of the LAN interface (or '' if absent).

    Used by the locality smoke test to assert the IPv4 path is unaffected.
    Reads ``interfaces/lan/ipaddr`` from config.xml — the stored address (valid
    for static interfaces; DHCP stores 'dhcp', which is also a usable string for
    the test's assertion that it appears in ``pfb_local``).
    """
    snippet = (
        f"$iface = config_get_path({_php_str('interfaces/lan')}, array());\n"
        f"echo {_php_str(_CFG_VAL_OPEN)}"
        " . ($iface['ipaddr'] ?? '')"
        f" . {_php_str(_CFG_VAL_CLOSE)};"
    )
    result = php_eval(vm, snippet, timeout=timeout)
    out = result.stdout
    start = out.find(_CFG_VAL_OPEN)
    end = out.find(_CFG_VAL_CLOSE)
    if start == -1 or end == -1:
        raise RuntimeError(f"get_lan_ipv4: no delimited value: rc={result.returncode} out={out!r}")
    return out[start + len(_CFG_VAL_OPEN) : end].strip()


def get_live_ipv4(vm: SmokeVM, iface: str = "lan", *, timeout: float = 30.0) -> str:
    """Return the RUNTIME IPv4 of ``iface`` via ``get_interface_ip()`` (or '').

    ``get_interface_ip()`` resolves DHCP/static/alias so it is the authoritative
    live address even when config.xml stores 'dhcp'.
    """
    return _php_read_scalar(
        vm,
        "",
        f"get_interface_ip({_php_str(iface)}) ?: ''",
        timeout=timeout,
    )
