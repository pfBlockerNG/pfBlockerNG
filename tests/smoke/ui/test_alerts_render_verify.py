"""Issue #809 populated-log render-verification harness for the Alerts page.

``pfblockerng_alerts.php`` renders ip_block/ip_permit/ip_match/dnsbl/dns_reply/
unified.log. The IP-side rows still run the re-validation pipeline that greps
feed/alias/aliastables files and falls back to a live ``drill`` -- issue #809
batched several of those per-row
lookups behind a prefetch pass (PR #825) without changing what gets rendered.
DNSBL rows do NOT (ADR-65 D2): ``convert_dnsbl_log()`` renders the LOGGED
group/feed straight off the log line, with no re-check, no strike/drift
markup, and no 'Unknown' rewrite of a total miss; the seeded
pfb_py_data.txt/pfb_py_zone.txt rows for the D-scenarios are BAIT the page
must ignore. This module is the durable regression harness that PROVES that:
it seeds every log the page reads with fixed, deterministic content (domains,
IPs, timestamps -- never ``helpers.unique_domain()`` or a live clock reading),
GETs the full view/filter/stats matrix in one fixed order exactly once, and
asserts on the rendered output (IP feed-drift strikes, suppression/whitelist
icons, GeoIP/IPv6/dup/alias-changed cells, the DNSBL logged-fields/upstream/
per-row-fallback paths, non-filter render caps, filter narrowing).

Byte-identity contract: every ``<tbody>`` region from every GET, plus its
SHA-256 and byte length, is written to ``smoke-diag/renderdiff/`` (env
``PFB_DIAG_DIR``, mirroring ``tests/smoke/conftest.py``'s ``DIAG_DIR``) as a
manifest + the raw region bytes + per-GET timings. THAT is how two separate CI
runs -- one on a base predating PR #825, one after it -- get diffed OFFLINE:
if the batching changed rendered output, the hashes diverge. This module is
picked up by ``ui-tests.yml``'s existing diagnostics upload; nothing new to
wire.

Cherry-pick constraint: this module drives the page over HTTP and seeds
fixtures only via raw file writes and generic ``config_get_path`` calls
-- it never calls a PHP function PR #825 introduced (``pfb_dnsbl_prefetch``,
``pfb_find_reported_headers``, ``pfb_ip_render_query``, …), so it applies
cleanly to a base commit that predates that PR.

Corrections vs. the original brief (verified against the CURRENT source,
CLAUDE.md "follow the code"):

* There is NO ``?ajax=tail`` endpoint on ``pfblockerng_alerts.php`` -- that
  endpoint exists only on ``pfblockerng_update.php`` (a different page/log).
  The GET matrix below omits it.
* ``?filterip=`` / ``?filterdnsbl=`` do NOT filter by a literal IP/domain --
  they set ``filterfieldsarray[0][13]`` / ``[1][13]``, which land on the
  **alias name** (IP tables, ``convert_ip_log()``'s post-reorder field
  reference) and the **group name** (DNSBL table, ``$pfbalertdnsbl[13]``)
  respectively. The filter GETs below pass an alias/group value, not an IP or
  domain literal.
* ``pfb_match_filter_field()`` builds an **unanchored** regex from the filter
  value, so a filter value that is a textual PREFIX of another alias/group
  would over-match. Every alias/group name below is chosen so none is a
  substring of another (letter suffixes, not digit suffixes, for the
  S-scenario aliases).
"""

from __future__ import annotations

import hashlib
import json
import re
import shlex
import subprocess
import sys
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

import pytest

from .. import helpers
from .render_oracle import PhpErrorLogGuard, evaluate_render
from .webui import looks_like_login_page, row_containing

if TYPE_CHECKING:
    from .webui import WebUI

# Selecting S3 or S8 runs the full baseline-plus-seeded GET matrix.
pytestmark = pytest.mark.ui_e2e

ALERTS_PAGE = "/pfblockerng/pfblockerng_alerts.php"

# 'Alert Settings' (Form_Section, pfblockerng_alerts.php) renders UNCONDITIONALLY on
# every $_GET['view'] / filter combination -- a single safe marker for every capture.
MARKERS = ("Alert Settings",)

CFG_DNSBL_SETTINGS = "installedpackages/pfblockerngdnsblsettings/config/0"
CFG_DNSBL_ENABLE = f"{CFG_DNSBL_SETTINGS}/pfb_dnsbl"

# --------------------------------------------------------------------------- #
# Fixed literals -- byte-identity across two SEPARATE CI runs (before/after PR
# #825). NEVER helpers.unique_domain() (random per run) or a live timestamp
# (time.strftime() would differ run to run); every token here is a hardcoded
# constant so the two runs' captures are byte-comparable offline.
# --------------------------------------------------------------------------- #

FIXED_TS = "Jan 01 00:00:00"  # literal -- never derived from the wall clock

PFB_LOGDIR = "/var/log/pfblockerng"
IP_BLOCK_LOG = helpers.IP_BLOCK_LOG
IP_PERMIT_LOG = f"{PFB_LOGDIR}/ip_permit.log"
IP_MATCH_LOG = f"{PFB_LOGDIR}/ip_match.log"
DNSBL_LOG = f"{PFB_LOGDIR}/dnsbl.log"
DNS_REPLY_LOG = f"{PFB_LOGDIR}/dns_reply.log"
UNIFIED_LOG = f"{PFB_LOGDIR}/unified.log"

PY_DATA_FILE = "/var/unbound/pfb_py_data.txt"
PY_ZONE_FILE = "/var/unbound/pfb_py_zone.txt"

DENY_DIR = "/var/db/pfblockerng/deny"
PERMIT_DIR = "/var/db/pfblockerng/permit"
MATCH_DIR = "/var/db/pfblockerng/match"
ET_DIR = "/var/db/pfblockerng/ET"
GEOIP_CC_DIR = "/usr/local/share/GeoIP/cc"
ALIASTABLES_DIR = "/var/db/aliastables"

FEED_A = f"{DENY_DIR}/RVFeedA.txt"
FEED_B = f"{DENY_DIR}/RVFeedB.txt"
FEED_PERMIT = f"{PERMIT_DIR}/RVPermitFeed.txt"
FEED_MATCH = f"{MATCH_DIR}/RVMatchFeed.txt"
FEED_ET = f"{ET_DIR}/RVFeedS10.txt"
FEED_GEO = f"{GEOIP_CC_DIR}/RVGeoFeed.txt"
ALIAS_S8_A = f"{ALIASTABLES_DIR}/pfB_RVAliasA_v4.txt"
ALIAS_S8_Z = f"{ALIASTABLES_DIR}/pfB_RVAliasZ_v4.txt"

SEEDED_FILES = (FEED_A, FEED_B, FEED_PERMIT, FEED_MATCH, FEED_ET, FEED_GEO, ALIAS_S8_A, ALIAS_S8_Z)


@dataclass(frozen=True)
class SeededFileBackup:
    path: str
    backup_path: str | None
    kind: str


def _seeded_file_kind(vm: Any, path: str) -> str:
    quoted = shlex.quote(path)
    result = vm.ssh(
        f"if [ -L {quoted} ]; then printf symlink; "
        f"elif [ -f {quoted} ]; then printf file; "
        f"elif [ -e {quoted} ]; then printf unsupported; "
        "else printf absent; fi",
        timeout=15,
    )
    assert result.returncode == 0, (
        f"failed to inspect seeded path {path!r}: rc={result.returncode} stderr={result.stderr!r}"
    )
    kind = result.stdout.strip()
    assert kind in {"absent", "file", "symlink", "unsupported"}, f"unexpected seeded path type for {path!r}: {kind!r}"
    return kind


def _reconcile_seeded_restore(
    vm: Any,
    backup: SeededFileBackup,
    exc: Exception,
    action: str,
) -> str | None:
    assert backup.backup_path is not None
    try:
        path_kind = _seeded_file_kind(vm, backup.path)
        backup_kind = _seeded_file_kind(vm, backup.backup_path)
    except Exception as inspect_exc:
        return (
            f"{action} {backup.path!r} from {backup.backup_path!r} could not be reconciled after {exc}: "
            f"inspection raised unexpectedly: {inspect_exc}; recorded backup retained if present"
        )
    if path_kind == backup.kind and backup_kind == "absent":
        return None
    recovery = (
        f"recorded backup retained for recovery at {backup.backup_path!r}"
        if backup_kind == backup.kind
        else f"recorded backup unavailable for recovery at {backup.backup_path!r}"
    )
    return (
        f"{action} {backup.path!r} from {backup.backup_path!r} unresolved after {exc}: "
        f"path={path_kind} backup={backup_kind} expected={backup.kind}; {recovery}"
    )


def _restore_seeded_files(vm: Any, backups: list[SeededFileBackup]) -> list[str]:
    errors: list[str] = []
    for backup in reversed(backups):
        try:
            remove = vm.ssh("rm", "-f", backup.path, timeout=15)
        except Exception as exc:
            errors.append(f"remove seeded replacement {backup.path!r} raised unexpectedly: {exc}")
            continue
        if remove.returncode != 0:
            errors.append(
                f"remove seeded replacement {backup.path!r} failed: rc={remove.returncode} stderr={remove.stderr!r}"
            )
            continue
        if backup.backup_path is None:
            continue
        try:
            restore = vm.ssh("mv", backup.backup_path, backup.path, timeout=15)
        except Exception as exc:
            error = _reconcile_seeded_restore(vm, backup, exc, "restore seeded path")
            if error is not None:
                errors.append(error)
            continue
        if restore.returncode != 0:
            errors.append(
                f"restore seeded path {backup.path!r} from {backup.backup_path!r} failed: "
                f"rc={restore.returncode} stderr={restore.stderr!r}"
            )
    return errors


def _backup_seeded_files(vm: Any, paths: tuple[str, ...]) -> list[SeededFileBackup]:
    kinds = [(path, _seeded_file_kind(vm, path)) for path in paths]
    unsupported = [path for path, kind in kinds if kind == "unsupported"]
    assert not unsupported, f"unsupported seeded path type; refusing mutation: {unsupported!r}"

    backups: list[SeededFileBackup] = []
    planned: list[SeededFileBackup] = []
    for path, kind in kinds:
        if kind == "absent":
            planned.append(SeededFileBackup(path, None, kind))
            continue
        while True:
            backup_path = f"{path}.pfb-alerts-backup-{uuid.uuid4().hex}"
            if _seeded_file_kind(vm, backup_path) == "absent":
                break
        planned.append(SeededFileBackup(path, backup_path, kind))

    current: SeededFileBackup | None = None
    try:
        for backup in planned:
            current = backup
            if backup.backup_path is not None:
                move = vm.ssh("mv", backup.path, backup.backup_path, timeout=15)
                assert move.returncode == 0, (
                    f"backup seeded path {backup.path!r} to {backup.backup_path!r} failed: "
                    f"rc={move.returncode} stderr={move.stderr!r}"
                )
            backups.append(backup)
            current = None
    except Exception as exc:
        rollback_errors: list[str] = []
        if current is not None and current.backup_path is not None:
            try:
                path_kind = _seeded_file_kind(vm, current.path)
                backup_kind = _seeded_file_kind(vm, current.backup_path)
                if path_kind == "absent" and backup_kind in {"file", "symlink"}:
                    try:
                        restore = vm.ssh("mv", current.backup_path, current.path, timeout=15)
                    except Exception as restore_exc:
                        error = _reconcile_seeded_restore(
                            vm,
                            current,
                            restore_exc,
                            "restore ambiguous seeded path",
                        )
                        if error is not None:
                            rollback_errors.append(error)
                    else:
                        if restore.returncode != 0:
                            rollback_errors.append(
                                f"restore ambiguous seeded path {current.path!r} from {current.backup_path!r} "
                                f"failed: rc={restore.returncode} stderr={restore.stderr!r}"
                            )
                elif path_kind == "absent" or backup_kind != "absent":
                    rollback_errors.append(
                        f"ambiguous seeded path {current.path!r} retained for recovery: "
                        f"path={path_kind} backup={backup_kind} at {current.backup_path!r}"
                    )
            except Exception as inspect_exc:
                rollback_errors.append(
                    f"inspect ambiguous seeded path {current.path!r} and {current.backup_path!r} "
                    f"raised unexpectedly: {inspect_exc}"
                )
        rollback_errors.extend(_restore_seeded_files(vm, backups))
        if rollback_errors:
            exc.add_note("seeded path backup rollback errors:\n" + "\n".join(rollback_errors))
        raise

    return backups


# --- ip_block.log scenarios (S1-S10) -- RFC 5737/3849 addresses. S3 and S8
# deliberately pair an exact address with a longer textual prefix collision;
# the remaining values avoid accidental prefix overlap. ---
S1_IP = "192.0.2.10"  # still-listed (found in FEED_A)
S2_IP = "192.0.2.20"  # de-listed (nowhere)
S3_IP = "192.0.2.3"  # moved: FEED_A has only .30, exact address is in FEED_B
S4_IP = "203.0.113.77"  # CIDR: logged RVFeedA, FEED_A holds 203.0.113.0/24
S5_IP = "198.51.100.60"  # GeoIP: alias pfB_Top_v4, found in FEED_GEO
S6_IP = "2001:db8::5"  # IPv6, found in FEED_A
S6_LOCAL = "2001:db8:1234::1"  # the local/dst side of the v6 row (unmatched, cosmetic)
S8_IP = "198.51.100.4"  # alias-changed: exact A alias precedes longer Z decoy
S9_IP = "192.0.2.50"  # outbound copy of S1 (dst side), also in FEED_A
S10_IP = "192.0.2.90"  # ET feed, found in FEED_ET

# Letter suffixes (not digits) -- filterip's unanchored regex would let "SA" match a
# would-be "SA0"/"SA1" digit-suffixed sibling; letters avoid that entirely.
S1_ALIAS = "RVAliasSA"
S2_ALIAS = "RVAliasSB"
S3_ALIAS = "RVAliasSC"
S4_ALIAS = "RVAliasSD"
S5_ALIAS = "pfB_Top_v4"  # continent alias -- routes pfb_geoip=TRUE (ADR-11 continent list)
S6_ALIAS = "RVAliasSF"
S8_ALIAS_LOGGED = "RVAliasSHOld"  # deliberately stale; ALIAS_S8_A's basename is the "new" one
S9_ALIAS = "RVAliasSI"
S10_ALIAS = "RVAliasSJ"
FILLER_IP_ALIAS = "RVAliasFill"

FEED_A_NAME = "RVFeedA"
FEED_B_NAME = "RVFeedB"
FEED_C8_NAME = "RVFeedC8"  # logged for S8 -- deliberately absent, forces the miss path
FEED_GEO_NAME = "RVGeoFeed"
FEED_ET_NAME = "RVFeedS10"
FEED_ET_LOGGED = f"RVETCat:{FEED_ET_NAME}"  # ':' marks an ET/Proofpoint-header feed

IP_BLOCK_FILLER_IPS = [f"192.0.2.{150 + i}" for i in range(30)]
UNIFIED_ONLY_FILLER_IPS = [f"203.0.113.{210 + i}" for i in range(130)]

P1_IP, P2_IP = "198.51.100.10", "198.51.100.11"
M1_IP, M2_IP = "198.51.100.20", "198.51.100.21"
P1_ALIAS, P2_ALIAS = "RVAliasP1", "RVAliasP2"
M1_ALIAS, M2_ALIAS = "RVAliasM1", "RVAliasM2"
FEED_PERMIT_NAME = "RVPermitFeed"
FEED_MATCH_NAME = "RVMatchFeed"

# --- dnsbl.log / unified.log scenarios (D1-D8) ---
D1_DOMAIN = "rv809-c1.com"
D2_DOMAIN = "rv809-d1.com"
D3_DOMAIN = "sub.rv809-z1.com"
D3_PARENT = "rv809-z1.com"
D4_DOMAIN = "rv809-gone1.com"
D5_DOMAIN = "rv809-up1.com"
# Deliberately fails PFB_FILTER_DOMAIN ([a-zA-Z0-9_.-]) via the '*'. Formerly this
# excluded the domain from pfb_dnsbl_prefetch()'s 'covered' set (issue #809 review,
# "B2"), forcing pfb_dnsbl_parse_compute()'s per-row fallback instead of the batched
# grep; ADR-65 D2 retired that whole re-check, so the metachar shape now pins that
# rendering NEVER re-derives from the domain string at all -- D7's bait row is
# nowhere on disk, D8's IS (pfb_py_data.txt), and both must render their LOGGED
# fields untouched regardless.
D7_DOMAIN = "rv809*m1.com"
D8_DOMAIN = "rv809*p1.com"

D1_LOGGED_GROUP, D1_LOGGED_FEED = "RVLoggedGroup1", "RVLoggedFeed1"
D2_DATA_GROUP, D2_DATA_FEED = "RVGroupD", "RVFeedD"
D2_LOGGED_GROUP, D2_LOGGED_FEED = "RVLoggedGroupD2", "RVLoggedFeedD2"
D3_GROUP, D3_FEED = "RVGroupZ3", "RVFeedZ3"  # SAME as D3's logged value -- mode+domain are the bait discriminators
D4_LOGGED_GROUP, D4_LOGGED_FEED = "RVLoggedGroupD4", "RVLoggedFeedD4"
D7_LOGGED_GROUP, D7_LOGGED_FEED = "RVLoggedGroupD7", "RVLoggedFeedD7"
D8_DATA_GROUP, D8_DATA_FEED = "RVGroupMeta", "RVFeedMeta"
D8_LOGGED_GROUP, D8_LOGGED_FEED = "RVLoggedGroupMeta", "RVLoggedFeedMeta"
FILLER_DNSBL_GROUP, FILLER_DNSBL_FEED = "RVFillerGroup", "RVFillerFeed"

FILLER_DNSBL_DOMAINS = [f"rv809-f{i}.com" for i in range(30)]

# (reply_type, orig_record, final_record, ttl, domain, src_ip, dst_resolved, geoip)
DNS_REPLY_1 = ("A", "A", "A", "300", "rv809-reply1.com", "127.0.0.1", "203.0.113.5", "US")
DNS_REPLY_2 = ("cache", "AAAA", "AAAA", "60", "rv809-reply2.com", "127.0.0.1", "2001:db8::9", "US")


# --------------------------------------------------------------------------- #
# CSV line builders -- field order copied verbatim from the existing
# tests/smoke/ui/test_alerts.py seeds (the authoritative in-tree template).
# --------------------------------------------------------------------------- #


def _ip_line(
    *,
    src_ip: str,
    dst_ip: str,
    direction: str,
    alias: str,
    ip_eval: str,
    feed: str,
    action: str = "block",
    ipv: str = "4",
    proto_id: str = "6",
    proto: str = "TCP",
    dup: str = "+",
) -> str:
    """One ip_block.log/ip_permit.log/ip_match.log CSV line (23 fields).

    ts,rule,real_iface,friendly_iface,action,ipv,proto_id,proto,src_ip,dst_ip,
    src_port,dst_port,dir,geoip,alias,ip_eval,feed,rhost,chost,asn,asn_domain,asn_name,dup
    """
    ports = ",," if proto in ("ICMP", "ICMPV6") else ",12345,443"
    return (
        f"{FIXED_TS},100,em0,WAN,{action},{ipv},{proto_id},{proto},"
        f"{src_ip},{dst_ip}{ports},"
        f"{direction},US,{alias},{ip_eval},{feed},Unknown,Unknown,Unknown,,,{dup}\n"
    )


def _dnsbl_line(
    *,
    domain: str,
    group: str,
    feed: str,
    block_mode: str = "DNSBL",
    final_domain: str | None = None,
    dup: str = "+",
) -> str:
    """One dnsbl.log CSV line: l_type,ts,domain,src_ip,agent,block_mode,group,final_domain,feed,dup,qtype."""
    final_domain = domain if final_domain is None else final_domain
    return f"DNSBL-python,{FIXED_TS},{domain},127.0.0.1,Python,{block_mode},{group},{final_domain},{feed},{dup},A\n"


def _dns_reply_line(
    reply_type: str, orig_record: str, final_record: str, ttl: str, domain: str, src_ip: str, dst: str, geoip: str
) -> str:
    """One dns_reply.log CSV line: DNS-reply,ts,reply_type,orig_record,final_record,TTL,domain,src_ip,dst,geoip."""
    return f"DNS-reply,{FIXED_TS},{reply_type},{orig_record},{final_record},{ttl},{domain},{src_ip},{dst},{geoip}\n"


def _ip_scenarios() -> list[str]:
    """S1-S10 (+ S7, the dup marker for S1) -- see the module docstring's scenario table."""
    return [
        _ip_line(src_ip=S1_IP, dst_ip="10.0.0.5", direction="in", alias=S1_ALIAS, ip_eval=S1_IP, feed=FEED_A_NAME),
        # S7 dup of S1, appended immediately after: tail -r reads it FIRST (reverse
        # order) -> $dup['Block']++ -> the badge lands on S1's OWN rendered row.
        _ip_line(
            src_ip=S1_IP, dst_ip="10.0.0.5", direction="in", alias=S1_ALIAS, ip_eval=S1_IP, feed=FEED_A_NAME, dup="-"
        ),
        _ip_line(src_ip=S2_IP, dst_ip="10.0.0.5", direction="in", alias=S2_ALIAS, ip_eval=S2_IP, feed=FEED_A_NAME),
        _ip_line(src_ip=S3_IP, dst_ip="10.0.0.5", direction="in", alias=S3_ALIAS, ip_eval=S3_IP, feed=FEED_A_NAME),
        _ip_line(src_ip=S4_IP, dst_ip="10.0.0.5", direction="in", alias=S4_ALIAS, ip_eval=S4_IP, feed=FEED_A_NAME),
        _ip_line(src_ip=S5_IP, dst_ip="10.0.0.5", direction="in", alias=S5_ALIAS, ip_eval=S5_IP, feed=FEED_GEO_NAME),
        _ip_line(
            src_ip=S6_IP,
            dst_ip=S6_LOCAL,
            direction="in",
            alias=S6_ALIAS,
            ip_eval=S6_IP,
            feed=FEED_A_NAME,
            ipv="6",
            proto_id="58",
            proto="ICMPV6",
        ),
        _ip_line(
            src_ip=S8_IP, dst_ip="10.0.0.5", direction="in", alias=S8_ALIAS_LOGGED, ip_eval=S8_IP, feed=FEED_C8_NAME
        ),
        _ip_line(src_ip="10.0.0.7", dst_ip=S9_IP, direction="out", alias=S9_ALIAS, ip_eval=S9_IP, feed=FEED_A_NAME),
        _ip_line(
            src_ip=S10_IP, dst_ip="10.0.0.5", direction="in", alias=S10_ALIAS, ip_eval=S10_IP, feed=FEED_ET_LOGGED
        ),
    ]


def _ip_filler_lines(ips: list[str]) -> list[str]:
    return [
        _ip_line(src_ip=ip, dst_ip="10.0.0.5", direction="in", alias=FILLER_IP_ALIAS, ip_eval=ip, feed=FEED_A_NAME)
        for ip in ips
    ]


def _permit_lines() -> list[str]:
    return [
        _ip_line(
            src_ip=P1_IP,
            dst_ip="10.0.0.5",
            direction="in",
            alias=P1_ALIAS,
            ip_eval=P1_IP,
            feed=FEED_PERMIT_NAME,
            action="pass",
        ),
        _ip_line(
            src_ip=P2_IP,
            dst_ip="10.0.0.5",
            direction="in",
            alias=P2_ALIAS,
            ip_eval=P2_IP,
            feed=FEED_PERMIT_NAME,
            action="pass",
        ),
    ]


def _match_lines() -> list[str]:
    return [
        _ip_line(
            src_ip=M1_IP,
            dst_ip="10.0.0.5",
            direction="in",
            alias=M1_ALIAS,
            ip_eval=M1_IP,
            feed=FEED_MATCH_NAME,
            action="match",
        ),
        _ip_line(
            src_ip=M2_IP,
            dst_ip="10.0.0.5",
            direction="in",
            alias=M2_ALIAS,
            ip_eval=M2_IP,
            feed=FEED_MATCH_NAME,
            action="match",
        ),
    ]


def _dnsbl_scenarios() -> list[str]:
    """D1-D8 (+ D6, the dup marker for D1) -- see the module docstring's scenario table."""
    return [
        _dnsbl_line(domain=D1_DOMAIN, group=D1_LOGGED_GROUP, feed=D1_LOGGED_FEED),
        # D6: dup of D1, appended immediately after (same reverse-read reasoning as S7).
        _dnsbl_line(domain=D1_DOMAIN, group=D1_LOGGED_GROUP, feed=D1_LOGGED_FEED, dup="-"),
        _dnsbl_line(domain=D2_DOMAIN, group=D2_LOGGED_GROUP, feed=D2_LOGGED_FEED),
        _dnsbl_line(domain=D3_DOMAIN, group=D3_GROUP, feed=D3_FEED, final_domain=D3_DOMAIN),
        _dnsbl_line(domain=D4_DOMAIN, group=D4_LOGGED_GROUP, feed=D4_LOGGED_FEED),
        f"DNSBL-python,{FIXED_TS},{D5_DOMAIN},127.0.0.1,Python,Upstream_Block,Upstream,NXRA,Quad9,+,A\n",
        _dnsbl_line(domain=D7_DOMAIN, group=D7_LOGGED_GROUP, feed=D7_LOGGED_FEED),
        _dnsbl_line(domain=D8_DOMAIN, group=D8_LOGGED_GROUP, feed=D8_LOGGED_FEED),
    ]


def _dnsbl_filler_lines() -> list[str]:
    return [_dnsbl_line(domain=d, group=FILLER_DNSBL_GROUP, feed=FILLER_DNSBL_FEED) for d in FILLER_DNSBL_DOMAINS]


def _dns_reply_lines() -> list[str]:
    return [_dns_reply_line(*DNS_REPLY_1), _dns_reply_line(*DNS_REPLY_2)]


def _unified_lines() -> list[str]:
    """unified.log content: additional-only filler first (oldest), then every
    other log's content reused verbatim with its type prefix (issue #809: the
    Unified reader's Block/Permit/Match case array_shift()s only the prepended
    type field before handing the rest, UNCHANGED, to convert_ip_log() -- the
    DNSBL/DNS-reply cases pass $fields through with NO extra prefix, since
    field[0] already carries their own type). Named scenarios are appended LAST
    (most recent) so they stay within the pfbunicnt=200 render window even
    though ~130 pure filler rows push the total past it.
    """
    lines: list[str] = [
        "Block,"
        + _ip_line(src_ip=ip, dst_ip="10.0.0.5", direction="in", alias=FILLER_IP_ALIAS, ip_eval=ip, feed=FEED_A_NAME)
        for ip in UNIFIED_ONLY_FILLER_IPS
    ]
    lines += ["Block," + line for line in _ip_filler_lines(IP_BLOCK_FILLER_IPS)]
    lines += ["Block," + line for line in _ip_scenarios()]
    lines += ["Permit," + line for line in _permit_lines()]
    lines += ["Match," + line for line in _match_lines()]
    lines += _dnsbl_filler_lines()
    lines += _dnsbl_scenarios()
    lines += _dns_reply_lines()
    return lines


def _ndjson_domain_row(domain: str, feed: str, group: str) -> str:
    """Legacy object row for the retired pfb_py_data/zone UI fixture.

    Current issue #1177 staging writers emit compact tagged arrays. These historical files are
    not staging input; retaining their old object shape keeps the render fixture explicit.
    """
    row = {"kind": "domain", "domain": domain, "log": "1", "feed": feed, "group": group}
    return json.dumps(row, separators=(",", ":"), ensure_ascii=False) + "\n"


def _py_data_appendix() -> str:
    lines = [
        _ndjson_domain_row(D2_DOMAIN, D2_DATA_FEED, D2_DATA_GROUP),
        _ndjson_domain_row(D8_DOMAIN, D8_DATA_FEED, D8_DATA_GROUP),
    ]
    lines += [_ndjson_domain_row(d, FILLER_DNSBL_FEED, FILLER_DNSBL_GROUP) for d in FILLER_DNSBL_DOMAINS]
    return "".join(lines)


def _py_zone_appendix() -> str:
    return _ndjson_domain_row(D3_PARENT, D3_FEED, D3_GROUP)


# --------------------------------------------------------------------------- #
# Capture / diagnostics plumbing
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Capture:
    """One GET's captured response + wall-clock timing."""

    status: int
    body: str
    elapsed: float


GET_MATRIX: list[tuple[str, str]] = [
    ("alert", ALERTS_PAGE),
    ("unified", f"{ALERTS_PAGE}?view=unified"),
    ("reply", f"{ALERTS_PAGE}?view=reply"),
    ("dnsbl_stat", f"{ALERTS_PAGE}?view=dnsbl_stat"),
    ("dnsbl_reply_stat", f"{ALERTS_PAGE}?view=dnsbl_reply_stat"),
    ("ip_block_stat", f"{ALERTS_PAGE}?view=ip_block_stat"),
    ("ip_permit_stat", f"{ALERTS_PAGE}?view=ip_permit_stat"),
    ("ip_match_stat", f"{ALERTS_PAGE}?view=ip_match_stat"),
    ("alert_filterip", f"{ALERTS_PAGE}?filterip={quote(S1_ALIAS)}"),
    ("alert_filterdnsbl", f"{ALERTS_PAGE}?filterdnsbl={quote(D1_LOGGED_GROUP)}"),
    ("unified_filterip", f"{ALERTS_PAGE}?view=unified&filterip={quote(S1_ALIAS)}"),
    ("alert_2", ALERTS_PAGE),
]

_TBODY_RE = re.compile(r"<tbody\b[^>]*>.*?</tbody>", re.DOTALL | re.IGNORECASE)
_TR_RE = re.compile(r"<tr\b", re.IGNORECASE)


def _extract_tbody_regions(body: str) -> list[str]:
    """Every ``<tbody>...</tbody>`` block, in document order (the practical, byte-diffable "table body")."""
    return _TBODY_RE.findall(body)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_diagnostics(baseline: dict[str, Capture], captures: dict[str, Capture]) -> None:
    """Persist every capture's full body, its ``<tbody>`` regions (+ SHA-256), and per-GET timings.

    Layout under ``smoke-diag/renderdiff/``::

        bodies/<baseline|main>_<key>.html          -- the full raw response body
        regions/<baseline|main>_<key>_<idx>.html   -- one extracted <tbody> region
        manifest.json                              -- [{get_key, region_index, sha256, byte_len}, ...]
        timings.json                                -- {"<baseline|main>_<key>": seconds, ...}
    """
    diag_dir = helpers.DIAG_DIR / "renderdiff"
    bodies_dir = diag_dir / "bodies"
    regions_dir = diag_dir / "regions"
    bodies_dir.mkdir(parents=True, exist_ok=True)
    regions_dir.mkdir(parents=True, exist_ok=True)

    manifest: list[dict[str, Any]] = []
    timings: dict[str, float] = {}

    for label, store in (("baseline", baseline), ("main", captures)):
        for key, cap in store.items():
            tag = f"{label}_{key}"
            timings[tag] = cap.elapsed
            (bodies_dir / f"{tag}.html").write_text(cap.body, encoding="utf-8")
            for idx, region in enumerate(_extract_tbody_regions(cap.body)):
                region_bytes = region.encode("utf-8")
                (regions_dir / f"{tag}_{idx}.html").write_bytes(region_bytes)
                manifest.append(
                    {
                        "get_key": tag,
                        "region_index": idx,
                        "sha256": _sha256(region_bytes),
                        "byte_len": len(region_bytes),
                    }
                )

    (diag_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    (diag_dir / "timings.json").write_text(json.dumps(timings, indent=2), encoding="utf-8")


# --------------------------------------------------------------------------- #
# On-box seeding helpers
# --------------------------------------------------------------------------- #


def _ensure_log(vm: helpers.SmokeVM, path: str) -> str:
    """mkdir -p + touch a log file idempotently; return its ORIGINAL byte size (str)."""
    log_dir = path.rsplit("/", 1)[0]
    ensure = vm.ssh(f"mkdir -p {log_dir} && touch {path}", timeout=15)
    assert ensure.returncode == 0, f"failed to ensure {path!r} exists: rc={ensure.returncode} stderr={ensure.stderr!r}"
    size = vm.ssh("stat", "-f", "%z", path, timeout=15)
    assert size.returncode == 0, f"failed to stat {path!r}: rc={size.returncode} stderr={size.stderr!r}"
    return size.stdout.strip()


def _append(vm: helpers.SmokeVM, path: str, content: str) -> None:
    if not content:
        return
    result = subprocess.run(
        vm.ssh_argv("tee", "-a", path), input=content, capture_output=True, text=True, timeout=30, check=False
    )
    assert result.returncode == 0, f"failed to append to {path!r}: rc={result.returncode} stderr={result.stderr!r}"


def _seed_feed_files(vm: helpers.SmokeVM) -> None:
    mkdir = vm.ssh(
        f"mkdir -p {DENY_DIR} {PERMIT_DIR} {MATCH_DIR} {ET_DIR} {GEOIP_CC_DIR} {ALIASTABLES_DIR}", timeout=15
    )
    assert mkdir.returncode == 0, f"failed to mkdir feed dirs: rc={mkdir.returncode} stderr={mkdir.stderr!r}"

    feed_a_lines = [
        S1_IP,
        f"{S3_IP}0",
        "203.0.113.0/24",
        S6_IP,
        S8_IP,
        S9_IP,
        *IP_BLOCK_FILLER_IPS,
        *UNIFIED_ONLY_FILLER_IPS,
    ]
    files = {
        FEED_A: "\n".join(feed_a_lines) + "\n",
        FEED_B: f"{S3_IP}\n",
        FEED_PERMIT: f"{P1_IP}\n",
        FEED_MATCH: f"{M1_IP}\n",
        FEED_ET: f"{S10_IP}\n",
        FEED_GEO: f"{S5_IP}\n",
        ALIAS_S8_A: f"{S8_IP}\n",
        ALIAS_S8_Z: f"{S8_IP}0\n",
    }
    for path, content in files.items():
        result = subprocess.run(
            vm.ssh_argv("tee", path), input=content, capture_output=True, text=True, timeout=30, check=False
        )
        assert result.returncode == 0, f"failed to write {path!r}: rc={result.returncode} stderr={result.stderr!r}"

    alias_order = vm.ssh(f'for file in {ALIASTABLES_DIR}/*.txt; do printf "%s\\n" "$file"; done', timeout=15)
    assert alias_order.returncode == 0, (
        f"failed to read aliastables production-glob order: rc={alias_order.returncode} stderr={alias_order.stderr!r}"
    )
    ordered_aliases = alias_order.stdout.splitlines()
    assert ALIAS_S8_A in ordered_aliases and ALIAS_S8_Z in ordered_aliases, (
        f"S8 fixtures missing from production-glob order: {ordered_aliases!r}"
    )
    assert ordered_aliases.index(ALIAS_S8_A) < ordered_aliases.index(ALIAS_S8_Z), (
        f"S8 requires exact A before longer Z in production-glob order: {ordered_aliases!r}"
    )


# --------------------------------------------------------------------------- #
# The module-scoped fixture: seed ONCE, GET the fixed matrix ONCE, hand tests a
# read-only dict. No test does its own GET (order-independence, CLAUDE.md).
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def render_diff_state(smoke_vm: helpers.SmokeVM, webui: WebUI) -> Iterator[dict[str, dict[str, Capture]]]:
    vm = smoke_vm
    baseline: dict[str, Capture] = {}
    captures: dict[str, Capture] = {}
    seeded_backups: list[SeededFileBackup] = []
    orig_sizes: dict[str, str] = {}
    original_dnsbl_cfg: str | None = None
    error_log_guard: PhpErrorLogGuard | None = None
    error_log_snapshotted = False

    try:
        seeded_backups = _backup_seeded_files(vm, SEEDED_FILES)

        error_log_guard = PhpErrorLogGuard(vm)
        original_dnsbl_cfg = helpers.config_get(vm, CFG_DNSBL_ENABLE)
        for path in (
            IP_BLOCK_LOG,
            IP_PERMIT_LOG,
            IP_MATCH_LOG,
            DNSBL_LOG,
            DNS_REPLY_LOG,
            UNIFIED_LOG,
            PY_DATA_FILE,
            PY_ZONE_FILE,
        ):
            orig_sizes[path] = _ensure_log(vm, path)

        # DNSBL panel requires a configured sinkhole VIP and enabled toggle.
        # Configure VIP before enabling DNSBL.
        helpers.ensure_dnsbl_vip(vm)
        helpers.set_dnsbl_enabled(vm, True)

        error_log_guard.snapshot()
        error_log_snapshotted = True

        # (1) Capture fixed-order baseline responses before seeding.
        for key, path in GET_MATRIX:
            t0 = time.perf_counter()
            resp = webui.get(path)
            elapsed = time.perf_counter() - t0
            assert not looks_like_login_page(resp.text), f"baseline GET {path!r} returned the login form"
            baseline[key] = Capture(status=resp.status_code, body=resp.text, elapsed=elapsed)

        # (2) SEED every log/file row this module's scenarios need.
        _seed_feed_files(vm)
        _append(vm, IP_BLOCK_LOG, "".join(_ip_filler_lines(IP_BLOCK_FILLER_IPS) + _ip_scenarios()))
        _append(vm, IP_PERMIT_LOG, "".join(_permit_lines()))
        _append(vm, IP_MATCH_LOG, "".join(_match_lines()))
        _append(vm, DNSBL_LOG, "".join(_dnsbl_filler_lines() + _dnsbl_scenarios()))
        _append(vm, DNS_REPLY_LOG, "".join(_dns_reply_lines()))
        _append(vm, UNIFIED_LOG, "".join(_unified_lines()))
        _append(vm, PY_DATA_FILE, _py_data_appendix())
        _append(vm, PY_ZONE_FILE, _py_zone_appendix())

        # (3) The FIXED-ORDER GET matrix, exactly once (GET #12, 'alert_2', re-renders
        # the SAME view with no log/file mutation in between -- the idempotent
        # re-render check).
        for key, path in GET_MATRIX:
            t0 = time.perf_counter()
            resp = webui.get(path)
            elapsed = time.perf_counter() - t0
            assert not looks_like_login_page(resp.text), f"GET {path!r} returned the login form"
            captures[key] = Capture(status=resp.status_code, body=resp.text, elapsed=elapsed)

        _write_diagnostics(baseline, captures)

        yield {"baseline": baseline, "captures": captures}

    finally:
        original_error = sys.exception()
        errors: list[str] = []

        try:
            errors.extend(_restore_seeded_files(vm, seeded_backups))
        except Exception as exc:
            errors.append(f"restore seeded files raised unexpectedly: {exc}")

        for path, size in orig_sizes.items():
            try:
                result = subprocess.run(
                    vm.ssh_argv("/usr/bin/truncate", "-s", size, path),
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=False,
                )
                if result.returncode != 0:
                    errors.append(f"truncate {path!r} to size={size!r} failed: {result.stderr!r}")
            except Exception as exc:
                errors.append(f"truncate {path!r} to size={size!r} raised unexpectedly: {exc}")

        if original_dnsbl_cfg is not None:
            try:
                restore = helpers.php_eval(
                    vm,
                    f"config_set_path({helpers._php_str(CFG_DNSBL_ENABLE)}, {helpers._php_str(original_dnsbl_cfg)});\n"
                    "write_config('pfBlockerNG smoke: restore pfb_dnsbl after render-diff harness');\n"
                    "echo 'OK';",
                )
                if restore.returncode != 0 or "OK" not in restore.stdout:
                    errors.append(
                        f"restore pfb_dnsbl failed: rc={restore.returncode} "
                        f"stdout={restore.stdout!r} stderr={restore.stderr!r}"
                    )
            except Exception as exc:
                errors.append(f"restore pfb_dnsbl raised unexpectedly: {exc}")

        if error_log_guard is not None and error_log_snapshotted:
            try:
                error_log_guard.assert_no_growth()
            except Exception as exc:
                errors.append(str(exc))

        if errors:
            detail = "\n".join(errors)
            message = f"render_diff_state teardown left the VM polluted:\n{detail}"
            print(f"render_diff_state teardown FAILED to fully restore VM state:\n{detail}")
            if original_error is not None and not isinstance(original_error, GeneratorExit):
                original_error.add_note(message)
            else:
                raise AssertionError(message)


# --------------------------------------------------------------------------- #
# Tests -- pure assertions over the captured dict; no test performs its own GET.
# --------------------------------------------------------------------------- #


def test_baseline_excludes_seed_tokens(render_diff_state: dict[str, dict[str, Capture]]) -> None:
    """Before-state: no seeded token exists prior to the seed step.

    CLAUDE.md before/after rule: a later "token present" assertion is only
    evidence the seeding CAUSED it if the token is provably absent beforehand.
    """
    # A filter GET carries its filter value in the URL and the page echoes it back
    # into the filter form field -- so THAT token legitimately appears in THAT
    # baseline capture without any seeding. Exclude exactly those (key, token)
    # pairs; every other combination must still be absent.
    url_echoed = {
        "alert_filterip": {S1_ALIAS},
        "unified_filterip": {S1_ALIAS},
        "alert_filterdnsbl": {D1_LOGGED_GROUP},
    }
    baseline = render_diff_state["baseline"]
    for key, cap in baseline.items():
        for token in (D1_DOMAIN, S1_ALIAS, D1_LOGGED_GROUP, FEED_A_NAME, "rv809"):
            if token in url_echoed.get(key, set()):
                continue
            assert token not in cap.body, (
                f"baseline capture {key!r} already contains {token!r} before any seeding -- "
                f"cannot prove a later assertion is caused by this module's seed"
            )


def test_s1_still_listed_renders_without_strike(render_diff_state: dict[str, dict[str, Capture]]) -> None:
    """S1: an IP still present in its logged feed renders with NO drift strike.

    Given: 192.0.2.10 is logged against RVFeedA and IS present in FEED_A.
    Then: convert_ip_log()'s first (feed-scoped) validate succeeds, so the
    ENTIRE miss-block (find_reported_header + aliastables sweep) never runs --
    the row shows its logged feed/eval verbatim, with no <s> strike anywhere.
    """
    body = render_diff_state["captures"]["alert"].body
    row = row_containing(body, f"host={S1_IP}")
    assert "<s>" not in row, f"S1 ({S1_IP}) row unexpectedly struck (still-listed row should render clean): {row!r}"
    assert "Not listed!" not in row, f"S1 ({S1_IP}) row wrongly rendered 'Not listed!': {row!r}"


def test_s2_delisted_renders_not_listed(render_diff_state: dict[str, dict[str, Capture]]) -> None:
    """S2: an IP absent from every deny/native feed file renders 'Not listed!'.

    Given: 192.0.2.20 is logged against RVFeedA but present NOWHERE on disk.
    Then: find_reported_header() returns ('Unknown','Unknown') -> both the feed
    and evaluated-IP cells substitute 'Not listed!' (struck old value first).
    """
    body = render_diff_state["captures"]["alert"].body
    row = row_containing(body, f"host={S2_IP}")
    assert "Not listed!" in row, f"S2 ({S2_IP}) expected 'Not listed!' -- row: {row!r}"
    assert "<s>" in row, f"S2 ({S2_IP}) expected a struck old feed/IP -- row: {row!r}"


@pytest.mark.ui_render
def test_s3_moved_feed_renders_strike(render_diff_state: dict[str, dict[str, Capture]]) -> None:
    """S3: an IP re-located to a DIFFERENT feed file renders the struck old feed + the new one.

    Given: 192.0.2.3 is logged against RVFeedA, which contains only the longer
    192.0.2.30; the exact address is present in FEED_B (RVFeedB.txt).
    Then: exact attribution ignores FEED_A's collision and the feed cell
    struck-shows the old feed name before displaying the current one.
    """
    body = render_diff_state["captures"]["alert"].body
    row = row_containing(body, f"host={S3_IP}")
    assert f"<s>{FEED_A_NAME}</s>" in row, f"S3 ({S3_IP}) expected the old feed {FEED_A_NAME!r} struck: {row!r}"
    assert FEED_B_NAME in row, f"S3 ({S3_IP}) expected the new feed {FEED_B_NAME!r} present: {row!r}"


def test_s4_cidr_renders_evaluated_cell(render_diff_state: dict[str, dict[str, Capture]]) -> None:
    """S4: a host covered only by a broader CIDR renders that CIDR as the new evaluated cell.

    Given: 203.0.113.77 is logged with an exact ip_eval, but FEED_A only lists the
    containing 203.0.113.0/24 network.
    Then: pfb_match_reported_cidr()'s prefix-match branch finds the CIDR and it
    appears as the row's (re-)evaluated match.
    """
    body = render_diff_state["captures"]["alert"].body
    row = row_containing(body, f"host={S4_IP}")
    assert "203.0.113.0/24" in row, f"S4 ({S4_IP}) expected the covering CIDR 203.0.113.0/24 in its cell: {row!r}"


def test_s5_geoip_row_renders(render_diff_state: dict[str, dict[str, Capture]]) -> None:
    """S5: a GeoIP-continent-aliased row (pfB_Top_v4) renders cleanly, still-listed.

    Given: 198.51.100.60 carries the continent alias pfB_Top_v4 (routes
    $pfb_geoip=TRUE, folder=ccdir) and IS present in FEED_GEO.
    Then: the row renders with no strike/miss (the GeoIP folder validate succeeds).
    """
    body = render_diff_state["captures"]["alert"].body
    row = row_containing(body, f"host={S5_IP}")
    assert "Not listed!" not in row, f"S5 ({S5_IP}) GeoIP row wrongly rendered 'Not listed!': {row!r}"


def test_s6_ipv6_row_renders(render_diff_state: dict[str, dict[str, Capture]]) -> None:
    """S6: an IPv6 Block row, still listed in FEED_A, renders cleanly.

    Given: 2001:db8::5 is logged against RVFeedA and IS present in FEED_A.
    Then: the row renders (the threat-lookup href carries the RAW v6 address,
    unlike the SRC/DST table cells which wrap it in [...] with zero-width spaces).
    """
    body = render_diff_state["captures"]["alert"].body
    row = row_containing(body, f"host={S6_IP}")
    assert "<s>" not in row, f"S6 ({S6_IP}) IPv6 row unexpectedly struck: {row!r}"


def test_s7_dup_badge_renders_on_s1_row(render_diff_state: dict[str, dict[str, Capture]]) -> None:
    """S7: a dup-marked repeat of S1 does not render its OWN row but bumps S1's dup badge.

    Given: S1's line is immediately followed by an identical line whose dup
    field is '-' (S7). tail -r reads S7 FIRST (reverse order) -> $dup['Block']++
    -> continue (never rendered); S1 renders next and picks up the count.
    Then: S1's row carries the ' [1]' duplicate-count badge.
    """
    body = render_diff_state["captures"]["alert"].body
    row = row_containing(body, f"host={S1_IP}")
    assert "[1]" in row, f"S1 row missing the dup-count badge '[1]' expected from S7's dup marker: {row!r}"


@pytest.mark.ui_render
def test_s8_alias_changed_cell_renders(render_diff_state: dict[str, dict[str, Capture]]) -> None:
    """S8: a host now living under a DIFFERENT pf alias table renders the struck old alias + the new one.

    Given: 198.51.100.4 is logged under alias RVAliasSHOld (feed RVFeedC8, which
    has no on-disk file -- forces the miss path), found via FEED_A, and is an
    exact entry in the A alias while the later Z alias holds only 198.51.100.40.
    Then: the aliastables sweep ignores the longer collision and the Rule
    column struck-shows the old alias name before the exact A alias.
    """
    body = render_diff_state["captures"]["alert"].body
    row = row_containing(body, f"host={S8_IP}")
    assert f"<s>{S8_ALIAS_LOGGED}</s>" in row, f"S8 ({S8_IP}) expected the stale alias struck: {row!r}"
    assert "pfB_RVAliasA_v4" in row, f"S8 ({S8_IP}) expected the exact current alias pfB_RVAliasA_v4: {row!r}"
    assert "pfB_RVAliasZ_v4" not in row, f"S8 ({S8_IP}) unexpectedly attributed the longer Z decoy: {row!r}"
    feed_change = (
        f"<s>{FEED_C8_NAME}</s><br /><small><s>{S8_IP}</s></small><br />{FEED_A_NAME}<br /><small>{S8_IP}</small>"
    )
    cells = re.findall(r"<td(?:\s[^>]*)?>(.*?)</td>", row, re.DOTALL)
    assert cells, f"S8 ({S8_IP}) row has no table cells: {row!r}"
    assert cells[-1] == feed_change, f"S8 ({S8_IP}) expected Feed cell {feed_change!r}, got {cells[-1]!r}"


def test_s9_outbound_direction_still_listed(render_diff_state: dict[str, dict[str, Capture]]) -> None:
    """S9: an OUTBOUND still-listed row attributes the DST (not SRC) as the blocked host.

    Given: dir='out' -> convert_ip_log() picks $fields[8] (DST) as the host; S9's
    DST is 192.0.2.50, logged against RVFeedA and present in FEED_A.
    Then: the row renders clean (no strike), proving the outbound attribution
    branch is exercised (S1 already covers the inbound branch).
    """
    body = render_diff_state["captures"]["alert"].body
    row = row_containing(body, f"host={S9_IP}")
    assert "Not listed!" not in row, f"S9 ({S9_IP}) outbound row wrongly rendered 'Not listed!': {row!r}"
    assert "<s>" not in row, f"S9 ({S9_IP}) outbound row unexpectedly struck: {row!r}"


def test_s10_et_feed_row_renders(render_diff_state: dict[str, dict[str, Capture]]) -> None:
    """S10: an ET/Proofpoint-header feed (':' in the feed name) row renders still-listed.

    Given: the logged feed is 'RVETCat:RVFeedS10' -- the ':' strips the category
    prefix and routes the row's validate to $pfb['etdir'] instead of deny/native.
    Then: 192.0.2.90 (present in FEED_ET) renders clean, proving the ET-header
    folder-selection branch.
    """
    body = render_diff_state["captures"]["alert"].body
    row = row_containing(body, f"host={S10_IP}")
    assert "Not listed!" not in row, f"S10 ({S10_IP}) ET-feed row wrongly rendered 'Not listed!': {row!r}"


def test_permit_still_listed_and_delisted(render_diff_state: dict[str, dict[str, Capture]]) -> None:
    """Permit log: one still-listed row, one de-listed row (branch coverage, permit side).

    Permit/Match rows carry no suppression '+' icon (that is Block-only), so there
    is no ``host=<ip>`` marker -- locate the row by the bare IP (each P/M IP is
    unique to its own log).
    """
    body = render_diff_state["captures"]["alert"].body
    listed = row_containing(body, P1_IP)
    assert "Not listed!" not in listed, f"Permit {P1_IP} (still-listed) wrongly rendered 'Not listed!': {listed!r}"
    delisted = row_containing(body, P2_IP)
    assert "Not listed!" in delisted, f"Permit {P2_IP} (de-listed) expected 'Not listed!': {delisted!r}"


def test_match_still_listed_and_delisted(render_diff_state: dict[str, dict[str, Capture]]) -> None:
    """Match log: one still-listed row, one de-listed row (branch coverage, match side).

    Same bare-IP row location as the permit test (no ``host=`` marker on Match rows).
    """
    body = render_diff_state["captures"]["alert"].body
    listed = row_containing(body, M1_IP)
    assert "Not listed!" not in listed, f"Match {M1_IP} (still-listed) wrongly rendered 'Not listed!': {listed!r}"
    delisted = row_containing(body, M2_IP)
    assert "Not listed!" in delisted, f"Match {M2_IP} (de-listed) expected 'Not listed!': {delisted!r}"


def test_d1_logged_fields_render_verbatim(render_diff_state: dict[str, dict[str, Capture]]) -> None:
    """D1: the row renders its logged attribution directly (ADR-65 D2).

    Given: rv809-c1.com's log line carries RVLoggedGroup1/RVLoggedFeed1.
    Then: the row renders both values verbatim, with no strike markup.
    """
    body = render_diff_state["captures"]["alert"].body
    row = row_containing(body, D1_DOMAIN)
    assert D1_LOGGED_GROUP in row, f"D1 expected the logged group {D1_LOGGED_GROUP!r} present: {row!r}"
    assert D1_LOGGED_FEED in row, f"D1 expected the logged feed {D1_LOGGED_FEED!r} present: {row!r}"
    assert "<s>" not in row, f"D1 expected no strikethrough markup: {row!r}"


def test_d2_data_bait_ignored_renders_logged_fields(render_diff_state: dict[str, dict[str, Capture]]) -> None:
    """D2: a pfb_py_data.txt exact-domain hit is bait the render must IGNORE (ADR-65 D2).

    Given: rv809-d1.com is appended to pfb_py_data.txt with group=RVGroupD/
    feed=RVFeedD; the logged line carries different group/feed.
    Then: the row renders the LOGGED group/feed verbatim, with no strike markup
    and no leaked data-file value.
    """
    body = render_diff_state["captures"]["alert"].body
    row = row_containing(body, D2_DOMAIN)
    assert D2_LOGGED_GROUP in row, f"D2 expected the logged group {D2_LOGGED_GROUP!r} present: {row!r}"
    assert D2_LOGGED_FEED in row, f"D2 expected the logged feed {D2_LOGGED_FEED!r} present: {row!r}"
    assert "<s>" not in row, f"D2 expected no strikethrough markup: {row!r}"
    assert D2_DATA_GROUP not in row, f"D2 expected the data-bait group {D2_DATA_GROUP!r} absent: {row!r}"
    assert D2_DATA_FEED not in row, f"D2 expected the data-bait feed {D2_DATA_FEED!r} absent: {row!r}"


def test_d3_zone_bait_ignored_renders_logged_mode_and_domain(render_diff_state: dict[str, dict[str, Capture]]) -> None:
    """D3: a per-label zone-file (TLD wildcard) hit is bait the render must IGNORE (ADR-65 D2).

    Given: domain sub.rv809-z1.com is logged mode=DNSBL; pfb_py_zone.txt carries
    an entry for the ONE-LABEL-STRIPPED suffix rv809-z1.com -- the group/feed
    are the SAME for both (D3_GROUP/D3_FEED), so mode+domain are the only
    discriminators here.
    Then: the row keeps the LOGGED mode (DNSBL, not TLD) and the LOGGED
    (sub)domain, with no strike markup and no re-attributed threat-lookup href
    for the stripped parent.
    """
    body = render_diff_state["captures"]["alert"].body
    row = row_containing(body, D3_DOMAIN)
    assert '<s title="Previous Blocking Mode">' not in row, f"D3 expected no struck-mode markup: {row!r}"
    assert "TLD" not in row, f"D3 expected the logged mode 'DNSBL' kept, not re-attributed to 'TLD': {row!r}"
    assert '<s title="Previous Domain' not in row, f"D3 expected no struck-previous-domain markup: {row!r}"
    domain_href = f"pfblockerng_threats.php?domain={D3_DOMAIN}"
    assert domain_href in row, f"D3 expected the logged-domain threat href {domain_href!r} present: {row!r}"
    # D3_PARENT ("rv809-z1.com") is a trailing substring of D3_DOMAIN
    # ("sub.rv809-z1.com") -- the '=' vs '.' boundary keeps this a valid negative
    # (the parent's OWN href, "...=rv809-z1.com", is not a substring of
    # "...=sub.rv809-z1.com").
    parent_href = f"pfblockerng_threats.php?domain={D3_PARENT}"
    assert parent_href not in row, f"D3 expected NO re-attributed parent threat href {parent_href!r}: {row!r}"


def test_d4_total_miss_renders_logged_fields_not_unknown(render_diff_state: dict[str, dict[str, Capture]]) -> None:
    """D4: a domain absent from cache/data/zone no longer gets rewritten to Unknown (ADR-65 D2).

    Given: rv809-gone1.com exists nowhere on disk.
    Then: the row renders the LOGGED group/feed verbatim -- no re-check runs, so
    there is nothing left to fall through to 'Unknown'.
    """
    body = render_diff_state["captures"]["alert"].body
    row = row_containing(body, D4_DOMAIN)
    assert D4_LOGGED_GROUP in row, f"D4 expected the logged group {D4_LOGGED_GROUP!r} present: {row!r}"
    assert D4_LOGGED_FEED in row, f"D4 expected the logged feed {D4_LOGGED_FEED!r} present: {row!r}"
    assert "<s>" not in row, f"D4 expected no strikethrough markup: {row!r}"
    assert "Unknown" not in row, f"D4 expected no 'Unknown' rewrite of a total miss: {row!r}"


def test_d5_upstream_renders_cloud_icon_and_group(render_diff_state: dict[str, dict[str, Capture]]) -> None:
    """D5: an Upstream_Block row skips the stale-correction re-parse and shows the cloud icon.

    Reuses the exact CSV shape + assertions of the existing
    test_upstream_block_renders_cloud_icon_and_correct_group precedent.
    """
    body = render_diff_state["captures"]["alert"].body
    row = row_containing(body, D5_DOMAIN)
    assert "fa-cloud" in row, f"D5 upstream row missing the cloud-icon override: {row!r}"
    assert "Upstream" in row, f"D5 upstream row missing the preserved 'Upstream' group: {row!r}"
    assert "Unknown" not in row, f"D5 upstream row wrongly ran the stale-entry correction ('Unknown' present): {row!r}"


def test_d7_uncovered_metachar_domain_renders_logged_fields(render_diff_state: dict[str, dict[str, Capture]]) -> None:
    """D7: a metachar domain (nowhere on disk) renders its LOGGED fields, no re-derivation (ADR-65 D2).

    Given: 'rv809*m1.com' contains '*', outside PFB_FILTER_DOMAIN's
    [a-zA-Z0-9_.-] charset -- historically this excluded it from
    pfb_dnsbl_prefetch()'s 'covered' set (issue #809 review, "B2"). That whole
    re-check is gone, so the metachar shape is now moot: the row renders its
    logged group/feed exactly like D4's plain total miss.
    """
    body = render_diff_state["captures"]["alert"].body
    row = row_containing(body, D7_DOMAIN)
    assert D7_LOGGED_GROUP in row, f"D7 expected the logged group {D7_LOGGED_GROUP!r} present: {row!r}"
    assert D7_LOGGED_FEED in row, f"D7 expected the logged feed {D7_LOGGED_FEED!r} present: {row!r}"
    assert "<s>" not in row, f"D7 expected no strikethrough markup: {row!r}"
    assert "Unknown" not in row, f"D7 expected no 'Unknown' rewrite of a total miss: {row!r}"


def test_d8_covered_metachar_domain_data_bait_ignored(
    render_diff_state: dict[str, dict[str, Capture]],
) -> None:
    """D8: a metachar domain WITH a data-file bait row still renders its LOGGED fields (ADR-65 D2).

    Given: 'rv809*p1.com' also contains '*' like D7, but unlike D7 its NDJSON
    row IS present in pfb_py_data.txt (group=RVGroupMeta/feed=RVFeedMeta) --
    historically this exercised pfb_dnsbl_parse_compute()'s per-row fallback
    (issue #837/#1083). That re-check is gone; the data-file row is now bait
    the render must ignore just like D1/D2's cache/data bait.
    """
    body = render_diff_state["captures"]["alert"].body
    row = row_containing(body, D8_DOMAIN)
    assert D8_LOGGED_GROUP in row, f"D8 expected the logged group {D8_LOGGED_GROUP!r} present: {row!r}"
    assert D8_LOGGED_FEED in row, f"D8 expected the logged feed {D8_LOGGED_FEED!r} present: {row!r}"
    assert "<s>" not in row, f"D8 expected no strikethrough markup: {row!r}"
    assert D8_DATA_GROUP not in row, f"D8 expected the data-bait group {D8_DATA_GROUP!r} absent: {row!r}"
    assert D8_DATA_FEED not in row, f"D8 expected the data-bait feed {D8_DATA_FEED!r} absent: {row!r}"
    assert "Unknown" not in row, f"D8 expected no 'Unknown' rewrite: {row!r}"


def test_ip_block_nonfilter_cap_enforced(render_diff_state: dict[str, dict[str, Capture]]) -> None:
    """The default alert view never renders more than pfbdenycnt=25 Block rows.

    Given: 39 non-dup Block rows were fed (30 filler + 9 scenarios -- S7 is a
    dup marker, not its own row).
    Then: the Block panel's <tbody> (region 0 -- alert_view='alert' iterates
    Block, DNSBL Python, Permit, Match in that literal array order; the
    Unlocked-IP/Domain panel is absent since no unlock entries were seeded)
    renders AT MOST 25 rows.
    """
    body = render_diff_state["captures"]["alert"].body
    # The positional region indexing below assumes the "Unlocked IP(s) & Domain(s)"
    # panel is ABSENT (this module never unlocks anything) -- but that panel is gated
    # on process-external unlock state a misbehaving sibling module could leave behind.
    # Assert the assumption instead of trusting it, so a polluted VM fails loudly here
    # rather than silently shifting every region index.
    assert "Unlocked IP(s)" not in body, (
        "alert view unexpectedly shows the Unlocked IP(s) & Domain(s) panel -- foreign unlock "
        "state left by another module; region indexes below would be shifted"
    )
    regions = _extract_tbody_regions(body)
    assert regions, "alert view rendered no <tbody> regions at all"
    block_rows = len(_TR_RE.findall(regions[0]))
    assert block_rows <= 25, (
        f"Block panel rendered {block_rows} rows -- expected <= 25 (pfbdenycnt default); "
        f"39 non-dup rows were fed, so the cap must have truncated"
    )


def test_dnsbl_nonfilter_cap_enforced(render_diff_state: dict[str, dict[str, Capture]]) -> None:
    """The default alert view never renders more than pfbdnscnt=25 DNSBL Python rows.

    Given: 37 non-dup DNSBL rows were fed (30 filler + 7 scenarios -- D6 is a
    dup marker, not its own row).
    Then: the DNSBL Python panel's <tbody> (region 1, see the ordering note on
    the Block-cap test above) renders AT MOST 25 rows.
    """
    body = render_diff_state["captures"]["alert"].body
    # Same foreign-unlock-state guard as the Block-cap test above: positional region
    # indexing is only valid while the Unlocked panel is absent.
    assert "Unlocked IP(s)" not in body, (
        "alert view unexpectedly shows the Unlocked IP(s) & Domain(s) panel -- foreign unlock "
        "state left by another module; region indexes below would be shifted"
    )
    regions = _extract_tbody_regions(body)
    assert len(regions) >= 2, f"expected >= 2 <tbody> regions (Block, DNSBL Python, ...); got {len(regions)}"
    dnsbl_rows = len(_TR_RE.findall(regions[1]))
    assert dnsbl_rows <= 25, (
        f"DNSBL Python panel rendered {dnsbl_rows} rows -- expected <= 25 (pfbdnscnt default); "
        f"37 non-dup rows were fed, so the cap must have truncated"
    )


def test_unified_nonfilter_cap_enforced(render_diff_state: dict[str, dict[str, Capture]]) -> None:
    """?view=unified never renders more than pfbunicnt=200 rows, though > 200 were fed."""
    body = render_diff_state["captures"]["unified"].body
    regions = _extract_tbody_regions(body)
    assert regions, "unified view rendered no <tbody> region at all"
    unified_rows = len(_TR_RE.findall(regions[0]))
    assert unified_rows <= 200, (
        f"Unified table rendered {unified_rows} rows -- expected <= 200 (pfbunicnt default); "
        f"well over 200 qualifying rows were fed, so the cap must have truncated"
    )


def test_filterip_narrows_to_alias(render_diff_state: dict[str, dict[str, Capture]]) -> None:
    """?filterip=<alias> narrows the alert view's IP tables to that ALIAS (not a literal IP).

    Correction vs. the naive reading of the param name: filterip sets
    filterfieldsarray[0][13], which lands on convert_ip_log()'s POST-REORDER
    field 13 -- the ALIAS NAME, not the SRC/DST IP -- confirmed by reading the
    "Fields Reference" comment + pfb_match_filter_field()'s call site.
    """
    body = render_diff_state["captures"]["alert_filterip"].body
    assert S1_ALIAS in body, f"filtered alert view missing the filtered-for alias {S1_ALIAS!r}"
    assert S2_ALIAS not in body, f"a DIFFERENT alias {S2_ALIAS!r} leaked into the filterip={S1_ALIAS!r} view"


def test_filterdnsbl_narrows_to_group(render_diff_state: dict[str, dict[str, Capture]]) -> None:
    """?filterdnsbl=<group> narrows the alert view's DNSBL table to that GROUP (not a literal domain).

    Correction vs. the naive reading of the param name: filterdnsbl sets
    filterfieldsarray[1][13] -- the LOGGED group name (ADR-65 D2: filtering
    matches what actually blocked, not a re-derived current value).
    """
    body = render_diff_state["captures"]["alert_filterdnsbl"].body
    assert D1_LOGGED_GROUP in body, f"filtered alert view missing the filtered-for group {D1_LOGGED_GROUP!r}"
    assert D2_LOGGED_GROUP not in body, f"a DIFFERENT group {D2_LOGGED_GROUP!r} leaked into the filterdnsbl view"


def test_unified_filterip_narrows_ip_rows(render_diff_state: dict[str, dict[str, Capture]]) -> None:
    """?view=unified&filterip=<alias> narrows the Unified table's IP-type rows to that alias.

    DNSBL/DNS-reply rows in the SAME unified table are UNAFFECTED by filterip
    (convert_dnsbl_log()'s own filter array is untouched by the ip-only param),
    so only the IP-row narrowing is asserted here.
    """
    body = render_diff_state["captures"]["unified_filterip"].body
    assert S1_ALIAS in body, f"unified filtered view missing the filtered-for alias {S1_ALIAS!r}"
    assert S2_ALIAS not in body, f"a DIFFERENT alias {S2_ALIAS!r} leaked into the unified filterip view"


def test_dnsbl_stat_view_renders_seeded_token(render_diff_state: dict[str, dict[str, Capture]]) -> None:
    """?view=dnsbl_stat renders a panel containing a seeded DNSBL domain."""
    body = render_diff_state["captures"]["dnsbl_stat"].body
    assert D1_DOMAIN in body, f"dnsbl_stat view missing the seeded domain {D1_DOMAIN!r}"


def test_ip_block_stat_view_renders_seeded_token(render_diff_state: dict[str, dict[str, Capture]]) -> None:
    """?view=ip_block_stat renders a panel containing a seeded Block alias/IP."""
    body = render_diff_state["captures"]["ip_block_stat"].body
    assert S1_ALIAS in body, f"ip_block_stat view missing the seeded alias {S1_ALIAS!r}"


def test_ip_permit_stat_view_renders_seeded_token(render_diff_state: dict[str, dict[str, Capture]]) -> None:
    """?view=ip_permit_stat renders a panel containing a seeded Permit alias/IP."""
    body = render_diff_state["captures"]["ip_permit_stat"].body
    assert P1_ALIAS in body, f"ip_permit_stat view missing the seeded alias {P1_ALIAS!r}"


def test_ip_match_stat_view_renders_seeded_token(render_diff_state: dict[str, dict[str, Capture]]) -> None:
    """?view=ip_match_stat renders a panel containing a seeded Match alias/IP."""
    body = render_diff_state["captures"]["ip_match_stat"].body
    assert M1_ALIAS in body, f"ip_match_stat view missing the seeded alias {M1_ALIAS!r}"


def test_dnsbl_reply_stat_view_renders_seeded_token(render_diff_state: dict[str, dict[str, Capture]]) -> None:
    """?view=dnsbl_reply_stat renders a panel containing a seeded DNS Reply domain."""
    body = render_diff_state["captures"]["dnsbl_reply_stat"].body
    assert DNS_REPLY_1[4] in body, f"dnsbl_reply_stat view missing the seeded reply domain {DNS_REPLY_1[4]!r}"


def test_reply_view_renders_seeded_domains(render_diff_state: dict[str, dict[str, Capture]]) -> None:
    """?view=reply renders both seeded DNS Reply rows."""
    body = render_diff_state["captures"]["reply"].body
    for reply in (DNS_REPLY_1, DNS_REPLY_2):
        assert reply[4] in body, f"reply view missing the seeded domain {reply[4]!r}"


def test_alert_view_stable_across_unmutated_rerender(render_diff_state: dict[str, dict[str, Capture]]) -> None:
    """GET #12 (a bare re-render) reproduces GET #1's tbody hashes byte-for-byte.

    Scenario: idempotent re-render.
    Given: GET #1 (alert view) rendered every row from its own log line.
    When: the SAME view is GET-ted again (GET #12) with no log/file
        mutation in between.
    Then: every <tbody> region hashes IDENTICALLY.
    """
    captures = render_diff_state["captures"]
    first_hashes = [_sha256(r.encode()) for r in _extract_tbody_regions(captures["alert"].body)]
    second_hashes = [_sha256(r.encode()) for r in _extract_tbody_regions(captures["alert_2"].body)]
    assert first_hashes == second_hashes, (
        "alert view re-render diverged from its first unmutated render:\n"
        f"expected (GET #1 region hashes): {first_hashes}\n"
        f"actual   (GET #12 region hashes): {second_hashes}"
    )


def test_all_captures_pass_clean_render_oracle(render_diff_state: dict[str, dict[str, Capture]]) -> None:
    """Every capture (baseline + main, every GET in the matrix) is a clean render.

    Applies the Tier-A oracle (status 200, no rendered PHP diagnostic shape, the
    'Alert Settings' marker present and not the login form) to every single
    response this module collected -- a populated log must never itself trigger
    a PHP warning/notice/fatal.
    """
    for label, store in (("baseline", render_diff_state["baseline"]), ("main", render_diff_state["captures"])):
        for key, cap in store.items():
            result = evaluate_render(f"{label}:{key}", cap.status, cap.body, MARKERS)
            assert result.ok, f"capture {label}:{key} failed the render oracle: {result.detail}"
