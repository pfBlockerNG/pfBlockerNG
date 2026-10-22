"""Shared helpers for the two-node HA policy-sync smoke modules (issue #3455).

Node A (``pair.primary``) sends, node B (``pair.secondary``) receives. Nothing here invents a transport,
endpoint or double: the sender is configured exactly as the Sync page stores it, the send is triggered by the
real event (core's ``rc.filter_synchronize`` for the automatic transport, a package apply pass for the manual
one), and every completion is read from the records the package itself writes:

* A's ``pfb_sync_send.json`` (``handed`` / ``sent`` / ``failed`` per target, with the digest),
* B's ``pfb_sync_receive.json`` (``last`` receive outcome, its digests and ignored paths, and the separate
  ``apply`` record),
* B's ``UPDATE PROCESS START`` banners (one per apply pass).

Scheduled ticks stay off (``.pfb_cron_disable``); the only pass that can run on B is the receive-triggered one.
Guest work goes through ``/bin/sh`` (``SmokeVM.ssh``) or pfSsh snippets (``helpers.php_eval``).
"""

# ruff: noqa: E501 -- embedded PHP is one statement per line (pfSsh buffers by line).

from __future__ import annotations

import json
import secrets
import subprocess
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

from . import helpers as h
from .conftest import SmokeVM
from .ha_pair import HA_USER, SECONDARY_SYNC_IP, HaPair, _redact, clear_sshguard, xmlrpc_call

Transport = Literal["automatic", "manual"]
TRANSPORTS: tuple[Transport, ...] = ("automatic", "manual")

CONFIG = "/conf/config.xml"
PKGS = "installedpackages"
GEN = f"{PKGS}/pfblockerng/config/0"
IP = f"{PKGS}/pfblockerngipsettings/config/0"
DNSBL = f"{PKGS}/pfblockerngdnsblsettings/config/0"
DNS = f"{PKGS}/pfblockerngdns/config/0"
SYNC = f"{PKGS}/pfblockerngsync/config/0"
LISTS_V4 = f"{PKGS}/pfblockernglistsv4"
LISTS_V6 = f"{PKGS}/pfblockernglistsv6"
BLACKLIST = f"{PKGS}/pfblockerngblacklist"
GLOBAL = f"{PKGS}/pfblockerngglobal"

RECEIVE_FILE = f"{h.PFB_DBDIR}/pfb_sync_receive.json"
SEND_FILE = f"{h.PFB_DBDIR}/pfb_sync_send.json"
STATE_FILES = (
    RECEIVE_FILE,
    SEND_FILE,
    f"{h.PFB_DBDIR}/pfb_sync_findings.json",
    f"{h.PFB_DBDIR}/pfb_sync_copied.json",
)
# Written once per update pass by sync_package_pfblockerng(); with cron inhibited, nothing else prints it.
APPLY_BANNER = "UPDATE PROCESS START"
# Salvage caps for events whose only completion signal is a record: never assertions.
SETTLE_TIMEOUT = 300.0
FILTER_RELOAD_TIMEOUT = 120.0

# The package's own pinned row-local leaves (pfb_sync_local_paths()['row']; 'infolists' is a retired tag).
ROW_LOCAL_LEAVES = ("srcint", "script_pre", "script_post", "agateway_in", "agateway_out")
# What the receive merge gives a row it has never seen (pfb_sync_policy_merge(): the editor's local defaults).
NEW_ROW_DEFAULTS = {
    "srcint": "",
    "script_pre": "",
    "script_post": "",
    "agateway_in": "default",
    "agateway_out": "default",
}
BLACKLIST_CREDENTIAL_LEAVES = ("username", "password")

# The four scalar credential leaves (settings sections); the other two are every Blacklist item's username/password.
CREDENTIAL_SCALARS = {
    "maxmind_account": f"{IP}/maxmind_account",
    "maxmind_key": f"{IP}/maxmind_key",
    "asn_token": f"{IP}/asn_token",
    "top1m_token": f"{DNSBL}/top1m_token",
}

_OPEN, _CLOSE = "<<<PFB3455>>>", "<<<END3455>>>"
# `global $pfb` binds the package globals whichever scope pfSsh.php evals the buffer in.
_PRELUDE = (
    "require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');\n"
    "require_once('/usr/local/pkg/pfblockerng/pfblockerng_extra.inc');\n"
    "global $pfb;\n"
    "pfb_global();\n"
)


# --------------------------------------------------------------------------- #
# Pure helpers (pinned off-box in tests/test_issue3455_ha_policy.py)
# --------------------------------------------------------------------------- #


def sentinel(tag: str, name: str) -> str:
    """A greppable, redaction-safe value that names its node and leaf: ``PFBHA-A-maxmind_key``."""
    return f"PFBHA-{tag}-{name}"


def sender_section(
    transport: Transport, *, scope: str, password: str, timeout: int, ip: str = SECONDARY_SYNC_IP, user: str = HA_USER
) -> dict[str, Any]:
    """The sync section ``pfblockerng_sync.php`` stores on the sender (``installedpackages/pfblockerngsync/config/0``).

    Automatic hands the paths to core; manual stores one enabled HTTPS target row with the HA credentials.
    ``scope`` is the stored ``syncscope`` leaf: the registry default alone never sends.
    """
    section: dict[str, Any] = {
        "syncscope": scope,
        "varsynconchanges": "auto" if transport == "automatic" else "manual",
        "varsynctimeout": str(timeout),
    }
    if transport == "manual":
        section["row"] = [
            {
                "varsyncprotocol": "https",
                "varsyncipaddress": ip,
                "varsyncport": "443",
                "varsyncusername": user,
                "varsyncpassword": password,
                "varsyncdestinenable": "on",
            }
        ]
    return section


def diff_leaves(before: Mapping[str, Any], after: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    """What moved between two ``path -> leaf`` maps: ``changed`` (before, after), ``removed`` and ``added``."""
    return {
        "changed": {p: (before[p], after[p]) for p in before if p in after and before[p] != after[p]},
        "removed": {p: before[p] for p in before if p not in after},
        "added": {p: after[p] for p in after if p not in before},
    }


def unexpected_additions(added: Mapping[str, Any], new_rows: Iterable[str]) -> dict[str, Any]:
    """The added leaves that are NOT a new row's editor defaults.

    ``new_rows`` are section-relative row prefixes, e.g. ``installedpackages/pfblockernglistsv4/config/3``. A new
    group may bring exactly the leaves of :data:`NEW_ROW_DEFAULTS` at those defaults (the merge's "new-row local
    defaults"); a new Blacklist item row may bring empty ``username`` / ``password``.
    """
    prefixes = tuple(f"{row}/" for row in new_rows)
    allowed = {**NEW_ROW_DEFAULTS, **dict.fromkeys(BLACKLIST_CREDENTIAL_LEAVES, "")}
    return {
        path: value
        for path, value in added.items()
        if not (
            path.startswith(prefixes) and path.rsplit("/", 1)[1] in allowed and value == allowed[path.rsplit("/", 1)[1]]
        )
    }


def ip_group(
    alias: str, feed: str, *, action: str = "Deny_Inbound", local: Mapping[str, str] | None = None
) -> dict[str, Any]:
    """One IP list group as the category editor stores it (policy leaves, ``local`` row-local leaves, one feed row)."""
    row = {"header": alias, "url": feed, "state": "Enabled", "format": "auto"}
    return {"aliasname": alias, "action": action, "cron": "EveryDay", **(local or {}), "row": [row]}


def blacklist_item(xml: str, *, username: str = "", password: str = "") -> dict[str, str]:
    """One Blacklist provider row; ``xml`` is its identity, ``username`` / ``password`` are receiver-local."""
    return {
        "title": f"PFBHA {xml}",
        "xml": xml,
        "feed": f"https://feeds.invalid/{xml}.tar.gz",
        "size": "1",
        "selected": "",
        "username": username,
        "password": password,
    }


def group_local_values(tag: str, gateway: str) -> dict[str, str]:
    """A node's own row-local leaves for one group: ``tag`` names the node, ``gateway`` is a real gateway or default."""
    return {
        "srcint": "lan" if tag == "A" else "wan",
        "script_pre": f"/tmp/{sentinel(tag, 'script_pre')}.sh",
        "script_post": f"/tmp/{sentinel(tag, 'script_post')}.sh",
        "agateway_in": gateway,
        "agateway_out": gateway,
    }


# Every ``sync: local`` registry key (pfb_cfg_registry(): the 60 that never leave a node) the two guests keep apart, as
# (A's value, B's value). Each is a value the package reads as given, and none breaks a node's apply pass or DNSBL.
_LOG_SINKS = (
    "log",
    "errlog",
    "extraslog",
    "ip_blocklog",
    "ip_permitlog",
    "ip_matchlog",
    "ip_parse_err",
    "dnslog",
    "dnsbl_parse_err",
    "dnsreplylog",
    "unilog",
)
LOCAL_SEEDS: dict[str, tuple[str, str]] = {
    f"{IP}/maxmind_locale": ("de", "fr"),
    f"{IP}/asn_reporting": ("on", ""),
    f"{IP}/enable_rdns": ("on", ""),
    f"{IP}/inbound_interface": ("lan", "wan"),
    f"{IP}/outbound_interface": ("lan", "wan"),
    f"{DNSBL}/pfb_cache": ("on", ""),
    f"{DNSBL}/dnsbl_allow_int": ("lan", ""),
    f"{DNSBL}/dnsbl_redir_int": ("lan", ""),
    f"{DNSBL}/dnsbl_dot_block_int": ("lan", ""),
    f"{DNSBL}/pfb_dnsport": ("8082", "8083"),
    f"{DNSBL}/pfb_dnsport_ssl": ("8444", "8445"),
    f"{DNSBL}/pfb_cache_flush": ("on", ""),
    f"{DNSBL}/pfb_py_reply": ("on", ""),
    f"{DNSBL}/pfb_py_nolog": ("on", ""),
    f"{DNSBL}/pfb_py_cache_max": ("5000", "20000"),
    f"{DNSBL}/pfb_control": ("on", ""),
    f"{DNSBL}/pfb_control_legacy": ("on", ""),
    f"{GLOBAL}/alertrefresh": ("on", ""),
    f"{GEN}/pfb_syntax_highlight": ("on", ""),
    f"{GEN}/pfb_log_trim_margin_pct": ("5", "10"),
    f"{GEN}/pfb_reentry_timeout": ("1900", "2100"),
    f"{GEN}/pfb_software_check": ("on", ""),
    f"{GEN}/pfb_alias_delta_mode": ("replace", "auto"),
    f"{GEN}/pfb_alias_delta_batch": ("256", "1024"),
    f"{GEN}/log_syslog": ("on", ""),
    # B's own scope is not the sender's: B stays a receiver whatever A sends (R14).
    f"{SYNC}/syncscope": ("policy", "lists"),
    **{f"{GEN}/log_max_{sink}": ("15000", "25000") for sink in _LOG_SINKS},
    **{f"{GEN}/log_max_days_{sink}": ("7", "30") for sink in _LOG_SINKS},
}
# The two gateway leaves are seeded per node by ``seed_node``: a real gateway of the node, or ``default``.
GATEWAY_LEAVES = (f"{DNSBL}/agateway_in", f"{DNSBL}/agateway_out")
# The ``sync: local`` registry keys NOT seeded with distinct values, each with the reason a distinct value would break
# the pair. The run prints this list (``arrange_baseline``).
UNSEEDED_LOCAL_KEYS = {
    f"{GEN}/settings_family": "the installer's own mode marker (pfb_settings_family_record() owns it), not a setting",
    f"{GEN}/pfb_reuse": "a one-shot flag the update pass clears itself, so a seeded 'on' does not outlive the baseline pass",
    f"{DNSBL}/pfb_dnsvip_auto": "turns VIP management on, which rewrites the DNSBL VIP object whose uniqid the tests pin",
    f"{DNSBL}/dnsbl_interface": "must be the interface of the node's DNSBL VIP (lo0): pfb_validate_vips() disables DNSBL otherwise",
    f"{DNSBL}/pfb_dnsvip6": "names a VIP object the guests do not have: a dangling reference disables DNSBL",
    f"{GEN}/pfb_metrics_export": "'on' needs pfSense-pkg-node_exporter on the node (the save gate refuses it without), and no HA guest installs that package",
    f"{DNS}/pfb_dns": "turns pfB-DNS on, which moves the node's Resolver off its port and ends the DNSBL probes the harness runs",
    f"{DNS}/pfb_dns_saved": "the Resolver snapshot the apply writes itself when it moves the Resolver; a seeded value reads as a moved one",
    f"{DNS}/pfb_dns_interface": "read once pfB-DNS is on, which this harness leaves off: a seeded value changes nothing",
    f"{DNS}/pfb_dns_dot": "turns the TLS listener on, which needs the Resolver's certificate the guests do not have",
    f"{DNS}/pfb_dns_dot_port": "read only while DoT is on, which this harness leaves off: a seeded value changes nothing",
    f"{DNS}/pfb_dns_dot_interface": "read only while DoT is on, which this harness leaves off: a seeded value changes nothing",
    f"{DNS}/pfb_dns_sslcertref": "names the Resolver's certificate, which the guests do not have: a seeded value would dangle",
    **{
        f"{DNS}/pfb_dns_{kind}": "turns the TLS listener on, which needs the Resolver's certificate the guests do not have"
        for kind in ("doh", "doq")
    },
    **{
        f"{DNS}/pfb_dns_{leaf}": "read only while its DoH/DoQ toggle is on, which this harness leaves off: a seeded value changes nothing"
        for leaf in ("doh_port", "doh_interface", "doh_trusted", "doq_port", "doq_interface")
    },
    **{
        f"{DNS}/pfb_dns_{leaf}": "read only while pfB-DNS is on, which this harness leaves off: a seeded value changes nothing"
        for leaf in ("ddr", "ddr_doh_443")
    },
}


def node_local_leaves(tag: str, *, vip_uniqid: str) -> dict[str, Any]:
    """The local leaves the two nodes hold apart, ``tag`` = ``A`` or ``B``: every :data:`LOCAL_SEEDS` key but the gateways.

    The four scalar credentials carry per-node sentinels, and so do the widget and hook leaves the registry does not
    list. B's DNSBL VIP reference carries ITS OWN uniqid (#3441: the same address, another uniqid, must survive a
    receive).
    """
    leaves: dict[str, Any] = {path: sentinel(tag, name) for name, path in CREDENTIAL_SCALARS.items()}
    leaves.update({path: values[int(tag == "B")] for path, values in LOCAL_SEEDS.items()})
    leaves[f"{GLOBAL}/widget-pfblockerng"] = sentinel(tag, "widget-pfblockerng")
    # A disabled hook never runs; only its stored row matters.
    leaves[f"{GEN}/hooks/row"] = [
        {
            "script": f"hook_post_{sentinel(tag, 'hook')}.sh",
            "when": "post",
            "enabled": "",
            "description": sentinel(tag, "hook"),
            "timeout": "5",
        }
    ]
    if tag == "B":
        leaves[f"{DNSBL}/pfb_dnsvip4"] = f"_vip{vip_uniqid}"
    return leaves


# --------------------------------------------------------------------------- #
# Guest plumbing
# --------------------------------------------------------------------------- #


def emit(expr: str) -> str:
    """PHP that echoes ``json_encode(expr)`` between sentinels (pfSsh.php prints a banner of its own)."""
    return f"echo {h._php_str(_OPEN)} . json_encode({expr}) . {h._php_str(_CLOSE)};"


def php_json(vm: SmokeVM, php: str, *, secret_values: Iterable[str] = (), timeout: float = 120.0) -> Any:
    """Run ``php`` after the package prelude and return the JSON it emitted; secrets never reach a message."""
    result = h.php_eval(vm, _PRELUDE + php, timeout=timeout)
    out = result.stdout
    start, end = out.find(_OPEN), out.find(_CLOSE)
    if result.returncode != 0 or start == -1 or end == -1:
        text = _redact(f"rc={result.returncode} stdout={out[-800:]!r} stderr={result.stderr[-300:]!r}", secret_values)
        raise RuntimeError(f"guest snippet emitted no result: {text}")
    return json.loads(out[start + len(_OPEN) : end])


def php_write(
    vm: SmokeVM,
    php: str,
    message: str,
    *,
    secret_values: Iterable[str] = (),
    timeout: float = 120.0,
    sync: bool = False,
) -> None:
    """Run ``php`` after the package prelude, then ``write_config`` it; the snippet must not echo anything.

    Core's ``write_config()`` raises a "filter sync" event, and ``rc.filter_synchronize`` then runs on its own seconds
    later on a node with HA sync set: a stale request landing on B at a moment the test does not control. A harness
    write therefore saves the file only (``$write_config_only``) unless ``sync`` asks for the event.
    """
    save = f"write_config({h._php_str(message)}, TRUE, {'FALSE' if sync else 'TRUE'});"
    result = h.php_eval(vm, _PRELUDE + php + f"\n{save}\necho 'OK';", timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        text = _redact(
            f"rc={result.returncode} stdout={result.stdout[-800:]!r} stderr={result.stderr[-300:]!r}", secret_values
        )
        raise RuntimeError(f"config write {message!r} failed: {text}")


def _json_php(value: Any) -> str:
    """A PHP expression that decodes ``value`` (JSON) into an associative array; ``''`` stays ``''``, ``[]`` stays ``array()``."""
    return f"json_decode({h._php_str(json.dumps(value))}, TRUE)"


def set_leaves(vm: SmokeVM, leaves: Mapping[str, Any], message: str, *, secret_values: Iterable[str] = ()) -> None:
    """Store each ``path -> value`` as is (``None`` deletes the path; ``''`` and ``[]`` are stored as such)."""
    php = (
        f"foreach ({_json_php(dict(leaves))} as $p => $v) {{\n"
        "    if ($v === NULL) { config_del_path($p); } else { config_set_path($p, $v); }\n"
        "}"
    )
    php_write(vm, php, message, secret_values=secret_values)


def read_leaves(vm: SmokeVM, paths: Iterable[str]) -> dict[str, Any]:
    """The stored value of each path (``None`` when absent), read in a fresh process: the persisted shape."""
    return dict(
        php_json(
            vm,
            f"$o = array();\nforeach ({_json_php(list(paths))} as $p) {{ $o[$p] = config_get_path($p, NULL); }}\n"
            + emit("$o"),
        )
    )


def read_sections(vm: SmokeVM, names: Iterable[str]) -> dict[str, Any]:
    """The stored ``installedpackages/<name>`` subtrees (``None`` when absent)."""
    php = (
        "$o = array();\n"
        f"foreach ({_json_php(list(names))} as $n) {{ $o[$n] = config_get_path('{PKGS}/' . $n, NULL); }}\n" + emit("$o")
    )
    return dict(php_json(vm, php))


def write_sections(vm: SmokeVM, sections: Mapping[str, Any], message: str) -> None:
    """Replace whole ``installedpackages/<name>`` subtrees (``None`` deletes the section)."""
    php = (
        f"foreach ({_json_php(dict(sections))} as $n => $t) {{\n"
        f"    if ($t === NULL) {{ config_del_path('{PKGS}/' . $n); }} else {{ config_set_path('{PKGS}/' . $n, $t); }}\n"
        "}"
    )
    php_write(vm, php, message)


def node_time(vm: SmokeVM) -> int:
    """The node's own clock: a record's ``time`` is the writer's, so compare it with the writer's clock only."""
    result = vm.ssh("date", "+%s")
    assert result.returncode == 0, f"date failed on the guest: rc={result.returncode} stderr={result.stderr!r}"
    return int(result.stdout.strip())


# --------------------------------------------------------------------------- #
# Records
# --------------------------------------------------------------------------- #


def read_json_file(vm: SmokeVM, path: str) -> dict[str, Any] | None:
    """The JSON object in ``path`` on the guest, ``None`` while the file does not exist."""
    result = vm.ssh(f"if [ -f {path} ]; then cat {path}; else echo __ABSENT__; fi")
    assert result.returncode == 0, f"reading {path} failed: rc={result.returncode} stderr={result.stderr!r}"
    if result.stdout.strip() == "__ABSENT__":
        return None
    data: dict[str, Any] = json.loads(result.stdout)
    return data


def receive_state(vm: SmokeVM) -> dict[str, Any]:
    """The receiver's whole record: ``accepted_digest``, ``last`` and ``apply``; ``{}`` before any receive."""
    return read_json_file(vm, RECEIVE_FILE) or {}


def send_state(vm: SmokeVM) -> dict[str, Any]:
    """The sender's last pass: ``{"time", "attempts": [{target, time, outcome, digest?, error?}]}``; ``{}`` before one."""
    return read_json_file(vm, SEND_FILE) or {}


def clear_sync_state(vm: SmokeVM) -> None:
    """Remove every package sync state file and fail loudly if one is still there."""
    result = vm.ssh("rm", "-f", *STATE_FILES)
    assert result.returncode == 0, f"could not clear the sync state files: rc={result.returncode} {result.stderr!r}"
    left = vm.ssh("ls " + " ".join(STATE_FILES) + " 2>/dev/null")
    assert left.stdout.strip() == "", f"sync state files survived their removal: {left.stdout!r}"


def apply_banners(vm: SmokeVM) -> int:
    """How many update passes this node's log shows (``UPDATE PROCESS START``)."""
    return h.count_log_marker(vm, h.PFB_LOG, APPLY_BANNER)


def show(label: str, value: Any, *, secrets: Iterable[str] = ()) -> None:
    """Print the record an assertion is about to read; ``secrets`` are redacted (raw log text may carry any value)."""
    print(f"[HA3455] {label}: {_redact(json.dumps(value, sort_keys=True, default=str), secrets)}", flush=True)


def in_flight(vm: SmokeVM) -> list[str]:
    """The signals still set: ``pending`` (``pfb_pending_changes()``), ``tick`` (a tick process alive), ``sync`` (core's HA sync run)."""
    # The marker persists after an apply (#3481), so only the package's own check says whether it is pending.
    signals = ["pending"] if php_json(vm, emit("pfb_pending_changes()")) else []
    # Bracketed `[.]` keeps pgrep -f from matching this probe's own shell command line.
    result = vm.ssh(
        "if /bin/pgrep -f 'pfblockerng[.]php tick' >/dev/null 2>&1; then echo tick; fi; "
        "if /bin/pgrep -f 'rc[.]filter_synchronize' >/dev/null 2>&1; then echo sync; fi"
    )
    assert result.returncode == 0, f"in-flight probe failed: rc={result.returncode} stderr={result.stderr!r}"
    return signals + result.stdout.split()


def settle(vm: SmokeVM, *, timeout: float = SETTLE_TIMEOUT) -> None:
    """Block until nothing is pending and no tick process is left (a record-backed bounded poll)."""
    seen = ["<never probed>"]

    def over() -> bool:
        seen[:] = in_flight(vm)
        return not seen

    try:
        h.wait_until(over, timeout=timeout, interval=3.0)
    except RuntimeError as exc:
        raise RuntimeError(f"{exc}; still in flight: {seen}") from exc


def filter_reloads(vm: SmokeVM) -> list[str]:
    """Filter-reload processes still alive (the apply's own reload is detached and fills the pf tables when it ends)."""
    result = vm.ssh("/bin/pgrep -fl 'rc[.]filter_configure' || true")
    return [line for line in result.stdout.splitlines() if line.strip()]


def wait_filter_idle(vm: SmokeVM, *, timeout: float = FILTER_RELOAD_TIMEOUT) -> None:
    """Block until the detached firewall reload has ended; its process is the completion signal."""
    seen: list[str] = []

    def idle() -> bool:
        seen[:] = filter_reloads(vm)
        return not seen

    try:
        h.wait_until(idle, timeout=timeout, interval=2.0)
    except RuntimeError as exc:
        raise RuntimeError(f"{exc}; still running: {seen}") from exc


def wait_apply(vm: SmokeVM, *, since: int, timeout: float = SETTLE_TIMEOUT) -> dict[str, Any]:
    """Block until the receive-triggered apply record (opened at/after ``since``, this node's clock) leaves ``waiting``."""
    seen: dict[str, Any] = {}

    def done() -> bool:
        seen.clear()
        seen.update(receive_state(vm))
        apply = seen.get("apply") or {}
        return apply.get("opened", 0) >= since and apply.get("outcome") in ("applied", "failed")

    try:
        h.wait_until(done, timeout=timeout, interval=3.0)
    except RuntimeError as exc:
        raise RuntimeError(f"{exc}; last receive record: {seen}") from exc
    return seen


# --------------------------------------------------------------------------- #
# Sender configuration and trigger
# --------------------------------------------------------------------------- #


def hasync_section(password: str) -> dict[str, str]:
    """Node A's core HA sync: target B, the HA user and the sections ticked, as ``ha_pair.configure_primary_hasync`` stores them."""
    return {
        "synchronizetoip": SECONDARY_SYNC_IP,
        "username": HA_USER,
        "password": password,
        "synchronizerules": "on",
        "synchronizenat": "on",
        "synchronizealiases": "on",
    }


def configure_sender(
    pair: HaPair, transport: Transport, *, scope: str = "policy", timeout: int = 150, core_sync: bool | None = None
) -> None:
    """Store the sender's sync section on A as the Sync page does, in the automatic or the manual mode.

    ``core_sync`` says whether core's own HA sync (rules, NAT, aliases) stays set on A; the default is on for the
    automatic transport, which rides it, and off for the manual one. With it on, core runs ``rc.filter_synchronize``
    by itself after any apply pass on A, and that stale request lands on B at a moment no test controls.
    """
    section = sender_section(transport, scope=scope, password=pair.sync_password, timeout=timeout)
    core = transport == "automatic" if core_sync is None else core_sync
    leaves = {SYNC: section, "hasync": hasync_section(pair.sync_password) if core else None}
    set_leaves(pair.primary, leaves, "pfBlockerNG smoke: HA sender", secret_values=[pair.sync_password])


def core_ha_on(pair: HaPair) -> None:
    """Point A's pfSense HA sync (rules, NAT, aliases) at B; a file-only save, so core queues no run of its own.

    A plain ``write_config()`` makes core raise "filter sync", and ``rc.filter_synchronize`` then starts a second
    sender one second later next to the test's explicit one: B's ``last`` record is whichever of the two arrives last.
    """
    set_leaves(
        pair.primary,
        {"hasync": hasync_section(pair.sync_password)},
        "pfBlockerNG smoke: HA A core HA sync",
        secret_values=[pair.sync_password],
    )


# check_reload_status logs "Syncing firewall" when it queues a run and starts it one second later; an event raised
# within eight seconds of a run is logged again and starts five seconds after that. Two more seconds cover php's start.
CORE_SYNC_QUIET = 7
# Prints ``none``, or the last "Syncing firewall" line's syslog stamp (no year) and then the guest's clock.
_SYNC_LINE_PROBE = (
    "last=$(grep -h 'check_reload_status.*Syncing firewall' /var/log/system.log.0 /var/log/system.log 2>/dev/null "
    '| tail -n 1 | cut -c1-15); if [ -z "$last" ]; then echo none; else echo "$last"; date "+%Y %b %e %T"; fi'
)


def sync_line_age(probe: str) -> int | None:
    """Seconds since the last sync line, from :data:`_SYNC_LINE_PROBE`'s output (``None`` when the log has none).

    A syslog stamp has no year: it belongs to the clock's year, or to the one before when that would put it in the
    future (a December line read in January). Both stamps are the guest's local time, so their difference is exact
    except across a DST change, which only makes a quiet wait one hour too short or too long.
    """
    lines = probe.strip().splitlines()
    if lines == ["none"]:
        return None
    stamp, clock = lines
    now = datetime.strptime(clock, "%Y %b %d %H:%M:%S")
    for year in (now.year, now.year - 1):
        try:
            seen = datetime.strptime(f"{year} {stamp}", "%Y %b %d %H:%M:%S")
        except ValueError:  # Feb 29 of a year that has none
            continue
        if seen <= now:
            return int((now - seen).total_seconds())
    raise ValueError(
        f"the syslog stamp {stamp!r} is no past date in {now.year} or {now.year - 1} (guest clock {clock!r})"
    )


def core_sync_quiet(vm: SmokeVM, *, timeout: float = 60.0) -> None:
    """Block until no ``rc.filter_synchronize`` run that core queued on ``vm`` can still start.

    ``rc.filter_synchronize`` reads the HA sync target when it starts, so a run queued by a package write while the
    target was off must have started before the target goes back on, or it sends next to the test's explicit send.
    """
    seen: list[int | None] = []

    def quiet() -> bool:
        result = vm.ssh(_SYNC_LINE_PROBE)
        assert result.returncode == 0, f"the sync-line age probe failed: rc={result.returncode} {result.stderr!r}"
        seen[:] = [sync_line_age(result.stdout)]
        return seen[0] is None or seen[0] >= CORE_SYNC_QUIET

    try:
        h.wait_until(quiet, timeout=timeout, interval=1.0)
    except RuntimeError as exc:
        raise RuntimeError(f"{exc}; age of the last core sync line: {seen}") from exc


def trigger_send(pair: HaPair, transport: Transport, *, manual_pass: str = "update") -> None:
    """Make A send once, the way the platform does: core's filter synchronize, or a package apply pass."""
    if transport == "automatic":
        result = pair.primary.ssh("/etc/rc.filter_synchronize", timeout=300.0)
        assert result.returncode == 0, f"rc.filter_synchronize failed: rc={result.returncode} {result.stderr!r}"
    else:
        h.reload(pair.primary, manual_pass, wait_unbound=False)


# --------------------------------------------------------------------------- #
# Snapshots
# --------------------------------------------------------------------------- #

_STATE_PHP = (
    "$names = array();\n"
    f"foreach (config_get_path('{PKGS}', array()) as $name => $tree) {{\n"
    "    if (strpos((string) $name, 'pfblockerng') === 0) { $names[$name] = pfb_sync_persisted_shape($tree); }\n"
    "}\n"
    "$synced = array();\n"
    "foreach (pfblockerng_sync_sections(TRUE) as $s) { if (isset($names[$s])) { $synced[$s] = $names[$s]; } }\n"
    "$projection = pfb_sync_policy_projection($synced);\n"
    "$leaves = array();\n"
    "$walk = static function (string $path, mixed $value) use (&$walk, &$leaves): void {\n"
    "    if (is_array($value) && $value !== array()) {\n"
    "        foreach ($value as $k => $child) { $walk($path . '/' . $k, $child); }\n"
    "    } else {\n"
    "        $leaves[$path] = $value;\n"
    "    }\n"
    "};\n"
    f"foreach ($names as $name => $tree) {{ $walk('{PKGS}/' . $name, $tree); }}\n"
    "$core = array();\n"
    "foreach (array('interfaces', 'virtualip', 'gateways', 'system/webgui') as $c) { $core[$c] = hash('sha256', serialize(config_get_path($c, array()))); }\n"
    + emit(
        "array("
        "'digest' => pfb_sync_policy_digest($projection), "
        "'current_digest' => pfb_sync_policy_current_digest(), "
        "'projection' => $projection, "
        "'leaves' => $leaves, "
        f"'installedpackages_sha256' => hash('sha256', serialize(config_get_path('{PKGS}'))), "
        "'core' => $core)"
    )
)


@dataclass(frozen=True)
class NodeState:
    """One node's stored pfBlockerNG policy and everything that must not move with it."""

    digest: str
    projection: dict[str, Any]
    leaves: dict[str, Any]
    installedpackages_sha256: str
    core: dict[str, str]
    local: dict[str, Any] = field(init=False)

    def __post_init__(self) -> None:
        # Every stored pfBlockerNG leaf the package's own projection does not list is local (or unknown): it never syncs.
        object.__setattr__(self, "local", {p: v for p, v in self.leaves.items() if p not in self.projection})


def node_state(vm: SmokeVM) -> NodeState:
    """Read the node's policy projection and digest through the landed functions, in a fresh process."""
    raw = php_json(vm, _STATE_PHP)
    assert raw["digest"] == raw["current_digest"], (
        f"pfb_sync_policy_digest(projection) {raw['digest']} != pfb_sync_policy_current_digest() {raw['current_digest']}"
    )
    return NodeState(raw["digest"], raw["projection"], raw["leaves"], raw["installedpackages_sha256"], raw["core"])


def grep_leaks(vm: SmokeVM, needles: Iterable[str], paths: Iterable[str]) -> list[str]:
    """The files under ``paths`` on the guest that contain any needle (fixed strings, fed on stdin: never in a command line)."""
    result = subprocess.run(
        vm.ssh_argv("grep", "-rFl", "-f", "/dev/stdin", "--", *paths),
        input="\n".join(needles) + "\n",
        capture_output=True,
        text=True,
        timeout=120.0,
        check=False,
    )
    assert result.returncode in (0, 1), f"grep over {list(paths)} failed: rc={result.returncode} {result.stderr!r}"
    return result.stdout.split()


# --------------------------------------------------------------------------- #
# One send
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Sync:
    """What one send left behind: A's send record, B's receive record and the update passes B ran for it."""

    t0_b: int
    send: dict[str, Any]
    receive: dict[str, Any]
    passes: int


def sync_once(pair: HaPair, transport: Transport, *, manual_pass: str = "update", wait: bool = True) -> Sync:
    """Trigger one send from A, then read B's receive record (written before the call returned).

    With ``wait``, block until B is idle (no pending change, no tick, no core sync run) before the update passes are
    counted, whatever the receive outcome: the tick spawn is delayed, so a pass opened by an unchanged or refused
    receive could otherwise be missed. A ``changed`` receive first waits for the apply to leave ``waiting``. The
    receive is never polled for: both transports are synchronous. Without ``wait`` B is not settled, because a
    deferred apply keeps its pending mark.
    """
    a, b = pair.primary, pair.secondary
    t0_b = node_time(b)
    banners = apply_banners(b)
    trigger_send(pair, transport, manual_pass=manual_pass)
    send = send_state(a)
    receive = receive_state(b)
    last = receive.get("last") or {}
    assert last.get("time", 0) >= t0_b, (
        f"B's receive record is stale: {last!r} predates the send at B's {t0_b}; A sent {send!r}"
    )
    if wait:
        if last.get("outcome") == "changed":
            receive = wait_apply(b, since=t0_b)
        settle(b)
    return Sync(t0_b, send, receive, apply_banners(b) - banners)


def assert_sent(sync: Sync, transport: Transport, digest: str) -> None:
    """A's record holds one attempt of the right kind, carrying the digest of the policy it sent."""
    attempts = sync.send.get("attempts")
    expected = ("pfSense HA sync", "handed") if transport == "automatic" else (f"{SECONDARY_SYNC_IP}:443", "sent")
    assert isinstance(attempts, list) and len(attempts) == 1, (
        f"A's send record: expected one attempt, got {sync.send!r}"
    )
    (attempt,) = attempts
    assert (attempt.get("target"), attempt.get("outcome")) == expected, (
        f"A's send attempt: expected (target, outcome) {expected!r}, got {attempt!r}"
    )
    assert attempt.get("digest") == digest, f"A's send digest: expected {digest!r}, got {attempt.get('digest')!r}"


def assert_receive(sync: Sync, outcome: str, digest: str | None = None) -> dict[str, Any]:
    """B's ``last`` record has ``outcome``, equal incoming and accepted digests and nothing ignored (an honest A)."""
    last = sync.receive.get("last") or {}
    assert last.get("outcome") == outcome, f"B's receive record: expected outcome {outcome!r}, got {last!r}"
    assert last.get("incoming_digest") == last.get("accepted_digest"), (
        f"B's incoming digest != accepted digest, so A carried a leaf B ignored: {last!r}"
    )
    assert last.get("ignored") == [] and last.get("ignored_count") == 0, f"B ignored paths from an honest A: {last!r}"
    if digest is not None:
        assert last.get("accepted_digest") == digest, f"B's accepted digest: expected A's {digest!r}, got {last!r}"
    return last


def assert_applied_once(sync: Sync) -> None:
    """B's apply record says ``applied`` and exactly one update pass ran for the receive."""
    apply = sync.receive.get("apply") or {}
    assert apply.get("outcome") == "applied", f"B's apply record: expected applied, got {apply!r}"
    assert sync.passes == 1, f"B ran {sync.passes} update passes for one changed receive; apply record {apply!r}"


# --------------------------------------------------------------------------- #
# Baseline
# --------------------------------------------------------------------------- #

BASELINE_COPY = "/root/pfb-smoke-ha-policy-baseline.xml"
BASELINE_FEED_ADDR = {
    "pfbha_k1": "198.51.100.21",
    "pfbha_k2": "198.51.100.22",
    "pfbha_d1": "198.51.100.23",
}
BASELINE_FEED_ADDR6 = {"pfbha_s1": "2001:db8:ffff::21", "pfbha_s2": "2001:db8:ffff::22"}
BLACKLIST_XML = ("bl_alpha", "bl_beta", "bl_gamma")
B_VIP_UNIQID = "pfbhaB3455"


# Policy scalars both nodes start with (inert while their feature is off): the tests delete or blank them on A.
BASELINE_POLICY_LEAVES = {
    f"{DNSBL}/whitelist": "cGZiaGEtYmFzZS13aGl0ZS5jb20K",  # base64 "pfbha-base-white.com\n"
    f"{DNSBL}/top1m_inclusion": "pfbha-incl",
    f"{DNSBL}/pfb_regex_list": "cGZiaGEtcmVnZXgK",  # base64 "pfbha-regex\n"
}


def feed_path(alias: str) -> str:
    return f"{h.PFB_DBDIR}/{alias}.txt"


def write_feed(vm: SmokeVM, alias: str, address: str) -> str:
    """A local feed file with one address, written on THIS node (each node reads its own copy of the same path)."""
    return h.write_local_feed(vm, f"{alias}.txt", f"{address}{'/128' if ':' in address else '/32'}\n")


@dataclass
class Baseline:
    """The module baseline both nodes return to before every test."""

    gateway: str
    digests: dict[str, str]
    marker: str


def gateway_name(vm: SmokeVM) -> str:
    """A real gateway of this node, so a row-local gateway leaf can differ from ``default`` without breaking a rule."""
    names = php_json(vm, emit("array_column(config_get_path('gateways/gateway_item', array()), 'name')"))
    assert names, "node has no gateway to seed a row-local gateway leaf with"
    return str(names[0])


def add_deny_group(
    pair: HaPair,
    baseline: Baseline,
    alias: str,
    address: str,
    *,
    on: SmokeVM | None = None,
    tag: str = "A",
    group: Mapping[str, Any] | None = None,
    rows: Iterable[Mapping[str, str]] = (),
) -> int:
    """Append one IPv4 deny group to ``on``'s policy (node A by default), whose feed file exists on BOTH nodes.

    Each node reads its own copy of the same feed path. The group carries node ``tag``'s row-local values unless a
    ready-made ``group`` is given; ``rows`` are extra feed rows of it. Returns the new group's row index.
    """
    node = pair.primary if on is None else on
    for vm in (pair.primary, pair.secondary):
        write_feed(vm, alias, address)
    tree = read_sections(node, ["pfblockernglistsv4"])["pfblockernglistsv4"]
    assert isinstance(tree, dict) and tree.get("config"), f"the node has no IPv4 groups to add {alias} to: {tree!r}"
    base = group or ip_group(alias, feed_path(alias), local=group_local_values(tag, baseline.gateway))
    tree["config"] = [*tree["config"], {**base, "row": [*base["row"], *rows]}]
    write_sections(node, {"pfblockernglistsv4": tree}, f"pfBlockerNG smoke: HA group {alias}")
    return len(tree["config"]) - 1


def seed_node(vm: SmokeVM, tag: str, gateway: str) -> None:
    """Write the common policy baseline and this node's own local values onto ``vm``."""
    local = group_local_values(tag, gateway)
    v4 = [
        ip_group(alias, feed_path(alias), action="Deny_Inbound" if alias != "pfbha_k2" else "Deny_Both", local=local)
        for alias in BASELINE_FEED_ADDR
    ]
    v6 = [ip_group(alias, feed_path(alias), action="Deny_Inbound", local=local) for alias in BASELINE_FEED_ADDR6]
    items = [
        blacklist_item(xml, username=sentinel(tag, f"{xml}_user"), password=sentinel(tag, f"{xml}_pass"))
        for xml in BLACKLIST_XML
    ]
    write_sections(
        vm,
        {
            "pfblockernglistsv4": {"config": v4},
            "pfblockernglistsv6": {"config": v6},
            "pfblockerngblacklist": {"item": items},
        },
        "pfBlockerNG smoke: HA policy baseline",
    )
    leaves = node_local_leaves(tag, vip_uniqid=B_VIP_UNIQID)
    leaves.update(BASELINE_POLICY_LEAVES)
    leaves.update(dict.fromkeys(GATEWAY_LEAVES, gateway if tag == "A" else "default"))
    set_leaves(vm, leaves, "pfBlockerNG smoke: HA node local values", secret_values=credential_values(tag))


def assert_dnsbl_vip(vm: SmokeVM, node: str, uniqid: str) -> None:
    """The node owns its DNSBL VIP object, references it and has DNSBL on: a stale write must not have undone them."""
    state = php_json(
        vm,
        emit(
            "array('uniqids' => array_column(config_get_path('virtualip/vip', array()), 'uniqid'), "
            f"'ref' => config_get_path('{DNSBL}/pfb_dnsvip4'), 'dnsbl' => config_get_path('{DNSBL}/pfb_dnsbl'))"
        ),
    )
    assert uniqid in state["uniqids"], (
        f"{node}: DNSBL VIP uniqid {uniqid!r} is not among its virtual IPs {state['uniqids']}"
    )
    assert state["ref"] == f"_vip{uniqid}", f"{node}: pfb_dnsvip4: expected {f'_vip{uniqid}'!r}, got {state['ref']!r}"
    assert state["dnsbl"] == "on", f"{node}: pfb_dnsbl: expected 'on', got {state['dnsbl']!r}"


def arrange_baseline(pair: HaPair) -> Baseline:
    """Bring both nodes to one baseline: package on, DNSBL on, equal policy, different local values, one apply each.

    Core's HA sync is taken off A for the whole arrangement and stays off in the snapshot: with it on, every apply pass
    on A makes core run ``rc.filter_synchronize`` by itself, and its stale ``restore_config_section`` lands on B in the
    middle of B's own reload (unbound left stopped, B's DNSBL VIP overwritten). ``configure_sender`` turns it on again
    for the tests that ride it.
    """
    a, b = pair.primary, pair.secondary
    for path, reason in UNSEEDED_LOCAL_KEYS.items():
        print(f"HA sync:local key left unseeded: {path}: {reason}", flush=True)
    set_leaves(a, {"hasync": None}, "pfBlockerNG smoke: HA sync off for the baseline")
    settle(a)  # a run core already started with the old setting must end before B is touched
    gateway = gateway_name(a)
    for tag, vm in (("A", a), ("B", b)):
        h.inject_ip_lists(vm, [])
        h.ensure_dnsbl_vip(vm)
        for alias, addr in {**BASELINE_FEED_ADDR, **BASELINE_FEED_ADDR6}.items():
            write_feed(vm, alias, addr)
        seed_node(vm, tag, gateway)
    # B keeps its own VIP object: same address, another uniqid (#3441). seed_node set only the reference.
    php_write(
        b,
        "$vips = config_get_path('virtualip/vip', array());\n"
        f"foreach ($vips as $i => $v) {{ if (($v['uniqid'] ?? '') === {h._php_str(h.SMOKE_VIP_UNIQID)}) {{ $vips[$i]['uniqid'] = {h._php_str(B_VIP_UNIQID)}; }} }}\n"
        "config_set_path('virtualip/vip', $vips);",
        "pfBlockerNG smoke: HA node B VIP uniqid",
    )
    for vm in (a, b):
        h.set_dnsbl_enabled(vm, True)
        h.reload(vm, "update")
        settle(vm)
        wait_filter_idle(vm)
    assert_dnsbl_vip(a, "primary", h.SMOKE_VIP_UNIQID)
    assert_dnsbl_vip(b, "secondary", B_VIP_UNIQID)
    marker = str(php_json(b, emit("pfb_pending_changes_marker()")))
    digests: dict[str, str] = {}
    for name, vm in (("primary", a), ("secondary", b)):
        copied = vm.ssh(f"cp -p {CONFIG} {BASELINE_COPY}")
        assert copied.returncode == 0, f"{name}: baseline snapshot failed: {copied.stderr!r}"
        digests[name] = h.pfb_config_digest(vm)
    return Baseline(gateway, digests, marker)


def _reset_node(name: str, vm: SmokeVM, uniqid: str, baseline: Baseline) -> None:
    # The mark first: a failed apply keeps it set, and settle() would wait for that for ever.
    marked = vm.ssh(f"rm -f {baseline.marker}")
    assert marked.returncode == 0, f"{name}: could not clear the pending mark: {marked.stderr!r}"
    settle(vm)
    restored = vm.ssh(f"cp -p {BASELINE_COPY} {CONFIG} && rm -f /tmp/config.cache")
    assert restored.returncode == 0, f"{name}: baseline restore failed: rc={restored.returncode} {restored.stderr!r}"
    clear_sync_state(vm)
    h.apply_filter_sync(vm)
    clear_sshguard(vm)
    digest = h.pfb_config_digest(vm)
    expected = baseline.digests[name]
    assert digest == expected, f"{name}: baseline restore did not take: config digest {digest} != baseline {expected}"
    assert in_flight(vm) == [], f"{name}: an apply is still in flight after the baseline restore"
    assert_dnsbl_vip(vm, name, uniqid)


def reset_pair(pair: HaPair, baseline: Baseline) -> None:
    """Put both nodes back at the module baseline (B first, as ha_pair does) and fail loudly when it does not take.

    Each node is tried even when the other fails, and the failures are raised together, as ``ha_pair.restore_node``
    does: a node that did not come back must not leave the other one at its test state.
    """
    failures: list[str] = []
    for name, vm, uniqid in (
        ("secondary", pair.secondary, B_VIP_UNIQID),
        ("primary", pair.primary, h.SMOKE_VIP_UNIQID),
    ):
        try:
            _reset_node(name, vm, uniqid, baseline)
        except Exception as exc:
            text = str(exc)
            failures.append(text if text.startswith(f"{name}:") else f"{name}: {text}")
    if failures:
        raise AssertionError("baseline reset failed: " + "; ".join(failures))


def token() -> str:
    """A short per-test token for unique alias names (aliasname is at most 24 word characters)."""
    return secrets.token_hex(3)


# --------------------------------------------------------------------------- #
# Rows by identity, payloads, enforcement
# --------------------------------------------------------------------------- #

FINDINGS_FILE = f"{h.PFB_DBDIR}/pfb_sync_findings.json"


def _rows(section: Mapping[str, Any] | None) -> list[Mapping[str, Any]]:
    """The group (``config``) or provider (``item``) rows of a stored section, in stored order; empty elements dropped."""
    node = section or {}
    rows = node.get("config") or node.get("item") or []
    rows = list(rows.values()) if isinstance(rows, Mapping) else list(rows)
    return [row for row in rows if isinstance(row, Mapping)]


def identities(section: Mapping[str, Any] | None) -> list[str]:
    """The ``aliasname`` of each group, or the ``xml`` of each Blacklist provider, in stored order."""
    return [str(row.get("aliasname") or row.get("xml")) for row in _rows(section)]


def local_by_identity(section: Mapping[str, Any] | None) -> dict[str, dict[str, Any]]:
    """Each row's receiver-local leaves keyed by its identity: where a row sits in the list says nothing about them."""
    keep = (*ROW_LOCAL_LEAVES, *BLACKLIST_CREDENTIAL_LEAVES)
    return {
        str(row.get("aliasname") or row.get("xml")): {k: row[k] for k in keep if k in row} for row in _rows(section)
    }


def findings(vm: SmokeVM) -> list[str]:
    """The effective-policy findings the node's last completed apply recorded (``[]`` before one)."""
    data = read_json_file(vm, FINDINGS_FILE) or {}
    return [str(item) for item in data.get("findings", [])]


def pf_table(vm: SmokeVM, alias: str, family: str = "v4") -> list[str]:
    """The members of the group's pf table; ``[]`` while the table does not exist."""
    table = f"pfB_{alias}_{family}"
    result = vm.ssh(h.PFCTL, "-t", table, "-T", "show")
    if result.returncode != 0 and "does not exist" in result.stderr:
        return []
    assert result.returncode == 0, f"pfctl -t {table} -T show: rc={result.returncode} stderr={result.stderr!r}"
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def policy_payload(vm: SmokeVM) -> dict[str, Any]:
    """The ``restore_config_section`` payload ``vm``'s package builds in ``policy`` scope: the gate leaf plus the projection."""
    php = (
        "$stored = pfb_sync_stored_sections();\n"
        "$gate = PFB_SECTIONS['sync'] . '/syncscope';\n"
        "$payload = array();\n"
        "array_set_path($payload, $gate, 'policy');\n"
        "foreach (pfb_sync_policy_projection($stored) as $path => $leaf) {\n"
        "    if ($leaf === FALSE) { continue; }\n"
        "    array_set_path($payload, $path, is_array($leaf) ? $leaf : ($leaf === TRUE ? '' : (string) $leaf));\n"
        "}\n" + emit("$payload")
    )
    payload: dict[str, Any] = php_json(vm, php)
    try:
        gate = payload["installedpackages"]["pfblockerngsync"]["config"][0]["syncscope"]
    except (KeyError, IndexError, TypeError):
        gate = None
    assert gate == "policy", (
        f"payload gate leaf: expected 'policy', got {gate!r} in {payload.get('installedpackages')!r}"
    )
    return payload


def send_payload(pair: HaPair, payload: Any, *, user: str = HA_USER, password: str | None = None) -> dict[str, Any]:
    """One real ``restore_config_section`` call from A to B (B's HA credentials unless overridden): ``{"ok": True, "resp": ...}`` or a fault.

    ``payload`` is any JSON value: the harness also sends what a sender never would (a string where the array belongs).
    """
    return xmlrpc_call(
        pair,
        user=user,
        password=pair.sync_password if password is None else password,
        method="restore_config_section",
        params_php=_json_php(payload),
    )


def inject_leaf(payload: dict[str, Any], path: str, value: str) -> None:
    """Set ``value`` at ``path`` of a decoded payload, creating maps on the way.

    A decoded PHP array is a list while its keys are 0..n-1 and a map otherwise, so an integer segment indexes a list
    and any other segment (or a segment of a map) is a key.
    """
    node: Any = payload
    *parents, leaf = path.split("/")
    for segment in parents:
        node = node[int(segment)] if isinstance(node, list) else node.setdefault(segment, {})
    node[leaf] = value


def row_key(rows: Any, field: str, identity: str) -> str:
    """The key (a list position as text, or a map key) of the row of a decoded payload whose ``field`` is ``identity``."""
    pairs = enumerate(rows) if isinstance(rows, list) else rows.items()
    for key, row in pairs:
        if isinstance(row, Mapping) and row.get(field) == identity:
            return str(key)
    raise AssertionError(f"no row with {field}={identity!r} in {rows!r}")


def credential_values(tag: str) -> list[str]:
    """Every credential value node ``tag`` was seeded with: the four scalars and each Blacklist item's username and password."""
    return [sentinel(tag, name) for name in CREDENTIAL_SCALARS] + [
        sentinel(tag, f"{xml}_{leaf}") for xml in BLACKLIST_XML for leaf in ("user", "pass")
    ]
