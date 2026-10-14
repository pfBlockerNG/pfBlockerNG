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
from typing import Any, Literal

from . import helpers as h
from .conftest import SmokeVM
from .ha_pair import HA_USER, SECONDARY_SYNC_IP, HaPair, _redact, clear_sshguard

Transport = Literal["automatic", "manual"]
TRANSPORTS: tuple[Transport, ...] = ("automatic", "manual")

CONFIG = "/conf/config.xml"
PKGS = "installedpackages"
GEN = f"{PKGS}/pfblockerng/config/0"
IP = f"{PKGS}/pfblockerngipsettings/config/0"
DNSBL = f"{PKGS}/pfblockerngdnsblsettings/config/0"
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


def node_local_leaves(tag: str, *, vip_uniqid: str) -> dict[str, str]:
    """Settings-section local leaves that differ between the nodes, ``tag`` = ``A`` or ``B``.

    The four scalar credentials carry per-node sentinels; the rest are inert display/alert/interface/hook leaves the
    apply pass either does not read or reads harmlessly. B's DNSBL VIP reference carries ITS OWN uniqid (#3441: the
    same address, another uniqid, must survive a receive).
    """
    leaves: dict[str, Any] = {path: sentinel(tag, name) for name, path in CREDENTIAL_SCALARS.items()}
    leaves.update(
        {
            f"{IP}/maxmind_locale": "de" if tag == "A" else "fr",
            f"{IP}/asn_reporting": "on" if tag == "A" else "",
            f"{IP}/enable_rdns": "on" if tag == "A" else "",
            f"{IP}/inbound_interface": "lan" if tag == "A" else "wan",
            f"{IP}/outbound_interface": "lan" if tag == "A" else "wan",
            f"{DNSBL}/pfb_cache": "on" if tag == "A" else "",
            f"{DNSBL}/dnsbl_allow_int": "lan" if tag == "A" else "",
            f"{DNSBL}/dnsbl_redir_int": "lan" if tag == "A" else "",
            f"{DNSBL}/dnsbl_dot_block_int": "lan" if tag == "A" else "",
            f"{GLOBAL}/alertrefresh": "on" if tag == "A" else "",
            f"{GLOBAL}/widget-pfblockerng": sentinel(tag, "widget-pfblockerng"),
            f"{GEN}/pfb_syntax_highlight": "on" if tag == "A" else "",
            # A disabled hook never runs; only its stored row matters.
            f"{GEN}/hooks/row": [
                {
                    "script": f"hook_post_{sentinel(tag, 'hook')}.sh",
                    "when": "post",
                    "enabled": "",
                    "description": sentinel(tag, "hook"),
                    "timeout": "5",
                }
            ],
        }
    )
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
    vm: SmokeVM, php: str, message: str, *, secret_values: Iterable[str] = (), timeout: float = 120.0
) -> None:
    """Run ``php`` after the package prelude, then ``write_config`` it; the snippet must not echo anything."""
    result = h.php_eval(vm, _PRELUDE + php + f"\nwrite_config({h._php_str(message)});\necho 'OK';", timeout=timeout)
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


def in_flight(vm: SmokeVM) -> list[str]:
    """The apply's signals still set: ``pending`` (``pfb_pending_changes()``) and ``tick`` (a tick process alive)."""
    # The marker persists after an apply (#3481), so only the package's own check says whether it is pending.
    signals = ["pending"] if php_json(vm, emit("pfb_pending_changes()")) else []
    # Bracketed `[.]` keeps pgrep -f from matching this probe's own shell command line.
    result = vm.ssh("if /bin/pgrep -f 'pfblockerng[.]php tick' >/dev/null 2>&1; then echo tick; fi")
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


def configure_sender(pair: HaPair, transport: Transport, *, scope: str = "policy", timeout: int = 150) -> None:
    """Store the sender's sync section on A as the Sync page does, in the automatic or the manual mode."""
    section = sender_section(transport, scope=scope, password=pair.sync_password, timeout=timeout)
    set_leaves(pair.primary, {SYNC: section}, "pfBlockerNG smoke: HA sender", secret_values=[pair.sync_password])


def set_receiver_scope(vm: SmokeVM, scope: str) -> None:
    """Store ``scope`` as the node's own ``syncscope`` leaf with sending left off (what a receiver's Sync page holds)."""
    set_leaves(vm, {SYNC: {"syncscope": scope, "varsynconchanges": "disabled"}}, "pfBlockerNG smoke: HA receiver scope")


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

    With ``wait`` and a ``changed`` receive, block until the receive-triggered apply left ``waiting`` and B's tick is
    gone, so the pass count is final. The receive is never polled for: both transports are synchronous.
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
    if wait and last.get("outcome") == "changed":
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
    leaves[f"{DNSBL}/agateway_in"] = gateway if tag == "A" else "default"
    leaves[f"{DNSBL}/agateway_out"] = gateway if tag == "A" else "default"
    set_leaves(vm, leaves, "pfBlockerNG smoke: HA node local values", secret_values=list(CREDENTIAL_SCALARS.values()))


def arrange_baseline(pair: HaPair) -> Baseline:
    """Bring both nodes to one baseline: package on, DNSBL on, equal policy, different local values, one apply each."""
    a, b = pair.primary, pair.secondary
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
    marker = str(php_json(b, emit("pfb_pending_changes_marker()")))
    digests: dict[str, str] = {}
    for name, vm in (("primary", a), ("secondary", b)):
        copied = vm.ssh(f"cp -p {CONFIG} {BASELINE_COPY}")
        assert copied.returncode == 0, f"{name}: baseline snapshot failed: {copied.stderr!r}"
        digests[name] = h.pfb_config_digest(vm)
    return Baseline(gateway, digests, marker)


def reset_pair(pair: HaPair, baseline: Baseline) -> None:
    """Put both nodes back at the module baseline and fail loudly when it does not take (B first, as ha_pair does)."""
    for name, vm in (("secondary", pair.secondary), ("primary", pair.primary)):
        settle(vm)
        restored = vm.ssh(f"cp -p {BASELINE_COPY} {CONFIG} && rm -f /tmp/config.cache && rm -f {baseline.marker}")
        assert restored.returncode == 0, (
            f"{name}: baseline restore failed: rc={restored.returncode} {restored.stderr!r}"
        )
        clear_sync_state(vm)
        h.apply_filter_sync(vm)
        clear_sshguard(vm)
        digest = h.pfb_config_digest(vm)
        expected = baseline.digests[name]
        assert digest == expected, (
            f"{name}: baseline restore did not take: config digest {digest} != baseline {expected}"
        )
        assert in_flight(vm) == [], f"{name}: an apply is still in flight after the baseline restore"


def token() -> str:
    """A short per-test token for unique alias names (aliasname is at most 24 word characters)."""
    return secrets.token_hex(3)
