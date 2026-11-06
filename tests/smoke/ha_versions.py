"""Helpers for the mixed-build HA smoke module (issue #3455, spec rows 6 and 9): ``test_ha_policy_versions.py``.

The previous build (``prev_pkg``) and the branch build (``SMOKE_PKG``) are the same package name and version, so a
plain ``pkg add`` is a no-op ("the most recent version ... is already installed", exit 0) and ``helpers.deploy`` never
switches a node. :func:`install_build` forces the swap with ``pkg add -f`` and proves the result from a file marker,
never from the version string.

Evidence comes from records the nodes already write, never from the package under test:

* the sender's syslog (``/var/log/system.log``): pfSense's XMLRPC client logs each call it makes, with the method name,
  under the name of the process that made it (``/usr/local/www/pfblockerng/...`` for the package);
* the receiver's syslog: core's ``xmlrpc.php`` logs every configuration write a call causes, with the section names it
  merged;
* the pfBlockerNG sections each node stores.

Syslog windows are cut with markers the node logs itself. ``syslogd`` writes in arrival order, so once the closing
marker is visible every line logged before it is too, and no sleep is needed.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import secrets
import shlex
import socket
import subprocess
from collections.abc import Collection, Iterator, Mapping, Sequence
from pathlib import Path
from types import TracebackType
from typing import Any, Self

from . import ha_policy as hp
from . import helpers as h
from .conftest import SmokeVM
from .ha_pair import HaPair

PKG_INC = "/usr/local/pkg/pfblockerng/pfblockerng.inc"
PKG_EXTRA = "/usr/local/pkg/pfblockerng/pfblockerng_extra.inc"
SYSLOG = "/var/log/system.log"
SYNC_PAGE = "/pfblockerng/pfblockerng_sync.php"
SYNC_PAGE_MARKER = "XMLRPC Sync Settings"
# Section-relative path of the Sync page's own section, as ``flatten_sections`` spells it.
SYNC_LEAVES = "pfblockerngsync/config/0"
_SCOPE_LEAF = f"{SYNC_LEAVES}/syncscope"
_TOGGLE_LEAF = f"{SYNC_LEAVES}/syncinterfaces"
SYNCSCOPE = f"{hp.SYNC}/syncscope"
SYNCINTERFACES = f"{hp.SYNC}/syncinterfaces"
# The config path of every key the installed build's ``pfb_cfg_registry()`` stores, as ``flatten_sections`` spells it.
REGISTRY_PATHS_EXPR = (
    "array_map(function ($k) { [$s, $l] = explode('/', $k, 2); "
    "return str_replace('installedpackages/', '', PFB_SECTIONS[$s]) . '/' . $l; }, array_keys(pfb_cfg_registry()))"
)
# What each legacy scope sends on the branch build beyond the previous build's payload: the "all" scope also carries
# the DNS-settings section (#3649); the "lists" scope is unchanged.
LEGACY_PAYLOAD_GROWTH: Mapping[str, frozenset[str]] = {
    "lists": frozenset(),
    "all": frozenset({"pfblockerngdnssettings"}),
}
# The package words a policy-scope send differently from a legacy one (pfblockerng.inc, pfblockerng_sync_on_changes()).
_POLICY_SEND = " policy sync to [ "

# What the package's own sender logs per target, at NOTICE or above: every CE release writes these to system.log.
_SYNC_TARGET_MARK = " sync to [ "
_PACKAGE_TAG = "[pfBlockerNG] XMLRPC "
_MERGED = re.compile(
    r"Configuration Change: [^:]+: Merged in config \((?P<keys>[^)]*?) sections\) from XMLRPC client\."
)
# install-pkg.sh's matcher: pkg(8) can exit 0 after a package script failed.
_SCRIPT_FAILED = re.compile(r"pkg: .* script failed")


# --------------------------------------------------------------------------- #
# Pure helpers (pinned off-box in tests/test_issue3455_ha_versions.py)
# --------------------------------------------------------------------------- #


def build_from_markers(extra_hits: int, inc_hits: int) -> str:
    """``branch`` when both per-field-sync markers are in the installed code, ``previous`` when neither is."""
    if extra_hits == 0 and inc_hits == 0:
        return "previous"
    if extra_hits > 0 and inc_hits > 0:
        return "branch"
    raise AssertionError(
        f"half-installed package: pfb_sync_scope_migrate x{extra_hits} in pfblockerng_extra.inc, "
        f"pfb_sync_receive_policy x{inc_hits} in pfblockerng.inc"
    )


def flatten(tree: Any, prefix: str = "") -> dict[str, Any]:
    """``path -> leaf`` of a decoded config tree; an empty container is a leaf of its own."""
    if isinstance(tree, dict) and tree:
        pairs = list(tree.items())
    elif isinstance(tree, list) and tree:
        pairs = list(enumerate(tree))
    else:
        return {prefix: tree}
    leaves: dict[str, Any] = {}
    for key, child in pairs:
        leaves.update(flatten(child, f"{prefix}/{key}"))
    return leaves


def flatten_sections(sections: Mapping[str, Any]) -> dict[str, Any]:
    """``flatten`` over every stored section, each path starting with its section name."""
    return {path: leaf for name, tree in sections.items() for path, leaf in flatten(tree, name).items()}


def legacy_auto_merge(before: Any, incoming: Any) -> Any:
    """What the previous receive hook stores for a section: ``array_merge($old, $new)``, incoming keys win.

    A section empty on both sides is skipped by the hook, so it stays exactly as stored (the config reads an empty
    element back as ``''``, not an empty array).
    """
    if not before and not incoming:
        return before
    return {**(before or {}), **(incoming or {})}


def legacy_sync_section(transport: hp.Transport, *, toggle: str, password: str) -> dict[str, Any]:
    """The sync section the previous build's Sync page stores: no ``syncscope``, the toggle instead.

    ``toggle`` is the "Disable General/IP/DNSBL tab settings sync" checkbox as the page writes it: ``on`` checked,
    ``''`` unchecked.
    """
    section = hp.sender_section(transport, scope="", password=password, timeout=150)
    del section["syncscope"]
    section["syncinterfaces"] = toggle
    return section


def migration_delta(toggle: str, scope: str) -> dict[str, dict[str, Any]]:
    """The leaves an upgrade moves on its own account: the legacy toggle becomes the scope leaf."""
    return {"changed": {}, "removed": {_TOGGLE_LEAF: toggle}, "added": {_SCOPE_LEAF: scope}}


def without_registry_moves(
    delta: Mapping[str, Mapping[str, Any]], previous: Collection[str], branch: Collection[str]
) -> dict[str, dict[str, Any]]:
    """``delta`` minus what an upgrade moves because the two builds' registries differ.

    Keys only the branch build knows arrive with their defaults and keys it retired go; each is excused only in its own
    direction (an arrival is an addition, a retirement a removal). The toggle and scope leaves are ``migration_delta``'s
    and stay; a changed value is never a registry move.

    The VALUES of arrived and retired leaves are intentionally not checked: an arrival is not always its registry
    default (``grandfather`` maps, install-time seeds and the #2308 schedule migration set it from what the node
    stored), and a retired leaf's old value is whatever the node held. Those rules are pinned where they live
    (``CfgRegistryGrandfatherGateTest``, ``InstallGrandfatherChokepointTest``).
    """
    arrived = set(branch) - set(previous) - {_SCOPE_LEAF}
    retired = set(previous) - set(branch) - {_TOGGLE_LEAF}
    return {
        "changed": dict(delta["changed"]),
        "removed": {path: leaf for path, leaf in delta["removed"].items() if path not in retired},
        "added": {path: leaf for path, leaf in delta["added"].items() if path not in arrived},
    }


def assert_legacy_payload_growth(previous: Sequence[str], branch: Sequence[str], scope: str) -> None:
    """The branch build's legacy ``scope`` payload keeps every section the previous build sent and adds only #3649's."""
    dropped, added = set(previous) - set(branch), set(branch) - set(previous)
    wanted = LEGACY_PAYLOAD_GROWTH[scope]
    assert not dropped and added == wanted, (
        f"legacy scope {scope!r}: the branch build dropped {sorted(dropped)} and added {sorted(added)}; "
        f"expected it to add exactly {sorted(wanted)}"
    )


def assert_one_send(calls: Sequence[str], *, policy: bool) -> None:
    """Exactly one target was synced to, in the policy scope's wording (``policy``) or the legacy scope's."""
    assert len(calls) == 1, f"expected one XMLRPC sync to B, got {list(calls)}"
    assert (_POLICY_SEND in calls[0]) == policy, (
        f"expected a {'policy' if policy else 'legacy'}-scope send, got {calls[0]!r}"
    )


def package_xmlrpc(window: str) -> list[str]:
    """The lines pfBlockerNG's own sender logged for each target it reported on: a send that went out, or a target it
    refused for a bad setting. A transport failure logs nothing to syslog, so it never shows here.

    CE 2.9 keeps core's ``Beginning XMLRPC sync data`` lines out of ``system.log``, so only the package's NOTICE lines
    are common to every release. The method is proven by what the receiver merged, not by the sender's wording.
    ``XMLRPC sync is starting.`` alone is no call: automatic mode logs it, then hands the send to pfSense HA sync.
    """
    return [ln for ln in window.splitlines() if _PACKAGE_TAG in ln and _SYNC_TARGET_MARK in ln]


def merged_sections(window: str) -> list[list[str]]:
    """The section names of each ``Merged in config (...)`` write a receiver logged; ``[]`` when none were merged."""
    return [[k for k in m.group("keys").split(", ") if k.strip()] for m in _MERGED.finditer(window)]


def package_writes(window: str) -> list[list[str]]:
    """The receiver's writes that came from a pfBlockerNG call: ones naming a pfB section, or naming nothing at all.

    Core's own HA sync merges named core sections (``aliases``, ``filter``, ...), so it never matches. A write that
    names nothing is ``restore_config_section`` whose package hook merged nothing.
    """
    return [keys for keys in merged_sections(window) if not keys or any(k.startswith("pfblockerng") for k in keys)]


# --------------------------------------------------------------------------- #
# Which build a node runs
# --------------------------------------------------------------------------- #


def build_of(vm: SmokeVM) -> str:
    """``branch`` or ``previous``, from the per-field-sync functions in the installed code."""
    result = vm.ssh(
        'printf "%s %s\\n" '
        f'"$(grep -c pfb_sync_scope_migrate {PKG_EXTRA})" "$(grep -c pfb_sync_receive_policy {PKG_INC})"'
    )
    parts = result.stdout.split()
    assert result.returncode == 0 and len(parts) == 2 and all(p.isdigit() for p in parts), (
        f"could not read the build markers: rc={result.returncode} stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    return build_from_markers(int(parts[0]), int(parts[1]))


def announce(vm: SmokeVM, node: str, phase: str) -> str:
    """Print which build ``vm`` runs (marker verdict, package name-version, code hash) and return the verdict."""
    result = vm.ssh(
        "printf 'pkg=%s\\n' \"$(pkg query -x '%n-%v' pfBlockerNG 2>/dev/null | tr '\\n' ' ')\"; "
        f"printf 'inc_sha256=%s\\n' \"$(sha256 -q {PKG_INC})\""
    )
    fields = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    build = build_of(vm)
    print(
        f"PFB_HA_BUILD node={node} phase={phase!r} build={build} pkg={fields.get('pkg', '?').strip()} "
        f"inc_sha256={fields.get('inc_sha256', '?')[:16]}",
        flush=True,
    )
    return build


def install_build(vm: SmokeVM, pkg: Path, expect: str, *, node: str, phase: str) -> None:
    """Make ``vm`` run ``pkg`` and prove it.

    ``pkg add -f`` replaces the installed package the way an upgrade does (the old build's pre-deinstall hook runs,
    ``pfb_keep`` keeps the config), so the node keeps its stored pfBlockerNG sections. Scheduled ticks stay off: the
    cron-disable flag is re-asserted before and after, as ``helpers.deploy`` does.
    """
    h._write_cron_disable_flag(vm)
    remote = f"/tmp/pfb-ha-versions-{pkg.name}"
    with pkg.open("rb") as fh:
        sent = subprocess.run(
            vm.ssh_argv(f"cat > {shlex.quote(remote)}"), stdin=fh, capture_output=True, timeout=300.0, check=False
        )
    assert sent.returncode == 0, f"{node}: copying {pkg.name} failed: rc={sent.returncode} {sent.stderr[-300:]!r}"
    abi = os.environ.get("SMOKE_ABI", "")
    add = f"pkg -o ABI={shlex.quote(abi)} add" if abi else "pkg add"
    added = vm.ssh(f"env ASSUME_ALWAYS_YES=yes {add} -f {shlex.quote(remote)}", timeout=600.0)
    output = added.stdout + added.stderr
    assert added.returncode == 0 and not _SCRIPT_FAILED.search(output), (
        f"{node}: pkg add -f {pkg.name} failed: rc={added.returncode}\n{output[-1500:]}"
    )
    h.wait_unbound_ready(vm)
    h._write_cron_disable_flag(vm)
    vm.ssh("rm", "-f", remote)
    actual = announce(vm, node, phase)
    assert actual == expect, f"{node} {phase}: expected the {expect} build after installing {pkg}, found {actual}"


def restore_branch(pair: HaPair) -> None:
    """Put both nodes back on the branch build (B first, as ``ha_pair`` restores); every failure is raised together."""
    pkg = Path(os.environ["SMOKE_PKG"])
    failures: list[str] = []
    for node, vm in (("B", pair.secondary), ("A", pair.primary)):
        try:
            if build_of(vm) != "branch":
                install_build(vm, pkg, "branch", node=node, phase="restore the branch build")
        except Exception as exc:  # noqa: BLE001 -- every node is tried; the failures are raised together
            failures.append(f"{node}: {exc}")
    if failures:
        raise RuntimeError("could not restore the branch build: " + "; ".join(failures))


def put_back(pair: HaPair, baseline: hp.Baseline) -> None:
    """Both nodes on the branch build at the baseline config.

    The baseline config goes back FIRST: an install runs the package's own hooks (the upgrade migration and a resync),
    and they must not act on the sync settings a test left behind, or A would send to B during the restore. A's
    baseline keeps pfSense HA sync off (``arrange_baseline``), so the config writes of A's install queue core runs that
    find no target; the drain and the evidence line prove none started before B's baseline goes back.
    """
    for node, vm in (("B", pair.secondary), ("A", pair.primary)):
        result = vm.ssh(f"cp -p {hp.BASELINE_COPY} {hp.CONFIG} && rm -f /tmp/config.cache")
        assert result.returncode == 0, f"{node}: baseline config copy failed: rc={result.returncode} {result.stderr!r}"
    with LogWindow(pair.primary) as a_log, LogWindow(pair.secondary) as b_log:
        restore_branch(pair)
        wait_sync_idle(pair.primary)
    core_syncs = [ln for ln in a_log.text.splitlines() if "rc.filter_synchronize" in ln and "Beginning XMLRPC" in ln]
    evidence(
        "put-back", a_core_syncs_during_restore=len(core_syncs), b_merged_during_restore=merged_sections(b_log.text)
    )
    hp.reset_pair(pair, baseline)


# --------------------------------------------------------------------------- #
# Syslog windows
# --------------------------------------------------------------------------- #


class LogWindow:
    """The syslog lines a node wrote while the ``with`` body ran, as ``.text`` afterwards."""

    def __init__(self, vm: SmokeVM) -> None:
        self.vm = vm
        self.token = secrets.token_hex(4)
        self.text = ""

    def _log(self) -> str:
        return self.vm.ssh(f"cat {SYSLOG}.0 {SYSLOG} 2>/dev/null").stdout

    def _mark(self, edge: str) -> str:
        tag = f"PFBHAVERSIONS-{edge}-{self.token}"
        result = self.vm.ssh("/usr/bin/logger", tag)
        assert result.returncode == 0, f"logger failed: rc={result.returncode} {result.stderr!r}"
        h.wait_until(lambda: tag in self._log(), timeout=60.0, interval=0.5)
        return tag

    def __enter__(self) -> Self:
        self._mark("BEGIN")
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> None:
        if exc_type is not None:
            return
        end = self._mark("END")
        log = self._log()
        begin = f"PFBHAVERSIONS-BEGIN-{self.token}"
        self.text = log[log.index(begin) : log.index(end)]


def wait_sync_idle(vm: SmokeVM, *, timeout: float = 120.0) -> None:
    """Block until no ``rc.filter_synchronize`` run is left on ``vm``: a write on A starts one in the background."""
    seen: list[str] = []

    def idle() -> bool:
        result = vm.ssh("/bin/pgrep -fl 'rc[.]filter_synchronize' || true")
        seen[:] = [line for line in result.stdout.splitlines() if line.strip()]
        return not seen

    try:
        h.wait_until(idle, timeout=timeout, interval=2.0)
    except RuntimeError as exc:
        raise RuntimeError(f"{exc}; still running: {seen}") from exc


# --------------------------------------------------------------------------- #
# Stored state
# --------------------------------------------------------------------------- #

_SECTIONS_PHP = (
    "$o = array();\n"
    "foreach (config_get_path('installedpackages', array()) as $n => $t) {{ "
    "if (strpos((string) $n, 'pfblockerng') === 0) {{ $o[$n] = {value}; }} }}\n"
)


def pfb_sections(vm: SmokeVM) -> dict[str, Any]:
    """Every stored ``installedpackages/pfblockerng*`` subtree, read in a fresh process."""
    return dict(hp.php_json(vm, _SECTIONS_PHP.format(value="$t") + hp.emit("$o")))


def pfb_hashes(vm: SmokeVM) -> dict[str, str]:
    """``sha256(serialize(...))`` of each stored pfBlockerNG section: equal hashes mean byte-identical storage."""
    return dict(hp.php_json(vm, _SECTIONS_PHP.format(value="hash('sha256', serialize($t))") + hp.emit("$o")))


def sync_section_names(vm: SmokeVM, *, with_settings: bool) -> list[str]:
    """The sections the node's installed build syncs, in its own order (``pfblockerng_sync_sections``)."""
    flag = "TRUE" if with_settings else "FALSE"
    return [str(name) for name in hp.php_json(vm, hp.emit(f"pfblockerng_sync_sections({flag})"))]


def legacy_section_names(vm: SmokeVM, scope: str) -> list[str]:
    """The sections the branch build's legacy ``scope`` (``all`` or ``lists``) sends (``pfb_sync_legacy_sections``)."""
    flag = "TRUE" if scope == "all" else "FALSE"
    return [str(name) for name in hp.php_json(vm, hp.emit(f"pfb_sync_legacy_sections({flag})"))]


def registry_paths(vm: SmokeVM) -> set[str]:
    """Every config path the build installed on ``vm`` keeps a registry key for."""
    return {str(path) for path in hp.php_json(vm, hp.emit(REGISTRY_PATHS_EXPR))}


def assert_sections(actual: Mapping[str, Any], expected: Mapping[str, Any], what: str) -> None:
    """Equal stored sections, or the leaf-level difference as the failure text."""
    if actual != expected:
        delta = hp.diff_leaves(flatten_sections(expected), flatten_sections(actual))
        raise AssertionError(f"{what}: expected vs actual stored leaves differ: {str(delta)[:3000]}")


@contextlib.contextmanager
def web_tunnel(vm: SmokeVM) -> Iterator[int]:
    """A local port forwarded over SSH to the guest's HTTPS web GUI.

    The HA pair's GUI is HTTPS on 443, but the lane's web host port reaches only the guest's port 80, which merely
    redirects. The tunnel is up when its local port accepts a connection; it is closed on the way out.
    """
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    argv = [
        "ssh",
        *("-i", vm.ssh_key_path, "-p", str(vm.ssh_port)),
        *("-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "BatchMode=yes"),
        *("-o", "LogLevel=ERROR", "-o", "ExitOnForwardFailure=yes", "-N"),
        *("-L", f"127.0.0.1:{port}:127.0.0.1:443", vm.ssh_target),
    ]
    tunnel = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)

    def listening() -> bool:
        assert tunnel.poll() is None, f"the SSH tunnel to the web GUI exited: rc={tunnel.returncode}"
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1.0).close()
        except OSError:
            return False
        return True

    try:
        h.wait_until(listening, timeout=30.0, interval=0.2)
        yield port
    finally:
        tunnel.terminate()
        try:
            tunnel.wait(timeout=10.0)
        except subprocess.TimeoutExpired:
            tunnel.kill()
            tunnel.wait()


def sender_panel_rows(vm: SmokeVM) -> list[list[str]]:
    """Each attempt row (Target, Time, Digest, Result) of the Sync page's sender panel, read over a real web session."""
    from .ui.credgate import admin_password_decision
    from .ui.test_sync_status_panels import panel, sender_rows
    from .ui.webui import WebUI

    action, password = admin_password_decision(os.environ)
    assert action == "ok", password
    protocol = h.config_get(vm, "system/webgui/protocol").strip().lower()
    assert protocol == "https", f"the HA pair's web GUI must be HTTPS, found {protocol!r}"
    with web_tunnel(vm) as port:
        ui = WebUI(
            host="127.0.0.1",
            port=port,
            username=os.environ.get("SMOKE_ADMIN_USER") or "admin",
            password=password,
            scheme="https",
            verify=False,
        )
        ui.login()
        response = ui.get(SYNC_PAGE)
    html = response.content.decode("utf-8", errors="replace")
    assert response.status_code == 200 and SYNC_PAGE_MARKER in html, (
        f"the Sync page did not render: HTTP {response.status_code}, marker present: {SYNC_PAGE_MARKER in html}"
    )
    sender = panel(html, "pfb-sync-sender")
    assert sender is not None, "expected the sender panel (id=pfb-sync-sender) on the Sync page, found none"
    return sender_rows(sender)


def sentinel_alias_php(name: str, address: str) -> str:
    """PHP that adds one inert host alias ``name`` on a node (a unique marker for "did the pfSense HA sync land?")."""
    q = h._php_str
    return (
        "$aliases = config_get_path('aliases/alias', array());\n"
        f"$aliases[] = array('name' => {q(name)}, 'type' => 'host', 'address' => {q(address)}, "
        "'descr' => 'pfb smoke HA versions sentinel');\n"
        "config_set_path('aliases/alias', $aliases);"
    )


def evidence(label: str, **fields: Any) -> None:
    """Print the records an assertion block just proved as one ``PFB_HA_EVIDENCE`` line, so the run log shows them."""
    body = " ".join(f"{key}={json.dumps(value, sort_keys=True, default=str)[:900]}" for key, value in fields.items())
    print(f"PFB_HA_EVIDENCE {label} {body}", flush=True)
