"""Issue #3710 — Netgate 3.2's pfBlockerNG settings survive 3.2 -> 4.x -> 3.3.13 on a real pfSense VM.

Netgate's 3.2 package leaves the owned ``installedpackages/pfblockerng*`` sections in ``config.xml`` with NO
``settings_family`` marker and no ``/var/db/pfblockerng/settings-*.xml`` snapshot. Before #3710 the 4.x installer read
that missing marker as a 3.2 family and refused with ``install the 3.3 bridge before a 4.x family``. Now a missing
marker is the 3.3 family, the install proceeds, and the installer saves the unmarked settings into the 3.3 slot, so
going back to the shipped 3.3.13 package restores them.

Two scenarios, each arranged from scratch (neither reads state the other left):

  Scenario: the 4.x package installs over unmarked 3.2 settings
    Given pfBlockerNG settings with no settings_family marker and no settings snapshot, and no package installed
    When the branch .pkg is installed
    Then the install succeeds
     And the marker records the branch's 4.x family
     And settings-3.3.xml is a regular 0600 root-owned file whose payload holds the legacy settings

  Scenario: the shipped 3.3.13 package restores the 3.3 settings over 4.x
    Given the branch .pkg installed over unmarked 3.2 settings, and a sentinel edited afterwards (as 4.x edits would)
    When the package is removed (Keep Settings on) and the shipped v3.3.13 .pkg is installed in its place
    Then config.xml holds the ORIGINAL sentinel again
     And the marker reads 3.3

STAGING. The branch's pre-deinstall hook saves the CURRENT family's snapshot on any removal or replace, before it
looks at the operation, so it can never be the install path under test. The legacy state is therefore staged AFTER
the package is removed: ``pkg delete`` with Keep Settings on (the config survives), then the marker and every
snapshot are stripped and the sentinel is seeded, and only then is the branch .pkg installed.

DOWNGRADE SHAPE. Published channel builds all carry the canonical package name (``pfSense-pkg-pfBlockerNG``), so a
real 4.x -> 3.3.13 move is a same-name ``pkg install -f`` of the older build (install.sh step 9c). The smoke build is
named for its channel (``-edge`` here), so a ``pkg add -f`` of the shipped file does not replace it: pkg ignores the
file conflict "by forced mode" and registers BOTH packages (seen on a live VM). ``pkg delete`` of the branch build
followed by ``pkg add`` of the shipped file is the closest shape the harness can reach. The snapshot save the restore
relies on runs in the pre-deinstall hook before the operation is looked at, so it is the same in both shapes; a delete
also runs the full teardown, which a same-name ``-f`` install skips.

SENTINEL. An unknown key in an owned section is carried verbatim by the snapshot save and restore (a whole-tree
write that bypasses the field adapters), so a unique value in ``pfblockerngdnsblsettings`` is a precise tracer.
Whether the branch's install migrations keep an unknown key in the LIVE section is not specified, so the first
scenario asserts on the snapshot payload only; live ``config.xml`` is asserted only where the 3.3.13 installer
restores it.

Every VM change is undone: the module's baseline config, snapshot files and the branch build are put back after each
scenario, so later modules see the VM they always saw.
"""

from __future__ import annotations

import base64
import os
import re
import shlex
import subprocess
import uuid
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from pathlib import Path

import pytest

from . import helpers as h
from .conftest import SmokeVM

pytestmark = pytest.mark.smoke

SENTINEL_KEY = "smoke_3710_sentinel"
SENTINEL_PATH = f"{h.CFG_DNSBL_SETTINGS}/{SENTINEL_KEY}"
MARKER_PATH = f"{h.CFG_GLOBAL}/settings_family"
KEEP_PATH = f"{h.CFG_GLOBAL}/pfb_keep"
BASELINE_COPY = "/root/pfb-smoke-3710-baseline.xml"
SLOT_STASH = "/root/pfb-smoke-3710-slots"
# pkg(8) can exit 0 after a package script failed (install-pkg.sh's matcher).
_SCRIPT_FAILED = re.compile(r"pkg: .* script failed")
_VALUE_OPEN, _VALUE_CLOSE = "<<<VALUE>>>", "<<<ENDVALUE>>>"


# --------------------------------------------------------------------------- #
# Reading the box
# --------------------------------------------------------------------------- #


def _expect(what: str, expected: object, actual: object) -> None:
    assert actual == expected, f"{what}\n  expected: {expected!r}\n  actual:   {actual!r}"


def _sh(vm: SmokeVM, command: str, *, what: str, timeout: float = 60.0) -> str:
    """Run one POSIX-sh command line on the guest; fail with its whole output unless it exits 0."""
    result = vm.ssh(command, timeout=timeout)
    assert result.returncode == 0, f"{what}: rc={result.returncode}\n{result.stdout}{result.stderr}"
    return result.stdout


def _php_value(vm: SmokeVM, statements: str, expression: str, *, what: str) -> str:
    """Run ``statements`` then evaluate ``expression`` in the guest's pfSense PHP shell; its string value.

    pfSsh.php prints a startup banner, so the value is delimited.
    """
    snippet = f"{statements}\necho {h._php_str(_VALUE_OPEN)} . ({expression}) . {h._php_str(_VALUE_CLOSE)};"
    result = h.php_eval(vm, snippet)
    out = result.stdout
    start, end = out.find(_VALUE_OPEN), out.find(_VALUE_CLOSE)
    assert result.returncode == 0 and start != -1 and end != -1, (
        f"{what} unreadable: rc={result.returncode} stdout={out[-500:]!r} stderr={result.stderr[-500:]!r}"
    )
    return out[start + len(_VALUE_OPEN) : end]


def _owned_sections(vm: SmokeVM) -> list[str]:
    """The ``installedpackages/pfblockerng*`` section names in the live config (the sections a snapshot owns)."""
    names = _php_value(
        vm,
        "$names = array();\n"
        "foreach (array_keys(config_get_path('installedpackages', array())) as $k) {\n"
        "  if (strpos((string) $k, 'pfblockerng') === 0) { $names[] = $k; }\n"
        "}",
        "implode(',', $names)",
        what="the owned config sections",
    )
    return [name for name in names.split(",") if name]


def _slots(vm: SmokeVM) -> list[str]:
    """The settings snapshot files in the package's db dir, sorted."""
    out = _sh(
        vm,
        f'for f in {h.PFB_DBDIR}/settings-*.xml; do [ -e "$f" ] && echo "$f"; done; true',
        what="list settings snapshots",
    )
    return sorted(out.split())


def _copy_snapshots(src: str, dest: str) -> str:
    """Shell copying every settings snapshot in ``src`` into ``dest``, attributes kept; succeeds when none exist."""
    return f'for f in {src}/settings-*.xml; do [ -e "$f" ] && cp -p "$f" {dest}/; done; true'


def _installed(vm: SmokeVM) -> str:
    """``<name>-<version>`` of the installed pfBlockerNG package; ``''`` when none is installed."""
    return vm.ssh("pkg query -x '%n-%v' pfBlockerNG").stdout.strip()


def _announce(vm: SmokeVM, phase: str) -> None:
    """Name what the box runs at ``phase``: the log then says which build every assertion saw."""
    print(f"PFB_SETTINGS_FAMILY phase={phase!r} pkg={_installed(vm) or '<none>'}", flush=True)


def _marker(vm: SmokeVM) -> tuple[bool, str]:
    return h.config_get_state(vm, MARKER_PATH)


def _installed_nightly_family(vm: SmokeVM) -> str:
    """``PFB_NIGHTLY_SETTINGS_FAMILY`` as the installed package defines it: what a stamped nightly build records."""
    return _php_value(
        vm,
        "require_once('/usr/local/pkg/pfblockerng/pfblockerng_extra.inc');",
        "PFB_NIGHTLY_SETTINGS_FAMILY",
        what="the nightly settings family constant",
    )


def _branch_family(vm: SmokeVM, pkg: Path) -> str:
    """The family the branch build records: its version's major.minor, or the installed package's nightly family.

    A timestamp-stamped version (``YYYYMMDDHHMMSS.<sha7>``) maps to the ceiling constant the package itself defines, so
    the constant is read from the box rather than copied here. It is read for every build, so a package that cannot
    report it fails here, not only on a nightly channel.
    """
    nightly = _installed_nightly_family(vm)
    version = pkg.name.removesuffix(".pkg").rsplit("-", 1)[1]
    if re.fullmatch(r"\d{14}\.[0-9a-f]{7}", version):
        return nightly
    match = re.match(r"\d+\.\d+", version)
    assert match, f"cannot read a settings family from the branch package version {version!r} ({pkg.name})"
    return match.group(0)


class Slot:
    """One settings snapshot as it sits on the box: its file attributes and the decoded payload.

    The payload holds the whole owned config, credentials included, so it is never printed: the one thing read out of
    it is the value stored under a named key.
    """

    def __init__(self, vm: SmokeVM, family: str) -> None:
        path = f"{h.PFB_DBDIR}/settings-{family}.xml"
        self.path = path
        # %HT is the file type, and stat does not follow a symlink, so a link reads "Symbolic Link".
        self.attributes = _sh(vm, f"stat -f '%Lp %u %HT' {path}", what=f"stat {path}").strip()
        root = ET.fromstring(_sh(vm, f"cat {path}", what=f"read {path}"))
        self.family = (root.findtext("family") or "").strip()
        self._payload = base64.b64decode((root.findtext("payload") or "").strip(), validate=True)

    def value_of(self, key: str) -> str | None:
        """The string serialized under ``key`` (``s:<len>:"key";s:<len>:"value";``), ``None`` when the key is absent."""
        head = re.search(rb's:%d:"%s";s:(\d+):"' % (len(key), re.escape(key.encode())), self._payload)
        if head is None:
            return None
        return self._payload[head.end() : head.end() + int(head.group(1))].decode("utf-8", errors="replace")


# --------------------------------------------------------------------------- #
# Changing the box
# --------------------------------------------------------------------------- #


def _pkg_add(vm: SmokeVM, pkg: Path, *, force: bool, what: str) -> None:
    """Install ``pkg`` with ``pkg add`` (``-f`` when ``force``: reinstall over a registered build of the same name).

    Never ``-f`` over a differently named package: the shipped stable package and the branch's ``-edge`` one install the
    same files, and ``pkg add -f`` then registers BOTH and overwrites files ("conflicts with ... ignored by forced
    mode") instead of replacing the old one. The cron-disable flag is re-asserted before and after, as
    ``helpers.deploy`` does; the ABI override matches ``install-pkg.sh``. The installer's own output is printed, so
    the log carries the settings-family messages of a passing install too.
    """
    h._write_cron_disable_flag(vm)
    remote = f"/tmp/pfb-3710-{pkg.name}"
    with pkg.open("rb") as fh:
        sent = subprocess.run(
            vm.ssh_argv(f"cat > {shlex.quote(remote)}"), stdin=fh, capture_output=True, timeout=300.0, check=False
        )
    assert sent.returncode == 0, f"{what}: copying {pkg.name} failed: rc={sent.returncode} {sent.stderr[-300:]!r}"
    abi = os.environ.get("SMOKE_ABI", "")
    add = f"pkg -o ABI={shlex.quote(abi)} add" if abi else "pkg add"
    command = f"{add} {'-f ' if force else ''}{shlex.quote(remote)}"
    added = vm.ssh(f"env ASSUME_ALWAYS_YES=yes {command}", timeout=600.0)
    output = added.stdout + added.stderr
    print(f"PFB_SETTINGS_FAMILY {command}: rc={added.returncode}\n{output[-3000:]}", flush=True)
    vm.ssh("rm", "-f", remote)
    assert added.returncode == 0 and not _SCRIPT_FAILED.search(output), (
        f"{what}: {command} failed: rc={added.returncode}\n{output[-1500:]}"
    )
    h.wait_unbound_ready(vm)
    h._write_cron_disable_flag(vm)


def _pkg_delete(vm: SmokeVM, pkg_id: str) -> None:
    """Remove ``pkg_id`` (``<name>-<version>``); Keep Settings (``pfb_keep`` on) leaves the config sections in place."""
    h._write_cron_disable_flag(vm)
    result = vm.ssh("env", "ASSUME_ALWAYS_YES=yes", "pkg", "delete", "-y", pkg_id, timeout=300.0)
    assert result.returncode == 0, f"pkg delete {pkg_id}: rc={result.returncode}\n{result.stdout}{result.stderr}"
    h._write_cron_disable_flag(vm)


def _stage_unmarked_legacy_settings(vm: SmokeVM) -> str:
    """Leave the box as Netgate's 3.2 does: owned settings, no marker, no snapshot, no package. Returns the sentinel.

    The owned sections are read before and after ``pkg delete``, and must be the same non-empty list: the snapshot
    save does nothing without owned sections, so settings that did not survive the delete would make the install
    under test the fresh-install path instead of the upgrade one. The sentinel is written after that comparison
    (writing it creates its section when absent, which would make any later check vacuous). Every other part of the
    arrangement is read back too, so a scenario that starts from the wrong state fails here, not as a puzzling
    result later.
    """
    sentinel = f"legacy-3710-{uuid.uuid4().hex}"
    h.config_set(vm, KEEP_PATH, "on")
    owned_before = _owned_sections(vm)
    assert owned_before, "no pfblockerng* section in the config before pkg delete: there are no settings to keep"
    _pkg_delete(vm, _branch_pkg().name.removesuffix(".pkg"))
    _expect("owned pfblockerng* sections after pkg delete (Keep Settings on)", owned_before, _owned_sections(vm))
    h.config_restore_state(vm, MARKER_PATH, (False, ""))
    _sh(vm, f"rm -f {h.PFB_DBDIR}/settings-*.xml", what="remove the settings snapshots")
    h.config_set(vm, SENTINEL_PATH, sentinel)

    _expect("package installed before the install under test", "", _installed(vm))
    _expect("settings_family marker (present, value)", (False, ""), _marker(vm))
    _expect("settings snapshots in /var/db/pfblockerng", [], _slots(vm))
    _expect("sentinel in the live config (present, value)", (True, sentinel), h.config_get_state(vm, SENTINEL_PATH))
    return sentinel


# --------------------------------------------------------------------------- #
# The VM, put back after every scenario
# --------------------------------------------------------------------------- #


def _branch_pkg() -> Path:
    return Path(os.environ["SMOKE_PKG"])


def _put_back(vm: SmokeVM, slots_before: list[str]) -> None:
    """Branch build, baseline config and the original snapshot files back on the box; fails loudly if any did not take.

    The install goes first: it runs the package's own hooks, and the baseline config copied over it afterwards is
    what later modules read. Every step is tried, and the failures are raised together.
    """
    branch = _branch_pkg()
    failures: list[str] = []

    def reinstall_branch() -> None:
        wanted = branch.name.removesuffix(".pkg")
        others = [pkg_id for pkg_id in _installed(vm).splitlines() if pkg_id != wanted]
        if others or _installed(vm) != wanted:
            for pkg_id in others:
                _pkg_delete(vm, pkg_id)
            _pkg_add(vm, branch, force=True, what="restore the branch build")

    def restore_config() -> None:
        h.restore_pfb_config_baseline(vm, snapshot_path=BASELINE_COPY)

    def restore_snapshots() -> None:
        _sh(
            vm,
            f"rm -f {h.PFB_DBDIR}/settings-*.xml; {_copy_snapshots(SLOT_STASH, h.PFB_DBDIR)}",
            what="restore the settings snapshots",
        )

    for step in (reinstall_branch, restore_config, restore_snapshots):
        try:
            step()
        except Exception as exc:  # noqa: BLE001 -- every step is tried; the failures are raised together
            failures.append(f"{step.__name__}: {exc}")
    assert not failures, "could not put the VM back on the branch build and baseline config: " + "; ".join(failures)
    _expect("package installed after the put-back", branch.name.removesuffix(".pkg"), _installed(vm))
    _expect("sentinel left in the config after the put-back", (False, ""), h.config_get_state(vm, SENTINEL_PATH))
    _expect("settings snapshots after the put-back", slots_before, _slots(vm))


@pytest.fixture
def lifecycle_vm(legacy_pkg: Path, smoke_vm: SmokeVM) -> Iterator[SmokeVM]:
    """The VM on the branch build with its baseline config and snapshot files saved, and put back afterwards.

    ``legacy_pkg`` comes first: it skips before a VM boots when no .pkg was built at all, and fails when the shipped
    package was not fetched.
    """
    del legacy_pkg
    h.deploy(smoke_vm)
    _sh(smoke_vm, f"cp -p /conf/config.xml {BASELINE_COPY}", what="save the baseline config")
    _sh(
        smoke_vm,
        f"rm -rf {SLOT_STASH} && mkdir -p {SLOT_STASH} && {_copy_snapshots(h.PFB_DBDIR, SLOT_STASH)}",
        what="stash the settings snapshots",
    )
    slots_before = _slots(smoke_vm)
    try:
        yield smoke_vm
    finally:
        _put_back(smoke_vm, slots_before)


# --------------------------------------------------------------------------- #
# Scenarios
# --------------------------------------------------------------------------- #


@pytest.mark.timeout(900)  # pkg delete + install + a fixture put-back that may reinstall
def test_unmarked_legacy_settings_install_as_the_4x_family_with_a_3_3_snapshot(lifecycle_vm: SmokeVM) -> None:
    """The 4.x package installs over Netgate 3.2's unmarked settings, recording 4.x and a 3.3 snapshot of them."""
    vm, branch = lifecycle_vm, _branch_pkg()
    sentinel = _stage_unmarked_legacy_settings(vm)

    _pkg_add(vm, branch, force=False, what="install the branch package over unmarked legacy settings")
    _announce(vm, "branch installed over unmarked legacy settings")

    _expect("installed package", branch.name.removesuffix(".pkg"), _installed(vm))
    _expect("settings_family marker (present, value)", (True, _branch_family(vm, branch)), _marker(vm))
    slot = Slot(vm, "3.3")
    _expect(f"{slot.path} mode, owner and type", "600 0 Regular File", slot.attributes)
    _expect(f"{slot.path} family element", "3.3", slot.family)
    _expect(f"{SENTINEL_KEY} in the {slot.path} payload", sentinel, slot.value_of(SENTINEL_KEY))


@pytest.mark.timeout(1200)  # pkg delete + two installs + a fixture put-back that reinstalls the branch
def test_shipped_3_3_13_restores_the_3_3_settings_and_marker_after_the_4x_package(
    lifecycle_vm: SmokeVM, legacy_pkg: Path
) -> None:
    """Going back to the shipped v3.3.13 package brings back the settings saved before 4.x, marker 3.3."""
    vm, branch = lifecycle_vm, _branch_pkg()
    sentinel = _stage_unmarked_legacy_settings(vm)
    _pkg_add(vm, branch, force=False, what="install the branch package over unmarked legacy settings")
    edited = f"edited-on-4x-3710-{uuid.uuid4().hex}"
    h.config_set(vm, SENTINEL_PATH, edited)  # what an edit made while 4.x ran looks like
    _expect("settings_family marker before the downgrade", (True, _branch_family(vm, branch)), _marker(vm))
    _expect("sentinel before the downgrade (present, value)", (True, edited), h.config_get_state(vm, SENTINEL_PATH))

    _pkg_delete(vm, branch.name.removesuffix(".pkg"))
    _expect("package installed between the 4.x removal and the shipped install", "", _installed(vm))
    _pkg_add(vm, legacy_pkg, force=False, what="install the shipped v3.3.13 package after the branch build")
    _announce(vm, "shipped 3.3.13 installed after the branch build")

    shipped = re.match(r"pfSense-pkg-pfBlockerNG-\d+\.\d+\.\d+", legacy_pkg.name)
    assert shipped, f"not a shipped pfBlockerNG package file name: {legacy_pkg.name}"
    _expect("installed package", shipped.group(0), _installed(vm))
    _expect("sentinel after the downgrade (present, value)", (True, sentinel), h.config_get_state(vm, SENTINEL_PATH))
    _expect("settings_family marker after the downgrade (present, value)", (True, "3.3"), _marker(vm))
