"""Live downgrade-preparation contract — the ``scripts/pfb-downgrade-prep.sh`` devops tool.

NOT A SMOKE TEST. Like ``test_upgrade_config_stability.py`` this validates a
*distribution* mechanic — here the ADMIN-DRIVEN downgrade-preparation step that makes
rolling the package back to a pre-4.0.x release clean — and carries the ``repo`` marker
(NOT ``smoke``), so ``pytest -m smoke`` never selects it. It reuses
``test_repo_install.py``'s hermetic ``file://`` catalog and ``repo_vm`` fixture.

THE TOOL (``scripts/pfb-downgrade-prep.sh``) is a dev/ops-only script — NOT shipped in
the package — that an operator copies to the appliance and runs as root before the
``pkg`` downgrade. It reverses the three 4.0.x changes a pre-4.0.x release cannot cope
with:

  1. Custom list pre/post transform scripts relocated into ``list_scripts/`` on upgrade —
     an older release resolves list scripts against the package ROOT only, so a moved
     script silently stops running. They are moved back to the root (shipped AWS wrappers
     are left in place, recognised by name — no pkg query).
  2. Machine-owned match artifacts relocated + renamed from the match folder into its
     ``generated/`` subdirectory on upgrade (issue #1250) — an older release resolves
     match artifacts against the match folder ROOT only, under their old names, and a
     leftover ``generated/`` subdirectory pollutes its glob. Recognised artifacts are
     moved back under their pre-4.0.x names; a stray ``*.txt.new`` write-in-progress
     file is deleted; ``generated/`` is removed once emptied.
  3. The ADR-43 scheduled-tick cron entry — ``pfblockerng.php cron-tick`` (current,
     issue #1204) or the legacy pre-#1204 ``pfblockerng.php tick`` (an un-upgraded box)
     — is removed via ``pfSsh.php`` (the shipped ``install_cron_job()``), so the
     downgraded release re-establishes its own schedule instead of leaving an orphan
     tick cron behind.

WHAT THIS PROVES on a REAL box that the off-box shellspec suite
(``tests/shell/pfb_downgrade_prep_spec.sh``) cannot: the tool runs end-to-end on the
appliance — it moves a real file inside the real package dir, LEAVES the shipped AWS
wrapper in place, and removes the real tick-family cron entry from config.xml via
``install_cron_job``.

DESELECTED from the default ``python -m pytest`` (``--ignore=tests/smoke`` in
pyproject.toml). Run only via its own dispatch::

    python -m pytest tests/smoke -m repo --override-ini="addopts="

Needs the booted ``repo_vm`` fixture and the branch ``.pkg`` (``SMOKE_PKG``); without
them it skips cleanly.
"""

from __future__ import annotations

import os
import subprocess
import uuid
from pathlib import Path

import pytest

import tests.smoke.helpers as h

from .conftest import SmokeVM
from .test_repo_install import (  # noqa: F401
    NETGATE_REPO_NAME,
    UPGRADE_REPO_DIR,
    build_guest_repo,
    pkg_delete,
    pkg_install_from_repo,
    pkg_installed_version,
    pkg_update,
    read_compact_version,
    repo_priority,
    repo_vm,
    write_repo_conf,
)

pytestmark = pytest.mark.repo

_PKGDIR = "/usr/local/pkg/pfblockerng"
_LISTDIR = f"{_PKGDIR}/list_scripts"

# The dev tool under test and where it is staged on the guest.
_TOOL_SRC = Path(__file__).resolve().parents[2] / "scripts" / "pfb-downgrade-prep.sh"
_TOOL_DEST = "/tmp/pfb-downgrade-prep.sh"

# A user's custom list pre/post script (matches {ip,dnsbl}_{pre,post}_*.{sh,py}) — the
# file the tool must move back to the package root.
_USER_SCRIPT = "ip_pre_pfbdgsmoke.sh"
# A shipped AWS region wrapper — the tool must leave it in list_scripts/ (name gate).
_SHIPPED_SCRIPT = "ip_pre_AWS_US.sh"

# Machine match artifacts (issue #1250): matchdir/matchgendir and inert RFC 5737
# TEST-NET-3 fixture content, one distinguishable line per artifact.
_MATCHDIR = "/var/db/pfblockerng/match"
_MATCHGENDIR = f"{_MATCHDIR}/generated"
_ET_CONTENT = "203.0.113.10\n"
_EXEMPT_CONTENT = "203.0.113.11\n"
_REP_CONTENT = "203.0.113.12\n"
_COLLISION_OLD_CONTENT = "203.0.113.13\n"  # already at the pre-4.0.x name in matchdir
_COLLISION_NEW_CONTENT = "203.0.113.14\n"  # the generated/ file that must be LEFT

_TICK_CMD = "/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php tick >> /var/log/pfblockerng.log 2>&1"
# issue #1204: the current shipped cron entry — the tool must remove this ONE too,
# via its own second install_cron_job('pfblockerng.php cron-tick', FALSE) needle
# (a bare 'pfblockerng.php tick' does not substring-match it — see
# pfb-downgrade-prep.sh's pfb_remove_tick_cron).
_CRON_TICK_CMD = (
    "/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php cron-tick >> /var/log/pfblockerng.log 2>&1"
)
_CRON_TICK_NEEDLE = "pfblockerng.php cron-tick"
_LEGACY_TICK_NEEDLE = "pfblockerng.php tick"

_TICK_OPEN = "<<<TICK>>>"
_TICK_CLOSE = "<<<TICKEND>>>"


def _file_exists(vm: SmokeVM, path: str) -> bool:
    """TRUE iff ``path`` is a regular file on the guest (driven via /bin/sh -c by ssh)."""
    return vm.ssh("test", "-f", path, timeout=30.0).returncode == 0


def _dir_exists(vm: SmokeVM, path: str) -> bool:
    """TRUE iff ``path`` is a directory on the guest."""
    return vm.ssh("test", "-d", path, timeout=30.0).returncode == 0


def _write_guest_file(vm: SmokeVM, path: str, contents: str, *, timeout: float = 30.0) -> None:
    """Write ``contents`` to ``path`` on the guest via ``tee`` over SSH (parent dir must exist)."""
    result = subprocess.run(
        vm.ssh_argv("tee", path), input=contents, capture_output=True, text=True, timeout=timeout, check=False
    )
    if result.returncode != 0:
        raise RuntimeError(f"_write_guest_file({path}) failed: rc={result.returncode} {result.stderr!r}")


def _read_guest_file(vm: SmokeVM, path: str) -> str:
    """Read ``path`` on the guest and return its content (raises on a missing file/rc!=0)."""
    result = vm.ssh("/bin/cat", path, timeout=30.0)
    if result.returncode != 0:
        raise RuntimeError(f"_read_guest_file({path}) failed: rc={result.returncode} {result.stderr!r}")
    return result.stdout


def _scp_to_guest(vm: SmokeVM, local: Path, remote: str) -> None:
    """Copy a host file to the guest via scp (the tool is dev-only, not in the pkg)."""
    argv = [
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
        str(local),
        f"{vm.ssh_target}:{remote}",
    ]
    result = subprocess.run(argv, capture_output=True, text=True, timeout=60.0, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"scp {local} -> {remote} failed: rc={result.returncode} {result.stderr!r}")


def _seed_tick_cron(vm: SmokeVM, cmd: str = _TICK_CMD) -> None:
    """Plant a tick-family cron item directly into config.xml (the precondition the
    tool must remove). ``cmd`` selects which entry shape — the legacy bare ``tick``
    (default) or the current #1204 ``cron-tick`` (:data:`_CRON_TICK_CMD`) — since
    the tool must remove EITHER (its own needle is an OR of both). Direct
    config_set_path append — no dependency on install_cron_job being reachable from
    the pfSsh.php context."""
    snippet = (
        "$items = config_get_path('cron/item', array());\n"
        "$items[] = array('minute' => '*/15', 'hour' => '*', 'mday' => '*', "
        "'month' => '*', 'wday' => '*', 'who' => 'root', "
        f"'command' => {h._php_str(cmd)});\n"
        "config_set_path('cron/item', $items);\n"
        "write_config('pfBlockerNG downgrade smoke: seed a tick-family cron');\n"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet, timeout=60.0)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(
            f"_seed_tick_cron({cmd!r}) failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}"
        )


def _tick_cron_present(vm: SmokeVM, needle: str = _LEGACY_TICK_NEEDLE) -> bool:
    """Scan config.xml cron items for a command containing ``needle``."""
    snippet = (
        "$present = '0';\n"
        "foreach (config_get_path('cron/item', array()) as $i) {\n"
        f"    if (strpos($i['command'] ?? '', {h._php_str(needle)}) !== false) {{ $present = '1'; break; }}\n"
        "}\n"
        f"echo {h._php_str(_TICK_OPEN)} . $present . {h._php_str(_TICK_CLOSE)};"
    )
    result = h.php_eval(vm, snippet, timeout=60.0)
    if result.returncode != 0:
        raise RuntimeError(f"_tick_cron_present({needle!r}) failed: rc={result.returncode} {result.stderr!r}")
    out = result.stdout
    start = out.find(_TICK_OPEN)
    end = out.find(_TICK_CLOSE)
    if start == -1 or end == -1:
        raise RuntimeError(f"_tick_cron_present({needle!r}): no delimited value in output: {out!r}")
    return out[start + len(_TICK_OPEN) : end] == "1"


def _remove_tick_cron(vm: SmokeVM) -> None:
    """Strip any pfBlockerNG tick-family cron item from config.xml (teardown safety net).

    Matches EITHER needle (legacy ``tick`` or the #1204 ``cron-tick``) — a body
    assertion that fires AFTER ``_seed_tick_cron`` would otherwise leave a seeded
    item on the module-scoped ``repo_vm`` — dirtying config.xml for a sibling test.
    Self-encapsulation.
    """
    snippet = (
        "$kept = array();\n"
        "foreach (config_get_path('cron/item', array()) as $i) {\n"
        "    $cmd = $i['command'] ?? '';\n"
        f"    if (strpos($cmd, {h._php_str(_LEGACY_TICK_NEEDLE)}) === false"
        f" && strpos($cmd, {h._php_str(_CRON_TICK_NEEDLE)}) === false) {{ $kept[] = $i; }}\n"
        "}\n"
        "config_set_path('cron/item', $kept);\n"
        "write_config('pfBlockerNG downgrade smoke: cleanup seeded tick-family cron(s)');\n"
        "echo 'OK';"
    )
    h.php_eval(vm, snippet, timeout=60.0)


@pytest.mark.timeout(600)  # one pkg install cycle + a few ssh probes > the 30s default cap
def test_downgrade_tool_restores_scripts_and_removes_tick_cron(repo_vm: SmokeVM) -> None:
    """DOWNGRADE-PREPARATION CONTRACT: ``pfb-downgrade-prep.sh`` restores a relocated
    custom list script to the package root and removes BOTH the legacy tick cron AND
    the current #1204 cron-tick entry, WITHOUT moving a shipped AWS wrapper.

    Scenario: an admin prepares a 4.0.x box for a downgrade to a pre-4.0.x release.
      Background: our NONE-signed file:// repo above the Netgate ``pfSense`` repo.

    Given the branch build installed, the dev tool staged on the box, a custom user
      script ``ip_pre_pfbdgsmoke.sh`` sitting in list_scripts/ (as a prior upgrade would
      have relocated it), the shipped ``ip_pre_AWS_US.sh`` also in list_scripts/, and
      BOTH a legacy ``pfblockerng.php tick`` cron item AND a current
      ``pfblockerng.php cron-tick`` cron item in config.xml (issue #1204 — a box
      upgraded from a pre-#1204 release could carry the legacy entry; a #1204+ release
      installs the cron-tick one — the tool must remove either shape it finds),

    When ``pfb-downgrade-prep.sh`` is run on the box as root,

    Then the custom script is back at the package ROOT and gone from list_scripts/, the
      shipped AWS wrapper is left untouched in list_scripts/, and BOTH cron entries are
      removed from config.xml.
    """
    pkg = os.environ.get("SMOKE_PKG")
    assert pkg and Path(pkg).is_file(), "SMOKE_PKG not set / not a file — repo_vm already gated this"
    assert _TOOL_SRC.is_file(), f"dev tool not found at {_TOOL_SRC}"

    pfsense_prio = repo_priority(repo_vm, NETGATE_REPO_NAME)

    root_user = f"{_PKGDIR}/{_USER_SCRIPT}"
    list_user = f"{_LISTDIR}/{_USER_SCRIPT}"
    list_shipped = f"{_LISTDIR}/{_SHIPPED_SCRIPT}"
    root_shipped = f"{_PKGDIR}/{_SHIPPED_SCRIPT}"

    try:
        # ------------------------------------------------------------------ #
        # GIVEN: branch build installed; tool staged; preconditions planted   #
        # ------------------------------------------------------------------ #
        pkg_delete(repo_vm)
        build_guest_repo(repo_vm, UPGRADE_REPO_DIR, [Path(pkg)])
        write_repo_conf(repo_vm, UPGRADE_REPO_DIR, ours_priority=pfsense_prio + 100)
        pkg_update(repo_vm)
        pkg_install_from_repo(repo_vm)
        installed = pkg_installed_version(repo_vm)
        expected = read_compact_version(Path(pkg))
        assert installed == expected, f"expected branch build {expected!r} installed, got {installed!r}"

        # The shipped AWS wrapper must be present after install.
        assert _file_exists(repo_vm, list_shipped), (
            f"shipped {_SHIPPED_SCRIPT} not found in list_scripts/ after install — "
            "the fixture assumption (a shipped AWS wrapper exists) is broken"
        )

        # Stage the dev tool on the guest.
        _scp_to_guest(repo_vm, _TOOL_SRC, _TOOL_DEST)

        # Plant the user's custom script in list_scripts/ (as a prior upgrade would have).
        repo_vm.ssh("/usr/bin/touch", list_user, timeout=30.0)
        repo_vm.ssh("/bin/chmod", "0755", list_user, timeout=30.0)

        # Seed BOTH tick-family cron shapes (issue #1204: the legacy tick verb AND
        # the current cron-tick verb) so the tool is proven to remove either.
        _seed_tick_cron(repo_vm, _TICK_CMD)
        _seed_tick_cron(repo_vm, _CRON_TICK_CMD)

        # BEFORE: user script only in list_scripts/, not at the root; both tick-family
        # cron entries present.
        assert _file_exists(repo_vm, list_user), f"precondition: {_USER_SCRIPT} must be in list_scripts/"
        assert not _file_exists(repo_vm, root_user), f"precondition: {_USER_SCRIPT} must NOT be at the package root yet"
        assert _tick_cron_present(repo_vm, _LEGACY_TICK_NEEDLE), (
            "precondition: the legacy tick cron must be present before the tool runs"
        )
        assert _tick_cron_present(repo_vm, _CRON_TICK_NEEDLE), (
            "precondition: the cron-tick cron must be present before the tool runs"
        )

        # ------------------------------------------------------------------ #
        # WHEN: the admin runs the downgrade-preparation tool as root         #
        # ------------------------------------------------------------------ #
        proc = repo_vm.ssh("/bin/sh", _TOOL_DEST, timeout=120.0)
        assert proc.returncode == 0, (
            f"pfb-downgrade-prep.sh failed: rc={proc.returncode} stdout={proc.stdout[-2000:]!r} stderr={proc.stderr!r}"
        )
        # The tool reports what it did.
        assert "restored to package root: 1" in proc.stdout, (
            f"tool did not report restoring the custom script: {proc.stdout!r}"
        )
        assert "tick cron entry: removed" in proc.stdout, f"tool did not report removing the tick cron: {proc.stdout!r}"

        # ------------------------------------------------------------------ #
        # THEN: script back at the root; shipped untouched; tick cron gone    #
        # ------------------------------------------------------------------ #
        assert _file_exists(repo_vm, root_user), (
            f"AFTER: {_USER_SCRIPT} must be restored to the package root ({root_user})"
        )
        assert not _file_exists(repo_vm, list_user), (
            f"AFTER: {_USER_SCRIPT} must be gone from list_scripts/ ({list_user})"
        )
        # Shipped AWS wrapper: never moved to the root, still in list_scripts/.
        assert _file_exists(repo_vm, list_shipped), (
            f"AFTER: shipped {_SHIPPED_SCRIPT} must remain in list_scripts/ (name gate, never moved)"
        )
        assert not _file_exists(repo_vm, root_shipped), (
            f"AFTER: shipped {_SHIPPED_SCRIPT} must NOT be moved to the package root"
        )
        # Both tick-family cron entries removed.
        assert not _tick_cron_present(repo_vm, _LEGACY_TICK_NEEDLE), (
            "AFTER: the legacy tick cron must be removed from config.xml"
        )
        assert not _tick_cron_present(repo_vm, _CRON_TICK_NEEDLE), (
            "AFTER: the cron-tick cron must be removed from config.xml"
        )

    finally:
        # Remove the user script from both possible locations and the staged tool, strip
        # any leftover seeded tick cron (best-effort — a body assert may have fired before
        # the tool removed it), then delete the package + guest repo dir. Self-encapsulation:
        # leave no state for a sibling. The tick-cron cleanup must not mask a real failure.
        repo_vm.ssh("/bin/rm", "-f", root_user, list_user, _TOOL_DEST, timeout=30.0)
        try:
            _remove_tick_cron(repo_vm)
        except Exception as exc:  # noqa: BLE001 -- cleanup must not mask the real test outcome
            print(f"[smoke] _remove_tick_cron failed (non-fatal): {exc}")
        pkg_delete(repo_vm)
        repo_vm.ssh("/bin/rm", "-rf", UPGRADE_REPO_DIR, timeout=60.0)


@pytest.mark.timeout(600)  # one pkg install cycle + a few ssh probes > the 30s default cap
def test_downgrade_tool_reverses_matchgen_relocation(repo_vm: SmokeVM) -> None:
    """DOWNGRADE-PREPARATION CONTRACT (issue #1250): ``pfb-downgrade-prep.sh`` reverses the
    matchdir->matchgendir relocation — recognised machine artifacts move back to their
    pre-4.0.x names in the match folder ROOT, a stray write-in-progress file is deleted,
    and a genuine name collision is left in place (never silently overwritten).

    Scenario: an admin prepares a 4.0.x box for a downgrade to a pre-4.0.x release.
      Background: our NONE-signed file:// repo above the Netgate ``pfSense`` repo.

    Given the branch build installed and, staged directly in
      matchdir/generated/ (as a prior upgrade migration would have left them): the ET
      match artifact, the consolidated exempt artifact, a per-alias reputation
      artifact (a fresh uuid-suffixed alias name), a stray ``*.txt.new``
      write-in-progress file, AND a genuine name collision — a file already sitting at
      the OLD name in matchdir plus a same-mapping file in generated/,

    When ``pfb-downgrade-prep.sh`` is run on the box as root,

    Then the ET/exempt/reputation artifacts are back at their pre-4.0.x names in
      matchdir with byte-identical content and gone from generated/, the stray
      ``*.txt.new`` is deleted, the collision is left untouched on BOTH sides with a
      stderr report naming both paths, and generated/ still exists (not emptied — the
      collision file remains inside).
    """
    pkg = os.environ.get("SMOKE_PKG")
    assert pkg and Path(pkg).is_file(), "SMOKE_PKG not set / not a file — repo_vm already gated this"
    assert _TOOL_SRC.is_file(), f"dev tool not found at {_TOOL_SRC}"

    pfsense_prio = repo_priority(repo_vm, NETGATE_REPO_NAME)

    rep_alias = f"uuidalias{uuid.uuid4().hex[:8]}"
    gen_et, old_et = f"{_MATCHGENDIR}/pfB_Match_ET_v4.txt", f"{_MATCHDIR}/ETMatch.txt"
    gen_exempt, old_exempt = f"{_MATCHGENDIR}/pfB_Match_Exempt_v4.txt", f"{_MATCHDIR}/matchdedup_v4.txt"
    gen_rep, old_rep = f"{_MATCHGENDIR}/pfB_Match_Rep_{rep_alias}_v4.txt", f"{_MATCHDIR}/match{rep_alias}_v4.txt"
    stray = f"{_MATCHGENDIR}/foo.txt.new"
    gen_collision, old_collision = f"{_MATCHGENDIR}/pfB_Match_Rep_Spam_v4.txt", f"{_MATCHDIR}/matchSpam_v4.txt"

    try:
        # ------------------------------------------------------------------ #
        # GIVEN: branch build installed; tool staged; matchgen fixtures seeded #
        # ------------------------------------------------------------------ #
        pkg_delete(repo_vm)
        build_guest_repo(repo_vm, UPGRADE_REPO_DIR, [Path(pkg)])
        write_repo_conf(repo_vm, UPGRADE_REPO_DIR, ours_priority=pfsense_prio + 100)
        pkg_update(repo_vm)
        pkg_install_from_repo(repo_vm)
        installed = pkg_installed_version(repo_vm)
        expected = read_compact_version(Path(pkg))
        assert installed == expected, f"expected branch build {expected!r} installed, got {installed!r}"

        _scp_to_guest(repo_vm, _TOOL_SRC, _TOOL_DEST)

        repo_vm.ssh("/bin/mkdir", "-p", _MATCHGENDIR, timeout=30.0)
        _write_guest_file(repo_vm, gen_et, _ET_CONTENT)
        _write_guest_file(repo_vm, gen_exempt, _EXEMPT_CONTENT)
        _write_guest_file(repo_vm, gen_rep, _REP_CONTENT)
        _write_guest_file(repo_vm, stray, "stray write-in-progress\n")
        _write_guest_file(repo_vm, old_collision, _COLLISION_OLD_CONTENT)
        _write_guest_file(repo_vm, gen_collision, _COLLISION_NEW_CONTENT)

        # BEFORE: every fixture at its GENERATED location; none at its pre-4.0.x name
        # (except the deliberate collision, which already occupies the old name).
        for gen_path in (gen_et, gen_exempt, gen_rep, stray, gen_collision):
            assert _file_exists(repo_vm, gen_path), f"precondition: {gen_path} must be staged in generated/"
        assert not _file_exists(repo_vm, old_et), f"precondition: {old_et} must NOT exist yet"
        assert not _file_exists(repo_vm, old_exempt), f"precondition: {old_exempt} must NOT exist yet"
        assert not _file_exists(repo_vm, old_rep), f"precondition: {old_rep} must NOT exist yet"

        # ------------------------------------------------------------------ #
        # WHEN: the admin runs the downgrade-preparation tool as root         #
        # ------------------------------------------------------------------ #
        proc = repo_vm.ssh("/bin/sh", _TOOL_DEST, timeout=120.0)
        assert proc.returncode == 0, (
            f"pfb-downgrade-prep.sh failed: rc={proc.returncode} stdout={proc.stdout[-2000:]!r} stderr={proc.stderr!r}"
        )
        assert "Machine match artifacts restored to the match folder: 3" in proc.stdout, (
            f"tool did not report restoring exactly 3 matchgen artifacts: {proc.stdout!r}"
        )

        # ------------------------------------------------------------------ #
        # THEN: recognised artifacts restored; stray gone; collision left     #
        # ------------------------------------------------------------------ #
        et_content = _read_guest_file(repo_vm, old_et)
        assert et_content == _ET_CONTENT, f"AFTER {old_et}: expected {_ET_CONTENT!r}, got {et_content!r}"
        assert not _file_exists(repo_vm, gen_et), f"AFTER: {gen_et} must be gone from generated/"

        exempt_content = _read_guest_file(repo_vm, old_exempt)
        assert exempt_content == _EXEMPT_CONTENT, (
            f"AFTER {old_exempt}: expected {_EXEMPT_CONTENT!r}, got {exempt_content!r}"
        )
        assert not _file_exists(repo_vm, gen_exempt), f"AFTER: {gen_exempt} must be gone from generated/"

        rep_content = _read_guest_file(repo_vm, old_rep)
        assert rep_content == _REP_CONTENT, f"AFTER {old_rep}: expected {_REP_CONTENT!r}, got {rep_content!r}"
        assert not _file_exists(repo_vm, gen_rep), f"AFTER: {gen_rep} must be gone from generated/"

        assert not _file_exists(repo_vm, stray), f"AFTER: stray {stray} must be deleted"

        # Collision: neither side moved; the pre-existing matchdir file keeps its OWN
        # content, and the generated/ collider is left for the operator to resolve.
        collision_content = _read_guest_file(repo_vm, old_collision)
        assert collision_content == _COLLISION_OLD_CONTENT, (
            f"AFTER {old_collision}: no-clobber must leave the pre-existing content — "
            f"expected {_COLLISION_OLD_CONTENT!r}, got {collision_content!r}"
        )
        assert _file_exists(repo_vm, gen_collision), f"AFTER: collider {gen_collision} must remain in generated/"
        assert "not overwriting" in proc.stderr, f"tool did not report the no-clobber skip: {proc.stderr!r}"
        assert old_collision in proc.stderr, f"no-clobber report must name the matchdir path: {proc.stderr!r}"
        assert "pfB_Match_Rep_Spam_v4.txt" in proc.stderr, (
            f"no-clobber report must name the generated/ file: {proc.stderr!r}"
        )

        # generated/ is NOT emptied (the collision file is still inside) -> left in place.
        assert _dir_exists(repo_vm, _MATCHGENDIR), (
            "AFTER: generated/ must still exist — the collision file blocks its removal"
        )

    finally:
        # Self-encapsulation: leave no state for a sibling. The tick-cron/list-script
        # reversals are exercised by the sibling test above; this leg only seeds/cleans
        # matchdir/generated/.
        repo_vm.ssh("/bin/rm", "-rf", _MATCHDIR, timeout=30.0)
        repo_vm.ssh("/bin/rm", "-f", _TOOL_DEST, timeout=30.0)
        pkg_delete(repo_vm)
        repo_vm.ssh("/bin/rm", "-rf", UPGRADE_REPO_DIR, timeout=60.0)
