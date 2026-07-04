"""Config-preservation contract across both upgrade and downgrade.

NOT A SMOKE TEST. Like ``test_repo_install.py`` this validates a *distribution*
mechanic — specifically the config-preservation guarantee across package install
transitions — and carries the ``repo`` marker (NOT ``smoke``), so
``pytest -m smoke`` never selects it. It reuses ``test_repo_install.py``'s
hermetic ``file://`` catalog and ``repo_vm`` fixture machinery.

THREE CASES:

``test_pkg_upgrade_preserves_config_values`` — UPGRADE CONTRACT (issue #281)
  Config.xml user settings survive a ``pkg upgrade`` from a prior-release build
  to the branch build. Proves the pfb_keep_migrate() install-time seed fixes the
  pre-deinstall hook bug.

``test_pkg_downgrade_preserves_config_values`` — DOWNGRADE / ROLLBACK CONTRACT
  ADR-29 Phase 3: config.xml stored values are byte-identical after installing
  the HIGHER build, writing representative settings, and then downgrading back to
  the LOWER build. Also proves the lower build reads sane values — a DNSBL-blocked
  unique_domain() name still returns the VIP block shape after downgrade.

``test_pkg_install_applies_config_migrations`` — INSTALL-TIME MIGRATION CONTRACT
  (issue #795) Proves the three ``pfblockerng_install.inc`` config migrations
  (SafeSearch DoH rename, legacy Yandex DoH-list token rewrite, MaxMind key
  relocation) actually run during a REAL ``pkg install`` against a pre-seeded
  legacy config, not just at the pure-function level (``SsDohListYandexMigrateTest``
  covers the decision logic in isolation). A legacy config is written directly with
  raw ``config_get_path``/``config_set_path`` (the package is absent, so
  ``PfbConfig`` does not exist on the box yet), the unmodified branch ``.pkg`` is
  installed once, and every migrated field is asserted against its pre-migration
  value.

ROOT CAUSE (issue #281): on ``pkg upgrade``, pfSense fires the old pkg's
``custom_php_pre_deinstall_command`` -> ``pfblockerng_php_pre_deinstall_command()``.
It reads ``$pfb['keep']`` = ``$pfb['config']['pfb_keep']`` with no default. The key
only persists to config.xml when the user explicitly saves the General tab; the GUI
default is 'on' but that default never persists automatically. When the key is absent,
the ``!= 'on'`` check is TRUE -> ``pfb_remove_config_settings()`` deletes ALL ~22
pfBlockerNG config sections -> wholesale config loss on upgrade.

The fix (pfb_keep_migrate + the ?? 'on' runtime default) ensures that:

  1. The install-time seed (``pfb_keep_migrate``) writes 'on' into config.xml on
     an existing, already-populated General config section so the pre-deinstall hook
     finds the key on the NEXT upgrade.
  2. The runtime default (``?? 'on'`` in ``pfb_global()``) covers the gap between
     installation and the first General-tab save.

WHAT THE CASE PROVES (issue #281 contract):

  ``test_pkg_upgrade_preserves_config_values`` — config.xml stored values are
  byte-identical after a ``pkg upgrade`` from the prior-release build (``<V>_1``)
  to the branch build (``<V>_9``). The test asserts:

    (1) BEFORE state: representative config written and read back correctly on the
        LOWER build. pfb_keep is NOT set by the test (its absence is the bug
        condition the fix handles). After the lower build installs, the
        install-time seed migration writes pfb_keep='on' into config.xml
        automatically — the test asserts this seeded value is present.
        Representative config fields verified before upgrade:
          - ``dnsbl_lenient='on'``    (PfbLenient-adapted field)
          - ``dnsbl_vip_auto='on'``   (PfbToggle-adapted field)
          - ``pfb_dnsbl='on'``        (CONTROL field — not ADR-28-adapted here)
          - ``pfb_idn='all'``         (excluded field — kept as raw string; proves
                                       'all' is preserved, not "both empty")
          - ``pfb_keep='on'``         (seeded by install migration — the fix output)
        BEFORE runtime behaviour: a DNSBL-blocked ``unique_domain()`` name returns
        the VIP block shape on-box (proves DNSBL is live before the upgrade).

    (2) WHEN: branch build (``<V>_9``) is installed over the lower build via
        ``pkg upgrade``.

    (3) THEN every snapshotted config.xml value is byte-identical (same raw stored
        string, no loss or mutation), AND the DNSBL probe still returns the same VIP
        block shape on the same domain (runtime contract unchanged).

DESELECTED from the default ``python -m pytest``
(``--ignore=tests/smoke`` in pyproject.toml).
Run only via its own dispatch::

    python -m pytest tests/smoke -m repo --override-ini="addopts="

Both cases need the booted ``smoke_vm`` / ``repo_vm`` fixture, the branch
``.pkg`` (``SMOKE_PKG``) and the ``zstd`` runner host-tool (for the
re-versioned builds); without them they skip cleanly.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

import tests.smoke.helpers as h

# ``repo_vm`` is re-exported (not just imported): pytest resolves fixtures
# PER-MODULE, so importing the helper functions does NOT register the fixture in
# this module's namespace — the name must be present here for the cases below to
# request it. noqa keeps the (module-level "unused") fixture import; the matching
# F811 ("redefinition" by each case param) is suppressed for this file in pyproject.
from .conftest import SmokeVM
from .test_repo_install import (  # noqa: F401
    NETGATE_REPO_NAME,
    UPGRADE_REPO_DIR,
    build_guest_repo,
    pkg_delete,
    pkg_install_from_repo,
    pkg_installed_version,
    pkg_update,
    pkg_upgrade,
    read_compact_version,
    repo_priority,
    repo_vm,
    reversion_pkg,
    write_repo_conf,
)

pytestmark = pytest.mark.repo

# Config paths (mirrors helpers.py CFG_* constants — avoid importing private names)
_CFG_GLOBAL = "installedpackages/pfblockerng/config/0"
_CFG_DNSBL = "installedpackages/pfblockerngdnsblsettings/config/0"

# The fields snapshotted for the upgrade-contract assertion.
# pfb_keep is NOT included here — it is instead asserted explicitly as the
# seeded value after lower-build install (the fix output), then included in the
# before snapshot so we verify it survives the upgrade unchanged.
_SNAPSHOT_FIELDS: list[tuple[str, str]] = [
    (_CFG_DNSBL + "/dnsbl_lenient", "on"),  # PfbLenient::On
    (_CFG_DNSBL + "/dnsbl_vip_auto", "on"),  # PfbToggle::On (dnsbl-settings side)
    (_CFG_DNSBL + "/pfb_dnsbl", "on"),  # control field
    (_CFG_DNSBL + "/pfb_idn", "all"),  # excluded field — canonical stored value
    (_CFG_GLOBAL + "/pfb_keep", "on"),  # seeded by pfb_keep_migrate (the fix)
]

# Local feed fixture content used for the DNSBL probe.
_FEED_CONTENT = "uuid-9f3c1e8a2b47.com\n"
_BLOCKED_DOMAIN = "uuid-9f3c1e8a2b47.com"


def _write_representative_config(vm: SmokeVM) -> None:
    """Write representative config into config.xml on the lower build.

    Sets the minimum DNSBL enable chain and the four representative fields so
    the before-state DNS probe works. pfb_keep is intentionally NOT set here —
    its absence on a real user's box is the bug condition the fix handles.
    The install-time migration (pfb_keep_migrate) is responsible for seeding it.
    """
    snippet = (
        # Global block: master switch on (pfb_keep intentionally omitted here)
        f"$g = config_get_path({h._php_str(_CFG_GLOBAL)}, array());\n"
        "$g['enable_cb'] = 'on';\n"
        f"config_set_path({h._php_str(_CFG_GLOBAL)}, $g);\n"
        # DNSBL-settings block: the representative fields
        f"$s = config_get_path({h._php_str(_CFG_DNSBL)}, array());\n"
        "$s['pfb_dnsbl']      = 'on';\n"
        "$s['dnsbl_vip_auto'] = 'on';\n"
        "$s['dnsbl_lenient']  = 'on';\n"
        "$s['pfb_idn']        = 'all';\n"
        f"config_set_path({h._php_str(_CFG_DNSBL)}, $s);\n"
        "write_config('pfBlockerNG upgrade-config-stability smoke: set representative config');\n"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet, timeout=60.0)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(
            f"_write_representative_config failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}"
        )


def _snapshot_config(vm: SmokeVM) -> dict[str, str]:
    """Read each snapshotted field from config.xml and return {path: stored_value}."""
    return {path: h.config_get(vm, path) for path, _ in _SNAPSHOT_FIELDS}


def _assert_snapshot_identical(before: dict[str, str], after: dict[str, str]) -> None:
    """Assert every snapshotted field is byte-identical before and after upgrade.

    Raises AssertionError listing ALL drifted fields (not just the first).
    """
    drifts: list[str] = []
    for path, before_val in before.items():
        after_val = after.get(path, "<ABSENT>")
        if before_val != after_val:
            drifts.append(f"  {path!r}:  before={before_val!r}  after={after_val!r}")
    if drifts:
        raise AssertionError(
            "Upgrade config-preservation VIOLATED: config.xml stored values drifted "
            f"after pkg upgrade ({len(drifts)} field(s)):\n" + "\n".join(drifts)
        )


def _setup_dnsbl_feed(vm: SmokeVM) -> str:
    """Write the local DNSBL feed and wire it as the active DNSBL list; return the feed path."""
    feed_path = h.write_local_feed(vm, "upgrade_config_stability.txt", _FEED_CONTENT)
    spec = h.DnsblCase(
        aliasname="UpgradeConfigStability",
        feed_url=feed_path,
        mode=h.DnsblMode.VIP,
        header="upgrade-config-stability",
        hsts=False,
    )
    h.inject(vm, spec)
    return feed_path


# --------------------------------------------------------------------------- #
# The upgrade config-preservation test
# --------------------------------------------------------------------------- #


@pytest.mark.timeout(900)  # two pkg installs + two reloads + DNS probes; budget ~12 min
def test_pkg_upgrade_preserves_config_values(repo_vm: SmokeVM, tmp_path: Path) -> None:
    """UPGRADE CONFIG-PRESERVATION CONTRACT: config.xml user settings are byte-identical
    before and after ``pkg upgrade`` from the prior-release build to the branch build.

    Issue #281: the pre-deinstall hook wipes ALL pfBlockerNG config sections when
    pfb_keep is absent from config.xml. The fix seeds pfb_keep='on' via
    pfb_keep_migrate() at install time so the hook is safe on the next upgrade.
    This test proves the fix works end-to-end on the live VM.

    NOTE: pfb_keep is intentionally NOT set in _write_representative_config() — its
    absence is the exact bug condition the fix must handle. The test asserts that after
    the lower build installs, pfb_keep='on' appears in config.xml (seeded by the
    install migration), and that it and all other representative fields survive upgrade
    byte-identical.

    Scenario: issue #281 fix preserves user settings across pkg upgrade.
      Background: our NONE-signed file:// repo above the Netgate ``pfSense`` repo.

    Given the prior-release build (``<V>_1``) installed and representative config
      written (dnsbl_lenient='on', dnsbl_vip_auto='on', pfb_dnsbl='on',
      pfb_idn='all'; pfb_keep NOT set by the test), and the install migration having
      seeded pfb_keep='on' into config.xml, and a DNSBL-blocked unique_domain() name
      returning the VIP block shape on-box,

    When the branch build (``<V>_9``) is installed over the lower build via
      ``pkg upgrade``,

    Then every snapshotted config.xml value is byte-identical (same raw stored string,
      no config loss), AND the DNSBL probe still returns NOERROR + VIP on the SAME
      domain (runtime contract unchanged).
    """
    pkg = os.environ.get("SMOKE_PKG")
    assert pkg and Path(pkg).is_file(), "SMOKE_PKG not set / not a file — repo_vm already gated this"

    base_version = read_compact_version(Path(pkg))
    low_version = f"{base_version}_1"
    high_version = f"{base_version}_9"
    assert low_version != high_version, "forged builds must differ for a real version transition"

    # Forge two builds on the runner — only the version string changes.
    low_pkg = reversion_pkg(Path(pkg), low_version, tmp_path / "low")
    high_pkg = reversion_pkg(Path(pkg), high_version, tmp_path / "high")

    pfsense_prio = repo_priority(repo_vm, NETGATE_REPO_NAME)

    try:
        # ------------------------------------------------------------------ #
        # GIVEN: prior-release build installed; representative config written #
        # ------------------------------------------------------------------ #

        # Install the LOWER (prior-release) build from our file:// repo.
        pkg_delete(repo_vm)
        build_guest_repo(repo_vm, UPGRADE_REPO_DIR, [low_pkg])
        write_repo_conf(repo_vm, UPGRADE_REPO_DIR, ours_priority=pfsense_prio + 100)
        pkg_update(repo_vm)
        assert pkg_installed_version(repo_vm) is None, (
            "package unexpectedly present before upgrade-contract test install"
        )
        pkg_install_from_repo(repo_vm)
        assert pkg_installed_version(repo_vm) == low_version, (
            f"expected lower build {low_version!r} installed, got {pkg_installed_version(repo_vm)!r}"
        )

        # Write representative config fields into config.xml (pfb_keep intentionally omitted).
        _write_representative_config(repo_vm)

        # Assert the install-time migration seeded pfb_keep='on' into config.xml.
        # This proves pfb_keep_migrate() ran during install and the fix is in effect.
        # pfb_keep was NOT written by _write_representative_config; only the migration seeds it.
        seeded_keep = h.config_get(repo_vm, _CFG_GLOBAL + "/pfb_keep")
        assert seeded_keep == "on", (
            f"install-time migration did not seed pfb_keep: got {seeded_keep!r}, expected 'on'. "
            f"The issue #281 fix (pfb_keep_migrate) did not run or did not write the key."
        )

        # Snapshot the stored values (BEFORE values — the exact raw strings from config.xml).
        before_snapshot = _snapshot_config(repo_vm)

        # Verify every expected value is present in the before snapshot.
        for path, expected in _SNAPSHOT_FIELDS:
            actual = before_snapshot[path]
            assert actual == expected, f"BEFORE: config.xml {path!r} = {actual!r}, expected {expected!r}"

        # Set up the DNSBL feed and ensure_dnsbl_vip so the DNS probe can run.
        h.ensure_dnsbl_vip(repo_vm)
        _setup_dnsbl_feed(repo_vm)

        # Reload (the full DNSBL pass) to make the DNSBL live.
        h.reload(repo_vm, "updatednsbl")

        # BEFORE state DNS probe: the blocked domain must return NOERROR + VIP.
        before_answer = h.dns_probe(repo_vm, _BLOCKED_DOMAIN, "A")
        assert h.is_vip(before_answer), (
            f"BEFORE upgrade: expected VIP block for {_BLOCKED_DOMAIN!r}; "
            f"got rcode={before_answer.rcode!r} records={before_answer.records!r}. "
            f"DNSBL was not live on the lower build."
        )

        # ------------------------------------------------------------------ #
        # WHEN: branch build installed over the lower build via pkg upgrade   #
        # ------------------------------------------------------------------ #

        build_guest_repo(repo_vm, UPGRADE_REPO_DIR, [high_pkg])
        pkg_update(repo_vm)
        proc = pkg_upgrade(repo_vm)

        # Basic sanity: the upgrade actually moved the version.
        combined = proc.stdout + proc.stderr
        assert "Missing dependency" not in combined, f"RUN_DEPENDS did not resolve on pkg upgrade:\n{combined}"
        installed_after = pkg_installed_version(repo_vm)
        assert installed_after == high_version, (
            f"pkg upgrade did not move {low_version!r} -> {high_version!r}; now at {installed_after!r}"
        )

        # ------------------------------------------------------------------ #
        # THEN: config.xml values byte-identical; DNSBL behaviour unchanged  #
        # ------------------------------------------------------------------ #

        # Read config.xml AFTER upgrade and assert every field is byte-identical.
        after_snapshot = _snapshot_config(repo_vm)
        _assert_snapshot_identical(before_snapshot, after_snapshot)

        # DNS contract: re-reload so the upgraded build's DNSBL is live, then
        # probe the SAME blocked domain. Must still return NOERROR + VIP.
        h.reload(repo_vm, "updatednsbl")
        after_answer = h.dns_probe(repo_vm, _BLOCKED_DOMAIN, "A")
        assert h.is_vip(after_answer), (
            f"AFTER upgrade: expected VIP block for {_BLOCKED_DOMAIN!r}; "
            f"got rcode={after_answer.rcode!r} records={after_answer.records!r}. "
            f"Runtime contract broken by upgrade."
        )

    finally:
        pkg_delete(repo_vm)
        repo_vm.ssh("/bin/rm", "-rf", UPGRADE_REPO_DIR, timeout=60.0)


# --------------------------------------------------------------------------- #
# ADR-29 P3 — Downgrade / rollback config-preservation contract               #
# --------------------------------------------------------------------------- #


@pytest.mark.timeout(900)  # two pkg installs + two reloads + DNS probes; budget ~12 min
def test_pkg_downgrade_preserves_config_values(repo_vm: SmokeVM, tmp_path: Path) -> None:
    """DOWNGRADE CONFIG-PRESERVATION CONTRACT (ADR-29 Phase 3): config.xml stored
    values written by the HIGHER build are byte-identical after downgrading to the
    LOWER build, and the lower build reads sane values (DNSBL probe still works).

    This is the rollback leg of the ADR-29 backward-compat contract: because every
    write adapter emits only legacy vocabulary tokens (ADR-28 §2.2), a downgrade
    leaves older code reading values it already understands — no crash, no
    silent settings-loss.

    NOTE: pfb_keep is intentionally NOT set directly — the install-time migration
    (pfb_keep_migrate) seeds it on the HIGHER build install, and it must survive
    the downgrade unchanged (byte-identical). We rely on the migration seed, just
    as in the upgrade contract test.

    Scenario: ADR-29 rollback safety holds end-to-end on the live VM.
      Background: our NONE-signed file:// repo above the Netgate ``pfSense`` repo.

    Given the HIGHER (branch) build (``<V>_9``) installed and representative config
      written (dnsbl_lenient='on', dnsbl_vip_auto='on', pfb_dnsbl='on',
      pfb_idn='all'; pfb_keep seeded by migration), and a DNSBL-blocked
      unique_domain() name returning the VIP block shape on-box,

    When the LOWER build (``<V>_1``) is installed over the higher build via
      ``pkg install`` (reinstall path — same ABI, no ``pkg upgrade`` direction
      reversal; ``pkg delete`` + ``pkg_install_from_repo`` with the low-version
      repo mirrors what a user does to roll back),

    Then every snapshotted config.xml value is byte-identical (same raw stored
      string, no loss or mutation), AND the DNSBL probe still returns NOERROR + VIP
      on the SAME domain (runtime contract unchanged — lower build reads sane values).
    """
    pkg = os.environ.get("SMOKE_PKG")
    assert pkg and Path(pkg).is_file(), "SMOKE_PKG not set / not a file — repo_vm already gated this"

    base_version = read_compact_version(Path(pkg))
    low_version = f"{base_version}_1"
    high_version = f"{base_version}_9"
    assert low_version != high_version, "forged builds must differ for a real version transition"

    # Forge two builds on the runner — only the version string changes.
    low_pkg = reversion_pkg(Path(pkg), low_version, tmp_path / "low")
    high_pkg = reversion_pkg(Path(pkg), high_version, tmp_path / "high")

    pfsense_prio = repo_priority(repo_vm, NETGATE_REPO_NAME)

    try:
        # ------------------------------------------------------------------ #
        # GIVEN: higher (branch) build installed; representative config written#
        # ------------------------------------------------------------------ #

        # Install the HIGHER build from our file:// repo.
        pkg_delete(repo_vm)
        build_guest_repo(repo_vm, UPGRADE_REPO_DIR, [high_pkg])
        write_repo_conf(repo_vm, UPGRADE_REPO_DIR, ours_priority=pfsense_prio + 100)
        pkg_update(repo_vm)
        assert pkg_installed_version(repo_vm) is None, (
            "package unexpectedly present before downgrade-contract test install"
        )
        pkg_install_from_repo(repo_vm)
        assert pkg_installed_version(repo_vm) == high_version, (
            f"expected higher build {high_version!r} installed, got {pkg_installed_version(repo_vm)!r}"
        )

        # Write representative config fields into config.xml on the HIGHER build.
        # pfb_keep is intentionally omitted — the install migration seeds it.
        _write_representative_config(repo_vm)

        # Assert the install-time migration seeded pfb_keep='on' into config.xml.
        seeded_keep = h.config_get(repo_vm, _CFG_GLOBAL + "/pfb_keep")
        assert seeded_keep == "on", (
            f"install-time migration did not seed pfb_keep on higher build: got {seeded_keep!r}, expected 'on'."
        )

        # Snapshot the stored values on the HIGHER build (BEFORE values).
        before_snapshot = _snapshot_config(repo_vm)

        # Verify every expected value is present.
        for path, expected in _SNAPSHOT_FIELDS:
            actual = before_snapshot[path]
            assert actual == expected, f"BEFORE (higher build): config.xml {path!r} = {actual!r}, expected {expected!r}"

        # Set up DNSBL feed and VIP so the DNS probe can run.
        h.ensure_dnsbl_vip(repo_vm)
        _setup_dnsbl_feed(repo_vm)

        # Reload to make the DNSBL live on the HIGHER build.
        h.reload(repo_vm, "updatednsbl")

        # BEFORE state DNS probe: the blocked domain must return NOERROR + VIP.
        before_answer = h.dns_probe(repo_vm, _BLOCKED_DOMAIN, "A")
        assert h.is_vip(before_answer), (
            f"BEFORE downgrade: expected VIP block for {_BLOCKED_DOMAIN!r}; "
            f"got rcode={before_answer.rcode!r} records={before_answer.records!r}. "
            f"DNSBL was not live on the higher build."
        )

        # ------------------------------------------------------------------ #
        # WHEN: downgrade to lower build (pkg delete + reinstall lower version)#
        # ------------------------------------------------------------------ #

        # Replace the repo catalog with the lower build, then reinstall.
        # This mirrors the user rollback flow: delete current, install older.
        pkg_delete(repo_vm)
        build_guest_repo(repo_vm, UPGRADE_REPO_DIR, [low_pkg])
        pkg_update(repo_vm)
        pkg_install_from_repo(repo_vm)

        installed_after = pkg_installed_version(repo_vm)
        assert installed_after == low_version, (
            f"downgrade did not move {high_version!r} -> {low_version!r}; now at {installed_after!r}"
        )

        # ------------------------------------------------------------------ #
        # THEN: config.xml values byte-identical; DNSBL behaviour unchanged  #
        # ------------------------------------------------------------------ #

        # Read config.xml AFTER downgrade and assert every field is byte-identical.
        after_snapshot = _snapshot_config(repo_vm)
        _assert_snapshot_identical(before_snapshot, after_snapshot)

        # DNS contract: re-reload so the LOWER build's DNSBL is live, then probe
        # the SAME blocked domain. Must still return NOERROR + VIP.
        # This proves the lower build reads the written values as sane runtime values.
        h.reload(repo_vm, "updatednsbl")
        after_answer = h.dns_probe(repo_vm, _BLOCKED_DOMAIN, "A")
        assert h.is_vip(after_answer), (
            f"AFTER downgrade: expected VIP block for {_BLOCKED_DOMAIN!r}; "
            f"got rcode={after_answer.rcode!r} records={after_answer.records!r}. "
            f"Runtime contract broken by downgrade — rollback safety violated."
        )

    finally:
        pkg_delete(repo_vm)
        repo_vm.ssh("/bin/rm", "-rf", UPGRADE_REPO_DIR, timeout=60.0)


# --------------------------------------------------------------------------- #
# Issue #795 — install-time config-migration contract                        #
# --------------------------------------------------------------------------- #

# SafeSearch is a FLAT section (no /config/0) — mirrors pfblockerng_extra.inc's
# registry comment ("Section: installedpackages/pfblockerngsafesearch (flat, no /config/0)").
_CFG_SAFESEARCH = "installedpackages/pfblockerngsafesearch"
_CFG_IPSETTINGS = "installedpackages/pfblockerngipsettings/config/0"


def _seed_legacy_migration_config(vm: SmokeVM) -> None:
    """Seed a pre-migration legacy config directly via raw config_get_path/config_set_path.

    The package is ABSENT when this runs, so ``PfbConfig`` (defined in
    ``pfblockerng_extra.inc``) does not exist on the box yet — raw calls are the
    only option, same as pfSense itself sees an existing user's config.xml before
    the package (re)installs.

    ``safesearch_firefoxdoh`` is seeded 'Disable', NOT 'Enable': the firefoxdoh
    migration runs BEFORE the yandex-token migration in pfblockerng_install.inc, and
    its 'Enable' branch overwrites 'safesearch_doh_list' wholesale with
    'use-application-dns.net' — which would clobber the seeded legacy yandex token
    and turn the yandex migration into a no-op before it ever runs.
    """
    snippet = (
        # SafeSearch (flat section): legacy firefoxdoh key + a DoH list carrying the
        # legacy 'yandex.dns' token alongside an unrelated sibling entry.
        f"$ss = config_get_path({h._php_str(_CFG_SAFESEARCH)}, array());\n"
        "$ss['safesearch_firefoxdoh'] = 'Disable';\n"
        "$ss['safesearch_doh_list']   = 'dns.google,yandex.dns';\n"
        f"config_set_path({h._php_str(_CFG_SAFESEARCH)}, $ss);\n"
        # General section: MaxMind settings in their pre-migration (legacy) location.
        f"$g = config_get_path({h._php_str(_CFG_GLOBAL)}, array());\n"
        "$g['maxmind_key']    = 'SMOKE-MM-KEY-795';\n"
        "$g['maxmind_locale'] = 'en';\n"
        f"config_set_path({h._php_str(_CFG_GLOBAL)}, $g);\n"
        # IP-settings section: no maxmind_key, so the move migration's gate condition
        # (!isset($ip['maxmind_key'])) holds. The section itself is kept NON-empty
        # (marker key 'enable_dup'): the older, unrelated "General Tab -> IP Tab"
        # migration (pfblockerng_install.inc ~L447) fires when this section is empty
        # and would move 'maxmind_locale' FIRST — making the locale assertions pass
        # for the wrong reason instead of pinning the targeted MaxMind relocation.
        f"$ip = config_get_path({h._php_str(_CFG_IPSETTINGS)}, array());\n"
        "$ip['enable_dup'] = $ip['enable_dup'] ?? '';\n"
        "unset($ip['maxmind_key']);\n"
        f"config_set_path({h._php_str(_CFG_IPSETTINGS)}, $ip);\n"
        "write_config('pfBlockerNG issue-795 smoke: seed legacy pre-migration config');\n"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet, timeout=60.0)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(
            f"_seed_legacy_migration_config failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}"
        )


def _cleanup_migration_config(vm: SmokeVM) -> None:
    """Remove every key this test seeded/migrated, from BOTH possible locations.

    Self-encapsulation (CLAUDE.md): a sibling test must never inherit leftover
    SafeSearch/MaxMind state from this one. Deletes the whole (now package-owned)
    SafeSearch section and strips the MaxMind keys from both the general and
    ipsettings sections, regardless of which side the migration left them on —
    plus the 'enable_dup' non-empty marker the seed added to ipsettings.
    """
    snippet = (
        f"config_del_path({h._php_str(_CFG_SAFESEARCH)});\n"
        f"$g = config_get_path({h._php_str(_CFG_GLOBAL)}, array());\n"
        "unset($g['maxmind_key'], $g['maxmind_locale']);\n"
        f"config_set_path({h._php_str(_CFG_GLOBAL)}, $g);\n"
        f"$ip = config_get_path({h._php_str(_CFG_IPSETTINGS)}, array());\n"
        "unset($ip['maxmind_key'], $ip['maxmind_locale'], $ip['enable_dup']);\n"
        f"config_set_path({h._php_str(_CFG_IPSETTINGS)}, $ip);\n"
        "write_config('pfBlockerNG issue-795 smoke: cleanup migration config');\n"
        "echo 'OK';"
    )
    result = h.php_eval(vm, snippet, timeout=60.0)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(
            f"_cleanup_migration_config failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}"
        )


@pytest.mark.timeout(600)  # one pkg install cycle (no forged re-versioning) > the 30s default cap.
def test_pkg_install_applies_config_migrations(repo_vm: SmokeVM) -> None:
    """INSTALL-TIME MIGRATION CONTRACT (issue #795): the three config migrations in
    ``pfblockerng_install.inc`` run PROCEDURALLY during a real ``pkg install`` against
    a pre-seeded legacy config — not just at the pure-function level.
    ``SsDohListYandexMigrateTest`` (PHPUnit) already pins the yandex-token decision in
    isolation; this proves the full read-stored-value -> helper -> write ->
    ``write_config()`` chain actually executes on a live box, for all three migrations:

      1. SafeSearch DoH rename: 'safesearch_firefoxdoh' -> 'safesearch_doh' (key removed).
      2. Legacy Yandex DoH-list token rewrite: 'yandex.dns' -> 'dns.yandex' in the CSV.
      3. MaxMind key relocation: general section -> ipsettings section (removed from general).

    Scenario: issue #795 — install-time migrations apply on a real pkg install.
      Background: our NONE-signed file:// repo above the Netgate ``pfSense`` repo.

    Given the package ABSENT, and a legacy config seeded directly via raw
      config_get_path/config_set_path (safesearch_firefoxdoh='Disable',
      safesearch_doh_list='dns.google,yandex.dns'; general maxmind_key/maxmind_locale
      set; ipsettings maxmind_key absent),

    When the UNMODIFIED branch ``.pkg`` is installed (a plain ``pkg install`` runs
      ``rc.packages`` POST-INSTALL -> ``custom_php_install_command`` ->
      ``pfblockerng_install.inc`` top-to-bottom -> the trailing ``write_config()``),

    Then every migrated config.xml value reflects the post-migration state: the DoH
      setting moved to 'safesearch_doh', the legacy key removed, the yandex token
      rewritten with its sibling entry preserved, and the MaxMind settings moved from
      general to ipsettings.
    """
    pkg = os.environ.get("SMOKE_PKG")
    assert pkg and Path(pkg).is_file(), "SMOKE_PKG not set / not a file — repo_vm already gated this"

    pfsense_prio = repo_priority(repo_vm, NETGATE_REPO_NAME)

    try:
        # ------------------------------------------------------------------ #
        # GIVEN: package absent; a pre-seeded legacy config on the bare box   #
        # ------------------------------------------------------------------ #

        pkg_delete(repo_vm)
        assert pkg_installed_version(repo_vm) is None, (
            "package unexpectedly present before the issue-795 migration-contract install"
        )

        _seed_legacy_migration_config(repo_vm)

        # BEFORE state: assert the exact legacy values the migrations must transform.
        before_firefoxdoh = h.config_get(repo_vm, _CFG_SAFESEARCH + "/safesearch_firefoxdoh")
        assert before_firefoxdoh == "Disable", (
            f"BEFORE: safesearch_firefoxdoh = {before_firefoxdoh!r}, expected 'Disable' (seed did not take)"
        )
        before_doh_list = h.config_get(repo_vm, _CFG_SAFESEARCH + "/safesearch_doh_list")
        assert before_doh_list == "dns.google,yandex.dns", (
            f"BEFORE: safesearch_doh_list = {before_doh_list!r}, expected 'dns.google,yandex.dns' (seed did not take)"
        )
        before_gen_key = h.config_get(repo_vm, _CFG_GLOBAL + "/maxmind_key")
        assert before_gen_key == "SMOKE-MM-KEY-795", (
            f"BEFORE: general maxmind_key = {before_gen_key!r}, expected 'SMOKE-MM-KEY-795' (seed did not take)"
        )
        before_gen_locale = h.config_get(repo_vm, _CFG_GLOBAL + "/maxmind_locale")
        assert before_gen_locale == "en", (
            f"BEFORE: general maxmind_locale = {before_gen_locale!r}, expected 'en' (seed did not take)"
        )
        before_ip_key = h.config_get(repo_vm, _CFG_IPSETTINGS + "/maxmind_key")
        assert before_ip_key == "", (
            f"BEFORE: ipsettings maxmind_key = {before_ip_key!r}, expected '' (absent) — "
            "the move migration's gate condition requires this key to be unset"
        )

        # ------------------------------------------------------------------ #
        # WHEN: install the UNMODIFIED branch .pkg from our file:// repo     #
        # ------------------------------------------------------------------ #

        build_guest_repo(repo_vm, UPGRADE_REPO_DIR, [Path(pkg)])
        write_repo_conf(repo_vm, UPGRADE_REPO_DIR, ours_priority=pfsense_prio + 100)
        pkg_update(repo_vm)
        pkg_install_from_repo(repo_vm)

        installed = pkg_installed_version(repo_vm)
        expected_version = read_compact_version(Path(pkg))
        assert installed == expected_version, (
            f"expected the branch build {expected_version!r} installed, got {installed!r}"
        )

        # ------------------------------------------------------------------ #
        # THEN: every migrated value reflects the post-migration state       #
        # ------------------------------------------------------------------ #

        after_doh = h.config_get(repo_vm, _CFG_SAFESEARCH + "/safesearch_doh")
        assert after_doh == "Disable", (
            f"AFTER: safesearch_doh = {after_doh!r}, expected 'Disable' (copied from safesearch_firefoxdoh) — "
            "the SafeSearch DoH rename migration did not run"
        )
        after_firefoxdoh = h.config_get(repo_vm, _CFG_SAFESEARCH + "/safesearch_firefoxdoh")
        assert after_firefoxdoh == "", (
            f"AFTER: safesearch_firefoxdoh = {after_firefoxdoh!r}, expected '' (removed) — "
            "the legacy key was not unset by the SafeSearch DoH rename migration"
        )
        after_doh_list = h.config_get(repo_vm, _CFG_SAFESEARCH + "/safesearch_doh_list")
        assert after_doh_list == "dns.google,dns.yandex", (
            f"AFTER: safesearch_doh_list = {after_doh_list!r}, expected 'dns.google,dns.yandex' "
            "(legacy 'yandex.dns' token rewritten, sibling entry preserved) — "
            "the Yandex DoH-list token migration did not run"
        )
        after_ip_key = h.config_get(repo_vm, _CFG_IPSETTINGS + "/maxmind_key")
        assert after_ip_key == "SMOKE-MM-KEY-795", (
            f"AFTER: ipsettings maxmind_key = {after_ip_key!r}, expected 'SMOKE-MM-KEY-795' (moved) — "
            "the MaxMind key relocation migration did not run"
        )
        after_ip_locale = h.config_get(repo_vm, _CFG_IPSETTINGS + "/maxmind_locale")
        assert after_ip_locale == "en", (
            f"AFTER: ipsettings maxmind_locale = {after_ip_locale!r}, expected 'en' (moved) — "
            "the MaxMind key relocation migration did not run"
        )
        after_gen_key = h.config_get(repo_vm, _CFG_GLOBAL + "/maxmind_key")
        assert after_gen_key == "", (
            f"AFTER: general maxmind_key = {after_gen_key!r}, expected '' (removed from old location) — "
            "the MaxMind key relocation migration did not unset the source"
        )
        after_gen_locale = h.config_get(repo_vm, _CFG_GLOBAL + "/maxmind_locale")
        assert after_gen_locale == "", (
            f"AFTER: general maxmind_locale = {after_gen_locale!r}, expected '' (removed from old location) — "
            "the MaxMind key relocation migration did not unset the source"
        )

    finally:
        pkg_delete(repo_vm)
        repo_vm.ssh("/bin/rm", "-rf", UPGRADE_REPO_DIR, timeout=60.0)
        # Best-effort cleanup: never let a raised body assertion be masked — but still
        # remove the seeded/migrated keys so a sibling test never inherits this state.
        try:
            _cleanup_migration_config(repo_vm)
        except Exception as exc:  # noqa: BLE001 -- cleanup must not mask the real test outcome
            print(f"[smoke] _cleanup_migration_config failed (non-fatal): {exc}")
