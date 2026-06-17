"""ADR-28 Phase 11 — UPGRADE-CONTRACT KILL-GATE: config.xml stored values are
byte-identical before and after ``pkg upgrade`` from a prior-release build to the
branch build (which contains ADR-28's enum adoption).

NOT A SMOKE TEST. Like ``test_repo_install.py`` this validates a *distribution*
mechanic — specifically the no-migration, backward-compatible upgrade contract —
and carries the ``repo`` marker (NOT ``smoke``), so ``pytest -m smoke`` never
selects it. It reuses ``test_repo_install.py``'s hermetic ``file://`` catalog and
``repo_vm`` fixture machinery.

WHAT THE CASE PROVES (ADR-28 §2.2 + §7 DoD):

  ``test_adr28_upgrade_contract`` — config.xml stored values are byte-identical
  after a ``pkg upgrade`` from the prior-release build (``<V>_1``) to the branch
  build (``<V>_9``). The branch build introduces ADR-28's PHP ``PfbToggle`` /
  ``PfbLenient`` / ``PfbIdn`` enum adapters. The test asserts:

    (1) BEFORE state: representative config written and read back correctly on the
        LOWER build:
          - ``dnsbl_lenient='on'``    (adapted field → PfbLenient::On)
          - ``dnsbl_vip_auto='on'``   (adapted field → PfbToggle::On)
          - ``pfb_dnsbl='on'``        (adopted toggle field)
          - ``pfb_idn='all'``         (EXCLUDED field — kept as raw string; 'on'
                                       normalises to 'all', so only canonical values
                                       are snapshotted here — see ADR-28 §2.2 exclusion)
        BEFORE runtime behaviour: a DNSBL-blocked unique_domain() name returns the
        VIP block shape on-box (proves DNSBL is live before the upgrade).

    (2) WHEN: branch build (``<V>_9``) is installed over the lower build via
        ``pkg upgrade``.

    (3) THEN every snapshotted config.xml value is byte-identical (same raw string,
        no migration artefact), AND the DNSBL probe still returns the same VIP block
        shape on the same domain (runtime contract unchanged).

ADR-28 §2.2 hard-freeze: "config.xml stored values never change — every checkbox
'on'/''/… stays byte-identical across upgrade. No migration routine exists in this
package." A drift here is a reject criterion (ADR §7).

DESELECTED from the default ``python -m pytest``
(``--ignore=tests/smoke`` in pyproject.toml).
Run only via its own dispatch::

    python -m pytest tests/smoke -m repo --override-ini="addopts="

Needs the booted ``smoke_vm`` / ``repo_vm`` fixture, the branch ``.pkg``
(``SMOKE_PKG``) and the ``zstd`` runner host-tool (for the re-versioned builds);
without them it skips cleanly.
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

# The four fields snapshotted for the upgrade-contract assertion:
#   dnsbl_lenient — PfbLenient adapter (adopted); stored 'on'/'lenient'/''
#   dnsbl_vip_auto — PfbToggle adapter (adopted); stored 'on'/''
#   pfb_dnsbl     — PfbToggle adapter (adopted); stored 'on'/''
#   pfb_idn       — excluded (kept string); 'all'/'confusable'/''; 'on' -> 'all'
_SNAPSHOT_FIELDS: list[tuple[str, str]] = [
    (_CFG_DNSBL + "/dnsbl_lenient", "on"),  # PfbLenient::On
    (_CFG_DNSBL + "/dnsbl_vip_auto", "on"),  # PfbToggle::On (dnsbl-settings side)
    (_CFG_DNSBL + "/pfb_dnsbl", "on"),  # PfbToggle::On
    (_CFG_DNSBL + "/pfb_idn", "all"),  # excluded field — canonical stored value
]

# Local feed fixture content used for the DNSBL probe.
# Domain uuid-a344db4286a4.com is the block member in dnsbl_plain.txt (ASCII uuid).
_FEED_CONTENT = "uuid-a344db4286a4.com\n"
_BLOCKED_DOMAIN = "uuid-a344db4286a4.com"


def _write_representative_config(vm: SmokeVM) -> None:
    """Write the ADR-28 representative config into config.xml.

    Sets the four snapshotted fields plus the minimum DNSBL enable chain so the
    before-state DNS probe works:
      enable_cb='on'  (global pfBlockerNG master switch)
      pfb_dnsbl='on'  (DNSBL subsystem on — also a snapshotted field)
      dnsbl_vip_auto='on'  (auto-VIP; snapshotted field)
      dnsbl_lenient='on'  (PfbLenient; snapshotted field)
      pfb_idn='all'  (excluded field; stored canonical value)
    """
    snippet = (
        # Global block: master switch on
        f"$g = config_get_path({h._php_str(_CFG_GLOBAL)}, array());\n"
        "$g['enable_cb'] = 'on';\n"
        f"config_set_path({h._php_str(_CFG_GLOBAL)}, $g);\n"
        # DNSBL-settings block: the four snapshotted fields
        f"$s = config_get_path({h._php_str(_CFG_DNSBL)}, array());\n"
        "$s['pfb_dnsbl']      = 'on';\n"
        "$s['dnsbl_vip_auto'] = 'on';\n"
        "$s['dnsbl_lenient']  = 'on';\n"
        "$s['pfb_idn']        = 'all';\n"
        f"config_set_path({h._php_str(_CFG_DNSBL)}, $s);\n"
        "write_config('pfBlockerNG ADR-28 upgrade-contract smoke: set representative config');\n"
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
            "ADR-28 upgrade-contract VIOLATED: config.xml stored values drifted "
            f"after pkg upgrade ({len(drifts)} field(s)):\n" + "\n".join(drifts)
        )


def _setup_dnsbl_feed(vm: SmokeVM) -> str:
    """Write the local DNSBL feed and wire it as the active DNSBL list; return the feed path."""
    feed_path = h.write_local_feed(vm, "adr28_upgrade_contract.txt", _FEED_CONTENT)
    spec = h.DnsblCase(
        aliasname="ADR28Upgrade",
        feed_url=feed_path,
        mode=h.DnsblMode.VIP,
        header="adr28-upgrade-contract",
        # hsts=False: ensure the test domain is not silently promoted to NULL by
        # HSTS (the test domain is uuid-*.com, not an HSTS-preload name, so this
        # is belt-and-suspenders — pfb_hsts default is 'on' but uuid- names are
        # never in the preload list; explicitly off avoids any residual surprises).
        hsts=False,
    )
    h.inject(vm, spec)
    return feed_path


# --------------------------------------------------------------------------- #
# The upgrade-contract test
# --------------------------------------------------------------------------- #


@pytest.mark.timeout(900)  # two pkg installs + two reloads + DNS probes; budget ~12 min
def test_adr28_upgrade_contract(repo_vm: SmokeVM, tmp_path: Path) -> None:
    """ADR-28 UPGRADE-CONTRACT KILL-GATE: config.xml stored values are byte-identical
    before and after ``pkg upgrade`` from the prior-release build to the branch build.

    The branch build introduces ADR-28's PHP enum adapters (PfbToggle / PfbLenient /
    PfbIdn). The adapters must round-trip losslessly — no migration routine exists in
    this package, so the stored values must be byte-identical after upgrade (ADR-28
    §2.2 hard freeze). A drift here is a reject criterion (ADR §7).

    Scenario: ADR-28 PHP enum adapters leave config.xml byte-identical on upgrade.
      Background: our NONE-signed file:// repo above the Netgate ``pfSense`` repo.

    Given the prior-release build (``<V>_1``) installed and representative config
      written (dnsbl_lenient='on', dnsbl_vip_auto='on', pfb_dnsbl='on',
      pfb_idn='all'), and a DNSBL-blocked unique_domain() name returning the VIP block
      shape on-box,
      Assert the BEFORE state: config.xml fields read back correctly; DNSBL probe
      returns NOERROR + VIP (proves DNSBL is live before upgrade).

    When the branch build (``<V>_9``) is installed over the lower build via
      ``pkg upgrade``,

    Then every snapshotted config.xml value is byte-identical (same raw stored string,
      no enum migration artefact), AND the DNSBL probe still returns NOERROR + VIP on
      the SAME domain (runtime contract unchanged).
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

        # Write the representative config fields into config.xml on the lower build.
        _write_representative_config(repo_vm)

        # Snapshot the stored values (these are the BEFORE values every THEN assertion
        # is compared against — the exact raw strings from config.xml).
        before_snapshot = _snapshot_config(repo_vm)

        # Verify every expected value is present in the before snapshot.
        for path, expected in _SNAPSHOT_FIELDS:
            actual = before_snapshot[path]
            assert actual == expected, f"BEFORE: config.xml {path!r} = {actual!r}, expected {expected!r}"

        # Set up the DNSBL feed and ensure_dnsbl_vip so the DNS probe can run.
        h.ensure_dnsbl_vip(repo_vm)
        _setup_dnsbl_feed(repo_vm)

        # Reload (the full DNSBL + IP pass) to make the DNSBL live.
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
        # THEN: config.xml values byte-identical; DNSBL behaviour unchanged   #
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
