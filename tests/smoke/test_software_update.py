"""ADR-19 Phase 1 — KILL-GATE: read-our-repo-latest + idempotent file_notice + provenance.

This is the ADR-01-style cheap falsification of ADR-19's THREE load-bearing pkg/API-mechanic
premises (ADR §1 "Premise to falsify cheaply", §6 Phase 1, §7 reject/degrade criteria), proven
on the SAME live ADR-04 pfSense CE VM the ADR-17 repo flow uses — BEFORE any ``src/`` page or
cron code is written. If a real box cannot read OUR repo's latest version without falling back
to ``-r pfSense`` (re-locking discovery to Netgate), or ``file_notice`` cannot be made
idempotent per version from a cron-like context, the design is wrong and must be reshaped now.

NOT A SMOKE TEST. Like ``test_repo_install.py`` this validates *distribution/awareness*
mechanics, not pfBlockerNG runtime behaviour, and carries the SAME marker ``repo`` (NOT
``smoke``), so ``pytest -m smoke`` never selects it. It REUSES that file's hermetic catalog +
``repo_vm`` machinery wholesale (no new VM boot path, no duplicated catalog code) and only adds
the new ADR-19 mechanics on top.

WHAT EACH CASE PROVES (mapped to ADR §1 premises + the 2026-06-15 provenance amendment):

  (a) ``test_read_our_repo_latest_without_pfsense_repo`` — §1 premise 1. ``pkg update
      -r <ourrepo>`` + ``pkg rquery -r <ourrepo> '%v' <pkgname>`` reads our catalog's HIGHER
      version while ``pkg query '%v'`` still reports the installed (lower) one, and the read
      does NOT touch the ``pfSense`` repo (no ``pfSense-repo-setup`` invocation; the pfSense
      conf is byte-unchanged across the read). GO/REJECT gate for premise 1.

  (b) ``test_file_notice_is_idempotent_per_version`` — §1 premise 2. ``file_notice(...)`` from
      a php-cli (cron-like) context puts EXACTLY ONE matching row in ``get_notices()`` (before:
      absent; after: present once); a SECOND tick at the SAME latest version raises NO new
      notice when gated by a caller-side last-notified file; a HIGHER latest version raises a
      SECOND notice. GO/REJECT gate for premise 2.

  (c) ``test_same_channel_upgrade_advances_from_our_repo`` — §1 premise 3. A same-channel
      ``pkg upgrade <ourpkg>`` advances the installed version from OUR repo (``%v`` N -> N+1,
      ``%R`` == ours). GO-or-DEGRADE gate for premise 3. (This re-confirms ADR-17 Phase-5 for
      THIS package name + the ADR-19 read/upgrade combination on one image.)

  (d) ``test_provenance_repo_origin_distinguishes_our_build_from_decoy`` — the 2026-06-15
      amendment. ``pkg query '%R' <pkgname>`` returns OUR repo name for an our-repo install and
      the DECOY/Netgate repo name for a decoy install — the exact signal the later
      ``pfb_software_is_our_build()`` provenance gate keys on. Both directions asserted so the
      signal is provably discriminating, not an always-ours artefact.

DESELECTED from the default ``python -m pytest`` (``--ignore=tests/smoke`` in pyproject.toml).
Run only via its own dispatch::

    python -m pytest tests/smoke -m repo --override-ini="addopts="

Needs the booted ``smoke_vm`` / ``repo_vm`` fixture, the branch ``.pkg`` (``SMOKE_PKG``) and
the ``zstd`` runner host-tool (for the re-versioned builds); without them it skips cleanly.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

# ``repo_vm`` is re-exported (not just imported): pytest resolves fixtures PER-MODULE, so
# importing the helper functions does NOT register the fixture in this module's namespace —
# the name must be present here for the cases below to request it. The noqa keeps the
# (module-level "unused") fixture import; the matching F811 ("redefinition" by each case param)
# is suppressed for this file in pyproject. Both are the standard pytest re-export idiom.
from .conftest import SmokeVM
from .test_repo_install import (  # noqa: F401
    DECOY_REPO_DIR,
    DECOY_REPO_NAME,
    NETGATE_REPO_NAME,
    OURS_REPO_DIR,
    OURS_REPO_NAME,
    PKG_NAME,
    UPGRADE_REPO_DIR,
    _ssh_check,
    build_guest_repo,
    pkg_delete,
    pkg_install_from_repo,
    pkg_installed_version,
    pkg_repo_origin,
    pkg_update,
    pkg_upgrade,
    read_compact_version,
    repo_priority,
    repo_vm,
    reversion_pkg,
    write_repo_conf,
)

pytestmark = pytest.mark.repo

# The per-channel repo a "Read latest" maps to (ADR §2 + 2026-06-15 amendment): stable/devel
# share ``pfblockerng``; nightly is the only separate repo. Phase 1 exercises the shared repo
# (the ADR-17 ``repo_vm`` fixture builds ``pfblockerng`` from the branch .pkg); the nightly
# mapping is pure-helper logic settled off-box in Phase 2. ``OURS_REPO_NAME`` IS ``pfblockerng``.
OURS_REPO_NAME_DEVEL = OURS_REPO_NAME

# The pfSense repo conf the read must NOT disturb (premise 1). Reading our latest with
# ``-r <ourrepo>`` must never run ``pfSense-repo-setup`` (which would rewrite this) nor read it.
PFSENSE_REPO_CONF = "/usr/local/etc/pkg/repos/pfSense.conf"

# A throwaway caller-side last-notified state file under the package's own state dir — the
# de-dupe pattern the Phase-3 cron will use (ADR §2 "De-duped by persisting the last-notified
# version"). Phase 1 only PROVES the pattern works; the real path/field land in Phase 3.
LAST_NOTIFIED_FILE = "/var/db/pfblockerng/pfb_software_last_notified"

# The notice identity the cron will raise (ADR §2 "Notice" row). Phase 1 uses the same id +
# category so the get_notices row shape is what Phase 3 will produce.
NOTICE_ID = "pfBlockerNG"
NOTICE_CATEGORY = "pfBlockerNG"
NOTICE_URL = "/pfblockerng/pfblockerng_software.php"


# --------------------------------------------------------------------------- #
# pkg-read helpers — read our repo's latest via -r <ourrepo>, never -r pfSense
# --------------------------------------------------------------------------- #


def pkg_update_our_repo(vm: SmokeVM, repo: str = OURS_REPO_NAME_DEVEL, *, timeout: float = 240.0) -> None:
    """``pkg update -r <repo>`` — refresh ONLY our catalog DB (premise-1 read path).

    The ``-r <repo>`` form re-reads exactly the named repo's catalog and no other; crucially it
    does NOT invoke ``get_pkg_info`` / ``pfSense-repo-setup`` (the base-system path that re-locks
    discovery to the Netgate ``pfSense`` repo, ADR §1 Context 2). ``-f`` forces a re-fetch so a
    just-rebuilt ``file://`` catalog is honoured even when its mtime/etag looks unchanged.
    """
    _ssh_check(vm, "env", "ASSUME_ALWAYS_YES=yes", "pkg", "update", "-f", "-r", repo, timeout=timeout)


def pkg_rquery_latest(vm: SmokeVM, repo: str = OURS_REPO_NAME_DEVEL, *, timeout: float = 60.0) -> str:
    """The latest ``%v`` our repo advertises for the package, read via ``-r <repo>`` alone.

    This is the ADR §2 "Read latest" invocation: ``pkg rquery -r <ourrepo> '%v' <pkgname>``.
    The ``-r`` confines the lookup to OUR catalog — no fall-through to the Netgate ``pfSense``
    repo. Raises (with output) on a non-zero exit so a repo that fails to answer is a hard fail,
    not a silent empty string.
    """
    return _ssh_check(vm, "pkg", "rquery", "-r", repo, "%v", PKG_NAME, timeout=timeout).stdout.strip()


def file_sha256(vm: SmokeVM, path: str, *, timeout: float = 60.0) -> str | None:
    """The sha256 of a guest file, or ``None`` if it is absent (the byte-unchanged oracle).

    Used to prove the read left the ``pfSense`` repo conf BYTE-IDENTICAL (premise 1). ``None``
    on either side (file absent before AND after) is itself acceptable — the read created
    nothing — so the caller asserts before == after, not non-None.
    """
    result = vm.ssh("/sbin/sha256", "-q", path, timeout=timeout)
    if result.returncode != 0:
        return None
    digest = result.stdout.strip()
    return digest or None


# --------------------------------------------------------------------------- #
# Notice helpers — drive file_notice / get_notices / close_notice via pfSsh.php
# --------------------------------------------------------------------------- #
# pfSense's notices API (upstream src/etc/inc/notices.inc):
#   file_notice($id, $notice, $category="General", $url="", $priority=1, $local_only=false)
#   get_notices()  -> array of {id, notice, category, url, priority, time} rows
#   close_notice($id) -> removes every row whose id matches
# pfSsh.php runs them in the fully-bootstrapped pfSense env (notices.inc is auto-loaded), the
# same env the real cron uses, so this proves the cron-context delivery path end-to-end.

_NOTICE_OPEN = "<<<NOTICECOUNT>>>"
_NOTICE_CLOSE = "<<<NOTICEEND>>>"


def _pfssh(vm: SmokeVM, snippet: str, *, timeout: float = 120.0) -> str:
    """Run a PHP snippet through pfSsh.php (bootstrapped + config-locked) and return stdout.

    Mirrors ``helpers.php_eval`` but kept local so this file imports only catalog machinery
    from ``test_repo_install`` and does not couple to the DNSBL matrix helpers. Raises on a
    non-zero pfSsh.php exit with the captured output.
    """
    program = snippet + "\nexec\nexit\n"
    result = subprocess.run(
        vm.ssh_argv("/usr/local/sbin/pfSsh.php"),
        input=program,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"pfSsh.php snippet failed: rc={result.returncode}\n{result.stderr}\n{result.stdout}")
    return result.stdout


def raise_notice(vm: SmokeVM, message: str, *, timeout: float = 120.0) -> None:
    """Raise ONE ``file_notice`` with the ADR-19 id/category/url (the cron's delivery call).

    The ``$local_only`` flag is left at its default (false) — the real cron wants remote
    fan-out too — but in CI there are no configured remote channels, so only the local bell row
    is created, which is exactly what ``get_notices`` reports and what this gate measures.
    """
    snippet = (
        f"file_notice({_php_str(NOTICE_ID)}, {_php_str(message)}, "
        f"{_php_str(NOTICE_CATEGORY)}, {_php_str(NOTICE_URL)}, 1);\necho 'OK';"
    )
    out = _pfssh(vm, snippet, timeout=timeout)
    if "OK" not in out:
        raise RuntimeError(f"raise_notice did not confirm: {out!r}")


def count_matching_notices(vm: SmokeVM, needle: str, *, timeout: float = 120.0) -> int:
    """How many ``get_notices()`` rows carry ``needle`` in their ``notice`` text (the oracle).

    Counts by the message SUBSTRING (a per-version string), not the id: file_notice with a
    repeated id REPLACES the prior row of that id (notices are id-keyed by their md5), so the
    de-dupe being proven is the CALLER not re-raising — a count keyed on the version string is
    what distinguishes "raised once" from "raised again at a new version". Delimited so
    pfSsh.php's startup banner never pollutes the integer.
    """
    snippet = (
        "$n = 0;\n"
        "foreach (get_notices() as $row) {\n"
        f"  if (strpos((string)($row['notice'] ?? ''), {_php_str(needle)}) !== FALSE) {{ $n++; }}\n"
        "}\n"
        f"echo {_php_str(_NOTICE_OPEN)} . $n . {_php_str(_NOTICE_CLOSE)};"
    )
    out = _pfssh(vm, snippet, timeout=timeout)
    start = out.find(_NOTICE_OPEN)
    end = out.find(_NOTICE_CLOSE)
    if start == -1 or end == -1:
        raise RuntimeError(f"count_matching_notices: no delimited count in pfSsh.php output: {out!r}")
    return int(out[start + len(_NOTICE_OPEN) : end])


def close_all_notices(vm: SmokeVM, *, timeout: float = 120.0) -> None:
    """Close every notice carrying our id — leave the VM CLEAN (teardown counterpart)."""
    snippet = f"close_notice({_php_str(NOTICE_ID)});\necho 'OK';"
    _pfssh(vm, snippet, timeout=timeout)


def _php_str(value: str) -> str:
    """Render a Python str as a single-quoted PHP string literal (mirrors helpers._php_str)."""
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


# --------------------------------------------------------------------------- #
# De-dupe pattern — the caller-side last-notified state file (ADR §2)
# --------------------------------------------------------------------------- #


def read_last_notified(vm: SmokeVM, *, timeout: float = 30.0) -> str | None:
    """The version recorded in the last-notified state file, or ``None`` if never written."""
    result = vm.ssh("cat", LAST_NOTIFIED_FILE, timeout=timeout)
    if result.returncode != 0:
        return None
    val = result.stdout.strip()
    return val or None


def write_last_notified(vm: SmokeVM, version: str, *, timeout: float = 30.0) -> None:
    """Persist ``version`` as the last-notified state (mkdir the state dir first)."""
    _ssh_check(vm, "/bin/mkdir", "-p", os.path.dirname(LAST_NOTIFIED_FILE), timeout=timeout)
    result = subprocess.run(
        vm.ssh_argv("tee", LAST_NOTIFIED_FILE),
        input=f"{version}\n",
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"write_last_notified failed: rc={result.returncode} {result.stderr!r}")


def cron_tick(vm: SmokeVM, latest: str, message: str) -> bool:
    """One de-duped cron-like tick: raise the notice ONLY when ``latest`` is newly notifiable.

    This is the exact caller-side de-dupe the Phase-3 cron will implement (ADR §2 "De-duped by
    persisting the last-notified version"): compare ``latest`` to the last-notified file; raise
    + record only when they differ. Returns ``True`` iff a notice was raised this tick — the
    branch the test asserts (raised at a new version, suppressed at the same one).
    """
    if read_last_notified(vm) == latest:
        return False
    raise_notice(vm, message)
    write_last_notified(vm, latest)
    return True


# --------------------------------------------------------------------------- #
# (a) §1 premise 1 — read our repo's latest WITHOUT touching the pfSense repo
# --------------------------------------------------------------------------- #


@pytest.mark.timeout(600)  # forge a higher build + install lower + 2 pkg updates + rquery > the 30s cap.
def test_read_our_repo_latest_without_pfsense_repo(repo_vm: SmokeVM, tmp_path: Path) -> None:
    """KILL-GATE §1 premise 1: ``pkg rquery -r <ourrepo>`` reads our HIGHER latest while the
    installed stays LOWER, and the read leaves the Netgate ``pfSense`` repo conf BYTE-UNCHANGED.

    The ADR §2 "Read latest" path is ``pkg update -r <ourrepo>`` then
    ``pkg rquery -r <ourrepo> '%v' <pkgname>`` — it must answer from OUR catalog ALONE, never
    falling back to ``get_pkg_info`` / ``-r pfSense`` (which would re-lock discovery to Netgate
    and show Netgate's version, ADR §1 Context 2/3). REJECT/redesign if reading our latest
    requires the pfSense path or ``pfSense-repo-setup`` rewrites our/its conf on every read.

    Scenario: read our repo's newer build without disturbing the Netgate repo.
      Background: our NONE-signed file:// repo carries a build HIGHER than the installed one.

    Given the LOWER build ``<V>_1`` installed from OUR repo and the ``pfSense.conf`` digest
      captured (the BEFORE state),
    When the repo is rebuilt to the HIGHER build ``<V>_9``, ``pkg update -r <ourrepo>`` refreshes
      ONLY our catalog, and ``pkg rquery -r <ourrepo> '%v'`` is read,
    Then rquery returns ``<V>_9`` (our latest) while ``pkg query '%v'`` still returns ``<V>_1``
      (the installed) — latest != installed, read by value — AND the ``pfSense.conf`` digest is
      byte-identical to before (the read never ran ``pfSense-repo-setup``).
    """
    pkg = os.environ.get("SMOKE_PKG")
    assert pkg and Path(pkg).is_file(), "SMOKE_PKG not set / not a file"  # repo_vm already gated this
    base_version = read_compact_version(Path(pkg))
    low_version = f"{base_version}_1"
    high_version = f"{base_version}_9"
    assert low_version != high_version  # the installed-vs-latest gap must be real

    low_pkg = reversion_pkg(Path(pkg), low_version, tmp_path / "low")
    high_pkg = reversion_pkg(Path(pkg), high_version, tmp_path / "high")
    pfsense_prio = repo_priority(repo_vm, NETGATE_REPO_NAME)
    try:
        # GIVEN: install the LOWER build from our repo; capture the pfSense conf digest BEFORE.
        pkg_delete(repo_vm)
        build_guest_repo(repo_vm, UPGRADE_REPO_DIR, [low_pkg])
        write_repo_conf(repo_vm, UPGRADE_REPO_DIR, ours_priority=pfsense_prio + 100)
        pkg_update(repo_vm)
        pkg_install_from_repo(repo_vm)
        assert pkg_installed_version(repo_vm) == low_version, (
            f"expected {low_version!r} installed, got {pkg_installed_version(repo_vm)!r}"
        )
        pfsense_conf_before = file_sha256(repo_vm, PFSENSE_REPO_CONF)

        # WHEN: publish the HIGHER build, read OUR latest via -r <ourrepo> ALONE.
        build_guest_repo(repo_vm, UPGRADE_REPO_DIR, [high_pkg])
        pkg_update_our_repo(repo_vm)
        latest = pkg_rquery_latest(repo_vm)
        installed = pkg_installed_version(repo_vm)

        # THEN: our latest is the HIGHER build; the installed is still the LOWER one (read by
        # value, latest != installed), and the Netgate conf is byte-unchanged (no -r pfSense).
        assert latest == high_version, (
            f"pkg rquery -r {OURS_REPO_NAME_DEVEL} returned {latest!r}, expected {high_version!r}"
        )
        assert installed == low_version, f"installed moved unexpectedly to {installed!r}, expected {low_version!r}"
        assert latest != installed, "latest must differ from installed for the read to be meaningful"
        pfsense_conf_after = file_sha256(repo_vm, PFSENSE_REPO_CONF)
        assert pfsense_conf_after == pfsense_conf_before, (
            f"the -r {OURS_REPO_NAME_DEVEL} read disturbed {PFSENSE_REPO_CONF} "
            f"(before={pfsense_conf_before!r} after={pfsense_conf_after!r}) — pfSense-repo-setup ran"
        )
    finally:
        pkg_delete(repo_vm)
        repo_vm.ssh("/bin/rm", "-rf", UPGRADE_REPO_DIR, timeout=60.0)


# --------------------------------------------------------------------------- #
# (b) §1 premise 2 — file_notice fires from cron context + is idempotent per version
# --------------------------------------------------------------------------- #


@pytest.mark.timeout(300)  # several pfSsh.php round-trips (raise/count/close) > the 30s cap.
def test_file_notice_is_idempotent_per_version(repo_vm: SmokeVM) -> None:
    """KILL-GATE §1 premise 2: ``file_notice`` fires from a cron-like (php-cli) context and is
    DE-DUPED per version by a caller-side last-notified file — one notice per new version, not
    one per tick. REJECT/redesign the notice path if it cannot be made idempotent per version.

    Drives the real pfSense notices API (``file_notice`` -> ``get_notices``) in the
    fully-bootstrapped env the cron uses; de-dupe is proven a CALLER concern (the ADR §2
    pattern: persist last-notified, only call when latest != last).

    Scenario: a daily cron tick must notify once per NEW version, never re-notify the same one.
      Background: a clean notice state (our id closed, no last-notified file).

    Given NO matching notice for version ``A`` (count == 0) and no last-notified state — the
      asserted BEFORE state,
    When a first cron tick runs at latest ``A``,
    Then exactly ONE notice mentioning ``A`` exists (it fired) and last-notified == ``A``.
    When a SECOND tick runs at the SAME latest ``A``,
    Then still exactly ONE notice mentioning ``A`` (no re-notify — the de-dupe held).
    When a third tick runs at a HIGHER latest ``B``,
    Then a notice mentioning ``B`` now exists (a new version DOES re-notify) while the ``A`` and
      ``B`` notifications are distinct messages — proving the gate keys on the version, not a
      blanket once-ever suppression.
    """
    version_a = "9.9.9_1"
    version_b = "9.9.9_2"
    msg_a = f"pfBlockerNG {version_a} available (devel)"
    msg_b = f"pfBlockerNG {version_b} available (devel)"
    try:
        # GIVEN: a clean before-state — no last-notified, no matching notice for A.
        close_all_notices(repo_vm)
        repo_vm.ssh("/bin/rm", "-f", LAST_NOTIFIED_FILE, timeout=30.0)
        assert read_last_notified(repo_vm) is None, "last-notified file unexpectedly present before the test"
        assert count_matching_notices(repo_vm, version_a) == 0, (
            f"a notice for {version_a} already present before tick 1"
        )

        # WHEN/THEN (tick 1, new version A): fires exactly once; state records A.
        assert cron_tick(repo_vm, version_a, msg_a) is True, "tick 1 should have raised a notice (new version)"
        assert count_matching_notices(repo_vm, version_a) == 1, "tick 1 did not produce exactly one notice for A"
        assert read_last_notified(repo_vm) == version_a, "tick 1 did not record A as last-notified"

        # WHEN/THEN (tick 2, SAME version A): suppressed; still exactly one A notice.
        assert cron_tick(repo_vm, version_a, msg_a) is False, "tick 2 re-notified the SAME version (de-dupe failed)"
        assert count_matching_notices(repo_vm, version_a) == 1, "tick 2 created a duplicate notice for the same version"

        # WHEN/THEN (tick 3, HIGHER version B): a new version DOES re-notify.
        assert count_matching_notices(repo_vm, version_b) == 0, f"a notice for {version_b} present before tick 3"
        assert cron_tick(repo_vm, version_b, msg_b) is True, "tick 3 should have raised a notice (newer version)"
        assert count_matching_notices(repo_vm, version_b) == 1, "tick 3 did not produce exactly one notice for B"
        assert read_last_notified(repo_vm) == version_b, "tick 3 did not advance last-notified to B"
    finally:
        close_all_notices(repo_vm)
        repo_vm.ssh("/bin/rm", "-f", LAST_NOTIFIED_FILE, timeout=30.0)


# --------------------------------------------------------------------------- #
# (c) §1 premise 3 — same-channel pkg upgrade advances from our repo
# --------------------------------------------------------------------------- #


@pytest.mark.timeout(600)  # forge 2 builds + install lower + a real pkg upgrade transition > the 30s cap.
def test_same_channel_upgrade_advances_from_our_repo(repo_vm: SmokeVM, tmp_path: Path) -> None:
    """KILL-GATE §1 premise 3 (GO-or-DEGRADE): a same-channel ``pkg upgrade <ourpkg>`` advances
    the installed version from OUR repo — the "Update now" path the Software page will wrap.

    This re-confirms ADR-17 Phase-5's in-repo upgrade precedence for THIS package name combined
    with the ADR-19 read step, on one image. DEGRADE (not REJECT) to a documented CLI step if an
    in-GUI same-channel upgrade proves unreliable (ADR §7) — display + notice still ship.

    Scenario: a newer same-channel build in our repo upgrades an installed box.
      Background: our NONE-signed file:// repo above the Netgate ``pfSense`` repo.

    Given the LOWER build ``<V>_1`` installed from OUR repo (``%v`` == ``<V>_1``, ``%R`` == ours)
      — the asserted BEFORE state,
    When the SAME repo is rebuilt to the HIGHER build ``<V>_9`` and ``pkg upgrade -y`` runs,
    Then the box MOVES to ``<V>_9`` still from OUR repo (``%v`` == ``<V>_9``, ``%R`` == ours) —
      a real before != after transition, deps resolved.
    """
    pkg = os.environ.get("SMOKE_PKG")
    assert pkg and Path(pkg).is_file(), "SMOKE_PKG not set / not a file"  # repo_vm already gated this
    base_version = read_compact_version(Path(pkg))
    low_version = f"{base_version}_1"
    high_version = f"{base_version}_9"
    assert low_version != high_version

    low_pkg = reversion_pkg(Path(pkg), low_version, tmp_path / "low")
    high_pkg = reversion_pkg(Path(pkg), high_version, tmp_path / "high")
    pfsense_prio = repo_priority(repo_vm, NETGATE_REPO_NAME)
    try:
        # GIVEN: the LOWER build installed from our repo (the BEFORE state).
        pkg_delete(repo_vm)
        build_guest_repo(repo_vm, UPGRADE_REPO_DIR, [low_pkg])
        write_repo_conf(repo_vm, UPGRADE_REPO_DIR, ours_priority=pfsense_prio + 100)
        pkg_update(repo_vm)
        pkg_install_from_repo(repo_vm)
        assert pkg_installed_version(repo_vm) == low_version, (
            f"expected {low_version!r} before upgrade, got {pkg_installed_version(repo_vm)!r}"
        )
        assert pkg_repo_origin(repo_vm) == OURS_REPO_NAME, "lower build did not come from our repo"

        # WHEN: publish the HIGHER build into the SAME repo, re-read it, upgrade.
        build_guest_repo(repo_vm, UPGRADE_REPO_DIR, [high_pkg])
        pkg_update(repo_vm)
        proc = pkg_upgrade(repo_vm)

        # THEN: moved to the HIGHER build, still from our repo, deps resolved.
        combined = proc.stdout + proc.stderr
        assert "Missing dependency" not in combined, f"RUN_DEPENDS did not resolve on upgrade:\n{combined}"
        assert pkg_installed_version(repo_vm) == high_version, (
            f"pkg upgrade did not move {low_version!r} -> {high_version!r}; now at {pkg_installed_version(repo_vm)!r}"
        )
        assert pkg_repo_origin(repo_vm) == OURS_REPO_NAME, "upgraded build did not come from our repo"
    finally:
        pkg_delete(repo_vm)
        repo_vm.ssh("/bin/rm", "-rf", UPGRADE_REPO_DIR, timeout=60.0)


# --------------------------------------------------------------------------- #
# (d) 2026-06-15 amendment — the provenance probe (%R distinguishes our build)
# --------------------------------------------------------------------------- #


@pytest.mark.timeout(600)  # two installs (ours, then decoy) + queries > the 30s cap.
def test_provenance_repo_origin_distinguishes_our_build_from_decoy(repo_vm: SmokeVM) -> None:
    """KILL-GATE (2026-06-15 provenance amendment): ``pkg query '%R' <pkgname>`` returns OUR repo
    name for an our-repo install and the COMPETING repo name for a decoy install — the exact
    signal the later ``pfb_software_is_our_build()`` provenance gate keys on (the whole Software
    feature is present ONLY when ``%R`` is one of OUR repos).

    Both directions are asserted so the signal is provably DISCRIMINATING — a Netgate-installed
    add-on (a decoy/non-``pfblockerng`` ``%R``) must read DIFFERENTLY from our build, else the
    gate could never hide the feature on a stock install. The controlled ``netgate-decoy``
    file:// repo stands in for the Netgate repo (which does not serve ``-devel`` in this hermetic
    CE image), exactly as the ADR-17 precedence cases use it.

    Scenario: provenance is read from the repo a package was installed FROM.
      Background: ours + a decoy file:// repo both serving the identical package.

    Given the package ABSENT (before state) and OUR repo at the higher priority,
    When ``pkg install -y`` resolves across all repos,
    Then ``pkg query '%R'`` == ``pfblockerng`` (our build -> the gate would SHOW the feature).
    When the package is removed and reinstalled with the DECOY at the higher priority,
    Then ``pkg query '%R'`` == ``netgate-decoy`` (a non-our build -> the gate would HIDE it) —
      a real before != after on the provenance signal, not an always-ours artefact.
    """
    pfsense_prio = repo_priority(repo_vm, NETGATE_REPO_NAME)
    try:
        # GIVEN: package absent; ours ABOVE the decoy (both above pfSense).
        pkg_delete(repo_vm)
        write_repo_conf(
            repo_vm,
            OURS_REPO_DIR,
            ours_priority=pfsense_prio + 200,
            decoy_dir=DECOY_REPO_DIR,
            decoy_priority=pfsense_prio + 100,
        )
        pkg_update(repo_vm)
        assert pkg_installed_version(repo_vm) is None, f"{PKG_NAME} unexpectedly present before the provenance install"

        # WHEN/THEN (our build): %R reads OUR repo -> the gate would SHOW the feature.
        pkg_install_from_repo(repo_vm)
        our_origin = pkg_repo_origin(repo_vm)
        assert our_origin == OURS_REPO_NAME, (
            f"provenance %R for our-repo install was {our_origin!r}, expected {OURS_REPO_NAME!r} "
            f"(the gate would wrongly HIDE the feature on our own build)"
        )

        # WHEN: reinstall with the DECOY now at the higher priority (a non-our build).
        pkg_delete(repo_vm)
        write_repo_conf(
            repo_vm,
            OURS_REPO_DIR,
            ours_priority=pfsense_prio + 100,
            decoy_dir=DECOY_REPO_DIR,
            decoy_priority=pfsense_prio + 200,
        )
        pkg_update(repo_vm)
        assert pkg_installed_version(repo_vm) is None, "package not cleanly removed before the decoy install"
        pkg_install_from_repo(repo_vm)

        # THEN (decoy build): %R reads the DECOY repo -> the gate would HIDE the feature.
        decoy_origin = pkg_repo_origin(repo_vm)
        assert decoy_origin == DECOY_REPO_NAME, (
            f"provenance %R for decoy install was {decoy_origin!r}, expected {DECOY_REPO_NAME!r} "
            f"(the gate could not tell a stock/non-our build apart)"
        )
        assert decoy_origin != our_origin, "provenance %R did not change between our-repo and decoy installs"
    finally:
        pkg_delete(repo_vm)
