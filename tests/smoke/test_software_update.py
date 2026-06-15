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

import json
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
# Phase-5 POSITIVE journey constants — the SHIPPED Phase-4 src/ surfaces, now on a
# box installed FROM our repo (``%R`` == ``pfblockerng``), so the provenance gate is
# SATISFIED. (Phase 4 proved the NEGATIVE side live: the ADR-04 ``ui_render`` harness
# installs with ``pkg add -f``, ``%R`` is NOT our repo, so the page + tab are HIDDEN.
# An our-repo install — only reachable in this ``repo`` flow — is the only place the
# POSITIVE side can be proven.)
# --------------------------------------------------------------------------- #

# The Phase-3 orchestrator's cache file (ADR §2 "Background check"). The page reads it;
# the cron (pfb_software_update_check) writes it. Cleared between cases for clean befores.
SOFTWARE_CACHE_FILE = "/var/db/pfblockerng/software_update.json"

# The installed pfBlockerNG include + the Phase-4 page, at their on-box install paths.
# The page is shipped under www/ (NOT chroot-copied); the inc holds the orchestrator +
# the provenance helper the page guards on. ``pfb_software_provenance_ok()`` and
# ``pfb_software_update_check()`` are driven live by loading this inc in pfSsh.php.
PFB_INC_PATH = "/usr/local/pkg/pfblockerng/pfblockerng.inc"
SOFTWARE_PAGE_FILE = "/usr/local/www/pfblockerng/pfblockerng_software.php"

# The page's ui_render content marker (Phase 4): the element id on the Channel
# StaticText. Asserting it inside the SHIPPED page file proves the .pkg actually
# carried pfblockerng_software.php (the FreeBSD-ports plist entry took effect when the
# build ran with ports_ref=adr/19-update-channel-panel).
SOFTWARE_PANEL_MARKER = "pfb-software-panel"

# The notify config knob the page writes + the orchestrator reads (Phase 3). Driving it
# off the installed channel (devel) proves the channel-default OFF branch; injecting a
# nightly channel proves the channel-default ON branch (the nightly repo/package is not
# in this hermetic CE image, so the nightly CHANNEL is simulated via the orchestrator's
# documented $io seam — noted in the handoff).
NOTIFY_KNOB_PATH = "installedpackages/pfblockerng/config/0/pfb_software_notify"

# Delimiters for reading a single scalar back out of pfSsh.php (its startup banner
# otherwise pollutes stdout — same pattern as count_matching_notices above).
_VAL_OPEN = "<<<PFBVAL>>>"
_VAL_CLOSE = "<<<PFBEND>>>"


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


# =========================================================================== #
# PHASE 5 — the POSITIVE end-to-end journey on an OUR-REPO install
# =========================================================================== #
# Phases 1-3 proved the pkg/notice/upgrade MECHANICS and the pure decision core; Phase 4
# proved the page's NEGATIVE (hidden-on-Netgate) side live. This phase proves the
# POSITIVE side that only an our-repo install (``%R`` == ``pfblockerng``) can exercise:
# the provenance gate OPENS, the SHIPPED orchestrator (pfb_software_update_check) writes
# the cache + raises the de-duped channel-correct file_notice, and same-channel
# ``pkg upgrade`` advances the box from OUR repo. The page itself is asserted live via
# pfSsh.php (provenance_ok TRUE + ``php -l`` of the shipped page + its content marker
# present in the installed file) — the ``repo`` harness has no authenticated webui client
# (the ADR-14 ``webui`` fixture depends on ``deployed_vm``, a ``pkg add -f`` install whose
# ``%R`` is NOT our repo), so pfSsh.php is the robust live oracle here.


def _pfssh_scalar(vm: SmokeVM, snippet: str, *, timeout: float = 120.0) -> str:
    """Run a PHP snippet through pfSsh.php and return the value it prints between the
    ``_VAL_OPEN``/``_VAL_CLOSE`` delimiters (pfSsh.php's startup banner is stripped)."""
    out = _pfssh(vm, snippet, timeout=timeout)
    start = out.find(_VAL_OPEN)
    end = out.find(_VAL_CLOSE)
    if start == -1 or end == -1:
        raise RuntimeError(f"_pfssh_scalar: no delimited value in pfSsh.php output: {out!r}")
    return out[start + len(_VAL_OPEN) : end]


def provenance_ok_on_box(vm: SmokeVM, *, timeout: float = 120.0) -> bool:
    """The SHIPPED ``pfb_software_provenance_ok()`` evaluated on the live box.

    Loads the installed ``pfblockerng.inc`` in the bootstrapped pfSsh.php env and calls the
    real gate — the exact predicate the page's top-of-file guard + the tab append key on.
    On an our-repo install it must read TRUE (``%R`` == ``pfblockerng``); on a Netgate /
    decoy install FALSE. This is the live inverse of Phase 4's negative ``ui_render`` gate.
    """
    snippet = (
        f"require_once({_php_str(PFB_INC_PATH)});\n"
        f"echo {_php_str(_VAL_OPEN)} . (pfb_software_provenance_ok() ? '1' : '0') . {_php_str(_VAL_CLOSE)};"
    )
    return _pfssh_scalar(vm, snippet, timeout=timeout) == "1"


def run_update_check_on_box(
    vm: SmokeVM,
    *,
    force: bool = True,
    io_overrides: dict[str, str] | None = None,
    timeout: float = 240.0,
) -> None:
    """Drive the SHIPPED ``pfb_software_update_check()`` once, the way the cron tick does.

    With no ``io_overrides`` it runs fully live (reads ``pkg`` for installed/latest/repo) —
    the real journey. ``io_overrides`` exercises the documented ``$io`` seam to inject a
    channel/version (used ONLY to simulate the *nightly* channel, which has no repo/package
    in this hermetic CE image — noted in the handoff). Raises on a non-zero pfSsh.php exit.
    """
    if io_overrides:
        pairs = ", ".join(f"{_php_str(k)} => {_php_str(v)}" for k, v in io_overrides.items())
        io_arg = f"array({pairs})"
    else:
        io_arg = "null"
    snippet = (
        f"require_once({_php_str(PFB_INC_PATH)});\n"
        f"global $pfb; pfb_global();\n"
        f"pfb_software_update_check({'true' if force else 'false'}, {io_arg});\n"
        "echo 'OK';"
    )
    out = _pfssh(vm, snippet, timeout=timeout)
    if "OK" not in out:
        raise RuntimeError(f"pfb_software_update_check did not confirm: {out!r}")


def read_software_cache(vm: SmokeVM, *, timeout: float = 30.0) -> dict[str, object]:
    """The orchestrator's cache file decoded, or ``{}`` when absent (the before/after oracle)."""
    result = vm.ssh("cat", SOFTWARE_CACHE_FILE, timeout=timeout)
    if result.returncode != 0:
        return {}
    raw = result.stdout.strip()
    if not raw:
        return {}
    data = json.loads(raw)
    return data if isinstance(data, dict) else {}


def clear_software_state(vm: SmokeVM, *, timeout: float = 30.0) -> None:
    """Remove the cache + close our notices — a clean BEFORE state for each case."""
    vm.ssh("/bin/rm", "-f", SOFTWARE_CACHE_FILE, timeout=timeout)
    close_all_notices(vm, timeout=120.0)


def set_notify_knob(vm: SmokeVM, value: str, *, timeout: float = 120.0) -> None:
    """Persist ``pfb_software_notify`` (default|on|off) via the real config API.

    Mirrors what the page's save POST does — config_set_path + write_config in the
    config-locked pfSsh.php env — so the orchestrator reads the same value the GUI would.
    """
    snippet = (
        f"config_set_path({_php_str(NOTIFY_KNOB_PATH)}, {_php_str(value)});\n"
        "write_config('ADR-19 phase-5 smoke: set pfb_software_notify');\necho 'OK';"
    )
    out = _pfssh(vm, snippet, timeout=timeout)
    if "OK" not in out:
        raise RuntimeError(f"set_notify_knob did not confirm: {out!r}")


def clear_notify_knob(vm: SmokeVM, *, timeout: float = 120.0) -> None:
    """Reset the notify knob to its unset/'default' value (the channel-default branch)."""
    set_notify_knob(vm, "default", timeout=timeout)


def php_lint_ok(vm: SmokeVM, path: str, *, timeout: float = 60.0) -> bool:
    """``php -l <path>`` on the box — the shipped page parses cleanly (no Fatal/Parse)."""
    result = vm.ssh("php", "-l", path, timeout=timeout)
    return result.returncode == 0 and "No syntax errors detected" in result.stdout


def install_our_build_at(vm: SmokeVM, version: str, src: Path, tmp_path: Path, tag: str) -> None:
    """Install ``version`` of our package FROM our (re-versioned) repo (``%R`` == ours).

    Builds a single-build catalog in ``UPGRADE_REPO_DIR`` at ``version`` and installs it
    above the Netgate repo by priority, so the install provenance is OUR repo — the
    precondition for the provenance gate to OPEN.
    """
    forged = reversion_pkg(src, version, tmp_path / tag)
    pfsense_prio = repo_priority(vm, NETGATE_REPO_NAME)
    pkg_delete(vm)
    build_guest_repo(vm, UPGRADE_REPO_DIR, [forged])
    write_repo_conf(vm, UPGRADE_REPO_DIR, ours_priority=pfsense_prio + 100)
    pkg_update(vm)
    pkg_install_from_repo(vm)


# --------------------------------------------------------------------------- #
# (e) The POSITIVE page-gate + cache + de-duped-notice + Update-now journey
# --------------------------------------------------------------------------- #


@pytest.mark.timeout(900)  # 2 forged builds + install + 2 checks + a real pkg upgrade > the 30s cap.
def test_software_positive_journey_on_our_repo_install(repo_vm: SmokeVM, tmp_path: Path) -> None:
    """The POSITIVE end-to-end Software journey on an OUR-REPO install (``%R`` == ours).

    Proves every gate Phase 4 showed HIDDEN is now OPEN, and the publish-newer ->
    de-duped notice + cache + same-channel Update chain works live. Channel here is
    ``devel`` (the installed ``-devel`` package), whose notify default is OFF — so the
    knob is forced ``on`` for the notice legs (the channel-default OFF/ON branches are
    pinned separately in ``test_software_notify_default_is_channel_correct``).

    Scenario: an our-repo box sees the Software page, gets one notice for a newer build,
    and Update-now pulls it.
      Background: our NONE-signed file:// repo above the Netgate repo; egress open.

    Given build ``<V>_1`` installed FROM our repo (the asserted BEFORE: provenance OPEN,
      page parses + carries its marker, knob=on, NO cache, NO notice),
    When the first check runs at installed==latest==``<V>_1``,
    Then the cache records installed==latest==``<V>_1`` and NO notice is raised (up to date).
    When ``<V>_9`` is published to the SAME repo and the check runs,
    Then the cache ``latest`` advances to ``<V>_9`` and EXACTLY ONE notice mentioning
      ``<V>_9`` appears; a SECOND check at the same latest raises NO second notice (de-dupe).
    When ``pkg upgrade`` runs and the check runs again,
    Then the box moved to ``<V>_9`` still from OUR repo, the cache shows installed==latest,
      and NO new notice is raised — each before/after asserted by value.
    """
    pkg = os.environ.get("SMOKE_PKG")
    assert pkg and Path(pkg).is_file(), "SMOKE_PKG not set / not a file"  # repo_vm already gated this
    src = Path(pkg)
    base_version = read_compact_version(src)
    low = f"{base_version}_1"
    high = f"{base_version}_9"
    assert low != high

    try:
        # GIVEN: the LOWER build installed FROM our repo -> provenance gate OPENS.
        install_our_build_at(repo_vm, low, src, tmp_path, "low")
        got = pkg_installed_version(repo_vm)
        assert got == low, f"expected {low!r} installed, got {got!r}"
        assert pkg_repo_origin(repo_vm) == OURS_REPO_NAME, "lower build did not come from our repo"

        # GIVEN (the Phase-4 NEGATIVE inverse, now POSITIVE): the gate reads TRUE, the
        # SHIPPED page parses, and the .pkg actually carried it (marker in the file).
        assert provenance_ok_on_box(repo_vm) is True, (
            "pfb_software_provenance_ok() is FALSE on an our-repo install — the page/tab would be wrongly HIDDEN"
        )
        assert php_lint_ok(repo_vm, SOFTWARE_PAGE_FILE), (
            f"{SOFTWARE_PAGE_FILE} failed php -l (or is absent — was the .pkg built with the ports plist entry?)"
        )
        marker_grep = repo_vm.ssh("grep", "-q", SOFTWARE_PANEL_MARKER, SOFTWARE_PAGE_FILE, timeout=30.0)
        assert marker_grep.returncode == 0, (
            f"the {SOFTWARE_PANEL_MARKER!r} marker is absent from the shipped page — "
            f"the .pkg did not carry Phase-4's page"
        )

        # GIVEN: a clean state + knob ON; assert the BEFORE (no cache, no notice for high).
        clear_software_state(repo_vm)
        set_notify_knob(repo_vm, "on")
        assert read_software_cache(repo_vm) == {}, "software cache unexpectedly present before the first check"
        assert count_matching_notices(repo_vm, high) == 0, f"a notice for {high} existed before any check"

        # WHEN/THEN (first check, installed==latest): cache says up to date; NO notice.
        run_update_check_on_box(repo_vm)
        cache = read_software_cache(repo_vm)
        assert cache.get("installed") == low, f"cache installed {cache.get('installed')!r} != {low!r}"
        assert cache.get("latest") == low, f"cache latest {cache.get('latest')!r} != {low!r} (should equal installed)"
        assert cache.get("channel") == "devel", f"cache channel {cache.get('channel')!r} != 'devel'"
        assert count_matching_notices(repo_vm, high) == 0, "a notice fired while installed == latest (no update)"

        # WHEN: publish the HIGHER build into the SAME repo; the check sees a newer latest.
        high_pkg = reversion_pkg(src, high, tmp_path / "high")
        build_guest_repo(repo_vm, UPGRADE_REPO_DIR, [high_pkg])
        run_update_check_on_box(repo_vm)

        # THEN: cache latest advances; EXACTLY ONE notice for the new version.
        cache = read_software_cache(repo_vm)
        assert cache.get("installed") == low, f"installed moved unexpectedly to {cache.get('installed')!r}"
        assert cache.get("latest") == high, f"cache latest did not advance to {high!r}: {cache.get('latest')!r}"
        assert count_matching_notices(repo_vm, high) == 1, "the newer build did not raise exactly one notice"

        # WHEN/THEN (de-dupe): a second check at the SAME latest raises NO second notice.
        run_update_check_on_box(repo_vm)
        assert count_matching_notices(repo_vm, high) == 1, (
            "a second check at the same latest re-notified (de-dupe failed)"
        )

        # WHEN: Update now -> same-channel pkg upgrade pulls the newer build from OUR repo.
        proc = pkg_upgrade(repo_vm)
        combined = proc.stdout + proc.stderr
        assert "Missing dependency" not in combined, f"RUN_DEPENDS did not resolve on upgrade:\n{combined}"

        # THEN: moved to HIGH, still from our repo; re-check shows up-to-date + NO new notice.
        assert pkg_installed_version(repo_vm) == high, (
            f"pkg upgrade did not move {low!r} -> {high!r}; now {pkg_installed_version(repo_vm)!r}"
        )
        assert pkg_repo_origin(repo_vm) == OURS_REPO_NAME, "upgraded build did not come from our repo"
        run_update_check_on_box(repo_vm)
        cache = read_software_cache(repo_vm)
        assert cache.get("installed") == high, f"post-upgrade cache installed {cache.get('installed')!r} != {high!r}"
        assert cache.get("latest") == high, f"post-upgrade cache latest {cache.get('latest')!r} != {high!r}"
        assert count_matching_notices(repo_vm, high) == 1, (
            "a notice re-fired after upgrading to the latest (no new version)"
        )
    finally:
        clear_software_state(repo_vm)
        clear_notify_knob(repo_vm)
        pkg_delete(repo_vm)
        repo_vm.ssh("/bin/rm", "-rf", UPGRADE_REPO_DIR, timeout=60.0)


# --------------------------------------------------------------------------- #
# (f) Channel-correct notify DEFAULT — the OFF (devel) vs ON (nightly) branch, live
# --------------------------------------------------------------------------- #


@pytest.mark.timeout(600)  # install + 2 forged builds + several live checks > the 30s cap.
def test_software_notify_default_is_channel_correct(repo_vm: SmokeVM, tmp_path: Path) -> None:
    """The notify DEFAULT is driven by the CHANNEL, not an always-path (knob unset/'default').

    Pairs the two channel branches so green proves the channel drives the default:
    ``devel`` (the installed channel) defaults OFF -> a newer build raises NO notice;
    ``nightly`` defaults ON -> the same newer-build condition raises ONE notice. The
    nightly *channel* is simulated via the orchestrator's documented ``$io`` seam (a
    nightly ``installed_name`` + an our-repo ``installed_repo`` so the gate still OPENS):
    the nightly repo/package is not built into this hermetic CE image (ADR-18), so the
    CHANNEL-default decision is what is proven end to end (real orchestrator -> real
    file_notice), not a nightly pkg install. Noted as a simulation in the handoff.

    Scenario: a newer build notifies by default ONLY on the nightly channel.
      Background: our build installed from our repo; the notify knob UNSET ('default').

    Given build ``<V>_1`` installed from our repo, knob='default', a clean notice state,
      and a published newer ``<V>_9`` (the asserted BEFORE: no notice for ``<V>_9``),
    When a check runs as the DEVEL channel (the real installed one),
    Then NO notice is raised (devel default is OFF).
    When a check runs as the NIGHTLY channel (same newer-build condition, $io-simulated),
    Then EXACTLY ONE notice is raised (nightly default is ON) — the same condition, the
      opposite outcome, so the difference is the channel default and nothing else.
    """
    pkg = os.environ.get("SMOKE_PKG")
    assert pkg and Path(pkg).is_file(), "SMOKE_PKG not set / not a file"
    src = Path(pkg)
    base_version = read_compact_version(src)
    low = f"{base_version}_1"
    high = f"{base_version}_9"
    devel_msg = "available (devel)"
    nightly_msg = "available (nightly)"

    try:
        # GIVEN: our-repo install, knob 'default', clean notices, a newer build published.
        install_our_build_at(repo_vm, low, src, tmp_path, "low")
        assert pkg_repo_origin(repo_vm) == OURS_REPO_NAME, "build did not come from our repo (gate would be closed)"
        high_pkg = reversion_pkg(src, high, tmp_path / "high")
        build_guest_repo(repo_vm, UPGRADE_REPO_DIR, [high_pkg])
        clear_software_state(repo_vm)
        clear_notify_knob(repo_vm)
        assert count_matching_notices(repo_vm, devel_msg) == 0, "a devel notice existed before the devel check"
        assert count_matching_notices(repo_vm, nightly_msg) == 0, "a nightly notice existed before the nightly check"

        # WHEN/THEN (devel, default OFF): a newer build raises NO notice.
        run_update_check_on_box(repo_vm)
        assert count_matching_notices(repo_vm, devel_msg) == 0, (
            "the devel channel notified by default (its default must be OFF)"
        )

        # WHEN/THEN (nightly, default ON): the SAME newer-build condition raises ONE notice.
        # $io supplies a nightly installed_name (-> channel nightly) + an our-repo
        # installed_repo (gate OPENS) + the installed/latest version gap; the channel
        # default (ON) is the only thing that differs from the devel leg above.
        run_update_check_on_box(
            repo_vm,
            io_overrides={
                "installed_name": "pfSense-pkg-pfBlockerNG-NIGHTLY",
                "installed_repo": OURS_REPO_NAME,
                "installed": low,
                "latest": high,
            },
        )
        assert count_matching_notices(repo_vm, nightly_msg) == 1, (
            "the nightly channel did NOT notify by default (its default must be ON) — "
            "the channel does not drive the default"
        )
    finally:
        clear_software_state(repo_vm)
        clear_notify_knob(repo_vm)
        pkg_delete(repo_vm)
        repo_vm.ssh("/bin/rm", "-rf", UPGRADE_REPO_DIR, timeout=60.0)
