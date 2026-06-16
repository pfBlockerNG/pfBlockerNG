"""ADR-18 — the distinct ``-nightly`` package installs, registers, conflicts, upgrades.

The nightly channel ships a SEPARATE package ``pfSense-pkg-pfBlockerNG-nightly``
(distinct name, built from the new ``-nightly`` port, short ``info.xml <name>``
``pfBlockerNG-nightly`` via the ``${PORTNAME:S/pfSense-pkg-//}`` recipe). This
live-VM flow proves, on a real pfSense CE VM, the three ``pkg`` mechanics the
distinct-name design rests on — the ones the earlier same-name detour could not
settle:

  1. INSTALL + REGISTER + provenance — ``pkg install pfSense-pkg-pfBlockerNG-nightly``
     (no ``-f``) from a hermetic ``file://`` nightly catalog resolves deps, the
     rc.packages POST-INSTALL hook runs the FULL pfBlockerNG setup (NO abort — the
     short ``info.xml`` name is what ``get_package_id`` looks up), ``%R`` is our
     nightly repo, and the source commit rides ``pkg info -A`` (the annotation).
  2. CONFLICT-AND-REPLACE (both directions) — ``-nightly`` and ``-devel`` install
     the SAME ``src/`` paths, so they mutually exclude by FILE OVERLAP (no
     ``conflicts`` manifest key — that crashes CE libpkg). Installing one over the
     other replaces it cleanly; the reverse step replaces back.
  3. MONOTONIC ``pkg upgrade`` — the pkg-safe ``<target>.YYYYMMDD.N`` version orders
     component-wise, so ``pkg upgrade`` walks an installed nightly forward across
     successive builds.

NOT a unit test (the builder/manifest shape is pinned off-box in
``tests/test_build_pkg_portable.py``). Like ``test_repo_install.py`` this validates
DISTRIBUTION + pfSense behaviour and carries the ``repo`` marker (deselected from
``-m smoke``). It REUSES that file's proven harness (the ``smoke_vm`` fixture, the
egress-open wiring, ``build_guest_repo``, ``reversion_pkg``). Needs the booted VM
plus a builder-produced nightly ``.pkg`` (``SMOKE_NIGHTLY_PKG``) and the branch
``-devel`` ``.pkg`` (``SMOKE_PKG``); without either it SKIPS cleanly.

Run: ``gh workflow run smoke.yml -f pytest_marker=repo``.
"""

from __future__ import annotations

import os
import subprocess
import urllib.parse
from collections.abc import Iterator
from pathlib import Path

import pytest

from . import helpers as h
from ._matrix import matrix_abi
from .conftest import SmokeVM
from .test_repo_install import (
    _ensure_egress_open,
    _ssh_check,
    build_guest_repo,
    pin_pages_hosts,
    poll_catalog_served,
    read_compact_version,
    repo_priority,
    reversion_pkg,
)

pytestmark = pytest.mark.repo

NIGHTLY_NAME = "pfSense-pkg-pfBlockerNG-nightly"
DEVEL_NAME = "pfSense-pkg-pfBlockerNG-devel"
NIGHTLY_REPO = "pfblockerng-nightly"  # the %R origin a nightly install reports
DEVEL_REPO = "pfblockerng"  # %R origin of the controlled -devel install (the shared release repo)

SPIKE = "/tmp/pfb_nightly_spike"
NIGHTLY_DIR = f"{SPIKE}/nightly"  # the file:// nightly catalog
DEVEL_DIR = f"{SPIKE}/devel"  # a controlled file:// -devel catalog (for the conflict leg)
CONF = "/usr/local/etc/pkg/repos/pfb_nightly_smoke.conf"

# Phase-5d — live nightly Pages URL check (dispatch-only; gated on SMOKE_NIGHTLY_LIVE_URL).
# Unset -> SKIP (the file:// VM-acceptance above is the always-on proof).
LIVE_NIGHTLY_URL_ENV = "SMOKE_NIGHTLY_LIVE_URL"
DEFAULT_LIVE_NIGHTLY_URL = "https://pfblockerng.github.io/pkg/nightly"
NIGHTLY_LIVE_CONF = "/usr/local/etc/pkg/repos/pfb_nightly_live_smoke.conf"

# The rc.packages install hook aborts with one of these when the registration name
# is wrong (the short-name regression test_install_hook.py guards); the nightly must
# show NEITHER — its hook runs the full setup. Asserted on the raw install output.
_ABORT = ("is not installed", "Installation aborted", "Failed to install package")
_HOOK_OK = ("Executing custom_php_install_command", "Menu items")

# Three ascending pkg-safe nightly versions (<target>.YYYYMMDD.N) for the upgrade
# walk; `.N` is the same-day build counter, so .1 < .2 < .3 orders component-wise.
V1 = "3.2.16.20260606.1"
V2 = "3.2.16.20260606.2"
V3 = "3.2.16.20260606.3"


# --------------------------------------------------------------------------- #
# Conf + pkg helpers (by NAME — the release helpers in test_repo_install are
# hardcoded to the -devel name; the nightly flow drives two distinct names).
# --------------------------------------------------------------------------- #


def _stanza(name: str, directory: str, priority: int) -> str:
    return (
        f"{name}: {{\n"
        f'  url: "file://{directory}",\n'
        "  signature_type: none,\n"
        "  enabled: yes,\n"
        f"  priority: {priority}\n"
        "}\n"
    )


def write_conf(vm: SmokeVM, stanzas: list[tuple[str, str, int]]) -> None:
    """Write a NONE-signed ``file://`` repo conf naming each (repo, dir, priority)."""
    conf = "".join(_stanza(n, d, p) for n, d, p in stanzas)
    r = subprocess.run(vm.ssh_argv("tee", CONF), input=conf, capture_output=True, text=True, timeout=60.0, check=False)
    if r.returncode != 0:
        raise RuntimeError(f"write_conf failed: rc={r.returncode} {r.stderr!r}")


def pkg_present(vm: SmokeVM, name: str, *, timeout: float = 60.0) -> bool:
    return vm.ssh("pkg", "query", "%n", name, timeout=timeout).returncode == 0


def pkg_q(vm: SmokeVM, fmt: str, name: str, *, timeout: float = 60.0) -> str:
    """``pkg query <fmt> <name>`` (e.g. ``%v``/``%R``) — empty string if absent."""
    r = vm.ssh("pkg", "query", fmt, name, timeout=timeout)
    return r.stdout.strip() if r.returncode == 0 else ""


def pkg_annotation(vm: SmokeVM, name: str, key: str, *, timeout: float = 60.0) -> str | None:
    """The value of annotation ``key`` from ``pkg info -A`` (the provenance oracle)."""
    out = _ssh_check(vm, "pkg", "info", "-A", name, timeout=timeout).stdout
    for line in out.splitlines():
        # `pkg info -A` prints `  <key>         : <value>`.
        k, sep, v = line.partition(":")
        if sep and k.strip() == key:
            return v.strip()
    return None


def pkg_update(vm: SmokeVM, *, timeout: float = 240.0) -> None:
    _ssh_check(vm, "env", "ASSUME_ALWAYS_YES=yes", "pkg", "update", "-f", timeout=timeout)


def pkg_install(vm: SmokeVM, name: str, *, timeout: float = 600.0) -> str:
    """``pkg install -y <name>`` across all enabled repos (no ``-r``/``-f``); return its output.

    Output combines stdout+stderr so the caller can read the rc.packages POST-INSTALL
    hook text (the install-hook success oracle) and any "Missing dependency" line.
    """
    r = vm.ssh("env", "ASSUME_ALWAYS_YES=yes", "pkg", "install", "-y", name, timeout=timeout)
    if r.returncode != 0:
        raise RuntimeError(f"pkg install {name} failed: rc={r.returncode}\n{r.stdout}\n{r.stderr}")
    return r.stdout + r.stderr


def pkg_upgrade(vm: SmokeVM, name: str, *, timeout: float = 600.0) -> str:
    r = vm.ssh("env", "ASSUME_ALWAYS_YES=yes", "pkg", "upgrade", "-y", name, timeout=timeout)
    if r.returncode != 0:
        raise RuntimeError(f"pkg upgrade {name} failed: rc={r.returncode}\n{r.stdout}\n{r.stderr}")
    return r.stdout + r.stderr


def pkg_delete(vm: SmokeVM, name: str, *, timeout: float = 300.0) -> None:
    vm.ssh("env", "ASSUME_ALWAYS_YES=yes", "pkg", "delete", "-y", name, timeout=timeout)


def assert_hook_succeeded(install_out: str, *, name: str) -> None:
    """The rc.packages POST-INSTALL hook ran the FULL setup — NO abort phrase, markers present."""
    aborted = [p for p in _ABORT if p in install_out]
    assert not aborted, f"{name} rc.packages hook ABORTED ({aborted}):\n{install_out}"
    ran = [p for p in _HOOK_OK if p in install_out]
    assert ran, f"{name} install hook did not run the full pfBlockerNG setup:\n{install_out}"


# --------------------------------------------------------------------------- #
# Module fixture — a hermetic file:// nightly (+ controlled -devel) catalog.
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def nightly_vm(smoke_vm: SmokeVM) -> Iterator[SmokeVM]:
    """The booted VM with a hermetic ``file://`` nightly catalog (+ a controlled -devel one).

    Builds two NONE-signed ``file://`` catalogs from the handed-in ``.pkg`` files
    (the builder-produced nightly via ``SMOKE_NIGHTLY_PKG``; the branch ``-devel``
    via ``SMOKE_PKG`` for the conflict leg) and writes one conf naming both repos a
    clear margin ABOVE the Netgate ``pfSense`` repo. Egress is OPEN (the ADR-17 repo
    model); deps resolve from the baked image db, so ``pkg install`` needs no fetch.
    Leaves the VM clean in ``finally``.
    """
    nightly = os.environ.get("SMOKE_NIGHTLY_PKG")
    devel = os.environ.get("SMOKE_PKG")
    if not nightly or not Path(nightly).is_file():
        pytest.skip("SMOKE_NIGHTLY_PKG not set / not a file — no built -nightly .pkg")
    if not devel or not Path(devel).is_file():
        pytest.skip("SMOKE_PKG not set / not a file — no branch -devel .pkg")
    assert nightly and devel  # for the type-checker (skip above is NoReturn)
    _ensure_egress_open()
    prio = repo_priority(smoke_vm, "pfSense") + 100
    build_guest_repo(smoke_vm, NIGHTLY_DIR, [Path(nightly)])
    build_guest_repo(smoke_vm, DEVEL_DIR, [Path(devel)])
    write_conf(smoke_vm, [(NIGHTLY_REPO, NIGHTLY_DIR, prio), (DEVEL_REPO, DEVEL_DIR, prio)])
    pkg_update(smoke_vm)
    try:
        yield smoke_vm
    finally:
        pkg_delete(smoke_vm, NIGHTLY_NAME)
        pkg_delete(smoke_vm, DEVEL_NAME)
        smoke_vm.ssh("/bin/rm", "-rf", SPIKE, timeout=60.0)
        smoke_vm.ssh("/bin/rm", "-f", CONF, timeout=60.0)
        h.collect_host_diagnostics(smoke_vm)


def _ensure_absent(vm: SmokeVM) -> None:
    """Both packages removed, so each test starts from a known clean slate."""
    pkg_delete(vm, NIGHTLY_NAME)
    pkg_delete(vm, DEVEL_NAME)


# --------------------------------------------------------------------------- #
# The kill-gate tests
# --------------------------------------------------------------------------- #


@pytest.mark.timeout(900)
def test_nightly_installs_registers_and_carries_commit(nightly_vm: SmokeVM) -> None:
    """The nightly installs (no -f), its rc.packages hook SUCCEEDS, and it carries provenance.

    Scenario: a fresh install of the distinct ``-nightly`` package.
      Given the nightly catalog and the package ABSENT,
      When ``pkg install -y pfSense-pkg-pfBlockerNG-nightly`` runs (NO -f),
      Then the rc.packages POST-INSTALL hook runs the FULL pfBlockerNG setup (no
        abort — the short info.xml name resolves), ``%R`` is our nightly repo, ``%v``
        is the nightly version, and ``pkg info -A`` surfaces the ``commit`` annotation.
    """
    vm = nightly_vm
    _ensure_absent(vm)
    assert not pkg_present(vm, NIGHTLY_NAME), "precondition: -nightly absent"

    out = pkg_install(vm, NIGHTLY_NAME)

    assert_hook_succeeded(out, name=NIGHTLY_NAME)
    assert pkg_present(vm, NIGHTLY_NAME)
    assert pkg_q(vm, "%R", NIGHTLY_NAME) == NIGHTLY_REPO, f"%R should be our nightly repo:\n{out}"
    assert pkg_q(vm, "%v", NIGHTLY_NAME), "installed nightly has a version"
    commit = pkg_annotation(vm, NIGHTLY_NAME, "commit")
    assert commit, f"the source commit must ride pkg info -A (provenance); got {commit!r}"


@pytest.mark.timeout(1200)
def test_nightly_conflicts_and_replaces_devel_both_directions(nightly_vm: SmokeVM) -> None:
    """-nightly and -devel mutually exclude by FILE OVERLAP — each replaces the other cleanly.

    Scenario: switching channels in place.
      Given -devel installed from the controlled devel repo (and -nightly absent),
      When ``pkg install -y …-nightly`` runs,
      Then it is a conflict-and-replace: -nightly is now installed (%R our nightly
        repo) and -devel is GONE — proven a transition by asserting -devel present
        BEFORE. When -devel is then installed again, -nightly is GONE in turn.
    """
    vm = nightly_vm
    _ensure_absent(vm)

    # Given: -devel installed, -nightly absent.
    pkg_install(vm, DEVEL_NAME)
    assert pkg_present(vm, DEVEL_NAME) and not pkg_present(vm, NIGHTLY_NAME), "before: only -devel"
    assert pkg_q(vm, "%R", DEVEL_NAME) == DEVEL_REPO

    # When: install -nightly over it → file-overlap replace.
    out = pkg_install(vm, NIGHTLY_NAME)
    assert_hook_succeeded(out, name=NIGHTLY_NAME)
    # Then: -nightly present, -devel replaced (gone).
    assert pkg_present(vm, NIGHTLY_NAME), f"-nightly should be installed:\n{out}"
    assert not pkg_present(vm, DEVEL_NAME), f"-devel should have been REPLACED by the file overlap:\n{out}"
    assert pkg_q(vm, "%R", NIGHTLY_NAME) == NIGHTLY_REPO

    # And back: install -devel → -nightly replaced in turn (the reverse direction).
    out_back = pkg_install(vm, DEVEL_NAME)
    assert_hook_succeeded(out_back, name=DEVEL_NAME)
    assert pkg_present(vm, DEVEL_NAME), f"-devel should be reinstalled:\n{out_back}"
    assert not pkg_present(vm, NIGHTLY_NAME), f"-nightly should have been REPLACED back:\n{out_back}"


@pytest.mark.timeout(1200)
def test_nightly_pkg_upgrade_is_monotonic(nightly_vm: SmokeVM, tmp_path: Path) -> None:
    """``pkg upgrade`` walks an installed nightly forward across ascending builds.

    Scenario: the nightly version scheme orders.
      Given the nightly catalog at V1 and -nightly installed at V1,
      When the catalog is rebuilt at V2 (then V3) and ``pkg upgrade`` runs,
      Then the installed ``%v`` MOVES V1 -> V2 -> V3 — three real before != after
        transitions, proving ``<target>.YYYYMMDD.N`` is monotonically comparable.
    """
    vm = nightly_vm
    _ensure_absent(vm)
    nightly_src = Path(os.environ["SMOKE_NIGHTLY_PKG"])
    base = read_compact_version(nightly_src)
    assert base, "the built nightly .pkg must carry a version to re-version from"

    prio = repo_priority(vm, "pfSense") + 100

    def _serve(version: str) -> None:
        pkg = reversion_pkg(nightly_src, version, tmp_path / version)
        build_guest_repo(vm, NIGHTLY_DIR, [pkg])
        # Keep the controlled -devel repo in the conf so the box state is unchanged
        # except the nightly catalog version.
        write_conf(vm, [(NIGHTLY_REPO, NIGHTLY_DIR, prio), (DEVEL_REPO, DEVEL_DIR, prio)])
        pkg_update(vm)

    # Given: catalog at V1, install -> %v == V1.
    _serve(V1)
    pkg_install(vm, NIGHTLY_NAME)
    assert pkg_q(vm, "%v", NIGHTLY_NAME) == V1, "before: installed nightly at V1"

    # When/Then: rebuild at V2, upgrade moves it (before != after).
    _serve(V2)
    pkg_upgrade(vm, NIGHTLY_NAME)
    assert pkg_q(vm, "%v", NIGHTLY_NAME) == V2, "pkg upgrade must move V1 -> V2"

    # And again V2 -> V3.
    _serve(V3)
    pkg_upgrade(vm, NIGHTLY_NAME)
    assert pkg_q(vm, "%v", NIGHTLY_NAME) == V3, "pkg upgrade must move V2 -> V3"


# --------------------------------------------------------------------------- #
# Phase-5d — live nightly Pages URL (dispatch-only; gated on SMOKE_NIGHTLY_LIVE_URL)
# --------------------------------------------------------------------------- #


def _live_nightly_url() -> str | None:
    """The live nightly Pages base to test against, or None to SKIP.

    Gated on ``SMOKE_NIGHTLY_LIVE_URL``: set it to the deployed nightly base
    (e.g. ``https://pfblockerng.github.io/pkg/nightly``) after a nightly publish
    dispatch; leave it unset and the test SKIPS.  A bare ``1``/``true`` selects
    the default base.
    """
    val = os.environ.get(LIVE_NIGHTLY_URL_ENV)
    if not val:
        return None
    if val.strip().lower() in {"1", "true", "yes", "on"}:
        return DEFAULT_LIVE_NIGHTLY_URL
    return val.rstrip("/")


@pytest.mark.timeout(900)
def test_install_from_live_nightly_url(smoke_vm: SmokeVM) -> None:
    """PHASE-5d LIVE NIGHTLY URL: a real pfSense box installs -nightly from the
    deployed nightly Pages catalog over its public HTTPS URL (no ``-f``).

    DISPATCH-ONLY + GATED on ``SMOKE_NIGHTLY_LIVE_URL`` (unset -> SKIP). The
    always-on proof is the ``file://`` VM-acceptance above; this exercises the
    REAL transport the nightly publish pipeline serves, so it can only run after a
    nightly publish dispatch has deployed the catalog.

    Given the nightly publish pipeline has DEPLOYED the catalog to Pages (runner-side
      backstop: ``<base>/<ABI>/meta.conf`` + ``packagesite.pkg`` serve 200), the guest
      has the Pages IPs pinned for the host (its DNS is sandboxed), the package is
      ABSENT, and our nightly conf points at the live ``nightly/${ABI}`` URL above the
      Netgate ``pfSense`` repo,
    When ``pkg update`` reads the live nightly catalog and ``pkg install -y`` runs
      (NO ``-r``, NO ``-f``),
    Then the install comes from our nightly repo (``pkg query %R`` ==
      ``pfblockerng-nightly``) with deps resolved and the .pkg checksum validated —
      the deployed nightly Pages catalog is real + installable over HTTPS.
    """
    base_url = _live_nightly_url()
    if base_url is None:
        pytest.skip(
            f"{LIVE_NIGHTLY_URL_ENV} not set — live nightly URL check is dispatch-only (file:// proof always runs)"
        )
    assert base_url is not None  # for the type-checker

    host = urllib.parse.urlparse(base_url).hostname
    assert host, f"could not parse a host from {base_url!r}"

    # BACKSTOP: prove the deploy actually serves the nightly catalog from the runner
    # first (independent of the guest) — polls through first-deploy / DNS / cert lag.
    poll_catalog_served(base_url, matrix_abi())

    _ensure_egress_open()

    # GIVEN: Pages IPs pinned (guest DNS is sandboxed), nightly package absent, our
    # nightly conf at the live URL above the Netgate pfSense repo.
    pin_pages_hosts(smoke_vm, host)
    pfsense_prio = repo_priority(smoke_vm, "pfSense")
    pkg_delete(smoke_vm, NIGHTLY_NAME)

    # Write the production nightly conf: pfblockerng-nightly, HTTPS live URL, NONE-signed.
    # ${ABI} is a pkg(8) variable — must survive in the file as-is (not shell-expanded).
    conf = (
        f"{NIGHTLY_REPO}: {{\n"
        f'  url: "{base_url}/${{ABI}}",\n'
        "  mirror_type: none,\n"
        "  signature_type: none,\n"
        f"  priority: {pfsense_prio + 100},\n"
        "  enabled: yes\n"
        "}\n"
    )
    r = subprocess.run(
        smoke_vm.ssh_argv("tee", NIGHTLY_LIVE_CONF),
        input=conf,
        capture_output=True,
        text=True,
        timeout=60.0,
        check=False,
    )
    if r.returncode != 0:
        raise RuntimeError(f"write nightly live conf failed: rc={r.returncode} {r.stderr!r}")

    try:
        # WHEN: pkg update reads the live nightly catalog.
        pkg_update(smoke_vm)
        assert not pkg_present(smoke_vm, NIGHTLY_NAME), "precondition: -nightly absent before live install"

        out = pkg_install(smoke_vm, NIGHTLY_NAME)

        # THEN: installed from our nightly repo, deps resolved, checksum validated.
        assert "Missing dependency" not in out, f"deps did not resolve from the live nightly catalog:\n{out}"
        origin = pkg_q(smoke_vm, "%R", NIGHTLY_NAME)
        assert origin == NIGHTLY_REPO, f"installed from {origin!r}, expected our nightly repo {NIGHTLY_REPO!r}"
    finally:
        pkg_delete(smoke_vm, NIGHTLY_NAME)
        smoke_vm.ssh("/bin/rm", "-f", NIGHTLY_LIVE_CONF, timeout=60.0)
