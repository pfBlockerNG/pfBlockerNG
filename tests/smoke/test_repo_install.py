"""ADR-17 — the release -> repository -> install flow (DISTINCT from the smoke suite).

This is the ADR-01-style cheap falsification of ADR-17's core premise (§1 "Premise
to falsify", §6 Phase 1, §7 reject criteria): prove on the live ADR-04 pfSense CE
VM that a box installs pfBlockerNG from a self-hosted, NONE-signed third-party
`pkg` repository (no `pkg add -f`), the installed files land where the manifest
says, and cross-repo precedence favours our build over the REAL Netgate repo.

NOT A SMOKE TEST. This flow validates *distribution* (does our repo install + land
its files + win precedence), a separate concern from the ADR-04 smoke suite that
validates pfBlockerNG's *runtime behaviour* (DNSBL blocking, etc.). It carries its
OWN marker `repo` — NOT `smoke` — so `pytest -m smoke` never selects it; it is
dispatched on its own (`repo-install.yml` -> `-m repo`). It REUSES the smoke
harness (the `smoke_vm` fixture, `helpers`, the VM boot wiring) but is never
conflated with the smoke matrix, and deliberately does NOT re-probe runtime
behaviour (already covered there).

PRECEDENCE MODEL (proven on the VM, correcting ADR §1 Context 3): repository
PRIORITY dominates version — a higher-priority repo wins even with a LOWER version
(observed: a repo at priority 200 / version _1 beat ours at priority 99 / version
_9). So our repo simply needs a `priority:` above any competitor and it wins
regardless of version. The competitor here is a controlled `file://` `netgate-decoy`
repo serving the SAME package (a deterministic stand-in: the real Netgate `pfSense`
repo does NOT offer `-devel` in this hermetic CE image, so it cannot serve as the
competing provider). The two precedence tests flip ours/decoy priority to pin both
directions; both are set ABOVE the real `pfSense` repo so it never interferes.

EGRESS IS OPEN for this flow (unlike the hermetic smoke cases): the real Netgate
repos are LEFT ENABLED and reachable (`pkg update` must not rc=1 on them). The repo
flow never enters a CaseContext (the only caller of `helpers.block_egress`), and the
fixture forces egress open (`_ensure_egress_open`) so the flow is immune to any
residual block. The real `pfSense` repo simply loses on priority.

HOW (throwaway spike — the reusable `scripts/build-repo.sh` generator is Phase 2,
NOT built here):

  * The branch `.pkg` is built by the harness and handed in via `SMOKE_PKG`
    (`scripts/build-pkg-portable.py` on a Linux runner — the VM's exact ABI:
    `FreeBSD:15:amd64` / php83 / py311). We do NOT re-invoke the builder, and do
    NOT re-version it: priority (not version) is the precedence lever, so the real
    release `.pkg` is published as-is.
  * On the guest, the guest's OWN `pkg repo` (libpkg) builds the catalog from that
    one `.pkg`; served via an on-box `file://` URL — the acceptable hermetic
    transport (no second HTTP server, a CLAUDE.md constraint). Whether the
    Pages-style HTTP catalog is accepted is Phase 2/3's concern; the premise (does
    pfSense honor a NONE-signed third-party repo for install + precedence) is
    orthogonal to the transport.
  * A repo conf at `/usr/local/etc/pkg/repos/pfblockerng-devel.conf`
    (`signature_type: none`, `enabled: yes`, `priority:` above/below the pfSense
    repo per case), then `pkg update` + `pkg install -y` with NO `-f`.

WHAT IS ASSERTED (transition + branch coverage, via EFFECTIVE state — never an
exit code alone): the package is ABSENT before; AFTER a from-our-repo install it is
registered, its repo origin (`pkg query '%R'`) is OURS, RUN_DEPENDS resolved (no
"Missing dependency"), and EVERY file the package registers (`pkg info -l`) is
present on-box; and cross-repo precedence picks the HIGHER-priority repo in BOTH
directions (ours higher ⇒ ours; decoy higher ⇒ the decoy — so "ours wins" is
provably priority-driven, not an always-ours artefact).

DESELECTED from the default `python -m pytest` (`--ignore=tests/smoke` in
pyproject.toml — this file lives under `tests/smoke/` only to reuse the fixture
and helpers). Run only via its own dispatch::

    python -m pytest tests/smoke -m repo --override-ini="addopts="

Needs the booted `smoke_vm` fixture, the branch `.pkg` (`SMOKE_PKG`), and the
smoke deps; without them it skips cleanly.
"""

from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

from . import helpers as h
from .conftest import SmokeVM

pytestmark = pytest.mark.repo

PKG_NAME = "pfSense-pkg-pfBlockerNG-devel"

# Our repo conf on the guest + the served catalog root. The conf name follows the
# CLAUDE.md "match the surrounding pattern" rule: pfSense's own conf is
# `pfSense.conf` under the SAME dir; ours is the channel-named sibling Phase 4 will
# write for real (`add-repo.sh`).
REPO_CONF = "/usr/local/etc/pkg/repos/pfblockerng-devel.conf"
GUEST_SPIKE_DIR = "/tmp/pfb_repo_spike"
OURS_REPO_DIR = f"{GUEST_SPIKE_DIR}/ours"
DECOY_REPO_DIR = f"{GUEST_SPIKE_DIR}/decoy"
OURS_REPO_NAME = "pfblockerng-devel"  # the %R origin a from-our-repo install reports
DECOY_REPO_NAME = "netgate-decoy"  # a controlled file:// stand-in for a competing repo
NETGATE_REPO_NAME = "pfSense"  # the real base-system Netgate repo (left enabled; loses on priority)
GUEST_FILE_LIST = f"{GUEST_SPIKE_DIR}/installed_files.txt"


# --------------------------------------------------------------------------- #
# Egress — this flow needs the REAL Netgate repo reachable
# --------------------------------------------------------------------------- #


def _ensure_egress_open() -> None:
    """Force the runner's egress OPEN for this flow (idempotent; best-effort).

    This flow tests cross-repo precedence against the REAL Netgate `pfSense` repo,
    so it must NOT run under the smoke suite's hermetic egress block. The repo flow
    never enters a CaseContext (the only caller of `helpers.block_egress`), so
    egress is open by default — but force it explicitly so the flow is immune to any
    residual OUTPUT DROP from a prior test sharing the runner. Mirrors
    `helpers.unblock_egress` but UNCONDITIONAL (no SMOKE_BLOCK_EGRESS gate). On a
    local dev box without sudo/iptables this is a harmless no-op (`check=False`).
    """
    for argv in (
        ["sudo", "iptables", "-P", "OUTPUT", "ACCEPT"],
        ["sudo", "iptables", "-F", "OUTPUT"],
    ):
        subprocess.run(argv, check=False, timeout=30)


# --------------------------------------------------------------------------- #
# On-guest catalog build + repo conf + pkg ops (over SSH)
# --------------------------------------------------------------------------- #


def _scp_to_guest(vm: SmokeVM, local: Path, remote: str, *, timeout: float = 120.0) -> None:
    """Copy a local file to the guest via ``scp`` (mirrors install-pkg.sh)."""
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
        str(local),
        f"{vm.ssh_target}:{remote}",
    ]
    result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"scp {local} -> {remote} failed: rc={result.returncode} {result.stderr!r}")


def _ssh_check(vm: SmokeVM, *remote: str, timeout: float = 180.0) -> subprocess.CompletedProcess[str]:
    """Run a guest command over SSH and raise (with output) on a non-zero exit."""
    result = vm.ssh(*remote, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(
            f"guest cmd {remote!r} failed: rc={result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def build_guest_repo(vm: SmokeVM, repo_dir: str, pkg_files: list[Path]) -> None:
    """Lay ``pkg_files`` into a fresh ``repo_dir`` on the guest and ``pkg repo`` it.

    Uses the guest's OWN libpkg (``pkg repo``) — the same catalog op Phase 2 will
    run on Linux — to turn the dir of ``.pkg`` files into a real catalog
    (``meta.conf`` / ``packagesite.pkg`` / ``data.pkg``). Built with NO signing,
    so the served catalog is NONE-signed (the trust model under test).
    """
    _ssh_check(vm, "/bin/rm", "-rf", repo_dir)
    _ssh_check(vm, "/bin/mkdir", "-p", repo_dir)
    for pkg in pkg_files:
        _scp_to_guest(vm, pkg, f"{repo_dir}/{pkg.name}")
    # `pkg repo <dir>` with no key argument => an unsigned catalog.
    _ssh_check(vm, "env", "ASSUME_ALWAYS_YES=yes", "pkg", "repo", repo_dir)


def _repo_block(name: str, directory: str, priority: int) -> str:
    """One NONE-signed ``file://`` repo stanza for the pkg repo conf."""
    return (
        f"{name}: {{\n"
        f'  url: "file://{directory}",\n'
        "  signature_type: none,\n"
        "  enabled: yes,\n"
        f"  priority: {priority}\n"
        "}\n"
    )


def write_repo_conf(
    vm: SmokeVM,
    ours_dir: str,
    *,
    ours_priority: int,
    decoy_dir: str | None = None,
    decoy_priority: int = 0,
) -> None:
    """Write our NONE-signed repo conf on the guest (ours, plus an optional decoy).

    Declares OUR repo (`pfblockerng-devel`) and — for the precedence cases — a
    controlled `file://` `netgate-decoy` repo serving the SAME package, so the
    priority outcome between two genuine providers is deterministic. The base-system
    Netgate repos (`pfSense` / `pfSense-core`) are LEFT ENABLED and untouched (this
    flow runs with egress open so they are reachable); callers set ours/decoy
    priorities a clear margin ABOVE the pfSense repo (see ``repo_priority``) so the
    real Netgate repo never wins regardless of what it offers. ``signature_type:
    none`` (pfSense honors per-repo ``none``; trust = the local ``file://`` path
    here, HTTPS in production).
    """
    conf = _repo_block(OURS_REPO_NAME, ours_dir, ours_priority)
    if decoy_dir is not None:
        conf += _repo_block(DECOY_REPO_NAME, decoy_dir, decoy_priority)
    result = subprocess.run(
        vm.ssh_argv("tee", REPO_CONF),
        input=conf,
        capture_output=True,
        text=True,
        timeout=60.0,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"write_repo_conf failed: rc={result.returncode} {result.stderr!r}")


def repo_priority(vm: SmokeVM, name: str, *, timeout: float = 60.0) -> int:
    """The EFFECTIVE ``priority:`` of repo ``name`` (``pkg -vv``); 0 if unset/absent.

    Reads the tool's own merged config (resolves every ``*.conf``), not a single
    file — the CLAUDE.md "assert effective state" rule. Used to set OUR repo's
    priority a clear margin ABOVE / BELOW the base pfSense repo, so the precedence
    outcome is deterministic regardless of what priority Netgate happens to ship.
    """
    out = _ssh_check(vm, "pkg", "-vv", timeout=timeout).stdout
    # Each repo is `  <name>: { ... priority : N, ... }`; match the named block
    # (non-greedy to its first closing brace) then the priority inside it. The
    # literal colon means `pfSense:` does not match inside `pfSense-core:`.
    block = re.search(rf"(?ms)^\s*{re.escape(name)}:\s*\{{(.*?)\}}", out)
    if not block:
        return 0
    pr = re.search(r"priority\s*:\s*(-?\d+)", block.group(1))
    return int(pr.group(1)) if pr else 0


def pkg_update(vm: SmokeVM, *, timeout: float = 240.0) -> None:
    """``pkg update -f`` so the freshly-written catalog is re-read.

    ``-f`` forces a re-fetch even when the catalog mtime/etag looks unchanged. With
    egress OPEN, this refreshes ALL enabled repos — our reachable ``file://`` repo
    AND the real Netgate ``pfSense`` / ``pfSense-core`` repos — and exits ``rc=0``.
    A clean update of our repo is itself evidence pfSense accepts the unsigned
    third-party repo.
    """
    _ssh_check(vm, "env", "ASSUME_ALWAYS_YES=yes", "pkg", "update", "-f", timeout=timeout)


def pkg_installed_version(vm: SmokeVM, *, timeout: float = 60.0) -> str | None:
    """The installed ``%v`` of the package, or ``None`` if absent (the before/after oracle)."""
    result = vm.ssh("pkg", "query", "%v", PKG_NAME, timeout=timeout)
    return result.stdout.strip() if result.returncode == 0 and result.stdout.strip() else None


def pkg_repo_origin(vm: SmokeVM, *, timeout: float = 60.0) -> str:
    """The repo ``%R`` the installed package was fetched from (the precedence oracle)."""
    return _ssh_check(vm, "pkg", "query", "%R", PKG_NAME, timeout=timeout).stdout.strip()


def pkg_install_from_repo(vm: SmokeVM, *, timeout: float = 600.0) -> subprocess.CompletedProcess[str]:
    """``pkg install -y <name>`` across ALL enabled repos — NO ``-r``, NO ``-f``.

    This is the exact shape ``pkg_install()`` uses (ADR-17 §1 Context 3): resolve
    the name over every enabled repo and install the winner. The VM proved repo
    PRIORITY decides the winner (a higher-priority repo wins even at a lower
    version). Returns the completed process so the caller can read the "Missing
    dependency" line (deps-resolved evidence) off stderr/stdout.
    """
    result = vm.ssh("env", "ASSUME_ALWAYS_YES=yes", "pkg", "install", "-y", PKG_NAME, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(
            f"pkg install {PKG_NAME} failed: rc={result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def pkg_delete(vm: SmokeVM, *, timeout: float = 300.0) -> None:
    """Remove the package if present (between cases + final cleanup)."""
    vm.ssh("env", "ASSUME_ALWAYS_YES=yes", "pkg", "delete", "-y", PKG_NAME, timeout=timeout)


# --------------------------------------------------------------------------- #
# Files-present check — the install really WROTE the payload (distribution test)
# --------------------------------------------------------------------------- #


def assert_all_pkg_files_present(vm: SmokeVM, *, timeout: float = 120.0) -> int:
    """Assert EVERY file the installed package registers is present on-box.

    The distribution concern this flow exists for: ``pkg info -l <pkg>`` lists the
    files pkg recorded from the package manifest at install; we confirm each one
    actually EXISTS on disk — the repo install really wrote the payload, not merely
    registered metadata. The path list is parsed here, staged to a guest temp file,
    and existence-checked in ONE on-box pass. Returns the file count for the log.
    """
    listing = _ssh_check(vm, "pkg", "info", "-l", PKG_NAME, timeout=timeout).stdout
    # `pkg info -l` prints a `<pkg>-<ver>:` header, then indented absolute paths.
    paths = [ln.strip() for ln in listing.splitlines() if ln.startswith((" ", "\t")) and ln.strip().startswith("/")]
    assert paths, f"pkg info -l {PKG_NAME} listed no files — nothing was installed"

    staged = subprocess.run(
        vm.ssh_argv("tee", GUEST_FILE_LIST),
        input="\n".join(paths) + "\n",
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if staged.returncode != 0:
        raise RuntimeError(f"staging the installed-file list failed: rc={staged.returncode} {staged.stderr!r}")

    # Pipe the existence-sweep SCRIPT via STDIN to a remote `/bin/sh`. A complex
    # `/bin/sh -c '<script>'` argument is re-tokenised by ssh's remote login shell
    # (-> `sh: Syntax error: "do" unexpected`); reading the script from stdin avoids
    # all quoting. The script reads the staged list with `IFS= read -r` (any path,
    # verbatim) and prints those that are missing. GUEST_FILE_LIST is a fixed path.
    script = f'while IFS= read -r f; do [ -e "$f" ] || echo "$f"; done < {GUEST_FILE_LIST}\n'
    swept = subprocess.run(
        vm.ssh_argv("/bin/sh"),
        input=script,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if swept.returncode != 0:
        raise RuntimeError(
            f"files-present sweep failed: rc={swept.returncode}\nstdout:\n{swept.stdout}\nstderr:\n{swept.stderr}"
        )
    missing = [ln for ln in swept.stdout.splitlines() if ln.strip()]
    assert not missing, f"{len(missing)} registered file(s) absent on-box (first 10): {missing[:10]}"
    return len(paths)


# --------------------------------------------------------------------------- #
# Module fixture — deploy NOTHING; the test installs from the repo itself
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def repo_vm(smoke_vm: SmokeVM) -> Iterator[SmokeVM]:
    """The booted VM with our NONE-signed ``file://`` repo staged from the branch ``.pkg``.

    Unlike the smoke modules this does NOT ``deploy()`` (install-pkg.sh / ``pkg
    add``): the whole point is to install from our REPO. It forces egress OPEN (this
    flow needs the real Netgate repo reachable — see ``_ensure_egress_open``), stages
    the branch ``.pkg`` into our repo dir and builds the catalog once, and tears
    everything down in ``finally`` so the VM is left clean. No re-versioning / decoy:
    PRIORITY is the precedence lever (the VM proved repo priority dominates version)
    and the real Netgate ``pfSense`` repo is the competitor.
    """
    pkg = os.environ.get("SMOKE_PKG")
    if not pkg or not Path(pkg).is_file():
        pytest.skip("SMOKE_PKG not set / not a file — no built .pkg to publish")
    assert pkg  # for the type-checker: pytest.skip above is NoReturn
    src = Path(pkg)
    _ensure_egress_open()
    # Build BOTH catalogs from the same branch .pkg: ours and a controlled decoy that
    # serves the identical package, so the precedence cases compare two genuine
    # providers and the winner is decided purely by `priority:`.
    build_guest_repo(smoke_vm, OURS_REPO_DIR, [src])
    build_guest_repo(smoke_vm, DECOY_REPO_DIR, [src])
    try:
        yield smoke_vm
    finally:
        pkg_delete(smoke_vm)
        smoke_vm.ssh("/bin/rm", "-rf", GUEST_SPIKE_DIR, timeout=60.0)
        smoke_vm.ssh("/bin/rm", "-f", REPO_CONF, timeout=60.0)
        h.collect_host_diagnostics(smoke_vm)


# --------------------------------------------------------------------------- #
# The kill-gate tests
# --------------------------------------------------------------------------- #


@pytest.mark.timeout(600)  # pkg update + install + an on-box files-present sweep > the 30s cap.
def test_install_from_our_repo_lands_all_files(repo_vm: SmokeVM) -> None:
    """KILL-GATE: a NONE-signed third-party repo install (no ``-f``) resolves deps,
    reports OUR repo as origin, and LANDS EVERY FILE.

    Our repo is enabled at a priority above the real Netgate ``pfSense`` repo (which
    is left enabled, egress open), so ``pkg install`` — resolving across all repos
    with NO ``-r`` — picks ours.

    Given the package ABSENT (``pkg query %v`` fails),
    When ``pkg install -y pfSense-pkg-pfBlockerNG-devel`` runs (NO ``-r``, NO ``-f``),
    Then it installs from OUR repo (``pkg query %R`` == ``pfblockerng-devel``), with
      no "Missing dependency" (RUN_DEPENDS resolved), AND every file the package
      registers (``pkg info -l``) is present on-box (> 50) — the install really wrote
      the payload. Runtime behaviour is the smoke suite's job, not re-probed here.
    """
    pfsense_prio = repo_priority(repo_vm, NETGATE_REPO_NAME)

    # GIVEN: a clean before-state — package absent; ours enabled ABOVE pfSense.
    pkg_delete(repo_vm)
    write_repo_conf(repo_vm, OURS_REPO_DIR, ours_priority=pfsense_prio + 100)
    pkg_update(repo_vm)
    assert pkg_installed_version(repo_vm) is None, f"{PKG_NAME} unexpectedly present before the repo install"

    # WHEN: install across ALL enabled repos, no -r/-f.
    proc = pkg_install_from_repo(repo_vm)

    # THEN: installed from our repo; deps resolved; every registered file landed.
    combined = proc.stdout + proc.stderr
    assert "Missing dependency" not in combined, f"RUN_DEPENDS did not resolve from the repos:\n{combined}"
    origin = pkg_repo_origin(repo_vm)
    assert origin == OURS_REPO_NAME, f"installed from {origin!r}, expected our repo {OURS_REPO_NAME!r}"
    file_count = assert_all_pkg_files_present(repo_vm)
    assert file_count > 50, f"only {file_count} files registered — implausibly few for pfBlockerNG"


@pytest.mark.timeout(600)  # decoy-catalog already built; pkg update + a cross-repo install > the 30s cap.
def test_precedence_ours_higher_priority_wins(repo_vm: SmokeVM) -> None:
    """PRECEDENCE (ours wins): with a competing repo serving the SAME package, OUR
    higher ``priority:`` wins — the production mechanism (our repo outranks Netgate's).

    The VM proved repo PRIORITY decides cross-repo selection (a higher-priority repo
    wins even at a lower version). Here a controlled ``file://`` ``netgate-decoy``
    repo serves the identical package as a genuine competitor (the real Netgate repo
    does not offer ``-devel`` in this hermetic CE image, so a deterministic decoy
    stands in). Both are set ABOVE the real ``pfSense`` repo so it never interferes.

    Given the package ABSENT and BOTH file:// repos enabled, ours at the HIGHER priority,
    When ``pkg install -y`` resolves across all enabled repos,
    Then ours wins (``pkg query %R`` == ``pfblockerng-devel``).
    """
    pfsense_prio = repo_priority(repo_vm, NETGATE_REPO_NAME)

    # GIVEN: package absent; ours ABOVE the decoy, both above pfSense.
    pkg_delete(repo_vm)
    write_repo_conf(
        repo_vm,
        OURS_REPO_DIR,
        ours_priority=pfsense_prio + 200,
        decoy_dir=DECOY_REPO_DIR,
        decoy_priority=pfsense_prio + 100,
    )
    pkg_update(repo_vm)
    assert pkg_installed_version(repo_vm) is None, f"{PKG_NAME} unexpectedly present before the precedence install"

    # WHEN
    pkg_install_from_repo(repo_vm)

    # THEN: ours wins on the higher priority.
    origin = pkg_repo_origin(repo_vm)
    assert origin == OURS_REPO_NAME, (
        f"installed from {origin!r}, expected ours {OURS_REPO_NAME!r} "
        f"(ours {pfsense_prio + 200} > decoy {pfsense_prio + 100})"
    )


@pytest.mark.timeout(600)  # decoy-catalog already built; pkg update + a cross-repo install > the 30s cap.
def test_precedence_decoy_higher_priority_wins(repo_vm: SmokeVM) -> None:
    """PRECEDENCE counter-case: when the COMPETING repo outranks ours, IT wins —
    proving "ours wins" above is priority-driven (not always-ours), and that a
    higher-priority competitor (e.g. Netgate, if it outranked us) would shadow our
    build. The lever to prevent that is keeping our ``priority:`` highest.

    Given the package ABSENT and BOTH file:// repos enabled, the DECOY at the HIGHER priority,
    When ``pkg install -y`` resolves across all enabled repos,
    Then the DECOY wins (``pkg query %R`` == ``netgate-decoy``), not ours.
    """
    pfsense_prio = repo_priority(repo_vm, NETGATE_REPO_NAME)

    # GIVEN: package absent; the decoy ABOVE ours, both above pfSense.
    pkg_delete(repo_vm)
    write_repo_conf(
        repo_vm,
        OURS_REPO_DIR,
        ours_priority=pfsense_prio + 100,
        decoy_dir=DECOY_REPO_DIR,
        decoy_priority=pfsense_prio + 200,
    )
    pkg_update(repo_vm)
    assert pkg_installed_version(repo_vm) is None, f"{PKG_NAME} unexpectedly present before the precedence install"

    # WHEN
    pkg_install_from_repo(repo_vm)

    # THEN: the decoy wins on the higher priority — precedence is priority-driven.
    origin = pkg_repo_origin(repo_vm)
    assert origin == DECOY_REPO_NAME, (
        f"installed from {origin!r}, expected the decoy {DECOY_REPO_NAME!r} "
        f"(decoy {pfsense_prio + 200} > ours {pfsense_prio + 100})"
    )
