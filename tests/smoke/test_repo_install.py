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
    (`scripts/build-pkg-portable.py` on a Linux runner, for the ABI / php / Python
    flavor THIS leg's matrix row declares — read back here via `own_variant()` and
    `matrix_py_flavor()`, never assumed from the edition). We do NOT re-invoke the builder, and do
    NOT re-version it: priority (not version) is the precedence lever, so the real
    release `.pkg` is published as-is.
  * On the guest, the guest's OWN `pkg repo` (libpkg) builds the catalog from that
    one `.pkg`; served via an on-box `file://` URL — the acceptable hermetic
    transport (no second HTTP server, a CLAUDE.md constraint). Whether the
    Pages-style HTTP catalog is accepted is Phase 2/3's concern; the premise (does
    pfSense honor a NONE-signed third-party repo for install + precedence) is
    orthogonal to the transport.
  * A repo conf at `/usr/local/etc/pkg/repos/pfblockerng.conf` (the shared release
    repo `pfblockerng` — stable + devel; `signature_type: none`, `enabled: yes`,
    `priority:` above/below the pfSense repo per case), then `pkg update` +
    `pkg install -y` with NO `-f`.

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

import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from typing import NamedTuple

import pytest

from . import helpers as h
from ._matrix import (
    matrix_py_flavor,
    own_variant,
)
from .conftest import SmokeVM
from .pkg_identity import branch_pkg_name

pytestmark = pytest.mark.repo

PKG_NAME = branch_pkg_name(os.environ.get("SMOKE_PKG"))

# Our repo conf on the guest + the served catalog root. The conf name follows the
# CLAUDE.md "match the surrounding pattern" rule: pfSense's own conf is
# `pfSense.conf` under the SAME dir; ours is the legacy shared release conf
# (`pfblockerng.conf`, carrying stable + devel — retired by the per-channel
# installers, see PROJECT_CONF_NAMES).
REPO_CONF = "/usr/local/etc/pkg/repos/pfblockerng.conf"
GUEST_SPIKE_DIR = "/tmp/pfb_repo_spike"
OURS_REPO_DIR = f"{GUEST_SPIKE_DIR}/ours"
DECOY_REPO_DIR = f"{GUEST_SPIKE_DIR}/decoy"
# The upgrade test rebuilds ONE repo dir in place (lower build -> higher build) so a
# `pkg upgrade` moves the box across versions WITHIN our repo (not across repos).
UPGRADE_REPO_DIR = f"{GUEST_SPIKE_DIR}/upgrade"
OURS_REPO_NAME = "pfblockerng"  # the %R origin a from-our-repo install reports (shared release repo)
DECOY_REPO_NAME = "netgate-decoy"  # a controlled file:// stand-in for a competing repo
NETGATE_REPO_NAME = "pfSense"  # the real base-system Netgate repo (left enabled; loses on priority)
GUEST_FILE_LIST = f"{GUEST_SPIKE_DIR}/installed_files.txt"

# Phase-2 (ADR-17) catalog generator under test. ``build-repo.sh`` is the real,
# reusable catalog fallback tool; here it is staged to the guest and run with the
# guest's libpkg to prove the SCRIPT's output (the release/<varver>/ tree it
# lays out, arch-less NO_ARCH — issue #1806) is accepted by a real pfSense
# ``pkg update`` + install.
# (The libpkg-on-Linux half of the build-side premise — that the SAME script +
# the SAME ``pkg repo`` op runs on a Linux runner — is proven locally in
# RESULTS/02; the script is identical regardless of which libpkg invokes it.)
BUILD_REPO_SH = Path(__file__).resolve().parents[2] / "scripts" / "build-repo.sh"
GUEST_BUILD_REPO_SH = f"{GUEST_SPIKE_DIR}/build-repo.sh"
GUEST_PKG_IN_DIR = f"{GUEST_SPIKE_DIR}/pkg_in"  # the input dir of .pkg for build-repo.sh
SCRIPT_REPO_ROOT = f"{GUEST_SPIKE_DIR}/script_catalog"  # build-repo.sh --out (varver tree)

# Phase-3a (ADR-17) PURE-PYTHON catalog generator under test. Unlike build-repo.sh
# (which needs a libpkg ``pkg`` binary), ``build-repo-portable.py`` builds the
# catalog WITHOUT libpkg — the way the Phase-3b publish job will, on a plain Linux
# runner with no ``pkg``. Here it is run ON THE RUNNER (this test process's python,
# no guest involvement) over the branch ``.pkg``; a plain run (no ``--catalog-name``)
# emits the catalog directly at ``--out`` (arch-less, NO_ARCH — issue #1806; a
# wildcard ABI is required, a concrete ABI is a hard error), and only those files
# are shipped to the guest, proving a real pfSense ``pkg update``/``install`` accepts
# the pure-Python catalog. This is the load-bearing fidelity gate for the generator.
BUILD_REPO_PORTABLE = Path(__file__).resolve().parents[2] / "scripts" / "build-repo-portable.py"
PORTABLE_REPO_ROOT = f"{GUEST_SPIKE_DIR}/portable_catalog"  # where the flat portable catalog is shipped

# The repository copy of the boot-time generator hook — the executed-proof oracle
# for "the embedded heredoc survives ash when piped": a fresh-box install.sh
# run's on-guest hook must be byte-identical to THIS file.
RC_D_HOOK_SRC = Path(__file__).resolve().parents[2] / "src/usr/local/etc/rc.d/pfblockerng_repo_generate.sh"

# The caller supplies a selected channel root beneath the project Pages URL through
# SMOKE_REPO_LIVE_URL; when unset, the live HTTPS check is skipped.
LIVE_BASE_URL_ENV = "SMOKE_REPO_LIVE_URL"
LIVE_NIGHTLY_URL_ENV = "SMOKE_NIGHTLY_LIVE_URL"
LIVE_EXPECTED_SOURCE_SHA_ENV = "SMOKE_REPO_EXPECTED_SOURCE_SHA"
LIVE_EXPECTED_VERSION_ENV = "SMOKE_REPO_EXPECTED_VERSION"
LIVE_EXPECTED_CHANNEL_ENV = "SMOKE_REPO_EXPECTED_CHANNEL"
NIGHTLY_EXPECTED_SOURCE_SHA_ENV = "SMOKE_NIGHTLY_EXPECTED_SOURCE_SHA"
NIGHTLY_EXPECTED_VERSION_ENV = "SMOKE_NIGHTLY_EXPECTED_VERSION"
DEFAULT_LIVE_BASE_URL = "https://pkg.pfblockerng.com/stable"
# GitHub Pages' anycast IPs. The smoke harness sandboxes guest DNS to a mock that
# only answers `uuid-*.com`, so `pkg.pfblockerng.com` does not resolve on the guest. Pinning
# the Pages IPs in the guest /etc/hosts lets `pkg`'s HTTPS fetch reach Pages by name
# (TLS SNI still presents `pkg.pfblockerng.com`, validated by the Pages custom-domain cert) without
# touching the resolver. Egress is OPEN for this flow (_ensure_egress_open).
PAGES_IPS = ("185.199.108.153", "185.199.109.153", "185.199.110.153", "185.199.111.153")


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
# issue #1806 D3 — SMOKE_DEP_PKGS (extra dep .pkgs shipped alongside the branch
# build; folded into the catalog(s) below so `pkg install` resolves RUN_DEPENDS
# pfSense's own repo doesn't carry, e.g. textproc/py-charset-normalizer for CE)
# --------------------------------------------------------------------------- #


def _smoke_dep_pkg_paths() -> list[Path]:
    """Extra dep ``.pkg`` paths for THIS leg (``SMOKE_DEP_PKGS`` — space-separated
    absolute paths, set by smoke-single.yml/smoke-on-box.sh when the leg's
    ``extra_pkgs`` is non-empty). Folded into the catalog(s) built from the REAL
    branch ``.pkg`` so `pkg install` resolves RUN_DEPENDS pfSense's own repo
    doesn't carry FROM OUR CATALOG — the true user-facing install path. Unset or
    empty -> ``[]`` (deps assumed baked into the image, or this leg carries none;
    never a hard requirement)."""
    return [Path(p) for p in os.environ.get("SMOKE_DEP_PKGS", "").split() if p]


def test_smoke_dep_pkg_paths_parses_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Hermetic (no VM): ``_smoke_dep_pkg_paths()`` parses ``SMOKE_DEP_PKGS``.

    Unset/empty -> []. A space-separated list -> one ``Path`` per entry, in order.
    """
    monkeypatch.delenv("SMOKE_DEP_PKGS", raising=False)
    assert _smoke_dep_pkg_paths() == []

    monkeypatch.setenv("SMOKE_DEP_PKGS", "")
    assert _smoke_dep_pkg_paths() == []

    monkeypatch.setenv("SMOKE_DEP_PKGS", "/tmp/a.pkg /tmp/b.pkg")
    assert _smoke_dep_pkg_paths() == [Path("/tmp/a.pkg"), Path("/tmp/b.pkg")]


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


def _extra_dep_pkgs(pkg_files: list[Path]) -> list[Path]:
    """The locally built RUN_DEPENDS that must ride along in a guest catalog (issue #1914).

    ``smoke-on-box.sh`` builds any dependency the Netgate repositories do not carry
    (currently ``py311-charset-normalizer``) and exports their absolute paths as
    ``SMOKE_DEP_PKGS``; ``scripts/install-pkg.sh`` already consumes it for the direct
    ``pkg add`` path. A ``file://`` catalog that omits them resolves nothing at
    ``pkg install`` time — the failure surfaces as "<package> has a missing
    dependency", pointing at the package rather than at the staging gap.

    Missing paths raise rather than being skipped, mirroring ``install-pkg.sh``'s own
    ``[ -f "$_dep" ] || exit 1``: a catalog that is silently one package short fails
    much later and much less legibly.
    """
    already = {pkg.name for pkg in pkg_files}
    extra: list[Path] = []
    for raw in os.environ.get("SMOKE_DEP_PKGS", "").split():
        dep = Path(raw)
        if not dep.is_file():
            raise RuntimeError(f"SMOKE_DEP_PKGS names a file that does not exist: {dep}")
        if dep.name not in already:
            already.add(dep.name)
            extra.append(dep)
    return extra


def build_guest_repo(vm: SmokeVM, repo_dir: str, pkg_files: list[Path]) -> None:
    """Lay ``pkg_files`` into a fresh ``repo_dir`` on the guest and ``pkg repo`` it.

    Uses the guest's OWN libpkg (``pkg repo``) — the same catalog op Phase 2 will
    run on Linux — to turn the dir of ``.pkg`` files into a real catalog
    (``meta.conf`` / ``packagesite.pkg`` / ``data.pkg``). Built with NO signing,
    so the served catalog is NONE-signed (the trust model under test).

    Any locally built RUN_DEPENDS named by ``SMOKE_DEP_PKGS`` is published beside
    ``pkg_files`` before the catalog is indexed (issue #1914), so an install from the
    resulting repo can resolve dependencies that exist in no upstream repository.
    """
    # Resolve (and validate) the full package set BEFORE touching the guest: the rm -rf
    # below is destructive, so a bad SMOKE_DEP_PKGS must fail with any existing catalog
    # still intact rather than wiping it on the way out.
    staged = [*pkg_files, *_extra_dep_pkgs(pkg_files)]
    _ssh_check(vm, "/bin/rm", "-rf", repo_dir)
    _ssh_check(vm, "/bin/mkdir", "-p", repo_dir)
    for pkg in staged:
        _scp_to_guest(vm, pkg, f"{repo_dir}/{pkg.name}")
    pkg_repo_index(vm, repo_dir)


# `pkg repo` exit status when libpkg aborts (SIGABRT, 128+6) — the guest's jemalloc runs
# with assertions on and once in many runs trips one inside libpkg
# (`Failed assertion: "alloc_ctx.szind != SC_NSIZES"` … `Abort trap`, issue #2447).
_PKG_REPO_ABORT_RC = 134


def pkg_repo_index(vm: SmokeVM, repo_dir: str) -> None:
    """``pkg repo <dir>`` on the guest — no key argument => an unsigned catalog.

    Retries ONCE, and only when ``pkg`` itself died on SIGABRT (issue #2447): a
    transient libpkg crash, not a property of the catalog under test. Any other
    non-zero exit raises on the first try, exactly as before.
    """
    remote = ("env", "ASSUME_ALWAYS_YES=yes", "pkg", "repo", repo_dir)
    result = vm.ssh(*remote, timeout=180.0)
    if result.returncode == _PKG_REPO_ABORT_RC:
        print(
            f"PFB_NOTE pkg repo {repo_dir} aborted (rc={result.returncode}) — retrying once (#2447):\n{result.stderr}"
        )
        result = vm.ssh(*remote, timeout=180.0)
    if result.returncode != 0:
        raise RuntimeError(
            f"guest cmd {remote!r} failed: rc={result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )


def build_repo_via_script(vm: SmokeVM, pkg_files: list[Path]) -> str:
    """Run the Phase-2 ``scripts/build-repo.sh`` on the guest over ``pkg_files``.

    Stages the real ``build-repo.sh`` and the input ``.pkg`` to the guest, runs
    ``build-repo.sh --in <pkg_in> --out <script_catalog> --varver <varver>`` with
    the guest's own libpkg, then returns the catalog directory it produced. The
    script lays the release channel directly under ``<out>/release/<varver>/``
    (arch-less, NO_ARCH — issue #1806; matching ``build-repo-portable.py`` and
    the printed conf), so ``<out>`` is the base a ``file://`` repo conf points at
    and the conf's ``release/<varver>`` url resolves to the returned dir. The
    varver comes from the box itself via the ``_box_real_varver`` oracle.

    This validates the SCRIPT's output (the ``release/<varver>/`` tree + the
    catalog triple ``pkg repo`` emits) is accepted by a real pfSense box, the
    live half of the build-side premise.
    """
    # The script's own `pkg repo` runs un-retried (not routed through pkg_repo_index): the
    # #2447 abort has only ever been seen on the direct call, and retrying here would mean
    # re-running the whole script under test.
    real_varver = _box_real_varver(vm)
    _ssh_check(vm, "/bin/rm", "-rf", GUEST_PKG_IN_DIR, SCRIPT_REPO_ROOT)
    _ssh_check(vm, "/bin/mkdir", "-p", GUEST_PKG_IN_DIR, GUEST_SPIKE_DIR)
    _scp_to_guest(vm, BUILD_REPO_SH, GUEST_BUILD_REPO_SH)
    for pkg in pkg_files:
        _scp_to_guest(vm, pkg, f"{GUEST_PKG_IN_DIR}/{pkg.name}")
    # Run the script exactly as Phase 3 will (just with the guest's pkg as PKG_BIN
    # default). ASSUME_ALWAYS_YES so `pkg repo` never prompts.
    _ssh_check(
        vm,
        "env",
        "ASSUME_ALWAYS_YES=yes",
        "/bin/sh",
        GUEST_BUILD_REPO_SH,
        "--in",
        GUEST_PKG_IN_DIR,
        "--out",
        SCRIPT_REPO_ROOT,
        "--varver",
        real_varver,
        timeout=240.0,
    )
    catalog_dir = f"{SCRIPT_REPO_ROOT}/release/{real_varver}"
    # The catalog quadruple must be present (what `pkg update` consumes) — real `pkg
    # repo` emits the bare `meta` alongside `meta.conf` (ADR-17 RESULTS/02), matching
    # the portable generator's own byte-parity claim.
    for fname in ("meta.conf", "meta", "packagesite.pkg", "data.pkg"):
        present = vm.ssh("/bin/test", "-f", f"{catalog_dir}/{fname}")
        assert present.returncode == 0, f"build-repo.sh did not emit {fname} under {catalog_dir}"
    return catalog_dir


def build_repo_via_portable(vm: SmokeVM, pkg_files: list[Path], tmp_path: Path) -> str:
    """Run ``scripts/build-repo-portable.py`` ON THE RUNNER, then ship its catalog to the guest.

    This is the Phase-3a proof: the catalog is generated in PURE PYTHON on the runner
    (no libpkg, no guest involvement) exactly as the Phase-3b publish job will, then its
    catalog files are copied to the guest. A real pfSense ``pkg update``/``install`` then
    has to accept it — the fidelity gate that the pure-Python catalog is byte-compatible
    with what real ``pkg repo`` emits. A PLAIN run (no ``--catalog-name``) emits the
    catalog DIRECTLY at ``--out`` (arch-less, NO_ARCH — issue #1806; every
    pfSense-pkg-pfBlockerNG ``.pkg`` carries a wildcard ABI, and the generator hard-rejects
    a concrete one), so there is no per-ABI bucket to discover any more.

    The catalog files are then shipped FLAT to ``PORTABLE_REPO_ROOT`` itself. Returns
    ``PORTABLE_REPO_ROOT`` — the on-guest directory the ``file://`` repo conf points at.
    """
    in_dir = tmp_path / "portable_in"
    out_dir = tmp_path / "portable_out"
    in_dir.mkdir(parents=True, exist_ok=True)
    for pkg in pkg_files:
        # Copy (not symlink) so the generator reads real bytes regardless of cwd.
        (in_dir / pkg.name).write_bytes(pkg.read_bytes())

    # Run the pure-Python generator with THIS process's interpreter — no `pkg`/libpkg.
    # No --catalog-name: a plain run emits the catalog directly at --out (arch-less).
    proc = subprocess.run(
        [
            sys.executable,
            str(BUILD_REPO_PORTABLE),
            "--in",
            str(in_dir),
            "--out",
            str(out_dir),
        ],
        capture_output=True,
        text=True,
        timeout=180.0,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"build-repo-portable.py failed on the runner: rc={proc.returncode}\n"
            f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    # The catalog triple must be present locally, directly at out_dir, before shipping.
    for fname in ("meta.conf", "meta", "packagesite.pkg", "data.pkg"):
        assert (out_dir / fname).is_file(), f"portable generator did not emit {fname} under {out_dir}"

    # Ship the catalog files FLAT to PORTABLE_REPO_ROOT itself (fresh dir per run).
    _ssh_check(vm, "/bin/rm", "-rf", PORTABLE_REPO_ROOT)
    _ssh_check(vm, "/bin/mkdir", "-p", PORTABLE_REPO_ROOT)
    for f in sorted(out_dir.iterdir()):
        if f.is_file():
            _scp_to_guest(vm, f, f"{PORTABLE_REPO_ROOT}/{f.name}")
    return PORTABLE_REPO_ROOT


# --------------------------------------------------------------------------- #
# .pkg re-versioning — forge a LOWER + a HIGHER build for the upgrade transition
# --------------------------------------------------------------------------- #

# The manifest members of a libpkg ``.pkg`` (a zstd-compressed tar; these two come
# FIRST, then the payload at absolute paths — see scripts/build-pkg-portable.py).
# Both carry the package ``version``; pkg reads ``+COMPACT_MANIFEST`` for the
# catalog and ``+MANIFEST`` on install, so BOTH must be re-versioned in lockstep.
_PKG_MANIFEST_MEMBERS = ("+COMPACT_MANIFEST", "+MANIFEST")


def _zstd_decompress(data: bytes) -> bytes:
    """zstd-decode the ``.pkg`` framing (the ``zstd`` binary; runner host-tool)."""
    zstd = shutil.which("zstd")
    if not zstd:
        raise RuntimeError("re-versioning a .pkg needs the `zstd` binary on the runner (apt-get install -y zstd)")
    return subprocess.run([zstd, "-dc"], input=data, stdout=subprocess.PIPE, check=True).stdout


def _zstd_compress(data: bytes) -> bytes:
    """zstd-encode back to the ``tzst`` framing pkg(8) expects (``packing_format = tzst``)."""
    zstd = shutil.which("zstd")
    if not zstd:
        raise RuntimeError("re-versioning a .pkg needs the `zstd` binary on the runner (apt-get install -y zstd)")
    return subprocess.run([zstd, "-q", "-19", "-c"], input=data, stdout=subprocess.PIPE, check=True).stdout


def read_compact_manifest(src_pkg: Path) -> dict[str, object]:
    """A ``.pkg``'s ``+COMPACT_MANIFEST``, decoded — the built package's own declared identity."""
    tar_bytes = _zstd_decompress(src_pkg.read_bytes())
    with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tf:
        member = tf.extractfile("+COMPACT_MANIFEST")
        if member is None:
            raise RuntimeError(f"{src_pkg.name}: no +COMPACT_MANIFEST member — not a libpkg .pkg?")
        obj = json.loads(member.read())
    if not isinstance(obj, dict):
        raise RuntimeError(f"{src_pkg.name}: +COMPACT_MANIFEST is not an object (got {type(obj).__name__})")
    return obj


def read_compact_version(src_pkg: Path) -> str:
    """The ``version`` recorded in a ``.pkg``'s ``+COMPACT_MANIFEST`` (the base to re-version from)."""
    version = read_compact_manifest(src_pkg).get("version")
    if not isinstance(version, str) or not version:
        raise RuntimeError(f"{src_pkg.name}: +COMPACT_MANIFEST has no version string (got {version!r})")
    return version


def reversion_pkg(src_pkg: Path, new_version: str, out_dir: Path) -> Path:
    """Re-version a built ``.pkg`` to ``new_version``, payload untouched.

    A libpkg ``.pkg`` is a zstd-compressed tar with ``+COMPACT_MANIFEST`` +
    ``+MANIFEST`` first (UCL/JSON), then the payload files at absolute paths. This
    edits ONLY the ``version`` field in BOTH manifests (the catalog reads compact,
    install reads full — they must agree) and repacks: every other manifest field
    and every payload member is copied through verbatim, manifests kept first, and
    the archive recompressed as ``tzst`` (the ``packing_format`` meta.conf declares).
    So the forged builds differ from the real branch ``.pkg`` in NOTHING but the
    version string — letting a single image prove a real ``pkg upgrade`` moves the
    box from a LOWER (``<V>_1``) to a HIGHER (``<V>_9``) build of OUR repo.

    Returns the path of the written ``<name>-<new_version>.pkg`` under ``out_dir``.
    """
    tar_bytes = _zstd_decompress(src_pkg.read_bytes())
    repacked = io.BytesIO()
    pkg_name = ""
    with (
        tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tin,
        tarfile.open(fileobj=repacked, mode="w", format=tarfile.USTAR_FORMAT) as tout,
    ):
        for member in tin.getmembers():
            extracted = tin.extractfile(member) if member.isfile() else None
            data = extracted.read() if extracted is not None else b""
            if member.name in _PKG_MANIFEST_MEMBERS:
                obj = json.loads(data)
                obj["version"] = new_version
                pkg_name = obj.get("name", pkg_name)
                data = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode() + b"\n"
                # A fresh TarInfo so the re-sized manifest writes cleanly (root:wheel,
                # 0644, deterministic mtime — same framing build-pkg-portable.py uses).
                ti = tarfile.TarInfo(name=member.name)
                ti.size = len(data)
                ti.mode = 0o644
                ti.uid = ti.gid = 0
                ti.uname, ti.gname = "root", "wheel"
                ti.mtime = 0
                ti.type = tarfile.REGTYPE
                tout.addfile(ti, io.BytesIO(data))
            else:
                tout.addfile(member, io.BytesIO(data) if member.isfile() else None)
    if not pkg_name:
        raise RuntimeError(f"{src_pkg.name}: no +COMPACT_MANIFEST/+MANIFEST with a name — not a libpkg .pkg?")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{pkg_name}-{new_version}.pkg"
    out_path.write_bytes(_zstd_compress(repacked.getvalue()))
    return out_path


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

    Declares OUR repo (`pfblockerng`) and — for the precedence cases — a
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


def _pkg_retry_until(vm: SmokeVM, *remote: str, deadline: float, timeout: float) -> subprocess.CompletedProcess[str]:
    """Retry a pkg operation until an existing absolute deadline."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise subprocess.TimeoutExpired(remote, timeout)
    result = vm.ssh(*remote, timeout=remaining)
    while result.returncode != 0 and any(
        message in result.stdout + result.stderr
        for message in ("Waiting for another process to update repository", "database is locked")
    ):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(1.0, remaining))
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        result = vm.ssh(*remote, timeout=remaining)
    return result


def _pkg_retry(vm: SmokeVM, *remote: str, timeout: float) -> subprocess.CompletedProcess[str]:
    """Retry a pkg operation while another pkg process owns its SQLite database."""
    return _pkg_retry_until(vm, *remote, deadline=time.monotonic() + timeout, timeout=timeout)


def pkg_update(vm: SmokeVM, *, timeout: float = 240.0) -> None:
    """``pkg update -f`` so the freshly-written catalog is re-read.

    ``-f`` forces a re-fetch even when the catalog mtime/etag looks unchanged. With
    egress OPEN, this refreshes ALL enabled repos — our reachable ``file://`` repo
    AND the real Netgate ``pfSense`` / ``pfSense-core`` repos — and exits ``rc=0``.
    A clean update of our repo is itself evidence pfSense accepts the unsigned
    third-party repo.
    """
    remote = ("env", "ASSUME_ALWAYS_YES=yes", "pkg", "update", "-f")
    result = _pkg_retry(vm, *remote, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(
            f"guest cmd {remote!r} failed: rc={result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )


def pkg_installed_version_of(vm: SmokeVM, name: str, *, timeout: float = 60.0) -> str | None:
    """The installed ``%v`` of ``name``, or ``None`` if absent (the before/after oracle).

    Takes the package name because the four-channel cases (issue #2148) reason about
    THREE identities on one box — the branch build, the canonical
    ``pfSense-pkg-pfBlockerNG`` every channel publishes, and the legacy
    ``pfSense-pkg-pfBlockerNG-devel`` a migration replaces.
    """
    result = vm.ssh("pkg", "query", "%v", name, timeout=timeout)
    if result.returncode == 0:
        return result.stdout.strip() or None
    if result.returncode == 1:
        return None
    raise RuntimeError(
        f"pkg query {name} failed: rc={result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )


def pkg_repo_origin_of(vm: SmokeVM, name: str, *, timeout: float = 60.0) -> str | None:
    """The repo ``%R`` ``name`` was fetched from, or ``None`` if it is not installed."""
    result = vm.ssh("pkg", "query", "%R", name, timeout=timeout)
    if result.returncode == 0:
        return result.stdout.strip() or None
    if result.returncode == 1:
        return None
    raise RuntimeError(
        f"pkg query %R {name} failed: rc={result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )


def pkg_annotation(vm: SmokeVM, name: str, key: str, *, timeout: float = 60.0) -> str | None:
    """Return one installed package annotation from ``pkg info -A``."""
    out = _ssh_check(vm, "pkg", "info", "-A", name, timeout=timeout).stdout
    for line in out.splitlines():
        annotation, separator, value = line.partition(":")
        if separator and annotation.strip() == key:
            return value.strip()
    return None


def pkg_build_record(vm: SmokeVM, name: str, *, timeout: float = 60.0) -> dict[str, object]:
    """Return the installed package's publisher-validated build record."""
    raw = pkg_annotation(vm, name, "pfb_build_record", timeout=timeout)
    assert raw is not None, f"{name} has no pfb_build_record annotation"
    record: object = json.loads(raw)
    assert isinstance(record, dict), f"{name} pfb_build_record is not an object: {raw!r}"
    return record


def assert_live_package(
    vm: SmokeVM,
    name: str,
    expected_version: str,
    expected_source_sha: str,
    expected_channel: str,
) -> str:
    """Assert the installed package identity bound by the rehearsal caller."""
    version = pkg_installed_version_of(vm, name)
    assert version == expected_version, f"installed {version!r}, expected {expected_version!r}"
    record = pkg_build_record(vm, name)
    assert record.get("source_sha") == expected_source_sha, (
        f"installed source {record.get('source_sha')!r}, expected {expected_source_sha!r}"
    )
    assert record.get("channel") == expected_channel, (
        f"installed channel {record.get('channel')!r}, expected {expected_channel!r}"
    )
    return version


def pkg_installed_version(vm: SmokeVM, *, timeout: float = 60.0) -> str | None:
    """The installed ``%v`` of the branch package, or ``None`` if absent."""
    return pkg_installed_version_of(vm, PKG_NAME, timeout=timeout)


def pkg_repo_origin(vm: SmokeVM, *, timeout: float = 60.0) -> str:
    """The repo ``%R`` the installed branch package was fetched from (the precedence oracle)."""
    return _ssh_check(vm, "pkg", "query", "%R", PKG_NAME, timeout=timeout).stdout.strip()


def pkg_install_from_repo(
    vm: SmokeVM, *, pkg_name: str = PKG_NAME, timeout: float = 600.0
) -> subprocess.CompletedProcess[str]:
    """``pkg install -y <name>`` across ALL enabled repos — NO ``-r``, NO ``-f``.

    This is the exact shape ``pkg_install()`` uses (ADR-17 §1 Context 3): resolve
    the name over every enabled repo and install the winner. The VM proved repo
    PRIORITY decides the winner (a higher-priority repo wins even at a lower
    version). A successful exit is accepted only after ``pkg query`` sees the
    registration; the Plus VM's boot-time package lifecycle can otherwise make
    ``pkg install`` return 0 without leaving the package installed. Returns the
    completed process so the caller can read the "Missing dependency" line
    (deps-resolved evidence) off stderr/stdout.
    """
    remote = ("env", "ASSUME_ALWAYS_YES=yes", "pkg", "install", "-y", pkg_name)
    deadline = time.monotonic() + timeout
    while True:
        result = _pkg_retry_until(vm, *remote, deadline=deadline, timeout=timeout)
        if result.returncode != 0:
            raise RuntimeError(
                f"pkg install {pkg_name} failed: rc={result.returncode}\n"
                f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
            )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(remote, timeout)
        if pkg_installed_version_of(vm, pkg_name, timeout=min(60.0, remaining)) is not None:
            return result
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(remote, timeout)
        time.sleep(min(1.0, remaining))


def pkg_upgrade(vm: SmokeVM, *, timeout: float = 600.0) -> subprocess.CompletedProcess[str]:
    """``pkg upgrade -y <name>`` across ALL enabled repos — NO ``-f``.

    The exact in-repo update path a published newer build takes: with the catalog
    re-read (``pkg update -f``), ``pkg upgrade`` moves the installed package to the
    higher available build (priority decides which repo provides it — ours wins by
    ``priority:``). NO ``-f`` (a forced reinstall would mask a real version move).
    Returns the completed process so the caller can read "Missing dependency" off it.
    """
    result = _pkg_retry(vm, "env", "ASSUME_ALWAYS_YES=yes", "pkg", "upgrade", "-y", PKG_NAME, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(
            f"pkg upgrade {PKG_NAME} failed: rc={result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def pkg_delete(vm: SmokeVM, *, pkg_name: str = PKG_NAME, timeout: float = 300.0) -> None:
    """Remove the package if present (between cases + final cleanup)."""
    vm.ssh("env", "ASSUME_ALWAYS_YES=yes", "pkg", "delete", "-y", pkg_name, timeout=timeout)


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
    dep_pkgs = _smoke_dep_pkg_paths()
    build_guest_repo(smoke_vm, OURS_REPO_DIR, [src, *dep_pkgs])
    build_guest_repo(smoke_vm, DECOY_REPO_DIR, [src, *dep_pkgs])
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
    When ``pkg install -y <the branch package>`` runs (NO ``-r``, NO ``-f``),
    Then it installs from OUR repo (``pkg query %R`` == ``pfblockerng``), with
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


@pytest.mark.timeout(600)  # forge 2 builds + install + a real `pkg upgrade` transition > the 30s cap.
def test_pkg_upgrade_moves_to_our_newer_build(repo_vm: SmokeVM, tmp_path: Path) -> None:
    """UPGRADE TRANSITION: ``pkg upgrade`` moves the box from a LOWER to a HIGHER
    build served by OUR repo — the in-repo update path a published newer build takes.

    Re-versions the branch ``.pkg`` (priority-untouched, payload-untouched) into a
    LOWER (``<V>_1``) and a HIGHER (``<V>_9``) build of the SAME package. The repo
    holds only the LOWER build first (install lands ``<V>_1`` from ours); then the
    SAME repo dir is rebuilt with the HIGHER build and a ``pkg upgrade`` must carry
    the box to ``<V>_9``, still from ours. This is the single-image proof of the
    update path; a true OS-MAJOR jump is not reachable on one image and degrades to
    the documented CLI ``pkg upgrade`` (ADR §7).

    Scenario: a newer build published to our repo upgrades an installed box.
      Background: our NONE-signed file:// repo above the Netgate `pfSense` repo.

    Given the package ABSENT, and our repo carries ONLY the LOWER build ``<V>_1``,
      When ``pkg install -y`` runs (NO -r, NO -f),
      Then the box is at ``<V>_1`` from OUR repo (``%v`` == ``<V>_1``, ``%R`` ==
        ``pfblockerng``) — the asserted BEFORE state.
    When our repo is REBUILT in place with the HIGHER build ``<V>_9``, ``pkg update
      -f`` re-reads the catalog, and ``pkg upgrade -y`` runs,
      Then the box MOVES to ``<V>_9`` from OUR repo (``%v`` == ``<V>_9``, ``%R`` ==
        ``pfblockerng``) — a real before != after transition, not a final-state
        snapshot. (Runtime behaviour is the smoke suite's job, not re-probed here.)
    """
    pkg = os.environ.get("SMOKE_PKG")
    assert pkg and Path(pkg).is_file(), "SMOKE_PKG not set / not a file"  # repo_vm already gated this
    base_version = read_compact_version(Path(pkg))
    low_version = f"{base_version}_1"
    high_version = f"{base_version}_9"
    assert low_version != high_version  # forged builds must differ for the transition to be real

    # Forge the two builds on the runner (only the version field changes).
    low_pkg = reversion_pkg(Path(pkg), low_version, tmp_path / "low")
    high_pkg = reversion_pkg(Path(pkg), high_version, tmp_path / "high")

    pfsense_prio = repo_priority(repo_vm, NETGATE_REPO_NAME)
    try:
        # GIVEN: a clean before-state — package absent; our repo carries ONLY the
        # LOWER build, enabled ABOVE the Netgate `pfSense` repo.
        dep_pkgs = _smoke_dep_pkg_paths()
        pkg_delete(repo_vm)
        build_guest_repo(repo_vm, UPGRADE_REPO_DIR, [low_pkg, *dep_pkgs])
        write_repo_conf(repo_vm, UPGRADE_REPO_DIR, ours_priority=pfsense_prio + 100)
        pkg_update(repo_vm)
        assert pkg_installed_version(repo_vm) is None, f"{PKG_NAME} unexpectedly present before the upgrade test"

        # WHEN (1): install the lower build across all enabled repos (no -r/-f).
        pkg_install_from_repo(repo_vm)

        # THEN (before-state): the box is at the LOWER version, from OUR repo.
        assert pkg_installed_version(repo_vm) == low_version, (
            f"expected {low_version!r} installed first, got {pkg_installed_version(repo_vm)!r}"
        )
        assert pkg_repo_origin(repo_vm) == OURS_REPO_NAME, (
            f"lower build came from {pkg_repo_origin(repo_vm)!r}, expected our repo {OURS_REPO_NAME!r}"
        )

        # WHEN (2): publish the HIGHER build into the SAME repo dir, re-read it, upgrade.
        build_guest_repo(repo_vm, UPGRADE_REPO_DIR, [high_pkg, *dep_pkgs])
        pkg_update(repo_vm)
        proc = pkg_upgrade(repo_vm)

        # THEN (after-state): the box MOVED to the HIGHER version, still from OUR repo.
        combined = proc.stdout + proc.stderr
        assert "Missing dependency" not in combined, f"RUN_DEPENDS did not resolve on upgrade:\n{combined}"
        assert pkg_installed_version(repo_vm) == high_version, (
            f"pkg upgrade did not move {low_version!r} -> {high_version!r}; now at {pkg_installed_version(repo_vm)!r}"
        )
        assert pkg_repo_origin(repo_vm) == OURS_REPO_NAME, (
            f"upgraded build came from {pkg_repo_origin(repo_vm)!r}, expected our repo {OURS_REPO_NAME!r}"
        )
    finally:
        pkg_delete(repo_vm)
        repo_vm.ssh("/bin/rm", "-rf", UPGRADE_REPO_DIR, timeout=60.0)


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
    Then ours wins (``pkg query %R`` == ``pfblockerng``).
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


@pytest.mark.timeout(600)  # build-repo.sh + pkg update + install from the script's catalog > the 30s cap.
def test_build_repo_script_catalog_is_accepted(repo_vm: SmokeVM) -> None:
    """PHASE-2 BUILD TOOL: the catalog laid out by ``scripts/build-repo.sh`` is
    accepted by a real pfSense ``pkg update`` and installs from (no ``-f``).

    Phase 1 proved a hand-built (inline ``pkg repo``) catalog installs; this proves
    the REUSABLE Phase-2 generator produces an equivalent, VM-accepted tree — the
    live half of the build-side premise (the libpkg-on-Linux half is settled in
    RESULTS/02 by building the same catalog with a Linux ``pkg``; the script + the
    ``pkg repo`` op are identical regardless of which libpkg runs them).

    Given the package ABSENT and a catalog produced by ``build-repo.sh`` over the
      branch ``.pkg`` (its ``release/<varver>/`` bucket holds
      meta.conf/packagesite.pkg/data.pkg — arch-less, NO_ARCH, issue #1806),
      enabled via a NONE-signed ``file://`` repo above the pfSense repo,
    When ``pkg update`` reads it and ``pkg install -y`` runs (NO ``-r``, NO ``-f``),
    Then ``pkg update`` accepts the script-generated catalog AND the install comes
      from OUR repo (``pkg query %R`` == ``pfblockerng``) with deps resolved —
      the build tool's output is real and VM-consumable.
    """
    pkg = os.environ.get("SMOKE_PKG")
    assert pkg and Path(pkg).is_file(), "SMOKE_PKG not set / not a file"  # repo_vm already gated this

    # GIVEN: build the catalog with the Phase-2 SCRIPT (not the inline pkg repo), then
    # point a NONE-signed file:// repo at the produced release/<varver>/ dir, above pfSense.
    catalog_dir = build_repo_via_script(repo_vm, [Path(pkg), *_smoke_dep_pkg_paths()])
    pfsense_prio = repo_priority(repo_vm, NETGATE_REPO_NAME)
    pkg_delete(repo_vm)
    write_repo_conf(repo_vm, catalog_dir, ours_priority=pfsense_prio + 100)

    # WHEN: pkg update must ACCEPT the script-generated catalog (rc=0; a rejected
    # catalog would fail here — that is the build-side premise under test).
    pkg_update(repo_vm)
    assert pkg_installed_version(repo_vm) is None, f"{PKG_NAME} unexpectedly present before the script-catalog install"

    # THEN: install resolves from our repo over the script's catalog, deps included.
    proc = pkg_install_from_repo(repo_vm)
    combined = proc.stdout + proc.stderr
    assert "Missing dependency" not in combined, f"RUN_DEPENDS did not resolve from the script catalog:\n{combined}"
    origin = pkg_repo_origin(repo_vm)
    assert origin == OURS_REPO_NAME, f"installed from {origin!r}, expected our repo {OURS_REPO_NAME!r}"


@pytest.mark.timeout(600)  # build catalog + run the shipped bootstrap + install > the 30s cap.
@pytest.mark.timeout(600)  # runner-side portable build + ship + pkg update + install > the 30s cap.
def test_portable_catalog_is_accepted(repo_vm: SmokeVM, tmp_path: Path) -> None:
    """PHASE-3a PURE-PYTHON GENERATOR: the catalog built by ``build-repo-portable.py``
    ON THE RUNNER (no libpkg) is accepted by a real pfSense ``pkg update`` and installs
    from (no ``-f``) — the load-bearing fidelity gate.

    Phase 2's ``build-repo.sh`` drives real ``pkg repo`` (libpkg) and STAYS the
    FreeBSD-VM fallback; this proves the pure-Python catalog the Phase-3b publish job
    will emit on a plain Linux runner (no ``pkg`` binary) is byte-compatible with what
    libpkg produces — a real box honors its ``meta.conf``/``packagesite.pkg``/
    ``data.pkg`` AND its blake2b/z-base-32 ``sum`` (the .pkg integrity check passes).

    Given the package ABSENT and a catalog produced by ``build-repo-portable.py`` over
      the branch ``.pkg`` — generated ENTIRELY on the runner in pure Python, then
      shipped FLAT to the guest (arch-less, NO_ARCH — issue #1806) — enabled via a
      NONE-signed ``file://`` repo above the pfSense repo,
    When ``pkg update`` reads the pure-Python catalog and ``pkg install -y`` runs
      (NO ``-r``, NO ``-f``),
    Then ``pkg update`` accepts it AND the install comes from OUR repo
      (``pkg query %R`` == ``pfblockerng``) with deps resolved and the ``.pkg``
      checksum validated — the pure-Python generator's output is real + VM-consumable.
    """
    pkg = os.environ.get("SMOKE_PKG")
    assert pkg and Path(pkg).is_file(), "SMOKE_PKG not set / not a file"  # repo_vm already gated this

    # GIVEN: build the catalog with the PURE-PYTHON generator on the runner (no libpkg),
    # ship it flat to the guest, point a NONE-signed file:// repo above pfSense.
    catalog_dir = build_repo_via_portable(repo_vm, [Path(pkg), *_smoke_dep_pkg_paths()], tmp_path)
    pfsense_prio = repo_priority(repo_vm, NETGATE_REPO_NAME)
    pkg_delete(repo_vm)
    write_repo_conf(repo_vm, catalog_dir, ours_priority=pfsense_prio + 100)

    # WHEN: pkg update must ACCEPT the pure-Python catalog (rc=0; a rejected catalog —
    # bad meta.conf, malformed packagesite, or a mismatched sum — would fail here).
    pkg_update(repo_vm)
    assert pkg_installed_version(repo_vm) is None, (
        f"{PKG_NAME} unexpectedly present before the portable-catalog install"
    )

    # THEN: install resolves from our repo over the pure-Python catalog, deps included,
    # and the .pkg checksum (the catalog `sum`) validates — origin proves it came from ours.
    proc = pkg_install_from_repo(repo_vm)
    combined = proc.stdout + proc.stderr
    assert "Missing dependency" not in combined, f"RUN_DEPENDS did not resolve from the portable catalog:\n{combined}"
    origin = pkg_repo_origin(repo_vm)
    assert origin == OURS_REPO_NAME, f"installed from {origin!r}, expected our repo {OURS_REPO_NAME!r}"


@pytest.mark.timeout(600)  # runner-side portable build over 2 inputs + ship + pkg update + install > the 30s cap.
def test_portable_catalog_dedups_duplicate_sources(repo_vm: SmokeVM, tmp_path: Path) -> None:
    """DEDUP on the live VM (PR #144): the SAME package staged from TWO sources — the
    publish job's ``built-<source>-`` prefixed copies of the branch build + a release
    artifact — produces ONE canonically-named ``.pkg`` + ONE catalog entry that a real
    pfSense ``pkg`` installs, not two prefixed duplicates (the defect the first live
    Pages deploy actually served). Complements the unit pin
    (``test_duplicate_sources_dedup_to_one_canonical``) by driving the REAL generator
    output through a real ``pkg update``/``install`` on the box.

    Given the branch ``.pkg`` copied under TWO distinct ``built-<source>-`` filenames and
      a catalog built over BOTH by ``build-repo-portable.py`` on the runner, shipped to
      the guest, enabled via a NONE-signed ``file://`` repo above the pfSense repo,
    When ``pkg update`` reads it and ``pkg install -y`` runs (NO ``-r``, NO ``-f``),
    Then the bucket holds exactly ONE package ``.pkg``, canonically named
      ``<name>-<version>.pkg`` (no ``built-incoming_*`` prefix), and the install comes
      from OUR repo — the two staging duplicates collapsed to one.
    """
    pkg = os.environ.get("SMOKE_PKG")
    assert pkg and Path(pkg).is_file(), "SMOKE_PKG not set / not a file"  # repo_vm already gated this
    src = Path(pkg)

    # GIVEN: the SAME build staged under two `built-<source>-` filenames (mirrors the
    # publish job's store/ layout), built into one catalog by the pure-Python generator.
    a = tmp_path / "built-incoming_branch-pfb.pkg"
    b = tmp_path / "built-incoming_release-freebsd-pfb.pkg"
    a.write_bytes(src.read_bytes())
    b.write_bytes(src.read_bytes())
    # NOTE: deliberately NOT folding _smoke_dep_pkg_paths() here — this test's own
    # assertion below counts EXACTLY one package .pkg in the bucket (the dedup
    # proof); a dep .pkg would be a second, distinct-named entry and break that
    # count. It has no "Missing dependency" assertion (not this test's concern).
    catalog_dir = build_repo_via_portable(repo_vm, [a, b], tmp_path)

    # THEN (catalog shape): exactly ONE package .pkg, canonically named (no prefix) — the
    # catalog files (packagesite.pkg/data.pkg) also end in .pkg, so exclude them.
    listing = _ssh_check(repo_vm, "/bin/ls", "-1", catalog_dir).stdout.split()
    catalog_files = {"packagesite.pkg", "data.pkg", "meta.pkg"}
    pkgs = [n for n in listing if n.endswith(".pkg") and n not in catalog_files]
    assert len(pkgs) == 1, f"expected ONE deduped package .pkg in the bucket, got {pkgs}"
    assert pkgs[0].startswith(f"{PKG_NAME}-") and "built-incoming" not in pkgs[0], (
        f"published .pkg is not canonically named: {pkgs[0]!r}"
    )

    # WHEN/THEN (install): a real pkg installs the deduped catalog from OUR repo.
    pfsense_prio = repo_priority(repo_vm, NETGATE_REPO_NAME)
    pkg_delete(repo_vm)
    write_repo_conf(repo_vm, catalog_dir, ours_priority=pfsense_prio + 100)
    pkg_update(repo_vm)
    assert pkg_installed_version(repo_vm) is None, f"{PKG_NAME} unexpectedly present before the dedup install"
    pkg_install_from_repo(repo_vm)
    assert pkg_repo_origin(repo_vm) == OURS_REPO_NAME, "deduped catalog did not install from our repo"


# --------------------------------------------------------------------------- #
# Phase-3b — the LIVE GitHub-Pages-URL end-to-end (dispatch-only; gated)
# --------------------------------------------------------------------------- #


def _live_base_url() -> str | None:
    """The live Pages base to test against, or None to SKIP.

    Gated on ``SMOKE_REPO_LIVE_URL``: set it to the deployed base (e.g.
    ``https://pkg.pfblockerng.com/stable``, or a staged
    ``.../pkg/staging/<seg>/<channel>`` root pre-promote, issue #2389) to run the live
    check after a publish dispatch; leave it unset and the test SKIPS (the always-on
    proof is the file:// VM-acceptance above). A bare ``1``/``true`` selects the
    default base (``DEFAULT_LIVE_BASE_URL`` — Stable, the gated post-publish default).
    """
    val = os.environ.get(LIVE_BASE_URL_ENV)
    if not val:
        return None
    if val.strip().lower() in {"1", "true", "yes", "on"}:
        return DEFAULT_LIVE_BASE_URL
    return val.rstrip("/")


def poll_catalog_served(base_url: str, catalog_path: str, *, attempts: int = 30, delay: float = 10.0) -> None:
    """Poll the live ``<base>/<catalog_path>/meta.conf`` until it serves (first deploy + DNS/cert lag).

    Arch-less (NO_ARCH — issue #1806): a published catalog is keyed by varver alone,
    no ``${ABI}``/CPU segment. ``catalog_path`` is the caller's full subtree under
    ``base_url`` — no channel is hardcoded here because both tagged and Nightly callers
    pass a selected channel root and the bare ``varver``. The catalog files a client
    ``pkg update`` consumes are ``meta.conf``
    + ``packagesite.pkg``; a 200 on both is the runner-side BACKSTOP that the deploy
    actually published a usable tree, independent of the guest. Raises with the last
    error if the URL never serves within the budget.
    """
    last_err = ""
    for _ in range(attempts):
        try:
            for fname in ("meta.conf", "packagesite.pkg"):
                url = f"{base_url}/{catalog_path}/{fname}"
                with urllib.request.urlopen(url, timeout=15) as resp:  # noqa: S310 (fixed https Pages URL)
                    if resp.status != 200:
                        raise RuntimeError(f"{url} -> HTTP {resp.status}")
                    if not resp.read(1):
                        raise RuntimeError(f"{url} served an empty body")
            return
        except (urllib.error.URLError, RuntimeError, TimeoutError) as exc:
            last_err = f"{type(exc).__name__}: {exc}"
            time.sleep(delay)
    raise AssertionError(f"live catalog never served {base_url}/{catalog_path}/ within budget; last error: {last_err}")


def pin_pages_hosts(vm: SmokeVM, host: str, *, timeout: float = 60.0) -> str:
    """Pin GitHub Pages' anycast IPs for ``host`` in the guest ``/etc/hosts``.

    The smoke harness sandboxes guest DNS to a mock answering only ``uuid-*.com``,
    so the Pages host does not resolve on the box. A static ``/etc/hosts`` entry
    routes ``pkg``'s HTTPS fetch to Pages by IP while TLS SNI still presents ``host``
    (GitHub's *.github.io cert validates). Idempotent: the entry is removed first.

    Returns the pre-pin ``/etc/hosts`` content — pass it to :func:`restore_pages_hosts`
    in the caller's ``finally`` so the pin never outlives the test (issue #582: it
    used to leak into every later test/module sharing the guest).
    """
    prior = vm.ssh("cat", "/etc/hosts", timeout=timeout)
    if prior.returncode != 0:
        raise RuntimeError(f"pin_pages_hosts: reading /etc/hosts failed: rc={prior.returncode} {prior.stderr!r}")

    # Drop any prior line carrying this host as a whitespace-separated field (not
    # just a line-ending match, so stale aliases/comments don't survive), then pin
    # ALL the Pages IPs (resilient to a single-IP failure; pkg follows the cert).
    # Atomic via a tmp file + mv.
    strip = f"grep -Ev '[[:space:]]{re.escape(host)}([[:space:]]|$)' /etc/hosts > /etc/hosts.pfb 2>/dev/null"
    script = (
        f"{strip} || cp /etc/hosts /etc/hosts.pfb; "
        + "".join(f"printf '%s %s\\n' '{ip}' '{host}' >> /etc/hosts.pfb; " for ip in PAGES_IPS)
        + "mv /etc/hosts.pfb /etc/hosts"
    )
    result = subprocess.run(
        vm.ssh_argv("/bin/sh", "-c", script),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"pin_pages_hosts failed: rc={result.returncode} {result.stderr!r}")
    return prior.stdout


def restore_pages_hosts(vm: SmokeVM, prior_hosts: str, *, timeout: float = 60.0) -> None:
    """Restore ``/etc/hosts`` to the content :func:`pin_pages_hosts` snapshotted.

    Call from the caller's ``finally`` so the Pages-IP pin never survives the test.
    """
    result = subprocess.run(
        vm.ssh_argv("tee", "/etc/hosts"),
        input=prior_hosts,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"restore_pages_hosts failed: rc={result.returncode} {result.stderr!r}")


def write_live_repo_conf(
    vm: SmokeVM,
    base_url: str,
    varver: str,
    *,
    priority: int,
    channel: str | None = None,
    conf_path: str = REPO_CONF,
    timeout: float = 60.0,
) -> None:
    """Write a REPO CONF, ONLY, pointing at the LIVE ``<channel-base>/<varver>`` Pages URL —
    no install.sh run, no pkg mutation: a hand-written subscription, exactly what a
    restored config backup or a manually-edited conf looks like.

    Built from the SAME generator the publish job emits (``build-repo-portable.py
    --print-conf --base-url <base> --catalog-path <varver> [--channel <ch>]``), but with
    the ``priority:`` raised above the Netgate ``pfSense`` repo so cross-repo resolution
    favours ours. The conf URL is fully resolved (``<channel-base>/<varver>`` — arch-less,
    NO_ARCH, issue #1806): there is no ``${ABI}`` pkg(8) variable any more, the caller
    supplies the concrete varver. ``channel`` omitted defaults to the legacy release conf
    (``REPO_CONF``); pass it (with ``conf_path``) to write one of the four channel confs
    directly, bypassing install.sh's own always-installs convergence.
    """
    channel_args = () if channel is None else ("--channel", channel)
    proc = subprocess.run(
        [
            sys.executable,
            str(BUILD_REPO_PORTABLE),
            "--print-conf",
            "--base-url",
            base_url,
            "--catalog-path",
            varver,
            *channel_args,
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"--print-conf failed: rc={proc.returncode} {proc.stderr!r}")
    # Raise the priority above pfSense (the template ships priority 100; this flow
    # sets it deterministically above the box's effective pfSense priority).
    conf = re.sub(r"priority:\s*\d+", f"priority: {priority}", proc.stdout)
    written = subprocess.run(
        vm.ssh_argv("tee", conf_path),
        input=conf,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if written.returncode != 0:
        raise RuntimeError(f"write_live_repo_conf failed: rc={written.returncode} {written.stderr!r}")
    if "signature_type: fingerprints" in conf:
        _install_trusted_fingerprint(vm, timeout=timeout)


def _install_trusted_fingerprint(vm: SmokeVM, *, timeout: float = 60.0) -> None:
    """Install the catalogue signing key's trusted fingerprint on the guest.

    A conf written straight from ``--print-conf`` requires a signature (issue #2675), and
    on this path nothing has run the rc.d hook that normally installs the key — so without
    this the guest refuses the catalogue with "No trusted public keys found", whatever the
    catalogue actually contains. Read out of the shipped hook rather than restated here, so
    a rotated key cannot leave the smoke fleet pinning the retired one.
    """
    hook_text = GENERATE_HOOK_SRC.read_text()
    name = re.search(r"^CONF_FINGERPRINT_NAME=\"\$\{REPO_HOST\}\"", hook_text, re.M)
    host = re.search(r"^REPO_HOST='([^']+)'", hook_text, re.M)
    sha = re.search(r"^CONF_FINGERPRINT_SHA256='([0-9a-f]{64})'", hook_text, re.M)
    if not (name and host and sha):
        raise RuntimeError("cannot read the trusted fingerprint out of the shipped rc.d hook")
    trusted_dir = "/usr/local/etc/pkg/fingerprints/pfblockerng/trusted"
    body = f'function: "sha256"\nfingerprint: "{sha.group(1)}"\n'
    made = subprocess.run(
        vm.ssh_argv("/bin/mkdir", "-p", trusted_dir),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if made.returncode != 0:
        raise RuntimeError(f"could not create {trusted_dir}: {made.stderr!r}")
    put = subprocess.run(
        vm.ssh_argv("tee", f"{trusted_dir}/{host.group(1)}"),
        input=body,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if put.returncode != 0:
        raise RuntimeError(f"could not install the trusted fingerprint: {put.stderr!r}")


def _raise_live_pages_errors(context: str, errors: list[tuple[str, Exception]]) -> None:
    if not errors:
        return
    details = "; ".join(f"{operation}: {type(error).__name__}: {error}" for operation, error in errors)
    raise RuntimeError(f"{context}: {details}") from errors[0][1]


def _ensure_live_pages_packages_absent(vm: SmokeVM) -> None:
    package_names = (PKG_NAME,) if PKG_NAME == CANONICAL_PKG_NAME else (PKG_NAME, CANONICAL_PKG_NAME)
    errors: list[tuple[str, Exception]] = []
    for package_name in package_names:
        try:
            pkg_delete(vm, pkg_name=package_name)
        except Exception as error:
            errors.append((f"delete {package_name}", error))

    try:
        installed = installed_pfblockerng_names(vm)
        remaining = [package_name for package_name in package_names if package_name in installed]
        if remaining:
            raise AssertionError(
                f"live Pages packages still installed: expected absent {list(package_names)!r}; "
                f"remaining {remaining!r}; installed {installed!r}"
            )
    except Exception as error:
        errors.append(("verify package absence", error))

    _raise_live_pages_errors("live Pages package cleanup failed", errors)


def _cleanup_live_pages(vm: SmokeVM, prior_hosts: str) -> None:
    errors: list[tuple[str, Exception]] = []
    try:
        _ensure_live_pages_packages_absent(vm)
    except Exception as error:
        errors.append(("package cleanup", error))
    try:
        _ssh_check(vm, "/bin/rm", "-f", REPO_CONF)
    except Exception as error:
        errors.append(("remove repo conf", error))
    try:
        restore_pages_hosts(vm, prior_hosts)
    except Exception as error:
        errors.append(("restore Pages hosts", error))

    _raise_live_pages_errors("live Pages teardown failed", errors)


@pytest.mark.timeout(900)  # live deploy/DNS/cert can lag + pkg update + install over the public URL.
def test_install_from_live_pages_url(repo_vm: SmokeVM) -> None:
    """Install the canonical package from the selected live Pages repository."""
    base_url = _live_base_url()
    if base_url is None:
        pytest.skip(f"{LIVE_BASE_URL_ENV} not set — live Pages-URL check is dispatch-only (file:// proof always runs)")
    assert base_url is not None  # for the type-checker: pytest.skip above is NoReturn
    expected_source_sha = os.environ.get(LIVE_EXPECTED_SOURCE_SHA_ENV)
    expected_version = os.environ.get(LIVE_EXPECTED_VERSION_ENV)
    expected_channel = os.environ.get(LIVE_EXPECTED_CHANNEL_ENV)
    assert expected_source_sha, f"{LIVE_EXPECTED_SOURCE_SHA_ENV} is required with {LIVE_BASE_URL_ENV}"
    assert expected_version, f"{LIVE_EXPECTED_VERSION_ENV} is required with {LIVE_BASE_URL_ENV}"
    assert expected_channel, f"{LIVE_EXPECTED_CHANNEL_ENV} is required with {LIVE_BASE_URL_ENV}"

    host = urllib.parse.urlparse(base_url).hostname
    assert host, f"could not parse a host from {base_url!r}"

    # BACKSTOP: prove the deploy actually serves the catalog from the RUNNER first
    # (independent of the guest) — polls through first-deploy / DNS / cert lag. The
    # varver to poll is read from the BOX itself via the _box_real_varver oracle: the
    # guest, not the matrix, is the authority for which release line this leg runs.
    # The caller passes a selected channel root, so the subtree is the bare varver.
    varver = _box_real_varver(repo_vm)
    poll_catalog_served(base_url, varver)

    # GIVEN: Pages IPs pinned (guest DNS is sandboxed), package absent, our conf at
    # the LIVE url above pfSense.
    prior_hosts = pin_pages_hosts(repo_vm, host)
    try:
        pfsense_prio = repo_priority(repo_vm, NETGATE_REPO_NAME)
        _ensure_live_pages_packages_absent(repo_vm)
        write_live_repo_conf(repo_vm, base_url, varver, priority=pfsense_prio + 100)

        # WHEN: pkg update must ACCEPT the live HTTPS catalog (a rejected catalog — bad
        # meta.conf, malformed packagesite, mismatched sum, or an unreachable URL — fails here).
        pkg_update(repo_vm)
        assert pkg_installed_version_of(repo_vm, CANONICAL_PKG_NAME) is None, (
            f"{CANONICAL_PKG_NAME} unexpectedly present before the live-URL install"
        )

        # THEN: install resolves from our LIVE repo, deps included, .pkg checksum validated.
        proc = pkg_install_from_repo(repo_vm, pkg_name=CANONICAL_PKG_NAME)
        combined = proc.stdout + proc.stderr
        assert "Missing dependency" not in combined, (
            f"RUN_DEPENDS did not resolve from the live Pages catalog:\n{combined}"
        )
        dest_channel = base_url.rsplit("/", 1)[-1]
        assert dest_channel in CHANNELS, f"live base URL does not end in a known channel: {base_url!r}"
        assert expected_channel in CHANNELS, f"{LIVE_EXPECTED_CHANNEL_ENV} is not a known channel: {expected_channel!r}"
        assert dest_channel != "nightly", f"tagged live Pages dest cannot be nightly (primary {expected_channel!r})"
        assert CHANNELS.index(dest_channel) >= CHANNELS.index(expected_channel), (
            f"dest {dest_channel!r} is slower than primary {expected_channel!r}"
        )
        expected_origin = channel_repo_name(dest_channel)
        origin = pkg_repo_origin_of(repo_vm, CANONICAL_PKG_NAME)
        assert origin == expected_origin, f"installed from {origin!r}, expected selected repo {expected_origin!r}"
        assert_live_package(repo_vm, CANONICAL_PKG_NAME, expected_version, expected_source_sha, expected_channel)
    finally:
        body_error = sys.exception()
        try:
            _cleanup_live_pages(repo_vm, prior_hosts)
        except Exception as cleanup_error:
            if body_error is None:
                raise
            body_error.add_note(f"live Pages cleanup also failed: {cleanup_error}")


@pytest.mark.timeout(1800)
def test_live_nightly_downgrade_requires_selected_semantic_repo(repo_vm: SmokeVM, tmp_path: Path) -> None:
    """A date-version Nightly install moves down only through an explicit selected repo.

    The caller supplies one semantic channel root plus the Nightly root from the same
    deployed tree. Ordinary ``pkg upgrade`` must leave Nightly's higher date version
    untouched even with a lower-versioned semantic repo ALSO subscribed (a hand-written
    conf, exactly what a restored config backup looks like); the published
    ``install.sh --channel <channel>`` must then move the canonical package to the selected
    Stable, Testing, or Edge repository and its lower version.
    """
    from .test_nightly_install import _live_nightly_url

    semantic_url = _live_base_url()
    nightly_url = _live_nightly_url()
    if semantic_url is None or nightly_url is None:
        pytest.skip(f"{LIVE_BASE_URL_ENV} and {LIVE_NIGHTLY_URL_ENV} are required for the live downgrade")
    assert semantic_url is not None
    expected_semantic_source = os.environ.get(LIVE_EXPECTED_SOURCE_SHA_ENV)
    expected_semantic_version = os.environ.get(LIVE_EXPECTED_VERSION_ENV)
    expected_nightly_source = os.environ.get(NIGHTLY_EXPECTED_SOURCE_SHA_ENV)
    expected_nightly_version = os.environ.get(NIGHTLY_EXPECTED_VERSION_ENV)
    for name, value in (
        (LIVE_EXPECTED_SOURCE_SHA_ENV, expected_semantic_source),
        (LIVE_EXPECTED_VERSION_ENV, expected_semantic_version),
        (NIGHTLY_EXPECTED_SOURCE_SHA_ENV, expected_nightly_source),
        (NIGHTLY_EXPECTED_VERSION_ENV, expected_nightly_version),
    ):
        assert value, f"{name} is required for the live downgrade"
    assert expected_semantic_version is not None
    assert expected_nightly_version is not None
    assert expected_semantic_source is not None
    assert expected_nightly_source is not None

    semantic_channel = semantic_url.rsplit("/", 1)[-1]
    assert semantic_channel in CHANNELS[:3], (
        f"semantic live URL must end in stable, testing, or edge, got {semantic_url!r}"
    )
    common_base = semantic_url.rsplit("/", 1)[0]
    assert nightly_url == f"{common_base}/nightly", (
        f"semantic and Nightly URLs must share one deployed root: {semantic_url!r}, {nightly_url!r}"
    )
    host = urllib.parse.urlparse(common_base).hostname
    assert host, f"could not parse a host from {common_base!r}"

    varver = _box_real_varver(repo_vm)
    poll_catalog_served(semantic_url, varver)
    poll_catalog_served(nightly_url, varver)
    prior_hosts = pin_pages_hosts(repo_vm, host)
    try:
        reset_channel_subscription(repo_vm)

        # GIVEN: the published install.sh --channel nightly subscribes AND installs, in one shot.
        installer = run_channel_installer(repo_vm, "nightly", common_base, tmp_path)
        assert installer.returncode == 0, (
            f"install.sh --channel nightly exited {installer.returncode}\n"
            f"stdout:\n{installer.stdout}\nstderr:\n{installer.stderr}"
        )
        nightly_version = assert_live_package(
            repo_vm,
            CANONICAL_PKG_NAME,
            expected_nightly_version,
            expected_nightly_source,
            "nightly",
        )
        assert pkg_repo_origin_of(repo_vm, CANONICAL_PKG_NAME) == channel_repo_name("nightly")

        # WHEN (1): the semantic channel's conf ALSO becomes present — a hand-written
        # conf, no install.sh run, so the nightly install is untouched at this
        # point (asserted below) — exactly what a restored config backup looks like.
        write_live_repo_conf(
            repo_vm,
            semantic_url,
            varver,
            priority=100,
            channel=semantic_channel,
            conf_path=f"{PKG_REPOS_DIR}/{channel_conf_name(semantic_channel)}",
        )
        ordinary = _pkg_retry(
            repo_vm,
            "env",
            "ASSUME_ALWAYS_YES=yes",
            "pkg",
            "upgrade",
            "-y",
            CANONICAL_PKG_NAME,
            timeout=600.0,
        )
        assert ordinary.returncode == 0, (
            f"ordinary pkg upgrade failed: rc={ordinary.returncode}\n"
            f"stdout:\n{ordinary.stdout}\nstderr:\n{ordinary.stderr}"
        )
        assert pkg_installed_version_of(repo_vm, CANONICAL_PKG_NAME) == nightly_version, (
            f"ordinary pkg upgrade unexpectedly downgraded Nightly via {semantic_channel}:\n"
            f"stdout:\n{ordinary.stdout}\nstderr:\n{ordinary.stderr}"
        )

        # WHEN (2): the published install-<semantic_channel>.sh does the qualified move.
        migrated = run_channel_installer(repo_vm, semantic_channel, common_base, tmp_path)
        assert migrated.returncode == 0, (
            f"qualified Nightly -> {semantic_channel} migration failed: rc={migrated.returncode}\n"
            f"stdout:\n{migrated.stdout}\nstderr:\n{migrated.stderr}"
        )
        semantic_version = assert_live_package(
            repo_vm,
            CANONICAL_PKG_NAME,
            expected_semantic_version,
            expected_semantic_source,
            semantic_channel,
        )
        ordering = _ssh_check(repo_vm, "pkg", "version", "-t", semantic_version, nightly_version).stdout.strip()
        assert ordering == "<", (
            f"expected a real downgrade from Nightly {nightly_version!r}, got {semantic_version!r} ({ordering!r})"
        )
        assert pkg_repo_origin_of(repo_vm, CANONICAL_PKG_NAME) == channel_repo_name(semantic_channel)
        assert installed_pfblockerng_names(repo_vm) == [CANONICAL_PKG_NAME]
    finally:
        reset_channel_subscription(repo_vm)
        repo_vm.ssh("/bin/rm", "-f", GUEST_HOOK_PATH, timeout=60.0)
        repo_vm.ssh("/bin/sh", "-c", f"rm -f {GUEST_SPIKE_DIR}/install*.sh", timeout=60.0)
        restore_pages_hosts(repo_vm, prior_hosts)


# =========================================================================== #
# ADR-20 Phase 6 — variant-catalog live-VM cases: this leg installs from ITS   #
# OWN row's catalog, a build target that is NOT this row's is refused, and the  #
# routing URL. Both oracles are row-local (issue #2464): the forged package is  #
# derived from this row, never from another row, which may share this row's     #
# build target and make the forgery a no-op.                                    #
#                                                                              #
# Marker: @pytest.mark.repo  (inherited from pytestmark = pytest.mark.repo).  #
# Deselected from default `python -m pytest` — dispatched via:                #
#     gh workflow run smoke-single.yml -f pytest_marker=repo                          #
# =========================================================================== #

# Base dir for ADR-20 variant catalogs on the guest (isolated from the ADR-17 spike dir).
VARIANT_REPO_ROOT = "/tmp/pfb_variant_repo"

# Base dir for ADR-27 EOL route-only catalog on the guest.
EOL_REPO_ROOT = "/tmp/pfb_eol_repo"


# --------------------------------------------------------------------------- #
# Helper — build a variant-keyed catalog on the runner + ship to the guest    #
# --------------------------------------------------------------------------- #


def build_repo_via_portable_named(
    vm: SmokeVM,
    pkg_files: list[Path],
    tmp_path: Path,
    *,
    catalog_name: str,
    guest_root: str,
) -> str:
    """Like ``build_repo_via_portable`` but writes under ``<out>/<catalog-name>/``.

    Uses ``build-repo-portable.py --catalog-name <catalog_name>`` to place the catalog
    DIRECTLY under the named variant directory (arch-less, NO_ARCH — issue #1806; no
    per-ABI bucket any more, ``catalog_name`` may itself contain ``/``, e.g.
    ``"release/ce-2.8"``). Ships those files to ``<guest_root>/<catalog_name>/``.

    Returns the on-guest path the repo conf should point at.
    """
    in_dir = tmp_path / f"in_{catalog_name.replace('/', '_')}"
    out_dir = tmp_path / f"out_{catalog_name.replace('/', '_')}"
    in_dir.mkdir(parents=True, exist_ok=True)
    for pkg in pkg_files:
        (in_dir / pkg.name).write_bytes(pkg.read_bytes())

    proc = subprocess.run(
        [
            sys.executable,
            str(BUILD_REPO_PORTABLE),
            "--in",
            str(in_dir),
            "--out",
            str(out_dir),
            "--catalog-name",
            catalog_name,
        ],
        capture_output=True,
        text=True,
        timeout=180.0,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"build-repo-portable.py --catalog-name {catalog_name} failed: "
            f"rc={proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )

    local_catalog_dir = out_dir / catalog_name
    for fname in ("meta.conf", "meta", "packagesite.pkg", "data.pkg"):
        assert (local_catalog_dir / fname).is_file(), (
            f"portable generator did not emit {fname} under {local_catalog_dir}"
        )

    # Ship the catalog files to the guest under <guest_root>/<catalog_name>/.
    guest_catalog_dir = f"{guest_root}/{catalog_name}"
    _ssh_check(vm, "/bin/rm", "-rf", guest_catalog_dir)
    _ssh_check(vm, "/bin/mkdir", "-p", guest_catalog_dir)
    for f in sorted(local_catalog_dir.iterdir()):
        if f.is_file():
            _scp_to_guest(vm, f, f"{guest_catalog_dir}/{f.name}")
    return guest_catalog_dir


def forge_foreign_pkg(src_pkg: Path, out_dir: Path, *, target_php: str, target_abi: str) -> Path:
    """Forge a .pkg that is NOT built for this box, from the branch .pkg.

    Re-reads the +COMPACT_MANIFEST, replaces every ``php8N`` dep key with ``target_php``,
    sets the ``abi`` to ``target_abi``, and repacks. No payload change — the dep/ABI
    mismatch is refused before pkg ever reads the files.

    The caller derives the target from THIS leg's own row (issue #2464: a FreeBSD major
    and a php this row does not use), never from another matrix row — two rows may
    legitimately share a build target, which would make the forgery a no-op.
    """
    tar_bytes = _zstd_decompress(src_pkg.read_bytes())
    repacked = io.BytesIO()
    pkg_name = ""
    with (
        tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tin,
        tarfile.open(fileobj=repacked, mode="w", format=tarfile.USTAR_FORMAT) as tout,
    ):
        for member in tin.getmembers():
            extracted = tin.extractfile(member) if member.isfile() else None
            data = extracted.read() if extracted is not None else b""
            if member.name in _PKG_MANIFEST_MEMBERS:
                obj = json.loads(data)
                # Swap every php8N dep for the target variant's php (CE manifest has
                # php83; forging a Plus pkg makes it php85, and vice-versa).
                if "deps" in obj:
                    old_deps: dict[str, object] = obj["deps"]
                    new_deps: dict[str, object] = {}
                    for key, val in old_deps.items():
                        if re.match(r"php8\d", key):
                            # Replace the key; keep the value dict unchanged (origin/version are fictional).
                            new_deps[target_php] = val
                        else:
                            new_deps[key] = val
                    obj["deps"] = new_deps
                # Set the target ABI: the box's own `pkg install` ABI-compatibility check is
                # the guard under test (a concrete-vs-wildcard bucket no longer exists —
                # issue #1806 — so this must be a wildcard ABI or the portable generator
                # itself hard-rejects it; callers pass "FreeBSD:<opp_major>:*").
                obj["abi"] = target_abi
                pkg_name = obj.get("name", pkg_name)
                data = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode() + b"\n"
                ti = tarfile.TarInfo(name=member.name)
                ti.size = len(data)
                ti.mode = 0o644
                ti.uid = ti.gid = 0
                ti.uname, ti.gname = "root", "wheel"
                ti.mtime = 0
                ti.type = tarfile.REGTYPE
                tout.addfile(ti, io.BytesIO(data))
            else:
                tout.addfile(member, io.BytesIO(data) if member.isfile() else None)
    if not pkg_name:
        raise RuntimeError(f"{src_pkg.name}: no +COMPACT_MANIFEST with a name — not a libpkg .pkg?")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{pkg_name}-{target_php}.pkg"
    out_path.write_bytes(_zstd_compress(repacked.getvalue()))
    return out_path


def pkg_query_deps(vm: SmokeVM, *, timeout: float = 60.0) -> str:
    """Return the raw ``pkg query '%dn %dv' <PKG_NAME>`` output (dep names + versions).

    Uses ``%dn`` (dep name) and ``%dv`` (dep version) — the correct per-dependency
    sub-field specifiers in libpkg's query format. ``%d`` alone is an iterator
    marker with no output; ``%v`` is the package's own version (not the dep's).
    """
    result = vm.ssh("pkg", "query", "%dn %dv", PKG_NAME, timeout=timeout)
    return result.stdout.strip() if result.returncode == 0 else ""


# --------------------------------------------------------------------------- #
# ADR-20 Case 1 — install from the box's variant-keyed catalog                 #
# --------------------------------------------------------------------------- #


@pytest.mark.timeout(600)
def test_install_from_variant_catalog(repo_vm: SmokeVM, tmp_path: Path) -> None:
    """ADR-20 P6 CASE 1 — the box's package installs from its variant-keyed
    ``<variant>/`` catalog (arch-less, NO_ARCH — issue #1806); its own php + Python
    deps resolve; origin is our repo.

    Scenario: package installed from the variant-correct catalog for THIS box.
      Background: hermetic file:// catalog at ``<own.catalog>/`` directly (no ABI
      leaf). The variant (ABI / php / Python flavor) comes from the ci-metadata
      matrix (SMOKE_ABI / SMOKE_PHP_VERSION / SMOKE_PY_FLAVOR), so each leg asserts
      the deps ITS OWN matrix row declares — no hardcoded flavor.

    The oracle is conformance to this leg's own matrix row, never a comparison with
    another row (issue #2464). Two rows may legitimately share a build target — CE 2.9
    and Plus 26.03 are both FreeBSD:16 / php85 — so "some other variant's php is absent"
    asserts nothing about this build and is unfalsifiable exactly when the two rows agree.

    Given the package ABSENT and a variant-keyed catalog under ``<variant>/``
      built from the branch .pkg by the pure-Python generator,
    When ``pkg install -y <pkgname>`` resolves from this catalog,
    Then ``pkg query '%dn %dv' <pkgname>`` shows the php dep AND the Python flavor this
      leg's matrix row declares, the built .pkg's manifest ABI is the NO_ARCH wildcard on
      that row's FreeBSD major, the version matches the branch .pkg, and the origin is
      our repo.
    Assert BEFORE: ``pkg query '%n' <pkgname>`` returns empty (package absent).
    Assert AFTER: dep list contains this row's php + Python flavor; manifest ABI matches
      this row's FreeBSD major; version and origin correct.
    """
    pkg = os.environ.get("SMOKE_PKG")
    assert pkg and Path(pkg).is_file(), "SMOKE_PKG not set / not a file"

    own = own_variant()

    # GIVEN: build the box's variant catalog with the variant-keyed dir on the runner,
    # ship to guest, write a NONE-signed file:// repo conf above pfSense.
    catalog_dir = build_repo_via_portable_named(
        repo_vm,
        [Path(pkg), *_smoke_dep_pkg_paths()],
        tmp_path,
        catalog_name=own.catalog,
        guest_root=VARIANT_REPO_ROOT,
    )
    pfsense_prio = repo_priority(repo_vm, NETGATE_REPO_NAME)
    pkg_delete(repo_vm)
    write_repo_conf(repo_vm, catalog_dir, ours_priority=pfsense_prio + 100)

    # Before-state: package absent.
    pkg_update(repo_vm)
    before_name = vm_pkg_query_name(repo_vm)
    assert before_name == "", f"package unexpectedly present before variant install: {before_name!r}"

    # WHEN: install from the box's variant catalog (no -r, no -f).
    proc = pkg_install_from_repo(repo_vm)
    combined = proc.stdout + proc.stderr
    assert "Missing dependency" not in combined, f"variant catalog: RUN_DEPENDS did not resolve:\n{combined}"

    # THEN: dep list carries the php + Python flavor THIS leg's matrix row declares.
    deps_out = pkg_query_deps(repo_vm)
    assert own.php in deps_out, (
        f"{own.php} dep not satisfied after {own.abi} variant install; pkg query '%dn %dv' output:\n{deps_out}"
    )
    py_flavor = matrix_py_flavor()
    assert py_flavor in deps_out, (
        f"matrix Python flavor {py_flavor} not in deps after variant install; pkg query '%dn %dv' output:\n{deps_out}"
    )
    origin = pkg_repo_origin(repo_vm)
    assert origin == OURS_REPO_NAME, f"variant install: came from {origin!r}, expected {OURS_REPO_NAME!r}"
    version = pkg_installed_version(repo_vm)
    assert version is not None, "variant install: pkg query %v returned empty after install"

    # AND the .pkg this leg built declares the ABI its own matrix row implies: the NO_ARCH
    # wildcard on that row's FreeBSD major (issue #1806 — the catalog is arch-less, so the
    # manifest carries "FreeBSD:<major>:*", never the concrete guest ABI).
    own_major = own.abi.split(":")[1]
    manifest_abi = read_compact_manifest(Path(pkg)).get("abi")
    assert manifest_abi == f"FreeBSD:{own_major}:*", (
        f"built .pkg declares abi {manifest_abi!r}, but this leg's matrix row "
        f"({own.variant} / {own.catalog} / {own.abi}) implies 'FreeBSD:{own_major}:*'"
    )


def vm_pkg_query_name(vm: SmokeVM, *, timeout: float = 60.0) -> str:
    """``pkg query '%n' <PKG_NAME>`` — the package name if installed, else empty string."""
    result = vm.ssh("pkg", "query", "%n", PKG_NAME, timeout=timeout)
    return result.stdout.strip() if result.returncode == 0 else ""


# --------------------------------------------------------------------------- #
# ADR-20 Case 2 — a package that is NOT built for this box must not install    #
# --------------------------------------------------------------------------- #


@pytest.mark.timeout(900)
def test_foreign_build_target_catalog_fails(repo_vm: SmokeVM, tmp_path: Path) -> None:
    """ADR-20 P6 CASE 2 — a .pkg whose build target contradicts THIS leg's row does not
    install; the package is absent after the attempt.

    The forged target is derived from this leg's own row (issue #2464): the next FreeBSD
    major, and a php this row does not use. It is deliberately NOT "the other edition's"
    package — two matrix rows may share a build target (CE 2.9 and Plus 26.03 are both
    FreeBSD:16 / php85), which would make that forgery identical to the box's own build
    and the assertion unfalsifiable. What ADR-20 asks is narrower and row-local: a build
    that is not this row's must never install silently.

    Before-state ASSERT: the box's OWN package installs CLEANLY (own php dep satisfied) —
      proves the own path works, so the AFTER failure is the forgery, not broken setup.
    Given the own package uninstalled and the repo conf pointing at the foreign catalog,
    When ``pkg install -y <pkgname>`` runs against it,
    Then the install fails or the package is absent, the output names a pkg-level cause
      (the foreign php dep, the foreign ABI, an ABI/OS rejection, or no candidate),
      AND ``pkg query '%n' <pkgname>`` confirms the package is NOT installed.
    """
    pkg = os.environ.get("SMOKE_PKG")
    assert pkg and Path(pkg).is_file(), "SMOKE_PKG not set / not a file"
    src = Path(pkg)

    own = own_variant()
    own_major = own.abi.split(":")[1]
    # Derived from THIS row, not from a sibling row: the next major up, and any php that is
    # not this row's. Both are what makes the package foreign to this box.
    foreign_major = str(int(own_major) + 1)
    foreign_php = "php83" if own.php != "php83" else "php85"
    foreign_catalog = f"foreign-fbsd{foreign_major}"

    # ---- Before-state: prove the box's OWN path works (the control) ----
    own_catalog_dir = build_repo_via_portable_named(
        repo_vm,
        [src, *_smoke_dep_pkg_paths()],
        tmp_path,
        catalog_name=own.catalog,
        guest_root=VARIANT_REPO_ROOT,
    )
    pfsense_prio = repo_priority(repo_vm, NETGATE_REPO_NAME)
    pkg_delete(repo_vm)
    write_repo_conf(repo_vm, own_catalog_dir, ours_priority=pfsense_prio + 100)
    pkg_update(repo_vm)
    assert vm_pkg_query_name(repo_vm) == "", "package unexpectedly present before the control install"

    own_install = pkg_install_from_repo(repo_vm)
    own_combined = own_install.stdout + own_install.stderr
    assert "Missing dependency" not in own_combined, (
        f"Control ({own.abi}) install: RUN_DEPENDS did not resolve:\n{own_combined}"
    )
    own_deps = pkg_query_deps(repo_vm)
    assert own.php in own_deps, f"Control ({own.abi}) install: {own.php} not in deps; pkg query '%dn %dv':\n{own_deps}"

    # ---- Forge a .pkg for a build target this row does not have ----
    # The portable generator hard-rejects a concrete ABI (issue #1806 — production catalogs
    # only hold wildcard/NO_ARCH pkgs), so the forged ABI is wildcarded to the foreign major.
    foreign_pkg = forge_foreign_pkg(
        src, tmp_path / "foreign_forge", target_php=foreign_php, target_abi=f"FreeBSD:{foreign_major}:*"
    )
    # Deliberately NOT folding in _smoke_dep_pkg_paths(): this catalog exists only to be
    # REJECTED (foreign build target, not dep resolution), and those deps belong to the
    # box's own major.
    foreign_catalog_dir = build_repo_via_portable_named(
        repo_vm,
        [foreign_pkg],
        tmp_path,
        catalog_name=foreign_catalog,
        guest_root=VARIANT_REPO_ROOT,
    )

    pkg_delete(repo_vm)
    assert vm_pkg_query_name(repo_vm) == "", "package still present after pkg_delete"
    write_repo_conf(repo_vm, foreign_catalog_dir, ours_priority=pfsense_prio + 100)
    try:
        pkg_update(repo_vm)
    except RuntimeError:
        # pkg update may itself fail on the ABI mismatch — that IS the guard firing.
        pass

    install_result = repo_vm.ssh("env", "ASSUME_ALWAYS_YES=yes", "pkg", "install", "-y", PKG_NAME, timeout=300.0)
    install_failed = install_result.returncode != 0
    install_output = install_result.stdout + install_result.stderr
    package_installed = vm_pkg_query_name(repo_vm) != ""

    assert install_failed or not package_installed, (
        f"Foreign-target guard did NOT fire: a FreeBSD:{foreign_major} package installed on a "
        f"{own.abi} box.\npkg install rc={install_result.returncode}\n"
        f"pkg install output:\n{install_output}\npkg query '%n': {vm_pkg_query_name(repo_vm)!r}"
    )
    # AND the failure names a CAUSE, not merely a non-zero exit. `install_failed` is
    # deliberately NOT one of these clauses: it is already asserted above, so including it
    # would make every other clause unreachable (issue #1965).
    lowered = install_output.lower()
    reasons = {
        f"names the foreign php dep ({foreign_php})": foreign_php in install_output,
        f"names the foreign ABI (FreeBSD:{foreign_major})": f"freebsd:{foreign_major}" in lowered,
        "reports an ABI / OS-version rejection": any(
            kw in lowered for kw in ("wrong abi", "wrong os version", "mismatch", "incompatible")
        ),
        "reports no installable candidate from the catalog": any(
            kw in lowered for kw in ("no packages available", "not found", "missing dependency", "unable to find")
        ),
    }
    assert any(reasons.values()), (
        f"The foreign-target install failed, but for no attributable reason — the guard under "
        f"test may not be what fired.\nexpected at least one of: {sorted(reasons)}\n"
        f"actual: {reasons}\nrc={install_result.returncode}\n{install_output}"
    )
    assert not package_installed, (
        f"Foreign-target guard: package IS installed despite the expected failure; "
        f"pkg query '%n': {vm_pkg_query_name(repo_vm)!r}"
    )


# ADR-20 Case 3 (legacy ${ABI}/ conf transition window) retired: issue #1806 made
# every catalog arch-less and deliberately broke existing alpha confs (owner decision).
# N -> N+1 upgrade coverage is retained by test_pkg_upgrade_moves_to_our_newer_build
# above (uses build_guest_repo, untouched by the arch-less rework).

# =========================================================================== #
# ADR-27 Phase 10 — EOL route-only install from a frozen catalog              #
#                                                                              #
# Proves the Part-2 (route-only distribution) path end-to-end on a REAL       #
# pfSense guest: a frozen .pkg forged from the branch build, served via the    #
# Phase-7 route-only generator (--build-matrix + --route-only-pkgs), is       #
# installable by a real pfSense box — and NO nightly subtree was ever emitted  #
# for the EOL varver (the structural no-nightly guarantee).                    #
#                                                                              #
# Marker: @pytest.mark.repo (inherited from pytestmark = pytest.mark.repo).   #
# Deselected from default `python -m pytest` — dispatched via:                #
#     gh workflow run smoke-single.yml -f pytest_marker=repo                          #
# =========================================================================== #


def _build_eol_catalog_on_runner(
    frozen_pkg: Path,
    eol_varver: str,
    eol_pfsense_version: str,
    variant: str,
    freebsd_major: str,
    php_version: str,
    py_flavor: str,
    out_dir: Path,
) -> Path:
    """Build a route-only (EOL) catalog on the runner via ``--build-matrix --route-only-pkgs``.

    Runs ``build-repo-portable.py --build-matrix`` with a synthetic route-only
    matrix entry and ``--route-only-pkgs <eol_varver>:<frozen_pkg>``.  The new
    Phase-10 CLI flag is exercised end-to-end here — this is the exact invocation
    shape publish.yml uses for real EOL versions. The matrix carries no ``arch`` key
    any more (retired by issue #1806 — every catalog is arch-less/NO_ARCH).

    Returns the runner-side ``release/<eol_varver>/`` directory whose files will be
    shipped to the guest.
    """
    matrix_entry = {
        "pfsense_version": eol_pfsense_version,
        "variant": variant,
        "freebsd_major": freebsd_major,
        "php_version": php_version,
        "py_flavor": py_flavor,
        "status": "EOL",
        "role": "route-only",
    }
    proc = subprocess.run(
        [
            sys.executable,
            str(BUILD_REPO_PORTABLE),
            "--build-matrix",
            "--matrix-json",
            "-",
            "--out",
            str(out_dir),
            "--no-nightly",
            "--route-only-pkgs",
            f"{eol_varver}:{frozen_pkg}",
        ],
        input=json.dumps([matrix_entry]),
        capture_output=True,
        text=True,
        timeout=120.0,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"build-repo-portable.py --build-matrix (route-only) failed: rc={proc.returncode}\n"
            f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    release_dir = out_dir / "release" / eol_varver
    assert release_dir.is_dir(), f"route-only generator did not emit release/{eol_varver}/ under {out_dir}"
    for fname in ("meta.conf", "meta", "packagesite.pkg", "data.pkg"):
        assert (release_dir / fname).is_file(), f"route-only generator did not emit {fname} under {release_dir}"
    return release_dir


@pytest.mark.timeout(900)  # forge + catalog gen + pkg ops on a real guest > 30 s cap.
def test_eol_route_only_install_from_frozen_catalog(repo_vm: SmokeVM, tmp_path: Path) -> None:
    """ADR-27 P10 KILL-GATE: a REAL pfSense box installs from a route-only (EOL)
    frozen catalog built by the Phase-7 generator path (``--build-matrix --route-only-pkgs``).

    The variant (ABI / PHP / Python / edition) is derived from the version matrix
    (``own_variant()``) — never hardcoded.  A synthetic EOL pfSense version
    (``"1.99"``, varver ``"<edition>-1.99"``) is used so no real matrix entry is
    flipped to route-only by this test.  The frozen ``.pkg`` is forged from the
    branch build using ``reversion_pkg`` (payload untouched, only the version string
    changed).

    No-nightly assertion is on the RUNNER (structural guarantee, Phase 7): the
    ``nightly/<eol_varver>/`` directory must NOT exist in the generator output before
    the catalog is shipped to the guest.

    Scenario: EOL install from a frozen catalog
      Background:
        - own_variant() gives this leg's ABI (FreeBSD:NN:arch), edition, PHP/Python.
        - A synthetic EOL varver ``<edition.lower()>-1.99`` is computed.
        - A frozen .pkg is forged: ``<base_version>_frozen`` (reversion_pkg).
        - Route-only catalog built ON THE RUNNER via --build-matrix + --route-only-pkgs.
        - NONE-signed file:// repo conf pointing at the EOL catalog shipped to the guest.

    Given the package ABSENT and the EOL catalog carried by the frozen version,
      And ``nightly/<eol_varver>/`` does NOT exist in the runner-side catalog output
        (the no-nightly structural guarantee),
    When ``pkg install -y <name>`` runs on the guest (no -f, no -r),
    Then the frozen version is active (``pkg query %v`` == ``<base>_frozen``),
      the origin is OUR repo (``pkg query %R`` == ``pfblockerng``),
      and ``Missing dependency`` is absent (RUN_DEPENDS resolved from the catalog).
    """
    pkg = os.environ.get("SMOKE_PKG")
    assert pkg and Path(pkg).is_file(), "SMOKE_PKG not set / not a file"  # repo_vm already gated this
    src = Path(pkg)

    own = own_variant()

    # Synthetic EOL pfSense version — never a real matrix entry, so no production
    # entry is accidentally flipped to route-only by this test.
    eol_pfsense_version = "1.99"
    eol_varver = f"{own.variant.lower()}-1.99"

    # Split the ABI string "FreeBSD:<major>:<arch>" to get the major (the arch
    # segment is no longer needed anywhere — the catalog is arch-less, NO_ARCH,
    # issue #1806).
    freebsd_major = own.abi.split(":")[1]

    # Derive the PHP version string expected by the matrix entry (e.g. "8.3" from "php83").
    # own.php is "php83" / "php85" — strip "php" and re-insert the dot: "83" → "8.3".
    raw_php = own.php.removeprefix("php")  # e.g. "83"
    php_version = raw_php[0] + "." + raw_php[1:]  # e.g. "8.3"

    # Forge the "last supported" frozen .pkg: same payload as the branch build, new version.
    base_version = read_compact_version(src)
    frozen_version = f"{base_version}_frozen"
    frozen_pkg = reversion_pkg(src, frozen_version, tmp_path / "eol_frozen")

    pfsense_prio = repo_priority(repo_vm, NETGATE_REPO_NAME)

    # ---- Build the route-only (EOL) catalog ON THE RUNNER (no guest involved). ----
    # Uses --build-matrix + --route-only-pkgs — the exact CLI shape publish.yml will use.
    # issue #1828: route-only catalogs accept post-#1806 wildcard-ABI assets, but
    # --dep-pkgs never folds into a route-only entry. This frozen catalog therefore
    # cannot carry SMOKE_DEP_PKGS even though the frozen .pkg declares the same
    # RUN_DEPENDS.
    eol_out_dir = tmp_path / "eol_catalog_out"
    local_release_dir = _build_eol_catalog_on_runner(
        frozen_pkg,
        eol_varver,
        eol_pfsense_version,
        own.variant,
        freebsd_major,
        php_version,
        own.py,
        eol_out_dir,
    )

    # GIVEN (runner-side before-state): no nightly subtree was emitted for the EOL varver.
    # Structural guarantee (Phase 7): the route-only branch in build_repo_matrix never
    # reaches the nightly code path.  Assert it BEFORE shipping to the guest so the
    # no-nightly guarantee is proven unconditionally (not just absent from the guest).
    assert not (eol_out_dir / "nightly" / eol_varver).exists(), (
        f"nightly/{eol_varver}/ must NOT exist for a route-only entry — "
        f"the no-nightly structural guarantee (Phase 7) is violated"
    )

    try:
        # ---- Ship the EOL catalog tree to the guest. ----
        # Ship the release/<eol_varver>/ files directly (arch-less, NO_ARCH — issue
        # #1806); the guest conf points directly at the on-guest varver directory.
        guest_catalog_dir = f"{EOL_REPO_ROOT}/{eol_varver}"
        _ssh_check(repo_vm, "/bin/rm", "-rf", EOL_REPO_ROOT)
        _ssh_check(repo_vm, "/bin/mkdir", "-p", guest_catalog_dir)
        for f in sorted(local_release_dir.iterdir()):
            if f.is_file():
                _scp_to_guest(repo_vm, f, f"{guest_catalog_dir}/{f.name}")

        # --- GIVEN: package absent; EOL catalog enabled above the pfSense repo. ---
        pkg_delete(repo_vm)
        write_repo_conf(repo_vm, guest_catalog_dir, ours_priority=pfsense_prio + 100)
        pkg_update(repo_vm)
        before_version = pkg_installed_version(repo_vm)
        assert before_version is None, (
            f"{PKG_NAME} unexpectedly present before EOL install (version: {before_version!r})"
        )

        # --- WHEN: pkg install across ALL enabled repos, no -r/-f. ---
        proc = pkg_install_from_repo(repo_vm)

        # --- THEN: frozen version installed from our repo; deps resolved. ---
        combined = proc.stdout + proc.stderr
        assert "Missing dependency" not in combined, f"EOL frozen install: RUN_DEPENDS did not resolve:\n{combined}"
        installed = pkg_installed_version(repo_vm)
        assert installed == frozen_version, (
            f"EOL frozen install: expected {frozen_version!r}, got {installed!r} — "
            f"wrong version installed from the route-only catalog"
        )
        origin = pkg_repo_origin(repo_vm)
        assert origin == OURS_REPO_NAME, (
            f"EOL frozen install: origin {origin!r}, expected {OURS_REPO_NAME!r} — "
            f"pkg did not install from our route-only catalog"
        )
    finally:
        pkg_delete(repo_vm)
        repo_vm.ssh("/bin/rm", "-rf", EOL_REPO_ROOT, timeout=60.0)
        # REPO_CONF and GUEST_SPIKE_DIR teardown runs in the repo_vm module fixture.


# =========================================================================== #
# ADR-39 — boot-time repo-conf generator rc.d hook                            #
#                                                                              #
# Proves the generator hook on a REAL pfSense VM:                             #
#   1. ORPHAN path: no conf -> hook exits 0, writes nothing (boot-safe).      #
#   2. REGENERATE path: a conf carrying a STALE varver (as after an OS        #
#      upgrade) is unconditionally overwritten with the box's CURRENT         #
#      <varver> (arch-less, NO_ARCH — issue #1806); the corrected conf then   #
#      resolves our package via pkg update + install (end-to-end, file://    #
#      catalog). The hook's folded detection is cross-checked against an     #
#      independent Python oracle.                                            #
#   3. IDEMPOTENCE: a second run leaves the conf byte-identical (pure regen).  #
#                                                                              #
# The hook runs as a POSIX-sh rc.d script. Off the rc(8) framework it runs    #
# its *_start directly (its own else-branch), so we drive it as              #
# `/bin/sh <hook> onestart`. Env-overridable paths (PFB_STABLE_CONF,          #
# PFB_NIGHTLY_CONF, PFB_BASE_URL) point it at test fixtures + a file://       #
# catalog without modifying the production script. NO pkg call, NO network.   #
#                                                                              #
# Marker: @pytest.mark.repo (inherited from pytestmark).                      #
# Dispatch: gh workflow run smoke-single.yml -f pytest_marker=repo                   #
# =========================================================================== #

# Working directory on the guest for the generator-hook test.
GENERATE_DIR = "/tmp/pfb_generate_test"
# On-box path where install.sh installs the hook (production).
GUEST_HOOK_PATH = "/usr/local/etc/rc.d/pfblockerng_repo_generate.sh"

# Source path for the hook (runner side).
GENERATE_HOOK_SRC = Path(__file__).resolve().parents[2] / "src/usr/local/etc/rc.d/pfblockerng_repo_generate.sh"


def _stage_generate_hook(vm: SmokeVM, *, guest_hook: str) -> None:
    """Copy the generator hook to the guest (detection is folded in — no helper)."""
    _ssh_check(vm, "/bin/mkdir", "-p", GENERATE_DIR)
    _ssh_check(vm, "/bin/mkdir", "-p", "/".join(guest_hook.split("/")[:-1]))
    _scp_to_guest(vm, GENERATE_HOOK_SRC, guest_hook)
    _ssh_check(vm, "/bin/chmod", "755", guest_hook)


def _box_real_varver(vm: SmokeVM) -> str:
    """Independent Python oracle for the box's ``<varver>`` (cross-checks the hook).

    Mirrors the hook's folded detection: edition = "/etc/product_label contains 'Plus'"
    (absent file -> CE, matching the hook's grep-on-missing-file = CE), version =
    major.minor of /etc/version with any ``-BETA``-style dash suffix stripped FIRST
    (mirrors the production hook's own strip, issue #1806: a bare ``ver.split(".")[:2]``
    over ``"26.07-BETA"`` yields ``"plus-26.07-BETA"``, a varver ``build-repo.sh``'s
    lowercase-varver guard rejects). The catalog is arch-less (NO_ARCH; issue #1806) —
    there is no ``arch`` component any more.
    """
    label = vm.ssh("/bin/cat", "/etc/product_label", timeout=30.0)
    edition = "plus" if (label.returncode == 0 and "Plus" in label.stdout) else "ce"
    ver = _ssh_check(vm, "/bin/cat", "/etc/version").stdout.strip()
    ver = ver.split("-", 1)[0]
    mm = ".".join(ver.split(".")[:2])
    assert mm, f"oracle could not resolve box varver: ver={ver!r}"
    return f"{edition}-{mm}"


def _read_conf_url_on_guest(vm: SmokeVM, conf_path: str) -> str:
    """Read the ``url:`` value from a conf file on the guest; returns the bare URL string."""
    # POSIX class [[:space:]] — NOT GNU \s: BSD grep -E (FreeBSD/pfSense) treats \s as a
    # literal 's', so ^\s*url: would not match the space-indented `  url:` conf line.
    result = _ssh_check(vm, "grep", "-E", r"^[[:space:]]*url:", conf_path)
    # url: "https://..."  -> strip the key, whitespace, and surrounding quotes.
    raw = result.stdout.strip()
    match = re.search(r'url:\s*"([^"]+)"', raw)
    if not match:
        raise RuntimeError(f"could not parse url: line from {conf_path!r}: {raw!r}")
    return match.group(1)


def _run_generate_hook(
    vm: SmokeVM,
    *,
    stable_conf: str,
    base_url: str | None = None,
    nightly_conf: str | None = None,
    timeout: float = 300.0,
) -> subprocess.CompletedProcess[str]:
    """Run the generator hook directly as ``/bin/sh <hook> onestart``.

    Driven with its env-overridable paths pointing at the test fixtures:
    ``PFB_STABLE_CONF``, ``PFB_NIGHTLY_CONF``, and optionally ``PFB_BASE_URL`` (a
    file:// catalog base). ``nightly_conf`` defaults to a genuinely NON-EXISTENT path
    (not ``/dev/null`` — that exists and would defeat the orphan guard's ``[ -f ]``
    test conceptually), so by default only the stable conf is in play. Detection
    reads the real box files (/etc/product_label, /etc/version, pkg config abi).

    Returns the completed process. The hook MUST always exit 0 (a non-zero rc is an
    immediate test failure — the ADR-39 "always exit 0" boot-safety rule).
    """
    if nightly_conf is None:
        nightly_conf = f"{GENERATE_DIR}/nonexistent_pfblockerng_nightly.conf"
    env_args = [f"PFB_STABLE_CONF={stable_conf}", f"PFB_NIGHTLY_CONF={nightly_conf}"]
    if base_url is not None:
        env_args.append(f"PFB_BASE_URL={base_url}")
    result = vm.ssh("env", *env_args, "/bin/sh", GUEST_HOOK_PATH, "onestart", timeout=timeout)
    assert result.returncode == 0, (
        f"generator hook exited {result.returncode} (MUST always be 0 — boot-safety violation):\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    return result


@pytest.mark.timeout(60)
def test_generate_hook_safety_absent_conf_exits_0(repo_vm: SmokeVM) -> None:
    """ADR-39 ORPHAN PATH: when the stable conf is ABSENT the hook exits 0 and writes nothing.

    An orphaned hook (conf removed by the user after removing the repo) must be inert —
    it must not wedge boot or create a channel the user never bootstrapped.

    Scenario: generator hook with no repo conf is a safe no-op.

    Given NEITHER our stable conf NOR our nightly conf exists (both ``PFB_*_CONF``
      point at genuinely non-existent paths),
    When ``/bin/sh <hook> onestart`` runs with those overrides,
    Then the hook exits 0 (MUST — boot-safety hard rule) AND neither conf was created.
    Assert BEFORE: both conf paths do NOT exist.
    Assert AFTER: both conf paths still do NOT exist; exit code 0.
    """
    _stage_generate_hook(repo_vm, guest_hook=GUEST_HOOK_PATH)
    try:
        absent_conf = f"{GENERATE_DIR}/nonexistent_pfblockerng.conf"
        absent_nightly = f"{GENERATE_DIR}/nonexistent_pfblockerng_nightly.conf"

        # BEFORE: neither conf exists (a genuinely-absent nightly path, NOT /dev/null —
        # so the orphan guard is exercised for real on both channels).
        assert repo_vm.ssh("/bin/test", "-f", absent_conf).returncode != 0, (
            f"BEFORE: stable conf unexpectedly exists at {absent_conf}"
        )
        assert repo_vm.ssh("/bin/test", "-f", absent_nightly).returncode != 0, (
            f"BEFORE: nightly conf unexpectedly exists at {absent_nightly}"
        )

        # WHEN: run the hook with both conf paths non-existent.
        _run_generate_hook(repo_vm, stable_conf=absent_conf, nightly_conf=absent_nightly)

        # AFTER: both confs still absent; hook was a no-op (created no channel).
        assert repo_vm.ssh("/bin/test", "-f", absent_conf).returncode != 0, (
            f"AFTER: hook orphan guard FAILED — it created {absent_conf} when the conf was absent"
        )
        assert repo_vm.ssh("/bin/test", "-f", absent_nightly).returncode != 0, (
            f"AFTER: hook orphan guard FAILED — it created {absent_nightly} when the conf was absent"
        )
    finally:
        # _stage_generate_hook copies to the PRODUCTION rc.d path — remove it so a
        # staged hook never survives into a later module sharing this guest.
        repo_vm.ssh("/bin/rm", "-f", GUEST_HOOK_PATH, timeout=60.0)
        repo_vm.ssh("/bin/rm", "-rf", GENERATE_DIR, timeout=60.0)


@pytest.mark.timeout(600)  # forge build + catalog gen + conf regen + pkg update/install > 30s cap.
def test_generate_hook_rewrites_stale_varver_and_resolves(repo_vm: SmokeVM, tmp_path: Path) -> None:
    """ADR-39 REGENERATE PATH: a stale ``<varver>`` in the conf is rewritten to the box's current one.

    Simulates a post-OS-upgrade boot where the conf still points at an OLD varver. The
    hook unconditionally REGENERATES the conf for the box's CURRENT ``<varver>``
    (folded detection; arch-less, NO_ARCH — issue #1806), and the corrected conf then
    resolves our package end-to-end via ``pkg update`` + ``pkg install`` against a
    file:// catalog. The hook's detection is cross-checked against an independent
    Python oracle (``_box_real_varver``) — if they disagree the catalog is not found
    and ``pkg install`` fails loud. A second run leaves the conf byte-identical (pure
    regenerate, no patching).

    Scenario:
      Background: a file:// catalog at ``<base>/stable/<real_varver>/``; the seeded
        conf url initially points at ``<base>/stable/stale-9.9`` (wrong).
      Given the conf carries the stale varver (BEFORE asserted),
      When  the generator hook runs with ``PFB_BASE_URL=<file:// base>``,
      Then  the conf url contains the box's REAL varver (stale gone) and the canonical
            marker, ``pkg update`` accepts it, and our package installs with its files;
      And   a second hook run leaves the conf byte-identical.
    """
    pkg = os.environ.get("SMOKE_PKG")
    assert pkg and Path(pkg).is_file(), "SMOKE_PKG not set / not a file"  # repo_vm already gated this

    _stage_generate_hook(repo_vm, guest_hook=GUEST_HOOK_PATH)

    # Independent oracle for the box's real <varver> (cross-checks the hook's folded
    # detection — a disagreement makes the catalog unreachable below).
    real_varver = _box_real_varver(repo_vm)

    STALE_VARVER = "stale-9.9"

    catalog_base = f"{GENERATE_DIR}/catalog"
    base_url = f"file://{catalog_base}"
    guest_real_dir = f"{catalog_base}/stable/{real_varver}"
    test_conf_path = f"{GENERATE_DIR}/pfblockerng_test.conf"

    try:
        # 1. Build the real catalog on the guest under stable/<real_varver>/ — the
        #    PRODUCTION layout (build_repo_matrix, arch-less — issue #1806) that the
        #    hook's regenerated conf resolves to.
        shipped_dir = build_repo_via_portable_named(
            repo_vm,
            [Path(pkg), *_smoke_dep_pkg_paths()],
            tmp_path,
            catalog_name=f"stable/{real_varver}",
            guest_root=catalog_base,
        )
        assert shipped_dir == guest_real_dir, f"catalog shipped to {shipped_dir!r}, expected {guest_real_dir!r}"
        assert _ssh_check(repo_vm, "/bin/test", "-d", guest_real_dir).returncode == 0, (
            f"real catalog dir {guest_real_dir} not created on guest"
        )

        # 2. Seed the TEST conf with a STALE varver url (canonical body shape).
        stale_url = f"{base_url}/stable/{STALE_VARVER}"
        stale_conf_body = (
            "# pending boot-time generation\n"
            "pfblockerng-stable: {\n"
            f'  url: "{stale_url}",\n'
            "  mirror_type: none,\n"
            "  signature_type: none,\n"
            "  priority: 100,\n"
            "  enabled: yes\n"
            "}\n"
        )
        written = subprocess.run(
            repo_vm.ssh_argv("tee", test_conf_path),
            input=stale_conf_body,
            capture_output=True,
            text=True,
            timeout=30.0,
            check=False,
        )
        if written.returncode != 0:
            raise RuntimeError(f"writing test conf failed: rc={written.returncode} {written.stderr!r}")

        # BEFORE: conf carries the stale varver, not the real one.
        url_before = _read_conf_url_on_guest(repo_vm, test_conf_path)
        assert STALE_VARVER in url_before, f"BEFORE: expected stale varver {STALE_VARVER!r} in url, got {url_before!r}"
        assert real_varver not in url_before, (
            f"BEFORE: conf url already contains the real varver {real_varver!r}: {url_before!r}"
        )

        # WHEN: run the generator hook (file:// base) — it regenerates the conf.
        hook_result = _run_generate_hook(repo_vm, stable_conf=test_conf_path, base_url=base_url)

        # AFTER: conf url has the box's REAL varver (stale gone) + the canonical marker.
        url_after = _read_conf_url_on_guest(repo_vm, test_conf_path)
        assert real_varver in url_after, (
            f"AFTER: hook did not regenerate to {real_varver!r}, got {url_after!r}\n"
            f"Hook stdout:\n{hook_result.stdout}\nHook stderr:\n{hook_result.stderr}"
        )
        assert STALE_VARVER not in url_after, (
            f"AFTER: stale varver {STALE_VARVER!r} still in conf url after hook ran: {url_after!r}"
        )
        marker = _ssh_check(repo_vm, "grep", "-q", "Generated at boot by pfblockerng_repo_generate", test_conf_path)
        assert marker.returncode == 0, "AFTER: regenerated conf is missing the marker line"

        # AFTER: the corrected conf resolves our package end-to-end (file:// catalog).
        # (pkg reads /usr/local/etc/pkg/repos/pfblockerng.conf, not our test path.)
        pkg_delete(repo_vm)
        result_copy = subprocess.run(
            repo_vm.ssh_argv("cp", test_conf_path, REPO_CONF),
            capture_output=True,
            text=True,
            timeout=30.0,
            check=False,
        )
        if result_copy.returncode != 0:
            raise RuntimeError(f"copying corrected conf to {REPO_CONF} failed: {result_copy.stderr!r}")
        pkg_update(repo_vm)
        pkg_install_from_repo(repo_vm)
        installed_after = pkg_installed_version(repo_vm)
        assert installed_after is not None, "AFTER: package not installed from the corrected conf"
        file_count = assert_all_pkg_files_present(repo_vm)
        assert file_count > 50, f"AFTER: only {file_count} registered files — implausibly few for pfBlockerNG"

        # IDEMPOTENCE: a second run leaves the conf byte-identical (pure regenerate).
        sha_before = _ssh_check(repo_vm, "sha256", "-q", test_conf_path).stdout.strip()
        _run_generate_hook(repo_vm, stable_conf=test_conf_path, base_url=base_url)
        sha_after = _ssh_check(repo_vm, "sha256", "-q", test_conf_path).stdout.strip()
        assert sha_before == sha_after, (
            f"IDEMPOTENCE: conf changed on a second hook run ({sha_before!r} -> {sha_after!r})"
        )

    finally:
        pkg_delete(repo_vm)
        repo_vm.ssh("/bin/rm", "-rf", GENERATE_DIR, timeout=60.0)
        # _stage_generate_hook copied this to the PRODUCTION rc.d path — remove it so a
        # staged hook never survives into a later module sharing this guest.
        repo_vm.ssh("/bin/rm", "-f", GUEST_HOOK_PATH, timeout=60.0)
        # REPO_CONF is cleaned by the repo_vm module fixture teardown.


# =========================================================================== #
# issue #2148 — the four-channel client contract                              #
#                                                                              #
# Four channels — stable, testing, edge, nightly — each own a pkg repository   #
# `pfblockerng-<channel>` (conf `pfblockerng-<channel>.conf`) and ALL FOUR     #
# publish the ONE canonical identity `pfSense-pkg-pfBlockerNG`: channel is     #
# catalogue placement, never a package-name suffix. The legacy shared release  #
# repo `pfblockerng` (conf `pfblockerng.conf`) is the only one that ever       #
# carried a suffixed identity (`pfSense-pkg-pfBlockerNG-devel`).               #
#                                                                              #
# Two consequences the cases below pin on a real box:                          #
#   * SINGLE-REPOSITORY SUBSCRIPTION — every project repo shares priority 100  #
#     and `pkg` does not order across equal-priority repositories, so exactly  #
#     ONE project conf may exist. install.sh retires the others.              #
#   * The installed package NAME can no longer identify the channel, so the    #
#     repository it came from (`pkg query '%R'`) is the only authority — and   #
#     `pkg` never moves an installed package across repositories on its own,   #
#     which is why install.sh's converge step is repository-                  #
#     qualified.                                                              #
#                                                                              #
# Marker: @pytest.mark.repo (inherited from pytestmark).                       #
# Dispatch: gh workflow run smoke-single.yml -f pytest_marker=repo             #
# =========================================================================== #

# The four channels, in the order install.sh's PROJECT_CONFS enumerates them.
CHANNELS = ("stable", "testing", "edge", "nightly")

# The ONE identity every channel catalogue publishes, and the legacy suffixed identity a
# box installed from the shared release repo still carries until it is migrated.
CANONICAL_PKG_NAME = "pfSense-pkg-pfBlockerNG"
LEGACY_DEVEL_PKG_NAME = f"{CANONICAL_PKG_NAME}-devel"

# The on-box repo-conf directory — derived from REPO_CONF so the two can never drift.
PKG_REPOS_DIR = REPO_CONF.rsplit("/", 1)[0]
LEGACY_RELEASE_CONF_NAME = REPO_CONF.rsplit("/", 1)[1]

# Every conf install.sh's PROJECT_CONFS may ever have written. Exactly ONE
# may be present on a box; `test_project_conf_names_match_the_shipped_scripts`
# pins this tuple to that script.
PROJECT_CONF_NAMES = (LEGACY_RELEASE_CONF_NAME, *(f"pfblockerng-{channel}.conf" for channel in CHANNELS))

# Guest root for the four channel catalogues + the legacy release catalogue (isolated
# from GUEST_SPIKE_DIR so the ADR-17 cases above are unaffected).
CHANNEL_REPO_ROOT = "/tmp/pfb_channel_repo"

# The engine under test — the SOLE client entry point, --channel parameterized
# (issue #2416 follow-up).
INSTALL_SH = Path(__file__).resolve().parents[2] / "scripts" / "install.sh"

# Distinct PORTREVISIONs per catalogue, so `pkg query %v` alone identifies WHICH
# catalogue served a build (a `%R` assertion that happened to be right for the wrong
# reason cannot hide behind an identical version). `edge` carries TWO: `_3` is its own
# build and `_1` is the stable-era build it still contains — each channel catalogue
# strictly contains its slower channels' files, which is what makes an in-repo
# rollback on a faster channel possible without switching repositories.
CHANNEL_REVISIONS = {"stable": "_1", "testing": "_2", "edge": "_3", "nightly": "_4"}
EDGE_ROLLBACK_REVISION = CHANNEL_REVISIONS["stable"]
# The legacy `-devel` build sits ABOVE every channel build, so nothing about a migration
# off it can be explained by ordinary version ordering — only by the repository-qualified
# replacement install.sh performs.
LEGACY_REVISION = "_9"
# Which slower channels' builds each catalogue ALSO carries. Strict containment
# (edge ⊇ testing ⊇ stable) is what the in-repo rollback case rides on; expressed as
# data so no case has to branch on a channel name.
CHANNEL_CONTAINED_BUILDS: dict[str, tuple[str, ...]] = {"edge": ("stable",)}


def channel_repo_name(channel: str) -> str:
    """The pkg repository name a channel's conf declares (the ``%R`` a install reports)."""
    return f"pfblockerng-{channel}"


def channel_conf_name(channel: str) -> str:
    """The conf FILE name install.sh writes for a channel."""
    return f"pfblockerng-{channel}.conf"


def previous_channel(channel: str) -> str:
    """A deterministic OTHER channel to subscribe to first, so a switch has a before-state.

    Each case seeds its own previous subscription rather than relying on whatever a
    sibling test happened to leave behind — the cases below must pass in any order and
    in isolation.
    """
    return CHANNELS[(CHANNELS.index(channel) + 1) % len(CHANNELS)]


def rename_pkg(src_pkg: Path, new_name: str, out_dir: Path) -> Path:
    """Move a built ``.pkg`` onto a different package IDENTITY, payload untouched.

    The sibling of :func:`reversion_pkg`: it rewrites ``version``, this rewrites ``name``
    (and the trailing segment of ``origin``, which is the port the name comes from) in
    BOTH manifests — ``pkg`` reads ``+COMPACT_MANIFEST`` for the catalogue and
    ``+MANIFEST`` on install, so a package renamed in only one registers under the other
    name. Every other manifest field and every payload member is copied through verbatim.

    This is what lets ONE branch build stand in for both identities the four-channel
    cutover has to reconcile: the canonical ``pfSense-pkg-pfBlockerNG`` the channel
    catalogues publish, and the legacy ``pfSense-pkg-pfBlockerNG-devel`` an unmigrated
    box still carries. Returns the written ``<new_name>-<version>.pkg`` under ``out_dir``.
    """
    tar_bytes = _zstd_decompress(src_pkg.read_bytes())
    repacked = io.BytesIO()
    version = ""
    with (
        tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tin,
        tarfile.open(fileobj=repacked, mode="w", format=tarfile.USTAR_FORMAT) as tout,
    ):
        for member in tin.getmembers():
            extracted = tin.extractfile(member) if member.isfile() else None
            data = extracted.read() if extracted is not None else b""
            if member.name in _PKG_MANIFEST_MEMBERS:
                obj = json.loads(data)
                obj["name"] = new_name
                origin = obj.get("origin")
                if isinstance(origin, str) and "/" in origin:
                    obj["origin"] = f"{origin.rsplit('/', 1)[0]}/{new_name}"
                version = obj.get("version", version)
                data = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode() + b"\n"
                ti = tarfile.TarInfo(name=member.name)
                ti.size = len(data)
                ti.mode = 0o644
                ti.uid = ti.gid = 0
                ti.uname, ti.gname = "root", "wheel"
                ti.mtime = 0
                ti.type = tarfile.REGTYPE
                tout.addfile(ti, io.BytesIO(data))
            else:
                tout.addfile(member, io.BytesIO(data) if member.isfile() else None)
    if not version:
        raise RuntimeError(f"{src_pkg.name}: no +COMPACT_MANIFEST/+MANIFEST with a version — not a libpkg .pkg?")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{new_name}-{version}.pkg"
    out_path.write_bytes(_zstd_compress(repacked.getvalue()))
    return out_path


def _synthetic_pkg(path: Path, *, name: str, version: str, origin: str) -> Path:
    """Write a minimal libpkg-shaped ``.pkg`` (both manifests + one payload member).

    Hermetic input for the ``rename_pkg`` round-trip: real enough to exercise the
    manifest rewrite without a multi-megabyte branch artifact or a booted guest.
    """
    manifest = {"name": name, "version": version, "origin": origin, "abi": "FreeBSD:15:*"}
    body = json.dumps(manifest, separators=(",", ":")).encode() + b"\n"
    payload = b"#!/bin/sh\necho pfb payload\n"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        members = [(member, body) for member in _PKG_MANIFEST_MEMBERS]
        members.append(("/usr/local/bin/pfb_probe", payload))
        for member_name, data in members:
            ti = tarfile.TarInfo(name=member_name)
            ti.size = len(data)
            ti.mode = 0o644
            ti.uid = ti.gid = 0
            ti.uname, ti.gname = "root", "wheel"
            ti.mtime = 0
            ti.type = tarfile.REGTYPE
            tf.addfile(ti, io.BytesIO(data))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_zstd_compress(buf.getvalue()))
    return path


def _pkg_manifests(pkg_path: Path) -> dict[str, dict]:
    """Both manifest members of a ``.pkg``, parsed — the oracle for an identity rewrite."""
    tar_bytes = _zstd_decompress(pkg_path.read_bytes())
    out: dict[str, dict] = {}
    with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tf:
        for member in tf.getmembers():
            if member.name in _PKG_MANIFEST_MEMBERS:
                extracted = tf.extractfile(member)
                assert extracted is not None, f"{member.name} is not a regular file in {pkg_path.name}"
                out[member.name] = json.loads(extracted.read())
    return out


def _pkg_payload(pkg_path: Path) -> dict[str, bytes]:
    """Every NON-manifest member of a ``.pkg``, by name — the payload-passthrough oracle."""
    tar_bytes = _zstd_decompress(pkg_path.read_bytes())
    out: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tf:
        for member in tf.getmembers():
            if member.name in _PKG_MANIFEST_MEMBERS or not member.isfile():
                continue
            extracted = tf.extractfile(member)
            assert extracted is not None, f"{member.name} is not readable in {pkg_path.name}"
            out[member.name] = extracted.read()
    return out


def test_rename_pkg_rewrites_both_manifests_and_keeps_the_payload(tmp_path: Path) -> None:
    """HERMETIC (no VM): ``rename_pkg`` moves a ``.pkg`` onto a different package IDENTITY.

    The four-channel cases below need two identities forged from ONE branch build: the
    canonical ``pfSense-pkg-pfBlockerNG`` every channel catalogue publishes, and the
    legacy ``pfSense-pkg-pfBlockerNG-devel`` a box being migrated still carries. Both
    manifests must move in lockstep — ``pkg`` reads ``+COMPACT_MANIFEST`` for the
    catalogue and ``+MANIFEST`` on install, so rewriting only the first would publish a
    catalogue entry named canonical that REGISTERS as ``-devel``, and every migration
    assertion below would then be measuring the wrong thing.

    Given a ``.pkg`` whose BOTH manifests name ``pfSense-pkg-pfBlockerNG-devel``,
    When  ``rename_pkg`` retargets it at ``pfSense-pkg-pfBlockerNG``,
    Then  the written file is ``<canonical>-<version>.pkg``, BOTH manifests carry the
      canonical name and a canonical ``origin``, version/ABI are untouched, and every
      payload member survives byte-identical.
    """
    src = _synthetic_pkg(
        tmp_path / "src" / f"{LEGACY_DEVEL_PKG_NAME}-1.2.3_4.pkg",
        name=LEGACY_DEVEL_PKG_NAME,
        version="1.2.3_4",
        origin=f"net/{LEGACY_DEVEL_PKG_NAME}",
    )

    # BEFORE: the source really does carry the legacy identity in BOTH manifests.
    before = _pkg_manifests(src)
    assert sorted(before) == sorted(_PKG_MANIFEST_MEMBERS), f"synthetic .pkg is missing a manifest: {sorted(before)}"
    for member, obj in before.items():
        assert obj["name"] == LEGACY_DEVEL_PKG_NAME, f"BEFORE: {member} names {obj['name']!r}"

    out = rename_pkg(src, CANONICAL_PKG_NAME, tmp_path / "renamed")

    # AFTER: the identity moved everywhere it is recorded, and nothing else moved.
    assert out.name == f"{CANONICAL_PKG_NAME}-1.2.3_4.pkg", f"unexpected output filename {out.name!r}"
    after = _pkg_manifests(out)
    assert sorted(after) == sorted(_PKG_MANIFEST_MEMBERS), f"rename dropped a manifest: {sorted(after)}"
    for member, obj in after.items():
        assert obj["name"] == CANONICAL_PKG_NAME, f"AFTER: {member} still names {obj['name']!r}"
        assert obj["origin"] == f"net/{CANONICAL_PKG_NAME}", f"AFTER: {member} origin is {obj['origin']!r}"
        assert obj["version"] == "1.2.3_4", f"AFTER: {member} version drifted to {obj['version']!r}"
        assert obj["abi"] == "FreeBSD:15:*", f"AFTER: {member} abi drifted to {obj['abi']!r}"
    assert _pkg_payload(out) == _pkg_payload(src), (
        "rename_pkg altered the payload — the forged build is no longer the branch build"
    )


def test_project_conf_names_match_the_shipped_scripts() -> None:
    """HERMETIC (no VM): the conf set this module sweeps IS the set install.sh manages.

    ``PROJECT_CONF_NAMES`` must list every conf name install.sh's ``PROJECT_CONFS``
    declares — it drives both the per-channel parametrization and every "exactly
    one project conf" assertion below.
    """
    block = re.search(r'(?ms)^PROJECT_CONFS="(.*?)"', INSTALL_SH.read_text())
    assert block is not None, "install.sh: no PROJECT_CONFS list to compare against"
    declared = tuple(line.strip() for line in block.group(1).splitlines() if line.strip())
    assert declared == PROJECT_CONF_NAMES, f"install.sh manages {declared}, this module sweeps {PROJECT_CONF_NAMES}"


# --------------------------------------------------------------------------- #
# On-guest subscription state — read + reset explicitly, never inherited
# --------------------------------------------------------------------------- #


def _write_guest_file(vm: SmokeVM, remote_path: str, body: str, *, timeout: float = 60.0) -> None:
    """Write ``body`` to ``remote_path`` on the guest (the module's ``tee`` idiom)."""
    result = subprocess.run(
        vm.ssh_argv("tee", remote_path),
        input=body,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"writing {remote_path} failed: rc={result.returncode} {result.stderr!r}")


def project_confs_present(vm: SmokeVM, *, timeout: float = 60.0) -> set[str]:
    """Which project confs actually exist under the on-box repos dir.

    Effective state read off the box (the CLAUDE.md rule), not inferred from what a
    script printed: this is the oracle for single-repository subscription.
    """
    result = vm.ssh("/bin/ls", "-1", PKG_REPOS_DIR, timeout=timeout)
    if result.returncode != 0:  # the dir does not exist yet => no project conf
        return set()
    return {line.strip() for line in result.stdout.splitlines()} & set(PROJECT_CONF_NAMES)


def remove_project_confs(vm: SmokeVM, *, timeout: float = 60.0) -> None:
    """Delete EVERY project conf from the box."""
    vm.ssh("/bin/rm", "-f", *(f"{PKG_REPOS_DIR}/{name}" for name in PROJECT_CONF_NAMES), timeout=timeout)


def installed_pfblockerng_names(vm: SmokeVM, *, timeout: float = 60.0) -> list[str]:
    """Every installed pfBlockerNG IDENTITY, sorted — the box's identity oracle.

    ``-g`` makes the trailing ``*`` a glob; without it ``pkg query`` treats the pattern
    as an exact name and matches nothing. This is the same query install.sh
    classifies the box with, so a case asserting on it asserts on what the script sees.
    A query miss is "nothing installed" (rc=1), not an error.
    """
    result = vm.ssh("pkg", "query", "-g", "%n", f"{CANONICAL_PKG_NAME}*", timeout=timeout)
    if result.returncode not in (0, 1):
        raise RuntimeError(
            f"pkg query -g %n failed: rc={result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return sorted(line.strip() for line in result.stdout.splitlines() if line.strip())


def reset_channel_subscription(vm: SmokeVM) -> None:
    """Return the box to "no project repo, no pfBlockerNG" — the explicit per-test reset.

    Every case below builds its own before-state from here, so none of them depends on a
    sibling having run first (or on the order pytest happens to pick for the
    parametrized channels).
    """
    for name in (PKG_NAME, CANONICAL_PKG_NAME, LEGACY_DEVEL_PKG_NAME):
        vm.ssh("env", "ASSUME_ALWAYS_YES=yes", "pkg", "delete", "-y", name, timeout=300.0)
    remove_project_confs(vm)


def pkg_install_qualified(
    vm: SmokeVM,
    repo_name: str,
    target: str,
    *,
    force: bool = False,
    timeout: float = 600.0,
) -> subprocess.CompletedProcess[str]:
    """``pkg install [-f] -y -r <repo> <target>`` — a REPOSITORY-QUALIFIED install.

    ``-r`` pins WHICH catalogue serves the package, which is the whole point once every
    channel publishes the same identity at the same priority. ``force`` adds ``-f``, the
    only way to move to an equal-or-OLDER build (``pkg upgrade`` refuses a downgrade);
    ``target`` may be a bare name or an exact ``<name>-<version>``.
    """
    force_args = ("-f",) if force else ()
    remote = ("env", "ASSUME_ALWAYS_YES=yes", "pkg", "install", *force_args, "-y", "-r", repo_name, target)
    result = _pkg_retry(vm, *remote, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(
            f"pkg install -r {repo_name} {target} failed: rc={result.returncode}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


# --------------------------------------------------------------------------- #
# Module fixture — the four channel catalogues + the legacy release catalogue
# --------------------------------------------------------------------------- #


class ChannelCatalogs(NamedTuple):
    """What the four-channel cases need to know about the catalogues staged on the guest."""

    root: str
    """Guest catalogue root; ``<root>/<channel>/<varver>/`` is what the hook resolves."""
    varver: str
    """The box's own ``<varver>`` the catalogues are published under."""
    versions: dict[str, str]
    """channel -> the canonical version THAT channel serves (so ``%v`` identifies it)."""
    legacy_version: str
    """The ``-devel`` version the legacy release catalogue serves."""
    edge_rollback_version: str
    """The older canonical build ALSO carried by ``pfblockerng-edge`` (containment)."""

    @property
    def base_url(self) -> str:
        """The ``PFB_BASE_URL`` the published installer is driven with."""
        return f"file://{self.root}"


@pytest.fixture(scope="module")
def channel_catalogs(repo_vm: SmokeVM, tmp_path_factory: pytest.TempPathFactory) -> Iterator[ChannelCatalogs]:
    """Publish all four channel catalogues plus the legacy release catalogue on the guest.

    ONE branch build stands in for every identity and every channel: ``rename_pkg`` forges
    the canonical ``pfSense-pkg-pfBlockerNG`` and the legacy ``pfSense-pkg-pfBlockerNG-devel``
    from it, and ``reversion_pkg`` gives each catalogue its OWN PORTREVISION, so
    ``pkg query %v`` alone says which catalogue served a build.

    ``pfblockerng-edge`` deliberately carries TWO canonical builds — its own ``_3`` and the
    stable-era ``_1`` — because each channel catalogue strictly contains its slower
    channels' files. That containment is what makes an in-repo rollback on a faster channel
    possible, and it cannot be asserted against a single-version catalogue.

    The legacy release catalogue carries ONLY the ``-devel`` identity: a box needing
    migration is one that installed the suffixed package, and stocking the canonical one
    beside it would let a migration "succeed" without ever crossing repositories.

    Setup only — every case resets its own subscription state, so this fixture never
    establishes an ordering between them.
    """
    pkg = os.environ.get("SMOKE_PKG")
    assert pkg and Path(pkg).is_file(), "SMOKE_PKG not set / not a file"  # repo_vm already gated this
    src = Path(pkg)
    forge_dir = tmp_path_factory.mktemp("channel_forge")
    base_version = read_compact_version(src)
    real_varver = _box_real_varver(repo_vm)
    dep_pkgs = _smoke_dep_pkg_paths()

    canonical_src = rename_pkg(src, CANONICAL_PKG_NAME, forge_dir / "canonical")
    legacy_src = rename_pkg(src, LEGACY_DEVEL_PKG_NAME, forge_dir / "legacy")
    versions = {channel: f"{base_version}{rev}" for channel, rev in CHANNEL_REVISIONS.items()}
    builds = {
        channel: reversion_pkg(canonical_src, version, forge_dir / f"build_{channel}")
        for channel, version in versions.items()
    }
    legacy_version = f"{base_version}{LEGACY_REVISION}"
    legacy_build = reversion_pkg(legacy_src, legacy_version, forge_dir / "build_legacy")
    edge_rollback_version = f"{base_version}{EDGE_ROLLBACK_REVISION}"

    try:
        for channel in CHANNELS:
            # Each catalogue carries its own build plus everything its slower channels
            # still hold — the containment that makes an in-repo rollback possible.
            staged = [builds[channel], *(builds[slower] for slower in CHANNEL_CONTAINED_BUILDS.get(channel, ()))]
            build_repo_via_portable_named(
                repo_vm,
                [*staged, *dep_pkgs],
                tmp_path_factory.mktemp(f"catalog_{channel}"),
                catalog_name=f"{channel}/{real_varver}",
                guest_root=CHANNEL_REPO_ROOT,
            )
        build_repo_via_portable_named(
            repo_vm,
            [legacy_build, *dep_pkgs],
            tmp_path_factory.mktemp("catalog_release"),
            catalog_name=f"release/{real_varver}",
            guest_root=CHANNEL_REPO_ROOT,
        )
        yield ChannelCatalogs(
            root=CHANNEL_REPO_ROOT,
            varver=real_varver,
            versions=versions,
            legacy_version=legacy_version,
            edge_rollback_version=edge_rollback_version,
        )
    finally:
        reset_channel_subscription(repo_vm)
        repo_vm.ssh("/bin/rm", "-rf", CHANNEL_REPO_ROOT, timeout=60.0)
        # install.sh installs the generator hook at the PRODUCTION rc.d path;
        # drop it so a staged hook never survives into a later module sharing this guest.
        repo_vm.ssh("/bin/rm", "-f", GUEST_HOOK_PATH, timeout=60.0)
        # issue #2416 follow-up — the per-channel cases below stage install.sh
        # beside the other spike scripts; sweep every published one so none survives
        # into a later module sharing this guest.
        repo_vm.ssh("/bin/sh", "-c", f"rm -f {GUEST_SPIKE_DIR}/install*.sh", timeout=60.0)


# --------------------------------------------------------------------------- #
# The four-channel cases
# --------------------------------------------------------------------------- #


@pytest.mark.timeout(1800)  # bootstrap + install the newer build + a forced in-repo downgrade.
def test_edge_rollback_stays_within_the_edge_repository(
    repo_vm: SmokeVM,
    channel_catalogs: ChannelCatalogs,
    tmp_path: Path,
) -> None:
    """IN-REPO ROLLBACK: a box on ``edge`` moves BACK to an older build WITHOUT switching
    repositories, because ``pfblockerng-edge`` already contains it.

    Each channel catalogue strictly contains its slower channels' files (edge ⊇ testing ⊇
    stable), so "go back to the stable-era build" is a repository-qualified operation
    inside the one repo the box is subscribed to — not a re-subscription. If it required
    switching repos, single-repository subscription would be unworkable for anyone on a
    faster channel, so this is the case that makes that design hold.

    ``-f`` is required: ``pkg upgrade`` refuses to move DOWN, and the exact
    ``<name>-<version>`` picks the older of the two builds the edge catalogue carries.

    Scenario: rolling back on edge.
      Background: ``pfblockerng-edge`` serves BOTH the edge build and the older
        stable-era build of the canonical package.

    Given the box subscribed to edge and running the NEWER edge build via the published
      ``install.sh --channel edge`` (BEFORE asserted: ``%v`` is edge's version, ``%R`` is
      ``pfblockerng-edge``),
    When  ``pkg install -f -y -r pfblockerng-edge pfSense-pkg-pfBlockerNG-<older>`` runs,
    Then  ``%v`` is the OLDER version, ``%R`` is STILL ``pfblockerng-edge``, the box still
      carries exactly the canonical identity, and its subscription is untouched —
      ``pfblockerng-edge.conf`` is still the only project conf on the box.
    """
    channel = "edge"
    target_repo = channel_repo_name(channel)
    newer = channel_catalogs.versions[channel]
    older = channel_catalogs.edge_rollback_version
    assert newer != older, f"the rollback pair must differ (both {newer!r})"

    reset_channel_subscription(repo_vm)

    # GIVEN: the box on edge's OWN (newer) build, from the edge repository.
    installer = run_channel_installer(repo_vm, channel, channel_catalogs.base_url, tmp_path)
    assert installer.returncode == 0, (
        f"install-{channel}.sh exited {installer.returncode}\nstdout:\n{installer.stdout}\nstderr:\n{installer.stderr}"
    )
    assert pkg_installed_version_of(repo_vm, CANONICAL_PKG_NAME) == newer, (
        f"BEFORE: expected edge's build {newer!r}, got {pkg_installed_version_of(repo_vm, CANONICAL_PKG_NAME)!r}"
    )
    assert pkg_repo_origin_of(repo_vm, CANONICAL_PKG_NAME) == target_repo, (
        f"BEFORE: installed from {pkg_repo_origin_of(repo_vm, CANONICAL_PKG_NAME)!r}, expected {target_repo!r}"
    )
    assert project_confs_present(repo_vm) == {channel_conf_name(channel)}, (
        f"BEFORE: expected only {channel_conf_name(channel)}, found {sorted(project_confs_present(repo_vm))}"
    )

    # WHEN: roll back WITHIN the edge repository, repository-qualified and forced.
    proc = pkg_install_qualified(repo_vm, target_repo, f"{CANONICAL_PKG_NAME}-{older}", force=True)

    # THEN: the box moved DOWN a version and did NOT move repository.
    assert pkg_installed_version_of(repo_vm, CANONICAL_PKG_NAME) == older, (
        f"AFTER: rollback did not move {newer!r} -> {older!r}; now at "
        f"{pkg_installed_version_of(repo_vm, CANONICAL_PKG_NAME)!r}"
    )
    assert pkg_repo_origin_of(repo_vm, CANONICAL_PKG_NAME) == target_repo, (
        f"AFTER: the rollback changed the repository to "
        f"{pkg_repo_origin_of(repo_vm, CANONICAL_PKG_NAME)!r}, expected to stay on {target_repo!r}"
    )
    assert installed_pfblockerng_names(repo_vm) == [CANONICAL_PKG_NAME], (
        f"AFTER: expected only {CANONICAL_PKG_NAME}, found {installed_pfblockerng_names(repo_vm)}"
    )
    assert project_confs_present(repo_vm) == {channel_conf_name(channel)}, (
        f"AFTER: the rollback changed the subscription to {sorted(project_confs_present(repo_vm))}"
    )
    combined = proc.stdout + proc.stderr
    assert "Missing dependency" not in combined, f"RUN_DEPENDS did not resolve on the rollback:\n{combined}"


# ============================================================================ #
# issue #2416 — the per-channel installer, published                           #
#                                                                              #
# One self-contained install.sh, --channel parameterized, is the SOLE client
# entry point. These cases assemble the source-owned installer and hook inputs
# into the same safe single-quoted heredoc shape the pkg-owned renderer ships,
# then exercise the published pipe form on the guest.
#                                                                              #
# Marker: @pytest.mark.repo (inherited from pytestmark).                       #
# Dispatch: gh workflow run smoke-single.yml -f pytest_marker=repo             #
# ============================================================================ #

INSTALL_SH = Path(__file__).resolve().parents[2] / "scripts" / "install.sh"
REPO_GENERATE_HOOK = (
    Path(__file__).resolve().parents[2] / "src" / "usr" / "local" / "etc" / "rc.d" / "pfblockerng_repo_generate.sh"
)
_HOOK_BEGIN = "# PFB_EMBED_HOOK_BEGIN"
_HOOK_END = "# PFB_EMBED_HOOK_END"
_HOOK_HEREDOC = "PFB_REPO_GENERATE_HOOK_EOF"

# The four stdout markers install.sh's converge step (9) guards every mutating
# pkg call with; a no-op second run must print NONE of them.
_MUTATION_MARKERS = ("==> Installing", "==> Reinstalling", "==> Removing")


def _published_installer(path: Path) -> Path:
    script = INSTALL_SH.read_text(encoding="utf-8")
    hook = REPO_GENERATE_HOOK.read_text(encoding="utf-8")
    lines = script.splitlines(keepends=True)
    begin = next((i for i, line in enumerate(lines) if _HOOK_BEGIN in line), None)
    end = next((i for i, line in enumerate(lines) if _HOOK_END in line), None)
    assert begin is not None and end is not None and begin < end, "install.sh embed markers are missing or reordered"
    assert _HOOK_HEREDOC not in hook, "repository hook collides with the installer heredoc delimiter"
    replacement = [
        lines[begin],
        f"    cat <<'{_HOOK_HEREDOC}'\n",
        hook if hook.endswith("\n") else hook + "\n",
        f"{_HOOK_HEREDOC}\n",
        lines[end],
    ]
    path.write_text("".join(lines[:begin] + replacement + lines[end + 1 :]), encoding="utf-8")
    return path


def test_source_installer_inputs_assemble_self_contained(tmp_path: Path) -> None:
    published = _published_installer(tmp_path / "install.sh").read_text(encoding="utf-8")
    hook = REPO_GENERATE_HOOK.read_text(encoding="utf-8")
    assert hook in published
    assert "printf 'install.sh: no embedded hook in this copy" not in published
    assert published.count(_HOOK_HEREDOC) == 2


def run_channel_installer(
    vm: SmokeVM,
    channel: str,
    base_url: str,
    tmp_path: Path,
    *,
    timeout: float = 900.0,
) -> subprocess.CompletedProcess[str]:
    """Assemble the source client inputs and run the published pipe form.

    The pkg repository owns the production renderer and site. This source-side
    contract keeps the install state machine and hook composable into the same
    self-contained script without checking out or executing pkg code.

    Ships ``install.sh`` to ``GUEST_SPIKE_DIR`` (once — the same file serves every
    channel) and PIPES it through ``fetch(1)`` exactly the
    ``fetch -qo - <url> | sh -s -- --channel <ch>`` shape documented in the script's
    own usage() header (issue #2416 F2/N2) — a redirected file gives a SEEKABLE
    stdin and does not exercise the #2390 pipe hazard; ``fetch -qo - file://…`` does.
    The script's stdin IS the script text (install.sh's header explains why every
    pkg(8) call redirects ITS OWN stdin from /dev/null — a child that read the
    unredirected stdin would consume trailing script bytes). Returns WITHOUT
    raising — the refusal case (case 5 below) asserts on a non-zero exit.
    """
    local_script = _published_installer(tmp_path / "install.sh")

    guest_path = f"{GUEST_SPIKE_DIR}/install.sh"
    _ssh_check(vm, "/bin/mkdir", "-p", GUEST_SPIKE_DIR)
    _scp_to_guest(vm, local_script, guest_path)
    cmd = (
        f"env PFB_BASE_URL='{base_url}' /bin/sh -c "
        f'"fetch -qo - file://{guest_path} | /bin/sh -s -- --channel {channel}"'
    )
    return vm.ssh(cmd, timeout=timeout)


def _conf_bytes(vm: SmokeVM, path: str) -> str:
    """The on-guest content of ``path`` (the byte-identity oracle for a no-op second run)."""
    return _ssh_check(vm, "/bin/cat", path).stdout


def _hook_bytes(vm: SmokeVM) -> str:
    """The on-guest content of the installed generator hook (same oracle, for the hook)."""
    return _conf_bytes(vm, GUEST_HOOK_PATH)


def _pkg_state(vm: SmokeVM) -> tuple[list[str], str | None, str | None]:
    """(installed pfBlockerNG identities, canonical ``%v``, canonical ``%R``) in one call."""
    return (
        installed_pfblockerng_names(vm),
        pkg_installed_version_of(vm, CANONICAL_PKG_NAME),
        pkg_repo_origin_of(vm, CANONICAL_PKG_NAME),
    )


def _assert_second_run_is_a_noop(
    vm: SmokeVM,
    channel: str,
    base_url: str,
    tmp_path: Path,
    *,
    conf_path: str,
    conf_before: str,
    hook_before: str,
    version_before: str | None,
) -> None:
    """Re-run ``install.sh --channel <channel>`` on already-converged state: zero mutations.

    Shared second-run assertion for every case below — "Already up to date" reported,
    none of install.sh's mutating-step markers printed, and the conf, the hook,
    and the installed version are BYTE/VALUE identical to what the first run left.
    """
    proc = run_channel_installer(vm, channel, base_url, tmp_path)
    assert proc.returncode == 0, (
        f"second run of install-{channel}.sh exited {proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    )
    assert "Already up to date" in proc.stdout, (
        f"second run of install-{channel}.sh did not report convergence:\n{proc.stdout}"
    )
    for marker in _MUTATION_MARKERS:
        assert marker not in proc.stdout, (
            f"second run of install-{channel}.sh mutated the box ({marker!r} in stdout):\n{proc.stdout}"
        )
    assert _conf_bytes(vm, conf_path) == conf_before, f"second run of install-{channel}.sh changed the conf bytes"
    assert _hook_bytes(vm) == hook_before, f"second run of install-{channel}.sh changed the hook bytes"
    assert pkg_installed_version_of(vm, CANONICAL_PKG_NAME) == version_before, (
        f"second run of install-{channel}.sh changed the installed version: {version_before!r} -> "
        f"{pkg_installed_version_of(vm, CANONICAL_PKG_NAME)!r}"
    )


@pytest.mark.timeout(1800)
@pytest.mark.parametrize("channel", ["stable", "edge"])
def test_channel_installer_fresh_box_installs_from_the_channel(
    repo_vm: SmokeVM,
    channel_catalogs: ChannelCatalogs,
    channel: str,
    tmp_path: Path,
) -> None:
    """FRESH BOX: the published ``install.sh --channel <channel>``, piped, converges a box with
    nothing installed and no project conf onto that channel — and a second run is a
    true no-op.

    Scenario: a fresh box subscribes and installs via the one-file installer.

    Given nothing pfBlockerNG-shaped is installed and no project conf exists (BEFORE
      asserted),
    When  ``env PFB_BASE_URL=<file://catalogue> /bin/sh -c
      "fetch -qo - file://install.sh | /bin/sh -s -- --channel <channel>"``
      runs (the published, self-contained form, PIPED exactly like ``fetch | sh`` —
      a real non-seekable stdin, not a redirected file),
    Then  it exits 0, reports ``==> Done``, the box carries EXACTLY the canonical
      identity at the version this channel's catalogue serves, from this channel's
      repository, subscribed to EXACTLY this channel's conf, and the boot-time
      generator hook is present, byte-identical to the shipped
      src/usr/local/etc/rc.d/pfblockerng_repo_generate.sh (the executed proof the
      embedded heredoc survives ash when piped);
    And   a second run reports ``==> Already up to date``, performs no mutating step,
      and leaves the conf, the hook, and the installed version unchanged.
    """
    reset_channel_subscription(repo_vm)

    # GIVEN: nothing installed, no project conf.
    names_before = installed_pfblockerng_names(repo_vm)
    assert names_before == [], f"BEFORE: expected nothing installed, found {names_before}"
    confs_before = project_confs_present(repo_vm)
    assert confs_before == set(), f"BEFORE: expected no project conf, found {sorted(confs_before)}"

    # WHEN: the published installer, piped.
    proc = run_channel_installer(repo_vm, channel, channel_catalogs.base_url, tmp_path)

    # THEN: converged onto the channel.
    assert proc.returncode == 0, (
        f"install-{channel}.sh exited {proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    )
    assert "==> Done" in proc.stdout, f"install-{channel}.sh did not report completion:\n{proc.stdout}"
    names_after, version_after, repo_after = _pkg_state(repo_vm)
    assert names_after == [CANONICAL_PKG_NAME], f"AFTER: expected only {CANONICAL_PKG_NAME}, found {names_after}"
    assert version_after == channel_catalogs.versions[channel], (
        f"AFTER: installed version {version_after!r}, expected {channel_catalogs.versions[channel]!r}"
    )
    assert repo_after == channel_repo_name(channel), (
        f"AFTER: installed from {repo_after!r}, expected {channel_repo_name(channel)!r}"
    )
    confs_after = project_confs_present(repo_vm)
    assert confs_after == {channel_conf_name(channel)}, (
        f"AFTER: expected only {channel_conf_name(channel)}, found {sorted(confs_after)}"
    )
    assert _ssh_check(repo_vm, "/bin/test", "-f", GUEST_HOOK_PATH).returncode == 0, (
        f"AFTER: boot-time generator hook not present at {GUEST_HOOK_PATH}"
    )
    # The executed proof the embedded heredoc survives ash when piped: the installed
    # hook's bytes must match the shipped repository copy exactly.
    installed_hook = _hook_bytes(repo_vm)
    shipped_hook = RC_D_HOOK_SRC.read_text()
    assert installed_hook == shipped_hook, (
        f"AFTER: installed hook drifted from the shipped {RC_D_HOOK_SRC.name} "
        f"(len {len(installed_hook)} vs {len(shipped_hook)})"
    )

    conf_path = f"{PKG_REPOS_DIR}/{channel_conf_name(channel)}"
    conf_before = _conf_bytes(repo_vm, conf_path)
    hook_before = _hook_bytes(repo_vm)

    # THEN (second run): a converged box performs no mutation.
    _assert_second_run_is_a_noop(
        repo_vm,
        channel,
        channel_catalogs.base_url,
        tmp_path,
        conf_path=conf_path,
        conf_before=conf_before,
        hook_before=hook_before,
        version_before=version_after,
    )


@pytest.mark.timeout(1800)
def test_channel_installer_replaces_the_legacy_devel_identity(
    repo_vm: SmokeVM,
    channel_catalogs: ChannelCatalogs,
    tmp_path: Path,
) -> None:
    """LEGACY -devel: the published ``install.sh --channel stable`` REPLACES a box's legacy
    suffixed identity with the canonical one, installed from the stable channel.

    GIVEN mirrors ``test_migrate_channel_replaces_the_legacy_identity_with_the_canonical_one``'s:
    a box subscribed to the legacy shared release repo, carrying only
    ``pfSense-pkg-pfBlockerNG-devel``.

    Scenario: a legacy-devel box converges via the one-file installer.

    Given the box installed ``pfSense-pkg-pfBlockerNG-devel`` from the legacy
      ``pfblockerng`` repo (BEFORE asserted),
    When  ``install.sh --channel stable`` runs, piped,
    Then  it exits 0, reports removing the legacy identity, the box carries EXACTLY the
      canonical identity from the stable channel at the version that catalogue serves,
      and exactly one project conf survives;
    And   a second run is a true no-op.
    """
    channel = "stable"
    reset_channel_subscription(repo_vm)

    # GIVEN: subscribed to the legacy release repo (a hand-written pfblockerng.conf —
    # no install.sh run ever writes the legacy conf), carrying only the -devel identity.
    write_repo_conf(repo_vm, f"{channel_catalogs.root}/release/{channel_catalogs.varver}", ours_priority=100)
    pkg_update(repo_vm)
    pkg_install_qualified(repo_vm, OURS_REPO_NAME, LEGACY_DEVEL_PKG_NAME)
    names_before = installed_pfblockerng_names(repo_vm)
    assert names_before == [LEGACY_DEVEL_PKG_NAME], f"BEFORE: expected only the legacy identity, found {names_before}"

    # WHEN: the published stable installer, piped.
    proc = run_channel_installer(repo_vm, channel, channel_catalogs.base_url, tmp_path)

    # THEN: the legacy identity is gone; the canonical one is installed from stable.
    assert proc.returncode == 0, (
        f"install-{channel}.sh exited {proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    )
    assert f"==> Removing {LEGACY_DEVEL_PKG_NAME}" in proc.stdout, (
        f"install-{channel}.sh did not report removing the legacy identity:\n{proc.stdout}"
    )
    names_after, version_after, repo_after = _pkg_state(repo_vm)
    assert names_after == [CANONICAL_PKG_NAME], f"AFTER: expected only {CANONICAL_PKG_NAME}, found {names_after}"
    assert version_after == channel_catalogs.versions[channel], (
        f"AFTER: installed version {version_after!r}, expected {channel_catalogs.versions[channel]!r}"
    )
    assert repo_after == channel_repo_name(channel), (
        f"AFTER: installed from {repo_after!r}, expected {channel_repo_name(channel)!r}"
    )
    confs_after = project_confs_present(repo_vm)
    assert confs_after == {channel_conf_name(channel)}, (
        f"AFTER: expected only {channel_conf_name(channel)}, found {sorted(confs_after)}"
    )

    conf_path = f"{PKG_REPOS_DIR}/{channel_conf_name(channel)}"
    conf_before = _conf_bytes(repo_vm, conf_path)
    hook_before = _hook_bytes(repo_vm)

    # THEN (second run): a true no-op.
    _assert_second_run_is_a_noop(
        repo_vm,
        channel,
        channel_catalogs.base_url,
        tmp_path,
        conf_path=conf_path,
        conf_before=conf_before,
        hook_before=hook_before,
        version_before=version_after,
    )


@pytest.mark.timeout(1800)
def test_channel_installer_moves_a_canonical_install_between_channels(
    repo_vm: SmokeVM,
    channel_catalogs: ChannelCatalogs,
    tmp_path: Path,
) -> None:
    """CHANNEL-TO-CHANNEL: the published installer moves an already-canonical install
    across channels in BOTH directions — a same-release-family downgrade (edge -> stable,
    ``_3`` -> ``_1``, no WARNING) and back up (stable -> edge, a forward move).

    Scenario: switching channels via the one-file installer, both ways.

    Given the box converged onto edge via ``install.sh --channel edge`` (BEFORE asserted: edge's
      version, edge's repository),
    When  ``install.sh --channel stable`` runs, piped — a downgrade WITHIN the same release
      family (only the PORTREVISION differs),
    Then  it exits 0, the box is at stable's OLDER version from stable's repository, the
      edge conf is retired, and NO WARNING is printed (same family);
    When  ``install.sh --channel edge`` runs again, piped,
    Then  it exits 0, the box is back at edge's version from edge's repository;
    And   a second run of ``install.sh --channel edge`` is a true no-op.
    """
    reset_channel_subscription(repo_vm)

    # GIVEN: converged onto edge via the published installer.
    proc_edge = run_channel_installer(repo_vm, "edge", channel_catalogs.base_url, tmp_path)
    assert proc_edge.returncode == 0, (
        f"install.sh --channel edge exited {proc_edge.returncode}\n"
        f"stdout:\n{proc_edge.stdout}\nstderr:\n{proc_edge.stderr}"
    )
    _, version_before, repo_before = _pkg_state(repo_vm)
    assert version_before == channel_catalogs.versions["edge"], (
        f"BEFORE: expected edge {channel_catalogs.versions['edge']!r}, got {version_before!r}"
    )
    assert repo_before == channel_repo_name("edge"), (
        f"BEFORE: installed from {repo_before!r}, expected {channel_repo_name('edge')!r}"
    )

    # WHEN: install.sh --channel stable, piped — a same-family downgrade.
    proc_stable = run_channel_installer(repo_vm, "stable", channel_catalogs.base_url, tmp_path)

    # THEN: moved onto stable's build/repository; edge conf retired; no WARNING.
    assert proc_stable.returncode == 0, (
        f"install.sh --channel stable exited {proc_stable.returncode}\n"
        f"stdout:\n{proc_stable.stdout}\nstderr:\n{proc_stable.stderr}"
    )
    _, version_stable, repo_stable = _pkg_state(repo_vm)
    assert version_stable == channel_catalogs.versions["stable"], (
        f"AFTER stable: installed version {version_stable!r}, expected {channel_catalogs.versions['stable']!r}"
    )
    assert repo_stable == channel_repo_name("stable"), (
        f"AFTER stable: installed from {repo_stable!r}, expected {channel_repo_name('stable')!r}"
    )
    confs_after_stable = project_confs_present(repo_vm)
    assert confs_after_stable == {channel_conf_name("stable")}, (
        f"AFTER stable: expected only {channel_conf_name('stable')}, found {sorted(confs_after_stable)}"
    )
    assert "WARNING" not in proc_stable.stderr, f"same-family downgrade printed a WARNING:\n{proc_stable.stderr}"

    # WHEN: install.sh --channel edge again, piped — a forward move back onto edge.
    proc_edge_again = run_channel_installer(repo_vm, "edge", channel_catalogs.base_url, tmp_path)
    assert proc_edge_again.returncode == 0, (
        f"install.sh --channel edge (2nd) exited {proc_edge_again.returncode}\n"
        f"stdout:\n{proc_edge_again.stdout}\nstderr:\n{proc_edge_again.stderr}"
    )
    _, version_edge_again, repo_edge_again = _pkg_state(repo_vm)
    assert version_edge_again == channel_catalogs.versions["edge"], (
        f"AFTER edge (2nd): installed version {version_edge_again!r}, expected {channel_catalogs.versions['edge']!r}"
    )
    assert repo_edge_again == channel_repo_name("edge"), (
        f"AFTER edge (2nd): installed from {repo_edge_again!r}, expected {channel_repo_name('edge')!r}"
    )

    conf_path = f"{PKG_REPOS_DIR}/{channel_conf_name('edge')}"
    conf_before = _conf_bytes(repo_vm, conf_path)
    hook_before = _hook_bytes(repo_vm)

    # THEN (second run of install.sh --channel edge): a true no-op.
    _assert_second_run_is_a_noop(
        repo_vm,
        "edge",
        channel_catalogs.base_url,
        tmp_path,
        conf_path=conf_path,
        conf_before=conf_before,
        hook_before=hook_before,
        version_before=version_edge_again,
    )


@pytest.mark.timeout(1800)
def test_channel_installer_moves_a_netgate_install_onto_the_channel(
    repo_vm: SmokeVM,
    channel_catalogs: ChannelCatalogs,
    tmp_path: Path,
) -> None:
    """NETGATE-ORIGIN: the published installer moves a canonically-named install that
    came from a NON-project repository onto the channel — the shape a box gets from
    the real Netgate package manager (or any other third party publishing the SAME
    canonical identity).

    The real Netgate ``pfSense`` repo carries no pfBlockerNG in this hermetic CE
    catalogue (the ADR-17 kill-gate cases above note the same gap), so — mirroring
    their DECOY technique — a controlled ``file://`` repo NOT among the project confs
    stands in: it serves the SAME canonical identity, installed here by REPOSITORY
    QUALIFICATION (``-r``, no priority contest needed — install.sh's own
    installs are always ``-r``-qualified too).

    Scenario: a Netgate-origin canonical install converges via the one-file installer.

    Given the canonical identity installed from a repo that is NOT one of the four
      project repos (BEFORE asserted),
    When  ``install.sh --channel testing`` runs, piped,
    Then  it exits 0, the box is at testing's version from testing's repository, still
      carries EXACTLY the canonical identity, and the decoy conf — not a project conf —
      is left untouched;
    And   a second run is a true no-op.
    """
    channel = "testing"
    decoy_repo_name = "netgate-decoy-canonical"
    decoy_conf_path = f"{PKG_REPOS_DIR}/netgate-decoy-canonical.conf"
    decoy_root = f"{GUEST_SPIKE_DIR}/netgate_decoy_canonical"

    pkg = os.environ.get("SMOKE_PKG")
    assert pkg and Path(pkg).is_file(), "SMOKE_PKG not set / not a file"  # repo_vm already gated this

    reset_channel_subscription(repo_vm)
    try:
        # GIVEN: the canonical identity installed from a NON-project decoy repo.
        decoy_src = rename_pkg(Path(pkg), CANONICAL_PKG_NAME, tmp_path / "netgate_decoy_src")
        dep_pkgs = _smoke_dep_pkg_paths()
        decoy_dir = build_repo_via_portable_named(
            repo_vm,
            [decoy_src, *dep_pkgs],
            tmp_path,
            catalog_name="decoy",
            guest_root=decoy_root,
        )
        _write_guest_file(repo_vm, decoy_conf_path, _repo_block(decoy_repo_name, decoy_dir, 100))
        pkg_update(repo_vm)
        pkg_install_qualified(repo_vm, decoy_repo_name, CANONICAL_PKG_NAME)

        names_before, _, repo_before = _pkg_state(repo_vm)
        assert names_before == [CANONICAL_PKG_NAME], f"BEFORE: expected only {CANONICAL_PKG_NAME}, found {names_before}"
        assert repo_before == decoy_repo_name, (
            f"BEFORE: expected the decoy repo {decoy_repo_name!r}, got {repo_before!r}"
        )
        assert repo_before not in {channel_repo_name(c) for c in CHANNELS}, (
            f"BEFORE: the decoy repo name {repo_before!r} collides with a project repo — the case proves nothing"
        )

        # WHEN: the published testing installer, piped.
        proc = run_channel_installer(repo_vm, channel, channel_catalogs.base_url, tmp_path)

        # THEN: moved onto the channel's repository; the decoy conf is left alone.
        assert proc.returncode == 0, (
            f"install-{channel}.sh exited {proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
        names_after, version_after, repo_after = _pkg_state(repo_vm)
        assert names_after == [CANONICAL_PKG_NAME], f"AFTER: expected only {CANONICAL_PKG_NAME}, found {names_after}"
        assert version_after == channel_catalogs.versions[channel], (
            f"AFTER: installed version {version_after!r}, expected {channel_catalogs.versions[channel]!r}"
        )
        assert repo_after == channel_repo_name(channel), (
            f"AFTER: installed from {repo_after!r}, expected {channel_repo_name(channel)!r}"
        )
        assert _ssh_check(repo_vm, "/bin/test", "-f", decoy_conf_path).returncode == 0, (
            f"AFTER: the decoy conf {decoy_conf_path} was removed — it is not a project conf, "
            "install.sh must never touch it"
        )

        conf_path = f"{PKG_REPOS_DIR}/{channel_conf_name(channel)}"
        conf_before = _conf_bytes(repo_vm, conf_path)
        hook_before = _hook_bytes(repo_vm)

        # THEN (second run): a true no-op.
        _assert_second_run_is_a_noop(
            repo_vm,
            channel,
            channel_catalogs.base_url,
            tmp_path,
            conf_path=conf_path,
            conf_before=conf_before,
            hook_before=hook_before,
            version_before=version_after,
        )
    finally:
        repo_vm.ssh("/bin/rm", "-f", decoy_conf_path, timeout=60.0)
        repo_vm.ssh("/bin/rm", "-rf", decoy_root, timeout=60.0)


@pytest.mark.timeout(1800)
def test_channel_installer_refuses_an_unpublished_channel_without_touching_the_box(
    repo_vm: SmokeVM,
    channel_catalogs: ChannelCatalogs,
    tmp_path: Path,
) -> None:
    """UNPUBLISHED CHANNEL: the published installer REFUSES when its channel's
    catalogue is not there, and touches NOTHING already on the box.

    install.sh's own step 4 (``pkg update -f -r <repo>``) is what fails here —
    a genuinely unreachable ``file://`` root has no catalogue to fetch — and the
    conf stub the run itself created is removed on the way out (``CONF_CREATED``),
    exactly like ``test_migrate_channel_refuses_an_unsubscribed_channel_before_mutating``
    proves for the older two-script flow.

    Scenario: install.sh --channel nightly with no nightly catalogue published.

    Given the box converged onto stable via ``install.sh --channel stable`` (BEFORE asserted),
      and no nightly conf exists,
    When  ``install.sh --channel nightly`` runs, piped, with ``PFB_BASE_URL`` pointed at a root
      that has no ``nightly/<varver>`` catalogue at all,
    Then  it exits 4, the stable install is UNCHANGED (same version, same repository,
      the stable conf byte-identical), and no nightly conf was left behind.
    """
    reset_channel_subscription(repo_vm)

    # GIVEN: converged onto stable via the published installer.
    proc_stable = run_channel_installer(repo_vm, "stable", channel_catalogs.base_url, tmp_path)
    assert proc_stable.returncode == 0, (
        f"install.sh --channel stable exited {proc_stable.returncode}\n"
        f"stdout:\n{proc_stable.stdout}\nstderr:\n{proc_stable.stderr}"
    )
    _, version_before, repo_before = _pkg_state(repo_vm)
    assert version_before == channel_catalogs.versions["stable"], (
        f"BEFORE: expected stable {channel_catalogs.versions['stable']!r}, got {version_before!r}"
    )
    assert repo_before == channel_repo_name("stable"), (
        f"BEFORE: installed from {repo_before!r}, expected {channel_repo_name('stable')!r}"
    )
    stable_conf_path = f"{PKG_REPOS_DIR}/{channel_conf_name('stable')}"
    conf_before = _conf_bytes(repo_vm, stable_conf_path)
    nightly_conf_path = f"{PKG_REPOS_DIR}/{channel_conf_name('nightly')}"
    assert channel_conf_name("nightly") not in project_confs_present(repo_vm), (
        "BEFORE: already subscribed to nightly — the refusal cannot be exercised"
    )

    # WHEN: install.sh --channel nightly, piped, at a base URL with no nightly catalogue.
    missing_base_url = f"file://{channel_catalogs.root}-missing"
    proc = run_channel_installer(repo_vm, "nightly", missing_base_url, tmp_path)

    # THEN: refused; the stable install is untouched; no nightly conf survives.
    assert proc.returncode == 4, (
        f"expected exit 4 (target unavailable), got {proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    )
    _, version_after, repo_after = _pkg_state(repo_vm)
    assert version_after == version_before, (
        f"the refusal changed the installed version: {version_before!r} -> {version_after!r}"
    )
    assert repo_after == repo_before, f"the refusal changed the installed repo: {repo_before!r} -> {repo_after!r}"
    assert _conf_bytes(repo_vm, stable_conf_path) == conf_before, "the refusal changed the stable conf bytes"
    assert channel_conf_name("nightly") not in project_confs_present(repo_vm), (
        f"AFTER: the refusal left a stub nightly conf at {nightly_conf_path} — the created stub must be removed"
    )
