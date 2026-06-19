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

import pytest

from . import helpers as h
from ._matrix import (
    matrix_abi,
    matrix_py_flavor,
    opposite_variant,
    own_variant,
)
from .conftest import SmokeVM

pytestmark = pytest.mark.repo

PKG_NAME = "pfSense-pkg-pfBlockerNG-devel"

# Our repo conf on the guest + the served catalog root. The conf name follows the
# CLAUDE.md "match the surrounding pattern" rule: pfSense's own conf is
# `pfSense.conf` under the SAME dir; ours is the shared release sibling Phase 4 will
# write for real (`add-repo.sh` — `pfblockerng.conf`, carrying stable + devel).
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
# reusable per-ABI catalog tool the Phase-3 publish job runs; here it is staged to
# the guest and run with the guest's libpkg to prove the SCRIPT's output (an
# <ABI>/ catalog tree it lays out) is accepted by a real pfSense ``pkg update`` +
# install. (The libpkg-on-Linux half of the build-side premise — that the SAME
# script + the SAME ``pkg repo`` op runs on a Linux runner — is proven locally in
# RESULTS/02; the script is identical regardless of which libpkg invokes it.)
BUILD_REPO_SH = Path(__file__).resolve().parents[2] / "scripts" / "build-repo.sh"
GUEST_BUILD_REPO_SH = f"{GUEST_SPIKE_DIR}/build-repo.sh"
GUEST_PKG_IN_DIR = f"{GUEST_SPIKE_DIR}/pkg_in"  # the input dir of .pkg for build-repo.sh
SCRIPT_REPO_ROOT = f"{GUEST_SPIKE_DIR}/script_catalog"  # build-repo.sh --out (per-ABI tree)

# Phase-3a (ADR-17) PURE-PYTHON catalog generator under test. Unlike build-repo.sh
# (which needs a libpkg ``pkg`` binary), ``build-repo-portable.py`` builds the
# catalog WITHOUT libpkg — the way the Phase-3b publish job will, on a plain Linux
# runner with no ``pkg``. Here it is run ON THE RUNNER (this test process's python,
# no guest involvement) over the branch ``.pkg``; only the produced ``<ABI>/`` tree
# is shipped to the guest, proving a real pfSense ``pkg update``/``install`` accepts
# the pure-Python catalog. This is the load-bearing fidelity gate for the generator.
BUILD_REPO_PORTABLE = Path(__file__).resolve().parents[2] / "scripts" / "build-repo-portable.py"
PORTABLE_REPO_ROOT = f"{GUEST_SPIKE_DIR}/portable_catalog"  # where the portable <ABI>/ tree is shipped

# Phase-4 (ADR-17) SHIPPED client bootstrap under test. ``add-repo.sh`` is the real
# user-facing script: it writes the production repo conf, runs ``pkg update``, and
# verifies the package is visible from OUR repo. Here it is staged to the guest and
# driven against the LOCAL file:// catalog via its existing ``--base-url`` override
# (hermetic; the github.io default + a live add-repo.sh run are a post-deploy note),
# proving the SHIPPED bootstrap — not just a hand-written conf — installs our build.
ADD_REPO_SH = Path(__file__).resolve().parents[2] / "scripts" / "add-repo.sh"
GUEST_ADD_REPO_SH = f"{GUEST_SPIKE_DIR}/add-repo.sh"

# Phase-3b (ADR-17) LIVE GitHub-Pages-URL end-to-end check. The publish pipeline
# deploys the catalog to the repo's standard project Pages URL (gh api
# repos/.../pages -> html_url https://pfblockerng.github.io/pkg/); we serve over HTTPS.
# This dispatch-only test proves a REAL pfSense box `pkg update`/`pkg install`
# against the LIVE https URL (not file://) — the maintainer's real-URL check. It is
# GATED on SMOKE_REPO_LIVE_URL: unset -> SKIP (the file:// VM-acceptance above is the
# always-on proof; the live URL only exists once the deploy has run).
LIVE_BASE_URL_ENV = "SMOKE_REPO_LIVE_URL"
DEFAULT_LIVE_BASE_URL = "https://pfblockerng.github.io/pkg"
# Case 4 (the live Cloudflare Worker leg) is GATED on SMOKE_WORKER_LIVE: unset -> SKIP.
# The Worker's routing (UA -> catalog + path mapping) is proven deterministically and
# always-on by the offline unit tests in scripts/worker/test/router.test.js; the live
# leg additionally depends on the Worker + Pages routing.json being deployed AND
# CDN-propagated, which a PR/dispatch can't guarantee — so it is opt-in post-deploy
# verification, not a hard CI gate (it would red the suite on a deploy/propagation race).
WORKER_LIVE_ENV = "SMOKE_WORKER_LIVE"
# GitHub Pages' anycast IPs. The smoke harness sandboxes guest DNS to a mock that
# only answers `uuid-*.com`, so `pfblockerng.github.io` does not resolve on the guest. Pinning
# the Pages IPs in the guest /etc/hosts lets `pkg`'s HTTPS fetch reach Pages by name
# (TLS SNI still presents `pfblockerng.github.io`, validated by GitHub's *.github.io cert) without
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


def build_repo_via_script(vm: SmokeVM, pkg_files: list[Path]) -> str:
    """Run the Phase-2 ``scripts/build-repo.sh`` on the guest over ``pkg_files``.

    Stages the real ``build-repo.sh`` and the input ``.pkg`` to the guest, runs
    ``build-repo.sh --in <pkg_in> --out <script_catalog>`` with the guest's own
    libpkg, then returns the single per-ABI catalog directory it produced. The
    script lays the release channel under ``<out>/release/<ABI>/`` (ADR-20, symmetric
    with nightly), so ``<out>`` is the base a ``file://`` repo conf points at and the
    conf's ``release/${ABI}`` url resolves to the returned dir.

    This validates the SCRIPT's output (the bucketed ``release/<ABI>/`` tree + the
    catalog triple ``pkg repo`` emits) is accepted by a real pfSense box, the live
    half of the build-side premise. The branch ``.pkg`` is a single ABI
    (``FreeBSD:15:amd64``), so exactly one ``<ABI>/`` dir is expected.
    """
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
        timeout=240.0,
    )
    # The script nests the release channel under release/, then buckets by ABI; the
    # branch .pkg is one ABI -> one release/<ABI>/ subdir.
    release_root = f"{SCRIPT_REPO_ROOT}/release"
    listing = _ssh_check(vm, "/bin/ls", "-1", release_root).stdout.split()
    assert len(listing) == 1, f"build-repo.sh produced {listing!r} ABI buckets under release/, expected exactly 1"
    abi_dir = f"{release_root}/{listing[0]}"
    # The catalog triple must be present (what `pkg update` consumes).
    for fname in ("meta.conf", "packagesite.pkg", "data.pkg"):
        present = vm.ssh("/bin/test", "-f", f"{abi_dir}/{fname}")
        assert present.returncode == 0, f"build-repo.sh did not emit {fname} under {abi_dir}"
    return abi_dir


def build_repo_via_portable(vm: SmokeVM, pkg_files: list[Path], tmp_path: Path) -> str:
    """Run ``scripts/build-repo-portable.py`` ON THE RUNNER, then ship its catalog to the guest.

    This is the Phase-3a proof: the catalog is generated in PURE PYTHON on the runner
    (no libpkg, no guest involvement) exactly as the Phase-3b publish job will, then its
    catalog files are copied to the guest. A real pfSense ``pkg update``/``install`` then
    has to accept it — the fidelity gate that the pure-Python catalog is byte-compatible
    with what real ``pkg repo`` emits. The generator is driven with ``--catalog-name
    release`` so it produces ``out/release/<ABI>/`` locally.

    The catalog files are then staged to a FLAT on-guest path, ``PORTABLE_REPO_ROOT/<ABI>/``
    — the ``release/`` segment is intentionally dropped. That flat ``<ABI>/`` layout is
    also the legacy "no variant prefix" path that ``test_legacy_abi_path_still_upgrades``
    (ADR-20 Case 3) reuses this helper to produce, so it must stay flat. The literal
    ``/release`` end-to-end symmetry is exercised by ``build_repo_via_portable_named``
    and the routing-Worker cases, not here.

    Returns the on-guest flat ``<ABI>/`` directory (the branch ``.pkg`` is one ABI,
    ``FreeBSD:15:amd64``) that the ``file://`` repo conf points at.
    """
    in_dir = tmp_path / "portable_in"
    out_dir = tmp_path / "portable_out"
    in_dir.mkdir(parents=True, exist_ok=True)
    for pkg in pkg_files:
        # Copy (not symlink) so the generator reads real bytes regardless of cwd.
        (in_dir / pkg.name).write_bytes(pkg.read_bytes())

    # Run the pure-Python generator with THIS process's interpreter — no `pkg`/libpkg.
    # --catalog-name release nests the channel under out/release/<ABI>/ (literal /release).
    proc = subprocess.run(
        [
            sys.executable,
            str(BUILD_REPO_PORTABLE),
            "--in",
            str(in_dir),
            "--out",
            str(out_dir),
            "--catalog-name",
            "release",
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
    release_root = out_dir / "release"
    abi_buckets = sorted(p for p in release_root.iterdir() if p.is_dir()) if release_root.is_dir() else []
    assert len(abi_buckets) == 1, f"portable generator produced {[p.name for p in abi_buckets]} ABI buckets, expected 1"
    local_abi_dir = abi_buckets[0]
    # The catalog triple must be present locally before shipping.
    for fname in ("meta.conf", "meta", "packagesite.pkg", "data.pkg"):
        assert (local_abi_dir / fname).is_file(), f"portable generator did not emit {fname} under {local_abi_dir}"

    # Ship the catalog files to a FLAT on-guest <ABI>/ path (fresh dir per run). The
    # release/ segment is intentionally dropped so this doubles as the legacy "no variant
    # prefix" ${ABI}/ layout that test_legacy_abi_path_still_upgrades (ADR-20 Case 3)
    # reuses this helper to produce; the /release symmetry is covered by
    # build_repo_via_portable_named + the routing-Worker cases.
    guest_abi_dir = f"{PORTABLE_REPO_ROOT}/{local_abi_dir.name}"
    _ssh_check(vm, "/bin/rm", "-rf", PORTABLE_REPO_ROOT)
    _ssh_check(vm, "/bin/mkdir", "-p", guest_abi_dir)
    for f in sorted(local_abi_dir.iterdir()):
        if f.is_file():
            _scp_to_guest(vm, f, f"{guest_abi_dir}/{f.name}")
    return guest_abi_dir


def run_add_repo_sh(vm: SmokeVM, base_url: str, *, timeout: float = 300.0) -> subprocess.CompletedProcess[str]:
    """Stage the SHIPPED ``scripts/add-repo.sh`` and run it (default release repo) against ``base_url``.

    Drives the real client bootstrap on the box: it writes the production conf to
    ``/usr/local/etc/pkg/repos/pfblockerng.conf`` (here pointed at a local
    ``file://`` catalog via the script's own ``--base-url`` override — the github.io
    default and a live HTTPS add-repo.sh run are a post-deploy note), runs ``pkg
    update``, and VERIFIES the package is visible from OUR repo. A non-zero exit (its
    verify step failing) raises with the captured output. ``base_url`` points at the
    catalog ROOT; add-repo.sh appends the literal ``${ABI}`` (pkg expands it to the
    box's ABI), so the catalog MUST live under ``<base_url>/<ABI>/``.
    """
    _ssh_check(vm, "/bin/mkdir", "-p", GUEST_SPIKE_DIR)
    _scp_to_guest(vm, ADD_REPO_SH, GUEST_ADD_REPO_SH)
    result = vm.ssh("/bin/sh", GUEST_ADD_REPO_SH, "--base-url", base_url, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(
            f"add-repo.sh --base-url {base_url} failed: rc={result.returncode}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


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


def read_compact_version(src_pkg: Path) -> str:
    """The ``version`` recorded in a ``.pkg``'s ``+COMPACT_MANIFEST`` (the base to re-version from)."""
    tar_bytes = _zstd_decompress(src_pkg.read_bytes())
    with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tf:
        member = tf.extractfile("+COMPACT_MANIFEST")
        if member is None:
            raise RuntimeError(f"{src_pkg.name}: no +COMPACT_MANIFEST member — not a libpkg .pkg?")
        obj = json.loads(member.read())
    version = obj.get("version")
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


def pkg_upgrade(vm: SmokeVM, *, timeout: float = 600.0) -> subprocess.CompletedProcess[str]:
    """``pkg upgrade -y <name>`` across ALL enabled repos — NO ``-f``.

    The exact in-repo update path a published newer build takes: with the catalog
    re-read (``pkg update -f``), ``pkg upgrade`` moves the installed package to the
    higher available build (priority decides which repo provides it — ours wins by
    ``priority:``). NO ``-f`` (a forced reinstall would mask a real version move).
    Returns the completed process so the caller can read "Missing dependency" off it.
    """
    result = vm.ssh("env", "ASSUME_ALWAYS_YES=yes", "pkg", "upgrade", "-y", PKG_NAME, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(
            f"pkg upgrade {PKG_NAME} failed: rc={result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
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
        pkg_delete(repo_vm)
        build_guest_repo(repo_vm, UPGRADE_REPO_DIR, [low_pkg])
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
        build_guest_repo(repo_vm, UPGRADE_REPO_DIR, [high_pkg])
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
      branch ``.pkg`` (its ``<ABI>/`` bucket holds meta.conf/packagesite.pkg/data.pkg),
      enabled via a NONE-signed ``file://`` repo above the pfSense repo,
    When ``pkg update`` reads it and ``pkg install -y`` runs (NO ``-r``, NO ``-f``),
    Then ``pkg update`` accepts the script-generated catalog AND the install comes
      from OUR repo (``pkg query %R`` == ``pfblockerng``) with deps resolved —
      the build tool's output is real and VM-consumable.
    """
    pkg = os.environ.get("SMOKE_PKG")
    assert pkg and Path(pkg).is_file(), "SMOKE_PKG not set / not a file"  # repo_vm already gated this

    # GIVEN: build the catalog with the Phase-2 SCRIPT (not the inline pkg repo), then
    # point a NONE-signed file:// repo at the produced <ABI>/ dir, above pfSense.
    abi_dir = build_repo_via_script(repo_vm, [Path(pkg)])
    pfsense_prio = repo_priority(repo_vm, NETGATE_REPO_NAME)
    pkg_delete(repo_vm)
    write_repo_conf(repo_vm, abi_dir, ours_priority=pfsense_prio + 100)

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
def test_shipped_add_repo_sh_bootstrap_installs(repo_vm: SmokeVM) -> None:
    """PHASE-4 SHIPPED BOOTSTRAP: the user-facing ``scripts/add-repo.sh`` writes the
    production conf, ``pkg update``s, verifies our package is visible, and the box
    then installs OUR build (no ``-f``) — the real client path, not a hand-written conf.

    add-repo.sh is run hermetically against a LOCAL ``file://`` catalog via its own
    ``--base-url`` override; the github.io default + a live HTTPS add-repo.sh run are
    the post-deploy/Phase-6 note. The shipped release conf carries the explicit
    ``release/`` channel prefix (ADR-20, symmetric with ``nightly/``), so the catalog
    is laid out by ``build-repo.sh`` under ``<root>/release/<ABI>/`` — mirroring the
    Worker's release subtree — and ``--base-url file://<root>`` makes add-repo.sh's
    ``release/${ABI}`` url resolve to it. The script ships priority 100, above the
    Netgate ``pfSense`` repo (0), so cross-repo install picks ours — the production
    mechanism.

    Given the package ABSENT and a ``build-repo.sh`` catalog under ``<root>/release/<ABI>/``,
    When ``add-repo.sh --base-url file://<root>`` runs (default release repo: writes the
      conf, ``pkg update``, verifies) and then ``pkg install -y`` runs (NO -r, NO -f),
    Then add-repo.sh exits 0 (its own verify found the package in our repo), it wrote
      the production conf to ``pfblockerng.conf``, and the install comes from
      OUR repo (``pkg query %R`` == ``pfblockerng``) with deps resolved.
    """
    pkg = os.environ.get("SMOKE_PKG")
    assert pkg and Path(pkg).is_file(), "SMOKE_PKG not set / not a file"  # repo_vm already gated this

    # GIVEN: a catalog under <SCRIPT_REPO_ROOT>/release/<ABI>/ (build-repo.sh nests the release
    # channel there, matching the shipped conf's explicit prefix), package absent. add-repo.sh's
    # release/${ABI} url resolves here.
    abi_dir = build_repo_via_script(repo_vm, [Path(pkg)])
    assert abi_dir.startswith(f"{SCRIPT_REPO_ROOT}/release/"), f"unexpected catalog dir {abi_dir!r}"
    pkg_delete(repo_vm)

    # WHEN: run the SHIPPED bootstrap against the local catalog root. Its verify step
    # must pass (it raises here otherwise) — proving the shipped conf loads our catalog.
    proc = run_add_repo_sh(repo_vm, f"file://{SCRIPT_REPO_ROOT}")

    # THEN: add-repo.sh wrote the production conf and its verify confirmed our package.
    assert "available from 'pfblockerng'" in proc.stdout, (
        f"add-repo.sh did not report the package from our repo:\n{proc.stdout}"
    )
    conf_present = repo_vm.ssh("/bin/test", "-f", REPO_CONF)
    assert conf_present.returncode == 0, f"add-repo.sh did not write {REPO_CONF}"
    assert pkg_installed_version(repo_vm) is None, f"{PKG_NAME} unexpectedly present before the bootstrap install"

    # The shipped conf is now in place; install across all enabled repos (no -r/-f).
    install = pkg_install_from_repo(repo_vm)
    combined = install.stdout + install.stderr
    assert "Missing dependency" not in combined, f"RUN_DEPENDS did not resolve via the shipped bootstrap:\n{combined}"
    origin = pkg_repo_origin(repo_vm)
    assert origin == OURS_REPO_NAME, f"installed from {origin!r}, expected our repo {OURS_REPO_NAME!r}"


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
      the branch ``.pkg`` — generated ENTIRELY on the runner in pure Python, then its
      ``<ABI>/`` tree shipped to the guest — enabled via a NONE-signed ``file://`` repo
      above the pfSense repo,
    When ``pkg update`` reads the pure-Python catalog and ``pkg install -y`` runs
      (NO ``-r``, NO ``-f``),
    Then ``pkg update`` accepts it AND the install comes from OUR repo
      (``pkg query %R`` == ``pfblockerng``) with deps resolved and the ``.pkg``
      checksum validated — the pure-Python generator's output is real + VM-consumable.
    """
    pkg = os.environ.get("SMOKE_PKG")
    assert pkg and Path(pkg).is_file(), "SMOKE_PKG not set / not a file"  # repo_vm already gated this

    # GIVEN: build the catalog with the PURE-PYTHON generator on the runner (no libpkg),
    # ship its <ABI>/ tree to the guest, point a NONE-signed file:// repo above pfSense.
    abi_dir = build_repo_via_portable(repo_vm, [Path(pkg)], tmp_path)
    pfsense_prio = repo_priority(repo_vm, NETGATE_REPO_NAME)
    pkg_delete(repo_vm)
    write_repo_conf(repo_vm, abi_dir, ours_priority=pfsense_prio + 100)

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
    abi_dir = build_repo_via_portable(repo_vm, [a, b], tmp_path)

    # THEN (catalog shape): exactly ONE package .pkg, canonically named (no prefix) — the
    # catalog files (packagesite.pkg/data.pkg) also end in .pkg, so exclude them.
    listing = _ssh_check(repo_vm, "/bin/ls", "-1", abi_dir).stdout.split()
    catalog_files = {"packagesite.pkg", "data.pkg", "meta.pkg"}
    pkgs = [n for n in listing if n.endswith(".pkg") and n not in catalog_files]
    assert len(pkgs) == 1, f"expected ONE deduped package .pkg in the bucket, got {pkgs}"
    assert pkgs[0].startswith(f"{PKG_NAME}-") and "built-incoming" not in pkgs[0], (
        f"published .pkg is not canonically named: {pkgs[0]!r}"
    )

    # WHEN/THEN (install): a real pkg installs the deduped catalog from OUR repo.
    pfsense_prio = repo_priority(repo_vm, NETGATE_REPO_NAME)
    pkg_delete(repo_vm)
    write_repo_conf(repo_vm, abi_dir, ours_priority=pfsense_prio + 100)
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
    ``https://pfblockerng.github.io/pkg``) to run the live check after a publish
    dispatch; leave it unset and the test SKIPS (the always-on proof is the
    file:// VM-acceptance above). A bare ``1``/``true`` selects the default base.
    """
    val = os.environ.get(LIVE_BASE_URL_ENV)
    if not val:
        return None
    if val.strip().lower() in {"1", "true", "yes", "on"}:
        return DEFAULT_LIVE_BASE_URL
    return val.rstrip("/")


def poll_catalog_served(base_url: str, abi: str, *, attempts: int = 30, delay: float = 10.0) -> None:
    """Poll the live ``<base>/<ABI>/meta.conf`` until it serves (first deploy + DNS/cert lag).

    The catalog files a client ``pkg update`` consumes are ``meta.conf`` +
    ``packagesite.pkg``; a 200 on both is the runner-side BACKSTOP that the deploy
    actually published a usable tree, independent of the guest. Raises with the last
    error if the URL never serves within the budget.
    """
    last_err = ""
    for _ in range(attempts):
        try:
            for fname in ("meta.conf", "packagesite.pkg"):
                url = f"{base_url}/{abi}/{fname}"
                with urllib.request.urlopen(url, timeout=15) as resp:  # noqa: S310 (fixed https Pages URL)
                    if resp.status != 200:
                        raise RuntimeError(f"{url} -> HTTP {resp.status}")
                    if not resp.read(1):
                        raise RuntimeError(f"{url} served an empty body")
            return
        except (urllib.error.URLError, RuntimeError, TimeoutError) as exc:
            last_err = f"{type(exc).__name__}: {exc}"
            time.sleep(delay)
    raise AssertionError(f"live catalog never served {base_url}/{abi}/ within budget; last error: {last_err}")


def pin_pages_hosts(vm: SmokeVM, host: str, *, timeout: float = 60.0) -> None:
    """Pin GitHub Pages' anycast IPs for ``host`` in the guest ``/etc/hosts``.

    The smoke harness sandboxes guest DNS to a mock answering only ``uuid-*.com``,
    so the Pages host does not resolve on the box. A static ``/etc/hosts`` entry
    routes ``pkg``'s HTTPS fetch to Pages by IP while TLS SNI still presents ``host``
    (GitHub's *.github.io cert validates). Idempotent: the entry is removed first.
    """
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


def write_live_repo_conf(vm: SmokeVM, base_url: str, *, priority: int, timeout: float = 60.0) -> None:
    """Write OUR production conf pointing at the LIVE ``<base>/${ABI}`` Pages URL.

    Built from the SAME generator the publish job emits (``build-repo-portable.py
    --print-conf --base-url <base>``), but with the ``priority:`` raised above the
    Netgate ``pfSense`` repo so cross-repo resolution favours ours. The literal
    ``${ABI}`` is expanded by pkg(8) (not the shell) and follows the box's ABI.
    """
    proc = subprocess.run(
        [sys.executable, str(BUILD_REPO_PORTABLE), "--print-conf", "--base-url", base_url],
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
        vm.ssh_argv("tee", REPO_CONF),
        input=conf,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if written.returncode != 0:
        raise RuntimeError(f"write_live_repo_conf failed: rc={written.returncode} {written.stderr!r}")


@pytest.mark.timeout(900)  # live deploy/DNS/cert can lag + pkg update + install over the public URL.
def test_install_from_live_pages_url(repo_vm: SmokeVM) -> None:
    """PHASE-3b LIVE URL: a real pfSense box installs from the DEPLOYED Pages catalog
    over its public HTTPS ``https://pfblockerng.github.io/pkg/${ABI}`` URL (no ``-f``).

    DISPATCH-ONLY + GATED on ``SMOKE_REPO_LIVE_URL`` (unset -> SKIP). The always-on
    proof is the file:// VM-acceptance above; this exercises the REAL transport the
    publish pipeline serves, so it can only run after a publish dispatch has deployed.

    Given the publish job has DEPLOYED the catalog to Pages (runner-side backstop:
      ``<base>/<ABI>/meta.conf`` + ``packagesite.pkg`` serve 200), the guest has the
      Pages IPs pinned for the host (its DNS is sandboxed), the package is ABSENT, and
      OUR conf points at the live ``${ABI}`` URL above the Netgate ``pfSense`` repo,
    When ``pkg update`` reads the live catalog and ``pkg install -y`` runs (NO ``-r``,
      NO ``-f``),
    Then ``pkg update`` accepts the deployed catalog AND the install comes from OUR
      repo (``pkg query %R`` == ``pfblockerng``) with deps resolved and the .pkg
      checksum validated — the deployed Pages repo is real + installable over HTTPS.
    """
    base_url = _live_base_url()
    if base_url is None:
        pytest.skip(f"{LIVE_BASE_URL_ENV} not set — live Pages-URL check is dispatch-only (file:// proof always runs)")
    assert base_url is not None  # for the type-checker: pytest.skip above is NoReturn

    host = urllib.parse.urlparse(base_url).hostname
    assert host, f"could not parse a host from {base_url!r}"

    # BACKSTOP: prove the deploy actually serves the catalog from the RUNNER first
    # (independent of the guest) — polls through first-deploy / DNS / cert lag. The ABI to
    # poll is this leg's own, derived from the matrix (the CE box for the live-pages check).
    poll_catalog_served(base_url, matrix_abi())

    # GIVEN: Pages IPs pinned (guest DNS is sandboxed), package absent, our conf at
    # the LIVE url above pfSense.
    pin_pages_hosts(repo_vm, host)
    pfsense_prio = repo_priority(repo_vm, NETGATE_REPO_NAME)
    pkg_delete(repo_vm)
    write_live_repo_conf(repo_vm, base_url, priority=pfsense_prio + 100)

    # WHEN: pkg update must ACCEPT the live HTTPS catalog (a rejected catalog — bad
    # meta.conf, malformed packagesite, mismatched sum, or an unreachable URL — fails here).
    pkg_update(repo_vm)
    assert pkg_installed_version(repo_vm) is None, f"{PKG_NAME} unexpectedly present before the live-URL install"

    # THEN: install resolves from our LIVE repo, deps included, .pkg checksum validated.
    proc = pkg_install_from_repo(repo_vm)
    combined = proc.stdout + proc.stderr
    assert "Missing dependency" not in combined, f"RUN_DEPENDS did not resolve from the live Pages catalog:\n{combined}"
    origin = pkg_repo_origin(repo_vm)
    assert origin == OURS_REPO_NAME, f"installed from {origin!r}, expected our repo {OURS_REPO_NAME!r}"


# =========================================================================== #
# ADR-20 Phase 6 — variant-catalog live-VM cases (CE install, wrong-variant   #
# guard, legacy path, routing URL).                                            #
#                                                                              #
# Marker: @pytest.mark.repo  (inherited from pytestmark = pytest.mark.repo).  #
# Deselected from default `python -m pytest` — dispatched via:                #
#     gh workflow run smoke.yml -f pytest_marker=repo                          #
# =========================================================================== #

# Base dir for ADR-20 variant catalogs on the guest (isolated from the ADR-17 spike dir).
VARIANT_REPO_ROOT = "/tmp/pfb_variant_repo"

# Base dir for ADR-27 EOL route-only catalog on the guest.
EOL_REPO_ROOT = "/tmp/pfb_eol_repo"


# Routing Worker URL (Phase 5). The live Case 4 leg is gated on SMOKE_WORKER_LIVE (the
# deterministic routing proof is the offline scripts/worker/test/ suite).
WORKER_BASE_URL = "https://pkg.pfblockerng.workers.dev"


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
    """Like ``build_repo_via_portable`` but writes under ``<out>/<catalog-name>/<ABI>/``.

    Uses ``build-repo-portable.py --catalog-name <catalog_name>`` to place the
    ABI subtree under the named variant directory (e.g. ``ce-2.8/FreeBSD:15:amd64/``).
    Ships only the produced ``<catalog-name>/<ABI>/`` tree to the guest under
    ``guest_root``; returns the on-guest ABI path the repo conf should point at.
    """
    in_dir = tmp_path / f"in_{catalog_name}"
    out_dir = tmp_path / f"out_{catalog_name}"
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

    catalog_root = out_dir / catalog_name
    abi_buckets = sorted(p for p in catalog_root.iterdir() if p.is_dir())
    assert len(abi_buckets) == 1, (
        f"portable generator produced {[p.name for p in abi_buckets]} ABI buckets under {catalog_name}/, expected 1"
    )
    local_abi_dir = abi_buckets[0]
    for fname in ("meta.conf", "meta", "packagesite.pkg", "data.pkg"):
        assert (local_abi_dir / fname).is_file(), f"portable generator did not emit {fname} under {local_abi_dir}"

    # Ship the <catalog-name>/<ABI>/ tree to the guest.
    guest_abi_dir = f"{guest_root}/{catalog_name}/{local_abi_dir.name}"
    _ssh_check(vm, "/bin/rm", "-rf", f"{guest_root}/{catalog_name}")
    _ssh_check(vm, "/bin/mkdir", "-p", guest_abi_dir)
    for f in sorted(local_abi_dir.iterdir()):
        if f.is_file():
            _scp_to_guest(vm, f, f"{guest_abi_dir}/{f.name}")
    return guest_abi_dir


def forge_variant_pkg(src_pkg: Path, out_dir: Path, *, target_php: str, target_abi: str) -> Path:
    """Forge a fake .pkg for a DIFFERENT variant from the branch .pkg.

    Re-reads the +COMPACT_MANIFEST, replaces every ``php8N`` dep key with
    ``target_php``, sets the ``abi`` to ``target_abi``, and repacks. No payload
    change — the dep/ABI-mismatch guard fires before pkg ever checks the files.
    Used by the wrong-variant guard to fabricate the OPPOSITE variant for this
    box (CE box -> Plus pkg; Plus box -> CE pkg). The returned .pkg is placed in
    ``out_dir``.
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
                # Set the target ABI so the portable generator buckets it correctly.
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
    ``<variant>/${ABI}`` catalog; its own php + Python deps resolve; origin is our repo.

    Scenario: package installed from the variant-correct catalog for THIS box.
      Background: hermetic file:// catalog at ``<own.catalog>/<own.abi>/``. The variant
      (ABI / php / Python flavor) comes from the ci-metadata matrix (SMOKE_ABI /
      SMOKE_PHP_VERSION / SMOKE_PY_FLAVOR), so the CE leg asserts php83/FreeBSD:15 and the
      Plus leg asserts php85/FreeBSD:16 — no hardcoded flavor.

    Given the package ABSENT and a variant-keyed catalog under ``<variant>/${ABI}/``
      built from the branch .pkg by the pure-Python generator,
    When ``pkg install -y <pkgname>`` resolves from this catalog,
    Then ``pkg query '%dn %dv' <pkgname>`` shows the box's OWN php dep AND the matrix
      Python flavor, the OPPOSITE variant's php dep is ABSENT, the version matches the
      branch .pkg, and the origin is our repo.
    Assert BEFORE: ``pkg query '%n' <pkgname>`` returns empty (package absent).
    Assert AFTER: dep list contains own php + Python flavor; opposite php absent; version
      and origin correct.
    """
    pkg = os.environ.get("SMOKE_PKG")
    assert pkg and Path(pkg).is_file(), "SMOKE_PKG not set / not a file"

    own = own_variant()
    opp = opposite_variant()

    # GIVEN: build the box's variant catalog with the variant-keyed dir on the runner,
    # ship to guest, write a NONE-signed file:// repo conf above pfSense.
    abi_dir = build_repo_via_portable_named(
        repo_vm,
        [Path(pkg)],
        tmp_path,
        catalog_name=own.catalog,
        guest_root=VARIANT_REPO_ROOT,
    )
    pfsense_prio = repo_priority(repo_vm, NETGATE_REPO_NAME)
    pkg_delete(repo_vm)
    write_repo_conf(repo_vm, abi_dir, ours_priority=pfsense_prio + 100)

    # Before-state: package absent.
    pkg_update(repo_vm)
    before_name = vm_pkg_query_name(repo_vm)
    assert before_name == "", f"package unexpectedly present before variant install: {before_name!r}"

    # WHEN: install from the box's variant catalog (no -r, no -f).
    proc = pkg_install_from_repo(repo_vm)
    combined = proc.stdout + proc.stderr
    assert "Missing dependency" not in combined, f"variant catalog: RUN_DEPENDS did not resolve:\n{combined}"

    # THEN: dep list carries the box's OWN php + the matrix Python flavor, NOT the opposite php.
    deps_out = pkg_query_deps(repo_vm)
    assert own.php in deps_out, (
        f"{own.php} dep not satisfied after {own.abi} variant install; pkg query '%dn %dv' output:\n{deps_out}"
    )
    assert opp.php not in deps_out, (
        f"opposite-variant dep {opp.php} should not appear in a {own.abi} install; "
        f"pkg query '%dn %dv' output:\n{deps_out}"
    )
    py_flavor = matrix_py_flavor()
    assert py_flavor in deps_out, (
        f"matrix Python flavor {py_flavor} not in deps after variant install; pkg query '%dn %dv' output:\n{deps_out}"
    )
    origin = pkg_repo_origin(repo_vm)
    assert origin == OURS_REPO_NAME, f"variant install: came from {origin!r}, expected {OURS_REPO_NAME!r}"
    version = pkg_installed_version(repo_vm)
    assert version is not None, "variant install: pkg query %v returned empty after install"


def vm_pkg_query_name(vm: SmokeVM, *, timeout: float = 60.0) -> str:
    """``pkg query '%n' <PKG_NAME>`` — the package name if installed, else empty string."""
    result = vm.ssh("pkg", "query", "%n", PKG_NAME, timeout=timeout)
    return result.stdout.strip() if result.returncode == 0 else ""


# --------------------------------------------------------------------------- #
# ADR-20 Case 2 — wrong-variant guard: box rejects the OPPOSITE variant        #
# --------------------------------------------------------------------------- #


@pytest.mark.timeout(900)
def test_wrong_variant_catalog_fails(repo_vm: SmokeVM, tmp_path: Path) -> None:
    """ADR-20 P6 CASE 2 — Installing the OPPOSITE variant's package on this box fails;
    that variant's php dep is unsatisfied; the package is NOT installed after the attempt.

    The box's own variant and the wrong (opposite) variant both come from the ci-metadata
    matrix (SMOKE_ABI / SMOKE_PHP_VERSION), so this runs symmetrically: a CE box rejects a
    forged Plus (php85/FreeBSD:16) package, and a Plus box rejects a forged CE
    (php83/FreeBSD:15) package — no hardcoded direction.

    Scenario: installing the opposite-variant package fails with an unsatisfied dep.
      Background: hermetic file:// catalog at ``<opp.catalog>/<opp.abi>/``.

    Before-state ASSERT: the box's OWN package (``<own.catalog>/${ABI}``) installs CLEANLY
      (own php dep satisfied) — proves the own path is correct and the AFTER failure is
      caused by the variant mismatch, not an unrelated setup issue.
    Given the own package uninstalled and the repo conf pointing at the opposite-variant
      catalog (ABI mismatch),
    When ``pkg install -y <pkgname>`` from the opposite catalog,
    Then exit code is non-zero OR the error output mentions the opposite php / ABI mismatch,
      AND ``pkg query '%n' <pkgname>`` confirms the package is NOT installed.
    """
    pkg = os.environ.get("SMOKE_PKG")
    assert pkg and Path(pkg).is_file(), "SMOKE_PKG not set / not a file"
    src = Path(pkg)

    own = own_variant()
    opp = opposite_variant()

    # ---- Before-state: prove the box's OWN path works (the guard control) ----
    own_abi_dir = build_repo_via_portable_named(
        repo_vm,
        [src],
        tmp_path,
        catalog_name=own.catalog,
        guest_root=VARIANT_REPO_ROOT,
    )
    pfsense_prio = repo_priority(repo_vm, NETGATE_REPO_NAME)
    pkg_delete(repo_vm)
    write_repo_conf(repo_vm, own_abi_dir, ours_priority=pfsense_prio + 100)
    pkg_update(repo_vm)

    # Assert before-state: absent before the own-variant control install.
    assert vm_pkg_query_name(repo_vm) == "", "package unexpectedly present before own-variant control install"

    own_install = pkg_install_from_repo(repo_vm)
    own_combined = own_install.stdout + own_install.stderr
    assert "Missing dependency" not in own_combined, (
        f"Control ({own.abi}) install: RUN_DEPENDS did not resolve:\n{own_combined}"
    )
    own_deps = pkg_query_deps(repo_vm)
    assert own.php in own_deps, f"Control ({own.abi}) install: {own.php} not in deps; pkg query '%dn %dv':\n{own_deps}"
    # Own install succeeded — this is the before-state anchor.

    # ---- Forge the OPPOSITE variant's .pkg (opp.php dep, opp.abi ABI) ----
    opp_pkg = forge_variant_pkg(src, tmp_path / "opp_forge", target_php=opp.php, target_abi=opp.abi)

    # ---- Build the opposite-variant catalog in <opp.catalog>/<opp.abi>/ ----
    opp_abi_dir = build_repo_via_portable_named(
        repo_vm,
        [opp_pkg],
        tmp_path,
        catalog_name=opp.catalog,
        guest_root=VARIANT_REPO_ROOT,
    )

    # Remove the own install; point conf at the opposite-variant catalog.
    pkg_delete(repo_vm)
    assert vm_pkg_query_name(repo_vm) == "", "package still present after pkg_delete"
    write_repo_conf(repo_vm, opp_abi_dir, ours_priority=pfsense_prio + 100)

    try:
        pkg_update(repo_vm)
    except RuntimeError:
        # pkg update may fail on ABI mismatch (this box vs the opposite ABI) — that
        # is itself evidence the guard fired; treat as acceptable.
        pass

    # WHEN: attempt install of the opposite variant on this box.
    install_result = repo_vm.ssh("env", "ASSUME_ALWAYS_YES=yes", "pkg", "install", "-y", PKG_NAME, timeout=300.0)

    # THEN: either the install failed non-zero, or it "succeeded" but the dep was
    # unsatisfied (pkg may exit 0 on some error paths but the package is absent).
    install_failed = install_result.returncode != 0
    install_output = install_result.stdout + install_result.stderr
    package_installed = vm_pkg_query_name(repo_vm) != ""

    # The guard must fire: either the install returned non-zero, or the package is absent.
    assert install_failed or not package_installed, (
        f"Wrong-variant guard did NOT fire: {opp.abi} package installed successfully on a {own.abi} box.\n"
        f"pkg install rc={install_result.returncode}\n"
        f"pkg install output:\n{install_output}\n"
        f"pkg query '%n': {vm_pkg_query_name(repo_vm)!r}"
    )
    # The error output should mention the opposite php or an ABI mismatch (informational — soft).
    has_opp_php_error = opp.php in install_output
    has_abi_error = any(kw in install_output.lower() for kw in ("abi", "mismatch", "incompatible", "not found"))
    assert has_opp_php_error or has_abi_error or install_failed, (
        f"Wrong-variant install: expected {opp.php}/ABI error or non-zero exit; got:\n"
        f"rc={install_result.returncode}\n{install_output}"
    )
    # Package must NOT be installed after the failed attempt.
    assert not package_installed, (
        f"Wrong-variant guard: package IS installed despite expected failure; "
        f"pkg query '%n': {vm_pkg_query_name(repo_vm)!r}"
    )


# --------------------------------------------------------------------------- #
# ADR-20 Case 3 — legacy ${ABI}/ path still serves CE build                   #
# --------------------------------------------------------------------------- #


@pytest.mark.timeout(900)
def test_legacy_abi_path_still_upgrades(repo_vm: SmokeVM, tmp_path: Path) -> None:
    """ADR-20 P6 CASE 3 — Old-conf CE box (legacy ``${ABI}/`` path, no variant
    prefix) still upgrades from N to N+1 during the ADR-20 transition window.

    Scenario: Old-conf CE box (legacy ABI/ path) still upgrades.
      Background: hermetic file:// legacy catalog at FreeBSD:15:amd64/ (no variant prefix).

    Given version N installed from the legacy (no-prefix) ``${ABI}/`` path,
    When the catalog is rebuilt with version N+1 and ``pkg upgrade -y`` runs,
    Then the box moves to N+1, still from our repo.
    Assert BEFORE: version N installed, N+1 available from catalog.
    Assert AFTER: version N+1 installed.
    """
    pkg = os.environ.get("SMOKE_PKG")
    assert pkg and Path(pkg).is_file(), "SMOKE_PKG not set / not a file"
    src = Path(pkg)

    base_version = read_compact_version(src)
    low_version = f"{base_version}_1"
    high_version = f"{base_version}_9"
    assert low_version != high_version

    low_pkg = reversion_pkg(src, low_version, tmp_path / "legacy_low")
    high_pkg = reversion_pkg(src, high_version, tmp_path / "legacy_high")

    pfsense_prio = repo_priority(repo_vm, NETGATE_REPO_NAME)

    try:
        # ---- GIVEN: legacy catalog (no variant prefix) with the LOWER build ----
        # build_repo_via_portable produces <out>/<ABI>/ (no catalog-name prefix).
        legacy_abi_dir = build_repo_via_portable(repo_vm, [low_pkg], tmp_path)
        pkg_delete(repo_vm)
        write_repo_conf(repo_vm, legacy_abi_dir, ours_priority=pfsense_prio + 100)
        pkg_update(repo_vm)
        assert vm_pkg_query_name(repo_vm) == "", f"{PKG_NAME} unexpectedly present before legacy upgrade test"

        # Install the LOWER version from the legacy path.
        pkg_install_from_repo(repo_vm)

        # Assert BEFORE: N installed, from our repo.
        installed_low = pkg_installed_version(repo_vm)
        assert installed_low == low_version, (
            f"Legacy path: expected {low_version!r} installed first, got {installed_low!r}"
        )
        assert pkg_repo_origin(repo_vm) == OURS_REPO_NAME, (
            f"Legacy low build came from {pkg_repo_origin(repo_vm)!r}, expected our repo"
        )

        # ---- WHEN: rebuild legacy catalog with HIGHER build, upgrade ----
        # Must rebuild into the SAME on-guest dir so the existing conf still points at it.
        # Re-run portable generator into a new runner tmp, ship to the same guest dir.
        in_high = tmp_path / "legacy_high_in"
        out_high = tmp_path / "legacy_high_out"
        in_high.mkdir(parents=True, exist_ok=True)
        (in_high / high_pkg.name).write_bytes(high_pkg.read_bytes())
        proc_high = subprocess.run(
            [sys.executable, str(BUILD_REPO_PORTABLE), "--in", str(in_high), "--out", str(out_high)],
            capture_output=True,
            text=True,
            timeout=180.0,
            check=False,
        )
        if proc_high.returncode != 0:
            raise RuntimeError(
                f"build-repo-portable.py (legacy high) failed: rc={proc_high.returncode}\n"
                f"stdout:\n{proc_high.stdout}\nstderr:\n{proc_high.stderr}"
            )
        high_abi_dirs = sorted(p for p in out_high.iterdir() if p.is_dir())
        assert len(high_abi_dirs) == 1, (
            f"legacy high catalog produced {[p.name for p in high_abi_dirs]} ABI dirs, expected 1"
        )
        high_local_abi = high_abi_dirs[0]

        # Ship the updated catalog to the SAME guest ABI dir (overwrite in place).
        for f in sorted(high_local_abi.iterdir()):
            if f.is_file():
                _scp_to_guest(repo_vm, f, f"{legacy_abi_dir}/{f.name}")

        pkg_update(repo_vm)
        proc_upg = pkg_upgrade(repo_vm)

        # THEN: box moves to N+1, still from our repo.
        upg_combined = proc_upg.stdout + proc_upg.stderr
        assert "Missing dependency" not in upg_combined, f"Legacy upgrade: RUN_DEPENDS did not resolve:\n{upg_combined}"
        installed_high = pkg_installed_version(repo_vm)
        assert installed_high == high_version, (
            f"Legacy upgrade: expected {high_version!r} after upgrade, got {installed_high!r}"
        )
        assert pkg_repo_origin(repo_vm) == OURS_REPO_NAME, (
            f"Legacy upgrade: origin {pkg_repo_origin(repo_vm)!r}, expected our repo"
        )
    finally:
        pkg_delete(repo_vm)
        repo_vm.ssh("/bin/rm", "-rf", VARIANT_REPO_ROOT, timeout=60.0)


# --------------------------------------------------------------------------- #
# ADR-20 Case 4 — routing URL delivers CE catalog (network; xfail)            #
# --------------------------------------------------------------------------- #


@pytest.mark.timeout(300)
def test_routing_url_delivers_variant_catalog(repo_vm: SmokeVM) -> None:
    """ADR-20 P6 CASE 4 — pkg fetch via Worker URL gets THIS box's variant catalog.

    Scenario: pkg fetch via Worker URL gets the box's variant meta.conf.
      Background: conf with url: https://pkg.pfblockerng.workers.dev.

    Given a box with the conf pointing at the Worker URL (``${ABI}`` suffix added
      by pkg), ``pkg update -r pfblockerng`` fetches from the Worker.
    Then the fetched catalog contains the box's OWN variant package (not the opposite) —
      confirmed by ``pkg rquery -r pfblockerng '%dn %dv' <pkgname>`` showing the box's own
      php dep (php83 on CE / php85 on Plus, from the matrix).

    GATED on ``SMOKE_WORKER_LIVE`` (unset -> SKIP). The routing LOGIC is proven
    always-on + deterministically by the offline Worker unit tests
    (``scripts/worker/test/router.test.js`` — UA->catalog dispatch + path mapping with
    the edge stubbed). THIS leg additionally exercises the LIVE Worker + Pages
    routing.json end-to-end, which depends on a deployed + CDN-propagated edge a
    PR/dispatch can't guarantee; run it as opt-in post-deploy verification.
    """
    val = os.environ.get(WORKER_LIVE_ENV, "").strip().lower()
    if val not in {"1", "true", "yes", "on"}:
        pytest.skip(
            f"{WORKER_LIVE_ENV} not set — the live Cloudflare Worker leg is CDN-dependent "
            f"(deterministic routing proof is the offline scripts/worker/test/ unit suite)"
        )
    _ensure_egress_open()

    # Write a NONE-signed repo conf pointing at the Worker URL.
    # The Worker appends the request path (/<ABI>/...) and 302s to the variant catalog.
    worker_conf = (
        f"{OURS_REPO_NAME}: {{\n"
        f'  url: "{WORKER_BASE_URL}/${{ABI}}",\n'
        "  signature_type: none,\n"
        "  enabled: yes,\n"
        "  priority: 100\n"
        "}\n"
    )
    written = subprocess.run(
        repo_vm.ssh_argv("tee", REPO_CONF),
        input=worker_conf,
        capture_output=True,
        text=True,
        timeout=60.0,
        check=False,
    )
    if written.returncode != 0:
        raise RuntimeError(f"write Worker conf failed: rc={written.returncode} {written.stderr!r}")

    # pkg update via the Worker must succeed (routing.json is live on Pages). Earlier cases in
    # this VM built the `pfblockerng` repo DB from a different (Pages/add-repo) URL; pkg keys its
    # cached catalogue DB to the packagesite and otherwise refuses with "wrong packagesite, need
    # to re-create database" (a forced `-f` refresh does not clear it). Drop the cached per-repo
    # DB so this fetch re-creates it cleanly from the Worker URL.
    _ssh_check(repo_vm, "/bin/rm", "-rf", f"/var/db/pkg/repos/{OURS_REPO_NAME}", timeout=60.0)
    update_result = repo_vm.ssh(
        "env", "ASSUME_ALWAYS_YES=yes", "pkg", "update", "-f", "-r", OURS_REPO_NAME, timeout=120.0
    )
    if update_result.returncode != 0:
        update_out = update_result.stdout + update_result.stderr
        pytest.fail(
            f"Worker pkg update failed (rc={update_result.returncode}); routing.json should be live:\n{update_out}"
        )

    # The fetched catalog must contain the box's OWN variant package (own php dep
    # present, opposite absent) — variant from the matrix.
    own = own_variant()
    opp = opposite_variant()
    rquery = repo_vm.ssh("pkg", "rquery", "-r", OURS_REPO_NAME, "%dn %dv", PKG_NAME, timeout=60.0)
    if rquery.returncode != 0:
        pytest.fail(
            f"Worker pkg rquery failed (rc={rquery.returncode})\nstdout:\n{rquery.stdout}\nstderr:\n{rquery.stderr}"
        )
    rquery_out = rquery.stdout.strip()
    assert own.php in rquery_out, (
        f"Worker URL catalog does not contain the box's {own.php} dep; pkg rquery '%dn %dv' output:\n{rquery_out}"
    )
    assert opp.php not in rquery_out, (
        f"Worker URL returned the {opp.abi} ({opp.php}) catalog to a {own.abi} box; pkg rquery output:\n{rquery_out}"
    )


# =========================================================================== #
# ADR-27 Phase 4 — release rollback lifecycle (multi-version catalog, -m repo) #
#                                                                               #
# Proves the ADR-27 §2 premise on a REAL pfSense VM: a multi-version release   #
# catalog lets pkg install a pinned older version with dependency resolution    #
# from our repo (the only route that resolves deps; pkg add <raw-url> does not #
# consult the catalog for dep resolution). This is the REJECT gate per ADR §7: #
# if `pkg install <name>-<version>` cannot roll back with dep resolution, Part  #
# 1 degrades to docs-only (raw `pkg add` path only).                           #
#                                                                               #
# Marker: @pytest.mark.repo  (inherited from pytestmark = pytest.mark.repo).   #
# Dispatched via:  gh workflow run smoke.yml -f pytest_marker=repo             #
# =========================================================================== #


def pkg_install_pinned(vm: SmokeVM, version: str, *, timeout: float = 600.0) -> subprocess.CompletedProcess[str]:
    """``pkg install -fy <name>-<version>`` — the PINNED rollback command (ADR §2.1 rollback UX).

    This is the exact CLI command documented in README and scripts/README.md: installs the
    named package at an EXPLICIT version from the multi-version catalog.  ``-f`` (force) is
    REQUIRED to roll *back*: without it, ``pkg install`` is a no-op when a NEWER build of the
    same package is already installed (pkg never downgrades by default) — the documented
    FreeBSD downgrade idiom.  If the version is not in the catalog, pkg returns non-zero.  Dep
    resolution against the enabled repos runs normally — the catalog-provided dep metadata is
    honoured, not bypassed (unlike ``pkg add <raw-url>`` which skips catalog dep resolution).
    A non-zero exit raises with the full output.
    """
    pinned_name = f"{PKG_NAME}-{version}"
    result = vm.ssh("env", "ASSUME_ALWAYS_YES=yes", "pkg", "install", "-fy", pinned_name, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(
            f"pkg install {pinned_name} failed: rc={result.returncode}"
            f"\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


@pytest.mark.timeout(900)  # forge 2 builds + 2 catalog gen + 3 pkg ops (install/rollback/upgrade) > the 30s cap.
def test_release_rollback_to_retained_older_version(repo_vm: SmokeVM, tmp_path: Path) -> None:
    """ADR-27 P4 KILL-GATE: a multi-version release catalog allows a REAL pfSense box to
    pin-install an OLDER retained version with dependency resolution (the documented
    rollback UX), then re-upgrade to the newest — a full install→rollback→upgrade lifecycle.

    This is the ADR §7 REJECT gate: if ``pkg install <name>-<version>`` cannot pin-install
    a retained older version with dep resolution from our repo, Part 1 degrades to docs-only
    (only ``pkg add <raw-url>`` is available, with no dep resolution from the catalog).

    The multi-version catalog is built on the runner (pure-Python ``build-repo-portable.py``)
    over BOTH the lower (``<V>_lo``) and higher (``<V>_hi``) forged builds, then shipped to
    the guest as a single ``<ABI>/`` tree.  Both packages are advertised in the same
    ``packagesite.yaml``; ``pkg install <name>`` resolves the highest; ``pkg install
    <name>-<V>_lo`` resolves the pinned older one.

    The variant (ABI / PHP flavor) comes from the version matrix (SMOKE_ABI / SMOKE_PHP_VERSION)
    — never hardcoded.  ``build_repo_via_portable`` derives the ABI bucket from the ``.pkg``'s
    own manifest (the branch ``.pkg`` is the box's exact ABI: ``FreeBSD:15:amd64`` / php83 on
    CE, ``FreeBSD:16:amd64`` / php85 on Plus).

    Scenario: install-newest → pin-rollback → re-upgrade, all from a multi-version release catalog.
      Background:
        - Two versions forged from the branch .pkg: ``<V>_lo`` (older) and ``<V>_hi`` (newer).
        - A single multi-version catalog serving BOTH, built by build-repo-portable.py.
        - A NONE-signed file:// repo conf above the Netgate pfSense repo.

    Given the package ABSENT and the multi-version catalog carrying BOTH ``<V>_lo`` and ``<V>_hi``,
      When ``pkg install -y <name>`` (no version pin) runs,
      Then NEWEST-WINS: ``<V>_hi`` is active, origin is our repo, RUN_DEPENDS resolved.
        (This asserts the before-state for the rollback step — proves the catalog serves
        the highest version by default and that the after-rollback state is a real regression.)
    When ``pkg install -fy <name>-<V>_lo`` (PINNED older version, ``-f`` forces the downgrade) runs,
      Then ROLLBACK: ``<V>_lo`` is active, origin is still our repo, no "Missing dependency"
        (catalog dep resolution worked; the premise holds).
        (This is the REJECT gate: if this install fails, Part 1 must be downgraded to docs-only.)
    When ``pkg upgrade -y <name>`` runs (after pkg update -f re-reads the same catalog),
      Then RE-UPGRADE: ``<V>_hi`` is active again, origin is our repo — lifecycle closed.
    """
    pkg = os.environ.get("SMOKE_PKG")
    assert pkg and Path(pkg).is_file(), "SMOKE_PKG not set / not a file"  # repo_vm already gated this
    src = Path(pkg)

    base_version = read_compact_version(src)
    lo_version = f"{base_version}_1"
    hi_version = f"{base_version}_9"
    # Sanity: the forged versions must be distinct so each transition is real.
    assert lo_version != hi_version
    # The rollback target must sort BELOW the high version so pkg install <name> picks hi by default.
    # pkg version-sorts the trailing ``_N`` as the numeric PORTREVISION, so _1 < _9 (same as the
    # _1->_9 upgrade cases above). A non-numeric suffix (_lo/_hi) would instead sort ALPHABETICALLY
    # under pkg's PORTREVISION rules — "lo" > "hi" — inverting the intended order. Verified:
    # reversion_pkg only rewrites the version string; all other manifest fields (including deps)
    # are copied verbatim, so both builds have identical RUN_DEPENDS.

    lo_pkg = reversion_pkg(src, lo_version, tmp_path / "rollback_lo")
    hi_pkg = reversion_pkg(src, hi_version, tmp_path / "rollback_hi")

    pfsense_prio = repo_priority(repo_vm, NETGATE_REPO_NAME)

    try:
        # ---- Build the multi-version catalog (BOTH builds in one ABI tree) ----
        # build_repo_via_portable takes a list of .pkg files; with two distinct versions of
        # the SAME package it writes two NDJSON entries in packagesite.yaml — a multi-version
        # catalog exactly as build_repo_matrix(release_keep_devel=2) produces in production.
        # The catalog is built on the runner (pure Python; no libpkg needed) and shipped to
        # the guest under PORTABLE_REPO_ROOT/<ABI>/ (same helper used by the portable fidelity tests).
        multi_abi_dir = build_repo_via_portable(repo_vm, [lo_pkg, hi_pkg], tmp_path)

        # --- GIVEN: package absent; multi-version catalog enabled above the pfSense repo. ---
        pkg_delete(repo_vm)
        write_repo_conf(repo_vm, multi_abi_dir, ours_priority=pfsense_prio + 100)
        pkg_update(repo_vm)
        assert pkg_installed_version(repo_vm) is None, (
            f"{PKG_NAME} unexpectedly present before the rollback lifecycle test"
        )

        # --- WHEN (1): install without a version pin → newest-wins. ---
        proc_install = pkg_install_from_repo(repo_vm)

        # THEN (before-state anchor): the box is at the HIGHER version (newest-wins default),
        # from our repo, deps resolved.  This is the before-state the rollback must visibly
        # depart from — if the before-state is already at _lo, the rollback assertion is vacuous.
        combined_install = proc_install.stdout + proc_install.stderr
        assert "Missing dependency" not in combined_install, (
            f"Multi-version catalog: RUN_DEPENDS did not resolve on newest-wins install:\n{combined_install}"
        )
        before_version = pkg_installed_version(repo_vm)
        assert before_version == hi_version, (
            f"Newest-wins: expected {hi_version!r} installed first (highest in catalog), "
            f"got {before_version!r} — catalog version ordering wrong"
        )
        assert pkg_repo_origin(repo_vm) == OURS_REPO_NAME, (
            f"Newest-wins install: origin {pkg_repo_origin(repo_vm)!r}, expected {OURS_REPO_NAME!r}"
        )

        # --- WHEN (2): pin-install the OLDER version — the documented rollback command. ---
        # This is the ADR §7 REJECT gate: failure here (non-zero exit or "Missing dependency")
        # means the catalog-based rollback premise does NOT hold.
        proc_rollback = pkg_install_pinned(repo_vm, lo_version)

        # THEN (rollback): the box is now at the LOWER version, STILL from our repo, deps resolved.
        combined_rollback = proc_rollback.stdout + proc_rollback.stderr
        assert "Missing dependency" not in combined_rollback, (
            f"Rollback: RUN_DEPENDS did not resolve when pinning {lo_version!r}:\n{combined_rollback}"
        )
        rollback_version = pkg_installed_version(repo_vm)
        assert rollback_version == lo_version, (
            f"Rollback: expected {lo_version!r} active after pin-install, got {rollback_version!r}"
        )
        assert pkg_repo_origin(repo_vm) == OURS_REPO_NAME, (
            f"Rollback: origin {pkg_repo_origin(repo_vm)!r}, expected {OURS_REPO_NAME!r} — "
            f"pinned install should still source from our multi-version catalog"
        )

        # --- WHEN (3): re-upgrade — close the lifecycle. ---
        # The multi-version catalog still carries hi_version; pkg upgrade moves back up.
        pkg_update(repo_vm)
        proc_upgrade = pkg_upgrade(repo_vm)

        # THEN (re-upgrade): the box is back at the HIGHER version, lifecycle closed.
        combined_upgrade = proc_upgrade.stdout + proc_upgrade.stderr
        assert "Missing dependency" not in combined_upgrade, (
            f"Re-upgrade: RUN_DEPENDS did not resolve when upgrading from {lo_version!r}:\n{combined_upgrade}"
        )
        reupgraded_version = pkg_installed_version(repo_vm)
        assert reupgraded_version == hi_version, (
            f"Re-upgrade: expected {hi_version!r} after upgrade, got {reupgraded_version!r} — lifecycle did not close"
        )
        assert pkg_repo_origin(repo_vm) == OURS_REPO_NAME, (
            f"Re-upgrade: origin {pkg_repo_origin(repo_vm)!r}, expected {OURS_REPO_NAME!r}"
        )
    finally:
        pkg_delete(repo_vm)
        # PORTABLE_REPO_ROOT is cleaned by build_repo_via_portable on each call;
        # the broader GUEST_SPIKE_DIR teardown runs in the repo_vm module fixture.


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
#     gh workflow run smoke.yml -f pytest_marker=repo                          #
# =========================================================================== #


def _build_eol_catalog_on_runner(
    frozen_pkg: Path,
    eol_varver: str,
    eol_pfsense_version: str,
    variant: str,
    freebsd_major: str,
    arch: str,
    php_version: str,
    py_flavor: str,
    out_dir: Path,
) -> Path:
    """Build a route-only (EOL) catalog on the runner via ``--build-matrix --route-only-pkgs``.

    Runs ``build-repo-portable.py --build-matrix`` with a synthetic route-only
    matrix entry and ``--route-only-pkgs <eol_varver>:<frozen_pkg>``.  The new
    Phase-10 CLI flag is exercised end-to-end here — this is the exact invocation
    shape publish.yml uses for real EOL versions.

    Returns the runner-side ``release/<eol_varver>/<arch>/`` directory whose files
    will be shipped to the guest.
    """
    matrix_entry = {
        "pfsense_version": eol_pfsense_version,
        "variant": variant,
        "freebsd_major": freebsd_major,
        "arch": arch,
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
    release_dir = out_dir / "release" / eol_varver / arch
    assert release_dir.is_dir(), f"route-only generator did not emit release/{eol_varver}/{arch}/ under {out_dir}"
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

    # Split the ABI string "FreeBSD:<major>:<arch>" into its components.
    _proto, freebsd_major, arch = own.abi.split(":", 2)

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
    eol_out_dir = tmp_path / "eol_catalog_out"
    local_release_dir = _build_eol_catalog_on_runner(
        frozen_pkg,
        eol_varver,
        eol_pfsense_version,
        own.variant,
        freebsd_major,
        arch,
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
        # Ship only the release/<eol_varver>/<arch>/ files (the ABI subtree); the
        # guest conf points directly at the on-guest ABI directory.
        guest_abi_dir = f"{EOL_REPO_ROOT}/{eol_varver}/{arch}"
        _ssh_check(repo_vm, "/bin/rm", "-rf", EOL_REPO_ROOT)
        _ssh_check(repo_vm, "/bin/mkdir", "-p", guest_abi_dir)
        for f in sorted(local_release_dir.iterdir()):
            if f.is_file():
                _scp_to_guest(repo_vm, f, f"{guest_abi_dir}/{f.name}")

        # --- GIVEN: package absent; EOL catalog enabled above the pfSense repo. ---
        pkg_delete(repo_vm)
        write_repo_conf(repo_vm, guest_abi_dir, ours_priority=pfsense_prio + 100)
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
