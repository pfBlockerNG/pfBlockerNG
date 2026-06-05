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
# The upgrade test rebuilds ONE repo dir in place (lower build -> higher build) so a
# `pkg upgrade` moves the box across versions WITHIN our repo (not across repos).
UPGRADE_REPO_DIR = f"{GUEST_SPIKE_DIR}/upgrade"
OURS_REPO_NAME = "pfblockerng-devel"  # the %R origin a from-our-repo install reports
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
# (hermetic; the brait.dev default + a live add-repo.sh run are a post-deploy note),
# proving the SHIPPED bootstrap — not just a hand-written conf — installs our build.
ADD_REPO_SH = Path(__file__).resolve().parents[2] / "scripts" / "add-repo.sh"
GUEST_ADD_REPO_SH = f"{GUEST_SPIKE_DIR}/add-repo.sh"

# Phase-3b (ADR-17) LIVE GitHub-Pages-URL end-to-end check. The publish pipeline
# deploys the catalog to a Pages site served at the CUSTOM DOMAIN brait.dev (gh api
# repos/.../pages -> html_url http://brait.dev/pfBlockerNG/); we serve over HTTPS.
# This dispatch-only test proves a REAL pfSense box `pkg update`/`pkg install`
# against the LIVE https URL (not file://) — the maintainer's real-URL check. It is
# GATED on SMOKE_REPO_LIVE_URL: unset -> SKIP (the file:// VM-acceptance above is the
# always-on proof; the live URL only exists once the deploy has run).
LIVE_BASE_URL_ENV = "SMOKE_REPO_LIVE_URL"
DEFAULT_LIVE_BASE_URL = "https://brait.dev/pfBlockerNG"
GUEST_ABI = "FreeBSD:15:amd64"  # the single supported ABI (CE 2.8 + Plus 25.03)
# GitHub Pages' anycast IPs. The smoke harness sandboxes guest DNS to a mock that
# only answers `uuid-*.com`, so `brait.dev` does not resolve on the guest. Pinning
# the Pages IPs in the guest /etc/hosts lets `pkg`'s HTTPS fetch reach Pages by name
# (TLS SNI still presents `brait.dev`, so the custom-domain cert validates) without
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
    libpkg, then returns the single per-ABI catalog directory it produced
    (``<out>/<ABI>/``) — the dir a ``file://`` repo conf points at.

    This validates the SCRIPT's output (the bucketed ``<ABI>/`` tree + the catalog
    triple ``pkg repo`` emits) is accepted by a real pfSense box, the live half of
    the build-side premise. The branch ``.pkg`` is a single ABI
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
    # The script buckets by ABI; the branch .pkg is one ABI -> one <ABI>/ subdir.
    listing = _ssh_check(vm, "/bin/ls", "-1", SCRIPT_REPO_ROOT).stdout.split()
    assert len(listing) == 1, f"build-repo.sh produced {listing!r} ABI buckets, expected exactly 1"
    abi_dir = f"{SCRIPT_REPO_ROOT}/{listing[0]}"
    # The catalog triple must be present (what `pkg update` consumes).
    for fname in ("meta.conf", "packagesite.pkg", "data.pkg"):
        present = vm.ssh("/bin/test", "-f", f"{abi_dir}/{fname}")
        assert present.returncode == 0, f"build-repo.sh did not emit {fname} under {abi_dir}"
    return abi_dir


def build_repo_via_portable(vm: SmokeVM, pkg_files: list[Path], tmp_path: Path) -> str:
    """Run ``scripts/build-repo-portable.py`` ON THE RUNNER, then ship its catalog to the guest.

    This is the Phase-3a proof: the catalog is generated in PURE PYTHON on the runner
    (no libpkg, no guest involvement) exactly as the Phase-3b publish job will, then
    only the produced ``<out>/<ABI>/`` tree is copied to the guest. A real pfSense
    ``pkg update``/``install`` then has to accept it — the fidelity gate that the
    pure-Python catalog is byte-compatible with what real ``pkg repo`` emits.

    Returns the on-guest path of the single ``<ABI>/`` directory (the branch ``.pkg``
    is one ABI, ``FreeBSD:15:amd64``), which the ``file://`` repo conf points at.
    """
    in_dir = tmp_path / "portable_in"
    out_dir = tmp_path / "portable_out"
    in_dir.mkdir(parents=True, exist_ok=True)
    for pkg in pkg_files:
        # Copy (not symlink) so the generator reads real bytes regardless of cwd.
        (in_dir / pkg.name).write_bytes(pkg.read_bytes())

    # Run the pure-Python generator with THIS process's interpreter — no `pkg`/libpkg.
    proc = subprocess.run(
        [sys.executable, str(BUILD_REPO_PORTABLE), "--in", str(in_dir), "--out", str(out_dir)],
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
    abi_buckets = sorted(p for p in out_dir.iterdir() if p.is_dir())
    assert len(abi_buckets) == 1, f"portable generator produced {[p.name for p in abi_buckets]} ABI buckets, expected 1"
    local_abi_dir = abi_buckets[0]
    # The catalog triple must be present locally before shipping.
    for fname in ("meta.conf", "meta", "packagesite.pkg", "data.pkg"):
        assert (local_abi_dir / fname).is_file(), f"portable generator did not emit {fname} under {local_abi_dir}"

    # Ship the <ABI>/ tree to the guest (fresh dir per run).
    guest_abi_dir = f"{PORTABLE_REPO_ROOT}/{local_abi_dir.name}"
    _ssh_check(vm, "/bin/rm", "-rf", PORTABLE_REPO_ROOT)
    _ssh_check(vm, "/bin/mkdir", "-p", guest_abi_dir)
    for f in sorted(local_abi_dir.iterdir()):
        if f.is_file():
            _scp_to_guest(vm, f, f"{guest_abi_dir}/{f.name}")
    return guest_abi_dir


def run_add_repo_sh(vm: SmokeVM, base_url: str, *, timeout: float = 300.0) -> subprocess.CompletedProcess[str]:
    """Stage the SHIPPED ``scripts/add-repo.sh`` and run it (devel) against ``base_url``.

    Drives the real client bootstrap on the box: it writes the production conf to
    ``/usr/local/etc/pkg/repos/pfblockerng-devel.conf`` (here pointed at a local
    ``file://`` catalog via the script's own ``--base-url`` override — the brait.dev
    default and a live HTTPS add-repo.sh run are a post-deploy note), runs ``pkg
    update``, and VERIFIES the package is visible from OUR repo. A non-zero exit (its
    verify step failing) raises with the captured output. ``base_url`` points at the
    catalog ROOT; add-repo.sh appends the literal ``${ABI}`` (pkg expands it to the
    box's ABI), so the catalog MUST live under ``<base_url>/<ABI>/``.
    """
    _ssh_check(vm, "/bin/mkdir", "-p", GUEST_SPIKE_DIR)
    _scp_to_guest(vm, ADD_REPO_SH, GUEST_ADD_REPO_SH)
    result = vm.ssh("/bin/sh", GUEST_ADD_REPO_SH, "--base-url", base_url, "devel", timeout=timeout)
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
        ``pfblockerng-devel``) — the asserted BEFORE state.
    When our repo is REBUILT in place with the HIGHER build ``<V>_9``, ``pkg update
      -f`` re-reads the catalog, and ``pkg upgrade -y`` runs,
      Then the box MOVES to ``<V>_9`` from OUR repo (``%v`` == ``<V>_9``, ``%R`` ==
        ``pfblockerng-devel``) — a real before != after transition, not a final-state
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
      from OUR repo (``pkg query %R`` == ``pfblockerng-devel``) with deps resolved —
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
    ``--base-url`` override; the brait.dev default + a live HTTPS add-repo.sh run are
    the post-deploy/Phase-6 note. The catalog is laid out by ``build-repo.sh`` under
    ``<root>/<ABI>/`` so add-repo.sh's literal ``${ABI}`` url resolves to it. The
    script ships priority 100, above the Netgate ``pfSense`` repo (0), so cross-repo
    install picks ours — exactly the production mechanism.

    Given the package ABSENT and a ``build-repo.sh`` catalog under ``<root>/<ABI>/``,
    When ``add-repo.sh --base-url file://<root> devel`` runs (writes the conf, ``pkg
      update``, verifies) and then ``pkg install -y`` runs (NO -r, NO -f),
    Then add-repo.sh exits 0 (its own verify found the package in our repo), it wrote
      the production conf to ``pfblockerng-devel.conf``, and the install comes from
      OUR repo (``pkg query %R`` == ``pfblockerng-devel``) with deps resolved.
    """
    pkg = os.environ.get("SMOKE_PKG")
    assert pkg and Path(pkg).is_file(), "SMOKE_PKG not set / not a file"  # repo_vm already gated this

    # GIVEN: a catalog under <SCRIPT_REPO_ROOT>/<ABI>/ (build-repo.sh lays it out so),
    # package absent. The dir add-repo.sh's ${ABI} url will resolve to.
    abi_dir = build_repo_via_script(repo_vm, [Path(pkg)])
    assert abi_dir.startswith(f"{SCRIPT_REPO_ROOT}/"), f"unexpected catalog dir {abi_dir!r}"
    pkg_delete(repo_vm)

    # WHEN: run the SHIPPED bootstrap against the local catalog root. Its verify step
    # must pass (it raises here otherwise) — proving the shipped conf loads our catalog.
    proc = run_add_repo_sh(repo_vm, f"file://{SCRIPT_REPO_ROOT}")

    # THEN: add-repo.sh wrote the production conf and its verify confirmed our package.
    assert "available from 'pfblockerng-devel'" in proc.stdout, (
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
      (``pkg query %R`` == ``pfblockerng-devel``) with deps resolved and the ``.pkg``
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


# --------------------------------------------------------------------------- #
# Phase-3b — the LIVE GitHub-Pages-URL end-to-end (dispatch-only; gated)
# --------------------------------------------------------------------------- #


def _live_base_url() -> str | None:
    """The live Pages base to test against, or None to SKIP.

    Gated on ``SMOKE_REPO_LIVE_URL``: set it to the deployed base (e.g.
    ``https://brait.dev/pfBlockerNG``) to run the live check after a publish
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
    so the custom domain does not resolve on the box. A static ``/etc/hosts`` entry
    routes ``pkg``'s HTTPS fetch to Pages by IP while TLS SNI still presents ``host``
    (the custom-domain cert validates). Idempotent: the entry is removed first.
    """
    # Remove any prior pin for this exact host, then append the fresh one. The line
    # is `<ip> <host>` (the first listed Pages IP suffices; pkg follows the cert).
    strip = f"grep -v '[[:space:]]{re.escape(host)}$' /etc/hosts > /etc/hosts.pfb 2>/dev/null"
    script = (
        f"{strip} || cp /etc/hosts /etc/hosts.pfb; "
        f"printf '%s %s\\n' '{PAGES_IPS[0]}' '{host}' >> /etc/hosts.pfb; "
        f"mv /etc/hosts.pfb /etc/hosts"
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
    over its public HTTPS ``https://brait.dev/pfBlockerNG/${ABI}`` URL (no ``-f``).

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
      repo (``pkg query %R`` == ``pfblockerng-devel``) with deps resolved and the .pkg
      checksum validated — the deployed Pages repo is real + installable over HTTPS.
    """
    base_url = _live_base_url()
    if base_url is None:
        pytest.skip(f"{LIVE_BASE_URL_ENV} not set — live Pages-URL check is dispatch-only (file:// proof always runs)")
    assert base_url is not None  # for the type-checker: pytest.skip above is NoReturn

    host = urllib.parse.urlparse(base_url).hostname
    assert host, f"could not parse a host from {base_url!r}"

    # BACKSTOP: prove the deploy actually serves the catalog from the RUNNER first
    # (independent of the guest) — polls through first-deploy / DNS / cert lag.
    poll_catalog_served(base_url, GUEST_ABI)

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
