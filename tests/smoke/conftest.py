"""pytest scaffolding for the ADR-04 live-VM smoke suite.

This package is DESELECTED from the default ``python -m pytest`` run
(``pyproject.toml`` ``addopts = "... --ignore=tests/smoke"``), so nothing here
is imported during default collection. It is collected only by the smoke
workflow, which runs e.g.::

    python -m pip install -r tests/smoke/requirements.txt
    python -m pytest tests/smoke -m smoke --override-ini="addopts="

What this module provides:

* ``smoke_vm`` — a SESSION-scoped fixture that pulls the pfSense CE qcow2 from
  private GHCR (by the immutable ref in ``SMOKE_IMAGE_REF``), or reuses an
  already-pulled image dir (``SMOKE_IMAGE_DIR``, one ``.qcow2``) so the workflow
  can pull -> block egress -> run hermetically without a second network pull,
  boots it headless
  under QEMU/KVM, waits until it is actually usable, yields a small connection
  object, and tears the VM down on session teardown. It REUSES the existing
  POSIX-sh helpers (``boot_vm.sh`` makes the read-only-base copy-on-write
  overlay and boots it; ``wait_ready.sh`` polls SSH/WebUI readiness with bounded
  backoff and a hard timeout) over ``subprocess`` — it does NOT reimplement
  QEMU or SSH in Python.

* ``mock_feeds`` — a FUNCTION-scoped fixture serving files from
  ``tests/smoke/fixtures/`` (plus per-test registered content) over stdlib
  ``http.server`` on the runner, reachable by the guest at
  ``http://192.168.89.2:<port>/<name>`` via the QEMU WAN user-net (SLIRP) host alias.

The boot+probe core lives in :func:`boot_and_probe`, separate from the pytest
fixtures, so it can double as a reusable health/sanity gate (ADR-09 fans the
harness across CE versions; the image ref/digest is always a PARAMETER, never
hardcoded).
"""

from __future__ import annotations

import contextlib
import os
import shlex
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from collections.abc import Generator, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from functools import partial
from http.server import BaseHTTPRequestHandler, SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

from ..timing import step_min_seconds, timed, timed_step  # issue #605 — per-step timing (PFB_TIMING)
from . import stub_responses

# --------------------------------------------------------------------------- #
# Paths + constants
# --------------------------------------------------------------------------- #

SMOKE_DIR = Path(__file__).resolve().parent
BOOT_VM_SH = SMOKE_DIR / "boot_vm.sh"
WAIT_READY_SH = SMOKE_DIR / "wait_ready.sh"
FIXTURES_DIR = SMOKE_DIR / "fixtures"

# Host<->guest exposure baked into boot_vm.sh's hostfwd map (see RESULTS/01).
DEFAULT_HOST = "127.0.0.1"

# Per-lane port offset — each parallel smoke lane boots its own VM on disjoint host-forward
# ports so multiple pytest-xdist workers can run isolated on the same host.
_LANE = int(os.environ.get("SMOKE_LANE", "0"))


def _lane_port(base: int, lane: int, *, stride: int = 10) -> int:
    """Give each parallel lane a disjoint 127.0.0.1 host-forward port.

    Stride 10 leaves headroom between adjacent lanes (e.g. lane 0→2222, lane 1→2232).
    """
    return base + lane * stride


def _validate_lane(lane: int) -> None:
    """Reject a SMOKE_LANE that would break port isolation — fail fast, not silently.

    A negative lane derives lower-numbered ports (reusing another lane's range), and a lane
    large enough to push the highest-based host-forward port past 65535 yields an invalid
    port that fails the boot confusingly.  The effective base is read from
    SMOKE_LAN_SOCKET_PORT (default 12340) so the ceiling tracks the overridden base.
    Upper bound: base + lane*10 <= 65535.
    """
    base = int(os.environ.get("SMOKE_LAN_SOCKET_PORT", "12340"))
    max_lane = (65535 - base) // 10
    if lane < 0 or _lane_port(base, lane) > 65535:
        raise ValueError(f"SMOKE_LANE out of range: {lane} (must be 0..{max_lane})")


_validate_lane(_LANE)


# INVARIANT: at _LANE == 0 with no SMOKE_*_HOSTPORT overrides all five equal the
# historical defaults (2222 / 8080 / 5353 / 2223 / 12340) — behaviour-preserving at lane 0.
DEFAULT_SSH_PORT = _lane_port(int(os.environ.get("SMOKE_SSH_HOSTPORT", "2222")), _LANE)  # host -> guest 22
DEFAULT_WEB_PORT = _lane_port(int(os.environ.get("SMOKE_WEB_HOSTPORT", "8080")), _LANE)  # host -> guest 80
DEFAULT_DNS_PORT = _lane_port(5353, _LANE)  # host -> guest 53 (tcp+udp); no env consumer in boot_vm.sh

# The WAN SLIRP host alias the guest uses to reach the runner (mock feed server,
# stub DNS, webhook sink). Corresponds to boot_vm.sh net0: net=192.168.89.0/24,
# host=192.168.89.2. The old 10.0.2.2 was the classic libslirp default; the two-VM
# topology uses 192.168.89.0/24 — it avoids the management net (192.168.43.0/24) AND
# leaves the DNSBL sinkhole VIP 10.10.10.1 outside the WAN subnet (an overlap
# makes pfBlockerNG disable DNSBL).
GUEST_TO_HOST_ALIAS = "192.168.89.2"

# Sentinel answers the runner-side stub upstream returns for any forwarded query
# (see _StubDnsServer / helpers.configure_upstream). Distinct from every DNSBL
# block shape (NXDOMAIN / 0.0.0.0 / the VIP), so a name that should be blocked
# but ISN'T resolves to the sentinel — a true pass, never a false-green block.
# Single source: stub_responses (shared with the off-box shape tests).
STUB_DNS_A = stub_responses.STUB_DNS_A  # RFC 5737 documentation range
STUB_DNS_AAAA = stub_responses.STUB_DNS_AAAA  # RFC 3849 documentation range

# Hard readiness ceiling for wait_ready.sh's poll (8s grace -> 1s, then 5s past
# 75s). Measured web-ready is ~15s on a fast bare-metal host but ~55-60s on a
# nested-KVM / low-power box, and parallel-lane CPU contention pushes it higher, so
# ~3 min leaves headroom; a dead qemu still fails IMMEDIATELY via its PID watch (not
# by burning this ceiling). Raise SMOKE_BOOT_TIMEOUT for an unusually slow runner.
DEFAULT_BOOT_TIMEOUT = int(os.environ.get("SMOKE_BOOT_TIMEOUT", "180"))

# civm client VM ssh host-forward port (host -> civm:22). Honour the same
# SMOKE_CLIENT_SSH_HOSTPORT override boot_vm.sh reads (default 2223), so a custom
# host port reaches the client instead of a hardcoded 2223.
DEFAULT_CLIENT_SSH_PORT = _lane_port(int(os.environ.get("SMOKE_CLIENT_SSH_HOSTPORT", "2223")), _LANE)  # host -> civm 22

# LAN socket crossover port (pfSense LISTENER <-> civm CONNECTOR). Lane-strided from
# boot_vm.sh's historical default 12340, eliminating the bind(:0) TOCTOU race — the
# port is now DETERMINISTIC per lane (lane 0 → 12340, lane 1 → 12350, …).
# The pkill + lane stride on the leased box frees the port before boot.
DEFAULT_LAN_SOCKET_PORT = _lane_port(int(os.environ.get("SMOKE_LAN_SOCKET_PORT", "12340")), _LANE)

# Write the lane-resolved ports back so boot_vm.sh's hostfwd reads the same values SmokeVM uses.
os.environ["SMOKE_SSH_HOSTPORT"] = str(DEFAULT_SSH_PORT)
os.environ["SMOKE_WEB_HOSTPORT"] = str(DEFAULT_WEB_PORT)
os.environ["SMOKE_CLIENT_SSH_HOSTPORT"] = str(DEFAULT_CLIENT_SSH_PORT)
os.environ["SMOKE_LAN_SOCKET_PORT"] = str(DEFAULT_LAN_SOCKET_PORT)

# The address civm uses to reach pfSense (pfSense LAN side of the socket crossover).
PFSENSE_LAN_IP = "192.168.1.1"  # pfSense LAN IP baked in the two-VM image

# civm's pfSense static-DHCP lease address (informational; keyed by SMOKE_CLIENT_MAC_ADDRESS).
CLIENT_LAN_IP = "192.168.1.10"  # civm's static lease on the pfSense LAN


# --------------------------------------------------------------------------- #
# Connection object yielded by the VM fixture
# --------------------------------------------------------------------------- #

# issue #605: a leading interpreter is noise in an ssh timing label ("ssh:php" tells you
# nothing) — drop it so the script + verb surface ("ssh:pfblockerng.php pfb_trigger").
_SSH_INTERPRETERS = frozenset({"php", "php83", "php-cgi", "python", "python3", "python3.11", "sh", "bash"})


def _ssh_timing_label(remote: tuple[str, ...]) -> str:
    """Build a descriptive PFB_TIMING label for an ssh command (issue #605).

    Shows the meaningful command, not just the interpreter: the first few non-flag tokens
    (basename'd), with a leading php/python/sh dropped, capped for the log.
    """
    cmd = " ".join(str(part) for part in remote).strip()
    if not cmd:
        return "ssh"
    parts: list[str] = []
    for token in cmd.split():
        if token.startswith("-"):  # skip flags/options
            continue
        base = os.path.basename(token)
        if not parts and base in _SSH_INTERPRETERS:
            continue  # drop the leading interpreter; surface the script/verb instead
        parts.append(base)
        if len(parts) >= 3:
            break
    label = " ".join(parts) if parts else os.path.basename(cmd.split()[0])
    return f"ssh:{label}"[:60]


@dataclass
class SmokeVM:
    """Connection details for a booted smoke VM (the fixture's yielded value).

    Fields are the stable contract Phase 4 (deploy/config-inject/probe helpers)
    builds on. ``feed_base_url`` is what a test bakes into a pfBlockerNG feed
    config so the guest fetches fixtures from the runner over SLIRP.
    """

    ssh_key_path: str
    host: str = DEFAULT_HOST
    ssh_port: int = DEFAULT_SSH_PORT
    web_port: int = DEFAULT_WEB_PORT
    dns_port: int = DEFAULT_DNS_PORT
    # The runner-side address the guest reaches via the SLIRP host alias. Set
    # once mock_feeds is up (it allocates the port); None until then.
    feed_base_url: str | None = None
    # Runner-side port of the stub DNS upstream (reached by the guest at
    # 192.168.89.2:<port> via the WAN SLIRP alias). Set once the stub_dns fixture is
    # up; None otherwise. Unbound is pointed here so it never recurses into dark egress.
    upstream_dns_port: int | None = None
    # qemu PID + overlay are bookkeeping for teardown.
    vm_pid: int | None = None
    log_path: str | None = None

    @property
    def ssh_target(self) -> str:
        """``root@<host>`` — the SSH target the harness connects to."""
        return f"root@{self.host}"

    def ssh_argv(self, *remote: str) -> list[str]:
        """Build an ``ssh`` argv for a one-shot command on the guest.

        Throwaway VM: skip host-key verification but keep the private key
        private. Mirrors wait_ready.sh's SSH options.

        Always fire up ``/bin/sh`` on the guest. pfSense's root login shell is
        ``tcsh``, and ``sshd`` runs the remote command as
        ``$SHELL -c "<argv joined by spaces>"``; letting tcsh parse that string is
        the bug we are avoiding — tcsh is finicky and mangles any token containing
        a shell metacharacter (``|``, ``$``, ``(``, ``)``, ``!`` …), e.g. a
        ``grep -nE 'a|b'`` pattern collapses because tcsh reads the ``|`` as a pipe.

        Callers use one of two conventions, matched here:

        * **one argument** — already a POSIX-sh command line (``"pfctl -sr | grep x"``);
          run it verbatim under ``sh``.
        * **multiple arguments** — the command's argv (``"grep", "-nE", "a|b", p``);
          ``shlex.join`` re-quotes them into one sh command line so each token
          reaches the program intact (no shell splitting of ``a|b``).

        Either way the result runs as ``/bin/sh -c '<cmd>'``. ``shlex.quote`` makes
        the whole ``<cmd>`` a single tcsh token, so tcsh only sees the trivial,
        metacharacter-free sequence ``/bin/sh -c '<blob>'``, strips the outer quotes,
        and hands the blob to ``/bin/sh -c`` which does the real parsing. ``stdin``
        is untouched, so callers that pipe data (``tee``, ``pfSsh.php``) keep working.
        """
        sh_command = remote[0] if len(remote) == 1 else shlex.join(remote)
        return [
            "ssh",
            "-i",
            self.ssh_key_path,
            "-p",
            str(self.ssh_port),
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "LogLevel=ERROR",
            self.ssh_target,
            "/bin/sh",
            "-c",
            shlex.quote(sh_command),
        ]

    def ssh(self, *remote: str, timeout: float = 60.0) -> subprocess.CompletedProcess[str]:
        """Run a command on the guest over SSH and capture its output."""
        # issue #605: time each guest command, but emit only the heavy ones (>=1s) so the
        # tight poll loops (wait_*, snap_state) don't flood the log with sub-second lines.
        with timed(_ssh_timing_label(remote), min_seconds=step_min_seconds()):
            return subprocess.run(
                self.ssh_argv(*remote),
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )


# --------------------------------------------------------------------------- #
# Image pull (oras) — ref is a PARAMETER (env), never hardcoded
# --------------------------------------------------------------------------- #


def _require(binary: str) -> str:
    path = shutil.which(binary)
    if path is None:
        raise RuntimeError(f"smoke harness needs `{binary}` on PATH but it was not found")
    return path


def oras_pull_image(image_ref: str, dest: Path) -> Path:
    """Pull the pfSense qcow2 from GHCR via ``oras`` and return its path.

    ``image_ref`` is the OCI ref (ideally pinned by ``@sha256:...`` digest —
    ADR §2). GHCR auth, if needed, is via ``oras login`` performed by the
    workflow before pytest runs (using SMOKE_GHCR_USER/TOKEN); this function
    only pulls. The artifact carries exactly one ``.qcow2`` layer.
    """
    oras = _require("oras")
    dest.mkdir(parents=True, exist_ok=True)
    subprocess.run([oras, "pull", image_ref, "--output", str(dest)], check=True)
    qcows = sorted(dest.glob("*.qcow2"))
    if len(qcows) != 1:
        raise RuntimeError(f"expected exactly one .qcow2 in pulled artifact, found {len(qcows)}: {qcows}")
    return qcows[0]


# --------------------------------------------------------------------------- #
# Boot + readiness probe — reusable health gate, not pytest-only plumbing
# --------------------------------------------------------------------------- #


@dataclass
class BootHandle:
    """A booted VM process plus its connection details."""

    process: subprocess.Popen[bytes]
    vm: SmokeVM
    log_file: object = field(repr=False)


@timed_step("boot_and_probe")
def boot_and_probe(
    base_image: Path,
    ssh_key_path: str,
    *,
    log_path: Path,
    host: str = DEFAULT_HOST,
    ssh_port: int = DEFAULT_SSH_PORT,
    web_port: int = DEFAULT_WEB_PORT,
    dns_port: int = DEFAULT_DNS_PORT,
    boot_timeout: int = DEFAULT_BOOT_TIMEOUT,
    diag_name: str = "pfsense",
) -> BootHandle:
    """Boot ``base_image`` and block until the guest is usable.

    REUSES the shell helpers over subprocess:
      * ``boot_vm.sh`` creates the ephemeral copy-on-write overlay (the base is
        read-only and never mutated — run-level immutability) and execs qemu;
      * ``wait_ready.sh`` polls WebUI readiness (the pfSense gate; nginx+PHP up
        implies sshd is too) on an 8s-grace -> 1s -> 5s cadence with a hard
        timeout (NO fixed sleep), and bails immediately if the qemu PID dies
        (bad image / KVM abort).

    On readiness, returns a :class:`BootHandle`. On timeout or a dead qemu it
    raises, after killing qemu. Designed to be callable outside pytest (a CE
    image sanity gate).
    """
    log_file = log_path.open("wb")
    # Expose a QMP control socket so a wedged, no-serial boot can be screendumped
    # (the only diagnostic window when SSH/web never come up). boot_vm.sh keeps
    # the serial console on stdio (-> log_file) alongside QMP.
    qmp_sock = _qmp_sock_path(diag_name)
    # boot_vm.sh backgrounds nothing itself (it execs qemu); we background it
    # via Popen and pass its PID to wait_ready.sh so a dead boot is caught fast.
    process: subprocess.Popen[bytes] = subprocess.Popen(
        ["sh", str(BOOT_VM_SH), str(base_image)],
        stdout=log_file,
        stderr=subprocess.STDOUT,
        env={**os.environ, "QMP_SOCK": qmp_sock},
    )

    vm = SmokeVM(
        ssh_key_path=ssh_key_path,
        host=host,
        ssh_port=ssh_port,
        web_port=web_port,
        dns_port=dns_port,
        vm_pid=process.pid,
        log_path=str(log_path),
    )

    try:
        # wait_ready.sh <ssh-key> [host] [port] [timeout] [vm-pid] [web-port].
        # Passing web_port selects the pfSense gate: readiness = the webConfigurator
        # answering (nginx+PHP), which comes up after sshd.
        result = subprocess.run(
            [
                "sh",
                str(WAIT_READY_SH),
                ssh_key_path,
                host,
                str(ssh_port),
                str(boot_timeout),
                str(process.pid),
                str(web_port),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
    except Exception:
        _capture_boot_failure(diag_name, qmp_sock, log_path, process)
        _kill(process)
        log_file.close()
        raise

    if result.returncode != 0:
        _capture_boot_failure(diag_name, qmp_sock, log_path, process)
        _kill(process)
        log_file.close()
        tail = _tail(log_path)
        raise RuntimeError(
            f"VM never became ready (wait_ready exit {result.returncode}).\n"
            f"wait_ready stderr:\n{result.stderr}\n--- boot log tail ---\n{tail}"
        )

    # Surface "boot-to-ready: N seconds" so it lands in the captured output.
    print(result.stdout.strip())

    # wait_ready.sh keys on the web port, which answers BEFORE pfSense's rc finishes and
    # removes /var/run/booting. Block until boot is actually complete so the first
    # pfBlockerNG update does not race it (is_platform_booting() true -> "Sync terminated
    # during boot process." -> silent no-op). Local import avoids the conftest<->helpers
    # module cycle (helpers imports from conftest at module load).
    from . import helpers  # noqa: PLC0415

    try:
        helpers.wait_boot_complete(vm)
    except Exception:
        # Route a boot-complete failure (its loud timeout, or an SSH/php_eval error) through the
        # SAME cleanup as a wait_ready failure: capture diagnostics, kill qemu, close the log --
        # otherwise a never-completing boot leaks the VM and produces no screendump/log tail.
        _capture_boot_failure(diag_name, qmp_sock, log_path, process)
        _kill(process)
        log_file.close()
        raise
    return BootHandle(process=process, vm=vm, log_file=log_file)


def _kill(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        process.kill()
        with contextlib.suppress(Exception):
            process.wait(timeout=15)


def _tail(path: Path, lines: int = 40) -> str:
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return "(boot log unavailable)"
    return "\n".join(text.splitlines()[-lines:])


# Diagnostics for a wedged boot are written under helpers.DIAG_DIR, RELATIVE to
# the workspace cwd (where pytest runs). The smoke workflow's "Upload
# diagnostics" step globs ``smoke-diag/**`` + ``**/screen-*.png`` — so anything
# dropped there is uploaded. This is the ONLY window into a setup-time boot
# failure: the session VM fixture errors before any test runs, so the
# on-failure ``_dump_vm_on_failure`` hook (which needs SSH) never fires, and
# the boot log otherwise lives under pytest's tmp dir (outside the artifact
# globs). DIAG_DIR itself lives in helpers.py (shared with the render-diff UI
# harness); ``_capture_boot_failure`` below local-imports ``helpers`` for it
# (the usual conftest<->helpers cycle guard).


def _qmp_sock_path(tag: str) -> str:
    """A short unix-socket path for QEMU's QMP control channel.

    Unix socket paths are capped at ~108 bytes, so we anchor under RUNNER_TEMP
    (or /tmp), NOT pytest's deep tmp_path_factory dir. boot_vm.sh ``rm -f``s and
    recreates it; we only need a unique, short name.
    """
    base = os.environ.get("RUNNER_TEMP") or "/tmp"
    return tempfile.mktemp(prefix=f"pfb-qmp-{tag}-", suffix=".sock", dir=base)


def _capture_boot_failure(tag: str, qmp_sock: str | None, log_path: Path, process: subprocess.Popen[bytes]) -> None:
    """Snapshot a wedged boot into ``smoke-diag/`` before the VM is killed.

    These images may have NO serial console (screendump.py's whole reason for
    being), so the boot log can be empty and the VGA framebuffer is the only
    window into a stuck/unreachable boot. Captures both, best-effort, into the
    workflow-uploaded ``smoke-diag/`` dir:

      * ``boot-<tag>.log`` — whatever the guest wrote to the serial/stdio channel;
      * ``screen-<tag>.png`` — the VGA framebuffer via QEMU's QMP ``screendump``
        (the same mechanism ``build-image.yml`` uses for a stuck headless boot).

    MUST run BEFORE the qemu process is killed — QMP needs the process alive.
    """
    from . import helpers  # local import: helpers imports from conftest (avoid cycle)

    with contextlib.suppress(Exception):
        helpers.DIAG_DIR.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(Exception):
        shutil.copyfile(log_path, helpers.DIAG_DIR / f"boot-{tag}.log")
    if qmp_sock and process.poll() is None and Path(qmp_sock).exists():
        with contextlib.suppress(Exception):
            subprocess.run(
                ["python3", str(SMOKE_DIR / "screendump.py"), qmp_sock, str(helpers.DIAG_DIR / f"screen-{tag}.png")],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )


# --------------------------------------------------------------------------- #
# LAN socket port — shared by pfSense (LISTENER) and civm (CONNECTOR)
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="session")
def lan_socket_port() -> Iterator[int]:
    """Yield the deterministic LAN-socket port for the pfSense<->civm crossover.

    The port is lane-strided off boot_vm.sh's historical default 12340
    (``DEFAULT_LAN_SOCKET_PORT``) and written to ``SMOKE_LAN_SOCKET_PORT`` at
    import time, so BOTH boot_vm.sh invocations (pfSense LISTENER, civm CONNECTOR)
    see the same value. The lane/pkill contract on the leased box frees the port
    before boot — no bind(:0) race.

    Must be depended on BEFORE pfSense boots (``smoke_vm`` depends on this fixture).
    """
    # SMOKE_LAN_SOCKET_PORT was already written to os.environ at import time
    # (alongside SSH/WEB/CLIENT_SSH writebacks); just yield the value.
    yield DEFAULT_LAN_SOCKET_PORT


# --------------------------------------------------------------------------- #
# Session-scoped VM fixture
# --------------------------------------------------------------------------- #

# Records the booted pfSense VM on the session so the per-module isolation teardown
# (`_pfb_module_baseline`) can find it WITHOUT calling getfixturevalue — which would
# re-enter fixture setup (deprecated in pytest 9.1 for a not-already-requested fixture)
# and could boot a VM purely to reset a module that never used one. None once torn down.
SMOKE_VM_KEY: pytest.StashKey[SmokeVM | None] = pytest.StashKey()


@pytest.fixture(scope="session")
def smoke_vm(
    lan_socket_port: int, tmp_path_factory: pytest.TempPathFactory, request: pytest.FixtureRequest
) -> Iterator[SmokeVM]:
    """Pull -> boot -> wait-ready -> yield -> teardown, once per session.

    Per-case isolation (Phase 4 provides the reset verbs): cases run against
    this ONE long-lived boot and reset state between themselves via
    pfBlockerNG's ``clearip``/``cleardnsbl`` + a forced ``update`` (ADR §2
    "Reset between cases"). A fresh-boot-per-case alternative is available
    (call :func:`boot_and_probe` from a function-scoped fixture) but is far
    slower; the session boot + clear/reload is the chosen default. The base
    qcow2 is read-only (boot_vm.sh overlays it), so run-level immutability and
    concurrency safety hold regardless.

    Skips (not fails) when its prerequisites are absent, so a developer who
    accidentally runs ``pytest tests/smoke`` without KVM/secrets gets a clean
    skip rather than an error.
    """
    # SMOKE_IMAGE_DIR lets the caller supply an ALREADY-PULLED image dir (one
    # .qcow2) so the in-fixture `oras pull` is skipped. This is what makes the
    # ADR §2 hermetic sequence work: the workflow pulls the image from GHCR
    # FIRST, then BLOCKS the runner's egress, THEN runs pytest — so the fixture
    # must not need the network. Without it, fall back to pulling by
    # SMOKE_IMAGE_REF (the local-dev path, before any egress block).
    image_dir = os.environ.get("SMOKE_IMAGE_DIR")
    image_ref = os.environ.get("SMOKE_IMAGE_REF")
    if not image_dir and not image_ref:
        pytest.skip("neither SMOKE_IMAGE_DIR nor SMOKE_IMAGE_REF set — no pfSense image")

    ssh_key_path = os.environ.get("SMOKE_SSH_KEY")
    if not ssh_key_path or not Path(ssh_key_path).is_file():
        pytest.skip("SMOKE_SSH_KEY not set or not a file — no guest SSH key")

    if not Path("/dev/kvm").exists():
        pytest.skip("/dev/kvm absent — KVM acceleration required for the smoke VM")

    # `oras` is only needed when we have to pull; a pre-pulled SMOKE_IMAGE_DIR
    # run (egress blocked) does not require it.
    required = ("qemu-system-x86_64", "qemu-img", "ssh")
    if not image_dir:
        required = ("oras", *required)
    for binary in required:
        if shutil.which(binary) is None:
            pytest.skip(f"required binary `{binary}` not on PATH")

    work = tmp_path_factory.mktemp("smoke-vm")
    if image_dir:
        qcows = sorted(Path(image_dir).glob("*.qcow2"))
        if len(qcows) != 1:
            raise RuntimeError(f"SMOKE_IMAGE_DIR must hold exactly one .qcow2, found {len(qcows)}: {qcows}")
        base_image = qcows[0]
    else:
        base_image = oras_pull_image(image_ref, work / "image")

    handle = boot_and_probe(
        base_image,
        ssh_key_path,
        log_path=work / "vm.log",
        boot_timeout=DEFAULT_BOOT_TIMEOUT,
    )
    request.session.stash[SMOKE_VM_KEY] = handle.vm
    try:
        yield handle.vm
    finally:
        request.session.stash[SMOKE_VM_KEY] = None
        _kill(handle.process)
        with contextlib.suppress(Exception):
            handle.log_file.close()
        # The overlay is mktemp'd inside boot_vm.sh and removed on its clean
        # exit (trap on EXIT/INT/TERM); terminating qemu fires it. The pulled
        # image + logs live under tmp_path_factory, which pytest reaps.


# --------------------------------------------------------------------------- #
# Client VM fixture (civm — the Debian behind-the-firewall client)
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="session")
def client_vm(
    smoke_vm: SmokeVM,
    lan_socket_port: int,
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[SmokeVM]:
    """Boot the civm Debian client and yield its SSH connection object, once per session.

    Ordering is critical: pfSense (the LAN socket LISTENER) MUST be up before
    civm (the CONNECTOR) tries to connect — hence the ``smoke_vm`` dependency.
    Without pfSense's LISTENER the civm QEMU socket CONNECT would fail
    immediately. The ``lan_socket_port`` dependency guarantees the shared TCP port
    is set in ``SMOKE_LAN_SOCKET_PORT`` before either VM boots.

    NIC topology (from boot_vm.sh --role client):
      net0 MGMT — SLIRP user-net; host->guest SSH forward at
                  host:``DEFAULT_CLIENT_SSH_PORT`` (2223). This is the harness
                  control path for running ``dig`` probes on civm.
      net1 DATA — QEMU socket CONNECTOR to the pfSense LAN LISTENER; its MAC is
                  ``SMOKE_CLIENT_MAC_ADDRESS``, which pfSense matches to a static
                  DHCP lease handing civm ``CLIENT_LAN_IP`` (192.168.1.10).

    Readiness: SSH-only (no web server on civm). ``wait_ready.sh`` is called
    WITHOUT a web-port argument so the gate is SSH-only.

    The ``SmokeVM`` object's DNS-specific fields (``dns_port``, ``feed_base_url``,
    ``upstream_dns_port``) are unused for the client VM; its ``ssh()`` method is
    what matters for running ``dig @192.168.1.1`` probes.

    The civm data-NIC MAC (the pfSense static-lease key) defaults in boot_vm.sh,
    so ``SMOKE_CLIENT_MAC_ADDRESS`` is an OVERRIDE (CI sets it from the secret),
    not a precondition.

    Skips (not fails) when:
      * ``SMOKE_CLIENT_IMAGE_DIR``/``SMOKE_CLIENT_IMAGE_REF`` are both unset
        (pfSense-only suites can run without a client image).
      * The same prerequisites as ``smoke_vm`` (KVM, ssh, qemu binaries).
    """
    client_image_dir = os.environ.get("SMOKE_CLIENT_IMAGE_DIR")
    client_image_ref = os.environ.get("SMOKE_CLIENT_IMAGE_REF")
    if not client_image_dir and not client_image_ref:
        pytest.skip("no civm client image (SMOKE_CLIENT_IMAGE_DIR/REF unset)")

    # The civm data-NIC MAC (static-lease key) has a committed default in
    # boot_vm.sh, so SMOKE_CLIENT_MAC_ADDRESS is an OVERRIDE, not a requirement;
    # CI still sets it from the secret. No skip on its absence.

    ssh_key_path = os.environ.get("SMOKE_SSH_KEY")
    if not ssh_key_path or not Path(ssh_key_path).is_file():
        pytest.skip("SMOKE_SSH_KEY not set or not a file — no guest SSH key")

    if not Path("/dev/kvm").exists():
        pytest.skip("/dev/kvm absent — KVM acceleration required for the smoke VM")

    required: tuple[str, ...] = ("qemu-system-x86_64", "qemu-img", "ssh")
    if not client_image_dir:
        required = ("oras", *required)
    for binary in required:
        if shutil.which(binary) is None:
            pytest.skip(f"required binary `{binary}` not on PATH")

    work = tmp_path_factory.mktemp("client-vm")
    if client_image_dir:
        qcows = sorted(Path(client_image_dir).glob("*.qcow2"))
        if len(qcows) != 1:
            raise RuntimeError(f"SMOKE_CLIENT_IMAGE_DIR must hold exactly one .qcow2, found {len(qcows)}: {qcows}")
        client_image = qcows[0]
    else:
        client_image = oras_pull_image(client_image_ref, work / "image")  # type: ignore[arg-type]

    log_path = work / "client-vm.log"
    log_file = log_path.open("wb")
    qmp_sock = _qmp_sock_path("civm")

    # pfSense (LISTENER) is already up (smoke_vm dependency); boot civm (CONNECTOR).
    process: subprocess.Popen[bytes] = subprocess.Popen(
        ["sh", str(BOOT_VM_SH), "--role", "client", str(client_image)],
        stdout=log_file,
        stderr=subprocess.STDOUT,
        env={**os.environ, "QMP_SOCK": qmp_sock},
    )

    try:
        # SSH-only readiness: omit web-port arg so wait_ready.sh uses SSH gate only.
        result = subprocess.run(
            [
                "sh",
                str(WAIT_READY_SH),
                ssh_key_path,
                DEFAULT_HOST,
                str(DEFAULT_CLIENT_SSH_PORT),
                str(DEFAULT_BOOT_TIMEOUT),
                str(process.pid),
                # No web-port arg → SSH-only readiness gate.
            ],
            capture_output=True,
            text=True,
            check=False,
        )
    except Exception:
        _capture_boot_failure("civm", qmp_sock, log_path, process)
        _kill(process)
        log_file.close()
        raise

    if result.returncode != 0:
        _capture_boot_failure("civm", qmp_sock, log_path, process)
        _kill(process)
        log_file.close()
        tail = _tail(log_path)
        raise RuntimeError(
            f"civm never became ready (wait_ready exit {result.returncode}).\n"
            f"wait_ready stderr:\n{result.stderr}\n--- client boot log tail ---\n{tail}"
        )

    print(result.stdout.strip())

    vm = SmokeVM(
        ssh_key_path=ssh_key_path,
        host=DEFAULT_HOST,
        ssh_port=DEFAULT_CLIENT_SSH_PORT,
        vm_pid=process.pid,
        log_path=str(log_path),
    )

    try:
        yield vm
    finally:
        _kill(process)
        with contextlib.suppress(Exception):
            log_file.close()


# --------------------------------------------------------------------------- #
# Mock HTTP feed server (stdlib only)
# --------------------------------------------------------------------------- #


# Fixed Last-Modified the mock emits on every registered-feed 200 (unless
# disable_lastmod() opts a name out): epoch 1700000000 = 2023-11-14T22:13:20Z.
# Shared by the emitted header string and the enable_lastmod_304() IMS compare
# so the two can never drift apart.
_MOCK_LAST_MODIFIED_EPOCH = 1700000000
_MOCK_LAST_MODIFIED_HTTPDATE = "Tue, 14 Nov 2023 22:13:20 GMT"


def _parse_http_date(raw: str) -> datetime | None:
    """Parse an RFC 7231 HTTP-date request header (``If-Modified-Since``) to an aware UTC datetime.

    Returns ``None`` for an empty/unparsable value — the caller then falls through to a plain
    200, exactly as a real server would for a header it cannot understand.
    """
    if not raw:
        return None
    try:
        parsed = parsedate_to_datetime(raw)
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        # email.utils returns a naive datetime for an obsolete/no-tz date; HTTP-dates are
        # always GMT, so treat naive results as UTC rather than the local zone's offset.
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


class _MockFeedServer:
    """A stdlib HTTP server serving feed fixtures to the guest over SLIRP.

    Files under ``tests/smoke/fixtures/`` are served by name; a test may also
    register ad-hoc content in memory via :meth:`register`. The guest fetches
    them at ``feed_url(name)`` (``http://192.168.89.2:<port>/<name>``).

    ADR-42 Phase 3: registered feeds emit ``ETag`` and ``Last-Modified`` response
    headers on 200 replies, and answer ``304 Not Modified`` to a matching
    ``If-None-Match`` request header.  Use :meth:`set_content` to update a feed's
    body and bump its ETag atomically (simulates a real feed update).

    issue #722: two more per-name opt-outs/opt-ins isolate the OTHER two
    conditional-GET branches that the always-on Last-Modified header masked:
    :meth:`disable_lastmod` (no validator at all -> exercises the genuine
    no-validator download+hash path) and :meth:`enable_lastmod_304` (an
    RFC-conformant ``If-Modified-Since`` responder -> exercises the
    Last-Modified/``CURLOPT_TIMECONDITION`` fallback, distinct from the
    ETag/``If-None-Match`` path above).
    """

    def __init__(self, root: Path) -> None:
        self._root = root
        self._registered: dict[str, bytes] = {}
        # ADR-42 Phase 3: per-name ETag map (opaque string). A name with no entry
        # in this map serves no ETag (simulates a server that does not support
        # conditional requests).
        self._etag_map: dict[str, str] = {}
        # issue #722: names in this set get NO Last-Modified header on 200 (the
        # genuine "no validator at all" server) — default behaviour (no entry)
        # still emits the fixed Last-Modified below, unchanged for existing tests.
        self._no_lastmod: set[str] = set()
        # issue #722: names in this set get a real If-Modified-Since responder
        # (RFC 9110 §13.1.3) instead of the fixed header being ignored.
        self._ims_304: set[str] = set()
        self._lock = threading.Lock()
        registered = self._registered
        etag_map = self._etag_map
        no_lastmod = self._no_lastmod
        ims_304 = self._ims_304
        lock = self._lock

        class Handler(SimpleHTTPRequestHandler):
            # Serve fixtures dir by default; intercept registered names first.
            def do_GET(self) -> None:  # noqa: N802 (stdlib name)
                name = self.path.lstrip("/")
                with lock:
                    body = registered.get(name)
                    etag = etag_map.get(name)
                    emit_lastmod = name not in no_lastmod
                    honour_ims = name in ims_304
                if body is None:
                    super().do_GET()
                    return
                # ADR-42 Phase 3: honour If-None-Match for conditional-GET.
                # RFC 9110 §13.1.3: a recipient MUST ignore If-Modified-Since when the
                # request also carries If-None-Match, so this branch always takes
                # precedence over the IMS handling below for a name that has an ETag.
                if etag is not None:
                    client_etag = self.headers.get("If-None-Match", "")
                    if client_etag.strip() == etag:
                        self.send_response(304)
                        self.send_header("ETag", etag)
                        self.end_headers()
                        return
                elif honour_ims:
                    # issue #722: RFC-conformant If-Modified-Since — 304 when this
                    # resource's fixed Last-Modified is NOT newer than the client's
                    # IMS value (i.e. the client already has the current version).
                    ims_raw = self.headers.get("If-Modified-Since", "")
                    ims_dt = _parse_http_date(ims_raw)
                    if ims_dt is not None:
                        resource_dt = datetime.fromtimestamp(_MOCK_LAST_MODIFIED_EPOCH, tz=timezone.utc)
                        if resource_dt <= ims_dt:
                            self.send_response(304)
                            self.send_header("Last-Modified", _MOCK_LAST_MODIFIED_HTTPDATE)
                            self.end_headers()
                            return
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                if etag is not None:
                    self.send_header("ETag", etag)
                if emit_lastmod:
                    # Emit a fixed Last-Modified in the past so the guest also has a
                    # validator to store (epoch 1700000000 = 2023-11-14T22:13:20Z).
                    self.send_header("Last-Modified", _MOCK_LAST_MODIFIED_HTTPDATE)
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, fmt: str, *args: object) -> None:
                # Stay quiet in pytest output; failures surface via assertions.
                return

        # Bind to all interfaces so the WAN SLIRP alias 192.168.89.2 (which maps to
        # the runner) can reach it; port 0 lets the OS pick a free port.
        handler = partial(Handler, directory=str(root))
        self._httpd = ThreadingHTTPServer(("0.0.0.0", 0), handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return self._httpd.server_address[1]

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=10)

    def register(self, name: str, content: str | bytes) -> str:
        """Register an in-memory feed body and return its guest-reachable URL.

        The registered feed does NOT emit an ETag by default — it behaves like a
        server that does not support conditional requests.  Call :meth:`set_content`
        (or :meth:`enable_etag`) after :meth:`register` to opt into ETag behaviour.
        """
        body = content.encode() if isinstance(content, str) else content
        with self._lock:
            self._registered[name] = body
        return self.feed_url(name)

    def set_content(self, name: str, content: str | bytes, etag: str | None = None) -> None:
        """Update the body of a registered feed and optionally bump its ETag.

        ADR-42 Phase 3: call this to simulate a feed update on the server side.
        When ``etag`` is given, the new ETag replaces the old one, so the next
        conditional GET from the guest will see a 200 (the stored If-None-Match
        no longer matches) and then re-learn the new ETag for future 304s.
        """
        body = content.encode() if isinstance(content, str) else content
        with self._lock:
            self._registered[name] = body
            if etag is not None:
                self._etag_map[name] = etag

    def enable_etag(self, name: str, etag: str) -> None:
        """Assign an ETag to a registered feed without changing its body.

        After this call the feed emits ``ETag: <etag>`` on 200 responses and
        returns 304 to a matching ``If-None-Match: <etag>`` request.
        """
        with self._lock:
            self._etag_map[name] = etag

    def disable_lastmod(self, name: str) -> None:
        """Opt a registered feed OUT of the default Last-Modified header entirely.

        issue #722: the mock emits a fixed Last-Modified on every 200 by default, so a feed
        registered without :meth:`enable_etag` still leaves the guest with a ``.lastmod``
        validator — the genuine "server supports no conditional requests at all" case was
        never actually reachable. A name in this set gets NO Last-Modified (and, since
        :meth:`enable_etag` was not called either, no ETag) — the guest stores no validator,
        so every future probe is a plain GET and the download+hash comparison genuinely
        decides the outcome.
        """
        with self._lock:
            self._no_lastmod.add(name)

    def enable_lastmod_304(self, name: str) -> None:
        """Make a registered feed answer a matching ``If-Modified-Since`` with a real 304.

        issue #722: without this, the mock's fixed Last-Modified header is emitted but never
        consulted on the request side, so a stored ``.lastmod`` validator never actually gets
        a 304 back — the Last-Modified/``CURLOPT_TIMECONDITION`` fallback (the branch used
        when a feed has no ETag) was unexercised. After this call, a request whose
        If-Modified-Since is at or after this feed's fixed Last-Modified
        (epoch 1700000000) gets a 304 (still with the Last-Modified header echoed back);
        otherwise a plain 200. Has no effect on a name that also carries an ETag — RFC 9110
        §13.1.3 has If-None-Match take precedence, and the handler enforces that ordering.
        """
        with self._lock:
            self._ims_304.add(name)

    def feed_url(self, name: str) -> str:
        """The URL the GUEST uses to fetch ``name`` (via the SLIRP host alias)."""
        return f"http://{GUEST_TO_HOST_ALIAS}:{self.port}/{name.lstrip('/')}"


@dataclass
class CallbackRecord:
    """One request a guest hook made to the callback sink.

    ``form`` is the parsed ``application/x-www-form-urlencoded`` body (the default
    ``--data-urlencode`` shape, POST), ``query`` the parsed URL query string (a GET
    or a ``?k=v`` URL). Both are ``parse_qs`` dicts (``str -> list[str]``): the
    space-encoded changed-alias list round-trips back to a real space here, so a
    test asserts membership against ``form['ip_aliases'][0].split()``.
    """

    method: str
    path: str
    form: dict[str, list[str]]
    query: dict[str, list[str]]


class _MockCallbackSink:
    """A stdlib HTTP server that RECORDS each guest webhook call and replies 200.

    The runner-side mirror of the ADR-12 HAProxy recipe's external consumer (minus
    HAProxy): a recipe-shaped ``post`` hook ``curl``s this sink and forwards the
    url-encoded changed-alias env vars. The sink is OBSERVE-ONLY — it parses the
    body/query into a thread-safe :class:`CallbackRecord` list and answers ``200``,
    nothing more (no side effect on the guest). Bound to ``0.0.0.0`` so the WAN
    SLIRP host alias ``192.168.89.2`` reaches it, exactly like :class:`_MockFeedServer`;
    the guest hits :meth:`guest_url`.
    """

    def __init__(self) -> None:
        self._callbacks: list[CallbackRecord] = []
        self._lock = threading.Lock()
        callbacks = self._callbacks
        lock = self._lock

        class Handler(BaseHTTPRequestHandler):
            def _record(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
                rec = CallbackRecord(
                    method=self.command,
                    path=self.path,
                    form=parse_qs(body),
                    query=parse_qs(urlsplit(self.path).query),
                )
                with lock:
                    callbacks.append(rec)
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_POST(self) -> None:  # noqa: N802 (stdlib name)
                self._record()

            def do_GET(self) -> None:  # noqa: N802 (stdlib name)
                self._record()

            def log_message(self, fmt: str, *args: object) -> None:
                # Stay quiet in pytest output; failures surface via assertions.
                return

        self._httpd = ThreadingHTTPServer(("0.0.0.0", 0), Handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return self._httpd.server_address[1]

    @property
    def callbacks(self) -> list[CallbackRecord]:
        """A snapshot of the recorded callbacks (safe to iterate while the server runs)."""
        with self._lock:
            return list(self._callbacks)

    def clear(self) -> None:
        """Drop all recorded callbacks (call between phases for clean assertions)."""
        with self._lock:
            self._callbacks.clear()

    def guest_url(self, path: str = "/reload") -> str:
        """The URL the GUEST uses to reach this sink (via the SLIRP host alias)."""
        return f"http://{GUEST_TO_HOST_ALIAS}:{self.port}{path}"

    def wait_for(self, n: int, timeout: float = 10.0) -> bool:
        """Poll until at least ``n`` callbacks are recorded, or time out.

        The hook ``curl`` is synchronous within the update pass, but the sink's
        handler thread records a moment later — poll (no fixed sleep) so the
        assertion is not racy. Returns True iff the count was reached.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                if len(self._callbacks) >= n:
                    return True
            time.sleep(0.1)
        with self._lock:
            return len(self._callbacks) >= n

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=10)


class _StubDnsServer:
    """A controlled, OBSERVABLE DNS upstream for the guest's Unbound (over SLIRP).

    This is the smoke matrix's upstream: pfSense forwards every non-local query to its
    System DNS server ``192.168.89.2`` (QEMU/libslirp's WAN host alias — see
    ``helpers.use_system_dns_upstream``), and libslirp NATs guest->192.168.89.2:53 straight
    to this server on the RUNNER's loopback (``127.0.0.1:53``), port-preserving — the
    same WAN host-alias path the mock-feed HTTP server already rides, and the runner's
    own ``/etc/resolv.conf`` is never touched. So what reaches this server is EXACTLY
    what Unbound did not answer locally. That makes
    blocking VERIFIABLE from the upstream side rather than inferred from a bare
    SERVFAIL: every query is recorded (:meth:`received`), so a DNSBL-blocked name must
    NEVER appear here, while a not-blocked name DOES — and resolves to a known answer,
    distinct from every block shape. Nothing leaks to the real internet; the server
    answers everything itself. Listens UDP+TCP on one (configurable) port.

    Per-domain answers are explicit and observable. Default (unregistered name): the
    sentinel A/AAAA (``STUB_DNS_A`` / ``STUB_DNS_AAAA``). Overrides:

      * :meth:`set_records` — give a name its OWN ``A`` (IPv4) and/or ``AAAA`` (IPv6)
        addresses, one or many each; omit a family to serve NODATA for it (to test a
        missing record). Families are validated (A must be IPv4, AAAA IPv6).
      * :meth:`register_cname` — ``src -> target``; an ``A``/``AAAA`` query returns
        ``CNAME + the TARGET's A/AAAA`` in one response, so the chain resolves
        CONSISTENTLY to the target's own addresses (sentinel if the target is
        unregistered). That 2-rrset shape (``an_numrrsets > 1``) is what
        ``pfb_unbound.py``'s CNAME walk reads — a raw Unbound ``local-data`` CNAME
        can't stand in (Unbound returns the bare CNAME, a single rrset).
      * :meth:`register_nxdomain` — deny the name exists.

    Because every domain has its OWN addresses, a probe can assert the EXACT IPs and
    know which name was forwarded at each stage (no inference); :meth:`received` /
    :meth:`queries` are the query log.
    """

    @staticmethod
    def _bind_udp_tcp(addr: str, port: int, *, attempts: int = 10) -> tuple[int, socket.socket, socket.socket]:
        """Bind a UDP+TCP listener pair sharing ONE port, race-free (issue #243).

        Bind the TCP socket FIRST: with ``port == 0`` the kernel's ephemeral pick is
        guaranteed free for TCP (it cannot collide with another live/``TIME_WAIT`` TCP
        socket), then UDP reuses that number — a separate namespace, so safe. The old
        order (ephemeral UDP first, its number forced onto TCP) lost the race when that
        number was already held by an unrelated TCP/``TIME_WAIT`` socket ->
        ``OSError: [Errno 98] Address already in use`` (``SO_REUSEADDR`` does not help: the
        conflict is a foreign socket, not this process re-binding its own). With
        ``port == 0`` each attempt re-draws a fresh ephemeral port, so a rare UDP-side
        collision is retried away; a fixed port (the session mock's ``:53``) cannot be
        re-drawn, so a conflict there surfaces immediately.
        """
        import errno

        last_exc: OSError | None = None
        for _ in range(attempts):
            tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                tcp.bind((addr, port))
                chosen = tcp.getsockname()[1]
                udp.bind((addr, chosen))
            except OSError as exc:
                last_exc = exc
                tcp.close()
                udp.close()
                # A fixed port cannot be re-drawn, and only an address-in-use collision is
                # worth retrying — any other error (EACCES, EADDRNOTAVAIL, ...) surfaces now.
                if port != 0 or exc.errno != errno.EADDRINUSE:
                    raise
                continue
            tcp.listen(16)
            return chosen, udp, tcp
        raise last_exc if last_exc is not None else OSError("stub DNS: could not bind a UDP/TCP port pair")

    def __init__(self, *, port: int | None = None) -> None:
        # Bind address/port are env-overridable so the smoke workflow can put the session
        # mock on the runner's loopback :53 — the System-DNS host-alias path: pfSense
        # forwards to 192.168.89.2 (libslirp's WAN host alias), which NATs
        # guest->192.168.89.2:53 to the runner's 127.0.0.1:53 (this mock), port-preserving.
        # The runner's own /etc/resolv.conf is NEVER touched.
        # ``net.ipv4.ip_unprivileged_port_start`` is lowered by the workflow so this
        # non-root process can bind :53; binding 127.0.0.1 (not 0.0.0.0) avoids clashing
        # with systemd-resolved on 127.0.0.53:53. ``port`` overrides the env (the pure
        # unit tests pass ``port=0`` to force an ephemeral port, so they never collide
        # with the session mock holding :53).
        addr = os.environ.get("SMOKE_STUB_DNS_ADDR") or "127.0.0.1"
        if port is None:
            port = int(os.environ.get("SMOKE_STUB_DNS_PORT") or "0")
        # Bind TCP first so the shared port number is proven free for both (issue #243).
        self._port, self._udp, self._tcp = self._bind_udp_tcp(addr, port)
        self._stop = threading.Event()
        self._lock = threading.Lock()
        # fqdn (lowercased, trailing dot) -> a record dict, one of:
        #   {"cname": target_fqdn}
        #   {"a": [ipv4,...], "aaaa": [ipv6,...]}   (either key optional => NODATA)
        #   {"nxdomain": True}
        # Absent => the sentinel default (STUB_DNS_A / STUB_DNS_AAAA).
        self._records: dict[str, dict[str, object]] = {}
        # Every received query, in order: {"name", "type", "client"}.
        self._queries: list[dict[str, str]] = []
        self._threads = [
            threading.Thread(target=self._serve_udp, daemon=True),
            threading.Thread(target=self._serve_tcp, daemon=True),
        ]

    @property
    def port(self) -> int:
        return self._port

    @staticmethod
    def _fqdn(name: str) -> str:
        return name.rstrip(".").lower() + "."

    @staticmethod
    def _check_family(ips: tuple[str, ...], want_v6: bool) -> list[str]:
        import ipaddress

        out = []
        for ip in ips:
            addr = ipaddress.ip_address(ip)  # raises on a non-IP
            if (addr.version == 6) != want_v6:
                raise ValueError(f"{'AAAA' if want_v6 else 'A'} record needs an IPv{6 if want_v6 else 4} address: {ip}")
            out.append(ip)
        return out

    def set_records(self, name: str, *, a: tuple[str, ...] = (), aaaa: tuple[str, ...] = ()) -> None:
        """Give ``name`` its own A (IPv4) and/or AAAA (IPv6) addresses (one or many each).

        Omit a family to serve NODATA (empty NOERROR) for it — e.g. ``a=(...)`` only
        makes the name AAAA-less. Replaces any prior record for the name.
        """
        rec: dict[str, object] = {}
        if a:
            rec["a"] = self._check_family(a, want_v6=False)
        if aaaa:
            rec["aaaa"] = self._check_family(aaaa, want_v6=True)
        with self._lock:  # _records is read by the server threads — guard every write
            self._records[self._fqdn(name)] = rec

    def register_a(self, name: str, *ips: str) -> None:
        """Answer A for ``name`` with the given IPv4(s) (convenience for set_records)."""
        self.set_records(name, a=ips)

    def register_cname(self, src: str, target: str) -> None:
        """Answer ``src`` with a CNAME to ``target``; the chain resolves to the target's
        own A/AAAA (or the sentinel if the target is unregistered)."""
        with self._lock:
            self._records[self._fqdn(src)] = {"cname": self._fqdn(target)}

    def register_nxdomain(
        self,
        name: str,
        *,
        ede_info_code: int | None = None,
        ede_text: str = "",
        authoritative: bool = False,
        recursion_available: bool = False,
    ) -> None:
        """Answer NXDOMAIN for ``name``, modelling the distinct upstream NXDOMAIN
        shapes the issue #267 detector must tell apart (AA/RA survive to
        ``inplace_cb_query_response``):

          * default (a Quad9-style BLOCK): RA=0, AA=0 -> the block signal.
          * ``recursion_available=True`` (a forwarder relaying a NATURAL NXDOMAIN):
            RA=1, AA=0 -> NOT a block (RA=1 excludes it).
          * ``authoritative=True`` (an AUTHORITATIVE NXDOMAIN, recursive mode):
            RA=0, AA=1 -> NOT a block (AA=0 is what excludes it).

        Optional ``ede_info_code``/``ede_text`` attach an RFC 8914 EDE option (the
        EXTRA-TEXT is the provider name, or ``""`` for none).
        """
        rec = stub_responses.nxdomain_record(
            authoritative=authoritative,
            recursion_available=recursion_available,
            ede_info_code=ede_info_code,
            ede_text=ede_text,
        )
        with self._lock:
            self._records[self._fqdn(name)] = rec

    def clear_cname(self) -> None:
        """Drop ALL per-name records (back to the sentinel default for everything)."""
        with self._lock:
            self._records.clear()

    def received(self, name: str | None = None, rtype: str | None = None) -> list[dict[str, str]]:
        """Queries this upstream got, optionally filtered by name and/or rtype.

        A blocked name must return an EMPTY list (it never reached the upstream); a
        forwarded name returns its hits. The authoritative, log-free signal for
        "was this name answered locally or forwarded?".
        """
        target = self._fqdn(name) if name else None
        with self._lock:
            return [
                dict(q)
                for q in self._queries
                if (target is None or q["name"] == target) and (rtype is None or q["type"] == rtype)
            ]

    def queries(self) -> list[dict[str, str]]:
        """A snapshot of the whole received-query log (for failure diagnostics)."""
        with self._lock:
            return [dict(q) for q in self._queries]

    def reset_queries(self) -> None:
        """Clear the received-query log (call between cases for clean assertions)."""
        with self._lock:
            self._queries.clear()

    def _build_response(self, data: bytes, client: str = "") -> bytes | None:
        # Snapshot the override map under the lock so a concurrent register_*/clear_cname
        # on the test thread can't change it mid-request (which would make the smoke
        # assertions nondeterministic), then build off the snapshot via the shared
        # stub_responses builder (single source, shared with the off-box shape tests).
        with self._lock:
            records = dict(self._records)
        wire, qlog = stub_responses.build_response(records, data, sentinel_a=STUB_DNS_A, sentinel_aaaa=STUB_DNS_AAAA)
        if qlog is not None:
            with self._lock:
                self._queries.append({"name": qlog["name"], "type": qlog["type"], "client": client})
        return wire

    def _serve_udp(self) -> None:
        self._udp.settimeout(0.5)
        while not self._stop.is_set():
            try:
                data, addr = self._udp.recvfrom(65535)
            except OSError:
                continue
            wire = self._build_response(data, addr[0])
            if wire is not None:
                with contextlib.suppress(OSError):
                    self._udp.sendto(wire, addr)

    def _serve_tcp(self) -> None:
        self._tcp.settimeout(0.5)
        while not self._stop.is_set():
            try:
                conn, peer = self._tcp.accept()
            except OSError:
                continue
            with contextlib.suppress(Exception):
                conn.settimeout(2.0)
                header = conn.recv(2)
                if len(header) == 2:
                    n = int.from_bytes(header, "big")
                    data = b""
                    while len(data) < n:
                        chunk = conn.recv(n - len(data))
                        if not chunk:
                            break
                        data += chunk
                    wire = self._build_response(data, peer[0])
                    if wire is not None:
                        conn.sendall(len(wire).to_bytes(2, "big") + wire)
            with contextlib.suppress(OSError):
                conn.close()

    def start(self) -> None:
        for thread in self._threads:
            thread.start()

    def stop(self) -> None:
        self._stop.set()
        for thread in self._threads:
            if thread.ident is not None:  # joinable only once started — stop() is idempotent
                thread.join(timeout=5)
        with contextlib.suppress(OSError):
            self._udp.close()
        with contextlib.suppress(OSError):
            self._tcp.close()


@pytest.fixture(scope="session")
def lan_interface(smoke_vm: SmokeVM, client_vm: SmokeVM) -> Iterator[SmokeVM]:
    """Gate on civm being connected so the pfSense LAN link has carrier, then yield the VM.

    In the two-VM topology the LAN (net2) is a baked QEMU socket crossover between
    pfSense and civm — 192.168.1.1/24 on pfSense, 192.168.1.10 on civm (static DHCP
    lease keyed by ``SMOKE_CLIENT_MAC_ADDRESS``). No VLAN provisioning is needed: the
    LAN interface is configured in the image and is live once both VMs are booted and
    the socket link is connected.

    Depending on ``client_vm`` guarantees civm is up and its data NIC is connected
    (the QEMU socket CONNECTOR has joined the pfSense LISTENER) before any test that
    needs a LAN client runs. Yields the pfSense ``SmokeVM`` object so callers use the
    same reference they always have.

    Inherits both fixtures' skip behaviour: if either ``smoke_vm`` or ``client_vm``
    skips (no image, no KVM, no MAC), this fixture is never entered.
    """
    yield smoke_vm


@pytest.fixture(scope="session")
def stub_dns(smoke_vm: SmokeVM) -> Iterator[_StubDnsServer]:
    """Run the stub DNS upstream and record its port on the VM object.

    Reachable by the guest at 192.168.89.2:<port> via the WAN SLIRP alias (survives
    the egress block, same as mock_feeds). helpers.configure_upstream() points
    Unbound here.
    """
    server = _StubDnsServer()
    server.start()
    smoke_vm.upstream_dns_port = server.port
    try:
        yield server
    finally:
        smoke_vm.upstream_dns_port = None
        server.stop()


@pytest.fixture
def mock_feeds(smoke_vm: SmokeVM) -> Iterator[_MockFeedServer]:
    """Serve fixture feeds to the guest; record the base URL on the VM object.

    Hermeticity note (ADR §2): the egress block is sequenced pull -> block ->
    run and is wired by Phase 6 (the workflow blocks the runner's outbound
    after the GHCR pull). WAN SLIRP-internal ``192.168.89.2`` feeds survive the
    block, so this server stays reachable; do NOT assume real internet egress.
    """
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
    server = _MockFeedServer(FIXTURES_DIR)
    server.start()
    smoke_vm.feed_base_url = f"http://{GUEST_TO_HOST_ALIAS}:{server.port}/"
    try:
        yield server
    finally:
        smoke_vm.feed_base_url = None
        server.stop()


@pytest.fixture
def webhook_sink(smoke_vm: SmokeVM) -> Iterator[_MockCallbackSink]:
    """A runner-side HTTP sink that records guest hook callbacks (ADR-12 webhook recipe).

    FUNCTION-scoped for per-test isolation: each case gets a fresh sink (empty
    callback list, its own ephemeral port). Reachable from the guest at
    ``sink.guest_url(path)`` (``http://192.168.89.2:<port><path>``) via the WAN SLIRP
    host alias — the same path the mock-feed server rides, so it survives the egress
    block. Shut down on teardown.
    """
    server = _MockCallbackSink()
    server.start()
    try:
        yield server
    finally:
        server.stop()


# --------------------------------------------------------------------------- #
# Small probe helpers shared by smoke tests
# --------------------------------------------------------------------------- #


def wait_for_tcp(host: str, port: int, timeout: float = 5.0) -> bool:
    """Best-effort TCP reachability check (no fixed sleep elsewhere)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with contextlib.suppress(OSError):
            with socket.create_connection((host, port), timeout=2.0):
                return True
        time.sleep(0.2)
    return False


def resolve_a(name: str, host: str, port: int, timeout: float = 5.0) -> list[str]:
    """Resolve an A record against the guest's Unbound and return the IPs.

    Uses dnspython for precise rcode+record assertions (richer than ``dig``).
    Imported here, not at module top, so a default collection that does not run
    smoke never needs the third-party dep (belt-and-suspenders alongside the
    ``--ignore``).
    """
    import dns.message
    import dns.query
    import dns.rdatatype

    query = dns.message.make_query(name, dns.rdatatype.A)
    # TCP: deterministic, and the hostfwd maps both tcp+udp 5353 -> 53.
    response = dns.query.tcp(query, host, port=port, timeout=timeout)
    answers: list[str] = []
    for rrset in response.answer:
        if rrset.rdtype == dns.rdatatype.A:
            answers.extend(str(item) for item in rrset)
    return answers


def expected_control_answer(env: Mapping[str, str] = os.environ) -> tuple[str, str | None]:
    """The baked Unbound local-data control name + expected A (RESULTS/02).

    Both are PARAMETERS (env overridable) so the probe is not pinned to one
    baked image: defaults match what RESULTS/02 records as baked.
    """
    # Empty/absent SMOKE_CONTROL_NAME => no baked control => callers skip. Use
    # `or` (not get's default): smoke-single.yml SETS the var to "" when the secret/var
    # is unset, AND a truly-absent var must also skip — a hardcoded default name
    # would make the optional probe FAIL (instead of skip) on a local run with no
    # baked control. ip defaults only matter when a name IS configured.
    name = env.get("SMOKE_CONTROL_NAME") or ""
    ip = (env.get("SMOKE_CONTROL_IP") or "") if name else ""
    return name, (ip or None)


# --------------------------------------------------------------------------- #
# On-failure diagnostics — dump live VM state (the session VM is torn down at
# end of run, so a failed case must capture it here, in-run)
# --------------------------------------------------------------------------- #


def _needs_two_vm(fixturenames: list[str] | set[str]) -> bool:
    """Return True iff this test boots the civm LAN client (two-VM topology).

    Ground truth for "does this test need civm?" computed from the fixture dependency:
    pytest's ``item.fixturenames`` is the full transitive closure, so membership of
    ``client_vm`` or ``lan_interface`` is exact. When a test gains or loses ``client_vm``
    the tag flips automatically — no list, no drift.
    """
    return bool({"client_vm", "lan_interface"} & set(fixturenames))


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Auto-apply the ``two_vm`` marker from the fixture closure — never hand-apply it.

    The tag is COMPUTED: if a test (transitively) requests ``client_vm`` or
    ``lan_interface`` it boots the civm client and therefore belongs to the two-VM
    topology. The lane orchestrator partitions civm-needing vs civm-less lanes via
    ``-m two_vm`` / ``-m 'not two_vm'`` without a hardcoded list.
    """
    for item in items:
        if _needs_two_vm(item.fixturenames):
            item.add_marker("two_vm")


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo[Any]) -> Generator[None, None, None]:
    """Stash each phase's report on the item so fixtures can read pass/fail."""
    outcome = yield
    rep = outcome.get_result()
    setattr(item, f"_rep_{rep.when}", rep)


def _failure_report(node: pytest.Item) -> pytest.TestReport | None:
    """The report that proves this test failed, or None if it did not fail.

    Call-phase report first; when absent, fall back to the setup report (issue #777):
    a fixture that raises during arrange means the test never reaches its call phase,
    so ``_rep_call`` is never stashed — without the fallback an arrange failure got no
    diagnostics at all. A setup SKIP (e.g. SMOKE_PKG unset) has ``failed == False`` and
    correctly returns None.
    """
    rep = getattr(node, "_rep_call", None)
    if rep is None:
        rep = getattr(node, "_rep_setup", None)
    return rep if rep is not None and rep.failed else None


@pytest.fixture(autouse=True)
def _dump_vm_on_failure(request: pytest.FixtureRequest) -> Iterator[None]:
    """If a VM-backed case failed — in its body OR in a fixture arrange — print
    pfSense/Unbound/pfBlockerNG state."""
    yield
    if _failure_report(request.node) is None:
        return
    # The mock DNS query log — what reached the upstream, READ not inferred.
    stub = request.node.funcargs.get("stub_dns")
    if isinstance(stub, _StubDnsServer):
        print("\n========== STUB DNS UPSTREAM — received queries ==========")
        for entry in stub.queries():
            print(f"  {entry['client']:>15}  {entry['type']:<5} {entry['name']}")
        print("========== END STUB DNS UPSTREAM ==========")
    # A fixture (tick's mfs_var) may have already captured failure-time state pre-teardown,
    # BEFORE its revert reboot wiped the MFS /var (issue #774). This autouse dump finalizes
    # after that fixture, so a second dump here would show the post-reboot state and mislead
    # the post-mortem — keep the (host-side) stub log above, skip the VM dump.
    if getattr(request.node, "_pfb_failure_dumped", False):
        return
    vm = request.node.funcargs.get("deployed_vm") or request.node.funcargs.get("smoke_vm")
    # Some deployed_vm fixtures yield a (pfSense, civm) tuple in the two-VM topology;
    # dump_diagnostics wants the pfSense SmokeVM, so unwrap to the first element.
    if isinstance(vm, tuple):
        vm = vm[0] if vm else None
    if vm is None:
        return
    from . import helpers  # local import: helpers imports from conftest (avoid cycle)

    helpers.dump_diagnostics(vm)


# --------------------------------------------------------------------------- #
# Cross-test isolation — the session VM is ONE boot whose disk persists across every
# test/module. reset() clears only the pf tables, NOT config.xml, so without these two
# autouse guards injected feeds/settings/toggles/host-overrides and a runner egress block
# bleed into the next test along collection order (a real false-green source).
# --------------------------------------------------------------------------- #


@pytest.fixture(autouse=True, scope="module")
def _pfb_module_baseline(request: pytest.FixtureRequest) -> Generator[None, None, None]:
    """Wipe pfBlockerNG config to a clean baseline AFTER each smoke module (cross-module isolation).

    Each module's ``deployed_vm`` deploys on top of whatever the PREVIOUS module left behind,
    and ``reset()`` only drops the pf tables — so injected feeds/settings/global toggles and
    the smoke control Host Overrides leak forward (e.g. ``killstates`` leaving ``enable_float``
    on flips the next module's intended non-floating rule to floating). This teardown calls
    :func:`helpers.reset_pfb_baseline` so the next module starts from an empty pfBlockerNG
    config; module 1 is already clean from the fresh boot.

    Scoped to the SMOKE tier only — the UI tier (``tests/smoke/ui/``) shares a session-scoped
    login + box and is reset separately, so it is excluded here. A strict no-op unless
    ``SMOKE_PKG`` is set (a package was actually deployed) AND the VM was actually booted, so
    off-box modules that never touch the VM are untouched (and never boot one just to reset).
    A genuine reset failure is allowed to SURFACE — silently swallowing it would leak dirty
    state into the next module, defeating the isolation this fixture exists to provide.
    """
    yield
    # UI tier shares session state (deferred to its own per-test reset) — leave it alone.
    if Path(str(request.path)).parent.name == "ui":
        return
    # No-op outside a real deployed smoke run, so off-box modules (no VM) are unaffected.
    if not os.environ.get("SMOKE_PKG"):
        return
    # Read the already-booted VM from the session stash — NEVER getfixturevalue (it re-enters
    # setup and could boot a VM just to reset it). None ⇒ the VM was never booted this run, so
    # there is nothing to reset.
    vm = request.session.stash.get(SMOKE_VM_KEY, None)
    if vm is None:
        return
    from . import helpers  # local import: helpers imports from conftest (avoid cycle)

    # Let a genuine baseline-reset failure propagate rather than silently leaking dirty state
    # into the next module. The module's test results are already recorded before this teardown
    # runs, so a teardown error is reported separately and cannot mask a test outcome.
    helpers.reset_pfb_baseline(vm)


@pytest.fixture(autouse=True)
def _restore_egress() -> Generator[None, None, None]:
    """Restore the runner's egress after every test (cross-test guard).

    ``block_egress()`` / ``unblock_egress()`` flip the runner's GLOBAL iptables OUTPUT policy;
    a test that blocks egress (e.g. a ``CaseContext`` probe) and dies before unblocking would
    leave dark egress for every later test — every later ``pkg``/feed fetch then fails. This
    always unblocks on teardown. A strict no-op unless ``SMOKE_BLOCK_EGRESS`` is set, so a local
    run never touches the dev machine's firewall.
    """
    yield
    from . import helpers  # local import: helpers imports from conftest (avoid cycle)

    with contextlib.suppress(Exception):
        helpers.unblock_egress()
