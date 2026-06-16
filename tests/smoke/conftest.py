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
  ``http://10.0.2.2:<port>/<name>`` via the QEMU user-net (SLIRP) host alias.

The boot+probe core lives in :func:`boot_and_probe`, separate from the pytest
fixtures, so it can double as a reusable health/sanity gate (ADR-09 fans the
harness across CE versions; the image ref/digest is always a PARAMETER, never
hardcoded).
"""

from __future__ import annotations

import contextlib
import os
import shutil
import socket
import subprocess
import threading
import time
from collections.abc import Generator, Iterator, Mapping
from dataclasses import dataclass, field
from functools import partial
from http.server import BaseHTTPRequestHandler, SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

# --------------------------------------------------------------------------- #
# Paths + constants
# --------------------------------------------------------------------------- #

SMOKE_DIR = Path(__file__).resolve().parent
BOOT_VM_SH = SMOKE_DIR / "boot_vm.sh"
WAIT_READY_SH = SMOKE_DIR / "wait_ready.sh"
FIXTURES_DIR = SMOKE_DIR / "fixtures"

# Host<->guest exposure baked into boot_vm.sh's hostfwd map (see RESULTS/01).
DEFAULT_HOST = "127.0.0.1"
DEFAULT_SSH_PORT = 2222  # host -> guest 22
DEFAULT_WEB_PORT = 8080  # host -> guest 80
DEFAULT_DNS_PORT = 5353  # host -> guest 53 (tcp+udp)

# The SLIRP host alias the guest uses to reach the runner (mock feed server).
GUEST_TO_HOST_ALIAS = "10.0.2.2"

# Sentinel answers the runner-side stub upstream returns for any forwarded query
# (see _StubDnsServer / helpers.configure_upstream). Distinct from every DNSBL
# block shape (NXDOMAIN / 0.0.0.0 / the VIP), so a name that should be blocked
# but ISN'T resolves to the sentinel — a true pass, never a false-green block.
STUB_DNS_A = "203.0.113.99"  # RFC 5737 documentation range
STUB_DNS_AAAA = "2001:db8::99"  # RFC 3849 documentation range

# Hard readiness ceiling; wait_ready.sh polls (no fixed sleep) up to this.
DEFAULT_BOOT_TIMEOUT = int(os.environ.get("SMOKE_BOOT_TIMEOUT", "300"))


# --------------------------------------------------------------------------- #
# Connection object yielded by the VM fixture
# --------------------------------------------------------------------------- #


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
    # 10.0.2.2:<port> via SLIRP). Set once the stub_dns fixture is up; None
    # otherwise. Unbound is pointed here so it never recurses into dark egress.
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
        """
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
            *remote,
        ]

    def ssh(self, *remote: str, timeout: float = 60.0) -> subprocess.CompletedProcess[str]:
        """Run a command on the guest over SSH and capture its output."""
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
) -> BootHandle:
    """Boot ``base_image`` and block until the guest is usable.

    REUSES the shell helpers over subprocess:
      * ``boot_vm.sh`` creates the ephemeral copy-on-write overlay (the base is
        read-only and never mutated — run-level immutability) and execs qemu;
      * ``wait_ready.sh`` polls SSH + WebUI readiness with bounded backoff and a
        hard timeout (NO fixed sleep), and bails immediately if the qemu PID
        dies (bad image / KVM abort).

    On readiness, returns a :class:`BootHandle`. On timeout or a dead qemu it
    raises, after killing qemu. Designed to be callable outside pytest (a CE
    image sanity gate).
    """
    log_file = log_path.open("wb")
    # boot_vm.sh backgrounds nothing itself (it execs qemu); we background it
    # via Popen and pass its PID to wait_ready.sh so a dead boot is caught fast.
    process: subprocess.Popen[bytes] = subprocess.Popen(
        ["sh", str(BOOT_VM_SH), str(base_image)],
        stdout=log_file,
        stderr=subprocess.STDOUT,
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
        # Passing web_port makes readiness require nginx+PHP, not just sshd.
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
        _kill(process)
        log_file.close()
        raise

    if result.returncode != 0:
        _kill(process)
        log_file.close()
        tail = _tail(log_path)
        raise RuntimeError(
            f"VM never became ready (wait_ready exit {result.returncode}).\n"
            f"wait_ready stderr:\n{result.stderr}\n--- boot log tail ---\n{tail}"
        )

    # Surface "boot-to-ready: N seconds" so it lands in the captured output.
    print(result.stdout.strip())
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


# --------------------------------------------------------------------------- #
# Session-scoped VM fixture
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="session")
def smoke_vm(tmp_path_factory: pytest.TempPathFactory) -> Iterator[SmokeVM]:
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
    try:
        yield handle.vm
    finally:
        _kill(handle.process)
        with contextlib.suppress(Exception):
            handle.log_file.close()
        # The overlay is mktemp'd inside boot_vm.sh and removed on its clean
        # exit (trap on EXIT/INT/TERM); terminating qemu fires it. The pulled
        # image + logs live under tmp_path_factory, which pytest reaps.


# --------------------------------------------------------------------------- #
# Mock HTTP feed server (stdlib only)
# --------------------------------------------------------------------------- #


class _MockFeedServer:
    """A stdlib HTTP server serving feed fixtures to the guest over SLIRP.

    Files under ``tests/smoke/fixtures/`` are served by name; a test may also
    register ad-hoc content in memory via :meth:`register`. The guest fetches
    them at ``feed_url(name)`` (``http://10.0.2.2:<port>/<name>``).
    """

    def __init__(self, root: Path) -> None:
        self._root = root
        self._registered: dict[str, bytes] = {}
        registered = self._registered

        class Handler(SimpleHTTPRequestHandler):
            # Serve fixtures dir by default; intercept registered names first.
            def do_GET(self) -> None:  # noqa: N802 (stdlib name)
                name = self.path.lstrip("/")
                if name in registered:
                    body = registered[name]
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                super().do_GET()

            def log_message(self, fmt: str, *args: object) -> None:
                # Stay quiet in pytest output; failures surface via assertions.
                return

        # Bind to all interfaces so the SLIRP alias 10.0.2.2 (which maps to the
        # runner) can reach it; port 0 lets the OS pick a free port.
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
        """Register an in-memory feed body and return its guest-reachable URL."""
        body = content.encode() if isinstance(content, str) else content
        self._registered[name] = body
        return self.feed_url(name)

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
    nothing more (no side effect on the guest). Bound to ``0.0.0.0`` so the SLIRP
    host alias ``10.0.2.2`` reaches it, exactly like :class:`_MockFeedServer`; the
    guest hits :meth:`guest_url`.
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
    System DNS server ``10.0.2.2`` (QEMU/libslirp's host alias — see
    ``helpers.use_system_dns_upstream``), and libslirp NATs guest->10.0.2.2:53 straight
    to this server on the RUNNER's loopback (``127.0.0.1:53``), port-preserving — the
    same host-alias path the mock-feed HTTP server already rides, and the runner's own
    ``/etc/resolv.conf`` is never touched. So what reaches this server is EXACTLY what
    Unbound did not answer locally. That makes
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
        # forwards to 10.0.2.2 (libslirp's host alias), which NATs guest->10.0.2.2:53 to
        # the runner's 127.0.0.1:53 (this mock), port-preserving. The runner's own
        # /etc/resolv.conf is NEVER touched. ``net.ipv4.ip_unprivileged_port_start`` is
        # lowered by the workflow so this non-root process can bind :53; binding
        # 127.0.0.1 (not 0.0.0.0) avoids clashing with systemd-resolved on 127.0.0.53:53.
        # ``port`` overrides the env (the pure unit tests pass ``port=0`` to force an
        # ephemeral port, so they never collide with the session mock holding :53).
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

    def register_nxdomain(self, name: str) -> None:
        """Answer NXDOMAIN for ``name`` (an upstream that denies the name exists)."""
        with self._lock:
            self._records[self._fqdn(name)] = {"nxdomain": True}

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

    @staticmethod
    def _addrs(rec: dict[str, object] | None, want_v6: bool) -> list[str] | None:
        """Addresses to emit for a record of this family, or None for NODATA.

        rec None (unregistered) -> the sentinel (a single default address). Registered
        with the family -> its list. Registered WITHOUT the family -> None (NODATA).
        """
        if rec is None:
            return [STUB_DNS_AAAA if want_v6 else STUB_DNS_A]
        return rec.get("aaaa" if want_v6 else "a")  # type: ignore[return-value]

    def _build_response(self, data: bytes, client: str = "") -> bytes | None:
        import dns.message
        import dns.rcode
        import dns.rdatatype
        import dns.rrset

        try:
            req = dns.message.from_wire(data)
        except Exception:
            return None
        resp = dns.message.make_response(req)
        if not req.question:
            return resp.to_wire()
        q = req.question[0]
        name = q.name.to_text().lower()
        # Snapshot the query log AND the record(s) this answer needs atomically, so a
        # concurrent register_*/clear_cname on the test thread can't change the override
        # map mid-request (which would make the smoke assertions nondeterministic).
        with self._lock:
            self._queries.append({"name": name, "type": dns.rdatatype.to_text(q.rdtype), "client": client})
            rec = self._records.get(name)
            target_rec = self._records.get(str(rec["cname"])) if (rec is not None and "cname" in rec) else None
        if rec is not None and rec.get("nxdomain"):
            resp.set_rcode(dns.rcode.NXDOMAIN)
            return resp.to_wire()
        if q.rdtype not in (dns.rdatatype.A, dns.rdatatype.AAAA):
            return resp.to_wire()  # other qtypes: empty NOERROR
        want_v6 = q.rdtype == dns.rdatatype.AAAA
        rtype = "AAAA" if want_v6 else "A"
        if rec is not None and "cname" in rec:
            target = str(rec["cname"])
            resp.answer.append(dns.rrset.from_text(q.name, 60, "IN", "CNAME", target))
            ips = self._addrs(target_rec, want_v6)
            if ips:
                resp.answer.append(dns.rrset.from_text(target, 60, "IN", rtype, *ips))
            return resp.to_wire()
        ips = self._addrs(rec, want_v6)
        if ips:
            resp.answer.append(dns.rrset.from_text(q.name, 60, "IN", rtype, *ips))
        return resp.to_wire()

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
def stub_dns(smoke_vm: SmokeVM) -> Iterator[_StubDnsServer]:
    """Run the stub DNS upstream and record its port on the VM object.

    Reachable by the guest at 10.0.2.2:<port> via SLIRP (survives the egress
    block, same as mock_feeds). helpers.configure_upstream() points Unbound here.
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
    after the GHCR pull). SLIRP-internal ``10.0.2.2`` feeds survive the block,
    so this server stays reachable; do NOT assume real internet egress.
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
    ``sink.guest_url(path)`` (``http://10.0.2.2:<port><path>``) via the SLIRP host
    alias — the same path the mock-feed server rides, so it survives the egress
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
    # `or` (not get's default): smoke.yml SETS the var to "" when the secret/var
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


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo[Any]) -> Generator[None, None, None]:
    """Stash each phase's report on the item so fixtures can read pass/fail."""
    outcome = yield
    rep = outcome.get_result()
    setattr(item, f"_rep_{rep.when}", rep)


@pytest.fixture(autouse=True)
def _dump_vm_on_failure(request: pytest.FixtureRequest) -> Iterator[None]:
    """If a VM-backed case failed, print pfSense/Unbound/pfBlockerNG state."""
    yield
    rep = getattr(request.node, "_rep_call", None)
    if rep is None or not rep.failed:
        return
    # The mock DNS query log — what reached the upstream, READ not inferred.
    stub = request.node.funcargs.get("stub_dns")
    if isinstance(stub, _StubDnsServer):
        print("\n========== STUB DNS UPSTREAM — received queries ==========")
        for entry in stub.queries():
            print(f"  {entry['client']:>15}  {entry['type']:<5} {entry['name']}")
        print("========== END STUB DNS UPSTREAM ==========")
    vm = request.node.funcargs.get("deployed_vm") or request.node.funcargs.get("smoke_vm")
    if vm is None:
        return
    from . import helpers  # local import: helpers imports from conftest (avoid cycle)

    helpers.dump_diagnostics(vm)
