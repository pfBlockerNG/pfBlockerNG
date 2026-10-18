"""`--ready-file PATH` (issue #3515): the proxy publishes its own PID there once it serves.

The marker is written atomically with mode 0600 after the sockets are bound, the privileges are dropped, the module (or
the reply log) is started and the signal handlers are installed; a start that fails leaves none. Only the process whose
PID it holds removes it, at shutdown. A marker says the front end answers queries; it does not say Unbound resolves.
"""

from __future__ import annotations

import asyncio
import errno
import logging
import logging.handlers
import os
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import dnswire
import pfb_dns_proxy
import pytest
from dot_helpers import free_port
from frontend_constants import BLOCKED, DNSBL_IPV4, PROTO_DIR
from frontend_helpers import WATCHDOG, FakeProxyUpstream, FakeUnbound, build_query, running_proxy, serving, udp_exchange

LOOPBACK = ["--listen", "127.0.0.1", "--port", "0"]
VIP4 = bytes(int(octet) for octet in DNSBL_IPV4.split("."))
BLOCKED_ADDRESS = bytes([192, 0, 2, 99])
ZONE = {(BLOCKED, dnswire.TYPE_A): [f"{BLOCKED} 300 IN A 192.0.2.99"]}


def _ready_args(argv: list[str], ready: Path | None) -> Any:
    flag = [] if ready is None else ["--ready-file", str(ready)]
    return pfb_dns_proxy.parse_args([*argv, *flag])


def _own_pid() -> bytes:
    return f"{os.getpid()}\n".encode()


@pytest.fixture
def run_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "run"
    directory.mkdir()
    return directory


@pytest.fixture
def ready(run_dir: Path) -> Path:
    return run_dir / "pfb_dns_ready"


@pytest.fixture
def quiet_module(module_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The real module boots from module_dir without writing its /var/log files (as test_no_module.py's `boots`)."""
    real_boot = pfb_dns_proxy.boot

    def boot_without_log_files(directory: str) -> Any:
        module = real_boot(directory)
        monkeypatch.setattr(module, "pfb_log", lambda name, line: None)
        return module

    monkeypatch.chdir(module_dir)
    monkeypatch.setattr(sys, "stderr", sys.stderr)  # init_standard() replaces it; register the auto-restore
    monkeypatch.setattr(pfb_dns_proxy, "boot", boot_without_log_files)


class _NoFile(logging.Handler):
    """Stands in for the reply log's WatchedFileHandler: no file is written and nothing is kept."""

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        super().__init__()

    def emit(self, record: logging.LogRecord) -> None:
        del record


@pytest.fixture
def no_reply_file(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(logging.handlers, "WatchedFileHandler", _NoFile)


def test_the_ready_file_is_off_unless_asked_for() -> None:
    assert pfb_dns_proxy.parse_args([]).ready_file is None
    assert pfb_dns_proxy.parse_args(["--ready-file", "/var/unbound/pfb_dns_ready"]).ready_file == (
        "/var/unbound/pfb_dns_ready"
    )


@pytest.mark.parametrize(
    ("argv", "answer"),
    [
        pytest.param(["--module-dir", "MODULE"], VIP4, id="module"),
        pytest.param(["--no-module", "--module-dir", "MODULE/absent"], BLOCKED_ADDRESS, id="no-module"),
        pytest.param(
            ["--no-module", "--reply-log", "--module-dir", "MODULE/absent"], BLOCKED_ADDRESS, id="logging-only"
        ),
    ],
)
def test_while_the_proxy_serves_the_marker_holds_its_pid_at_mode_0600_and_shutdown_removes_it(
    argv: list[str],
    answer: bytes,
    module_dir: Path,
    quiet_module: None,
    no_reply_file: None,
    ready: Path,
) -> None:
    args = _ready_args([*LOOPBACK, *(arg.replace("MODULE", str(module_dir)) for arg in argv)], ready)

    async def scenario() -> tuple[tuple[bytes, int], bytes, int]:
        async with FakeProxyUpstream(FakeUnbound(ZONE)) as upstream:
            args.upstream = f"127.0.0.1:{upstream.port}"
            async with serving(args) as [server]:
                published = (ready.read_bytes(), stat.S_IMODE(ready.stat().st_mode))
                reply = (await udp_exchange(server, build_query(BLOCKED)))[0]
            return published, reply, len(upstream.headers)

    published, reply, forwarded = asyncio.run(scenario())
    assert published == (_own_pid(), 0o600)
    assert [rr.rdata for rr in dnswire.parse(reply).answers] == [answer]
    assert forwarded == (0 if answer == VIP4 else 1)
    assert not ready.exists()


def test_the_marker_is_published_last_after_the_privilege_drop_the_module_and_the_listeners(
    module_dir: Path, quiet_module: None, ready: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[tuple[str, bool]] = []
    boot_quietly = pfb_dns_proxy.boot
    real_serve_listeners = pfb_dns_proxy.Frontend.serve_listeners

    def drop(_account: Any) -> None:
        seen.append(("drop", ready.exists()))

    def boot(directory: str) -> Any:
        seen.append(("boot", ready.exists()))
        return boot_quietly(directory)

    async def serve_listeners(self: pfb_dns_proxy.Frontend, listeners: Any, context: Any = None) -> Any:
        seen.append(("listeners", ready.exists()))
        return await real_serve_listeners(self, listeners, context)

    monkeypatch.setattr(pfb_dns_proxy, "lookup_user", lambda name: SimpleNamespace(pw_name=name))
    monkeypatch.setattr(pfb_dns_proxy, "drop_privileges", drop)
    monkeypatch.setattr(pfb_dns_proxy, "boot", boot)
    monkeypatch.setattr(pfb_dns_proxy.Frontend, "serve_listeners", serve_listeners)
    args = _ready_args([*LOOPBACK, "--module-dir", str(module_dir), "--user", "nobody"], ready)

    async def scenario() -> bytes:
        async with serving(args):
            return ready.read_bytes()

    assert asyncio.run(scenario()) == _own_pid()
    assert [step for step, _ in seen[:3]] == ["drop", "boot", "listeners"]  # serve_listeners() runs again for DoT
    assert not any(exists for _, exists in seen)


def test_a_module_that_fails_to_boot_leaves_no_marker(
    module_dir: Path, ready: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boot(_directory: str) -> Any:
        raise RuntimeError("module init failed")

    monkeypatch.setattr(pfb_dns_proxy, "boot", boot)
    args = _ready_args([*LOOPBACK, "--module-dir", str(module_dir)], ready)
    with pytest.raises(RuntimeError, match="module init failed"):
        asyncio.run(pfb_dns_proxy.serve(args))
    assert not ready.exists()


def test_a_listener_that_cannot_bind_leaves_no_marker(ready: Path) -> None:
    args = _ready_args(["--listen", "203.0.113.9", "--port", "0", "--no-module"], ready)
    with pytest.raises(pfb_dns_proxy.ListenError):
        asyncio.run(pfb_dns_proxy.serve(args))
    assert not ready.exists()


def test_a_ready_file_that_cannot_be_written_stops_the_proxy_with_exit_1_and_one_error_line(
    run_dir: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    ready = run_dir / "missing" / "pfb_dns_ready"
    argv = [*LOOPBACK, "--no-module", "--upstream", f"127.0.0.1:{free_port()}", "--ready-file", str(ready)]
    assert pfb_dns_proxy.main(argv) == 1
    assert capfd.readouterr().err == f"pfb_dns_proxy: cannot write ready file {ready}: {os.strerror(errno.ENOENT)}\n"
    assert not ready.parent.exists()


def test_a_stale_symlink_at_the_ready_path_is_replaced_and_its_target_is_never_written(
    run_dir: Path, ready: Path
) -> None:
    victim = run_dir / "victim"
    victim.write_text("keep me\n", encoding="utf-8")
    ready.symlink_to(victim)
    args = _ready_args([*LOOPBACK, "--no-module", "--upstream", f"127.0.0.1:{free_port()}"], ready)

    async def scenario() -> tuple[bool, bytes]:
        async with serving(args):
            return ready.is_symlink(), ready.read_bytes()

    is_link, marker = asyncio.run(scenario())
    assert not is_link and marker == _own_pid()
    assert victim.read_text(encoding="utf-8") == "keep me\n"
    assert not os.path.lexists(ready)


def test_shutdown_leaves_a_marker_that_another_process_has_written_since(run_dir: Path, ready: Path) -> None:
    args = _ready_args([*LOOPBACK, "--no-module", "--upstream", f"127.0.0.1:{free_port()}"], ready)

    async def scenario() -> None:
        async with serving(args):
            ready.write_text("424242\n", encoding="utf-8")  # a newer proxy has taken the marker over

    asyncio.run(scenario())
    assert ready.read_text(encoding="utf-8") == "424242\n"


def test_the_real_process_publishes_its_pid_answers_a_query_and_removes_the_marker_on_sigterm(
    run_dir: Path, ready: Path
) -> None:
    argv = [*LOOPBACK, "--no-module", "--upstream", f"127.0.0.1:{free_port()}", "--ready-file", str(ready)]
    with running_proxy(argv, cwd=run_dir) as (child, port):
        assert ready.read_bytes() == f"{child.pid}\n".encode()
        reply = dnswire.parse(asyncio.run(udp_exchange(("127.0.0.1", port), build_query(BLOCKED, qid=0x3515)))[0])
        assert (reply.id, reply.rcode) == (0x3515, 2)  # Unbound is down: the relay's own SERVFAIL, from the child
    assert not ready.exists()


def test_a_sigterm_sent_the_moment_the_marker_appears_is_handled_and_exits_0(run_dir: Path, ready: Path) -> None:
    argv = [*LOOPBACK, "--no-module", "--upstream", f"127.0.0.1:{free_port()}", "--ready-file", str(ready)]
    for _ in range(10):
        child = subprocess.Popen(
            [sys.executable, str(PROTO_DIR / "pfb_dns_proxy.py"), *argv],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=run_dir,
        )
        try:
            deadline = time.monotonic() + WATCHDOG
            while not ready.exists():
                assert time.monotonic() < deadline, "the marker never appeared"
                time.sleep(0.0005)
            child.send_signal(signal.SIGTERM)
            assert child.wait(timeout=WATCHDOG) == 0
        finally:
            if child.poll() is None:
                child.kill()
            child.wait()
        assert not ready.exists()


def test_without_the_flag_no_file_is_written_at_startup_or_shutdown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    args = _ready_args([*LOOPBACK, "--no-module", "--upstream", f"127.0.0.1:{free_port()}"], None)

    async def scenario() -> list[str]:
        async with serving(args):
            return sorted(os.listdir(tmp_path))

    assert asyncio.run(scenario()) == []
    assert os.listdir(tmp_path) == []
