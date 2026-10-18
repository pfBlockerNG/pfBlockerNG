"""The upstream observer: how an upstream DNS block (issue #267) is still logged while the proxy hosts pfb_unbound.py.

Unbound rewrites every reply it sends (RA set, AA clear, the upstream's EDNS options gone), so the proxy never sees what
makes a reply an upstream block: only a python callback INSIDE Unbound sees the raw response. pfb_upstream_observer.py
is that callback and nothing else: it hands the raw facts to the proxy over a Unix datagram socket, and the proxy
fires the module's own inplace_cb_query_response on them. These tests cover both ends without a real Unbound; the
signatures against a real one are in test_integration_unbound.py.
"""

from __future__ import annotations

import asyncio
import contextlib
import csv
import importlib.util
import json
import os
import socket
import stat
import sys
from collections.abc import Awaitable, Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any, TypeVar

import dnswire
import pfb_dns_proxy
import pytest
import unbound_shim as shim
from frontend_constants import PROTO_DIR, Booted
from frontend_helpers import WATCHDOG, build_query, udp_exchange

OBSERVER = PROTO_DIR / "pfb_upstream_observer.py"
T = TypeVar("T")

NXDOMAIN_RECURSIVE = 0x8183  # QR RD RA, NXDOMAIN
EDE15_BLOCKED = (15, b"\x00\x0fBlocked by Quad9")
CLIENT = "192.0.2.7"
MODULE_EVENT_REPLY = 2  # util/module.h: an event the observer has no use for


@dataclass
class Observer:
    module: ModuleType
    registered: dict[str, Any]  # what the script asked Unbound to call, by kind


@pytest.fixture
def observer() -> Iterator[Observer]:
    """The shipped script loaded the way pythonmod loads it: its names are in scope before its code runs.

    Registration goes to a dict of its own: in the proxy process shim.callbacks belongs to the module.
    """
    registered: dict[str, Any] = {}
    spec = importlib.util.spec_from_file_location("pfb_upstream_observer", OBSERVER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    for name in shim.__all__:
        setattr(module, name, getattr(shim, name))

    def register(callback: Any, env: Any, id: int) -> bool:
        registered["query_response"] = callback
        return True

    module.register_inplace_cb_query_response = register  # type: ignore[attr-defined]
    spec.loader.exec_module(module)
    yield Observer(module, registered)
    sock = getattr(module, "_sock", None)
    if sock is not None:
        sock.close()


def _upstream_response(
    name: str = "blocked.example.",
    qtype: int = shim.RR_TYPE_A,
    client: str = CLIENT,
    flags: int = NXDOMAIN_RECURSIVE,
    options: tuple[tuple[int, bytes], ...] = (EDE15_BLOCKED,),
) -> tuple[shim.module_qstate, shim.DnsMsg]:
    """The two arguments pythonmod gives inplace_cb_query_response: the qstate (with the upstream's EDNS options) and
    the raw response."""
    qstate = shim.module_qstate(shim.query_info(name, qtype), client, 40000, 0x0100)
    qstate.edns_opts_back_in_iter = [shim.EdnsOpt(code, data) for code, data in options]
    return qstate, shim.DnsMsg(shim.query_info(name, qtype), flags, [], [], [])


def _listen(path: Path) -> socket.socket:
    receiver = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    receiver.bind(str(path))
    receiver.settimeout(WATCHDOG)
    return receiver


# --- the script inside Unbound -------------------------------------------------------------------


def test_the_observer_registers_the_upstream_response_callback_and_nothing_else(observer: Observer) -> None:
    assert observer.module.init_standard(shim.MODULE_ID, shim.module_env()) is True
    assert list(observer.registered) == ["query_response"]
    assert shim.callbacks == {}  # no reply callback: it never sees, let alone changes, what a client is told


def test_the_observer_sends_the_raw_upstream_facts_in_one_datagram(
    observer: Observer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)  # the socket name is relative to Unbound's working directory
    observer.module.init_standard(shim.MODULE_ID, shim.module_env())
    with _listen(tmp_path / pfb_dns_proxy.OBSERVER_SOCKET) as receiver:
        qstate, response = _upstream_response(
            "Blocked.Example.", shim.RR_TYPE_AAAA, options=(EDE15_BLOCKED, (10, b"\x01\x02"))
        )
        assert observer.registered["query_response"](qstate, response) is True
        report = json.loads(receiver.recv(65535))
    assert report == {
        "client": CLIENT,
        "qname": "Blocked.Example.",  # the client's case, as Unbound has it
        "qtype": shim.RR_TYPE_AAAA,
        "flags": NXDOMAIN_RECURSIVE,
        "opts": [[15, EDE15_BLOCKED[1].hex()], [10, "0102"]],
    }


def test_a_full_proxy_socket_loses_the_report_and_never_holds_up_the_answer(
    observer: Observer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The script runs on Unbound's worker threads: a send that waited for a proxy that stopped reading would stall
    them all."""
    monkeypatch.chdir(tmp_path)
    warned: list[str] = []
    monkeypatch.setattr(observer.module, "log_warn", warned.append)
    observer.module.init_standard(shim.MODULE_ID, shim.module_env())
    assert observer.module._sock.getblocking() is False
    path = str(tmp_path / pfb_dns_proxy.OBSERVER_SOCKET)
    with _listen(tmp_path / pfb_dns_proxy.OBSERVER_SOCKET), contextlib.ExitStack() as senders:
        sent = 1
        while sent:  # each sender is stopped by its own buffer; one refused at once finds the receiver's queue full
            filler = senders.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM))
            filler.setblocking(False)
            sent = 0
            with contextlib.suppress(BlockingIOError):
                while True:
                    filler.sendto(b"x", path)
                    sent += 1
        assert observer.registered["query_response"](*_upstream_response()) is True
    assert warned == []  # a full socket is routine under load, not a fault to log for every response


@pytest.mark.parametrize("listener", ["no socket file", "stale socket file nobody listens on"])
def test_resolution_goes_on_when_the_proxy_is_not_listening(
    observer: Observer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, listener: str
) -> None:
    monkeypatch.chdir(tmp_path)
    if listener != "no socket file":
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as gone:
            gone.bind(pfb_dns_proxy.OBSERVER_SOCKET)  # closing it leaves the file: the proxy that made it is gone
    observer.module.init_standard(shim.MODULE_ID, shim.module_env())
    assert observer.registered["query_response"](*_upstream_response()) is True


def test_a_response_the_observer_cannot_describe_resolves_on_and_says_so(
    observer: Observer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    warned: list[str] = []
    monkeypatch.setattr(observer.module, "log_warn", warned.append)
    observer.module.init_standard(shim.MODULE_ID, shim.module_env())
    qstate, response = _upstream_response()
    qstate.qinfo = None  # type: ignore[assignment]
    with _listen(tmp_path / pfb_dns_proxy.OBSERVER_SOCKET):  # the proxy is listening, so a report is attempted
        assert observer.registered["query_response"](qstate, response) is True
    assert len(warned) == 1
    assert "pfb_upstream_observer" in warned[0]


class _Reads:
    """A qstate stand-in that records the name of every attribute read from the real one."""

    def __init__(self, qstate: shim.module_qstate) -> None:
        self._qstate = qstate
        self.reads: list[str] = []

    def __getattr__(self, name: str) -> Any:
        self.reads.append(name)
        return getattr(self._qstate, name)


def test_a_response_is_not_even_read_while_nobody_is_listening_for_the_report(
    observer: Observer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The callback runs for every upstream response of every query, so with no socket file (no proxy asked for
    reports) it must cost one existence check, not a report built from the response and thrown away."""
    monkeypatch.chdir(tmp_path)
    observer.module.init_standard(shim.MODULE_ID, shim.module_env())
    relay = observer.registered["query_response"]
    qstate, response = _upstream_response()
    spy = _Reads(qstate)
    path = tmp_path / pfb_dns_proxy.OBSERVER_SOCKET
    with _listen(path) as receiver:
        assert relay(spy, response) is True
        assert json.loads(receiver.recv(65535))["qname"] == "blocked.example."
    assert spy.reads != []  # before: with the proxy listening the response is read and reported
    path.unlink()
    spy.reads.clear()
    assert relay(spy, response) is True
    assert spy.reads == []


@pytest.mark.parametrize(
    ("event", "state"),
    [
        (shim.MODULE_EVENT_NEW, shim.MODULE_WAIT_MODULE),
        (shim.MODULE_EVENT_PASS, shim.MODULE_WAIT_MODULE),
        (shim.MODULE_EVENT_MODDONE, shim.MODULE_FINISHED),
        (MODULE_EVENT_REPLY, shim.MODULE_ERROR),
    ],
    ids=["new", "pass", "done", "any-other-event"],
)
def test_the_observer_is_a_pass_through_in_unbounds_module_chain(observer: Observer, event: int, state: int) -> None:
    qstate, _ = _upstream_response()
    before = (qstate.return_msg, qstate.return_rcode, qstate.no_cache_store)
    assert observer.module.operate(shim.MODULE_ID, event, qstate, None) is True
    assert qstate.ext_state[shim.MODULE_ID] == state
    assert (qstate.return_msg, qstate.return_rcode, qstate.no_cache_store) == before


def test_the_observer_and_the_proxy_agree_on_the_socket_name(observer: Observer) -> None:
    assert observer.module.SOCKET == pfb_dns_proxy.OBSERVER_SOCKET


# --- the proxy end -------------------------------------------------------------------------------


def _report(**overrides: Any) -> bytes:
    fields: dict[str, Any] = {
        "client": CLIENT,
        "qname": "blocked.example.",
        "qtype": shim.RR_TYPE_A,
        "flags": NXDOMAIN_RECURSIVE,
        "opts": [[15, EDE15_BLOCKED[1].hex()]],
    }
    return json.dumps({**fields, **overrides}).encode()


def _frontend(booted: Booted) -> pfb_dns_proxy.Frontend:
    return pfb_dns_proxy.Frontend(booted.module, ("127.0.0.1", 9), timeout=WATCHDOG)


def _upstream_blocks(booted: Booted) -> list[list[str]]:
    rows = [next(csv.reader([line])) for name, line in booted.log if name.endswith("dnsbl.log")]
    return [row for row in rows if row[5] == "Upstream_Block"]


def test_a_reported_upstream_block_is_logged_as_the_module_logs_one(fwd_booted: Booted) -> None:
    _frontend(fwd_booted).relay_upstream_response(_report())
    [row] = _upstream_blocks(fwd_booted)
    assert (row[0], row[2], row[3], row[4], row[5], row[6], row[7], row[8], row[9], row[10]) == (
        "DNSBL-python",
        "blocked.example",
        CLIENT,  # the client the observer saw behind the PROXYv2 header, not the proxy's 127.0.0.1
        "Python",
        "Upstream_Block",
        "Upstream",
        "EDE15 (Blocked)",
        "Blocked by Quad9",
        "+",
        "A",
    )


def test_a_report_of_an_ordinary_response_logs_nothing(fwd_booted: Booted) -> None:
    frontend = _frontend(fwd_booted)
    frontend.relay_upstream_response(_report(opts=[]))  # a natural NXDOMAIN: RA set, no EDE
    frontend.relay_upstream_response(_report(qname="sentinel.example.", flags=0x8103, opts=[]))  # NXRA: RA clear
    assert [row[2] for row in _upstream_blocks(fwd_booted)] == ["sentinel.example"]


def test_a_reported_block_is_not_logged_while_the_resolver_is_not_forwarding(booted: Booted) -> None:
    """The module's own gate decides, as it does inside Unbound: without forwarding there is no upstream to blame."""
    _frontend(booted).relay_upstream_response(_report())
    assert _upstream_blocks(booted) == []


def test_a_report_without_a_client_is_logged_against_the_resolver(fwd_booted: Booted) -> None:
    _frontend(fwd_booted).relay_upstream_response(_report(client=""))
    assert [row[3] for row in _upstream_blocks(fwd_booted)] == ["127.0.0.1"]


def _block_option_of_hex_size(digits: int) -> list[Any]:
    """The EDE15 block option padded (extra text) to exactly `digits` hex digits, so an over-cap report is one the
    proxy would log if it did not refuse it."""
    return [15, (EDE15_BLOCKED[1] + b"a" * (digits // 2 - len(EDE15_BLOCKED[1]))).hex()]


def _block_with_options(count: int) -> bytes:
    """A report of an upstream block carrying `count` options in all: the block, then unrelated ones."""
    return _report(opts=[[15, EDE15_BLOCKED[1].hex()], *[[10, "0102"]] * (count - 1)])


MALFORMED = {
    "not json": b"not json",
    "empty": b"",
    "not utf-8": b"\xff\xfe\x00",
    "not an object": b"[1, 2]",
    "nested deeper than the parser recurses": b"[" * 5000,
    "json null": b"null",
    "no fields": b"{}",
    "qname not a string": _report(qname=7),
    "qname too long": _report(qname="a" * 1025),
    "qtype not a number": _report(qtype="A"),
    "qtype a boolean": _report(qtype=True),
    "qtype out of range": _report(qtype=70000),
    "flags not a number": _report(flags="x"),
    "flags fractional": _report(flags=1.5),
    "flags negative": _report(flags=-1),
    "flags out of range": _report(flags=70000),
    "client not an address": _report(client="not-an-ip"),
    "client not a string": _report(client=5),
    "opts not a list": _report(opts="x"),
    "option not a pair": _report(opts=[[15]]),
    "option code not a number": _report(opts=[["a", "00"]]),
    "option code out of range": _report(opts=[[70000, "00"]]),
    "option data not hex": _report(opts=[[15, "zz"]]),
    "option data not a string": _report(opts=[[15, 5]]),
    "option data over the cap": _report(opts=[_block_option_of_hex_size(pfb_dns_proxy.MAX_REPORT_OPTION_HEX + 2)]),
    "too many options": _block_with_options(pfb_dns_proxy.MAX_REPORT_OPTIONS + 1),
}


@pytest.mark.parametrize("datagram", MALFORMED.values(), ids=MALFORMED.keys())
def test_a_malformed_report_is_dropped_and_the_next_good_one_is_still_logged(
    fwd_booted: Booted, datagram: bytes
) -> None:
    frontend = _frontend(fwd_booted)
    frontend.relay_upstream_response(datagram)
    assert _upstream_blocks(fwd_booted) == []
    frontend.relay_upstream_response(_report())
    assert len(_upstream_blocks(fwd_booted)) == 1


@pytest.mark.parametrize(
    "datagram",
    [
        _block_with_options(pfb_dns_proxy.MAX_REPORT_OPTIONS),
        _report(opts=[_block_option_of_hex_size(pfb_dns_proxy.MAX_REPORT_OPTION_HEX)]),
    ],
    ids=["options at the cap", "option data at the cap"],
)
def test_a_report_exactly_at_a_size_cap_is_still_logged(fwd_booted: Booted, datagram: bytes) -> None:
    """The caps refuse only what is over them; a report at the limit is a genuine block."""
    _frontend(fwd_booted).relay_upstream_response(datagram)
    assert len(_upstream_blocks(fwd_booted)) == 1


def test_malformed_reports_are_warned_about_once_not_once_each(
    fwd_booted: Booted, capfd: pytest.CaptureFixture[str]
) -> None:
    frontend = _frontend(fwd_booted)
    for _ in range(5):
        frontend.relay_upstream_response(b"not json")
    warnings = [line for line in capfd.readouterr().err.splitlines() if "malformed upstream report" in line]
    assert len(warnings) == 1


async def _row_logged(booted: Booted, name: str) -> list[list[str]]:
    """The upstream-block rows once one for `name` is in the log (the datagram arrives on the event loop)."""
    await asyncio.to_thread(booted.log.wait_for, lambda _log: any(row[2] == name for row in _upstream_blocks(booted)))
    return _upstream_blocks(booted)


def test_what_the_observer_sends_over_the_socket_is_logged_by_the_proxy(fwd_booted: Booted, observer: Observer) -> None:
    """The two ends together, as they meet in production: one directory, a relative socket name, a real datagram."""

    async def scenario() -> list[list[str]]:
        frontend = _frontend(fwd_booted)
        await frontend.serve_observer(pfb_dns_proxy.OBSERVER_SOCKET)  # the module dir is the working directory
        try:
            observer.module.init_standard(shim.MODULE_ID, shim.module_env())
            qstate, response = _upstream_response("sent.example.", options=(EDE15_BLOCKED,))
            assert observer.registered["query_response"](qstate, response) is True
            return await _row_logged(fwd_booted, "sent.example")
        finally:
            await frontend.stop()

    [row] = asyncio.run(scenario())
    assert (row[2], row[3], row[7], row[8]) == ("sent.example", CLIENT, "EDE15 (Blocked)", "Blocked by Quad9")


def test_the_socket_is_private_to_its_owner_and_gone_when_the_proxy_stops(tmp_path: Path, fwd_booted: Booted) -> None:
    path = tmp_path / "observer.sock"

    async def scenario() -> int:
        frontend = _frontend(fwd_booted)
        await frontend.serve_observer(str(path))
        try:
            assert stat.S_ISSOCK(path.stat().st_mode)
            return stat.S_IMODE(path.stat().st_mode)
        finally:
            await frontend.stop()

    assert asyncio.run(scenario()) == 0o600
    assert not path.exists()


def test_a_stale_socket_file_from_a_previous_proxy_is_replaced(tmp_path: Path, fwd_booted: Booted) -> None:
    path = tmp_path / "observer.sock"
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as previous:
        previous.bind(str(path))  # the file stays when the proxy is killed

    async def scenario() -> list[list[str]]:
        frontend = _frontend(fwd_booted)
        await frontend.serve_observer(str(path))
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sender:
                sender.sendto(_report(qname="after-restart.example."), str(path))
            return await _row_logged(fwd_booted, "after-restart.example")
        finally:
            await frontend.stop()

    assert [row[2] for row in asyncio.run(scenario())] == ["after-restart.example"]


def test_a_file_that_is_not_a_socket_is_never_removed(tmp_path: Path, fwd_booted: Booted) -> None:
    path = tmp_path / "observer.sock"
    path.write_text("precious", encoding="utf-8")

    async def scenario() -> None:
        await _frontend(fwd_booted).serve_observer(str(path))

    with pytest.raises(OSError, match="not a socket"):
        asyncio.run(scenario())
    assert path.read_text(encoding="utf-8") == "precious"


# --- serve(): the socket comes up with the proxy ---------------------------------------------------


@pytest.fixture
def quiet_boot(module_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The real module, booted from `module_dir` without its /var/log files."""
    real_boot = pfb_dns_proxy.boot

    def boot_without_log_files(directory: str) -> Any:
        module = real_boot(directory)
        monkeypatch.setattr(module, "pfb_log", lambda name, line: None)
        return module

    monkeypatch.chdir(module_dir)
    monkeypatch.setattr(sys, "stderr", sys.stderr)  # init_standard() replaces it; register the auto-restore
    monkeypatch.setattr(pfb_dns_proxy, "boot", boot_without_log_files)


def _serving(module_dir: Path, during: Callable[[tuple[str, int]], Awaitable[T]], *flags: str) -> T:
    """Run serve() on an ephemeral loopback port with `module_dir` as the module dir; `during` runs once it is ready."""
    args = pfb_dns_proxy.parse_args(
        ["--upstream", "127.0.0.1:9", "--listen", "127.0.0.1", "--port", "0", "--module-dir", str(module_dir), *flags]
    )

    async def scenario() -> T:
        stop = asyncio.Event()
        ready: asyncio.Future[list[tuple[str, int]]] = asyncio.get_running_loop().create_future()
        task = asyncio.create_task(pfb_dns_proxy.serve(args, stop=stop, on_ready=ready.set_result))
        try:
            await asyncio.wait({ready, task}, timeout=WATCHDOG, return_when=asyncio.FIRST_COMPLETED)
            if task.done():
                task.result()
            if not ready.done():
                pytest.fail("STUCK: serve() was not ready in time")
            return await during(ready.result()[0])
        finally:
            stop.set()
            await asyncio.wait_for(task, WATCHDOG)

    return asyncio.run(scenario())


@pytest.mark.parametrize(
    ("flags", "socket_exists"), [(["--observer"], True), ([], False)], ids=["with --observer", "by default"]
)
def test_the_proxy_listens_for_the_observer_in_the_module_dir_only_when_asked_to_and_removes_it_when_it_stops(
    module_dir: Path, quiet_boot: None, flags: list[str], socket_exists: bool
) -> None:
    async def during(_server: tuple[str, int]) -> bool:
        return os.path.lexists(module_dir / pfb_dns_proxy.OBSERVER_SOCKET)

    assert _serving(module_dir, during, *flags) is socket_exists
    assert not (module_dir / pfb_dns_proxy.OBSERVER_SOCKET).exists()


def test_the_observer_socket_is_a_socket_while_the_proxy_serves(module_dir: Path, quiet_boot: None) -> None:
    async def during(_server: tuple[str, int]) -> bool:
        return stat.S_ISSOCK((module_dir / pfb_dns_proxy.OBSERVER_SOCKET).stat().st_mode)

    assert _serving(module_dir, during, "--observer") is True


def test_observer_is_off_unless_asked_for() -> None:
    assert pfb_dns_proxy.parse_args([]).observer is False
    assert pfb_dns_proxy.parse_args(["--observer"]).observer is True


def test_observer_without_the_module_is_an_argument_error(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as refused:
        pfb_dns_proxy.parse_args(["--observer", "--no-module"])
    assert refused.value.code == 2
    assert "--observer cannot be used with --no-module" in capsys.readouterr().err


def test_dns_is_served_without_upstream_block_logging_when_the_socket_cannot_be_made(
    module_dir: Path, quiet_boot: None, capfd: pytest.CaptureFixture[str]
) -> None:
    (module_dir / pfb_dns_proxy.OBSERVER_SOCKET).write_text("in the way", encoding="utf-8")

    async def during(server: tuple[str, int]) -> list[bytes]:
        reply = (await udp_exchange(server, build_query("blocked.example.")))[0]
        return [rr.rdata for rr in dnswire.parse(reply).answers]

    assert len(_serving(module_dir, during, "--observer")) == 1  # the module's DNSBL answer: the proxy still serves
    assert "upstream-block detection is off" in capfd.readouterr().err
    assert (module_dir / pfb_dns_proxy.OBSERVER_SOCKET).read_text(encoding="utf-8") == "in the way"
