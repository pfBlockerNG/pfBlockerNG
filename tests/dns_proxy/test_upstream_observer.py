"""The upstream observer script (issue #267): how an upstream DNS block is still logged now that Unbound's replies lose
what makes it one.

Unbound rewrites every reply it sends (RA set, AA clear, the upstream's EDNS options gone), so only a python callback
INSIDE Unbound sees the raw upstream response. pfb_upstream_observer.py is that callback and nothing else: it hands the
raw facts to the gateway's decider over a Unix datagram socket. These tests cover the script's end without a real
Unbound; the receiving end is in go/pfb_dns_gateway/decider (pfb_dns_proxy_socket_test.go,
pfb_unbound_observer_oracle_test.go), and the two ends together, against a real Unbound, in
test_gateway_modes.py::test_an_upstream_ede_block_is_logged_for_the_real_client_in_observer_mode and
test_gateway_upstream_blocks.py. The copies of the limits the two ends keep are compared with the Go constants here.
"""

from __future__ import annotations

import contextlib
import importlib.util
import json
import re
import socket
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest
from frontend_constants import PROTO_DIR, REPO_ROOT
from frontend_helpers import WATCHDOG, watched

OBSERVER = PROTO_DIR / "pfb_upstream_observer.py"
DECIDER = REPO_ROOT / "go" / "pfb_dns_gateway" / "decider"

# What Unbound's embedded Python injects into a script's globals (util/module.h): the ids and states it passes around.
MODULE_ID = 0
MODULE_EVENT_NEW, MODULE_EVENT_PASS, MODULE_EVENT_REPLY, MODULE_EVENT_MODDONE = 0, 1, 2, 5
MODULE_WAIT_MODULE, MODULE_ERROR, MODULE_FINISHED = 2, 5, 6

RR_TYPE_A, RR_TYPE_AAAA = 1, 28
NXDOMAIN_RECURSIVE = 0x8183  # QR RD RA, NXDOMAIN
EDE15_BLOCKED = (15, b"\x00\x0fBlocked by Quad9")
CLIENT = "192.0.2.7"
SOCKET = "pfb_upstream.sock"
DEFAULT_DATAGRAM = 2048  # The observer's conservative report budget, not the platform-dependent kernel maximum.


@dataclass
class Observer:
    module: ModuleType
    registered: dict[str, Any]  # what the script asked Unbound to call, by kind
    warned: list[str]  # what it logged through log_warn


@pytest.fixture
def observer() -> Iterator[Observer]:
    """The shipped script loaded the way pythonmod loads it: its names are in scope before its code runs."""
    registered: dict[str, Any] = {}
    warned: list[str] = []
    spec = importlib.util.spec_from_file_location("pfb_upstream_observer", OBSERVER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    names = {
        "MODULE_EVENT_NEW": MODULE_EVENT_NEW,
        "MODULE_EVENT_PASS": MODULE_EVENT_PASS,
        "MODULE_EVENT_MODDONE": MODULE_EVENT_MODDONE,
        "MODULE_WAIT_MODULE": MODULE_WAIT_MODULE,
        "MODULE_ERROR": MODULE_ERROR,
        "MODULE_FINISHED": MODULE_FINISHED,
        "log_warn": warned.append,
    }
    for name, value in names.items():
        setattr(module, name, value)

    def register(callback: Any, env: Any, id: int) -> bool:
        registered["query_response"] = callback
        return True

    module.register_inplace_cb_query_response = register  # type: ignore[attr-defined]
    spec.loader.exec_module(module)
    yield Observer(module, registered, warned)
    sock = getattr(module, "_sock", None)
    if sock is not None:
        sock.close()


def _start(observer: Observer, directory: Path, monkeypatch: pytest.MonkeyPatch) -> Callable[..., bool]:
    """The script initialised in `directory` (the socket name is relative to Unbound's working directory); returns the
    callback it registered."""
    monkeypatch.chdir(directory)
    assert observer.module.init_standard(MODULE_ID, None) is True
    return observer.registered["query_response"]  # type: ignore[no-any-return]


def _upstream_response(
    name: str = "blocked.example.",
    qtype: int = RR_TYPE_A,
    client: str = CLIENT,
    flags: int = NXDOMAIN_RECURSIVE,
    options: tuple[tuple[int, bytes], ...] = (EDE15_BLOCKED,),
) -> tuple[SimpleNamespace, SimpleNamespace]:
    """The two arguments pythonmod gives inplace_cb_query_response: the qstate (with the upstream's EDNS options) and
    the raw response."""
    qstate = SimpleNamespace(
        qinfo=SimpleNamespace(qname_str=name, qtype=qtype),
        mesh_info=SimpleNamespace(
            reply_list=SimpleNamespace(query_reply=SimpleNamespace(addr=client)),
        ),
        edns_opts_back_in_iter=[SimpleNamespace(code=code, data=data) for code, data in options],
        ext_state=[0],
        return_msg=None,
        return_rcode=0,
        no_cache_store=0,
    )
    return qstate, SimpleNamespace(rep=SimpleNamespace(flags=flags))


def _listen(path: Path) -> socket.socket:
    receiver = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    receiver.bind(str(path))
    receiver.settimeout(WATCHDOG)
    return receiver


def _fill_queue(path: str, senders: contextlib.ExitStack) -> None:
    """Fill the receiver's queue: from then on every report is lost until the queue is drained."""
    sent = 1
    while sent:  # each sender is stopped by its own buffer; one refused at once finds the receiver's queue full
        filler = senders.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM))
        filler.setblocking(False)
        sent = 0
        with contextlib.suppress(BlockingIOError):
            while True:
                filler.sendto(b"x", path)
                sent += 1


def _drain(receiver: socket.socket) -> None:
    receiver.setblocking(False)
    with contextlib.suppress(BlockingIOError):
        while True:
            receiver.recv(65535)
    receiver.settimeout(WATCHDOG)


def _next_report(receiver: socket.socket) -> bytes:
    """The next report on the observer's socket: one that never comes is a stuck run, not a verdict."""
    with watched("the observer's report"):
        return receiver.recv(65535)


def test_the_observer_registers_the_upstream_response_callback_and_nothing_else(observer: Observer) -> None:
    assert observer.module.init_standard(MODULE_ID, None) is True
    assert list(observer.registered) == ["query_response"]  # no reply callback: it never sees what a client is told


def test_the_observer_sends_the_raw_upstream_facts_in_one_datagram(
    observer: Observer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    relay = _start(observer, tmp_path, monkeypatch)
    with _listen(tmp_path / SOCKET) as receiver:
        qstate, response = _upstream_response(
            "Blocked.Example.", RR_TYPE_AAAA, options=(EDE15_BLOCKED, (10, b"\x01\x02"))
        )
        assert relay(qstate, response) is True
        report = json.loads(_next_report(receiver))
    assert report == {
        "client": CLIENT,
        "qname": "Blocked.Example.",  # the client's case, as Unbound has it
        "qtype": RR_TYPE_AAAA,
        "flags": NXDOMAIN_RECURSIVE,
        "opts": [[15, EDE15_BLOCKED[1].hex()], [10, "0102"]],
    }


def test_a_full_gateway_socket_loses_the_report_and_never_holds_up_the_answer(
    observer: Observer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The script runs on Unbound's worker threads: a send that waited for a gateway that stopped reading would stall
    them all."""
    relay = _start(observer, tmp_path, monkeypatch)
    assert observer.module._sock.getblocking() is False
    with _listen(tmp_path / SOCKET), contextlib.ExitStack() as senders:
        _fill_queue(str(tmp_path / SOCKET), senders)
        assert relay(*_upstream_response()) is True
    assert (
        len(observer.warned) == 1
    )  # a full socket is routine under load: one line for the burst, not one per response


def test_reports_lost_in_one_burst_are_warned_about_once_and_a_later_burst_again(
    observer: Observer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    relay = _start(observer, tmp_path, monkeypatch)
    path = str(tmp_path / SOCKET)
    counts: list[int] = []
    with _listen(tmp_path / SOCKET) as receiver, contextlib.ExitStack() as senders:
        _fill_queue(path, senders)
        for _ in range(5):
            assert relay(*_upstream_response()) is True
        counts.append(len(observer.warned))
        _drain(receiver)
        assert relay(*_upstream_response()) is True  # gets through, so the burst is over
        assert json.loads(_next_report(receiver))["qname"] == "blocked.example."
        _fill_queue(path, senders)
        assert relay(*_upstream_response()) is True
        counts.append(len(observer.warned))
    assert counts == [1, 2]
    assert [re.findall(r"(\d+) lost so far", line) for line in observer.warned] == [["1"], ["6"]]  # every loss counted


LONG_NAME = "\\000" * 250  # 250 octets written as Unbound writes an unprintable byte: 1000 characters
EDE_AT_CAP = b"\x00\x0f" + b"x" * 510  # an EDE option whose data is exactly MAX_REPORT_OPTION_HEX hex digits


@pytest.mark.parametrize(
    ("options", "sent_codes"),
    [
        pytest.param(
            ((10, b"a" * 400), (10, b"b" * 400), (10, b"c" * 400), EDE15_BLOCKED),
            [15, 10, 10],
            id="total over a datagram",
        ),
        pytest.param(((10, b"x" * 600), EDE15_BLOCKED), [15], id="option over the cap"),
        pytest.param(
            ((10, b"a" * 400), (10, b"b" * 400), (10, b"c" * 400), (11, b"d"), EDE15_BLOCKED),
            [15, 10, 10, 11],
            id="a later option that fits is sent past one that does not",
        ),
    ],
)
def test_the_observer_keeps_the_extended_dns_error_first_and_sends_only_what_fits(
    observer: Observer,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    options: tuple[tuple[int, bytes], ...],
    sent_codes: list[int],
) -> None:
    """A report never leaves bigger than a datagram, and never without the Extended DNS Error that makes it a block:
    that option goes first, the others keep their order, and only those that still fit are sent."""
    relay = _start(observer, tmp_path, monkeypatch)
    qstate, response = _upstream_response(options=options)
    with _listen(tmp_path / SOCKET) as receiver:
        assert relay(qstate, response) is True
        raw = _next_report(receiver)
    assert len(raw) <= DEFAULT_DATAGRAM
    assert [code for code, _ in json.loads(raw)["opts"]] == sent_codes


@pytest.mark.parametrize(
    ("name", "options"),
    [
        pytest.param(LONG_NAME, ((15, EDE_AT_CAP),), id="a name this long leaves no room for the block"),
        pytest.param("blocked.example.", ((15, b"x" * 600),), id="an EDE over the option cap"),
    ],
)
def test_a_block_that_cannot_be_sent_whole_is_counted_lost_and_nothing_is_sent(
    observer: Observer,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    options: tuple[tuple[int, bytes], ...],
) -> None:
    """The Extended DNS Error is the block itself: when it cannot be sent, nothing is, and the loss is counted and
    warned about like one the socket refused."""
    relay = _start(observer, tmp_path, monkeypatch)
    qstate, response = _upstream_response(name, options=options)
    with _listen(tmp_path / SOCKET) as receiver:
        receiver.setblocking(False)
        assert relay(qstate, response) is True
        with pytest.raises(BlockingIOError):
            receiver.recv(65535)
    assert [re.findall(r"(\d+) lost so far", line) for line in observer.warned] == [["1"]]


def test_the_observer_sends_no_more_options_than_the_decider_accepts(
    observer: Observer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    relay = _start(observer, tmp_path, monkeypatch)
    qstate, response = _upstream_response(options=((10, b"\x01"),) * 8 + (EDE15_BLOCKED,))
    with _listen(tmp_path / SOCKET) as receiver:
        assert relay(qstate, response) is True
        opts = json.loads(_next_report(receiver))["opts"]
    assert (len(opts), opts[0][0]) == (_go_constant("pfb_dns_proxy_observer.go", "maxReportOptions"), 15)


def test_one_option_at_the_cap_fits_a_default_datagram(
    observer: Observer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    relay = _start(observer, tmp_path, monkeypatch)
    cap = observer.module.MAX_REPORT_OPTION_HEX
    qstate, response = _upstream_response(options=((15, b"x" * (cap // 2)),))
    with _listen(tmp_path / SOCKET) as receiver:
        assert relay(qstate, response) is True
        raw = _next_report(receiver)
    assert [(code, len(data)) for code, data in json.loads(raw)["opts"]] == [(15, cap)]


@pytest.mark.parametrize("listener", ["no socket file", "stale socket file nobody listens on"])
def test_resolution_goes_on_when_the_gateway_is_not_listening(
    observer: Observer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, listener: str
) -> None:
    monkeypatch.chdir(tmp_path)
    if listener != "no socket file":
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as gone:
            gone.bind(SOCKET)  # closing it leaves the file: the gateway that made it is gone
    relay = _start(observer, tmp_path, monkeypatch)
    assert relay(*_upstream_response()) is True


def test_a_response_the_observer_cannot_describe_resolves_on_and_says_so(
    observer: Observer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    relay = _start(observer, tmp_path, monkeypatch)
    qstate, response = _upstream_response()
    qstate.qinfo = None
    with _listen(tmp_path / SOCKET):  # the gateway is listening, so a report is attempted
        assert relay(qstate, response) is True
    assert len(observer.warned) == 1
    assert "pfb_upstream_observer" in observer.warned[0]


class _Reads:
    """A qstate stand-in that records the name of every attribute read from the real one."""

    def __init__(self, qstate: SimpleNamespace) -> None:
        self._qstate = qstate
        self.reads: list[str] = []

    def __getattr__(self, name: str) -> Any:
        self.reads.append(name)
        return getattr(self._qstate, name)


def test_a_response_is_not_even_read_while_nobody_is_listening_for_the_report(
    observer: Observer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The callback runs for every upstream response of every query, so with no socket file (the gateway was not
    started with --observer) it must cost one existence check, not a report built from the response and thrown away."""
    relay = _start(observer, tmp_path, monkeypatch)
    qstate, response = _upstream_response()
    spy = _Reads(qstate)
    path = tmp_path / SOCKET
    with _listen(path) as receiver:
        assert relay(spy, response) is True
        assert json.loads(_next_report(receiver))["qname"] == "blocked.example."
    assert spy.reads != []  # before: with the gateway listening the response is read and reported
    path.unlink()
    spy.reads.clear()
    assert relay(spy, response) is True
    assert spy.reads == []


@pytest.mark.parametrize(
    ("event", "state"),
    [
        (MODULE_EVENT_NEW, MODULE_WAIT_MODULE),
        (MODULE_EVENT_PASS, MODULE_WAIT_MODULE),
        (MODULE_EVENT_MODDONE, MODULE_FINISHED),
        (MODULE_EVENT_REPLY, MODULE_ERROR),
    ],
    ids=["new", "pass", "done", "any-other-event"],
)
def test_the_observer_is_a_pass_through_in_unbounds_module_chain(observer: Observer, event: int, state: int) -> None:
    qstate, _ = _upstream_response()
    before = (qstate.return_msg, qstate.return_rcode, qstate.no_cache_store)
    assert observer.module.operate(MODULE_ID, event, qstate, None) is True
    assert qstate.ext_state[MODULE_ID] == state
    assert (qstate.return_msg, qstate.return_rcode, qstate.no_cache_store) == before


# --- the two ends agree: the observer keeps its own copies of what the Go decider enforces ----------------------


def _go_constant(source: str, name: str) -> int | str:
    """The value of a constant of the Go decider (`name = value` in a const block)."""
    text = (DECIDER / source).read_text(encoding="utf-8")
    found = re.search(rf"^\s*{name}\s*=\s*(\d+|\"[^\"]*\")", text, re.MULTILINE)
    assert found is not None, f"{name} is not a constant of {source}"
    value = found.group(1)
    return value.strip('"') if value.startswith('"') else int(value)


def test_the_observer_and_the_decider_agree_on_the_socket_name(observer: Observer) -> None:
    assert observer.module.SOCKET == _go_constant("pfb_dns_proxy_socket.go", "observerSocketName")


def test_the_observer_and_the_decider_agree_on_the_report_limits_and_the_block_option(observer: Observer) -> None:
    limits = {
        "MAX_REPORT_BYTES": "maxReportBytes",
        "MAX_REPORT_OPTIONS": "maxReportOptions",
        "MAX_REPORT_OPTION_HEX": "maxReportOptionHex",
    }
    assert {name: getattr(observer.module, name) for name in limits} == {
        name: _go_constant("pfb_dns_proxy_observer.go", go) for name, go in limits.items()
    }
    assert observer.module.EDE_OPTION == _go_constant("pfb_unbound_upstream.go", "ednsOptCodeEDE")
