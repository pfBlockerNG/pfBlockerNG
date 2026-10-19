"""The Docker Unbound of the end-to-end tests is given a port the test picked. Picking and binding are two steps, and
under load another process may take the port between them; Unbound then exits with "Address already in use". That is
the environment, not a verdict: a fresh pick is tried, a bounded number of times and for that outcome only."""

from __future__ import annotations

import itertools
import socket
from pathlib import Path

import pytest
from dot_helpers import PORT_PICKS, free_loopback_port, retry_on_taken_port
from frontend_helpers import FakeAuthoritative, FakeUnbound
from test_integration_unbound import (  # noqa: F401  (unbound: a fixture)
    AUTHORITATIVE,
    _start_unbound,
    first_needle_seen,
    unbound,
)


def test_a_picked_port_that_was_taken_is_picked_again() -> None:
    tried: list[int] = []
    ports = itertools.count(100)

    def attempt(port: int) -> str | None:
        tried.append(port)
        return f"started on {port}" if port >= 103 else None

    assert retry_on_taken_port(attempt, pick=lambda: next(ports)) == "started on 103"
    assert tried == [100, 101, 102, 103]


def test_a_port_that_was_not_taken_is_not_picked_again() -> None:
    tried: list[int] = []

    def attempt(port: int) -> int:
        tried.append(port)
        return port

    assert retry_on_taken_port(attempt, pick=itertools.count(100).__next__) == 100
    assert tried == [100]


def test_ports_that_are_always_taken_are_given_up_on_after_the_picks() -> None:
    tried: list[int] = []
    ports = itertools.count(100)

    def attempt(port: int) -> None:
        tried.append(port)

    with pytest.raises(RuntimeError, match="taken"):
        retry_on_taken_port(attempt, pick=lambda: next(ports))
    assert len(tried) == PORT_PICKS


def test_anything_but_a_taken_port_is_not_retried() -> None:
    tried: list[int] = []

    def attempt(port: int) -> int:
        tried.append(port)
        raise ValueError("not about the port")

    with pytest.raises(ValueError, match="not about the port"):
        retry_on_taken_port(attempt, pick=itertools.count(100).__next__)
    assert tried == [100]


def test_a_port_that_is_free_for_tcp_but_held_for_udp_is_not_the_port_unbound_gets() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as held_udp:
        held_udp.bind(("127.0.0.1", 0))
        held = held_udp.getsockname()[1]
        free = free_loopback_port()
        candidates = iter([held, held, free])
        assert free_loopback_port(pick=lambda: next(candidates)) == free


@pytest.mark.usefixtures("unbound")  # which builds the image
def test_unbound_that_exits_on_a_port_held_by_someone_else_is_reported_as_taken(tmp_path: Path) -> None:
    """Held for UDP and TCP, as another process would hold it, the port makes Unbound exit: "address already in use"."""
    authoritative = FakeAuthoritative(FakeUnbound(AUTHORITATIVE))
    try:
        with (
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp,
            socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp,
        ):
            udp.bind(("127.0.0.1", 0))
            tcp.bind(("127.0.0.1", udp.getsockname()[1]))
            assert _start_unbound(udp.getsockname()[1], authoritative, tmp_path, observer=False) is None
    finally:
        authoritative.close()


def test_a_port_that_is_free_for_udp_but_held_for_tcp_is_not_the_port_unbound_gets() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as held_tcp:
        held_tcp.bind(("127.0.0.1", 0))
        held = held_tcp.getsockname()[1]
        free = free_loopback_port()
        candidates = iter([held, held, free])
        assert free_loopback_port(pick=lambda: next(candidates)) == free


@pytest.mark.parametrize(
    "line",
    [
        "[1792405701] unbound[1:0] error: can't bind socket: Address already in use for 127.0.0.1 port 35260",
        "[1792407420] unbound[1:0] error: bind: address already in use",
    ],
    ids=["one socket, capitalised", "the other, lower case"],
)
def test_unbounds_two_spellings_of_a_taken_port_are_both_seen(line: str) -> None:
    needles = ("start of service", "address already in use")
    assert first_needle_seen(needles, ["notice: init module 0: iterator", line]) == "address already in use"
    assert first_needle_seen(needles, ["info: start of service (unbound 1.22)"]) == "start of service"
    assert first_needle_seen(needles, ["notice: init module 0: iterator"]) is None
