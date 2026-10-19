"""The Docker Unbound of the end-to-end tests is given a port the test picked. Picking and binding are two steps, and
under load another process may take the port between them; Unbound then exits with "Address already in use". That is
the environment, not a verdict: a fresh pick is tried, a bounded number of times and for that outcome only."""

from __future__ import annotations

import itertools
import socket

import pytest
from dot_helpers import PORT_PICKS, free_loopback_port, retry_on_taken_port


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
