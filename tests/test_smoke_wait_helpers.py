from __future__ import annotations

import threading
from collections.abc import Callable
from typing import cast
from urllib.request import urlopen

import pytest

from tests.smoke import helpers
from tests.smoke.conftest import _MockCallbackSink


def _answer() -> helpers.DnsAnswer:
    return helpers.DnsAnswer(rcode="NOERROR", records=["198.51.100.7"])


def test_wait_until_expiry_is_loud_environment_failure() -> None:
    with pytest.raises(RuntimeError, match="stuck/environment"):
        helpers.wait_until(lambda: False, timeout=0, interval=0)


def test_dns_probe_until_expiry_is_loud_environment_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(helpers, "dns_probe", lambda *args, **kwargs: _answer())
    with pytest.raises(RuntimeError, match="stuck/environment"):
        helpers.dns_probe_until(
            cast(helpers.SmokeVM, object()), "example.invalid", lambda answer: False, timeout=0, interval=0
        )


def test_dns_probe_client_until_expiry_is_loud_environment_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(helpers, "dns_probe_client", lambda *args, **kwargs: _answer())
    with pytest.raises(RuntimeError, match="stuck/environment"):
        helpers.dns_probe_client_until(
            cast(helpers.SmokeVM, object()), "example.invalid", lambda answer: False, timeout=0, interval=0
        )


def _request_callback(sink: _MockCallbackSink, path: str = "/reload") -> None:
    with urlopen(f"http://127.0.0.1:{sink.port}{path}", timeout=2.0):  # noqa: S310 - local test server
        pass


def test_callback_sink_wait_for_observes_existing_and_later_callbacks(monkeypatch: pytest.MonkeyPatch) -> None:
    sink = _MockCallbackSink()
    sink.start()
    waiter: threading.Thread | None = None
    try:
        _request_callback(sink)
        assert sink.wait_for(1, timeout=0.01)

        sink.clear()
        wait_entered = threading.Event()
        outcome: list[object] = []
        original_wait_for = sink._condition.wait_for

        def wrapped_wait_for(predicate: Callable[[], bool], timeout: float | None = None) -> bool:
            wait_entered.set()
            return original_wait_for(predicate, timeout=timeout)

        monkeypatch.setattr(sink._condition, "wait_for", wrapped_wait_for)

        def wait_for_callback() -> None:
            try:
                outcome.append(sink.wait_for(1, timeout=2.0))
            except BaseException as exc:  # noqa: BLE001 - propagate through assertion below
                outcome.append(exc)

        waiter = threading.Thread(target=wait_for_callback)
        waiter.start()
        assert wait_entered.wait(timeout=2.0), "waiter did not enter Condition.wait_for"
        _request_callback(sink, "/later")
        waiter.join(timeout=2.0)
        assert not waiter.is_alive(), "callback notification did not release waiter"
        assert outcome == [True]
    finally:
        if waiter is not None and waiter.is_alive():
            _request_callback(sink, "/release")
            waiter.join(timeout=2.0)
        sink.stop()


def test_callback_sink_wait_for_expiry_is_loud_environment_failure() -> None:
    sink = _MockCallbackSink()
    sink.start()
    try:
        with pytest.raises(RuntimeError, match="stuck/environment"):
            sink.wait_for(1, timeout=0)
    finally:
        sink.stop()
