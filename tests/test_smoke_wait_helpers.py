from __future__ import annotations

import threading
from collections.abc import Callable
from typing import cast
from urllib.error import URLError
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
    try:
        with urlopen(f"http://127.0.0.1:{sink.port}{path}", timeout=2.0):  # noqa: S310 - local test server
            pass
    except (OSError, URLError) as exc:
        raise RuntimeError(f"stuck/environment: callback request {path} did not complete") from exc


def _wait_event(event: threading.Event, label: str) -> None:
    if not event.wait(timeout=2.0):
        raise RuntimeError(f"stuck/environment: {label} event was not observed before salvage cap")


def _join_thread(thread: threading.Thread, label: str) -> None:
    thread.join(timeout=2.0)
    if thread.is_alive():
        raise RuntimeError(f"stuck/environment: {label} did not terminate before salvage cap")


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
        _wait_event(wait_entered, "waiter-entry")
        _request_callback(sink, "/later")
        _join_thread(waiter, "callback waiter")
        assert outcome == [True]
    finally:
        if waiter is not None and waiter.is_alive():
            try:
                _request_callback(sink, "/release")
            finally:
                _join_thread(waiter, "callback waiter cleanup")
        sink.stop()


def test_callback_sink_wait_for_expiry_is_loud_environment_failure() -> None:
    sink = _MockCallbackSink()
    sink.start()
    try:
        with pytest.raises(RuntimeError, match="stuck/environment"):
            sink.wait_for(1, timeout=0)
    finally:
        sink.stop()
