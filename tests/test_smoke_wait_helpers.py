from __future__ import annotations

import threading
import time
from typing import cast

import pytest

from tests.smoke import helpers
from tests.smoke.conftest import CallbackRecord, _MockCallbackSink


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


def _record() -> CallbackRecord:
    return CallbackRecord(method="POST", path="/reload", form={}, query={})


def test_callback_sink_wait_for_observes_existing_and_later_callbacks() -> None:
    sink = _MockCallbackSink()
    sink.start()
    try:
        sink._callbacks.append(_record())
        assert sink.wait_for(1, timeout=0.01)

        sink.clear()

        def record_later() -> None:
            time.sleep(0.01)
            with sink._lock:
                sink._callbacks.append(_record())
                if hasattr(sink, "_condition"):
                    sink._condition.notify_all()

        thread = threading.Thread(target=record_later)
        thread.start()
        assert sink.wait_for(1, timeout=0.5)
        thread.join()
    finally:
        sink.stop()


def test_callback_sink_wait_for_expiry_is_loud_environment_failure() -> None:
    sink = _MockCallbackSink()
    sink.start()
    try:
        with pytest.raises(RuntimeError, match="stuck/environment"):
            sink.wait_for(1, timeout=0)
    finally:
        sink.stop()
