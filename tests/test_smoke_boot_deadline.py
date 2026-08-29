"""Issue #2355: boot readiness work stays inside its advertised deadline."""

from __future__ import annotations

import subprocess
from typing import cast

import pytest

from tests.smoke import helpers


def test_wait_boot_complete_caps_platform_probe_and_sleep_to_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monotonic_values = iter([0.0, 0.0, 0.4, 1.0])
    probe_timeouts: list[float] = []
    sleeps: list[float] = []

    def fake_php_eval(
        _vm: helpers.SmokeVM,
        _snippet: str,
        *,
        timeout: float,
    ) -> subprocess.CompletedProcess[str]:
        probe_timeouts.append(timeout)
        return subprocess.CompletedProcess([], 0, "<<BOOT>>1<<END>>", "")

    monkeypatch.setattr(helpers, "php_eval", fake_php_eval)
    monkeypatch.setattr(helpers.time, "sleep", sleeps.append)
    monkeypatch.setattr(helpers.time, "monotonic", lambda: next(monotonic_values))

    with pytest.raises(RuntimeError, match="did not settle after 1s"):
        helpers.wait_boot_complete(cast(helpers.SmokeVM, object()), timeout=1, delay=7)

    assert probe_timeouts == [1.0]
    assert sleeps == pytest.approx([0.6])


def test_wait_boot_complete_caps_metadata_probe_to_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    monotonic_values = iter([0.0, 0.0, 0.25, 1.0])
    metadata_timeouts: list[float] = []
    sleeps: list[float] = []

    class FakeVM:
        def ssh(self, *_remote: str, timeout: float = 60.0) -> subprocess.CompletedProcess[str]:
            metadata_timeouts.append(timeout)
            return subprocess.CompletedProcess([], 1, "", "")

    monkeypatch.setattr(
        helpers,
        "php_eval",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, "<<BOOT>>0<<END>>", ""),
    )
    monkeypatch.setattr(helpers.time, "sleep", sleeps.append)
    monkeypatch.setattr(helpers.time, "monotonic", lambda: next(monotonic_values))

    with pytest.raises(RuntimeError, match="did not settle after 1s"):
        helpers.wait_boot_complete(cast(helpers.SmokeVM, FakeVM()), timeout=1, delay=7)

    assert metadata_timeouts == pytest.approx([0.75])
    assert sleeps == []


def test_wait_boot_complete_stops_when_platform_probe_spends_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    monotonic_values = iter([0.0, 0.0, 1.0])

    class FakeVM:
        def ssh(self, *_remote: str, timeout: float = 60.0) -> subprocess.CompletedProcess[str]:
            raise AssertionError("expired deadline reached metadata probe")

    monkeypatch.setattr(
        helpers,
        "php_eval",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, "<<BOOT>>0<<END>>", ""),
    )
    monkeypatch.setattr(
        helpers.time,
        "sleep",
        lambda _delay: (_ for _ in ()).throw(AssertionError("expired deadline reached sleep")),
    )
    monkeypatch.setattr(helpers.time, "monotonic", lambda: next(monotonic_values))

    with pytest.raises(RuntimeError, match="did not settle after 1s"):
        helpers.wait_boot_complete(cast(helpers.SmokeVM, FakeVM()), timeout=1, delay=7)
