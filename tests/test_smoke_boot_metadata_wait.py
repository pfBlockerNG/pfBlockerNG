"""Issue #2242: boot readiness includes pfSense package metadata settlement."""

from __future__ import annotations

import subprocess
from typing import cast

import pytest

from tests.smoke import helpers


def test_wait_boot_complete_waits_for_boot_metadata_sentinel(monkeypatch: pytest.MonkeyPatch) -> None:
    sentinel_statuses = iter([1, 0])
    monotonic_values = iter([0.0, 0.0, 1.0, 2.0, 3.0])
    calls: list[tuple[str, ...]] = []

    class FakeVM:
        def ssh(self, *remote: str, timeout: float = 60.0) -> subprocess.CompletedProcess[str]:
            calls.append(remote)
            if remote == ("/bin/test", "-f", "/var/run/pfSense_version.rc"):
                return subprocess.CompletedProcess(remote, next(sentinel_statuses), "", "")
            return subprocess.CompletedProcess(remote, 0, "", "")

    monkeypatch.setattr(
        helpers,
        "php_eval",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, "<<BOOT>>0<<END>>", ""),
    )
    monkeypatch.setattr(helpers.time, "sleep", lambda _delay: None)
    monkeypatch.setattr(helpers.time, "monotonic", lambda: next(monotonic_values))

    helpers.wait_boot_complete(cast(helpers.SmokeVM, FakeVM()), timeout=3, delay=0)

    assert calls == [
        ("/bin/test", "-f", "/var/run/pfSense_version.rc"),
        ("/bin/test", "-f", "/var/run/pfSense_version.rc"),
    ]


def test_wait_boot_complete_plain_reboot_needs_only_platform_boot_flag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    boot_values = iter(["1", "0"])
    php_calls: list[str] = []

    class FakeVM:
        def ssh(self, *_remote: str, timeout: float = 60.0) -> subprocess.CompletedProcess[str]:
            raise AssertionError("plain reboot must not probe package metadata")

    def fake_php_eval(_vm: helpers.SmokeVM, snippet: str, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        php_calls.append(snippet)
        return subprocess.CompletedProcess([], 0, f"<<BOOT>>{next(boot_values)}<<END>>", "")

    monkeypatch.setattr(
        helpers,
        "php_eval",
        fake_php_eval,
    )
    monkeypatch.setattr(helpers.time, "sleep", lambda _delay: None)
    monkeypatch.setattr(helpers.time, "monotonic", lambda: 0.0)

    helpers.wait_boot_complete(
        cast(helpers.SmokeVM, FakeVM()),
        timeout=3,
        delay=0,
        require_pkg_metadata=False,
    )

    assert len(php_calls) == 2
    assert all("is_platform_booting" in snippet for snippet in php_calls)
