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
