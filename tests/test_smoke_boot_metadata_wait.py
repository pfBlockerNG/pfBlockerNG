"""Issue #2242: boot readiness includes pfSense package metadata settlement."""

from __future__ import annotations

import subprocess
from typing import cast

import pytest

from tests.smoke import helpers


def test_wait_boot_complete_waits_for_boot_pkg_processes(monkeypatch: pytest.MonkeyPatch) -> None:
    process_outputs = iter(
        [
            "123 sh /bin/sh /etc/rc.update_pkg_metadata now\n456 sh /bin/sh /usr/local/libexec/pfSense-upgrade -uf\n",
            "",
        ]
    )
    calls: list[tuple[str, ...]] = []

    class FakeVM:
        def ssh(self, *remote: str, timeout: float = 60.0) -> subprocess.CompletedProcess[str]:
            calls.append(remote)
            return subprocess.CompletedProcess(remote, 0, next(process_outputs), "")

    monkeypatch.setattr(
        helpers,
        "php_eval",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, "<<BOOT>>0<<END>>", ""),
    )
    monkeypatch.setattr(helpers.time, "sleep", lambda _delay: None)

    helpers.wait_boot_complete(cast(helpers.SmokeVM, FakeVM()), delay=0)

    assert calls == [
        ("/bin/ps", "axww", "-o", "pid=", "-o", "comm=", "-o", "args="),
        ("/bin/ps", "axww", "-o", "pid=", "-o", "comm=", "-o", "args="),
    ]
