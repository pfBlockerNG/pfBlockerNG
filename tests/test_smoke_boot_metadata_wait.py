"""Issue #2242: boot readiness includes pfSense package metadata settlement.

Owner residual (2026-08-15 02:55): ``pfSense-upgrade -uf`` only publishes
``/var/run/pfSense_version.rc`` on SUCCESS. A finished-but-failed run leaves the
metadata job gone and the sentinel never written, so the old ``test -f`` probe
spun until the full 180s timeout instead of recognising "job exited, no
sentinel" as metadata FAILURE. The predicate now asks a single probe for one of
three words (``present``/``running``/``gone``) and returns on either
``present`` or ``gone`` -- only ``running`` keeps polling.
"""

from __future__ import annotations

import subprocess
from typing import cast

import pytest

from tests.smoke import helpers

_PROBE_ARGV = ("/bin/sh", "-c", helpers._METADATA_PROBE_CMD)


def test_wait_boot_complete_waits_for_boot_metadata_sentinel(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The metadata job is still running on the first probe; the sentinel
    appears by the second -- waits, no loud "metadata failed" line."""
    probe_words = iter(["running", "present"])
    calls: list[tuple[str, ...]] = []

    class FakeVM:
        def ssh(self, *remote: str, timeout: float = 60.0) -> subprocess.CompletedProcess[str]:
            calls.append(remote)
            if remote == _PROBE_ARGV:
                return subprocess.CompletedProcess(remote, 0, next(probe_words), "")
            return subprocess.CompletedProcess(remote, 1, "", "")

    monkeypatch.setattr(
        helpers,
        "php_eval",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, "<<BOOT>>0<<END>>", ""),
    )
    monkeypatch.setattr(helpers.time, "sleep", lambda _delay: None)

    helpers.wait_boot_complete(cast(helpers.SmokeVM, FakeVM()), timeout=2, delay=0)

    assert calls == [_PROBE_ARGV, _PROBE_ARGV]
    assert "PFB_BOOT_METADATA" not in capsys.readouterr().out


def test_wait_boot_complete_returns_when_metadata_job_exits_without_sentinel(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Issue #2242 owner residual 02:55: two probes see the job still running,
    the third sees it gone with no sentinel published -- must return (not
    time out) and print the one loud metadata-failure line."""
    probe_words = ["running", "running", "gone"]
    calls: list[tuple[str, ...]] = []

    class FakeVM:
        def __init__(self) -> None:
            self._n = 0

        def ssh(self, *remote: str, timeout: float = 60.0) -> subprocess.CompletedProcess[str]:
            calls.append(remote)
            # OLD-shape probe (pre-fix production code) never matches _PROBE_ARGV and
            # always reports a non-zero rc here, so the pre-fix code cannot return early
            # (its success test is bare `returncode == 0`) and instead spins to timeout --
            # the RED failure this fixture proves is "raise on timeout", not a StopIteration
            # or an argv-mismatch assertion error.
            if remote != _PROBE_ARGV:
                return subprocess.CompletedProcess(remote, 1, "", "")
            word = probe_words[min(self._n, len(probe_words) - 1)]
            self._n += 1
            return subprocess.CompletedProcess(remote, 0, word, "")

    monkeypatch.setattr(
        helpers,
        "php_eval",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, "<<BOOT>>0<<END>>", ""),
    )
    monkeypatch.setattr(helpers.time, "sleep", lambda _delay: None)

    helpers.wait_boot_complete(cast(helpers.SmokeVM, FakeVM()), timeout=2, delay=0)

    assert [c for c in calls if c == _PROBE_ARGV] == [_PROBE_ARGV] * 3
    printed = capsys.readouterr().out
    assert (
        "PFB_BOOT_METADATA sentinel=absent job=gone — pfSense metadata refresh exited without "
        "publishing /var/run/pfSense_version.rc (metadata FAILED, not still booting; issue #2242)"
    ) in printed


def test_wait_boot_complete_metadata_job_stuck_running_times_out(monkeypatch: pytest.MonkeyPatch) -> None:
    """The job never exits (always ``running``) -- the timeout path must still
    raise, not spin forever or silently return."""
    ticks = iter([0.0, 0.0] + [float(n) for n in range(1, 200)])

    def fake_monotonic() -> float:
        try:
            return next(ticks)
        except StopIteration:
            return 1000.0

    calls: list[tuple[str, ...]] = []

    class FakeVM:
        def ssh(self, *remote: str, timeout: float = 60.0) -> subprocess.CompletedProcess[str]:
            calls.append(remote)
            return subprocess.CompletedProcess(remote, 0, "running", "")

    monkeypatch.setattr(
        helpers,
        "php_eval",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, "<<BOOT>>0<<END>>", ""),
    )
    monkeypatch.setattr(helpers.time, "sleep", lambda _delay: None)
    monkeypatch.setattr(helpers.time, "monotonic", fake_monotonic)

    with pytest.raises(RuntimeError, match="did not settle"):
        helpers.wait_boot_complete(cast(helpers.SmokeVM, FakeVM()), timeout=3, delay=0)

    assert _PROBE_ARGV in calls


def test_wait_boot_complete_keeps_per_probe_cap_for_long_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    probe_timeouts: list[float] = []
    metadata_timeouts: list[float] = []

    class FakeVM:
        def ssh(self, *_remote: str, timeout: float = 60.0) -> subprocess.CompletedProcess[str]:
            metadata_timeouts.append(timeout)
            return subprocess.CompletedProcess([], 0, "present", "")

    def fake_php_eval(
        _vm: helpers.SmokeVM,
        _snippet: str,
        *,
        timeout: float,
    ) -> subprocess.CompletedProcess[str]:
        probe_timeouts.append(timeout)
        return subprocess.CompletedProcess([], 0, "<<BOOT>>0<<END>>", "")

    monkeypatch.setattr(helpers, "php_eval", fake_php_eval)
    monkeypatch.setattr(helpers.time, "monotonic", lambda: 0.0)

    helpers.wait_boot_complete(cast(helpers.SmokeVM, FakeVM()), timeout=31)

    assert probe_timeouts == [30.0]
    assert metadata_timeouts == [30.0]


def test_wait_boot_complete_nan_deadline_does_not_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        helpers,
        "php_eval",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("NaN deadline reached platform probe")),
    )
    monkeypatch.setattr(helpers.time, "monotonic", lambda: 0.0)

    with pytest.raises(RuntimeError, match="did not settle"):
        helpers.wait_boot_complete(cast(helpers.SmokeVM, object()), timeout=float("nan"))


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
