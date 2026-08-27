"""Issue #2458: boot readiness must not treat a not-yet-started metadata job as done.

Issue #2242 taught ``wait_boot_complete`` that ``pfSense-upgrade -uf`` only
publishes ``/var/run/pfSense_version.rc`` on SUCCESS, so a finished-but-failed
run leaves the sentinel absent forever. The fix returned on ``gone`` -- which
also matches the FIRST probe of a perfectly healthy boot, because
``is_platform_booting()`` can clear seconds BEFORE ``rc.update_pkg_metadata``
starts (#2242 measured ABI 15 with no metadata process at 10:16:37Z and ABI 16
with the job active at 10:17:03Z). Callers then ran ``pkg add`` straight
through the ABI flip window.

``gone`` is therefore not a verdict on its own: it means "job not started yet"
until a ``running`` probe has been seen, and "job died without the sentinel"
after one. The waiter keeps polling in the first case and RAISES in the second;
only ``present`` is success.
"""

from __future__ import annotations

import subprocess
from typing import cast

import pytest

from tests.smoke import helpers

_PROBE_ARGV = ("/bin/sh", "-c", helpers._METADATA_PROBE_CMD)


def test_wait_boot_complete_waits_for_boot_metadata_sentinel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The metadata job is still running on the first probe; the sentinel
    appears by the second -- the waiter polls again rather than giving up."""
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


def test_wait_boot_complete_keeps_polling_when_first_probe_finds_no_metadata_job(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Issue #2458: ``gone`` on the FIRST probe means rc.update_pkg_metadata has
    not started yet, not that it finished. The waiter must keep polling, and a
    job that never appears must end the wait by RAISING, never by returning and
    letting callers pkg-add through the ABI flip window."""
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
            if remote != _PROBE_ARGV:
                return subprocess.CompletedProcess(remote, 1, "", "")
            return subprocess.CompletedProcess(remote, 0, "gone", "")

    monkeypatch.setattr(
        helpers,
        "php_eval",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, "<<BOOT>>0<<END>>", ""),
    )
    monkeypatch.setattr(helpers.time, "sleep", lambda _delay: None)
    monkeypatch.setattr(helpers.time, "monotonic", fake_monotonic)

    with pytest.raises(RuntimeError, match=r"sentinel /var/run/pfSense_version\.rc was not observed"):
        helpers.wait_boot_complete(cast(helpers.SmokeVM, FakeVM()), timeout=10, delay=0)

    assert len([c for c in calls if c == _PROBE_ARGV]) >= 2


def test_wait_boot_complete_accepts_a_metadata_job_that_starts_late(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Issue #2458: the #2242 timestamps (absent at 10:16:37Z, active at
    10:17:03Z) are the NORMAL boot, so ``gone`` then ``running`` then
    ``present`` must succeed quietly -- a waiter that treats ``gone`` as
    terminal fails closed on every healthy boot."""
    probe_words = iter(["gone", "running", "present"])
    calls: list[tuple[str, ...]] = []

    class FakeVM:
        def ssh(self, *remote: str, timeout: float = 60.0) -> subprocess.CompletedProcess[str]:
            calls.append(remote)
            if remote != _PROBE_ARGV:
                return subprocess.CompletedProcess(remote, 1, "", "")
            return subprocess.CompletedProcess(remote, 0, next(probe_words), "")

    monkeypatch.setattr(
        helpers,
        "php_eval",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, "<<BOOT>>0<<END>>", ""),
    )
    monkeypatch.setattr(helpers.time, "sleep", lambda _delay: None)

    helpers.wait_boot_complete(cast(helpers.SmokeVM, FakeVM()), timeout=5, delay=0)

    assert [c for c in calls if c == _PROBE_ARGV] == [_PROBE_ARGV] * 3


def test_wait_boot_complete_raises_when_metadata_job_exits_without_sentinel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Issue #2458 (replaces the #2242-era row that pinned the fail-open, which
    required ``running, running, gone`` to RETURN): once the job has been seen
    running, ``gone`` with no sentinel is a FAILED metadata refresh. Returning
    there let ``pkg add`` / the artifact ABI sample / ``shutdown -p`` proceed
    against a box whose pkg ABI was mid-rewrite, so it must raise."""
    probe_words = ["running", "running", "gone"]
    calls: list[tuple[str, ...]] = []

    class FakeVM:
        def __init__(self) -> None:
            self._n = 0

        def ssh(self, *remote: str, timeout: float = 60.0) -> subprocess.CompletedProcess[str]:
            calls.append(remote)
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

    with pytest.raises(RuntimeError, match="metadata refresh"):
        helpers.wait_boot_complete(cast(helpers.SmokeVM, FakeVM()), timeout=5, delay=0)

    assert [c for c in calls if c == _PROBE_ARGV] == [_PROBE_ARGV] * 3


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

    with pytest.raises(RuntimeError, match=r"sentinel /var/run/pfSense_version\.rc was not observed"):
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

    with pytest.raises(RuntimeError, match=r"last returned '\?' \(expected '0'\)"):
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
