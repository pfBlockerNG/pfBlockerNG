"""issue #1175 — feed-pass serialization smoke tests (live pfSense CE VM).

Feed passes are serialized by a cross-process flock (``pfb_feed_pass.lock``
under ``/var/db/pfblockerng``): every dispatch path funnels through
``pfblockerng_sync_cron()`` / ``sync_package_pfblockerng()``, whose entry guard
(``pfb_feed_pass_begin()``) skips the pass with a logged message when another
pass already holds the lock — instead of running two overlapping passes that
corrupt the shared recompute staging (``masterfile.new`` et al.).

These tests drive the REAL ``pfblockerng.php cron`` verb on the guest while the
lock is genuinely held by another on-box process (a real flock holder, not a
mock), pinning the end-to-end wiring the PHPUnit suite cannot reach
(``sync_package_pfblockerng()`` has no off-appliance driver — issue #993).

Dispatch:
    gh workflow run smoke.yml -f pytest_filter="feed_pass_lock"

Tests:
    test_cron_verb_skips_while_feed_pass_lock_held — second pass defers (rc=75) + logs
    test_cron_verb_proceeds_when_lock_free         — normal pass unaffected (rc=0)
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from . import helpers as h
from .conftest import SmokeVM

pytestmark = pytest.mark.smoke

_PHP = "/usr/local/bin/php"
_PFB_PHP = "/usr/local/www/pfblockerng/pfblockerng.php"
_PFB_LOG = "/var/log/pfblockerng/pfblockerng.log"

_HOLDER = "/tmp/pfb_smoke_lock_holder.php"
_READY = "/tmp/pfb_smoke_lock_ready"
_STOP = "/tmp/pfb_smoke_lock_stop"

# The two discriminating log lines (see pfb_feed_pass_begin() and
# pfblockerng_sync_cron()): the skip line appears ONLY on a refused pass, the
# CRON START banner ONLY on a proceeding one — each test asserts one present
# and the other absent, so neither negative assertion can pass vacuously.
_SKIP_LINE = "Feed pass [ cron ] skipped -- another pfBlockerNG feed pass is running"
_START_LINE = "CRON  PROCESS  START"

# The CLI contract for a deferred pass (5a19a2ef, issue #2945): pfb_feed_pass_exit_code()
# returns PFB_EXIT_LOCKED for a deferral, 0 for a completed pass and 1 for a failed one.
# The exact code is asserted, not "non-zero", so the three stay apart.
_EX_TEMPFAIL = 75
_DEFERRAL_MESSAGE = "pfBlockerNG feed pass deferred: feed-pass lock is held"

# Real on-box lock holder: acquires the SAME flock the funnels use, signals
# readiness, then waits for the stop file. Self-terminating (120 s deadline)
# so an orphaned holder can never wedge the box; the flock itself dies with
# the process regardless.
_HOLDER_PHP = f"""<?php
require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');
require_once('/usr/local/pkg/pfblockerng/pfblockerng_extra.inc');
pfb_global();
if (!pfb_feed_pass_acquire()) {{
    exit(2);
}}
touch('{_READY}');
for ($i = 0; $i < 1200 && !file_exists('{_STOP}'); $i++) {{
    usleep(100000);
}}
@unlink('{_READY}');
"""


@pytest.fixture(scope="module")
def deployed_vm(smoke_vm: SmokeVM) -> Iterator[SmokeVM]:
    """Deploy the branch .pkg once for this module."""
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    try:
        yield smoke_vm
    finally:
        h.collect_host_diagnostics(smoke_vm)


def _guest_file_exists(vm: SmokeVM, path: str) -> bool:
    return vm.ssh("test", "-f", path).returncode == 0


def _log_size(vm: SmokeVM) -> int:
    """Current byte size of the pfBlockerNG log (0 when absent)."""
    result = vm.ssh(f"[ -f {_PFB_LOG} ] && wc -c < {_PFB_LOG} || echo 0")
    assert result.returncode == 0, f"log size probe failed: rc={result.returncode} {result.stderr!r}"
    return int(result.stdout.strip())


def _log_delta(vm: SmokeVM, offset: int) -> str:
    """Log content appended after byte ``offset`` (whole log when it rotated shorter)."""
    result = vm.ssh(
        f"[ -f {_PFB_LOG} ] || exit 0; "
        f'if [ "$(wc -c < {_PFB_LOG})" -ge {offset} ]; then tail -c +{offset + 1} {_PFB_LOG}; '
        f"else cat {_PFB_LOG}; fi"
    )
    return result.stdout


def _stop_holder(vm: SmokeVM) -> None:
    """Signal the holder to exit and wait until it has released (ready file gone)."""
    vm.ssh("touch", _STOP)
    released = h.wait_until(lambda: not _guest_file_exists(vm, _READY), timeout=30.0)
    assert released, "lock holder did not exit within 30s of the stop signal"


def test_cron_verb_skips_while_feed_pass_lock_held(deployed_vm: SmokeVM) -> None:
    """Scenario: a feed pass is running (its process holds the feed-pass lock).

    Given another on-box process holds pfb_feed_pass.lock,
    When the cron verb is dispatched,
    Then it defers with EX_TEMPFAIL and says so on stderr, logs the skip line, and
    never starts the pass (no CRON START banner).
    """
    vm = deployed_vm
    h.wait_no_active_pfb_task(vm)

    vm.ssh(f"rm -f {_READY} {_STOP}; cat > {_HOLDER} << 'PFBEOF'\n{_HOLDER_PHP}\nPFBEOF")
    vm.ssh(f"nohup {_PHP} {_HOLDER} >/dev/null 2>&1 &")
    acquired = h.wait_until(lambda: _guest_file_exists(vm, _READY), timeout=30.0)
    assert acquired, "test setup: on-box holder never acquired the feed-pass lock"

    try:
        offset = _log_size(vm)
        run = vm.ssh(f"{_PHP} {_PFB_PHP} cron", timeout=120.0)
        assert run.returncode == _EX_TEMPFAIL, (
            f"a deferred pass must report EX_TEMPFAIL: expected {_EX_TEMPFAIL}, "
            f"got rc={run.returncode} stderr={run.stderr!r}"
        )
        assert _DEFERRAL_MESSAGE in run.stderr, (
            f"the deferral must name its reason on stderr: expected {_DEFERRAL_MESSAGE!r}, got {run.stderr!r}"
        )
        delta = _log_delta(vm, offset)
        assert _SKIP_LINE in delta, f"expected skip line {_SKIP_LINE!r} in log delta, got: {delta!r}"
        assert _START_LINE not in delta, f"pass must NOT start while the lock is held, log delta: {delta!r}"
    finally:
        _stop_holder(vm)


def test_cron_verb_proceeds_when_lock_free(deployed_vm: SmokeVM) -> None:
    """Scenario: no feed pass is running — serialization must not block normal work.

    Given the feed-pass lock is free,
    When the cron verb is dispatched,
    Then the pass starts (CRON START banner) and no skip line is logged.
    """
    vm = deployed_vm
    h.wait_no_active_pfb_task(vm)

    offset = _log_size(vm)
    run = vm.ssh(f"{_PHP} {_PFB_PHP} cron", timeout=240.0)
    assert run.returncode == 0, (
        f"a completed pass must report success, not a deferral or a failure: "
        f"expected 0, got rc={run.returncode} stderr={run.stderr!r}"
    )
    assert _DEFERRAL_MESSAGE not in run.stderr, f"a free lock must not report a deferral, stderr: {run.stderr!r}"
    delta = _log_delta(vm, offset)
    assert _START_LINE in delta, f"expected {_START_LINE!r} in log delta, got: {delta!r}"
    assert _SKIP_LINE not in delta, f"a free lock must not produce a skip, log delta: {delta!r}"
    h.wait_no_active_pfb_task(vm)
