"""issue #2878 live-VM smoke: the bounded synchronous firewall-configuration reload.

``sync_package_pfblockerng()`` (``pfblockerng_apply.inc``) calls the new
``pfb_filter_reload_cmd()`` / ``pfb_filter_reload_exec()`` seam in place of the old
unbounded ``mwexec('/etc/rc.filter_configure_sync')``. The PHPUnit suite
(``tests/php/FilterReloadBoundTest.php``) proves the seam itself with deterministic
reload doubles; this module is the issue's OWN required live black-box verification:
a real appliance, a real ``/etc/rc.filter_configure_sync``, a real ``timeout(1)``.

WHAT THIS FILE AUTOMATES (issue #2878 "Verification" + "Escalation" sections):

* **Healthy row** — a real, supported filter-changing update pass (an ip_unlock-forced
  re-block over a settled IP alias, issue #519's trigger) reaches a finite terminal
  state well inside the budget, the pf table reflects the reload, and nothing is
  logged as ``TIMED OUT``.
* **Stalled row** — the REAL ``/etc/rc.filter_configure_sync`` is temporarily swapped
  for a double that ignores ``SIGTERM`` and never exits on its own (``trap '' TERM;
  exec sleep 300``, mirroring ``FilterReloadBoundTest::fakeReload('exec sleep N')``),
  with the shared #2851 operator budget shrunk to its 60s floor so the wait stays
  CI-sized. The pass must still return in bounded time (nowhere near the double's own
  300s, nowhere near the un-shrunk 1800s default), name the 124 expiry in BOTH the
  pfBlockerNG log and the error log, mark the pass pending
  (``/usr/local/etc/pfb_pending_changes``), leave no orphaned transient child (the
  double is a single process — no forked grandchild survives a ``--foreground`` kill),
  and leave the ``pfb_filter`` daemon in its documented (enabled ⇒ running) state —
  ordering is unchanged, so the daemon-management stage still runs after the timeout.

The real script is backed up before the swap and restored (and one settling reload
re-run) in a ``finally``, regardless of outcome, mirroring how other live-VM smoke
modules capture/restore config state (``config_get_state``/``config_restore_state``).

DESELECTED from the default ``python -m pytest`` (``--ignore=tests/smoke``). Run only
by the smoke workflow::

    python -m pytest tests/smoke -m smoke --override-ini="addopts="

Needs the booted ``smoke_vm`` fixture, the branch ``.pkg`` (``SMOKE_PKG``), and the
smoke deps; without them it skips cleanly.
"""

from __future__ import annotations

import os
import subprocess
import time
from collections.abc import Iterator

import pytest

from . import helpers as h
from .conftest import SmokeVM

pytestmark = pytest.mark.smoke

# The real pfSense reload script this seam wraps (pfblockerng_apply.inc's fallback
# default for the off-appliance injection point $pfb['filter_configure_sync']).
_RELOAD_SCRIPT = "/etc/rc.filter_configure_sync"
_RELOAD_SCRIPT_BACKUP = "/etc/rc.filter_configure_sync.pfbsmoke_orig"

# The ip_unlock sentinel (pfblockerng.inc $pfb['ip_unlock']) — writing it forces an
# unconditional re-block of every active alias (issue #519's mechanism), which is the
# simplest deterministic way to reach filter_configure=TRUE without depending on any
# feed actually changing content.
_IP_UNLOCK_PATH = "/tmp/ip_unlock"

# The single shared #2851 operator setting (General -> Advanced "Nested pass
# timeout"), floor 60s / ceiling 7200s (PFB_REENTRY_TIMEOUT_MIN/MAX). Shrinking it to
# its floor keeps the stalled-row wait CI-sized instead of the 1800s default.
_CFG_REENTRY_TIMEOUT = f"{h.CFG_GLOBAL}/pfb_reentry_timeout"
_STALL_BUDGET = "60"

# pfb_pending_changes_marker() default (pfblockerng.inc) — touched on a 124/-1 expiry
# so the next tick re-applies; never cleared by a healthy pass on its own.
_PENDING_MARKER = "/usr/local/etc/pfb_pending_changes"

_PFB_ERRLOG = f"{h.PFB_LOGDIR}/error.log"

# Generous salvage ceiling for the stalled row: budget(60s) + PFB_HOOK_KILL_GRACE(5s)
# + reload/CLI overhead. Its expiry means "stuck/environment", never behaviour —
# nowhere near the double's own 300s sleep or the un-shrunk 1800s default budget.
_STALL_SALVAGE_CEILING = 150.0
# Healthy-row ceiling: a real reload over one tiny alias finishes in a few seconds.
_HEALTHY_SALVAGE_CEILING = 90.0


@pytest.fixture(scope="module")
def deployed_vm(smoke_vm: SmokeVM) -> Iterator[SmokeVM]:
    """Deploy the branch .pkg once for the issue #2878 filter-reload-bound module.

    Pure IP-side (mirrors ``test_smoke_ip_recompute.py``'s minimal shape): the reload
    seam sits in the IP-scope path only, no DNSBL/DNS probe needed.
    """
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    try:
        yield smoke_vm
    finally:
        h.collect_host_diagnostics(smoke_vm)


def _settle_alias(vm: SmokeVM, aliasname: str, inert_ip: str) -> h.IpCase:
    """Inject + settle one tiny IP alias so ip_unlock has an active table to re-block."""
    feed = h.write_local_feed(vm, f"smoke_frb_{aliasname}_ip.txt", f"{inert_ip}\n")
    spec = h.IpCase(aliasname=aliasname, feed_url=feed, header=aliasname)
    h.inject(vm, spec)
    h.reload(vm, "update")
    assert h.wait_until(
        lambda: h.member_present(h.pfctl_table_members(vm, spec.alias), inert_ip),
        timeout=60.0,
        interval=2.0,
    ), f"settle pass did not populate {spec.alias} with {inert_ip}"
    return spec


def _write_ip_unlock(vm: SmokeVM, inert_ip: str, alias: str) -> None:
    """Write ``/tmp/ip_unlock`` with a valid ``ip,table`` row (pfb_unlock() format,
    issue #519's forced-re-block trigger — matches
    ``test_hooks_ip_changed_unlock_forced``'s construction)."""
    content = f"{inert_ip},{alias}\n"
    result = subprocess.run(
        vm.ssh_argv("tee", _IP_UNLOCK_PATH),
        input=content,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"_write_ip_unlock: failed to write {_IP_UNLOCK_PATH}: rc={result.returncode} {result.stderr!r}"
        )


def test_filter_reload_healthy_pass_reaches_finite_terminal_state(deployed_vm: SmokeVM) -> None:
    """A real, supported filter-changing update pass finishes bounded and the pf
    table reflects it — the issue's "Healthy row" (live-VM verification requirement,
    not covered by the PHPUnit doubles).

    Given a settled IP alias and an ip_unlock-forced re-block (issue #519's trigger,
    no feed content change needed), when the pass runs through the real
    ``/etc/rc.filter_configure_sync``, then it must complete well inside a generous
    ceiling, log no "TIMED OUT", and the pf alias table must still carry the IP —
    proof the REAL reload ran end-to-end through the new seam, not merely that the
    PHP process returned.
    """
    inert_ip = "203.0.113.50"  # RFC 5737 TEST-NET-3
    spec = _settle_alias(deployed_vm, "smokefrbhealthy", inert_ip)

    members = h.pfctl_table_members(deployed_vm, spec.alias)
    assert h.member_present(members, inert_ip), f"settle pass did not populate {spec.alias} with {inert_ip}: {members}"

    _write_ip_unlock(deployed_vm, inert_ip, spec.alias)

    started = time.monotonic()
    h.reload(deployed_vm, "update")
    elapsed = time.monotonic() - started

    assert elapsed < _HEALTHY_SALVAGE_CEILING, (
        f"stuck/environment: a healthy ip_unlock-forced reload took {elapsed:.1f}s"
    )

    log_tail = deployed_vm.ssh(f"/usr/bin/tail -n 80 {h.PFB_LOG} 2>/dev/null || true").stdout
    assert "TIMED OUT" not in log_tail, f"a healthy reload must never log a timeout: {log_tail}"

    members_after = h.pfctl_table_members(deployed_vm, spec.alias)
    assert h.member_present(members_after, inert_ip), (
        f"the ip_unlock-forced reload did not leave {inert_ip} in {spec.alias} "
        f"(finite terminal state not reached): {members_after}"
    )


@pytest.mark.timeout(180)
def test_filter_reload_stall_is_bounded_with_no_orphan(deployed_vm: SmokeVM) -> None:
    """A stalled ``/etc/rc.filter_configure_sync`` is bounded, named, marked pending,
    and leaves no orphaned transient child — the issue's "Stalled row" + hostile rows
    ("Reload script never returns", "Transient reload descendant ignores TERM",
    "Deadline expires after partial firewall mutation").

    The double (``trap '' TERM; exec sleep 300``) IGNORES SIGTERM and is a SINGLE
    process (``exec`` replaces the shell image — no forked grandchild), so only the
    ``-k`` grace's SIGKILL can end it and there is nothing left to orphan. The #2851
    budget is shrunk to its 60s floor so the wait stays CI-sized; the real script and
    budget are restored, and one real settling reload re-run, in ``finally``
    regardless of outcome.
    """
    inert_ip = "203.0.113.60"  # RFC 5737 TEST-NET-3, distinct from the healthy row
    orig_budget = h.config_get_state(deployed_vm, _CFG_REENTRY_TIMEOUT)
    backed_up = False
    try:
        h.config_set(deployed_vm, _CFG_REENTRY_TIMEOUT, _STALL_BUDGET)

        cp = deployed_vm.ssh("/bin/cp", "-p", _RELOAD_SCRIPT, _RELOAD_SCRIPT_BACKUP)
        assert cp.returncode == 0, f"failed to back up {_RELOAD_SCRIPT}: {cp.stderr!r}"
        backed_up = True

        stub = "#!/bin/sh\ntrap '' TERM\nexec sleep 300\n"
        write = subprocess.run(
            deployed_vm.ssh_argv("tee", _RELOAD_SCRIPT),
            input=stub,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert write.returncode == 0, f"failed to write the stalling double: {write.stderr!r}"
        chmod = deployed_vm.ssh("/bin/chmod", "755", _RELOAD_SCRIPT)
        assert chmod.returncode == 0, f"failed to chmod the stalling double: {chmod.stderr!r}"

        # Inject a NEW alias with the stub already in place. A second update of an
        # already-settled alias skips filter_configure (ip_unlock only pfctl-replaces).
        feed = h.write_local_feed(deployed_vm, "smoke_frb_smokefrbstall_ip.txt", f"{inert_ip}\n")
        spec = h.IpCase(aliasname="smokefrbstall", feed_url=feed, header="smokefrbstall")
        h.inject(deployed_vm, spec)

        deployed_vm.ssh("/bin/rm", "-f", _PENDING_MARKER)

        # Only lines written by this pass may satisfy the expiry assertion.
        lines_before = int(deployed_vm.ssh("/usr/bin/wc", "-l", h.PFB_LOG).stdout.split()[0])

        started = time.monotonic()
        # Same trigger as the healthy row: scope=both force=false trigger=cron.
        result = deployed_vm.ssh(
            h.PHP_BIN,
            h.PFB_CLI,
            "pfb_trigger",
            "scope=both",
            "force=false",
            "trigger=cron",
            timeout=_STALL_SALVAGE_CEILING + 30.0,
        )
        elapsed = time.monotonic() - started

        assert elapsed < _STALL_SALVAGE_CEILING, (
            f"stuck/environment: a {_STALL_BUDGET}s-budgeted reload took {elapsed:.1f}s "
            f"against a stub that sleeps 300s and ignores TERM"
        )
        # rc must stay observable, never masking the seam's own contract with a
        # CLI-level failure that looks unrelated.
        assert result.returncode in (0, 75), (
            f"pfb_trigger update returned an unexpected rc={result.returncode}: {result.stdout!r} {result.stderr!r}"
        )

        log_tail = deployed_vm.ssh("/usr/bin/tail", "-n", f"+{lines_before + 1}", h.PFB_LOG).stdout
        errlog_tail = deployed_vm.ssh(f"/usr/bin/tail -n 80 {_PFB_ERRLOG} 2>/dev/null || true").stdout
        assert "TIMED OUT" in log_tail, f"the expiry must be named in the pfBlockerNG log: {log_tail!r}"
        assert "TIMED OUT" in errlog_tail, f"the expiry must be named in the error log: {errlog_tail!r}"

        pending = deployed_vm.ssh("/bin/test", "-f", _PENDING_MARKER)
        assert pending.returncode == 0, (
            f"an expired reload must mark the pass pending ({_PENDING_MARKER} missing) so the next tick re-applies"
        )

        orphan_check = deployed_vm.ssh("/bin/ps", "-wax").stdout
        assert "sleep 300" not in orphan_check, (
            f"a TERM-ignoring transient reload descendant survived the bound as an orphan: {orphan_check}"
        )

        assert "filter daemon" in log_tail, (
            f"the filter-daemon management stage must still run after expiry: {log_tail!r}"
        )

    finally:
        if backed_up:
            restore = deployed_vm.ssh("/bin/cp", "-p", _RELOAD_SCRIPT_BACKUP, _RELOAD_SCRIPT)
            deployed_vm.ssh("/bin/rm", "-f", _RELOAD_SCRIPT_BACKUP)
            if restore.returncode != 0:
                raise RuntimeError(f"failed to restore {_RELOAD_SCRIPT}: {restore.stderr!r}")
        deployed_vm.ssh("/bin/rm", "-f", _IP_UNLOCK_PATH)
        h.config_restore_state(deployed_vm, _CFG_REENTRY_TIMEOUT, orig_budget)
        # Resettle with the REAL script so the guest isn't left with a stale pf
        # ruleset for whatever runs next (best-effort — never masks the result above).
        try:
            h.reload(deployed_vm, "update")
        except Exception as exc:  # noqa: BLE001 - best-effort teardown, never masks the test result
            print(f"[smoke] post-stall resettle reload failed (non-fatal): {exc!r}")
