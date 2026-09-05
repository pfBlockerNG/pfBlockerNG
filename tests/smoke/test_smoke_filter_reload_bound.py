"""Firewall-configuration reload smoke: the DETACHED pass (owner directive
2026-09-05, superseding the issue #2878 bound).

``sync_package_pfblockerng()`` (``pfblockerng_apply.inc``) now fires
``/etc/rc.filter_configure_sync`` through ``pfb_filter_reload_exec()`` as a
detached, fire-and-forget child: no wait, no timeout kill. pfSense's reload is
uncontrollable and signals filterd asynchronously anyway — the script exiting
never meant the rules were live — so the pass neither waits on it nor judges
its outcome. The ONE failure pfBlockerNG owns is the launch itself. The
PHPUnit suite (``tests/php/FilterReloadBoundTest.php``) proves the seam with
deterministic doubles; this module is the live black-box verification on a
real appliance with the real ``/etc/rc.filter_configure_sync``.

ROWS:

* **Healthy row** — a real, supported filter-changing update pass (an
  ip_unlock-forced re-block over a settled IP alias, issue #519's trigger)
  finishes bounded, the pf table reflects the reload, and nothing is logged as
  ``TIMED OUT``.
* **Stalled row** — the real script is temporarily swapped for a double that
  ignores SIGTERM and never exits on its own (``trap '' TERM; exec sleep 300``).
  The pass must NOT be blocked by it: it completes, logs no ``TIMED OUT``,
  still runs the filter-daemon management stage, and does not mark the pass
  pending (the launch succeeded — the stalled reload is pfSense's own domain,
  not an orphan pfB owns). The double is reaped by its own pidfile in the
  teardown.
* **Launch-gate row** — the script made non-executable is the one owned
  failure: the pass finishes, marks itself pending
  (``/usr/local/etc/pfb_pending_changes``), and names the gate ("missing or
  not executable") in the error log.

The real script is backed up before each swap and restored (and one settling
reload re-run) in a ``finally``, regardless of outcome, mirroring how other
live-VM smoke modules capture/restore config state.

DESELECTED from the default ``python -m pytest`` (``--ignore=tests/smoke``).
Run only by the smoke workflow::

    python -m pytest tests/smoke -m smoke --override-ini="addopts="

Needs the booted ``smoke_vm`` fixture, the branch ``.pkg`` (``SMOKE_PKG``), and
the smoke deps; without them it skips cleanly.
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

# The real pfSense reload script this seam fires (pfblockerng_apply.inc's fallback
# default for the off-appliance injection point $pfb['filter_configure_sync']).
_RELOAD_SCRIPT = "/etc/rc.filter_configure_sync"
_RELOAD_SCRIPT_BACKUP = "/etc/rc.filter_configure_sync.pfbsmoke_orig"

# The ip_unlock sentinel (pfblockerng.inc $pfb['ip_unlock']) — writing it forces an
# unconditional re-block of every active alias (issue #519's mechanism), which is the
# simplest deterministic way to reach filter_configure=TRUE without depending on any
# feed actually changing content.
_IP_UNLOCK_PATH = "/tmp/ip_unlock"

# pfb_pending_changes_marker() default (pfblockerng.inc) — touched ONLY on a launch
# failure now (never by a healthy or merely-stalled detached reload).
_PENDING_MARKER = "/usr/local/etc/pfb_pending_changes"

_PFB_ERRLOG = f"{h.PFB_LOGDIR}/error.log"

# The stalled double's pidfile (the double records its own $$ pre-exec so the
# teardown can reap what pfSense now owns but the VM should not keep for 300s).
_STALL_PIDFILE = "/tmp/pfbsmoke_frb_stall.pid"

# Salvage ceilings: their expiry means "stuck/environment", never behaviour —
# nowhere near the double's own 300s sleep (the pass no longer waits on it).
_STALLED_SALVAGE_CEILING = 150.0
_HEALTHY_SALVAGE_CEILING = 90.0


@pytest.fixture(scope="module")
def deployed_vm(smoke_vm: SmokeVM) -> Iterator[SmokeVM]:
    """Deploy the branch .pkg once for the detached filter-reload smoke module.

    Pure IP-side (mirrors ``test_smoke_ip_recompute.py``'s minimal shape): the
    reload seam sits in the IP-scope path only, no DNSBL/DNS probe needed.
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


def _swap_reload_script(vm: SmokeVM, body: str, mode: str = "755") -> None:
    """Back up the real script and put ``body`` in its place with ``mode``."""
    cp = vm.ssh("/bin/cp", "-p", _RELOAD_SCRIPT, _RELOAD_SCRIPT_BACKUP)
    assert cp.returncode == 0, f"failed to back up {_RELOAD_SCRIPT}: {cp.stderr!r}"
    # The backup exists now, so ANY later failure must put the real script back:
    # `tee` truncates before it writes, and smoke_vm is session-scoped -- a wrecked
    # /etc/rc.filter_configure_sync would poison every later module on this VM.
    try:
        write = subprocess.run(
            vm.ssh_argv("tee", _RELOAD_SCRIPT),
            input=body,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert write.returncode == 0, f"failed to write the reload double: {write.stderr!r}"
        chmod = vm.ssh("/bin/chmod", mode, _RELOAD_SCRIPT)
        assert chmod.returncode == 0, f"failed to chmod the reload double: {chmod.stderr!r}"
    except BaseException:
        _restore_reload_script(vm)
        raise


def _restore_reload_script(vm: SmokeVM) -> None:
    restore = vm.ssh("/bin/cp", "-p", _RELOAD_SCRIPT_BACKUP, _RELOAD_SCRIPT)
    vm.ssh("/bin/rm", "-f", _RELOAD_SCRIPT_BACKUP)
    if restore.returncode != 0:
        raise RuntimeError(f"failed to restore {_RELOAD_SCRIPT}: {restore.stderr!r}")


def test_filter_reload_healthy_pass_reaches_finite_terminal_state(deployed_vm: SmokeVM) -> None:
    """A real, supported filter-changing update pass finishes bounded and the pf
    table reflects it — the healthy row for the detached reload."""
    inert_ip = "203.0.113.50"  # RFC 5737 TEST-NET-3
    spec = _settle_alias(deployed_vm, "smokefrbhealthy", inert_ip)

    _write_ip_unlock(deployed_vm, inert_ip, spec.alias)
    deployed_vm.ssh("/bin/rm", "-f", _PENDING_MARKER)

    started = time.monotonic()
    result = deployed_vm.ssh(
        h.PHP_BIN,
        h.PFB_CLI,
        "pfb_trigger",
        "scope=both",
        "force=false",
        "trigger=cron",
        timeout=_HEALTHY_SALVAGE_CEILING + 30.0,
    )
    elapsed = time.monotonic() - started

    assert result.returncode in (0, 75), (
        f"pfb_trigger update returned an unexpected rc={result.returncode}: {result.stdout!r} {result.stderr!r}"
    )
    assert elapsed < _HEALTHY_SALVAGE_CEILING, f"stuck/environment: a healthy detached pass took {elapsed:.1f}s"
    members_after = h.pfctl_table_members(deployed_vm, spec.alias)
    assert h.member_present(members_after, inert_ip), (
        f"the ip_unlock-forced reload did not leave {inert_ip} in {spec.alias} "
        f"(finite terminal state not reached): {members_after}"
    )
    deployed_vm.ssh("/bin/rm", "-f", _IP_UNLOCK_PATH, _PENDING_MARKER)


@pytest.mark.timeout(240)
def test_filter_reload_stall_does_not_block_the_pass(deployed_vm: SmokeVM) -> None:
    """A TERM-ignoring, never-exiting reload double must NOT block the pass.

    The reload is fired detached: the pass completes, logs no ``TIMED OUT``,
    still runs the filter-daemon management stage, and does not mark itself
    pending — the launch succeeded, and the stalled reload is pfSense's own
    domain (its outcome is not pfB's to wait for or judge).
    """
    inert_ip = "203.0.113.60"  # RFC 5737 TEST-NET-3, distinct from the healthy row
    backed_up = False
    try:
        stub = f"#!/bin/sh\necho $$ > {_STALL_PIDFILE}\ntrap '' TERM\nexec sleep 300\n"
        _swap_reload_script(deployed_vm, stub)
        backed_up = True

        # Inject a NEW alias with the stub already in place. A second update of an
        # already-settled alias skips filter_configure (ip_unlock only pfctl-replaces).
        feed = h.write_local_feed(deployed_vm, "smoke_frb_smokefrbstall_ip.txt", f"{inert_ip}\n")
        spec = h.IpCase(aliasname="smokefrbstall", feed_url=feed, header="smokefrbstall")
        h.inject(deployed_vm, spec)

        deployed_vm.ssh("/bin/rm", "-f", _PENDING_MARKER)

        # Only lines written by this pass may satisfy the assertions.
        lines_before = int(deployed_vm.ssh("/usr/bin/wc", "-l", h.PFB_LOG).stdout.split()[0])

        started = time.monotonic()
        result = deployed_vm.ssh(
            h.PHP_BIN,
            h.PFB_CLI,
            "pfb_trigger",
            "scope=both",
            "force=false",
            "trigger=cron",
            timeout=_STALLED_SALVAGE_CEILING + 30.0,
        )
        elapsed = time.monotonic() - started

        assert result.returncode in (0, 75), (
            f"pfb_trigger update returned an unexpected rc={result.returncode}: {result.stdout!r} {result.stderr!r}"
        )
        assert elapsed < _STALLED_SALVAGE_CEILING, (
            f"stuck/environment: the pass blocked {elapsed:.1f}s on a detached double that sleeps 300s and ignores TERM"
        )

        log_tail = deployed_vm.ssh("/usr/bin/tail", "-n", f"+{lines_before + 1}", h.PFB_LOG).stdout
        assert "TIMED OUT" not in log_tail, f"a detached reload must never surface an expiry: {log_tail!r}"
        assert "filter daemon" in log_tail, (
            f"the filter-daemon management stage must still run after the detached fire: {log_tail!r}"
        )

        pending = deployed_vm.ssh("/bin/test", "-f", _PENDING_MARKER)
        assert pending.returncode != 0, (
            f"a launched (merely stalled) reload must NOT mark the pass pending ({_PENDING_MARKER} exists)"
        )

    finally:
        if backed_up:
            _restore_reload_script(deployed_vm)
        deployed_vm.ssh(
            "/bin/sh",
            "-c",
            f"[ -f {_STALL_PIDFILE} ] && kill -9 $(cat {_STALL_PIDFILE}) 2>/dev/null; " + f"rm -f {_STALL_PIDFILE}",
        )
        deployed_vm.ssh("/bin/rm", "-f", _IP_UNLOCK_PATH)
        # Resettle with the REAL script so the guest isn't left with a stale pf
        # ruleset for whatever runs next (best-effort — never masks the result above).
        try:
            h.reload(deployed_vm, "update")
        except Exception as exc:  # noqa: BLE001 - best-effort teardown, never masks the test result
            print(f"[smoke] post-stall resettle reload failed (non-fatal): {exc!r}")


@pytest.mark.timeout(240)
def test_filter_reload_launch_gate_marks_pending_and_names_itself(deployed_vm: SmokeVM) -> None:
    """A non-executable reload script is the one owned failure: the pass still
    completes (nothing blocks), marks itself pending so the next tick re-applies,
    and names the gate in the error log."""
    inert_ip = "203.0.113.70"  # RFC 5737 TEST-NET-3, distinct from the other rows
    backed_up = False
    try:
        # 0644: no execute bit anywhere, so the gate holds for root too.
        _swap_reload_script(deployed_vm, "#!/bin/sh\nexit 0\n", mode="644")
        backed_up = True

        feed = h.write_local_feed(deployed_vm, "smoke_frb_smokefrbgate_ip.txt", f"{inert_ip}\n")
        spec = h.IpCase(aliasname="smokefrbgate", feed_url=feed, header="smokefrbgate")
        h.inject(deployed_vm, spec)

        deployed_vm.ssh("/bin/rm", "-f", _PENDING_MARKER)

        lines_before = int(deployed_vm.ssh("/usr/bin/wc", "-l", h.PFB_LOG).stdout.split()[0])

        started = time.monotonic()
        result = deployed_vm.ssh(
            h.PHP_BIN,
            h.PFB_CLI,
            "pfb_trigger",
            "scope=both",
            "force=false",
            "trigger=cron",
            timeout=_STALLED_SALVAGE_CEILING + 30.0,
        )
        elapsed = time.monotonic() - started

        assert result.returncode in (0, 75), (
            f"pfb_trigger update returned an unexpected rc={result.returncode}: {result.stdout!r} {result.stderr!r}"
        )
        assert elapsed < _STALLED_SALVAGE_CEILING, (
            f"stuck/environment: the launch-gate pass took {elapsed:.1f}s — nothing should block on a gate refusal"
        )

        log_tail = deployed_vm.ssh("/usr/bin/tail", "-n", f"+{lines_before + 1}", h.PFB_LOG).stdout
        assert "missing or not executable" in log_tail, (
            f"the launch gate must name itself in the pfBlockerNG log: {log_tail!r}"
        )
        errlog_tail = deployed_vm.ssh(f"/usr/bin/tail -n 80 {_PFB_ERRLOG} 2>/dev/null || true").stdout
        assert "missing or not executable" in errlog_tail, (
            f"the launch gate must name itself in the error log: {errlog_tail!r}"
        )

        pending = deployed_vm.ssh("/bin/test", "-f", _PENDING_MARKER)
        assert pending.returncode == 0, (
            f"a failed reload launch must mark the pass pending ({_PENDING_MARKER} missing) so the next tick re-applies"
        )

    finally:
        if backed_up:
            _restore_reload_script(deployed_vm)
        deployed_vm.ssh("/bin/rm", "-f", _IP_UNLOCK_PATH, _PENDING_MARKER)
        try:
            h.reload(deployed_vm, "update")
        except Exception as exc:  # noqa: BLE001 - best-effort teardown, never masks the test result
            print(f"[smoke] post-gate resettle reload failed (non-fatal): {exc!r}")
