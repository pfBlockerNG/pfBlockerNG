"""ADR-43 Phase 4 — Due-ledger trigger-tick smoke tests.

These tests exercise the tick verb and the due-ledger on a LIVE pfSense CE VM
(ADR-04 harness). They are authored in Phase 4 but DISPATCHED in Phase 7 as
part of the full smoke fan-out.

Dispatch (when ready):
    gh workflow run smoke.yml -f pytest_marker="tick"

Tests:
    test_tick_dispatches_due_feed     — tick fires a due feed (ledger past)
    test_tick_skips_non_due_feed      — tick skips a feed whose next_due is future
    test_tick_wiped_ledger_jittered   — wiped ledger gives due-now but jittered next_due
    test_tick_reboot_persists_ledger  — clean reboot keeps the schedule (ledger restored)
"""

import json

import pytest

from . import helpers as h

# Module mark: 'tick' on every test. 'smoke' is applied PER-TEST (not module-wide)
# so the reboot test — which reboots the shared session VM — carries 'reboot' but
# NOT 'smoke', keeping it out of the -m smoke run (see the 'reboot' marker rationale
# in pyproject.toml; mirrors test_smoke_boot_reload.py).
pytestmark = [pytest.mark.tick]


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

LEDGER_PATH = "/var/db/pfblockerng/pfb_due_ledger.json"
_PHP = "/usr/local/bin/php"
_PFB_PHP = "/usr/local/www/pfblockerng/pfblockerng.php"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _read_ledger(vm) -> dict:
    """Return the parsed ledger as a dict (empty on absent/corrupt)."""
    raw, _, _ = vm.ssh(f"/bin/sh -c 'cat {LEDGER_PATH} 2>/dev/null || echo {{}}'")
    try:
        return json.loads(raw.strip()) if raw.strip() else {}
    except json.JSONDecodeError:
        return {}


def _write_ledger_entry(vm, job_key: str, last_run: int, next_due: int, jitter: int = 0) -> None:
    """Merge one entry into the on-box ledger via a small Python snippet."""
    # Build the JSON snippet inline (no shell escaping needed beyond basic quoting).
    entry_json = json.dumps({"last_run": last_run, "next_due": next_due, "jitter": jitter})
    script = (
        "import json, os; "
        f"p='{LEDGER_PATH}'; "
        "d=json.load(open(p)) if os.path.exists(p) else {}; "
        f"d['{job_key}']={entry_json}; "
        "open(p,'w').write(json.dumps(d))"
    )
    vm.ssh(f"/usr/local/bin/python3 -c {json.dumps(script)}")


def _run_tick(vm) -> str:
    """Fire one tick synchronously and return its combined stdout+stderr."""
    out, _, _ = vm.ssh(f"{_PHP} {_PFB_PHP} tick 2>&1")
    return out


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.smoke
@pytest.mark.tick
def test_tick_dispatches_due_feed(smoke_vm):
    """Tick fires a due feed sync when the cron ledger entry is past.

    Scenario:
        Background: pfBlockerNG installed with at least one enabled feed.
            Given the 'cron' ledger entry has next_due in the past.
            When pfblockerng.php tick runs.
            Then the log contains 'Tick: dispatching feed cron.'
            And  the 'cron' ledger entry's next_due is updated to the future.
    """
    vm = smoke_vm

    now_ts = int(vm.ssh("date +%s")[0].strip())

    # Given: force cron past.
    _write_ledger_entry(vm, "cron", now_ts - 90000, now_ts - 1)

    before = _read_ledger(vm)
    assert before.get("cron", {}).get("next_due", 0) < now_ts, (
        f"before: cron next_due should be in the past; ledger={before}"
    )

    # When: tick fires.
    tick_out = _run_tick(vm)

    # Then: dispatch log line present.
    assert "Tick: dispatching feed cron" in tick_out, f"expected dispatch log line; tick output:\n{tick_out}"

    # Poll until mark_ran has persisted the updated next_due (VM clock as reference).
    assert h.wait_until(
        lambda: _read_ledger(vm).get("cron", {}).get("next_due", 0) > now_ts,
        timeout=30,
        interval=2,
    ), f"after: cron next_due should be in the future;\n  ledger={_read_ledger(vm)}, now_ts={now_ts}"


@pytest.mark.smoke
@pytest.mark.tick
def test_tick_skips_non_due_feed(smoke_vm):
    """Tick does NOT fire a feed sync when cron next_due is in the future.

    Scenario:
        Background: pfBlockerNG installed.
            Given the 'cron' ledger entry has next_due = now + 1 hour.
            When pfblockerng.php tick runs.
            Then the log does NOT contain 'Tick: dispatching feed cron.'
    """
    vm = smoke_vm

    now_ts = int(vm.ssh("date +%s")[0].strip())
    future = now_ts + 3600

    _write_ledger_entry(vm, "cron", now_ts - 86400, future)

    tick_out = _run_tick(vm)

    assert "Tick: dispatching feed cron" not in tick_out, (
        f"expected no dispatch (not yet due); tick output:\n{tick_out}"
    )


@pytest.mark.smoke
@pytest.mark.tick
def test_tick_wiped_ledger_jittered(smoke_vm):
    """After the ledger is wiped, the tick runs jobs but schedules them jittered.

    Scenario:
        Background: pfBlockerNG installed.
            Given the ledger file is deleted (RAM-disk reboot simulation).
            When pfblockerng.php tick runs.
            Then all jobs run (due-now after absent ledger).
            And  the 'dcc' next_due has non-zero jitter (not exactly last_run+86400).
    """
    vm = smoke_vm

    # Wipe the ledger.
    vm.ssh(f"rm -f {LEDGER_PATH}")

    # Tick — all jobs are due (absent ledger ⇒ due-now).
    _run_tick(vm)

    # Poll until mark_ran has persisted the dcc entry.
    assert h.wait_until(lambda: "dcc" in _read_ledger(vm), timeout=30, interval=2), (
        f"dcc ledger entry missing after wiped-ledger tick; ledger={_read_ledger(vm)}"
    )
    ledger = _read_ledger(vm)

    # dcc should have run and have a non-zero jitter.
    assert "dcc" in ledger, f"dcc ledger entry missing after wiped-ledger tick; ledger={ledger}"
    now_ts = int(vm.ssh("date +%s")[0].strip())
    no_jitter_next_due = ledger["dcc"]["last_run"] + 86400
    actual_next = ledger["dcc"]["next_due"]
    assert actual_next != no_jitter_next_due, (
        f"dcc next_due should differ from last_run+86400 (jitter expected);\n"
        f"  next_due={actual_next} last_run={ledger['dcc']['last_run']} "
        f"no-jitter={no_jitter_next_due}"
    )
    assert actual_next > now_ts, f"dcc next_due should be in the future; got {actual_next} now={now_ts}"


@pytest.mark.reboot
@pytest.mark.tick
def test_tick_reboot_persists_ledger(smoke_vm):
    """A clean reboot keeps the due-ledger (restored via #468 earlyshellcmd).

    Scenario:
        Background: pfBlockerNG installed with MFS /var (use_mfs_tmpvar).
            Given the ledger has a future cron next_due.
            When the VM reboots cleanly.
            Then the ledger is restored.
            And  the cron next_due is still in the future (no spurious dispatch).
    """
    vm = smoke_vm

    now_ts = int(vm.ssh("date +%s")[0].strip())
    future = now_ts + 7200  # 2 hours out

    _write_ledger_entry(vm, "cron", now_ts, future)

    # Reboot.
    vm.reboot()

    # After reboot: verify ledger was restored.
    after = _read_ledger(vm)
    assert "cron" in after, f"cron ledger entry missing after reboot; ledger={after}"
    assert after["cron"]["next_due"] == future, (
        f"cron next_due changed across reboot;\n  before={future} after={after['cron']['next_due']}"
    )
