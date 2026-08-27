"""``unblock_egress`` must NEVER raise — it heads teardown ``finally`` blocks.

Several smoke-module teardowns call ``helpers.unblock_egress()`` as the first statement
of a ``finally:`` block, ahead of must-run cleanup (the ramdisk revert + reboot of
issue #765, ``clear_dnsbl_settings``, diagnostics collection). ``check=False`` on its
``subprocess.run`` calls only suppresses a nonzero exit — ``TimeoutExpired`` would still
raise, abort the whole block, and silently skip that cleanup (residual finding from the
PR #772 adversarial review). This module pins the never-raises contract off-VM (no VM
I/O; ``tests.smoke.helpers`` is import-safe — precedent: ``test_smoke_reboot_boottime``).
"""

from __future__ import annotations

import subprocess

import pytest

from tests.smoke import helpers


def test_unblock_egress_swallows_and_reports_a_subprocess_timeout(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Given SMOKE_BLOCK_EGRESS is set and iptables hangs (TimeoutExpired)
    When unblock_egress runs
    Then it does not raise — the caller's remaining cleanup survives —
    And the failure is reported on stdout, never swallowed silently.
    """
    monkeypatch.setenv("SMOKE_BLOCK_EGRESS", "1")

    def raise_timeout(argv: list[str], **kwargs: object) -> None:
        raise subprocess.TimeoutExpired(cmd=argv, timeout=30)

    monkeypatch.setattr(helpers.subprocess, "run", raise_timeout)

    helpers.unblock_egress()  # must not raise

    assert "unblock_egress failed (non-fatal)" in capsys.readouterr().out


def test_unblock_egress_runs_both_iptables_commands_when_enabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Given SMOKE_BLOCK_EGRESS is set and iptables behaves
    When unblock_egress runs
    Then both restore commands execute (policy ACCEPT, then flush) — the guard
    must not change the happy path.
    """
    monkeypatch.setenv("SMOKE_BLOCK_EGRESS", "1")
    calls: list[list[str]] = []
    monkeypatch.setattr(helpers.subprocess, "run", lambda argv, **kw: calls.append(argv))

    helpers.unblock_egress()

    assert [argv[-2:] for argv in calls] == [["OUTPUT", "ACCEPT"], ["-F", "OUTPUT"]]


def test_unblock_egress_is_a_noop_without_the_env_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Given SMOKE_BLOCK_EGRESS is unset (a local dev run)
    When unblock_egress runs
    Then it touches nothing — the dev machine's firewall is never modified.
    """
    monkeypatch.delenv("SMOKE_BLOCK_EGRESS", raising=False)
    monkeypatch.setattr(helpers.subprocess, "run", lambda argv, **kw: pytest.fail(f"unexpected subprocess.run: {argv}"))

    helpers.unblock_egress()
