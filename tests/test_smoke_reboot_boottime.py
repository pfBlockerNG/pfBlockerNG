"""Issue #738 finding F4 — ``reboot_vm`` must PROVE the guest actually rebooted.

``tests/smoke/helpers.reboot_vm`` replaced the old ``kern.boottime``-change POLL with a fixed
settle sleep (see ``_REBOOT_SETTLE_SECS``): if shutdown outlasts that settle on a slow host, the
still-up PRE-reboot sshd answers the readiness gate as "ready", and every downstream assertion
(the reboot-persistence tests in ``tests/smoke/test_smoke_boot_reload.py`` and
``tests/smoke/test_smoke_tick.py``) silently runs against stale pre-reboot state. The fix restores
proof WITHOUT restoring the poll: a single ``kern.boottime`` read before the reboot and a single
read after the full readiness gate, compared by ``_assert_boottime_advanced``.

This module pins that PURE comparison seam off-VM (no VM I/O, no network) — it lives under
``tests/`` (NOT ``tests/smoke/``) so it runs in the default suite. Importing
``tests.smoke.helpers`` itself needs no VM (its own module docstring guarantees import-safety;
mirrors the precedent in ``tests/test_smoke_diag_redaction.py``).
"""

from __future__ import annotations

import pytest

from tests.smoke.helpers import _assert_boottime_advanced

_BEFORE = "{ sec = 1751500000, usec = 123456 }"
_AFTER = "{ sec = 1751500090, usec = 654321 }"


def test_assert_boottime_advanced_passes_when_value_changed() -> None:
    """Given a kern.boottime reading that DIFFERS before vs. after the reboot
    When _assert_boottime_advanced runs
    Then it does not raise — this is the real-reboot case.
    """
    _assert_boottime_advanced(_BEFORE, _AFTER)  # must not raise


def test_assert_boottime_advanced_raises_when_value_unchanged() -> None:
    """LOAD-BEARING: an unchanged kern.boottime means the readiness gate answered on the
    PRE-reboot instance (the guest never actually went down and back up).

    Given the same kern.boottime reading before AND after
    When _assert_boottime_advanced runs
    Then it raises AssertionError naming BOTH the before and after value, so a maintainer never
         has to guess which side is stale.
    """
    with pytest.raises(AssertionError) as exc_info:
        _assert_boottime_advanced(_BEFORE, _BEFORE)
    message = str(exc_info.value)
    assert _BEFORE in message, f"expected the unchanged value {_BEFORE!r} in the message, got: {message!r}"
    assert "never rebooted" in message


def test_assert_boottime_advanced_raises_when_before_is_empty() -> None:
    """Given an EMPTY pre-reboot reading (the sysctl read itself failed)
    When _assert_boottime_advanced runs
    Then it raises AssertionError naming the BEFORE side as the empty one — never silently
         treats a failed read as "changed".
    """
    with pytest.raises(AssertionError) as exc_info:
        _assert_boottime_advanced("", _AFTER)
    message = str(exc_info.value)
    assert "BEFORE" in message, f"expected the message to name the empty BEFORE side, got: {message!r}"


def test_assert_boottime_advanced_raises_when_after_is_empty() -> None:
    """Given an EMPTY post-reboot reading (the sysctl read itself failed)
    When _assert_boottime_advanced runs
    Then it raises AssertionError naming the AFTER side as the empty one.
    """
    with pytest.raises(AssertionError) as exc_info:
        _assert_boottime_advanced(_BEFORE, "")
    message = str(exc_info.value)
    assert "AFTER" in message, f"expected the message to name the empty AFTER side, got: {message!r}"


def test_assert_boottime_advanced_strips_whitespace_before_comparing() -> None:
    """Given the same value but with SSH-transport-typical trailing newline/whitespace noise on
         one side
    When _assert_boottime_advanced runs
    Then it still detects the values as unchanged (whitespace alone must not read as "advanced").
    """
    with pytest.raises(AssertionError):
        _assert_boottime_advanced(_BEFORE, f"{_BEFORE}\n")
