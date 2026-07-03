"""Live-VM smoke for DNSBL runtime control via the local command channel (PFBL-03).

DNSBL runtime control (disable / enable / addbypass / removebypass) is driven by a
root-only CLI — ``pfblockerng dnsbl-control …`` (the ``dnsbl-control`` action of the
package shell script, forwarding to ``pfblockerng.php``). The PHP writer validates the
command and atomically publishes a JSON record to the chroot channel
``/var/unbound/pfb_py_control``; the in-module reader thread (``pfb_control_watcher``)
applies it and republishes the applied sequence to ``/var/unbound/pfb_py_control.applied``.
The reader thread runs only when the DNSBL Control toggle (``pfb_control`` -> ini
``python_control``) is on.

A deprecated in-band DNS-TXT control path remains, gated by a separate, default-OFF
sub-toggle (``pfb_control_legacy`` -> ini ``python_control_legacy``). With it off (the
default) a ``python_control.*`` DNS-TXT query does nothing; with it on the in-band path
is honoured again.

These tests drive the REAL paths on a live VM:

* The CLI disables then re-enables DNSBL blocking (asserting the blocked-name shape
  before and after each command), and the applied-sequence marker advances across them.
* The CLI adds then removes a per-client bypass for the on-box client (127.0.0.1), so a
  blocked name resolves clean for that client while the bypass stands.
* Turning the DNSBL Control toggle OFF (``python_control = off``) stops the reader thread,
  so a CLI ``disable`` is published but never consumed — blocking is unchanged and the
  applied marker is frozen, proving ``python_control`` is a real gate, not an always-on path.
* The deprecated DNS-TXT control path is inert by default (a TXT ``python_control.disable``
  leaves blocking unchanged), and turning its sub-toggle on re-enables that path — proving
  it is a real gate, not an always-off branch.

Probed ON-BOX (``drill @127.0.0.1``): python-mode DNSBL has no localhost exemption, so a
blocked name returns its block shape even from 127.0.0.1; the per-client bypass keys on the
client IP, which an on-box drill presents as 127.0.0.1.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from . import helpers as h
from .conftest import CLIENT_LAN_IP, SmokeVM

pytestmark = pytest.mark.smoke


@pytest.fixture(scope="module")
def control_vm(smoke_vm: SmokeVM, client_vm: SmokeVM) -> Iterator[tuple[SmokeVM, str]]:
    """Deploy once with DNSBL + DNSBL Control on and a single feed-listed blocked domain.

    DNSBL Control is enabled (``pfb_control`` -> ini ``python_control`` on) so the reader
    thread runs; the legacy DNS-TXT sub-toggle is left OFF (its default). One local feed
    pins a unique domain to a VIP block; that injection is done ONCE and NOT reloaded
    between control commands, so the domain stays on the blocklist while the CLI flips
    runtime state on the live resolver. Yields ``(vm, blocked_domain)``.
    """
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    h.ensure_dnsbl_vip(smoke_vm)

    blocked = h.unique_domain("ctlblocked")
    feed = h.write_local_feed(smoke_vm, "smoke_ctl_feed.txt", f"{blocked}\n")
    # DNSBL Control on (reader thread runs), legacy DNS-TXT off (default), carried on the
    # case so inject()'s DNSBL-settings replace writes them with the other toggles. Setting
    # them via a separate pre-inject write would be wiped by that replace (#588).
    spec = h.DnsblCase(
        aliasname="smokectl",
        feed_url=feed,
        header="smokectl",
        mode=h.DnsblMode.VIP,
        control=True,
        control_legacy=False,
    )
    h.inject(smoke_vm, spec)
    h.reload(smoke_vm, "update")

    # Guard the gate: the reader thread is enabled and the DNS-TXT path is inert by default.
    h.assert_control_ini(smoke_vm, control=True, legacy=False)
    h.assert_link_health(client_vm, smoke_vm, control_name=h.unique_domain())
    try:
        yield smoke_vm, blocked
    finally:
        h.unblock_egress()
        try:
            h.clear_dnsbl_settings(smoke_vm)
        except Exception as cleanup_exc:  # noqa: BLE001
            print(f"[smoke] clear_dnsbl_settings failed on control teardown (suppressed): {cleanup_exc!r}")
        h.collect_host_diagnostics(smoke_vm)


def test_cli_disable_then_enable_drives_dnsbl(control_vm: tuple[SmokeVM, str], client_vm: SmokeVM) -> None:
    """Scenario: the CLI disable/enable toggles DNSBL blocking at runtime.

    Background: DNSBL Control is on (reader thread running) and ``blocked`` is feed-listed.
    Given the domain is VIP-blocked,
    When ``dnsbl-control disable`` is applied (reader consumes it),
    Then the SAME domain resolves clean (not the block shape);
    When ``dnsbl-control enable`` is applied,
    Then it is VIP-blocked again.
    And the applied-sequence marker strictly advances across the two commands — proof the
    reader consumed each one (not a left-over state).
    """
    vm, blocked = control_vm

    # GIVEN: blocked first (the before-state, so the disable's effect is causal).
    before = h.dns_probe_client(client_vm, blocked, "A")
    assert h.is_vip(before), f"{blocked} expected VIP block before disable, got {before}"
    applied0 = h.read_control_applied(vm)

    # WHEN: disable. THEN: resolves clean (no VIP).
    seq_disable = h.dnsbl_control_cli(vm, "disable")
    h.wait_control_applied(vm, seq_disable)
    h.flush_unbound_cache(vm)
    disabled = h.dns_probe_client(client_vm, blocked, "A")
    assert not h.is_vip(disabled), f"{blocked} should resolve clean after disable, still VIP-blocked: {disabled}"

    # WHEN: enable. THEN: VIP-blocked again.
    seq_enable = h.dnsbl_control_cli(vm, "enable")
    h.wait_control_applied(vm, seq_enable)
    h.flush_unbound_cache(vm)
    reenabled = h.dns_probe_client(client_vm, blocked, "A")
    assert h.is_vip(reenabled), f"{blocked} should be VIP-blocked again after enable, got {reenabled}"

    # AND: the applied marker advanced across both commands.
    assert seq_enable > seq_disable, f"enable seq {seq_enable} did not advance past disable seq {seq_disable}"
    final_applied = h.read_control_applied(vm)
    assert final_applied is not None and final_applied >= seq_enable, (
        f"applied marker {final_applied} did not advance to the enable seq {seq_enable} "
        f"(baseline before commands: {applied0})"
    )


def test_cli_addbypass_then_removebypass_exempts_client(control_vm: tuple[SmokeVM, str], client_vm: SmokeVM) -> None:
    """Scenario: the CLI add/remove a per-client DNSBL bypass for the civm client.

    Background: DNSBL Control is on and ``blocked`` is feed-listed; the civm queries
    pfSense DNS from CLIENT_LAN_IP (192.168.1.10), and the bypass keys on the client IP.
    Given the domain is VIP-blocked for that client,
    When ``dnsbl-control addbypass <CLIENT_LAN_IP>`` is applied,
    Then the domain resolves clean for that client (the bypass stands);
    When ``dnsbl-control removebypass <CLIENT_LAN_IP>`` is applied,
    Then it is VIP-blocked again.
    """
    vm, blocked = control_vm
    client = CLIENT_LAN_IP

    # GIVEN: blocked first for the civm client (the before-state).
    before = h.dns_probe_client(client_vm, blocked, "A")
    assert h.is_vip(before), f"{blocked} expected VIP block before addbypass, got {before}"

    # WHEN: addbypass the civm client. THEN: resolves clean for it.
    seq_add = h.dnsbl_control_cli(vm, "addbypass", client)
    h.wait_control_applied(vm, seq_add)
    h.flush_unbound_cache(vm)
    bypassed = h.dns_probe_client(client_vm, blocked, "A")
    assert not h.is_vip(bypassed), (
        f"{blocked} should resolve clean for bypassed client {client}, still VIP-blocked: {bypassed}"
    )

    # WHEN: removebypass. THEN: VIP-blocked again.
    seq_remove = h.dnsbl_control_cli(vm, "removebypass", client)
    h.wait_control_applied(vm, seq_remove)
    h.flush_unbound_cache(vm)
    restored = h.dns_probe_client(client_vm, blocked, "A")
    assert h.is_vip(restored), f"{blocked} should be VIP-blocked again after removebypass, got {restored}"
    assert seq_remove > seq_add, f"removebypass seq {seq_remove} did not advance past addbypass seq {seq_add}"


def test_dnsbl_control_off_makes_cli_channel_inert(control_vm: tuple[SmokeVM, str], client_vm: SmokeVM) -> None:
    """Scenario (branch coverage): with DNSBL Control OFF the CLI control channel is inert.

    Background: the fixture runs with DNSBL Control ON, so the ``pfb_control_watcher`` reader
    thread consumes CLI commands — that is the gate the disable/enable test above relies on.
    This flips the toggle OFF (``set_dnsbl_control`` -> ini ``python_control = off``) and
    reloads, proving the reader is a REAL gate (not always-on): with it off, a queued CLI
    ``disable`` is published but never consumed, so DNSBL blocking is unchanged and the
    applied-sequence marker does not advance. The control-ON half is already covered above, so
    together they are the on/off branch pair. Restores the fixture baseline (Control ON +
    reload) so the legacy tests that follow see ``python_control = on`` and a fresh block.

    Given DNSBL Control is ON (reader running) and the domain is VIP-blocked,
    When Control is turned OFF and reloaded (``python_control = off``, reader thread stops),
    And a ``dnsbl-control disable`` is issued (the writer still publishes it),
    Then the domain STAYS VIP-blocked — no reader consumed the command — and the applied
    marker is unchanged, proving the reader is gated on ``python_control``.
    """
    vm, blocked = control_vm

    # GIVEN: the fixture baseline — Control on, reader live, domain blocked. Establish it
    # explicitly (don't depend on a sibling test's end state). Nothing mutated yet, so this
    # stays outside the try below.
    h.assert_control_ini(vm, control=True, legacy=False)
    before = h.dns_probe_client(client_vm, blocked, "A")
    assert h.is_vip(before), f"{blocked} expected VIP block with DNSBL Control on, got {before}"

    # #738 F6: everything from here mutates the MODULE-scoped control_vm's shared baseline
    # (Control OFF). The two legacy tests below don't re-establish Control ON — they ASSERT
    # it via assert_control_ini as a precondition. An assertion failure anywhere in this OFF
    # phase must not skip the restore, or Control-OFF leaks into those tests and one real
    # regression here reports as three failures. finally runs on every exit path.
    try:
        # WHEN: turn DNSBL Control OFF and reload so the reader thread does not start.
        h.set_dnsbl_control(vm, False)
        h.reload(vm, "update")
        h.assert_control_ini(vm, control=False, legacy=False)

        # AND: issue a disable. The CLI writer still validates + publishes it (returns a seq),
        # but with no reader thread nothing consumes it — the writer waits up to 5s for the
        # (absent) reader to confirm, logs "not confirmed applied", then returns the seq.
        applied_before = h.read_control_applied(vm)
        seq = h.dnsbl_control_cli(vm, "disable")
        h.flush_unbound_cache(vm)

        # THEN: blocking is UNCHANGED — the domain stays VIP-blocked (the disable never applied).
        still = h.dns_probe_client(client_vm, blocked, "A")
        assert h.is_vip(still), (
            f"{blocked} should STAY VIP-blocked — with DNSBL Control OFF no reader thread consumes "
            f"the CLI disable (seq {seq}), got {still}"
        )
        # AND: the applied marker did not advance to the queued command (no reader ran).
        applied_after = h.read_control_applied(vm)
        assert applied_after == applied_before, (
            f"applied marker moved to {applied_after} (was {applied_before}); with DNSBL Control OFF "
            f"the reader thread must be stopped, so command seq {seq} must NOT be applied"
        )
    finally:
        # Restore the fixture baseline for the legacy tests below: Control back ON + reload
        # re-initialises python_blacklist (blocking on) and restarts the reader thread. Runs
        # unconditionally — pass, assertion failure, or any other exception (#738 F6).
        h.set_dnsbl_control(vm, True)
        h.reload(vm, "update")
        h.assert_control_ini(vm, control=True, legacy=False)


def test_legacy_dns_txt_control_inert_by_default(control_vm: tuple[SmokeVM, str], client_vm: SmokeVM) -> None:
    """Scenario: the deprecated DNS-TXT control path is inert by default.

    Background: DNSBL Control is on but the legacy DNS-TXT sub-toggle is OFF (its default),
    so the ini has ``python_control_legacy = off``.
    Given the domain is VIP-blocked,
    When an in-band ``python_control.disable`` TXT query is issued on-box,
    Then DNSBL blocking is UNCHANGED — the domain STAYS VIP-blocked (the DNS-TXT path does
    nothing). The before/after pair proves it is the disabled gate, not a missed query.
    """
    vm, blocked = control_vm

    # GIVEN: the gate is off and the domain is blocked.
    h.assert_control_ini(vm, control=True, legacy=False)
    before = h.dns_probe_client(client_vm, blocked, "A")
    assert h.is_vip(before), f"{blocked} expected VIP block before the TXT query, got {before}"

    # WHEN: issue the in-band TXT control query. THEN: still VIP-blocked (path inert).
    h.drill_txt(vm, "python_control.disable")
    h.flush_unbound_cache(vm)
    after = h.dns_probe_client(client_vm, blocked, "A")
    assert h.is_vip(after), (
        f"{blocked} should STAY VIP-blocked — the legacy DNS-TXT control path must be inert by default, got {after}"
    )


def test_legacy_dns_txt_control_active_when_enabled(control_vm: tuple[SmokeVM, str], client_vm: SmokeVM) -> None:
    """Scenario (branch coverage): turning the legacy sub-toggle on re-activates DNS-TXT control.

    Background: the same VM, but the legacy DNS-TXT sub-toggle is flipped ON (ini
    ``python_control_legacy = on``) and reloaded — proving the default-off behaviour above
    is a real gate, not an always-off path.
    Given (after the reload re-initialises blocking) the domain is VIP-blocked,
    When an in-band ``python_control.disable`` TXT query is issued on-box,
    Then DNSBL blocking IS disabled — the domain now resolves clean.

    Run LAST: it mutates the module config + reloads; the fixture finalizer restores the
    baseline DNSBL settings node.
    """
    vm, blocked = control_vm

    # Flip the legacy sub-toggle on and reload so the ini regenerates with it on. The reload
    # restarts Unbound, re-initialising python_blacklist (blocking back on) — so the BEFORE
    # state below is a fresh block, and the TXT disable's effect is causal.
    h.set_dnsbl_control_legacy(vm, True)
    h.reload(vm, "update")
    h.assert_control_ini(vm, control=True, legacy=True)

    # GIVEN: blocked first (the reload re-enabled blocking).
    before = h.dns_probe_client(client_vm, blocked, "A")
    assert h.is_vip(before), f"{blocked} expected VIP block after legacy-on reload, got {before}"

    # WHEN: the in-band TXT control query. THEN: blocking is disabled — resolves clean.
    h.drill_txt(vm, "python_control.disable")
    h.flush_unbound_cache(vm)
    after = h.dns_probe_client(client_vm, blocked, "A")
    assert not h.is_vip(after), (
        f"{blocked} should resolve clean — with the legacy sub-toggle ON the DNS-TXT control path "
        f"must disable DNSBL, still blocked: {after}"
    )
