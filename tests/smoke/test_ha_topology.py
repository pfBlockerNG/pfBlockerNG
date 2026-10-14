"""Smoke leg: two real pfSense guests as an HA pair (issue #3454, harness ``ha_pair``).

The ``ha_pair`` fixture (conftest.py + ha_pair.py) boots a second pfSense CE guest from the SAME image, joins
the two on a QEMU UDP point-to-point sync link (net3/vtnet3), and configures pfSense HA: a SYNC interface, a
CARP VIP, HTTPS webgui, an HA-privileged and an unprivileged user on node B, ``hasync`` on node A. The module
ends by restoring both nodes' config.xml, so later one-node modules see the image they always saw.

This module proves the topology the pfBlockerNG HA-sync work builds on: each guest keeps its own management
path, authenticated HTTPS XMLRPC works A -> B and rejects bad credentials / a missing privilege without
mutating B, management survives a CARP role flip, and core's automatic HA transport reaches B.

DESELECTED from the default ``python -m pytest`` (``--ignore=tests/smoke`` in pyproject.toml). Run only by
the smoke workflow or locally::

    python -m pytest tests/smoke/test_ha_topology.py -m smoke --override-ini="addopts="

Needs ``SMOKE_PKG`` (deployed on both nodes), KVM and room for two guests; otherwise it skips cleanly.
"""

from __future__ import annotations

import secrets
from typing import Any

import pytest

from . import helpers as h
from .conftest import SmokeVM
from .ha_pair import (
    HA_USER,
    NOPRIV_USER,
    PRIMARY_SYNC_IP,
    SECONDARY_SYNC_IP,
    SYNC_NIC,
    HaPair,
    carp_state,
    clear_sshguard,
    config_digest,
    set_carp_maintenance,
    wait_carp_state,
    xmlrpc_call,
)

pytestmark = pytest.mark.smoke

CONFIG = "/conf/config.xml"


def _sentinel() -> str:
    return f"pfb_smoke_ha_{secrets.token_hex(4)}"


def _alias_entry(sentinel: str, address: str) -> str:
    """PHP expression: one inert host alias named ``sentinel`` (a unique marker for "did this config land?")."""
    q = h._php_str
    descr = "pfb smoke HA sentinel"
    return f"array('name' => {q(sentinel)}, 'type' => 'host', 'address' => {q(address)}, 'descr' => {q(descr)})"


def _snapshot_config(vm: SmokeVM, path: str) -> None:
    result = vm.ssh(f"cp -p {CONFIG} {path}")
    assert result.returncode == 0, f"snapshot of {CONFIG} to {path} failed: {result.stderr!r}"


def _restore_config(vm: SmokeVM, path: str) -> None:
    """Copy the per-test snapshot back, drop pfSense's parsed-config cache, reload the filter, un-block sshguard."""
    result = vm.ssh(f"cp -p {path} {CONFIG} && rm -f /tmp/config.cache && rm -f {path}")
    assert result.returncode == 0, f"restore of {CONFIG} from {path} failed: {result.stderr!r}"
    h.apply_filter_sync(vm)
    clear_sshguard(vm)


def test_each_node_answers_on_its_own_management_path(ha_pair: HaPair) -> None:
    """Given two guests from one image, each management path reaches a different, correctly addressed node."""
    nodes = (
        ("primary", ha_pair.primary, PRIMARY_SYNC_IP, SECONDARY_SYNC_IP),
        ("secondary", ha_pair.secondary, SECONDARY_SYNC_IP, PRIMARY_SYNC_IP),
    )
    assert ha_pair.primary.ssh_port != ha_pair.secondary.ssh_port, (
        f"both nodes share SSH host port {ha_pair.primary.ssh_port}: one guest would answer for both"
    )
    for name, vm, own_ip, other_ip in nodes:
        assert vm.ssh("true").returncode == 0, f"{name}: ssh on host port {vm.ssh_port} did not answer"
        ifconfig = vm.ssh(f"ifconfig {SYNC_NIC}").stdout
        assert f"inet {own_ip} " in ifconfig, f"{name}: expected inet {own_ip} on {SYNC_NIC}, got {ifconfig!r}"
        assert f"inet {other_ip} " not in ifconfig, f"{name}: must not own the peer's {other_ip}, got {ifconfig!r}"
        protocol = h.config_get(vm, "system/webgui/protocol")
        assert protocol == "https", f"{name}: expected webgui protocol https, got {protocol!r}"


def test_ha_privileged_user_authenticates_over_https_xmlrpc(ha_pair: HaPair) -> None:
    """Given an HA-privileged account on B, A's XMLRPC call to B over HTTPS is authenticated and answered."""
    has_user = h.guest_file_contains(ha_pair.secondary, CONFIG, f"<name>{HA_USER}</name>")
    assert has_user, f"{HA_USER} is not in the secondary's {CONFIG}: the account was never created"

    result = xmlrpc_call(ha_pair, user=HA_USER, password=ha_pair.sync_password, method="host_firmware_version")

    assert result.get("ok") is True, f"expected an authenticated XMLRPC reply, got {result}"
    expected = h.config_get(ha_pair.secondary, "version")
    assert result["resp"]["config_version"] == expected, (
        f"expected the secondary's config version {expected!r}, got {result['resp']!r}"
    )


def test_wrong_password_and_unprivileged_user_are_rejected_without_mutation(ha_pair: HaPair) -> None:
    """Rejected callers must change nothing on B; the same payload with valid credentials DOES change it.

    The positive control keeps the "unchanged" assertions from passing vacuously (e.g. a payload B never
    would have applied).
    """
    secondary = ha_pair.secondary
    sentinel = _sentinel()
    params = f"array('aliases' => array('alias' => array({_alias_entry(sentinel, '192.0.2.77')})))"
    snapshot = "/root/pfb-smoke-ha-test-reject.xml"

    def call(user: str, password: str) -> dict[str, Any]:
        return xmlrpc_call(ha_pair, user=user, password=password, method="restore_config_section", params_php=params)

    _snapshot_config(secondary, snapshot)
    digest_before = config_digest(secondary)
    assert not h.guest_file_contains(secondary, CONFIG, sentinel), f"sentinel {sentinel} already on the secondary"
    try:
        wrong = call(HA_USER, "not-" + ha_pair.sync_password)
        clear_sshguard(secondary)
        nopriv = call(NOPRIV_USER, ha_pair.nopriv_password)
        clear_sshguard(secondary)

        assert wrong.get("fault") == -1, f"wrong password: expected fault -1, got {wrong}"
        assert nopriv.get("fault") == -2, f"user without the HA privilege: expected fault -2, got {nopriv}"
        assert config_digest(secondary) == digest_before, "a rejected call changed the secondary's config.xml"
        assert not h.guest_file_contains(secondary, CONFIG, sentinel), "a rejected call wrote the sentinel alias"

        accepted = call(HA_USER, ha_pair.sync_password)

        assert accepted.get("ok") is True, f"positive control: expected the valid call to be accepted, got {accepted}"
        assert h.guest_file_contains(secondary, CONFIG, sentinel), "positive control: accepted call wrote nothing"
    finally:
        _restore_config(secondary, snapshot)
    assert config_digest(secondary) == digest_before, "the secondary's config.xml was not restored"


def test_management_stays_reachable_while_carp_role_changes(ha_pair: HaPair) -> None:
    """Given A MASTER / B BACKUP, forcing A into CARP maintenance flips the roles and breaks no path."""
    primary, secondary = ha_pair.primary, ha_pair.secondary
    wait_carp_state(primary, "MASTER", node="primary")
    wait_carp_state(secondary, "BACKUP", node="secondary")
    assert (carp_state(primary), carp_state(secondary)) == ("MASTER", "BACKUP")
    try:
        set_carp_maintenance(primary, True)
        wait_carp_state(secondary, "MASTER", node="secondary")
        wait_carp_state(primary, "BACKUP", node="primary")

        for name, vm in (("primary", primary), ("secondary", secondary)):
            assert vm.ssh("true").returncode == 0, f"{name}: management ssh broke during the CARP flip"
        result = xmlrpc_call(ha_pair, user=HA_USER, password=ha_pair.sync_password, method="host_firmware_version")
        assert result.get("ok") is True, f"expected XMLRPC to keep working through the CARP flip, got {result}"
    finally:
        set_carp_maintenance(primary, False)
        wait_carp_state(primary, "MASTER", node="primary")
        wait_carp_state(secondary, "BACKUP", node="secondary")


def test_core_automatic_ha_sync_reaches_secondary(ha_pair: HaPair) -> None:
    """Core's ``rc.filter_synchronize`` on A (hasync -> B) carries a ticked section onto B."""
    primary, secondary = ha_pair.primary, ha_pair.secondary
    wait_carp_state(primary, "MASTER", node="primary")
    wait_carp_state(secondary, "BACKUP", node="secondary")
    sentinel = _sentinel()
    snapshot = "/root/pfb-smoke-ha-test-sync.xml"
    _snapshot_config(primary, snapshot)
    _snapshot_config(secondary, snapshot)
    try:
        added = h.php_eval(
            primary,
            "$aliases = config_get_path('aliases/alias', array());\n"
            f"$aliases[] = {_alias_entry(sentinel, '192.0.2.78')};\n"
            "config_set_path('aliases/alias', $aliases);\n"
            "write_config('pfBlockerNG smoke: HA sync sentinel alias');\n"
            "echo 'OK';",
        )
        assert added.returncode == 0 and "OK" in added.stdout, f"could not add the sentinel alias: {added}"
        assert h.guest_file_contains(primary, CONFIG, sentinel), f"sentinel {sentinel} not on the primary"
        assert not h.guest_file_contains(secondary, CONFIG, sentinel), f"sentinel {sentinel} already on the secondary"

        synced = primary.ssh("/etc/rc.filter_synchronize", timeout=300.0)

        assert synced.returncode == 0, f"rc.filter_synchronize failed: rc={synced.returncode} {synced.stderr!r}"
        assert h.guest_file_contains(secondary, CONFIG, sentinel), "the sentinel alias never reached the secondary"
    finally:
        _restore_config(secondary, snapshot)
        _restore_config(primary, snapshot)
