"""tests/test_smoke_net_mode.py — ADR-50 P3: SMOKE_NET_MODE bridge/slirp conftest unit tests.

Pins the NET_MODE-aware endpoint selection added to tests/smoke/conftest.py:
  1. slirp (default/unset) is behaviour-preserving: DEFAULT_HOST/CLIENT_HOST stay on
     127.0.0.1, SSH/WEB/CLIENT_SSH ports stay at the historical lane-0 hostfwd values,
     DEFAULT_STUB_DNS_ADDR stays on loopback.
  2. bridge flips the endpoints: DEFAULT_HOST → 192.168.43.15, DEFAULT_SSH_PORT → 22,
     DEFAULT_WEB_PORT → 80, DEFAULT_CLIENT_HOST → 192.168.43.16,
     DEFAULT_CLIENT_SSH_PORT → 22, DEFAULT_STUB_DNS_ADDR → 192.168.89.2.
  3. Bridge MGMT IPs are env-overridable via SMOKE_PFSENSE_MGMT_IP / SMOKE_CLIENT_MGMT_IP.
  4. An invalid SMOKE_NET_MODE value raises ValueError at import time.

RED→GREEN evidence (tests that FAIL on pre-P3 code, PASS after):
  - test_bridge_flips_endpoints: before P3 the bridge branch does not exist, so the
    constants stay at loopback/slirp values.  Asserting DEFAULT_HOST == "192.168.43.15"
    FAILS with: AssertionError: expected 192.168.43.15; got 127.0.0.1.
    After P3: PASSES.
  - test_bridge_client_host: DEFAULT_CLIENT_HOST does not exist before P3 →
    AttributeError.  After P3: exists and equals 192.168.43.16.
  - test_bridge_stub_dns_addr: DEFAULT_STUB_DNS_ADDR does not exist before P3 →
    AttributeError.  After P3: exists and equals 192.168.89.2.

Run: python -m pytest tests/test_smoke_net_mode.py -v
"""

from __future__ import annotations

import importlib
import os
import sys
import types

import pytest

# ---------------------------------------------------------------------------
# Helpers — load conftest in an isolated environment
# ---------------------------------------------------------------------------

# All env vars that conftest reads or writes at import time (superset of
# test_adr47_conftest_lane._CONFTEST_ENV_KEYS, extended with the NET_MODE vars).
_CONFTEST_ENV_KEYS: tuple[str, ...] = (
    "SMOKE_LANE",
    "SMOKE_SSH_HOSTPORT",
    "SMOKE_WEB_HOSTPORT",
    "SMOKE_CLIENT_SSH_HOSTPORT",
    "SMOKE_LAN_SOCKET_PORT",
    "PFB_DIAG_DIR",
    "SMOKE_NET_MODE",
    "SMOKE_PFSENSE_MGMT_IP",
    "SMOKE_CLIENT_MGMT_IP",
    "SMOKE_STUB_DNS_ADDR",
)


def _load_conftest(
    *,
    net_mode: str | None = None,
    pfsense_mgmt_ip: str | None = None,
    client_mgmt_ip: str | None = None,
    stub_dns_addr: str | None = None,
    lane: int = 0,
) -> types.ModuleType:
    """Import tests.smoke.conftest with controlled env vars.

    Saves and restores all conftest-side-effected env vars AND the affected
    sys.modules entries so tests are fully order-independent.
    """
    saved = {k: os.environ.get(k) for k in _CONFTEST_ENV_KEYS}
    saved_modules = {
        k: sys.modules[k] for k in list(sys.modules) if "smoke.conftest" in k or k == "tests.smoke.conftest"
    }

    os.environ["SMOKE_LANE"] = str(lane)
    # Set or unset each NET_MODE-related env var.
    _set_or_pop("SMOKE_NET_MODE", net_mode)
    _set_or_pop("SMOKE_PFSENSE_MGMT_IP", pfsense_mgmt_ip)
    _set_or_pop("SMOKE_CLIENT_MGMT_IP", client_mgmt_ip)
    _set_or_pop("SMOKE_STUB_DNS_ADDR", stub_dns_addr)
    # PFB_DIAG_DIR: unset so DIAG_DIR defaults to 'smoke-diag' (avoids cwd Path("")).
    os.environ.pop("PFB_DIAG_DIR", None)

    # Force a fresh import — conftest reads env at module level.
    for key in list(sys.modules):
        if "smoke.conftest" in key or key == "tests.smoke.conftest":
            del sys.modules[key]

    try:
        return importlib.import_module("tests.smoke.conftest")
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        # Restore sys.modules to the pre-call state (delete any entries this call added).
        for key in list(sys.modules):
            if "smoke.conftest" in key or key == "tests.smoke.conftest":
                del sys.modules[key]
        sys.modules.update(saved_modules)


def _set_or_pop(key: str, value: str | None) -> None:
    if value is None:
        os.environ.pop(key, None)
    else:
        os.environ[key] = value


# ---------------------------------------------------------------------------
# 1 — slirp (default) is behaviour-preserving
# ---------------------------------------------------------------------------


class TestSlirpDefault:
    """slirp mode (SMOKE_NET_MODE unset or 'slirp') keeps today's loopback/hostfwd values.

    Scenario: existing runs without SMOKE_NET_MODE set must be byte-for-behaviour
    identical before and after P3.  This class is the 'before' oracle: the values
    it pins were the only values possible pre-P3, so if they change for slirp, P3
    broke something.
    """

    def test_default_host_is_loopback(self) -> None:
        """Given SMOKE_NET_MODE unset, DEFAULT_HOST is 127.0.0.1 (slirp hostfwd)."""
        mod = _load_conftest()
        assert mod.DEFAULT_HOST == "127.0.0.1", f"expected 127.0.0.1; got {mod.DEFAULT_HOST!r}"

    def test_client_host_is_loopback(self) -> None:
        """Given SMOKE_NET_MODE unset, DEFAULT_CLIENT_HOST is 127.0.0.1."""
        mod = _load_conftest()
        assert mod.DEFAULT_CLIENT_HOST == "127.0.0.1", f"expected 127.0.0.1; got {mod.DEFAULT_CLIENT_HOST!r}"

    def test_ssh_port_is_historical_default(self) -> None:
        """Given SMOKE_NET_MODE unset, DEFAULT_SSH_PORT is 2222 at lane 0."""
        mod = _load_conftest(lane=0)
        assert mod.DEFAULT_SSH_PORT == 2222, f"expected 2222; got {mod.DEFAULT_SSH_PORT}"

    def test_web_port_is_historical_default(self) -> None:
        """Given SMOKE_NET_MODE unset, DEFAULT_WEB_PORT is 8080 at lane 0."""
        mod = _load_conftest(lane=0)
        assert mod.DEFAULT_WEB_PORT == 8080, f"expected 8080; got {mod.DEFAULT_WEB_PORT}"

    def test_client_ssh_port_is_historical_default(self) -> None:
        """Given SMOKE_NET_MODE unset, DEFAULT_CLIENT_SSH_PORT is 2223 at lane 0."""
        mod = _load_conftest(lane=0)
        assert mod.DEFAULT_CLIENT_SSH_PORT == 2223, f"expected 2223; got {mod.DEFAULT_CLIENT_SSH_PORT}"

    def test_stub_dns_addr_is_loopback(self) -> None:
        """Given SMOKE_NET_MODE unset, DEFAULT_STUB_DNS_ADDR is 127.0.0.1."""
        mod = _load_conftest()
        assert mod.DEFAULT_STUB_DNS_ADDR == "127.0.0.1", f"expected 127.0.0.1; got {mod.DEFAULT_STUB_DNS_ADDR!r}"

    def test_explicit_slirp_same_as_unset(self) -> None:
        """SMOKE_NET_MODE='slirp' gives the same result as unset."""
        mod = _load_conftest(net_mode="slirp")
        assert mod.DEFAULT_HOST == "127.0.0.1"
        assert mod.DEFAULT_CLIENT_HOST == "127.0.0.1"
        assert mod.DEFAULT_SSH_PORT == 2222
        assert mod.DEFAULT_WEB_PORT == 8080
        assert mod.DEFAULT_CLIENT_SSH_PORT == 2223
        assert mod.DEFAULT_STUB_DNS_ADDR == "127.0.0.1"


# ---------------------------------------------------------------------------
# 2 — bridge flips the endpoints (RED→GREEN: fails on pre-P3 code)
# ---------------------------------------------------------------------------


class TestBridgeFlipsEndpoints:
    """bridge mode routes SSH/DNS to the MGMT bridge IPs, not the loopback hostfwd.

    Scenario / Given–When–Then:
      Given SMOKE_NET_MODE=bridge (the per-box setup exports this before pytest)
      When tests/smoke/conftest.py is imported
      Then DEFAULT_HOST == 192.168.43.15 (pfSense MGMT bridge static lease)
           DEFAULT_SSH_PORT == 22
           DEFAULT_WEB_PORT == 80
           DEFAULT_CLIENT_HOST == 192.168.43.16 (civm MGMT bridge static lease)
           DEFAULT_CLIENT_SSH_PORT == 22
           DEFAULT_STUB_DNS_ADDR == 192.168.89.2 (WAN bridge IP; no loopback conflict)

    RED→GREEN evidence:
      Before P3: DEFAULT_HOST stays '127.0.0.1' → first assert FAILS.
      After  P3: all six asserts PASS.
    """

    def test_bridge_flips_endpoints(self) -> None:
        """SMOKE_NET_MODE=bridge → pfSense SSH/web target the MGMT bridge IP."""
        # Assert the slirp baseline first (the 'before' state).
        slirp = _load_conftest()
        assert slirp.DEFAULT_HOST == "127.0.0.1", "slirp baseline: DEFAULT_HOST must be loopback"
        assert slirp.DEFAULT_SSH_PORT == 2222, "slirp baseline: DEFAULT_SSH_PORT must be 2222"
        assert slirp.DEFAULT_WEB_PORT == 8080, "slirp baseline: DEFAULT_WEB_PORT must be 8080"

        # Now load with bridge mode and assert the flip.
        bridge = _load_conftest(net_mode="bridge")
        assert bridge.DEFAULT_HOST == "192.168.43.15", f"expected 192.168.43.15; got {bridge.DEFAULT_HOST!r}"
        assert bridge.DEFAULT_SSH_PORT == 22, f"expected 22; got {bridge.DEFAULT_SSH_PORT}"
        assert bridge.DEFAULT_WEB_PORT == 80, f"expected 80; got {bridge.DEFAULT_WEB_PORT}"

    def test_bridge_client_host(self) -> None:
        """SMOKE_NET_MODE=bridge → civm SSH targets the civm MGMT bridge IP."""
        # Assert the slirp baseline first.
        slirp = _load_conftest()
        assert slirp.DEFAULT_CLIENT_HOST == "127.0.0.1", "slirp baseline: DEFAULT_CLIENT_HOST must be loopback"
        assert slirp.DEFAULT_CLIENT_SSH_PORT == 2223, "slirp baseline: DEFAULT_CLIENT_SSH_PORT must be 2223"

        bridge = _load_conftest(net_mode="bridge")
        assert bridge.DEFAULT_CLIENT_HOST == "192.168.43.16", (
            f"expected 192.168.43.16; got {bridge.DEFAULT_CLIENT_HOST!r}"
        )
        assert bridge.DEFAULT_CLIENT_SSH_PORT == 22, f"expected 22; got {bridge.DEFAULT_CLIENT_SSH_PORT}"

    def test_bridge_stub_dns_addr(self) -> None:
        """SMOKE_NET_MODE=bridge → stub DNS binds the WAN bridge IP 192.168.89.2."""
        slirp = _load_conftest()
        assert slirp.DEFAULT_STUB_DNS_ADDR == "127.0.0.1", "slirp baseline: DEFAULT_STUB_DNS_ADDR must be loopback"

        bridge = _load_conftest(net_mode="bridge")
        assert bridge.DEFAULT_STUB_DNS_ADDR == "192.168.89.2", (
            f"expected 192.168.89.2; got {bridge.DEFAULT_STUB_DNS_ADDR!r}"
        )


# ---------------------------------------------------------------------------
# 3 — bridge MGMT IPs are env-overridable
# ---------------------------------------------------------------------------


class TestBridgeMgmtIpOverrides:
    """SMOKE_PFSENSE_MGMT_IP / SMOKE_CLIENT_MGMT_IP override the bridge static-lease defaults.

    P2's per-box setup exports these when its dnsmasq static leases differ from the
    defaults.  An explicit env value must win over the hardcoded fallback.
    """

    def test_pfsense_mgmt_ip_override(self) -> None:
        """SMOKE_PFSENSE_MGMT_IP overrides the DEFAULT_HOST in bridge mode."""
        mod = _load_conftest(net_mode="bridge", pfsense_mgmt_ip="10.99.1.100")
        assert mod.DEFAULT_HOST == "10.99.1.100", f"expected 10.99.1.100; got {mod.DEFAULT_HOST!r}"

    def test_client_mgmt_ip_override(self) -> None:
        """SMOKE_CLIENT_MGMT_IP overrides the DEFAULT_CLIENT_HOST in bridge mode."""
        mod = _load_conftest(net_mode="bridge", client_mgmt_ip="10.99.1.101")
        assert mod.DEFAULT_CLIENT_HOST == "10.99.1.101", f"expected 10.99.1.101; got {mod.DEFAULT_CLIENT_HOST!r}"

    def test_both_overrides_together(self) -> None:
        """Both overrides in bridge mode are independent and both honoured."""
        mod = _load_conftest(
            net_mode="bridge",
            pfsense_mgmt_ip="10.1.2.3",
            client_mgmt_ip="10.1.2.4",
        )
        assert mod.DEFAULT_HOST == "10.1.2.3", f"expected 10.1.2.3; got {mod.DEFAULT_HOST!r}"
        assert mod.DEFAULT_CLIENT_HOST == "10.1.2.4", f"expected 10.1.2.4; got {mod.DEFAULT_CLIENT_HOST!r}"

    def test_overrides_have_no_effect_in_slirp_mode(self) -> None:
        """MGMT IP overrides in slirp mode do not affect DEFAULT_HOST or DEFAULT_CLIENT_HOST."""
        mod = _load_conftest(
            net_mode="slirp",
            pfsense_mgmt_ip="10.1.2.3",
            client_mgmt_ip="10.1.2.4",
        )
        assert mod.DEFAULT_HOST == "127.0.0.1", f"slirp must keep loopback; got {mod.DEFAULT_HOST!r}"
        assert mod.DEFAULT_CLIENT_HOST == "127.0.0.1", f"slirp must keep loopback; got {mod.DEFAULT_CLIENT_HOST!r}"


# ---------------------------------------------------------------------------
# 4 — invalid SMOKE_NET_MODE raises ValueError
# ---------------------------------------------------------------------------


class TestInvalidNetMode:
    """An unrecognised SMOKE_NET_MODE raises ValueError at import time."""

    def test_invalid_mode_raises(self) -> None:
        """SMOKE_NET_MODE='garbage' → ValueError on import (same guard as boot_vm.sh)."""
        with pytest.raises(ValueError, match="SMOKE_NET_MODE"):
            _load_conftest(net_mode="garbage")
