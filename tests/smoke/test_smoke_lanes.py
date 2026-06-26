"""Pure unit tests for the smoke-lane foundation helpers.

No VM, no network, no markers — runs fast under the override invocation:
    python -m pytest tests/smoke/test_smoke_lanes.py --override-ini="addopts="

Tests the helpers introduced for per-lane parallelism:

* ``_needs_two_vm``  — predicate: does this test's fixture closure require civm?
* ``_lane_port``     — offset: disjoint host-forward port per lane.
* ``_validate_lane`` — reject a SMOKE_LANE that would break port isolation.
"""

from __future__ import annotations

import pytest

from .conftest import _lane_port, _needs_two_vm, _validate_lane

# --------------------------------------------------------------------------- #
# _needs_two_vm
# --------------------------------------------------------------------------- #


def test_needs_two_vm_true_for_client_vm() -> None:
    # A test that directly requests client_vm boots the civm client.
    assert _needs_two_vm({"client_vm"}) is True


def test_needs_two_vm_true_for_lan_interface() -> None:
    # lan_interface also implies civm (it depends on client_vm transitively).
    assert _needs_two_vm({"lan_interface"}) is True


def test_needs_two_vm_true_when_mixed_with_other_fixtures() -> None:
    # Civm detection survives alongside other fixtures in the transitive closure.
    assert _needs_two_vm({"smoke_vm", "client_vm", "stub_dns"}) is True


def test_needs_two_vm_false_for_pfsense_only_fixtures() -> None:
    # smoke_vm + stub_dns alone: pfSense only, no civm.
    assert _needs_two_vm({"smoke_vm", "stub_dns"}) is False


def test_needs_two_vm_false_for_empty_closure() -> None:
    # A test with no fixtures at all does not need civm.
    assert _needs_two_vm(set()) is False


def test_needs_two_vm_false_for_deployed_vm_only() -> None:
    # deployed_vm is a pfSense-only fixture alias; does not boot civm.
    assert _needs_two_vm({"deployed_vm"}) is False


# --------------------------------------------------------------------------- #
# _lane_port
# --------------------------------------------------------------------------- #


def test_lane_port_lane0_returns_base() -> None:
    # Lane 0 invariant: no offset → the same port as today's historical default.
    assert _lane_port(2222, 0) == 2222
    assert _lane_port(8080, 0) == 8080
    assert _lane_port(5353, 0) == 5353
    assert _lane_port(2223, 0) == 2223


def test_lane_port_eight_lanes_all_distinct() -> None:
    # Eight lanes must produce eight distinct ports — proves lane is not ignored.
    ports = [_lane_port(2222, lane) for lane in range(8)]
    assert len(set(ports)) == 8, f"collisions among lane ports: {ports}"


def test_lane_port_nonzero_lane_differs_from_base() -> None:
    # Any lane > 0 must not land on the base — rules out a constant implementation.
    for lane in range(1, 8):
        assert _lane_port(2222, lane) != 2222, f"lane {lane} collides with base"


def test_lane_port_adjacent_bases_no_collision_across_lanes() -> None:
    # Two bases one apart (2222 vs 2223, as SSH and civm-SSH share a host) must not
    # collide across lanes 0..7 with the default stride=10 — each lane's pair stays
    # one apart and never crosses another lane's pair.
    ports_a = {_lane_port(2222, lane) for lane in range(8)}
    ports_b = {_lane_port(2223, lane) for lane in range(8)}
    overlap = ports_a & ports_b
    assert not overlap, f"bases 2222 and 2223 collide at lanes: {overlap}"


# --------------------------------------------------------------------------- #
# _validate_lane
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("lane", [0, 1, 7, 5745])
def test_validate_lane_accepts_in_range(lane: int) -> None:
    # 0 (default), a couple of real lanes, and the max that keeps web 8080 <= 65535.
    _validate_lane(lane)  # must not raise


@pytest.mark.parametrize("lane", [-1, -10])
def test_validate_lane_rejects_negative(lane: int) -> None:
    # A negative lane derives lower-numbered ports, reusing another lane's range — reject it.
    with pytest.raises(ValueError, match="SMOKE_LANE"):
        _validate_lane(lane)


@pytest.mark.parametrize("lane", [5746, 99999])
def test_validate_lane_rejects_port_overflow(lane: int) -> None:
    # A lane that pushes web 8080 past 65535 yields an invalid host-forward port — reject it.
    with pytest.raises(ValueError, match="SMOKE_LANE"):
        _validate_lane(lane)
