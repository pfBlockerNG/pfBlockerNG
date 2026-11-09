"""Issue #3722: the HA harness survives core's package restart and never leaks the pending-changes marker.

Core runs ``rc.newwanip`` -> ``rc.start_packages`` once the SYNC NIC has its address. A pfBlockerNG pass that lands in
that window exits 75 and leaves ``pfb_pending_changes`` behind. Everything here runs off-box against fake guests; the
live proof is the HA modules themselves (``tests/smoke/test_ha_policy_authority.py`` and friends).
"""

from __future__ import annotations

import importlib
import math
import subprocess
import time
from types import ModuleType
from typing import Any

import pytest

from tests.test_issue3454_ha_pair import FakeNode

MARKER = "/usr/local/etc/pfb_pending_changes"
APPLIED = f"{MARKER}.applied"


@pytest.fixture
def ha() -> ModuleType:
    return importlib.import_module("tests.smoke.ha_pair")


@pytest.fixture
def hp() -> ModuleType:
    return importlib.import_module("tests.smoke.ha_policy")


class _Clock:
    """Controlled time for ``helpers``: ``sleep`` advances ``monotonic``, everything else is the real module."""

    def __init__(self) -> None:
        self.now = 0.0
        self.slept: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds

    def __getattr__(self, name: str) -> Any:
        return getattr(time, name)


class _Guest(FakeNode):
    """A node whose pfBlockerNG passes exit ``rc`` for ``deferrals`` calls (each leaving the marker), then succeed."""

    RUNAWAY = 1000

    def __init__(
        self,
        name: str,
        *,
        deferrals: int | None = 0,
        rc: int = 75,
        pass_seconds: float = 0.0,
        clock: _Clock | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(name, **kwargs)
        self.deferrals = deferrals  # None: the lock never frees
        self.rc = rc
        self.pass_seconds, self.clock = pass_seconds, clock  # what one pass costs on the guest's clock
        self.passes = 0

    def ssh(self, *remote: str, timeout: float = 60.0) -> subprocess.CompletedProcess[str]:
        if "pfb_trigger" not in remote:
            return super().ssh(*remote, timeout=timeout)
        self.ssh_calls.append(" ".join(remote))
        self.passes += 1
        if self.clock is not None:
            self.clock.now += self.pass_seconds
        assert self.passes <= self.RUNAWAY, "the harness re-ran a pass without end: its retry loop has no bound"
        if self.deferrals is None or self.passes <= self.deferrals:
            self.files.add(MARKER)
            return subprocess.CompletedProcess(remote, self.rc, "", "Feed pass [ sync ] deferred - dispatcher lock\n")
        return subprocess.CompletedProcess(remote, 0, "", "")


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch, hp: ModuleType) -> _Clock:
    fake = _Clock()
    monkeypatch.setattr(hp.h, "time", fake)
    return fake


def _guest_json(_vm: Any, php: str, **_kw: Any) -> Any:
    """The guest's answer to a pfSsh read: the marker's path, or a policy state with nothing in it."""
    if "pfb_pending_changes_marker" in php:
        return MARKER
    empty = {"digest": "d", "current_digest": "d", "projection": {}, "leaves": {}, "installedpackages_sha256": "s"}
    return {**empty, "core": {}}


@pytest.fixture
def seams(hp: ModuleType, ha: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    """Everything ``arrange_baseline`` does around its reloads is answered; the reloads themselves run for real."""
    for name in (
        "set_leaves",
        "settle",
        "write_feed",
        "seed_node",
        "php_write",
        "wait_filter_idle",
        "assert_dnsbl_vip",
    ):
        monkeypatch.setattr(hp, name, lambda *_a, **_k: None)
    for name in (
        "inject_ip_lists",
        "ensure_dnsbl_vip",
        "set_dnsbl_enabled",
        "wait_unbound_ready",
        "_require_pfb_dns_serving",
        "release_pfb_dns",
    ):
        monkeypatch.setattr(hp.h, name, lambda *_a, **_k: None)
    monkeypatch.setattr(hp, "gateway_name", lambda _vm: "WAN_DHCP")
    monkeypatch.setattr(hp, "php_json", _guest_json)
    monkeypatch.setattr(hp.h, "pfb_config_digest", lambda _vm: "digest")
    monkeypatch.setattr(ha.helpers, "php_eval", lambda vm, snippet, **_k: vm.php(snippet))
    monkeypatch.setattr(ha.helpers, "apply_filter_sync", lambda *_a, **_k: None)


def _pair(hp: ModuleType, a: _Guest, b: _Guest) -> Any:
    return hp.HaPair(a, b, sync_password="s", nopriv_password="n", carp_password="c")


def _guests(deferred: str, **kwargs: Any) -> tuple[_Guest, _Guest]:
    """Node A and node B, with ``deferred`` ("primary" or "secondary") the one whose pass is held up."""
    held = {"deferrals": None, **kwargs}
    return (
        _Guest("primary", **(held if deferred == "primary" else {})),
        _Guest("secondary", **(held if deferred == "secondary" else {})),
    )


ONE_NODE = pytest.mark.parametrize("deferred", ["primary", "secondary"])


@ONE_NODE
def test_a_pass_deferred_by_cores_package_restart_is_retried_until_the_lock_frees(
    hp: ModuleType, seams: None, clock: _Clock, deferred: str
) -> None:
    a, b = _guests(deferred, deferrals=2)

    base = hp.arrange_baseline(_pair(hp, a, b))

    held, other = (a, b) if deferred == "primary" else (b, a)
    assert held.passes == 3, f"expected two deferrals then one clean pass on {held.name}, got {held.passes} passes"
    assert other.passes == 1, f"{other.name} was never deferred and must run exactly one pass, got {other.passes}"
    assert base.marker == MARKER
    assert clock.slept, "the retry must wait between attempts"


@ONE_NODE
def test_a_lock_that_never_frees_fails_loudly_with_the_deferral_reason_after_a_bounded_wait(
    hp: ModuleType, seams: None, clock: _Clock, deferred: str
) -> None:
    a, b = _guests(deferred)
    attempts = 1 + math.ceil(hp.CORE_RESTART_TIMEOUT / hp.h.RELOAD_RETRY_INTERVAL)

    with pytest.raises(
        RuntimeError, match=r"reload\(update\) deferred \(rc=75\): Feed pass \[ sync \] deferred"
    ) as err:
        hp.arrange_baseline(_pair(hp, a, b))

    held = a if deferred == "primary" else b
    assert held.passes == attempts, f"{held.name}: expected {attempts} attempts before giving up, got {held.passes}"
    assert clock.now <= hp.CORE_RESTART_TIMEOUT + max(clock.slept), (
        f"the wait overshot its budget: waited {clock.now}s of {hp.CORE_RESTART_TIMEOUT}s"
    )
    assert f"gave up after {attempts} attempts in {clock.now:.0f}s" in str(err.value), (
        f"the failure must say how long the harness waited and how often it tried: {err.value}"
    )


@ONE_NODE
def test_a_failed_baseline_clears_the_pending_marker_on_both_nodes(
    hp: ModuleType, seams: None, clock: _Clock, deferred: str
) -> None:
    a, b = _guests(deferred)
    for node in (a, b):
        node.files.update({MARKER, APPLIED})  # whatever an earlier module left, and what the failed pass adds

    with pytest.raises(RuntimeError, match="deferred"):
        hp.arrange_baseline(_pair(hp, a, b))

    for node in (a, b):
        leaked = {MARKER, APPLIED} & node.files
        assert not leaked, f"{node.name}: a failed baseline left {sorted(leaked)} behind to stall the next settle()"


@pytest.mark.parametrize("rc", [1, 127])
def test_only_a_deferral_is_retried_any_other_failure_fails_at_once(hp: ModuleType, clock: _Clock, rc: int) -> None:
    node = _Guest("primary", deferrals=None, rc=rc)

    with pytest.raises(RuntimeError, match=rf"reload\(update\) failed: rc={rc}"):
        hp.h.reload(node, "update", wait_unbound=False, retry_deferred=hp.CORE_RESTART_TIMEOUT)

    assert node.passes == 1, f"rc={rc} is a failure, not a deferral, and must not be re-run: {node.passes} passes"
    assert clock.slept == [], "a failure must not wait before it is reported"


def test_a_retried_pass_reports_how_often_it_ran_and_how_long_it_took(
    hp: ModuleType, clock: _Clock, capsys: pytest.CaptureFixture[str]
) -> None:
    node = _Guest("primary", deferrals=2)

    hp.h.reload(node, "update", wait_unbound=False, retry_deferred=hp.CORE_RESTART_TIMEOUT)

    waited = 2 * hp.h.RELOAD_RETRY_INTERVAL
    assert f"ran on attempt 3 after {waited:.0f}s" in capsys.readouterr().out


def test_a_pass_accepted_at_once_says_nothing_about_retries(
    hp: ModuleType, clock: _Clock, capsys: pytest.CaptureFixture[str]
) -> None:
    hp.h.reload(_Guest("primary"), "update", wait_unbound=False, retry_deferred=hp.CORE_RESTART_TIMEOUT)

    assert "attempt" not in capsys.readouterr().out


def test_a_clock_that_never_advances_still_ends_the_retries(
    hp: ModuleType, clock: _Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(clock, "sleep", lambda _seconds: None)
    node = _Guest("primary", deferrals=None)

    with pytest.raises(RuntimeError, match=r"deferred \(rc=75\)"):
        hp.h.reload(node, "update", wait_unbound=False, retry_deferred=20.0)

    assert node.passes == 1 + math.ceil(20.0 / hp.h.RELOAD_RETRY_INTERVAL)


def test_the_retries_stop_when_the_time_budget_is_spent_though_attempts_remain(hp: ModuleType, clock: _Clock) -> None:
    budget, pass_seconds = 60.0, 10.0
    node = _Guest("primary", deferrals=None, pass_seconds=pass_seconds, clock=clock)

    with pytest.raises(RuntimeError, match=r"deferred \(rc=75\)"):
        hp.h.reload(node, "update", wait_unbound=False, retry_deferred=budget)

    assert clock.now <= budget + pass_seconds, f"a slow pass must not stretch the wait: {clock.now}s of {budget}s"
    assert node.passes < 1 + math.ceil(budget / hp.h.RELOAD_RETRY_INTERVAL), "the time bound never took effect"


def test_restore_node_clears_the_pending_marker_a_pass_left_behind(ha: ModuleType, seams: None) -> None:
    node = _Guest("primary", baseline=True)
    node.files.update({MARKER, APPLIED})

    ha.restore_node(node, "primary")

    leaked = {MARKER, APPLIED} & node.files
    assert not leaked, f"restore left {sorted(leaked)} behind: the next module's baseline would wait on it"
