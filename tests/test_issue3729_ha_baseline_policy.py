"""Issue #3729: the HA baseline starts both nodes at one stored policy, whatever earlier modules left on node A.

Node B is a fresh install holding every registry default; node A is the long-lived session VM whose earlier
teardowns deleted defaults. ``arrange_baseline`` seeds only lists and a few leaves, so without a copy the two nodes'
policy digests differ and a test that starts from "nothing is left to sync" fails before it begins. Everything here
runs off-box against a stateful fake of the two nodes' stored leaves; the live proof is the HA policy modules.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import subprocess
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

POLICY, LOCAL = "policy/", "local/"


class _Nodes:
    """Two nodes' stored leaves: ``policy/...`` is in the package's sync projection, ``local/...`` is not."""

    def __init__(self, hp: ModuleType, a: dict[str, Any], b: dict[str, Any]) -> None:
        self.hp = hp
        self.leaves = {"A": dict(a), "B": dict(b)}
        self.writes: list[tuple[str, dict[str, Any]]] = []

    def set_leaves(self, vm: Any, leaves: Any, _message: str, **_kw: Any) -> None:
        self.writes.append((vm.name, dict(leaves)))
        stored = self.leaves[vm.name]
        for path, value in leaves.items():
            if value is None:
                stored.pop(path, None)
            else:
                stored[path] = value

    def node_state(self, vm: Any) -> Any:
        stored = self.leaves[vm.name]
        projection = {p: v for p, v in stored.items() if p.startswith(POLICY)}
        digest = hashlib.sha256(json.dumps(projection, sort_keys=True).encode()).hexdigest()
        return self.hp.NodeState(digest, projection, dict(stored), "sha", {})

    def writes_to(self, node: str) -> list[dict[str, Any]]:
        return [leaves for name, leaves in self.writes if name == node]


@pytest.fixture
def hp() -> ModuleType:
    return importlib.import_module("tests.smoke.ha_policy")


def _arrange(hp: ModuleType, monkeypatch: pytest.MonkeyPatch, a: dict[str, Any], b: dict[str, Any]) -> _Nodes:
    """Run the real ``arrange_baseline`` with everything around the policy leaves answered by a fake."""
    nodes = _Nodes(hp, a, b)
    monkeypatch.setattr(hp, "set_leaves", nodes.set_leaves)
    monkeypatch.setattr(hp, "node_state", nodes.node_state)
    for name in ("settle", "write_feed", "seed_node", "php_write", "wait_filter_idle", "assert_dnsbl_vip"):
        monkeypatch.setattr(hp, name, lambda *_a, **_k: None)
    for name in ("inject_ip_lists", "ensure_dnsbl_vip", "set_dnsbl_enabled", "reload"):
        monkeypatch.setattr(hp.h, name, lambda *_a, **_k: None)
    monkeypatch.setattr(hp, "gateway_name", lambda _vm: "WAN_DHCP")
    monkeypatch.setattr(hp, "php_json", lambda *_a, **_k: "/usr/local/etc/pfb_pending_changes")
    monkeypatch.setattr(hp.h, "pfb_config_digest", lambda _vm: "digest")

    def snapshot_ok(*command: str, **_kw: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, "", "")

    pair = SimpleNamespace(
        primary=SimpleNamespace(name="A", ssh=snapshot_ok), secondary=SimpleNamespace(name="B", ssh=snapshot_ok)
    )
    hp.arrange_baseline(pair)
    return nodes


def test_b_ends_with_exactly_the_policy_a_holds_and_keeps_its_own_local_leaves(
    hp: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    a = {
        f"{POLICY}differs": "from-a",
        f"{POLICY}same": "x",
        f"{POLICY}only-on-a": "kept-sparse",
        f"{LOCAL}shared-name": "a-local",
    }
    b = {
        f"{POLICY}differs": "from-b",
        f"{POLICY}same": "x",
        f"{POLICY}only-on-b": "registry-default",
        f"{LOCAL}shared-name": "b-local",
        f"{LOCAL}only-on-b": "b-only",
    }
    a_before, b_local = dict(a), {p: v for p, v in b.items() if p.startswith(LOCAL)}

    nodes = _arrange(hp, monkeypatch, a, b)

    state_a, state_b = nodes.node_state(SimpleNamespace(name="A")), nodes.node_state(SimpleNamespace(name="B"))
    assert state_b.projection == state_a.projection, (
        f"B's policy must equal A's: A holds {state_a.projection}, B holds {state_b.projection}"
    )
    assert state_a.digest == state_b.digest, f"policy digests differ: A {state_a.digest}, B {state_b.digest}"
    assert nodes.leaves["A"] == a_before, f"A is the source and must not be written: {nodes.writes_to('A')}"
    assert {p: v for p, v in nodes.leaves["B"].items() if p.startswith(LOCAL)} == b_local, (
        f"B's local leaves must survive the copy: {nodes.leaves['B']}"
    )


def test_nodes_already_at_one_policy_are_not_written_again(hp: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    same = {f"{POLICY}same": "x", f"{LOCAL}own": "a-local"}

    nodes = _arrange(hp, monkeypatch, same, {**same, f"{LOCAL}own": "b-local"})

    assert nodes.writes_to("B") == [], f"equal policy needs no write on B at all, got {nodes.writes_to('B')}"
