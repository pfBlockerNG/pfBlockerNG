"""Trivial end-to-end smoke test — proves the Phase-3 scaffolding works.

DESELECTED from the default ``python -m pytest`` (``--ignore=tests/smoke`` in
pyproject.toml). Run only by the smoke workflow:

    python -m pytest tests/smoke -m smoke --override-ini="addopts="

It boots the VM (session fixture), then asserts the two cheapest signals that
the whole chain is live:
  * the IP path is observable: ``pfctl -sr`` over SSH returns a non-empty
    ruleset (sshd up, WAN pass rule lets the runner in, pf loaded);
  * the DNS path is live: the baked Unbound ``local-data`` control name
    resolves to its known answer over the host-forwarded :53.

This is scaffolding proof only; the IP/DNS matrix is Phase 5.
"""

from __future__ import annotations

import pytest

from .conftest import SmokeVM, expected_control_answer, resolve_a

pytestmark = pytest.mark.smoke


def test_pfctl_ruleset_nonempty(smoke_vm: SmokeVM) -> None:
    """`pfctl -sr` over SSH returns a non-empty ruleset."""
    result = smoke_vm.ssh("/sbin/pfctl", "-sr", timeout=30)
    assert result.returncode == 0, f"pfctl -sr failed: rc={result.returncode} stderr={result.stderr!r}"
    rules = [line for line in result.stdout.splitlines() if line.strip()]
    assert rules, f"pfctl returned no rules; stdout was: {result.stdout!r}"


def test_control_name_resolves(smoke_vm: SmokeVM) -> None:
    """The baked local-data control name resolves to its known answer."""
    name, expected_ip = expected_control_answer()
    answers = resolve_a(name, smoke_vm.host, smoke_vm.dns_port)
    assert answers, f"control name {name!r} returned no A record"
    if expected_ip is not None:
        assert expected_ip in answers, f"{name!r} resolved to {answers}, expected {expected_ip!r}"
