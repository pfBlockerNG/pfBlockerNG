"""A DNSBL-IP case must configure its own firewall interfaces — never inherit a sibling's.

Issue #1239: ``test_dnsblip_dual_stack_partition`` asserts that a pf rule references
``pfB_DNSBLIP_v4``/``_v6``. pfBlockerNG only builds that rule when an inbound/outbound
interface is configured (``helpers.SMOKE_IP_IFACE``, inc:10132 "Inbound interface option
not configured") — the alias TABLE builds regardless. ``_ip_inject_snippet`` sets those
interfaces; ``_dnsbl_inject_snippet`` did not, so a DNSBL-IP case only found them in the
shared config when some IpCase sibling had already run and left them there.

That made the test pass in a full ordered run and fail deterministically in isolation (a
``-k`` filter, or selective dispatch) — reported as an intermittent flake. CLAUDE.md:
"Self-encapsulated — never order-dependent. No test may depend on a sibling running first."

These pins are pure (no VM): the snippet is a string builder, so the contract is enforced on
every PR rather than only when the live smoke lane runs.
"""

from __future__ import annotations

from collections.abc import Callable
from types import SimpleNamespace

import pytest

from tests.smoke import helpers


def _case(**kwargs: object) -> helpers.DnsblCase:
    return helpers.DnsblCase(
        aliasname="smokedualip",
        feed_url="http://127.0.0.1:1/feed.txt",
        header="smokedualip",
        mode=helpers.DnsblMode.NULL,
        **kwargs,  # type: ignore[arg-type]
    )


def _single_list_snippet(**kwargs: object) -> str:
    return helpers._dnsbl_inject_snippet(_case(**kwargs))


def _multi_list_snippet(**kwargs: object) -> str:
    """The PHP `inject_dnsbl_lists` feeds pfSsh.php (it injects directly, so capture it)."""
    captured: list[str] = []

    class _FakeVM:
        def ssh(self, *_remote: str, **_kw: object) -> object:
            raise AssertionError("inject_dnsbl_lists must not shell out here")

    def _capture(_vm: object, snippet: str, *, timeout: float = 60.0) -> object:
        captured.append(snippet)
        return SimpleNamespace(returncode=0, stdout="OK", stderr="")

    original = helpers.php_eval
    helpers.php_eval = _capture  # type: ignore[assignment]
    try:
        helpers.inject_dnsbl_lists(_FakeVM(), [(_case(**kwargs), "Deny")])  # type: ignore[arg-type]
    finally:
        helpers.php_eval = original  # type: ignore[assignment]
    return captured[0]


# BOTH injection paths, not just the one issue #1239 happened to surface: inject_dnsbl_lists
# also honours dnsbl_ip_action, so leaving it out would let the identical order-dependent
# flake return through the multi-list door the moment a test combines the two.
INJECTORS = [
    pytest.param(_single_list_snippet, id="single-list(_dnsbl_inject_snippet)"),
    pytest.param(_multi_list_snippet, id="multi-list(inject_dnsbl_lists)"),
]


@pytest.mark.parametrize("build_snippet", INJECTORS)
@pytest.mark.parametrize("action", ["Deny_Both", "Deny_Inbound", "Deny_Outbound"])
def test_dnsbl_ip_case_sets_the_firewall_interfaces_itself(build_snippet: Callable[..., str], action: str) -> None:
    """Given a DNSBL case that enables the DNSBL-IP firewall feature (via EITHER injector)
    When its config-injection snippet is built
    Then the snippet writes the inbound/outbound interface into the IP settings — the
    precondition pfBlockerNG requires to emit the rule at all — so the case never depends
    on an IpCase sibling having left those interfaces behind in the shared config.
    """
    snippet = build_snippet(dnsbl_ip_action=action)

    assert helpers.CFG_IP_SETTINGS in snippet, f"DNSBL-IP case never touches the IP settings:\n{snippet}"
    assert f"'inbound_interface' => '{helpers.SMOKE_IP_IFACE}'" in snippet, (
        f"inbound_interface not configured — pfBlockerNG would build the table but NO rule:\n{snippet}"
    )
    assert f"'outbound_interface' => '{helpers.SMOKE_IP_IFACE}'" in snippet, (
        f"outbound_interface not configured — pfBlockerNG would build the table but NO rule:\n{snippet}"
    )


@pytest.mark.parametrize("build_snippet", INJECTORS)
def test_plain_dnsbl_case_leaves_the_firewall_interfaces_alone(build_snippet: Callable[..., str]) -> None:
    """Given a DNSBL case that does NOT enable the DNSBL-IP firewall feature
    When its config-injection snippet is built
    Then it does not touch the IP settings at all — the interfaces are a DNSBL-IP
    precondition, not a blanket DNSBL one, so a domain-only case must not quietly
    reconfigure the firewall out from under an unrelated test.
    """
    snippet = build_snippet()

    assert helpers.CFG_IP_SETTINGS not in snippet, f"a domain-only DNSBL case rewrote the IP settings:\n{snippet}"
    assert "inbound_interface" not in snippet, f"a domain-only DNSBL case configured a firewall interface:\n{snippet}"
