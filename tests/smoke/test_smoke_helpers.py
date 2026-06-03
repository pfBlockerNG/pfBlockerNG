"""Self-tests pinning the Phase-4 per-case loop primitives.

DESELECTED from the default ``python -m pytest`` (``--ignore=tests/smoke``).
Run only by the smoke workflow:

    python -m pytest tests/smoke -m smoke --override-ini="addopts="

Each test pins one helper against the REAL VM so a regression in the helper (or
a broken inject/reload) goes RED. The FALSE-GREEN GUARD
(:func:`test_false_green_guard`) asserts the WRONG block shape and REQUIRES it
to fail — proving the probe distinguishes a true block from a true pass.

These need the booted ``smoke_vm`` fixture, the branch ``.pkg`` (``SMOKE_PKG``),
and the smoke deps; without them they skip cleanly (the fixture skips on missing
prerequisites). They are NOT the matrix (Phase 5) — just enough to pin the
primitives.
"""

from __future__ import annotations

import os

import pytest

from . import helpers as h
from .conftest import SmokeVM, expected_control_answer

pytestmark = pytest.mark.smoke


@pytest.fixture(scope="module")
def deployed_vm(smoke_vm: SmokeVM) -> SmokeVM:
    """Deploy the branch .pkg once for the helper self-tests."""
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    return smoke_vm


# --------------------------------------------------------------------------- #
# 1) Deploy self-test
# --------------------------------------------------------------------------- #


def test_deploy_registers_package(deployed_vm: SmokeVM) -> None:
    """After deploy, the PHP CLI exists and ``update`` exits 0."""
    ls = deployed_vm.ssh("test", "-f", h.PFB_CLI, timeout=20)
    assert ls.returncode == 0, f"{h.PFB_CLI} missing after deploy"
    result = deployed_vm.ssh(h.PHP_BIN, h.PFB_CLI, "update", timeout=600)
    assert result.returncode == 0, f"pfblockerng.php update failed: {result.stderr!r}"


# --------------------------------------------------------------------------- #
# 2) Config-injection self-test (read-back + control resolve)
# --------------------------------------------------------------------------- #


def test_inject_value_roundtrips(deployed_vm: SmokeVM) -> None:
    """A value set via the config API reads back via the config API."""
    snippet = (
        f"config_set_path({h._php_str(h.CFG_DNSBL_SETTINGS)}, "
        f"array_merge(config_get_path({h._php_str(h.CFG_DNSBL_SETTINGS)}, array()), "
        f"array('pfb_dnsbl' => 'on')));\n"
        "write_config('smoke selftest');\necho 'OK';"
    )
    res = h.php_eval(deployed_vm, snippet)
    assert "OK" in res.stdout, f"inject write failed: {res.stderr!r}"
    back = h.config_get(deployed_vm, f"{h.CFG_DNSBL_SETTINGS}/pfb_dnsbl")
    assert back.strip() == "on", f"read-back mismatch: {back!r}"


def test_inject_control_record_resolves(deployed_vm: SmokeVM) -> None:
    """A control local-data injected in CONFIG resolves after a reload."""
    name = h.unique_domain("selftest-control")
    ip = "192.0.2.250"
    h.set_control_records(deployed_vm, {name: {"A": ip}}, {})
    # The reload regenerates unbound.conf; the config-baked record must survive.
    h.reload(deployed_vm, "update")
    answer = h.dns_probe(deployed_vm, name, "A")
    assert h.resolves_to(answer, ip), f"{name} -> {answer.records}, expected {ip}"


# --------------------------------------------------------------------------- #
# 3) Reload / reset self-test
# --------------------------------------------------------------------------- #


def test_reset_returns_to_baseline(deployed_vm: SmokeVM) -> None:
    """reset() runs clear* + a forced update and leaves Unbound ready."""
    h.reset(deployed_vm)
    # The baked control name still resolves (reset didn't break the resolver).
    name, expected_ip = expected_control_answer()
    if not name:
        pytest.skip("no baked control name (SMOKE_CONTROL_NAME unset)")
    answer = h.dns_probe(deployed_vm, name, "A")
    assert answer.records, f"baked control {name!r} gone after reset"
    if expected_ip is not None:
        assert h.resolves_to(answer, expected_ip)


# --------------------------------------------------------------------------- #
# 4) DNS probe + assert helpers (pure, no VM) + false-green guard
# --------------------------------------------------------------------------- #


def test_dns_assert_helpers_pure() -> None:
    """The shape-assert helpers classify each block shape correctly."""
    assert h.is_nxdomain(h.DnsAnswer("NXDOMAIN", []))
    assert not h.is_nxdomain(h.DnsAnswer("NOERROR", ["0.0.0.0"]))
    assert h.is_null_ip(h.DnsAnswer("NOERROR", ["0.0.0.0"]))
    assert not h.is_null_ip(h.DnsAnswer("NOERROR", ["192.0.2.1"]))
    assert h.is_vip(h.DnsAnswer("NOERROR", [h.DEFAULT_DNSBL_VIP4]))
    assert h.resolves_to(h.DnsAnswer("NOERROR", ["192.0.2.1"]), "192.0.2.1")


def test_false_green_guard() -> None:
    """A WRONG-shape assertion MUST fail — proves no silent false-green.

    An NXDOMAIN block asserted as a null-IP pass must be REJECTED. This test
    passes precisely because the wrong assertion is false; flipping the helper
    to be lenient would make this test go red.
    """
    nxdomain_block = h.DnsAnswer("NXDOMAIN", [])
    # The block is real; asserting it "resolves to" a pass IP must be false.
    assert not h.resolves_to(nxdomain_block, "192.0.2.1")
    assert not h.is_null_ip(nxdomain_block)
    assert not h.is_vip(nxdomain_block)
    # And a real pass must NOT read as a block.
    real_pass = h.DnsAnswer("NOERROR", ["192.0.2.1"])
    assert not h.is_nxdomain(real_pass)


def test_dns_probe_nxdomain_shape(deployed_vm: SmokeVM) -> None:
    """A name with no local-data and egress blocked is NOT a false A answer.

    Probes a guaranteed-absent name: it must NOT return a spurious A record
    (would indicate a leaking upstream / wrong probe), proving the probe reads
    the real resolver state.
    """
    answer = h.dns_probe(deployed_vm, h.unique_domain("definitely-absent"), "A")
    assert not answer.records or answer.rcode != "NOERROR", (
        f"absent name returned records {answer.records} rcode {answer.rcode}"
    )


# --------------------------------------------------------------------------- #
# 5) IP probe self-test (fed vs non-fed; rule reference)
# --------------------------------------------------------------------------- #


def test_ip_probe_membership_and_rule(deployed_vm: SmokeVM, mock_feeds: object) -> None:
    """A fed IP is a table member, a non-fed IP isn't, and a rule references it."""
    fed_ip = "198.51.100.7"
    non_fed = "198.51.100.200"
    feed_url = h.write_local_feed(deployed_vm, "smoke_ip_selftest.txt", f"{fed_ip}\n")
    spec = h.IpCase(aliasname="smokeipself", feed_url=feed_url, header="smokeipself")
    with h.CaseContext(deployed_vm, spec):
        members = h.pfctl_table_members(deployed_vm, spec.alias)
        assert h.member_present(members, fed_ip), f"{fed_ip} not in {spec.alias}: {members}"
        assert not h.member_present(members, non_fed), f"{non_fed} unexpectedly in {spec.alias}"
        assert h.rule_references(deployed_vm, spec.alias), f"no rule references {spec.alias}"


# --------------------------------------------------------------------------- #
# 6) ABP harness extensions (ADR-07) — PURE, no VM
#    Pin the feed-body builder + the config-injection snippet so a regression in
#    the ABP wiring (wrong settings key, a dropped extra row) goes RED without a
#    booted VM, exactly like the pure DNS-assert guards above.
# --------------------------------------------------------------------------- #


def test_abp_feed_body_has_header_and_lines() -> None:
    """``abp_feed`` prepends the sniffed ABP header so pfBlockerNG tags it ABP."""
    body = h.abp_feed("||evil.example^", "@@||good.example^")
    # The FIRST line must be the marker pfBlockerNG header-sniffs (inc:7934); a
    # body that does not start with it is parsed as a plain feed, not ABP.
    assert body.splitlines()[0] == h.ABP_HEADER
    assert "||evil.example^" in body
    assert "@@||good.example^" in body


def test_abp_inject_snippet_emits_user_regex_and_cap() -> None:
    """A DnsblCase carrying user_regex + regex_cap renders the matching config keys."""
    spec = h.DnsblCase(
        aliasname="smokeabp",
        feed_url="/var/db/pfblockerng/smokeabp.txt",
        header="smokeabp",
        user_regex=[r"ad[0-9]+\.example\.net", r"(a+)+\.evil\.example"],
        regex_cap=True,
    )
    snippet = h._dnsbl_inject_snippet(spec)
    assert "'pfb_regex' => 'on'" in snippet
    assert "'pfb_regex_cap' => 'on'" in snippet
    assert "'pfb_regex_list' =>" in snippet
    # Both user patterns ride along in the newline-joined list value.
    assert r"ad[0-9]+\\.example\\.net" in snippet or r"ad[0-9]+\.example\.net" in snippet


def test_abp_inject_snippet_emits_extra_rows() -> None:
    """extra_rows append additional headers/urls to the SAME DNSBL group's row[].

    Two ABP-bodied rows == two ABP feeds whose rules the Python build merges — the
    cross-feed ``@@``/``$badfilter`` vehicle. Both headers + urls must appear, and
    the group's logging/aliasname stay single (one group, many rows).
    """
    spec = h.DnsblCase(
        aliasname="smokexfeed",
        feed_url="/var/db/pfblockerng/feedA.txt",
        header="feedA",
        extra_rows=[("feedB", "/var/db/pfblockerng/feedB.txt")],
    )
    snippet = h._dnsbl_inject_snippet(spec)
    assert "'header' => 'feedA'" in snippet
    assert "'header' => 'feedB'" in snippet
    assert "/var/db/pfblockerng/feedA.txt" in snippet
    assert "/var/db/pfblockerng/feedB.txt" in snippet


def test_abp_inject_snippet_default_is_unchanged() -> None:
    """A plain DnsblCase (no ABP fields) emits NO regex keys and exactly one row —
    proving the ADR-07 fields are additive and the ADR-04 matrix is byte-stable."""
    spec = h.DnsblCase(aliasname="plain", feed_url="/var/db/pfblockerng/plain.txt", header="plain")
    snippet = h._dnsbl_inject_snippet(spec)
    assert "pfb_regex" not in snippet
    assert "regex_cap" not in snippet
    assert "custom" not in snippet
    assert snippet.count("'header' =>") == 1


def test_abp_inject_snippet_emits_cname_validation() -> None:
    """cname_validation -> the pfb_cname setting (ini python_cname)."""
    spec = h.DnsblCase(
        aliasname="smokecname",
        feed_url="/var/db/pfblockerng/smokecname.txt",
        header="smokecname",
        cname_validation=True,
    )
    snippet = h._dnsbl_inject_snippet(spec)
    assert "'pfb_cname' => 'on'" in snippet


def test_abp_inject_snippet_emits_custom_list() -> None:
    """custom_domains -> a base64 'custom' field (the sovereign Custom_List vehicle)."""
    spec = h.DnsblCase(
        aliasname="smokecust",
        feed_url="/var/db/pfblockerng/smokecust.txt",
        header="smokecust",
        custom_domains=["evil.example.com", "ads.example.net"],
    )
    snippet = h._dnsbl_inject_snippet(spec)
    assert "$list['custom'] = base64_encode(" in snippet
    # The domains ride along CRLF-joined inside the base64-encoded literal.
    assert "evil.example.com" in snippet
