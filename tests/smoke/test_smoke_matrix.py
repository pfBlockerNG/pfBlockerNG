"""ADR-04 Phase 5 — the first landed smoke matrix (a THIN vertical slice).

This is NOT the broad knob space (SafeSearch/TLD/GeoIP/full-AAAA are out of scope,
ADR §2). It is the minimum that proves the Phase-4 harness asserts
REAL pfBlockerNG behaviour end-to-end on BOTH paths — the IP path (``pfctl``
alias table + rule) and the DNS path (``dig`` rcode/record shape) — hermetically
(mock feeds + baked Unbound ``local-data`` only) and guarded against false-green.

DESELECTED from the default ``python -m pytest`` (``--ignore=tests/smoke`` in
pyproject.toml). Run only by the smoke workflow::

    python -m pytest tests/smoke -m smoke --override-ini="addopts="

Every expected answer is pinned to the REAL matcher semantics in
``src/usr/local/pkg/pfblockerng/pfb_unbound.py`` + ``pfblockerng.inc`` (verified
against source, not guessed):

* DNSBL **python** mode (the ONLY mode on ``next``): the manifest build loads
  the feed into ``dataDB`` as EXACT entries (zone-file/TLD classification is the
  out-of-scope TLD feature). ``evaluate_domain``
  (``pfb_unbound.py:evaluate_domain``) looks the name up in ``dataDB`` EXACTLY.
  The response shape is:

  - ``logging='disabled_log'`` (the default, and every retired VIP marker since
    issue #4053) → ``logging_type='2'`` → NOERROR + A = ``0.0.0.0``. (**NULL** shape.)
  - ``logging='disabled'`` → ``logging_type='2'`` → ``null_blocking=True``
    → NOERROR + A = ``0.0.0.0`` / AAAA = ``::0``. (**NULL** shape.)
  - ``logging='nxdomain_log'`` → ``logging_type='3'`` → ``operate()`` returns a
    bare ``RCODE_NXDOMAIN`` (no records). (**NXDOMAIN** shape, issue #31.)

  A matched subdomain is NOT in ``dataDB`` and is NOT blocked (exact match only).
  Before issue #31 NXDOMAIN was reachable only via SafeSearch; it is now also a
  user-selectable DNSBL block response (the ``nxdomain``/``nxdomain_log`` modes).

  Probed ON-BOX (``drill @127.0.0.1`` over SSH): verified on a live box that
  python-mode DNSBL has NO localhost exemption — a blocked name returns its block
  shape even for a 127.0.0.1 query. (The QEMU SLIRP WAN-hostfwd path, unlike a real
  LAN client, is not answered in CI — so we don't use it.)

  One domain constraint, load-bearing (see ``helpers.unique_domain``):
  test names must NOT use RFC 6761 TLDs (``.test`` / ``.example`` / …) — DNSBL runs in
  the pfB-DNS decider, which answers a LISTED name there before Unbound is asked
  (listed ``.test`` / ``.example`` / ``.invalid`` names get the null answer), but
  an UNLISTED name (a not-blocked probe) under ``.test`` / ``.invalid`` reaches
  Unbound's built-in ``local-zone`` and is answered NXDOMAIN, not by the stub upstream.
  A random ``uuid-*.com`` satisfies it.
* WHITELIST (``suppression``): ``whitelist_check_domain`` short-circuits before
  any block shape, so a suppressed name resolves via its control ``local-data``.
* DNSBL-IP dual-stack (``action != 'Disabled'``): IP literals in the DNSBL feed
  split by family into ``<header>_v4.ip``/``_v6.ip`` (``inc:8596-8617``,
  ``8688-8702``), merged into ``DNSBLIP_v4.txt``/``_v6.txt`` (``inc:8869-8931``),
  loaded into the per-family alias tables ``pfB_DNSBLIP_v4`` AND
  ``pfB_DNSBLIP_v6`` (``inc:9306``); each holds only its own family.

These need the booted ``smoke_vm`` fixture, the branch ``.pkg`` (``SMOKE_PKG``),
and the smoke deps; without them they skip cleanly.
"""

from __future__ import annotations

import base64
import json
import os
import re
import shlex
import time
from collections.abc import Callable, Iterator
from functools import partial

import pytest

from tests.test_issue3222_soa_wire import rr_has_type

from . import helpers as h
from .conftest import PFSENSE_LAN_IP, STUB_DNS_A, SmokeVM, _MockFeedServer, _StubDnsServer

pytestmark = pytest.mark.smoke


@pytest.fixture(scope="module")
def deployed_vm(smoke_vm: SmokeVM, client_vm: SmokeVM, stub_dns: _StubDnsServer) -> Iterator[SmokeVM]:
    """Deploy the branch .pkg once for the matrix; the per-case egress block is
    managed by ``CaseContext``, NOT here.

    Egress stays OPEN during a pfBlockerNG reload (the DNSBL update path needs a
    working resolver/network) and ``CaseContext`` blocks it only for the per-case
    DNS probe. The probe stays hermetic because every name the matrix asserts
    resolves LOCALLY — a blocked name is intercepted by the python module before
    the forwarder, and a control/whitelist name answers from its injected host
    override — so the probe never needs the real internet. A not-blocked,
    no-control name resolves via the runner-side mock (``use_system_dns_upstream``:
    pfSense forwards to the SLIRP host alias 192.168.89.2, which libslirp NATs to the mock) — a known
    answer, AND recorded, so "was it blocked?" is read off the upstream, not inferred
    from a SERVFAIL. deploy() needs no egress for dependencies either — the pre-baked
    image ships pfBlockerNG's RUN_DEPENDS, so ``pkg add`` resolves them from the local
    pkg db offline. unblock on teardown as a safety net.
    """
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    # Snapshot the DNSBL-OFF unbound.conf so dump_diagnostics can diff what the
    # DNSBL reload changes (incl. whether it drops custom access-control).
    h.snapshot_unbound_conf(smoke_vm)
    h.snap_state(smoke_vm, "deployed")
    # dns_probe queries on-box (drill @127.0.0.1) — no localhost exemption — so no
    # WAN/ACL plumbing is needed.
    # Point pfSense at the controlled mock via its System-DNS path BEFORE any per-test
    # unbound-config snapshot (test_dnsbl_unbound_config_immutable), so the forwarding
    # config is part of the baseline and the DNSBL reload still adds only python.
    h.use_system_dns_upstream(smoke_vm)
    h.snap_state(smoke_vm, "upstream")
    h.assert_link_health(client_vm, smoke_vm, control_name=h.unique_domain())
    try:
        yield smoke_vm
    finally:
        h.unblock_egress()
        # ALWAYS collect a full guest snapshot (all /var/log, dmesg, pf, unbound,
        # scrubbed config.xml) for the workflow to upload — for this debug and for
        # after-the-fact analysis. Best-effort; never masks a test result.
        h.collect_host_diagnostics(smoke_vm)


# --------------------------------------------------------------------------- #
# 1) IP path — alias-table membership (positive + negative) + rule reference
# --------------------------------------------------------------------------- #


def test_ip_alias_table_and_rule(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """A fed IP is a table member, a non-fed IP is NOT, and a rule references it.

    Positive + negative member on the real ``pfctl`` path: the fed
    ``198.51.100.5`` must be in ``pfB_<alias>`` and the never-fed
    ``198.51.100.99`` must be absent (a table that swallowed everything, or a
    stale table, would fail the negative). A loaded pf rule must reference the
    alias (proves the table is actually wired into the ruleset, not orphaned).
    """
    fed_ip = "198.51.100.5"
    non_fed = "198.51.100.99"
    feed_url = h.write_local_feed(deployed_vm, "smoke_ip_matrix.txt", f"{fed_ip}\n")
    spec = h.IpCase(aliasname="smokeipmtx", feed_url=feed_url, header="smokeipmtx")
    with h.CaseContext(deployed_vm, spec):
        members = h.pfctl_table_members(deployed_vm, spec.alias)
        assert h.member_present(members, fed_ip), f"{fed_ip} not in {spec.alias}: {members}"
        assert not h.member_present(members, non_fed), f"{non_fed} unexpectedly in {spec.alias}: {members}"
        assert h.pfctl_rule_has_alias(deployed_vm, spec.alias), f"no loaded pf rule references {spec.alias}"


# --------------------------------------------------------------------------- #
# 2) DNSBL path — the response-shape matrix (pinned to pfb_unbound.py)
# --------------------------------------------------------------------------- #


# Resolver fixtures the immutability test seeds BEFORE pfB-DNS moves the Resolver, so the baseline carries a host
# entry and a server directive whose loss a DNSBL reload could cause.
_IMMUT_HOST_IP = "192.0.2.77"  # RFC 5737 documentation address, inert
_IMMUT_TUNING = "outbound-msg-retry: 7"  # a server directive pfSense never generates, with a non-default value
_IMMUT_CUSTOM_OPTIONS = f"server:\n{_IMMUT_TUNING}\n"
_CFG_CUSTOM_OPTIONS = "unbound/custom_options"


def _seed_resolver_fixtures(vm: SmokeVM, host: str) -> None:
    """A Host Override for ``host`` and a server directive in the Resolver's Custom Options, applied to Unbound."""
    h.set_control_records(vm, {host: {"A": _IMMUT_HOST_IP}}, {})
    encoded = base64.b64encode(_IMMUT_CUSTOM_OPTIONS.encode()).decode()
    result = h.php_eval(
        vm,
        f"config_set_path({h._php_str(_CFG_CUSTOM_OPTIONS)}, {h._php_str(encoded)});\n"
        "write_config('pfBlockerNG smoke: seed a Resolver server directive');\n"
        "services_unbound_configure();\n"
        "echo 'OK';",
    )
    assert result.returncode == 0 and "OK" in result.stdout, f"seeding Custom Options failed: {result!r}"


def _remove_host_override(vm: SmokeVM, host: str) -> None:
    label, _, domain = host.partition(".")
    result = h.php_eval(
        vm,
        f"$hosts = config_get_path({h._php_str(h.CFG_UNBOUND_HOSTS)}, array());\n"
        "$hosts = array_values(array_filter($hosts, function($r) {\n"
        f"  return ($r['host'] ?? '') !== {h._php_str(label)} || ($r['domain'] ?? '') !== {h._php_str(domain)};\n"
        "}));\n"
        f"config_set_path({h._php_str(h.CFG_UNBOUND_HOSTS)}, $hosts);\n"
        "write_config('pfBlockerNG smoke: remove the immutability host override');\n"
        "services_unbound_configure();\n"
        "echo 'OK';",
    )
    assert result.returncode == 0 and "OK" in result.stdout, f"removing the host override failed: {result!r}"


def _restore_resolver_fixtures(vm: SmokeVM, host: str, prior: dict[str, tuple[bool, str]]) -> list[Exception]:
    """Give the Resolver back (pfB-DNS off first, so its snapshot is restored), then undo every seeded value.

    Every step runs, in this order, whatever an earlier one raised, so one failure cannot leave a seeded value
    behind for later modules. The failures come back, each noted with its step, for the caller to report.
    """
    errors: list[Exception] = []

    def step(what: str, run: Callable[[], None]) -> None:
        try:
            run()
        except Exception as exc:
            exc.add_note(f"restoring the Resolver fixtures: {what}")
            errors.append(exc)

    step("release pfB-DNS", lambda: h.release_pfb_dns(vm))
    for path, state in prior.items():
        step(f"restore {path}", partial(h.config_restore_state, vm, path, state))
    step("remove the host override", lambda: _remove_host_override(vm, host))
    return errors


def test_dnsbl_unbound_config_immutable(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """A DNSBL reload under pfB-DNS only adds python-module config to unbound.conf.

    DNSBL runs only through pfB-DNS (#3770), and pfB-DNS moves the DNS Resolver
    (``interface-automatic`` becomes ``interface: 127.0.0.1`` / ``::1`` and the
    forward-zone is rewritten): those lines are pfB-DNS's to change, not the DNSBL
    reload's. The baseline is therefore taken AFTER pfB-DNS has moved the Resolver
    and BEFORE the DNSBL reload. From there pfBlockerNG is allowed exactly ONE
    class of change to Unbound's configuration: adding python-module directives
    (``module-config``, ``python-script``, pfBlockerNG managed ``include`` lines).  No other configuration —
    access-control, forward-zones, host entries, server tuning — may be removed or
    altered.

    The Resolver carries a unique Host Override and a server directive in Custom
    Options before pfB-DNS moves it, and the baseline must hold both, so a reload
    that dropped either class is caught; every seeded value is restored afterwards.

    This guards against pfBlockerNG silently clobbering custom Unbound config
    (e.g. the DNS-Resolver ACLs in access_lists.conf) during a reload.
    """
    vm = deployed_vm
    host = h.unique_domain("cfgimmut-host")
    prior = {
        path: h.config_get_state(vm, path)
        for path in (_CFG_CUSTOM_OPTIONS, f"{h.CFG_GLOBAL}/enable_cb", h.dns_config_path("pfb_dns"))
    }
    try:
        _seed_resolver_fixtures(vm, host)
        # pfB-DNS next, with no DNSBL list: pfBlockerNG enabled and the toggle on make its
        # apply move the Resolver (the proxy runs --no-module). Its own changes are not under test here.
        h.config_set(vm, f"{h.CFG_GLOBAL}/enable_cb", "on")
        h.config_set(vm, h.dns_config_path("pfb_dns"), "on")
        h.reload(vm, "updatednsbl")
        assert h._pfb_dns_moved(vm), "baseline: pfB-DNS did not take the Resolver"
        # Baseline the EFFECTIVE unbound config (unbound.conf + all *.conf includes,
        # so access_lists.conf, host_entries.conf etc. are covered) AND the live ACLs, with pfB-DNS
        # holding the Resolver, BEFORE DNSBL is applied. The case carries no control records, so
        # the only legitimate delta is pfBlockerNG's python-module config.
        h.snapshot_unbound_effective(vm)
        baseline = vm.ssh("cat", h.UNBOUND_SETUP)
        assert baseline.returncode == 0 and baseline.stdout.strip(), (
            f"baseline: the effective-config snapshot {h.UNBOUND_SETUP} is empty (the assertion would pass vacuously)"
        )
        lines = [ln.strip() for ln in baseline.stdout.splitlines()]
        assert any(ln.startswith("local-data:") and host in ln and _IMMUT_HOST_IP in ln for ln in lines), (
            f"baseline: the host override for {host} is not a local-data line:\n{baseline.stdout}"
        )
        assert _IMMUT_TUNING in lines, (
            f"baseline: Custom Options' {_IMMUT_TUNING!r} is not in the config:\n{baseline.stdout}"
        )
        acls_before = h.unbound_access_control(vm)
        assert acls_before, "baseline: the live Unbound enforces no access-control"
        domain = h.unique_domain("cfgimmut")
        feed_url = h.write_local_feed(vm, "smoke_cfgimmut.txt", f"{domain}\n")
        spec = h.DnsblCase(aliasname="smokecfgimmut", feed_url=feed_url, header="smokecfgimmut")
        with h.CaseContext(vm, spec):
            h.assert_unbound_adds_only_python_config(vm)
            # Authoritative ACL check via the daemon itself (unbound-control), not a
            # file grep: the DNSBL reload must not drop/alter the resolver ACLs.
            acls_after = h.unbound_access_control(vm)
            assert acls_after == acls_before, (
                f"DNSBL reload changed Unbound ACLs: before={sorted(acls_before)} after={sorted(acls_after)}"
            )
    except BaseException as failure:
        for error in _restore_resolver_fixtures(vm, host, prior):
            failure.add_note(f"restoring the Resolver fixtures also failed: {error!r}")
        raise
    errors = _restore_resolver_fixtures(vm, host, prior)
    if errors:
        raise ExceptionGroup("restoring the Resolver fixtures failed", errors)


def test_dnsbl_python_exact_null(deployed_vm: SmokeVM, client_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """Python-mode exact block: NOERROR + 0.0.0.0 for the listed domain; subdomain passes.

    Verified on the live box: the manifest build loads the feed into ``dataDB``
    as EXACT entries.  ``evaluate_domain`` looks the name up in ``dataDB`` EXACTLY
    — the default ``logging`` → NOERROR + A = ``0.0.0.0``.
    A subdomain is NOT in ``dataDB`` and resolves normally (exact, not wildcard).
    Probed on-box (``drill @127.0.0.1``); python-mode has no localhost exemption,
    so the block shows there. Domain is a unique non-RFC-6761 ``.com`` so no
    Unbound local-zone shadows it.
    """
    domain = h.unique_domain("blocked")
    sub = f"x.{domain}"
    sub_ip = "198.51.100.40"
    feed_url = h.write_local_feed(deployed_vm, "smoke_dnsbl_exact.txt", f"{domain}\n")
    spec = h.DnsblCase(
        aliasname="smokeexact",
        feed_url=feed_url,
        header="smokeexact",
        control_local_data={sub: {"A": sub_ip}},
    )
    with h.CaseContext(deployed_vm, spec):
        blocked = h.dns_probe_client(client_vm, domain, "A")
        assert h.is_null_ip(blocked), f"{domain} expected {h.NULL_IP4}, got {blocked}"
        # EXACT match: subdomain NOT in dataDB, resolves to its control answer.
        passed = h.dns_probe_client(client_vm, sub, "A")
        assert h.resolves_to(passed, sub_ip), f"{sub} should resolve to {sub_ip} (exact != wildcard), got {passed}"
        assert not h.is_null_ip(passed), f"{sub} wrongly null-blocked (exact match, not wildcard): {passed}"


_SECTION_COUNTS = re.compile(
    r"ANSWER:\s*(\d+).*AUTHORITY:\s*(\d+).*ADDITIONAL:\s*(\d+)",
    re.IGNORECASE | re.DOTALL,
)


def _header_counts(raw: str) -> tuple[int | None, int | None, int | None]:
    """Parse ANSWER/AUTHORITY/ADDITIONAL counts from a dig or drill header line."""
    m = _SECTION_COUNTS.search(raw)
    if m is None:
        return None, None, None
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def _raw_dig(client_vm: SmokeVM, name: str, rtype: str) -> str:
    result = client_vm.ssh(
        f"dig +tries=1 +time=5 {shlex.quote(rtype)} {shlex.quote(name)} @{shlex.quote(PFSENSE_LAN_IP)}",
        timeout=30.0,
    )
    return result.stdout


def _raw_drill(vm: SmokeVM, name: str, rtype: str) -> str:
    drill_type = "TYPE65" if rtype == "HTTPS" else rtype
    result = vm.ssh(f"{h.DRILL_BIN} {name} {drill_type} @127.0.0.1", timeout=30.0)
    return result.stdout


def test_dnsbl_https_svcb_nodata_soa(deployed_vm: SmokeVM, client_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """Issue #3222: null-blocked HTTPS/SVCB is RFC 2308 Type-2 NODATA (SOA), not empty NOERROR.

    Control: the listed name's A query is the null answer, so DNSBL python-mode
    is armed. Then the same name is queried as HTTPS, TYPE64, and MX
    from both the LAN client (``dig``, the iOS-like path) and on-box
    (``drill @127.0.0.1``).

    Non-address intercepts must return NOERROR with ANSWER 0 and AUTHORITY 1
    (a synthetic SOA). Empty AUTHORITY is the pre-fix defect. dnsbl.log hits
    must grow after the HTTPS/SVCB queries (the A control already logs one).
    """
    blocked = h.unique_domain("https3222")
    control = h.unique_domain("https3222ctl")
    feed_url = h.write_local_feed(deployed_vm, "smoke_dnsbl_https3222.txt", f"{blocked}\n")
    spec = h.DnsblCase(
        aliasname="smokehttps3222",
        feed_url=feed_url,
        header="smokehttps3222",
    )
    with h.CaseContext(deployed_vm, spec):
        a = h.dns_probe_client(client_vm, blocked, "A")
        assert h.is_null_ip(a), f"{blocked} A expected {h.NULL_IP4}, got {a}"
        hits_after_a = _dnsbl_log_hits(deployed_vm, blocked)

        dumps: list[str] = []
        for rtype in ("HTTPS", "TYPE64", "MX"):
            lan = _raw_dig(client_vm, blocked, rtype)
            box = _raw_drill(deployed_vm, blocked, rtype)
            dumps.append(f"=== blocked {rtype} LAN dig ===\n{lan}\n=== blocked {rtype} on-box drill ===\n{box}")
            parsed = h.dns_probe_client(client_vm, blocked, rtype)
            lan_an, lan_ns, lan_ar = _header_counts(lan)
            box_an, box_ns, box_ar = _header_counts(box)
            dump = "\n".join(dumps)
            assert parsed.rcode == "NOERROR", (
                f"{blocked} {rtype} expected NOERROR, got {parsed.rcode} records={parsed.records!r}\n{dump}"
            )
            assert parsed.records == [], f"{blocked} {rtype} expected empty ANSWER, got {parsed.records!r}\n{dump}"
            assert lan_an == 0 and lan_ns == 1, (
                f"{blocked} {rtype} LAN expected ANSWER=0 AUTHORITY=1 (SOA), "
                f"got ANSWER={lan_an} AUTHORITY={lan_ns} ADDITIONAL={lan_ar}\n{dump}"
            )
            assert box_an == 0 and box_ns == 1, (
                f"{blocked} {rtype} on-box expected ANSWER=0 AUTHORITY=1 (SOA), "
                f"got ANSWER={box_an} AUTHORITY={box_ns} ADDITIONAL={box_ar}\n{dump}"
            )
            assert rr_has_type(lan, "SOA"), f"{blocked} {rtype} LAN expected an SOA in AUTHORITY\n{dump}"
            assert rr_has_type(box, "SOA"), f"{blocked} {rtype} on-box expected an SOA in AUTHORITY\n{dump}"

        ctl_a = h.dns_probe_client(client_vm, control, "A")
        assert not h.is_null_ip(ctl_a), f"{control} A must not be null-blocked (unlisted), got {ctl_a}"

        dump = "\n".join(dumps)
        h.wait_until(
            lambda: _dnsbl_log_hits(deployed_vm, blocked) > hits_after_a,
            timeout=20.0,
            interval=1.0,
        )
        assert _dnsbl_log_hits(deployed_vm, blocked) > hits_after_a, (
            f"dnsbl.log did not grow after HTTPS/SVCB queries (after A hits={hits_after_a}); dumps:\n{dump}"
        )


def test_dnsbl_exact_null(deployed_vm: SmokeVM, client_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """Python-mode null sinkhole: NOERROR + 0.0.0.0/::0 for a logging='disabled' feed.

    ``logging='disabled'`` → ``logging_type='2'`` → ``null_blocking=True`` →
    pfb_unbound.py answers NOERROR + A 0.0.0.0 / AAAA ::0 — purely the per-list
    ``logging='disabled'`` path.
    """
    domain = h.unique_domain("null")
    feed_url = h.write_local_feed(deployed_vm, "smoke_dnsbl_null.txt", f"{domain}\n")
    spec = h.DnsblCase(
        aliasname="smokenull",
        feed_url=feed_url,
        header="smokenull",
        mode=h.DnsblMode.NULL,
    )
    with h.CaseContext(deployed_vm, spec):
        a = h.dns_probe_client(client_vm, domain, "A")
        assert h.is_null_ip(a), f"{domain} A expected {h.NULL_IP4}, got {a}"
        aaaa = h.dns_probe_client(client_vm, domain, "AAAA")
        assert h.is_null_ip(aaaa, null_ip="::0"), f"{domain} AAAA expected ::0, got {aaaa}"


def test_dnsbl_exact_nxdomain(deployed_vm: SmokeVM, client_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """Python-mode NXDOMAIN block (issue #31): a bare NXDOMAIN, no records.

    ``logging='nxdomain_log'`` → ``logging_type='3'`` → ``operate()`` returns
    ``RCODE_NXDOMAIN`` with no DNSMessage (neither the VIP nor the 0.0.0.0 null
    shape). The rcode is name-level, so BOTH the A and AAAA queries answer
    NXDOMAIN. A unique ``.com`` is used so the result is the
    NXDOMAIN block path itself, not the NXDOMAIN Unbound's built-in ``local-zone``
    gives an unlisted name under an RFC-6761 TLD. Contrast the
    VIP/null cases above: same feed match, different per-list ``logging`` →
    different response shape, proving '3' is a distinct, live branch.
    """
    domain = h.unique_domain("nxdomain")
    feed_url = h.write_local_feed(deployed_vm, "smoke_dnsbl_nxdomain.txt", f"{domain}\n")
    spec = h.DnsblCase(
        aliasname="smokenxd",
        feed_url=feed_url,
        header="smokenxd",
        mode=h.DnsblMode.NXDOMAIN,
    )
    with h.CaseContext(deployed_vm, spec):
        a = h.dns_probe_client(client_vm, domain, "A")
        assert h.is_nxdomain(a), f"{domain} A expected NXDOMAIN (no records), got {a}"
        assert not h.is_null_ip(a), f"{domain} must be a bare NXDOMAIN, not a null record: {a}"
        aaaa = h.dns_probe_client(client_vm, domain, "AAAA")
        assert h.is_nxdomain(aaaa), f"{domain} AAAA expected NXDOMAIN (no records), got {aaaa}"


@pytest.mark.parametrize("mode", ["nodata_log", "nodata"])
def test_dnsbl_selected_nodata_soa(deployed_vm: SmokeVM, client_vm: SmokeVM, mode: str) -> None:
    """Selecting NODATA replaces address replies with NOERROR and an authority SOA."""
    domain = h.unique_domain("nodata3243")
    header = "smoke" + mode.replace("_", "") + "3243"
    feed_url = h.write_local_feed(deployed_vm, f"{header}.txt", f"{domain}\n")
    spec = h.DnsblCase(aliasname=header, feed_url=feed_url, header=header, mode=h.DnsblMode.NULL)
    with h.CaseContext(deployed_vm, spec):
        before = h.dns_probe_client(client_vm, domain, "A")
        assert h.is_null_ip(before), f"{domain} expected initial null block, got {before}"
        h.config_set(deployed_vm, f"{h.CFG_DNSBL_SETTINGS}/global_log_mode", "override")
        h.config_set(deployed_vm, f"{h.CFG_DNSBL_SETTINGS}/global_log", mode)
        h.reload(deployed_vm, "updatednsbl")
        for rtype in ("A", "AAAA", "ANY", "HTTPS", "TYPE64", "MX"):
            for raw in (_raw_dig(client_vm, domain, rtype), _raw_drill(deployed_vm, domain, rtype)):
                assert "rcode: NOERROR" in raw or "status: NOERROR" in raw, f"{mode} {rtype}:\n{raw}"
                answers, authority, _ = _header_counts(raw)
                assert (answers, authority) == (0, 1), f"{mode} {rtype} expected ANSWER=0 AUTHORITY=1:\n{raw}"
                assert rr_has_type(raw, "SOA"), f"{mode} {rtype} expected an authority SOA:\n{raw}"


# IDN homoglyph protection — Confusable mode (ADR-08). The block comes from the
# matcher's TR39 mixed-script analyzer (pfb_unbound.py classify_idn), NOT a feed
# entry — the feed below is one innocuous filler so the DNSBL list/alias is real and
# python mode is active; ``idn_mode='confusable'`` is what arms the analyzer.


def test_dnsbl_idn_confusable_blocks_homoglyph_resolves_legit(
    deployed_vm: SmokeVM, client_vm: SmokeVM, mock_feeds: _MockFeedServer
) -> None:
    """Confusable mode blocks a cross-script homoglyph (null) but resolves a legit IDN.

    Scenario: ``pfb_idn='confusable'`` + ``block_malicious`` ON (default). The
    matcher decodes each ``xn--`` label, runs the TR39 analyzer per-label, and:
      * ``xn--pple-43d`` (аpple — Cyrillic U+0430 + Latin) is a confusable Latin+
        Cyrillic mix → MALICIOUS → blocked as feed ``Homoglyph`` (log_type '1')
        → NOERROR + ``0.0.0.0``.
      * ``xn--mnchen-3ya`` (münchen — single-script Latin) is legit → NO IDN action,
        so it resolves via the controlled stub upstream (the before-state: green
        proves the analyzer is the cause of the block, not an always-block path).
    Probed on-box (``drill @127.0.0.1``); python-mode has no localhost exemption.
    NOTE: no ``control_local_data`` override on ``legit`` — a host override is served
    as local-data BEFORE the python module and would mask a broken analyzer as a
    pass (#582); egress is unblocked so the legit probe reaches the stub for real.
    """
    homoglyph = "xn--pple-43d.com"  # аpple — Latin+Cyrillic confusable → MALICIOUS
    legit = "xn--mnchen-3ya.com"  # münchen — single-script Latin → legit
    feed_url = h.write_local_feed(deployed_vm, "smoke_idn_confusable.txt", f"{h.unique_domain('idnfiller')}\n")
    spec = h.DnsblCase(
        aliasname="smokeidn",
        feed_url=feed_url,
        header="smokeidn",
        idn_mode="confusable",
        idn_block_malicious=True,
        idn_escalate_suspicious=False,
    )
    with h.CaseContext(deployed_vm, spec):
        # Before-state: the legit single-script IDN is NOT blocked — resolves via
        # the stub (egress unblocked so the un-blocked probe reaches it).
        h.unblock_egress()
        legit_ans = h.dns_probe_client(client_vm, legit, "A")
        assert h.resolves_to(legit_ans, STUB_DNS_A), f"legit IDN {legit} should resolve via stub, got {legit_ans}"
        assert not h.is_null_ip(legit_ans), f"legit IDN {legit} must NOT be blocked (FALSE POSITIVE): {legit_ans}"
        # The confusable homograph blocks with the null answer.
        blocked = h.dns_probe_client(client_vm, homoglyph, "A")
        assert h.is_null_ip(blocked), f"homoglyph {homoglyph} (Latin+Cyrillic) expected {h.NULL_IP4}, got {blocked}"


def test_dnsbl_idn_confusable_block_malicious_off_alerts_only(
    deployed_vm: SmokeVM, client_vm: SmokeVM, mock_feeds: _MockFeedServer
) -> None:
    """The ``block_malicious`` sub-toggle is a real branch: OFF → the SAME homograph
    only alerts (resolves), not blocks.

    Same confusable ``xn--pple-43d`` (аpple) as the positive case, but with
    ``block_malicious`` OFF: ``idn_confusable_action`` maps MALICIOUS → ALERT, so
    ``is_found`` stays False and the name resolves via the controlled stub upstream.
    Paired with the block-on case above (same input, toggle flipped) this proves it
    is the toggle, not an always-resolve path. NOTE: no ``control_local_data``
    override — it would be served as local-data BEFORE the python module and mask a
    broken toggle as a pass (#582); egress is unblocked so the probe reaches the
    stub for real.
    """
    homoglyph = "xn--pple-43d.com"  # аpple — MALICIOUS, but block_malicious is OFF
    feed_url = h.write_local_feed(deployed_vm, "smoke_idn_alert.txt", f"{h.unique_domain('idnfiller')}\n")
    spec = h.DnsblCase(
        aliasname="smokeidnalert",
        feed_url=feed_url,
        header="smokeidnalert",
        idn_mode="confusable",
        idn_block_malicious=False,  # malicious → ALERT only (no block)
    )
    with h.CaseContext(deployed_vm, spec):
        h.unblock_egress()
        ans = h.dns_probe_client(client_vm, homoglyph, "A")
        assert h.resolves_to(ans, STUB_DNS_A), f"block_malicious OFF: {homoglyph} should resolve via stub, got {ans}"
        assert not h.is_null_ip(ans), f"block_malicious OFF must NOT block the homograph (alert only): {ans}"


def test_dnsbl_whitelist_passthrough(deployed_vm: SmokeVM, client_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """WHITELIST: a domain on the whitelist AND in the block feed RESOLVES.

    ``suppression`` short-circuits before any block shape, so the name resolves via
    the controlled stub upstream (a true pass) — NOT NXDOMAIN/null/VIP. NOTE: no
    ``control_local_data`` override — it would be served as local-data BEFORE the
    python module and mask a broken suppression check as a pass (#582); egress is
    unblocked so the probe reaches the stub for real.
    """
    domain = h.unique_domain("allowed")
    feed_url = h.write_local_feed(deployed_vm, "smoke_dnsbl_white.txt", f"{domain}\n")
    spec = h.DnsblCase(
        aliasname="smokewhite",
        feed_url=feed_url,
        header="smokewhite",
        whitelist=[domain],
    )
    with h.CaseContext(deployed_vm, spec):
        h.unblock_egress()
        answer = h.dns_probe_client(client_vm, domain, "A")
        assert h.resolves_to(answer, STUB_DNS_A), f"whitelisted {domain} should resolve via stub, got {answer}"
        assert not h.is_null_ip(answer), f"whitelisted {domain} wrongly null-blocked: {answer}"
        assert not h.is_null_ip(answer), f"whitelisted {domain} wrongly null-IP: {answer}"


def test_dnsbl_whitelist_wildcard_not_demoted_by_www(
    deployed_vm: SmokeVM, client_vm: SmokeVM, mock_feeds: _MockFeedServer
) -> None:
    """WHITELIST: `.apex` plus later `www.apex` must still cover `sub.apex` (issue #3191).

    Last-wins normalisation used to demote the leading-dot wildcard to exact when a
    www-stripped line collided on the same key, so a feed block of ``sub.{apex}``
    leaked through as VIP/NULL. Exact-name passthrough would not have caught that.
    """
    apex = h.unique_domain("wlwild")
    blocked = f"sub.{apex}"
    feed_url = h.write_local_feed(deployed_vm, "smoke_dnsbl_white_wild.txt", f"{blocked}\n")
    spec = h.DnsblCase(
        aliasname="smokewlwild",
        feed_url=feed_url,
        header="smokewlwild",
        whitelist=[f".{apex}", f"www.{apex}"],
    )
    with h.CaseContext(deployed_vm, spec):
        h.unblock_egress()
        answer = h.dns_probe_client(client_vm, blocked, "A")
        assert h.resolves_to(answer, STUB_DNS_A), (
            f"wildcard-whitelisted {blocked} should resolve via stub, got {answer}"
        )
        assert not h.is_null_ip(answer), f"wildcard-whitelisted {blocked} wrongly null-blocked: {answer}"
        assert not h.is_null_ip(answer), f"wildcard-whitelisted {blocked} wrongly null-IP: {answer}"


# ADR-10: several bounded wait-for-apply round-trips per case (each swap blocks PHP
# until the watcher confirms the applied generation -- seconds, not the old async poll)
# plus per-case setup exceed the smoke harness's 30s per-test cap; override it.
@pytest.mark.timeout(120)
def test_dnsbl_resolve_block_unlock_relock_lifecycle(
    deployed_vm: SmokeVM, client_vm: SmokeVM, mock_feeds: _MockFeedServer
) -> None:
    """#51 FULL lifecycle, asserting the ACTUAL resolution at every transition:

      (a) BEFORE any list  -> the domain RESOLVES (forwarded to the stub sentinel);
      (b) added to a feed  -> BLOCKED (null), no longer resolves;
      (c) temporary Unlock -> RESOLVES again (forwarded to the stub sentinel);
      (d) re-Lock          -> BLOCKED again (null).

    Proving the domain resolves in (a) and again in (c) rules out a false-green: the
    VIP in (b)/(d) genuinely comes from the feed block, and the pass in (c) genuinely
    comes from the Unlock. The Unlock/Lock drives the real python-mode
    ``pfblockerng_alerts.php`` ``dnsbl_remove`` sequence (toggle the ``pfb_unlock`` store
    -> regenerate ``config.user_unlock`` -> reload Unbound).

    ZERO-DOWNTIME (ADR-10, #51): the reload takes the no-restart DATA FAST PATH — PHP
    patches the manifest, flips the generation sentinel, and the in-module watcher rebuilds
    + atomically swaps the snapshot (a Lock additionally targeted-flushes that one name from
    the C-cache; an Unlock needs none since #43 stopped C-caching blocks). Unbound is NOT
    restarted, so its **pid is captured before and asserted UNCHANGED after** the whole
    Unlock/Lock sequence — proving the #51 flips apply with no restart. (Before the #51 fix
    step (c) was a NO-OP — it wrote files the manifest build no longer reads — so the domain
    stayed null-blocked; here it must resolve again.) The helper returns only after the
    applied-generation handshake; its targeted cache flush is conditional on Lock, so each
    following DNS probe is authoritative without a restart.

    NOTE: NO ``control_local_data`` host override on the name. A host override is served
    by Unbound as ``local-data`` BEFORE the python module runs, so it would shadow the
    DNSBL block (the name would resolve to the override even in step (b)). An *allowed*
    name therefore resolves via the controlled stub upstream (``STUB_DNS_A``) — exactly
    how ``test_dns_probe_absent_resolves_via_stub`` proves a real pass. Egress is left
    OPEN in the body so the allowed probes reach the (SLIRP-local, controlled) stub;
    the block probes return the VIP locally, so there is no false-green from egress.
    """
    domain = h.unique_domain("unlock")

    # (a) BEFORE any blocklist: forwarded to the controlled stub -> resolves to the
    #     sentinel (a real, observable baseline — not yet on any feed, not blocked).
    before = h.dns_probe_client(client_vm, domain, "A")
    assert h.resolves_to(before, STUB_DNS_A), f"{domain} should resolve via stub BEFORE listing, got {before}"
    assert not h.is_null_ip(before), f"{domain} unexpectedly blocked before any feed: {before}"

    # (b) Now put it on a DNSBL feed -> the SAME domain is now BLOCKED (null).
    feed_url = h.write_local_feed(deployed_vm, "smoke_dnsbl_unlock.txt", f"{domain}\n")
    spec = h.DnsblCase(aliasname="smokeunlock", feed_url=feed_url, header="smokeunlock")
    with h.CaseContext(deployed_vm, spec):
        h.unblock_egress()  # the allowed probes (a-shape) must reach the controlled stub
        # Listing the name is the feed/swap allow->block direction: the module already
        # mounted (a prior case), so first-enable applies via the no-restart swap. Flush
        # the pre-resolved answer before observing the new block.
        h.flush_unbound_name(deployed_vm, domain)
        blocked = h.dns_probe_client(client_vm, domain, "A")
        assert h.is_null_ip(blocked), f"{domain} still resolving after block: {blocked}"

        # NO-RESTART invariant: capture the DNSBL hosts' pids (Unbound's, the pfB-DNS gateway's) before the #51 flips.
        # Each flip takes the ADR-10 zero-downtime fast path, so neither pid may change.
        pids_before = h.dns_host_pids(deployed_vm)

        # (c) Temporary Unlock -> resolves again (forwarded to the stub sentinel).
        #     A VIP here would be the #51 no-op (unlock never reaching the build).
        #     The helper returns only after the applied-generation handshake.
        h.dnsbl_alert_lock_toggle(deployed_vm, domain, "unlock")
        unlocked = h.dns_probe_client(client_vm, domain, "A")
        assert not h.is_null_ip(unlocked), f"unlocked {domain} still null-blocked (the #51 no-op): {unlocked}"

        # (d) Re-Lock -> the temporary allow is removed: blocked again (null). allow->block
        #     here clears the prior resolved answer via the caller-owned targeted C-cache
        #     flush, so the VIP block is observable.
        h.dnsbl_alert_lock_toggle(deployed_vm, domain, "lock")
        relocked = h.dns_probe_client(client_vm, domain, "A")
        assert h.is_null_ip(relocked), f"re-locked {domain} still resolving: {relocked}"

        # The whole Unlock/Lock sequence applied with NO restart: pids unchanged.
        pids_after = h.dns_host_pids(deployed_vm)
        assert pids_after == pids_before, (
            f"#51 Unlock/Lock must apply via the no-restart zero-downtime swap, but a DNSBL host "
            f"restarted: (Unbound, pfB-DNS gateway) pids {pids_before} -> {pids_after}"
        )


# The ADR-10 sentinel PHP flips to wake the reload-watcher (pfblockerng.inc:6001);
# fixed host path (dnsbldir='/var/unbound').
_ADR10_SENTINEL = "/var/unbound/pfb_py_reload"
# The daemon-suppression marker pfb_reload_unbound() touches at the top of the fast
# path -- $pfb['dnsbl_file'] . '.sync' (pfblockerng.inc:153 dnsbl_file + inc:~7466).
_ADR10_SYNC_MARKER = "/var/unbound/pfb_dnsbl.sync"


@pytest.mark.timeout(180)  # ADR-10: this forces the restart FALLBACK (a full Unbound restart).
def test_dnsbl_sentinel_flip_failure_clears_sync_marker(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """ADR-10 fallback: a failed sentinel flip must NOT leak the '.sync' daemon-suppression
    marker (issue #713 bug 3).

    ``pfb_reload_unbound()``'s zero-downtime fast path touches ``<dnsbl_file>.sync`` (to
    suppress the DNSBL Queries daemon's control-socket use during the swap) BEFORE
    attempting the sentinel flip. On a successful swap it clears that marker itself before
    returning -- the #51 alerts-page caller (``pfblockerng_alerts.php``) has NO later
    ``clear_work_files`` call (unlike the CLI ``update``/``updatednsbl`` verbs, whose
    ``pfb_update_unbound()`` always clears it at the end regardless of which branch ran),
    so the marker must be cleared on every exit from the fast path, not just the happy
    one. Before this fix, BOTH fallback branches ("sentinel flip failed" and "swap not
    confirmed in time") fell through to the restart WITHOUT clearing it, leaking a
    suppressed DNSBL Queries daemon until the next full update.

    This pins the "sentinel flip failed" branch specifically: it fails SYNCHRONOUSLY
    (no 30s wait) and never touches the DNSBL manifest, so it is safe to induce on the
    shared session VM. The ADR-10 sentinel (``/var/unbound/pfb_py_reload``) is replaced
    with a DIRECTORY, so ``pfb_unbound_py_atomic_write()``'s publishing ``rename()`` fails
    deterministically (EISDIR) -- the manifest itself is untouched, so the restart's
    cold-start rebuild that follows is unaffected. The #51 sequence is replayed via
    ``pfSsh.php`` exactly as ``pfblockerng_alerts.php``'s ``dnsbl_remove`` handler does
    (mirroring ``helpers.dnsbl_alert_lock_toggle``, minus its trailing swap-applied wait --
    no swap occurs on this branch).

    Given a DNSBL-listed domain already blocked (null) by the CaseContext setup,
    When the ADR-10 sentinel is corrupted and a #51 temporary Unlock fires -- taking the
      fast path, which fails to flip and falls back to a full Unbound restart --
    Then the "sentinel flip failed" fallback log line appears (proving the branch under
      test actually ran), Unbound genuinely restarted (pid changed), and the '.sync'
      marker is ABSENT afterward -- the regression this fix guards.

    Teardown restores the sentinel to its ORIGINAL content (captured before corruption --
    never a fresh '1': the in-module watcher tracks a monotonically non-decreasing
    generation in memory, so resetting to a lower/absent value would silently desync
    every LATER fast-path swap in this session VM) and PROVES the fast path still works
    by running one more ordinary #51 action and relying on
    ``dnsbl_alert_lock_toggle``'s own swap-applied wait (raises loudly on timeout) -- so a
    bad restore fails HERE, not as a mysterious later test failure.
    """
    domain = h.unique_domain("sentinelfail")
    feed_url = h.write_local_feed(deployed_vm, "smoke_dnsbl_sentinelfail.txt", f"{domain}\n")
    spec = h.DnsblCase(aliasname="smokesentinelfail", feed_url=feed_url, header="smokesentinelfail")
    with h.CaseContext(deployed_vm, spec):
        # Given: the domain is already null-blocked by CaseContext's own (healthy) reload.
        blocked_before = h.dns_probe(deployed_vm, domain, "A")
        assert h.is_null_ip(blocked_before), (
            f"{domain} expected a null block before the sentinel corruption, got {blocked_before}"
        )

        pids_before = h.dns_host_pids(deployed_vm)
        fail_log_before = h.count_log_marker(deployed_vm, h.PFB_LOG, "ADR-10: sentinel flip failed")
        # Pre-condition, not the regression under test: a marker already present here
        # would mean an EARLIER case/module leaked it, not this one.
        assert not h.hook_marker_exists(deployed_vm, _ADR10_SYNC_MARKER), (
            f"'.sync' marker unexpectedly present BEFORE this test runs: {_ADR10_SYNC_MARKER} "
            f"-- an earlier case/module leaked it (not this test's regression)"
        )

        # Capture the sentinel's PRIOR content (for restoration), then corrupt it.
        capture = h.php_eval(
            deployed_vm,
            f"$s = {h._php_str(_ADR10_SENTINEL)};\n"
            "$prior = @file_get_contents($s);\n"
            f"echo ($prior === FALSE) ? 'ABSENT' : "
            f"({h._php_str(h._CFG_VAL_OPEN)} . $prior . {h._php_str(h._CFG_VAL_CLOSE)});\n"
            "@unlink($s);\n"
            "@mkdir($s, 0755);\n"
            "@chown($s, 'unbound'); @chgrp($s, 'unbound');\n"
            "echo '|CORRUPTED';",
            timeout=30.0,
        )
        assert "CORRUPTED" in capture.stdout, (
            f"failed to corrupt the ADR-10 sentinel: rc={capture.returncode} {capture.stderr!r} {capture.stdout!r}"
        )
        prior_start = capture.stdout.find(h._CFG_VAL_OPEN)
        prior_end = capture.stdout.find(h._CFG_VAL_CLOSE)
        prior_sentinel_content = None
        if prior_start != -1 and prior_end != -1:
            prior_sentinel_content = capture.stdout[prior_start + len(h._CFG_VAL_OPEN) : prior_end]

        try:
            # When: replay the #51 alerts-page temporary-Unlock sequence. The corrupted
            # sentinel makes pfb_unbound_py_flip_sentinel() fail, so pfb_reload_unbound()
            # falls back to pfb_stop_start_unbound() -- a REAL restart with the
            # UNCORRUPTED, freshly-published manifest (only the sentinel was touched), so
            # the restart's cold-start rebuild is unaffected.
            snippet = (
                "require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');\n"
                "pfb_global();\n"
                "$ua = pfb_dnsbl_unlock_action('unlock');\n"
                "$u = pfb_unlock('read', 'dnsbl', '', '', '');\n"
                f"pfb_unlock($ua['mode'], 'dnsbl', $u, {h._php_str(domain)}, 'python');\n"
                "pfb_unbound_python_sources_unlock();\n"
                "pfb_reload_unbound('enabled', FALSE, TRUE);\n"
                "echo 'OK';"
            )
            result = h.php_eval(deployed_vm, snippet, timeout=150.0)
            assert result.returncode == 0 and "OK" in result.stdout, (
                f"#51 unlock (sentinel-flip-failure replay) failed: rc={result.returncode} "
                f"{result.stderr!r} {result.stdout!r}"
            )

            # Then: Unbound is back up (the fallback restarted it) before any further check.
            h.wait_unbound_ready(deployed_vm)

            # Then: the fallback branch under test actually ran (not a false pass from a
            # differently-shaped failure) -- the "sentinel flip failed" line is NEW.
            fail_log_after = h.count_log_marker(deployed_vm, h.PFB_LOG, "ADR-10: sentinel flip failed")
            assert fail_log_after > fail_log_before, (
                f"expected a NEW 'ADR-10: sentinel flip failed' line in {h.PFB_LOG} "
                f"(before={fail_log_before}, after={fail_log_after}) -- the sentinel corruption "
                f"did not drive pfb_reload_unbound() into the branch under test"
            )

            # Then: it genuinely fell back to a RESTART (a host's pid changed) -- the fallback this
            # fix's comment describes, not some other no-op path.
            pids_after = h.dns_host_pids(deployed_vm)
            assert pids_after != pids_before, (
                f"expected the sentinel-flip-failure fallback to RESTART a DNSBL host, but the pids "
                f"(Unbound, pfB-DNS gateway) were unchanged ({pids_before}) -- the restart fallback did not run"
            )

            # Then: the '.sync' daemon-suppression marker touched at the top of the fast
            # path must NOT be left behind -- this IS the regression (issue #713 bug 3).
            leaked = h.hook_marker_exists(deployed_vm, _ADR10_SYNC_MARKER)
            assert not leaked, (
                f"'.sync' marker leaked after the sentinel-flip-failure fallback: {_ADR10_SYNC_MARKER} "
                f"-- the DNSBL Queries daemon stays suppressed until the next full update"
            )
        finally:
            # Restore the sentinel to its ORIGINAL content -- never a fresh value (see
            # docstring: a lower/absent generation would desync the in-memory watcher).
            restore_snippet = f"$s = {h._php_str(_ADR10_SENTINEL)};\nif (is_dir($s)) {{ @rmdir($s); }}\n"
            if prior_sentinel_content is not None:
                restore_snippet += (
                    f"if (!file_exists($s)) {{ file_put_contents($s, {h._php_str(prior_sentinel_content)}); "
                    "@chown($s, 'unbound'); @chgrp($s, 'unbound'); }\n"
                )
            restore_snippet += "echo (is_dir($s) ? 'STILL_DIR' : 'RESTORED');"
            restore = h.php_eval(deployed_vm, restore_snippet, timeout=30.0)
            assert "RESTORED" in restore.stdout, (
                f"failed to restore the ADR-10 sentinel after corrupting it: "
                f"rc={restore.returncode} {restore.stderr!r} {restore.stdout!r} -- "
                f"the session VM's ADR-10 fast path is left broken for later tests"
            )

            # Prove the fast path genuinely still works post-restore: one more ordinary
            # #51 action (re-Lock; the domain is presently unlocked) must take the swap.
            # dnsbl_alert_lock_toggle raises loudly on a swap-applied timeout, so a bad
            # restore (a desynced generation counter) surfaces HERE, not as a later
            # test's unrelated-looking failure.
            h.dnsbl_alert_lock_toggle(deployed_vm, domain, "lock")


@pytest.mark.timeout(120)  # ADR-10: multiple wait-for-apply round-trips > the 30s smoke cap.
def test_dnsbl_temp_unlock_cleared_by_force_update(
    deployed_vm: SmokeVM, client_vm: SmokeVM, mock_feeds: _MockFeedServer
) -> None:
    """#51: a temporary Unlock is re-locked by a Cron/Force update — even with NO feed
    change (parity with main).

    A pending temporary-unlock store forces the reload path regardless of feed changes
    (``inc:8806`` ``|| file_exists($pfb['dnsbl_unlock'])``); that path drops the store
    and clears the manifest's ``config.user_unlock`` (``inc:3451`` ->
    ``pfb_unbound_python_sources_unlock``), so the re-read whiteDB no longer allows the
    domain and it is re-blocked. On ``main`` the equivalent re-lock is the ungated
    whitelist regeneration; before this fix devel only cleared ``user_unlock`` on a
    feed-change rebuild, so a no-change Force left the unlock live (the regression this
    run caught). A plain ``update`` over the UNCHANGED feed is therefore enough.

    ZERO-DOWNTIME (ADR-10): both the #51 Unlock AND the config-clean Force ``update`` are
    pure DNSBL-DATA updates in python mode, so each takes the no-restart fast path (flip
    the sentinel -> the watcher rebuilds + atomically swaps). Unbound's **pid is captured
    before and asserted UNCHANGED after** both operations — proving the re-lock applies with
    no restart. The Force update is driven with ``data_path=True`` so the helper waits on
    the swap-applied log line (not restart readiness), and the re-lock decision is observed
    via the first DNS probe after the helper's applied-generation return (the Force update's
    allow->block re-lock clears the prior resolved answer because the pending-unlock-store
    reload path re-applies the feed block).
    """
    domain = h.unique_domain("unlocktmp")
    feed_url = h.write_local_feed(deployed_vm, "smoke_dnsbl_unlocktmp.txt", f"{domain}\n")
    # No host override on the name — it would shadow the DNSBL block (served as
    # local-data before the python module); an allowed name resolves via the stub.
    spec = h.DnsblCase(aliasname="smokeunlocktmp", feed_url=feed_url, header="smokeunlocktmp")
    with h.CaseContext(deployed_vm, spec), h.DnsblCacheFlushEnabled(deployed_vm):
        # Egress OPEN: the update path deadlocks under a dark egress, and the allowed
        # (unlock) probe must reach the controlled stub. The block probes return the VIP
        # locally, so there is no false-green from leaving egress open.
        h.unblock_egress()
        # Blocked by the feed -> VIP (the "before" of the Unlock operation).
        blocked = h.dns_probe_client(client_vm, domain, "A")
        assert h.is_null_ip(blocked), f"{domain} expected a null block, got {blocked}"

        # NO-RESTART invariant: capture the DNSBL hosts' pids before the Unlock + Force-update re-lock.
        pids_before = h.dns_host_pids(deployed_vm)

        # Unlock -> resolves again through the stub sentinel. The helper waits for the
        # applied-generation handshake but flushes the native cache only for Lock.
        h.dnsbl_alert_lock_toggle(deployed_vm, domain, "unlock")
        unlocked = h.dns_probe_client(client_vm, domain, "A")
        assert not h.is_null_ip(unlocked), f"unlocked {domain} still null-blocked: {unlocked}"

        # A Cron/Force update over the UNCHANGED feed re-locks it: the pending unlock store
        # forces the reload + clears the manifest's user_unlock. It is a config-clean
        # DNSBL-data update -> the no-restart fast path (data_path=True waits on the swap).
        h.reload(deployed_vm, "update", data_path=True)
        # The enabled post-handshake full-cache flush clears the prior resolved answer
        # before the swapped re-block is observed.
        relocked = h.dns_probe_client(client_vm, domain, "A")
        assert h.is_null_ip(relocked), f"re-locked {domain} still resolving: {relocked}"

        # Both the Unlock and the Force-update re-lock applied with NO restart: pids unchanged.
        pids_after = h.dns_host_pids(deployed_vm)
        assert pids_after == pids_before, (
            f"#51 Unlock + Cron/Force re-lock must apply via the no-restart swap, but a DNSBL host "
            f"restarted: (Unbound, pfB-DNS gateway) pids {pids_before} -> {pids_after}"
        )


# --------------------------------------------------------------------------- #
# 2b) ADR-10 zero-downtime DNSBL — no-restart data path, config-restart fork,
#     fail-closed. Automates the §7 maintainer smoke checklist. The hard proof is
#     Unbound's pid: UNCHANGED across a DATA update (the swap reuses the running
#     process), CHANGED across a CONFIG update (the restart fork). Each case asserts
#     the BEFORE-state and the pid invariant (CLAUDE.md test-coverage rules).
# --------------------------------------------------------------------------- #


@pytest.mark.timeout(120)  # ADR-10: setup restart + a wait-for-apply swap > the 30s smoke cap.
def test_dnsbl_feed_update_no_restart(deployed_vm: SmokeVM, client_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """A feed-content DNSBL update applies WITHOUT restarting Unbound (ADR-10 zero-downtime).

    Branch-coverage partner of ``test_dnsbl_config_change_restarts`` (data fork vs config
    fork). Full before/after with the pid invariant:

    * BEFORE: a name NOT in the feed RESOLVES (forwarded to the stub sentinel) — the
      list is live but does not yet contain it. (Asserted, so the later block is proven
      to come from the feed edit, not a pre-existing state.)
    * APPLY: add the name to the SAME local feed file and force a full ``update``. Feeds
      are cached and re-fetched only on a force (the ``reset``/force-update precedent —
      see ``test_dnsbl_temp_unlock_cleared_by_force_update``). A config-clean feed/cron
      update in python mode routes through the no-restart data fast path
      (``pfb_update_unbound`` -> ``pfb_reload_unbound($mode, $pfbpython, $datapath)``),
      so PHP flips the sentinel and the watcher swaps the snapshot. The bulk
      caller then clears the full resolver cache after the applied-generation handshake
      because this test explicitly enables the default-off cache-flush option.
    * AFTER: the name is BLOCKED (null), Unbound's pid is UNCHANGED (no restart), and the
      pfBlockerNG log gained a ``zero-downtime swap`` fast-path line.

    NO-FALLBACK NOTE: a config-clean feed-content re-fetch reliably takes the no-restart
    path. The enabled post-handshake full cache flush removes the name's prior resolved answer
    before the first post-reload probe observes the swapped block.
    """
    domain = h.unique_domain("feedupd")
    other = h.unique_domain("feedupd-filler")
    # Start with a feed that does NOT contain the target (only an unrelated filler line),
    # so the list is live but the target is not yet blocked.
    feed_name = "smoke_dnsbl_feedupd.txt"
    feed_url = h.write_local_feed(deployed_vm, feed_name, f"{other}\n")
    spec = h.DnsblCase(aliasname="smokefeedupd", feed_url=feed_url, header="smokefeedupd")
    with h.CaseContext(deployed_vm, spec), h.DnsblCacheFlushEnabled(deployed_vm):
        h.unblock_egress()  # the allowed (before-state) probe must reach the controlled stub

        # BEFORE: the target is not on the feed yet -> it RESOLVES via the stub sentinel.
        before = h.dns_probe_client(client_vm, domain, "A")
        assert h.resolves_to(before, STUB_DNS_A), f"{domain} should resolve via stub BEFORE the feed edit, got {before}"
        assert not h.is_null_ip(before), f"{domain} unexpectedly null-blocked before being listed: {before}"

        # NO-RESTART invariant + fast-path-log proof: capture the hosts' pids and the swap-log baseline.
        pids_before = h.dns_host_pids(deployed_vm)
        swap_before = h.count_log_marker(deployed_vm, h.PFB_LOG, h.SWAP_LOG_MARKER)

        # APPLY: add the target to the feed and force a full update (re-fetches the edited
        # local feed). data_path=True -> the no-restart fast path; the helper waits on the
        # swap-applied log line and RAISES if the restart fallback was taken instead.
        h.write_local_feed(deployed_vm, feed_name, f"{other}\n{domain}\n")
        # Invalidate the per-feed cache so the full update RE-READS the edited local feed
        # (pfBlockerNG reuses the cached '.txt' otherwise -> the edit never reaches the
        # manifest and no swap fires). This is the config-clean data update the swap targets.
        h.force_dnsbl_refetch(deployed_vm, spec.header)
        h.reload(deployed_vm, "update", data_path=True)

        # Reload returns only after the generation is applied. Probe FIRST so this
        # assertion cannot wait through a DNS TTL while unrelated probes run.
        blocked = h.dns_probe_client(client_vm, domain, "A")
        assert h.is_null_ip(blocked), f"{domain} still not null-blocked after feed update: {blocked}"
        assert not h.resolves_to(blocked, STUB_DNS_A), f"{domain} still resolving after the feed block: {blocked}"

        fsync_probe = h.php_eval(
            deployed_vm,
            "$dir = '/var/unbound/.pfb1357-fsync-' . getmypid(); $step = 'mkdir';\n"
            "$ok = @mkdir($dir, 0700);\n"
            "if ($ok) { $step = 'write'; $ok = file_put_contents($dir . '/before', 'x') === 1; }\n"
            "if ($ok) { $step = 'rename'; $ok = @rename($dir . '/before', $dir . '/after'); }\n"
            "$fh = FALSE;\n"
            "if ($ok) { $step = 'open-dir'; $fh = @fopen($dir, 'r'); $ok = $fh !== FALSE; }\n"
            "if ($ok) { $step = 'fsync-dir'; $ok = @fsync($fh); }\n"
            "$error = $ok ? NULL : error_get_last();\n"
            "if (is_resource($fh)) { fclose($fh); }\n"
            "@unlink($dir . '/before'); @unlink($dir . '/after'); @rmdir($dir);\n"
            "echo '<<PFB1357>>' . json_encode(array('ok' => $ok, 'step' => $step, 'error' => $error)) . '<<END1357>>';",
            timeout=30.0,
        )
        assert fsync_probe.returncode == 0, fsync_probe.stderr
        fsync_result = json.loads(fsync_probe.stdout.split("<<PFB1357>>", 1)[1].split("<<END1357>>", 1)[0])
        print(f"[smoke] #1357 FreeBSD directory fsync probe: {fsync_result}")
        assert fsync_result["ok"] is True, f"FreeBSD directory fsync failed: {fsync_result!r}"

        generation_probe = h.php_eval(
            deployed_vm,
            "$m = json_decode(file_get_contents('/var/unbound/pfb_py_sources.json'), TRUE);\n"
            "$dirs = array(); $missing = array(); $staged = array();\n"
            "foreach (($m['feeds'] ?? array()) as $row) {\n"
            "  $raw = $row['raw'] ?? ''; $dir = dirname($raw); $dirs[$dir] = TRUE;\n"
            "  if (strpos($raw, 'pfb_py_raw.stage.') !== FALSE) { $staged[] = $raw; }\n"
            "  if (!is_file('/var/unbound/' . $raw)) { $missing[] = $raw; }\n"
            "}\n"
            "echo '<<PFB1357>>' . json_encode(array(\n"
            "  'dirs' => array_keys($dirs), 'missing' => $missing, 'staged' => $staged\n"
            ")) . '<<END1357>>';",
            timeout=30.0,
        )
        assert generation_probe.returncode == 0, generation_probe.stderr
        generation = json.loads(generation_probe.stdout.split("<<PFB1357>>", 1)[1].split("<<END1357>>", 1)[0])
        assert len(generation["dirs"]) == 1, f"feed raws span generations: {generation!r}"
        assert re.fullmatch(r"pfb_py_raw\.[0-9a-f]{32}", generation["dirs"][0]), generation
        assert generation["missing"] == [], f"published manifest has missing raw refs: {generation!r}"
        assert generation["staged"] == [], f"published manifest references staging: {generation!r}"

        # AFTER: pids unchanged (no restart) AND a fresh fast-path swap line was logged.
        pids_after = h.dns_host_pids(deployed_vm)
        assert pids_after == pids_before, (
            f"a feed DNSBL update must take the no-restart zero-downtime swap, but a DNSBL host "
            f"restarted: (Unbound, pfB-DNS gateway) pids {pids_before} -> {pids_after}"
        )
        swap_after = h.count_log_marker(deployed_vm, h.PFB_LOG, h.SWAP_LOG_MARKER)
        assert swap_after > swap_before, (
            f"no new '{h.SWAP_LOG_MARKER}' fast-path line logged for the feed update "
            f"(before={swap_before}, after={swap_after}) — the data fast path did not run"
        )


@pytest.mark.timeout(120)  # ADR-10: two full Unbound restarts (disable + enable) > the 30s cap.
def test_dnsbl_config_change_restarts(deployed_vm: SmokeVM, client_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """A CONFIG change DOES restart Unbound — the other fork of the data/config split.

    Branch-coverage partner of ``test_dnsbl_feed_update_no_restart``: ADR-10 keeps the
    restart for a config change (unbound.conf/ini/mode regenerated), only DNSBL DATA is
    zero-downtime. Disabling then re-enabling the DNSBL component toggles
    ``pfb_dnsbl``/the python integration, which regenerates Unbound's config and forces a
    restart (``$pfbpython`` TRUE -> ``$datapath`` FALSE -> ``pfb_stop_start_unbound``).
    The proof is the pid CHANGING.

    Before/after with the pid invariant:

    * BEFORE: DNSBL is live with the name blocked (null) — capture Unbound's pid.
    * CONFIG CHANGE: disable DNSBL (``pfb_dnsbl`` off) + ``updatednsbl`` (regenerates
      unbound.conf without the python module -> restart), then re-enable + ``updatednsbl``
      (regenerates WITH it -> restart). Both are config changes, so each restarts.
    * AFTER: Unbound's pid has CHANGED at least once (a genuine restart happened), proving
      the config fork does NOT take the no-restart data path. The name blocks again (the
      list is restored).

    Teardown (``CaseContext.__exit__`` -> ``reset``) restores ``pfb_dnsbl`` on via the
    normal config, so the rest of the matrix runs against its baseline.
    """
    domain = h.unique_domain("cfgrestart")
    feed_url = h.write_local_feed(deployed_vm, "smoke_dnsbl_cfgrestart.txt", f"{domain}\n")
    spec = h.DnsblCase(aliasname="smokecfgrestart", feed_url=feed_url, header="smokecfgrestart")
    with h.CaseContext(deployed_vm, spec):
        # BEFORE: the name is blocked (null) and DNSBL is live. Capture the running pid.
        blocked = h.dns_probe_client(client_vm, domain, "A")
        assert h.is_null_ip(blocked), f"{domain} expected a null block before the config change, got {blocked}"
        pids_before = h.dns_host_pids(deployed_vm)

        # CONFIG CHANGE: disable DNSBL -> regenerates unbound.conf (drops the python
        # module) -> restart. These reloads are NOT data_path: a config change keeps the
        # restart, so wait on restart readiness (the default reload() path).
        h.set_dnsbl_enabled(deployed_vm, False)
        h.reload(deployed_vm, "updatednsbl")
        pids_mid = h.dns_host_pids(deployed_vm)
        assert pids_mid != pids_before, (
            f"disabling DNSBL is a config change and MUST restart a DNSBL host, but the pids "
            f"(Unbound, pfB-DNS gateway) were unchanged ({pids_before}) — the config fork wrongly took the "
            "no-restart path"
        )

        # Re-enable DNSBL -> regenerates unbound.conf WITH the python module -> restart.
        h.set_dnsbl_enabled(deployed_vm, True)
        h.reload(deployed_vm, "updatednsbl")
        pids_after = h.dns_host_pids(deployed_vm)
        assert pids_after != pids_mid, (
            f"re-enabling DNSBL is a config change and MUST restart a DNSBL host, but the pids "
            f"(Unbound, pfB-DNS gateway) were unchanged ({pids_mid})"
        )
        # The list is restored: the name blocks again after the config round-trip.
        reblocked = h.dns_probe_client(client_vm, domain, "A")
        assert h.is_null_ip(reblocked), f"{domain} expected a null block after re-enabling DNSBL, got {reblocked}"


@pytest.mark.timeout(120)  # ADR-10: setup + a watcher build-fail observation window > the 30s cap.
def test_dnsbl_fail_closed_broken_manifest(
    deployed_vm: SmokeVM, client_vm: SmokeVM, mock_feeds: _MockFeedServer
) -> None:
    """A broken manifest does NOT swap — the last-good lists keep serving (ADR-10 fail-closed).

    The ADR-10 safety contract: if a rebuild fails (bad/partial manifest), the watcher keeps
    the OLD snapshot live and never swaps to an empty/partial set ("never fail open to no
    blocking"). Before/after with the pid invariant:

    * BEFORE: the name is BLOCKED (null) — the last-good snapshot. Capture Unbound's pid and
      the py_error.log baseline.
    * CORRUPT + TRIGGER: overwrite ``/var/unbound/pfb_py_sources.json`` with invalid JSON
      (preserving unbound:unbound ownership so the chrooted module can still OPEN it — the
      failure must be a PARSE failure, not a permission one), then bump the generation
      sentinel (``/var/unbound/pfb_py_reload`` -> current+1) to trigger the watcher. The
      build fails (``dnsbl_build_from_manifest`` logs "Failed to load DNSBL manifest" and
      returns None -> ``rebuild_and_swap`` keeps the old snapshot).
    * AFTER: the name STILL BLOCKS (old snapshot kept), Unbound is still UP (``unbound-control
      status`` ok) with its pid UNCHANGED (no restart, no crash), and py_error.log gained a
      ``Failed to load DNSBL manifest`` (or ``keeping current snapshot``) line.

    Teardown restores a clean state: a real ``reset`` (clear* + forced ``update``) rewrites a
    valid manifest, so the next case starts from the baseline.
    """
    domain = h.unique_domain("failclosed")
    feed_url = h.write_local_feed(deployed_vm, "smoke_dnsbl_failclosed.txt", f"{domain}\n")
    spec = h.DnsblCase(aliasname="smokefailclosed", feed_url=feed_url, header="smokefailclosed")
    with h.CaseContext(deployed_vm, spec):
        # BEFORE: the name is blocked (null) by the last-good snapshot.
        blocked = h.dns_probe_client(client_vm, domain, "A")
        assert h.is_null_ip(blocked), f"{domain} expected a null block before corrupting the manifest, got {blocked}"
        pids_before = h.dns_host_pids(deployed_vm)
        pyerr_before = h.count_log_marker(deployed_vm, h.PY_ERROR_LOG, "Failed to load DNSBL manifest")

        # CORRUPT the manifest + bump the sentinel via PHP (pfSsh.php) — NOT a raw SSH shell
        # string: pfSense's root login shell is tcsh, which lacks POSIX ``$(...)``/``case``/
        # ``$((…))``; PHP gives deterministic file ops and ownership. Write invalid JSON
        # (a PARSE error, not a permission one), keep unbound:unbound ownership so the
        # chrooted module can still OPEN it, then write generation current+1 into the
        # sentinel (the watcher swaps only on a STRICT advance) to trigger the failing build.
        snippet = (
            "$m = '/var/unbound/pfb_py_sources.json';\n"
            "file_put_contents($m, '{ this is not valid json');\n"
            "@chown($m, 'unbound'); @chgrp($m, 'unbound');\n"
            "$s = '/var/unbound/pfb_py_reload';\n"
            "$raw = @file_get_contents($s);\n"
            '$cur = ($raw !== FALSE) ? (int) strtok($raw, "\\n") : 0;\n'
            'file_put_contents($s, ($cur + 1) . "\\n");\n'
            "@chown($s, 'unbound'); @chgrp($s, 'unbound');\n"
            "echo 'OK';"
        )
        res = h.php_eval(deployed_vm, snippet, timeout=60)
        assert "OK" in res.stdout, f"failed to corrupt manifest / bump sentinel: rc={res.returncode} {res.stderr!r}"

        # Give the watcher a bounded window to wake, fail the build, and log it — then assert
        # the fail-closed outcome. py_error.log gaining the manifest-load failure line proves
        # the build was attempted AND failed (not silently skipped).
        def _pyerr_logged(_a: h.DnsAnswer) -> bool:
            now = h.count_log_marker(deployed_vm, h.PY_ERROR_LOG, "Failed to load DNSBL manifest")
            return now > pyerr_before

        # dns_probe_client_until polls the (still-blocked) name; the predicate also confirms
        # the py_error line appeared — both must hold within the window (raises otherwise).
        still = h.dns_probe_client_until(
            client_vm,
            domain,
            lambda a: h.is_null_ip(a) and _pyerr_logged(a),
            timeout=45.0,
        )
        assert h.is_null_ip(still), f"fail-closed: {domain} must STILL block on the old snapshot, got {still}"

        # Unbound is still UP and was NOT restarted by the failed build.
        h.wait_unbound_ready(deployed_vm)
        pids_after = h.dns_host_pids(deployed_vm)
        assert pids_after == pids_before, (
            f"a failed (fail-closed) build must keep the running resolver: a DNSBL host restarted, "
            f"(Unbound, pfB-DNS gateway) pids {pids_before} -> {pids_after}"
        )
        pyerr_after = h.count_log_marker(deployed_vm, h.PY_ERROR_LOG, "Failed to load DNSBL manifest")
        assert pyerr_after > pyerr_before, (
            f"expected a 'Failed to load DNSBL manifest' line in {h.PY_ERROR_LOG} "
            f"(before={pyerr_before}, after={pyerr_after}) — the broken-manifest build was not logged"
        )


_RET_OPEN = "<<<RET>>>"
_RET_CLOSE = "<<<ENDRET>>>"
_SYNC_OPEN = "<<<SYNC>>>"
_SYNC_CLOSE = "<<<ENDSYNC>>>"
_INFLIGHT_LINE = "swap still in flight"


def _delimited(out: str, opening: str, closing: str) -> str:
    start = out.find(opening)
    end = out.find(closing)
    if start == -1 or end == -1:
        raise RuntimeError(f"no delimited value in pfSsh.php output ({opening!r}..{closing!r}): {out[-500:]!r}")
    return out[start + len(opening) : end]


def _open_apply_ledger_count(vm: SmokeVM) -> int:
    """Count open ADR-61 entries for the EXACT (dnsbl, dnsbl, apply) key.

    Filtered, not a bare group count: the dnsbl group also carries download-stage
    records, and an unrelated open download would let the apply assertion pass
    without the apply entry ever opening.
    """
    expr = (
        "count(array_filter(pfb_sync_status_list_open($GLOBALS['pfb']['dbdir'], 'dnsbl'), "
        "static fn($e) => ($e['item'] ?? '') === 'dnsbl' && ($e['stage'] ?? '') === 'apply'))"
    )
    return int(
        h._php_read_scalar(  # noqa: SLF001 -- suite-internal helper, used the same way elsewhere here
            vm,
            "require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');\npfb_global();",
            expr,
        )
    )


# The seam-shrunk budget (1 s) plus the watcher's fail-closed build window; the pfSsh.php
# reload round-trip itself is the long pole.
@pytest.mark.timeout(120)
def test_datapath_swap_budget_expiry_keeps_resolver_serving(
    deployed_vm: SmokeVM, client_vm: SmokeVM, mock_feeds: _MockFeedServer
) -> None:
    """#3200: a datapath swap that does not confirm in time must NOT restart Unbound.

    The reload-watcher applies the generation independently of PHP's wait, so an expired
    budget is a self-unlock, never a failure verdict: the previous snapshot keeps serving
    while the swap stays in flight, and the ADR-61 tick reconciliation re-publishes until
    it converges. Deterministic seat method: corrupt the manifest (parse failure with
    unbound:unbound ownership preserved — the same trick as
    ``test_dnsbl_fail_closed_broken_manifest``) so the applied marker can never advance,
    then drive the REAL ``pfb_reload_unbound('enabled', FALSE, TRUE)`` fast path
    under the test-only budget seam (``$GLOBALS['pfb_test_swap_wait_s'] = 1``) so the
    wait expires deterministically into the in-flight branch.

    * BEFORE: the name is BLOCKED (null). Capture the pid, the fast-path / in-flight /
      stop / fallback log baselines, and the open apply-ledger count.
    * TRIGGER: corrupt the manifest, then run the reload with the 1 s seam budget.
    * AFTER: the reload returned FALSE, ``.sync`` is cleared, the fast-path AND
      in-flight lines were logged, ``Stopping Unbound Resolver`` and
      ``falling back to Unbound restart`` were NOT, the ADR-61 apply-ledger entry is
      OPEN, the name STILL blocks on the old snapshot, and Unbound's pid is UNCHANGED.
    """
    domain = h.unique_domain("inflight")
    feed_url = h.write_local_feed(deployed_vm, "smoke_dnsbl_inflight.txt", f"{domain}\n")
    spec = h.DnsblCase(aliasname="smokeinflight", feed_url=feed_url, header="smokeinflight")
    with h.CaseContext(deployed_vm, spec):
        # BEFORE: the name is blocked (null) by the live snapshot; capture every baseline.
        blocked = h.dns_probe_client(client_vm, domain, "A")
        assert h.is_null_ip(blocked), f"{domain} expected a null block before the forced expiry, got {blocked}"
        pids_before = h.dns_host_pids(deployed_vm)
        swap_before = h.count_log_marker(deployed_vm, h.PFB_LOG, h.SWAP_LOG_MARKER)
        inflight_before = h.count_log_marker(deployed_vm, h.PFB_LOG, _INFLIGHT_LINE)
        stop_before = h.count_log_marker(deployed_vm, h.PFB_LOG, "Stopping Unbound Resolver")
        fallback_before = h.count_log_marker(deployed_vm, h.PFB_LOG, "falling back to Unbound restart")
        ledger_before = _open_apply_ledger_count(deployed_vm)

        # CORRUPT the manifest: a PARSE failure (ownership preserved so the chrooted
        # module can still open it), so the watcher's rebuild fail-closes and the
        # applied marker freezes no matter how long anyone waits.
        corrupt = (
            "$m = '/var/unbound/pfb_py_sources.json';\n"
            "file_put_contents($m, '{ this is not valid json');\n"
            "@chown($m, 'unbound'); @chgrp($m, 'unbound');\n"
            "echo 'OK';"
        )
        res = h.php_eval(deployed_vm, corrupt, timeout=60)
        assert "OK" in res.stdout, f"failed to corrupt the manifest: rc={res.returncode} {res.stderr!r}"

        # TRIGGER: the real production fast path under the 1 s test-only budget seam.
        # pfb_reload_unbound() flips the sentinel itself; the watcher cannot apply, so
        # the wait deterministically expires into the in-flight branch.
        reload_snippet = (
            "require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');\n"
            "pfb_global();\n"
            "$GLOBALS['pfb_test_swap_wait_s'] = 1;\n"
            "$ret = pfb_reload_unbound('enabled', FALSE, TRUE);\n"
            f"echo '{_RET_OPEN}' . var_export($ret, TRUE) . '{_RET_CLOSE}';\n"
            f"echo '{_SYNC_OPEN}' . var_export("
            "file_exists($GLOBALS['pfb']['dnsbl_file'] . '.sync'), TRUE) . "
            f"'{_SYNC_CLOSE}';\n"
        )
        res = h.php_eval(deployed_vm, reload_snippet, timeout=120)
        ret = _delimited(res.stdout, _RET_OPEN, _RET_CLOSE)
        sync_left = _delimited(res.stdout, _SYNC_OPEN, _SYNC_CLOSE)
        assert ret == "false", (
            f"an unconfirmed swap must return FALSE (callers skip flushes on not-live data), got {ret!r}"
        )
        assert sync_left == "false", (
            "the in-flight return must clear the .sync daemon-suppression marker (issue #713 bug 3)"
        )

        # The in-flight line is the row's core signal: wait for it while confirming the
        # old snapshot still serves (combined predicate, fail-closed-row idiom).
        def _inflight_and_blocked(_a: h.DnsAnswer) -> bool:
            return h.is_null_ip(_a) and h.count_log_marker(deployed_vm, h.PFB_LOG, _INFLIGHT_LINE) > inflight_before

        still = h.dns_probe_client_until(client_vm, domain, _inflight_and_blocked, timeout=45.0)
        assert h.is_null_ip(still), f"the previous snapshot must keep serving during the in-flight swap, got {still}"

        # THE #3200 INVARIANT: no restart, no fallback, exactly one fresh swap line.
        pids_after = h.dns_host_pids(deployed_vm)
        assert pids_after == pids_before, (
            f"a budget-expired datapath swap must NEVER restart a DNSBL host: "
            f"(Unbound, pfB-DNS gateway) pids {pids_before} -> {pids_after}"
        )
        assert h.count_log_marker(deployed_vm, h.PFB_LOG, "Stopping Unbound Resolver") == stop_before, (
            "'Stopping Unbound Resolver' logged for a datapath reload -- the #3200 regression"
        )
        assert h.count_log_marker(deployed_vm, h.PFB_LOG, "falling back to Unbound restart") == fallback_before, (
            "the restart fallback was chosen for a slow swap -- the #3200 regression"
        )
        assert h.count_log_marker(deployed_vm, h.PFB_LOG, h.SWAP_LOG_MARKER) == swap_before + 1, (
            "exactly one fresh fast-path swap line expected for the forced-expiry reload"
        )
        assert ledger_before == 0, (
            "baseline: the (dnsbl, dnsbl, apply) entry must start CLOSED, or the assertion below "
            f"proves nothing (got {ledger_before})"
        )
        assert _open_apply_ledger_count(deployed_vm) >= 1, (
            "the unconfirmed swap must OPEN the ADR-61 (dnsbl, dnsbl, apply) entry (visible pending state)"
        )


# --------------------------------------------------------------------------- #
# 3) DNSBL-IP dual-stack — two distinct pf tables, partitioned by family
# --------------------------------------------------------------------------- #


# The 30s default body cap cannot cover reload + two table reads + the on-failure dump.
# (issue #1239). The budget is a deadlock guard here, not a pacer.
@pytest.mark.timeout(180)
def test_dnsblip_dual_stack_partition(deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """A DNSBL feed with BOTH families -> pfB_DNSBLIP_v4 AND pfB_DNSBLIP_v6.

    Scenario: a DNSBL-IP feed carrying BOTH families partitions onto two tables.
      Given a feed file with exactly one IPv4 literal and one IPv6 literal
        And a DNSBL list referencing it with the DNSBL-IP action 'Deny_Both' on
      When a Force Update builds the domain DB and the IP firewall tables
      Then pfBlockerNG populates TWO distinct alias tables, pfB_DNSBLIP_v4 and
           pfB_DNSBLIP_v6 (the hardcoded ``DNSBLIP`` base name suffixed per family,
           inc:9306) — each holding ONLY its own family, never merged onto one
        And the inet/inet6 rules each reference the matching per-family table.

    ADR §2 contract; on the maintainer's §7 manual checklist. The IP-firewall path
    itself is already proven synchronously by ``test_ip_alias_table_and_rule``; what
    this pins is specifically the dual-stack PARTITION (families never collide on one
    table).

    ``pfB_DNSBLIP_v4`` / ``pfB_DNSBLIP_v6`` are read after one blocking filter apply,
    making each single-shot table result authoritative.
    """
    # Given: a feed carrying exactly one literal per family.
    v4 = "203.0.113.7"  # RFC 5737 documentation range
    v6 = "2001:db8:5::7"  # RFC 3849 documentation range
    feed_url = h.write_local_feed(deployed_vm, "smoke_dnsblip_dual.txt", f"{v4}\n{v6}\n")
    # The feed is reached by a DNSBL list; the embedded IPs feed the DNSBLIP
    # tables once the DNSBL-IP feature (action) is enabled. update covers both
    # the domain DB and the IP tables.
    spec = h.DnsblCase(
        aliasname="smokedualip",
        feed_url=feed_url,
        header="smokedualip",
        mode=h.DnsblMode.NULL,
        dnsbl_ip_action="Deny_Both",
    )
    with h.CaseContext(deployed_vm, spec, scope="update"):
        h.apply_filter_sync(deployed_vm)
        # When: read each per-family table once after the sync boundary.
        # Then: both tables exist and are non-empty.
        v4_members = h.pfctl_table_members(deployed_vm, "pfB_DNSBLIP_v4")
        v6_members = h.pfctl_table_members(deployed_vm, "pfB_DNSBLIP_v6")
        assert v4_members, "pfB_DNSBLIP_v4 missing after filter sync"
        assert v6_members, "pfB_DNSBLIP_v6 missing after filter sync"

        # Then: each table holds ONLY its own family (the partition — no collision / merge).
        assert h.member_present(v4_members, v4), f"{v4} not in pfB_DNSBLIP_v4: {v4_members}"
        assert not any(":" in m for m in v4_members), f"IPv6 leaked into pfB_DNSBLIP_v4: {v4_members}"
        assert h.member_present(v6_members, v6), f"{v6} not in pfB_DNSBLIP_v6: {v6_members}"
        assert any(":" in m for m in v6_members), f"no IPv6 in pfB_DNSBLIP_v6: {v6_members}"
        assert not any(_is_v4_literal(m) for m in v6_members), f"IPv4 leaked into pfB_DNSBLIP_v6: {v6_members}"

        # Then: inet/inet6 rules reference the matching per-family table. On failure, dump
        # the three layers so the report says WHICH one lost the rule (issue #1239).
        assert h.pfctl_rule_has_alias(deployed_vm, "pfB_DNSBLIP_v4"), (
            "no rule references pfB_DNSBLIP_v4\n" + h.alias_rule_dump(deployed_vm, "pfB_DNSBLIP_v4")
        )
        assert h.pfctl_rule_has_alias(deployed_vm, "pfB_DNSBLIP_v6"), (
            "no rule references pfB_DNSBLIP_v6\n" + h.alias_rule_dump(deployed_vm, "pfB_DNSBLIP_v6")
        )


def _is_v4_literal(member: str) -> bool:
    """True iff a pfctl table member looks like an IPv4 address/CIDR."""
    head = member.split("/", 1)[0]
    parts = head.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)


# --------------------------------------------------------------------------- #
# 4) FALSE-GREEN GUARD — a deliberately-wrong expectation MUST go red
# --------------------------------------------------------------------------- #


@pytest.mark.xfail(strict=True, reason="deliberately-wrong expectation: a real block is NOT a pass")
def test_false_green_guard_vm(deployed_vm: SmokeVM, client_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    """STRICT-xfail guard: assert a real block RESOLVES — it must NOT.

    Blocks a unique domain (null) then asserts it resolves to a pass IP.
    That assertion is FALSE on a working harness, so the test fails -> the
    ``strict=True`` xfail turns the failure into the expected outcome (green
    overall). If a broken/lenient harness silently let the block "pass", this
    test would PASS unexpectedly and ``strict=True`` would flip the suite RED —
    catching a false-green at the VM level (on top of the pure-Python guard in
    test_smoke_helpers.py::test_false_green_guard).
    """
    domain = h.unique_domain("guard")
    feed_url = h.write_local_feed(deployed_vm, "smoke_dnsbl_guard.txt", f"{domain}\n")
    spec = h.DnsblCase(
        aliasname="smokeguard",
        feed_url=feed_url,
        header="smokeguard",
    )
    with h.CaseContext(deployed_vm, spec):
        answer = h.dns_probe_client(client_vm, domain, "A")
        # WRONG on purpose: a block does not resolve to a pass IP.
        assert h.resolves_to(answer, "198.51.100.250"), "expected (wrongly) to resolve — must fail"


# --------------------------------------------------------------------------- #
# ADR-03 — persistent log handle: a VIP block reaches dnsbl.log under real Unbound.
# The off-box golden harness pins byte-identical log CONTENT; this pins that the
# persistent WatchedFileHandler/QueueListener path actually WRITES the line live —
# the one thing the off-box harness cannot prove (the chrooted Python loader's file IO).
# --------------------------------------------------------------------------- #


def _dnsbl_log_hits(vm: SmokeVM, needle: str, *, timeout: float = 30.0) -> int:
    """Count ``dnsbl.log`` lines containing ``needle`` on the guest (host + chroot paths).

    ``pfb_unbound.py`` runs chrooted at ``/var/unbound``, so its
    ``/var/log/pfblockerng/dnsbl.log`` open resolves inside the chroot; grep BOTH the host
    and the chroot path so the assertion is independent of which one the line lands in.
    ``grep -hcF`` prints one integer per file (filename suppressed); a missing file is
    skipped (its error goes to stderr), so summing the integer tokens is robust.
    """
    res = vm.ssh(
        "grep",
        "-hcF",
        "--",
        needle,
        "/var/log/pfblockerng/dnsbl.log",
        "/var/unbound/var/log/pfblockerng/dnsbl.log",
        timeout=timeout,
    )
    return sum(int(tok) for tok in res.stdout.split() if tok.isdigit())


def test_dnsbl_block_writes_persistent_log_line(
    deployed_vm: SmokeVM, client_vm: SmokeVM, mock_feeds: _MockFeedServer
) -> None:
    """ADR-03: a VIP (``log_type='1'``) block is written to ``dnsbl.log`` via the persistent handle.

    Scenario: ADR-03 replaced per-call open/close with a persistent ``WatchedFileHandler``
    behind a ``QueueListener``. The off-box golden harness pins byte-identical log content;
    this pins that — under REAL Unbound (the chrooted python loader) — a block decision
    actually reaches ``dnsbl.log`` through that persistent path.

    Given a unique domain not yet listed, ``dnsbl.log`` names it zero times (before-state).
    When it is listed VIP (per-list logging enabled -> ``log_type='1'``) and queried once,
    Then a ``dnsbl.log`` line naming it appears (the persistent logging IO path wrote it). A
      NULL / non-logged block (``log_type`` ``'2'``/``'4'``) writes nothing, so the line is
      real evidence of the ``log_type='1'`` write path, not mere execution.
    """
    domain = h.unique_domain("adr03log")
    feed_url = h.write_local_feed(deployed_vm, "smoke_adr03_log.txt", f"{domain}\n")
    spec = h.DnsblCase(aliasname="smokeadr03", feed_url=feed_url, header="smokeadr03")

    # BEFORE: the unique domain has never been blocked -> no dnsbl.log line names it.
    assert _dnsbl_log_hits(deployed_vm, domain) == 0, f"{domain} already in dnsbl.log before listing"

    with h.CaseContext(deployed_vm, spec):
        blocked = h.dns_probe_client(client_vm, domain, "A")
        assert h.is_null_ip(blocked), f"{domain} expected a null block, got {blocked}"
        # The log write rides the async QueueListener -> poll briefly for the line.
        deadline = time.monotonic() + 20.0
        hits = 0
        while time.monotonic() < deadline:
            hits = _dnsbl_log_hits(deployed_vm, domain)
            if hits >= 1:
                break
            time.sleep(1.0)
        if hits < 1:
            observed = deployed_vm.ssh(
                "cat",
                "/var/log/pfblockerng/dnsbl.log",
                "/var/unbound/var/log/pfblockerng/dnsbl.log",
                timeout=15.0,
            )
            raise RuntimeError(
                "salvage cap expired / stuck or environment: "
                f"test_dnsbl_block_writes_persistent_log_line awaited dnsbl.log marker "
                f"containing domain {domain!r}; observed hits={hits}; "
                f"cat rc={observed.returncode} stdout={observed.stdout!r} stderr={observed.stderr!r}"
            )
        assert hits >= 1, f"no dnsbl.log line for {domain} after a VIP block (ADR-03 persistent log handle)"
