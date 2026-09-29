"""Live-VM smoke: numeric URL hosts and IPv4-mapped IPv6 in an IP feed land in the IPv4 alias table.

A client dials ``http://0300.0.02.04/x`` as 192.0.2.4, ``http://0xC6336409/x`` as 198.51.100.9
and ``http://3405803790/x`` as 203.0.113.14 (WHATWG URL rules). ``pfb_ip_parse_line()`` decodes a
line that starts with ``scheme://`` and has such a host, drops its userinfo and port, and
``::ffff:c633:6405`` on a v4 list is its embedded IPv4. Previously the leading-zero host was read
as decimal, the hex and DWORD hosts were dropped without a log line, and a userinfo decoy
(``1.2.3.4@host``) was collected instead of the host.

The addresses come from the RFC 5737 documentation ranges; ``deploy()`` pins IP Suppression off.
The decoy 1.2.3.4 and the invalid ``08.08.08.08`` (never 8.8.8.8) must stay out of the table.

DESELECTED from the default ``python -m pytest``; select with ``-k ip_feed_numeric_host``.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from . import helpers as h
from .conftest import SmokeVM

pytestmark = pytest.mark.smoke

HEADER = "smokeipnumhost"
# Feed line -> the IPv4 a client reaches. Distinct, non-adjacent addresses so each is asserted alone.
EXPECTED = {
    "http://0300.0.02.04/x": "192.0.2.4",  # leading-zero octal host
    "http://0xC6336409/x": "198.51.100.9",  # hex DWORD host
    "http://3405803790/x": "203.0.113.14",  # decimal DWORD host
    "http://1.2.3.4@0xC0000205/": "192.0.2.5",  # userinfo decoy before a hex host
    "http://0xC0000206:/x": "192.0.2.6",  # empty port after the host
    "::ffff:c633:6405": "198.51.100.5",  # whole-line IPv4-mapped IPv6 on a v4 list
    "198.51.100.77": "198.51.100.77",  # canonical control
}
# Reached by no client (08 is not a valid octal digit) or a decoy: must not be collected.
ABSENT = {
    "http://08.08.08.08/x": "8.8.8.8",
    "http://1.2.3.4@0xC0000205/": "1.2.3.4",
}


@pytest.fixture(scope="module")
def deployed_vm(smoke_vm: SmokeVM) -> Iterator[SmokeVM]:
    """Deploy the branch .pkg once."""
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set - no built .pkg to deploy")
    h.deploy(smoke_vm)
    try:
        yield smoke_vm
    finally:
        h.collect_host_diagnostics(smoke_vm)


@pytest.mark.timeout(300)
def test_ip_feed_numeric_host_collects_decoded_ipv4(deployed_vm: SmokeVM) -> None:
    """Scenario: an IP feed's numeric URL hosts are collected as the IPv4 a client reaches.

    Given an IPv4 Deny_Both feed with octal, hex and DWORD URL hosts, a userinfo decoy, an
      empty-port host, an IPv4-mapped IPv6 line, an invalid 08.08.08.08 host and a canonical control,
    When the IP alias is updated,
    Then pfB_<alias>_v4 holds every decoded address and the control,
      and holds neither 8.8.8.8 nor the decoy 1.2.3.4.
    """
    vm = deployed_vm
    body = "\n".join([*EXPECTED, "http://08.08.08.08/x"]) + "\n"
    feed_url = h.write_local_feed(vm, "smoke_ip_feed_numeric_host.txt", body)
    spec = h.IpCase(aliasname=HEADER, feed_url=feed_url, header=HEADER)
    with h.CaseContext(vm, spec):
        members = h.pfctl_table_members(vm, spec.alias)
        missing = {line: ip for line, ip in EXPECTED.items() if not h.member_present(members, ip)}
        assert not missing, f"{spec.alias} lacks {missing} (feed line -> expected IP); members: {members}"
        leaked = {line: ip for line, ip in ABSENT.items() if h.member_present(members, ip)}
        assert not leaked, f"{spec.alias} holds addresses no client reaches {leaked}; members: {members}"
