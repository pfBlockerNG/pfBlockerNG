"""CVE-2026-78902 — live-VM smoke for DNS logging with write-side escaping.

NetSPI showed a TXT reply carrying ``"><script ...>`` reaching ``dns_reply.log``
raw. v4 pages escape log fields on output; ``_log_text()`` in ``pfb_unbound.py``
additionally rewrites ``< > " ' &`` and control characters to ``\\DDD`` before a
row is written. These cases prove, on a real Unbound + python module, that:

* a TXT answer carrying the payload is still delivered to the client, and its
  ``dns_reply.log`` row holds the escaped payload in the reply column;
* a CNAME answer whose target label carries quote and angle brackets is logged
  escaped the same way (every non-address type shares that reply column);
* a queried name carrying angle brackets reaches the log as Unbound's own
  ``qname_str`` rendering (``dname_str()`` turns every byte outside
  ``[A-Za-z0-9-_*]`` into ``?``), so the name column never carries raw ``<>``;
* an ordinary A answer is logged exactly as before (10 columns, plain name, IP);
* a DNSBL block is logged exactly as before (11 columns, plain name).

Guest Unbound forwards to the runner-side ``stub_dns`` over SLIRP
(``use_system_dns_upstream``), so the TXT payload comes off the wire the way an
attacker's authoritative server would send it.
"""

from __future__ import annotations

import csv
import os
import re
import time
from collections.abc import Iterator

import pytest

from . import helpers as h
from .conftest import SmokeVM, _StubDnsServer

pytestmark = [pytest.mark.smoke]

_DNS_REPLY_LOG = "/var/log/pfblockerng/dns_reply.log"
_DNSBL_LOG = "/var/log/pfblockerng/dnsbl.log"
_PY_INI = "/var/unbound/pfb_unbound.ini"

PAYLOAD = b"\"><script src='//x.example/a.js'></script>&"
PAYLOAD_ESCAPED = "\\034\\062\\060script src=\\039//x.example/a.js\\039\\062\\060/script\\062\\038"
HOSTILE_TARGET = 'we\\"ird\\<x\\>.example.'  # presentation form of the label we"ird<x>
HOSTILE_TARGET_ESCAPED = "we\\034ird\\060x\\062.example"


@pytest.fixture(scope="module")
def deployed_vm(smoke_vm: SmokeVM, client_vm: SmokeVM, stub_dns: _StubDnsServer) -> Iterator[tuple[SmokeVM, SmokeVM]]:  # noqa: ARG001
    """Deploy the branch .pkg with DNSBL python mode active and forwarding to the stub.

    One LOCAL feed activates the python module (DNSBL self-disables with no feed); its
    single domain doubles as the DNSBL-block control.
    """
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    h.snapshot_unbound_conf(smoke_vm)
    h.ensure_dnsbl_vip(smoke_vm)
    h.use_system_dns_upstream(smoke_vm)
    seed = h.unique_domain("pfbsmoke-replylog-seed")
    feed_url = h.write_local_feed(smoke_vm, "smoke_replylog_seed.txt", f"{seed}\n")
    h.inject(
        smoke_vm,
        h.DnsblCase(aliasname="smokereplylog", feed_url=feed_url, header="smokereplylog", mode=h.DnsblMode.VIP),
    )
    h.reload(smoke_vm, "update")
    h.wait_unbound_ready(smoke_vm)
    h.assert_link_health(client_vm, smoke_vm, control_name=h.unique_domain())
    smoke_vm._pfb_replylog_seed = seed  # type: ignore[attr-defined]
    try:
        # The ini separates key and value with a tab ("python_reply\t= on").
        ini = h.read_log_file(smoke_vm, _PY_INI)
        assert re.search(r"^python_reply\s*=\s*on\s*$", ini, re.M), f"DNS Reply logging is not on in {_PY_INI}:\n{ini}"
        yield smoke_vm, client_vm
    finally:
        h.unblock_egress()
        h.collect_host_diagnostics(smoke_vm)


def _rows(vm: SmokeVM, log: str, prefix: str, name: str, name_col: int, *, suffix: bool = False) -> list[list[str]]:
    raw = [line for line in h.read_log_file(vm, log).splitlines() if line.startswith(prefix)]
    return [
        row
        for row in csv.reader(raw)
        if len(row) > name_col and (row[name_col].endswith(name) if suffix else row[name_col] == name)
    ]


def _wait_rows(
    vm: SmokeVM, log: str, prefix: str, name: str, name_col: int, *, suffix: bool = False, timeout_s: float = 15.0
) -> list[list[str]]:
    """Poll ``log`` until a ``prefix`` row names ``name`` (the module logs through a queue)."""
    deadline = time.monotonic() + timeout_s
    while True:
        rows = _rows(vm, log, prefix, name, name_col, suffix=suffix)
        if rows:
            return rows
        if time.monotonic() >= deadline:
            tail = h.read_log_file(vm, log)[-3000:]
            raise AssertionError(f"no {prefix} row for {name!r} in {log} after {timeout_s}s; tail={tail!r}")
        time.sleep(0.5)


class TestDnsReplyLogEscape:
    def test_txt_payload_is_delivered_and_logged_escaped(
        self, deployed_vm: tuple[SmokeVM, SmokeVM], stub_dns: _StubDnsServer
    ) -> None:
        # Given: the upstream answers TXT for a fresh name with the NetSPI-style payload
        vm, cvm = deployed_vm
        name = h.unique_domain("pfbsmoke-replylog-txt")
        stub_dns.register_txt(name, PAYLOAD)

        # When: a LAN client resolves it
        ans = h.dns_probe_client(cvm, name, "TXT")

        # Then: the client still gets the answer, and the log row carries the escaped payload
        assert ans.rcode == "NOERROR", f"TXT {name}: {ans}"
        assert ans.records, f"TXT {name}: no TXT record delivered to the client: {ans}"
        rows = _wait_rows(vm, _DNS_REPLY_LOG, "DNS-reply,", name, 6)
        for row in rows:
            assert len(row) == 10, row
            assert row[8] == PAYLOAD_ESCAPED, row
        raw = [line for line in h.read_log_file(vm, _DNS_REPLY_LOG).splitlines() if name in line]
        assert not any(c in line for line in raw for c in "<>\"'"), raw

    def test_cname_target_is_logged_escaped(
        self, deployed_vm: tuple[SmokeVM, SmokeVM], stub_dns: _StubDnsServer
    ) -> None:
        vm, cvm = deployed_vm
        name = h.unique_domain("pfbsmoke-replylog-cname")
        stub_dns.register_rdata(name, "CNAME", HOSTILE_TARGET)

        ans = h.dns_probe_client(cvm, name, "CNAME")

        assert ans.rcode == "NOERROR", f"CNAME {name}: {ans}"
        rows = _wait_rows(vm, _DNS_REPLY_LOG, "DNS-reply,", name, 6)
        for row in rows:
            assert len(row) == 10, row
            assert row[8] == HOSTILE_TARGET_ESCAPED, row
        raw = [line for line in h.read_log_file(vm, _DNS_REPLY_LOG).splitlines() if name in line]
        assert not any(c in line for line in raw for c in "<>\"'"), raw

    def test_hostile_query_name_is_sanitised_by_unbound(
        self, deployed_vm: tuple[SmokeVM, SmokeVM], stub_dns: _StubDnsServer
    ) -> None:
        vm, cvm = deployed_vm
        suffix = h.unique_domain("pfbsmoke-replylog-qname")
        stub_dns.register_a(f"a<b>.{suffix}", "203.0.113.42")

        ans = h.dns_probe_client(cvm, f"a<b>.{suffix}", "A")

        assert ans.rcode == "NOERROR" and ans.records == ["203.0.113.42"], ans
        rows = _wait_rows(vm, _DNS_REPLY_LOG, "DNS-reply,", f".{suffix}", 6, suffix=True)
        for row in rows:
            assert len(row) == 10, row
            # Unbound, not pfBlockerNG, rewrites the brackets (dname_str); the row sees "?".
            assert row[6] == f"a?b?.{suffix}", row
            assert row[8] == "203.0.113.42", row
        raw = [line for line in h.read_log_file(vm, _DNS_REPLY_LOG).splitlines() if suffix in line]
        assert not any(c in line for line in raw for c in "<>"), raw

    def test_a_reply_is_logged_unchanged(self, deployed_vm: tuple[SmokeVM, SmokeVM], stub_dns: _StubDnsServer) -> None:
        vm, cvm = deployed_vm
        name = h.unique_domain("pfbsmoke-replylog-a")
        stub_dns.register_a(name, "203.0.113.41")

        ans = h.dns_probe_client(cvm, name, "A")

        assert ans.rcode == "NOERROR" and ans.records == ["203.0.113.41"], ans
        rows = _wait_rows(vm, _DNS_REPLY_LOG, "DNS-reply,", name, 6)
        for row in rows:
            assert len(row) == 10, row
            assert row[4] == "A", row
            assert row[8] == "203.0.113.41", row

    def test_dnsbl_block_is_logged_unchanged(self, deployed_vm: tuple[SmokeVM, SmokeVM]) -> None:
        vm, cvm = deployed_vm
        seed: str = vm._pfb_replylog_seed  # type: ignore[attr-defined]
        h.flush_unbound_name(vm, seed)

        ans = h.dns_probe_client(cvm, seed, "A")

        assert h.is_vip(ans), f"DNSBL seed {seed} expected VIP, got {ans}"
        rows = _wait_rows(vm, _DNSBL_LOG, "DNSBL-python,", seed, 2)
        for row in rows:
            assert len(row) == 11, row
            assert row[8] not in ("", "Unknown"), row  # feed column still resolved
