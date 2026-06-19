"""Issue #267 — live-VM smoke for upstream/external DNS block detection.

pfBlockerNG detects when pfSense's Unbound forwards a query to a filtering
resolver (e.g. Quad9) and the upstream returns a block signal. Two signals are
recognised:

* **NXRA** — NXDOMAIN reply with RA (Recursion Available) bit CLEARED and AA
  (Authoritative Answer) bit CLEARED. A filtering resolver synthesises NXDOMAIN
  and clears RA; a genuinely authoritative NXDOMAIN sets AA (excluded).
* **EDE15** / **EDE17** — RFC 8914 Extended DNS Error options with INFO-CODE
  15 (Blocked) or 17 (Filtered), regardless of RA or rcode.

Detection fires in ``inplace_cb_query_response`` (the raw upstream-response
hook), which preserves the upstream RA/AA bits and EDNS options before Unbound
normalises the client reply (where RA is always forced to 1). It is gated on
forwarding mode (``pfb["forwarding"]``): only active when Unbound is in resolver
forwarding mode.

When triggered, a ``DNSBL-python``-source CSV line is written to
``/var/log/pfblockerng/dnsbl.log`` and ``unified.log`` with ``b_type``
``Upstream_Block``, ``group`` ``Upstream``, and ``b_eval`` equal to the
classifier label (``"NXRA"``, ``"EDE15 (Blocked)"``, etc.).

The ``Upstream`` groupname row in the SQLite ``dnsbl`` table is seeded by
``dnsbl_save_stats()`` in PHP and its ``counter`` column is incremented by
Python on each upstream block — the same pattern as per-feed DNSBL counters.

These tests are DESELECTED from the default ``python -m pytest`` run. Run via::

    python -m pytest tests/smoke -m smoke --override-ini="addopts="

They need the booted ``smoke_vm`` fixture, the branch ``.pkg`` (``SMOKE_PKG``),
and the smoke deps.
"""

from __future__ import annotations

import os
import time
from collections.abc import Iterator

import pytest

from . import helpers as h
from .conftest import SmokeVM, _StubDnsServer

pytestmark = [pytest.mark.smoke, pytest.mark.upstream]


# ---------------------------------------------------------------------------
# Module-scoped deploy fixture
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def deployed_vm(smoke_vm: SmokeVM, stub_dns: _StubDnsServer) -> Iterator[SmokeVM]:  # noqa: ARG001
    """Deploy the branch .pkg once with DNSBL/python active and forwarding to the stub.

    ``use_system_dns_upstream`` wires forwarding:
      guest Unbound → 10.0.2.2:53 (SLIRP NAT) → runner 127.0.0.1:53 (stub).

    pfBlockerNG force-disables DNSBL — and so never injects the Unbound ``python:``
    module, meaning ``inplace_cb_query_response`` is never registered — unless at least
    one DNSBL feed is configured. We therefore seed ONE minimal LOCAL feed whose single
    domain is unrelated to the probe names, purely to activate the Python module. The
    upstream-block probes below are forwarded to the stub (they are NOT in this feed),
    so they exercise the forwarding path and reach ``inplace_cb_query_response``.
    """
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    h.snapshot_unbound_conf(smoke_vm)
    h.ensure_dnsbl_vip(smoke_vm)
    h.use_system_dns_upstream(smoke_vm)
    # Seed a minimal local DNSBL feed so pfBlockerNG injects the Unbound python module
    # (else DNSBL self-disables and inplace_cb_query_response never fires). The seed
    # domain is distinct from every probe name, so it never shadows a forwarded probe.
    seed = h.unique_domain("pfbsmoke-upstream-seed")
    feed_url = h.write_local_feed(smoke_vm, "smoke_upstream_seed.txt", f"{seed}\n")
    h.inject(
        smoke_vm,
        h.DnsblCase(aliasname="smokeupstream", feed_url=feed_url, header="smokeupstream", mode=h.DnsblMode.VIP),
    )
    h.reload(smoke_vm, "update")
    h.wait_unbound_ready(smoke_vm)
    try:
        yield smoke_vm
    finally:
        h.unblock_egress()
        h.collect_host_diagnostics(smoke_vm)


# ---------------------------------------------------------------------------
# Helper: read the on-box dnsbl.log over SSH
# ---------------------------------------------------------------------------

_DNSBL_LOG = "/var/log/pfblockerng/dnsbl.log"


def _read_dnsbl_log(vm: SmokeVM) -> str:
    return h.read_log_file(vm, _DNSBL_LOG)


def _upstream_block_lines(log: str, name: str) -> list[str]:
    """Lines in ``log`` with source DNSBL-python, b_type Upstream_Block, and ``name``."""
    out = []
    for line in log.splitlines():
        # Cheapest guard first (ADR-28 conv #2): the source prefix rules out most lines
        # before the substring scans.
        if line.startswith("DNSBL-python") and "Upstream_Block" in line and name in line:
            out.append(line)
    return out


def _wait_for_upstream_block_lines(vm: SmokeVM, name: str, *, timeout_s: float = 8.0, poll_s: float = 0.5) -> list[str]:
    """Poll the on-box dnsbl.log for ``name``'s Upstream_Block lines until they appear.

    The python module logs asynchronously (a queue flush), so a fresh probe's line is
    not instantaneous. Bounded polling is steadier than a fixed sleep on slow CI VMs and
    returns as soon as the line lands on fast paths. (Absence checks can't poll — they
    keep a fixed settle, see the control tests.)
    """
    deadline = time.monotonic() + timeout_s
    lines: list[str] = []
    while time.monotonic() < deadline:
        lines = _upstream_block_lines(_read_dnsbl_log(vm), name)
        if lines:
            return lines
        time.sleep(poll_s)
    return lines


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestUpstreamBlockNXRA:
    """NXRA signal: upstream NXDOMAIN with RA cleared (Quad9 block shape).

    Scenario: Unbound is in forwarding mode. The stub upstream returns NXDOMAIN
    with RA=0, AA=0 — the signature of a filtering resolver blocking a domain.
    The classifier detects this as NXRA and logs it.
    """

    def test_nxra_block_detected_and_logged(self, deployed_vm: SmokeVM, stub_dns: _StubDnsServer) -> None:
        """
        Given: Unbound forwards to the stub; stub answers NXDOMAIN (RA=0, AA=0) for a name.
        When: the on-box resolver resolves that name.
        Then:
          - Client gets NXDOMAIN (upstream answer passed through).
          - A log line with b_type=Upstream_Block and b_eval=NXRA appears in dnsbl.log.
        """
        name = h.unique_domain("pfbsmoke-upstream-nxra")
        stub_dns.register_nxdomain(name)  # default: RA=0, AA=0

        # Resolve on-box; first response is authoritative.
        ans = h.dns_probe(deployed_vm, name, "A")
        assert ans.rcode == "NXDOMAIN", f"Expected NXDOMAIN for {name}, got {ans.rcode}"

        lines = _wait_for_upstream_block_lines(deployed_vm, name)
        assert lines, (
            f"No Upstream_Block log line for {name} after NXRA probe.\n"
            f"Log excerpt (last 3000 chars):\n{_read_dnsbl_log(deployed_vm)[-3000:]}"
        )
        assert any("NXRA" in line for line in lines), (
            f"Upstream_Block line found but b_eval is not NXRA.\nLines: {lines}"
        )


class TestUpstreamBlockEDE15:
    """EDE 15 (Blocked) signal: upstream NXDOMAIN with RFC 8914 EDE option."""

    def test_ede15_block_detected_with_provider(self, deployed_vm: SmokeVM, stub_dns: _StubDnsServer) -> None:
        """
        Given: stub answers NXDOMAIN + EDE INFO-CODE 15 with EXTRA-TEXT "Quad9".
        When: the on-box resolver resolves that name.
        Then:
          - dnsbl.log contains an Upstream_Block line for the name.
          - b_eval is "EDE15 (Blocked)".
          - feed/provider column contains "Quad9".
        """
        name = h.unique_domain("pfbsmoke-upstream-ede15")
        stub_dns.register_nxdomain(name, ede_info_code=15, ede_text="Quad9")

        ans = h.dns_probe(deployed_vm, name, "A")
        assert ans.rcode == "NXDOMAIN", f"Expected NXDOMAIN for {name}, got {ans.rcode}"

        lines = _wait_for_upstream_block_lines(deployed_vm, name)
        assert lines, (
            f"No Upstream_Block log line for {name} (EDE15).\nLog excerpt:\n{_read_dnsbl_log(deployed_vm)[-3000:]}"
        )
        assert any("EDE15 (Blocked)" in line for line in lines), f"b_eval is not 'EDE15 (Blocked)'.\nLines: {lines}"
        assert any("Quad9" in line for line in lines), (
            f"Provider 'Quad9' not found in Upstream_Block line.\nLines: {lines}"
        )


class TestUpstreamBlockEDE17:
    """EDE 17 (Filtered) signal: upstream NXDOMAIN with RFC 8914 EDE option.

    Twin of the EDE15 case for the other recognised EDE info-code, so both documented
    signals are exercised on the live-VM path (test-coverage mandate: every branch).
    """

    def test_ede17_block_detected_with_provider(self, deployed_vm: SmokeVM, stub_dns: _StubDnsServer) -> None:
        """
        Given: stub answers NXDOMAIN + EDE INFO-CODE 17 (Filtered) with EXTRA-TEXT "Quad9".
        When: the on-box resolver resolves that name.
        Then:
          - dnsbl.log contains an Upstream_Block line for the name.
          - b_eval is "EDE17 (Filtered)".
          - feed/provider column contains "Quad9".
        """
        name = h.unique_domain("pfbsmoke-upstream-ede17")
        stub_dns.register_nxdomain(name, ede_info_code=17, ede_text="Quad9")

        ans = h.dns_probe(deployed_vm, name, "A")
        assert ans.rcode == "NXDOMAIN", f"Expected NXDOMAIN for {name}, got {ans.rcode}"

        lines = _wait_for_upstream_block_lines(deployed_vm, name)
        assert lines, (
            f"No Upstream_Block log line for {name} (EDE17).\nLog excerpt:\n{_read_dnsbl_log(deployed_vm)[-3000:]}"
        )
        assert any("EDE17 (Filtered)" in line for line in lines), f"b_eval is not 'EDE17 (Filtered)'.\nLines: {lines}"
        assert any("Quad9" in line for line in lines), (
            f"Provider 'Quad9' not found in Upstream_Block line.\nLines: {lines}"
        )


class TestUpstreamBlockAuthoritativeControl:
    """Control: authoritative NXDOMAIN (AA=1) must NOT be detected as an upstream block.

    This is the before/after discriminator for the AA guard: same NXDOMAIN + RA=0,
    but AA=1 means the server is authoritative (e.g. a local zone) not a filtering
    resolver. The classifier must return None.
    """

    def test_authoritative_nxdomain_not_logged(self, deployed_vm: SmokeVM, stub_dns: _StubDnsServer) -> None:
        """
        Given: stub answers NXDOMAIN with AA=1, RA=0 (authoritative NXDOMAIN).
        When: the on-box resolver resolves that name.
        Then:
          - Client gets NXDOMAIN (upstream answer passed through).
          - NO Upstream_Block log line appears (AA=1 excludes it).

        Before-state: same name would be detected if AA=0 (the NXRA case above).
        """
        name = h.unique_domain("pfbsmoke-upstream-auth")
        stub_dns.register_nxdomain(name, authoritative=True)  # AA=1, RA=0

        # Before: confirm the name returns NXDOMAIN (the upstream answered).
        ans = h.dns_probe(deployed_vm, name, "A")
        assert ans.rcode == "NXDOMAIN", f"Expected NXDOMAIN for {name}, got {ans.rcode}"

        time.sleep(2)
        log = _read_dnsbl_log(deployed_vm)
        lines = _upstream_block_lines(log, name)
        assert not lines, (
            f"Authoritative NXDOMAIN (AA=1) produced an Upstream_Block line — "
            f"AA guard not working.\nLines: {lines}\nLog excerpt:\n{log[-2000:]}"
        )


class TestUpstreamBlockForwarderNaturalControl:
    """Control: forwarder-relayed natural NXDOMAIN (RA=1) must NOT be detected.

    This is the before/after discriminator for the RA guard: NXDOMAIN + RA=1
    (a recursive resolver relaying a real NXDOMAIN). The classifier must return None.
    """

    def test_forwarder_natural_nxdomain_not_logged(self, deployed_vm: SmokeVM, stub_dns: _StubDnsServer) -> None:
        """
        Given: stub answers NXDOMAIN with RA=1, AA=0 (forwarder-relayed natural NXDOMAIN).
        When: the on-box resolver resolves that name.
        Then:
          - Client gets NXDOMAIN.
          - NO Upstream_Block log line appears (RA=1 excludes it).
        """
        name = h.unique_domain("pfbsmoke-upstream-fwdnat")
        stub_dns.register_nxdomain(name, recursion_available=True)  # RA=1, AA=0

        ans = h.dns_probe(deployed_vm, name, "A")
        assert ans.rcode == "NXDOMAIN", f"Expected NXDOMAIN for {name}, got {ans.rcode}"

        time.sleep(2)
        log = _read_dnsbl_log(deployed_vm)
        lines = _upstream_block_lines(log, name)
        assert not lines, (
            f"Forwarder-natural NXDOMAIN (RA=1) produced an Upstream_Block line — "
            f"RA guard not working.\nLines: {lines}\nLog excerpt:\n{log[-2000:]}"
        )


class TestUpstreamBlockNormalControl:
    """Control: a name resolving normally must NOT produce an Upstream_Block line."""

    def test_normal_resolution_not_logged(self, deployed_vm: SmokeVM, stub_dns: _StubDnsServer) -> None:
        """
        Given: an unregistered name (stub answers NOERROR with sentinel A record).
        When: the on-box resolver resolves it.
        Then: NO Upstream_Block line appears (NOERROR, not a block).

        Before-state: the name resolves to the stub sentinel, proving the forwarding
        path works. After: no Upstream_Block line in the log.
        """
        name = h.unique_domain("pfbsmoke-upstream-ctrl")
        # Not registered → stub answers NOERROR + sentinel STUB_DNS_A.

        # Before: confirm normal resolution works (forwarding active, stub reachable).
        ans = h.dns_probe(deployed_vm, name, "A")
        assert h.resolves_to(ans, h.STUB_DNS_A), f"Control name should resolve to sentinel {h.STUB_DNS_A}, got {ans}"

        time.sleep(2)
        log = _read_dnsbl_log(deployed_vm)
        lines = _upstream_block_lines(log, name)
        assert not lines, (
            f"Normal resolution produced Upstream_Block lines — over-triggering.\n"
            f"Lines: {lines}\nLog excerpt:\n{log[-2000:]}"
        )


# ---------------------------------------------------------------------------
# Upstream SQLite counter — dnsbl table row increments end-to-end
# ---------------------------------------------------------------------------

_DNSBL_DB = "/var/unbound/pfb_py_dnsbl.sqlite"
_CTR_OPEN = "<<<UPCTR>>>"
_CTR_CLOSE = "<<<UPEND>>>"


def _read_upstream_counter(vm: SmokeVM) -> int:
    """Read the ``counter`` of the ``Upstream`` row from the on-box dnsbl SQLite DB.

    Uses pfSsh.php (PHP + the SQLite3 class the package itself runs on), NOT a python
    one-liner: the appliance ships ``python3.11`` with no ``python3`` symlink, so a
    ``python3 -c`` read is not portable. Reads the same ``/var/unbound/pfb_py_dnsbl.sqlite``
    the chrooted Python module writes. The value is delimited so pfSsh.php's startup
    banner does not pollute it. Returns the integer counter, or -1 when the row is
    absent or the DB/table cannot be read.
    """
    snippet = (
        "$__c = -1;\n"
        "try {\n"
        f"    $__db = new SQLite3('{_DNSBL_DB}');\n"
        "    $__r = $__db->querySingle(\"SELECT counter FROM dnsbl WHERE groupname = 'Upstream'\");\n"
        "    $__c = ($__r === null || $__r === FALSE) ? -1 : (int) $__r;\n"
        "    $__db->close();\n"
        "} catch (Throwable $__e) { $__c = -1; }\n"
        f"echo '{_CTR_OPEN}' . $__c . '{_CTR_CLOSE}';\n"
    )
    out = h.php_eval(vm, snippet).stdout or ""
    start = out.find(_CTR_OPEN)
    end = out.find(_CTR_CLOSE)
    if start == -1 or end == -1:
        return -1
    try:
        return int(out[start + len(_CTR_OPEN) : end])
    except ValueError:
        return -1


def _wait_for_counter_above(vm: SmokeVM, baseline: int, *, timeout_s: float = 30.0, poll_s: float = 2.0) -> int:
    """Poll the on-box Upstream dnsbl counter until it exceeds ``baseline`` or the deadline expires.

    The counter is flushed by the async db_worker thread, so a freshly-logged block
    does not appear instantly.  Bounded polling matches the log-line polling pattern
    used by ``_wait_for_upstream_block_lines``.

    Returns the final observed counter value (may equal ``baseline`` on timeout).
    """
    deadline = time.monotonic() + timeout_s
    current = baseline
    while time.monotonic() < deadline:
        current = _read_upstream_counter(vm)
        if current > baseline:
            return current
        time.sleep(poll_s)
    return current


class TestUpstreamCounterIncrement:
    """The dnsbl SQLite Upstream counter increments end-to-end on an upstream block.

    Scenario: an NXRA block is logged by _log_upstream_block; the async
    db_worker flushes the enqueued ("dnsbl", "Upstream") task; the on-box
    ``counter`` column for the Upstream row increases.

    Before/after: counter is read BEFORE the probe and AFTER, asserting a
    strict increase so that the test fails if the counter is stuck.
    """

    def test_upstream_counter_increments_on_nxra_block(self, deployed_vm: SmokeVM, stub_dns: _StubDnsServer) -> None:
        """
        Given: DNSBL active, forwarding to stub, dnsbl table seeded with Upstream row.
        When: stub answers NXDOMAIN (RA=0, AA=0) — an NXRA upstream block is logged.
        Then: the on-box dnsbl counter for groupname='Upstream' strictly increases.
        """
        name = h.unique_domain("pfbsmoke-upstream-ctr")
        stub_dns.register_nxdomain(name)  # RA=0, AA=0 -> NXRA block

        # Before: record the baseline counter (row may already have a count from
        # earlier tests in this session).
        baseline = _read_upstream_counter(deployed_vm)
        assert baseline >= 0, (
            "Upstream row not found in dnsbl table before probe — "
            "the Python DB-init seed (_db_create) did not create it. "
            f"DB: {_DNSBL_DB!r}"
        )

        # When: trigger a block (first response is authoritative — assert it arrived).
        ans = h.dns_probe(deployed_vm, name, "A")
        assert ans.rcode == "NXDOMAIN", f"Expected NXDOMAIN for {name}, got {ans.rcode}"

        # Confirm the block line was logged (proves the detection fired, not just a
        # natural NXDOMAIN — the counter increment is meaningless without this).
        lines = _wait_for_upstream_block_lines(deployed_vm, name)
        assert lines, (
            f"No Upstream_Block log line for {name} — detection did not fire; "
            f"counter increment cannot be attributed to an upstream block.\n"
            f"Log excerpt:\n{_read_dnsbl_log(deployed_vm)[-2000:]}"
        )

        # Then: wait for the async flush and assert strict increase.
        final = _wait_for_counter_above(deployed_vm, baseline)
        assert final > baseline, (
            f"Upstream counter did not increase after NXRA block: "
            f"baseline={baseline}, final={final}. "
            f"Detection fired (log line present), so the enqueue or flush may be broken."
        )
