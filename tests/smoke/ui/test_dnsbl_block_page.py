"""Live-VM proof the DNSBL sinkhole page correlates a real block (issue #1013).

``tests/php/LogFormatConsumersTest.php`` proves off-box that ``index.php``'s
``dnsbl.log`` correlation grep tolerates the ISO-8601 timestamp format (ADR-60
Phase 5), but nothing drives the real script end-to-end: a genuine DNS block, a
genuine ``dnsbl.log`` line, a genuine HTTP hit on the sinkhole, and a genuine
Type/Group/Evaluated-Domain/Feed render -- as opposed to the ``-`` placeholders
``index.php`` falls back to when the correlation grep misses.

Tier B (``ui_e2e``): the sinkhole listener (lighttpd on the DNSBL VIP, port
80) is outside the authenticated webConfigurator's reach, so Tier A
(``ui_render``) cannot exercise it -- see ``test_render_smoke.py``'s
``EXCLUDED_FROM_TIER_A["dnsbl_vip_sinkhole_pages"]``. This test causes a real
DNS block and a real HTTP correlation (mutating, slow) -- daily/on-demand
only, never the PR gate.
"""

from __future__ import annotations

import re
import subprocess
import time

import pytest

from .. import helpers

pytestmark = pytest.mark.ui_e2e


def test_dnsbl_block_page_shows_real_correlation_detail(deployed_vm: helpers.SmokeVM) -> None:
    """Scenario: a real DNSBL block correlates into the sinkhole page's detail row.

    Given a DNSBL feed listing one unique test domain (VIP mode).
    When the domain is force-updated into the block list, resolved (the real DNS
    query that both proves the block AND writes the ``dnsbl.log`` correlator
    line), then fetched (polled -- the sinkhole restart is async, see below) from
    the sinkhole webserver with that domain as the ``Host`` header.
    Then the page renders "Site blocked via DNSBL" AND its 6-cell detail row's
    Type/Group/Evaluated-Domain/Feed cells are populated from the real
    ``dnsbl.log`` match -- never the ``-`` fallback -- with the Evaluated Domain
    cell equal to the queried name.
    """
    domain = helpers.unique_domain("dnsblpage")
    feed_path = helpers.write_local_feed(deployed_vm, "ui_dnsbl_block_page.txt", f"{domain}\n")
    spec = helpers.DnsblCase(
        aliasname="uidnsblpage", feed_url=feed_path, header="uidnsblpage", mode=helpers.DnsblMode.VIP
    )

    # scope="update" (not CaseContext's default "updatednsbl"): pfb_create_dnsbl()
    # (pfblockerng.inc:5671) -- the NAT/lighttpd-conf/restart_service('pfb_dnsbl')
    # pass that actually starts the sinkhole -- only runs reliably off a FULL
    # update pass; test_functional.py's dnsvip_auto test documents the same split
    # ("a bare update with no DNSBL list does NOT reach the VIP-provisioning pass").
    with helpers.CaseContext(deployed_vm, spec, scope="update"):
        # BEFORE (transition-test discipline): the real DNS query both proves the
        # block itself is real AND writes the dnsbl.log correlator line -- the
        # HTTP probe below only makes sense once this is asserted true.
        answer = helpers.dns_probe(deployed_vm, domain)
        assert helpers.is_vip(answer), f"expected VIP block for {domain!r}, got answer: {answer!r}"

        # THEN: an on-box curl to the sinkhole (the DNSBL VIP is a loopback-scoped
        # lo0 IP-alias, unreachable from the runner) with Host set to the
        # just-blocked domain -- the access recipe test_render_smoke.py documents
        # for reaching index.php/dnsbl_default.php outside the webConfigurator.
        # Runs inside CaseContext so the dnsbl.log line is guaranteed fresh and
        # egress being blocked here doesn't matter (the curl is loopback-local).
        #
        # issue #1013: pfb_create_lighttpd() (pfblockerng.inc:5459-5460) binds the
        # sinkhole to port 80 (443 for TLS) when dnsbl_iface=='lo0' (this harness's
        # VIP mode) -- NAT is skipped entirely for lo0 (pfb_dnsbl_nat_enabled()), so
        # dnsbl_port/dnsbl_port_ssl (8081/8443) never apply here; on a real interface
        # they're the internal NAT local-port, never externally reachable either. The
        # externally-reachable port is always 80/443.
        #
        # pfb_create_dnsbl() (pfblockerng.inc ~5793) restarts the sinkhole via
        # restart_service('pfb_dnsbl'), whose rc script forks lighttpd_pfb --
        # lighttpd self-daemonizes (pfblockerng.inc ~2587-2591, issue #662), so the
        # rc script -- and reload() -- can return before the forked child finishes
        # binding. Poll instead of one unbounded curl, with a short per-attempt
        # timeout so a dropped-not-refused SYN fails fast rather than hanging the
        # whole budget on one attempt.
        curl_argv = (
            helpers.GUEST_CURL,
            "-sS",  # silent but keep stderr -- a bare -s leaves stderr empty on failure
            "--connect-timeout",
            "3",
            "--max-time",
            "8",
            "-H",
            f"Host: {domain}",
            f"http://{helpers.DEFAULT_DNSBL_VIP4}/",
        )
        attempts, delay = 10, 1.5  # lighttpd's post-fork bind is normally sub-second; generous headroom
        result: subprocess.CompletedProcess[str] | None = None
        for attempt in range(attempts):
            result = deployed_vm.ssh(*curl_argv, timeout=15.0)
            if result.returncode == 0 and "Site blocked via DNSBL" in result.stdout:
                break
            if attempt < attempts - 1:
                time.sleep(delay)
        assert result is not None  # attempts >= 1, loop always assigns

        if result.returncode != 0 or "Site blocked via DNSBL" not in result.stdout:
            # Self-diagnosing failure: confirms/refutes the restart race straight from
            # this log, no second CI dispatch + diagnostics-archaeology round trip.
            diag = deployed_vm.ssh(
                "ps auxww | grep -i '[l]ighttpd_pfb'; "
                "/usr/bin/sockstat -4 -l 2>/dev/null | grep -E ':80([[:space:]]|$)' || echo NO_LISTENER",
                timeout=15.0,
            )
            pytest.fail(
                f"sinkhole curl never succeeded after {attempts} attempts: "
                f"rc={result.returncode} stderr={result.stderr!r}\n"
                f"lighttpd_pfb/:80 snapshot (rc={diag.returncode}):\n{diag.stdout}{diag.stderr}"
            )

        # The block marker is already guaranteed by the fail-path above (its condition's
        # negation), so no separate assertion here -- re-asserting it would be dead code.
        body = result.stdout
        cells = re.findall(r"<td>(.*?)</td>", body, re.DOTALL)
        assert len(cells) == 6, (
            f"expected 6 <td> cells (Referer/Client/Type/Group/Evaluated Domain/Feed), got {len(cells)}: {cells}"
        )

        _referer, _client, ptype, group, evald, feed = cells
        for label, value in (("Type", ptype), ("Group", group), ("Evaluated Domain", evald), ("Feed", feed)):
            assert value != "-", (
                f"{label} cell fell back to the '-' placeholder -- dnsbl.log correlation missed for "
                f"{domain!r}; full cells: {cells}"
            )
        assert evald == domain, f"Evaluated Domain cell expected {domain!r}, got {evald!r} (cells: {cells})"
