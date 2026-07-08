"""Live-VM proof the DNSBL sinkhole page correlates a real block (issue #1013).

``tests/php/LogFormatConsumersTest.php`` proves off-box that ``index.php``'s
``dnsbl.log`` correlation grep tolerates the ISO-8601 timestamp format (ADR-60
Phase 5), but nothing drives the real script end-to-end: a genuine DNS block, a
genuine ``dnsbl.log`` line, a genuine HTTP hit on the sinkhole, and a genuine
Type/Group/Evaluated-Domain/Feed render -- as opposed to the ``-`` placeholders
``index.php`` falls back to when the correlation grep misses.

Tier B (``ui_e2e``): the sinkhole listener (lighttpd on the DNSBL VIP, port
8081) is outside the authenticated webConfigurator's reach, so Tier A
(``ui_render``) cannot exercise it -- see ``test_render_smoke.py``'s
``EXCLUDED_FROM_TIER_A["dnsbl_vip_sinkhole_pages"]``. This test causes a real
DNS block and a real HTTP correlation (mutating, slow) -- daily/on-demand
only, never the PR gate.
"""

from __future__ import annotations

import re
import subprocess

import pytest

from .. import helpers

pytestmark = pytest.mark.ui_e2e


def test_dnsbl_block_page_shows_real_correlation_detail(deployed_vm: helpers.SmokeVM) -> None:
    """Scenario: a real DNSBL block correlates into the sinkhole page's detail row.

    Given a DNSBL feed listing one unique test domain (VIP mode).
    When the domain is force-updated into the block list, resolved (the real DNS
    query that both proves the block AND writes the ``dnsbl.log`` correlator
    line), then fetched from the sinkhole webserver with that domain as the
    ``Host`` header.
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

    with helpers.CaseContext(deployed_vm, spec):
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
        result = subprocess.run(
            deployed_vm.ssh_argv(
                helpers.GUEST_CURL, "-s", "-H", f"Host: {domain}", f"http://{helpers.DEFAULT_DNSBL_VIP4}:8081/"
            ),
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, (
            f"on-box curl to the DNSBL sinkhole failed: rc={result.returncode} stderr={result.stderr!r}"
        )

        body = result.stdout
        assert "Site blocked via DNSBL" in body, f"sinkhole page missing its block marker; body:\n{body}"

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
