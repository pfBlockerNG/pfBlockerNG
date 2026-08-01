"""ADR-65 D2 live-VM row: the Alerts page renders a REAL block's LOGGED group/feed.

``test_alerts_render_verify.py`` pins the same contract (logged group/feed render,
no "<s>" strike-through, no "Not currently listed" re-check text) over SEEDED,
deterministic dnsbl.log lines written directly by the test harness. This module
pins the identical contract over a line the package's OWN persistent logger just
wrote for a genuine live DNSBL block -- the durable end-to-end proof the seeded
harness cannot give (SS7 checklist row (d)).

Tier B (``ui_e2e``): causes a real DNS block (mutating, needs a live Unbound) --
daily/on-demand only, never the Tier-A PR gate.

DESELECTED from the default ``python -m pytest`` (``--ignore=tests/smoke``). Run
via the ui-tests workflow or locally::

    python -m pytest tests/smoke/ui -m ui_e2e --override-ini="addopts="
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .webui import looks_like_login_page, row_containing

if TYPE_CHECKING:
    from .webui import WebUI

pytestmark = pytest.mark.ui_e2e

ALERTS_PAGE = "/pfblockerng/pfblockerng_alerts.php"

_DNSBL_LOG_PATHS = ("/var/log/pfblockerng/dnsbl.log", "/var/unbound/var/log/pfblockerng/dnsbl.log")


def _dnsbl_log_hits(vm: helpers.SmokeVM, needle: str, *, timeout: float = 30.0) -> int:
    """Count dnsbl.log lines containing ``needle`` across host + chroot paths (summed).

    Module-local copy of test_smoke_matrix._dnsbl_log_hits' shape (pfb_unbound.py
    runs chrooted at /var/unbound) -- this phase adds new modules only, no
    helpers.py changes.
    """
    res = vm.ssh("grep", "-hcF", "--", needle, *_DNSBL_LOG_PATHS, timeout=timeout)
    return sum(int(tok) for tok in res.stdout.split() if tok.isdigit())


def _dnsbl_log_line(vm: helpers.SmokeVM, needle: str, *, timeout: float = 30.0) -> str:
    """First dnsbl.log line (host or chroot) containing ``needle``; raises loudly if none."""
    res = vm.ssh("grep", "-hF", "--", needle, *_DNSBL_LOG_PATHS, timeout=timeout)
    lines = [ln for ln in res.stdout.splitlines() if ln]
    if not lines:
        raise RuntimeError(
            f"no dnsbl.log line found for {needle!r}: rc={res.returncode} stdout={res.stdout!r} stderr={res.stderr!r}"
        )
    return lines[0]


def test_alerts_row_renders_logged_group_and_feed_live(deployed_vm: helpers.SmokeVM, webui: WebUI) -> None:
    """ADR-65 D2: the Alerts page renders a REAL block's LOGGED group/feed live,
    with the retired re-check's markup gone.

    Given: a unique domain VIP-blocks and its Python dnsbl.log line lands
      (before-state: the log line the page must render).
    When: the Alerts page is fetched authenticated.
    Then: the row for the domain renders the LOGGED group (log field[6]) and
      feed (log field[8]) -- parsed off the same line the page itself reads,
      never hardcoded -- and carries none of the retired re-check's markup
      ("<s>" strike-through, "Not currently listed").
    """
    domain = helpers.unique_domain("adr65alerts")
    feed = helpers.write_local_feed(deployed_vm, "adr65_alerts.txt", f"{domain}\n")
    spec = helpers.DnsblCase(
        aliasname="adr65alerts", feed_url=feed, header="adr65alertshdr", mode=helpers.DnsblMode.VIP
    )

    with helpers.CaseContext(deployed_vm, spec):
        answer = helpers.dns_probe(deployed_vm, domain)
        assert helpers.is_vip(answer), f"expected VIP block for {domain!r}, got {answer!r}"

        hits = 0

        def log_hit_observed() -> bool:
            nonlocal hits
            hits = _dnsbl_log_hits(deployed_vm, domain)
            return hits >= 1

        try:
            helpers.wait_until(log_hit_observed, timeout=30.0, interval=1.0)
        except RuntimeError as exc:
            raise RuntimeError(
                f"salvage cap expired / stuck or environment: ADR-65 dnsbl.log expected hits>=1; observed hits={hits}"
            ) from exc
        line = _dnsbl_log_line(deployed_vm, domain)

        fields = line.split(",")
        assert len(fields) > 8, f"unexpected dnsbl.log line shape for {domain}: {line!r}"
        logged_group, logged_feed = fields[6], fields[8]
        assert logged_group and logged_group != "Unknown", f"empty/Unknown group parsed from log line: {line!r}"
        assert logged_feed and logged_feed != "Unknown", f"empty/Unknown feed parsed from log line: {line!r}"

        resp = webui.get(ALERTS_PAGE)
        assert resp.status_code == 200, f"GET {ALERTS_PAGE} -> HTTP {resp.status_code}"
        assert not looks_like_login_page(resp.text), (
            f"GET {ALERTS_PAGE} returned the login form -- session not authenticated"
        )

        row = row_containing(resp.text, domain)
        assert logged_group in row, f"expected the logged group {logged_group!r} in the Alerts row: {row!r}"
        assert logged_feed in row, f"expected the logged feed {logged_feed!r} in the Alerts row: {row!r}"
        assert "<s>" not in row, (
            f"expected NO strike-through markup (the retired re-check, ADR-65 D2) in the row: {row!r}"
        )
        assert "Not currently listed" not in row, (
            f"expected NO 'Not currently listed' re-check text (ADR-65 D2) in the row: {row!r}"
        )
