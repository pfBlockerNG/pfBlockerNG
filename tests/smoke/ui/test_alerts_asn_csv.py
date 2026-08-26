"""Tier-A ``ui_render`` coverage for the ASN CSV-column schema (issue #1369,
ADR-38 Amendment 3).

The single pipe-delimited ASN blob field in ``ip_block.log`` (etc.) is
replaced by 3 plain CSV columns (``asn``, ``asn_domain``, ``asn_name``),
CSV-escaped via native ``fputcsv()``. The owner's 2026-07-18 amendment drops
ALL back-compat for log entries: ``convert_ip_log()`` parses ONLY the current
23-field feature-row schema; a pre-upgrade legacy (21-field, single-blob) row
is skipped silently -- no PHP warning/notice, the row simply never renders,
until log rotation removes it.

This module seeds real log content directly into ``ip_block.log`` (the same
CSV-injection technique ``test_alerts.py``'s suppression-icon test uses) and
asserts what a generic 200-status sweep never would: a NEW-schema row's ASN
+ tooltip actually render, a LEGACY-schema row renders NOTHING (not a
garbled/partial row), and the page carries no PHP diagnostic either in the
response body OR the server's own ``php_error.log`` (``PhpErrorLogGuard``,
the sweep-level oracle condition ``(d)`` a body-only check would miss).
"""

from __future__ import annotations

import re
import subprocess
import time
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .render_oracle import PhpErrorLogGuard, evaluate_render
from .webui import looks_like_login_page

if TYPE_CHECKING:
    from collections.abc import Iterator

    from ..conftest import SmokeVM
    from .webui import WebUI

pytestmark = pytest.mark.ui_render

ALERTS_PAGE = "/pfblockerng/pfblockerng_alerts.php"
IP_BLOCK_LOG = "/var/log/pfblockerng/ip_block.log"
ASN_REPORTING_CFG = "installedpackages/pfblockerngipsettings/config/0/asn_reporting"

# RFC 5737 TEST-NET-3 -- clearly synthetic, never a real routable host.
NEW_SCHEMA_HOST = "203.0.113.50"
LEGACY_SCHEMA_HOST = "203.0.113.51"

NEW_SCHEMA_ASN = "AS64500"
NEW_SCHEMA_DOMAIN = "example,test"  # comma -- must round-trip through real CSV quoting
NEW_SCHEMA_NAME = "Example, Org"  # comma -- same


@pytest.fixture
def _asn_reporting_enabled(smoke_vm: SmokeVM) -> Iterator[None]:
    """Force ``asn_reporting`` on (any non-'disabled' value) for the test, restore after.

    The Alerts page's ASN column renders nothing at all when ASN reporting is
    disabled (``$pfb['asn_reporting'] != 'disabled'`` gate), independent of
    what the log rows themselves carry -- this fixture is the precondition
    every assertion below depends on.
    """
    vm = smoke_vm
    original = helpers.config_get(vm, ASN_REPORTING_CFG)
    enable = helpers.php_eval(
        vm,
        f"config_set_path('{ASN_REPORTING_CFG}', 'week');\n"
        "write_config('pfBlockerNG smoke: enable asn_reporting for issue #1369 ASN CSV test');\n"
        "echo 'OK';",
    )
    assert enable.returncode == 0 and "OK" in enable.stdout, (
        f"failed to enable asn_reporting (rc={enable.returncode}, stdout={enable.stdout!r}) -- "
        "config may be partially mutated"
    )
    try:
        yield
    finally:
        restore = helpers.php_eval(
            vm,
            f"config_set_path('{ASN_REPORTING_CFG}', '{original}');\n"
            "write_config('pfBlockerNG smoke: restore asn_reporting after issue #1369 ASN CSV test');\n"
            "echo 'OK';",
        )
        assert restore.returncode == 0 and "OK" in restore.stdout, (
            f"failed to restore asn_reporting={original!r} (rc={restore.returncode}, "
            f"stdout={restore.stdout!r}) -- config state leaked to sibling smoke modules"
        )


@pytest.fixture
def _seeded_ip_block_log(smoke_vm: SmokeVM) -> Iterator[None]:
    """Append one new-schema + one legacy-schema row to ``ip_block.log``; restore size after.

    Feed files are seeded in the deny folder so both rows are "still listed"
    (avoids the unrelated find_reported_header() miss-path noise; the NB in
    ``test_alerts.py``'s suppression-icon test explains why this matters for
    a clean, focused assertion).
    """
    vm = smoke_vm
    ts = time.strftime("%Y-%m-%d %H:%M:%S")

    # NEW schema (23 raw fields incl. timestamp): ...,feed,rhost,chost,
    # asn,asn_domain,asn_name,dup -- the comma-bearing domain/name are
    # RFC4180-quoted (double-quote wrapping, no escape character), the
    # exact bytes pfb_asn_csv_fields()/fputcsv() emit for these values.
    new_row = (
        f"{ts},100,em0,WAN,block,4,6,TCP,"
        f"{NEW_SCHEMA_HOST},10.0.0.5,12345,443,"
        f"in,US,pfB_Deny_v4,{NEW_SCHEMA_HOST},pfB_AsnFeedNew,Unknown,Unknown,"
        f'{NEW_SCHEMA_ASN},"{NEW_SCHEMA_DOMAIN}","{NEW_SCHEMA_NAME}",+\n'
    )
    # LEGACY schema (21 raw fields): the single pipe-blob ASN column, no
    # asn_domain/asn_name -- must render NOTHING per the owner's no-back-compat
    # amendment, not a garbled row.
    legacy_row = (
        f"{ts},100,em0,WAN,block,4,6,TCP,"
        f"{LEGACY_SCHEMA_HOST},10.0.0.6,12345,443,"
        f"in,US,pfB_Deny_v4,{LEGACY_SCHEMA_HOST},pfB_AsnFeedLegacy,Unknown,Unknown,"
        "|ASN:  AS99999 | domain:  legacy.example | name:  Legacy Org |,+\n"
    )

    log_dir = IP_BLOCK_LOG.rsplit("/", 1)[0]
    deny_feed_new = "/var/db/pfblockerng/deny/pfB_AsnFeedNew.txt"
    deny_feed_legacy = "/var/db/pfblockerng/deny/pfB_AsnFeedLegacy.txt"

    # Every mutation registers its undo BEFORE the next fallible step runs, so
    # a failure anywhere mid-setup still tears down what already landed
    # instead of leaking feed files / log rows into sibling smoke modules.
    feeds_seeded = False
    original_size: str | None = None
    try:
        ensure = vm.ssh(f"mkdir -p {log_dir} && touch {IP_BLOCK_LOG}", timeout=15)
        assert ensure.returncode == 0, f"failed to ensure {IP_BLOCK_LOG} exists: {ensure.stderr!r}"

        seed = vm.ssh(
            f"printf '{NEW_SCHEMA_HOST}\\n' > {deny_feed_new} && printf '{LEGACY_SCHEMA_HOST}\\n' > {deny_feed_legacy}",
            timeout=15,
        )
        feeds_seeded = True
        assert seed.returncode == 0, f"failed to seed deny-folder feed files: stderr={seed.stderr!r}"

        size_before = vm.ssh("stat", "-f", "%z", IP_BLOCK_LOG, timeout=15)
        assert size_before.returncode == 0, f"failed to stat {IP_BLOCK_LOG}: stderr={size_before.stderr!r}"

        append = subprocess.run(
            vm.ssh_argv("tee", "-a", IP_BLOCK_LOG),
            input=new_row + legacy_row,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        original_size = size_before.stdout.strip()
        assert append.returncode == 0, f"failed to append fixture rows to {IP_BLOCK_LOG}: stderr={append.stderr!r}"

        yield
    finally:
        if original_size is not None:
            restore = vm.ssh(f"truncate -s {original_size} {IP_BLOCK_LOG}", timeout=15)
            assert restore.returncode == 0, f"failed to restore {IP_BLOCK_LOG} size: stderr={restore.stderr!r}"
            size_after = vm.ssh("stat", "-f", "%z", IP_BLOCK_LOG, timeout=15)
            assert size_after.returncode == 0 and size_after.stdout.strip() == original_size, (
                f"{IP_BLOCK_LOG} restore did not take (before={original_size!r}, after={size_after.stdout.strip()!r}) "
                "-- synthetic rows leaked to sibling tests"
            )
        if feeds_seeded:
            removed = vm.ssh(f"rm -f {deny_feed_new} {deny_feed_legacy}", timeout=15)
            assert removed.returncode == 0, (
                f"failed to remove seeded deny-folder feed files: stderr={removed.stderr!r} "
                "-- feed state leaked to sibling smoke modules"
            )


def test_alerts_asn_csv_new_schema_renders_legacy_schema_silently_absent(
    smoke_vm: SmokeVM,
    webui: WebUI,
    _asn_reporting_enabled: None,
    _seeded_ip_block_log: None,
) -> None:
    """New-schema ASN row renders visible ASN + tooltip; legacy row renders nothing.

    Scenario:
      Given ip_block.log carries one new (23-field) row with a found ASN whose
            domain/name each carry a comma (real CSV round-trip, not a bespoke
            escape), and one pre-upgrade legacy (21-field, single pipe-blob
            ASN column) row.
      When  the Alerts page (default view, which renders ip_block.log's Block
            table) is GET-ted.
      Then  the Tier-A render oracle passes (200, no PHP diagnostic in the
            body, page marker present) AND the server's own php_error.log
            gained no gated-class diagnostic (oracle condition (d) -- a logged-but-not-echoed
            warning would still fail this)
        AND the new-schema row's ASN renders visibly, with a tooltip built
            from its domain + name
        AND the legacy row renders NOTHING AT ALL -- its host never appears
            anywhere in the page body.
    """
    guard = PhpErrorLogGuard(smoke_vm)
    guard.snapshot()

    resp = webui.get(ALERTS_PAGE)
    result = evaluate_render(ALERTS_PAGE, resp.status_code, resp.text, ("Alert Settings",))
    assert result.ok, f"Tier-A render oracle failed for the Alerts page: {result.detail}"
    assert not looks_like_login_page(resp.text), "alerts page GET returned the login form (session lost)"

    body = resp.text

    # THEN: the new-schema row's ASN renders visibly, inside ITS OWN span --
    # scoped to the ASN cell so a stray occurrence of the same strings
    # elsewhere on the page cannot satisfy these assertions.
    asn_span = re.search(r'<span title="([^"]*)">' + re.escape(NEW_SCHEMA_ASN) + r"</span>", body)
    assert asn_span, f"no ASN span rendering {NEW_SCHEMA_ASN!r} found in the page"
    # The tooltip is built from the domain + name columns (the comma itself is
    # not an HTML metacharacter, so it appears verbatim in the title attribute
    # even though it required CSV quoting on the wire).
    asn_title = asn_span.group(1)
    assert NEW_SCHEMA_DOMAIN in asn_title, (
        f"ASN tooltip domain {NEW_SCHEMA_DOMAIN!r} missing from the ASN span title {asn_title!r}"
    )
    assert "Example, Org" in asn_title, (
        f"ASN tooltip name (with its comma intact) missing from the ASN span title {asn_title!r}"
    )
    assert NEW_SCHEMA_HOST in body, "the new-schema row's host itself did not render at all"

    # THEN: the legacy row is COMPLETELY absent -- not a garbled/partial
    # render, no trace of its host anywhere in the page.
    assert LEGACY_SCHEMA_HOST not in body, (
        f"the legacy-schema row's host {LEGACY_SCHEMA_HOST!r} rendered -- pre-upgrade rows must be "
        "skipped silently per the owner's no-back-compat amendment (issue #1369)"
    )
    assert "AS99999" not in body, "the legacy row's raw ASN number must never render"
    assert "legacy.example" not in body, "the legacy row's raw domain must never render"

    # THEN (oracle condition (d)): no PHP diagnostic was logged either, even
    # if display_errors would have kept it out of the body.
    guard.assert_no_growth()
