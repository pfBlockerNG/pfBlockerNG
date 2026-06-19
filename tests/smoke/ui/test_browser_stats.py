"""Tier-B browser screenshots of the Reports stats pie charts (issue #387).

The fix in ``pfblockerng_alerts.php`` (issue #387) reworks the Reports stats
panels to use a flex layout (``.pfb-stats-row`` / ``.pfb-stats-col``) and a
``pfbPieFluid(id)`` JS helper that sets a ``viewBox`` on each d3pie ``<svg>``
and strips its fixed ``width``/``height`` attributes, so the pie scales
responsively with its column and stacks cleanly under ``@media print``.

These tests verify the fix is active on the live page by:

1. Seeding realistic CSV lines into the relevant log so the PHP stats engine
   has data to render a pie (a pie only renders when the log has entries).
2. Navigating the browser to the stats view.
3. Asserting that ``pfbPieFluid`` ran: the ``<svg>`` inside
   ``#pieChart_<stat_type>`` has a non-empty ``viewBox`` attribute and
   NO ``width``/``height`` attribute — the exact DOM transformation the fix
   applies.
4. Capturing three screenshots per view: default viewport (screen), a narrow
   viewport (columns wrap; pie must not clip), and print-media emulation
   (columns stack per ``@media print``).

Cleanup: every test restores the log to its pre-seed size in ``finally``.
Marker: ``ui_browser`` — schedule/dispatch only, never a PR gate.
"""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .conftest import mask_page_identity

sync_api = pytest.importorskip(
    "playwright.sync_api",
    reason="playwright not installed (Tier-B browser dep)",
)
expect = sync_api.expect

if TYPE_CHECKING:
    from playwright.sync_api import Page

    from .webui import WebUI

pytestmark = pytest.mark.ui_browser

# ── page paths ────────────────────────────────────────────────────────────────
ALERTS_IP_STAT = "/pfblockerng/pfblockerng_alerts.php?view=ip_block_stat"
ALERTS_DNSBL_STAT = "/pfblockerng/pfblockerng_alerts.php?view=dnsbl_stat"

# ── log paths (on the VM) ─────────────────────────────────────────────────────
IP_BLOCK_LOG = "/var/log/pfblockerng/ip_block.log"
DNSBL_LOG = "/var/log/pfblockerng/dnsbl.log"

# ── stat_type ids used in the pie container selector ─────────────────────────
# ip_block_stat: first stat with a pie that will carry our seeded data.
# stat_info column 14 = geoip — every seeded line has a GeoIP code, so
# pieChart_ipgeoip is the safest first-data pie for this view.
IP_PIE_STAT_TYPE = "ipgeoip"

# dnsbl_stat: column 4 = source IP (dnsblip); every seeded line has an IP,
# so pieChart_dnsblip reliably gets data from our seed lines.
DNSBL_PIE_STAT_TYPE = "dnsblip"

# ── JS timeouts ───────────────────────────────────────────────────────────────
# pfbPieFluid fires synchronously via <script> after d3pie; generous ceiling
# for the page render + JS execution, not a functional wait knob.
JS_TIMEOUT_MS = 30_000

# ── narrow viewport for responsive check ─────────────────────────────────────
NARROW_WIDTH = 800
NARROW_HEIGHT = 1000


# ── helpers mirroring test_browser.py ────────────────────────────────────────


def _open(page: Page, webui: WebUI, path: str) -> None:
    """Navigate the authenticated browser page to ``path`` and settle the DOM.

    Asserts the load did NOT bounce to the login form — proving the injected
    session cookie authenticated the browser. Waits on ``networkidle`` so
    inline ``<script>`` blocks (including ``pfbPieFluid``) have run.
    """
    page.goto(webui.url(path), wait_until="domcontentloaded", timeout=JS_TIMEOUT_MS * 3)
    page.wait_for_load_state("networkidle", timeout=JS_TIMEOUT_MS * 3)
    assert page.locator("#usernamefld").count() == 0, f"GET {path} showed the login form — cookie not authenticated"


def _shot(page: Page, screenshot_dir: Path, name: str) -> None:
    """Full-page screenshot artifact ``<screenshot_dir>/<name>.png``.

    Value-redacts the Plus VM identity from the DOM first (ADR-24 no-op on CE).
    """
    mask_page_identity(page)
    page.screenshot(path=str(screenshot_dir / f"{name}.png"), full_page=True)


def _log_size(vm: helpers.SmokeVM, log_path: str, timeout: int = 15) -> str | None:
    """Return the byte size of ``log_path`` on the VM, or ``None`` if it is absent.

    A fresh box may not have created ``ip_block.log`` yet (no IP block has fired),
    so absence is normal — the caller seeds the file and DELETES it on cleanup,
    rather than truncating back to a pre-existing size.
    """
    result = vm.ssh("stat", "-f", "%z", log_path, timeout=timeout)
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def _append(vm: helpers.SmokeVM, log_path: str, lines: str, timeout: int = 15) -> None:
    """Append ``lines`` to ``log_path`` on the VM via SSH tee -a (creating it if absent)."""
    mk = vm.ssh("/bin/mkdir", "-p", os.path.dirname(log_path), timeout=timeout)
    assert mk.returncode == 0, f"mkdir for {log_path!r} failed: {mk.stderr!r}"
    result = subprocess.run(
        vm.ssh_argv("tee", "-a", log_path),
        input=lines,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    assert result.returncode == 0, f"tee -a {log_path!r} failed: rc={result.returncode}, stderr={result.stderr!r}"


def _restore(vm: helpers.SmokeVM, log_path: str, original_size: str | None, timeout: int = 15) -> None:
    """Restore ``log_path`` to its pre-seed state on the VM.

    Truncate back to ``original_size`` bytes when the file pre-existed; remove it
    entirely when it did not (``original_size is None`` — we created it by seeding).
    """
    if original_size is None:
        result = subprocess.run(
            vm.ssh_argv("/bin/rm", "-f", log_path),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        assert result.returncode == 0, f"rm {log_path!r} failed: rc={result.returncode}, stderr={result.stderr!r}"
        return

    result = subprocess.run(
        vm.ssh_argv("/usr/bin/truncate", "-s", original_size, log_path),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    assert result.returncode == 0, (
        f"truncate {log_path!r} to size={original_size!r} failed: rc={result.returncode}, stderr={result.stderr!r}"
    )


def _assert_pie_fluid(page: Page, stat_type: str) -> None:
    """Assert that ``pfbPieFluid`` ran on ``#pieChart_<stat_type> svg``.

    Verifies the issue-#387 fix is active:
    - the ``<svg>`` has a non-empty ``viewBox`` attribute (set by pfbPieFluid)
    - the ``<svg>`` has NO ``width`` or ``height`` attribute (removed by pfbPieFluid)

    Fails with a clear message if the pie SVG is absent (log seed yielded no data).
    """
    container = f"#pieChart_{stat_type}"
    svg_sel = f"{container} svg"

    # Wait for the container to exist first — confirms the stat panel rendered.
    expect(page.locator(container)).to_be_attached(timeout=JS_TIMEOUT_MS)

    svg = page.locator(svg_sel)
    svg_count = svg.count()
    assert svg_count > 0, (
        f"No <svg> found inside {container!r} — the pie did not render. "
        f"Check that the seed lines produced data for stat_type={stat_type!r}."
    )

    # viewBox must be non-empty (pfbPieFluid sets it from the SVG's natural size).
    view_box = svg.first.get_attribute("viewBox")
    assert view_box and view_box.strip(), (
        f"{container} svg has no viewBox attribute — pfbPieFluid did not run "
        f"(issue #387 fix is absent or the SVG rendered with zero size)."
    )

    # width and height must be absent (pfbPieFluid removes them so CSS scales the SVG).
    width_attr = svg.first.get_attribute("width")
    height_attr = svg.first.get_attribute("height")
    assert width_attr is None, (
        f"{container} svg still has width={width_attr!r} — pfbPieFluid did not "
        f"remove the fixed width attribute (issue #387 fix not applied)."
    )
    assert height_attr is None, (
        f"{container} svg still has height={height_attr!r} — pfbPieFluid did not "
        f"remove the fixed height attribute (issue #387 fix not applied)."
    )


# ── test: IP Block Stats ──────────────────────────────────────────────────────


def test_stats_ip_block_pie_fluid_and_screenshots(
    browser_page: Page,
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    screenshot_dir: Path,
) -> None:
    """The IP Block Stats pie is viewBox-scaled (pfbPieFluid ran); three screenshots.

    Scenario: issue-#387 responsive/print fix is active on ip_block_stat.
      Background: pfBlockerNG deployed; webConfigurator authenticated;
        ip_block.log seeded with 8 synthetic IPv4 block entries across 3 GeoIP
        codes, 3 alias names, and 3 feed names.

    Given ip_block.log has diverse synthetic entries,
    When the browser navigates to ?view=ip_block_stat,
    Then pieChart_ipgeoip's <svg> has a viewBox and no width/height attributes
      (pfbPieFluid ran — the fix is present);
    And three screenshots capture the default, narrow, and print layouts.

    Cleanup: ip_block.log is restored to its pre-seed size in finally.

    ip_block.log CSV format (IPv4 line — from pfb_daemon_filterlog writer):
      field 1:  timestamp (e.g. "Jun  8 12:00:00")
      field 2:  rule number
      field 3:  action (numeric ID)
      field 4:  interface name (e.g. "em0")
      field 5:  action type (e.g. "block")
      field 6:  IP version (4)
      field 7:  protocol ID
      field 8:  protocol (e.g. "TCP")
      field 9:  SRC IP
      field 10: DST IP
      field 11: SRC port
      field 12: DST port
      field 13: direction ("in"/"out")
      field 14: GeoIP code → drives pieChart_ipgeoip (stat col 14)
      field 15: alias name  → drives pieChart_ipaliasname (stat col 15)
      field 16: IP evaluated
      field 17: feed name   → drives pieChart_ipfeed (stat col 17)
      field 18: resolved hostname
      field 19: client hostname
      field 20: ASN
      field 21: dup_entry ("+")
    """
    vm = smoke_vm
    ts = time.strftime("%b %e %H:%M:%S")  # "Jun  8 12:00:00" style

    # 8 entries: 3 GeoIP codes (US×3, DE×3, JP×2), 3 alias names, 3 feed names.
    # SRC IPs from RFC-5737 (192.0.2.x / 198.51.100.x); DST is also RFC-5737.
    # Rule/proto/port values are plausible but arbitrary — only GeoIP/alias/feed
    # columns are consumed by the stat engine for the pies we assert.
    # Format: ts,rule,real_iface,friendly_iface,action,ipv,proto_id,proto,
    #          src_ip,dst_ip,src_port,dst_port,dir,geoip,alias,
    #          ip_eval,feed,rhost,chost,asn,dup
    _u = "Unknown"
    rows = [
        f"{ts},100,em0,WAN,block,4,6,TCP"
        f",192.0.2.1,198.51.100.1,54321,80,in,US,pfB_Deny_v4"
        f",192.0.2.1,EasyList,{_u},{_u},{_u},+",
        f"{ts},100,em0,WAN,block,4,6,TCP"
        f",192.0.2.2,198.51.100.1,54322,80,in,US,pfB_Deny_v4"
        f",192.0.2.2,EasyList,{_u},{_u},{_u},+",
        f"{ts},100,em0,WAN,block,4,6,TCP"
        f",192.0.2.3,198.51.100.1,54323,80,in,US,pfB_StevenBlack_v4"
        f",192.0.2.3,StevenBlack,{_u},{_u},{_u},+",
        f"{ts},101,em0,WAN,block,4,17,UDP"
        f",192.0.2.4,198.51.100.2,54324,53,out,DE,pfB_Deny_v4"
        f",192.0.2.4,EasyList,{_u},{_u},{_u},+",
        f"{ts},101,em0,WAN,block,4,17,UDP"
        f",192.0.2.5,198.51.100.2,54325,53,out,DE,pfB_StevenBlack_v4"
        f",192.0.2.5,StevenBlack,{_u},{_u},{_u},+",
        f"{ts},101,em0,WAN,block,4,17,UDP"
        f",192.0.2.6,198.51.100.2,54326,53,out,DE,pfB_DNSBLIP_v4"
        f",192.0.2.6,DNSBL_IP,{_u},{_u},{_u},+",
        f"{ts},102,em0,WAN,block,4,6,TCP"
        f",198.51.100.10,192.0.2.10,54327,443,in,JP,pfB_StevenBlack_v4"
        f",198.51.100.10,StevenBlack,{_u},{_u},{_u},+",
        f"{ts},102,em0,WAN,block,4,6,TCP"
        f",198.51.100.11,192.0.2.11,54328,443,in,JP,pfB_DNSBLIP_v4"
        f",198.51.100.11,DNSBL_IP,{_u},{_u},{_u},+",
    ]
    seed_lines = "\n".join(rows) + "\n"

    original_size = _log_size(vm, IP_BLOCK_LOG)

    try:
        # GIVEN: seed the ip_block.log with synthetic entries.
        _append(vm, IP_BLOCK_LOG, seed_lines)

        page = browser_page

        # ── default viewport ──────────────────────────────────────────────────
        _open(page, webui, ALERTS_IP_STAT)

        # THEN: pfbPieFluid ran — viewBox set, width/height removed.
        _assert_pie_fluid(page, IP_PIE_STAT_TYPE)

        _shot(page, screenshot_dir, "stats_ip_block_screen")

        # ── narrow viewport — columns must wrap; pie must not clip ────────────
        page.set_viewport_size({"width": NARROW_WIDTH, "height": NARROW_HEIGHT})
        _open(page, webui, ALERTS_IP_STAT)
        _assert_pie_fluid(page, IP_PIE_STAT_TYPE)
        _shot(page, screenshot_dir, "stats_ip_block_narrow")

        # ── print emulation — columns stack per @media print ─────────────────
        page.emulate_media(media="print")
        _shot(page, screenshot_dir, "stats_ip_block_print")

        # restore viewport and media for any sibling test using this page object
        page.emulate_media(media=None)
        page.set_viewport_size({"width": 1280, "height": 720})

    finally:
        _restore(vm, IP_BLOCK_LOG, original_size)


# ── test: DNSBL Block Stats ───────────────────────────────────────────────────


def test_stats_dnsbl_pie_fluid_and_screenshots(
    browser_page: Page,
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    screenshot_dir: Path,
) -> None:
    """The DNSBL Block Stats pie is viewBox-scaled (pfbPieFluid ran); three screenshots.

    Scenario: issue-#387 responsive/print fix is active on dnsbl_stat.
      Background: pfBlockerNG deployed; webConfigurator authenticated;
        dnsbl.log seeded with 8 synthetic DNSBL-python block entries across
        3 source IPs (field 4), 3 DNSBL modes (field 6), and 3 feed names
        (field 9) — enough variety for multi-slice pies.

    Given dnsbl.log has diverse synthetic entries,
    When the browser navigates to ?view=dnsbl_stat,
    Then pieChart_dnsblip's <svg> has a viewBox and no width/height attributes
      (pfbPieFluid ran — the fix is present);
    And three screenshots capture the default, narrow, and print layouts.

    Cleanup: dnsbl.log is restored to its pre-seed size in finally.

    dnsbl.log CSV format (Python-mode entry — from _log_upstream_block / the
    DNSBL Python logger; 11 fields, 0-indexed):
      [0]  prefix:   "DNSBL-python"
      [1]  timestamp: e.g. "Jun 18 12:00:00"
      [2]  domain:   the blocked domain name
      [3]  src_ip:   client source IP (drives pieChart_dnsblip, stat col 4)
      [4]  type:     "Python" | "HSTS"
      [5]  mode:     "DNSBL" | "TLD" | "Upstream_Block" (drives dnsblmode, col 6)
      [6]  group:    feed group name
      [7]  eval:     evaluated domain / TLD
      [8]  feed:     feed name (drives pieChart_dnsblfeed, stat col 9)
      [9]  dup:      "+" (duplicate indicator; consumed by uniq-count pipeline)
      [10] qtype:    "A" | "AAAA"
    """
    vm = smoke_vm
    ts = time.strftime("%b %d %H:%M:%S")  # "Jun 18 12:00:00"

    # Use helpers.unique_domain() for domains (smoke-domain rule: no RFC-6761
    # TLDs; uuid-*.com avoids HSTS preload and Unbound local-zone shadowing).
    # Source IPs from RFC-5737 (192.0.2.x); all 8 lines differ in src_ip, mode,
    # and feed to give the pies multiple distinct slices.
    d1 = helpers.unique_domain("stats1")
    d2 = helpers.unique_domain("stats2")
    d3 = helpers.unique_domain("stats3")
    d4 = helpers.unique_domain("stats4")
    d5 = helpers.unique_domain("stats5")
    d6 = helpers.unique_domain("stats6")
    d7 = helpers.unique_domain("stats7")
    d8 = helpers.unique_domain("stats8")

    rows = [
        # prefix,ts,domain,src_ip,type,mode,group,eval,feed,dup,qtype
        f"DNSBL-python,{ts},{d1},192.0.2.1,Python,DNSBL,EasyList,{d1},EasyList,+,A",
        f"DNSBL-python,{ts},{d2},192.0.2.1,Python,DNSBL,EasyList,{d2},EasyList,+,A",
        f"DNSBL-python,{ts},{d3},192.0.2.2,Python,DNSBL,StevenBlack,{d3},StevenBlack,+,A",
        f"DNSBL-python,{ts},{d4},192.0.2.2,Python,TLD,StevenBlack,com,StevenBlack,+,A",
        f"DNSBL-python,{ts},{d5},192.0.2.3,Python,TLD,OISD,com,OISD,+,A",
        f"DNSBL-python,{ts},{d6},192.0.2.3,Python,DNSBL,OISD,{d6},OISD,+,AAAA",
        f"DNSBL-python,{ts},{d7},192.0.2.1,Python,DNSBL,EasyList,{d7},EasyList,+,AAAA",
        f"DNSBL-python,{ts},{d8},192.0.2.2,Python,TLD,StevenBlack,net,StevenBlack,+,A",
    ]
    seed_lines = "\n".join(rows) + "\n"

    original_size = _log_size(vm, DNSBL_LOG)

    try:
        # GIVEN: seed dnsbl.log with synthetic DNSBL-python block entries.
        _append(vm, DNSBL_LOG, seed_lines)

        page = browser_page

        # ── default viewport ──────────────────────────────────────────────────
        _open(page, webui, ALERTS_DNSBL_STAT)

        # THEN: pfbPieFluid ran — viewBox set, width/height removed.
        _assert_pie_fluid(page, DNSBL_PIE_STAT_TYPE)

        _shot(page, screenshot_dir, "stats_dnsbl_screen")

        # ── narrow viewport — columns must wrap; pie must not clip ────────────
        page.set_viewport_size({"width": NARROW_WIDTH, "height": NARROW_HEIGHT})
        _open(page, webui, ALERTS_DNSBL_STAT)
        _assert_pie_fluid(page, DNSBL_PIE_STAT_TYPE)
        _shot(page, screenshot_dir, "stats_dnsbl_narrow")

        # ── print emulation — columns stack per @media print ─────────────────
        page.emulate_media(media="print")
        _shot(page, screenshot_dir, "stats_dnsbl_print")

        # restore viewport and media for any sibling test using this page object
        page.emulate_media(media=None)
        page.set_viewport_size({"width": 1280, "height": 720})

    finally:
        _restore(vm, DNSBL_LOG, original_size)
