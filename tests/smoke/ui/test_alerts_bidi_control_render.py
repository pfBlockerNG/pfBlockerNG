"""Bidi controls in a log-derived value must not reach the rendered Alerts page.

``pfb_hsc()`` encodes HTML metacharacters; Unicode bidirectional controls are not
metacharacters, so before issue #2041 they survived encoding and reversed the display
order of everything after them — a blocked domain could render as something other than
the bytes ``dnsbl.log`` actually carries.

Tier-A companion to ``tests/php/AlertsBidiControlStripTest.php``: the unit tests pin
``pfb_hsc()`` itself, this pins that no path between the log line and the rendered cell
re-introduces the control.

The DNSBL stats view is the one that renders this row (``?view=dnsbl_stat``); the
default Alerts view does not, so asserting against the default page would pass
vacuously.
"""

from __future__ import annotations

import subprocess
from typing import TYPE_CHECKING, Iterator

import pytest

from .. import helpers
from .render_oracle import PhpErrorLogGuard, evaluate_render

if TYPE_CHECKING:
    from ..helpers import SmokeVM
    from .webui import WebUI

pytestmark = pytest.mark.ui_render

DNSBL_LOG = "/var/log/pfblockerng/dnsbl.log"
STATS_PAGE = "/pfblockerng/pfblockerng_alerts.php?view=dnsbl_stat"
CFG_DNSBL_ENABLE = "installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl"

# U+202E RIGHT-TO-LEFT OVERRIDE between an innocuous prefix and a reversed-looking
# suffix -- the canonical filename/domain spoof. Inert: never resolved, never fetched.
RLO = "‮"
SPOOF_DOM = f"evil-rv2041{RLO}gnp.exe"
FIXED_TS = "2030-01-15 09:00:05"

# dnsbl.log CSV shape: l_type,ts,domain,src_ip,agent,block_mode,group,final_domain,feed,dup,qtype
_LOG_LINE = f"DNSBL-python,{FIXED_TS},{SPOOF_DOM},127.0.0.1,Python,DNSBL_TLD,RV2041Group,{SPOOF_DOM},RV2041Feed,+,A\n"


@pytest.fixture
def _seeded_bidi_row(smoke_vm: SmokeVM) -> Iterator[None]:
    """Seed the bidi-carrying dnsbl.log row; restore the log and the DNSBL toggle."""
    vm = smoke_vm

    prior_dnsbl = helpers.config_get(vm, CFG_DNSBL_ENABLE)
    helpers.ensure_dnsbl_vip(vm)
    helpers.set_dnsbl_enabled(vm, True)

    log_dir = DNSBL_LOG.rsplit("/", 1)[0]
    ensure = vm.ssh(f"mkdir -p {log_dir} && touch {DNSBL_LOG}", timeout=15)
    assert ensure.returncode == 0, f"failed to ensure {DNSBL_LOG} exists: {ensure.stderr!r}"
    size_before = vm.ssh("stat", "-f", "%z", DNSBL_LOG, timeout=15)
    assert size_before.returncode == 0, f"failed to stat {DNSBL_LOG}: stderr={size_before.stderr!r}"
    original_size = size_before.stdout.strip()

    append = subprocess.run(
        vm.ssh_argv("tee", "-a", DNSBL_LOG),
        input=_LOG_LINE,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert append.returncode == 0, f"failed to append the fixture row to {DNSBL_LOG}: stderr={append.stderr!r}"

    yield

    restore_log = vm.ssh(f"truncate -s {original_size} {DNSBL_LOG}", timeout=15)
    assert restore_log.returncode == 0, f"failed to restore {DNSBL_LOG} size: stderr={restore_log.stderr!r}"
    size_after = vm.ssh("stat", "-f", "%z", DNSBL_LOG, timeout=15)
    assert size_after.returncode == 0 and size_after.stdout.strip() == original_size, (
        f"{DNSBL_LOG} restore did not take (before={original_size!r}, after={size_after.stdout.strip()!r})"
    )

    helpers.config_set(vm, CFG_DNSBL_ENABLE, prior_dnsbl)
    assert helpers.config_get(vm, CFG_DNSBL_ENABLE) == prior_dnsbl, (
        f"pfb_dnsbl toggle restore did not take (wanted {prior_dnsbl!r}) -- leaked to sibling tests"
    )


def test_bidi_override_does_not_reach_the_rendered_cell(
    smoke_vm: SmokeVM, webui: WebUI, _seeded_bidi_row: None
) -> None:
    """The row renders, and carries no bidi control that could reverse it (issue #2041)."""
    guard = PhpErrorLogGuard(smoke_vm)
    guard.snapshot()

    resp = webui.get(STATS_PAGE)
    result = evaluate_render(STATS_PAGE, resp.status_code, resp.text, ("Alert Settings",))
    assert result.ok, f"Tier-A render oracle failed for the DNSBL stats page: {result.detail}"

    body = resp.text
    # Fixture sanity first: a page that never rendered the row would pass the bidi
    # assertion vacuously.
    assert "evil-rv2041" in body, "the seeded dnsbl.log row did not render at all -- fixture broken, not a #2041 signal"
    assert RLO not in body, (
        "U+202E reached the rendered Alerts markup -- a log-derived value can be displayed "
        "reversed relative to the bytes actually logged (issue #2041)"
    )
    # The whole set pfb_hsc() strips, so a partial revert is caught too.
    for ch in ("؜", "‎", "‏", "‪", "‫", "‬", "‭", "⁦", "⁧", "⁨", "⁩"):
        assert ch not in body, f"bidi control U+{ord(ch):04X} reached the rendered markup (issue #2041)"

    guard.assert_no_growth()
