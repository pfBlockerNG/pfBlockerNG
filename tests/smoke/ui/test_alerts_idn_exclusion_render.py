"""Tier-A ``ui_render`` coverage for issue #1782: an IDN TLD-exclusion row is
RECOGNISED by the Alerts page for the punycode domain the dnsbl.log carries.

``pfblockerng_alerts.php`` decodes its ``tld_wildcard_exclusion`` customlist at render
time to key the "already excluded" lookup map. Before the #1782 fix that
decode ran WITHOUT ``$idn=TRUE``, so a Unicode row (stored raw-Unicode by the
DNSBL page since PR #1781/#1731) keyed the map by its Unicode label -- while
the ``dnsbl.log`` evaluated-domain field it is compared against always carries
the punycode wire form. The row never matched: instead of the
``delete_exclusion`` control (the "this block is YOUR exclusion" affordance),
the page offered the duplicate-creating ``add`` control.

Scenario (self-encapsulated: config node + log both restored in teardown):
  Given a Unicode domain seeded raw in the ``tld_wildcard_exclusion`` config node
  And   a dnsbl.log row TLD-blocking its punycode form (``DNSBL_TLD`` mode)
  When  GET the Alerts page
  Then  the Tier-A render oracle passes
  And   the row renders the ``delete_exclusion|<punycode>`` control
  And   never the duplicate-add ``DNSBLWT|add|<punycode>`` control.

The domain is a fixed inert literal (log-content rendering only -- no DNS
resolution ever happens, same carve-out ``test_alerts_stat_render.py`` uses);
its punycode form is computed, not hand-transcribed.
"""

from __future__ import annotations

import base64
import subprocess
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .render_oracle import PhpErrorLogGuard, evaluate_render

if TYPE_CHECKING:
    from collections.abc import Iterator

    from ..conftest import SmokeVM
    from .webui import WebUI

pytestmark = pytest.mark.ui_render

DNSBL_LOG = "/var/log/pfblockerng/dnsbl.log"
ALERTS_PAGE = "/pfblockerng/pfblockerng_alerts.php"
CFG_TLD_WILDCARD_EXCLUSION = "installedpackages/pfblockerngdnsblsettings/config/0/tld_wildcard_exclusion"
CFG_DNSBL_ENABLE = "installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl"

# Fixed synthetic IDN pair -- clearly inert, never resolved. The punycode form
# is derived by the stdlib codec so the fixture can't carry a transcription typo.
UNICODE_DOM = "bücher-rv1782.de"
PUNY_DOM = UNICODE_DOM.encode("idna").decode("ascii")
FIXED_TS = "2030-01-15 09:00:05"

# dnsbl.log CSV shape (see test_alerts_render_verify._dnsbl_line):
# l_type,ts,domain,src_ip,agent,block_mode,group,final_domain,feed,dup,qtype
_LOG_LINE = f"DNSBL-python,{FIXED_TS},sub.{PUNY_DOM},127.0.0.1,Python,DNSBL_TLD,RV1782Group,{PUNY_DOM},RV1782Feed,+,A\n"


@pytest.fixture
def _seeded_idn_exclusion(smoke_vm: SmokeVM) -> Iterator[None]:
    """Seed the Unicode tld_wildcard_exclusion row + the punycode dnsbl.log line; restore both.

    Self-encapsulated (this module is ``ui_render``-only, so the shared
    ``_ui_pfb_isolation`` restore fixture does not run for it): the config node
    goes back to its exact prior value and the log truncates back to its exact
    pre-test byte size, failing loudly if either restore didn't take.
    """
    vm = smoke_vm

    # The Alerts page renders its DNSBL table only when the DNSBL toggle is On
    # (`case 'alert'` gates on pfb_cfg_toggle_read($pfb['dnsbl'])), and the
    # toggle needs a configured sinkhole VIP first -- same sequence as
    # test_alerts_render_verify.py's harness. Restored in teardown.
    prior_dnsbl = helpers.config_get(vm, CFG_DNSBL_ENABLE)
    helpers.ensure_dnsbl_vip(vm)
    helpers.set_dnsbl_enabled(vm, True)

    prior_b64 = helpers.config_get(vm, CFG_TLD_WILDCARD_EXCLUSION)
    seeded_b64 = base64.b64encode(UNICODE_DOM.encode("utf-8")).decode("ascii")
    write = helpers.php_eval(
        vm,
        f"config_set_path('{CFG_TLD_WILDCARD_EXCLUSION}', '{seeded_b64}');\n"
        "write_config('pfBlockerNG smoke #1782: seed IDN tld_wildcard_exclusion');\n"
        "echo 'SEED-OK';\n",
    )
    assert write.returncode == 0 and "SEED-OK" in write.stdout, (
        f"failed to seed the tld_wildcard_exclusion config node: stdout={write.stdout!r} stderr={write.stderr!r}"
    )

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

    restore_cfg = helpers.php_eval(
        vm,
        f"config_set_path('{CFG_TLD_WILDCARD_EXCLUSION}', '{prior_b64}');\n"
        "write_config('pfBlockerNG smoke #1782: restore tld_wildcard_exclusion');\n"
        "echo 'RESTORE-OK';\n",
    )
    assert restore_cfg.returncode == 0 and "RESTORE-OK" in restore_cfg.stdout, (
        f"failed to restore the tld_wildcard_exclusion config node: "
        f"stdout={restore_cfg.stdout!r} stderr={restore_cfg.stderr!r}"
    )
    assert helpers.config_get(vm, CFG_TLD_WILDCARD_EXCLUSION) == prior_b64, (
        "tld_wildcard_exclusion config restore did not take -- the seeded IDN row leaked to sibling tests"
    )

    # Restore VERBATIM, not through the boolean helper: the box may hold the
    # legacy 'off' token, which set_dnsbl_enabled would canonicalise to raw ''
    # and fail the strict round-trip assert below (issue #1947).
    helpers.config_set(vm, CFG_DNSBL_ENABLE, prior_dnsbl)
    assert helpers.config_get(vm, CFG_DNSBL_ENABLE) == prior_dnsbl, (
        f"pfb_dnsbl toggle restore did not take (wanted {prior_dnsbl!r}) -- leaked to sibling tests"
    )


def test_idn_tld_exclusion_row_renders_delete_not_duplicate_add(
    smoke_vm: SmokeVM, webui: WebUI, _seeded_idn_exclusion: None
) -> None:
    """The punycode-blocked IDN exclusion renders ``delete_exclusion``, not a dup-``add``."""
    guard = PhpErrorLogGuard(smoke_vm)
    guard.snapshot()

    resp = webui.get(ALERTS_PAGE)
    result = evaluate_render(ALERTS_PAGE, resp.status_code, resp.text, ("Alert Settings",))
    assert result.ok, f"Tier-A render oracle failed for the Alerts page: {result.detail}"

    body = resp.text
    assert f"sub.{PUNY_DOM}" in body, (
        f"the seeded DNSBL_TLD log row (sub.{PUNY_DOM}) did not render at all -- fixture broken, not a #1782 signal"
    )
    assert f"delete_exclusion|{PUNY_DOM}" in body, (
        "the IDN TLD-exclusion row was NOT recognised for its punycode evaluated domain "
        "(no delete_exclusion control) -- the Alerts customlist decode is missing $idn=TRUE (issue #1782)"
    )
    assert f"DNSBLWT|add|{PUNY_DOM}" not in body, (
        "the Alerts page offered the duplicate-creating add-exclusion control for a domain "
        "that already HAS an exclusion row (issue #1782)"
    )

    guard.assert_no_growth()
