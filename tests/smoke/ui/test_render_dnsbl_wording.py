"""Issue #3850: the web UI no longer presents Python as how DNSBL works.

Since #3838 the DNSBL decider runs inside pfB-DNS. The Alerts page titles its DNSBL panel
``DNSBL`` and the setup wizard no longer links a tutorial for the retired Python mode.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Iterator

import pytest

from .. import helpers
from .render_oracle import PhpErrorLogGuard, evaluate_render

if TYPE_CHECKING:
    from ..helpers import SmokeVM
    from .webui import WebUI

pytestmark = pytest.mark.ui_render

ALERTS_PAGE = "/pfblockerng/pfblockerng_alerts.php"
WIZARD_WELCOME_STEP = "/wizard.php?xml=pfblockerng_wizard.xml&stepid=0"
CFG_DNSBL_ENABLE = "installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl"


@pytest.fixture
def _dnsbl_on(smoke_vm: SmokeVM) -> Iterator[None]:
    """DNSBL on, so the Alerts page renders its DNSBL panel; the toggle is restored afterwards."""
    prior = helpers.config_get(smoke_vm, CFG_DNSBL_ENABLE)
    helpers.ensure_dnsbl_vip(smoke_vm)
    helpers.set_dnsbl_enabled(smoke_vm, True)
    yield
    helpers.config_set(smoke_vm, CFG_DNSBL_ENABLE, prior)
    assert helpers.config_get(smoke_vm, CFG_DNSBL_ENABLE) == prior, (
        f"pfb_dnsbl toggle restore did not take (wanted {prior!r}) -- leaked to sibling tests"
    )


def test_alerts_titles_the_dnsbl_panel_dnsbl(smoke_vm: SmokeVM, webui: WebUI, _dnsbl_on: None) -> None:
    """With DNSBL on, the Alerts page's DNSBL panel is titled ``DNSBL``, never ``DNSBL Python``."""
    guard = PhpErrorLogGuard(smoke_vm)
    guard.snapshot()

    resp = webui.get(ALERTS_PAGE)
    result = evaluate_render(ALERTS_PAGE, resp.status_code, resp.text, ("Alert Settings",))
    assert result.ok, f"Tier-A render oracle failed for the Alerts page: {result.detail}"
    body = resp.text
    # The panel's own heading, so a page that rendered no DNSBL panel cannot pass.
    assert "DNSBL<small>-&nbsp;Last" in body, "the Alerts page rendered no panel titled DNSBL"
    assert "DNSBL Python" not in body, "the Alerts page still titles its DNSBL panel 'DNSBL Python'"

    guard.assert_no_growth()


def test_wizard_welcome_step_links_no_python_mode_tutorial(smoke_vm: SmokeVM, webui: WebUI) -> None:
    """The wizard's resource links still render, without the retired Python-mode tutorial."""
    guard = PhpErrorLogGuard(smoke_vm)
    guard.snapshot()

    resp = webui.get(WIZARD_WELCOME_STEP)
    result = evaluate_render(WIZARD_WELCOME_STEP, resp.status_code, resp.text, ("pfBlockerNG Setup",))
    assert result.ok, f"wizard welcome step render oracle failed: {result.detail}"
    body = resp.text
    assert "Tom Lawrence Youtube channel" in body, "the wizard's resource links did not render"
    assert "Python mode" not in body, "the wizard still links a tutorial for the retired Python mode"

    guard.assert_no_growth()
