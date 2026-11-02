"""Tier-A rendered help for the pfB-DNS shared/local split (issue #3649)."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from .render_oracle import PhpErrorLogGuard, evaluate_render

if TYPE_CHECKING:
    from ..conftest import SmokeVM
    from .webui import WebUI

pytestmark = pytest.mark.ui_render


@pytest.mark.parametrize(
    ("path", "marker", "phrases"),
    [
        (
            "/pfblockerng/pfblockerng_sync.php",
            "XMLRPC Sync Settings",
            (
                "<b>All settings (legacy)</b>",
                "pfB-DNS transport toggles, ports, trusted DoH front ends and DDR settings",
                "pfB-DNS enable toggle, Resolver snapshot, listen interfaces/addresses (including VIPs) "
                "and certificate stay per node",
                "Hook script files and Sync settings are not sent",
            ),
        ),
    ],
)
def test_rendered_help_explains_shared_transport_settings_and_local_activation(
    smoke_vm: SmokeVM, webui: WebUI, path: str, marker: str, phrases: tuple[str, ...]
) -> None:
    guard = PhpErrorLogGuard(smoke_vm)
    guard.snapshot()
    response = webui.get(path)
    result = evaluate_render(path, response.status_code, response.text, (marker,))
    assert result.ok, f"Tier-A render failed for {path}: {result.detail}"
    for phrase in phrases:
        assert phrase in response.text, f"expected {phrase!r} in rendered {path}, found no matching help"
    guard.assert_no_growth()
