"""A DNSBL case's mode must drive the global response mechanism (issue #3305).

Since #3291/#3332 (c35bfa8e/390dbeba), built-in DNSBL blocks (regex, IDN, TLD
Allow, TLD Blacklist) inherit ``dnsbl/global_log`` instead of hardcoding VIP.
``helpers._dnsbl_mode_settings`` previously ignored its ``mode`` argument and
always wrote Null Blocking (``global_log='disabled_log'``) -- so every VIP/NXDOMAIN
matrix case's built-in hits answered 0.0.0.0 regardless of the case's own mode.
This pin is pure (no VM): it targets the snippet-builder mapping directly.
"""

from __future__ import annotations

import pytest

from tests.smoke import helpers


@pytest.mark.parametrize(
    ("mode", "expected_global_log"),
    [
        (helpers.DnsblMode.VIP, "enabled"),
        (helpers.DnsblMode.NXDOMAIN, "nxdomain_log"),
        (helpers.DnsblMode.NULL, "disabled_log"),
    ],
)
def test_dnsbl_mode_settings_drives_global_log_from_case_mode(
    mode: helpers.DnsblMode, expected_global_log: str
) -> None:
    settings = helpers._dnsbl_mode_settings(mode)
    assert settings["global_log"] == expected_global_log
    assert settings["global_log_mode"] == "default"
