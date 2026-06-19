<?php

/*
 * ADR-29 RequireConfigGateway sniff fixture (NOT production code).
 *
 * Contains raw config_*_path calls targeting REGISTERED
 * installedpackages/pfblockerng* keys — the sniff MUST flag each one.
 *
 * Flagged: config_get_path on a gen-section key (line 19),
 *          config_set_path on a DNSBL-section key (line 22),
 *          config_del_path on a SafeSearch key (line 25).
 *
 * Pinned by RequireConfigGatewaySniffTest::testFlagsRawRegisteredKeyAccess.
 */

function pfb_gateway_violation_example()
{
	// Direct read of a registered key — must be flagged.
	$val = config_get_path('installedpackages/pfblockerng/config/0/pfb_keep');

	// Direct write of a registered DNSBL-settings key — must be flagged.
	config_set_path('installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl', 'on');

	// Direct delete of a registered SafeSearch key — must be flagged.
	config_del_path('installedpackages/pfblockerngsafesearch/safesearch_enable');

	return $val;
}
