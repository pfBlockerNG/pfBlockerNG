<?php

/*
 * ADR-29 RequireConfigGateway sniff fixture (NOT production code).
 *
 * Contains config_*_path calls that the sniff MUST NOT flag:
 *
 *   a) Foreign / non-registered key access — sniff stays silent.
 *   b) Dynamic-path access (variable in the path string) — sniff stays silent.
 *   c) Section-level read (path is a section, not a registered scalar key) —
 *      sniff stays silent.
 *   d) pfSense-core section access (aliases/*, system/*, unbound/*) — silent.
 *
 * Pinned by RequireConfigGatewaySniffTest::testCompliantCasesAreClean.
 */

function pfb_gateway_compliant_foreign_key()
{
	// Foreign section — pfblockerngipsettings is NOT in the registry.
	$v4 = config_get_path('installedpackages/pfblockerngipsettings/config/0/v4suppression');

	// Foreign dynamic per-row key — not in the registered path set.
	$row = 0;
	$custom = config_get_path("installedpackages/pfblockerngdnsbl/config/{$row}/custom");

	// pfSense core section — completely out of gateway scope.
	$aliases = config_get_path('aliases/alias', []);

	// Section-level read of a registered section — NOT a scalar key.
	$section = config_get_path('installedpackages/pfblockerng/config/0', []);

	// Section-level read of the DNSBL settings section — NOT a scalar key.
	$dnsbl = config_get_path('installedpackages/pfblockerngdnsblsettings/config/0', []);

	return [$v4, $custom, $aliases, $section, $dnsbl];
}

function pfb_gateway_compliant_dynamic_path($key)
{
	// Dynamic path (variable) — sniff must not flag (cannot statically evaluate).
	$val = config_get_path('installedpackages/pfblockerngglobal/feed_' . $key);

	// Dynamic per-continent path — foreign, dynamic.
	$continent = 'africa';
	$cfg = config_get_path("installedpackages/pfblockerng{$continent}/config/0");

	return [$val, $cfg];
}

function pfb_gateway_compliant_foreign_write()
{
	// Foreign write — pfblockerngblacklist is NOT in the registry.
	config_set_path('installedpackages/pfblockerngblacklist/blacklist_enable', 'Enable');

	// Widget-* foreign keys in pfblockerngglobal.
	config_set_path('installedpackages/pfblockerngglobal/widget-popup', 'yes');

	// Foreign delete — wizard temp section.
	config_del_path('pfblockerng_wizard');
}
