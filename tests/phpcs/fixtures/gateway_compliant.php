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
 *   e) ADR-53: the registered v4suppression key accessed via PfbConfig (not a
 *      raw config_*_path call at all) — sniff stays silent.
 *
 * Pinned by RequireConfigGatewaySniffTest::testCompliantCasesAreClean.
 */

function pfb_gateway_compliant_foreign_key()
{
	// Foreign key — pfblockerngipsettings/ip_placeholder is NOT in the registry.
	// (v4suppression, the ADR-53 sibling in this same section, IS registered — see
	// pfb_gateway_compliant_v4suppression_via_gateway() below — and issue #2123
	// registered the section's seven checkbox keys, so this example uses a key that
	// is still genuinely foreign.)
	$dup = config_get_path('installedpackages/pfblockerngipsettings/config/0/ip_placeholder');

	// Foreign dynamic per-row key — not in the registered path set.
	$row = 0;
	$custom = config_get_path("installedpackages/pfblockerngdnsbl/config/{$row}/custom");

	// pfSense core section — completely out of gateway scope.
	$aliases = config_get_path('aliases/alias', []);

	// Section-level read of a registered section — NOT a scalar key.
	$section = config_get_path('installedpackages/pfblockerng/config/0', []);

	// Section-level read of the DNSBL settings section — NOT a scalar key.
	$dnsbl = config_get_path('installedpackages/pfblockerngdnsblsettings/config/0', []);

	return [$dup, $custom, $aliases, $section, $dnsbl];
}

function pfb_gateway_compliant_v4suppression_via_gateway()
{
	// ADR-53: v4suppression is registered — access via PfbConfig::read/write, never
	// raw config_get_path/config_set_path. Neither call here is one of the sniff's
	// gated function names, so this stays silent regardless of the key.
	$v4 = PfbConfig::read('ip/v4suppression');
	PfbConfig::write('ip/v4suppression', $v4);

	return $v4;
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
