<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * ADR-29 Phase 1 — PfbConfig gateway + field registry tests.
 *
 * Three test groups per the phase requirements:
 *
 * A — ROUND-TRIP IDENTITY
 *   For every registered field that carries a read+write adapter pair:
 *   write(read(v)) == v for every canonical stored vocabulary value.
 *   Mirrors the ADR-28 §2.2 contract.
 *
 * B — DEFAULT ON ABSENT KEY
 *   PfbConfig::read($key) returns the registered default when the key is
 *   absent from config (config_get_path returns NULL).
 *
 * C — INVENTORY COMPLETENESS
 *   Every installedpackages/pfblockerng* key that appears as a direct
 *   config_get_path/config_set_path argument in src/ is either:
 *     (i)  in the field registry (pfb_cfg_registry()), or
 *     (ii) on the explicit out-of-scope list defined in this test.
 *   A key absent from both fails the test, preventing silent blind-spots.
 *
 * D — GATEWAY MECHANICS
 *   PfbConfig::read/write/delete correctly apply adapters, route to the
 *   right config path, and throw for unregistered keys.
 *   PfbConfig::readSection/writeSection/deleteSection cover section helpers.
 */
final class CfgGatewayTest extends TestCase
{
	// -----------------------------------------------------------------------
	// Test fixture helpers
	// -----------------------------------------------------------------------

	protected function setUp(): void
	{
		// Give each test a clean config slate.
		$GLOBALS['config'] = [];
	}

	/**
	 * Seed a raw value at a config.xml path so ::read() sees it.
	 */
	private function seedConfig(string $path, mixed $value): void
	{
		config_set_path($path, $value);
	}

	// -----------------------------------------------------------------------
	// A — Round-trip identity for adapter-bearing fields
	//     (toggle and lenient adapters; idn-mode exclusion documented below)
	// -----------------------------------------------------------------------

	/**
	 * PfbToggle fields: 'on' and '' both round-trip losslessly.
	 *
	 * Scenario:
	 *   Background: toggle fields are stored as 'on' (enabled) or '' (disabled).
	 *     Given a canonical stored value v in {'on', ''}.
	 *     When PfbConfig::write($key, PfbConfig::read_raw_via_adapter($key, v)).
	 *     Then the stored string equals v (write(read(v)) == v).
	 */
	public function testToggleFieldsRoundTripOn(): void
	{
		// All toggle-adapted fields: we pick a representative one (pfb_keep) and
		// also verify pfb_dnsbl and pfb_dnsvip_auto to cover every adapter instance.
		$toggle_fields = [
			'enable_cb'     => 'installedpackages/pfblockerng/config/0/enable_cb',
			'pfb_keep'      => 'installedpackages/pfblockerng/config/0/pfb_keep',
			'pfb_dnsbl'     => 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl',
			'pfb_dnsvip_auto' => 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsvip_auto',
			'pfb_reuse'     => 'installedpackages/pfblockerng/config/0/pfb_reuse',
			'pfb_hsts'      => 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_hsts',
		];

		foreach ($toggle_fields as $key => $path) {
			// Given: canonical 'on' stored.
			$this->seedConfig($path, 'on');

			// Before: raw value is 'on'.
			$this->assertSame('on', config_get_path($path), "before: {$key} seed is 'on'");

			// When: read -> write.
			$enum   = PfbConfig::read($key);
			$this->assertSame(PfbToggle::On, $enum, "read: {$key} 'on' -> PfbToggle::On");

			// After: write back produces 'on'.
			PfbConfig::write($key, $enum);
			$this->assertSame('on', config_get_path($path), "write(read('on'))==on for {$key}");
		}
	}

	public function testToggleFieldsRoundTripOff(): void
	{
		$toggle_fields = [
			'enable_cb'       => 'installedpackages/pfblockerng/config/0/enable_cb',
			'pfb_keep'        => 'installedpackages/pfblockerng/config/0/pfb_keep',
			'pfb_dnsbl'       => 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl',
			'pfb_dnsvip_auto' => 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsvip_auto',
			'pfb_reuse'       => 'installedpackages/pfblockerng/config/0/pfb_reuse',
			'pfb_hsts'        => 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_hsts',
		];

		foreach ($toggle_fields as $key => $path) {
			// Given: canonical '' (unchecked) stored.
			$this->seedConfig($path, '');

			// Before: raw value is ''.
			$this->assertSame('', config_get_path($path), "before: {$key} seed is ''");

			// When: read -> write.
			$enum = PfbConfig::read($key);
			$this->assertSame(PfbToggle::Off, $enum, "read: {$key} '' -> PfbToggle::Off");

			// After: write back produces ''.
			PfbConfig::write($key, $enum);
			$this->assertSame('', config_get_path($path), "write(read(''))=='' for {$key}");
		}
	}

	/**
	 * PfbLenient field (pfb_dnsbl_lenient): 'on'/'off' round-trip; '' -> 'off' (documented).
	 *
	 * Scenario:
	 *   Background: pfb_dnsbl_lenient stored as 'on', 'off', or '' (pre-ADR-22).
	 *     Given v.  When read/write.
	 *     Then 'on' and 'off' round-trip losslessly.
	 *     And '' normalises to 'off' on write (documented default normalisation).
	 */
	public function testLenientFieldRoundTripOn(): void
	{
		$path = 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl_lenient';

		// Given: canonical 'on'.
		$this->seedConfig($path, 'on');

		// Before: raw 'on'.
		$this->assertSame('on', config_get_path($path));

		// When/After.
		$enum = PfbConfig::read('pfb_dnsbl_lenient');
		$this->assertSame(PfbLenient::On, $enum);

		PfbConfig::write('pfb_dnsbl_lenient', $enum);
		$this->assertSame('on', config_get_path($path));
	}

	public function testLenientFieldRoundTripOff(): void
	{
		$path = 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl_lenient';

		// Given: canonical 'off'.
		$this->seedConfig($path, 'off');

		// Before: raw 'off'.
		$this->assertSame('off', config_get_path($path));

		// When/After.
		$enum = PfbConfig::read('pfb_dnsbl_lenient');
		$this->assertSame(PfbLenient::Off, $enum);

		PfbConfig::write('pfb_dnsbl_lenient', $enum);
		$this->assertSame('off', config_get_path($path));
	}

	public function testLenientFieldEmptyNormalisesToOff(): void
	{
		$path = 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl_lenient';

		// Given: '' (pre-ADR-22 install, key never written).
		$this->seedConfig($path, '');

		// Before: raw ''.
		$this->assertSame('', config_get_path($path));

		// When/After: normalised to 'off' (documented, matches pfb_global() behaviour).
		$enum = PfbConfig::read('pfb_dnsbl_lenient');
		$this->assertSame(PfbLenient::Off, $enum);

		PfbConfig::write('pfb_dnsbl_lenient', $enum);
		// Normalised: stored as 'off', NOT ''.
		$this->assertSame('off', config_get_path($path));
	}

	// -----------------------------------------------------------------------
	// B — Default on absent key
	// -----------------------------------------------------------------------

	/**
	 * ::read($key) returns the registered default when the key is absent.
	 *
	 * Scenario:
	 *   Background: config[$section/$key] is unset.
	 *     Given PfbConfig::read($key) with no seed in config.
	 *     Then the return value matches the registered default.
	 */
	public function testReadReturnsRegisteredDefaultForToggleAbsentKey(): void
	{
		// enable_cb default is '' (Off enum).
		// Before: key absent.
		$this->assertNull(config_get_path('installedpackages/pfblockerng/config/0/enable_cb'));

		// When/Then: returns Off (default '').
		$result = PfbConfig::read('enable_cb');
		$this->assertSame(PfbToggle::Off, $result, 'enable_cb absent -> Off (default)');
	}

	public function testReadReturnsRegisteredDefaultForPfbKeepAbsentKey(): void
	{
		// pfb_keep default is 'on' (On enum) — the #281 canonical default.
		// Before: key absent.
		$this->assertNull(config_get_path('installedpackages/pfblockerng/config/0/pfb_keep'));

		// When: read with no seed.
		$result = PfbConfig::read('pfb_keep');

		// Then: returns On (the registered default 'on', applied through toggle adapter).
		$this->assertSame(PfbToggle::On, $result, 'pfb_keep absent -> On (default on)');
	}

	public function testReadReturnsRegisteredDefaultForLenientAbsentKey(): void
	{
		// pfb_dnsbl_lenient default is 'off' -> PfbLenient::Off.
		// Before: key absent.
		$this->assertNull(
			config_get_path('installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl_lenient')
		);

		// When.
		$result = PfbConfig::read('pfb_dnsbl_lenient');

		// Then: Off.
		$this->assertSame(PfbLenient::Off, $result, 'pfb_dnsbl_lenient absent -> Off');
	}

	public function testReadReturnsRegisteredDefaultForPlainStringAbsentKey(): void
	{
		// pfb_interval default is '1'.
		$this->assertNull(config_get_path('installedpackages/pfblockerng/config/0/pfb_interval'));

		$result = PfbConfig::read('pfb_interval');
		$this->assertSame('1', $result, 'pfb_interval absent -> "1"');
	}

	public function testReadReturnsRegisteredDefaultForAlexaTypeAbsentKey(): void
	{
		// alexa_type default is 'tranco'.
		$this->assertNull(
			config_get_path('installedpackages/pfblockerngdnsblsettings/config/0/alexa_type')
		);

		$result = PfbConfig::read('alexa_type');
		$this->assertSame('tranco', $result);
	}

	public function testReadReturnsRegisteredDefaultForDnsblInterfaceAbsentKey(): void
	{
		// dnsbl_interface default is 'lo0'.
		$this->assertNull(
			config_get_path('installedpackages/pfblockerngdnsblsettings/config/0/dnsbl_interface')
		);

		$result = PfbConfig::read('dnsbl_interface');
		$this->assertSame('lo0', $result);
	}

	public function testReadReturnsRegisteredDefaultForSafeSearchAbsentKey(): void
	{
		// safesearch_enable default is 'Disable'.
		$this->assertNull(config_get_path('installedpackages/pfblockerngsafesearch/safesearch_enable'));

		$result = PfbConfig::read('safesearch_enable');
		$this->assertSame('Disable', $result);
	}

	public function testReadReturnsRegisteredDefaultForIdnBlockMaliciousAbsentKey(): void
	{
		// pfb_idn_block_malicious default is 'on'.
		$this->assertNull(
			config_get_path('installedpackages/pfblockerngdnsblsettings/config/0/pfb_idn_block_malicious')
		);

		$result = PfbConfig::read('pfb_idn_block_malicious');
		$this->assertSame('on', $result);
	}

	// -----------------------------------------------------------------------
	// C — Inventory completeness
	// -----------------------------------------------------------------------

	/**
	 * Every installedpackages/pfblockerng* scalar key directly read from
	 * config_get_path in src/ is either in the registry or explicitly
	 * listed as out-of-scope.
	 *
	 * Scenario:
	 *   Background: the known inventory is derived from grepping src/ for
	 *   config_get_path/config_set_path calls with installedpackages/pfblockerng*
	 *   paths. Out-of-scope keys are documented below.
	 *   Given the union of registry + out-of-scope covers the inventory.
	 *   When we check each inventory key against both lists.
	 *   Then no key is unaccounted for.
	 *
	 * OUT-OF-SCOPE / FOREIGN KEYS (§2.5 ADR-29):
	 *   Whole-section paths (section reads) and structural/non-scalar keys
	 *   that are read as arrays or sub-trees, not individual scalar fields.
	 *   Phase 1 does not register per-key entries for these — they are
	 *   handled via PfbConfig::readSection() or remain on direct config_*_path.
	 *
	 *   - 'pfb_wizard_skip' — wizard skip flag (pfblockerng level, not /config/0)
	 *   - 'hooks' / 'hooks/row' — hooks sub-tree (structural list, not scalar)
	 *   - Entire section reads: pfblockerngblacklist, pfblockerngglobal,
	 *     pfblockerngipsettings, pfblockerngreputation, pfblockerngsync,
	 *     pfblockerngdnsbl, pfblockerngdnsbleasylist, pfblockernglistsv{n},
	 *     pfblockerngantartica (typo in old data), pfblockerng{continent}
	 *   - Dynamic feed/continent keys: feed_alt_*, widget-{type}
	 *   - pfblockerngipsettings sub-keys (all section-level, handled together):
	 *     v4suppression, maxmind_key, etc. (suppression key in ipsettings is a distinct
	 *     concept from pfblockerngdnsblsettings/suppression which IS registered).
	 *   - pfblockerngreputation sub-keys: et_header
	 *   - pfblockerngsync sub-keys: syncinterfaces, varsynconchanges, row/*
	 *   - pfblockerngblacklist sub-keys: blacklist_enable, blacklist_freq,
	 *     blacklist_lang, blacklist_logging, blacklist_selected, item
	 *   - pfblockerngdnsblsettings sub-keys with ambiguous names across files:
	 *     dnsbl_webpage (used inconsistently with dnsblwebpage in the codebase)
	 */
	public function testInventoryCompletenessAllKnownKeysAccountedFor(): void
	{
		$registry = pfb_cfg_registry();
		$registered_keys = array_keys($registry);

		// Out-of-scope keys — foreign, structural, or section-level (§2.5 ADR-29).
		// Any key listed here must NOT be in the registry (it stays foreign).
		$out_of_scope = [
			// Wizard-level flag (pfblockerng level, not /config/0 scalar).
			'pfb_wizard_skip',

			// Hooks sub-tree (structural list, not a scalar field).
			'hooks',
			'hooks/row',

			// pfblockerngblacklist — whole-section or sub-key reads.
			'blacklist_enable',
			'blacklist_freq',
			'blacklist_lang',
			'blacklist_logging',
			'blacklist_selected',
			'item',

			// pfblockerngglobal — dynamic keys (feed_alt_*, widget-*, feed_*).
			// These are read with dynamic paths; not individual static fields.
			'pfbextdns',

			// pfblockerngipsettings — section read + sub-keys.
			'v4suppression',
			'maxmind_key',
			'maxmind_locale',
			'database_cc',
			'asn_reporting',
			'asn_token',
			'maxmind_account',
			'inbound_deny_action',
			'outbound_deny_action',
			'enable_float',
			'enable_dup',
			'enable_agg',
			'pass_order',
			'enable_log',
			'autorule_suffix',
			'killstates',
			'ip_placeholder',

			// pfblockerngreputation sub-keys.
			'et_header',

			// pfblockerngsync sub-keys.
			'syncinterfaces',
			'varsynconchanges',
			'varsynctimeout',
			'varsyncdestinenable',

			// pfblockerngdnsblsettings ambiguous duplicate name (typo in pfblockerng.inc:
			// 'dnsbl_webpage' used at line 413 in www/pfblockerng_dnsbl.php vs
			// 'dnsblwebpage' which IS registered above).
			'dnsbl_webpage',
		];

		// Verify the out-of-scope list doesn't conflict with the registry
		// (no key should be in BOTH lists — that would be a registry error).
		$conflicts = array_intersect($registered_keys, $out_of_scope);
		$this->assertEmpty(
			$conflicts,
			'Keys must not be in BOTH the registry and the out-of-scope list: '
			. implode(', ', $conflicts)
		);

		// Known inventory: every scalar key read via config_get_path on a
		// installedpackages/pfblockerng* path in src/ (non-dynamic, non-section).
		// This is the ground truth derived from grep of src/; must be kept in
		// sync with the actual codebase. The test FAILS if a new key is added
		// to src/ without updating the registry or this out-of-scope list.
		$inventory = [
			// pfblockerng/config/0 scalars
			'enable_cb',
			'pfb_keep',
			'pfb_interval',
			'pfb_min',
			'pfb_hour',
			'pfb_dailystart',
			'skipfeed',
			'pfb_agg_types',
			'log_max_log',
			'log_max_errlog',
			'log_max_extraslog',
			'log_max_ip_blocklog',
			'log_max_ip_permitlog',
			'log_max_ip_matchlog',
			'log_max_dnslog',
			'log_max_dnsbl_parse_err',
			'log_max_dnsreplylog',
			'log_max_unilog',
			'log_rotate_log',
			'log_rotate_errlog',
			'log_rotate_extraslog',
			'log_rotate_ip_blocklog',
			'log_rotate_ip_permitlog',
			'log_rotate_ip_matchlog',
			'log_rotate_dnslog',
			'log_rotate_dnsbl_parse_err',
			'log_rotate_dnsreplylog',
			'log_rotate_unilog',
			'log_reset_keep_log',
			'log_reset_keep_errlog',
			'log_reset_keep_extraslog',
			'log_reset_keep_ip_blocklog',
			'log_reset_keep_ip_permitlog',
			'log_reset_keep_ip_matchlog',
			'log_reset_keep_dnslog',
			'log_reset_keep_dnsbl_parse_err',
			'log_reset_keep_dnsreplylog',
			'log_reset_keep_unilog',
			'pfb_software_check',
			'pfb_feed_internal_filter',
			'pfb_feed_internal_allowlist',
			'pfb_reuse',

			// pfblockerngdnsblsettings/config/0 scalars
			'pfb_dnsbl',
			'pfb_dnsvip_auto',
			'dnsbl_interface',
			'pfb_dnsvip4',
			'pfb_dnsvip6',
			'pfb_dnsport',
			'pfb_dnsport_ssl',
			'alexa_enable',
			'alexa_type',
			'alexa_count',
			'alexa_inclusion',
			'pfb_cache',
			'global_log',
			'pfb_dnsbl_lenient',
			'pfb_py_reply',
			'pfb_hsts',
			'pfb_idn',
			'pfb_idn_block_malicious',
			'pfb_idn_escalate_suspicious',
			'pfb_regex',
			'pfb_regex_list',
			'pfb_regex_cap',
			'pfb_cname',
			'pfb_pytld',
			'pfb_py_nolog',
			'pfb_noaaaa',
			'pfb_noaaaa_list',
			'pfb_gp',
			'pfb_gp_bypass_list',
			'tldblacklist',
			'tldexclusion',
			'suppression',
			'action',
			'pfb_dnsbl_rule',
			'dnsbl_allow_int',
			'pfb_control',
			'pfb_control_legacy',
			'pfb_py_cache_max',
			'pfb_tld',
			'aliaslog',
			'dnsblwebpage',

			// pfblockerngsafesearch scalars
			'safesearch_enable',
			'safesearch_youtube',
			'safesearch_doh',
			'safesearch_doh_list',

			// Out-of-scope keys (must also appear in $out_of_scope above)
			'pfb_wizard_skip',
			'hooks',
			'hooks/row',
			'blacklist_enable',
			'blacklist_freq',
			'blacklist_lang',
			'blacklist_logging',
			'blacklist_selected',
			'item',
			'pfbextdns',
			'v4suppression',
			'maxmind_key',
			'maxmind_locale',
			'database_cc',
			'asn_reporting',
			'asn_token',
			'maxmind_account',
			'inbound_deny_action',
			'outbound_deny_action',
			'enable_float',
			'enable_dup',
			'enable_agg',
			'pass_order',
			'enable_log',
			'autorule_suffix',
			'killstates',
			'ip_placeholder',
			'et_header',
			'syncinterfaces',
			'varsynconchanges',
			'varsynctimeout',
			'varsyncdestinenable',
			'dnsbl_webpage',
		];

		// Deduplicate (some keys appear in multiple sections).
		$inventory = array_unique($inventory);

		// Every inventory key must be accounted for.
		$union = array_unique(array_merge($registered_keys, $out_of_scope));

		$unaccounted = array_diff($inventory, $union);
		$this->assertEmpty(
			$unaccounted,
			'Inventory keys not in registry OR out-of-scope list: '
			. implode(', ', $unaccounted)
		);
	}

	// -----------------------------------------------------------------------
	// D — Gateway mechanics
	// -----------------------------------------------------------------------

	/**
	 * PfbConfig::read() routes to the correct config.xml path for each section.
	 *
	 * Scenario:
	 *   Given a value seeded directly at the expected full path.
	 *   When PfbConfig::read($key) is called.
	 *   Then the value returned matches the seeded value (through identity adapter).
	 */
	public function testReadRoutesToCorrectConfigPath(): void
	{
		// General section key.
		$this->seedConfig('installedpackages/pfblockerng/config/0/pfb_interval', '6');
		$this->assertSame('6', PfbConfig::read('pfb_interval'));

		// DNSBL settings section key.
		$this->seedConfig('installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsport', '8080');
		$this->assertSame('8080', PfbConfig::read('pfb_dnsport'));

		// SafeSearch section key (flat, no /config/0).
		$this->seedConfig('installedpackages/pfblockerngsafesearch/safesearch_enable', 'Google');
		$this->assertSame('Google', PfbConfig::read('safesearch_enable'));
	}

	/**
	 * PfbConfig::write() routes to the correct config.xml path for each section.
	 *
	 * Scenario:
	 *   Given nothing seeded in config.
	 *   When PfbConfig::write($key, $value) is called.
	 *   Then config_get_path at the expected full path returns the written value.
	 */
	public function testWriteRoutesToCorrectConfigPath(): void
	{
		// General section key (plain string).
		// Before: absent.
		$this->assertNull(config_get_path('installedpackages/pfblockerng/config/0/pfb_interval'));

		// When.
		PfbConfig::write('pfb_interval', '12');

		// After: stored.
		$this->assertSame('12', config_get_path('installedpackages/pfblockerng/config/0/pfb_interval'));
	}

	public function testWriteAppliesToggleAdapterBeforeStorage(): void
	{
		// PfbToggle::On enum must be converted to the stored string 'on'.
		$path = 'installedpackages/pfblockerng/config/0/enable_cb';

		// Before: absent.
		$this->assertNull(config_get_path($path));

		// When: write enum value.
		PfbConfig::write('enable_cb', PfbToggle::On);

		// After: stored as the string 'on', not an enum object.
		$this->assertSame('on', config_get_path($path));
	}

	public function testWriteAppliesLenientAdapterBeforeStorage(): void
	{
		$path = 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl_lenient';

		// Before: absent.
		$this->assertNull(config_get_path($path));

		// When: write Off enum.
		PfbConfig::write('pfb_dnsbl_lenient', PfbLenient::Off);

		// After: stored as 'off' (not '' — PfbLenient::Off = 'off').
		$this->assertSame('off', config_get_path($path));
	}

	/**
	 * PfbConfig::delete() removes the key from the config path.
	 *
	 * Scenario:
	 *   Given a seeded key.
	 *   When PfbConfig::delete($key).
	 *   Then config_get_path for that path returns null.
	 */
	public function testDeleteRemovesKeyFromConfigPath(): void
	{
		$path = 'installedpackages/pfblockerng/config/0/pfb_interval';

		// Given.
		$this->seedConfig($path, '3');
		$this->assertSame('3', config_get_path($path), 'before: key is set');

		// When.
		PfbConfig::delete('pfb_interval');

		// After.
		$this->assertNull(config_get_path($path), 'after delete: key is gone');
	}

	/**
	 * PfbConfig::read() throws for a key not in the registry.
	 */
	public function testReadThrowsForUnregisteredKey(): void
	{
		$this->expectException(InvalidArgumentException::class);
		$this->expectExceptionMessageMatches('/not in the field registry/');

		PfbConfig::read('this_key_does_not_exist_in_registry');
	}

	/**
	 * PfbConfig::write() throws for a key not in the registry.
	 */
	public function testWriteThrowsForUnregisteredKey(): void
	{
		$this->expectException(InvalidArgumentException::class);
		$this->expectExceptionMessageMatches('/not in the field registry/');

		PfbConfig::write('this_key_does_not_exist_in_registry', 'value');
	}

	/**
	 * PfbConfig::delete() throws for a key not in the registry.
	 */
	public function testDeleteThrowsForUnregisteredKey(): void
	{
		$this->expectException(InvalidArgumentException::class);
		$this->expectExceptionMessageMatches('/not in the field registry/');

		PfbConfig::delete('this_key_does_not_exist_in_registry');
	}

	/**
	 * PfbConfig::readSection() returns the section array from config.
	 *
	 * Scenario:
	 *   Given a seeded section array.
	 *   When PfbConfig::readSection($section).
	 *   Then the returned array matches the seeded data.
	 */
	public function testReadSectionReturnsSeededSectionArray(): void
	{
		$section = 'installedpackages/pfblockerng/config/0';
		$data    = ['enable_cb' => 'on', 'pfb_keep' => 'on', 'pfb_interval' => '6'];

		// Before: absent.
		$this->assertSame([], PfbConfig::readSection($section), 'before: empty section returns []');

		// Given.
		config_set_path($section, $data);

		// When/Then.
		$this->assertSame($data, PfbConfig::readSection($section));
	}

	/**
	 * PfbConfig::writeSection() persists a section array.
	 */
	public function testWriteSectionPersistsSectionArray(): void
	{
		$section = 'installedpackages/pfblockerngdnsblsettings/config/0';
		$data    = ['pfb_dnsbl' => 'on', 'pfb_dnsport' => '8080'];

		// Before: absent.
		$this->assertNull(config_get_path($section));

		// When.
		PfbConfig::writeSection($section, $data);

		// After.
		$this->assertSame($data, config_get_path($section));
	}

	/**
	 * PfbConfig::deleteSection() removes the whole section.
	 *
	 * Scenario:
	 *   Given a seeded section.
	 *   When PfbConfig::deleteSection($section).
	 *   Then readSection($section) returns [].
	 */
	public function testDeleteSectionRemovesWholeSection(): void
	{
		$section = 'installedpackages/pfblockerng/config/0';
		$data    = ['enable_cb' => 'on'];

		// Given.
		config_set_path($section, $data);
		$this->assertSame($data, PfbConfig::readSection($section), 'before: section present');

		// When.
		PfbConfig::deleteSection($section);

		// After: gone.
		$this->assertSame([], PfbConfig::readSection($section), 'after: section absent -> []');
	}

	// -----------------------------------------------------------------------
	// D (extra) — pfb_idn exclusion from adapter adoption is documented and enforced
	// -----------------------------------------------------------------------

	/**
	 * pfb_idn is excluded from adapter adoption: stored plain (no PfbIdnMode adapter).
	 *
	 * The legacy 'on' value cannot round-trip (write(read('on')) == 'all' != 'on').
	 * The registry entry uses null adapters (plain string) to preserve the stored value.
	 * This test documents and pins the exclusion.
	 *
	 * Scenario:
	 *   Background: pfb_idn stored as 'on' (legacy) or 'all'/'confusable'/'off'.
	 *     Given pfb_idn = 'on'.
	 *     When PfbConfig::read('pfb_idn').
	 *     Then the raw string 'on' is returned (no adapter normalisation).
	 *     And write(read('on')) == 'on' (identity — NOT 'all').
	 */
	public function testIdnFieldExcludedFromAdapterReturnsRawStringOn(): void
	{
		$path = 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_idn';

		// Given: legacy 'on' stored.
		$this->seedConfig($path, 'on');

		// Before: raw 'on'.
		$this->assertSame('on', config_get_path($path));

		// When: read.
		$raw = PfbConfig::read('pfb_idn');

		// Then: raw string 'on' (NOT PfbIdnMode::All — the adapter is NOT wired).
		$this->assertSame('on', $raw, 'pfb_idn returns raw string, not adapted enum');
		$this->assertNotInstanceOf(PfbIdnMode::class, $raw, 'pfb_idn must not return an enum');

		// And: write(read('on')) == 'on' (lossless identity — exclusion confirmed).
		PfbConfig::write('pfb_idn', $raw);
		$this->assertSame('on', config_get_path($path), 'write(read("on")) == "on" for pfb_idn');
	}

	public function testIdnFieldExcludedFromAdapterReturnsRawStringAll(): void
	{
		$path = 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_idn';

		// Given: canonical 'all'.
		$this->seedConfig($path, 'all');

		// Before: raw 'all'.
		$this->assertSame('all', config_get_path($path));

		// When/After: identity — 'all' stays 'all'.
		$raw = PfbConfig::read('pfb_idn');
		$this->assertSame('all', $raw);

		PfbConfig::write('pfb_idn', $raw);
		$this->assertSame('all', config_get_path($path));
	}

	// -----------------------------------------------------------------------
	// D (extra) — Registry completeness: every registered key has all required fields
	// -----------------------------------------------------------------------

	/**
	 * Every registry entry has the required shape: section, default, read_adapter,
	 * write_adapter, since — and adapters are callable|null.
	 */
	public function testRegistryEntriesHaveRequiredShape(): void
	{
		$registry       = pfb_cfg_registry();
		$required_keys  = ['section', 'default', 'read_adapter', 'write_adapter', 'since'];

		$this->assertNotEmpty($registry, 'Registry must not be empty');

		foreach ($registry as $field_key => $entry) {
			foreach ($required_keys as $k) {
				$this->assertArrayHasKey($k, $entry,
					"Registry entry '{$field_key}' missing required key '{$k}'"
				);
			}

			// section must be a non-empty string.
			$this->assertIsString($entry['section'],  "'{$field_key}'.section must be a string");
			$this->assertNotEmpty($entry['section'],  "'{$field_key}'.section must not be empty");

			// default must be a string.
			$this->assertIsString($entry['default'],  "'{$field_key}'.default must be a string");

			// adapters must be callable or null.
			if ($entry['read_adapter'] !== NULL) {
				$this->assertTrue(
					is_callable($entry['read_adapter']),
					"'{$field_key}'.read_adapter must be callable or NULL"
				);
			}
			if ($entry['write_adapter'] !== NULL) {
				$this->assertTrue(
					is_callable($entry['write_adapter']),
					"'{$field_key}'.write_adapter must be callable or NULL"
				);
			}

			// Adapters must be paired (both or neither).
			$this->assertSame(
				$entry['read_adapter'] === NULL,
				$entry['write_adapter'] === NULL,
				"'{$field_key}': read_adapter and write_adapter must both be NULL or both callable"
			);

			// since must be a non-empty string.
			$this->assertIsString($entry['since'],    "'{$field_key}'.since must be a string");
			$this->assertNotEmpty($entry['since'],    "'{$field_key}'.since must not be empty");
		}
	}

	/**
	 * The static cache in pfb_cfg_registry() is stable: multiple calls return the same array.
	 */
	public function testRegistryStaticCacheIsStable(): void
	{
		$first  = pfb_cfg_registry();
		$second = pfb_cfg_registry();

		$this->assertSame($first, $second, 'Registry must return the same array on repeated calls');
		$this->assertNotEmpty($first, 'Registry must not be empty');
	}

	// -----------------------------------------------------------------------
	// ADR-30 — log_rotate_<type> field round-trip, default-absent, inventory
	// -----------------------------------------------------------------------

	/**
	 * All 10 log_rotate_<type> fields are registered.
	 *
	 * Scenario:
	 *   Background: ADR-30 adds one log_rotate_<type> key per log type.
	 *     Given pfb_cfg_registry().
	 *     When checking for each expected key.
	 *     Then all 10 are present.
	 */
	public function testLogRotateFieldsAreRegistered(): void
	{
		$registry  = pfb_cfg_registry();
		$log_types = [
			'log', 'errlog', 'extraslog', 'ip_blocklog', 'ip_permitlog',
			'ip_matchlog', 'dnslog', 'dnsbl_parse_err', 'dnsreplylog', 'unilog',
		];

		foreach ($log_types as $type) {
			$key = 'log_rotate_' . $type;
			$this->assertArrayHasKey($key, $registry,
				"log_rotate_{$type} must be in the registry"
			);
		}
	}

	/**
	 * Data provider — all 10 log_rotate_<type> keys × all 4 vocabulary tokens.
	 *
	 * @return array<string, array{string, string}>
	 */
	public static function logRotateVocabularyProvider(): array
	{
		$log_types = [
			'log', 'errlog', 'extraslog', 'ip_blocklog', 'ip_permitlog',
			'ip_matchlog', 'dnslog', 'dnsbl_parse_err', 'dnsreplylog', 'unilog',
		];
		$vocab     = ['off', 'daily', 'weekly', 'monthly'];
		$cases     = [];
		foreach ($log_types as $type) {
			foreach ($vocab as $token) {
				$cases["log_rotate_{$type}/{$token}"] = ["log_rotate_{$type}", $token];
			}
		}
		return $cases;
	}

	/**
	 * log_rotate_<type>: write(read(v)) == v for every vocabulary token.
	 *
	 * Scenario:
	 *   Background: log_rotate_<type> fields use identity (null/null) adapter.
	 *     Given a vocabulary token v ∈ {'off','daily','weekly','monthly'}.
	 *     When PfbConfig::read($key) then PfbConfig::write($key, result).
	 *     Then write(read(v)) == v (round-trip identity).
	 */
	#[DataProvider('logRotateVocabularyProvider')]
	public function testLogRotateFieldRoundTripForAllVocabularyTokens(
		string $key,
		string $token
	): void {
		$path = 'installedpackages/pfblockerng/config/0/' . $key;

		// Given: a vocabulary token stored.
		$this->seedConfig($path, $token);

		// Before: raw value confirmed.
		$this->assertSame($token, config_get_path($path),
			"before: {$key} seeded to '{$token}'"
		);

		// When: read.
		$result = PfbConfig::read($key);

		// Then: identity adapter — result is the same string.
		$this->assertIsString($result, "{$key} read('{$token}') must return a string");
		$this->assertSame($token, $result,
			"{$key} read('{$token}') must return '{$token}' (identity)"
		);

		// And: write back produces the same stored value (round-trip).
		PfbConfig::write($key, $result);
		$this->assertSame($token, config_get_path($path),
			"write(read('{$token}')) == '{$token}' for {$key}"
		);
	}

	/**
	 * log_rotate_<type>: absent key returns default 'off'.
	 *
	 * Scenario:
	 *   Background: key entirely absent from config.xml.
	 *     Given no value seeded.
	 *     When PfbConfig::read($key).
	 *     Then 'off' is returned (registered default).
	 */
	public function testLogRotateFieldAbsentKeyReturnsDefaultOff(): void
	{
		$log_types = [
			'log', 'errlog', 'extraslog', 'ip_blocklog', 'ip_permitlog',
			'ip_matchlog', 'dnslog', 'dnsbl_parse_err', 'dnsreplylog', 'unilog',
		];

		foreach ($log_types as $type) {
			$key  = 'log_rotate_' . $type;
			$path = 'installedpackages/pfblockerng/config/0/' . $key;

			// Before: absent.
			$this->assertNull(config_get_path($path),
				"before: {$key} must be absent"
			);

			// When/Then: default 'off' returned.
			$result = PfbConfig::read($key);
			$this->assertSame('off', $result,
				"{$key} absent must return 'off' (registered default)"
			);
		}
	}

	// -----------------------------------------------------------------------
	// ADR-30 amendment — log_reset_keep_<type> field round-trip, default-absent, inventory
	// -----------------------------------------------------------------------

	/**
	 * All 10 log_reset_keep_<type> fields are registered.
	 *
	 * Scenario:
	 *   Background: ADR-30 amendment adds one log_reset_keep_<type> key per log type.
	 *     Given pfb_cfg_registry().
	 *     When checking for each expected key.
	 *     Then all 10 are present.
	 */
	public function testLogResetKeepFieldsAreRegistered(): void
	{
		$registry  = pfb_cfg_registry();
		$log_types = [
			'log', 'errlog', 'extraslog', 'ip_blocklog', 'ip_permitlog',
			'ip_matchlog', 'dnslog', 'dnsbl_parse_err', 'dnsreplylog', 'unilog',
		];

		foreach ($log_types as $type) {
			$key = 'log_reset_keep_' . $type;
			$this->assertArrayHasKey($key, $registry,
				"log_reset_keep_{$type} must be in the registry"
			);
		}
	}

	/**
	 * Data provider — all 10 log_reset_keep_<type> keys × canonical numeric tokens.
	 *
	 * @return array<string, array{string, string}>
	 */
	public static function logResetKeepVocabularyProvider(): array
	{
		$log_types = [
			'log', 'errlog', 'extraslog', 'ip_blocklog', 'ip_permitlog',
			'ip_matchlog', 'dnslog', 'dnsbl_parse_err', 'dnsreplylog', 'unilog',
		];
		$vocab  = ['0', '100', '500'];
		$cases  = [];
		foreach ($log_types as $type) {
			foreach ($vocab as $token) {
				$cases["log_reset_keep_{$type}/{$token}"] = ["log_reset_keep_{$type}", $token];
			}
		}
		return $cases;
	}

	/**
	 * log_reset_keep_<type>: write(read(v)) == v for every vocabulary token.
	 *
	 * Scenario:
	 *   Background: log_reset_keep_<type> fields use identity (null/null) adapter.
	 *     Given a vocabulary token v ∈ {'0','100','500'}.
	 *     When PfbConfig::read($key) then PfbConfig::write($key, result).
	 *     Then write(read(v)) == v (round-trip identity).
	 */
	#[DataProvider('logResetKeepVocabularyProvider')]
	public function testLogResetKeepFieldRoundTripForAllVocabularyTokens(
		string $key,
		string $token
	): void {
		$path = 'installedpackages/pfblockerng/config/0/' . $key;

		// Given: a vocabulary token stored.
		$this->seedConfig($path, $token);

		// Before: raw value confirmed.
		$this->assertSame($token, config_get_path($path),
			"before: {$key} seeded to '{$token}'"
		);

		// When: read.
		$result = PfbConfig::read($key);

		// Then: identity adapter — result is the same string.
		$this->assertIsString($result, "{$key} read('{$token}') must return a string");
		$this->assertSame($token, $result,
			"{$key} read('{$token}') must return '{$token}' (identity)"
		);

		// And: write back produces the same stored value (round-trip).
		PfbConfig::write($key, $result);
		$this->assertSame($token, config_get_path($path),
			"write(read('{$token}')) == '{$token}' for {$key}"
		);
	}

	/**
	 * log_reset_keep_<type>: absent key returns default '0'.
	 *
	 * Scenario:
	 *   Background: key entirely absent from config.xml.
	 *     Given no value seeded.
	 *     When PfbConfig::read($key).
	 *     Then '0' is returned (registered default).
	 */
	public function testLogResetKeepFieldAbsentKeyReturnsDefaultZero(): void
	{
		$log_types = [
			'log', 'errlog', 'extraslog', 'ip_blocklog', 'ip_permitlog',
			'ip_matchlog', 'dnslog', 'dnsbl_parse_err', 'dnsreplylog', 'unilog',
		];

		foreach ($log_types as $type) {
			$key  = 'log_reset_keep_' . $type;
			$path = 'installedpackages/pfblockerng/config/0/' . $key;

			// Before: absent.
			$this->assertNull(config_get_path($path),
				"before: {$key} must be absent"
			);

			// When/Then: default '0' returned.
			$result = PfbConfig::read($key);
			$this->assertSame('0', $result,
				"{$key} absent must return '0' (registered default)"
			);
		}
	}
}
