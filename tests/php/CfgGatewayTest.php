<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/LogTypesFixture.php';

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
		// Representative toggle-adapted fields (pfb_keep is now lenient — see below).
		$toggle_fields = [
			'enable_cb'        => 'installedpackages/pfblockerng/config/0/enable_cb',
			'pfb_dnsbl'        => 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl',
			'pfb_dnsvip_auto'  => 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsvip_auto',
			'pfb_dnsbl_nonat'  => 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl_nonat',
			'pfb_reuse'        => 'installedpackages/pfblockerng/config/0/pfb_reuse',
			'pfb_hsts'         => 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_hsts',
			'pfb_feed_sanity'  => 'installedpackages/pfblockerng/config/0/pfb_feed_sanity',
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
		// pfb_keep is now lenient — see testPfbKeepLenientRoundTrip*() below.
		$toggle_fields = [
			'enable_cb'        => 'installedpackages/pfblockerng/config/0/enable_cb',
			'pfb_dnsbl'        => 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl',
			'pfb_dnsvip_auto'  => 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsvip_auto',
			'pfb_dnsbl_nonat'  => 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl_nonat',
			'pfb_reuse'        => 'installedpackages/pfblockerng/config/0/pfb_reuse',
			'pfb_hsts'         => 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_hsts',
			'pfb_feed_sanity'  => 'installedpackages/pfblockerng/config/0/pfb_feed_sanity',
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

	/**
	 * pfb_keep (lenient adapter): 'on'/'off'/'' round-trips and legacy '' normalises.
	 *
	 * Scenario:
	 *   Background: pfb_keep stored as 'on', 'off', or '' (pre-#484-fix legacy empty).
	 *     Given v.  When read/write.
	 *     Then 'on' round-trips to 'on'; 'off' round-trips to 'off'.
	 *     And '' (legacy) normalises to 'off' on write (backward-safe).
	 */
	public function testPfbKeepLenientRoundTripOn(): void
	{
		$path = 'installedpackages/pfblockerng/config/0/pfb_keep';

		// Given: canonical 'on'.
		$this->seedConfig($path, 'on');

		// Before: raw 'on'.
		$this->assertSame('on', config_get_path($path), 'before: pfb_keep seed is on');

		// When/After: read -> PfbLenient::On; write -> 'on'.
		$enum = PfbConfig::read('pfb_keep');
		$this->assertSame(PfbLenient::On, $enum, "read: pfb_keep 'on' -> PfbLenient::On");

		PfbConfig::write('pfb_keep', $enum);
		$this->assertSame('on', config_get_path($path), "write(read('on'))==on for pfb_keep");
	}

	public function testPfbKeepLenientRoundTripOff(): void
	{
		$path = 'installedpackages/pfblockerng/config/0/pfb_keep';

		// Given: canonical 'off' (the new stored value for unchecked-save after #484 fix).
		$this->seedConfig($path, 'off');

		// Before: raw 'off'.
		$this->assertSame('off', config_get_path($path), 'before: pfb_keep seed is off');

		// When/After: read -> PfbLenient::Off; write -> 'off'.
		$enum = PfbConfig::read('pfb_keep');
		$this->assertSame(PfbLenient::Off, $enum, "read: pfb_keep 'off' -> PfbLenient::Off");

		PfbConfig::write('pfb_keep', $enum);
		$this->assertSame('off', config_get_path($path), "write(read('off'))==off for pfb_keep");
	}

	public function testPfbKeepLenientLegacyEmptyNormalisesToOff(): void
	{
		$path = 'installedpackages/pfblockerng/config/0/pfb_keep';

		// Given: '' (pre-#484 install — toggle OFF value written by old GUI).
		$this->seedConfig($path, '');

		// Before: raw ''.
		$this->assertSame('', config_get_path($path), 'before: pfb_keep seed is empty string');

		// When: read maps '' to PfbLenient::Off (legacy token, same as 'off').
		$enum = PfbConfig::read('pfb_keep');
		$this->assertSame(PfbLenient::Off, $enum, "read: pfb_keep '' -> PfbLenient::Off (legacy)");

		// After: write emits 'off' (not ''); normalises the legacy token.
		PfbConfig::write('pfb_keep', $enum);
		$this->assertSame('off', config_get_path($path), "write(read(''))==off for pfb_keep");
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

	/**
	 * ADR-49: pfb_feed_sanity absent key returns Off — proves the scan is
	 * unreachable (never consulted) on an existing install that predates the
	 * feature, exactly like a brand-new install (no grandfather seed needed).
	 *
	 * Scenario:
	 *   Background: config[.../pfb_feed_sanity] is unset (feature is new).
	 *     Given no seed.
	 *     When PfbConfig::read('pfb_feed_sanity').
	 *     Then PfbToggle::Off is returned (default '').
	 */
	public function testReadReturnsRegisteredDefaultForPfbFeedSanityAbsentKey(): void
	{
		// Before: key absent.
		$this->assertNull(config_get_path('installedpackages/pfblockerng/config/0/pfb_feed_sanity'));

		// When/Then: returns Off (default '').
		$result = PfbConfig::read('pfb_feed_sanity');
		$this->assertSame(PfbToggle::Off, $result, 'pfb_feed_sanity absent -> Off (default)');
	}

	public function testReadReturnsRegisteredDefaultForPfbKeepAbsentKey(): void
	{
		// pfb_keep default is 'on' (On enum) — the #281 canonical default.
		// Uses the lenient adapter so absent key → PfbLenient::On (not PfbToggle::On).
		// Before: key absent.
		$this->assertNull(config_get_path('installedpackages/pfblockerng/config/0/pfb_keep'));

		// When: read with no seed.
		$result = PfbConfig::read('pfb_keep');

		// Then: returns On (the registered default 'on', applied through lenient adapter).
		$this->assertSame(PfbLenient::On, $result, 'pfb_keep absent -> PfbLenient::On (default on)');
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
		// alexa_type default is 'tranco' -> PfbTop1mSource::Tranco.
		$this->assertNull(
			config_get_path('installedpackages/pfblockerngdnsblsettings/config/0/alexa_type')
		);

		$result = PfbConfig::read('alexa_type');
		$this->assertInstanceOf(PfbTop1mSource::class, $result, 'alexa_type must return a PfbTop1mSource enum');
		$this->assertSame(PfbTop1mSource::Tranco, $result);
	}

	/**
	 * alexa_type (issue #877): a stored legacy 'alexa' (dead TOP1M source, #872)
	 * coalesces to PfbTop1mSource::Tranco through the gateway's read adapter.
	 *
	 * Scenario: the dropped Alexa TOP1M option still reads safely on an existing
	 * install that had it selected.
	 *   Given alexa_type stored as the legacy 'alexa' token.
	 *   When PfbConfig::read('alexa_type').
	 *   Then the result is PfbTop1mSource::Tranco, not the dead 'alexa' token.
	 */
	public function testReadCoalescesLegacyAlexaTypeToTranco(): void
	{
		$path = 'installedpackages/pfblockerngdnsblsettings/config/0/alexa_type';

		// Given: legacy 'alexa' stored.
		$this->seedConfig($path, 'alexa');
		$this->assertSame('alexa', config_get_path($path), 'before: alexa_type seed is legacy alexa');

		// When/Then: coalesced to PfbTop1mSource::Tranco.
		$this->assertSame(PfbTop1mSource::Tranco, PfbConfig::read('alexa_type'), "legacy 'alexa' coalesces to Tranco");
	}

	/**
	 * alexa_type (issue #928): a stored legacy 'domcop' token (the DomCop TOP1M list's
	 * hosting moved to OpenPageRank) coalesces to PfbTop1mSource::OpenPageRank through
	 * the gateway's read adapter -- same shape as the 'alexa' legacy coalesce above.
	 *
	 * Scenario: an existing install with DomCop selected still reads safely.
	 *   Given alexa_type stored as the legacy 'domcop' token.
	 *   When PfbConfig::read('alexa_type').
	 *   Then the result is PfbTop1mSource::OpenPageRank, not the dead 'domcop' token.
	 */
	public function testReadCoalescesLegacyDomCopTypeToOpenPageRank(): void
	{
		$path = 'installedpackages/pfblockerngdnsblsettings/config/0/alexa_type';

		// Given: legacy 'domcop' stored.
		$this->seedConfig($path, 'domcop');
		$this->assertSame('domcop', config_get_path($path), 'before: alexa_type seed is legacy domcop');

		// When/Then: coalesced to PfbTop1mSource::OpenPageRank.
		$this->assertSame(
			PfbTop1mSource::OpenPageRank,
			PfbConfig::read('alexa_type'),
			"legacy 'domcop' coalesces to OpenPageRank"
		);
	}

	/**
	 * alexa_type: all five live tokens pass through as their enum cases (openpagerank/majestic
	 * added ADR-59 P4, cloudflare added ADR-59 P5).
	 */
	public function testReadPassesThroughLivePfbTop1mSourceTokens(): void
	{
		$path = 'installedpackages/pfblockerngdnsblsettings/config/0/alexa_type';

		$this->seedConfig($path, 'cisco');
		$this->assertSame(PfbTop1mSource::Cisco, PfbConfig::read('alexa_type'), "'cisco' passes through as Cisco");

		$this->seedConfig($path, 'tranco');
		$this->assertSame(PfbTop1mSource::Tranco, PfbConfig::read('alexa_type'), "'tranco' passes through as Tranco");

		$this->seedConfig($path, 'openpagerank');
		$this->assertSame(PfbTop1mSource::OpenPageRank, PfbConfig::read('alexa_type'), "'openpagerank' passes through as OpenPageRank");

		$this->seedConfig($path, 'majestic');
		$this->assertSame(PfbTop1mSource::Majestic, PfbConfig::read('alexa_type'), "'majestic' passes through as Majestic");

		$this->seedConfig($path, 'cloudflare');
		$this->assertSame(PfbTop1mSource::Cloudflare, PfbConfig::read('alexa_type'), "'cloudflare' passes through as Cloudflare");
	}

	/**
	 * top1m_token (ADR-59 P5): a masked, write-only plain-string field (no adapter) --
	 * absent reads as the registered default '', and any stored token round-trips
	 * (write(read(v)) == v) like every other plain field.
	 *
	 * Scenario: top1m_token default-absent + round-trip.
	 *   Given the key is absent from config.xml.
	 *   When PfbConfig::read('top1m_token').
	 *   Then the result is '' (the registered default).
	 *   And when a real-looking token is written then read back, it comes back verbatim.
	 */
	public function testTop1mTokenDefaultsToEmptyAndRoundTrips(): void
	{
		$path = 'installedpackages/pfblockerngdnsblsettings/config/0/top1m_token';

		// Given/When: absent key.
		$this->assertNull(config_get_path($path));
		$this->assertSame('', PfbConfig::read('top1m_token'), 'top1m_token absent -> default ""');

		// Round-trip: write(read(v)) == v for a real-looking base64url/JWT-charset token.
		$token = 'cf-abc123._~+/=-XYZ';
		PfbConfig::write('top1m_token', $token);
		$this->assertSame($token, config_get_path($path), 'top1m_token write() must store the token verbatim');
		$this->assertSame($token, PfbConfig::read('top1m_token'), 'top1m_token read() must return the stored token verbatim');
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

	public function testReadReturnsRejectDefaultForDotBlockActionAbsentKey(): void
	{
		// dnsbl_dot_block_action default is 'reject' (ADR-37): an existing install
		// upgrading with the key absent reads to Reject, the corrected outbound default.
		$this->assertNull(
			config_get_path('installedpackages/pfblockerngdnsblsettings/config/0/dnsbl_dot_block_action')
		);

		$result = PfbConfig::read('dnsbl_dot_block_action');
		$this->assertSame('reject', $result, 'dnsbl_dot_block_action absent -> reject (default)');
	}

	public function testReadReturnsOffDefaultForDotBlockFloatingAbsentKey(): void
	{
		// dnsbl_dot_block_floating default is '' -> PfbToggle::Off (ADR-37): absent key
		// preserves the per-interface default; floating is strictly opt-in.
		$this->assertNull(
			config_get_path('installedpackages/pfblockerngdnsblsettings/config/0/dnsbl_dot_block_floating')
		);

		$result = PfbConfig::read('dnsbl_dot_block_floating');
		$this->assertSame(PfbToggle::Off, $result, 'dnsbl_dot_block_floating absent -> Off (per-interface default)');
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
	// ADR-53 — v4suppression (plain base64 blob; IPv4 suppression customlist)
	// -----------------------------------------------------------------------

	/**
	 * v4suppression absent key returns the registered default '' (empty customlist).
	 *
	 * Scenario:
	 *   Background: v4suppression is a plain base64-blob field; default = '' --
	 *     mirrors the DNSBL 'suppression' sibling shape.
	 *     Given no stored value.
	 *     When PfbConfig::read('v4suppression').
	 *     Then '' is returned (registered default).
	 *
	 * Red->green: before this phase, 'v4suppression' was not registered ->
	 *   PfbConfig::read('v4suppression') threw InvalidArgumentException.
	 */
	public function testV4SuppressionAbsentKeyReturnsDefaultEmptyString(): void
	{
		$path = 'installedpackages/pfblockerngipsettings/config/0/v4suppression';

		// Before: absent.
		$this->assertNull(config_get_path($path), 'before: v4suppression must be absent');

		// When/Then.
		$this->assertSame('', PfbConfig::read('v4suppression'), 'v4suppression absent -> ""');
	}

	/**
	 * v4suppression round-trips a base64 blob losslessly (write(read(v)) == v).
	 *
	 * Scenario:
	 *   Background: v4suppression stores a base64-encoded CIDR/host customlist.
	 *     Given stored = base64_encode("192.168.1.1/32\r\n").
	 *     When PfbConfig::write('v4suppression', PfbConfig::read('v4suppression')).
	 *     Then the stored string is unchanged (byte-identical round-trip).
	 */
	public function testV4SuppressionRoundTrips(): void
	{
		$path = 'installedpackages/pfblockerngipsettings/config/0/v4suppression';
		$blob = base64_encode("192.168.1.1/32\r\n");

		// Given: seed the blob.
		$this->seedConfig($path, $blob);

		// Before: raw stored value is the blob.
		$this->assertSame($blob, config_get_path($path), 'before: v4suppression seed matches blob');

		// When: read -> write.
		$val = PfbConfig::read('v4suppression');
		$this->assertSame($blob, $val, 'read: v4suppression round-trips the blob unchanged');

		// After: write back produces the identical stored string.
		PfbConfig::write('v4suppression', $val);
		$this->assertSame($blob, config_get_path($path), 'write(read(blob))==blob for v4suppression');
	}

	// -----------------------------------------------------------------------
	// ADR-53 P6 — v6suppression (plain base64 blob; IPv6 suppression customlist)
	// -----------------------------------------------------------------------

	/**
	 * v6suppression absent key returns the registered default '' (empty customlist).
	 *
	 * Scenario:
	 *   Background: v6suppression is a plain base64-blob field; default = '' --
	 *     mirrors the v4suppression sibling shape (this section, above).
	 *     Given no stored value.
	 *     When PfbConfig::read('v6suppression').
	 *     Then '' is returned (registered default).
	 *
	 * Red->green: before Phase 6, 'v6suppression' was not registered at all ->
	 *   PfbConfig::read('v6suppression') threw InvalidArgumentException.
	 */
	public function testV6SuppressionAbsentKeyReturnsDefaultEmptyString(): void
	{
		$path = 'installedpackages/pfblockerngipsettings/config/0/v6suppression';

		// Before: absent.
		$this->assertNull(config_get_path($path), 'before: v6suppression must be absent');

		// When/Then.
		$this->assertSame('', PfbConfig::read('v6suppression'), 'v6suppression absent -> ""');
	}

	/**
	 * v6suppression round-trips a base64 blob losslessly (write(read(v)) == v).
	 *
	 * Scenario:
	 *   Background: v6suppression stores a base64-encoded CIDR customlist.
	 *     Given stored = base64_encode("2001:db8::1/128\r\n").
	 *     When PfbConfig::write('v6suppression', PfbConfig::read('v6suppression')).
	 *     Then the stored string is unchanged (byte-identical round-trip).
	 */
	public function testV6SuppressionRoundTrips(): void
	{
		$path = 'installedpackages/pfblockerngipsettings/config/0/v6suppression';
		$blob = base64_encode("2001:db8::1/128\r\n");

		// Given: seed the blob.
		$this->seedConfig($path, $blob);

		// Before: raw stored value is the blob.
		$this->assertSame($blob, config_get_path($path), 'before: v6suppression seed matches blob');

		// When: read -> write.
		$val = PfbConfig::read('v6suppression');
		$this->assertSame($blob, $val, 'read: v6suppression round-trips the blob unchanged');

		// After: write back produces the identical stored string.
		PfbConfig::write('v6suppression', $val);
		$this->assertSame($blob, config_get_path($path), 'write(read(blob))==blob for v6suppression');
	}

	// -----------------------------------------------------------------------
	// ADR-43 — pfb_tick_interval (plain string; tick-cron dispatch interval)
	// -----------------------------------------------------------------------

	/**
	 * pfb_tick_interval absent key returns the registered default '15'.
	 *
	 * Scenario:
	 *   Background: pfb_tick_interval is a plain-string field; default = '15'.
	 *     Given no stored value.
	 *     When PfbConfig::read('pfb_tick_interval').
	 *     Then '15' is returned (registered default).
	 */
	public function testPfbTickIntervalAbsentKeyReturnsDefault(): void
	{
		$path = 'installedpackages/pfblockerng/config/0/pfb_tick_interval';

		// Before: absent.
		$this->assertNull(config_get_path($path), 'before: pfb_tick_interval must be absent');

		// When/Then: absent → default '15'.
		$result = PfbConfig::read('pfb_tick_interval');
		$this->assertSame('15', $result, 'pfb_tick_interval absent -> default 15');
	}

	/**
	 * pfb_tick_interval round-trips losslessly for a non-default value.
	 *
	 * Scenario:
	 *   Background: pfb_tick_interval is a plain-string field.
	 *     Given stored = '30'.
	 *     When PfbConfig::write('pfb_tick_interval', PfbConfig::read('pfb_tick_interval')).
	 *     Then stored string == '30' (write(read('30')) == '30').
	 */
	public function testPfbTickIntervalRoundTrip(): void
	{
		$path = 'installedpackages/pfblockerng/config/0/pfb_tick_interval';

		// Given: '30' stored.
		$this->seedConfig($path, '30');

		// Before: raw value is '30'.
		$this->assertSame('30', config_get_path($path), "before: pfb_tick_interval seed is '30'");

		// When: read -> write.
		$val = PfbConfig::read('pfb_tick_interval');
		$this->assertSame('30', $val, "read: pfb_tick_interval '30' -> '30'");

		// After: write back produces '30'.
		PfbConfig::write('pfb_tick_interval', $val);
		$this->assertSame('30', config_get_path($path), "write(read('30'))=='30' for pfb_tick_interval");
	}

	// -----------------------------------------------------------------------
	// ADR-43 P5 — pfb_quiet_hours (plain string; apply-on-change window)
	// -----------------------------------------------------------------------

	/**
	 * pfb_quiet_hours absent key returns the registered default '' (no window).
	 *
	 * Scenario:
	 *   Background: pfb_quiet_hours is a plain-string field; default = '' (apply immediately).
	 *     Given no stored value.
	 *     When PfbConfig::read('pfb_quiet_hours').
	 *     Then '' is returned (registered default = no window, apply immediately).
	 *
	 * Red→green: before Phase 5, 'pfb_quiet_hours' was not registered →
	 *   PfbConfig::read('pfb_quiet_hours') threw InvalidArgumentException.
	 */
	public function testPfbQuietHoursAbsentKeyReturnsDefault(): void
	{
		$path = 'installedpackages/pfblockerng/config/0/pfb_quiet_hours';

		// Before: absent.
		$this->assertNull(config_get_path($path), 'before: pfb_quiet_hours must be absent');

		// When/Then: absent → default '' (no window).
		$result = PfbConfig::read('pfb_quiet_hours');
		$this->assertSame('', $result, 'pfb_quiet_hours absent -> default empty string');
	}

	/**
	 * pfb_quiet_hours round-trips a non-default window string.
	 *
	 * Scenario:
	 *   Background: pfb_quiet_hours is a plain-string field (no adapter).
	 *     Given stored = '02:00-06:00'.
	 *     When PfbConfig::write('pfb_quiet_hours', PfbConfig::read('pfb_quiet_hours')).
	 *     Then stored string == '02:00-06:00' (lossless round-trip).
	 *
	 * Red→green: before Phase 5, read/write threw InvalidArgumentException.
	 */
	public function testPfbQuietHoursRoundTrip(): void
	{
		$path = 'installedpackages/pfblockerng/config/0/pfb_quiet_hours';

		// Given: '02:00-06:00' stored.
		$this->seedConfig($path, '02:00-06:00');

		// Before: raw value is '02:00-06:00'.
		$this->assertSame('02:00-06:00', config_get_path($path),
			"before: pfb_quiet_hours seed is '02:00-06:00'");

		// When: read -> write.
		$val = PfbConfig::read('pfb_quiet_hours');
		$this->assertSame('02:00-06:00', $val,
			"read: pfb_quiet_hours '02:00-06:00' -> '02:00-06:00'");

		// After: write back produces '02:00-06:00'.
		PfbConfig::write('pfb_quiet_hours', $val);
		$this->assertSame('02:00-06:00', config_get_path($path),
			"write(read('02:00-06:00'))=='02:00-06:00' for pfb_quiet_hours");
	}

	// -----------------------------------------------------------------------
	// issue #1109 — pfb_log_trim_margin_pct (global hysteresis margin percent)
	// -----------------------------------------------------------------------

	/**
	 * pfb_log_trim_margin_pct absent key returns the registered default '0'
	 * (no hysteresis -- today's exact-cap trim behaviour).
	 *
	 * Scenario:
	 *   Background: pfb_log_trim_margin_pct is a plain-string field; default = '0'.
	 *     Given no stored value.
	 *     When PfbConfig::read('pfb_log_trim_margin_pct').
	 *     Then '0' is returned.
	 */
	public function testPfbLogTrimMarginPctAbsentKeyReturnsDefaultZero(): void
	{
		$path = 'installedpackages/pfblockerng/config/0/pfb_log_trim_margin_pct';

		// Before: absent.
		$this->assertNull(config_get_path($path), 'before: pfb_log_trim_margin_pct must be absent');

		// When/Then: absent -> default '0'.
		$result = PfbConfig::read('pfb_log_trim_margin_pct');
		$this->assertSame('0', $result, 'pfb_log_trim_margin_pct absent -> default 0');
	}

	/**
	 * pfb_log_trim_margin_pct round-trips losslessly for a non-default value.
	 *
	 * Scenario:
	 *   Background: pfb_log_trim_margin_pct is a plain-string field (no adapter).
	 *     Given stored = '50'.
	 *     When PfbConfig::write('pfb_log_trim_margin_pct', PfbConfig::read('pfb_log_trim_margin_pct')).
	 *     Then stored string == '50' (write(read('50')) == '50').
	 */
	public function testPfbLogTrimMarginPctRoundTrip(): void
	{
		$path = 'installedpackages/pfblockerng/config/0/pfb_log_trim_margin_pct';

		// Given: '50' stored.
		$this->seedConfig($path, '50');

		// Before: raw value is '50'.
		$this->assertSame('50', config_get_path($path), "before: pfb_log_trim_margin_pct seed is '50'");

		// When: read -> write.
		$val = PfbConfig::read('pfb_log_trim_margin_pct');
		$this->assertSame('50', $val, "read: pfb_log_trim_margin_pct '50' -> '50'");

		// After: write back produces '50'.
		PfbConfig::write('pfb_log_trim_margin_pct', $val);
		$this->assertSame('50', config_get_path($path), "write(read('50'))=='50' for pfb_log_trim_margin_pct");
	}

	// ADR-38 — log_syslog (toggle; Amendment 1: facility/priority removed)
	// -----------------------------------------------------------------------

	/**
	 * log_syslog toggle field round-trips losslessly for 'on' (enabled).
	 *
	 * Scenario:
	 *   Background: log_syslog is a PfbToggle field; vocabulary = {'on', ''}.
	 *     Given stored = 'on'.
	 *     When PfbConfig::write('log_syslog', PfbConfig::read('log_syslog')).
	 *     Then stored string == 'on' (write(read('on')) == 'on').
	 */
	public function testLogSyslogRoundTripOn(): void
	{
		$path = 'installedpackages/pfblockerng/config/0/log_syslog';

		// Given: 'on' stored.
		$this->seedConfig($path, 'on');

		// Before: raw value is 'on'.
		$this->assertSame('on', config_get_path($path), "before: log_syslog seed is 'on'");

		// When: read -> write.
		$enum = PfbConfig::read('log_syslog');
		$this->assertSame(PfbToggle::On, $enum, "read: log_syslog 'on' -> PfbToggle::On");

		// After: write back produces 'on'.
		PfbConfig::write('log_syslog', $enum);
		$this->assertSame('on', config_get_path($path), "write(read('on'))==on for log_syslog");
	}

	/**
	 * log_syslog toggle field round-trips losslessly for '' (disabled).
	 *
	 * Scenario:
	 *   Background: log_syslog vocabulary = {'on', ''}.
	 *     Given stored = '' (unchecked / off).
	 *     When PfbConfig::write('log_syslog', PfbConfig::read('log_syslog')).
	 *     Then stored string == '' (write(read('')) == '').
	 */
	public function testLogSyslogRoundTripOff(): void
	{
		$path = 'installedpackages/pfblockerng/config/0/log_syslog';

		// Given: '' stored.
		$this->seedConfig($path, '');

		// Before: raw value is ''.
		$this->assertSame('', config_get_path($path), "before: log_syslog seed is ''");

		// When: read -> write.
		$enum = PfbConfig::read('log_syslog');
		$this->assertSame(PfbToggle::Off, $enum, "read: log_syslog '' -> PfbToggle::Off");

		// After: write back produces ''.
		PfbConfig::write('log_syslog', $enum);
		$this->assertSame('', config_get_path($path), "write(read(''))=='' for log_syslog");
	}

	/**
	 * log_syslog absent key returns PfbToggle::Off (default '' applied via toggle adapter).
	 *
	 * Scenario:
	 *   Background: log_syslog registered default is '' (off).
	 *     Given no stored value.
	 *     When PfbConfig::read('log_syslog').
	 *     Then PfbToggle::Off is returned (registered default '').
	 */
	public function testLogSyslogAbsentKeyReturnsOffDefault(): void
	{
		$path = 'installedpackages/pfblockerng/config/0/log_syslog';

		// Before: absent.
		$this->assertNull(config_get_path($path), 'before: log_syslog must be absent');

		// When/Then: default '' → PfbToggle::Off.
		$result = PfbConfig::read('log_syslog');
		$this->assertSame(PfbToggle::Off, $result, 'log_syslog absent -> Off (default)');
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
	 *     maxmind_key, etc. (suppression key in ipsettings is a distinct concept
	 *     from pfblockerngdnsblsettings/suppression which IS registered).
	 *     ADR-53: v4suppression + v6suppression are now registered (see the registered
	 *     inventory below) -- they are the two ipsettings scalars NOT on this
	 *     out-of-scope list.
	 *   - pfblockerngreputation sub-keys: et_header
	 *   - pfblockerngsync sub-keys: syncinterfaces, varsynconchanges, row/*
	 *   - pfblockerngblacklist sub-keys: blacklist_enable, blacklist_freq,
	 *     blacklist_lang, blacklist_logging, blacklist_selected, item
	 *   - pfblockerngdnsblsettings foreign key: dnsbl_webpage (written directly by
	 *     www/pfblockerng_dnsbl.php, read via pfb_dnsbl_webpage(); issue #713 removed
	 *     the never-written 'dnsblwebpage' registry mis-spelling)
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
			// (v4suppression is registered -- ADR-53 -- and lives in the registry, not here.)
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

			// pfblockerngdnsblsettings foreign key: written directly by
			// www/pfblockerng_dnsbl.php and read via pfb_dnsbl_webpage() (issue #713
			// removed the never-written 'dnsblwebpage' registry mis-spelling).
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
			'log_max_ip_parse_err',
			'log_max_dnslog',
			'log_max_dnsbl_parse_err',
			'log_max_dnsreplylog',
			'log_max_unilog',
			// ADR-60: per-log age-based retention cap (days; '0' = off)
			'log_max_days_log',
			'log_max_days_errlog',
			'log_max_days_extraslog',
			'log_max_days_ip_blocklog',
			'log_max_days_ip_permitlog',
			'log_max_days_ip_matchlog',
			'log_max_days_ip_parse_err',
			'log_max_days_dnslog',
			'log_max_days_dnsbl_parse_err',
			'log_max_days_dnsreplylog',
			'log_max_days_unilog',
			'pfb_software_check',
			'pfb_feed_internal_filter',
			'pfb_feed_internal_allowlist',
			// ADR-49: opt-in plain-text feed sanity scan toggle
			'pfb_feed_sanity',
			'pfb_reuse',
			// ADR-40: alias-table apply mode + batch size
			'pfb_alias_delta_mode',
			'pfb_alias_delta_batch',
			// ADR-43: tick-cron dispatch interval + apply-on-change window
			'pfb_tick_interval',
			'pfb_quiet_hours',
			// issue #1109: log-retention trim hysteresis margin percent
			'pfb_log_trim_margin_pct',
			// ADR-38: syslog export toggle
			'log_syslog',

			// pfblockerngdnsblsettings/config/0 scalars
			'pfb_dnsbl',
			'pfb_dnsvip_auto',
			'pfb_dnsbl_nonat',
			'dnsbl_interface',
			'pfb_dnsvip4',
			'pfb_dnsvip6',
			'pfb_dnsport',
			'pfb_dnsport_ssl',
			'alexa_enable',
			'alexa_type',
			'alexa_count',
			'alexa_inclusion',
			'top1m_token', // ADR-59 P5
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
			// ADR-36: NAT DNS-redirect fields
			'dnsbl_redir',
			'dnsbl_redir_int',
			'dnsbl_redir_exclude',
			// ADR-37: DoT/DoQ block fields
			'dnsbl_dot_block',
			'dnsbl_dot_block_int',
			'dnsbl_dot_block_exclude',
			'dnsbl_dot_block_action',
			'dnsbl_dot_block_floating',

			// pfblockerngsafesearch scalars
			'safesearch_enable',
			'safesearch_youtube',
			'safesearch_doh',
			'safesearch_doh_list',

			// pfblockerngipsettings/config/0 scalars (ADR-53)
			'v4suppression',
			'v6suppression',

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

	public function testWriteToggleFieldAcceptsLegacyStringValue(): void
	{
		// Regression: pfblockerng_update.php Force Reload calls
		// PfbConfig::write('pfb_reuse', 'on') with a raw string. The toggle
		// write adapter must accept it (enum-or-string contract) and store
		// the exact legacy token — previously a TypeError.
		$path = 'installedpackages/pfblockerng/config/0/pfb_reuse';

		// Before: absent.
		$this->assertNull(config_get_path($path));

		// When: write the raw legacy string (not the enum).
		PfbConfig::write('pfb_reuse', 'on');

		// After: stored as the string 'on'.
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
	// D (extra) — pfb_idn PfbIdnMode adapter adoption is documented and enforced
	// -----------------------------------------------------------------------

	/**
	 * pfb_idn is now adapted via PfbIdnMode: read returns an enum, write persists
	 * the canonical stored token.
	 *
	 * ADR-28 reframe: PfbIdnMode::All backing value is 'on' — the original
	 * pre-ADR-08 block-all token.  This reuse means 'on' round-trips losslessly
	 * AND old releases reading 'on' still block all IDN (downgrade-safe).
	 *
	 * Scenario:
	 *   Background: pfb_idn stored as 'on' (canonical, = All).
	 *     Given pfb_idn = 'on'.
	 *     When PfbConfig::read('pfb_idn').
	 *     Then PfbIdnMode::All is returned (adapter is wired).
	 *     And write(read('on')) stores 'on' (canonical identity — the backing value).
	 */
	public function testIdnFieldAdaptedReturnsEnumForCanonicalOn(): void
	{
		$path = 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_idn';

		// Given: canonical 'on' stored (= block-all-IDN).
		$this->seedConfig($path, 'on');

		// Before: raw 'on'.
		$this->assertSame('on', config_get_path($path));

		// When: read.
		$result = PfbConfig::read('pfb_idn');

		// Then: PfbIdnMode::All (adapter IS wired — NOT raw string).
		$this->assertInstanceOf(PfbIdnMode::class, $result, 'pfb_idn must return a PfbIdnMode enum');
		$this->assertSame(PfbIdnMode::All, $result, "pfb_idn 'on' -> PfbIdnMode::All");

		// And: write(read('on')) stores 'on' — canonical identity.
		PfbConfig::write('pfb_idn', $result);
		$this->assertSame('on', config_get_path($path), "write(read('on')) == 'on' for pfb_idn");
	}

	public function testIdnFieldAdaptedDroppedAlphaAllNormalisesToOff(): void
	{
		$path = 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_idn';

		// Given: the 4.0.0-alpha-only token 'all' (alpha compatibility intentionally dropped).
		$this->seedConfig($path, 'all');

		// Before: raw 'all'.
		$this->assertSame('all', config_get_path($path));

		// When/Then: 'all' is unrecognised -> PfbIdnMode::Off (canonical block-all is 'on').
		$result = PfbConfig::read('pfb_idn');
		$this->assertInstanceOf(PfbIdnMode::class, $result, 'pfb_idn must return a PfbIdnMode enum');
		$this->assertSame(PfbIdnMode::Off, $result, "pfb_idn 'all' (dropped alpha token) -> PfbIdnMode::Off");

		// Write emits the canonical 'off' — 'all' is not re-emitted.
		PfbConfig::write('pfb_idn', $result);
		$stored = config_get_path($path);
		$this->assertSame('off', $stored, "write(read('all')) == 'off' for pfb_idn");
		$this->assertNotSame('all', $stored, "'all' must not be re-emitted");
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
	 * No registered field may be a TOGGLE adapter (off-value '') while defaulting
	 * to 'on'. Such a field cannot represent "off" on a live pfSense config: an
	 * empty stored value does not persist distinguishably from absent, and an
	 * absent value re-applies the registry default 'on' — silently flipping a
	 * deliberate "off" back to "on". (This is the pfb_keep bug: #484 fan-out.)
	 *
	 * A default-'on' field MUST therefore use the LENIENT adapter (off persists as
	 * the explicit 'off' token) or a PLAIN field that writes an explicit 'on'/'off'
	 * (as pfb_feed_internal_filter does). This guard makes the rule mechanical so
	 * the class of bug cannot recur — the off-box config doubles round-trip ''
	 * faithfully and would otherwise never catch it.
	 */
	public function testNoToggleFieldDefaultsToOn(): void
	{
		$toggle_count = 0;
		foreach (pfb_cfg_registry() as $field_key => $entry) {
			if ($entry['read_adapter'] === 'pfb_cfg_toggle_read') {
				$toggle_count++;
				$this->assertNotSame(
					'on', $entry['default'],
					"'{$field_key}': a TOGGLE field must not default to 'on' — its '' off-value "
					. "cannot survive the live config round-trip (becomes absent -> default 'on'). "
					. "Use the lenient adapter (explicit 'off') or a plain explicit-on/off field."
				);
			}
		}
		// Anchor against a vacuous pass: if no toggle field exists the loop above
		// asserts nothing, so this guard would silently stop guarding.
		$this->assertGreaterThan(0, $toggle_count,
			'Registry must contain at least one toggle-adapter field for this guard to be meaningful'
		);
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
	// ADR-60 — log_max_days_<type> field round-trip, default-absent, inventory
	// -----------------------------------------------------------------------

	/**
	 * All 11 log_max_days_<type> fields are registered.
	 *
	 * Scenario:
	 *   Background: ADR-60 adds one log_max_days_<type> key per log type.
	 *     Given pfb_cfg_registry().
	 *     When checking for each expected key.
	 *     Then all 11 are present.
	 */
	public function testLogMaxDaysFieldsAreRegistered(): void
	{
		$registry  = pfb_cfg_registry();
		$log_types = pfb_test_log_types();
		$this->assertNotEmpty($log_types, 'pfb_test_log_types() must not be empty');

		foreach ($log_types as $type) {
			$key = 'log_max_days_' . $type;
			$this->assertArrayHasKey($key, $registry,
				"log_max_days_{$type} must be in the registry"
			);
		}
	}

	/**
	 * Pin pfb_test_log_types() to the known 11-item vocabulary so a broken
	 * derivation (e.g. an empty/partial result) fails loudly here instead of
	 * silently under-testing every consumer via a vacuous foreach.
	 */
	public function testLogTypesFixtureMatchesCanonicalVocabulary(): void
	{
		$expected = [
			'log', 'errlog', 'extraslog', 'ip_blocklog', 'ip_permitlog',
			'ip_matchlog', 'ip_parse_err', 'dnslog', 'dnsbl_parse_err', 'dnsreplylog', 'unilog',
		];
		$this->assertSame($expected, pfb_test_log_types(),
			'pfb_test_log_types() must match the canonical 11 log types exactly'
		);
	}

	/**
	 * Data provider — all 11 log_max_days_<type> keys × canonical numeric tokens.
	 *
	 * @return array<string, array{string, string}>
	 */
	public static function logMaxDaysVocabularyProvider(): array
	{
		$log_types = pfb_test_log_types();
		$vocab  = ['0', '30', '365'];
		$cases  = [];
		foreach ($log_types as $type) {
			foreach ($vocab as $token) {
				$cases["log_max_days_{$type}/{$token}"] = ["log_max_days_{$type}", $token];
			}
		}
		return $cases;
	}

	/**
	 * log_max_days_<type>: write(read(v)) == v for every vocabulary token.
	 *
	 * Scenario:
	 *   Background: log_max_days_<type> fields use identity (null/null) adapter.
	 *     Given a vocabulary token v ∈ {'0','30','365'}.
	 *     When PfbConfig::read($key) then PfbConfig::write($key, result).
	 *     Then write(read(v)) == v (round-trip identity).
	 */
	#[DataProvider('logMaxDaysVocabularyProvider')]
	public function testLogMaxDaysFieldRoundTripForAllVocabularyTokens(
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
	 * log_max_days_<type>: absent key returns default '0' (off).
	 *
	 * Scenario:
	 *   Background: key entirely absent from config.xml.
	 *     Given no value seeded.
	 *     When PfbConfig::read($key).
	 *     Then '0' is returned (registered default; age cap off).
	 */
	public function testLogMaxDaysFieldAbsentKeyReturnsDefaultZero(): void
	{
		$log_types = pfb_test_log_types();
		$this->assertNotEmpty($log_types, 'pfb_test_log_types() must not be empty');

		foreach ($log_types as $type) {
			$key  = 'log_max_days_' . $type;
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

	/**
	 * issue #1004: log_max_ip_parse_err (line-count cap) is registered with the
	 * same '20000' default every other log_max_<type> field uses.
	 *
	 * Scenario:
	 *   Background: key entirely absent from config.xml.
	 *     Given no value seeded.
	 *     When PfbConfig::read('log_max_ip_parse_err').
	 *     Then '20000' is returned (registered default; matches every sibling log_max_<type>).
	 */
	public function testLogMaxIpParseErrAbsentKeyReturnsDefault20000(): void
	{
		$path = 'installedpackages/pfblockerng/config/0/log_max_ip_parse_err';

		// Before: absent.
		$this->assertNull(config_get_path($path), 'before: log_max_ip_parse_err must be absent');

		// When/Then: default '20000' returned.
		$this->assertSame('20000', PfbConfig::read('log_max_ip_parse_err'),
			'log_max_ip_parse_err absent must return \'20000\' (registered default)'
		);
	}

	// -----------------------------------------------------------------------
	// ADR-36 — dnsbl_redir / dnsbl_redir_int / dnsbl_redir_exclude
	// -----------------------------------------------------------------------

	/**
	 * dnsbl_redir (toggle): 'on' and '' both round-trip losslessly.
	 *
	 * Scenario:
	 *   Background: dnsbl_redir stored as 'on' (enabled) or '' (disabled).
	 *     Given canonical stored value v in {'on', ''}.
	 *     When PfbConfig::write('dnsbl_redir', PfbConfig::read('dnsbl_redir')).
	 *     Then stored string equals v (write(read(v)) == v).
	 */
	public function testDnsblRedirToggleRoundTripOn(): void
	{
		$path = 'installedpackages/pfblockerngdnsblsettings/config/0/dnsbl_redir';

		// Given: canonical 'on'.
		$this->seedConfig($path, 'on');

		// Before: raw 'on'.
		$this->assertSame('on', config_get_path($path),
			'before: dnsbl_redir seed must be on'
		);

		// When: read -> write.
		$enum = PfbConfig::read('dnsbl_redir');
		$this->assertSame(PfbToggle::On, $enum, 'read: on -> PfbToggle::On');

		PfbConfig::write('dnsbl_redir', $enum);

		// After: stored as 'on'.
		$this->assertSame('on', config_get_path($path),
			'write(read(on)) == on for dnsbl_redir'
		);
	}

	public function testDnsblRedirToggleRoundTripOff(): void
	{
		$path = 'installedpackages/pfblockerngdnsblsettings/config/0/dnsbl_redir';

		// Given: canonical '' (checkbox unchecked).
		$this->seedConfig($path, '');

		// Before: raw ''.
		$this->assertSame('', config_get_path($path),
			"before: dnsbl_redir seed must be ''"
		);

		// When: read -> write.
		$enum = PfbConfig::read('dnsbl_redir');
		$this->assertSame(PfbToggle::Off, $enum, "read: '' -> PfbToggle::Off");

		PfbConfig::write('dnsbl_redir', $enum);

		// After: stored as ''.
		$this->assertSame('', config_get_path($path),
			"write(read('')) == '' for dnsbl_redir"
		);
	}

	/**
	 * dnsbl_redir absent key returns the registered default '' (Off).
	 *
	 * Scenario:
	 *   Background: key absent from config.
	 *     Given no seed.
	 *     When PfbConfig::read('dnsbl_redir').
	 *     Then PfbToggle::Off is returned (default '').
	 */
	public function testDnsblRedirAbsentKeyReturnsOff(): void
	{
		$path = 'installedpackages/pfblockerngdnsblsettings/config/0/dnsbl_redir';

		// Before: absent.
		$this->assertNull(config_get_path($path),
			'before: dnsbl_redir must be absent'
		);

		// When/Then.
		$result = PfbConfig::read('dnsbl_redir');
		$this->assertSame(PfbToggle::Off, $result,
			"dnsbl_redir absent -> PfbToggle::Off (default '')"
		);
	}

	/**
	 * dnsbl_redir_int (plain): arbitrary strings round-trip as identity.
	 *
	 * Scenario:
	 *   Background: plain adapter — any stored string passes through unchanged.
	 *     Given stored value v.
	 *     When PfbConfig::write('dnsbl_redir_int', PfbConfig::read('dnsbl_redir_int')).
	 *     Then stored string equals v (write(read(v)) == v).
	 */
	public function testDnsblRedirIntPlainRoundTripNonEmpty(): void
	{
		$path = 'installedpackages/pfblockerngdnsblsettings/config/0/dnsbl_redir_int';

		// Given: comma-joined interface names.
		$this->seedConfig($path, 'lan,opt1');

		// Before.
		$this->assertSame('lan,opt1', config_get_path($path),
			'before: dnsbl_redir_int seed must be lan,opt1'
		);

		// When.
		$value = PfbConfig::read('dnsbl_redir_int');
		$this->assertSame('lan,opt1', $value,
			'read: plain adapter returns raw stored string'
		);

		PfbConfig::write('dnsbl_redir_int', $value);

		// After.
		$this->assertSame('lan,opt1', config_get_path($path),
			'write(read(lan,opt1)) == lan,opt1 for dnsbl_redir_int'
		);
	}

	public function testDnsblRedirIntPlainRoundTripEmpty(): void
	{
		$path = 'installedpackages/pfblockerngdnsblsettings/config/0/dnsbl_redir_int';

		// Given: '' (no interfaces selected).
		$this->seedConfig($path, '');

		// Before.
		$this->assertSame('', config_get_path($path),
			"before: dnsbl_redir_int seed must be ''"
		);

		// When.
		$value = PfbConfig::read('dnsbl_redir_int');
		$this->assertSame('', $value, "read: '' returns ''");

		PfbConfig::write('dnsbl_redir_int', $value);

		// After.
		$this->assertSame('', config_get_path($path),
			"write(read('')) == '' for dnsbl_redir_int"
		);
	}

	/**
	 * dnsbl_redir_int absent key returns the registered default ''.
	 *
	 * Scenario:
	 *   Background: key absent from config.
	 *     Given no seed.
	 *     When PfbConfig::read('dnsbl_redir_int').
	 *     Then '' is returned (registered default).
	 */
	public function testDnsblRedirIntAbsentKeyReturnsDefaultEmpty(): void
	{
		$path = 'installedpackages/pfblockerngdnsblsettings/config/0/dnsbl_redir_int';

		// Before: absent.
		$this->assertNull(config_get_path($path),
			'before: dnsbl_redir_int must be absent'
		);

		// When/Then.
		$result = PfbConfig::read('dnsbl_redir_int');
		$this->assertSame('', $result,
			"dnsbl_redir_int absent -> '' (registered default)"
		);
	}

	/**
	 * dnsbl_redir_exclude (plain): arbitrary strings round-trip as identity.
	 *
	 * Scenario:
	 *   Background: plain adapter — any stored string passes through unchanged.
	 *     Given stored value v.
	 *     When PfbConfig::write('dnsbl_redir_exclude', PfbConfig::read('dnsbl_redir_exclude')).
	 *     Then stored string equals v (write(read(v)) == v).
	 */
	public function testDnsblRedirExcludePlainRoundTripNonEmpty(): void
	{
		$path = 'installedpackages/pfblockerngdnsblsettings/config/0/dnsbl_redir_exclude';

		// Given: alias name.
		$this->seedConfig($path, 'DNS_Whitelist');

		// Before.
		$this->assertSame('DNS_Whitelist', config_get_path($path),
			'before: dnsbl_redir_exclude seed must be DNS_Whitelist'
		);

		// When.
		$value = PfbConfig::read('dnsbl_redir_exclude');
		$this->assertSame('DNS_Whitelist', $value,
			'read: plain adapter returns raw stored string'
		);

		PfbConfig::write('dnsbl_redir_exclude', $value);

		// After.
		$this->assertSame('DNS_Whitelist', config_get_path($path),
			'write(read(DNS_Whitelist)) == DNS_Whitelist for dnsbl_redir_exclude'
		);
	}

	public function testDnsblRedirExcludePlainRoundTripEmpty(): void
	{
		$path = 'installedpackages/pfblockerngdnsblsettings/config/0/dnsbl_redir_exclude';

		// Given: '' (no exception).
		$this->seedConfig($path, '');

		// Before.
		$this->assertSame('', config_get_path($path),
			"before: dnsbl_redir_exclude seed must be ''"
		);

		// When.
		$value = PfbConfig::read('dnsbl_redir_exclude');
		$this->assertSame('', $value, "read: '' returns ''");

		PfbConfig::write('dnsbl_redir_exclude', $value);

		// After.
		$this->assertSame('', config_get_path($path),
			"write(read('')) == '' for dnsbl_redir_exclude"
		);
	}

	/**
	 * dnsbl_redir_exclude absent key returns the registered default ''.
	 *
	 * Scenario:
	 *   Background: key absent from config.
	 *     Given no seed.
	 *     When PfbConfig::read('dnsbl_redir_exclude').
	 *     Then '' is returned (registered default).
	 */
	public function testDnsblRedirExcludeAbsentKeyReturnsDefaultEmpty(): void
	{
		$path = 'installedpackages/pfblockerngdnsblsettings/config/0/dnsbl_redir_exclude';

		// Before: absent.
		$this->assertNull(config_get_path($path),
			'before: dnsbl_redir_exclude must be absent'
		);

		// When/Then.
		$result = PfbConfig::read('dnsbl_redir_exclude');
		$this->assertSame('', $result,
			"dnsbl_redir_exclude absent -> '' (registered default)"
		);
	}

	// -----------------------------------------------------------------------
	// ADR-37 — dnsbl_dot_block / dnsbl_dot_block_int / dnsbl_dot_block_exclude
	// -----------------------------------------------------------------------

	/**
	 * dnsbl_dot_block (toggle): 'on' and '' both round-trip losslessly.
	 *
	 * Scenario:
	 *   Background: dnsbl_dot_block stored as 'on' (enabled) or '' (disabled).
	 *     Given canonical stored value v in {'on', ''}.
	 *     When PfbConfig::write('dnsbl_dot_block', PfbConfig::read('dnsbl_dot_block')).
	 *     Then stored string equals v (write(read(v)) == v).
	 */
	public function testDnsblDotBlockToggleRoundTripOn(): void
	{
		$path = 'installedpackages/pfblockerngdnsblsettings/config/0/dnsbl_dot_block';

		// Given: canonical 'on'.
		$this->seedConfig($path, 'on');

		// Before: raw 'on'.
		$this->assertSame('on', config_get_path($path),
			'before: dnsbl_dot_block seed must be on'
		);

		// When: read -> write.
		$enum = PfbConfig::read('dnsbl_dot_block');
		$this->assertSame(PfbToggle::On, $enum, 'read: on -> PfbToggle::On');

		PfbConfig::write('dnsbl_dot_block', $enum);

		// After: stored as 'on'.
		$this->assertSame('on', config_get_path($path),
			'write(read(on)) == on for dnsbl_dot_block'
		);
	}

	public function testDnsblDotBlockToggleRoundTripOff(): void
	{
		$path = 'installedpackages/pfblockerngdnsblsettings/config/0/dnsbl_dot_block';

		// Given: canonical '' (checkbox unchecked).
		$this->seedConfig($path, '');

		// Before: raw ''.
		$this->assertSame('', config_get_path($path),
			"before: dnsbl_dot_block seed must be ''"
		);

		// When: read -> write.
		$enum = PfbConfig::read('dnsbl_dot_block');
		$this->assertSame(PfbToggle::Off, $enum, "read: '' -> PfbToggle::Off");

		PfbConfig::write('dnsbl_dot_block', $enum);

		// After: stored as ''.
		$this->assertSame('', config_get_path($path),
			"write(read('')) == '' for dnsbl_dot_block"
		);
	}

	/**
	 * dnsbl_dot_block absent key returns the registered default '' (Off).
	 *
	 * Scenario:
	 *   Background: key absent from config (feature never enabled).
	 *     Given no seed.
	 *     When PfbConfig::read('dnsbl_dot_block').
	 *     Then PfbToggle::Off is returned (default '').
	 */
	public function testDnsblDotBlockAbsentKeyReturnsOff(): void
	{
		$path = 'installedpackages/pfblockerngdnsblsettings/config/0/dnsbl_dot_block';

		// Before: absent.
		$this->assertNull(config_get_path($path),
			'before: dnsbl_dot_block must be absent'
		);

		// When/Then.
		$result = PfbConfig::read('dnsbl_dot_block');
		$this->assertSame(PfbToggle::Off, $result,
			"dnsbl_dot_block absent -> PfbToggle::Off (default '')"
		);
	}

	/**
	 * dnsbl_dot_block_int (plain): arbitrary strings round-trip as identity.
	 *
	 * Scenario:
	 *   Background: plain adapter — any stored string passes through unchanged.
	 *     Given stored value v.
	 *     When PfbConfig::write('dnsbl_dot_block_int', PfbConfig::read('dnsbl_dot_block_int')).
	 *     Then stored string equals v (write(read(v)) == v).
	 */
	public function testDnsblDotBlockIntPlainRoundTripNonEmpty(): void
	{
		$path = 'installedpackages/pfblockerngdnsblsettings/config/0/dnsbl_dot_block_int';

		// Given: comma-joined interface names.
		$this->seedConfig($path, 'lan,opt1');

		// Before.
		$this->assertSame('lan,opt1', config_get_path($path),
			'before: dnsbl_dot_block_int seed must be lan,opt1'
		);

		// When.
		$value = PfbConfig::read('dnsbl_dot_block_int');
		$this->assertSame('lan,opt1', $value,
			'read: plain adapter returns raw stored string'
		);

		PfbConfig::write('dnsbl_dot_block_int', $value);

		// After.
		$this->assertSame('lan,opt1', config_get_path($path),
			'write(read(lan,opt1)) == lan,opt1 for dnsbl_dot_block_int'
		);
	}

	/**
	 * dnsbl_dot_block_int absent key returns the registered default ''.
	 *
	 * Scenario:
	 *   Background: key absent from config.
	 *     Given no seed.
	 *     When PfbConfig::read('dnsbl_dot_block_int').
	 *     Then '' is returned (registered default).
	 */
	public function testDnsblDotBlockIntAbsentKeyReturnsDefaultEmpty(): void
	{
		$path = 'installedpackages/pfblockerngdnsblsettings/config/0/dnsbl_dot_block_int';

		// Before: absent.
		$this->assertNull(config_get_path($path),
			'before: dnsbl_dot_block_int must be absent'
		);

		// When/Then.
		$result = PfbConfig::read('dnsbl_dot_block_int');
		$this->assertSame('', $result,
			"dnsbl_dot_block_int absent -> '' (registered default)"
		);
	}

	/**
	 * dnsbl_dot_block_exclude (plain): arbitrary strings round-trip as identity.
	 *
	 * Scenario:
	 *   Background: plain adapter — any stored string passes through unchanged.
	 *     Given stored value v.
	 *     When PfbConfig::write('dnsbl_dot_block_exclude', PfbConfig::read('dnsbl_dot_block_exclude')).
	 *     Then stored string equals v (write(read(v)) == v).
	 */
	public function testDnsblDotBlockExcludePlainRoundTripNonEmpty(): void
	{
		$path = 'installedpackages/pfblockerngdnsblsettings/config/0/dnsbl_dot_block_exclude';

		// Given: alias name.
		$this->seedConfig($path, 'DoT_Exceptions');

		// Before.
		$this->assertSame('DoT_Exceptions', config_get_path($path),
			'before: dnsbl_dot_block_exclude seed must be DoT_Exceptions'
		);

		// When.
		$value = PfbConfig::read('dnsbl_dot_block_exclude');
		$this->assertSame('DoT_Exceptions', $value,
			'read: plain adapter returns raw stored string'
		);

		PfbConfig::write('dnsbl_dot_block_exclude', $value);

		// After.
		$this->assertSame('DoT_Exceptions', config_get_path($path),
			'write(read(DoT_Exceptions)) == DoT_Exceptions for dnsbl_dot_block_exclude'
		);
	}

	/**
	 * dnsbl_dot_block_exclude absent key returns the registered default ''.
	 *
	 * Scenario:
	 *   Background: key absent from config.
	 *     Given no seed.
	 *     When PfbConfig::read('dnsbl_dot_block_exclude').
	 *     Then '' is returned (registered default).
	 */
	public function testDnsblDotBlockExcludeAbsentKeyReturnsDefaultEmpty(): void
	{
		$path = 'installedpackages/pfblockerngdnsblsettings/config/0/dnsbl_dot_block_exclude';

		// Before: absent.
		$this->assertNull(config_get_path($path),
			'before: dnsbl_dot_block_exclude must be absent'
		);

		// When/Then.
		$result = PfbConfig::read('dnsbl_dot_block_exclude');
		$this->assertSame('', $result,
			"dnsbl_dot_block_exclude absent -> '' (registered default)"
		);
	}

	// -----------------------------------------------------------------------
	// E — writeSection() applies per-field write adapters (issue #930)
	//
	// Before this fix, writeSection() called config_set_path($section, $data)
	// directly, bypassing every registered adapter -- a legacy read-only token
	// ('domcop', 'alexa', alpha-only 'all') or hostile/junk value written through
	// ANY section blob (www/ save handlers, install seeds, migrations) persisted
	// raw into config.xml instead of being normalised like a single-key write().
	// -----------------------------------------------------------------------

	/**
	 * Property test: for EVERY registered key carrying both a read and a write
	 * adapter (enumerated from pfb_cfg_registry() itself, never a hand-picked
	 * subset -- so this can't under-enumerate), writeSection($section, [$key =>
	 * $raw]) must persist the exact same stored byte PfbConfig::write($key, $raw)
	 * would for a representative sample set per adapter type: a canonical token,
	 * a legacy/empty token, and a junk string.
	 *
	 * Scenario:
	 *   Given a registered key with an adapter pair, and a raw sample value.
	 *   When writeSection($section, [$key => $raw]) and write($key, $raw) are each
	 *     applied to a fresh config slate.
	 *   Then both persist the identical stored byte at the key's config.xml path.
	 */
	public function testWriteSectionAppliesAdapterForEveryRegisteredFieldAndSample(): void
	{
		$samples_by_read_adapter = [
			'pfb_cfg_toggle_read'           => ['on', '', 'junk'],
			'pfb_cfg_lenient_read'          => ['on', 'off', '', 'junk'],
			'pfb_cfg_idn_mode_read'         => ['on', 'confusable', 'off', 'all', 'junk'],
			'pfb_cfg_top1m_source_read'     => ['tranco', 'cisco', 'openpagerank', 'majestic', 'cloudflare', 'alexa', 'domcop', 'junk'],
			'pfb_cfg_alias_delta_mode_read' => ['auto', 'delta', 'replace', '', 'junk'],
		];

		$tested = 0;
		foreach (pfb_cfg_registry() as $key => $entry) {
			$read_adapter  = $entry['read_adapter'];
			$write_adapter = $entry['write_adapter'];
			if ($read_adapter === NULL || $write_adapter === NULL) {
				continue;
			}
			$this->assertArrayHasKey($read_adapter, $samples_by_read_adapter,
				"no sample set registered for adapter type '{$read_adapter}' (field '{$key}') -- extend the sample map"
			);

			$section = $entry['section'];
			$path    = $section . '/' . $key;

			foreach ($samples_by_read_adapter[$read_adapter] as $raw) {
				// Oracle: PfbConfig::write() on a fresh slate.
				$GLOBALS['config'] = [];
				PfbConfig::write($key, $raw);
				$expected = config_get_path($path);

				// Under test: PfbConfig::writeSection() on a fresh slate.
				$GLOBALS['config'] = [];
				PfbConfig::writeSection($section, [$key => $raw]);
				$actual = config_get_path($path);

				$this->assertSame($expected, $actual,
					"writeSection() vs write() mismatch for key '{$key}' raw " . var_export($raw, TRUE)
				);
				$tested++;
			}
		}

		// Sanity: the loop actually exercised all 16 adapted fields x >= 3 samples
		// each (issue #930 coverage matrix) -- guards against a future registry
		// refactor silently emptying the loop.
		$this->assertGreaterThanOrEqual(16 * 3, $tested,
			'expected at least 16 adapted fields x >= 3 samples each to have been exercised'
		);
	}

	/**
	 * THE pinning red test (mirrors the issue #930 repro): a legacy 'domcop'
	 * alexa_type token riding a section blob write is no longer re-emitted raw --
	 * it is coalesced to the canonical 'openpagerank' token, same as a single-key
	 * PfbConfig::write('alexa_type', 'domcop') would.
	 *
	 * Scenario:
	 *   Given a DNSBL settings blob with the legacy 'domcop' alexa_type token.
	 *   When PfbConfig::writeSection() persists it.
	 *   Then the stored alexa_type is 'openpagerank', never the dead 'domcop' token.
	 */
	public function testWriteSectionAlexaTypeLegacyDomcopNormalisesToOpenPageRank(): void
	{
		$section = 'installedpackages/pfblockerngdnsblsettings/config/0';
		$path    = $section . '/alexa_type';

		PfbConfig::writeSection($section, ['alexa_type' => 'domcop']);

		$this->assertSame('openpagerank', config_get_path($path),
			"legacy 'domcop' riding a section write coalesces to 'openpagerank'"
		);
	}

	/**
	 * Legacy 'alexa' (dead TOP1M service, #872) riding a section blob write
	 * coalesces to the canonical 'tranco' token.
	 *
	 * Scenario:
	 *   Given a DNSBL settings blob with the legacy 'alexa' alexa_type token.
	 *   When PfbConfig::writeSection() persists it.
	 *   Then the stored alexa_type is 'tranco', never the dead 'alexa' token.
	 */
	public function testWriteSectionAlexaTypeLegacyAlexaNormalisesToTranco(): void
	{
		$section = 'installedpackages/pfblockerngdnsblsettings/config/0';
		$path    = $section . '/alexa_type';

		PfbConfig::writeSection($section, ['alexa_type' => 'alexa']);

		$this->assertSame('tranco', config_get_path($path),
			"legacy 'alexa' riding a section write coalesces to 'tranco'"
		);
	}

	/**
	 * A live canonical alexa_type token ('cisco') riding a section blob write
	 * passes through byte-identical -- normalisation never mangles a live token.
	 *
	 * Scenario:
	 *   Given a DNSBL settings blob with the canonical 'cisco' alexa_type token.
	 *   When PfbConfig::writeSection() persists it.
	 *   Then the stored alexa_type is still 'cisco'.
	 */
	public function testWriteSectionAlexaTypeCanonicalCiscoPassesThroughUnchanged(): void
	{
		$section = 'installedpackages/pfblockerngdnsblsettings/config/0';
		$path    = $section . '/alexa_type';

		PfbConfig::writeSection($section, ['alexa_type' => 'cisco']);

		$this->assertSame('cisco', config_get_path($path),
			"canonical 'cisco' riding a section write is byte-identical"
		);
	}

	/**
	 * pfb_idn: the dropped 4.0.0-alpha-only 'all' token riding a section blob
	 * write normalises to 'off' (never re-emitted); the canonical 'on' token
	 * (= PfbIdnMode::All) stays 'on' unchanged.
	 *
	 * Scenario:
	 *   Given a DNSBL settings blob with pfb_idn = the alpha-only 'all' token.
	 *   When PfbConfig::writeSection() persists it.
	 *   Then the stored pfb_idn is 'off', never the dropped 'all' token.
	 *   And a canonical 'on' token riding the same path stays 'on'.
	 */
	public function testWriteSectionPfbIdnAlphaOnlyAllNormalisesToOff(): void
	{
		$section = 'installedpackages/pfblockerngdnsblsettings/config/0';
		$path    = $section . '/pfb_idn';

		// Alpha-only 'all' -> normalised to 'off'.
		PfbConfig::writeSection($section, ['pfb_idn' => 'all']);
		$this->assertSame('off', config_get_path($path),
			"dropped alpha-only 'all' riding a section write normalises to 'off'"
		);

		// Canonical 'on' -> stays 'on'.
		PfbConfig::writeSection($section, ['pfb_idn' => 'on']);
		$this->assertSame('on', config_get_path($path),
			"canonical 'on' riding a section write is byte-identical"
		);
	}

	/**
	 * pfb_keep: the legacy empty-string token (pre-#484 absent-key install)
	 * riding a section blob write normalises to the explicit 'off' token, same
	 * as the single-key PfbConfig::write() lenient-adapter contract.
	 *
	 * Scenario:
	 *   Given a General settings blob with pfb_keep = '' (legacy empty).
	 *   When PfbConfig::writeSection() persists it.
	 *   Then the stored pfb_keep is 'off', never the legacy '' token.
	 */
	public function testWriteSectionPfbKeepEmptyNormalisesToOff(): void
	{
		$section = 'installedpackages/pfblockerng/config/0';
		$path    = $section . '/pfb_keep';

		PfbConfig::writeSection($section, ['pfb_keep' => '']);

		$this->assertSame('off', config_get_path($path),
			"legacy empty pfb_keep riding a section write normalises to 'off'"
		);
	}

	/**
	 * A junk value on a toggle-adapted field ('yes' is not a recognized toggle
	 * token) riding a section blob write parse-falls-back to Off ('').
	 *
	 * Scenario:
	 *   Given a DNSBL settings blob with pfb_dnsbl = 'yes' (hostile/junk).
	 *   When PfbConfig::writeSection() persists it.
	 *   Then the stored pfb_dnsbl is '' (parse-fallback Off), never 'yes'.
	 */
	public function testWriteSectionToggleJunkNormalisesToOff(): void
	{
		$section = 'installedpackages/pfblockerngdnsblsettings/config/0';
		$path    = $section . '/pfb_dnsbl';

		PfbConfig::writeSection($section, ['pfb_dnsbl' => 'yes']);

		$this->assertSame('', config_get_path($path),
			"junk toggle value 'yes' riding a section write parse-falls-back to ''"
		);
	}

	/**
	 * Hostile input: a crafted array value (e.g. a POST array
	 * alexa_type[]=x) riding a section blob write hits the adapter's
	 * non-scalar guard and normalises to the parse-fallback default, never
	 * crashes and never persists the raw array.
	 *
	 * Scenario:
	 *   Given a DNSBL settings blob with alexa_type = ['x'] (non-scalar).
	 *   When PfbConfig::writeSection() persists it.
	 *   Then the stored alexa_type is 'tranco' (the non-scalar-guard default).
	 */
	public function testWriteSectionAlexaTypeArrayValueNormalisesToDefaultTranco(): void
	{
		$section = 'installedpackages/pfblockerngdnsblsettings/config/0';
		$path    = $section . '/alexa_type';

		PfbConfig::writeSection($section, ['alexa_type' => ['x']]);

		$this->assertSame('tranco', config_get_path($path),
			'array-valued alexa_type riding a section write hits the non-scalar guard -> tranco'
		);
	}

	/**
	 * Hostile input: a NULL value on an adapted key riding a section blob write
	 * is not a TypeError -- the read adapter's NULL->'' collapse feeds the write
	 * adapter a well-formed enum, landing on the field's Off/legacy-empty token.
	 *
	 * Scenario:
	 *   Given a General settings blob with pfb_keep = NULL.
	 *   When PfbConfig::writeSection() persists it.
	 *   Then the stored pfb_keep is 'off' (lenient NULL-collapse path), no crash.
	 */
	public function testWriteSectionNullValueNormalisesViaDefaultCollapse(): void
	{
		$section = 'installedpackages/pfblockerng/config/0';
		$path    = $section . '/pfb_keep';

		PfbConfig::writeSection($section, ['pfb_keep' => NULL]);

		$this->assertSame('off', config_get_path($path),
			'NULL-valued pfb_keep riding a section write collapses to the lenient Off token'
		);
	}

	/**
	 * Hostile input / idempotency: an already-adapted enum instance (e.g. fed
	 * back through from a prior PfbConfig::read()) riding a section blob write
	 * is not double-mangled -- the read adapter's `instanceof static` passthrough
	 * returns it as-is, and the write adapter emits its canonical token.
	 *
	 * Scenario:
	 *   Given a DNSBL settings blob with alexa_type = PfbTop1mSource::Cisco (an
	 *     enum instance, not a raw string).
	 *   When PfbConfig::writeSection() persists it.
	 *   Then the stored alexa_type is 'cisco', not mangled by a double-apply.
	 */
	public function testWriteSectionAlexaTypeEnumInstanceIsIdempotent(): void
	{
		$section = 'installedpackages/pfblockerngdnsblsettings/config/0';
		$path    = $section . '/alexa_type';

		PfbConfig::writeSection($section, ['alexa_type' => PfbTop1mSource::Cisco]);

		$this->assertSame('cisco', config_get_path($path),
			'an already-adapted PfbTop1mSource enum instance riding a section write is idempotent'
		);
	}

	/**
	 * Hostile input: an integer value on an adapted key riding a section blob
	 * write hits the non-scalar-adjacent junk path (no matching token) and
	 * normalises to the field's parse-fallback default.
	 *
	 * Scenario:
	 *   Given a DNSBL settings blob with alexa_type = 1 (int, not a string token).
	 *   When PfbConfig::writeSection() persists it.
	 *   Then the stored alexa_type is 'tranco' (the parse-fallback default).
	 */
	public function testWriteSectionAlexaTypeIntValueNormalisesToDefaultTranco(): void
	{
		$section = 'installedpackages/pfblockerngdnsblsettings/config/0';
		$path    = $section . '/alexa_type';

		PfbConfig::writeSection($section, ['alexa_type' => 1]);

		$this->assertSame('tranco', config_get_path($path),
			'int-valued alexa_type riding a section write normalises to the parse-fallback tranco'
		);
	}

	/**
	 * A registered key with NO adapter pair (plain string, e.g. top1m_token and
	 * dnsbl_interface) riding a section blob write is left byte-identical --
	 * normalisation only ever touches adapter-bearing keys.
	 *
	 * Scenario:
	 *   Given a DNSBL settings blob with two unadapted registered keys.
	 *   When PfbConfig::writeSection() persists it.
	 *   Then both stored values are byte-identical to the input.
	 */
	public function testWriteSectionUnadaptedRegisteredKeysPassThroughRaw(): void
	{
		$section = 'installedpackages/pfblockerngdnsblsettings/config/0';

		PfbConfig::writeSection($section, [
			'top1m_token'     => 'AbC123',
			'dnsbl_interface' => 'lo0',
		]);

		$this->assertSame('AbC123', config_get_path($section . '/top1m_token'),
			'unadapted top1m_token riding a section write is byte-identical'
		);
		$this->assertSame('lo0', config_get_path($section . '/dnsbl_interface'),
			'unadapted dnsbl_interface riding a section write is byte-identical'
		);
	}

	/**
	 * An adapted KEY NAME landing in a FOREIGN section (not the section the
	 * registry maps that key to) stays raw -- writeSection() matches on the
	 * EXACT registered section string, so a same-named key belonging to a
	 * different registry entry is untouched foreign data.
	 *
	 * Scenario:
	 *   Given a pfblockerngsync section blob that happens to reuse the key name
	 *     'alexa_type' (foreign to this section -- the registry maps alexa_type
	 *     to the DNSBL section only) with the legacy 'domcop' value.
	 *   When PfbConfig::writeSection() persists it against the SYNC section.
	 *   Then the stored value is the raw 'domcop' -- no normalisation applied,
	 *     because no registry entry has 'section' === the sync section for
	 *     this key.
	 */
	public function testWriteSectionAdaptedKeyNameInForeignSectionStaysRaw(): void
	{
		$section = 'installedpackages/pfblockerngsync/config/0';
		$path    = $section . '/alexa_type';

		PfbConfig::writeSection($section, ['alexa_type' => 'domcop']);

		$this->assertSame('domcop', config_get_path($path),
			"a same-named key in a foreign (non-registered-for-it) section stays raw"
		);
	}

	/**
	 * A realistic dconfig-shaped blob (mirrors pfblockerng_dnsbl.php's save
	 * handler): a mix of adapted legacy/hostile tokens and unadapted
	 * base64/plain fields. Adapted fields normalise; every other field is
	 * byte-identical.
	 *
	 * Scenario:
	 *   Given a DNSBL settings blob mixing legacy alexa_type/pfb_idn tokens with
	 *     unadapted plain fields (dnsbl_interface, pfb_dnsvip4, top1m_token).
	 *   When PfbConfig::writeSection() persists it.
	 *   Then the adapted fields are stored at their canonical tokens and every
	 *     unadapted field is byte-identical to the input.
	 */
	public function testWriteSectionDconfigShapedBlobNormalisesAdaptedFieldsOnly(): void
	{
		$section = 'installedpackages/pfblockerngdnsblsettings/config/0';

		$data = [
			'pfb_dnsbl'       => 'on',           // adapted (toggle), canonical.
			'alexa_type'      => 'domcop',        // adapted (top1m_source), LEGACY -> normalises.
			'pfb_idn'         => 'all',           // adapted (idn_mode), ALPHA-ONLY -> normalises.
			'pfb_hsts'        => 'on',            // adapted (toggle), canonical.
			'dnsbl_interface' => 'lo0',           // unadapted, plain.
			'pfb_dnsvip4'     => '',              // unadapted, plain.
			'top1m_token'     => 'QWJjMTIz',      // unadapted, plain (base64-shaped).
		];

		PfbConfig::writeSection($section, $data);

		$result = PfbConfig::readSection($section);

		$this->assertSame('on', $result['pfb_dnsbl'], 'pfb_dnsbl canonical stays on');
		$this->assertSame('openpagerank', $result['alexa_type'], "legacy 'domcop' normalises to 'openpagerank'");
		$this->assertSame('off', $result['pfb_idn'], "alpha-only 'all' normalises to 'off'");
		$this->assertSame('on', $result['pfb_hsts'], 'pfb_hsts canonical stays on');
		$this->assertSame('lo0', $result['dnsbl_interface'], 'unadapted dnsbl_interface is byte-identical');
		$this->assertSame('', $result['pfb_dnsvip4'], 'unadapted pfb_dnsvip4 is byte-identical');
		$this->assertSame('QWJjMTIz', $result['top1m_token'], 'unadapted top1m_token is byte-identical');
	}

	/**
	 * The gateway NEVER calls write_config() -- the caller decides when to
	 * flush (CLAUDE.md "Config gateway -- PfbConfig"). Pins that invariant for
	 * every public PfbConfig method: the pfsense_doubles write_config() records
	 * each call in $GLOBALS['pfb_test_write_config_calls'], so an accidental
	 * write_config() slipped into any gateway path fails this test (PR #949
	 * review: a mutation adding one to writeSection() survived the whole suite).
	 *
	 * Scenario:
	 *   Given a clean write_config() call recorder.
	 *   When every public PfbConfig method runs (read/write/delete +
	 *     readSection/writeSection/deleteSection).
	 *   Then zero write_config() calls were recorded.
	 */
	public function testGatewayNeverCallsWriteConfig(): void
	{
		$GLOBALS['pfb_test_write_config_calls'] = [];

		PfbConfig::write('pfb_keep', 'on');
		PfbConfig::read('pfb_keep');
		PfbConfig::delete('pfb_keep');
		PfbConfig::readSection('installedpackages/pfblockerng/config/0');
		PfbConfig::writeSection('installedpackages/pfblockerng/config/0', ['pfb_keep' => '', 'pfb_interval' => '1']);
		PfbConfig::deleteSection('installedpackages/pfblockerng/config/0');

		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls'],
			'PfbConfig must never call write_config() -- the caller flushes');

		unset($GLOBALS['pfb_test_write_config_calls']);
	}
}
