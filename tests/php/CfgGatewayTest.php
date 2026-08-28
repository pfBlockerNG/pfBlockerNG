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
 *   For every registered field that carries a read+write adapter pair, recognised
 *   values preserve their case; toggle Off writes the canonical empty token and
 *   legacy 'off' remains read-compatible only.
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
	//     (toggle adapters; multi-valued enum handling documented below)
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
		// Representative toggle-adapted fields (pfb_keep is default-on).
		$toggle_fields = [
			'gen/enable_cb'        => 'installedpackages/pfblockerng/config/0/enable_cb',
			'dnsbl/pfb_dnsbl'        => 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl',
			'dnsbl/pfb_dnsvip_auto'  => 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsvip_auto',
			'dnsbl/pfb_dnsbl_nonat'  => 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl_nonat',
			'gen/pfb_reuse'        => 'installedpackages/pfblockerng/config/0/pfb_reuse',
			'dnsbl/pfb_hsts'         => 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_hsts',
			'dnsbl/pfb_psl_include_private' => 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_psl_include_private',
			'dnsbl/pfb_psl_allow_private' => 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_psl_allow_private',
			'dnsbl/pfb_cache_flush'  => 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_cache_flush',
			'gen/pfb_feed_sanity'  => 'installedpackages/pfblockerng/config/0/pfb_feed_sanity',
			// issue #1907: adopted onto the toggle adapter (default flipped to 'on').
			'dnsbl/pfb_cache'        => 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_cache',
			'dnsbl/pfb_py_reply'     => 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_py_reply',
			'ip/suppression'         => 'installedpackages/pfblockerngipsettings/config/0/suppression',
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
		// pfb_keep is default-on — see testPfbKeepRoundTrip*() below. issue #1907:
		// dnsbl/pfb_hsts, dnsbl/pfb_cache, dnsbl/pfb_py_reply, ip/suppression joined
		// that same default-on class. Their present empty token is explicit Off and is
		// covered by ConfigEmptyStorageContractTest.
		$toggle_fields = [
			'gen/enable_cb'        => 'installedpackages/pfblockerng/config/0/enable_cb',
			'dnsbl/pfb_dnsbl'        => 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl',
			'dnsbl/pfb_dnsvip_auto'  => 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsvip_auto',
			'dnsbl/pfb_dnsbl_nonat'  => 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl_nonat',
			'gen/pfb_reuse'        => 'installedpackages/pfblockerng/config/0/pfb_reuse',
			'dnsbl/pfb_cache_flush'  => 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_cache_flush',
			'gen/pfb_feed_sanity'  => 'installedpackages/pfblockerng/config/0/pfb_feed_sanity',
		];

		foreach ($toggle_fields as $key => $path) {
			// Given: canonical '' (unchecked) stored.
			$this->seedConfig($path, '');

			// Before: raw value is ''.
			$this->assertSame('', config_get_path($path), "before: {$key} seed is ''");

			// When: read -> write.
			$enum = PfbConfig::read($key);
			$this->assertSame(PfbToggle::Off, $enum, "read: {$key} '' -> PfbToggle::Off");

			// After: write back emits the empty checkbox token.
			PfbConfig::write($key, $enum);
			$this->assertSame('', config_get_path($path), "write(read(''))=='' for {$key}");
		}
	}

	/**
	 * Toggle field (pfb_dnsbl_lenient): 'on'/'off' read; Off writes ''.
	 *
	 * Scenario:
	 *   Background: pfb_dnsbl_lenient stored as 'on', legacy 'off', or ''.
	 *     Given v.  When read/write.
	 *     Then 'on' remains 'on'; legacy 'off' and empty both write canonical empty Off.
	 */
	public function testLenientFieldRoundTripOn(): void
	{
		$path = 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl_lenient';

		// Given: canonical 'on'.
		$this->seedConfig($path, 'on');

		// Before: raw 'on'.
		$this->assertSame('on', config_get_path($path));

		// When/After.
		$enum = PfbConfig::read('dnsbl/pfb_dnsbl_lenient');
		$this->assertSame(PfbToggle::On, $enum);

		PfbConfig::write('dnsbl/pfb_dnsbl_lenient', $enum);
		$this->assertSame('on', config_get_path($path));
	}

	public function testLenientFieldRoundTripOff(): void
	{
		$path = 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl_lenient';

		// Given: legacy 'off' (read-compatible; never written).
		$this->seedConfig($path, 'off');

		// Before: raw 'off'.
		$this->assertSame('off', config_get_path($path));

		// When/After.
		$enum = PfbConfig::read('dnsbl/pfb_dnsbl_lenient');
		$this->assertSame(PfbToggle::Off, $enum);

		PfbConfig::write('dnsbl/pfb_dnsbl_lenient', $enum);
		$this->assertSame('', config_get_path($path));
	}

	public function testLenientFieldEmptyNormalisesToOff(): void
	{
		$path = 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl_lenient';

		// Given: '' (pre-ADR-22 install, key never written).
		$this->seedConfig($path, '');

		// Before: raw ''.
		$this->assertSame('', config_get_path($path));

		// When/After: Off remains the canonical empty token.
		$enum = PfbConfig::read('dnsbl/pfb_dnsbl_lenient');
		$this->assertSame(PfbToggle::Off, $enum);

		PfbConfig::write('dnsbl/pfb_dnsbl_lenient', $enum);
		// Checkbox Off stores as ''.
		$this->assertSame('', config_get_path($path));
	}

	/**
	 * pfb_keep (toggle adapter): 'on'/'off'/'' reads; Off writes the empty token.
	 *
	 * Scenario:
	 *   Background: pfb_keep stored as 'on', 'off', or '' (pre-#484-fix legacy empty).
	 *     Given v.  When read/write.
	 *     Then 'on' round-trips to 'on'; legacy 'off' reads Off and writes ''.
	 *     And '' is preserved as the canonical empty token on write.
	 */
	public function testPfbKeepLenientRoundTripOn(): void
	{
		$path = 'installedpackages/pfblockerng/config/0/pfb_keep';

		// Given: canonical 'on'.
		$this->seedConfig($path, 'on');

		// Before: raw 'on'.
		$this->assertSame('on', config_get_path($path), 'before: pfb_keep seed is on');

		// When/After: read -> PfbToggle::On; write -> 'on'.
		$enum = PfbConfig::read('gen/pfb_keep');
		$this->assertSame(PfbToggle::On, $enum, "read: pfb_keep 'on' -> PfbToggle::On");

		PfbConfig::write('gen/pfb_keep', $enum);
		$this->assertSame('on', config_get_path($path), "write(read('on'))==on for pfb_keep");
	}

	public function testPfbKeepLenientRoundTripOff(): void
	{
		$path = 'installedpackages/pfblockerng/config/0/pfb_keep';

		// Given: legacy 'off' (accepted on read; no longer written).
		$this->seedConfig($path, 'off');

		// Before: raw 'off'.
		$this->assertSame('off', config_get_path($path), 'before: pfb_keep seed is off');

		// When/After: read -> PfbToggle::Off; write -> ''.
		$enum = PfbConfig::read('gen/pfb_keep');
		$this->assertSame(PfbToggle::Off, $enum, "read: pfb_keep 'off' -> PfbToggle::Off");

		PfbConfig::write('gen/pfb_keep', $enum);
		$this->assertSame('', config_get_path($path), "write(read('off'))=='' for pfb_keep");
	}

	public function testPfbKeepEmptyPreservesExplicitOff(): void
	{
		$path = 'installedpackages/pfblockerng/config/0/pfb_keep';

		// Given: '' — an adapter-bearing field's present empty token is explicit Off;
		// only an absent key resolves to its registered default.
		$this->seedConfig($path, '');

		$this->assertSame('', config_get_path($path), 'before: pfb_keep seed is empty string');

		$enum = PfbConfig::read('gen/pfb_keep');
		$this->assertSame(PfbToggle::Off, $enum, "read: pfb_keep '' -> PfbToggle::Off");

		// After: write emits the canonical token of the default.
		PfbConfig::write('gen/pfb_keep', $enum);
		$this->assertSame('', config_get_path($path), "write(read(''))=='' for pfb_keep");
	}

	/**
	 * issue #1669 slice C: pfb_syntax_highlight (toggle adapter, default on):
	 * 'on' remains 'on' and legacy 'off' normalises to empty. Mirrors testPfbKeepLenientRoundTripOn/Off --
	 * this field is the same default-on-checkbox shape as pfb_keep, using PfbToggle.
	 *
	 * Scenario:
	 *   Background: pfb_syntax_highlight stored as 'on' or 'off'.
	 *     Given v.  When read/write.
	 *     Then 'on' round-trips to 'on'; legacy 'off' reads Off and writes ''.
	 */
	public function testPfbSyntaxHighlightLenientRoundTripOn(): void
	{
		$path = 'installedpackages/pfblockerng/config/0/pfb_syntax_highlight';

		// Given: canonical 'on'.
		$this->seedConfig($path, 'on');

		// Before: raw 'on'.
		$this->assertSame('on', config_get_path($path), 'before: pfb_syntax_highlight seed is on');

		// When/After: read -> PfbToggle::On; write -> 'on'.
		$enum = PfbConfig::read('gen/pfb_syntax_highlight');
		$this->assertSame(PfbToggle::On, $enum, "read: pfb_syntax_highlight 'on' -> PfbToggle::On");

		PfbConfig::write('gen/pfb_syntax_highlight', $enum);
		$this->assertSame('on', config_get_path($path), "write(read('on'))==on for pfb_syntax_highlight");
	}

	public function testPfbSyntaxHighlightLenientRoundTripOff(): void
	{
		$path = 'installedpackages/pfblockerng/config/0/pfb_syntax_highlight';

		// Given: legacy 'off' (accepted on read; no longer written).
		$this->seedConfig($path, 'off');

		// Before: raw 'off'.
		$this->assertSame('off', config_get_path($path), 'before: pfb_syntax_highlight seed is off');

		// When/After: read -> PfbToggle::Off; write -> ''.
		$enum = PfbConfig::read('gen/pfb_syntax_highlight');
		$this->assertSame(PfbToggle::Off, $enum, "read: pfb_syntax_highlight 'off' -> PfbToggle::Off");

		PfbConfig::write('gen/pfb_syntax_highlight', $enum);
		$this->assertSame('', config_get_path($path), "write(read('off'))=='' for pfb_syntax_highlight");
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
		$result = PfbConfig::read('gen/enable_cb');
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
	 *     When PfbConfig::read('gen/pfb_feed_sanity').
	 *     Then PfbToggle::Off is returned (default '').
	 */
	public function testReadReturnsRegisteredDefaultForPfbFeedSanityAbsentKey(): void
	{
		// Before: key absent.
		$this->assertNull(config_get_path('installedpackages/pfblockerng/config/0/pfb_feed_sanity'));

		// When/Then: returns Off (default '').
		$result = PfbConfig::read('gen/pfb_feed_sanity');
		$this->assertSame(PfbToggle::Off, $result, 'pfb_feed_sanity absent -> Off (default)');
	}

	public function testReadReturnsOffDefaultForDnsblCacheFlushAbsentKey(): void
	{
		$path = 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_cache_flush';
		$this->assertNull(config_get_path($path));
		$this->assertSame(PfbToggle::Off, PfbConfig::read('dnsbl/pfb_cache_flush'),
			'pfb_cache_flush absent -> Off (default)');
	}

	/**
	 * issue #1669 slice C: pfb_syntax_highlight absent key returns On — the
	 * registry default is 'on' (NEW feature, no prior behaviour to preserve, so
	 * both fresh installs and upgraders read the same default; no grandfather
	 * seed is needed per docs/misc/config-gateway.md's two-case forward-compat
	 * rule). Uses the LENIENT adapter (mirrors pfb_keep) -- see the registry
	 * comment and testNoToggleFieldDefaultsToOn for why PfbToggle cannot be used
	 * for a default-on field.
	 *
	 * Scenario:
	 *   Background: config[.../pfb_syntax_highlight] is unset.
	 *     Given no seed.
	 *     When PfbConfig::read('gen/pfb_syntax_highlight').
	 *     Then PfbToggle::On is returned (default 'on').
	 */
	public function testReadReturnsOnDefaultForPfbSyntaxHighlightAbsentKey(): void
	{
		$path = 'installedpackages/pfblockerng/config/0/pfb_syntax_highlight';
		$this->assertNull(config_get_path($path));
		$this->assertSame(PfbToggle::On, PfbConfig::read('gen/pfb_syntax_highlight'),
			'pfb_syntax_highlight absent -> On (default)');
	}

	public function testReadReturnsRegisteredDefaultForPfbKeepAbsentKey(): void
	{
		// pfb_keep default is 'on' (On enum) — the #281 canonical default; the
		// merged PfbToggle adapter resolves the absent key to it (issue #1887).
		// Before: key absent.
		$this->assertNull(config_get_path('installedpackages/pfblockerng/config/0/pfb_keep'));

		// When: read with no seed.
		$result = PfbConfig::read('gen/pfb_keep');

		// Then: returns On (the registered default 'on').
		$this->assertSame(PfbToggle::On, $result, 'pfb_keep absent -> PfbToggle::On (default on)');
	}

	public function testReadReturnsRegisteredDefaultForLenientAbsentKey(): void
	{
		// pfb_dnsbl_lenient default is 'off' -> PfbToggle::Off.
		// Before: key absent.
		$this->assertNull(
			config_get_path('installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl_lenient')
		);

		// When.
		$result = PfbConfig::read('dnsbl/pfb_dnsbl_lenient');

		// Then: Off.
		$this->assertSame(PfbToggle::Off, $result, 'pfb_dnsbl_lenient absent -> Off');
	}

	public function testReadReturnsRegisteredDefaultForPlainStringAbsentKey(): void
	{
		$this->assertNull(config_get_path('installedpackages/pfblockerng/config/0/pfb_schedule_hour'));

		$result = PfbConfig::read('gen/pfb_schedule_hour');
		$this->assertSame('0', $result, 'pfb_schedule_hour absent -> "0"');
	}

	public function testReadReturnsRegisteredDefaultForAlexaTypeAbsentKey(): void
	{
		// top1m_source default is 'tranco' -> PfbTop1mSource::Tranco.
		$this->assertNull(
			config_get_path('installedpackages/pfblockerngdnsblsettings/config/0/top1m_source')
		);

		$result = PfbConfig::read('dnsbl/top1m_source');
		$this->assertInstanceOf(PfbTop1mSource::class, $result, 'top1m_source must return a PfbTop1mSource enum');
		$this->assertSame(PfbTop1mSource::Tranco, $result);
	}

	/**
	 * top1m_source (issue #877): a stored legacy 'alexa' (dead TOP1M source, #872)
	 * coalesces to PfbTop1mSource::Tranco through the gateway's read adapter.
	 *
	 * Scenario: the dropped Alexa TOP1M option still reads safely on an existing
	 * install that had it selected.
	 *   Given top1m_source stored as the legacy 'alexa' token.
	 *   When PfbConfig::read('dnsbl/top1m_source').
	 *   Then the result is PfbTop1mSource::Tranco, not the dead 'alexa' token.
	 */
	public function testReadCoalescesLegacyAlexaTypeToTranco(): void
	{
		$path = 'installedpackages/pfblockerngdnsblsettings/config/0/top1m_source';

		// Given: legacy 'alexa' stored.
		$this->seedConfig($path, 'alexa');
		$this->assertSame('alexa', config_get_path($path), 'before: top1m_source seed is legacy alexa');

		// When/Then: coalesced to PfbTop1mSource::Tranco.
		$this->assertSame(PfbTop1mSource::Tranco, PfbConfig::read('dnsbl/top1m_source'), "legacy 'alexa' coalesces to Tranco");
	}

	/**
	 * top1m_source (issue #928): a stored legacy 'domcop' token (the DomCop TOP1M list's
	 * hosting moved to OpenPageRank) coalesces to PfbTop1mSource::OpenPageRank through
	 * the gateway's read adapter -- same shape as the 'alexa' legacy coalesce above.
	 *
	 * Scenario: an existing install with DomCop selected still reads safely.
	 *   Given top1m_source stored as the legacy 'domcop' token.
	 *   When PfbConfig::read('dnsbl/top1m_source').
	 *   Then the result is PfbTop1mSource::OpenPageRank, not the dead 'domcop' token.
	 */
	public function testReadCoalescesLegacyDomCopTypeToOpenPageRank(): void
	{
		$path = 'installedpackages/pfblockerngdnsblsettings/config/0/top1m_source';

		// Given: legacy 'domcop' stored.
		$this->seedConfig($path, 'domcop');
		$this->assertSame('domcop', config_get_path($path), 'before: top1m_source seed is legacy domcop');

		// When/Then: coalesced to PfbTop1mSource::OpenPageRank.
		$this->assertSame(
			PfbTop1mSource::OpenPageRank,
			PfbConfig::read('dnsbl/top1m_source'),
			"legacy 'domcop' coalesces to OpenPageRank"
		);
	}

	/**
	 * top1m_source: all five live tokens pass through as their enum cases (openpagerank/majestic
	 * added ADR-59 P4, cloudflare added ADR-59 P5).
	 */
	public function testReadPassesThroughLivePfbTop1mSourceTokens(): void
	{
		$path = 'installedpackages/pfblockerngdnsblsettings/config/0/top1m_source';

		$this->seedConfig($path, 'cisco');
		$this->assertSame(PfbTop1mSource::Cisco, PfbConfig::read('dnsbl/top1m_source'), "'cisco' passes through as Cisco");

		$this->seedConfig($path, 'tranco');
		$this->assertSame(PfbTop1mSource::Tranco, PfbConfig::read('dnsbl/top1m_source'), "'tranco' passes through as Tranco");

		$this->seedConfig($path, 'openpagerank');
		$this->assertSame(PfbTop1mSource::OpenPageRank, PfbConfig::read('dnsbl/top1m_source'), "'openpagerank' passes through as OpenPageRank");

		$this->seedConfig($path, 'majestic');
		$this->assertSame(PfbTop1mSource::Majestic, PfbConfig::read('dnsbl/top1m_source'), "'majestic' passes through as Majestic");

		$this->seedConfig($path, 'cloudflare');
		$this->assertSame(PfbTop1mSource::Cloudflare, PfbConfig::read('dnsbl/top1m_source'), "'cloudflare' passes through as Cloudflare");
	}

	/**
	 * top1m_token (ADR-59 P5): a masked, write-only plain-string field (no adapter) --
	 * absent reads as the registered default '', and any stored token round-trips
	 * (write(read(v)) == v) like every other plain field.
	 *
	 * Scenario: top1m_token default-absent + round-trip.
	 *   Given the key is absent from config.xml.
	 *   When PfbConfig::read('dnsbl/top1m_token').
	 *   Then the result is '' (the registered default).
	 *   And when a real-looking token is written then read back, it comes back verbatim.
	 */
	public function testTop1mTokenDefaultsToEmptyAndRoundTrips(): void
	{
		$path = 'installedpackages/pfblockerngdnsblsettings/config/0/top1m_token';

		// Given/When: absent key.
		$this->assertNull(config_get_path($path));
		$this->assertSame('', PfbConfig::read('dnsbl/top1m_token'), 'top1m_token absent -> default ""');

		// Round-trip: write(read(v)) == v for a real-looking base64url/JWT-charset token.
		$token = 'cf-abc123._~+/=-XYZ';
		PfbConfig::write('dnsbl/top1m_token', $token);
		$this->assertSame($token, config_get_path($path), 'top1m_token write() must store the token verbatim');
		$this->assertSame($token, PfbConfig::read('dnsbl/top1m_token'), 'top1m_token read() must return the stored token verbatim');
	}

	public function testReadReturnsRegisteredDefaultForDnsblInterfaceAbsentKey(): void
	{
		// dnsbl_interface default is 'lo0'.
		$this->assertNull(
			config_get_path('installedpackages/pfblockerngdnsblsettings/config/0/dnsbl_interface')
		);

		$result = PfbConfig::read('dnsbl/dnsbl_interface');
		$this->assertSame('lo0', $result);
	}

	public function testReadReturnsRejectDefaultForDotBlockActionAbsentKey(): void
	{
		// dnsbl_dot_block_action default is 'reject' (ADR-37): an existing install
		// upgrading with the key absent reads to Reject, the corrected outbound default.
		$this->assertNull(
			config_get_path('installedpackages/pfblockerngdnsblsettings/config/0/dnsbl_dot_block_action')
		);

		$result = PfbConfig::read('dnsbl/dnsbl_dot_block_action');
		$this->assertSame('reject', $result, 'dnsbl_dot_block_action absent -> reject (default)');
	}

	public function testReadReturnsOffDefaultForDotBlockFloatingAbsentKey(): void
	{
		// dnsbl_dot_block_floating default is '' -> PfbToggle::Off (ADR-37): absent key
		// preserves the per-interface default; floating is strictly opt-in.
		$this->assertNull(
			config_get_path('installedpackages/pfblockerngdnsblsettings/config/0/dnsbl_dot_block_floating')
		);

		$result = PfbConfig::read('dnsbl/dnsbl_dot_block_floating');
		$this->assertSame(PfbToggle::Off, $result, 'dnsbl_dot_block_floating absent -> Off (per-interface default)');
	}

	public function testReadReturnsRegisteredDefaultForSafeSearchAbsentKey(): void
	{
		// safesearch_enable default is 'Disable'.
		$this->assertNull(config_get_path('installedpackages/pfblockerngsafesearch/safesearch_enable'));

		$result = PfbConfig::read('ss/safesearch_enable');
		$this->assertSame('Disable', $result);
	}

	public function testReadReturnsRegisteredDefaultForIdnBlockMaliciousAbsentKey(): void
	{
		// pfb_idn_block_malicious default is 'on'.
		$this->assertNull(
			config_get_path('installedpackages/pfblockerngdnsblsettings/config/0/pfb_idn_block_malicious')
		);

		// issue #1887: the field carries the toggle adapter now, so the enum comes back.
		$result = PfbConfig::read('dnsbl/pfb_idn_block_malicious');
		$this->assertSame(PfbToggle::On, $result);
	}

	public function testPslPolicyDefaultsAndStoredTogglePolarity(): void
	{
		$includePath = 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_psl_include_private';
		$allowPath = 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_psl_allow_private';
		$this->assertNull(config_get_path($includePath));
		$this->assertNull(config_get_path($allowPath));
		$this->assertSame(PfbToggle::On, PfbConfig::read('dnsbl/pfb_psl_include_private'));
		$this->assertSame(PfbToggle::Off, PfbConfig::read('dnsbl/pfb_psl_allow_private'));

		$this->seedConfig($includePath, '');
		$this->seedConfig($allowPath, 'on');
		$this->assertSame(PfbToggle::Off, PfbConfig::read('dnsbl/pfb_psl_include_private'));
		$this->assertSame(PfbToggle::On, PfbConfig::read('dnsbl/pfb_psl_allow_private'));
	}

	/**
	 * issue #2371: dnsbl/pfb_psl_feed_private_policy + dnsbl/pfb_psl_feed_icann_policy --
	 * absent/''/unknown all read Honor (grandfather + fail-safe: an unrecognised stored
	 * value must never throw or silently drop/demote a feed entry); every canonical
	 * token round-trips through PfbConfig::write().
	 */
	public function testFeedSuffixPolicyDefaultsRoundTripsAndHostileInput(): void
	{
		$privatePath = 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_psl_feed_private_policy';
		$icannPath   = 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_psl_feed_icann_policy';

		foreach (['dnsbl/pfb_psl_feed_private_policy' => $privatePath, 'dnsbl/pfb_psl_feed_icann_policy' => $icannPath] as $key => $path) {
			$this->assertNull(config_get_path($path), "before: {$key} must be absent");
			$this->assertSame(PfbFeedSuffixPolicy::Honor, PfbConfig::read($key), "{$key}: absent -> Honor");

			foreach ([PfbFeedSuffixPolicy::Ignore, PfbFeedSuffixPolicy::Apex, PfbFeedSuffixPolicy::Honor] as $value) {
				PfbConfig::write($key, $value);
				$this->assertSame($value, PfbConfig::read($key), "{$key}: {$value->value} must round-trip");
				$this->assertSame($value->value, config_get_path($path), "{$key}: stored token must be canonical '{$value->value}'");
			}

			// Hostile input: present '', legacy/junk, and case-mismatched tokens all read Honor.
			foreach (['', 'suppress', 'IGNORE', 'Apex', ' apex', 'legacy-junk'] as $hostile) {
				$this->seedConfig($path, $hostile);
				$this->assertSame(PfbFeedSuffixPolicy::Honor, PfbConfig::read($key), "{$key}: stored '{$hostile}' must read Honor, never throw");
			}
		}
	}

	/**
	 * issue #1907: dnsbl/pfb_cache, dnsbl/pfb_py_reply, dnsbl/pfb_hsts, ip/suppression --
	 * same default-on shape as pfb_idn_block_malicious/pfb_keep above. Absent resolves
	 * to On; present empty and legacy 'off' resolve to Off; present 'on' resolves to On.
	 */
	public function testIssue1907FieldsDistinguishAbsentFromEmpty(): void
	{
		$fields = [
			'dnsbl/pfb_cache'    => 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_cache',
			'dnsbl/pfb_py_reply' => 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_py_reply',
			'dnsbl/pfb_hsts'     => 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_hsts',
			'ip/suppression'     => 'installedpackages/pfblockerngipsettings/config/0/suppression',
		];

		foreach ($fields as $key => $path) {
			$this->assertNull(config_get_path($path), "before: {$key} must be absent");
			$this->assertSame(PfbToggle::On, PfbConfig::read($key), "{$key}: absent -> On (default)");

			$this->seedConfig($path, '');
			$this->assertSame(PfbToggle::Off, PfbConfig::read($key), "{$key}: stored '' -> Off");

			$this->seedConfig($path, 'off');
			$this->assertSame(PfbToggle::Off, PfbConfig::read($key), "{$key}: stored 'off' -> Off");

			$this->seedConfig($path, 'on');
			$this->assertSame(PfbToggle::On, PfbConfig::read($key), "{$key}: stored 'on' -> On");
		}
	}

	// -----------------------------------------------------------------------
	// ADR-53 — v4suppression (plain base64 blob; IPv4 suppression customlist)
	// -----------------------------------------------------------------------

	/**
	 * v4suppression absent key returns the registered default '' (empty customlist).
	 *
	 * Scenario:
	 *   Background: v4suppression is a plain base64-blob field; default = '' --
	 *     mirrors the DNSBL 'whitelist' sibling shape.
	 *     Given no stored value.
	 *     When PfbConfig::read('ip/v4suppression').
	 *     Then '' is returned (registered default).
	 *
	 * Red->green: before this phase, 'v4suppression' was not registered ->
	 *   PfbConfig::read('ip/v4suppression') threw InvalidArgumentException.
	 */
	public function testV4SuppressionAbsentKeyReturnsDefaultEmptyString(): void
	{
		$path = 'installedpackages/pfblockerngipsettings/config/0/v4suppression';

		// Before: absent.
		$this->assertNull(config_get_path($path), 'before: v4suppression must be absent');

		// When/Then.
		$this->assertSame('', PfbConfig::read('ip/v4suppression'), 'v4suppression absent -> ""');
	}

	/**
	 * v4suppression round-trips a base64 blob losslessly (write(read(v)) == v).
	 *
	 * Scenario:
	 *   Background: v4suppression stores a base64-encoded CIDR/host customlist.
	 *     Given stored = base64_encode("192.168.1.1/32\r\n").
	 *     When PfbConfig::write('ip/v4suppression', PfbConfig::read('ip/v4suppression')).
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
		$val = PfbConfig::read('ip/v4suppression');
		$this->assertSame($blob, $val, 'read: v4suppression round-trips the blob unchanged');

		// After: write back produces the identical stored string.
		PfbConfig::write('ip/v4suppression', $val);
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
	 *     When PfbConfig::read('ip/v6suppression').
	 *     Then '' is returned (registered default).
	 *
	 * Red->green: before Phase 6, 'v6suppression' was not registered at all ->
	 *   PfbConfig::read('ip/v6suppression') threw InvalidArgumentException.
	 */
	public function testV6SuppressionAbsentKeyReturnsDefaultEmptyString(): void
	{
		$path = 'installedpackages/pfblockerngipsettings/config/0/v6suppression';

		// Before: absent.
		$this->assertNull(config_get_path($path), 'before: v6suppression must be absent');

		// When/Then.
		$this->assertSame('', PfbConfig::read('ip/v6suppression'), 'v6suppression absent -> ""');
	}

	/**
	 * v6suppression round-trips a base64 blob losslessly (write(read(v)) == v).
	 *
	 * Scenario:
	 *   Background: v6suppression stores a base64-encoded CIDR customlist.
	 *     Given stored = base64_encode("2001:db8::1/128\r\n").
	 *     When PfbConfig::write('ip/v6suppression', PfbConfig::read('ip/v6suppression')).
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
		$val = PfbConfig::read('ip/v6suppression');
		$this->assertSame($blob, $val, 'read: v6suppression round-trips the blob unchanged');

		// After: write back produces the identical stored string.
		PfbConfig::write('ip/v6suppression', $val);
		$this->assertSame($blob, config_get_path($path), 'write(read(blob))==blob for v6suppression');
	}

	// -----------------------------------------------------------------------
	// issue #1931 — ip/suppression (IP page "Enable Suppression" toggle;
	// path-addressed so it no longer collides with dnsbl/whitelist)
	// -----------------------------------------------------------------------

	/**
	 * ip/suppression absent key returns the registered default PfbToggle::On -- issue
	 * #1907 owner decision: this key now carries the toggle adapter, default 'on' (the
	 * de-facto page default since 3.2, matching pfblockerng_ip.php's own
	 * isset(...) ? ... : 'on' render fallback -- the #1907-class page/registry
	 * divergence this closes).
	 *
	 * Scenario:
	 *   Background: ip/suppression carries the toggle adapter, default 'on'.
	 *     Given no stored value.
	 *     When PfbConfig::read('ip/suppression').
	 *     Then PfbToggle::On is returned (registered default).
	 *
	 * Red->green: before this step, 'ip/suppression' resolved to the plain default ''.
	 */
	public function testIpSuppressionAbsentKeyReturnsOnDefault(): void
	{
		$path = 'installedpackages/pfblockerngipsettings/config/0/suppression';

		// Before: absent.
		$this->assertNull(config_get_path($path), 'before: ip suppression must be absent');

		// When/Then.
		$this->assertSame(PfbToggle::On, PfbConfig::read('ip/suppression'), 'ip/suppression absent -> On (default)');
	}

	/**
	 * writeSystem('ip/suppression', 'on') stores 'on' at the exact ipsettings
	 * path -- proves the path-addressed registry entry routes to
	 * pfblockerngipsettings/config/0, never pfblockerngdnsblsettings/config/0.
	 *
	 * Scenario:
	 *   Given no stored value.
	 *   When PfbConfig::writeSystem('ip/suppression', 'on').
	 *   Then the ipsettings path stores 'on' and the DNSBL whitelist path
	 *     stays untouched (still absent).
	 */
	public function testIpSuppressionWriteStoresAtIpsettingsPath(): void
	{
		$ip_path    = 'installedpackages/pfblockerngipsettings/config/0/suppression';
		$dnsbl_path = 'installedpackages/pfblockerngdnsblsettings/config/0/whitelist';

		PfbConfig::writeSystem('ip/suppression', 'on');

		$this->assertSame('on', config_get_path($ip_path),
			"writeSystem('ip/suppression') must store at the ipsettings path");
		$this->assertNull(config_get_path($dnsbl_path),
			'dnsbl/whitelist must stay untouched by an ip/suppression write');
	}

	/**
	 * 'ip/suppression' and 'dnsbl/whitelist' used to share the same bare key name
	 * ('suppression', pre-#1921 rename) despite resolving to different config.xml
	 * sections -- the #1931 path-addressing fix for that pre-step-A collision. The
	 * #1921 rename removes the shared spelling entirely; this test now just pins
	 * that the two keys stay independently registered and readable, each at its
	 * own default, at their own distinct paths.
	 *
	 * Scenario:
	 *   When PFB_SECTIONS resolves each alias's section path.
	 *   Then the two full paths differ, and writing one leaves the other's
	 *     value untouched.
	 */
	public function testIpSuppressionAndDnsblSuppressionResolveToDifferentPaths(): void
	{
		$ip_path    = PFB_SECTIONS['ip'] . '/suppression';
		$dnsbl_path = PFB_SECTIONS['dnsbl'] . '/whitelist';

		$this->assertNotSame($ip_path, $dnsbl_path,
			"'ip/suppression' and 'dnsbl/whitelist' must resolve to different config.xml paths");

		PfbConfig::writeSystem('ip/suppression', 'on');
		$this->assertSame(PfbToggle::On, PfbConfig::read('ip/suppression'));
		$this->assertSame('', PfbConfig::read('dnsbl/whitelist'), 'dnsbl/whitelist stays at its own default');
	}

	// -----------------------------------------------------------------------
	// ADR-43 — pfb_tick_interval retirement
	// -----------------------------------------------------------------------

	/**
	 * Retired pfb_tick_interval remains inert: PfbConfig rejects the key while raw XML stays untouched.
	 *
	 * Scenario:
	 *   Given a stale stored value of '30'.
	 *   When the retired gateway key is read.
	 *   Then it throws InvalidArgumentException and does not rewrite the raw config value.
	 */
	public function testRetiredPfbTickIntervalIsUnknownAndRawValueUnchanged(): void
	{
		$path = 'installedpackages/pfblockerng/config/0/pfb_tick_interval';
		$this->seedConfig($path, '30');
		$this->assertSame('30', config_get_path($path), "before: stale pfb_tick_interval seed is '30'");

		$caught = NULL;
		try {
			PfbConfig::read('gen/pfb_tick_interval');
		} catch (InvalidArgumentException $exception) {
			$caught = $exception;
		}

		$this->assertInstanceOf(InvalidArgumentException::class, $caught,
			'retired pfb_tick_interval must be rejected as an unknown gateway key');
		$this->assertSame('30', config_get_path($path), 'retired key read must leave stale raw value unchanged');
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
	 *     When PfbConfig::read('gen/pfb_quiet_hours').
	 *     Then '' is returned (registered default = no window, apply immediately).
	 *
	 * Red→green: before Phase 5, 'pfb_quiet_hours' was not registered →
	 *   PfbConfig::read('gen/pfb_quiet_hours') threw InvalidArgumentException.
	 */
	public function testPfbQuietHoursAbsentKeyReturnsDefault(): void
	{
		$path = 'installedpackages/pfblockerng/config/0/pfb_quiet_hours';

		// Before: absent.
		$this->assertNull(config_get_path($path), 'before: pfb_quiet_hours must be absent');

		// When/Then: absent → default '' (no window).
		$result = PfbConfig::read('gen/pfb_quiet_hours');
		$this->assertSame('', $result, 'pfb_quiet_hours absent -> default empty string');
	}

	/**
	 * pfb_quiet_hours round-trips a non-default window string.
	 *
	 * Scenario:
	 *   Background: pfb_quiet_hours is a plain-string field (no adapter).
	 *     Given stored = '02:00-06:00'.
	 *     When PfbConfig::write('gen/pfb_quiet_hours', PfbConfig::read('gen/pfb_quiet_hours')).
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
		$val = PfbConfig::read('gen/pfb_quiet_hours');
		$this->assertSame('02:00-06:00', $val,
			"read: pfb_quiet_hours '02:00-06:00' -> '02:00-06:00'");

		// After: write back produces '02:00-06:00'.
		PfbConfig::write('gen/pfb_quiet_hours', $val);
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
	 *     When PfbConfig::read('gen/pfb_log_trim_margin_pct').
	 *     Then '0' is returned.
	 */
	public function testPfbLogTrimMarginPctAbsentKeyReturnsDefaultZero(): void
	{
		$path = 'installedpackages/pfblockerng/config/0/pfb_log_trim_margin_pct';

		// Before: absent.
		$this->assertNull(config_get_path($path), 'before: pfb_log_trim_margin_pct must be absent');

		// When/Then: absent -> default '0'.
		$result = PfbConfig::read('gen/pfb_log_trim_margin_pct');
		$this->assertSame('0', $result, 'pfb_log_trim_margin_pct absent -> default 0');
	}

	/**
	 * pfb_log_trim_margin_pct round-trips losslessly for a non-default value.
	 *
	 * Scenario:
	 *   Background: pfb_log_trim_margin_pct is a plain-string field (no adapter).
	 *     Given stored = '50'.
	 *     When PfbConfig::write('gen/pfb_log_trim_margin_pct', PfbConfig::read('gen/pfb_log_trim_margin_pct')).
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
		$val = PfbConfig::read('gen/pfb_log_trim_margin_pct');
		$this->assertSame('50', $val, "read: pfb_log_trim_margin_pct '50' -> '50'");

		// After: write back produces '50'.
		PfbConfig::write('gen/pfb_log_trim_margin_pct', $val);
		$this->assertSame('50', config_get_path($path), "write(read('50'))=='50' for pfb_log_trim_margin_pct");
	}

	public function testPfbLogTrimMarginPctSurvivesSectionWrite(): void
	{
		// The UI saves the whole section (writeSection), never a per-field write, so the
		// per-field round-trip above cannot catch a key dropped on the section path. Tier-B
		// covers the real save, but it is schedule-only -- this is the PR-gated guard.
		$path = 'installedpackages/pfblockerng/config/0/pfb_log_trim_margin_pct';

		$this->seedConfig($path, '0');
		$this->assertSame('0', config_get_path($path), "before: pfb_log_trim_margin_pct seed is '0'");

		// The exact readSection/writeSection shape pfblockerng_general.php saves with.
		$gen = 'installedpackages/pfblockerng/config/0';
		$section = PfbConfig::readSection($gen);
		$section['pfb_log_trim_margin_pct'] = '50';
		PfbConfig::writeSection($gen, $section);

		$this->assertSame('50', config_get_path($path),
			'the section write must carry pfb_log_trim_margin_pct -- a key dropped here saves nothing from the UI'
		);
		$this->assertSame('50', PfbConfig::read('gen/pfb_log_trim_margin_pct'), 'and the gateway must read it back');
	}

	// ADR-38 — log_syslog (toggle; Amendment 1: facility/priority removed)
	// -----------------------------------------------------------------------

	/**
	 * log_syslog toggle field round-trips losslessly for 'on' (enabled).
	 *
	 * Scenario:
	 *   Background: log_syslog is a PfbToggle field; vocabulary = {'on', ''}.
	 *     Given stored = 'on'.
	 *     When PfbConfig::write('gen/log_syslog', PfbConfig::read('gen/log_syslog')).
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
		$enum = PfbConfig::read('gen/log_syslog');
		$this->assertSame(PfbToggle::On, $enum, "read: log_syslog 'on' -> PfbToggle::On");

		// After: write back produces 'on'.
		PfbConfig::write('gen/log_syslog', $enum);
		$this->assertSame('on', config_get_path($path), "write(read('on'))==on for log_syslog");
	}

	/**
	 * log_syslog toggle field round-trips losslessly for '' (disabled).
	 *
	 * Scenario:
	 *   Background: log_syslog vocabulary = {'on', ''}.
	 *     Given stored = '' (unchecked / off).
	 *     When PfbConfig::write('gen/log_syslog', PfbConfig::read('gen/log_syslog')).
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
		$enum = PfbConfig::read('gen/log_syslog');
		$this->assertSame(PfbToggle::Off, $enum, "read: log_syslog '' -> PfbToggle::Off");

		// After: write back emits the empty checkbox token.
		PfbConfig::write('gen/log_syslog', $enum);
		$this->assertSame('', config_get_path($path), "write(read(''))=='' for log_syslog");
	}

	/**
	 * log_syslog absent key returns PfbToggle::Off (default '' applied via toggle adapter).
	 *
	 * Scenario:
	 *   Background: log_syslog registered default is '' (off).
	 *     Given no stored value.
	 *     When PfbConfig::read('gen/log_syslog').
	 *     Then PfbToggle::Off is returned (registered default '').
	 */
	public function testLogSyslogAbsentKeyReturnsOffDefault(): void
	{
		$path = 'installedpackages/pfblockerng/config/0/log_syslog';

		// Before: absent.
		$this->assertNull(config_get_path($path), 'before: log_syslog must be absent');

		// When/Then: default '' → PfbToggle::Off.
		$result = PfbConfig::read('gen/log_syslog');
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
	 *     maxmind_key, etc. ADR-53 registered v4suppression + v6suppression; issue
	 *     #1931 registers 'suppression' too, as path-addressed 'ip/suppression' --
	 *     distinct storage from the already-registered 'dnsbl/whitelist' (pre-#1921
	 *     rename: dnsbl alias, bare key suppression, despite the shared bare name).
	 *     All three are NOT on this out-of-scope list; only their still-foreign
	 *     ipsettings siblings are.
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

		// issue #1931 (pre-#1921 rename: shared its bare key with the then-registered
		// dnsbl alias's bare-key suppression, so the bare-key inventory below couldn't
		// distinguish the two) -- assert the alias-qualified registration directly
		// regardless.
		$this->assertArrayHasKey('ip/suppression', $registry,
			"'ip/suppression' must be registered (issue #1931)");

		// issue #1931: registry keys are now '<alias>/<bare-key>'; this inventory compares
		// against the bare config.xml names below, so strip the alias prefix back off.
		$registered_keys = array_map(
			static fn (string $path_key): string => substr($path_key, strpos($path_key, '/') + 1),
			array_keys($registry)
		);

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
			// (v4suppression is registered -- ADR-53 -- and lives in the registry, not here.
			// issue #2123 moved enable_dup / enable_agg / enable_log / enable_rdns /
			// database_cc / enable_float / killstates off this list into the registry.)
			'maxmind_key',
			'maxmind_locale',
			'asn_reporting',
			'asn_token',
			'maxmind_account',
			'inbound_deny_action',
			'outbound_deny_action',
			'pass_order',
			'autorule_suffix',
			'ip_placeholder',

			// pfblockerngreputation sub-keys.
			'et_header',

			// pfblockerngsync sub-keys. (issue #2123 registered 'syncinterfaces' as
			// 'sync/syncinterfaces'; its siblings here stay foreign.)
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
			'pfb_scheduled_feed_updates',
			'pfb_schedule_weekday',
			'pfb_schedule_hour',
			'pfb_schedule_minute',
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
			// ADR-43: apply-on-change window
			'pfb_quiet_hours',
			// issue #1109: log-retention trim hysteresis margin percent
			'pfb_log_trim_margin_pct',
			// ADR-38: syslog export toggle
			'log_syslog',
			// issue #1669 slice C: CodeMirror 6 live syntax-highlight toggle (default on)
			'pfb_syntax_highlight',

			// pfblockerngdnsblsettings/config/0 scalars
			'pfb_dnsbl',
			'pfb_dnsvip_auto',
			'pfb_dnsbl_nonat',
			'dnsbl_interface',
			'pfb_dnsvip4',
			'pfb_dnsvip6',
			'pfb_dnsport',
			'pfb_dnsport_ssl',
			'top1m_enable',
			'top1m_source',
			'top1m_count',
			'top1m_inclusion',
			'top1m_token', // ADR-59 P5
			'pfb_cache',
			'pfb_cache_flush',
			'global_log',
			'pfb_dnsbl_lenient',
			'pfb_py_reply',
			'pfb_hsts',
			'pfb_idn',
			'pfb_idn_block_malicious',
			'pfb_idn_escalate_suspicious',
			'pfb_psl_include_private',
			'pfb_psl_allow_private',
			// issue #2371: feed-at-suffix PSL policy fields
			'pfb_psl_feed_private_policy',
			'pfb_psl_feed_icann_policy',
			'pfb_regex',
			'pfb_regex_list',
			'pfb_regex_cap',
			'pfb_cname',
			'tld_allow',
			// issue #1921: TLD Allow sort + bucket scalars (renamed from pfb_pytld* by #1898).
			'tld_allow_sort',
			'tld_allow_gtld',
			'tld_allow_cctld',
			'tld_allow_itld',
			'tld_allow_bgtld',
			'pfb_py_nolog',
			'pfb_noaaaa',
			'pfb_noaaaa_list',
			'pfb_gp',
			'pfb_gp_bypass_list',
			'tld_wildcard_blacklist',
			'tld_wildcard_exclusion',
			'whitelist',
			'action',
			'pfb_dnsbl_rule',
			'dnsbl_allow_int',
			'pfb_control',
			'pfb_control_legacy',
			'pfb_py_cache_max',
			'tld_wildcard',
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

			// pfblockerngreputation/config/0 scalars (issue #1896)
			'enable_rep',
			'enable_pdup',
			'enable_dedup',

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
		$this->seedConfig('installedpackages/pfblockerng/config/0/pfb_schedule_hour', '6');
		$this->assertSame('6', PfbConfig::read('gen/pfb_schedule_hour'));

		// DNSBL settings section key.
		$this->seedConfig('installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsport', '8080');
		$this->assertSame('8080', PfbConfig::read('dnsbl/pfb_dnsport'));

		// SafeSearch section key (flat, no /config/0).
		$this->seedConfig('installedpackages/pfblockerngsafesearch/safesearch_enable', 'Google');
		$this->assertSame('Google', PfbConfig::read('ss/safesearch_enable'));
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
		$this->assertNull(config_get_path('installedpackages/pfblockerng/config/0/pfb_schedule_hour'));

		// When.
		PfbConfig::write('gen/pfb_schedule_hour', '12');

		// After: stored.
		$this->assertSame('12', config_get_path('installedpackages/pfblockerng/config/0/pfb_schedule_hour'));
	}

	public function testWriteAppliesToggleAdapterBeforeStorage(): void
	{
		// PfbToggle::On enum must be converted to the stored string 'on'.
		$path = 'installedpackages/pfblockerng/config/0/enable_cb';

		// Before: absent.
		$this->assertNull(config_get_path($path));

		// When: write enum value.
		PfbConfig::write('gen/enable_cb', PfbToggle::On);

		// After: stored as the string 'on', not an enum object.
		$this->assertSame('on', config_get_path($path));
	}

	public function testWriteToggleFieldAcceptsLegacyStringValue(): void
	{
		// Regression: pfblockerng_update.php Force Reload calls
		// PfbConfig::write('gen/pfb_reuse', 'on') with a raw string. The toggle
		// write adapter must accept it (enum-or-string contract) and store
		// the exact legacy token — previously a TypeError.
		$path = 'installedpackages/pfblockerng/config/0/pfb_reuse';

		// Before: absent.
		$this->assertNull(config_get_path($path));

		// When: write the raw legacy string (not the enum).
		PfbConfig::write('gen/pfb_reuse', 'on');

		// After: stored as the string 'on'.
		$this->assertSame('on', config_get_path($path));
	}

	public function testWriteEmitsExplicitOffTokenBeforeStorage(): void
	{
		$path = 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl_lenient';

		// Before: absent.
		$this->assertNull(config_get_path($path));

		// When: write Off enum.
		PfbConfig::write('dnsbl/pfb_dnsbl_lenient', PfbToggle::Off);

		// After: stored as the empty checkbox token; PfbToggle::Off backing remains 'off'.
		$this->assertSame('', config_get_path($path));
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
		$path = 'installedpackages/pfblockerng/config/0/pfb_schedule_hour';

		// Given.
		$this->seedConfig($path, '3');
		$this->assertSame('3', config_get_path($path), 'before: key is set');

		// When.
		PfbConfig::delete('gen/pfb_schedule_hour');

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
		$data    = ['enable_cb' => 'on', 'pfb_keep' => 'on', 'pfb_schedule_hour' => '6'];

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
	 * AND the established block-all-IDN behaviour remains unchanged.
	 *
	 * Scenario:
	 *   Background: pfb_idn stored as 'on' (canonical, = All).
	 *     Given pfb_idn = 'on'.
	 *     When PfbConfig::read('dnsbl/pfb_idn').
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
		$result = PfbConfig::read('dnsbl/pfb_idn');

		// Then: PfbIdnMode::All (adapter IS wired — NOT raw string).
		$this->assertInstanceOf(PfbIdnMode::class, $result, 'pfb_idn must return a PfbIdnMode enum');
		$this->assertSame(PfbIdnMode::All, $result, "pfb_idn 'on' -> PfbIdnMode::All");

		// And: write(read('on')) stores 'on' — canonical identity.
		PfbConfig::write('dnsbl/pfb_idn', $result);
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
		$result = PfbConfig::read('dnsbl/pfb_idn');
		$this->assertInstanceOf(PfbIdnMode::class, $result, 'pfb_idn must return a PfbIdnMode enum');
		$this->assertSame(PfbIdnMode::Off, $result, "pfb_idn 'all' (dropped alpha token) -> PfbIdnMode::Off");

		// Write emits the canonical empty Off token — 'all' is not re-emitted.
		PfbConfig::write('dnsbl/pfb_idn', $result);
		$stored = config_get_path($path);
		$this->assertSame('', $stored, "write(read('all')) == '' for pfb_idn");
		$this->assertNotSame('all', $stored, "'all' must not be re-emitted");
	}

	// -----------------------------------------------------------------------
	// D (extra) — Registry completeness: every registered key has all required fields
	// -----------------------------------------------------------------------

	/**
	 * Every registry entry has the required shape: section, default, read_adapter,
	 * write_adapter — and adapters are callable|null.
	 */
	public function testRegistryEntriesHaveRequiredShape(): void
	{
		$registry       = pfb_cfg_registry();
		$required_keys  = ['default', 'read_adapter', 'write_adapter'];

		$this->assertNotEmpty($registry, 'Registry must not be empty');

		foreach ($registry as $field_key => $entry) {
			foreach ($required_keys as $k) {
				$this->assertArrayHasKey($k, $entry,
					"Registry entry '{$field_key}' missing required key '{$k}'"
				);
			}

			// issue #1931: entries no longer carry a 'section' -- the path key's alias
			// prefix resolves through PFB_SECTIONS instead.
			$this->assertArrayNotHasKey('section', $entry, "'{$field_key}' must not carry a 'section' field");

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

		}
	}

	/**
	 * Default-on adapter fields are valid: adapter presence distinguishes absent
	 * (registered default) from present empty (Off), and PfbToggle writes empty.
	 * The old no-default-on invariant was retired by issue #2120.
	 */
	// testNoToggleFieldDefaultsToOn retired by issue #1887/#2120; the adapter-presence
	// distinction is pinned by ConfigEmptyStorageContractTest.

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
			$key = 'gen/log_max_days_' . $type;
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
				$cases["log_max_days_{$type}/{$token}"] = ["gen/log_max_days_{$type}", $token];
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
		$path = 'installedpackages/pfblockerng/config/0/' . substr($key, strlen('gen/'));

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
			$bare = 'log_max_days_' . $type;
			$path = 'installedpackages/pfblockerng/config/0/' . $bare;

			// Before: absent.
			$this->assertNull(config_get_path($path),
				"before: {$bare} must be absent"
			);

			// When/Then: default '0' returned.
			$result = PfbConfig::read('gen/' . $bare);
			$this->assertSame('0', $result,
				"{$bare} absent must return '0' (registered default)"
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
	 *     When PfbConfig::read('gen/log_max_ip_parse_err').
	 *     Then '20000' is returned (registered default; matches every sibling log_max_<type>).
	 */
	public function testLogMaxIpParseErrAbsentKeyReturnsDefault20000(): void
	{
		$path = 'installedpackages/pfblockerng/config/0/log_max_ip_parse_err';

		// Before: absent.
		$this->assertNull(config_get_path($path), 'before: log_max_ip_parse_err must be absent');

		// When/Then: default '20000' returned.
		$this->assertSame('20000', PfbConfig::read('gen/log_max_ip_parse_err'),
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
	 *     When PfbConfig::write('dnsbl/dnsbl_redir', PfbConfig::read('dnsbl/dnsbl_redir')).
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
		$enum = PfbConfig::read('dnsbl/dnsbl_redir');
		$this->assertSame(PfbToggle::On, $enum, 'read: on -> PfbToggle::On');

		PfbConfig::write('dnsbl/dnsbl_redir', $enum);

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
		$enum = PfbConfig::read('dnsbl/dnsbl_redir');
		$this->assertSame(PfbToggle::Off, $enum, "read: '' -> PfbToggle::Off");

		PfbConfig::write('dnsbl/dnsbl_redir', $enum);

		// After: stored as the empty checkbox token.
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
	 *     When PfbConfig::read('dnsbl/dnsbl_redir').
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
		$result = PfbConfig::read('dnsbl/dnsbl_redir');
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
	 *     When PfbConfig::write('dnsbl/dnsbl_redir_int', PfbConfig::read('dnsbl/dnsbl_redir_int')).
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
		$value = PfbConfig::read('dnsbl/dnsbl_redir_int');
		$this->assertSame('lan,opt1', $value,
			'read: plain adapter returns raw stored string'
		);

		PfbConfig::write('dnsbl/dnsbl_redir_int', $value);

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
		$value = PfbConfig::read('dnsbl/dnsbl_redir_int');
		$this->assertSame('', $value, "read: '' returns ''");

		PfbConfig::write('dnsbl/dnsbl_redir_int', $value);

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
	 *     When PfbConfig::read('dnsbl/dnsbl_redir_int').
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
		$result = PfbConfig::read('dnsbl/dnsbl_redir_int');
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
	 *     When PfbConfig::write('dnsbl/dnsbl_redir_exclude', PfbConfig::read('dnsbl/dnsbl_redir_exclude')).
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
		$value = PfbConfig::read('dnsbl/dnsbl_redir_exclude');
		$this->assertSame('DNS_Whitelist', $value,
			'read: plain adapter returns raw stored string'
		);

		PfbConfig::write('dnsbl/dnsbl_redir_exclude', $value);

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
		$value = PfbConfig::read('dnsbl/dnsbl_redir_exclude');
		$this->assertSame('', $value, "read: '' returns ''");

		PfbConfig::write('dnsbl/dnsbl_redir_exclude', $value);

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
	 *     When PfbConfig::read('dnsbl/dnsbl_redir_exclude').
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
		$result = PfbConfig::read('dnsbl/dnsbl_redir_exclude');
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
	 *     When PfbConfig::write('dnsbl/dnsbl_dot_block', PfbConfig::read('dnsbl/dnsbl_dot_block')).
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
		$enum = PfbConfig::read('dnsbl/dnsbl_dot_block');
		$this->assertSame(PfbToggle::On, $enum, 'read: on -> PfbToggle::On');

		PfbConfig::write('dnsbl/dnsbl_dot_block', $enum);

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
		$enum = PfbConfig::read('dnsbl/dnsbl_dot_block');
		$this->assertSame(PfbToggle::Off, $enum, "read: '' -> PfbToggle::Off");

		PfbConfig::write('dnsbl/dnsbl_dot_block', $enum);

		// After: stored as the empty checkbox token.
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
	 *     When PfbConfig::read('dnsbl/dnsbl_dot_block').
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
		$result = PfbConfig::read('dnsbl/dnsbl_dot_block');
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
	 *     When PfbConfig::write('dnsbl/dnsbl_dot_block_int', PfbConfig::read('dnsbl/dnsbl_dot_block_int')).
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
		$value = PfbConfig::read('dnsbl/dnsbl_dot_block_int');
		$this->assertSame('lan,opt1', $value,
			'read: plain adapter returns raw stored string'
		);

		PfbConfig::write('dnsbl/dnsbl_dot_block_int', $value);

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
	 *     When PfbConfig::read('dnsbl/dnsbl_dot_block_int').
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
		$result = PfbConfig::read('dnsbl/dnsbl_dot_block_int');
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
	 *     When PfbConfig::write('dnsbl/dnsbl_dot_block_exclude', PfbConfig::read('dnsbl/dnsbl_dot_block_exclude')).
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
		$value = PfbConfig::read('dnsbl/dnsbl_dot_block_exclude');
		$this->assertSame('DoT_Exceptions', $value,
			'read: plain adapter returns raw stored string'
		);

		PfbConfig::write('dnsbl/dnsbl_dot_block_exclude', $value);

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
	 *     When PfbConfig::read('dnsbl/dnsbl_dot_block_exclude').
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
		$result = PfbConfig::read('dnsbl/dnsbl_dot_block_exclude');
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
			'pfb_cfg_idn_mode_read'         => ['on', 'confusable', 'off', 'all', 'junk'],
			'pfb_cfg_top1m_source_read'     => ['tranco', 'cisco', 'openpagerank', 'majestic', 'cloudflare', 'alexa', 'domcop', 'junk'],
			'pfb_cfg_alias_delta_mode_read' => ['auto', 'delta', 'replace', '', 'junk'],
			'pfb_cfg_feed_suffix_policy_read' => ['ignore', 'apex', 'honor', '', 'junk'],
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

			// issue #1931: $key is now '<alias>/<bare>'; resolve the real section path
			// via PFB_SECTIONS and use the bare part for the section-blob key.
			[$alias, $bare] = explode('/', $key, 2);
			$section = PFB_SECTIONS[$alias];
			$path    = $section . '/' . $bare;

			foreach ($samples_by_read_adapter[$read_adapter] as $raw) {
				// Oracle: PfbConfig::write() on a fresh slate.
				$GLOBALS['config'] = [];
				PfbConfig::write($key, $raw);
				$expected = config_get_path($path);

				// Under test: PfbConfig::writeSection() on a fresh slate.
				$GLOBALS['config'] = [];
				PfbConfig::writeSection($section, [$bare => $raw]);
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
	 * top1m_source token riding a section blob write is no longer re-emitted raw --
	 * it is coalesced to the canonical 'openpagerank' token, same as a single-key
	 * PfbConfig::write('dnsbl/top1m_source', 'domcop') would.
	 *
	 * Scenario:
	 *   Given a DNSBL settings blob with the legacy 'domcop' top1m_source token.
	 *   When PfbConfig::writeSection() persists it.
	 *   Then the stored top1m_source is 'openpagerank', never the dead 'domcop' token.
	 */
	public function testWriteSectionAlexaTypeLegacyDomcopNormalisesToOpenPageRank(): void
	{
		$section = 'installedpackages/pfblockerngdnsblsettings/config/0';
		$path    = $section . '/top1m_source';

		PfbConfig::writeSection($section, ['top1m_source' => 'domcop']);

		$this->assertSame('openpagerank', config_get_path($path),
			"legacy 'domcop' riding a section write coalesces to 'openpagerank'"
		);
	}

	/**
	 * Legacy 'alexa' (dead TOP1M service, #872) riding a section blob write
	 * coalesces to the canonical 'tranco' token.
	 *
	 * Scenario:
	 *   Given a DNSBL settings blob with the legacy 'alexa' top1m_source token.
	 *   When PfbConfig::writeSection() persists it.
	 *   Then the stored top1m_source is 'tranco', never the dead 'alexa' token.
	 */
	public function testWriteSectionAlexaTypeLegacyAlexaNormalisesToTranco(): void
	{
		$section = 'installedpackages/pfblockerngdnsblsettings/config/0';
		$path    = $section . '/top1m_source';

		PfbConfig::writeSection($section, ['top1m_source' => 'alexa']);

		$this->assertSame('tranco', config_get_path($path),
			"legacy 'alexa' riding a section write coalesces to 'tranco'"
		);
	}

	/**
	 * A live canonical top1m_source token ('cisco') riding a section blob write
	 * passes through byte-identical -- normalisation never mangles a live token.
	 *
	 * Scenario:
	 *   Given a DNSBL settings blob with the canonical 'cisco' top1m_source token.
	 *   When PfbConfig::writeSection() persists it.
	 *   Then the stored top1m_source is still 'cisco'.
	 */
	public function testWriteSectionAlexaTypeCanonicalCiscoPassesThroughUnchanged(): void
	{
		$section = 'installedpackages/pfblockerngdnsblsettings/config/0';
		$path    = $section . '/top1m_source';

		PfbConfig::writeSection($section, ['top1m_source' => 'cisco']);

		$this->assertSame('cisco', config_get_path($path),
			"canonical 'cisco' riding a section write is byte-identical"
		);
	}

	/**
	 * pfb_idn: the dropped 4.0.0-alpha-only 'all' token riding a section blob
	 * write normalises to empty (never re-emits legacy 'off'); the canonical 'on' token
	 * (= PfbIdnMode::All) stays 'on' unchanged.
	 *
	 * Scenario:
	 *   Given a DNSBL settings blob with pfb_idn = the alpha-only 'all' token.
	 *   When PfbConfig::writeSection() persists it.
	 *   Then the stored pfb_idn is empty Off, never the dropped 'all' token.
	 *   And a canonical 'on' token riding the same path stays 'on'.
	 */
	public function testWriteSectionPfbIdnAlphaOnlyAllNormalisesToOff(): void
	{
		$section = 'installedpackages/pfblockerngdnsblsettings/config/0';
		$path    = $section . '/pfb_idn';

		// Alpha-only 'all' -> normalised to empty Off.
		PfbConfig::writeSection($section, ['pfb_idn' => 'all']);
		$this->assertSame('', config_get_path($path),
			"dropped alpha-only 'all' riding a section write normalises to ''"
		);

		// Canonical 'on' -> stays 'on'.
		PfbConfig::writeSection($section, ['pfb_idn' => 'on']);
		$this->assertSame('on', config_get_path($path),
			"canonical 'on' riding a section write is byte-identical"
		);
	}

	/**
	 * pfb_keep: the legacy empty-string token (pre-#484 absent-key install)
	 * riding a section blob write preserves the explicit empty Off token, same
	 * as the single-key PfbConfig::write() toggle contract.
	 *
	 * Scenario:
	 *   Given a General settings blob with pfb_keep = '' (legacy empty).
	 *   When PfbConfig::writeSection() persists it.
	 *   Then the stored pfb_keep remains '', and legacy 'off' is never written.
	 */
	public function testWriteSectionPfbKeepEmptyPreservesExplicitOff(): void
	{
		$section = 'installedpackages/pfblockerng/config/0';
		$path    = $section . '/pfb_keep';

		PfbConfig::writeSection($section, ['pfb_keep' => '']);

		$this->assertSame('', config_get_path($path),
			"'' is the checkbox Off token and remains empty on a section write"
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
			"junk toggle value 'yes' riding a section write parse-falls-back to empty"
		);
	}

	/**
	 * Hostile input: a crafted array value (e.g. a POST array
	 * top1m_source[]=x) riding a section blob write hits the adapter's
	 * non-scalar guard and normalises to the parse-fallback default, never
	 * crashes and never persists the raw array.
	 *
	 * Scenario:
	 *   Given a DNSBL settings blob with top1m_source = ['x'] (non-scalar).
	 *   When PfbConfig::writeSection() persists it.
	 *   Then the stored top1m_source is 'tranco' (the non-scalar-guard default).
	 */
	public function testWriteSectionAlexaTypeArrayValueNormalisesToDefaultTranco(): void
	{
		$section = 'installedpackages/pfblockerngdnsblsettings/config/0';
		$path    = $section . '/top1m_source';

		PfbConfig::writeSection($section, ['top1m_source' => ['x']]);

		$this->assertSame('tranco', config_get_path($path),
			'array-valued top1m_source riding a section write hits the non-scalar guard -> tranco'
		);
	}

	/**
	 * Hostile input: a NULL value on an adapted key riding a section blob write
	 * is not a TypeError -- NULL deletes the adapted key.
	 *
	 * Scenario:
	 *   Given a General settings blob with pfb_keep = NULL.
	 *   When PfbConfig::writeSection() persists it.
	 *   Then the stored pfb_keep key is absent, no crash.
	 */
	public function testWriteSectionNullValueDeletesAdapterKey(): void
	{
		$section = 'installedpackages/pfblockerng/config/0';
		$path    = $section . '/pfb_keep';

		PfbConfig::writeSection($section, ['pfb_keep' => NULL]);

		$this->assertNull(config_get_path($path), 'NULL section writes delete adapted keys');
	}

	/**
	 * Hostile input / idempotency: an already-adapted enum instance (e.g. fed
	 * back through from a prior PfbConfig::read()) riding a section blob write
	 * is not double-mangled -- the read adapter's `instanceof static` passthrough
	 * returns it as-is, and the write adapter emits its canonical token.
	 *
	 * Scenario:
	 *   Given a DNSBL settings blob with top1m_source = PfbTop1mSource::Cisco (an
	 *     enum instance, not a raw string).
	 *   When PfbConfig::writeSection() persists it.
	 *   Then the stored top1m_source is 'cisco', not mangled by a double-apply.
	 */
	public function testWriteSectionAlexaTypeEnumInstanceIsIdempotent(): void
	{
		$section = 'installedpackages/pfblockerngdnsblsettings/config/0';
		$path    = $section . '/top1m_source';

		PfbConfig::writeSection($section, ['top1m_source' => PfbTop1mSource::Cisco]);

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
	 *   Given a DNSBL settings blob with top1m_source = 1 (int, not a string token).
	 *   When PfbConfig::writeSection() persists it.
	 *   Then the stored top1m_source is 'tranco' (the parse-fallback default).
	 */
	public function testWriteSectionAlexaTypeIntValueNormalisesToDefaultTranco(): void
	{
		$section = 'installedpackages/pfblockerngdnsblsettings/config/0';
		$path    = $section . '/top1m_source';

		PfbConfig::writeSection($section, ['top1m_source' => 1]);

		$this->assertSame('tranco', config_get_path($path),
			'int-valued top1m_source riding a section write normalises to the parse-fallback tranco'
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
	 *     'top1m_source' (foreign to this section -- the registry maps top1m_source
	 *     to the DNSBL section only) with the legacy 'domcop' value.
	 *   When PfbConfig::writeSection() persists it against the SYNC section.
	 *   Then the stored value is the raw 'domcop' -- no normalisation applied,
	 *     because no registry entry has 'section' === the sync section for
	 *     this key.
	 */
	public function testWriteSectionAdaptedKeyNameInForeignSectionStaysRaw(): void
	{
		$section = 'installedpackages/pfblockerngsync/config/0';
		$path    = $section . '/top1m_source';

		PfbConfig::writeSection($section, ['top1m_source' => 'domcop']);

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
	 *   Given a DNSBL settings blob mixing legacy top1m_source/pfb_idn tokens with
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
			'top1m_source'      => 'domcop',        // adapted (top1m_source), LEGACY -> normalises.
			'pfb_idn'         => 'all',           // adapted (idn_mode), ALPHA-ONLY -> normalises.
			'pfb_hsts'        => 'on',            // adapted (toggle), canonical.
			'dnsbl_interface' => 'lo0',           // unadapted, plain.
			'pfb_dnsvip4'     => '',              // unadapted, plain.
			'top1m_token'     => 'QWJjMTIz',      // unadapted, plain (base64-shaped).
			// issue #2371: adapted (feed_suffix_policy), HOSTILE junk -> normalises to Honor.
			'pfb_psl_feed_private_policy' => 'suppress',
		];

		PfbConfig::writeSection($section, $data);

		$result = PfbConfig::readSection($section);

		$this->assertSame('on', $result['pfb_dnsbl'], 'pfb_dnsbl canonical stays on');
		$this->assertSame('openpagerank', $result['top1m_source'], "legacy 'domcop' normalises to 'openpagerank'");
		$this->assertSame('', $result['pfb_idn'], "alpha-only 'all' normalises to empty");
		$this->assertSame('on', $result['pfb_hsts'], 'pfb_hsts canonical stays on');
		$this->assertSame('lo0', $result['dnsbl_interface'], 'unadapted dnsbl_interface is byte-identical');
		$this->assertSame('', $result['pfb_dnsvip4'], 'unadapted pfb_dnsvip4 is byte-identical');
		$this->assertSame('QWJjMTIz', $result['top1m_token'], 'unadapted top1m_token is byte-identical');
		$this->assertSame('honor', $result['pfb_psl_feed_private_policy'], "hostile 'suppress' normalises to 'honor'");
		$this->assertArrayNotHasKey('pfb_psl_feed_icann_policy', $result,
			'a key absent from the input section blob stays absent (writeSection never materialises an untouched sibling)');
	}

	/**
	 * issue #1896: a realistic Reputation save blob (mirrors
	 * pfblockerng_geoip.inc's Reputation save handler) mixing the three newly
	 * registered toggles with unadapted plain fields. The unchecked toggle
	 * ('') remains the canonical empty Off token; every unadapted field
	 * (p24_dmax_var, et_header, ccexclude) is byte-identical.
	 *
	 * Scenario:
	 *   Given a Reputation section blob with enable_rep checked ('on'),
	 *     enable_pdup/enable_dedup unchecked (''), and unadapted plain fields.
	 *   When PfbConfig::writeSection() persists it.
	 *   Then enable_rep stays 'on', enable_pdup/enable_dedup normalise to
	 *     'off', and every unadapted field is byte-identical to the input.
	 */
	public function testWriteSectionReputationBlobNormalisesAdaptedFieldsOnly(): void
	{
		$section = 'installedpackages/pfblockerngreputation/config/0';

		$data = [
			'enable_rep'    => 'on',     // adapted (toggle), canonical.
			'enable_pdup'   => '',       // adapted (toggle), unchecked -> remains empty.
			'enable_dedup'  => '',       // adapted (toggle), unchecked -> remains empty.
			'p24_dmax_var'  => '5',      // unadapted, plain.
			'et_header'     => '',       // unadapted, plain.
			'ccexclude'     => 'US,CA',  // unadapted, plain.
		];

		PfbConfig::writeSection($section, $data);

		$result = PfbConfig::readSection($section);

		$this->assertSame('on', $result['enable_rep'], 'enable_rep canonical stays on');
		$this->assertSame('', $result['enable_pdup'], "unchecked enable_pdup ('') remains empty");
		$this->assertSame('', $result['enable_dedup'], "unchecked enable_dedup ('') remains empty");
		$this->assertSame('5', $result['p24_dmax_var'], 'unadapted p24_dmax_var is byte-identical');
		$this->assertSame('', $result['et_header'], 'unadapted et_header is byte-identical');
		$this->assertSame('US,CA', $result['ccexclude'], 'unadapted ccexclude is byte-identical');
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

		PfbConfig::write('gen/pfb_keep', 'on');
		PfbConfig::read('gen/pfb_keep');
		PfbConfig::delete('gen/pfb_keep');
		PfbConfig::readSection('installedpackages/pfblockerng/config/0');
		PfbConfig::writeSection('installedpackages/pfblockerng/config/0', ['pfb_keep' => '', 'pfb_schedule_hour' => '1']);
		PfbConfig::deleteSection('installedpackages/pfblockerng/config/0');

		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls'],
			'PfbConfig must never call write_config() -- the caller flushes');

		unset($GLOBALS['pfb_test_write_config_calls']);
	}

	// -----------------------------------------------------------------------
	// F — issue #1931: path-addressed registry parity oracle + alias-prefix gate
	// -----------------------------------------------------------------------

	/**
	 * Parity oracle: every fixture entry (bare key -> {section, default,
	 * read_adapter, write_adapter, write_priv?}), captured from the pre-#1931
	 * registry, must still resolve identically once its section is flipped to
	 * an alias via PFB_SECTIONS and joined onto the bare key. Iterates the
	 * FIXTURE, never the live registry -- additions to the registry stay
	 * legal; only a removal or a changed field on an existing entry fails.
	 *
	 * issue #1907: the fixture pins the #1931 re-key TRANSITION (that flipping bare
	 * keys to alias/bare paths changed nothing else), not future default-value
	 * decisions -- so pfb_cache/pfb_py_reply/pfb_hsts's rows were updated in step with
	 * the registry (default '' -> 'on'; pfb_cache/pfb_py_reply additionally gained the
	 * toggle adapter pfb_hsts already carried) rather than frozen against it.
	 */
	public function testPathKeyedRegistryMatchesPre1931ParityFixture(): void
	{
		$fixture_path = __DIR__ . '/fixtures/cfg_registry_pre1931_parity.json';
		$fixture      = json_decode((string) file_get_contents($fixture_path), TRUE);
		$this->assertIsArray($fixture, 'parity fixture must decode to an array');
		$this->assertCount(102, $fixture, 'parity fixture must carry exactly 102 entries (guards a truncated oracle)');

		$alias_of_section = array_flip(PFB_SECTIONS);
		$registry         = pfb_cfg_registry();
		$retired = ['pfb_interval', 'pfb_min', 'pfb_hour', 'pfb_dailystart'];
		foreach ($retired as $bare) {
			$this->assertArrayHasKey($bare, $fixture, "historical fixture must retain retired key '{$bare}'");
		}

		foreach ($fixture as $bare => $expected) {
			if (in_array($bare, $retired, TRUE)) {
				continue;
			}
			$this->assertArrayHasKey($expected['section'], $alias_of_section,
				"fixture entry '{$bare}': section '{$expected['section']}' has no PFB_SECTIONS alias"
			);
			$path_key = $alias_of_section[$expected['section']] . '/' . $bare;

			$this->assertArrayHasKey($path_key, $registry,
				"registry must still carry '{$path_key}' (fixture bare key '{$bare}')"
			);
			$actual = $registry[$path_key];

			if ($bare !== 'skipfeed') {
				$this->assertSame($expected['default'], $actual['default'], "{$path_key}: default must match the fixture");
			} else {
				$this->assertSame('0', $expected['default'], 'historical skipfeed fixture remains unlimited');
				$this->assertSame('3', $actual['default'], 'fresh-install skipfeed default is 3');
			}
			$this->assertSame($expected['read_adapter'], $actual['read_adapter'], "{$path_key}: read_adapter must match the fixture");
			$this->assertSame($expected['write_adapter'], $actual['write_adapter'], "{$path_key}: write_adapter must match the fixture");
			$this->assertSame(
				array_key_exists('write_priv', $expected),
				array_key_exists('write_priv', $actual),
				"{$path_key}: write_priv presence must match the fixture"
			);
			if (array_key_exists('write_priv', $expected)) {
				$this->assertSame($expected['write_priv'], $actual['write_priv'], "{$path_key}: write_priv value must match the fixture");
			}
		}
	}

	/**
	 * Pure helper: one violation message per registry key that is not exactly
	 * '<alias>/<bare>' with alias in PFB_SECTIONS and bare non-empty containing
	 * no '/'. A typo'd alias or a bare (unprefixed) key must fail this gate
	 * instead of silently minting a new section.
	 *
	 * @param  array<string,mixed> $registry
	 * @return list<string>
	 */
	private static function violations(array $registry): array
	{
		$violations = [];
		foreach (array_keys($registry) as $key) {
			$slash = strpos($key, '/');
			if ($slash === FALSE) {
				$violations[] = "'{$key}': no alias prefix";
				continue;
			}
			$alias = substr($key, 0, $slash);
			$bare  = substr($key, $slash + 1);
			if (!array_key_exists($alias, PFB_SECTIONS)) {
				$violations[] = "'{$key}': unknown alias '{$alias}'";
				continue;
			}
			if ($bare === '' || str_contains($bare, '/')) {
				$violations[] = "'{$key}': malformed bare key '{$bare}'";
			}
		}
		return $violations;
	}

	public function testRegistryHasNoAliasPrefixViolations(): void
	{
		$this->assertSame([], self::violations(pfb_cfg_registry()));
	}

	/**
	 * Vacuity proof: violations() actually fires on the three ways a registry
	 * key can be malformed, so testRegistryHasNoAliasPrefixViolations() is not
	 * passing by never exercising the check.
	 */
	public function testViolationsHelperFiresOnEachMalformedKeyShape(): void
	{
		$this->assertNotEmpty(self::violations(['bogus/x' => []]), "a typo'd alias must be a violation");
		$this->assertNotEmpty(self::violations(['nokey' => []]), 'a bare (unprefixed) key must be a violation');
		$this->assertNotEmpty(self::violations(['gen/' => []]), 'an empty bare part must be a violation');
	}

	/**
	 * PFB_SECTIONS integrity: its values are unique (no two aliases collide on
	 * one section) and every value is scoped to a pfBlockerNG-owned section.
	 */
	public function testPfbSectionsValuesAreUniqueAndScopedToThePackage(): void
	{
		$this->assertSame(
			count(PFB_SECTIONS),
			count(array_unique(PFB_SECTIONS)),
			'PFB_SECTIONS values must be unique'
		);
		foreach (PFB_SECTIONS as $alias => $path) {
			$this->assertStringStartsWith(
				'installedpackages/pfblockerng',
				$path,
				"PFB_SECTIONS['{$alias}'] must be a pfBlockerNG-owned installedpackages path"
			);
		}
	}
}
