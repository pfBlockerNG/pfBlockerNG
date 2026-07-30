<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * ADR-29 Phase 4 — Default-parity tests for pfb_global() seam routing.
 *
 * For every key that pfb_global() reads from a registered section, this file
 * asserts that PfbConfig::read($key) on an absent/empty section returns the
 * SAME effective value the OLD pfb_global() code produced (registered default
 * == prior per-site default).
 *
 * The ONLY intentional divergence is pfb_keep: the OLD code used `?? 'on'`
 * (PHP null-coalesce), which the registry formalises as default 'on'. Both
 * yield 'on'; the test asserts the repaired value and documents the #281 fix.
 *
 * Scenario (all tests):
 *   Background: config.xml is empty — no pfblockerng* sections.
 *     Given PfbConfig::read($key) with no seed.
 *     When the key is absent from every section.
 *     Then the returned value equals the expected pfb_global() runtime default.
 *
 * Test groups:
 *   A — General section (installedpackages/pfblockerng/config/0)
 *   B — DNSBL settings section (installedpackages/pfblockerngdnsblsettings/config/0)
 *   C — SafeSearch section (installedpackages/pfblockerngsafesearch)
 */
final class PfbGlobalParityTest extends TestCase
{
	protected function setUp(): void
	{
		$GLOBALS['config'] = [];
	}

	// -----------------------------------------------------------------------
	// A — General section defaults
	// -----------------------------------------------------------------------

	/**
	 * enable_cb: OLD pfb_global() = $pfb['config']['enable_cb'] = null when absent.
	 * Via gateway: PfbConfig::read('enable_cb')->value = '' (PfbToggle::Off).
	 * PARITY: null and '' are both falsy; downstream checks == 'on' — equivalent.
	 * Gateway form emits '' (the registered default), which is the canonical off value.
	 */
	public function testParityEnableCbAbsentYieldsOff(): void
	{
		// Before: key absent from config.
		$this->assertNull(config_get_path('installedpackages/pfblockerng/config/0/enable_cb'));

		// When: gateway read.
		$result = PfbConfig::read('enable_cb');

		// Then: PfbToggle::Off -> value ''.
		$this->assertSame(PfbToggle::Off, $result);
		$this->assertSame('off', $result->value, 'enable_cb absent -> off token (matches pfb_global null-absent)');
	}

	/**
	 * pfb_keep: OLD pfb_global() = $pfb['config']['pfb_keep'] ?? 'on' = 'on' when absent.
	 * Via gateway: PfbConfig::read('pfb_keep')->value = 'on' (PfbToggle::On, #484 fix).
	 *
	 * #281 DEFAULT REPAIR: This is the canonical defect class. The registry default
	 * is 'on', matching the old ?? 'on' fallback. Both old code and gateway agree.
	 * The issue #281 migration (pfb_keep_migrate) seeds this into config.xml for
	 * EXISTING installs; new installs and the runtime both default to 'on'.
	 *
	 * #484 FIX: pfb_keep now uses the lenient adapter (PfbLenient) so the GUI stores
	 * 'off' for unchecked-save — distinguishable from absent (default 'on').
	 */
	public function testParityPfbKeepAbsentYieldsOn(): void
	{
		// Before: key absent.
		$this->assertNull(config_get_path('installedpackages/pfblockerng/config/0/pfb_keep'));

		// When: gateway read (the #281-repaired registry default).
		$result = PfbConfig::read('pfb_keep');

		// Then: 'on' — matches OLD ?? 'on' AND the repaired registry default.
		// Adapter is now PfbLenient (not PfbToggle), but the value is unchanged.
		$this->assertSame(PfbToggle::On, $result);
		$this->assertSame('on', $result->value, 'pfb_keep absent -> "on" (#281: default repaired via registry)');
	}

	/**
	 * pfb_interval: OLD = $pfb['config']['pfb_interval'] ?: '1' = '1' when absent.
	 * Via gateway: PfbConfig::read('pfb_interval') = '1' (registered default).
	 */
	public function testParityPfbIntervalAbsentYieldsOne(): void
	{
		$this->assertNull(config_get_path('installedpackages/pfblockerng/config/0/pfb_interval'));

		$result = PfbConfig::read('pfb_interval');

		$this->assertSame('1', $result, 'pfb_interval absent -> "1"');
	}

	/**
	 * pfb_agg_types: OLD = $pfb['config']['pfb_agg_types'] ?? '' = '' when absent.
	 * Via gateway: PfbConfig::read('pfb_agg_types') = '' (registered default).
	 */
	public function testParityPfbAggTypesAbsentYieldsEmpty(): void
	{
		$this->assertNull(config_get_path('installedpackages/pfblockerng/config/0/pfb_agg_types'));

		$result = PfbConfig::read('pfb_agg_types');

		$this->assertSame('', $result, 'pfb_agg_types absent -> ""');
	}

	/**
	 * pfb_min: OLD = $pfb['config']['pfb_min'] ?: '0' = '0' when absent.
	 * Via gateway: PfbConfig::read('pfb_min') = '0' (registered default).
	 */
	public function testParityPfbMinAbsentYieldsZero(): void
	{
		$this->assertNull(config_get_path('installedpackages/pfblockerng/config/0/pfb_min'));

		$result = PfbConfig::read('pfb_min');

		$this->assertSame('0', $result, 'pfb_min absent -> "0"');
	}

	/**
	 * pfb_hour: OLD = $pfb['config']['pfb_hour'] ?: '0' = '0' when absent.
	 * Via gateway: PfbConfig::read('pfb_hour') = '0' (registered default).
	 */
	public function testParityPfbHourAbsentYieldsZero(): void
	{
		$this->assertNull(config_get_path('installedpackages/pfblockerng/config/0/pfb_hour'));

		$result = PfbConfig::read('pfb_hour');

		$this->assertSame('0', $result, 'pfb_hour absent -> "0"');
	}

	/**
	 * pfb_dailystart: OLD = $pfb['config']['pfb_dailystart'] ?: '0' = '0' when absent.
	 * Via gateway: PfbConfig::read('pfb_dailystart') = '0' (registered default).
	 */
	public function testParityPfbDailystartAbsentYieldsZero(): void
	{
		$this->assertNull(config_get_path('installedpackages/pfblockerng/config/0/pfb_dailystart'));

		$result = PfbConfig::read('pfb_dailystart');

		$this->assertSame('0', $result, 'pfb_dailystart absent -> "0"');
	}

	/**
	 * skipfeed: OLD = $pfb['config']['skipfeed'] != '' ? ... : 0 = 0 when absent
	 * (absent key = null; null == '' in PHP, so the else branch runs -> 0).
	 * Via gateway: PfbConfig::read('skipfeed') = '0' (registered default).
	 * PARITY: '0' and 0 are equivalent for the downstream numeric comparisons.
	 */
	public function testParitySkipfeedAbsentYieldsZeroString(): void
	{
		$this->assertNull(config_get_path('installedpackages/pfblockerng/config/0/skipfeed'));

		$result = PfbConfig::read('skipfeed');

		// Registry default '0'; old code: null -> 0 (int). Numeric equivalence.
		$this->assertSame('0', $result, 'skipfeed absent -> "0" (parity with pfb_global null->0)');
	}

	/**
	 * pfb_reuse: OLD = $pfb['config']['pfb_reuse'] (null when absent — no adapter call in old code).
	 * Via gateway: PfbConfig::read('pfb_reuse')->value = '' (PfbToggle::Off, default '').
	 * PARITY: null and '' are both falsy; downstream checks == 'on'.
	 */
	public function testParityPfbReuseAbsentYieldsOff(): void
	{
		$this->assertNull(config_get_path('installedpackages/pfblockerng/config/0/pfb_reuse'));

		$result = PfbConfig::read('pfb_reuse');

		$this->assertSame(PfbToggle::Off, $result);
		$this->assertSame('off', $result->value, 'pfb_reuse absent -> off token');
	}

	// -----------------------------------------------------------------------
	// B — DNSBL settings section defaults
	// -----------------------------------------------------------------------

	/**
	 * pfb_dnsbl: OLD = $pfb['dnsblconfig']['pfb_dnsbl'] = null when absent.
	 * Via gateway: PfbConfig::read('pfb_dnsbl')->value = '' (PfbToggle::Off).
	 * PARITY: null and '' are both falsy; downstream checks !empty() or == 'on'.
	 */
	public function testParityPfbDnsblAbsentYieldsOff(): void
	{
		$this->assertNull(
			config_get_path('installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl')
		);

		$result = PfbConfig::read('pfb_dnsbl');

		$this->assertSame(PfbToggle::Off, $result);
		$this->assertSame('off', $result->value, 'pfb_dnsbl absent -> off token');
	}

	/**
	 * pfb_dnsvip_auto: OLD = pfb_cfg_toggle_read($pfb['dnsblconfig']['pfb_dnsvip_auto'] ?? '')->value.
	 * When absent: pfb_cfg_toggle_read('')->value = ''.
	 * Via gateway: PfbConfig::read('pfb_dnsvip_auto')->value = '' (default '').
	 * PARITY: identical.
	 */
	public function testParityPfbDnsvipAutoAbsentYieldsOff(): void
	{
		$this->assertNull(
			config_get_path('installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsvip_auto')
		);

		// The adapter's legacy '' normalises to the canonical 'off' (issue #1887).
		$old_result = pfb_cfg_toggle_read('')->value;
		$this->assertSame('off', $old_result);

		// When: gateway read.
		$result = PfbConfig::read('pfb_dnsvip_auto');

		// Then: same value.
		$this->assertSame(PfbToggle::Off, $result);
		$this->assertSame('off', $result->value, 'pfb_dnsvip_auto absent -> off token (matches the adapter normalisation)');
	}

	/**
	 * dnsbl_interface: OLD = isset($pfb['dnsblconfig']['dnsbl_interface'])
	 *                        ? $pfb['dnsblconfig']['dnsbl_interface'] : 'lo0'.
	 * When absent: 'lo0'.
	 * Via gateway: PfbConfig::read('dnsbl_interface') = 'lo0' (registered default).
	 * PARITY: identical.
	 */
	public function testParityDnsblInterfaceAbsentYieldsLo0(): void
	{
		$this->assertNull(
			config_get_path('installedpackages/pfblockerngdnsblsettings/config/0/dnsbl_interface')
		);

		$result = PfbConfig::read('dnsbl_interface');

		$this->assertSame('lo0', $result, 'dnsbl_interface absent -> "lo0"');
	}

	/**
	 * alexa_type: OLD = isset($pfb['dnsblconfig']['alexa_type'])
	 *                   ? $pfb['dnsblconfig']['alexa_type'] : 'tranco'.
	 * When absent: 'tranco'.
	 * Via gateway: PfbConfig::read('alexa_type') = PfbTop1mSource::Tranco (registered
	 * default 'tranco', adapted through the PfbTop1mSource enum, issue #877 review).
	 * PARITY: same runtime meaning ('tranco'), now enum-typed instead of a raw string.
	 */
	public function testParityAlexaTypeAbsentYieldsTranco(): void
	{
		$this->assertNull(
			config_get_path('installedpackages/pfblockerngdnsblsettings/config/0/alexa_type')
		);

		$result = PfbConfig::read('alexa_type');

		$this->assertSame(PfbTop1mSource::Tranco, $result, 'alexa_type absent -> PfbTop1mSource::Tranco');
	}

	/**
	 * global_log: OLD = isset($pfb['dnsblconfig']['global_log'])
	 *                   ? $pfb['dnsblconfig']['global_log'] : ''.
	 * When absent: ''.
	 * Via gateway: PfbConfig::read('global_log') = '' (registered default).
	 * PARITY: identical.
	 */
	public function testParityGlobalLogAbsentYieldsEmpty(): void
	{
		$this->assertNull(
			config_get_path('installedpackages/pfblockerngdnsblsettings/config/0/global_log')
		);

		$result = PfbConfig::read('global_log');

		$this->assertSame('', $result, 'global_log absent -> ""');
	}

	/**
	 * pfb_dnsbl_lenient: OLD = pfb_cfg_toggle_read($pfb['dnsblconfig']['pfb_dnsbl_lenient'] ?? '')->value.
	 * When absent: pfb_cfg_toggle_read('')->value = 'off'.
	 * Via gateway: PfbConfig::read('pfb_dnsbl_lenient')->value = 'off' (default 'off', lenient adapter).
	 * PARITY: identical.
	 */
	public function testParityPfbDnsblLenientAbsentYieldsOff(): void
	{
		$this->assertNull(
			config_get_path('installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl_lenient')
		);

		// Before: old code would produce pfb_cfg_toggle_read('')->value = 'off'.
		$old_result = pfb_cfg_toggle_read('')->value;
		$this->assertSame('off', $old_result);

		// When: gateway read.
		$result = PfbConfig::read('pfb_dnsbl_lenient');

		// Then: same value.
		$this->assertSame(PfbToggle::Off, $result);
		$this->assertSame('off', $result->value, 'pfb_dnsbl_lenient absent -> "off" (matches old pfb_cfg_toggle_read)');
	}

	/**
	 * pfb_hsts: OLD = $pfb['dnsblconfig']['pfb_hsts'] (null when absent).
	 * Via gateway: PfbConfig::read('pfb_hsts')->value = '' (PfbToggle::Off, default '').
	 * PARITY: null and '' both falsy; downstream checks == 'on'.
	 */
	public function testParityPfbHstsAbsentYieldsOff(): void
	{
		$this->assertNull(
			config_get_path('installedpackages/pfblockerngdnsblsettings/config/0/pfb_hsts')
		);

		$result = PfbConfig::read('pfb_hsts');

		$this->assertSame(PfbToggle::Off, $result);
		$this->assertSame('off', $result->value, 'pfb_hsts absent -> "" (off)');
	}

	/**
	 * pfb_idn: OLD = $pfb['dnsblconfig']['pfb_idn'] ?? '' = '' when absent (null-coalesce).
	 * Via gateway (ADR-28 reframe): PfbConfig::read('pfb_idn') = PfbIdnMode::Off when absent.
	 *
	 * PARITY: the registry default is '' which the PfbIdnMode adapter normalises to Off.
	 * OLD code compared the raw string against 'on'/'all'/'confusable' — Off ('off') and
	 * the old '' both result in IDN being disabled, so the effective behaviour is the same.
	 * pfb_idn is now adapted (no longer excluded from adapter adoption, ADR-28 reframe).
	 */
	public function testParityPfbIdnAbsentYieldsOff(): void
	{
		$this->assertNull(
			config_get_path('installedpackages/pfblockerngdnsblsettings/config/0/pfb_idn')
		);

		// Before: absent — old code produced null ?? '' = ''.
		$old_result = config_get_path(
			'installedpackages/pfblockerngdnsblsettings/config/0/pfb_idn'
		) ?? '';
		$this->assertSame('', $old_result, 'before: old code produces empty string for absent pfb_idn');

		// When: gateway read.
		$result = PfbConfig::read('pfb_idn');

		// Then: PfbIdnMode::Off (adapted; '' normalises to Off — IDN disabled).
		// Effective behaviour unchanged: both '' (old) and Off (new) mean IDN disabled.
		$this->assertInstanceOf(PfbIdnMode::class, $result, 'pfb_idn absent -> PfbIdnMode enum');
		$this->assertSame(PfbIdnMode::Off, $result, 'pfb_idn absent -> PfbIdnMode::Off');
		$this->assertSame('off', $result->value, 'pfb_idn absent -> Off value is "off" (IDN disabled)');
	}

	/**
	 * pfb_idn_block_malicious: OLD = isset($pfb['dnsblconfig']['pfb_idn_block_malicious'])
	 *                                ? $pfb['dnsblconfig']['pfb_idn_block_malicious'] : 'on'.
	 * When absent: 'on'.
	 * Via gateway: PfbConfig::read('pfb_idn_block_malicious') = 'on' (registered default).
	 * PARITY: identical.
	 */
	public function testParityPfbIdnBlockMaliciousAbsentYieldsOn(): void
	{
		$this->assertNull(
			config_get_path('installedpackages/pfblockerngdnsblsettings/config/0/pfb_idn_block_malicious')
		);

		$result = PfbConfig::read('pfb_idn_block_malicious');

		$this->assertSame(PfbToggle::On, $result, 'pfb_idn_block_malicious absent -> On (default-on; enum since #1887)');
	}

	/**
	 * pfb_idn_escalate_suspicious: OLD = $pfb['dnsblconfig']['pfb_idn_escalate_suspicious'] ?? '' = '' when absent.
	 * Via gateway: PfbConfig::read('pfb_idn_escalate_suspicious') = '' (registered default).
	 * PARITY: identical.
	 */
	public function testParityPfbIdnEscalateSuspiciousAbsentYieldsEmpty(): void
	{
		$this->assertNull(
			config_get_path('installedpackages/pfblockerngdnsblsettings/config/0/pfb_idn_escalate_suspicious')
		);

		$result = PfbConfig::read('pfb_idn_escalate_suspicious');

		$this->assertSame(PfbToggle::Off, $result, 'pfb_idn_escalate_suspicious absent -> Off (enum since #1887)');
	}

	/**
	 * pfb_regex_cap: OLD = $pfb['dnsblconfig']['pfb_regex_cap'] ?? '' = '' when absent.
	 * Via gateway: PfbConfig::read('pfb_regex_cap') = '' (registered default).
	 * PARITY: identical.
	 */
	public function testParityPfbRegexCapAbsentYieldsOff(): void
	{
		$this->assertNull(
			config_get_path('installedpackages/pfblockerngdnsblsettings/config/0/pfb_regex_cap')
		);

		$result = PfbConfig::read('pfb_regex_cap');

		// issue #1887: the field gained the toggle adapter pair, so the gateway returns
		// the enum; absent still means the feature is off, just as the raw '' did.
		$this->assertSame(PfbToggle::Off, $result, 'pfb_regex_cap absent -> Off');
	}

	// -----------------------------------------------------------------------
	// C — SafeSearch section defaults
	// -----------------------------------------------------------------------

	/**
	 * safesearch_enable: OLD = config_get_path('installedpackages/pfblockerngsafesearch/safesearch_enable', 'Disable') = 'Disable'.
	 * Via gateway: PfbConfig::read('safesearch_enable') = 'Disable' (registered default).
	 * PARITY: identical.
	 */
	public function testParitySafesearchEnableAbsentYieldsDisable(): void
	{
		$this->assertNull(config_get_path('installedpackages/pfblockerngsafesearch/safesearch_enable'));

		// Before: old code produced 'Disable' via config_get_path default.
		$old_result = config_get_path('installedpackages/pfblockerngsafesearch/safesearch_enable', 'Disable');
		$this->assertSame('Disable', $old_result);

		// When: gateway read.
		$result = PfbConfig::read('safesearch_enable');

		// Then: same value.
		$this->assertSame('Disable', $result, 'safesearch_enable absent -> "Disable"');
	}

	/**
	 * safesearch_youtube: OLD = config_get_path(..., 'Disable') = 'Disable'.
	 * Via gateway: PfbConfig::read('safesearch_youtube') = 'Disable'.
	 * PARITY: identical.
	 */
	public function testParitySafesearchYoutubeAbsentYieldsDisable(): void
	{
		$this->assertNull(config_get_path('installedpackages/pfblockerngsafesearch/safesearch_youtube'));

		$result = PfbConfig::read('safesearch_youtube');

		$this->assertSame('Disable', $result, 'safesearch_youtube absent -> "Disable"');
	}

	/**
	 * safesearch_doh: OLD = config_get_path(..., 'Disable') = 'Disable'.
	 * Via gateway: PfbConfig::read('safesearch_doh') = 'Disable'.
	 * PARITY: identical.
	 */
	public function testParitySafesearchDohAbsentYieldsDisable(): void
	{
		$this->assertNull(config_get_path('installedpackages/pfblockerngsafesearch/safesearch_doh'));

		$result = PfbConfig::read('safesearch_doh');

		$this->assertSame('Disable', $result, 'safesearch_doh absent -> "Disable"');
	}

	/**
	 * safesearch_doh_list: OLD = config_get_path(..., '') = '' -> explode -> [''].
	 * Via gateway: PfbConfig::read('safesearch_doh_list') = '' -> explode -> [''].
	 * PARITY: identical.
	 */
	public function testParitySafesearchDohListAbsentYieldsEmpty(): void
	{
		$this->assertNull(config_get_path('installedpackages/pfblockerngsafesearch/safesearch_doh_list'));

		$result = PfbConfig::read('safesearch_doh_list');

		$this->assertSame('', $result, 'safesearch_doh_list absent -> ""');

		// Both old and new code explode the result: [''].
		$this->assertSame([''], explode(',', $result));
	}

	// -----------------------------------------------------------------------
	// D — Explicit #281 repair assertion
	//     The ONLY intentional behaviour change in Phase 4 is the already-landed
	//     #281 default repair. This test documents it explicitly.
	// -----------------------------------------------------------------------

	/**
	 * #281 DEFAULT REPAIR — pfb_keep registry default == old code fallback.
	 *
	 * The old pfb_global() code: $pfb['keep'] = $pfb['config']['pfb_keep'] ?? 'on'.
	 * The registry default: 'on'.
	 * After routing to PfbConfig::read('pfb_keep')->value: 'on'.
	 * RESULT: no behaviour change — both old code and gateway agree on 'on'.
	 *
	 * The structural fix: the default is now FORMAL (in the registry) instead of
	 * a scattered per-site ?? fallback. The pfb_keep_migrate() migration seeds
	 * this into config.xml for existing installs; the runtime default is identical.
	 *
	 * #484 FIX: pfb_keep now uses the lenient adapter (PfbLenient) so the GUI stores
	 * 'off' for unchecked-save — distinguishable from absent (default 'on'). Current code
	 * reads the legacy '' token (written by the old GUI) as PfbToggle::Off.
	 */
	public function testRepair281PfbKeepDefaultIsFormallyOn(): void
	{
		// Before: key absent; old code would have produced 'on' via ?? 'on'.
		$this->assertNull(config_get_path('installedpackages/pfblockerng/config/0/pfb_keep'));

		// When: gateway read (the formal registry default).
		$result = PfbConfig::read('pfb_keep');

		// Then: value is 'on' — same as old ?? 'on' fallback.
		// The #281 class is now structurally closed: the default is formal,
		// not scattered, and a missing key cannot diverge from the GUI default.
		// Adapter is the merged PfbToggle (issue #1887); value is unchanged.
		$this->assertSame(PfbToggle::On, $result);
		$this->assertSame('on', $result->value);

		// issue #1887 (owner decision): a stored '' is the SAME not-configured state as an
		// absent key — pfSense writes an unchecked checkbox as an empty element — so it
		// resolves to the registered default 'on'. A deliberate opt-out is the explicit
		// 'off' token, which round-trips (testPfbKeepRoundTrip* in CfgGatewayTest).
		config_set_path('installedpackages/pfblockerng/config/0/pfb_keep', '');
		$result_empty = PfbConfig::read('pfb_keep');
		$this->assertSame(PfbToggle::On, $result_empty, "stored '' pfb_keep resolves to the registered default On");
	}
}
