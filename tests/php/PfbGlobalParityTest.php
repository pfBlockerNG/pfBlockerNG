<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * ADR-29 Phase 4 — Default-parity tests for pfb_global() seam routing.
 *
 * For every key that pfb_global() reads from a registered section, this file
 * asserts that PfbConfig::read($key) on an absent section returns the SAME
 * effective value the OLD pfb_global() code produced (registered default ==
 * prior per-site default). Present empty adapter tokens are explicit Off and
 * are covered by the storage contract suite.
 *
 * The intentional divergences are the #281/#1907 default-repair class: pfb_keep (OLD
 * code used `?? 'on'`, PHP null-coalesce) and, per the #1907 owner decision,
 * pfb_hsts/pfb_cache/pfb_py_reply (OLD code called the toggle adapter directly on the
 * raw section value, bypassing the gateway's registry default entirely). All four now
 * default to On, formalising what was already the de-facto page default since 3.2;
 * each test below asserts the repaired value and documents its origin.
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
	 * Via gateway: PfbConfig::read('gen/enable_cb')->value = '' (PfbToggle::Off).
	 * PARITY: null and '' are both falsy; downstream checks == 'on' — equivalent.
	 * Gateway storage emits the canonical empty Off token.
	 */
	public function testParityEnableCbAbsentYieldsOff(): void
	{
		// Before: key absent from config.
		$this->assertNull(config_get_path('installedpackages/pfblockerng/config/0/enable_cb'));

		// When: gateway read.
		$result = PfbConfig::read('gen/enable_cb');

		// Then: PfbToggle::Off -> value ''.
		$this->assertSame(PfbToggle::Off, $result);
		$this->assertSame('off', $result->value, 'enable_cb absent -> off token (matches pfb_global null-absent)');
	}

	/**
	 * pfb_keep: OLD pfb_global() = $pfb['config']['pfb_keep'] ?? 'on' = 'on' when absent.
	 * Via gateway: PfbConfig::read('gen/pfb_keep')->value = 'on' (PfbToggle::On, #484 fix).
	 *
	 * #281 DEFAULT REPAIR: This is the canonical defect class. The registry default
	 * is 'on', matching the old ?? 'on' fallback. Both old code and gateway agree.
	 * issue #1921's registry pass grandfathers this into config.xml for EXISTING
	 * installs (gen/pfb_keep's grandfather map); new installs and the runtime both
	 * default to 'on'.
	 *
	 * The GUI stores the canonical empty token for unchecked-save — distinguishable
	 * from absent (default 'on'). Legacy 'off' remains read-compatible only.
	 */
	public function testParityPfbKeepAbsentYieldsOn(): void
	{
		// Before: key absent.
		$this->assertNull(config_get_path('installedpackages/pfblockerng/config/0/pfb_keep'));

		// When: gateway read (the #281-repaired registry default).
		$result = PfbConfig::read('gen/pfb_keep');

		// Then: 'on' — matches OLD ?? 'on' AND the repaired registry default.
		// The merged PfbToggle adapter (issue #1887); the value is unchanged.
		$this->assertSame(PfbToggle::On, $result);
		$this->assertSame('on', $result->value, 'pfb_keep absent -> "on" (#281: default repaired via registry)');
	}

	/**
	 * pfb_agg_types: OLD = $pfb['config']['pfb_agg_types'] ?? '' = '' when absent.
	 * Via gateway: PfbConfig::read('gen/pfb_agg_types') = '' (registered default).
	 */
	public function testParityPfbAggTypesAbsentYieldsEmpty(): void
	{
		$this->assertNull(config_get_path('installedpackages/pfblockerng/config/0/pfb_agg_types'));

		$result = PfbConfig::read('gen/pfb_agg_types');

		$this->assertSame('', $result, 'pfb_agg_types absent -> ""');
	}

	/**
	 * Fresh installs now read the registered default '3'. The migration preserves
	 * absent old-install storage as '0', matching its former unlimited behavior.
	 */
	public function testParitySkipfeedAbsentYieldsFreshDefaultThree(): void
	{
		$this->assertNull(config_get_path('installedpackages/pfblockerng/config/0/skipfeed'));

		$result = PfbConfig::read('gen/skipfeed');

		// Fresh-install registry default is 3; OLDCFG migration preserves unlimited 0.
		$this->assertSame('3', $result, 'skipfeed absent -> fresh default "3"');
	}

	/**
	 * pfb_reuse: OLD = $pfb['config']['pfb_reuse'] (null when absent — no adapter call in old code).
	 * Via gateway: PfbConfig::read('gen/pfb_reuse')->value = '' (PfbToggle::Off, default '').
	 * PARITY: null and '' are both falsy; downstream checks == 'on'.
	 */
	public function testParityPfbReuseAbsentYieldsOff(): void
	{
		$this->assertNull(config_get_path('installedpackages/pfblockerng/config/0/pfb_reuse'));

		$result = PfbConfig::read('gen/pfb_reuse');

		$this->assertSame(PfbToggle::Off, $result);
		$this->assertSame('off', $result->value, 'pfb_reuse absent -> off token');
	}

	// -----------------------------------------------------------------------
	// B — DNSBL settings section defaults
	// -----------------------------------------------------------------------

	/**
	 * pfb_dnsbl: OLD = $pfb['dnsblconfig']['pfb_dnsbl'] = null when absent.
	 * Via gateway: PfbConfig::read('dnsbl/pfb_dnsbl')->value = '' (PfbToggle::Off).
	 * PARITY: null and '' are both falsy; downstream checks !empty() or == 'on'.
	 */
	public function testParityPfbDnsblAbsentYieldsOff(): void
	{
		$this->assertNull(
			config_get_path('installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl')
		);

		$result = PfbConfig::read('dnsbl/pfb_dnsbl');

		$this->assertSame(PfbToggle::Off, $result);
		$this->assertSame('off', $result->value, 'pfb_dnsbl absent -> off token');
	}

	/**
	 * pfb_dnsvip_auto: OLD = pfb_cfg_toggle_read($pfb['dnsblconfig']['pfb_dnsvip_auto'] ?? '')->value.
	 * When absent: pfb_cfg_toggle_read('')->value = ''.
	 * Via gateway: PfbConfig::read('dnsbl/pfb_dnsvip_auto')->value = '' (default '').
	 * PARITY: identical.
	 */
	public function testParityPfbDnsvipAutoAbsentYieldsOff(): void
	{
		$this->assertNull(
			config_get_path('installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsvip_auto')
		);

		// The adapter's empty Off token remains empty on write.
		$old_result = pfb_cfg_toggle_read('')->value;
		$this->assertSame('off', $old_result);

		// When: gateway read.
		$result = PfbConfig::read('dnsbl/pfb_dnsvip_auto');

		// Then: same value.
		$this->assertSame(PfbToggle::Off, $result);
		$this->assertSame('off', $result->value, 'pfb_dnsvip_auto absent -> off token (matches the adapter normalisation)');
	}

	/**
	 * dnsbl_interface: OLD = isset($pfb['dnsblconfig']['dnsbl_interface'])
	 *                        ? $pfb['dnsblconfig']['dnsbl_interface'] : 'lo0'.
	 * When absent: 'lo0'.
	 * Via gateway: PfbConfig::read('dnsbl/dnsbl_interface') = 'lo0' (registered default).
	 * PARITY: identical.
	 */
	public function testParityDnsblInterfaceAbsentYieldsLo0(): void
	{
		$this->assertNull(
			config_get_path('installedpackages/pfblockerngdnsblsettings/config/0/dnsbl_interface')
		);

		$result = PfbConfig::read('dnsbl/dnsbl_interface');

		$this->assertSame('lo0', $result, 'dnsbl_interface absent -> "lo0"');
	}

	/**
	 * top1m_source: OLD = isset($pfb['dnsblconfig']['top1m_source'])
	 *                   ? $pfb['dnsblconfig']['top1m_source'] : 'tranco'.
	 * When absent: 'tranco'.
	 * Via gateway: PfbConfig::read('dnsbl/top1m_source') = PfbTop1mSource::Tranco (registered
	 * default 'tranco', adapted through the PfbTop1mSource enum, issue #877 review).
	 * PARITY: same runtime meaning ('tranco'), now enum-typed instead of a raw string.
	 */
	public function testParityAlexaTypeAbsentYieldsTranco(): void
	{
		$this->assertNull(
			config_get_path('installedpackages/pfblockerngdnsblsettings/config/0/top1m_source')
		);

		$result = PfbConfig::read('dnsbl/top1m_source');

		$this->assertSame(PfbTop1mSource::Tranco, $result, 'top1m_source absent -> PfbTop1mSource::Tranco');
	}

	/**
	 * global_log: OLD = isset($pfb['dnsblconfig']['global_log'])
	 *                   ? $pfb['dnsblconfig']['global_log'] : ''.
	 * When absent: ''.
	 * Via gateway: PfbConfig::read('dnsbl/global_log') = '' (registered default).
	 * PARITY: identical.
	 */
	public function testParityGlobalLogAbsentYieldsEmpty(): void
	{
		$this->assertNull(
			config_get_path('installedpackages/pfblockerngdnsblsettings/config/0/global_log')
		);

		$result = PfbConfig::read('dnsbl/global_log');

		$this->assertSame('', $result, 'global_log absent -> ""');
	}

	/**
	 * pfb_dnsbl_lenient: OLD = pfb_cfg_toggle_read($pfb['dnsblconfig']['pfb_dnsbl_lenient'] ?? '')->value.
	 * When absent: pfb_cfg_toggle_read('')->value = 'off'.
	 * Via gateway: PfbConfig::read('dnsbl/pfb_dnsbl_lenient')->value = 'off' (default Off).
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
		$result = PfbConfig::read('dnsbl/pfb_dnsbl_lenient');

		// Then: same value.
		$this->assertSame(PfbToggle::Off, $result);
		$this->assertSame('off', $result->value, 'pfb_dnsbl_lenient absent -> "off" (matches old pfb_cfg_toggle_read)');
	}

	/**
	 * pfb_hsts (issue #1907 DEFAULT REPAIR): OLD = $pfb['dnsblconfig']['pfb_hsts']
	 * (null when absent) -> effectively Off. Via gateway (owner decision, #1907): the
	 * registry default flipped to 'on' -- the de-facto page default since 3.2
	 * (pfblockerng_dnsbl.php's own isset(...) ? ... : 'on' render fallback), so
	 * PfbConfig::read('dnsbl/pfb_hsts') now resolves absent to PfbToggle::On.
	 * DIVERGENCE (intentional, same class as #281's pfb_keep repair below): the
	 * Existing stored empty values remain explicit Off; absent values and fresh
	 * installs use the registered On default.
	 */
	public function testParityPfbHstsAbsentYieldsOn(): void
	{
		$this->assertNull(
			config_get_path('installedpackages/pfblockerngdnsblsettings/config/0/pfb_hsts')
		);

		$result = PfbConfig::read('dnsbl/pfb_hsts');

		$this->assertSame(PfbToggle::On, $result, 'pfb_hsts absent -> On (issue #1907 default repair)');
		$this->assertSame('on', $result->value, 'pfb_hsts absent -> on token');
	}

	/**
	 * pfb_cache (issue #1907 DEFAULT REPAIR): OLD pfb_global() =
	 * pfb_cfg_toggle_read($pfb['dnsblconfig']['pfb_cache'] ?? '') -- a DIRECT adapter
	 * call bypassing the gateway entirely, so absent/'' fell to the adapter's bare
	 * parse-fallback (Off), never the registry default. Post-#1907, pfb_global() routes
	 * this key through PfbConfig::read('dnsbl/pfb_cache'), whose registry default is
	 * now 'on' -- the de-facto page default since 3.2 (pfblockerng_dnsbl.php's own
	 * isset(...) ? ... : 'on' render fallback). DIVERGENCE (intentional): adopting the
	 * gateway repairs the same #281-class defect pfb_keep already had fixed.
	 */
	public function testParityPfbCacheAbsentYieldsOn(): void
	{
		$this->assertNull(
			config_get_path('installedpackages/pfblockerngdnsblsettings/config/0/pfb_cache')
		);

		// Before: the OLD direct-adapter call (bypassing the gateway) fell to Off.
		$old_result = pfb_cfg_toggle_read('');
		$this->assertSame(PfbToggle::Off, $old_result, 'before: the pre-#1907 direct adapter call fell to Off');

		// When: gateway read (the #1907-repaired registry default).
		$result = PfbConfig::read('dnsbl/pfb_cache');

		// Then: On -- the registry default, adopted at pfb_global()'s assignment site.
		$this->assertSame(PfbToggle::On, $result, 'pfb_cache absent -> On (issue #1907 default repair)');
		$this->assertSame('on', $result->value, 'pfb_cache absent -> on token');
	}

	/**
	 * pfb_py_reply (issue #1907 DEFAULT REPAIR): same shape as pfb_cache above.
	 */
	public function testParityPfbPyReplyAbsentYieldsOn(): void
	{
		$this->assertNull(
			config_get_path('installedpackages/pfblockerngdnsblsettings/config/0/pfb_py_reply')
		);

		$old_result = pfb_cfg_toggle_read('');
		$this->assertSame(PfbToggle::Off, $old_result, 'before: the pre-#1907 direct adapter call fell to Off');

		$result = PfbConfig::read('dnsbl/pfb_py_reply');

		$this->assertSame(PfbToggle::On, $result, 'pfb_py_reply absent -> On (issue #1907 default repair)');
		$this->assertSame('on', $result->value, 'pfb_py_reply absent -> on token');
	}

	/**
	 * pfb_idn: OLD = $pfb['dnsblconfig']['pfb_idn'] ?? '' = '' when absent (null-coalesce).
	 * Via gateway (ADR-28 reframe): PfbConfig::read('dnsbl/pfb_idn') = PfbIdnMode::Off when absent.
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
		$result = PfbConfig::read('dnsbl/pfb_idn');

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
	 * Via gateway: PfbConfig::read('dnsbl/pfb_idn_block_malicious') = 'on' (registered default).
	 * PARITY: identical.
	 */
	public function testParityPfbIdnBlockMaliciousAbsentYieldsOn(): void
	{
		$this->assertNull(
			config_get_path('installedpackages/pfblockerngdnsblsettings/config/0/pfb_idn_block_malicious')
		);

		$result = PfbConfig::read('dnsbl/pfb_idn_block_malicious');

		$this->assertSame(PfbToggle::On, $result, 'pfb_idn_block_malicious absent -> On (default-on; enum since #1887)');
	}

	/**
	 * pfb_idn_escalate_suspicious: OLD = $pfb['dnsblconfig']['pfb_idn_escalate_suspicious'] ?? '' = '' when absent.
	 * Via gateway: PfbConfig::read('dnsbl/pfb_idn_escalate_suspicious') = '' (registered default).
	 * PARITY: identical.
	 */
	public function testParityPfbIdnEscalateSuspiciousAbsentYieldsOff(): void
	{
		$this->assertNull(
			config_get_path('installedpackages/pfblockerngdnsblsettings/config/0/pfb_idn_escalate_suspicious')
		);

		$result = PfbConfig::read('dnsbl/pfb_idn_escalate_suspicious');

		$this->assertSame(PfbToggle::Off, $result, 'pfb_idn_escalate_suspicious absent -> Off (enum since #1887)');
	}

	/**
	 * pfb_regex_cap: OLD = $pfb['dnsblconfig']['pfb_regex_cap'] ?? '' = '' when absent.
	 * Via gateway: PfbConfig::read('dnsbl/pfb_regex_cap') = '' (registered default).
	 * PARITY: identical.
	 */
	public function testParityPfbRegexCapAbsentYieldsOff(): void
	{
		$this->assertNull(
			config_get_path('installedpackages/pfblockerngdnsblsettings/config/0/pfb_regex_cap')
		);

		$result = PfbConfig::read('dnsbl/pfb_regex_cap');

		// issue #1887: the field gained the toggle adapter pair, so the gateway returns
		// the enum; absent still means the feature is off, just as the raw '' did.
		$this->assertSame(PfbToggle::Off, $result, 'pfb_regex_cap absent -> Off');
	}

	// -----------------------------------------------------------------------
	// C — SafeSearch section defaults
	// -----------------------------------------------------------------------

	/**
	 * safesearch_enable: OLD = config_get_path('installedpackages/pfblockerngsafesearch/safesearch_enable', 'Disable') = 'Disable'.
	 * Via gateway: PfbConfig::read('ss/safesearch_enable') = 'Disable' (registered default).
	 * PARITY: identical.
	 */
	public function testParitySafesearchEnableAbsentYieldsDisable(): void
	{
		$this->assertNull(config_get_path('installedpackages/pfblockerngsafesearch/safesearch_enable'));

		// Before: old code produced 'Disable' via config_get_path default.
		$old_result = config_get_path('installedpackages/pfblockerngsafesearch/safesearch_enable', 'Disable');
		$this->assertSame('Disable', $old_result);

		// When: gateway read.
		$result = PfbConfig::read('ss/safesearch_enable');

		// Then: same value.
		$this->assertSame('Disable', $result, 'safesearch_enable absent -> "Disable"');
	}

	/**
	 * safesearch_youtube: OLD = config_get_path(..., 'Disable') = 'Disable'.
	 * Via gateway: PfbConfig::read('ss/safesearch_youtube') = 'Disable'.
	 * PARITY: identical.
	 */
	public function testParitySafesearchYoutubeAbsentYieldsDisable(): void
	{
		$this->assertNull(config_get_path('installedpackages/pfblockerngsafesearch/safesearch_youtube'));

		$result = PfbConfig::read('ss/safesearch_youtube');

		$this->assertSame('Disable', $result, 'safesearch_youtube absent -> "Disable"');
	}

	/**
	 * safesearch_doh: OLD = config_get_path(..., 'Disable') = 'Disable'.
	 * Via gateway: PfbConfig::read('ss/safesearch_doh') = 'Disable'.
	 * PARITY: identical.
	 */
	public function testParitySafesearchDohAbsentYieldsDisable(): void
	{
		$this->assertNull(config_get_path('installedpackages/pfblockerngsafesearch/safesearch_doh'));

		$result = PfbConfig::read('ss/safesearch_doh');

		$this->assertSame('Disable', $result, 'safesearch_doh absent -> "Disable"');
	}

	/**
	 * safesearch_doh_list: OLD = config_get_path(..., '') = '' -> explode -> [''].
	 * Via gateway: PfbConfig::read('ss/safesearch_doh_list') = '' -> explode -> [''].
	 * PARITY: identical.
	 */
	public function testParitySafesearchDohListAbsentYieldsEmpty(): void
	{
		$this->assertNull(config_get_path('installedpackages/pfblockerngsafesearch/safesearch_doh_list'));

		$result = PfbConfig::read('ss/safesearch_doh_list');

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
	 * After routing to PfbConfig::read('gen/pfb_keep')->value: 'on'.
	 * RESULT: no behaviour change — both old code and gateway agree on 'on'.
	 *
	 * The structural fix: the default is now FORMAL (in the registry) instead of
	 * a scattered per-site ?? fallback. issue #1921's registry pass grandfathers this
	 * into config.xml for existing installs; the runtime default is identical.
	 *
	 * #484 FIX (merged into PfbToggle by #1887): the GUI stores
	 * The empty token is used for unchecked-save — distinguishable from absent
	 * (default 'on'). Current code reads a present empty token as PfbToggle::Off.
	 */
	public function testRepair281PfbKeepDefaultIsFormallyOn(): void
	{
		// Before: key absent; old code would have produced 'on' via ?? 'on'.
		$this->assertNull(config_get_path('installedpackages/pfblockerng/config/0/pfb_keep'));

		// When: gateway read (the formal registry default).
		$result = PfbConfig::read('gen/pfb_keep');

		// Then: value is 'on' — same as old ?? 'on' fallback.
		// The #281 class is now structurally closed: the default is formal,
		// not scattered, and a missing key cannot diverge from the GUI default.
		// Adapter is the merged PfbToggle (issue #1887); value is unchanged.
		$this->assertSame(PfbToggle::On, $result);
		$this->assertSame('on', $result->value);

		// issue #2120: a present empty token is the owner-ruled Off state; only an
		// absent key resolves to the registered default On.
		config_set_path('installedpackages/pfblockerng/config/0/pfb_keep', '');
		$result_empty = PfbConfig::read('gen/pfb_keep');
		$this->assertSame(PfbToggle::Off, $result_empty, "stored '' pfb_keep resolves to Off");
	}
}
