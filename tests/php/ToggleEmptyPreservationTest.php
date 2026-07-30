<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #1887 follow-through — a pre-merge stored '' meant an EXPLICIT Off, and that
 * intent must survive the merge on the fields where the registered default is 'on'.
 *
 * Under the merged contract a stored '' is the not-configured state and resolves to the
 * registered default. For a default-'' toggle that changes nothing. For a default-'on'
 * toggle it FLIPS a legacy unchecked save: a 3.2.x operator who deliberately unchecked
 * Keep holds '' (upstream wrote '' for unchecked, and pfb_keep_migrate() deliberately
 * never overwrites an existing value), and reading that as On silently re-enables their
 * opt-out. The same shape reached pfb_idn_block_malicious through its save path.
 *
 * The repair is the owner-directed one-time upgrade conversion: rewrite the lingering ''
 * to the explicit 'off' it meant, so config.xml carries only canonical tokens and the
 * '' ≡ absent rule applies cleanly ever after. The migration is naturally idempotent —
 * it only fires while a '' exists, and nothing writes '' any more.
 *
 * Companion fix, same defect class: the DNSBL page staged its two IDN checkboxes as
 * `pfb_filter(...) ?: ''`, so an UNCHECKED save wrote '' — which the gateway now reads
 * as the default. For the default-'on' pfb_idn_block_malicious that meant the checkbox
 * could never be turned off again. The save path stages the explicit token instead
 * (the general.php idiom), and both IDN toggles carry the toggle adapter.
 */
final class ToggleEmptyPreservationTest extends TestCase
{
	private const KEEP = 'installedpackages/pfblockerng/config/0/pfb_keep';
	private const IDN  = 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_idn_block_malicious';

	protected function setUp(): void
	{
		$GLOBALS['config'] = [];
	}

	// -----------------------------------------------------------------------
	// The one-time '' -> 'off' preservation migration
	// -----------------------------------------------------------------------

	/**
	 * A legacy stored '' on pfb_keep is preserved as the explicit 'off' it meant.
	 *
	 * This is the 3.2.x opt-out case: pfb_keep_migrate() (#281) deliberately never
	 * touches an existing value, so only this conversion stands between the operator's
	 * unchecked Keep and a silent re-enable on the next read.
	 */
	public function testLegacyEmptyPfbKeepIsPreservedAsExplicitOff(): void
	{
		config_set_path(self::KEEP, '');

		pfb_run_migrations();

		$this->assertSame('off', config_get_path(self::KEEP),
			"a pre-#1887 stored '' on pfb_keep must be rewritten to the explicit 'off' it meant");
		$this->assertSame(PfbToggle::Off, PfbConfig::read('pfb_keep'),
			'the preserved opt-out must read as Off, not resolve to the default-on');
	}

	/**
	 * The same preservation for pfb_idn_block_malicious — the other default-'on'
	 * toggle a stored '' could reach (via the DNSBL page's old unchecked save).
	 */
	public function testLegacyEmptyIdnBlockMaliciousIsPreservedAsExplicitOff(): void
	{
		config_set_path(self::IDN, '');

		pfb_run_migrations();

		$this->assertSame('off', config_get_path(self::IDN),
			"a pre-#1887 stored '' on pfb_idn_block_malicious must be preserved as 'off'");
		$this->assertSame(PfbToggle::Off, PfbConfig::read('pfb_idn_block_malicious'),
			'the preserved opt-out must read as Off');
	}

	/**
	 * An ABSENT key is not the preservation migration's business: it rewrites recorded
	 * intent ('') only. pfb_keep still gets its 'on' from the SEPARATE #281 seed (an
	 * existing install predating the key must survive the pre-deinstall wipe — that
	 * migration is deliberately untouched here); pfb_idn_block_malicious has no seed,
	 * stays absent, and reads the registry default On.
	 */
	public function testAbsentKeysTakeTheirExistingSeedOrDefaultBehaviour(): void
	{
		// A populated section without the two keys, so the existing-install
		// discriminators see real operator config rather than an empty section.
		config_set_path('installedpackages/pfblockerng/config/0/pfb_interval', '1');
		config_set_path('installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl', 'on');

		pfb_run_migrations();

		$this->assertSame('on', config_get_path(self::KEEP),
			'absent pfb_keep on an existing install is seeded on by the #281 migration, as before');
		$this->assertNull(config_get_path(self::IDN), 'absent pfb_idn_block_malicious must stay absent');
		$this->assertSame(PfbToggle::On, PfbConfig::read('pfb_keep'));
		$this->assertSame(PfbToggle::On, PfbConfig::read('pfb_idn_block_malicious'));
	}

	/**
	 * Canonical stored values are never touched — the conversion is '' -> 'off' only.
	 */
	public function testCanonicalValuesAreNeverRewritten(): void
	{
		config_set_path(self::KEEP, 'on');
		config_set_path(self::IDN, 'off');

		pfb_run_migrations();

		$this->assertSame('on', config_get_path(self::KEEP), "a stored 'on' must survive untouched");
		$this->assertSame('off', config_get_path(self::IDN), "a stored 'off' must survive untouched");
	}

	// -----------------------------------------------------------------------
	// The save-path half: an unchecked IDN save must disable, not re-enable
	// -----------------------------------------------------------------------

	/**
	 * The defect the sweep found: with the field read through the gateway, a staged ''
	 * resolves to the default 'on', so the old `pfb_filter(...) ?: ''` unchecked save
	 * could never turn malicious-homoglyph blocking off. The save must stage the
	 * explicit token; this drives the staged value through the same writeSection the
	 * page uses and asserts the read-back.
	 */
	public function testUncheckedIdnBlockMaliciousSaveDisables(): void
	{
		$section = 'installedpackages/pfblockerngdnsblsettings/config/0';

		// The page's staging idiom for an unchecked box (POST key absent).
		$staged = ((NULL ?? '') === 'on') ? 'on' : 'off';
		PfbConfig::writeSection($section, ['pfb_idn_block_malicious' => $staged]);

		$this->assertSame('off', config_get_path(self::IDN),
			'an unchecked save must persist the explicit off token');
		$this->assertSame(PfbToggle::Off, PfbConfig::read('pfb_idn_block_malicious'),
			'an unchecked save must read back as disabled — not resolve to the default-on');
	}

	/**
	 * The page source stages both IDN checkboxes with the explicit-token ternary, not
	 * the `?: ''` coalesce whose '' now means "not configured".
	 */
	public function testDnsblPageStagesTheIdnTogglesExplicitly(): void
	{
		$src = (string) file_get_contents(
			dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php'
		);

		foreach (['pfb_idn_block_malicious', 'pfb_idn_escalate_suspicious'] as $field) {
			$this->assertStringContainsString(
				"((\$_POST['{$field}'] ?? '') === 'on') ? 'on' : 'off'",
				$src,
				"{$field} must be staged as an explicit 'on'/'off' (checkbox-absent means Off)"
			);
			$this->assertStringNotContainsString(
				"pfb_filter(\$_POST['{$field}'], PFB_FILTER_ON_OFF, 'dnsbl')\t?: ''",
				$src,
				"{$field} must not be staged with the ?: '' coalesce"
			);
		}
	}
}
