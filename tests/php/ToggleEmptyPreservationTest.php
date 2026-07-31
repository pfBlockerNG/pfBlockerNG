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
 * Keep holds '' (upstream wrote '' for unchecked), and reading that as On silently
 * re-enables their opt-out. The same shape reached pfb_idn_block_malicious through its
 * save path.
 *
 * issue #1921 (S2): the one-time '' -> 'off' upgrade conversion this file used to pin
 * directly (pfb_run_migrations()'s #1887 entries) folded into pfb_registry_pass()'s
 * grandfather map (gen/pfb_keep and dnsbl/pfb_idn_block_malicious both carry
 * ['' => 'off']) -- RegistryPassTest rows 4 and 8 cover the full absent/''/'on'/'off'
 * matrix for both keys now. What remains here is the save-path half, unrelated to any
 * migration: the DNSBL page staged its two IDN checkboxes as `pfb_filter(...) ?: ''`, so
 * an UNCHECKED save wrote '' — which the gateway now reads as the default. For the
 * default-'on' pfb_idn_block_malicious that meant the checkbox could never be turned off
 * again. The save path stages the explicit token instead (the general.php idiom), and
 * both IDN toggles carry the toggle adapter.
 */
final class ToggleEmptyPreservationTest extends TestCase
{
	private const IDN = 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_idn_block_malicious';

	protected function setUp(): void
	{
		$GLOBALS['config'] = [];
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
		$this->assertSame(PfbToggle::Off, PfbConfig::read('dnsbl/pfb_idn_block_malicious'),
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
