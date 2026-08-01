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
 *
 * issue #1907 (#1921 S3): the same save-path shape, extended to dnsbl/pfb_cache,
 * dnsbl/pfb_py_reply, dnsbl/pfb_hsts, and ip/suppression -- all four adopted the toggle
 * adapter and flipped their registry default to 'on', so their pages' saves needed the
 * same explicit-token staging fix.
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

	// -----------------------------------------------------------------------
	// issue #1907 — the same shape for dnsbl/pfb_cache, dnsbl/pfb_py_reply,
	// dnsbl/pfb_hsts, and ip/suppression: all four flipped to a default-'on'
	// registry entry, so an unchecked save staging '' would resolve back to On at
	// the gateway unless the page stages the explicit 'off' token.
	// -----------------------------------------------------------------------

	/**
	 * @return array<string,array{0:string,1:string,2:string}> label => [gateway key, section path, bare key]
	 */
	private static function issue1907Fields(): array
	{
		$dnsbl = 'installedpackages/pfblockerngdnsblsettings/config/0';
		$ip    = 'installedpackages/pfblockerngipsettings/config/0';
		return [
			'pfb_cache'    => ['dnsbl/pfb_cache',    $dnsbl, 'pfb_cache'],
			'pfb_py_reply' => ['dnsbl/pfb_py_reply', $dnsbl, 'pfb_py_reply'],
			'pfb_hsts'     => ['dnsbl/pfb_hsts',     $dnsbl, 'pfb_hsts'],
			'suppression'  => ['ip/suppression',     $ip,    'suppression'],
		];
	}

	/**
	 * An unchecked save (POST key absent, staged via the page's explicit ternary)
	 * must persist and read back as disabled -- not resolve to the new default-on.
	 */
	public function testUncheckedIssue1907FieldsSaveDisables(): void
	{
		foreach (self::issue1907Fields() as $label => [$gateway_key, $section, $bare]) {
			$GLOBALS['config'] = [];

			$post_value = NULL; // checkbox absent from $_POST
			$staged     = (($post_value ?? '') === 'on') ? 'on' : 'off';
			PfbConfig::writeSection($section, [$bare => $staged]);

			$this->assertSame('off', config_get_path("{$section}/{$bare}"),
				"{$label}: an unchecked save must persist the explicit off token");
			$this->assertSame(PfbToggle::Off, PfbConfig::read($gateway_key),
				"{$label}: an unchecked save must read back as disabled -- not resolve to the default-on");
		}
	}

	/**
	 * The before-state for the flip: a checked save stages 'on' and reads back as
	 * enabled -- the polarity pair for the unchecked case above.
	 */
	public function testCheckedIssue1907FieldsSaveEnables(): void
	{
		foreach (self::issue1907Fields() as $label => [$gateway_key, $section, $bare]) {
			$GLOBALS['config'] = [];

			$post_value = 'on'; // checkbox checked
			$staged     = (($post_value ?? '') === 'on') ? 'on' : 'off';
			PfbConfig::writeSection($section, [$bare => $staged]);

			$this->assertSame('on', config_get_path("{$section}/{$bare}"),
				"{$label}: a checked save must persist the explicit on token");
			$this->assertSame(PfbToggle::On, PfbConfig::read($gateway_key),
				"{$label}: a checked save must read back as enabled");
		}
	}

	/**
	 * The page source stages all four checkboxes with the explicit-token ternary, not
	 * the `pfb_filter(...) ?: ''` coalesce whose '' now means "not configured" and
	 * would silently re-enable an unchecked save now these fields default on.
	 */
	public function testPagesStageTheIssue1907TogglesExplicitly(): void
	{
		$dnsbl_src = (string) file_get_contents(
			dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php'
		);
		foreach (['pfb_cache', 'pfb_py_reply', 'pfb_hsts'] as $field) {
			$this->assertStringContainsString(
				"((\$_POST['{$field}'] ?? '') === 'on') ? 'on' : 'off'",
				$dnsbl_src,
				"{$field} must be staged as an explicit 'on'/'off' (checkbox-absent means Off)"
			);
			$this->assertStringNotContainsString(
				"pfb_filter(\$_POST['{$field}'], PFB_FILTER_ON_OFF, 'dnsbl')",
				$dnsbl_src,
				"{$field} must not be staged with the pfb_filter(...) ?: '' coalesce"
			);
		}

		$ip_src = (string) file_get_contents(
			dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_ip.php'
		);
		$this->assertStringContainsString(
			"((\$_POST['suppression'] ?? '') === 'on') ? 'on' : 'off'",
			$ip_src,
			"suppression must be staged as an explicit 'on'/'off' (checkbox-absent means Off)"
		);
		$this->assertStringNotContainsString(
			"pfb_filter(\$_POST['suppression'], PFB_FILTER_ON_OFF, 'ip')",
			$ip_src,
			"suppression must not be staged with the pfb_filter(...) ?: '' coalesce"
		);
	}

	/**
	 * The render expression must survive the validation-error re-render, where
	 * `$pconfig = $_POST` replaces the gateway enum with the raw POST string ('on',
	 * or absent when unchecked). A bare `$pconfig[...] === PfbToggle::On` is FALSE
	 * for the string 'on', so the checkbox re-renders unchecked and the corrected
	 * resubmit silently stores 'off' — the #1887 enum-in-string-context class.
	 * pfb_cfg_toggle_read() accepts both (enum passthrough + string parse), and
	 * `?? ''` covers the unchecked-POST absent key.
	 */
	public function testPagesRenderTheIssue1907TogglesThroughTheToggleRead(): void
	{
		$dnsbl_src = (string) file_get_contents(
			dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php'
		);
		foreach (['pfb_cache', 'pfb_py_reply', 'pfb_hsts'] as $field) {
			$this->assertStringContainsString(
				"pfb_cfg_toggle_read(\$pconfig['{$field}'] ?? '') === PfbToggle::On",
				$dnsbl_src,
				"{$field} must render through pfb_cfg_toggle_read with the absent-POST fallback"
			);
		}

		$ip_src = (string) file_get_contents(
			dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_ip.php'
		);
		$this->assertStringContainsString(
			"pfb_cfg_toggle_read(\$pconfig['suppression'] ?? '') === PfbToggle::On",
			$ip_src,
			'suppression must render through pfb_cfg_toggle_read with the absent-POST fallback'
		);
		$this->assertStringNotContainsString(
			"\$pconfig['suppression'] === PfbToggle::On",
			$ip_src,
			'a bare enum comparison breaks on the $pconfig = $_POST error re-render path'
		);
	}
}
