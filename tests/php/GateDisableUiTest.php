<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Per-control gating: some single-row companions disable, others hide.
 * A control that is temporarily unavailable greys out; one that does not APPLY
 * to the current selection hides (issue #3060's top1m_token).
 * Whole sections still hide. Disabled controls re-enable on submit so POST
 * keeps the stored value (a disabled input is omitted from the form).
 */
final class GateDisableUiTest extends TestCase
{
	private static function dnsbl(): string
	{
		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php');
		if ($source === FALSE) {
			throw new RuntimeException('failed to read DNSBL page');
		}
		return $source;
	}

	private static function ip(): string
	{
		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_ip.php');
		if ($source === FALSE) {
			throw new RuntimeException('failed to read IP page');
		}
		return $source;
	}

	public function testSingleControlsUseDisableInputNotHide(): void
	{
		$dnsbl = self::dnsbl();
		foreach ([
			'pfb_psl_include_private',
			'pfb_dnsport',
			'pfb_dnsport_ssl',
			'pfb_psl_allow_private',
			'aliaslog',
		] as $id) {
			$this->assertStringContainsString("disableInput('{$id}'", $dnsbl, "{$id} must stay visible when inert");
			$this->assertStringNotContainsString("hideCheckbox('{$id}'", $dnsbl, "{$id} must not hide");
			$this->assertStringNotContainsString("hideInput('{$id}'", $dnsbl, "{$id} must not hide");
		}
		foreach ([
			'pfb_regex_cap',
			'pfb_idn_block_malicious',
			'pfb_idn_escalate_suspicious',
		] as $id) {
			$this->assertStringContainsString("hideCheckbox('{$id}'", $dnsbl, "{$id} hides while its parent is off");
			$this->assertStringNotContainsString("disableInput('{$id}'", $dnsbl);
		}

		// issue #3060: the Cloudflare Radar API Token is not APPLICABLE for a keyless
		// TOP1M type rather than temporarily unavailable, so it hides like the IP page's
		// delta-batch input below instead of greying out. It is the one gated control on
		// this page that moved out of the disable group, so it is pinned by name.
		$this->assertStringContainsString("hideInput('top1m_token'", $dnsbl, 'top1m_token hides for a keyless TOP1M type');
		$this->assertStringNotContainsString("disableInput('top1m_token'", $dnsbl, 'top1m_token must not grey out');
		$this->assertStringNotContainsString("hideCheckbox('top1m_token'", $dnsbl, 'top1m_token is an input, not a checkbox row');

		$ip = self::ip();
		$this->assertStringContainsString("hideInput('pfb_alias_delta_batch'", $ip);
		$this->assertStringNotContainsString("disableInput('pfb_alias_delta_batch'", $ip);
	}

	public function testWholeSectionsStayHidden(): void
	{
		$dnsbl = self::dnsbl();
		foreach ([
			'TLD_Exclusion',
			'TLD_BW_list',
			'tld_allow_pickers',
			'Python_regex_list',
			'Python_noaaaa_list',
			'Python_Group_Policy',
			'advinboundsettings',
			'advoutboundsettings',
		] as $id) {
			$this->assertStringContainsString("$('#{$id}').hide()", $dnsbl, "{$id} stays a hidden section");
		}
	}

	public function testEachDisabledControlNamesItsGateInHelp(): void
	{
		$dnsbl = self::dnsbl();
		$this->assertStringContainsString('Applies when Wildcard Blocking is enabled.', $dnsbl);
		$this->assertStringContainsString('Applies when Web Server Interface is not Localhost.', $dnsbl);
		$this->assertStringContainsString('Applies when Allow Only Selected Domain Suffixes is enabled.', $dnsbl);
		$this->assertStringContainsString('Applies when the selected Type requires an API token.', $dnsbl);
		$this->assertStringContainsString('Applies when List Action is not Disabled.', $dnsbl);

		$ip = self::ip();
		$this->assertStringContainsString('Applies in Auto and Delta modes.', $ip);
	}

	public function testSubmitReenablesGatedControlsSoPostKeepsTheirValues(): void
	{
		$dnsbl = self::dnsbl();
		$this->assertStringContainsString('pfb_gated_ids', $dnsbl);
		$this->assertStringContainsString("disableInput(id, false)", $dnsbl);
		$this->assertStringContainsString("$('form').submit", $dnsbl);

		$ip = self::ip();
		$this->assertStringNotContainsString('pfb_gated_ids', $ip);
	}
}
