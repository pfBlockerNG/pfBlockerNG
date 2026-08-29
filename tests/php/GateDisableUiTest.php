<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Per-control gating: some single-row companions disable, others hide.
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
			'top1m_token',
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

		$ip = self::ip();
		$this->assertStringContainsString("disableInput('pfb_alias_delta_batch'", $ip);
		$this->assertStringNotContainsString("hideInput('pfb_alias_delta_batch'", $ip);
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
		$this->assertStringContainsString('pfb_gated_ids', $ip);
		$this->assertStringContainsString("disableInput(id, false)", $ip);
		$this->assertStringContainsString("$('form').submit", $ip);
	}
}
