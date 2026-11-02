<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * DNSBL tab: Webserver is the second section, Matching refinements live in
 * the DNSBL section, Caches renamed, Exception Alias qualified, Bypass
 * Prevention and DNSBL IPs collapsed.
 */
final class DnsblTabLayoutUiTest extends TestCase
{
	private static function source(): string
	{
		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php');
		if ($source === FALSE) {
			throw new RuntimeException('failed to read DNSBL page');
		}
		return $source;
	}

	/** @return array<string, int> */
	private static function sectionPositions(string $source): array
	{
		$titles = [
			'DNSBL',
			'DNSBL Webserver Configuration',
			'Public-suffix handling',
			'TLD Allow list',
			'DNSBL Control',
			'DNSBL Group Policy',
			'DNS Bypass Prevention',
			'Regex List',
			'no-AAAA List',
			'DNS Caching',
			'DNSBL Whitelist',
			'TOP1M Whitelist',
			'TLD Exclusion List',
			'TLD Blacklist',
			'DNSBL IPs',
		];
		$positions = [];
		foreach ($titles as $title) {
			$pos = strpos($source, "new Form_Section('{$title}'");
			self::assertNotFalse($pos, "Form_Section('{$title}') missing");
			$positions[$title] = $pos;
		}
		return $positions;
	}

	public function testDnsblConfigurationSectionWasRenamedAway(): void
	{
		$source = self::source();
		$this->assertStringNotContainsString("new Form_Section('DNSBL Configuration'", $source);
		$this->assertStringContainsString("new Form_Section('DNSBL Webserver Configuration'", $source);
	}

	public function testWebserverIsSecondSectionAndFileWasNotTruncated(): void
	{
		$source = self::source();
		$order = array_keys(self::sectionPositions($source));
		$this->assertSame('DNSBL', $order[0]);
		$this->assertSame('DNSBL Webserver Configuration', $order[1]);
		$this->assertStringContainsString("\$tld_list['gTLD']", $source);
		$this->assertStringContainsString("include('foot.inc')", $source);
		$this->assertGreaterThan(150000, strlen($source), 'dnsbl.php must keep the TLD tables; a truncated cut-paste is a hard fail');
	}

	public function testBypassPreventionAndDnsblIpsAreCollapsed(): void
	{
		$source = self::source();
		$this->assertMatchesRegularExpression(
			"/new Form_Section\(\s*'DNS Bypass Prevention'\s*,\s*'dnsbl_bypass'\s*,\s*COLLAPSIBLE\s*\|\s*SEC_CLOSED\s*\)/",
			$source
		);
		$this->assertMatchesRegularExpression(
			"/new Form_Section\(\s*'DNSBL IPs'\s*,\s*'dnsbl_ips'\s*,\s*COLLAPSIBLE\s*\|\s*SEC_CLOSED\s*\)/",
			$source
		);
	}

	public function testCachesRenamedToDnsCaching(): void
	{
		$source = self::source();
		$this->assertMatchesRegularExpression(
			"/new Form_Section\(\s*'DNS Caching'\s*,\s*'dnsbl_caches'\s*,\s*COLLAPSIBLE\s*\|\s*SEC_CLOSED\s*\)/",
			$source
		);
		$this->assertStringNotContainsString("new Form_Section('Caches'", $source);
	}

	public function testRedirectExceptionAliasIsQualified(): void
	{
		$source = self::source();
		$this->assertStringContainsString("gettext('DNS Redirect Exception Alias')", $source);
		$this->assertStringContainsString("gettext('DoT/DoQ Exception Alias')", $source);
		$this->assertDoesNotMatchRegularExpression(
			"/dnsbl_redir_exclude',\s*\n\s*gettext\('Exception Alias'\)/",
			$source
		);
	}

	public function testIdnAndRegexGatesStillHideThePairedControls(): void
	{
		$source = self::source();
		$this->assertStringContainsString("hideCheckbox('pfb_idn_block_malicious'", $source);
		$this->assertStringContainsString("hideCheckbox('pfb_idn_escalate_suspicious'", $source);
		$this->assertStringContainsString("hideCheckbox('pfb_regex_cap'", $source);
		$this->assertStringContainsString("$('#pfb_regex').on('click change'", $source);
		$this->assertStringContainsString("$('#pfb_idn').change(", $source);
		$this->assertStringContainsString("new Form_Checkbox(\n\t'pfb_regex'", $source);
		$this->assertStringContainsString("new Form_Select(\n\t'pfb_idn'", $source);
		$this->assertStringContainsString('function enable_idn_mode()', $source);
		$this->assertStringContainsString('function enable_python_regex()', $source);
	}

	public function testExpandAllToggleSitsOnTheDnsblSectionTitle(): void
	{
		$source = self::source();
		$this->assertStringContainsString('<button type="button" id="pfb_expand_all" class="btn btn-xs btn-default pull-right">Expand all</button>', $source);
		$this->assertStringNotContainsString('<a href="#" id="pfb_expand_all"', $source);
		$this->assertStringContainsString("$('#pfb_dnsbl').closest('.panel')", $source);
		$this->assertStringContainsString('collapses().collapse(', $source);
		$this->assertStringContainsString("$('form .panel-body.collapse')", $source);
		$this->assertStringNotContainsString("$('form .panel-collapse')", $source);
		$this->assertStringContainsString('e.preventDefault()', $source);
		$this->assertStringContainsString('Expand all', $source);
		$this->assertStringContainsString('Collapse all', $source);
	}

	public function testPslAllowPrivateSitsInPublicSuffixHandling(): void
	{
		$source = self::source();
		$suffixPos = strpos($source, "new Form_Section('Public-suffix handling'");
		$includePos = strpos($source, "new Form_Checkbox(\n\t'pfb_psl_include_private'");
		$allowPos = strpos($source, "new Form_Checkbox(\n\t'pfb_psl_allow_private'");
		$pickersPos = strpos($source, "new Form_Section('TLD Allow list'");
		$this->assertNotFalse($suffixPos);
		$this->assertNotFalse($includePos);
		$this->assertNotFalse($allowPos);
		$this->assertNotFalse($pickersPos);
		$this->assertGreaterThan($suffixPos, $includePos);
		$this->assertGreaterThan($includePos, $allowPos);
		$this->assertGreaterThan($allowPos, $pickersPos);
	}

	public function testListTextareasDoNotHardcodeALightBackground(): void
	{
		$source = self::source();
		$this->assertStringNotContainsString('background:#fafafa', $source);
		$this->assertSame(6, substr_count($source, "->setAttribute('style', 'width: 100%')"));
	}
}
