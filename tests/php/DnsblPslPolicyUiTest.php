<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/** Step3 UI contract: PSL policy controls use the gateway and exact operator language. */
final class DnsblPslPolicyUiTest extends TestCase
{
	private static function source(): string
	{
		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php');
		if ($source === FALSE) {
			throw new RuntimeException('failed to read DNSBL page');
		}
		return $source;
	}

	public function testPslLabelsAndHelpExplainPrivateBoundary(): void
	{
		$source = self::source();
		foreach ([
			'Wildcard Blocking',
			'Allow Only Selected Domain Suffixes',
			'IANA root TLDs',
			'Recognize Shared-Hosting Suffixes (PSL PRIVATE)',
			'Allow Shared-Hosting Suffixes (PSL PRIVATE)',
			'registrable',
			'suffix apex',
			'github.io',
			'private DNS',
		] as $term) {
			$this->assertStringContainsString($term, $source, "UI/help must contain '{$term}'");
		}
	}

	public function testPslControlsUseRegisteredGatewayKeysAndScopedVisibility(): void
	{
		$source = self::source();
		$this->assertStringContainsString("PfbConfig::read('dnsbl/pfb_psl_include_private')", $source);
		$this->assertStringContainsString("PfbConfig::read('dnsbl/pfb_psl_allow_private')", $source);
		$this->assertStringContainsString("PfbConfig::write('dnsbl/pfb_psl_include_private'", $source);
		$this->assertStringContainsString("PfbConfig::write('dnsbl/pfb_psl_allow_private'", $source);
		$this->assertStringContainsString("$('#tld_wildcard')", $source);
		$this->assertStringContainsString("$('#tld_allow')", $source);
		// Row-level visibility rides the page's hideCheckbox() idiom (hides the
		// whole form-group, label and help included), never a bare input hide().
		$this->assertStringContainsString("hideCheckbox('pfb_psl_include_private'", $source);
		$this->assertStringContainsString("hideCheckbox('pfb_psl_allow_private'", $source);
		$this->assertStringNotContainsString('psl-policy', $source);
		$this->assertStringNotContainsString("config_get_path('installedpackages/pfblockerngdnsblsettings/config/0/pfb_psl_", $source);
		$this->assertStringNotContainsString("config_set_path('installedpackages/pfblockerngdnsblsettings/config/0/pfb_psl_", $source);
	}
}
