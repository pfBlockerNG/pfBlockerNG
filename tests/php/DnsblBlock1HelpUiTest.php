<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * DNSBL §1 help: five fields get one infoblock each; Wildcard drops the v2 warning
 * and the Advanced-process framing; $dnsbl_text is only Enable DNSBL's help.
 */
final class DnsblBlock1HelpUiTest extends TestCase
{
	private static function source(): string
	{
		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php');
		if ($source === FALSE) {
			throw new RuntimeException('failed to read DNSBL page');
		}
		return $source;
	}

	private static function setHelpFor(string $source, string $widget, string $id): string
	{
		self::assertSame(
			1,
			preg_match(
				"/new {$widget}\\(\\s*'{$id}'.*?->setHelp\\((.*?)\\);/s",
				$source,
				$m
			),
			"{$widget}('{$id}') setHelp() must exist"
		);
		return $m[1];
	}

	public function testFiveFieldsCarryExactlyOneInfoblock(): void
	{
		$source = self::source();
		foreach ([
			['Form_Select', 'pfb_idn'],
			['Form_Checkbox', 'pfb_hsts'],
			['Form_Checkbox', 'pfb_dnsbl_lenient'],
			['Form_Checkbox', 'pfb_cname'],
		] as [$widget, $id]) {
			$help = self::setHelpFor($source, $widget, $id);
			$this->assertSame(
				1,
				substr_count($help, 'class="infoblock"'),
				"{$id} help must have exactly one infoblock"
			);
		}

		$this->assertSame(
			1,
			preg_match(
				'/\$options_global_log_txt\s*=(.*?);/s',
				$source,
				$m
			),
			'$options_global_log_txt must exist'
		);
		$this->assertSame(1, substr_count($m[1], 'class="infoblock"'), 'global_log help must have exactly one infoblock');
		$this->assertStringContainsString('No Global mode', $m[1]);
		$this->assertStringContainsString('DNSBL WebServer/VIP', $m[1]);
		$this->assertStringContainsString('Null Blocking (logging)', $m[1]);
		$this->assertStringContainsString('NXDOMAIN', $m[1]);
	}

	public function testWildcardDropsAdvancedFramingAndClickInfoblock(): void
	{
		$source = self::source();
		$this->assertStringNotContainsString('Advanced process', $source);
		$this->assertStringNotContainsString('Click infoblock', $source);
		$this->assertStringContainsString('$tld_wildcard_text =', $source);
		$this->assertStringContainsString('id="dnsbl_tld_info"', $source);
		$this->assertStringContainsString('subdomains', $source);
		$this->assertStringContainsString('))->setHelp($tld_wildcard_text);', $source);
		$this->assertStringNotContainsString('their subdomains.<br />', $source);
	}

	public function testDnsblTextVariableIsOnlyEnableDnsblHelp(): void
	{
		$source = self::source();
		$this->assertSame(1, preg_match_all('/\$dnsbl_text\s*=/', $source));
		$this->assertStringContainsString('. "{$dnsbl_text}"', $source);
		$this->assertStringNotContainsString('))->setHelp($dnsbl_text);', $source);
	}
}
