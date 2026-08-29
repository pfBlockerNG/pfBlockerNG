<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Long DNSBL helps keep Save-outcome sentences visible and fold rationale.
 */
final class DnsblHelpFoldUiTest extends TestCase
{
	public function testEightLongHelpsCarryAnInfoblock(): void
	{
		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php');
		$this->assertNotFalse($source);
		foreach ([
			'<div class="infoblock">From both feeds (ABP) and the Regex List below',
			'<div class="infoblock">This Port must not be in use by any other process.</div>',
			'<div class="infoblock">This option is not designed to bypass DNSBL',
			'<div class="infoblock">DoH (port 443) is <strong>not</strong> blocked here',
			'<div class="infoblock">A single floating rule (direction <strong>in</strong>, quick)',
			'<div class="infoblock">Modern browsers and devices often use encrypted DNS',
			'<div class="infoblock">The stored token is never displayed here.</div>',
		] as $block) {
			$this->assertStringContainsString($block, $source);
		}
		$this->assertSame(2, substr_count($source, '<div class="infoblock">This Port must not be in use by any other process.</div>'));
		$this->assertStringContainsString('Leave blank on Save to keep the existing token.', $source);
		$this->assertStringContainsString('Applies when Regex Blocking is enabled.', $source);
	}
}
