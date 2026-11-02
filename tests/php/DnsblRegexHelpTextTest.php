<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * The helper assertions validate rendered prose directly. The DNSBL page has
 * top-level pfSense render/config execution and cannot be required safely off
 * appliance, so its live render call is pinned from comment-free PHP; comments
 * and docblocks are never allowed to define this coverage boundary.
 */
final class DnsblRegexHelpTextTest extends TestCase
{
	private static string $source;

	public static function setUpBeforeClass(): void
	{
		self::$source = php_strip_whitespace(
			dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php'
		);
		if (self::$source === '') {
			throw new RuntimeException('test bootstrap: failed to read comment-free pfblockerng_dnsbl.php');
		}
	}

	/**
	 * Pin the page's executable help-render call without booting its live Form_*
	 * stack, which would require a real pfSense appliance request context.
	 * Comments/docblocks cannot define this callsite boundary.
	 */
	public function testDnsblPageRendersRegexHelpThroughSharedHelper(): void
	{
		$this->assertStringContainsString(
			'$regex_text = pfb_dnsbl_regex_help_render();',
			self::$source
		);
	}
}
