<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #1263: pfb_update_unbound()'s DNSBL feed-count site must call
 * pfb_dnsbl_feed_count($pfb['dnsdir']) -- the old `/bin/cat *.txt | grep -c ^`
 * exec() shell-out is gone entirely. pfb_update_unbound() restarts real
 * services, so this is a source-inspection pin (same technique as
 * DownloadExtractionExitCodeTest); pfb_dnsbl_feed_count()'s own behaviour is
 * proven directly in DnsblFeedCountTest.
 */
final class DnsblFeedCountWiringTest extends TestCase
{
	private static string $body;

	public static function setUpBeforeClass(): void
	{
		$source = file_get_contents(
			dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng.inc'
		);
		if ($source === false) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng.inc');
		}

		$start = strpos($source, 'function pfb_update_unbound(');
		if ($start === false) {
			throw new RuntimeException('test bootstrap: function pfb_update_unbound( not found');
		}

		if (!preg_match('/^function\s+\w+/m', $source, $m, PREG_OFFSET_CAPTURE, $start + 20)) {
			throw new RuntimeException('test bootstrap: end-of-function boundary not found');
		}
		$end = $m[0][1];

		self::$body = substr($source, $start, $end - $start);
	}

	public function testCallsPfbDnsblFeedCountOnTheDnsdir(): void
	{
		$this->assertStringContainsString("pfb_dnsbl_feed_count(\$pfb['dnsdir'])", self::$body,
			'the per-file sum must replace the exec()d cat|grep -c ^ shell-out');
	}

	public function testNoLongerShellsOutToCatGrepForTheDnsblCount(): void
	{
		$this->assertDoesNotMatchRegularExpression('/exec\(\s*"\/bin\/cat/', self::$body,
			'the cat|grep -c ^ exec() shell-out must be gone -- an unterminated feed file welds into the next '
			. 'one and undercounts through it');
	}
}
