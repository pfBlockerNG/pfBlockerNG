<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

/**
 * Issue #1792, sweep family 5 — the sinkhole block page's request-attribute
 * labels (`www/index.php`, standalone under the DNSBL VIP lighttpd, so no
 * pfblockerng.inc helpers there). The `htmlspecialchars($_SERVER[...] ?? '')
 * ?: 'Unknown'` idiom read a literal `Host: 0` / `User-Agent: 0` header as an
 * ABSENCE and labelled it "Unknown"; only a genuinely missing/empty attribute
 * may do that. Hermetic (page is Tier-A-unreachable per
 * `EXCLUDED_FROM_TIER_A["dnsbl_vip_sinkhole_pages"]`; the live VIP-sinkhole
 * leg covers the page render itself) — evals the REAL foreach statement out
 * of the page via Issue1792SweepSiteLoader.php.
 */
#[CoversNothing]
final class Issue1792SinkholeLabelTest extends TestCase
{
	private const SINKHOLE_PAGE = 'src/usr/local/www/pfblockerng/www/index.php';

	public static function setUpBeforeClass(): void
	{
		require_once __DIR__ . '/Issue1792SweepSiteLoader.php';
	}

	/**
	 * Run the loop body's REAL label statement for one attribute with
	 * $_SERVER seeded. (The statement -- not the enclosing foreach -- is the
	 * site under test; the loader is line-scoped.)
	 */
	private function runLabelStatement(string $server_type, ?string $value): string
	{
		$prev = $_SERVER;
		if ($value === null) {
			unset($_SERVER[$server_type]);
		} else {
			$_SERVER[$server_type] = $value;
		}
		try {
			$out = pfb_test_1792_eval_site(self::SINKHOLE_PAGE, "\$ptype[\$server_type] = ", [
				'ptype'       => [],
				'server_type' => $server_type,
			]);
			return $out['ptype'][$server_type];
		} finally {
			$_SERVER = $prev;
		}
	}

	public function testLiteralZeroHeaderIsDataNotUnknown(): void
	{
		$this->assertSame('0', $this->runLabelStatement('HTTP_HOST', '0'),
			'a literal `Host: 0` header is data, never the "Unknown" absence label');
		$this->assertSame('0', $this->runLabelStatement('HTTP_USER_AGENT', '0'));
		$this->assertSame('192.0.2.9', $this->runLabelStatement('REMOTE_ADDR', '192.0.2.9'));
	}

	public function testMissingAndEmptyHeadersStillReadUnknown(): void
	{
		$this->assertSame('Unknown', $this->runLabelStatement('HTTP_REFERER', ''),
			'an EMPTY header must still read "Unknown" -- the load-bearing fallback survives');
		$this->assertSame('Unknown', $this->runLabelStatement('HTTP_USER_AGENT', null),
			'a MISSING header must still read "Unknown"');
	}
}
